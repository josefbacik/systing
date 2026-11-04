#!/usr/bin/env python3
"""The end-to-end check of systing-go-profile: read each profile of the
workload out of its memory, fetch the same profile from the program's own
pprof port, and read it from memory again; then copy its flight recorder and
have the program write the same window itself. The first read of each
profile is written as a pprof file (`snoop -o`), which `go tool pprof` must
take, and is read back from it.

    check.py TOOL WORKLOAD [WORKLOAD ...]

Passes when, for every workload binary (by Go's linker and by the system
linker, each as built and stripped):

- heap, block and mutex: every stack's pprof values lie between the two reads
  (equal where the profile did not move); block and mutex delays may be a
  little beyond (1 us, and a part in a million): they are CPU ticks turned
  into nanoseconds, and until the program has worked out its tick rate the
  reader works it out itself, a moment apart. A stack that neither read holds
  is looked for under one other name: where the compiler inlined a call into
  the wrapper it made for a go or defer statement or a method value, Go names
  the call and leaves the wrapper out, and the reader, which expands no
  inlined call, names the wrapper. The stack is then held to the same rule
  against the stack of the reads that has such a wrapper in that frame's place
  and is the same in every other frame, if there is just one, and the
  profile's line names the call. A wrapper counts only where the compiler puts
  it: a go statement's at the root, a defer statement's above the function
  that made it, a method value's in its own method's place;
- goroutines: the 1000 parked goroutines on one stack on both sides, and the
  totals apart by no more than the goroutines that were running (which keep
  no stack in memory) and the one serving pprof;
- flight recorder: every generation both files hold is byte for byte the same.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.request

EV_EVENT_BATCH, EV_EXPERIMENTAL_BATCH, EV_END_OF_GENERATION = 1, 49, 52
PARKED = 1000
WRAPPER = re.compile(r"\.(gowrap|deferwrap)\d+$")


def run_json_lines(args):
    out = subprocess.run(args, capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"{' '.join(args)}: {out.stderr.strip()}")
    lines = out.stdout.splitlines()
    return json.loads(lines[0]), [json.loads(line) for line in lines[1:]]


def norm(stack, wrappers=False):
    """Both sides alike: no unnamed frames, no wrappers a go or defer
    statement made (`wrappers` keeps them), no runtime.goexit at the root, and
    a function repeated in a row once (Go's block and mutex stacks give inlined
    calls PCs of their own)."""
    s = [f for f in stack if f and f != "?" and (wrappers or not WRAPPER.search(f))]
    while s and s[-1] == "runtime.goexit":
        s.pop()
    return tuple(f for i, f in enumerate(s) if i == 0 or s[i - 1] != f)


def by_stack(rows, skip_running=False):
    d = {}
    for r in rows:
        if skip_running and r.get("labels", {}).get("state") == "running":
            continue
        cur = d.setdefault(norm(r["stack"]), [0] * len(r["values"]))
        for i, v in enumerate(r["values"]):
            cur[i] += v
    return d


def with_wrappers(rows):
    return {norm(r["stack"], wrappers=True) for r in rows}


def inlined_call(read, own):
    """The one frame of `own`, a stack of the program's profile, in whose place
    `read`, a stack out of memory that is otherwise the same, has a wrapper
    (both with their wrappers kept); None if there is no such frame. A wrapper
    counts only where the compiler puts it: a go statement's at the root, a
    defer statement's above the function that made it (the body of a
    range-over-function loop, "-rangeN", defers for the function around it), a
    method value's ("-fm") in its own method's place."""
    differ = [i for i, (r, o) in enumerate(zip(read, own)) if r != o]
    if len(read) != len(own) or len(differ) != 1:
        return None
    i = differ[0]
    if re.search(r"\.gowrap\d+$", read[i]):
        fits = i == len(read) - 1
    elif re.search(r"\.deferwrap\d+$", read[i]):
        fits = re.sub(r"(-range\d+)*\.deferwrap\d+$", "", read[i]) in read[i + 1 :]
    else:
        fits = read[i] == own[i] + "-fm"
    return own[i] if fits else None


def between(before, pp, after, delays, own, reads):
    """The stacks whose pprof values are not between the two reads; with
    `delays`, the second value is a delay converted from CPU ticks. And
    {stack: (the reads' name for it, the inlined call)} of those that neither
    read holds and that were looked up under the one stack of the reads that
    has a wrapper for one of their calls: one that the program's profile does
    not hold as well, and that stands for no other of its stacks. `own` and
    `reads` are the two sides' stacks with their wrappers kept."""
    claims = {}
    for o in own:
        if norm(o) not in before and norm(o) not in after:
            found = {norm(w): inlined_call(w, o) for w in reads if inlined_call(w, o) and norm(w) not in pp}
            if len(found) == 1:
                r, call = found.popitem()
                claims.setdefault(r, {})[norm(o)] = (r, call)
    read_as = {k: v for ks in claims.values() if len(ks) == 1 for k, v in ks.items()}
    bad = []
    for k, p in pp.items():
        r = read_as.get(k, (k,))[0]
        b = before.get(r, [0] * len(p))
        a = after.get(r, [0] * len(p))
        for i, (x, y, z) in enumerate(zip(b, p, a)):
            slack = 1000 + max(x, z) // 1_000_000 if delays and i == 1 else 0
            lo, hi = min(x, z) - slack, max(x, z) + slack
            if not lo <= y <= hi:
                bad.append({"stack": list(k), "before": b, "pprof": p, "after": a})
                if r != k:
                    bad[-1]["read_as"] = list(r)
                break
    return bad, read_as


def uvarint(b, i):
    v = shift = 0
    while True:
        x = b[i]
        i += 1
        v |= (x & 0x7F) << shift
        if x < 0x80:
            return v, i
        shift += 7


def generations(path):
    """{generation: [batch bytes, ...]} of an execution trace file."""
    b = open(path, "rb").read()
    gens, i, last = {}, 16, None
    while i < len(b):
        start, typ = i, b[i]
        if typ == EV_END_OF_GENERATION:
            gens.setdefault(last, []).append(b[i : i + 1])
            i += 1
            continue
        j = i + 1
        if typ == EV_EXPERIMENTAL_BATCH:
            _, j = uvarint(b, j)
        elif typ != EV_EVENT_BATCH:
            raise ValueError(f"{path}: event {typ} at {i}")
        gen, j = uvarint(b, j)
        _, j = uvarint(b, j)
        _, j = uvarint(b, j)
        size, j = uvarint(b, j)
        i = j + size
        gens.setdefault(gen, []).append(b[start:i])
        last = gen
    return gens


def check_one(tool, workload, tmp):
    p = subprocess.Popen([workload], stdout=subprocess.PIPE, text=True)
    try:
        port, pid = re.match(r"port (\d+) pid (\d+)", p.stdout.readline()).groups()
        get = lambda path: urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=60).read()
        # A few collections, and a few finished trace generations.
        time.sleep(5)
        failures = []
        snoop = lambda kind: run_json_lines([tool, "snoop", "--pid", pid, "--profile", kind])
        for kind in ("heap", "mutex", "block", "goroutine"):
            mine = os.path.join(tmp, f"{os.path.basename(workload)}-{kind}-read.pb.gz")
            hb, _ = run_json_lines([tool, "snoop", "--pid", pid, "--profile", kind, "-o", mine])
            path = os.path.join(tmp, f"{os.path.basename(workload)}-{kind}.pb.gz")
            with open(path, "wb") as f:
                f.write(get(f"/debug/pprof/{kind}"))
            _, after = snoop(kind)
            _, before = run_json_lines([tool, "pprof", mine])
            _, pprof = run_json_lines([tool, "pprof", path])
            took = subprocess.run(["go", "tool", "pprof", "-top", mine], capture_output=True, text=True)
            if took.returncode != 0:
                failures.append(f"{kind}: go tool pprof refused the file: {took.stderr.strip()[-300:]}")
            running = kind == "goroutine"
            b, pp, a = by_stack(before, running), by_stack(pprof), by_stack(after, running)
            line = f"  {kind}: {len(pp)} stacks, {hb['globals_found_by']}, read in {hb['read_us']} us"
            if kind == "goroutine":
                parked = [v[0] for k, v in pp.items() if k and k[-1] == "main.parked"]
                mine = [v[0] for k, v in b.items() if k and k[-1] == "main.parked"]
                total = lambda d: sum(v[0] for v in d.values())
                gap = total(pp) - total(b)
                line += f"; {total(b)} read, {total(pp)} from pprof"
                if parked != [PARKED] or mine != [PARKED]:
                    failures.append(f"{kind}: parked goroutines {mine} read, {parked} from pprof")
                if not 0 <= gap <= hb["running_without_stack"] + 1 + os.cpu_count():
                    failures.append(f"{kind}: {total(b)} read against {total(pp)} from pprof")
            else:
                own, reads = with_wrappers(pprof), with_wrappers(before + after)
                bad, read_as = between(b, pp, a, kind != "heap", own, reads)
                if read_as:
                    calls = sorted({call for _, call in read_as.values()})
                    line += f"; {len(read_as)} matched at a wrapper ({', '.join(calls)})"
                for one in bad[:3]:
                    failures.append(f"{kind}: {json.dumps(one)}")
                if not pp:
                    failures.append(f"{kind}: the program's own profile is empty")
            print(line)
        copy, ref = os.path.join(tmp, "copy.trace"), os.path.join(tmp, "ref.trace")
        run_json_lines([tool, "flight", "--pid", pid, "--out", copy])
        get(f"/flight?out={ref}")
        c, r = generations(copy), generations(ref)
        common = sorted(set(c) & set(r))
        differ = [g for g in common if c[g] != r[g]]
        print(f"  flight: generations {sorted(c)} copied, {sorted(r)} written; {len(common)} compared")
        if not common or differ:
            failures.append(f"flight: {len(common)} generations compared, {differ} differ")
        return failures
    finally:
        p.kill()
        p.wait()


def main():
    tool, workloads = sys.argv[1], sys.argv[2:]
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        os.chmod(tmp, 0o755)
        for w in workloads:
            print(os.path.basename(w))
            failures += [f"{os.path.basename(w)}: {f}" for f in check_one(tool, w, tmp)]
    for f in failures:
        print("FAIL", f)
    print("ok" if not failures else f"{len(failures)} failures")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
