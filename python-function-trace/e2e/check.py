#!/usr/bin/env python3
"""Check a slices table of workload.py against what the script does."""
import collections, sys
path, mode = sys.argv[1], sys.argv[2]   # mode: dispatch | eval-frame
rows = [l.rstrip("\n").split("\t") for l in open(path)][1:]
mine = [r for r in rows if r[7].endswith("workload.py")]
by = collections.Counter()
for r in mine:
    name = r[6].split(" [")[0].split(":")[-1]
    by[(name, r[5])] += 1
tot = collections.Counter()
for (n, e), c in by.items():
    tot[n] += c
# function -> (slices, {end kind: count}) in dispatch mode
want = {
    "leaf": (713, {"return": 713}),
    "mid": (350, {"return": 350}),
    "raiser": (40, {"unwound": 40}),
    "catcher": (10, {"return": 10}),
    "gen": (31, {"yield": 30, "return": 1}),
    "K.__init__": (25, {"return": 25}),
    "K.method": (20, {"return": 20}),
    "<genexpr>": (21, {"yield": 20, "return": 1}),
    "K.__getattr__": (5, {"unwound": 5}),
    "swallowed": (5, {"return": 5}),
    "via_c": (1, {"return": 1}),
    "co": (6, {"yield": 3, "return": 3}),
    "amain": (2, {"yield": 1, "return": 1}),
    "worker": (3, {"return": 3}),
    "<module>": (1, {"return": 1}),
    "K": (1, {"return": 1}),
}
bad = 0
for name, (n, ends) in want.items():
    got = tot[name]
    got_ends = {e: c for (nm, e), c in by.items() if nm == name}
    ok = got == n and (mode != "dispatch" or got_ends == ends)
    bad += not ok
    print(f"  {'ok ' if ok else 'BAD'} {name:14} slices {got:4} (want {n:4})  {got_ends}")
extra = set(tot) - set(want)
if extra:
    print("  unexpected functions:", extra); bad += 1
# threads: worker on 3 tids, none the main thread; each has 50 mid at depth 1+
main_tid = next(r[1] for r in mine if r[6].endswith("<module>"))
wt = {r[1] for r in mine if r[6].endswith("worker")}
ok = len(wt) == 3 and main_tid not in wt
bad += not ok
print(f"  {'ok ' if ok else 'BAD'} worker threads: {len(wt)} distinct, main thread {main_tid}")
# nesting and depth: on each thread, a slice lies inside the slices that
# enclose it, and its depth is how many there are
by_tid = collections.defaultdict(list)
for r in rows:
    by_tid[r[1]].append((int(r[2]), int(r[2]) + int(r[3]), int(r[4]), r[6]))
nest_bad = depth_bad = 0
for tid, sl in by_tid.items():
    stack = []
    for s, e, d, name in sl:           # outermost first within a thread
        while stack and stack[-1][2] >= d:
            stack.pop()
        if stack and not (stack[-1][0] <= s and e <= stack[-1][1]):
            nest_bad += 1
        stack.append((s, e, d))
    stack = []
    for s, e, d, name in sl:
        while stack and not (stack[-1][0] <= s and e <= stack[-1][1]):
            stack.pop()
        if d != len(stack):
            depth_bad += 1
        stack.append((s, e))
bad += nest_bad > 0
bad += depth_bad > 0
print(f"  {'ok ' if nest_bad == 0 else 'BAD'} nesting: {nest_bad} slices outside their parent ({len(rows)} slices)")
print(f"  {'ok ' if depth_bad == 0 else 'BAD'} depth: {depth_bad} slices whose depth is not the number of slices around them")
print("PASS" if not bad else f"FAIL ({bad})")
sys.exit(1 if bad else 0)
