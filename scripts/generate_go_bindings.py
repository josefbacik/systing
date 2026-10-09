#!/usr/bin/env python3
"""Generate Rust offset constants from the Go runtime's own debug info.

Builds a small reference program with the Go version asked for, then reads,
with a reader written in Go (debug/dwarf, debug/elf, go/parser):

  - the layout of every runtime struct src/golang reads, from the program's
    DWARF (the runtime's types are private, so nothing else knows them);
  - the goroutine status and wait reason numbers, from the same DWARF;
  - the goroutine states' and wait reasons' text, from the program's own
    `runtime.gStatusStrings` and `runtime.waitReasonStrings`;
  - the trace format's event numbers, from that toolchain's
    `internal/trace/tracev2/events.go`.

and writes a Rust file per Go minor version: a module of `pub const`
declarations per reader (TABLES), each only when everything it names is in
that version's runtime.

Requires:
  - a Go toolchain on PATH (it builds the reader, and fetches other
    toolchains through GOTOOLCHAIN), or --go naming the one to build with

Usage:
  python3 scripts/generate_go_bindings.py go1.26.7
  python3 scripts/generate_go_bindings.py --go /usr/local/go/bin/go
"""
import argparse
import os
import re
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.path.join(REPO_ROOT, "src", "golang", "bindings")

# The reference program: links what the readers walk (the heap, block and
# mutex profiles, profiler labels and the flight recorder), so their types are
# in its DWARF.
REFERENCE_PROGRAM = """\
package main

import (
\t"context"
\t"os"
\t"runtime/pprof"
\t"runtime/trace"
)

func main() {
\tfr := trace.NewFlightRecorder(trace.FlightRecorderConfig{})
\t_ = fr.Start()
\t_ = pprof.Lookup("heap").WriteTo(os.Stdout, 0)
\tpprof.Do(context.Background(), pprof.Labels("k", "v"), func(context.Context) {})
}
"""

# The tables, one per reader. A version's file has a table only when every
# value it names is in that version's runtime: a reader whose structs changed
# shape is refused for the version until its code follows, and the others are
# not held back by it. Each table lists:
#   offsets:   Rust name, Go struct, field path ("" for the struct's size)
#   lengths:   Rust name, Go struct, array field: its number of elements
#   constants: Rust name, Go constant (Rust type u32 for names starting G_)
#   events:    Rust name, event in internal/trace/tracev2/events.go
#   strings:   Rust name, Go [N]string global: the runtime's own text
TABLES = [
    {
        "name": "profiles",
        "about": "The profile readers' table (profiles, goroutines, flight): the heap,\n"
        "/// block and mutex buckets, the goroutines and the flight recorder.",
        "offsets": [
            ("BUCKET_SIZE", "runtime.bucket", ""),
            ("BUCKET_ALLNEXT", "runtime.bucket", "allnext"),
            ("BUCKET_TYP", "runtime.bucket", "typ"),
            ("BUCKET_NSTK", "runtime.bucket", "nstk"),
            ("MEM_RECORD_SIZE", "runtime.memRecord", ""),
            ("MEM_RECORD_ACTIVE", "runtime.memRecord", "active"),
            ("MEM_RECORD_FUTURE", "runtime.memRecord", "future"),
            ("MEM_RECORD_CYCLE_SIZE", "runtime.memRecordCycle", ""),
            ("MEM_RECORD_CYCLE_ALLOCS", "runtime.memRecordCycle", "allocs"),
            ("MEM_RECORD_CYCLE_FREES", "runtime.memRecordCycle", "frees"),
            ("MEM_RECORD_CYCLE_ALLOC_BYTES", "runtime.memRecordCycle", "alloc_bytes"),
            ("MEM_RECORD_CYCLE_FREE_BYTES", "runtime.memRecordCycle", "free_bytes"),
            ("BLOCK_RECORD_SIZE", "runtime.blockRecord", ""),
            ("BLOCK_RECORD_COUNT", "runtime.blockRecord", "count"),
            ("BLOCK_RECORD_CYCLES", "runtime.blockRecord", "cycles"),
            ("TICKS_START_TICKS", "runtime.ticksType", "startTicks"),
            ("TICKS_START_TIME", "runtime.ticksType", "startTime"),
            ("TICKS_VAL", "runtime.ticksType", "val"),
            ("G_SIZE", "runtime.g", ""),
            ("G_STACK_HI", "runtime.g", "stack.hi"),
            ("G_SCHED_SP", "runtime.g", "sched.sp"),
            ("G_SCHED_PC", "runtime.g", "sched.pc"),
            ("G_SCHED_BP", "runtime.g", "sched.bp"),
            ("G_SYSCALLPC", "runtime.g", "syscallpc"),
            ("G_SYSCALLBP", "runtime.g", "syscallbp"),
            ("G_ATOMICSTATUS", "runtime.g", "atomicstatus"),
            ("G_GOID", "runtime.g", "goid"),
            ("G_WAITSINCE", "runtime.g", "waitsince"),
            ("G_WAITREASON", "runtime.g", "waitreason"),
            ("G_STARTPC", "runtime.g", "startpc"),
            ("TRACE_MUX_FLIGHT_RECORDER", "runtime/trace.traceMultiplexer", "flightRecorder"),
            ("TRACE_RECORDER_R", "runtime/trace.recorder", "r"),
            ("FLIGHT_RECORDER_HEADER", "runtime/trace.FlightRecorder", "header"),
            ("FLIGHT_RECORDER_RING", "runtime/trace.FlightRecorder", "ring"),
            ("RAW_GENERATION_SIZE", "runtime/trace.rawGeneration", ""),
            ("RAW_GENERATION_GEN", "runtime/trace.rawGeneration", "gen"),
            ("RAW_GENERATION_BATCHES", "runtime/trace.rawGeneration", "batches"),
        ],
        "lengths": [
            ("MEM_RECORD_FUTURE_CYCLES", "runtime.memRecord", "future"),
        ],
        "constants": [
            ("MEM_PROFILE", "runtime.memProfile"),
            ("BLOCK_PROFILE", "runtime.blockProfile"),
            ("MUTEX_PROFILE", "runtime.mutexProfile"),
            ("G_RUNNING", "runtime._Grunning"),
            ("G_SYSCALL", "runtime._Gsyscall"),
            ("G_WAITING", "runtime._Gwaiting"),
            ("G_DEAD", "runtime._Gdead"),
            ("G_COPYSTACK", "runtime._Gcopystack"),
            ("G_LEAKED", "runtime._Gleaked"),
            ("G_DEADEXTRA", "runtime._Gdeadextra"),
            ("G_SCAN", "runtime._Gscan"),
        ],
        "events": [
            ("EV_EVENT_BATCH", "EvEventBatch"),
            ("EV_EXPERIMENTAL_BATCH", "EvExperimentalBatch"),
            ("EV_END_OF_GENERATION", "EvEndOfGeneration"),
        ],
        "strings": [
            ("G_STATUS_NAMES", "runtime.gStatusStrings"),
            ("WAIT_REASONS", "runtime.waitReasonStrings"),
        ],
    },
]

# The reader. Prints `name value` lines; `name` is a request's key.
READER_PROGRAM = r"""
package main

import (
	"bufio"
	"debug/dwarf"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
)

func fail(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...); os.Exit(1) }

// What this version's runtime does not have: printed, not fatal, so that a
// table that needs it is left out and the others are still written.
func missing(out *bufio.Writer, key, f string, a ...any) {
	fmt.Fprintf(out, "missing %s %s\n", key, fmt.Sprintf(f, a...))
}

func main() {
	bin, eventsGo := os.Args[1], os.Args[2]
	f, err := elf.Open(bin)
	if err != nil { fail("%v", err) }
	d, err := f.DWARF()
	if err != nil { fail("no DWARF: %v", err) }

	structs := map[string]*dwarf.StructType{}
	consts := map[string]int64{}
	r := d.Reader()
	for {
		e, err := r.Next()
		if err != nil { fail("%v", err) }
		if e == nil { break }
		name, _ := e.Val(dwarf.AttrName).(string)
		switch e.Tag {
		case dwarf.TagStructType:
			if _, seen := structs[name]; !seen {
				if t, err := d.Type(e.Offset); err == nil {
					if st, ok := t.(*dwarf.StructType); ok && !st.Incomplete {
						structs[name] = st
					}
				}
			}
		case dwarf.TagConstant:
			if v, ok := e.Val(dwarf.AttrConstValue).(int64); ok {
				consts[name] = v
			}
		}
	}

	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		req := strings.Fields(sc.Text())
		switch req[0] {
		case "offset": // key struct path
			st := structs[req[2]]
			if st == nil {
				missing(out, req[1], "no struct %s", req[2])
				continue
			}
			if len(req) < 4 {
				fmt.Fprintf(out, "%s %d\n", req[1], st.ByteSize)
				continue
			}
			off, ok := int64(0), true
			for _, part := range strings.Split(req[3], ".") {
				var found *dwarf.StructField
				if st != nil {
					for _, fl := range st.Field {
						if fl.Name == part { found = fl; break }
					}
				}
				if found == nil {
					missing(out, req[1], "%s has no field %s", req[2], req[3])
					ok = false
					break
				}
				off += found.ByteOffset
				st = structOf(found.Type)
			}
			if ok { fmt.Fprintf(out, "%s %d\n", req[1], off) }
		case "length": // key struct field
			st := structs[req[2]]
			n := int64(-1)
			if st != nil {
				for _, fl := range st.Field {
					if at, ok := fl.Type.(*dwarf.ArrayType); ok && fl.Name == req[3] { n = at.Count }
				}
			}
			if n < 0 {
				missing(out, req[1], "%s has no array field %s", req[2], req[3])
				continue
			}
			fmt.Fprintf(out, "%s %d\n", req[1], n)
		case "const": // key name
			v, ok := consts[req[2]]
			if !ok {
				missing(out, req[1], "no constant %s", req[2])
				continue
			}
			fmt.Fprintf(out, "%s %d\n", req[1], v)
		case "event": // key name
			n := eventNumber(eventsGo, req[2])
			if n < 0 {
				missing(out, req[1], "no event %s", req[2])
				continue
			}
			fmt.Fprintf(out, "%s %d\n", req[1], n)
		case "strings": // key symbol
			table, why := stringTable(f, req[2])
			if why != "" {
				missing(out, req[1], "%s", why)
				continue
			}
			for _, s := range table {
				fmt.Fprintf(out, "string %s %q\n", req[1], s)
			}
		}
	}
}

// The struct `t` is, through typedefs.
func structOf(t dwarf.Type) *dwarf.StructType {
	for {
		switch v := t.(type) {
		case *dwarf.StructType:
			return v
		case *dwarf.TypedefType:
			t = v.Type
		default:
			return nil
		}
	}
}

// The position of `name` in the const block that starts `EvNone EventType = iota`,
// or -1.
func eventNumber(path, name string) int {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil { fail("%v", err) }
	for _, decl := range file.Decls {
		g, ok := decl.(*ast.GenDecl)
		if !ok || g.Tok != token.CONST || len(g.Specs) == 0 { continue }
		if first := g.Specs[0].(*ast.ValueSpec); first.Names[0].Name != "EvNone" { continue }
		for i, spec := range g.Specs {
			if spec.(*ast.ValueSpec).Names[0].Name == name { return i }
		}
	}
	return -1
}

// A [N]string global, read out of the program's data: one string header
// (pointer, length) per element; or why there is none.
func stringTable(f *elf.File, symbol string) ([]string, string) {
	syms, err := f.Symbols()
	if err != nil { fail("%v", err) }
	var table elf.Symbol
	for _, s := range syms {
		if s.Name == symbol { table = s }
	}
	if table.Value == 0 || table.Size%16 != 0 { return nil, "no [N]string " + symbol }
	n := int(table.Size / 16)
	read := func(addr, size uint64) []byte {
		for _, p := range f.Progs {
			if p.Type == elf.PT_LOAD && addr >= p.Vaddr && addr+size <= p.Vaddr+p.Filesz {
				b := make([]byte, size)
				if _, err := p.ReadAt(b, int64(addr-p.Vaddr)); err != nil { fail("%v", err) }
				return b
			}
		}
		fail("%#x is not in the file", addr)
		return nil
	}
	hdrs := read(table.Value, table.Size)
	out := make([]string, n)
	for i := range out {
		ptr := binary.LittleEndian.Uint64(hdrs[i*16:])
		ln := binary.LittleEndian.Uint64(hdrs[i*16+8:])
		if ln > 0 { out[i] = string(read(ptr, ln)) }
	}
	return out, ""
}
"""


def run(cmd, **kwargs):
    """Run a command, raising on failure."""
    print(f"  $ {' '.join(cmd)}", file=sys.stderr)
    result = subprocess.run(cmd, **kwargs)
    if result.returncode != 0:
        if kwargs.get("capture_output"):
            sys.stderr.write(result.stderr)
        raise RuntimeError(f"Command failed with exit code {result.returncode}: {' '.join(cmd)}")
    return result


def build_reference(go, toolchain, workdir):
    """Build the reference program; returns (binary path, `go version`, GOROOT)."""
    env = dict(os.environ, CGO_ENABLED="0", GOOS="linux", GOARCH="amd64")
    if toolchain:
        env["GOTOOLCHAIN"] = toolchain
    src = os.path.join(workdir, "ref")
    os.makedirs(src)
    with open(os.path.join(src, "main.go"), "w") as f:
        f.write(REFERENCE_PROGRAM)
    with open(os.path.join(src, "go.mod"), "w") as f:
        f.write("module ref\n\ngo 1.21\n")
    binary = os.path.join(workdir, "ref.bin")
    run([go, "build", "-o", binary, "."], cwd=src, env=env)
    version = run([go, "env", "GOVERSION"], cwd=src, env=env, capture_output=True, text=True)
    goroot = run([go, "env", "GOROOT"], cwd=src, env=env, capture_output=True, text=True)
    return binary, version.stdout.strip(), goroot.stdout.strip()


def read_facts(binary, goroot, workdir):
    """Ask the reader for every table's values: returns, by table name,
    (values by key, string tables by key) or the reasons it cannot be had."""
    reader = os.path.join(workdir, "reader")
    os.makedirs(reader)
    with open(os.path.join(reader, "main.go"), "w") as f:
        f.write(READER_PROGRAM)
    with open(os.path.join(reader, "go.mod"), "w") as f:
        f.write("module reader\n\ngo 1.21\n")
    events = os.path.join(goroot, "src", "internal", "trace", "tracev2", "events.go")
    requests = []
    for t in TABLES:
        n = t["name"]
        for key, struct, field in t.get("offsets", []):
            requests.append(f"offset {n}.{key} {struct} {field}".strip())
        for key, struct, field in t.get("lengths", []):
            requests.append(f"length {n}.{key} {struct} {field}")
        for key, name in t.get("constants", []):
            requests.append(f"const {n}.{key} {name}")
        for key, name in t.get("events", []):
            requests.append(f"event {n}.{key} {name}")
        for key, symbol in t.get("strings", []):
            requests.append(f"strings {n}.{key} {symbol}")
    # The reader is built with the Go on PATH: it only needs the standard library.
    out = run(
        ["go", "run", ".", binary, events],
        cwd=reader,
        input="\n".join(requests) + "\n",
        capture_output=True,
        text=True,
        env=dict(os.environ, GOTOOLCHAIN="local"),
    ).stdout
    values, strings, missing = {}, {}, {}
    for line in out.splitlines():
        if line.startswith("string "):
            m = re.match(r'string (\S+) (".*")$', line)
            strings.setdefault(m.group(1), []).append(m.group(2))
        elif line.startswith("missing "):
            _, key, why = line.split(" ", 2)
            missing.setdefault(key.split(".")[0], []).append(why)
        else:
            key, value = line.split()
            values[key] = int(value)
    found = {}
    for t in TABLES:
        n = t["name"]
        if n in missing:
            found[n] = missing[n]
            continue
        found[n] = (
            {k.split(".", 1)[1]: v for k, v in values.items() if k.startswith(n + ".")},
            {k.split(".", 1)[1]: v for k, v in strings.items() if k.startswith(n + ".")},
        )
    return found


def minor_of(version):
    m = re.match(r"go1\.(\d+)", version)
    if not m:
        raise RuntimeError(f"not a Go 1.x version: {version}")
    return int(m.group(1))


def rust_table(t, values, strings):
    """One table's module, its constants indented in it."""
    lines = [f"/// {t['about']}", f"pub mod {t['name']} {{"]
    offsets = t.get("offsets", []) + t.get("lengths", [])
    structs = list(dict.fromkeys(struct for _, struct, _ in offsets))
    for i, struct in enumerate(structs):
        lines += [f"    // {struct}"] if i == 0 else ["", f"    // {struct}"]
        for key, of, _ in offsets:
            if of == struct:
                lines.append(f"    pub const {key}: usize = {values[key]};")
    if t.get("constants"):
        lines += ["", "    // Constants"]
        for key, name in t["constants"]:
            ty = "u32" if key.startswith("G_") else "u64"
            lines.append(f"    pub const {key}: {ty} = {values[key]}; // {name}")
    if t.get("events"):
        lines += ["", "    // internal/trace/tracev2"]
        for key, name in t["events"]:
            lines.append(f"    pub const {key}: u8 = {values[key]}; // {name}")
    for key, symbol in t.get("strings", []):
        table = strings[key]
        lines += ["", f"    // {symbol}"]
        lines.append(f"    pub const {key}: [&str; {len(table)}] = [")
        lines += [f"        {s}," for s in table]
        lines.append("    ];")
    lines.append("}")
    return lines


def rust_file(version, found):
    lines = [
        f"// Auto-generated offset constants for Go {version}",
        "// Generated by scripts/generate_go_bindings.py",
        "// Target: linux/amd64",
        "//",
        "// DO NOT EDIT - regenerate with:",
        f"//   python3 scripts/generate_go_bindings.py {version}",
    ]
    for t in TABLES:
        lines.append("")
        what = found[t["name"]]
        if isinstance(what, list):
            lines.append(f"// No {t['name']} table: this runtime has " + "; ".join(what) + ".")
            continue
        lines += rust_table(t, *what)
    return "\n".join(lines) + "\n"


def update_mod_rs():
    modules = sorted(
        f[:-3] for f in os.listdir(OUTPUT_DIR) if f.startswith("v") and f.endswith(".rs")
    )
    with open(os.path.join(OUTPUT_DIR, "mod.rs"), "w") as f:
        f.write("".join(f"pub mod {m};\n" for m in modules))


def generate(go, toolchain):
    with tempfile.TemporaryDirectory() as workdir:
        binary, version, goroot = build_reference(go, toolchain, workdir)
        found = read_facts(binary, goroot, workdir)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    path = os.path.join(OUTPUT_DIR, f"v1_{minor_of(version)}.rs")
    with open(path, "w") as f:
        f.write(rust_file(version, found))
    print(f"wrote {os.path.relpath(path, REPO_ROOT)} ({version})", file=sys.stderr)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("versions", nargs="*", help="Go versions to fetch through GOTOOLCHAIN, e.g. go1.26.7")
    p.add_argument("--go", default="go", help="the go command to build with (default: go on PATH)")
    args = p.parse_args()
    for toolchain in args.versions or [None]:
        generate(args.go, toolchain)
    update_mod_rs()


if __name__ == "__main__":
    main()
