# Go profiles from memory

A Go program keeps profiles of itself whether or not anyone asks: where its
memory was allocated (heap), where its goroutines waited on channels (block)
and on locks (mutex), and every goroutine's state and stack. Go hands them out
through `runtime/pprof`, which needs code in the program and usually a
`/debug/pprof` port. systing reads them out of the program's memory instead,
from outside: no port, no signal, no code of ours in the program, and the
program is not stopped.

**Status:** experimental. Go 1.26 on x86-64 only; other versions are refused
until they have bindings (below). The reading is `systing::golang`
(`src/golang/`); two commands use it:

- `systing-heap --pid PID --snoop` on a Go program: its heap profile, into the
  heap tables or a Perfetto trace like any heap snapshot (`heap/README.md`).
  `systing-heap` also reads Go's own heap profile files (`.pb.gz`).
- `systing-go-profile` (`go-profile/`, a workspace package of its own, so
  installing systing does not install it): every profile, and the flight
  recorder.

```
cargo build --release -p systing-go-profile -p systing-heap

systing-go-profile snoop --pid PID --profile heap        # or goroutine, block, mutex
systing-go-profile snoop --pid PID --profile goroutine --each
systing-go-profile flight --pid PID --out trace.out      # then: go tool trace trace.out
systing-go-profile pprof heap.pb.gz                       # a pprof file, printed the same way
systing-heap -o heap.duckdb --pid PID --snoop
```

`snoop` and `pprof` print JSON lines: a header, then one object per stack
with its values (in pprof's order and units) and its frames, leaf first;
`snoop -o FILE` writes the profile as a pprof file instead (gzipped
`profile.proto`, as `/debug/pprof/<profile>` serves it), which `go tool pprof`
and any other pprof tool read. A goroutine profile written so also has a
`state` label on each stack: the wait reason, or the state of a goroutine
that is not waiting.
Reading memory needs the program's own user or `CAP_SYS_PTRACE`, as for
`--snoop` of jemalloc.

## Goroutines and labels on CPU samples

`systing --include-go-context` reads, for every CPU sample of a Go program,
the goroutine that was running and its profiler labels (`pprof.Do`,
`SetGoroutineLabels`), from inside the sampler:

- `stack_sample.go_goid`: the goroutine, Go's own id for it;
- `stack_sample.go_labels_id`: the id of its label set, and the set itself,
  once per process, in the `go_labels` table (`SCHEMA_CHANGES.md`, schema 30).

```sql
SELECT l.name AS key, l.value_str AS value, count(*) AS samples
FROM stack_sample s
JOIN thread t ON t.trace_id = s.trace_id AND t.utid = s.utid
JOIN go_labels l ON l.trace_id = s.trace_id AND l.upid = t.upid AND l.id = s.go_labels_id
GROUP BY 1, 2 ORDER BY 3 DESC;
```

It is built as `--include-task-context` is (`src/golang/context/`,
`src/golang/bpf/go_context.bpf.h`). User space reads each Go program's
executable once for where the runtime keeps the running goroutine (`g`, at a
fixed distance from the thread pointer that the program's own code loads it
from) and writes that, with the layout of its Go version, into a map the
sampler looks up. A sample then costs three reads of the program's memory: `g`,
its id, its labels' address. A thread's label set is copied only when its
goroutine or set changes; a copy is named by a hash of what it holds (Go reuses
a freed set's memory for the next request's), and goes to user space only if
the process has not sent that set before. At most eight labels a set, keys cut
at 64 bytes and values at 128. Every miss is counted, and printed at the end of
the capture (`go_context samples:`).

## What it matches

On a test program (Go 1.26.7, 10,000 idle goroutines, a garbage collection
every two seconds or so, lock and channel waits), each profile was read from
memory, fetched from the program's own pprof port, then read from memory
again, on a normal and a stripped build:

| Profile | Against Go's own |
|---|---|
| Heap | Identical: every stack and every number |
| Mutex, block | The same stacks and counts; delays within about 30 ns in 15 s. They are CPU ticks turned into nanoseconds, and until the program has worked out its tick rate (the first time it is asked for one of these profiles) the reader works the rate out itself, a moment apart |
| Goroutines | All but the few running at that instant (10,022 of 10,027): a running goroutine's registers are on a CPU, not in memory |
| Flight recorder | Byte-identical to the program's own `WriteTo`, about 0.7 s behind it; only if the program runs one |

Reading never pauses the program; Go's own goroutine profile stops the world
twice per request. 10,000 goroutines take about 25 ms to read.

`go-profile/e2e/run.sh` runs this comparison on a small workload, normal and
stripped, and fails on any difference beyond those (it needs Go 1.26 and a
build of the tool; no root).

## How it works

`src/golang/` is built as `src/pystacks/` is for Python:

| File | What it does |
|---|---|
| `discovery.rs` | Opens a program: its Go version (`.go.buildinfo`), where the runtime's globals are, and how far it was loaded from its link addresses. Globals come from `.symtab`; a stripped binary has none, but its `.gopclntab` names every function, and each global is the first one a known runtime function loads (`runtime.memProfileInternal` loads `runtime.mbuckets`, and so on), read from the file's code. |
| `offsets.rs`, `bindings/` | The runtime's struct layouts per Go version, generated (below). |
| `profiles.rs` | The heap, block and mutex bucket lists, turned into what pprof writes: the heap as of the last finished GC cycle and scaled as Go scales it, delays from CPU ticks to nanoseconds. |
| `goroutines.rs` | `runtime.allgs`: each goroutine's state, wait reason and since when, and its stack by frame pointers from where it stopped. |
| `flight.rs` | The flight recorder's finished generations, copied batch by batch, again if the recorder swapped its ring meanwhile. |
| `symbols.rs` | Names from the program's own function table, which every Go binary keeps. |
| `pprof.rs` | Go's profile file format. |

Memory is read through `/proc/PID/mem` with the reader the Python walker uses
(`pystacks::process`). The program runs on while it is read: a record that
cannot be right (more frees than allocations, a stack deeper than the runtime
keeps) is skipped and counted.

## Go versions

The runtime's structs are private and change between minor releases (Go
1.27's heap record is half the size of 1.26's). Their layouts are not written
by hand: `scripts/generate_go_bindings.py` builds a small program with the Go
asked for and reads, from its DWARF and its data, every offset, constant,
goroutine state name and wait reason the readers use, into
`src/golang/bindings/v1_<minor>.rs`:

```
python3 scripts/generate_go_bindings.py go1.27.1     # fetches that toolchain
python3 scripts/generate_go_bindings.py --go /path/to/go
```

A new version is then a line in `offsets::for_version`, and a struct that
changed shape (a field gone, not moved) a change to its reader. A version with
no bindings is refused when the program is opened, never read with another's.

## Limits

- x86-64 only: stripped binaries are read by instruction encoding, and the
  bindings are for linux/amd64.
- Function names only: no line numbers, and inlined calls are not expanded
  (the function table has both; they are not decoded yet).
- `systing-go-profile` reads no pprof labels (`--include-go-context` does,
  on CPU samples), and has no stack for a goroutine that is running.
- Block and mutex profiles are empty until the program sets their rates, and
  the heap profile is empty in a program that never links Go's profile code
  (`GODEBUG=memprofilerate` turns it on), whichever way they are read.
- A stripped program linked by the system linker (external linking, as many
  distribution builds are) is named from the wrong base by the function-table
  reader systing shares; that needs fixing in `crates/gopclntab` first.
