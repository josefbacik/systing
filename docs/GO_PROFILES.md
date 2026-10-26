# Go profiles from memory

A Go program keeps profiles of itself whether or not anyone asks: where its
memory was allocated (heap), where its goroutines waited on channels (block)
and on locks (mutex), and every goroutine's state and stack. Go hands them out
through `runtime/pprof`, which needs code in the program and usually a
`/debug/pprof` port. systing reads them out of the program's memory instead,
from outside: no port, no signal, no code of ours in the program, and the
program is not stopped.

**Status:** experimental. x86-64 and arm64, a program of the machine's own
architecture. Go 1.26 and 1.27; other versions are refused until they have
bindings (below). The reading is `systing::golang`
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
executable once, in bounded reads, for where the runtime keeps the running
goroutine (`g`, at a fixed distance from the thread pointer that the
program's own code loads it from; on arm64 in register x28, which the sampler
reads), and writes that, with the layout of its Go version, into a map the
sampler looks up. It does so only for a process whose
executable is mapped in its own memory: a process forked from a Go program
that never execs keeps the program's `exe` link, but not its memory (gVisor's
systrap stubs hold their sandboxed guest's). On x86-64 a position-independent
program is refused: it does not load `g` from a fixed offset.

A sample then reads `g`, its m (`g.m`) and the m's current goroutine
(`m.curg`): a thread on its system stack (a cgo call, the garbage collector's
work) counts for the goroutine it runs for, as in Go's own profiles, and
otherwise `g` must be `m.curg` itself, so words that only look like a `g` are
not believed. A goroutine's label set is copied at every sample of it into one
of the CPU's two copy records and named by a hash of what it holds: never by
its address, which Go reuses for the next request's set once a set is freed.
The copy goes to user space only when the process has not sent that set
before, inside a per-CPU budget that bounds what is sent, not what is read;
over the budget the sample still carries the set's id. At most eight labels a
set, keys cut at 64 bytes and values at 128. A sample whose set could not be
read carries the id `1`, and a set with no labels is no labels. Every miss is
counted, and printed at the end of the capture (`go_context samples:`), and
`sysinfo.go_context` says how the flag ran.

On a labelled workload (three goroutines under labels, one without) the CPU
sampler's mean run time, by the kernel's BPF statistics, went from 534 to 596
ns without the flag to 972 to 1,016 ns with it. That is a mean over all of the
sampler's runs, those that found no Go program included, on a machine with
few CPUs sampling. So on that machine the sampler's run on a labelled sample
takes at least 1 microsecond, of which the flag adds at least the difference,
0.4 to 0.5: floors, not measures.

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
twice per request.

`go-profile/e2e/run.sh` runs this comparison on a small workload linked by
Go's own linker and by the system linker (as distributions build Go
programs), each as built and stripped, and fails on any difference beyond
those (it needs Go 1.26 or 1.27, a C compiler and a build of the tool). CI
runs it with both on x86-64 and on arm64.

## How it works

`src/golang/` is built as `src/pystacks/` is for Python:

| File | What it does |
|---|---|
| `discovery.rs` | Opens a program: its Go version (`.go.buildinfo`), where the runtime's globals are, and how far it was loaded from its link addresses. Globals come from `.symtab`; a stripped binary has none, but its `.gopclntab` names every function, and each global is the first one a known runtime function loads (`runtime.memProfileInternal` loads `runtime.mbuckets`, and so on), read from the file's code: a RIP-relative load on x86-64, an `adrp` pair on arm64. |
| `offsets.rs`, `bindings/` | The runtime's struct layouts per Go version, generated (below). |
| `profiles.rs` | The heap, block and mutex bucket lists, turned into what pprof writes: the heap as of the last finished GC cycle and scaled as Go scales it (a bucket's bytes are its objects times its object size), delays from CPU ticks to nanoseconds. |
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
python3 scripts/generate_go_bindings.py go1.27.2     # fetches that toolchain
python3 scripts/generate_go_bindings.py --go /path/to/go
```

The script reads the program built for amd64 and for arm64, and refuses to
write a file if they disagree: one file serves both. Each reader has a table
of its own in that file (`TABLES` in the script),
written only when everything it names is in that runtime. So a struct that
changed shape (a field gone, not moved) leaves out only the table of the
reader that reads it, until its code follows, and the other readers can take
the new version at once. A new version is then a line in
`offsets::for_version` (or the other reader's lookup). A version with no table
for a reader is refused when the program is opened, never read with another
version's numbers, and so are release candidates and experiment builds
(`go1.26rc1`, `go1.26.0-X:...`).

## Limits

- `systing-go-profile` caps its own address space, at 4 GiB unless
  `--max-memory-mib` says otherwise (0: no cap), because a target's memory
  decides how much it allocates. At the cap it aborts; the target is not
  touched. It also refuses a profile of more than 2^22 frames, each stack
  counted as eight more and every 64 bytes of a frame's names as one more.
- On a Go program or profile, `systing-heap` has no overall limit on memory
  or time. Where that input isn't trusted, run it under a cgroup memory limit
  and `timeout`.
- x86-64 and arm64 only: stripped binaries are read by instruction encoding,
  and the bindings are for linux/amd64 and linux/arm64.
- On x86-64, `--include-go-context` gives no goroutine for a
  position-independent Go program (`-buildmode=pie`, the default of some
  distributions). On arm64 it gives none for a sample in C code that has taken
  x28 for itself.
- Function names only: no line numbers, and inlined calls are not expanded
  (the function table has both; they are not decoded yet).
- `systing-go-profile` reads no pprof labels (`--include-go-context` does,
  on CPU samples), and has no stack for a goroutine that is running.
- A flight recorder's window above 1 GiB, or of more than 2^20 batches, is
  refused. The limit is this reader's own: Go sets none.
- Block and mutex profiles are empty until the program sets their rates,
  whichever way they are read. The heap profile is off in a program that
  never links Go's profile code: its linker sets `MemProfileRate` to 0, after
  `GODEBUG` is read, so `GODEBUG=memprofilerate` does not turn it on. Code
  that calls `runtime.MemProfile` turns it on (a blank import of
  `net/http/pprof` links such code; one of `runtime/pprof` does not), and so
  does setting `runtime.MemProfileRate` in the program (then only a binary
  that keeps its symbol table can be read). A heap read of such a program
  says so.
