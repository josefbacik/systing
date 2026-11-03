# Python function trace

The `python-function-trace` recorder records every entry to and every exit from
a Python function in the processes a capture targets, so each call becomes a
row of `python_function_slice`, and a slice on its thread's timeline. It works
with or without perf trampolines and does not use ptrace.

```
# these processes, and what they fork, for ten seconds
sudo systing --only-recorder python-function-trace --pid 1234 --pid 1250 -d 10

# every Python process of a cgroup, beside the usual recorders
sudo systing --add-recorder python-function-trace --cgroup /sys/fs/cgroup/app -d 10

# a command
sudo systing --only-recorder python-function-trace -d 10 -- python3 app.py
```

**It slows what it traces, many times over** (see [What it costs](#what-it-costs)).
It is for a short, deliberate look at a process, so it is off by default, and
takes no default target: `--pid`, `--cgroup` or a command is required, and with
both `--pid` and `--cgroup` only processes in both are traced. It cannot run with
`--continuous`.

## Why

systing sees Python through *samples*: many times a second it asks which
Python functions are on a thread's stack. Samples say where time goes on
average. They do not say when a particular call began or ended, how often a
function was called, or in what order things happened. A request that was
slow once in a thousand, a function called a million times for a microsecond
each, a coroutine resumed forty times: none of these can be read off samples.

It is built to three constraints:

1. **No ptrace, and no code of ours in the process.** Nothing is injected, no
   library is loaded, no Python object is changed, and the interpreter's file
   is not modified. The kernel does change the process's memory while the
   probes are in: it puts a one-byte breakpoint into a private copy of each
   probed page of the interpreter's code (11 or 12 places), and it maps one
   extra page, `[uprobes]`, from which the displaced instructions are run.
   That page stays mapped until the process exits. A thread that reaches a
   probe enters the kernel twice; no thread is stopped otherwise.
2. **With or without trampolines.** Perf trampolines are off by default and can
   only be switched on from inside the process. The trace is the same either way.
3. **Current Pythons.** CPython 3.12, 3.13 and 3.14.

## What it records

`python_function_slice` (`ts`, `dur`, `utid`, `depth`, `function`, `file`,
`line`, `end_kind`), one row per run of a frame. A generator or coroutine is one
row per resumption, ending in `yield` until the last, so a slice is always time
the function was actually running. `end_kind` is `return`, `yield`, `unwound`
(no exit event: an exception, usually) or `open` (still running when the trace
ended). `line` is the function's first line.

```sql
-- The functions that took longest, by process
SELECT p.name, s.function, count(*) AS runs, sum(s.dur) / 1e6 AS total_ms
FROM python_function_slice s
JOIN thread t ON t.trace_id = s.trace_id AND t.utid = s.utid
JOIN process p ON p.trace_id = t.trace_id AND p.upid = t.upid
GROUP BY 1, 2 ORDER BY 4 DESC LIMIT 20;
```

A Perfetto output shows them as a `Python Functions: <thread>` track under each
thread. `sysinfo` says what became of the trace: `python_function_processes`,
`python_function_events`, `python_function_no_thread_state`,
`python_function_lost_events`, `python_function_symbol_records_dropped`,
`python_function_cap_reached`, and `python_function_notes`, a line for each process
not traced and why (a `--pid` that was never a Python or never there among them),
for why the recorder was off if it was, and for each thing that could make the
trace wrong. Events lost to a full ring are the `python function` class of the
capture's missed-events tracks, and of its closing lines. All of the columns are
NULL for a capture without the recorder.

## Which processes

At the start of the capture the recorder looks at its targets: the `--pid` and
`--cgroup` processes. After that the capture's own fork and exec events tell it of
a new one, as they tell pystacks, so `--collect-pystacks` is on with this recorder.
It also goes through the capture's target set twice a second, and with `--cgroup` the
cgroups once a second, for what no event told of, such as a process moved in.
Each process that is a Python it can read gets its 11 or 12 probes. As with every
recorder, a `--pid` target's children are targets if they fork during the capture.
A process's frames that are already running stay invisible until they return. The
frames of a process that execs end there, as `unwound`. For a traced command, what
runs before its probes are in is not traced: its first few tens of milliseconds,
and all of a command that is over by then.

Probes check the target set as every recorder's do, so a process that leaves a
`--cgroup` target stops being recorded at once, though it pays until the capture
ends.

If the recorder cannot run (the kernel's confidentiality mode, or its BPF object
does not load, as on arm64 today) the capture goes on with its other recorders and
`python_function_notes` says why.

A process is refused, with its reason in `python_function_notes`, for: a build
with no dispatch table, a free-threaded build, a pre-release, a Python outside
3.12 to 3.14, a process on musl libc, a thread id given for a process, or more
than 64 processes in one capture. A refusal does not fail the capture.

Reaching `--python-function-max-slices` (5,000,000 by default) takes the probes
out at once, since past it every traced process would pay for nothing. The
capture goes on, and `python_function_cap_reached` says so. The slices kept are
those begun first, in time, over all processes, and the frames open at that point
end there. A capture never holds more than the cap.

## How it works

Uprobes sit on the bytecode loop's own handlers for the few opcodes that
begin, end, suspend and resume a frame. A uprobe is a kernel breakpoint on an
instruction of a file; a BPF program runs when a thread reaches it. Every
Python frame runs these opcodes however it was called, so the same probes
see every frame with trampolines on or off.

### Where the probes go

CPython's bytecode loop reaches the code for each opcode by an indirect jump
through a table of 256 addresses, one per opcode number (`opcode_targets`, a
static table inside `_PyEval_EvalFrameDefault`). That makes these addresses
dependable where function symbols are not: a handler cannot be inlined away,
because the jump needs an address to go to.

| Event | Opcodes probed | What it means |
| --- | --- | --- |
| enter | `RESUME`, `RESUME_CHECK` (3.13+), `INSTRUMENTED_RESUME` | First thing a function body runs, and first thing a generator or coroutine runs after each `yield`/`await`. |
| exit | `RETURN_VALUE`, `RETURN_CONST` (3.12, 3.13), and their `INSTRUMENTED_` forms | The frame returns. |
| yield | `YIELD_VALUE`, `INSTRUMENTED_YIELD_VALUE` | A generator or coroutine frame suspends. |
| handler | `PUSH_EXC_INFO`, `CLEANUP_THROW`, `END_ASYNC_FOR`, `INSTRUMENTED_END_ASYNC_FOR` (3.14) | An `except`/`finally`/`with` handler starts in a frame: every frame the exception unwound is gone. |

Eleven or twelve probes per traced process, fewer where two opcodes share a
handler.

### How the table is found, and checked

From the interpreter's file alone, by shape: 256 consecutive pointers into
executable code, at least 100 of them into `_PyEval_EvalFrameDefault` (a
compiler moves rarely used handlers to a cold section outside the function).
A symbol for the table, where a build kept one, names the window. Which entry
is which opcode comes from a small per-version list of opcode numbers.

Before any probe goes in, the build must pass three checks, or the tool
refuses rather than guesses:

- The file's own `Py_Version` must name the minor version discovery found,
  and a final release (pre-releases renumber opcodes).
- `_PyRuntime`'s debug offsets must not say free-threaded: those builds lay
  out their objects otherwise.
- The table's slots on the unknown-opcode handler must be exactly the numbers
  the version leaves unassigned (63 in 3.12, 44 in 3.13, 29 in 3.14). A wrong
  list or a shifted window fails this.

Reading the file is limited, since it is the traced process's choice and the
tool runs as root. Refused before or while parsing: anything but a 64-bit ELF
file with a dynamic symbol table, a file over 512 MiB (and 512 MiB for all
of one process's files together), more than 128 sections (counted from the
raw header first), 64 executable ranges, 8 candidate tables, 64 MiB of data
sections or 64 MiB of dynamic relocation sections. A refused file's reason is
the tool's error. These limit what one file can make the tool read; they are
not a cap on the tool's own memory: a crafted file within them can still make
the parser use around a hundred times its size. The file is the one the process
has mapped, opened once through `/proc/PID/map_files`; the parse and the
probes go through that one descriptor.

| Interpreter | Build | Table |
| --- | --- | --- |
| 3.12.3, Ubuntu `/usr/bin/python3.12` and `libpython3.12.so.1.0` | gcc, stripped executable | found by shape (181 of 256 handlers in the function) |
| 3.13.15 (pyenv), `libpython3.13.so` | clang 18, PGO + LTO | found, symbol agrees |
| 3.14.7 (nix), `libpython3.14.so` | gcc 15, LTO | found, symbol agrees |

A reviewer ran the finder over 21 more files: it finds the right table in
every computed-goto build as shipped (gcc and clang, with and without PGO,
LTO and BOLT; a BOLT executable stripped of its symbols is not found), and
none in the tail-calling builds that uv installs for 3.14 and
3.15, which `auto` therefore refuses.

### What a probe does

In the traced thread's own context, one program for every site of every process:

1. Find the thread's Python thread state through its thread-local storage, as
   the stack sampler does, and read the current frame from it.
2. For an entry or a handler: read the frame's code object and look its address
   up in a per-CPU cache, checked against three words of the object. On a miss,
   read the function's qualified name and file, hash them into pystacks' symbol
   id and send the names to user space, again every 100 ms until user space has
   them.
3. Write one event (time, thread, frame address, symbol, kind; 48 bytes in the
   ring) to this CPU's ring. The reader polls; the traced thread never pays for a
   wakeup.

### Locks

The rule is the samplers' (`src/pystacks/bpf/pystacks.bpf.c`): a probe takes no
lock that another CPU is using. A waiter on a contended map or ring lock can halt
its vCPU with interrupts off, and on a hypervisor that drops the kick that wakes
it, stay halted. These probes run with interrupts on, but the kernel turns them
off itself to wait for those locks.

So the rings are a family like any other's, per CPU, `cpu % nr_rings`, at the sizes
of `--ringbuf-size-mib` and `--ringbuf-shards`, with the same pollers and the same
half-full wakeup. Names go on them too, and on to pystacks' resolver. The code cache
and every counter are per-CPU arrays. Only user space writes a hash map. None of
this depends on how many processes are traced or how many GILs they have, which
is why several processes, and sub-interpreters, are safe. On a host with more
than 64 CPUs some CPUs share a ring, as they do for every recorder.

These programs run with preemption on, so two can be under way on one CPU. The
one path that writes per-CPU scratch or a cache entry runs alone on its CPU; a
miss that meets another on its CPU goes without a name for that one event.

Events reach the reader by CPU and a thread moves between CPUs, so a thread's
events are not in order as they are read. The recorder keeps them and sorts and
pairs each thread's when the capture ends, as the task-stacks recorder keeps its
events to the end.

### From events to slices

A thread's events arrive in order, so a stack of open frames per thread pairs
them. The frame's address is the identity. Events from while the probes are
going in are dropped: a frame running then would otherwise end as though an
exception had taken it.

| Event | Rule |
| --- | --- |
| enter of frame F | If F is already open, that frame is gone (see exceptions): close it and everything above it. Open F. |
| exit or yield of F | Close everything above F as *unwound*, then F as *return* or *yield*. F not open: count it and move on. |
| handler starts in F | Close everything above F as *unwound*. F not open (a coroutine resumed by an exception thrown into it runs no `RESUME`): open it. |

An exception that leaves a frame produces no exit event. The frame is closed
when the exception is caught in Python (exact to within the unwinding).
If C code swallowed it (a `__getattr__` raising `AttributeError` under
`hasattr`), the dead frame is closed at the next entry on the same address or
the next event of a frame below it: usually the thread's next event, but a
generator or coroutine resumed in between is shown inside the dead frame. A
frame from before the trace that catches its callees' exceptions, and an
await chain cancelled or timed out, can also come out with wrong parents or
ends. A slice the tool closed without an exit event is marked `unwound`, but
a wrong parent is not marked. In a reviewer's replay of three real
programs (1.9 million slices), 12 slices came out wrong, all after one
`asyncio.wait_for` timeout.

A generator or coroutine is one slice per resumption, ending in `yield` until
the last, so a slice is always time the function was actually running.

## What it costs

Measured on one x86-64 host, Linux 6.12, CPython 3.13.15 (clang, PGO + LTO),
best of three runs, against a process with no probes:

| Workload | Untraced | Traced |
| --- | --- | --- |
| 2,000,000 calls of a one-line function, nothing else | 0.068 s (34 ns a call) | 5.37 s (2.7 µs a call, 79x) |
| Mixed: JSON, regex, hashing, sorting, per-record Python functions (624,000 events) | 0.36 s | 1.09 s (3.0x) |

- **About 1.3 µs per event, two events per call** on that host; 4.2 µs on a KVM
  guest with no nested acceleration. The BPF program is about 0.2 µs of it. The
  rest is the kernel's breakpoint: a trap, then single-stepping the displaced
  instruction, which is a second trap.
- It is paid by every Python function call in a traced process while the probes
  are in: only those processes pay, each for its own calls.
- **The reported times include it.** The time stamp is taken in the first trap,
  so each slice holds about one event's cost of its own and its caller's self
  time the other. Ranking by self time therefore favours functions that are
  called often or call often.
- For scale, hooks *inside* the process on the same loop: `cProfile` adds
  0.14 µs a call, `sys.monitoring` with Python callbacks 0.09 µs. That is the
  price of constraint 1.
- Removing the probes takes a fraction of a second; the process pays for any hit
  until the last probe is out. They come out before anything is written.

Where function traces are wanted often, or on hot paths, and the service can load
a module, a hook inside the process is 10 to 30 times cheaper and gives exact
exception exits. This recorder is what works on a process that was not prepared.

## Limits

| Limit | Note |
| --- | --- |
| A process checkpointed with CRIU | The `[uprobes]` page stays after the trace, and CRIU refuses it (or the restored process gets SIGTRAP if it was dumped with a probe in). |
| Frames already running when the process's probes go in | Invisible until they return; their callees are traced. |
| greenlet and gevent | A switch between greenlets runs no probed opcode, so frames that are only switched out end as `unwound` and their callers' times are wrong. Noted in `python_function_notes`. Real support needs a stack per greenlet. |
| Only Python functions | Calls into C (builtins, extension modules) are not events. |
| Builds with no dispatch table | Built without computed gotos, or with the tail-calling interpreter (uv's 3.14 and 3.15 builds, a 3.14 option with clang 19+): refused. |
| The JIT | Calls inside JIT-compiled code are not seen (`PYTHON_JIT=1`; noted). |
| Python 3.15 | Needs its opcode list, and a new way to the thread state: 3.15 drops the `autoTSSkey` that pystacks finds it through. |
| A capture outside the host's pid namespace | Refused: the probes see the initial namespace's process ids. |
| Only the executable and `libpython*` are looked at | An interpreter in another library, or a file replaced on disk, is not found. A library loaded long after the process starts is found only if its process execs again. |
| Names | Qualified names are cut at 128 bytes, file names keep their last 192; the code-object cache can, rarely, give a function the name of a dead one whose addresses it reuses. |
| A re-dispatched `RESUME` shows as an extra sub-microsecond `unwound` slice | After instrumentation changes (cProfile, coverage, a debugger), at the next start of each function. |
| The interpreter's own `__init__` clean-up frames return without having entered (3.13+) | Counted and ignored. |
| On kernels 6.6 and 6.12 every probe hit takes the process's `mmap_lock` for reading | A call can wait in the trap behind a writer of that lock, holding the GIL. |
| Memory | The rings are kernel memory; the events are kept in memory until the capture ends, about 80 bytes a slice, with no spill to disk. |

## Code

| File | What |
| --- | --- |
| `src/bpf/python_function_trace.bpf.c` | The probe program, an object of its own loaded only when the recorder runs. Compiles pystacks into itself, as the task-stacks recorder does, for the thread-state lookup and symbol records. |
| `src/python_function_trace/sites.rs` | Finds and checks the dispatch table and the probe offsets in an interpreter file. |
| `src/python_function_trace/pairing.rs` | Events to slices. |
| `src/python_function_trace/mod.rs` | The recorder: attaches to the processes it is told of, keeps the events, writes the rows. |
| `tests/python_function_trace.rs` | The end-to-end tests, with `tests/python_function_trace/workload.py`. |

The load-shape gate (`tests/bpf_load_shapes.rs`, `every_shape_loads`) loads the
object on every kernel of CI's guest matrix, and the stack-budget test adds up
its frames.

## Next

1. **Seed open frames** at attach from a stack walk, and pair by the
   interpreter's frame depth as well as by address, which repairs the exception
   cases above in a reviewer's emulation.
2. **A duration threshold in BPF**: keep the stack of open frames in the probe and
   emit only slices over a threshold. It lowers what is recorded, not what the
   process pays.
3. **Cheaper entry probes.** The kernel emulates a few instruction kinds (branches,
   `push`) instead of single-stepping them; the entry handlers have a conditional
   jump early on, and a probe there should save about 0.6 µs on half the events.
4. **One attach and one detach per process**, with uprobe-multi links (6.6+).
5. **Take the probes' own cost out of the times** with a per-host calibration.
