# Python function trace

`systing-python-function-trace` records every entry to and every exit from a
Python function in a process, so each call becomes a slice on its thread's
timeline. It works with or without perf trampolines and does not use ptrace.

**Status:** experimental. It is a tool of its own, in a workspace package of
its own (`python-function-trace/`), so installing systing does not install
it. It is not yet a recorder of a systing capture, and it has run only on
x86-64, Linux 6.12, with CPython 3.12, 3.13 and 3.14. It is not for
production hosts until it is a recorder: a run by hand stands outside the
limits, audit and requester checks a capture service applies, and it slows
the traced process while its probes are in.

## Why

systing sees Python through *samples*: many times a second it asks which
Python functions are on a thread's stack. Samples say where time goes on
average. They do not say when a particular call began or ended, how often a
function was called, or in what order things happened. A request that was
slow once in a thousand, a function called a million times for a microsecond
each, a coroutine resumed forty times: none of these can be read off samples.
A function trace records them.

It is built to three constraints:

1. **No ptrace, and no code of ours in the process.** Nothing is injected, no
   library is loaded, no Python object is changed, and the interpreter's file
   is not modified. The kernel does change the process's memory while the
   probes are in: it puts a one-byte breakpoint into a private copy of each
   probed page of the interpreter's code (11 or 12 places), and it maps one
   extra page, `[uprobes]`, from which the displaced instructions are run.
   That page stays mapped until the process exits. A thread that reaches a
   probe enters the kernel twice, for about 1.3 µs in all; no thread is
   stopped otherwise. (`--mode eval-frame` also rewrites a return address on
   the thread's stack, and `-- command` holds the new process with SIGSTOP
   until the probes are in.)
2. **With or without trampolines.** *Perf trampolines* are small pieces of
   machine code CPython can generate, one per Python function, so that native
   profilers see Python frames (`python -X perf`, `PYTHONPERFSUPPORT=1`). They
   are off by default and can only be switched on from inside the process.
   The trace works the same in a process that has them and in one that does
   not.
3. **Current Pythons.** CPython 3.12, 3.13 and 3.14.

## Using it

It needs root (it loads BPF programs and places uprobes), and it is built on
its own: `cargo build --release -p systing-python-function-trace`.

```
# a running process, for five seconds
sudo systing-python-function-trace --pid 1234 --duration 5 -o trace.pb

# a command, from its first call (held with SIGSTOP until the probes are in),
# to its end rather than the 10 s default
sudo systing-python-function-trace --duration 0 --slices slices.tsv -- python3 app.py

# statistics for every call, slices kept only for calls of 1 ms and more
sudo systing-python-function-trace --pid 1234 --duration 30 --min-duration-us 1000
```

Every Python call of the traced process pays for the probes while they are
in, so a trace is bounded: by `--duration` (10 s unless given; `0` means until
Ctrl-C or the process exits), and by `--max-slices`, whose cap ends the trace.
SIGINT, SIGTERM and SIGHUP each end it with its files written (the files
first, then the summary on stdout). The summary says which of these ended
it. One process at a time (see
[Limits](#limits)).

Output files are written as root, so their names cannot be used to steer a
write elsewhere: the directory must belong to root, the caller or the user
who ran `sudo`, and not be open to renames by others (a sticky directory such
as `/tmp` is fine), and an
existing entry at the name must be the caller's own regular file with one
link (no symlink, hard link, FIFO or device).

| Output | What |
| --- | --- |
| Summary (stdout) | What was attached and how, why the trace ended, event counts, what was lost or inferred, and the functions by self time. |
| `-o FILE` (default `python-function-trace.pb`) | A Perfetto trace: the slices on each thread's track, each named after its function, with `file`, `line` (the function's first line), `language` and `end` (how it ended) as its arguments, as task stacks show their frames. A track of its own, `python-function-trace`, carries the mode, why the trace ended and every loss counter. Opens at ui.perfetto.dev. |
| `--slices FILE` | One line per slice, tab-separated: pid, tid, start, duration, depth, how it ended, function, file, line. |

Before the probes go in, the tool says on stderr which mode it attaches and
what could make the trace wrong for this process: greenlet loaded,
`PYTHON_JIT` set, or eval-frame sites (which it refuses where greenlet is
loaded, or where its maps cannot be read in full). Since a command is held
before its first import, it looks for greenlet again while the trace runs
(at 100 ms, then once a second) and at the end, in the process's maps and in
the trace's own file names; the warnings go into the summary and the
Perfetto file too. For `-- command` the eval-frame refusal can only use what
is mapped before the first import.

Names the traced process chooses (functions, files, threads, paths) are
printed with control and other non-printing characters escaped, so they
cannot drive a terminal or add a column or line to the table.

With `-- command`, the command must be, or exec, the interpreter. It runs as
the tool's user (root) and dies with the tool (unless it changes its user or
group, which clears that). If the trace ends first, the outputs are written,
then the command gets SIGINT and 5 s before SIGKILL, and the tool exits with
its exit code, or 128 plus the signal that ended it. If the tool fails before
the trace begins, the command is killed.

`--mode` chooses where the probes go: `auto` (the default) is `dispatch`, and
refuses with the reason where there are no dispatch sites; it never falls
back to `eval-frame` on its own. See
[Two kinds of probe site](#two-kinds-of-probe-site).

The summary of a run of the test script described below, on Ubuntu's Python
3.12 (most of a 0.2 s run is imports, so the script's own functions are far
down the list):

```
pid 4242 (python3.12): Python 3.12, dispatch sites in /usr/bin/python3.12
  dispatch table at 0x784760 (found by Shape); 11 probes: RESUME, INSTRUMENTED_RESUME, RETURN_VALUE, ...
0.213 s traced, until the traced process exited: 56221 events (27914 entries, 27203 returns, 495 yields, 609 handler starts), 263810 events/s
27914 slices of 987 functions on 4 threads; 27914 kept
  216 slices with no return event (an exception, or a lost or unseen event)

    slices      self ms     total ms     avg us     max us  function
        77        8.728        8.855     115.00     1163.2  _compile_bytecode [<frozen importlib._bootstrap_external>:751]
       154        5.084        5.084      33.01       93.6  FileLoader.get_data [<frozen importlib._bootstrap_external>:1183]
        13        4.134       13.604    1046.48     2288.3  enum:EnumType._convert_ [enum.py:919]
       274        4.134      507.450    1852.01   110301.7  _call_with_frames_removed [<frozen importlib._bootstrap>:480]
        20        4.044        8.223     411.17      928.9  enum:_simple_enum.<locals>.convert_class [enum.py:1708]
```

Times include the probes' own cost (see [What it costs](#what-it-costs)), and
"total" sums every slice, so a recursive function counts its inner calls
again.

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

In the traced thread's own context:

1. Find the thread's Python thread state through its thread-local storage, as
   the stack sampler does, and read the current frame from it. (The frame is
   in a register at these addresses, but which one depends on the compiler.)
2. For an entry or a handler: read the frame's code object and look its
   address up in a cache, checked against three words of the object. On a
   miss, read the function's qualified name and file, hash them into
   pystacks' symbol id and send the names to user space, again every 100 ms
   until user space has them.
3. Write one event (time, thread, frame address, symbol, kind; 56 bytes in
   the ring) to a ring buffer. The reader polls; the traced thread never pays
   for a wakeup.

Names and first line numbers come from the probe. Everything else comes from
`/proc/PID` (`maps`, `exe`, `map_files`, `status`, `stat`, `comm`,
`task/TID/comm`, and the first MiB of `environ`) and the interpreter's file. (Process discovery is pystacks', which on 3.13+ also tries
one read of `/proc/PID/mem` for the GIL's address; the function trace does
not use the result and works when that read is refused.)

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

### Two kinds of probe site

**Dispatch sites** (the opcode handlers above) are the mechanism, with or
without trampolines.

**Eval-frame sites** are a uprobe on entry to `_PyEval_EvalFrameDefault` and
a uretprobe on its return, for Python 3.12 and later. While trampolines are
on, every Python call goes through that function, so these need no table and
no opcode numbers, and they cost less per event on a build whose function
begins with a `push` (the kernel emulates it instead of single-stepping it).
Only `--mode eval-frame` uses them, never `auto`, because:

| Limit of eval-frame sites | Measured |
| --- | --- |
| Without trampolines they see only calls made from C | 3 of 713 calls of a plain function |
| The kernel keeps at most 64 nested uretprobes per thread; deeper returns are not reported | recursion 150 deep, 20 times: 1,260 of 3,020 returns (`uprobe: omit uretprobe due to nestedness limit` in the kernel log) |
| They see only what the trampolines see | 3.13 with `-X perf`: 2 of 25 `__init__` calls (the interpreter's fast path for constructing an object bypasses the frame evaluator there; 3.12 and 3.14 show all 25) |
| A uretprobe rewrites a return address on the thread's stack | A return that finds no record gets SIGILL from the kernel, which kills a process that switches C stacks (greenlet, fibers); the tool refuses eval-frame sites where greenlet is loaded. Not run here. Kernels 6.11 to 6.12.13 and 6.13 to 6.13.2 also segfault a process whose seccomp filter refuses the return probe's system call (CVE-2025-21834). |
| A yield and an exception both look like a return | No `yield` end kind; `unwound` only where a return probe's record was lost |

### Why not something simpler

| Alternative | Why it was not used |
| --- | --- |
| systing's Python stack sampler (pystacks) | Samples, not entries and exits. |
| `sys.setprofile`, `sys.monitoring` (PEP 669) | The right tool from *inside* a process, and cheap (see the cost below). But a hook has to be installed by code running in the process: either the service imports something, or it is injected, which is ptrace-class access (`sys.remote_exec` in 3.14 writes the target's memory). |
| CPython's USDT probes `function__entry` / `function__return` | Gone in practice. Ubuntu's 3.12, built with them, carries five probes (`gc`, `import`, `audit`) and none for functions; the 3.14 source still declares the two and never fires them. |
| A uprobe and uretprobe on `_PyEval_EvalFrameDefault` alone | Since 3.11 a Python function calling a Python function does not call it: the bytecode loop pushes the new frame and carries on (the eval-frame sites above). |
| Perf trampolines themselves | They make samples readable; they are not a trace. They live in anonymous memory, where a uprobe cannot be placed. |
| Uprobes on interpreter helpers (`_PyEval_FrameClearAndPop`, `PyTraceBack_Here`) | The compiler inlines them. In a clang PGO+LTO build of 3.13 neither is called from the bytecode loop at all (0 call sites; a gcc build of 3.14 has 6 and 1). |

## Code

A tool and BPF object of their own; the systing capture's behaviour does not
change. Every build of the systing library does compile the new BPF object.

| File | What |
| --- | --- |
| `src/bpf/python_function_trace.bpf.c` | The probe program. Compiles pystacks into itself, as the task-stacks recorder does, for the thread-state lookup and symbol records. |
| `src/python_function_trace/sites.rs` | Finds and checks the dispatch table and the probe offsets in an interpreter file. |
| `src/python_function_trace/pairing.rs` | Events to slices and per-function statistics. |
| `src/python_function_trace/mod.rs`, `output.rs` | Load, attach, read; summary, Perfetto trace, table of slices; the load probe for the load-shape test. |
| `python-function-trace/src/main.rs` | The command, in its own workspace package. |
| `python-function-trace/e2e/` | The end-to-end workload and checker (`run.sh`) and the benchmarks (`bench.sh`). |

The load-shape gate (`tests/bpf_load_shapes.rs`, `every_shape_loads`) loads
the object on every kernel of CI's guest matrix, and the stack-budget test
adds up its frames.

## What was checked

`python-function-trace/e2e/workload.py` makes a known number of calls of each
kind: plain calls, recursion that raises through four frames into an
`except`, an exception swallowed by C, generators, a generator expression,
`__init__`, a C function calling back into Python, asyncio coroutines, and
three threads. `check.py` compares the slices per function and how each
ended, that the worker threads are distinct, and that every slice lies inside
its parent (`sudo python-function-trace/e2e/run.sh PYTHON [MODE] [ARGS]`).

| Interpreter | Dispatch sites | Dispatch sites, `-X perf` | Eval-frame sites, `-X perf` | Eval-frame sites, no trampolines |
| --- | --- | --- | --- | --- |
| 3.12.3 (Ubuntu, gcc, stripped) | all checks pass | all pass | counts right; each generator's creating call is one more slice | 9 functions short |
| 3.13.15 (clang, PGO + LTO) | all pass | all pass | as 3.12, and 2 of 25 `__init__` | 10 functions short |
| 3.14.7 (gcc, LTO) | all pass | all pass | as 3.12 | 10 functions short |

In the dispatch columns every count is exact, including the 40 frames an
exception unwound, the 5 `__getattr__` calls whose exception C swallowed, and
the yields and returns of each generator and coroutine. The Perfetto file was
checked apart from the tool: begins and ends balanced on every track.

Also checked: attaching to a running multi-threaded process by pid and leaving
it running, with no slice cut at the start; recursion 150 deep (all 3,020
returns, depth right); function, file and thread names holding escape
sequences, tabs and newlines (printed escaped; every line of the table has
nine columns); a thread id given for `--pid` (refused); SIGTERM, the slice cap
and a command that outlives the duration (each ends the trace with its
output); unit tests for the pairing rules, the output and the escaping, and
the table checks on every interpreter installed (in CI, finding none fails).

## What it costs

Measured on one x86-64 host, Linux 6.12, CPython 3.13.15 (clang, PGO + LTO),
best of three runs (`python-function-trace/e2e/bench.sh`).

| Workload | Untraced | Dispatch sites | Eval-frame sites with `-X perf` |
| --- | --- | --- | --- |
| 2,000,000 calls of a one-line function, nothing else | 0.068 s (34 ns a call) | 5.37 s (2.7 µs a call, 79x) | 2.11 s (1.1 µs a call, 31x) |
| Mixed: JSON, regex, hashing, sorting, per-record Python functions (624,000 events) | 0.36 s | 1.09 s (3.0x) | 0.65 s (1.8x) |

- **About 1.3 µs per event, two events per call.** The BPF program is 0.2 µs
  of that (kernel BPF statistics: 201 ns a run over 3.6 million runs). The
  rest is the kernel's breakpoint: a trap, then single-stepping the displaced
  instruction, which is a second trap.
- It is paid by every Python function call in the process while the probes
  are attached: filtering by function or duration reduces what is recorded,
  not what is paid.
- **The reported times include it.** The time stamp is taken in the first
  trap, so each slice holds about one event's cost of its own and its
  caller's self time the other: self time is real time plus about 1.3 µs for
  each call the function makes, plus one. The ranking by self time therefore
  favours functions that are called often or call often.
- For scale, hooks *inside* the process on the same loop: `cProfile` adds
  0.14 µs a call, `sys.monitoring` with Python callbacks 0.09 µs. That is the
  price of constraint 1.
- Trace volume: 56 bytes an event in the ring (about 4.8 million events in
  the default 256 MiB); no events were lost at 740,000 events a second.
- Removing the probes takes a fraction of a second per probe in the kernel;
  the tool drops the events after the cutoff, so they are not in the trace,
  but the process pays for any hit until the last probe is out.

It is for a short, deliberate look at a process, not for leaving on.

## When not to use it

A call-heavy service slows several-fold while the probes are in, and nothing
in user space can make a kernel breakpoint much cheaper. Where function traces
are wanted often, or on hot paths, and the service can load a module, a hook
inside the process (`sys.monitoring` with a C callback) is 10 to 30 times
cheaper and gives exact exception exits. This tool is what works on a process
that was not prepared.

Also not on:

- A process checkpointed with CRIU: the `[uprobes]` page stays after the
  trace, and CRIU refuses it (or the restored process gets SIGTRAP if it was
  dumped with a probe in).
- A process that uses greenlet or gevent: see [Limits](#limits).

It leans on CPython internals (a dispatch table, opcode numbers, frame
layout). The table, the numbers and the version are checked at attach, and a
mismatch refuses rather than guesses, but each new CPython minor version
needs a look.

## Limits

| Limit | Note |
| --- | --- |
| One process at a time | The probe takes map and ring locks. Under one process's GIL only one thread is in the probe at a time, so nobody waits; with several processes a waiter could spin, and on older kernels on a KVM guest with paravirtual spinlocks halt with interrupts off (the hash map's and ring's locks changed in 6.15, the LRU lists' later). Several need a ring and a cache per producer first. |
| Frames already running when the trace starts are invisible until they return | Their callees are traced. The fix is to seed each thread's stack from one pystacks walk at attach. |
| Processes forked after attach are not followed | The tool attaches by pid. |
| greenlet and gevent | A switch between greenlets runs no probed opcode, so frames that are only switched out end as `unwound` and their callers' times are wrong (56% of slices cut early in a reviewer's switch-heavy emulation). The tool warns when greenlet is loaded. Real support needs a stack per greenlet. |
| Only Python functions | Calls into C (builtins, extension modules) are not events. |
| Builds with no dispatch table | Built without computed gotos, or with the tail-calling interpreter (uv's 3.14 and 3.15 builds, a 3.14 option with clang 19+): refused. |
| The JIT | Calls inside JIT-compiled code are not seen (`PYTHON_JIT=1`; the tool warns). |
| Free-threaded builds | Refused. |
| Pre-releases | Refused for dispatch sites (their opcodes can be renumbered); eval-frame sites take 3.12 to 3.14 only. |
| Sub-interpreters with their own GIL | Not supported, and not detected: they run in parallel, so more than one thread can be in the probe at a time, which the one-process rule is there to prevent. Do not trace such a process. |
| aarch64, musl | Not tested; the thread-state lookup is pystacks' and shares its limits (glibc). |
| Python 3.15 | Needs its opcode list, and a new way to the thread state: 3.15 drops the `autoTSSkey` that pystacks finds it through. |
| Run from another pid namespace | Refused: the probes see the initial namespace's process ids. |
| Only the executable and `libpython*` are looked at | An interpreter in another library, or a file replaced on disk, is not found. |
| Line numbers are the function's first line | Not the call site. |
| Names | Qualified names are cut at 128 bytes, file names keep their last 192; the code-object cache can, rarely, give a function the name of a dead one whose addresses it reuses. |
| The slice cap ends the trace | The slices kept are those that closed first, so long outer frames are the ones lost when it is reached. |
| A re-dispatched `RESUME` shows as an extra sub-microsecond `unwound` slice | After instrumentation changes (cProfile, coverage, a debugger), at the next start of each function. |
| The interpreter's own `__init__` clean-up frames return without having entered (3.13+) | Counted ("returns with no entry seen") and ignored, so on 3.13+ that counter is no sign of lost entries. |
| On kernels 6.6 and 6.12 every probe hit takes the process's `mmap_lock` for reading | A call can wait in the trap behind a writer of that lock, holding the GIL. |
| Memory | The ring is kernel memory (256 MiB by default); the tool keeps up to `--max-slices` slices in memory. |

## Next: a systing recorder

In order:

1. **Tests in CI** for the end-to-end script, per Python version, in the VM
   jobs. (The load-shape gate already loads the object.)
2. **A ring and a cache per producer**, so more than one process (or a
   process with sub-interpreters) can be traced without a producer waiting on
   another's lock; symbol records rate-limited per CPU as pystacks' are.
3. **Recorder `python-function-trace`**, off by default, enabled with
   `--add-recorder`, reusing the capture's targeting (`--pid`, `--cgroup`,
   `-- command`) and its pystacks maps, under the capture's bounds.
4. **A table**, `python_function_slice` (start, duration, thread, depth,
   function, file, line, how it ended), with a schema version bump, exported
   to Perfetto as slices on thread tracks.
5. **Follow forks and execs** with one link set per followed process, added
   from the existing fork and exec handling. Attaching to the file without a
   pid would make every process that maps it trap, bystanders included. On
   kernels with uprobe-multi links (6.6+), one attach and one detach for all
   sites.
6. **Seed open frames** at attach from a stack walk, and pair by the
   interpreter's frame depth as well as by address, which repairs the
   exception cases above in a reviewer's emulation.
7. **A duration threshold in BPF**: keep the stack of open frames in the
   probe and emit only slices over a threshold, so a long capture's ring
   carries thousands of events rather than millions. It lowers what is
   recorded, not what the process pays.
8. **Cheaper entry probes.** The kernel emulates a few instruction kinds
   (branches, `push`) instead of single-stepping them; the entry handlers
   have a conditional jump early on, and a probe there should save about
   0.6 µs on half the events. Exit and yield handlers have no such
   instruction before the frame is unlinked, so they stay as they are.
