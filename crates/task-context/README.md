# task-context

Attach a few named values to the calling thread — a request id, an iteration
number — so that a tracer can read them from outside the process and store
them beside each sample it takes of that thread. New to it? See the
[quick start](https://github.com/josefbacik/systing/blob/main/docs/TASK_CONTEXT.md),
which also covers collecting the data with systing.

```c
#include "task_context.h"

set_task_context("request_id", "abc-123");        /* a string, up to 256 bytes */
set_task_context("iteration_id", (uint64_t)42);   /* a 64-bit number           */
clear_task_context("request_id");                 /* forget a name             */
```

Each call applies to the **calling thread only** and returns 0 or a negative
`TASK_CONTEXT_E*` code. Nothing is ever truncated: a name or a value that does
not fit is refused. After a thread's first call, setting a value is a few
stores into memory the thread owns — no system call, no lock, no allocation.

Nothing here talks to a tracer. The library publishes, inside the process, a
small record that says how to get from a thread to its values; a tracer
started with `--include-task-context` looks for that record. A program that
links the library and is never traced pays for one untouched 16 MiB
address-space reservation and nothing else.

## The contract

[`include/task_context.h`](include/task_context.h) is the whole contract
between the library and a reader, and the reference for everything on this
page: the per-process record, the per-thread block, the rule by which they are
written and the rule by which they must be read, and the limits. The same file
is included by the library and by a tracer's BPF code.

In one paragraph: the library owns exactly one pointer-sized thread-local,
holding the address of the thread's block (or NULL). By default it is compiled
with the initial-exec TLS model: static TLS puts that variable at the same
distance from the thread pointer in every thread of the process, and the
library reports that distance, so a reader reads thread pointer + offset,
follows the pointer, and checks what it lands on. Built with
`-DTASK_CONTEXT_DTV` the variable is general-dynamic instead: it lives in its
module's TLS block, and the library reports the module's id and the variable's
offset in that block; a reader finds the block through the thread's DTV, the
way the dynamic linker does. Either way a reader never parses a relocation.

## Using it

**C.** `set_task_context(name, value)` is a C11 `_Generic` macro over the two
functions the library exports, `set_task_context_str` and
`set_task_context_u64`. **C++** gets two inline overloads of the same name; for
a literal `0`, call `set_task_context_u64` by name. Other languages call the two
typed functions directly.

**Rust.** This crate compiles the C file and wraps it:

```rust
task_context::set_str("request_id", "abc-123")?;
task_context::set_u64("iteration_id", 42)?;
task_context::clear("request_id")?;
```

**Linking.** The library is one C file, `src/task_context.c`, and links
either way:

```sh
# statically
cc -O2 -pthread -I include -c src/task_context.c -o task_context.o
ar rcs libtask_context.a task_context.o
cc -O2 -static -pthread -I include your_program.c libtask_context.a -o your_program

# dynamically, loaded when the program starts
cc -O2 -fPIC -shared -pthread -Wl,-z,nodelete -I include src/task_context.c -o libtask_context.so
cc -O2 -pthread -I include your_program.c -L. -ltask_context -o your_program
```

`-z nodelete` keeps the shared object mapped for the life of the process: a
thread's exit handler and the published record both point into it.

**The DTV build.** Add `-DTASK_CONTEXT_DTV` when compiling `task_context.c`
(static or shared) and the thread-local is general-dynamic: the library needs
no static TLS, and publishes the recipe that walks the thread's DTV. This is
glibc's layout on x86-64 and aarch64; the file refuses to compile with the
flag on another C library. Where the loader puts the variable in static TLS
anyway (TLS descriptors, the aarch64 default, do that to a library loaded with
`dlopen`), the library publishes the fixed-distance recipe instead of the walk,
and the calls below still hold. The cost is in the calls: the dynamic linker
allocates the thread-local on a thread's first touch and updates a thread's
DTV, under its own lock, after another thread has loaded a library with TLS,
so a call may allocate or take that lock, and none of them is
async-signal-safe.

**One copy.** A process holds one copy of the library. A second copy — a
static one in the executable beside a shared object — is refused: the copy
that publishes second publishes nothing, and every call it serves returns
`TASK_CONTEXT_EDUPLICATE` (`Error::Duplicate` in Rust). Where the program has
no `dlopen` and `dlsym`, or does not export the record of the first copy, the
check cannot see it and does not refuse.

Loading the library with `dlopen` after the program has started is outside
what this version's example and tests cover; the header's "Limits" section
says what the two common C libraries do with it.

## Limits

- 8 names set at once per thread; clearing a name frees its slot.
- A name is 1 to 31 bytes of `[A-Za-z0-9_.:-]`.
- A string value is up to 256 bytes; a number is 64 bits.
- 64-bit processes on x86-64 and aarch64.
- The context belongs to the OS thread: a runtime that moves a task between
  OS threads must set it again where the task lands.
- Not from a signal handler on a thread's first call; a call that interrupts
  the same thread's own update is refused with `TASK_CONTEXT_EBUSY`.
- At most 6,553 threads hold a block at once; one more is refused with
  `TASK_CONTEXT_ENOBLOCK` and counted in the record.
- The 16 MiB region is reserved when the library is loaded, in every process
  that links it. It is untouched address space until threads set values, but:
  a host with strict overcommit (`vm.overcommit_memory=2`) charges all of it
  to the commit limit at load; a process that called `mlockall(MCL_FUTURE)`
  gets it populated and locked, or the reservation fails against
  `RLIMIT_MEMLOCK`; and it counts toward `RLIMIT_AS`. When the reservation
  fails nothing is published, and a thread's first set tries again and
  returns `TASK_CONTEXT_ENOMEM` if it fails again.
- A thread that ends without running its pthread destructors keeps its block.
  After `fork`, the blocks of the parent's other threads stay allocated in
  the child, with no owner.

## Trust

Any process can set any name to any value. A consumer may **join** on a
context value; it must never authorise, bill or attribute ownership by one.
Values are copied into traces: do not put a secret in one.

## The example, and what the tests check

[`examples/tcx_example.c`](examples/tcx_example.c) is the usage above in a
program of three threads. It is one source built three ways — statically
linked, dynamically linked at program start, and dynamically linked against a
library built with `-DTASK_CONTEXT_DTV` (the program has a thread-local of its
own, so that library is not TLS module 1) — and prints, per thread, one line in
the form the header fixes (`TCX1 tid=… tp=… slot=… off=… block=… id=… set=…`).
With `--hold` it waits for a line on standard input between phases, so that
something outside the process has time to look; with `--busy-ms N` every
thread stays on a CPU for N milliseconds after each phase, because a sampling
profiler only ever sees a thread that is running.

`cargo test -p task-context` runs the library's unit tests and then
`tests/examples.rs`, which builds the programs with the system C compiler,
runs each, and checks them **from outside the process**: it finds the record
in the ELF file by its section name, reads it out of the child's memory, and
for every thread follows the published recipe (thread pointer + offset, or the
walk through the thread's DTV) to the block and compares what is there with
the line the thread printed. Two more cases link a second copy of the library
into the program and check that the copy that publishes second is refused. What it cannot
do is read the thread pointer the way a tracer does, from the task's saved
registers: the program prints it. A missing tool (no C compiler, no static C
library, no leave to read a child's memory) makes these tests skip with a
reason; when the `CI` environment variable is set they fail instead, so that
a green run there means the checks ran.
