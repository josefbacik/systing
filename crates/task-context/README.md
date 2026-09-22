# task-context

Attach a few named values to the calling thread — a request id, an iteration
number — so that a tracer can read them from outside the process and store
them beside each sample it takes of that thread.

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
compiled with the initial-exec TLS model, holding the address of the thread's
block (or NULL). Static TLS puts that variable at the same distance from the
thread pointer in every thread of the process, and the library reports that
distance. A reader therefore never derives an offset from a TLS module id,
never walks a DTV and never parses a relocation: it reads thread pointer +
offset, follows the pointer, and checks what it lands on.

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
program of three threads. It is one source built two ways — statically linked,
and dynamically linked at program start — and prints, per thread, one line in
the form the header fixes (`TCX1 tid=… tp=… slot=… off=… block=… id=… set=…`).
With `--hold` it waits for a line on standard input between phases, so that
something outside the process has time to look; with `--busy-ms N` every
thread stays on a CPU for N milliseconds after each phase, because a sampling
profiler only ever sees a thread that is running.

`cargo test -p task-context` runs the library's unit tests and then
`tests/examples.rs`, which builds both programs with the system C compiler,
runs each, and checks them **from outside the process**: it finds the record
in the ELF file by its section name, reads it out of the child's memory, and
for every thread follows thread pointer + the published offset to the block
and compares what is there with the line the thread printed. What it cannot
do is read the thread pointer the way a tracer does, from the task's saved
registers: the program prints it. A missing tool (no C compiler, no static C
library, no leave to read a child's memory) makes these tests skip with a
reason; when the `CI` environment variable is set they fail instead, so that
a green run there means the checks ran.
