# Task context quick start

Tag your app's threads with what they are working on, such as a request id,
and see it next to every CPU sample in a systing profile.

1. [Add it to your app](#1-add-it-to-your-app)
2. [Collect it with systing](#2-collect-it-with-systing)
3. [Read the results](#3-read-the-results)

## 1. Add it to your app

Each thread sets named values while it works and clears them when it is done.
Systing reads them while it profiles, so you can ask "which request was this CPU
time spent on?"

**C and C++**

```c
#include "task_context.h"

set_task_context("request_id", "abc-123");       /* a string, up to 256 bytes */
set_task_context("iteration_id", (uint64_t)42);  /* a 64-bit number */
clear_task_context("request_id");                /* when the work is done */
```

**Rust**

```rust
task_context::set_str("request_id", "abc-123")?;
task_context::set_u64("iteration_id", 42)?;
task_context::clear("request_id")?;
```

```toml
# Cargo.toml
task-context = { git = "https://github.com/josefbacik/systing" }
```

**Building it into a C or C++ program.** The library is one C file in
[`crates/task-context`](../crates/task-context). Compile it into your program:

```sh
cc -O2 -pthread -I crates/task-context/include \
   your_program.c crates/task-context/src/task_context.c -o your_program
```

Or build it as a shared library that your program links at start:

```sh
cc -O2 -fPIC -shared -pthread -Wl,-z,nodelete -I crates/task-context/include \
   crates/task-context/src/task_context.c -o libtask_context.so
cc -O2 -pthread -I crates/task-context/include your_program.c -L. -ltask_context -o your_program
```

**Rules**

- A call applies to the calling thread only. If your runtime moves work between
  threads, such as async tasks, set the value again where the work lands.
- A name is 1 to 31 characters from `A-Z a-z 0-9 _ . : -`. A thread can have 8
  names set at once. A string is up to 256 bytes and a number is 64 bits.
- Every call returns 0 or a negative error, and nothing is ever truncated: a
  value that does not fit is refused. Check the result.
- After a thread's first call, setting a value is a few memory writes, with no
  system call, lock or allocation. Each process reserves 16 MiB of address
  space for the library, and uses none of it until threads set values.
- Values are copied into traces. Do not put secrets or personal data in them.
- Link one copy of the library per process. It supports 64-bit Linux on x86-64
  and aarch64.

## 2. Collect it with systing

You need Linux 6.12 or newer, root, and the `--include-task-context` flag.

```sh
# one process, 10 seconds
sudo systing --include-task-context --pid 1234 -d 10 --output trace.duckdb

# every process on the host
sudo systing --include-task-context -d 10 --output trace.duckdb
```

- Start your app before or after the capture. A process that starts during the
  capture is picked up within a fraction of a second, so its first samples may
  have no context.
- Systing finds a process when its program contains the library or lists it as
  a direct dependency (`libtask_context*.so`). A library loaded later with
  `dlopen`, preloaded, or reached through another library is not found.
- Without the flag, systing reads nothing from your app.
- When the capture ends, systing prints `task_context samples:` and
  `task_context discovery:` lines. They say how many samples got a context and
  why the others did not.

## 3. Read the results

Each CPU sample has a `task_context_id`. The values behind an id are in the
`task_context` table, joined on trace, thread and id. Open the trace with the
DuckDB CLI and group samples by a value, for example by request:

```sql
SELECT c.value_str AS request, count(*) AS samples
FROM stack_sample s
JOIN task_context c
  ON c.trace_id = s.trace_id AND c.utid = s.utid AND c.id = s.task_context_id
WHERE c.name = 'request_id'
GROUP BY 1 ORDER BY 2 DESC;
```

A sample with no `task_context_id` has no context: the thread had nothing set,
its process was not found, or the read missed.

## Not covered yet

Sleeping stacks and the other recorders' events carry no context, and the
Perfetto view does not show it; use the tables. When the kernel is in lockdown
confidentiality mode, nothing is read. Details are in the
[Task Context section of the README](../README.md#task-context) and in the
[library's README](../crates/task-context/README.md).
