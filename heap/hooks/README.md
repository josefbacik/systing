# systing-heap hooks

Optional replacements for how jemalloc captures a sampled allocation's stack, installed at runtime by the program that wants them.
See "Python stacks" in [`../README.md`](../README.md) for when to use them.

- `systing_heap_hooks.c` / `.h`: the library. It links only libdl and libpthread and does nothing until `systing_heap_hooks_install()` is called.
- `systing_heap_hooks_python.c`: the `"python"` backtrace, which reads the allocating thread's Python frames from the interpreter.
- `py_offsets.h`: the CPython struct offsets it reads, by version. Rendered from systing's pystacks offsets; `cargo test -p systing-heap hook_offsets` fails when the two differ, and rewrites the header when run with `SYSTING_HEAP_UPDATE_OFFSETS=1`.
- `systing_heap_hooks.py`: the Python helper that loads the library with `ctypes`, checks the `"python"` backtrace against Python's own view of the stack before installing it, and can turn on perf trampolines.
- `make` builds `libsysting_heap_hooks.so`; `make OUT=/dir` puts it elsewhere. It needs a C compiler only: no Python headers, no libunwind.

The helper finds the library through its `lib` argument, then `SYSTING_HEAP_HOOKS_LIB`, then next to the `.py` file.
`SYSTING_HEAP_HOOKS_LIBUNWIND` names the libunwind to load instead of `libunwind.so.8`.

Backtraces: `"default"` (jemalloc's own), `"libunwind"` and `"python"`.
Each is one entry in `systing_heap_hooks_install()`.

## What the `"python"` backtrace may and may not do

It runs inside malloc, in the service's process, mostly on threads that do not hold the GIL, so:

- A thread walks only its own frames.
- No pointer that came from Python is dereferenced. Everything Python owns is read with `process_vm_readv` on the process itself (`/proc/self/mem` where seccomp refuses that), so a bad address is an error, not a fault. If neither works, the backtrace is not installed.
- It calls nothing of Python's but the two functions that return the thread's state and the one that says the interpreter is exiting. It never takes the GIL, touches a reference count, or allocates.
- Every loop and length is bounded, and what is read is checked for its type before it is used.
- It keeps no file descriptor open: the code map is opened for each line and closed again, so a program that closes descriptors it did not open never has a line of ours written to a file of its own.
- The folder the dumps are in may be one others can write. The code map is opened without waiting, so a FIFO put at its path does not hold the allocation, and a line is written only to the regular file that was made, as the last line left it: the same device and number, the same size, and the same time of last change. What has taken its place since is left alone, and so is the map itself once something else has changed it (a `chmod`, a line added by hand); the map then names nothing more.
- Where reads go through `/proc/self/mem`, a forked child closes its parent's descriptor and opens its own.
- jemalloc's own backtrace is called exactly as jemalloc calls it, with the whole array.
- A forked child keeps the ids it was forked with, and its code map begins with its parent's lines: jemalloc keeps the stacks sampled before the fork, and the child's dumps hold them.

## Installing from C

`systing_heap_hooks.py` checks the walk against Python's own view of the stack before it installs, and that check is in the helper alone: Python's view is asked of Python.
`systing_heap_hooks_install("python")` called from C installs on the interpreter's version.
On a Python of a listed version that is laid out otherwise (a free-threaded or a patched build), every object the walk reads is still checked for its type and every read is still made by the kernel, so the stacks are short or unnamed; nothing faults.
A C caller that wants the check calls `systing_heap_hooks_prepare("python")`, compares `systing_heap_hooks_python_check()` with what it knows the stack to be, and installs after.

A new Python minor version needs its offsets added to systing's pystacks bindings (`scripts/generate_python_bindings.py`) and to `MINORS` in `heap/src/hook_offsets.rs`.
