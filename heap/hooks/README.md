# systing-heap hooks

What a service loads to get more than jemalloc gives by itself. There are two pieces, and a service takes either without the other:

- **the backtraces**: other ways of capturing a sampled allocation's stack, which put Python functions in the stacks;
- **the responder** (experimental): a thread that answers requests for a dump.

See "Python stacks" and "Asking a live process" in [`../README.md`](../README.md) for when to use them.
A service that wants neither loads nothing of this: jemalloc's own snapshots, `--snoop` and `--ask python` need none of it.

## What to take, for what

| To get | The library | In the service | What else must be in the image |
|---|---|---|---|
| Python functions in the stacks, with file and line | `libsysting_heap_hooks.so`, with `systing_heap_hooks.py` | `install(backtrace="python")` | nothing |
| Stacks walked through Python's perf trampolines | the same | `install(backtrace="libunwind")` | `libunwind.so.8`, opened when asked for |
| An answer to `systing-heap --ask`, from a Python service (experimental) | the same | `listen()` | nothing |
| The same, from a service that is not changed (experimental) | `libsysting_heap_responder.so`, preloaded | nothing: `SYSTING_HEAP_HOOKS_LISTEN=1` in its environment | nothing |
| The same, from a C, C++ or Rust service that calls it (experimental) | `libsysting_heap_responder.so` | `systing_heap_hooks_listen(NULL)` | nothing |

`libsysting_heap_hooks.so` has both pieces, and is what a Python service loads.
`libsysting_heap_responder.so` is the responder alone: nothing in it knows of Python or of the backtraces, and it is about a twentieth of the other's size (14 KB against 276 KB, nearly all of the difference the `"python"` backtrace's tables).
Either does nothing when it is loaded and not asked: no thread, no file, no socket.

## What is where

```
heap/hooks/
  systing_heap_hooks.h    what a C program includes: both pieces' functions
  systing_heap_hooks.py   what a Python program imports
  Makefile                builds the libraries
  common/                 what the pieces share: finding jemalloc, fork, what the errors mean
  backtrace/              the backtraces: backtrace.c, and python.c with py_offsets.h
  responder/              the responder: responder.c
```

Each piece is built from its own folder and `common/`, and calls nothing of the other piece.
The one thing that passes between them is the code map: the `"python"` backtrace says how it is asked for, through `common/`, and the responder hands over what it is given, which in the library without the backtraces is nothing.

- `make` builds both libraries here; `make OUT=/dir` puts them elsewhere. `make hooks` and `make responder` build one. It needs a C compiler only: no Python headers, no libunwind. Both link only libdl and libpthread.
- `backtrace/py_offsets.h`: the CPython struct offsets the `"python"` backtrace reads, by version. Rendered from systing's pystacks offsets; `cargo test -p systing-heap hook_offsets` fails when the two differ, and rewrites the header when run with `SYSTING_HEAP_UPDATE_OFFSETS=1`.
- `systing_heap_hooks.py` loads the library with `ctypes`, checks the `"python"` backtrace against Python's own view of the stack before installing it, can turn on perf trampolines, and starts the responder (`listen()`, experimental). It finds the library through its `lib` argument, then `SYSTING_HEAP_HOOKS_LIB`, then next to the `.py` file. Given the library that is the responder alone, `listen()` works and `install()` says why it cannot.
- `SYSTING_HEAP_HOOKS_LIBUNWIND` names the libunwind to load instead of `libunwind.so.8`.

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

## The responder (experimental)

> **Very experimental.**
> It puts a thread and a socket of ours in the service, and what it is asked and answers may change, as may `systing-heap --ask` with it.
> Expect it to change, and do not build on it yet.

`systing_heap_hooks.listen()`, or `systing_heap_hooks_listen(dir)` from C, makes the process answer requests for a heap dump: `systing-heap --pid PID --ask` asks (see "Asking a live process" in [`../README.md`](../README.md)).
It is apart from the backtraces: a process can have either without the other.

- One thread is started, named `heap-responder`. It waits in `accept()` until someone asks, and costs nothing until then.
- The socket is a file, `.systing-heap.<pid>`, in `dir`, else in the directory `SYSTING_HEAP_HOOKS_SOCKET_DIR` names, else in `/tmp`. Its path must fit a Unix socket's address (107 bytes).
- **In production, give it a directory of the service's own**, one that only the service's user writes to. In `/tmp` anyone can take the name first. That denies the service its responder and redirects nothing: `listen()` fails, and the tool checks that what answers is the process it asked about before it says anything. The name has the pid as the process itself sees it, so two containers that share a directory collide on small pids, and the second one's `listen()` fails.
- It answers the process's own user and root: the file is made for its owner alone, and the peer's credentials are checked as well, before a byte of the request is read. Where that user's processes are closed to one another (`kernel.yama.ptrace_scope` of 1 or more) this opens a little: another process of that user gets the heap profile (sampled stacks and sizes, the paths of mapped files) and the Python code map (function names, files, lines). It gets no contents of memory.
- A socket already at that path is taken over if no one answers there. Whether someone does is asked without waiting, so a socket put in the way cannot hold the program that calls `listen()`; the call then fails.
- The socket is known by what it is, not by its number alone. A program that closes descriptors it did not open may give the number to a socket of its own: the thread then ends instead of answering there, and `listen()` can be called again.
- jemalloc writes the dump into an anonymous file (`memfd_create`), which is then sealed and handed over as a descriptor, with the code map's when the `"python"` backtrace writes one. The dump is not written to disk. With the `"python"` backtrace on, the first request to a forked worker makes that worker's code map file, beside the dumps, as its first new function would have; the library that is the responder alone writes no file but its socket.
- **The dump is the service's memory until it is read.** The anonymous file's pages count against the service's own memory limit until the tool has read it and closed it. A dump is small beside a heap (tens of kilobytes to a few megabytes), and a service at the edge of its limit is the one that is asked.
- **Nothing limits how often it is asked.** Each request is a whole `prof.dump`, on the responder's thread. Whoever may ask can already stop the service, so this gives no one a new power; it is a cost.
- The answer says whether jemalloc's sampling goes on (`prof.active`): a dump of a service that has paused it holds what was sampled before, and the tool warns.
- Every signal is blocked on the thread, so no handler of the program's runs there. It calls nothing of Python's, and takes no lock of the program's own. With the `"python"` backtrace on it takes that backtrace's lock while a forked worker's code map is made, for as long as the inherited lines take to copy: a thread of the program whose allocation is sampled meanwhile waits for it.
- Requests are answered one at a time, and a peer that says or reads nothing is given up on after 5 seconds.
- A process that is killed, or that ends with `_exit()` as a worker forked by Python's `multiprocessing` does, or that goes on to run another program (`execve`), leaves its socket's file behind. The next process to listen under that name takes it over, and a process that exits removes its own. A server that replaces its workers leaves one such file for each until then.
- **fork.** The thread is not in a forked child, which lets go of its parent's socket; a child that is to answer calls `listen()` itself. The Python helper does that in every child, in the directory its first `listen()` was given: each has a thread and a socket file of its own from the start. No child is forked between the socket's making and its being on record, so none is left with a copy of it that it cannot let go of. Python 3.12 and later warn (`DeprecationWarning`) when a process with more than one thread forks, and the responder is a thread.

### A service that is not changed

A service listens without a line of it being changed when the library is loaded into it and its environment says so:

```yaml
env:
  - name: LD_PRELOAD
    value: /usr/lib/x86_64-linux-gnu/libjemalloc.so.2:/opt/systing/libsysting_heap_responder.so
  - name: MALLOC_CONF
    value: prof:true
  - name: SYSTING_HEAP_HOOKS_LISTEN
    value: "1"
  - name: SYSTING_HEAP_HOOKS_LISTEN_ONLY   # not the programs it starts
    value: python3.13
  - name: SYSTING_HEAP_HOOKS_SOCKET_DIR    # the service's own, not /tmp
    value: /run/my-service
```

- `SYSTING_HEAP_HOOKS_LISTEN=1` is `systing_heap_hooks_listen(NULL)`, called as the library is loaded: the socket is in the directory `SYSTING_HEAP_HOOKS_SOCKET_DIR` names, else in `/tmp`. Unset, empty or `0`, nothing is done.
- `SYSTING_HEAP_HOOKS_LISTEN=fork` has the processes this one forks listen as well, each on a socket of its own, as a server's workers must if they are to be asked. The child's thread is started inside `fork()`, before it returns in the child. The manual allows the forked child of a program with threads only a short list of simple calls, and starting a thread is not one of them. What makes it work is glibc's own order, which is no promise: the child puts its locks back before it runs any library's fork handler (read in glibc 2.39). The library calls jemalloc before it takes its own part in `fork()`, so that jemalloc's locks too are the child's again by then. It has run on glibc alone: on another C library, musl above all, nothing is known. It is asked for by name for that reason.
- There is no caller to tell what came of it. A request that cannot be followed (no jemalloc, profiling off, a directory that is not there, a value that is neither) is said in one line on standard error, and the service runs as it would have. So is a forked worker's that cannot listen, with its pid.
- **Every program started with that environment listens**, not the service alone: a shell command it runs, a helper it starts. Each has a thread and a socket of its own for as long as it runs, and one without jemalloc or profiling says so on its standard error.
- **That can break a program.** It has a second thread before its own code begins, and Linux refuses a program with more than one thread a new user namespace: `unshare --user`, and a sandbox launcher that does the same, fail with `Invalid argument`. This was run, and is so.
- **`SYSTING_HEAP_HOOKS_LISTEN_ONLY` names the one program that is to listen**, by the file name of its executable, which for a Python service is the interpreter's (`python3.13`; `readlink /proc/PID/exe` says). Every other program that inherits the environment does nothing and says nothing. Set it in production. The other ways out are for the service to take the variables out of the environment it gives the programs it starts, or to call `listen()` itself and leave the environment alone.
- "Not changed" is the service's code. Its environment has three changes: `prof:true`, which cannot be turned on after the start, the preloaded library, and the variable.
- jemalloc comes first in `LD_PRELOAD`: the library looks for it as it is loaded.


## Installing from C

`systing_heap_hooks.py` checks the walk against Python's own view of the stack before it installs, and that check is in the helper alone: Python's view is asked of Python.
`systing_heap_hooks_install("python")` called from C installs on the interpreter's version.
On a Python of a listed version that is laid out otherwise (a free-threaded or a patched build), every object the walk reads is still checked for its type and every read is still made by the kernel, so the stacks are short or unnamed; nothing faults.
A C caller that wants the check calls `systing_heap_hooks_prepare("python")`, compares `systing_heap_hooks_python_check()` with what it knows the stack to be, and installs after.

A new Python minor version needs its offsets added to systing's pystacks bindings (`scripts/generate_python_bindings.py`) and to `MINORS` in `heap/src/hook_offsets.rs`.
