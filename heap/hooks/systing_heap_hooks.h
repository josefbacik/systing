/*
 * systing-heap hooks: what a program calls. Two pieces, and a program takes
 * either without the other:
 *
 *   the backtraces   replace how jemalloc captures a sampled allocation's
 *                    stack (backtrace/): install, prepare, active, python_*
 *   the responder    answers requests for a heap dump (responder/):
 *                    listen, socket
 *
 * libsysting_heap_hooks.so has both. libsysting_heap_responder.so has the
 * responder alone, and none of the backtraces' functions.
 *
 * Heap profiling in systing is still experimental: all of this may change.
 */
#ifndef SYSTING_HEAP_HOOKS_H
#define SYSTING_HEAP_HOOKS_H

#define SHH_OK 0
#define SHH_ERR_UNKNOWN_BACKTRACE 1
#define SHH_ERR_NO_JEMALLOC 2
#define SHH_ERR_PROF_OFF 3
#define SHH_ERR_NO_HOOK 4
#define SHH_ERR_NO_LIBUNWIND 5
#define SHH_ERR_NO_PYTHON 6
#define SHH_ERR_PY_VERSION 7
#define SHH_ERR_PY_READ 8
#define SHH_ERR_PY_MAP 9
#define SHH_ERR_SOCKET_PATH 10
#define SHH_ERR_SOCKET 11
#define SHH_ERR_LISTEN_HOW 12
#define SHH_ERR_NO_LOADER 13
#define SHH_ERR_STACK_READ 14

#include <stddef.h>

/*
 * Make jemalloc capture stacks with `backtrace`: "default" (jemalloc's own),
 * "libunwind", or "python" (jemalloc's own, then the allocating thread's
 * Python frames). Returns SHH_OK, or an SHH_ERR_* code with jemalloc left as
 * it was.
 */
int systing_heap_hooks_install(const char *backtrace);

/*
 * Everything install() does for `backtrace` short of installing it, so
 * "python" can be checked (systing_heap_hooks_python_check) before jemalloc
 * uses it. install() itself checks the interpreter's version and no more:
 * the check against Python's own view of the stack is the caller's, as
 * systing_heap_hooks.py makes it.
 */
int systing_heap_hooks_prepare(const char *backtrace);

/* The backtrace installed: "default", "libunwind" or "python". */
const char *systing_heap_hooks_active(void);
/* How often the "libunwind" backtrace found afterwards that the dynamic loader
 * had called malloc, and it had not seen so in time. 0 is what to expect. */
unsigned long systing_heap_hooks_missed(void);

/*
 * The calling thread's Python frames as the "python" backtrace reads them,
 * innermost first, one per line: "entry" for an interpreter entry frame,
 * else "<code object address> <instruction index + 1> <code-map line>".
 * Returns the number of frames, or a negated SHH_ERR_* code.
 */
int systing_heap_hooks_python_check(char *buf, size_t cap);

/* The code map this process writes; "" when it writes none. */
const char *systing_heap_hooks_python_map(void);

/*
 * Stop reading Python frames, and wait for the reads in progress: stacks
 * are native from here on. For the interpreter's exit, before it frees what
 * a walk would read.
 */
void systing_heap_hooks_python_stop(void);

/* The "python" backtrace itself, as jemalloc calls it. */
void systing_heap_hooks_python_backtrace(void **vec, unsigned *len, unsigned max_len);

/*
 * Answer requests for a heap dump on a Unix socket, from this process's own
 * user and from root: the file .systing-heap.<pid> in `dir`, or when that is
 * NULL in the directory SYSTING_HEAP_HOOKS_SOCKET_DIR names, else in /tmp.
 * `systing-heap --pid PID --ask` is what asks. One thread is started for it,
 * which sleeps until someone does. Returns SHH_OK, also when this process
 * listens already (wherever that is), or an SHH_ERR_* code.
 *
 * A forked child listens nowhere until it calls this itself.
 *
 * A program that is not changed listens when the library is loaded into it
 * (LD_PRELOAD) with SYSTING_HEAP_HOOKS_LISTEN=1 in its environment, as if it
 * had called this with NULL; with SYSTING_HEAP_HOOKS_LISTEN=fork the
 * processes it forks listen as well. Every program started with that
 * environment listens, unless SYSTING_HEAP_HOOKS_LISTEN_ONLY names the one
 * that is to, by its executable's file name ("python3.13").
 */
int systing_heap_hooks_listen(const char *dir);

/* The socket this process answers on; "" when it does not. */
const char *systing_heap_hooks_socket(void);

/* What an SHH_* code means. */
const char *systing_heap_hooks_strerror(int code);

#endif
