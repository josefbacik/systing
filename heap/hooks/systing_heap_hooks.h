/*
 * systing-heap hooks: replace how jemalloc captures a sampled allocation's
 * stack. See systing_heap_hooks.c.
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

/* What an SHH_* code means. */
const char *systing_heap_hooks_strerror(int code);

#endif
