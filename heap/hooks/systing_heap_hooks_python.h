/*
 * systing-heap hooks: the "python" backtrace. Internal to the library; see
 * systing_heap_hooks_python.c.
 */
#ifndef SYSTING_HEAP_HOOKS_PYTHON_H
#define SYSTING_HEAP_HOOKS_PYTHON_H

#include <stddef.h>

typedef void (*shh_backtrace_fn)(void **, unsigned *, unsigned);
typedef int (*shh_mallctl_fn)(const char *, void *, size_t *, void *, size_t);

/* Between this library's two files only: not exported. */
#pragma GCC visibility push(hidden)

/*
 * Get ready to walk Python frames in this process: find the interpreter, its
 * version's offsets and a protected way to read memory, and start the code
 * map. `native` captures the native stack. Returns SHH_OK or an SHH_ERR_*
 * code; does nothing the second time.
 */
int shh_python_prepare(shh_mallctl_fn mallctl, shh_backtrace_fn native);

/* The fork handlers' part; the caller's handlers call these. */
void shh_python_before_fork(void);
void shh_python_after_fork_parent(void);
void shh_python_after_fork_child(void);

/* Whether the calling thread is inside fork(), between the handlers. */
int shh_forking_here(void);

#pragma GCC visibility pop

#endif
