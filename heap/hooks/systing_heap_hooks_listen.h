/*
 * systing-heap hooks: the responder. Internal to the library; see
 * systing_heap_hooks_listen.c.
 */
#ifndef SYSTING_HEAP_HOOKS_LISTEN_H
#define SYSTING_HEAP_HOOKS_LISTEN_H

#include <stdbool.h>

#include "systing_heap_hooks_python.h"

/* Between this library's files only: not exported. */
#pragma GCC visibility push(hidden)

/* jemalloc's mallctl in this process, or NULL. (systing_heap_hooks.c) */
shh_mallctl_fn shh_find_mallctl(void);

/* Register the library's fork handlers, once. (systing_heap_hooks.c) */
void shh_register_fork_handlers(void);

/* The fork handlers' part; the library's handlers call it. */
void shh_listen_after_fork_child(void);

#pragma GCC visibility pop

#endif
