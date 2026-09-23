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

/*
 * Make jemalloc capture stacks with `backtrace`: "default" (jemalloc's own)
 * or "libunwind". Returns SHH_OK, or an SHH_ERR_* code with jemalloc left as
 * it was.
 */
int systing_heap_hooks_install(const char *backtrace);

/* The backtrace installed: "default" or "libunwind". */
const char *systing_heap_hooks_active(void);

/* What an SHH_* code means. */
const char *systing_heap_hooks_strerror(int code);

#endif
