/*
 * systing-heap hooks: what the pieces of the library share. Internal to the
 * library; see common.c.
 */
#ifndef SYSTING_HEAP_HOOKS_COMMON_H
#define SYSTING_HEAP_HOOKS_COMMON_H

#include <stddef.h>

typedef void (*shh_backtrace_fn)(void **, unsigned *, unsigned);
typedef int (*shh_mallctl_fn)(const char *, void *, size_t *, void *, size_t);

/* Between this library's files only: not exported. */
#pragma GCC visibility push(hidden)

/* jemalloc's mallctl in this process, or NULL. */
shh_mallctl_fn shh_find_mallctl(void);

/*
 * A backtrace runs inside malloc, on top of whatever called malloc, and that
 * can be the dynamic loader in the middle of work it is not made to start
 * again: bringing a thread's table of thread-local variables up to date, which
 * it does with malloc and realloc. Reading a thread-local variable through
 * __tls_get_addr() starts that work again, whoever's variable it is and
 * whichever library the call is made from, an interpreter's own included.
 *
 * jemalloc keeps a backtrace from being entered twice. It cannot keep one from
 * entering its caller. But the caller is in the stack the backtrace has just
 * captured: where shh_loader_called_malloc() says so, a backtrace does no more
 * than jemalloc's own would have.
 *
 * shh_find_loader() finds where the loader's code is. It is called when a
 * backtrace is installed, not from one.
 */
void shh_find_loader(void);
/* Whether the loader is among the innermost frames of vec[0..n), innermost
 * first: the allocator's own come first, and those of any wrapper around it. */
int shh_loader_called_malloc(void *const *vec, unsigned n);

/*
 * A piece's part in a fork: what it does before one, and after it in the
 * process that forked and in the child. Any of the three may be NULL.
 */
struct shh_fork_part {
	void (*before)(void);
	void (*after_in_parent)(void);
	void (*after_in_child)(void);
};

/*
 * Have `part` take its part in every fork from now on. The parts' `before`
 * run in the order the parts were added, and what follows a fork in the
 * reverse of it, so a piece that is added after another may take its lock
 * inside the other's. `part` is a static of the piece's; adding it again
 * adds nothing.
 */
void shh_at_fork(const struct shh_fork_part *part);

/* Whether the calling thread is inside fork(), between the parts' `before`
 * and what follows. */
int shh_forking_here(void);

/*
 * The code map that names the Python frames of this process's dumps: its
 * path, or "" when the process writes none. The piece that writes one says
 * how it is asked for; without that piece there is none.
 */
void shh_set_code_map(const char *(*path)(void));
const char *shh_code_map(void);

#pragma GCC visibility pop

#endif
