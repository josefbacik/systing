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
