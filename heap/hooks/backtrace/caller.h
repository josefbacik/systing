/* Between this library's files only. See caller.c. */
#ifndef SYSTING_HEAP_HOOKS_CALLER_H
#define SYSTING_HEAP_HOOKS_CALLER_H

#include <pthread.h>
#include <stdint.h>
#include <sys/types.h>

#pragma GCC visibility push(hidden)

/*
 * Copy up to `len` bytes of this process's memory at `src`, by the kernel, so
 * that a bad address is an error and not a fault. Returns how many were copied,
 * which is fewer where the memory ends, or -1.
 */
typedef ssize_t (*shh_read_fn)(void *dst, uintptr_t src, size_t len);
ssize_t shh_read_self(void *dst, uintptr_t src, size_t len);

/*
 * The two below walk through the libraries (dl_iterate_phdr()), with a lock of
 * the loader's held that fork() does not make anew in the child: a child that
 * another thread forked in the middle would wait for it for good, the next time
 * it loaded a library. So each takes `a_fork_waits_for`, a lock that this
 * library's fork handler takes, for as long as the walk lasts and no longer.
 * Nothing is allocated under it.
 */

/*
 * Find where the loader's code is. Called when a backtrace is installed, not
 * from one. Returns SHH_OK or SHH_ERR_NO_LOADER: a backtrace that could not
 * tell is not installed.
 */
int shh_find_loader(pthread_mutex_t *a_fork_waits_for);

/*
 * Whether the loader may have called malloc. A backtrace asks before it calls
 * anything that may read a thread-local variable through the loader. `above` is
 * the backtrace's own frame address, and `read` a read that works in this
 * process.
 */
int shh_loader_called_malloc(const void *above, shh_read_fn read);

/*
 * What the look is to tell beforehand, told afterwards from a stack that has been
 * made.
 *
 * Whether the loader is among its innermost frames. That is so of more than what
 * the loader allocates: of what a library's constructor does, which the loader
 * calls. For whom a yes costs nothing.
 */
int shh_loader_is_near(void *const *vec, unsigned len);

/*
 * Whether __tls_get_addr() is: the thread was being given a thread-local variable
 * when malloc was called, which is when another may not be read. Where the look
 * had answered no and one has been read, call this. It is counted, and the first
 * time said on stderr, so that a fault that comes later has something to be traced
 * back to. Returns whether it was so.
 */
int shh_missed(void *const *vec, unsigned len);

/* How many bytes of thread-local variables the library `pc` is in has. Called
 * when a backtrace is installed, not from one. */
size_t shh_thread_locals(uintptr_t pc, pthread_mutex_t *a_fork_waits_for);

#pragma GCC visibility pop

#endif
