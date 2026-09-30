/* Between this library's files only. See caller.c. */
#ifndef SYSTING_HEAP_HOOKS_CALLER_H
#define SYSTING_HEAP_HOOKS_CALLER_H

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
 * Find where the loader's code is. Called when a backtrace is installed, not
 * from one. Returns SHH_OK or SHH_ERR_NO_LOADER: a backtrace that could not
 * tell is not installed.
 */
int shh_find_loader(void);

/*
 * Whether the loader may have called malloc. A backtrace asks before it calls
 * anything that may read a thread-local variable through the loader. `above` is
 * the backtrace's own frame address, and `read` a read that works in this
 * process.
 */
int shh_loader_called_malloc(const void *above, shh_read_fn read);

/* How many bytes of thread-local variables the library `pc` is in has. Called
 * when a backtrace is installed, not from one. */
size_t shh_thread_locals(uintptr_t pc);

#pragma GCC visibility pop

#endif
