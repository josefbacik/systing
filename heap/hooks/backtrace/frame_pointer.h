/*
 * systing-heap hooks: the "frame-pointer" backtrace. Internal to the library;
 * see frame_pointer.c.
 */
#ifndef SYSTING_HEAP_HOOKS_FRAME_POINTER_H
#define SYSTING_HEAP_HOOKS_FRAME_POINTER_H

#include <stdint.h>

/* Between this library's files only: not exported. */
#pragma GCC visibility push(hidden)

/*
 * Get ready to capture stacks: everything that is done once, so that none of
 * it is left to be done inside malloc. Returns SHH_OK or an SHH_ERR_* code;
 * does nothing the second time.
 */
int shh_frame_pointer_prepare(void);

/* The backtrace, as jemalloc calls it. */
void shh_frame_pointer_backtrace(void **vec, unsigned *len, unsigned max_len);

/*
 * The mapping of this process that `addr` is in: [*start, *end). Returns 0, or
 * an errno value (ENOENT when no mapping has it) with both set to 0. Allocates
 * nothing; changes errno. (stack_range.c)
 */
int shh_mapping_containing(uintptr_t addr, uintptr_t *start, uintptr_t *end);

#pragma GCC visibility pop

#endif
