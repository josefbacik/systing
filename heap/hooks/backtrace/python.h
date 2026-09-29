/*
 * systing-heap hooks: the "python" backtrace. Internal to the library; see
 * python.c.
 */
#ifndef SYSTING_HEAP_HOOKS_PYTHON_H
#define SYSTING_HEAP_HOOKS_PYTHON_H

#include "../common/common.h"

/* Between this library's files only: not exported. */
#pragma GCC visibility push(hidden)

/*
 * Get ready to walk Python frames in this process: find the interpreter, its
 * version's offsets and a protected way to read memory, and start the code
 * map. `native` captures the native stack. Returns SHH_OK or an SHH_ERR_*
 * code; does nothing the second time. It takes its part in fork() from the
 * first call on, whatever comes of the call.
 */
int shh_python_prepare(shh_mallctl_fn mallctl, shh_backtrace_fn native);

#pragma GCC visibility pop

#endif
