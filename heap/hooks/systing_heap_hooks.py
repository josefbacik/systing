"""Choose how jemalloc captures heap-snapshot stacks in this Python process.

Nothing changes until install() is called. Then, for jemalloc's sampled
allocations (MALLOC_CONF=prof:true,...):

    import systing_heap_hooks
    systing_heap_hooks.install(backtrace="libunwind", trampolines=True)

trampolines=True turns on Python's perf trampolines (3.12+), so each Python
function gets its own native frame and systing-heap can name it from
/tmp/perf-<pid>.map. backtrace="libunwind" makes jemalloc capture stacks
with libunwind, which walks through those frames; jemalloc's default
(libgcc) stops at the first one. backtrace="default" leaves or puts back
jemalloc's own.

What cannot be done is skipped with a warning, and the result says what is
active, so one call works on machines with and without libunwind8:

    {"backtrace": "default", "trampolines": True,
     "reasons": ["libunwind.so.8 not found"]}

strict=True raises instead. The C library is found by the lib argument, then
SYSTING_HEAP_HOOKS_LIB, then libsysting_heap_hooks.so next to this file.
"""

import ctypes
import os
import sys
import warnings

__all__ = ["install"]

_LIB_NAME = "libsysting_heap_hooks.so"
_lib = None


def _load(path):
    global _lib
    if _lib is None:
        path = (
            path
            or os.environ.get("SYSTING_HEAP_HOOKS_LIB")
            or os.path.join(os.path.dirname(os.path.abspath(__file__)), _LIB_NAME)
        )
        lib = ctypes.CDLL(path)
        lib.systing_heap_hooks_install.argtypes = [ctypes.c_char_p]
        lib.systing_heap_hooks_install.restype = ctypes.c_int
        lib.systing_heap_hooks_active.restype = ctypes.c_char_p
        lib.systing_heap_hooks_strerror.argtypes = [ctypes.c_int]
        lib.systing_heap_hooks_strerror.restype = ctypes.c_char_p
        _lib = lib
    return _lib


def _enable_trampolines():
    """Turn on perf trampolines; return why not, or None."""
    if sys.platform != "linux" or not hasattr(sys, "activate_stack_trampoline"):
        return "perf trampolines need Python 3.12+ on Linux"
    try:
        if not sys.is_stack_trampoline_active():
            sys.activate_stack_trampoline("perf")
    except (ValueError, RuntimeError) as e:
        return f"perf trampolines: {e}"
    return None


def install(backtrace="libunwind", trampolines=True, strict=False, lib=None):
    """Install `backtrace` ("libunwind" or "default") and, with
    `trampolines`, Python's perf trampolines. Returns what is active."""
    reasons = []
    active_trampolines = False

    if trampolines:
        why = _enable_trampolines()
        if why is None:
            active_trampolines = True
        else:
            reasons.append(why)

    try:
        hooks = _load(lib)
    except OSError as e:
        reasons.append(f"{_LIB_NAME}: {e}")
        active_backtrace = "default"
    else:
        rc = hooks.systing_heap_hooks_install(backtrace.encode())
        if rc != 0:
            reasons.append(hooks.systing_heap_hooks_strerror(rc).decode())
        active_backtrace = hooks.systing_heap_hooks_active().decode()

    result = {
        "backtrace": active_backtrace,
        "trampolines": active_trampolines,
        "reasons": reasons,
    }
    if reasons:
        message = "systing_heap_hooks: " + "; ".join(reasons)
        if strict:
            raise RuntimeError(message)
        warnings.warn(message, RuntimeWarning, stacklevel=2)
    return result
