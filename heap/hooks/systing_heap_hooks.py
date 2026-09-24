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

A server that forks workers (gunicorn, multiprocessing) calls install() in
each worker after the fork, and keep_perf_map_across_fork() once in the
parent before it: a child starts a perf map of its own, and without this the
frames it inherited running from the parent (the parent's loop under every
worker) are named in no map the child's dumps can use.
"""

import ctypes
import os
import stat
import sys
import warnings

__all__ = ["install", "keep_perf_map_across_fork"]

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


_copy_on_fork = False


def keep_perf_map_across_fork(strict=False):
    """Make each child this process forks add this process's perf map to its
    own (CPython 3.13+). Call it in the parent, before the fork, with perf
    trampolines on. Returns whether it is on."""
    global _copy_on_fork
    why = None
    copy = None
    if not getattr(sys, "is_stack_trampoline_active", lambda: False)():
        why = "keeping the perf map across fork: perf trampolines are not active"
    else:
        copy = getattr(ctypes.pythonapi, "PyUnstable_CopyPerfMapFile", None)
        if copy is None:
            why = "keeping the perf map across fork needs Python 3.13+"
    if why is None:
        if not _copy_on_fork:
            copy.argtypes = [ctypes.c_char_p]
            copy.restype = ctypes.c_int

            # CPython starts the child's own map before these run. Its
            # persist-after-fork setting is not used: that stops the child
            # making trampolines, so what the child runs later is unnamed.
            # The forking process's pid is taken before the fork: getppid()
            # in the child is 1 once the parent has exited.
            forking = [None]

            def note_parent():
                forking[0] = os.getpid()

            def add_parent_map():
                # /tmp is shared: open without following a link, check that
                # handle is a regular file of ours (CPython writes the map as
                # the effective uid), and copy through the same handle.
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
                try:
                    fd = os.open(f"/tmp/perf-{forking[0]}.map", flags)
                except OSError:
                    return
                try:
                    st = os.fstat(fd)
                    if stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid():
                        copy(f"/proc/self/fd/{fd}".encode())
                finally:
                    os.close(fd)

            os.register_at_fork(before=note_parent, after_in_child=add_parent_map)
            _copy_on_fork = True
        return True
    message = "systing_heap_hooks: " + why
    if strict:
        raise RuntimeError(message)
    warnings.warn(message, RuntimeWarning, stacklevel=2)
    return False
