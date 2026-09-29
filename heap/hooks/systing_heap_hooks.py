"""Choose how jemalloc captures heap-snapshot stacks in this Python process.

Nothing changes until install() is called. Then, for jemalloc's sampled
allocations (MALLOC_CONF=prof:true,...), either of:

    import systing_heap_hooks
    systing_heap_hooks.install(backtrace="python")
    systing_heap_hooks.install(backtrace="libunwind", trampolines=True)

backtrace="python" adds the allocating thread's Python frames to jemalloc's
own native stack, read from the interpreter when an allocation is sampled
(CPython 3.12 to 3.14). Python runs at full speed, and systing-heap names
each frame with its file and line from the code map the library writes
beside the dumps (pycode-<pid>-<token>.map). Before it is installed, what the
library reads of this thread's stack is compared with what Python says it
is; if they differ it is not installed.

trampolines=True turns on Python's perf trampolines (3.12+), so each Python
function gets its own native frame and systing-heap can name it from
/tmp/perf-<pid>.map. backtrace="libunwind" makes jemalloc capture stacks
with libunwind, which walks through those frames; jemalloc's default
(libgcc) stops at the first one. backtrace="default" leaves or puts back
jemalloc's own. Trampolines are on unless the backtrace is "python", which
has no use for them.

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

import atexit
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
        lib.systing_heap_hooks_prepare.argtypes = [ctypes.c_char_p]
        lib.systing_heap_hooks_prepare.restype = ctypes.c_int
        lib.systing_heap_hooks_python_check.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
        lib.systing_heap_hooks_python_check.restype = ctypes.c_int
        lib.systing_heap_hooks_python_map.restype = ctypes.c_char_p
        lib.systing_heap_hooks_python_stop.restype = None
        _lib = lib
    return _lib


_KINDS = {"1": "latin-1", "2": "utf-16-le", "4": "utf-32-le"}


def _text(field):
    """A str of a code-map line: "<bytes per character>:<hex>"."""
    kind, _, data = field.partition(":")
    return bytes.fromhex(data).decode(_KINDS[kind], "surrogatepass")


# The most frames one check walks (MAX_STEPS in the library).
_MAX_WALK = 1024


def _walk_differs(hooks):
    """Compare the library's walk of this thread with Python's own view of
    the same stack, frame for frame and to its end; return how they differ,
    or None."""
    buf = ctypes.create_string_buffer(16 << 20)
    # ctypes releases the GIL for the call: the walk runs as it will inside
    # malloc on a thread that does not hold it.
    n = hooks.systing_heap_hooks_python_check(buf, len(buf))
    if n < 0:
        return hooks.systing_heap_hooks_strerror(-n).decode()
    lines = buf.value.decode().splitlines()
    got = [l.split(" ") for l in lines if l != "entry"]
    frame = sys._getframe(0)
    if not got:
        return "no Python frames found"
    whole = len(lines) < _MAX_WALK
    # Python is entered from C through an entry frame, so a stack read to
    # its end ends with one: without it, the frames would be misplaced
    # among the native ones.
    if whole and lines[-1] != "entry":
        return "the stack does not end with an interpreter entry frame"
    for depth, fields in enumerate(got):
        if frame is None:
            return f"frame {depth}: more frames than Python has"
        code = frame.f_code
        try:
            address, index, _, first, qualname, filename, linetable = fields
            seen = (
                int(address, 16),
                int(first),
                _text(qualname),
                _text(filename),
                linetable,
            )
        except (ValueError, KeyError):
            return f"frame {depth}: not read ({' '.join(fields)[:80]})"
        want = (
            id(code),
            code.co_firstlineno,
            code.co_qualname,
            code.co_filename,
            code.co_linetable.hex() or "-",
        )
        if seen != want:
            return f"frame {depth} ({code.co_qualname}): read {seen[:4]}, expected {want[:4]}"
        # This frame has moved on since the walk; its callers are where
        # they were.
        if depth and int(index) != frame.f_lasti // 2 + 1:
            return f"frame {depth} ({code.co_qualname}): at instruction {int(index) - 1}, expected {frame.f_lasti // 2}"
        frame = frame.f_back
    if whole and frame is not None:
        return f"read {len(got)} frames, Python has more (next: {frame.f_code.co_qualname})"
    return None


def _walk_differs_beneath_a_wide_name(hooks):
    """_walk_differs with a function on the stack whose name is not ASCII.
    Such a str keeps its text at another offset than an ASCII one, and the
    names of the functions that happen to be running seldom have one: this
    puts that offset under the check at every install."""

    def probe():
        return _walk_differs(hooks)

    probe.__code__ = probe.__code__.replace(co_qualname="probe_\u00e9_\u65e5")
    return probe()


_stop_at_exit = False


def _install_python(hooks):
    """Install the "python" backtrace once it reads this thread's stack
    right; return why not, or None."""
    global _stop_at_exit
    if hooks.systing_heap_hooks_active() == b"python":
        # Installed and checked already, here or in the process this one
        # was forked from: its code map is in use.
        return None
    rc = hooks.systing_heap_hooks_prepare(b"python")
    if rc != 0:
        return hooks.systing_heap_hooks_strerror(rc).decode()
    why = _walk_differs_beneath_a_wide_name(hooks)
    if why is not None:
        unused = hooks.systing_heap_hooks_python_map()
        hooks.systing_heap_hooks_python_stop()
        try:
            os.unlink(unused)
        except OSError:
            pass
        return f"python frames: this interpreter is not laid out as expected ({why})"
    rc = hooks.systing_heap_hooks_install(b"python")
    if rc != 0:
        return hooks.systing_heap_hooks_strerror(rc).decode()
    if not _stop_at_exit:
        # As it exits, the interpreter frees the state of threads that are
        # still running: no walk may read it after that.
        atexit.register(hooks.systing_heap_hooks_python_stop)
        _stop_at_exit = True
    return None


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


def install(backtrace="libunwind", trampolines=None, strict=False, lib=None):
    """Install `backtrace` ("python", "libunwind" or "default") and, with
    `trampolines`, Python's perf trampolines (on by default unless the
    backtrace is "python"). Returns what is active."""
    reasons = []
    active_trampolines = False

    if trampolines is None:
        trampolines = backtrace != "python"
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
        if backtrace == "python":
            why = _install_python(hooks)
            if why is not None:
                reasons.append(why)
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
