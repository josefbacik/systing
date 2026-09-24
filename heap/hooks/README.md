# systing-heap hooks

Optional replacements for how jemalloc captures a sampled allocation's stack, installed at runtime by the program that wants them.
See "Python stacks" in [`../README.md`](../README.md) for when to use them.

- `systing_heap_hooks.c` / `.h`: the library. It links only libdl and does nothing until `systing_heap_hooks_install()` is called.
- `systing_heap_hooks.py`: the Python helper that loads the library with `ctypes` and can turn on perf trampolines.
- `make` builds `libsysting_heap_hooks.so`; `make OUT=/dir` puts it elsewhere.

The helper finds the library through its `lib` argument, then `SYSTING_HEAP_HOOKS_LIB`, then next to the `.py` file.
`SYSTING_HEAP_HOOKS_LIBUNWIND` names the libunwind to load instead of `libunwind.so.8`.

Backtraces: `"default"` (jemalloc's own) and `"libunwind"`.
Each is one entry in `systing_heap_hooks_install()`, so a further one, such as reading CPython's frames directly for line numbers, is added the same way.
