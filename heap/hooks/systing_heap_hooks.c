/*
 * systing-heap hooks: optional replacements for how jemalloc captures the
 * stack of a sampled allocation, installed at runtime by the program that
 * wants them (see systing_heap_hooks.py).
 *
 * jemalloc (>= 5.3) lets a program replace its backtrace function through
 * the "experimental.hooks.prof_backtrace" mallctl. The distro jemalloc
 * captures stacks with libgcc's unwinder, which stops at code without unwind
 * tables, such as Python's perf trampolines (-X perf, PYTHONPERFSUPPORT=1).
 * libunwind falls back to frame pointers there and walks the whole stack.
 *
 * Backtraces:
 *   "default"    jemalloc's own (restores it if another was installed)
 *   "libunwind"  unw_backtrace() from libunwind.so.8, loaded at runtime so
 *                this library loads on machines without it
 *
 * The library links only libdl and libpthread, and does nothing until
 * systing_heap_hooks_install() is called.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "systing_heap_hooks.h"

typedef int (*mallctl_fn)(const char *, void *, size_t *, void *, size_t);
typedef void (*prof_backtrace_hook_t)(void **, unsigned *, unsigned);
typedef int (*unw_backtrace_fn)(void **, int);

/* install() runs from any thread; this guards the statics below. */
static pthread_mutex_t install_lock = PTHREAD_MUTEX_INITIALIZER;
/*
 * Held for each unwind. libunwind's cache takes a lock of its own and
 * registers no fork handler, so a fork while another thread unwinds would
 * leave that lock held in the child; the fork handlers below wait on this
 * one instead, so no unwind is in progress when the process forks.
 */
static pthread_mutex_t unwind_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t fork_handlers_once = PTHREAD_ONCE_INIT;
/*
 * The thread that holds unwind_lock across a fork. Other libraries' fork
 * handlers run inside that window on that thread, and one that allocates can
 * be sampled: that thread must not wait on the lock it holds. (A thread
 * handle, not a __thread flag: in a dlopen'd library a __thread variable's
 * first use on a thread can allocate.)
 */
static pthread_t forking_thread;
static _Atomic int forking;
static mallctl_fn mallctl_p;
static prof_backtrace_hook_t jemalloc_default;
static unw_backtrace_fn unw_backtrace_p;
static const char *active = "default";

static void libunwind_backtrace(void **vec, unsigned *len, unsigned max_len)
{
	/*
	 * Unwind into jemalloc's own array (no buffer of ours on the stack
	 * inside malloc), then drop this function's frame so jemalloc's stacks
	 * start where its own backends' do. At full depth that costs the
	 * outermost frame.
	 */
	/* jemalloc holds none of its locks here and never calls this
	 * reentrantly; the one thread that may already hold unwind_lock is
	 * the one forking, which records no stack instead. */
	if (forking && pthread_equal(forking_thread, pthread_self())) {
		*len = 0;
		return;
	}
	pthread_mutex_lock(&unwind_lock);
	int n = unw_backtrace_p(vec, (int)max_len);
	pthread_mutex_unlock(&unwind_lock);
	if (n <= 1) {
		*len = 0;
		return;
	}
	memmove(vec, vec + 1, (size_t)(n - 1) * sizeof(void *));
	*len = (unsigned)(n - 1);
}

static mallctl_fn find_mallctl(void)
{
	/* The plain name, then the prefixed names jemalloc builds export. */
	static const char *const names[] = {"mallctl", "je_mallctl",
					    "_rjem_mallctl"};
	for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
		void *p = dlsym(RTLD_DEFAULT, names[i]);
		if (p)
			return (mallctl_fn)p;
	}
	return NULL;
}

static int set_hook(prof_backtrace_hook_t hook)
{
	prof_backtrace_hook_t old;
	size_t old_len = sizeof(old);
	if (mallctl_p("experimental.hooks.prof_backtrace", &old, &old_len,
		      &hook, sizeof(hook)) != 0)
		return SHH_ERR_NO_HOOK;
	/* The first swap returns jemalloc's own function: keep it to restore. */
	if (!jemalloc_default)
		jemalloc_default = old;
	return SHH_OK;
}

static void before_fork(void)
{
	pthread_mutex_lock(&unwind_lock);
	forking_thread = pthread_self();
	forking = 1;
}

static void after_fork_parent(void)
{
	forking = 0;
	pthread_mutex_unlock(&unwind_lock);
}

static void after_fork_child(void)
{
	/* The child's thread is the one that forked, with the same handle. */
	forking = 0;
	pthread_mutex_unlock(&unwind_lock);
	/* The child's only thread is the one that forked: an install that
	 * another thread had in progress never finishes there. install_lock is
	 * not taken before the fork because an install holds it while it waits
	 * on jemalloc's own locks, which jemalloc's fork handler holds. */
	pthread_mutex_init(&install_lock, NULL);
}

static void register_fork_handlers(void)
{
	pthread_atfork(before_fork, after_fork_parent, after_fork_child);
}

static int load_libunwind(void)
{
	if (unw_backtrace_p)
		return SHH_OK;
	/* SYSTING_HEAP_HOOKS_LIBUNWIND names another library (or, in tests, a
	 * missing one); ignored in a setuid or file-capability process. */
	const char *name = secure_getenv("SYSTING_HEAP_HOOKS_LIBUNWIND");
	const char *const names[] = {name ? name : "libunwind.so.8",
				     name ? NULL : "libunwind.so"};
	for (size_t i = 0; i < 2 && names[i]; i++) {
		void *h = dlopen(names[i], RTLD_NOW | RTLD_LOCAL);
		if (!h)
			continue;
		void *p = dlsym(h, "unw_backtrace");
		if (p) {
			unw_backtrace_p = (unw_backtrace_fn)p;
			return SHH_OK;
		}
		dlclose(h);
	}
	return SHH_ERR_NO_LIBUNWIND;
}

static int install_locked(const char *backtrace);

int systing_heap_hooks_install(const char *backtrace)
{
	pthread_once(&fork_handlers_once, register_fork_handlers);
	pthread_mutex_lock(&install_lock);
	int rc = install_locked(backtrace);
	pthread_mutex_unlock(&install_lock);
	return rc;
}

static int install_locked(const char *backtrace)
{
	if (!backtrace)
		return SHH_ERR_UNKNOWN_BACKTRACE;
	bool want_default = strcmp(backtrace, "default") == 0;
	bool want_libunwind = strcmp(backtrace, "libunwind") == 0;
	if (!want_default && !want_libunwind)
		return SHH_ERR_UNKNOWN_BACKTRACE;

	if (!mallctl_p)
		mallctl_p = find_mallctl();
	if (!mallctl_p)
		return SHH_ERR_NO_JEMALLOC;

	bool prof = false;
	size_t prof_len = sizeof(prof);
	if (mallctl_p("opt.prof", &prof, &prof_len, NULL, 0) != 0 || !prof)
		return SHH_ERR_PROF_OFF;

	if (want_default) {
		if (jemalloc_default) {
			int rc = set_hook(jemalloc_default);
			if (rc != SHH_OK)
				return rc;
		}
		active = "default";
		return SHH_OK;
	}

	int rc = load_libunwind();
	if (rc != SHH_OK)
		return rc;
	rc = set_hook(libunwind_backtrace);
	if (rc != SHH_OK)
		return rc;
	active = "libunwind";
	return SHH_OK;
}

const char *systing_heap_hooks_active(void)
{
	pthread_mutex_lock(&install_lock);
	const char *a = active;
	pthread_mutex_unlock(&install_lock);
	return a;
}

const char *systing_heap_hooks_strerror(int code)
{
	switch (code) {
	case SHH_OK:
		return "ok";
	case SHH_ERR_UNKNOWN_BACKTRACE:
		return "unknown backtrace (expected \"default\" or \"libunwind\")";
	case SHH_ERR_NO_JEMALLOC:
		return "jemalloc is not this process's allocator (no mallctl)";
	case SHH_ERR_PROF_OFF:
		return "jemalloc profiling is off (MALLOC_CONF has no prof:true)";
	case SHH_ERR_NO_HOOK:
		return "this jemalloc has no prof_backtrace hook (needs >= 5.3)";
	case SHH_ERR_NO_LIBUNWIND:
		return "libunwind.so.8 not found";
	default:
		return "unknown error";
	}
}
