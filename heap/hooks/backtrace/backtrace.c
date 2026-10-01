/*
 * systing-heap hooks: the backtraces. Optional replacements for how jemalloc
 * captures the stack of a sampled allocation, installed at runtime by the
 * program that wants them (see systing_heap_hooks.py).
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
 *                this library loads on machines without it. A frame at a time
 *                where the dynamic loader called malloc (caller.c)
 *   "python"     jemalloc's own, then the allocating thread's Python frames
 *                read from the interpreter (python.c)
 *
 * Nothing here runs until systing_heap_hooks_install() is called.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>

#include "../common/common.h"
#include "../systing_heap_hooks.h"
#include "caller.h"
#include "python.h"

typedef shh_mallctl_fn mallctl_fn;
typedef shh_backtrace_fn prof_backtrace_hook_t;
typedef int (*unw_backtrace_fn)(void **, int);

/* install() runs from any thread; this guards the statics below. */
static pthread_mutex_t install_lock = PTHREAD_MUTEX_INITIALIZER;
/*
 * Held for each unwind. libunwind's cache takes a lock of its own and
 * registers no fork handler, so a fork while another thread unwinds would
 * leave that lock held in the child; the fork handlers below wait on this
 * one instead, so no unwind is in progress when the process forks.
 *
 * Only they wait on it, and install(), for its walks through the libraries
 * (caller.h). A backtrace does not. libunwind asks for the dynamic loader's list lock
 * (dl_iterate_phdr()) while this one is held, and a sampled allocation may
 * come from a thread that holds the loader's: a callback of
 * dl_iterate_phdr() that allocates. If that thread waited here, each of the
 * two would wait for the lock the other holds, for good.
 */
static pthread_mutex_t unwind_lock = PTHREAD_MUTEX_INITIALIZER;
static mallctl_fn mallctl_p;
static prof_backtrace_hook_t jemalloc_default;
static unw_backtrace_fn unw_backtrace_p;
static const char *active = "default";

/*
 * libunwind a frame at a time, which is what unw_backtrace() itself falls back
 * to. It gives the same stack, four times slower: without the cache per thread
 * that makes unw_backtrace() fast, and that cache is all libunwind keeps in
 * thread-local variables. So it can be called where the loader called malloc.
 *
 * The names are those <libunwind.h> gives unw_getcontext() and the rest on
 * x86-64, where they are all functions. Where there are none (find_steps()),
 * what the loader may have allocated is recorded with no stack.
 */
static struct {
	int (*getcontext)(ucontext_t *);
	int (*init_local)(void *cursor, ucontext_t *);
	int (*step)(void *cursor);
	int (*get_reg)(void *cursor, int reg, uintptr_t *value);
} steps;
#define UNW_REG_IP 16
/* Under unwind_lock. A cursor is 127 words. */
static ucontext_t steps_context;
static uintptr_t steps_cursor[256];

static void libunwind_backtrace(void **vec, unsigned *len, unsigned max_len)
{
	*len = 0;
	/* jemalloc holds none of its locks here and never calls this
	 * reentrantly; the one thread that may already hold unwind_lock is
	 * the one forking, which records no stack instead. */
	if (shh_forking_here())
		return;
	/* A malloc that succeeds is expected to leave errno alone, and libunwind
	 * changes it where it checks an address before reading it. */
	int saved_errno = errno;
	bool by_loader = shh_loader_called_malloc(__builtin_frame_address(0), shh_read_self);
	/* Nor does a thread that finds another one unwinding: see unwind_lock. */
	if (pthread_mutex_trylock(&unwind_lock) != 0) {
		errno = saved_errno;
		return;
	}
	/*
	 * Unwind into jemalloc's own array (no buffer of ours is on the stack
	 * while an unwinder runs), from this function's caller, so that
	 * jemalloc's stacks start where its own backends' do.
	 */
	if (!by_loader) {
		/* This function's frame comes first. At full depth dropping it
		 * costs the outermost one. */
		int n = unw_backtrace_p(vec, (int)max_len);
		if (n > 1) {
			memmove(vec, vec + 1, (size_t)(n - 1) * sizeof(void *));
			*len = (unsigned)(n - 1);
		}
		shh_missed(vec, *len);
	} else if (steps.step) {
		unsigned n = 0;
		uintptr_t ip;
		steps.getcontext(&steps_context);
		if (steps.init_local(steps_cursor, &steps_context) >= 0)
			/* As many frames as the other way keeps. */
			while (n + 1 < max_len && steps.step(steps_cursor) > 0 &&
			       steps.get_reg(steps_cursor, UNW_REG_IP, &ip) >= 0)
				vec[n++] = (void *)ip;
		*len = n;
	}
	pthread_mutex_unlock(&unwind_lock);
	errno = saved_errno;
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
}

static void after_fork_in_parent(void)
{
	pthread_mutex_unlock(&unwind_lock);
}

static void after_fork_in_child(void)
{
	pthread_mutex_unlock(&unwind_lock);
	/* The child's only thread is the one that forked: an install that
	 * another thread had in progress never finishes there. install_lock is
	 * not taken before the fork because an install holds it while it waits
	 * on jemalloc's own locks, which jemalloc's fork handler holds. */
	pthread_mutex_init(&install_lock, NULL);
}

/* Added before the "python" backtrace's part, whose lock is taken inside
 * this one's. */
static const struct shh_fork_part fork_part = {before_fork, after_fork_in_parent,
					       after_fork_in_child};

static void find_steps(void *libunwind, void *unw_backtrace)
{
#ifdef __x86_64__
	/* A libunwind built with --enable-per-thread-cache keeps more in
	 * thread-local variables than the cache of unw_backtrace(), which is a
	 * pointer and a flag, and reads it at each step. */
	if (shh_thread_locals((uintptr_t)unw_backtrace, &unwind_lock) > 2 * sizeof(void *))
		return;
	*(void **)&steps.getcontext = dlsym(libunwind, "_Ux86_64_getcontext");
	*(void **)&steps.init_local = dlsym(libunwind, "_ULx86_64_init_local");
	*(void **)&steps.get_reg = dlsym(libunwind, "_ULx86_64_get_reg");
	if (steps.getcontext && steps.init_local && steps.get_reg)
		*(void **)&steps.step = dlsym(libunwind, "_ULx86_64_step");
#else
	(void)libunwind;
	(void)unw_backtrace;
#endif
}

static int load_libunwind(void)
{
	/* Stored last, as in shh_find_loader(). */
	if (__atomic_load_n(&unw_backtrace_p, __ATOMIC_ACQUIRE))
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
			find_steps(h, p);
			__atomic_store_n(&unw_backtrace_p, (unw_backtrace_fn)p, __ATOMIC_RELEASE);
			return SHH_OK;
		}
		dlclose(h);
	}
	return SHH_ERR_NO_LIBUNWIND;
}

static int install_locked(const char *backtrace, bool install);

int systing_heap_hooks_install(const char *backtrace)
{
	shh_at_fork(&fork_part);
	pthread_mutex_lock(&install_lock);
	int rc = install_locked(backtrace, true);
	pthread_mutex_unlock(&install_lock);
	return rc;
}

int systing_heap_hooks_prepare(const char *backtrace)
{
	shh_at_fork(&fork_part);
	pthread_mutex_lock(&install_lock);
	int rc = install_locked(backtrace, false);
	pthread_mutex_unlock(&install_lock);
	return rc;
}

/* The backtrace installed now, which the first swap would otherwise be the
 * one to tell: jemalloc's own, unless the program put another there. */
static int find_default(void)
{
	if (jemalloc_default)
		return SHH_OK;
	prof_backtrace_hook_t now = NULL;
	size_t len = sizeof(now);
	if (mallctl_p("experimental.hooks.prof_backtrace", &now, &len, NULL, 0) != 0 ||
	    !now)
		return SHH_ERR_NO_HOOK;
	jemalloc_default = now;
	return SHH_OK;
}

static int install_locked(const char *backtrace, bool install)
{
	if (!backtrace)
		return SHH_ERR_UNKNOWN_BACKTRACE;
	bool want_default = strcmp(backtrace, "default") == 0;
	bool want_libunwind = strcmp(backtrace, "libunwind") == 0;
	bool want_python = strcmp(backtrace, "python") == 0;
	if (!want_default && !want_libunwind && !want_python)
		return SHH_ERR_UNKNOWN_BACKTRACE;

	if (!mallctl_p)
		mallctl_p = shh_find_mallctl();
	if (!mallctl_p)
		return SHH_ERR_NO_JEMALLOC;

	bool prof = false;
	size_t prof_len = sizeof(prof);
	if (mallctl_p("opt.prof", &prof, &prof_len, NULL, 0) != 0 || !prof)
		return SHH_ERR_PROF_OFF;

	/* jemalloc's own is as safe as it is without this library. */
	if (!want_default) {
		int rc = shh_find_loader(&unwind_lock);
		if (rc != SHH_OK)
			return rc;
	}

	if (want_python) {
		int rc = find_default();
		if (rc == SHH_OK)
			rc = shh_python_prepare(mallctl_p, jemalloc_default);
		if (rc == SHH_OK && install)
			rc = set_hook(systing_heap_hooks_python_backtrace);
		if (rc == SHH_OK && install)
			active = "python";
		return rc;
	}
	if (!install)
		return SHH_OK;

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
	/* Where the stack cannot be read, every allocation is taken for the
	 * loader's. That costs time where libunwind can be driven a frame at a
	 * time, and every stack where it cannot. "python" finds a read of its
	 * own. */
	char from = 1, to = 0;
	if (!steps.step && (shh_read_self(&to, (uintptr_t)&from, 1) != 1 || to != from))
		return SHH_ERR_STACK_READ;
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
