/*
 * systing-heap hooks: what the pieces of the library share, and no more, so
 * that each piece can be built without the others. Finding jemalloc, one
 * registration with fork() that every piece takes part in, the code map's
 * way from the piece that writes it to the piece that hands it over, and
 * what the error codes mean.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdatomic.h>

#include "../systing_heap_hooks.h"
#include "common.h"

/* The pieces there are, and room for one more. */
#define MAX_PARTS 4

static const struct shh_fork_part *parts[MAX_PARTS];
static int n_parts;
/*
 * Held while a part is added, and across every fork: the parts that were
 * asked before a fork are the ones told after it, and two threads that fork
 * at once take their turns. Nothing is done under it but the parts' own
 * handlers, which allocate nothing.
 */
static pthread_mutex_t parts_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t once = PTHREAD_ONCE_INIT;
/*
 * The thread that is forking. Other libraries' fork handlers run inside that
 * window on that thread, and one that allocates can be sampled: that thread
 * must not wait on a lock one of the parts holds. (A thread handle, not a
 * __thread flag: in a dlopen'd library a __thread variable's first use on a
 * thread can allocate.)
 */
static pthread_t forking_thread;
static _Atomic int forking;
static const char *(*_Atomic code_map_p)(void);

shh_mallctl_fn shh_find_mallctl(void)
{
	/* The plain name, then the prefixed names jemalloc builds export. */
	static const char *const names[] = {"mallctl", "je_mallctl",
					    "_rjem_mallctl"};
	for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
		void *p = dlsym(RTLD_DEFAULT, names[i]);
		if (p)
			return (shh_mallctl_fn)p;
	}
	return NULL;
}

int shh_forking_here(void)
{
	return forking && pthread_equal(forking_thread, pthread_self());
}

static void before_fork(void)
{
	pthread_mutex_lock(&parts_lock);
	for (int i = 0; i < n_parts; i++)
		if (parts[i]->before)
			parts[i]->before();
	forking_thread = pthread_self();
	forking = 1;
}

static void after_fork_in_parent(void)
{
	forking = 0;
	for (int i = n_parts - 1; i >= 0; i--)
		if (parts[i]->after_in_parent)
			parts[i]->after_in_parent();
	pthread_mutex_unlock(&parts_lock);
}

static void after_fork_in_child(void)
{
	/* The child's thread is the one that forked, with the same handle. */
	forking = 0;
	for (int i = n_parts - 1; i >= 0; i--)
		if (parts[i]->after_in_child)
			parts[i]->after_in_child();
	/* Made anew and not unlocked: the child's one thread is a new one to
	 * the lock, whatever its handle says. */
	pthread_mutex_init(&parts_lock, NULL);
}

static void register_with_fork(void)
{
	pthread_atfork(before_fork, after_fork_in_parent, after_fork_in_child);
}

void shh_at_fork(const struct shh_fork_part *part)
{
	pthread_once(&once, register_with_fork);
	pthread_mutex_lock(&parts_lock);
	int have = 0;
	for (int i = 0; i < n_parts; i++)
		have |= parts[i] == part;
	if (!have && n_parts < MAX_PARTS)
		parts[n_parts++] = part;
	pthread_mutex_unlock(&parts_lock);
}

void shh_set_code_map(const char *(*path)(void))
{
	atomic_store(&code_map_p, path);
}

const char *shh_code_map(void)
{
	const char *(*path)(void) = atomic_load(&code_map_p);
	return path ? path() : "";
}

const char *systing_heap_hooks_strerror(int code)
{
	switch (code) {
	case SHH_OK:
		return "ok";
	case SHH_ERR_UNKNOWN_BACKTRACE:
		return "unknown backtrace (expected \"default\", \"libunwind\" or \"python\")";
	case SHH_ERR_NO_JEMALLOC:
		return "jemalloc is not this process's allocator (no mallctl)";
	case SHH_ERR_PROF_OFF:
		return "jemalloc profiling is off (MALLOC_CONF has no prof:true)";
	case SHH_ERR_NO_HOOK:
		return "this jemalloc has no prof_backtrace hook (needs >= 5.3)";
	case SHH_ERR_NO_LIBUNWIND:
		return "libunwind.so.8 not found";
	case SHH_ERR_NO_PYTHON:
		return "no Python interpreter in this process (its symbols are not exported)";
	case SHH_ERR_PY_VERSION:
		return "python frames need CPython 3.12, 3.13 or 3.14";
	case SHH_ERR_PY_READ:
		return "python frames: no protected way to read memory (process_vm_readv and /proc/self/mem both refused)";
	case SHH_ERR_PY_MAP:
		return "python frames: cannot start the code map beside the dumps (memfd_create, or the prof_prefix directory is not writable)";
	case SHH_ERR_SOCKET_PATH:
		return "the responder's socket: its path is too long for a Unix socket";
	case SHH_ERR_SOCKET:
		return "the responder's socket: cannot listen there (the directory is missing or not writable, another process answers at that path, or no thread could be started)";
	case SHH_ERR_LISTEN_HOW:
		return "expected 1 (this process listens) or fork (and the processes it forks)";
	case SHH_ERR_NO_LOADER:
		return "the dynamic loader's code was not found, so a backtrace could not tell when it is what called malloc";
	case SHH_ERR_STACK_READ:
		return "no protected way to read the stack (process_vm_readv refused), so a backtrace could not tell whether the dynamic loader called malloc";
	default:
		return "unknown error";
	}
}
