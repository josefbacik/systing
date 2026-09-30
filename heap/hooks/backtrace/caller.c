/*
 * systing-heap hooks: whether the dynamic loader called malloc.
 *
 * A backtrace runs inside malloc, on top of whatever called malloc, in the
 * middle of that caller's work. jemalloc keeps a backtrace from being entered
 * twice. It cannot keep one from entering its caller, and the loader is not
 * made to be entered again.
 *
 * Every thread has a table of its thread-local blocks, made with room for 14
 * more libraries than there were. After a library with thread-local variables
 * is loaded, each thread brings its own table up to date the next time it reads
 * one through __tls_get_addr(), and grows it with realloc() where it has become
 * too small. Read another one from inside that realloc(), whoever's it is, and
 * the loader starts the same update again and reallocates the same table. If
 * that moves it, the outer realloc() then frees a block that has been freed.
 * libunwind keeps a cache in such variables, and a shared libpython can keep its
 * thread state in one.
 *
 * So a backtrace finds out whether the loader called malloc before it calls
 * anything that may read such a variable, and where the loader did, calls
 * nothing that does (backtrace.c, python.c). An unwinder cannot be what finds out. What does is a
 * look at the stack: malloc's return address is a little way above the
 * backtrace's frame, past jemalloc's own frames, and an address in the loader's
 * code is looked for among the words there.
 *
 * The look errs one way. Words that calls long returned have left behind are
 * taken for a caller too, and stay where they are for as long as nothing writes
 * over them: every allocation from one place in a program can be answered
 * wrongly. So what a backtrace does instead gives up next to nothing. Missing the
 * caller would cost the heap, so much more of the stack is looked at than
 * jemalloc's frames have been seen to take (README.md has the numbers), and a
 * stack that cannot be read is answered as if the loader had called.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <sys/auxv.h>
#include <sys/uio.h>
#include <unistd.h>

#include "../systing_heap_hooks.h"
#include "caller.h"

/* How much of the stack is looked at, in words: 4 KiB. It is copied to this
 * function's own frame, which is gone again before an unwinder is called. */
#define SEEN 512

/* The loader's code: [start, start + size). Written under the lock of whoever
 * installs a backtrace, before the backtrace is installed. */
static uintptr_t loader_start, loader_size;

/* The library to find: the one loaded at `base`, or else the one `inside` is
 * in. */
struct library {
	uintptr_t base, inside;
	uintptr_t code_start, code_size;
	size_t thread_locals;
};

static int look_at(struct dl_phdr_info *info, size_t size, void *arg)
{
	(void)size;
	struct library *l = arg;
	if (l->base && info->dlpi_addr != l->base)
		return 0;
	size_t thread_locals = 0;
	for (int i = 0; i < info->dlpi_phnum; i++) {
		const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
		uintptr_t start = info->dlpi_addr + ph->p_vaddr;
		if (ph->p_type == PT_LOAD && (ph->p_flags & PF_X) &&
		    (l->base || l->inside - start < ph->p_memsz)) {
			l->code_start = start;
			l->code_size = ph->p_memsz;
		}
		if (ph->p_type == PT_TLS)
			thread_locals = ph->p_memsz;
	}
	if (!l->code_size)
		return 0;
	l->thread_locals = thread_locals;
	return 1;
}

int shh_find_loader(void)
{
	if (loader_size)
		return SHH_OK;
	/* Where the kernel put the program's interpreter, which no library can
	 * stand in front of. There is none where the loader was itself run as the
	 * program: then the library __tls_get_addr is in, looked up by name so
	 * that this library does not itself depend on it. */
	struct library l = {.base = getauxval(AT_BASE)};
	if (!l.base)
		l.inside = (uintptr_t)dlsym(RTLD_DEFAULT, "__tls_get_addr");
	if (l.base || l.inside)
		dl_iterate_phdr(look_at, &l);
	loader_start = l.code_start;
	loader_size = l.code_size;
	return loader_size ? SHH_OK : SHH_ERR_NO_LOADER;
}

size_t shh_thread_locals(uintptr_t pc)
{
	struct library l = {.inside = pc};
	dl_iterate_phdr(look_at, &l);
	return l.thread_locals;
}

ssize_t shh_read_self(void *dst, uintptr_t src, size_t len)
{
	struct iovec l = {dst, len}, r = {(void *)src, len};
	return process_vm_readv(getpid(), &l, 1, &r, 1, 0);
}

int shh_loader_called_malloc(const void *above, shh_read_fn read)
{
	uintptr_t word[SEEN];
	/* Fewer than were asked for is the end of the stack: all there is of it
	 * has been seen. */
	ssize_t got = read(word, (uintptr_t)above, sizeof(word));
	if (got <= 0)
		return 1;
	for (size_t i = 0; i < (size_t)got / sizeof(word[0]); i++)
		if (word[i] - loader_start < loader_size)
			return 1;
	return 0;
}
