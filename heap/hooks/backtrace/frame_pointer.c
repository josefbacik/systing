/*
 * systing-heap hooks: the "frame-pointer" backtrace. A sampled allocation's
 * stack, walked through code that has no unwind tables, such as Python's perf
 * trampolines (-X perf, PYTHONPERFSUPPORT=1), where jemalloc's own walk ends.
 *
 * Two walks, one after the other:
 *
 *   1. By unwind tables, with libgcc's _Unwind_Backtrace, as the distro's
 *      jemalloc does it. It gets out of code built without frame pointers,
 *      which most binary Python packages are, and it ends at the first frame
 *      without tables.
 *   2. By frame pointers from there on: each frame's record holds its caller's
 *      frame pointer and the address it returns to. The interpreter has to be
 *      built with them (-fno-omit-frame-pointer). Code that was not built with
 *      them and calls back into Python either left the register alone, and its
 *      own frames are passed over, or used it for something else, and the
 *      stack ends there.
 *
 * The second walk follows the frame-pointer unwinder jemalloc had between 2024
 * and 2026 (--enable-prof-frameptr, src/prof_sys.c): a record is believed only
 * inside the range of the thread's stack, which is read from /proc and
 * remembered per thread, and a thread found on some other stack does without
 * frame pointers from then on. What differs from it, and why:
 *
 *   - jemalloc read the records with plain loads. What is remembered of a range
 *     can outlive it: the kernel shows neighbouring mappings as one, so a stack
 *     the program made for itself right below a thread's is in the thread's
 *     range, and can be unmapped later. Here the kernel makes every read
 *     (process_vm_readv), a window of the stack at a time, so a bad address is
 *     an error and not a fault. The range is what keeps false frames out.
 *   - jemalloc remembered the range in a __thread variable. In a library that
 *     is loaded with dlopen(), reading one goes through the dynamic loader,
 *     which malloc's caller can be (../common/common.h). It is kept under two
 *     pthread keys instead. Nothing here may enter the loader: no __thread
 *     variable, no dl*() function, no function bound at its first call (the
 *     Makefile links with -z now). The one way in that is left is libgcc's, to
 *     ask which library an address is in. It changes nothing there, and
 *     jemalloc's own backtrace makes the same call at every sample.
 *   - The range ends below the end of the mapping, at an address known to be
 *     above the stack in the same block (stack_bounds()).
 *   - A record must be 16-byte aligned, as the ABI has it, and further up the
 *     stack than the one before (jemalloc's first version had the latter).
 *     With the range, that left no false frame in some 6,000 stacks captured
 *     under numpy, pandas, pyarrow, torch and others. The range alone left one
 *     in 2% of them, and alignment alone in 3%.
 *   - The whole record must be inside the range, not just its first byte.
 *   - jemalloc fell back to backtrace(), which loads libgcc at its first call.
 *     Here the walk by tables has been made already.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/auxv.h>
#include <sys/uio.h>
#include <unistd.h>
#include <unwind.h>

#include "../common/common.h"
#include "../systing_heap_hooks.h"
#include "frame_pointer.h"

#if defined(__x86_64__) && !defined(__ILP32__)
/* rbp, by its number in the unwind tables. */
#define FRAME_POINTER_REGISTER 6
#endif

#ifdef FRAME_POINTER_REGISTER

/* A frame's record: two words, at an address that is a multiple of this. */
#define RECORD_SIZE (2 * sizeof(uintptr_t))

/*
 * The calling thread's range: records are believed in [low, high). high is 0
 * until the thread has been looked at, and NO_WALK once it was found on a
 * stack that cannot be vouched for. The values are the numbers themselves, so
 * this file allocates nothing for them.
 *
 * glibc does, inside pthread_setspecific, for the 33rd key of a process and
 * later ones: a block for each 32 keys, at a thread's first use of one of
 * them. That is malloc called from inside malloc, which jemalloc allows a
 * backtrace. If the allocation being sampled is that very one, made for a key
 * of the same 32, glibc's call goes on to put its own block in place of the one
 * made here: 512 bytes are lost, and the thread is looked at again.
 */
static pthread_key_t low_key, high_key;
#define NO_WALK ((uintptr_t)1)
static bool prepared;
/* An address the kernel put above the process's first stack, in its mapping. */
static uintptr_t above_first_stack;

/*
 * Where records of the stack that `here` is on are believed, or false: from
 * `here` up to *high, which is in the same mapping and is
 *
 *   - the thread's control block, which the C library puts at the top of the
 *     block it makes the stack in (glibc and musl both), or
 *   - for the process's first stack, the random bytes the kernel leaves above
 *     it for the program (AT_RANDOM).
 *
 * Below either, and above the frames, are the thread's static thread-local
 * variables, or the program's arguments and environment.
 *
 * A stack with neither above it is one the program made for itself (a fiber's,
 * a signal handler's). As in jemalloc: "If the stack range has changed, it is
 * likely to change again in the future", and reading /proc each time is dear,
 * so the thread goes without from then on. The first stack growing downwards
 * is not that: it is looked up again and found to be the same stack.
 */
static bool stack_bounds(uintptr_t here, uintptr_t *high)
{
	uintptr_t low = (uintptr_t)pthread_getspecific(low_key);
	*high = (uintptr_t)pthread_getspecific(high_key);
	if (*high == NO_WALK)
		return false;
	if (low && here >= low && here < *high)
		return true;

	uintptr_t end, self = (uintptr_t)pthread_self();
	*high = NO_WALK;
	if (shh_mapping_containing(here, &low, &end) == 0) {
		if (self > here && self < end)
			*high = self & ~(RECORD_SIZE - 1);
		else if (above_first_stack > here && above_first_stack < end)
			*high = above_first_stack & ~(RECORD_SIZE - 1);
	}
	/* Both or neither: what cannot be kept is looked up again next time. */
	if (pthread_setspecific(low_key, (void *)low) != 0 ||
	    pthread_setspecific(high_key, (void *)*high) != 0)
		pthread_setspecific(low_key, NULL);
	return *high != NO_WALK;
}

/* A copy of a piece of the stack: [start, end). */
struct window {
	uintptr_t start, end;
	uintptr_t words[4096 / sizeof(uintptr_t)];
};

/* The record at `fp`, which is inside [.., high), or NULL if it cannot be
 * read. The window is filled from `fp` up: that is the way the walk goes. */
static const uintptr_t *record_at(struct window *w, uintptr_t fp, uintptr_t high,
				  pid_t pid)
{
	if (fp < w->start || fp > w->end - RECORD_SIZE) {
		size_t want = high - fp < sizeof(w->words) ? high - fp : sizeof(w->words);
		struct iovec to = {w->words, want}, from = {(void *)fp, want};
		ssize_t got = process_vm_readv(pid, &to, 1, &from, 1, 0);
		if (got < (ssize_t)RECORD_SIZE)
			return NULL;
		w->start = fp;
		w->end = fp + (uintptr_t)got;
	}
	return &w->words[(fp - w->start) / sizeof(uintptr_t)];
}

/*
 * Add to vec[n..max) the return addresses of the records from `fp` up, and
 * return the new n. `fp` may be anything: code built without frame pointers
 * uses the register for whatever it likes. It is believed while it is aligned,
 * in [low, high) and above the last record, so the walk ends, and what it can
 * be misled by is in the stack itself.
 */
static unsigned by_frame_pointers(uintptr_t fp, uintptr_t low, uintptr_t high,
				  void **vec, unsigned n, unsigned max)
{
	struct window w;
	w.start = w.end = RECORD_SIZE;
	pid_t pid = getpid();
	while (n < max && fp >= low && fp <= high - RECORD_SIZE &&
	       fp % RECORD_SIZE == 0) {
		const uintptr_t *record = record_at(&w, fp, high, pid);
		if (record == NULL || record[1] == 0)
			break;
		vec[n++] = (void *)record[1];
		low = fp + RECORD_SIZE;
		fp = record[0];
	}
	return n;
}

struct by_tables {
	void **vec;
	unsigned n, max;
	/* Frames still to leave out: this file's own. */
	unsigned skip;
	/* In the last frame seen: the frame pointer, and where the stack
	 * pointer was. Its caller's record, and every one after, is above. */
	uintptr_t fp, sp;
};

/* As jemalloc's prof_unwind_callback(). */
static _Unwind_Reason_Code by_tables_frame(struct _Unwind_Context *context, void *arg)
{
	struct by_tables *w = arg;
	void *ip = (void *)_Unwind_GetIP(context);
	if (ip == NULL)
		return _URC_END_OF_STACK;
	w->fp = _Unwind_GetGR(context, FRAME_POINTER_REGISTER);
	w->sp = _Unwind_GetCFA(context);
	if (w->skip) {
		w->skip--;
		return _URC_NO_REASON;
	}
	w->vec[w->n++] = ip;
	return w->n == w->max ? _URC_END_OF_STACK : _URC_NO_REASON;
}

void shh_frame_pointer_backtrace(void **vec, unsigned *len, unsigned max_len)
{
	*len = 0;
	if (max_len == 0)
		return;
	/* malloc that succeeds is expected to leave errno alone. */
	int saved_errno = errno;
	/* Without this function's own frame: the stack starts in jemalloc. */
	struct by_tables w = {vec, 0, max_len, 1, 0, 0};
	_Unwind_Backtrace(by_tables_frame, &w);
	/* The last frame seen is the one without tables, or the outermost, whose
	 * frame pointer is 0. */
	uintptr_t here = (uintptr_t)__builtin_frame_address(0), high;
	if (w.n < max_len && w.fp >= w.sp && w.sp > here &&
	    !shh_loader_called_malloc(vec, w.n) && stack_bounds(here, &high))
		w.n = by_frame_pointers(w.fp, w.sp, high, vec, w.n, max_len);
	*len = w.n;
	errno = saved_errno;
}

static _Unwind_Reason_Code no_frame(struct _Unwind_Context *context, void *arg)
{
	(void)context;
	(void)arg;
	return _URC_NO_REASON;
}

/* Called under the lock of whoever installs a backtrace. */
int shh_frame_pointer_prepare(void)
{
	if (prepared)
		return SHH_OK;
	uintptr_t word = 0, copy;
	struct iovec to = {&copy, sizeof(copy)}, from = {&word, sizeof(word)};
	if (process_vm_readv(getpid(), &to, 1, &from, 1, 0) != (ssize_t)sizeof(word))
		return SHH_ERR_FP_READ;
	if (pthread_key_create(&low_key, NULL) != 0)
		return SHH_ERR_FP_KEYS;
	if (pthread_key_create(&high_key, NULL) != 0) {
		pthread_key_delete(low_key);
		return SHH_ERR_FP_KEYS;
	}
	above_first_stack = getauxval(AT_RANDOM);
	/* As jemalloc's prof_unwind_init(): "Cause the backtracing machinery to
	 * allocate its internal state before enabling profiling." */
	_Unwind_Backtrace(no_frame, NULL);
	prepared = true;
	return SHH_OK;
}

#else /* !FRAME_POINTER_REGISTER */

int shh_frame_pointer_prepare(void)
{
	return SHH_ERR_FP_MACHINE;
}

void shh_frame_pointer_backtrace(void **vec, unsigned *len, unsigned max_len)
{
	(void)vec;
	(void)max_len;
	*len = 0;
}

#endif
