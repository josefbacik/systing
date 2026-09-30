/*
 * What tests/frame_pointer.rs runs: the "frame-pointer" backtrace given frame
 * pointers of every kind, on stacks of every kind. It needs no jemalloc: the
 * library's own check function captures a stack as the backtrace does.
 *
 *   frame_pointer_target <libsysting_heap_hooks.so> <scenario>
 *
 * Ends with 0, or says what was not as expected and ends with 1. A fault is a
 * failure too, and the one that matters: in a service this code runs inside
 * malloc.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>

#define EXPECT(what)                                                          \
	do {                                                                  \
		if (!(what)) {                                                \
			fprintf(stderr, "%s:%d: not so: %s\n", __func__,      \
				__LINE__, #what);                             \
			exit(1);                                              \
		}                                                             \
	} while (0)

#define MAX_FRAMES 256

static int (*check)(void **, int);

/*
 * Code without unwind tables, as a JIT's or Python's trampolines: calls
 * fn(arg) with `fp` in the frame pointer register. The walk by tables ends at
 * returns_here, and what it goes on from is `fp`.
 */
long without_tables(uintptr_t fp, long (*fn)(void *), void *arg);
extern char returns_here[];
__asm__(".text\n"
	".globl without_tables\n"
	".type without_tables, @function\n"
	"without_tables:\n"
	"	push %rbp\n"
	"	mov %rdi, %rbp\n"
	"	mov %rdx, %rdi\n"
	"	call *%rsi\n"
	".globl returns_here\n"
	"returns_here:\n"
	"	pop %rbp\n"
	"	ret\n"
	".size without_tables, . - without_tables\n");

struct captured {
	void *vec[MAX_FRAMES];
	int n;
};

static long capture(void *arg)
{
	struct captured *c = arg;
	c->n = check(c->vec, MAX_FRAMES);
	return 0;
}

/* The frames found by frame pointers when the walk goes on from `fp`: those
 * after returns_here. Returns how many. */
static int walked_from(uintptr_t fp, void ***frames)
{
	static __thread struct captured c;
	without_tables(fp, capture, &c);
	EXPECT(c.n > 0);
	/* The library's check function, capture(), and the code without tables:
	 * nothing of the walk's own comes first. */
	EXPECT(c.n >= 3 && c.vec[2] == (void *)returns_here);
	*frames = c.vec + 3;
	return c.n - 3;
}

static int has(void **frames, int n, void *address)
{
	for (int i = 0; i < n; i++)
		if (frames[i] == address)
			return 1;
	return 0;
}

/* From a true frame pointer, the walk goes on to this function's caller. */
static __attribute__((noinline)) void gets_through(void)
{
	void **frames;
	int n = walked_from((uintptr_t)__builtin_frame_address(0), &frames);
	EXPECT(n >= 1);
	EXPECT(frames[0] == __builtin_return_address(0));
}

static __attribute__((noinline)) void does_not_get_through(void)
{
	void **frames;
	EXPECT(walked_from((uintptr_t)__builtin_frame_address(0), &frames) == 0);
}

static void *in_a_thread(void *fn)
{
	((void (*)(void))fn)();
	return NULL;
}

static void run_in_a_thread(void (*fn)(void))
{
	pthread_t t;
	EXPECT(pthread_create(&t, NULL, in_a_thread, (void *)fn) == 0);
	EXPECT(pthread_join(t, NULL) == 0);
}

/* Nothing is read through a frame pointer that is not one, and nothing is
 * added for it. */
static __attribute__((noinline)) void hostile(void)
{
	uintptr_t here = (uintptr_t)__builtin_frame_address(0);
	/* Readable, aligned, and made up to look like a record that leads on. */
	uintptr_t *heap = aligned_alloc(16, 64);
	heap[0] = (uintptr_t)(heap + 2);
	heap[1] = 0x1111;
	heap[2] = 0;
	heap[3] = 0x2222;
	void *gone = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
			  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	EXPECT(gone != MAP_FAILED);
	munmap(gone, 4096);
	const uintptr_t values[] = {
		0,
		1,
		8,
		16,
		here + 8,		      /* in the stack, not aligned */
		here + 1,
		(here - (1 << 16)) & ~15ul,	      /* below where the stack is in use */
		(uintptr_t)heap,
		(uintptr_t)gone,
		(uintptr_t)&hostile,		      /* code */
		(uintptr_t)pthread_self() & ~15ul,    /* where a thread's stack ends */
		((uintptr_t)pthread_self() & ~15ul) - 8,
		((uintptr_t)pthread_self() + 4096) & ~15ul,
		0x00007ffffffffff0ul,		      /* the last of user space */
		0xffff800000000000ul,		      /* the kernel's */
		(uintptr_t)-16,
		(uintptr_t)-8,
	};
	for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
		void **frames;
		int n = walked_from(values[i], &frames);
		if (n != 0) {
			fprintf(stderr, "from %#lx: %d frames, the first %p\n",
				(unsigned long)values[i], n, frames[0]);
			exit(1);
		}
	}
	free(heap);
	/* And the thread is none the worse for it. */
	gets_through();
}

/* Records that are in the stack, and lead nowhere good. */
static __attribute__((noinline)) void misleading(void)
{
	uintptr_t r[8] __attribute__((aligned(16)));
	void **frames;

	/* Back down the stack: followed no further. */
	r[0] = (uintptr_t)&r[4];
	r[1] = 0x1111;
	r[4] = (uintptr_t)&r[0];
	r[5] = 0x2222;
	EXPECT(walked_from((uintptr_t)&r[0], &frames) == 2);
	EXPECT(frames[0] == (void *)0x1111 && frames[1] == (void *)0x2222);

	/* To itself. */
	r[0] = (uintptr_t)&r[0];
	EXPECT(walked_from((uintptr_t)&r[0], &frames) == 1);

	/* No return address: the end of a stack. */
	r[0] = (uintptr_t)&r[4];
	r[1] = 0;
	EXPECT(walked_from((uintptr_t)&r[0], &frames) == 0);

	/* Out of the stack. */
	r[1] = 0x1111;
	r[4] = 0xffff800000000000ul;
	EXPECT(walked_from((uintptr_t)&r[0], &frames) == 2);
}

/* The last record there is room for below a thread's control block is read,
 * and the one after it is not. */
static void at_the_top(void)
{
	uintptr_t top = (uintptr_t)pthread_self() & ~15ul;
	void **frames;
	walked_from(top - 16, &frames);
	EXPECT(walked_from(top, &frames) == 0);
	gets_through();
}

/* The same for the process's first stack, which ends at the random bytes the
 * kernel leaves for the program. Its mapping goes on above them. */
static void at_the_top_of_the_first(void)
{
	uintptr_t top = getauxval(AT_RANDOM) & ~15ul;
	void **frames;
	EXPECT(top != 0);
	walked_from(top - 16, &frames);
	EXPECT(walked_from(top, &frames) == 0);
	EXPECT(walked_from(top + 16, &frames) == 0);
	gets_through();
}

static void no_descriptors(struct rlimit *was)
{
	struct rlimit none;
	EXPECT(getrlimit(RLIMIT_NOFILE, was) == 0);
	none = *was;
	none.rlim_cur = 0;
	EXPECT(setrlimit(RLIMIT_NOFILE, &none) == 0);
}

/* A thread's range is read from /proc once: with no descriptor to be had, a
 * thread that has been looked at goes on as before. */
static void remembers(void)
{
	struct rlimit was;
	gets_through();
	no_descriptors(&was);
	gets_through();
	EXPECT(setrlimit(RLIMIT_NOFILE, &was) == 0);
}

static ucontext_t back, fiber;

static void on_a_fiber(void)
{
	does_not_get_through();
}

/* A stack the program made for itself cannot be vouched for, and a thread that
 * has been on one goes without frame pointers from then on. */
static void fibers(void)
{
	gets_through();
	size_t size = 256 * 1024;
	void *stack = mmap(NULL, size, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	EXPECT(stack != MAP_FAILED);
	EXPECT(getcontext(&fiber) == 0);
	fiber.uc_stack.ss_sp = stack;
	fiber.uc_stack.ss_size = size;
	fiber.uc_link = &back;
	makecontext(&fiber, on_a_fiber, 0);
	EXPECT(swapcontext(&back, &fiber) == 0);
	munmap(stack, size);
	does_not_get_through();
}

/*
 * What is remembered of a range can outlive it. A thread without a guard page,
 * and two stacks of the program's own mapped right below it, which the kernel
 * shows as one mapping with the thread's: they are in the thread's range. The
 * lower is made by code that runs on the upper, so its outermost frame's frame
 * pointer leads into the upper, which is then unmapped.
 */
#define OWN_STACK (256 * 1024)
static ucontext_t upper, lower;
static char *upper_stack, *lower_stack;
static int frames_on_the_lower;

static void on_the_lower(void)
{
	for (;;) {
		struct captured c;
		capture(&c);
		EXPECT(c.n > 0);
		frames_on_the_lower = c.n;
		EXPECT(swapcontext(&lower, &back) == 0);
	}
}

static int in_one_mapping(const void *a, const void *b)
{
	FILE *maps = fopen("/proc/self/maps", "r");
	char line[512];
	int one = 0;
	EXPECT(maps != NULL);
	while (fgets(line, sizeof line, maps)) {
		unsigned long start, end;
		if (sscanf(line, "%lx-%lx", &start, &end) == 2 &&
		    (unsigned long)a >= start && (unsigned long)a < end)
			one = (unsigned long)b >= start && (unsigned long)b < end;
	}
	fclose(maps);
	return one;
}

static __attribute__((noinline)) void on_the_upper(void)
{
	EXPECT(getcontext(&lower) == 0);
	lower.uc_stack.ss_sp = lower_stack;
	lower.uc_stack.ss_size = OWN_STACK;
	lower.uc_link = &back;
	makecontext(&lower, on_the_lower, 0);
}

static void *unmapped_in_range(void *arg)
{
	pthread_attr_t attr;
	void *base;
	size_t size;
	EXPECT(pthread_getattr_np(pthread_self(), &attr) == 0);
	EXPECT(pthread_attr_getstack(&attr, &base, &size) == 0);
	pthread_attr_destroy(&attr);
	int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK | MAP_FIXED_NOREPLACE;
	upper_stack = mmap((char *)base - OWN_STACK, OWN_STACK,
			   PROT_READ | PROT_WRITE, flags, -1, 0);
	lower_stack = mmap((char *)base - 2 * OWN_STACK, OWN_STACK,
			   PROT_READ | PROT_WRITE, flags, -1, 0);
	if (upper_stack == MAP_FAILED || lower_stack == MAP_FAILED) {
		/* Something else is there: nothing to be learnt this time. */
		fprintf(stderr, "no room below the thread's stack\n");
		return arg;
	}
	EXPECT(getcontext(&upper) == 0);
	upper.uc_stack.ss_sp = upper_stack;
	upper.uc_stack.ss_size = OWN_STACK;
	upper.uc_link = &back;
	makecontext(&upper, on_the_upper, 0);
	int merged = in_one_mapping(lower_stack, (void *)pthread_self());
	EXPECT(swapcontext(&back, &upper) == 0);
	EXPECT(swapcontext(&back, &lower) == 0);
	int before = frames_on_the_lower;
	munmap(upper_stack, OWN_STACK);
	EXPECT(swapcontext(&back, &lower) == 0);
	/* What was read from the upper stack while it was there is not made up
	 * once it is gone. (Not every kernel shows the three as one mapping:
	 * where it does not, the lower stack is not walked at all.) */
	if (merged)
		EXPECT(frames_on_the_lower < before);
	else
		EXPECT(frames_on_the_lower == before);
	return arg;
}

static void outlives_its_range(void)
{
	pthread_attr_t attr;
	pthread_t t;
	EXPECT(pthread_attr_init(&attr) == 0);
	EXPECT(pthread_attr_setguardsize(&attr, 0) == 0);
	EXPECT(pthread_create(&t, &attr, unmapped_in_range, NULL) == 0);
	EXPECT(pthread_join(t, NULL) == 0);
}

static __attribute__((noinline)) void deeper(int levels, void *outermost)
{
	volatile char room[64 * 1024];
	room[0] = (char)levels;
	if (levels > 0) {
		deeper(levels - 1, outermost);
		room[1] = room[0];
		return;
	}
	void **frames;
	int n = walked_from((uintptr_t)__builtin_frame_address(0), &frames);
	EXPECT(has(frames, n, outermost));
}

/* The process's first stack is mapped as it grows: what was its range when it
 * was first looked at is not its range later. */
static __attribute__((noinline)) void grows(void)
{
	gets_through();
	deeper(64, __builtin_return_address(0));
	gets_through();
}

static void many_threads(void)
{
	for (int round = 0; round < 50; round++) {
		pthread_t t[16];
		for (int i = 0; i < 16; i++)
			EXPECT(pthread_create(&t[i], NULL, in_a_thread,
					      (void *)gets_through) == 0);
		for (int i = 0; i < 16; i++)
			EXPECT(pthread_join(t[i], NULL) == 0);
	}
}

/* The child of a fork has the thread that forked, on the stack it was on. */
static void forks(void)
{
	gets_through();
	pid_t pid = fork();
	EXPECT(pid >= 0);
	if (pid == 0) {
		gets_through();
		hostile();
		run_in_a_thread(gets_through);
		_exit(0);
	}
	int status;
	EXPECT(waitpid(pid, &status, 0) == pid);
	EXPECT(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

/* On a thread's first capture /proc is read. With no descriptor to be had that
 * fails, and says so in errno: the thread goes without frame pointers, and
 * errno is as it was. */
static void keeps_errno(void)
{
	struct rlimit was;
	no_descriptors(&was);
	errno = 4242;
	does_not_get_through();
	EXPECT(errno == 4242);
	EXPECT(setrlimit(RLIMIT_NOFILE, &was) == 0);
}

static void first_and_in_a_thread(void (*fn)(void))
{
	fn();
	run_in_a_thread(fn);
}

int main(int argc, char **argv)
{
	if (argc != 3)
		return 2;
	void *hooks = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
	if (!hooks) {
		fprintf(stderr, "%s\n", dlerror());
		return 2;
	}
	check = (int (*)(void **, int))dlsym(hooks, "systing_heap_hooks_frame_pointer_check");
	if (!check)
		return 2;
	const char *scenario = argv[2];
	if (!strcmp(scenario, "gets-through"))
		first_and_in_a_thread(gets_through);
	else if (!strcmp(scenario, "hostile"))
		first_and_in_a_thread(hostile);
	else if (!strcmp(scenario, "misleading"))
		first_and_in_a_thread(misleading);
	else if (!strcmp(scenario, "at-the-top"))
		run_in_a_thread(at_the_top);
	else if (!strcmp(scenario, "at-the-top-of-the-first"))
		at_the_top_of_the_first();
	else if (!strcmp(scenario, "remembers"))
		first_and_in_a_thread(remembers);
	else if (!strcmp(scenario, "outlives-its-range"))
		outlives_its_range();
	else if (!strcmp(scenario, "fibers")) {
		run_in_a_thread(fibers);
		/* Other threads are as they were. */
		first_and_in_a_thread(gets_through);
		fibers();
	} else if (!strcmp(scenario, "grows"))
		grows();
	else if (!strcmp(scenario, "many-threads"))
		many_threads();
	else if (!strcmp(scenario, "forks"))
		first_and_in_a_thread(forks);
	else if (!strcmp(scenario, "keeps-errno"))
		first_and_in_a_thread(keeps_errno);
	else
		return 2;
	return 0;
}
