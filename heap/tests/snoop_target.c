// The program tests/snoop.rs reads the heap of.
//
//   snoop_target <dump-file | ->
//
// It allocates from call paths the test looks for by name, and from a few
// hundred anonymous ones on two threads, keeping some and freeing the rest.
// With a file name it then asks jemalloc for an ordinary dump of that heap, to
// compare against. It prints READY, and parks until it is told to stop.
//
// Nothing after the dump allocates (no stdio, threads already joined), so a
// dump and a read from outside see the same heap.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

#ifdef COMPILED_MALLOC_CONF
// jemalloc's options given by the program itself, as a service might: neither
// the environment nor any file says what they are.
const char *malloc_conf = COMPILED_MALLOC_CONF;
#endif

#define NOINLINE __attribute__((noinline))
static void *volatile sink;

// 256 buffers of 64 KiB kept: 16 MiB the test expects to see, by this name.
NOINLINE void *snoop_test_big(size_t n) { return malloc(n); }
// Many small objects of mixed sizes from one stack.
NOINLINE void *snoop_test_small(size_t n) { return malloc(n); }
// Allocated and freed at once: holds nothing, so is not in a profile.
NOINLINE void snoop_test_freed(size_t n) { free(malloc(n)); }

// Two functions per level, picked by the bits of `path`: 2^DEPTH distinct
// stacks reach the same malloc.
#define DEPTH 6
typedef void *(*step_fn)(unsigned path, int level, size_t n);
static step_fn steps[DEPTH][2];
#define STEP(L)                                                                \
	static NOINLINE void *step_##L##_0(unsigned path, int level, size_t n) {   \
		return level + 1 == DEPTH ? malloc(n) : steps[level + 1][(path >> (level + 1)) & 1](path, level + 1, n); \
	}                                                                          \
	static NOINLINE void *step_##L##_1(unsigned path, int level, size_t n) {   \
		void *r = level + 1 == DEPTH ? malloc(n) : steps[level + 1][(path >> (level + 1)) & 1](path, level + 1, n); \
		sink = r;                                                              \
		return r;                                                              \
	}
STEP(0) STEP(1) STEP(2) STEP(3) STEP(4) STEP(5)

static void *worker(void *arg) {
	uint64_t s = (uint64_t)(uintptr_t)arg * 0x9E3779B97F4A7C15ull + 1;
	void *held[512] = {0};
	for (int i = 0; i < 20000; i++) {
		s ^= s << 13; s ^= s >> 7; s ^= s << 17;
		unsigned path = (unsigned)(s % (1u << DEPTH));
		size_t n = 64u << ((s >> 20) % 7); // 64 B .. 4 KiB
		void *p = steps[0][path & 1](path, 0, n);
		int slot = (int)((s >> 30) % 512);
		free(held[slot]); // NULL the first time
		held[slot] = p;
	}
	// The rest stay allocated when the thread ends.
	return NULL;
}

int main(int argc, char **argv) {
	// Under kernel.yama.ptrace_scope=1 (the default on many distributions) a
	// process can be read only by its ancestors. The tool under test is the
	// test's child, as this program is, so this lets it read us.
	prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
	steps[0][0] = step_0_0; steps[0][1] = step_0_1;
	steps[1][0] = step_1_0; steps[1][1] = step_1_1;
	steps[2][0] = step_2_0; steps[2][1] = step_2_1;
	steps[3][0] = step_3_0; steps[3][1] = step_3_1;
	steps[4][0] = step_4_0; steps[4][1] = step_4_1;
	steps[5][0] = step_5_0; steps[5][1] = step_5_1;

	// `held` above is the workers' own; these are the ones kept for good.
	static void *keep[256 + 3000];
	pthread_t th[2];
	for (long i = 0; i < 2; i++) pthread_create(&th[i], NULL, worker, (void *)(i + 1));
	for (int i = 0; i < 2; i++) pthread_join(th[i], NULL);

	for (int i = 0; i < 256; i++) keep[i] = snoop_test_big(65536);
	for (int i = 0; i < 3000; i++) keep[256 + i] = snoop_test_small(100 + (i % 7) * 300);
	for (int i = 0; i < 2000; i++) snoop_test_freed(4096);

	if (argc > 1 && strcmp(argv[1], "-") != 0) {
		// Resolved at run time: whichever jemalloc is LD_PRELOADed answers.
		int (*ctl)(const char *, void *, size_t *, void *, size_t) = dlsym(RTLD_DEFAULT, "mallctl");
		const char *file = argv[1];
		if (!ctl || ctl("prof.dump", NULL, NULL, &file, sizeof file) != 0) {
			(void)!write(2, "prof.dump failed\n", 17);
			return 1;
		}
	}
	(void)!write(1, "READY\n", 6);
	char c;
	(void)!read(0, &c, 1);
	return 0;
}
