// SPDX-License-Identifier: MIT
/*
 * tcx_example.c - how a program uses task_context, and the fixture the
 * tests run.
 *
 * The same source is built twice: once against the static archive with
 * -static, once against the shared object.  Nothing in it differs between
 * the two; how the library arrived is the linker's business, not the
 * caller's.
 *
 * WHAT A CALLER WRITES is three lines (see work_phase() below):
 *
 *	set_task_context("request_id", "abc-123");       // a string
 *	set_task_context("iteration_id", (uint64_t)42);  // a 64-bit number
 *	clear_task_context("request_id");                // forget a name
 *
 * Each call applies to the CALLING thread only, returns 0 or a negative
 * TASK_CONTEXT_E* code, and never truncates: a value that does not fit is
 * refused.
 *
 * WHAT THIS PROGRAM DOES.  Three threads (main and two workers) go through
 * three phases; after each phase every thread prints ONE line in the form
 * fixed by task_context.h ("THE EXAMPLE LINE"), and the main thread then
 * prints "TCX-PHASE <n> done":
 *
 *	phase 0  set request_id (a string) and iteration_id (a number)
 *	phase 1  set iteration_id to a new number
 *	phase 2  clear request_id
 *
 * Run plainly it goes straight through and exits.  With --hold it waits for
 * a line on standard input before each later phase and before exiting, so
 * that something outside the process has time to look at it; end of input
 * ends the program.  With --busy-ms N every thread stays on a CPU for N
 * milliseconds after each phase, while that phase's values stand: a sampling
 * profiler only ever sees a thread that is running.
 */
#define _GNU_SOURCE
#include "task_context.h"

#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define NTHREADS 3
#define NPHASES 3

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t moved = PTHREAD_COND_INITIALIZER;
static int phase_wanted = -1;	/* the newest phase the threads may run */
static int phase_done[NPHASES];	/* threads that finished each phase */
static int stopping;
static long busy_ms;		/* --busy-ms: time on a CPU after each phase */

/*
 * A thread-local of the program's own, unrelated to task_context.  It gives
 * the executable a TLS segment, and an executable that has one is TLS module
 * 1: a library loaded beside it gets a module id above 1, so that a reader
 * which resolves the library's module id (a build with -DTASK_CONTEXT_DTV)
 * is tested with an id that is not the trivial one.  `used` keeps it in the
 * file even though nothing reads it.
 */
static __thread int own_thread_local __attribute__((used));

/* What one thread currently has set, kept here only to print it. */
struct my_values {
	int has_request;
	char request[64];
	uint64_t iteration;
};

static void die(const char *what, int rc)
{
	fprintf(stderr, "TCX-ERROR %s rc=%d\n", what, rc);
	exit(1);
}

/* Bytes outside '!'..'~', and '%' itself, are written %XX. */
static size_t pct_encode(char *dst, size_t room, const char *src)
{
	static const char hex[] = "0123456789ABCDEF";
	size_t n = 0;

	for (; *src != '\0' && n + 4 < room; src++) {
		unsigned char c = (unsigned char)*src;

		if (c < '!' || c > '~' || c == '%') {
			dst[n++] = '%';
			dst[n++] = hex[c >> 4];
			dst[n++] = hex[c & 15];
		} else {
			dst[n++] = (char)c;
		}
	}
	dst[n] = '\0';
	return n;
}

/* One line per thread, in the form task_context.h fixes. */
static void print_line(const struct my_values *v)
{
	struct task_context_self self;
	char line[1024];
	char pct[256];
	int n;
	int rc = task_context_describe_self(&self);

	if (rc != TASK_CONTEXT_OK)
		die("task_context_describe_self", rc);

	n = snprintf(line, sizeof(line),
		     "TCX1 tid=%ld tp=0x%" PRIxPTR " slot=0x%" PRIxPTR
		     " off=%" PRId64 " block=0x%" PRIxPTR " id=0x%016" PRIx64
		     " set=%d",
		     (long)syscall(SYS_gettid), (uintptr_t)self.thread_pointer,
		     (uintptr_t)self.slot_address, self.tp_offset,
		     (uintptr_t)self.block, self.id, 1 + v->has_request);
	n += snprintf(line + n, sizeof(line) - (size_t)n,
		      " iteration_id:u=%" PRIu64, v->iteration);
	if (v->has_request) {
		pct_encode(pct, sizeof(pct), v->request);
		n += snprintf(line + n, sizeof(line) - (size_t)n,
			      " request_id:s=%s", pct);
	}
	snprintf(line + n, sizeof(line) - (size_t)n, "\n");

	pthread_mutex_lock(&lock);
	fputs(line, stdout);
	fflush(stdout);
	pthread_mutex_unlock(&lock);
}

/* THE USAGE: what each thread does in each phase. */
static void work_phase(int who, int phase, struct my_values *v)
{
	int rc;

	switch (phase) {
	case 0:
		/* A space and a percent sign, to show how they are printed. */
		snprintf(v->request, sizeof(v->request), "req-%d 100%%", who);
		rc = set_task_context("request_id", v->request);
		if (rc != TASK_CONTEXT_OK)
			die("set_task_context(request_id)", rc);
		v->has_request = 1;

		v->iteration = 1000u * (uint64_t)who + 1;
		rc = set_task_context("iteration_id", v->iteration);
		if (rc != TASK_CONTEXT_OK)
			die("set_task_context(iteration_id)", rc);
		break;
	case 1:
		v->iteration += 1;
		rc = set_task_context("iteration_id", v->iteration);
		if (rc != TASK_CONTEXT_OK)
			die("set_task_context(iteration_id)", rc);
		break;
	default:
		rc = clear_task_context("request_id");
		if (rc != TASK_CONTEXT_OK)
			die("clear_task_context(request_id)", rc);
		v->has_request = 0;
		break;
	}
}

/*
 * With --busy-ms: spin on the clock, so that this thread is running, and so
 * can be sampled, while the values it has just printed still stand.
 */
static void stay_on_cpu(void)
{
	struct timespec start, now;

	if (busy_ms <= 0)
		return;
	clock_gettime(CLOCK_MONOTONIC, &start);
	do {
		clock_gettime(CLOCK_MONOTONIC, &now);
	} while ((now.tv_sec - start.tv_sec) * 1000L +
			 (now.tv_nsec - start.tv_nsec) / 1000000L <
		 busy_ms);
}

/* Run every phase the main thread has released, in order. */
static void run_released_phases(int who, int *next, struct my_values *v)
{
	for (;;) {
		int phase;

		pthread_mutex_lock(&lock);
		while (!stopping && phase_wanted < *next)
			pthread_cond_wait(&moved, &lock);
		if (phase_wanted < *next) {
			pthread_mutex_unlock(&lock);
			return;	/* stopping, and nothing left to run */
		}
		phase = *next;
		pthread_mutex_unlock(&lock);

		work_phase(who, phase, v);
		print_line(v);
		stay_on_cpu();

		pthread_mutex_lock(&lock);
		phase_done[phase]++;
		pthread_cond_broadcast(&moved);
		pthread_mutex_unlock(&lock);

		*next = phase + 1;
		if (*next >= NPHASES)
			return;
	}
}

static void *worker(void *arg)
{
	int who = (int)(intptr_t)arg;
	int next = 0;
	struct my_values v;

	memset(&v, 0, sizeof(v));
	run_released_phases(who, &next, &v);

	/* Stay alive until the program ends, so the block stays this thread's. */
	pthread_mutex_lock(&lock);
	while (!stopping)
		pthread_cond_wait(&moved, &lock);
	pthread_mutex_unlock(&lock);
	return NULL;
}

/* With --hold: one line of input lets the program go on; end of input stops it. */
static int wait_for_go(int hold)
{
	char buf[64];

	if (!hold)
		return 1;
	return fgets(buf, sizeof(buf), stdin) != NULL;
}

int main(int argc, char **argv)
{
	pthread_t threads[NTHREADS - 1];
	struct my_values v;
	int hold = 0;
	int phase;
	int i;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--hold") == 0) {
			hold = 1;
		} else if (strcmp(argv[i], "--busy-ms") == 0 && i + 1 < argc) {
			busy_ms = strtol(argv[++i], NULL, 10);
		} else {
			fprintf(stderr, "usage: %s [--hold] [--busy-ms N]\n",
				argv[0]);
			return 2;
		}
	}

	memset(&v, 0, sizeof(v));
	for (i = 0; i < NTHREADS - 1; i++) {
		if (pthread_create(&threads[i], NULL, worker,
				   (void *)(intptr_t)(i + 1)) != 0)
			die("pthread_create", i);
	}

	for (phase = 0; phase < NPHASES; phase++) {
		if (phase > 0 && !wait_for_go(hold))
			break;

		pthread_mutex_lock(&lock);
		phase_wanted = phase;
		pthread_cond_broadcast(&moved);
		pthread_mutex_unlock(&lock);

		/* The main thread is thread 0 and does the same work. */
		work_phase(0, phase, &v);
		print_line(&v);
		stay_on_cpu();

		pthread_mutex_lock(&lock);
		phase_done[phase]++;
		while (phase_done[phase] < NTHREADS)
			pthread_cond_wait(&moved, &lock);
		printf("TCX-PHASE %d done\n", phase);
		fflush(stdout);
		pthread_mutex_unlock(&lock);
	}

	/* Hold still once more, so the last state can be looked at. */
	if (phase == NPHASES)
		(void)wait_for_go(hold);

	pthread_mutex_lock(&lock);
	stopping = 1;
	pthread_cond_broadcast(&moved);
	pthread_mutex_unlock(&lock);
	for (i = 0; i < NTHREADS - 1; i++)
		pthread_join(threads[i], NULL);
	return 0;
}
