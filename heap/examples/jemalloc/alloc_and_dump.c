/*
 * Allocates memory in a few recognizable patterns so jemalloc's heap
 * profiles have something to show. The program never calls jemalloc itself:
 * run.sh preloads jemalloc and sets MALLOC_CONF, and jemalloc writes the
 * snapshots (every lg_prof_interval bytes allocated, and one at exit).
 *
 * Each pattern has its own function, marked noinline, so its frames stay
 * distinct in the symbolized stacks:
 *   leak_buffers      - allocated and never freed; grows every round
 *   cache_fill        - a fixed-size cache, refilled (freed then allocated)
 *   churn             - allocated and freed at once; leaves nothing live
 *   build_list        - a linked list kept until the end, then freed
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NOINLINE __attribute__((noinline))

#define ROUNDS 8
#define CACHE_SLOTS 64

struct node {
	struct node *next;
	char payload[240];
};

static void *leaked[ROUNDS * 32];
static size_t n_leaked;
static void *cache[CACHE_SLOTS];

NOINLINE static void leak_buffers(int round)
{
	/* 32 buffers of 64 KiB a round: 2 MiB of leak per round. */
	for (int i = 0; i < 32; i++) {
		void *p = malloc(64 * 1024);
		memset(p, round, 64 * 1024);
		leaked[n_leaked++] = p;
	}
}

NOINLINE static void cache_fill(int round)
{
	for (int i = 0; i < CACHE_SLOTS; i++) {
		free(cache[i]);
		cache[i] = malloc(16 * 1024);
		memset(cache[i], round, 16 * 1024);
	}
}

NOINLINE static void churn(void)
{
	for (int i = 0; i < 1000; i++) {
		char *p = malloc(4096);
		p[0] = (char)i;
		free(p);
	}
}

NOINLINE static struct node *build_list(struct node *head, int n)
{
	for (int i = 0; i < n; i++) {
		struct node *nd = malloc(sizeof(*nd));
		memset(nd->payload, i, sizeof(nd->payload));
		nd->next = head;
		head = nd;
	}
	return head;
}

int main(void)
{
	struct node *list = NULL;

	for (int round = 0; round < ROUNDS; round++) {
		leak_buffers(round);
		cache_fill(round);
		churn();
		list = build_list(list, 2000);
	}

	while (list) {
		struct node *next = list->next;
		free(list);
		list = next;
	}
	for (int i = 0; i < CACHE_SLOTS; i++)
		free(cache[i]);

	printf("done: %zu buffers leaked (%zu KiB)\n", n_leaked, n_leaked * 64);
	return 0;
}
