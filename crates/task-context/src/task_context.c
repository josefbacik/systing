// SPDX-License-Identifier: MIT
/*
 * task_context.c - the writer library behind task_context.h.
 *
 * ONE translation unit on purpose: whatever pulls any API function out of a
 * static archive pulls in the load-time constructor and the info record with
 * it, so a statically linked program publishes its recipe exactly as a
 * dynamically linked one does.
 *
 * Everything a reader relies on is written down in task_context.h ("WRITER
 * RULE", "PUBLICATION RULE", "Limits"); the comments here say only how this
 * file keeps those rules.
 */
#define _GNU_SOURCE
#include "task_context.h"

#include <dlfcn.h>
#include <pthread.h>
#include <string.h>
#include <sys/mman.h>

#if !defined(__x86_64__) && !defined(__aarch64__)
#error "task_context: only x86-64 and aarch64 are supported"
#endif

/*
 * dlopen(), dlsym() and dlclose() are used for one check only (see
 * tcx_another_copy_is_ahead()).  Weak, so that a program that does not link them - a
 * static one, or a dynamic one on a C library that keeps them in a separate
 * libdl - still links, and skips it.
 */
#pragma weak dlopen
#pragma weak dlsym
#pragma weak dlclose

/*
 * The library is built one of two ways (see task_context.h): by default its
 * thread-local is initial-exec and the recipe is a fixed distance from the
 * thread pointer; with -DTASK_CONTEXT_DTV it is general-dynamic and the
 * recipe is the DTV walk.  The walk is glibc's layout.
 */
#if defined(TASK_CONTEXT_DTV)
#if !defined(__GLIBC__)
#error "task_context: -DTASK_CONTEXT_DTV reads glibc's DTV layout"
#endif
#include <link.h>
#define TCX_TLS_MODEL "global-dynamic"
#else
#define TCX_TLS_MODEL "initial-exec"
#endif

#define TCX_NBLOCKS (TASK_CONTEXT_REGION_SIZE / TASK_CONTEXT_BLOCK_STRIDE)

/* ---------------------------------------------------------------------- */
/* The two things a reader looks for                                       */
/* ---------------------------------------------------------------------- */

/*
 * The per-process record.  The constant fields are in the file's data image;
 * the rest is filled by tcx_publish_locked().  recipe_tag stays UNSET until
 * every other field is in place.
 */
struct task_context_info_v1 task_context_info_v1
	__attribute__((section(TASK_CONTEXT_INFO_SECTION), used,
		       visibility("default"), aligned(8))) = {
	.magic = TASK_CONTEXT_INFO_MAGIC,
	.version = TASK_CONTEXT_ABI_VERSION,
	.info_size = sizeof(struct task_context_info_v1),
	.recipe_tag = TASK_CONTEXT_RECIPE_UNSET,
	.block_size = TASK_CONTEXT_BLOCK_STRIDE,
	.block_hdr_size = offsetof(struct task_context_block_v1, slots),
	.slot_size = sizeof(struct task_context_slot_v1),
	.nslots = TASK_CONTEXT_SLOTS,
	.name_max = TASK_CONTEXT_NAME_MAX,
	.value_max = TASK_CONTEXT_VALUE_MAX,
};

/*
 * The per-thread slot: NULL, or the address of the thread's block.  The
 * initial-exec model puts it in static TLS, which is what makes its distance
 * from the thread pointer one constant for the whole process; the
 * general-dynamic model puts it in its module's block, which a reader finds
 * through the thread's DTV.
 */
static __thread struct task_context_block_v1 *tcx_slot
	__attribute__((tls_model(TCX_TLS_MODEL)));

/* ---------------------------------------------------------------------- */
/* Process-wide state                                                      */
/* ---------------------------------------------------------------------- */

/* The writer's own bytes of a block: past the ABI part, inside the stride. */
struct tcx_block_private {
	tcx_u32 next_free;	/* index + 1 of the next free block, 0 = none */
};

_Static_assert(sizeof(struct task_context_block_v1) +
		       sizeof(struct tcx_block_private) <=
		       TASK_CONTEXT_BLOCK_STRIDE,
	       "the private part fits inside the stride");
_Static_assert(TCX_NBLOCKS > 0 && TCX_NBLOCKS < 0xffffffffu,
	       "block indices fit in 32 bits");

static pthread_mutex_t tcx_init_lock = PTHREAD_MUTEX_INITIALIZER;
static int tcx_ready;		/* 1 once the recipe is published */
static int tcx_refused;		/* 1 once another copy was found to publish first */
static int tcx_key_made;
static int tcx_atfork_made;
static pthread_key_t tcx_key;
static unsigned char *tcx_region;	/* the one region; never unmapped */
static tcx_u32 tcx_next_unused;	/* blocks that were never handed out */
static tcx_u64 tcx_free_head;	/* (tag << 32) | (index + 1); low half 0 = empty */
static tcx_u64 tcx_index_counter;	/* thread indices handed out so far */

static inline uintptr_t tcx_thread_pointer(void)
{
	uintptr_t tp;

#if defined(__x86_64__)
	/* %fs:0 holds the thread pointer itself (the FS base). */
	__asm__("movq %%fs:0, %0" : "=r"(tp));
#else
	__asm__("mrs %0, tpidr_el0" : "=r"(tp));
#endif
	return tp;
}

static inline tcx_s64 tcx_slot_offset(void)
{
	return (tcx_s64)((intptr_t)&tcx_slot - (intptr_t)tcx_thread_pointer());
}

#if defined(TASK_CONTEXT_DTV)
/*
 * The DTV walk of task_context.h, done for the calling thread: the start of
 * this thread's TLS block of module `modid`, or NULL when the thread's DTV
 * does not reach the module or holds no block for it yet.  The walk a reader
 * makes for another thread, word for word.
 */
static inline uintptr_t tcx_word_at(uintptr_t address)
{
	uintptr_t word;

	memcpy(&word, (const void *)address, sizeof(word));
	return word;
}

static void *tcx_dtv_block(tcx_u64 modid)
{
	uintptr_t dtv = tcx_word_at(tcx_thread_pointer() +
				    TASK_CONTEXT_TCB_DTV_OFFSET);
	uintptr_t block;

	if (!dtv || modid == 0 || modid > TASK_CONTEXT_DTV_MODID_MAX)
		return NULL;
	if (modid > tcx_word_at(dtv - TASK_CONTEXT_DTV_ENTRY_SIZE))
		return NULL;
	block = tcx_word_at(dtv + modid * TASK_CONTEXT_DTV_ENTRY_SIZE);
	if (block == TASK_CONTEXT_DTV_UNALLOCATED)
		return NULL;
	return (void *)block;
}

/*
 * The slot's address in this thread.  Taking it makes the loader allocate
 * this thread's block of a dynamic module, and the DTV walk that follows
 * must find that block, so the touch has to happen HERE.  `noinline` is not
 * enough: the compiler infers that a function which only takes an address is
 * pure and moves the call after the loads it should precede (gcc -O3 does).
 * The empty volatile asm is a side effect the compiler cannot move or drop,
 * and its memory clobber keeps the walk's loads behind it.
 */
static __attribute__((noinline)) uintptr_t tcx_slot_address(void)
{
	uintptr_t address = (uintptr_t)&tcx_slot;

	__asm__ volatile("" : "+r"(address) : : "memory");
	return address;
}

struct tcx_module_search {
	uintptr_t address;	/* looked for */
	size_t modid;		/* the TLS module id of the object that holds it */
};

/* dl_iterate_phdr callback: the object whose loadable segments hold the address. */
static int tcx_module_holding(struct dl_phdr_info *info, size_t size, void *arg)
{
	struct tcx_module_search *search = arg;
	ElfW(Half) i;

	if (size < offsetof(struct dl_phdr_info, dlpi_tls_modid) +
			   sizeof(info->dlpi_tls_modid))
		return 0;
	for (i = 0; i < info->dlpi_phnum; i++) {
		const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
		uintptr_t start = info->dlpi_addr + ph->p_vaddr;

		if (ph->p_type == PT_LOAD && search->address >= start &&
		    search->address - start < ph->p_memsz) {
			search->modid = info->dlpi_tls_modid;
			return 1;
		}
	}
	return 0;
}

/*
 * The recipe of this build: the module id of the object this file is in, and
 * where the slot sits in that module's block - measured by the walk a reader
 * will make, so that the two cannot disagree.
 */
static int tcx_dtv_measure(tcx_u64 *modid_out, tcx_u64 *offset_out)
{
	/* An address that cannot have been interposed: a static function's,
	 * which is in this object whoever else defines the record. */
	struct tcx_module_search search = {
		.address = (uintptr_t)&tcx_module_holding,
	};
	uintptr_t slot = tcx_slot_address();
	uintptr_t block;

	if (!dl_iterate_phdr(tcx_module_holding, &search) || search.modid == 0)
		return TASK_CONTEXT_EUNSUPPORTED;
	block = (uintptr_t)tcx_dtv_block(search.modid);
	if (!block || slot < block ||
	    slot - block > TASK_CONTEXT_DTV_BLOCK_OFFSET_MAX || (slot - block) % 8)
		return TASK_CONTEXT_EUNSUPPORTED;
	*modid_out = search.modid;
	*offset_out = slot - block;
	return TASK_CONTEXT_OK;
}
#endif /* TASK_CONTEXT_DTV */

/*
 * The writer's self-check: in THIS thread the slot must sit where the
 * published recipe says every thread's slot sits.
 */
static int tcx_slot_is_where_the_recipe_says(void)
{
#if defined(TASK_CONTEXT_DTV)
	if (__atomic_load_n(&task_context_info_v1.recipe_tag, __ATOMIC_ACQUIRE) ==
	    TASK_CONTEXT_RECIPE_DTV) {
		uintptr_t slot = tcx_slot_address();
		uintptr_t block =
			(uintptr_t)tcx_dtv_block(task_context_info_v1.dtv_modid);

		return block && slot >= block &&
		       slot - block == task_context_info_v1.dtv_block_offset;
	}
#endif
	return tcx_slot_offset() == task_context_info_v1.tp_offset;
}

static inline struct tcx_block_private *
tcx_private(struct task_context_block_v1 *b)
{
	return (struct tcx_block_private *)((unsigned char *)b +
					    sizeof(struct task_context_block_v1));
}

static inline struct task_context_block_v1 *tcx_block_at(tcx_u32 index)
{
	return (struct task_context_block_v1 *)(tcx_region +
						(size_t)index *
							TASK_CONTEXT_BLOCK_STRIDE);
}

/* ---------------------------------------------------------------------- */
/* Blocks: a bump counter for fresh ones, a tagged stack for returned ones  */
/* ---------------------------------------------------------------------- */

/*
 * The free list is a stack of block indices.  Its head carries a tag that
 * goes up at every push and pop, so a pop that raced a pop-and-push of the
 * same block fails its compare-and-swap instead of installing a stale link.
 */
static void tcx_block_give_back(struct task_context_block_v1 *b)
{
	tcx_u32 index1 = (tcx_u32)(((unsigned char *)b - tcx_region) /
				   TASK_CONTEXT_BLOCK_STRIDE) + 1;
	tcx_u64 head = __atomic_load_n(&tcx_free_head, __ATOMIC_RELAXED);

	for (;;) {
		tcx_u64 next = (((head >> 32) + 1) << 32) | index1;

		__atomic_store_n(&tcx_private(b)->next_free, (tcx_u32)head,
				 __ATOMIC_RELAXED);
		if (__atomic_compare_exchange_n(&tcx_free_head, &head, next, 0,
						__ATOMIC_RELEASE,
						__ATOMIC_RELAXED))
			return;
	}
}

static struct task_context_block_v1 *tcx_block_take(void)
{
	tcx_u64 head = __atomic_load_n(&tcx_free_head, __ATOMIC_ACQUIRE);
	tcx_u32 fresh;

	while ((tcx_u32)head != 0) {
		struct task_context_block_v1 *b = tcx_block_at((tcx_u32)head - 1);
		tcx_u32 link = __atomic_load_n(&tcx_private(b)->next_free,
					       __ATOMIC_RELAXED);
		tcx_u64 next = (((head >> 32) + 1) << 32) | link;

		if (__atomic_compare_exchange_n(&tcx_free_head, &head, next, 0,
						__ATOMIC_ACQUIRE,
						__ATOMIC_ACQUIRE))
			return b;
	}

	fresh = __atomic_load_n(&tcx_next_unused, __ATOMIC_RELAXED);
	while (fresh < TCX_NBLOCKS) {
		if (__atomic_compare_exchange_n(&tcx_next_unused, &fresh,
						fresh + 1, 0, __ATOMIC_RELAXED,
						__ATOMIC_RELAXED))
			return tcx_block_at(fresh);
	}
	return NULL;
}

/* 1..0xffffff, never 0; the counter behind it is wide enough not to wrap. */
static tcx_u64 tcx_next_thread_index(void)
{
	tcx_u64 n = __atomic_fetch_add(&tcx_index_counter, 1, __ATOMIC_RELAXED);

	return (n % 0xffffffull) + 1;
}

/*
 * Make a block ready for a new owner.  A block that comes off the free list
 * may still be in the hands of a reader that picked its address up from the
 * thread that returned it, so the reset is itself a sequence-locked update:
 * that reader sees the odd word or a changed word, never a consistent mix of
 * two owners.  The new first word carries a new thread index.
 */
static void tcx_block_reset(struct task_context_block_v1 *b, tcx_u64 index)
{
	tcx_u64 old = __atomic_load_n(&b->seq, __ATOMIC_RELAXED);

	__atomic_store_n(&b->seq, old | TASK_CONTEXT_SEQ_BUSY, __ATOMIC_RELAXED);
	__atomic_thread_fence(__ATOMIC_RELEASE);
	memset(b->slots, 0, sizeof(b->slots));
	b->set_mask = 0;
	b->reserved0 = 0;
	b->reserved1 = 0;
	b->magic = TASK_CONTEXT_BLOCK_MAGIC;
	b->version = TASK_CONTEXT_ABI_VERSION;
	b->hdr_size = offsetof(struct task_context_block_v1, slots);
	__atomic_store_n(&b->seq, task_context_seq_first(index),
			 __ATOMIC_RELEASE);
}

/* Thread exit: the slot goes back to NULL first, then the block is free. */
static void tcx_thread_exit(void *arg)
{
	struct task_context_block_v1 *b = arg;

	__atomic_store_n(&tcx_slot, NULL, __ATOMIC_RELEASE);
	tcx_block_give_back(b);
}

/* ---------------------------------------------------------------------- */
/* Publication                                                             */
/* ---------------------------------------------------------------------- */

/*
 * The init lock is held only while the recipe is still unpublished.  A
 * process that forks at that moment from another thread would leave the
 * child's copy of the lock held for ever; the child gets a fresh one.
 */
static void tcx_after_fork_in_child(void)
{
	pthread_mutex_init(&tcx_init_lock, NULL);
}

/*
 * The first definition of the record in the PROGRAM's global scope, or NULL.
 * Asked of the program's handle, not of RTLD_DEFAULT: that one answers for
 * the caller's own lookup scope, and a library linked -Bsymbolic puts itself
 * first in its own.
 */
static void *tcx_first_record_in_the_program(void)
{
	void *program, *first;

	if (!dlopen || !dlsym || !dlclose)
		return NULL;
	program = dlopen(NULL, RTLD_LAZY);
	if (!program)
		return NULL;
	first = dlsym(program, TASK_CONTEXT_INFO_SYMBOL);
	dlclose(program);
	return first;
}

/*
 * Is another copy of this library the first in the process?  Two ways to be
 * behind one.  By default the dynamic linker binds every copy's references to
 * the first definition of the record it finds, so the copies share one record
 * and the one that publishes second finds it published (checked under the
 * lock, in tcx_publish_locked()).  A copy linked with -Bsymbolic keeps a
 * record of its own; then another copy's record is the first in the program's
 * global scope, and this copy is behind it (checked here).  A copy whose
 * record the program does not export is not seen, and is not counted as a
 * second one.  Asks the dynamic linker, so it is never called under our lock.
 */
static int tcx_another_copy_is_ahead(void)
{
	void *first = tcx_first_record_in_the_program();

	return first && first != (void *)&task_context_info_v1;
}

/*
 * `modid` and `block_offset` are the DTV recipe's numbers, measured before
 * the lock was taken (see tcx_publish()); 0 where there is none - a default
 * build, or a DTV build whose variable the loader put in static TLS.
 */
static int tcx_publish_locked(tcx_u64 modid, tcx_u64 block_offset)
{
	struct task_context_info_v1 *info = &task_context_info_v1;
	tcx_u32 tag = modid ? TASK_CONTEXT_RECIPE_DTV : TASK_CONTEXT_RECIPE_TP_OFFSET;

	/* The record is already published, and not by this copy (a copy that
	 * had would have set tcx_ready): another copy shares it. */
	if (__atomic_load_n(&info->recipe_tag, __ATOMIC_ACQUIRE) !=
	    TASK_CONTEXT_RECIPE_UNSET) {
		__atomic_store_n(&tcx_refused, 1, __ATOMIC_RELEASE);
		return TASK_CONTEXT_EDUPLICATE;
	}
	if (!tcx_atfork_made) {
		/* A failure leaves only the narrow case above uncovered. */
		(void)pthread_atfork(NULL, NULL, tcx_after_fork_in_child);
		tcx_atfork_made = 1;
	}
	if (!tcx_key_made) {
		if (pthread_key_create(&tcx_key, tcx_thread_exit) != 0)
			return TASK_CONTEXT_ENOMEM;
		tcx_key_made = 1;
	}
	if (!tcx_region) {
		void *p = mmap(NULL, TASK_CONTEXT_REGION_SIZE,
			       PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1,
			       0);

		if (p == MAP_FAILED)
			return TASK_CONTEXT_ENOMEM;
#ifdef MADV_NOHUGEPAGE
		/*
		 * Where every anonymous mapping is given huge pages, the first
		 * byte touched here would otherwise fault in 2 MiB per process.
		 * A kernel without huge pages refuses the advice; that is fine.
		 */
		(void)madvise(p, TASK_CONTEXT_REGION_SIZE, MADV_NOHUGEPAGE);
#endif
		tcx_region = p;
	}

	info->self_address = (tcx_u64)(uintptr_t)info;
	info->region_base = (tcx_u64)(uintptr_t)tcx_region;
	info->region_size = TASK_CONTEXT_REGION_SIZE;
	if (modid) {
		info->tp_offset = 0;
		info->dtv_modid = modid;
		info->dtv_block_offset = block_offset;
	} else {
		info->tp_offset = tcx_slot_offset();
	}
	__atomic_store_n(&info->recipe_generation, info->recipe_generation + 1,
			 __ATOMIC_RELEASE);
	/* The tag last: a reader that sees it sees everything above. */
	__atomic_store_n(&info->recipe_tag, tag, __ATOMIC_RELEASE);
	__atomic_store_n(&tcx_ready, 1, __ATOMIC_RELEASE);
	return TASK_CONTEXT_OK;
}

static int tcx_publish(void)
{
	tcx_u64 modid = 0, block_offset = 0;
	int rc = TASK_CONTEXT_OK;

	if (__atomic_load_n(&tcx_ready, __ATOMIC_ACQUIRE))
		return TASK_CONTEXT_OK;
	if (__atomic_load_n(&tcx_refused, __ATOMIC_ACQUIRE))
		return TASK_CONTEXT_EDUPLICATE;
	/*
	 * Whatever needs the dynamic linker's locks is done before ours is
	 * taken, never under it: a thread inside dlopen() holds theirs while a
	 * library's constructor may call in here for ours.  Two threads that
	 * both get this far measure the same numbers.
	 */
	if (tcx_another_copy_is_ahead()) {
		__atomic_store_n(&tcx_refused, 1, __ATOMIC_RELEASE);
		return TASK_CONTEXT_EDUPLICATE;
	}
#if defined(TASK_CONTEXT_DTV)
	/*
	 * If the walk cannot find the block after the touch, the loader put the
	 * variable in static TLS and never fills this thread's DTV entry for it:
	 * TLS descriptors, aarch64's default, do that for a library loaded with
	 * dlopen.  The variable is then a fixed distance from the thread pointer
	 * in every thread, and the recipe is that distance - checked in each
	 * thread's first call, as in a default build.
	 */
	if (tcx_dtv_measure(&modid, &block_offset) != TASK_CONTEXT_OK)
		modid = 0;
#endif
	pthread_mutex_lock(&tcx_init_lock);
	if (!tcx_ready)
		rc = tcx_publish_locked(modid, block_offset);
	pthread_mutex_unlock(&tcx_init_lock);
	return rc;
}

/*
 * Publish at load, so that a tracer attached after program start finds the
 * recipe already there.  A failure here is not fatal: nothing is published
 * and the first set tries again and reports it.
 */
__attribute__((constructor)) static void tcx_at_load(void)
{
	(void)tcx_publish();
}

/* ---------------------------------------------------------------------- */
/* A thread's first call                                                   */
/* ---------------------------------------------------------------------- */

static struct task_context_block_v1 *tcx_first_call(int *rc_out)
{
	struct task_context_block_v1 *b;
	int rc = tcx_publish();

	if (rc != TASK_CONTEXT_OK) {
		*rc_out = rc;
		return NULL;
	}
	if (!tcx_slot_is_where_the_recipe_says()) {
		*rc_out = TASK_CONTEXT_EUNSUPPORTED;
		return NULL;
	}
	b = tcx_block_take();
	if (!b) {
		__atomic_fetch_add(&task_context_info_v1.region_full_count, 1,
				   __ATOMIC_RELAXED);
		*rc_out = TASK_CONTEXT_ENOBLOCK;
		return NULL;
	}
	tcx_block_reset(b, tcx_next_thread_index());
	if (pthread_setspecific(tcx_key, b) != 0) {
		tcx_block_give_back(b);
		*rc_out = TASK_CONTEXT_ENOMEM;
		return NULL;
	}
	/* The block is complete; only now does the slot point at it. */
	__atomic_store_n(&tcx_slot, b, __ATOMIC_RELEASE);
	return b;
}

/* ---------------------------------------------------------------------- */
/* Updates: the header's writer rule, line for line                        */
/* ---------------------------------------------------------------------- */

static int tcx_update_begin(struct task_context_block_v1 *b, tcx_u64 *s_out)
{
	tcx_u64 s = __atomic_load_n(&b->seq, __ATOMIC_RELAXED);

again:
	if (s & TASK_CONTEXT_SEQ_BUSY) {
		/* We interrupted this thread's own update. */
		__atomic_fetch_add(&task_context_info_v1.busy_refused_count, 1,
				   __ATOMIC_RELAXED);
		return TASK_CONTEXT_EBUSY;
	}
	if (!__atomic_compare_exchange_n(&b->seq, &s,
					 s | TASK_CONTEXT_SEQ_BUSY, 0,
					 __ATOMIC_RELAXED, __ATOMIC_RELAXED))
		goto again;	/* a signal handler updated in between */
	__atomic_thread_fence(__ATOMIC_RELEASE);
	*s_out = s;
	return TASK_CONTEXT_OK;
}

static void tcx_update_end(struct task_context_block_v1 *b, tcx_u64 s)
{
	__atomic_store_n(&b->seq, task_context_seq_next(s), __ATOMIC_RELEASE);
}

/* Nothing was written: the word goes back to the id it had. */
static void tcx_update_abandon(struct task_context_block_v1 *b, tcx_u64 s)
{
	__atomic_store_n(&b->seq, s, __ATOMIC_RELEASE);
}

static int tcx_name_byte_ok(unsigned char c)
{
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
	       (c >= '0' && c <= '9') || c == '_' || c == '.' || c == ':' ||
	       c == '-';
}

/* 1..NAME_MAX-1 bytes of the name class; the length through *len_out. */
static int tcx_check_name(const char *name, size_t *len_out)
{
	size_t n = 0;

	if (!name)
		return TASK_CONTEXT_EINVAL_NAME;
	while (n < TASK_CONTEXT_NAME_MAX && name[n] != '\0') {
		if (!tcx_name_byte_ok((unsigned char)name[n]))
			return TASK_CONTEXT_EINVAL_NAME;
		n++;
	}
	if (n == 0 || n >= TASK_CONTEXT_NAME_MAX)
		return TASK_CONTEXT_EINVAL_NAME;
	*len_out = n;
	return TASK_CONTEXT_OK;
}

static int tcx_find_name(const struct task_context_block_v1 *b,
			 const char *name, size_t len)
{
	int i;

	for (i = 0; i < TASK_CONTEXT_SLOTS; i++) {
		const struct task_context_slot_v1 *slot = &b->slots[i];

		if (!((b->set_mask >> i) & 1u))
			continue;
		if (slot->name_len == len && memcmp(slot->name, name, len) == 0)
			return i;
	}
	return -1;
}

static int tcx_unused_slot(const struct task_context_block_v1 *b)
{
	int i;

	for (i = 0; i < TASK_CONTEXT_SLOTS; i++) {
		if (!((b->set_mask >> i) & 1u))
			return i;
	}
	return -1;
}

static int tcx_set(const char *name, size_t name_len, tcx_u8 type,
		   const char *str, size_t str_len, tcx_u64 number)
{
	struct task_context_block_v1 *b = tcx_slot;
	struct task_context_slot_v1 *slot;
	tcx_u64 s;
	int rc = TASK_CONTEXT_OK;
	int i;

	if (!b) {
		b = tcx_first_call(&rc);
		if (!b)
			return rc;
	}
	rc = tcx_update_begin(b, &s);
	if (rc != TASK_CONTEXT_OK)
		return rc;

	/* The slots are looked at only now, with the word odd. */
	i = tcx_find_name(b, name, name_len);
	if (i < 0) {
		i = tcx_unused_slot(b);
		if (i < 0) {
			tcx_update_abandon(b, s);
			return TASK_CONTEXT_ENOSLOT;
		}
		slot = &b->slots[i];
		memset(slot->name, 0, sizeof(slot->name));
		memcpy(slot->name, name, name_len);
		slot->name_len = (tcx_u8)name_len;
	}
	slot = &b->slots[i];
	slot->reserved = 0;
	memset(slot->value.str, 0, sizeof(slot->value.str));
	if (type == TASK_CONTEXT_TYPE_STRING) {
		memcpy(slot->value.str, str, str_len);
		slot->value_len = (tcx_u16)str_len;
	} else {
		slot->value.u64 = number;
		slot->value_len = (tcx_u16)sizeof(number);
	}
	slot->type = type;
	b->set_mask |= 1u << i;
	tcx_update_end(b, s);
	return TASK_CONTEXT_OK;
}

/* ---------------------------------------------------------------------- */
/* The API                                                                 */
/* ---------------------------------------------------------------------- */

int set_task_context_str(const char *name, const char *value)
{
	size_t name_len = 0;
	size_t value_len;
	int rc = tcx_check_name(name, &name_len);

	if (rc != TASK_CONTEXT_OK)
		return rc;
	if (!value)
		return TASK_CONTEXT_EINVAL_VALUE;
	value_len = strnlen(value, TASK_CONTEXT_VALUE_MAX + 1);
	if (value_len > TASK_CONTEXT_VALUE_MAX)
		return TASK_CONTEXT_ETOOLONG;
	return tcx_set(name, name_len, TASK_CONTEXT_TYPE_STRING, value,
		       value_len, 0);
}

int set_task_context_u64(const char *name, uint64_t value)
{
	size_t name_len = 0;
	int rc = tcx_check_name(name, &name_len);

	if (rc != TASK_CONTEXT_OK)
		return rc;
	return tcx_set(name, name_len, TASK_CONTEXT_TYPE_U64, NULL, 0, value);
}

int clear_task_context(const char *name)
{
	struct task_context_block_v1 *b;
	size_t name_len = 0;
	tcx_u64 s;
	int rc = tcx_check_name(name, &name_len);
	int i;

	if (rc != TASK_CONTEXT_OK)
		return rc;
	b = tcx_slot;
	if (!b)
		return TASK_CONTEXT_OK;	/* this thread never set anything */
	rc = tcx_update_begin(b, &s);
	if (rc != TASK_CONTEXT_OK)
		return rc;
	i = tcx_find_name(b, name, name_len);
	if (i < 0) {
		tcx_update_abandon(b, s);
		return TASK_CONTEXT_OK;
	}
	memset(&b->slots[i], 0, sizeof(b->slots[i]));
	b->set_mask &= ~(1u << i);
	tcx_update_end(b, s);
	return TASK_CONTEXT_OK;
}

uint64_t task_context_current_id(void)
{
	struct task_context_block_v1 *b = tcx_slot;

	if (!b)
		return 0;
	/* From inside an interrupted update: the id that update started from. */
	return __atomic_load_n(&b->seq, __ATOMIC_RELAXED) &
	       ~TASK_CONTEXT_SEQ_BUSY;
}

int task_context_describe_self(struct task_context_self *out)
{
	uintptr_t tp;

	if (!out)
		return TASK_CONTEXT_EINVAL_VALUE;
	tp = tcx_thread_pointer();
	out->thread_pointer = (const void *)tp;
	out->slot_address = (const void *)&tcx_slot;
	out->tp_offset = (int64_t)((intptr_t)&tcx_slot - (intptr_t)tp);
	out->block = tcx_slot;
	out->id = task_context_current_id();
	return TASK_CONTEXT_OK;
}
