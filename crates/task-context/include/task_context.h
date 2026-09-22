/* SPDX-License-Identifier: MIT */
/*
 * task_context.h - the task_context ABI and API, version 1.
 *
 * task_context lets a thread attach a few NAMED values (a string of up to
 * TASK_CONTEXT_VALUE_MAX bytes, or a 64-bit number) to itself, for example
 * "request_id" or "iteration_id".  A tracer started with
 * --include-task-context reads them from outside the process and stores
 * them beside the samples it takes of that thread.
 *
 * This ONE file is the whole contract between the two sides:
 *
 *   PART 1 (the ABI) is included by the writer library AND by the tracer's
 *   BPF code.  It uses no libc type, so a BPF translation unit can include
 *   it after vmlinux.h.  It defines the two records a reader looks at - one
 *   per process ("info"), one per thread ("block") - and the rule by which
 *   they are written and read.
 *
 *   PART 2 (the API) is for programs that link the library: set, clear, and
 *   a small accessor used by the examples and the tests.
 *
 * HOW A READER FINDS A THREAD'S VALUES, in one paragraph.  The library owns
 * exactly ONE pointer-sized thread-local variable, compiled with the
 * initial-exec TLS model.  Its value is NULL ("this thread has no context")
 * or the address of the thread's block.  Because the variable is in STATIC
 * TLS, its distance from the thread pointer is the same for every thread of
 * the process and never changes - whether the library was linked statically,
 * loaded at program start, or (glibc, within limits, see "Limits") loaded
 * with dlopen.  The library REPORTS that distance in its info record.  A
 * reader therefore never derives an offset from a TLS module id, never walks
 * a DTV and never parses a relocation: it reads thread pointer + tp_offset,
 * follows the pointer, and checks what it lands on.
 *
 *   thread pointer:  x86-64  the FS base          (TLS variant 2: static TLS
 *                            lies BELOW it, so tp_offset is NEGATIVE)
 *                    aarch64 TPIDR_EL0            (TLS variant 1: static TLS
 *                            lies ABOVE it, so tp_offset is POSITIVE)
 *
 * TRUST.  Any process can set any name to any value.  A consumer may JOIN on
 * a context value for convenience; it must never authorise, bill or
 * attribute ownership by one.  Values are copied into traces: do not put a
 * secret in one.  A reader treats everything in both records as untrusted
 * input and bounds every length by its OWN constants (see "Reader rule").
 */
#ifndef TASK_CONTEXT_H
#define TASK_CONTEXT_H

/* ====================================================================== */
/* PART 1 - THE ABI (writer library and BPF reader)                        */
/* ====================================================================== */

#define TASK_CONTEXT_ABI_VERSION	1

/* The single constants.  A reader clamps by its OWN copy of each. */
#define TASK_CONTEXT_VALUE_MAX		256	/* longest string value, bytes  */
#define TASK_CONTEXT_NAME_MAX		32	/* name buffer; names <= 31 bytes */
#define TASK_CONTEXT_SLOTS		8	/* names set at once, per thread */

/*
 * Every block lives in ONE region the library reserves whole, once, and
 * never unmaps or moves: anonymous, private, read-write, MAP_NORESERVE,
 * then madvise(MADV_NOHUGEPAGE) (untouched pages cost address space only;
 * without the advice a host that gives huge pages to every anonymous
 * mapping would make the first block's first byte cost 2 MiB).  Its size is
 * a multiple of 64 KiB so that it is page-aligned on every page size.
 */
#define TASK_CONTEXT_REGION_SIZE	(16u * 1024u * 1024u)
/*
 * Blocks sit at region_base + k * TASK_CONTEXT_BLOCK_STRIDE.  The stride is
 * a multiple of 64 so that two threads' blocks never share a cache line;
 * bytes of a block past the ABI part (2,400) are private to the writer.
 */
#define TASK_CONTEXT_BLOCK_STRIDE	2560u

#define TASK_CONTEXT_INFO_MAGIC		0x31584354u	/* "TCX1" */
#define TASK_CONTEXT_BLOCK_MAGIC	0x42584354u	/* "TCXB" */

/* Where discovery looks, first by section, then by dynamic symbol. */
#define TASK_CONTEXT_INFO_SECTION	"task_context_info"
#define TASK_CONTEXT_INFO_SYMBOL	"task_context_info_v1"

#if defined(__bpf__)
/* vmlinux.h (or linux/types.h) and bpf/bpf_helpers.h come first in a BPF
 * translation unit: they give __u8..__s64 and __always_inline. */
typedef __u8  tcx_u8;
typedef __u16 tcx_u16;
typedef __u32 tcx_u32;
typedef __u64 tcx_u64;
typedef __s64 tcx_s64;
#define TCX_INLINE static __always_inline
#else
#include <stddef.h>
#include <stdint.h>
typedef uint8_t  tcx_u8;
typedef uint16_t tcx_u16;
typedef uint32_t tcx_u32;
typedef uint64_t tcx_u64;
typedef int64_t  tcx_s64;
#define TCX_INLINE static inline
#endif

#if defined(__cplusplus)
#define TCX_STATIC_ASSERT(cond, msg) static_assert(cond, msg)
#else
#define TCX_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)
#endif

/* ---------------------------------------------------------------------- */
/* 1.1 The info record: one per process, written by the library            */
/* ---------------------------------------------------------------------- */

/* recipe_tag: how a reader gets from a thread to its slot. */
#define TASK_CONTEXT_RECIPE_UNSET	0u	/* not published yet          */
#define TASK_CONTEXT_RECIPE_TP_OFFSET	1u	/* slot = thread pointer + tp_offset */
#define TASK_CONTEXT_RECIPE_DTV		2u	/* reserved: via the DTV entry of dtv_modid */
#define TASK_CONTEXT_RECIPE_PTHREAD_KEY	3u	/* reserved: via pthread_key  */
/* Tags 0x100 and up are reserved for recipes a READER makes up for a
 * process that does not link this library; the library never publishes one. */

/*
 * The library defines exactly one object of this type,
 *
 *	struct task_context_info_v1 task_context_info_v1
 *		__attribute__((section(TASK_CONTEXT_INFO_SECTION), used,
 *			       visibility("default"), aligned(8)));
 *
 * in a section of its own - so a static binary that was stripped still
 * answers (strip keeps allocated sections and their headers; a file whose
 * section header table was removed answers through the dynamic symbol
 * only) - AND exported as a dynamic symbol.  Runtime address = the
 * section's (or symbol's) link-time address + the object's load bias.
 *
 * All fields are host-endian and naturally aligned; there is no padding
 * that is not a named field.  Fields marked CONST are in the file's data
 * image; the others are written at run time under the publication rule.
 */
struct task_context_info_v1 {
	tcx_u32 magic;			/*   0 CONST TASK_CONTEXT_INFO_MAGIC      */
	tcx_u16 version;		/*   4 CONST TASK_CONTEXT_ABI_VERSION     */
	tcx_u16 info_size;		/*   6 CONST sizeof(this) as built; a reader
					 *     copies min(its own, this)       */
	tcx_u32 recipe_tag;		/*   8 TASK_CONTEXT_RECIPE_*; written LAST  */
	tcx_u32 recipe_generation;	/*  12 1 at first publication, +1 each time
					 *     the recipe is published again     */
	tcx_s64 tp_offset;		/*  16 tag 1: &slot - thread pointer       */
	tcx_u64 dtv_modid;		/*  24 tag 2 (reserved)                    */
	tcx_u64 dtv_block_offset;	/*  32 tag 2 (reserved): &slot - start of
					 *     this module's TLS block           */
	tcx_u32 pthread_key;		/*  40 tag 3 (reserved)                    */
	tcx_u32 flags;			/*  44 0                                   */
	tcx_u64 self_address;		/*  48 this record's own run-time address:
					 *     a reader that computed the address
					 *     from the file checks its arithmetic */
	tcx_u64 region_base;		/*  56 every block lies in               */
	tcx_u64 region_size;		/*  64 [region_base, region_base + size) */
	tcx_u32 block_size;		/*  72 CONST TASK_CONTEXT_BLOCK_STRIDE     */
	tcx_u16 block_hdr_size;		/*  76 CONST bytes before slots[0]         */
	tcx_u16 slot_size;		/*  78 CONST sizeof(one slot)              */
	tcx_u16 nslots;			/*  80 CONST TASK_CONTEXT_SLOTS            */
	tcx_u16 name_max;		/*  82 CONST TASK_CONTEXT_NAME_MAX         */
	tcx_u32 value_max;		/*  84 CONST TASK_CONTEXT_VALUE_MAX        */
	tcx_u64 region_full_count;	/*  88 sets refused: no free block         */
	tcx_u64 busy_refused_count;	/*  96 sets / clears refused: nested call  */
};					/* 104                                     */

/*
 * PUBLICATION RULE.  The library fills self_address, region_base,
 * region_size and tp_offset, and only then stores recipe_generation and
 * recipe_tag with release ordering (recipe_tag last).  A reader that finds
 * recipe_tag == TASK_CONTEXT_RECIPE_UNSET has found a process that links the
 * library and has not published yet: it reads nothing further and looks
 * again later by whatever means it already has.  The library SHOULD publish
 * from a load-time constructor, so that a tracer attached after program
 * start finds the recipe already there; it MUST have published before the
 * first set returns.  The two counters may change at any time and are
 * statistics, nothing more.
 *
 * SELF-CHECK (writer).  On every thread's first call the library recomputes
 * &slot - thread pointer and compares it with tp_offset.  A difference means
 * the variable is not in static TLS in this process: the call returns
 * TASK_CONTEXT_EUNSUPPORTED and nothing is published for that thread.
 *
 * ONE COPY (writer).  A process holds ONE copy of the library.  A second
 * copy - a static one in the executable beside a shared object - would make a
 * second variable and, unless the dynamic linker binds both copies to one
 * record, a second record for the same process.  Whichever copy publishes
 * second finds the record already published (or, for a copy that keeps a
 * record of its own, another copy's record ahead of it in the program's
 * global symbol scope), publishes nothing, and every call it serves returns
 * TASK_CONTEXT_EDUPLICATE.  The second check needs dlopen() and dlsym();
 * where the program has none it is not made, and a copy the program does not
 * export is not seen.
 */

/* ---------------------------------------------------------------------- */
/* 1.2 The block: one per thread that ever called set                      */
/* ---------------------------------------------------------------------- */

#define TASK_CONTEXT_TYPE_UNSET		0u
#define TASK_CONTEXT_TYPE_U64		1u
#define TASK_CONTEXT_TYPE_STRING	2u

struct task_context_slot_v1 {
	tcx_u8  type;			/*   0 TASK_CONTEXT_TYPE_*                 */
	tcx_u8  name_len;		/*   1 1..NAME_MAX-1 when type != UNSET    */
	tcx_u16 value_len;		/*   2 STRING: bytes used, 0..VALUE_MAX;
					 *     U64: 8.  A HINT to a reader.      */
	tcx_u32 reserved;		/*   4 0                                   */
	char    name[TASK_CONTEXT_NAME_MAX]; /* 8 NUL-terminated, zero-filled     */
	union {
		tcx_u64 u64;
		char    str[TASK_CONTEXT_VALUE_MAX]; /* value_len bytes, the rest
					 * zero; NOT NUL-terminated at full length */
	} value;			/*  40                                     */
};					/* 296                                     */

struct task_context_block_v1 {
	tcx_u32 magic;			/*   0 TASK_CONTEXT_BLOCK_MAGIC            */
	tcx_u16 version;		/*   4 TASK_CONTEXT_ABI_VERSION            */
	tcx_u16 hdr_size;		/*   6 32                                  */
	tcx_u64 seq;			/*   8 the SEQUENCE WORD, see below        */
	tcx_u32 set_mask;		/*  16 bit i set = slots[i].type != UNSET  */
	tcx_u32 reserved0;		/*  20 0                                   */
	tcx_u64 reserved1;		/*  24 0                                   */
	struct task_context_slot_v1 slots[TASK_CONTEXT_SLOTS];	/* 32        */
};					/* 2400; the stride is 2560                */

/*
 * THE SEQUENCE WORD is also the thread's CONTEXT ID: the 8 bytes a tracer
 * stores with each sample.  The values themselves travel once per id.
 *
 *	bits 63..40  thread index: taken ONCE, when the block is handed to a
 *	             thread, from a process-wide counter that starts at 1 and
 *	             skips 0 when it wraps.  A block returned by an exiting
 *	             thread is handed out again under a NEW index.
 *	bits 39..1   update count, starts at 1, +1 per completed set / clear,
 *	             wraps inside its own field and skips 0.
 *	bit  0       1 while an update is in progress.
 *
 * So the word is never 0, ids of one process do not collide while the
 * 24-bit index has not wrapped, and no set writes memory shared with another
 * thread.  Because the index CAN wrap in a long-lived process, a consumer
 * keys values by (thread id, context id), never by the context id alone.
 * Context id 0 means "no context".
 */
#define TASK_CONTEXT_SEQ_BUSY		0x0000000000000001ull
#define TASK_CONTEXT_SEQ_COUNT_MASK	0x000000fffffffffeull
#define TASK_CONTEXT_SEQ_INDEX_MASK	0xffffff0000000000ull
#define TASK_CONTEXT_SEQ_INDEX_SHIFT	40

/* The first word of a block handed to thread index `idx` (1..0xffffff). */
TCX_INLINE tcx_u64 task_context_seq_first(tcx_u64 idx)
{
	return (idx << TASK_CONTEXT_SEQ_INDEX_SHIFT) | 2ull;
}

/* The even word that follows even word `s`. */
TCX_INLINE tcx_u64 task_context_seq_next(tcx_u64 s)
{
	tcx_u64 cnt = (s + 2ull) & TASK_CONTEXT_SEQ_COUNT_MASK;

	if (cnt == 0)
		cnt = 2ull;
	return (s & TASK_CONTEXT_SEQ_INDEX_MASK) | cnt;
}

/*
 * WRITER RULE (normative).  `seq` is a plain 64-bit field accessed with the
 * compiler's __atomic builtins; `b` is the calling thread's own block.
 *
 *	s = __atomic_load_n(&b->seq, __ATOMIC_RELAXED);
 *   again:
 *	if (s & TASK_CONTEXT_SEQ_BUSY)
 *		return TASK_CONTEXT_EBUSY;	// we interrupted our own update
 *	if (!__atomic_compare_exchange_n(&b->seq, &s, s | TASK_CONTEXT_SEQ_BUSY,
 *					 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED))
 *		goto again;			// a signal handler updated in between
 *	__atomic_thread_fence(__ATOMIC_RELEASE);
 *	... write the slot's bytes and set_mask ...
 *	__atomic_store_n(&b->seq, task_context_seq_next(s), __ATOMIC_RELEASE);
 *
 * The odd store is RELAXED and is FOLLOWED by a release fence: a release
 * store would order only what came before it, and the slot writes that come
 * after it could then become visible ahead of it on a weakly ordered CPU.
 * The closing even store is a release store: the slot writes are visible
 * before it.  This is the C11 sequence-lock writer, and the shape of the
 * kernel's seqcount writer.  The odd transition is a compare-and-swap from
 * the value just loaded, so an update made by a signal handler between the
 * load and the swap is seen and the step starts again; a set or clear
 * entered while the word is odd returns TASK_CONTEXT_EBUSY at once - it
 * never waits and never nests.
 *
 * A NEW BLOCK is complete - magic, version, hdr_size, its first sequence
 * word (task_context_seq_first), every slot zero - BEFORE its address is
 * stored into the thread's slot, and that store is a release store: a
 * reader that sees a non-NULL slot sees a valid header behind it.
 *
 * READER RULE (normative).  A reader never blocks and never retries in
 * place.  Every miss is COUNTED under its own reason and is never stored as
 * an empty or zero value.
 *
 *   0. Test the RETURN of every copy before looking at one byte of its
 *      destination: the kernel's user-memory read helpers zero the
 *      destination when they fail.  ZERO IS NEVER A VALID HEADER WORD: the
 *      magic is not 0, the version is at least 1, the sequence word is never
 *      0.  "No context" is a NULL slot that was read SUCCESSFULLY.
 *   1. No published recipe for the process: read nothing.
 *   2. Read the 8-byte slot at thread pointer + tp_offset.  NULL: no context.
 *      A reader that copies from ANOTHER task's address space first checks
 *      that the thread pointer is plausible for the architecture and, after
 *      the slot read, that the block address lies inside
 *      [region_base, region_base + region_size) at a multiple of block_size
 *      from region_base (block_size checked non-zero) - BEFORE it reads the
 *      block, so that it never asks the kernel for an address the process
 *      did not reserve.
 *   3. Copy the first 16 bytes of the block.  magic / version wrong: a miss.
 *   4. s1 = seq.  s1 odd: an update is in progress; the sample keeps the last
 *      id seen for the thread.  (When the reader runs ON the writer's own
 *      CPU, inside its thread, this is the only tear it can ever meet.)
 *   5. s1 equals the last id seen for the thread: nothing changed.
 *   6. Otherwise copy the header and the slots - walking at most the
 *      reader's OWN TASK_CONTEXT_SLOTS, taking a name as at most its OWN
 *      NAME_MAX bytes and a value as at most its OWN VALUE_MAX bytes,
 *      whatever nslots / name_len / value_len say - then copy seq again: s2.
 *   7. s2 != s1: torn; discard the copy, keep the last id seen.
 *   8. The sample carries s1, and the copied values are the values of s1.
 *
 * A string is kept only after bytes that are not valid UTF-8, and the
 * control ranges U+0000-U+001F and U+007F-U+009F, have been replaced.
 *
 * ORDERING, WHAT IS AND IS NOT SHOWN.  For a reader inside the writer's own
 * thread only compiler order matters, and the fence provides it.  For a
 * reader on another CPU the argument above follows from the C11 memory
 * model and mirrors the kernel's own seqcount; on x86-64 stores are not
 * reordered with stores, so the question is about weakly ordered machines
 * such as aarch64.  No test has yet demonstrated it on such hardware, and an
 * emulator cannot: the library's test suite is to carry a two-thread test
 * (one thread setting two values in a loop, one reading word / slots / word
 * and counting torn pairs) meant to run on real aarch64 cores.
 */

/* ---------------------------------------------------------------------- */
/* 1.3 Limits and behaviours a reader or a caller can rely on              */
/* ---------------------------------------------------------------------- */
/*
 * - dlopen.  A library loaded AFTER program start gets its initial-exec
 *   variable from the static-TLS surplus the loader kept.  glibc keeps
 *   1,664 bytes by default for ALL such libraries together (glibc 2.42;
 *   tunables glibc.rtld.optional_static_tls and glibc.rtld.nns): this
 *   library needs 8 of them, and if they are gone dlopen fails with the
 *   loader's own error.  musl refuses to dlopen a library with initial-exec
 *   TLS at all.  Neither case is silent.  Linking statically or at program
 *   start has no such limit.  (Tags 2 and 3 exist so that a later version
 *   can serve those cases; version 1 publishes tag 1 only.)
 * - A thread that never called set has a NULL slot and no block.
 * - Thread exit: one process-wide pthread key's destructor sets the slot to
 *   NULL and returns the block to a lock-free free list.  The region is
 *   never unmapped, so a reader racing an exit reads memory the library
 *   still owns.
 * - fork: the child's one thread inherits the slot, the block and the
 *   region at the same addresses, so the parent's recipe holds in the child
 *   and the child starts with the parent thread's context.
 * - exec: a new image; nothing is inherited.
 * - More threads holding a block than the region has room for
 *   (TASK_CONTEXT_REGION_SIZE / TASK_CONTEXT_BLOCK_STRIDE = 6,553): set
 *   returns TASK_CONTEXT_ENOBLOCK and region_full_count goes up.
 * - Signal handlers: set and clear are refused (TASK_CONTEXT_EBUSY) when
 *   they interrupt the same thread's own update, and must not be a thread's
 *   FIRST call (that call takes a block and may create the pthread key).
 * - 64-bit processes only.  A thread that rewrites its own thread pointer,
 *   and runtimes that move a task between OS threads, are out of scope: the
 *   context belongs to the OS thread.
 */

TCX_STATIC_ASSERT(sizeof(struct task_context_info_v1) == 104, "info record size");
TCX_STATIC_ASSERT(__builtin_offsetof(struct task_context_info_v1, recipe_tag) == 8, "recipe_tag");
TCX_STATIC_ASSERT(__builtin_offsetof(struct task_context_info_v1, tp_offset) == 16, "tp_offset");
TCX_STATIC_ASSERT(__builtin_offsetof(struct task_context_info_v1, region_base) == 56, "region_base");
TCX_STATIC_ASSERT(__builtin_offsetof(struct task_context_info_v1, block_size) == 72, "block_size");
TCX_STATIC_ASSERT(sizeof(struct task_context_slot_v1) == 296, "slot size");
TCX_STATIC_ASSERT(__builtin_offsetof(struct task_context_slot_v1, value) == 40, "slot value");
TCX_STATIC_ASSERT(__builtin_offsetof(struct task_context_block_v1, seq) == 8, "seq");
TCX_STATIC_ASSERT(__builtin_offsetof(struct task_context_block_v1, slots) == 32, "slots");
TCX_STATIC_ASSERT(sizeof(struct task_context_block_v1) == 2400, "block size");
TCX_STATIC_ASSERT(sizeof(struct task_context_block_v1) <= TASK_CONTEXT_BLOCK_STRIDE, "stride");
TCX_STATIC_ASSERT(TASK_CONTEXT_BLOCK_STRIDE % 64 == 0, "stride is cache-line aligned");
TCX_STATIC_ASSERT(TASK_CONTEXT_REGION_SIZE % 65536 == 0, "region is 64 KiB aligned");
TCX_STATIC_ASSERT(TASK_CONTEXT_SLOTS <= 32, "set_mask is 32 bits");

/* ====================================================================== */
/* PART 2 - THE API (programs that link the library)                       */
/* ====================================================================== */
#if !defined(__bpf__)

#if UINTPTR_MAX != 0xffffffffffffffffull
#error "task_context supports 64-bit processes only"
#endif

#if defined(__GNUC__)
#define TASK_CONTEXT_API __attribute__((visibility("default")))
#else
#define TASK_CONTEXT_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Return values: 0, or one of these.  Nothing is ever truncated. */
#define TASK_CONTEXT_OK			0
#define TASK_CONTEXT_EINVAL_NAME	(-1)	/* NULL, empty, 32 bytes or longer, or a
						 * byte outside [A-Za-z0-9_.:-]          */
#define TASK_CONTEXT_EINVAL_VALUE	(-2)	/* NULL string                          */
#define TASK_CONTEXT_ETOOLONG		(-3)	/* string longer than VALUE_MAX bytes   */
#define TASK_CONTEXT_ENOSLOT		(-4)	/* SLOTS names are already set here     */
#define TASK_CONTEXT_EBUSY		(-5)	/* nested call, see "Signal handlers"   */
#define TASK_CONTEXT_ENOBLOCK		(-6)	/* the block region is full             */
#define TASK_CONTEXT_ENOMEM		(-7)	/* the region could not be reserved     */
#define TASK_CONTEXT_EUNSUPPORTED	(-8)	/* the thread-local is not in static
						 * TLS in this process                  */
#define TASK_CONTEXT_EDUPLICATE		(-9)	/* another copy of the library in this
						 * process published first: see "ONE COPY" */

/*
 * Set `name` to `value` for the CALLING thread.  A name is bound to a slot
 * at its first set on the thread and keeps it until it is cleared.  No
 * system call, no lock and no allocation after the thread's first call.
 * The string is copied; `value` is NUL-terminated and at most
 * TASK_CONTEXT_VALUE_MAX bytes long, not counting the terminator.
 */
TASK_CONTEXT_API int set_task_context_str(const char *name, const char *value);
TASK_CONTEXT_API int set_task_context_u64(const char *name, uint64_t value);

/* Forget `name` on the calling thread and free its slot.  Clearing a name
 * that is not set returns 0. */
TASK_CONTEXT_API int clear_task_context(const char *name);

/* The calling thread's current context id (an even sequence word), or 0. */
TASK_CONTEXT_API uint64_t task_context_current_id(void);

#ifdef __cplusplus
} /* extern "C" */

/* C++: a literal 0 converts to both parameter types; for a zero value call
 * set_task_context_u64 by name. */
static inline int set_task_context(const char *name, const char *value)
{
	return set_task_context_str(name, value);
}
static inline int set_task_context(const char *name, uint64_t value)
{
	return set_task_context_u64(name, value);
}
extern "C" {
#else
/* set_task_context(name, value): a string or any integer. */
#define set_task_context(name, value)					\
	_Generic((value),						\
		 char *: set_task_context_str,				\
		 const char *: set_task_context_str,			\
		 default: set_task_context_u64)((name), (value))
#endif

/* ---------------------------------------------------------------------- */
/* 2.1 For the examples and the tests                                      */
/* ---------------------------------------------------------------------- */

struct task_context_self {
	const void *thread_pointer;	/* as the architecture defines it      */
	const void *slot_address;	/* &the library's thread-local         */
	int64_t     tp_offset;		/* slot_address - thread_pointer       */
	const void *block;		/* NULL before the thread's first set  */
	uint64_t    id;			/* task_context_current_id()           */
};

/* Describe the calling thread.  Never takes a block, never publishes. */
TASK_CONTEXT_API int task_context_describe_self(struct task_context_self *out);

/*
 * THE EXAMPLE LINE.  Each example program prints, per thread, ONE line in
 * exactly this form - the tests parse it, the userspace check and the
 * tracer's end-to-end test compare a trace against it, so it is fixed here:
 *
 *   TCX1 tid=<dec> tp=0x<hex> slot=0x<hex> off=<signed dec> block=0x<hex>
 *        id=0x<16 hex digits> set=<count>[ <name>:u=<dec>| <name>:s=<pct>]...
 *
 * on ONE line, fields separated by one space, ended by '\n'.  <tid> is the
 * kernel thread id as the thread itself sees it (gettid).  A thread that
 * never set prints block=0x0 id=0x0000000000000000 set=0.  <pct> is the
 * string value with every byte outside '!'..'~', and '%' itself,
 * written %XX.
 */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* !__bpf__ */
#endif /* TASK_CONTEXT_H */
