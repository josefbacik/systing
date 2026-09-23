/* SPDX-License-Identifier: GPL-2.0 */
/*
 * task_context_reader.bpf.h - the BPF side of --include-task-context.
 *
 * Everything the tracer's BPF object needs in order to read a thread's
 * task_context (see crates/task-context/include/task_context.h, the ABI both
 * sides are written against) lives in this one file: the maps, the one helper
 * a recorder's handler calls, and three small programs that keep a process's
 * recipe from outliving its image. The rest of the tracer includes this file
 * and calls task_context_read_current(); nothing else of the feature is in
 * systing_system.bpf.c.
 *
 * WHO CAN CALL IT. Any handler that records something about the CURRENT
 * thread: the helper is one inline function taking the task, and every
 * recorder's handlers in systing_system.bpf.c are one translation unit with
 * it. The first caller is the path that emits a running stack. A separately
 * built object (the task-stacks recorder's) would include this file as well
 * and share the maps by reusing their descriptors at load; none does yet, and
 * that recorder samples OTHER threads, which the helper refuses by design.
 *
 * HOW IT WORKS. User space (src/task_context/discovery.rs) finds each process
 * that links the writer library, validates the record the library publishes
 * and writes ONE immutable recipe per process - the distance from the thread
 * pointer to the library's thread-local slot, and the bounds of the region
 * every block lives in - into task_context_recipes, keyed by tgid. For a
 * sample of the CURRENT thread the helper below then follows the ABI's reader
 * rule: thread pointer + offset -> the slot -> the block's first 24 bytes ->
 * the sequence word, which IS the 8-byte context id the sample carries. The
 * values themselves travel once per id, on a ring of their own.
 *
 * WHAT IT NEVER DOES. It never reads kernel memory at an address a process
 * supplied: every copy of a process's bytes is bpf_probe_read_user(), and
 * every kernel read is a field of the kernel's own task struct, or of the
 * signal struct it points to, at an offset CO-RE relocates (a task's ids and
 * flags, its thread pointer in the sample path, its process's count of live
 * threads in the exit hook). It never reads another task's memory: the
 * subject is the current task or the call is a counted miss. It never blocks,
 * retries in place or faults a page in. It never submits a record it did not
 * fill completely under a good return: a reserved record is either whole or
 * discarded. Every miss in a process that published a recipe is counted under
 * its own reason and the sample then carries no id (or, when it interrupted
 * the thread's own update, the id the thread's values last travelled under);
 * a miss is never stored as an empty value. A process that published nothing
 * costs one map lookup a sample and is not counted.
 *
 * Kernel floor: nothing here is newer than what the rest of this object
 * already uses (bpf_probe_read_user, the ring buffer, BTF-typed task access,
 * tp_btf programs). The feature is written for 6.12 and newer, the kernels
 * its load test runs on; every helper and field it uses is present at 6.6.
 *
 * With the feature off (task_context_config.enabled == 0, the default) user
 * space does not load the three programs or create the maps below, and the
 * one call site is dead code the verifier prunes.
 */
#ifndef __TASK_CONTEXT_READER_BPF_H
#define __TASK_CONTEXT_READER_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "systing_shared.bpf.h"
#include "task_context.h"

/*
 * The feature's own read-only configuration, set by user space before load
 * and frozen with the rest of .rodata, so every test below is a constant the
 * verifier folds.
 */
const volatile struct task_context_config {
	u32 enabled; /* --include-task-context */
	u32 restricted; /* mirrors the tracer's confidentiality mode: read
			 * nothing of any process, store no id and no value */
	u32 values_per_cpu_per_sec; /* value records one CPU may send a second */
	u32 execs_per_cpu_per_sec; /* exec notices one CPU may send a second */
} task_context_config = { 0 };

/*
 * Why a call did not produce an id, or what it did. A CLOSED set: the index
 * into task_context_stats and nothing else; no text of any process is ever
 * part of a reason. User space prints these by name (src/task_context/mod.rs
 * keeps the same order).
 */
enum task_context_reason {
	TASK_CONTEXT_R_SAME_ID = 0, /* id read, unchanged: nothing sent */
	TASK_CONTEXT_R_NEW_ID, /* id read, a value record sent */
	TASK_CONTEXT_R_RESTRICTED, /* confidentiality mode: nothing read */
	TASK_CONTEXT_R_NOT_CURRENT, /* the task is not the current task */
	TASK_CONTEXT_R_NO_USER_CONTEXT, /* a kernel thread */
	TASK_CONTEXT_R_UNSUPPORTED_ARCH,
	TASK_CONTEXT_R_TP_IMPLAUSIBLE, /* thread pointer or slot address */
	TASK_CONTEXT_R_SLOT_READ_FAILED,
	TASK_CONTEXT_R_UNSET, /* a NULL slot, read successfully */
	TASK_CONTEXT_R_EMPTY, /* a block with no name set: no context */
	TASK_CONTEXT_R_OUT_OF_RANGE, /* block address not in the region:
				      * refused, nothing read */
	TASK_CONTEXT_R_BLOCK_READ_FAILED,
	TASK_CONTEXT_R_BAD_HEADER, /* magic / version / size / a zero word */
	TASK_CONTEXT_R_IN_PROGRESS, /* odd word: the last id stands */
	TASK_CONTEXT_R_TORN, /* unequal pair: copy discarded */
	TASK_CONTEXT_R_RATE_LIMITED, /* id kept, value record not sent */
	TASK_CONTEXT_R_RING_FULL, /* id kept, value record not sent */
	TASK_CONTEXT_R_CACHE_REFUSED, /* last-id update refused */
	TASK_CONTEXT_R_EXEC_NOTICE_DROPPED, /* limited, or its ring was full */
	TASK_CONTEXT_R_RECIPES_FULL, /* fork: no room for the child */
	TASK_CONTEXT_R_MAX,
};

/*
 * One process's recipe, as user space validated it. region_size is at least
 * one block stride and at most the reader's own ceiling (user space refuses
 * anything else), so the range test below cannot be made a no-op by a record
 * that claims the whole address space.
 */
struct task_context_recipe {
	s64 tp_offset; /* &slot - thread pointer */
	u64 region_base;
	u64 region_size;
};

/*
 * tgid -> recipe. Written by user space (discovery), copied at fork and
 * deleted at exec and at the last thread's exit by the tp_btf programs below.
 * A program that records a sample only ever looks it up. Preallocated (the
 * default for a hash map), never LRU.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct task_context_recipe);
	__uint(max_entries, 4096);
} task_context_recipes SEC(".maps");

/*
 * tid -> the last context id a value record was sent for. It only decides
 * whether the values travel again; the id a sample carries never comes from
 * it except while the thread's own update is in progress. Written by every
 * program that records a running stack - the CPU sampler (perf_event, NMI
 * context) and, when trace events are configured, the usdt, uprobe, kprobe,
 * tracepoint and raw tracepoint handlers - and deleted by the exit and exec
 * programs (tp_btf): a PREALLOCATED hash map, the one kind all of them may
 * write. An update allocates nothing, and one that interrupts another update
 * of the same bucket on its own CPU is refused by the kernel (it would
 * otherwise wait for itself) and counted here; a bucket another CPU holds is
 * a short wait on that CPU's few instructions. Never LRU.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, 16384);
} task_context_last_id SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, TASK_CONTEXT_R_MAX);
} task_context_stats SEC(".maps");

/* Per-CPU one-second budgets: slot 0 value records, slot 1 exec notices. */
struct task_context_budget {
	u64 window_start_ns;
	u64 used;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct task_context_budget);
	__uint(max_entries, 2);
} task_context_budgets SEC(".maps");

#define TASK_CONTEXT_BUDGET_VALUES 0
#define TASK_CONTEXT_BUDGET_EXECS 1

/*
 * A thread's values, sent when a sample first sees a new id for it. `block`
 * is the block's ABI part copied whole in ONE call; user space walks it with
 * its own constants. Every field is written before submit and the struct has
 * no padding: bpf_ringbuf_reserve() hands out the ring's memory as it is, and
 * nothing here clears it, so a hole would carry an earlier record's bytes out.
 */
struct task_context_value_event {
	u64 ts;
	u32 tgid;
	u32 tid;
	u64 id;
	u32 cpu;
	u32 reserved;
	u8 block[sizeof(struct task_context_block_v1)];
};

_Static_assert(sizeof(struct task_context_value_event) ==
		       32 + sizeof(struct task_context_block_v1),
	       "task_context_value_event must have no padding");

/* One ring for the value records: small, and created only with the feature. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 * 1024 * 1024);
} task_context_values SEC(".maps");

/* "This process has a new image: look at it again." */
struct task_context_exec_event {
	u32 pid;
	u32 reserved;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 64 * 1024);
} task_context_execs SEC(".maps");

/*
 * Tasks that never run user code: kernel threads, and the workers the kernel
 * makes INSIDE a process (io_uring's, vhost's). The latter share the process's
 * memory, its tgid and so its recipe, and start life with their creator's
 * thread pointer, so a read for one of them would land on the creator's
 * block: another thread's, from another CPU. They are refused like kernel
 * threads. (task_struct.flags bits, the same values at 6.6, 6.12 and 6.18.)
 */
#define TASK_CONTEXT_PF_IO_WORKER 0x00000010
#define TASK_CONTEXT_PF_USER_WORKER 0x00004000
#define TASK_CONTEXT_PF_KTHREAD 0x00200000
#define TASK_CONTEXT_PF_NO_USER_CODE                              \
	(TASK_CONTEXT_PF_KTHREAD | TASK_CONTEXT_PF_IO_WORKER |    \
	 TASK_CONTEXT_PF_USER_WORKER)

/* The lowest address a slot, a block or a thread pointer may have, and the
 * highest a user address can have on the architecture (56 bits with 5-level
 * paging on x86-64; 52 with CONFIG_ARM64_VA_BITS_52). Belt and braces: the
 * user-memory helper itself refuses a kernel address. */
#define TASK_CONTEXT_USER_ADDR_MIN 0x10000ULL
#if defined(__aarch64__)
#define TASK_CONTEXT_USER_ADDR_MAX 0x000fffffffffffffULL
#else
#define TASK_CONTEXT_USER_ADDR_MAX 0x00ffffffffffffffULL
#endif

/* Per-CPU and unlocked: a count can be lost when the sampler interrupts one
 * of the programs below in the middle of its own increment. These are
 * diagnostics, not accounting. */
static __always_inline void task_context_count(u32 reason)
{
	u32 key = reason;
	u64 *value = bpf_map_lookup_elem(&task_context_stats, &key);

	if (value)
		*value += 1;
}

static __always_inline bool task_context_user_range_ok(u64 addr, u64 len)
{
	return addr >= TASK_CONTEXT_USER_ADDR_MIN &&
	       addr <= TASK_CONTEXT_USER_ADDR_MAX - len;
}

/* One unit of this CPU's budget `which` for the current second, or false. */
static __always_inline bool task_context_take(u32 which, u64 now, u32 limit)
{
	u32 key = which;
	struct task_context_budget *b =
		bpf_map_lookup_elem(&task_context_budgets, &key);

	if (!b)
		return false;
	if (now - b->window_start_ns >= 1000000000ULL) {
		b->window_start_ns = now;
		b->used = 0;
	}
	if (b->used >= limit)
		return false;
	b->used += 1;
	return true;
}

/*
 * The thread pointer the kernel keeps for a task. Like the ids and flags the
 * helper loads from the typed task pointer, it is a field of the kernel's
 * own task struct, read at an offset CO-RE relocates. x86-64: thread.fsbase,
 * written by arch_prctl(ARCH_SET_FS) and saved at every switch. aarch64:
 * thread.uw.tp_value, refreshed from TPIDR_EL0 at every switch - user code
 * may write that register without a system call, so the saved value of a
 * MAIN thread can be stale from the C library's set-up until the thread is
 * first switched out; such a sample reads a miss, never a wrong thread's
 * context, because whatever it lands on must still pass every check below.
 */
static __always_inline u64 task_context_thread_pointer(struct task_struct *task)
{
#if defined(__x86_64__)
	return BPF_CORE_READ(task, thread.fsbase);
#elif defined(__aarch64__)
	return BPF_CORE_READ(task, thread.uw.tp_value);
#else
	return 0;
#endif
}

/*
 * The id a sample carries when the thread's block cannot be read whole right
 * now: the last one the thread's values travelled under - but only if it is
 * THIS block's. A word's top bits are the index its block was given when it
 * was handed to its thread, and they never change while the thread holds it;
 * an entry left under the same tid by an earlier thread of the SAME process
 * whose exit was not seen has another block's index, and is not carried.
 * (Each process numbers its own blocks, so across processes an index can
 * repeat: there it is the exit program's unconditional delete that keeps an
 * old entry from meeting a new thread.)
 */
static __always_inline u64 task_context_last_or_none(const u64 *last, u64 word)
{
	u64 id;

	if (!last)
		return 0;
	id = *last;
	if ((id ^ word) & TASK_CONTEXT_SEQ_INDEX_MASK)
		return 0;
	return id;
}

/*
 * The context id of the CURRENT thread for one sample, or 0 for "none".
 * `task` must be the current task (a handler whose sample describes another
 * task must not call this: the check below turns that into a counted miss).
 *
 * The steps are the ABI's reader rule, in its order and with its numbers.
 */
static __always_inline u64 task_context_read_current(struct task_struct *task)
{
	struct task_context_value_event *rec;
	struct task_context_recipe *recipe;
	u64 tp, slot_addr, block = 0, offset, s1, s2 = 0, copied = 0, now;
	u64 *last;
	u32 tgid, tid;
	struct {
		u32 magic;
		u16 version;
		u16 hdr_size;
		u64 seq;
		u32 set_mask;
		u32 reserved0;
	} head = { 0 };

	if (task_context_config.restricted) {
		task_context_count(TASK_CONTEXT_R_RESTRICTED);
		return 0;
	}

#if !defined(__x86_64__) && !defined(__aarch64__)
	task_context_count(TASK_CONTEXT_R_UNSUPPORTED_ARCH);
	return 0;
#endif

	tgid = task->tgid;
	tid = task->pid;
	if ((u32)bpf_get_current_pid_tgid() != tid) {
		task_context_count(TASK_CONTEXT_R_NOT_CURRENT);
		return 0;
	}
	if (task->flags & TASK_CONTEXT_PF_NO_USER_CODE) {
		task_context_count(TASK_CONTEXT_R_NO_USER_CONTEXT);
		return 0;
	}

	/* 1. No published recipe for the process: read nothing. The common
	 * case, and deliberately not counted: one lookup and out. */
	recipe = bpf_map_lookup_elem(&task_context_recipes, &tgid);
	if (!recipe)
		return 0;

	/* 2. The 8-byte slot at thread pointer + tp_offset. */
	tp = task_context_thread_pointer(task);
	if (!task_context_user_range_ok(tp, 0)) {
		task_context_count(TASK_CONTEXT_R_TP_IMPLAUSIBLE);
		return 0;
	}
	slot_addr = tp + (u64)recipe->tp_offset;
	if (!task_context_user_range_ok(slot_addr, sizeof(block))) {
		task_context_count(TASK_CONTEXT_R_TP_IMPLAUSIBLE);
		return 0;
	}
	/* 0. The return is tested before one byte of the destination is
	 * looked at: the helper zeroes the destination when it fails. */
	if (bpf_probe_read_user(&block, sizeof(block), (void *)slot_addr)) {
		task_context_count(TASK_CONTEXT_R_SLOT_READ_FAILED);
		return 0;
	}
	if (!block) {
		task_context_count(TASK_CONTEXT_R_UNSET);
		return 0;
	}
	/* The block must lie inside the region the library published, at a
	 * whole number of strides from its base - the test the rule demands
	 * of a reader of ANOTHER task's memory, made here too, so that a
	 * stale or wrong recipe reads nothing at all. */
	if (block < recipe->region_base ||
	    recipe->region_size < sizeof(struct task_context_block_v1)) {
		task_context_count(TASK_CONTEXT_R_OUT_OF_RANGE);
		return 0;
	}
	offset = block - recipe->region_base;
	if (offset > recipe->region_size - sizeof(struct task_context_block_v1) ||
	    offset % TASK_CONTEXT_BLOCK_STRIDE) {
		task_context_count(TASK_CONTEXT_R_OUT_OF_RANGE);
		return 0;
	}

	/* 3. The first 24 bytes of the block: the 16 the rule names and the
	 * set mask beside them. Zero is never a valid word. */
	if (bpf_probe_read_user(&head, sizeof(head), (void *)block)) {
		task_context_count(TASK_CONTEXT_R_BLOCK_READ_FAILED);
		return 0;
	}
	if (head.magic != TASK_CONTEXT_BLOCK_MAGIC ||
	    head.version != TASK_CONTEXT_ABI_VERSION ||
	    head.hdr_size != __builtin_offsetof(struct task_context_block_v1, slots) ||
	    head.seq == 0) {
		task_context_count(TASK_CONTEXT_R_BAD_HEADER);
		return 0;
	}

	/* 4. An odd word: the thread's own update is in progress (the only
	 * tear a reader inside the writer's thread can meet). The last id
	 * seen for the thread stands: the last one its values travelled
	 * under, which is older than the id of its previous sample when a
	 * value record was held back in between (the budget, a full ring). */
	s1 = head.seq;
	last = bpf_map_lookup_elem(&task_context_last_id, &tid);
	if (s1 & TASK_CONTEXT_SEQ_BUSY) {
		task_context_count(TASK_CONTEXT_R_IN_PROGRESS);
		return task_context_last_or_none(last, s1);
	}

	/* The thread has a block and has cleared every name: no context, so
	 * an id in a trace always stands for at least one name that was set.
	 * (The mask came in the same copy as the even word, from inside the
	 * thread that writes both, so the two belong together.) */
	if (!head.set_mask) {
		task_context_count(TASK_CONTEXT_R_EMPTY);
		return 0;
	}

	/* 5. Nothing changed since the values last travelled. */
	if (last && *last == s1) {
		task_context_count(TASK_CONTEXT_R_SAME_ID);
		return s1;
	}

	/* 6. A new id: its values travel once, within this CPU's budget.
	 * Past the budget, or with the ring full, the sample still carries
	 * its id; the last-id entry is left alone so that a later sample
	 * tries again. */
	now = bpf_ktime_get_boot_ns();
	if (!task_context_take(TASK_CONTEXT_BUDGET_VALUES, now,
			       task_context_config.values_per_cpu_per_sec)) {
		task_context_count(TASK_CONTEXT_R_RATE_LIMITED);
		return s1;
	}
	rec = bpf_ringbuf_reserve(&task_context_values, sizeof(*rec), 0);
	if (!rec) {
		task_context_count(TASK_CONTEXT_R_RING_FULL);
		return s1;
	}
	/* The block's ABI part, whole, in one call, straight into the
	 * record; then the word again. A record is submitted only when both
	 * copies succeeded and all three words agree - otherwise it is
	 * discarded, so no byte of an earlier record can ride out in it. */
	if (bpf_probe_read_user(rec->block, sizeof(rec->block), (void *)block) ||
	    bpf_probe_read_user(&s2, sizeof(s2),
				(void *)(block + __builtin_offsetof(struct task_context_block_v1, seq)))) {
		bpf_ringbuf_discard(rec, 0);
		task_context_count(TASK_CONTEXT_R_BLOCK_READ_FAILED);
		return s1;
	}
	__builtin_memcpy(&copied,
			 &rec->block[__builtin_offsetof(struct task_context_block_v1, seq)],
			 sizeof(copied));
	/* 7. Unequal: torn; the copy is discarded, the last id stands. */
	if (copied != s1 || s2 != s1) {
		bpf_ringbuf_discard(rec, 0);
		task_context_count(TASK_CONTEXT_R_TORN);
		return task_context_last_or_none(last, s1);
	}
	rec->ts = now;
	rec->tgid = tgid;
	rec->tid = tid;
	rec->id = s1;
	rec->cpu = bpf_get_smp_processor_id();
	rec->reserved = 0;
	bpf_ringbuf_submit(rec, 0);

	if (bpf_map_update_elem(&task_context_last_id, &tid, &s1, BPF_ANY))
		task_context_count(TASK_CONTEXT_R_CACHE_REFUSED);

	/* 8. The sample carries s1, and the values sent are the values of s1. */
	task_context_count(TASK_CONTEXT_R_NEW_ID);
	return s1;
}

/*
 * The three programs below run only with the feature on, and do nothing in
 * the tracer's confidentiality mode: no recipe exists then, so there is none
 * to copy or to delete, and nothing is announced because nothing is looked
 * for.
 */
static __always_inline bool task_context_active(void)
{
	return task_context_config.enabled && !task_context_config.restricted;
}

/*
 * A recipe does not outlive its image. exec: the old image is gone - drop the
 * recipe and the thread's last id, and tell user space to look at the process
 * again (exec fires before the loader has mapped the libraries, so user space
 * retries on a short schedule). Only processes the capture targets are
 * announced, within a per-CPU budget: user space opens files for each notice.
 */
SEC("tp_btf/sched_process_exec")
int BPF_PROG(task_context_exec, struct task_struct *task, pid_t old_pid,
	     struct linux_binprm *bprm)
{
	struct task_context_exec_event *event;
	u32 tgid = task->tgid;
	u32 tid = task->pid;
	u32 old_tid = old_pid;

	if (!task_context_active())
		return 0;

	/* A thread that execs takes over its process's id, so the entry it
	 * had until now sits under the id it had until now. */
	bpf_map_delete_elem(&task_context_recipes, &tgid);
	bpf_map_delete_elem(&task_context_last_id, &tid);
	if (old_tid != tid)
		bpf_map_delete_elem(&task_context_last_id, &old_tid);

	if (!task_in_target_set(task))
		return 0;
	if (!task_context_take(TASK_CONTEXT_BUDGET_EXECS, bpf_ktime_get_boot_ns(),
			       task_context_config.execs_per_cpu_per_sec)) {
		task_context_count(TASK_CONTEXT_R_EXEC_NOTICE_DROPPED);
		return 0;
	}
	event = bpf_ringbuf_reserve(&task_context_execs, sizeof(*event), 0);
	if (!event) {
		task_context_count(TASK_CONTEXT_R_EXEC_NOTICE_DROPPED);
		return 0;
	}
	event->pid = tgid;
	event->reserved = 0;
	bpf_ringbuf_submit(event, 0);
	return 0;
}

/*
 * fork of a PROCESS: the child's one thread inherits the slot, the block and
 * the region at the same addresses, so the parent's recipe holds in the child
 * until it execs. A new THREAD shares the tgid and needs nothing: its slot
 * starts NULL.
 */
SEC("tp_btf/sched_process_fork")
int BPF_PROG(task_context_fork, struct task_struct *parent,
	     struct task_struct *child)
{
	struct task_context_recipe *recipe, copy;
	u32 parent_tgid = parent->tgid;
	u32 child_tgid = child->tgid;

	if (!task_context_active() || parent_tgid == child_tgid)
		return 0;
	recipe = bpf_map_lookup_elem(&task_context_recipes, &parent_tgid);
	if (!recipe)
		return 0;
	/* Through the stack: the value of an update must not point into the
	 * map being updated. */
	copy.tp_offset = recipe->tp_offset;
	copy.region_base = recipe->region_base;
	copy.region_size = recipe->region_size;
	if (bpf_map_update_elem(&task_context_recipes, &child_tgid, &copy, BPF_ANY))
		task_context_count(TASK_CONTEXT_R_RECIPES_FULL);
	return 0;
}

/*
 * exit: the thread's last id goes; the recipe goes with the LAST thread of
 * the process (do_exit() decrements signal->live before this tracepoint
 * fires, so 0 here means no thread is left). The thread's own entry is
 * deleted first and without looking the recipe up: two threads of a process
 * can be here at once, and the one that finds no thread left takes the
 * recipe away under the other.
 */
SEC("tp_btf/sched_process_exit")
int BPF_PROG(task_context_exit, struct task_struct *task)
{
	u32 tgid = task->tgid;
	u32 tid = task->pid;

	if (!task_context_active())
		return 0;
	bpf_map_delete_elem(&task_context_last_id, &tid);
	if (BPF_CORE_READ(task, signal, live.counter) == 0)
		bpf_map_delete_elem(&task_context_recipes, &tgid);
	return 0;
}

#endif /* __TASK_CONTEXT_READER_BPF_H */
