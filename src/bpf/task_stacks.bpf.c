// SPDX-License-Identifier: GPL-2.0
/*
 * task-stacks recorder: a sleepable BPF task iterator. Userspace reads a seq
 * file from an iterator link; the program runs once per thread the link
 * covers, in the process context of that read(2) -- every thread on the host
 * for the plain link, one process's threads for a link scoped to it (see
 * TaskStacksIter in task_stacks_recorder.rs) -- and writes one
 * variable-length record per targeted thread: struct task_stacks_event, then
 * kernel_stack_len kernel frames, user_stack_len user frames (u64 each, leaf
 * first) and py_len bytes of struct pystacks_message. A thread that has not run
 * since its last record, and is in the same state as then, gets the header
 * alone, flagged TASK_STACKS_UNCHANGED. The header also carries the
 * thread's task_context id (--include-task-context), the system call it is in
 * and whether it is blocked on I/O, each read for a full record only: a thread
 * that has not run cannot have changed any of them.
 *
 * Why this is its own BPF object rather than a program in systing_system.bpf.o:
 *  - STROBELIGHT_SLEEPABLE_BPF selects the sleepable bodies of the pystacks
 *    task/read helpers, per compilation unit. The main object links pystacks
 *    non-sleepable under the same global names, so the two cannot share an
 *    object; this one compiles pystacks.bpf.c into itself, sleepable.
 *  - Sleepable-only helpers and kfuncs cannot reach the main object's
 *    non-sleepable programs.
 *  - It has its own lifetime: loaded only when the recorder runs, and
 *    independently of the main object.
 *
 * Targeting and shared types come from systing_shared.bpf.h.
 */
#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef STROBELIGHT_SLEEPABLE_BPF
#error "task_stacks.bpf.c must be compiled with -DSTROBELIGHT_SLEEPABLE_BPF (see build_task_stacks_bpf in build.rs)"
#endif

/*
 * Never wait at another program's memory-map lock that is already busy. Every
 * read of another task's memory takes that task's mmap_lock for reading, and
 * waits for it; there is no form of the read that gives up instead. While it
 * waits, the walk of every other thread waits behind it, and so does whatever
 * waits for this program's tasks-trace RCU read section to end, on any tool's
 * behalf. So each read looks at the lock first, and when a writer holds it or
 * anyone queues for it the read is refused, and so is every read left in that
 * thread's record: a short stack now, and the whole one once the lock is free
 * (see status_delta()). The kernel frames, read without the lock, show who
 * holds it and who waits.
 *
 * All four sites of the read in this object go through the look: the #define
 * below reaches the unwinder, pystacks' two read helpers and the task-context
 * reader, none of which is changed for it, so it has to come ahead of them.
 *
 * A look is no guarantee: the lock can be taken between it and the read, a
 * reader holds it with none of these bits set, and a read that finds it free
 * can go on to hold it for as long as a page takes to arrive, which is why the
 * unwinder keeps to the stack.
 *
 * mm is the thread's address space as this record found it, unpinned. It is
 * only ever a number to read a word at, with a read that cannot fault, and
 * what is read only decides whether to call the helper, which pins the
 * address space itself. 0: no address space, or nothing to read in it.
 */
struct task_stacks_look {
	u64 mm;
	u32 cut;	/* a look found the lock busy: read no more of this record */
	u32 off_stack;	/* the user stack stopped at a frame off the thread's stack */
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct task_stacks_look);
} task_stacks_look SEC(".maps");

/* What makes __down_read_trylock() fail, RWSEM_READ_FAILED_MASK in
 * kernel/locking/rwsem.c: the writer, waiters and handoff bits and the top
 * bit, set when too many readers have the lock. */
#define TASK_STACKS_RWSEM_BUSY \
	((1ULL << 0) | (1ULL << 1) | (1ULL << 2) | (1ULL << 63))

static __always_inline struct task_stacks_look *get_look(void)
{
	u32 key = 0;

	return bpf_map_lookup_elem(&task_stacks_look, &key);
}

/*
 * Whether this record may read no more of its thread's memory. Global, so the
 * verifier walks it once however many reads it guards (see "How this file
 * keeps the verifier's work down" below). A kernel with no such word, as under
 * PREEMPT_RT, has no way to look: the read goes on as it would have.
 */
__noinline int task_stacks_lock_busy(void)
{
	struct task_stacks_look *look = get_look();
	struct mm_struct *mm;
	u64 count;

	if (!look || !look->mm)
		return 0;
	if (look->cut)
		return 1;
	mm = (struct mm_struct *)look->mm;
	if (!bpf_core_field_exists(mm->mmap_lock.count) ||
	    bpf_core_read(&count, sizeof(count), &mm->mmap_lock.count.counter) ||
	    !(count & TASK_STACKS_RWSEM_BUSY))
		return 0;
	look->cut = 1;
	return 1;
}

/* bpf_copy_from_user_task(), but for a busy lock: fails as the helper fails,
 * with the destination zeroed (a read of NULL does that), so that what counts
 * a failed read counts this one too. */
static __always_inline long copy_unless_busy(void *dst, u32 size,
					     const void *ptr,
					     struct task_struct *task, u64 flags)
{
	if (task_stacks_lock_busy()) {
		bpf_probe_read_kernel(dst, size, NULL);
		return -16; /* -EBUSY */
	}
	return bpf_copy_from_user_task(dst, size, ptr, task, flags);
}

#define bpf_copy_from_user_task copy_unless_busy

#ifdef __aarch64__
/* The unwinder's lookup on arm64 comes before its read of a frame, and gives
 * up by itself at a busy lock, with nothing to say so: look first, so that the
 * record is cut like any other. */
static __always_inline long find_vma_unless_busy(struct task_struct *task,
						 u64 addr, void *callback,
						 void *ctx, u64 flags)
{
	if (task_stacks_lock_busy())
		return -16; /* -EBUSY */
	return bpf_find_vma(task, addr, callback, ctx, flags);
}

#define bpf_find_vma find_vma_unless_busy
#endif

/*
 * pystacks, unmodified, as part of this compilation unit: the define above
 * selects the sleepable bodies of its task and read helpers (which it pulls in
 * as .c files itself, for the same reason). One unit, so nothing here crosses
 * a link: its __hidden functions, its maps and `zero` are simply in scope.
 */
#include "pystacks.bpf.c"

#include "systing_shared.bpf.h"
#include "task_stack_unwinder.bpf.h"

/*
 * --include-task-context: the reader of a thread's task_context, compiled for
 * another task's memory (the header says how). Its maps are the main
 * object's, reused at load when the capture asks for the feature and not
 * created when it does not (TaskStacksIter::load_object).
 */
#include "task_context_reader.bpf.h"

#define TASK_STACKS_MAX_DEPTH 127

/* Which stacks to collect; set by userspace from the stack mode. Rodata, so
 * the verifier prunes the legs a run does not use. */
const volatile struct {
	u32 collect_kernel;
	u32 collect_user;
	u32 collect_python;
	/* May this object read another task's user memory: a user stack past
	 * its first frame, a thread's Python frames, its task context. 0 unless
	 * userspace sets it, and userspace sets it only where that is known to
	 * be safe (see remote_reads() in task_stacks_recorder.rs). With it 0 the
	 * unwinder and its bpf_find_vma() lookup on arm64 sit behind a branch on
	 * a frozen constant, so the verifier never walks them, and the Python
	 * walk and the task-context reader are never reached. What the verifier
	 * of a privileged load never walked the kernel does not keep runnable;
	 * from 6.8 on that includes global functions that nothing calls, which
	 * it no longer verifies. */
	u32 remote_user_reads;
} task_stacks_config = {0};

/*
 * Each thread's CPU time and state as of its last full record, keyed by tid:
 * the deltas a record carries are against these, and a thread that matches
 * them is unchanged (see status_delta()). LRU so it never fills; a thread
 * evicted from it starts over with a full record and zero deltas. An iteration
 * touches every targeted thread once, in pid order, which is an LRU's worst
 * case: with more targeted threads than entries nearly every lookup misses,
 * so every thread is walked every time and every delta is zero. So userspace
 * sizes it to the host's threads before the load (task_status_entries() in
 * task_stacks_recorder.rs); what is declared here is the least it gets.
 */
struct task_status {
	u64 utime;
	u64 stime;
	u64 runtime;	/* se.sum_exec_runtime: ns on a CPU, exact */
	u32 state;
	u16 on_cpu;	/* read while the thread was on a CPU */
	u16 cut;	/* its record was cut short at a busy lock */
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, u32);
	__type(value, struct task_status);
} task_status SEC(".maps");

/* task_stacks_event.flags */
#define TASK_STACKS_UNCHANGED 1	/* the thread's last record still stands */
#define TASK_STACKS_IN_IOWAIT 2	/* blocked on I/O (task_struct.in_iowait) */
#define TASK_STACKS_USER_CUT 4	/* its lock was busy: see task_stacks_look */
#define TASK_STACKS_USER_OFF_STACK 8	/* a frame pointer left the thread's stack */

struct task_stacks_event {
	struct task_info task;
	u64 utime_delta;	/* ns of user time since the last full record */
	u64 stime_delta;	/* ns of system time since the last full record */
	u64 runtime_delta;	/* ns on a CPU since then: exact, those two tick */
	u32 state;		/* __state | exit_state */
	u32 flags;		/* TASK_STACKS_* */
	u32 kernel_stack_len;	/* frames that follow the event */
	u32 user_stack_len;	/* frames that follow the kernel frames */
	u32 py_len;		/* bytes of pystacks_message after the frames */
	s32 syscall_nr;		/* the system call the thread is in; -1 = none */
	u64 task_context_id;	/* the thread's task_context id; 0 = none */
};

/* Exposes the record type to the generated skeleton. */
struct task_stacks_event _task_stacks_event = {0};

struct task_stacks_scratch {
	struct task_stacks_event event;
	u64 kernel_stack[TASK_STACKS_MAX_DEPTH];
	u64 user_stack[TASK_STACKS_MAX_DEPTH];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct task_stacks_scratch);
} task_stacks_scratch SEC(".maps");

/*
 * What the walks cost: every task the capture's links handed the program, and
 * of those the ones in the target set. A walk scoped to the targets visits
 * little more than it records; the walk over the whole host visits every
 * thread there is to record a few. Userspace reads the pair for its closing
 * note, and the tests to tell which walk ran. One slot, and one reader of the
 * capture's links at a time, so the adds never contend.
 *
 * group_threads is how userspace tells a walk of one process that the kernel
 * cut short. A walk scoped to a process has no cursor in its thread list: to
 * advance, the iterator looks the thread it last handed over up again by pid,
 * and if that thread has exited meanwhile -- it may, while this program is
 * unwinding it -- the walk ends there and the threads behind it are not
 * visited. (The walk over every thread steps to the next pid that exists and
 * has no such window.) So the program notes how many threads the group it has
 * just entered has, userspace sets that against the threads its read visited
 * -- the runs less the ones whose record did not fit the seq buffer, which the
 * kernel hands over again -- and reads a process that came up short once more.
 */
struct task_stacks_walk_stats {
	u64 visited;
	u64 targeted;
	u64 unsent;
	u64 group_threads;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct task_stacks_walk_stats);
} task_stacks_walk_stats SEC(".maps");

static __always_inline void read_status(struct task_struct *task, bool on_cpu,
					struct task_status *now)
{
	now->utime = BPF_CORE_READ(task, utime);
	now->stime = BPF_CORE_READ(task, stime);
	now->runtime = BPF_CORE_READ(task, se.sum_exec_runtime);
	now->state = get_task_state(task);
	now->on_cpu = on_cpu;
	now->cut = 0;
}

/*
 * Fill the event's state and its CPU-time deltas against the thread's last
 * full record (zero the first time a thread is seen), and return whether the
 * thread is unchanged since then: it has not been on a CPU, and it is in the
 * state it was in. A thread changes its stacks only by running, whether it is
 * blocked or waits for a CPU; so its last record, stacks included, still
 * describes it, and the walk can be skipped.
 *
 * "Has not been on a CPU" is se.sum_exec_runtime standing still. utime and
 * stime are what the record reports, but they advance by scheduler ticks: a
 * thread that wakes, moves to another stack and blocks again between two
 * ticks leaves them as they were. The scheduler's own runtime is in
 * nanoseconds, and settled by the time a thread is off its CPU.
 *
 * Not before: a thread that is about to block sets its state first, and its
 * runtime is brought up to date as it is switched out. In between it reads as
 * asleep with the runtime of before it ran. So a thread that is on a CPU is
 * never unchanged, whatever its state says; on_cpu is cleared after the
 * switch-out's update, which is why the caller reads it before the status.
 * Nor is a thread whose last record was read on a CPU: that is a best effort,
 * with no kernel frames and no system call, and a thread caught between the
 * update and the clearing has the counters it will go on having.
 * The two reads are helper calls, which the compiler keeps in order, and
 * x86-64 keeps loads in order; arm64 may not, but the runtime load would have
 * to pass the whole switch-out, a microsecond, to see the old value.
 *
 * Unchanged is the counters being EQUAL to the baseline's, not the deltas
 * being zero: the deltas are clamped, so they are zero for counters below the
 * baseline's too. A thread's own never go back, but nothing removes a dead
 * thread's baseline, and a new thread that is handed its tid starts from zero
 * under it: it would read unchanged until it had run for longer than the dead
 * one. As it is, it gets a full record, with one clamped delta. The one exception
 * takes a wrap of pid_max within a capture: a baseline read before its thread
 * first ran, and a new thread on that tid that has not run yet either.
 *
 * What a thread's last record says of its stacks does not stand if a busy lock
 * cut it short. Such a thread is walked again once the lock is free; as long
 * as it is busy the thread is unchanged like any other, so that one long hold
 * is one short event and no reads. The record that comes after has the event's
 * whole stack and deltas of zero, the time before it being in the short one.
 */
static bool status_delta(u32 tid, const struct task_status *now, bool on_cpu,
			 struct task_stacks_event *e)
{
	struct task_status *prev = bpf_map_lookup_elem(&task_status, &tid);

	e->state = now->state;
	e->utime_delta = 0;
	e->stime_delta = 0;
	e->runtime_delta = 0;
	if (!prev)
		return false;
	if (now->utime > prev->utime)
		e->utime_delta = now->utime - prev->utime;
	if (now->stime > prev->stime)
		e->stime_delta = now->stime - prev->stime;
	if (now->runtime > prev->runtime)
		e->runtime_delta = now->runtime - prev->runtime;
	return !on_cpu && !prev->on_cpu && now->runtime == prev->runtime &&
	       now->utime == prev->utime && now->stime == prev->stime &&
	       now->state == prev->state &&
	       (!prev->cut || task_stacks_lock_busy());
}

/*
 * The system call thread `task` is in, by its number in the kernel's native
 * table, or -1 for none: what tells a thread parked in epoll_wait, futex or
 * nanosleep from one blocked in a read. It is read from the thread's saved
 * user registers, which are as its last entry into the kernel left them, and
 * every entry that is not a system call (an interrupt, a fault) leaves the
 * "no system call" mark there: -1 in orig_ax on x86-64 and in syscallno on
 * arm64. riscv has no such mark; its saved cause says which entry it was.
 *
 * So the number is exact for a thread that is off its CPU, blocked or
 * preempted, and for one that is still on it with its state already set to
 * sleep: a thread sets that only in the kernel, on its way to schedule(), so
 * its registers are this entry's. A thread that is on a CPU and runnable may
 * be back in user space, where the registers still hold the entry before: it
 * reads as in none (as does one that is in the kernel there). `on_cpu` is
 * read for this after the state, not the caller's earlier read: a thread that
 * left its CPU in between would have the state of its sleep and no call,
 * and keep both for as long as it slept.
 *
 * None either, sooner than a number that is not the thread's call:
 *  - a thread that has exited: its stack, and the registers on it, may be
 *    freed, and a failed read is zero, which is a call's number;
 *  - a kernel thread, which has no user registers, and an io_uring or vhost
 *    worker, which has a copy of those of the thread that made it;
 *  - a 32-bit task, whose number is one of another table (see
 *    systing_in_compat_syscall() in systing_system.bpf.c for the three
 *    tests), and an x32 call, whose number carries __X32_SYSCALL_BIT.
 */
#define TASK_STACKS_NO_SYSCALL (-1)
#define TASK_STACKS_PF_IO_WORKER 0x00000010   /* include/linux/sched.h */
#define TASK_STACKS_PF_USER_WORKER 0x00004000 /* a hole before Linux 6.4 */

#if defined(__TARGET_ARCH_x86)
#define TASK_STACKS_TS_COMPAT 0x0002 /* arch/x86/include/asm/thread_info.h */
#define TASK_STACKS_X32_SYSCALL_BIT 0x40000000 /* arch/x86/include/uapi/asm/unistd.h */
#elif defined(__TARGET_ARCH_arm64)
#define TASK_STACKS_TIF_32BIT_MASK (1UL << 22) /* arch/arm64/include/asm/thread_info.h */
#elif defined(__TARGET_ARCH_riscv)
#define TASK_STACKS_EXC_SYSCALL 8 /* arch/riscv/include/asm/csr.h */
#define TASK_STACKS_SR_UXL 0x300000000UL
#define TASK_STACKS_SR_UXL_32 0x100000000UL
#endif

static __always_inline s32 task_syscall_nr(struct task_struct *task, u32 state)
{
	struct pt_regs *regs;
	bool on_cpu;

	if (BPF_CORE_READ(task, exit_state) || is_kernel_thread(task) ||
	    (BPF_CORE_READ(task, flags) &
	     (TASK_STACKS_PF_IO_WORKER | TASK_STACKS_PF_USER_WORKER)))
		return TASK_STACKS_NO_SYSCALL;
	on_cpu = bpf_core_field_exists(task->on_cpu) ?
			 BPF_CORE_READ(task, on_cpu) : 0;
	/* TASK_RUNNING is 0. */
	if (on_cpu && !state)
		return TASK_STACKS_NO_SYSCALL;
	regs = (struct pt_regs *)bpf_task_pt_regs(task);
#if defined(__TARGET_ARCH_x86)
	unsigned long nr;

	if (BPF_CORE_READ(task, thread_info.status) & TASK_STACKS_TS_COMPAT)
		return TASK_STACKS_NO_SYSCALL;
	if (bpf_core_read(&nr, sizeof(nr), &regs->orig_ax) ||
	    (nr & TASK_STACKS_X32_SYSCALL_BIT))
		return TASK_STACKS_NO_SYSCALL;
	return (s32)nr;
#elif defined(__TARGET_ARCH_arm64)
	s32 nr;

	if (BPF_CORE_READ(task, thread_info.flags) & TASK_STACKS_TIF_32BIT_MASK)
		return TASK_STACKS_NO_SYSCALL;
	if (bpf_core_read(&nr, sizeof(nr), &regs->syscallno))
		return TASK_STACKS_NO_SYSCALL;
	return nr;
#elif defined(__TARGET_ARCH_riscv)
	unsigned long cause, status, nr;

	if (bpf_core_read(&cause, sizeof(cause), &regs->cause) ||
	    bpf_core_read(&status, sizeof(status), &regs->status) ||
	    bpf_core_read(&nr, sizeof(nr), &regs->a7))
		return TASK_STACKS_NO_SYSCALL;
	if (cause != TASK_STACKS_EXC_SYSCALL ||
	    (status & TASK_STACKS_SR_UXL) == TASK_STACKS_SR_UXL_32)
		return TASK_STACKS_NO_SYSCALL;
	return (s32)nr;
#else
	return TASK_STACKS_NO_SYSCALL;
#endif
}

/*
 * How this file keeps the verifier's work down. All of it is pystacks.bpf.c's
 * own practice (see pystacks_get_frame_data() and
 * pystacks_read_stacks_global() there).
 *
 *  - The legs that loop are global functions: neither static nor __hidden.
 *    The verifier checks a global function once, on its own, with unknown
 *    arguments; at a call to one it checks the arguments and moves on. A
 *    static function it walks again on every path into every call. The
 *    Python walk costs ~410K of the 1M-instruction budget however it is
 *    called, so it has to be walked exactly once: inlined into the iterator
 *    program, one branch ahead of it doubles it.
 *  - A global function takes scalars. It cannot be handed the iterator's
 *    trusted task pointer (before __arg_trusted, 6.8), so each takes the tid
 *    and re-acquires the thread with get_task(), releasing it with
 *    put_task(): in a sleepable build those are bpf_task_from_pid() and
 *    bpf_task_release(). The lookup is by number: were the thread to exit and
 *    its tid be handed to a new one in between, that one would be walked. Pid
 *    allocation is cyclic, so that takes a wrap of pid_max within the record.
 *  - Nor is it handed its buffers. Each fetches the per-CPU scratch itself
 *    with get_scratch(), as pystacks does with get_state(); a sleepable
 *    program cannot migrate, so every leg of one record sees the same slot.
 *  - pystacks' message is fetched the same way, by looking pystacks_msg_heap
 *    up. pystacks_get_msg() would do, but only for as long as the compiler
 *    inlines it: it is a global function that returns a pointer, which the
 *    verifier refuses as a call.
 *  - Each global function starts with its own rodata gate. Kernels before 6.8
 *    verify every global function in the program, called or not; the gate
 *    makes a leg that is off cost a few instructions there too.
 */
static __always_inline struct task_stacks_scratch *get_scratch(void)
{
	return bpf_map_lookup_elem(&task_stacks_scratch, &zero);
}

static __always_inline struct pystacks_message *get_py_msg(void)
{
	return bpf_map_lookup_elem(&pystacks_msg_heap, &zero);
}

/*
 * min(n, max), for a length the verifier must see bounded. What a global
 * function returns is a wholly unknown scalar to its caller; the barrier keeps
 * the compiler from range-checking one copy of it and using another.
 */
static __always_inline u32 bounded(u32 n, u32 max)
{
	barrier_var(n);
	return n > max ? max : n;
}

/*
 * The most a stack can reach above a thread's stack pointer and still be told
 * by what lies above it (8 MiB, the usual limit of a stack), and what is allowed
 * to a stack nothing tells the end of.
 */
#define TASK_STACKS_TOP_WINDOW (8ULL << 20)
#define TASK_STACKS_UNKNOWN_TOP (1ULL << 20)

/*
 * An address no frame of `task`'s user stack reaches, for the unwinder.
 *
 * A C library puts a thread's descriptor, which is what its thread pointer
 * points at, at the top of the mapping of the thread's stack, so that is the
 * top of a thread's stack where the pointer lies a stack's reach above sp.
 * Where it lies there and is something else, as on a stack the thread was
 * handed or under Go without cgo, nothing is cut: the limit is only further up.
 * A main thread's descriptor is elsewhere, and its stack ends where exec left
 * it. What is left has only so much above sp: goroutines and fibers, stacks
 * past the window. Honest frames that lie on another stack from sp's are lost
 * to this: the frames of the goroutine beneath cgo or systemstack, and those
 * beneath a signal handler on an alternate stack.
 */
static __always_inline u64 task_stacks_user_top(struct task_struct *task, u64 sp)
{
	u64 tp = task_context_thread_pointer(task);
	u64 start;

	if (tp > sp && tp - sp <= TASK_STACKS_TOP_WINDOW)
		return tp;
	if (task->pid == task->tgid) {
		start = BPF_CORE_READ(task, mm, start_stack);
		if (start > sp && start - sp <= TASK_STACKS_TOP_WINDOW)
			return start;
	}
	return sp + TASK_STACKS_UNKNOWN_TOP;
}

/*
 * Thread `tid`'s user stack into the scratch, by frame pointers (see
 * task_stack_unwinder.bpf.h: bpf_get_task_stack() reads a user stack only for
 * the current task). Returns the number of frames.
 *
 * Where the object may not read another task's memory (remote_user_reads is
 * 0) the stack is its first frame alone: what the unwinder itself stores
 * before its first read, and what it returns for a thread whose walk stops
 * at once.
 */
__noinline int task_stacks_read_user(pid_t tid)
{
	struct task_stacks_scratch *s = get_scratch();
	struct task_struct *task;
	int n;

	if (!task_stacks_config.collect_user || !s)
		return 0;
	if (get_task(tid, &task))
		return 0;
	if (task_stacks_config.remote_user_reads) {
		struct pt_regs *regs = (struct pt_regs *)bpf_task_pt_regs(task);
		struct task_stacks_look *look = get_look();
		bool refused = false;

		n = unwind_user_stack_task(task, s->user_stack,
					   TASK_STACKS_MAX_DEPTH,
					   task_stacks_user_top(task, PT_REGS_SP(regs)),
					   &refused);
		if (look)
			look->off_stack = refused;
	} else {
		/* Where the thread was interrupted, from its saved registers.
		 * Nothing of the task's own memory is read, and on arm64 the
		 * lookup that guards such a read is not called. */
		struct pt_regs *regs = (struct pt_regs *)bpf_task_pt_regs(task);

		s->user_stack[0] = PT_REGS_IP(regs);
		n = 1;
	}
	put_task(task);
	return n;
}

/*
 * Thread `tid`'s Python stack into pystacks' message. Returns the bytes of
 * the message worth emitting, its header and the frames it holds; 0 when the
 * thread is not a targeted Python process's or has no Python frames.
 *
 * This is pystacks_read_stacks_global() keyed by tid. That one, and so
 * pystacks' public entry pystacks_read_stacks(), re-acquires the task by tgid:
 * in a sleepable build it walks the process's main thread whichever thread
 * it was asked about.
 */
__noinline int task_stacks_read_python(pid_t tid)
{
	struct pystacks_message *py;
	struct task_struct *task;
	pid_t tgid;
	int ret = 0;
	u64 len;

	/* remote_user_reads is tested here as well as at the call: below 6.8 a
	 * global function is verified on its own (see task_stacks_config). */
	if (!task_stacks_config.collect_python ||
	    !task_stacks_config.remote_user_reads)
		return 0;
	if (get_task(tid, &task))
		return 0;
	tgid = task->tgid;
	if (profile_pid_task(tgid, task))
		ret = pystacks_read_stacks_task(
			(struct pt_regs *)bpf_task_pt_regs(task), tgid, task);
	put_task(task);
	if (ret <= 0)
		return 0;

	py = get_py_msg();
	if (!py)
		return 0;
	len = py->stack_len;
	if (!len)
		return 0;
	if (len > BPF_LIB_MAX_STACK_DEPTH)
		len = BPF_LIB_MAX_STACK_DEPTH;
	return offsetof(struct pystacks_message, buffer) +
	       len * sizeof(struct stack_walker_frame);
}

/*
 * Thread `tid`'s task_context id, or 0 for none (--include-task-context; the
 * reader is task_context_read_task() in task_context_reader.bpf.h, which
 * counts every miss under its reason). Sends the values of a new id on the
 * main object's values ring, as the sampler does.
 */
__noinline u64 task_stacks_read_context(pid_t tid)
{
	struct task_struct *task;
	u64 id;

	/* remote_user_reads is tested here as well as at the call: below 6.8 a
	 * global function is verified on its own (see task_stacks_config). */
	if (!task_context_config.enabled ||
	    !task_stacks_config.remote_user_reads)
		return 0;
	if (get_task(tid, &task))
		return 0;
	id = task_context_read_task(task);
	put_task(task);
	return id;
}

/*
 * task_in_target_set() for the task the iterator hands the program.
 *
 * The kernel's --cgroup test, bpf_task_under_cgroup(), takes a task the
 * verifier holds to be trusted. A task iterator's task is that from Linux 6.7
 * on; a 6.5 or 6.6 verifier refuses the call on it ("R1 must be a rcu
 * pointer"), and with it the whole program. So for that test the thread is
 * acquired by its tid, as the legs above acquire it: what bpf_task_from_pid()
 * returns is trusted on every kernel that has the test. One lookup more per
 * thread such a capture's walk visits, on every kernel, so that one program
 * loads on all of them. By number, as above; and a thread that has been
 * reaped since the iterator took it has no tid to be found by: it is in no
 * target set, and the legs above would have found nothing of it either.
 */
static __always_inline bool iter_task_in_target_set(struct task_struct *task)
{
	struct task_struct *held;
	bool hit;

	if (!task_in_target_pids(task))
		return false;
	if (!target_filter.filter_cgroup)
		return true;
	if (!target_filter.cgroup_match_kernel)
		return task_in_legacy_cgroup_set(task);
	if (get_task(task->pid, &held))
		return false;
	hit = task_in_cgroup_filter(held);
	put_task(held);
	return hit;
}

SEC("iter.s/task")
int systing_task_stacks(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	struct task_stacks_walk_stats *stats;
	struct task_stacks_scratch *s;
	struct task_stacks_look *look;
	struct pystacks_message *py;
	struct task_stacks_event *e;
	u32 klen = 0, ulen = 0, py_len = 0;
	struct task_status now;
	bool on_cpu;
	long err;
	u32 tid;

	/* NULL once, after the last task. */
	if (!task)
		return 0;
	/* Runs of the program, so a task whose record did not fit the seq
	 * buffer and is handed over again counts again: it cost again. */
	stats = bpf_map_lookup_elem(&task_stacks_walk_stats, &zero);
	if (stats) {
		__sync_fetch_and_add(&stats->visited, 1);
		/* A group leader: the first task a walk scoped to a process is
		 * handed, so what this holds when that read ends is that
		 * process's thread count. */
		if (task->pid == task->tgid)
			stats->group_threads = task->signal->nr_threads;
	}
	/* The iterator runs in the reader's context: skip systing itself. */
	if (task->tgid == bpf_get_current_pid_tgid() >> 32)
		return 0;
	/* Whatever the link covers: a walk scoped to the targets narrows what
	 * is visited, never what is recorded. */
	if (!iter_task_in_target_set(task))
		return 0;
	if (stats)
		__sync_fetch_and_add(&stats->targeted, 1);
	s = get_scratch();
	if (!s)
		return 0;
	e = &s->event;
	tid = task->pid;

	e->task.tgidpid = ((u64)task->tgid << 32) | tid;
	e->task.cgid = task_cg_id(task);
	__builtin_memset(e->task.comm, 0, sizeof(e->task.comm));
	bpf_probe_read_kernel_str(e->task.comm, sizeof(e->task.comm), task->comm);
	e->flags = 0;
	e->syscall_nr = TASK_STACKS_NO_SYSCALL;
	e->task_context_id = 0;

	look = get_look();
	if (!look)
		return 0;
	look->mm = task_stacks_config.remote_user_reads ?
			   (u64)BPF_CORE_READ(task, mm) : 0;
	look->cut = 0;
	look->off_stack = 0;

	/* Before the status, not after: see status_delta(). A uniprocessor
	 * kernel has no on_cpu, nor a CPU for the thread to be on but ours. */
	on_cpu = bpf_core_field_exists(task->on_cpu) ?
			 BPF_CORE_READ(task, on_cpu) : 0;
	read_status(task, on_cpu, &now);
	if (status_delta(tid, &now, on_cpu, e)) {
		/* The header alone: userspace extends the thread's last record
		 * to this iteration. A thread it hears nothing of has gone. */
		e->flags = TASK_STACKS_UNCHANGED;
		if (look->cut)
			e->flags |= TASK_STACKS_USER_CUT;
		e->kernel_stack_len = 0;
		e->user_stack_len = 0;
		e->py_len = 0;
		err = bpf_seq_write(seq, e, sizeof(*e));
		if (err && stats)
			__sync_fetch_and_add(&stats->unsent, 1);
		return 0;
	}

	/* What the thread waits in, where it waits: both of the kernel's own
	 * record, with nothing of the thread's memory read. */
	e->syscall_nr = task_syscall_nr(task, now.state);
	if (BPF_CORE_READ_BITFIELD_PROBED(task, in_iowait))
		e->flags |= TASK_STACKS_IN_IOWAIT;

	/* One helper call on the trusted pointer: nothing to gain from a
	 * global function here. */
	if (task_stacks_config.collect_kernel) {
		long n = bpf_get_task_stack(task, s->kernel_stack,
					    sizeof(s->kernel_stack), 0);
		if (n > 0)
			klen = n / sizeof(u64);
	}
	if (task_stacks_config.collect_user && !is_kernel_thread(task))
		ulen = task_stacks_read_user(tid);
	/* Both read another task's memory and nothing else: off with it. */
	if (task_stacks_config.collect_python &&
	    task_stacks_config.remote_user_reads)
		py_len = task_stacks_read_python(tid);
	if (task_context_config.enabled &&
	    task_stacks_config.remote_user_reads)
		e->task_context_id = task_stacks_read_context(tid);
	if (look->cut) {
		e->flags |= TASK_STACKS_USER_CUT;
		now.cut = 1;
	}
	if (look->off_stack)
		e->flags |= TASK_STACKS_USER_OFF_STACK;

	klen = bounded(klen, TASK_STACKS_MAX_DEPTH);
	ulen = bounded(ulen, TASK_STACKS_MAX_DEPTH);
	py_len = bounded(py_len, sizeof(struct pystacks_message));
	py = py_len ? get_py_msg() : NULL;
	e->kernel_stack_len = klen;
	e->user_stack_len = ulen;
	e->py_len = py ? py_len : 0;

	err = bpf_seq_write(seq, e, sizeof(*e));
	err |= bpf_seq_write(seq, s->kernel_stack, klen * sizeof(u64));
	err |= bpf_seq_write(seq, s->user_stack, ulen * sizeof(u64));
	/*
	 * Bounded once more, at the call. py_len has to outlive the calls above,
	 * and the compiler may keep it in a 4-byte stack slot it filled before
	 * the bound was tested. An older verifier (6.6.97's; not 6.6.157's, nor
	 * 6.12's) carries a tested bound to the registers that hold the value
	 * and not to a stack slot narrower than a register, so what is read back
	 * from the slot is any u32 to it ("R3 unbounded memory access").
	 */
	if (py)
		err |= bpf_seq_write(seq, py, bounded(py_len, sizeof(*py)));
	/*
	 * The status becomes the thread's baseline only once its record is out.
	 * When the seq buffer fills, the kernel drops what this call wrote and
	 * runs the program again for the same thread on the next read(2); had
	 * the first run moved the baseline, the second would find the thread
	 * unchanged and its new stacks would never be sent.
	 */
	if (!err)
		bpf_map_update_elem(&task_status, &tid, &now, BPF_ANY);
	else if (stats)
		__sync_fetch_and_add(&stats->unsent, 1);
	return 0;
}

/*
 * The processes of a cgroup, for the walk scoped to --cgroup targets: a cgroup
 * iterator that userspace attaches to a target's directory, the cgroups below
 * it included, and reads once per snapshot. For each cgroup it visits it
 * writes the tgid of each process in it (u32 each), which the kernel hands
 * over with the css_task open-coded iterator (Linux 6.7). Userspace then walks
 * each of those processes with a link of the task iterator above scoped to it.
 *
 * It lists and does no more, for two reasons of the kernel's. A cgroup
 * iterator's program runs with cgroup_mutex held: every cgroup operation on
 * the host waits for it, so it must not unwind stacks there. And a cgroup
 * iterator has one read session, which the kernel ends once what the program
 * has written reaches either of two lengths: the iterator's seq buffer, eight
 * pages and never grown, or the length the read asked for. All it writes, for
 * the target and every cgroup below it, has to come under both, so userspace
 * asks for the seq buffer's length at every read and the buffer is the one that
 * binds. One cgroup's output over it fails the read with E2BIG, several
 * cgroups' with EOPNOTSUPP once the first buffer has been read. On 4K pages
 * the tgids of 8191 processes under one target fit it (a write needs room for
 * a byte more than it writes); the records of a dozen threads with deep stacks
 * fill it. A read that fails is a snapshot that walks every thread instead.
 *
 * "?": loaded only where userspace asks for it, which it does where the
 * kernel has the css_task iterator and the capture is one it is for. Elsewhere
 * the object loads without it and the capture walks every thread, as before.
 * The kfuncs are weak in vmlinux.h, so their absence is no relocation error.
 */
SEC("?iter/cgroup")
int systing_task_stacks_members(struct bpf_iter__cgroup *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct cgroup *cgrp = ctx->cgroup;
	struct cgroup_subsys_state *css;
	struct task_struct *task;

	/* NULL once, after the last cgroup. */
	if (!cgrp)
		return 0;
	css = &cgrp->self;
	bpf_for_each(css_task, task, css, CSS_TASK_ITER_PROCS) {
		u32 tgid = task->tgid;

		bpf_seq_write(seq, &tgid, sizeof(tgid));
	}
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
