// SPDX-License-Identifier: GPL-2.0
/*
 * task-stacks recorder: a sleepable BPF task iterator. Userspace reads one
 * seq file from the iterator link per iteration; the program runs once per
 * thread on the host, in the process context of that read(2), and writes one
 * variable-length record per targeted thread: struct task_stacks_event, then
 * kernel_stack_len kernel frames, user_stack_len user frames (u64 each, leaf
 * first) and py_len bytes of struct pystacks_message. A thread that has not run
 * since its last record gets the header alone, flagged TASK_STACKS_UNCHANGED.
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
 * pystacks, unmodified, as part of this compilation unit: the define above
 * selects the sleepable bodies of its task and read helpers (which it pulls in
 * as .c files itself, for the same reason). One unit, so nothing here crosses
 * a link: its __hidden functions, its maps and `zero` are simply in scope.
 */
#include "pystacks.bpf.c"

#include "systing_shared.bpf.h"
#include "task_stack_unwinder.bpf.h"

#define TASK_STACKS_MAX_DEPTH 127

/* Which stacks to collect; set by userspace from the stack mode. Rodata, so
 * the verifier prunes the legs a run does not use. */
const volatile struct {
	u32 collect_kernel;
	u32 collect_user;
	u32 collect_python;
} task_stacks_config = {0};

/*
 * Each thread's CPU time and state as of its last full record, keyed by tid:
 * the deltas a record carries are against these, and a thread that matches
 * them is unchanged (see status_delta()). LRU so it never fills; a thread
 * evicted from it starts over with a full record and zero deltas.
 */
struct task_status {
	u64 utime;
	u64 stime;
	u64 runtime;	/* se.sum_exec_runtime: ns on a CPU, exact */
	u32 state;
	u32 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, u32);
	__type(value, struct task_status);
} task_status SEC(".maps");

/* task_stacks_event.flags */
#define TASK_STACKS_UNCHANGED 1	/* the thread's last record still stands */

struct task_stacks_event {
	struct task_info task;
	u64 utime_delta;	/* ns of user time since the last full record */
	u64 stime_delta;	/* ns of system time since the last full record */
	u32 state;		/* __state | exit_state */
	u32 flags;		/* TASK_STACKS_* */
	u32 kernel_stack_len;	/* frames that follow the event */
	u32 user_stack_len;	/* frames that follow the kernel frames */
	u32 py_len;		/* bytes of pystacks_message after the frames */
	u32 pad;
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

static __always_inline void read_status(struct task_struct *task,
					struct task_status *now)
{
	now->utime = BPF_CORE_READ(task, utime);
	now->stime = BPF_CORE_READ(task, stime);
	now->runtime = BPF_CORE_READ(task, se.sum_exec_runtime);
	now->state = get_task_state(task);
	now->pad = 0;
}

/*
 * Fill the event's state and its CPU-time deltas against the thread's last
 * full record (zero the first time a thread is seen), and return whether the
 * thread is unchanged since then: it has not been on a CPU, and it is, as it
 * was, in one and the same state other than runnable. A thread that is not
 * runnable changes its stacks only by running; so its last record, stacks
 * included, still describes it, and the walk can be skipped.
 *
 * "Has not been on a CPU" is se.sum_exec_runtime standing still. utime and
 * stime are what the record reports, but they advance by scheduler ticks: a
 * thread that wakes, moves to another stack and blocks again between two
 * ticks leaves them as they were. The scheduler's own runtime is in
 * nanoseconds, and settled by the time a thread has blocked.
 */
static bool status_delta(u32 tid, const struct task_status *now,
			 struct task_stacks_event *e)
{
	struct task_status *prev = bpf_map_lookup_elem(&task_status, &tid);

	e->state = now->state;
	e->utime_delta = 0;
	e->stime_delta = 0;
	if (!prev)
		return false;
	if (now->utime > prev->utime)
		e->utime_delta = now->utime - prev->utime;
	if (now->stime > prev->stime)
		e->stime_delta = now->stime - prev->stime;
	/* TASK_RUNNING is 0: on a CPU, or waiting for one. */
	return now->runtime == prev->runtime && !e->utime_delta &&
	       !e->stime_delta && now->state && now->state == prev->state;
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
 *    bpf_task_release().
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
 * Thread `tid`'s user stack into the scratch, by frame pointers (see
 * task_stack_unwinder.bpf.h: bpf_get_task_stack() reads a user stack only for
 * the current task). Returns the number of frames.
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
	n = unwind_user_stack_task(task, s->user_stack, TASK_STACKS_MAX_DEPTH);
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

	if (!task_stacks_config.collect_python)
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

SEC("iter.s/task")
int systing_task_stacks(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	struct task_stacks_scratch *s;
	struct pystacks_message *py;
	struct task_stacks_event *e;
	u32 klen = 0, ulen = 0, py_len = 0;
	struct task_status now;
	long err;
	u32 tid;

	/* NULL once, after the last task. */
	if (!task)
		return 0;
	/* The iterator runs in the reader's context: skip systing itself. */
	if (task->tgid == bpf_get_current_pid_tgid() >> 32)
		return 0;
	if (!task_in_target_set(task))
		return 0;
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
	e->pad = 0;

	read_status(task, &now);
	if (status_delta(tid, &now, e)) {
		/* The header alone: userspace extends the thread's last record
		 * to this iteration. A thread it hears nothing of has gone. */
		e->flags = TASK_STACKS_UNCHANGED;
		e->kernel_stack_len = 0;
		e->user_stack_len = 0;
		e->py_len = 0;
		bpf_seq_write(seq, e, sizeof(*e));
		return 0;
	}

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
	if (task_stacks_config.collect_python)
		py_len = task_stacks_read_python(tid);

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
	if (py)
		err |= bpf_seq_write(seq, py, py_len);
	/*
	 * The status becomes the thread's baseline only once its record is out.
	 * When the seq buffer fills, the kernel drops what this call wrote and
	 * runs the program again for the same thread on the next read(2); had
	 * the first run moved the baseline, the second would find the thread
	 * unchanged and its new stacks would never be sent.
	 */
	if (!err)
		bpf_map_update_elem(&task_status, &tid, &now, BPF_ANY);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
