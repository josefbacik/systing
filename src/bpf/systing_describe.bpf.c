#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

const volatile struct {
	u32 tgid;
} tool_config = {};

#define PF_KTHREAD 0x00200000
#define MAX_STACK_DEPTH 24
#define SKIP_STACK_DEPTH 3
#define TASK_STATE_MASK 3

#define KERNEL_THREAD_STACK_STUB 1234
#define PREEMPT_EVENT_STACK_STUB 5678

struct wakee_stack {
	u64 start_ns;
	u64 kernel_stack[MAX_STACK_DEPTH];
	u64 user_stack[MAX_STACK_DEPTH];
};

struct wake_event {
	u64 waker_tgidpid;
	u64 wakee_tgidpid;
	u64 sleep_time_ns;
	u64 waker_kernel_stack[MAX_STACK_DEPTH];
	u64 wakee_kernel_stack[MAX_STACK_DEPTH];
	u64 waker_user_stack[MAX_STACK_DEPTH];
	u64 wakee_user_stack[MAX_STACK_DEPTH];
};

/*
 * Dummy instance to get skeleton to generate definition for
 * `struct wake_event` and `struct wakee_stack`.
 */
struct wake_event _event = {0};
struct wakee_stack _stack = {0};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct wakee_stack);
	__uint(max_entries, 10240);
} wakee SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 10 * 1024 * 1024 /* 10Mib */);
} events SEC(".maps");

SEC("tp_btf/sched_waking")
int handle__sched_wakup(u64 *ctx)
{
	/* TP_PROTO(struct task_struct *p) */
	struct task_struct *task = (struct task_struct *)ctx[0];
	struct task_struct *curtask = (struct task_struct *)bpf_get_current_task_btf();
	u64 pid = bpf_get_current_pid_tgid();
	u64 sleeper = (u64)task->tgid << 32 | task->pid;
	struct wakee_stack *value;
	struct wake_event *event;

	value = bpf_map_lookup_elem(&wakee, &sleeper);
	if (!value)
		return 0;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;

	event->waker_tgidpid = pid;
	event->wakee_tgidpid = sleeper;
	event->sleep_time_ns = bpf_ktime_get_ns() - value->start_ns;
	bpf_get_stack(ctx, &event->waker_kernel_stack, sizeof(event->waker_kernel_stack),
		      SKIP_STACK_DEPTH);
	if (!(curtask->flags & PF_KTHREAD))
		bpf_get_stack(ctx, &event->waker_user_stack,
			      sizeof(event->waker_user_stack), BPF_F_USER_STACK);
	else
		event->waker_user_stack[0] = KERNEL_THREAD_STACK_STUB;
	__builtin_memcpy(&event->wakee_kernel_stack, &value->kernel_stack,
			 sizeof(event->wakee_kernel_stack));
	__builtin_memcpy(&event->wakee_user_stack, &value->user_stack,
			 sizeof(event->wakee_user_stack));
	bpf_ringbuf_submit(event, 0);
	bpf_map_delete_elem(&wakee, &sleeper);
	return 0;
}

static void handle_preempt_event(struct task_struct *task)
{
	u64 key = (u64)task->tgid << 32 | task->pid;
	struct wakee_stack *value;
	struct wake_event *event;
	u64 delta = 0;

	if (tool_config.tgid && task->tgid != tool_config.tgid)
		return;

	value = bpf_map_lookup_elem(&wakee, &key);
	if (!value)
		return;

	delta = bpf_ktime_get_ns() - value->start_ns;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return;

	{
		const char *fmt = "preempted {}";
		bpf_trace_printk(fmt, sizeof(fmt), delta);
	}

	event->waker_tgidpid = 0;
	event->wakee_tgidpid = key;
	event->sleep_time_ns = delta;
	event->waker_kernel_stack[0] = PREEMPT_EVENT_STACK_STUB;
	event->waker_user_stack[0] = PREEMPT_EVENT_STACK_STUB;
	event->wakee_kernel_stack[0] = PREEMPT_EVENT_STACK_STUB;
	event->wakee_user_stack[0] = PREEMPT_EVENT_STACK_STUB;
	bpf_ringbuf_submit(event, 0);
	bpf_map_delete_elem(&wakee, &key);
}

SEC("tp_btf/sched_switch")
int handle__sched_switch(u64 *ctx)
{
	/*
	 * TP_PROTO(bool preempt, struct task_struct *prev,
	 *	    struct task_struct *next)
	 */
	struct task_struct *prev = (struct task_struct *)ctx[1];
	struct task_struct *next = (struct task_struct *)ctx[2];
	int prev_state = prev->__state & TASK_STATE_MASK;
	u64 key = (u64)prev->tgid << 32 | prev->pid;

	handle_preempt_event(next);

	if (tool_config.tgid && prev->tgid != tool_config.tgid)
		return 0;

	struct wakee_stack stack = {
		.start_ns = bpf_ktime_get_ns(),
	};
	bpf_get_stack(ctx, &stack.kernel_stack, sizeof(stack.kernel_stack),
		      SKIP_STACK_DEPTH);
	bpf_get_stack(ctx, &stack.user_stack, sizeof(stack.user_stack),
		      BPF_F_USER_STACK);
	bpf_map_update_elem(&wakee, &key, &stack, BPF_ANY);
	return 0;
}

SEC("perf_event")
int sample_process(void *ctx)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
	struct wake_event *event;

	if (tool_config.tgid && task->tgid != tool_config.tgid)
		return 0;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;

	event->waker_tgidpid = (u64)-1;
	event->wakee_tgidpid = (u64)task->tgid << 32 | task->pid;
	event->sleep_time_ns = 0;
	bpf_get_task_stack(task, &event->wakee_kernel_stack, sizeof(event->wakee_kernel_stack), SKIP_STACK_DEPTH);
	bpf_get_task_stack(task, &event->wakee_user_stack, sizeof(event->wakee_user_stack), BPF_F_USER_STACK);
	bpf_ringbuf_submit(event, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
