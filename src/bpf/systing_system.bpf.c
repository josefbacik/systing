#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#define TASK_RUNNING 0
#define TASK_INTERRUPTIBLE 1
#define TASK_UNINTERRUPTIBLE 2

/*
 * Used specifically to make sure we don't accidentally record stats for a value
 * we didn't catch at sched_waking time.
 */
#define TASK_WAKING 4567

#define TASK_STATE_MASK 3

#define TASK_COMM_LEN 16

const volatile struct {
	gid_t tgid;
	u32 filter_cgroup;
} tool_config = {};

enum event_type {
	EVENT_TASK_SLEEP,
	EVENT_TASK_WAKEUP,
	EVENT_TASK_RUN,
	EVENT_IRQ,
	EVENT_SOFTIRQ,
};

struct task_event {
	u64 ts;
	enum event_type type;
	u64 tgidpid;
	u64 cpu;

	/*
	 * For EVENT_WAKE_TASK, this is the CPU that the task was woken from.
	 */
	u64 waker_cpu;

	/*
	 * For EVENT_WAKE_TASK, this is the tgidpid of the waker.
	 */
	u64 waker_tgidpid;

	/*
	 * For EVENT_TASK_SLEEP, this is the state of the task.
	 * For EVENT_TASK_WAKEUP, this is wakeup TS.
	 * For EVENT_*IRQ, this is the start time of the event.
	 */
	u64 extra;
	u8 comm[TASK_COMM_LEN];
};

struct wake_event {
	u64 ts;
	u64 tgidpid;
	u64 cpu;
};

/*
 * Dummy instance to get skeleton to generate definition for
 * `struct task_event`
 */
struct task_event _event = {0};
enum event_type _event_type = EVENT_TASK_SLEEP;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, u8);
	__uint(max_entries, 10240);
} cgroups SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct wake_event);
	__uint(max_entries, 10240);
} wakeups SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, u64);
	__uint(max_entries, 10240);
} irq_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 10 * 1024 * 1024 /* 10Mib */);
} events SEC(".maps");

static __always_inline
u64 task_cg_id(struct task_struct *task)
{
	struct cgroup *cgrp = task->cgroups->dfl_cgrp;
	return cgrp->kn->id;
}

static __always_inline
u64 task_key(struct task_struct *task)
{
	return ((u64)task->tgid << 32) | task->pid;
}

static __always_inline
bool trace_task(struct task_struct *task)
{
	if (tool_config.tgid && task->tgid != tool_config.tgid)
		return false;
	if (task->tgid == 0)
		return false;
//	if (tool_config.filter_cgroup) {
//		u64 cgid = task_cg_id(task);
//		if (bpf_map_lookup_elem(&cgroups, &cgid) == NULL)
//			return false;
//	}
	return true;
}

static __always_inline
int trace_irq_enter(void)
{
	struct task_struct *tsk = (struct task_struct *)bpf_get_current_task_btf();
	u64 key = task_key(tsk);
	u64 start;
	u32 tgid = tsk->tgid;

	if (!trace_task(tsk))
		return 0;
	start = bpf_ktime_get_ns();
	bpf_map_update_elem(&irq_events, &key, &start, BPF_ANY);
	return 0;
}

static __always_inline
int trace_irq_exit(bool softirq)
{
	struct task_struct *tsk = (struct task_struct *)bpf_get_current_task_btf();
	struct task_stat *stat;
	u64 key = task_key(tsk);
	struct task_event *event;
	u64 *start_ns;

	start_ns = bpf_map_lookup_elem(&irq_events, &key);
	if (!start_ns)
		return 0;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;
	event->ts = bpf_ktime_get_ns();
	event->type = softirq ? EVENT_SOFTIRQ : EVENT_IRQ;
	event->tgidpid = key;
	event->cpu = bpf_get_smp_processor_id();
	event->extra = *start_ns;
	bpf_probe_read_kernel_str(event->comm, sizeof(event->comm), tsk->comm);
	bpf_ringbuf_submit(event, 0);
	bpf_map_delete_elem(&irq_events, &key);
	return 0;
}

SEC("tp_btf/sched_wakeup_new")
int handle__sched_wakeup_new(u64 *ctx)
{
	/* TP_PROTO(struct task_struct *p) */
	struct task_struct *task = (void *)ctx[0];
	struct task_struct *cur = (struct task_struct *)bpf_get_current_task_btf();

	if (!trace_task(cur))
		return 0;

	struct wake_event e = {
		.ts = bpf_ktime_get_ns(),
		.tgidpid = task_key(cur),
		.cpu = bpf_get_smp_processor_id(),
	};
	u64 key = task_key(task);
	bpf_map_update_elem(&wakeups, &key, &e, BPF_ANY);
	return 0;
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
	int next_state = next->__state & TASK_STATE_MASK;
	u64 key = task_key(prev);
	u64 ts = bpf_ktime_get_ns();
	struct task_event *event;

	if (trace_task(prev)) {
		event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
		if (!event)
			return 0;

		event->ts = ts;
		event->type = EVENT_TASK_SLEEP;
		event->tgidpid = task_key(prev);
		event->cpu = bpf_get_smp_processor_id();
		event->extra = prev_state;
		bpf_probe_read_kernel_str(event->comm, sizeof(event->comm),
					  prev->comm);
		bpf_ringbuf_submit(event, 0);
	}

	if (!trace_task(next))
		return 0;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;

	struct wake_event *value;
	key = task_key(next);
	value = bpf_map_lookup_elem(&wakeups, &key);
	if (value) {
		event->type = EVENT_TASK_WAKEUP;
		event->extra = value->ts;
		event->waker_cpu = value->cpu;
		event->waker_tgidpid = value->tgidpid;
		bpf_map_delete_elem(&wakeups, &key);
	} else {
		event->type = EVENT_TASK_RUN;
		event->extra = 0;
	}
	event->ts = ts;
	event->tgidpid = key;
	event->cpu = bpf_get_smp_processor_id();
	bpf_probe_read_kernel_str(event->comm, sizeof(event->comm), next->comm);
	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("tp_btf/sched_waking")
int handle__sched_waking(u64 *ctx)
{
	/* TP_PROTO(struct task_struct *p) */
	struct task_struct *task = (struct task_struct *)ctx[0];
	struct task_struct *cur = (struct task_struct *)bpf_get_current_task_btf();

	if (!trace_task(cur))
		return 0;

	struct wake_event e = {
		.ts = bpf_ktime_get_ns(),
		.tgidpid = task_key(cur),
		.cpu = bpf_get_smp_processor_id(),
	};
	u64 key = task_key(task);
	bpf_map_update_elem(&wakeups, &key, &e, BPF_ANY);
	return 0;
}

SEC("tp_btf/irq_handler_entry")
int handle__irq_handler_entry(u64 *ctx)
{
	/* TP_PROTO(int irq, struct irqaction *action) */
	return trace_irq_enter();
}

SEC("tp_btf/irq_handler_exit")
int handle__irq_handler_exit(u64 *ctx)
{
	/* TP_PROTO(int irq, struct irqaction *action, int ret) */
	return trace_irq_exit(false);
}

SEC("tp_btf/softirq_entry")
int handle__softirq_entry(u64 *ctx)
{
	/* TP_PROTO(unsigned int vec_nr) */
	return trace_irq_enter();
}

SEC("tp_btf/softirq_exit")
int handle__softirq_exit(u64 *ctx)
{
	/* TP_PROTO(unsigned int vec_nr) */
	return trace_irq_exit(true);
}

char LICENSE[] SEC("license") = "GPL";

