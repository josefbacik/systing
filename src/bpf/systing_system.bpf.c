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

#define PF_WQ_WORKER 0x00000020
#define PF_KTHREAD 0x00200000

#define MAX_STACK_DEPTH 36
#define SKIP_STACK_DEPTH 3
#define NR_RINGBUFS 8

const volatile struct {
	gid_t tgid;
	u32 filter_cgroup;
	u32 no_stack_traces;
} tool_config = {};

enum event_type {
	SCHED_SWITCH,
	SCHED_WAKING,
	SCHED_WAKEUP_NEW,
	SCHED_WAKEUP,
};

/*
 * sched_switch is the largest event, for the smaller events we just use prev_*
 * for the values, and things are left uninitialized.
 */
struct task_event {
	enum event_type type;
	u32 cpu;
	u64 ts;
	u64 latency;
	u64 prev_tgidpid;
	u64 next_tgidpid;
	u64 prev_state;
	u32 target_cpu;
	u32 next_prio;
	u32 prev_prio;
	u64 kernel_stack_length;
	u64 user_stack_length;
	u8 prev_comm[TASK_COMM_LEN];
	u8 next_comm[TASK_COMM_LEN];
	u64 kernel_stack[MAX_STACK_DEPTH];
	u64 user_stack[MAX_STACK_DEPTH];
};
/*
 * Dummy instance to get skeleton to generate definition for
 * `struct task_event`
 */
struct task_event _event = {0};
enum event_type _type = SCHED_SWITCH;
bool tracing_enabled = true;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, u64);
	__uint(max_entries, 10240);
} wake_ts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, u8);
	__uint(max_entries, 10240);
} cgroups SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, u64);
	__uint(max_entries, 10240);
} irq_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, 1);
} missed_events SEC(".maps");

struct ringbuf_map {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 50 * 1024 * 1024 /* 50Mib */);
} node0_events SEC(".maps"), node1_events SEC(".maps"), node2_events SEC(".maps"),
  node3_events SEC(".maps"), node4_events SEC(".maps"), node5_events SEC(".maps"),
  node6_events SEC(".maps"), node7_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, NR_RINGBUFS);
	__type(key, u32);
	__array(values, struct ringbuf_map);
} ringbufs SEC(".maps") = {
	.values = {
		&node0_events,
		&node1_events,
		&node2_events,
		&node3_events,
		&node4_events,
		&node5_events,
		&node6_events,
		&node7_events,
	},
};

static __always_inline
struct task_event *reserve_task_event(void)
{
	u32 node = (u32)bpf_get_numa_node_id() % NR_RINGBUFS;
	void *rb;

	rb = bpf_map_lookup_elem(&ringbufs, &node);
	if (!rb)
		return NULL;
	return bpf_ringbuf_reserve(rb, sizeof(struct task_event), 0);
}

static __always_inline
u32 task_cpu(struct task_struct *task)
{
	if (bpf_core_field_exists(task->thread_info)) {
		return task->thread_info.cpu;
	}
	struct thread_info *ti = task->stack;
	return ti->cpu;
}

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
	if (!tracing_enabled)
		return false;
	if (tool_config.tgid && task->tgid != tool_config.tgid)
		return false;
	if (task->tgid == 0)
		return false;
	if (tool_config.filter_cgroup) {
		u64 cgid = task_cg_id(task);
		if (bpf_map_lookup_elem(&cgroups, &cgid) == NULL)
			return false;
	}
	return true;
}

static __always_inline
int handle_missed_event(void)
{
	u32 index = 0;

	u64 *value = bpf_map_lookup_elem(&missed_events, &index);
	if (value)
		*value += 1;
	return 0;
}

static __always_inline
void record_task_name(struct task_struct *task, u8 *comm)
{
	if (task->flags & PF_WQ_WORKER) {
		struct kthread *k = bpf_core_cast(task->worker_private, struct kthread);
		struct worker *worker = bpf_core_cast(k->data, struct worker);

		bpf_probe_read_kernel_str(comm, TASK_COMM_LEN, worker->desc);
	} else {
		bpf_probe_read_kernel_str(comm, TASK_COMM_LEN, task->comm);
	}
}

static __always_inline
int trace_irq_enter(void)
{
	/*
	struct task_struct *tsk = (struct task_struct *)bpf_get_current_task_btf();
	u64 key = task_key(tsk);
	u64 start;
	u32 tgid = tsk->tgid;

	if (!trace_task(tsk))
		return 0;
	start = bpf_ktime_get_boot_ns();
	bpf_map_update_elem(&irq_events, &key, &start, BPF_ANY);
	*/
	return 0;
}

static __always_inline
int trace_irq_exit(bool softirq)
{
	/*
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
	event->ts = bpf_ktime_get_boot_ns();
	event->type = softirq ? EVENT_SOFTIRQ : EVENT_IRQ;
	event->tgidpid = key;
	event->cpu = bpf_get_smp_processor_id();
	event->extra = *start_ns;
	bpf_probe_read_kernel_str(event->comm, sizeof(event->comm), tsk->comm);
	bpf_ringbuf_submit(event, 0);
	bpf_map_delete_elem(&irq_events, &key);
	*/
	return 0;
}

static __always_inline
int handle_wakeup(struct task_struct *waker, struct task_struct *wakee,
		  enum event_type type)
{
	struct task_event *event;
	u64 ts = bpf_ktime_get_boot_ns();
	u64 key = task_key(wakee);

	if (type == SCHED_WAKING || type == SCHED_WAKEUP_NEW)
		bpf_map_update_elem(&wake_ts, &key, &ts, BPF_ANY);

	event = reserve_task_event();
	if (!event)
		return handle_missed_event();
	event->ts = ts;
	event->type = type;
	event->cpu = bpf_get_smp_processor_id();
	event->prev_tgidpid = task_key(waker);
	event->next_tgidpid = key;
	event->next_prio = wakee->prio;
	event->target_cpu = task_cpu(wakee);
	event->kernel_stack_length = 0;
	event->user_stack_length = 0;
	record_task_name(wakee, event->next_comm);
	record_task_name(waker, event->prev_comm);
	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("tp_btf/sched_wakeup")
int handle__sched_wakeup(u64 *ctx)
{
	/* TP_PROTO(struct task_struct *p, int success) */
	struct task_struct *task = (struct task_struct *)ctx[0];
	struct task_struct *cur = (struct task_struct *)bpf_get_current_task_btf();

	if (!trace_task(cur) && !trace_task(task))
		return 0;
	return handle_wakeup(cur, task, SCHED_WAKEUP);
}

SEC("tp_btf/sched_wakeup_new")
int handle__sched_wakeup_new(u64 *ctx)
{
	/* TP_PROTO(struct task_struct *p) */
	struct task_struct *task = (void *)ctx[0];
	struct task_struct *cur = (struct task_struct *)bpf_get_current_task_btf();

	if (!trace_task(cur) && !trace_task(task))
		return 0;
	return handle_wakeup(cur, task, SCHED_WAKEUP_NEW);
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
	struct task_event *event;
	u64 next_key = task_key(next);
	u64 ts = bpf_ktime_get_boot_ns();
	u64 latency = 0;
	u64 *start_ns;

	if (!trace_task(prev) && !trace_task(next))
		return 0;

	start_ns = bpf_map_lookup_elem(&wake_ts, &next_key);
	if (start_ns) {
		if (ts > *start_ns)
			latency = ts - *start_ns;
		bpf_map_delete_elem(&wake_ts, &next_key);
	}

	event = reserve_task_event();
	if (!event)
		return handle_missed_event();

	event->ts = ts;
	event->type = SCHED_SWITCH;
	event->latency = latency;
	event->cpu = bpf_get_smp_processor_id();
	event->prev_tgidpid = task_key(prev);
	event->prev_state = prev->__state;
	event->next_tgidpid = task_key(next);
	event->next_prio = next->prio;
	event->prev_prio = prev->prio;
	event->kernel_stack_length = 0;
	event->user_stack_length = 0;
	record_task_name(prev, event->prev_comm);
	record_task_name(next, event->next_comm);

	/* Record the blocked stack trace. */
	if (!tool_config.no_stack_traces &&
	    prev->__state & TASK_UNINTERRUPTIBLE) {
		u64 len = 0;
		if (!(prev->flags & PF_KTHREAD)) {
			len = bpf_get_stack(ctx, &event->user_stack,
					    sizeof(event->user_stack),
					    BPF_F_USER_STACK);
			event->user_stack_length = len / sizeof(u64);
		}
		len = bpf_get_stack(ctx, &event->kernel_stack,
				    sizeof(event->kernel_stack),
				    SKIP_STACK_DEPTH);
		event->kernel_stack_length = len / sizeof(u64);
	}
	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("tp_btf/sched_waking")
int handle__sched_waking(u64 *ctx)
{
	/* TP_PROTO(struct task_struct *p) */
	struct task_struct *task = (struct task_struct *)ctx[0];
	struct task_struct *cur = (struct task_struct *)bpf_get_current_task_btf();

	if (!trace_task(cur) && !trace_task(task))
		return 0;
	return handle_wakeup(cur, task, SCHED_WAKING);
}

SEC("tp_btf/irq_handler_entry")
int handle__irq_handler_entry(u64 *ctx)
{
#if 0
	/* TP_PROTO(int irq, struct irqaction *action) */
	int irq = ctx[0];
	struct irqaction *action = (void *)ctx[1];
	struct task_event *event;
	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;
	event->ts = bpf_ktime_get_boot_ns();
	event->type = IRQ_ENTRY;
	event->cpu = bpf_get_smp_processor_id();
	event->target_cpu = irq;
	bpf_probe_read_kernel_str(event->prev_comm, sizeof(event->comm), action->name);
	bpf_ringbuf_submit(event, 0);
#endif
	return 0;
}

SEC("tp_btf/irq_handler_exit")
int handle__irq_handler_exit(u64 *ctx)
{
	/* TP_PROTO(int irq, struct irqaction *action, int ret) */
	int irq = ctx[0];
	struct task_event *event;

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

