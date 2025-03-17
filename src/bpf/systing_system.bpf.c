#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/usdt.bpf.h>

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
	u32 filter_pid;
	u32 filter_cgroup;
	u32 no_stack_traces;
} tool_config = {};

enum event_type {
	SCHED_SWITCH,
	SCHED_WAKING,
	SCHED_WAKEUP_NEW,
	SCHED_WAKEUP,
	SCHED_SOFTIRQ_ENTER,
	SCHED_SOFTIRQ_EXIT,
	SCHED_IRQ_ENTER,
	SCHED_IRQ_EXIT,
	SCHED_PROCESS_EXIT,
};

enum stack_event_type {
	STACK_SLEEP,
	STACK_RUNNING,
};

enum cache_event_type {
	CACHE_MISS,
	CACHE_HIT,
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
	u8 prev_comm[TASK_COMM_LEN];
	u8 next_comm[TASK_COMM_LEN];
};

enum usdt_arg_type {
	ARG_NONE,
	ARG_LONG,
	ARG_STRING,
};

#define ARG0_SIZE 64
struct usdt_event {
	u32 cpu;
	enum usdt_arg_type arg_type;
	u64 ts;
	u64 tgidpid;
	u64 cookie;
	u8 usdt_arg0[ARG0_SIZE];
};

struct stack_event {
	enum stack_event_type stack_event_type;
	u64 ts;
	u32 cpu;
	u64 tgidpid;
	u64 kernel_stack_length;
	u64 user_stack_length;
	u64 kernel_stack[MAX_STACK_DEPTH];
	u64 user_stack[MAX_STACK_DEPTH];
};

enum irq_event_type {
	EVENT_IRQ,
	EVENT_SOFTIRQ,
};

struct irq_event {
	u64 ts;
	enum irq_event_type type;
	u32 cpu;
	u32 irq;
	u32 target_cpu;
	u8 comm[TASK_COMM_LEN];
};

struct cache_counter_event {
	u64 ts;
	u64 tgidpid;
	u64 value;
	enum cache_event_type type;
	u32 cpu;
};

/*
 * Dummy instance to get skeleton to generate definition for
 * `struct task_event`
 */
struct task_event _event = {0};
struct usdt_event _usdt_event = {0};
struct stack_event _stack_event = {0};
struct cache_counter_event _cache_counter_event = {0};
enum event_type _type = SCHED_SWITCH;
enum usdt_arg_type _usdt_type = ARG_NONE;
enum stack_event_type _stack_type = STACK_SLEEP;
enum cache_event_type _cache_type = CACHE_MISS;
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
	__type(key, u32);
	__type(value, u8);
	__uint(max_entries, 10240);
} pids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, u64);
	__uint(max_entries, 10240);
} irq_events SEC(".maps");

#define MISSED_SCHED_EVENT 0
#define MISSED_STACK_EVENT 1
#define MISSED_USDT_EVENT 2
#define MISSED_CACHE_EVENT 3
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, 4);
} missed_events SEC(".maps");

struct ringbuf_map {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 50 * 1024 * 1024 /* 50Mib */);
} ringbuf_events_node0 SEC(".maps"), ringbuf_events_node1 SEC(".maps"),
  ringbuf_events_node2 SEC(".maps"), ringbuf_events_node3 SEC(".maps"),
  ringbuf_events_node4 SEC(".maps"), ringbuf_events_node5 SEC(".maps"),
  ringbuf_events_node6 SEC(".maps"), ringbuf_events_node7 SEC(".maps");

struct usdt_ringbuf_map {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 50 * 1024 * 1024 /* 50Mib */);
} ringbuf_usdt_events_node0 SEC(".maps"), ringbuf_usdt_events_node1 SEC(".maps"),
  ringbuf_usdt_events_node2 SEC(".maps"), ringbuf_usdt_events_node3 SEC(".maps"),
  ringbuf_usdt_events_node4 SEC(".maps"), ringbuf_usdt_events_node5 SEC(".maps"),
  ringbuf_usdt_events_node6 SEC(".maps"), ringbuf_usdt_events_node7 SEC(".maps");

struct stack_ringbuf_map {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 50 * 1024 * 1024 /* 50Mib */);
} ringbuf_stack_events_node0 SEC(".maps"), ringbuf_stack_events_node1 SEC(".maps"),
  ringbuf_stack_events_node2 SEC(".maps"), ringbuf_stack_events_node3 SEC(".maps"),
  ringbuf_stack_events_node4 SEC(".maps"), ringbuf_stack_events_node5 SEC(".maps"),
  ringbuf_stack_events_node6 SEC(".maps"), ringbuf_stack_events_node7 SEC(".maps");

struct cache_counter_ringbuf_map {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 50 * 1024 * 1024 /* 50Mib */);
} ringbuf_cache_counter_events_node0 SEC(".maps"),
	ringbuf_cache_counter_events_node1 SEC(".maps"),
	ringbuf_cache_counter_events_node2 SEC(".maps"),
	ringbuf_cache_counter_events_node3 SEC(".maps"),
	ringbuf_cache_counter_events_node4 SEC(".maps"),
	ringbuf_cache_counter_events_node5 SEC(".maps"),
	ringbuf_cache_counter_events_node6 SEC(".maps"),
	ringbuf_cache_counter_events_node7 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, NR_RINGBUFS);
	__type(key, u32);
	__array(values, struct ringbuf_map);
} ringbufs SEC(".maps") = {
	.values = {
		&ringbuf_events_node0,
		&ringbuf_events_node1,
		&ringbuf_events_node2,
		&ringbuf_events_node3,
		&ringbuf_events_node4,
		&ringbuf_events_node5,
		&ringbuf_events_node6,
		&ringbuf_events_node7,
	},
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, NR_RINGBUFS);
	__type(key, u32);
	__array(values, struct usdt_ringbuf_map);
} usdt_ringbufs SEC(".maps") = {
	.values = {
		&ringbuf_usdt_events_node0,
		&ringbuf_usdt_events_node1,
		&ringbuf_usdt_events_node2,
		&ringbuf_usdt_events_node3,
		&ringbuf_usdt_events_node4,
		&ringbuf_usdt_events_node5,
		&ringbuf_usdt_events_node6,
		&ringbuf_usdt_events_node7,
	},
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, NR_RINGBUFS);
	__type(key, u32);
	__array(values, struct stack_ringbuf_map);
} stack_ringbufs SEC(".maps") = {
	.values = {
		&ringbuf_stack_events_node0,
		&ringbuf_stack_events_node1,
		&ringbuf_stack_events_node2,
		&ringbuf_stack_events_node3,
		&ringbuf_stack_events_node4,
		&ringbuf_stack_events_node5,
		&ringbuf_stack_events_node6,
		&ringbuf_stack_events_node7,
	},
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, NR_RINGBUFS);
	__type(key, u32);
	__array(values, struct cache_counter_ringbuf_map);
} cache_counter_ringbufs SEC(".maps") = {
	.values = {
		&ringbuf_cache_counter_events_node0,
		&ringbuf_cache_counter_events_node1,
		&ringbuf_cache_counter_events_node2,
		&ringbuf_cache_counter_events_node3,
		&ringbuf_cache_counter_events_node4,
		&ringbuf_cache_counter_events_node5,
		&ringbuf_cache_counter_events_node6,
		&ringbuf_cache_counter_events_node7,
	},
};

static struct task_event *reserve_task_event(void)
{
	u32 node = (u32)bpf_get_numa_node_id() % NR_RINGBUFS;
	void *rb;

	rb = bpf_map_lookup_elem(&ringbufs, &node);
	if (!rb)
		return NULL;
	return bpf_ringbuf_reserve(rb, sizeof(struct task_event), 0);
}

static struct usdt_event *reserve_usdt_event(void)
{
	u32 node = (u32)bpf_get_numa_node_id() % NR_RINGBUFS;
	void *rb;

	rb = bpf_map_lookup_elem(&usdt_ringbufs, &node);
	if (!rb)
		return NULL;
	return bpf_ringbuf_reserve(rb, sizeof(struct usdt_event), 0);
}

static struct stack_event *reserve_stack_event(void)
{
	u32 node = (u32)bpf_get_numa_node_id() % NR_RINGBUFS;
	void *rb;

	rb = bpf_map_lookup_elem(&stack_ringbufs, &node);
	if (!rb)
		return NULL;
	return bpf_ringbuf_reserve(rb, sizeof(struct stack_event), 0);
}

static struct cache_counter_event *reserve_cache_counter_event(void)
{
	u32 node = (u32)bpf_get_numa_node_id() % NR_RINGBUFS;
	void *rb;

	rb = bpf_map_lookup_elem(&cache_counter_ringbufs, &node);
	if (!rb)
		return NULL;
	return bpf_ringbuf_reserve(rb, sizeof(struct cache_counter_event), 0);
}

static u32 task_cpu(struct task_struct *task)
{
	if (bpf_core_field_exists(task->thread_info)) {
		return task->thread_info.cpu;
	}
	struct thread_info *ti = task->stack;
	return ti->cpu;
}

static u64 task_cg_id(struct task_struct *task)
{
	struct cgroup *cgrp = task->cgroups->dfl_cgrp;
	return cgrp->kn->id;
}

static u64 task_key(struct task_struct *task)
{
	return ((u64)task->tgid << 32) | task->pid;
}

static bool trace_task(struct task_struct *task)
{
	if (!tracing_enabled)
		return false;
	if (task->tgid == 0)
		return false;
	if (tool_config.filter_pid) {
		u32 pid = task->tgid;
		if (bpf_map_lookup_elem(&pids, &pid) == NULL)
			return false;
	}
	if (tool_config.filter_cgroup) {
		u64 cgid = task_cg_id(task);
		if (bpf_map_lookup_elem(&cgroups, &cgid) == NULL)
			return false;
	}
	return true;
}

static int handle_missed_event(u32 index)
{
	u64 *value = bpf_map_lookup_elem(&missed_events, &index);
	if (value)
		*value += 1;
	return 0;
}

static void record_task_name(struct task_struct *task, u8 *comm)
{
	if (task->flags & PF_WQ_WORKER) {
		struct kthread *k = bpf_core_cast(task->worker_private, struct kthread);
		struct worker *worker = bpf_core_cast(k->data, struct worker);

		bpf_probe_read_kernel_str(comm, TASK_COMM_LEN, worker->desc);
	} else {
		bpf_probe_read_kernel_str(comm, TASK_COMM_LEN, task->comm);
	}
}

static void emit_stack_event(void *ctx,struct task_struct *task,
			     enum stack_event_type type)
{
	struct stack_event *event;
	long len = 0;

	if (tool_config.no_stack_traces)
		return;

	if (!trace_task(task))
		return;

	event = reserve_stack_event();
	if (!event) {
		handle_missed_event(MISSED_STACK_EVENT);
		return;
	}

	event->ts = bpf_ktime_get_boot_ns();
	event->cpu = bpf_get_smp_processor_id();
	event->tgidpid = task_key(task);
	event->stack_event_type = type;

	if (!(task->flags & PF_KTHREAD)) {
		len = bpf_get_stack(ctx, &event->user_stack,
				    sizeof(event->user_stack),
				    BPF_F_USER_STACK);
		if (len > 0)
			event->user_stack_length = len / sizeof(u64);
		else
			event->user_stack_length = 0;
	} else {
		event->user_stack_length = 0;
	}

	len = bpf_get_stack(ctx, &event->kernel_stack,
			    sizeof(event->kernel_stack), SKIP_STACK_DEPTH);
	if (len > 0)
		event->kernel_stack_length = len / sizeof(u64);
	else
		event->kernel_stack_length = 0;
	bpf_ringbuf_submit(event, 0);
}

static int trace_irq_event(struct irqaction *action, int irq, int ret, bool enter)
{
	struct task_struct *tsk = (struct task_struct *)bpf_get_current_task_btf();

	if (!trace_task(tsk))
		return 0;

	struct task_event *event;
	event = reserve_task_event();
	if (!event)
		return handle_missed_event(MISSED_SCHED_EVENT);
	event->ts = bpf_ktime_get_boot_ns();
	event->cpu = bpf_get_smp_processor_id();
	event->prev_tgidpid = task_key(tsk);
	event->target_cpu = irq;
	if (enter) {
		event->type = SCHED_IRQ_ENTER;
		bpf_probe_read_kernel_str(event->prev_comm, TASK_COMM_LEN, action->name);
	} else {
		event->type = SCHED_IRQ_EXIT;
		event->next_prio = ret;
	}
	bpf_ringbuf_submit(event, 0);
	return 0;
}

static int trace_softirq_event(unsigned int vec_nr, bool enter)
{
	struct task_struct *tsk = (struct task_struct *)bpf_get_current_task_btf();

	if (!trace_task(tsk))
		return 0;

	struct task_event *event;
	event = reserve_task_event();
	if (!event)
		return handle_missed_event(MISSED_SCHED_EVENT);
	event->ts = bpf_ktime_get_boot_ns();
	event->cpu = bpf_get_smp_processor_id();
	event->prev_tgidpid = task_key(tsk);
	event->target_cpu = vec_nr;
	event->type = enter ? SCHED_SOFTIRQ_ENTER : SCHED_SOFTIRQ_EXIT;
	bpf_ringbuf_submit(event, 0);
	return 0;
}

static int handle_wakeup(struct task_struct *waker, struct task_struct *wakee,
			 enum event_type type)
{
	struct task_event *event;
	u64 ts = bpf_ktime_get_boot_ns();
	u64 key = task_key(wakee);

	if (type == SCHED_WAKING || type == SCHED_WAKEUP_NEW)
		bpf_map_update_elem(&wake_ts, &key, &ts, BPF_ANY);

	event = reserve_task_event();
	if (!event)
		return handle_missed_event(MISSED_SCHED_EVENT);
	event->ts = ts;
	event->type = type;
	event->cpu = bpf_get_smp_processor_id();
	event->prev_tgidpid = task_key(waker);
	event->next_tgidpid = key;
	event->next_prio = wakee->prio;
	event->target_cpu = task_cpu(wakee);
	record_task_name(wakee, event->next_comm);
	record_task_name(waker, event->prev_comm);
	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(systing_sched_wakeup, struct task_struct *task, int success)
{
	struct task_struct *cur = (struct task_struct *)bpf_get_current_task_btf();

	if (!trace_task(cur) && !trace_task(task))
		return 0;
	return handle_wakeup(cur, task, SCHED_WAKEUP);
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(systing_sched_wakeup_new, struct task_struct *task)
{
	struct task_struct *cur = (struct task_struct *)bpf_get_current_task_btf();

	if (!trace_task(cur) && !trace_task(task))
		return 0;
	return handle_wakeup(cur, task, SCHED_WAKEUP_NEW);
}

SEC("tp_btf/sched_switch")
int BPF_PROG(systing_sched_switch, bool preempt, struct task_struct *prev,
	     struct task_struct *next)
{
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
		return handle_missed_event(MISSED_SCHED_EVENT);

	event->ts = ts;
	event->type = SCHED_SWITCH;
	event->latency = latency;
	event->cpu = bpf_get_smp_processor_id();
	event->prev_tgidpid = task_key(prev);
	event->prev_state = prev->__state;
	event->next_tgidpid = task_key(next);
	event->next_prio = next->prio;
	event->prev_prio = prev->prio;
	record_task_name(prev, event->prev_comm);
	record_task_name(next, event->next_comm);
	bpf_ringbuf_submit(event, 0);

	/* Record the blocked stack trace. */
	if (prev->__state & TASK_UNINTERRUPTIBLE)
		emit_stack_event(ctx, prev, STACK_SLEEP);
	return 0;
}

SEC("tp_btf/sched_waking")
int BPF_PROG(systing_sched_waking, struct task_struct *task)
{
	struct task_struct *cur = (struct task_struct *)bpf_get_current_task_btf();

	if (!trace_task(cur) && !trace_task(task))
		return 0;
	return handle_wakeup(cur, task, SCHED_WAKING);
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(systing_sched_process_exit, struct task_struct *task)
{
	struct task_event *event;
	u64 ts = bpf_ktime_get_boot_ns();

	if (!trace_task(task))
		return 0;

	event = reserve_task_event();
	if (!event)
		return handle_missed_event(MISSED_SCHED_EVENT);
	event->ts = ts;
	event->type = SCHED_PROCESS_EXIT;
	event->cpu = bpf_get_smp_processor_id();
	event->prev_tgidpid = task_key(task);
	event->prev_prio = task->prio;
	record_task_name(task, event->prev_comm);
	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("tp_btf/irq_handler_entry")
int BPF_PROG(systing_irq_handler_entry, int irq, struct irqaction *action)
{
	return trace_irq_event(action, irq, 0, true);
}

SEC("tp_btf/irq_handler_exit")
int BPF_PROG(systing_irq_handler_exit, int irq, struct irqaction *action, int ret)
{
	return trace_irq_event(action, irq, ret, false);
}

SEC("tp_btf/softirq_entry")
int BPF_PROG(systing_softirq_entry, unsigned int vec_nr)
{
	return trace_softirq_event(vec_nr, true);
}

SEC("tp_btf/softirq_exit")
int BPF_PROG(systing_softirq_exit, unsigned int vec_nr)
{
	return trace_softirq_event(vec_nr, false);
}

SEC("usdt")
int systing_usdt(u64 *ctx)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

	if (!trace_task(task))
		return 0;

	struct usdt_event *event = reserve_usdt_event();
	if (!event)
		return handle_missed_event(MISSED_USDT_EVENT);
	event->ts = bpf_ktime_get_boot_ns();
	event->cpu = bpf_get_smp_processor_id();
	event->tgidpid = task_key(task);
	event->cookie = bpf_usdt_cookie(ctx);
	event->usdt_arg0[0] = 0;
	event->arg_type = ARG_NONE;

	/*
	 * We don't have an easy way to tell what kind of argument arg0 is, so
	 * we try to read it as if it's a pointer to something, like a string.
	 * If it fails then we'll just pass the raw value.
	 */
	u64 *val = NULL;
	bpf_usdt_arg(ctx, 0, &val);
	if (val) {
		int ret = bpf_probe_read_user_str(&event->usdt_arg0,
						  sizeof(event->usdt_arg0),
						  val);
		if (ret > 0) {
			event->arg_type = ARG_STRING;
		} else {
			u64 realval;
			bpf_usdt_arg(ctx, 0, &realval);
			__builtin_memcpy(&event->usdt_arg0, &realval, sizeof(u64));
			event->arg_type = ARG_LONG;
		}
	}
	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("perf_event")
int systing_perf_event_clock(void *ctx)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
	emit_stack_event(ctx, task, STACK_RUNNING);
	return 0;
}

static int handle_cache_event(struct bpf_perf_event_data *ctx, enum cache_event_type type)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
	if (!trace_task(task))
		return 0;

	struct cache_counter_event *event = reserve_cache_counter_event();
	if (!event)
		return handle_missed_event(MISSED_CACHE_EVENT);
	event->ts = bpf_ktime_get_boot_ns();
	event->tgidpid = task_key(task);
	event->cpu = bpf_get_smp_processor_id();
	event->type = type;
	event->value = ctx->sample_period;
	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("perf_event")
int systing_perf_event_cache_miss(struct bpf_perf_event_data *ctx)
{
	return handle_cache_event(ctx, CACHE_MISS);
}

SEC("perf_event")
int systing_perf_event_cache_hit(struct bpf_perf_event_data *ctx)
{
	return handle_cache_event(ctx, CACHE_HIT);
}

char LICENSE[] SEC("license") = "GPL";
