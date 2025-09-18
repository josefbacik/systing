#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/usdt.bpf.h>

#ifdef SYSTING_PYSTACKS
#include "strobelight/bpf_lib/common/common.h"
#include "strobelight/bpf_lib/python/pystacks/pystacks.bpf.h"
#endif

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
	u32 no_cpu_stack_traces;
	u32 no_sleep_stack_traces;
	u32 num_perf_counters;
	u32 num_cpus;
	u32 my_tgid;
	u64 my_dev;
	u64 my_ino;
	u32 collect_pystacks;
	u32 collect_syscalls;
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

struct task_info {
	u64 tgidpid;
	u8 comm[TASK_COMM_LEN];
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
	u64 prev_state;
	u32 target_cpu;
	u32 next_prio;
	u32 prev_prio;
	struct task_info prev;
	struct task_info next;
};

enum arg_type {
	ARG_NONE,
	ARG_LONG,
	ARG_STRING,
};

struct arg_desc {
	enum arg_type arg_type;
	int arg_index;
};

#define ARG_SIZE 64
struct probe_event {
	u32 cpu;
	enum arg_type arg_type;
	u64 ts;
	u64 cookie;
	struct task_info task;
	u8 arg[ARG_SIZE];
};

struct stack_event {
	enum stack_event_type stack_event_type;
	u64 ts;
	u32 cpu;
	struct task_info task;
	u64 kernel_stack_length;
	u64 user_stack_length;
	u64 kernel_stack[MAX_STACK_DEPTH];
	u64 user_stack[MAX_STACK_DEPTH];
#ifdef SYSTING_PYSTACKS
	struct pystacks_message py_msg_buffer;
#endif
};

struct perf_counter_event {
	u64 ts;
	struct task_info task;
	struct bpf_perf_event_value value;
	u32 cpu;
	u32 counter_num;
};

struct syscall_event {
	u64 ts;
	struct task_info task;
	u64 syscall_nr;
	u64 ret;
	u32 cpu;
	u8 is_enter;  // 1 for sys_enter, 0 for sys_exit
};

/*
 * Dummy instance to get skeleton to generate definition for
 * `struct task_event`
 */
struct task_event _event = {0};
struct stack_event _stack_event = {0};
struct perf_counter_event _perf_counter_event = {0};
struct syscall_event _syscall_event = {0};
struct task_info _task_info = {0};
struct probe_event _uprobe_event = {0};
struct arg_desc _arg_desc = {0};
enum event_type _type = SCHED_SWITCH;
enum arg_type _arg_type = ARG_NONE;
enum stack_event_type _stack_type = STACK_SLEEP;
bool tracing_enabled = true;

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 10240);
} perf_counters SEC(".maps");

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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct arg_desc);
	__uint(max_entries, 10240);
} event_key_types SEC(".maps");

#define MISSED_SCHED_EVENT 0
#define MISSED_STACK_EVENT 1
#define MISSED_PROBE_EVENT 2
#define MISSED_CACHE_EVENT 3
#define MISSED_SYSCALL_EVENT 4
#define MISSED_EVENT_MAX 5
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, MISSED_EVENT_MAX);
} missed_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, 1);
} last_perf_counter_value SEC(".maps");

struct ringbuf_map {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 50 * 1024 * 1024 /* 50Mib */);
} ringbuf_events_node0 SEC(".maps"), ringbuf_events_node1 SEC(".maps"),
  ringbuf_events_node2 SEC(".maps"), ringbuf_events_node3 SEC(".maps"),
  ringbuf_events_node4 SEC(".maps"), ringbuf_events_node5 SEC(".maps"),
  ringbuf_events_node6 SEC(".maps"), ringbuf_events_node7 SEC(".maps");

struct stack_ringbuf_map {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 50 * 1024 * 1024 /* 50Mib */);
} ringbuf_stack_events_node0 SEC(".maps"), ringbuf_stack_events_node1 SEC(".maps"),
  ringbuf_stack_events_node2 SEC(".maps"), ringbuf_stack_events_node3 SEC(".maps"),
  ringbuf_stack_events_node4 SEC(".maps"), ringbuf_stack_events_node5 SEC(".maps"),
  ringbuf_stack_events_node6 SEC(".maps"), ringbuf_stack_events_node7 SEC(".maps");

struct probe_ringbuf_map {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 50 * 1024 * 1024 /* 50Mib */);
} ringbuf_probe_events_node0 SEC(".maps"), ringbuf_probe_events_node1 SEC(".maps"),
  ringbuf_probe_events_node2 SEC(".maps"), ringbuf_probe_events_node3 SEC(".maps"),
  ringbuf_probe_events_node4 SEC(".maps"), ringbuf_probe_events_node5 SEC(".maps"),
  ringbuf_probe_events_node6 SEC(".maps"), ringbuf_probe_events_node7 SEC(".maps");

struct perf_counter_ringbuf_map {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 50 * 1024 * 1024 /* 50Mib */);
} ringbuf_perf_counter_events_node0 SEC(".maps"),
	ringbuf_perf_counter_events_node1 SEC(".maps"),
	ringbuf_perf_counter_events_node2 SEC(".maps"),
	ringbuf_perf_counter_events_node3 SEC(".maps"),
	ringbuf_perf_counter_events_node4 SEC(".maps"),
	ringbuf_perf_counter_events_node5 SEC(".maps"),
	ringbuf_perf_counter_events_node6 SEC(".maps"),
	ringbuf_perf_counter_events_node7 SEC(".maps");

struct syscall_ringbuf_map {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 50 * 1024 * 1024 /* 50Mib */);
} ringbuf_syscall_events_node0 SEC(".maps"),
	ringbuf_syscall_events_node1 SEC(".maps"),
	ringbuf_syscall_events_node2 SEC(".maps"),
	ringbuf_syscall_events_node3 SEC(".maps"),
	ringbuf_syscall_events_node4 SEC(".maps"),
	ringbuf_syscall_events_node5 SEC(".maps"),
	ringbuf_syscall_events_node6 SEC(".maps"),
	ringbuf_syscall_events_node7 SEC(".maps");

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
	__array(values, struct perf_counter_ringbuf_map);
} perf_counter_ringbufs SEC(".maps") = {
	.values = {
		&ringbuf_perf_counter_events_node0,
		&ringbuf_perf_counter_events_node1,
		&ringbuf_perf_counter_events_node2,
		&ringbuf_perf_counter_events_node3,
		&ringbuf_perf_counter_events_node4,
		&ringbuf_perf_counter_events_node5,
		&ringbuf_perf_counter_events_node6,
		&ringbuf_perf_counter_events_node7,
	},
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, NR_RINGBUFS);
	__type(key, u32);
	__array(values, struct probe_ringbuf_map);
} probe_ringbufs SEC(".maps") = {
	.values = {
		&ringbuf_probe_events_node0,
		&ringbuf_probe_events_node1,
		&ringbuf_probe_events_node2,
		&ringbuf_probe_events_node3,
		&ringbuf_probe_events_node4,
		&ringbuf_probe_events_node5,
		&ringbuf_probe_events_node6,
		&ringbuf_probe_events_node7,
	},
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, NR_RINGBUFS);
	__type(key, u32);
	__array(values, struct syscall_ringbuf_map);
} syscall_ringbufs SEC(".maps") = {
	.values = {
		&ringbuf_syscall_events_node0,
		&ringbuf_syscall_events_node1,
		&ringbuf_syscall_events_node2,
		&ringbuf_syscall_events_node3,
		&ringbuf_syscall_events_node4,
		&ringbuf_syscall_events_node5,
		&ringbuf_syscall_events_node6,
		&ringbuf_syscall_events_node7,
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

static struct stack_event *reserve_stack_event(void)
{
	u32 node = (u32)bpf_get_numa_node_id() % NR_RINGBUFS;
	void *rb;

	rb = bpf_map_lookup_elem(&stack_ringbufs, &node);
	if (!rb)
		return NULL;
	return bpf_ringbuf_reserve(rb, sizeof(struct stack_event), 0);
}

static struct perf_counter_event *reserve_perf_counter_event(void)
{
	u32 node = (u32)bpf_get_numa_node_id() % NR_RINGBUFS;
	void *rb;

	rb = bpf_map_lookup_elem(&perf_counter_ringbufs, &node);
	if (!rb)
		return NULL;
	return bpf_ringbuf_reserve(rb, sizeof(struct perf_counter_event), 0);
}

static struct probe_event *reserve_probe_event(void)
{
	u32 node = (u32)bpf_get_numa_node_id() % NR_RINGBUFS;
	void *rb;

	rb = bpf_map_lookup_elem(&probe_ringbufs, &node);
	if (!rb)
		return NULL;
	return bpf_ringbuf_reserve(rb, sizeof(struct probe_event), 0);
}

static struct syscall_event *reserve_syscall_event(void)
{
	u32 node = (u32)bpf_get_numa_node_id() % NR_RINGBUFS;
	void *rb;

	rb = bpf_map_lookup_elem(&syscall_ringbufs, &node);
	if (!rb)
		return NULL;
	return bpf_ringbuf_reserve(rb, sizeof(struct syscall_event), 0);
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

struct systing_pid_filter {
	u32 kernel_tgid;
	u32 initialized;
};

struct systing_pid_filter filter = {0, 0};

static bool should_filter_systing(struct task_struct *task)
{
	// If filter is initialized, check against kernel namespace TGID
	if (filter.initialized) {
		return task->tgid == filter.kernel_tgid;
	}

	// Filter not initialized - check if we have namespace info
	if (tool_config.my_dev == 0 && tool_config.my_ino == 0) {
		// No namespace info, use the userspace TGID directly
		filter.kernel_tgid = tool_config.my_tgid;
		filter.initialized = 1;
		return task->tgid == filter.kernel_tgid;
	}

	// We have namespace info, check if current process matches our namespace TGID
	struct bpf_pidns_info ns_info = {};
	if (bpf_get_ns_current_pid_tgid(tool_config.my_dev, tool_config.my_ino,
					 &ns_info, sizeof(ns_info)) == 0) {
		// Check if the namespace TGID matches our userspace TGID
		if (ns_info.tgid == tool_config.my_tgid) {
			// This is our process - get the kernel namespace TGID
			u64 pid_tgid = bpf_get_current_pid_tgid();
			filter.kernel_tgid = pid_tgid >> 32;
			filter.initialized = 1;
			return true; // This is systing process
		}
	}

	// Unable to determine if this is our process, don't filter
	return false;
}

static bool trace_task(struct task_struct *task)
{
	if (!tracing_enabled)
		return false;
	if (task->tgid == 0)
		return false;
	if (should_filter_systing(task))
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

static void record_task_info(struct task_info *info, struct task_struct *task)
{
	info->tgidpid = task_key(task);
	if (task->flags & PF_WQ_WORKER) {
		struct kthread *k = bpf_core_cast(task->worker_private,
						  struct kthread);
		struct worker *worker = bpf_core_cast(k->data, struct worker);

		bpf_probe_read_kernel_str(info->comm, TASK_COMM_LEN,
					  worker->desc);
	} else {
		bpf_probe_read_kernel_str(info->comm, TASK_COMM_LEN,
					  task->comm);
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
	record_task_info(&event->task, task);

#ifdef SYSTING_PYSTACKS
	event->py_msg_buffer.stack_len = 0;
	if (tool_config.collect_pystacks) {
		pystacks_read_stacks(ctx, NULL, &event->py_msg_buffer);
	}
#endif

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
	record_task_info(&event->prev, tsk);
	event->target_cpu = irq;
	if (enter) {
		event->type = SCHED_IRQ_ENTER;
		bpf_probe_read_kernel_str(event->next.comm, TASK_COMM_LEN,
					  action->name);
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
	record_task_info(&event->prev, tsk);
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
	event->next_prio = wakee->prio;
	event->target_cpu = task_cpu(wakee);
	record_task_info(&event->prev, waker);
	record_task_info(&event->next, wakee);
	bpf_ringbuf_submit(event, 0);
	return 0;
}

static int handle_sched_wakeup(struct task_struct *task, int success)
{
	struct task_struct *cur = (struct task_struct *)bpf_get_current_task_btf();

	if (!trace_task(cur) && !trace_task(task))
		return 0;
	return handle_wakeup(cur, task, SCHED_WAKEUP);
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(systing_sched_wakeup, struct task_struct *task, int success)
{
	return handle_sched_wakeup(task, success);
}

static int handle_sched_wakeup_new(struct task_struct *task)
{
	struct task_struct *cur = (struct task_struct *)bpf_get_current_task_btf();

	if (!trace_task(cur) && !trace_task(task))
		return 0;
	return handle_wakeup(cur, task, SCHED_WAKEUP_NEW);
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(systing_sched_wakeup_new, struct task_struct *task)
{
	return handle_sched_wakeup_new(task);
}

static int handle_sched_switch(void *ctx, bool preempt, struct task_struct *prev,
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
	record_task_info(&event->next, next);
	record_task_info(&event->prev, prev);
	event->prev_state = prev->__state;
	event->next_prio = next->prio;
	event->prev_prio = prev->prio;
	bpf_ringbuf_submit(event, 0);

	/* Record the blocked stack trace. */
	if (!tool_config.no_sleep_stack_traces && prev->__state & TASK_UNINTERRUPTIBLE)
		emit_stack_event(ctx, prev, STACK_SLEEP);
	return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(systing_sched_switch, bool preempt, struct task_struct *prev,
	     struct task_struct *next)
{
	return handle_sched_switch(ctx, preempt, prev, next);
}

static int handle_sched_waking(struct task_struct *task)
{
	struct task_struct *cur = (struct task_struct *)bpf_get_current_task_btf();

	if (!trace_task(cur) && !trace_task(task))
		return 0;
	return handle_wakeup(cur, task, SCHED_WAKING);
}

SEC("tp_btf/sched_waking")
int BPF_PROG(systing_sched_waking, struct task_struct *task)
{
	return handle_sched_waking(task);
}

static int handle_sched_process_exit(struct task_struct *task)
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
	record_task_info(&event->prev, task);
	event->prev_prio = task->prio;
	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(systing_sched_process_exit, struct task_struct *task)
{
	return handle_sched_process_exit(task);
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
int systing_usdt(struct pt_regs *ctx)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

	if (!trace_task(task))
		return 0;

	u64 cookie = bpf_usdt_cookie(ctx);

	struct probe_event *event = reserve_probe_event();
	if (!event)
		return handle_missed_event(MISSED_PROBE_EVENT);
	event->ts = bpf_ktime_get_boot_ns();
	event->cpu = bpf_get_smp_processor_id();
	record_task_info(&event->task, task);
	event->cookie = cookie;
	event->arg[0] = 0;
	event->arg_type = ARG_NONE;

	struct arg_desc *desc = bpf_map_lookup_elem(&event_key_types, &cookie);
	if (desc) {
		long val = 0;
		bpf_usdt_arg(ctx, desc->arg_index, &val);
		if (val) {
			if (desc->arg_type == ARG_STRING) {
				bpf_probe_read_user_str(&event->arg,
							sizeof(event->arg), (long *)val);
				event->arg_type = ARG_STRING;
			} else {
				__builtin_memcpy(&event->arg, &val, sizeof(long));
				event->arg_type = ARG_LONG;
			}
		}
	}
	bpf_ringbuf_submit(event, 0);
	return 0;
}

static void read_counters(void *ctx, struct task_struct *task)
{
	u32 key, cpu = bpf_get_smp_processor_id();

	if (!trace_task(task))
		return;

	u64 ts = bpf_ktime_get_boot_ns();
	key = cpu;

	for (int i = 0; i < tool_config.num_perf_counters; i++, key += tool_config.num_cpus) {
		int err;

		struct perf_counter_event *event = reserve_perf_counter_event();
		if (!event) {
			handle_missed_event(MISSED_CACHE_EVENT);
			continue;
		}

		err = bpf_perf_event_read_value(&perf_counters, key, (void *)&event->value,
						sizeof(event->value));
		if (err) {
			bpf_ringbuf_discard(event, 0);
			continue;
		}
		if (event->value.counter == 0) {
			bpf_ringbuf_discard(event, 0);
			continue;
		}
		u32 index = i;
		u64 *last_value = bpf_map_lookup_elem(&last_perf_counter_value, &index);
		if (last_value) {
			u64 old_value = event->value.counter;
			event->value.counter -= *last_value;
			*last_value = old_value;
		}
		event->ts = ts;
		event->cpu = cpu;
		event->counter_num = i;
		record_task_info(&event->task, task);
		bpf_ringbuf_submit(event, 0);
	}
}

SEC("perf_event")
int systing_perf_event_clock(void *ctx)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
	if (!tool_config.no_cpu_stack_traces)
		emit_stack_event(ctx, task, STACK_RUNNING);
	read_counters(ctx, task);
	return 0;
}

static void handle_probe_event(struct pt_regs *ctx, bool kernel)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

	if (!trace_task(task))
		return;

	u64 cookie = bpf_get_attach_cookie(ctx);
	struct probe_event *event = reserve_probe_event();
	if (!event) {
		handle_missed_event(MISSED_PROBE_EVENT);
		return;
	}

	event->ts = bpf_ktime_get_boot_ns();
	event->cpu = bpf_get_smp_processor_id();
	record_task_info(&event->task, task);
	event->cookie = cookie;
	event->arg[0] = 0;
	event->arg_type = ARG_NONE;

	struct arg_desc *desc = bpf_map_lookup_elem(&event_key_types, &cookie);
	if (desc) {
		u64 arg = 0;
		if (desc->arg_index == 0) {
			arg = PT_REGS_PARM1_CORE(ctx);
		} else if (desc->arg_index == 1) {
			arg = PT_REGS_PARM2_CORE(ctx);
		} else if (desc->arg_index == 2) {
			arg = PT_REGS_PARM3_CORE(ctx);
		} else if (desc->arg_index == 3) {
			arg = PT_REGS_PARM4_CORE(ctx);
		} else if (desc->arg_index == 4) {
			arg = PT_REGS_PARM5_CORE(ctx);
		} else if (desc->arg_index == 5) {
			arg = PT_REGS_PARM6_CORE(ctx);
		}
		if (desc->arg_type == ARG_STRING) {
			if (kernel)
				bpf_probe_read_kernel_str(&event->arg,
							  sizeof(event->arg),
							  (void *)arg);
			else
				bpf_probe_read_user_str(&event->arg,
							sizeof(event->arg),
							(void *)arg);
			event->arg_type = ARG_STRING;
		} else if (desc->arg_type == ARG_LONG) {
			__builtin_memcpy(&event->arg, &arg, sizeof(u64));
			event->arg_type = ARG_LONG;
		}
	}
	bpf_ringbuf_submit(event, 0);
}

SEC("uprobe")
int systing_uprobe(struct pt_regs *ctx)
{
	handle_probe_event(ctx, false);
	return 0;
}

SEC("kprobe")
int systing_kprobe(struct pt_regs *ctx)
{
	handle_probe_event(ctx, true);
	return 0;
}

SEC("raw_tracepoint")
int systing_raw_tracepoint(struct bpf_raw_tracepoint_args *args)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

	if (!trace_task(task))
		return 0;

	u64 cookie = bpf_get_attach_cookie(args);
	struct probe_event *event = reserve_probe_event();
	if (!event) {
		handle_missed_event(MISSED_PROBE_EVENT);
		return 0;
	}

	event->ts = bpf_ktime_get_boot_ns();
	event->cpu = bpf_get_smp_processor_id();
	record_task_info(&event->task, task);
	event->cookie = cookie;
	event->arg[0] = 0;
	event->arg_type = ARG_NONE;

	struct arg_desc *desc = bpf_map_lookup_elem(&event_key_types, &cookie);
	if (desc) {
		u64 arg = 0;
		if (desc->arg_index == 0) {
			bpf_probe_read_kernel(&arg, sizeof(arg), &args->args[0]);
		} else if (desc->arg_index == 1) {
			bpf_probe_read_kernel(&arg, sizeof(arg), &args->args[1]);
		} else if (desc->arg_index == 2) {
			bpf_probe_read_kernel(&arg, sizeof(arg), &args->args[2]);
		} else if (desc->arg_index == 3) {
			bpf_probe_read_kernel(&arg, sizeof(arg), &args->args[3]);
		} else if (desc->arg_index == 4) {
			bpf_probe_read_kernel(&arg, sizeof(arg), &args->args[4]);
		} else if (desc->arg_index == 5) {
			bpf_probe_read_kernel(&arg, sizeof(arg), &args->args[5]);
		}
		if (desc->arg_type == ARG_STRING) {
			bpf_probe_read_kernel_str(&event->arg,
						  sizeof(event->arg),
						  (void *)arg);
			event->arg_type = ARG_STRING;
		} else if (desc->arg_type == ARG_LONG) {
			__builtin_memcpy(&event->arg, &arg, sizeof(u64));
			event->arg_type = ARG_LONG;
		}
	}
	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("tracepoint")
int systing_tracepoint(struct bpf_raw_tracepoint_args *args)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

	if (!trace_task(task))
		return 0;

	u64 cookie = bpf_get_attach_cookie(args);
	struct probe_event *event = reserve_probe_event();
	if (!event) {
		handle_missed_event(MISSED_PROBE_EVENT);
		return 0;
	}

	event->ts = bpf_ktime_get_boot_ns();
	event->cpu = bpf_get_smp_processor_id();
	record_task_info(&event->task, task);
	event->cookie = cookie;
	event->arg[0] = 0;
	event->arg_type = ARG_NONE;

	// To get the tracepoint arguments we'd have to figure out the memory
	// layout of the buffer and get to the right argument, which we're not
	// going to do here. This is only provided so we can capture tracepoints
	// in systing, if you want arguments you need a newer kernel and then
	// systing will use the raw_tracepoint variation where we can record the
	// argument.
	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int tracepoint__raw_syscalls__sys_enter(struct trace_event_raw_sys_enter *ctx)
{
	if (!tool_config.collect_syscalls)
		return 0;

	struct task_struct *task = bpf_get_current_task_btf();
	if (!trace_task(task))
		return 0;

	struct syscall_event *event = reserve_syscall_event();
	if (!event) {
		handle_missed_event(MISSED_SYSCALL_EVENT);
		return 0;
	}

	event->ts = bpf_ktime_get_boot_ns();
	event->cpu = bpf_get_smp_processor_id();
	record_task_info(&event->task, task);
	event->syscall_nr = ctx->id;
	event->ret = 0;  // Not available for sys_enter
	event->is_enter = 1;

	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int tracepoint__raw_syscalls__sys_exit(struct trace_event_raw_sys_exit *ctx)
{
	if (!tool_config.collect_syscalls)
		return 0;

	struct task_struct *task = bpf_get_current_task_btf();
	if (!trace_task(task))
		return 0;

	struct syscall_event *event = reserve_syscall_event();
	if (!event) {
		handle_missed_event(MISSED_SYSCALL_EVENT);
		return 0;
	}

	event->ts = bpf_ktime_get_boot_ns();
	event->cpu = bpf_get_smp_processor_id();
	record_task_info(&event->task, task);
	event->syscall_nr = ctx->id;
	event->ret = ctx->ret;
	event->is_enter = 0;

	bpf_ringbuf_submit(event, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
