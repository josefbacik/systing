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

/* Address family constants (from linux/socket.h) */
#define AF_INET 2
#define AF_INET6 10

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
	u32 confidentiality_mode;
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

enum network_protocol {
	NETWORK_TCP,
	NETWORK_UDP,
};

enum network_operation {
	NETWORK_SEND,
	NETWORK_RECV,
};

enum network_address_family {
	NETWORK_AF_INET,   // IPv4
	NETWORK_AF_INET6,  // IPv6
};

struct network_event {
	u64 start_ts;
	u64 end_ts;
	struct task_info task;
	enum network_protocol protocol;
	enum network_operation operation;
	enum network_address_family af;  // Address family (IPv4 or IPv6)
	u8 dest_addr[16];  // IPv4 (first 4 bytes) or IPv6 (all 16 bytes) in network byte order
	u16 dest_port;     // Port in host byte order
	u32 bytes;
	u32 cpu;
};

/*
 * Dummy instance to get skeleton to generate definition for
 * `struct task_event`
 */
struct task_event _event = {0};
struct stack_event _stack_event = {0};
struct perf_counter_event _perf_counter_event = {0};
struct syscall_event _syscall_event = {0};
struct network_event _network_event = {0};
struct task_info _task_info = {0};
struct probe_event _uprobe_event = {0};
struct arg_desc _arg_desc = {0};
enum event_type _type = SCHED_SWITCH;
enum arg_type _arg_type = ARG_NONE;
enum stack_event_type _stack_type = STACK_SLEEP;
enum network_protocol _network_proto = NETWORK_TCP;
enum network_operation _network_op = NETWORK_SEND;
enum network_address_family _network_af = NETWORK_AF_INET;
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

// Tracks pending network operations (both sends and receives)
//
// Note: network_send_info and network_recv_info have identical structure currently,
// but are kept separate for future extensibility. Potential future additions:
//   - send_info: TTL, TOS/DSCP, fragmentation flags
//   - recv_info: flags, truncation indicators, multicast info
struct network_send_info {
	enum network_protocol protocol;
	enum network_address_family af;
	u8 dest_addr[16];
	u16 dest_port;
	u64 start_ts;
};

// Tracks pending receive operations with peer address
struct network_recv_info {
	enum network_protocol protocol;
	enum network_address_family af;
	u8 peer_addr[16];
	u16 peer_port;
	u64 start_ts;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);  // tgidpid
	__type(value, struct network_send_info);
	__uint(max_entries, 10240);
} pending_network_sends SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);  // tgidpid
	__type(value, struct network_recv_info);
	__uint(max_entries, 10240);
} pending_network_recvs SEC(".maps");

#define MISSED_SCHED_EVENT 0
#define MISSED_STACK_EVENT 1
#define MISSED_PROBE_EVENT 2
#define MISSED_CACHE_EVENT 3
#define MISSED_SYSCALL_EVENT 4
#define MISSED_NETWORK_EVENT 5
#define MISSED_EVENT_MAX 6
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

struct network_ringbuf_map {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 50 * 1024 * 1024 /* 50Mib */);
} ringbuf_network_events_node0 SEC(".maps"),
	ringbuf_network_events_node1 SEC(".maps"),
	ringbuf_network_events_node2 SEC(".maps"),
	ringbuf_network_events_node3 SEC(".maps"),
	ringbuf_network_events_node4 SEC(".maps"),
	ringbuf_network_events_node5 SEC(".maps"),
	ringbuf_network_events_node6 SEC(".maps"),
	ringbuf_network_events_node7 SEC(".maps");

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

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, NR_RINGBUFS);
	__type(key, u32);
	__array(values, struct network_ringbuf_map);
} network_ringbufs SEC(".maps") = {
	.values = {
		&ringbuf_network_events_node0,
		&ringbuf_network_events_node1,
		&ringbuf_network_events_node2,
		&ringbuf_network_events_node3,
		&ringbuf_network_events_node4,
		&ringbuf_network_events_node5,
		&ringbuf_network_events_node6,
		&ringbuf_network_events_node7,
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

static struct network_event *reserve_network_event(void)
{
	u32 node = (u32)bpf_get_numa_node_id() % NR_RINGBUFS;
	void *rb;

	rb = bpf_map_lookup_elem(&network_ringbufs, &node);
	if (!rb)
		return NULL;
	return bpf_ringbuf_reserve(rb, sizeof(struct network_event), 0);
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

/*
 * Safe wrapper for reading kernel strings that handles confidentiality mode.
 * When confidentiality mode is enabled, bpf_probe_read_kernel_str is disabled,
 * so we use a placeholder string instead.
 */
static __always_inline long safe_probe_read_kernel_str(void *dst, u32 size, const void *unsafe_ptr)
{
	if (tool_config.confidentiality_mode) {
		// In confidentiality mode, use a placeholder
		// We can't use bpf_probe_read_str as it's also restricted
		const char placeholder[] = "<restricted>";
		int len = sizeof(placeholder) - 1;
		if (len > size - 1)
			len = size - 1;
		__builtin_memcpy(dst, placeholder, len);
		((char *)dst)[len] = '\0';
		return len;
	}

	// Normal mode - use the standard kernel string reader
	return bpf_probe_read_kernel_str(dst, size, unsafe_ptr);
}

/*
 * Safe wrapper for reading user strings that handles confidentiality mode.
 * When confidentiality mode is enabled, bpf_probe_read_user_str is disabled,
 * so we use a placeholder string instead.
 */
static __always_inline long safe_probe_read_user_str(void *dst, u32 size, const void *unsafe_ptr)
{
	if (tool_config.confidentiality_mode) {
		// In confidentiality mode, use a placeholder
		// We can't use bpf_probe_read_str as it's also restricted
		const char placeholder[] = "<restricted>";
		int len = sizeof(placeholder) - 1;
		if (len > size - 1)
			len = size - 1;
		__builtin_memcpy(dst, placeholder, len);
		((char *)dst)[len] = '\0';
		return len;
	}

	// Normal mode - use the standard user string reader
	return bpf_probe_read_user_str(dst, size, unsafe_ptr);
}

static void record_task_info(struct task_info *info, struct task_struct *task)
{
	info->tgidpid = task_key(task);

	// In confidentiality mode, use NULL comm (all zeros)
	if (tool_config.confidentiality_mode) {
		__builtin_memset(info->comm, 0, TASK_COMM_LEN);
		return;
	}

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
		struct pt_regs *pt_regs = (struct pt_regs *)bpf_task_pt_regs(task);
		pystacks_read_stacks(pt_regs, NULL, &event->py_msg_buffer);
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
		if (tool_config.confidentiality_mode) {
			__builtin_memset(event->next.comm, 0, TASK_COMM_LEN);
		} else {
			bpf_probe_read_kernel_str(event->next.comm, TASK_COMM_LEN,
						  action->name);
		}
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

static int handle_sched_process_fork(struct task_struct *parent,
				     struct task_struct *child)
{
	// Check if parent is being traced
	if (!trace_task(parent))
		return 0;

	// Add child to the pids map so we trace it too
	u32 child_pid = child->tgid;
	u8 val = 1;
	bpf_map_update_elem(&pids, &child_pid, &val, BPF_ANY);

	return 0;
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(systing_sched_process_fork, struct task_struct *parent,
	     struct task_struct *child)
{
	return handle_sched_process_fork(parent, child);
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
	// Exit early in confidentiality mode since USDT helpers are restricted
	if (tool_config.confidentiality_mode)
		return 0;

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
				safe_probe_read_user_str(&event->arg,
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
				safe_probe_read_kernel_str(&event->arg,
							  sizeof(event->arg),
							  (void *)arg);
			else
				safe_probe_read_user_str(&event->arg,
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
	// Exit early in confidentiality mode since probe helpers are restricted
	if (tool_config.confidentiality_mode)
		return 0;

	handle_probe_event(ctx, false);
	return 0;
}

SEC("kprobe")
int systing_kprobe(struct pt_regs *ctx)
{
	// Exit early in confidentiality mode since probe helpers are restricted
	if (tool_config.confidentiality_mode)
		return 0;

	handle_probe_event(ctx, true);
	return 0;
}

SEC("raw_tracepoint")
int systing_raw_tracepoint(struct bpf_raw_tracepoint_args *args)
{
	// Exit early in confidentiality mode since probe helpers are restricted
	if (tool_config.confidentiality_mode)
		return 0;

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
			safe_probe_read_kernel_str(&event->arg,
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
	// Exit early in confidentiality mode since we can't read arguments
	if (tool_config.confidentiality_mode)
		return 0;

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

static int handle_sendmsg_entry(struct sock *sk, struct msghdr *msg, enum network_protocol protocol)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

	if (!trace_task(task))
		return 0;

	u64 tgidpid = bpf_get_current_pid_tgid();
	struct network_send_info info = {0};

	info.protocol = protocol;
	info.start_ts = bpf_ktime_get_boot_ns();
	info.af = NETWORK_AF_INET;  // Default to IPv4, will update if IPv6

	// For UDP (and optionally TCP with msg_name), try to read from msghdr first
	// This handles unconnected UDP sockets where destination is passed per-send
	if (msg) {
		void *msg_name;
		size_t msg_namelen;

		// Read msg_name and msg_namelen from the msghdr structure using probe_read
		bpf_probe_read_kernel(&msg_name, sizeof(msg_name), &msg->msg_name);
		bpf_probe_read_kernel(&msg_namelen, sizeof(msg_namelen), &msg->msg_namelen);

		if (msg_name) {
			u16 family;
			bpf_probe_read_kernel(&family, sizeof(family), msg_name);

			// Check if this is IPv4
			if (family == AF_INET && msg_namelen >= sizeof(struct sockaddr_in)) {
				struct sockaddr_in addr;
				bpf_probe_read_kernel(&addr, sizeof(addr), msg_name);

				info.af = NETWORK_AF_INET;
				__builtin_memcpy(info.dest_addr, &addr.sin_addr.s_addr, 4);
				info.dest_port = __builtin_bswap16(addr.sin_port);
			}
			// Check if this is IPv6
			else if (family == AF_INET6 && msg_namelen >= sizeof(struct sockaddr_in6)) {
				struct sockaddr_in6 addr6;
				bpf_probe_read_kernel(&addr6, sizeof(addr6), msg_name);

				info.af = NETWORK_AF_INET6;
				__builtin_memcpy(info.dest_addr, &addr6.sin6_addr, 16);
				info.dest_port = __builtin_bswap16(addr6.sin6_port);
			}
		}
	}

	// Fallback: for TCP or connected UDP sockets, read from socket structure
	// Check if we haven't extracted an address yet (port will be non-zero if extracted from msg_name)
	if (sk && info.dest_port == 0) {
		u16 family;
		bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);

		if (family == AF_INET) {
			info.af = NETWORK_AF_INET;
			u32 addr;
			bpf_probe_read_kernel(&addr, sizeof(addr), &sk->__sk_common.skc_daddr);
			__builtin_memcpy(info.dest_addr, &addr, 4);
			bpf_probe_read_kernel(&info.dest_port, sizeof(info.dest_port),
					      &sk->__sk_common.skc_dport);
			info.dest_port = __builtin_bswap16(info.dest_port);
		} else if (family == AF_INET6) {
			// Note: IPv4-mapped IPv6 addresses (::ffff:192.0.2.1) are stored as IPv6.
			// This is intentional - we preserve the address family from the socket,
			// allowing userspace to see the actual socket type being used.
			info.af = NETWORK_AF_INET6;
			bpf_probe_read_kernel(info.dest_addr, 16, &sk->__sk_common.skc_v6_daddr);
			bpf_probe_read_kernel(&info.dest_port, sizeof(info.dest_port),
					      &sk->__sk_common.skc_dport);
			info.dest_port = __builtin_bswap16(info.dest_port);
		}
	}

	bpf_map_update_elem(&pending_network_sends, &tgidpid, &info, BPF_ANY);

	return 0;
}

static int handle_sendmsg_exit(void *ctx, int ret)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

	if (!trace_task(task))
		return 0;

	// Only record successful sends
	if (ret <= 0)
		return 0;

	u64 tgidpid = bpf_get_current_pid_tgid();
	struct network_send_info *info = bpf_map_lookup_elem(&pending_network_sends, &tgidpid);

	if (!info) {
		// No matching entry, skip
		return 0;
	}

	struct network_event *event = reserve_network_event();
	if (!event) {
		bpf_map_delete_elem(&pending_network_sends, &tgidpid);
		return handle_missed_event(MISSED_NETWORK_EVENT);
	}

	event->start_ts = info->start_ts;
	event->end_ts = bpf_ktime_get_boot_ns();
	event->cpu = bpf_get_smp_processor_id();
	record_task_info(&event->task, task);
	event->protocol = info->protocol;
	event->operation = NETWORK_SEND;
	event->af = info->af;
	__builtin_memcpy(event->dest_addr, info->dest_addr, 16);
	event->dest_port = info->dest_port;
	event->bytes = (u32)ret;  // Return value is number of bytes sent

	bpf_ringbuf_submit(event, 0);
	bpf_map_delete_elem(&pending_network_sends, &tgidpid);

	return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg_entry, struct sock *sk, struct msghdr *msg, size_t size)
{
	return handle_sendmsg_entry(sk, msg, NETWORK_TCP);
}

SEC("kretprobe/tcp_sendmsg")
int BPF_KRETPROBE(tcp_sendmsg_exit, int ret)
{
	return handle_sendmsg_exit(ctx, ret);
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(udp_sendmsg_entry, struct sock *sk, struct msghdr *msg, size_t size)
{
	return handle_sendmsg_entry(sk, msg, NETWORK_UDP);
}

SEC("kretprobe/udp_sendmsg")
int BPF_KRETPROBE(udp_sendmsg_exit, int ret)
{
	return handle_sendmsg_exit(ctx, ret);
}

// For TCP: read peer address from socket structure
static int handle_tcp_recvmsg_entry(struct sock *sk, struct msghdr *msg)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

	if (!trace_task(task))
		return 0;

	u64 tgidpid = bpf_get_current_pid_tgid();
	struct network_recv_info info = {0};

	info.protocol = NETWORK_TCP;
	info.start_ts = bpf_ktime_get_boot_ns();
	info.af = NETWORK_AF_INET;  // Default to IPv4

	// For TCP (connected socket): socket stores peer address/port
	// skc_daddr/skc_dport are the remote endpoint (peer)
	if (sk) {
		u16 family;
		bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);

		if (family == AF_INET) {
			info.af = NETWORK_AF_INET;
			u32 addr;
			bpf_probe_read_kernel(&addr, sizeof(addr), &sk->__sk_common.skc_daddr);
			__builtin_memcpy(info.peer_addr, &addr, 4);
			bpf_probe_read_kernel(&info.peer_port, sizeof(info.peer_port),
					      &sk->__sk_common.skc_dport);
			info.peer_port = __builtin_bswap16(info.peer_port);
		} else if (family == AF_INET6) {
			// Note: IPv4-mapped IPv6 addresses (::ffff:192.0.2.1) are stored as IPv6.
			// This preserves the actual socket family for accurate connection tracking.
			info.af = NETWORK_AF_INET6;
			bpf_probe_read_kernel(info.peer_addr, 16, &sk->__sk_common.skc_v6_daddr);
			bpf_probe_read_kernel(&info.peer_port, sizeof(info.peer_port),
					      &sk->__sk_common.skc_dport);
			info.peer_port = __builtin_bswap16(info.peer_port);
		}
	}

	bpf_map_update_elem(&pending_network_recvs, &tgidpid, &info, BPF_ANY);

	return 0;
}

static int handle_recvmsg_exit(void *ctx, int ret)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

	if (!trace_task(task))
		return 0;

	// Only record successful receives
	if (ret <= 0)
		return 0;

	u64 tgidpid = bpf_get_current_pid_tgid();
	struct network_recv_info *info = bpf_map_lookup_elem(&pending_network_recvs, &tgidpid);

	if (!info) {
		// No matching entry, skip
		return 0;
	}

	// For UDP: skip if peer address wasn't successfully extracted (peer_port will be 0)
	// This can happen if __skb_recv_udp returned NULL
	if (info->protocol == NETWORK_UDP && info->peer_port == 0) {
		bpf_map_delete_elem(&pending_network_recvs, &tgidpid);
		return 0;
	}

	struct network_event *event = reserve_network_event();
	if (!event) {
		bpf_map_delete_elem(&pending_network_recvs, &tgidpid);
		return handle_missed_event(MISSED_NETWORK_EVENT);
	}

	event->start_ts = info->start_ts;
	event->end_ts = bpf_ktime_get_boot_ns();
	event->cpu = bpf_get_smp_processor_id();
	record_task_info(&event->task, task);
	event->protocol = info->protocol;
	event->operation = NETWORK_RECV;
	event->af = info->af;
	event->bytes = (u32)ret;  // Return value is number of bytes received

	// Use the peer address that was extracted in the entry handler
	__builtin_memcpy(event->dest_addr, info->peer_addr, 16);
	event->dest_port = info->peer_port;

	bpf_ringbuf_submit(event, 0);
	bpf_map_delete_elem(&pending_network_recvs, &tgidpid);

	return 0;
}

SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(tcp_recvmsg_entry, struct sock *sk, struct msghdr *msg, size_t len, int flags)
{
	return handle_tcp_recvmsg_entry(sk, msg);
}

SEC("kretprobe/tcp_recvmsg")
int BPF_KRETPROBE(tcp_recvmsg_exit, int ret)
{
	return handle_recvmsg_exit(ctx, ret);
}

// Store timing info for UDP receives on entry
SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(udp_recvmsg_entry, struct sock *sk, struct msghdr *msg, size_t len, int flags)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

	if (!trace_task(task))
		return 0;

	u64 tgidpid = bpf_get_current_pid_tgid();
	struct network_recv_info info = {0};

	info.protocol = NETWORK_UDP;
	info.start_ts = bpf_ktime_get_boot_ns();
	info.af = NETWORK_AF_INET;  // Default to IPv4
	// Peer address/port will be extracted from sk_buff headers by __skb_recv_udp kretprobe

	bpf_map_update_elem(&pending_network_recvs, &tgidpid, &info, BPF_ANY);

	return 0;
}

// Capture the sk_buff when __skb_recv_udp returns it
SEC("kretprobe/__skb_recv_udp")
int BPF_KRETPROBE(skb_recv_udp_exit, struct sk_buff *skb)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

	if (!trace_task(task))
		return 0;

	if (!skb)
		return 0;

	u64 tgidpid = bpf_get_current_pid_tgid();
	struct network_recv_info *info = bpf_map_lookup_elem(&pending_network_recvs, &tgidpid);

	if (!info || info->protocol != NETWORK_UDP)
		return 0;

	// Extract headers from the sk_buff
	unsigned char *head = NULL;
	u16 network_header = 0;
	u16 transport_header = 0;

	bpf_probe_read_kernel(&head, sizeof(head), &skb->head);
	bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header);
	bpf_probe_read_kernel(&transport_header, sizeof(transport_header), &skb->transport_header);

	if (head) {
		// First, determine IP version by reading the first byte
		u8 ip_version = 0;
		bpf_probe_read_kernel(&ip_version, sizeof(ip_version), head + network_header);
		ip_version = (ip_version >> 4) & 0x0F;

		if (ip_version == 4) {
			// IPv4
			struct iphdr ip = {0};
			struct udphdr udp = {0};

			info->af = NETWORK_AF_INET;

			// Read IP header to get source address (peer who sent to us)
			if (bpf_probe_read_kernel(&ip, sizeof(ip), head + network_header) == 0) {
				__builtin_memcpy(info->peer_addr, &ip.saddr, 4);
			}

			// Read UDP header to get source port (peer port)
			if (bpf_probe_read_kernel(&udp, sizeof(udp), head + transport_header) == 0) {
				info->peer_port = __builtin_bswap16(udp.source);
			}
		} else if (ip_version == 6) {
			// IPv6
			struct ipv6hdr ip6 = {0};
			struct udphdr udp = {0};

			info->af = NETWORK_AF_INET6;

			// Read IPv6 header to get source address
			if (bpf_probe_read_kernel(&ip6, sizeof(ip6), head + network_header) == 0) {
				__builtin_memcpy(info->peer_addr, &ip6.saddr, 16);
			}

			// Read UDP header to get source port
			if (bpf_probe_read_kernel(&udp, sizeof(udp), head + transport_header) == 0) {
				info->peer_port = __builtin_bswap16(udp.source);
			}
		}
	}

	return 0;
}

SEC("kretprobe/udp_recvmsg")
int BPF_KRETPROBE(udp_recvmsg_exit, int ret)
{
	return handle_recvmsg_exit(ctx, ret);
}

char LICENSE[] SEC("license") = "GPL";
