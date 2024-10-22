#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#define TASK_RUNNING 0
#define TASK_INTERRUPTIBLE 1
#define TASK_UNINTERRUPTIBLE 2
#define TASK_STATE_MASK 3

#define TASK_COMM_LEN 16

const volatile struct {
	gid_t tgid;
	u64 cgroupid;
} tool_config = {};

enum stat_type {
	STAT_SLEEP_TIME,
	STAT_PREEMPT_TIME,
	STAT_RUN_TIME,
	STAT_WAIT_TIME,
	STAT_QUEUE_TIME,
	STAT_MAX,
};

struct task_state_value {
	u64 ts;
	u32 state;
	bool preempt;
};

struct task_stat {
	u8 comm[TASK_COMM_LEN];
	u64 sleep_time;
	u64 preempt_time;
	u64 run_time;
	u64 wait_time;
	u64 queue_time;
};

struct preempt_event {
	u8 comm[TASK_COMM_LEN];
	u64 tgidpid;
	u64 preempt_tgidpid;
	u64 cgid;
};

/*
 * Dummy instance to get skeleton to generate definition for
 * `struct preempt_event`
 */
struct preempt_event _event = {0};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct task_state_value);
	__uint(max_entries, 10240);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct task_stat);
	__uint(max_entries, 10240);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u8);
	__uint(max_entries, 10240);
} ignore_pids SEC(".maps");

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
int trace_enqueue(struct task_struct *tsk, u32 state, bool preempt)
{
	u64 key = (u64)tsk->tgid << 32 | tsk->pid;
	u32 tgid = tsk->tgid;
	struct task_state_value value;

	if (bpf_map_lookup_elem(&ignore_pids, &tgid))
		return 0;
	if (tool_config.tgid && tsk->tgid != tool_config.tgid)
		return 0;
	if (tool_config.cgroupid && task_cg_id(tsk) != tool_config.cgroupid)
		return 0;
	value.ts = bpf_ktime_get_ns();
	value.state = state;
	value.preempt = preempt;
	bpf_map_update_elem(&start, &key, &value, BPF_ANY);
	return 0;
}

static struct task_stat zero_stat = {};

static __always_inline
void update_counter(struct task_struct *task, u64 delta, enum stat_type type)
{
	u64 key = (u64)task->tgid << 32 | task->pid;
	struct task_stat *stat;

	stat = bpf_map_lookup_elem(&stats, &key);
	if (!stat) {
		bpf_map_update_elem(&stats, &key, &zero_stat, BPF_ANY);

		stat = bpf_map_lookup_elem(&stats, &key);
		if (!stat)
			return;
		bpf_probe_read_kernel_str(stat->comm, sizeof(stat->comm),
					  task->comm);
	}

	switch (type) {
	case STAT_SLEEP_TIME:
		__sync_fetch_and_add(&stat->sleep_time, delta);
		break;
	case STAT_PREEMPT_TIME:
		__sync_fetch_and_add(&stat->preempt_time, delta);
		break;
	case STAT_RUN_TIME:
		__sync_fetch_and_add(&stat->run_time, delta);
		break;
	case STAT_WAIT_TIME:
		__sync_fetch_and_add(&stat->wait_time, delta);
		break;
	case STAT_QUEUE_TIME:
		__sync_fetch_and_add(&stat->queue_time, delta);
		break;
	default:
		break;
	}
}

SEC("tp_btf/sched_wakeup")
int handle__sched_wakeup(u64 *ctx)
{
	/* TP_PROTO(struct task_struct *p) */
	struct task_struct *task = (struct task_struct *)ctx[0];
	u64 key = (u64)task->tgid << 32 | task->pid;
	struct task_state_value *value;

	value = bpf_map_lookup_elem(&start, &key);
	if (value) {
		u64 delta = bpf_ktime_get_ns() - value->ts;
		switch (value->state) {
		case TASK_INTERRUPTIBLE:
			update_counter(task, delta, STAT_SLEEP_TIME);
			break;
		case TASK_UNINTERRUPTIBLE:
			update_counter(task, delta, STAT_WAIT_TIME);
			break;
		default:
			break;
		}
	}
	return trace_enqueue(task, TASK_RUNNING, false);
}

SEC("tp_btf/sched_wakeup_new")
int handle__sched_wakeup_new(u64 *ctx)
{
	/* TP_PROTO(struct task_struct *p) */
	struct task_struct *task = (void *)ctx[0];
	return trace_enqueue(task, TASK_RUNNING, false);
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
	u64 key = (u64)prev->tgid << 32 | prev->pid;
	u64 ts = bpf_ktime_get_ns();
	struct task_state_value *value;

	value = bpf_map_lookup_elem(&start, &key);
	if (value) {
		u64 delta = ts - value->ts;
		update_counter(prev, delta, STAT_RUN_TIME);
	}
	trace_enqueue(prev, prev_state, prev_state == TASK_RUNNING);

	if (prev_state == TASK_RUNNING) {
		struct preempt_event *e;

		e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
		if (e) {
			e->tgidpid = key;
			e->cgid = task_cg_id(next);
			e->preempt_tgidpid = (u64)next->tgid << 32 | next->pid;
			bpf_probe_read_kernel_str(e->comm, sizeof(e->comm),
						  next->comm);
			bpf_ringbuf_submit(e, 0);
		}
	}

	key = (u64)next->tgid << 32 | next->pid;
	value = bpf_map_lookup_elem(&start, &key);
	if (value) {
		u64 delta = ts - value->ts;
		if (value->preempt)
			update_counter(next, delta, STAT_PREEMPT_TIME);
		else
			update_counter(next, delta, STAT_QUEUE_TIME);
	}
	trace_enqueue(next, next_state, false);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
