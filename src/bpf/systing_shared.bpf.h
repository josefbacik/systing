/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Definitions shared by systing's BPF objects: systing_system.bpf.c and
 * task_stacks.bpf.c (see there for why that one is a separate object).
 *
 * The --pid / --cgroup target filter is compiled into each object, but there
 * is one set of target maps at runtime: userspace points every other object's
 * target maps at the main object's before loading it (TargetFilterMaps in
 * src/target_filter.rs), so all of them read the one live target set,
 * children added at fork included. Defining the maps once, here, keeps the
 * objects' definitions compatible for that. The target_filter rodata is per
 * object; userspace fills each copy from one TargetFilter.
 */
#ifndef __SYSTING_SHARED_BPF_H
#define __SYSTING_SHARED_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/* Each object includes the whole filter and uses part of it. */
#define __systing_maybe_unused __attribute__((unused))

#define TASK_COMM_LEN 16

/*
 * Per-task identity shipped inline with every event that references a task.
 *
 * cgid (the task's cgroup id) is constant per task and is ultimately consumed
 * only once, when userspace first creates the process record. It is nonetheless
 * carried inline here - rather than via a separate BPF-populated map read at
 * finalize - to stay consistent with comm, which is already shipped inline the
 * same way. The cost is 8 bytes per task_info (so +16 bytes on sched_switch's
 * task_event, which embeds prev+next). If event size ever becomes a concern,
 * comm and cgid should move to a per-task metadata map together rather than
 * splitting the two.
 */
struct task_info {
	u64 tgidpid;
	u64 cgid;
	u8 comm[TASK_COMM_LEN];
};

const volatile struct target_filter_config {
	u32 filter_pid;
	u32 filter_cgroup;
	u32 num_cgroup_targets; /* --cgroup arguments = filled slots of the
				 * cgroup_targets / cgroup_target_refs maps;
				 * rodata so the filter loops are
				 * verifier-bounded. */
	u32 cgroup_match_kernel; /* 1: the kernel decides --cgroup membership
				  * (cgroup_targets / cgroup_target_refs);
				  * 0: legacy exact match of the task's own
				  * cgroup id against the cgroups map (see the
				  * map comments). Rodata, so the branch not
				  * taken is dead code to the verifier. */
} target_filter = {0};

/*
 * --cgroup filter targets: one slot per --cgroup argument in each of the two
 * maps below, both filled by userspace before tracing starts and only ever
 * READ from the tracing programs (no BPF-side writer in any program that runs
 * in NMI or IRQ context, nothing LRU). Sized by userspace to the number of
 * --cgroup arguments, at most MAX_CGROUP_TARGETS.
 *
 * The matching is the kernel's own: task_under_cgroup_hierarchy(), "is the
 * task's cgroup the target or somewhere below it", which is what makes
 * cgroups created AFTER the trace started (a nested container runtime making
 * cgroups inside a pod, a transient systemd scope) match too. Two entry
 * points into it exist and we need both:
 *
 *   cgroup_targets      BPF_MAP_TYPE_CGROUP_ARRAY of the target directory fds
 *                       (the kernel holds a cgroup reference per slot).
 *                       bpf_current_task_under_cgroup(map, idx) tests CURRENT
 *                       against a slot: a READ_ONCE of the slot plus an
 *                       ancestors[] compare, lock-free and NMI-safe, available
 *                       to every tracing program type since 4.8. trace_task()
 *                       uses it - all of its callers outside the sched
 *                       tracepoints pass current.
 *
 *   cgroup_target_refs  the same targets as referenced struct cgroup kptrs,
 *                       for bpf_task_under_cgroup(task, cgrp) on a task that
 *                       is NOT current: the switched-in task, a woken task, a
 *                       migrating one. Only TRACING programs (tp_btf) may call
 *                       that kfunc on 6.6 and 6.12 kernels - 6.6 registers the
 *                       generic kfuncs for TRACING alone, 6.12 adds tracepoint
 *                       and perf_event but never kprobe or raw_tracepoint - so
 *                       it cannot replace the helper above, and the kfunc
 *                       needs a trusted cgroup pointer, which
 *                       bpf_cgroup_from_id() must not produce from IRQ or NMI
 *                       context (it takes kernfs_idr_lock on 6.6). The
 *                       references are therefore taken once, in process
 *                       context, by systing_cgroup_target_add (in
 *                       systing_system.bpf.c) and read
 *                       under bpf_rcu_read_lock() by task_in_cgroup_filter().
 */
#define MAX_CGROUP_TARGETS 64

struct cgroup_target_ref {
	struct cgroup __kptr *cgrp;
	u64 id; /* the target's cgroup id (kn->id), set with the reference so
		 * userspace can confirm the slot was filled */
};

struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} cgroup_targets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct cgroup_target_ref);
	__uint(max_entries, 1);
} cgroup_target_refs SEC(".maps");

/*
 * Legacy --cgroup matching, used when the running kernel's BTF does not
 * export bpf_task_under_cgroup (before 6.5) or when SYSTING_CGROUP_FILTER_LEGACY
 * forces it: userspace loads the cgroup ids of each target and of every
 * descendant that exists when the trace starts, sized to that count, and the
 * tracing programs match the task's own cgroup id against the set exactly.
 * Cgroups created under a target after the trace started are not in the set
 * and their tasks are not traced - the limitation the kernel-side matching
 * above removes. Written by userspace only, lookup-only from BPF.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, u8);
	__uint(max_entries, 1);
} cgroups SEC(".maps");

/*
 * --pid targets (tgids, the traced command's included): filled by userspace,
 * grown at fork by the main object's sched_process_fork program.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u8);
	__uint(max_entries, 10240);
} pids SEC(".maps");

static __systing_maybe_unused u64 task_cg_id(struct task_struct *task)
{
	struct cgroup *cgrp = task->cgroups->dfl_cgrp;
	return cgrp->kn->id;
}

/*
 * --cgroup filter for the CURRENT task, from any program type. The helper runs
 * the kernel's task_under_cgroup_hierarchy() on current against each target
 * slot of cgroup_targets (see the map comment): 1 when current's cgroup is the
 * target or below it, 0 when not, negative for an unfilled slot. Lock-free and
 * NMI-safe, so the perf_event sampler may call it like everything else.
 */
static __systing_maybe_unused bool current_in_cgroup_filter(void)
{
	for (u32 i = 0; i < MAX_CGROUP_TARGETS; i++) {
		if (i >= target_filter.num_cgroup_targets)
			break;
		if (bpf_current_task_under_cgroup(&cgroup_targets, i) == 1)
			return true;
	}
	return false;
}

/*
 * --cgroup filter for ANY task, from tp_btf and iterator programs only: the
 * sched tracepoints test tasks other than current (the switched-in task, a
 * woken task, a migrating one), the task iterator every task it visits. bpf_task_under_cgroup() is the same kernel predicate
 * as the helper above, taking the task and a trusted cgroup pointer; the
 * pointer is the reference systing_cgroup_target_add parked in
 * cgroup_target_refs, loaded under bpf_rcu_read_lock() (struct cgroup is an
 * RCU-protected kptr type, so the verifier accepts the load as trusted for
 * this KF_RCU kfunc). The rcu section holds no lock and takes no reference:
 * one map lookup and one ancestors[] compare per target.
 *
 * Kernels without the kfunc (< 6.5) never get here - userspace selects the
 * legacy snapshot matching on them (target_filter.cgroup_match_kernel == 0,
 * see task_in_legacy_cgroup_set) - and bpf_ksym_exists() keeps every program
 * that inlines this loadable there.
 */
static __systing_maybe_unused bool task_in_cgroup_filter(struct task_struct *task)
{
	bool hit = false;

	if (!bpf_ksym_exists(bpf_task_under_cgroup))
		return false;

	bpf_rcu_read_lock();
	for (u32 i = 0; i < MAX_CGROUP_TARGETS && !hit; i++) {
		struct cgroup_target_ref *ref;
		struct cgroup *cgrp;
		/* A separate key keeps the loop counter in a register; passing &i
		 * to the lookup spills it and the verifier loses its bound. */
		u32 key = i;

		if (i >= target_filter.num_cgroup_targets)
			break;
		ref = bpf_map_lookup_elem(&cgroup_target_refs, &key);
		if (!ref)
			break;
		cgrp = ref->cgrp;
		if (cgrp && bpf_task_under_cgroup(task, cgrp) == 1)
			hit = true;
	}
	bpf_rcu_read_unlock();
	return hit;
}

/*
 * Legacy --cgroup matching (cgroup_match_kernel == 0): the task's own cgroup
 * id looked up in the start-time set userspace loaded into the cgroups map.
 * Any program type, any kernel; misses cgroups created after the trace
 * started (see the cgroups map comment).
 */
static __systing_maybe_unused bool task_in_legacy_cgroup_set(struct task_struct *task)
{
	u64 cgid = task_cg_id(task);
	return bpf_map_lookup_elem(&cgroups, &cgid) != NULL;
}

/* --pid: the task's process is a target. Any program type. */
static __systing_maybe_unused bool task_in_target_pids(struct task_struct *task)
{
	u32 pid = task->tgid;

	return !target_filter.filter_pid ||
	       bpf_map_lookup_elem(&pids, &pid) != NULL;
}

/*
 * --pid and --cgroup for a task that need not be current. The kernel-mode
 * --cgroup test is bpf_task_under_cgroup(), so tp_btf and iterator programs
 * only (see task_in_cgroup_filter()).
 */
static __systing_maybe_unused bool task_in_target_set(struct task_struct *task)
{
	if (!task_in_target_pids(task))
		return false;
	if (target_filter.filter_cgroup) {
		if (target_filter.cgroup_match_kernel)
			return task_in_cgroup_filter(task);
		return task_in_legacy_cgroup_set(task);
	}
	return true;
}

#endif /* __SYSTING_SHARED_BPF_H */
