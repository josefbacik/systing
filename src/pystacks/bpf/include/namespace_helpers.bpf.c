// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "namespace_helpers.bpf.h"
#include "task_helpers.bpf.h"

__hidden struct pid_namespace* get_task_pid_ns(const struct task_struct* task) {
  // See kernel function task_active_pid_ns in pid.c which calls into ns_of_pid.
  // Returns the pid namespace of the given task.
  if (!task) {
    task = bpf_get_current_task_btf();
  }
  if (!task) {
    return NULL;
  }
  struct pid* p = get_task_pid_ptr(task, PIDTYPE_TGID);
  if (!p) {
    return NULL;
  }
  struct pid_namespace* ns;
  int level;
  level = BPF_CORE_READ(p, level);
  ns = BPF_CORE_READ(p, numbers[level].ns);
  return ns;
}

__hidden pid_t get_pid_nr_ns(struct pid* pid, struct pid_namespace* ns) {
  /* This function implements the kernel equivalent pid_nr_ns in linux/pid.h */
  pid_t nr = 0;
  if (!pid || !ns) {
    return nr;
  }
  int level = BPF_CORE_READ(pid, level);
  int ns_level = BPF_CORE_READ(ns, level);

  if (ns_level <= level) {
    struct upid upid;
    upid = BPF_CORE_READ(pid, numbers[ns_level]);
    if (upid.ns == ns) {
      nr = upid.nr;
    }
  }
  return nr;
}

static __always_inline pid_t
get_task_ns_pid_type(const struct task_struct* task, enum pid_type type) {
  if (!task) {
    task = bpf_get_current_task_btf();
  }
  struct pid_namespace* ns = get_task_pid_ns(task);
  struct pid* p = get_task_pid_ptr(task, type);
  return get_pid_nr_ns(p, ns);
}

__hidden pid_t get_task_ns_tgid(const struct task_struct* task) {
  return get_task_ns_pid_type(task, PIDTYPE_TGID);
}

__hidden pid_t get_task_ns_pid(const struct task_struct* task) {
  return get_task_ns_pid_type(task, PIDTYPE_PID);
}

pid_t get_ns_pid(void) {
  return get_task_ns_pid(NULL);
}
