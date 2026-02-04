// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "pid_target_helpers.bpf.h"
#include "task_helpers.bpf.h"

#ifndef BPF_LIB_MAX_PID_TARGETS
#define BPF_LIB_MAX_PID_TARGETS 1024
#endif // BPF_LIB_MAX_PID_TARGETS

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, BPF_LIB_MAX_PID_TARGETS);
  __type(key, pid_t);
  __type(value, bool);
} targeted_pids SEC(".maps");

volatile struct {
  pid_t targeted_pid; // if targeting 1 pid, this is cheaper than map lookup
  bool has_targeted_pids; // use the map for lookup vs target all pids
  int self_pid;
  bool filter_self;

  bool filter_kernel_threads;
} pid_target_helpers_prog_cfg = {};

__hidden bool profile_pid_task(pid_t pid, struct task_struct* task) {
  // For profilers that only target a single process (e.g. Crochet,
  // FunctionTracer) we can avoid the map lookup below, which is
  // beneficial for high-frequency events
  if (pid_target_helpers_prog_cfg.targeted_pid > 0) {
    return pid == pid_target_helpers_prog_cfg.targeted_pid;
  }
  if (pid_target_helpers_prog_cfg.has_targeted_pids) {
    return bpf_map_lookup_elem(&targeted_pids, &pid) != NULL;
  }

  // ignore samples from strobelight itself
  if (pid_target_helpers_prog_cfg.filter_self &&
      pid == pid_target_helpers_prog_cfg.self_pid) {
    return false;
  }
  // ignore samples from kernel threads
  if (pid_target_helpers_prog_cfg.filter_kernel_threads &&
      is_kernel_thread(task)) {
    return false;
  }

  return true;
}

bool profile_pid(pid_t pid) {
  return profile_pid_task(pid, bpf_get_current_task_btf());
};
