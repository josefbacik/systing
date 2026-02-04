// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpf_read_helpers.bpf.h"
#include "task_helpers.bpf.h"

__hidden inline long bpf_probe_read_user_task(
    void* dst,
    u32 size,
    const void* unsafe_ptr,
    struct task_struct* task) {
  if (!task || is_current_task(task)) {
    return bpf_probe_read_user(dst, size, unsafe_ptr);
  }

#ifdef STROBELIGHT_SLEEPABLE_BPF
  return bpf_copy_from_user_task(dst, size, unsafe_ptr, task, 0);
#else // STROBELIGHT_SLEEPABLE_BPF

  // This should never happen as it means we are calling
  // bpf_probe_read_user_task with a task from a non-sleepable program.
  // Verifier fails in this case.
  return -1;
#endif // STROBELIGHT_SLEEPABLE_BPF
}

__hidden inline long bpf_probe_read_user_str_task(
    void* dst,
    u32 size,
    const void* unsafe_ptr,
    struct task_struct* task) {
  if (!task || is_current_task(task)) {
    return bpf_probe_read_user_str(dst, size, unsafe_ptr);
  }

#ifdef STROBELIGHT_SLEEPABLE_BPF
  int ret = bpf_copy_from_user_task(dst, size, unsafe_ptr, task, 0);
  if (ret) {
    return ret;
  }
  return bpf_probe_read_kernel_str(dst, size, dst);
#else // STROBELIGHT_SLEEPABLE_BPF
  // This should never happen as it means we are calling
  // bpf_probe_read_user_task with a task from a non-sleepable program.
  // Verifier fails in this case.
  return -1;
#endif // STROBELIGHT_SLEEPABLE_BPF
}
