// Copyright (c) Meta Platforms, Inc. and affiliates.

#ifndef __BPF_LIB_TASK_HELPERS_H__
#define __BPF_LIB_TASK_HELPERS_H__

#include "common.h"

#include <vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h> /* most used helpers: SEC, __always_inline, etc */

static __always_inline bool is_current_task(struct task_struct* task) {
  return ((u64)BPF_CORE_READ(task, tgid) << 32 | BPF_CORE_READ(task, pid)) ==
      bpf_get_current_pid_tgid();
}

int get_task(int pid, struct task_struct** task);

void put_task(struct task_struct* task);

struct task_struct* get_current_task(struct task_struct* task);

struct pid* get_task_pid_ptr(
    const struct task_struct* task,
    enum pid_type type);

static __always_inline bool is_kernel_thread(struct task_struct* task) {
  return (BPF_CORE_READ(task, flags) &
          (BPF_LIB_PF_KTHREAD | BPF_LIB_PF_IDLE)) != 0;
}

unsigned int get_task_state(void* arg);

#endif // __BPF_LIB_TASK_HELPERS_H__
