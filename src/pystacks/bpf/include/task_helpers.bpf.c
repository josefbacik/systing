// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "task_helpers.bpf.h"

struct task_struct* bpf_task_from_pid(s32 pid) __ksym __weak;
void bpf_task_release(struct task_struct* p) __ksym __weak;

__hidden int get_task(int pid, struct task_struct** task) {
  struct task_struct* t;

#ifdef STROBELIGHT_SLEEPABLE_BPF
  t = bpf_task_from_pid(pid);
  if (!t) {
    /* failure, sleepable, NULL task means error, caller should bail out */
    *task = NULL;
    return -1;
  }

  /* sleepable, success, guaranteed to have non-NULL task */
  *task = t;
  return 0;
#else // STROBELIGHT_SLEEPABLE_BPF
  /* non-sleepable, success and NULL task is expected */
  *task = NULL;
  return 0;
#endif // STROBELIGHT_SLEEPABLE_BPF
}

__hidden void put_task(struct task_struct* task) {
#ifdef STROBELIGHT_SLEEPABLE_BPF
  bpf_task_release(task);
#endif // STROBELIGHT_SLEEPABLE_BPF
}

__hidden struct task_struct* get_current_task(struct task_struct* task) {
  return task ? task : bpf_get_current_task_btf();
}

__hidden struct pid* get_task_pid_ptr(
    const struct task_struct* task,
    enum pid_type type) {
  // Returns the pid pointer of the given task. See get_task_pid_ptr for the
  // kernel implementation.
  return (type == PIDTYPE_PID) ? BPF_CORE_READ(task, thread_pid)
                               : BPF_CORE_READ(task, signal, pids[type]);
}

/* The task struct changed the type of state in v514. In order to interpret the
 * data correctly, we define a struct in both ways, and check if the old field
 * exists in the kernel. We then read the field using the approriate struct
 * based on that result.
 */
struct task_struct___post514 {
  unsigned int __state;
} __attribute__((preserve_access_index));

struct task_struct___pre514 {
  long state;
} __attribute__((preserve_access_index));

__hidden unsigned int get_task_state(void* arg) {
  // Report task state similar to how the kernel does it for
  // /proc/<pid>/status.
  // https://elixir.bootlin.com/linux/v6.0/source/include/linux/sched.h#L1680
  unsigned int task_state;
  if (bpf_core_field_exists(((struct task_struct___pre514*)NULL)->state)) {
    struct task_struct___pre514* task = arg;
    task_state = task->state;
  } else {
    struct task_struct___post514* task = arg;
    task_state = task->__state;
  }
  unsigned int task_exit_state = ((struct task_struct*)arg)->exit_state;
  return task_state | task_exit_state;
}
