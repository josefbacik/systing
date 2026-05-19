// Copyright (c) Meta Platforms, Inc. and affiliates.

#ifndef __PYSTACKS_BPF_H__
#define __PYSTACKS_BPF_H__

#include <vmlinux.h>

#include "common.h"
#include "py_structs.h"

#define BPF_LIB_FILE_NAME_TRYGET 256

enum {
  PYSTACKS_STATUS_UNKNOWN = 0,
  PYSTACKS_STATUS_COMPLETE = 1,
  PYSTACKS_STATUS_ERROR = 2,
  PYSTACKS_STATUS_TRUNCATED = 3,
};

enum {
  PYSTACKS_GIL_STATE_NO_INFO = 0,
  PYSTACKS_GIL_STATE_ERROR = 1,
  PYSTACKS_GIL_STATE_UNINITIALIZED = 2,
  PYSTACKS_GIL_STATE_NOT_LOCKED = 3,
  PYSTACKS_GIL_STATE_THIS_THREAD = 4,
  PYSTACKS_GIL_STATE_GLOBAL_CURRENT_THREAD = 5,
  PYSTACKS_GIL_STATE_OTHER_THREAD = 6,
  PYSTACKS_GIL_STATE_NULL = 7,
};

// Possible result for pthread ID matching
enum {
  PYSTACKS_PTHREAD_ID_UNKNOWN = 0,
  PYSTACKS_PTHREAD_ID_MATCH = 1,
  PYSTACKS_PTHREAD_ID_MISMATCH = 2,
  PYSTACKS_PTHREAD_ID_THREAD_STATE_NULL = 3,
  PYSTACKS_PTHREAD_ID_NULL = 4,
  PYSTACKS_PTHREAD_ID_NOT_USING_TLS = 5,
  PYSTACKS_PTHREAD_ID_ERROR = 6,
};

enum {
  PYSTACKS_THREAD_STATE_UNKNOWN = 0,
  PYSTACKS_THREAD_STATE_MATCH = 1,
  PYSTACKS_THREAD_STATE_MISMATCH = 2,
  PYSTACKS_THREAD_STATE_THIS_THREAD_NULL = 3,
  PYSTACKS_THREAD_STATE_GLOBAL_CURRENT_THREAD_NULL = 4,
  PYSTACKS_THREAD_STATE_BOTH_NULL = 5,
  PYSTACKS_THREAD_STATE_NOT_USING_TLS = 6,
};

int pystacks_read_stacks(
    struct pt_regs* ctx,
    struct task_struct* task,
    struct pystacks_message* py_msg_buffer);

/* Propagate the parent's pystacks pid configuration to a forked child.
 *
 * Forked children share the parent's address space (CoW) until they exec, so
 * the parent's PyPidData (struct offsets, _PyRuntime address, TLS key, ...)
 * is valid for the child too. Without this, every fork() of a Python process
 * (multiprocessing workers, gunicorn pre-forks, plain os.fork()) gets a fresh
 * tgid that fails the targeted_pids / pystacks_pid_config lookups and silently
 * drops every Python stack for the child.
 *
 * Returns true if the parent was a registered Python process and the config
 * was propagated. Threads (same tgid) are a no-op and return false.
 */
bool pystacks_propagate_fork(pid_t parent_pid, pid_t child_pid);

/* Drop a pid from the pystacks targeting maps. Called on exec: the address
 * space (and any inherited PyPidData) is replaced, so the cached config is
 * stale. The exec event handler in userspace re-discovers the new binary and
 * re-registers if it is still Python. Without this cleanup, fork+exec from a
 * Python parent (subprocess.Popen) leaks a stale entry per call and steadily
 * fills the bounded pid maps. Safe to call for pids that were never registered.
 */
void pystacks_clear_pid(pid_t pid);

struct pystacks_msg_heap_map {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct pystacks_message);
};

extern struct pystacks_msg_heap_map pystacks_msg_heap SEC(".maps");

struct pystacks_message* pystacks_get_msg(void);

#endif
