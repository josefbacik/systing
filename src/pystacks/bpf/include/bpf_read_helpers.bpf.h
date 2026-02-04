// Copyright (c) Meta Platforms, Inc. and affiliates.

#ifndef __BPF_LIB_READ_HELPERS_H__
#define __BPF_LIB_READ_HELPERS_H__

// clang-format off
// disable format as bpf_core_read.h relies on types from vmlinux.h
#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
// clang-format on

// Reading from task memory support
long bpf_probe_read_user_task(
    void* dst,
    u32 size,
    const void* unsafe_ptr,
    struct task_struct* task);

long bpf_probe_read_user_str_task(
    void* dst,
    u32 size,
    const void* unsafe_ptr,
    struct task_struct* task);

static inline void memset_zero(void* s, size_t len) {
  // efficient way to zero out memory of arbitrary length in BPF
  bpf_probe_read_kernel(s, len, NULL);
}

static inline void* memcpy(void* dst, const void* src, size_t len) {
  bpf_probe_read_kernel(dst, len, src);
  return dst;
}

#endif // __BPF_LIB_READ_HELPERS_H__
