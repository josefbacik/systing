// Copyright (c) Meta Platforms, Inc. and affiliates.

#ifndef __BPF_LIB_PTHREAD_HELPERS_H__
#define __BPF_LIB_PTHREAD_HELPERS_H__

#include <vmlinux.h>

int probe_read_pthread_tls_slot(
    uint32_t key,
    void** value,
    struct task_struct* task);

#endif // __BPF_LIB_PTHREAD_HELPERS_H__
