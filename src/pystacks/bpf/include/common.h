// Copyright (c) Meta Platforms, Inc. and affiliates.

#ifndef __STROBELIGHT_BPF_LIB_COMMON_H__
#define __STROBELIGHT_BPF_LIB_COMMON_H__

#ifndef __cplusplus
#include <vmlinux.h>
#else
#include <linux/bpf.h>
#include <ostream>
#endif

// from <linux/sched.h>
#define BPF_LIB_PF_IDLE 0x00000002 /* I am an IDLE thread */
#define BPF_LIB_PF_KTHREAD 0x00200000 /* I am a kernel thread */

#define BPF_LIB_MIN_USER_SPACE_ADDRESS ((uintptr_t)0x1000)
#ifdef __x86_64__
// https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt
#define BPF_LIB_MAX_USER_SPACE_ADDRESS ((uintptr_t)0x00ffffffffffffff)
#elif defined(__aarch64__)
// https://www.kernel.org/doc/Documentation/arm64/memory.txt
#define BPF_LIB_MAX_USER_SPACE_ADDRESS ((uintptr_t)0x0000007fffffffff)
#else
#error Unsupported architecture
#endif

#define IS_VALID_USER_SPACE_ADDRESS(addr)                 \
  (((uintptr_t)addr) >= BPF_LIB_MIN_USER_SPACE_ADDRESS && \
   ((uintptr_t)addr) <= BPF_LIB_MAX_USER_SPACE_ADDRESS)

extern int32_t zero;

#endif // __STROBELIGHT_BPF_LIB_COMMON_H__
