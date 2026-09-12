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
// https://www.kernel.org/doc/Documentation/arch/arm64/memory.rst
// arm64 distribution kernels give user space 48 bits (4KB pages + 4
// levels: 0x0000000000000000 - 0x0000ffffffffffff), and up to 52 bits with
// CONFIG_ARM64_VA_BITS_52 (0x000fffffffffffff); the smaller 39- and 42-bit
// configurations fit under the same bound, so it is the 52-bit maximum.
// Kernel addresses always sit at 0xfff0000000000000 and above, so nothing
// kernel-side passes this check. The previous value, 0x0000007fffffffff,
// was the 39-bit (4KB pages + 3 levels) layout, under which every pointer
// in the mmap region (0x0000ffff........) and every PIE executable
// (0x0000aaaa........) of a 48-bit process read as invalid.
#define BPF_LIB_MAX_USER_SPACE_ADDRESS ((uintptr_t)0x000fffffffffffff)
#elif defined(__riscv64__)
// https://www.kernel.org/doc/Documentation/riscv/vm-layout.rst
#define BPF_LIB_MAX_USER_SPACE_ADDRESS ((uintptr_t)0x00ffffffffffffff)
#else
#error Unsupported architecture
#endif

#define IS_VALID_USER_SPACE_ADDRESS(addr)                 \
  (((uintptr_t)addr) >= BPF_LIB_MIN_USER_SPACE_ADDRESS && \
   ((uintptr_t)addr) <= BPF_LIB_MAX_USER_SPACE_ADDRESS)

extern int32_t zero;

#endif // __STROBELIGHT_BPF_LIB_COMMON_H__
