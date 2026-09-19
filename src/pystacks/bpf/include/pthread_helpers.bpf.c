// Copyright (c) Meta Platforms, Inc. and affiliates.

#include <vmlinux.h>

#include "bpf_read_helpers.bpf.h"
#include "task_helpers.bpf.h"

/*
 * glibc's struct pthread, head-anchored: the three offsets the walker relies
 * on, per architecture. On x86-64 the thread pointer (fsbase) IS the
 * descriptor and its head is the full tcbhead_t (0x2c0 bytes); on the
 * TLS-variant-1 architectures (aarch64, riscv64) the thread pointer
 * addresses the 16-byte TCB, the descriptor sits at tp - sizeof(struct
 * pthread) — a tail-anchored distance that changes when glibc grows or
 * shrinks struct pthread (1856 bytes in glibc 2.36 vs 1824 in 2.41 on
 * aarch64) — and the head is the 24-pointer padding (192 bytes). After the
 * head, the same generic-nptl layout on all three: list_head (16), tid (4),
 * pid_ununsed (4), robust_prev (8), robust_head (24), cleanup (8),
 * cleanup_jmp_buf (8), cancelhandling (4), flags (4), specific_1stblock.
 */
#if __x86_64__
#define GLIBC_PTHREAD_TID_OFFSET 0x2d0
#define GLIBC_PTHREAD_ROBUST_HEAD_OFFSET 0x2e0
#define GLIBC_PTHREAD_SPECIFIC_1STBLOCK_OFFSET 0x310
#elif __aarch64__ || __riscv64__
#define GLIBC_PTHREAD_TID_OFFSET 0xd0
#define GLIBC_PTHREAD_ROBUST_HEAD_OFFSET 0xe0
#define GLIBC_PTHREAD_SPECIFIC_1STBLOCK_OFFSET 0x110
#else
#error "Unsupported platform"
#endif

/*
 * The descriptor of the current thread, or NULL when it is not laid out the
 * way the offsets above say.
 *
 * glibc registers two pointers INTO the descriptor with the kernel:
 * &pthread->tid as the clear-child-tid pointer (set_tid_address for the
 * main thread, CLONE_CHILD_CLEARTID for the others) and &pthread->robust_head
 * as the robust-list pointer (set_robust_list). Both sit at fixed
 * head-anchored offsets, so on x86-64 the thread pointer is the candidate
 * and on the TLS-variant-1 architectures the candidate is derived from the
 * clear-child-tid pointer; either way the candidate is trusted only when
 * both registered pointers sit where glibc puts them. A C library with
 * another layout registers the same two pointers from its own descriptor
 * (musl keeps them 0x58 apart — tid at 0x30 and the robust list at 0x88 on
 * x86-64, 0x20 and 0x78 on aarch64 — where glibc keeps them 0x10 apart), so
 * the check refuses it without reading a byte of user memory, and the
 * walker then reports no thread state instead of reading through the wrong
 * offsets.
 */
static __always_inline void* get_glibc_pthread_descriptor(
    const struct task_struct* cur_task) {
  void* clear_child_tid = (void*)BPF_PROBE_READ(cur_task, clear_child_tid);
  void* robust_list = (void*)BPF_PROBE_READ(cur_task, robust_list);
  if (!IS_VALID_USER_SPACE_ADDRESS(clear_child_tid) ||
      !IS_VALID_USER_SPACE_ADDRESS(robust_list)) {
    return NULL;
  }
#if __x86_64__
  void* descriptor = (void*)BPF_PROBE_READ(cur_task, thread.fsbase);
  if (!IS_VALID_USER_SPACE_ADDRESS(descriptor)) {
    return NULL;
  }
#else
  void* descriptor = (char*)clear_child_tid - GLIBC_PTHREAD_TID_OFFSET;
#endif
  if ((char*)clear_child_tid != (char*)descriptor + GLIBC_PTHREAD_TID_OFFSET ||
      (char*)robust_list != (char*)descriptor + GLIBC_PTHREAD_ROBUST_HEAD_OFFSET) {
    return NULL;
  }
  return descriptor;
}

static __always_inline void* get_glibc_specific1stblock(
    const struct task_struct* cur_task) {
  void* descriptor = get_glibc_pthread_descriptor(cur_task);
  return descriptor
      ? (char*)descriptor + GLIBC_PTHREAD_SPECIFIC_1STBLOCK_OFFSET
      : NULL;
}

// Read the current value of the pthread tls slot, mirroring the logic
// in pthread_getspecific().
//
// If the read was successful then populates *value with the pointer
// stored in the TLS slot and returns 0.
// Otherwise, returns a negative error code from the underlying memory read.
__hidden int probe_read_pthread_tls_slot(
    uint32_t key,
    void** value,
    struct task_struct* task) {
  struct task_struct* cur_task = get_current_task(task);
  void* specific1stblock = get_glibc_specific1stblock(cur_task);
  if (!specific1stblock) {
    *value = 0;
    return -1;
  }

  // Assuming implementation of pthread_getspecific() described here:
  //   https://fburl.com/2rgefzmn
  // And pthread data-structures described here:
  //   https://fburl.com/tffquvz4
  //
  // When tlsKey < 32, this means that the TLS is stored in
  //   pthread->specific_1stblock[autoTLSkey].data
  //
  // When tlsKey >= 32, this means that the TLS is stored in a two
  // level data-structure that is an array of pointers to 32-entry blocks.
  //   pthread->specific[key / 32][key % 32].data
  //
  // 'struct pthread' is not in the public API.
  // - x86-64 uses the fixed offset above (fsbase is the descriptor itself).
  // - AArch64 and RISC-V derive the block from the kernel's glibc
  //   robust-list pointer.
  //   (https://codebrowser.dev/glibc/glibc/sysdeps/nptl/dl-tls_init_tp.c.html#92)
  const uint32_t specific1stblock_count = 32;
  const uint32_t sizeof_pthread_key_data = 16;
  const uint32_t sizeof_pointer = 8;
  const uint32_t sizeof_specific1stblock =
      specific1stblock_count * sizeof_pthread_key_data;
  const uint32_t offsetof_data_member = 8;

  int error;

  void* tlsSlotDataAddress;
  if (key < 32) {
    tlsSlotDataAddress = (char*)specific1stblock +
        key * sizeof_pthread_key_data + offsetof_data_member;

    error = bpf_probe_read_user_task(
        value, sizeof(void*), tlsSlotDataAddress, task);

    if (error < 0) {
      *value = 0;
      return error;
    }

    return 0;
  } else if (key < 1024) {
    uint32_t idx1st = key / 32;
    uint32_t idx2nd = key % 32;

    void* secondLevelPtrAddress = (char*)specific1stblock +
        sizeof_specific1stblock + idx1st * sizeof_pointer;
    void* secondLevelAddress;
    error = bpf_probe_read_user_task(
        &secondLevelAddress,
        sizeof(secondLevelAddress),
        secondLevelPtrAddress,
        task);
    if (error < 0) {
      *value = 0;
      return error;
    }

    if (secondLevelAddress == 0) {
      // No data chunk allocated for this range of keys yet.
      // Value must still be NULL.
      *value = 0;
      return 0;
    }

    tlsSlotDataAddress = secondLevelAddress + sizeof_pthread_key_data * idx2nd +
        offsetof_data_member;
    error = bpf_probe_read_user_task(
        value, sizeof(void*), tlsSlotDataAddress, task);
    if (error < 0) {
      *value = 0;
      return error;
    }

    return 0;
  } else {
    // TLS key invalid or not yet initialised.
    *value = 0;
    return 0;
  }
}
