// Copyright (c) Meta Platforms, Inc. and affiliates.

#include <vmlinux.h>

#include "bpf_read_helpers.bpf.h"
#include "task_helpers.bpf.h"

#if __riscv64__
/* glibc registers &pthread->tid as the kernel clear-child-tid pointer. */
static __always_inline void* get_riscv_pthread_descriptor(
    const struct task_struct* cur_task) {
  const uint32_t offsetof_tid = 0xd0;
  void* clear_child_tid = (void*)BPF_PROBE_READ(cur_task, clear_child_tid);
  if (!IS_VALID_USER_SPACE_ADDRESS(clear_child_tid))
      return NULL;
  return (char*)clear_child_tid - offsetof_tid;
}

/*
 * glibc registers &pthread->robust_head as the kernel robust-list pointer.
 * specific_1stblock is 0x30 bytes after robust_head in both of glibc's
 * robust-mutex layouts.
 */
static __always_inline void* get_riscv_specific1stblock(
    const struct task_struct* cur_task) {
  void* robust_list = (void*)BPF_PROBE_READ(cur_task, robust_list);
  return IS_VALID_USER_SPACE_ADDRESS(robust_list)
      ? (char*)robust_list + 0x30
      : NULL;
}
#endif

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
#if __x86_64__
  void* tls_base = (void*)BPF_PROBE_READ(cur_task, thread.fsbase);
  void* specific1stblock = (char*)tls_base + 0x310;
#elif __aarch64__
  void* tls_base = (void*)BPF_PROBE_READ(cur_task, thread.uw.tp_value);
  void* specific1stblock = (char*)tls_base + 0x310;
#elif __riscv64__
  void* specific1stblock = get_riscv_specific1stblock(cur_task);
  if (!specific1stblock) {
    *value = 0;
    return -1;
  }
#else
#error "Unsupported platform"
#endif

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
  // - x86-64 and AArch64 use fixed offset above.
  // - RISC-V derives the block from the kernel's glibc robust-list pointer.
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
