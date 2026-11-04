// Copyright (c) Meta Platforms, Inc. and affiliates.

#include <vmlinux.h>

#include "bpf_read_helpers.bpf.h"
#include "task_helpers.bpf.h"

/*
 * Linux 7.2 moved task->robust_list to task->futex.robust_list (kernel commit
 * c1ffc9c6e4f8, "futex: Move futex task related data into a struct"). CO-RE
 * ignores the ___ suffixes, so these match the running kernel's structs.
 */
struct task_struct___pre72 {
  struct robust_list_head* robust_list;
} __attribute__((preserve_access_index));

struct futex_sched_data___post72 {
  struct robust_list_head* robust_list;
} __attribute__((preserve_access_index));

struct task_struct___post72 {
  struct futex_sched_data___post72 futex;
} __attribute__((preserve_access_index));

static __always_inline void* get_task_robust_list(
    const struct task_struct* task) {
  struct task_struct___post72* post72 = (void*)task;
  struct task_struct___pre72* pre72 = (void*)task;

  if (bpf_core_field_exists(post72->futex.robust_list)) {
    return BPF_CORE_READ(post72, futex.robust_list);
  }
  return BPF_CORE_READ(pre72, robust_list);
}

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
 * glibc registers &pthread->robust_head with the kernel as the robust-list
 * pointer (set_robust_list), and that sits at a fixed head-anchored offset, so
 * on x86-64 the thread pointer is the candidate and on the TLS-variant-1
 * architectures the candidate is derived from the robust-list pointer. A C
 * library with another layout registers its own descriptor's: musl's robust
 * list is at 0x88 on x86-64, so the thread pointer does not match, and the check
 * refuses it without reading a byte of user memory; the walker then reports no
 * thread state instead of reading through the wrong offsets.
 *
 * The clear-child-tid pointer says less. It is &pthread->tid up to glibc 2.42.
 * From 2.43 it points at a later field, 0x348 past the robust list on both x86-64
 * and aarch64, except a forked child's own thread, whose is still at tid, so it
 * cannot be required at tid. Where the thread pointer cannot witness the
 * descriptor it is still needed to refuse musl, whose two pointers are 0x58
 * apart, so there it may be at either place. That was measured on glibc 2.43 and
 * not on riscv64, and no CI job runs this path on 2.43: a thread where it is
 * elsewhere reports no thread state.
 */
#define GLIBC_2_43_ROBUST_TO_CLEAR_CHILD_TID 0x348

static __always_inline void* get_glibc_pthread_descriptor(
    const struct task_struct* cur_task) {
  void* robust_list = get_task_robust_list(cur_task);
  if (!IS_VALID_USER_SPACE_ADDRESS(robust_list)) {
    return NULL;
  }
  void* descriptor = (char*)robust_list - GLIBC_PTHREAD_ROBUST_HEAD_OFFSET;
#if __x86_64__
  if (descriptor != (void*)BPF_PROBE_READ(cur_task, thread.fsbase)) {
    return NULL;
  }
#else
  void* clear_child_tid = (void*)BPF_PROBE_READ(cur_task, clear_child_tid);
  if ((char*)clear_child_tid != (char*)descriptor + GLIBC_PTHREAD_TID_OFFSET &&
      (char*)clear_child_tid !=
          (char*)robust_list + GLIBC_2_43_ROBUST_TO_CLEAR_CHILD_TID) {
    return NULL;
  }
#endif
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
