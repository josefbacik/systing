// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// Vendored from facebookincubator/strobelight-libs
// (strobelight/bpf_lib/common/task_stack_unwinder.bpf.h). What differs: the
// vmlinux.h include path, and the limits on the frames it follows, which take
// the arguments `stack_top` and `refused`.

#ifndef __BPF_LIB_TASK_STACK_UNWINDER_H__
#define __BPF_LIB_TASK_STACK_UNWINDER_H__

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct task_stack_frame {
  struct task_stack_frame* next_frame;
  unsigned long return_address;
};

// VMA safety checks are only needed on ARM where accessing device memory
// regions (VM_IO|VM_PFNMAP) can cause unaligned access faults. See S612453.
#ifdef __aarch64__

#define VM_READ 0x00000001
#define VM_WRITE 0x00000002
#define VM_IO 0x00004000
#define VM_PFNMAP 0x00000400

// Result struct for VMA safety checks, including address range for caching.
struct vma_check_result {
  bool is_safe;
  unsigned long vm_start;
  unsigned long vm_end;
};

// Callback for bpf_find_vma() that checks if a VMA is safe to read from.
// Populates vma_check_result with safety status and VMA boundaries.
static long vma_is_safe_callback(
    struct task_struct* task,
    struct vm_area_struct* vma,
    void* callback_ctx) {
  struct vma_check_result* result = (struct vma_check_result*)callback_ctx;
  unsigned long vm_flags = BPF_CORE_READ(vma, vm_flags);

  result->vm_start = BPF_CORE_READ(vma, vm_start);
  result->vm_end = BPF_CORE_READ(vma, vm_end);

  // Valid stack memory should be readable and writable, and not device memory
  bool is_rw = (vm_flags & (VM_READ | VM_WRITE)) == (VM_READ | VM_WRITE);
  bool is_device = vm_flags & (VM_IO | VM_PFNMAP);

  result->is_safe = is_rw && !is_device;
  return 0;
}

#endif // __aarch64__

// Unwind user stack for a task by following frame pointers.
// This is a workaround for bpf_get_task_stack() not supporting
// user stack collection for non-current tasks.
// Returns number of frames collected.
//
// NOTE: On ARM (aarch64), this function checks VMA flags before reading memory
// to prevent crashes when the frame pointer points into device memory regions
// (VM_IO|VM_PFNMAP) such as NVIDIA driver memory. See S612453.
// VMA lookups are cached to avoid redundant bpf_find_vma() calls when
// consecutive frame pointers fall within the same memory region.
//
// A frame pointer is whatever the thread left in that register, which is an
// address on its stack only in code built to keep it so. A read at any other
// address can fault a page in from a file while it holds the task's mmap_lock,
// or, at an address no mapping covers, take that lock for writing. So a frame
// is read only if it is aligned, at or above the stack pointer, above the frame
// before it, and all below `stack_top`, which limits the whole walk and not each
// step of it. *refused is set when a frame pointer fails that. The kernel's user
// unwinder (kernel/unwind/user.c) and abseil's x86 stack walker ask much the same.
static __always_inline size_t unwind_user_stack_task(
    struct task_struct* task,
    uint64_t* stack_buf,
    size_t max_frames,
    uint64_t stack_top,
    bool* refused) {
  struct pt_regs* regs = (struct pt_regs*)bpf_task_pt_regs(task);
  struct task_stack_frame frame;
  int err;
  size_t idx = 0;

#ifdef __aarch64__
  struct vma_check_result vma_result = {};
#endif

  uint64_t ip = PT_REGS_IP(regs);
  uint64_t fp = PT_REGS_FP(regs);
  uint64_t lowest = PT_REGS_SP(regs);

  if (idx < max_frames) {
    stack_buf[idx++] = ip;
  }

  void* next_frame = (void*)fp;

  while (next_frame != NULL && idx < max_frames) {
    uint64_t at = (uint64_t)next_frame;

    if ((at & 7) != 0 || at < lowest || at >= stack_top ||
        stack_top - at < sizeof(frame)) {
      *refused = true;
      break;
    }

#ifdef __aarch64__
    // Check if address falls within current checked VMA range
    if ((unsigned long)next_frame < vma_result.vm_start ||
        (unsigned long)next_frame >= vma_result.vm_end) {
      long ret = bpf_find_vma(
          task,
          (unsigned long)next_frame,
          vma_is_safe_callback,
          &vma_result,
          0);

      if (ret != 0 || !vma_result.is_safe) {
        break;
      }
    }
#endif

    err = bpf_copy_from_user_task(&frame, sizeof(frame), next_frame, task, 0);
    if (err != 0 || frame.return_address == 0) {
      break;
    }

    stack_buf[idx++] = frame.return_address;
    lowest = at + 1;
    next_frame = frame.next_frame;
  }

  return idx;
}

#endif // __BPF_LIB_TASK_STACK_UNWINDER_H__
