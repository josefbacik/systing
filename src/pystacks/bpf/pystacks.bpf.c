// Copyright (c) Meta Platforms, Inc. and affiliates.

#include <vmlinux.h>

#ifndef int8_t
typedef __s8 int8_t;
#endif

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>

#include "bpf_read_helpers.bpf.h"
#include "common.h"
#include "namespace_helpers.bpf.h"
#include "pid_target_helpers.bpf.h"
#include "pthread_helpers.bpf.h"
#include "task_helpers.bpf.h"
#include "binary_id.h"

#include "pystacks.bpf.h"

#include "PyPidData.h"

#include "py_structs.h"

/* Include helper .bpf.c files that define global variables and functions
 * needed by pystacks. These are normally compiled separately in strobelight-libs
 * but we include them here since they need to be in the same compilation unit. */
#include "common.bpf.c"
#include "task_helpers.bpf.c"
#include "bpf_read_helpers.bpf.c"
#include "pid_target_helpers.bpf.c"
#include "pthread_helpers.bpf.c"
#include "namespace_helpers.bpf.c"

struct pystacks_msg_heap_map pystacks_msg_heap SEC(".maps");

volatile struct {
  bool read_leaf_frame;
  uint32_t num_cpus;
  bool enable_debug_msgs;
  uint32_t stack_max_len;
  int sample_interval;
  bool enable_py_src_lines;
} pystacks_prog_cfg = {};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, BPF_LIB_DEFAULT_MAP_SIZE);
  __type(key, pid_t);
  __type(value, PyPidData);
} pystacks_pid_config SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, BPF_LIB_DEFAULT_MAP_SIZE);
  __type(key, struct bpf_lib_binary_id);
  __type(value, PyPidData);
} pystacks_binaryid_config SEC(".maps");

#define BPF_LIB_CO_COROUTINE 0x0080
#define BPF_LIB_CO_ITERABLE_COROUTINE 0x0100
#define BPF_LIB_CO_STATICALLY_COMPILED 0x4000000

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, BPF_LIB_DEFAULT_MAP_SIZE);
  __type(key, struct pystacks_symbol);
  __type(value, symbol_id_t);
} pystacks_symbols SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, BPF_LIB_DEFAULT_MAP_SIZE);
  __type(key, symbol_id_t);
  __type(value, struct pystacks_line_table);
} pystacks_linetables SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, BPF_LIB_DEFAULT_MAP_SIZE);
  __type(key, struct pystacks_symbol);
  __type(value, int8_t);
} pystacks_ending_frames SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, BPF_LIB_DEFAULT_MAP_SIZE);
  __type(key, struct read_qualified_name);
  __type(value, int8_t);
} pystacks_ending_frame_qualnames SEC(".maps");

struct sample_state_t {
  OffsetConfig offsets;
  uint64_t cur_cpu;
  void* frame_ptr;
  bool sync_use_shadow_frame;
  char long_file_name[BPF_LIB_FILE_NAME_TRYGET];
  struct pystacks_symbol sym;
  struct pystacks_line_table linetable;
  int32_t lasti;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct sample_state_t);
} pystacks_state_heap SEC(".maps");

static __always_inline struct sample_state_t* get_state() {
  return bpf_map_lookup_elem(&pystacks_state_heap, &zero);
}

#define BPF_LIB_GET_STATE()                   \
  struct sample_state_t* state = get_state(); \
  if (!state) {                               \
    return 0; /* should never happen */       \
  }

static symbol_id_t next_symbol_id = 1;

static __always_inline void read_shadow_frame_data(
    void* shadow_frame,
    const OffsetConfig* const offsets,
    void** data_ptr,
    int64_t* ptr_kind,
    struct task_struct* task) {
  // The PyShadowFrame stores a variety of Py objects in its "data" field
  // We determine the type using the bottom n bits in the "data" field
  void* shadow_frame_data;
  // If the read on shadow_frame->data is unsuccessful set everything to NULL
  // and return early
  if (bpf_probe_read_user_task(
          &shadow_frame_data,
          sizeof(void*),
          (char*)shadow_frame + offsets->PyShadowFrame_data,
          task) < 0) {
    *ptr_kind = -1;
    *data_ptr = NULL;
    return;
  }
  // The bottom n bits are extracted using the ptr kind bit mask
  // (PyShadowFrame_PtrKindMask)
  *ptr_kind = (int64_t)((uintptr_t)shadow_frame_data &
                        (uintptr_t)offsets->PyShadowFrame_PtrKindMask);
  // The pointer to the object is stored in the top 64 - n bits of the "data"
  // field We extract that pointer using the ptr bit mask
  // (PyShadowFrame_PtrKindMask)
  *data_ptr = (void*)((uintptr_t)shadow_frame_data &
                      (uintptr_t)offsets->PyShadowFrame_PtrMask);
}

static symbol_id_t get_py_symbol_id(struct pystacks_symbol* const sym) {
  symbol_id_t* id = bpf_map_lookup_elem(&pystacks_symbols, sym);
  if (id) {
    return *id;
  } else {
    symbol_id_t new_id = next_symbol_id;
    __sync_fetch_and_add(&next_symbol_id, 1);
    int error =
        bpf_map_update_elem(&pystacks_symbols, sym, &new_id, BPF_NOEXIST);
    if (!error) {
      return new_id;
    }
    if (error == -EEXIST) {
      // Another thread updated the map already with the same stack.
      // It should exist now.
      id = bpf_map_lookup_elem(&pystacks_symbols, sym);
      if (!id) {
        // This shouldn't happen (fingers crossed).
        return 0;
      }
      return *id;
    }
    return 0;
  }
}

static __always_inline void* get_gen_ptr(
    void* frame_ptr,
    void* code_ptr,
    const OffsetConfig* const offsets,
    bool use_shadow_frame,
    struct task_struct* task) {
  if (!code_ptr) {
    return NULL;
  }

  void* gen_ptr = NULL;
  // code flags
  int co_flags;
  if (bpf_probe_read_user_task(
          &co_flags,
          sizeof(int),
          (char*)code_ptr + offsets->PyCodeObject_co_flags,
          task) < 0) {
    return NULL;
  }

  if (use_shadow_frame) {
    void* data_ptr;
    int64_t ptr_kind;
    read_shadow_frame_data(frame_ptr, offsets, &data_ptr, &ptr_kind, task);
    if (!data_ptr || ptr_kind == -1) {
      return NULL;
    }
    const int gen_flags = BPF_LIB_CO_COROUTINE | BPF_LIB_CO_ITERABLE_COROUTINE;
    // JIT'd coroutines have their shadow frames embedded in the coroutine
    // object
    if (ptr_kind == offsets->PyShadowFrame_PYSF_CODE_RT &&
        (co_flags & gen_flags)) {
      gen_ptr =
          (void*)((char*)frame_ptr - offsets->PyGenObject_gi_shadow_frame);
    }
    // Other coroutines have the PyFrameObject in the shadow frame data member
    // We can then get the coroutine obejct using PyFrameObject->f_gen
    else if (
        ptr_kind == offsets->PyShadowFrame_PYSF_PYFRAME &&
        (co_flags & BPF_LIB_CO_COROUTINE)) {
      if (bpf_probe_read_user_task(
              &gen_ptr,
              sizeof(void*),
              (char*)data_ptr + offsets->PyFrameObject_gen,
              task) < 0) {
        return NULL;
      }
    }
    // ptr_kind == offsets->PyShadowFrame_PYSF_PYCODE
    // returns NULL
  }
  // We check code flag first for old style coroutines, f_gen only exists in PY3
  else if (co_flags & BPF_LIB_CO_COROUTINE) {
    bpf_probe_read_user_task(
        &gen_ptr,
        sizeof(void*),
        (char*)frame_ptr + offsets->PyFrameObject_gen,
        task);
  }
  return gen_ptr;
}

static __always_inline void get_names(
    struct sample_state_t* const state,
    void* cur_frame,
    void* code_ptr,
    bool use_shadow_frame,
    struct task_struct* task) {
  const OffsetConfig* const offsets = &state->offsets;
  const pid_t pid = task ? BPF_CORE_READ(task, tgid)
                         : (pid_t)(bpf_get_current_pid_tgid() >> 32);
  struct pystacks_symbol* const symbol = &state->sym;
  struct pystacks_line_table* const linetable = &state->linetable;

  // We re-use the same pystacks_symbol instance across loop iterations, which
  // means we will have left-over data in the struct. Although this won't affect
  // correctness of the result because we have '\0' at end of the strings
  // read, it would affect effectiveness of the deduplication.
  memset_zero(symbol, sizeof(struct pystacks_symbol));
  memset_zero(linetable, sizeof(struct pystacks_line_table));
  state->lasti = -1;

  if (!code_ptr) {
    // if we end up here, this means that reading of `PyCodeObject` for this
    // frame was unsuccessful; annotate the passed-in symbol with an error tag
    // and return
    bpf_probe_read_kernel_str(
        symbol->qualname.value,
        sizeof(symbol->qualname.value),
        "[Frame Error]");

    // file name already empty string (zeroed)
    return;
  }

  if (pystacks_prog_cfg.enable_py_src_lines &&
      offsets->PyCodeObject_linetable != BPF_LIB_DEFAULT_FIELD_OFFSET &&
      offsets->PyVarObject_size != BPF_LIB_DEFAULT_FIELD_OFFSET &&
      offsets->PyBytesObject_data != BPF_LIB_DEFAULT_FIELD_OFFSET &&
      offsets->PyCodeObject_firstlineno != BPF_LIB_DEFAULT_FIELD_OFFSET) {
    void* linetable_ptr = 0;
    if (bpf_probe_read_user_task(
            &linetable_ptr,
            sizeof(linetable_ptr),
            code_ptr + offsets->PyCodeObject_linetable,
            task) == 0) {
      linetable->addr = (uintptr_t)linetable_ptr + offsets->PyBytesObject_data;

      ssize_t linetable_length = 0;
      bpf_probe_read_user_task(
          &linetable_length,
          sizeof(linetable_length),
          linetable_ptr + offsets->PyVarObject_size,
          task);
      linetable->length = (uint32_t)linetable_length;

      uint32_t first_line = 0;
      bpf_probe_read_user_task(
          &first_line,
          sizeof(first_line),
          code_ptr + offsets->PyCodeObject_firstlineno,
          task);
      linetable->first_line = first_line;
      linetable->pid = pid;

      int32_t lasti = -1;
      if (offsets->PyVersion_major == 3 && offsets->PyVersion_minor < 11) {
        if (use_shadow_frame) {
          // If shadow frames are used then cur_frame points to a PyShadowFrame
          // - not a PyFrameObject. The content of the `data` member of a
          // PyShadowFrame varies according to `ptr_knd`.
          void* data_ptr;
          int64_t ptr_kind;
          read_shadow_frame_data(
              cur_frame, offsets, &data_ptr, &ptr_kind, task);
          if (data_ptr && ptr_kind == offsets->PyShadowFrame_PYSF_PYFRAME) {
            // data_ptr holds PyFrameObject*.
            // See cinder/include/internal/pycore_shadow_frame_struct.h
            bpf_probe_read_user_task(
                &lasti,
                sizeof(lasti),
                data_ptr + offsets->PyFrameObject_lasti,
                task);
          } else {
            state->lasti = -2; // unsupported ptr_kind
          }
        } else if (
            offsets->PyFrameObject_lasti != BPF_LIB_DEFAULT_FIELD_OFFSET) {
          bpf_probe_read_user_task(
              &lasti,
              sizeof(lasti),
              cur_frame + offsets->PyFrameObject_lasti,
              task);
        }
      } else {
        // In Python 3.11+ lasti is caclulated from the _PyInterpreterFrame
        // struct:
        // ((int)((IF)->prev_instr - _PyCode_CODE((IF)->f_code)))
        // See PyFrame_GetLasti() in cpython/Objects/frameobject.c
        if (offsets->PyInterpreterFrame_prev_instr !=
                BPF_LIB_DEFAULT_FIELD_OFFSET &&
            offsets->PyInterpreterFrame_code != BPF_LIB_DEFAULT_FIELD_OFFSET &&
            offsets->PyCodeObject_code_adaptive !=
                BPF_LIB_DEFAULT_FIELD_OFFSET) {
          void* prev_instr_ptr = NULL;
          bpf_probe_read_user_task(
              &prev_instr_ptr,
              sizeof(void*),
              state->frame_ptr + offsets->PyInterpreterFrame_prev_instr,
              task);
          if (prev_instr_ptr) {
            // sizeof(_Py_CODEUNIT) is 2 bytes
            lasti = (uint16_t*)prev_instr_ptr -
                (uint16_t*)(code_ptr + offsets->PyCodeObject_code_adaptive);
          }
        }
      }
      state->lasti = lasti;
    }
  }

  // read PyCodeObject's qualname into symbol
  // qualname should be a combination of classname and name
  int qualname_len = 0;
  if (offsets->PyCodeObject_qualname != BPF_LIB_DEFAULT_FIELD_OFFSET) {
    void* qualname_ptr;
    if (bpf_probe_read_user_task(
            &qualname_ptr,
            sizeof(void*),
            code_ptr + offsets->PyCodeObject_qualname,
            task) == 0 &&
        IS_VALID_USER_SPACE_ADDRESS(qualname_ptr)) {
      qualname_len = bpf_probe_read_user_str_task(
          symbol->qualname.value,
          sizeof(symbol->qualname.value),
          qualname_ptr + offsets->String_data,
          task);
      symbol->qualname.value[BPF_LIB_PYSTACKS_CLASS_NAME_LEN] = '\0';
      if (qualname_len == -EFAULT) {
        symbol->fault_pid = pid;
        symbol->qualname.fault_addr =
            (uintptr_t)(qualname_ptr + offsets->String_data);
      }
    } else {
      bpf_probe_read_kernel_str(
          symbol->qualname.value,
          sizeof(symbol->qualname.value),
          "[Frame Error]");
      return;
    }
  }

  // Query classname and function name using old method if qualname is empty
  // (qualname_len = 0 or 1) When qualname_len = 1, it is just the string
  // termination character '\0' so we consider it empty We also want to fallback
  // if there is a failure when reading qualname which will result in a negative
  // qualname_len
  if (!use_shadow_frame && qualname_len <= 1) {
    // Figure out if we want to parse class name, basically checking the name of
    // the first argument,
    //   ((PyTupleObject*)$frame->f_code->co_varnames)->ob_item[0]
    // If it's 'self', we get the type and its name, if it's cls, we just get
    // the name. This is not perfect but there is no better way to figure this
    // out from the code object.
    void* args_ptr;
    char ob_item[5];
    bpf_probe_read_user_task(
        &args_ptr,
        sizeof(void*),
        code_ptr + offsets->PyCodeObject_varnames,
        task);
    bpf_probe_read_user_task(
        &args_ptr, sizeof(void*), args_ptr + offsets->PyTupleObject_item, task);
    bpf_probe_read_user_str_task(
        ob_item, sizeof(ob_item), args_ptr + offsets->String_data, task);

    // compare strings as ints to save instructions
    char self_str[4] = {'s', 'e', 'l', 'f'};
    char cls_str[4] = {'c', 'l', 's', '\0'};
    bool first_self = *(int32_t*)ob_item == *(int32_t*)self_str;
    bool first_cls = *(int32_t*)ob_item == *(int32_t*)cls_str;

    // Read class name from $frame->f_localsplus[0]->ob_type->tp_name.
    if ((first_self || first_cls) && cur_frame) {
      void* ptr;
      bpf_probe_read_user_task(
          &ptr,
          sizeof(void*),
          cur_frame + offsets->PyFrameObject_localsplus,
          task);
      if (first_self) {
        // we are working with an instance, first we need to get type
        bpf_probe_read_user_task(
            &ptr, sizeof(void*), ptr + offsets->PyObject_type, task);
      }
      bpf_probe_read_user_task(
          &ptr, sizeof(void*), ptr + offsets->PyTypeObject_name, task);
      bpf_probe_read_user_str_task(
          symbol->qualname.value, BPF_LIB_PYSTACKS_CLASS_NAME_LEN, ptr, task);
      symbol->qualname.value[BPF_LIB_PYSTACKS_CLASS_NAME_LEN] = '\0';
    }
    // read PyCodeObject's name into symbol
    void* name_ptr;
    bpf_probe_read_user_task(
        &name_ptr, sizeof(void*), code_ptr + offsets->PyCodeObject_name, task);
    bpf_probe_read_user_str_task(
        symbol->qualname.value + BPF_LIB_PYSTACKS_CLASS_NAME_LEN,
        BPF_LIB_PYSTACKS_FUNCTION_NAME_LEN,
        name_ptr + offsets->String_data,
        task);
  }

  // read PyCodeObject's filename into symbol
  void* filename_ptr;
  if (bpf_probe_read_user_task(
          &filename_ptr,
          sizeof(void*),
          code_ptr + offsets->PyCodeObject_filename,
          task) == 0 &&
      IS_VALID_USER_SPACE_ADDRESS(filename_ptr)) {
    int len = bpf_probe_read_user_str_task(
        state->long_file_name,
        BPF_LIB_FILE_NAME_TRYGET,
        filename_ptr + offsets->String_data,
        task);

    if (len > 0) {
      void* src = len > BPF_LIB_PYSTACKS_FILE_NAME_LEN
          ? state->long_file_name + len - BPF_LIB_PYSTACKS_FILE_NAME_LEN
          : state->long_file_name;
      bpf_probe_read_kernel_str(
          &symbol->filename.value, sizeof(symbol->filename.value), src);
    } else if (len == -EFAULT) {
      symbol->fault_pid = pid;
      symbol->filename.fault_addr =
          (uintptr_t)(filename_ptr + offsets->String_data);
    }
  }
}

// Get the PyCodeObject from the frame pointer
static __always_inline void* get_code_ptr(
    void* frame_ptr,
    const OffsetConfig* const offsets,
    bool use_shadow_frame,
    struct task_struct* task) {
  long result = 0;
  // The frame pointer can be either a PyFrameObject or a PyShadowFrame
  void* code_ptr = NULL;
  // If we are using shadow frames we know the frame pointer is a PyShadowFrame
  if (use_shadow_frame) {
    void* data_ptr;
    int64_t ptr_kind;
    read_shadow_frame_data(frame_ptr, offsets, &data_ptr, &ptr_kind, task);
    if (!data_ptr || ptr_kind == -1) {
      return NULL;
    }
    if (ptr_kind == offsets->PyShadowFrame_PYSF_CODE_RT) {
      result = bpf_probe_read_user_task(
          &code_ptr,
          sizeof(void*),
          (char*)data_ptr + offsets->CodeRuntime_py_code,
          task);
    } else if (ptr_kind == offsets->PyShadowFrame_PYSF_RTFS) {
      result = bpf_probe_read_user_task(
          &code_ptr,
          sizeof(void*),
          (char*)data_ptr + offsets->RuntimeFrameState_py_code,
          task);
    } else if (ptr_kind == offsets->PyShadowFrame_PYSF_PYFRAME) {
      result = bpf_probe_read_user_task(
          &code_ptr,
          sizeof(void*),
          (char*)data_ptr + offsets->PyFrameObject_code,
          task);
    } else if (ptr_kind == offsets->PyShadowFrame_PYSF_PYCODE) {
      code_ptr = data_ptr;
    }
  }
  // If we aren't using shadow frames then the frame pointer is a PyFrameObject
  else {
    if (offsets->PyVersion_major >= 3 && offsets->PyVersion_minor >= 11) {
      result = bpf_probe_read_user_task(
          &code_ptr,
          sizeof(void*),
          (char*)frame_ptr + offsets->PyInterpreterFrame_code,
          task);
    } else {
      result = bpf_probe_read_user_task(
          &code_ptr,
          sizeof(void*),
          (char*)frame_ptr + offsets->PyFrameObject_code,
          task);
    }
  }
  if (result != 0) {
    code_ptr = NULL;
  }
  return code_ptr;
}

static __always_inline bool is_ending_frame(struct pystacks_symbol* sym) {
  return bpf_map_lookup_elem(&pystacks_ending_frames, sym) != NULL ||
      bpf_map_lookup_elem(&pystacks_ending_frame_qualnames, &sym->qualname) !=
      NULL;
}

/*
 * Read current PyFrameObject filename/name and update
 * stack_info->frame_ptr with pointer to next PyFrameObject
 */
__noinline bool pystacks_get_frame_data(int pid) {
  BPF_LIB_GET_STATE();

  if (state == NULL) {
    return false;
  }

  bool use_shadow_frame = state->sync_use_shadow_frame;
  const OffsetConfig* const offsets = &state->offsets;

  struct task_struct* task;
  if (get_task(pid, &task)) {
    return false;
  }

  void* code_ptr =
      get_code_ptr(state->frame_ptr, offsets, use_shadow_frame, task);

  get_names(state, state->frame_ptr, code_ptr, use_shadow_frame, task);

  int ret_code = 0;

  // read next PyFrameObject/PyShadowFrame pointer
  if (offsets->PyVersion_major >= 3 && offsets->PyVersion_minor >= 11) {
    ret_code = bpf_probe_read_user_task(
        &state->frame_ptr,
        sizeof(void*),
        state->frame_ptr + offsets->PyInterpreterFrame_previous,
        task);

  } else {
    ret_code = bpf_probe_read_user_task(
        &state->frame_ptr,
        sizeof(void*),
        state->frame_ptr +
            (use_shadow_frame ? offsets->PyShadowFrame_prev
                              : offsets->PyFrameObject_back),
        task);
  }

  put_task(task);

  return ret_code == 0;
}

static __noinline uint64_t
add_symbol_to_buffer(struct pystacks_message* const py_msg) {
  struct sample_state_t* const state = get_state();
  if (!state || !py_msg) {
    return 0; /* should never happen */
  }

  const symbol_id_t symbol_id = get_py_symbol_id(&state->sym);

  uint64_t max_len = pystacks_prog_cfg.stack_max_len;
  uint64_t max_offset = BPF_LIB_MAX_STACK_DEPTH;
  uint64_t st_len = py_msg->stack_len;

  if (st_len >= 0 && st_len < max_len && st_len < max_offset) {
    py_msg->buffer[st_len].symbol_id = symbol_id;
    py_msg->buffer[st_len].inst_idx = state->lasti;
    py_msg->header.len += sizeof(struct stack_walker_frame);
    ++st_len;
  }

  if (pystacks_prog_cfg.enable_py_src_lines) {
    bpf_map_update_elem(
        &pystacks_linetables, &symbol_id, &state->linetable, BPF_NOEXIST);
  }
  py_msg->stack_len = st_len;
  return st_len;
}

#ifdef STROBELIGHT_READ_LEAF_FRAME
/*
  *** Problem ***
  The ready to run frame is passed as an argument to _PyEval_EvalFrameDefault,
  but it isn't linked into the call stack until _PyEval_EvalFrameDefault
  starts executing. As such, we're unable to retrieve the executing Python
  function name using the usual process of constructing Python sync/async
  stacks.

  *** Solution ***
  To read the leaf python function name, we inspect the passed-in
  PyFrameObject frame (see function definition for implementation details).
*/
static __always_inline void read_leaf_frame(
    struct pt_regs* ctx,
    struct pystacks_message* const py_msg,
    struct task_struct* task) {
  struct sample_state_t* const state = get_state();
  if (!state) {
    return; /* should never happen */
  }

  const OffsetConfig* const offsets = &state->offsets;
  void* pt1 = (void*)PT_REGS_PARM1(ctx);
  void* pt2 = (void*)PT_REGS_PARM2(ctx);
  void* frame_ptr =
      (offsets->PyVersion_major >= 3 && offsets->PyVersion_minor >= 10) ? pt2
                                                                        : pt1;
  void* code_ptr = get_code_ptr(frame_ptr, &state->offsets, false, task);

  /*
  *** Problem ***
  Functions called via `asyncio.gather` appear both in the register we're
  reading `frame_ptr` from and in the bottom of the stack, so we want to
  avoid adding a duplicated function to the buffer twice. This results in
  weird-looking stacks, where non-recursive bottom functions are calling
 themselves recursively.

  *** Explanation by ther Cinder team ***
  There's an inconsistency for generators. The generator `send` implementation
  will link the shadow frame instead of _PyEval_EvalFrameDefault. The
 generator `send` implementation ends up calling _PyEval_EvalFrameDefault, so
 at the point where uprobe executes, `state->shadow_frame` will point to the
 shadow frame for the ready-to-run PyFrameObject.

  *** Solution ***
  Do not add leaf symbol to the buffer in case the PyFrameObject read from the
  register has a non-NULL generator object.
  */
  if (!get_gen_ptr(
          frame_ptr,
          code_ptr,
          &state->offsets,
          false /* this is not a shadow frame */,
          task)) {
    get_names(
        state,
        frame_ptr,
        code_ptr,
        false /* this is not a shadow frame */,
        task);

    add_symbol_to_buffer(py_msg);
  }
}
#endif

static int set_py_stack_status(
    uint8_t* const stack_status,
    long frame_ptr,
    bool last_frame_read,
    bool is_final_iteration) {
  /*
   * Stack status is considered "truncated" if:
   * (1) `frame_ptr` is valid (i.e. `frame_ptr != NULL`) AND the last frame data
  was read successfully before loop termination (i.e. `last_frame_read ==
  true`).
   * OR
   (2) `frame_ptr` is invalid (NULL) AND this was the final loop iteration
   (i.e. `is_final_iteration == true`).

  * Stack status is considered "error" if:
  (1) `frame_ptr` is valid (i.e. `frame_ptr != NULL`) AND the last frame data
  was NOT read successfully before loop termination (i.e. `last_frame_read ==
  false`).

  * Stack status is considered "complete" if:
  (1) `frame_ptr` is invalid (NULL) AND we've read the maximum number of frames
  allowed ( i.e. `last_frame_read == true`).
   */
  if (frame_ptr) {
    *stack_status =
        last_frame_read ? PYSTACKS_STATUS_TRUNCATED : PYSTACKS_STATUS_ERROR;
  } else {
    *stack_status = is_final_iteration ? PYSTACKS_STATUS_TRUNCATED
                                       : PYSTACKS_STATUS_COMPLETE;
  }

  return 0;
}

__hidden int walk_and_load_py_stack(
    struct pt_regs* ctx,
    struct task_struct* task) {
  struct pystacks_message* py_msg = pystacks_get_msg();
  if (!py_msg) {
    return -PYSTACKS_ERROR; /* should never happen */
  }

  BPF_LIB_GET_STATE();

  uint64_t i = 0;
  const uint32_t stack_max_len = pystacks_prog_cfg.stack_max_len;

#ifdef STROBELIGHT_READ_LEAF_FRAME
  if (pystacks_prog_cfg.read_leaf_frame) {
    /*
     * At the time when uprobe attached to a native function (e.g.
     * _PyEval_EvalFrameDefault) activates, we're unable to read the Python
     * function that's being executed, so this work-around is necessary (see
     * comment in `read_leaf_frame` definition).
     */
    read_leaf_frame(ctx, py_msg, task);
    ++i;
  }
#endif

  bool last_frame_read = false;
  int pid = task ? BPF_CORE_READ(task, pid) : 0;

  for (; i < stack_max_len && i < BPF_LIB_MAX_STACK_DEPTH &&
       (last_frame_read = pystacks_get_frame_data(pid));
       ++i) {
    add_symbol_to_buffer(py_msg);
  }

  set_py_stack_status(
      &py_msg->stack_status,
      (long)state->frame_ptr,
      last_frame_read,
      (i == stack_max_len - 1) /* is_final_iteration */);

  return py_msg->header.len;
}

static __always_inline void* get_thread_state(
    PyPidData* pid_data,
    struct task_struct* task) {
  // Python sets the thread_state using pthread_setspecific with the key
  // stored in a global variable autoTLSkey: https://fburl.com/t6zrkein,
  // https://fburl.com/4bz21uu1.
  //
  // We read the value of the key from the global variable and then read
  // the value in the thread-local storage. This relies on pthread
  // implementation: https://fburl.com/j2u1fvs8

  // read TLS key
  int key = 0;
  long result = bpf_probe_read_user_task(
      &key, sizeof(key), (void*)pid_data->tls_key_addr, task);
  if (result != 0) {
    return NULL;
  }

  void* thread_state;
  result = probe_read_pthread_tls_slot(key, &thread_state, task);
  if (result != 0) {
    return NULL;
  }

  return thread_state;
}

// Get the frame pointer from the thread state
// This could either be the PyFrameObject of PyShadowFrame
static __always_inline void* get_frame_ptr(
    void* thread_state,
    const OffsetConfig* const offsets,
    bool use_shadow_frame,
    struct task_struct* task) {
  void* frame_ptr;

  if (offsets->PyThreadState_frame != BPF_LIB_DEFAULT_FIELD_OFFSET) {
    if (bpf_probe_read_user_task(
            &frame_ptr,
            sizeof(void*),
            (char*)thread_state +
                (use_shadow_frame ? offsets->PyThreadState_shadow_frame
                                  : offsets->PyThreadState_frame),
            task) < 0) {
      frame_ptr = NULL;
    }
  } else {
    if (bpf_probe_read_user_task(
            &frame_ptr,
            sizeof(void*),
            (char*)thread_state + (offsets->PyThreadState_cframe),
            task) < 0) {
      frame_ptr = NULL;
    }
    // Python 3.13+: current_frame is directly in PyThreadState, no cframe wrapper
    // In this case, _PyCFrame_current_frame is set to BPF_LIB_DEFAULT_FIELD_OFFSET
    // to signal that no second dereference is needed
    if (offsets->_PyCFrame_current_frame != BPF_LIB_DEFAULT_FIELD_OFFSET) {
      if (bpf_probe_read_user_task(
              &frame_ptr,
              sizeof(void*),
              (char*)frame_ptr + (offsets->_PyCFrame_current_frame),
              task) < 0) {
        frame_ptr = NULL;
      }
    }
  }
  return frame_ptr;
}

// Determine if can use shadow frames when profiling based on offset
// availability
static __always_inline bool use_shadow_frame(
    const OffsetConfig* const offsets) {
  // Use of shadow frames rely on these offsets and thus they must be defined
  // These offsets are defaulted to an invalid offset of
  // BPF_LIB_DEFAULT_FIELD_OFFSET in the offset resolver
  return offsets->PyThreadState_shadow_frame != BPF_LIB_DEFAULT_FIELD_OFFSET &&
      offsets->PyGenObject_gi_shadow_frame != BPF_LIB_DEFAULT_FIELD_OFFSET &&
      offsets->PyCoroObject_cr_awaiter != BPF_LIB_DEFAULT_FIELD_OFFSET &&
      offsets->PyShadowFrame_data != BPF_LIB_DEFAULT_FIELD_OFFSET &&
      offsets->PyShadowFrame_prev != BPF_LIB_DEFAULT_FIELD_OFFSET &&
      offsets->PyShadowFrame_PtrMask != BPF_LIB_DEFAULT_FIELD_OFFSET &&
      offsets->PyShadowFrame_PtrKindMask != BPF_LIB_DEFAULT_FIELD_OFFSET &&
      offsets->PyShadowFrame_PYSF_CODE_RT != BPF_LIB_DEFAULT_FIELD_OFFSET &&
      offsets->PyShadowFrame_PYSF_PYCODE != BPF_LIB_DEFAULT_FIELD_OFFSET &&
      offsets->PyShadowFrame_PYSF_PYFRAME != BPF_LIB_DEFAULT_FIELD_OFFSET;
}

static __always_inline int
get_pthread_id_match(void* thread_state, void* tls_base, PyPidData* pid_data) {
  if (thread_state == 0) {
    return PYSTACKS_PTHREAD_ID_THREAD_STATE_NULL;
  }

  uint64_t pthread_self, pthread_created;
  long result;
  result = bpf_probe_read_kernel(
      &pthread_created,
      sizeof(pthread_created),
      thread_state + pid_data->offsets.PyThreadState_thread);
  if (result != 0) {
    return PYSTACKS_PTHREAD_ID_ERROR;
  }
  if (pthread_created == 0) {
    return PYSTACKS_PTHREAD_ID_NULL;
  }

  // 0x10 = offsetof(struct pthread, header.self)
  result = bpf_probe_read_kernel(
      &pthread_self, sizeof(pthread_self), tls_base + 0x10);
  if (result != 0) {
    return PYSTACKS_PTHREAD_ID_ERROR;
  }
  if (pthread_self == 0) {
    return PYSTACKS_PTHREAD_ID_ERROR;
  }

  if (pthread_self == pthread_created) {
    return PYSTACKS_PTHREAD_ID_MATCH;
  } else {
    return PYSTACKS_PTHREAD_ID_MISMATCH;
  }
}

static __always_inline int get_gil_state(
    void* this_thread_state,
    void* global_thread_state,
    PyPidData* pid_data,
    struct task_struct* task) {
  // Get information of GIL state
  if (pid_data->gil_locked_addr == 0 || pid_data->gil_last_holder_addr == 0) {
    return PYSTACKS_GIL_STATE_NO_INFO;
  }

  int gil_locked = 0;
  void* gil_thread_state = 0;
  long result = bpf_probe_read_user_task(
      &gil_locked, sizeof(gil_locked), (void*)pid_data->gil_locked_addr, task);
  if (result != 0) {
    return PYSTACKS_GIL_STATE_ERROR;
  }

  switch (gil_locked) {
    case -1:
      return PYSTACKS_GIL_STATE_UNINITIALIZED;
    case 0:
      return PYSTACKS_GIL_STATE_NOT_LOCKED;
    case 1:
      // GIL is held by some Thread
      bpf_probe_read_user_task(
          &gil_thread_state,
          sizeof(void*),
          (void*)pid_data->gil_last_holder_addr,
          task);
      if (gil_thread_state == this_thread_state) {
        return PYSTACKS_GIL_STATE_THIS_THREAD;
      } else if (gil_thread_state == global_thread_state) {
        return PYSTACKS_GIL_STATE_GLOBAL_CURRENT_THREAD;
      } else if (gil_thread_state == 0) {
        return PYSTACKS_GIL_STATE_NULL;
      } else {
        return PYSTACKS_GIL_STATE_OTHER_THREAD;
      }
    default:
      return PYSTACKS_GIL_STATE_ERROR;
  }
}

static int get_thread_state_match(
    void* this_thread_state,
    void* global_thread_state) {
  if (this_thread_state == 0 && global_thread_state == 0) {
    return PYSTACKS_THREAD_STATE_BOTH_NULL;
  }
  if (this_thread_state == 0) {
    return PYSTACKS_THREAD_STATE_THIS_THREAD_NULL;
  }
  if (global_thread_state == 0) {
    return PYSTACKS_THREAD_STATE_GLOBAL_CURRENT_THREAD_NULL;
  }
  if (this_thread_state == global_thread_state) {
    return PYSTACKS_THREAD_STATE_MATCH;
  } else {
    return PYSTACKS_THREAD_STATE_MISMATCH;
  }
}

__hidden int pystacks_read_stacks_task(
    struct pt_regs* ctx,
    pid_t pid,
    struct task_struct* task) {
  if (!ctx) {
    return -PYSTACKS_PROG_NOT_SUPPORTED;
  }

  uint64_t sample_ts = bpf_ktime_get_ns();

  // Get inode and pid and filter by them
  const struct task_struct* cur_task = get_current_task(task);

  PyPidData* pid_data = bpf_map_lookup_elem(&pystacks_pid_config, &pid);
  if (!pid_data) {
    struct bpf_lib_binary_id search_key;
    search_key.inode = BPF_CORE_READ(cur_task, mm, exe_file, f_inode, i_ino);
    search_key.dev =
        BPF_CORE_READ(cur_task, mm, exe_file, f_inode, i_sb, s_dev);

    // Is the inode of the task exe one we know to have python statically
    // linked?
    pid_data = bpf_map_lookup_elem(&pystacks_binaryid_config, &search_key);
  }
  // If this PID is not a python process stack of which we can decode
  if (!pid_data) {
    return -PYSTACKS_NON_PY_PROCESS;
  }

  BPF_LIB_GET_STATE();

  state->offsets = pid_data->offsets;
  state->cur_cpu = bpf_get_smp_processor_id();

  // Get pointer of global PyThreadState, which should belong to the Thread
  // currently holds the GIL
  void* global_current_thread = (void*)0;
  bpf_probe_read_kernel(
      &global_current_thread,
      sizeof(global_current_thread),
      (void*)pid_data->current_state_addr);

#if __x86_64__
  void* tls_base = (void*)BPF_PROBE_READ(cur_task, thread.fsbase);
#elif __aarch64__
  void* tls_base = (void*)BPF_PROBE_READ(cur_task, thread.uw.tp_value);
#else
#error "Unsupported platform"
#endif

  struct pystacks_message* py_msg = pystacks_get_msg();
  if (!py_msg) {
    return -PYSTACKS_ERROR; /* should never happen */
  }
  // zero-initialize struct pystacks_message up to 'buffer' offset
  memset_zero(py_msg, offsetof(struct pystacks_message, buffer));

  py_msg->header.type = BPF_LIB_PYSTACKS_MESSAGE;
  py_msg->header.len = offsetof(struct pystacks_message, buffer);

  void* thread_state = 0;
  if (pid_data->use_tls) {
    // Read PyThreadState of this Thread from TLS
    thread_state = get_thread_state(pid_data, task);

    // Check for matching between TLS PyThreadState and
    // the global _PyThreadState_Current
    py_msg->thread_state_match =
        get_thread_state_match(thread_state, global_current_thread);

    // Read GIL state
    py_msg->gil_state =
        get_gil_state(thread_state, global_current_thread, pid_data, task);

    // Check for matching between pthread ID created current PyThreadState and
    // pthread of actual current pthread
    py_msg->pthread_id_match =
        get_pthread_id_match(thread_state, tls_base, pid_data);
  } else {
    // Use the global PyThreadState if native TLS not available
    thread_state = global_current_thread;
    py_msg->thread_state_match = PYSTACKS_THREAD_STATE_NOT_USING_TLS;
    py_msg->pthread_id_match = PYSTACKS_PTHREAD_ID_NOT_USING_TLS;
  }

  // pre-initialize event struct in case any subprogram below fails
  py_msg->stack_status = PYSTACKS_STATUS_UNKNOWN;
  py_msg->async_stack_status = PYSTACKS_STATUS_UNKNOWN;

  if (!thread_state) {
    py_msg->probe_time_ns = bpf_ktime_get_ns() - sample_ts;
    return 0; // PYSTACKS_SUCCESS;
  }

  // Shadow frame usage is determined by availability off shadow frame
  // related offsets. This condition is the same for both sync and async
  // python stacks
  state->sync_use_shadow_frame = use_shadow_frame(&pid_data->offsets);

  // Get pointer to top frame from PyThreadState
  state->frame_ptr = get_frame_ptr(
      thread_state, &pid_data->offsets, state->sync_use_shadow_frame, task);
  if (!state->frame_ptr) {
    py_msg->probe_time_ns = bpf_ktime_get_ns() - sample_ts;
    return 0; // PYSTACKS_SUCCESS; // Finalize sample.
  }

  int py_stack_size = walk_and_load_py_stack(ctx, task);

  py_msg->probe_time_ns = bpf_ktime_get_ns() - sample_ts;

  return py_stack_size;
}

// global wrapper for verification
// main function is to get and put the task around pystacks_read_stacks_task
// call
int pystacks_read_stacks_global(struct pt_regs* ctx, pid_t pid) {
  struct task_struct* task;
  if (get_task(pid, &task))
    return 0;

  int ret = pystacks_read_stacks_task(ctx, pid, task);

  put_task(task);

  return ret;
}

// pystacks_read_stacks
// return :
//    >= 0 - number of bytes written to buffer
//    <  0 - error
// non-global function for verification of destination buffer
__hidden int pystacks_read_stacks(
    struct pt_regs* ctx,
    struct task_struct* task,
    struct pystacks_message* py_msg_buffer) {
  // Get TGID in upper 32bit.
  // Userspace-referred "PID" is TGID for kernel.
  pid_t pid = task ? BPF_CORE_READ(task, tgid)
                   : (pid_t)(bpf_get_current_pid_tgid() >> 32);

  if (!profile_pid(pid)) {
    // process not targeted. Not an error, zero bytes written
    return 0;
  }

  struct pystacks_message* py_msg = pystacks_get_msg();
  if (!py_msg) {
    return -PYSTACKS_ERROR; /* should never happen */
  }

  int py_stack_size = pystacks_read_stacks_global(ctx, pid);

  if (py_stack_size > 0 && (uint32_t)py_stack_size <= sizeof(*py_msg_buffer)) {
    /* Use bpf_probe_read_kernel with the fixed struct size to satisfy the
     * BPF verifier. The verifier needs a compile-time constant or tightly
     * bounded value for the size parameter. */
    bpf_probe_read_kernel(py_msg_buffer, sizeof(*py_msg_buffer), py_msg);
    return py_stack_size;
  }

  return 0;
}

struct pystacks_message* pystacks_get_msg(void) {
  return bpf_map_lookup_elem(&pystacks_msg_heap, &zero);
}
