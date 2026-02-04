// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#ifdef __cplusplus
#include <cstdint>
#endif

#define BPF_LIB_DEFAULT_FIELD_OFFSET 9999

#ifdef __cplusplus
struct OffsetConfig {
  OffsetConfig()
      : PyObject_type(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyTypeObject_name(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyThreadState_frame(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyThreadState_cframe(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyThreadState_shadow_frame(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyThreadState_thread(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyThreadState_interp(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyInterpreterState_modules(BPF_LIB_DEFAULT_FIELD_OFFSET),
        _PyCFrame_current_frame(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyFrameObject_back(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyFrameObject_code(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyFrameObject_lasti(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyFrameObject_localsplus(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyFrameObject_gen(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyInterpreterFrame_code(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyInterpreterFrame_previous(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyInterpreterFrame_localsplus(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyInterpreterFrame_prev_instr(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyGenObject_gi_shadow_frame(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyCodeObject_co_flags(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyCodeObject_filename(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyCodeObject_name(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyCodeObject_varnames(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyCodeObject_firstlineno(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyCodeObject_linetable(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyCodeObject_code_adaptive(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyTupleObject_item(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyCodeObject_qualname(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyCoroObject_cr_awaiter(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyShadowFrame_prev(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyShadowFrame_data(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyShadowFrame_PtrMask(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyShadowFrame_PtrKindMask(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyShadowFrame_PYSF_CODE_RT(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyShadowFrame_PYSF_PYCODE(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyShadowFrame_PYSF_PYFRAME(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyShadowFrame_PYSF_RTFS(BPF_LIB_DEFAULT_FIELD_OFFSET),
        CodeRuntime_py_code(BPF_LIB_DEFAULT_FIELD_OFFSET),
        RuntimeFrameState_py_code(BPF_LIB_DEFAULT_FIELD_OFFSET),
        String_data(BPF_LIB_DEFAULT_FIELD_OFFSET),
        TLSKey_offset(BPF_LIB_DEFAULT_FIELD_OFFSET),
        TCurrentState_offset(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyGIL_offset(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyGIL_last_holder(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyRuntimeState_interpreters_head(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyInterpreterState_gil_locked(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyInterpreterState_gil_last_holder(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyBytesObject_data(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyVarObject_size(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyFrameObject_owner(BPF_LIB_DEFAULT_FIELD_OFFSET),
        PyGenObject_iframe(BPF_LIB_DEFAULT_FIELD_OFFSET),

        PyVersion_major(0),
        PyVersion_minor(0),
        PyVersion_micro(0) {}
#else
typedef struct {
#endif // __cplusplus
  // IMPORTANT: When adding a new offset field it must be added to the
  // constructor as well as operator<<() in PythonOffsets.cpp.
  // Also update the tests in PyPerfOffsetResolverTest.cpp.
  uintptr_t PyObject_type;
  uintptr_t PyTypeObject_name;
  uintptr_t PyThreadState_frame;
  uintptr_t PyThreadState_cframe;
  uintptr_t PyThreadState_shadow_frame;
  uintptr_t PyThreadState_thread;
  uintptr_t PyThreadState_interp;
  uintptr_t PyInterpreterState_modules;
  uintptr_t _PyCFrame_current_frame;
  uintptr_t PyFrameObject_back;
  uintptr_t PyFrameObject_code;
  uintptr_t PyFrameObject_lasti;
  uintptr_t PyFrameObject_localsplus;
  uintptr_t PyFrameObject_gen;
  uintptr_t PyInterpreterFrame_code;
  uintptr_t PyInterpreterFrame_previous;
  uintptr_t PyInterpreterFrame_localsplus;
  uintptr_t PyInterpreterFrame_prev_instr;
  uintptr_t PyGenObject_gi_shadow_frame;
  uintptr_t PyCodeObject_co_flags;
  uintptr_t PyCodeObject_filename;
  uintptr_t PyCodeObject_name;
  uintptr_t PyCodeObject_varnames;
  uintptr_t PyCodeObject_firstlineno;
  uintptr_t PyCodeObject_linetable;
  uintptr_t PyCodeObject_code_adaptive;
  uintptr_t PyTupleObject_item;
  uintptr_t PyCodeObject_qualname;
  uintptr_t PyCoroObject_cr_awaiter;
  uintptr_t PyShadowFrame_prev;
  uintptr_t PyShadowFrame_data;
  uintptr_t PyShadowFrame_PtrMask;
  uintptr_t PyShadowFrame_PtrKindMask;
  uintptr_t PyShadowFrame_PYSF_CODE_RT;
  uintptr_t PyShadowFrame_PYSF_PYCODE;
  uintptr_t PyShadowFrame_PYSF_PYFRAME;
  uintptr_t PyShadowFrame_PYSF_RTFS;
  uintptr_t CodeRuntime_py_code;
  uintptr_t RuntimeFrameState_py_code;
  uintptr_t String_data;
  uintptr_t TLSKey_offset;
  uintptr_t TCurrentState_offset;
  uintptr_t PyGIL_offset;
  uintptr_t PyGIL_last_holder;
  // Python 3.13+ GIL offsets (GIL moved from _PyRuntimeState to PyInterpreterState)
  uintptr_t PyRuntimeState_interpreters_head;
  uintptr_t PyInterpreterState_gil_locked;
  uintptr_t PyInterpreterState_gil_last_holder;
  uintptr_t PyBytesObject_data;
  uintptr_t PyVarObject_size;
  uintptr_t PyFrameObject_owner;
  uintptr_t PyGenObject_iframe;

  int32_t PyVersion_major;
  int32_t PyVersion_minor;
  int32_t PyVersion_micro;
#ifdef __cplusplus
};
#else
} OffsetConfig;
#endif // __cplusplus
