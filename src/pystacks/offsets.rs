/// Python version-specific offset configurations.
///
/// Offsets are computed from bindgen-generated CPython struct definitions
/// using `std::mem::offset_of!()` and `std::mem::size_of()`.
/// Compound offsets (nested structs that bindgen cannot resolve) are
/// computed by the generation script via a C program.
use super::bindings;
use super::types::OffsetConfig;
use super::types::BPF_LIB_DEFAULT_FIELD_OFFSET;

/// Returns the OffsetConfig for a given Python (major, minor) version.
/// Returns None if the version is not supported.
/// Falls back to Python 3.13 for unknown versions >= 3.13.
pub fn for_version(major: i32, minor: i32) -> Option<OffsetConfig> {
    if major != 3 {
        return None;
    }
    match minor {
        8 => Some(py38()),
        9 => Some(py39()),
        10 => Some(py310()),
        11 => Some(py311()),
        12 => Some(py312()),
        13 => Some(py313()),
        m if m > 13 => Some(py313()), // fallback to latest known
        _ => None,
    }
}

#[allow(clippy::field_reassign_with_default)]
pub fn py38() -> OffsetConfig {
    use bindings::v3_8_0::*;
    let mut c = OffsetConfig::default();

    // Common offsets
    // Note: py_var_object_size, py_bytes_object_data, py_code_object_firstlineno are
    // left at sentinel (9999) for 3.8. The BPF code checks against the sentinel before
    // use; these features (line table parsing, bytes object reading) were added in 3.9+.
    c.py_object_type = std::mem::offset_of!(_object, ob_type);
    c.py_type_object_name = std::mem::offset_of!(_typeobject, tp_name);
    c.py_tuple_object_item = std::mem::offset_of!(PyTupleObject, ob_item);
    c.string_data = std::mem::size_of::<PyASCIIObject>();

    // Thread state (traditional frame)
    c.py_thread_state_frame = std::mem::offset_of!(_ts, frame);
    c.py_thread_state_thread = std::mem::offset_of!(_ts, thread_id);

    // Frame object (old-style _frame)
    c.py_frame_object_back = std::mem::offset_of!(_frame, f_back);
    c.py_frame_object_code = std::mem::offset_of!(_frame, f_code);
    c.py_frame_object_localsplus = std::mem::offset_of!(_frame, f_localsplus);
    c.py_frame_object_gen = std::mem::offset_of!(_frame, f_gen);

    // Code object
    c.py_code_object_co_flags = std::mem::offset_of!(PyCodeObject, co_flags);
    c.py_code_object_filename = std::mem::offset_of!(PyCodeObject, co_filename);
    c.py_code_object_name = std::mem::offset_of!(PyCodeObject, co_name);
    c.py_code_object_varnames = std::mem::offset_of!(PyCodeObject, co_varnames);

    // Compound offsets (from C program)
    c.tls_key_offset = PYRUNTIME_TLS_KEY_OFFSET;
    c.t_current_state_offset = PYRUNTIME_TSTATE_CURRENT_OFFSET;
    c.py_gil_offset = PYRUNTIME_GIL_LOCKED_OFFSET;
    c.py_gil_last_holder = PYRUNTIME_GIL_LAST_HOLDER_OFFSET;

    c.py_version_major = 3;
    c.py_version_minor = 8;
    c.py_version_micro = 0;
    c
}

#[allow(clippy::field_reassign_with_default)]
pub fn py39() -> OffsetConfig {
    use bindings::v3_9_0::*;
    let mut c = OffsetConfig::default();

    // Common offsets
    c.py_object_type = std::mem::offset_of!(_object, ob_type);
    c.py_type_object_name = std::mem::offset_of!(_typeobject, tp_name);
    c.py_var_object_size = std::mem::offset_of!(PyVarObject, ob_size);
    c.py_tuple_object_item = std::mem::offset_of!(PyTupleObject, ob_item);
    c.py_bytes_object_data = std::mem::offset_of!(PyBytesObject, ob_sval);
    c.string_data = std::mem::size_of::<PyASCIIObject>();

    // Thread state (traditional frame)
    c.py_thread_state_frame = std::mem::offset_of!(_ts, frame);
    c.py_thread_state_thread = std::mem::offset_of!(_ts, thread_id);

    // Frame object (old-style _frame)
    c.py_frame_object_back = std::mem::offset_of!(_frame, f_back);
    c.py_frame_object_code = std::mem::offset_of!(_frame, f_code);
    c.py_frame_object_lasti = std::mem::offset_of!(_frame, f_lasti);
    c.py_frame_object_localsplus = std::mem::offset_of!(_frame, f_localsplus);
    c.py_frame_object_gen = std::mem::offset_of!(_frame, f_gen);

    // Code object
    c.py_code_object_co_flags = std::mem::offset_of!(PyCodeObject, co_flags);
    c.py_code_object_filename = std::mem::offset_of!(PyCodeObject, co_filename);
    c.py_code_object_name = std::mem::offset_of!(PyCodeObject, co_name);
    c.py_code_object_varnames = std::mem::offset_of!(PyCodeObject, co_varnames);
    c.py_code_object_firstlineno = std::mem::offset_of!(PyCodeObject, co_firstlineno);

    // Compound offsets (from C program)
    c.tls_key_offset = PYRUNTIME_TLS_KEY_OFFSET;
    c.t_current_state_offset = PYRUNTIME_TSTATE_CURRENT_OFFSET;
    c.py_gil_offset = PYRUNTIME_GIL_LOCKED_OFFSET;
    c.py_gil_last_holder = PYRUNTIME_GIL_LAST_HOLDER_OFFSET;

    c.py_version_major = 3;
    c.py_version_minor = 9;
    c.py_version_micro = 0;
    c
}

#[allow(clippy::field_reassign_with_default)]
pub fn py310() -> OffsetConfig {
    use bindings::v3_10_0::*;
    let mut c = OffsetConfig::default();

    // Common offsets
    c.py_object_type = std::mem::offset_of!(_object, ob_type);
    c.py_type_object_name = std::mem::offset_of!(_typeobject, tp_name);
    c.py_var_object_size = std::mem::offset_of!(PyVarObject, ob_size);
    c.py_tuple_object_item = std::mem::offset_of!(PyTupleObject, ob_item);
    c.py_bytes_object_data = std::mem::offset_of!(PyBytesObject, ob_sval);
    c.string_data = std::mem::size_of::<PyASCIIObject>();

    // Thread state (traditional frame)
    c.py_thread_state_frame = std::mem::offset_of!(_ts, frame);
    c.py_thread_state_thread = std::mem::offset_of!(_ts, thread_id);
    c.py_thread_state_interp = std::mem::offset_of!(_ts, interp);

    // Frame object (old-style _frame)
    c.py_frame_object_back = std::mem::offset_of!(_frame, f_back);
    c.py_frame_object_code = std::mem::offset_of!(_frame, f_code);
    c.py_frame_object_lasti = std::mem::offset_of!(_frame, f_lasti);
    c.py_frame_object_localsplus = std::mem::offset_of!(_frame, f_localsplus);
    c.py_frame_object_gen = std::mem::offset_of!(_frame, f_gen);

    // Code object
    c.py_code_object_co_flags = std::mem::offset_of!(PyCodeObject, co_flags);
    c.py_code_object_filename = std::mem::offset_of!(PyCodeObject, co_filename);
    c.py_code_object_name = std::mem::offset_of!(PyCodeObject, co_name);
    c.py_code_object_varnames = std::mem::offset_of!(PyCodeObject, co_varnames);
    c.py_code_object_firstlineno = std::mem::offset_of!(PyCodeObject, co_firstlineno);
    c.py_code_object_linetable = std::mem::offset_of!(PyCodeObject, co_linetable);

    // Compound offsets (from C program)
    c.tls_key_offset = PYRUNTIME_TLS_KEY_OFFSET;
    c.t_current_state_offset = PYRUNTIME_TSTATE_CURRENT_OFFSET;
    c.py_gil_offset = PYRUNTIME_GIL_LOCKED_OFFSET;
    c.py_gil_last_holder = PYRUNTIME_GIL_LAST_HOLDER_OFFSET;
    c.py_interpreter_state_modules = PYINTERP_MODULES_OFFSET;

    c.py_version_major = 3;
    c.py_version_minor = 10;
    c.py_version_micro = 0;
    c
}

#[allow(clippy::field_reassign_with_default)]
pub fn py311() -> OffsetConfig {
    use bindings::v3_11_0::*;
    let mut c = OffsetConfig::default();

    // Common offsets
    c.py_object_type = std::mem::offset_of!(_object, ob_type);
    c.py_type_object_name = std::mem::offset_of!(_typeobject, tp_name);
    c.py_var_object_size = std::mem::offset_of!(PyVarObject, ob_size);
    c.py_tuple_object_item = std::mem::offset_of!(PyTupleObject, ob_item);
    c.py_bytes_object_data = std::mem::offset_of!(PyBytesObject, ob_sval);
    c.string_data = std::mem::size_of::<PyASCIIObject>();

    // Thread state (new-style via _PyCFrame)
    c.py_thread_state_cframe = std::mem::offset_of!(_ts, cframe);
    c.py_thread_state_thread = std::mem::offset_of!(_ts, thread_id);

    // CFrame -> interpreter frame
    c.py_cframe_current_frame = std::mem::offset_of!(_PyCFrame, current_frame);

    // Interpreter frame (new-style)
    c.py_interpreter_frame_code = std::mem::offset_of!(_PyInterpreterFrame, f_code);
    c.py_interpreter_frame_previous = std::mem::offset_of!(_PyInterpreterFrame, previous);
    c.py_interpreter_frame_localsplus = std::mem::offset_of!(_PyInterpreterFrame, localsplus);
    c.py_interpreter_frame_prev_instr = std::mem::offset_of!(_PyInterpreterFrame, prev_instr);

    // Code object
    c.py_code_object_co_flags = std::mem::offset_of!(PyCodeObject, co_flags);
    c.py_code_object_filename = std::mem::offset_of!(PyCodeObject, co_filename);
    c.py_code_object_name = std::mem::offset_of!(PyCodeObject, co_name);
    c.py_code_object_qualname = std::mem::offset_of!(PyCodeObject, co_qualname);
    c.py_code_object_linetable = std::mem::offset_of!(PyCodeObject, co_linetable);
    c.py_code_object_firstlineno = std::mem::offset_of!(PyCodeObject, co_firstlineno);

    // Compound offsets (from C program)
    c.tls_key_offset = PYRUNTIME_TLS_KEY_OFFSET;
    c.t_current_state_offset = PYRUNTIME_TSTATE_CURRENT_OFFSET;
    c.py_gil_offset = PYRUNTIME_GIL_LOCKED_OFFSET;
    c.py_gil_last_holder = PYRUNTIME_GIL_LAST_HOLDER_OFFSET;

    c.py_version_major = 3;
    c.py_version_minor = 11;
    c.py_version_micro = 0;
    c
}

#[allow(clippy::field_reassign_with_default)]
pub fn py312() -> OffsetConfig {
    use bindings::v3_12_0::*;
    let mut c = OffsetConfig::default();

    // Common offsets
    c.py_object_type = std::mem::offset_of!(_object, ob_type);
    c.py_type_object_name = std::mem::offset_of!(_typeobject, tp_name);
    c.py_var_object_size = std::mem::offset_of!(PyVarObject, ob_size);
    c.py_tuple_object_item = std::mem::offset_of!(PyTupleObject, ob_item);
    c.py_bytes_object_data = std::mem::offset_of!(PyBytesObject, ob_sval);
    c.string_data = std::mem::size_of::<PyASCIIObject>(); // Changed in 3.12

    // Thread state (via _PyCFrame)
    c.py_thread_state_cframe = std::mem::offset_of!(_ts, cframe);
    c.py_thread_state_thread = std::mem::offset_of!(_ts, thread_id);
    c.py_thread_state_interp = std::mem::offset_of!(_ts, interp);

    // CFrame -> interpreter frame
    c.py_cframe_current_frame = std::mem::offset_of!(_PyCFrame, current_frame);

    // Interpreter frame (new-style)
    c.py_interpreter_frame_code = std::mem::offset_of!(_PyInterpreterFrame, f_code);
    c.py_interpreter_frame_previous = std::mem::offset_of!(_PyInterpreterFrame, previous);
    c.py_interpreter_frame_localsplus = std::mem::offset_of!(_PyInterpreterFrame, localsplus);
    c.py_interpreter_frame_prev_instr = std::mem::offset_of!(_PyInterpreterFrame, prev_instr);

    // Code object
    c.py_code_object_co_flags = std::mem::offset_of!(PyCodeObject, co_flags);
    c.py_code_object_filename = std::mem::offset_of!(PyCodeObject, co_filename);
    c.py_code_object_name = std::mem::offset_of!(PyCodeObject, co_name);
    c.py_code_object_qualname = std::mem::offset_of!(PyCodeObject, co_qualname);
    c.py_code_object_linetable = std::mem::offset_of!(PyCodeObject, co_linetable);
    c.py_code_object_firstlineno = std::mem::offset_of!(PyCodeObject, co_firstlineno);
    c.py_code_object_code_adaptive = std::mem::offset_of!(PyCodeObject, co_code_adaptive);

    // 3.12+ generator/coroutine offsets
    c.py_coro_object_cr_awaiter = std::mem::offset_of!(PyCoroObject, cr_origin_or_finalizer);
    c.py_gen_object_iframe = std::mem::offset_of!(PyGenObject, gi_iframe);
    c.py_frame_object_owner = std::mem::offset_of!(_PyInterpreterFrame, owner);

    // Compound offsets (from C program)
    c.tls_key_offset = PYRUNTIME_TLS_KEY_OFFSET;
    c.py_interpreter_state_modules = PYINTERP_MODULES_OFFSET;

    c.py_version_major = 3;
    c.py_version_minor = 12;
    c.py_version_micro = 0;
    c
}

#[allow(clippy::field_reassign_with_default)]
pub fn py313() -> OffsetConfig {
    use bindings::v3_13_0::*;
    let mut c = OffsetConfig::default();

    // Common offsets
    c.py_object_type = std::mem::offset_of!(_object, ob_type);
    c.py_type_object_name = std::mem::offset_of!(_typeobject, tp_name);
    c.py_var_object_size = std::mem::offset_of!(PyVarObject, ob_size);
    c.py_tuple_object_item = std::mem::offset_of!(PyTupleObject, ob_item);
    c.py_bytes_object_data = std::mem::offset_of!(PyBytesObject, ob_sval);
    c.string_data = std::mem::size_of::<PyASCIIObject>(); // Changed in 3.12+

    // Thread state (3.13: current_frame is directly on _ts, no _PyCFrame)
    c.py_thread_state_cframe = std::mem::offset_of!(_ts, current_frame);
    c.py_thread_state_thread = std::mem::offset_of!(_ts, thread_id);
    c.py_thread_state_interp = std::mem::offset_of!(_ts, interp);

    // 3.13: No _PyCFrame indirection - sentinel means "no second dereference"
    c.py_cframe_current_frame = BPF_LIB_DEFAULT_FIELD_OFFSET;

    // Interpreter frame (new-style, f_code renamed to f_executable)
    c.py_interpreter_frame_code = std::mem::offset_of!(_PyInterpreterFrame, f_executable);
    c.py_interpreter_frame_previous = std::mem::offset_of!(_PyInterpreterFrame, previous);
    c.py_interpreter_frame_localsplus = std::mem::offset_of!(_PyInterpreterFrame, localsplus);
    c.py_interpreter_frame_prev_instr = std::mem::offset_of!(_PyInterpreterFrame, instr_ptr);

    // Code object
    c.py_code_object_co_flags = std::mem::offset_of!(PyCodeObject, co_flags);
    c.py_code_object_filename = std::mem::offset_of!(PyCodeObject, co_filename);
    c.py_code_object_name = std::mem::offset_of!(PyCodeObject, co_name);
    c.py_code_object_qualname = std::mem::offset_of!(PyCodeObject, co_qualname);
    c.py_code_object_linetable = std::mem::offset_of!(PyCodeObject, co_linetable);
    c.py_code_object_firstlineno = std::mem::offset_of!(PyCodeObject, co_firstlineno);
    c.py_code_object_code_adaptive = std::mem::offset_of!(PyCodeObject, co_code_adaptive);

    // 3.12+ generator/coroutine offsets
    c.py_coro_object_cr_awaiter = std::mem::offset_of!(PyCoroObject, cr_origin_or_finalizer);
    c.py_gen_object_iframe = std::mem::offset_of!(PyGenObject, gi_iframe);
    c.py_frame_object_owner = std::mem::offset_of!(_PyInterpreterFrame, owner);

    // Compound offsets (from C program)
    c.tls_key_offset = PYRUNTIME_TLS_KEY_OFFSET;
    c.py_runtime_state_interpreters_head = PYRUNTIME_INTERPRETERS_HEAD_OFFSET;
    c.py_interpreter_state_modules = PYINTERP_MODULES_OFFSET;
    c.py_interpreter_state_gil_locked = PYINTERP_GIL_LOCKED_OFFSET;
    c.py_interpreter_state_gil_last_holder = PYINTERP_GIL_LAST_HOLDER_OFFSET;

    c.py_version_major = 3;
    c.py_version_minor = 13;
    c.py_version_micro = 0;
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_for_version_known() {
        assert!(for_version(3, 8).is_some());
        assert!(for_version(3, 13).is_some());
    }

    #[test]
    fn test_for_version_unknown() {
        assert!(for_version(2, 7).is_none());
        assert!(for_version(3, 7).is_none());
    }

    #[test]
    fn test_for_version_future_fallback() {
        let future = for_version(3, 14).unwrap();
        assert_eq!(future.py_version_minor, 13); // falls back to 3.13
    }

    #[test]
    fn test_default_offset_sentinel() {
        let c = OffsetConfig::default();
        assert_eq!(c.py_object_type, 9999);
        assert_eq!(c.py_shadow_frame_prev, 9999);
    }

    #[test]
    fn test_py38_offsets() {
        let c = py38();
        assert_eq!(c.py_version_major, 3);
        assert_eq!(c.py_version_minor, 8);
        assert_eq!(c.py_object_type, 8);
        assert_eq!(c.tls_key_offset, 1396);
        assert_eq!(c.t_current_state_offset, 1368);
    }

    #[test]
    fn test_py310_offsets() {
        let c = py310();
        assert_eq!(c.py_version_minor, 10);
        assert_eq!(c.py_code_object_linetable, 120);
        assert_eq!(c.py_frame_object_lasti, 96);
    }

    #[test]
    fn test_py311_offsets() {
        let c = py311();
        assert_eq!(c.py_version_minor, 11);
        assert_eq!(c.py_thread_state_cframe, 56);
        assert_eq!(c.py_cframe_current_frame, 8);
        assert_eq!(c.py_interpreter_frame_code, 32);
    }

    #[test]
    fn test_py312_offsets() {
        let c = py312();
        assert_eq!(c.py_version_minor, 12);
        assert_eq!(c.py_cframe_current_frame, 0);
        assert_eq!(c.py_interpreter_frame_code, 0);
        assert_eq!(c.py_code_object_code_adaptive, 192);
    }

    #[test]
    fn test_py313_offsets() {
        let c = py313();
        assert_eq!(c.py_version_minor, 13);
        assert_eq!(c.py_thread_state_cframe, 72);
        assert_eq!(c.tls_key_offset, 2164);
        assert_eq!(c.py_runtime_state_interpreters_head, 632);
        assert_eq!(c.py_interpreter_state_gil_locked, 7768);
        assert_eq!(c.py_interpreter_state_gil_last_holder, 7760);
    }
}
