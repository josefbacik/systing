/// Python version-specific offset configurations.
///
/// Offsets are pre-computed constants generated from CPython struct definitions.
/// Simple offsets use `offsetof()` and `sizeof()`, compound offsets (nested
/// structs) are computed by the generation script via a C program.
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
    c.py_object_type = PY_OBJECT_OB_TYPE;
    c.py_type_object_name = PY_TYPE_OBJECT_TP_NAME;
    c.py_tuple_object_item = PY_TUPLE_OBJECT_OB_ITEM;
    c.string_data = PY_ASCII_OBJECT_SIZE;

    // Thread state (traditional frame)
    c.py_thread_state_frame = PY_THREAD_STATE_FRAME;
    c.py_thread_state_thread = PY_THREAD_STATE_THREAD;

    // Frame object (old-style _frame)
    c.py_frame_object_back = PY_FRAME_OBJECT_BACK;
    c.py_frame_object_code = PY_FRAME_OBJECT_CODE;
    c.py_frame_object_localsplus = PY_FRAME_OBJECT_LOCALSPLUS;
    c.py_frame_object_gen = PY_FRAME_OBJECT_GEN;

    // Code object
    c.py_code_object_co_flags = PY_CODE_OBJECT_CO_FLAGS;
    c.py_code_object_filename = PY_CODE_OBJECT_CO_FILENAME;
    c.py_code_object_name = PY_CODE_OBJECT_CO_NAME;
    c.py_code_object_varnames = PY_CODE_OBJECT_CO_VARNAMES;

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
    c.py_object_type = PY_OBJECT_OB_TYPE;
    c.py_type_object_name = PY_TYPE_OBJECT_TP_NAME;
    c.py_var_object_size = PY_VAR_OBJECT_OB_SIZE;
    c.py_tuple_object_item = PY_TUPLE_OBJECT_OB_ITEM;
    c.py_bytes_object_data = PY_BYTES_OBJECT_OB_SVAL;
    c.string_data = PY_ASCII_OBJECT_SIZE;

    // Thread state (traditional frame)
    c.py_thread_state_frame = PY_THREAD_STATE_FRAME;
    c.py_thread_state_thread = PY_THREAD_STATE_THREAD;

    // Frame object (old-style _frame)
    c.py_frame_object_back = PY_FRAME_OBJECT_BACK;
    c.py_frame_object_code = PY_FRAME_OBJECT_CODE;
    c.py_frame_object_lasti = PY_FRAME_OBJECT_LASTI;
    c.py_frame_object_localsplus = PY_FRAME_OBJECT_LOCALSPLUS;
    c.py_frame_object_gen = PY_FRAME_OBJECT_GEN;

    // Code object
    c.py_code_object_co_flags = PY_CODE_OBJECT_CO_FLAGS;
    c.py_code_object_filename = PY_CODE_OBJECT_CO_FILENAME;
    c.py_code_object_name = PY_CODE_OBJECT_CO_NAME;
    c.py_code_object_varnames = PY_CODE_OBJECT_CO_VARNAMES;
    c.py_code_object_firstlineno = PY_CODE_OBJECT_CO_FIRSTLINENO;

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
    c.py_object_type = PY_OBJECT_OB_TYPE;
    c.py_type_object_name = PY_TYPE_OBJECT_TP_NAME;
    c.py_var_object_size = PY_VAR_OBJECT_OB_SIZE;
    c.py_tuple_object_item = PY_TUPLE_OBJECT_OB_ITEM;
    c.py_bytes_object_data = PY_BYTES_OBJECT_OB_SVAL;
    c.string_data = PY_ASCII_OBJECT_SIZE;

    // Thread state (traditional frame)
    c.py_thread_state_frame = PY_THREAD_STATE_FRAME;
    c.py_thread_state_thread = PY_THREAD_STATE_THREAD;
    c.py_thread_state_interp = PY_THREAD_STATE_INTERP;

    // Frame object (old-style _frame)
    c.py_frame_object_back = PY_FRAME_OBJECT_BACK;
    c.py_frame_object_code = PY_FRAME_OBJECT_CODE;
    c.py_frame_object_lasti = PY_FRAME_OBJECT_LASTI;
    c.py_frame_object_localsplus = PY_FRAME_OBJECT_LOCALSPLUS;
    c.py_frame_object_gen = PY_FRAME_OBJECT_GEN;

    // Code object
    c.py_code_object_co_flags = PY_CODE_OBJECT_CO_FLAGS;
    c.py_code_object_filename = PY_CODE_OBJECT_CO_FILENAME;
    c.py_code_object_name = PY_CODE_OBJECT_CO_NAME;
    c.py_code_object_varnames = PY_CODE_OBJECT_CO_VARNAMES;
    c.py_code_object_firstlineno = PY_CODE_OBJECT_CO_FIRSTLINENO;
    c.py_code_object_linetable = PY_CODE_OBJECT_CO_LINETABLE;

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
    c.py_object_type = PY_OBJECT_OB_TYPE;
    c.py_type_object_name = PY_TYPE_OBJECT_TP_NAME;
    c.py_var_object_size = PY_VAR_OBJECT_OB_SIZE;
    c.py_tuple_object_item = PY_TUPLE_OBJECT_OB_ITEM;
    c.py_bytes_object_data = PY_BYTES_OBJECT_OB_SVAL;
    c.string_data = PY_ASCII_OBJECT_SIZE;

    // Thread state (new-style via _PyCFrame)
    c.py_thread_state_cframe = PY_THREAD_STATE_CFRAME;
    c.py_thread_state_thread = PY_THREAD_STATE_THREAD;

    // CFrame -> interpreter frame
    c.py_cframe_current_frame = PY_CFRAME_CURRENT_FRAME;

    // Interpreter frame (new-style)
    c.py_interpreter_frame_code = PY_INTERP_FRAME_CODE;
    c.py_interpreter_frame_previous = PY_INTERP_FRAME_PREVIOUS;
    c.py_interpreter_frame_localsplus = PY_INTERP_FRAME_LOCALSPLUS;
    c.py_interpreter_frame_prev_instr = PY_INTERP_FRAME_PREV_INSTR;

    // Code object
    c.py_code_object_co_flags = PY_CODE_OBJECT_CO_FLAGS;
    c.py_code_object_filename = PY_CODE_OBJECT_CO_FILENAME;
    c.py_code_object_name = PY_CODE_OBJECT_CO_NAME;
    c.py_code_object_qualname = PY_CODE_OBJECT_CO_QUALNAME;
    c.py_code_object_linetable = PY_CODE_OBJECT_CO_LINETABLE;
    c.py_code_object_firstlineno = PY_CODE_OBJECT_CO_FIRSTLINENO;

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
    c.py_object_type = PY_OBJECT_OB_TYPE;
    c.py_type_object_name = PY_TYPE_OBJECT_TP_NAME;
    c.py_var_object_size = PY_VAR_OBJECT_OB_SIZE;
    c.py_tuple_object_item = PY_TUPLE_OBJECT_OB_ITEM;
    c.py_bytes_object_data = PY_BYTES_OBJECT_OB_SVAL;
    c.string_data = PY_ASCII_OBJECT_SIZE;

    // Thread state (via _PyCFrame)
    c.py_thread_state_cframe = PY_THREAD_STATE_CFRAME;
    c.py_thread_state_thread = PY_THREAD_STATE_THREAD;
    c.py_thread_state_interp = PY_THREAD_STATE_INTERP;

    // CFrame -> interpreter frame
    c.py_cframe_current_frame = PY_CFRAME_CURRENT_FRAME;

    // Interpreter frame (new-style)
    c.py_interpreter_frame_code = PY_INTERP_FRAME_CODE;
    c.py_interpreter_frame_previous = PY_INTERP_FRAME_PREVIOUS;
    c.py_interpreter_frame_localsplus = PY_INTERP_FRAME_LOCALSPLUS;
    c.py_interpreter_frame_prev_instr = PY_INTERP_FRAME_PREV_INSTR;

    // Code object
    c.py_code_object_co_flags = PY_CODE_OBJECT_CO_FLAGS;
    c.py_code_object_filename = PY_CODE_OBJECT_CO_FILENAME;
    c.py_code_object_name = PY_CODE_OBJECT_CO_NAME;
    c.py_code_object_qualname = PY_CODE_OBJECT_CO_QUALNAME;
    c.py_code_object_linetable = PY_CODE_OBJECT_CO_LINETABLE;
    c.py_code_object_firstlineno = PY_CODE_OBJECT_CO_FIRSTLINENO;
    c.py_code_object_code_adaptive = PY_CODE_OBJECT_CO_CODE_ADAPTIVE;

    // 3.12+ generator/coroutine offsets
    c.py_coro_object_cr_awaiter = PY_CORO_OBJECT_CR_ORIGIN_OR_FINALIZER;
    c.py_gen_object_iframe = PY_GEN_OBJECT_GI_IFRAME;
    c.py_frame_object_owner = PY_INTERP_FRAME_OWNER;

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
    c.py_object_type = PY_OBJECT_OB_TYPE;
    c.py_type_object_name = PY_TYPE_OBJECT_TP_NAME;
    c.py_var_object_size = PY_VAR_OBJECT_OB_SIZE;
    c.py_tuple_object_item = PY_TUPLE_OBJECT_OB_ITEM;
    c.py_bytes_object_data = PY_BYTES_OBJECT_OB_SVAL;
    c.string_data = PY_ASCII_OBJECT_SIZE;

    // Thread state (3.13: current_frame is directly on _ts, no _PyCFrame)
    c.py_thread_state_cframe = PY_THREAD_STATE_CURRENT_FRAME;
    c.py_thread_state_thread = PY_THREAD_STATE_THREAD;
    c.py_thread_state_interp = PY_THREAD_STATE_INTERP;

    // 3.13: No _PyCFrame indirection - sentinel means "no second dereference"
    c.py_cframe_current_frame = BPF_LIB_DEFAULT_FIELD_OFFSET;

    // Interpreter frame (new-style, f_code renamed to f_executable)
    c.py_interpreter_frame_code = PY_INTERP_FRAME_CODE;
    c.py_interpreter_frame_previous = PY_INTERP_FRAME_PREVIOUS;
    c.py_interpreter_frame_localsplus = PY_INTERP_FRAME_LOCALSPLUS;
    c.py_interpreter_frame_prev_instr = PY_INTERP_FRAME_PREV_INSTR;

    // Code object
    c.py_code_object_co_flags = PY_CODE_OBJECT_CO_FLAGS;
    c.py_code_object_filename = PY_CODE_OBJECT_CO_FILENAME;
    c.py_code_object_name = PY_CODE_OBJECT_CO_NAME;
    c.py_code_object_qualname = PY_CODE_OBJECT_CO_QUALNAME;
    c.py_code_object_linetable = PY_CODE_OBJECT_CO_LINETABLE;
    c.py_code_object_firstlineno = PY_CODE_OBJECT_CO_FIRSTLINENO;
    c.py_code_object_code_adaptive = PY_CODE_OBJECT_CO_CODE_ADAPTIVE;

    // 3.12+ generator/coroutine offsets
    c.py_coro_object_cr_awaiter = PY_CORO_OBJECT_CR_ORIGIN_OR_FINALIZER;
    c.py_gen_object_iframe = PY_GEN_OBJECT_GI_IFRAME;
    c.py_frame_object_owner = PY_INTERP_FRAME_OWNER;

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
