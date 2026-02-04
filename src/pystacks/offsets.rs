/// Python version-specific offset configurations.
///
/// Each configuration matches the hardcoded offsets from the corresponding
/// Py*Offsets.cpp file in strobelight-libs.
use super::types::OffsetConfig;

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
    let mut c = OffsetConfig::default();
    c.py_object_type = 8;
    c.py_type_object_name = 24;
    c.py_thread_state_frame = 24;
    c.py_thread_state_thread = 176;
    c.py_frame_object_back = 24;
    c.py_frame_object_code = 32;
    c.py_frame_object_localsplus = 360;
    c.py_frame_object_gen = 96;
    c.py_code_object_co_flags = 36;
    c.py_code_object_filename = 104;
    c.py_code_object_name = 112;
    c.py_code_object_varnames = 72;
    c.py_tuple_object_item = 24;
    c.string_data = 48;
    c.tls_key_offset = 1396;
    c.t_current_state_offset = 1368;
    c.py_gil_offset = 1168;
    c.py_gil_last_holder = 1160;
    c.py_version_major = 3;
    c.py_version_minor = 8;
    c.py_version_micro = 0;
    c
}

#[allow(clippy::field_reassign_with_default)]
pub fn py39() -> OffsetConfig {
    let mut c = OffsetConfig::default();
    c.py_object_type = 8;
    c.py_type_object_name = 24;
    c.py_thread_state_frame = 24;
    c.py_thread_state_thread = 176;
    c.py_frame_object_back = 24;
    c.py_frame_object_code = 32;
    c.py_frame_object_lasti = 104;
    c.py_frame_object_localsplus = 360;
    c.py_frame_object_gen = 96;
    c.py_code_object_co_flags = 36;
    c.py_code_object_filename = 104;
    c.py_code_object_name = 112;
    c.py_code_object_varnames = 72;
    c.py_code_object_firstlineno = 40;
    c.py_tuple_object_item = 24;
    c.string_data = 48;
    c.tls_key_offset = 588;
    c.t_current_state_offset = 568;
    c.py_gil_offset = 368;
    c.py_gil_last_holder = 360;
    c.py_bytes_object_data = 32;
    c.py_var_object_size = 16;
    c.py_version_major = 3;
    c.py_version_minor = 9;
    c.py_version_micro = 0;
    c
}

#[allow(clippy::field_reassign_with_default)]
pub fn py310() -> OffsetConfig {
    let mut c = OffsetConfig::default();
    c.py_object_type = 8;
    c.py_type_object_name = 24;
    c.py_thread_state_frame = 24;
    c.py_thread_state_thread = 176;
    c.py_thread_state_interp = 16;
    c.py_interpreter_state_modules = 856;
    c.py_frame_object_back = 24;
    c.py_frame_object_code = 32;
    c.py_frame_object_lasti = 96;
    c.py_frame_object_localsplus = 352;
    c.py_frame_object_gen = 88;
    c.py_code_object_co_flags = 36;
    c.py_code_object_filename = 104;
    c.py_code_object_name = 112;
    c.py_code_object_varnames = 72;
    c.py_code_object_firstlineno = 40;
    c.py_code_object_linetable = 120;
    c.py_tuple_object_item = 24;
    c.string_data = 48;
    c.tls_key_offset = 588;
    c.t_current_state_offset = 568;
    c.py_gil_offset = 368;
    c.py_gil_last_holder = 360;
    c.py_bytes_object_data = 32;
    c.py_var_object_size = 16;
    c.py_version_major = 3;
    c.py_version_minor = 10;
    c.py_version_micro = 0;
    c
}

#[allow(clippy::field_reassign_with_default)]
pub fn py311() -> OffsetConfig {
    let mut c = OffsetConfig::default();
    c.py_object_type = 8;
    c.py_type_object_name = 24;
    c.py_thread_state_cframe = 56;
    c.py_thread_state_thread = 152;
    c.py_cframe_current_frame = 8;
    c.py_interpreter_frame_code = 32;
    c.py_interpreter_frame_previous = 48;
    c.py_interpreter_frame_localsplus = 72;
    c.py_interpreter_frame_prev_instr = 56;
    c.py_code_object_co_flags = 48;
    c.py_code_object_filename = 112;
    c.py_code_object_name = 120;
    c.py_code_object_qualname = 128;
    c.py_code_object_linetable = 136;
    c.py_code_object_firstlineno = 72;
    c.py_tuple_object_item = 24;
    c.py_bytes_object_data = 32;
    c.py_var_object_size = 16;
    c.string_data = 48;
    c.tls_key_offset = 596;
    c.t_current_state_offset = 576;
    c.py_gil_offset = 376;
    c.py_gil_last_holder = 368;
    c.py_version_major = 3;
    c.py_version_minor = 11;
    c.py_version_micro = 0;
    c
}

#[allow(clippy::field_reassign_with_default)]
pub fn py312() -> OffsetConfig {
    let mut c = OffsetConfig::default();
    c.py_object_type = 8;
    c.py_type_object_name = 24;
    c.py_thread_state_cframe = 56;
    c.py_thread_state_thread = 136;
    c.py_thread_state_interp = 16;
    c.py_interpreter_state_modules = 944;
    c.py_cframe_current_frame = 0;
    c.py_interpreter_frame_code = 0;
    c.py_interpreter_frame_previous = 8;
    c.py_interpreter_frame_localsplus = 72;
    c.py_interpreter_frame_prev_instr = 56;
    c.py_code_object_co_flags = 48;
    c.py_code_object_filename = 112;
    c.py_code_object_name = 120;
    c.py_code_object_qualname = 128;
    c.py_code_object_linetable = 136;
    c.py_code_object_firstlineno = 68;
    c.py_code_object_code_adaptive = 192;
    c.py_tuple_object_item = 24;
    c.tls_key_offset = 1548;
    c.py_bytes_object_data = 32;
    c.py_var_object_size = 16;
    c.string_data = 40;
    c.py_coro_object_cr_awaiter = 64;
    c.py_gen_object_iframe = 80;
    c.py_frame_object_owner = 70;
    c.py_version_major = 3;
    c.py_version_minor = 12;
    c.py_version_micro = 4;
    c
}

#[allow(clippy::field_reassign_with_default)]
pub fn py313() -> OffsetConfig {
    let mut c = OffsetConfig::default();
    c.py_object_type = 8;
    c.py_type_object_name = 24;
    c.py_thread_state_cframe = 72;
    c.py_thread_state_thread = 152;
    c.py_thread_state_interp = 16;
    c.py_interpreter_state_modules = 944;
    c.py_cframe_current_frame = super::types::BPF_LIB_DEFAULT_FIELD_OFFSET;
    c.py_interpreter_frame_code = 0;
    c.py_interpreter_frame_previous = 8;
    c.py_interpreter_frame_localsplus = 72;
    c.py_interpreter_frame_prev_instr = 56;
    c.py_code_object_co_flags = 48;
    c.py_code_object_filename = 112;
    c.py_code_object_name = 120;
    c.py_code_object_qualname = 128;
    c.py_code_object_linetable = 136;
    c.py_code_object_firstlineno = 68;
    c.py_code_object_code_adaptive = 200;
    c.py_tuple_object_item = 24;
    c.tls_key_offset = 2164;
    c.py_bytes_object_data = 32;
    c.py_var_object_size = 16;
    c.string_data = 40;
    c.py_coro_object_cr_awaiter = 64;
    c.py_gen_object_iframe = 80;
    c.py_frame_object_owner = 70;
    c.py_runtime_state_interpreters_head = 632;
    c.py_interpreter_state_gil_locked = 7768;
    c.py_interpreter_state_gil_last_holder = 7760;
    c.py_version_major = 3;
    c.py_version_minor = 13;
    c.py_version_micro = 0;
    c
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
