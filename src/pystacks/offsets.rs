/// Python version-specific offset configurations.
///
/// Offsets are pre-computed constants generated from CPython struct definitions.
/// Simple offsets use `offsetof()` and `sizeof()`, compound offsets (nested
/// structs) are computed by the generation script via a C program.
use super::bindings;
use super::types::OffsetConfig;
use super::types::BPF_LIB_DEFAULT_FIELD_OFFSET;

/// Where a `_Py_DebugOffsets` (3.13+) says what it is: its cookie, the version
/// of its Python, and whether that is a free-threaded build. The table starts
/// with these, the same way in every version and build that has one.
pub const DEBUG_OFFSETS_COOKIE: usize = bindings::v3_14_7t::PY_DEBUG_OFFSETS_COOKIE;
pub const DEBUG_OFFSETS_VERSION: usize = bindings::v3_14_7t::PY_DEBUG_OFFSETS_VERSION;
pub const DEBUG_OFFSETS_FREE_THREADED: usize = bindings::v3_14_7t::PY_DEBUG_OFFSETS_FREE_THREADED;

/// Returns the OffsetConfig for a given Python (major, minor) version of the
/// default build. See `for_build`.
pub fn for_version(major: i32, minor: i32) -> Option<OffsetConfig> {
    for_build(major, minor, false)
}

/// Returns the OffsetConfig for a given Python (major, minor) version and build:
/// free-threaded (`--disable-gil`) is a different ABI from the default one.
/// Returns None if the version or the build is not supported.
/// Falls back to Python 3.14 for unknown versions >= 3.14 of the default build.
pub fn for_build(major: i32, minor: i32, free_threaded: bool) -> Option<OffsetConfig> {
    if major != 3 {
        return None;
    }
    if free_threaded {
        // No fallback: a table for another layout reads the wrong words.
        return match minor {
            14 => Some(py314t()),
            _ => None,
        };
    }
    match minor {
        8 => Some(py38()),
        9 => Some(py39()),
        10 => Some(py310()),
        11 => Some(py311()),
        12 => Some(py312()),
        13 => Some(py313()),
        14 => Some(py314()),
        m if m > 14 => Some(py314()), // fallback to latest known
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

#[allow(clippy::field_reassign_with_default)]
pub fn py314() -> OffsetConfig {
    use bindings::v3_14_0::*;
    let mut c = OffsetConfig::default();

    // Common offsets
    c.py_object_type = PY_OBJECT_OB_TYPE;
    c.py_type_object_name = PY_TYPE_OBJECT_TP_NAME;
    c.py_var_object_size = PY_VAR_OBJECT_OB_SIZE;
    c.py_tuple_object_item = PY_TUPLE_OBJECT_OB_ITEM;
    c.py_bytes_object_data = PY_BYTES_OBJECT_OB_SVAL;
    c.string_data = PY_ASCII_OBJECT_SIZE;

    // Thread state (like 3.13: current_frame directly on _ts, no _PyCFrame)
    c.py_thread_state_cframe = PY_THREAD_STATE_CURRENT_FRAME;
    c.py_thread_state_thread = PY_THREAD_STATE_THREAD;
    c.py_thread_state_interp = PY_THREAD_STATE_INTERP;

    // No _PyCFrame indirection - sentinel means "no second dereference"
    c.py_cframe_current_frame = BPF_LIB_DEFAULT_FIELD_OFFSET;

    // Interpreter frame (same shape as 3.13; offsets shifted)
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
    c.py_version_minor = 14;
    c.py_version_micro = 0;
    c
}

/// Free-threaded 3.14: the fields `py314` sets, from that build's bindings.
#[allow(clippy::field_reassign_with_default)]
pub fn py314t() -> OffsetConfig {
    use bindings::v3_14_7t::*;
    let mut c = OffsetConfig::default();

    // Common offsets
    c.py_object_type = PY_OBJECT_OB_TYPE;
    c.py_type_object_name = PY_TYPE_OBJECT_TP_NAME;
    c.py_var_object_size = PY_VAR_OBJECT_OB_SIZE;
    c.py_tuple_object_item = PY_TUPLE_OBJECT_OB_ITEM;
    c.py_bytes_object_data = PY_BYTES_OBJECT_OB_SVAL;
    c.string_data = PY_ASCII_OBJECT_SIZE;

    // Thread state (current_frame directly on _ts, no _PyCFrame)
    c.py_thread_state_cframe = PY_THREAD_STATE_CURRENT_FRAME;
    c.py_thread_state_thread = PY_THREAD_STATE_THREAD;
    c.py_thread_state_interp = PY_THREAD_STATE_INTERP;

    // No _PyCFrame indirection - sentinel means "no second dereference"
    c.py_cframe_current_frame = BPF_LIB_DEFAULT_FIELD_OFFSET;

    // Interpreter frame (as in the default build, but for owner)
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
    c.py_version_minor = 14;
    c.py_version_micro = 0;
    c
}

/// Offsets for reading Python objects out of a process from user space: a
/// dict, an instance's attributes, a module, an int, a string (see
/// `pyobject.rs`). BPF does none of this, so these are not part of the
/// `OffsetConfig` it shares; they come from the same generated bindings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectOffsets {
    // _PyRuntimeState and PyInterpreterState: the way in. PyInterpreterState
    // grows in patch releases, so these two are what the release the bindings
    // were generated from has; a process says its own in the table it keeps
    // at `runtime_debug_offsets` (_Py_DebugOffsets, 3.13+), at these two
    // places in it. The table has `interpreters.head` only, and the list that
    // starts there is newest first; the main interpreter is
    // `interpreters.main`, the next field, found from head by where the two
    // are in the bindings.
    pub runtime_interpreters_head: usize,
    pub runtime_interpreters_main: usize,
    pub interp_modules: usize,
    pub runtime_debug_offsets: usize,
    pub debug_interpreters_head: usize,
    pub debug_imports_modules: usize,

    // PyObject, and the bytes ahead of it where its managed dict pointer sits
    pub ob_type: usize,
    pub managed_dict_before: usize,

    // PyTypeObject / PyHeapTypeObject
    pub type_basicsize: usize,
    pub type_flags: usize,
    pub type_dictoffset: usize,
    pub heap_type_cached_keys: usize,

    // PyASCIIObject / PyCompactUnicodeObject
    pub ascii_length: usize,
    pub ascii_state: usize,
    pub ascii_size: usize,
    pub compact_unicode_size: usize,

    // PyLongObject
    pub long_lv_tag: usize,
    pub long_ob_digit: usize,

    // PyModuleObject
    pub module_md_dict: usize,

    // PyDictObject
    pub dict_ma_keys: usize,
    pub dict_ma_values: usize,

    // PyDictKeysObject: its header, then the index table, then the entries
    pub keys_log2_index_bytes: usize,
    pub keys_kind: usize,
    pub keys_nentries: usize,
    pub keys_indices: usize,

    // PyDictKeyEntry and PyDictUnicodeEntry
    pub key_entry_size: usize,
    pub key_entry_key: usize,
    pub key_entry_value: usize,
    pub unicode_entry_size: usize,
    pub unicode_entry_key: usize,
    pub unicode_entry_value: usize,

    // PyDictValues
    pub values_valid: usize,
    pub values_values: usize,
}

macro_rules! object_offsets {
    ($version:ident) => {{
        use bindings::$version::*;
        ObjectOffsets {
            runtime_interpreters_head: PYRUNTIME_INTERPRETERS_HEAD_OFFSET,
            runtime_interpreters_main: PYRUNTIME_INTERPRETERS_MAIN_OFFSET,
            interp_modules: PYINTERP_MODULES_OFFSET,
            runtime_debug_offsets: PYRUNTIME_DEBUG_OFFSETS_OFFSET,
            debug_interpreters_head: PY_DEBUG_OFFSETS_RUNTIME_INTERPRETERS_HEAD,
            debug_imports_modules: PY_DEBUG_OFFSETS_INTERP_IMPORTS_MODULES,
            ob_type: PY_OBJECT_OB_TYPE,
            managed_dict_before: PY_OBJECT_MANAGED_DICT_BEFORE,
            type_basicsize: PY_TYPE_OBJECT_TP_BASICSIZE,
            type_flags: PY_TYPE_OBJECT_TP_FLAGS,
            type_dictoffset: PY_TYPE_OBJECT_TP_DICTOFFSET,
            heap_type_cached_keys: PY_HEAP_TYPE_OBJECT_HT_CACHED_KEYS,
            ascii_length: PY_ASCII_OBJECT_LENGTH,
            ascii_state: PY_ASCII_OBJECT_STATE,
            ascii_size: PY_ASCII_OBJECT_SIZE,
            compact_unicode_size: PY_COMPACT_UNICODE_OBJECT_SIZE,
            long_lv_tag: PY_LONG_OBJECT_LV_TAG,
            long_ob_digit: PY_LONG_OBJECT_OB_DIGIT,
            module_md_dict: PY_MODULE_OBJECT_MD_DICT,
            dict_ma_keys: PY_DICT_OBJECT_MA_KEYS,
            dict_ma_values: PY_DICT_OBJECT_MA_VALUES,
            keys_log2_index_bytes: PY_DICT_KEYS_DK_LOG2_INDEX_BYTES,
            keys_kind: PY_DICT_KEYS_DK_KIND,
            keys_nentries: PY_DICT_KEYS_DK_NENTRIES,
            keys_indices: PY_DICT_KEYS_DK_INDICES,
            key_entry_size: PY_DICT_KEY_ENTRY_SIZE,
            key_entry_key: PY_DICT_KEY_ENTRY_ME_KEY,
            key_entry_value: PY_DICT_KEY_ENTRY_ME_VALUE,
            unicode_entry_size: PY_DICT_UNICODE_ENTRY_SIZE,
            unicode_entry_key: PY_DICT_UNICODE_ENTRY_ME_KEY,
            unicode_entry_value: PY_DICT_UNICODE_ENTRY_ME_VALUE,
            values_valid: PY_DICT_VALUES_VALID,
            values_values: PY_DICT_VALUES_VALUES,
        }
    }};
}

/// The `ObjectOffsets` for a Python (major, minor), `None` for a version with
/// no table. 3.13 and 3.14 have one. An older version needs its own block in
/// `scripts/generate_python_bindings.py` first, and `pyobject.rs` taught its
/// layouts where they differ: up to 3.10 the index table's size comes from
/// `dk_size` and there are no unicode-only entries, and 3.11 and 3.12 keep an
/// instance's values behind a pointer ahead of the object, not inline.
pub fn object_offsets_for_version(major: i32, minor: i32) -> Option<ObjectOffsets> {
    object_offsets_for_build(major, minor, false)
}

/// The `ObjectOffsets` for a Python (major, minor) and build. `None` for a
/// free-threaded build: `pyobject.rs` reads a str's state bits, which that
/// build lays out differently, so offsets alone would not read its objects.
/// Nothing asks for one yet: thread names are read as for the default build.
pub fn object_offsets_for_build(
    major: i32,
    minor: i32,
    free_threaded: bool,
) -> Option<ObjectOffsets> {
    if major != 3 || free_threaded {
        return None;
    }
    match minor {
        13 => Some(object_offsets!(v3_13_0)),
        m if m >= 14 => Some(object_offsets!(v3_14_0)), // the latest known
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_for_version_known() {
        assert!(for_version(3, 8).is_some());
        assert!(for_version(3, 13).is_some());
        assert!(for_version(3, 14).is_some());
    }

    #[test]
    fn test_for_version_unknown() {
        assert!(for_version(2, 7).is_none());
        assert!(for_version(3, 7).is_none());
    }

    #[test]
    fn test_for_version_future_fallback() {
        let future = for_version(3, 15).unwrap();
        assert_eq!(future.py_version_minor, 14); // falls back to 3.14
    }

    #[test]
    fn test_object_offsets_are_for_313_and_up() {
        assert!(object_offsets_for_version(3, 12).is_none());
        assert!(object_offsets_for_version(2, 7).is_none());
        let o = object_offsets_for_version(3, 13).unwrap();
        assert_eq!((o.dict_ma_keys, o.dict_ma_values), (32, 40));
        assert_eq!((o.keys_nentries, o.keys_indices), (24, 32));
        assert_eq!((o.key_entry_size, o.unicode_entry_size), (24, 16));
        assert_eq!((o.values_valid, o.values_values), (3, 8));
        assert_eq!(o.managed_dict_before, 24);
        assert_eq!(o.interp_modules, 7656);
        // 3.14 moved the interpreter state's fields, not the objects'.
        let p = object_offsets_for_version(3, 14).unwrap();
        assert_eq!(p.interp_modules, 7664);
        // Nor is the process's own table of offsets laid out the same.
        assert_eq!((o.debug_imports_modules, p.debug_imports_modules), (88, 96));
        assert_eq!(p.heap_type_cached_keys, o.heap_type_cached_keys);
        assert_eq!(object_offsets_for_version(3, 15), Some(p));
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
    fn test_py314_offsets() {
        let c = py314();
        assert_eq!(c.py_version_minor, 14);
        assert_eq!(c.py_thread_state_cframe, 72);
        assert_eq!(c.py_cframe_current_frame, BPF_LIB_DEFAULT_FIELD_OFFSET);
        assert_eq!(c.tls_key_offset, 2340);
        assert_eq!(c.py_runtime_state_interpreters_head, 808);
        assert_eq!(c.py_interpreter_frame_localsplus, 80);
        assert_eq!(c.py_frame_object_owner, 74);
        assert_eq!(c.py_tuple_object_item, 32);
        assert_eq!(c.py_interpreter_state_gil_locked, 7776);
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

    /// Each field of an OffsetConfig as (name, value), from its Debug form:
    /// the struct has no PartialEq to compare two of them with.
    fn fields(c: &OffsetConfig) -> Vec<(String, String)> {
        let debug = format!("{c:?}");
        let body = debug
            .trim_start_matches("OffsetConfig { ")
            .trim_end_matches(" }");
        body.split(", ")
            .map(|f| f.split_once(": ").unwrap())
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect()
    }

    #[test]
    fn test_for_build_default_build() {
        let tables = [
            (8, py38()),
            (9, py39()),
            (10, py310()),
            (11, py311()),
            (12, py312()),
            (13, py313()),
            (14, py314()),
            (15, py314()), // falls back to 3.14
        ];
        for (minor, table) in &tables {
            assert_eq!(fields(&for_build(3, *minor, false).unwrap()), fields(table));
            assert_eq!(fields(&for_version(3, *minor).unwrap()), fields(table));
        }
        assert!(for_build(3, 7, false).is_none());
        assert!(for_build(2, 7, false).is_none());
    }

    #[test]
    fn test_py314t_offsets() {
        let c = for_build(3, 14, true).unwrap();
        assert_eq!((c.py_version_major, c.py_version_minor), (3, 14));
        // A 32-byte object header: ob_type is its last word, and a field behind
        // a header is 16 bytes further than in the default build (24 when it is
        // also behind co_tlbc, which only this build's code object has).
        assert_eq!(c.py_object_type, 24);
        assert_eq!(c.py_var_object_size, 32);
        assert_eq!(c.string_data, 56);
        assert_eq!(c.py_type_object_name, 40);
        assert_eq!(c.py_tuple_object_item, 48);
        assert_eq!(c.py_bytes_object_data, 48);
        assert_eq!(c.py_code_object_co_flags, 64);
        assert_eq!(c.py_code_object_firstlineno, 84);
        assert_eq!(c.py_code_object_filename, 128);
        assert_eq!(c.py_code_object_name, 136);
        assert_eq!(c.py_code_object_qualname, 144);
        assert_eq!(c.py_code_object_linetable, 152);
        assert_eq!(c.py_code_object_code_adaptive, 232);
        // The frame has tlbc_index ahead of owner, and is otherwise the same.
        assert_eq!(c.py_frame_object_owner, 78);
        assert_eq!(c.py_interpreter_frame_code, 0);
        assert_eq!(c.py_interpreter_frame_previous, 8);
        assert_eq!(c.py_interpreter_frame_prev_instr, 56);
        assert_eq!(c.py_interpreter_frame_localsplus, 80);
        // Neither the thread state nor the runtime has an object header.
        let d = py314();
        assert_eq!(c.py_thread_state_cframe, d.py_thread_state_cframe);
        assert_eq!(c.py_thread_state_thread, d.py_thread_state_thread);
        assert_eq!(c.tls_key_offset, d.tls_key_offset);
    }

    #[test]
    fn test_py314t_sets_the_fields_py314_sets() {
        let unset = BPF_LIB_DEFAULT_FIELD_OFFSET.to_string();
        let (default, free_threaded) = (fields(&py314()), fields(&py314t()));
        for ((name, d), (_, t)) in default.iter().zip(&free_threaded) {
            assert_eq!(*d == unset, *t == unset, "{name}");
        }
    }

    #[test]
    fn test_for_build_free_threaded_without_a_table() {
        assert!(for_build(3, 12, true).is_none());
        assert!(for_build(3, 13, true).is_none());
        assert!(for_build(3, 15, true).is_none()); // no fallback
        assert!(for_build(2, 7, true).is_none());
    }

    #[test]
    fn test_object_offsets_for_build() {
        for minor in 12..=15 {
            assert_eq!(
                object_offsets_for_build(3, minor, false),
                object_offsets_for_version(3, minor)
            );
            assert!(object_offsets_for_build(3, minor, true).is_none());
        }
    }

    #[test]
    fn test_debug_offsets_start() {
        use bindings::{v3_13_0, v3_14_0, v3_14_7t};
        assert_eq!(
            (
                DEBUG_OFFSETS_COOKIE,
                DEBUG_OFFSETS_VERSION,
                DEBUG_OFFSETS_FREE_THREADED
            ),
            (0, 8, 16)
        );
        // The table is where every version and build has it.
        assert_eq!(v3_14_7t::PYRUNTIME_DEBUG_OFFSETS_OFFSET, 0);
        assert_eq!(v3_14_0::PYRUNTIME_DEBUG_OFFSETS_OFFSET, 0);
        assert_eq!(v3_13_0::PYRUNTIME_DEBUG_OFFSETS_OFFSET, 0);
        // And starts with those three words in each: what follows them (size,
        // finalizing, then interpreters_head) is at 24 + 16.
        assert_eq!(v3_14_7t::PY_DEBUG_OFFSETS_RUNTIME_INTERPRETERS_HEAD, 40);
        assert_eq!(v3_14_0::PY_DEBUG_OFFSETS_RUNTIME_INTERPRETERS_HEAD, 40);
        assert_eq!(v3_13_0::PY_DEBUG_OFFSETS_RUNTIME_INTERPRETERS_HEAD, 40);
    }
}
