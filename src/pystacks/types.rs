/// Rust repr(C) types matching the BPF-shared C structs from strobelight-libs.
///
/// These must match the exact memory layout of the C structs used by the BPF
/// kernel code. The BPF maps use these as keys and values, so any mismatch
/// will cause silent data corruption.
pub const BPF_LIB_DEFAULT_FIELD_OFFSET: usize = 9999;
pub const BPF_LIB_PYSTACKS_CLASS_NAME_LEN: usize = 128;
pub const BPF_LIB_PYSTACKS_FUNCTION_NAME_LEN: usize = 96;
pub const BPF_LIB_PYSTACKS_FILE_NAME_LEN: usize = 192;
pub const BPF_LIB_PYSTACKS_QUAL_NAME_LEN: usize =
    BPF_LIB_PYSTACKS_CLASS_NAME_LEN + BPF_LIB_PYSTACKS_FUNCTION_NAME_LEN;
pub const BPF_LIB_MAX_STACK_DEPTH: usize = 127;
pub const BPF_LIB_DEFAULT_MAP_SIZE: usize = 1024;

pub type SymbolIdT = u32;

/// Matches `struct stack_walker_frame` from stack_walker.h.
/// 8 bytes: symbol_id (u32) + inst_idx (i32).
#[repr(C)]
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, Hash)]
pub struct StackWalkerFrame {
    pub symbol_id: SymbolIdT,
    pub inst_idx: i32,
}

/// Matches `struct read_file_name` from python/include/structs.h.
/// value: 192 bytes, fault_addr: usize.
#[repr(C)]
#[derive(Clone)]
pub struct ReadFileName {
    pub value: [u8; BPF_LIB_PYSTACKS_FILE_NAME_LEN],
    pub fault_addr: usize,
}

impl Default for ReadFileName {
    fn default() -> Self {
        Self {
            value: [0u8; BPF_LIB_PYSTACKS_FILE_NAME_LEN],
            fault_addr: 0,
        }
    }
}

/// Matches `struct read_qualified_name` from python/include/structs.h.
/// value: 224 bytes, fault_addr: usize.
#[repr(C)]
#[derive(Clone)]
pub struct ReadQualifiedName {
    pub value: [u8; BPF_LIB_PYSTACKS_QUAL_NAME_LEN],
    pub fault_addr: usize,
}

impl Default for ReadQualifiedName {
    fn default() -> Self {
        Self {
            value: [0u8; BPF_LIB_PYSTACKS_QUAL_NAME_LEN],
            fault_addr: 0,
        }
    }
}

/// Matches `struct pystacks_symbol` from python/include/structs.h.
/// Used as the key in the `pystacks_symbols` BPF map.
#[repr(C)]
#[derive(Clone, Default)]
pub struct PystacksSymbol {
    pub filename: ReadFileName,
    pub qualname: ReadQualifiedName,
    pub fault_pid: i32,
}

/// Matches `struct pystacks_line_table` from python/include/structs.h.
#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct PystacksLineTable {
    pub first_line: u32,
    pub length: u32,
    pub addr: usize,
    pub pid: i32,
}

/// Matches `OffsetConfig` from python/include/OffsetConfig.h.
/// Contains field offsets for Python runtime structures.
/// 51 usize fields + 3 i32 fields.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct OffsetConfig {
    pub py_object_type: usize,
    pub py_type_object_name: usize,
    pub py_thread_state_frame: usize,
    pub py_thread_state_cframe: usize,
    pub py_thread_state_shadow_frame: usize,
    pub py_thread_state_thread: usize,
    pub py_thread_state_interp: usize,
    pub py_interpreter_state_modules: usize,
    pub py_cframe_current_frame: usize,
    pub py_frame_object_back: usize,
    pub py_frame_object_code: usize,
    pub py_frame_object_lasti: usize,
    pub py_frame_object_localsplus: usize,
    pub py_frame_object_gen: usize,
    pub py_interpreter_frame_code: usize,
    pub py_interpreter_frame_previous: usize,
    pub py_interpreter_frame_localsplus: usize,
    pub py_interpreter_frame_prev_instr: usize,
    pub py_gen_object_gi_shadow_frame: usize,
    pub py_code_object_co_flags: usize,
    pub py_code_object_filename: usize,
    pub py_code_object_name: usize,
    pub py_code_object_varnames: usize,
    pub py_code_object_firstlineno: usize,
    pub py_code_object_linetable: usize,
    pub py_code_object_code_adaptive: usize,
    pub py_tuple_object_item: usize,
    pub py_code_object_qualname: usize,
    pub py_coro_object_cr_awaiter: usize,
    pub py_shadow_frame_prev: usize,
    pub py_shadow_frame_data: usize,
    pub py_shadow_frame_ptr_mask: usize,
    pub py_shadow_frame_ptr_kind_mask: usize,
    pub py_shadow_frame_pysf_code_rt: usize,
    pub py_shadow_frame_pysf_pycode: usize,
    pub py_shadow_frame_pysf_pyframe: usize,
    pub py_shadow_frame_pysf_rtfs: usize,
    pub code_runtime_py_code: usize,
    pub runtime_frame_state_py_code: usize,
    pub string_data: usize,
    pub tls_key_offset: usize,
    pub t_current_state_offset: usize,
    pub py_gil_offset: usize,
    pub py_gil_last_holder: usize,
    pub py_runtime_state_interpreters_head: usize,
    pub py_interpreter_state_gil_locked: usize,
    pub py_interpreter_state_gil_last_holder: usize,
    pub py_bytes_object_data: usize,
    pub py_var_object_size: usize,
    pub py_frame_object_owner: usize,
    pub py_gen_object_iframe: usize,

    pub py_version_major: i32,
    pub py_version_minor: i32,
    pub py_version_micro: i32,
}

impl Default for OffsetConfig {
    fn default() -> Self {
        Self {
            py_object_type: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_type_object_name: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_thread_state_frame: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_thread_state_cframe: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_thread_state_shadow_frame: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_thread_state_thread: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_thread_state_interp: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_interpreter_state_modules: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_cframe_current_frame: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_frame_object_back: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_frame_object_code: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_frame_object_lasti: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_frame_object_localsplus: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_frame_object_gen: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_interpreter_frame_code: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_interpreter_frame_previous: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_interpreter_frame_localsplus: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_interpreter_frame_prev_instr: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_gen_object_gi_shadow_frame: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_code_object_co_flags: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_code_object_filename: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_code_object_name: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_code_object_varnames: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_code_object_firstlineno: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_code_object_linetable: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_code_object_code_adaptive: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_tuple_object_item: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_code_object_qualname: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_coro_object_cr_awaiter: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_shadow_frame_prev: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_shadow_frame_data: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_shadow_frame_ptr_mask: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_shadow_frame_ptr_kind_mask: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_shadow_frame_pysf_code_rt: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_shadow_frame_pysf_pycode: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_shadow_frame_pysf_pyframe: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_shadow_frame_pysf_rtfs: BPF_LIB_DEFAULT_FIELD_OFFSET,
            code_runtime_py_code: BPF_LIB_DEFAULT_FIELD_OFFSET,
            runtime_frame_state_py_code: BPF_LIB_DEFAULT_FIELD_OFFSET,
            string_data: BPF_LIB_DEFAULT_FIELD_OFFSET,
            tls_key_offset: BPF_LIB_DEFAULT_FIELD_OFFSET,
            t_current_state_offset: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_gil_offset: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_gil_last_holder: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_runtime_state_interpreters_head: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_interpreter_state_gil_locked: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_interpreter_state_gil_last_holder: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_bytes_object_data: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_var_object_size: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_frame_object_owner: BPF_LIB_DEFAULT_FIELD_OFFSET,
            py_gen_object_iframe: BPF_LIB_DEFAULT_FIELD_OFFSET,

            py_version_major: 0,
            py_version_minor: 0,
            py_version_micro: 0,
        }
    }
}

/// Matches `PyPidData` from python/include/PyPidData.h.
/// Per-process Python runtime configuration stored in BPF map.
#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct PyPidData {
    pub offsets: OffsetConfig,
    pub use_tls: bool,
    pub py_runtime_addr: usize,
    pub current_state_addr: usize,
    pub tls_key_addr: usize,
    pub gil_locked_addr: usize,
    pub gil_last_holder_addr: usize,
}

/// BPF binary ID for binary-level caching.
/// Matches `struct bpf_lib_binary_id` from include/binary_id.h.
/// Fields: ino_t inode (u64), uint64_t dev (u64) — in that order.
#[repr(C)]
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, Hash)]
pub struct BpfLibBinaryId {
    pub inode: u64,
    pub dev: u64,
}

// Size assertions to validate struct layout matches C definitions.
// These are compile-time checks - any mismatch is a build error.
const _: () = {
    assert!(std::mem::size_of::<StackWalkerFrame>() == 8);
    assert!(std::mem::align_of::<StackWalkerFrame>() == 4);

    // ReadFileName: 192 bytes + padding + usize
    assert!(std::mem::size_of::<ReadFileName>() == BPF_LIB_PYSTACKS_FILE_NAME_LEN + 8);

    // ReadQualifiedName: 224 bytes + usize
    assert!(std::mem::size_of::<ReadQualifiedName>() == BPF_LIB_PYSTACKS_QUAL_NAME_LEN + 8);

    // PystacksLineTable: u32 + u32 + usize + i32 + padding
    // On 64-bit: 4 + 4 + 8 + 4 + 4(pad) = 24
    assert!(std::mem::size_of::<PystacksLineTable>() == 24);

    // OffsetConfig: 51 usize fields + 3 i32 fields
    // On 64-bit: 51*8 + 3*4 + 4(pad) = 408 + 12 + 4 = 424
    assert!(std::mem::size_of::<OffsetConfig>() == 424);

    // PystacksSymbol: ReadFileName(200) + ReadQualifiedName(232) + i32(4) + padding(4) = 440
    assert!(std::mem::size_of::<PystacksSymbol>() == 440);

    // PyPidData: OffsetConfig(424) + bool(1) + padding(7) + 5*usize(40) = 472
    assert!(std::mem::size_of::<PyPidData>() == 472);

    // BpfLibBinaryId: u64 + u64 = 16
    assert!(std::mem::size_of::<BpfLibBinaryId>() == 16);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stack_walker_frame_size() {
        assert_eq!(std::mem::size_of::<StackWalkerFrame>(), 8);
        assert_eq!(std::mem::align_of::<StackWalkerFrame>(), 4);
    }

    #[test]
    fn test_offset_config_default() {
        let cfg = OffsetConfig::default();
        assert_eq!(cfg.py_object_type, BPF_LIB_DEFAULT_FIELD_OFFSET);
        assert_eq!(cfg.py_version_major, 0);
        assert_eq!(cfg.py_version_minor, 0);
    }

    #[test]
    fn test_py_pid_data_default() {
        let data = PyPidData::default();
        assert!(!data.use_tls);
        assert_eq!(data.py_runtime_addr, 0);
        assert_eq!(data.offsets.py_object_type, BPF_LIB_DEFAULT_FIELD_OFFSET);
    }

    #[test]
    fn test_pystacks_symbol_zero_init() {
        let sym = PystacksSymbol::default();
        assert_eq!(sym.fault_pid, 0);
        assert_eq!(sym.filename.fault_addr, 0);
        assert_eq!(sym.qualname.fault_addr, 0);
        assert!(sym.filename.value.iter().all(|&b| b == 0));
        assert!(sym.qualname.value.iter().all(|&b| b == 0));
    }
}
