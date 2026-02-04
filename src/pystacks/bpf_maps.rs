/// BPF map management for pystacks.
///
/// Uses the generated pystacks skeleton types for proper BSS field access.
/// The pystacks BPF object is linked into the main systing_system BPF object,
/// so we access maps through the main loaded BPF object.

#[allow(
    clippy::all,
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals,
    dead_code
)]
mod skel {
    include!(concat!(env!("OUT_DIR"), "/pystacks.skel.rs"));
}

use crate::pystacks::types::PyPidData;
use libbpf_rs::{MapCore, Object};
use std::os::fd::{AsFd, AsRawFd};

/// Holds BPF map file descriptors and BSS access for pystacks.
pub struct PystacksMaps {
    pub symbols_fd: i32,
    pub linetables_fd: i32,
    pub pid_config_fd: i32,
    pub targeted_pids_fd: i32,
    bss_fd: i32,
    bss_size: usize,
}

impl PystacksMaps {
    /// Initialize map FDs from the loaded BPF object.
    pub fn new(bpf_object: &Object) -> Option<Self> {
        let symbols_fd = get_map_fd(bpf_object, "pystacks_symbols")?;
        let linetables_fd = get_map_fd(bpf_object, "pystacks_linetables")?;
        let pid_config_fd = get_map_fd(bpf_object, "pystacks_pid_config")?;
        let targeted_pids_fd = get_map_fd(bpf_object, "targeted_pids")?;

        // Find the BSS map - it may be named "systing_.bss" or similar
        let (bss_fd, bss_size) = find_bss_map(bpf_object)?;

        Some(Self {
            symbols_fd,
            linetables_fd,
            pid_config_fd,
            targeted_pids_fd,
            bss_fd,
            bss_size,
        })
    }

    /// Add a PID to the targeted_pids BPF map.
    pub fn add_targeted_pid(&self, pid: i32) -> bool {
        let targeted: u8 = 1;
        unsafe {
            libbpf_rs::libbpf_sys::bpf_map_update_elem(
                self.targeted_pids_fd,
                &pid as *const i32 as *const std::ffi::c_void,
                &targeted as *const u8 as *const std::ffi::c_void,
                0, // BPF_ANY
            ) == 0
        }
    }

    /// Write PyPidData to the pystacks_pid_config BPF map.
    pub fn update_pid_config(&self, pid: i32, data: &PyPidData) {
        unsafe {
            libbpf_rs::libbpf_sys::bpf_map_update_elem(
                self.pid_config_fd,
                &pid as *const i32 as *const std::ffi::c_void,
                data as *const PyPidData as *const std::ffi::c_void,
                0,
            );
        }
    }

    /// Set BSS configuration fields for pystacks.
    /// Uses the generated pystacks skeleton BSS type for correct field offsets.
    pub fn configure_bss(&self) {
        // Build the pystacks BSS struct with our desired configuration
        // SAFETY: bss is repr(C) and all-zeros is a valid state
        let mut bss: skel::types::bss = unsafe { std::mem::zeroed() };
        // pid_target_helpers_prog_cfg.has_targeted_pids = true
        bss.pid_target_helpers_prog_cfg
            .has_targeted_pids
            .write(true);
        // pystacks_prog_cfg settings
        bss.pystacks_prog_cfg.enable_py_src_lines.write(true);
        bss.pystacks_prog_cfg.stack_max_len = 127;

        // Write specific fields to the BSS map.
        // The BSS map key is always 0 (single-element array map).
        // We need to read the current BSS, patch our fields, and write it back
        // to avoid clobbering the main systing BSS fields.
        //
        // The pystacks BSS fields are at the END of the combined BSS section
        // (since pystacks.bpf.o is linked after systing_system_tmp.bpf.o).
        // We find the pystacks BSS offset by looking at the total BSS size
        // minus the pystacks BSS size.
        let pystacks_bss_size = std::mem::size_of::<skel::types::bss>();
        if self.bss_size < pystacks_bss_size {
            eprintln!(
                "[pystacks] BSS map too small ({} < {}), cannot configure",
                self.bss_size, pystacks_bss_size
            );
            return;
        }
        let pystacks_bss_offset = self.bss_size - pystacks_bss_size;

        // Read current BSS
        let key: u32 = 0;
        let mut full_bss = vec![0u8; self.bss_size];
        let ret = unsafe {
            libbpf_rs::libbpf_sys::bpf_map_lookup_elem(
                self.bss_fd,
                &key as *const u32 as *const std::ffi::c_void,
                full_bss.as_mut_ptr() as *mut std::ffi::c_void,
            )
        };
        if ret != 0 {
            eprintln!("[pystacks] Failed to read BSS map");
            return;
        }

        // Patch pystacks BSS fields
        let bss_bytes =
            unsafe { std::slice::from_raw_parts(&bss as *const _ as *const u8, pystacks_bss_size) };
        full_bss[pystacks_bss_offset..].copy_from_slice(bss_bytes);

        // Write back
        let ret = unsafe {
            libbpf_rs::libbpf_sys::bpf_map_update_elem(
                self.bss_fd,
                &key as *const u32 as *const std::ffi::c_void,
                full_bss.as_ptr() as *const std::ffi::c_void,
                0,
            )
        };
        if ret != 0 {
            eprintln!("[pystacks] Failed to write BSS map");
        }
    }
}

fn get_map_fd(bpf_object: &Object, name: &str) -> Option<i32> {
    match bpf_object.maps().find(|m| m.name() == name) {
        Some(map) => Some(map.as_fd().as_raw_fd()),
        None => {
            eprintln!("[pystacks] BPF map '{}' not found", name);
            None
        }
    }
}

fn find_bss_map(bpf_object: &Object) -> Option<(i32, usize)> {
    for map in bpf_object.maps() {
        let name = map.name().to_string_lossy();
        if name.ends_with(".bss") || name == ".bss" || name == "bss" {
            let fd = map.as_fd().as_raw_fd();
            let size = map.value_size() as usize;
            return Some((fd, size));
        }
    }
    eprintln!("[pystacks] BSS map not found");
    None
}
