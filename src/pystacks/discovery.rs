/// Python process discovery.
///
/// Replaces PyProcessDiscovery.cpp: detects Python processes, parses ELF
/// binaries for version info and _PyRuntime symbol, computes runtime addresses.
use super::offsets;
use super::process::{self, MemoryMapping};
use super::types::{BpfLibBinaryId, PyPidData, BPF_LIB_DEFAULT_FIELD_OFFSET};
use object::{Object, ObjectSymbol};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Kernel MKDEV macro: (major << 20) | minor
fn kmkdev(major: u32, minor: u32) -> u64 {
    ((major as u64) << 20) | (minor as u64)
}

/// Information about a discovered Python process.
#[derive(Debug, Clone)]
pub struct PyProcessInfo {
    pub pid: i32,
    pub pid_data: PyPidData,
    pub binary_id: BpfLibBinaryId,
    pub version_major: i32,
    pub version_minor: i32,
    pub version_micro: i32,
}

/// Discover Python processes from a list of PIDs.
/// Returns a map of PID -> PyProcessInfo for all Python processes found.
pub fn discover_python_processes(pids: &[i32]) -> HashMap<i32, PyProcessInfo> {
    let mut results = HashMap::new();

    for &pid in pids {
        if let Some(info) = check_python_process(pid) {
            results.insert(pid, info);
        }
    }

    if !results.is_empty() {
        eprintln!(
            "[pystacks] Discovered {} Python processes out of {} examined",
            results.len(),
            pids.len()
        );
    }

    results
}

/// Check if a single PID is a Python process.
pub fn check_python_process(pid: i32) -> Option<PyProcessInfo> {
    let maps = process::parse_proc_maps(pid);
    if maps.is_empty() {
        return None;
    }

    // Strategy:
    // 1. Check if exe is a Python binary
    // 2. If not, scan maps for libpython*.so
    let exe_path = process::read_exe_path(pid)?;
    let exe_str = exe_path.to_string_lossy();

    // Check exe first
    let mut checked_paths = std::collections::HashSet::new();

    // Try the exe
    if let Some(info) = try_python_module(pid, &exe_str, &maps, true) {
        return Some(info);
    }
    checked_paths.insert(exe_str.to_string());

    // Scan maps for libpython or python shared libraries
    for mapping in &maps {
        if mapping.name.is_empty() || checked_paths.contains(&mapping.name) {
            continue;
        }
        if mapping.offset != 0 {
            continue; // Only check first mapping of each module
        }

        let name_lower = mapping.name.to_lowercase();
        if name_lower.contains("libpython") || name_lower.contains("python") {
            checked_paths.insert(mapping.name.clone());
            if let Some(info) = try_python_module(pid, &mapping.name, &maps, false) {
                return Some(info);
            }
        }
    }

    None
}

/// Try to identify a module as a Python runtime.
fn try_python_module(
    pid: i32,
    module_path: &str,
    maps: &[MemoryMapping],
    is_exe: bool,
) -> Option<PyProcessInfo> {
    // Read the ELF file
    let file_path = resolve_proc_path(pid, module_path);
    let data = fs::read(&file_path).ok()?;
    let elf = object::File::parse(&*data).ok()?;

    let is_pie = elf.kind() == object::ObjectKind::Dynamic && is_exe;
    let is_shared = elf.kind() == object::ObjectKind::Dynamic && !is_exe;

    // Find _PyRuntime symbol
    let py_runtime_addr = find_symbol_address(&elf, "_PyRuntime")?;

    // Try to determine Python version
    let version = detect_python_version(&elf, module_path);
    let (major, minor, micro) = version?;

    // Get offset config for this version
    let offsets = offsets::for_version(major, minor)?;

    // Find base load address from maps
    let base_addr = find_module_base_address(maps, module_path).unwrap_or(0);

    // Build binary ID — prefer the executable mapping for consistency with
    // base address computation, fall back to any mapping for this module.
    let binary_id = maps
        .iter()
        .find(|m| m.name == module_path && m.perms.contains('x'))
        .or_else(|| maps.iter().find(|m| m.name == module_path))
        .map(|m| BpfLibBinaryId {
            dev: kmkdev(m.dev_major, m.dev_minor),
            inode: m.inode,
        })
        .unwrap_or_default();

    // Compute PyPidData with runtime addresses
    let mut pid_data = PyPidData {
        offsets,
        ..Default::default()
    };
    pid_data.offsets.py_version_major = major;
    pid_data.offsets.py_version_minor = minor;
    pid_data.offsets.py_version_micro = micro;

    // Compute effective _PyRuntime address
    let effective_runtime_addr = if is_exe {
        if is_pie {
            base_addr + py_runtime_addr
        } else {
            py_runtime_addr
        }
    } else if is_shared {
        base_addr + py_runtime_addr
    } else {
        py_runtime_addr
    };

    pid_data.py_runtime_addr = effective_runtime_addr;

    // Compute derived addresses from _PyRuntime for Python >= 3.7
    if major == 3 && minor >= 7 {
        if pid_data.offsets.tls_key_offset != BPF_LIB_DEFAULT_FIELD_OFFSET {
            pid_data.tls_key_addr = effective_runtime_addr + pid_data.offsets.tls_key_offset;
        }
        if pid_data.offsets.t_current_state_offset != BPF_LIB_DEFAULT_FIELD_OFFSET {
            pid_data.current_state_addr =
                effective_runtime_addr + pid_data.offsets.t_current_state_offset;
        }
        if pid_data.offsets.py_gil_offset != BPF_LIB_DEFAULT_FIELD_OFFSET {
            pid_data.gil_locked_addr = effective_runtime_addr + pid_data.offsets.py_gil_offset;
        }
        if pid_data.offsets.py_gil_last_holder != BPF_LIB_DEFAULT_FIELD_OFFSET {
            pid_data.gil_last_holder_addr =
                effective_runtime_addr + pid_data.offsets.py_gil_last_holder;
        }
    }

    pid_data.use_tls = pid_data.tls_key_addr > 0;

    // Python 3.13+: GIL moved from _PyRuntimeState to PyInterpreterState
    if major == 3
        && minor >= 13
        && pid_data.offsets.py_runtime_state_interpreters_head != BPF_LIB_DEFAULT_FIELD_OFFSET
        && pid_data.offsets.py_interpreter_state_gil_locked != BPF_LIB_DEFAULT_FIELD_OFFSET
    {
        let interp_head_addr =
            effective_runtime_addr + pid_data.offsets.py_runtime_state_interpreters_head;
        let mut interp_addr_buf = [0u8; 8];
        if process::read_process_memory(pid, interp_head_addr, &mut interp_addr_buf).is_ok() {
            let interp_addr = usize::from_ne_bytes(interp_addr_buf);
            if interp_addr != 0 {
                pid_data.gil_locked_addr =
                    interp_addr + pid_data.offsets.py_interpreter_state_gil_locked;
                pid_data.gil_last_holder_addr =
                    interp_addr + pid_data.offsets.py_interpreter_state_gil_last_holder;
            }
        }
    }

    eprintln!(
        "[pystacks] Process {} uses Python {}.{}.{} - runtime at {:#x}",
        pid, major, minor, micro, effective_runtime_addr
    );

    Some(PyProcessInfo {
        pid,
        pid_data,
        binary_id,
        version_major: major,
        version_minor: minor,
        version_micro: micro,
    })
}

/// Resolve a path through /proc/pid/root for containerized processes.
fn resolve_proc_path(pid: i32, path: &str) -> String {
    let proc_root = format!("/proc/{pid}/root{path}");
    if Path::new(&proc_root).exists() {
        proc_root
    } else {
        path.to_string()
    }
}

/// Find a symbol's address in an ELF file.
fn find_symbol_address(elf: &object::File, name: &str) -> Option<usize> {
    for sym in elf.symbols() {
        if sym.name() == Ok(name) && sym.address() != 0 {
            return Some(sym.address() as usize);
        }
    }
    // Try dynamic symbols
    for sym in elf.dynamic_symbols() {
        if sym.name() == Ok(name) && sym.address() != 0 {
            return Some(sym.address() as usize);
        }
    }
    None
}

/// Detect the Python version from an ELF file.
/// Tries _PySys_ImplCacheTag first, then falls back to filename pattern.
fn detect_python_version(elf: &object::File, module_path: &str) -> Option<(i32, i32, i32)> {
    // Try to find version from _PySys_ImplCacheTag symbol value
    if let Some(version_str) = read_impl_cache_tag(elf) {
        if let Some(ver) = parse_cpython_version(&version_str) {
            return Some(ver);
        }
    }

    // Fallback: try to extract version from filename (e.g., python3.10, libpython3.11.so)
    parse_version_from_path(module_path)
}

/// Try to read the _PySys_ImplCacheTag string from ELF.
fn read_impl_cache_tag(elf: &object::File) -> Option<String> {
    use object::ObjectSection;

    // Find the symbol
    let sym = elf
        .symbols()
        .chain(elf.dynamic_symbols())
        .find(|s| s.name() == Ok("_PySys_ImplCacheTag"))?;

    let addr = sym.address();
    if addr == 0 {
        return None;
    }

    // Read string value from the ELF section data
    // For non-PIE executables, the symbol points to a pointer to the string.
    // For shared libs, we need the relocation-adjusted value.
    // Simplified: try to read from .rodata section at the symbol offset.
    for section in elf.sections() {
        let section_addr = section.address();
        let section_size = section.size();
        if addr >= section_addr && addr < section_addr + section_size {
            let section_data = section.data().ok()?;
            let offset = (addr - section_addr) as usize;

            // The symbol might point to a pointer (for dynamically linked Python)
            // or directly to the string. Try reading as a string first.
            if offset < section_data.len() {
                // Read pointer value at the offset
                if offset + 8 <= section_data.len() {
                    let ptr_bytes: [u8; 8] = section_data[offset..offset + 8].try_into().ok()?;
                    let ptr_val = u64::from_le_bytes(ptr_bytes);

                    // Check if ptr_val looks like a valid section offset
                    for sec2 in elf.sections() {
                        let s2_addr = sec2.address();
                        let s2_size = sec2.size();
                        if ptr_val >= s2_addr && ptr_val < s2_addr + s2_size {
                            let s2_data = sec2.data().ok()?;
                            let s2_offset = (ptr_val - s2_addr) as usize;
                            if s2_offset < s2_data.len() {
                                let s = read_cstring(&s2_data[s2_offset..]);
                                if !s.is_empty() && s.starts_with("cpython") {
                                    return Some(s);
                                }
                            }
                        }
                    }
                }

                // Maybe it's directly a string
                let s = read_cstring(&section_data[offset..]);
                if !s.is_empty() && s.starts_with("cpython") {
                    return Some(s);
                }
            }
        }
    }

    None
}

fn read_cstring(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).to_string()
}

/// Parse "cpython-3XX" style version strings.
fn parse_cpython_version(s: &str) -> Option<(i32, i32, i32)> {
    // Formats: "cpython-38", "cpython-310", "cpython-311", "cpython-312", "cpython-313"
    let s = s.strip_prefix("cpython-")?;
    if s.len() == 2 {
        // e.g., "38" -> 3.8
        let major = s[..1].parse().ok()?;
        let minor = s[1..].parse().ok()?;
        Some((major, minor, 0))
    } else if s.len() >= 3 {
        // e.g., "310" -> 3.10, "313" -> 3.13
        let major: i32 = s[..1].parse().ok()?;
        let minor: i32 = s[1..].parse().ok()?;
        Some((major, minor, 0))
    } else {
        None
    }
}

/// Extract Python version from a file path.
fn parse_version_from_path(path: &str) -> Option<(i32, i32, i32)> {
    let filename = Path::new(path).file_name()?.to_str()?;

    // Match patterns like "python3.10", "libpython3.11.so.1.0"
    // Find "pythonX.Y" pattern without regex
    let idx = filename.find("python")?;
    let after = &filename[idx + "python".len()..];
    let dot = after.find('.')?;
    let major: i32 = after[..dot].parse().ok()?;
    let rest = &after[dot + 1..];
    // Minor version ends at next non-digit
    let minor_end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    let minor: i32 = rest[..minor_end].parse().ok()?;
    Some((major, minor, 0))
}

/// Find the base load address for a module in process maps.
///
/// When a shared library is loaded, the dynamic linker may leave a stale
/// read-only mmap of the file at a lower address in addition to the final
/// LOAD segment mappings. If there are multiple mappings with offset == 0
/// for the same file, we can't simply pick the first one.
///
/// Instead, we compute the base from the executable (r-xp) mapping:
///   base = exec_mapping.start - exec_mapping.offset
/// This is reliable because there is exactly one executable mapping per
/// loaded module, and its file offset tells us where vaddr 0 would be.
fn find_module_base_address(maps: &[MemoryMapping], module_path: &str) -> Option<usize> {
    // Prefer computing base from the executable mapping
    if let Some(exec_map) = maps
        .iter()
        .find(|m| m.name == module_path && m.perms.contains('x'))
    {
        return exec_map.start.checked_sub(exec_map.offset as usize);
    }

    // Fallback: use the last offset=0 mapping (the dynamic linker creates
    // the active mapping after any stale reservations). This path should
    // rarely be hit — log a warning so it's visible in diagnostic output.
    let fallback = maps
        .iter()
        .filter(|m| m.name == module_path && m.offset == 0)
        .last()
        .map(|m| m.start);
    if fallback.is_some() {
        eprintln!(
            "[pystacks] Warning: no executable mapping for {}, using fallback base address",
            module_path
        );
    }
    fallback
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cpython_version() {
        assert_eq!(parse_cpython_version("cpython-38"), Some((3, 8, 0)));
        assert_eq!(parse_cpython_version("cpython-310"), Some((3, 10, 0)));
        assert_eq!(parse_cpython_version("cpython-313"), Some((3, 13, 0)));
        assert_eq!(parse_cpython_version("invalid"), None);
    }

    #[test]
    fn test_parse_version_from_path() {
        assert_eq!(
            parse_version_from_path("/usr/bin/python3.10"),
            Some((3, 10, 0))
        );
        assert_eq!(
            parse_version_from_path("/usr/lib/libpython3.11.so.1.0"),
            Some((3, 11, 0))
        );
        assert_eq!(parse_version_from_path("/usr/bin/ls"), None);
    }

    #[test]
    fn test_kmkdev() {
        assert_eq!(kmkdev(8, 1), (8 << 20) | 1);
    }

    #[test]
    fn test_find_module_base_address_single_mapping() {
        let maps = vec![
            MemoryMapping {
                start: 0x7f0000000000,
                end: 0x7f0000100000,
                perms: "r--p".to_string(),
                offset: 0,
                dev_major: 8,
                dev_minor: 1,
                inode: 12345,
                name: "/usr/lib/libpython3.13.so.1.0".to_string(),
            },
            MemoryMapping {
                start: 0x7f0000100000,
                end: 0x7f0000400000,
                perms: "r-xp".to_string(),
                offset: 0x100000,
                dev_major: 8,
                dev_minor: 1,
                inode: 12345,
                name: "/usr/lib/libpython3.13.so.1.0".to_string(),
            },
        ];
        assert_eq!(
            find_module_base_address(&maps, "/usr/lib/libpython3.13.so.1.0"),
            Some(0x7f0000000000)
        );
    }

    #[test]
    fn test_find_module_base_address_stale_mapping() {
        // Simulates the case where a stale mmap reservation exists at a lower
        // address, as seen when libpython is loaded alongside a Rust extension.
        let maps = vec![
            // Stale read-only mmap at a lower address (from dynamic linker reservation)
            MemoryMapping {
                start: 0x7cfa18000000,
                end: 0x7cfa1a000000,
                perms: "r--p".to_string(),
                offset: 0,
                dev_major: 8,
                dev_minor: 1,
                inode: 12345,
                name: "/usr/lib/libpython3.13.so.1.0".to_string(),
            },
            // Correct offset=0 mapping
            MemoryMapping {
                start: 0x7cfdaf421000,
                end: 0x7cfdaf4a0000,
                perms: "r--p".to_string(),
                offset: 0,
                dev_major: 8,
                dev_minor: 1,
                inode: 12345,
                name: "/usr/lib/libpython3.13.so.1.0".to_string(),
            },
            // Executable mapping
            MemoryMapping {
                start: 0x7cfdaf4a0000,
                end: 0x7cfdaf7f5000,
                perms: "r-xp".to_string(),
                offset: 0x7f000,
                dev_major: 8,
                dev_minor: 1,
                inode: 12345,
                name: "/usr/lib/libpython3.13.so.1.0".to_string(),
            },
            // Data mapping
            MemoryMapping {
                start: 0x7cfdaf9a2000,
                end: 0x7cfdafa23000,
                perms: "rw-p".to_string(),
                offset: 0x580000,
                dev_major: 8,
                dev_minor: 1,
                inode: 12345,
                name: "/usr/lib/libpython3.13.so.1.0".to_string(),
            },
        ];
        // Should compute base from exec mapping: 0x7cfdaf4a0000 - 0x7f000 = 0x7cfdaf421000
        assert_eq!(
            find_module_base_address(&maps, "/usr/lib/libpython3.13.so.1.0"),
            Some(0x7cfdaf421000)
        );
    }

    #[test]
    fn test_find_module_base_address_no_exec_mapping() {
        // Fallback: if no executable mapping exists, use the last offset=0 mapping
        let maps = vec![
            MemoryMapping {
                start: 0x7f0000000000,
                end: 0x7f0000100000,
                perms: "r--p".to_string(),
                offset: 0,
                dev_major: 8,
                dev_minor: 1,
                inode: 12345,
                name: "/usr/lib/libpython3.13.so.1.0".to_string(),
            },
            MemoryMapping {
                start: 0x7f0000200000,
                end: 0x7f0000300000,
                perms: "r--p".to_string(),
                offset: 0,
                dev_major: 8,
                dev_minor: 1,
                inode: 12345,
                name: "/usr/lib/libpython3.13.so.1.0".to_string(),
            },
        ];
        // Should use the last offset=0 mapping
        assert_eq!(
            find_module_base_address(&maps, "/usr/lib/libpython3.13.so.1.0"),
            Some(0x7f0000200000)
        );
    }

    #[test]
    fn test_find_module_base_address_no_match() {
        let maps = vec![MemoryMapping {
            start: 0x7f0000000000,
            end: 0x7f0000100000,
            perms: "r-xp".to_string(),
            offset: 0x1000,
            dev_major: 8,
            dev_minor: 1,
            inode: 12345,
            name: "/usr/lib/libpython3.13.so.1.0".to_string(),
        }];
        assert_eq!(find_module_base_address(&maps, "/nonexistent.so"), None);
    }
}
