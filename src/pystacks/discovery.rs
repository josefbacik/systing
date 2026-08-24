/// Python process discovery.
///
/// Replaces PyProcessDiscovery.cpp: detects Python processes, parses ELF
/// binaries for version info and _PyRuntime symbol, computes runtime addresses.
use super::offsets;
use super::process::{self, MemoryMapping};
use super::types::{BpfLibBinaryId, PyPidData, BPF_LIB_DEFAULT_FIELD_OFFSET};
use object::read::{ReadCache, ReadRef};
use object::{Object, ObjectSymbol};
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::Path;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Instant;

/// ELF-derived facts about a Python runtime binary. These depend only on the
/// file contents, never on the process mapping it, so they are cached by
/// (st_dev, st_ino) — a node running N forked workers of the same interpreter
/// would otherwise read and symbol-scan the same multi-hundred-MB binary N
/// times, which can take seconds per process.
#[derive(Debug)]
struct ElfPyInfo {
    py_runtime_addr: usize,
    version: (i32, i32, i32),
    is_dynamic: bool,
}

/// Per-binary ELF parse results keyed by (st_dev, st_ino, st_size). `None`
/// records a binary that is not a Python runtime — rejections cost a full
/// ELF parse too, so they're worth remembering. I/O failures are never
/// cached: a transient read error (ESTALE, a /proc/pid/root path vanishing
/// when the process exits mid-check) must not blacklist an interpreter for
/// the rest of the session.
type ElfCache = HashMap<(u64, u64, u64), Option<Arc<ElfPyInfo>>>;

static ELF_CACHE: LazyLock<Mutex<ElfCache>> = LazyLock::new(Default::default);

/// Parse the ELF at `file_path` for Python runtime facts, going through the
/// (st_dev, st_ino, st_size) cache. Returns `None` when the file is
/// unreadable or is not a Python runtime.
fn elf_py_info(file_path: &str) -> Option<Arc<ElfPyInfo>> {
    // Open first and stat through the handle so the cache key describes the
    // file we actually read. The inode is pinned while any process maps the
    // binary, but a cache entry can outlive every mapper; st_size in the key
    // guards against a freed (dev, ino) being reused by a different file
    // later in the session.
    //
    // Known limit: the version fallback in detect_python_version keys off
    // the basename, so hardlinks to one inode under different names share
    // whichever result was cached first.
    let file = fs::File::open(file_path).ok()?;
    let meta = file.metadata().ok()?;
    let key = (meta.dev(), meta.ino(), meta.len());
    if let Some(cached) = ELF_CACHE.lock().unwrap().get(&key) {
        return cached.clone();
    }
    // Prove the file is readable before parsing: an I/O failure here
    // (EISDIR, ESTALE, a /proc/pid/root path vanishing) returns without
    // caching, so a transient error never blacklists an interpreter.
    if !file_readable(&file) {
        return None;
    }
    // Parse outside the lock; two threads racing on the same binary produce
    // identical results, so last-write-wins is fine.
    let parsed = parse_elf_py_info(file_path, &file);
    // A rejection is cached only if the file is still readable: an I/O
    // error mid-parse (the file vanished under us) is indistinguishable
    // from "not a runtime" inside the parser, and must not be remembered.
    if parsed.is_none() && !file_readable(&file) {
        return None;
    }
    ELF_CACHE.lock().unwrap().insert(key, parsed.clone());
    parsed
}

/// Whether the ELF identification header can be read: false on any I/O
/// error (EISDIR, ESTALE, a vanished /proc path).
fn file_readable(file: &fs::File) -> bool {
    let mut header = [0u8; 64];
    file.read_exact_at(&mut header, 0).is_ok()
}

/// Rejections costing at least this long are logged: a large non-Python
/// embedder pays the same symbol scans as an accept, and the log line makes
/// the negative-cache benefit attributable.
const SLOW_REJECT_SECS: f64 = 0.5;

/// Parse the runtime facts out of an open ELF file.
///
/// The file is read on demand through `object`'s `ReadCache` rather than
/// slurped into memory: the check needs the headers, the symbol tables and
/// the few bytes behind `_PySys_ImplCacheTag`, which for a libpython is a
/// few MB out of tens, and for a rejected binary only the tables. Discovery
/// runs once per process per run (the per-binary cache is process-local),
/// so on a page-cache-starved host every byte it touches is a cold read
/// that competes with the traced workload's own page faults.
fn parse_elf_py_info(file_path: &str, file: &fs::File) -> Option<Arc<ElfPyInfo>> {
    let start = Instant::now();
    let reader = ReadCache::new(file);
    let result = object::File::parse(&reader).ok().and_then(|elf| {
        let py_runtime_addr = find_symbol_address(&elf, "_PyRuntime")?;
        let version = detect_python_version(&elf, file_path)?;
        Some(Arc::new(ElfPyInfo {
            py_runtime_addr,
            version,
            is_dynamic: elf.kind() == object::ObjectKind::Dynamic,
        }))
    });
    let elapsed = start.elapsed().as_secs_f64();
    if result.is_some() {
        eprintln!("[pystacks] Parsed Python runtime ELF {file_path} in {elapsed:.2}s");
    } else if elapsed >= SLOW_REJECT_SECS {
        eprintln!("[pystacks] Rejected non-Python ELF {file_path} in {elapsed:.2}s");
    }
    result
}

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
    let start = Instant::now();
    let mut results = HashMap::new();

    for &pid in pids {
        if let Some(info) = check_python_process(pid) {
            results.insert(pid, info);
        }
    }

    if !results.is_empty() {
        eprintln!(
            "[pystacks] Discovered {} Python processes out of {} examined in {:.2}s",
            results.len(),
            pids.len(),
            start.elapsed().as_secs_f64()
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

    // Strategy: the exe, then any libpython shared object (runtime_candidates).
    let exe_path = process::read_exe_path(pid)?;
    let exe_str = exe_path.to_string_lossy();

    // Cheap gate: try_python_module() opens and ELF-parses candidate
    // binaries. This is called for every traced exec, so short-circuit when
    // neither the exe path nor any mapped module mentions python. Embedders
    // like uwsgi/gunicorn are still detected via their libpython mapping.
    let exe_lower = exe_str.to_lowercase();
    let looks_like_python = exe_lower.contains("python")
        || maps
            .iter()
            .any(|m| !m.name.is_empty() && m.name.to_lowercase().contains("python"));
    if !looks_like_python {
        return None;
    }

    for candidate in runtime_candidates(&exe_str, &maps) {
        let is_exe = candidate == exe_str;
        if let Some(info) = try_python_module(pid, &candidate, &maps, is_exe) {
            return Some(info);
        }
    }

    None
}

/// The objects worth parsing for a CPython runtime, in the order to try
/// them: the executable first (static and `--enable-shared` launcher builds
/// alike), then each distinct `libpython*` shared object in mapping order.
///
/// Nothing else is a candidate. A CPython runtime lives in the executable or
/// in a libpython shared object; `site-packages/*.so`, `lib/python3.X/...`
/// and every other object whose path merely contains "python" never carries
/// `_PyRuntime`. Parsing them anyway was how discovery read gigabytes per
/// run on ML images: later-`dlopen`ed extension modules (libtpu, jaxlib,
/// torch) map below libpython, so they were read in full — cold, on every
/// run — before the runtime was reached.
fn runtime_candidates(exe: &str, maps: &[MemoryMapping]) -> Vec<String> {
    let mut candidates = vec![exe.to_string()];
    for mapping in maps {
        // Only the first mapping of each module; later mappings carry a
        // non-zero file offset.
        if mapping.name.is_empty() || mapping.offset != 0 {
            continue;
        }
        let is_libpython = Path::new(&mapping.name)
            .file_name()
            .and_then(|f| f.to_str())
            .is_some_and(|f| f.to_lowercase().starts_with("libpython"));
        if is_libpython && !candidates.contains(&mapping.name) {
            candidates.push(mapping.name.clone());
        }
    }
    candidates
}

/// Try to identify a module as a Python runtime.
fn try_python_module(
    pid: i32,
    module_path: &str,
    maps: &[MemoryMapping],
    is_exe: bool,
) -> Option<PyProcessInfo> {
    // ELF facts come from the per-binary cache — forked workers of the same
    // interpreter share one parse instead of re-reading the binary per PID.
    let file_path = resolve_proc_path(pid, module_path);
    let elf_info = elf_py_info(&file_path)?;

    let is_pie = elf_info.is_dynamic && is_exe;
    let is_shared = elf_info.is_dynamic && !is_exe;

    let py_runtime_addr = elf_info.py_runtime_addr;
    let (major, minor, micro) = elf_info.version;

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
fn find_symbol_address<'data, R: ReadRef<'data>>(
    elf: &object::File<'data, R>,
    name: &str,
) -> Option<usize> {
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
/// Tries _PySys_ImplCacheTag first, then falls back to filename pattern
/// (the resolved on-disk path has the same basename as the mapped module,
/// so the pattern match is unaffected by /proc/pid/root resolution).
fn detect_python_version<'data, R: ReadRef<'data>>(
    elf: &object::File<'data, R>,
    module_path: &str,
) -> Option<(i32, i32, i32)> {
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
///
/// Reads only the bytes it needs through `data_range` — the 8-byte pointer
/// at the symbol and up to `TAG_MAX_LEN` bytes of the string it points at
/// (or the string itself, for a non-PIE executable) — never a whole
/// section: on a lazily-read file a `.rodata`/`.data` section is MBs.
fn read_impl_cache_tag<'data, R: ReadRef<'data>>(elf: &object::File<'data, R>) -> Option<String> {
    use object::ObjectSection;

    /// "cpython-313" is 11 bytes; the tag never approaches this.
    const TAG_MAX_LEN: u64 = 32;

    // Find the symbol
    let sym = elf
        .symbols()
        .chain(elf.dynamic_symbols())
        .find(|s| s.name() == Ok("_PySys_ImplCacheTag"))?;

    let addr = sym.address();
    if addr == 0 {
        return None;
    }

    // Up to `TAG_MAX_LEN` bytes at a virtual address, clamped to the
    // section that holds it.
    let bytes_at = |va: u64| -> Option<&'data [u8]> {
        elf.sections().find_map(|section| {
            let (s_addr, s_size) = (section.address(), section.size());
            if va < s_addr || va >= s_addr + s_size {
                return None;
            }
            let len = TAG_MAX_LEN.min(s_addr + s_size - va);
            section.data_range(va, len).ok().flatten()
        })
    };

    let at_symbol = bytes_at(addr)?;

    // The symbol is normally a `const char *`: read the pointer and follow
    // it (unrelocated link-time address, which is what the section
    // addresses are too).
    if at_symbol.len() >= 8 {
        let ptr_val = u64::from_le_bytes(at_symbol[..8].try_into().ok()?);
        if let Some(target) = bytes_at(ptr_val) {
            let s = read_cstring(target);
            if !s.is_empty() && s.starts_with("cpython") {
                return Some(s);
            }
        }
    }

    // Maybe it's directly a string
    let s = read_cstring(at_symbol);
    if !s.is_empty() && s.starts_with("cpython") {
        return Some(s);
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
        .rfind(|m| m.name == module_path && m.offset == 0)
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
    fn test_elf_py_info_caches_negative_results() {
        // Our own test binary is a valid ELF with no _PyRuntime symbol: it
        // must be rejected, and the rejection must be cached by (dev, ino)
        // so re-checking (e.g. N workers of one non-Python embedder) skips
        // the ELF re-parse.
        let exe = std::env::current_exe().unwrap();
        let exe_str = exe.to_string_lossy();
        assert!(elf_py_info(&exe_str).is_none());

        let meta = fs::metadata(&*exe_str).unwrap();
        let cached = ELF_CACHE
            .lock()
            .unwrap()
            .get(&(meta.dev(), meta.ino(), meta.len()))
            .cloned();
        assert!(matches!(cached, Some(None)), "negative result not cached");

        // Second lookup serves from cache (same answer).
        assert!(elf_py_info(&exe_str).is_none());
    }

    #[test]
    fn test_elf_py_info_unreadable_path() {
        assert!(elf_py_info("/nonexistent/definitely-not-a-file").is_none());
    }

    fn mapping(start: usize, offset: u64, name: &str) -> MemoryMapping {
        MemoryMapping {
            start,
            end: start + 0x1000,
            perms: "r--p".to_string(),
            offset,
            dev_major: 8,
            dev_minor: 1,
            inode: 1,
            name: name.to_string(),
        }
    }

    #[test]
    fn test_runtime_candidates_exe_then_libpython_only() {
        // An ML image as /proc/pid/maps lists it: extension modules dlopen'ed
        // after start-up sit BELOW libpython, every one of them under a path
        // containing "python". None of them may be a candidate — they were
        // the gigabytes of cold reads per run — while the exe and each
        // distinct libpython are, exe first, then in mapping order.
        let exe = "/opt/venv/bin/python3.13";
        let maps = vec![
            mapping(
                0x7f0000000000,
                0,
                "/opt/venv/lib/python3.13/site-packages/libtpu/libtpu.so",
            ),
            mapping(
                0x7f0100000000,
                0,
                "/opt/venv/lib/python3.13/site-packages/jaxlib/xla_extension.so",
            ),
            mapping(
                0x7f0200000000,
                0,
                "/opt/venv/lib/python3.13/site-packages/torch/lib/libtorch_python.so",
            ),
            mapping(0x7f0300000000, 0, "/usr/lib/x86_64-linux-gnu/libc.so.6"),
            // A stale linker reservation and the real mapping of one libpython.
            mapping(0x7f0400000000, 0, "/opt/python/lib/libpython3.13.so.1.0"),
            mapping(0x7f0500000000, 0, "/opt/python/lib/libpython3.13.so.1.0"),
            mapping(
                0x7f0500100000,
                0x100000,
                "/opt/python/lib/libpython3.13.so.1.0",
            ),
            mapping(
                0x7f0600000000,
                0,
                "/opt/venv/lib/python3.13/lib-dynload/math.cpython-313-x86_64-linux-gnu.so",
            ),
            mapping(0x7f0700000000, 0, exe),
        ];
        assert_eq!(
            runtime_candidates(exe, &maps),
            vec![
                exe.to_string(),
                "/opt/python/lib/libpython3.13.so.1.0".to_string()
            ]
        );
    }

    #[test]
    fn test_runtime_candidates_embedder_without_python_exe() {
        // uwsgi/gunicorn-style embedder: the exe is not python, the runtime
        // is the mapped libpython. Basename match is case-insensitive and
        // accepts debug/versioned spellings.
        let exe = "/usr/bin/uwsgi";
        let maps = vec![
            mapping(0x7f0000000000, 0, "/usr/lib/libpython3.11d.so.1.0"),
            mapping(0x7f0100000000, 0, exe),
        ];
        assert_eq!(
            runtime_candidates(exe, &maps),
            vec![
                exe.to_string(),
                "/usr/lib/libpython3.11d.so.1.0".to_string()
            ]
        );
        // No libpython anywhere: only the exe is examined.
        let maps = vec![mapping(0x7f0100000000, 0, exe)];
        assert_eq!(runtime_candidates(exe, &maps), vec![exe.to_string()]);
    }

    #[test]
    fn test_elf_py_info_real_interpreters() {
        // Real CPython builds on the host: a pyenv `--enable-shared` build has
        // a launcher exe without _PyRuntime and the runtime in libpython;
        // both must parse through the lazy reader with the right verdict and
        // the version read from _PySys_ImplCacheTag. Skipped (with a note)
        // where no pyenv interpreter is installed.
        let root = std::env::var("PYENV_ROOT")
            .unwrap_or_else(|_| format!("{}/.pyenv", std::env::var("HOME").unwrap_or_default()));
        let Ok(versions) = fs::read_dir(format!("{root}/versions")) else {
            eprintln!("no pyenv at {root}: skipping real-interpreter check");
            return;
        };
        let mut checked = 0;
        for entry in versions.flatten() {
            let dir = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            let mut parts = name.split('.');
            let (Some(major), Some(minor)) = (
                parts.next().and_then(|s| s.parse::<i32>().ok()),
                parts.next().and_then(|s| s.parse::<i32>().ok()),
            ) else {
                continue;
            };
            let lib = dir.join(format!("lib/libpython{major}.{minor}.so.1.0"));
            if !lib.exists() {
                continue;
            }
            let info = elf_py_info(&lib.to_string_lossy())
                .unwrap_or_else(|| panic!("{} not recognized as a runtime", lib.display()));
            assert_eq!(
                (info.version.0, info.version.1),
                (major, minor),
                "{}",
                lib.display()
            );
            assert!(
                info.is_dynamic,
                "{} should be a shared object",
                lib.display()
            );
            assert_ne!(info.py_runtime_addr, 0);
            // The exe of a shared build is usually a launcher linked against
            // libpython (no _PyRuntime of its own); a build that also links
            // the runtime statically is legal, so this is reported, not
            // asserted. Either way the lazy reader must classify it.
            let exe = dir.join(format!("bin/python{major}.{minor}"));
            if exe.exists() {
                let exe_is_runtime = elf_py_info(&exe.to_string_lossy()).is_some();
                eprintln!(
                    "{}: exe {} a runtime",
                    exe.display(),
                    if exe_is_runtime { "is" } else { "is not" }
                );
            }
            checked += 1;
        }
        eprintln!("real-interpreter check: {checked} shared builds verified");
    }

    /// Bytes this THREAD has requested through read(2) so far (`rchar` in
    /// /proc/thread-self/io — counted whether or not the page cache served
    /// them, so it measures what discovery asks for; per-thread so the
    /// other tests running in this process do not pollute the figure).
    fn rchar() -> u64 {
        fs::read_to_string("/proc/thread-self/io")
            .unwrap()
            .lines()
            .find_map(|l| l.strip_prefix("rchar: ")?.trim().parse().ok())
            .unwrap()
    }

    #[test]
    fn test_discovery_read_volume_real_python() {
        // Discover a live interpreter that has loaded a spread of extension
        // modules (every one of them under a "python"-containing path) and
        // measure what the check reads, against what the previous scan
        // order would have read: every python-pathed object below libpython
        // in full, plus libpython itself in full. Skipped where no pyenv
        // interpreter is installed.
        let root = std::env::var("PYENV_ROOT")
            .unwrap_or_else(|_| format!("{}/.pyenv", std::env::var("HOME").unwrap_or_default()));
        let Some(python) = fs::read_dir(format!("{root}/versions")).ok().and_then(|d| {
            d.flatten().find_map(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                let mut parts = name.split('.');
                let major = parts.next()?.parse::<i32>().ok()?;
                let minor = parts.next()?.parse::<i32>().ok()?;
                let exe = e.path().join(format!("bin/python{major}.{minor}"));
                exe.exists().then_some(exe)
            })
        }) else {
            eprintln!("no pyenv at {root}: skipping read-volume check");
            return;
        };
        let mut child = std::process::Command::new(&python)
            .args([
                "-c",
                "import ssl, sqlite3, ctypes, decimal, hashlib, zlib, bz2, lzma, json, socket, select, struct, time\n\
                 print('ready', flush=True)\n\
                 time.sleep(120)",
            ])
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn python");
        let pid = child.id() as i32;
        {
            use std::io::BufRead;
            let mut line = String::new();
            std::io::BufReader::new(child.stdout.take().unwrap())
                .read_line(&mut line)
                .unwrap();
            assert_eq!(line.trim(), "ready");
        }

        let maps = process::parse_proc_maps(pid);
        let exe = process::read_exe_path(pid)
            .unwrap()
            .to_string_lossy()
            .to_string();
        // What the previous order read: the exe, then every offset-0
        // mapping whose path contains "python", in full, up to and
        // including the first libpython.
        let mut previous_bytes = fs::metadata(&exe).map(|m| m.len()).unwrap_or(0);
        let mut previous_files = 1;
        let mut seen = std::collections::HashSet::new();
        for m in &maps {
            if m.offset != 0 || m.name.is_empty() || m.name == exe || !seen.insert(&m.name) {
                continue;
            }
            if m.name.to_lowercase().contains("python") {
                previous_bytes += fs::metadata(&m.name).map(|m| m.len()).unwrap_or(0);
                previous_files += 1;
                if Path::new(&m.name)
                    .file_name()
                    .is_some_and(|f| f.to_string_lossy().starts_with("libpython"))
                {
                    break;
                }
            }
        }

        // Run alone (`cargo test test_discovery_read_volume_real_python`)
        // for a cold-cache number: in the full suite the sibling test above
        // may already have cached this libpython, which only lowers the
        // measured bytes.
        let before = rchar();
        let info = check_python_process(pid);
        let read_bytes = rchar() - before;
        let _ = child.kill();
        let _ = child.wait();

        let info = info.expect("live pyenv interpreter not discovered");
        assert_eq!(info.pid, pid);
        assert_eq!(info.version_major, 3);
        eprintln!(
            "discovery read {read_bytes} bytes; the previous scan order would have read \
             {previous_bytes} bytes across {previous_files} files"
        );
        assert!(
            read_bytes * 4 < previous_bytes,
            "lazy discovery read {read_bytes} bytes vs {previous_bytes} for the full-file scan"
        );
    }

    #[test]
    fn test_elf_py_info_io_failure_not_cached() {
        // Opening a directory succeeds but reading it fails (EISDIR) — a
        // stand-in for transient I/O failures like ESTALE or a /proc path
        // vanishing mid-read. Those must not be cached as negatives, or one
        // transient error would blacklist the inode for the whole session.
        let dir = tempfile::tempdir().unwrap();
        let dir_str = dir.path().to_string_lossy();
        assert!(elf_py_info(&dir_str).is_none());

        let meta = fs::metadata(dir.path()).unwrap();
        assert!(
            !ELF_CACHE
                .lock()
                .unwrap()
                .contains_key(&(meta.dev(), meta.ino(), meta.len())),
            "I/O failure must not be cached"
        );
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
