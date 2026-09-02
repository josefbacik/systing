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
/// ELF parse too, so they're worth remembering. A file that fails a
/// readability probe (see `elf_py_info`) is not cached: a transient read
/// error (ESTALE, a /proc/pid/root path vanishing when the process exits
/// mid-check) must not blacklist an interpreter for the rest of the session.
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
    // The probe reads the first 64 bytes, so it stands in for "the file is
    // gone or unreadable", not for an error in the middle of a file that
    // is otherwise fine — that narrower case would be cached as a
    // rejection.
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
        let version = detect_python_version(&elf, &reader, file_path)?;
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
    reader: R,
    module_path: &str,
) -> Option<(i32, i32, i32)> {
    // Try to find version from _PySys_ImplCacheTag symbol value
    if let Some(version_str) = read_impl_cache_tag(elf, reader) {
        if let Some(ver) = parse_cpython_version(&version_str) {
            return Some(ver);
        }
    }

    // Fallback: try to extract version from filename (e.g., python3.10, libpython3.11.so)
    parse_version_from_path(module_path)
}

/// Try to read the _PySys_ImplCacheTag string from ELF.
///
/// Reads only the bytes it needs, straight from the file through `reader`:
/// the 8-byte pointer at the symbol and up to `TAG_MAX_LEN` bytes of the
/// string it points at (or the string itself, for a non-PIE executable).
/// The virtual address is translated to a file offset through the section
/// that holds it rather than read with `Section::data_range`, which pulls
/// the whole section through the reader first — on a lazily-read libpython
/// that is the MBs of `.rodata`/`.data` this path exists to avoid.
fn read_impl_cache_tag<'data, R: ReadRef<'data>>(
    elf: &object::File<'data, R>,
    reader: R,
) -> Option<String> {
    use object::{ObjectSection, SectionFlags};

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

    // Up to `TAG_MAX_LEN` bytes at a virtual address, read from the file
    // range of the allocated section that holds it. Only allocated sections
    // with an address are candidates (non-allocated ones carry no virtual
    // address, and `.bss`-style sections have no file bytes), so the lookup
    // does not depend on section order. The range arithmetic is checked: a
    // malformed header whose address plus size wraps is skipped rather than
    // matched, in the release build as in the test profile.
    let alloc_flag = u64::from(object::elf::SHF_ALLOC);
    let bytes_at = |va: u64| -> Option<&'data [u8]> {
        elf.sections().find_map(|section| {
            let allocated = match section.flags() {
                SectionFlags::Elf { sh_flags } => sh_flags & alloc_flag != 0,
                _ => false,
            };
            let (s_addr, s_size) = (section.address(), section.size());
            let s_end = s_addr.checked_add(s_size)?;
            if !allocated || s_addr == 0 || va < s_addr || va >= s_end {
                return None;
            }
            let (file_off, file_size) = section.file_range()?;
            let within = va - s_addr;
            if within >= file_size {
                return None;
            }
            let len = TAG_MAX_LEN.min(file_size - within);
            let at = file_off.checked_add(within)?;
            reader.read_bytes_at(at, len).ok()
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

    /// A real CPython runtime on this host: the file that carries
    /// `_PyRuntime` (libpython for a shared build, the executable for a
    /// static one) and the version it should report. Sources: every pyenv
    /// `--enable-shared` build under `$PYENV_ROOT/versions`, and the system
    /// interpreter at `/usr/bin/python3` (asked where its runtime lives).
    struct RealRuntime {
        path: std::path::PathBuf,
        exe: std::path::PathBuf,
        major: i32,
        minor: i32,
        shared: bool,
    }

    fn real_runtimes() -> Vec<RealRuntime> {
        let mut out: Vec<RealRuntime> = Vec::new();
        let root = std::env::var("PYENV_ROOT")
            .unwrap_or_else(|_| format!("{}/.pyenv", std::env::var("HOME").unwrap_or_default()));
        if let Ok(versions) = fs::read_dir(format!("{root}/versions")) {
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
                let exe = dir.join(format!("bin/python{major}.{minor}"));
                if lib.exists() && exe.exists() {
                    out.push(RealRuntime {
                        path: lib,
                        exe,
                        major,
                        minor,
                        shared: true,
                    });
                }
            }
        }
        // The distribution's interpreter, typically a static (non-shared)
        // build whose executable IS the runtime — and the one a CI runner
        // has when it has nothing else.
        let probe = "import sys, sysconfig\n\
                     print(sys.version_info[0], sys.version_info[1], \
                     int(bool(sysconfig.get_config_var('Py_ENABLE_SHARED'))), \
                     sysconfig.get_config_var('LIBDIR') or '', \
                     sysconfig.get_config_var('INSTSONAME') or '', \
                     sys.executable, sep='\\n')";
        if let Ok(output) = std::process::Command::new("/usr/bin/python3")
            .args(["-c", probe])
            .output()
        {
            let text = String::from_utf8_lossy(&output.stdout);
            let lines: Vec<&str> = text.lines().collect();
            if output.status.success() && lines.len() == 6 {
                if let (Ok(major), Ok(minor)) = (lines[0].parse::<i32>(), lines[1].parse::<i32>()) {
                    let exe = fs::canonicalize(lines[5]).unwrap_or_else(|_| lines[5].into());
                    // `Py_ENABLE_SHARED` says how the interpreter was
                    // configured, not what is installed: Debian's python3
                    // reports 1 while /usr/bin/python3.X is statically
                    // linked and the libpython package may be absent. When
                    // the shared library is not there, the executable is
                    // the runtime (the static exe is a good one, as the
                    // objprobe of every distro build showed), so use it
                    // rather than skip the check — a runner image without
                    // the libpython package must not turn the real-
                    // interpreter check vacuous.
                    let lib = Path::new(lines[3]).join(lines[4]);
                    let (path, shared) = if lines[2] == "1" && lib.exists() {
                        (lib, true)
                    } else {
                        (exe.clone(), false)
                    };
                    if path.exists() && !out.iter().any(|r| r.path == path) {
                        out.push(RealRuntime {
                            path,
                            exe,
                            major,
                            minor,
                            shared,
                        });
                    }
                }
            }
        }
        out
    }

    /// Whether a skip is allowed: locally a host without CPython just skips
    /// the real-interpreter checks with a note; in CI (`CI` set, as GitHub
    /// Actions does) a skip would make the green run prove nothing about the
    /// lazy reader on a real runtime, so it fails instead.
    fn skip_or_fail_without_runtime(what: &str) {
        assert!(
            std::env::var_os("CI").is_none(),
            "no CPython runtime on this host (pyenv shared builds or /usr/bin/python3): \
             the {what} check must not pass vacuously in CI"
        );
        eprintln!("no CPython runtime on this host: skipping the {what} check");
    }

    #[test]
    fn test_elf_py_info_real_interpreters() {
        // Real CPython builds on the host, through the lazy reader: the
        // runtime file (libpython of a shared build, the exe of a static
        // one) must parse with the right verdict and version. Where the
        // build carries `_PySys_ImplCacheTag` the tag read is checked
        // directly against the expected string — `(major, minor)` alone
        // would also be satisfied by the filename fallback in
        // `detect_python_version`, so it cannot tell the two apart.
        let runtimes = real_runtimes();
        if runtimes.is_empty() {
            skip_or_fail_without_runtime("real-interpreter");
            return;
        }
        let mut tag_checked = 0;
        for rt in &runtimes {
            let path = rt.path.to_string_lossy().to_string();
            let info = elf_py_info(&path)
                .unwrap_or_else(|| panic!("{} not recognized as a runtime", rt.path.display()));
            assert_eq!(
                (info.version.0, info.version.1),
                (rt.major, rt.minor),
                "{}",
                rt.path.display()
            );
            // `is_dynamic` is the ELF kind (ET_DYN), which a shared build's
            // libpython always is; a static build's executable may be ET_DYN
            // too (a PIE exe) or ET_EXEC, and either is a fine runtime, so
            // for those it is reported rather than pinned to "not shared".
            if rt.shared {
                assert!(
                    info.is_dynamic,
                    "{}: the shared build's runtime library should be a shared object",
                    rt.path.display()
                );
            } else {
                eprintln!(
                    "{}: static build, the exe is {}",
                    rt.path.display(),
                    if info.is_dynamic {
                        "position-independent (ET_DYN)"
                    } else {
                        "ET_EXEC"
                    }
                );
            }
            assert_ne!(info.py_runtime_addr, 0);

            let file = fs::File::open(&rt.path).unwrap();
            let reader = ReadCache::new(&file);
            let elf = object::File::parse(&reader).unwrap();
            let has_tag = elf
                .symbols()
                .chain(elf.dynamic_symbols())
                .any(|s| s.name() == Ok("_PySys_ImplCacheTag") && s.address() != 0);
            if has_tag {
                assert_eq!(
                    read_impl_cache_tag(&elf, &reader).as_deref(),
                    Some(format!("cpython-{}{}", rt.major, rt.minor).as_str()),
                    "{}: the cache tag read",
                    rt.path.display()
                );
                tag_checked += 1;
            }

            // The exe of a shared build is usually a launcher linked against
            // libpython (no _PyRuntime of its own); a build that also links
            // the runtime statically is legal, so this is reported, not
            // asserted. Either way the lazy reader must classify it.
            if rt.shared {
                let exe_is_runtime = elf_py_info(&rt.exe.to_string_lossy()).is_some();
                eprintln!(
                    "{}: exe {} a runtime",
                    rt.exe.display(),
                    if exe_is_runtime { "is" } else { "is not" }
                );
            }
        }
        eprintln!(
            "real-interpreter check: {} runtimes verified, {tag_checked} of them through the cache tag",
            runtimes.len()
        );
    }

    /// A stand-in CPython runtime built on the spot: the two symbols
    /// discovery keys on and nothing else, with a cache tag no real build
    /// has and a filename that carries no version, so the version the lazy
    /// reader reports can only have come through the tag read. The
    /// real-interpreter check above only exercises that path where a build
    /// still ships `_PySys_ImplCacheTag` (pyenv 3.13.14 does not; a distro
    /// libpython is stripped of it), so on a runner it proved nothing about
    /// the most intricate hunk of the reader. Two shapes, as the two shapes
    /// of real runtimes: a shared object whose symbol IS the string (the
    /// direct-string branch), and a non-PIE executable whose symbol is a
    /// pointer resolved at link time (the follow-the-pointer branch, without
    /// depending on how the linker fills a dynamic relocation's slot).
    /// Needs a C compiler; in CI its absence fails the test rather than
    /// skipping it, for the same reason as `skip_or_fail_without_runtime`.
    #[test]
    fn test_read_impl_cache_tag_on_a_built_fixture() {
        use std::process::Command;

        const TAG: &str = "cpython-399";
        // `CC` may carry a driver prefix ("sccache clang", "ccache cc"), as
        // the cc crate accepts it: the first word is the program.
        let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
        let mut cc_words = cc.split_whitespace();
        let cc_prog = cc_words.next().unwrap_or("cc").to_string();
        let cc_args: Vec<String> = cc_words.map(String::from).collect();
        let compile = |flags: &[&str], out: &Path, src: &Path| -> bool {
            Command::new(&cc_prog)
                .args(&cc_args)
                .args(flags)
                .arg("-o")
                .arg(out)
                .arg(src)
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        };
        if Command::new(&cc_prog)
            .args(&cc_args)
            .arg("--version")
            .output()
            .is_err()
        {
            assert!(
                std::env::var_os("CI").is_none(),
                "no C compiler ({cc}) on this host: the built-fixture tag check must not \
                 pass vacuously in CI"
            );
            eprintln!("no C compiler ({cc}) on this host: skipping the built-fixture tag check");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let src_string = dir.path().join("string.c");
        let src_pointer = dir.path().join("pointer.c");
        // The tag as the symbol's own bytes.
        fs::write(
            &src_string,
            format!(
                "const char _PySys_ImplCacheTag[] = \"{TAG}\";\n\
                 char _PyRuntime[64];\n\
                 int systing_fixture_keep(void) {{ return _PyRuntime[0]; }}\n"
            ),
        )
        .unwrap();
        // The tag behind a pointer, the way CPython declares it.
        fs::write(
            &src_pointer,
            format!(
                "static const char tag[] = \"{TAG}\";\n\
                 const char *_PySys_ImplCacheTag = tag;\n\
                 char _PyRuntime[64];\n\
                 int main(void) {{ return _PyRuntime[0] + (int)_PySys_ImplCacheTag[0]; }}\n"
            ),
        )
        .unwrap();
        // Filenames without a version: the filename fallback cannot supply
        // one, so a (3, 99) can only have been read from the tag.
        let so = dir.path().join("fixture-runtime.so");
        let exe = dir.path().join("fixture-runtime");
        let built_so = compile(&["-shared", "-fPIC"], &so, &src_string);
        assert!(built_so, "{cc} could not build the shared-object fixture");
        let built_exe = compile(&["-no-pie"], &exe, &src_pointer);

        let mut checked = 0;
        for (path, expect_dynamic, built) in [(&so, true, true), (&exe, false, built_exe)] {
            if !built {
                // A toolchain without -no-pie (some clang setups) loses the
                // pointer leg locally; in CI the runner's gcc has it.
                assert!(
                    std::env::var_os("CI").is_none(),
                    "{cc} could not build the non-PIE executable fixture"
                );
                eprintln!("{cc} could not build the non-PIE executable fixture: skipping that leg");
                continue;
            }
            let file = fs::File::open(path).unwrap();
            let reader = ReadCache::new(&file);
            let elf = object::File::parse(&reader).unwrap();
            assert_eq!(
                read_impl_cache_tag(&elf, &reader).as_deref(),
                Some(TAG),
                "{}: the cache tag read",
                path.display()
            );
            let info = elf_py_info(&path.to_string_lossy())
                .unwrap_or_else(|| panic!("{} not recognized as a runtime", path.display()));
            assert_eq!(
                (info.version.0, info.version.1),
                (3, 99),
                "{}: the version must come from the tag, not the filename",
                path.display()
            );
            assert_eq!(info.is_dynamic, expect_dynamic, "{}", path.display());
            assert_ne!(info.py_runtime_addr, 0, "{}", path.display());
            checked += 1;
        }
        assert!(checked >= 1);
        eprintln!("built-fixture check: {checked} fixture(s) read their cache tag");
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
        // in full, plus libpython itself in full (or the exe in full, for a
        // static build). A pyenv shared build is preferred; the system
        // interpreter serves where there is none.
        let runtimes = real_runtimes();
        let Some(python) = runtimes
            .iter()
            .find(|r| r.shared)
            .or(runtimes.first())
            .map(|r| r.exe.clone())
        else {
            skip_or_fail_without_runtime("read-volume");
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
