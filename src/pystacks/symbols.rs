/// Symbol resolution for Python stack frames.
///
/// Replaces the core symbol lookup logic from pystacks.cpp.
/// Reads symbols from BPF maps, constructs function names, and resolves
/// source file/line information using line tables.
use super::discovery::PyProcessInfo;
use super::linetable::PyLineTable;
use super::process;
use super::types::*;
use std::collections::HashMap;
use std::sync::RwLock;

/// A resolved Python symbol with optional line table.
struct PySymbol {
    funcname: String,
    filename: String,
    linetable: Option<PyLineTable>,
}

/// Manages symbol resolution from BPF maps.
pub struct SymbolResolver {
    symbols: RwLock<HashMap<SymbolIdT, PySymbol>>,
    /// Map of PID -> version info for line table construction.
    pid_versions: HashMap<i32, (i32, i32)>,
    /// FD for the pystacks_symbols BPF map.
    symbols_fd: i32,
    /// FD for the pystacks_linetables BPF map.
    linetables_fd: i32,
}

impl SymbolResolver {
    pub fn new(
        symbols_fd: i32,
        linetables_fd: i32,
        process_info: &HashMap<i32, PyProcessInfo>,
    ) -> Self {
        let pid_versions = process_info
            .iter()
            .map(|(&pid, info)| (pid, (info.version_major, info.version_minor)))
            .collect();

        Self {
            symbols: RwLock::new(HashMap::new()),
            pid_versions,
            symbols_fd,
            linetables_fd,
        }
    }

    /// Load symbols from BPF maps.
    /// Iterates the pystacks_symbols BPF hash map and caches resolved symbols.
    pub fn load_symbols(&self) {
        let mut new_symbols = 0usize;
        let mut missing_linetables = 0usize;

        // Iterate over all elements in the symbols BPF hash map.
        // bpf_map_get_next_key with NULL key returns the first key.
        let mut prev_key: Option<PystacksSymbol> = None;
        let mut next_key = PystacksSymbol::default();

        loop {
            let prev_ptr = match &prev_key {
                Some(k) => k as *const PystacksSymbol as *const std::ffi::c_void,
                None => std::ptr::null(),
            };

            let ret = unsafe {
                libbpf_rs::libbpf_sys::bpf_map_get_next_key(
                    self.symbols_fd,
                    prev_ptr,
                    &mut next_key as *mut PystacksSymbol as *mut std::ffi::c_void,
                )
            };

            if ret != 0 {
                break; // No more keys
            }

            // Look up the symbol_id value for this key
            let mut id: SymbolIdT = 0;
            let ret = unsafe {
                libbpf_rs::libbpf_sys::bpf_map_lookup_elem(
                    self.symbols_fd,
                    &next_key as *const PystacksSymbol as *const std::ffi::c_void,
                    &mut id as *mut SymbolIdT as *mut std::ffi::c_void,
                )
            };

            if ret != 0 {
                prev_key = Some(next_key.clone());
                continue;
            }

            // Skip if already cached
            {
                let symbols = self.symbols.read().unwrap();
                if symbols.contains_key(&id) {
                    prev_key = Some(next_key.clone());
                    continue;
                }
            }

            // Handle page fault recovery for qualname
            let mut sym = next_key.clone();
            if sym.qualname.fault_addr != 0 && sym.fault_pid != 0 {
                let mut buf = [0u8; BPF_LIB_PYSTACKS_QUAL_NAME_LEN];
                if process::read_process_memory(sym.fault_pid, sym.qualname.fault_addr, &mut buf)
                    .is_ok()
                {
                    sym.qualname.value = buf;
                } else {
                    prev_key = Some(next_key.clone());
                    continue; // Can't recover qualname
                }
            }

            // Handle page fault recovery for filename
            if sym.filename.fault_addr != 0 && sym.fault_pid != 0 {
                let mut buf = [0u8; BPF_LIB_PYSTACKS_FILE_NAME_LEN];
                let _ =
                    process::read_process_memory(sym.fault_pid, sym.filename.fault_addr, &mut buf)
                        .map(|_| {
                            sym.filename.value = buf;
                        });
                // Continue even if filename recovery fails - qualname is more important
            }

            // Build the symbol
            let funcname = get_symbol_name(&sym);
            let filename = cstring_from_bytes(&sym.filename.value);

            // Try to load line table
            let linetable = self.load_line_table(id);
            if linetable.is_none() {
                missing_linetables += 1;
            }

            let py_symbol = PySymbol {
                funcname,
                filename,
                linetable,
            };

            {
                let mut symbols = self.symbols.write().unwrap();
                symbols.insert(id, py_symbol);
            }
            new_symbols += 1;

            prev_key = Some(next_key.clone());
        }

        if new_symbols > 0 {
            let total = self.symbols.read().unwrap().len();
            eprintln!(
                "[pystacks] Added {} Python symbols ({} total, {} missing linetables)",
                new_symbols, total, missing_linetables
            );
        }
    }

    /// Load a line table from BPF map for a given symbol ID.
    fn load_line_table(&self, id: SymbolIdT) -> Option<PyLineTable> {
        let mut lt = PystacksLineTable::default();

        let ret = unsafe {
            libbpf_rs::libbpf_sys::bpf_map_lookup_elem(
                self.linetables_fd,
                &id as *const SymbolIdT as *const std::ffi::c_void,
                &mut lt as *mut PystacksLineTable as *mut std::ffi::c_void,
            )
        };

        if ret != 0 || lt.addr == 0 || lt.length == 0 || lt.first_line == 0 || lt.pid == 0 {
            return None;
        }

        let (major, minor) = self.pid_versions.get(&lt.pid).copied().unwrap_or((3, 11));

        PyLineTable::from_process(
            lt.pid,
            lt.first_line as i32,
            lt.addr,
            lt.length as usize,
            major,
            minor,
        )
    }

    /// Resolve a frame's function name.
    /// Returns the function name or "<unknown python>".
    pub fn symbolize_function(&self, frame: &StackWalkerFrame) -> String {
        let symbols = self.symbols.read().unwrap();
        match symbols.get(&frame.symbol_id) {
            Some(sym) => sym.funcname.clone(),
            None => "<unknown python>".to_string(),
        }
    }

    /// Resolve a frame's source filename and line number.
    /// Returns (filename, Option<line>).
    pub fn symbolize_filename_line(&self, frame: &StackWalkerFrame) -> (String, Option<usize>) {
        let symbols = self.symbols.read().unwrap();
        match symbols.get(&frame.symbol_id) {
            Some(sym) => {
                let filename = if sym.filename.is_empty() {
                    "unknown".to_string()
                } else {
                    sym.filename.clone()
                };

                let line = match &sym.linetable {
                    Some(lt) => {
                        let l = lt.get_line_for_inst_index(frame.inst_idx);
                        if l == 0 {
                            None
                        } else {
                            Some(l as usize)
                        }
                    }
                    None => None,
                };

                (filename, line)
            }
            None => ("unknown".to_string(), None),
        }
    }
}

/// Extract a C string from a byte array (up to first null byte).
fn cstring_from_bytes(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

/// Construct a full symbol name from a pystacks_symbol.
///
/// The qualname field is split into two partitions:
/// - First 128 bytes: class name (or full qualname if it fits)
/// - Next 96 bytes: function name (only if class+function were stored separately)
///
/// If the first partition contains the full qualname (including any dots),
/// the second partition is empty and we use the first as-is.
fn get_symbol_name(sym: &PystacksSymbol) -> String {
    // Read qualname from first partition
    let qualname_full = cstring_from_bytes(&sym.qualname.value);

    let qualname = if qualname_full.len() <= BPF_LIB_PYSTACKS_CLASS_NAME_LEN {
        // Check if there's a function name in the second partition
        let func_start = BPF_LIB_PYSTACKS_CLASS_NAME_LEN;
        let func_name = if func_start < sym.qualname.value.len() {
            cstring_from_bytes(&sym.qualname.value[func_start..])
        } else {
            String::new()
        };

        if !func_name.is_empty() {
            if !qualname_full.is_empty() {
                format!("{}.{}", qualname_full, func_name)
            } else {
                func_name
            }
        } else {
            qualname_full
        }
    } else {
        qualname_full
    };

    // Extract module name from filename
    let filename = cstring_from_bytes(&sym.filename.value);
    let module_name = get_module_name_from_filename(&filename);

    if module_name.is_empty() {
        qualname
    } else {
        format!("{}:{}", module_name, qualname)
    }
}

/// Extract a module name from a file path.
/// Looks for known directory markers (site-packages, lib/python*, etc.)
/// and constructs a dotted module path from the remainder.
fn get_module_name_from_filename(path: &str) -> String {
    const KEYWORDS: &[&str] = &["site-packages/", "dist-packages/", "lib/python"];

    let mut max_boundary = None;
    let mut matched_keyword = "";

    // Find the keyword that appears furthest into the path
    for keyword in KEYWORDS {
        if let Some(pos) = path.rfind(keyword) {
            let boundary = pos + keyword.len();
            if max_boundary.is_none() || boundary > max_boundary.unwrap() {
                max_boundary = Some(boundary);
                matched_keyword = keyword;
            }
        }
    }

    let boundary = match max_boundary {
        None => return String::new(),
        Some(b) => {
            if !matched_keyword.ends_with('/') {
                // Find the next '/' after the keyword
                match path[b..].find('/') {
                    Some(slash_pos) => b + slash_pos + 1,
                    None => return String::new(),
                }
            } else {
                b
            }
        }
    };

    if boundary >= path.len() {
        return String::new();
    }

    let mut module_name = path[boundary..].to_string();

    // Remove .py extension
    if module_name.ends_with(".py") {
        module_name.truncate(module_name.len() - 3);
    }

    // Replace path separators with dots
    module_name = module_name.replace('/', ".");

    module_name
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cstring_from_bytes() {
        let mut buf = [0u8; 10];
        buf[..5].copy_from_slice(b"hello");
        assert_eq!(cstring_from_bytes(&buf), "hello");
    }

    #[test]
    fn test_cstring_from_bytes_all_null() {
        let buf = [0u8; 10];
        assert_eq!(cstring_from_bytes(&buf), "");
    }

    #[test]
    fn test_module_name_from_site_packages() {
        assert_eq!(
            get_module_name_from_filename("/usr/lib/python3.10/site-packages/flask/app.py"),
            "flask.app"
        );
    }

    #[test]
    fn test_module_name_from_lib_python() {
        assert_eq!(
            get_module_name_from_filename("/usr/lib/python3.10/collections/__init__.py"),
            "collections.__init__"
        );
    }

    #[test]
    fn test_module_name_no_match() {
        assert_eq!(get_module_name_from_filename("/some/random/path.py"), "");
    }

    #[test]
    fn test_get_symbol_name_simple() {
        let mut sym = PystacksSymbol::default();
        // Set qualname to "MyClass.my_func"
        let name = b"MyClass.my_func";
        sym.qualname.value[..name.len()].copy_from_slice(name);

        assert_eq!(get_symbol_name(&sym), "MyClass.my_func");
    }

    #[test]
    fn test_get_symbol_name_split() {
        let mut sym = PystacksSymbol::default();
        // Class in first partition
        let class_name = b"MyClass";
        sym.qualname.value[..class_name.len()].copy_from_slice(class_name);
        // Function in second partition (at offset 128)
        let func_name = b"my_method";
        sym.qualname.value[128..128 + func_name.len()].copy_from_slice(func_name);

        assert_eq!(get_symbol_name(&sym), "MyClass.my_method");
    }
}
