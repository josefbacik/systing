/// Symbol resolution for Python stack frames.
///
/// Symbols arrive as `PystacksSymbolRecord`s through the pysym ringbuf: BPF
/// emits a record the first time a symbol's content hash misses the
/// `pystacks_symbols` gate map, and `ingest_record` resolves it here (page
/// fault recovery, line table read) and caches it by symbol ID. The caller
/// then inserts the ID into the gate map (from process context) so BPF stops
/// emitting that symbol. BPF never inserts into shared hash maps itself
/// because its probes run with IRQs off, where a contended map bucket lock
/// can permanently halt the vCPU on hypervisors that drop PV spinlock kicks.
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

/// Manages symbol resolution from BPF symbol records.
pub struct SymbolResolver {
    symbols: RwLock<HashMap<SymbolIdT, PySymbol>>,
    /// Map of PID -> version info for line table construction.
    pid_versions: RwLock<HashMap<i32, (i32, i32)>>,
}

impl SymbolResolver {
    pub fn new(process_info: &HashMap<i32, PyProcessInfo>) -> Self {
        let pid_versions = process_info
            .iter()
            .map(|(&pid, info)| (pid, (info.version_major, info.version_minor)))
            .collect();

        Self {
            symbols: RwLock::new(HashMap::new()),
            pid_versions: RwLock::new(pid_versions),
        }
    }

    pub fn add_pid_version(&self, pid: i32, major: i32, minor: i32) {
        self.pid_versions
            .write()
            .unwrap()
            .insert(pid, (major, minor));
    }

    /// Number of symbols currently cached.
    pub fn symbol_count(&self) -> usize {
        self.symbols.read().unwrap().len()
    }

    /// Ingest one symbol record emitted by BPF.
    ///
    /// Returns true if the symbol is cached after this call (newly resolved
    /// or already known); the caller should then mark the ID as interned in
    /// the BPF gate map. Returns false if resolution failed (e.g. the
    /// faulted qualname could not be read back); the ID is left out of the
    /// gate map so BPF re-emits it (rate-limited) and we retry — the page
    /// may be resident on a later attempt.
    pub fn ingest_record(&self, record: &PystacksSymbolRecord) -> bool {
        let id = record.symbol_id;
        if id == 0 {
            // 0 is reserved as "no symbol".
            return false;
        }

        if self.symbols.read().unwrap().contains_key(&id) {
            return true;
        }

        let mut sym = record.sym.clone();

        // Handle page fault recovery for qualname
        if sym.qualname.fault_addr != 0 && sym.fault_pid != 0 {
            let mut buf = [0u8; BPF_LIB_PYSTACKS_QUAL_NAME_LEN];
            if process::read_process_memory(sym.fault_pid, sym.qualname.fault_addr, &mut buf)
                .is_ok()
            {
                sym.qualname.value = buf;
            } else {
                return false; // Can't recover qualname yet; retry on re-emit
            }
        }

        // Handle page fault recovery for filename
        if sym.filename.fault_addr != 0 && sym.fault_pid != 0 {
            let mut buf = [0u8; BPF_LIB_PYSTACKS_FILE_NAME_LEN];
            let _ = process::read_process_memory(sym.fault_pid, sym.filename.fault_addr, &mut buf)
                .map(|_| {
                    sym.filename.value = buf;
                });
            // Continue even if filename recovery fails - qualname is more important
        }

        let funcname = get_symbol_name(&sym);
        let filename = cstring_from_bytes(&sym.filename.value);
        let linetable = self.load_line_table(&record.linetable);

        self.symbols.write().unwrap().insert(
            id,
            PySymbol {
                funcname,
                filename,
                linetable,
            },
        );
        true
    }

    /// Build a line table from the data carried in a symbol record.
    fn load_line_table(&self, lt: &PystacksLineTable) -> Option<PyLineTable> {
        if lt.addr == 0 || lt.length == 0 || lt.first_line == 0 || lt.pid == 0 {
            return None;
        }

        let (major, minor) = self
            .pid_versions
            .read()
            .unwrap()
            .get(&lt.pid)
            .copied()
            .unwrap_or((3, 11));

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

    #[test]
    fn test_ingest_record_caches_symbol() {
        let resolver = SymbolResolver::new(&HashMap::new());
        let mut record = PystacksSymbolRecord {
            symbol_id: 0xdeadbeefcafef00d,
            ..Default::default()
        };
        let name = b"my_func";
        record.sym.qualname.value[..name.len()].copy_from_slice(name);

        assert!(resolver.ingest_record(&record));
        assert_eq!(resolver.symbol_count(), 1);
        // Duplicate ingestion is a no-op but still reports cached.
        assert!(resolver.ingest_record(&record));
        assert_eq!(resolver.symbol_count(), 1);

        let frame = StackWalkerFrame {
            symbol_id: 0xdeadbeefcafef00d,
            inst_idx: -1,
            pad_: 0,
        };
        assert_eq!(resolver.symbolize_function(&frame), "my_func");
    }

    #[test]
    fn test_ingest_record_rejects_zero_id() {
        let resolver = SymbolResolver::new(&HashMap::new());
        let record = PystacksSymbolRecord::default();
        assert!(!resolver.ingest_record(&record));
        assert_eq!(resolver.symbol_count(), 0);
    }
}
