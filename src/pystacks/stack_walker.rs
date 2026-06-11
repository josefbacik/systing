use crate::systing_core::types::{pystacks_message, stack_event};
use libbpf_rs::Object;
use std::hash::{Hash, Hasher};

use {
    crate::pystacks::bpf_maps::PystacksMaps, crate::pystacks::discovery,
    crate::pystacks::symbols::SymbolResolver, crate::pystacks::types::PystacksSymbolRecord,
    crate::pystacks::types::StackWalkerFrame, std::fmt,
};

#[derive(Debug, Clone)]
pub struct PyAddr {
    pub addr: StackWalkerFrame,
}

impl PartialEq for PyAddr {
    fn eq(&self, other: &Self) -> bool {
        self.addr.symbol_id == other.addr.symbol_id && self.addr.inst_idx == other.addr.inst_idx
    }
}
impl Eq for PyAddr {}

impl Hash for PyAddr {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.addr.symbol_id.hash(state);
        self.addr.inst_idx.hash(state);
    }
}

impl From<&crate::systing_core::types::stack_walker_frame> for StackWalkerFrame {
    fn from(frame: &crate::systing_core::types::stack_walker_frame) -> Self {
        StackWalkerFrame {
            symbol_id: frame.symbol_id,
            inst_idx: frame.inst_idx,
            pad_: 0,
        }
    }
}

impl fmt::Display for crate::systing_core::types::stack_walker_frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "StackWalkerFrame {{ symbol_id: {} inst_idx: {} }}",
            self.symbol_id, self.inst_idx
        )
    }
}

impl fmt::Display for StackWalkerFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "StackWalkerFrame {{ symbol_id: {} inst_idx: {} }}",
            self.symbol_id, self.inst_idx
        )
    }
}

/// Maximum number of sample events/frames to log in debug mode.
const DEBUG_SAMPLE_LOG_LIMIT: u64 = 10;

pub struct StackWalkerRun {
    resolver: Option<SymbolResolver>,
    maps: Option<PystacksMaps>,
    // Debug mode flag (atomic for thread safety with Sync impl)
    debug: std::sync::atomic::AtomicBool,
    // Counters for debug statistics (atomic for thread safety with Sync impl)
    events_with_pystack: std::sync::atomic::AtomicU64,
    events_without_pystack: std::sync::atomic::AtomicU64,
    symbols_loaded_count: std::sync::atomic::AtomicU64,
    frames_symbolized: std::sync::atomic::AtomicU64,
    frames_unknown: std::sync::atomic::AtomicU64,
    /// Failed inserts into the BPF gate map (warned once, see
    /// `ingest_symbol_record`).
    gate_insert_failures: std::sync::atomic::AtomicU64,
}

impl StackWalkerRun {
    fn new() -> Self {
        use std::sync::atomic::AtomicBool;
        use std::sync::atomic::AtomicU64;

        StackWalkerRun {
            resolver: None,
            maps: None,
            debug: AtomicBool::new(false),
            events_with_pystack: AtomicU64::new(0),
            events_without_pystack: AtomicU64::new(0),
            symbols_loaded_count: AtomicU64::new(0),
            frames_symbolized: AtomicU64::new(0),
            frames_unknown: AtomicU64::new(0),
            gate_insert_failures: AtomicU64::new(0),
        }
    }

    fn init(&mut self, bpf_object: &Object, pid_opts: &[i32], debug: bool) {
        use std::sync::atomic::Ordering;

        self.debug.store(debug, Ordering::Relaxed);

        if debug {
            eprintln!(
                "[pystacks debug] StackWalkerRun::init called with {} PIDs",
                pid_opts.len()
            );
        }

        if self.initialized() {
            if debug {
                eprintln!("[pystacks debug] StackWalkerRun already initialized, skipping");
            }
            return;
        }

        // Get BPF map FDs (do this first so add_pid works even with no initial PIDs)
        let maps = match PystacksMaps::new(bpf_object) {
            Some(m) => m,
            None => {
                eprintln!("[pystacks] Failed to get BPF map FDs");
                return;
            }
        };

        // Set BSS configuration (has_targeted_pids, enable_py_src_lines, etc.)
        maps.configure_bss();

        // Discover Python processes
        let process_info = discovery::discover_python_processes(pid_opts);

        if process_info.is_empty() && debug {
            eprintln!(
                "[pystacks debug] No Python processes found initially (will discover via exec)"
            );
        }

        // Populate BPF maps
        let mut attached_count = 0;
        for (pid, info) in &process_info {
            if maps.add_targeted_pid(*pid) {
                attached_count += 1;
            }
            maps.update_pid_config(*pid, &info.pid_data);
        }

        if debug {
            eprintln!(
                "[pystacks debug] Attached {} Python processes to BPF maps",
                attached_count
            );
        }

        // Create symbol resolver
        self.resolver = Some(SymbolResolver::new(&process_info));

        self.maps = Some(maps);

        if debug {
            eprintln!("[pystacks debug] pystacks init SUCCESS - Rust implementation initialized");
        }
    }

    fn initialized(&self) -> bool {
        self.resolver.is_some()
    }

    /// Returns true if debug mode is enabled.
    fn is_debug(&self) -> bool {
        self.debug.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn print_debug_stats(&self) {
        use std::sync::atomic::Ordering;

        if self.is_debug() {
            eprintln!(
                "[pystacks debug] stats: with_pystack={} without_pystack={} \
                 symbol_loads={} symbolized={} unknown={} initialized={}",
                self.events_with_pystack.load(Ordering::Relaxed),
                self.events_without_pystack.load(Ordering::Relaxed),
                self.symbols_loaded_count.load(Ordering::Relaxed),
                self.frames_symbolized.load(Ordering::Relaxed),
                self.frames_unknown.load(Ordering::Relaxed),
                self.initialized()
            );
            let gate_failures = self.gate_insert_failures.load(Ordering::Relaxed);
            if gate_failures > 0 {
                eprintln!("[pystacks debug] gate map insert failures: {gate_failures}");
            }
        }
    }

    fn symbolize_function(&self, frame: &PyAddr) -> String {
        match &self.resolver {
            Some(resolver) => resolver.symbolize_function(&frame.addr),
            None => "<unknown python>".to_string(),
        }
    }

    fn symbolize_filename_line(&self, frame: &PyAddr) -> (String, Option<usize>) {
        match &self.resolver {
            Some(resolver) => resolver.symbolize_filename_line(&frame.addr),
            None => ("unknown".to_string(), None),
        }
    }

    /// Ingest a symbol record emitted by BPF through the pysym ringbuf.
    ///
    /// Resolves and caches the symbol, then marks its ID as interned in the
    /// BPF gate map so BPF stops re-emitting it. The gate update happens
    /// here, from process context — BPF must never insert into the gate map
    /// from its probes (IRQs-off hash-map updates can wedge the CPU on
    /// hypervisors that drop PV spinlock kicks; see pystacks.bpf.c).
    pub fn ingest_symbol_record(&self, record: &PystacksSymbolRecord) {
        use std::sync::atomic::Ordering;

        let Some(resolver) = &self.resolver else {
            return;
        };

        if resolver.ingest_record(record) {
            if let Some(maps) = &self.maps {
                if !maps.mark_symbol_interned(record.symbol_id) {
                    // Likely the gate map is full. Symbolization stays
                    // correct (the userspace cache above is authoritative),
                    // but BPF will keep re-emitting this symbol at the
                    // rate-limited cadence for the rest of the trace.
                    let count = self.gate_insert_failures.fetch_add(1, Ordering::Relaxed) + 1;
                    if count == 1 {
                        eprintln!(
                            "[pystacks] Warning: failed to mark symbol {:#x} as interned \
                             (gate map full?); BPF will keep re-emitting un-interned symbols",
                            record.symbol_id
                        );
                    }
                }
            }

            if self.is_debug() {
                let count = self.symbols_loaded_count.fetch_add(1, Ordering::Relaxed) + 1;
                if count <= DEBUG_SAMPLE_LOG_LIMIT {
                    eprintln!(
                        "[pystacks debug] Interned symbol #{} (id {:#x}, {} total)",
                        count,
                        record.symbol_id,
                        resolver.symbol_count()
                    );
                }
            }
        }
    }

    pub fn add_pid(&self, pid: i32) -> bool {
        if !self.initialized() {
            return false;
        }

        if self.is_debug() {
            eprintln!("[pystacks debug] Dynamically adding PID {}", pid);
        }

        // Check if this is a Python process
        if let Some(info) = discovery::check_python_process(pid) {
            if self.is_debug() {
                eprintln!(
                    "[pystacks debug] Found Python {}.{} in PID {}",
                    info.version_major, info.version_minor, pid
                );
            }

            if let Some(resolver) = &self.resolver {
                resolver.add_pid_version(pid, info.version_major, info.version_minor);
            }
            if let Some(maps) = &self.maps {
                maps.add_targeted_pid(pid);
                maps.update_pid_config(pid, &info.pid_data);
            }
            true
        } else {
            false
        }
    }

    pub fn get_pystack_from_event(&self, event: &stack_event) -> Vec<PyAddr> {
        self.get_pystack_from_buffer(&event.py_msg_buffer, event.task.tgidpid >> 32)
    }

    pub fn get_pystack_from_buffer(&self, buf: &pystacks_message, pid: u64) -> Vec<PyAddr> {
        use std::sync::atomic::Ordering;

        let stack_len = (buf.stack_len as usize).min(buf.buffer.len());

        if self.is_debug() {
            if stack_len > 0 {
                let count = self.events_with_pystack.fetch_add(1, Ordering::Relaxed) + 1;
                if count <= DEBUG_SAMPLE_LOG_LIMIT {
                    eprintln!(
                        "[pystacks debug] Event #{} with Python stack: PID={} stack_len={}",
                        count, pid, stack_len
                    );
                }
            } else {
                self.events_without_pystack.fetch_add(1, Ordering::Relaxed);
            }
        }

        Vec::from(&buf.buffer[..stack_len])
            .iter()
            .map(|frame| PyAddr { addr: frame.into() })
            .collect()
    }

    pub fn init_pystacks(&mut self, pids: &[u32], bpf_object: &Object, debug: bool) {
        if debug {
            eprintln!(
                "[pystacks debug] init_pystacks called with {} PIDs",
                pids.len()
            );
        }

        if !pids.is_empty() {
            let pid_opts: Vec<i32> = pids.iter().map(|&pid| pid as i32).collect();
            self.init(bpf_object, &pid_opts, debug);
        } else if debug {
            eprintln!("[pystacks debug] No PIDs provided, skipping pystacks initialization");
        }
    }

    pub fn get_python_frame_names(&self, py_stack: &[PyAddr]) -> Vec<String> {
        use std::sync::atomic::Ordering;

        if !self.initialized() {
            if self.is_debug() && !py_stack.is_empty() {
                eprintln!(
                    "[pystacks debug] get_python_frame_names: not initialized, returning empty for {} frames",
                    py_stack.len()
                );
            }
            return Vec::new();
        }

        if py_stack.is_empty() {
            return Vec::new();
        }

        let debug = self.is_debug();

        py_stack
            .iter()
            .map(|frame| {
                let func_name = self.symbolize_function(frame);
                let (filename, line_number) = self.symbolize_filename_line(frame);

                if debug {
                    if func_name == "<unknown python>" {
                        self.frames_unknown.fetch_add(1, Ordering::Relaxed);
                    } else {
                        let count = self.frames_symbolized.fetch_add(1, Ordering::Relaxed) + 1;
                        if count <= DEBUG_SAMPLE_LOG_LIMIT {
                            let base_filename = std::path::Path::new(&filename)
                                .file_name()
                                .and_then(|f| f.to_str())
                                .unwrap_or(&filename);
                            eprintln!(
                                "[pystacks debug] Symbolized frame #{}: symbol_id={} -> {} [{}]",
                                count, frame.addr.symbol_id, func_name, base_filename
                            );
                        }
                    }
                }

                let base_filename = std::path::Path::new(&filename)
                    .file_name()
                    .and_then(|f| f.to_str())
                    .unwrap_or(&filename);

                match line_number {
                    Some(line) => format!("{func_name} (python) [{base_filename}:{line}]"),
                    None => format!("{func_name} (python) [{base_filename}]"),
                }
            })
            .collect()
    }
}

impl Default for StackWalkerRun {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for StackWalkerRun {
    fn drop(&mut self) {
        self.print_debug_stats();
    }
}

unsafe impl Send for StackWalkerRun {}
unsafe impl Sync for StackWalkerRun {}
