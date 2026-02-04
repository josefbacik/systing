use crate::stack_recorder::{LocalFrame, Stack};
use crate::systing_core::types::stack_event;
use libbpf_rs::Object;
use std::collections::HashMap;
#[cfg(feature = "pystacks")]
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
#[cfg(feature = "pystacks")]
use std::time::Instant;

#[cfg(feature = "pystacks")]
use {
    crate::pystacks::bpf_maps::PystacksMaps, crate::pystacks::discovery,
    crate::pystacks::symbols::SymbolResolver, crate::pystacks::types::StackWalkerFrame,
    crate::stack_recorder::add_frame, std::fmt,
};

#[derive(Debug, Clone)]
pub struct PyAddr {
    #[cfg(feature = "pystacks")]
    pub addr: StackWalkerFrame,
}

impl PartialEq for PyAddr {
    #[cfg(not(feature = "pystacks"))]
    fn eq(&self, _: &Self) -> bool {
        true
    }

    #[cfg(feature = "pystacks")]
    fn eq(&self, other: &Self) -> bool {
        self.addr.symbol_id == other.addr.symbol_id && self.addr.inst_idx == other.addr.inst_idx
    }
}
impl Eq for PyAddr {}

impl Hash for PyAddr {
    #[cfg(not(feature = "pystacks"))]
    fn hash<H: Hasher>(&self, _: &mut H) {}

    #[cfg(feature = "pystacks")]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.addr.symbol_id.hash(state);
        self.addr.inst_idx.hash(state);
    }
}

#[cfg(feature = "pystacks")]
impl From<&crate::systing_core::types::stack_walker_frame> for StackWalkerFrame {
    fn from(frame: &crate::systing_core::types::stack_walker_frame) -> Self {
        StackWalkerFrame {
            symbol_id: frame.symbol_id,
            inst_idx: frame.inst_idx,
        }
    }
}

#[cfg(feature = "pystacks")]
impl fmt::Display for crate::systing_core::types::stack_walker_frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "StackWalkerFrame {{ symbol_id: {} inst_idx: {} }}",
            self.symbol_id, self.inst_idx
        )
    }
}

#[cfg(feature = "pystacks")]
impl fmt::Display for StackWalkerFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "StackWalkerFrame {{ symbol_id: {} inst_idx: {} }}",
            self.symbol_id, self.inst_idx
        )
    }
}

//
// Implementation when pystacks feature is ENABLED
//
/// Maximum number of sample events/frames to log in debug mode.
#[cfg(feature = "pystacks")]
const DEBUG_SAMPLE_LOG_LIMIT: u64 = 10;

#[cfg(feature = "pystacks")]
pub struct StackWalkerRun {
    resolver: Option<SymbolResolver>,
    maps: Option<PystacksMaps>,
    // Symbol loading rate limiting
    last_symbol_load: std::cell::Cell<Option<Instant>>,
    symbol_load_interval: std::time::Duration,
    // Debug mode flag (atomic for thread safety with Sync impl)
    debug: std::sync::atomic::AtomicBool,
    // Counters for debug statistics (atomic for thread safety with Sync impl)
    events_with_pystack: std::sync::atomic::AtomicU64,
    events_without_pystack: std::sync::atomic::AtomicU64,
    symbols_loaded_count: std::sync::atomic::AtomicU64,
    frames_symbolized: std::sync::atomic::AtomicU64,
    frames_unknown: std::sync::atomic::AtomicU64,
}

#[cfg(feature = "pystacks")]
impl StackWalkerRun {
    fn new() -> Self {
        use std::sync::atomic::AtomicBool;
        use std::sync::atomic::AtomicU64;

        StackWalkerRun {
            resolver: None,
            maps: None,
            last_symbol_load: std::cell::Cell::new(None),
            // Load symbols at most once per 500ms (2 Hz) to catch dying processes
            // while minimizing overhead on long traces
            symbol_load_interval: std::time::Duration::from_millis(500),
            debug: AtomicBool::new(false),
            events_with_pystack: AtomicU64::new(0),
            events_without_pystack: AtomicU64::new(0),
            symbols_loaded_count: AtomicU64::new(0),
            frames_symbolized: AtomicU64::new(0),
            frames_unknown: AtomicU64::new(0),
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
        self.resolver = Some(SymbolResolver::new(
            maps.symbols_fd,
            maps.linetables_fd,
            &process_info,
        ));

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

    fn load_symbols(&self) {
        if let Some(resolver) = &self.resolver {
            resolver.load_symbols();
        }
    }

    pub fn add_pid(&self, pid: i32) {
        if !self.initialized() {
            return;
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

            if let Some(maps) = &self.maps {
                maps.add_targeted_pid(pid);
                maps.update_pid_config(pid, &info.pid_data);
            }
        }
    }

    pub fn pystacks_to_frames_mapping(
        &self,
        frame_map: &mut HashMap<u64, Vec<LocalFrame>>,
        global_func_manager: &Arc<crate::stack_recorder::GlobalFunctionManager>,
        id_counter: &Arc<AtomicUsize>,
        python_stack_markers: &mut Vec<u64>,
        stack: &[PyAddr],
    ) {
        if !self.initialized() {
            return;
        }

        for frame in stack {
            if frame_map.contains_key(&(frame.addr.symbol_id as u64)) {
                continue;
            }

            let func_name = self.symbolize_function(frame);
            let (filename, line_number) = self.symbolize_filename_line(frame);

            let base_filename = std::path::Path::new(&filename)
                .file_name()
                .and_then(|f| f.to_str())
                .unwrap_or(&filename);

            let formatted_name = match line_number {
                Some(line) => format!("{func_name} (python) [{base_filename}:{line}]"),
                None => format!("{func_name} (python) [{base_filename}]"),
            };

            add_frame(
                frame_map,
                global_func_manager,
                id_counter,
                frame.addr.symbol_id.into(),
                0,
                0,
                formatted_name,
            );

            if func_name == "<interpreter trampoline>" {
                python_stack_markers.push(frame.addr.symbol_id.into());
            }
        }
    }

    #[allow(clippy::ptr_arg)]
    pub fn user_stack_to_python_calls(
        &self,
        frame_map: &mut HashMap<u64, Vec<LocalFrame>>,
        global_func_manager: &Arc<crate::stack_recorder::GlobalFunctionManager>,
        python_calls: &mut Vec<u64>,
    ) {
        let all_python_iids: HashSet<u64> = global_func_manager
            .get_function_ids_matching("PyEval")
            .into_iter()
            .chain(global_func_manager.get_function_ids_matching("_PyEval_EvalFrame"))
            .collect();

        for (key, values) in frame_map {
            for value in values {
                if value.frame.function_name_id.is_some()
                    && all_python_iids.contains(&value.frame.function_name_id.unwrap())
                {
                    python_calls.push(*key);
                }
            }
        }
    }

    // Heuristic threshold for detecting stack truncation vs normal frame count mismatch
    const FRAME_MISMATCH_THRESHOLD: usize = 5;

    pub fn merge_pystacks(
        &self,
        stack: &Stack,
        python_calls: &[u64],
        python_stack_markers: &[u64],
    ) -> Vec<u64> {
        let mut merged_addrs = Vec::new();
        let mut user_stack_idx = 0;
        let mut pystack_idx = stack.py_stack.len();

        let py_call_count = stack
            .user_stack
            .iter()
            .filter(|&x| python_calls.contains(x))
            .count();
        let py_marker_count = if python_stack_markers.is_empty() {
            stack.py_stack.len()
        } else {
            stack
                .py_stack
                .iter()
                .filter(|&x| python_stack_markers.contains(&(x.addr.symbol_id as u64)))
                .count()
        };

        // Fallback for Python binaries without frame pointers
        if !stack.py_stack.is_empty() && py_call_count == 0 {
            merged_addrs.extend(
                stack
                    .py_stack
                    .iter()
                    .rev()
                    .map(|frame| frame.addr.symbol_id as u64),
            );
            merged_addrs.extend(stack.user_stack.iter().copied());
            return merged_addrs;
        }

        let mut skip_py_calls =
            if py_call_count > py_marker_count && py_call_count - py_marker_count > 1 {
                py_call_count - py_marker_count
            } else {
                0
            };

        let frame_mismatch = py_marker_count.saturating_sub(py_call_count);
        let mut skip_py_frame = if python_stack_markers.is_empty() {
            0
        } else if frame_mismatch > Self::FRAME_MISMATCH_THRESHOLD {
            frame_mismatch
        } else {
            0
        };

        if python_stack_markers.is_empty() {
            pystack_idx -= skip_py_frame;
        } else {
            while skip_py_frame > 0 {
                if python_stack_markers
                    .contains(&(stack.py_stack[pystack_idx - 1].addr.symbol_id as u64))
                {
                    skip_py_frame -= 1;
                }
            }
        }

        while user_stack_idx < stack.user_stack.len() {
            let user_addr = stack.user_stack[user_stack_idx];
            if skip_py_calls == 0 && pystack_idx > 0 && python_calls.contains(&user_addr) {
                if python_stack_markers.is_empty() {
                    while pystack_idx > 0 {
                        pystack_idx -= 1;
                        merged_addrs.push(stack.py_stack[pystack_idx].addr.symbol_id as u64);
                    }
                } else {
                    pystack_idx -= 1;
                    while pystack_idx > 0
                        && !python_stack_markers
                            .contains(&(stack.py_stack[pystack_idx - 1].addr.symbol_id as u64))
                    {
                        pystack_idx -= 1;
                        merged_addrs.push(stack.py_stack[pystack_idx].addr.symbol_id as u64);
                    }
                }
            } else {
                if python_calls.contains(&user_addr) && skip_py_calls > 0 {
                    skip_py_calls -= 1;
                }

                merged_addrs.push(user_addr);
            }
            user_stack_idx += 1;
        }

        merged_addrs
    }

    pub fn get_pystack_from_event(&self, event: &stack_event) -> Vec<PyAddr> {
        use std::sync::atomic::Ordering;

        let stack_len =
            (event.py_msg_buffer.stack_len as usize).min(event.py_msg_buffer.buffer.len());

        if self.is_debug() {
            if stack_len > 0 {
                let count = self.events_with_pystack.fetch_add(1, Ordering::Relaxed) + 1;
                if count <= DEBUG_SAMPLE_LOG_LIMIT {
                    let pid = event.task.tgidpid >> 32;
                    eprintln!(
                        "[pystacks debug] Event #{} with Python stack: PID={} stack_len={}",
                        count, pid, stack_len
                    );
                }
            } else {
                self.events_without_pystack.fetch_add(1, Ordering::Relaxed);
            }
        }

        Vec::from(&event.py_msg_buffer.buffer[..stack_len])
            .iter()
            .map(|frame| PyAddr { addr: frame.into() })
            .collect()
    }

    pub fn load_pystack_symbols(&self, event: &stack_event) {
        use std::sync::atomic::Ordering;

        if !self.initialized() {
            if self.is_debug() && self.events_with_pystack.load(Ordering::Relaxed) == 1 {
                eprintln!("[pystacks debug] load_pystack_symbols: not initialized!");
            }
            return;
        }

        if event.py_msg_buffer.stack_len == 0 {
            return;
        }

        let now = Instant::now();
        let should_load = match self.last_symbol_load.get() {
            None => true,
            Some(last_load) => now.duration_since(last_load) >= self.symbol_load_interval,
        };

        if should_load {
            if self.is_debug() {
                let count = self.symbols_loaded_count.fetch_add(1, Ordering::Relaxed) + 1;
                if count <= DEBUG_SAMPLE_LOG_LIMIT {
                    eprintln!("[pystacks debug] Loading symbols (load #{})", count);
                }
            }

            self.load_symbols();
            self.last_symbol_load.set(Some(now));
        }
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

#[cfg(feature = "pystacks")]
impl Default for StackWalkerRun {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "pystacks")]
impl Drop for StackWalkerRun {
    fn drop(&mut self) {
        self.print_debug_stats();
    }
}

#[cfg(feature = "pystacks")]
unsafe impl Send for StackWalkerRun {}
#[cfg(feature = "pystacks")]
unsafe impl Sync for StackWalkerRun {}

//
// Implementation when pystacks feature is DISABLED
//
#[cfg(not(feature = "pystacks"))]
pub struct StackWalkerRun {}

#[cfg(not(feature = "pystacks"))]
impl StackWalkerRun {
    fn new() -> Self {
        StackWalkerRun {}
    }

    #[allow(clippy::ptr_arg)]
    pub fn pystacks_to_frames_mapping(
        &self,
        _frame_map: &mut HashMap<u64, Vec<LocalFrame>>,
        _global_func_manager: &Arc<crate::stack_recorder::GlobalFunctionManager>,
        _id_counter: &Arc<AtomicUsize>,
        _python_stack_markers: &mut Vec<u64>,
        _stack: &[PyAddr],
    ) {
    }

    #[allow(clippy::ptr_arg)]
    pub fn user_stack_to_python_calls(
        &self,
        _frame_map: &mut HashMap<u64, Vec<LocalFrame>>,
        _global_func_manager: &Arc<crate::stack_recorder::GlobalFunctionManager>,
        _python_calls: &mut Vec<u64>,
    ) {
    }

    pub fn merge_pystacks(
        &self,
        _stack: &Stack,
        _python_calls: &[u64],
        _python_stack_markers: &[u64],
    ) -> Vec<u64> {
        Vec::new()
    }

    pub fn get_pystack_from_event(&self, _event: &stack_event) -> Vec<PyAddr> {
        Vec::new()
    }

    pub fn load_pystack_symbols(&self, _event: &stack_event) {}

    pub fn init_pystacks(&mut self, _pids: &[u32], _bpf_object: &Object, _debug: bool) {}

    pub fn add_pid(&self, _pid: i32) {}

    pub fn print_debug_stats(&self) {}

    pub fn get_python_frame_names(&self, _py_stack: &[PyAddr]) -> Vec<String> {
        Vec::new()
    }
}

#[cfg(not(feature = "pystacks"))]
impl Default for StackWalkerRun {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(feature = "pystacks"))]
impl Drop for StackWalkerRun {
    fn drop(&mut self) {}
}

#[cfg(not(feature = "pystacks"))]
unsafe impl Send for StackWalkerRun {}
#[cfg(not(feature = "pystacks"))]
unsafe impl Sync for StackWalkerRun {}
