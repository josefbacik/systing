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
    crate::pystacks::bindings, crate::stack_recorder::add_frame, libbpf_rs::libbpf_sys,
    libbpf_rs::AsRawLibbpf, std::ffi::CStr, std::fmt, std::ptr::NonNull,
};

/// Callback function for strobelight library logging.
/// Only logs WARN level by default. Set PYSTACKS_DEBUG=1 to enable all levels.
#[cfg(feature = "pystacks")]
extern "C" fn strobelight_log_callback(
    level: bindings::strobelight_lib_print_level,
    msg: *const std::os::raw::c_char,
) -> std::os::raw::c_int {
    use std::sync::atomic::{AtomicBool, Ordering};

    // Cache whether debug mode is enabled (checked once on first call)
    static DEBUG_ENABLED: AtomicBool = AtomicBool::new(false);
    static INITIALIZED: AtomicBool = AtomicBool::new(false);

    if !INITIALIZED.swap(true, Ordering::Relaxed) {
        DEBUG_ENABLED.store(std::env::var("PYSTACKS_DEBUG").is_ok(), Ordering::Relaxed);
    }

    if msg.is_null() {
        return 0;
    }

    // By default, only log WARN. Enable DEBUG/INFO with PYSTACKS_DEBUG=1
    let should_log = match level {
        bindings::strobelight_lib_print_level_STROBELIGHT_LIB_WARN => true,
        _ => DEBUG_ENABLED.load(Ordering::Relaxed),
    };

    if should_log {
        // SAFETY: msg pointer was checked for null above, and the C library
        // guarantees it provides a valid null-terminated string.
        let msg_str = unsafe { CStr::from_ptr(msg) }.to_string_lossy();
        let level_str = match level {
            bindings::strobelight_lib_print_level_STROBELIGHT_LIB_WARN => "WARN",
            bindings::strobelight_lib_print_level_STROBELIGHT_LIB_INFO => "INFO",
            bindings::strobelight_lib_print_level_STROBELIGHT_LIB_DEBUG => "DEBUG",
            _ => "UNKNOWN",
        };
        eprintln!("[pystacks {level_str}] {msg_str}");
    }
    0
}

#[derive(Debug, Clone)]
pub struct PyAddr {
    #[cfg(feature = "pystacks")]
    pub addr: bindings::stack_walker_frame,
}
unsafe impl Send for PyAddr {}
unsafe impl Sync for PyAddr {}

impl PartialEq for PyAddr {
    #[cfg(not(feature = "pystacks"))]
    fn eq(&self, _: &Self) -> bool {
        true
    }

    #[cfg(feature = "pystacks")]
    fn eq(&self, other: &Self) -> bool {
        // Define equality based on both fields
        self.addr.symbol_id == other.addr.symbol_id && self.addr.inst_idx == other.addr.inst_idx
    }
}
impl Eq for PyAddr {}

impl Hash for PyAddr {
    #[cfg(not(feature = "pystacks"))]
    fn hash<H: Hasher>(&self, _: &mut H) {}

    #[cfg(feature = "pystacks")]
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Hash each field
        self.addr.symbol_id.hash(state);
        self.addr.inst_idx.hash(state);
    }
}

#[cfg(feature = "pystacks")]
impl From<&crate::systing_core::types::stack_walker_frame> for bindings::stack_walker_frame {
    fn from(frame: &crate::systing_core::types::stack_walker_frame) -> Self {
        bindings::stack_walker_frame {
            symbol_id: frame.symbol_id,
            inst_idx: frame.inst_idx,
        }
    }
}

#[cfg(feature = "pystacks")]
impl fmt::Display for crate::systing_core::types::stack_walker_frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Customize the formatting as needed
        write!(
            f,
            "StackWalkerFrame {{ symbol_id: {} inst_idx: {} }}",
            self.symbol_id, self.inst_idx
        )
    }
}

#[cfg(feature = "pystacks")]
impl fmt::Display for bindings::stack_walker_frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Customize the formatting as needed
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
    ptr: *mut bindings::stack_walker_run,
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
            ptr: std::ptr::null_mut(),
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

    fn init(
        &mut self,
        bpf_object: NonNull<libbpf_sys::bpf_object>,
        pid_opts: &mut [i32],
        debug: bool,
    ) {
        use std::sync::atomic::Ordering;

        self.debug.store(debug, Ordering::Relaxed);

        if debug {
            eprintln!(
                "[pystacks debug] StackWalkerRun::init called with {} PIDs",
                pid_opts.len()
            );
        }

        if !self.initialized() {
            let mut opts = bindings::stack_walker_opts {
                pids: pid_opts.as_mut_ptr(),
                pidCount: pid_opts.len(),
                manualSymbolRefresh: true,
            };

            if debug {
                eprintln!("[pystacks debug] Calling pystacks_init...");
            }

            self.ptr = unsafe {
                bindings::pystacks_init(
                    bpf_object.as_ptr() as *mut bindings::bpf_object,
                    &mut opts as *mut _,
                    std::ptr::null_mut(),
                )
            };

            if debug {
                if self.ptr.is_null() {
                    eprintln!("[pystacks debug] pystacks_init FAILED - returned null pointer");
                } else {
                    eprintln!("[pystacks debug] pystacks_init SUCCESS - library initialized");
                }
            }
        } else if debug {
            eprintln!("[pystacks debug] StackWalkerRun already initialized, skipping");
        }
    }

    fn initialized(&self) -> bool {
        !self.ptr.is_null()
    }

    /// Returns true if debug mode is enabled.
    fn is_debug(&self) -> bool {
        self.debug.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Prints debug statistics summarizing pystacks activity.
    ///
    /// This is automatically called when the StackWalkerRun is dropped,
    /// but can also be called manually to get intermediate statistics.
    /// Only produces output if debug mode was enabled during initialization.
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
        let mut buff = vec![0; 256];
        let mut len = 0;

        if self.initialized() {
            len = unsafe {
                bindings::pystacks_symbolize_function(
                    self.ptr,
                    &raw const frame.addr,
                    buff.as_mut_ptr() as *mut i8,
                    buff.len(),
                )
            };
        }

        if len > 0 {
            core::str::from_utf8(&buff[..len as usize])
                .unwrap_or("<unknown python>")
                .to_string()
        } else {
            "<unknown python>".to_string()
        }
    }

    /// Symbolizes a Python frame to extract the source filename and line number.
    ///
    /// Returns a tuple of (filename, line_number) where:
    /// - `filename` is the source file path, or "unknown" if unavailable
    /// - `line_number` is `Some(line)` if available, or `None` if unavailable
    ///
    /// The C++ pystacks library uses `u32::MAX` as a sentinel value to indicate
    /// no line information is available.
    fn symbolize_filename_line(&self, frame: &PyAddr) -> (String, Option<usize>) {
        const FILENAME_BUFFER_SIZE: usize = 512;
        const NO_LINE_INFO: usize = u32::MAX as usize;
        const UNKNOWN_FILENAME: &str = "unknown";

        let mut buff = vec![0; FILENAME_BUFFER_SIZE];
        let mut line_number: usize = 0;

        let len = if self.initialized() {
            unsafe {
                bindings::pystacks_symbolize_filename_line(
                    self.ptr,
                    &raw const frame.addr,
                    buff.as_mut_ptr() as *mut i8,
                    buff.len(),
                    &mut line_number as *mut usize,
                )
            }
        } else {
            0
        };

        let filename = if len > 0 {
            core::str::from_utf8(&buff[..len as usize])
                .unwrap_or(UNKNOWN_FILENAME)
                .to_string()
        } else {
            UNKNOWN_FILENAME.to_string()
        };

        let line = if line_number == NO_LINE_INFO {
            None
        } else {
            Some(line_number)
        };

        (filename, line)
    }

    fn load_symbols(&self) {
        if self.initialized() {
            unsafe { bindings::pystacks_load_symbols(self.ptr) };
        }
    }

    pub fn add_pid(&self, pid: i32) {
        if self.initialized() {
            if self.is_debug() {
                eprintln!("[pystacks debug] Dynamically adding PID {}", pid);
            }
            unsafe { bindings::pystacks_add_pid(self.ptr, pid) };
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

            // Extract just the base filename (similar to how blazesym extracts module name)
            let base_filename = std::path::Path::new(&filename)
                .file_name()
                .and_then(|f| f.to_str())
                .unwrap_or(&filename);

            // Format matches blazesym: "function_name (python) [filename:line]"
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

    #[allow(clippy::ptr_arg)] // allow Vec needed for push below
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

        // Fallback for Python binaries without frame pointers: C stack unwinding fails,
        // so use Python frames directly when no _PyEval_EvalFrame marker is found.
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

        // if we have more python calls in the system stack than python frames
        // skip the first N python calls, as the python frames are leafs
        // If it is only off by 1, it is more likely that we have entered a
        // PyEval_EvalFrameDefault but not yet setup the leaf frame, so ignore these
        // instances
        let mut skip_py_calls =
            if py_call_count > py_marker_count && py_call_count - py_marker_count > 1 {
                py_call_count - py_marker_count
            } else {
                0
            };

        // if we have more python frames than python calls in the system stack
        // drop the first N python frames. This could happen if the system stack overflows
        // the buffer used to collect it, in which case the base of the stack would be
        // missing.
        let frame_mismatch = py_marker_count.saturating_sub(py_call_count);
        let mut skip_py_frame = if python_stack_markers.is_empty() {
            // No markers - we'll add all frames when we hit PyEval, so don't skip any
            0
        } else if frame_mismatch > Self::FRAME_MISMATCH_THRESHOLD {
            // With markers but significant mismatch - likely truncation
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
                // decrement either way. In the if case below, we added the address. In
                // the else case below, we are incrementing past the stack marker that
                // ended the previous loop
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
            // increment either way. In the if case, we are incremented past the
            // python_call address, in the else case, we added the address
            user_stack_idx += 1;
        }

        merged_addrs
    }

    pub fn get_pystack_from_event(&self, event: &stack_event) -> Vec<PyAddr> {
        use std::sync::atomic::Ordering;

        let stack_len =
            (event.py_msg_buffer.stack_len as usize).min(event.py_msg_buffer.buffer.len());

        // Track statistics only in debug mode to avoid overhead in hot path
        if self.is_debug() {
            if stack_len > 0 {
                let count = self.events_with_pystack.fetch_add(1, Ordering::Relaxed) + 1;

                // Log first few events with Python stacks
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
                eprintln!("[pystacks debug] load_pystack_symbols: library not initialized!");
            }
            return;
        }

        if event.py_msg_buffer.stack_len == 0 {
            return;
        }

        // Rate limit symbol loading - only reload if enough time has passed
        // This catches dying processes while avoiding excessive BPF map scanning
        let now = Instant::now();
        let should_load = match self.last_symbol_load.get() {
            None => true, // First time, always load
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
            // Set up logging before initialization
            // Note: The strobelight_log_callback checks PYSTACKS_DEBUG env var internally
            // for enabling verbose C++ library output. Set this env var before running
            // systing if you need C++ library debug output.
            unsafe {
                bindings::strobelight_lib_set_print(Some(strobelight_log_callback));
            }

            let mut pid_opts: Vec<i32> = pids.iter().map(|&pid| pid as i32).collect();

            self.init(bpf_object.as_libbpf_object(), &mut pid_opts, debug);
        } else if debug {
            eprintln!("[pystacks debug] No PIDs provided, skipping pystacks initialization");
        }
    }

    /// Get Python frame names as formatted strings for streaming mode.
    /// Returns a vector of frame name strings in the format:
    /// "function_name (python) [filename:line]"
    pub fn get_python_frame_names(&self, py_stack: &[PyAddr]) -> Vec<String> {
        use std::sync::atomic::Ordering;

        if !self.initialized() {
            if self.is_debug() && !py_stack.is_empty() {
                eprintln!(
                    "[pystacks debug] get_python_frame_names: library not initialized, returning empty for {} frames",
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

                // Track statistics only in debug mode
                if debug {
                    if func_name == "<unknown python>" {
                        self.frames_unknown.fetch_add(1, Ordering::Relaxed);
                    } else {
                        let count = self.frames_symbolized.fetch_add(1, Ordering::Relaxed) + 1;

                        // Log sample frames
                        if count <= DEBUG_SAMPLE_LOG_LIMIT {
                            // Extract just the base filename for logging
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

                // Extract just the base filename
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
        // Print debug stats before cleanup
        self.print_debug_stats();

        if !self.ptr.is_null() {
            unsafe { bindings::pystacks_free(self.ptr) };
            self.ptr = std::ptr::null_mut();
        }
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

    #[allow(clippy::ptr_arg)] // allow Vec needed for consistency with pystacks version
    pub fn pystacks_to_frames_mapping(
        &self,
        _frame_map: &mut HashMap<u64, Vec<LocalFrame>>,
        _global_func_manager: &Arc<crate::stack_recorder::GlobalFunctionManager>,
        _id_counter: &Arc<AtomicUsize>,
        _python_stack_markers: &mut Vec<u64>,
        _stack: &[PyAddr],
    ) {
        // Stub implementation when pystacks feature is disabled
    }

    #[allow(clippy::ptr_arg)] // allow Vec needed for consistency with pystacks version
    pub fn user_stack_to_python_calls(
        &self,
        _frame_map: &mut HashMap<u64, Vec<LocalFrame>>,
        _global_func_manager: &Arc<crate::stack_recorder::GlobalFunctionManager>,
        _python_calls: &mut Vec<u64>,
    ) {
        // Stub implementation when pystacks feature is disabled
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

    pub fn load_pystack_symbols(&self, _event: &stack_event) {
        // Stub implementation when pystacks feature is disabled
    }

    pub fn init_pystacks(&mut self, _pids: &[u32], _bpf_object: &Object, _debug: bool) {
        // Stub implementation when pystacks feature is disabled
    }

    pub fn add_pid(&self, _pid: i32) {
        // Stub implementation when pystacks feature is disabled
    }

    pub fn print_debug_stats(&self) {
        // Stub implementation when pystacks feature is disabled
    }

    pub fn get_python_frame_names(&self, _py_stack: &[PyAddr]) -> Vec<String> {
        // Stub implementation when pystacks feature is disabled
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
    fn drop(&mut self) {
        // Stub implementation when pystacks feature is disabled
    }
}

#[cfg(not(feature = "pystacks"))]
unsafe impl Send for StackWalkerRun {}
#[cfg(not(feature = "pystacks"))]
unsafe impl Sync for StackWalkerRun {}
