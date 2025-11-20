use crate::stack_recorder::{LocalFrame, Stack};
use crate::systing::types::stack_event;
use libbpf_rs::Object;
use std::collections::HashMap;
#[cfg(feature = "pystacks")]
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

#[cfg(feature = "pystacks")]
use {
    crate::pystacks::bindings, crate::stack_recorder::add_frame, libbpf_rs::libbpf_sys,
    libbpf_rs::AsRawLibbpf, std::fmt, std::ptr::NonNull,
};

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
impl From<&crate::systing::types::stack_walker_frame> for bindings::stack_walker_frame {
    fn from(frame: &crate::systing::types::stack_walker_frame) -> Self {
        bindings::stack_walker_frame {
            symbol_id: frame.symbol_id,
            inst_idx: frame.inst_idx,
        }
    }
}

#[cfg(feature = "pystacks")]
impl fmt::Display for crate::systing::types::stack_walker_frame {
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
#[cfg(feature = "pystacks")]
pub struct StackWalkerRun {
    ptr: *mut bindings::stack_walker_run,
}

#[cfg(feature = "pystacks")]
impl StackWalkerRun {
    fn new() -> Self {
        StackWalkerRun {
            ptr: std::ptr::null_mut(),
        }
    }

    fn init(&mut self, bpf_object: NonNull<libbpf_sys::bpf_object>, pid_opts: &mut [i32]) {
        if !self.initialized() {
            let mut opts = bindings::stack_walker_opts {
                pids: pid_opts.as_mut_ptr(),
                pidCount: pid_opts.len(),
                manualSymbolRefresh: true,
            };

            self.ptr = unsafe {
                bindings::pystacks_init(
                    bpf_object.as_ptr() as *mut bindings::bpf_object,
                    &mut opts as *mut _,
                )
            };
        }
    }

    fn initialized(&self) -> bool {
        !self.ptr.is_null()
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
        let stack_len =
            (event.py_msg_buffer.stack_len as usize).min(event.py_msg_buffer.buffer.len());
        Vec::from(&event.py_msg_buffer.buffer[..stack_len])
            .iter()
            .map(|frame| PyAddr { addr: frame.into() })
            .collect()
    }

    pub fn load_pystack_symbols(&self, event: &stack_event) {
        if self.initialized() && event.py_msg_buffer.stack_len > 0 {
            self.load_symbols();
        }
    }

    pub fn init_pystacks(&mut self, pids: &[u32], bpf_object: &Object) {
        if !pids.is_empty() {
            let mut pid_opts: Vec<i32> = Vec::new();
            for pid in pids.iter() {
                pid_opts.push(*pid as i32);
            }

            self.init(bpf_object.as_libbpf_object(), &mut pid_opts);
        }
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

    pub fn init_pystacks(&mut self, _pids: &[u32], _bpf_object: &Object) {
        // Stub implementation when pystacks feature is disabled
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
