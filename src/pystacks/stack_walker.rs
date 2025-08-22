use crate::stack_recorder::LocalFrame;
use crate::symbolize::Stack;
use crate::systing::types::stack_event;
use libbpf_rs::libbpf_sys;
use libbpf_rs::Object;
use perfetto_protos::profile_common::InternedString;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::ptr::NonNull;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

#[cfg(feature = "pystacks")]
use {
    crate::pystacks::bindings,
    crate::stack_recorder::add_frame,
    libbpf_rs::AsRawLibbpf,
    std::fmt,
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

    pub fn init(&mut self, bpf_object: NonNull<libbpf_sys::bpf_object>, pid_opts: &mut [i32]) {
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

    pub fn initialized(&self) -> bool {
        !self.ptr.is_null()
    }

    pub fn symbolize_function(&self, frame: &PyAddr) -> String {
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

    pub fn load_symbols(&self) {
        if self.initialized() {
            unsafe { bindings::pystacks_load_symbols(self.ptr) };
        }
    }

    pub fn pystacks_to_frames_mapping(
        &self,
        frame_map: &mut HashMap<u64, Vec<LocalFrame>>,
        func_map: &mut HashMap<String, InternedString>,
        id_counter: &mut Arc<AtomicUsize>,
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

            let name = self.symbolize_function(frame);

            add_frame(
                frame_map,
                func_map,
                id_counter,
                frame.addr.symbol_id.into(),
                0,
                0,
                format!("{name} [py]"),
            );

            if name == "<interpreter trampoline>" {
                python_stack_markers.push(frame.addr.symbol_id.into());
            }
        }
    }

    #[allow(clippy::ptr_arg)] // allow Vec needed for push below
    pub fn user_stack_to_python_calls(
        &self,
        frame_map: &mut HashMap<u64, Vec<LocalFrame>>,
        func_map: &mut HashMap<String, InternedString>,
        python_calls: &mut Vec<u64>,
    ) {
        let python_call_iids: Vec<_> = func_map
            .iter()
            .filter(|(key, value)| key.starts_with("_PyEval_EvalFrame") && value.iid.is_some())
            .map(|(_, value)| value.iid.unwrap())
            .collect();

        for (key, values) in frame_map {
            for value in values {
                if value.frame.function_name_id.is_some()
                    && python_call_iids.contains(&value.frame.function_name_id.unwrap())
                {
                    python_calls.push(*key);
                }
            }
        }
    }

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

        // if we have more pyton calls in the system stack than python frames
        // skip the first N python calls, as the python frames are leafs
        // If it is only off by 1, it is more likely that we have entered a
        // PyEval_EvalFrameDeafult but not yet setup the leaf frame, so ignore these
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
        let mut skip_py_frame = py_marker_count.saturating_sub(py_call_count);

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
                pystack_idx -= 1;
                if python_stack_markers.is_empty() {
                    merged_addrs.push(stack.py_stack[pystack_idx].addr.symbol_id as u64);
                } else {
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
        let stack_len = (event.py_msg_buffer.stack_len as usize).min(event.py_msg_buffer.buffer.len());
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

    pub fn init(&mut self, _bpf_object: NonNull<libbpf_sys::bpf_object>, _pid_opts: &mut [i32]) {
        // Stub implementation when pystacks feature is disabled
    }

    pub fn initialized(&self) -> bool {
        false
    }

    pub fn symbolize_function(&self, _frame: &PyAddr) -> String {
        "<unknown python>".to_string()
    }

    pub fn load_symbols(&self) {
        // Stub implementation when pystacks feature is disabled
    }

    #[allow(clippy::ptr_arg)] // allow Vec needed for consistency with pystacks version
    pub fn pystacks_to_frames_mapping(
        &self,
        _frame_map: &mut HashMap<u64, Vec<LocalFrame>>,
        _func_map: &mut HashMap<String, InternedString>,
        _id_counter: &mut Arc<AtomicUsize>,
        _python_stack_markers: &mut Vec<u64>,
        _stack: &[PyAddr],
    ) {
        // Stub implementation when pystacks feature is disabled
    }

    #[allow(clippy::ptr_arg)] // allow Vec needed for consistency with pystacks version
    pub fn user_stack_to_python_calls(
        &self,
        _frame_map: &mut HashMap<u64, Vec<LocalFrame>>,
        _func_map: &mut HashMap<String, InternedString>,
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