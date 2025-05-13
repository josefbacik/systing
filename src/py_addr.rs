use crate::pystacks_bindings;
use std::fmt;
use std::hash::{Hash, Hasher};

#[derive(Debug, Clone)]
pub struct PyAddr {
    pub addr: pystacks_bindings::stack_walker_frame,
}
unsafe impl Send for PyAddr {}
unsafe impl Sync for PyAddr {}

impl PartialEq for PyAddr {
    fn eq(&self, other: &Self) -> bool {
        // Define equality based on both fields
        self.addr.symbol_id == other.addr.symbol_id && self.addr.inst_idx == other.addr.inst_idx
    }
}
impl Eq for PyAddr {}

impl Hash for PyAddr {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Hash each field
        self.addr.symbol_id.hash(state);
        self.addr.inst_idx.hash(state);
    }
}

impl From<&crate::systing::types::stack_walker_frame> for pystacks_bindings::stack_walker_frame {
    fn from(frame: &crate::systing::types::stack_walker_frame) -> Self {
        pystacks_bindings::stack_walker_frame {
            symbol_id: frame.symbol_id,
            inst_idx: frame.inst_idx,
        }
    }
}

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

impl fmt::Display for pystacks_bindings::stack_walker_frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Customize the formatting as needed
        write!(
            f,
            "StackWalkerFrame {{ symbol_id: {} inst_idx: {} }}",
            self.symbol_id, self.inst_idx
        )
    }
}
