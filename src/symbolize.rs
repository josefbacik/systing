use blazesym::Addr;

use crate::pystacks::stack_walker::PyAddr;

pub const KERNEL_THREAD_STACK_STUB: u64 = 1234;
pub const PREEMPT_EVENT_STACK_STUB: u64 = 5678;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Stack {
    pub kernel_stack: Vec<Addr>,
    pub user_stack: Vec<Addr>,
    pub py_stack: Vec<PyAddr>,
}


impl Stack {
    pub fn new(kernel_stack: &[u64], user_stack: &[u64], py_stack: &[PyAddr]) -> Self {
        let first_kernel_element = if kernel_stack.is_empty() {
            0
        } else {
            kernel_stack[0]
        };
        let first_user_element = if user_stack.is_empty() {
            0
        } else {
            user_stack[0]
        };
        let my_kernel_stack = match first_kernel_element {
            PREEMPT_EVENT_STACK_STUB => vec![],
            _ => kernel_stack
                .iter()
                .rev()
                .filter(|x| **x > 0)
                .copied()
                .collect(),
        };
        let my_user_stack = match first_user_element {
            KERNEL_THREAD_STACK_STUB => vec![],
            PREEMPT_EVENT_STACK_STUB => vec![PREEMPT_EVENT_STACK_STUB],
            _ => user_stack
                .iter()
                .rev()
                .filter(|x| **x > 0)
                .copied()
                .collect(),
        };
        Stack {
            kernel_stack: my_kernel_stack,
            user_stack: my_user_stack,
            py_stack: py_stack.to_vec(),
        }
    }
}
