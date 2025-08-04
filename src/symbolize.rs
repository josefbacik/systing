use blazesym::symbolize::{CodeInfo, Sym, Symbolized};
use blazesym::Addr;

use crate::pystacks::stack_walker::PyAddr;

const ADDR_WIDTH: usize = 16;
pub const KERNEL_THREAD_STACK_STUB: u64 = 1234;
pub const PREEMPT_EVENT_STACK_STUB: u64 = 5678;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Stack {
    pub kernel_stack: Vec<Addr>,
    pub user_stack: Vec<Addr>,
    pub py_stack: Vec<PyAddr>,
}

fn print_frame(
    name: &str,
    addr_info: Option<(Addr, Addr, usize)>,
    code_info: &Option<CodeInfo>,
) -> String {
    let code_info = code_info.as_ref().map(|code_info| {
        let path = code_info.to_path();
        let path = path.display();

        match (code_info.line, code_info.column) {
            (Some(line), Some(col)) => format!(" {path}:{line}:{col}"),
            (Some(line), None) => format!(" {path}:{line}"),
            (None, _) => format!(" {path}"),
        }
    });

    if let Some((input_addr, addr, offset)) = addr_info {
        // If we have various address information bits we have a new symbol.
        format!(
            "  {input_addr:#0ADDR_WIDTH$x}: {name} @ {addr:#x}+{offset:#x}{code_info}",
            code_info = code_info.as_deref().unwrap_or("")
        )
        .to_string()
    } else {
        // Otherwise we are dealing with an inlined call.
        format!(
            "  {:ADDR_WIDTH$}  {name}{code_info} [inlined]",
            " ",
            code_info = code_info
                .map(|info| format!(" @{info}"))
                .as_deref()
                .unwrap_or("")
        )
        .to_string()
    }
}

pub fn print_symbols<'a, I>(syms: I) -> Vec<String>
where
    I: IntoIterator<Item = (Addr, Symbolized<'a>)>,
{
    let mut ret = Vec::new();
    for (input_addr, sym) in syms {
        match sym {
            Symbolized::Sym(Sym {
                addr,
                name,
                offset,
                code_info,
                inlined,
                ..
            }) => {
                ret.push(print_frame(
                    &name,
                    Some((input_addr, addr, offset)),
                    &code_info,
                ));
                for inline in inlined {
                    ret.push(print_frame(&inline.name, None, &inline.code_info));
                }
            }
            Symbolized::Unknown(e) => {
                ret.push(format!("  {input_addr:#0ADDR_WIDTH$x}: <unknown: {e}>",));
            }
        }
    }
    ret
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
