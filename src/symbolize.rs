use std::collections::HashMap;

use anyhow::Error;
use blazesym::symbolize::{CodeInfo, Input, Kernel, Process, Source, Sym, Symbolized, Symbolizer};
use blazesym::{Addr, Pid};

const ADDR_WIDTH: usize = 16;
pub const KERNEL_THREAD_STACK_STUB: u64 = 1234;
pub const PREEMPT_EVENT_STACK_STUB: u64 = 5678;

pub struct SymbolizerCache<'a> {
    symbolizer: Symbolizer,
    kernel_src: Source<'a>,
    src_cache: HashMap<u32, Source<'a>>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Stack {
    kernel_stack: Vec<Addr>,
    user_stack: Vec<Addr>,
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
            "  {input_addr:#0width$x}: {name} @ {addr:#x}+{offset:#x}{code_info}",
            code_info = code_info.as_deref().unwrap_or(""),
            width = ADDR_WIDTH
        )
        .to_string()
    } else {
        // Otherwise we are dealing with an inlined call.
        format!(
            "  {:width$}  {name}{code_info} [inlined]",
            " ",
            code_info = code_info
                .map(|info| format!(" @{info}"))
                .as_deref()
                .unwrap_or(""),
            width = ADDR_WIDTH
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
                ret.push(format!(
                    "  {input_addr:#0width$x}: <unknown: {e}>",
                    width = ADDR_WIDTH,
                    e = e
                ));
            }
        }
    }
    ret
}

impl<'a> SymbolizerCache<'a> {
    pub fn new() -> Self {
        SymbolizerCache {
            symbolizer: Symbolizer::new(),
            kernel_src: Source::Kernel(Kernel::default()),
            src_cache: HashMap::new(),
        }
    }

    pub fn symbolize_stack(
        &mut self,
        pid: u32,
        stack: &Stack,
    ) -> Result<Vec<String>, Error> {
        let kernel_src = &self.kernel_src;
        let user_src = self.src_cache.entry(pid).or_insert(Source::Process(Process::new(Pid::from(pid))));

        let user_stack = &stack.user_stack;
        let kernel_stack = &stack.kernel_stack;

        if !user_stack.is_empty() && user_stack[0] == PREEMPT_EVENT_STACK_STUB {
            return Ok(vec!["preempt".to_string()]);
        }

        let mut symbols = Vec::<String>::new();
        match self.symbolizer.symbolize(user_src, Input::AbsAddr(user_stack)) {
            Ok(syms) => {
                symbols.extend(print_symbols(user_stack.iter().copied().zip(syms)));
            }
            Err(e) => return Err(e.into()),
        }
        match self.symbolizer.symbolize(kernel_src, Input::AbsAddr(kernel_stack)) {
            Ok(syms) => {
                symbols.extend(print_symbols(kernel_stack.iter().copied().zip(syms)));
            }
            Err(e) => return Err(e.into()),
        }
        Ok(symbols)
    }
}

impl Stack {
    pub fn new(kernel_stack: &Vec<u64>, user_stack: &Vec<u64>) -> Self {
        let my_kernel_stack = match kernel_stack[0] {
            PREEMPT_EVENT_STACK_STUB => vec![],
            _ => kernel_stack
                .iter()
                .rev()
                .filter(|x| **x > 0)
                .copied()
                .collect(),
        };
        let my_user_stack = match user_stack[0] {
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
        }
    }
}
