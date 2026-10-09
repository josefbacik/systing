//! Naming a Go program's code by its own function table (`.gopclntab`),
//! which every Go binary keeps, stripped or not.

use super::GoProcess;

impl GoProcess {
    /// The function `pc` is in. A return address is looked up one byte back,
    /// in the call.
    pub fn function(&self, pc: u64, return_address: bool) -> Option<&str> {
        let pc = pc.wrapping_sub(self.bias);
        let pc = if return_address {
            pc.wrapping_sub(1)
        } else {
            pc
        };
        self.pclntab.find_func(pc).map(|f| f.name)
    }

    /// The functions of a stack of return addresses, leaf first; `?` where
    /// the table has none.
    pub fn names(&self, pcs: &[u64]) -> Vec<String> {
        pcs.iter()
            .map(|&pc| self.function(pc, true).unwrap_or("?").to_string())
            .collect()
    }

    /// pprof's `hideRuntime`: the runtime's frames at the leaf of a heap
    /// stack (mallocgc and its helpers) left out, unless that is all there is.
    pub(crate) fn hide_runtime(&self, pcs: &[u64]) -> Vec<u64> {
        let first_user = pcs.iter().position(|&pc| {
            self.function(pc, true)
                .is_some_and(|f| !f.starts_with("runtime.") && !f.starts_with("internal/runtime/"))
        });
        match first_user {
            Some(i) => pcs[i..].to_vec(),
            None => pcs.to_vec(),
        }
    }
}
