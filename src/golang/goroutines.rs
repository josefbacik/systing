//! Every goroutine of a Go program, read from `runtime.allgs` without
//! stopping it: its state, why and since when it waits, and its stack.
//!
//! A goroutine that is not running keeps where it stopped in its `g`
//! (`sched`, or `syscallpc`/`syscallbp` in a system call), and its stack is
//! walked from there by frame pointers, which Go keeps on x86-64. A running
//! goroutine's registers are on a CPU, not in memory: it has no stack here.

use std::time::Instant;

use anyhow::{bail, Context, Result};

use super::discovery::{u64_in, Global};
use super::profiles::MAX_RECORDS;
use super::{GoProcess, ReadStats};

/// The deepest goroutine stack walked, as pprof's default
/// `debug.profstackdepth`.
const MAX_DEPTH: usize = 128;

/// One goroutine.
#[derive(Debug, Clone)]
pub struct Goroutine {
    pub goid: u64,
    pub status: &'static str,
    /// Empty when it is not waiting.
    pub wait_reason: &'static str,
    /// When it started waiting, in the runtime's nanotime (CLOCK_MONOTONIC);
    /// 0 when the runtime did not note it.
    pub wait_since: i64,
    /// One of the runtime's own goroutines, which pprof leaves out.
    pub system: bool,
    /// Return addresses, leaf first. Empty for a running goroutine.
    pub pcs: Vec<u64>,
    pub start_function: String,
}

impl GoProcess {
    /// Every goroutine, the program's and the runtime's own.
    pub fn goroutines(&self, stats: &mut ReadStats) -> Result<Vec<Goroutine>> {
        let started = Instant::now();
        let before = self.mem.traffic();
        let l = &self.layout;
        let allgs = self.global(Global::AllGs)?;
        let ptr = self.mem.u64_at(allgs)?;
        let len = self.mem.u64_at(allgs + 8)? as usize;
        if len > MAX_RECORDS {
            bail!("allgs says {len} goroutines: not believable");
        }
        let table = self
            .mem
            .bytes(ptr, len * 8)
            .context("reading the goroutine table")?;
        let g_len = l.g_read_len();
        let mut out = Vec::with_capacity(len);
        for gp in table
            .as_chunks::<8>()
            .0
            .iter()
            .map(|c| u64::from_le_bytes(*c))
        {
            let Ok(g) = self.mem.bytes(gp, g_len) else {
                stats.skipped += 1;
                continue;
            };
            let word = |at: usize| u64_in(&g, at);
            let status =
                u32::from_le_bytes(g[l.g_atomicstatus..][..4].try_into().unwrap()) & !l.g_scan;
            if status == l.g_dead || status == l.g_deadextra {
                continue;
            }
            stats.records += 1;
            let start_function = self
                .function(word(l.g_startpc), false)
                .unwrap_or("")
                .to_string();
            let pcs = if status == l.g_running {
                Vec::new()
            } else if status == l.g_syscall {
                self.walk_stack(word(l.g_syscallpc), word(l.g_syscallbp), word(l.g_stack_hi))
            } else {
                self.walk_stack(word(l.g_sched_pc), word(l.g_sched_bp), word(l.g_stack_hi))
            };
            out.push(Goroutine {
                goid: word(l.g_goid),
                status: l
                    .status_names
                    .get(status as usize)
                    .copied()
                    .filter(|s| !s.is_empty())
                    .unwrap_or("unknown"),
                wait_reason: l
                    .wait_reasons
                    .get(usize::from(g[l.g_waitreason]))
                    .copied()
                    .unwrap_or("unknown"),
                wait_since: word(l.g_waitsince) as i64,
                system: is_system_goroutine(&start_function),
                pcs,
                start_function,
            });
        }
        self.account(stats, before, started.elapsed());
        Ok(out)
    }

    /// A stopped goroutine's stack by frame pointers: `pc` where it will go
    /// on, then the return address saved above each frame pointer. The stack
    /// is read a window at a time, up to its top at `hi`, so a typical
    /// goroutine costs one read.
    fn walk_stack(&self, pc: u64, mut bp: u64, hi: u64) -> Vec<u64> {
        const WINDOW: u64 = 8192;
        let mut pcs = vec![pc];
        let mut window: (u64, Vec<u8>) = (0, Vec::new());
        while bp != 0 && pcs.len() < MAX_DEPTH {
            let (start, buf) = &window;
            let inside = bp >= *start && bp + 16 <= *start + buf.len() as u64;
            if !inside {
                let end = if hi > bp + 16 {
                    hi.min(bp + WINDOW)
                } else {
                    bp + 16
                };
                let Ok(buf) = self.mem.bytes(bp, (end - bp) as usize) else {
                    break;
                };
                window = (bp, buf);
            }
            let at = (bp - window.0) as usize;
            let next = u64_in(&window.1, at);
            let ret = u64_in(&window.1, at + 8);
            if ret == 0 {
                break;
            }
            pcs.push(ret);
            // Callers' frames are above: a frame pointer that does not climb
            // is the end, or a stack that moved under the read.
            if next <= bp {
                break;
            }
            bp = next;
        }
        pcs
    }
}

/// `isSystemGoroutine`, by the function the goroutine started in.
fn is_system_goroutine(start: &str) -> bool {
    start.starts_with("runtime.")
        && !matches!(
            start,
            "runtime.main" | "runtime.corostart" | "runtime.handleAsyncEvent"
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_goroutines_as_the_runtime_says() {
        assert!(is_system_goroutine("runtime.bgsweep"));
        assert!(!is_system_goroutine("runtime.main"));
        assert!(!is_system_goroutine("main.worker"));
    }
}
