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
use super::profiles::{MAX_FRAMES_TOTAL, MAX_RECORDS, MAX_TIME};
use super::{GoProcess, ReadStats};

/// The deepest goroutine stack walked, as pprof's default
/// `debug.profstackdepth`.
const MAX_DEPTH: usize = 128;

/// How often a goroutine that changed while it was read is read again.
const MAX_TRIES: usize = 3;

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
        if len == 0 || len > MAX_RECORDS {
            bail!("allgs says {len} goroutines: not believable");
        }
        let table = self
            .mem
            .bytes(ptr, len * 8)
            .context("reading the goroutine table")?;
        let g_len = l.g_read_len();
        let mut out = Vec::with_capacity(len);
        let mut frames = 0u64;
        for gp in table
            .as_chunks::<8>()
            .0
            .iter()
            .map(|c| u64::from_le_bytes(*c))
        {
            for attempt in 1..=MAX_TRIES {
                let Ok(g) = self.mem.bytes(gp, g_len) else {
                    stats.skipped += 1;
                    break;
                };
                let word = |at: usize| u64_in(&g, at);
                let raw = u32::from_le_bytes(g[l.g_atomicstatus..][..4].try_into().unwrap());
                let status = raw & !l.g_scan;
                if status == l.g_dead || status == l.g_deadextra {
                    break;
                }
                if frames > MAX_FRAMES_TOTAL || started.elapsed() > MAX_TIME {
                    bail!(
                        "{frames} frames in {} goroutines after {:?}: given up",
                        stats.records,
                        started.elapsed()
                    );
                }
                let status_name = l
                    .status_names
                    .get(status as usize)
                    .copied()
                    .filter(|s| !s.is_empty())
                    .unwrap_or("unknown");
                // A goroutine whose stack is being copied runs too: its
                // `sched` is stale.
                let on_cpu = status == l.g_running || status == l.g_copystack;
                let (mut pcs, whole) = if on_cpu {
                    (Vec::new(), true)
                } else if status == l.g_syscall {
                    self.walk_stack(word(l.g_syscallpc), word(l.g_syscallbp), word(l.g_stack_hi))
                } else {
                    let pc = word(l.g_sched_pc);
                    let (mut pcs, whole) =
                        self.walk_stack(pc, word(l.g_sched_bp), word(l.g_stack_hi));
                    if status != l.g_waiting {
                        if let Some(caller) = self.caller_at_stack_check(pc, word(l.g_sched_sp)) {
                            pcs.insert(1, caller);
                        }
                    }
                    (pcs, whole)
                };
                if !on_cpu {
                    // The program runs on: the goroutine may have run, or its
                    // stack may have been moved and handed to another, between
                    // the read of its `g` and the reads of its stack. Then its
                    // `g` has changed (state, `sched`, `stack`, `trackingSeq`).
                    let same = self.mem.bytes(gp, g_len).is_ok_and(|again| again == g);
                    if !(same && whole) && attempt < MAX_TRIES {
                        continue;
                    }
                    if !same || (!whole && raw & l.g_scan != 0) {
                        // It never held still, or the collector, which owns
                        // the stack while the scan bit is set, was moving it
                        // every time: listed without a stack, as a running
                        // goroutine is, and counted. (A walk that ends early
                        // on a goroutine at rest is kept: its frame pointers
                        // lead out of its stack, as under a call from C.)
                        stats.skipped += 1;
                        pcs = Vec::new();
                    }
                }
                stats.records += 1;
                frames += pcs.len() as u64;
                let start_function = self
                    .function(word(l.g_startpc), false)
                    .unwrap_or("")
                    .to_string();
                // The name is charged to the same budget, eight bytes as a
                // frame.
                frames += start_function.len() as u64 / 8;
                out.push(Goroutine {
                    goid: word(l.g_goid),
                    status: status_name,
                    // The runtime leaves the last reason in place when the
                    // goroutine wakes: it means something only while it waits.
                    wait_reason: if status == l.g_waiting || status == l.g_leaked {
                        l.wait_reasons
                            .get(usize::from(g[l.g_waitreason]))
                            .copied()
                            .unwrap_or("unknown")
                    } else {
                        ""
                    },
                    wait_since: word(l.g_waitsince) as i64,
                    system: is_system_goroutine(&start_function),
                    pcs,
                    start_function,
                });
                break;
            }
        }
        self.account(stats, before, started.elapsed());
        Ok(out)
    }

    /// A goroutine preempted at a function's stack check was stopped before
    /// that function pushed its frame pointer: `sched.bp` is still its
    /// caller's, so the walk from it passes the caller over. `morestack` saved
    /// the function's SP, where the return address into the caller lies. The
    /// case is known by the instruction before `pc`: the call to morestack.
    fn caller_at_stack_check(&self, pc: u64, sp: u64) -> Option<u64> {
        let call = self.mem.bytes(pc.checked_sub(5)?, 5).ok()?;
        if call[0] != 0xe8 {
            return None;
        }
        let rel = i64::from(i32::from_le_bytes(call[1..5].try_into().unwrap()));
        let target = (pc as i64).wrapping_add(rel) as u64;
        if !self
            .function(target, false)?
            .starts_with("runtime.morestack")
        {
            return None;
        }
        self.mem.u64_at(sp).ok()
    }

    /// A stopped goroutine's stack by frame pointers: `pc` where it will go
    /// on, then the return address saved above each frame pointer. The stack
    /// is read a window at a time, up to its top at `hi`, so a typical
    /// goroutine costs one read. Also whether the walk came to the outermost
    /// frame (or to `MAX_DEPTH`): if not, the stack was moving under the read,
    /// or its frame pointers lead out of it (a Go function that C called).
    fn walk_stack(&self, pc: u64, mut bp: u64, hi: u64) -> (Vec<u64>, bool) {
        const WINDOW: u64 = 8192;
        // Every pc is named as a return address, one byte back. A goroutine
        // that has not run yet stands at its function's first instruction.
        let mut pcs = vec![if self.is_entry(pc) { pc + 1 } else { pc }];
        let mut window: (u64, Vec<u8>) = (0, Vec::new());
        while bp != 0 && pcs.len() < MAX_DEPTH {
            // A frame is inside the goroutine's stack.
            if bp.checked_add(16).is_none_or(|end| end > hi) {
                return (pcs, false);
            }
            let (start, buf) = &window;
            let inside = bp >= *start && bp + 16 <= *start + buf.len() as u64;
            if !inside {
                let end = hi.min(bp.saturating_add(WINDOW));
                let Ok(buf) = self.mem.bytes(bp, (end - bp) as usize) else {
                    return (pcs, false);
                };
                window = (bp, buf);
            }
            let at = (bp - window.0) as usize;
            let next = u64_in(&window.1, at);
            let ret = u64_in(&window.1, at + 8);
            if ret == 0 {
                return (pcs, false);
            }
            pcs.push(ret);
            // The outermost frame saved no frame pointer. Callers' frames are
            // above: one that does not climb is a stack that moved under the
            // read.
            if next == 0 {
                return (pcs, true);
            }
            if next <= bp {
                return (pcs, false);
            }
            bp = next;
        }
        (pcs, true)
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
