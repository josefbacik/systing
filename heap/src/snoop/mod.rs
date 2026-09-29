//! Read a running process's jemalloc heap profile straight
//! out of its memory, instead of from a `.heap` file jemalloc wrote.
//!
//! `systing-heap --pid PID --snoop` takes the profile the process holds at
//! that moment: no dump interval to wait for, no file written (so no
//! `prof_prefix`, `lg_prof_interval` or disk needed), and nothing done to the
//! process: it is not stopped or signalled and runs no code of ours. The
//! result is a [`Snapshot`] like the one a dump gives, so it goes through the
//! same symbolization and the same output: its rows are the ones a dump of the
//! same heap would hold.
//!
//! How it works, and what it relies on:
//!
//! - [`mem`]: reads through `/proc/<pid>/mem` only. A bad address is an
//!   error, never a fault.
//! - [`locate`]: finds jemalloc's profile table (`bt2gctx`) by its symbol,
//!   or by its shape in a stripped library.
//! - [`layout`] and [`walk`]: the structures behind it, as jemalloc 5.3 and
//!   `dev` lay them out, checked as they are read.
//! - [`elf`]: symbols from a file's `.symtab`.
//!
//! This depends on jemalloc's private data structures, which its authors are
//! free to change; a jemalloc this does not recognise is refused, not
//! guessed at. It is kept in this module, and nothing else in the crate knows
//! how it works.

pub mod elf;
pub mod layout;
pub mod locate;
pub mod mem;
pub mod walk;

use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};

use crate::maps::Maps;
use crate::root::Root;
use crate::{Format, LiveRead, Sample, Snapshot};

use layout::Counts;
use locate::How;
use mem::ProcMem;

/// jemalloc's default `lg_prof_sample`: one sample per 512 KiB.
const DEFAULT_LG_PROF_SAMPLE: u32 = 19;

/// The value `Snapshot::trigger` has for a snapshot taken this way.
pub const TRIGGER: &str = "snoop";

/// How long a whole snoop may take. Reading a real profile takes well under a
/// second; a process (or a filesystem behind its memory) that makes it take
/// longer is given up on, so a read that never returns cannot hold the tool.
pub const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);

/// The most read of the process's own text files: what it maps, the fields of
/// its status, and its environment (looked at for one option only).
const MAX_MAPS_BYTES: u64 = 64 << 20;
const MAX_STATUS_BYTES: u64 = 1 << 20;
const MAX_ENVIRON_BYTES: u64 = 16 << 20;

/// Where a snapshot's sample period is from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeriodFrom {
    /// `lg_prof_sample` itself, read from the process at the library's symbol.
    Symbols,
    /// The `MALLOC_CONF` the process was started with.
    MallocConf,
    /// Neither could be read: jemalloc's default, which is a guess.
    Default,
}

impl PeriodFrom {
    /// As a sentence says it.
    fn said(self) -> &'static str {
        match self {
            PeriodFrom::Symbols => "the library's symbols",
            PeriodFrom::MallocConf => "the process's MALLOC_CONF",
            PeriodFrom::Default => "jemalloc's default",
        }
    }

    /// As `heap_live_read.sample_period_from` has it.
    fn name(self) -> &'static str {
        match self {
            PeriodFrom::Symbols => "symbols",
            PeriodFrom::MallocConf => "malloc_conf",
            PeriodFrom::Default => "default",
        }
    }
}

/// What a snoop found, besides the snapshot: how, for the caller to say.
#[derive(Debug)]
pub struct Report {
    pub how: How,
    pub object: String,
    pub lg_prof_sample: u32,
    pub sample_period_from: PeriodFrom,
    /// Stacks read.
    pub stacks: usize,
    pub stats: walk::Stats,
    pub reads: u64,
    pub bytes: u64,
    pub millis: u128,
}

/// One process, pinned. A pid can come to name another process between one
/// look at it and the next, so it is opened once, as a directory, and its
/// files (memory, maps, root, ...) are all opened through that handle: they
/// are all of the process it was when this was called, or fail if it has since
/// exited.
pub struct Process {
    pid: u32,
    dir: File,
}

impl Process {
    pub fn open(pid: u32) -> Result<Process> {
        let dir =
            File::open(format!("/proc/{pid}")).with_context(|| format!("opening /proc/{pid}"))?;
        Ok(Process { pid, dir })
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// `name` in the process's `/proc` directory, through the handle.
    pub(crate) fn file(&self, name: &str) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}/{name}", self.dir.as_raw_fd()))
    }

    /// Another handle on the same process.
    pub fn try_clone(&self) -> Result<Process> {
        Ok(Process {
            pid: self.pid,
            dir: self
                .dir
                .try_clone()
                .context("duplicating the process handle")?,
        })
    }

    /// The process's root directory, to read the files it names beneath.
    pub fn root(&self) -> Result<Root> {
        Root::open(&self.file("root"))
            .with_context(|| format!("opening the root of pid {}", self.pid))
    }

    /// A file of the process's, no more than `cap` bytes of it: what a process
    /// can be made to hold there is not the tool's to hold.
    pub(crate) fn read_capped(&self, name: &str, cap: u64) -> Result<Vec<u8>> {
        use std::io::Read;
        let mut buf = Vec::new();
        File::open(self.file(name))
            .and_then(|f| f.take(cap + 1).read_to_end(&mut buf))
            .with_context(|| format!("reading /proc/{}/{name}", self.pid))?;
        if buf.len() as u64 > cap {
            bail!("/proc/{}/{name} is larger than {cap} bytes", self.pid);
        }
        Ok(buf)
    }

    fn read_text(&self, name: &str, cap: u64) -> Result<String> {
        Ok(String::from_utf8_lossy(&self.read_capped(name, cap)?).into_owned())
    }

    /// What the process maps, as text.
    pub(crate) fn maps_text(&self) -> Result<String> {
        self.read_text("maps", MAX_MAPS_BYTES)
    }

    /// The user and group a file the process wrote would belong to.
    pub(crate) fn owner(&self) -> Option<(u32, u32)> {
        use std::os::unix::fs::MetadataExt;
        self.dir.metadata().ok().map(|m| (m.uid(), m.gid()))
    }
}

/// [`read`], given up on after `limit`. It runs on a thread of its own, on a
/// second handle to the process, and if it has not finished in time the
/// thread is left behind (it ends with the program, which is about to).
pub fn read_within(process: &Process, limit: std::time::Duration) -> Result<(Snapshot, Report)> {
    let process = process.try_clone()?;
    match run_within(limit, move || {
        let root = process.root()?;
        read(&process, &root)
    }) {
        Ok(result) => result,
        Err(Wait::TimedOut) => bail!(
            "gave up after {} s: reading the process's memory did not finish, \
             perhaps because a page of it is on a filesystem that stalls",
            limit.as_secs()
        ),
        Err(Wait::Panicked) => bail!("reading the process's memory failed unexpectedly"),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Wait {
    TimedOut,
    Panicked,
}

/// Run `f` on a thread and wait for it, no longer than `limit`.
pub(crate) fn run_within<T: Send + 'static>(
    limit: std::time::Duration,
    f: impl FnOnce() -> T + Send + 'static,
) -> std::result::Result<T, Wait> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(limit).map_err(|e| match e {
        std::sync::mpsc::RecvTimeoutError::Timeout => Wait::TimedOut,
        std::sync::mpsc::RecvTimeoutError::Disconnected => Wait::Panicked,
    })
}

/// The heap profile of `process`, as of now. Files it names are read beneath
/// `root`, which must be the process's own ([`Process::root`]).
pub fn read(process: &Process, root: &Root) -> Result<(Snapshot, Report)> {
    let pid = process.pid;
    let started = std::time::Instant::now();
    let mem = ProcMem::open(&process.file("mem")).with_context(|| {
        format!(
            "opening /proc/{pid}/mem: reading a process's memory needs the same user as the \
             process (any other, root included, needs CAP_SYS_PTRACE), a process that is \
             dumpable, and a kernel.yama.ptrace_scope that permits it"
        )
    })?;
    let maps_text = process.read_text("maps", MAX_MAPS_BYTES)?;
    let found = locate::locate(&mem, &Maps::parse(&maps_text), root)?;
    let profile = walk::walk(&mem, found.bt2gctx).with_context(|| {
        format!(
            "reading the profile at {:#x} in {}",
            found.bt2gctx,
            locate::shown(&found.object)
        )
    })?;
    refuse_unusable(&profile)?;
    // The mappings as of the end, so a library loaded meanwhile is named.
    let maps = Maps::parse(&process.read_text("maps", MAX_MAPS_BYTES)?);

    let (lg, from) = match found.lg_prof_sample {
        Some(lg) => (lg, PeriodFrom::Symbols),
        None => match lg_prof_sample_from_env(process) {
            Some(lg) => (lg, PeriodFrom::MallocConf),
            None => (DEFAULT_LG_PROF_SAMPLE, PeriodFrom::Default),
        },
    };
    let samples: Vec<Sample> = profile
        .stacks
        .iter()
        .map(|s| sample(&s.addrs, &s.counts))
        .collect();

    let (reads, bytes) = mem.traffic();
    let report = Report {
        how: found.how,
        object: found.object,
        lg_prof_sample: lg,
        sample_period_from: from,
        stacks: profile.stacks.len(),
        stats: profile.stats,
        reads,
        bytes,
        millis: started.elapsed().as_millis(),
    };
    let snapshot = Snapshot {
        format: Format::Jemalloc,
        source_path: PathBuf::from(format!("/proc/{pid}/mem")),
        // A dump's file name has the pid the process saw for itself; so does this.
        pid: i32::try_from(own_pid(process)).ok(),
        seq: None,
        trigger: Some(TRIGGER),
        dumped_at_unix_ns: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_nanos()).ok()),
        // The user a file the process wrote would belong to.
        owner_uid: process
            .dir
            .metadata()
            .ok()
            .map(|m| std::os::unix::fs::MetadataExt::uid(&m)),
        sample_period: 1u64 << lg,
        samples,
        maps,
        perf_map: None,
        py_code: None,
        live_read: Some(report.live_read()),
    };
    Ok((snapshot, report))
}

/// Say why a profile that was read cannot be used, if it cannot.
fn refuse_unusable(profile: &walk::Profile) -> Result<()> {
    // Backtraces that were recognised, and no thread record under any of them
    // that was: the layout behind the backtrace's own is not this tool's. This
    // is asked before whether there are stacks, which it would otherwise hide.
    if profile.stats.gctx_read > 0 && profile.stats.tctx_read == 0 {
        bail!(
            "found backtraces but no per-thread counters under them: \
             this jemalloc is laid out differently from the ones this tool knows"
        );
    }
    if profile.stacks.is_empty() {
        bail!("the process has no live sampled allocations to report yet");
    }
    // A layout that differs somewhere the shape checks do not look shows as
    // records that cannot be read, or that are not in the order jemalloc keeps
    // them, or whose counters cannot be jemalloc's. A moving heap breaks each
    // of these for a moment, for a few records; a share of them is not that.
    let s = &profile.stats;
    // A majority of eight or more records; fewer say too little either way.
    let mostly_skipped = |skipped: u64, read: u64| skipped + read >= 8 && skipped > read;
    if mostly_skipped(s.tctx_skipped, s.tctx_read) || mostly_skipped(s.gctx_skipped, s.gctx_read) {
        bail!(
            "most of the records could not be read as jemalloc's ({} thread records skipped, \
             {} read; {} backtraces skipped, {} read): the heap is being rewritten faster \
             than it can be read, or this jemalloc is laid out differently from the ones \
             this tool knows",
            s.tctx_skipped,
            s.tctx_read,
            s.gctx_skipped,
            s.gctx_read
        );
    }
    let mostly = |violated: u64, checked: u64| checked >= 8 && violated * 4 > checked;
    if mostly(s.order_violated, s.order_checked) {
        bail!(
            "the thread records are not in the order jemalloc keeps them in ({} of {} links out \
             of order): this jemalloc is laid out differently from the ones this tool knows",
            s.order_violated,
            s.order_checked
        );
    }
    if mostly(s.counters_violated, s.counters_checked) {
        bail!(
            "the counters of {} of {} thread records cannot be jemalloc's (fewer unbiased than \
             sampled): this jemalloc is laid out differently from the ones this tool knows, or \
             its sampling period was changed while the process ran",
            s.counters_violated,
            s.counters_checked
        );
    }
    Ok(())
}

/// A counter word this large has wrapped below zero: no count is that big.
const WRAPPED: u64 = 1 << 63;

/// One stack's row.
///
/// The counts are the sampled ones jemalloc holds, as a dump with
/// `prof_unbias:false` prints them. Next to each, jemalloc keeps what the
/// sampled objects stand for, summed object by object as they were sampled:
/// `cur_objs_shifted_unbiased / 8` objects and `cur_bytes_unbiased` bytes.
/// Those are the row's estimates, as they are.
///
/// A dump cannot say them: it prints a pair of counts that jeprof's unbiasing
/// turns back into them, made with the sampling period. Here the period is
/// not needed for an estimate at all, so an estimate cannot be wrong for a
/// period that was guessed (a stripped library does not say what its period
/// is); the period is only the label on the snapshot.
fn sample(addrs: &[u64], c: &Counts) -> Sample {
    // The counter is kept times 1 << SC_LG_TINY_MIN, to keep the rounding of
    // each sampled object small.
    let objs = |shifted: u64| shifted.saturating_add(4) / 8;
    // Estimates are stored as BIGINT.
    let est = |v: u64| v.min(i64::MAX as u64);
    // jemalloc takes a freed object's weight off at the period in force then,
    // so after `prof.reset` to another period a counter can pass zero and wrap.
    // No byte or object count is 2^63: such a stack has no estimate of its own,
    // and gets the one the counts give at the snapshot's period.
    let wrapped = c.cur_objs_shifted_unbiased.max(c.cur_bytes_unbiased) >= WRAPPED
        || c.accum_objs_shifted_unbiased.max(c.accum_bytes_unbiased) >= WRAPPED;
    Sample {
        addrs: addrs.to_vec(),
        live_objects: c.cur_objs,
        live_bytes: c.cur_bytes,
        alloc_objects: c.accum_objs,
        alloc_bytes: c.accum_bytes,
        exact_estimates: (!wrapped).then(|| {
            [
                est(c.cur_bytes_unbiased),
                est(objs(c.cur_objs_shifted_unbiased)),
                est(c.accum_bytes_unbiased),
                est(objs(c.accum_objs_shifted_unbiased)),
            ]
        }),
    }
}

/// `lg_prof_sample` from the `MALLOC_CONF` the process started with. A stopgap
/// for a library with no symbols: `mallctl("prof.reset")` can change it later.
fn lg_prof_sample_from_env(process: &Process) -> Option<u32> {
    let environ = process.read_capped("environ", MAX_ENVIRON_BYTES).ok()?;
    environ
        .split(|&b| b == 0)
        .find_map(|kv| kv.strip_prefix(b"MALLOC_CONF="))
        .and_then(|conf| lg_prof_sample_in(&String::from_utf8_lossy(conf)))
}

fn lg_prof_sample_in(conf: &str) -> Option<u32> {
    conf.split(',')
        .filter_map(|opt| opt.split_once(':'))
        .rfind(|(k, _)| k.trim() == "lg_prof_sample")
        .and_then(|(_, v)| v.trim().parse().ok())
        // Zero is a period of one byte: every allocation is sampled.
        .filter(|lg| *lg <= 63)
}

/// The pid the process knows itself by: the innermost one of `NSpid` in
/// `/proc/<pid>/status`, which is `pid` itself outside a pid namespace.
pub(crate) fn own_pid(process: &Process) -> u32 {
    process
        .read_text("status", MAX_STATUS_BYTES)
        .ok()
        .and_then(|status| innermost_pid(&status))
        .unwrap_or(process.pid)
}

fn innermost_pid(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("NSpid:"))
        .and_then(|l| l.split_whitespace().last()?.parse().ok())
}

impl Report {
    /// The same, as the snapshot keeps it and the database has it.
    pub fn live_read(&self) -> LiveRead {
        let s = &self.stats;
        LiveRead {
            found_by: match self.how {
                How::Symbol => "symbol",
                How::Shape => "shape",
            },
            object_path: self.object.clone(),
            sample_period_from: self.sample_period_from.name(),
            walks_redone: s.retries,
            unsteady: s.unsteady,
            backtraces_read: s.gctx_read,
            backtraces_skipped: s.gctx_skipped,
            thread_records_read: s.tctx_read,
            thread_records_skipped: s.tctx_skipped,
            links_checked: s.order_checked,
            links_out_of_order: s.order_violated,
            counters_checked: s.counters_checked,
            counters_off: s.counters_violated,
            reads: self.reads,
            bytes_read: self.bytes,
            duration_ms: u64::try_from(self.millis).unwrap_or(u64::MAX),
        }
    }

    /// What a caller prints about a snoop.
    pub fn summary(&self, pid: u32) -> String {
        let moved =
            self.stats.retries > 0 || self.stats.gctx_skipped > 0 || self.stats.tctx_skipped > 0;
        let mut out = format!(
            "pid {pid}: {} stack(s) read from {} ({}) in {} ms: {} reads, {} KiB; \
             sample period 2^{} from {}",
            self.stacks,
            // A file name is the process owner's to choose.
            locate::shown(&self.object),
            match self.how {
                How::Symbol => "found by symbol",
                How::Shape => "found by shape, no symbols",
            },
            self.millis,
            self.reads,
            self.bytes / 1024,
            self.lg_prof_sample,
            self.sample_period_from.said(),
        );
        if moved {
            out.push_str(&format!(
                "; the heap moved meanwhile ({} retries, {} stacks and {} thread counters skipped)",
                self.stats.retries, self.stats.gctx_skipped, self.stats.tctx_skipped
            ));
        }
        if self.stats.unsteady {
            out.push_str(
                "; the profile table was being changed during every read (jemalloc \
                 rebuilding it, or a busy process), so stacks may be missing: run it again",
            );
        }
        // What the layout checks had to go on, so that a profile they could not
        // judge does not read the same as one they passed.
        let s = &self.stats;
        // A check with fewer than eight records to judge refuses nothing, and
        // says so. (A process where each stack is allocated from by one thread
        // has no links at all, which is a fact about it and not a warning.)
        let judged = |n: u64| if n < 8 { " (too few to judge)" } else { "" };
        out.push_str(&format!(
            "; layout checks: {} of {} links out of order{}, {} of {} counters off{}",
            s.order_violated,
            s.order_checked,
            judged(s.order_checked),
            s.counters_violated,
            s.counters_checked,
            judged(s.counters_checked)
        ));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_layout_that_differs_behind_the_backtrace_is_refused_as_that() {
        let profile = |stats| walk::Profile {
            stacks: vec![],
            stats,
        };
        // Backtraces found, thread records under them all skipped.
        let e = refuse_unusable(&profile(walk::Stats {
            gctx_read: 3,
            tctx_skipped: 3,
            ..Default::default()
        }))
        .unwrap_err();
        assert!(e.to_string().contains("laid out differently"), "{e}");
        // Nothing sampled yet is another thing.
        let e = refuse_unusable(&profile(walk::Stats::default())).unwrap_err();
        assert!(e.to_string().contains("no live sampled allocations"), "{e}");
        // Backtraces with counters, none live: also just nothing to report.
        let e = refuse_unusable(&profile(walk::Stats {
            gctx_read: 3,
            tctx_read: 3,
            ..Default::default()
        }))
        .unwrap_err();
        assert!(e.to_string().contains("no live sampled allocations"), "{e}");
    }

    #[test]
    fn a_share_of_records_that_are_not_jemallocs_is_refused() {
        let profile = |stats| walk::Profile {
            stacks: vec![walk::Stack {
                addrs: vec![1],
                counts: Counts::default(),
            }],
            stats,
        };
        let base = walk::Stats {
            gctx_read: 40,
            tctx_read: 100,
            order_checked: 60,
            counters_checked: 100,
            ..Default::default()
        };
        // A few records out is a busy process.
        let busy = walk::Stats {
            tctx_skipped: 3,
            gctx_skipped: 2,
            order_violated: 3,
            counters_violated: 4,
            ..base.clone()
        };
        assert!(refuse_unusable(&profile(busy)).is_ok());
        for (stats, says) in [
            (
                walk::Stats {
                    tctx_skipped: 150,
                    ..base.clone()
                },
                "most of the records",
            ),
            (
                walk::Stats {
                    gctx_skipped: 60,
                    ..base.clone()
                },
                "most of the records",
            ),
            (
                walk::Stats {
                    order_violated: 30,
                    ..base.clone()
                },
                "not in the order",
            ),
            (
                walk::Stats {
                    counters_violated: 40,
                    ..base.clone()
                },
                "cannot be jemalloc's",
            ),
        ] {
            let e = refuse_unusable(&profile(stats)).unwrap_err();
            assert!(e.to_string().contains(says), "{e}");
        }
        // With too few links to judge by, the vote does not count.
        let few = walk::Stats {
            order_checked: 4,
            order_violated: 4,
            ..base
        };
        assert!(refuse_unusable(&profile(few)).is_ok());
    }

    #[test]
    fn a_small_profile_is_not_refused_on_a_couple_of_skips() {
        let profile = |stats| walk::Profile {
            stacks: vec![walk::Stack {
                addrs: vec![1],
                counts: Counts::default(),
            }],
            stats,
        };
        // Two skipped against one read: a majority, but of three records.
        let few = walk::Stats {
            gctx_read: 1,
            tctx_read: 1,
            tctx_skipped: 2,
            ..Default::default()
        };
        assert!(refuse_unusable(&profile(few)).is_ok());
        // Five against three is a majority of eight.
        let eight = walk::Stats {
            gctx_read: 1,
            tctx_read: 3,
            tctx_skipped: 5,
            ..Default::default()
        };
        assert!(refuse_unusable(&profile(eight)).is_err());
    }

    #[test]
    fn what_is_kept_with_the_snapshot_is_what_the_walk_counted() {
        let report = |stats| Report {
            how: How::Shape,
            object: "/lib/j.so".into(),
            lg_prof_sample: 19,
            sample_period_from: PeriodFrom::Default,
            stacks: 3,
            stats,
            reads: 11,
            bytes: 2048,
            millis: 7,
        };
        let kept = report(walk::Stats {
            retries: 2,
            gctx_read: 5,
            tctx_read: 9,
            order_checked: 4,
            counters_checked: 9,
            ..Default::default()
        })
        .live_read();
        assert_eq!(
            (kept.found_by, kept.sample_period_from, &*kept.object_path),
            ("shape", "default", "/lib/j.so")
        );
        assert_eq!(
            (kept.walks_redone, kept.reads, kept.bytes_read),
            (2, 11, 2048)
        );
        assert_eq!((kept.backtraces_read, kept.thread_records_read), (5, 9));
        assert_eq!((kept.links_checked, kept.counters_checked), (4, 9));
        assert_eq!(kept.duration_ms, 7);
        // A walk done again is not held against the one that was kept.
        assert!(kept.is_clean());

        // Each of the things that can be wrong with a read makes it not clean.
        let not_clean = [
            walk::Stats {
                unsteady: true,
                ..Default::default()
            },
            walk::Stats {
                gctx_skipped: 1,
                ..Default::default()
            },
            walk::Stats {
                tctx_skipped: 1,
                ..Default::default()
            },
            walk::Stats {
                order_violated: 1,
                ..Default::default()
            },
            walk::Stats {
                counters_violated: 1,
                ..Default::default()
            },
        ];
        for stats in not_clean {
            assert!(!report(stats.clone()).live_read().is_clean(), "{stats:?}");
        }
    }

    #[test]
    fn the_summary_says_what_the_layout_checks_had_to_go_on() {
        let report = |order_checked, counters_checked| Report {
            how: How::Symbol,
            object: "/lib/j.so".into(),
            lg_prof_sample: 9,
            sample_period_from: PeriodFrom::Symbols,
            stacks: 3,
            stats: walk::Stats {
                order_checked,
                counters_checked,
                ..Default::default()
            },
            reads: 1,
            bytes: 2048,
            millis: 1,
        };
        // Each check says for itself whether it had enough to judge.
        let few = report(2, 3).summary(7);
        assert!(
            few.contains(
                "0 of 2 links out of order (too few to judge), \
                 0 of 3 counters off (too few to judge)"
            ),
            "{few}"
        );
        // A process where each stack has one thread has no links at all: that
        // is said of the links, and not of the counters.
        let single = report(0, 40).summary(7);
        assert!(
            single.ends_with("0 of 0 links out of order (too few to judge), 0 of 40 counters off"),
            "{single}"
        );
        let both = report(40, 40).summary(7);
        assert!(!both.contains("too few"), "{both}");
    }

    #[test]
    fn a_counter_that_wrapped_gives_its_stack_no_estimate_of_its_own() {
        let normal = Counts {
            cur_objs: 2,
            cur_objs_shifted_unbiased: 40,
            cur_bytes: 2048,
            cur_bytes_unbiased: 5000,
            ..Default::default()
        };
        assert!(sample(&[1], &normal).exact_estimates.is_some());
        // A free after a reset to a longer period took off more than was added.
        for wrapped in [
            Counts {
                cur_bytes_unbiased: u64::MAX - 100,
                ..normal
            },
            Counts {
                cur_objs_shifted_unbiased: 1 << 63,
                ..normal
            },
        ] {
            let s = sample(&[1], &wrapped);
            assert_eq!(s.exact_estimates, None);
            // The raw counts are still there, for the pipeline to scale.
            assert_eq!((s.live_objects, s.live_bytes), (2, 2048));
        }
    }

    #[test]
    fn a_row_holds_the_counts_and_the_estimate_jemalloc_kept() {
        let s = sample(
            &[1, 2],
            &Counts {
                cur_objs: 3,
                cur_objs_shifted_unbiased: 8 * 1500 + 3,
                cur_bytes: 1_000,
                cur_bytes_unbiased: 1_000_000,
                accum_objs: 4,
                accum_objs_shifted_unbiased: 8 * 2000,
                accum_bytes: 2_000,
                accum_bytes_unbiased: 2_000_000,
            },
        );
        assert_eq!((s.live_objects, s.live_bytes), (3, 1_000));
        assert_eq!((s.alloc_objects, s.alloc_bytes), (4, 2_000));
        // Whatever the period, and however wrong a guess of it was, the
        // estimate is not scaled again.
        for period in [1, 512, 1 << 19, 1 << 40] {
            assert_eq!(s.estimates(period), [1_000_000, 1500, 2_000_000, 2000]);
        }
    }

    /// The case that made a dump-style pair unsafe: a stack of a few small
    /// objects, with a period assumed far above the true one. The pair rounds
    /// to zero objects and the estimate is lost; the estimate kept here is not.
    #[test]
    fn a_wrong_period_does_not_lose_a_small_stacks_estimate() {
        // Two sampled 1 KiB objects at a true period of 2 KiB: each stands for
        // 1 / (1 - exp(-0.5)) = 2.54 objects.
        let unbiased = 1.0 / (1.0 - (-0.5f64).exp());
        let s = sample(
            &[1],
            &Counts {
                cur_objs: 2,
                cur_objs_shifted_unbiased: (2.0 * unbiased * 8.0).round() as u64,
                cur_bytes: 2048,
                cur_bytes_unbiased: (2.0 * unbiased * 1024.0).round() as u64,
                ..Default::default()
            },
        );
        let [bytes, objs, ..] = s.estimates(1 << 19);
        assert_eq!(objs, 5);
        assert!(bytes > 5_000 && bytes < 5_300, "{bytes}");
    }

    #[test]
    fn counters_from_a_torn_read_cannot_make_a_row_panic() {
        let s = sample(
            &[1],
            &Counts {
                cur_objs_shifted_unbiased: u64::MAX,
                cur_bytes_unbiased: u64::MAX,
                accum_objs_shifted_unbiased: u64::MAX,
                accum_bytes_unbiased: u64::MAX,
                ..Default::default()
            },
        );
        assert!(s.estimates(512).iter().all(|&v| v <= i64::MAX as u64));
    }

    #[test]
    fn a_process_in_a_container_is_named_by_the_pid_it_sees() {
        let status = "Name:\tapp\nNSpid:\t48213\t311\t7\nPPid:\t1\n";
        assert_eq!(innermost_pid(status), Some(7));
        assert_eq!(innermost_pid("NSpid:\t42\n"), Some(42));
        assert_eq!(innermost_pid("Name:\tapp\n"), None);
        // This process is read from where it is.
        let me = Process::open(std::process::id()).unwrap();
        assert_eq!(own_pid(&me), std::process::id());
    }

    #[test]
    fn a_wait_that_takes_too_long_is_given_up_on() {
        use std::time::Duration;
        let started = std::time::Instant::now();
        let r = run_within(Duration::from_millis(50), || {
            std::thread::sleep(Duration::from_secs(20));
            1
        });
        assert_eq!(r, Err(Wait::TimedOut));
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(run_within(Duration::from_secs(5), || 7), Ok(7));
        let r: Result<u8, Wait> = run_within(Duration::from_secs(5), || panic!("no"));
        assert_eq!(r, Err(Wait::Panicked));
    }

    #[test]
    fn a_file_of_the_process_larger_than_its_cap_is_refused() {
        let me = Process::open(std::process::id()).unwrap();
        assert!(me.read_capped("maps", 64).is_err());
        assert!(me.read_capped("maps", MAX_MAPS_BYTES).is_ok());
    }

    #[test]
    fn the_summary_says_when_the_table_was_changing_and_escapes_the_path() {
        let mut report = Report {
            how: How::Shape,
            object: "/lib/a\x1bb.so".into(),
            lg_prof_sample: 9,
            sample_period_from: PeriodFrom::Symbols,
            stacks: 3,
            stats: walk::Stats::default(),
            reads: 1,
            bytes: 2048,
            millis: 1,
        };
        let plain = report.summary(7);
        assert!(
            !plain.contains('\x1b') && plain.contains("a\\u{1b}b.so"),
            "{plain}"
        );
        assert!(!plain.contains("changed") && !plain.contains("moved"));
        report.stats.unsteady = true;
        assert!(report
            .summary(7)
            .contains("being changed during every read"));
    }

    #[test]
    fn the_period_is_read_from_malloc_conf() {
        assert_eq!(lg_prof_sample_in("prof:true,lg_prof_sample:9"), Some(9));
        assert_eq!(
            lg_prof_sample_in("lg_prof_sample:9,lg_prof_sample:12"),
            Some(12)
        );
        assert_eq!(lg_prof_sample_in("prof:true"), None);
        assert_eq!(lg_prof_sample_in("lg_prof_sample:0"), Some(0));
        assert_eq!(lg_prof_sample_in("lg_prof_sample:99"), None);
        assert_eq!(lg_prof_sample_in("lg_prof_sample:x"), None);
    }
}
