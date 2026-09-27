//! **Experimental.** Read a running process's jemalloc heap profile straight
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
use crate::{Format, Sample, Snapshot};

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

/// What a snoop found, besides the snapshot: how, for the caller to say.
#[derive(Debug)]
pub struct Report {
    pub how: How,
    pub object: String,
    pub lg_prof_sample: u32,
    /// Where `lg_prof_sample` came from.
    pub sample_period_from: &'static str,
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
    fn file(&self, name: &str) -> PathBuf {
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
    fn read_capped(&self, name: &str, cap: u64) -> Result<Vec<u8>> {
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
enum Wait {
    TimedOut,
    Panicked,
}

/// Run `f` on a thread and wait for it, no longer than `limit`.
fn run_within<T: Send + 'static>(
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
            "opening /proc/{pid}/mem: reading a process's memory needs the same user or root, \
             and kernel.yama.ptrace_scope permitting it"
        )
    })?;
    let maps_text = process.read_text("maps", MAX_MAPS_BYTES)?;
    let found = locate::locate(&mem, &Maps::parse(&maps_text), root)?;
    let profile = walk::walk(&mem, found.bt2gctx).with_context(|| {
        format!(
            "reading the profile at {:#x} in {}",
            found.bt2gctx, found.object
        )
    })?;
    if profile.stacks.is_empty() {
        bail!("the process has no live sampled allocations to report yet");
    }
    if profile.stats.tctx_read == 0 {
        bail!(
            "found backtraces but no per-thread counters under them: \
             this jemalloc is laid out differently from the ones this tool knows"
        );
    }
    // The mappings as of the end, so a library loaded meanwhile is named.
    let maps = Maps::parse(&process.read_text("maps", MAX_MAPS_BYTES)?);

    let (lg, from) = match found.lg_prof_sample {
        Some(lg) => (lg, "the library's symbols"),
        None => match lg_prof_sample_from_env(process) {
            Some(lg) => (lg, "the process's MALLOC_CONF"),
            None => (DEFAULT_LG_PROF_SAMPLE, "jemalloc's default"),
        },
    };
    let samples: Vec<Sample> = profile
        .stacks
        .iter()
        .map(|s| sample(&s.addrs, &s.counts, lg))
        .collect();

    let (reads, bytes) = mem.traffic();
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
    };
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
    Ok((snapshot, report))
}

/// One stack's row, the one a dump of the same heap would hold.
///
/// jemalloc keeps, next to each raw count, what the sampled objects stand for,
/// summed object by object as they were sampled: `cur_objs_shifted_unbiased / 8`
/// objects and `cur_bytes_unbiased` bytes. A dump does not print those. It
/// prints the pair of counts that jeprof's unbiasing (what [`Sample::estimates`]
/// does) turns back into them, and this makes the same pair, as jemalloc's
/// `prof_do_unbias` does. So the row is the dump's row, and the estimate that
/// comes of it is jemalloc's own to within a rounding: the same one a dump has.
///
/// The period is used to make the pair and again to take it apart, so a wrong
/// period changes the counts shown but hardly the estimate.
fn sample(addrs: &[u64], c: &Counts, lg_prof_sample: u32) -> Sample {
    let (live_objects, live_bytes) = unbias_pair(
        c.cur_objs_shifted_unbiased,
        c.cur_bytes_unbiased,
        lg_prof_sample,
    );
    let (alloc_objects, alloc_bytes) = unbias_pair(
        c.accum_objs_shifted_unbiased,
        c.accum_bytes_unbiased,
        lg_prof_sample,
    );
    Sample {
        addrs: addrs.to_vec(),
        live_objects,
        live_bytes,
        alloc_objects,
        alloc_bytes,
    }
}

/// jemalloc's `prof_do_unbias`: from an unbiased object count (kept times
/// `1 << SC_LG_TINY_MIN`, that is 8) and byte count, the counts a dump prints.
fn unbias_pair(objs_shifted: u64, bytes: u64, lg_prof_sample: u32) -> (u64, u64) {
    if objs_shifted == 0 || bytes == 0 {
        return (0, 0);
    }
    let c_out = objs_shifted as f64 / 8.0;
    let s_out = bytes as f64;
    let r = (1u64 << lg_prof_sample) as f64;
    let x = s_out / c_out;
    let y = s_out * (1.0 - (-x / r).exp());
    // C's round() (half away from zero), then a saturating conversion.
    (((y / x).round()) as u64, y.round() as u64)
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
fn own_pid(process: &Process) -> u32 {
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

/// What a caller prints about a snoop.
impl Report {
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
            self.sample_period_from,
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
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pair made for a stack comes back out of `Sample::estimates` as the
    /// unbiased estimate jemalloc kept, to within the rounding of the integers
    /// a dump has, for any period and mix of sizes.
    #[test]
    fn a_rows_estimate_is_the_estimate_jemalloc_kept() {
        for lg in [9, 12, 14, 19] {
            for (objs, bytes) in [(1500u64, 1_000_000u64), (3, 3 * 65536), (40_000, 9_000_000)] {
                let s = sample(
                    &[1],
                    &Counts {
                        cur_objs_shifted_unbiased: objs * 8,
                        cur_bytes_unbiased: bytes,
                        ..Default::default()
                    },
                    lg,
                );
                let [b, n, ab, an] = s.estimates(1 << lg);
                // The pair is made of integers, so half a count in c_in is
                // the resolution: coarser for a stack of fewer sampled objects.
                let tolerance = 1.0 / s.live_objects as f64 + 0.001;
                let close = |got: u64, want: u64| {
                    got.abs_diff(want) as f64 <= want as f64 * tolerance + 1.0
                };
                assert!(close(b, bytes), "lg {lg}: {b} bytes, want {bytes}");
                assert!(close(n, objs), "lg {lg}: {n} objects, want {objs}");
                assert_eq!((ab, an), (0, 0));
            }
        }
    }

    /// A stack of one sampled object of any size is one object of about its
    /// size again (jemalloc rounds each object's unbiased count to an integer,
    /// so about): a stack with one large object is not lost to the encoding.
    #[test]
    fn one_sampled_object_comes_out_as_one_object_of_its_size() {
        let r = 524_288.0f64;
        for size in [64.0f64, 4096.0, 65536.0, 1_048_576.0] {
            let objs = 1.0 / (1.0 - (-size / r).exp());
            let s = sample(
                &[1],
                &Counts {
                    cur_objs_shifted_unbiased: (objs * 8.0).round() as u64,
                    cur_bytes_unbiased: (objs * size).round() as u64,
                    ..Default::default()
                },
                19,
            );
            assert_eq!(s.live_objects, 1, "size {size}");
            assert!(
                (s.live_bytes as f64 - size).abs() <= size * 0.05,
                "size {size}: {} bytes",
                s.live_bytes
            );
        }
    }

    #[test]
    fn nothing_counted_is_a_row_of_zeros() {
        assert_eq!(unbias_pair(0, 100, 12), (0, 0));
        assert_eq!(unbias_pair(80, 0, 12), (0, 0));
    }

    #[test]
    fn counters_from_a_torn_read_cannot_make_a_row_panic() {
        // Absurd counters from a half-updated structure: no panic.
        let _ = unbias_pair(u64::MAX, 1, 12);
        let _ = unbias_pair(1, u64::MAX, 63);
        let _ = unbias_pair(1, 1, 1);
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
            sample_period_from: "x",
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
