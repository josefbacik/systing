//! Reads allocator heap snapshots into a systing DuckDB database.
//!
//! A heap snapshot is the allocator's own dump of the memory a process had
//! live when it wrote the file: one allocation stack per entry, with the
//! objects and bytes still allocated from it. This is not a stream of
//! malloc/free calls (that is systing's `memory-alloc` recorder); a snapshot
//! is what the allocator itself sampled and aggregated.
//!
//! The pipeline is parse ([`jemalloc`], or Go's own heap profile: a [`pprof`]
//! file, or [`golang`] from memory), symbolize ([`symbolize`], offline,
//! through the memory map each dump carries) and write ([`db`]), into the
//! same `frame` / `stack` tables every systing recorder uses plus
//! `heap_snapshot` / `heap_sample`.

pub mod ask;
pub mod check;
pub mod db;
pub mod format;
pub mod golang;
#[cfg(test)]
mod hook_offsets;
pub mod jemalloc;
pub mod maps;
pub mod perfetto;
pub mod perfmap;
pub mod pprof;
pub mod pycode;
pub mod retention;
pub mod root;
pub mod snoop;
pub mod symbolize;

use std::path::PathBuf;

pub use format::Format;
use maps::Maps;

/// One heap snapshot file, parsed.
#[derive(Debug)]
pub struct Snapshot {
    pub format: Format,
    pub source_path: PathBuf,
    /// The process that wrote it, when the file name says.
    pub pid: Option<i32>,
    /// The allocator's dump sequence number, when the file name has one.
    pub seq: Option<u64>,
    /// Why the allocator dumped (jemalloc: `interval`, `manual`, `gdump`,
    /// `final`).
    pub trigger: Option<&'static str>,
    pub dumped_at_unix_ns: Option<i64>,
    /// The user who owns the dump file, when it was found under a prefix.
    pub owner_uid: Option<u32>,
    /// Mean bytes between samples, as the dump states it.
    pub sample_period: u64,
    pub samples: Vec<Sample>,
    /// The process's memory map as of the dump, for symbolization.
    pub maps: Maps,
    /// The process's perf map (`perf-<pid>.map`), naming code it generated
    /// at runtime such as Python's perf trampolines; None if not found.
    pub perf_map: Option<std::sync::Arc<perfmap::PerfMap>>,
    /// The process's code map (`pycode-<pid>-<token>.map`), naming the
    /// Python frames the hooks' "python" backtrace stored; None if not
    /// found.
    pub py_code: Option<std::sync::Arc<pycode::CodeMap>>,
    /// How the read went, for a snapshot read out of a running process
    /// (`--snoop`); None for a dump, which the allocator wrote under its own
    /// locks.
    pub live_read: Option<LiveRead>,
    /// Frame names for each sample, root (outermost) first, for a source
    /// that names its own frames (a pprof file): used as they are, instead
    /// of symbolizing `addrs`.
    pub named_frames: Option<Vec<Vec<String>>>,
}

/// How reading a snapshot out of a running process's memory went
/// ([`snoop`]). The process runs meanwhile and nothing of it is locked, so
/// records that changed under the read are skipped and a walk the table
/// changed under is done again; and the layout is judged by what was read.
/// These are the counts, kept with the snapshot (`heap_live_read`) so that a
/// reader of the database can tell a clean read from one that was not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveRead {
    /// How the profile was found: `symbol` or `shape`.
    pub found_by: &'static str,
    /// The file it was found in, as the process maps it.
    pub object_path: String,
    /// Where the sample period is from: `symbols`, `malloc_conf`, or
    /// `default`, which is a guess.
    pub sample_period_from: &'static str,
    /// Walks done again.
    pub walks_redone: u32,
    /// The profile was changing during every walk: stacks may be missing.
    pub unsteady: bool,
    pub backtraces_read: u64,
    pub backtraces_skipped: u64,
    pub thread_records_read: u64,
    pub thread_records_skipped: u64,
    /// Parent and child thread records compared for jemalloc's order, and
    /// those out of it.
    pub links_checked: u64,
    pub links_out_of_order: u64,
    /// Thread records whose counters were compared with each other, and
    /// those that cannot be jemalloc's.
    pub counters_checked: u64,
    pub counters_off: u64,
    /// Reads of the process's memory, and the bytes read.
    pub reads: u64,
    pub bytes_read: u64,
    pub duration_ms: u64,
}

impl LiveRead {
    /// Nothing was skipped, nothing was out of place, and the profile held
    /// still for the walk that was kept. A walk done again is not held
    /// against it: the one kept is what is judged.
    pub fn is_clean(&self) -> bool {
        !self.unsteady
            && self.backtraces_skipped == 0
            && self.thread_records_skipped == 0
            && self.links_out_of_order == 0
            && self.counters_off == 0
    }
}

/// One allocation stack and what is allocated from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sample {
    /// Return addresses, leaf (innermost) first, as the allocator wrote them.
    pub addrs: Vec<u64>,
    pub live_objects: u64,
    pub live_bytes: u64,
    /// Cumulative since start; 0 unless the allocator tracked them.
    pub alloc_objects: u64,
    pub alloc_bytes: u64,
    /// The allocator's own estimate for this stack (live bytes, live
    /// objects, alloc bytes, alloc objects), for a source that has one:
    /// [`Sample::estimates`] gives it as it is. A dump has none, and its
    /// counts are scaled at the sample period instead.
    pub exact_estimates: Option<[u64; 4]>,
}

impl Sample {
    /// Estimated (live bytes, live objects, alloc bytes, alloc objects) in
    /// the process, from this stack's sampled counts at `sample_period`.
    ///
    /// jemalloc samples an allocation of `s` bytes with probability
    /// `1 - exp(-s / sample_period)`, so each pair is divided by that
    /// probability at the stack's mean object size, as jeprof does. This is
    /// per stack: summing stacks first and scaling the sum under-counts small
    /// objects badly (jemalloc's PROFILING_INTERNALS.md, "Aggregation must be
    /// done after unbiasing samples"). jemalloc 5.3 writes each stack's pair
    /// so that this per-stack step gives its own estimate.
    pub fn estimates(&self, sample_period: u64) -> [u64; 4] {
        if let Some(exact) = self.exact_estimates {
            return exact;
        }
        let (live_bytes, live_objects) = unbias(self.live_bytes, self.live_objects, sample_period);
        let (alloc_bytes, alloc_objects) =
            unbias(self.alloc_bytes, self.alloc_objects, sample_period);
        [live_bytes, live_objects, alloc_bytes, alloc_objects]
    }
}

/// One (bytes, objects) pair, unbiased at its mean object size.
fn unbias(bytes: u64, objects: u64, sample_period: u64) -> (u64, u64) {
    if objects == 0 || sample_period == 0 {
        return (bytes, objects);
    }
    let mean = bytes as f64 / objects as f64;
    let scale = 1.0 / (1.0 - (-mean / sample_period as f64).exp());
    // Only a malformed dump gets here (objects but no bytes, or a period too
    // large for mean / period to register): there is no estimate to make.
    if !scale.is_finite() {
        return (bytes, objects);
    }
    // Estimates are stored as BIGINT: the cast to i64 saturates there.
    let clamp = |v: f64| (v.round() as i64).max(0) as u64;
    (clamp(bytes as f64 * scale), clamp(objects as f64 * scale))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_objects_scale_up_far_more_than_large_ones() {
        let sample = |bytes, objects| Sample {
            addrs: vec![],
            live_objects: objects,
            live_bytes: bytes,
            alloc_objects: 0,
            alloc_bytes: 0,
            exact_estimates: None,
        };
        // 256-byte objects at a 16 KiB period: each is sampled with
        // probability about 1/64.5.
        let [b, n, _, _] = sample(256, 1).estimates(16384);
        assert_eq!((b, n), (16512, 65));
        // 64 KiB objects are nearly always sampled.
        let [b, _, _, _] = sample(65536, 1).estimates(16384);
        assert_eq!(b, 66759);
        // Nothing sampled stays nothing.
        assert_eq!(sample(0, 0).estimates(16384), [0, 0, 0, 0]);
        // A malformed row keeps its counts rather than turning infinite.
        assert_eq!(sample(0, 3).estimates(16384), [0, 3, 0, 0]);
        assert_eq!(sample(1, 1).estimates(u64::MAX), [1, 1, 0, 0]);
        let [b, n, _, _] = sample(u64::MAX, 1 << 40).estimates(1);
        assert!(b <= i64::MAX as u64 && n <= i64::MAX as u64);
        // An allocator's own estimate is not scaled again, whatever the period.
        let exact = Sample {
            exact_estimates: Some([7, 6, 5, 4]),
            ..sample(256, 1)
        };
        assert_eq!(exact.estimates(16384), [7, 6, 5, 4]);
        assert_eq!(exact.estimates(1), [7, 6, 5, 4]);
    }
}
