//! Reads allocator heap snapshots into a systing DuckDB database.
//!
//! A heap snapshot is the allocator's own dump of the memory a process had
//! live when it wrote the file: one allocation stack per entry, with the
//! objects and bytes still allocated from it. This is not a stream of
//! malloc/free calls (that is systing's `memory-alloc` recorder); a snapshot
//! is what the allocator itself sampled and aggregated.
//!
//! The pipeline is parse ([`jemalloc`]), symbolize ([`symbolize`], offline,
//! through the memory map each dump carries) and write ([`db`]), into the
//! same `frame` / `stack` tables every systing recorder uses plus
//! `heap_snapshot` / `heap_sample`.

pub mod db;
pub mod format;
pub mod jemalloc;
pub mod maps;
pub mod perfetto;
pub mod perfmap;
pub mod retention;
pub mod root;
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
    }
}
