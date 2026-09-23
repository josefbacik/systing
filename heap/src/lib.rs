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
pub mod perfmap;
pub mod retention;
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
    /// Mean bytes between samples, as the dump states it.
    pub sample_period: u64,
    /// The dump's header totals, as written: not always the sum of
    /// `samples` (jemalloc 5.3 interval dumps disagree).
    pub header_live_objects: u64,
    pub header_live_bytes: u64,
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
