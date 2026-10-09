//! `--snoop` of a Go program: its heap profile, read out of its memory by
//! `systing::golang`, as a snapshot. Go keeps the profile itself (it samples
//! every `runtime.MemProfileRate` bytes), so this is what `pprof.Lookup("heap")`
//! would write at the same moment, with no pprof port.

use anyhow::{bail, Result};
use systing::golang::{self, GoProcess, ReadStats};

use crate::maps::Maps;
use crate::snoop::Process;
use crate::{Format, LiveRead, Sample, Snapshot};

/// The value `Snapshot::trigger` has for a heap read this way.
pub const TRIGGER: &str = "go-snoop";

/// Whether the process runs a Go program.
pub fn is_go(process: &Process) -> bool {
    golang::is_go(&process.file("exe"))
}

/// Read the process's heap profile; also returns a line saying how.
pub fn read(process: &Process) -> Result<(Snapshot, String)> {
    let pid = process.pid();
    let go = GoProcess::open(pid, &process.file(""))?;
    let mut stats = ReadStats::default();
    let heap = go.heap(&mut stats)?;
    if heap.records.is_empty() {
        bail!("the program has no sampled allocations to report yet");
    }
    let samples = heap
        .records
        .iter()
        .map(|r| {
            let [ao, ab, lo, lb] = r.scaled(heap.rate);
            Sample {
                addrs: r.pcs.clone(),
                live_objects: r.live_objects,
                live_bytes: r.live_bytes,
                alloc_objects: r.alloc_objects,
                alloc_bytes: r.alloc_bytes,
                exact_estimates: Some([lb, lo, ab, ao]),
            }
        })
        .collect();
    let snapshot = Snapshot {
        format: Format::Pprof,
        source_path: format!("/proc/{pid}/mem").into(),
        pid: i32::try_from(pid).ok(),
        seq: None,
        trigger: Some(TRIGGER),
        dumped_at_unix_ns: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_nanos()).ok()),
        owner_uid: process.owner().map(|(uid, _)| uid),
        sample_period: u64::try_from(heap.rate).unwrap_or(0),
        samples,
        maps: Maps::parse(&process.maps_text()?),
        perf_map: None,
        py_code: None,
        live_read: Some(LiveRead {
            found_by: go.found_by.name(),
            object_path: go.exe.clone(),
            sample_period_from: "symbols",
            walks_redone: 0,
            unsteady: false,
            backtraces_read: stats.records,
            backtraces_skipped: stats.skipped,
            thread_records_read: 0,
            thread_records_skipped: 0,
            links_checked: 0,
            links_out_of_order: 0,
            counters_checked: 0,
            counters_off: 0,
            reads: stats.reads,
            bytes_read: stats.bytes,
            duration_ms: (stats.micros / 1000) as u64,
        }),
        named_frames: None,
    };
    let summary = format!(
        "pid {pid}: {} ({}), globals found by {}: read {} heap stacks ({} skipped) in {} us, \
         {} reads, {} bytes",
        go.exe,
        go.version,
        go.found_by.name(),
        stats.records,
        stats.skipped,
        stats.micros,
        stats.reads,
        stats.bytes
    );
    Ok((snapshot, summary))
}
