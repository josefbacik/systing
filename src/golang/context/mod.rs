//! `--include-go-context`: the user-space side of the goroutine reader.
//!
//! For each running-stack sample of a Go program the BPF side
//! (`src/golang/bpf/go_context.bpf.h`) reads the goroutine that was running
//! and the id of its profiler label set; a set's labels travel once per
//! process, on a ring of their own. This module is everything else, and none
//! of it runs without the flag, as `task_context`'s is for its own:
//!
//! - [`recipe`] reads a Go program's executable for what the BPF side needs
//!   (where `g` is, and the layout to read it with);
//! - the discovery thread here writes a recipe for every Go program the
//!   capture targets (all of them, without targets) once the programs are
//!   attached, and for a process that execs a Go program while it runs;
//! - [`labels`] turns a label record into rows of the `go_labels` table;
//! - [`start`] and [`Running::finish`] start and stop the two, and print
//!   what each side counted.
//!
//! The rest of the tracer touches the feature where it touches
//! `task_context`: the flag, the read-only configuration and the maps before
//! load, [`start`] once the object is loaded, [`Running::attached`], and
//! [`Running::finish`] when the capture stops.

pub mod labels;
pub mod recipe;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use libbpf_rs::{MapCore, MapFlags, MapHandle, RingBuffer, RingBufferBuilder};

use crate::parquet::{ParquetSink, StreamingParquetWriter};
use crate::task_context::discovery::all_pids;
use crate::utid::UtidGenerator;
use labels::LabelsSink;
use recipe::Finding;

/// The programs loaded only with the flag: they keep a process's recipe from
/// outliving its image.
pub const BPF_PROGRAMS: &[&str] = &["go_context_exec", "go_context_exit"];

/// Every map of the BPF side has a name that starts with this, and none of
/// them is created without the flag.
pub const MAP_PREFIX: &str = "go_context_";

/// Label records one CPU may send a second. A record is 1.6 KiB and is sent
/// when a thread's goroutine or label set changes to one the process has not
/// sent: a program that makes a new set per request sends one per request.
pub const DEFAULT_LABELS_PER_CPU_PER_SEC: u32 = 200;
/// Exec notices one CPU may send a second. Each makes discovery open one
/// executable, or none when it has seen that file before.
pub const DEFAULT_EXECS_PER_CPU_PER_SEC: u32 = 100;

/// The BPF side's counters by name, in the order of `enum go_context_reason`.
/// [`start`] checks the count against the map.
pub const REASONS: [&str; 15] = [
    "same_labels",
    "no_labels",
    "new_labels",
    "labels_sent_before",
    "restricted",
    "no_user_context",
    "tp_implausible",
    "g_read_failed",
    "system_stack",
    "labels_read_failed",
    "labels_cut",
    "rate_limited",
    "ring_full",
    "sent_full",
    "exec_notice_dropped",
];

/// How long the look at every process of the host, once the programs are
/// attached, may take. What it does not reach is counted and still found at
/// its next exec.
const ATTACH_PASS_BUDGET: Duration = Duration::from_secs(2);
/// Exec notices waiting for the discovery thread; one more is dropped and
/// counted.
const EXEC_QUEUE: usize = 1024;

/// What [`start`] needs of the loaded BPF object.
pub struct Maps<'a> {
    pub labels_ring: &'a dyn MapCore,
    pub execs_ring: &'a dyn MapCore,
    pub recipes: MapHandle,
    pub stats: MapHandle,
}

pub struct Options {
    /// The kernel's confidentiality mode is on: the BPF side reads nothing,
    /// and nothing is looked at here either.
    pub restricted: bool,
    /// The processes the capture was pointed at; empty for "every process".
    pub pids: Vec<u32>,
}

/// What discovery found, counted under fixed names. Nothing of a process is
/// printed but its count.
#[derive(Debug, Default, Clone)]
pub struct DiscoveryCounters {
    pub looked: u64,
    pub go_programs: u64,
    pub published: u64,
    /// Go programs this reader cannot read: no bindings for their version,
    /// another architecture, or no load of `g` to go by.
    pub refused: u64,
    pub gone: u64,
    pub map_errors: u64,
    /// The look at every process ran out of time before these.
    pub not_reached: u64,
}

impl DiscoveryCounters {
    pub fn summary(&self) -> String {
        format!(
            "looked={} go_programs={} published={} refused={} gone={} map_errors={} not_reached={}",
            self.looked,
            self.go_programs,
            self.published,
            self.refused,
            self.gone,
            self.map_errors,
            self.not_reached
        )
    }
}

/// Look at process `pid` and write its recipe, or delete the one it had (a
/// process that execs a program that is not Go must not keep the old one).
fn look(recipes: &MapHandle, counters: &mut DiscoveryCounters, pid: u32) {
    counters.looked += 1;
    match recipe::of_executable(std::path::Path::new(&format!("/proc/{pid}/exe"))) {
        Finding::Recipe(recipe) => {
            counters.go_programs += 1;
            if recipes
                .update(&pid.to_ne_bytes(), &recipe.to_bytes(), MapFlags::ANY)
                .is_ok()
            {
                counters.published += 1;
            } else {
                counters.map_errors += 1;
            }
            return;
        }
        Finding::NotGo => {}
        Finding::Refused(_) => {
            counters.go_programs += 1;
            counters.refused += 1;
        }
        Finding::Gone => counters.gone += 1,
    }
    // Absent is the common case; the error says nothing new.
    let _ = recipes.delete(&pid.to_ne_bytes());
}

/// The discovery thread: once the programs are attached (from then on an
/// exec is announced), the capture's targets, or every process of the host
/// within [`ATTACH_PASS_BUDGET`]; then each exec notice as it comes. It ends
/// when the ring that feeds it is dropped.
fn discovery_thread(
    recipes: MapHandle,
    pids: Vec<u32>,
    attached: Receiver<()>,
    execs: Receiver<u32>,
) -> DiscoveryCounters {
    let mut counters = DiscoveryCounters::default();
    if attached.recv().is_err() {
        return counters;
    }
    if pids.is_empty() {
        let started = Instant::now();
        let every = all_pids();
        for (i, pid) in every.iter().enumerate() {
            if started.elapsed() > ATTACH_PASS_BUDGET {
                counters.not_reached = (every.len() - i) as u64;
                break;
            }
            look(&recipes, &mut counters, *pid);
        }
        eprintln!(
            "go_context: looked at {} processes in {} ms, {} Go programs, {} with a recipe, {} not reached",
            counters.looked,
            started.elapsed().as_millis(),
            counters.go_programs,
            counters.published,
            counters.not_reached
        );
    } else {
        for pid in &pids {
            look(&recipes, &mut counters, *pid);
        }
    }
    loop {
        match execs.recv_timeout(Duration::from_secs(1)) {
            Ok(pid) => look(&recipes, &mut counters, pid),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    counters
}

/// The feature while a capture runs.
pub struct Running {
    labels: Option<Arc<Mutex<LabelsSink<StreamingParquetWriter>>>>,
    discovery: Option<thread::JoinHandle<DiscoveryCounters>>,
    stats: MapHandle,
    exec_notices_unqueued: Arc<AtomicU64>,
    attached: Option<SyncSender<()>>,
}

/// What [`start`] hands back: the rings the caller polls (each with the name
/// of its poller thread), and the handle to finish with.
pub struct Started<'a> {
    pub rings: Vec<(String, RingBuffer<'a>)>,
    pub running: Running,
}

/// Start the feature on a loaded object, before its programs are attached.
/// The caller polls the rings it gets back, calls [`Running::attached`] once
/// the programs are attached, and [`Running::finish`] when the capture stops.
pub fn start<'a>(
    maps: Maps<'_>,
    sink: &ParquetSink,
    utids: Arc<UtidGenerator>,
    options: Options,
) -> Result<Started<'a>> {
    if maps.stats.max_entries() as usize != REASONS.len() {
        eprintln!(
            "go_context: the BPF side counts {} reasons and this build names {}: \
             the counters at the end are printed by number",
            maps.stats.max_entries(),
            REASONS.len()
        );
    }
    let exec_notices_unqueued = Arc::new(AtomicU64::new(0));
    if options.restricted {
        eprintln!(
            "go_context: the kernel's confidentiality mode is on: no process is looked at \
             and no goroutine is read"
        );
        return Ok(Started {
            rings: Vec::new(),
            running: Running {
                labels: None,
                discovery: None,
                stats: maps.stats,
                exec_notices_unqueued,
                attached: None,
            },
        });
    }

    // The table's one writer, fed from the labels ring's own poller thread:
    // records are few (one per label set a process sends, within a per-CPU
    // budget), so there is no queue between the ring and the rows.
    let labels = Arc::new(Mutex::new(LabelsSink::new(
        StreamingParquetWriter::for_sink(sink.clone()),
        utids,
    )));
    let labels_for_ring = Arc::clone(&labels);
    let mut builder = RingBufferBuilder::new();
    builder
        .add(maps.labels_ring, move |data: &[u8]| {
            labels_for_ring
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .handle(data);
            0
        })
        .context("go_context: the labels ring")?;
    let labels_ring = builder.build().context("go_context: the labels ring")?;

    let (exec_tx, exec_rx) = sync_channel::<u32>(EXEC_QUEUE);
    let unqueued = Arc::clone(&exec_notices_unqueued);
    let mut builder = RingBufferBuilder::new();
    builder
        .add(maps.execs_ring, move |data: &[u8]| {
            // struct go_context_exec_event: the process id, then a reserved
            // word.
            if let Some(pid) = data.get(0..4) {
                let pid = u32::from_ne_bytes([pid[0], pid[1], pid[2], pid[3]]);
                if exec_tx.try_send(pid).is_err() {
                    unqueued.fetch_add(1, Ordering::Relaxed);
                }
            }
            0
        })
        .context("go_context: the exec ring")?;
    let execs_ring = builder.build().context("go_context: the exec ring")?;

    // The capture's targets are looked at before any program is attached,
    // so that their first samples already carry a goroutine; the thread
    // looks at them again once the programs are attached.
    let mut counters = DiscoveryCounters::default();
    for pid in &options.pids {
        look(&maps.recipes, &mut counters, *pid);
    }
    let (attached_tx, attached_rx) = sync_channel::<()>(1);
    let recipes = maps.recipes;
    let pids = options.pids;
    let discovery = thread::Builder::new()
        .name("go_discovery".to_string())
        .spawn(move || discovery_thread(recipes, pids, attached_rx, exec_rx))
        .context("go_context: the discovery thread")?;

    Ok(Started {
        rings: vec![
            ("rb_go_labels".to_string(), labels_ring),
            ("rb_go_exec".to_string(), execs_ring),
        ],
        running: Running {
            labels: Some(labels),
            discovery: Some(discovery),
            stats: maps.stats,
            exec_notices_unqueued,
            attached: Some(attached_tx),
        },
    })
}

/// One of the BPF side's counters, summed over the CPUs.
fn reason_count(stats: &MapHandle, reason: u32) -> u64 {
    let Ok(Some(per_cpu)) = stats.lookup_percpu(&reason.to_ne_bytes(), MapFlags::ANY) else {
        return 0;
    };
    per_cpu
        .iter()
        .filter_map(|bytes| bytes.get(0..8))
        .map(|bytes| u64::from_ne_bytes(bytes.try_into().unwrap()))
        .sum()
}

impl Running {
    /// The programs are attached: from here on an exec is announced, so this
    /// is when the discovery thread starts looking. Call it once, right after
    /// the attach.
    pub fn attached(&self) {
        if let Some(attached) = &self.attached {
            let _ = attached.try_send(());
        }
    }

    /// Stop the feature. Called once the pollers of the rings [`start`]
    /// returned have been joined and the rings dropped: that is what ends
    /// the discovery thread and leaves this the table's only owner.
    pub fn finish(mut self) -> Result<()> {
        drop(self.attached.take());
        let named = self.stats.max_entries() as usize == REASONS.len();
        let samples = (0..self.stats.max_entries())
            .map(|reason| {
                let name = REASONS
                    .get(reason as usize)
                    .filter(|_| named)
                    .map_or_else(|| format!("reason_{reason}"), |name| name.to_string());
                (name, reason_count(&self.stats, reason))
            })
            .filter(|(_, count)| *count > 0)
            .map(|(name, count)| format!("{name}={count}"))
            .collect::<Vec<_>>()
            .join(" ");
        println!("go_context samples: {samples}");

        if let Some(discovery) = self.discovery {
            match discovery.join() {
                Ok(counters) => println!("go_context discovery: {}", counters.summary()),
                Err(_) => eprintln!("go_context: the discovery thread panicked"),
            }
        }
        let unqueued = self.exec_notices_unqueued.load(Ordering::Relaxed);
        if unqueued > 0 {
            println!("go_context discovery: exec_notices_unqueued={unqueued}");
        }

        if let Some(labels) = self.labels {
            match Arc::try_unwrap(labels) {
                Ok(sink) => {
                    let counters = sink
                        .into_inner()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .finish()
                        .context("go_context: closing the go_labels table")?;
                    println!("go_context labels: {}", counters.summary());
                }
                Err(_) => eprintln!(
                    "go_context: the labels ring is still open; its table is closed when the ring is"
                ),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_reason_is_named_once() {
        let mut names = REASONS.to_vec();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), REASONS.len());
    }
}
