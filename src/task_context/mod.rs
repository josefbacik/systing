//! `--include-task-context`: the user-space side of the task_context reader.
//!
//! A program that links the writer library (`crates/task-context`) can
//! attach a few named values to each of its threads. With this flag the BPF
//! side (`bpf/task_context_reader.bpf.h`) reads, for every running-stack
//! sample, the 8-byte id of the sampled thread's current context and stores
//! it in the sample; the values themselves travel once per id on a ring of
//! their own. This module is everything else, and none of it runs without
//! the flag:
//!
//! - [`discovery`] finds the processes that publish a recipe, validates it
//!   and writes it into the BPF map the sampler looks up;
//! - [`values`] turns a value record into rows of the `task_context` table;
//! - this file starts and stops the two, and prints what each side counted.
//!
//! The rest of the tracer touches the feature in four places only: the flag,
//! the read-only configuration and map set-up before load, [`start`] once
//! the object is loaded, and [`Running::finish`] when the capture stops.

pub mod discovery;
pub mod values;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use libbpf_rs::{MapCore, MapFlags, MapHandle, RingBuffer, RingBufferBuilder};

use crate::parquet::{ParquetSink, StreamingParquetWriter};
use crate::utid::UtidGenerator;
use discovery::{all_pids, Discovery, DiscoveryCounters, Finding, Recipe};
use values::ValuesSink;

/// The programs of the BPF side that are loaded only with the flag: they
/// keep a process's recipe from outliving its image.
pub const BPF_PROGRAMS: &[&str] = &[
    "task_context_exec",
    "task_context_fork",
    "task_context_exit",
];

/// Every map of the BPF side has a name that starts with this, and none of
/// them is created without the flag.
pub const MAP_PREFIX: &str = "task_context_";

/// Value records one CPU may send a second. A record is 2.4 KiB and is sent
/// when a sample first sees a new id, so this bounds what a thread that
/// changes its context in a tight loop can make the tracer copy.
pub const DEFAULT_VALUES_PER_CPU_PER_SEC: u32 = 200;
/// Exec notices one CPU may send a second. Each makes discovery open one
/// file, or none when it has seen that file before.
pub const DEFAULT_EXECS_PER_CPU_PER_SEC: u32 = 100;

/// The BPF side's counters by name, in the order of
/// `enum task_context_reason`. [`start`] checks the count against the map.
pub const REASONS: [&str; 20] = [
    "same_id",
    "new_id",
    "restricted",
    "not_current",
    "no_user_context",
    "unsupported_arch",
    "tp_implausible",
    "slot_read_failed",
    "unset",
    "empty",
    "out_of_range",
    "block_read_failed",
    "bad_header",
    "in_progress",
    "torn",
    "rate_limited",
    "ring_full",
    "cache_refused",
    "exec_notice_dropped",
    "recipes_full",
];

/// The longest the pass over every process at the start of a capture may
/// take. What it does not reach is counted (`not_reached`) and is still
/// found at its next exec.
const ATTACH_PASS_BUDGET: Duration = Duration::from_secs(2);
/// An exec is announced before the loader has mapped the program's
/// libraries and before the writer library's constructor has run, so a
/// process that links the library is looked at again after these waits.
const EXEC_RETRY_MS: [u64; 3] = [10, 30, 60];
/// How often the processes still waiting after that are looked at again.
const LOOK_AGAIN_EVERY: Duration = Duration::from_secs(1);
/// Exec notices waiting for the discovery thread; one more is dropped and
/// counted.
const EXEC_QUEUE: usize = 1024;

/// What [`start`] needs of the loaded BPF object.
pub struct Maps<'a> {
    pub values_ring: &'a dyn MapCore,
    pub execs_ring: &'a dyn MapCore,
    pub recipes: MapHandle,
    pub stats: MapHandle,
}

pub struct Options {
    /// The kernel's confidentiality mode is on: the BPF side reads nothing
    /// of any process, and nothing is looked for here either.
    pub restricted: bool,
    /// The processes the capture was pointed at; empty for "every process".
    pub pids: Vec<u32>,
    /// Testing only (`Config::task_context_planted_recipes`): recipes written
    /// to the map as given, with none of discovery's validation.
    pub planted_recipes: Vec<(u32, [u64; 3])>,
}

/// What [`start`] does with a capture's options, decided in one place so
/// that one test can hold it.
#[derive(Debug, PartialEq, Eq)]
enum Plan {
    /// The kernel's confidentiality mode: no ring is polled, no process is
    /// looked at, no thread is started.
    Inert,
    /// `first`: the processes looked at before the programs attach (so that
    /// their first samples carry an id) and again once they have (an exec in
    /// between would otherwise leave the old image's recipe standing).
    /// `walk`: then every process of the host, once.
    Live { first: Vec<u32>, walk: bool },
}

fn plan(options: &Options) -> Plan {
    if options.restricted {
        return Plan::Inert;
    }
    Plan::Live {
        first: options.pids.clone(),
        walk: options.pids.is_empty(),
    }
}

/// The feature while a capture runs.
pub struct Running {
    values: Option<Arc<Mutex<ValuesSink<StreamingParquetWriter>>>>,
    discovery: Option<thread::JoinHandle<DiscoveryCounters>>,
    stats: MapHandle,
    exec_notices_unqueued: Arc<AtomicU64>,
    attached: Option<SyncSender<()>>,
}

/// What [`start`] hands back: the rings the caller polls (each with the
/// name of its poller thread), and the handle to finish with.
pub struct Started<'a> {
    pub rings: Vec<(String, RingBuffer<'a>)>,
    pub running: Running,
}

/// Processes that link the library and had not published a recipe when they
/// were last looked at. Bounded both ways: in how many it holds and in how
/// often each is looked at, so that a process which never publishes is not
/// read for ever.
#[derive(Debug, Default)]
struct LookAgain {
    /// (process, looks so far)
    waiting: Vec<(u32, u32)>,
}

impl LookAgain {
    const MAX_WAITING: usize = 256;
    const MAX_LOOKS: u32 = 30;

    /// Returns false, and takes nothing, when the list is full.
    fn add(&mut self, pid: u32) -> bool {
        if self.waiting.iter().any(|(waiting, _)| *waiting == pid) {
            return true;
        }
        if self.waiting.len() >= Self::MAX_WAITING {
            return false;
        }
        self.waiting.push((pid, 0));
        true
    }

    /// Look at every waiting process once. A process leaves the list when
    /// it publishes (`publish` is called), when it turns out not to link the
    /// library after all, when it is refused or gone, or when it has been
    /// looked at `MAX_LOOKS` times; the last are counted and returned.
    fn tick(
        &mut self,
        mut look: impl FnMut(u32) -> Finding,
        mut publish: impl FnMut(u32, Recipe),
    ) -> u64 {
        let mut gave_up = 0;
        self.waiting.retain_mut(|(pid, looks)| match look(*pid) {
            Finding::Published(recipe) => {
                publish(*pid, recipe);
                false
            }
            Finding::NotYet => {
                *looks += 1;
                if *looks >= Self::MAX_LOOKS {
                    gave_up += 1;
                    false
                } else {
                    true
                }
            }
            Finding::NotLinked | Finding::Refused(_) | Finding::Gone => false,
        });
        gave_up
    }
}

/// Write a process's recipe where the BPF side looks it up.
fn publish(recipes: &MapHandle, counters: &mut DiscoveryCounters, pid: u32, recipe: Recipe) {
    if recipes
        .update(&pid.to_ne_bytes(), &recipe.to_bytes(), MapFlags::ANY)
        .is_err()
    {
        counters.map_errors += 1;
    }
}

/// A process has a new image. The BPF side dropped its recipe at the exec;
/// this looks at the new image, and whatever it finds, a recipe this thread
/// may have written for the OLD image in the meantime does not survive it.
fn handle_exec(
    discovery: &mut Discovery,
    recipes: &MapHandle,
    look_again: &mut LookAgain,
    pid: u32,
) {
    let mut finding = discovery.look(pid);
    for wait in EXEC_RETRY_MS {
        if finding != Finding::NotYet {
            break;
        }
        thread::sleep(Duration::from_millis(wait));
        finding = discovery.look(pid);
    }
    match finding {
        Finding::Published(recipe) => publish(recipes, &mut discovery.counters, pid, recipe),
        other => {
            // Absent is the common case; the error says nothing new.
            let _ = recipes.delete(&pid.to_ne_bytes());
            if other == Finding::NotYet && !look_again.add(pid) {
                discovery.counters.gave_up += 1;
            }
        }
    }
}

/// Look at the processes the capture was pointed at. Run twice: before the
/// programs attach, and again right after, when whatever it finds replaces
/// what the first run wrote (a process that took a new image in between has
/// no exec notice to say so).
fn look_at_targets(
    discovery: &mut Discovery,
    recipes: &MapHandle,
    look_again: &mut LookAgain,
    pids: &[u32],
    again: bool,
) {
    for &pid in pids {
        match discovery.look(pid) {
            Finding::Published(recipe) => publish(recipes, &mut discovery.counters, pid, recipe),
            other => {
                if again {
                    let _ = recipes.delete(&pid.to_ne_bytes());
                }
                if other == Finding::NotYet && !look_again.add(pid) {
                    discovery.counters.gave_up += 1;
                }
            }
        }
    }
}

/// What the discovery thread starts with.
struct DiscoveryJob {
    discovery: Discovery,
    recipes: MapHandle,
    look_again: LookAgain,
    /// The capture's targets, already looked at once.
    first: Vec<u32>,
    /// No targets: look at every process of the host, once.
    walk: bool,
    /// Testing only: recipes to write as given once everything above has
    /// had its say, so that nothing but the BPF side's own checks stands
    /// between a wrong recipe and the process it was planted on.
    planted: Vec<(u32, [u64; 3])>,
}

/// The discovery thread. It waits until the caller says the programs are
/// attached (from then on an exec is announced), looks at the capture's
/// targets once more, or at every process when there are none, then serves
/// exec notices as they come and the waiting processes once a second. It
/// ends when the ring that feeds it is dropped.
fn discovery_thread(
    job: DiscoveryJob,
    attached: Receiver<()>,
    execs: Receiver<u32>,
) -> DiscoveryCounters {
    let DiscoveryJob {
        mut discovery,
        recipes,
        mut look_again,
        first,
        walk,
        planted,
    } = job;
    // A capture that fails before it attaches drops its sender: nothing to
    // look for. No time limit: loading and attaching can take tens of
    // seconds on a slow machine.
    if attached.recv().is_err() {
        return discovery.counters;
    }
    look_at_targets(&mut discovery, &recipes, &mut look_again, &first, true);
    if walk {
        let pass = discovery.pass(&all_pids(), ATTACH_PASS_BUDGET);
        for (pid, recipe) in &pass.published {
            publish(&recipes, &mut discovery.counters, *pid, *recipe);
        }
        for pid in &pass.not_yet {
            if !look_again.add(*pid) {
                discovery.counters.gave_up += 1;
            }
        }
        eprintln!(
            "task_context: looked at {} processes in {} ms, {} publish a recipe, {} not yet, {} not reached",
            pass.looked,
            pass.elapsed.as_millis(),
            pass.published.len(),
            pass.not_yet.len(),
            pass.not_reached
        );
    }
    for (pid, words) in &planted {
        let mut bytes = [0u8; 24];
        for (at, word) in words.iter().enumerate() {
            bytes[at * 8..at * 8 + 8].copy_from_slice(&word.to_ne_bytes());
        }
        if recipes
            .update(&pid.to_ne_bytes(), &bytes, MapFlags::ANY)
            .is_err()
        {
            discovery.counters.map_errors += 1;
        }
    }
    loop {
        match execs.recv_timeout(LOOK_AGAIN_EVERY) {
            Ok(pid) => handle_exec(&mut discovery, &recipes, &mut look_again, pid),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        if !look_again.waiting.is_empty() {
            let mut found = Vec::new();
            let gave_up = look_again.tick(
                |pid| discovery.look(pid),
                |pid, recipe| found.push((pid, recipe)),
            );
            discovery.counters.gave_up += gave_up;
            for (pid, recipe) in found {
                publish(&recipes, &mut discovery.counters, pid, recipe);
            }
        }
    }
    discovery.counters
}

/// Start the feature on a loaded object, before its programs are attached.
/// The caller polls the rings it gets back, calls [`Running::attached`] once
/// the programs are attached, and [`Running::finish`] when the capture stops.
///
/// The rings' lifetime is the callbacks', not the maps': like the tracer's own
/// ring set-up, what is returned holds no borrow of the loaded object, which
/// the caller still has to attach.
pub fn start<'a>(
    maps: Maps<'_>,
    sink: &ParquetSink,
    utids: Arc<UtidGenerator>,
    options: Options,
) -> Result<Started<'a>> {
    if maps.stats.max_entries() as usize != REASONS.len() {
        eprintln!(
            "task_context: the BPF side counts {} reasons and this build names {}: \
             the counters at the end are printed by number",
            maps.stats.max_entries(),
            REASONS.len()
        );
    }
    let exec_notices_unqueued = Arc::new(AtomicU64::new(0));
    let Plan::Live { first, walk } = plan(&options) else {
        eprintln!(
            "task_context: the kernel's confidentiality mode is on: no process is looked at \
             and no context is read"
        );
        return Ok(Started {
            rings: Vec::new(),
            running: Running {
                values: None,
                discovery: None,
                stats: maps.stats,
                exec_notices_unqueued,
                attached: None,
            },
        });
    };

    // The table's one writer, fed from the values ring's own poller thread:
    // records are few (one per new id, within a per-CPU budget), so there is
    // no queue between the ring and the rows.
    let values = Arc::new(Mutex::new(ValuesSink::new(
        StreamingParquetWriter::for_sink(sink.clone()),
        utids,
    )));
    let values_for_ring = Arc::clone(&values);
    let mut builder = RingBufferBuilder::new();
    builder
        .add(maps.values_ring, move |data: &[u8]| {
            values_for_ring
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .handle(data);
            0
        })
        .context("task_context: the values ring")?;
    let values_ring = builder.build().context("task_context: the values ring")?;

    let (exec_tx, exec_rx) = sync_channel::<u32>(EXEC_QUEUE);
    let unqueued = Arc::clone(&exec_notices_unqueued);
    let mut builder = RingBufferBuilder::new();
    builder
        .add(maps.execs_ring, move |data: &[u8]| {
            // struct task_context_exec_event: the process id, then a
            // reserved word.
            if let Some(pid) = data.get(0..4) {
                let pid = u32::from_ne_bytes([pid[0], pid[1], pid[2], pid[3]]);
                if exec_tx.try_send(pid).is_err() {
                    unqueued.fetch_add(1, Ordering::Relaxed);
                }
            }
            0
        })
        .context("task_context: the exec ring")?;
    let execs_ring = builder.build().context("task_context: the exec ring")?;

    let mut discovery = Discovery::new();
    let mut look_again = LookAgain::default();
    // The capture's targets are looked at here, before any program is
    // attached, so that their first samples already carry an id; the thread
    // looks at them again once the programs are attached.
    look_at_targets(
        &mut discovery,
        &maps.recipes,
        &mut look_again,
        &first,
        false,
    );
    let job = DiscoveryJob {
        discovery,
        recipes: maps.recipes,
        look_again,
        first,
        walk,
        planted: options.planted_recipes,
    };
    let (attached_tx, attached_rx) = sync_channel::<()>(1);
    let discovery_handle = thread::Builder::new()
        .name("tcx_discovery".to_string())
        .spawn(move || discovery_thread(job, attached_rx, exec_rx))
        .context("task_context: the discovery thread")?;

    Ok(Started {
        rings: vec![
            ("rb_tcx_val".to_string(), values_ring),
            ("rb_tcx_exec".to_string(), execs_ring),
        ],
        running: Running {
            values: Some(values),
            discovery: Some(discovery_handle),
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
        .map(|bytes| {
            let mut word = [0u8; 8];
            word.copy_from_slice(bytes);
            u64::from_ne_bytes(word)
        })
        .sum()
}

impl Running {
    /// The programs are attached: from here on an exec is announced, so this
    /// is when the discovery thread starts looking. Call it once, right after
    /// the attach.
    pub fn attached(&self) {
        if let Some(attached) = &self.attached {
            // Full means it was already said.
            let _ = attached.try_send(());
        }
    }

    /// Stop the feature. Called once the pollers of the rings [`start`]
    /// returned have been joined and the rings dropped: that is what ends
    /// the discovery thread and leaves this the table's only owner.
    pub fn finish(mut self) -> Result<()> {
        // A capture that never said "attached" must not leave the discovery
        // thread waiting for it while this waits for the thread.
        drop(self.attached.take());
        let counts: Vec<(String, u64)> = (0..self.stats.max_entries())
            .map(|reason| {
                let name = REASONS
                    .get(reason as usize)
                    .filter(|_| self.stats.max_entries() as usize == REASONS.len())
                    .map_or_else(|| format!("reason_{reason}"), |name| name.to_string());
                (name, reason_count(&self.stats, reason))
            })
            .filter(|(_, count)| *count > 0)
            .collect();
        let samples = counts
            .iter()
            .map(|(name, count)| format!("{name}={count}"))
            .collect::<Vec<_>>()
            .join(" ");
        println!("task_context samples: {samples}");

        if let Some(discovery) = self.discovery {
            match discovery.join() {
                Ok(counters) => println!("task_context discovery: {}", counters.summary()),
                Err(_) => eprintln!("task_context: the discovery thread panicked"),
            }
        }
        let unqueued = self.exec_notices_unqueued.load(Ordering::Relaxed);
        if unqueued > 0 {
            println!("task_context discovery: exec_notices_unqueued={unqueued}");
        }

        if let Some(values) = self.values {
            match Arc::try_unwrap(values) {
                Ok(sink) => {
                    let counters = sink
                        .into_inner()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .finish()
                        .context("task_context: closing the task_context table")?;
                    println!("task_context values: {}", counters.summary());
                }
                Err(_) => eprintln!(
                    "task_context: the values ring is still open; its table is closed when the ring is"
                ),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use discovery::Refusal;

    const RECIPE: Recipe = Recipe {
        tp_offset: -8,
        region_base: 0x7f00_0000_0000,
        region_size: 16 * 1024 * 1024,
    };

    fn options(restricted: bool, pids: &[u32]) -> Options {
        Options {
            restricted,
            pids: pids.to_vec(),
            planted_recipes: vec![(1, [0; 3])],
        }
    }

    /// In the kernel's confidentiality mode the feature is inert whatever
    /// else the capture asked for: no ring, no thread, no process looked at,
    /// nothing planted.
    #[test]
    fn nothing_runs_under_the_confidentiality_switch() {
        assert_eq!(plan(&options(true, &[])), Plan::Inert);
        assert_eq!(plan(&options(true, &[1, 2])), Plan::Inert);
    }

    #[test]
    fn a_capture_with_targets_looks_at_them_alone_and_one_without_walks_the_host() {
        assert_eq!(
            plan(&options(false, &[7, 8])),
            Plan::Live {
                first: vec![7, 8],
                walk: false
            }
        );
        assert_eq!(
            plan(&options(false, &[])),
            Plan::Live {
                first: Vec::new(),
                walk: true
            }
        );
    }

    #[test]
    fn a_process_that_never_publishes_is_not_looked_at_for_ever() {
        let mut list = LookAgain::default();
        assert!(list.add(7));
        assert!(list.add(7), "the same process twice is one entry");
        assert_eq!(list.waiting.len(), 1);

        let mut looks = 0;
        let mut gave_up = 0;
        for _ in 0..LookAgain::MAX_LOOKS + 5 {
            gave_up += list.tick(
                |_| {
                    looks += 1;
                    Finding::NotYet
                },
                |_, _| panic!("nothing was published"),
            );
        }
        assert_eq!(looks, LookAgain::MAX_LOOKS);
        assert_eq!(gave_up, 1);
        assert!(list.waiting.is_empty());
    }

    #[test]
    fn a_waiting_process_leaves_the_list_when_it_publishes_or_stops_mattering() {
        let mut list = LookAgain::default();
        for pid in [1, 2, 3, 4, 5] {
            assert!(list.add(pid));
        }
        let mut published = Vec::new();
        let gave_up = list.tick(
            |pid| match pid {
                1 => Finding::Published(RECIPE),
                2 => Finding::NotLinked,
                3 => Finding::Gone,
                4 => Finding::Refused(Refusal::Geometry),
                _ => Finding::NotYet,
            },
            |pid, recipe| published.push((pid, recipe)),
        );
        assert_eq!(gave_up, 0);
        assert_eq!(published, vec![(1, RECIPE)]);
        assert_eq!(list.waiting, vec![(5, 1)]);
    }

    #[test]
    fn the_list_takes_no_more_than_its_bound() {
        let mut list = LookAgain::default();
        for pid in 0..LookAgain::MAX_WAITING as u32 {
            assert!(list.add(pid));
        }
        assert!(!list.add(u32::MAX));
        assert!(list.add(0), "a process already waiting is not a new entry");
        assert_eq!(list.waiting.len(), LookAgain::MAX_WAITING);
    }

    #[test]
    fn a_recipe_is_three_native_words() {
        let bytes = RECIPE.to_bytes();
        assert_eq!(bytes[0..8], (-8i64).to_ne_bytes());
        assert_eq!(bytes[8..16], 0x7f00_0000_0000u64.to_ne_bytes());
        assert_eq!(bytes[16..24], (16u64 * 1024 * 1024).to_ne_bytes());
    }

    #[test]
    fn the_reason_names_are_distinct_and_printable() {
        let mut names = REASONS.to_vec();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), REASONS.len());
        assert!(REASONS
            .iter()
            .all(|name| name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')));
    }
}
