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
use crate::pystacks::process::{parse_maps, MemoryMapping};
use crate::task_context::discovery::{all_pids, exe_mapping};
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
/// when a sample finds a label set its process has not sent: a program that
/// makes a new set per request sends one per request. Over the budget a
/// sample still carries its set's id, and the set is sent by a later one.
/// The budget bounds what is sent, not what is read: every labelled sample
/// copies and hashes its set.
pub const DEFAULT_LABELS_PER_CPU_PER_SEC: u32 = 200;
/// Exec notices one CPU may send a second. Each makes discovery open one
/// executable, or none when it has seen that file before.
pub const DEFAULT_EXECS_PER_CPU_PER_SEC: u32 = 100;

/// The BPF side's counters by name, in the order of `enum go_context_reason`.
/// [`start`] checks the count against the map.
pub const REASONS: [&str; 18] = [
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
    "curg",
    "nested",
    "not_its_g",
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
    /// The executable is not in the process's own memory map: a child that
    /// was forked from a Go program and unmapped it.
    pub not_mapped: u64,
    pub map_errors: u64,
    /// The look at every process ran out of time before these.
    pub not_reached: u64,
}

impl DiscoveryCounters {
    pub fn summary(&self) -> String {
        format!(
            "looked={} go_programs={} published={} refused={} gone={} not_mapped={} map_errors={} not_reached={}",
            self.looked,
            self.go_programs,
            self.published,
            self.refused,
            self.gone,
            self.not_mapped,
            self.map_errors,
            self.not_reached
        )
    }
}

/// The most of `/proc/<pid>/maps` that a look reads: the process chooses how
/// long its map is, and a program linked at fixed addresses is at its start.
const MAPS_HEAD: u64 = 256 << 10;

/// The head of process `pid`'s map: whole lines only, and a name that is not
/// UTF-8 costs its own line's name, not the map. Empty when it cannot be read.
fn maps_head(pid: u32) -> Vec<MemoryMapping> {
    use std::io::Read as _;
    let Ok(file) = std::fs::File::open(format!("/proc/{pid}/maps")) else {
        return Vec::new();
    };
    let mut bytes = Vec::new();
    if file.take(MAPS_HEAD).read_to_end(&mut bytes).is_err() {
        return Vec::new();
    }
    if bytes.len() as u64 == MAPS_HEAD {
        let whole = bytes
            .iter()
            .rposition(|b| *b == b'\n')
            .map_or(0, |at| at + 1);
        bytes.truncate(whole);
    }
    parse_maps(&String::from_utf8_lossy(&bytes))
}

/// Whether `exe`, opened through `/proc/<pid>/exe`, is mapped in process
/// `pid`'s own memory.
fn is_its_own(pid: u32, exe: &std::fs::File) -> bool {
    exe_mapping(pid, exe, &maps_head(pid)).is_some()
}

/// Look at process `pid` and write its recipe, or delete the one it had (a
/// process that execs a program that is not Go must not keep the old one).
///
/// A process is taken for its executable only when that file is mapped in
/// the process's own memory, as task context judges one: the `exe` link
/// survives a fork without exec, so a child that has unmapped the program
/// (gVisor's systrap stubs, whose memory is the sandboxed guest's) still names
/// it. The file is opened once, and that handle is both what the recipe is
/// read from and what the map is checked against.
fn look(recipes: &MapHandle, counters: &mut DiscoveryCounters, pid: u32) {
    counters.looked += 1;
    let found = match std::fs::File::open(format!("/proc/{pid}/exe")) {
        Err(_) => Finding::Gone,
        Ok(exe) => match recipe::of_executable(&exe) {
            Finding::Recipe(_) if !is_its_own(pid, &exe) => {
                counters.not_mapped += 1;
                Finding::NotGo
            }
            other => other,
        },
    };
    match found {
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

    /// A child of this process that has unmapped the program (every mapping in
    /// `ranges`) and waits on a page of code of its own: a fork with no exec,
    /// whose `exe` link still names what it no longer holds, as a gVisor
    /// systrap stub's does. The rest of its memory stays: the C library has
    /// told the kernel of a word in the thread's own data (rseq), and the
    /// kernel kills a thread that has lost it.
    #[cfg(target_arch = "x86_64")]
    fn child_without(ranges: &[(usize, usize)]) -> libc::pid_t {
        let mut code: Vec<u8> = Vec::new();
        for (start, end) in ranges {
            // munmap(start, end - start)
            code.extend([0xb8, 0x0b, 0, 0, 0, 0x48, 0xbf]);
            code.extend((*start as u64).to_le_bytes());
            code.extend([0x48, 0xbe]);
            code.extend(((end - start) as u64).to_le_bytes());
            code.extend([0x0f, 0x05]);
        }
        // for (;;) pause();
        code.extend([0xb8, 0x22, 0, 0, 0, 0x0f, 0x05, 0xeb, 0xf7]);
        assert!(code.len() <= 4096);
        // The test harness has other threads: nothing is allocated and no
        // lock is taken between the fork and the jump.
        unsafe {
            let child = libc::fork();
            if child != 0 {
                return child;
            }
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
            let page = libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            if page == libc::MAP_FAILED {
                libc::_exit(3);
            }
            std::ptr::copy_nonoverlapping(code.as_ptr(), page as *mut u8, code.len());
            if libc::mprotect(page, 4096, libc::PROT_READ | libc::PROT_EXEC) != 0 {
                libc::_exit(4);
            }
            let run: extern "C" fn() -> ! = std::mem::transmute(page);
            run()
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn a_child_that_unmapped_the_program_is_not_taken_for_it() {
        let link = |pid: u32| std::fs::read_link(format!("/proc/{pid}/exe")).ok();
        let taken = |pid: u32| {
            std::fs::File::open(format!("/proc/{pid}/exe"))
                .ok()
                .map(|exe| is_its_own(pid, &exe))
        };
        let me = std::process::id();
        assert_eq!(taken(me), Some(true), "this process runs its program");

        let path = link(me).unwrap().to_string_lossy().into_owned();
        // The whole map, not the head a look reads: tests that run beside
        // this one map the test binary too, anywhere.
        let of_program = |pid: u32| -> Vec<(usize, usize)> {
            crate::pystacks::process::parse_proc_maps(pid as i32)
                .iter()
                .filter(|mapping| mapping.name == path)
                .map(|mapping| (mapping.start, mapping.end))
                .collect()
        };
        let reap = |child: libc::pid_t| unsafe {
            libc::kill(child, libc::SIGKILL);
            libc::waitpid(child, std::ptr::null_mut(), 0);
        };
        // A mapping another test makes between the listing and the fork stays
        // in the child: then the child is not what this test needs, and it
        // is made again.
        for _ in 0..5 {
            let child = child_without(&of_program(me));
            assert!(child > 0, "fork");
            let pid = child as u32;
            // Until it has unmapped the program it is a copy of this process.
            let started = Instant::now();
            while !of_program(pid).is_empty() && started.elapsed() < Duration::from_secs(5) {
                thread::sleep(Duration::from_millis(1));
            }
            if !of_program(pid).is_empty() {
                reap(child);
                continue;
            }
            let found = (maps_head(pid).len(), link(pid) == link(me), taken(pid));
            reap(child);
            assert!(found.0 > 0, "the child lives, and its map was read");
            assert!(found.1, "it still names the program");
            assert_eq!(found.2, Some(false), "and has none of it mapped");
            return;
        }
        panic!("no child held none of the program in five tries");
    }
}
