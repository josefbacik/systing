//! The python-function-trace recorder: the entries to and exits from Python
//! functions, as a slice per run of a frame.
//!
//! Uprobes on the interpreter binary, placed by [`sites`], emit one event per
//! frame entry, exit, yield and exception handler; [`pairing`] turns them into
//! slices. No ptrace, and no code of ours in the process: the probes read the
//! frame and code object from the thread that hits them. The kernel does change
//! the process's memory while the probes are in: a breakpoint in a private copy
//! of each probed page, and one extra page of its own.
//!
//! Like the task-stacks recorder it is a BPF object of its own, loaded only when
//! it runs, and it shares what the capture already has rather than keeping its
//! own. The target set and pystacks' maps are the main object's. A process comes
//! to it from the capture's targets at the start and then from the fork and exec
//! events pystacks acts on, registered with pystacks either way. Its rings are a
//! family like any other's, read by the same pollers into a recorder fed by the
//! same consumer loop; names go to pystacks' resolver, and lost events are a
//! class of the capture's missed events.
//!
//! One program serves every process, with 11 or 12 links per process (a link
//! attached without a pid would make every process that maps the file trap,
//! bystanders included). Every Python call of a traced process pays for the
//! probes, so they come out as soon as the capture ends or the slice cap is
//! reached, before anything is written.

pub mod pairing;
pub mod sites;

#[allow(
    clippy::all,
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals,
    dead_code
)]
mod skel {
    include!(concat!(env!("OUT_DIR"), "/python_function_trace.skel.rs"));
}

use crate::pystacks::stack_walker::StackWalkerRun;
use crate::pystacks::types::PystacksSymbolRecord;
use crate::pystacks::{discovery, process};
use crate::record::RecordCollector;
use crate::ringbuf::RingBuffer;
use crate::session_recorder::SessionRecorder;
use crate::systing_core::{task_info, SystingEvent, SystingRecordEvent};
use crate::target_filter::{set_target_filter, TargetFilter, TargetFilterMaps};
use crate::task_stacks_recorder::{MapKeys, PythonThreadNames, SharedPystacksMaps};
use crate::trace::PythonFunctionSliceRecord;
use crate::utid::{ThreadAwareRecorder, UtidGenerator};
use anyhow::{anyhow, bail, Context, Result};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{Link, MapCore, MapFlags, RingBufferBuilder, UprobeOpts};
use pairing::{Counters, Event, Pairer};
use sites::{Interpreter, Kind, Site};
use std::collections::{HashMap, HashSet};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, sync_channel, Receiver, RecvTimeoutError, Sender, SyncSender};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// The slices a capture keeps unless `--python-function-max-slices` says
/// otherwise. Reaching the cap takes the probes out.
pub const DEFAULT_MAX_SLICES: usize = 5_000_000;

/// The most processes traced at once: each is slowed, and each costs 11 or 12
/// links to put in and take out. One more is refused, with this for a reason.
const MAX_PROCESSES: usize = 64;

/// The file descriptors the most processes can take, for the capture's budget.
pub const MAX_LINKS: u32 = MAX_PROCESSES as u32 * 12;

/// How often the kernel's event count is held to the cap and the processes are
/// looked at for having gone.
const HOUSEKEEP_EVERY: Duration = Duration::from_millis(100);
/// How often a traced process's thread names are read and its maps looked at
/// for greenlet, which a process can import at any time.
const LOOK_INSIDE_EVERY: Duration = Duration::from_secs(1);
/// The threads that take the links out: each detach waits out a grace period
/// in the kernel (a third of a second on 6.12), and the target pays until the
/// last is gone.
const DETACH_THREADS: usize = 32;
/// How often the target set is looked through for what no event told of, and a
/// process not yet a Python looked at again. The first is a safety net, and a
/// call into the kernel per key; the second reads the process's maps.
const LOOK_FOR_NEW_EVERY: Duration = Duration::from_millis(500);
const LOOK_AGAIN_EVERY: Duration = Duration::from_millis(50);
/// See [`Seen::NotPython`].
const NOT_PYTHON_FOR: Duration = Duration::from_secs(1);

/// What the recorder is pointed at.
#[derive(Clone, Debug, Default)]
pub struct Options {
    /// `--pid` and the traced command.
    pub pids: Vec<u32>,
    /// `--cgroup` directories, with the cgroups below them. With `pids` too,
    /// only processes in both are traced, as every other recorder has it.
    pub cgroups: Vec<PathBuf>,
    /// The slice cap.
    pub max_slices: usize,
    /// Whether the kernel decides `--cgroup` membership, so that a cgroup made
    /// after the start counts (see `target_filter_config`).
    pub cgroup_match_kernel: bool,
    /// The ring family's layout, [`crate::systing_core::plan_ringbufs`]'s.
    pub nr_rings: u32,
    pub wakeup_bytes: u64,
}

/// What the BPF side counted (`enum pyft_counter`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KernelCounters {
    pub events: u64,
    pub no_thread_state: u64,
    pub no_frame: u64,
    pub no_code: u64,
    pub symbol_reads: u64,
    pub symbol_records: u64,
    pub symbol_records_dropped: u64,
    pub symbol_busy: u64,
    /// Entry and handler events, what [`slice_cutoff`] counts and the cap holds.
    pub begun: u64,
    /// Every run of the probe, and those that stopped for want of a target or a
    /// config: with `events`, what tells a process that made no calls from one
    /// whose probes never fire or find nothing.
    pub hits: u64,
    pub not_targeted: u64,
    pub no_config: u64,
}

/// One event as BPF sends it (`struct pyft_event`), with the thread's identity as
/// every recorder's events carry it. The recorder keeps the [`Event`] of it.
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct WireEvent {
    pub task: task_info,
    pub ts: u64,
    pub frame: u64,
    pub symbol_id: u64,
    pub first_line: u32,
    pub kind: u8,
    pub pad: [u8; 3],
}

// SAFETY: repr(C), integers only, and no implicit padding: task_info's 32 bytes,
// then fields in descending alignment, the last three an explicit pad.
unsafe impl plain::Plain for WireEvent {}

impl SystingEvent for WireEvent {
    fn ts(&self) -> u64 {
        self.ts
    }
    fn next_task_info(&self) -> Option<&task_info> {
        Some(&self.task)
    }
}

// A symbol record is not an event, so a record's size says which it is.
const _: () =
    assert!(std::mem::size_of::<WireEvent>() != std::mem::size_of::<PystacksSymbolRecord>());

/// `PYFT_EXEC`: not a frame's event, so not one of [`sites::Kind`]'s.
const KIND_EXEC: u8 = 5;

/// A ring of the family: events to the recorder's consumer, names to the
/// capture's symbol loader. The senders block when full, as [`crate::systing_core`]'s
/// rings' do: the kernel's ring is what is bounded.
pub(crate) fn create_ring<'a>(
    map: &dyn MapCore,
    events: SyncSender<WireEvent>,
    symbols: SyncSender<PystacksSymbolRecord>,
) -> Result<libbpf_rs::RingBuffer<'a>, libbpf_rs::Error> {
    let mut builder = RingBufferBuilder::new();
    builder.add(map, move |data: &[u8]| {
        let sent = if data.len() == std::mem::size_of::<WireEvent>() {
            let mut event = WireEvent::default();
            plain::copy_from_bytes(&mut event, data).expect("an event's size was checked");
            events.send(event).is_ok()
        } else {
            let mut record = PystacksSymbolRecord::default();
            plain::copy_from_bytes(&mut record, data).is_ok() && symbols.send(record).is_ok()
        };
        if sent {
            0
        } else {
            -1
        }
    })?;
    builder.build()
}

#[derive(Default)]
struct ThreadEvents {
    tgid: u32,
    events: Vec<Event>,
}

/// What a capture's trace came to, for `sysinfo`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    pub kernel: KernelCounters,
    /// How many processes had probes.
    pub traced: u64,
    /// A process that was not traced, and why; or why nothing was.
    pub refused: Vec<String>,
    /// What could make the trace wrong for a process.
    pub warnings: Vec<String>,
    pub cap_reached: bool,
}

impl Outcome {
    /// `sysinfo.python_function_notes`: `None` where there is nothing to say.
    pub fn notes(&self) -> Option<String> {
        let lines: Vec<&str> = self
            .refused
            .iter()
            .map(|line| line.as_str())
            .chain(self.warnings.iter().map(String::as_str))
            .collect();
        (!lines.is_empty()).then(|| lines.join("\n"))
    }
}

/// The events of a capture, until the trace is written.
pub struct PythonFunctionRecorder {
    ringbuf: RingBuffer<WireEvent>,
    utid_generator: Arc<UtidGenerator>,
    threads: HashMap<u32, ThreadEvents>,
    /// By process: when it exec'd, in order. Its frames end there.
    execs: HashMap<u32, Vec<u64>>,
    /// By process: when its probes were all in. Events from before then are
    /// dropped: a frame running while they went in would end as though an
    /// exception had taken it.
    started: HashMap<u32, u64>,
    /// By process: about when it was seen gone. Its frames still open end
    /// there rather than at the end of the capture.
    gone: HashMap<u32, u64>,
    max_slices: usize,
    outcome: Option<Outcome>,
}

impl ThreadAwareRecorder for PythonFunctionRecorder {
    fn utid_generator(&self) -> &UtidGenerator {
        &self.utid_generator
    }
}

impl SystingRecordEvent<WireEvent> for PythonFunctionRecorder {
    fn ringbuf(&self) -> &RingBuffer<WireEvent> {
        &self.ringbuf
    }
    fn ringbuf_mut(&mut self) -> &mut RingBuffer<WireEvent> {
        &mut self.ringbuf
    }
    fn handle_event(&mut self, event: WireEvent) {
        let tgid = (event.task.tgidpid >> 32) as u32;
        let tid = event.task.tgidpid as u32;
        if event.kind == KIND_EXEC {
            self.execs.entry(tgid).or_default().push(event.ts);
            return;
        }
        let thread = self.threads.entry(tid).or_default();
        thread.tgid = tgid;
        thread.events.push(Event {
            ts: event.ts,
            frame: event.frame,
            symbol_id: event.symbol_id,
            tgid,
            tid,
            first_line: event.first_line,
            kind: event.kind,
        });
    }
}

impl PythonFunctionRecorder {
    pub fn new(utid_generator: Arc<UtidGenerator>) -> Self {
        Self {
            ringbuf: RingBuffer::default(),
            utid_generator,
            threads: HashMap::new(),
            execs: HashMap::new(),
            started: HashMap::new(),
            gone: HashMap::new(),
            max_slices: 0,
            outcome: None,
        }
    }

    /// The recorder cannot run in this capture, for this reason.
    pub fn set_off(&mut self, why: &str) {
        self.outcome = Some(Outcome {
            refused: vec![format!("off for this capture: {}", printable(why))],
            ..Default::default()
        });
    }

    /// What the recorder's thread had to say, once the probes are out.
    pub fn finish(&mut self, finished: Finished) {
        self.started = finished.started;
        self.gone = finished.gone;
        self.max_slices = finished.max_slices;
        self.outcome = Some(finished.outcome);
    }

    /// A process can load greenlet and exit between looks at its maps; what it
    /// ran says so all the same.
    pub fn note_greenlet(&mut self, psr: &StackWalkerRun) {
        let Some(outcome) = self.outcome.as_mut() else {
            return;
        };
        let mut is_greenlet: HashMap<u64, bool> = HashMap::new();
        for thread in self.threads.values() {
            let ran = thread.events.iter().any(|e| {
                *is_greenlet.entry(e.symbol_id).or_insert_with(|| {
                    psr.symbol_name(e.symbol_id)
                        .is_some_and(|(_, file)| is_greenlet_file(&file))
                })
            });
            if ran {
                let line = format!("process {}: {GREENLET_WARNING}", thread.tgid);
                if !outcome.warnings.contains(&line) {
                    outcome.warnings.push(line);
                }
            }
        }
    }

    /// Whether it ran: its closing line matters most when it has no slices.
    pub fn has_data(&self) -> bool {
        self.outcome.is_some()
    }

    /// When the first process began to be traced.
    pub fn min_timestamp(&self) -> Option<u64> {
        self.started.values().min().copied()
    }

    pub fn outcome(&self) -> Option<&Outcome> {
        self.outcome.as_ref()
    }

    /// Pairs each thread's events, in the order they happened, and writes the
    /// slices. The rings are per CPU and a thread moves between CPUs, so only
    /// here, with all of a thread's events in hand, is their order known.
    pub fn write_records(
        &mut self,
        collector: &mut dyn RecordCollector,
        psr: &StackWalkerRun,
        capture_end: u64,
    ) -> Result<()> {
        let threads = std::mem::take(&mut self.threads);
        let outcome = self.outcome.clone().unwrap_or_default();
        let cap_reached = outcome.cap_reached;
        let k = outcome.kernel;
        let end = if cap_reached {
            slice_cutoff(&threads, &self.started, self.max_slices)
                .map_or(capture_end, |at| at.min(capture_end))
        } else {
            capture_end
        };
        // A name once, not once a call. A function BPF could not name has no
        // entry in the resolver, whatever it was retried with.
        let mut names: HashMap<u64, (String, Option<String>)> = HashMap::new();
        let mut counters = Counters::default();
        let mut written: u64 = 0;
        for (tid, mut thread) in threads {
            let start = self.started.get(&thread.tgid).copied().unwrap_or(0);
            thread.events.sort_by_key(|e| e.ts);
            let mut pairer = Pairer::new();
            let mut execs: Vec<u64> = self
                .execs
                .get(&thread.tgid)
                .into_iter()
                .flatten()
                .copied()
                .filter(|at| *at <= end)
                .collect();
            // As with the events: the rings are not read in time order.
            execs.sort_unstable();
            let mut execs = execs.into_iter().peekable();
            for event in thread
                .events
                .iter()
                .filter(|e| e.ts >= start && e.ts <= end)
            {
                while let Some(at) = execs.next_if(|at| *at <= event.ts) {
                    pairer.close_all(at);
                }
                pairer.push(event);
            }
            for at in execs {
                pairer.close_all(at);
            }
            pairer.finish(self.gone.get(&thread.tgid).map_or(end, |at| (*at).min(end)));
            let utid = self.utid_generator.get_or_create_utid(tid as i32);
            for slice in &pairer.slices {
                let (function, file) = names.entry(slice.symbol_id).or_insert_with(|| {
                    match psr.symbol_name(slice.symbol_id) {
                        Some((function, file)) => (
                            printable(&function),
                            (!file.is_empty()).then(|| printable(&file)),
                        ),
                        None => (format!("<unknown python {:#x}>", slice.symbol_id), None),
                    }
                });
                collector.add_python_function_slice(PythonFunctionSliceRecord {
                    ts: slice.start as i64,
                    dur: (slice.end - slice.start) as i64,
                    utid,
                    depth: slice.depth as i32,
                    function: function.clone(),
                    file: file.clone(),
                    line: slice.first_line as i32,
                    end_kind: slice.end_kind.as_str().to_string(),
                })?;
                written += 1;
            }
            counters.add(&pairer.counters);
        }
        eprintln!(
            "python-function-trace: {written} slices of {} processes; {} probe hits, {} events, \
             {} out of the target set, {} with no config, {} with no thread state, {} with no \
             frame, {} with no name to give ({} name records lost); {} slices with no return \
             event (an exception, or a lost or unseen event), {} returns with no entry seen \
             (frames from before the trace, the interpreter's own)",
            outcome.traced,
            k.hits,
            k.events,
            k.not_targeted,
            k.no_config,
            k.no_thread_state,
            k.no_frame,
            k.no_code,
            k.symbol_records_dropped,
            counters.unwound,
            counters.unmatched_exits
        );
        Ok(())
    }
}

/// `s` with every control character (escape sequences, tabs, newlines) and
/// every other character that is not a space, visible ASCII, or a letter or
/// digit, written out as an escape. Every string the
/// traced process chooses (function and file names, thread and process
/// names, paths) passes through this before it reaches a terminal, the table
/// of slices or the trace, so it can neither drive the terminal nor add a
/// column or a line.
pub fn printable(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        // Kept as it is: a space, visible ASCII, and letters and digits of
        // other scripts. Everything else, which includes every control,
        // format, line and paragraph separator character, is escaped.
        let plain = c == ' ' || c.is_ascii_graphic() || (!c.is_ascii() && c.is_alphanumeric());
        if !plain || c == '\\' {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

fn is_greenlet_file(file: &str) -> bool {
    file.contains("/greenlet/") || file.contains("/gevent/")
}

/// The time by which `max_slices` slices had begun, where more had: everything
/// after it is left out. Only here, with every ring read, is that known: the
/// rings are not read in time order. A handler counts as beginning a slice though
/// most continue one, so a capture never holds more than the cap.
fn slice_cutoff(
    threads: &HashMap<u32, ThreadEvents>,
    started: &HashMap<u32, u64>,
    max_slices: usize,
) -> Option<u64> {
    let mut begun: Vec<u64> = threads
        .values()
        .flat_map(|thread| {
            let start = started.get(&thread.tgid).copied().unwrap_or(0);
            thread.events.iter().filter_map(move |e| {
                begins_a_slice(e.kind)
                    .then_some(e.ts)
                    .filter(|ts| *ts >= start)
            })
        })
        .collect();
    if max_slices == 0 || begun.len() <= max_slices {
        return None;
    }
    let (_, at, _) = begun.select_nth_unstable(max_slices - 1);
    Some(*at)
}

fn begins_a_slice(kind: u8) -> bool {
    matches!(Kind::from_u8(kind), Some(Kind::Enter | Kind::Sync))
}

/// The processes `opts` points at when the capture starts: the `--pid` processes
/// and those in the `--cgroup` subtrees, and with both, those in both. The fork
/// and exec events of the capture's main object say what comes after.
fn targets(opts: &Options) -> Vec<u32> {
    let mut in_cgroups = HashSet::new();
    for cgroup in &opts.cgroups {
        crate::cgroup::collect_cgroup_procs(cgroup, &mut in_cgroups);
    }
    let mut found: Vec<u32> = if opts.pids.is_empty() {
        in_cgroups.into_iter().collect()
    } else {
        opts.pids
            .iter()
            .copied()
            .filter(|pid| opts.cgroups.is_empty() || in_cgroups.contains(pid))
            .collect()
    };
    found.sort_unstable();
    found.dedup();
    found
}

/// Refuses a tool outside the initial pid namespace: the probes see the initial
/// namespace's ids, the attach this namespace's.
fn check_pid_namespace() -> Result<()> {
    let meta = std::fs::metadata("/proc/self/ns/pid")
        .context("cannot read this process's pid namespace")?;
    // The initial pid namespace's inode is fixed (PROC_PID_INIT_INO).
    if meta.ino() != 0xEFFF_FFFC {
        bail!(
            "the python-function-trace recorder runs only in the host's pid namespace: the \
             probes' process ids would not match"
        );
    }
    Ok(())
}

/// Why `pid` cannot be traced, for a thing no later look would change: a thread
/// id given for a process, or a C library the thread-state lookup cannot read.
fn why_not_traceable(pid: u32) -> Option<String> {
    let status = std::fs::read(format!("/proc/{pid}/status")).ok()?;
    let tgid = status
        .split(|b| *b == b'\n')
        .find_map(|line| line.strip_prefix(b"Tgid:"))
        .and_then(|v| std::str::from_utf8(v).ok())
        .and_then(|v| v.trim().parse::<u32>().ok());
    if tgid.is_some_and(|tgid| tgid != pid) {
        return Some(format!(
            "a thread of process {}: give the process id",
            tgid?
        ));
    }
    if process::parse_proc_maps(pid as i32)
        .iter()
        .any(|m| is_musl_library(&m.name))
    {
        return Some(
            "musl libc: the probes could not find a thread's Python state, so the process \
             would pay for a trace with nothing in it"
                .to_string(),
        );
    }
    None
}

fn is_musl_library(path: &str) -> bool {
    Path::new(path)
        .file_name()
        .and_then(|f| f.to_str())
        .is_some_and(|f| f.starts_with("ld-musl-") || f.starts_with("libc.musl-"))
}

/// Interpreter files already read, by the open file's device, inode, size
/// and modification time: what was found in each, or why it was refused.
type InterpreterCache = HashMap<(u64, u64, u64, i64, i64), Result<Option<Interpreter>, String>>;

/// The file of process `pid` that defines the interpreter, with what
/// [`sites`] found in it: the file, open, the name the maps line gives it,
/// made printable, and what was found in it. The file is opened once,
/// through the mapping itself (`/proc/PID/map_files/START-END`, so it is the
/// file the process has mapped, whatever its maps line or its mount
/// namespace says); the cache key, the parse and the probes all go through
/// that one descriptor, so they cannot describe different files.
fn interpreter_of(
    pid: u32,
    cache: &mut InterpreterCache,
) -> Result<(std::fs::File, String, Interpreter)> {
    let maps = process::parse_proc_maps(pid as i32);
    let exe =
        process::read_exe_path(pid as i32).ok_or_else(|| anyhow!("cannot read /proc/{pid}/exe"))?;
    let exe = exe.to_string_lossy();
    // The executable, then each libpython: where pystacks' discovery looks.
    // Each by the first mapping of its file.
    let is_libpython = |name: &str| {
        Path::new(name)
            .file_name()
            .and_then(|f| f.to_str())
            .is_some_and(|f| f.to_lowercase().starts_with("libpython"))
    };
    let mut candidates: Vec<&process::MemoryMapping> = maps
        .iter()
        .find(|m| m.offset == 0 && m.inode != 0 && m.name == exe)
        .into_iter()
        .collect();
    for m in &maps {
        if m.offset == 0
            && m.inode != 0
            && is_libpython(&m.name)
            && !candidates.iter().any(|c| c.name == m.name)
        {
            candidates.push(m);
        }
    }
    let mut refused: Option<String> = None;
    // What all the files read for one process may come to: each is bounded
    // on its own too (see `sites`).
    let mut budget: u64 = 512 << 20;
    for m in candidates {
        let path = PathBuf::from(format!("/proc/{pid}/map_files/{:x}-{:x}", m.start, m.end));
        let Ok(file) = std::fs::File::open(&path) else {
            continue;
        };
        // Keyed by the open file, as the kernel reports it, not by what the
        // maps line says.
        let Ok(meta) = file.metadata() else {
            continue;
        };
        let Some(left) = budget.checked_sub(meta.size()) else {
            refused.get_or_insert(format!(
                "{}: the files of this process come to more than 512 MiB",
                printable(&m.name)
            ));
            continue;
        };
        budget = left;
        let key = (
            meta.dev(),
            meta.ino(),
            meta.size(),
            meta.mtime(),
            meta.mtime_nsec(),
        );
        let found = match cache.get(&key) {
            Some(found) => found.clone(),
            None => {
                let found = Interpreter::from_file(&file, &path).map_err(|e| format!("{e:#}"));
                cache.insert(key, found.clone());
                found
            }
        };
        match found {
            Ok(Some(interpreter)) => return Ok((file, printable(&m.name), interpreter)),
            Ok(None) => {}
            Err(e) => {
                refused.get_or_insert(format!("{}: {}", printable(&m.name), printable(&e)));
            }
        }
    }
    match refused {
        Some(why) => bail!("process {pid}'s interpreter file is refused: {why}"),
        None => bail!("no file of process {pid} defines _PyEval_EvalFrameDefault"),
    }
}

/// The capture's end of the recorder: its thread, while it runs.
pub struct Running {
    stop: Arc<AtomicBool>,
    begin: Option<Sender<Begin>>,
    notify: Sender<u32>,
    thread: Option<thread::JoinHandle<Result<Finished>>>,
}

impl Drop for Running {
    /// A capture that failed on its way never got to stop: the processes do not go
    /// on paying for that.
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.begin.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// What the recorder's thread waits for: pystacks, the session, and whom to tell
/// when the processes already there have their probes.
type Begin = (Arc<StackWalkerRun>, Arc<SessionRecorder>, SyncSender<()>);

/// What the recorder's thread hands over once the probes are out.
pub struct Finished {
    started: HashMap<u32, u64>,
    gone: HashMap<u32, u64>,
    outcome: Outcome,
    max_slices: usize,
}

impl Running {
    /// Tells the recorder of a process that has just forked or exec'd.
    pub(crate) fn notifier(&self) -> Sender<u32> {
        self.notify.clone()
    }

    /// Pystacks is up: the targets get their probes, and this returns when the
    /// processes already there have them, so a capture's time is all traced.
    pub(crate) fn begin(&mut self, psr: Arc<StackWalkerRun>, recorder: Arc<SessionRecorder>) {
        if let Some(begin) = self.begin.take() {
            let (begun_tx, begun_rx) = sync_channel(1);
            if begin.send((psr, recorder, begun_tx)).is_ok() {
                let _ = begun_rx.recv();
            }
        }
    }

    /// Takes the probes out and says what became of the trace. What is still in
    /// the rings reaches the recorder through its consumer afterwards.
    pub fn stop(mut self) -> Result<Finished> {
        self.stop.store(true, Ordering::Relaxed);
        self.begin.take();
        self.thread
            .take()
            .expect("stop is the one taker of the thread")
            .join()
            .map_err(|_| anyhow!("the python-function-trace thread panicked"))?
    }
}

/// The main object's maps, held by the recorder's thread until it has loaded.
struct SharedFds {
    cgroup_targets: OwnedFd,
    cgroup_target_refs: OwnedFd,
    cgroups: OwnedFd,
    pids: OwnedFd,
    targeted_pids: OwnedFd,
    pid_config: OwnedFd,
    binaryid_config: OwnedFd,
    symbols: OwnedFd,
    ending_frames: OwnedFd,
    ending_frame_qualnames: OwnedFd,
    rings: OwnedFd,
    missed: OwnedFd,
}

/// Loads the object, reusing the main object's maps. An `Err` is why this recorder
/// cannot run; the capture's others are not affected.
pub fn load(
    opts: Options,
    filter: TargetFilter,
    target: &TargetFilterMaps<'_>,
    pystacks: &SharedPystacksMaps<'_>,
    rings: BorrowedFd<'_>,
    missed: BorrowedFd<'_>,
) -> Result<Running> {
    check_pid_namespace()?;
    if let Some(why) = std::env::var_os(REFUSE_ENV).filter(|v| !v.is_empty()) {
        bail!("{}", why.to_string_lossy());
    }
    let own = |fd: BorrowedFd<'_>| fd.try_clone_to_owned().context("Failed to keep a map");
    let fds = SharedFds {
        cgroup_targets: own(target.cgroup_targets)?,
        cgroup_target_refs: own(target.cgroup_target_refs)?,
        cgroups: own(target.cgroups)?,
        pids: own(target.pids)?,
        targeted_pids: own(pystacks.targeted_pids)?,
        pid_config: own(pystacks.pid_config)?,
        binaryid_config: own(pystacks.binaryid_config)?,
        symbols: own(pystacks.symbols)?,
        ending_frames: own(pystacks.ending_frames)?,
        ending_frame_qualnames: own(pystacks.ending_frame_qualnames)?,
        rings: own(rings)?,
        missed: own(missed)?,
    };
    let stop = Arc::new(AtomicBool::new(false));
    let (ready_tx, ready_rx) = sync_channel(1);
    let (begin_tx, begin_rx) = channel();
    let (notify_tx, notify_rx) = channel();
    let thread = {
        let stop = stop.clone();
        // The skeleton borrows from this thread's stack, and lives and dies here.
        thread::Builder::new()
            .name("py_func_trace".to_string())
            .spawn(move || run(&opts, filter, fds, &stop, &ready_tx, begin_rx, notify_rx))
            .context("Failed to start the python-function-trace thread")?
    };
    match ready_rx.recv() {
        Ok(()) => Ok(Running {
            stop,
            begin: Some(begin_tx),
            notify: notify_tx,
            thread: Some(thread),
        }),
        // The thread ended before it was ready: its error says why.
        Err(_) => match thread.join() {
            Ok(Err(e)) => Err(e),
            _ => bail!("the python-function-trace thread ended before it began"),
        },
    }
}

/// Set, this recorder refuses to load with its value for a reason: how a test
/// sees a capture carry on without it.
const REFUSE_ENV: &str = "SYSTING_PYTHON_FUNCTION_TRACE_REFUSE";

fn now_boottime() -> u64 {
    crate::session_recorder::get_clock_value(libc::CLOCK_BOOTTIME)
}

/// What is known of a process at the last look. A process with probes is also in
/// [`Tracer::files`], whatever it has exec'd into since.
enum Seen {
    Traced,
    /// Looked at again until [`NOT_PYTHON_FOR`] has passed: an exec comes before
    /// the loader has mapped libpython, and an embedder's name says nothing.
    NotPython {
        first: Instant,
    },
    Refused,
    /// Not there when looked at: a `pids` key can outlive its process.
    Gone,
}

/// Which processes have probes, and the probes.
struct Tracer<'obj, 'skel> {
    skel: &'skel skel::PythonFunctionTraceSkel<'obj>,
    psr: Arc<StackWalkerRun>,
    interpreters: InterpreterCache,
    seen: HashMap<u32, Seen>,
    /// By process with probes, the files they are on: the links outlive an
    /// exec, so one into a file already probed must not add more.
    files: HashMap<u32, HashSet<(u64, u64)>>,
    links: HashMap<u32, Vec<Link>>,
    started: HashMap<u32, u64>,
    gone: HashMap<u32, u64>,
    outcome: Outcome,
}

impl Tracer<'_, '_> {
    /// Registers `pid` with pystacks and, if it is a Python this can read, puts its
    /// probes in. Pystacks may have registered it already; that changes nothing.
    fn look_at(&mut self, pid: u32) {
        // Only a process that is there can be said not to be a Python.
        let Some(info) = discovery::check_python_process(pid as i32) else {
            let state = if is_running(pid) {
                let first = match self.seen.get(&pid) {
                    Some(Seen::NotPython { first }) => *first,
                    _ => Instant::now(),
                };
                Seen::NotPython { first }
            } else {
                // Fork passes pystacks' config on before anyone looks.
                self.psr.forget_pid(pid as i32);
                Seen::Gone
            };
            self.seen.insert(pid, state);
            return;
        };
        if !self.psr.register_pid(pid as i32, &info) {
            self.refuse(pid, "", "pystacks' table of processes is full");
            return;
        }
        if let Some(why) = why_not_traceable(pid) {
            self.refuse(pid, "", &why);
            return;
        }
        let (file, name, interpreter) = match interpreter_of(pid, &mut self.interpreters) {
            Ok(found) => found,
            Err(e) => {
                self.refuse(pid, "", &format!("{e:#}"));
                return;
            }
        };
        let sites = interpreter
            .check_build(info.version_major, info.version_minor)
            .and_then(|()| interpreter.dispatch_sites(info.version_major, info.version_minor));
        let sites = match sites {
            Ok(sites) => sites,
            Err(e) => {
                self.refuse(pid, &name, &format!("{e:#}"));
                return;
            }
        };
        let first_time = !self.files.contains_key(&pid);
        // A process that has gone holds no place.
        if first_time && self.files.len() - self.gone.len() >= MAX_PROCESSES {
            self.refuse(
                pid,
                &name,
                &format!("more than the {MAX_PROCESSES} processes one capture traces"),
            );
            return;
        }
        let Ok(meta) = file.metadata() else {
            self.refuse(pid, &name, "its interpreter file cannot be read");
            return;
        };
        let file_id = (meta.dev(), meta.ino());
        if !self.files.get(&pid).is_some_and(|f| f.contains(&file_id)) {
            match self.attach(pid, &file, &sites) {
                Ok(links) => self.links.entry(pid).or_default().extend(links),
                // Gone while it was looked at, which is no refusal.
                Err(_) if !is_running(pid) => return,
                Err(e) => {
                    self.refuse(pid, &name, &format!("{e:#}"));
                    return;
                }
            }
            self.files.entry(pid).or_default().insert(file_id);
        }
        if first_time {
            self.outcome.traced += 1;
            self.started.insert(pid, now_boottime());
        }
        for warning in warnings(pid) {
            self.warn(pid, warning);
        }
        eprintln!(
            "python-function-trace: process {pid}: Python {}.{}, {} probes in {name}",
            info.version_major,
            info.version_minor,
            sites.len()
        );
        self.seen.insert(pid, Seen::Traced);
    }

    /// Every site in, or none. The probes go into the file that was parsed:
    /// the kernel resolves this path to the descriptor's own file.
    fn attach(&self, pid: u32, file: &std::fs::File, sites: &[Site]) -> Result<Vec<Link>> {
        let binary = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
        let mut links = Vec::with_capacity(sites.len());
        for site in sites {
            let link = self
                .skel
                .progs
                .pyft_site
                .attach_uprobe_with_opts(
                    pid as i32,
                    &binary,
                    site.file_offset as usize,
                    UprobeOpts {
                        cookie: site.cookie(),
                        retprobe: false,
                        func_name: None,
                        ..Default::default()
                    },
                )
                .with_context(|| {
                    format!(
                        "Failed to attach at {} (+{:#x})",
                        site.name, site.file_offset
                    )
                })?;
            links.push(link);
        }
        Ok(links)
    }

    fn refuse(&mut self, pid: u32, name: &str, why: &str) {
        let line = if name.is_empty() {
            format!("process {pid}: {}", printable(why))
        } else {
            format!("process {pid} ({name}): {}", printable(why))
        };
        if !self.outcome.refused.contains(&line) {
            eprintln!("python-function-trace: not traced: {line}");
            if self.outcome.refused.len() < MAX_PROCESSES {
                self.outcome.refused.push(line);
            }
        }
        self.seen.insert(pid, Seen::Refused);
    }

    /// A process just forked or exec'd: looked at afresh, its time to become a
    /// Python starting over.
    fn on_event(&mut self, pid: u32) {
        self.seen.remove(&pid);
        self.look_at(pid);
    }

    /// Those still in the time they may yet become a Python.
    fn look_again(&mut self) {
        let again: Vec<u32> = self
            .seen
            .iter()
            .filter(|(_, seen)| {
                matches!(seen, Seen::NotPython { first } if first.elapsed() < NOT_PYTHON_FOR)
            })
            .map(|(pid, _)| *pid)
            .collect();
        for pid in again {
            self.look_at(pid);
        }
    }

    /// Processes no event told of: a child whose fork reached the target set but
    /// not pystacks (the parent mid-exec, a full ring), one moved into a target
    /// cgroup. The main object's `pids` map has every child of a target; with
    /// `--cgroup` a look at the cgroups finds the rest, less often.
    fn look_for_new(&mut self, opts: &Options, pids: BorrowedFd<'_>, walk_cgroups: bool) {
        let both = !opts.pids.is_empty() && !opts.cgroups.is_empty();
        let mut found: Vec<u32> = if both {
            Vec::new()
        } else {
            MapKeys::of(pids).collect()
        };
        // A cgroup made since the start counts only where the kernel decides: the
        // probes of a process in one would refuse it, and it would pay for nothing.
        if walk_cgroups && !opts.cgroups.is_empty() && opts.cgroup_match_kernel {
            if both {
                let mut in_cgroups = HashSet::new();
                for cgroup in &opts.cgroups {
                    crate::cgroup::collect_cgroup_procs(cgroup, &mut in_cgroups);
                }
                found.extend(MapKeys::of(pids).filter(|pid| in_cgroups.contains(pid)));
            } else {
                found.extend(targets(opts));
            }
        }
        for pid in found {
            if !self.seen.contains_key(&pid) {
                self.look_at(pid);
            }
        }
    }

    fn warn(&mut self, pid: u32, warning: String) {
        let line = format!("process {pid}: {warning}");
        if !self.outcome.warnings.contains(&line) {
            eprintln!("python-function-trace: warning: {line}");
            self.outcome.warnings.push(line);
        }
    }

    fn note_gone(&mut self) {
        let gone: Vec<u32> = self
            .files
            .keys()
            .filter(|pid| !self.gone.contains_key(pid) && !is_running(**pid))
            .copied()
            .collect();
        let mut links = Vec::new();
        for pid in gone {
            self.gone.insert(pid, now_boottime());
            self.psr.forget_pid(pid as i32);
            links.extend(self.links.remove(&pid).into_iter().flatten());
        }
        // Their probes cost nothing now, and taking them out waits on the kernel.
        if !links.is_empty() {
            thread::spawn(move || detach(links));
        }
    }

    /// What can change inside a process while it runs: its threads' names, for the
    /// `thread` table as task stacks read them, and whether it has loaded greenlet.
    fn look_inside(&mut self, names: &mut PythonThreadNames, recorder: &SessionRecorder) {
        let pids: Vec<u32> = self
            .files
            .keys()
            .filter(|pid| !self.gone.contains_key(pid))
            .copied()
            .collect();
        for pid in pids {
            let seen = threads_of(pid);
            let read = names.read(pid, &seen, &seen);
            if !read.is_empty() {
                recorder.note_py_thread_names(pid as i32, read);
            }
            // Its maps can be long, and reading them takes the lock its probes
            // may wait on: once it has said yes, that is that.
            let line = format!("process {pid}: {GREENLET_WARNING}");
            if !self.outcome.warnings.contains(&line) && has_greenlet(pid) == Some(true) {
                self.warn(pid, GREENLET_WARNING.to_string());
            }
        }
    }
}

fn threads_of(pid: u32) -> HashSet<i32> {
    std::fs::read_dir(format!("/proc/{pid}/task"))
        .map(|tasks| {
            tasks
                .flatten()
                .filter_map(|t| t.file_name().to_str()?.parse().ok())
                .collect()
        })
        .unwrap_or_default()
}

/// Takes `links` out side by side: see [`DETACH_THREADS`].
fn detach(links: Vec<Link>) {
    let mut lots: Vec<Vec<Link>> = (0..DETACH_THREADS).map(|_| Vec::new()).collect();
    for (i, link) in links.into_iter().enumerate() {
        lots[i % DETACH_THREADS].push(link);
    }
    thread::scope(|scope| {
        for lot in lots.into_iter().filter(|lot| !lot.is_empty()) {
            scope.spawn(move || drop(lot));
        }
    });
}

fn run(
    opts: &Options,
    filter: TargetFilter,
    fds: SharedFds,
    stop: &AtomicBool,
    ready: &SyncSender<()>,
    begin: Receiver<Begin>,
    notified: Receiver<u32>,
) -> Result<Finished> {
    let mut storage = MaybeUninit::uninit();
    let mut open_skel = skel::PythonFunctionTraceSkelBuilder::default()
        .open(&mut storage)
        .context("Failed to open the Python function trace BPF object")?;
    configure(&mut open_skel, opts.nr_rings, opts.wakeup_bytes, &filter)?;
    {
        let m = &mut open_skel.maps;
        TargetFilterMaps {
            cgroup_targets: fds.cgroup_targets.as_fd(),
            cgroup_target_refs: fds.cgroup_target_refs.as_fd(),
            cgroups: fds.cgroups.as_fd(),
            pids: fds.pids.as_fd(),
        }
        .reuse_in(
            &mut m.cgroup_targets,
            &mut m.cgroup_target_refs,
            &mut m.cgroups,
            &mut m.pids,
        )?;
        for (map, fd) in [
            (&mut m.targeted_pids, &fds.targeted_pids),
            (&mut m.pystacks_pid_config, &fds.pid_config),
            (&mut m.pystacks_binaryid_config, &fds.binaryid_config),
            (&mut m.pystacks_symbols, &fds.symbols),
            (&mut m.pystacks_ending_frames, &fds.ending_frames),
            (
                &mut m.pystacks_ending_frame_qualnames,
                &fds.ending_frame_qualnames,
            ),
            (&mut m.python_function_ringbufs, &fds.rings),
            (&mut m.missed_events, &fds.missed),
        ] {
            map.reuse_fd(fd.as_fd())
                .with_context(|| format!("Failed to reuse the {:?} map", map.name()))?;
        }
    }
    let skel = open_skel
        .load()
        .context("Failed to load the Python function trace BPF object")?;
    drop(fds);
    let _exec_link = skel
        .progs
        .pyft_exec
        .attach()
        .context("Failed to attach to sched_process_exec")?;
    // Only a capture that stopped waiting has hung up.
    let _ = ready.send(());

    let mut finished = Finished {
        started: HashMap::new(),
        gone: HashMap::new(),
        outcome: Outcome::default(),
        max_slices: opts.max_slices,
    };
    // A capture stopped before pystacks was up: nothing has been attached.
    let Ok((psr, recorder, begun)) = begin.recv() else {
        return Ok(finished);
    };
    let mut tracer = Tracer {
        skel: &skel,
        psr: psr.clone(),
        interpreters: HashMap::new(),
        seen: HashMap::new(),
        files: HashMap::new(),
        links: HashMap::new(),
        started: HashMap::new(),
        gone: HashMap::new(),
        outcome: Outcome::default(),
    };
    for pid in targets(opts) {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        tracer.look_at(pid);
    }
    let _ = begun.send(());
    let pids_map =
        libbpf_rs::MapHandle::try_from(&skel.maps.pids).context("Failed to get the target pids")?;
    let mut thread_names = PythonThreadNames::new(psr);
    let (mut last_housekeeping, mut last_look_inside) = (Instant::now(), Instant::now());
    let (mut last_look_for_new, mut last_look_again) = (Instant::now(), Instant::now());
    let mut capped = false;
    while !stop.load(Ordering::Relaxed) && !capped {
        match notified.recv_timeout(Duration::from_millis(10)) {
            Ok(pid) => tracer.on_event(pid),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        if last_look_again.elapsed() >= LOOK_AGAIN_EVERY {
            last_look_again = Instant::now();
            tracer.look_again();
        }
        if last_look_for_new.elapsed() >= LOOK_FOR_NEW_EVERY {
            last_look_for_new = Instant::now();
            tracer.look_for_new(opts, pids_map.as_fd(), false);
        }
        if last_housekeeping.elapsed() >= HOUSEKEEP_EVERY {
            last_housekeeping = Instant::now();
            tracer.note_gone();
            // A ring is read only when half full, so what has been read says
            // nothing yet: the kernel's own count does.
            capped = read_counters(&skel.maps.pyft_counters).begun >= opts.max_slices as u64;
        }
        if last_look_inside.elapsed() >= LOOK_INSIDE_EVERY {
            last_look_inside = Instant::now();
            tracer.look_for_new(opts, pids_map.as_fd(), true);
            tracer.look_inside(&mut thread_names, &recorder);
        }
    }
    // Before anything else, however long what follows may take: every Python
    // call of every traced process pays while they are in.
    detach(
        std::mem::take(&mut tracer.links)
            .into_values()
            .flatten()
            .collect(),
    );

    tracer.outcome.kernel = read_counters(&skel.maps.pyft_counters);
    tracer.outcome.cap_reached = tracer.outcome.kernel.begun >= opts.max_slices as u64;
    tracer.look_inside(&mut thread_names, &recorder);
    for line in unfound_targets(opts, &tracer) {
        eprintln!("python-function-trace: not traced: {line}");
        tracer.outcome.refused.push(line);
    }
    finished.started = tracer.started;
    finished.gone = tracer.gone;
    finished.outcome = tracer.outcome;
    Ok(finished)
}

/// A process named on the command line that never had probes and was not refused
/// says so too: a mistyped pid should not read as a process with nothing to show.
fn unfound_targets(opts: &Options, tracer: &Tracer<'_, '_>) -> Vec<String> {
    opts.pids
        .iter()
        .filter(|pid| !tracer.files.contains_key(pid))
        .filter_map(|pid| match tracer.seen.get(pid) {
            Some(Seen::Refused | Seen::Traced) => None,
            // A short command can be over before its image was seen as a Python.
            Some(Seen::NotPython { .. }) if !is_running(*pid) => Some(format!(
                "process {pid}: gone before it was seen to be a Python"
            )),
            Some(Seen::NotPython { .. }) => Some(format!(
                "process {pid}: not a Python pystacks could register"
            )),
            Some(Seen::Gone) | None => Some(format!("process {pid}: not there, or not readable")),
        })
        .collect()
}

/// What this object is told before load, by a capture and by the load-shape test
/// alike: which of its paths the verifier walks follows from these constants.
fn configure(
    open_skel: &mut skel::OpenPythonFunctionTraceSkel<'_>,
    nr_rings: u32,
    wakeup_bytes: u64,
    filter: &TargetFilter,
) -> Result<()> {
    let rodata = open_skel
        .maps
        .rodata_data
        .as_deref_mut()
        .context("The Python function trace BPF object has no rodata")?;
    rodata.pyft_nr_rings = nr_rings;
    rodata.pyft_wakeup_bytes = wakeup_bytes;
    set_target_filter!(rodata, filter);
    // pystacks' own configuration, as the main object's (see
    // PystacksMaps::configure_bss). Its symbol gate is shared, so a record sent
    // from here with no line table would keep one from the samplers' stacks.
    let bss = open_skel
        .maps
        .bss_data
        .as_deref_mut()
        .context("The Python function trace BPF object has no bss")?;
    bss.pystacks_prog_cfg.enable_py_src_lines.write(true);
    shrink_unused_maps(open_skel)
}

/// What `pystacks.bpf.c` brings along for a sampler and these programs do not
/// use: its own symbol ring and rate limiter.
fn shrink_unused_maps(open_skel: &mut skel::OpenPythonFunctionTraceSkel<'_>) -> Result<()> {
    // SAFETY: sysconf reads a constant of the running system.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u32;
    open_skel
        .maps
        .ringbuf_pysym_events
        .set_max_entries(page)
        .context("Failed to shrink the pystacks symbol ring")?;
    open_skel
        .maps
        .pystacks_emitted_cache
        .set_max_entries(1)
        .context("Failed to shrink the pystacks symbol cache")?;
    Ok(())
}

/// The target filters a capture can load this object with, for the load-shape
/// test: each one is a path the verifier walks and the others prune.
pub fn load_probe_filters() -> [(&'static str, TargetFilter); 5] {
    [
        (
            "python-function-trace-pid",
            TargetFilter {
                filter_pid: true,
                ..Default::default()
            },
        ),
        (
            "python-function-trace-cgroup",
            TargetFilter {
                filter_cgroup: true,
                cgroup_match_kernel: true,
                num_cgroup_targets: 1,
                ..Default::default()
            },
        ),
        (
            "python-function-trace-cgroup-legacy",
            TargetFilter {
                filter_cgroup: true,
                num_cgroup_targets: 1,
                ..Default::default()
            },
        ),
        (
            "python-function-trace-pid-and-cgroup",
            TargetFilter {
                filter_pid: true,
                filter_cgroup: true,
                cgroup_match_kernel: true,
                num_cgroup_targets: 1,
            },
        ),
        (
            "python-function-trace-pid-and-cgroup-legacy",
            TargetFilter {
                filter_pid: true,
                filter_cgroup: true,
                num_cgroup_targets: 1,
                ..Default::default()
            },
        ),
    ]
}

/// Loads this object's programs and nothing else (no map is shared, no probe
/// attached): for the load-shape test, which runs it on every kernel of CI's
/// matrix and on its native arm64 runner. `log_level` gives the verifier log level per program.
pub fn load_probe(
    filter: &TargetFilter,
    log_level: &dyn Fn(&str) -> u32,
) -> Result<crate::bpf_load_shapes::LoadReport> {
    let probe = crate::systing_core::probe_lock();
    let mut storage = MaybeUninit::uninit();
    let mut open_skel = skel::PythonFunctionTraceSkelBuilder::default()
        .open(&mut storage)
        .context("Failed to open the Python function trace BPF object")?;
    configure(&mut open_skel, 8, 1 << 20, filter)?;
    let mut autoloaded = Vec::new();
    for mut prog in open_skel.open_object_mut().progs_mut() {
        let name = prog.name().to_string_lossy().into_owned();
        let level = log_level(&name);
        if level > 0 {
            prog.set_log_level(level);
        }
        autoloaded.push(name);
    }
    let (load_result, log) = crate::systing_core::capture_libbpf_print(&probe, || open_skel.load());
    let outcome = match load_result {
        Ok(skel) => Ok(skel
            .object()
            .progs()
            .map(|p| (p.name().to_string_lossy().into_owned(), p.insn_cnt()))
            .collect()),
        Err(e) => Err(format!("{e:#}")),
    };
    Ok(crate::bpf_load_shapes::LoadReport::from_load(
        autoloaded,
        Vec::new(),
        &log,
        outcome,
    ))
}

const GREENLET_UNKNOWN: &str = "the process's maps could not be read in full, so whether greenlet \
     is loaded is not known";
const GREENLET_WARNING: &str = "greenlet is loaded: a switch between greenlets is not seen, so \
     frames that are only switched out end as \"unwound\" and their callers' times are wrong";

/// The most of `/proc/PID/maps` read to look for greenlet (the process
/// chooses how long its maps are).
const MAPS_READ_CAP: u64 = 8 << 20;

/// Whether process `pid` has a greenlet module mapped: `None` when that is
/// not known, because the maps could not be read or are longer than
/// [`MAPS_READ_CAP`].
fn has_greenlet(pid: u32) -> Option<bool> {
    let file = std::fs::File::open(format!("/proc/{pid}/maps")).ok()?;
    greenlet_in(file, MAPS_READ_CAP)
}

fn greenlet_in(maps: impl std::io::Read, cap: u64) -> Option<bool> {
    use std::io::Read as _;
    let mut bytes = Vec::new();
    // One byte past the cap tells a file of exactly the cap from a longer one.
    maps.take(cap + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > cap {
        return None;
    }
    Some(bytes.windows(b"greenlet".len()).any(|w| w == b"greenlet"))
}

/// Whether `pid` is a process that can still run code: there, and not a
/// zombie waiting to be reaped. Read as bytes: the command name before the
/// state is the process's choice and need not be UTF-8.
fn is_running(pid: u32) -> bool {
    std::fs::read(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        let Some(close) = stat.iter().rposition(|b| *b == b')') else {
            return false;
        };
        stat[close + 1..]
            .iter()
            .find(|b| !b.is_ascii_whitespace())
            .is_some_and(|state| *state != b'Z' && *state != b'X')
    })
}

/// What could make this trace of `pid` wrong, to say before it starts.
fn warnings(pid: u32) -> Vec<String> {
    let mut out = Vec::new();
    match has_greenlet(pid) {
        Some(true) => out.push(GREENLET_WARNING.to_string()),
        Some(false) => {}
        None => out.push(GREENLET_UNKNOWN.to_string()),
    }
    let environ = std::fs::File::open(format!("/proc/{pid}/environ")).and_then(|f| {
        // The process chooses its environment's length: read 1 MiB at most.
        use std::io::Read as _;
        let mut environ = Vec::new();
        f.take(1 << 20).read_to_end(&mut environ).map(|_| environ)
    });
    if let Ok(environ) = environ {
        let jit = environ
            .split(|b| *b == 0)
            .any(|v| v.starts_with(b"PYTHON_JIT=") && v != b"PYTHON_JIT=0");
        if jit {
            out.push(
                "PYTHON_JIT is set: calls inside code the JIT compiled are not seen".to_string(),
            );
        }
    }
    out
}

fn read_counters(map: &impl MapCore) -> KernelCounters {
    let read = |index: u32| -> u64 {
        map.lookup_percpu(&index.to_ne_bytes(), MapFlags::ANY)
            .ok()
            .flatten()
            .map(|per_cpu| {
                per_cpu
                    .iter()
                    .filter_map(|v| v.get(..8))
                    .map(|v| u64::from_ne_bytes(v.try_into().unwrap()))
                    .sum()
            })
            .unwrap_or(0)
    };
    KernelCounters {
        events: read(0),
        no_thread_state: read(1),
        no_frame: read(2),
        no_code: read(3),
        symbol_reads: read(4),
        symbol_records: read(5),
        symbol_records_dropped: read(6),
        symbol_busy: read(7),
        begun: read(8),
        hits: read(9),
        not_targeted: read(10),
        no_config: read(11),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_longer_than_the_cap_leave_greenlet_unknown() {
        use super::greenlet_in;
        let lib = b"7f00-7f01 r-xp 0 08:01 1 /x/_greenlet.so\n";
        assert_eq!(greenlet_in(&lib[..], 1 << 10), Some(true));
        assert_eq!(
            greenlet_in(&b"7f00-7f01 r-xp 0 08:01 1 /x/libc.so\n"[..], 1 << 10),
            Some(false)
        );
        // greenlet after the cap: not seen, so not known either way.
        let mut long = vec![b'a'; 64];
        long.extend_from_slice(lib);
        assert_eq!(greenlet_in(&long[..], 64), None);
        // Exactly the cap is read in full.
        assert_eq!(greenlet_in(&lib[..], lib.len() as u64), Some(true));
    }

    #[test]
    fn what_the_process_names_cannot_drive_a_terminal_or_split_a_line() {
        assert_eq!(printable("app:handler"), "app:handler");
        assert_eq!(printable("caf\u{e9}"), "caf\u{e9}");
        assert_eq!(printable("a\x1b[2Jb"), "a\\u{1b}[2Jb");
        assert_eq!(printable("f\tg\nh\ri"), "f\\tg\\nh\\ri");
        assert_eq!(printable("x\u{202e}y\u{9b}z"), "x\\u{202e}y\\u{9b}z");
        // Line and paragraph separators, a word joiner, a byte-order mark.
        assert_eq!(
            printable("a\u{2028}b\u{2029}c\u{2060}d\u{feff}e"),
            "a\\u{2028}b\\u{2029}c\\u{2060}d\\u{feff}e"
        );
        assert_eq!(printable("\u{65e5}\u{672c}"), "\u{65e5}\u{672c}");
        // A backslash is escaped too, so an escape in the output is always ours.
        assert_eq!(printable("a\\tb"), "a\\\\tb");
    }

    fn events(tgid: u32, begins: &[u64]) -> ThreadEvents {
        ThreadEvents {
            tgid,
            events: begins
                .iter()
                .map(|ts| Event {
                    ts: *ts,
                    kind: Kind::Enter as u8,
                    tgid,
                    ..Default::default()
                })
                .collect(),
        }
    }

    #[test]
    fn the_cutoff_is_in_time_whatever_order_the_rings_were_read_in() {
        let threads = HashMap::from([(1, events(1, &[50, 10, 30])), (2, events(2, &[40, 20]))]);
        assert_eq!(slice_cutoff(&threads, &HashMap::new(), 3), Some(30));
        // Not more than the cap: no cutoff.
        assert_eq!(slice_cutoff(&threads, &HashMap::new(), 5), None);
        // Events from before a process's probes were in are not slices.
        let started = HashMap::from([(1, 25)]);
        assert_eq!(slice_cutoff(&threads, &started, 3), Some(40));
    }

    #[test]
    fn musl_is_told_by_its_loader_and_library_names() {
        assert!(is_musl_library("/lib/ld-musl-x86_64.so.1"));
        assert!(is_musl_library("/usr/lib/libc.musl-aarch64.so.1"));
        assert!(!is_musl_library("/lib/x86_64-linux-gnu/libc.so.6"));
        assert!(!is_musl_library("/home/musl/libpython3.13.so"));
    }

    #[test]
    fn a_cgroup_narrows_named_processes_and_names_alone_are_taken_as_given() {
        let opts = Options {
            pids: vec![5, 3, 5],
            ..Default::default()
        };
        assert_eq!(targets(&opts), [3, 5]);
        let empty = tempfile::tempdir().unwrap();
        let narrowed = Options {
            cgroups: vec![empty.path().to_path_buf()],
            ..opts
        };
        assert!(targets(&narrowed).is_empty());
    }

    #[test]
    fn the_wire_event_is_the_size_bpf_writes() {
        assert_eq!(std::mem::size_of::<WireEvent>(), 64);
    }
}
