//! The task-stacks recorder: periodic snapshots of every targeted thread's
//! stack, taken with a sleepable BPF task iterator (`src/bpf/task_stacks.bpf.c`).
//!
//! Each iteration creates a fresh seq file from the iterator link and reads it
//! to the end; the kernel runs the BPF program once per thread on the host,
//! and the program writes one record per targeted thread: its identity, its
//! user/system CPU time since its last record, its state, and its kernel,
//! native user and Python frames (per [`TaskStackMode`]). A thread that has
//! used no CPU time and sits in the same non-runnable state as at its last
//! record cannot have changed its stack: for it the program skips the walk and
//! writes a bare header flagged unchanged. The stacks are symbolized with the
//! stack recorder's at the end of the capture. In Python-only mode a thread
//! without Python frames is left out.
//!
//! A thread's records become events. A full record opens one, from the start
//! of its iteration; an unchanged record extends the thread's open event by
//! an iteration; the next full record, or an iteration that does not see the
//! thread, closes it at that iteration's start (the capture's end closes the
//! last). So an event spans `start_iteration..=end_iteration`.
//!
//! The events are the `task_stack_event` table, one row each, with the stack
//! by id into the `stack` table like every other recorder's. Drawing them is
//! the Perfetto converter's business (`parquet_to_perfetto.rs`).

use std::collections::HashMap;
use std::io::Read;
use std::mem::MaybeUninit;
use std::os::fd::BorrowedFd;
use std::path::Path;
use std::sync::mpsc::{channel, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use libbpf_rs::skel::{OpenSkel, SkelBuilder};

use crate::pystacks::stack_walker::{PyAddr, StackWalkerRun};
use crate::record::RecordCollector;
use crate::session_recorder::{get_clock_value, SessionRecorder};
use crate::stack_recorder::{Stack, StackInterner};
use crate::systing_core::types::pystacks_message;
use crate::systing_core::{task_info, TaskSightings};
use crate::target_filter::{set_target_filter, TargetFilter, TargetFilterMaps};
use crate::trace::TaskStackEventRecord;
use crate::utid::UtidGenerator;

#[allow(
    clippy::all,
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals,
    dead_code,
    unused_imports
)]
mod skel {
    include!(concat!(env!("OUT_DIR"), "/task_stacks.skel.rs"));
}

use skel::types::task_stacks_event;

// SAFETY: task_stacks_event is a #[repr(C)] struct of integers and byte
// arrays without padding, so every byte pattern is a valid value.
unsafe impl plain::Plain for task_stacks_event {}

/// First id of the task-stacks recorder's stack ids: the stack recorder's
/// own start at 1 and the memory recorder's at `MEMORY_STACK_ID_OFFSET`.
const TASK_STACKS_STACK_ID_OFFSET: i64 = 2_000_000_000;

/// Most frames BPF emits per stack segment (TASK_STACKS_MAX_DEPTH).
const MAX_FRAMES: usize = 127;

/// Which stacks the recorder collects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskStackMode {
    /// Kernel and native user frames.
    Native,
    /// Kernel, native user and Python frames (`--collect-pystacks`).
    Merged,
    /// Python frames only (`--only-pystacks`).
    PythonOnly,
}

impl TaskStackMode {
    pub fn from_flags(collect_pystacks: bool, only_pystacks: bool) -> Self {
        match (collect_pystacks, only_pystacks) {
            (_, true) => TaskStackMode::PythonOnly,
            (true, false) => TaskStackMode::Merged,
            (false, false) => TaskStackMode::Native,
        }
    }

    fn native(self) -> bool {
        self != TaskStackMode::PythonOnly
    }

    fn python(self) -> bool {
        self != TaskStackMode::Native
    }

    /// Whether a thread is recorded in an iteration that found it `has_stack`.
    /// Python-only mode is about the Python threads: one with no Python frames
    /// gets no slice, and so, if it never has any, no track. The other modes
    /// record every targeted thread, with its CPU time and state, stack or not.
    fn records(self, has_stack: bool) -> bool {
        has_stack || self != TaskStackMode::PythonOnly
    }
}

/// The main object's pystacks maps, which the task-stacks object reuses so it
/// shares pystacks' Python process discovery (pid and binary configs, target
/// pids) and symbol interning (gate map, symbol ringbuf, emission cache). Only
/// the per-CPU scratch heaps are the object's own.
pub struct SharedPystacksMaps<'a> {
    pub targeted_pids: BorrowedFd<'a>,
    pub pid_config: BorrowedFd<'a>,
    pub binaryid_config: BorrowedFd<'a>,
    pub symbols: BorrowedFd<'a>,
    pub pysym_events: BorrowedFd<'a>,
    pub emitted_cache: BorrowedFd<'a>,
    pub ending_frames: BorrowedFd<'a>,
    pub ending_frame_qualnames: BorrowedFd<'a>,
}

impl SharedPystacksMaps<'_> {
    fn reuse_in(&self, m: &mut skel::OpenTaskStacksMaps<'_>) -> Result<()> {
        for (map, fd) in [
            (&mut m.targeted_pids, self.targeted_pids),
            (&mut m.pystacks_pid_config, self.pid_config),
            (&mut m.pystacks_binaryid_config, self.binaryid_config),
            (&mut m.pystacks_symbols, self.symbols),
            (&mut m.ringbuf_pysym_events, self.pysym_events),
            (&mut m.pystacks_emitted_cache, self.emitted_cache),
            (&mut m.pystacks_ending_frames, self.ending_frames),
            (
                &mut m.pystacks_ending_frame_qualnames,
                self.ending_frame_qualnames,
            ),
        ] {
            map.reuse_fd(fd)
                .with_context(|| format!("Failed to reuse the {:?} map", map.name()))?;
        }
        Ok(())
    }
}

fn tid(task: &task_info) -> u32 {
    task.tgidpid as u32
}

fn tgid(task: &task_info) -> u32 {
    (task.tgidpid >> 32) as u32
}

/// The kernel's one-letter name for a task state (`__state | exit_state`),
/// as `/proc/<pid>/stat` and ftrace print it.
fn state_name(state: u32) -> &'static str {
    const TASK_REPORT: u32 = 0x7f;
    const TASK_IDLE: u32 = 0x402; // TASK_UNINTERRUPTIBLE | TASK_NOLOAD
    if state & TASK_IDLE == TASK_IDLE {
        return "I";
    }
    let report = state & TASK_REPORT;
    ["R", "S", "D", "T", "t", "X", "Z", "P"][(u32::BITS - report.leading_zeros()) as usize]
}

/// `task_stacks_event.flags`: the thread's last record still stands, and no
/// stacks follow this one (TASK_STACKS_UNCHANGED).
const FLAG_UNCHANGED: u32 = 1;

/// One thread as an iteration saw it.
pub struct TaskSample {
    pub task: task_info,
    /// BPF found the thread as its last full record left it, and sent no
    /// stacks.
    pub unchanged: bool,
    /// Nanoseconds of user / system CPU time since the thread's last full
    /// record (0 the first time).
    pub utime_delta: u64,
    pub stime_delta: u64,
    /// `__state | exit_state`.
    pub state: u32,
    /// Leaf first, as the kernel and the unwinder deliver them.
    pub kernel_stack: Vec<u64>,
    pub user_stack: Vec<u64>,
    pub py_msg: Option<Box<pystacks_message>>,
}

impl TaskSample {
    /// The thread's stack as `mode` collects it; `None` when it has no frames.
    fn stack(&self, mode: TaskStackMode, psr: &StackWalkerRun) -> Option<Stack> {
        let py: Vec<PyAddr> = match &self.py_msg {
            Some(msg) if mode.python() => {
                psr.get_pystack_from_buffer(msg, u64::from(tgid(&self.task)))
            }
            _ => Vec::new(),
        };
        let (kernel, user): (&[u64], &[u64]) = if mode.native() {
            (&self.kernel_stack, &self.user_stack)
        } else {
            (&[], &[])
        };
        let stack = Stack::new(kernel, user, &py);
        let empty = stack.kernel_stack.is_empty()
            && stack.user_stack.is_empty()
            && stack.py_stack.is_empty();
        (!empty).then_some(stack)
    }
}

fn read_frames(bytes: &[u8]) -> Vec<u64> {
    bytes
        .chunks_exact(8)
        .map(|c| u64::from_ne_bytes(c.try_into().expect("8-byte chunk")))
        .collect()
}

/// A pystacks_message from the first `bytes.len()` bytes BPF emitted of one;
/// the rest (the unused frame slots) stays zero.
fn read_py_msg(bytes: &[u8]) -> Box<pystacks_message> {
    // SAFETY: pystacks_message is a #[repr(C)] struct of integers and arrays
    // of them, for which all-zero bytes, and any bytes, are a valid value;
    // the caller bounds `bytes` by its size.
    let mut msg: Box<pystacks_message> = Box::new(unsafe { std::mem::zeroed() });
    let dst = unsafe {
        std::slice::from_raw_parts_mut(
            &mut *msg as *mut pystacks_message as *mut u8,
            std::mem::size_of::<pystacks_message>(),
        )
    };
    dst[..bytes.len()].copy_from_slice(bytes);
    msg
}

/// Parse the records one iterator read produced: each a task_stacks_event,
/// its kernel and user frames, then its pystacks_message bytes.
fn parse_records(buf: &[u8]) -> Result<Vec<TaskSample>> {
    let header = std::mem::size_of::<task_stacks_event>();
    let mut samples = Vec::new();
    let mut off = 0;
    while off < buf.len() {
        if buf.len() - off < header {
            bail!("task-stacks record header truncated at byte {off}");
        }
        let mut e = task_stacks_event::default();
        plain::copy_from_bytes(&mut e, &buf[off..off + header])
            .map_err(|e| anyhow::anyhow!("task-stacks record header: {e:?}"))?;
        off += header;

        let (klen, ulen, py_len) = (
            e.kernel_stack_len as usize,
            e.user_stack_len as usize,
            e.py_len as usize,
        );
        if klen > MAX_FRAMES
            || ulen > MAX_FRAMES
            || py_len > std::mem::size_of::<pystacks_message>()
        {
            bail!("task-stacks record lengths out of range ({klen}, {ulen}, {py_len})");
        }
        let body = (klen + ulen) * 8 + py_len;
        if buf.len() - off < body {
            bail!("task-stacks record body truncated at byte {off}");
        }
        let kernel_stack = read_frames(&buf[off..off + klen * 8]);
        off += klen * 8;
        let user_stack = read_frames(&buf[off..off + ulen * 8]);
        off += ulen * 8;
        let py_msg = (py_len > 0).then(|| read_py_msg(&buf[off..off + py_len]));
        off += py_len;

        samples.push(TaskSample {
            task: task_info {
                tgidpid: e.task.tgidpid,
                cgid: e.task.cgid,
                comm: e.task.comm,
            },
            unchanged: e.flags & FLAG_UNCHANGED != 0,
            utime_delta: e.utime_delta,
            stime_delta: e.stime_delta,
            state: e.state,
            kernel_stack,
            user_stack,
            py_msg,
        });
    }
    Ok(samples)
}

/// The loaded and attached task iterator.
///
/// Only the link is kept: it holds the kernel's references to the program
/// (and the program to its maps), so the skeleton it came from can go.
pub struct TaskStacksIter {
    link: libbpf_rs::Link,
}

impl TaskStacksIter {
    /// Load the iterator with the capture's targeting, reading the main
    /// object's target and pystacks maps, collecting the stacks `mode` names.
    pub fn load(
        filter: &TargetFilter,
        maps: &TargetFilterMaps<'_>,
        pystacks_maps: &SharedPystacksMaps<'_>,
        mode: TaskStackMode,
    ) -> Result<Self> {
        let mut storage = MaybeUninit::uninit();
        let mut open_skel = skel::TaskStacksSkelBuilder::default()
            .open(&mut storage)
            .context("Failed to open the task-stacks BPF object")?;

        let rodata = open_skel
            .maps
            .rodata_data
            .as_deref_mut()
            .expect("'rodata' is not mmap'ed, your kernel is too old");
        set_target_filter!(rodata, filter);
        rodata.task_stacks_config.collect_kernel = mode.native() as u32;
        rodata.task_stacks_config.collect_user = mode.native() as u32;
        rodata.task_stacks_config.collect_python = mode.python() as u32;

        // pystacks' own configuration, as the main object's (see
        // PystacksMaps::configure_bss): only the registered Python pids.
        if mode.python() {
            let bss = open_skel
                .maps
                .bss_data
                .as_deref_mut()
                .expect("'bss' is not mmap'ed, your kernel is too old");
            bss.pid_target_helpers_prog_cfg
                .has_targeted_pids
                .write(true);
            bss.pystacks_prog_cfg.enable_py_src_lines.write(true);
            bss.pystacks_prog_cfg.stack_max_len = MAX_FRAMES as u32;
        }

        let m = &mut open_skel.maps;
        maps.reuse_in(
            &mut m.cgroup_targets,
            &mut m.cgroup_target_refs,
            &mut m.cgroups,
            &mut m.pids,
        )
        .context("Failed to share the target maps with the task-stacks iterator")?;
        pystacks_maps
            .reuse_in(m)
            .context("Failed to share the pystacks maps with the task-stacks iterator")?;

        let skel = open_skel.load().context(
            "Failed to load the task-stacks BPF iterator (needs sleepable task iterators)",
        )?;
        let link = skel
            .progs
            .systing_task_stacks
            .attach()
            .context("Failed to attach the task-stacks BPF iterator")?;
        Ok(Self { link })
    }

    /// Walk every thread once and return the targeted ones.
    pub fn snapshot(&self) -> Result<Vec<TaskSample>> {
        let mut iter =
            libbpf_rs::Iter::new(&self.link).context("Failed to create a task-stacks iterator")?;
        let mut buf = Vec::new();
        iter.read_to_end(&mut buf)
            .context("Failed to read the task-stacks iterator")?;
        parse_records(&buf)
    }
}

/// How many snapshots a capture of `duration` holds, one every `interval`
/// from its start: ceil(duration / interval), so 10 s at 1 s is 10. `None`
/// for an open-ended capture (zero duration).
pub fn iteration_count(duration: Duration, interval: Duration) -> Option<u64> {
    if duration.is_zero() {
        return None;
    }
    Some(duration.as_nanos().div_ceil(interval.as_nanos().max(1)) as u64)
}

/// The snapshot thread: takes a snapshot every `interval`, numbered from 1,
/// until stopped or until `max_iterations` have been taken.
pub struct TaskStacksThread {
    stop_tx: Sender<()>,
    handle: thread::JoinHandle<()>,
}

impl TaskStacksThread {
    pub fn spawn(
        iter: TaskStacksIter,
        interval: Duration,
        max_iterations: Option<u64>,
        mode: TaskStackMode,
        psr: Arc<StackWalkerRun>,
        recorder: Arc<SessionRecorder>,
        task_info_tx: Sender<task_info>,
    ) -> Result<Self> {
        let (stop_tx, stop_rx) = channel::<()>();
        let handle = thread::Builder::new()
            .name("task_stacks".to_string())
            .spawn(move || {
                let mut seen_tasks = TaskSightings::new();
                let mut next = Instant::now();
                for iteration in 1u64.. {
                    // The iteration starts when its walk does (the trace clock).
                    let start = get_clock_value(libc::CLOCK_BOOTTIME);
                    let entries = match iter.snapshot() {
                        Ok(samples) => samples
                            .iter()
                            .filter_map(|sample| {
                                if sample.unchanged {
                                    return Some(SnapshotEntry::Unchanged {
                                        tid: tid(&sample.task) as i32,
                                    });
                                }
                                let stack = sample.stack(mode, &psr);
                                if !mode.records(stack.is_some()) {
                                    return None;
                                }
                                if seen_tasks.observe(&sample.task) {
                                    let _ = task_info_tx.send(sample.task);
                                }
                                Some(SnapshotEntry::Changed(TaskEntry {
                                    task: sample.task,
                                    utime_delta: sample.utime_delta,
                                    stime_delta: sample.stime_delta,
                                    state: sample.state,
                                    stack,
                                }))
                            })
                            .collect(),
                        Err(e) => {
                            eprintln!("task-stacks: iteration {iteration} failed: {e:#}");
                            Vec::new()
                        }
                    };
                    // Extends, closes and opens the threads' events, even
                    // when this iteration saw nothing.
                    recorder
                        .task_stacks_recorder
                        .lock()
                        .unwrap()
                        .record_snapshot(iteration, start, entries);

                    if max_iterations == Some(iteration) {
                        break;
                    }
                    next += interval;
                    match stop_rx.recv_timeout(next.saturating_duration_since(Instant::now())) {
                        Err(RecvTimeoutError::Timeout) => {}
                        _ => break,
                    }
                }
            })?;
        Ok(Self { stop_tx, handle })
    }

    /// Stop taking snapshots and wait for the thread to exit.
    pub fn stop(self) {
        drop(self.stop_tx);
        self.handle
            .join()
            .expect("Failed to join the task-stacks thread");
    }
}

/// One thread's full record, ready to record.
pub struct TaskEntry {
    pub task: task_info,
    pub utime_delta: u64,
    pub stime_delta: u64,
    pub state: u32,
    pub stack: Option<Stack>,
}

/// What an iteration has to say about one thread.
pub enum SnapshotEntry {
    /// A full record: the thread's next event.
    Changed(TaskEntry),
    /// The thread is as its last record left it: its open event, if it has
    /// one, runs on through this iteration.
    Unchanged { tid: i32 },
}

/// A thread as one full record found it, for as long as it stayed that way.
struct TaskEvent {
    /// The iteration whose record opened the event, and the last one that
    /// found the thread unchanged since.
    start_iteration: u64,
    end_iteration: u64,
    start: u64,
    /// The start of the iteration that replaced the event or did not see the
    /// thread; `None` while the event is open.
    end: Option<u64>,
    tid: i32,
    utime_delta: u64,
    stime_delta: u64,
    state: u32,
    stack_id: Option<i64>,
}

/// Collects the snapshots for the trace.
pub struct TaskStacksRecorder {
    events: Vec<TaskEvent>,
    /// The threads' open events, by tid: indexes into `events`.
    open: HashMap<i32, usize>,
    /// The unique stacks, symbolized by the stack recorder at the end.
    interner: StackInterner,
    utid_generator: Arc<UtidGenerator>,
}

impl TaskStacksRecorder {
    pub fn new(utid_generator: Arc<UtidGenerator>) -> Self {
        Self {
            events: Vec::new(),
            open: HashMap::new(),
            interner: StackInterner::new(TASK_STACKS_STACK_ID_OFFSET),
            utid_generator,
        }
    }

    /// Configure the directory for the unique-stack spill file. Must be
    /// called before recording starts; without it, stacks stay in memory.
    pub fn set_spill_dir(&mut self, dir: &Path) {
        self.interner.set_spill_dir(dir);
    }

    /// Drain the stack interner for hand-off to `StackRecorder`, which
    /// symbolizes the stacks into the shared `stack` table.
    pub(crate) fn take_interner(&mut self) -> StackInterner {
        std::mem::replace(
            &mut self.interner,
            StackInterner::new(TASK_STACKS_STACK_ID_OFFSET),
        )
    }

    /// Record an iteration that started at `start` (CLOCK_BOOTTIME, the trace
    /// clock): a thread it found unchanged keeps its open event, which now
    /// reaches this iteration; a thread it has a full record of gets a new
    /// one; and every other open event, of a thread with a new one or of a
    /// thread the iteration did not see, closes at `start`.
    pub fn record_snapshot(&mut self, iteration: u64, start: u64, entries: Vec<SnapshotEntry>) {
        let mut open = HashMap::with_capacity(entries.len());
        for entry in entries {
            match entry {
                // Nothing to extend when the thread's last record was left
                // out (Python-only mode, no Python frames): nor is there now.
                SnapshotEntry::Unchanged { tid } => {
                    if let Some(idx) = self.open.remove(&tid) {
                        self.events[idx].end_iteration = iteration;
                        open.insert(tid, idx);
                    }
                }
                SnapshotEntry::Changed(entry) => {
                    let stack_id = entry
                        .stack
                        .map(|stack| self.interner.intern(stack, tgid(&entry.task) as i32));
                    let tid = tid(&entry.task) as i32;
                    open.insert(tid, self.events.len());
                    self.events.push(TaskEvent {
                        start_iteration: iteration,
                        end_iteration: iteration,
                        start,
                        end: None,
                        tid,
                        utime_delta: entry.utime_delta,
                        stime_delta: entry.stime_delta,
                        state: entry.state,
                        stack_id,
                    });
                }
            }
        }
        for (_, idx) in self.open.drain() {
            self.events[idx].end = Some(start);
        }
        self.open = open;
    }

    pub fn has_data(&self) -> bool {
        !self.events.is_empty()
    }

    pub fn min_timestamp(&self) -> Option<u64> {
        self.events.iter().map(|e| e.start).min()
    }

    /// Write the events, in the order they began; the ones still open close
    /// at `capture_end`.
    pub fn write_records(
        &self,
        collector: &mut dyn RecordCollector,
        capture_end: u64,
    ) -> Result<()> {
        for event in &self.events {
            // max(): an iteration that raced the stop and began after the
            // capture closed ends where it began.
            let end = event.end.unwrap_or(capture_end).max(event.start);
            collector.add_task_stack_event(TaskStackEventRecord {
                ts: event.start as i64,
                dur: (end - event.start) as i64,
                utid: self.utid_generator.get_or_create_utid(event.tid),
                // Reserved: not populated yet.
                thread_name: None,
                start_iteration: event.start_iteration as i64,
                end_iteration: event.end_iteration as i64,
                utime_delta_ns: event.utime_delta as i64,
                stime_delta_ns: event.stime_delta as i64,
                state: state_name(event.state).to_string(),
                stack_id: event.stack_id,
            })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::InMemoryCollector;

    fn task(tgid: u32, tid: u32, comm: &str) -> task_info {
        let mut name = [0u8; 16];
        name[..comm.len()].copy_from_slice(comm.as_bytes());
        task_info {
            tgidpid: ((tgid as u64) << 32) | tid as u64,
            cgid: 0,
            comm: name,
        }
    }

    /// One BPF record: header, kernel and user frames, pystacks bytes.
    fn record_bytes(
        t: &task_info,
        flags: u32,
        deltas: (u64, u64),
        kernel: &[u64],
        user: &[u64],
        py: &[u8],
    ) -> Vec<u8> {
        let mut e = task_stacks_event::default();
        e.task.tgidpid = t.tgidpid;
        e.task.cgid = t.cgid;
        e.task.comm = t.comm;
        e.utime_delta = deltas.0;
        e.stime_delta = deltas.1;
        e.state = 1;
        e.flags = flags;
        e.kernel_stack_len = kernel.len() as u32;
        e.user_stack_len = user.len() as u32;
        e.py_len = py.len() as u32;
        let mut bytes = unsafe { plain::as_bytes(&e) }.to_vec();
        for frame in kernel.iter().chain(user) {
            bytes.extend_from_slice(&frame.to_ne_bytes());
        }
        bytes.extend_from_slice(py);
        bytes
    }

    fn changed(t: task_info, stack: Option<Stack>) -> SnapshotEntry {
        SnapshotEntry::Changed(TaskEntry {
            task: t,
            utime_delta: 0,
            stime_delta: 0,
            state: 0,
            stack,
        })
    }

    fn unchanged(t: task_info) -> SnapshotEntry {
        SnapshotEntry::Unchanged {
            tid: tid(&t) as i32,
        }
    }

    /// A recorder, and the utid its generator gives `tid`.
    fn recorder() -> (TaskStacksRecorder, impl Fn(u32) -> i64) {
        let utids = Arc::new(UtidGenerator::new());
        let recorder = TaskStacksRecorder::new(Arc::clone(&utids));
        (recorder, move |tid| utids.get_or_create_utid(tid as i32))
    }

    fn written(recorder: &TaskStacksRecorder, capture_end: u64) -> Vec<TaskStackEventRecord> {
        let mut collector = InMemoryCollector::new();
        recorder.write_records(&mut collector, capture_end).unwrap();
        collector.into_data().task_stack_events
    }

    /// (utid, ts, dur, start_iteration, end_iteration) of every event written.
    fn spans(events: &[TaskStackEventRecord]) -> Vec<(i64, i64, i64, i64, i64)> {
        events
            .iter()
            .map(|e| (e.utid, e.ts, e.dur, e.start_iteration, e.end_iteration))
            .collect()
    }

    #[test]
    fn iteration_count_fits_the_capture() {
        let secs = Duration::from_secs;
        assert_eq!(iteration_count(secs(10), secs(1)), Some(10));
        assert_eq!(iteration_count(secs(10), secs(3)), Some(4));
        assert_eq!(
            iteration_count(secs(3), Duration::from_millis(500)),
            Some(6)
        );
        assert_eq!(iteration_count(secs(1), secs(2)), Some(1));
        assert_eq!(iteration_count(Duration::ZERO, secs(1)), None);
    }

    #[test]
    fn stack_modes_select_the_bpf_legs() {
        use TaskStackMode::*;
        assert_eq!(TaskStackMode::from_flags(false, false), Native);
        assert_eq!(TaskStackMode::from_flags(true, false), Merged);
        assert_eq!(TaskStackMode::from_flags(true, true), PythonOnly);
        assert!(Native.native() && !Native.python());
        assert!(Merged.native() && Merged.python());
        assert!(!PythonOnly.native() && PythonOnly.python());
    }

    #[test]
    fn python_only_mode_skips_threads_without_python_frames() {
        use TaskStackMode::*;
        assert!(PythonOnly.records(true));
        assert!(!PythonOnly.records(false));
        // The other modes keep a thread whose stack came out empty: its CPU
        // time and state are still worth an event.
        for mode in [Native, Merged] {
            assert!(mode.records(true) && mode.records(false));
        }
    }

    #[test]
    fn state_names_match_the_kernel() {
        assert_eq!(state_name(0), "R");
        assert_eq!(state_name(0x1), "S");
        assert_eq!(state_name(0x2), "D");
        assert_eq!(state_name(0x4), "T");
        assert_eq!(state_name(0x8), "t");
        assert_eq!(state_name(0x10), "X");
        assert_eq!(state_name(0x20), "Z");
        assert_eq!(state_name(0x40), "P");
        assert_eq!(state_name(0x402), "I");
    }

    #[test]
    fn record_header_has_no_padding() {
        assert_eq!(std::mem::size_of::<task_stacks_event>(), 72);
    }

    #[test]
    fn parse_records_reads_frames_python_bytes_and_the_unchanged_flag() {
        let main = task(100, 100, "main");
        let worker = task(100, 101, "worker-1");
        let idle = task(100, 102, "idle");
        let py = [7u8; 40];
        let mut buf = record_bytes(&main, 0, (5, 6), &[0xfff1, 0xfff2], &[0x401000], &[]);
        buf.extend(record_bytes(
            &worker,
            0,
            (0, 0),
            &[],
            &[0x402000, 0x403000],
            &py,
        ));
        buf.extend(record_bytes(&idle, FLAG_UNCHANGED, (0, 0), &[], &[], &[]));
        let samples = parse_records(&buf).unwrap();
        assert_eq!(samples.len(), 3);

        assert_eq!(samples[0].task.comm, main.comm);
        assert!(!samples[0].unchanged);
        assert_eq!((samples[0].utime_delta, samples[0].stime_delta), (5, 6));
        assert_eq!(samples[0].kernel_stack, [0xfff1, 0xfff2]);
        assert_eq!(samples[0].user_stack, [0x401000]);
        assert!(samples[0].py_msg.is_none());

        assert_eq!(tid(&samples[1].task), 101);
        assert!(samples[1].kernel_stack.is_empty());
        assert_eq!(samples[1].user_stack, [0x402000, 0x403000]);
        let msg = samples[1].py_msg.as_ref().unwrap();
        let bytes = unsafe { plain::as_bytes(&**msg) };
        assert_eq!(&bytes[..40], &py[..]);
        assert!(bytes[40..].iter().all(|&b| b == 0));

        assert_eq!(tid(&samples[2].task), 102);
        assert!(samples[2].unchanged);
    }

    #[test]
    fn parse_records_rejects_truncated_records() {
        let t = task(1, 1, "x");
        let buf = record_bytes(&t, 0, (0, 0), &[1, 2], &[], &[]);
        assert!(parse_records(&buf[..buf.len() - 1]).is_err());
        assert!(parse_records(&buf[..10]).is_err());
        assert!(parse_records(&[]).unwrap().is_empty());
    }

    #[test]
    fn a_full_record_closes_the_event_before_it_and_the_capture_end_closes_the_last() {
        let (main, worker) = (task(10, 10, "main"), task(10, 11, "worker"));
        let (mut recorder, utid) = recorder();
        recorder.record_snapshot(1, 1_000, vec![changed(main, None), changed(worker, None)]);
        // The worker has exited by iteration 2: its event still closes here.
        recorder.record_snapshot(2, 2_000, vec![changed(main, None)]);
        assert_eq!(recorder.min_timestamp(), Some(1_000));

        assert_eq!(
            spans(&written(&recorder, 2_600)),
            [
                (utid(10), 1_000, 1_000, 1, 1),
                (utid(11), 1_000, 1_000, 1, 1),
                (utid(10), 2_000, 600, 2, 2),
            ]
        );
    }

    #[test]
    fn an_unchanged_thread_extends_its_event_instead_of_starting_one() {
        let (main, worker) = (task(10, 10, "main"), task(10, 11, "worker"));
        let (mut recorder, utid) = recorder();
        recorder.record_snapshot(1, 1_000, vec![changed(main, None), changed(worker, None)]);
        recorder.record_snapshot(2, 2_000, vec![unchanged(main), changed(worker, None)]);
        recorder.record_snapshot(3, 3_000, vec![unchanged(main), unchanged(worker)]);
        // main ran: a new event. The worker is gone: its event ends here.
        recorder.record_snapshot(4, 4_000, vec![changed(main, None)]);

        assert_eq!(
            spans(&written(&recorder, 4_500)),
            [
                // main's first event: iterations 1 to 3, up to 4's start.
                (utid(10), 1_000, 3_000, 1, 3),
                (utid(11), 1_000, 1_000, 1, 1),
                (utid(11), 2_000, 2_000, 2, 3),
                (utid(10), 4_000, 500, 4, 4),
            ]
        );
    }

    #[test]
    fn an_unchanged_thread_with_no_open_event_stays_out() {
        let t = task(10, 10, "main");
        let (mut recorder, _) = recorder();
        // Its full record was left out (Python-only mode, no Python frames).
        recorder.record_snapshot(1, 1_000, Vec::new());
        recorder.record_snapshot(2, 2_000, vec![unchanged(t)]);
        assert!(!recorder.has_data());
    }

    #[test]
    fn an_event_carries_its_deltas_state_and_stack() {
        let t = task(10, 10, "main");
        let stack = || Some(Stack::new(&[0xffff_ffff_8100_0000], &[0x401000], &[]));
        let (mut recorder, utid) = recorder();
        recorder.record_snapshot(
            1,
            1_000,
            vec![SnapshotEntry::Changed(TaskEntry {
                task: t,
                utime_delta: 300,
                stime_delta: 40,
                state: 0x2,
                stack: stack(),
            })],
        );
        // The same stack again: interned once. No stack: no id.
        recorder.record_snapshot(2, 2_000, vec![changed(t, stack())]);
        recorder.record_snapshot(3, 3_000, vec![changed(t, None)]);

        let events = written(&recorder, 4_000);
        assert_eq!(
            events[0],
            TaskStackEventRecord {
                ts: 1_000,
                dur: 1_000,
                utid: utid(10),
                thread_name: None,
                start_iteration: 1,
                end_iteration: 1,
                utime_delta_ns: 300,
                stime_delta_ns: 40,
                state: "D".to_string(),
                stack_id: Some(TASK_STACKS_STACK_ID_OFFSET),
            }
        );
        assert_eq!(events[1].stack_id, Some(TASK_STACKS_STACK_ID_OFFSET));
        assert_eq!(events[2].stack_id, None);
        assert_eq!(recorder.take_interner().total(), 1);
    }

    #[test]
    fn an_iteration_that_saw_nothing_still_closes_the_open_events() {
        let t = task(10, 10, "main");
        let (mut recorder, utid) = recorder();
        recorder.record_snapshot(1, 1_000, vec![changed(t, None)]);
        recorder.record_snapshot(2, 2_000, Vec::new());
        recorder.record_snapshot(3, 3_000, vec![changed(t, None)]);
        assert_eq!(
            spans(&written(&recorder, 3_500)),
            [(utid(10), 1_000, 1_000, 1, 1), (utid(10), 3_000, 500, 3, 3)]
        );
    }

    #[test]
    fn an_iteration_after_the_capture_end_closes_where_it_began() {
        let t = task(10, 10, "main");
        let (mut recorder, utid) = recorder();
        recorder.record_snapshot(1, 5_000, vec![changed(t, None)]);
        assert_eq!(
            spans(&written(&recorder, 4_000)),
            [(utid(10), 5_000, 0, 1, 1)]
        );
    }
}
