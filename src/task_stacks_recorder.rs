//! The task-stacks recorder: periodic snapshots of every targeted thread's
//! stack, taken with a sleepable BPF task iterator (`src/bpf/task_stacks.bpf.c`).
//!
//! Each iteration opens a fresh seq file on an iterator link and reads it to
//! the end; the kernel runs the BPF program once per thread the link covers,
//! and the program writes one record per targeted thread: its identity, its
//! user/system CPU time since its last record, its state, and its kernel,
//! native user and Python frames (per [`TaskStackFrames`]). A capture without
//! targets walks every thread on the host; one with `--pid` or `--cgroup`
//! targets walks their threads alone where the host allows it, a link per
//! target process ([`TaskWalk`]), and every thread on the host where it does
//! not, recording the same threads either way. A thread that has
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

use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::io::Read;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use libbpf_rs::libbpf_sys;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};

use crate::pystacks::stack_walker::{PyAddr, StackWalkerRun};
use crate::pystacks::thread_names::ThreadNames;
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

// The bytes this object's pystacks writes are read as the main object's
// pystacks_message (read_py_msg): the two compilations must agree on it.
const _: () = assert!(
    std::mem::size_of::<skel::types::pystacks_message>() == std::mem::size_of::<pystacks_message>()
);

/// First id of the task-stacks recorder's stack ids: the stack recorder's
/// own start at 1 and the memory recorder's at `MEMORY_STACK_ID_OFFSET`.
pub(crate) const TASK_STACKS_STACK_ID_OFFSET: i64 = 2_000_000_000;

/// Most frames BPF emits per stack segment (TASK_STACKS_MAX_DEPTH).
const MAX_FRAMES: usize = 127;

/// Which frames the recorder collects: `--task-stacks-frames`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskStackFrames {
    /// Kernel and native user frames.
    Native,
    /// Python frames only, and only the threads that have any.
    Python,
    /// Kernel, native user and Python frames.
    All,
}

impl std::str::FromStr for TaskStackFrames {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "native" => Ok(TaskStackFrames::Native),
            "python" => Ok(TaskStackFrames::Python),
            "all" => Ok(TaskStackFrames::All),
            other => Err(format!(
                "unknown task-stacks frames {other:?}: expected \"native\", \"python\" or \"all\""
            )),
        }
    }
}

impl TaskStackFrames {
    /// The frames to collect: the ones asked for, else what the capture as a
    /// whole collects, Python with `--collect-pystacks` and not without.
    pub fn resolve(asked: Option<Self>, collect_pystacks: bool) -> Self {
        asked.unwrap_or(if collect_pystacks {
            TaskStackFrames::All
        } else {
            TaskStackFrames::Native
        })
    }

    /// Whether these need the Python stack walker.
    pub fn needs_pystacks(self) -> bool {
        self.python()
    }

    fn native(self) -> bool {
        self != TaskStackFrames::Python
    }

    fn python(self) -> bool {
        self != TaskStackFrames::Native
    }

    /// Whether a thread is recorded in an iteration that found it `has_stack`.
    /// Python-only mode is about the Python threads: one with no Python frames
    /// gets no slice, and so, if it never has any, no track. The other modes
    /// record every targeted thread, with its CPU time and state, stack or not.
    fn records(self, has_stack: bool) -> bool {
        has_stack || self != TaskStackFrames::Python
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
    const TASK_RTLOCK_WAIT: u32 = 0x1000;
    const TASK_FROZEN: u32 = 0x8000;
    // Neither is in TASK_REPORT; the kernel reports both as uninterruptible
    // (__task_state_index()).
    if state & (TASK_RTLOCK_WAIT | TASK_FROZEN) != 0 {
        return "D";
    }
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
    /// record (0 the first time), which advance by scheduler ticks, and of
    /// time on a CPU, which is exact.
    pub utime_delta: u64,
    pub stime_delta: u64,
    pub runtime_delta: u64,
    /// `__state | exit_state`.
    pub state: u32,
    /// Leaf first, as the kernel and the unwinder deliver them.
    pub kernel_stack: Vec<u64>,
    pub user_stack: Vec<u64>,
    pub py_msg: Option<Box<pystacks_message>>,
}

impl TaskSample {
    /// The thread's stack as `mode` collects it; `None` when it has no frames.
    fn stack(&self, mode: TaskStackFrames, psr: &StackWalkerRun) -> Option<Stack> {
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
        .as_chunks::<8>()
        .0
        .iter()
        .map(|c| u64::from_ne_bytes(*c))
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
            bail!(
                "task-stacks record lengths out of range: {klen} kernel frames, \
                 {ulen} user frames, {py_len} Python bytes"
            );
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
            runtime_delta: e.runtime_delta,
            state: e.state,
            kernel_stack,
            user_stack,
            py_msg,
        });
    }
    Ok(samples)
}

/// Forces the walk over every thread on the host, whatever the capture
/// targets and whatever the kernel offers: the scoped walks' fallback,
/// which this makes exercisable (and testable) on any kernel.
const FULL_WALK_ENV: &str = "SYSTING_TASK_STACKS_FULL_WALK";

/// The most target processes a snapshot walks one at a time. Each of those
/// walks costs a link, a seq file and a handful of system calls on top of its
/// threads' records: nothing beside a walk over every thread of a host, until
/// the targets are a good part of the host themselves. Past this many the
/// snapshot takes the one walk over everything.
const SCOPED_WALK_MAX_PROCESSES: usize = 1024;

/// The inode of the root pid namespace (the kernel's `PROC_PID_INIT_INO`).
const ROOT_PID_NS_INO: u64 = 0xEFFF_FFFC;

/// The kfunc that starts a walk over a cgroup's tasks (Linux 6.7).
const CSS_TASK_ITER_KFUNC: &str = "bpf_iter_css_task_new";

/// How a snapshot reaches the threads it records. Whichever it is, the BPF
/// program tests every task it is handed against the capture's targets: a
/// scoped walk narrows what is visited, never what is recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskWalk {
    /// One walk over every thread on the host. What a capture without
    /// targets asks for, what every capture did before the scoped walks, and
    /// what one they do not cover still does.
    Full,
    /// `--pid` (the traced command's included): a walk per target process
    /// over its threads alone, with the task iterator's `pid` parameter
    /// (Linux 6.1, older than anything the iterator itself loads on). The
    /// processes are the `pids` map's keys at each snapshot, so the children
    /// the targets have during the capture are walked as soon as the fork
    /// hook has added them.
    ByPid,
    /// `--cgroup` alone: the kernel lists the processes of each target cgroup
    /// and of the cgroups below it (the css_task iterator, Linux 6.7) at each
    /// snapshot, and each is walked as with `--pid`.
    ByCgroup,
}

impl TaskWalk {
    fn describe(self) -> &'static str {
        match self {
            TaskWalk::Full => "every thread on the host",
            TaskWalk::ByPid => "the --pid targets' threads alone",
            TaskWalk::ByCgroup => "the --cgroup targets' processes alone",
        }
    }
}

/// What the choice of walk rests on besides the capture's targeting, spelled
/// out so a test can ask about hosts it does not run on.
#[derive(Clone, Copy, Debug)]
struct WalkFacts {
    /// [`FULL_WALK_ENV`] is set.
    force_full: bool,
    /// systing runs in the root pid namespace. A scoped link looks its pid up
    /// in the namespace of the process that reads it, while the targets are
    /// kept, and matched by the BPF program, by their pid in the root one.
    root_pid_ns: bool,
    /// The kernel's BTF exports [`CSS_TASK_ITER_KFUNC`].
    css_task_iter: bool,
}

impl WalkFacts {
    fn of_this_host(filter: &TargetFilter) -> Self {
        WalkFacts {
            force_full: std::env::var_os(FULL_WALK_ENV).is_some_and(|v| !v.is_empty()),
            root_pid_ns: std::fs::metadata("/proc/self/ns/pid")
                .map(|ns| ns.ino() == ROOT_PID_NS_INO)
                .unwrap_or(false),
            // Asked of the BTF only by the capture that would use it.
            css_task_iter: filter.filter_cgroup
                && filter.cgroup_match_kernel
                && !filter.filter_pid
                && crate::systing_core::kernel_has_kfunc(CSS_TASK_ITER_KFUNC),
        }
    }
}

/// The walk a capture targeted as `filter` gets on a host like `facts`, and,
/// when a capture with targets gets the full walk, why.
fn choose_walk(filter: &TargetFilter, facts: &WalkFacts) -> (TaskWalk, Option<&'static str>) {
    if !filter.filter_pid && !filter.filter_cgroup {
        // No targets: every thread on the host is what was asked for.
        return (TaskWalk::Full, None);
    }
    if facts.force_full {
        return (TaskWalk::Full, Some("SYSTING_TASK_STACKS_FULL_WALK is set"));
    }
    if !facts.root_pid_ns {
        return (
            TaskWalk::Full,
            Some(
                "systing is not in the root pid namespace, which the targets' pids are counted in",
            ),
        );
    }
    if filter.filter_pid {
        // With --cgroup as well the targets are the --pid processes that are
        // in the cgroups: the pids are the shorter list, the program's test
        // does the rest.
        return (TaskWalk::ByPid, None);
    }
    if !filter.cgroup_match_kernel {
        return (
            TaskWalk::Full,
            Some("--cgroup is matched against a start-time snapshot of cgroup ids here"),
        );
    }
    if !facts.css_task_iter {
        return (
            TaskWalk::Full,
            Some("this kernel's BTF does not export bpf_iter_css_task_new"),
        );
    }
    (TaskWalk::ByCgroup, None)
}

/// Create an iterator link of `prog` with `link_info`'s parameters: what
/// libbpf's own attach does, by file descriptor, so the link needs nothing of
/// the skeleton the program came from. libbpf-rs's `attach_iter` only knows
/// map iterators.
fn create_iter_link(
    prog: BorrowedFd<'_>,
    link_info: &mut libbpf_sys::bpf_iter_link_info,
) -> std::io::Result<OwnedFd> {
    let opts = libbpf_sys::bpf_link_create_opts {
        sz: std::mem::size_of::<libbpf_sys::bpf_link_create_opts>() as _,
        iter_info: link_info as *mut libbpf_sys::bpf_iter_link_info,
        iter_info_len: std::mem::size_of::<libbpf_sys::bpf_iter_link_info>() as _,
        ..Default::default()
    };
    // SAFETY: `prog` is an open program, and `opts` and the `link_info` it
    // points at outlive the call, which copies what it keeps.
    let fd = unsafe {
        libbpf_sys::bpf_link_create(
            prog.as_raw_fd(),
            0,
            libbpf_sys::BPF_TRACE_ITER,
            &opts as *const libbpf_sys::bpf_link_create_opts,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::from_raw_os_error(-fd));
    }
    // SAFETY: a non-negative return is a descriptor created for us to own.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Open a seq file on iterator link `link` and append all it has to `buf`:
/// the read is what runs the link's program, in this thread.
fn read_iter_link(link: BorrowedFd<'_>, buf: &mut Vec<u8>) -> std::io::Result<()> {
    // SAFETY: `link` is an open iterator link.
    let fd = unsafe { libbpf_sys::bpf_iter_create(link.as_raw_fd()) };
    if fd < 0 {
        return Err(std::io::Error::from_raw_os_error(-fd));
    }
    // SAFETY: a non-negative return is a descriptor created for us to own.
    let mut seq = unsafe { std::fs::File::from_raw_fd(fd) };
    seq.read_to_end(buf)?;
    Ok(())
}

/// The tgids the cgroup-members program wrote (`u32` each), appended to
/// `tgids` in the order written, each once: a process is in one cgroup, but
/// one target may lie below another.
fn append_member_tgids(bytes: &[u8], seen: &mut HashSet<u32>, tgids: &mut Vec<u32>) {
    for tgid in bytes.chunks_exact(std::mem::size_of::<u32>()) {
        let tgid = u32::from_ne_bytes(tgid.try_into().expect("chunks of four bytes"));
        if seen.insert(tgid) {
            tgids.push(tgid);
        }
    }
}

/// What [`TaskStacksIter::load_object`] keeps of the object it loaded.
struct LoadedObject {
    link: libbpf_rs::Link,
    prog: OwnedFd,
    walk_stats: OwnedFd,
    member_links: Vec<OwnedFd>,
}

/// The loaded and attached task iterator.
///
/// Only links and file descriptors are kept: they hold the kernel's
/// references to the programs (and the programs to their maps), so the
/// skeleton they came from can go.
pub struct TaskStacksIter {
    /// The link over every thread on the host: every snapshot's walk when
    /// `walk` is [`TaskWalk::Full`], and that of any snapshot the scoped
    /// walks cannot cover.
    link: libbpf_rs::Link,
    walk: TaskWalk,
    /// The iterator program, to scope a link of it to each target process.
    prog: OwnedFd,
    /// The capture's `--pid` targets as they stand: the main object's `pids`
    /// map, which the fork hook grows.
    pids: OwnedFd,
    /// A link of the cgroup-members program per `--cgroup` target
    /// ([`TaskWalk::ByCgroup`]).
    member_links: Vec<OwnedFd>,
    /// The program's count of the tasks it was handed and of those it found
    /// targeted (`task_stacks_walk_stats`).
    walk_stats: OwnedFd,
    /// The snapshots of a scoped capture that took the full walk instead.
    full_walk_snapshots: AtomicU64,
}

impl TaskStacksIter {
    /// Load the iterator with the capture's targeting, reading the main
    /// object's target and pystacks maps, collecting the stacks `mode` names.
    /// `cgroup_dirs` are the `--cgroup` targets' directories (none when the
    /// kernel does not decide `--cgroup` membership).
    pub fn load(
        filter: &TargetFilter,
        maps: &TargetFilterMaps<'_>,
        pystacks_maps: &SharedPystacksMaps<'_>,
        mode: TaskStackFrames,
        cgroup_dirs: &[BorrowedFd<'_>],
    ) -> Result<Self> {
        let (mut walk, mut why_full) = choose_walk(filter, &WalkFacts::of_this_host(filter));
        if walk == TaskWalk::ByCgroup && cgroup_dirs.is_empty() {
            (walk, why_full) = (
                TaskWalk::Full,
                Some("there is no --cgroup directory to list"),
            );
        }
        let loaded = if walk == TaskWalk::ByCgroup {
            // The members program is one more thing a kernel can refuse, and
            // nothing a capture should fail for: without it, the full walk.
            match Self::load_object(filter, maps, pystacks_maps, mode, cgroup_dirs) {
                Ok(loaded) => loaded,
                Err(e) => {
                    eprintln!("task-stacks: could not load the cgroup-members iterator: {e:#}");
                    (walk, why_full) = (TaskWalk::Full, Some("the kernel refused the iterator"));
                    Self::load_object(filter, maps, pystacks_maps, mode, &[])?
                }
            }
        } else {
            Self::load_object(filter, maps, pystacks_maps, mode, &[])?
        };
        // One line on which walk a capture with targets runs with: the first
        // thing to read when its snapshots cost more, or see less, than hoped.
        match why_full {
            Some(why) => eprintln!("task-stacks: walking {}: {why}", walk.describe()),
            None if walk != TaskWalk::Full => eprintln!("task-stacks: walking {}", walk.describe()),
            None => {}
        }
        Ok(Self {
            link: loaded.link,
            walk,
            prog: loaded.prog,
            pids: maps
                .pids
                .try_clone_to_owned()
                .context("Failed to keep the pids map for the task-stacks iterator")?,
            member_links: loaded.member_links,
            walk_stats: loaded.walk_stats,
            full_walk_snapshots: AtomicU64::new(0),
        })
    }

    /// Open, configure, load and attach the object; with `member_dirs`, the
    /// cgroup-members program too, a link of it on each directory and the
    /// cgroups below it.
    fn load_object(
        filter: &TargetFilter,
        maps: &TargetFilterMaps<'_>,
        pystacks_maps: &SharedPystacksMaps<'_>,
        mode: TaskStackFrames,
        member_dirs: &[BorrowedFd<'_>],
    ) -> Result<LoadedObject> {
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

        // Off in the object ("?iter/cgroup"): on for the capture that reads it.
        if !member_dirs.is_empty() {
            open_skel
                .progs
                .systing_task_stacks_members
                .set_autoload(true);
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
            "Failed to load the task-stacks BPF iterator: it needs Linux 6.2 or newer \
             (sleepable task iterators and bpf_task_from_pid)",
        )?;
        let link = skel
            .progs
            .systing_task_stacks
            .attach()
            .context("Failed to attach the task-stacks BPF iterator")?;
        let prog = skel
            .progs
            .systing_task_stacks
            .as_fd()
            .try_clone_to_owned()
            .context("Failed to keep the task-stacks iterator program")?;
        let walk_stats = skel
            .maps
            .task_stacks_walk_stats
            .as_fd()
            .try_clone_to_owned()
            .context("Failed to keep the task-stacks walk counters")?;
        let mut member_links = Vec::with_capacity(member_dirs.len());
        for dir in member_dirs {
            let mut link_info = libbpf_sys::bpf_iter_link_info::default();
            link_info.cgroup.order = libbpf_sys::BPF_CGROUP_ITER_DESCENDANTS_PRE;
            link_info.cgroup.cgroup_fd = dir.as_raw_fd() as u32;
            member_links.push(
                create_iter_link(
                    skel.progs.systing_task_stacks_members.as_fd(),
                    &mut link_info,
                )
                .context("Failed to attach the cgroup-members iterator to a --cgroup target")?,
            );
        }
        Ok(LoadedObject {
            link,
            prog,
            walk_stats,
            member_links,
        })
    }

    /// The walk this capture's snapshots take.
    pub fn walk(&self) -> TaskWalk {
        self.walk
    }

    /// The `--pid` targets now: the keys of the `pids` map, the processes the
    /// targets have forked since the capture began among them.
    fn target_pids(&self) -> Result<Vec<u32>> {
        let mut tgids = Vec::new();
        let mut seen = HashSet::new();
        let mut key = 0u32;
        let mut have_key = false;
        loop {
            let mut next = 0u32;
            // SAFETY: the map's keys are u32, `key` and `next` are one each,
            // and a null key asks for the first.
            let ret = unsafe {
                libbpf_sys::bpf_map_get_next_key(
                    self.pids.as_raw_fd(),
                    if have_key {
                        &key as *const u32 as *const c_void
                    } else {
                        std::ptr::null()
                    },
                    &mut next as *mut u32 as *mut c_void,
                )
            };
            if ret == -libc::ENOENT {
                return Ok(tgids);
            }
            if ret < 0 {
                return Err(std::io::Error::from_raw_os_error(-ret))
                    .context("Failed to read the --pid targets");
            }
            // The map grows under the walk; a key met twice is walked once.
            if seen.insert(next) {
                tgids.push(next);
            }
            if tgids.len() > SCOPED_WALK_MAX_PROCESSES {
                return Ok(tgids);
            }
            key = next;
            have_key = true;
        }
    }

    /// The processes in the `--cgroup` targets now, the cgroups below them
    /// included, as the kernel lists them.
    fn cgroup_members(&self) -> Result<Vec<u32>> {
        let mut tgids = Vec::new();
        let mut seen = HashSet::new();
        let mut bytes = Vec::new();
        for link in &self.member_links {
            bytes.clear();
            read_iter_link(link.as_fd(), &mut bytes)
                .context("Failed to list a --cgroup target's processes")?;
            append_member_tgids(&bytes, &mut seen, &mut tgids);
        }
        Ok(tgids)
    }

    /// The processes this snapshot walks one at a time, or `None` for the one
    /// walk over every thread on the host.
    fn scoped_targets(&self) -> Option<Vec<u32>> {
        let tgids = match self.walk {
            TaskWalk::Full => return None,
            TaskWalk::ByPid => self.target_pids(),
            TaskWalk::ByCgroup => self.cgroup_members(),
        };
        let why = match tgids {
            Ok(tgids) if tgids.len() <= SCOPED_WALK_MAX_PROCESSES => return Some(tgids),
            Ok(_) => format!("more than {SCOPED_WALK_MAX_PROCESSES} target processes"),
            Err(e) => format!("{e:#}"),
        };
        if self.full_walk_snapshots.fetch_add(1, Ordering::Relaxed) == 0 {
            eprintln!("task-stacks: a snapshot walked every thread on the host instead: {why}");
        }
        None
    }

    /// Walk the targeted threads once and return them: every thread on the
    /// host for the program to pick them from, or each target process's own.
    pub fn snapshot(&self) -> Result<Vec<TaskSample>> {
        let mut buf = Vec::new();
        match self.scoped_targets() {
            Some(tgids) => {
                for tgid in tgids {
                    let mut link_info = libbpf_sys::bpf_iter_link_info::default();
                    link_info.task.pid = tgid;
                    // A link to a process that has gone reads as empty.
                    let link = create_iter_link(self.prog.as_fd(), &mut link_info)
                        .context("Failed to scope a task-stacks iterator to a process")?;
                    read_iter_link(link.as_fd(), &mut buf)
                        .context("Failed to read a task-stacks iterator")?;
                }
            }
            None => {
                let mut iter = libbpf_rs::Iter::new(&self.link)
                    .context("Failed to create a task-stacks iterator")?;
                iter.read_to_end(&mut buf)
                    .context("Failed to read the task-stacks iterator")?;
            }
        }
        parse_records(&buf)
    }

    /// The tasks the capture's walks handed the program so far, and of those
    /// the ones it found targeted; `None` if the counters cannot be read.
    pub fn walk_stats(&self) -> Option<(u64, u64)> {
        let key = 0u32;
        let mut stats = [0u64; 2];
        // SAFETY: the map's one value is two u64, which `stats` is.
        let ret = unsafe {
            libbpf_sys::bpf_map_lookup_elem(
                self.walk_stats.as_raw_fd(),
                &key as *const u32 as *const c_void,
                stats.as_mut_ptr() as *mut c_void,
            )
        };
        (ret == 0).then_some((stats[0], stats[1]))
    }

    /// The snapshots of a scoped capture that took the full walk instead.
    pub fn full_walk_snapshots(&self) -> u64 {
        self.full_walk_snapshots.load(Ordering::Relaxed)
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

/// The names Python processes gave their threads, for the snapshot thread: a
/// reader per process, opened the first time one of its threads is recorded
/// and kept, with its open /proc/pid/mem, for as long as the snapshots see the
/// process.
struct PythonThreadNames {
    psr: Arc<StackWalkerRun>,
    /// By tgid. A process that has no reader (not Python, a Python whose
    /// objects cannot be read, or one pystacks has yet to find) has no entry
    /// and is asked about again: that is a map lookup.
    readers: HashMap<u32, ThreadNames>,
    /// The processes whose reader lost them (an exec: the pid lives on in a
    /// new address space), and when to open another: not on every snapshot,
    /// which is what it would take for one that became something other than
    /// a Python.
    reopen_at: HashMap<u32, Instant>,
}

/// How long to leave a process alone after its reader lost it.
const REOPEN_AFTER: Duration = Duration::from_secs(2);

impl PythonThreadNames {
    /// The names of process `tgid`'s threads there are to take note of, when
    /// `changed` of them have a full record in this snapshot and `seen` are
    /// all of them it saw (see [`ThreadNames::read`]). A name's tid is the
    /// process's word (`Thread._native_id`): one that is not a thread of its
    /// own is not its to name, and is not answered for.
    fn read(
        &mut self,
        tgid: u32,
        changed: &HashSet<i32>,
        seen: &HashSet<i32>,
    ) -> HashMap<i32, String> {
        if !self.readers.contains_key(&tgid) {
            if self
                .reopen_at
                .get(&tgid)
                .is_some_and(|at| Instant::now() < *at)
            {
                return HashMap::new();
            }
            match self.psr.thread_names(tgid as i32) {
                Some(reader) => self.readers.insert(tgid, reader),
                None => return HashMap::new(),
            };
        }
        let Some(reader) = self.readers.get_mut(&tgid) else {
            return HashMap::new();
        };
        let names = reader.read(changed, seen);
        if reader.is_gone() {
            self.readers.remove(&tgid);
            self.reopen_at.insert(tgid, Instant::now() + REOPEN_AFTER);
        }
        names
    }

    /// Let go of the readers of the processes a snapshot did not see: they
    /// have exited, and their tgid may be another process's next time.
    fn forget_all_but(&mut self, seen: &HashMap<u32, HashSet<i32>>) {
        self.readers.retain(|tgid, _| seen.contains_key(tgid));
        self.reopen_at.retain(|tgid, _| seen.contains_key(tgid));
    }
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
        mode: TaskStackFrames,
        psr: Arc<StackWalkerRun>,
        recorder: Arc<SessionRecorder>,
        task_info_tx: Sender<task_info>,
    ) -> Result<Self> {
        let (stop_tx, stop_rx) = channel::<()>();
        let handle = thread::Builder::new()
            .name("task_stacks".to_string())
            .spawn(move || {
                let mut seen_tasks = TaskSightings::new();
                let mut thread_names = PythonThreadNames {
                    psr: Arc::clone(&psr),
                    readers: HashMap::new(),
                    reopen_at: HashMap::new(),
                };
                let mut next = Instant::now();
                let mut failed = 0u64;
                for iteration in 1u64.. {
                    // The iteration starts when its walk does (the trace clock).
                    let start = get_clock_value(libc::CLOCK_BOOTTIME);
                    // With Python frames collected: every process's threads
                    // as this snapshot sees them, and of those the ones with
                    // a full record, which are the reason to ask for their
                    // process's names: no thread is renamed without one of
                    // them running. (Asked for is not read: the reader
                    // remembers, see ThreadNames::read.)
                    let mut seen: HashMap<u32, HashSet<i32>> = HashMap::new();
                    let mut renamers: HashMap<u32, HashSet<i32>> = HashMap::new();
                    let entries: Option<Vec<_>> = match iter.snapshot() {
                        Ok(samples) => Some(
                            samples
                                .iter()
                                .filter_map(|sample| {
                                    if mode.python() {
                                        seen.entry(tgid(&sample.task))
                                            .or_default()
                                            .insert(tid(&sample.task) as i32);
                                    }
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
                                    if mode.python() {
                                        renamers
                                            .entry(tgid(&sample.task))
                                            .or_default()
                                            .insert(tid(&sample.task) as i32);
                                    }
                                    Some(SnapshotEntry::Changed(TaskEntry {
                                        task: sample.task,
                                        utime_delta: sample.utime_delta,
                                        stime_delta: sample.stime_delta,
                                        runtime_delta: sample.runtime_delta,
                                        state: sample.state,
                                        stack,
                                    }))
                                })
                                .collect(),
                        ),
                        Err(e) => {
                            failed += 1;
                            if failed == 1 {
                                eprintln!("task-stacks: iteration {iteration} failed: {e:#}");
                            }
                            None
                        }
                    };
                    // Extends, closes and opens the threads' events, even
                    // when the iteration saw nothing. One that failed records
                    // nothing, not "nothing seen": BPF has moved the baseline
                    // of every thread it wrote a record for, so a thread that
                    // stays blocked comes back as unchanged, and that has to
                    // find its event still open. What this cannot mend: a
                    // thread that moved to another stack within the failed
                    // iteration comes back as unchanged too, and its event
                    // runs on over the stack that was lost, until the thread
                    // next changes.
                    for (tgid, changed) in renamers {
                        let names = thread_names.read(tgid, &changed, &seen[&tgid]);
                        if !names.is_empty() {
                            recorder.note_py_thread_names(tgid as i32, names);
                        }
                    }
                    if entries.is_some() {
                        thread_names.forget_all_but(&seen);
                    }
                    if let Some(entries) = entries {
                        recorder
                            .task_stacks_recorder
                            .lock()
                            .unwrap()
                            .record_snapshot(iteration, start, entries);
                    }

                    if max_iterations == Some(iteration) {
                        break;
                    }
                    // An iteration that overran is not caught up on: the
                    // next one starts now, not back to back with more.
                    next = (next + interval).max(Instant::now());
                    match stop_rx.recv_timeout(next.saturating_duration_since(Instant::now())) {
                        Err(RecvTimeoutError::Timeout) => {}
                        _ => break,
                    }
                }
                if failed > 1 {
                    eprintln!("task-stacks: {failed} iterations failed in all");
                }
                // What the walks cost: the tasks the program was handed
                // against those it had records to write for.
                if let Some((visited, targeted)) = iter.walk_stats() {
                    let full_walks = match iter.full_walk_snapshots() {
                        0 => String::new(),
                        n => format!("; {n} snapshots walked every thread on the host instead"),
                    };
                    eprintln!(
                        "task-stacks: walked {} and visited {visited} tasks for {targeted} targeted{full_walks}",
                        iter.walk().describe()
                    );
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
    pub runtime_delta: u64,
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
    runtime_delta: u64,
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
                        runtime_delta: entry.runtime_delta,
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
                start_iteration: event.start_iteration as i64,
                end_iteration: event.end_iteration as i64,
                utime_delta_ns: event.utime_delta as i64,
                stime_delta_ns: event.stime_delta as i64,
                runtime_delta_ns: event.runtime_delta as i64,
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
        e.runtime_delta = deltas.0 + deltas.1;
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
            runtime_delta: 0,
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

    /// A host every scoped walk runs on: nothing forced, the root pid
    /// namespace, a kernel with the css_task iterator.
    const ABLE_HOST: WalkFacts = WalkFacts {
        force_full: false,
        root_pid_ns: true,
        css_task_iter: true,
    };

    fn targeting(pid: bool, cgroup: bool, kernel: bool) -> TargetFilter {
        TargetFilter {
            filter_pid: pid,
            filter_cgroup: cgroup,
            cgroup_match_kernel: cgroup && kernel,
            num_cgroup_targets: cgroup as u32,
        }
    }

    #[test]
    fn a_capture_without_targets_walks_every_thread_and_says_nothing() {
        // Whatever the host: every thread is what it asked for, not a
        // fallback to explain.
        for facts in [
            ABLE_HOST,
            WalkFacts {
                force_full: true,
                ..ABLE_HOST
            },
            WalkFacts {
                root_pid_ns: false,
                css_task_iter: false,
                ..ABLE_HOST
            },
        ] {
            assert_eq!(
                choose_walk(&targeting(false, false, false), &facts),
                (TaskWalk::Full, None)
            );
        }
    }

    #[test]
    fn pid_targets_are_walked_one_process_at_a_time() {
        let (walk, why) = choose_walk(&targeting(true, false, false), &ABLE_HOST);
        assert_eq!((walk, why), (TaskWalk::ByPid, None));
        // No kernel the iterator loads on is without the pid parameter, so
        // the css_task iterator's absence is none of its business.
        let old = WalkFacts {
            css_task_iter: false,
            ..ABLE_HOST
        };
        assert_eq!(
            choose_walk(&targeting(true, false, false), &old).0,
            TaskWalk::ByPid
        );
    }

    #[test]
    fn pid_and_cgroup_targets_are_walked_by_pid() {
        // The pids are the shorter list; the program intersects.
        for kernel in [true, false] {
            assert_eq!(
                choose_walk(&targeting(true, true, kernel), &ABLE_HOST),
                (TaskWalk::ByPid, None)
            );
        }
    }

    #[test]
    fn cgroup_targets_are_listed_by_the_kernel_where_it_can() {
        assert_eq!(
            choose_walk(&targeting(false, true, true), &ABLE_HOST),
            (TaskWalk::ByCgroup, None)
        );
    }

    #[test]
    fn cgroup_targets_fall_back_to_the_full_walk_and_say_why() {
        // A kernel without the css_task iterator.
        let (walk, why) = choose_walk(
            &targeting(false, true, true),
            &WalkFacts {
                css_task_iter: false,
                ..ABLE_HOST
            },
        );
        assert_eq!(walk, TaskWalk::Full);
        assert!(why.unwrap().contains("bpf_iter_css_task_new"));
        // The start-time snapshot of cgroup ids, by the kernel's age or by
        // the knob: there are no target directories to list then, whatever
        // else the kernel has.
        let (walk, why) = choose_walk(&targeting(false, true, false), &ABLE_HOST);
        assert_eq!(walk, TaskWalk::Full);
        assert!(why.unwrap().contains("start-time snapshot"));
    }

    #[test]
    fn the_knob_and_a_pid_namespace_of_its_own_force_the_full_walk() {
        for filter in [
            targeting(true, false, false),
            targeting(false, true, true),
            targeting(true, true, true),
        ] {
            let (walk, why) = choose_walk(
                &filter,
                &WalkFacts {
                    force_full: true,
                    ..ABLE_HOST
                },
            );
            assert_eq!(walk, TaskWalk::Full);
            assert!(why.unwrap().contains(FULL_WALK_ENV));

            let (walk, why) = choose_walk(
                &filter,
                &WalkFacts {
                    root_pid_ns: false,
                    ..ABLE_HOST
                },
            );
            assert_eq!(walk, TaskWalk::Full);
            assert!(why.unwrap().contains("pid namespace"));
        }
    }

    #[test]
    fn member_tgids_come_out_once_each_in_the_order_written() {
        let mut bytes = Vec::new();
        for tgid in [30u32, 10, 30, 20] {
            bytes.extend_from_slice(&tgid.to_ne_bytes());
        }
        // A read never ends inside a tgid; were it to, the tail is no tgid.
        bytes.extend_from_slice(&[0xff, 0xff]);
        let mut seen = HashSet::new();
        let mut tgids = Vec::new();
        append_member_tgids(&bytes, &mut seen, &mut tgids);
        assert_eq!(tgids, [30, 10, 20]);
        // A second target's list, one process of it met under the first.
        append_member_tgids(&10u32.to_ne_bytes(), &mut seen, &mut tgids);
        append_member_tgids(&40u32.to_ne_bytes(), &mut seen, &mut tgids);
        assert_eq!(tgids, [30, 10, 20, 40]);
    }

    #[test]
    fn frames_select_the_bpf_legs() {
        use TaskStackFrames::*;
        assert!(Native.native() && !Native.python());
        assert!(All.native() && All.python());
        assert!(!Python.native() && Python.python());
        assert!(!Native.needs_pystacks() && Python.needs_pystacks() && All.needs_pystacks());
    }

    #[test]
    fn frames_asked_for_win_over_what_the_capture_collects() {
        use TaskStackFrames::*;
        // Not asked: as the rest of the capture.
        assert_eq!(TaskStackFrames::resolve(None, false), Native);
        assert_eq!(TaskStackFrames::resolve(None, true), All);
        // Asked: that, whatever the other recorders collect.
        assert_eq!(TaskStackFrames::resolve(Some(Native), true), Native);
        assert_eq!(TaskStackFrames::resolve(Some(Python), false), Python);
        assert_eq!(TaskStackFrames::resolve(Some(All), false), All);
        assert_eq!("native".parse(), Ok(Native));
        assert_eq!("python".parse(), Ok(Python));
        assert_eq!("all".parse(), Ok(All));
        assert!("system".parse::<TaskStackFrames>().is_err());
    }

    #[test]
    fn python_only_mode_skips_threads_without_python_frames() {
        use TaskStackFrames::*;
        assert!(Python.records(true));
        assert!(!Python.records(false));
        // The other modes keep a thread whose stack came out empty: its CPU
        // time and state are still worth an event.
        for mode in [Native, All] {
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
        // TASK_INTERRUPTIBLE | TASK_FREEZABLE: a freezable sleep is a sleep.
        assert_eq!(state_name(0x2001), "S");
        // TASK_FROZEN (the v1 freezer, suspend) and TASK_RTLOCK_WAIT.
        assert_eq!(state_name(0x8000), "D");
        assert_eq!(state_name(0x1000), "D");
    }

    #[test]
    fn record_header_has_no_padding() {
        assert_eq!(std::mem::size_of::<task_stacks_event>(), 80);
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
        assert_eq!(samples[0].runtime_delta, 11);
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
    fn parse_records_rejects_lengths_bpf_cannot_have_written() {
        let t = task(1, 1, "x");
        let frames = vec![1u64; MAX_FRAMES + 1];
        let err = parse_records(&record_bytes(&t, 0, (0, 0), &frames, &[], &[]))
            .err()
            .unwrap();
        assert!(err.to_string().contains("128 kernel frames"), "{err}");
        assert!(parse_records(&record_bytes(&t, 0, (0, 0), &[], &frames, &[])).is_err());
        let py = vec![0u8; std::mem::size_of::<pystacks_message>() + 1];
        assert!(parse_records(&record_bytes(&t, 0, (0, 0), &[], &[], &py)).is_err());
        // At the bound is fine.
        let full = &frames[..MAX_FRAMES];
        let samples = parse_records(&record_bytes(&t, 0, (0, 0), full, full, &[])).unwrap();
        assert_eq!(samples[0].kernel_stack.len(), MAX_FRAMES);
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
                runtime_delta: 345,
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
                start_iteration: 1,
                end_iteration: 1,
                utime_delta_ns: 300,
                stime_delta_ns: 40,
                runtime_delta_ns: 345,
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
    fn a_failed_iteration_records_nothing_and_the_next_extends_across_it() {
        // The snapshot thread does not call record_snapshot for an iteration
        // that failed (here the second): the event stays open, and the thread,
        // which BPF finds unchanged at the third, keeps it.
        let t = task(10, 10, "main");
        let (mut recorder, utid) = recorder();
        recorder.record_snapshot(1, 1_000, vec![changed(t, None)]);
        recorder.record_snapshot(3, 3_000, vec![unchanged(t)]);
        assert_eq!(
            spans(&written(&recorder, 4_000)),
            [(utid(10), 1_000, 3_000, 1, 3)]
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
