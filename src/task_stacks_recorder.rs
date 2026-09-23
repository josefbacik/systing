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
//! not. Either walk records the same threads, but for a process whose every
//! thread has exited and which waits to be reaped: the kernel's listing of a
//! `--cgroup` target leaves it out, and the walk over every thread meets it.
//! A thread that has used no CPU time and sits in the same non-runnable state
//! as at its last record cannot have changed its stack: for it the program
//! skips the walk and writes a bare header flagged unchanged. The stacks are
//! symbolized with the stack recorder's at the end of the capture. In
//! Python-only mode a thread without Python frames is left out.
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

/// Whether `dir`, a `--cgroup` target's directory, is a member of a threaded
/// subtree (cgroup v2's threaded mode). There a thread and its process can sit
/// in different cgroups, and the kernel lists a cgroup by process: a thread
/// placed in the target whose process sits beside it would never be walked,
/// where the walk over every thread matches it by its own cgroup. A type that
/// cannot be read is taken for a domain's, in which every thread of a process
/// is where its process is. Only a member of such a subtree counts, the type
/// `threaded`: the subtree's own root (`domain threaded`) and a cgroup that can
/// hold no process (`domain invalid`) are listed by process like any domain.
fn in_threaded_subtree(dir: BorrowedFd<'_>) -> bool {
    std::fs::read_to_string(format!("/proc/self/fd/{}/cgroup.type", dir.as_raw_fd()))
        .is_ok_and(|kind| kind.trim() == "threaded")
}

/// Why the kernel cannot be asked to list the `--cgroup` targets whose
/// directories are `dirs`, where it cannot. `threaded` is
/// [`in_threaded_subtree`], a parameter so that a test can stand in for it.
fn why_not_listed(
    dirs: &[BorrowedFd<'_>],
    threaded: impl Fn(BorrowedFd<'_>) -> bool,
) -> Option<&'static str> {
    if dirs.is_empty() {
        return Some("there is no --cgroup directory to list");
    }
    // A link's parameters say "no descriptor" with a 0, and a link made with
    // none walks the whole hierarchy.
    if dirs.iter().any(|dir| dir.as_raw_fd() == 0) {
        return Some(
            "a --cgroup directory is open as descriptor 0, which the kernel takes for none",
        );
    }
    if dirs.iter().any(|dir| threaded(*dir)) {
        return Some(
            "a --cgroup target is in a threaded subtree, where a thread need not be in its process's cgroup",
        );
    }
    None
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

/// The length every read of an iterator's seq file asks for: the kernel's own
/// buffer for one, eight pages, never grown. A read ends the iterator's read
/// session once what it has gathered reaches the length asked for, as it does
/// once its own buffer is full, and a cgroup iterator has one session: asked
/// for less than the whole of what its program writes, it cannot be read to
/// the end at all, and the read after the short one fails with EOPNOTSUPP.
/// Asked for the kernel's buffer in full, a read is never what ends a session
/// before that buffer would.
fn iter_read_len() -> usize {
    // SAFETY: sysconf reads a constant of the running system.
    read_len_for_page(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
}

/// The largest page the kernels this runs on are built with.
const LARGEST_PAGE: usize = 64 * 1024;

/// [`iter_read_len()`] on a system whose page size reads as `page`. A size the
/// system does not give, or one under the smallest there is, is taken for the
/// largest: a read that asks for more than the kernel's buffer costs the memory
/// it reads into, and one that asks for less is what cuts a listing short.
fn read_len_for_page(page: libc::c_long) -> usize {
    match usize::try_from(page) {
        Ok(page) if page >= 4096 => page * 8,
        _ => LARGEST_PAGE * 8,
    }
}

/// Append all `seq` has to `buf`, reading into `into` and asking for the whole
/// of its length at every read, never for fewer: the caller gives it the
/// length `iter_read_len()` says and keeps it for all the reads of a snapshot.
/// `Read::read_to_end` will not do for an iterator with one read session: it
/// sizes each read by the room to spare in the vector it fills, and into a
/// vector with none it opens with a read of a few dozen bytes, to see whether
/// there is anything to read at all.
fn read_in_full_lengths(
    seq: &mut impl Read,
    into: &mut [u8],
    buf: &mut Vec<u8>,
) -> std::io::Result<()> {
    loop {
        match seq.read(into) {
            Ok(0) => return Ok(()),
            Ok(n) => buf.extend_from_slice(&into[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

/// Open a seq file on iterator link `link` and append all it has to `buf`,
/// reading through `into` as `read_in_full_lengths()` does: the read is what
/// runs the link's program, in this thread.
fn read_iter_link(link: BorrowedFd<'_>, into: &mut [u8], buf: &mut Vec<u8>) -> std::io::Result<()> {
    debug_assert!(
        into.len() >= iter_read_len(),
        "a buffer of {} bytes is short of the {} an iterator is read through",
        into.len(),
        iter_read_len()
    );
    // SAFETY: `link` is an open iterator link.
    let fd = unsafe { libbpf_sys::bpf_iter_create(link.as_raw_fd()) };
    if fd < 0 {
        return Err(std::io::Error::from_raw_os_error(-fd));
    }
    // SAFETY: a non-negative return is a descriptor created for us to own.
    let mut seq = unsafe { std::fs::File::from_raw_fd(fd) };
    read_in_full_lengths(&mut seq, into, buf)
}

/// The tgids the cgroup-members program wrote (`u32` each), appended to
/// `tgids` in the order written, each once: a process is in one cgroup, but
/// one target may lie below another.
fn append_member_tgids(bytes: &[u8], seen: &mut HashSet<u32>, tgids: &mut Vec<u32>) {
    for tgid in bytes.as_chunks::<4>().0 {
        let tgid = u32::from_ne_bytes(*tgid);
        if seen.insert(tgid) {
            tgids.push(tgid);
        }
    }
}

/// Whether a process with this pid exists in systing's own pid namespace, the
/// one the walk by pid counts its targets in. One that has exited and waits to
/// be reaped still does. Signal 0 answers for any task's id, a thread's
/// included: a number that has come round to another process's thread keeps a
/// key it should lose, never the other way.
fn process_exists(pid: u32) -> bool {
    match libc::pid_t::try_from(pid) {
        // Signal 0 to pid 0 would look systing's own process group up.
        Ok(0) | Err(_) => false,
        Ok(pid) => {
            // SAFETY: signal 0 delivers nothing: the call only looks the pid up.
            let found = unsafe { libc::kill(pid, 0) } == 0;
            found || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
        }
    }
}

/// The keys of a BPF map with `u32` keys, in the order the kernel steps
/// through them. An error ends the keys and is kept in `err`.
struct MapKeys<'a> {
    map: BorrowedFd<'a>,
    last: Option<u32>,
    err: Option<std::io::Error>,
}

impl<'a> MapKeys<'a> {
    fn of(map: BorrowedFd<'a>) -> Self {
        MapKeys {
            map,
            last: None,
            err: None,
        }
    }
}

impl Iterator for MapKeys<'_> {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        let mut next = 0u32;
        // SAFETY: the map's keys are u32, `last` and `next` are one each, and
        // a null key asks for the first.
        let ret = unsafe {
            libbpf_sys::bpf_map_get_next_key(
                self.map.as_raw_fd(),
                self.last
                    .as_ref()
                    .map_or(std::ptr::null(), |key| key as *const u32 as *const c_void),
                &mut next as *mut u32 as *mut c_void,
            )
        };
        if ret < 0 {
            if ret != -libc::ENOENT {
                self.err = Some(std::io::Error::from_raw_os_error(-ret));
            }
            return None;
        }
        self.last = Some(next);
        Some(next)
    }
}

/// The `pids` map's keys split for a snapshot: the processes to walk, each
/// once and no more than one past what a snapshot walks one at a time, and the
/// keys met on the way whose process `exists` says has gone. The fork hook adds
/// a key for every child a target has and nothing takes one out, so without
/// the second list the children that came and went would count against the
/// first for the rest of the capture.
fn live_targets(
    keys: impl IntoIterator<Item = u32>,
    exists: impl Fn(u32) -> bool,
) -> (Vec<u32>, Vec<u32>) {
    let mut seen = HashSet::new();
    let (mut live, mut gone) = (Vec::new(), Vec::new());
    for key in keys {
        // The map grows under the walk; a key met twice is walked once.
        if !seen.insert(key) {
            continue;
        }
        if !exists(key) {
            gone.push(key);
            continue;
        }
        live.push(key);
        if live.len() > SCOPED_WALK_MAX_PROCESSES {
            break;
        }
    }
    (live, gone)
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
    /// The scoped walks of one process that came up short and were read again.
    reread_processes: AtomicU64,
    /// Of those, the ones whose second walk came up short too.
    still_short_processes: AtomicU64,
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
        if walk == TaskWalk::ByCgroup {
            if let Some(why) = why_not_listed(cgroup_dirs, in_threaded_subtree) {
                (walk, why_full) = (TaskWalk::Full, Some(why));
            }
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
            reread_processes: AtomicU64::new(0),
            still_short_processes: AtomicU64::new(0),
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
    /// targets have forked since the capture began among them. Those that have
    /// gone since leave the map here, the only place that takes a key out.
    fn target_pids(&self) -> Result<Vec<u32>> {
        let mut keys = MapKeys::of(self.pids.as_fd());
        let (live, gone) = live_targets(&mut keys, process_exists);
        if let Some(e) = keys.err {
            return Err(e).context("Failed to read the --pid targets");
        }
        // Once the keys have been stepped through, not under it: the kernel
        // cannot step on from a key that has been taken out, and starts over.
        for pid in gone {
            // SAFETY: the map's keys are u32 and `pid` is one. The return is
            // left unread: a key something else took out first is as good.
            unsafe {
                libbpf_sys::bpf_map_delete_elem(
                    self.pids.as_raw_fd(),
                    &pid as *const u32 as *const c_void,
                );
            }
        }
        Ok(live)
    }

    /// The processes in the `--cgroup` targets now, the cgroups below them
    /// included, as the kernel lists them.
    fn cgroup_members(&self) -> Result<Vec<u32>> {
        let mut tgids = Vec::new();
        let mut seen = HashSet::new();
        let mut bytes = Vec::new();
        let mut into = vec![0u8; iter_read_len()];
        for link in &self.member_links {
            bytes.clear();
            read_iter_link(link.as_fd(), &mut into, &mut bytes)
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
        let scoped = match self.scoped_targets() {
            Some(tgids) => {
                // The counters as they stand: one process's read leaves them
                // as the next one's finds them, since a snapshot is the only
                // thing that runs the program while it is being taken.
                let mut stats = self.walk_stats();
                // One buffer to read into, for every process of the snapshot.
                let mut into = vec![0u8; iter_read_len()];
                for tgid in tgids {
                    if self.read_process(tgid, &mut into, &mut buf, &mut stats)? {
                        // Cut short by a thread that exited under the walk:
                        // once more, for the threads behind it. The second
                        // walk can be cut too; one re-read is the bound, and
                        // the ones that were have a count of their own.
                        self.reread_processes.fetch_add(1, Ordering::Relaxed);
                        if self.read_process(tgid, &mut into, &mut buf, &mut stats)? {
                            self.still_short_processes.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                true
            }
            None => {
                let mut iter = libbpf_rs::Iter::new(&self.link)
                    .context("Failed to create a task-stacks iterator")?;
                iter.read_to_end(&mut buf)
                    .context("Failed to read the task-stacks iterator")?;
                false
            }
        };
        let samples = parse_records(&buf)?;
        // The walk over every thread steps through the pids in order and
        // meets each once; the scoped walks can hand a thread over again.
        Ok(if scoped {
            one_entry_per_thread(samples)
        } else {
            samples
        })
    }

    /// Walk process `tgid`'s threads through a link of the iterator program
    /// scoped to it, appending their records to `buf`. `true` when the walk
    /// visited fewer threads than the process had as the walk entered it: the
    /// kernel ends such a walk early when the thread it has just handed over
    /// exits before it advances (it finds its place again by that thread's
    /// pid), and the threads behind it go unvisited. A count that races the
    /// process's own thread starts and exits, so a reason to read once more,
    /// never an error. A link to a process that has gone reads as empty.
    ///
    /// `stats` is the program's counters as the caller last saw them, and as
    /// this read leaves them on return. `into` is the buffer the records are
    /// read through, the caller's for the whole snapshot.
    fn read_process(
        &self,
        tgid: u32,
        into: &mut [u8],
        buf: &mut Vec<u8>,
        stats: &mut Option<WalkStats>,
    ) -> Result<bool> {
        let before = *stats;
        let mut link_info = libbpf_sys::bpf_iter_link_info::default();
        link_info.task.pid = tgid;
        let link = create_iter_link(self.prog.as_fd(), &mut link_info)
            .context("Failed to scope a task-stacks iterator to a process")?;
        read_iter_link(link.as_fd(), into, buf).context("Failed to read a task-stacks iterator")?;
        *stats = self.walk_stats();
        let (Some(before), Some(after)) = (before, *stats) else {
            return Ok(false);
        };
        let runs = after.visited.wrapping_sub(before.visited);
        let resent = after.unsent.wrapping_sub(before.unsent);
        Ok(runs > 0 && runs.saturating_sub(resent) < after.group_threads)
    }

    /// The program's counters so far; `None` if they cannot be read.
    pub fn walk_stats(&self) -> Option<WalkStats> {
        let key = 0u32;
        let mut stats = WalkStats::default();
        // SAFETY: the map's one value is a `struct task_stacks_walk_stats`,
        // which `WalkStats` mirrors field for field (its size is checked
        // against the skeleton's at compile time).
        let ret = unsafe {
            libbpf_sys::bpf_map_lookup_elem(
                self.walk_stats.as_raw_fd(),
                &key as *const u32 as *const c_void,
                &mut stats as *mut WalkStats as *mut c_void,
            )
        };
        (ret == 0).then_some(stats)
    }

    /// The snapshots of a scoped capture that took the full walk instead.
    pub fn full_walk_snapshots(&self) -> u64 {
        self.full_walk_snapshots.load(Ordering::Relaxed)
    }

    /// The scoped walks of one process that came up short and were read again.
    pub fn reread_processes(&self) -> u64 {
        self.reread_processes.load(Ordering::Relaxed)
    }

    /// Of those, the ones whose second walk came up short too: what says
    /// whether one re-read is enough.
    pub fn still_short_processes(&self) -> u64 {
        self.still_short_processes.load(Ordering::Relaxed)
    }
}

/// Userspace mirror of the BPF side's `struct task_stacks_walk_stats`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WalkStats {
    /// Runs of the iterator program: a task whose record did not fit the seq
    /// buffer is handed over again and counts again.
    pub visited: u64,
    /// The runs that found their task in the capture's target set.
    pub targeted: u64,
    /// The runs whose record did not fit the seq buffer.
    pub unsent: u64,
    /// The thread count of the thread group the walk last entered.
    pub group_threads: u64,
}

const _: () = assert!(
    std::mem::size_of::<WalkStats>() == std::mem::size_of::<skel::types::task_stacks_walk_stats>()
);

/// What the capture's closing line adds to its counts, each part only when
/// there is something to say: the snapshots of a scoped capture that took the
/// full walk, the walks of a process read again and those of them short the
/// second time too, and the records that did not fit the kernel's buffer and
/// were unwound again at the next read. New parts go last: what reads the
/// line finds the earlier ones where they were.
fn closing_asides(full_walks: u64, reread: u64, still_short: u64, unsent: u64) -> String {
    let mut asides = String::new();
    match full_walks {
        0 => {}
        n => asides.push_str(&format!(
            "; {n} snapshots walked every thread on the host instead"
        )),
    }
    match reread {
        0 => {}
        n => asides.push_str(&format!(
            "; {n} walks of a process came up short and were read again, \
             {still_short} of them short the second time too"
        )),
    }
    match unsent {
        0 => {}
        n => asides.push_str(&format!(
            "; {n} records did not fit the kernel's buffer and were unwound again"
        )),
    }
    asides
}

/// One entry per thread out of a snapshot of scoped walks, which can hand a
/// thread over more than once: the second walk of a process read twice meets
/// again the threads the first reached, and a kernel older than 6.8 can return
/// a thread group's leader twice to a walk that races an exec by another of
/// its threads. The recorder takes one statement about a thread per snapshot.
///
/// The program moves a thread's baseline every time a full record of it goes
/// out, so the baseline it holds when the snapshot ends is the LAST full
/// record's: that is the one to keep, or the thread's next "unchanged" would
/// extend a stack the program has since replaced. Its CPU-time deltas run from
/// the record before it, so the full records' deltas are summed. A header
/// after a record says no more than the record did, and a thread with headers
/// alone keeps one.
fn one_entry_per_thread(samples: Vec<TaskSample>) -> Vec<TaskSample> {
    let mut merged: Vec<TaskSample> = Vec::with_capacity(samples.len());
    let mut at: HashMap<u32, usize> = HashMap::with_capacity(samples.len());
    for mut sample in samples {
        match at.get(&tid(&sample.task)).copied() {
            None => {
                at.insert(tid(&sample.task), merged.len());
                merged.push(sample);
            }
            Some(_) if sample.unchanged => {}
            Some(i) => {
                let earlier = &merged[i];
                if !earlier.unchanged {
                    sample.utime_delta += earlier.utime_delta;
                    sample.stime_delta += earlier.stime_delta;
                    sample.runtime_delta += earlier.runtime_delta;
                }
                merged[i] = sample;
            }
        }
    }
    merged
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
                if let Some(stats) = iter.walk_stats() {
                    eprintln!(
                        "task-stacks: walked {} and visited {} tasks for {} targeted{}",
                        iter.walk().describe(),
                        stats.visited,
                        stats.targeted,
                        closing_asides(
                            iter.full_walk_snapshots(),
                            iter.reread_processes(),
                            iter.still_short_processes(),
                            stats.unsent
                        )
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

    /// The seq file of an iterator with one read session, as the kernel runs a
    /// cgroup iterator's. A read with nothing left over from the one before
    /// starts the session: the objects write their output whole, one after
    /// another, the first whatever the length asked for and each of the others
    /// only while what has been gathered is under that length. A session that
    /// stopped with objects still to come cannot be started again, and the
    /// read that would fails with EOPNOTSUPP. That rule and no more of the
    /// kernel's read: its own buffer's limit is left out.
    struct OneSession {
        /// What each object writes, in the order the walk visits them.
        objects: Vec<Vec<u8>>,
        next: usize,
        started: bool,
        /// Gathered and not read yet.
        left_over: Vec<u8>,
        /// The length each read asked for.
        asked: Vec<usize>,
    }

    impl OneSession {
        fn over(objects: Vec<Vec<u8>>) -> OneSession {
            OneSession {
                objects,
                next: 0,
                started: false,
                left_over: Vec::new(),
                asked: Vec::new(),
            }
        }
    }

    impl Read for OneSession {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            self.asked.push(out.len());
            if self.left_over.is_empty() {
                if self.started && self.next < self.objects.len() {
                    return Err(std::io::Error::from_raw_os_error(libc::EOPNOTSUPP));
                }
                self.started = true;
                while self.next < self.objects.len() {
                    self.left_over.extend_from_slice(&self.objects[self.next]);
                    self.next += 1;
                    if self.left_over.len() >= out.len() {
                        break;
                    }
                }
            }
            let n = self.left_over.len().min(out.len());
            out[..n].copy_from_slice(&self.left_over[..n]);
            self.left_over.drain(..n);
            Ok(n)
        }
    }

    /// A target with no process of its own, nine in the first cgroup below it
    /// and one in the second: three objects, 36 bytes and then 4.
    fn a_listing_over_three_cgroups() -> (Vec<Vec<u8>>, Vec<u8>) {
        let tgids = |pids: std::ops::Range<u32>| -> Vec<u8> {
            pids.flat_map(|pid| pid.to_ne_bytes()).collect()
        };
        let objects = vec![Vec::new(), tgids(100..109), tgids(200..201)];
        let whole = objects.concat();
        (objects, whole)
    }

    #[test]
    fn a_listing_over_several_cgroups_is_read_whole_at_the_kernels_buffer_length() {
        let (objects, whole) = a_listing_over_three_cgroups();
        let mut seq = OneSession::over(objects);
        let len = iter_read_len();
        assert!(len >= 8 * 4096, "{len} is under eight pages");
        let mut into = vec![0u8; len];
        // Appended to what the vector holds already, which stays as it was.
        let mut buf = vec![0xaa, 0xbb];
        read_in_full_lengths(&mut seq, &mut into, &mut buf).expect("the listing reads whole");
        assert_eq!(&buf[..2], [0xaa, 0xbb]);
        assert_eq!(&buf[2..], whole);
        // One read for the listing and one that finds its end, each of them
        // asking for the full length.
        assert_eq!(seq.asked, [len, len]);
    }

    #[test]
    fn a_reader_that_asks_for_little_loses_a_listing_over_several_cgroups() {
        // The control for the test above: the same listing, read in lengths of
        // 32 bytes. The first read ends the session after the nine (36 bytes
        // gathered, the second cgroup still to come), the second takes the
        // four bytes left over, and the third has no session to start.
        let (objects, whole) = a_listing_over_three_cgroups();
        let mut seq = OneSession::over(objects);
        let mut into = [0u8; 32];
        let mut buf = Vec::new();
        let err = read_in_full_lengths(&mut seq, &mut into, &mut buf)
            .expect_err("a session cut short cannot be read to the end");
        assert_eq!(err.raw_os_error(), Some(libc::EOPNOTSUPP));
        assert_eq!(seq.asked, [32, 32, 32]);
        // What did come back is the nine and no more.
        assert_eq!(buf, &whole[..36]);
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
    fn a_page_size_the_system_does_not_give_is_taken_for_the_largest() {
        assert_eq!(read_len_for_page(4096), 8 * 4096);
        assert_eq!(read_len_for_page(65536), 8 * 65536);
        // sysconf's error, and a size under the smallest there is.
        assert_eq!(read_len_for_page(-1), 8 * LARGEST_PAGE);
        assert_eq!(read_len_for_page(512), 8 * LARGEST_PAGE);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "is short of the")]
    fn an_iterator_is_not_read_through_a_short_buffer() {
        // The length is checked before the link is touched: any descriptor does.
        let any = std::fs::File::open("/dev/null").expect("Failed to open /dev/null");
        let _ = read_iter_link(any.as_fd(), &mut [0u8; 32], &mut Vec::new());
    }

    #[test]
    fn processes_that_have_gone_leave_the_targets_and_do_not_count() {
        let (live, gone) = live_targets([7u32, 100, 101, 8, 102, 7], |pid| pid < 100);
        assert_eq!(live, [7, 8]);
        assert_eq!(gone, [100, 101, 102]);

        // More keys than a snapshot walks one at a time, three of them alive.
        let cap = SCOPED_WALK_MAX_PROCESSES as u32;
        let keys = (1..=cap + 3).chain([cap + 10, cap + 11, cap + 12]);
        let (live, gone) = live_targets(keys, |pid| pid > cap + 3);
        assert_eq!(live, [cap + 10, cap + 11, cap + 12]);
        assert_eq!(gone.len(), SCOPED_WALK_MAX_PROCESSES + 3);
    }

    #[test]
    fn more_live_targets_than_a_snapshot_walks_end_the_listing_there() {
        let cap = SCOPED_WALK_MAX_PROCESSES as u32;
        let asked = std::cell::Cell::new(0u32);
        let (live, gone) = live_targets(1..=cap + 500, |_| {
            asked.set(asked.get() + 1);
            true
        });
        assert_eq!(live.len(), SCOPED_WALK_MAX_PROCESSES + 1);
        assert!(gone.is_empty());
        // Nothing past the one too many is looked up.
        assert_eq!(asked.get(), cap + 1);
    }

    #[test]
    fn a_process_exists_until_it_is_reaped() {
        assert!(process_exists(std::process::id()));
        assert!(!process_exists(0));
        assert!(!process_exists(u32::MAX));
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("Failed to spawn true");
        let pid = child.id();
        // Running, or exited and waiting to be reaped: it is there.
        let before_the_wait = process_exists(pid);
        child.wait().expect("Failed to wait for true");
        assert!(before_the_wait);
        assert!(!process_exists(pid));
    }

    #[test]
    fn only_a_member_of_a_threaded_subtree_counts_as_in_one() {
        let dir = tempfile::tempdir().expect("Failed to create a temporary directory");
        let kind_file = dir.path().join("cgroup.type");
        let open = || std::fs::File::open(dir.path()).expect("Failed to open the directory");
        // No type to read: a domain's.
        assert!(!in_threaded_subtree(open().as_fd()));
        for (kind, threaded) in [
            ("threaded\n", true),
            ("domain\n", false),
            ("domain threaded\n", false),
            ("domain invalid\n", false),
        ] {
            std::fs::write(&kind_file, kind).expect("Failed to write cgroup.type");
            assert_eq!(in_threaded_subtree(open().as_fd()), threaded, "{kind:?}");
        }
    }

    #[test]
    fn a_cgroup_listing_is_refused_for_what_its_directories_cannot_give() {
        let dir = tempfile::tempdir().expect("Failed to create a temporary directory");
        let opened = std::fs::File::open(dir.path()).expect("Failed to open the directory");
        assert_ne!(
            opened.as_raw_fd(),
            0,
            "this test needs its standard input open"
        );
        let no = |_: BorrowedFd<'_>| false;
        assert_eq!(why_not_listed(&[opened.as_fd()], no), None);
        assert_eq!(
            why_not_listed(&[], no),
            Some("there is no --cgroup directory to list")
        );
        // SAFETY: descriptor 0 is the test process's standard input, open for
        // its life; it is compared here, never read.
        let zero = unsafe { BorrowedFd::borrow_raw(0) };
        assert!(why_not_listed(&[opened.as_fd(), zero], no)
            .is_some_and(|why| why.contains("descriptor 0")));
        assert!(why_not_listed(&[opened.as_fd()], |_| true)
            .is_some_and(|why| why.contains("threaded subtree")));
    }

    #[test]
    fn the_closing_line_adds_only_what_there_is_to_say() {
        assert_eq!(closing_asides(0, 0, 0, 0), "");
        assert_eq!(
            closing_asides(0, 0, 0, 3),
            "; 3 records did not fit the kernel's buffer and were unwound again"
        );
        assert_eq!(
            closing_asides(2, 5, 1, 3),
            "; 2 snapshots walked every thread on the host instead\
             ; 5 walks of a process came up short and were read again, \
             1 of them short the second time too\
             ; 3 records did not fit the kernel's buffer and were unwound again"
        );
    }

    #[test]
    fn a_process_read_twice_keeps_each_threads_last_full_record() {
        // The first walk of the process wrote thread 11's record and was cut
        // short there. The second hands 11 over again: a header if it has not
        // run since, a full record if it has -- and then that record is the
        // program's baseline, so it is the one to keep, with the CPU time of
        // both. Thread 12 the first walk never met; 13 has headers alone; 14
        // had not run when the first walk passed it and had when the second
        // did, and a header gives way to the record that follows it.
        let (ran, behind, idle, woke) = (
            task(10, 11, "worker"),
            task(10, 12, "worker"),
            task(10, 13, "worker"),
            task(10, 14, "worker"),
        );
        let mut buf = record_bytes(&ran, 0, (1, 2), &[0xa], &[], &[]);
        buf.extend(record_bytes(&idle, FLAG_UNCHANGED, (0, 0), &[], &[], &[]));
        buf.extend(record_bytes(&woke, FLAG_UNCHANGED, (0, 0), &[], &[], &[]));
        buf.extend(record_bytes(&ran, 0, (5, 6), &[0xb], &[], &[]));
        buf.extend(record_bytes(&ran, FLAG_UNCHANGED, (0, 0), &[], &[], &[]));
        buf.extend(record_bytes(&behind, 0, (3, 4), &[0xc], &[], &[]));
        buf.extend(record_bytes(&idle, FLAG_UNCHANGED, (0, 0), &[], &[], &[]));
        buf.extend(record_bytes(&woke, 0, (7, 1), &[0xd], &[], &[]));
        let samples = one_entry_per_thread(parse_records(&buf).unwrap());
        let kept: Vec<_> = samples
            .iter()
            .map(|sample| {
                (
                    tid(&sample.task),
                    sample.unchanged,
                    sample.kernel_stack.clone(),
                    (sample.utime_delta, sample.stime_delta, sample.runtime_delta),
                )
            })
            .collect();
        assert_eq!(
            kept,
            [
                (11, false, vec![0xb], (6, 8, 14)),
                (13, true, vec![], (0, 0, 0)),
                (14, false, vec![0xd], (7, 1, 8)),
                (12, false, vec![0xc], (3, 4, 7)),
            ]
        );
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
