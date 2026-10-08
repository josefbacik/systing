//! Python function trace (experimental): the entries to and exits from Python
//! functions, as slices per thread.
//!
//! Uprobes on the interpreter binary, placed by [`sites`], emit one event per
//! frame entry, exit, yield and exception handler; [`pairing`] turns them into
//! slices. No ptrace, and no code of ours in the process: the probes read the
//! frame and code object from the thread that hits them, and everything else
//! comes from `/proc/PID` and the interpreter's file. The kernel does change
//! the process's memory while the probes are in: a breakpoint in a private
//! copy of each probed page, and one extra page of its own.
//!
//! This is its own BPF object and its own tool
//! (`systing-python-function-trace`); it shares pystacks' discovery, offsets
//! and symbol records, and is not yet a recorder of a systing capture.

pub mod output;
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

use crate::pystacks::bpf_maps::PystacksMaps;
use crate::pystacks::types::PystacksSymbolRecord;
use crate::pystacks::{discovery, process, symbols};
use anyhow::{anyhow, bail, Context, Result};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{Link, MapCore, MapFlags, RingBufferBuilder, UprobeOpts};
use pairing::{Counters, Event, FunctionStats, Pairer, Slice};
use sites::{FoundBy, Interpreter, Site};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::mem::MaybeUninit;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Which sites to attach.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Dispatch sites, or a refusal that says why there are none. Never a
    /// return probe nobody asked for: under one, the kernel can kill a
    /// process that switches C stacks.
    Auto,
    /// The opcode handlers: every frame, with or without perf trampolines.
    Dispatch,
    /// `_PyEval_EvalFrameDefault` entry and return: every frame only while
    /// perf trampolines (or another frame evaluator) are on.
    EvalFrame,
}

impl std::str::FromStr for Mode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "auto" => Ok(Mode::Auto),
            "dispatch" => Ok(Mode::Dispatch),
            "eval-frame" => Ok(Mode::EvalFrame),
            other => Err(format!(
                "unknown mode {other:?}: one of auto, dispatch, eval-frame"
            )),
        }
    }
}

pub struct Options {
    pub pids: Vec<u32>,
    pub mode: Mode,
    /// Size of the events ring; rounded up to a power of two of pages.
    pub ringbuf_bytes: u32,
    /// Slices shorter than this are counted in the statistics and not kept.
    pub min_slice_ns: u64,
    /// The most slices kept. Reaching it ends the trace: past it the traced
    /// process would pay for slices that are only counted.
    pub max_slices: usize,
    /// Write every raw event here as it arrives (kind, tid, frame, sp,
    /// symbol, first line): for checking the pairing against what BPF saw.
    pub events_path: Option<PathBuf>,
    pub verbose: bool,
}

/// One function's name, as far as the probes read it.
#[derive(Clone, Debug, Default)]
pub struct Symbol {
    /// `module:qualname`, as the stack walker names frames.
    pub name: String,
    pub file: String,
}

/// What the BPF side counted (`enum pyft_counter`).
#[derive(Clone, Debug, Default)]
pub struct KernelCounters {
    pub events: u64,
    pub dropped: u64,
    pub no_thread_state: u64,
    pub no_frame: u64,
    pub no_code: u64,
    pub symbol_reads: u64,
    pub symbol_records: u64,
    pub symbol_records_dropped: u64,
}

/// What one process was attached with.
#[derive(Clone, Debug)]
pub struct Attached {
    pub pid: u32,
    pub version: (i32, i32, i32),
    /// The interpreter file as the process's map names it, made printable
    /// ([`printable`]); the probes are attached through `/proc/PID/map_files`.
    pub binary: String,
    pub mode: Mode,
    pub sites: Vec<String>,
    /// How the dispatch table was found, for dispatch sites.
    pub table: Option<(u64, FoundBy)>,
}

/// Why a trace ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ended {
    Duration,
    Stopped,
    ProcessGone,
    SliceCap,
}

impl Ended {
    pub fn describe(self) -> &'static str {
        match self {
            Ended::Duration => "the duration passed",
            Ended::Stopped => "it was stopped by a signal",
            Ended::ProcessGone => "the traced process exited",
            Ended::SliceCap => "the slice cap was reached",
        }
    }
}

pub struct Trace {
    pub ended: Ended,
    pub slices: Vec<Slice>,
    pub stats: HashMap<(u64, u32), FunctionStats>,
    pub counters: Counters,
    pub kernel: KernelCounters,
    pub symbols: HashMap<u64, Symbol>,
    /// Thread names by tid, read when a thread's first event arrived.
    pub threads: HashMap<u32, String>,
    /// Process names by pid.
    pub processes: HashMap<u32, String>,
    pub attached: Vec<Attached>,
    /// What could make the trace wrong for its process, as said on stderr.
    pub warnings: Vec<String>,
    /// CLOCK_BOOTTIME ns, the events' clock.
    pub start_ts: u64,
    pub end_ts: u64,
}

impl Trace {
    /// A function's name alone (`module:qualname`), made printable.
    pub fn function(&self, symbol_id: u64) -> String {
        match self.symbols.get(&symbol_id) {
            Some(sym) => printable(&sym.name),
            None => format!("<unknown python {symbol_id:#x}>"),
        }
    }

    /// The function's source file as the probe read it (the last 192 bytes
    /// of the path), made printable; `None` where there was none.
    pub fn source_file(&self, symbol_id: u64) -> Option<String> {
        self.symbols
            .get(&symbol_id)
            .filter(|sym| !sym.file.is_empty())
            .map(|sym| printable(&sym.file))
    }

    /// `name [file:line]` for a function, the file by its name alone.
    pub fn function_name(&self, symbol_id: u64, first_line: u32) -> String {
        match self.symbols.get(&symbol_id) {
            Some(sym) => {
                let file = Path::new(&sym.file)
                    .file_name()
                    .and_then(|f| f.to_str())
                    .unwrap_or(&sym.file);
                if file.is_empty() {
                    printable(&sym.name)
                } else {
                    printable(&format!("{} [{file}:{first_line}]", sym.name))
                }
            }
            None => format!("<unknown python {symbol_id:#x}>"),
        }
    }
}

fn boottime_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime writes the timespec we own.
    unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// Whether `pid` is a process that can still run code: there, and not a
/// zombie waiting to be reaped. Read as bytes: the command name before the
/// state is the process's choice and need not be UTF-8.
pub fn is_running(pid: u32) -> bool {
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

/// Refuses a target the probes cannot be told about or would count wrong:
/// a thread id, or a tool outside the initial pid namespace (the probes see
/// the initial namespace's ids, the attach this namespace's).
fn check_target(pid: u32) -> Result<()> {
    let status = std::fs::read(format!("/proc/{pid}/status"))
        .with_context(|| format!("process {pid} is not there"))?;
    let tgid = status
        .split(|b| *b == b'\n')
        .find_map(|line| line.strip_prefix(b"Tgid:"))
        .and_then(|v| std::str::from_utf8(v).ok())
        .and_then(|v| v.trim().parse::<u32>().ok());
    match tgid {
        Some(tgid) if tgid == pid => {}
        Some(tgid) => bail!("{pid} is a thread of process {tgid}: give the process id"),
        None => bail!("cannot read the thread group of {pid}"),
    }
    let ns = |p: &str| {
        std::fs::metadata(p).map(|m| {
            use std::os::unix::fs::MetadataExt as _;
            (m.dev(), m.ino())
        })
    };
    // The initial pid namespace's inode is fixed (PROC_PID_INIT_INO).
    match ns("/proc/self/ns/pid") {
        Ok((_, 0xEFFF_FFFC)) => Ok(()),
        Ok(_) => bail!(
            "this tool runs outside the initial pid namespace, where the probes' process ids \
             would not match: run it from the host's"
        ),
        Err(e) => Err(e).context("cannot read this process's pid namespace"),
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

fn comm(path: &str) -> String {
    std::fs::read_to_string(path)
        .map(|s| printable(s.trim_end()))
        .unwrap_or_default()
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
        use std::os::unix::fs::MetadataExt as _;
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

/// The sites for `mode`. `auto` is dispatch, and where there are no dispatch
/// sites it refuses with the reason: eval-frame sites put a return probe in
/// the process, which only `--mode eval-frame` asks for.
fn choose_sites(
    interpreter: &Interpreter,
    (major, minor): (i32, i32),
    mode: Mode,
) -> Result<(Mode, Vec<Site>)> {
    match mode {
        Mode::Dispatch | Mode::Auto => {
            let sites = interpreter
                .check_build(major, minor, true)
                .and_then(|()| interpreter.dispatch_sites(major, minor));
            match (sites, mode) {
                (Ok(sites), _) => Ok((Mode::Dispatch, sites)),
                (Err(e), Mode::Auto) if eval_frame_check(interpreter, major, minor).is_ok() => {
                    Err(e.context(
                        "no dispatch sites. `--mode eval-frame` would trace this process only \
                         while perf trampolines are on, and puts a return probe in it, under \
                         which the kernel kills a process that switches C stacks (greenlet, \
                         fibers)",
                    ))
                }
                (Err(e), _) => Err(e.context("no dispatch sites")),
            }
        }
        Mode::EvalFrame => {
            eval_frame_check(interpreter, major, minor)?;
            Ok((Mode::EvalFrame, interpreter.eval_frame_sites()?))
        }
    }
}

/// Whether eval-frame sites can be used on this build: perf trampolines,
/// which make every call go through the frame evaluator, came with 3.12, and
/// the offsets the probe reads names with are known up to 3.14.
fn eval_frame_check(interpreter: &Interpreter, major: i32, minor: i32) -> Result<()> {
    if major != 3 || !(12..=14).contains(&minor) {
        bail!("eval-frame sites need Python 3.12 to 3.14");
    }
    interpreter.check_build(major, minor, false)
}

/// Traces `opts.pids` until `stop` is set, `duration` passes, the slice cap
/// is reached or every traced process is gone.
pub fn run(opts: &Options, duration: Option<Duration>, stop: &AtomicBool) -> Result<Trace> {
    run_with(opts, duration, stop, || {})
}

/// [`run`], calling `attached` once the probes are in and the trace has begun
/// (a caller holding the process stopped lets it go there).
pub fn run_with(
    opts: &Options,
    duration: Option<Duration>,
    stop: &AtomicBool,
    attached_cb: impl FnOnce(),
) -> Result<Trace> {
    let mut pids = opts.pids.clone();
    pids.sort_unstable();
    pids.dedup();
    // One process at a time: under its GIL one process has one thread in the
    // probe at a time, so nobody ever waits on the probe's map and ring
    // locks. With two, a waiter could spin, and on a KVM guest with
    // paravirtual spinlocks halt with interrupts off.
    match pids.as_slice() {
        [] => bail!("no process to trace"),
        [_] => {}
        _ => bail!("one process at a time (more need a ring per process)"),
    }
    for &pid in &pids {
        check_target(pid)?;
    }

    let mut storage = MaybeUninit::uninit();
    let mut open_skel = skel::PythonFunctionTraceSkelBuilder::default()
        .open(&mut storage)
        .context("Failed to open the Python function trace BPF object")?;
    let ring_bytes = u32::try_from(u64::from(opts.ringbuf_bytes.max(4096)).next_power_of_two())
        .unwrap_or(1 << 31);
    open_skel
        .maps
        .pyft_events
        .set_max_entries(ring_bytes)
        .context("Failed to size the events ring")?;
    let skel = open_skel
        .load()
        .context("Failed to load the Python function trace BPF object")?;

    // pystacks' own settings (`configure_bss`) are for the sampler's object
    // and its .bss layout; this object reads none of them.
    let maps = PystacksMaps::new(skel.object())
        .ok_or_else(|| anyhow!("the BPF object lacks the pystacks maps"))?;

    // Each process: its interpreter's offsets into the BPF maps, then the
    // probes into its interpreter's text.
    let mut links: Vec<Link> = Vec::new();
    let mut attached = Vec::new();
    let mut processes = HashMap::new();
    let mut interpreters = HashMap::new();
    // Every process's sites are chosen before any probe goes in.
    let mut plans = Vec::new();
    let mut all_warnings: Vec<String> = Vec::new();
    for &pid in &pids {
        let info = discovery::check_python_process(pid as i32)
            .ok_or_else(|| anyhow!("process {pid} is not a Python process pystacks knows"))?;
        let (binary_file, binary_name, interpreter) = interpreter_of(pid, &mut interpreters)?;
        let (mode, sites) = choose_sites(
            &interpreter,
            (info.version_major, info.version_minor),
            opts.mode,
        )
        .with_context(|| format!("process {pid} ({binary_name})"))?;
        let warned = warnings(pid, mode);
        // A return probe can kill a process that switches C stacks: refused
        // where greenlet is loaded, and where that cannot be known.
        if mode == Mode::EvalFrame {
            match has_greenlet(pid) {
                Some(false) => {}
                Some(true) => bail!(
                    "process {pid} has greenlet loaded: eval-frame sites put a return probe in \
                     it, under which the kernel kills a process that switches C stacks"
                ),
                None => bail!(
                    "process {pid}'s maps could not be read in full, so greenlet cannot be ruled \
                     out: eval-frame sites are refused"
                ),
            }
        }
        for warning in &warned {
            eprintln!("python-function-trace: warning: process {pid}: {warning}");
            all_warnings.push(format!("process {pid}: {warning}"));
        }
        eprintln!(
            "python-function-trace: process {pid}: Python {}.{}, {} ({} probes) in {binary_name}",
            info.version_major,
            info.version_minor,
            match mode {
                Mode::EvalFrame => "eval-frame sites, with a return probe",
                _ => "dispatch sites",
            },
            sites.len()
        );
        plans.push((
            pid,
            info,
            binary_file,
            binary_name,
            interpreter,
            mode,
            sites,
        ));
    }
    for (pid, info, binary_file, binary_name, interpreter, mode, sites) in plans {
        if stop.load(Ordering::Relaxed) {
            bail!("stopped before the trace began");
        }
        // The probes go into the file that was parsed: the kernel resolves
        // this path to the descriptor's own file.
        use std::os::fd::AsRawFd as _;
        let binary = PathBuf::from(format!("/proc/self/fd/{}", binary_file.as_raw_fd()));

        maps.add_targeted_pid(pid as i32);
        maps.update_pid_config(pid as i32, &info.pid_data);

        for site in &sites {
            let prog = if site.retprobe {
                &skel.progs.pyft_return
            } else {
                &skel.progs.pyft_site
            };
            let link = prog
                .attach_uprobe_with_opts(
                    pid as i32,
                    &binary,
                    site.file_offset as usize,
                    UprobeOpts {
                        cookie: site.cookie(),
                        retprobe: site.retprobe,
                        func_name: None,
                        ..Default::default()
                    },
                )
                .with_context(|| {
                    format!(
                        "Failed to attach at {} ({binary_name}+{:#x}) in process {pid}",
                        site.name, site.file_offset
                    )
                })?;
            links.push(link);
        }
        processes.insert(pid, comm(&format!("/proc/{pid}/comm")));
        attached.push(Attached {
            pid,
            version: (info.version_major, info.version_minor, info.version_micro),
            binary: binary_name,
            mode,
            sites: sites.iter().map(|s| s.name.clone()).collect(),
            table: (mode == Mode::Dispatch)
                .then(|| interpreter.table.as_ref().map(|t| (t.address, t.found_by)))
                .flatten(),
        });
    }
    // The trace starts once every probe is in. Events from while they went in
    // are dropped: a frame that was running then would end as though an
    // exception had taken it.
    let start_ts = boottime_ns();

    let pairer = Rc::new(RefCell::new(Pairer::new(
        opts.min_slice_ns,
        opts.max_slices,
    )));
    let symbols: Rc<RefCell<HashMap<u64, Symbol>>> = Rc::default();
    let threads: Rc<RefCell<HashMap<u32, String>>> = Rc::default();

    let mut raw_events = match &opts.events_path {
        Some(path) => Some(std::io::BufWriter::new(
            std::fs::File::create(path).with_context(|| format!("create {}", path.display()))?,
        )),
        None => None,
    };
    let cutoff = Rc::new(std::cell::Cell::new(u64::MAX));
    // Why the reader should stop, checked inside the callback too: a ring that
    // the process fills faster than it is read is never seen empty, and the
    // loop's own checks would never run.
    let began = Instant::now();
    let ended: Rc<std::cell::Cell<Option<Ended>>> = Rc::default();
    let should_end = {
        let ended = ended.clone();
        move |slices_full: bool| -> bool {
            if ended.get().is_none() {
                if stop.load(Ordering::Relaxed) {
                    ended.set(Some(Ended::Stopped));
                } else if duration.is_some_and(|d| began.elapsed() >= d) {
                    ended.set(Some(Ended::Duration));
                } else if slices_full {
                    ended.set(Some(Ended::SliceCap));
                }
            }
            ended.get().is_some()
        }
    };
    let mut builder = RingBufferBuilder::new();
    {
        let pairer = pairer.clone();
        let threads = threads.clone();
        let cutoff = cutoff.clone();
        let should_end = should_end.clone();
        let mut seen: u64 = 0;
        builder.add(&skel.maps.pyft_events, move |data: &[u8]| {
            use std::io::Write as _;
            let mut event = Event::default();
            if plain::copy_from_bytes(&mut event, data).is_err()
                || event.ts < start_ts
                || event.ts > cutoff.get()
            {
                return 0;
            }
            if let Some(w) = raw_events.as_mut() {
                let _ = writeln!(
                    w,
                    "{}\t{}\t{}\t{:#x}\t{:#x}\t{:#x}\t{}",
                    event.ts,
                    event.kind,
                    event.tid,
                    event.frame,
                    event.sp,
                    event.symbol_id,
                    event.first_line
                );
            }
            threads
                .borrow_mut()
                .entry(event.tid)
                .or_insert_with(|| comm(&format!("/proc/{}/task/{}/comm", event.tgid, event.tid)));
            pairer.borrow_mut().push(&event);
            // The event is in; a negative return stops this consume, and
            // libbpf has already moved past the record.
            seen += 1;
            if seen.is_multiple_of(4096)
                && cutoff.get() == u64::MAX
                && should_end(pairer.borrow().full())
            {
                return -1;
            }
            0
        })?;
    }
    {
        let symbols = symbols.clone();
        let maps = &maps;
        builder.add(&skel.maps.ringbuf_pysym_events, move |data: &[u8]| {
            let mut record = PystacksSymbolRecord::default();
            if plain::copy_from_bytes(&mut record, data).is_err() {
                return 0;
            }
            // A name the probe could not read (the page was not resident) is
            // left un-interned: BPF reads and sends it again.
            if record.sym.qualname.fault_addr != 0 {
                return 0;
            }
            let end = record
                .sym
                .filename
                .value
                .iter()
                .position(|b| *b == 0)
                .unwrap_or(record.sym.filename.value.len());
            symbols.borrow_mut().insert(
                record.symbol_id,
                Symbol {
                    name: symbols::get_symbol_name(&record.sym),
                    file: String::from_utf8_lossy(&record.sym.filename.value[..end]).to_string(),
                },
            );
            maps.mark_symbol_interned(record.symbol_id);
            0
        })?;
    }
    let ring = builder.build()?;
    attached_cb();
    eprintln!(
        "python-function-trace: tracing{}; Ctrl-C to stop",
        match duration {
            Some(d) => format!(" for {:.1} s", d.as_secs_f64()),
            None => String::new(),
        }
    );

    // The events ring never wakes its reader (the traced thread does not pay
    // for that), so it is read on a timer.
    let mut last_alive_check = Instant::now();
    // The first look comes with the first liveness check (100 ms in), so a
    // short command is looked at too.
    let mut last_greenlet_check = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .unwrap_or_else(Instant::now);
    let mut greenlet_seen: Vec<u32> = Vec::new();
    loop {
        // A callback that asked to stop makes consume return its error code.
        let _ = ring.consume();
        if should_end(pairer.borrow().full()) {
            break;
        }
        if last_alive_check.elapsed() >= Duration::from_millis(100) {
            last_alive_check = Instant::now();
            // greenlet imported after the probes went in (a command held
            // before any import) is seen here, once a second, while the
            // process's maps can still be read.
            if last_greenlet_check.elapsed() >= Duration::from_secs(1) {
                last_greenlet_check = Instant::now();
                for &pid in &pids {
                    if !greenlet_seen.contains(&pid) && has_greenlet(pid) == Some(true) {
                        greenlet_seen.push(pid);
                    }
                }
            }
            if !pids.iter().any(|pid| is_running(*pid)) {
                ended.set(Some(Ended::ProcessGone));
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(2));
    }

    // The trace ends here; what the probes emit while they are being taken
    // out is past the cutoff and dropped by the reader. Each detach waits out
    // a grace period in the kernel (a third of a second on 6.12), so they run
    // side by side.
    let end_ts = boottime_ns();
    cutoff.set(end_ts);
    let _ = ring.consume();
    std::thread::scope(|scope| {
        for link in links {
            scope.spawn(move || drop(link));
        }
    });
    let _ = ring.consume();
    drop(ring);

    let kernel = read_counters(&skel.maps.pyft_counters);
    let mut pairer = Rc::try_unwrap(pairer)
        .map_err(|_| anyhow!("the events ring still holds the pairer"))?
        .into_inner();
    pairer.finish(end_ts);

    if opts.verbose {
        let seen: HashSet<u32> = pairer.slices.iter().map(|s| s.tgid).collect();
        eprintln!(
            "python-function-trace: {} events from {} of {} processes",
            pairer.counters.events,
            seen.len(),
            pids.len()
        );
    }

    for &pid in &pids {
        // Also by the trace's own file names: they outlive the process.
        let in_trace = symbols
            .borrow()
            .values()
            .any(|sym| sym.file.contains("greenlet"));
        if greenlet_seen.contains(&pid) || in_trace || has_greenlet(pid) == Some(true) {
            let line = format!("process {pid}: {GREENLET_WARNING}");
            if !all_warnings.contains(&line) {
                // A stderr that is gone must not end the run before the
                // files are written.
                use std::io::Write as _;
                let _ = writeln!(std::io::stderr(), "python-function-trace: warning: {line}");
                all_warnings.push(line);
            }
        }
    }

    Ok(Trace {
        ended: ended.get().unwrap_or(Ended::Stopped),
        warnings: all_warnings,
        slices: std::mem::take(&mut pairer.slices),
        stats: std::mem::take(&mut pairer.stats),
        counters: pairer.counters.clone(),
        kernel,
        symbols: symbols.take(),
        threads: threads.take(),
        processes,
        attached,
        start_ts,
        end_ts,
    })
}

/// Loads this object's programs and nothing else (no map is filled, no probe
/// attached): for the load-shape test, which runs it on every kernel of CI's
/// matrix. `log_level` gives the verifier log level per program.
pub fn load_probe(log_level: &dyn Fn(&str) -> u32) -> Result<crate::bpf_load_shapes::LoadReport> {
    let probe = crate::systing_core::probe_lock();
    let mut storage = MaybeUninit::uninit();
    let mut open_skel = skel::PythonFunctionTraceSkelBuilder::default()
        .open(&mut storage)
        .context("Failed to open the Python function trace BPF object")?;
    // The probe needs no real ring; keep it small.
    open_skel
        .maps
        .pyft_events
        .set_max_entries(4096)
        .context("Failed to size the events ring")?;
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

/// What could make this trace of `pid` wrong or risky, to say before it
/// starts.
fn warnings(pid: u32, mode: Mode) -> Vec<String> {
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
    if mode == Mode::EvalFrame {
        out.push(
            "eval-frame sites: only calls through the frame evaluator are seen (all of them only \
             while perf trampolines are on), and the return probe can kill a process that \
             switches C stacks"
                .to_string(),
        );
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
        dropped: read(1),
        no_thread_state: read(2),
        no_frame: read(3),
        no_code: read(4),
        symbol_reads: read(5),
        symbol_records: read(6),
        symbol_records_dropped: read(7),
    }
}

#[cfg(test)]
mod tests {
    use super::printable;

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
}
