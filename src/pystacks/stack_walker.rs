use crate::systing_core::types::{pystacks_message, stack_event};
use libbpf_rs::Object;
use std::hash::{Hash, Hasher};

use {
    crate::pystacks::bpf_maps::PystacksMaps, crate::pystacks::discovery,
    crate::pystacks::symbols::SymbolResolver, crate::pystacks::thread_names::ThreadNames,
    crate::pystacks::types::PystacksSymbolRecord, crate::pystacks::types::StackWalkerFrame,
    std::fmt,
};

/// A symbolized Python frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PythonFrame {
    /// `function (python) [file:line]`, the file by its name alone.
    pub name: String,
    /// The file's full path, as far as BPF kept it (the last 192 bytes).
    pub file: Option<String>,
    /// One of the interpreter's own entry frames rather than a function's: see
    /// [`with_entry_markers`].
    pub entry: bool,
}

/// Puts the entry frames BPF stepped over back beside the frames it emitted.
///
/// From 3.12 CPython pushes a frame of its own each time C enters the bytecode
/// loop (one per native `_PyEval_EvalFrameDefault`), and links it into the
/// chain the BPF walk follows: they mark where, among the native frames, each
/// run of Python frames belongs, and name no Python function. BPF tells them
/// by the interpreter's own mark, `_PyInterpreterFrame.owner`, emits no
/// symbol for them and counts each on the symbol just inward of it: a frame's
/// `pad_` is the number of entry frames between it and the next frame
/// outward. `frames` is root-first, as `Stack` keeps it, so a frame's entry
/// frames stand in front of it. An entry frame beyond the innermost emitted
/// frame is not counted (the interpreter between two Python calls), and a
/// walk that met only entry frames emits nothing. A count is clamped to what
/// one walk can visit ([`MAX_ENTRY_FRAMES_PER_SYMBOL`]): a frame read back
/// from a spill can carry any word, and a word past the walk's bound is not
/// the walk's.
fn with_entry_markers(frames: impl IntoIterator<Item = (PythonFrame, i32)>) -> Vec<PythonFrame> {
    let mut out = Vec::new();
    for (frame, entry_frames) in frames {
        let entry_frames = usize::try_from(entry_frames)
            .unwrap_or(0)
            .min(MAX_ENTRY_FRAMES_PER_SYMBOL);
        out.extend(std::iter::repeat_with(entry_marker).take(entry_frames));
        out.push(frame);
    }
    out
}

/// The most entry frames one symbol can count: the walk visits at most twice
/// the symbol budget (the bound in `pystacks.bpf.c`), and every visited frame
/// but the counting symbol itself could be an entry frame.
const MAX_ENTRY_FRAMES_PER_SYMBOL: usize = 2 * crate::pystacks::types::BPF_LIB_MAX_STACK_DEPTH - 1;

/// The stand-in for an entry frame: named so a reader of the raw list can
/// tell it, never shown (the interleave consumes the markers).
fn entry_marker() -> PythonFrame {
    PythonFrame {
        name: "<interpreter entry> (python) [unknown]".to_string(),
        file: None,
        entry: true,
    }
}

#[derive(Debug, Clone)]
pub struct PyAddr {
    pub addr: StackWalkerFrame,
}

// The entry-frame count is part of a frame's identity: the same Python frames
// reached through different C re-entries interleave differently with the
// native frames, so they are different stacks.
impl PartialEq for PyAddr {
    fn eq(&self, other: &Self) -> bool {
        self.addr.symbol_id == other.addr.symbol_id
            && self.addr.inst_idx == other.addr.inst_idx
            && self.addr.pad_ == other.addr.pad_
    }
}
impl Eq for PyAddr {}

impl Hash for PyAddr {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.addr.symbol_id.hash(state);
        self.addr.inst_idx.hash(state);
        self.addr.pad_.hash(state);
    }
}

impl From<&crate::systing_core::types::stack_walker_frame> for StackWalkerFrame {
    fn from(frame: &crate::systing_core::types::stack_walker_frame) -> Self {
        StackWalkerFrame {
            symbol_id: frame.symbol_id,
            inst_idx: frame.inst_idx,
            pad_: frame.pad_,
        }
    }
}

impl fmt::Display for crate::systing_core::types::stack_walker_frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "StackWalkerFrame {{ symbol_id: {} inst_idx: {} entry_frames: {} }}",
            self.symbol_id, self.inst_idx, self.pad_
        )
    }
}

impl fmt::Display for StackWalkerFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "StackWalkerFrame {{ symbol_id: {} inst_idx: {} }}",
            self.symbol_id, self.inst_idx
        )
    }
}

/// Maximum number of sample events/frames to log in debug mode.
const DEBUG_SAMPLE_LOG_LIMIT: u64 = 10;

pub struct StackWalkerRun {
    resolver: Option<SymbolResolver>,
    maps: Option<PystacksMaps>,
    // Debug mode flag (atomic for thread safety with Sync impl)
    debug: std::sync::atomic::AtomicBool,
    // Counters for debug statistics (atomic for thread safety with Sync impl)
    events_with_pystack: std::sync::atomic::AtomicU64,
    events_without_pystack: std::sync::atomic::AtomicU64,
    symbols_loaded_count: std::sync::atomic::AtomicU64,
    frames_symbolized: std::sync::atomic::AtomicU64,
    frames_unknown: std::sync::atomic::AtomicU64,
    /// Failed inserts into the BPF gate map (warned once, see
    /// `ingest_symbol_record`).
    gate_insert_failures: std::sync::atomic::AtomicU64,
    /// Per process, how BPF's pthread-id witness read on its samples, indexed
    /// by the `PYSTACKS_PTHREAD_ID_*` value (see [`PTHREAD_ID_KIND_NAMES`]):
    /// MISMATCH against MATCH says whether the thread states found through
    /// the TLS slot were bound by the threads sampled. Debug mode only.
    pthread_id_by_pid: std::sync::Mutex<std::collections::HashMap<u64, [u64; PTHREAD_ID_KINDS]>>,
    /// The Python processes found so far, for reading their memory from user
    /// space: (major, minor, the address of `_PyRuntime`) by pid.
    python_processes: std::sync::RwLock<std::collections::HashMap<i32, (i32, i32, usize)>>,
}

/// The values of `pystacks_message.pthread_id_match`, in the BPF enum's
/// order (`PYSTACKS_PTHREAD_ID_UNKNOWN` = 0 … `PYSTACKS_PTHREAD_ID_NO_DESCRIPTOR`
/// = 7).
const PTHREAD_ID_KIND_NAMES: [&str; PTHREAD_ID_KINDS] = [
    "unknown",
    "match",
    "mismatch",
    "thread_state_null",
    "null",
    "not_using_tls",
    "error",
    "no_descriptor",
];
const PTHREAD_ID_KINDS: usize = 8;

/// One line per process of the witness counts, `kind=count` for every kind
/// that was seen, in a fixed order.
fn describe_pthread_id_counts(counts: &[u64; PTHREAD_ID_KINDS]) -> String {
    PTHREAD_ID_KIND_NAMES
        .iter()
        .zip(counts)
        .filter(|(_, count)| **count > 0)
        .map(|(name, count)| format!("{name}={count}"))
        .collect::<Vec<_>>()
        .join(" ")
}

impl StackWalkerRun {
    fn new() -> Self {
        use std::sync::atomic::AtomicBool;
        use std::sync::atomic::AtomicU64;

        StackWalkerRun {
            resolver: None,
            maps: None,
            debug: AtomicBool::new(false),
            events_with_pystack: AtomicU64::new(0),
            events_without_pystack: AtomicU64::new(0),
            symbols_loaded_count: AtomicU64::new(0),
            frames_symbolized: AtomicU64::new(0),
            frames_unknown: AtomicU64::new(0),
            gate_insert_failures: AtomicU64::new(0),
            pthread_id_by_pid: Default::default(),
            python_processes: Default::default(),
        }
    }

    /// Tallies one sample's witness value for `pid` (debug mode only; an
    /// out-of-range value counts as `unknown`).
    fn note_pthread_id_match(&self, pid: u64, kind: u8) {
        let kind = usize::from(kind);
        let kind = if kind < PTHREAD_ID_KINDS { kind } else { 0 };
        let mut by_pid = self.pthread_id_by_pid.lock().unwrap();
        by_pid.entry(pid).or_insert([0; PTHREAD_ID_KINDS])[kind] += 1;
    }

    fn note_python_process(&self, pid: i32, info: &discovery::PyProcessInfo) {
        self.python_processes.write().unwrap().insert(
            pid,
            (
                info.version_major,
                info.version_minor,
                info.pid_data.py_runtime_addr,
            ),
        );
    }

    /// A reader of the names process `pid` gave its threads; `None` when it is
    /// not a Python process pystacks found, is one whose objects cannot be
    /// read yet (before 3.13), or is gone.
    pub fn thread_names(&self, pid: i32) -> Option<ThreadNames> {
        let (major, minor, runtime_addr) = *self.python_processes.read().unwrap().get(&pid)?;
        ThreadNames::open(pid, runtime_addr, major, minor)
    }

    fn init(&mut self, bpf_object: &Object, pid_opts: &[i32], debug: bool) {
        use std::sync::atomic::Ordering;

        self.debug.store(debug, Ordering::Relaxed);

        if debug {
            eprintln!(
                "[pystacks debug] StackWalkerRun::init called with {} PIDs",
                pid_opts.len()
            );
        }

        if self.initialized() {
            if debug {
                eprintln!("[pystacks debug] StackWalkerRun already initialized, skipping");
            }
            return;
        }

        // Get BPF map FDs (do this first so add_pid works even with no initial PIDs)
        let maps = match PystacksMaps::new(bpf_object) {
            Some(m) => m,
            None => {
                eprintln!("[pystacks] Failed to get BPF map FDs");
                return;
            }
        };

        // Set BSS configuration (has_targeted_pids, enable_py_src_lines, etc.)
        maps.configure_bss();

        // Discover Python processes
        let process_info = discovery::discover_python_processes(pid_opts);

        if process_info.is_empty() && debug {
            eprintln!(
                "[pystacks debug] No Python processes found initially (will discover via exec)"
            );
        }

        // Populate BPF maps
        let mut attached_count = 0;
        for (pid, info) in &process_info {
            if maps.add_targeted_pid(*pid) {
                attached_count += 1;
            }
            maps.update_pid_config(*pid, &info.pid_data);
            self.note_python_process(*pid, info);
        }

        if debug {
            eprintln!(
                "[pystacks debug] Attached {} Python processes to BPF maps",
                attached_count
            );
        }

        // Create symbol resolver
        self.resolver = Some(SymbolResolver::new(&process_info));

        self.maps = Some(maps);

        if debug {
            eprintln!("[pystacks debug] pystacks init SUCCESS - Rust implementation initialized");
        }
    }

    fn initialized(&self) -> bool {
        self.resolver.is_some()
    }

    /// Returns true if debug mode is enabled.
    fn is_debug(&self) -> bool {
        self.debug.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn print_debug_stats(&self) {
        use std::sync::atomic::Ordering;

        if self.is_debug() {
            eprintln!(
                "[pystacks debug] stats: with_pystack={} without_pystack={} \
                 symbol_loads={} symbolized={} unknown={} initialized={}",
                self.events_with_pystack.load(Ordering::Relaxed),
                self.events_without_pystack.load(Ordering::Relaxed),
                self.symbols_loaded_count.load(Ordering::Relaxed),
                self.frames_symbolized.load(Ordering::Relaxed),
                self.frames_unknown.load(Ordering::Relaxed),
                self.initialized()
            );
            let gate_failures = self.gate_insert_failures.load(Ordering::Relaxed);
            if gate_failures > 0 {
                eprintln!("[pystacks debug] gate map insert failures: {gate_failures}");
            }
            let by_pid = self.pthread_id_by_pid.lock().unwrap();
            let mut pids: Vec<&u64> = by_pid.keys().collect();
            pids.sort_unstable();
            for pid in pids {
                eprintln!(
                    "[pystacks debug] pthread-id witness pid={pid}: {}",
                    describe_pthread_id_counts(&by_pid[pid])
                );
            }
        }
    }

    fn symbolize_function(&self, frame: &PyAddr) -> String {
        match &self.resolver {
            Some(resolver) => resolver.symbolize_function(&frame.addr),
            None => "<unknown python>".to_string(),
        }
    }

    fn symbolize_filename_line(&self, frame: &PyAddr) -> (String, Option<usize>) {
        match &self.resolver {
            Some(resolver) => resolver.symbolize_filename_line(&frame.addr),
            None => ("unknown".to_string(), None),
        }
    }

    /// Ingest a symbol record emitted by BPF through the pysym ringbuf.
    ///
    /// Resolves and caches the symbol, then marks its ID as interned in the
    /// BPF gate map so BPF stops re-emitting it. The gate update happens
    /// here, from process context — BPF must never insert into the gate map
    /// from its probes (IRQs-off hash-map updates can wedge the CPU on
    /// hypervisors that drop PV spinlock kicks; see pystacks.bpf.c).
    pub fn ingest_symbol_record(&self, record: &PystacksSymbolRecord) {
        use std::sync::atomic::Ordering;

        let Some(resolver) = &self.resolver else {
            return;
        };

        if resolver.ingest_record(record) {
            if let Some(maps) = &self.maps {
                if !maps.mark_symbol_interned(record.symbol_id) {
                    // Likely the gate map is full. Symbolization stays
                    // correct (the userspace cache above is authoritative),
                    // but BPF will keep re-emitting this symbol at the
                    // rate-limited cadence for the rest of the trace.
                    let count = self.gate_insert_failures.fetch_add(1, Ordering::Relaxed) + 1;
                    if count == 1 {
                        eprintln!(
                            "[pystacks] Warning: failed to mark symbol {:#x} as interned \
                             (gate map full?); BPF will keep re-emitting un-interned symbols",
                            record.symbol_id
                        );
                    }
                }
            }

            if self.is_debug() {
                let count = self.symbols_loaded_count.fetch_add(1, Ordering::Relaxed) + 1;
                if count <= DEBUG_SAMPLE_LOG_LIMIT {
                    eprintln!(
                        "[pystacks debug] Interned symbol #{} (id {:#x}, {} total)",
                        count,
                        record.symbol_id,
                        resolver.symbol_count()
                    );
                }
            }
        }
    }

    pub fn add_pid(&self, pid: i32) -> bool {
        if !self.initialized() {
            return false;
        }

        if self.is_debug() {
            eprintln!("[pystacks debug] Dynamically adding PID {}", pid);
        }

        // Check if this is a Python process
        if let Some(info) = discovery::check_python_process(pid) {
            if self.is_debug() {
                eprintln!(
                    "[pystacks debug] Found Python {}.{} in PID {}",
                    info.version_major, info.version_minor, pid
                );
            }

            if let Some(resolver) = &self.resolver {
                resolver.add_pid_version(pid, info.version_major, info.version_minor);
            }
            self.note_python_process(pid, &info);
            if let Some(maps) = &self.maps {
                maps.add_targeted_pid(pid);
                maps.update_pid_config(pid, &info.pid_data);
            }
            true
        } else {
            false
        }
    }

    pub fn get_pystack_from_event(&self, event: &stack_event) -> Vec<PyAddr> {
        self.get_pystack_from_buffer(&event.py_msg_buffer, event.task.tgidpid >> 32)
    }

    pub fn get_pystack_from_buffer(&self, buf: &pystacks_message, pid: u64) -> Vec<PyAddr> {
        use std::sync::atomic::Ordering;

        let stack_len = (buf.stack_len as usize).min(buf.buffer.len());

        if self.is_debug() {
            // The witness byte is reset to "unknown" (0) by the sampler for a
            // process the walker did not run on; every other value is the
            // walker's own reading for this sample.
            if buf.pthread_id_match != 0 {
                self.note_pthread_id_match(pid, buf.pthread_id_match);
            }
            if stack_len > 0 {
                let count = self.events_with_pystack.fetch_add(1, Ordering::Relaxed) + 1;
                if count <= DEBUG_SAMPLE_LOG_LIMIT {
                    eprintln!(
                        "[pystacks debug] Event #{} with Python stack: PID={} stack_len={}",
                        count, pid, stack_len
                    );
                }
            } else {
                self.events_without_pystack.fetch_add(1, Ordering::Relaxed);
            }
        }

        Vec::from(&buf.buffer[..stack_len])
            .iter()
            .map(|frame| PyAddr { addr: frame.into() })
            .collect()
    }

    pub fn init_pystacks(&mut self, pids: &[u32], bpf_object: &Object, debug: bool) {
        if debug {
            eprintln!(
                "[pystacks debug] init_pystacks called with {} PIDs",
                pids.len()
            );
        }

        if !pids.is_empty() {
            let pid_opts: Vec<i32> = pids.iter().map(|&pid| pid as i32).collect();
            self.init(bpf_object, &pid_opts, debug);
        } else if debug {
            eprintln!("[pystacks debug] No PIDs provided, skipping pystacks initialization");
        }
    }

    pub fn get_python_frames(&self, py_stack: &[PyAddr]) -> Vec<PythonFrame> {
        use std::sync::atomic::Ordering;

        if !self.initialized() {
            if self.is_debug() && !py_stack.is_empty() {
                eprintln!(
                    "[pystacks debug] get_python_frames: not initialized, returning empty for {} frames",
                    py_stack.len()
                );
            }
            return Vec::new();
        }

        if py_stack.is_empty() {
            return Vec::new();
        }

        let debug = self.is_debug();

        let frames = py_stack.iter().map(|frame| {
            let func_name = self.symbolize_function(frame);
            let (filename, line_number) = self.symbolize_filename_line(frame);

            if debug {
                if func_name == "<unknown python>" {
                    self.frames_unknown.fetch_add(1, Ordering::Relaxed);
                } else {
                    let count = self.frames_symbolized.fetch_add(1, Ordering::Relaxed) + 1;
                    if count <= DEBUG_SAMPLE_LOG_LIMIT {
                        let base_filename = std::path::Path::new(&filename)
                            .file_name()
                            .and_then(|f| f.to_str())
                            .unwrap_or(&filename);
                        eprintln!(
                            "[pystacks debug] Symbolized frame #{}: symbol_id={} -> {} [{}]",
                            count, frame.addr.symbol_id, func_name, base_filename
                        );
                    }
                }
            }

            let base_filename = std::path::Path::new(&filename)
                .file_name()
                .and_then(|f| f.to_str())
                .unwrap_or(&filename);

            let name = match line_number {
                Some(line) => format!("{func_name} (python) [{base_filename}:{line}]"),
                None => format!("{func_name} (python) [{base_filename}]"),
            };
            let frame_out = PythonFrame {
                name,
                file: (!filename.is_empty() && filename != "unknown").then_some(filename),
                entry: false,
            };
            (frame_out, frame.addr.pad_)
        });
        with_entry_markers(frames)
    }
}

impl Default for StackWalkerRun {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for StackWalkerRun {
    fn drop(&mut self) {
        self.print_debug_stats();
    }
}

unsafe impl Send for StackWalkerRun {}
unsafe impl Sync for StackWalkerRun {}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(name: &str) -> PythonFrame {
        PythonFrame {
            name: format!("{name} (python) [app.py:1]"),
            file: None,
            entry: false,
        }
    }

    /// The names of a list, an entry frame as `ENTRY`.
    fn shape(frames: &[PythonFrame]) -> Vec<&str> {
        frames
            .iter()
            .map(|f| {
                if f.entry {
                    "ENTRY"
                } else {
                    f.name.split(' ').next().unwrap()
                }
            })
            .collect()
    }

    #[test]
    fn entry_frames_stand_in_front_of_the_frame_that_counted_them() {
        // Root-first: `<module>` ran in the outermost loop frame, called
        // `sorted`, whose key function `inner` ran in a second one.
        let merged = with_entry_markers(vec![(frame("<module>"), 1), (frame("inner"), 1)]);
        assert_eq!(shape(&merged), ["ENTRY", "<module>", "ENTRY", "inner"]);
    }

    #[test]
    fn a_count_of_zero_adds_nothing_and_a_count_of_two_adds_two() {
        // 3.11 and older: no entry frames at all.
        let merged = with_entry_markers(vec![(frame("outer"), 0), (frame("inner"), 0)]);
        assert_eq!(shape(&merged), ["outer", "inner"]);
        // A finalizer re-entered the interpreter while a frame was being
        // popped: two entry frames back to back.
        let merged = with_entry_markers(vec![(frame("outer"), 2), (frame("inner"), 0)]);
        assert_eq!(shape(&merged), ["ENTRY", "ENTRY", "outer", "inner"]);
        // A walk that stopped short of its outermost entry frame.
        let merged = with_entry_markers(vec![(frame("outer"), 0), (frame("inner"), 1)]);
        assert_eq!(shape(&merged), ["outer", "ENTRY", "inner"]);
    }

    #[test]
    fn a_frame_from_before_the_count_reads_as_no_entry_frames() {
        // A negative word is not a count.
        let merged = with_entry_markers(vec![(frame("f"), -1)]);
        assert_eq!(shape(&merged), ["f"]);
        assert!(with_entry_markers(Vec::new()).is_empty());
    }

    #[test]
    fn a_count_past_the_walks_bound_is_clamped_to_it() {
        // A spilled record can carry any word; the walk never counts past its
        // own visit budget, so the expansion stops there.
        let merged = with_entry_markers(vec![(frame("f"), i32::MAX)]);
        let merged = shape(&merged);
        assert_eq!(merged.len(), MAX_ENTRY_FRAMES_PER_SYMBOL + 1);
        assert!(merged[..MAX_ENTRY_FRAMES_PER_SYMBOL]
            .iter()
            .all(|name| *name == "ENTRY"));
        assert_eq!(merged.last(), Some(&"f"));
        let exact = with_entry_markers(vec![(frame("f"), MAX_ENTRY_FRAMES_PER_SYMBOL as i32)]);
        assert_eq!(exact.len(), MAX_ENTRY_FRAMES_PER_SYMBOL + 1);
    }

    #[test]
    fn the_count_is_part_of_the_frame_identity() {
        let with = PyAddr {
            addr: StackWalkerFrame {
                symbol_id: 7,
                inst_idx: 3,
                pad_: 1,
            },
        };
        let without = PyAddr {
            addr: StackWalkerFrame {
                symbol_id: 7,
                inst_idx: 3,
                pad_: 0,
            },
        };
        assert_ne!(with, without);
        assert_eq!(with, with.clone());
    }

    #[test]
    fn the_witness_counts_read_as_named_kinds_in_a_fixed_order() {
        let mut counts = [0u64; PTHREAD_ID_KINDS];
        counts[1] = 40;
        counts[2] = 2;
        counts[6] = 1;
        counts[7] = 3;
        assert_eq!(
            describe_pthread_id_counts(&counts),
            "match=40 mismatch=2 error=1 no_descriptor=3"
        );
        assert_eq!(describe_pthread_id_counts(&[0; PTHREAD_ID_KINDS]), "");
    }

    #[test]
    fn the_witness_is_tallied_per_process_and_an_unknown_value_counts_as_unknown() {
        let run = StackWalkerRun::new();
        run.note_pthread_id_match(7, 1);
        run.note_pthread_id_match(7, 1);
        run.note_pthread_id_match(7, 2);
        run.note_pthread_id_match(9, 3);
        run.note_pthread_id_match(9, 7);
        // A value past the enum is not a kind: it counts as "unknown".
        run.note_pthread_id_match(9, 42);
        let by_pid = run.pthread_id_by_pid.lock().unwrap();
        assert_eq!(
            describe_pthread_id_counts(&by_pid[&7]),
            "match=2 mismatch=1"
        );
        assert_eq!(
            describe_pthread_id_counts(&by_pid[&9]),
            "unknown=1 thread_state_null=1 no_descriptor=1"
        );
        assert!(!by_pid.contains_key(&8));
    }
}
