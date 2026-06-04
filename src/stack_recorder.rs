use std::collections::hash_map::RandomState;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};

use crate::pystacks::stack_walker::{PyAddr, StackWalkerRun};
use crate::record::RecordCollector;
use crate::ringbuf::RingBuffer;
use crate::systing_core::types::stack_event;
use crate::systing_core::SystingRecordEvent;
use crate::trace::{StackRecord, StackSampleRecord};
use crate::utid::{ThreadAwareRecorder, UtidGenerator};

use blazesym::helper::{read_elf_build_id, ElfResolver};
use blazesym::symbolize::source::{Kernel, Process, Source};
use blazesym::symbolize::{
    cache, Input, ProcessMemberInfo, ProcessMemberType, Resolve, Sym, Symbolizer,
};
use blazesym::Error as BlazeErr;
use blazesym::Pid;

use indicatif::{ProgressBar, ProgressStyle};

type ProcessDispatcher = Box<
    dyn for<'a> Fn(ProcessMemberInfo<'a>) -> Result<Option<Box<dyn Resolve>>, BlazeErr>
        + Send
        + Sync,
>;
use debuginfod::{BuildId, CachingClient, Client};

// Stack structure representing kernel, user, and Python stacks
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Stack {
    pub(crate) kernel_stack: Vec<u64>,
    pub(crate) user_stack: Vec<u64>,
    pub(crate) py_stack: Vec<PyAddr>,
}

/// Maximum valid user-space address (48-bit virtual address space boundary).
/// Addresses above this threshold in the user stack are garbage from bad frame pointer
/// unwinding (typically instruction bytes or other non-address data that leaked into
/// the stack frame chain).
const MAX_USER_ADDR: u64 = 0x0000_FFFF_FFFF_FFFF;

/// Filters out zero and garbage addresses from user stack and reverses to get root-to-leaf order.
fn filter_and_reverse_user_stack(addrs: &[u64]) -> Vec<u64> {
    addrs
        .iter()
        .copied()
        .filter(|&addr| addr != 0 && addr <= MAX_USER_ADDR)
        .rev()
        .collect()
}

/// Filters out zero addresses from kernel stack and reverses to get root-to-leaf order.
fn filter_and_reverse_kernel_stack(addrs: &[u64]) -> Vec<u64> {
    addrs
        .iter()
        .copied()
        .filter(|&addr| addr != 0)
        .rev()
        .collect()
}

impl Stack {
    pub fn new(kernel_stack: &[u64], user_stack: &[u64], py_stack: &[PyAddr]) -> Self {
        Self {
            kernel_stack: filter_and_reverse_kernel_stack(kernel_stack),
            user_stack: filter_and_reverse_user_stack(user_stack),
            py_stack: py_stack.to_vec(),
        }
    }
}

/// 128-bit content hash of a (stack, tgid) dedup key. Used so the recorder
/// only has to keep a 16-byte digest per unique stack in memory instead of the
/// full address vectors; the actual contents are spilled to disk until
/// end-of-trace symbolization. Two SipHash passes with independently random
/// per-run keys give 128 bits, making collisions (which would alias two
/// different stacks to one id) vanishingly unlikely — and, because the keys
/// are not known to traced processes, not constructible offline either.
fn stack_dedup_hash(hashers: &(RandomState, RandomState), stack: &Stack, tgid: i32) -> u128 {
    use std::hash::{BuildHasher, Hash, Hasher};

    let mut h1 = hashers.0.build_hasher();
    tgid.hash(&mut h1);
    stack.hash(&mut h1);
    let mut h2 = hashers.1.build_hasher();
    tgid.hash(&mut h2);
    stack.hash(&mut h2);
    ((h1.finish() as u128) << 64) | h2.finish() as u128
}

/// Disk-backed store for unique stack contents. During recording each unique
/// (stack, tgid) is appended once; at end of trace the records are streamed
/// back for symbolization. This keeps per-unique-stack memory at ~16 bytes
/// (the dedup hash) instead of the full address vectors, which on hosts with
/// heavy short-lived-process churn (CI) otherwise grow to multiple GiB.
///
/// The backing file is created unlinked (tempfile) in the trace output
/// directory. If no directory was configured (unit tests) or a write fails,
/// records are kept in memory instead.
struct StackSpill {
    writer: Option<BufWriter<File>>,
    /// In-memory fallback used when no spill dir is set or after an IO error.
    fallback: Vec<(Stack, i32, i64)>,
    /// Records handed to the writer (not in `fallback` or `pending`).
    written: u64,
    /// Records known durable: count at the last successful flush. Only records
    /// up to this point are replayed from the file if a later flush fails.
    flushed: u64,
    /// Copies of records written since the last successful flush. Moved to
    /// `fallback` on an IO error so no record is ever lost or duplicated;
    /// bounded by `SPILL_FLUSH_INTERVAL`.
    pending: Vec<(Stack, i32, i64)>,
    /// Reusable serialization buffer.
    buf: Vec<u8>,
}

/// Explicitly flush the spill BufWriter every this many records. Bounds both
/// the size of `pending` (records that fall back to memory on an IO error) and
/// the cost of the extra page-cache writes.
const SPILL_FLUSH_INTERVAL: u64 = 256;

impl StackSpill {
    fn new() -> Self {
        Self {
            writer: None,
            fallback: Vec::new(),
            written: 0,
            flushed: 0,
            pending: Vec::new(),
            buf: Vec::new(),
        }
    }

    fn set_dir(&mut self, dir: &Path) {
        match tempfile::tempfile_in(dir) {
            Ok(f) => self.writer = Some(BufWriter::new(f)),
            Err(e) => {
                eprintln!(
                    "Warning: failed to create stack spill file in {}: {e}; \
                     keeping stacks in memory",
                    dir.display()
                );
            }
        }
    }

    fn total(&self) -> u64 {
        self.written + self.fallback.len() as u64
    }

    /// Record format (little-endian):
    /// id: i64, tgid: i32, klen: u16, ulen: u16, pylen: u16,
    /// then klen+ulen u64 addresses and pylen (u32 symbol_id, i32 inst_idx).
    ///
    /// Called from the ringbuf consumer path, but only once per *unique* stack
    /// and buffered through page cache, so it does not normally block event
    /// consumption. A stalled filesystem on the output directory could.
    fn push(&mut self, stack: Stack, tgid: i32, id: i64) {
        if self.writer.is_none() {
            self.fallback.push((stack, tgid, id));
            return;
        }

        // The depth fields are u16; BPF caps kernel/user stacks at
        // MAX_STACK_DEPTH (36) and Python stacks at 127 frames, so these can
        // only fire if those limits grow past 65535.
        debug_assert!(stack.kernel_stack.len() <= u16::MAX as usize);
        debug_assert!(stack.user_stack.len() <= u16::MAX as usize);
        debug_assert!(stack.py_stack.len() <= u16::MAX as usize);

        self.buf.clear();
        self.buf.extend_from_slice(&id.to_le_bytes());
        self.buf.extend_from_slice(&tgid.to_le_bytes());
        self.buf
            .extend_from_slice(&(stack.kernel_stack.len() as u16).to_le_bytes());
        self.buf
            .extend_from_slice(&(stack.user_stack.len() as u16).to_le_bytes());
        self.buf
            .extend_from_slice(&(stack.py_stack.len() as u16).to_le_bytes());
        for addr in &stack.kernel_stack {
            self.buf.extend_from_slice(&addr.to_le_bytes());
        }
        for addr in &stack.user_stack {
            self.buf.extend_from_slice(&addr.to_le_bytes());
        }
        for py in &stack.py_stack {
            self.buf.extend_from_slice(&py.addr.symbol_id.to_le_bytes());
            self.buf.extend_from_slice(&py.addr.inst_idx.to_le_bytes());
        }

        let writer = self.writer.as_mut().expect("writer checked above");
        if let Err(e) = writer.write_all(&self.buf) {
            // Anything since the last successful flush (including this record)
            // moves to the in-memory fallback; the reader only replays up to
            // `flushed`, so nothing is lost or duplicated.
            eprintln!(
                "Warning: stack spill write failed ({e}); keeping {} affected stacks \
                 (and all further ones) in memory",
                self.pending.len() + 1
            );
            self.writer = None;
            self.written = self.flushed;
            self.fallback.append(&mut self.pending);
            self.fallback.push((stack, tgid, id));
            return;
        }
        self.written += 1;
        self.pending.push((stack, tgid, id));

        if self.written - self.flushed >= SPILL_FLUSH_INTERVAL {
            match writer.flush() {
                Ok(()) => {
                    self.flushed = self.written;
                    self.pending.clear();
                }
                Err(e) => {
                    eprintln!(
                        "Warning: stack spill flush failed ({e}); keeping {} affected \
                         stacks (and all further ones) in memory",
                        self.pending.len()
                    );
                    self.writer = None;
                    self.written = self.flushed;
                    self.fallback.append(&mut self.pending);
                }
            }
        }
    }

    /// Flush and rewind the spill file for reading. Returns the reader plus
    /// the number of durable records to replay; `None` if nothing was spilled
    /// to disk. On a final-flush failure the file prefix written so far is
    /// still replayed and the unflushed tail is recovered from `pending`.
    fn take_reader(&mut self) -> Option<(BufReader<File>, u64)> {
        let mut writer = self.writer.take()?;
        match writer.flush() {
            Ok(()) => {
                self.flushed = self.written;
                self.pending.clear();
            }
            Err(e) => {
                eprintln!(
                    "Warning: failed to flush stack spill file ({e}); recovering {} \
                     buffered stacks from memory",
                    self.pending.len()
                );
                self.written = self.flushed;
                self.fallback.append(&mut self.pending);
            }
        }
        // into_parts (rather than into_inner) so a flush failure above cannot
        // cost us the file: the already-flushed prefix is always readable.
        let (mut f, _) = writer.into_parts();
        match f.seek(SeekFrom::Start(0)) {
            Ok(_) => Some((BufReader::new(f), self.flushed)),
            Err(e) => {
                eprintln!(
                    "Warning: failed to rewind stack spill file: {e}; {} stacks will \
                     be missing from the trace",
                    self.flushed
                );
                None
            }
        }
    }
}

/// Approximate anonymous RSS of this process in bytes (resident minus
/// file-backed shared pages, from /proc/self/statm).
fn current_anon_rss_bytes() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/statm").ok()?;
    let mut it = s.split_whitespace();
    let _size = it.next()?;
    let resident: u64 = it.next()?.parse().ok()?;
    let shared: u64 = it.next()?.parse().ok()?;
    // SAFETY: sysconf is always safe to call; _SC_PAGESIZE cannot fail.
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
    Some(resident.saturating_sub(shared) * page_size)
}

/// Memory budget for the symbolization phase. blazesym retains parsed debug
/// info for every live binary it symbolizes (with code-info and inlined-fn
/// resolution this can be GiBs for large debug-heavy binaries), so the
/// symbolization loop periodically checks anon RSS against this budget and
/// rebuilds the symbolizer when it is exceeded.
fn symbolizer_memory_budget() -> u64 {
    const DEFAULT_BUDGET: u64 = 2 << 30; // 2 GiB
    crate::duckdb::detect_cgroup_memory_limit()
        .map(|limit| limit / 2)
        .unwrap_or(DEFAULT_BUDGET)
        .clamp(256 << 20, 16 << 30)
}

/// Memory-bounded interner for unique (stack, tgid) pairs, shared by the
/// stack and memory recorders. Keeps only a 16-byte content hash per unique
/// stack in memory and spills the address vectors to disk (see [`StackSpill`]);
/// `StackRecorder::finish` replays the contents for symbolization.
pub(crate) struct StackInterner {
    /// 128-bit content hash of (stack, tgid) -> assigned stack id.
    stack_ids: HashMap<u128, i64>,
    /// Per-run random keys for the dedup hash, so collisions cannot be
    /// precomputed by traced processes.
    hashers: (RandomState, RandomState),
    spill: StackSpill,
    /// Next stack id to assign. Each interner owns a disjoint id range
    /// (the memory recorder's starts at MEMORY_STACK_ID_OFFSET).
    next_id: i64,
    /// Ids at or beyond this value belong to another interner's range.
    /// Crossing it would silently corrupt stack joins, so `intern` warns.
    /// Practically unreachable: ~40-50 bytes of dedup map per unique stack
    /// means the process runs out of memory orders of magnitude earlier.
    id_limit: Option<i64>,
    id_limit_warned: bool,
}

impl StackInterner {
    pub(crate) fn new(first_id: i64) -> Self {
        Self {
            stack_ids: HashMap::new(),
            hashers: (RandomState::new(), RandomState::new()),
            spill: StackSpill::new(),
            next_id: first_id,
            id_limit: None,
            id_limit_warned: false,
        }
    }

    pub(crate) fn with_id_limit(mut self, limit: i64) -> Self {
        self.id_limit = Some(limit);
        self
    }

    /// Configure the directory for the spill file. Must be called before
    /// recording starts; without it, stack contents are kept in memory.
    pub(crate) fn set_spill_dir(&mut self, dir: &Path) {
        self.spill.set_dir(dir);
    }

    /// Get or assign the stack id for this (stack, tgid) pair, persisting the
    /// contents on first sight.
    pub(crate) fn intern(&mut self, stack: Stack, tgid: i32) -> i64 {
        let hash = stack_dedup_hash(&self.hashers, &stack, tgid);
        if let Some(&id) = self.stack_ids.get(&hash) {
            return id;
        }
        let id = self.next_id;
        self.next_id += 1;
        if !self.id_limit_warned && self.id_limit.is_some_and(|limit| id >= limit) {
            self.id_limit_warned = true;
            eprintln!(
                "Warning: stack id {id} crossed into another interner's range (>= {}); \
                 stack table joins may be ambiguous",
                self.id_limit.unwrap_or(0)
            );
        }
        self.stack_ids.insert(hash, id);
        self.spill.push(stack, tgid, id);
        id
    }

    /// Number of unique stacks interned.
    pub(crate) fn total(&self) -> u64 {
        self.spill.total()
    }
}

/// Emit a symbolized stack as a StackRecord (skipping empty stacks).
fn emit_stack_record(
    collector: &mut dyn RecordCollector,
    stack_id: i64,
    frame_names: Vec<String>,
) -> Result<()> {
    if frame_names.is_empty() {
        return Ok(());
    }
    let leaf_name = frame_names.first().cloned().unwrap_or_default();
    let depth = frame_names.len().min(i32::MAX as usize) as i32;
    collector.add_stack(StackRecord {
        id: stack_id,
        frame_names,
        depth,
        leaf_name,
    })
}

/// Read one spill record. Returns `Ok(None)` on clean EOF, `Err` on a torn
/// record (which terminates reading; the writer warned when it happened).
fn read_spill_record(reader: &mut BufReader<File>) -> Result<Option<(Stack, i32, i64)>> {
    let mut hdr = [0u8; 18];
    match reader.read_exact(&mut hdr[..1]) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e).context("reading stack spill record header"),
    }
    reader
        .read_exact(&mut hdr[1..])
        .context("reading stack spill record header")?;

    let id = i64::from_le_bytes(hdr[0..8].try_into().unwrap());
    let tgid = i32::from_le_bytes(hdr[8..12].try_into().unwrap());
    let klen = u16::from_le_bytes(hdr[12..14].try_into().unwrap()) as usize;
    let ulen = u16::from_le_bytes(hdr[14..16].try_into().unwrap()) as usize;
    let pylen = u16::from_le_bytes(hdr[16..18].try_into().unwrap()) as usize;

    let mut addrs = vec![0u8; (klen + ulen) * 8 + pylen * 8];
    reader
        .read_exact(&mut addrs)
        .context("reading stack spill record body")?;

    let mut off = 0;
    let read_u64s = |n: usize, off: &mut usize| -> Vec<u64> {
        let v = addrs[*off..*off + n * 8]
            .chunks_exact(8)
            .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
            .collect();
        *off += n * 8;
        v
    };
    let kernel_stack = read_u64s(klen, &mut off);
    let user_stack = read_u64s(ulen, &mut off);
    let py_stack = addrs[off..off + pylen * 8]
        .chunks_exact(8)
        .map(|c| PyAddr {
            addr: crate::pystacks::types::StackWalkerFrame {
                symbol_id: u32::from_le_bytes(c[0..4].try_into().unwrap()),
                inst_idx: i32::from_le_bytes(c[4..8].try_into().unwrap()),
            },
        })
        .collect();

    Ok(Some((
        Stack {
            kernel_stack,
            user_stack,
            py_stack,
        },
        tgid,
        id,
    )))
}

/// Convert BPF stack_event_type (u32) to i8, clamping to valid range.
/// Valid values are 0 (STACK_SLEEP_UNINTERRUPTIBLE), 1 (STACK_RUNNING), 2 (STACK_SLEEP_INTERRUPTIBLE).
/// Unknown values are preserved but clamped to i8::MAX to avoid truncation issues.
#[inline]
fn convert_stack_event_type(bpf_type: u32) -> i8 {
    if bpf_type <= i8::MAX as u32 {
        bpf_type as i8
    } else {
        // Clamp to max i8 value to indicate unknown/invalid type
        i8::MAX
    }
}

pub struct StackRecorder {
    pub(crate) ringbuf: RingBuffer<stack_event>,
    pub(crate) psr: Arc<StackWalkerRun>,
    process_dispatcher: Option<Arc<ProcessDispatcher>>,
    // Streaming support
    /// Collector for emitting StackSampleRecords as they arrive. When set, samples
    /// are written immediately in handle_event() and stacks are deduplicated during
    /// recording for end-of-trace symbolization via finish().
    streaming_collector: Option<Box<dyn RecordCollector + Send>>,
    /// Dedup + disk spill of unique (stack, tgid) contents seen by this
    /// recorder. The tgid is part of the dedup key because the same addresses
    /// in different processes may resolve to different symbols (e.g., shared
    /// libraries at fixed addresses).
    interner: StackInterner,
    /// Interners handed over by other recorders (the memory recorder) at
    /// trace end; their stacks are symbolized alongside this recorder's in
    /// `finish()`. Id ranges are disjoint per interner, so identical contents
    /// interned by two recorders simply emit one StackRecord per id.
    external_interners: Vec<StackInterner>,
    /// Shared utid generator for consistent thread IDs across all recorders.
    utid_generator: Arc<UtidGenerator>,
}

impl ThreadAwareRecorder for StackRecorder {
    fn utid_generator(&self) -> &UtidGenerator {
        &self.utid_generator
    }
}

impl StackRecorder {
    pub fn new(enable_debuginfod: bool, utid_generator: Arc<UtidGenerator>) -> Self {
        let process_dispatcher = if enable_debuginfod {
            create_debuginfod_dispatcher()
        } else {
            None
        };

        Self {
            ringbuf: RingBuffer::default(),
            psr: Arc::new(StackWalkerRun::default()),
            process_dispatcher,
            streaming_collector: None,
            interner: StackInterner::new(1)
                .with_id_limit(crate::memory_recorder::MEMORY_STACK_ID_OFFSET),
            external_interners: Vec::new(),
            utid_generator,
        }
    }

    /// Enable streaming mode and attach a collector so that StackSampleRecords
    /// are emitted immediately in handle_event() rather than accumulated for the
    /// entire trace. Unique stack contents are spilled (see `set_spill_dir`)
    /// for end-of-trace symbolization.
    pub fn set_streaming_collector(&mut self, collector: Box<dyn RecordCollector + Send>) {
        self.streaming_collector = Some(collector);
    }

    /// Configure the directory for the unique-stack spill file. Must be called
    /// before recording starts; without it, stack contents are kept in memory.
    pub fn set_spill_dir(&mut self, dir: &Path) {
        self.interner.set_spill_dir(dir);
    }

    /// Take ownership of another recorder's interner so its stacks are
    /// symbolized and emitted alongside profiler stacks in `finish()`.
    /// Interners use disjoint id ranges, so ids never collide; identical
    /// contents interned by both recorders emit one StackRecord per id.
    pub(crate) fn merge_external_interner(&mut self, interner: StackInterner) {
        self.external_interners.push(interner);
    }

    /// Create a symbolizer with the configured process dispatcher.
    fn create_symbolizer(&self) -> Symbolizer {
        if let Some(dispatcher) = &self.process_dispatcher {
            let dispatcher = dispatcher.clone();
            Symbolizer::builder()
                .enable_code_info(true)
                .enable_inlined_fns(true)
                .set_process_dispatcher(move |info| dispatcher(info))
                .build()
        } else {
            Symbolizer::builder()
                .enable_code_info(true)
                .enable_inlined_fns(true)
                .build()
        }
    }

    /// Finish streaming and symbolize all unique stacks.
    ///
    /// This method should be called at the end of recording to:
    /// 1. Flush any remaining pending samples to the collector
    /// 2. Symbolize all unique stacks collected during recording
    /// 3. Stream StackRecords for each unique stack
    ///
    /// # Arguments
    /// * `collector` - The collector to write samples and stacks to. This is typically
    ///   the collector returned by sched recorder's finish().
    ///
    /// Returns the collector so it can be passed to other recorders or finished.
    pub fn finish(
        &mut self,
        collector: Box<dyn RecordCollector + Send>,
    ) -> Result<Box<dyn RecordCollector + Send>> {
        debug_assert!(
            self.streaming_collector.is_some(),
            "StackRecorder requires a streaming collector; non-streaming mode has been removed"
        );

        // Stack samples have already been written to the streaming collector
        // incrementally. Route the symbolized stacks through it as well, finish
        // it, and hand the caller's collector back untouched.
        let mut own = self
            .streaming_collector
            .take()
            .expect("streaming collector must be set");
        self.finish_inner(own.as_mut())?;
        own.flush()?;
        own.finish_boxed()?;
        Ok(collector)
    }

    fn finish_inner(&mut self, collector: &mut dyn RecordCollector) -> Result<()> {
        // Move all interners (own + external) out of self so their spills can
        // be replayed while `self` stays borrowable for symbolization, and so
        // each interner's dedup table and fallback storage are freed as soon as
        // it has been drained.
        let mut interners = vec![std::mem::replace(&mut self.interner, StackInterner::new(1))];
        interners.append(&mut self.external_interners);

        let total: u64 = interners.iter().map(|i| i.total()).sum();
        if total == 0 {
            return Ok(());
        }

        // Symbolize all unique stacks and stream StackRecords
        let pb = ProgressBar::new(total);
        pb.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} stacks ({per_sec}, {eta})"
                )
                .expect("Failed to set progress bar template")
                .progress_chars("#>-"),
        );
        pb.set_message("Symbolizing stacks");

        let mut symbolizer = self.create_symbolizer();

        // Create kernel source once - it's shared across all processes
        let kernel_src = Source::Kernel(Kernel::default());

        // Kernel address cache: blazesym caches metadata (KASLR, kallsyms
        // parsing) but not individual symbolization results, and the KASLR
        // offset is system-wide so the same kernel address resolves identically
        // for all processes.
        let mut kernel_cache: HashMap<u64, String> = HashMap::new();

        // Pass 1: stream spilled stacks back from disk one record at a time
        // (then any kept in memory). Stacks of exited processes are emitted
        // immediately: their user addresses cannot be symbolized at all
        // (blazesym needs /proc/<pid>/maps), so they only need the kernel cache
        // and a hex rendering, and their address vectors are freed right away.
        // Stacks of live processes are grouped per tgid for pass 2.
        //
        // Under heavy short-lived-process churn (CI) nearly everything is dead
        // by now, so this pass keeps peak memory flat where the old
        // hold-everything approach grew to multiple GiB.
        let mut live_groups: HashMap<i32, Vec<(Stack, i64)>> = HashMap::new();
        let mut tgid_alive: HashMap<i32, bool> = HashMap::new();

        let mut handle_record = |this: &Self,
                                 symbolizer: &mut Symbolizer,
                                 kernel_cache: &mut HashMap<u64, String>,
                                 live_groups: &mut HashMap<i32, Vec<(Stack, i64)>>,
                                 stack: Stack,
                                 tgid: i32,
                                 stack_id: i64|
         -> Result<()> {
            let alive = *tgid_alive
                .entry(tgid)
                .or_insert_with(|| Path::new("/proc").join(tgid.to_string()).exists());
            if alive {
                live_groups.entry(tgid).or_default().push((stack, stack_id));
                return Ok(());
            }

            let frame_names =
                this.symbolize_stack_frames(symbolizer, &stack, None, &kernel_src, kernel_cache);
            pb.inc(1);
            emit_stack_record(collector, stack_id, frame_names)
        };

        // Each interner is dropped at the end of its loop iteration, releasing
        // its dedup table before the (memory-hungry) live-group pass below.
        for mut interner in interners {
            if let Some((mut reader, durable_records)) = interner.spill.take_reader() {
                for _ in 0..durable_records {
                    match read_spill_record(&mut reader) {
                        Ok(Some((stack, tgid, stack_id))) => {
                            handle_record(
                                self,
                                &mut symbolizer,
                                &mut kernel_cache,
                                &mut live_groups,
                                stack,
                                tgid,
                                stack_id,
                            )?;
                        }
                        Ok(None) => break,
                        Err(e) => {
                            eprintln!("Warning: stopping stack spill replay early: {e:#}");
                            break;
                        }
                    }
                }
            }
            for (stack, tgid, stack_id) in std::mem::take(&mut interner.spill.fallback) {
                handle_record(
                    self,
                    &mut symbolizer,
                    &mut kernel_cache,
                    &mut live_groups,
                    stack,
                    tgid,
                    stack_id,
                )?;
            }
        }

        // Pass 2: symbolize live processes one tgid at a time. blazesym
        // accumulates parsed debug info for every binary it touches with no
        // eviction (with code-info and inlined-fn resolution this can reach
        // GiBs for debug-heavy binaries), so anon RSS is checked against a
        // budget after each group and periodically within large groups, and
        // the symbolizer is rebuilt when it is exceeded. Grouping per tgid
        // means each process's binaries are normally parsed once; a rebuild
        // costs re-parsing for addresses not already in the string caches.
        //
        // `rebuild_floor` is the RSS right after the last rebuild: if a rebuild
        // doesn't actually free memory (the budget is exceeded by things a
        // rebuild can't touch, or one binary's debug info alone exceeds it),
        // further rebuilds would only thrash re-parsing, so the valve waits for
        // real growth above the floor before firing again.
        let memory_budget = symbolizer_memory_budget();
        const VALVE_CHECK_INTERVAL: usize = 8192;
        const REBUILD_GROWTH_MARGIN: u64 = 256 << 20;
        let mut rebuild_floor: u64 = 0;
        let mut maybe_rebuild = |this: &Self, symbolizer: &mut Symbolizer| {
            let Some(anon) = current_anon_rss_bytes() else {
                return;
            };
            if anon <= memory_budget || anon <= rebuild_floor.saturating_add(REBUILD_GROWTH_MARGIN)
            {
                return;
            }
            *symbolizer = this.create_symbolizer();
            // SAFETY: malloc_trim is always safe to call on glibc.
            unsafe {
                libc::malloc_trim(0);
            }
            rebuild_floor = current_anon_rss_bytes().unwrap_or(anon);
            eprintln!(
                "Note: symbolizer caches rebuilt to stay under memory budget ({} MiB)",
                memory_budget >> 20
            );
        };

        for (tgid, stacks) in live_groups {
            // Pre-cache process metadata for this tgid (best-effort
            // optimization; failure doesn't affect correctness).
            let _ = symbolizer.cache(&cache::Cache::from(cache::Process::new(
                (tgid as u32).into(),
            )));
            let proc_src = Source::Process(Process::new(Pid::from(tgid as u32)));
            // Per-process user-address cache, freed with the group. Survives a
            // mid-group rebuild, so already-resolved addresses are not re-done.
            let mut user_cache: HashMap<u64, String> = HashMap::new();

            for (i, (stack, stack_id)) in stacks.into_iter().enumerate() {
                if i > 0 && i % VALVE_CHECK_INTERVAL == 0 {
                    maybe_rebuild(self, &mut symbolizer);
                }
                let frame_names = self.symbolize_stack_frames(
                    &mut symbolizer,
                    &stack,
                    Some((&proc_src, &mut user_cache)),
                    &kernel_src,
                    &mut kernel_cache,
                );
                pb.inc(1);
                emit_stack_record(collector, stack_id, frame_names)?;
            }

            maybe_rebuild(self, &mut symbolizer);
        }

        pb.finish_with_message("Stack symbolization complete");

        Ok(())
    }

    /// Symbolize a single stack and return frame names.
    ///
    /// `user` carries the process source and per-process address cache for a
    /// live process; `None` means the process has exited, in which case user
    /// addresses are rendered as raw hex (symbolization cannot succeed without
    /// /proc/<pid>/maps). Kernel addresses go through the shared `kernel_cache`.
    fn symbolize_stack_frames(
        &self,
        symbolizer: &mut Symbolizer,
        stack: &Stack,
        user: Option<(&Source<'_>, &mut HashMap<u64, String>)>,
        kernel_src: &Source<'_>,
        kernel_cache: &mut HashMap<u64, String>,
    ) -> Vec<String> {
        let mut frame_names = Vec::with_capacity(
            stack.user_stack.len() + stack.kernel_stack.len() + stack.py_stack.len(),
        );

        // Symbolize Python stack first (if present)
        let python_frames = self.psr.get_python_frame_names(&stack.py_stack);
        frame_names.extend(python_frames);

        // Symbolize user addresses (leaf)
        match user {
            Some((proc_src, user_cache)) => {
                for &addr in &stack.user_stack {
                    let frame_name = user_cache
                        .entry(addr)
                        .or_insert_with(|| {
                            symbolizer
                                .symbolize_single(proc_src, Input::AbsAddr(addr))
                                .ok()
                                .and_then(|s| s.into_sym())
                                .map(|s| format_symbolized_frame(&s, addr, "unknown"))
                                .unwrap_or_else(|| format!("0x{addr:x}"))
                        })
                        .clone();
                    frame_names.push(frame_name);
                }
            }
            None => {
                for &addr in &stack.user_stack {
                    frame_names.push(format!("0x{addr:x}"));
                }
            }
        }

        // Symbolize kernel addresses (root).
        for &addr in &stack.kernel_stack {
            let frame_name = kernel_cache
                .entry(addr)
                .or_insert_with(|| {
                    symbolizer
                        .symbolize_single(kernel_src, Input::AbsAddr(addr))
                        .ok()
                        .and_then(|s| s.into_sym())
                        .map(|s| format_symbolized_frame(&s, addr, "[kernel]"))
                        .unwrap_or_else(|| format!("unknown ([kernel]) <{addr:#x}>"))
                })
                .clone();
            frame_names.push(frame_name);
        }

        frame_names
    }

    pub fn init_pystacks(&mut self, pids: &[u32], bpf_object: &libbpf_rs::Object, debug: bool) {
        let psr = Arc::get_mut(&mut self.psr).expect(
            "Unable to initialize pystacks: Arc is already shared. \
             The symbol loader thread must not be spawned before init_pystacks.",
        );
        psr.init_pystacks(pids, bpf_object, debug);
    }
}

/// Formats code location information as a string suffix (e.g., "[file.rs:123]")
fn format_location_info(code_info: Option<&blazesym::symbolize::CodeInfo>) -> String {
    code_info.map_or(String::new(), |info| {
        let file_name = info.file.to_str().unwrap_or("unknown");
        if let Some(line) = info.line {
            format!(" [{file_name}:{line}]")
        } else {
            format!(" [{file_name}]")
        }
    })
}

/// Formats a symbolized frame as a string with module and location info.
/// Format: "function_name (module_name [file:line]) <0xaddr>"
fn format_symbolized_frame(sym: &Sym, addr: u64, default_module: &str) -> String {
    let module_name = sym
        .module
        .as_ref()
        .and_then(|m| m.to_str())
        .and_then(|m| std::path::Path::new(m).file_name())
        .and_then(|f| f.to_str())
        .unwrap_or(default_module);
    let location_info = format_location_info(sym.code_info.as_deref());
    format!(
        "{} ({}{}) <{:#x}>",
        sym.name, module_name, location_info, addr
    )
}

/// Create a debuginfod dispatcher if debuginfod is available in the environment
fn create_debuginfod_dispatcher() -> Option<Arc<ProcessDispatcher>> {
    match Client::from_env() {
        Ok(Some(client)) => match CachingClient::from_env(client) {
            Ok(caching_client) => {
                println!("Debuginfod enabled: using debuginfod for symbol resolution");

                // Wrap the CachingClient in an Arc so it can be shared across threads.
                // The closure below will take ownership of this Arc (via the `move` keyword),
                // storing it as part of the closure's captured state. When the closure is
                // called during symbolization, it will clone the Arc to pass to
                // dispatch_process_with_client. The CachingClient itself remains shared
                // across all threads (only the Arc reference is cloned, not the client).
                // The closure and its captured Arc<CachingClient> will live as long as the
                // StackRecorder that owns the process_dispatcher field.
                let client = Arc::new(caching_client);
                Some(Arc::new(Box::new(move |info: ProcessMemberInfo<'_>| -> Result<Option<Box<dyn Resolve>>, BlazeErr> {
                    dispatch_process_with_client(info, client.clone())
                }) as ProcessDispatcher))
            }
            Err(e) => {
                println!("Failed to create caching debuginfod client: {e}, using default resolver");
                None
            }
        },
        Ok(None) => {
            println!("No debuginfod URLs found in environment, using default resolver. If using sudo try --preserve-env");
            None
        }
        Err(e) => {
            println!("Failed to create debuginfod client: {e}, using default resolver");
            None
        }
    }
}

/// Callback function for process dispatcher that fetches debug info using debuginfod
fn dispatch_process_with_client(
    info: ProcessMemberInfo<'_>,
    client: Arc<CachingClient>,
) -> Result<Option<Box<dyn Resolve>>, BlazeErr> {
    let ProcessMemberInfo {
        member_entry: entry,
        ..
    } = info;

    match entry {
        ProcessMemberType::Path(path) => {
            let build_id = if let Some(build_id) = read_elf_build_id(&path.maps_file)? {
                BuildId::raw(build_id)
            } else {
                return Ok(None);
            };

            println!("Fetching debug info for build ID: {}", &build_id);
            let path = if let Some(path) = client.fetch_debug_info(&build_id).map_err(Box::from)? {
                path
            } else {
                return Ok(None);
            };
            println!("Fetched debug info from debuginfod: {}", path.display());

            let resolver = ElfResolver::open(&path).map_err(Box::from)?;
            Ok(Some(Box::new(resolver)))
        }
        ProcessMemberType::Component(..) => Ok(None),
        _ => Ok(None),
    }
}

impl SystingRecordEvent<stack_event> for StackRecorder {
    fn ringbuf(&self) -> &RingBuffer<stack_event> {
        &self.ringbuf
    }
    fn ringbuf_mut(&mut self) -> &mut RingBuffer<stack_event> {
        &mut self.ringbuf
    }
    fn handle_event(&mut self, event: stack_event) {
        let py_stack_len = event.py_msg_buffer.stack_len;

        let has_stack =
            event.user_stack_length > 0 || event.kernel_stack_length > 0 || py_stack_len > 0;

        if has_stack {
            let kstack_vec = Vec::from(&event.kernel_stack[..event.kernel_stack_length as usize]);
            let ustack_vec = Vec::from(&event.user_stack[..event.user_stack_length as usize]);
            let stack_key = (event.task.tgidpid >> 32) as i32;
            let py_stack = self.psr.get_pystack_from_event(&event);

            let stack = Stack::new(&kstack_vec, &ustack_vec, &py_stack);
            let tid = event.task.tgidpid as i32;
            let tgid = stack_key; // tgid for process-specific symbolization

            debug_assert!(
                self.streaming_collector.is_some(),
                "StackRecorder requires a streaming collector; non-streaming mode has been removed"
            );

            // Streaming mode: dedupe stacks and emit samples directly to the collector
            if let Some(collector) = &mut self.streaming_collector {
                // Get or assign stack_id for this (stack, tgid) pair.
                // Include tgid in key since same addresses may resolve differently
                // per-process. Only the content hash is kept in memory; new stacks
                // are spilled to disk for end-of-trace symbolization.
                let stack_id = self.interner.intern(stack, tgid);

                let sample = StackSampleRecord {
                    ts: event.ts as i64,
                    utid: self.utid_generator.get_or_create_utid(tid),
                    cpu: Some(event.cpu as i32),
                    stack_id,
                    stack_event_type: convert_stack_event_type(event.stack_event_type.0),
                };

                if let Err(e) = collector.add_stack_sample(sample) {
                    eprintln!("Warning: Failed to stream stack sample: {e}");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_and_reverse_user_stack() {
        // Test zero filtering
        assert_eq!(filter_and_reverse_user_stack(&[0, 0x1000, 0]), vec![0x1000]);

        // Test reversal
        assert_eq!(
            filter_and_reverse_user_stack(&[0x1000, 0x2000]),
            vec![0x2000, 0x1000]
        );

        // Test MAX_USER_ADDR boundary - address at boundary should be kept
        assert_eq!(
            filter_and_reverse_user_stack(&[0x1000, MAX_USER_ADDR]),
            vec![MAX_USER_ADDR, 0x1000]
        );

        // Test garbage addresses above MAX_USER_ADDR are filtered
        assert_eq!(
            filter_and_reverse_user_stack(&[0x1000, MAX_USER_ADDR + 1]),
            vec![0x1000]
        );

        // Test typical garbage from bad frame pointer unwinding (instruction bytes)
        assert_eq!(
            filter_and_reverse_user_stack(&[0x7f0000001000, 0xc48348d88948ff31]),
            vec![0x7f0000001000]
        );

        // Empty stack
        assert_eq!(filter_and_reverse_user_stack(&[]), Vec::<u64>::new());

        // All zeros
        assert_eq!(filter_and_reverse_user_stack(&[0, 0, 0]), Vec::<u64>::new());
    }

    #[test]
    fn test_filter_and_reverse_kernel_stack() {
        // Test zero filtering
        assert_eq!(
            filter_and_reverse_kernel_stack(&[0, 0xffffffff81000000, 0]),
            vec![0xffffffff81000000]
        );

        // Test reversal
        assert_eq!(
            filter_and_reverse_kernel_stack(&[0xffffffff81000000, 0xffffffff82000000]),
            vec![0xffffffff82000000, 0xffffffff81000000]
        );

        // Kernel addresses above MAX_USER_ADDR should be kept
        assert_eq!(
            filter_and_reverse_kernel_stack(&[0xffffffff81000000]),
            vec![0xffffffff81000000]
        );

        // Empty stack
        assert_eq!(filter_and_reverse_kernel_stack(&[]), Vec::<u64>::new());
    }

    #[test]
    fn test_stack_spill_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let mut spill = StackSpill::new();
        spill.set_dir(dir.path());
        assert!(spill.writer.is_some(), "spill file should be created");

        let py = vec![PyAddr {
            addr: crate::pystacks::types::StackWalkerFrame {
                symbol_id: 7,
                inst_idx: -1,
            },
        }];
        let stacks = [
            (
                Stack {
                    kernel_stack: vec![0xffffffff81000000, 0xffffffff82000000],
                    user_stack: vec![0x7f0000001000],
                    py_stack: py.clone(),
                },
                42,
                1,
            ),
            (
                Stack {
                    kernel_stack: vec![],
                    user_stack: vec![0x1000, 0x2000, 0x3000],
                    py_stack: vec![],
                },
                -1,
                1_000_000_007,
            ),
            (
                Stack {
                    kernel_stack: vec![],
                    user_stack: vec![],
                    py_stack: py,
                },
                i32::MAX,
                i64::MAX,
            ),
        ];
        for (stack, tgid, id) in &stacks {
            spill.push(stack.clone(), *tgid, *id);
        }
        assert_eq!(spill.total(), 3);
        assert!(spill.fallback.is_empty());

        let (mut reader, durable) = spill.take_reader().expect("reader");
        assert_eq!(durable, 3);
        for (stack, tgid, id) in &stacks {
            let (rstack, rtgid, rid) = read_spill_record(&mut reader).unwrap().unwrap();
            assert_eq!(&rstack, stack);
            assert_eq!(rtgid, *tgid);
            assert_eq!(rid, *id);
        }
        assert!(read_spill_record(&mut reader).unwrap().is_none());
    }

    #[test]
    fn test_stack_spill_periodic_flush() {
        let dir = tempfile::tempdir().unwrap();
        let mut spill = StackSpill::new();
        spill.set_dir(dir.path());

        let n = SPILL_FLUSH_INTERVAL * 2 + 7;
        for i in 0..n {
            let stack = Stack {
                kernel_stack: vec![i],
                user_stack: vec![i + 1],
                py_stack: vec![],
            };
            spill.push(stack, i as i32, i as i64);
        }
        // Two full flush intervals are durable; the remainder is pending.
        assert_eq!(spill.flushed, SPILL_FLUSH_INTERVAL * 2);
        assert_eq!(spill.pending.len(), 7);
        assert_eq!(spill.total(), n);

        let (mut reader, durable) = spill.take_reader().expect("reader");
        assert_eq!(durable, n, "final flush makes everything durable");
        assert!(spill.pending.is_empty());
        for i in 0..n {
            let (rstack, rtgid, rid) = read_spill_record(&mut reader).unwrap().unwrap();
            assert_eq!(rstack.kernel_stack, vec![i]);
            assert_eq!(rtgid, i as i32);
            assert_eq!(rid, i as i64);
        }
        assert!(read_spill_record(&mut reader).unwrap().is_none());
    }

    #[test]
    fn test_stack_spill_fallback_without_dir() {
        let mut spill = StackSpill::new();
        let stack = Stack {
            kernel_stack: vec![1],
            user_stack: vec![2],
            py_stack: vec![],
        };
        spill.push(stack.clone(), 5, 9);
        assert_eq!(spill.total(), 1);
        assert_eq!(spill.fallback, vec![(stack, 5, 9)]);
        assert!(spill.take_reader().is_none());
    }

    #[test]
    fn test_stack_interner() {
        let dir = tempfile::tempdir().unwrap();
        let mut interner = StackInterner::new(1_000_000_000);
        interner.set_spill_dir(dir.path());

        let a = Stack {
            kernel_stack: vec![0xffffffff81000000],
            user_stack: vec![0x1000],
            py_stack: vec![],
        };
        let b = Stack {
            kernel_stack: vec![0xffffffff81000000],
            user_stack: vec![0x2000],
            py_stack: vec![],
        };

        // Ids start at the configured offset and dedup by content + tgid.
        let id_a = interner.intern(a.clone(), 1);
        assert_eq!(id_a, 1_000_000_000);
        assert_eq!(interner.intern(a.clone(), 1), id_a);
        let id_b = interner.intern(b.clone(), 1);
        assert_eq!(id_b, 1_000_000_001);
        let id_a2 = interner.intern(a.clone(), 2);
        assert_eq!(id_a2, 1_000_000_002);
        assert_eq!(interner.total(), 3);

        // Contents are persisted once per unique (stack, tgid).
        let (mut reader, durable) = interner.spill.take_reader().expect("reader");
        assert_eq!(durable, 3);
        let expected = [(a.clone(), 1, id_a), (b, 1, id_b), (a, 2, id_a2)];
        for (stack, tgid, id) in &expected {
            let (rstack, rtgid, rid) = read_spill_record(&mut reader).unwrap().unwrap();
            assert_eq!(&rstack, stack);
            assert_eq!(rtgid, *tgid);
            assert_eq!(rid, *id);
        }
        assert!(read_spill_record(&mut reader).unwrap().is_none());
    }

    #[test]
    fn test_stack_dedup_hash() {
        let h = (RandomState::new(), RandomState::new());
        let a = Stack {
            kernel_stack: vec![0xffffffff81000000],
            user_stack: vec![0x1000],
            py_stack: vec![],
        };
        let b = a.clone();
        assert_eq!(stack_dedup_hash(&h, &a, 1), stack_dedup_hash(&h, &b, 1));
        // Different tgid must produce a different key
        assert_ne!(stack_dedup_hash(&h, &a, 1), stack_dedup_hash(&h, &a, 2));
        // Different contents must produce a different key
        let c = Stack {
            kernel_stack: vec![0xffffffff81000000],
            user_stack: vec![0x1001],
            py_stack: vec![],
        };
        assert_ne!(stack_dedup_hash(&h, &a, 1), stack_dedup_hash(&h, &c, 1));
        // Moving an address between kernel and user stacks must change the key
        let d = Stack {
            kernel_stack: vec![],
            user_stack: vec![0xffffffff81000000, 0x1000],
            py_stack: vec![],
        };
        assert_ne!(stack_dedup_hash(&h, &a, 1), stack_dedup_hash(&h, &d, 1));
    }

    #[test]
    fn test_convert_stack_event_type() {
        assert_eq!(convert_stack_event_type(0), 0);
        assert_eq!(convert_stack_event_type(1), 1);
        assert_eq!(convert_stack_event_type(2), 2);
        assert_eq!(convert_stack_event_type(127), 127);
        assert_eq!(convert_stack_event_type(128), i8::MAX);
        assert_eq!(convert_stack_event_type(u32::MAX), i8::MAX);
    }
}
