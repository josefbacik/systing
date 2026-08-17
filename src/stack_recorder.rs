use std::collections::hash_map::RandomState;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};

use crate::build_id_store::{build_id_hex, BuildIdStore};
use crate::gvisor_guest::{GuestAddr, GuestProcess, SandboxIndex};
use crate::pystacks::stack_walker::{PyAddr, StackWalkerRun};
use crate::record::RecordCollector;
use crate::ringbuf::RingBuffer;
use crate::sandbox_maps::ProcessMaps;
use crate::systing_core::types::stack_event;
use crate::systing_core::SystingRecordEvent;
use crate::trace::{StackRecord, StackSampleRecord};
use crate::utid::{ThreadAwareRecorder, UtidGenerator};

use blazesym::helper::{read_elf_build_id, ElfResolver};
use blazesym::symbolize::source::{Elf, Kernel, Process, Source};
use blazesym::symbolize::{
    cache, evict, Input, ProcessMemberInfo, ProcessMemberType, Resolve, Sym, Symbolizer,
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

/// One user-space frame as delivered by the BPF walker.
///
/// Classic capture yields raw virtual addresses. Build-id capture
/// (`--collect-build-id`) yields `(build_id, file offset)` pairs for frames
/// the kernel could resolve to a mapped file carrying an ELF build-id note —
/// a process-independent identity that stays symbolizable after the process
/// exits — and falls back to the raw IP (`BPF_STACK_BUILD_ID_IP`) where it
/// could not.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub enum UserFrame {
    /// Raw virtual address; symbolized through the live process (or labeled
    /// `[exited]`/`[gvisor:*]`/... when that is impossible).
    Ip(u64),
    /// ELF build-id plus file offset; symbolized through the build-id store
    /// regardless of whether the process still exists.
    BuildId { id: [u8; 20], offset: u64 },
    /// Synthetic: the sample interrupted a hypervisor vCPU thread while it
    /// was executing guest code (`PF_VCPU`, the flag the kernel's cputime
    /// accounting bills as guest time). There is no host address to
    /// symbolize — the kernel returns empty callchains for guest-mode
    /// samples by design, on x86 and arm64 alike — so the frame renders as
    /// the `[guest]` label. It exists so that CPU time spent inside virtual
    /// machines is *counted*, attributed to the VMM thread that ran it,
    /// rather than silently dropped as an unwind failure.
    Guest,
}

/// Rendered name of [`UserFrame::Guest`]: the standard `symbol (module)`
/// frame shape with the label in the module slot, like `[exited]` and the
/// `[gvisor:*]` family, so existing frame parsers classify it without
/// changes. No `<0x…>` suffix — there is no address, and inventing one
/// would be worse than its honest absence.
const GUEST_FRAME_NAME: &str = "unknown ([guest])";

// Stack structure representing kernel, user, and Python stacks.
//
// Direction invariant: every segment is stored ROOT-TO-LEAF (outermost
// caller first, innermost/executing frame last). The BPF unwinder and
// pystacks both deliver frames leaf-first; the constructors reverse each
// segment so `frame_ids`, folded output, and exports all read one
// coherent direction.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Stack {
    pub(crate) kernel_stack: Vec<u64>,
    pub(crate) user_stack: Vec<UserFrame>,
    pub(crate) py_stack: Vec<PyAddr>,
}

/// Maximum valid user-space address (48-bit virtual address space boundary).
/// Addresses above this threshold in the user stack are garbage from bad frame pointer
/// unwinding (typically instruction bytes or other non-address data that leaked into
/// the stack frame chain).
const MAX_USER_ADDR: u64 = 0x0000_FFFF_FFFF_FFFF;

/// Filters out zero and garbage addresses from user stack and reverses to get root-to-leaf order.
fn filter_and_reverse_user_stack(addrs: &[u64]) -> Vec<UserFrame> {
    addrs
        .iter()
        .copied()
        .filter(|&addr| addr != 0 && addr <= MAX_USER_ADDR)
        .map(UserFrame::Ip)
        .rev()
        .collect()
}

/// Same for pre-parsed frames (build-id mode): the garbage-address filter
/// applies to raw-IP fallback frames only — build-id frames carry a file
/// offset, for which the virtual-address bound is meaningless.
fn filter_and_reverse_user_frames(frames: Vec<UserFrame>) -> Vec<UserFrame> {
    frames
        .into_iter()
        .filter(|f| match f {
            UserFrame::Ip(addr) => *addr != 0 && *addr <= MAX_USER_ADDR,
            UserFrame::BuildId { .. } | UserFrame::Guest => true,
        })
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

/// Reverses the python stack to get root-to-leaf order. pystacks fills its
/// buffer leaf-first (the executing frame is read first, then the walk
/// follows the frame chain outward), mirroring the BPF unwinder direction.
fn reverse_py_stack(frames: &[PyAddr]) -> Vec<PyAddr> {
    frames.iter().rev().cloned().collect()
}

impl Stack {
    pub fn new(kernel_stack: &[u64], user_stack: &[u64], py_stack: &[PyAddr]) -> Self {
        Self {
            kernel_stack: filter_and_reverse_kernel_stack(kernel_stack),
            user_stack: filter_and_reverse_user_stack(user_stack),
            py_stack: reverse_py_stack(py_stack),
        }
    }

    /// Like [`Stack::new`] but with pre-parsed user frames (build-id mode).
    pub fn from_frames(
        kernel_stack: &[u64],
        user_frames: Vec<UserFrame>,
        py_stack: &[PyAddr],
    ) -> Self {
        Self {
            kernel_stack: filter_and_reverse_kernel_stack(kernel_stack),
            user_stack: filter_and_reverse_user_frames(user_frames),
            py_stack: reverse_py_stack(py_stack),
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
    /// then klen u64 kernel addresses, ulen self-describing user frames
    /// (tag u8: 0 = raw IP, u64 follows; 1 = build-id, 20 id bytes + u64
    /// offset follow), and pylen (u64 symbol_id, i32 inst_idx) entries.
    /// The file never outlives the run, so there is no cross-version
    /// compatibility to keep.
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
        for frame in &stack.user_stack {
            match frame {
                UserFrame::Ip(addr) => {
                    self.buf.push(0);
                    self.buf.extend_from_slice(&addr.to_le_bytes());
                }
                UserFrame::BuildId { id, offset } => {
                    self.buf.push(1);
                    self.buf.extend_from_slice(id);
                    self.buf.extend_from_slice(&offset.to_le_bytes());
                }
                UserFrame::Guest => {
                    // Tag only: a guest frame carries no payload.
                    self.buf.push(2);
                }
            }
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

    /// Drain all records (durable file contents then in-memory fallback) into
    /// `f`, consuming the spill. Convenience wrapper around `take_reader` +
    /// `read_spill_record` so callers replay the full record set without
    /// repeating that loop.
    fn drain(&mut self, mut f: impl FnMut(Stack, i32, i64) -> Result<()>) -> Result<()> {
        if let Some((mut reader, durable)) = self.take_reader() {
            for _ in 0..durable {
                match read_spill_record(&mut reader) {
                    Ok(Some((stack, tgid, id))) => f(stack, tgid, id)?,
                    Ok(None) => break,
                    Err(e) => {
                        eprintln!("Warning: stopping stack spill replay early: {e:#}");
                        break;
                    }
                }
            }
        }
        for (stack, tgid, id) in std::mem::take(&mut self.fallback) {
            f(stack, tgid, id)?;
        }
        Ok(())
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

/// Approximate file-backed RSS of this process in bytes — the resident
/// *shared* pages from /proc/self/statm, which is exactly the term
/// [`current_anon_rss_bytes`] subtracts. During symbolization this is
/// dominated by blazesym's `FileCache`, which mmaps every ELF/`.so` it
/// touches and never evicts; that cache grows with the count of distinct
/// binaries symbolized and is file-backed, not heap, so the anon budget
/// above is blind to it. Watching this axis is what lets the evict valve
/// fire on the symbol-file cache rather than only on parse-time heap.
fn current_file_rss_bytes() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/statm").ok()?;
    let mut it = s.split_whitespace();
    let _size = it.next()?;
    let _resident = it.next()?;
    let shared: u64 = it.next()?.parse().ok()?;
    // SAFETY: sysconf is always safe to call; _SC_PAGESIZE cannot fail.
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
    Some(shared * page_size)
}

/// Number of second-tier spill files alive-process stacks are hashed into
/// during `finish()`. The recording-phase spill is a single file (one fd, one
/// sequential write stream on the hot path); at symbolization time stacks of
/// still-live processes are re-spilled into `tgid % RESPILL_BUCKETS` files
/// and replayed one bucket at a time, so peak memory is roughly
/// `total_live_stacks / RESPILL_BUCKETS` instead of all of them at once. 64
/// keeps the fd cost trivial while bringing the per-bucket fraction well
/// under the symbolizer budget on 192-core hosts.
const RESPILL_BUCKETS: usize = 64;

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

/// Budget for the file-backed symbol cache — blazesym's mmap'd ELF/`.so`
/// `FileCache`, measured by [`current_file_rss_bytes`]. Distinct from the
/// anon [`symbolizer_memory_budget`] above, and the reason this fix exists:
/// the file cache runs ~3 GiB and deterministic on the fleet (every capture
/// symbolizes the same common-binary set), dominates the tracer's ~3.9 GiB
/// peak, and is invisible to the anon watch — so it needs its own, tighter
/// bound. Kept well under the anon budget so the symbolization footprint
/// leaves headroom in the cgroup for the later DuckDB build phase, which is
/// where large captures OOM. cgroup/8 targets ~1 GiB on an 8Gi slice.
fn symbolizer_file_budget() -> u64 {
    const DEFAULT_BUDGET: u64 = 1 << 30; // 1 GiB
    crate::duckdb::detect_cgroup_memory_limit()
        .map(|limit| limit / 8)
        .unwrap_or(DEFAULT_BUDGET)
        .clamp(256 << 20, 4 << 30)
}

/// Plan which touched ELF files to evict, fattest-first, so that the estimated
/// file-backed RSS after eviction falls to `budget` or below. Returns the paths
/// in eviction order; empty when already at or under budget. The on-disk `size`
/// is an upper bound on the resident drop a single evict yields, so the plan is
/// conservative — if a pass under-sheds, the valve re-fires on the next check
/// interval. Kept pure and deterministic (size descending, ties broken by path)
/// so the eviction policy is unit-testable without a live symbolizer.
fn plan_evictions(touched_elf: &HashMap<PathBuf, u64>, file_rss: u64, budget: u64) -> Vec<PathBuf> {
    if file_rss <= budget {
        return Vec::new();
    }
    let mut by_size: Vec<(&PathBuf, u64)> = touched_elf.iter().map(|(p, &s)| (p, s)).collect();
    by_size.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    let mut est = file_rss;
    let mut plan = Vec::new();
    for (path, size) in by_size {
        if est <= budget {
            break;
        }
        plan.push(path.clone());
        est = est.saturating_sub(size);
    }
    plan
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
    // Frames are stored root-to-leaf; the leaf (innermost executing frame)
    // is the last entry.
    let leaf_name = frame_names.last().cloned().unwrap_or_default();
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

    let mut kernel_stack = Vec::with_capacity(klen);
    let mut buf8 = [0u8; 8];
    for _ in 0..klen {
        reader
            .read_exact(&mut buf8)
            .context("reading stack spill kernel frame")?;
        kernel_stack.push(u64::from_le_bytes(buf8));
    }

    // User frames are self-describing (see `push`): tag 0 = raw IP (u64),
    // tag 1 = build-id (20 id bytes + u64 file offset), tag 2 = guest
    // (no payload).
    let mut user_stack = Vec::with_capacity(ulen);
    for _ in 0..ulen {
        let mut tag = [0u8; 1];
        reader
            .read_exact(&mut tag)
            .context("reading stack spill user frame tag")?;
        match tag[0] {
            0 => {
                reader
                    .read_exact(&mut buf8)
                    .context("reading stack spill user frame")?;
                user_stack.push(UserFrame::Ip(u64::from_le_bytes(buf8)));
            }
            1 => {
                let mut bid = [0u8; 20];
                reader
                    .read_exact(&mut bid)
                    .context("reading stack spill build-id")?;
                reader
                    .read_exact(&mut buf8)
                    .context("reading stack spill build-id offset")?;
                user_stack.push(UserFrame::BuildId {
                    id: bid,
                    offset: u64::from_le_bytes(buf8),
                });
            }
            2 => user_stack.push(UserFrame::Guest),
            t => anyhow::bail!("corrupt stack spill record: unknown user frame tag {t}"),
        }
    }

    // Python frames serialize as 12 bytes: u64 symbol_id + i32 inst_idx.
    const PY_FRAME_BYTES: usize = 12;
    let mut py_bytes = vec![0u8; pylen * PY_FRAME_BYTES];
    reader
        .read_exact(&mut py_bytes)
        .context("reading stack spill record body")?;
    let py_stack = py_bytes
        .chunks_exact(PY_FRAME_BYTES)
        .map(|c| PyAddr {
            addr: crate::pystacks::types::StackWalkerFrame {
                symbol_id: u64::from_le_bytes(c[0..8].try_into().unwrap()),
                inst_idx: i32::from_le_bytes(c[8..12].try_into().unwrap()),
                pad_: 0,
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

/// Everything known about one live process while symbolizing its user
/// frames: the blazesym process source, the host-side maps analysis, and —
/// for sandbox stubs — the guest process they mirror.
struct UserSymbolizeCtx<'a> {
    proc_src: &'a Source<'a>,
    maps: Option<&'a ProcessMaps>,
    guest: Option<&'a GuestProcess>,
}

/// Key of a kernel-tagged build-id frame: the fixed 20-byte note field plus
/// the file offset the kernel computed for the ip.
type BuildIdFrameKey = ([u8; 20], u64);

/// A live process's symbolization input: the context plus the two
/// per-process caches (raw user addresses; live-path build-id frames).
type LiveUserState<'a, 'b> = (
    &'a UserSymbolizeCtx<'b>,
    &'a mut HashMap<u64, String>,
    &'a mut HashMap<BuildIdFrameKey, String>,
);

/// Kernel `enum bpf_stack_build_id_status` values, as delivered in
/// `systing_stack_build_id.status` (EMPTY = 0 produces no frame at all).
const BUILD_ID_STATUS_VALID: i32 = 1;
const BUILD_ID_STATUS_IP: i32 = 2;

/// `stack_event.user_stack_format` values (mirrors the BPF-side
/// USER_STACK_FORMAT_* defines): which entry format the event's user_stack
/// region carries.
const USER_STACK_FORMAT_BUILD_ID: u32 = 1;

/// `stack_event.sample_flags` bit (mirrors the BPF-side SAMPLE_FLAG_IN_GUEST
/// define): the sampled task was a vCPU thread executing its guest
/// (`PF_VCPU`). Such events carry no frames — the kernel does not walk
/// callchains for guest-mode samples — and are accounted as one
/// [`UserFrame::Guest`] frame instead of being dropped.
const SAMPLE_FLAG_IN_GUEST: u32 = 1;

/// Index one live process's executable mappings into the build-id store
/// (the opportunistic fill source). Returns how many mappings were read.
///
/// Each mapping is read through its `map_files` link first — namespace-
/// immune, so containerized processes' binaries index correctly under the
/// privileges systing runs with in production — falling back to the maps
/// path, which works unprivileged for same-namespace processes. A process
/// racing to exit mid-read is just a miss.
fn fill_store_from_maps(store: &mut BuildIdStore, maps: &ProcessMaps) -> usize {
    let mut mappings = 0usize;
    for (link, display) in maps.exec_file_links() {
        let (bid, resolve_path) = match read_elf_build_id(&link) {
            Ok(Some(b)) => (b, link),
            _ => match read_elf_build_id(&display) {
                Ok(Some(b)) => (b, display.clone()),
                _ => continue,
            },
        };
        let id = note_to_id(&bid);
        let module = display
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("[buildid]")
            .to_string();
        store.fill_live(id, resolve_path, module);
        mappings += 1;
    }
    mappings
}

/// A build-id note payload as the kernel's fixed 20-byte stack-frame field:
/// shorter notes zero-extend, longer ones truncate (the kernel does both).
fn note_to_id(bytes: &[u8]) -> [u8; 20] {
    let mut id = [0u8; 20];
    let n = bytes.len().min(20);
    id[..n].copy_from_slice(&bytes[..n]);
    id
}

/// Locate a (build-id, file offset) frame in a live process's own address
/// space and return the virtual address to symbolize, or `None` to send the
/// frame down the store path unchanged. Two cases:
///
/// 1. Ordinary file-backed text: the offset is a real ELF file offset; find
///    the file-backed executable mapping that both contains it and carries
///    the frame's build-id note, and return where that offset is mapped.
///
/// 2. gVisor guest islands: under systrap the kernel reports a guest frame's
///    offset relative to the `runsc-memory` pool memfd, so no file mapping
///    matches. Reconstruct the island address from the pool mapping and keep
///    it only if it bridges to a real file — [`ProcessMaps::bridge_for`]'s
///    neighbour-congruence is the disambiguator, and the bridged neighbour's
///    own ELF note must match the frame's build-id (the pool memfd's note is
///    unreliable, but the neighbour file's is authoritative).
///
/// 3. Fully pool-backed guest text: on a memory-backed overlay (the container
///    writable layer, or tmpfs) the whole image lives in the pool memfd with
///    no file-backed neighbour, so case 2 finds nothing to bridge. Here the
///    image's own ELF note IS authoritative — the bytes are the real binary,
///    not a syscall-patch copy — so read it from the process's live memory at
///    the image base and, on a build-id match, return the reconstructed
///    address for the caller to symbolize through the live cascade. A
///    coincidental pool-offset match in an unrelated image fails the note
///    match and falls through to the store path unchanged.
///
/// Every non-match falls through to the store path, so this only ever adds a
/// live-process resolution ahead of the unchanged fallback.
fn read_build_id_from_process_mem(tgid: i32, image_base: u64) -> Option<[u8; 20]> {
    use std::os::unix::fs::FileExt;
    let mem = std::fs::File::open(format!("/proc/{tgid}/mem")).ok()?;
    parse_build_id_from_elf(image_base, |addr, len| {
        let mut buf = vec![0u8; len];
        mem.read_exact_at(&mut buf, addr).ok()?;
        Some(buf)
    })
}

/// The ELF-parsing core of [`read_build_id_from_process_mem`], split from the
/// `/proc/<tgid>/mem` read so it is testable with synthetic bytes. `read`
/// returns `len` bytes at an absolute virtual address, or `None`.
///
/// Parses the guest's own Elf64 image at `image_base` with the `object` crate
/// and returns the first `NT_GNU_BUILD_ID` note descriptor, or `None` on any
/// malformed or short input. The image is read through object's bounds-checked
/// parsers segment by segment rather than loaded whole: a running image keeps
/// no section-header table in memory (sections are not `SHF_ALLOC`), so the
/// high-level `Object::build_id` — which needs it — cannot be used here; the
/// program headers, which do live in memory, reach the note on their own. Each
/// read is size-capped because the bytes are another process's (semi-trusted)
/// memory.
fn parse_build_id_from_elf(
    image_base: u64,
    read: impl Fn(u64, usize) -> Option<Vec<u8>>,
) -> Option<[u8; 20]> {
    use object::elf::{FileHeader64, NT_GNU_BUILD_ID, PT_NOTE};
    use object::read::elf::{FileHeader, NoteIterator, ProgramHeader};
    use object::Endianness;
    use std::mem::size_of;

    type Ehdr = FileHeader64<Endianness>;

    // A malformed header must not drive a huge read of another process's
    // memory: real images carry a few program headers and a tiny build-id note.
    const MAX_PHNUM: u64 = 256;
    const MAX_NOTE_BYTES: u64 = 64 * 1024;

    // Header first — object validates the magic, class, version and endianness
    // and declines on anything malformed; `parse` reads only the fixed header.
    let ehdr_bytes = read(image_base, size_of::<Ehdr>())?;
    let header = Ehdr::parse(&*ehdr_bytes).ok()?;
    let endian = header.endian().ok()?;

    // Read the header plus the program-header table (which sits just past the
    // header, at e_phoff) in one span so object can index the table.
    let phnum = header.e_phnum(endian) as u64;
    if phnum > MAX_PHNUM {
        return None;
    }
    let table_end = header
        .e_phoff(endian)
        .checked_add(phnum.checked_mul(header.e_phentsize(endian) as u64)?)?;
    let front = read(image_base, usize::try_from(table_end).ok()?)?;

    for ph in header.program_headers(endian, &*front).ok()? {
        if ph.p_type(endian) != PT_NOTE {
            continue;
        }
        // A PT_NOTE segment maps at image_base + p_offset; read exactly its
        // bytes and let object walk the notes (it handles the note alignment
        // and every bound).
        let filesz = ph.p_filesz(endian);
        if filesz == 0 || filesz > MAX_NOTE_BYTES {
            continue;
        }
        let seg = read(
            image_base.checked_add(ph.p_offset(endian))?,
            usize::try_from(filesz).ok()?,
        )?;
        let mut notes = NoteIterator::<Ehdr>::new(endian, ph.p_align(endian), &seg).ok()?;
        while let Some(note) = notes.next().ok()? {
            if note.n_type(endian) == NT_GNU_BUILD_ID && note.name() == b"GNU" {
                return Some(note_to_id(note.desc()));
            }
        }
    }
    None
}

fn reconstruct_build_id_addr(
    maps: Option<&ProcessMaps>,
    id: &[u8; 20],
    file_offset: u64,
) -> Option<u64> {
    let maps = maps?;
    for (addr, link) in maps.virt_candidates_for_file_offset(file_offset) {
        if let Ok(Some(bid)) = read_elf_build_id(&link) {
            if note_to_id(&bid) == *id {
                return Some(addr);
            }
        }
    }
    for addr in maps.pool_candidates_for_offset(file_offset) {
        match maps.bridge_for(addr) {
            // Case 2: syscall-patch island — a file-backed neighbour carries
            // the authoritative note.
            Some(bridge) => {
                if let Ok(Some(bid)) = read_elf_build_id(&bridge.map_files_path) {
                    if note_to_id(&bid) == *id {
                        return Some(addr);
                    }
                }
            }
            // Case 3: fully pool-backed guest text — no file neighbour, so the
            // image's own note (read from live process memory at its base) is
            // authoritative.
            None => {
                if let Some(image_base) = maps.pool_image_base(addr) {
                    if read_build_id_from_process_mem(maps.tgid(), image_base) == Some(*id) {
                        return Some(addr);
                    }
                }
            }
        }
    }
    None
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
    /// Shared debuginfod client (when enabled): backs both the process
    /// dispatcher above and the build-id store's by-id fetches.
    debuginfod_client: Option<Arc<CachingClient>>,
    /// When set, BPF delivered user frames as (build-id, file offset) pairs
    /// (`--collect-build-id`): handle_event parses the `user_stack_bid`
    /// tail, and symbolization resolves those frames through the
    /// build-id store instead of the process.
    build_id_mode: bool,
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
    /// Directory for spill tempfiles. Retained so `finish()` can re-spill
    /// alive-process stacks into per-bucket files (see [`RESPILL_BUCKETS`]).
    spill_dir: Option<PathBuf>,
    /// Shared utid generator for consistent thread IDs across all recorders.
    utid_generator: Arc<UtidGenerator>,
    /// When set (default), frames that fail symbolization are rendered with
    /// the most specific context known — `unknown ([gvisor:runtime]) <addr>`,
    /// `unknown ([jit:node]) <addr>`, `unknown (<module>) <addr>`,
    /// `unknown ([exited]) <addr>` — instead of bare hex. See
    /// [`crate::sandbox_maps`].
    frame_labels: bool,
    /// When set (default), gVisor sandboxes on the host are queried over
    /// their control sockets so guest processes' own maps refine the
    /// classification of otherwise-unresolvable frames. See
    /// [`crate::gvisor_guest`].
    gvisor_guest_maps: bool,
    /// When set (default), process members that have no ELF symbol table
    /// but carry a `.gopclntab` — stripped Go binaries — are symbolized
    /// from the Go runtime's function table instead of rendering as hex.
    /// See [`crate::gopclntab_resolver`].
    gopclntab: bool,
    /// When set, resolve user-space symbols from ELF symbol tables only:
    /// no DWARF debug info, source line info, inlined-function resolution,
    /// or debuginfod fetches. Function names are unchanged for binaries
    /// that carry a symbol table (and `.gopclntab` handling for stripped
    /// Go binaries is unaffected); frames lose their "[file:line]" suffix
    /// and inlined frames collapse into their caller. This bounds
    /// symbolization memory: blazesym retains parsed debug info per binary
    /// with no eviction, and one freshly-built `-g` binary can hold
    /// hundreds of MiB resident, so a host running many of them (a CI node
    /// mid-build) accumulates past any fixed budget — while the
    /// symbol-table path costs a few MiB per binary for identical names.
    names_only: bool,
    /// When set, symbol names longer than
    /// [`crate::symbol_shorten::ELIDE_GATE`] bytes have their generic /
    /// template argument groups collapsed (`a::b<X<Y>, Z>::c(P)` renders
    /// as `a::b<...>::c(...)`). Deeply monomorphized Rust and C++ names
    /// legitimately demangle to multi-KiB strings; with stacks
    /// materialized as per-frame strings, one hot kilobyte-scale name
    /// repeated across millions of frames dominates recorder memory and
    /// trace size. Shorter names are unchanged; longer names keep their
    /// path head and function segment. See [`crate::symbol_shorten`].
    elide_generics: bool,
    /// Samples accounted as guest execution: a vCPU thread interrupted
    /// while its guest was running (see [`UserFrame::Guest`]). Reported at
    /// trace end — this is CPU time that used to be invisible.
    guest_samples: u64,
    /// Stack events that arrived with no kernel, user, or Python frames and
    /// no guest mark, and were therefore dropped. Both unwinds failing for
    /// an ordinary task is rare; counting it keeps the recorder from ever
    /// discarding samples without a trace.
    dropped_frameless: u64,
}

impl ThreadAwareRecorder for StackRecorder {
    fn utid_generator(&self) -> &UtidGenerator {
        &self.utid_generator
    }
}

impl StackRecorder {
    pub fn new(enable_debuginfod: bool, utid_generator: Arc<UtidGenerator>) -> Self {
        let debuginfod_client = if enable_debuginfod {
            create_debuginfod_client()
        } else {
            None
        };
        let process_dispatcher = debuginfod_client.clone().map(create_debuginfod_dispatcher);

        Self {
            ringbuf: RingBuffer::default(),
            psr: Arc::new(StackWalkerRun::default()),
            process_dispatcher,
            debuginfod_client,
            build_id_mode: false,
            streaming_collector: None,
            interner: StackInterner::new(1)
                .with_id_limit(crate::memory_recorder::MEMORY_STACK_ID_OFFSET),
            external_interners: Vec::new(),
            spill_dir: None,
            utid_generator,
            frame_labels: true,
            gvisor_guest_maps: true,
            gopclntab: true,
            names_only: false,
            elide_generics: false,
            guest_samples: 0,
            dropped_frameless: 0,
        }
    }

    /// Enable build-id mode: user frames arrive as (build-id, file offset)
    /// pairs in the event's `user_stack_bid` tail and symbolize through the
    /// build-id store. Must match the BPF-side `collect_build_id` rodata
    /// setting.
    pub fn set_build_id_mode(&mut self, enabled: bool) {
        self.build_id_mode = enabled;
    }

    /// Disable contextual labels on unresolvable frames (revert to bare hex).
    pub fn set_frame_labels(&mut self, enabled: bool) {
        self.frame_labels = enabled;
    }

    /// Disable `.gopclntab`-based symbolization of stripped Go binaries.
    pub fn set_gopclntab(&mut self, enabled: bool) {
        self.gopclntab = enabled;
    }

    /// Restrict user-space symbolization to ELF symbol tables (see the
    /// `names_only` field docs for what is kept and what is lost).
    pub fn set_names_only(&mut self, enabled: bool) {
        self.names_only = enabled;
    }

    /// Collapse generic/template argument groups in over-long symbol
    /// names (see the `elide_generics` field docs).
    pub fn set_elide_generics(&mut self, enabled: bool) {
        self.elide_generics = enabled;
    }

    /// Disable querying gVisor control sockets for guest maps.
    pub fn set_gvisor_guest_maps(&mut self, enabled: bool) {
        self.gvisor_guest_maps = enabled;
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
        self.spill_dir = Some(dir.to_path_buf());
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
        // names_only drops debuginfod: its purpose is fetching debug info,
        // which names-only symbolization would then ignore. gopclntab stays —
        // it provides function names for stripped Go binaries at
        // symbol-table-like cost.
        let debuginfod = if self.names_only {
            None
        } else {
            self.process_dispatcher.clone()
        };
        let gopclntab = self.gopclntab;
        let code_info = !self.names_only;
        if debuginfod.is_none() && !gopclntab {
            return Symbolizer::builder()
                .enable_code_info(code_info)
                .enable_inlined_fns(code_info)
                .build();
        }
        // Dispatch order: debuginfod first (fetched debug info beats
        // everything), then the stripped-Go probe, then blazesym's default
        // ELF handling for members neither claims.
        let dispatcher =
            move |info: ProcessMemberInfo<'_>| -> Result<Option<Box<dyn Resolve>>, BlazeErr> {
                if let Some(debuginfod) = &debuginfod {
                    if let Some(resolver) = debuginfod(info.clone())? {
                        return Ok(Some(resolver));
                    }
                }
                if gopclntab {
                    if let ProcessMemberType::Path(path) = info.member_entry {
                        if let Some(resolver) = crate::gopclntab_resolver::try_gopclntab_resolver(
                            &path.maps_file,
                            &path.symbolic_path,
                        ) {
                            return Ok(Some(resolver));
                        }
                    }
                }
                Ok(None)
            };
        Symbolizer::builder()
            .enable_code_info(code_info)
            .enable_inlined_fns(code_info)
            .set_process_dispatcher(dispatcher)
            .build()
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

        // Sample-accounting notes. Guest samples are CPU time inside virtual
        // machines that carries no host frames (rendered as [guest]); the
        // frameless count is the residual class that still cannot be
        // attributed to anything — surfaced so it is never silently zero.
        if self.guest_samples > 0 {
            eprintln!(
                "Note: {} CPU samples landed in guest execution (vCPU threads) and were recorded as [guest]",
                self.guest_samples
            );
        }
        if self.dropped_frameless > 0 {
            eprintln!(
                "Note: dropped {} stack samples that carried no frames (kernel and user unwind both empty)",
                self.dropped_frameless
            );
        }

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

        // Phase-boundary RSS notes: together with the rebuild note below,
        // these attribute a memory blowup (or an OOM kill's last words) to
        // the exited-process pass vs. the live-process symbolization pass
        // without any tooling on the host.
        let phase_rss = |phase: &str| {
            if let Some(anon) = current_anon_rss_bytes() {
                eprintln!(
                    "Note: symbolization {phase}: anon RSS {} MiB ({total} unique stacks)",
                    anon >> 20
                );
            }
        };
        phase_rss("start");

        let mut symbolizer = self.create_symbolizer();

        // Create kernel source once - it's shared across all processes
        let kernel_src = Source::Kernel(Kernel::default());

        // Kernel address cache: blazesym caches metadata (KASLR, kallsyms
        // parsing) but not individual symbolization results, and the KASLR
        // offset is system-wide so the same kernel address resolves identically
        // for all processes.
        let mut kernel_cache: HashMap<u64, String> = HashMap::new();

        // Build-id store and store-path result cache (build-id mode; both
        // stay empty otherwise). Unlike the per-process user caches below,
        // these are global: a STORE-path resolution of (build-id, offset)
        // is process-independent, so one serves every process — dead or
        // alive — that ever mapped that binary. Live-path build-id results
        // (frames re-located in a live process's own maps and symbolized
        // through the full cascade) are process-scoped — bridge and guest
        // labels depend on the process — and cache per group below.
        let mut bid_store = BuildIdStore::new(self.debuginfod_client.clone());
        let mut bid_cache: HashMap<BuildIdFrameKey, String> = HashMap::new();

        // Index every live process's executable mappings by build-id note —
        // the store's opportunistic source. Host-wide rather than
        // sampled-tgids-only because the binaries a dead process mapped are
        // often held open by processes that were never sampled (the
        // `systing record -- short_cmd` shape: the traced command dies, its
        // binary lives on in unsampled processes). One bounded pass at
        // symbolization time; nothing here runs during capture.
        if self.build_id_mode {
            let t0 = std::time::Instant::now();
            let mut mappings = 0usize;
            if let Ok(entries) = std::fs::read_dir("/proc") {
                for entry in entries.flatten() {
                    let Some(tgid) = entry
                        .file_name()
                        .to_str()
                        .and_then(|s| s.parse::<i32>().ok())
                    else {
                        continue;
                    };
                    let Some(maps) = ProcessMaps::load(tgid) else {
                        continue;
                    };
                    mappings += fill_store_from_maps(&mut bid_store, &maps);
                }
            }
            eprintln!(
                "Note: build-id store: indexed {mappings} executable mappings \
                 from live processes in {:.0?}",
                t0.elapsed()
            );
        }

        // Pass 1: stream spilled stacks back from disk one record at a time
        // (then any kept in memory). Stacks of exited processes are emitted
        // immediately: their user addresses cannot be symbolized at all
        // (blazesym needs /proc/<pid>/maps), so they only need the kernel cache
        // and a hex rendering, and their address vectors are freed right away.
        // Stacks of live processes are re-spilled into RESPILL_BUCKETS
        // tgid-hashed second-tier files for pass 2, so they stay on disk
        // instead of accumulating in memory.
        //
        // Under heavy short-lived-process churn (CI) nearly everything is dead
        // by now and this pass keeps peak memory flat. On long-lived-process
        // hosts (training, inference) nearly everything is alive, and the
        // re-spill is what keeps the address vectors out of RAM until pass 2
        // touches one bucket at a time.
        let mut respill: Vec<StackSpill> = (0..RESPILL_BUCKETS)
            .map(|_| {
                let mut s = StackSpill::new();
                if let Some(dir) = &self.spill_dir {
                    s.set_dir(dir);
                }
                s
            })
            .collect();
        let mut tgid_alive: HashMap<i32, bool> = HashMap::new();

        // Each interner is dropped at the end of its loop iteration, releasing
        // its dedup table before the (memory-hungry) live-process pass below.
        // Build-id frames of exited processes resolve right here: the store
        // was populated from all live processes above, before any pass ran.
        for mut interner in interners {
            interner.spill.drain(|stack, tgid, stack_id| {
                let alive = *tgid_alive
                    .entry(tgid)
                    .or_insert_with(|| Path::new("/proc").join(tgid.to_string()).exists());
                if alive {
                    respill[(tgid as u32 as usize) % RESPILL_BUCKETS].push(stack, tgid, stack_id);
                    return Ok(());
                }
                let frame_names = self.symbolize_stack_frames(
                    &mut symbolizer,
                    &stack,
                    None,
                    &kernel_src,
                    &mut kernel_cache,
                    &mut bid_store,
                    &mut bid_cache,
                );
                pb.inc(1);
                emit_stack_record(collector, stack_id, frame_names)
            })?;
        }
        drop(tgid_alive);
        phase_rss("exited-process pass done");

        // Pass 2: symbolize live processes one re-spill bucket at a time, and
        // within each bucket one tgid at a time. blazesym accumulates parsed
        // debug info for every binary it touches with no eviction (with
        // code-info and inlined-fn resolution this can reach GiBs for
        // debug-heavy binaries), so anon RSS is checked against a budget after
        // each group and periodically within large groups, and the symbolizer
        // is rebuilt when it is exceeded. Grouping per tgid means each
        // process's binaries are normally parsed once; a rebuild costs
        // re-parsing for addresses not already in the string caches.
        //
        // `rebuild_floor` is the RSS right after the last rebuild: if a rebuild
        // doesn't actually free memory (the budget is exceeded by things a
        // rebuild can't touch, or one binary's debug info alone exceeds it),
        // further rebuilds would only thrash re-parsing, so the valve waits for
        // real growth above the floor before firing again.
        let memory_budget = symbolizer_memory_budget();
        let file_budget = symbolizer_file_budget();
        const VALVE_CHECK_INTERVAL: usize = 8192;
        const REBUILD_GROWTH_MARGIN: u64 = 256 << 20;
        let mut rebuild_floor: u64 = 0;
        // The valve watches BOTH memory axes. The file-backed symbol cache
        // (blazesym's mmap'd ELFs — see [`current_file_rss_bytes`]) is the
        // dominant, deterministic term of the tracer's footprint and is
        // invisible to `current_anon_rss_bytes`, so when it exceeds its
        // budget we surgically `evict(Elf)` the fattest touched binaries —
        // releasing their mmaps drops rss_file while keeping the rest of the
        // warm cache — and fall back to a full rebuild only for anon growth
        // (parse-time heap) a targeted evict can't reach. `touched_elf` (ELF
        // path → on-disk size, the fattest-first key) is a parameter so the
        // Pass-2 loop can keep populating it between valve calls.
        let mut maybe_evict_or_rebuild =
            |this: &Self, symbolizer: &mut Symbolizer, touched_elf: &mut HashMap<PathBuf, u64>| {
                if let Some(file_rss) = current_file_rss_bytes() {
                    let mut evicted = 0usize;
                    for path in plan_evictions(touched_elf, file_rss, file_budget) {
                        // A failed eviction only means blazesym holds that entry
                        // until the symbolizer is dropped; not worth failing
                        // symbolization over. `path` is the map_files link, which
                        // is blazesym's elf_cache key (its EntryPath maps_file /
                        // actual_path) for a live Process source, so this releases
                        // the mmap and its fd; the VM gate confirms the rss_file
                        // drop empirically.
                        if symbolizer
                            .evict(&evict::Evict::from(evict::Elf::new(path.clone())))
                            .is_ok()
                        {
                            touched_elf.remove(&path);
                            evicted += 1;
                        }
                    }
                    if evicted > 0 {
                        // SAFETY: malloc_trim is always safe to call on glibc.
                        unsafe {
                            libc::malloc_trim(0);
                        }
                        eprintln!(
                            "Note: evicted {evicted} symbol-file cache entries to \
                             stay under file budget ({} MiB)",
                            file_budget >> 20
                        );
                    }
                }

                let Some(anon) = current_anon_rss_bytes() else {
                    return;
                };
                if anon <= memory_budget
                    || anon <= rebuild_floor.saturating_add(REBUILD_GROWTH_MARGIN)
                {
                    return;
                }
                *symbolizer = this.create_symbolizer();
                // A full rebuild drops the whole cache, so the touched-ELF set
                // no longer reflects what blazesym holds.
                touched_elf.clear();
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

        // ELF paths symbolized this pass → on-disk size, the fattest-first
        // key for `maybe_evict_or_rebuild`. Populated per-tgid from each
        // process's exec-file maps as Pass 2 walks the buckets.
        let mut touched_elf: HashMap<PathBuf, u64> = HashMap::new();

        // Guest-side sandbox snapshot, taken lazily on the first gVisor
        // process encountered and shared by every group after it.
        let mut sandbox_index: Option<SandboxIndex> = None;

        for mut bucket in respill {
            // Load this bucket's records and group by tgid so each process's
            // user addresses go through one Process source and one cache.
            // Only ~1/RESPILL_BUCKETS of the total live-stack volume is
            // resident at a time; it is freed when `bucket_groups` drops at
            // the end of the iteration.
            let mut bucket_groups: HashMap<i32, Vec<(Stack, i64)>> = HashMap::new();
            bucket.drain(|stack, tgid, stack_id| {
                bucket_groups
                    .entry(tgid)
                    .or_default()
                    .push((stack, stack_id));
                Ok(())
            })?;

            for (tgid, stacks) in bucket_groups {
                // Pre-cache process metadata for this tgid (best-effort
                // optimization; failure doesn't affect correctness).
                let _ = symbolizer.cache(&cache::Cache::from(cache::Process::new(
                    (tgid as u32).into(),
                )));
                let mut proc_source = Process::new(Pid::from(tgid as u32));
                // See the `names_only` field for the tradeoff.
                proc_source.debug_syms = !self.names_only;
                let proc_src = Source::Process(proc_source);
                // One maps analysis per process, powering island bridging and
                // frame labels for its whole group. `None` (process raced to
                // exit, unreadable maps) degrades to plain symbolization.
                let maps_info = ProcessMaps::load(tgid);
                // Record this process's mapped ELF files so the valve can evict
                // the fattest ones when the symbol-file cache exceeds its budget.
                // exec_file_links yields (map_files link, display path). We key
                // by the map_files link — `/proc/<pid>/map_files/<start>-<end>` —
                // because that is byte-for-byte blazesym's elf_cache key for a
                // live Process source (its `EntryPath::maps_file`, the cache
                // `actual_path`; the display/maps-text path is only the module
                // name and evicts nothing). The link is also namespace-immune:
                // `metadata` follows it to the backing file for the size even
                // when the process's maps-text path does not resolve from here.
                if let Some(maps) = maps_info.as_ref() {
                    for (link, _display) in maps.exec_file_links() {
                        touched_elf.entry(link).or_insert_with_key(|p| {
                            std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)
                        });
                    }
                }
                // For sandbox processes, the guest process this stub mirrors
                // (if any). The sandbox snapshot is taken once, on first
                // contact with a gVisor process.
                let mut guest: Option<&GuestProcess> = None;
                if self.gvisor_guest_maps {
                    if let Some(m) = maps_info.as_ref().filter(|m| m.is_gvisor()) {
                        if sandbox_index.is_none() {
                            sandbox_index = Some(SandboxIndex::load());
                        }
                        guest = sandbox_index
                            .as_ref()
                            .and_then(|idx| idx.correlate(&m.exec_file_ranges()));
                    }
                }
                let ctx = UserSymbolizeCtx {
                    proc_src: &proc_src,
                    maps: maps_info.as_ref(),
                    guest,
                };
                // Per-process caches, freed with the group: raw user
                // addresses, and live-path build-id frames (whose rendering
                // is process-scoped — see the bid_cache comment above).
                // Both survive a mid-group rebuild, so already-resolved
                // frames are not re-done.
                let mut user_cache: HashMap<u64, String> = HashMap::new();
                let mut live_bid_cache: HashMap<BuildIdFrameKey, String> = HashMap::new();

                for (i, (stack, stack_id)) in stacks.into_iter().enumerate() {
                    if i > 0 && i % VALVE_CHECK_INTERVAL == 0 {
                        maybe_evict_or_rebuild(self, &mut symbolizer, &mut touched_elf);
                    }
                    let frame_names = self.symbolize_stack_frames(
                        &mut symbolizer,
                        &stack,
                        Some((&ctx, &mut user_cache, &mut live_bid_cache)),
                        &kernel_src,
                        &mut kernel_cache,
                        &mut bid_store,
                        &mut bid_cache,
                    );
                    pb.inc(1);
                    emit_stack_record(collector, stack_id, frame_names)?;
                }

                maybe_evict_or_rebuild(self, &mut symbolizer, &mut touched_elf);
            }
        }

        pb.finish_with_message("Stack symbolization complete");
        phase_rss("done");

        Ok(())
    }

    /// Symbolize one user-space address of a live process: regular process
    /// symbolization, then — for sandboxed processes — bridging of
    /// pool-memfd islands back to their original file (see
    /// [`crate::sandbox_maps`]), then the guest's own view of the address
    /// (see [`crate::gvisor_guest`]), then the most specific label
    /// available from the host side.
    fn symbolize_user_addr(
        &self,
        symbolizer: &mut Symbolizer,
        ctx: &UserSymbolizeCtx<'_>,
        addr: u64,
    ) -> String {
        if let Some(sym) = symbolizer
            .symbolize_single(ctx.proc_src, Input::AbsAddr(addr))
            .ok()
            .and_then(|s| s.into_sym())
        {
            return format_symbolized_frame(&sym, addr, "unknown", self.elide_generics);
        }

        if let Some(bridge) = ctx.maps.and_then(|m| m.bridge_for(addr)) {
            let mut bridge_elf = Elf::new(&bridge.map_files_path);
            bridge_elf.debug_syms = !self.names_only;
            let elf_src = Source::Elf(bridge_elf);
            if let Some(sym) = symbolizer
                .symbolize_single(&elf_src, Input::FileOffset(bridge.file_offset))
                .ok()
                .and_then(|s| s.into_sym())
            {
                // sym.module would render the map_files link; report the
                // original binary the island belongs to instead.
                return format_symbolized_frame_forced_module(
                    &sym,
                    addr,
                    &bridge.module_name,
                    self.elide_generics,
                );
            }
        }

        if !self.frame_labels {
            return format!("0x{addr:x}");
        }

        // The guest's own maps are authoritative where the host view is a
        // pool memfd: they name the file a pool-backed range belongs to and
        // bound the runtime-injected regions exactly.
        if let Some(guest) = ctx.guest {
            match guest.lookup(addr) {
                GuestAddr::File { module, .. } => {
                    return format!("unknown ({module}) <{addr:#x}>");
                }
                GuestAddr::Runtime => {
                    return format!("unknown ([gvisor:runtime]) <{addr:#x}>");
                }
                GuestAddr::Jit(rt) => {
                    return format!("unknown ([jit:{rt}]) <{addr:#x}>");
                }
                GuestAddr::Anon => {
                    return format!("unknown ([gvisor:guest]) <{addr:#x}>");
                }
                GuestAddr::Unmapped => {}
            }
        }

        crate::sandbox_maps::format_unresolved(addr, ctx.maps)
    }

    /// Symbolize one (build-id, file offset) frame through the build-id
    /// store, with the global result cache in front. Process-independent:
    /// works identically whether the producing process is alive or gone.
    /// Store misses render the deferred form — the full build-id and offset
    /// travel in the frame string, so anything downstream can resolve it
    /// once some store learns the id.
    fn symbolize_build_id_frame(
        &self,
        symbolizer: &mut Symbolizer,
        store: &mut BuildIdStore,
        cache: &mut HashMap<BuildIdFrameKey, String>,
        id: [u8; 20],
        offset: u64,
    ) -> String {
        if let Some(name) = cache.get(&(id, offset)) {
            return name.clone();
        }
        let name = self.resolve_build_id_frame(symbolizer, store, id, offset);
        cache.insert((id, offset), name.clone());
        name
    }

    fn resolve_build_id_frame(
        &self,
        symbolizer: &mut Symbolizer,
        store: &mut BuildIdStore,
        id: [u8; 20],
        offset: u64,
    ) -> String {
        if let Some(bin) = store.lookup(&id) {
            let mut elf = Elf::new(&bin.path);
            elf.debug_syms = !self.names_only;
            let elf_src = Source::Elf(elf);
            if let Some(sym) = symbolizer
                .symbolize_single(&elf_src, Input::FileOffset(offset))
                .ok()
                .and_then(|s| s.into_sym())
            {
                // The trailing <...> slot carries the file offset (the
                // frame's identity within the module), not a virtual
                // address — build-id frames don't have one.
                return format_symbolized_frame_forced_module(
                    &sym,
                    offset,
                    &bin.display_module,
                    self.elide_generics,
                );
            }
            // Store hit, symbol unresolved: the module is still known.
            return render_unresolved_build_id(
                self.frame_labels,
                Some(&bin.display_module),
                &id,
                offset,
            );
        }
        // Full store miss: only the build-id identity is available.
        render_unresolved_build_id(self.frame_labels, None, &id, offset)
    }

    /// Symbolize a single stack and return frame names.
    ///
    /// `user` carries the symbolization context and the two per-process
    /// caches (raw addresses; live build-id frames) for a live process;
    /// `None` means the process has exited, in which case raw user
    /// addresses cannot be symbolized (no /proc/<pid>/maps) and are
    /// rendered as `unknown ([exited]) <addr>` (or raw hex with labels
    /// disabled). Build-id frames of a LIVE process are first located in
    /// the process's own maps and symbolized through the full live cascade
    /// (memory view, island bridging, guest labels — everything the store
    /// path lacks); the store path serves them only as fallback, and is
    /// the sole path once the process is gone (its design case). Kernel
    /// addresses go through the shared `kernel_cache`.
    #[allow(clippy::too_many_arguments)]
    fn symbolize_stack_frames(
        &self,
        symbolizer: &mut Symbolizer,
        stack: &Stack,
        user: Option<LiveUserState<'_, '_>>,
        kernel_src: &Source<'_>,
        kernel_cache: &mut HashMap<u64, String>,
        bid_store: &mut BuildIdStore,
        bid_cache: &mut HashMap<BuildIdFrameKey, String>,
    ) -> Vec<String> {
        let mut frame_names = Vec::with_capacity(
            stack.user_stack.len() + stack.kernel_stack.len() + stack.py_stack.len(),
        );

        // Symbolize Python stack first (if present)
        let python_frames = self.psr.get_python_frame_names(&stack.py_stack);
        frame_names.extend(python_frames);

        // Symbolize user addresses (middle segment of the root-to-leaf array)
        match user {
            Some((ctx, user_cache, live_bid_cache)) => {
                for frame in &stack.user_stack {
                    let frame_name = match frame {
                        UserFrame::Ip(addr) => match user_cache.get(addr) {
                            Some(name) => name.clone(),
                            None => {
                                let name = self.symbolize_user_addr(symbolizer, ctx, *addr);
                                user_cache.insert(*addr, name.clone());
                                name
                            }
                        },
                        UserFrame::BuildId { id, offset } => {
                            match live_bid_cache.get(&(*id, *offset)) {
                                Some(name) => name.clone(),
                                None => {
                                    let name =
                                        match reconstruct_build_id_addr(ctx.maps, id, *offset) {
                                            Some(addr) => {
                                                self.symbolize_user_addr(symbolizer, ctx, addr)
                                            }
                                            None => self.symbolize_build_id_frame(
                                                symbolizer, bid_store, bid_cache, *id, *offset,
                                            ),
                                        };
                                    live_bid_cache.insert((*id, *offset), name.clone());
                                    name
                                }
                            }
                        }
                        // Not an address: guest execution is opaque to the
                        // host, live process or not.
                        UserFrame::Guest => GUEST_FRAME_NAME.to_string(),
                    };
                    frame_names.push(frame_name);
                }
            }
            None => {
                for frame in &stack.user_stack {
                    let frame_name = match frame {
                        UserFrame::Ip(addr) => {
                            if self.frame_labels {
                                format!("unknown ([exited]) <{addr:#x}>")
                            } else {
                                format!("0x{addr:x}")
                            }
                        }
                        UserFrame::BuildId { id, offset } => self.symbolize_build_id_frame(
                            symbolizer, bid_store, bid_cache, *id, *offset,
                        ),
                        UserFrame::Guest => GUEST_FRAME_NAME.to_string(),
                    };
                    frame_names.push(frame_name);
                }
            }
        }

        // Symbolize kernel addresses (leaf end).
        for &addr in &stack.kernel_stack {
            let frame_name = kernel_cache
                .entry(addr)
                .or_insert_with(|| {
                    symbolizer
                        .symbolize_single(kernel_src, Input::AbsAddr(addr))
                        .ok()
                        .and_then(|s| s.into_sym())
                        .map(|s| format_symbolized_frame(&s, addr, "[kernel]", self.elide_generics))
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

/// Render a build-id frame that did not resolve to a symbol name.
///
/// `module` is the store's `display_module` when the id resolved to a mapped
/// binary, or `None` on a full store miss. Opportunistic-fill entries carry a
/// real module name (e.g. `libc.so.6`); trusted-source entries carry only the
/// id, so their `display_module` is itself a `[buildid:...]` placeholder.
///
/// With frame labels on, a known real module is named (`<module>:unknown`
/// once tideline stamps the leaf), matching the live-process path's
/// module-level fallback rather than emitting a bare build-id hash the module
/// name would have covered. When only the id is known (store miss, or a
/// trusted id-only entry) the deferred `[buildid:...]` form carries the
/// identity forward. With labels off the machine form always carries the id,
/// since a bare offset would masquerade as a virtual address.
fn render_unresolved_build_id(
    frame_labels: bool,
    module: Option<&str>,
    id: &[u8; 20],
    offset: u64,
) -> String {
    if !frame_labels {
        return format!("buildid:{}+{offset:#x}", build_id_hex(id));
    }
    match module {
        Some(m) if !m.starts_with("[buildid:") => format!("unknown ({m}) <{offset:#x}>"),
        _ => format!("unknown ([buildid:{}]) <{offset:#x}>", build_id_hex(id)),
    }
}

/// Formats a symbolized frame as a string with module and location info.
/// Format: "function_name (module_name [file:line]) <0xaddr>"
///
/// With `elide_generics` set, over-long function names have their
/// generic/template argument groups collapsed first (see
/// [`crate::symbol_shorten`]).
fn format_symbolized_frame(
    sym: &Sym,
    addr: u64,
    default_module: &str,
    elide_generics: bool,
) -> String {
    let module_name = sym
        .module
        .as_ref()
        .and_then(|m| m.to_str())
        .and_then(|m| std::path::Path::new(m).file_name())
        .and_then(|f| f.to_str())
        .unwrap_or(default_module);
    format_symbolized_frame_forced_module(sym, addr, module_name, elide_generics)
}

/// Same as [`format_symbolized_frame`] but with a caller-supplied module
/// name. Used when symbolization went through an indirect source (e.g. a
/// `map_files` link for a bridged island) whose path would be meaningless to
/// report.
fn format_symbolized_frame_forced_module(
    sym: &Sym,
    addr: u64,
    module_name: &str,
    elide_generics: bool,
) -> String {
    let location_info = format_location_info(sym.code_info.as_deref());
    let name: &str = &sym.name;
    let name = if elide_generics {
        crate::symbol_shorten::shorten_name(name)
    } else {
        std::borrow::Cow::Borrowed(name)
    };
    format!("{name} ({module_name}{location_info}) <{addr:#x}>")
}

/// Create a shared debuginfod client if debuginfod is available in the
/// environment. Backs both the process dispatcher (path-keyed fetches for
/// live processes) and the build-id store (id-keyed fetches, which need no
/// process at all).
fn create_debuginfod_client() -> Option<Arc<CachingClient>> {
    match Client::from_env() {
        Ok(Some(client)) => match CachingClient::from_env(client) {
            Ok(caching_client) => {
                println!("Debuginfod enabled: using debuginfod for symbol resolution");
                Some(Arc::new(caching_client))
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

/// Wrap the shared debuginfod client as a blazesym process dispatcher.
///
/// The closure takes ownership of one Arc clone; each dispatch clones the
/// Arc again (the client itself is shared, not copied). The closure and its
/// captured Arc live as long as the StackRecorder that owns the
/// process_dispatcher field.
fn create_debuginfod_dispatcher(client: Arc<CachingClient>) -> Arc<ProcessDispatcher> {
    Arc::new(Box::new(
        move |info: ProcessMemberInfo<'_>| -> Result<Option<Box<dyn Resolve>>, BlazeErr> {
            dispatch_process_with_client(info, client.clone())
        },
    ) as ProcessDispatcher)
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

            println!("Fetching debug info for build ID: {build_id}");
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

        // A vCPU thread sampled while its guest was executing arrives with
        // no frames at all (the kernel does not walk callchains for
        // guest-mode samples). That is CPU time all the same — a busy
        // virtual machine — so it is accounted below as one synthetic
        // [guest] frame under the VMM thread rather than dropped.
        let in_guest = event.sample_flags & SAMPLE_FLAG_IN_GUEST != 0;

        let has_frames =
            event.user_stack_length > 0 || event.kernel_stack_length > 0 || py_stack_len > 0;

        if has_frames || in_guest {
            let kstack_vec = Vec::from(&event.kernel_stack[..event.kernel_stack_length as usize]);
            // One user_stack region, two entry formats; the per-event
            // user_stack_format flag says which one this record carries
            // (self-describing — the parse never depends on recorder-side
            // configuration). user_stack_length counts entries of that
            // format; it is BPF-computed from the walker's return value,
            // but clamp anyway — a short (zero-extended) record must never
            // index past the region.
            let ulen = event.user_stack_length as usize;
            let mut user_frames: Vec<UserFrame> =
                if event.user_stack_format == USER_STACK_FORMAT_BUILD_ID {
                    event.user_stack[..ulen.min(event.user_stack.len())]
                        .iter()
                        .filter_map(|e| match e.status {
                            BUILD_ID_STATUS_VALID => Some(UserFrame::BuildId {
                                id: e.build_id,
                                offset: e.offset_or_ip,
                            }),
                            BUILD_ID_STATUS_IP => Some(UserFrame::Ip(e.offset_or_ip)),
                            // EMPTY (or anything unknown): no frame.
                            _ => None,
                        })
                        .collect()
                } else {
                    // Raw-IP format: the region holds packed u64 addresses from
                    // its start (the reservation covered only those bytes).
                    // SAFETY: stack_event is Plain (repr(C)); the region starts
                    // u64-aligned (it follows u64-aligned fields in a struct of
                    // alignment 8), MAX_STACK_DEPTH u64s (288B) fit inside the
                    // MAX_STACK_DEPTH 32-byte entries (1152B), and the record
                    // was zero-extended to the full struct size on copy.
                    let ips: &[u64] = unsafe {
                        std::slice::from_raw_parts(
                            event.user_stack.as_ptr() as *const u64,
                            event.user_stack.len(),
                        )
                    };
                    ips[..ulen.min(ips.len())]
                        .iter()
                        .map(|&addr| UserFrame::Ip(addr))
                        .collect()
                };
            // Guest-mode sample with (as expected) no host frames: the
            // synthetic frame makes it a countable stack. If a guest-marked
            // sample does carry frames — a sampling NMI landing in the
            // host's VM-entry/exit glue — the real frames are kept as-is.
            if in_guest && !has_frames {
                user_frames.push(UserFrame::Guest);
                self.guest_samples += 1;
            }
            let stack_key = (event.task.tgidpid >> 32) as i32;
            let py_stack = self.psr.get_pystack_from_event(&event);

            let stack = Stack::from_frames(&kstack_vec, user_frames, &py_stack);
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
        } else {
            // Neither unwind produced a frame and the task was not running a
            // guest: nothing to attribute the sample to. Counted, not silent.
            self.dropped_frameless += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Raw addresses as Ip frames (the classic-capture shape).
    fn ips(addrs: &[u64]) -> Vec<UserFrame> {
        addrs.iter().map(|&a| UserFrame::Ip(a)).collect()
    }

    fn bid_frame(seed: u8, offset: u64) -> UserFrame {
        UserFrame::BuildId {
            id: [seed; 20],
            offset,
        }
    }

    #[test]
    fn test_note_to_id_zero_extend_and_truncate() {
        assert_eq!(note_to_id(&[0xab; 20]), [0xab; 20]);
        let mut short = [0u8; 20];
        short[..4].copy_from_slice(&[1, 2, 3, 4]);
        assert_eq!(
            note_to_id(&[1, 2, 3, 4]),
            short,
            "short notes zero-extend like the kernel's fixed field"
        );
        assert_eq!(note_to_id(&[0x7; 24]), [0x7; 20], "long notes truncate");
    }

    #[test]
    fn test_reconstruct_build_id_addr_falls_back_to_store_path() {
        // Exited shape: no maps at all.
        assert_eq!(reconstruct_build_id_addr(None, &[1; 20], 0x1000), None);

        // A containing candidate whose map_files link is unreadable (the
        // fixture tgid doesn't exist): the note check cannot confirm it, so
        // reconstruction declines — the frame takes the store path rather
        // than guessing among offset-overlapping mappings.
        let pm = crate::sandbox_maps::ProcessMaps::parse(
            -42,
            "400000-500000 r-xp 00000000 08:01 7 /usr/bin/x",
            "x",
        );
        assert_eq!(pm.virt_candidates_for_file_offset(0x1000).len(), 1);
        assert_eq!(reconstruct_build_id_addr(Some(&pm), &[1; 20], 0x1000), None);

        // gVisor island shape: a pool-relative offset finds no file candidate
        // but reconstructs to an island address that bridges to its congruent
        // file neighbours. With the neighbour's note unreadable (fixture tgid
        // doesn't exist) the pool path declines too, sending the frame to the
        // store path rather than resolving against an unconfirmed binary.
        let guest = crate::sandbox_maps::ProcessMaps::parse(
            -42,
            "400000-4c2000 r-xs 00000000 00:13 426 /root/bin/guestbox\n\
             4c2000-4c3000 r-xs 3ff1f000 00:01 4   /memfd:runsc-memory (deleted)\n\
             4c3000-4cd000 r-xs 000c3000 00:13 426 /root/bin/guestbox",
            "guestbox",
        );
        assert!(guest.virt_candidates_for_file_offset(0x3ff1f500).is_empty());
        assert_eq!(guest.pool_candidates_for_offset(0x3ff1f500), vec![0x4c2500]);
        assert!(guest.bridge_for(0x4c2500).is_some());
        assert_eq!(
            reconstruct_build_id_addr(Some(&guest), &[1; 20], 0x3ff1f500),
            None
        );
    }

    /// Assemble a minimal Elf64 (header + one PT_NOTE segment carrying an
    /// NT_GNU_BUILD_ID note with `id`) so the note walker can be exercised
    /// without a real process. Uses the same layout constants as the parser.
    fn synth_elf_with_build_id(id: &[u8; 20]) -> Vec<u8> {
        use core::mem::{offset_of, size_of};
        use object::elf::{
            FileHeader64, Ident, NoteHeader64, ProgramHeader64, ELFCLASS64, ELFDATA2LSB, ELFMAG,
            EV_CURRENT, NT_GNU_BUILD_ID, PT_NOTE,
        };
        use object::Endianness;

        type Eh = FileHeader64<Endianness>;
        type Ph = ProgramHeader64<Endianness>;

        // One program header directly after the header, the note after it. All
        // offsets and widths come from object's own struct layout, so the
        // fixture and the parser agree on the format by construction.
        let phdr_at = size_of::<Eh>();
        let note_at = phdr_at + size_of::<Ph>();
        let name = b"GNU\0"; // n_namesz counts the trailing NUL
        let note_len = size_of::<NoteHeader64<Endianness>>() + name.len() + id.len();

        let mut b = vec![0u8; note_at];
        let ident = offset_of!(Eh, e_ident);
        b[ident..ident + ELFMAG.len()].copy_from_slice(&ELFMAG);
        b[ident + offset_of!(Ident, class)] = ELFCLASS64;
        b[ident + offset_of!(Ident, data)] = ELFDATA2LSB;
        b[ident + offset_of!(Ident, version)] = EV_CURRENT;
        b[offset_of!(Eh, e_phoff)..][..size_of::<u64>()]
            .copy_from_slice(&(phdr_at as u64).to_le_bytes());
        b[offset_of!(Eh, e_phentsize)..][..size_of::<u16>()]
            .copy_from_slice(&(size_of::<Ph>() as u16).to_le_bytes());
        b[offset_of!(Eh, e_phnum)..][..size_of::<u16>()].copy_from_slice(&1u16.to_le_bytes());

        b[phdr_at + offset_of!(Ph, p_type)..][..size_of::<u32>()]
            .copy_from_slice(&PT_NOTE.to_le_bytes());
        b[phdr_at + offset_of!(Ph, p_offset)..][..size_of::<u64>()]
            .copy_from_slice(&(note_at as u64).to_le_bytes());
        b[phdr_at + offset_of!(Ph, p_filesz)..][..size_of::<u64>()]
            .copy_from_slice(&(note_len as u64).to_le_bytes());
        b[phdr_at + offset_of!(Ph, p_align)..][..size_of::<u64>()]
            .copy_from_slice(&4u64.to_le_bytes());

        // Elf64_Nhdr { n_namesz, n_descsz, n_type }, then the name and the id.
        b.extend_from_slice(&(name.len() as u32).to_le_bytes());
        b.extend_from_slice(&(id.len() as u32).to_le_bytes());
        b.extend_from_slice(&NT_GNU_BUILD_ID.to_le_bytes());
        b.extend_from_slice(name);
        b.extend_from_slice(id);
        b
    }

    #[test]
    fn test_parse_build_id_from_elf() {
        let id = [0x5au8; 20];
        let blob = synth_elf_with_build_id(&id);
        let reader = |addr: u64, len: usize| {
            let a = addr as usize;
            blob.get(a..a + len).map(<[u8]>::to_vec)
        };
        // The note walker recovers the build-id from the synthetic image.
        assert_eq!(parse_build_id_from_elf(0, reader), Some(id));

        // Bad magic → None (never mistakes arbitrary memory for an ELF).
        let junk = [0u8; 200];
        let junk_reader = |addr: u64, len: usize| {
            let a = addr as usize;
            junk.get(a..a + len).map(<[u8]>::to_vec)
        };
        assert_eq!(parse_build_id_from_elf(0, junk_reader), None);

        // A short read anywhere on the path declines rather than panicking.
        let short = synth_elf_with_build_id(&id)[..100].to_vec();
        let short_reader = |addr: u64, len: usize| {
            let a = addr as usize;
            short.get(a..a + len).map(<[u8]>::to_vec)
        };
        assert_eq!(parse_build_id_from_elf(0, short_reader), None);
    }

    #[test]
    fn test_pool_image_base_and_full_pool_declines() {
        // Fully pool-backed guest text: a lone runsc-memory exec mapping with
        // no file-backed neighbour (the memory-overlay case). image_base is
        // start - pool_pgoff = 0x400000 - 0x6000.
        let pm = crate::sandbox_maps::ProcessMaps::parse(
            -42,
            "400000-413000 r-xs 00006000 00:01 2 /memfd:runsc-memory (deleted)",
            "guestbox",
        );
        assert_eq!(pm.pool_candidates_for_offset(0x6500), vec![0x400500]);
        // No file neighbour to bridge — this is the case-3 (full-pool) shape.
        assert!(pm.bridge_for(0x400500).is_none());
        assert_eq!(pm.pool_image_base(0x400500), Some(0x3fa000));
        // A real ELF file offset (non-pool) has no pool image base.
        assert_eq!(pm.pool_image_base(0x800000), None);
        // With the fixture tgid unreadable, the live-memory note auth cannot
        // confirm the image, so reconstruction declines to the store path.
        assert_eq!(reconstruct_build_id_addr(Some(&pm), &[1; 20], 0x6500), None);
    }

    #[test]
    fn test_render_unresolved_build_id() {
        let id = [0xabu8; 20];
        let full = build_id_hex(&id);

        // Store hit with a real module name (opportunistic-fill entry) and an
        // unresolved symbol: name the module so the leaf stamps as
        // `libc.so.6:unknown`, not a bare build-id hash.
        assert_eq!(
            render_unresolved_build_id(true, Some("libc.so.6"), &id, 0x1234),
            "unknown (libc.so.6) <0x1234>"
        );

        // Trusted id-only entry (its display_module is itself a placeholder):
        // the id is the only identity, so keep the deferred form.
        assert_eq!(
            render_unresolved_build_id(true, Some("[buildid:abababab]"), &id, 0x1234),
            format!("unknown ([buildid:{full}]) <0x1234>")
        );

        // Full store miss: same deferred form, driven by `None`.
        assert_eq!(
            render_unresolved_build_id(true, None, &id, 0x1234),
            format!("unknown ([buildid:{full}]) <0x1234>")
        );

        // Labels off: the machine form always carries the id, regardless of
        // whether the module name was known.
        assert_eq!(
            render_unresolved_build_id(false, Some("libc.so.6"), &id, 0x1234),
            format!("buildid:{full}+0x1234")
        );
        assert_eq!(
            render_unresolved_build_id(false, None, &id, 0x1234),
            format!("buildid:{full}+0x1234")
        );
    }

    #[test]
    fn test_filter_and_reverse_user_stack() {
        // Test zero filtering
        assert_eq!(
            filter_and_reverse_user_stack(&[0, 0x1000, 0]),
            ips(&[0x1000])
        );

        // Test reversal
        assert_eq!(
            filter_and_reverse_user_stack(&[0x1000, 0x2000]),
            ips(&[0x2000, 0x1000])
        );

        // Test MAX_USER_ADDR boundary - address at boundary should be kept
        assert_eq!(
            filter_and_reverse_user_stack(&[0x1000, MAX_USER_ADDR]),
            ips(&[MAX_USER_ADDR, 0x1000])
        );

        // Test garbage addresses above MAX_USER_ADDR are filtered
        assert_eq!(
            filter_and_reverse_user_stack(&[0x1000, MAX_USER_ADDR + 1]),
            ips(&[0x1000])
        );

        // Test typical garbage from bad frame pointer unwinding (instruction bytes)
        assert_eq!(
            filter_and_reverse_user_stack(&[0x7f0000001000, 0xc48348d88948ff31]),
            ips(&[0x7f0000001000])
        );

        // Empty stack
        assert_eq!(filter_and_reverse_user_stack(&[]), Vec::<UserFrame>::new());

        // All zeros
        assert_eq!(
            filter_and_reverse_user_stack(&[0, 0, 0]),
            Vec::<UserFrame>::new()
        );
    }

    #[test]
    fn test_filter_and_reverse_user_frames() {
        // The garbage filter applies to Ip fallback frames only; build-id
        // frames carry file offsets, for which the virtual-address bound is
        // meaningless (offset 0 is a legitimate file offset).
        let frames = vec![
            UserFrame::Ip(0),                 // filtered: zero addr
            bid_frame(1, 0),                  // kept: offset 0 is valid
            UserFrame::Ip(MAX_USER_ADDR + 1), // filtered: garbage addr
            bid_frame(2, u64::MAX),           // kept: any offset
            UserFrame::Guest,                 // kept: no address to judge
            UserFrame::Ip(0x1000),            // kept
        ];
        assert_eq!(
            filter_and_reverse_user_frames(frames),
            vec![
                UserFrame::Ip(0x1000),
                UserFrame::Guest,
                bid_frame(2, u64::MAX),
                bid_frame(1, 0)
            ]
        );
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
    fn test_stack_new_reverses_py_stack() {
        use crate::pystacks::types::StackWalkerFrame;
        // pystacks delivers frames leaf-first; Stack stores every segment
        // root-to-leaf, so construction must reverse the python segment too.
        let py = |symbol_id: u64| PyAddr {
            addr: StackWalkerFrame {
                symbol_id,
                inst_idx: 0,
                pad_: 0,
            },
        };
        let stack = Stack::new(&[], &[], &[py(1), py(2), py(3)]);
        assert_eq!(stack.py_stack, vec![py(3), py(2), py(1)]);

        // Empty python stack stays empty.
        assert!(Stack::new(&[], &[], &[]).py_stack.is_empty());
    }

    #[test]
    fn test_emit_stack_record_leaf_name_is_last_frame() {
        use crate::record::collector::InMemoryCollector;
        // Frames arrive root-to-leaf; leaf_name must be the innermost
        // (executing) frame — the LAST entry, not the first.
        let mut collector = InMemoryCollector::new();
        emit_stack_record(
            &mut collector,
            7,
            vec!["root".to_string(), "mid".to_string(), "leaf".to_string()],
        )
        .unwrap();
        let stacks = &collector.data().stacks;
        assert_eq!(stacks.len(), 1);
        assert_eq!(stacks[0].leaf_name, "leaf");
        assert_eq!(stacks[0].depth, 3);
    }

    #[test]
    fn test_stack_spill_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let mut spill = StackSpill::new();
        spill.set_dir(dir.path());
        assert!(spill.writer.is_some(), "spill file should be created");

        let py = vec![PyAddr {
            addr: crate::pystacks::types::StackWalkerFrame {
                symbol_id: 0xdeadbeef_cafef00d,
                inst_idx: -1,
                pad_: 0,
            },
        }];
        let stacks = [
            (
                Stack {
                    kernel_stack: vec![0xffffffff81000000, 0xffffffff82000000],
                    user_stack: ips(&[0x7f0000001000]),
                    py_stack: py.clone(),
                },
                42,
                1,
            ),
            (
                Stack {
                    kernel_stack: vec![],
                    user_stack: ips(&[0x1000, 0x2000, 0x3000]),
                    py_stack: vec![],
                },
                -1,
                1_000_000_007,
            ),
            (
                Stack {
                    kernel_stack: vec![],
                    user_stack: ips(&[]),
                    py_stack: py,
                },
                i32::MAX,
                i64::MAX,
            ),
            // Build-id mode stacks interleave BuildId and Ip-fallback
            // frames; both tags must round-trip.
            (
                Stack {
                    kernel_stack: vec![0xffffffff81000000],
                    user_stack: vec![
                        bid_frame(0xab, 0x1234),
                        UserFrame::Ip(0x7f0000002000),
                        bid_frame(0x01, u64::MAX),
                    ],
                    py_stack: vec![],
                },
                7,
                8,
            ),
            // The payload-free guest tag must round-trip and must not
            // desynchronize the frames that follow it in the record.
            (
                Stack {
                    kernel_stack: vec![0xffffffff81000000],
                    user_stack: vec![UserFrame::Guest],
                    py_stack: vec![],
                },
                9,
                10,
            ),
        ];
        for (stack, tgid, id) in &stacks {
            spill.push(stack.clone(), *tgid, *id);
        }
        assert_eq!(spill.total(), 5);
        assert!(spill.fallback.is_empty());

        let (mut reader, durable) = spill.take_reader().expect("reader");
        assert_eq!(durable, 5);
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
                user_stack: ips(&[i + 1]),
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
    fn test_stack_spill_drain() {
        let dir = tempfile::tempdir().unwrap();
        let mut spill = StackSpill::new();
        spill.set_dir(dir.path());

        // First few go to the file; then drop the writer and push to fallback.
        for i in 0..3 {
            spill.push(
                Stack {
                    kernel_stack: vec![i],
                    user_stack: ips(&[]),
                    py_stack: vec![],
                },
                i as i32,
                i as i64,
            );
        }
        spill.take_reader(); // flush + consume the writer
        spill.push(
            Stack {
                kernel_stack: vec![99],
                user_stack: ips(&[]),
                py_stack: vec![],
            },
            99,
            99,
        );
        assert_eq!(spill.fallback.len(), 1);

        // Re-seed a writer and re-push the file records so drain() sees both
        // file and fallback paths in one call.
        let mut spill = StackSpill::new();
        spill.set_dir(dir.path());
        for i in 0..3 {
            spill.push(
                Stack {
                    kernel_stack: vec![i],
                    user_stack: ips(&[]),
                    py_stack: vec![],
                },
                i as i32,
                i as i64,
            );
        }
        spill.fallback.push((
            Stack {
                kernel_stack: vec![99],
                user_stack: ips(&[]),
                py_stack: vec![],
            },
            99,
            99,
        ));

        let mut got = Vec::new();
        spill
            .drain(|stack, tgid, id| {
                got.push((stack.kernel_stack[0], tgid, id));
                Ok(())
            })
            .unwrap();
        assert_eq!(got, vec![(0, 0, 0), (1, 1, 1), (2, 2, 2), (99, 99, 99)]);
        assert!(spill.fallback.is_empty());
        assert!(spill.take_reader().is_none());
    }

    #[test]
    fn test_stack_spill_fallback_without_dir() {
        let mut spill = StackSpill::new();
        let stack = Stack {
            kernel_stack: vec![1],
            user_stack: ips(&[2]),
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
            user_stack: ips(&[0x1000]),
            py_stack: vec![],
        };
        let b = Stack {
            kernel_stack: vec![0xffffffff81000000],
            user_stack: ips(&[0x2000]),
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
            user_stack: ips(&[0x1000]),
            py_stack: vec![],
        };
        let b = a.clone();
        assert_eq!(stack_dedup_hash(&h, &a, 1), stack_dedup_hash(&h, &b, 1));
        // Different tgid must produce a different key
        assert_ne!(stack_dedup_hash(&h, &a, 1), stack_dedup_hash(&h, &a, 2));
        // Different contents must produce a different key
        let c = Stack {
            kernel_stack: vec![0xffffffff81000000],
            user_stack: ips(&[0x1001]),
            py_stack: vec![],
        };
        assert_ne!(stack_dedup_hash(&h, &a, 1), stack_dedup_hash(&h, &c, 1));
        // Moving an address between kernel and user stacks must change the key
        let d = Stack {
            kernel_stack: vec![],
            user_stack: ips(&[0xffffffff81000000, 0x1000]),
            py_stack: vec![],
        };
        assert_ne!(stack_dedup_hash(&h, &a, 1), stack_dedup_hash(&h, &d, 1));
        // An Ip frame and a BuildId frame whose offset equals the address
        // must not alias — the variant (and the id bytes) are part of the key.
        let e = Stack {
            kernel_stack: vec![0xffffffff81000000],
            user_stack: vec![bid_frame(0, 0x1000)],
            py_stack: vec![],
        };
        assert_ne!(stack_dedup_hash(&h, &a, 1), stack_dedup_hash(&h, &e, 1));
        // Same offset, different build-id: different key.
        let f = Stack {
            kernel_stack: vec![0xffffffff81000000],
            user_stack: vec![bid_frame(1, 0x1000)],
            py_stack: vec![],
        };
        assert_ne!(stack_dedup_hash(&h, &e, 1), stack_dedup_hash(&h, &f, 1));
    }

    /// The user_stack region is ONE tail-positioned array sized for the
    /// build-id entry format; raw-IP mode packs u64s from its start and the
    /// BPF side reserves only `offsetof(user_stack) + 36 * 8` bytes for it.
    /// The region must therefore be the LAST field (a shorter raw-IP
    /// reservation would truncate anything after it), and the raw-IP u64
    /// view requires the region to start u64-aligned. Also pins the mirror
    /// struct's layout to the kernel's bpf_stack_build_id (s32 + 20 bytes +
    /// u64 at offset 24 = 32 bytes).
    #[test]
    fn test_stack_event_user_stack_region_layout() {
        use crate::systing_core::types::systing_stack_build_id;
        use std::mem::{align_of, offset_of, size_of};
        assert_eq!(size_of::<systing_stack_build_id>(), 32);
        let region = offset_of!(stack_event, user_stack);
        let full = size_of::<stack_event>();
        assert_eq!(
            full - region,
            36 * size_of::<systing_stack_build_id>(),
            "user_stack must be the final field of stack_event \
             (raw-IP reservations stop partway into it)"
        );
        assert_eq!(
            region % align_of::<u64>(),
            0,
            "the region must start u64-aligned for the raw-IP packed view"
        );
        let ip_reserve = region + 36 * size_of::<u64>();
        eprintln!(
            "stack_event reservation: raw-ip={ip_reserve}B build-id={full}B \
             ratio={:.2}",
            full as f64 / ip_reserve as f64
        );
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

    /// An address inside this test binary's text, guaranteed to be backed by
    /// a symbolizable mapping of our own executable.
    #[inline(never)]
    fn marker_fn() -> u64 {
        42
    }

    /// A BPF-shaped stack event for `handle_event` tests: zeroed (as the
    /// ring delivers short records), then given a task identity, a RUNNING
    /// type, and the requested sample flags. No frames.
    fn frameless_event(tgid: i32, tid: i32, sample_flags: u32) -> stack_event {
        use crate::systing_core::types::{stack_event_type, task_info};
        stack_event {
            stack_event_type: stack_event_type::STACK_RUNNING,
            sample_flags,
            task: task_info {
                tgidpid: ((tgid as u32 as u64) << 32) | (tid as u32 as u64),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// The fix for invisible virtual-machine CPU time, end to end through
    /// the recorder: a frameless sample marked as guest execution must be
    /// COUNTED — interned as a one-frame stack and streamed as a sample —
    /// and must symbolize to the `[guest]` label whether or not the VMM
    /// process is still alive at trace end. Before this, such events were
    /// discarded in `handle_event` and a busy VM host profiled as idle.
    #[test]
    fn test_guest_sample_is_counted_and_labeled() {
        let dir = tempfile::tempdir().unwrap();
        let mut rec = StackRecorder::new(false, Arc::new(UtidGenerator::new()));
        rec.set_spill_dir(dir.path());
        rec.set_streaming_collector(Box::new(crate::record::InMemoryCollector::new()));

        // One guest sample from our own (live) process, one from a VMM that
        // has since exited (tgid far above pid_max).
        let self_tgid = std::process::id() as i32;
        let dead_tgid = i32::MAX - 1;
        rec.handle_event(frameless_event(self_tgid, self_tgid, SAMPLE_FLAG_IN_GUEST));
        rec.handle_event(frameless_event(dead_tgid, dead_tgid, SAMPLE_FLAG_IN_GUEST));

        assert_eq!(rec.guest_samples, 2);
        assert_eq!(rec.dropped_frameless, 0);
        // Same synthetic content, two tgids: two dedup keys.
        assert_eq!(rec.interner.total(), 2);

        let mut collector = crate::record::InMemoryCollector::new();
        rec.finish_inner(&mut collector).unwrap();
        let stacks = &collector.data().stacks;
        assert_eq!(stacks.len(), 2);
        for s in stacks {
            assert_eq!(s.frame_names, vec![GUEST_FRAME_NAME.to_string()]);
        }
    }

    /// The residual class — no frames and no guest mark (both unwinds
    /// failed for an ordinary task) — is still dropped, but now counted;
    /// and a guest mark never turns a sample that HAS frames into `[guest]`.
    #[test]
    fn test_frameless_unmarked_sample_is_dropped_and_counted() {
        let dir = tempfile::tempdir().unwrap();
        let mut rec = StackRecorder::new(false, Arc::new(UtidGenerator::new()));
        rec.set_spill_dir(dir.path());
        rec.set_streaming_collector(Box::new(crate::record::InMemoryCollector::new()));

        rec.handle_event(frameless_event(1234, 1234, 0));
        assert_eq!(rec.dropped_frameless, 1);
        assert_eq!(rec.guest_samples, 0);
        assert_eq!(rec.interner.total(), 0);

        // Guest-marked but WITH a kernel frame (an NMI in the host's
        // VM-entry/exit glue): kept as the real stack, no synthetic frame.
        let mut ev = frameless_event(1234, 1234, SAMPLE_FLAG_IN_GUEST);
        ev.kernel_stack[0] = 0xffffffff81000000;
        ev.kernel_stack_length = 1;
        rec.handle_event(ev);
        assert_eq!(rec.guest_samples, 0);
        assert_eq!(rec.dropped_frameless, 1);
        assert_eq!(rec.interner.total(), 1);
    }

    /// End-to-end run of the finish()-time symbolization over the real
    /// /proc: a stack from our own live process must not degrade to hex
    /// (either the symbol resolves or the module label kicks in), and a
    /// stack from an impossible tgid must take the dead-process path and be
    /// labeled [exited].
    #[test]
    fn test_finish_inner_symbolizes_live_and_labels_dead() {
        let dir = tempfile::tempdir().unwrap();
        let mut rec = StackRecorder::new(false, Arc::new(UtidGenerator::new()));
        rec.set_spill_dir(dir.path());

        let self_tgid = std::process::id() as i32;
        let live_addr = marker_fn as fn() -> u64 as usize as u64;
        let live_id = rec.interner.intern(
            Stack {
                kernel_stack: vec![],
                user_stack: ips(&[live_addr]),
                py_stack: vec![],
            },
            self_tgid,
        );

        // Far above pid_max: /proc/<tgid> cannot exist.
        let dead_tgid = i32::MAX - 1;
        let dead_addr = 0x1234_5678u64;
        let dead_id = rec.interner.intern(
            Stack {
                kernel_stack: vec![],
                user_stack: ips(&[dead_addr]),
                py_stack: vec![],
            },
            dead_tgid,
        );

        let mut collector = crate::record::InMemoryCollector::new();
        rec.finish_inner(&mut collector).unwrap();
        let stacks = &collector.data().stacks;

        let dead = stacks.iter().find(|s| s.id == dead_id).expect("dead stack");
        assert_eq!(
            dead.frame_names[0],
            format!("unknown ([exited]) <{dead_addr:#x}>")
        );

        let live = stacks.iter().find(|s| s.id == live_id).expect("live stack");
        let frame = &live.frame_names[0];
        assert!(
            !frame.starts_with("0x") && frame.contains('('),
            "live self-process frame should symbolize or at least carry a \
             module label, got: {frame}"
        );

        // With labels disabled the dead path reverts to historical bare hex.
        let mut rec_plain = StackRecorder::new(false, Arc::new(UtidGenerator::new()));
        rec_plain.set_frame_labels(false);
        rec_plain.set_spill_dir(dir.path());
        let plain_id = rec_plain.interner.intern(
            Stack {
                kernel_stack: vec![],
                user_stack: ips(&[dead_addr]),
                py_stack: vec![],
            },
            dead_tgid,
        );
        let mut plain_collector = crate::record::InMemoryCollector::new();
        rec_plain.finish_inner(&mut plain_collector).unwrap();
        let plain = plain_collector
            .data()
            .stacks
            .iter()
            .find(|s| s.id == plain_id)
            .expect("plain stack");
        assert_eq!(plain.frame_names[0], format!("0x{dead_addr:x}"));
    }

    /// Names-only mode must still resolve live-process symbols — the ELF
    /// symbol table carries the same function names DWARF does — while the
    /// dead-process path is unchanged.
    #[test]
    fn test_finish_inner_names_only_still_resolves_live() {
        let dir = tempfile::tempdir().unwrap();
        let mut rec = StackRecorder::new(false, Arc::new(UtidGenerator::new()));
        rec.set_names_only(true);
        rec.set_spill_dir(dir.path());

        let self_tgid = std::process::id() as i32;
        let live_addr = marker_fn as fn() -> u64 as usize as u64;
        let live_id = rec.interner.intern(
            Stack {
                kernel_stack: vec![],
                user_stack: ips(&[live_addr]),
                py_stack: vec![],
            },
            self_tgid,
        );
        let dead_tgid = i32::MAX - 1;
        let dead_addr = 0x1234_5678u64;
        let dead_id = rec.interner.intern(
            Stack {
                kernel_stack: vec![],
                user_stack: ips(&[dead_addr]),
                py_stack: vec![],
            },
            dead_tgid,
        );

        let mut collector = crate::record::InMemoryCollector::new();
        rec.finish_inner(&mut collector).unwrap();
        let stacks = &collector.data().stacks;

        let live = stacks.iter().find(|s| s.id == live_id).expect("live stack");
        let frame = &live.frame_names[0];
        assert!(
            !frame.starts_with("0x") && frame.contains('('),
            "names-only live frame should still resolve from the symbol \
             table (or carry a module label), got: {frame}"
        );
        // The test binary carries full DWARF, so a "[file:line]" suffix
        // here would mean names-only silently stopped disabling code info.
        assert!(
            !frame.contains(".rs:"),
            "names-only frame must not carry source location info, got: {frame}"
        );

        let dead = stacks.iter().find(|s| s.id == dead_id).expect("dead stack");
        assert_eq!(
            dead.frame_names[0],
            format!("unknown ([exited]) <{dead_addr:#x}>")
        );
    }

    /// Build-id mode, the deferred path: a dead-process frame whose
    /// build-id no source knows must render the full id and offset (that
    /// identity is what makes it resolvable offline), not `[exited]` hex.
    #[test]
    fn test_finish_inner_build_id_deferred_render() {
        let dir = tempfile::tempdir().unwrap();
        let mut rec = StackRecorder::new(false, Arc::new(UtidGenerator::new()));
        rec.set_build_id_mode(true);
        rec.set_spill_dir(dir.path());

        let dead_tgid = i32::MAX - 1;
        let id_bytes = [0x5au8; 20];
        let dead_id = rec.interner.intern(
            Stack {
                kernel_stack: vec![],
                user_stack: vec![UserFrame::BuildId {
                    id: id_bytes,
                    offset: 0x1234,
                }],
                py_stack: vec![],
            },
            dead_tgid,
        );

        let mut collector = crate::record::InMemoryCollector::new();
        rec.finish_inner(&mut collector).unwrap();
        let stacks = &collector.data().stacks;
        let dead = stacks.iter().find(|s| s.id == dead_id).expect("dead stack");
        assert_eq!(
            dead.frame_names[0],
            format!("unknown ([buildid:{}]) <0x1234>", "5a".repeat(20))
        );
    }

    /// Build-id mode, the resolution path this design exists for: a frame
    /// of a DEAD process symbolizes because a LIVE process (here: the test
    /// binary itself) still maps the binary, whose build-id the store
    /// indexes during the live pass. Skips (with a note) when the test
    /// binary carries no GNU build-id note — linker-dependent.
    #[test]
    fn test_finish_inner_build_id_dead_frame_resolves_via_live_fill() {
        let exe = std::fs::read_link("/proc/self/exe").unwrap();
        let Ok(Some(own_bid)) = read_elf_build_id(&exe) else {
            eprintln!("skipping: test binary has no GNU build-id note");
            return;
        };
        let mut id = [0u8; 20];
        let bytes: &[u8] = &own_bid;
        let n = bytes.len().min(20);
        id[..n].copy_from_slice(&bytes[..n]);

        // File offset of marker_fn inside our own executable, derived from
        // /proc/self/maps (addr - segment start + segment file offset).
        let addr = marker_fn as fn() -> u64 as usize as u64;
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
        let mut offset = None;
        for line in maps.lines() {
            let mut parts = line.split_whitespace();
            let (Some(range), Some(_perms), Some(off)) = (parts.next(), parts.next(), parts.next())
            else {
                continue;
            };
            let Some((lo, hi)) = range.split_once('-') else {
                continue;
            };
            let (Ok(lo), Ok(hi), Ok(off)) = (
                u64::from_str_radix(lo, 16),
                u64::from_str_radix(hi, 16),
                u64::from_str_radix(off, 16),
            ) else {
                continue;
            };
            if lo <= addr && addr < hi {
                offset = Some(addr - lo + off);
                break;
            }
        }
        let offset = offset.expect("marker_fn must be inside a mapping of our own exe");

        let dir = tempfile::tempdir().unwrap();
        let mut rec = StackRecorder::new(false, Arc::new(UtidGenerator::new()));
        rec.set_build_id_mode(true);
        rec.set_spill_dir(dir.path());

        // The live stack makes pass 2 visit our own tgid and index our
        // executable mappings by build-id; the dead stack then resolves
        // against that fill even though its tgid has no /proc entry.
        let self_tgid = std::process::id() as i32;
        let live_id = rec.interner.intern(
            Stack {
                kernel_stack: vec![],
                user_stack: vec![UserFrame::BuildId { id, offset }],
                py_stack: vec![],
            },
            self_tgid,
        );
        let dead_tgid = i32::MAX - 1;
        let dead_id = rec.interner.intern(
            Stack {
                kernel_stack: vec![],
                user_stack: vec![UserFrame::BuildId { id, offset }],
                py_stack: vec![],
            },
            dead_tgid,
        );

        let mut collector = crate::record::InMemoryCollector::new();
        rec.finish_inner(&mut collector).unwrap();
        let stacks = &collector.data().stacks;

        for (which, sid) in [("live", live_id), ("dead", dead_id)] {
            let s = stacks.iter().find(|s| s.id == sid).expect(which);
            let frame = &s.frame_names[0];
            assert!(
                frame.contains("marker_fn"),
                "{which} build-id frame should resolve to marker_fn via the \
                 live-fill store, got: {frame}"
            );
        }
    }

    /// Build a touched-ELF map (path -> on-disk size) for eviction-plan tests.
    fn touched(entries: &[(&str, u64)]) -> HashMap<PathBuf, u64> {
        entries
            .iter()
            .map(|&(p, s)| (PathBuf::from(p), s))
            .collect()
    }

    #[test]
    fn plan_evictions_empty_when_at_or_under_budget() {
        let t = touched(&[("/a", 100), ("/b", 200)]);
        assert!(
            plan_evictions(&t, 500, 1000).is_empty(),
            "under budget evicts nothing"
        );
        assert!(
            plan_evictions(&t, 1000, 1000).is_empty(),
            "exactly at budget evicts nothing"
        );
    }

    #[test]
    fn plan_evictions_fattest_first_stops_once_under() {
        let t = touched(&[("/small", 100), ("/big", 800), ("/mid", 400)]);
        // rss 1500, budget 1000: shed >=500. Fattest first, /big (800) alone
        // brings the estimate to 700 <= 1000, so the plan stops after it.
        assert_eq!(plan_evictions(&t, 1500, 1000), vec![PathBuf::from("/big")]);
    }

    #[test]
    fn plan_evictions_continues_until_enough_shed() {
        let t = touched(&[("/a", 100), ("/b", 120), ("/c", 90)]);
        // rss 1000, budget 700: shed >=300. Fattest first: b(120)->880,
        // a(100)->780, c(90)->690 <= 700.
        assert_eq!(
            plan_evictions(&t, 1000, 700),
            vec![
                PathBuf::from("/b"),
                PathBuf::from("/a"),
                PathBuf::from("/c")
            ]
        );
    }

    #[test]
    fn plan_evictions_deterministic_on_size_ties() {
        let t = touched(&[("/z", 500), ("/a", 500)]);
        // Equal sizes: tie broken by path ascending, so /a is chosen first and
        // alone (500 -> 700 <= 800) — deterministic regardless of map order.
        assert_eq!(plan_evictions(&t, 1200, 800), vec![PathBuf::from("/a")]);
    }

    #[test]
    fn symbolizer_file_budget_within_clamp() {
        let b = symbolizer_file_budget();
        assert!(
            ((256u64 << 20)..=(4u64 << 30)).contains(&b),
            "file budget {b} must stay within the [256 MiB, 4 GiB] clamp"
        );
    }

    #[test]
    fn current_file_rss_bytes_reads_own_statm() {
        // A running process always has resident shared pages (libc and friends),
        // so the file-backed axis reads as a positive value from our own statm.
        let v = current_file_rss_bytes().expect("statm is readable for self");
        assert!(v > 0, "file-backed RSS should be > 0 for a running process");
    }
}
