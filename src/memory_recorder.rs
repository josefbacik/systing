use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::pystacks::stack_walker::StackWalkerRun;
use crate::record::RecordCollector;
use crate::ringbuf::RingBuffer;
use crate::stack_recorder::{Stack, StackInterner};
use crate::systing_core::types::{
    memory_alloc_op, memory_event, memory_event_type, memory_rss_member, memory_thp_split_kind,
};
use crate::systing_core::{MemoryIommuHistEntry, SystingRecordEvent};
use crate::trace::{
    MemoryAllocRecord, MemoryFaultRecord, MemoryIommuRecord, MemoryMapRecord, MemoryRssRecord,
    MemoryThpRecord, MemoryVfioRecord, MemoryVmstatRecord,
};
use crate::utid::{ResolvedTask, ThreadAwareRecorder, UtidGenerator};

/// stack_id offset for stacks interned by the memory recorder. Each
/// recorder's interner owns a disjoint id range for the whole trace: the
/// stack recorder assigns ids below this value (and warns if it ever runs
/// out), the memory recorder from here up.
pub(crate) const MEMORY_STACK_ID_OFFSET: i64 = 1_000_000_000;

/// Synthetic `member` values for periodic mm_struct samples (distinguish from
/// the kernel rss_stat member indices 0..=3).
pub const MEMORY_MEMBER_HIWATER_RSS: i8 = -1;
pub const MEMORY_MEMBER_TOTAL_VM: i8 = -2;
/// Synthetic `member` values for the passive per-task thrash counters sampled
/// at the same periodic mm snapshot. maj_flt is a fault COUNT (not bytes);
/// thrashing_count is delayacct's thrash stall count and thrashing_delay its
/// cumulative stall time in NANOSECONDS — all cumulative per sampled thread.
/// The thrashing pair is emitted whenever delayacct was readable on the host,
/// zero values included — so zero-valued rows mean "delayacct on, no thrash",
/// and their complete absence while -3 rows are present means delayacct is
/// not enabled (kernel config or the `delayacct` boot / `kernel.task_delayacct`
/// sysctl setting).
pub const MEMORY_MEMBER_MAJ_FLT: i8 = -3;
pub const MEMORY_MEMBER_THRASHING_COUNT: i8 = -4;
pub const MEMORY_MEMBER_THRASHING_DELAY: i8 = -5;
/// Synthetic `member` for the process's transparent-huge-page-backed
/// anonymous memory in bytes (`AnonHugePages` from `/proc/<pid>/smaps_rollup`),
/// sampled once at the end of the capture for every process that produced a
/// memory event — "did this process get THP" beside its `rss_anon`. Absent
/// when the process had exited by then.
pub const MEMORY_MEMBER_ANON_HUGE: i8 = -6;

/// The `/proc/vmstat` counters sampled at capture start and end into
/// `memory_vmstat`: the THP allocation / split families, compaction and
/// direct reclaim — the host-wide "how often" behind the sampled legs.
pub const VMSTAT_COUNTERS: &[&str] = &[
    "thp_fault_alloc",
    "thp_fault_fallback",
    "thp_fault_fallback_charge",
    "thp_collapse_alloc",
    "thp_collapse_alloc_failed",
    "thp_split_page",
    "thp_split_page_failed",
    "thp_deferred_split_page",
    "thp_split_pmd",
    "thp_zero_page_alloc",
    "thp_swpout",
    "compact_stall",
    "compact_success",
    "compact_fail",
    "compact_migrate_scanned",
    "compact_free_scanned",
    "pgscan_direct",
    "pgsteal_direct",
    "pgmigrate_success",
    "pgmigrate_fail",
    "nr_anon_transparent_hugepages",
];

/// Mirror of `MEMORY_RSS_FLAG_EXTERNAL` in systing_system.bpf.c: the rss_stat
/// counter update came from outside the process's thread group (external
/// reclaim) rather than the process's own fault/map/unmap/exit path.
const MEMORY_RSS_FLAG_EXTERNAL: u32 = 1 << 0;

/// Mirror of `MEMORY_THRASH_FLAG_DELAYACCT` in systing_system.bpf.c: delayacct
/// was enabled and the thrash counters were actually read for this sample.
const MEMORY_THRASH_FLAG_DELAYACCT: u32 = 1 << 0;

pub struct MemoryRecorder {
    pub(crate) ringbuf: RingBuffer<memory_event>,
    pub(crate) psr: Arc<StackWalkerRun>,
    streaming_collector: Option<Box<dyn RecordCollector + Send>>,
    /// Dedup + disk spill of unique (stack, tgid) contents, handed to the
    /// StackRecorder at trace end for symbolization. Memory-alloc tracing
    /// interns a stack per malloc site per process, so under short-lived-
    /// process churn this would otherwise grow to GiBs in memory.
    interner: StackInterner,
    next_map_id: i64,
    next_alloc_id: i64,
    next_vfio_id: i64,
    next_thp_id: i64,
    write_error_reported: bool,
    utid_generator: Arc<UtidGenerator>,
    /// Every tgid that produced a memory event, with the bytes its events
    /// moved (|size| summed), for the end-of-capture per-process
    /// AnonHugePages sample: the walk takes the heaviest processes first.
    seen_tgids: HashMap<i32, u64>,
    /// The start-of-capture vmstat sample (boot ns, name -> value).
    vmstat_start: Option<(i64, Vec<(String, i64)>)>,
}

impl MemoryRecorder {
    pub fn new(utid_generator: Arc<UtidGenerator>) -> Self {
        Self {
            ringbuf: RingBuffer::default(),
            psr: Arc::new(StackWalkerRun::default()),
            streaming_collector: None,
            interner: StackInterner::new(MEMORY_STACK_ID_OFFSET),
            next_map_id: 1,
            next_alloc_id: 1,
            next_vfio_id: 1,
            next_thp_id: 1,
            write_error_reported: false,
            utid_generator,
            seen_tgids: HashMap::new(),
            vmstat_start: None,
        }
    }
}

/// Read the `VMSTAT_COUNTERS` present in `/proc/vmstat` (a counter a kernel
/// lacks is simply absent from the sample).
pub fn read_vmstat_counters() -> Vec<(String, i64)> {
    match std::fs::read_to_string("/proc/vmstat") {
        Ok(contents) => parse_vmstat(&contents),
        Err(_) => Vec::new(),
    }
}

/// `parse_vmstat` over the text of `/proc/vmstat`, keeping `VMSTAT_COUNTERS`
/// in file order.
pub fn parse_vmstat(contents: &str) -> Vec<(String, i64)> {
    contents
        .lines()
        .filter_map(|line| {
            let mut it = line.split_whitespace();
            let name = it.next()?;
            let value = it.next()?.parse::<i64>().ok()?;
            VMSTAT_COUNTERS
                .contains(&name)
                .then(|| (name.to_string(), value))
        })
        .collect()
}

/// `AnonHugePages` (bytes) from `/proc/<pid>/smaps_rollup`; `None` when the
/// process is gone or the file is unreadable.
fn read_anon_huge_pages(pid: i32) -> Option<i64> {
    let contents = std::fs::read_to_string(format!("/proc/{pid}/smaps_rollup")).ok()?;
    parse_smaps_anon_huge(&contents)
}

/// The most processes the end-of-capture AnonHugePages walk reads; each
/// read is a kernel page-table walk of that process.
pub const ANON_HUGE_WALK_MAX_TGIDS: usize = 64;
/// The wall-time budget of the whole AnonHugePages walk; a host whose
/// processes map terabytes at 4 KiB would otherwise hold the capture's stop
/// for seconds.
pub const ANON_HUGE_WALK_BUDGET: Duration = Duration::from_millis(500);

/// What the end-of-capture AnonHugePages walk did, for `sysinfo`
/// (`memory_anon_huge_walk`): `complete:<read>/<candidates>` when every
/// live candidate was read, `capped:<read>/<candidates>` when the process
/// cap stopped it, `budget:<read>/<candidates>` when the time budget did.
/// `candidates` counts every process that produced a memory event; those
/// already gone at capture end are neither read nor skipped.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AnonHugeWalk {
    pub candidates: usize,
    pub read: usize,
    pub gone: usize,
    pub skipped_cap: usize,
    pub skipped_budget: usize,
}

impl AnonHugeWalk {
    /// The `sysinfo.memory_anon_huge_walk` value.
    pub fn sysinfo_value(&self) -> String {
        let state = if self.skipped_budget > 0 {
            "budget"
        } else if self.skipped_cap > 0 {
            "capped"
        } else {
            "complete"
        };
        format!("{state}:{}/{}", self.read, self.candidates)
    }
}

/// The `AnonHugePages: <n> kB` line of a smaps / smaps_rollup text, in bytes.
pub fn parse_smaps_anon_huge(contents: &str) -> Option<i64> {
    contents.lines().find_map(|line| {
        let rest = line.strip_prefix("AnonHugePages:")?;
        let kb = rest.split_whitespace().next()?.parse::<i64>().ok()?;
        Some(kb * 1024)
    })
}

impl ThreadAwareRecorder for MemoryRecorder {
    fn utid_generator(&self) -> &UtidGenerator {
        &self.utid_generator
    }
}

fn alloc_op_name(op: u32) -> &'static str {
    match memory_alloc_op(op) {
        memory_alloc_op::MEMORY_OP_MALLOC => "malloc",
        memory_alloc_op::MEMORY_OP_CALLOC => "calloc",
        memory_alloc_op::MEMORY_OP_REALLOC => "realloc",
        memory_alloc_op::MEMORY_OP_POSIX_MEMALIGN => "posix_memalign",
        memory_alloc_op::MEMORY_OP_ALIGNED_ALLOC => "aligned_alloc",
        memory_alloc_op::MEMORY_OP_FREE => "free",
        _ => "unknown",
    }
}

impl MemoryRecorder {
    pub fn set_streaming_collector(&mut self, collector: Box<dyn RecordCollector + Send>) {
        self.streaming_collector = Some(collector);
    }

    pub fn set_pystacks_run(&mut self, psr: Arc<StackWalkerRun>) {
        self.psr = psr;
    }

    /// Configure the directory for the unique-stack spill file. Must be called
    /// before recording starts; without it, stack contents are kept in memory.
    pub fn set_spill_dir(&mut self, dir: &Path) {
        self.interner.set_spill_dir(dir);
    }

    /// Drain the stack interner for hand-off to `StackRecorder` so its stacks
    /// are symbolized in the shared `stack` table during finish.
    pub(crate) fn take_interner(&mut self) -> StackInterner {
        std::mem::replace(
            &mut self.interner,
            StackInterner::new(MEMORY_STACK_ID_OFFSET),
        )
    }

    pub fn finish(
        &mut self,
        collector: Box<dyn RecordCollector + Send>,
    ) -> Result<Box<dyn RecordCollector + Send>> {
        if let Some(mut own) = self.streaming_collector.take() {
            own.flush()?;
            own.finish_boxed()?;
        }
        Ok(collector)
    }

    /// Keep the start-of-capture vmstat sample until the end sample arrives.
    pub fn set_vmstat_start(&mut self, ts: i64, samples: Vec<(String, i64)>) {
        self.vmstat_start = Some((ts, samples));
    }

    /// Write the `memory_vmstat` rows: every counter present in both samples.
    pub fn emit_vmstat_end(&mut self, ts_end: i64, end: Vec<(String, i64)>) {
        let Some((ts_start, start)) = self.vmstat_start.take() else {
            return;
        };
        let Some(mut collector) = self.streaming_collector.take() else {
            return;
        };
        for (name, value_start) in start {
            let Some((_, value_end)) = end.iter().find(|(n, _)| *n == name) else {
                continue;
            };
            let r = collector.add_memory_vmstat(MemoryVmstatRecord {
                name,
                ts_start,
                value_start,
                ts_end,
                value_end: *value_end,
            });
            self.report_write_error(r);
        }
        self.streaming_collector = Some(collector);
    }

    /// Write the `memory_iommu` rows from the drained BPF histogram; `utid`
    /// is the mapping process's main thread.
    pub fn emit_iommu_hist(&mut self, ts: i64, entries: &[MemoryIommuHistEntry]) {
        if entries.is_empty() {
            return;
        }
        let Some(mut collector) = self.streaming_collector.take() else {
            return;
        };
        for e in entries {
            let utid = self.utid_generator.get_or_create_utid(e.tgid);
            let op = match e.op {
                1 => "map",
                2 => "unmap",
                _ => "unknown",
            };
            let r = collector.add_memory_iommu(MemoryIommuRecord {
                ts,
                utid,
                op: op.to_string(),
                iova_gib: e.iova_gib as i64,
                size_order: e.order as i32,
                count: e.count as i64,
                bytes: e.bytes as i64,
            });
            self.report_write_error(r);
        }
        self.streaming_collector = Some(collector);
    }

    /// One `memory_rss` row (member `MEMORY_MEMBER_ANON_HUGE`) per process
    /// that produced a memory event and is still alive, read from
    /// `/proc/<pid>/smaps_rollup`. Each read is a page-table walk of that
    /// process in the kernel, so the caller runs this only for captures
    /// that asked the huge-page question (the THP-split leg), never on
    /// every memory capture — and even then the walk is bounded: at most
    /// [`ANON_HUGE_WALK_MAX_TGIDS`] processes, the ones whose memory events
    /// moved the most bytes first, under [`ANON_HUGE_WALK_BUDGET`] of wall
    /// time. The outcome (how many were read, how many the cap or the
    /// budget skipped) is returned for the capture's `sysinfo` row, so a
    /// reader can tell a complete sample from a capped one.
    pub fn emit_anon_huge_pages(&mut self, ts: i64) -> AnonHugeWalk {
        let mut tgids: Vec<(i32, u64)> = self.seen_tgids.iter().map(|(t, b)| (*t, *b)).collect();
        let candidates = tgids.len();
        let mut walk = AnonHugeWalk {
            candidates,
            ..AnonHugeWalk::default()
        };
        if tgids.is_empty() {
            return walk;
        }
        let Some(mut collector) = self.streaming_collector.take() else {
            return walk;
        };
        // Heaviest first, then by tgid so the order is stable.
        tgids.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        let started = Instant::now();
        for (i, (tgid, _)) in tgids.iter().enumerate() {
            if i >= ANON_HUGE_WALK_MAX_TGIDS {
                walk.skipped_cap = candidates - i;
                break;
            }
            if started.elapsed() > ANON_HUGE_WALK_BUDGET {
                walk.skipped_budget = candidates - i;
                break;
            }
            let Some(bytes) = read_anon_huge_pages(*tgid) else {
                walk.gone += 1;
                continue;
            };
            walk.read += 1;
            let utid = self.utid_generator.get_or_create_utid(*tgid);
            let r = collector.add_memory_rss(MemoryRssRecord {
                ts,
                utid,
                member: MEMORY_MEMBER_ANON_HUGE,
                size: bytes,
                external: false,
            });
            self.report_write_error(r);
        }
        self.streaming_collector = Some(collector);
        walk
    }

    fn report_write_error(&mut self, r: Result<()>) {
        if let Err(e) = r {
            if !self.write_error_reported {
                self.write_error_reported = true;
                eprintln!("memory_recorder: write error (further errors suppressed): {e}");
            }
        }
    }

    fn intern_stack(&mut self, event: &memory_event, tgid: i32) -> Option<i64> {
        let klen = (event.hdr.kernel_stack_length as usize).min(event.kernel_stack.len());
        let ulen = (event.hdr.user_stack_length as usize).min(event.user_stack.len());
        let kstack = &event.kernel_stack[..klen];
        let ustack = &event.user_stack[..ulen];
        let py_stack = self
            .psr
            .get_pystack_from_buffer(&event.py_msg_buffer, tgid as u64);
        if kstack.is_empty() && ustack.is_empty() && py_stack.is_empty() {
            return None;
        }
        let stack = Stack::new(kstack, ustack, &py_stack);
        Some(self.interner.intern(stack, tgid))
    }

    fn emit_map(
        &mut self,
        collector: &mut (dyn RecordCollector + Send),
        event: &memory_event,
        task: ResolvedTask,
        event_type: &'static str,
        prot: Option<i32>,
        flags: Option<i32>,
    ) {
        let stack_id = self.intern_stack(event, task.tgid);
        let id = self.next_map_id;
        self.next_map_id += 1;
        // Per-type field reuse: map legs carry the signed RSS delta in
        // old_addr (see the BPF header comment); the sentinel marks rows
        // where either resident read was unavailable.
        let rss_delta_bytes = match event.hdr.old_addr as i64 {
            i64::MIN => None,
            d => Some(d),
        };
        let r = collector.add_memory_map(MemoryMapRecord {
            id,
            ts: event.hdr.ts as i64,
            utid: task.utid,
            event_type: event_type.to_string(),
            addr: event.hdr.addr as i64,
            size: event.hdr.size as i64,
            rss_delta_bytes,
            prot,
            flags,
            stack_id,
        });
        self.report_write_error(r);
    }
}

impl SystingRecordEvent<memory_event> for MemoryRecorder {
    fn ringbuf(&self) -> &RingBuffer<memory_event> {
        &self.ringbuf
    }
    fn ringbuf_mut(&mut self) -> &mut RingBuffer<memory_event> {
        &mut self.ringbuf
    }
    fn handle_event(&mut self, event: memory_event) {
        let Some(mut collector) = self.streaming_collector.take() else {
            return;
        };
        let hdr = &event.hdr;
        let task = self.utid_generator.resolve_task(&hdr.task);
        let ResolvedTask { utid, tgid } = task;
        *self.seen_tgids.entry(tgid).or_insert(0) += (hdr.size as i64).unsigned_abs();

        match hdr.r#type {
            memory_event_type::MEMORY_RSS_STAT => {
                let r = collector.add_memory_rss(MemoryRssRecord {
                    ts: hdr.ts as i64,
                    utid,
                    member: hdr.member.min(i8::MAX as u32) as i8,
                    size: hdr.size as i64,
                    external: hdr.flags & MEMORY_RSS_FLAG_EXTERNAL != 0,
                });
                self.report_write_error(r);
            }
            memory_event_type::MEMORY_MMAP => {
                self.emit_map(
                    collector.as_mut(),
                    &event,
                    task,
                    "mmap",
                    Some(hdr.member as i32),
                    Some(hdr.flags as i32),
                );
            }
            memory_event_type::MEMORY_MUNMAP => {
                self.emit_map(collector.as_mut(), &event, task, "munmap", None, None);
            }
            memory_event_type::MEMORY_BRK => {
                self.emit_map(collector.as_mut(), &event, task, "brk", None, None);
            }
            memory_event_type::MEMORY_PAGE_FAULT => {
                let stack_id = self.intern_stack(&event, tgid);
                let r = collector.add_memory_fault(MemoryFaultRecord {
                    ts: hdr.ts as i64,
                    utid,
                    addr: hdr.addr as i64,
                    error_code: hdr.flags as i32,
                    stack_id,
                });
                self.report_write_error(r);
            }
            memory_event_type::MEMORY_ALLOC | memory_event_type::MEMORY_FREE => {
                let stack_id = self.intern_stack(&event, tgid);
                let id = self.next_alloc_id;
                self.next_alloc_id += 1;
                let is_realloc = memory_alloc_op(hdr.member) == memory_alloc_op::MEMORY_OP_REALLOC;
                let r = collector.add_memory_alloc(MemoryAllocRecord {
                    id,
                    ts: hdr.ts as i64,
                    utid,
                    op: alloc_op_name(hdr.member).to_string(),
                    addr: hdr.addr as i64,
                    size: hdr.size as i64,
                    old_addr: if is_realloc {
                        Some(hdr.old_addr as i64)
                    } else {
                        None
                    },
                    stack_id,
                });
                self.report_write_error(r);
            }
            memory_event_type::MEMORY_MM_SAMPLE => {
                let r = collector.add_memory_rss(MemoryRssRecord {
                    ts: hdr.ts as i64,
                    utid,
                    member: MEMORY_MEMBER_HIWATER_RSS,
                    size: hdr.addr as i64,
                    external: false,
                });
                self.report_write_error(r);
                let r = collector.add_memory_rss(MemoryRssRecord {
                    ts: hdr.ts as i64,
                    utid,
                    member: MEMORY_MEMBER_TOTAL_VM,
                    size: hdr.size as i64,
                    external: false,
                });
                self.report_write_error(r);
            }
            memory_event_type::MEMORY_VFIO_MAP | memory_event_type::MEMORY_VFIO_UNMAP => {
                // Per-type field reuse: addr = iova, size = region bytes,
                // old_addr = user vaddr (map only), flags = ioctl flags.
                let is_map = hdr.r#type == memory_event_type::MEMORY_VFIO_MAP;
                let stack_id = self.intern_stack(&event, tgid);
                let id = self.next_vfio_id;
                self.next_vfio_id += 1;
                let r = collector.add_memory_vfio(MemoryVfioRecord {
                    id,
                    ts: hdr.ts as i64,
                    utid,
                    op: if is_map { "map" } else { "unmap" }.to_string(),
                    iova: hdr.addr as i64,
                    vaddr: is_map.then_some(hdr.old_addr as i64),
                    size: hdr.size as i64,
                    flags: hdr.flags as i32,
                    stack_id,
                });
                self.report_write_error(r);
            }
            memory_event_type::MEMORY_THP_SPLIT => {
                // Per-type field reuse: member = memory_thp_split_kind, addr =
                // the split address (pmd only), flags = the kernel's return
                // value (page only; 0 = split).
                let kind = memory_thp_split_kind(hdr.member);
                let is_pmd = kind == memory_thp_split_kind::MEMORY_THP_SPLIT_PMD;
                let stack_id = self.intern_stack(&event, tgid);
                let id = self.next_thp_id;
                self.next_thp_id += 1;
                let r = collector.add_memory_thp(MemoryThpRecord {
                    id,
                    ts: hdr.ts as i64,
                    utid,
                    kind: if is_pmd { "pmd" } else { "page" }.to_string(),
                    addr: is_pmd.then_some(hdr.addr as i64),
                    result: hdr.flags as i32,
                    stack_id,
                });
                self.report_write_error(r);
            }
            memory_event_type::MEMORY_THRASH_SAMPLE => {
                // Per-type field reuse: addr = maj_flt, size = delayacct
                // thrashing_count, old_addr = thrashing_delay ns.
                let (maj_flt, thrash_count, thrash_delay_ns) = (hdr.addr, hdr.size, hdr.old_addr);
                // maj_flt is emitted unconditionally (a 0 row distinguishes
                // "no major faults yet" from "no data"); the delayacct pair
                // only when the flag says the counters were readable, so
                // zero-valued pair rows mean "no thrash" and pair absence
                // means delayacct is off on the host.
                let r = collector.add_memory_rss(MemoryRssRecord {
                    ts: hdr.ts as i64,
                    utid,
                    member: MEMORY_MEMBER_MAJ_FLT,
                    size: maj_flt as i64,
                    external: false,
                });
                self.report_write_error(r);
                if hdr.flags & MEMORY_THRASH_FLAG_DELAYACCT != 0 {
                    let r = collector.add_memory_rss(MemoryRssRecord {
                        ts: hdr.ts as i64,
                        utid,
                        member: MEMORY_MEMBER_THRASHING_COUNT,
                        size: thrash_count as i64,
                        external: false,
                    });
                    self.report_write_error(r);
                    let r = collector.add_memory_rss(MemoryRssRecord {
                        ts: hdr.ts as i64,
                        utid,
                        member: MEMORY_MEMBER_THRASHING_DELAY,
                        size: thrash_delay_ns as i64,
                        external: false,
                    });
                    self.report_write_error(r);
                }
            }
            _ => {}
        }

        self.streaming_collector = Some(collector);
    }
}

/// Human-readable label for the `memory_rss.member` column.
pub fn memory_rss_member_name(member: i8) -> &'static str {
    match member {
        MEMORY_MEMBER_HIWATER_RSS => "hiwater_rss",
        MEMORY_MEMBER_TOTAL_VM => "total_vm",
        MEMORY_MEMBER_ANON_HUGE => "anon_huge",
        MEMORY_MEMBER_MAJ_FLT => "maj_flt",
        MEMORY_MEMBER_THRASHING_COUNT => "thrashing_count",
        MEMORY_MEMBER_THRASHING_DELAY => "thrashing_delay_ns",
        m if m >= 0 => match memory_rss_member(m as u32) {
            memory_rss_member::MEMORY_MM_FILEPAGES => "file",
            memory_rss_member::MEMORY_MM_ANONPAGES => "anon",
            memory_rss_member::MEMORY_MM_SWAPENTS => "swap",
            memory_rss_member::MEMORY_MM_SHMEMPAGES => "shmem",
            _ => "unknown",
        },
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_member_name() {
        assert_eq!(memory_rss_member_name(1), "anon");
        assert_eq!(memory_rss_member_name(-1), "hiwater_rss");
        assert_eq!(memory_rss_member_name(-2), "total_vm");
        assert_eq!(memory_rss_member_name(-3), "maj_flt");
        assert_eq!(memory_rss_member_name(-4), "thrashing_count");
        assert_eq!(memory_rss_member_name(-5), "thrashing_delay_ns");
        assert_eq!(memory_rss_member_name(-6), "anon_huge");
        assert_eq!(memory_rss_member_name(-7), "unknown");
        assert_eq!(memory_rss_member_name(99), "unknown");
    }

    #[test]
    fn test_parse_vmstat_keeps_the_listed_counters_in_file_order() {
        let text = "nr_free_pages 12345\nthp_fault_alloc 10\nthp_fault_fallback 3\n\
                    bogus line\nthp_split_pmd 7\nnr_anon_transparent_hugepages 2048\n\
                    pgscan_direct notanumber\ncompact_stall 1\n";
        let got = parse_vmstat(text);
        assert_eq!(
            got,
            vec![
                ("thp_fault_alloc".to_string(), 10),
                ("thp_fault_fallback".to_string(), 3),
                ("thp_split_pmd".to_string(), 7),
                ("nr_anon_transparent_hugepages".to_string(), 2048),
                ("compact_stall".to_string(), 1),
            ]
        );
        assert!(parse_vmstat("").is_empty());
    }

    #[test]
    fn test_parse_smaps_anon_huge() {
        let text = "Rss:              123456 kB\nAnonHugePages:     4096 kB\nShmemPmdMapped:        0 kB\n";
        assert_eq!(parse_smaps_anon_huge(text), Some(4096 * 1024));
        assert_eq!(parse_smaps_anon_huge("Rss: 1 kB\n"), None);
        assert_eq!(parse_smaps_anon_huge("AnonHugePages: x kB\n"), None);
    }
}
