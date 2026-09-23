//! Writing snapshots as a Perfetto trace of native heap profiles, the form
//! Perfetto's own heap profiler (heapprofd) writes, so ui.perfetto.dev shows
//! each process's snapshots on its track and a flamegraph for each.
//!
//! Frames are split as systing's task-stacks tracks split them
//! ([`systing::parquet_to_perfetto::parse_frame`]): the frame is named after
//! the function alone, the module is its mapping, and the source file and
//! line are the frame's symbols (`ModuleSymbols`).
//!
//! Each snapshot is one `ProfilePacket` on a packet sequence of its own that
//! defines every string, mapping, frame and stack it uses (Perfetto forgets
//! them when a profile ends, and does not take them again on the same
//! sequence). Its counts are each stack's increase since the process's
//! previous snapshot; Perfetto adds up the rows at or before a snapshot's
//! time, so each flamegraph shows the cumulative counts, which never go
//! down:
//!
//! - live bytes and objects are jeprof's estimates (the rows scaled as
//!   `SCHEMA_CHANGES.md`, schema 26, says), not the counts as written;
//! - "allocated" is jemalloc's cumulative count where it kept one
//!   (`prof_accum`), otherwise the smallest total consistent with the live
//!   counts seen so far (it grows by each rise in live bytes); "freed" is
//!   allocated less live. "Unreleased" (allocated - freed) is the live
//!   estimate exactly; "total allocated" is a lower bound without
//!   `prof_accum`;
//! - a stack a later snapshot no longer has is reported with nothing live.

use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use perfetto_protos::builtin_clock::BuiltinClock;
use perfetto_protos::clock_snapshot::{clock_snapshot::Clock, ClockSnapshot};
use perfetto_protos::process_tree::{process_tree::Process, ProcessTree};
use perfetto_protos::profile_common::{
    AddressSymbols, Callstack, Frame, InternedString, Line, Mapping, ModuleSymbols,
};
use perfetto_protos::profile_packet::profile_packet::{HeapSample, ProcessHeapSamples};
use perfetto_protos::profile_packet::ProfilePacket;
use perfetto_protos::trace_packet::trace_packet::SequenceFlags;
use perfetto_protos::trace_packet::TracePacket;
use systing::parquet_to_perfetto::parse_frame;
use systing::perfetto::{StreamingTraceWriter, TraceWriter};

use crate::db::Written;
use crate::symbolize::Symbolized;
use crate::Snapshot;

/// Whether `path` names a Perfetto trace, by the extensions systing-util
/// takes.
pub fn is_perfetto_output(path: &Path) -> bool {
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    [".pb", ".perfetto", ".pftrace", ".perfetto-trace"]
        .iter()
        .any(|e| name.ends_with(e))
}

/// A stack's cumulative counts as last reported.
#[derive(Default, Clone, Copy)]
struct Reported {
    allocated: u64,
    freed: u64,
    alloc_count: u64,
    free_count: u64,
}

impl Reported {
    /// The next report, from a snapshot's estimates; counts never go down.
    fn next(self, [live_b, live_n, acc_b, acc_n]: [u64; 4]) -> Reported {
        let grow = |prev_alloc: u64, prev_freed: u64, live: u64, acc: u64| {
            let allocated = if acc > 0 {
                prev_alloc.max(acc).max(prev_freed.saturating_add(live))
            } else {
                prev_alloc.saturating_add(live.saturating_sub(prev_alloc - prev_freed))
            };
            let freed = prev_freed.max(allocated.saturating_sub(live));
            (allocated, freed)
        };
        let (allocated, freed) = grow(self.allocated, self.freed, live_b, acc_b);
        let (alloc_count, free_count) = grow(self.alloc_count, self.free_count, live_n, acc_n);
        Reported {
            allocated,
            freed,
            alloc_count,
            free_count,
        }
    }
}

/// One process's state across its snapshots. Ids are stable for the process
/// (a stack's cumulative counts follow its id), but each snapshot is written
/// as a sequence of its own that carries every string, mapping, frame and
/// stack it refers to.
struct Sequence {
    strings: HashMap<String, u64>,
    mappings: HashMap<String, u64>,
    frames: HashMap<String, u64>,
    callstacks: HashMap<Vec<u64>, u64>,
    string_defs: Vec<InternedString>,
    mapping_defs: Vec<Mapping>,
    frame_defs: Vec<Frame>,
    callstack_defs: Vec<Callstack>,
    reported: BTreeMap<u64, Reported>,
    /// The last snapshot's timestamp, to keep this process's in order.
    last_ts: Option<u64>,
}

/// State shared by every process in the trace. Perfetto merges every
/// process's mapping of one module and attaches symbols by (mapping,
/// rel_pc), so what those are keyed by must mean the same frame in every
/// process.
#[derive(Default)]
struct Trace {
    /// The rel_pc of each frame with no address (Python functions), by name.
    addressless: HashMap<String, u64>,
    /// Frames with a source file, for the symbols sent at the end:
    /// (module, rel_pc) -> (function, file, line).
    sourced: BTreeMap<(String, u64), (String, String, Option<i64>)>,
}

impl Sequence {
    fn new() -> Sequence {
        Sequence {
            strings: HashMap::new(),
            mappings: HashMap::new(),
            frames: HashMap::new(),
            callstacks: HashMap::new(),
            string_defs: Vec::new(),
            mapping_defs: Vec::new(),
            frame_defs: Vec::new(),
            callstack_defs: Vec::new(),
            reported: BTreeMap::new(),
            last_ts: None,
        }
    }

    fn string(&mut self, s: &str) -> u64 {
        if let Some(&iid) = self.strings.get(s) {
            return iid;
        }
        let iid = self.string_defs.len() as u64 + 1;
        self.strings.insert(s.to_string(), iid);
        let mut i = InternedString::default();
        i.set_iid(iid);
        i.set_str(s.as_bytes().to_vec());
        self.string_defs.push(i);
        iid
    }

    fn mapping(&mut self, module: &str) -> u64 {
        if let Some(&iid) = self.mappings.get(module) {
            return iid;
        }
        let path = self.string(module);
        let build_id = self.string(&build_id(module));
        let iid = self.mapping_defs.len() as u64 + 1;
        self.mappings.insert(module.to_string(), iid);
        let mut m = Mapping::default();
        m.set_iid(iid);
        m.set_build_id(build_id);
        m.set_exact_offset(0);
        m.set_start_offset(0);
        m.path_string_ids = vec![path];
        self.mapping_defs.push(m);
        iid
    }

    /// The frame for a systing frame name, split into function, module and
    /// source; `full_path` is the source's full path where known.
    fn frame(&mut self, name: &str, full_path: Option<&str>, trace: &mut Trace) -> u64 {
        if let Some(&iid) = self.frames.get(name) {
            return iid;
        }
        let parts = parse_frame(name);
        let module = match (parts.module, parts.language) {
            (Some(m), _) => m.to_string(),
            (None, "python") => "[python]".to_string(),
            _ => "[unknown]".to_string(),
        };
        let mapping = self.mapping(&module);
        let function = self.string(parts.function);
        let iid = self.frame_defs.len() as u64 + 1;
        self.frames.insert(name.to_string(), iid);
        let mut f = Frame::default();
        f.set_iid(iid);
        f.set_function_name_id(function);
        f.set_mapping_id(mapping);
        // The frame's identity within its mapping: the address where there
        // is one, else a value no address takes, one per frame name across
        // the trace, so frames that differ only by their source are not
        // merged and one process's frame never takes another's symbols.
        let address = parts
            .address
            .and_then(|a| u64::from_str_radix(a.trim_start_matches("0x"), 16).ok());
        let rel_pc = address.unwrap_or_else(|| {
            let next = u64::MAX - trace.addressless.len() as u64 - 1;
            *trace.addressless.entry(name.to_string()).or_insert(next)
        });
        f.set_rel_pc(rel_pc);
        self.frame_defs.push(f);
        if let Some(file) = full_path.or(parts.file) {
            trace
                .sourced
                .entry((module, rel_pc))
                .or_insert_with(|| (parts.function.to_string(), file.to_string(), parts.line));
        }
        iid
    }

    fn callstack(&mut self, frames: Vec<u64>) -> u64 {
        if let Some(&iid) = self.callstacks.get(&frames) {
            return iid;
        }
        let iid = self.callstack_defs.len() as u64 + 1;
        let mut c = Callstack::default();
        c.set_iid(iid);
        c.frame_ids = frames.clone();
        self.callstack_defs.push(c);
        self.callstacks.insert(frames, iid);
        iid
    }

    /// Put into `out` the definitions `callstacks` need: the stacks, their
    /// frames, the frames' mappings, and every string those name.
    fn define(&self, callstacks: impl Iterator<Item = u64>, out: &mut ProfilePacket) {
        let def = |iid: u64| (iid - 1) as usize;
        let mut frames = std::collections::BTreeSet::new();
        for c in callstacks {
            let cs = &self.callstack_defs[def(c)];
            frames.extend(cs.frame_ids.iter().copied());
            out.callstacks.push(cs.clone());
        }
        let mut mappings = std::collections::BTreeSet::new();
        let mut strings = std::collections::BTreeSet::new();
        for &f in &frames {
            let fr = &self.frame_defs[def(f)];
            mappings.insert(fr.mapping_id());
            strings.insert(fr.function_name_id());
            out.frames.push(fr.clone());
        }
        for &m in &mappings {
            let mp = &self.mapping_defs[def(m)];
            strings.extend(mp.path_string_ids.iter().copied());
            strings.insert(mp.build_id());
            out.mappings.push(mp.clone());
        }
        for &s in &strings {
            out.strings.push(self.string_defs[def(s)].clone());
        }
    }
}

/// Write `snapshots`, named by `symbolized`, as a Perfetto trace at `out`.
pub fn write(out: &Path, snapshots: &[Snapshot], symbolized: &Symbolized) -> Result<Written> {
    let file = std::fs::File::create(out).with_context(|| format!("creating {}", out.display()))?;
    let mut buf = std::io::BufWriter::new(file);
    let mut written = Written::default();
    {
        let mut writer = StreamingTraceWriter::new(&mut buf);
        write_packets(&mut writer, snapshots, symbolized, &mut written)?;
        writer.flush()?;
    }
    buf.flush()?;
    // On disk before the caller deletes the dumps it was made from.
    buf.get_ref()
        .sync_all()
        .with_context(|| format!("syncing {}", out.display()))?;
    Ok(written)
}

fn write_packets(
    writer: &mut dyn TraceWriter,
    snapshots: &[Snapshot],
    symbolized: &Symbolized,
    written: &mut Written,
) -> Result<()> {
    // Every built-in clock at one instant. Perfetto reads heap-profile
    // timestamps in a clock of its choosing and needs a snapshot to convert
    // it to the trace's; the snapshot times are the dumps' wall-clock times,
    // so any clock reads the same.
    let mut clocks = ClockSnapshot::default();
    for id in [
        BuiltinClock::BUILTIN_CLOCK_REALTIME,
        BuiltinClock::BUILTIN_CLOCK_REALTIME_COARSE,
        BuiltinClock::BUILTIN_CLOCK_MONOTONIC,
        BuiltinClock::BUILTIN_CLOCK_MONOTONIC_COARSE,
        BuiltinClock::BUILTIN_CLOCK_MONOTONIC_RAW,
        BuiltinClock::BUILTIN_CLOCK_BOOTTIME,
    ] {
        let mut c = Clock::default();
        c.set_clock_id(id as u32);
        c.set_timestamp(0);
        clocks.clocks.push(c);
    }
    let mut packet = TracePacket::default();
    packet.set_clock_snapshot(clocks);
    packet.set_trusted_packet_sequence_id(1);
    writer.write_packet(&packet)?;

    // One process row per pid, named as `process.name` is.
    let mut tree = ProcessTree::default();
    let mut named: Vec<i32> = Vec::new();
    for s in snapshots {
        let Some(pid) = s.pid else { continue };
        if named.contains(&pid) {
            continue;
        }
        named.push(pid);
        let mut p = Process::default();
        p.set_pid(pid);
        p.cmdline = s.maps.exe_name().map(str::to_string).into_iter().collect();
        tree.processes.push(p);
    }
    if !tree.processes.is_empty() {
        let mut packet = TracePacket::default();
        packet.set_process_tree(tree);
        packet.set_trusted_packet_sequence_id(1);
        writer.write_packet(&packet)?;
    }

    // Snapshots in dump order per process (the caller sorts by pid, seq).
    let mut sequences: BTreeMap<Option<i32>, Sequence> = BTreeMap::new();
    let mut trace = Trace::default();
    let mut frame_count = 0;
    for (si, s) in snapshots.iter().enumerate() {
        let seq = sequences.entry(s.pid).or_insert_with(Sequence::new);
        // A packet sequence of its own (1 is the trace's metadata): Perfetto
        // forgets a sequence's definitions after a profile and will not take
        // them again on it.
        let packet_seq = si as u32 + 2;
        let mut profile = ProfilePacket::default();

        let mut dump = ProcessHeapSamples::default();
        // A dump with no pid is still shown, on a process of its own.
        dump.set_pid(s.pid.map_or(0, |p| p as u64));
        dump.set_heap_name(s.format.name().to_string());
        dump.set_sampling_interval_bytes(s.sample_period);
        let ts = s
            .dumped_at_unix_ns
            .and_then(|t| u64::try_from(t).ok())
            .unwrap_or(si as u64 * 1_000_000_000);
        // Each snapshot holds its increase since the previous one in
        // sequence order, and Perfetto adds them up in time order: keep the
        // two the same where a copy moved the files' mtimes.
        let ts = seq.last_ts.map_or(ts, |last| ts.max(last + 1));
        seq.last_ts = Some(ts);
        dump.set_timestamp(ts);

        // This snapshot's estimates per stack: two rows can share a stack
        // (names that collapse to the same frames), and add up.
        let mut now: BTreeMap<u64, [u64; 4]> = BTreeMap::new();
        for (sample, names) in s.samples.iter().zip(&symbolized.frames[si]) {
            let frames: Vec<u64> = names
                .iter()
                .map(|n| {
                    let full = symbolized.files.get(n).map(String::as_str);
                    seq.frame(n, full, &mut trace)
                })
                .collect();
            let callstack = seq.callstack(frames);
            let est = sample.estimates(s.sample_period);
            let sum = now.entry(callstack).or_default();
            for (a, b) in sum.iter_mut().zip(est) {
                *a = a.saturating_add(b);
            }
            written.samples += 1;
        }
        // Every stack this process has shown is reported in every later
        // snapshot, with nothing live where it is gone.
        for callstack in seq.reported.keys().copied().collect::<Vec<_>>() {
            now.entry(callstack).or_default();
        }
        // Each stack's increase since the process's previous snapshot:
        // Perfetto adds up a process's rows at or before a snapshot's time,
        // so the flamegraph at each snapshot shows the cumulative counts.
        let mut changed: Vec<(u64, Reported)> = Vec::new();
        for (callstack, est) in now {
            let prev = seq.reported.get(&callstack).copied().unwrap_or_default();
            let next = prev.next(est);
            seq.reported.insert(callstack, next);
            let delta = Reported {
                allocated: next.allocated - prev.allocated,
                freed: next.freed - prev.freed,
                alloc_count: next.alloc_count - prev.alloc_count,
                free_count: next.free_count - prev.free_count,
            };
            if delta.allocated + delta.freed + delta.alloc_count + delta.free_count > 0 {
                changed.push((callstack, delta));
            }
        }
        seq.define(changed.iter().map(|(c, _)| *c), &mut profile);
        for (callstack, d) in &changed {
            let mut h = HeapSample::default();
            h.set_callstack_id(*callstack);
            h.set_self_allocated(d.allocated);
            h.set_self_freed(d.freed);
            h.set_alloc_count(d.alloc_count);
            h.set_free_count(d.free_count);
            dump.samples.push(h);
        }
        profile.process_dumps.push(dump);
        profile.set_continued(false);
        profile.set_index(0);

        let mut packet = TracePacket::default();
        packet.set_timestamp(ts);
        packet.set_trusted_packet_sequence_id(packet_seq);
        packet.set_sequence_flags(SequenceFlags::SEQ_INCREMENTAL_STATE_CLEARED as u32);
        packet.set_profile_packet(profile);
        writer.write_packet(&packet)?;
        written.snapshots += 1;
    }

    // Each frame's source, where it has one, as the symbols of its module:
    // Perfetto matches a module's symbols to its mapping by path and to its
    // frames by address (rel_pc). (ProfiledFrameSymbols, the older form,
    // is gone from newer Perfetto.)
    for seq in sequences.values() {
        frame_count += seq.frame_defs.len();
        written.stacks += seq.callstack_defs.len();
    }
    {
        let mut by_module: BTreeMap<&str, Vec<AddressSymbols>> = BTreeMap::new();
        for ((module, rel_pc), (function, file, line)) in &trace.sourced {
            let mut l = Line::default();
            l.set_function_name(function.clone());
            l.set_source_file_name(file.clone());
            // 0 where the line is unknown (a Python frame from a perf
            // trampoline, which names a function and its file, not a line):
            // the UI shows a source location only with a line.
            l.set_line_number(line.and_then(|l| u32::try_from(l).ok()).unwrap_or(0));
            let mut a = AddressSymbols::default();
            a.set_address(*rel_pc);
            a.lines.push(l);
            by_module.entry(module.as_str()).or_default().push(a);
        }
        for (module, address_symbols) in by_module {
            let mut m = ModuleSymbols::default();
            m.set_path(mapping_name(module));
            m.set_build_id(build_id(module));
            m.address_symbols = address_symbols;
            let mut packet = TracePacket::default();
            packet.set_trusted_packet_sequence_id(1);
            packet.set_module_symbols(m);
            writer.write_packet(&packet)?;
        }
    }
    written.frames = frame_count;
    Ok(())
}

/// The build id a module's mapping and its symbols carry: Perfetto attaches
/// a module's symbols only where both have the same one. A dump names no
/// build ids, and this one is plainly not an ELF build id, so no tool takes
/// it for one.
fn build_id(module: &str) -> String {
    format!("systing-heap:{module}")
}

/// The name Perfetto gives a mapping whose path is the single component
/// `module`: its path components, each after a '/'.
fn mapping_name(module: &str) -> String {
    format!("/{module}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unreleased_is_live_and_counts_never_fall() {
        // Live bytes 100, then 300, then 50, then gone; no prof_accum.
        let mut r = Reported::default();
        let mut last = r;
        for live in [100, 300, 50, 0] {
            r = r.next([live, live / 10, 0, 0]);
            assert_eq!(r.allocated - r.freed, live);
            assert!(r.allocated >= last.allocated && r.freed >= last.freed);
            last = r;
        }
        // Total allocated is the smallest consistent with what was seen.
        assert_eq!(r.allocated, 300);
    }

    #[test]
    fn prof_accum_totals_are_used_where_kept() {
        let r = Reported::default().next([100, 1, 1000, 10]);
        assert_eq!((r.allocated, r.freed), (1000, 900));
        // A cumulative total that reads lower (a different mean size) never
        // takes the report back.
        let r2 = r.next([100, 1, 950, 10]);
        assert_eq!((r2.allocated, r2.freed), (1000, 900));
    }

    #[test]
    fn perfetto_extensions() {
        for ok in ["a.pb", "a.perfetto", "a.pftrace", "a.perfetto-trace"] {
            assert!(is_perfetto_output(Path::new(ok)), "{ok}");
        }
        assert!(!is_perfetto_output(Path::new("a.duckdb")));
    }
}
