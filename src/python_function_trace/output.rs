//! What a function trace is written as: a summary, a table of slices, and a
//! Perfetto trace with the slices on each thread's track.

use super::pairing::Slice;
use super::{Mode, Trace};
use crate::perfetto::{StreamingTraceWriter, TraceWriter};
use anyhow::{Context, Result};
use perfetto_protos::debug_annotation::DebugAnnotation;
use perfetto_protos::interned_data::InternedData;
use perfetto_protos::process_descriptor::ProcessDescriptor;
use perfetto_protos::thread_descriptor::ThreadDescriptor;
use perfetto_protos::trace_packet::trace_packet::SequenceFlags;
use perfetto_protos::trace_packet::TracePacket;
use perfetto_protos::track_descriptor::TrackDescriptor;
use perfetto_protos::track_event::track_event::Type;
use perfetto_protos::track_event::{EventName, TrackEvent};
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::io::{BufWriter, Write};
use std::path::Path;

fn ms(ns: u64) -> f64 {
    ns as f64 / 1e6
}

/// What was attached, what was seen and lost, and the `top` functions by
/// self time.
pub fn summary(trace: &Trace, top: usize) -> String {
    let mut out = String::new();
    for a in &trace.attached {
        let mode = match a.mode {
            Mode::Dispatch => "dispatch sites",
            Mode::EvalFrame => "eval-frame sites (with a return probe)",
            Mode::Auto => "auto",
        };
        let _ = writeln!(
            out,
            "pid {} ({}): Python {}.{}, {mode} in {}",
            a.pid,
            trace.processes.get(&a.pid).map_or("", String::as_str),
            a.version.0,
            a.version.1,
            a.binary
        );
        if let Some((address, found_by)) = a.table {
            let _ = writeln!(
                out,
                "  dispatch table at {address:#x} (found by {found_by:?}); {} probes: {}",
                a.sites.len(),
                a.sites.join(", ")
            );
        }
    }
    for warning in &trace.warnings {
        let _ = writeln!(out, "  warning: {warning}");
    }
    let c = &trace.counters;
    let k = &trace.kernel;
    let secs = (trace.end_ts.saturating_sub(trace.start_ts)) as f64 / 1e9;
    let _ = writeln!(
        out,
        "{:.3} s traced, until {}: {} events ({} entries, {} returns, {} yields, {} handler \
         starts), {:.0} events/s",
        secs,
        trace.ended.describe(),
        c.events,
        c.enters,
        c.exits,
        c.yields,
        c.syncs,
        if secs > 0.0 {
            c.events as f64 / secs
        } else {
            0.0
        }
    );
    let total_slices: u64 = trace.stats.values().map(|s| s.slices).sum();
    let _ = writeln!(
        out,
        "{} slices of {} functions on {} threads; {} kept",
        total_slices,
        trace.stats.len(),
        trace.threads.len(),
        trace.slices.len()
    );
    let mut asides = Vec::new();
    for (count, what) in [
        (k.dropped, "events lost to a full ring"),
        (
            c.unwound,
            "slices with no return event (an exception, or a lost or unseen event)",
        ),
        (
            c.unmatched_exits,
            "returns with no entry seen (frames from before the trace, the interpreter's \
             own shim frames)",
        ),
        (c.open_at_end, "frames still running at the end"),
        (c.first_seen_in_handler, "frames first seen in a handler"),
        (c.below_threshold, "slices under the duration threshold"),
        (c.over_cap, "slices past the cap"),
        (k.no_thread_state, "probe hits without a thread state"),
        (k.no_frame, "probe hits without a frame"),
        (k.no_code, "probe hits whose code object was unreadable"),
        (k.symbol_records_dropped, "symbol records lost"),
    ] {
        if count > 0 {
            asides.push(format!("{count} {what}"));
        }
    }
    if !asides.is_empty() {
        let _ = writeln!(out, "  {}", asides.join("; "));
    }

    let mut by_self: Vec<_> = trace.stats.iter().collect();
    by_self.sort_by(|a, b| b.1.self_ns.cmp(&a.1.self_ns).then(a.0.cmp(b.0)));
    let _ = writeln!(
        out,
        "\n{:>10} {:>12} {:>12} {:>10} {:>10}  function",
        "slices", "self ms", "total ms", "avg us", "max us"
    );
    for ((symbol_id, first_line), s) in by_self.into_iter().take(top) {
        let _ = writeln!(
            out,
            "{:>10} {:>12.3} {:>12.3} {:>10.2} {:>10.1}  {}",
            s.slices,
            ms(s.self_ns),
            ms(s.total_ns),
            s.total_ns as f64 / s.slices.max(1) as f64 / 1e3,
            s.max_ns as f64 / 1e3,
            trace.function_name(*symbol_id, *first_line)
        );
    }
    out
}

/// One line per kept slice, tab-separated, in order of start within a thread.
pub fn write_tsv(trace: &Trace, path: &Path) -> Result<()> {
    let file = std::fs::File::create(path).with_context(|| format!("create {}", path.display()))?;
    let mut w = BufWriter::new(file);
    writeln!(
        w,
        "pid\ttid\tstart_ns\tdur_ns\tdepth\tend\tfunction\tfile\tline"
    )?;
    for s in sorted(&trace.slices) {
        writeln!(
            w,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            s.tgid,
            s.tid,
            s.start,
            s.end - s.start,
            s.depth,
            s.end_kind.as_str(),
            trace.function(s.symbol_id),
            trace.source_file(s.symbol_id).unwrap_or_default(),
            s.first_line
        )?;
    }
    w.flush()?;
    Ok(())
}

/// The track id of the trace's own record.
const INFO_TRACK: u64 = 0x5046_5400_0000_0001;

/// A track of the trace's own, "python-function-trace", with one instant
/// event at the start whose arguments say how the trace was taken and what it
/// lost: which sites, why it ended, and every counter the summary prints. A
/// file from a lossy trace can then be told from a full one.
fn write_trace_info(trace: &Trace, writer: &mut dyn TraceWriter) -> Result<()> {
    let mut desc = TrackDescriptor::default();
    desc.set_uuid(INFO_TRACK);
    desc.set_name("python-function-trace".to_string());
    let mut packet = TracePacket::default();
    packet.set_track_descriptor(desc);
    packet.set_trusted_packet_sequence_id(SEQUENCE);
    writer.write_packet(&packet)?;

    let text = |name: &str, value: String| {
        let mut ann = DebugAnnotation::default();
        ann.set_name(name.to_string());
        ann.set_string_value(value);
        ann
    };
    let int = |name: &str, value: u64| {
        let mut ann = DebugAnnotation::default();
        ann.set_name(name.to_string());
        ann.set_int_value(value as i64);
        ann
    };
    let mut event = TrackEvent::default();
    event.set_type(Type::TYPE_INSTANT);
    event.set_track_uuid(INFO_TRACK);
    event.set_name("trace info".to_string());
    for a in &trace.attached {
        event.debug_annotations.push(text(
            "mode",
            match a.mode {
                Mode::EvalFrame => "eval-frame (with a return probe)".to_string(),
                _ => "dispatch".to_string(),
            },
        ));
        event
            .debug_annotations
            .push(text("sites", a.sites.join(", ")));
        event
            .debug_annotations
            .push(text("interpreter", a.binary.clone()));
    }
    event
        .debug_annotations
        .push(text("ended", trace.ended.describe().to_string()));
    for warning in &trace.warnings {
        event
            .debug_annotations
            .push(text("warning", warning.clone()));
    }
    let c = &trace.counters;
    let k = &trace.kernel;
    for (name, value) in [
        ("events", c.events),
        ("events_lost_full_ring", k.dropped),
        ("slices_no_return_event", c.unwound),
        ("returns_no_entry_seen", c.unmatched_exits),
        ("frames_open_at_end", c.open_at_end),
        ("frames_first_seen_in_handler", c.first_seen_in_handler),
        ("slices_below_threshold", c.below_threshold),
        ("slices_over_cap", c.over_cap),
        ("hits_no_thread_state", k.no_thread_state),
        ("hits_no_frame", k.no_frame),
        ("hits_no_code", k.no_code),
        ("symbol_records_lost", k.symbol_records_dropped),
    ] {
        event.debug_annotations.push(int(name, value));
    }
    let mut packet = TracePacket::default();
    packet.set_track_event(event);
    packet.set_timestamp(trace.start_ts);
    packet.set_trusted_packet_sequence_id(SEQUENCE);
    writer.write_packet(&packet)
}

/// A slice's arguments, named as task stacks name a frame's: `language`,
/// `file` (the full path, as far as the probe read it) and `line` (the
/// function's first line), then `end`, how the slice ended.
fn annotations(trace: &Trace, slice: &Slice) -> Vec<DebugAnnotation> {
    let text = |name: &str, value: String| {
        let mut ann = DebugAnnotation::default();
        ann.set_name(name.to_string());
        ann.set_string_value(value);
        ann
    };
    let mut out = vec![text("language", "python".to_string())];
    if let Some(file) = trace.source_file(slice.symbol_id) {
        out.push(text("file", file));
    }
    if slice.first_line != 0 {
        let mut line = DebugAnnotation::default();
        line.set_name("line".to_string());
        line.set_int_value(i64::from(slice.first_line));
        out.push(line);
    }
    out.push(text("end", slice.end_kind.as_str().to_string()));
    out
}

/// By thread, then outermost first: a slice before the slices it contains.
fn sorted(slices: &[Slice]) -> Vec<&Slice> {
    let mut sorted: Vec<&Slice> = slices.iter().collect();
    sorted.sort_by_key(|s| (s.tgid, s.tid, s.start, s.depth));
    sorted
}

/// A Perfetto trace: a track per process and thread, and each slice as a
/// begin/end pair on its thread's track. Open it at ui.perfetto.dev.
pub fn write_perfetto(trace: &Trace, path: &Path) -> Result<()> {
    let file = std::fs::File::create(path).with_context(|| format!("create {}", path.display()))?;
    let mut buffered = BufWriter::new(file);
    {
        let mut writer = StreamingTraceWriter::new(&mut buffered);
        write_packets(trace, &mut writer)?;
        writer.flush()?;
    }
    buffered.flush()?;
    Ok(())
}

const SEQUENCE: u32 = 1;

fn write_packets(trace: &Trace, writer: &mut dyn TraceWriter) -> Result<()> {
    // Track ids: processes and threads, out of the way of pids.
    let process_uuid = |pid: u32| 0x5059_0000_0000_0000u64 | pid as u64;
    let thread_uuid = |tid: u32| 0x5054_0000_0000_0000u64 | tid as u64;
    // A process's main thread is its process track, as in systing's traces.
    let track_of = |pid: u32, tid: u32| {
        if pid == tid {
            process_uuid(pid)
        } else {
            thread_uuid(tid)
        }
    };

    let mut by_thread: BTreeMap<(u32, u32), Vec<&Slice>> = BTreeMap::new();
    for slice in sorted(&trace.slices) {
        by_thread
            .entry((slice.tgid, slice.tid))
            .or_default()
            .push(slice);
    }

    let mut described = std::collections::HashSet::new();
    for (pid, tid) in by_thread.keys() {
        if described.insert(*pid) {
            let mut process = ProcessDescriptor::default();
            process.set_pid(*pid as i32);
            if let Some(name) = trace.processes.get(pid).filter(|n| !n.is_empty()) {
                process.set_process_name(name.clone());
            }
            let mut desc = TrackDescriptor::default();
            desc.set_uuid(process_uuid(*pid));
            desc.process = Some(process).into();
            let mut packet = TracePacket::default();
            packet.set_track_descriptor(desc);
            packet.set_trusted_packet_sequence_id(SEQUENCE);
            writer.write_packet(&packet)?;
        }
        if pid == tid {
            continue;
        }
        let mut thread = ThreadDescriptor::default();
        thread.set_pid(*pid as i32);
        thread.set_tid(*tid as i32);
        // A thread gone before its name was read goes by its process's.
        let name = trace
            .threads
            .get(tid)
            .filter(|n| !n.is_empty())
            .or_else(|| trace.processes.get(pid).filter(|n| !n.is_empty()));
        if let Some(name) = name {
            thread.set_thread_name(name.clone());
        }
        let mut desc = TrackDescriptor::default();
        desc.set_uuid(thread_uuid(*tid));
        desc.set_parent_uuid(process_uuid(*pid));
        desc.thread = Some(thread).into();
        let mut packet = TracePacket::default();
        packet.set_track_descriptor(desc);
        packet.set_trusted_packet_sequence_id(SEQUENCE);
        writer.write_packet(&packet)?;
    }

    write_trace_info(trace, writer)?;

    // Names are interned: a function called a million times is named once.
    // A slice is named after the function alone, as task stacks name theirs;
    // where it is from, and how it ended, go in its arguments.
    let mut name_ids: HashMap<u64, u64> = HashMap::new();
    let mut first_packet = true;
    let mut emit =
        |writer: &mut dyn TraceWriter, ts: u64, track: u64, begin: Option<&Slice>| -> Result<()> {
            let mut event = TrackEvent::default();
            event.set_track_uuid(track);
            let mut packet = TracePacket::default();
            match begin {
                Some(slice) => {
                    event.set_type(Type::TYPE_SLICE_BEGIN);
                    let next = name_ids.len() as u64 + 1;
                    let iid = *name_ids.entry(slice.symbol_id).or_insert(next);
                    if iid == next {
                        let mut name = EventName::default();
                        name.set_iid(iid);
                        name.set_name(trace.function(slice.symbol_id));
                        let mut interned = InternedData::default();
                        interned.event_names.push(name);
                        packet.interned_data = Some(interned).into();
                    }
                    event.set_name_iid(iid);
                    event.categories.push("python".to_string());
                    event.debug_annotations = annotations(trace, slice);
                }
                None => event.set_type(Type::TYPE_SLICE_END),
            }
            packet.set_track_event(event);
            packet.set_timestamp(ts);
            packet.set_trusted_packet_sequence_id(SEQUENCE);
            let mut flags = SequenceFlags::SEQ_NEEDS_INCREMENTAL_STATE as u32;
            if first_packet {
                flags |= SequenceFlags::SEQ_INCREMENTAL_STATE_CLEARED as u32;
                first_packet = false;
            }
            packet.set_sequence_flags(flags);
            writer.write_packet(&packet)
        };

    for ((pid, tid), slices) in &by_thread {
        let track = track_of(*pid, *tid);
        // Outermost first, so a stack of the slices begun and not yet ended
        // says which ends are due before each begin.
        let mut open: Vec<&Slice> = Vec::new();
        for &slice in slices {
            while open.last().is_some_and(|top| top.depth >= slice.depth) {
                let top = open.pop().unwrap();
                emit(writer, top.end, track, None)?;
            }
            emit(writer, slice.start, track, Some(slice))?;
            open.push(slice);
        }
        while let Some(top) = open.pop() {
            emit(writer, top.end, track, None)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::pairing::{Counters, End};
    use super::super::{KernelCounters, Symbol};
    use super::*;
    use crate::perfetto::VecTraceWriter;

    fn slice(symbol_id: u64, start: u64, end: u64, depth: u32) -> Slice {
        Slice {
            tgid: 10,
            tid: 11,
            start,
            end,
            symbol_id,
            first_line: 3,
            depth,
            end_kind: End::Return,
        }
    }

    fn trace(slices: Vec<Slice>) -> Trace {
        let mut symbols = HashMap::new();
        for (id, name) in [(1, "app:outer"), (2, "app:inner")] {
            symbols.insert(
                id,
                Symbol {
                    name: name.to_string(),
                    file: "/srv/app.py".to_string(),
                },
            );
        }
        Trace {
            ended: super::super::Ended::Duration,
            warnings: vec!["process 10: greenlet is loaded".to_string()],
            slices,
            stats: HashMap::new(),
            counters: Counters::default(),
            kernel: KernelCounters::default(),
            symbols,
            threads: HashMap::from([(11, "worker".to_string())]),
            processes: HashMap::from([(10, "python3".to_string())]),
            attached: Vec::new(),
            start_ts: 0,
            end_ts: 100,
        }
    }

    /// (timestamp, B/E, name id) of every track event, in file order.
    fn events(writer: &VecTraceWriter) -> Vec<(u64, char, u64)> {
        writer
            .packets
            .iter()
            .filter(|p| p.has_track_event() && p.track_event().type_() != Type::TYPE_INSTANT)
            .map(|p| {
                let e = p.track_event();
                let phase = if e.type_() == Type::TYPE_SLICE_BEGIN {
                    'B'
                } else {
                    'E'
                };
                (p.timestamp(), phase, e.name_iid())
            })
            .collect()
    }

    #[test]
    fn slices_are_written_as_nested_begin_end_pairs_with_each_name_once() {
        // As the pairer leaves them: in the order they closed.
        let t = trace(vec![
            slice(2, 20, 30, 1),
            slice(2, 40, 40, 1),
            slice(1, 10, 50, 0),
            slice(1, 60, 70, 0),
        ]);
        let mut writer = VecTraceWriter::new();
        write_packets(&t, &mut writer).unwrap();
        assert_eq!(
            events(&writer),
            [
                (10, 'B', 1),
                (20, 'B', 2),
                (30, 'E', 0),
                (40, 'B', 2),
                (40, 'E', 0),
                (50, 'E', 0),
                (60, 'B', 1),
                (70, 'E', 0)
            ]
        );
        let names: Vec<String> = writer
            .packets
            .iter()
            .flat_map(|p| p.interned_data.event_names.iter())
            .map(|n| n.name().to_string())
            .collect();
        assert_eq!(names, ["app:outer", "app:inner"]);
        // Where a slice is from is in its arguments, as for task stacks.
        let args: Vec<(String, String)> = writer
            .packets
            .iter()
            .filter(|p| p.has_track_event())
            .find(|p| p.track_event().type_() == Type::TYPE_SLICE_BEGIN)
            .unwrap()
            .track_event()
            .debug_annotations
            .iter()
            .map(|a| {
                let value = if a.has_int_value() {
                    a.int_value().to_string()
                } else {
                    a.string_value().to_string()
                };
                (a.name().to_string(), value)
            })
            .collect();
        let args: Vec<(&str, &str)> = args.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect();
        assert_eq!(
            args,
            [
                ("language", "python"),
                ("file", "/srv/app.py"),
                ("line", "3"),
                ("end", "return")
            ]
        );
        // One process track, one thread track under it, and the trace's own.
        let tracks: Vec<_> = writer
            .packets
            .iter()
            .filter(|p| p.has_track_descriptor())
            .collect();
        assert_eq!(tracks.len(), 3);
        assert_eq!(tracks[1].track_descriptor().thread.thread_name(), "worker");
        assert_eq!(tracks[2].track_descriptor().name(), "python-function-trace");
        // How the trace ended and what it lost travel in the file.
        let info = writer
            .packets
            .iter()
            .find(|p| p.has_track_event() && p.track_event().type_() == Type::TYPE_INSTANT)
            .unwrap();
        let names: Vec<&str> = info
            .track_event()
            .debug_annotations
            .iter()
            .map(|a| a.name())
            .collect();
        assert!(names.contains(&"ended") && names.contains(&"events_lost_full_ring"));
    }

    #[test]
    fn the_table_lists_a_slice_before_the_slices_it_contains() {
        let t = trace(vec![slice(2, 20, 30, 1), slice(1, 10, 50, 0)]);
        let dir = std::env::temp_dir().join(format!("pyft-tsv-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("slices.tsv");
        write_tsv(&t, &path).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines[0],
            "pid\ttid\tstart_ns\tdur_ns\tdepth\tend\tfunction\tfile\tline"
        );
        assert_eq!(
            lines[1],
            "10\t11\t10\t40\t0\treturn\tapp:outer\t/srv/app.py\t3"
        );
        assert_eq!(
            lines[2],
            "10\t11\t20\t10\t1\treturn\tapp:inner\t/srv/app.py\t3"
        );
    }
}
