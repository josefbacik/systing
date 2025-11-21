//! SQLite to Perfetto conversion implementation
//!
//! This module converts SQLite database traces back to Perfetto protobuf format.
//! The conversion reads data from the relational SQLite schema and generates
//! appropriate Perfetto TracePacket protobufs.

use anyhow::{Context, Result};
use perfetto_protos::builtin_clock::BuiltinClock;
use perfetto_protos::clock_snapshot::clock_snapshot::Clock;
use perfetto_protos::clock_snapshot::ClockSnapshot;
use perfetto_protos::counter_descriptor::counter_descriptor::Unit;
use perfetto_protos::counter_descriptor::CounterDescriptor;
use perfetto_protos::ftrace_event_bundle::ftrace_event_bundle::CompactSched;
use perfetto_protos::ftrace_event_bundle::FtraceEventBundle;
use perfetto_protos::interned_data::InternedData;
use perfetto_protos::process_descriptor::ProcessDescriptor;
use perfetto_protos::thread_descriptor::ThreadDescriptor;
use perfetto_protos::trace::Trace;
use perfetto_protos::trace_packet::trace_packet::Data;
use perfetto_protos::trace_packet::trace_packet::SequenceFlags;
use perfetto_protos::trace_packet::TracePacket;
use perfetto_protos::track_descriptor::TrackDescriptor;
use perfetto_protos::track_event::track_event::Type;
use perfetto_protos::track_event::TrackEvent;
use protobuf::Message;
use rusqlite::Connection;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::sync::atomic::{AtomicU32, Ordering};

/// Convert a SQLite database trace to Perfetto protobuf format
///
/// This function reads trace data from a SQLite database and generates
/// a Perfetto protobuf trace file.
///
/// # Arguments
///
/// * `input_path` - Path to the input SQLite database file (.db)
/// * `output_path` - Path to the output Perfetto trace file (.pb)
///
/// # Returns
///
/// Returns `Ok(())` on success, or an error if the conversion fails.
///
/// # Current Implementation
///
/// This basic implementation extracts:
/// - Metadata (stored as trace comment)
/// - Clock snapshots for timestamp synchronization
/// - Process and thread descriptors
///
/// Future enhancements will add support for:
/// - Scheduler events
/// - Stack traces
/// - Performance counter data
/// - Network events
/// - Custom probe events
pub fn convert_sqlite_to_perfetto(input_path: &str, output_path: &str) -> Result<()> {
    // Open SQLite database
    let conn = Connection::open(input_path)
        .with_context(|| format!("Failed to open SQLite database: {input_path}"))?;

    // Create trace with packets
    let mut trace = Trace::default();

    // Sequence ID counter for packets
    let sequence_counter = AtomicU32::new(1);

    println!("Reading metadata from SQLite database...");

    // Generate TracePackets in order:
    // 1. Clock snapshots (must come early for timestamp reference)
    add_clock_packets(&conn, &mut trace, &sequence_counter)?;

    // 2. Process descriptors (wrapped in TrackDescriptors)
    add_process_packets(&conn, &mut trace, &sequence_counter)?;

    // 3. Thread descriptors (wrapped in TrackDescriptors)
    add_thread_packets(&conn, &mut trace, &sequence_counter)?;

    // 4. Scheduler events (the actual trace events!)
    add_scheduler_event_packets(&conn, &mut trace, &sequence_counter)?;

    // 5. Counter tracks and values (runqueue size, latency, etc.)
    add_counter_packets(&conn, &mut trace, &sequence_counter)?;

    // 6. Stack traces and perf samples
    add_stack_trace_packets(&conn, &mut trace, &sequence_counter)?;

    // 7. Network events
    add_network_event_packets(&conn, &mut trace, &sequence_counter)?;

    println!(
        "Generated {} trace packets from SQLite database",
        trace.packet.len()
    );

    // Write to file
    let mut file = File::create(output_path)
        .with_context(|| format!("Failed to create output file: {output_path}"))?;
    trace
        .write_to_writer(&mut file)
        .context("Failed to write Perfetto trace")?;

    println!("Conversion complete: {input_path} -> {output_path}");
    Ok(())
}

/// Read clock snapshots from SQLite and generate ClockSnapshot packets
///
/// Clock snapshots provide timestamp synchronization information across
/// different clock sources (monotonic, boottime, realtime, etc.).
fn add_clock_packets(
    conn: &Connection,
    trace: &mut Trace,
    sequence_counter: &AtomicU32,
) -> Result<()> {
    // Query for distinct snapshot IDs
    let mut stmt = conn
        .prepare("SELECT DISTINCT snapshot_id FROM clocks ORDER BY snapshot_id")
        .context("Failed to prepare clock snapshot query")?;

    let snapshot_ids: Vec<i64> = stmt
        .query_map([], |row| row.get(0))
        .context("Failed to query snapshot IDs")?
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to collect snapshot IDs")?;

    for snapshot_id in snapshot_ids {
        // Query all clocks for this snapshot
        let mut clock_stmt = conn
            .prepare("SELECT clock_type, timestamp FROM clocks WHERE snapshot_id = ?1")
            .context("Failed to prepare clock query")?;

        // Use a HashSet to track which clock IDs we've already added to avoid duplicates
        let mut seen_clock_ids = HashSet::new();
        let mut clocks = Vec::new();

        let clock_rows: Vec<_> = clock_stmt
            .query_map([snapshot_id], |row| {
                let clock_type: String = row.get(0)?;
                let timestamp: u64 = row.get(1)?;
                Ok((clock_type, timestamp))
            })
            .context("Failed to query clocks")?
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to collect clock rows")?;

        for (clock_type, timestamp) in clock_rows {
            // Map clock type string to clock ID
            // Database stores actual clock names like "BOOTTIME", "MONOTONIC", etc.
            let clock_id = match clock_type.as_str() {
                "UNKNOWN" => BuiltinClock::BUILTIN_CLOCK_UNKNOWN as u32, // 0
                "REALTIME" => BuiltinClock::BUILTIN_CLOCK_REALTIME as u32, // 1
                "REALTIME_COARSE" => BuiltinClock::BUILTIN_CLOCK_REALTIME_COARSE as u32, // 2
                "MONOTONIC" => BuiltinClock::BUILTIN_CLOCK_MONOTONIC as u32, // 3
                "MONOTONIC_COARSE" => BuiltinClock::BUILTIN_CLOCK_MONOTONIC_COARSE as u32, // 4
                "MONOTONIC_RAW" => BuiltinClock::BUILTIN_CLOCK_MONOTONIC_RAW as u32, // 5
                "BOOTTIME" => BuiltinClock::BUILTIN_CLOCK_BOOTTIME as u32, // 6
                "TSC" => BuiltinClock::BUILTIN_CLOCK_TSC as u32,         // 9
                "PERF" => BuiltinClock::BUILTIN_CLOCK_PERF as u32,       // 10
                _ => {
                    eprintln!("Warning: Unknown clock type '{clock_type}', skipping");
                    continue; // Skip unknown clock types
                }
            };

            // Skip duplicate clock IDs within the same snapshot
            if seen_clock_ids.contains(&clock_id) {
                continue;
            }
            seen_clock_ids.insert(clock_id);

            let mut clock = Clock::new();
            clock.set_clock_id(clock_id);
            clock.set_timestamp(timestamp);
            clocks.push(clock);
        }

        if !clocks.is_empty() {
            let mut clock_snapshot = ClockSnapshot::new();
            clock_snapshot.clocks = clocks;
            clock_snapshot.set_primary_trace_clock(BuiltinClock::BUILTIN_CLOCK_BOOTTIME);

            let mut packet = TracePacket::new();
            packet.set_trusted_packet_sequence_id(sequence_counter.fetch_add(1, Ordering::Relaxed));
            packet.data = Some(Data::ClockSnapshot(clock_snapshot));
            trace.packet.push(packet);
        }
    }

    if trace.packet.is_empty() {
        println!("Warning: No clock snapshots found in database");
    }

    Ok(())
}

/// Read processes from SQLite and generate ProcessDescriptor packets
///
/// Process descriptors provide information about processes in the trace,
/// including PID, name, and command line. They are wrapped in TrackDescriptors.
fn add_process_packets(
    conn: &Connection,
    trace: &mut Trace,
    sequence_counter: &AtomicU32,
) -> Result<()> {
    let mut stmt = conn
        .prepare("SELECT pid, name, cmdline FROM processes ORDER BY pid")
        .context("Failed to prepare process query")?;

    let mut process_count = 0;
    let mut uuid_counter = 1000u64; // Start with a base UUID for processes

    let rows = stmt
        .query_map([], |row| {
            let pid: i32 = row.get(0)?;
            let name: String = row.get(1)?;
            let cmdline_json: String = row.get(2)?;

            Ok((pid, name, cmdline_json))
        })
        .context("Failed to query processes")?;

    for row_result in rows {
        let (pid, name, cmdline_json) = row_result.context("Failed to read process row")?;

        let mut process_desc = ProcessDescriptor::new();
        process_desc.set_pid(pid);
        process_desc.set_process_name(name);

        // Parse cmdline JSON array
        if let Ok(cmdline_array) = serde_json::from_str::<Vec<String>>(&cmdline_json) {
            process_desc.cmdline = cmdline_array;
        }

        // Wrap in TrackDescriptor
        let mut track_desc = TrackDescriptor::new();
        track_desc.set_uuid(uuid_counter);
        track_desc.process = Some(process_desc).into();
        uuid_counter += 1;

        let mut packet = TracePacket::new();
        packet.set_trusted_packet_sequence_id(sequence_counter.fetch_add(1, Ordering::Relaxed));
        packet.data = Some(Data::TrackDescriptor(track_desc));
        trace.packet.push(packet);
        process_count += 1;
    }

    println!("Extracted {process_count} process descriptors");
    Ok(())
}

/// Read threads from SQLite and generate ThreadDescriptor packets
///
/// Thread descriptors provide information about threads in the trace,
/// including TID, PID (parent process), and thread name. They are wrapped in TrackDescriptors.
fn add_thread_packets(
    conn: &Connection,
    trace: &mut Trace,
    sequence_counter: &AtomicU32,
) -> Result<()> {
    let mut stmt = conn
        .prepare("SELECT tid, pid, name FROM threads ORDER BY tid")
        .context("Failed to prepare thread query")?;

    let mut thread_count = 0;
    let mut uuid_counter = 10000u64; // Start with a different base UUID for threads

    let rows = stmt
        .query_map([], |row| {
            let tid: i32 = row.get(0)?;
            let pid: i32 = row.get(1)?;
            let name: String = row.get(2)?;

            Ok((tid, pid, name))
        })
        .context("Failed to query threads")?;

    for row_result in rows {
        let (tid, pid, name) = row_result.context("Failed to read thread row")?;

        let mut thread_desc = ThreadDescriptor::new();
        thread_desc.set_tid(tid);
        thread_desc.set_pid(pid);
        thread_desc.set_thread_name(name);

        // Wrap in TrackDescriptor
        let mut track_desc = TrackDescriptor::new();
        track_desc.set_uuid(uuid_counter);
        track_desc.thread = Some(thread_desc).into();
        uuid_counter += 1;

        let mut packet = TracePacket::new();
        packet.set_trusted_packet_sequence_id(sequence_counter.fetch_add(1, Ordering::Relaxed));
        packet.data = Some(Data::TrackDescriptor(track_desc));
        trace.packet.push(packet);
        thread_count += 1;
    }

    println!("Extracted {thread_count} thread descriptors");
    Ok(())
}

/// Read scheduler events from SQLite and generate FtraceEventBundle packets
///
/// Scheduler events (SCHED_SWITCH and SCHED_WAKING) provide information about
/// context switches and thread wakeups. These are converted to CompactSched
/// format for efficient representation in Perfetto.
fn add_scheduler_event_packets(
    conn: &Connection,
    trace: &mut Trace,
    sequence_counter: &AtomicU32,
) -> Result<()> {
    // Query all scheduler events grouped by CPU
    let mut stmt = conn
        .prepare(
            "SELECT ts, cpu, event_type, prev_pid, prev_state, prev_prio, next_pid, next_prio
             FROM sched_events
             ORDER BY cpu, ts",
        )
        .context("Failed to prepare scheduler events query")?;

    // Structure to hold events per CPU
    struct CpuEvents {
        switch_timestamps: Vec<u64>,
        switch_prev_states: Vec<i64>,
        switch_next_pids: Vec<i32>,
        switch_next_prios: Vec<i32>,
        switch_next_comms: Vec<String>,
        waking_timestamps: Vec<u64>,
        waking_pids: Vec<i32>,
        waking_target_cpus: Vec<i32>,
        waking_prios: Vec<i32>,
        waking_comms: Vec<String>,
        // Individual ftrace events (not in CompactSched)
        other_events: Vec<(u64, String, i32, i32, String)>, // (ts, event_type, pid, prio, comm)
    }

    let mut cpu_events_map: HashMap<u32, CpuEvents> = HashMap::new();

    // Also prepare a query to get thread names for PIDs
    let mut thread_name_stmt = conn
        .prepare("SELECT name FROM threads WHERE tid = ?1")
        .context("Failed to prepare thread name query")?;

    let rows = stmt
        .query_map([], |row| {
            let ts: u64 = row.get(0)?;
            let cpu: u32 = row.get(1)?;
            let event_type: String = row.get(2)?;
            let prev_pid: Option<i32> = row.get(3)?;
            let prev_state: Option<i32> = row.get(4)?;
            let prev_prio: Option<i32> = row.get(5)?;
            let next_pid: Option<i32> = row.get(6)?;
            let next_prio: Option<i32> = row.get(7)?;

            Ok((
                ts, cpu, event_type, prev_pid, prev_state, prev_prio, next_pid, next_prio,
            ))
        })
        .context("Failed to query scheduler events")?;

    let mut event_count = 0;

    for row_result in rows {
        let (ts, cpu, event_type, _prev_pid, prev_state, _prev_prio, next_pid, next_prio) =
            row_result.context("Failed to read scheduler event row")?;

        let cpu_events = cpu_events_map.entry(cpu).or_insert_with(|| CpuEvents {
            switch_timestamps: Vec::new(),
            switch_prev_states: Vec::new(),
            switch_next_pids: Vec::new(),
            switch_next_prios: Vec::new(),
            switch_next_comms: Vec::new(),
            waking_timestamps: Vec::new(),
            waking_pids: Vec::new(),
            waking_target_cpus: Vec::new(),
            waking_prios: Vec::new(),
            waking_comms: Vec::new(),
            other_events: Vec::new(),
        });

        match event_type.as_str() {
            "switch" => {
                if let Some(pid) = next_pid {
                    cpu_events.switch_timestamps.push(ts);
                    cpu_events
                        .switch_prev_states
                        .push(prev_state.unwrap_or(0) as i64);
                    cpu_events.switch_next_pids.push(pid);
                    cpu_events.switch_next_prios.push(next_prio.unwrap_or(0));

                    // Get thread name for next_pid
                    let thread_name: String = thread_name_stmt
                        .query_row([pid], |row| row.get(0))
                        .unwrap_or_else(|_| format!("pid-{pid}"));
                    cpu_events.switch_next_comms.push(thread_name);
                }
            }
            "waking" => {
                if let Some(pid) = next_pid {
                    cpu_events.waking_timestamps.push(ts);
                    cpu_events.waking_pids.push(pid);
                    // Target CPU is the CPU where the waking event happened
                    cpu_events.waking_target_cpus.push(cpu as i32);
                    cpu_events.waking_prios.push(next_prio.unwrap_or(0));

                    // Get thread name for waking pid
                    let thread_name: String = thread_name_stmt
                        .query_row([pid], |row| row.get(0))
                        .unwrap_or_else(|_| format!("pid-{pid}"));
                    cpu_events.waking_comms.push(thread_name);
                }
            }
            "wakeup" | "wakeup_new" | "exit" => {
                // These event types are not supported in CompactSched format,
                // but can be represented as individual FtraceEvent messages
                if let Some(pid) = next_pid {
                    let thread_name: String = thread_name_stmt
                        .query_row([pid], |row| row.get(0))
                        .unwrap_or_else(|_| format!("pid-{pid}"));
                    cpu_events.other_events.push((
                        ts,
                        event_type.clone(),
                        pid,
                        next_prio.unwrap_or(0),
                        thread_name,
                    ));
                }
            }
            _ => {
                eprintln!("Warning: Unknown scheduler event type '{event_type}'");
            }
        }
        event_count += 1;
    }

    // Generate FtraceEventBundle packets for each CPU
    for (cpu, events) in cpu_events_map {
        if events.switch_timestamps.is_empty()
            && events.waking_timestamps.is_empty()
            && events.other_events.is_empty()
        {
            continue;
        }

        // Build intern table for unique strings (thread names)
        let mut intern_table = Vec::new();
        let mut intern_map = HashMap::new();

        // Helper to intern a string
        let mut intern_string = |s: &str| -> u32 {
            if let Some(&idx) = intern_map.get(s) {
                idx
            } else {
                let idx = intern_table.len() as u32;
                intern_table.push(s.to_string());
                intern_map.insert(s.to_string(), idx);
                idx
            }
        };

        // Create CompactSched message
        let mut compact_sched = CompactSched::new();

        // Convert switch events to delta-encoded format
        if !events.switch_timestamps.is_empty() {
            let mut delta_timestamps = Vec::new();
            let mut prev_ts = 0u64;
            for &ts in &events.switch_timestamps {
                delta_timestamps.push(ts - prev_ts);
                prev_ts = ts;
            }
            compact_sched.switch_timestamp = delta_timestamps;
            compact_sched.switch_prev_state = events.switch_prev_states;
            compact_sched.switch_next_pid = events.switch_next_pids;
            compact_sched.switch_next_prio = events.switch_next_prios;

            // Intern thread names and build comm index array
            let mut comm_indices = Vec::new();
            for comm in &events.switch_next_comms {
                comm_indices.push(intern_string(comm));
            }
            compact_sched.switch_next_comm_index = comm_indices;
        }

        // Convert waking events to delta-encoded format
        if !events.waking_timestamps.is_empty() {
            let mut delta_timestamps = Vec::new();
            let mut prev_ts = 0u64;
            for &ts in &events.waking_timestamps {
                delta_timestamps.push(ts - prev_ts);
                prev_ts = ts;
            }
            compact_sched.waking_timestamp = delta_timestamps;
            compact_sched.waking_pid = events.waking_pids;
            compact_sched.waking_target_cpu = events.waking_target_cpus;
            compact_sched.waking_prio = events.waking_prios;

            // Intern thread names and build comm index array
            let mut comm_indices = Vec::new();
            for comm in &events.waking_comms {
                comm_indices.push(intern_string(comm));
            }
            compact_sched.waking_comm_index = comm_indices;
        }

        // Set the intern table
        compact_sched.intern_table = intern_table;

        // Create FtraceEventBundle
        let mut event_bundle = FtraceEventBundle::default();
        event_bundle.set_cpu(cpu);
        event_bundle.compact_sched = Some(compact_sched).into();

        // Add individual ftrace events for wakeup, wakeup_new, and exit
        for (ts, event_type, pid, prio, comm) in &events.other_events {
            use perfetto_protos::ftrace_event::ftrace_event::Event;
            use perfetto_protos::ftrace_event::FtraceEvent;
            use perfetto_protos::sched::SchedProcessExitFtraceEvent;
            use perfetto_protos::sched::SchedWakeupFtraceEvent;
            use perfetto_protos::sched::SchedWakeupNewFtraceEvent;

            let mut ftrace_event = FtraceEvent::new();
            ftrace_event.set_timestamp(*ts);
            ftrace_event.set_pid(*pid as u32);

            match event_type.as_str() {
                "wakeup" => {
                    let mut wakeup = SchedWakeupFtraceEvent::new();
                    wakeup.set_comm(comm.clone());
                    wakeup.set_pid(*pid);
                    wakeup.set_prio(*prio);
                    wakeup.set_target_cpu(cpu as i32);
                    ftrace_event.event = Some(Event::SchedWakeup(wakeup));
                }
                "wakeup_new" => {
                    let mut wakeup_new = SchedWakeupNewFtraceEvent::new();
                    wakeup_new.set_comm(comm.clone());
                    wakeup_new.set_pid(*pid);
                    wakeup_new.set_prio(*prio);
                    wakeup_new.set_target_cpu(cpu as i32);
                    ftrace_event.event = Some(Event::SchedWakeupNew(wakeup_new));
                }
                "exit" => {
                    let mut exit = SchedProcessExitFtraceEvent::new();
                    exit.set_comm(comm.clone());
                    exit.set_pid(*pid);
                    ftrace_event.event = Some(Event::SchedProcessExit(exit));
                }
                _ => {} // Should not happen due to earlier match
            }

            event_bundle.event.push(ftrace_event);
        }

        // Create TracePacket
        let mut packet = TracePacket::new();
        packet.set_trusted_packet_sequence_id(sequence_counter.fetch_add(1, Ordering::Relaxed));
        packet.data = Some(Data::FtraceEvents(event_bundle));
        trace.packet.push(packet);
    }

    println!("Extracted {event_count} scheduler events");
    Ok(())
}

/// Read counter tracks and values from SQLite and generate TrackDescriptor and TrackEvent packets
///
/// This includes counter tracks for runqueue size, CPU latency, process wake latency,
/// and any other performance counters stored in the database.
fn add_counter_packets(
    conn: &Connection,
    trace: &mut Trace,
    sequence_counter: &AtomicU32,
) -> Result<()> {
    // First, query for counter tracks
    let mut track_stmt = conn
        .prepare(
            "SELECT DISTINCT t.uuid, t.name, t.cpu, t.pid, t.tid, p.unit
             FROM tracks t
             LEFT JOIN perf_counters p ON t.uuid = p.track_uuid
             WHERE t.track_type = 'counter'
             ORDER BY t.uuid",
        )
        .context("Failed to prepare counter track query")?;

    struct CounterTrack {
        uuid: u64,
        name: String,
        cpu: Option<u32>,
        pid: Option<i32>,
        tid: Option<i32>,
        unit: String,
    }

    let tracks: Vec<CounterTrack> = track_stmt
        .query_map([], |row| {
            Ok(CounterTrack {
                uuid: row.get::<_, i64>(0)? as u64,
                name: row.get(1)?,
                cpu: row.get::<_, Option<i32>>(2)?.map(|c| c as u32),
                pid: row.get(3)?,
                tid: row.get(4)?,
                unit: row.get(5).unwrap_or_else(|_| "count".to_string()),
            })
        })
        .context("Failed to query counter tracks")?
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to collect counter tracks")?;

    let mut counter_count = 0;

    // Generate TrackDescriptor packets for each counter track
    for track in &tracks {
        let mut counter_desc = CounterDescriptor::new();
        counter_desc.set_is_incremental(false);

        // Map unit string to enum
        let unit = match track.unit.as_str() {
            "ns" | "time_ns" => Unit::UNIT_TIME_NS,
            "count" => Unit::UNIT_COUNT,
            _ => Unit::UNIT_COUNT,
            // Note: UNIT_TIME_MS and UNIT_BYTES don't exist in this version
            // We'll map everything else to UNIT_COUNT
        };
        counter_desc.set_unit(unit);

        let mut track_desc = TrackDescriptor::new();
        track_desc.set_uuid(track.uuid);
        track_desc.set_name(track.name.clone());
        track_desc.counter = Some(counter_desc).into();

        // Set parent UUID based on what's available
        if let Some(tid) = track.tid {
            // Thread-scoped counter
            track_desc.set_parent_uuid((tid as u64) + 10000); // Match thread UUID scheme
        } else if let Some(pid) = track.pid {
            // Process-scoped counter
            track_desc.set_parent_uuid((pid as u64) + 1000); // Match process UUID scheme
        } else if let Some(cpu) = track.cpu {
            // CPU-scoped counter (no parent, but we could set cpu field if needed)
            // For now, include CPU in the name
            if !track.name.contains("cpu") {
                track_desc.set_name(format!("{}_cpu{}", track.name, cpu));
            }
        }

        let mut packet = TracePacket::new();
        packet.set_trusted_packet_sequence_id(sequence_counter.fetch_add(1, Ordering::Relaxed));
        packet.data = Some(Data::TrackDescriptor(track_desc));
        trace.packet.push(packet);
        counter_count += 1;
    }

    // Now query for counter values
    let mut value_stmt = conn
        .prepare(
            "SELECT pc.track_uuid, pcv.ts, pcv.value
             FROM perf_counter_values pcv
             JOIN perf_counters pc ON pcv.counter_id = pc.id
             WHERE pc.track_uuid IN (
                 SELECT uuid FROM tracks WHERE track_type = 'counter'
             )
             ORDER BY pc.track_uuid, pcv.ts",
        )
        .context("Failed to prepare counter value query")?;

    // Group values by track UUID
    let mut values_by_track: HashMap<u64, Vec<(u64, i64)>> = HashMap::new();

    let value_rows = value_stmt
        .query_map([], |row| {
            let track_uuid: i64 = row.get(0)?;
            let ts: i64 = row.get(1)?;
            let value: i64 = row.get(2)?;
            Ok((track_uuid as u64, ts as u64, value))
        })
        .context("Failed to query counter values")?;

    let mut value_count = 0;
    for row_result in value_rows {
        let (track_uuid, ts, value) = row_result.context("Failed to read counter value row")?;
        values_by_track
            .entry(track_uuid)
            .or_default()
            .push((ts, value));
        value_count += 1;
    }

    // Generate TrackEvent packets for counter values
    for (track_uuid, values) in values_by_track {
        for (ts, value) in values {
            let mut track_event = TrackEvent::new();
            track_event.set_timestamp_absolute_us((ts / 1000) as i64); // Convert ns to us
            track_event.set_type(Type::TYPE_COUNTER);
            track_event.set_track_uuid(track_uuid);
            // Set the counter value directly
            track_event.set_counter_value(value);

            let mut packet = TracePacket::new();
            packet.set_trusted_packet_sequence_id(sequence_counter.fetch_add(1, Ordering::Relaxed));
            packet.set_timestamp(ts);
            packet.data = Some(Data::TrackEvent(track_event));
            trace.packet.push(packet);
        }
    }

    if counter_count > 0 {
        println!("Extracted {counter_count} counter tracks with {value_count} values");
    }

    Ok(())
}

/// Read stack traces and perf samples from SQLite and generate InternedData + PerfSample packets
///
/// This creates the interning structure (function_names, frames, callstacks) and
/// PerfSample packets that reference the interned callstacks by IID.
fn add_stack_trace_packets(
    conn: &Connection,
    trace: &mut Trace,
    sequence_counter: &AtomicU32,
) -> Result<()> {
    use perfetto_protos::profile_common::{Callstack, Frame, InternedString};
    use perfetto_protos::profile_packet::PerfSample;
    use std::collections::HashMap;

    // Query symbols from SQLite
    let mut symbol_stmt = conn
        .prepare(
            "SELECT id, function_name, file_name, line_number, build_id, mapping_name, mapping_offset
             FROM symbols ORDER BY id"
        )
        .context("Failed to prepare symbols query")?;

    // Map SQLite symbol IDs to Perfetto function name IIDs
    let mut function_name_map: HashMap<i64, u64> = HashMap::new();
    let mut function_names: Vec<InternedString> = Vec::new();
    let mut next_function_iid = 1u64;

    let symbol_rows = symbol_stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,    // id
                row.get::<_, String>(1)?, // function_name
            ))
        })
        .context("Failed to query symbols")?;

    for result in symbol_rows {
        let (symbol_id, function_name) = result?;

        // Create interned function name
        let mut interned_str = InternedString::default();
        interned_str.set_iid(next_function_iid);
        interned_str.set_str(function_name.as_bytes().to_vec());

        function_names.push(interned_str);
        function_name_map.insert(symbol_id, next_function_iid);
        next_function_iid += 1;
    }

    // Query stack traces
    let mut stack_stmt = conn
        .prepare("SELECT DISTINCT stack_id FROM stack_trace_frames ORDER BY stack_id")
        .context("Failed to prepare stack trace query")?;

    let stack_ids: Vec<i64> = stack_stmt
        .query_map([], |row| row.get(0))
        .context("Failed to query stack IDs")?
        .collect::<Result<Vec<_>, _>>()?;

    let mut frames: Vec<Frame> = Vec::new();
    let mut callstacks: Vec<Callstack> = Vec::new();
    let mut next_frame_iid = 1u64;
    let mut next_callstack_iid = 1u64;
    let mut callstack_map: HashMap<i64, u64> = HashMap::new();

    // For each stack, read its frames and build the interned data
    for stack_id in &stack_ids {
        let mut frame_stmt = conn
            .prepare(
                "SELECT stf.frame_index, stf.stack_type, s.id, s.function_name, s.mapping_offset
                 FROM stack_trace_frames stf
                 JOIN symbols s ON stf.symbol_id = s.id
                 WHERE stf.stack_id = ?1
                 ORDER BY stf.stack_type, stf.frame_index",
            )
            .context("Failed to prepare frame query")?;

        let frame_rows = frame_stmt
            .query_map([stack_id], |row| {
                Ok((
                    row.get::<_, i64>(2)?,         // symbol id
                    row.get::<_, Option<u64>>(4)?, // mapping_offset
                ))
            })
            .context("Failed to query frames")?;

        let mut frame_iids = Vec::new();

        for result in frame_rows {
            let (symbol_id, mapping_offset) = result?;

            // Get the function name IID for this symbol
            if let Some(&function_iid) = function_name_map.get(&symbol_id) {
                // Create a Frame
                let mut frame = Frame::default();
                frame.set_iid(next_frame_iid);
                frame.set_function_name_id(function_iid);

                if let Some(offset) = mapping_offset {
                    frame.set_rel_pc(offset);
                }

                frames.push(frame);
                frame_iids.push(next_frame_iid);
                next_frame_iid += 1;
            }
        }

        // Create callstack from the frames
        if !frame_iids.is_empty() {
            let mut callstack = Callstack::default();
            callstack.set_iid(next_callstack_iid);
            callstack.frame_ids = frame_iids;

            callstacks.push(callstack);
            callstack_map.insert(*stack_id, next_callstack_iid);
            next_callstack_iid += 1;
        }
    }

    // Create InternedData packet with all the interned data
    if !function_names.is_empty() || !frames.is_empty() || !callstacks.is_empty() {
        // Capture lengths before moving data
        let function_count = function_name_map.len();
        let frame_count = frames.len();
        let callstack_count = callstack_map.len();

        let mut interned_packet = TracePacket::new();
        let interned_data = InternedData {
            function_names,
            frames,
            callstacks,
            mappings: Vec::new(),
            ..Default::default()
        };
        interned_packet.interned_data = Some(interned_data).into();
        interned_packet
            .set_trusted_packet_sequence_id(sequence_counter.fetch_add(1, Ordering::Relaxed));
        interned_packet.set_sequence_flags(
            SequenceFlags::SEQ_INCREMENTAL_STATE_CLEARED as u32
                | SequenceFlags::SEQ_NEEDS_INCREMENTAL_STATE as u32,
        );
        trace.packet.push(interned_packet);

        println!(
            "Created interned data: {function_count} functions, {frame_count} frames, {callstack_count} callstacks"
        );
    }

    // Now create PerfSample packets
    let mut sample_stmt = conn
        .prepare("SELECT ts, tid, stack_id FROM perf_samples ORDER BY ts")
        .context("Failed to prepare perf samples query")?;

    let sample_rows = sample_stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, u64>(0)?, // ts
                row.get::<_, i32>(1)?, // tid
                row.get::<_, i64>(2)?, // stack_id
            ))
        })
        .context("Failed to query perf samples")?;

    let mut sample_count = 0;
    for result in sample_rows {
        let (ts, tid, stack_id) = result?;

        if let Some(&callstack_iid) = callstack_map.get(&stack_id) {
            let mut perf_sample = PerfSample::default();
            perf_sample.set_tid(tid as u32);
            perf_sample.set_callstack_iid(callstack_iid);

            let mut packet = TracePacket::new();
            packet.set_trusted_packet_sequence_id(sequence_counter.fetch_add(1, Ordering::Relaxed));
            packet.set_timestamp(ts);
            packet.data = Some(Data::PerfSample(perf_sample));

            trace.packet.push(packet);
            sample_count += 1;
        }
    }

    if sample_count > 0 {
        println!("Converted {sample_count} perf samples with stack traces");
    }

    Ok(())
}

/// Read network events from SQLite and generate TrackDescriptor + TrackEvent packets
///
/// This creates track descriptors for each network connection and generates slice events
/// (begin/end pairs) with debug annotations for the network operations.
fn add_network_event_packets(
    conn: &Connection,
    trace: &mut Trace,
    sequence_counter: &AtomicU32,
) -> Result<()> {
    use perfetto_protos::debug_annotation::DebugAnnotation;
    use perfetto_protos::interned_data::InternedData;
    use perfetto_protos::track_event::EventName;
    use std::collections::HashMap;

    // Query network connections
    let mut conn_stmt = conn
        .prepare(
            "SELECT id, protocol, address_family, dest_addr, dest_port
             FROM network_connections
             ORDER BY id",
        )
        .context("Failed to prepare network connections query")?;

    struct NetworkConn {
        id: u64,
        protocol: String,
        dest_addr: String,
        dest_port: u16,
    }

    let connections: Vec<NetworkConn> = conn_stmt
        .query_map([], |row| {
            Ok(NetworkConn {
                id: row.get::<_, i64>(0)? as u64,
                protocol: row.get(1)?,
                dest_addr: row.get(3)?,
                dest_port: row.get::<_, i64>(4)? as u16,
            })
        })
        .context("Failed to query network connections")?
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to collect network connections")?;

    // Create track descriptors for each connection
    let mut track_uuid_map: HashMap<u64, u64> = HashMap::new();

    for connection in &connections {
        // Generate a unique track UUID for this connection
        let track_uuid = 1000000 + connection.id; // Offset to avoid conflicts

        let mut track_desc = TrackDescriptor::new();
        track_desc.set_uuid(track_uuid);
        track_desc.set_name(format!(
            "{} {}:{}",
            connection.protocol, connection.dest_addr, connection.dest_port
        ));

        let mut packet = TracePacket::new();
        packet.set_trusted_packet_sequence_id(sequence_counter.fetch_add(1, Ordering::Relaxed));
        packet.data = Some(Data::TrackDescriptor(track_desc));
        trace.packet.push(packet);

        track_uuid_map.insert(connection.id, track_uuid);
    }

    // Query network events
    let mut event_stmt = conn
        .prepare(
            "SELECT connection_id, tid, track_uuid, event_type, start_ts, end_ts,
                    bytes, sequence_num, tcp_flags
             FROM network_events
             ORDER BY start_ts",
        )
        .context("Failed to prepare network events query")?;

    // Collect event names for interning
    let mut event_name_set: HashMap<String, u64> = HashMap::new();
    let mut next_event_name_iid = 1u64;

    let event_rows = event_stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)? as u64,                    // connection_id
                row.get::<_, i32>(1)?,                           // tid
                row.get::<_, i64>(2)? as u64,                    // track_uuid
                row.get::<_, String>(3)?,                        // event_type
                row.get::<_, i64>(4)? as u64,                    // start_ts
                row.get::<_, Option<i64>>(5)?.map(|t| t as u64), // end_ts
                row.get::<_, Option<i32>>(6)?,                   // bytes
                row.get::<_, Option<i32>>(7)?,                   // sequence_num
                row.get::<_, Option<u8>>(8)?,                    // tcp_flags
            ))
        })
        .context("Failed to query network events")?;

    let mut events = Vec::new();
    for row_result in event_rows {
        let event = row_result.context("Failed to read network event row")?;

        // Add event name to interning set
        let event_type = &event.3;
        if !event_name_set.contains_key(event_type) {
            event_name_set.insert(event_type.clone(), next_event_name_iid);
            next_event_name_iid += 1;
        }

        events.push(event);
    }

    // Create interned data packet for event names
    if !event_name_set.is_empty() {
        let mut event_names = Vec::new();
        for (name, iid) in &event_name_set {
            let mut event_name = EventName::default();
            event_name.set_iid(*iid);
            event_name.set_name(name.clone());
            event_names.push(event_name);
        }

        let mut interned_packet = TracePacket::new();
        let interned_data = InternedData {
            event_names,
            ..Default::default()
        };
        interned_packet.interned_data = Some(interned_data).into();
        interned_packet
            .set_trusted_packet_sequence_id(sequence_counter.fetch_add(1, Ordering::Relaxed));
        interned_packet.set_sequence_flags(
            SequenceFlags::SEQ_INCREMENTAL_STATE_CLEARED as u32
                | SequenceFlags::SEQ_NEEDS_INCREMENTAL_STATE as u32,
        );
        trace.packet.push(interned_packet);
    }

    // Generate slice events (begin/end pairs)
    let mut event_count = 0;
    for (
        connection_id,
        _tid,
        _orig_track_uuid,
        event_type,
        start_ts,
        end_ts,
        bytes,
        sequence_num,
        tcp_flags,
    ) in events
    {
        // Get the track UUID for this connection
        let track_uuid = track_uuid_map
            .get(&connection_id)
            .copied()
            .unwrap_or(connection_id);
        let event_name_iid = *event_name_set.get(&event_type).unwrap();

        // Create begin event
        let mut begin_event = TrackEvent::new();
        begin_event.set_type(Type::TYPE_SLICE_BEGIN);
        begin_event.set_name_iid(event_name_iid);
        begin_event.set_track_uuid(track_uuid);

        // Add debug annotations
        if let Some(bytes_val) = bytes {
            let mut annotation = DebugAnnotation::default();
            annotation.set_name("length".to_string());
            annotation.set_uint_value(bytes_val as u64);
            begin_event.debug_annotations.push(annotation);
        }

        if let Some(seq) = sequence_num {
            let mut annotation = DebugAnnotation::default();
            annotation.set_name("seq".to_string());
            annotation.set_uint_value(seq as u64);
            begin_event.debug_annotations.push(annotation);
        }

        if let Some(flags) = tcp_flags {
            let mut annotation = DebugAnnotation::default();
            annotation.set_name("flags".to_string());
            annotation.set_string_value(format_tcp_flags(flags));
            begin_event.debug_annotations.push(annotation);
        }

        let mut begin_packet = TracePacket::new();
        begin_packet
            .set_trusted_packet_sequence_id(sequence_counter.fetch_add(1, Ordering::Relaxed));
        begin_packet.set_timestamp(start_ts);
        begin_packet.data = Some(Data::TrackEvent(begin_event));
        trace.packet.push(begin_packet);

        // Create end event if end timestamp exists
        if let Some(end_ts_val) = end_ts {
            let mut end_event = TrackEvent::new();
            end_event.set_type(Type::TYPE_SLICE_END);
            end_event.set_track_uuid(track_uuid);

            let mut end_packet = TracePacket::new();
            end_packet
                .set_trusted_packet_sequence_id(sequence_counter.fetch_add(1, Ordering::Relaxed));
            end_packet.set_timestamp(end_ts_val);
            end_packet.data = Some(Data::TrackEvent(end_event));
            trace.packet.push(end_packet);
        }

        event_count += 1;
    }

    if event_count > 0 {
        println!("Converted {event_count} network events");
    }

    Ok(())
}

/// Format TCP flags as a string like "PSH|ACK"
fn format_tcp_flags(flags: u8) -> String {
    let mut parts = Vec::new();

    if flags & 0x01 != 0 {
        parts.push("FIN");
    }
    if flags & 0x02 != 0 {
        parts.push("SYN");
    }
    if flags & 0x04 != 0 {
        parts.push("RST");
    }
    if flags & 0x08 != 0 {
        parts.push("PSH");
    }
    if flags & 0x10 != 0 {
        parts.push("ACK");
    }
    if flags & 0x20 != 0 {
        parts.push("URG");
    }

    if parts.is_empty() {
        "NONE".to_string()
    } else {
        parts.join("|")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite::schema::create_schema;

    #[test]
    fn test_empty_database() {
        let conn = Connection::open_in_memory().unwrap();
        create_schema(&conn).unwrap();

        let mut trace = Trace::default();
        let sequence_counter = AtomicU32::new(1);
        add_clock_packets(&conn, &mut trace, &sequence_counter).unwrap();
        add_process_packets(&conn, &mut trace, &sequence_counter).unwrap();
        add_thread_packets(&conn, &mut trace, &sequence_counter).unwrap();

        assert_eq!(
            trace.packet.len(),
            0,
            "Empty database should produce no packets"
        );
    }

    #[test]
    fn test_process_conversion() {
        let conn = Connection::open_in_memory().unwrap();
        create_schema(&conn).unwrap();

        // Insert test process
        conn.execute(
            "INSERT INTO processes (pid, name, cmdline) VALUES (123, 'test', '[]')",
            [],
        )
        .unwrap();

        let mut trace = Trace::default();
        let sequence_counter = AtomicU32::new(1);
        add_process_packets(&conn, &mut trace, &sequence_counter).unwrap();

        assert_eq!(trace.packet.len(), 1);
        if let Some(Data::TrackDescriptor(ref td)) = trace.packet[0].data {
            if let Some(ref process_desc) = td.process.0 {
                assert_eq!(process_desc.pid(), 123);
                assert_eq!(process_desc.process_name(), "test");
            } else {
                panic!("TrackDescriptor missing process");
            }
        } else {
            panic!("Expected TrackDescriptor packet");
        }
    }

    #[test]
    fn test_thread_conversion() {
        let conn = Connection::open_in_memory().unwrap();
        create_schema(&conn).unwrap();

        // Insert test process first (required by foreign key)
        conn.execute(
            "INSERT INTO processes (pid, name, cmdline) VALUES (100, 'parent', '[]')",
            [],
        )
        .unwrap();

        // Insert test thread
        conn.execute(
            "INSERT INTO threads (tid, pid, name) VALUES (200, 100, 'worker')",
            [],
        )
        .unwrap();

        let mut trace = Trace::default();
        let sequence_counter = AtomicU32::new(1);
        add_thread_packets(&conn, &mut trace, &sequence_counter).unwrap();

        assert_eq!(trace.packet.len(), 1);
        if let Some(Data::TrackDescriptor(ref td)) = trace.packet[0].data {
            if let Some(ref thread_desc) = td.thread.0 {
                assert_eq!(thread_desc.tid(), 200);
                assert_eq!(thread_desc.pid(), 100);
                assert_eq!(thread_desc.thread_name(), "worker");
            } else {
                panic!("TrackDescriptor missing thread");
            }
        } else {
            panic!("Expected TrackDescriptor packet");
        }
    }

    #[test]
    fn test_clock_conversion() {
        let conn = Connection::open_in_memory().unwrap();
        create_schema(&conn).unwrap();

        // Insert clock snapshots with actual clock names
        conn.execute(
            "INSERT INTO clocks (snapshot_id, clock_type, timestamp) VALUES (1, 'BOOTTIME', 1000000)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO clocks (snapshot_id, clock_type, timestamp) VALUES (1, 'REALTIME', 2000000)",
            [],
        )
        .unwrap();

        let mut trace = Trace::default();
        let sequence_counter = AtomicU32::new(1);
        add_clock_packets(&conn, &mut trace, &sequence_counter).unwrap();

        assert_eq!(trace.packet.len(), 1);
        if let Some(Data::ClockSnapshot(ref cs)) = trace.packet[0].data {
            assert_eq!(cs.clocks.len(), 2);
        } else {
            panic!("Expected ClockSnapshot packet");
        }
    }

    #[test]
    fn test_no_duplicate_clock_ids() {
        // Test that conversion correctly handles clock snapshots and doesn't produce duplicate IDs
        let conn = Connection::open_in_memory().unwrap();
        create_schema(&conn).unwrap();

        // Insert different clock types in same snapshot
        conn.execute(
            "INSERT INTO clocks (snapshot_id, clock_type, timestamp) VALUES (1, 'BOOTTIME', 1000000)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO clocks (snapshot_id, clock_type, timestamp) VALUES (1, 'MONOTONIC', 2000000)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO clocks (snapshot_id, clock_type, timestamp) VALUES (1, 'REALTIME', 3000000)",
            [],
        )
        .unwrap();

        let mut trace = Trace::default();
        let sequence_counter = AtomicU32::new(1);
        add_clock_packets(&conn, &mut trace, &sequence_counter).unwrap();

        assert_eq!(
            trace.packet.len(),
            1,
            "Should have exactly one clock snapshot packet"
        );
        if let Some(Data::ClockSnapshot(ref cs)) = trace.packet[0].data {
            assert_eq!(
                cs.clocks.len(),
                3,
                "Should have all three different clock types"
            );

            // Verify no duplicate clock IDs
            let mut seen_ids = HashSet::new();
            for clock in &cs.clocks {
                assert!(
                    seen_ids.insert(clock.clock_id()),
                    "Found duplicate clock ID: {}",
                    clock.clock_id()
                );
            }

            // Verify each clock has the correct ID
            for clock in &cs.clocks {
                match clock.clock_id() {
                    id if id == BuiltinClock::BUILTIN_CLOCK_BOOTTIME as u32 => {
                        assert_eq!(clock.timestamp(), 1000000);
                    }
                    id if id == BuiltinClock::BUILTIN_CLOCK_MONOTONIC as u32 => {
                        assert_eq!(clock.timestamp(), 2000000);
                    }
                    id if id == BuiltinClock::BUILTIN_CLOCK_REALTIME as u32 => {
                        assert_eq!(clock.timestamp(), 3000000);
                    }
                    _ => panic!("Unexpected clock ID: {}", clock.clock_id()),
                }
            }
        } else {
            panic!("Expected ClockSnapshot packet");
        }
    }

    #[test]
    fn test_database_prevents_duplicate_clock_types() {
        // Test that the database schema correctly prevents duplicate clock types in same snapshot
        let conn = Connection::open_in_memory().unwrap();
        create_schema(&conn).unwrap();

        // Insert first BOOTTIME clock
        conn.execute(
            "INSERT INTO clocks (snapshot_id, clock_type, timestamp) VALUES (1, 'BOOTTIME', 1000000)",
            [],
        )
        .unwrap();

        // Try to insert duplicate BOOTTIME for same snapshot (should fail)
        let result = conn.execute(
            "INSERT INTO clocks (snapshot_id, clock_type, timestamp) VALUES (1, 'BOOTTIME', 1500000)",
            [],
        );

        assert!(
            result.is_err(),
            "Database should prevent duplicate clock_type in same snapshot"
        );

        // But different snapshot should work
        conn.execute(
            "INSERT INTO clocks (snapshot_id, clock_type, timestamp) VALUES (2, 'BOOTTIME', 2000000)",
            [],
        )
        .unwrap();
    }

    #[test]
    fn test_clock_snapshot_has_primary_clock() {
        // Test that clock snapshots have primary_trace_clock set
        let conn = Connection::open_in_memory().unwrap();
        create_schema(&conn).unwrap();

        conn.execute(
            "INSERT INTO clocks (snapshot_id, clock_type, timestamp) VALUES (1, 'BOOTTIME', 1000000)",
            [],
        )
        .unwrap();

        let mut trace = Trace::default();
        let sequence_counter = AtomicU32::new(1);
        add_clock_packets(&conn, &mut trace, &sequence_counter).unwrap();

        if let Some(Data::ClockSnapshot(ref cs)) = trace.packet[0].data {
            assert_eq!(
                cs.primary_trace_clock(),
                BuiltinClock::BUILTIN_CLOCK_BOOTTIME,
                "Primary trace clock should be set to BOOTTIME"
            );
        } else {
            panic!("Expected ClockSnapshot packet");
        }
    }

    #[test]
    fn test_thread_descriptors_wrapped_in_track_descriptors() {
        // Test that thread descriptors are properly wrapped in TrackDescriptors
        let conn = Connection::open_in_memory().unwrap();
        create_schema(&conn).unwrap();

        // Insert test process and thread
        conn.execute(
            "INSERT INTO processes (pid, name, cmdline) VALUES (100, 'parent', '[]')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO threads (tid, pid, name) VALUES (200, 100, 'worker')",
            [],
        )
        .unwrap();

        let mut trace = Trace::default();
        let sequence_counter = AtomicU32::new(1);
        add_thread_packets(&conn, &mut trace, &sequence_counter).unwrap();

        assert_eq!(trace.packet.len(), 1);

        // Verify it's a TrackDescriptor, not a bare ThreadDescriptor
        match &trace.packet[0].data {
            Some(Data::TrackDescriptor(td)) => {
                assert!(
                    td.thread.0.is_some(),
                    "TrackDescriptor should contain thread"
                );
                assert!(td.uuid() > 0, "TrackDescriptor should have UUID");
                let thread = td.thread.0.as_ref().unwrap();
                assert_eq!(thread.tid(), 200);
                assert_eq!(thread.pid(), 100);
            }
            Some(Data::ThreadDescriptor(_)) => {
                panic!("Thread descriptor should be wrapped in TrackDescriptor, not sent as bare ThreadDescriptor");
            }
            _ => panic!("Expected TrackDescriptor packet"),
        }
    }

    #[test]
    fn test_process_descriptors_wrapped_in_track_descriptors() {
        // Test that process descriptors are properly wrapped in TrackDescriptors
        let conn = Connection::open_in_memory().unwrap();
        create_schema(&conn).unwrap();

        conn.execute(
            "INSERT INTO processes (pid, name, cmdline) VALUES (123, 'test_proc', '[\"test\", \"args\"]')",
            [],
        )
        .unwrap();

        let mut trace = Trace::default();
        let sequence_counter = AtomicU32::new(1);
        add_process_packets(&conn, &mut trace, &sequence_counter).unwrap();

        assert_eq!(trace.packet.len(), 1);

        // Verify it's a TrackDescriptor, not a bare ProcessDescriptor
        match &trace.packet[0].data {
            Some(Data::TrackDescriptor(td)) => {
                assert!(
                    td.process.0.is_some(),
                    "TrackDescriptor should contain process"
                );
                assert!(td.uuid() > 0, "TrackDescriptor should have UUID");
                let process = td.process.0.as_ref().unwrap();
                assert_eq!(process.pid(), 123);
                assert_eq!(process.process_name(), "test_proc");
            }
            Some(Data::ProcessDescriptor(_)) => {
                panic!("Process descriptor should be wrapped in TrackDescriptor, not sent as bare ProcessDescriptor");
            }
            _ => panic!("Expected TrackDescriptor packet"),
        }
    }

    #[test]
    fn test_all_packets_have_sequence_ids() {
        // Test that all packets have trusted_packet_sequence_id set
        let conn = Connection::open_in_memory().unwrap();
        create_schema(&conn).unwrap();

        // Add various types of data
        conn.execute(
            "INSERT INTO clocks (snapshot_id, clock_type, timestamp) VALUES (1, 'BOOTTIME', 1000000)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO processes (pid, name, cmdline) VALUES (100, 'parent', '[]')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO threads (tid, pid, name) VALUES (200, 100, 'worker')",
            [],
        )
        .unwrap();

        let mut trace = Trace::default();
        let sequence_counter = AtomicU32::new(1);

        add_clock_packets(&conn, &mut trace, &sequence_counter).unwrap();
        add_process_packets(&conn, &mut trace, &sequence_counter).unwrap();
        add_thread_packets(&conn, &mut trace, &sequence_counter).unwrap();

        // Verify all packets have sequence IDs
        for (i, packet) in trace.packet.iter().enumerate() {
            assert!(
                packet.trusted_packet_sequence_id() > 0,
                "Packet {i} should have a trusted_packet_sequence_id"
            );
        }

        // Verify sequence IDs are unique
        let mut seen_ids = HashSet::new();
        for packet in &trace.packet {
            let seq_id = packet.trusted_packet_sequence_id();
            assert!(
                seen_ids.insert(seq_id),
                "Duplicate sequence ID found: {seq_id}"
            );
        }
    }

    #[test]
    fn test_clock_name_mapping() {
        // Test that all standard clock names are properly mapped
        let conn = Connection::open_in_memory().unwrap();
        create_schema(&conn).unwrap();

        let clock_names = vec![
            ("BOOTTIME", BuiltinClock::BUILTIN_CLOCK_BOOTTIME),
            ("MONOTONIC", BuiltinClock::BUILTIN_CLOCK_MONOTONIC),
            ("REALTIME", BuiltinClock::BUILTIN_CLOCK_REALTIME),
            (
                "MONOTONIC_COARSE",
                BuiltinClock::BUILTIN_CLOCK_MONOTONIC_COARSE,
            ),
            (
                "REALTIME_COARSE",
                BuiltinClock::BUILTIN_CLOCK_REALTIME_COARSE,
            ),
            ("MONOTONIC_RAW", BuiltinClock::BUILTIN_CLOCK_MONOTONIC_RAW),
        ];

        for (name, expected_enum) in clock_names {
            conn.execute("DELETE FROM clocks", []).unwrap();

            conn.execute(
                &format!("INSERT INTO clocks (snapshot_id, clock_type, timestamp) VALUES (1, '{name}', 1000000)"),
                [],
            )
            .unwrap();

            let mut trace = Trace::default();
            let sequence_counter = AtomicU32::new(1);
            add_clock_packets(&conn, &mut trace, &sequence_counter).unwrap();

            if let Some(Data::ClockSnapshot(ref cs)) = trace.packet[0].data {
                assert_eq!(cs.clocks.len(), 1);
                assert_eq!(
                    cs.clocks[0].clock_id(),
                    expected_enum as u32,
                    "Clock name '{}' should map to ID {}",
                    name,
                    expected_enum as u32
                );
            } else {
                panic!("Expected ClockSnapshot packet for clock '{name}'");
            }
        }
    }

    #[test]
    fn test_unknown_clock_names_are_skipped() {
        // Test that unknown clock names are skipped with a warning
        let conn = Connection::open_in_memory().unwrap();
        create_schema(&conn).unwrap();

        conn.execute(
            "INSERT INTO clocks (snapshot_id, clock_type, timestamp) VALUES (1, 'BOOTTIME', 1000000)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO clocks (snapshot_id, clock_type, timestamp) VALUES (1, 'INVALID_CLOCK', 2000000)",
            [],
        )
        .unwrap();

        let mut trace = Trace::default();
        let sequence_counter = AtomicU32::new(1);
        add_clock_packets(&conn, &mut trace, &sequence_counter).unwrap();

        if let Some(Data::ClockSnapshot(ref cs)) = trace.packet[0].data {
            assert_eq!(
                cs.clocks.len(),
                1,
                "Should only have valid BOOTTIME clock, INVALID_CLOCK should be skipped"
            );
            assert_eq!(
                cs.clocks[0].clock_id(),
                BuiltinClock::BUILTIN_CLOCK_BOOTTIME as u32
            );
        } else {
            panic!("Expected ClockSnapshot packet");
        }
    }

    #[test]
    fn test_complete_conversion_produces_valid_trace() {
        // Integration test that runs full conversion and validates output structure
        let conn = Connection::open_in_memory().unwrap();
        create_schema(&conn).unwrap();

        // Set up a minimal but complete trace (note: metadata table columns are trace_start_ts, trace_end_ts, systing_version)
        conn.execute(
            "INSERT INTO metadata (trace_start_ts, trace_end_ts, systing_version) VALUES (1000, 2000, '1.0.0')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO clocks (snapshot_id, clock_type, timestamp) VALUES (1, 'BOOTTIME', 1000)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO clocks (snapshot_id, clock_type, timestamp) VALUES (1, 'MONOTONIC', 1000)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO processes (pid, name, cmdline) VALUES (1, 'init', '[\"init\"]')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO threads (tid, pid, name) VALUES (1, 1, 'main')",
            [],
        )
        .unwrap();

        // Run full conversion
        let mut trace = Trace::default();
        let sequence_counter = AtomicU32::new(1);

        add_clock_packets(&conn, &mut trace, &sequence_counter).unwrap();
        add_process_packets(&conn, &mut trace, &sequence_counter).unwrap();
        add_thread_packets(&conn, &mut trace, &sequence_counter).unwrap();

        // Validate the complete trace structure
        assert!(
            trace.packet.len() >= 3,
            "Should have at least clock, process, and thread packets"
        );

        let mut has_clock_snapshot = false;
        let mut has_process_track = false;
        let mut has_thread_track = false;
        let mut all_have_sequence_ids = true;

        for packet in &trace.packet {
            if packet.trusted_packet_sequence_id() == 0 {
                all_have_sequence_ids = false;
            }

            match &packet.data {
                Some(Data::ClockSnapshot(cs)) => {
                    has_clock_snapshot = true;
                    // Verify no duplicate clock IDs
                    let mut seen_ids = HashSet::new();
                    for clock in &cs.clocks {
                        assert!(seen_ids.insert(clock.clock_id()), "Duplicate clock ID");
                    }
                }
                Some(Data::TrackDescriptor(td)) => {
                    if td.process.0.is_some() {
                        has_process_track = true;
                    }
                    if td.thread.0.is_some() {
                        has_thread_track = true;
                    }
                }
                _ => {}
            }
        }

        assert!(has_clock_snapshot, "Trace should have clock snapshot");
        assert!(
            has_process_track,
            "Trace should have process track descriptor"
        );
        assert!(
            has_thread_track,
            "Trace should have thread track descriptor"
        );
        assert!(
            all_have_sequence_ids,
            "All packets should have sequence IDs"
        );
    }

    #[test]
    fn test_scheduler_event_conversion_switch() {
        // Test that sched_switch events are properly converted
        let conn = Connection::open_in_memory().unwrap();
        create_schema(&conn).unwrap();

        // Insert test process and threads
        conn.execute(
            "INSERT INTO processes (pid, name, cmdline) VALUES (100, 'test_proc', '[]')",
            [],
        )
        .unwrap();
        // Insert both threads referenced in the events
        conn.execute(
            "INSERT INTO threads (tid, pid, name) VALUES (100, 100, 'thread_100')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO threads (tid, pid, name) VALUES (200, 100, 'thread_200')",
            [],
        )
        .unwrap();

        // Insert sched_switch events
        conn.execute(
            "INSERT INTO sched_events (ts, cpu, event_type, prev_pid, prev_state, next_pid, next_prio)
             VALUES (1000000, 0, 'switch', 100, 0, 200, 120)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO sched_events (ts, cpu, event_type, prev_pid, prev_state, next_pid, next_prio)
             VALUES (2000000, 0, 'switch', 200, 1, 100, 120)",
            [],
        )
        .unwrap();

        let mut trace = Trace::default();
        let sequence_counter = AtomicU32::new(1);
        add_scheduler_event_packets(&conn, &mut trace, &sequence_counter).unwrap();

        // Should have one FtraceEventBundle packet for CPU 0
        assert_eq!(trace.packet.len(), 1, "Should have one packet for CPU 0");

        // Verify it's an FtraceEventBundle with CompactSched
        if let Some(Data::FtraceEvents(ref bundle)) = trace.packet[0].data {
            assert_eq!(bundle.cpu(), 0, "Should be for CPU 0");
            assert!(
                bundle.compact_sched.0.is_some(),
                "Should have compact_sched"
            );

            let compact_sched = bundle.compact_sched.0.as_ref().unwrap();

            // Check switch events
            assert_eq!(
                compact_sched.switch_timestamp.len(),
                2,
                "Should have 2 switch events"
            );
            assert_eq!(
                compact_sched.switch_next_pid,
                vec![200, 100],
                "Should have correct next PIDs"
            );

            // Check delta encoding - first timestamp is absolute, second is delta
            assert_eq!(
                compact_sched.switch_timestamp[0], 1000000,
                "First timestamp should be absolute"
            );
            assert_eq!(
                compact_sched.switch_timestamp[1], 1000000,
                "Second timestamp should be delta (2000000 - 1000000)"
            );
        } else {
            panic!("Expected FtraceEvents packet");
        }
    }

    #[test]
    fn test_scheduler_event_conversion_waking() {
        // Test that sched_waking events are properly converted
        let conn = Connection::open_in_memory().unwrap();
        create_schema(&conn).unwrap();

        // Insert test process and threads
        conn.execute(
            "INSERT INTO processes (pid, name, cmdline) VALUES (100, 'test_proc', '[]')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO threads (tid, pid, name) VALUES (200, 100, 'waker')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO threads (tid, pid, name) VALUES (300, 100, 'wakee')",
            [],
        )
        .unwrap();

        // Insert sched_waking events
        conn.execute(
            "INSERT INTO sched_events (ts, cpu, event_type, next_pid, next_prio)
             VALUES (500000, 1, 'waking', 300, 120)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO sched_events (ts, cpu, event_type, next_pid, next_prio)
             VALUES (600000, 1, 'waking', 200, 110)",
            [],
        )
        .unwrap();

        let mut trace = Trace::default();
        let sequence_counter = AtomicU32::new(1);
        add_scheduler_event_packets(&conn, &mut trace, &sequence_counter).unwrap();

        assert_eq!(trace.packet.len(), 1, "Should have one packet for CPU 1");

        if let Some(Data::FtraceEvents(ref bundle)) = trace.packet[0].data {
            assert_eq!(bundle.cpu(), 1, "Should be for CPU 1");
            let compact_sched = bundle.compact_sched.0.as_ref().unwrap();

            // Check waking events
            assert_eq!(
                compact_sched.waking_timestamp.len(),
                2,
                "Should have 2 waking events"
            );
            assert_eq!(
                compact_sched.waking_pid,
                vec![300, 200],
                "Should have correct waking PIDs"
            );

            // Check delta encoding
            assert_eq!(
                compact_sched.waking_timestamp[0], 500000,
                "First timestamp should be absolute"
            );
            assert_eq!(
                compact_sched.waking_timestamp[1], 100000,
                "Second timestamp should be delta (600000 - 500000)"
            );

            // Check target CPU (should be same as source CPU for waking events)
            assert_eq!(
                compact_sched.waking_target_cpu,
                vec![1, 1],
                "Target CPU should be CPU 1 for both"
            );
        } else {
            panic!("Expected FtraceEvents packet");
        }
    }

    #[test]
    fn test_scheduler_event_thread_name_interning() {
        // Test that thread names are properly interned
        let conn = Connection::open_in_memory().unwrap();
        create_schema(&conn).unwrap();

        // Insert test process and threads with specific names
        conn.execute(
            "INSERT INTO processes (pid, name, cmdline) VALUES (100, 'test_proc', '[]')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO threads (tid, pid, name) VALUES (200, 100, 'thread_a')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO threads (tid, pid, name) VALUES (300, 100, 'thread_b')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO threads (tid, pid, name) VALUES (400, 100, 'thread_a')",
            [],
        )
        .unwrap(); // Same name as 200

        // Insert events that reference these threads
        conn.execute(
            "INSERT INTO sched_events (ts, cpu, event_type, next_pid)
             VALUES (1000, 0, 'switch', 200)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO sched_events (ts, cpu, event_type, next_pid)
             VALUES (2000, 0, 'switch', 300)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO sched_events (ts, cpu, event_type, next_pid)
             VALUES (3000, 0, 'switch', 400)",
            [],
        )
        .unwrap();

        let mut trace = Trace::default();
        let sequence_counter = AtomicU32::new(1);
        add_scheduler_event_packets(&conn, &mut trace, &sequence_counter).unwrap();

        if let Some(Data::FtraceEvents(ref bundle)) = trace.packet[0].data {
            let compact_sched = bundle.compact_sched.0.as_ref().unwrap();

            // Check intern table - should have exactly 2 unique strings
            assert_eq!(
                compact_sched.intern_table.len(),
                2,
                "Should have 2 unique thread names"
            );
            assert!(
                compact_sched.intern_table.contains(&"thread_a".to_string()),
                "Should contain thread_a"
            );
            assert!(
                compact_sched.intern_table.contains(&"thread_b".to_string()),
                "Should contain thread_b"
            );

            // Check comm indices refer to correct interned strings
            assert_eq!(
                compact_sched.switch_next_comm_index.len(),
                3,
                "Should have 3 comm indices"
            );

            // First and third should refer to same interned string (thread_a)
            assert_eq!(
                compact_sched.switch_next_comm_index[0], compact_sched.switch_next_comm_index[2],
                "PIDs 200 and 400 should have same comm index (both thread_a)"
            );
        } else {
            panic!("Expected FtraceEvents packet");
        }
    }

    #[test]
    fn test_scheduler_events_grouped_by_cpu() {
        // Test that events are properly grouped by CPU
        let conn = Connection::open_in_memory().unwrap();
        create_schema(&conn).unwrap();

        // Insert test process and thread
        conn.execute(
            "INSERT INTO processes (pid, name, cmdline) VALUES (100, 'test_proc', '[]')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO threads (tid, pid, name) VALUES (200, 100, 'worker')",
            [],
        )
        .unwrap();

        // Insert events on different CPUs
        conn.execute(
            "INSERT INTO sched_events (ts, cpu, event_type, next_pid)
             VALUES (1000, 0, 'switch', 200)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO sched_events (ts, cpu, event_type, next_pid)
             VALUES (2000, 1, 'switch', 200)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO sched_events (ts, cpu, event_type, next_pid)
             VALUES (3000, 0, 'waking', 200)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO sched_events (ts, cpu, event_type, next_pid)
             VALUES (4000, 2, 'waking', 200)",
            [],
        )
        .unwrap();

        let mut trace = Trace::default();
        let sequence_counter = AtomicU32::new(1);
        add_scheduler_event_packets(&conn, &mut trace, &sequence_counter).unwrap();

        // Should have 3 packets (one for each CPU: 0, 1, 2)
        assert_eq!(trace.packet.len(), 3, "Should have 3 packets for 3 CPUs");

        // Collect CPU numbers from packets
        let mut cpus = Vec::new();
        for packet in &trace.packet {
            if let Some(Data::FtraceEvents(ref bundle)) = packet.data {
                cpus.push(bundle.cpu());
            }
        }
        cpus.sort_unstable();
        assert_eq!(cpus, vec![0, 1, 2], "Should have packets for CPUs 0, 1, 2");

        // Check CPU 0 packet has both switch and waking
        for packet in &trace.packet {
            if let Some(Data::FtraceEvents(ref bundle)) = packet.data {
                if bundle.cpu() == 0 {
                    let compact_sched = bundle.compact_sched.0.as_ref().unwrap();
                    assert_eq!(
                        compact_sched.switch_timestamp.len(),
                        1,
                        "CPU 0 should have 1 switch event"
                    );
                    assert_eq!(
                        compact_sched.waking_timestamp.len(),
                        1,
                        "CPU 0 should have 1 waking event"
                    );
                }
            }
        }
    }

    #[test]
    fn test_scheduler_event_with_missing_thread() {
        // Test handling of events referencing non-existent threads
        let conn = Connection::open_in_memory().unwrap();
        create_schema(&conn).unwrap();

        // Disable foreign key constraints for this test
        conn.execute("PRAGMA foreign_keys = OFF", []).unwrap();

        // Insert events without corresponding thread entries
        conn.execute(
            "INSERT INTO sched_events (ts, cpu, event_type, next_pid)
             VALUES (1000, 0, 'switch', 999)",
            [],
        )
        .unwrap(); // PID 999 doesn't exist

        let mut trace = Trace::default();
        let sequence_counter = AtomicU32::new(1);
        add_scheduler_event_packets(&conn, &mut trace, &sequence_counter).unwrap();

        if let Some(Data::FtraceEvents(ref bundle)) = trace.packet[0].data {
            let compact_sched = bundle.compact_sched.0.as_ref().unwrap();

            // Should generate a default name for missing thread
            assert_eq!(compact_sched.intern_table.len(), 1);
            assert_eq!(
                compact_sched.intern_table[0], "pid-999",
                "Should generate default name for missing thread"
            );
        } else {
            panic!("Expected FtraceEvents packet");
        }
    }

    #[test]
    fn test_scheduler_event_unknown_event_types() {
        // Test that unknown event types are properly skipped
        let conn = Connection::open_in_memory().unwrap();
        create_schema(&conn).unwrap();

        // Insert process and thread
        conn.execute(
            "INSERT INTO processes (pid, name, cmdline) VALUES (100, 'test_proc', '[]')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO threads (tid, pid, name) VALUES (200, 100, 'worker')",
            [],
        )
        .unwrap();

        // Insert valid and invalid event types
        conn.execute(
            "INSERT INTO sched_events (ts, cpu, event_type, next_pid)
             VALUES (1000, 0, 'switch', 200)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO sched_events (ts, cpu, event_type, next_pid)
             VALUES (2000, 0, 'unknown_type', 200)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO sched_events (ts, cpu, event_type, next_pid)
             VALUES (3000, 0, 'waking', 200)",
            [],
        )
        .unwrap();

        let mut trace = Trace::default();
        let sequence_counter = AtomicU32::new(1);

        // Should not panic and should process valid events
        add_scheduler_event_packets(&conn, &mut trace, &sequence_counter).unwrap();

        if let Some(Data::FtraceEvents(ref bundle)) = trace.packet[0].data {
            let compact_sched = bundle.compact_sched.0.as_ref().unwrap();

            // Should only have the valid events
            assert_eq!(
                compact_sched.switch_timestamp.len(),
                1,
                "Should have 1 switch event (unknown_type skipped)"
            );
            assert_eq!(
                compact_sched.waking_timestamp.len(),
                1,
                "Should have 1 waking event"
            );
        } else {
            panic!("Expected FtraceEvents packet");
        }
    }

    #[test]
    fn test_scheduler_event_empty_database() {
        // Test that empty scheduler events table produces no packets
        let conn = Connection::open_in_memory().unwrap();
        create_schema(&conn).unwrap();

        let mut trace = Trace::default();
        let sequence_counter = AtomicU32::new(1);
        add_scheduler_event_packets(&conn, &mut trace, &sequence_counter).unwrap();

        assert_eq!(
            trace.packet.len(),
            0,
            "Empty scheduler events should produce no packets"
        );
    }

    #[test]
    fn test_scheduler_event_priority_values() {
        // Test that priority values are correctly preserved
        let conn = Connection::open_in_memory().unwrap();
        create_schema(&conn).unwrap();

        // Insert test data
        conn.execute(
            "INSERT INTO processes (pid, name, cmdline) VALUES (100, 'test_proc', '[]')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO threads (tid, pid, name) VALUES (200, 100, 'high_prio')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO threads (tid, pid, name) VALUES (300, 100, 'low_prio')",
            [],
        )
        .unwrap();

        // Insert events with different priorities
        conn.execute(
            "INSERT INTO sched_events (ts, cpu, event_type, next_pid, next_prio)
             VALUES (1000, 0, 'switch', 200, 50)",
            [],
        )
        .unwrap(); // High priority (lower number)
        conn.execute(
            "INSERT INTO sched_events (ts, cpu, event_type, next_pid, next_prio)
             VALUES (2000, 0, 'switch', 300, 139)",
            [],
        )
        .unwrap(); // Low priority (higher number)
        conn.execute(
            "INSERT INTO sched_events (ts, cpu, event_type, next_pid, next_prio)
             VALUES (3000, 0, 'waking', 200, 50)",
            [],
        )
        .unwrap();

        let mut trace = Trace::default();
        let sequence_counter = AtomicU32::new(1);
        add_scheduler_event_packets(&conn, &mut trace, &sequence_counter).unwrap();

        if let Some(Data::FtraceEvents(ref bundle)) = trace.packet[0].data {
            let compact_sched = bundle.compact_sched.0.as_ref().unwrap();

            // Check switch priorities
            assert_eq!(
                compact_sched.switch_next_prio,
                vec![50, 139],
                "Should preserve priority values for switch events"
            );

            // Check waking priorities
            assert_eq!(
                compact_sched.waking_prio,
                vec![50],
                "Should preserve priority values for waking events"
            );
        } else {
            panic!("Expected FtraceEvents packet");
        }
    }

    #[test]
    fn test_scheduler_event_state_values() {
        // Test that prev_state values are correctly preserved
        let conn = Connection::open_in_memory().unwrap();
        create_schema(&conn).unwrap();

        // Insert test data
        conn.execute(
            "INSERT INTO processes (pid, name, cmdline) VALUES (100, 'test_proc', '[]')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO threads (tid, pid, name) VALUES (200, 100, 'worker')",
            [],
        )
        .unwrap();

        // Insert switch events with different state values
        // Common Linux task states: 0=RUNNING, 1=INTERRUPTIBLE, 2=UNINTERRUPTIBLE, etc.
        conn.execute(
            "INSERT INTO sched_events (ts, cpu, event_type, prev_state, next_pid)
             VALUES (1000, 0, 'switch', 0, 200)",
            [],
        )
        .unwrap(); // RUNNING
        conn.execute(
            "INSERT INTO sched_events (ts, cpu, event_type, prev_state, next_pid)
             VALUES (2000, 0, 'switch', 1, 200)",
            [],
        )
        .unwrap(); // INTERRUPTIBLE
        conn.execute(
            "INSERT INTO sched_events (ts, cpu, event_type, prev_state, next_pid)
             VALUES (3000, 0, 'switch', 2, 200)",
            [],
        )
        .unwrap(); // UNINTERRUPTIBLE

        let mut trace = Trace::default();
        let sequence_counter = AtomicU32::new(1);
        add_scheduler_event_packets(&conn, &mut trace, &sequence_counter).unwrap();

        if let Some(Data::FtraceEvents(ref bundle)) = trace.packet[0].data {
            let compact_sched = bundle.compact_sched.0.as_ref().unwrap();

            assert_eq!(
                compact_sched.switch_prev_state,
                vec![0, 1, 2],
                "Should preserve all state values"
            );
        } else {
            panic!("Expected FtraceEvents packet");
        }
    }

    #[test]
    fn test_scheduler_event_large_timestamp_delta() {
        // Test that large timestamp deltas are handled correctly
        let conn = Connection::open_in_memory().unwrap();
        create_schema(&conn).unwrap();

        // Insert test data
        conn.execute(
            "INSERT INTO processes (pid, name, cmdline) VALUES (100, 'test_proc', '[]')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO threads (tid, pid, name) VALUES (200, 100, 'worker')",
            [],
        )
        .unwrap();

        // Insert events with large timestamp gaps
        let ts1 = 1_000_000_000u64; // 1 second in nanoseconds
        let ts2 = 60_000_000_000u64; // 60 seconds
        let ts3 = 3_600_000_000_000u64; // 1 hour

        conn.execute(
            &format!(
                "INSERT INTO sched_events (ts, cpu, event_type, next_pid)
                 VALUES ({ts1}, 0, 'switch', 200)"
            ),
            [],
        )
        .unwrap();
        conn.execute(
            &format!(
                "INSERT INTO sched_events (ts, cpu, event_type, next_pid)
                 VALUES ({ts2}, 0, 'switch', 200)"
            ),
            [],
        )
        .unwrap();
        conn.execute(
            &format!(
                "INSERT INTO sched_events (ts, cpu, event_type, next_pid)
                 VALUES ({ts3}, 0, 'switch', 200)"
            ),
            [],
        )
        .unwrap();

        let mut trace = Trace::default();
        let sequence_counter = AtomicU32::new(1);
        add_scheduler_event_packets(&conn, &mut trace, &sequence_counter).unwrap();

        if let Some(Data::FtraceEvents(ref bundle)) = trace.packet[0].data {
            let compact_sched = bundle.compact_sched.0.as_ref().unwrap();

            // Verify delta encoding
            assert_eq!(compact_sched.switch_timestamp[0], ts1, "First is absolute");
            assert_eq!(
                compact_sched.switch_timestamp[1],
                ts2 - ts1,
                "Second is delta from first"
            );
            assert_eq!(
                compact_sched.switch_timestamp[2],
                ts3 - ts2,
                "Third is delta from second"
            );
        } else {
            panic!("Expected FtraceEvents packet");
        }
    }
}
