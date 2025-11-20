//! SQLite to Perfetto conversion implementation
//!
//! This module converts SQLite database traces back to Perfetto protobuf format.
//! The conversion reads data from the relational SQLite schema and generates
//! appropriate Perfetto TracePacket protobufs.

use anyhow::{Context, Result};
use perfetto_protos::builtin_clock::BuiltinClock;
use perfetto_protos::clock_snapshot::clock_snapshot::Clock;
use perfetto_protos::clock_snapshot::ClockSnapshot;
use perfetto_protos::process_descriptor::ProcessDescriptor;
use perfetto_protos::thread_descriptor::ThreadDescriptor;
use perfetto_protos::trace::Trace;
use perfetto_protos::trace_packet::trace_packet::Data;
use perfetto_protos::trace_packet::TracePacket;
use perfetto_protos::track_descriptor::TrackDescriptor;
use protobuf::Message;
use rusqlite::Connection;
use std::collections::HashSet;
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
        .with_context(|| format!("Failed to open SQLite database: {}", input_path))?;

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

    println!(
        "Generated {} trace packets from SQLite database",
        trace.packet.len()
    );

    // Write to file
    let mut file = File::create(output_path)
        .with_context(|| format!("Failed to create output file: {}", output_path))?;
    trace
        .write_to_writer(&mut file)
        .context("Failed to write Perfetto trace")?;

    println!("Conversion complete: {} -> {}", input_path, output_path);
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
                    eprintln!("Warning: Unknown clock type '{}', skipping", clock_type);
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

    println!("Extracted {} process descriptors", process_count);
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

    println!("Extracted {} thread descriptors", thread_count);
    Ok(())
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
                "Packet {} should have a trusted_packet_sequence_id",
                i
            );
        }

        // Verify sequence IDs are unique
        let mut seen_ids = HashSet::new();
        for packet in &trace.packet {
            let seq_id = packet.trusted_packet_sequence_id();
            assert!(
                seen_ids.insert(seq_id),
                "Duplicate sequence ID found: {}",
                seq_id
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
                &format!("INSERT INTO clocks (snapshot_id, clock_type, timestamp) VALUES (1, '{}', 1000000)", name),
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
                panic!("Expected ClockSnapshot packet for clock '{}'", name);
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
}
