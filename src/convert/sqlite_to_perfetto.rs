//! SQLite to Perfetto conversion implementation
//!
//! This module converts SQLite database traces back to Perfetto protobuf format.
//! The conversion reads data from the relational SQLite schema and generates
//! appropriate Perfetto TracePacket protobufs.

use anyhow::{Context, Result};
use perfetto_protos::clock_snapshot::clock_snapshot::Clock;
use perfetto_protos::clock_snapshot::ClockSnapshot;
use perfetto_protos::process_descriptor::ProcessDescriptor;
use perfetto_protos::thread_descriptor::ThreadDescriptor;
use perfetto_protos::trace::Trace;
use perfetto_protos::trace_packet::trace_packet::Data;
use perfetto_protos::trace_packet::TracePacket;
use protobuf::Message;
use rusqlite::Connection;
use std::fs::File;

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

    println!("Reading metadata from SQLite database...");

    // Generate TracePackets in order:
    // 1. Clock snapshots (must come early for timestamp reference)
    add_clock_packets(&conn, &mut trace)?;

    // 2. Process descriptors
    add_process_packets(&conn, &mut trace)?;

    // 3. Thread descriptors
    add_thread_packets(&conn, &mut trace)?;

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
fn add_clock_packets(conn: &Connection, trace: &mut Trace) -> Result<()> {
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

        let clocks_result: Result<Vec<Clock>, _> = clock_stmt
            .query_map([snapshot_id], |row| {
                let clock_type: String = row.get(0)?;
                let timestamp: u64 = row.get(1)?;

                // Map clock type string to clock ID
                // Note: BOOTTIME is clock_6, MONOTONIC is clock_1, REALTIME is clock_0
                let clock_id = match clock_type.as_str() {
                    "BOOTTIME" | "clock_6" => {
                        perfetto_protos::builtin_clock::BuiltinClock::BUILTIN_CLOCK_BOOTTIME as u32
                    }
                    "MONOTONIC" | "clock_1" => {
                        perfetto_protos::builtin_clock::BuiltinClock::BUILTIN_CLOCK_MONOTONIC as u32
                    }
                    "REALTIME" | "clock_0" => {
                        perfetto_protos::builtin_clock::BuiltinClock::BUILTIN_CLOCK_REALTIME as u32
                    }
                    "MONOTONIC_COARSE" => {
                        perfetto_protos::builtin_clock::BuiltinClock::BUILTIN_CLOCK_MONOTONIC_COARSE
                            as u32
                    }
                    "REALTIME_COARSE" | "clock_5" => {
                        perfetto_protos::builtin_clock::BuiltinClock::BUILTIN_CLOCK_REALTIME_COARSE
                            as u32
                    }
                    // Try to parse as clock_N format for any other clock IDs
                    s if s.starts_with("clock_") => {
                        s.strip_prefix("clock_")
                            .and_then(|id_str| id_str.parse::<u32>().ok())
                            .unwrap_or(6) // Default to BOOTTIME
                    }
                    _ => 6, // Default to BOOTTIME for unknown clock types
                };

                let mut clock = Clock::new();
                clock.set_clock_id(clock_id);
                clock.set_timestamp(timestamp);

                Ok(clock)
            })
            .context("Failed to query clocks")?
            .collect();

        let clocks = clocks_result.context("Failed to collect clock data")?;

        if !clocks.is_empty() {
            let mut clock_snapshot = ClockSnapshot::new();
            clock_snapshot.clocks = clocks;

            let mut packet = TracePacket::new();
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
/// including PID, name, and command line.
fn add_process_packets(conn: &Connection, trace: &mut Trace) -> Result<()> {
    let mut stmt = conn
        .prepare("SELECT pid, name, cmdline FROM processes ORDER BY pid")
        .context("Failed to prepare process query")?;

    let mut process_count = 0;
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

        let mut packet = TracePacket::new();
        packet.data = Some(Data::ProcessDescriptor(process_desc));
        trace.packet.push(packet);
        process_count += 1;
    }

    println!("Extracted {} process descriptors", process_count);
    Ok(())
}

/// Read threads from SQLite and generate ThreadDescriptor packets
///
/// Thread descriptors provide information about threads in the trace,
/// including TID, PID (parent process), and thread name.
fn add_thread_packets(conn: &Connection, trace: &mut Trace) -> Result<()> {
    let mut stmt = conn
        .prepare("SELECT tid, pid, name FROM threads ORDER BY tid")
        .context("Failed to prepare thread query")?;

    let mut thread_count = 0;
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

        let mut packet = TracePacket::new();
        packet.data = Some(Data::ThreadDescriptor(thread_desc));
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
        add_clock_packets(&conn, &mut trace).unwrap();
        add_process_packets(&conn, &mut trace).unwrap();
        add_thread_packets(&conn, &mut trace).unwrap();

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
        add_process_packets(&conn, &mut trace).unwrap();

        assert_eq!(trace.packet.len(), 1);
        if let Some(Data::ProcessDescriptor(ref pd)) = trace.packet[0].data {
            assert_eq!(pd.pid(), 123);
            assert_eq!(pd.process_name(), "test");
        } else {
            panic!("Expected ProcessDescriptor packet");
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
        add_thread_packets(&conn, &mut trace).unwrap();

        assert_eq!(trace.packet.len(), 1);
        if let Some(Data::ThreadDescriptor(ref td)) = trace.packet[0].data {
            assert_eq!(td.tid(), 200);
            assert_eq!(td.pid(), 100);
            assert_eq!(td.thread_name(), "worker");
        } else {
            panic!("Expected ThreadDescriptor packet");
        }
    }

    #[test]
    fn test_clock_conversion() {
        let conn = Connection::open_in_memory().unwrap();
        create_schema(&conn).unwrap();

        // Insert clock snapshots
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
        add_clock_packets(&conn, &mut trace).unwrap();

        assert_eq!(trace.packet.len(), 1);
        if let Some(Data::ClockSnapshot(ref cs)) = trace.packet[0].data {
            assert_eq!(cs.clocks.len(), 2);
        } else {
            panic!("Expected ClockSnapshot packet");
        }
    }
}
