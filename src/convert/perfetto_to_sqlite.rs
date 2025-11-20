//! Perfetto to SQLite conversion implementation
//!
//! This module converts Perfetto protobuf traces to SQLite database format.
//! The conversion extracts metadata, process/thread information, and basic
//! trace structure from Perfetto packets.

use anyhow::{Context, Result};
use perfetto_protos::trace::Trace;
use protobuf::Message;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;

use crate::output::TraceOutput;
use crate::sqlite::SqliteOutput;

/// Convert a Perfetto protobuf trace file to SQLite format
///
/// This function reads a Perfetto trace file, extracts relevant information,
/// and writes it to a SQLite database using the TraceOutput abstraction.
///
/// # Arguments
///
/// * `input_path` - Path to the input Perfetto trace file (.pb)
/// * `output_path` - Path to the output SQLite database file (.db)
///
/// # Returns
///
/// Returns `Ok(())` on success, or an error if the conversion fails.
///
/// # Current Implementation
///
/// This is a basic implementation that extracts:
/// - Clock snapshots for timestamp synchronization
/// - Process and thread descriptors
/// - Basic metadata
///
/// Future enhancements will add support for:
/// - Scheduler events
/// - Stack traces
/// - Performance counter data
/// - Network events
/// - Custom probe events
pub fn convert_perfetto_to_sqlite(input_path: &str, output_path: &str) -> Result<()> {
    // Read Perfetto trace file
    let mut file = File::open(input_path)
        .with_context(|| format!("Failed to open Perfetto trace file: {}", input_path))?;

    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .context("Failed to read Perfetto trace file contents")?;

    // Parse Perfetto protobuf
    let trace = Trace::parse_from_bytes(&buffer).context(
        "Failed to parse Perfetto protobuf. File may be corrupted or not a valid Perfetto trace.",
    )?;

    println!("Loaded Perfetto trace with {} packets", trace.packet.len());

    // Create SQLite output
    let mut sqlite = SqliteOutput::create(output_path)
        .with_context(|| format!("Failed to create SQLite output: {}", output_path))?;

    // Extract timestamp range from trace
    let (start_ts, end_ts) = extract_timestamp_range(&trace);

    // Write metadata
    sqlite
        .write_metadata(start_ts, end_ts, env!("CARGO_PKG_VERSION"))
        .context("Failed to write metadata")?;

    // Extract and write clock snapshots
    extract_clock_snapshots(&trace, &mut sqlite)?;

    // Extract and write process/thread information
    extract_process_tree(&trace, &mut sqlite)?;

    // Flush and finalize the SQLite database
    sqlite.flush().context("Failed to flush SQLite database")?;

    println!("Conversion complete: {} -> {}", input_path, output_path);
    Ok(())
}

/// Extract the timestamp range (start and end) from the trace
///
/// Scans all packets to find the earliest and latest timestamps.
fn extract_timestamp_range(trace: &Trace) -> (u64, u64) {
    let mut min_ts = u64::MAX;
    let mut max_ts = 0u64;

    for packet in &trace.packet {
        if packet.has_timestamp() {
            let ts = packet.timestamp();
            min_ts = min_ts.min(ts);
            max_ts = max_ts.max(ts);
        }

        // Also check trusted_packet_sequence_id packets which may have different timestamp fields
        if packet.has_clock_snapshot() {
            for clock in packet.clock_snapshot().clocks.iter() {
                if clock.has_timestamp() {
                    let ts = clock.timestamp();
                    min_ts = min_ts.min(ts);
                    max_ts = max_ts.max(ts);
                }
            }
        }
    }

    // If no timestamps found, use zeros
    if min_ts == u64::MAX {
        min_ts = 0;
    }

    (min_ts, max_ts)
}

/// Extract and write clock snapshots from the trace
///
/// Clock snapshots provide timestamp synchronization information across
/// different clock sources (monotonic, boottime, realtime, etc.).
fn extract_clock_snapshots(trace: &Trace, output: &mut dyn TraceOutput) -> Result<()> {
    use crate::output::ClockInfo;

    let mut clocks_written = false;

    for packet in &trace.packet {
        if packet.has_clock_snapshot() {
            let snapshot = packet.clock_snapshot();
            let mut clock_infos = Vec::new();

            for clock in snapshot.clocks.iter() {
                if clock.has_clock_id() && clock.has_timestamp() {
                    let clock_info = ClockInfo {
                        clock_id: clock.clock_id(),
                        clock_name: format!("clock_{}", clock.clock_id()),
                        timestamp: clock.timestamp(),
                    };
                    clock_infos.push(clock_info);
                }
            }

            if !clock_infos.is_empty() {
                output
                    .write_clock_snapshot(&clock_infos)
                    .context("Failed to write clock snapshot")?;
                clocks_written = true;
                // Only write the first clock snapshot we find
                break;
            }
        }
    }

    if !clocks_written {
        println!("Warning: No clock snapshots found in trace");
    }

    Ok(())
}

/// Extract and write process tree (processes and threads) from the trace
///
/// Scans for ProcessDescriptor and ThreadDescriptor packets to build
/// the process hierarchy and thread information.
fn extract_process_tree(trace: &Trace, output: &mut dyn TraceOutput) -> Result<()> {
    // Track which processes and threads we've seen to avoid duplicates
    let mut seen_processes = HashMap::new();
    let mut seen_threads = HashMap::new();

    for packet in &trace.packet {
        // Extract process descriptors
        if packet.has_process_descriptor() {
            let process_desc = packet.process_descriptor();

            if process_desc.has_pid() {
                let pid = process_desc.pid();

                // Only write each process once
                if let std::collections::hash_map::Entry::Vacant(e) = seen_processes.entry(pid) {
                    let process_name = if process_desc.has_process_name() {
                        process_desc.process_name()
                    } else {
                        "unknown"
                    };

                    // Extract cmdline if available
                    let cmdline: Vec<String> =
                        process_desc.cmdline.iter().map(|s| s.to_string()).collect();

                    output
                        .write_process(pid, process_name, &cmdline)
                        .with_context(|| {
                            format!("Failed to write process descriptor for PID {}", pid)
                        })?;

                    e.insert(process_name.to_string());
                }
            }
        }

        // Extract thread descriptors
        if packet.has_thread_descriptor() {
            let thread_desc = packet.thread_descriptor();

            if thread_desc.has_pid() && thread_desc.has_tid() {
                let pid = thread_desc.pid();
                let tid = thread_desc.tid();

                // Only write each thread once
                if let std::collections::hash_map::Entry::Vacant(e) = seen_threads.entry(tid) {
                    let thread_name = if thread_desc.has_thread_name() {
                        thread_desc.thread_name()
                    } else {
                        "unknown"
                    };

                    // Ensure the parent process exists
                    if let std::collections::hash_map::Entry::Vacant(e) = seen_processes.entry(pid)
                    {
                        // Create a placeholder process
                        output.write_process(pid, "unknown", &[]).with_context(|| {
                            format!("Failed to write placeholder process for PID {}", pid)
                        })?;
                        e.insert("unknown".to_string());
                    }

                    output
                        .write_thread(tid, pid, thread_name)
                        .with_context(|| {
                            format!("Failed to write thread descriptor for TID {}", tid)
                        })?;

                    e.insert(thread_name.to_string());
                }
            }
        }
    }

    println!(
        "Extracted {} processes and {} threads",
        seen_processes.len(),
        seen_threads.len()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_range_empty_trace() {
        let trace = Trace::default();
        let (start, end) = extract_timestamp_range(&trace);
        assert_eq!(start, 0);
        assert_eq!(end, 0);
    }
}
