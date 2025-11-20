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

    // Extract and write counter tracks and values
    extract_counters(&trace, &mut sqlite)?;

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

/// Extract and write counter tracks and values from the trace
///
/// Scans for TrackDescriptor packets with counter descriptors and TrackEvent packets
/// with counter values, writing them to the SQLite database using the TraceOutput abstraction.
fn extract_counters(trace: &Trace, output: &mut dyn TraceOutput) -> Result<()> {
    use crate::output::{CounterTrackInfo, CounterUnit};
    use perfetto_protos::counter_descriptor::counter_descriptor::Unit;

    // Map track UUIDs to their track info
    let mut counter_tracks: HashMap<u64, CounterTrackInfo> = HashMap::new();
    let mut track_uuids: HashMap<u64, u64> = HashMap::new(); // Perfetto UUID -> Our UUID

    // First pass: Extract counter track descriptors
    for packet in &trace.packet {
        if let Some(data) = &packet.data {
            use perfetto_protos::trace_packet::trace_packet::Data;

            if let Data::TrackDescriptor(track_desc) = data {
                // Check if this is a counter track
                if track_desc.counter.0.is_some() && track_desc.has_uuid() {
                    let uuid = track_desc.uuid();
                    let counter_desc = track_desc.counter.0.as_ref().unwrap();

                    // Determine the unit
                    let unit = if counter_desc.has_unit() {
                        match counter_desc.unit() {
                            Unit::UNIT_TIME_NS => CounterUnit::TimeNs,
                            Unit::UNIT_COUNT | _ => CounterUnit::Count,
                        }
                    } else {
                        CounterUnit::Count
                    };

                    // Get the track name
                    let name = if track_desc.has_name() {
                        track_desc.name().to_string()
                    } else {
                        format!("counter_{}", uuid)
                    };

                    // Extract CPU/PID/TID if available from parent relationships
                    // For now, we'll parse from the name since that's how we write them
                    let (cpu, pid, tid) = parse_track_scope(&name);

                    let track_info = CounterTrackInfo {
                        name: name.clone(),
                        description: None,
                        unit,
                        is_incremental: counter_desc.is_incremental.unwrap_or(false),
                        cpu,
                        pid,
                        tid,
                    };

                    counter_tracks.insert(uuid, track_info);
                }
            }
        }
    }

    // Write counter tracks and get their assigned UUIDs
    for (perfetto_uuid, track_info) in &counter_tracks {
        let assigned_uuid = output
            .write_counter_track(track_info)
            .with_context(|| format!("Failed to write counter track: {}", track_info.name))?;
        track_uuids.insert(*perfetto_uuid, assigned_uuid);
    }

    // Second pass: Extract counter values from TrackEvents
    let mut counter_value_count = 0;
    for packet in &trace.packet {
        if let Some(data) = &packet.data {
            use perfetto_protos::trace_packet::trace_packet::Data;

            if let Data::TrackEvent(track_event) = data {
                // Check if this is a counter event
                if track_event.has_type()
                    && track_event.type_()
                        == perfetto_protos::track_event::track_event::Type::TYPE_COUNTER
                    && track_event.has_track_uuid()
                {
                    let track_uuid = track_event.track_uuid();

                    // Get the assigned UUID for this track
                    if let Some(&assigned_uuid) = track_uuids.get(&track_uuid) {
                        // Get the timestamp
                        let ts = if packet.has_timestamp() {
                            packet.timestamp()
                        } else if track_event.has_timestamp_absolute_us() {
                            track_event.timestamp_absolute_us() as u64 * 1000 // Convert us to ns
                        } else {
                            continue; // Skip if no timestamp
                        };

                        // Get the counter value
                        let value = if track_event.has_counter_value() {
                            track_event.counter_value()
                        } else {
                            continue; // Skip if no value
                        };

                        output
                            .write_counter_value(assigned_uuid, ts, value)
                            .with_context(|| {
                                format!("Failed to write counter value for track {}", track_uuid)
                            })?;

                        counter_value_count += 1;
                    }
                }
            }
        }
    }

    if !counter_tracks.is_empty() {
        println!(
            "Extracted {} counter tracks with {} values",
            counter_tracks.len(),
            counter_value_count
        );
    }

    Ok(())
}

/// Parse track scope (CPU/PID/TID) from track name
///
/// Attempts to extract CPU, PID, or TID information from counter track names
/// based on common naming patterns like "runqueue_size_cpu0", "latency_cpu1", etc.
fn parse_track_scope(name: &str) -> (Option<u32>, Option<i32>, Option<i32>) {
    let mut cpu = None;
    let mut pid = None;
    let tid = None;

    // Check for CPU in name (e.g., "cpu0", "cpu1")
    if let Some(cpu_start) = name.find("cpu") {
        let cpu_str = &name[cpu_start + 3..];
        if let Some(cpu_end) = cpu_str.find(|c: char| !c.is_ascii_digit()) {
            if let Ok(cpu_num) = cpu_str[..cpu_end].parse::<u32>() {
                cpu = Some(cpu_num);
            }
        } else if let Ok(cpu_num) = cpu_str.parse::<u32>() {
            cpu = Some(cpu_num);
        }
    }

    // Check for PID in name (e.g., "pid_123")
    if let Some(pid_start) = name.find("pid_") {
        let pid_str = &name[pid_start + 4..];
        if let Some(pid_end) = pid_str.find(|c: char| !c.is_ascii_digit()) {
            if let Ok(pid_num) = pid_str[..pid_end].parse::<i32>() {
                pid = Some(pid_num);
            }
        } else if let Ok(pid_num) = pid_str.parse::<i32>() {
            pid = Some(pid_num);
        }
    }

    (cpu, pid, tid)
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
