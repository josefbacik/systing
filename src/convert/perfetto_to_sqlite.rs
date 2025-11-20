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
        .with_context(|| format!("Failed to open Perfetto trace file: {input_path}"))?;

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
        .with_context(|| format!("Failed to create SQLite output: {output_path}"))?;

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

    // Extract and write stack traces and perf samples
    extract_stack_traces(&trace, &mut sqlite)?;

    // Extract and write network events
    extract_network_events(&trace, &mut sqlite)?;

    // Flush and finalize the SQLite database
    sqlite.flush().context("Failed to flush SQLite database")?;

    println!("Conversion complete: {input_path} -> {output_path}");
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
                            format!("Failed to write process descriptor for PID {pid}")
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
                            format!("Failed to write placeholder process for PID {pid}")
                        })?;
                        e.insert("unknown".to_string());
                    }

                    output
                        .write_thread(tid, pid, thread_name)
                        .with_context(|| {
                            format!("Failed to write thread descriptor for TID {tid}")
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
                            Unit::UNIT_COUNT => CounterUnit::Count,
                            _ => CounterUnit::Count,
                        }
                    } else {
                        CounterUnit::Count
                    };

                    // Get the track name
                    let name = if track_desc.has_name() {
                        track_desc.name().to_string()
                    } else {
                        format!("counter_{uuid}")
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
                                format!("Failed to write counter value for track {track_uuid}")
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

/// Extract and write stack traces and perf samples from the trace
///
/// Processes InternedData packets to build a mapping of IIDs to actual data,
/// then extracts PerfSample packets and converts them to the SQLite format.
fn extract_stack_traces(trace: &Trace, output: &mut dyn TraceOutput) -> Result<()> {
    use crate::output::{PerfSampleData, StackTraceData, SymbolInfo};
    use perfetto_protos::profile_common::{Callstack, Frame, Mapping};
    use std::collections::HashMap;

    // Storage for interned data (IID -> actual data)
    let mut function_names: HashMap<u64, String> = HashMap::new();
    let mut mappings: HashMap<u64, Mapping> = HashMap::new();
    let mut frames: HashMap<u64, Frame> = HashMap::new();
    let mut callstacks: HashMap<u64, Callstack> = HashMap::new();

    // First pass: Extract all interned data
    for packet in &trace.packet {
        if let Some(interned_data) = &packet.interned_data.0 {
            // Extract function names
            for func in &interned_data.function_names {
                if func.has_iid() && func.has_str() {
                    // Convert bytes to string
                    let name = String::from_utf8_lossy(func.str()).to_string();
                    function_names.insert(func.iid(), name);
                }
            }

            // Extract mappings
            for mapping in &interned_data.mappings {
                if mapping.has_iid() {
                    mappings.insert(mapping.iid(), mapping.clone());
                }
            }

            // Extract frames
            for frame in &interned_data.frames {
                if frame.has_iid() {
                    frames.insert(frame.iid(), frame.clone());
                }
            }

            // Extract callstacks
            for callstack in &interned_data.callstacks {
                if callstack.has_iid() {
                    callstacks.insert(callstack.iid(), callstack.clone());
                }
            }
        }
    }

    println!(
        "Extracted interned data: {} functions, {} mappings, {} frames, {} callstacks",
        function_names.len(),
        mappings.len(),
        frames.len(),
        callstacks.len()
    );

    // Helper function to convert a Frame to SymbolInfo
    let frame_to_symbol = |frame: &Frame| -> Result<SymbolInfo> {
        let function_name = if frame.has_function_name_id() {
            function_names
                .get(&frame.function_name_id())
                .cloned()
                .unwrap_or_else(|| format!("unknown_{}", frame.function_name_id()))
        } else {
            "unknown".to_string()
        };

        let mapping_info = if frame.has_mapping_id() {
            mappings.get(&frame.mapping_id())
        } else {
            None
        };

        let mapping_name = mapping_info.and_then(|m| {
            if m.has_build_id() {
                Some(format!("build_id:{}", m.build_id()))
            } else {
                None
            }
        });

        Ok(SymbolInfo {
            function_name,
            file_name: None, // Perfetto doesn't typically have file info in frames
            line_number: None,
            build_id: mapping_info.and_then(|m| {
                if m.has_build_id() {
                    Some(m.build_id().to_string())
                } else {
                    None
                }
            }),
            mapping_name,
            mapping_offset: if frame.has_rel_pc() {
                Some(frame.rel_pc())
            } else {
                None
            },
        })
    };

    // Second pass: Extract PerfSample packets and convert them
    let mut sample_count = 0;
    let mut skipped_no_callstack = 0;
    let skipped_no_frames = 0; // Reserved for future use

    for packet in &trace.packet {
        if let Some(data) = &packet.data {
            use perfetto_protos::trace_packet::trace_packet::Data;

            if let Data::PerfSample(perf_sample) = data {
                if !perf_sample.has_callstack_iid() {
                    continue; // Skip samples without callstacks
                }

                let callstack_iid = perf_sample.callstack_iid();
                let callstack = match callstacks.get(&callstack_iid) {
                    Some(cs) => cs,
                    None => {
                        // Missing callstack - skip this sample
                        skipped_no_callstack += 1;
                        continue;
                    }
                };

                // Convert frame IIDs to symbols
                let mut kernel_symbols = Vec::new();
                let mut user_symbols = Vec::new();

                for &frame_iid in &callstack.frame_ids {
                    if let Some(frame) = frames.get(&frame_iid) {
                        let symbol = frame_to_symbol(frame)?;

                        // Heuristic: kernel addresses are typically very high
                        // This is a simplification - ideally we'd check the mapping
                        if frame.has_rel_pc() && frame.rel_pc() > 0xffff_0000_0000_0000 {
                            kernel_symbols.push(symbol);
                        } else {
                            user_symbols.push(symbol);
                        }
                    }
                }

                let stack_data = StackTraceData {
                    kernel_symbols,
                    user_symbols,
                    py_symbols: Vec::new(), // Python stacks not in standard Perfetto samples
                };

                let sample_data = PerfSampleData {
                    ts: packet.timestamp(),
                    tid: perf_sample.tid() as i32,
                    stack: stack_data,
                };

                output.write_perf_sample(&sample_data)?;
                sample_count += 1;
            }
        }
    }

    if sample_count > 0 {
        println!("Converted {sample_count} perf samples with stack traces");
    }

    if skipped_no_callstack > 0 {
        println!(
            "Warning: Skipped {skipped_no_callstack} perf samples due to missing callstack data"
        );
    }

    if skipped_no_frames > 0 {
        println!("Warning: Skipped {skipped_no_frames} frames due to missing frame data");
    }

    Ok(())
}

/// Extract and write network events from the trace
///
/// Processes TrackEvent slice pairs (begin/end) that represent network operations,
/// extracts connection information and event details, and writes to SQLite.
fn extract_network_events(trace: &Trace, output: &mut dyn TraceOutput) -> Result<()> {
    use crate::output::{NetworkConnection, NetworkEventData};
    use perfetto_protos::track_event::track_event::Type;
    use std::collections::HashMap;

    // Type alias to simplify complex type
    type PendingSlice = (u64, String, Vec<(String, String)>, i32);

    // Map track UUIDs to their track names and connection info
    let mut track_names: HashMap<u64, String> = HashMap::new();

    // Extract track names from TrackDescriptor packets
    for packet in &trace.packet {
        if let Some(data) = &packet.data {
            use perfetto_protos::trace_packet::trace_packet::Data;

            if let Data::TrackDescriptor(track_desc) = data {
                if track_desc.has_uuid() && track_desc.has_name() {
                    track_names.insert(track_desc.uuid(), track_desc.name().to_string());
                }
            }
        }
    }

    // Extract event names from interned data
    let mut event_names: HashMap<u64, String> = HashMap::new();
    for packet in &trace.packet {
        if let Some(interned_data) = &packet.interned_data.0 {
            for event_name in &interned_data.event_names {
                if event_name.has_iid() && event_name.has_name() {
                    event_names.insert(event_name.iid(), event_name.name().to_string());
                }
            }
        }
    }

    // Extract thread information from packets for TID lookup
    let mut thread_track_map: HashMap<u64, i32> = HashMap::new();
    for packet in &trace.packet {
        if let Some(data) = &packet.data {
            use perfetto_protos::trace_packet::trace_packet::Data;

            if let Data::TrackDescriptor(track_desc) = data {
                if track_desc.has_uuid() && track_desc.thread.0.is_some() {
                    if let Some(ref thread_desc) = track_desc.thread.0 {
                        if thread_desc.has_tid() {
                            thread_track_map.insert(track_desc.uuid(), thread_desc.tid());
                        }
                    }
                }
            }
        }
    }

    // Map to store begin events waiting for their end event
    let mut pending_slices: HashMap<u64, PendingSlice> = HashMap::new();

    let mut event_count = 0;
    let mut skipped_no_connection = 0;
    let mut skipped_no_end = 0;

    // Process TrackEvent packets
    for packet in &trace.packet {
        if let Some(data) = &packet.data {
            use perfetto_protos::trace_packet::trace_packet::Data;

            if let Data::TrackEvent(track_event) = data {
                if !track_event.has_track_uuid() {
                    continue;
                }

                let track_uuid = track_event.track_uuid();
                let track_name = track_names.get(&track_uuid).cloned().unwrap_or_default();

                // Only process network-related tracks (heuristic: check track name)
                if !track_name.contains("TCP")
                    && !track_name.contains("UDP")
                    && !track_name.contains("network")
                    && !track_name.contains("send")
                    && !track_name.contains("recv")
                {
                    continue;
                }

                let event_type = if track_event.has_type() {
                    track_event.type_()
                } else {
                    continue;
                };

                match event_type {
                    Type::TYPE_SLICE_BEGIN => {
                        // Extract event name
                        let event_name = if track_event.has_name_iid() {
                            event_names
                                .get(&track_event.name_iid())
                                .cloned()
                                .unwrap_or_default()
                        } else if track_event.has_name() {
                            track_event.name().to_string()
                        } else {
                            continue;
                        };

                        // Extract debug annotations
                        let mut annotations: Vec<(String, String)> = Vec::new();
                        for annotation in &track_event.debug_annotations {
                            if annotation.has_name() {
                                let name = annotation.name().to_string();
                                let value = if annotation.has_uint_value() {
                                    annotation.uint_value().to_string()
                                } else if annotation.has_string_value() {
                                    annotation.string_value().to_string()
                                } else {
                                    continue;
                                };
                                annotations.push((name, value));
                            }
                        }

                        // Extract TID from thread track map or use 0 as fallback
                        let tid = thread_track_map.get(&track_uuid).copied().unwrap_or(0);

                        // Store the begin event with TID
                        pending_slices.insert(
                            track_uuid,
                            (packet.timestamp(), event_name, annotations, tid),
                        );
                    }
                    Type::TYPE_SLICE_END => {
                        // Find matching begin event
                        if let Some((start_ts, event_name, annotations, tid)) =
                            pending_slices.remove(&track_uuid)
                        {
                            let end_ts = packet.timestamp();

                            // Parse connection info from track name and annotations
                            // Format: "TCP/UDP <addr>:<port>" or similar
                            let (protocol, dest_addr, dest_port) =
                                parse_network_track_name(&track_name);

                            if !protocol.is_empty() && !dest_addr.is_empty() {
                                // Create connection
                                let connection = NetworkConnection {
                                    protocol: protocol.clone(),
                                    address_family: if dest_addr.contains(':') {
                                        "IPv6".to_string()
                                    } else {
                                        "IPv4".to_string()
                                    },
                                    dest_addr: dest_addr.clone(),
                                    dest_port,
                                };

                                let connection_id = output.write_network_connection(&connection)?;

                                // Extract additional data from annotations
                                let mut bytes = None;
                                let mut sequence_num = None;
                                let mut tcp_flags = None;

                                for (name, value) in &annotations {
                                    match name.as_str() {
                                        "length" => bytes = value.parse().ok(),
                                        "seq" => sequence_num = value.parse().ok(),
                                        "flags" => {
                                            // Parse TCP flags string like "PSH|ACK"
                                            tcp_flags = parse_tcp_flags(value);
                                        }
                                        _ => {}
                                    }
                                }

                                // Create network event (TID extracted from track descriptor)
                                let network_event = NetworkEventData {
                                    connection_id,
                                    tid,
                                    track_uuid,
                                    event_type: event_name.clone(),
                                    start_ts,
                                    end_ts: Some(end_ts),
                                    bytes,
                                    sequence_num,
                                    tcp_flags,
                                };

                                output.write_network_event(&network_event)?;
                                event_count += 1;
                            } else {
                                skipped_no_connection += 1;
                            }
                        } else {
                            skipped_no_end += 1;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    if event_count > 0 {
        println!("Converted {event_count} network events");
    }

    if skipped_no_connection > 0 {
        println!(
            "Warning: Skipped {skipped_no_connection} network events due to unparseable connection info"
        );
    }

    if skipped_no_end > 0 {
        println!("Warning: {skipped_no_end} unmatched slice end events (missing begin events)");
    }

    Ok(())
}

/// Parse network track name to extract protocol, address, and port
/// Expected format: "TCP <addr>:<port>" or "UDP <addr>:<port>"
fn parse_network_track_name(track_name: &str) -> (String, String, u16) {
    let parts: Vec<&str> = track_name.split_whitespace().collect();

    if parts.len() >= 2 {
        let protocol = parts[0].to_string();
        let addr_port = parts[1];

        if let Some(colon_pos) = addr_port.rfind(':') {
            let addr = addr_port[..colon_pos].to_string();
            let port = addr_port[colon_pos + 1..].parse().unwrap_or(0);
            return (protocol, addr, port);
        }
    }

    (String::new(), String::new(), 0)
}

/// Parse TCP flags string like "PSH|ACK" into a bitfield
fn parse_tcp_flags(flags_str: &str) -> Option<u8> {
    let mut flags = 0u8;

    for flag in flags_str.split('|') {
        flags |= match flag.trim() {
            "FIN" => 0x01,
            "SYN" => 0x02,
            "RST" => 0x04,
            "PSH" => 0x08,
            "ACK" => 0x10,
            "URG" => 0x20,
            _ => 0,
        };
    }

    if flags > 0 {
        Some(flags)
    } else {
        None
    }
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
