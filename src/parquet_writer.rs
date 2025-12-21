//! Parquet-based trace writer for direct parquet output.
//!
//! This module provides a TraceWriter implementation that writes trace data
//! directly to Parquet files, allowing comparison with the Perfetto protobuf format.

use std::collections::HashMap;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};

use anyhow::Result;
use arrow::array::{
    BooleanBuilder, Float64Builder, Int32Builder, Int64Builder, RecordBatch, StringBuilder,
};
use arrow::datatypes::{DataType, Field, Schema};
use parquet::arrow::ArrowWriter;
use parquet::basic::Compression;
use parquet::file::properties::WriterProperties;
use perfetto_protos::counter_descriptor::counter_descriptor::Unit;
use perfetto_protos::ftrace_event_bundle::ftrace_event_bundle::CompactSched;
use perfetto_protos::trace_packet::TracePacket;
use perfetto_protos::track_event::track_event::Type;
use regex::Regex;

use crate::perfetto::TraceWriter;

/// Batch size for writing records to parquet
const PARQUET_BATCH_SIZE: usize = 100_000;

/// Track name for network interface metadata in Perfetto traces.
const NETWORK_INTERFACES_TRACK_NAME: &str = "Network Interfaces";

/// Static regex for parsing socket track names. Compiled once at first use.
/// Pattern: Socket {socket_id}:{protocol}:{src_ip}:{src_port}->{dest_ip}:{dest_port}
/// Uses non-greedy matching (.+?) to correctly handle IPv6 addresses with colons.
static SOCKET_TRACK_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^Socket (\d+):([A-Z]+):(.+?):(\d+)->(.+?):(\d+)$")
        .expect("Invalid socket track regex pattern")
});

/// Data extracted from trace packets for parquet output
#[derive(Default)]
struct ExtractedData {
    processes: Vec<ProcessRecord>,
    threads: Vec<ThreadRecord>,
    sched_slices: Vec<SchedSliceRecord>,
    thread_states: Vec<ThreadStateRecord>,
    counters: Vec<CounterRecord>,
    counter_tracks: Vec<CounterTrackRecord>,
    slices: Vec<SliceRecord>,
    tracks: Vec<TrackRecord>,
    instants: Vec<InstantRecord>,
    args: Vec<ArgRecord>,
    instant_args: Vec<InstantArgRecord>,
    perf_samples: Vec<PerfSampleRecord>,
    // Stack trace data
    symbols: Vec<SymbolRecord>,
    mappings: Vec<MappingRecord>,
    frames: Vec<FrameRecord>,
    callsites: Vec<CallsiteRecord>,
    // Network metadata
    network_interfaces: Vec<NetworkInterfaceRecord>,
    socket_connections: Vec<SocketConnectionRecord>,
    // Clock snapshot data
    clock_snapshots: Vec<ClockSnapshotRecord>,
}

#[derive(Clone)]
struct ThreadStateRecord {
    ts: i64,
    dur: i64,
    utid: i64,
    state: i32,
    cpu: Option<i32>,
}

#[derive(Clone)]
struct PerfSampleRecord {
    ts: i64,
    utid: i64,
    callsite_id: Option<i64>,
    cpu: Option<i32>,
}

#[derive(Clone)]
struct ProcessRecord {
    upid: i64,
    pid: i32,
    name: Option<String>,
    parent_upid: Option<i64>,
}

#[derive(Clone)]
struct ThreadRecord {
    utid: i64,
    tid: i32,
    name: Option<String>,
    upid: Option<i64>,
}

#[derive(Clone)]
struct SchedSliceRecord {
    ts: i64,
    dur: i64,
    cpu: i32,
    utid: i64,
    end_state: Option<i32>,
    priority: i32,
}

#[derive(Clone)]
struct CounterRecord {
    ts: i64,
    track_id: i64,
    value: f64,
}

#[derive(Clone)]
struct CounterTrackRecord {
    id: i64,
    name: String,
    unit: Option<String>,
}

#[derive(Clone)]
struct SliceRecord {
    id: i64,
    ts: i64,
    dur: i64,
    track_id: i64,
    utid: Option<i64>,
    name: String,
    category: Option<String>,
    depth: i32,
}

#[derive(Clone)]
struct TrackRecord {
    id: i64,
    name: String,
    parent_id: Option<i64>,
}

#[derive(Clone)]
struct InstantRecord {
    id: i64,
    ts: i64,
    track_id: i64,
    utid: Option<i64>,
    name: String,
    category: Option<String>,
}

#[derive(Clone)]
struct ArgRecord {
    slice_id: i64,
    key: String,
    int_value: Option<i64>,
    string_value: Option<String>,
    real_value: Option<f64>,
}

#[derive(Clone)]
struct InstantArgRecord {
    instant_id: i64,
    key: String,
    int_value: Option<i64>,
    string_value: Option<String>,
    real_value: Option<f64>,
}

// Stack profiling records
#[derive(Clone)]
struct SymbolRecord {
    id: i64,
    name: String,
}

#[derive(Clone)]
struct MappingRecord {
    id: i64,
    build_id: Option<String>,
    name: Option<String>,
    exact_offset: i64,
    start_offset: i64,
}

#[derive(Clone)]
struct FrameRecord {
    id: i64,
    name: Option<String>,
    mapping_id: Option<i64>,
    rel_pc: i64,
    symbol_id: Option<i64>,
}

#[derive(Clone)]
struct CallsiteRecord {
    id: i64,
    parent_id: Option<i64>,
    frame_id: i64,
    depth: i32,
}

// Network metadata records
#[derive(Clone)]
struct NetworkInterfaceRecord {
    namespace: String,
    interface_name: String,
    ip_address: String,
    address_type: String,
}

#[derive(Clone)]
struct SocketConnectionRecord {
    socket_id: i64,
    track_id: i64,
    protocol: String,
    src_ip: String,
    src_port: i32,
    dest_ip: String,
    dest_port: i32,
    address_family: String,
}

// Clock snapshot record
#[derive(Clone)]
struct ClockSnapshotRecord {
    clock_id: i32,
    clock_name: String,
    timestamp_ns: i64,
    is_primary: bool,
}

/// Paths to all parquet output files
pub struct ParquetPaths {
    pub process: PathBuf,
    pub thread: PathBuf,
    pub sched_slice: PathBuf,
    pub thread_state: PathBuf,
    pub counter: PathBuf,
    pub counter_track: PathBuf,
    pub slice: PathBuf,
    pub track: PathBuf,
    pub instant: PathBuf,
    pub args: PathBuf,
    pub instant_args: PathBuf,
    pub perf_sample: PathBuf,
    // Stack profiling tables
    pub symbol: PathBuf,
    pub mapping: PathBuf,
    pub frame: PathBuf,
    pub callsite: PathBuf,
    // Network metadata tables
    pub network_interface: PathBuf,
    pub socket_connection: PathBuf,
    // Clock snapshot table
    pub clock_snapshot: PathBuf,
}

impl ParquetPaths {
    /// Create paths for parquet files in the given directory.
    /// Files are named simply (e.g., `process.parquet`, not `trace_process.parquet`).
    pub fn new(dir: &Path) -> Self {
        Self {
            process: dir.join("process.parquet"),
            thread: dir.join("thread.parquet"),
            sched_slice: dir.join("sched_slice.parquet"),
            thread_state: dir.join("thread_state.parquet"),
            counter: dir.join("counter.parquet"),
            counter_track: dir.join("counter_track.parquet"),
            slice: dir.join("slice.parquet"),
            track: dir.join("track.parquet"),
            instant: dir.join("instant.parquet"),
            args: dir.join("args.parquet"),
            instant_args: dir.join("instant_args.parquet"),
            perf_sample: dir.join("perf_sample.parquet"),
            // Stack profiling tables
            symbol: dir.join("symbol.parquet"),
            mapping: dir.join("mapping.parquet"),
            frame: dir.join("frame.parquet"),
            callsite: dir.join("callsite.parquet"),
            // Network metadata tables
            network_interface: dir.join("network_interface.parquet"),
            socket_connection: dir.join("socket_connection.parquet"),
            // Clock snapshot table
            clock_snapshot: dir.join("clock_snapshot.parquet"),
        }
    }

    /// Get total size of all parquet files in bytes
    #[allow(dead_code)]
    pub fn total_size(&self) -> std::io::Result<u64> {
        let paths = [
            &self.process,
            &self.thread,
            &self.sched_slice,
            &self.thread_state,
            &self.counter,
            &self.counter_track,
            &self.slice,
            &self.track,
            &self.instant,
            &self.args,
            &self.instant_args,
            &self.perf_sample,
            &self.symbol,
            &self.mapping,
            &self.frame,
            &self.callsite,
            &self.network_interface,
            &self.socket_connection,
            &self.clock_snapshot,
        ];

        let mut total = 0u64;
        for path in paths {
            if path.exists() {
                total += std::fs::metadata(path)?.len();
            }
        }
        Ok(total)
    }

    /// List all files with their sizes
    #[allow(dead_code)]
    pub fn file_sizes(&self) -> Vec<(String, u64)> {
        let paths = [
            (&self.process, "process"),
            (&self.thread, "thread"),
            (&self.sched_slice, "sched_slice"),
            (&self.thread_state, "thread_state"),
            (&self.counter, "counter"),
            (&self.counter_track, "counter_track"),
            (&self.slice, "slice"),
            (&self.track, "track"),
            (&self.instant, "instant"),
            (&self.args, "args"),
            (&self.instant_args, "instant_args"),
            (&self.perf_sample, "perf_sample"),
            (&self.symbol, "symbol"),
            (&self.mapping, "mapping"),
            (&self.frame, "frame"),
            (&self.callsite, "callsite"),
            (&self.network_interface, "network_interface"),
            (&self.socket_connection, "socket_connection"),
            (&self.clock_snapshot, "clock_snapshot"),
        ];

        paths
            .iter()
            .filter_map(|(path, name)| {
                if path.exists() {
                    std::fs::metadata(path)
                        .ok()
                        .map(|m| (name.to_string(), m.len()))
                } else {
                    None
                }
            })
            .collect()
    }
}

/// A TraceWriter implementation that collects packets and writes to Parquet files.
pub struct ParquetTraceWriter {
    packets: Vec<TracePacket>,
    output_dir: PathBuf,
    packet_count: usize,
}

impl ParquetTraceWriter {
    /// Create a new ParquetTraceWriter that writes to the given directory.
    /// The directory will be created if it doesn't exist.
    pub fn new(output_dir: &Path) -> Result<Self> {
        // Create the output directory if it doesn't exist
        if !output_dir.exists() {
            fs::create_dir_all(output_dir)?;
        }
        Ok(Self {
            packets: Vec::new(),
            output_dir: output_dir.to_path_buf(),
            packet_count: 0,
        })
    }

    pub fn packet_count(&self) -> usize {
        self.packet_count
    }

    /// Flush collected packets to parquet files
    pub fn flush(&mut self) -> Result<ParquetPaths> {
        let paths = ParquetPaths::new(&self.output_dir);
        let extractor = TraceExtractor::new();
        let data = extractor.extract(&self.packets)?;
        write_data_to_parquet(&data, &paths)?;
        Ok(paths)
    }
}

impl TraceWriter for ParquetTraceWriter {
    fn write_packet(&mut self, packet: &TracePacket) -> Result<()> {
        self.packets.push(packet.clone());
        self.packet_count += 1;
        Ok(())
    }
}

/// Parse socket track name format: "Socket {id}:{protocol}:{src}:{src_port}->{dest}:{dest_port}"
fn parse_socket_track_name(name: &str, track_id: i64) -> Option<SocketConnectionRecord> {
    let caps = SOCKET_TRACK_RE.captures(name)?;

    let socket_id: i64 = caps.get(1)?.as_str().parse().ok()?;

    let protocol = match caps.get(2)?.as_str() {
        "TCP" => "TCP",
        "UDP" => "UDP",
        _ => return None,
    };

    let src_ip = caps.get(3)?.as_str().to_string();
    let src_port: i32 = caps.get(4)?.as_str().parse().ok()?;
    let dest_ip = caps.get(5)?.as_str().to_string();
    let dest_port: i32 = caps.get(6)?.as_str().parse().ok()?;

    // Validate port ranges
    if !(0..=65535).contains(&src_port) || !(0..=65535).contains(&dest_port) {
        return None;
    }

    // Infer address family
    let address_family = if src_ip.contains(':') || dest_ip.contains(':') {
        "IPv6"
    } else {
        "IPv4"
    };

    Some(SocketConnectionRecord {
        socket_id,
        track_id,
        protocol: protocol.to_string(),
        src_ip,
        src_port,
        dest_ip,
        dest_port,
        address_family: address_family.to_string(),
    })
}

/// Extracts structured data from trace packets
struct TraceExtractor {
    data: ExtractedData,
    pid_to_upid: HashMap<i32, i64>,
    tid_to_utid: HashMap<i32, i64>,
    track_uuid_to_id: HashMap<u64, i64>,
    track_uuid_to_utid: HashMap<u64, i64>,
    interned_event_names: HashMap<u64, String>,
    interned_function_names: HashMap<u64, String>,
    interned_mappings: HashMap<u64, MappingRecord>,
    interned_frames: HashMap<u64, FrameRecord>,
    interned_callstacks: HashMap<u64, Vec<u64>>,
    callsite_map: HashMap<Vec<u64>, i64>,
    callstack_iid_to_callsite: HashMap<u64, i64>,
    next_upid: i64,
    next_utid: i64,
    next_track_id: i64,
    next_slice_id: i64,
    next_instant_id: i64,
    next_callsite_id: i64,
    open_slices: HashMap<u64, Vec<usize>>, // track_uuid -> stack of slice indices
    // Network interface tracking
    network_interfaces_root_uuid: Option<u64>,
    network_namespace_tracks: HashMap<u64, String>,
    network_interface_tracks: HashMap<u64, (String, String)>,
}

impl TraceExtractor {
    fn new() -> Self {
        Self {
            data: ExtractedData::default(),
            pid_to_upid: HashMap::new(),
            tid_to_utid: HashMap::new(),
            track_uuid_to_id: HashMap::new(),
            track_uuid_to_utid: HashMap::new(),
            interned_event_names: HashMap::new(),
            interned_function_names: HashMap::new(),
            interned_mappings: HashMap::new(),
            interned_frames: HashMap::new(),
            interned_callstacks: HashMap::new(),
            callsite_map: HashMap::new(),
            callstack_iid_to_callsite: HashMap::new(),
            next_upid: 1,
            next_utid: 1,
            next_track_id: 1,
            next_slice_id: 1,
            next_instant_id: 1,
            next_callsite_id: 1,
            open_slices: HashMap::new(),
            network_interfaces_root_uuid: None,
            network_namespace_tracks: HashMap::new(),
            network_interface_tracks: HashMap::new(),
        }
    }

    fn extract(mut self, packets: &[TracePacket]) -> Result<ExtractedData> {
        for packet in packets {
            self.process_packet(packet)?;
        }
        self.finalize_stack_data();
        Ok(self.data)
    }

    fn process_packet(&mut self, packet: &TracePacket) -> Result<()> {
        self.process_clock_snapshot(packet);
        self.process_interned_data(packet);
        self.process_descriptors(packet);
        self.process_ftrace_events(packet)?;
        self.process_events(packet)?;
        self.process_perf_sample(packet)?;
        Ok(())
    }

    fn process_clock_snapshot(&mut self, packet: &TracePacket) {
        if !packet.has_clock_snapshot() {
            return;
        }

        let snapshot = packet.clock_snapshot();
        let primary_clock_id = snapshot.primary_trace_clock() as i32;

        for clock in &snapshot.clocks {
            let clock_id = clock.clock_id() as i32;
            let clock_name = match clock_id {
                0 => "UNKNOWN",
                1 => "REALTIME",
                2 => "REALTIME_COARSE",
                3 => "MONOTONIC",
                4 => "MONOTONIC_COARSE",
                5 => "MONOTONIC_RAW",
                6 => "BOOTTIME",
                9 => "TSC",
                10 => "PERF",
                _ => "UNKNOWN",
            }
            .to_string();

            let timestamp = clock.timestamp.unwrap_or(0) as i64;

            self.data.clock_snapshots.push(ClockSnapshotRecord {
                clock_id,
                clock_name,
                timestamp_ns: timestamp,
                is_primary: clock_id == primary_clock_id,
            });
        }
    }

    fn process_interned_data(&mut self, packet: &TracePacket) {
        if let Some(interned) = packet.interned_data.as_ref() {
            for event_name in &interned.event_names {
                if event_name.has_iid() && event_name.has_name() {
                    self.interned_event_names
                        .insert(event_name.iid(), event_name.name().to_string());
                }
            }

            for func_name in &interned.function_names {
                if func_name.has_iid() && func_name.has_str() {
                    let name = String::from_utf8_lossy(func_name.str()).to_string();
                    self.interned_function_names.insert(func_name.iid(), name);
                }
            }

            for mapping in &interned.mappings {
                if mapping.has_iid() {
                    let record = MappingRecord {
                        id: mapping.iid() as i64,
                        build_id: None,
                        name: None,
                        exact_offset: mapping.exact_offset() as i64,
                        start_offset: mapping.start_offset() as i64,
                    };
                    self.interned_mappings.insert(mapping.iid(), record);
                }
            }

            for frame in &interned.frames {
                if frame.has_iid() {
                    let name = if frame.has_function_name_id() {
                        self.interned_function_names
                            .get(&frame.function_name_id())
                            .cloned()
                    } else {
                        None
                    };
                    let record = FrameRecord {
                        id: frame.iid() as i64,
                        name,
                        mapping_id: frame.has_mapping_id().then(|| frame.mapping_id() as i64),
                        rel_pc: frame.rel_pc() as i64,
                        symbol_id: frame
                            .has_function_name_id()
                            .then(|| frame.function_name_id() as i64),
                    };
                    self.interned_frames.insert(frame.iid(), record);
                }
            }

            for callstack in &interned.callstacks {
                if callstack.has_iid() {
                    let iid = callstack.iid();
                    self.callstack_iid_to_callsite.remove(&iid);
                    self.interned_callstacks
                        .insert(iid, callstack.frame_ids.clone());
                }
            }
        }
    }

    fn process_descriptors(&mut self, packet: &TracePacket) {
        // Process track descriptors
        if packet.has_track_descriptor() {
            let track_desc = packet.track_descriptor();
            let uuid = track_desc.uuid();
            let name = track_desc.name().to_string();
            let parent_uuid = if track_desc.has_parent_uuid() {
                Some(track_desc.parent_uuid())
            } else {
                None
            };

            let track_id = self.next_track_id;
            self.next_track_id += 1;
            self.track_uuid_to_id.insert(uuid, track_id);

            let parent_id =
                parent_uuid.and_then(|puuid| self.track_uuid_to_id.get(&puuid).copied());

            // Propagate utid from parent track
            if let Some(puuid) = parent_uuid {
                if let Some(&parent_utid) = self.track_uuid_to_utid.get(&puuid) {
                    self.track_uuid_to_utid.insert(uuid, parent_utid);
                }
            }

            // Network interface tracking
            if name == NETWORK_INTERFACES_TRACK_NAME {
                self.network_interfaces_root_uuid = Some(uuid);
            } else if let Some(puuid) = parent_uuid {
                if Some(puuid) == self.network_interfaces_root_uuid {
                    self.network_namespace_tracks.insert(uuid, name.clone());
                } else if let Some(namespace_name) =
                    self.network_namespace_tracks.get(&puuid).cloned()
                {
                    self.network_interface_tracks
                        .insert(uuid, (namespace_name, name.clone()));
                }
            }

            // Check for socket connection in track name
            if let Some(socket_conn) = parse_socket_track_name(&name, track_id) {
                self.data.socket_connections.push(socket_conn);
            }

            if !name.is_empty() {
                self.data.tracks.push(TrackRecord {
                    id: track_id,
                    name: name.clone(),
                    parent_id,
                });
            }

            // Check for process descriptor
            if let Some(process) = track_desc.process.as_ref() {
                let pid = process.pid();
                if !self.pid_to_upid.contains_key(&pid) {
                    let upid = self.next_upid;
                    self.next_upid += 1;
                    self.pid_to_upid.insert(pid, upid);
                    // Use process_name from ProcessDescriptor, fall back to track name
                    let process_name =
                        if process.has_process_name() && !process.process_name().is_empty() {
                            Some(process.process_name().to_string())
                        } else if !name.is_empty() {
                            Some(name.clone())
                        } else {
                            None
                        };
                    self.data.processes.push(ProcessRecord {
                        upid,
                        pid,
                        name: process_name,
                        parent_upid: None,
                    });
                }
            }

            // Check for thread descriptor
            if let Some(thread) = track_desc.thread.as_ref() {
                let tid = thread.tid();
                let pid = thread.pid();

                if !self.tid_to_utid.contains_key(&tid) {
                    let utid = self.next_utid;
                    self.next_utid += 1;
                    self.tid_to_utid.insert(tid, utid);
                    self.track_uuid_to_utid.insert(uuid, utid);

                    let upid = self.pid_to_upid.get(&pid).copied();

                    // Use thread_name from ThreadDescriptor, fall back to track name
                    let thread_name =
                        if thread.has_thread_name() && !thread.thread_name().is_empty() {
                            Some(thread.thread_name().to_string())
                        } else if !name.is_empty() {
                            Some(name)
                        } else {
                            None
                        };
                    self.data.threads.push(ThreadRecord {
                        utid,
                        tid,
                        name: thread_name,
                        upid,
                    });
                }
            }

            // Check for counter descriptor
            if let Some(counter) = track_desc.counter.as_ref() {
                let unit = if counter.has_unit_name() {
                    Some(counter.unit_name().to_string())
                } else if counter.has_unit() {
                    // Convert enum to string for storage
                    match counter.unit() {
                        Unit::UNIT_COUNT => Some("count".to_string()),
                        Unit::UNIT_TIME_NS => Some("time_ns".to_string()),
                        Unit::UNIT_SIZE_BYTES => Some("size_bytes".to_string()),
                        Unit::UNIT_UNSPECIFIED => None,
                    }
                } else {
                    None
                };

                self.data.counter_tracks.push(CounterTrackRecord {
                    id: track_id,
                    name: track_desc.name().to_string(),
                    unit,
                });
            }
        }
    }

    fn process_events(&mut self, packet: &TracePacket) -> Result<()> {
        if packet.has_track_event() {
            let track_event = packet.track_event();
            let ts = packet.timestamp() as i64;
            let track_uuid = track_event.track_uuid();
            let track_id = self.track_uuid_to_id.get(&track_uuid).copied().unwrap_or(0);
            let utid = self.track_uuid_to_utid.get(&track_uuid).copied();

            // Get event name
            let name = if track_event.has_name() {
                track_event.name().to_string()
            } else if track_event.has_name_iid() {
                self.interned_event_names
                    .get(&track_event.name_iid())
                    .cloned()
                    .unwrap_or_default()
            } else {
                String::new()
            };

            let category = track_event.categories.first().map(|s| s.to_string());

            match track_event.type_() {
                Type::TYPE_SLICE_BEGIN => {
                    let slice_id = self.next_slice_id;
                    self.next_slice_id += 1;
                    let slice_index = self.data.slices.len();

                    self.data.slices.push(SliceRecord {
                        id: slice_id,
                        ts,
                        dur: 0,
                        track_id,
                        utid,
                        name: name.clone(),
                        category: category.clone(),
                        depth: 0,
                    });

                    self.open_slices
                        .entry(track_uuid)
                        .or_default()
                        .push(slice_index);

                    // Extract debug annotations as args
                    for ann in &track_event.debug_annotations {
                        let key = ann.name().to_string();
                        let (int_value, string_value, real_value) = if ann.has_uint_value() {
                            (Some(ann.uint_value() as i64), None, None)
                        } else if ann.has_int_value() {
                            (Some(ann.int_value()), None, None)
                        } else if ann.has_string_value() {
                            (None, Some(ann.string_value().to_string()), None)
                        } else if ann.has_double_value() {
                            (None, None, Some(ann.double_value()))
                        } else {
                            (None, None, None)
                        };

                        self.data.args.push(ArgRecord {
                            slice_id,
                            key,
                            int_value,
                            string_value,
                            real_value,
                        });
                    }
                }
                Type::TYPE_SLICE_END => {
                    if let Some(slice_stack) = self.open_slices.get_mut(&track_uuid) {
                        if let Some(slice_index) = slice_stack.pop() {
                            let begin_ts = self.data.slices[slice_index].ts;
                            self.data.slices[slice_index].dur = ts - begin_ts;
                        }
                    }
                }
                Type::TYPE_INSTANT => {
                    // Extract network interface metadata
                    if let Some((namespace_name, interface_name)) =
                        self.network_interface_tracks.get(&track_uuid).cloned()
                    {
                        for annotation in &track_event.debug_annotations {
                            if annotation.has_string_value() {
                                let key = annotation.name();
                                if key == "ipv4" || key == "ipv6" {
                                    self.data.network_interfaces.push(NetworkInterfaceRecord {
                                        namespace: namespace_name.clone(),
                                        interface_name: interface_name.clone(),
                                        ip_address: annotation.string_value().to_string(),
                                        address_type: key.to_string(),
                                    });
                                }
                            }
                        }
                    }

                    let instant_id = self.next_instant_id;
                    self.next_instant_id += 1;

                    self.data.instants.push(InstantRecord {
                        id: instant_id,
                        ts,
                        track_id,
                        utid,
                        name: name.clone(),
                        category,
                    });

                    // Extract debug annotations as instant args
                    for ann in &track_event.debug_annotations {
                        let key = ann.name().to_string();
                        let (int_value, string_value, real_value) = if ann.has_uint_value() {
                            (Some(ann.uint_value() as i64), None, None)
                        } else if ann.has_int_value() {
                            (Some(ann.int_value()), None, None)
                        } else if ann.has_string_value() {
                            (None, Some(ann.string_value().to_string()), None)
                        } else if ann.has_double_value() {
                            (None, None, Some(ann.double_value()))
                        } else {
                            (None, None, None)
                        };

                        self.data.instant_args.push(InstantArgRecord {
                            instant_id,
                            key,
                            int_value,
                            string_value,
                            real_value,
                        });
                    }
                }
                Type::TYPE_COUNTER => {
                    let value = if track_event.has_counter_value() {
                        track_event.counter_value() as f64
                    } else if track_event.has_double_counter_value() {
                        track_event.double_counter_value()
                    } else {
                        0.0
                    };

                    self.data.counters.push(CounterRecord {
                        ts,
                        track_id,
                        value,
                    });
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn process_ftrace_events(&mut self, packet: &TracePacket) -> Result<()> {
        if packet.has_ftrace_events() {
            let bundle = packet.ftrace_events();
            let cpu = bundle.cpu() as i32;

            // Process compact scheduler data
            if let Some(compact) = bundle.compact_sched.as_ref() {
                self.extract_compact_sched(compact, cpu)?;
            }

            // Process individual ftrace events
            for event in &bundle.event {
                let ts = event.timestamp() as i64;

                if event.has_sched_switch() {
                    let switch = event.sched_switch();
                    let next_pid = switch.next_pid();
                    let prev_pid = switch.prev_pid();

                    self.ensure_thread_exists(next_pid, Some(switch.next_comm()));
                    self.ensure_thread_exists(prev_pid, Some(switch.prev_comm()));

                    if let Some(&utid) = self.tid_to_utid.get(&next_pid) {
                        self.data.sched_slices.push(SchedSliceRecord {
                            ts,
                            dur: 0,
                            cpu,
                            utid,
                            end_state: None,
                            priority: switch.next_prio(),
                        });
                    }
                }

                if event.has_sched_waking() {
                    let waking = event.sched_waking();
                    let pid = waking.pid();
                    self.ensure_thread_exists(pid, Some(waking.comm()));

                    if let Some(&utid) = self.tid_to_utid.get(&pid) {
                        self.data.thread_states.push(ThreadStateRecord {
                            ts,
                            dur: 0,
                            utid,
                            state: 0, // TASK_RUNNING (runnable)
                            cpu: Some(waking.target_cpu()),
                        });
                    }
                }
            }
        }
        Ok(())
    }

    fn extract_compact_sched(&mut self, compact: &CompactSched, cpu: i32) -> Result<()> {
        let mut switch_ts: i64 = 0;
        for i in 0..compact.switch_timestamp.len() {
            switch_ts += compact.switch_timestamp[i] as i64;
            let next_pid = compact.switch_next_pid[i];
            let next_prio = compact.switch_next_prio.get(i).copied().unwrap_or_default();
            let comm_idx = compact
                .switch_next_comm_index
                .get(i)
                .copied()
                .unwrap_or_default() as usize;
            let comm = compact.intern_table.get(comm_idx).map(String::as_str);

            self.ensure_thread_exists(next_pid, comm);

            if let Some(&utid) = self.tid_to_utid.get(&next_pid) {
                self.data.sched_slices.push(SchedSliceRecord {
                    ts: switch_ts,
                    dur: 0,
                    cpu,
                    utid,
                    end_state: None,
                    priority: next_prio,
                });
            }
        }

        let mut waking_ts: i64 = 0;
        for i in 0..compact.waking_timestamp.len() {
            waking_ts += compact.waking_timestamp[i] as i64;
            let pid = compact.waking_pid[i];
            let target_cpu = compact
                .waking_target_cpu
                .get(i)
                .copied()
                .unwrap_or_default();
            let comm_idx = compact
                .waking_comm_index
                .get(i)
                .copied()
                .unwrap_or_default() as usize;
            let comm = compact.intern_table.get(comm_idx).map(String::as_str);

            self.ensure_thread_exists(pid, comm);

            if let Some(&utid) = self.tid_to_utid.get(&pid) {
                self.data.thread_states.push(ThreadStateRecord {
                    ts: waking_ts,
                    dur: 0,
                    utid,
                    state: 0, // TASK_RUNNING (runnable)
                    cpu: Some(target_cpu),
                });
            }
        }
        Ok(())
    }

    fn ensure_thread_exists(&mut self, tid: i32, name: Option<&str>) {
        if let std::collections::hash_map::Entry::Vacant(e) = self.tid_to_utid.entry(tid) {
            let utid = self.next_utid;
            self.next_utid += 1;
            e.insert(utid);

            let upid = if let Some(&existing) = self.pid_to_upid.get(&tid) {
                existing
            } else {
                let upid = self.next_upid;
                self.next_upid += 1;
                self.pid_to_upid.insert(tid, upid);
                self.data.processes.push(ProcessRecord {
                    upid,
                    pid: tid,
                    name: name.map(str::to_string),
                    parent_upid: None,
                });
                upid
            };

            self.data.threads.push(ThreadRecord {
                utid,
                tid,
                name: name.map(ToOwned::to_owned),
                upid: Some(upid),
            });
        }
    }

    fn process_perf_sample(&mut self, packet: &TracePacket) -> Result<()> {
        if packet.has_perf_sample() {
            let sample = packet.perf_sample();
            let ts = packet.timestamp() as i64;
            let tid = sample.tid() as i32;
            let tgid = sample.pid() as i32;
            let cpu = if sample.has_cpu() {
                Some(sample.cpu() as i32)
            } else {
                None
            };

            // Ensure process exists
            if let std::collections::hash_map::Entry::Vacant(e) = self.pid_to_upid.entry(tgid) {
                let upid = self.next_upid;
                self.next_upid += 1;
                e.insert(upid);
                self.data.processes.push(ProcessRecord {
                    upid,
                    pid: tgid,
                    name: None,
                    parent_upid: None,
                });
            }

            self.ensure_thread_exists(tid, None);

            let callsite_id = if sample.has_callstack_iid() {
                let iid = sample.callstack_iid();
                if let Some(&cached) = self.callstack_iid_to_callsite.get(&iid) {
                    Some(cached)
                } else if let Some(frame_ids) = self.interned_callstacks.get(&iid).cloned() {
                    let id = self.get_or_create_callsite(&frame_ids);
                    self.callstack_iid_to_callsite.insert(iid, id);
                    Some(id)
                } else {
                    None
                }
            } else {
                None
            };

            if let Some(&utid) = self.tid_to_utid.get(&tid) {
                self.data.perf_samples.push(PerfSampleRecord {
                    ts,
                    utid,
                    callsite_id,
                    cpu,
                });
            }
        }
        Ok(())
    }

    fn get_or_create_callsite(&mut self, frame_ids: &[u64]) -> i64 {
        if frame_ids.is_empty() {
            return 0;
        }

        let num_frames = frame_ids.len();
        let reversed_key: Vec<u64> = frame_ids.iter().rev().copied().collect();
        if let Some(&id) = self.callsite_map.get(&reversed_key) {
            return id;
        }

        let mut parent_id: Option<i64> = None;
        let mut current_prefix: Vec<u64> = Vec::new();
        let mut leaf_callsite_id: i64 = 0;

        for (i, &frame_iid) in frame_ids.iter().rev().enumerate() {
            current_prefix.push(frame_iid);

            if let Some(&existing_id) = self.callsite_map.get(&current_prefix) {
                parent_id = Some(existing_id);
                leaf_callsite_id = existing_id;
                continue;
            }

            let callsite_id = self.next_callsite_id;
            self.next_callsite_id += 1;

            self.data.callsites.push(CallsiteRecord {
                id: callsite_id,
                parent_id,
                frame_id: frame_iid as i64,
                depth: (num_frames - 1 - i) as i32,
            });

            self.callsite_map
                .insert(current_prefix.clone(), callsite_id);
            parent_id = Some(callsite_id);
            leaf_callsite_id = callsite_id;
        }

        leaf_callsite_id
    }

    fn finalize_stack_data(&mut self) {
        for (iid, name) in self.interned_function_names.drain() {
            self.data.symbols.push(SymbolRecord {
                id: iid as i64,
                name,
            });
        }

        for (_, mapping) in self.interned_mappings.drain() {
            self.data.mappings.push(mapping);
        }

        for (_, frame) in self.interned_frames.drain() {
            self.data.frames.push(frame);
        }
    }
}

/// Write extracted data to parquet files
fn write_data_to_parquet(data: &ExtractedData, paths: &ParquetPaths) -> Result<()> {
    let props = WriterProperties::builder()
        .set_compression(Compression::ZSTD(Default::default()))
        .build();

    // Write processes
    if !data.processes.is_empty() {
        write_processes(&data.processes, &paths.process, &props)?;
    }

    // Write threads
    if !data.threads.is_empty() {
        write_threads(&data.threads, &paths.thread, &props)?;
    }

    // Write sched slices
    if !data.sched_slices.is_empty() {
        write_sched_slices(&data.sched_slices, &paths.sched_slice, &props)?;
    }

    // Write thread states
    if !data.thread_states.is_empty() {
        write_thread_states(&data.thread_states, &paths.thread_state, &props)?;
    }

    // Write counters
    if !data.counters.is_empty() {
        write_counters(&data.counters, &paths.counter, &props)?;
    }

    // Write counter tracks
    if !data.counter_tracks.is_empty() {
        write_counter_tracks(&data.counter_tracks, &paths.counter_track, &props)?;
    }

    // Write slices
    if !data.slices.is_empty() {
        write_slices(&data.slices, &paths.slice, &props)?;
    }

    // Write tracks
    if !data.tracks.is_empty() {
        write_tracks(&data.tracks, &paths.track, &props)?;
    }

    // Write instants
    if !data.instants.is_empty() {
        write_instants(&data.instants, &paths.instant, &props)?;
    }

    // Write args
    if !data.args.is_empty() {
        write_args(&data.args, &paths.args, &props)?;
    }

    // Write instant args
    if !data.instant_args.is_empty() {
        write_instant_args(&data.instant_args, &paths.instant_args, &props)?;
    }

    // Write perf samples
    if !data.perf_samples.is_empty() {
        write_perf_samples(&data.perf_samples, &paths.perf_sample, &props)?;
    }

    // Write symbols
    if !data.symbols.is_empty() {
        write_symbols(&data.symbols, &paths.symbol, &props)?;
    }

    // Write mappings
    if !data.mappings.is_empty() {
        write_mappings(&data.mappings, &paths.mapping, &props)?;
    }

    // Write frames
    if !data.frames.is_empty() {
        write_frames(&data.frames, &paths.frame, &props)?;
    }

    // Write callsites
    if !data.callsites.is_empty() {
        write_callsites(&data.callsites, &paths.callsite, &props)?;
    }

    // Write network interfaces
    if !data.network_interfaces.is_empty() {
        write_network_interfaces(&data.network_interfaces, &paths.network_interface, &props)?;
    }

    // Write socket connections
    if !data.socket_connections.is_empty() {
        write_socket_connections(&data.socket_connections, &paths.socket_connection, &props)?;
    }

    // Write clock snapshots
    if !data.clock_snapshots.is_empty() {
        write_clock_snapshots(&data.clock_snapshots, &paths.clock_snapshot, &props)?;
    }

    Ok(())
}

fn write_processes(
    records: &[ProcessRecord],
    path: &PathBuf,
    props: &WriterProperties,
) -> Result<()> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("upid", DataType::Int64, false),
        Field::new("pid", DataType::Int32, false),
        Field::new("name", DataType::Utf8, true),
        Field::new("parent_upid", DataType::Int64, true),
    ]));

    let file = File::create(path)?;
    let mut writer = ArrowWriter::try_new(file, schema.clone(), Some(props.clone()))?;

    for chunk in records.chunks(PARQUET_BATCH_SIZE) {
        let mut upid_builder = Int64Builder::with_capacity(chunk.len());
        let mut pid_builder = Int32Builder::with_capacity(chunk.len());
        let mut name_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 32);
        let mut parent_upid_builder = Int64Builder::with_capacity(chunk.len());

        for record in chunk {
            upid_builder.append_value(record.upid);
            pid_builder.append_value(record.pid);
            name_builder.append_option(record.name.as_deref());
            parent_upid_builder.append_option(record.parent_upid);
        }

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(upid_builder.finish()),
                Arc::new(pid_builder.finish()),
                Arc::new(name_builder.finish()),
                Arc::new(parent_upid_builder.finish()),
            ],
        )?;

        writer.write(&batch)?;
    }

    writer.close()?;
    Ok(())
}

fn write_threads(records: &[ThreadRecord], path: &PathBuf, props: &WriterProperties) -> Result<()> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("utid", DataType::Int64, false),
        Field::new("tid", DataType::Int32, false),
        Field::new("name", DataType::Utf8, true),
        Field::new("upid", DataType::Int64, true),
    ]));

    let file = File::create(path)?;
    let mut writer = ArrowWriter::try_new(file, schema.clone(), Some(props.clone()))?;

    for chunk in records.chunks(PARQUET_BATCH_SIZE) {
        let mut utid_builder = Int64Builder::with_capacity(chunk.len());
        let mut tid_builder = Int32Builder::with_capacity(chunk.len());
        let mut name_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 32);
        let mut upid_builder = Int64Builder::with_capacity(chunk.len());

        for record in chunk {
            utid_builder.append_value(record.utid);
            tid_builder.append_value(record.tid);
            name_builder.append_option(record.name.as_deref());
            upid_builder.append_option(record.upid);
        }

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(utid_builder.finish()),
                Arc::new(tid_builder.finish()),
                Arc::new(name_builder.finish()),
                Arc::new(upid_builder.finish()),
            ],
        )?;

        writer.write(&batch)?;
    }

    writer.close()?;
    Ok(())
}

fn write_sched_slices(
    records: &[SchedSliceRecord],
    path: &PathBuf,
    props: &WriterProperties,
) -> Result<()> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("ts", DataType::Int64, false),
        Field::new("dur", DataType::Int64, false),
        Field::new("cpu", DataType::Int32, false),
        Field::new("utid", DataType::Int64, false),
        Field::new("end_state", DataType::Int32, true),
        Field::new("priority", DataType::Int32, false),
    ]));

    let file = File::create(path)?;
    let mut writer = ArrowWriter::try_new(file, schema.clone(), Some(props.clone()))?;

    for chunk in records.chunks(PARQUET_BATCH_SIZE) {
        let mut ts_builder = Int64Builder::with_capacity(chunk.len());
        let mut dur_builder = Int64Builder::with_capacity(chunk.len());
        let mut cpu_builder = Int32Builder::with_capacity(chunk.len());
        let mut utid_builder = Int64Builder::with_capacity(chunk.len());
        let mut end_state_builder = Int32Builder::with_capacity(chunk.len());
        let mut priority_builder = Int32Builder::with_capacity(chunk.len());

        for record in chunk {
            ts_builder.append_value(record.ts);
            dur_builder.append_value(record.dur);
            cpu_builder.append_value(record.cpu);
            utid_builder.append_value(record.utid);
            end_state_builder.append_option(record.end_state);
            priority_builder.append_value(record.priority);
        }

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(ts_builder.finish()),
                Arc::new(dur_builder.finish()),
                Arc::new(cpu_builder.finish()),
                Arc::new(utid_builder.finish()),
                Arc::new(end_state_builder.finish()),
                Arc::new(priority_builder.finish()),
            ],
        )?;

        writer.write(&batch)?;
    }

    writer.close()?;
    Ok(())
}

fn write_counters(
    records: &[CounterRecord],
    path: &PathBuf,
    props: &WriterProperties,
) -> Result<()> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("ts", DataType::Int64, false),
        Field::new("track_id", DataType::Int64, false),
        Field::new("value", DataType::Float64, false),
    ]));

    let file = File::create(path)?;
    let mut writer = ArrowWriter::try_new(file, schema.clone(), Some(props.clone()))?;

    for chunk in records.chunks(PARQUET_BATCH_SIZE) {
        let mut ts_builder = Int64Builder::with_capacity(chunk.len());
        let mut track_id_builder = Int64Builder::with_capacity(chunk.len());
        let mut value_builder = Float64Builder::with_capacity(chunk.len());

        for record in chunk {
            ts_builder.append_value(record.ts);
            track_id_builder.append_value(record.track_id);
            value_builder.append_value(record.value);
        }

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(ts_builder.finish()),
                Arc::new(track_id_builder.finish()),
                Arc::new(value_builder.finish()),
            ],
        )?;

        writer.write(&batch)?;
    }

    writer.close()?;
    Ok(())
}

fn write_counter_tracks(
    records: &[CounterTrackRecord],
    path: &PathBuf,
    props: &WriterProperties,
) -> Result<()> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("name", DataType::Utf8, false),
        Field::new("unit", DataType::Utf8, true),
    ]));

    let file = File::create(path)?;
    let mut writer = ArrowWriter::try_new(file, schema.clone(), Some(props.clone()))?;

    for chunk in records.chunks(PARQUET_BATCH_SIZE) {
        let mut id_builder = Int64Builder::with_capacity(chunk.len());
        let mut name_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 32);
        let mut unit_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 8);

        for record in chunk {
            id_builder.append_value(record.id);
            name_builder.append_value(&record.name);
            unit_builder.append_option(record.unit.as_deref());
        }

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(id_builder.finish()),
                Arc::new(name_builder.finish()),
                Arc::new(unit_builder.finish()),
            ],
        )?;

        writer.write(&batch)?;
    }

    writer.close()?;
    Ok(())
}

fn write_slices(records: &[SliceRecord], path: &PathBuf, props: &WriterProperties) -> Result<()> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("ts", DataType::Int64, false),
        Field::new("dur", DataType::Int64, false),
        Field::new("track_id", DataType::Int64, false),
        Field::new("utid", DataType::Int64, true),
        Field::new("name", DataType::Utf8, false),
        Field::new("category", DataType::Utf8, true),
        Field::new("depth", DataType::Int32, false),
    ]));

    let file = File::create(path)?;
    let mut writer = ArrowWriter::try_new(file, schema.clone(), Some(props.clone()))?;

    for chunk in records.chunks(PARQUET_BATCH_SIZE) {
        let mut id_builder = Int64Builder::with_capacity(chunk.len());
        let mut ts_builder = Int64Builder::with_capacity(chunk.len());
        let mut dur_builder = Int64Builder::with_capacity(chunk.len());
        let mut track_id_builder = Int64Builder::with_capacity(chunk.len());
        let mut utid_builder = Int64Builder::with_capacity(chunk.len());
        let mut name_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 32);
        let mut category_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 16);
        let mut depth_builder = Int32Builder::with_capacity(chunk.len());

        for record in chunk {
            id_builder.append_value(record.id);
            ts_builder.append_value(record.ts);
            dur_builder.append_value(record.dur);
            track_id_builder.append_value(record.track_id);
            utid_builder.append_option(record.utid);
            name_builder.append_value(&record.name);
            category_builder.append_option(record.category.as_deref());
            depth_builder.append_value(record.depth);
        }

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(id_builder.finish()),
                Arc::new(ts_builder.finish()),
                Arc::new(dur_builder.finish()),
                Arc::new(track_id_builder.finish()),
                Arc::new(utid_builder.finish()),
                Arc::new(name_builder.finish()),
                Arc::new(category_builder.finish()),
                Arc::new(depth_builder.finish()),
            ],
        )?;

        writer.write(&batch)?;
    }

    writer.close()?;
    Ok(())
}

fn write_tracks(records: &[TrackRecord], path: &PathBuf, props: &WriterProperties) -> Result<()> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("name", DataType::Utf8, false),
        Field::new("parent_id", DataType::Int64, true),
    ]));

    let file = File::create(path)?;
    let mut writer = ArrowWriter::try_new(file, schema.clone(), Some(props.clone()))?;

    for chunk in records.chunks(PARQUET_BATCH_SIZE) {
        let mut id_builder = Int64Builder::with_capacity(chunk.len());
        let mut name_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 32);
        let mut parent_id_builder = Int64Builder::with_capacity(chunk.len());

        for record in chunk {
            id_builder.append_value(record.id);
            name_builder.append_value(&record.name);
            parent_id_builder.append_option(record.parent_id);
        }

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(id_builder.finish()),
                Arc::new(name_builder.finish()),
                Arc::new(parent_id_builder.finish()),
            ],
        )?;

        writer.write(&batch)?;
    }

    writer.close()?;
    Ok(())
}

fn write_instants(
    records: &[InstantRecord],
    path: &PathBuf,
    props: &WriterProperties,
) -> Result<()> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("ts", DataType::Int64, false),
        Field::new("track_id", DataType::Int64, false),
        Field::new("utid", DataType::Int64, true),
        Field::new("name", DataType::Utf8, false),
        Field::new("category", DataType::Utf8, true),
    ]));

    let file = File::create(path)?;
    let mut writer = ArrowWriter::try_new(file, schema.clone(), Some(props.clone()))?;

    for chunk in records.chunks(PARQUET_BATCH_SIZE) {
        let mut id_builder = Int64Builder::with_capacity(chunk.len());
        let mut ts_builder = Int64Builder::with_capacity(chunk.len());
        let mut track_id_builder = Int64Builder::with_capacity(chunk.len());
        let mut utid_builder = Int64Builder::with_capacity(chunk.len());
        let mut name_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 32);
        let mut category_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 16);

        for record in chunk {
            id_builder.append_value(record.id);
            ts_builder.append_value(record.ts);
            track_id_builder.append_value(record.track_id);
            utid_builder.append_option(record.utid);
            name_builder.append_value(&record.name);
            category_builder.append_option(record.category.as_deref());
        }

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(id_builder.finish()),
                Arc::new(ts_builder.finish()),
                Arc::new(track_id_builder.finish()),
                Arc::new(utid_builder.finish()),
                Arc::new(name_builder.finish()),
                Arc::new(category_builder.finish()),
            ],
        )?;

        writer.write(&batch)?;
    }

    writer.close()?;
    Ok(())
}

fn write_args(records: &[ArgRecord], path: &PathBuf, props: &WriterProperties) -> Result<()> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("slice_id", DataType::Int64, false),
        Field::new("key", DataType::Utf8, false),
        Field::new("int_value", DataType::Int64, true),
        Field::new("string_value", DataType::Utf8, true),
        Field::new("real_value", DataType::Float64, true),
    ]));

    let file = File::create(path)?;
    let mut writer = ArrowWriter::try_new(file, schema.clone(), Some(props.clone()))?;

    for chunk in records.chunks(PARQUET_BATCH_SIZE) {
        let mut slice_id_builder = Int64Builder::with_capacity(chunk.len());
        let mut key_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 16);
        let mut int_value_builder = Int64Builder::with_capacity(chunk.len());
        let mut string_value_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 32);
        let mut real_value_builder = Float64Builder::with_capacity(chunk.len());

        for record in chunk {
            slice_id_builder.append_value(record.slice_id);
            key_builder.append_value(&record.key);
            int_value_builder.append_option(record.int_value);
            string_value_builder.append_option(record.string_value.as_deref());
            real_value_builder.append_option(record.real_value);
        }

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(slice_id_builder.finish()),
                Arc::new(key_builder.finish()),
                Arc::new(int_value_builder.finish()),
                Arc::new(string_value_builder.finish()),
                Arc::new(real_value_builder.finish()),
            ],
        )?;

        writer.write(&batch)?;
    }

    writer.close()?;
    Ok(())
}

fn write_instant_args(
    records: &[InstantArgRecord],
    path: &PathBuf,
    props: &WriterProperties,
) -> Result<()> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("instant_id", DataType::Int64, false),
        Field::new("key", DataType::Utf8, false),
        Field::new("int_value", DataType::Int64, true),
        Field::new("string_value", DataType::Utf8, true),
        Field::new("real_value", DataType::Float64, true),
    ]));

    let file = File::create(path)?;
    let mut writer = ArrowWriter::try_new(file, schema.clone(), Some(props.clone()))?;

    for chunk in records.chunks(PARQUET_BATCH_SIZE) {
        let mut instant_id_builder = Int64Builder::with_capacity(chunk.len());
        let mut key_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 16);
        let mut int_value_builder = Int64Builder::with_capacity(chunk.len());
        let mut string_value_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 32);
        let mut real_value_builder = Float64Builder::with_capacity(chunk.len());

        for record in chunk {
            instant_id_builder.append_value(record.instant_id);
            key_builder.append_value(&record.key);
            int_value_builder.append_option(record.int_value);
            string_value_builder.append_option(record.string_value.as_deref());
            real_value_builder.append_option(record.real_value);
        }

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(instant_id_builder.finish()),
                Arc::new(key_builder.finish()),
                Arc::new(int_value_builder.finish()),
                Arc::new(string_value_builder.finish()),
                Arc::new(real_value_builder.finish()),
            ],
        )?;

        writer.write(&batch)?;
    }

    writer.close()?;
    Ok(())
}

fn write_thread_states(
    records: &[ThreadStateRecord],
    path: &PathBuf,
    props: &WriterProperties,
) -> Result<()> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("ts", DataType::Int64, false),
        Field::new("dur", DataType::Int64, false),
        Field::new("utid", DataType::Int64, false),
        Field::new("state", DataType::Int32, false),
        Field::new("cpu", DataType::Int32, true),
    ]));

    let file = File::create(path)?;
    let mut writer = ArrowWriter::try_new(file, schema.clone(), Some(props.clone()))?;

    for chunk in records.chunks(PARQUET_BATCH_SIZE) {
        let mut ts_builder = Int64Builder::with_capacity(chunk.len());
        let mut dur_builder = Int64Builder::with_capacity(chunk.len());
        let mut utid_builder = Int64Builder::with_capacity(chunk.len());
        let mut state_builder = Int32Builder::with_capacity(chunk.len());
        let mut cpu_builder = Int32Builder::with_capacity(chunk.len());

        for record in chunk {
            ts_builder.append_value(record.ts);
            dur_builder.append_value(record.dur);
            utid_builder.append_value(record.utid);
            state_builder.append_value(record.state);
            cpu_builder.append_option(record.cpu);
        }

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(ts_builder.finish()),
                Arc::new(dur_builder.finish()),
                Arc::new(utid_builder.finish()),
                Arc::new(state_builder.finish()),
                Arc::new(cpu_builder.finish()),
            ],
        )?;

        writer.write(&batch)?;
    }

    writer.close()?;
    Ok(())
}

fn write_perf_samples(
    records: &[PerfSampleRecord],
    path: &PathBuf,
    props: &WriterProperties,
) -> Result<()> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("ts", DataType::Int64, false),
        Field::new("utid", DataType::Int64, false),
        Field::new("callsite_id", DataType::Int64, true),
        Field::new("cpu", DataType::Int32, true),
    ]));

    let file = File::create(path)?;
    let mut writer = ArrowWriter::try_new(file, schema.clone(), Some(props.clone()))?;

    for chunk in records.chunks(PARQUET_BATCH_SIZE) {
        let mut ts_builder = Int64Builder::with_capacity(chunk.len());
        let mut utid_builder = Int64Builder::with_capacity(chunk.len());
        let mut callsite_id_builder = Int64Builder::with_capacity(chunk.len());
        let mut cpu_builder = Int32Builder::with_capacity(chunk.len());

        for record in chunk {
            ts_builder.append_value(record.ts);
            utid_builder.append_value(record.utid);
            callsite_id_builder.append_option(record.callsite_id);
            cpu_builder.append_option(record.cpu);
        }

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(ts_builder.finish()),
                Arc::new(utid_builder.finish()),
                Arc::new(callsite_id_builder.finish()),
                Arc::new(cpu_builder.finish()),
            ],
        )?;

        writer.write(&batch)?;
    }

    writer.close()?;
    Ok(())
}

fn write_symbols(records: &[SymbolRecord], path: &PathBuf, props: &WriterProperties) -> Result<()> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("name", DataType::Utf8, false),
    ]));

    let file = File::create(path)?;
    let mut writer = ArrowWriter::try_new(file, schema.clone(), Some(props.clone()))?;

    for chunk in records.chunks(PARQUET_BATCH_SIZE) {
        let mut id_builder = Int64Builder::with_capacity(chunk.len());
        let mut name_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 64);

        for record in chunk {
            id_builder.append_value(record.id);
            name_builder.append_value(&record.name);
        }

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(id_builder.finish()),
                Arc::new(name_builder.finish()),
            ],
        )?;

        writer.write(&batch)?;
    }

    writer.close()?;
    Ok(())
}

fn write_mappings(
    records: &[MappingRecord],
    path: &PathBuf,
    props: &WriterProperties,
) -> Result<()> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("build_id", DataType::Utf8, true),
        Field::new("name", DataType::Utf8, true),
        Field::new("exact_offset", DataType::Int64, false),
        Field::new("start_offset", DataType::Int64, false),
    ]));

    let file = File::create(path)?;
    let mut writer = ArrowWriter::try_new(file, schema.clone(), Some(props.clone()))?;

    for chunk in records.chunks(PARQUET_BATCH_SIZE) {
        let mut id_builder = Int64Builder::with_capacity(chunk.len());
        let mut build_id_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 40);
        let mut name_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 64);
        let mut exact_offset_builder = Int64Builder::with_capacity(chunk.len());
        let mut start_offset_builder = Int64Builder::with_capacity(chunk.len());

        for record in chunk {
            id_builder.append_value(record.id);
            build_id_builder.append_option(record.build_id.as_deref());
            name_builder.append_option(record.name.as_deref());
            exact_offset_builder.append_value(record.exact_offset);
            start_offset_builder.append_value(record.start_offset);
        }

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(id_builder.finish()),
                Arc::new(build_id_builder.finish()),
                Arc::new(name_builder.finish()),
                Arc::new(exact_offset_builder.finish()),
                Arc::new(start_offset_builder.finish()),
            ],
        )?;

        writer.write(&batch)?;
    }

    writer.close()?;
    Ok(())
}

fn write_frames(records: &[FrameRecord], path: &PathBuf, props: &WriterProperties) -> Result<()> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("name", DataType::Utf8, true),
        Field::new("mapping_id", DataType::Int64, true),
        Field::new("rel_pc", DataType::Int64, false),
        Field::new("symbol_id", DataType::Int64, true),
    ]));

    let file = File::create(path)?;
    let mut writer = ArrowWriter::try_new(file, schema.clone(), Some(props.clone()))?;

    for chunk in records.chunks(PARQUET_BATCH_SIZE) {
        let mut id_builder = Int64Builder::with_capacity(chunk.len());
        let mut name_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 64);
        let mut mapping_id_builder = Int64Builder::with_capacity(chunk.len());
        let mut rel_pc_builder = Int64Builder::with_capacity(chunk.len());
        let mut symbol_id_builder = Int64Builder::with_capacity(chunk.len());

        for record in chunk {
            id_builder.append_value(record.id);
            name_builder.append_option(record.name.as_deref());
            mapping_id_builder.append_option(record.mapping_id);
            rel_pc_builder.append_value(record.rel_pc);
            symbol_id_builder.append_option(record.symbol_id);
        }

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(id_builder.finish()),
                Arc::new(name_builder.finish()),
                Arc::new(mapping_id_builder.finish()),
                Arc::new(rel_pc_builder.finish()),
                Arc::new(symbol_id_builder.finish()),
            ],
        )?;

        writer.write(&batch)?;
    }

    writer.close()?;
    Ok(())
}

fn write_callsites(
    records: &[CallsiteRecord],
    path: &PathBuf,
    props: &WriterProperties,
) -> Result<()> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("parent_id", DataType::Int64, true),
        Field::new("frame_id", DataType::Int64, false),
        Field::new("depth", DataType::Int32, false),
    ]));

    let file = File::create(path)?;
    let mut writer = ArrowWriter::try_new(file, schema.clone(), Some(props.clone()))?;

    for chunk in records.chunks(PARQUET_BATCH_SIZE) {
        let mut id_builder = Int64Builder::with_capacity(chunk.len());
        let mut parent_id_builder = Int64Builder::with_capacity(chunk.len());
        let mut frame_id_builder = Int64Builder::with_capacity(chunk.len());
        let mut depth_builder = Int32Builder::with_capacity(chunk.len());

        for record in chunk {
            id_builder.append_value(record.id);
            parent_id_builder.append_option(record.parent_id);
            frame_id_builder.append_value(record.frame_id);
            depth_builder.append_value(record.depth);
        }

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(id_builder.finish()),
                Arc::new(parent_id_builder.finish()),
                Arc::new(frame_id_builder.finish()),
                Arc::new(depth_builder.finish()),
            ],
        )?;

        writer.write(&batch)?;
    }

    writer.close()?;
    Ok(())
}

fn write_network_interfaces(
    records: &[NetworkInterfaceRecord],
    path: &PathBuf,
    props: &WriterProperties,
) -> Result<()> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("namespace", DataType::Utf8, false),
        Field::new("interface_name", DataType::Utf8, false),
        Field::new("ip_address", DataType::Utf8, false),
        Field::new("address_type", DataType::Utf8, false),
    ]));

    let file = File::create(path)?;
    let mut writer = ArrowWriter::try_new(file, schema.clone(), Some(props.clone()))?;

    for chunk in records.chunks(PARQUET_BATCH_SIZE) {
        let mut namespace_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 32);
        let mut interface_name_builder =
            StringBuilder::with_capacity(chunk.len(), chunk.len() * 16);
        let mut ip_address_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 45);
        let mut address_type_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 4);

        for record in chunk {
            namespace_builder.append_value(&record.namespace);
            interface_name_builder.append_value(&record.interface_name);
            ip_address_builder.append_value(&record.ip_address);
            address_type_builder.append_value(&record.address_type);
        }

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(namespace_builder.finish()),
                Arc::new(interface_name_builder.finish()),
                Arc::new(ip_address_builder.finish()),
                Arc::new(address_type_builder.finish()),
            ],
        )?;

        writer.write(&batch)?;
    }

    writer.close()?;
    Ok(())
}

fn write_socket_connections(
    records: &[SocketConnectionRecord],
    path: &PathBuf,
    props: &WriterProperties,
) -> Result<()> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("socket_id", DataType::Int64, false),
        Field::new("track_id", DataType::Int64, false),
        Field::new("protocol", DataType::Utf8, false),
        Field::new("src_ip", DataType::Utf8, false),
        Field::new("src_port", DataType::Int32, false),
        Field::new("dest_ip", DataType::Utf8, false),
        Field::new("dest_port", DataType::Int32, false),
        Field::new("address_family", DataType::Utf8, false),
    ]));

    let file = File::create(path)?;
    let mut writer = ArrowWriter::try_new(file, schema.clone(), Some(props.clone()))?;

    for chunk in records.chunks(PARQUET_BATCH_SIZE) {
        let mut socket_id_builder = Int64Builder::with_capacity(chunk.len());
        let mut track_id_builder = Int64Builder::with_capacity(chunk.len());
        let mut protocol_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 3);
        let mut src_ip_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 45);
        let mut src_port_builder = Int32Builder::with_capacity(chunk.len());
        let mut dest_ip_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 45);
        let mut dest_port_builder = Int32Builder::with_capacity(chunk.len());
        let mut address_family_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 4);

        for record in chunk {
            socket_id_builder.append_value(record.socket_id);
            track_id_builder.append_value(record.track_id);
            protocol_builder.append_value(&record.protocol);
            src_ip_builder.append_value(&record.src_ip);
            src_port_builder.append_value(record.src_port);
            dest_ip_builder.append_value(&record.dest_ip);
            dest_port_builder.append_value(record.dest_port);
            address_family_builder.append_value(&record.address_family);
        }

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(socket_id_builder.finish()),
                Arc::new(track_id_builder.finish()),
                Arc::new(protocol_builder.finish()),
                Arc::new(src_ip_builder.finish()),
                Arc::new(src_port_builder.finish()),
                Arc::new(dest_ip_builder.finish()),
                Arc::new(dest_port_builder.finish()),
                Arc::new(address_family_builder.finish()),
            ],
        )?;

        writer.write(&batch)?;
    }

    writer.close()?;
    Ok(())
}

fn write_clock_snapshots(
    records: &[ClockSnapshotRecord],
    path: &PathBuf,
    props: &WriterProperties,
) -> Result<()> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("clock_id", DataType::Int32, false),
        Field::new("clock_name", DataType::Utf8, false),
        Field::new("timestamp_ns", DataType::Int64, false),
        Field::new("is_primary", DataType::Boolean, false),
    ]));

    let file = File::create(path)?;
    let mut writer = ArrowWriter::try_new(file, schema.clone(), Some(props.clone()))?;

    for chunk in records.chunks(PARQUET_BATCH_SIZE) {
        let mut clock_id_builder = Int32Builder::with_capacity(chunk.len());
        let mut clock_name_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 16);
        let mut timestamp_ns_builder = Int64Builder::with_capacity(chunk.len());
        let mut is_primary_builder = BooleanBuilder::with_capacity(chunk.len());

        for record in chunk {
            clock_id_builder.append_value(record.clock_id);
            clock_name_builder.append_value(&record.clock_name);
            timestamp_ns_builder.append_value(record.timestamp_ns);
            is_primary_builder.append_value(record.is_primary);
        }

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(clock_id_builder.finish()),
                Arc::new(clock_name_builder.finish()),
                Arc::new(timestamp_ns_builder.finish()),
                Arc::new(is_primary_builder.finish()),
            ],
        )?;

        writer.write(&batch)?;
    }

    writer.close()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use perfetto_protos::process_descriptor::ProcessDescriptor;
    use perfetto_protos::thread_descriptor::ThreadDescriptor;
    use perfetto_protos::track_descriptor::TrackDescriptor;

    #[test]
    fn test_process_name_from_process_descriptor() {
        let mut extractor = TraceExtractor::new();

        // Create a TracePacket with ProcessDescriptor that has process_name set
        let mut process = ProcessDescriptor::default();
        process.set_pid(1234);
        process.set_process_name("my_process".to_string());

        let mut track_desc = TrackDescriptor::default();
        track_desc.set_uuid(1);
        // Track name is empty, but process_name is set
        track_desc.set_name(String::new());
        track_desc.process = Some(process).into();

        let mut packet = TracePacket::default();
        packet.set_track_descriptor(track_desc);

        extractor.process_packet(&packet).unwrap();

        // Should use process_name from ProcessDescriptor, not empty track name
        assert_eq!(extractor.data.processes.len(), 1);
        assert_eq!(
            extractor.data.processes[0].name,
            Some("my_process".to_string())
        );
    }

    #[test]
    fn test_process_name_fallback_to_track_name() {
        let mut extractor = TraceExtractor::new();

        // Create a TracePacket with ProcessDescriptor that has empty process_name
        let mut process = ProcessDescriptor::default();
        process.set_pid(1234);
        // process_name not set or empty

        let mut track_desc = TrackDescriptor::default();
        track_desc.set_uuid(1);
        track_desc.set_name("track_based_name".to_string());
        track_desc.process = Some(process).into();

        let mut packet = TracePacket::default();
        packet.set_track_descriptor(track_desc);

        extractor.process_packet(&packet).unwrap();

        // Should fall back to track name when process_name is empty
        assert_eq!(extractor.data.processes.len(), 1);
        assert_eq!(
            extractor.data.processes[0].name,
            Some("track_based_name".to_string())
        );
    }

    #[test]
    fn test_thread_name_from_thread_descriptor() {
        let mut extractor = TraceExtractor::new();

        // Create a TracePacket with ThreadDescriptor that has thread_name set
        let mut thread = ThreadDescriptor::default();
        thread.set_tid(5678);
        thread.set_pid(1234);
        thread.set_thread_name("my_thread".to_string());

        let mut track_desc = TrackDescriptor::default();
        track_desc.set_uuid(1);
        // Track name is empty, but thread_name is set
        track_desc.set_name(String::new());
        track_desc.thread = Some(thread).into();

        let mut packet = TracePacket::default();
        packet.set_track_descriptor(track_desc);

        extractor.process_packet(&packet).unwrap();

        // Should use thread_name from ThreadDescriptor, not empty track name
        assert_eq!(extractor.data.threads.len(), 1);
        assert_eq!(
            extractor.data.threads[0].name,
            Some("my_thread".to_string())
        );
    }

    #[test]
    fn test_thread_name_fallback_to_track_name() {
        let mut extractor = TraceExtractor::new();

        // Create a TracePacket with ThreadDescriptor that has empty thread_name
        let mut thread = ThreadDescriptor::default();
        thread.set_tid(5678);
        thread.set_pid(1234);
        // thread_name not set or empty

        let mut track_desc = TrackDescriptor::default();
        track_desc.set_uuid(1);
        track_desc.set_name("track_based_thread".to_string());
        track_desc.thread = Some(thread).into();

        let mut packet = TracePacket::default();
        packet.set_track_descriptor(track_desc);

        extractor.process_packet(&packet).unwrap();

        // Should fall back to track name when thread_name is empty
        assert_eq!(extractor.data.threads.len(), 1);
        assert_eq!(
            extractor.data.threads[0].name,
            Some("track_based_thread".to_string())
        );
    }

    #[test]
    fn test_process_name_none_when_both_empty() {
        let mut extractor = TraceExtractor::new();

        // Create a TracePacket with ProcessDescriptor where both names are empty
        let mut process = ProcessDescriptor::default();
        process.set_pid(1234);
        // process_name not set

        let mut track_desc = TrackDescriptor::default();
        track_desc.set_uuid(1);
        // track name also empty
        track_desc.process = Some(process).into();

        let mut packet = TracePacket::default();
        packet.set_track_descriptor(track_desc);

        extractor.process_packet(&packet).unwrap();

        // Should be None when both are empty
        assert_eq!(extractor.data.processes.len(), 1);
        assert_eq!(extractor.data.processes[0].name, None);
    }

    #[test]
    fn test_thread_name_none_when_both_empty() {
        let mut extractor = TraceExtractor::new();

        // Create a TracePacket with ThreadDescriptor where both names are empty
        let mut thread = ThreadDescriptor::default();
        thread.set_tid(5678);
        thread.set_pid(1234);
        // thread_name not set

        let mut track_desc = TrackDescriptor::default();
        track_desc.set_uuid(1);
        // track name also empty
        track_desc.thread = Some(thread).into();

        let mut packet = TracePacket::default();
        packet.set_track_descriptor(track_desc);

        extractor.process_packet(&packet).unwrap();

        // Should be None when both are empty
        assert_eq!(extractor.data.threads.len(), 1);
        assert_eq!(extractor.data.threads[0].name, None);
    }
}
