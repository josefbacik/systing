//! systing-analyze: A tool for converting and querying Perfetto trace databases
//!
//! This tool converts Perfetto trace files directly to DuckDB databases for efficient
//! querying and analysis, supporting multiple traces aggregated into a single database.

use anyhow::{bail, Context, Result};
use arrow::array::{
    BooleanBuilder, Float64Builder, Int32Builder, Int64Builder, ListBuilder, RecordBatch,
    StringBuilder,
};
use arrow::datatypes::{DataType, Field, Schema};
use clap::{Parser, Subcommand};
use duckdb::{params, Connection};

// Import shared modules from library
use flate2::read::GzDecoder;
use indicatif::{ProgressBar, ProgressStyle};
use parquet::arrow::ArrowWriter;
use parquet::basic::Compression;
use parquet::file::properties::WriterProperties;
use perfetto_protos::ftrace_event_bundle::ftrace_event_bundle::CompactSched;
use perfetto_protos::trace_packet::TracePacket;
use protobuf::Message;
use regex::Regex;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::LazyLock;
use std::thread;
use std::time::Instant;
use systing::duckdb::{create_schema, get_trace_info, import_duckdb_traces, TraceImportMapping};
use systing::ParquetPaths;

/// Track name for network interface metadata in Perfetto traces.
const NETWORK_INTERFACES_TRACK_NAME: &str = "Network Interfaces";

/// Static regex for parsing socket track names. Compiled once at first use.
/// Pattern: Socket {socket_id}:{protocol}:{src_ip}:{src_port}->{dest_ip}:{dest_port}
/// Uses non-greedy matching (.+?) to correctly handle IPv6 addresses with colons.
static SOCKET_TRACK_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^Socket (\d+):([A-Z]+):(.+?):(\d+)->(.+?):(\d+)$")
        .expect("Invalid socket track regex pattern")
});

#[derive(Parser)]
#[command(name = "systing-analyze")]
#[command(about = "Convert and query Perfetto trace databases")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Convert trace files between formats (Perfetto/Parquet/DuckDB)
    Convert {
        /// Input trace files or directories
        #[arg(required = true)]
        inputs: Vec<PathBuf>,

        /// Output path (DuckDB .duckdb or Perfetto .pb/.pftrace/.perfetto-trace)
        #[arg(short, long)]
        output: PathBuf,

        /// Trace ID to export (required when DuckDB has multiple traces)
        #[arg(long)]
        trace_id: Option<String>,

        /// Recursively search directories for trace files
        #[arg(short, long)]
        recursive: bool,

        /// Verbose output (show timing breakdown)
        #[arg(short, long)]
        verbose: bool,
    },

    /// Run SQL queries against a DuckDB database
    Query {
        /// Path to DuckDB database
        #[arg(short, long)]
        database: PathBuf,

        /// SQL query to execute (if not provided, starts interactive mode)
        #[arg(short, long)]
        sql: Option<String>,

        /// Output format: table, csv, json
        #[arg(short, long, default_value = "table")]
        format: String,
    },

    /// Validate trace data for correctness
    Validate {
        /// Path to Parquet directory, DuckDB database, or Perfetto trace file
        #[arg(required = true)]
        path: PathBuf,

        /// Verbose output (show all checks)
        #[arg(short, long)]
        verbose: bool,

        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },
}

/// Information about a trace being processed
#[derive(Clone)]
struct TraceInfo {
    trace_id: String,
    source_path: PathBuf,
}

fn get_num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(std::num::NonZero::get)
        .unwrap_or(8)
}

fn generate_trace_id(path: &Path) -> String {
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("trace")
        .trim_end_matches(".pb")
        .trim_end_matches(".perfetto-trace")
        .trim_end_matches(".pftrace");

    let safe_id: String = stem
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect();

    if safe_id.chars().next().is_none_or(char::is_numeric) {
        format!("trace_{safe_id}")
    } else {
        safe_id
    }
}

fn walkdir(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut results = Vec::new();

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            results.extend(walkdir(&path)?);
        } else if path.is_file() {
            results.push(path);
        }
    }

    Ok(results)
}

fn is_trace_file(path: &Path) -> bool {
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    name.ends_with(".pb")
        || name.ends_with(".pb.gz")
        || name.ends_with(".perfetto-trace")
        || name.ends_with(".pftrace")
}

/// Check if a directory contains Parquet trace files (output from `systing --parquet`).
/// A valid Parquet trace directory must contain the core trace tables.
fn is_parquet_dir(path: &Path) -> bool {
    if !path.is_dir() {
        return false;
    }
    // Check for essential Parquet files - process, thread, and sched_slice are core tables
    // that should always be present in a valid systing trace
    path.join("process.parquet").exists()
        && path.join("thread.parquet").exists()
        && path.join("sched_slice.parquet").exists()
}

/// Check if a path is a DuckDB database file.
fn is_duckdb_file(path: &Path) -> bool {
    path.is_file()
        && path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("duckdb"))
}

/// Check if a path is a Perfetto trace file (output format).
fn is_perfetto_output(path: &Path) -> bool {
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    name.ends_with(".pb")
        || name.ends_with(".perfetto-trace")
        || name.ends_with(".perfetto")
        || name.ends_with(".pftrace")
}

/// Input type for trace conversion - Perfetto .pb file, Parquet directory, or DuckDB file.
#[derive(Clone, Debug)]
enum TraceInput {
    /// Perfetto protobuf trace file (.pb, .pb.gz, .perfetto-trace, .pftrace)
    PbFile(PathBuf),
    /// Directory containing Parquet trace files (from `systing --parquet`)
    ParquetDir(PathBuf),
    /// DuckDB database file (.duckdb)
    DuckDbFile(PathBuf),
}

impl TraceInput {
    #[allow(dead_code)]
    fn path(&self) -> &Path {
        match self {
            TraceInput::PbFile(p) | TraceInput::ParquetDir(p) | TraceInput::DuckDbFile(p) => p,
        }
    }
}

/// Generate a unique trace ID, appending a numeric suffix if the base ID already exists.
fn make_unique_trace_id(base_id: String, id_counts: &mut HashMap<String, usize>) -> String {
    let count = id_counts.entry(base_id.clone()).or_insert(0);
    let result = if *count > 0 {
        format!("{base_id}_{count}")
    } else {
        base_id
    };
    *count += 1;
    result
}

/// Find all trace inputs (Perfetto .pb files, Parquet directories, or DuckDB files) in the given inputs
fn find_trace_inputs(inputs: &[PathBuf], recursive: bool) -> Result<Vec<TraceInput>> {
    let mut traces = Vec::new();

    for input in inputs {
        if input.is_file() {
            if is_duckdb_file(input) {
                traces.push(TraceInput::DuckDbFile(input.clone()));
            } else if is_trace_file(input) {
                traces.push(TraceInput::PbFile(input.clone()));
            } else {
                // Warn about explicitly-provided files that aren't recognized trace formats
                eprintln!(
                    "Warning: {} is not a recognized trace format (expected .pb, .pb.gz, .perfetto-trace, .pftrace, or .duckdb)",
                    input.display()
                );
            }
        } else if input.is_dir() {
            // First check if this directory itself is a Parquet trace directory
            if is_parquet_dir(input) {
                traces.push(TraceInput::ParquetDir(input.clone()));
            } else if recursive {
                // Recursively search for .pb files, Parquet directories, and DuckDB files
                for entry in walkdir(input)? {
                    if entry.is_file() {
                        if is_duckdb_file(&entry) {
                            traces.push(TraceInput::DuckDbFile(entry));
                        } else if is_trace_file(&entry) {
                            traces.push(TraceInput::PbFile(entry));
                        }
                    } else if entry.is_dir() && is_parquet_dir(&entry) {
                        traces.push(TraceInput::ParquetDir(entry));
                    }
                }
            } else {
                // Non-recursive: check immediate children
                for entry in fs::read_dir(input)? {
                    let entry = entry?;
                    let path = entry.path();
                    if path.is_file() {
                        if is_duckdb_file(&path) {
                            traces.push(TraceInput::DuckDbFile(path));
                        } else if is_trace_file(&path) {
                            traces.push(TraceInput::PbFile(path));
                        }
                    } else if path.is_dir() && is_parquet_dir(&path) {
                        traces.push(TraceInput::ParquetDir(path));
                    }
                }
            }
        } else {
            bail!("Input path does not exist: {}", input.display());
        }
    }

    Ok(traces)
}

/// Iterator that streams TracePackets from a Perfetto trace file without loading all into memory
struct TracePacketIterator<R: BufRead> {
    reader: R,
    buffer: Vec<u8>,
}

impl<R: BufRead> TracePacketIterator<R> {
    fn new(reader: R) -> Self {
        Self {
            reader,
            buffer: Vec::with_capacity(64 * 1024),
        }
    }
}

impl<R: BufRead> Iterator for TracePacketIterator<R> {
    type Item = Result<TracePacket>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let mut tag_byte = [0u8; 1];
            match self.reader.read_exact(&mut tag_byte) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return None,
                Err(e) => return Some(Err(e.into())),
            }

            let wire_type = tag_byte[0] & 0x07;
            let field_number = tag_byte[0] >> 3;

            // Field 1 (packet), wire type 2 (length-delimited)
            if field_number == 1 && wire_type == 2 {
                let length = match read_varint(&mut self.reader) {
                    Ok(len) => len as usize,
                    Err(e) => return Some(Err(e)),
                };

                self.buffer.clear();
                if self.buffer.capacity() < length {
                    self.buffer.reserve(length - self.buffer.capacity());
                }
                self.buffer.resize(length, 0);

                if let Err(e) = self.reader.read_exact(&mut self.buffer) {
                    return Some(Err(e.into()));
                }

                return match TracePacket::parse_from_bytes(&self.buffer) {
                    Ok(packet) => Some(Ok(packet)),
                    Err(e) => Some(Err(e.into())),
                };
            }

            // Skip non-packet fields
            if let Err(e) = skip_field(&mut self.reader, wire_type) {
                return Some(Err(e));
            }
        }
    }
}

fn read_varint<R: Read>(reader: &mut R) -> Result<u64> {
    let mut result: u64 = 0;
    let mut shift = 0;
    loop {
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte)?;
        result |= ((byte[0] & 0x7f) as u64) << shift;
        if byte[0] & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            bail!("Varint too large");
        }
    }
    Ok(result)
}

fn skip_field<R: Read>(reader: &mut R, wire_type: u8) -> Result<()> {
    match wire_type {
        0 => {
            read_varint(reader)?;
        }
        1 => {
            let mut buf = [0u8; 8];
            reader.read_exact(&mut buf)?;
        }
        2 => {
            let len = read_varint(reader)? as usize;
            std::io::copy(&mut reader.take(len as u64), &mut std::io::sink())?;
        }
        5 => {
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf)?;
        }
        _ => bail!("Unknown wire type: {}", wire_type),
    }
    Ok(())
}

fn open_trace_reader(path: &Path) -> Result<Box<dyn BufRead + Send>> {
    let file = File::open(path).with_context(|| format!("Failed to open {}", path.display()))?;
    let reader = BufReader::with_capacity(256 * 1024, file);

    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    if name.ends_with(".gz") {
        let decoder = GzDecoder::new(reader);
        Ok(Box::new(BufReader::with_capacity(256 * 1024, decoder)))
    } else {
        Ok(Box::new(reader))
    }
}

/// Data extracted from a trace for database insertion
struct ExtractedData {
    processes: Vec<ProcessRecord>,
    threads: Vec<ThreadRecord>,
    sched_slices: Vec<SchedSliceRecord>,
    thread_states: Vec<ThreadStateRecord>,
    counters: Vec<CounterRecord>,
    counter_tracks: Vec<CounterTrackRecord>,
    slices: Vec<SliceRecord>,
    tracks: Vec<TrackRecord>,
    args: Vec<ArgRecord>,
    // Instant events (packet events, etc.)
    instants: Vec<InstantRecord>,
    instant_args: Vec<InstantArgRecord>,
    // Stack trace data
    symbols: Vec<SymbolRecord>,
    stack_mappings: Vec<StackMappingRecord>,
    frames: Vec<FrameRecord>,
    callsites: Vec<CallsiteRecord>,
    perf_samples: Vec<PerfSampleRecord>,
    // Network interface metadata
    network_interfaces: Vec<NetworkInterfaceRecord>,
    // Socket connection metadata (extracted from socket track names)
    socket_connections: Vec<SocketConnectionRecord>,
    // Clock snapshot data
    clock_snapshots: Vec<ClockSnapshotRecord>,
}

#[derive(Clone)]
struct ProcessRecord {
    upid: i64,
    pid: i32,
    name: Option<String>,
    parent_upid: Option<i64>,
    cmdline: Vec<String>,
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
struct ThreadStateRecord {
    ts: i64,
    dur: i64,
    utid: i64,
    state: i32,
    cpu: Option<i32>,
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
struct InstantRecord {
    id: i64,
    ts: i64,
    track_id: i64,
    utid: Option<i64>,
    name: String,
    category: Option<String>,
}

#[derive(Clone)]
struct TrackRecord {
    id: i64,
    name: String,
    parent_id: Option<i64>,
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

struct SymbolRecord {
    id: i64,
    name: String,
}

struct StackMappingRecord {
    id: i64,
    build_id: Option<String>,
    name: Option<String>,
    exact_offset: i64,
    start_offset: i64,
}

struct FrameRecord {
    id: i64,
    name: Option<String>,
    mapping_id: Option<i64>,
    rel_pc: i64,
    symbol_id: Option<i64>,
}

struct CallsiteRecord {
    id: i64,
    parent_id: Option<i64>,
    frame_id: i64,
    depth: i32,
}

struct PerfSampleRecord {
    ts: i64,
    utid: i64,
    callsite_id: Option<i64>,
    cpu: Option<i32>,
}

#[derive(Clone)]
struct NetworkInterfaceRecord {
    namespace: String,
    interface_name: String,
    ip_address: String,
    address_type: String,
}

/// Socket connection 4-tuple extracted from socket track names.
#[derive(Clone)]
struct SocketConnectionRecord {
    socket_id: i64,
    track_id: i64,
    protocol: &'static str,
    src_ip: String,
    src_port: i32,
    dest_ip: String,
    dest_port: i32,
    address_family: &'static str,
}

/// Clock snapshot record from a trace packet.
/// Used for correlating timestamps between different clock domains
/// (e.g., MONOTONIC vs BOOTTIME vs REALTIME).
#[derive(Clone)]
struct ClockSnapshotRecord {
    /// Clock ID (0-6 for builtin clocks, 9-10 for TSC/PERF, 64-127 for user-defined)
    clock_id: i32,
    /// Human-readable clock name (REALTIME, BOOTTIME, MONOTONIC, etc.)
    clock_name: String,
    /// Timestamp value in nanoseconds for this clock domain
    timestamp_ns: i64,
    /// True if this is the primary trace clock (authoritative time domain)
    is_primary: bool,
}

/// Parse socket track name format: "Socket {id}:{protocol}:{src}:{src_port}->{dest}:{dest_port}"
/// Returns None if the name doesn't match the expected socket track format.
fn parse_socket_track_name(name: &str, track_id: i64) -> Option<SocketConnectionRecord> {
    let caps = SOCKET_TRACK_RE.captures(name)?;

    let socket_id: i64 = caps.get(1)?.as_str().parse().ok()?;

    // Validate protocol is known (TCP or UDP)
    let protocol: &'static str = match caps.get(2)?.as_str() {
        "TCP" => "TCP",
        "UDP" => "UDP",
        _ => return None,
    };

    let src_ip = caps.get(3)?.as_str().to_string();
    let src_port: i32 = caps.get(4)?.as_str().parse().ok()?;
    let dest_ip = caps.get(5)?.as_str().to_string();
    let dest_port: i32 = caps.get(6)?.as_str().parse().ok()?;

    // Validate port ranges (0-65535)
    if !(0..=65535).contains(&src_port) || !(0..=65535).contains(&dest_port) {
        return None;
    }

    // Infer address family: IPv6 addresses contain colons
    let address_family: &'static str = if src_ip.contains(':') || dest_ip.contains(':') {
        "IPv6"
    } else {
        "IPv4"
    };

    Some(SocketConnectionRecord {
        socket_id,
        track_id,
        protocol,
        src_ip,
        src_port,
        dest_ip,
        dest_port,
        address_family,
    })
}

struct TraceExtractor {
    data: ExtractedData,
    pid_to_upid: HashMap<i32, i64>,
    tid_to_utid: HashMap<i32, i64>,
    track_uuid_to_id: HashMap<u64, i64>,
    track_uuid_to_utid: HashMap<u64, i64>,
    /// Interned event names: iid -> name string
    interned_event_names: HashMap<u64, String>,
    next_upid: i64,
    next_utid: i64,
    next_track_id: i64,
    next_instant_id: i64,

    interned_function_names: HashMap<u64, String>,
    interned_mappings: HashMap<u64, StackMappingRecord>,
    interned_frames: HashMap<u64, FrameRecord>,
    interned_callstacks: HashMap<u64, Vec<u64>>,
    callsite_map: HashMap<Vec<u64>, i64>,
    /// Cache: callstack_iid -> callsite_id (avoids repeated Vec cloning)
    callstack_iid_to_callsite: HashMap<u64, i64>,
    next_callsite_id: i64,

    network_interfaces_root_uuid: Option<u64>,
    /// Namespace tracks: uuid -> namespace name (e.g., "host", "container:abc123 (nginx)")
    network_namespace_tracks: HashMap<u64, String>,
    /// Interface tracks: uuid -> (namespace_name, interface_name)
    network_interface_tracks: HashMap<u64, (String, String)>,

    /// Open slices per track: track_uuid -> stack of slice indices in self.data.slices
    /// Used to match TYPE_SLICE_BEGIN with TYPE_SLICE_END and compute duration
    open_slices: HashMap<u64, Vec<usize>>,

    streaming_instant_writer: Option<StreamingInstantWriter>,
    streaming_perf_sample_writer: Option<StreamingWriter<PerfSampleRecord>>,
    streaming_thread_state_writer: Option<StreamingWriter<ThreadStateRecord>>,
    streaming_sched_slice_writer: Option<StreamingSchedSliceWriter>,
    streaming_args_writer: Option<StreamingWriter<ArgRecord>>,

    /// Pending sched slices per CPU for non-streaming mode.
    /// Used to apply prev_state as end_state to the previous slice.
    pending_sched_slices_per_cpu: HashMap<i32, SchedSliceRecord>,
}

impl TraceExtractor {
    fn new() -> Self {
        Self {
            data: ExtractedData {
                processes: Vec::new(),
                threads: Vec::new(),
                sched_slices: Vec::new(),
                thread_states: Vec::new(),
                counters: Vec::new(),
                counter_tracks: Vec::new(),
                slices: Vec::new(),
                tracks: Vec::new(),
                args: Vec::new(),
                instants: Vec::new(),
                instant_args: Vec::new(),
                symbols: Vec::new(),
                stack_mappings: Vec::new(),
                frames: Vec::new(),
                callsites: Vec::new(),
                perf_samples: Vec::new(),
                network_interfaces: Vec::new(),
                socket_connections: Vec::new(),
                clock_snapshots: Vec::new(),
            },
            pid_to_upid: HashMap::new(),
            tid_to_utid: HashMap::new(),
            track_uuid_to_id: HashMap::new(),
            track_uuid_to_utid: HashMap::new(),
            interned_event_names: HashMap::new(),
            next_upid: 1,
            next_utid: 1,
            next_track_id: 1,
            next_instant_id: 0,
            interned_function_names: HashMap::new(),
            interned_mappings: HashMap::new(),
            interned_frames: HashMap::new(),
            interned_callstacks: HashMap::new(),
            callsite_map: HashMap::new(),
            callstack_iid_to_callsite: HashMap::new(),
            next_callsite_id: 1,
            network_interfaces_root_uuid: None,
            network_namespace_tracks: HashMap::new(),
            network_interface_tracks: HashMap::new(),
            open_slices: HashMap::new(),
            streaming_instant_writer: None,
            streaming_perf_sample_writer: None,
            streaming_thread_state_writer: None,
            streaming_sched_slice_writer: None,
            streaming_args_writer: None,
            pending_sched_slices_per_cpu: HashMap::new(),
        }
    }

    /// Create a new TraceExtractor with streaming enabled for streamable data types
    fn new_with_streaming(trace_id: &str, paths: &ParquetPaths) -> Result<Self> {
        let mut extractor = Self::new();
        extractor.streaming_instant_writer = Some(StreamingInstantWriter::new(trace_id, paths)?);
        extractor.streaming_perf_sample_writer =
            Some(StreamingWriter::new(trace_id, &paths.perf_sample)?);
        extractor.streaming_thread_state_writer =
            Some(StreamingWriter::new(trace_id, &paths.thread_state)?);
        extractor.streaming_sched_slice_writer = Some(StreamingSchedSliceWriter::new(
            trace_id,
            &paths.sched_slice,
        )?);
        extractor.streaming_args_writer = Some(StreamingWriter::new(trace_id, &paths.args)?);
        Ok(extractor)
    }

    /// Finishes streaming writers and returns data with streamed record count.
    fn into_data_streaming(mut self) -> Result<(ExtractedData, usize)> {
        self.finalize_stack_data();
        let mut streamed_count = 0;
        if let Some(writer) = self.streaming_instant_writer.take() {
            let (instants, args) = writer.finish()?;
            streamed_count += instants + args;
        }
        if let Some(writer) = self.streaming_perf_sample_writer.take() {
            streamed_count += writer.finish()?;
        }
        if let Some(writer) = self.streaming_thread_state_writer.take() {
            streamed_count += writer.finish()?;
        }
        if let Some(writer) = self.streaming_sched_slice_writer.take() {
            streamed_count += writer.finish()?;
        }
        if let Some(writer) = self.streaming_args_writer.take() {
            streamed_count += writer.finish()?;
        }
        Ok((self.data, streamed_count))
    }

    fn push_instant(&mut self, record: InstantRecord) -> Result<()> {
        if let Some(ref mut writer) = self.streaming_instant_writer {
            writer.push_instant(record)
        } else {
            self.data.instants.push(record);
            Ok(())
        }
    }

    fn push_instant_arg(&mut self, record: InstantArgRecord) -> Result<()> {
        if let Some(ref mut writer) = self.streaming_instant_writer {
            writer.push_instant_arg(record)
        } else {
            self.data.instant_args.push(record);
            Ok(())
        }
    }

    fn push_perf_sample(&mut self, record: PerfSampleRecord) -> Result<()> {
        if let Some(ref mut writer) = self.streaming_perf_sample_writer {
            writer.push(record)
        } else {
            self.data.perf_samples.push(record);
            Ok(())
        }
    }

    fn push_thread_state(&mut self, record: ThreadStateRecord) -> Result<()> {
        if let Some(ref mut writer) = self.streaming_thread_state_writer {
            writer.push(record)
        } else {
            self.data.thread_states.push(record);
            Ok(())
        }
    }

    /// Push a sched_slice record with the prev_state from the current switch.
    /// The prev_state describes why the PREVIOUS task left the CPU, so it
    /// gets applied as end_state to the pending slice (the task being switched FROM),
    /// not to this new slice (the task being switched TO).
    fn push_sched_slice(
        &mut self,
        record: SchedSliceRecord,
        prev_state: Option<i64>,
    ) -> Result<()> {
        if let Some(ref mut writer) = self.streaming_sched_slice_writer {
            writer.push(record, prev_state)
        } else {
            // Non-streaming mode: buffer per-CPU to apply prev_state to previous slice
            let cpu = record.cpu;
            let ts = record.ts;
            if let Some(mut prev) = self.pending_sched_slices_per_cpu.insert(cpu, record) {
                prev.dur = ts - prev.ts;
                if let Some(state) = prev_state {
                    prev.end_state = Some(state as i32);
                }
                self.data.sched_slices.push(prev);
            }
            Ok(())
        }
    }

    /// Flush any pending sched slices (for non-streaming mode).
    /// Called at the end of extraction to write the last slice on each CPU.
    fn flush_pending_sched_slices(&mut self) {
        for (_, slice) in self.pending_sched_slices_per_cpu.drain() {
            self.data.sched_slices.push(slice);
        }
    }

    fn push_arg(&mut self, record: ArgRecord) -> Result<()> {
        if let Some(ref mut writer) = self.streaming_args_writer {
            writer.push(record)
        } else {
            self.data.args.push(record);
            Ok(())
        }
    }

    fn process_packet(&mut self, packet: &TracePacket) -> Result<()> {
        self.process_clock_snapshot(packet);
        self.process_interned_data(packet);
        self.process_descriptors(packet);
        self.process_events(packet)?;
        self.process_perf_sample(packet)?;
        Ok(())
    }

    /// Extract clock snapshot data from a trace packet.
    ///
    /// Clock snapshots provide timestamp correlation between different clock domains:
    /// - REALTIME: Wall clock time (affected by NTP adjustments)
    /// - BOOTTIME: Time since boot (monotonic, includes suspend time)
    /// - MONOTONIC: Time since arbitrary point (monotonic, excludes suspend)
    ///
    /// Multiple clock snapshots may appear in a trace (emitted periodically)
    /// to track clock drift over time.
    fn process_clock_snapshot(&mut self, packet: &TracePacket) {
        if !packet.has_clock_snapshot() {
            return;
        }

        let snapshot = packet.clock_snapshot();
        // primary_trace_clock indicates which clock domain is authoritative for the trace
        // Defaults to UNKNOWN (0) if not set
        let primary_clock_id = snapshot.primary_trace_clock() as i32;

        for clock in &snapshot.clocks {
            let clock_id = clock.clock_id() as i32;
            // Map clock IDs to human-readable names per BuiltinClock enum
            let clock_name = match clock_id {
                0 => "UNKNOWN",
                1 => "REALTIME",
                2 => "REALTIME_COARSE",
                3 => "MONOTONIC",
                4 => "MONOTONIC_COARSE",
                5 => "MONOTONIC_RAW",
                6 => "BOOTTIME",
                9 => "TSC",   // CPU timestamp counter
                10 => "PERF", // perf_event clock
                // IDs 64-127 are user-defined sequence-scoped clocks
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
            // Event names (existing)
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
                    let record = StackMappingRecord {
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
                    // Invalidate cache if redefining this IID (rare but possible)
                    self.callstack_iid_to_callsite.remove(&iid);
                    self.interned_callstacks
                        .insert(iid, callstack.frame_ids.clone());
                }
            }
        }
    }

    fn process_descriptors(&mut self, packet: &TracePacket) {
        if packet.has_track_descriptor() {
            let desc = packet.track_descriptor();

            if let Some(proc) = desc.process.as_ref() {
                let pid = proc.pid();
                if let std::collections::hash_map::Entry::Vacant(e) = self.pid_to_upid.entry(pid) {
                    let upid = self.next_upid;
                    self.next_upid += 1;
                    e.insert(upid);
                    self.data.processes.push(ProcessRecord {
                        upid,
                        pid,
                        name: proc.process_name.clone(),
                        parent_upid: None,
                        cmdline: proc.cmdline.clone(),
                    });
                }
                if desc.has_uuid() {
                    if let Some(&upid) = self.pid_to_upid.get(&pid) {
                        self.track_uuid_to_id.insert(desc.uuid(), upid);
                    }
                }
            }

            if let Some(thread) = desc.thread.as_ref() {
                let tid = thread.tid();
                let pid = thread.pid();

                if let std::collections::hash_map::Entry::Vacant(e) = self.pid_to_upid.entry(pid) {
                    let upid = self.next_upid;
                    self.next_upid += 1;
                    e.insert(upid);
                    self.data.processes.push(ProcessRecord {
                        upid,
                        pid,
                        name: None,
                        parent_upid: None,
                        cmdline: Vec::new(),
                    });
                }

                if let std::collections::hash_map::Entry::Vacant(e) = self.tid_to_utid.entry(tid) {
                    let utid = self.next_utid;
                    self.next_utid += 1;
                    e.insert(utid);
                    self.data.threads.push(ThreadRecord {
                        utid,
                        tid,
                        name: thread.thread_name.clone(),
                        upid: self.pid_to_upid.get(&pid).copied(),
                    });
                }
                if desc.has_uuid() {
                    if let Some(&utid) = self.tid_to_utid.get(&tid) {
                        self.track_uuid_to_utid.insert(desc.uuid(), utid);
                    }
                }
            }

            if let Some(counter) = desc.counter.as_ref() {
                let track_id = self.next_track_id;
                self.next_track_id += 1;
                if desc.has_uuid() {
                    self.track_uuid_to_id.insert(desc.uuid(), track_id);
                }
                self.data.counter_tracks.push(CounterTrackRecord {
                    id: track_id,
                    name: if desc.has_name() {
                        desc.name().to_string()
                    } else {
                        format!("counter_{track_id}")
                    },
                    unit: counter.unit_name.clone(),
                });
            } else if desc.has_uuid() {
                // Generic track descriptor (includes network tracks like "Socket 1:TCP:10.0.0.1:12345->10.0.0.2:8080")
                let track_id = self.next_track_id;
                self.next_track_id += 1;
                self.track_uuid_to_id.insert(desc.uuid(), track_id);

                // Propagate utid from parent track (enables direct slice-to-thread correlation)
                if desc.has_parent_uuid() {
                    if let Some(&parent_utid) = self.track_uuid_to_utid.get(&desc.parent_uuid()) {
                        self.track_uuid_to_utid.insert(desc.uuid(), parent_utid);
                    }
                }

                // Store track metadata if it has a name
                if desc.has_name() {
                    let name = desc.name().to_string();

                    if name == NETWORK_INTERFACES_TRACK_NAME {
                        self.network_interfaces_root_uuid = Some(desc.uuid());
                    } else if desc.has_parent_uuid() {
                        let parent_uuid = desc.parent_uuid();

                        // Check if this is a namespace track (child of root)
                        if Some(parent_uuid) == self.network_interfaces_root_uuid {
                            self.network_namespace_tracks
                                .insert(desc.uuid(), name.clone());
                        }
                        // Check if this is an interface track (child of a namespace track)
                        else if let Some(namespace_name) =
                            self.network_namespace_tracks.get(&parent_uuid).cloned()
                        {
                            self.network_interface_tracks
                                .insert(desc.uuid(), (namespace_name, name.clone()));
                        }
                    }

                    let parent_id = if desc.has_parent_uuid() {
                        self.track_uuid_to_id.get(&desc.parent_uuid()).copied()
                    } else {
                        None
                    };

                    // Extract socket connection info if this is a socket track
                    if let Some(socket_conn) = parse_socket_track_name(&name, track_id) {
                        self.data.socket_connections.push(socket_conn);
                    }

                    self.data.tracks.push(TrackRecord {
                        id: track_id,
                        name,
                        parent_id,
                    });
                }
            }
        }

        if packet.has_process_tree() {
            let tree = packet.process_tree();
            for proc in &tree.processes {
                let pid = proc.pid();
                if let std::collections::hash_map::Entry::Vacant(e) = self.pid_to_upid.entry(pid) {
                    let upid = self.next_upid;
                    self.next_upid += 1;
                    e.insert(upid);
                    self.data.processes.push(ProcessRecord {
                        upid,
                        pid,
                        name: proc.cmdline.first().cloned(),
                        parent_upid: self.pid_to_upid.get(&proc.ppid()).copied(),
                        cmdline: proc.cmdline.clone(),
                    });
                }
            }
            for thread in &tree.threads {
                let tid = thread.tid();
                let tgid = thread.tgid();
                if let std::collections::hash_map::Entry::Vacant(e) = self.tid_to_utid.entry(tid) {
                    let utid = self.next_utid;
                    self.next_utid += 1;
                    e.insert(utid);

                    if let std::collections::hash_map::Entry::Vacant(e) =
                        self.pid_to_upid.entry(tgid)
                    {
                        let upid = self.next_upid;
                        self.next_upid += 1;
                        e.insert(upid);
                        self.data.processes.push(ProcessRecord {
                            upid,
                            pid: tgid,
                            name: None,
                            parent_upid: None,
                            cmdline: Vec::new(),
                        });
                    }

                    self.data.threads.push(ThreadRecord {
                        utid,
                        tid,
                        name: if thread.has_name() {
                            Some(thread.name().to_string())
                        } else {
                            None
                        },
                        upid: self.pid_to_upid.get(&tgid).copied(),
                    });
                }
            }
        }
    }

    fn process_events(&mut self, packet: &TracePacket) -> Result<()> {
        if packet.has_ftrace_events() {
            let bundle = packet.ftrace_events();
            let cpu = bundle.cpu() as i32;

            if let Some(compact) = bundle.compact_sched.as_ref() {
                self.extract_compact_sched(compact, cpu)?;
            }

            for event in &bundle.event {
                let ts = event.timestamp() as i64;

                if event.has_sched_switch() {
                    let switch = event.sched_switch();
                    let next_pid = switch.next_pid();
                    let prev_pid = switch.prev_pid();

                    self.ensure_thread_exists(next_pid, Some(switch.next_comm()));
                    self.ensure_thread_exists(prev_pid, Some(switch.prev_comm()));

                    // Extract prev_state - this tells us why the PREVIOUS task left the CPU
                    let prev_state = if switch.has_prev_state() {
                        Some(switch.prev_state())
                    } else {
                        None
                    };

                    if let Some(&next_utid) = self.tid_to_utid.get(&next_pid) {
                        self.push_sched_slice(
                            SchedSliceRecord {
                                ts,
                                dur: 0,
                                cpu,
                                utid: next_utid,
                                end_state: None,
                                priority: switch.next_prio(),
                            },
                            prev_state,
                        )?;
                    }
                }

                if event.has_sched_waking() {
                    let waking = event.sched_waking();
                    let pid = waking.pid();
                    self.ensure_thread_exists(pid, Some(waking.comm()));

                    if let Some(&utid) = self.tid_to_utid.get(&pid) {
                        self.push_thread_state(ThreadStateRecord {
                            ts,
                            dur: 0,
                            utid,
                            state: 0, // TASK_RUNNING (runnable)
                            cpu: Some(waking.target_cpu()),
                        })?;
                    }
                }
            }
        }

        if packet.has_track_event() {
            let ts = packet.timestamp() as i64;
            let event = packet.track_event();

            if event.has_track_uuid() {
                let track_uuid = event.track_uuid();

                if event.has_counter_value() {
                    if let Some(&track_id) = self.track_uuid_to_id.get(&track_uuid) {
                        self.data.counters.push(CounterRecord {
                            ts,
                            track_id,
                            value: event.counter_value() as f64,
                        });
                    }
                }

                if event.has_type() {
                    use perfetto_protos::track_event::track_event::Type;
                    if let Type::TYPE_SLICE_BEGIN = event.type_() {
                        // Assign slice ID before pushing
                        let slice_id = self.data.slices.len() as i64;
                        let slice_index = self.data.slices.len();

                        // Try inline name first, then interned name via name_iid
                        let name = if event.has_name() {
                            event.name().to_string()
                        } else if event.has_name_iid() {
                            self.interned_event_names
                                .get(&event.name_iid())
                                .cloned()
                                .unwrap_or_else(|| "unknown".to_string())
                        } else {
                            "unknown".to_string()
                        };
                        let track_id = self.track_uuid_to_id.get(&track_uuid).copied().unwrap_or(0);
                        let utid = self.track_uuid_to_utid.get(&track_uuid).copied();
                        self.data.slices.push(SliceRecord {
                            id: slice_id,
                            ts,
                            dur: 0,
                            track_id,
                            utid,
                            name,
                            category: event.categories.first().cloned(),
                            depth: 0,
                        });

                        // Track this open slice so we can match it with TYPE_SLICE_END
                        self.open_slices
                            .entry(track_uuid)
                            .or_default()
                            .push(slice_index);

                        // Extract debug annotations
                        for annotation in &event.debug_annotations {
                            let key = if annotation.has_name() {
                                annotation.name().to_string()
                            } else {
                                continue; // Skip unnamed annotations
                            };

                            let (int_val, str_val, real_val) = if annotation.has_uint_value() {
                                (Some(annotation.uint_value() as i64), None, None)
                            } else if annotation.has_int_value() {
                                (Some(annotation.int_value()), None, None)
                            } else if annotation.has_string_value() {
                                (None, Some(annotation.string_value().to_string()), None)
                            } else if annotation.has_double_value() {
                                (None, None, Some(annotation.double_value()))
                            } else {
                                continue; // Skip annotations without values
                            };

                            self.push_arg(ArgRecord {
                                slice_id,
                                key,
                                int_value: int_val,
                                string_value: str_val,
                                real_value: real_val,
                            })?;
                        }
                    }

                    // Handle TYPE_SLICE_END events - match with begin and compute duration
                    if let Type::TYPE_SLICE_END = event.type_() {
                        if let Some(slice_stack) = self.open_slices.get_mut(&track_uuid) {
                            if let Some(slice_index) = slice_stack.pop() {
                                // Compute duration from begin timestamp to end timestamp
                                // Note: If end timestamp < begin timestamp (malformed trace),
                                // this will produce a negative duration which can be detected in analysis
                                let begin_ts = self.data.slices[slice_index].ts;
                                self.data.slices[slice_index].dur = ts - begin_ts;
                            }
                            // If stack is empty, this is an END without a matching BEGIN - silently ignore
                        }
                        // If track_uuid not found in open_slices, this is an END without a matching BEGIN - silently ignore
                    }

                    // Handle TYPE_INSTANT events (includes packet events and network interface metadata)
                    if let Type::TYPE_INSTANT = event.type_() {
                        // Extract network interface metadata
                        if let Some((namespace_name, interface_name)) =
                            self.network_interface_tracks.get(&track_uuid).cloned()
                        {
                            for annotation in &event.debug_annotations {
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

                        // Record instant event in the instant table
                        let instant_id = self.next_instant_id;
                        self.next_instant_id += 1;
                        let name = if event.has_name() {
                            event.name().to_string()
                        } else if event.has_name_iid() {
                            self.interned_event_names
                                .get(&event.name_iid())
                                .cloned()
                                .unwrap_or_else(|| "unknown".to_string())
                        } else {
                            "unknown".to_string()
                        };
                        let track_id = self.track_uuid_to_id.get(&track_uuid).copied().unwrap_or(0);
                        let utid = self.track_uuid_to_utid.get(&track_uuid).copied();
                        self.push_instant(InstantRecord {
                            id: instant_id,
                            ts,
                            track_id,
                            utid,
                            name,
                            category: event.categories.first().cloned(),
                        })?;

                        // Extract debug annotations for instant events
                        for annotation in &event.debug_annotations {
                            let key = if annotation.has_name() {
                                annotation.name().to_string()
                            } else {
                                continue;
                            };

                            let (int_val, str_val, real_val) = if annotation.has_uint_value() {
                                (Some(annotation.uint_value() as i64), None, None)
                            } else if annotation.has_int_value() {
                                (Some(annotation.int_value()), None, None)
                            } else if annotation.has_string_value() {
                                (None, Some(annotation.string_value().to_string()), None)
                            } else if annotation.has_double_value() {
                                (None, None, Some(annotation.double_value()))
                            } else {
                                continue;
                            };

                            self.push_instant_arg(InstantArgRecord {
                                instant_id,
                                key,
                                int_value: int_val,
                                string_value: str_val,
                                real_value: real_val,
                            })?;
                        }
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

            // Extract prev_state - this tells us why the PREVIOUS task left the CPU
            let prev_state = compact.switch_prev_state.get(i).copied();

            self.ensure_thread_exists(next_pid, comm);

            if let Some(&utid) = self.tid_to_utid.get(&next_pid) {
                self.push_sched_slice(
                    SchedSliceRecord {
                        ts: switch_ts,
                        dur: 0,
                        cpu,
                        utid,
                        end_state: None,
                        priority: next_prio,
                    },
                    prev_state,
                )?;
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
                self.push_thread_state(ThreadStateRecord {
                    ts: waking_ts,
                    dur: 0,
                    utid,
                    state: 0, // TASK_RUNNING (runnable)
                    cpu: Some(target_cpu),
                })?;
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
                    cmdline: Vec::new(),
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

    /// Process PerfSample packets for stack trace data
    fn process_perf_sample(&mut self, packet: &TracePacket) -> Result<()> {
        if packet.has_perf_sample() {
            let sample = packet.perf_sample();
            let ts = packet.timestamp() as i64;

            let callsite_id = if sample.has_callstack_iid() {
                let iid = sample.callstack_iid();
                // Check cache first to avoid Vec cloning
                if let Some(&cached) = self.callstack_iid_to_callsite.get(&iid) {
                    Some(cached)
                } else if let Some(frame_ids) = self.interned_callstacks.get(&iid).cloned() {
                    // Clone only on cache miss, then cache the result
                    let id = self.get_or_create_callsite(&frame_ids);
                    self.callstack_iid_to_callsite.insert(iid, id);
                    Some(id)
                } else {
                    None
                }
            } else {
                None
            };

            let tid = sample.tid() as i32;
            let tgid = sample.pid() as i32;
            if let std::collections::hash_map::Entry::Vacant(e) = self.pid_to_upid.entry(tgid) {
                let upid = self.next_upid;
                self.next_upid += 1;
                e.insert(upid);
                self.data.processes.push(ProcessRecord {
                    upid,
                    pid: tgid,
                    name: None,
                    parent_upid: None,
                    cmdline: Vec::new(),
                });
            }

            self.ensure_thread_exists(tid, None);

            if let Some(&utid) = self.tid_to_utid.get(&tid) {
                self.push_perf_sample(PerfSampleRecord {
                    ts,
                    utid,
                    callsite_id,
                    cpu: sample.cpu.map(|c| c as i32),
                })?;
            }
        }
        Ok(())
    }

    /// Convert flat frame_ids to parent-child callsite tree. Returns leaf callsite ID.
    fn get_or_create_callsite(&mut self, frame_ids: &[u64]) -> i64 {
        if frame_ids.is_empty() {
            return 0;
        }

        let num_frames = frame_ids.len();

        // Check if full stack already exists (reversed for root-to-leaf prefix matching)
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
        // Flush any pending sched slices (non-streaming mode only)
        self.flush_pending_sched_slices();

        for (iid, name) in self.interned_function_names.drain() {
            self.data.symbols.push(SymbolRecord {
                id: iid as i64,
                name,
            });
        }

        for (_, mapping) in self.interned_mappings.drain() {
            self.data.stack_mappings.push(mapping);
        }

        for (_, frame) in self.interned_frames.drain() {
            self.data.frames.push(frame);
        }
    }
}

/// Extract trace data, streaming some record types directly to parquet.
fn extract_trace_data_with_streaming<R: BufRead>(
    reader: R,
    trace_id: &str,
    paths: &ParquetPaths,
) -> Result<(ExtractedData, usize)> {
    let mut extractor = TraceExtractor::new_with_streaming(trace_id, paths)?;
    let packet_iter = TracePacketIterator::new(reader);

    for packet_result in packet_iter {
        let packet = packet_result?;
        extractor.process_packet(&packet)?;
    }

    extractor.into_data_streaming()
}

// create_schema and ParquetPaths are now imported from systing library

const PARQUET_BATCH_SIZE: usize = 500_000;
const STREAMING_BATCH_SIZE: usize = 50_000;

/// Trait for records that can be streamed to parquet
trait StreamableRecord: Sized {
    fn schema() -> Schema;
    fn build_batch(records: &[Self], trace_id: &str, schema: &Arc<Schema>) -> Result<RecordBatch>;
}

impl StreamableRecord for PerfSampleRecord {
    fn schema() -> Schema {
        Schema::new(vec![
            Field::new("trace_id", DataType::Utf8, false),
            Field::new("ts", DataType::Int64, false),
            Field::new("utid", DataType::Int64, false),
            Field::new("callsite_id", DataType::Int64, true),
            Field::new("cpu", DataType::Int32, true),
        ])
    }

    fn build_batch(records: &[Self], trace_id: &str, schema: &Arc<Schema>) -> Result<RecordBatch> {
        let mut trace_id_builder = StringBuilder::with_capacity(records.len(), records.len() * 32);
        let mut ts_builder = Int64Builder::with_capacity(records.len());
        let mut utid_builder = Int64Builder::with_capacity(records.len());
        let mut callsite_id_builder = Int64Builder::with_capacity(records.len());
        let mut cpu_builder = Int32Builder::with_capacity(records.len());

        for sample in records {
            trace_id_builder.append_value(trace_id);
            ts_builder.append_value(sample.ts);
            utid_builder.append_value(sample.utid);
            callsite_id_builder.append_option(sample.callsite_id);
            cpu_builder.append_option(sample.cpu);
        }

        Ok(RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(trace_id_builder.finish()),
                Arc::new(ts_builder.finish()),
                Arc::new(utid_builder.finish()),
                Arc::new(callsite_id_builder.finish()),
                Arc::new(cpu_builder.finish()),
            ],
        )?)
    }
}

impl StreamableRecord for ThreadStateRecord {
    fn schema() -> Schema {
        Schema::new(vec![
            Field::new("trace_id", DataType::Utf8, false),
            Field::new("ts", DataType::Int64, false),
            Field::new("dur", DataType::Int64, false),
            Field::new("utid", DataType::Int64, false),
            Field::new("state", DataType::Int32, false),
            Field::new("cpu", DataType::Int32, true),
        ])
    }

    fn build_batch(records: &[Self], trace_id: &str, schema: &Arc<Schema>) -> Result<RecordBatch> {
        let mut trace_id_builder = StringBuilder::with_capacity(records.len(), records.len() * 32);
        let mut ts_builder = Int64Builder::with_capacity(records.len());
        let mut dur_builder = Int64Builder::with_capacity(records.len());
        let mut utid_builder = Int64Builder::with_capacity(records.len());
        let mut state_builder = Int32Builder::with_capacity(records.len());
        let mut cpu_builder = Int32Builder::with_capacity(records.len());

        for state in records {
            trace_id_builder.append_value(trace_id);
            ts_builder.append_value(state.ts);
            dur_builder.append_value(state.dur);
            utid_builder.append_value(state.utid);
            state_builder.append_value(state.state);
            cpu_builder.append_option(state.cpu);
        }

        Ok(RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(trace_id_builder.finish()),
                Arc::new(ts_builder.finish()),
                Arc::new(dur_builder.finish()),
                Arc::new(utid_builder.finish()),
                Arc::new(state_builder.finish()),
                Arc::new(cpu_builder.finish()),
            ],
        )?)
    }
}

impl StreamableRecord for SchedSliceRecord {
    fn schema() -> Schema {
        Schema::new(vec![
            Field::new("trace_id", DataType::Utf8, false),
            Field::new("ts", DataType::Int64, false),
            Field::new("dur", DataType::Int64, false),
            Field::new("cpu", DataType::Int32, false),
            Field::new("utid", DataType::Int64, false),
            Field::new("end_state", DataType::Int32, true),
            Field::new("priority", DataType::Int32, false),
        ])
    }

    fn build_batch(records: &[Self], trace_id: &str, schema: &Arc<Schema>) -> Result<RecordBatch> {
        let mut trace_id_builder = StringBuilder::with_capacity(records.len(), records.len() * 32);
        let mut ts_builder = Int64Builder::with_capacity(records.len());
        let mut dur_builder = Int64Builder::with_capacity(records.len());
        let mut cpu_builder = Int32Builder::with_capacity(records.len());
        let mut utid_builder = Int64Builder::with_capacity(records.len());
        let mut end_state_builder = Int32Builder::with_capacity(records.len());
        let mut priority_builder = Int32Builder::with_capacity(records.len());

        for slice in records {
            trace_id_builder.append_value(trace_id);
            ts_builder.append_value(slice.ts);
            dur_builder.append_value(slice.dur);
            cpu_builder.append_value(slice.cpu);
            utid_builder.append_value(slice.utid);
            end_state_builder.append_option(slice.end_state);
            priority_builder.append_value(slice.priority);
        }

        Ok(RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(trace_id_builder.finish()),
                Arc::new(ts_builder.finish()),
                Arc::new(dur_builder.finish()),
                Arc::new(cpu_builder.finish()),
                Arc::new(utid_builder.finish()),
                Arc::new(end_state_builder.finish()),
                Arc::new(priority_builder.finish()),
            ],
        )?)
    }
}

impl StreamableRecord for InstantRecord {
    fn schema() -> Schema {
        Schema::new(vec![
            Field::new("trace_id", DataType::Utf8, false),
            Field::new("id", DataType::Int64, false),
            Field::new("ts", DataType::Int64, false),
            Field::new("track_id", DataType::Int64, false),
            Field::new("utid", DataType::Int64, true),
            Field::new("name", DataType::Utf8, false),
            Field::new("category", DataType::Utf8, true),
        ])
    }

    fn build_batch(records: &[Self], trace_id: &str, schema: &Arc<Schema>) -> Result<RecordBatch> {
        let mut trace_id_builder = StringBuilder::with_capacity(records.len(), records.len() * 32);
        let mut id_builder = Int64Builder::with_capacity(records.len());
        let mut ts_builder = Int64Builder::with_capacity(records.len());
        let mut track_id_builder = Int64Builder::with_capacity(records.len());
        let mut utid_builder = Int64Builder::with_capacity(records.len());
        let mut name_builder = StringBuilder::with_capacity(records.len(), records.len() * 32);
        let mut category_builder = StringBuilder::with_capacity(records.len(), records.len() * 16);

        for record in records {
            trace_id_builder.append_value(trace_id);
            id_builder.append_value(record.id);
            ts_builder.append_value(record.ts);
            track_id_builder.append_value(record.track_id);
            utid_builder.append_option(record.utid);
            name_builder.append_value(&record.name);
            category_builder.append_option(record.category.as_deref());
        }

        Ok(RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(trace_id_builder.finish()),
                Arc::new(id_builder.finish()),
                Arc::new(ts_builder.finish()),
                Arc::new(track_id_builder.finish()),
                Arc::new(utid_builder.finish()),
                Arc::new(name_builder.finish()),
                Arc::new(category_builder.finish()),
            ],
        )?)
    }
}

impl StreamableRecord for InstantArgRecord {
    fn schema() -> Schema {
        Schema::new(vec![
            Field::new("trace_id", DataType::Utf8, false),
            Field::new("instant_id", DataType::Int64, false),
            Field::new("key", DataType::Utf8, false),
            Field::new("int_value", DataType::Int64, true),
            Field::new("string_value", DataType::Utf8, true),
            Field::new("real_value", DataType::Float64, true),
        ])
    }

    fn build_batch(records: &[Self], trace_id: &str, schema: &Arc<Schema>) -> Result<RecordBatch> {
        let mut trace_id_builder = StringBuilder::with_capacity(records.len(), records.len() * 32);
        let mut instant_id_builder = Int64Builder::with_capacity(records.len());
        let mut key_builder = StringBuilder::with_capacity(records.len(), records.len() * 32);
        let mut int_value_builder = Int64Builder::with_capacity(records.len());
        let mut string_value_builder =
            StringBuilder::with_capacity(records.len(), records.len() * 64);
        let mut real_value_builder = Float64Builder::with_capacity(records.len());

        for record in records {
            trace_id_builder.append_value(trace_id);
            instant_id_builder.append_value(record.instant_id);
            key_builder.append_value(&record.key);
            int_value_builder.append_option(record.int_value);
            string_value_builder.append_option(record.string_value.as_deref());
            real_value_builder.append_option(record.real_value);
        }

        Ok(RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(trace_id_builder.finish()),
                Arc::new(instant_id_builder.finish()),
                Arc::new(key_builder.finish()),
                Arc::new(int_value_builder.finish()),
                Arc::new(string_value_builder.finish()),
                Arc::new(real_value_builder.finish()),
            ],
        )?)
    }
}

impl StreamableRecord for ArgRecord {
    fn schema() -> Schema {
        Schema::new(vec![
            Field::new("trace_id", DataType::Utf8, false),
            Field::new("slice_id", DataType::Int64, false),
            Field::new("key", DataType::Utf8, false),
            Field::new("int_value", DataType::Int64, true),
            Field::new("string_value", DataType::Utf8, true),
            Field::new("real_value", DataType::Float64, true),
        ])
    }

    fn build_batch(records: &[Self], trace_id: &str, schema: &Arc<Schema>) -> Result<RecordBatch> {
        let mut trace_id_builder = StringBuilder::with_capacity(records.len(), records.len() * 32);
        let mut slice_id_builder = Int64Builder::with_capacity(records.len());
        let mut key_builder = StringBuilder::with_capacity(records.len(), records.len() * 32);
        let mut int_value_builder = Int64Builder::with_capacity(records.len());
        let mut string_value_builder =
            StringBuilder::with_capacity(records.len(), records.len() * 64);
        let mut real_value_builder = Float64Builder::with_capacity(records.len());

        for record in records {
            trace_id_builder.append_value(trace_id);
            slice_id_builder.append_value(record.slice_id);
            key_builder.append_value(&record.key);
            int_value_builder.append_option(record.int_value);
            string_value_builder.append_option(record.string_value.as_deref());
            real_value_builder.append_option(record.real_value);
        }

        Ok(RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(trace_id_builder.finish()),
                Arc::new(slice_id_builder.finish()),
                Arc::new(key_builder.finish()),
                Arc::new(int_value_builder.finish()),
                Arc::new(string_value_builder.finish()),
                Arc::new(real_value_builder.finish()),
            ],
        )?)
    }
}

/// Generic streaming writer for any record type implementing StreamableRecord
struct StreamingWriter<T: StreamableRecord> {
    writer: Option<ArrowWriter<File>>,
    schema: Arc<Schema>,
    trace_id: String,
    buffer: Vec<T>,
    total_written: usize,
}

impl<T: StreamableRecord> StreamingWriter<T> {
    fn new(trace_id: &str, path: &Path) -> Result<Self> {
        let props = WriterProperties::builder()
            .set_compression(Compression::SNAPPY)
            .set_max_row_group_size(1_000_000)
            .build();

        let schema = Arc::new(T::schema());
        let file = File::create(path)?;
        let writer = ArrowWriter::try_new(file, schema.clone(), Some(props))?;

        Ok(Self {
            writer: Some(writer),
            schema,
            trace_id: trace_id.to_string(),
            buffer: Vec::with_capacity(STREAMING_BATCH_SIZE),
            total_written: 0,
        })
    }

    fn push(&mut self, record: T) -> Result<()> {
        self.buffer.push(record);
        if self.buffer.len() >= STREAMING_BATCH_SIZE {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }

        let batch = T::build_batch(&self.buffer, &self.trace_id, &self.schema)?;
        if let Some(ref mut writer) = self.writer {
            writer.write(&batch)?;
        }
        self.total_written += self.buffer.len();
        self.buffer.clear();
        Ok(())
    }

    fn finish(mut self) -> Result<usize> {
        self.flush()?;
        if let Some(writer) = self.writer.take() {
            writer.close()?;
        }
        Ok(self.total_written)
    }

    fn has_unflushed_data(&self) -> bool {
        !self.buffer.is_empty()
    }
}

impl<T: StreamableRecord> Drop for StreamingWriter<T> {
    fn drop(&mut self) {
        if self.has_unflushed_data() {
            eprintln!(
                "Warning: StreamingWriter dropped with {} unflushed records",
                self.buffer.len()
            );
        }
    }
}

/// Writer for instant events and their args.
struct StreamingInstantWriter {
    instants: StreamingWriter<InstantRecord>,
    args: StreamingWriter<InstantArgRecord>,
}

impl StreamingInstantWriter {
    fn new(trace_id: &str, paths: &ParquetPaths) -> Result<Self> {
        Ok(Self {
            instants: StreamingWriter::new(trace_id, &paths.instant)?,
            args: StreamingWriter::new(trace_id, &paths.instant_args)?,
        })
    }

    fn push_instant(&mut self, record: InstantRecord) -> Result<()> {
        self.instants.push(record)
    }

    fn push_instant_arg(&mut self, record: InstantArgRecord) -> Result<()> {
        self.args.push(record)
    }

    fn finish(self) -> Result<(usize, usize)> {
        let instants = self.instants.finish()?;
        let args = self.args.finish()?;
        Ok((instants, args))
    }
}

/// Buffers sched_slice events per-CPU to compute durations between consecutive slices.
struct StreamingSchedSliceWriter {
    writer: StreamingWriter<SchedSliceRecord>,
    pending_per_cpu: HashMap<i32, SchedSliceRecord>,
}

impl StreamingSchedSliceWriter {
    fn new(trace_id: &str, path: &Path) -> Result<Self> {
        Ok(Self {
            writer: StreamingWriter::new(trace_id, path)?,
            pending_per_cpu: HashMap::new(),
        })
    }

    /// Push a sched_slice record with the prev_state from the current switch.
    /// The prev_state describes why the PREVIOUS task left the CPU, so it
    /// gets applied as end_state to the pending slice, not to this new slice.
    fn push(&mut self, record: SchedSliceRecord, prev_state: Option<i64>) -> Result<()> {
        let cpu = record.cpu;
        let ts = record.ts;
        if let Some(mut prev) = self.pending_per_cpu.insert(cpu, record) {
            prev.dur = ts - prev.ts;
            // Apply prev_state as end_state to the previous slice
            if let Some(state) = prev_state {
                prev.end_state = Some(state as i32);
            }
            self.writer.push(prev)?;
        }
        Ok(())
    }

    fn finish(mut self) -> Result<usize> {
        for (_, slice) in self.pending_per_cpu.drain() {
            self.writer.push(slice)?;
        }
        self.writer.finish()
    }
}

fn write_data_to_parquet(trace_id: &str, data: &ExtractedData, paths: &ParquetPaths) -> Result<()> {
    let props = WriterProperties::builder()
        .set_compression(Compression::SNAPPY)
        .set_max_row_group_size(1_000_000)
        .build();

    if !data.processes.is_empty() {
        let schema = Arc::new(Schema::new(vec![
            Field::new("trace_id", DataType::Utf8, false),
            Field::new("upid", DataType::Int64, false),
            Field::new("pid", DataType::Int32, false),
            Field::new("name", DataType::Utf8, true),
            Field::new("parent_upid", DataType::Int64, true),
            Field::new(
                "cmdline",
                DataType::List(Arc::new(Field::new("item", DataType::Utf8, true))),
                false,
            ),
        ]));

        let mut trace_id_builder = StringBuilder::new();
        let mut upid_builder = Int64Builder::new();
        let mut pid_builder = Int32Builder::new();
        let mut name_builder = StringBuilder::new();
        let mut parent_upid_builder = Int64Builder::new();
        let mut cmdline_builder = ListBuilder::new(StringBuilder::new());

        for proc in &data.processes {
            trace_id_builder.append_value(trace_id);
            upid_builder.append_value(proc.upid);
            pid_builder.append_value(proc.pid);
            name_builder.append_option(proc.name.as_deref());
            parent_upid_builder.append_option(proc.parent_upid);
            // Build cmdline list
            for arg in &proc.cmdline {
                cmdline_builder.values().append_value(arg);
            }
            cmdline_builder.append(true);
        }

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(trace_id_builder.finish()),
                Arc::new(upid_builder.finish()),
                Arc::new(pid_builder.finish()),
                Arc::new(name_builder.finish()),
                Arc::new(parent_upid_builder.finish()),
                Arc::new(cmdline_builder.finish()),
            ],
        )?;

        let file = File::create(&paths.process)?;
        let mut writer = ArrowWriter::try_new(file, schema, Some(props.clone()))?;
        writer.write(&batch)?;
        writer.close()?;
    }

    if !data.threads.is_empty() {
        let schema = Arc::new(Schema::new(vec![
            Field::new("trace_id", DataType::Utf8, false),
            Field::new("utid", DataType::Int64, false),
            Field::new("tid", DataType::Int32, false),
            Field::new("name", DataType::Utf8, true),
            Field::new("upid", DataType::Int64, true),
        ]));

        let mut trace_id_builder = StringBuilder::new();
        let mut utid_builder = Int64Builder::new();
        let mut tid_builder = Int32Builder::new();
        let mut name_builder = StringBuilder::new();
        let mut upid_builder = Int64Builder::new();

        for thread in &data.threads {
            trace_id_builder.append_value(trace_id);
            utid_builder.append_value(thread.utid);
            tid_builder.append_value(thread.tid);
            name_builder.append_option(thread.name.as_deref());
            upid_builder.append_option(thread.upid);
        }

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(trace_id_builder.finish()),
                Arc::new(utid_builder.finish()),
                Arc::new(tid_builder.finish()),
                Arc::new(name_builder.finish()),
                Arc::new(upid_builder.finish()),
            ],
        )?;

        let file = File::create(&paths.thread)?;
        let mut writer = ArrowWriter::try_new(file, schema, Some(props.clone()))?;
        writer.write(&batch)?;
        writer.close()?;
    }

    if !data.sched_slices.is_empty() {
        let schema = Arc::new(Schema::new(vec![
            Field::new("trace_id", DataType::Utf8, false),
            Field::new("ts", DataType::Int64, false),
            Field::new("dur", DataType::Int64, false),
            Field::new("cpu", DataType::Int32, false),
            Field::new("utid", DataType::Int64, false),
            Field::new("end_state", DataType::Int32, true),
            Field::new("priority", DataType::Int32, false),
        ]));

        let file = File::create(&paths.sched_slice)?;
        let mut writer = ArrowWriter::try_new(file, schema.clone(), Some(props.clone()))?;

        for chunk in data.sched_slices.chunks(PARQUET_BATCH_SIZE) {
            let mut trace_id_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 32);
            let mut ts_builder = Int64Builder::with_capacity(chunk.len());
            let mut dur_builder = Int64Builder::with_capacity(chunk.len());
            let mut cpu_builder = Int32Builder::with_capacity(chunk.len());
            let mut utid_builder = Int64Builder::with_capacity(chunk.len());
            let mut end_state_builder = Int32Builder::with_capacity(chunk.len());
            let mut priority_builder = Int32Builder::with_capacity(chunk.len());

            for slice in chunk {
                trace_id_builder.append_value(trace_id);
                ts_builder.append_value(slice.ts);
                dur_builder.append_value(slice.dur);
                cpu_builder.append_value(slice.cpu);
                utid_builder.append_value(slice.utid);
                end_state_builder.append_option(slice.end_state);
                priority_builder.append_value(slice.priority);
            }

            let batch = RecordBatch::try_new(
                schema.clone(),
                vec![
                    Arc::new(trace_id_builder.finish()),
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
    }

    if !data.thread_states.is_empty() {
        let schema = Arc::new(Schema::new(vec![
            Field::new("trace_id", DataType::Utf8, false),
            Field::new("ts", DataType::Int64, false),
            Field::new("dur", DataType::Int64, false),
            Field::new("utid", DataType::Int64, false),
            Field::new("state", DataType::Int32, false),
            Field::new("cpu", DataType::Int32, true),
        ]));

        let file = File::create(&paths.thread_state)?;
        let mut writer = ArrowWriter::try_new(file, schema.clone(), Some(props.clone()))?;

        for chunk in data.thread_states.chunks(PARQUET_BATCH_SIZE) {
            let mut trace_id_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 32);
            let mut ts_builder = Int64Builder::with_capacity(chunk.len());
            let mut dur_builder = Int64Builder::with_capacity(chunk.len());
            let mut utid_builder = Int64Builder::with_capacity(chunk.len());
            let mut state_builder = Int32Builder::with_capacity(chunk.len());
            let mut cpu_builder = Int32Builder::with_capacity(chunk.len());

            for state in chunk {
                trace_id_builder.append_value(trace_id);
                ts_builder.append_value(state.ts);
                dur_builder.append_value(state.dur);
                utid_builder.append_value(state.utid);
                state_builder.append_value(state.state);
                cpu_builder.append_option(state.cpu);
            }

            let batch = RecordBatch::try_new(
                schema.clone(),
                vec![
                    Arc::new(trace_id_builder.finish()),
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
    }

    if !data.counter_tracks.is_empty() {
        let schema = Arc::new(Schema::new(vec![
            Field::new("trace_id", DataType::Utf8, false),
            Field::new("id", DataType::Int64, false),
            Field::new("name", DataType::Utf8, false),
            Field::new("unit", DataType::Utf8, true),
        ]));

        let mut trace_id_builder = StringBuilder::new();
        let mut id_builder = Int64Builder::new();
        let mut name_builder = StringBuilder::new();
        let mut unit_builder = StringBuilder::new();

        for track in &data.counter_tracks {
            trace_id_builder.append_value(trace_id);
            id_builder.append_value(track.id);
            name_builder.append_value(&track.name);
            unit_builder.append_option(track.unit.as_deref());
        }

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(trace_id_builder.finish()),
                Arc::new(id_builder.finish()),
                Arc::new(name_builder.finish()),
                Arc::new(unit_builder.finish()),
            ],
        )?;

        let file = File::create(&paths.counter_track)?;
        let mut writer = ArrowWriter::try_new(file, schema, Some(props.clone()))?;
        writer.write(&batch)?;
        writer.close()?;
    }

    if !data.counters.is_empty() {
        let schema = Arc::new(Schema::new(vec![
            Field::new("trace_id", DataType::Utf8, false),
            Field::new("ts", DataType::Int64, false),
            Field::new("track_id", DataType::Int64, false),
            Field::new("value", DataType::Float64, false),
        ]));

        let file = File::create(&paths.counter)?;
        let mut writer = ArrowWriter::try_new(file, schema.clone(), Some(props.clone()))?;

        for chunk in data.counters.chunks(PARQUET_BATCH_SIZE) {
            let mut trace_id_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 32);
            let mut ts_builder = Int64Builder::with_capacity(chunk.len());
            let mut track_id_builder = Int64Builder::with_capacity(chunk.len());
            let mut value_builder = Float64Builder::with_capacity(chunk.len());

            for counter in chunk {
                trace_id_builder.append_value(trace_id);
                ts_builder.append_value(counter.ts);
                track_id_builder.append_value(counter.track_id);
                value_builder.append_value(counter.value);
            }

            let batch = RecordBatch::try_new(
                schema.clone(),
                vec![
                    Arc::new(trace_id_builder.finish()),
                    Arc::new(ts_builder.finish()),
                    Arc::new(track_id_builder.finish()),
                    Arc::new(value_builder.finish()),
                ],
            )?;
            writer.write(&batch)?;
        }
        writer.close()?;
    }

    if !data.slices.is_empty() {
        let schema = Arc::new(Schema::new(vec![
            Field::new("trace_id", DataType::Utf8, false),
            Field::new("id", DataType::Int64, false),
            Field::new("ts", DataType::Int64, false),
            Field::new("dur", DataType::Int64, false),
            Field::new("track_id", DataType::Int64, false),
            Field::new("utid", DataType::Int64, true),
            Field::new("name", DataType::Utf8, false),
            Field::new("category", DataType::Utf8, true),
            Field::new("depth", DataType::Int32, false),
        ]));

        let file = File::create(&paths.slice)?;
        let mut writer = ArrowWriter::try_new(file, schema.clone(), Some(props.clone()))?;

        for chunk in data.slices.chunks(PARQUET_BATCH_SIZE) {
            let mut trace_id_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 32);
            let mut id_builder = Int64Builder::with_capacity(chunk.len());
            let mut ts_builder = Int64Builder::with_capacity(chunk.len());
            let mut dur_builder = Int64Builder::with_capacity(chunk.len());
            let mut track_id_builder = Int64Builder::with_capacity(chunk.len());
            let mut utid_builder = Int64Builder::with_capacity(chunk.len());
            let mut name_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 32);
            let mut category_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 16);
            let mut depth_builder = Int32Builder::with_capacity(chunk.len());

            for slice in chunk {
                trace_id_builder.append_value(trace_id);
                id_builder.append_value(slice.id);
                ts_builder.append_value(slice.ts);
                dur_builder.append_value(slice.dur);
                track_id_builder.append_value(slice.track_id);
                utid_builder.append_option(slice.utid);
                name_builder.append_value(&slice.name);
                category_builder.append_option(slice.category.as_deref());
                depth_builder.append_value(slice.depth);
            }

            let batch = RecordBatch::try_new(
                schema.clone(),
                vec![
                    Arc::new(trace_id_builder.finish()),
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
    }

    // Track metadata table
    if !data.tracks.is_empty() {
        let schema = Arc::new(Schema::new(vec![
            Field::new("trace_id", DataType::Utf8, false),
            Field::new("id", DataType::Int64, false),
            Field::new("name", DataType::Utf8, false),
            Field::new("parent_id", DataType::Int64, true),
        ]));

        let file = File::create(&paths.track)?;
        let mut writer = ArrowWriter::try_new(file, schema.clone(), Some(props.clone()))?;

        for chunk in data.tracks.chunks(PARQUET_BATCH_SIZE) {
            let mut trace_id_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 32);
            let mut id_builder = Int64Builder::with_capacity(chunk.len());
            let mut name_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 64);
            let mut parent_id_builder = Int64Builder::with_capacity(chunk.len());

            for track in chunk {
                trace_id_builder.append_value(trace_id);
                id_builder.append_value(track.id);
                name_builder.append_value(&track.name);
                parent_id_builder.append_option(track.parent_id);
            }

            let batch = RecordBatch::try_new(
                schema.clone(),
                vec![
                    Arc::new(trace_id_builder.finish()),
                    Arc::new(id_builder.finish()),
                    Arc::new(name_builder.finish()),
                    Arc::new(parent_id_builder.finish()),
                ],
            )?;
            writer.write(&batch)?;
        }
        writer.close()?;
    }

    // Args (debug annotations) table
    if !data.args.is_empty() {
        let schema = Arc::new(Schema::new(vec![
            Field::new("trace_id", DataType::Utf8, false),
            Field::new("slice_id", DataType::Int64, false),
            Field::new("key", DataType::Utf8, false),
            Field::new("int_value", DataType::Int64, true),
            Field::new("string_value", DataType::Utf8, true),
            Field::new("real_value", DataType::Float64, true),
        ]));

        let file = File::create(&paths.args)?;
        let mut writer = ArrowWriter::try_new(file, schema.clone(), Some(props.clone()))?;

        for chunk in data.args.chunks(PARQUET_BATCH_SIZE) {
            let mut trace_id_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 32);
            let mut slice_id_builder = Int64Builder::with_capacity(chunk.len());
            let mut key_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 32);
            let mut int_value_builder = Int64Builder::with_capacity(chunk.len());
            let mut string_value_builder =
                StringBuilder::with_capacity(chunk.len(), chunk.len() * 64);
            let mut real_value_builder = Float64Builder::with_capacity(chunk.len());

            for arg in chunk {
                trace_id_builder.append_value(trace_id);
                slice_id_builder.append_value(arg.slice_id);
                key_builder.append_value(&arg.key);
                int_value_builder.append_option(arg.int_value);
                string_value_builder.append_option(arg.string_value.as_deref());
                real_value_builder.append_option(arg.real_value);
            }

            let batch = RecordBatch::try_new(
                schema.clone(),
                vec![
                    Arc::new(trace_id_builder.finish()),
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
    }

    // Instant events (packet events, etc.)
    if !data.instants.is_empty() {
        let schema = Arc::new(Schema::new(vec![
            Field::new("trace_id", DataType::Utf8, false),
            Field::new("id", DataType::Int64, false),
            Field::new("ts", DataType::Int64, false),
            Field::new("track_id", DataType::Int64, false),
            Field::new("utid", DataType::Int64, true),
            Field::new("name", DataType::Utf8, false),
            Field::new("category", DataType::Utf8, true),
        ]));

        let file = File::create(&paths.instant)?;
        let mut writer = ArrowWriter::try_new(file, schema.clone(), Some(props.clone()))?;

        for chunk in data.instants.chunks(PARQUET_BATCH_SIZE) {
            let mut trace_id_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 32);
            let mut id_builder = Int64Builder::with_capacity(chunk.len());
            let mut ts_builder = Int64Builder::with_capacity(chunk.len());
            let mut track_id_builder = Int64Builder::with_capacity(chunk.len());
            let mut utid_builder = Int64Builder::with_capacity(chunk.len());
            let mut name_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 32);
            let mut category_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 16);

            for instant in chunk {
                trace_id_builder.append_value(trace_id);
                id_builder.append_value(instant.id);
                ts_builder.append_value(instant.ts);
                track_id_builder.append_value(instant.track_id);
                utid_builder.append_option(instant.utid);
                name_builder.append_value(&instant.name);
                category_builder.append_option(instant.category.as_deref());
            }

            let batch = RecordBatch::try_new(
                schema.clone(),
                vec![
                    Arc::new(trace_id_builder.finish()),
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
    }

    // Instant args (debug annotations for instant events)
    if !data.instant_args.is_empty() {
        let schema = Arc::new(Schema::new(vec![
            Field::new("trace_id", DataType::Utf8, false),
            Field::new("instant_id", DataType::Int64, false),
            Field::new("key", DataType::Utf8, false),
            Field::new("int_value", DataType::Int64, true),
            Field::new("string_value", DataType::Utf8, true),
            Field::new("real_value", DataType::Float64, true),
        ]));

        let file = File::create(&paths.instant_args)?;
        let mut writer = ArrowWriter::try_new(file, schema.clone(), Some(props.clone()))?;

        for chunk in data.instant_args.chunks(PARQUET_BATCH_SIZE) {
            let mut trace_id_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 32);
            let mut instant_id_builder = Int64Builder::with_capacity(chunk.len());
            let mut key_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 32);
            let mut int_value_builder = Int64Builder::with_capacity(chunk.len());
            let mut string_value_builder =
                StringBuilder::with_capacity(chunk.len(), chunk.len() * 64);
            let mut real_value_builder = Float64Builder::with_capacity(chunk.len());

            for arg in chunk {
                trace_id_builder.append_value(trace_id);
                instant_id_builder.append_value(arg.instant_id);
                key_builder.append_value(&arg.key);
                int_value_builder.append_option(arg.int_value);
                string_value_builder.append_option(arg.string_value.as_deref());
                real_value_builder.append_option(arg.real_value);
            }

            let batch = RecordBatch::try_new(
                schema.clone(),
                vec![
                    Arc::new(trace_id_builder.finish()),
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
    }

    // Stack trace tables

    // Symbols (function names)
    if !data.symbols.is_empty() {
        let schema = Arc::new(Schema::new(vec![
            Field::new("trace_id", DataType::Utf8, false),
            Field::new("id", DataType::Int64, false),
            Field::new("name", DataType::Utf8, false),
        ]));

        let mut trace_id_builder = StringBuilder::new();
        let mut id_builder = Int64Builder::new();
        let mut name_builder = StringBuilder::new();

        for symbol in &data.symbols {
            trace_id_builder.append_value(trace_id);
            id_builder.append_value(symbol.id);
            name_builder.append_value(&symbol.name);
        }

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(trace_id_builder.finish()),
                Arc::new(id_builder.finish()),
                Arc::new(name_builder.finish()),
            ],
        )?;

        let file = File::create(&paths.symbol)?;
        let mut writer = ArrowWriter::try_new(file, schema, Some(props.clone()))?;
        writer.write(&batch)?;
        writer.close()?;
    }

    // Stack mappings
    if !data.stack_mappings.is_empty() {
        let schema = Arc::new(Schema::new(vec![
            Field::new("trace_id", DataType::Utf8, false),
            Field::new("id", DataType::Int64, false),
            Field::new("build_id", DataType::Utf8, true),
            Field::new("name", DataType::Utf8, true),
            Field::new("exact_offset", DataType::Int64, false),
            Field::new("start_offset", DataType::Int64, false),
        ]));

        let mut trace_id_builder = StringBuilder::new();
        let mut id_builder = Int64Builder::new();
        let mut build_id_builder = StringBuilder::new();
        let mut name_builder = StringBuilder::new();
        let mut exact_offset_builder = Int64Builder::new();
        let mut start_offset_builder = Int64Builder::new();

        for mapping in &data.stack_mappings {
            trace_id_builder.append_value(trace_id);
            id_builder.append_value(mapping.id);
            build_id_builder.append_option(mapping.build_id.as_deref());
            name_builder.append_option(mapping.name.as_deref());
            exact_offset_builder.append_value(mapping.exact_offset);
            start_offset_builder.append_value(mapping.start_offset);
        }

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(trace_id_builder.finish()),
                Arc::new(id_builder.finish()),
                Arc::new(build_id_builder.finish()),
                Arc::new(name_builder.finish()),
                Arc::new(exact_offset_builder.finish()),
                Arc::new(start_offset_builder.finish()),
            ],
        )?;

        let file = File::create(&paths.stack_mapping)?;
        let mut writer = ArrowWriter::try_new(file, schema, Some(props.clone()))?;
        writer.write(&batch)?;
        writer.close()?;
    }

    // Frames
    if !data.frames.is_empty() {
        let schema = Arc::new(Schema::new(vec![
            Field::new("trace_id", DataType::Utf8, false),
            Field::new("id", DataType::Int64, false),
            Field::new("name", DataType::Utf8, true),
            Field::new("mapping_id", DataType::Int64, true),
            Field::new("rel_pc", DataType::Int64, false),
            Field::new("symbol_id", DataType::Int64, true),
        ]));

        let mut trace_id_builder = StringBuilder::new();
        let mut id_builder = Int64Builder::new();
        let mut name_builder = StringBuilder::new();
        let mut mapping_id_builder = Int64Builder::new();
        let mut rel_pc_builder = Int64Builder::new();
        let mut symbol_id_builder = Int64Builder::new();

        for frame in &data.frames {
            trace_id_builder.append_value(trace_id);
            id_builder.append_value(frame.id);
            name_builder.append_option(frame.name.as_deref());
            mapping_id_builder.append_option(frame.mapping_id);
            rel_pc_builder.append_value(frame.rel_pc);
            symbol_id_builder.append_option(frame.symbol_id);
        }

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(trace_id_builder.finish()),
                Arc::new(id_builder.finish()),
                Arc::new(name_builder.finish()),
                Arc::new(mapping_id_builder.finish()),
                Arc::new(rel_pc_builder.finish()),
                Arc::new(symbol_id_builder.finish()),
            ],
        )?;

        let file = File::create(&paths.frame)?;
        let mut writer = ArrowWriter::try_new(file, schema, Some(props.clone()))?;
        writer.write(&batch)?;
        writer.close()?;
    }

    // Callsites
    if !data.callsites.is_empty() {
        let schema = Arc::new(Schema::new(vec![
            Field::new("trace_id", DataType::Utf8, false),
            Field::new("id", DataType::Int64, false),
            Field::new("parent_id", DataType::Int64, true),
            Field::new("frame_id", DataType::Int64, false),
            Field::new("depth", DataType::Int32, false),
        ]));

        let file = File::create(&paths.callsite)?;
        let mut writer = ArrowWriter::try_new(file, schema.clone(), Some(props.clone()))?;

        for chunk in data.callsites.chunks(PARQUET_BATCH_SIZE) {
            let mut trace_id_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 32);
            let mut id_builder = Int64Builder::with_capacity(chunk.len());
            let mut parent_id_builder = Int64Builder::with_capacity(chunk.len());
            let mut frame_id_builder = Int64Builder::with_capacity(chunk.len());
            let mut depth_builder = Int32Builder::with_capacity(chunk.len());

            for callsite in chunk {
                trace_id_builder.append_value(trace_id);
                id_builder.append_value(callsite.id);
                parent_id_builder.append_option(callsite.parent_id);
                frame_id_builder.append_value(callsite.frame_id);
                depth_builder.append_value(callsite.depth);
            }

            let batch = RecordBatch::try_new(
                schema.clone(),
                vec![
                    Arc::new(trace_id_builder.finish()),
                    Arc::new(id_builder.finish()),
                    Arc::new(parent_id_builder.finish()),
                    Arc::new(frame_id_builder.finish()),
                    Arc::new(depth_builder.finish()),
                ],
            )?;
            writer.write(&batch)?;
        }
        writer.close()?;
    }

    // Perf samples
    if !data.perf_samples.is_empty() {
        let schema = Arc::new(Schema::new(vec![
            Field::new("trace_id", DataType::Utf8, false),
            Field::new("ts", DataType::Int64, false),
            Field::new("utid", DataType::Int64, false),
            Field::new("callsite_id", DataType::Int64, true),
            Field::new("cpu", DataType::Int32, true),
        ]));

        let file = File::create(&paths.perf_sample)?;
        let mut writer = ArrowWriter::try_new(file, schema.clone(), Some(props.clone()))?;

        for chunk in data.perf_samples.chunks(PARQUET_BATCH_SIZE) {
            let mut trace_id_builder = StringBuilder::with_capacity(chunk.len(), chunk.len() * 32);
            let mut ts_builder = Int64Builder::with_capacity(chunk.len());
            let mut utid_builder = Int64Builder::with_capacity(chunk.len());
            let mut callsite_id_builder = Int64Builder::with_capacity(chunk.len());
            let mut cpu_builder = Int32Builder::with_capacity(chunk.len());

            for sample in chunk {
                trace_id_builder.append_value(trace_id);
                ts_builder.append_value(sample.ts);
                utid_builder.append_value(sample.utid);
                callsite_id_builder.append_option(sample.callsite_id);
                cpu_builder.append_option(sample.cpu);
            }

            let batch = RecordBatch::try_new(
                schema.clone(),
                vec![
                    Arc::new(trace_id_builder.finish()),
                    Arc::new(ts_builder.finish()),
                    Arc::new(utid_builder.finish()),
                    Arc::new(callsite_id_builder.finish()),
                    Arc::new(cpu_builder.finish()),
                ],
            )?;
            writer.write(&batch)?;
        }
        writer.close()?;
    }

    // Network interface table
    if !data.network_interfaces.is_empty() {
        let schema = Arc::new(Schema::new(vec![
            Field::new("trace_id", DataType::Utf8, false),
            Field::new("namespace", DataType::Utf8, false),
            Field::new("interface_name", DataType::Utf8, false),
            Field::new("ip_address", DataType::Utf8, false),
            Field::new("address_type", DataType::Utf8, false),
        ]));

        let mut trace_id_builder = StringBuilder::new();
        let mut namespace_builder = StringBuilder::new();
        let mut interface_name_builder = StringBuilder::new();
        let mut ip_address_builder = StringBuilder::new();
        let mut address_type_builder = StringBuilder::new();

        for iface in &data.network_interfaces {
            trace_id_builder.append_value(trace_id);
            namespace_builder.append_value(&iface.namespace);
            interface_name_builder.append_value(&iface.interface_name);
            ip_address_builder.append_value(&iface.ip_address);
            address_type_builder.append_value(&iface.address_type);
        }

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(trace_id_builder.finish()),
                Arc::new(namespace_builder.finish()),
                Arc::new(interface_name_builder.finish()),
                Arc::new(ip_address_builder.finish()),
                Arc::new(address_type_builder.finish()),
            ],
        )?;

        let file = File::create(&paths.network_interface)?;
        let mut writer = ArrowWriter::try_new(file, schema, Some(props.clone()))?;
        writer.write(&batch)?;
        writer.close()?;
    }

    // Socket connection table
    if !data.socket_connections.is_empty() {
        let schema = Arc::new(Schema::new(vec![
            Field::new("trace_id", DataType::Utf8, false),
            Field::new("socket_id", DataType::Int64, false),
            Field::new("track_id", DataType::Int64, false),
            Field::new("protocol", DataType::Utf8, false),
            Field::new("src_ip", DataType::Utf8, false),
            Field::new("src_port", DataType::Int32, false),
            Field::new("dest_ip", DataType::Utf8, false),
            Field::new("dest_port", DataType::Int32, false),
            Field::new("address_family", DataType::Utf8, false),
        ]));

        let mut trace_id_builder = StringBuilder::new();
        let mut socket_id_builder = Int64Builder::new();
        let mut track_id_builder = Int64Builder::new();
        let mut protocol_builder = StringBuilder::new();
        let mut src_ip_builder = StringBuilder::new();
        let mut src_port_builder = Int32Builder::new();
        let mut dest_ip_builder = StringBuilder::new();
        let mut dest_port_builder = Int32Builder::new();
        let mut address_family_builder = StringBuilder::new();

        for conn in &data.socket_connections {
            trace_id_builder.append_value(trace_id);
            socket_id_builder.append_value(conn.socket_id);
            track_id_builder.append_value(conn.track_id);
            protocol_builder.append_value(conn.protocol);
            src_ip_builder.append_value(&conn.src_ip);
            src_port_builder.append_value(conn.src_port);
            dest_ip_builder.append_value(&conn.dest_ip);
            dest_port_builder.append_value(conn.dest_port);
            address_family_builder.append_value(conn.address_family);
        }

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(trace_id_builder.finish()),
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

        let file = File::create(&paths.socket_connection)?;
        let mut writer = ArrowWriter::try_new(file, schema, Some(props.clone()))?;
        writer.write(&batch)?;
        writer.close()?;
    }

    // Clock snapshot table
    if !data.clock_snapshots.is_empty() {
        let schema = Arc::new(Schema::new(vec![
            Field::new("trace_id", DataType::Utf8, false),
            Field::new("clock_id", DataType::Int32, false),
            Field::new("clock_name", DataType::Utf8, false),
            Field::new("timestamp_ns", DataType::Int64, false),
            Field::new("is_primary", DataType::Boolean, false),
        ]));

        let mut trace_id_builder = StringBuilder::new();
        let mut clock_id_builder = Int32Builder::new();
        let mut clock_name_builder = StringBuilder::new();
        let mut timestamp_ns_builder = Int64Builder::new();
        let mut is_primary_builder = BooleanBuilder::new();

        for clock in &data.clock_snapshots {
            trace_id_builder.append_value(trace_id);
            clock_id_builder.append_value(clock.clock_id);
            clock_name_builder.append_value(&clock.clock_name);
            timestamp_ns_builder.append_value(clock.timestamp_ns);
            is_primary_builder.append_value(clock.is_primary);
        }

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(trace_id_builder.finish()),
                Arc::new(clock_id_builder.finish()),
                Arc::new(clock_name_builder.finish()),
                Arc::new(timestamp_ns_builder.finish()),
                Arc::new(is_primary_builder.finish()),
            ],
        )?;

        let file = File::create(&paths.clock_snapshot)?;
        let mut writer = ArrowWriter::try_new(file, schema, Some(props.clone()))?;
        writer.write(&batch)?;
        writer.close()?;
    }

    Ok(())
}

/// Result from processing a trace (used for parallel processing)
struct TraceProcessingResult {
    trace_id: String,
    source_path: PathBuf,
    parquet_paths: ParquetPaths,
    event_count: usize,
    error: Option<String>,
    /// If true, the Parquet files don't have a trace_id column and need it injected during import.
    /// This is the case for Parquet directories from `systing --parquet`.
    needs_trace_id_injection: bool,
}

/// Run DuckDB → Perfetto conversion.
/// This is a separate path from the main multi-trace → DuckDB conversion.
fn run_duckdb_to_perfetto_convert(
    duckdb_path: &Path,
    output: &Path,
    trace_id: Option<String>,
    verbose: bool,
) -> Result<()> {
    use systing::duckdb::{duckdb_to_parquet, get_trace_ids};

    let start_time = Instant::now();

    // Get available trace IDs
    let trace_ids = get_trace_ids(duckdb_path)?;

    if trace_ids.is_empty() {
        bail!(
            "No traces found in DuckDB database: {}",
            duckdb_path.display()
        );
    }

    // Determine which trace to export
    let selected_trace_id = match trace_id {
        Some(id) => {
            if !trace_ids.contains(&id) {
                bail!(
                    "Trace ID '{}' not found in database. Available traces: {:?}",
                    id,
                    trace_ids
                );
            }
            id
        }
        None => {
            if trace_ids.len() > 1 {
                bail!(
                    "Database contains multiple traces: {:?}\n\
                     Use --trace-id to specify which trace to export.",
                    trace_ids
                );
            }
            trace_ids.into_iter().next().unwrap()
        }
    };

    eprintln!(
        "Converting DuckDB trace '{}' to Perfetto...",
        selected_trace_id
    );

    // Create temp directory for intermediate Parquet files
    let temp_dir = tempfile::tempdir()?;
    let temp_path = temp_dir.path();

    if verbose {
        eprintln!("Using temp directory: {}", temp_path.display());
    }

    // Step 1: Export DuckDB to Parquet
    let export_start = Instant::now();
    duckdb_to_parquet(duckdb_path, temp_path, &selected_trace_id)?;
    let export_time = export_start.elapsed();

    if verbose {
        eprintln!(
            "DuckDB → Parquet export time: {:.2}s",
            export_time.as_secs_f64()
        );
    }

    // Step 2: Convert Parquet to Perfetto
    let convert_start = Instant::now();
    systing::parquet_to_perfetto::convert(temp_path, output)?;
    let convert_time = convert_start.elapsed();

    if verbose {
        eprintln!(
            "Parquet → Perfetto conversion time: {:.2}s",
            convert_time.as_secs_f64()
        );
    }

    let total_time = start_time.elapsed();
    eprintln!(
        "Converted '{}' → {} in {:.2}s",
        selected_trace_id,
        output.display(),
        total_time.as_secs_f64()
    );

    Ok(())
}

/// Run the convert command
fn run_convert(
    inputs: Vec<PathBuf>,
    output: PathBuf,
    trace_id: Option<String>,
    recursive: bool,
    verbose: bool,
) -> Result<()> {
    let start_time = Instant::now();

    // Find all trace inputs (Perfetto .pb files, Parquet directories, or DuckDB files)
    let trace_inputs = find_trace_inputs(&inputs, recursive)?;
    if trace_inputs.is_empty() {
        bail!("No trace files, Parquet directories, or DuckDB files found in the specified inputs");
    }

    // Separate inputs by type
    let mut pb_files = Vec::new();
    let mut parquet_dirs = Vec::new();
    let mut duckdb_files = Vec::new();

    for input in trace_inputs {
        match input {
            TraceInput::PbFile(p) => pb_files.push(p),
            TraceInput::ParquetDir(p) => parquet_dirs.push(p),
            TraceInput::DuckDbFile(p) => duckdb_files.push(p),
        }
    }

    // Check for DuckDB → Perfetto conversion path
    if !duckdb_files.is_empty() && is_perfetto_output(&output) {
        // DuckDB → Perfetto conversion
        if duckdb_files.len() > 1 {
            bail!(
                "DuckDB → Perfetto conversion only supports a single DuckDB file. \
                 Found {} DuckDB files.",
                duckdb_files.len()
            );
        }
        if !pb_files.is_empty() || !parquet_dirs.is_empty() {
            bail!(
                "DuckDB → Perfetto conversion cannot be mixed with other input types. \
                 Found {} Perfetto files and {} Parquet directories.",
                pb_files.len(),
                parquet_dirs.len()
            );
        }
        return run_duckdb_to_perfetto_convert(&duckdb_files[0], &output, trace_id, verbose);
    }

    // Self-reference check: ensure no DuckDB input resolves to the same path as the output
    if !duckdb_files.is_empty() {
        let parent = output
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        if let Ok(canon_parent) = parent.canonicalize() {
            let output_canon = canon_parent.join(output.file_name().unwrap_or_default());
            for db_file in &duckdb_files {
                if let Ok(input_canon) = db_file.canonicalize() {
                    if input_canon == output_canon {
                        bail!(
                            "Input DuckDB file '{}' is the same as the output path. \
                             Cannot use the output file as an input.",
                            db_file.display()
                        );
                    }
                }
            }
        }
    }

    // Standard path: convert to DuckDB database
    let mut source_counts = Vec::new();
    if !pb_files.is_empty() {
        source_counts.push(format!(
            "{} Perfetto trace file{}",
            pb_files.len(),
            if pb_files.len() == 1 { "" } else { "s" }
        ));
    }
    if !parquet_dirs.is_empty() {
        source_counts.push(format!(
            "{} Parquet director{}",
            parquet_dirs.len(),
            if parquet_dirs.len() == 1 { "y" } else { "ies" }
        ));
    }
    if !duckdb_files.is_empty() {
        source_counts.push(format!(
            "{} DuckDB file{}",
            duckdb_files.len(),
            if duckdb_files.len() == 1 { "" } else { "s" }
        ));
    }
    eprintln!("Found {}", source_counts.join(", "));

    // Prepare trace info for .pb files
    let pb_traces: Vec<TraceInfo> = pb_files
        .iter()
        .map(|input| TraceInfo {
            trace_id: generate_trace_id(input),
            source_path: input.clone(),
        })
        .collect();

    // Make trace IDs unique if there are duplicates
    let mut id_counts: HashMap<String, usize> = HashMap::new();
    let pb_traces: Vec<TraceInfo> = pb_traces
        .into_iter()
        .map(|mut t| {
            t.trace_id = make_unique_trace_id(t.trace_id, &mut id_counts);
            t
        })
        .collect();

    // Prepare trace info for Parquet directories (with unique IDs)
    let parquet_traces: Vec<TraceInfo> = parquet_dirs
        .iter()
        .map(|input| {
            let base_id = generate_trace_id(input);
            let trace_id = make_unique_trace_id(base_id, &mut id_counts);
            TraceInfo {
                trace_id,
                source_path: input.clone(),
            }
        })
        .collect();

    // Phase 1c: Pre-scan DuckDB input files for their trace IDs
    struct DuckDbInput {
        path: PathBuf,
        mappings: Vec<TraceImportMapping>,
    }
    let mut duckdb_inputs: Vec<DuckDbInput> = Vec::new();
    let mut duckdb_trace_count = 0usize;

    for db_file in &duckdb_files {
        let trace_info = get_trace_info(db_file)
            .with_context(|| format!("Failed to read traces from '{}'", db_file.display()))?;
        if trace_info.is_empty() {
            eprintln!(
                "Warning: DuckDB file '{}' contains no traces, skipping",
                db_file.display()
            );
            continue;
        }

        let mut mappings = Vec::new();
        for (old_id, source_path) in &trace_info {
            let base_id = generate_trace_id(db_file);
            // If the DuckDB has multiple traces, incorporate the original trace ID into the base
            let base_id = if trace_info.len() > 1 {
                format!("{base_id}_{old_id}")
            } else {
                base_id
            };
            let new_id = make_unique_trace_id(base_id, &mut id_counts);
            mappings.push(TraceImportMapping {
                old_id: old_id.clone(),
                new_id,
                source_path: source_path.clone(),
            });
        }

        duckdb_trace_count += trace_info.len();
        duckdb_inputs.push(DuckDbInput {
            path: db_file.clone(),
            mappings,
        });
    }

    let total_traces = pb_traces.len() + parquet_traces.len() + duckdb_trace_count;

    // Remove existing output database
    if output.exists() {
        fs::remove_file(&output)?;
    }

    // Create temp directory for Parquet files (only needed for .pb processing)
    let temp_dir = tempfile::tempdir()?;
    let temp_path = temp_dir.path();
    if verbose && !pb_traces.is_empty() {
        eprintln!("Using temp directory: {}", temp_path.display());
    }

    let progress = ProgressBar::new(total_traces as u64);
    progress.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} Processing traces...")
            .unwrap()
            .progress_chars("#>-"),
    );

    // Phase 1a: Process .pb files in parallel (if any)
    let load_start = Instant::now();
    let mut results: Vec<TraceProcessingResult> = Vec::new();
    let num_cpus = get_num_cpus();

    if !pb_traces.is_empty() {
        let num_workers = num_cpus.min(pb_traces.len());
        if verbose {
            eprintln!("Using {num_workers} parallel workers for .pb extraction");
        }

        let num_pb_traces = pb_traces.len();
        let (tx, rx) = mpsc::sync_channel::<TraceProcessingResult>(num_workers * 2);
        let work_idx = AtomicUsize::new(0);
        let progress_ref = &progress;

        thread::scope(|s| {
            for _ in 0..num_workers {
                let tx = tx.clone();
                let work_idx = &work_idx;
                let traces = &pb_traces;
                s.spawn(move || loop {
                    let idx = work_idx.fetch_add(1, Ordering::Relaxed);
                    if idx >= num_pb_traces {
                        break;
                    }
                    let trace = &traces[idx];
                    let parquet_paths = ParquetPaths::with_trace_prefix(temp_path, &trace.trace_id);

                    let result = process_trace_to_parquet(trace, &parquet_paths);
                    let processing_result = match result {
                        Ok(event_count) => TraceProcessingResult {
                            trace_id: trace.trace_id.clone(),
                            source_path: trace.source_path.clone(),
                            parquet_paths,
                            event_count,
                            error: None,
                            needs_trace_id_injection: false, // Extracted files have trace_id
                        },
                        Err(e) => TraceProcessingResult {
                            trace_id: trace.trace_id.clone(),
                            source_path: trace.source_path.clone(),
                            parquet_paths,
                            event_count: 0,
                            error: Some(e.to_string()),
                            needs_trace_id_injection: false,
                        },
                    };
                    progress_ref.inc(1);
                    if tx.send(processing_result).is_err() {
                        break;
                    }
                });
            }
        });
        drop(tx);

        results.extend(rx);
    }

    // Phase 1b: Process Parquet directories (no extraction needed - just create results)
    for trace in &parquet_traces {
        let parquet_paths = ParquetPaths::new(&trace.source_path);
        results.push(TraceProcessingResult {
            trace_id: trace.trace_id.clone(),
            source_path: trace.source_path.clone(),
            parquet_paths,
            event_count: 0, // Unknown for pre-existing Parquet files
            error: None,
            needs_trace_id_injection: true, // Parquet dirs don't have trace_id column
        });
        progress.inc(1);
    }

    progress.finish_with_message("Trace processing complete");

    let load_time = load_start.elapsed();
    if verbose {
        eprintln!("Trace processing time: {:.2}s", load_time.as_secs_f64());
    }

    // Count successes and failures
    let mut total_events = 0usize;
    let mut errors: Vec<String> = Vec::new();
    let successful_results: Vec<&TraceProcessingResult> = results
        .iter()
        .filter(|r| {
            if let Some(ref e) = r.error {
                errors.push(format!("{}: {}", r.source_path.display(), e));
                false
            } else {
                total_events += r.event_count;
                true
            }
        })
        .collect();

    if successful_results.is_empty() && duckdb_inputs.is_empty() {
        bail!("All traces failed to process");
    }

    // Phase 2: Create DuckDB database and bulk import
    let total_import_count = successful_results.len() + duckdb_trace_count;
    if verbose {
        eprintln!("Importing {} traces into DuckDB...", total_import_count);
    }
    let import_start = Instant::now();

    let conn = Connection::open(&output)?;
    conn.execute_batch(&format!("SET threads TO {num_cpus};"))?;
    create_schema(&conn)?;

    // Wrap all imports in a single transaction for performance
    conn.execute_batch("BEGIN TRANSACTION")?;

    // Import _traces table for Parquet/.pb results
    for result in &successful_results {
        conn.execute(
            "INSERT INTO _traces (trace_id, source_path) VALUES (?, ?)",
            params![
                result.trace_id,
                result.source_path.to_string_lossy().to_string()
            ],
        )?;
    }

    // Import Parquet files for a table, filtering to only existing files.
    // Handles trace_id injection for Parquet directories (which don't have trace_id column).
    let import_table = |table_name: &str, get_path: fn(&ParquetPaths) -> &PathBuf| -> Result<()> {
        let start = Instant::now();

        // Separate paths by whether they need trace_id injection
        let mut with_trace_id: Vec<String> = Vec::new();
        let mut needs_injection: Vec<(&str, String)> = Vec::new();

        for result in successful_results.iter() {
            let path = get_path(&result.parquet_paths);
            if path.exists() {
                let path_str = path.to_string_lossy().into_owned();
                if result.needs_trace_id_injection {
                    needs_injection.push((&result.trace_id, path_str));
                } else {
                    with_trace_id.push(path_str);
                }
            }
        }

        // Import files that already have trace_id
        if !with_trace_id.is_empty() {
            let paths_list = with_trace_id
                .iter()
                .map(|p| format!("'{}'", p.replace('\'', "''")))
                .collect::<Vec<_>>()
                .join(", ");
            conn.execute_batch(&format!(
                "INSERT INTO {table_name} SELECT * FROM read_parquet([{paths_list}])"
            ))?;
        }

        // Import files that need trace_id injection (one at a time to add trace_id)
        for (trace_id, path) in needs_injection {
            let escaped_path = path.replace('\'', "''");
            let escaped_trace_id = trace_id.replace('\'', "''");
            conn.execute_batch(&format!(
                "INSERT INTO {table_name} SELECT '{escaped_trace_id}' as trace_id, * FROM read_parquet('{escaped_path}')"
            ))?;
        }

        if verbose {
            eprintln!(
                "  {} import: {:.2}s",
                table_name,
                start.elapsed().as_secs_f64()
            );
        }
        Ok(())
    };

    import_table("process", |p| &p.process)?;
    import_table("thread", |p| &p.thread)?;
    import_table("sched_slice", |p| &p.sched_slice)?;
    import_table("thread_state", |p| &p.thread_state)?;
    import_table("irq_slice", |p| &p.irq_slice)?;
    import_table("softirq_slice", |p| &p.softirq_slice)?;
    import_table("wakeup_new", |p| &p.wakeup_new)?;
    import_table("process_exit", |p| &p.process_exit)?;
    import_table("counter_track", |p| &p.counter_track)?;
    import_table("counter", |p| &p.counter)?;
    import_table("slice", |p| &p.slice)?;
    import_table("track", |p| &p.track)?;
    import_table("args", |p| &p.args)?;
    // Instant events (packet events, etc.)
    import_table("instant", |p| &p.instant)?;
    import_table("instant_args", |p| &p.instant_args)?;
    // Stack trace tables
    import_table("stack_profile_symbol", |p| &p.symbol)?;
    import_table("stack_profile_mapping", |p| &p.stack_mapping)?;
    import_table("stack_profile_frame", |p| &p.frame)?;
    import_table("stack_profile_callsite", |p| &p.callsite)?;
    import_table("perf_sample", |p| &p.perf_sample)?;
    // New query-friendly stack tables
    import_table("stack", |p| &p.stack)?;
    import_table("stack_sample", |p| &p.stack_sample)?;
    // Network interface metadata
    import_table("network_interface", |p| &p.network_interface)?;
    // Socket connection metadata
    import_table("socket_connection", |p| &p.socket_connection)?;
    // New network tables
    import_table("network_syscall", |p| &p.network_syscall)?;
    import_table("network_packet", |p| &p.network_packet)?;
    import_table("network_socket", |p| &p.network_socket)?;
    import_table("network_poll", |p| &p.network_poll)?;
    // Clock snapshot data
    import_table("clock_snapshot", |p| &p.clock_snapshot)?;
    // System info
    import_table("sysinfo", |p| &p.sysinfo)?;

    // Phase 2b: Import DuckDB traces via ATTACH.
    // Note: any failure here will propagate before COMMIT, so the entire transaction
    // (including earlier Parquet imports) will be rolled back when conn is dropped.
    for duckdb_input in &duckdb_inputs {
        if verbose {
            eprintln!(
                "  Importing {} traces from DuckDB file '{}'...",
                duckdb_input.mappings.len(),
                duckdb_input.path.display()
            );
        }
        let db_start = Instant::now();
        import_duckdb_traces(&conn, &duckdb_input.path, &duckdb_input.mappings).with_context(
            || {
                format!(
                    "Failed to import traces from DuckDB file '{}'",
                    duckdb_input.path.display()
                )
            },
        )?;
        if verbose {
            eprintln!(
                "  DuckDB import from '{}': {:.2}s",
                duckdb_input.path.display(),
                db_start.elapsed().as_secs_f64()
            );
        }
    }

    conn.execute_batch("COMMIT")?;

    let import_time = import_start.elapsed();
    if verbose {
        eprintln!("Import time: {:.2}s", import_time.as_secs_f64());
    }

    if !errors.is_empty() {
        eprintln!("\nConversion errors:");
        for error in &errors {
            eprintln!("  {error}");
        }
    }

    let elapsed = start_time.elapsed();
    let db_size = fs::metadata(&output)
        .map(|m| m.len() as f64 / (1024.0 * 1024.0))
        .unwrap_or(0.0);

    eprintln!(
        "\nComplete! Created {} ({:.1} MB) in {:.1}s",
        output.display(),
        db_size,
        elapsed.as_secs_f64()
    );

    // Build summary of import sources
    let parquet_dir_count = successful_results
        .iter()
        .filter(|r| r.needs_trace_id_injection)
        .count();
    let pb_file_count = successful_results.len() - parquet_dir_count;
    let total_imported = pb_file_count + parquet_dir_count + duckdb_trace_count;

    let mut parts = Vec::new();
    if pb_file_count > 0 {
        parts.push(format!(
            "{pb_file_count} from .pb with {total_events} events"
        ));
    }
    if parquet_dir_count > 0 {
        parts.push(format!("{parquet_dir_count} from Parquet"));
    }
    if duckdb_trace_count > 0 {
        parts.push(format!("{duckdb_trace_count} from DuckDB"));
    }

    if parts.len() <= 1 {
        // Single source type
        if pb_file_count > 0 {
            let s = if pb_file_count == 1 { "" } else { "s" };
            eprintln!("  {pb_file_count} trace{s} imported, {total_events} total events");
        } else if parquet_dir_count > 0 {
            let s = if parquet_dir_count == 1 { "" } else { "s" };
            eprintln!(
                "  {} trace{} imported from Parquet director{}",
                parquet_dir_count,
                s,
                if parquet_dir_count == 1 { "y" } else { "ies" }
            );
        } else if duckdb_trace_count > 0 {
            let s = if duckdb_trace_count == 1 { "" } else { "s" };
            eprintln!("  {} trace{} imported from DuckDB", duckdb_trace_count, s);
        }
    } else {
        // Mixed sources
        eprintln!(
            "  {} traces imported ({})",
            total_imported,
            parts.join(", ")
        );
    }

    Ok(())
}

/// Process a single trace: read, extract, compute durations, and write to Parquet
fn process_trace_to_parquet(trace: &TraceInfo, paths: &ParquetPaths) -> Result<usize> {
    let reader = open_trace_reader(&trace.source_path)?;

    // Use streaming extraction - streamable types are written directly to parquet
    let (data, streamed_count) = extract_trace_data_with_streaming(reader, &trace.trace_id, paths)?;

    let event_count = data.sched_slices.len()
        + data.thread_states.len()
        + data.counters.len()
        + data.slices.len()
        + data.perf_samples.len()
        + streamed_count; // Add streamed instants/instant_args to count

    // Write remaining data (instants/instant_args already written via streaming)
    write_data_to_parquet(&trace.trace_id, &data, paths)
        .with_context(|| format!("Failed writing Parquet for trace {}", trace.trace_id))?;

    Ok(event_count)
}

/// Run the query command
fn run_query(database: PathBuf, sql: Option<String>, format: String) -> Result<()> {
    if !database.exists() {
        bail!("Database not found: {}", database.display());
    }

    let conn = Connection::open(&database)?;

    match sql {
        Some(query) => {
            execute_query(&conn, &query, &format)?;
        }
        None => {
            // Interactive mode
            run_interactive(&conn, &format)?;
        }
    }

    Ok(())
}

/// Execute a single query and display results
fn execute_query(conn: &Connection, sql: &str, format: &str) -> Result<()> {
    let mut stmt = conn.prepare(sql)?;
    let mut rows = stmt.query([])?;

    // Get column info from the first row or statement
    let column_count = rows.as_ref().map_or(0, |r| r.column_count());
    let column_names: Vec<String> = if let Some(row_ref) = rows.as_ref() {
        (0..column_count)
            .map(|i| {
                row_ref
                    .column_name(i)
                    .map_or("?".to_string(), |s| s.to_string())
            })
            .collect()
    } else {
        Vec::new()
    };

    let mut rows_data: Vec<Vec<String>> = Vec::new();

    while let Some(row) = rows.next()? {
        let mut row_values = Vec::new();
        for i in 0..column_count {
            let value: duckdb::types::Value = row.get(i)?;
            let str_value = match value {
                duckdb::types::Value::Null => "NULL".to_string(),
                duckdb::types::Value::Boolean(b) => b.to_string(),
                duckdb::types::Value::TinyInt(n) => n.to_string(),
                duckdb::types::Value::SmallInt(n) => n.to_string(),
                duckdb::types::Value::Int(n) => n.to_string(),
                duckdb::types::Value::BigInt(n) => n.to_string(),
                duckdb::types::Value::HugeInt(n) => n.to_string(),
                duckdb::types::Value::UTinyInt(n) => n.to_string(),
                duckdb::types::Value::USmallInt(n) => n.to_string(),
                duckdb::types::Value::UInt(n) => n.to_string(),
                duckdb::types::Value::UBigInt(n) => n.to_string(),
                duckdb::types::Value::Float(n) => n.to_string(),
                duckdb::types::Value::Double(n) => n.to_string(),
                duckdb::types::Value::Text(s) => s,
                _ => format!("{value:?}"),
            };
            row_values.push(str_value);
        }
        rows_data.push(row_values);
    }

    match format {
        "csv" => {
            println!("{}", column_names.join(","));
            for row in &rows_data {
                println!("{}", row.join(","));
            }
        }
        "json" => {
            let json_rows: Vec<serde_json::Value> = rows_data
                .iter()
                .map(|row| {
                    let obj: serde_json::Map<String, serde_json::Value> = column_names
                        .iter()
                        .zip(row.iter())
                        .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                        .collect();
                    serde_json::Value::Object(obj)
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&json_rows)?);
        }
        _ => {
            // Table format
            print_table(&column_names, &rows_data);
        }
    }

    eprintln!("\n{} rows returned", rows_data.len());
    Ok(())
}

const MAX_COLUMN_WIDTH: usize = 50;

fn print_table(headers: &[String], rows: &[Vec<String>]) {
    if rows.is_empty() {
        println!("(no results)");
        return;
    }

    let mut widths: Vec<usize> = headers.iter().map(String::len).collect();
    for row in rows {
        for (i, val) in row.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(val.len());
            }
        }
    }

    for w in &mut widths {
        *w = (*w).min(MAX_COLUMN_WIDTH);
    }

    let header_line: Vec<String> = headers
        .iter()
        .enumerate()
        .map(|(i, h)| format!("{:width$}", h, width = widths.get(i).copied().unwrap_or(10)))
        .collect();
    println!("{}", header_line.join(" | "));

    let sep: Vec<String> = widths.iter().map(|w| "-".repeat(*w)).collect();
    println!("{}", sep.join("-+-"));

    for row in rows {
        let row_line: Vec<String> = row
            .iter()
            .enumerate()
            .map(|(i, v)| {
                let width = widths.get(i).copied().unwrap_or(10);
                let truncated = if v.len() > width && width > 3 {
                    format!("{}...", &v[..width.saturating_sub(3)])
                } else {
                    v.clone()
                };
                format!("{truncated:width$}")
            })
            .collect();
        println!("{}", row_line.join(" | "));
    }
}

fn run_interactive(conn: &Connection, format: &str) -> Result<()> {
    use std::io::{self, BufRead, Write};

    eprintln!("systing-analyze interactive mode");
    eprintln!("Enter SQL queries (end with ';'), or 'quit' to exit.\n");

    eprintln!("Available tables:");
    let mut stmt = conn.prepare(
        "SELECT table_name FROM information_schema.tables
         WHERE table_schema = 'main' ORDER BY table_name",
    )?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(0)?;
        eprintln!("  {name}");
    }
    eprintln!();

    let stdin = io::stdin();
    let mut query_buffer = String::new();

    loop {
        let prompt = if query_buffer.is_empty() {
            "sql> "
        } else {
            "...> "
        };
        eprint!("{prompt}");
        io::stderr().flush()?;

        let mut line = String::new();
        if stdin.lock().read_line(&mut line)? == 0 {
            break;
        }

        let trimmed = line.trim();
        if trimmed.eq_ignore_ascii_case("quit") || trimmed.eq_ignore_ascii_case("exit") {
            break;
        }

        query_buffer.push_str(&line);

        if query_buffer.trim().ends_with(';') {
            let query = query_buffer.trim().trim_end_matches(';').to_string();
            query_buffer.clear();

            if !query.is_empty() {
                if let Err(e) = execute_query(conn, &query, format) {
                    eprintln!("Error: {e}");
                }
            }
            println!();
        }
    }

    Ok(())
}

/// Run the validate command
fn run_validate(path: PathBuf, verbose: bool, json: bool) -> Result<()> {
    use systing::{
        validate_duckdb, validate_parquet_dir, validate_perfetto_trace, ValidationResult,
    };

    if !path.exists() {
        bail!("Path not found: {}", path.display());
    }

    let result: ValidationResult = if path.is_dir() {
        // Validate Parquet directory
        if verbose {
            eprintln!("Validating Parquet directory: {}", path.display());
        }
        validate_parquet_dir(&path)
    } else {
        // Validate file based on extension
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if name.ends_with(".duckdb") {
            // Validate DuckDB database
            if verbose {
                eprintln!("Validating DuckDB database: {}", path.display());
            }
            validate_duckdb(&path)
        } else if name.ends_with(".pb") || name.ends_with(".pb.gz") {
            if verbose {
                eprintln!("Validating Perfetto trace: {}", path.display());
            }
            validate_perfetto_trace(&path)
        } else {
            bail!("Unrecognized file type. Use a Parquet directory, .duckdb database, or .pb/.pb.gz trace file.");
        }
    };

    if json {
        // Output as JSON
        let output = serde_json::json!({
            "valid": result.is_valid(),
            "errors": result.errors.iter().map(|e| e.to_string()).collect::<Vec<_>>(),
            "warnings": result.warnings.iter().map(|w| w.to_string()).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        // Output as text
        if result.is_valid() {
            if verbose {
                eprintln!("All validation checks passed.");
            }
            println!("Validation: PASSED");
        } else {
            println!("Validation: FAILED");
            println!();
            println!("Errors ({}):", result.errors.len());
            for error in &result.errors {
                println!("  - {error}");
            }
        }

        if !result.warnings.is_empty() {
            println!();
            println!("Warnings ({}):", result.warnings.len());
            for warning in &result.warnings {
                println!("  - {warning}");
            }
        }
    }

    if result.is_valid() {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Convert {
            inputs,
            output,
            trace_id,
            recursive,
            verbose,
        } => run_convert(inputs, output, trace_id, recursive, verbose),
        Commands::Query {
            database,
            sql,
            format,
        } => run_query(database, sql, format),
        Commands::Validate {
            path,
            verbose,
            json,
        } => run_validate(path, verbose, json),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use perfetto_protos::interned_data::InternedData;
    use perfetto_protos::track_event::track_event::Type;
    use perfetto_protos::track_event::{EventName, TrackEvent};

    #[test]
    fn test_interned_event_names_are_decoded() {
        let mut extractor = TraceExtractor::new();

        // Create an interned_data packet with event names
        let mut interned_packet = TracePacket::default();
        let mut interned_data = InternedData::default();

        let mut event_name1 = EventName::default();
        event_name1.set_iid(100);
        event_name1.set_name("TCP packet_send".to_string());
        interned_data.event_names.push(event_name1);

        let mut event_name2 = EventName::default();
        event_name2.set_iid(101);
        event_name2.set_name("tcp_recv".to_string());
        interned_data.event_names.push(event_name2);

        interned_packet.interned_data = Some(interned_data).into();

        // Process the interned data packet
        extractor.process_packet(&interned_packet).unwrap();

        // Verify interned names are stored
        assert_eq!(
            extractor.interned_event_names.get(&100),
            Some(&"TCP packet_send".to_string())
        );
        assert_eq!(
            extractor.interned_event_names.get(&101),
            Some(&"tcp_recv".to_string())
        );

        // Create a track descriptor so we have a valid track_uuid mapping
        let mut track_desc_packet = TracePacket::default();
        let mut track_desc = perfetto_protos::track_descriptor::TrackDescriptor::default();
        track_desc.set_uuid(12345);
        track_desc.set_name("test_track".to_string());
        track_desc_packet.set_track_descriptor(track_desc);
        extractor.process_packet(&track_desc_packet).unwrap();

        // Create a track_event that uses name_iid instead of inline name
        let mut event_packet = TracePacket::default();
        event_packet.set_timestamp(1000);

        let mut track_event = TrackEvent::default();
        track_event.set_type(Type::TYPE_SLICE_BEGIN);
        track_event.set_track_uuid(12345);
        track_event.set_name_iid(100); // References "TCP packet_send"

        event_packet.set_track_event(track_event);

        // Process the event packet
        extractor.process_packet(&event_packet).unwrap();

        // Verify the slice was created with the correct interned name
        assert_eq!(extractor.data.slices.len(), 1);
        assert_eq!(extractor.data.slices[0].name, "TCP packet_send");
        assert_eq!(extractor.data.slices[0].ts, 1000);
    }

    #[test]
    fn test_inline_name_is_used_when_present() {
        // Note: In Perfetto's protobuf schema, `name` and `name_iid` are in a oneof,
        // so only one can be present at a time. This test verifies inline names work.
        let mut extractor = TraceExtractor::new();

        // Create a track descriptor
        let mut track_desc_packet = TracePacket::default();
        let mut track_desc = perfetto_protos::track_descriptor::TrackDescriptor::default();
        track_desc.set_uuid(99999);
        track_desc.set_name("test_track".to_string());
        track_desc_packet.set_track_descriptor(track_desc);
        extractor.process_packet(&track_desc_packet).unwrap();

        // Create a track_event with inline name (no name_iid)
        let mut event_packet = TracePacket::default();
        event_packet.set_timestamp(2000);

        let mut track_event = TrackEvent::default();
        track_event.set_type(Type::TYPE_SLICE_BEGIN);
        track_event.set_track_uuid(99999);
        track_event.set_name("inline_name".to_string());

        event_packet.set_track_event(track_event);
        extractor.process_packet(&event_packet).unwrap();

        // Verify inline name is used
        assert_eq!(extractor.data.slices.len(), 1);
        assert_eq!(extractor.data.slices[0].name, "inline_name");
    }

    #[test]
    fn test_unknown_name_iid_falls_back_to_unknown() {
        let mut extractor = TraceExtractor::new();

        // Create a track descriptor
        let mut track_desc_packet = TracePacket::default();
        let mut track_desc = perfetto_protos::track_descriptor::TrackDescriptor::default();
        track_desc.set_uuid(77777);
        track_desc.set_name("test_track".to_string());
        track_desc_packet.set_track_descriptor(track_desc);
        extractor.process_packet(&track_desc_packet).unwrap();

        // Create a track_event with a name_iid that doesn't exist in interned data
        let mut event_packet = TracePacket::default();
        event_packet.set_timestamp(3000);

        let mut track_event = TrackEvent::default();
        track_event.set_type(Type::TYPE_SLICE_BEGIN);
        track_event.set_track_uuid(77777);
        track_event.set_name_iid(99999); // Non-existent iid

        event_packet.set_track_event(track_event);
        extractor.process_packet(&event_packet).unwrap();

        // Verify fallback to "unknown"
        assert_eq!(extractor.data.slices.len(), 1);
        assert_eq!(extractor.data.slices[0].name, "unknown");
    }

    // ========================================================================
    // Stack trace / callsite tree tests
    // ========================================================================

    #[test]
    fn test_get_or_create_callsite_empty_frames() {
        let mut extractor = TraceExtractor::new();

        // Empty frame list should return 0
        let result = extractor.get_or_create_callsite(&[]);
        assert_eq!(result, 0);
        assert!(extractor.data.callsites.is_empty());
    }

    #[test]
    fn test_get_or_create_callsite_single_frame() {
        let mut extractor = TraceExtractor::new();

        // Single frame: frame_ids[0] is the leaf (and root)
        let frame_ids = vec![100u64];
        let callsite_id = extractor.get_or_create_callsite(&frame_ids);

        assert_eq!(callsite_id, 1);
        assert_eq!(extractor.data.callsites.len(), 1);

        let callsite = &extractor.data.callsites[0];
        assert_eq!(callsite.id, 1);
        assert_eq!(callsite.parent_id, None); // Single frame has no parent
        assert_eq!(callsite.frame_id, 100);
        assert_eq!(callsite.depth, 0); // Leaf is depth 0
    }

    #[test]
    fn test_get_or_create_callsite_multiple_frames() {
        let mut extractor = TraceExtractor::new();

        // frame_ids[0]=10 is leaf, frame_ids[2]=30 is root
        let frame_ids = vec![10u64, 20, 30];
        let callsite_id = extractor.get_or_create_callsite(&frame_ids);

        assert_eq!(extractor.data.callsites.len(), 3);

        let root = extractor
            .data
            .callsites
            .iter()
            .find(|c| c.frame_id == 30)
            .unwrap();
        assert_eq!(root.parent_id, None);
        assert_eq!(root.depth, 2);

        let middle = extractor
            .data
            .callsites
            .iter()
            .find(|c| c.frame_id == 20)
            .unwrap();
        assert_eq!(middle.parent_id, Some(root.id));
        assert_eq!(middle.depth, 1);

        let leaf = extractor
            .data
            .callsites
            .iter()
            .find(|c| c.frame_id == 10)
            .unwrap();
        assert_eq!(leaf.parent_id, Some(middle.id));
        assert_eq!(leaf.depth, 0);

        assert_eq!(callsite_id, leaf.id);
    }

    #[test]
    fn test_get_or_create_callsite_deduplication() {
        let mut extractor = TraceExtractor::new();

        // First stack: [A, B, C] where C is root
        let stack1 = vec![1u64, 2, 3];
        let id1 = extractor.get_or_create_callsite(&stack1);

        // Second stack with same frames should return same ID
        let id2 = extractor.get_or_create_callsite(&stack1);
        assert_eq!(id1, id2);
        assert_eq!(extractor.data.callsites.len(), 3); // No new callsites created
    }

    #[test]
    fn test_get_or_create_callsite_shared_prefix() {
        let mut extractor = TraceExtractor::new();

        let stack1 = vec![1u64, 2, 3]; // [leaf=1, 2, root=3]
        let id1 = extractor.get_or_create_callsite(&stack1);
        assert_eq!(extractor.data.callsites.len(), 3);

        let stack2 = vec![4u64, 2, 3]; // [leaf=4, 2, root=3] shares [2, 3] suffix
        let id2 = extractor.get_or_create_callsite(&stack2);

        assert_eq!(extractor.data.callsites.len(), 4); // Only 1 new callsite for frame 4
        assert_ne!(id1, id2);

        let new_callsite = extractor
            .data
            .callsites
            .iter()
            .find(|c| c.frame_id == 4)
            .unwrap();
        assert_eq!(new_callsite.depth, 0);

        let parent = extractor
            .data
            .callsites
            .iter()
            .find(|c| c.id == new_callsite.parent_id.unwrap())
            .unwrap();
        assert_eq!(parent.frame_id, 2);
    }

    #[test]
    fn test_get_or_create_callsite_different_roots() {
        let mut extractor = TraceExtractor::new();

        extractor.get_or_create_callsite(&[1u64, 2]);
        assert_eq!(extractor.data.callsites.len(), 2);

        extractor.get_or_create_callsite(&[3u64, 4]); // Different root
        assert_eq!(extractor.data.callsites.len(), 4);

        let roots_count = extractor
            .data
            .callsites
            .iter()
            .filter(|c| c.parent_id.is_none())
            .count();
        assert_eq!(roots_count, 2);
    }

    #[test]
    fn test_get_or_create_callsite_chain_integrity() {
        let mut extractor = TraceExtractor::new();

        let frame_ids: Vec<u64> = (0..10).collect();
        let leaf_id = extractor.get_or_create_callsite(&frame_ids);

        let callsites: HashMap<i64, &CallsiteRecord> =
            extractor.data.callsites.iter().map(|c| (c.id, c)).collect();

        let mut current_id = leaf_id;
        let mut visited_frames = Vec::new();
        loop {
            let callsite = callsites.get(&current_id).unwrap();
            visited_frames.push(callsite.frame_id as u64);
            match callsite.parent_id {
                Some(pid) => current_id = pid,
                None => break,
            }
        }

        assert_eq!(visited_frames, frame_ids);
    }

    #[test]
    fn test_finalize_stack_data_converts_interned_data() {
        let mut extractor = TraceExtractor::new();

        extractor
            .interned_function_names
            .insert(1, "main".to_string());
        extractor
            .interned_function_names
            .insert(2, "foo".to_string());

        extractor.interned_mappings.insert(
            10,
            StackMappingRecord {
                id: 10,
                build_id: Some("abc123".to_string()),
                name: Some("libc.so".to_string()),
                exact_offset: 0,
                start_offset: 0,
            },
        );

        extractor.interned_frames.insert(
            100,
            FrameRecord {
                id: 100,
                name: Some("main".to_string()),
                mapping_id: Some(10),
                rel_pc: 0x1234,
                symbol_id: Some(1),
            },
        );

        extractor.finalize_stack_data();

        assert_eq!(extractor.data.symbols.len(), 2);
        let symbol_names: Vec<_> = extractor.data.symbols.iter().map(|s| &s.name).collect();
        assert!(symbol_names.contains(&&"main".to_string()));
        assert!(symbol_names.contains(&&"foo".to_string()));

        assert_eq!(extractor.data.stack_mappings.len(), 1);
        assert_eq!(extractor.data.stack_mappings[0].id, 10);
        assert_eq!(
            extractor.data.stack_mappings[0].name,
            Some("libc.so".to_string())
        );

        assert_eq!(extractor.data.frames.len(), 1);
        assert_eq!(extractor.data.frames[0].id, 100);
        assert_eq!(extractor.data.frames[0].name, Some("main".to_string()));
    }

    #[test]
    fn test_process_perf_sample_creates_sample_with_callsite() {
        use perfetto_protos::interned_data::InternedData;
        use perfetto_protos::profile_common::{Callstack, Frame};
        use perfetto_protos::profile_packet::PerfSample;

        let mut extractor = TraceExtractor::new();

        let mut interned_packet = TracePacket::default();
        let mut interned_data = InternedData::default();

        let mut frame1 = Frame::default();
        frame1.set_iid(1);
        interned_data.frames.push(frame1);

        let mut frame2 = Frame::default();
        frame2.set_iid(2);
        interned_data.frames.push(frame2);

        let mut callstack = Callstack::default();
        callstack.set_iid(100);
        callstack.frame_ids = vec![1, 2];
        interned_data.callstacks.push(callstack);

        interned_packet.interned_data = Some(interned_data).into();
        extractor.process_packet(&interned_packet).unwrap();

        let mut sample_packet = TracePacket::default();
        sample_packet.set_timestamp(1000000);

        let mut perf_sample = PerfSample::default();
        perf_sample.set_pid(1234);
        perf_sample.set_tid(5678);
        perf_sample.set_callstack_iid(100);
        perf_sample.cpu = Some(0);

        sample_packet.set_perf_sample(perf_sample);
        extractor.process_packet(&sample_packet).unwrap();

        assert_eq!(extractor.data.perf_samples.len(), 1);
        let sample = &extractor.data.perf_samples[0];
        assert_eq!(sample.ts, 1000000);
        assert_eq!(sample.cpu, Some(0));
        assert!(sample.callsite_id.is_some());
        assert_eq!(extractor.data.callsites.len(), 2);
        assert!(!extractor.data.threads.is_empty());
    }

    #[test]
    fn test_process_perf_sample_without_callstack() {
        use perfetto_protos::profile_packet::PerfSample;

        let mut extractor = TraceExtractor::new();

        let mut sample_packet = TracePacket::default();
        sample_packet.set_timestamp(2000000);

        let mut perf_sample = PerfSample::default();
        perf_sample.set_pid(1234);
        perf_sample.set_tid(5678);

        sample_packet.set_perf_sample(perf_sample);
        extractor.process_packet(&sample_packet).unwrap();

        assert_eq!(extractor.data.perf_samples.len(), 1);
        let sample = &extractor.data.perf_samples[0];
        assert_eq!(sample.ts, 2000000);
        assert_eq!(sample.callsite_id, None);
    }

    #[test]
    fn test_callsite_depth_correctness() {
        let mut extractor = TraceExtractor::new();

        let frame_ids: Vec<u64> = vec![100, 101, 102, 103, 104]; // leaf=100, root=104
        extractor.get_or_create_callsite(&frame_ids);

        for (i, &frame_id) in frame_ids.iter().enumerate() {
            let callsite = extractor
                .data
                .callsites
                .iter()
                .find(|c| c.frame_id == frame_id as i64)
                .unwrap();
            assert_eq!(callsite.depth, i as i32);
        }
    }

    #[test]
    fn test_slice_duration_from_begin_end_events() {
        let mut extractor = TraceExtractor::new();

        // Create a track descriptor
        let mut track_desc_packet = TracePacket::default();
        let mut track_desc = perfetto_protos::track_descriptor::TrackDescriptor::default();
        track_desc.set_uuid(55555);
        track_desc.set_name("network_track".to_string());
        track_desc_packet.set_track_descriptor(track_desc);
        extractor.process_packet(&track_desc_packet).unwrap();

        // Create TYPE_SLICE_BEGIN event at timestamp 1000
        let mut begin_packet = TracePacket::default();
        begin_packet.set_timestamp(1000);

        let mut begin_event = TrackEvent::default();
        begin_event.set_type(Type::TYPE_SLICE_BEGIN);
        begin_event.set_track_uuid(55555);
        begin_event.set_name("tcp_send".to_string());

        begin_packet.set_track_event(begin_event);
        extractor.process_packet(&begin_packet).unwrap();

        // Verify slice was created with dur=0 (not yet ended)
        assert_eq!(extractor.data.slices.len(), 1);
        assert_eq!(extractor.data.slices[0].name, "tcp_send");
        assert_eq!(extractor.data.slices[0].ts, 1000);
        assert_eq!(extractor.data.slices[0].dur, 0);

        // Create TYPE_SLICE_END event at timestamp 5000
        let mut end_packet = TracePacket::default();
        end_packet.set_timestamp(5000);

        let mut end_event = TrackEvent::default();
        end_event.set_type(Type::TYPE_SLICE_END);
        end_event.set_track_uuid(55555);

        end_packet.set_track_event(end_event);
        extractor.process_packet(&end_packet).unwrap();

        // Verify duration was computed: 5000 - 1000 = 4000
        assert_eq!(extractor.data.slices.len(), 1);
        assert_eq!(extractor.data.slices[0].dur, 4000);
    }

    #[test]
    fn test_nested_slices_duration() {
        let mut extractor = TraceExtractor::new();

        // Create a track descriptor
        let mut track_desc_packet = TracePacket::default();
        let mut track_desc = perfetto_protos::track_descriptor::TrackDescriptor::default();
        track_desc.set_uuid(66666);
        track_desc.set_name("nested_track".to_string());
        track_desc_packet.set_track_descriptor(track_desc);
        extractor.process_packet(&track_desc_packet).unwrap();

        // Begin outer slice at t=1000
        let mut outer_begin = TracePacket::default();
        outer_begin.set_timestamp(1000);
        let mut outer_begin_event = TrackEvent::default();
        outer_begin_event.set_type(Type::TYPE_SLICE_BEGIN);
        outer_begin_event.set_track_uuid(66666);
        outer_begin_event.set_name("outer".to_string());
        outer_begin.set_track_event(outer_begin_event);
        extractor.process_packet(&outer_begin).unwrap();

        // Begin inner slice at t=2000
        let mut inner_begin = TracePacket::default();
        inner_begin.set_timestamp(2000);
        let mut inner_begin_event = TrackEvent::default();
        inner_begin_event.set_type(Type::TYPE_SLICE_BEGIN);
        inner_begin_event.set_track_uuid(66666);
        inner_begin_event.set_name("inner".to_string());
        inner_begin.set_track_event(inner_begin_event);
        extractor.process_packet(&inner_begin).unwrap();

        // End inner slice at t=3000
        let mut inner_end = TracePacket::default();
        inner_end.set_timestamp(3000);
        let mut inner_end_event = TrackEvent::default();
        inner_end_event.set_type(Type::TYPE_SLICE_END);
        inner_end_event.set_track_uuid(66666);
        inner_end.set_track_event(inner_end_event);
        extractor.process_packet(&inner_end).unwrap();

        // End outer slice at t=5000
        let mut outer_end = TracePacket::default();
        outer_end.set_timestamp(5000);
        let mut outer_end_event = TrackEvent::default();
        outer_end_event.set_type(Type::TYPE_SLICE_END);
        outer_end_event.set_track_uuid(66666);
        outer_end.set_track_event(outer_end_event);
        extractor.process_packet(&outer_end).unwrap();

        // Verify both slices have correct durations
        assert_eq!(extractor.data.slices.len(), 2);

        // Outer slice: 5000 - 1000 = 4000
        assert_eq!(extractor.data.slices[0].name, "outer");
        assert_eq!(extractor.data.slices[0].dur, 4000);

        // Inner slice: 3000 - 2000 = 1000
        assert_eq!(extractor.data.slices[1].name, "inner");
        assert_eq!(extractor.data.slices[1].dur, 1000);
    }

    #[test]
    fn test_slice_end_without_begin() {
        let mut extractor = TraceExtractor::new();

        // Create a track descriptor
        let mut track_desc_packet = TracePacket::default();
        let mut track_desc = perfetto_protos::track_descriptor::TrackDescriptor::default();
        track_desc.set_uuid(77777);
        track_desc.set_name("test_track".to_string());
        track_desc_packet.set_track_descriptor(track_desc);
        extractor.process_packet(&track_desc_packet).unwrap();

        // Send TYPE_SLICE_END without a corresponding BEGIN
        let mut end_packet = TracePacket::default();
        end_packet.set_timestamp(5000);
        let mut end_event = TrackEvent::default();
        end_event.set_type(Type::TYPE_SLICE_END);
        end_event.set_track_uuid(77777);
        end_packet.set_track_event(end_event);
        extractor.process_packet(&end_packet).unwrap();

        // Should not create any slices or crash
        assert_eq!(extractor.data.slices.len(), 0);
    }

    #[test]
    fn test_unclosed_slice_keeps_zero_duration() {
        let mut extractor = TraceExtractor::new();

        // Create a track descriptor
        let mut track_desc_packet = TracePacket::default();
        let mut track_desc = perfetto_protos::track_descriptor::TrackDescriptor::default();
        track_desc.set_uuid(88888);
        track_desc.set_name("unclosed_track".to_string());
        track_desc_packet.set_track_descriptor(track_desc);
        extractor.process_packet(&track_desc_packet).unwrap();

        // Create TYPE_SLICE_BEGIN but never send TYPE_SLICE_END
        let mut begin_packet = TracePacket::default();
        begin_packet.set_timestamp(1000);
        let mut begin_event = TrackEvent::default();
        begin_event.set_type(Type::TYPE_SLICE_BEGIN);
        begin_event.set_track_uuid(88888);
        begin_event.set_name("unclosed_slice".to_string());
        begin_packet.set_track_event(begin_event);
        extractor.process_packet(&begin_packet).unwrap();

        // Verify slice exists with dur=0 (never closed)
        assert_eq!(extractor.data.slices.len(), 1);
        assert_eq!(extractor.data.slices[0].name, "unclosed_slice");
        assert_eq!(extractor.data.slices[0].ts, 1000);
        assert_eq!(extractor.data.slices[0].dur, 0);
    }

    #[test]
    fn test_multiple_tracks_independent() {
        let mut extractor = TraceExtractor::new();

        // Create two track descriptors
        let mut track1_desc_packet = TracePacket::default();
        let mut track1_desc = perfetto_protos::track_descriptor::TrackDescriptor::default();
        track1_desc.set_uuid(11111);
        track1_desc.set_name("track1".to_string());
        track1_desc_packet.set_track_descriptor(track1_desc);
        extractor.process_packet(&track1_desc_packet).unwrap();

        let mut track2_desc_packet = TracePacket::default();
        let mut track2_desc = perfetto_protos::track_descriptor::TrackDescriptor::default();
        track2_desc.set_uuid(22222);
        track2_desc.set_name("track2".to_string());
        track2_desc_packet.set_track_descriptor(track2_desc);
        extractor.process_packet(&track2_desc_packet).unwrap();

        // Begin slice on track1
        let mut track1_begin = TracePacket::default();
        track1_begin.set_timestamp(1000);
        let mut track1_begin_event = TrackEvent::default();
        track1_begin_event.set_type(Type::TYPE_SLICE_BEGIN);
        track1_begin_event.set_track_uuid(11111);
        track1_begin_event.set_name("slice1".to_string());
        track1_begin.set_track_event(track1_begin_event);
        extractor.process_packet(&track1_begin).unwrap();

        // Begin slice on track2
        let mut track2_begin = TracePacket::default();
        track2_begin.set_timestamp(2000);
        let mut track2_begin_event = TrackEvent::default();
        track2_begin_event.set_type(Type::TYPE_SLICE_BEGIN);
        track2_begin_event.set_track_uuid(22222);
        track2_begin_event.set_name("slice2".to_string());
        track2_begin.set_track_event(track2_begin_event);
        extractor.process_packet(&track2_begin).unwrap();

        // End slice on track2
        let mut track2_end = TracePacket::default();
        track2_end.set_timestamp(3000);
        let mut track2_end_event = TrackEvent::default();
        track2_end_event.set_type(Type::TYPE_SLICE_END);
        track2_end_event.set_track_uuid(22222);
        track2_end.set_track_event(track2_end_event);
        extractor.process_packet(&track2_end).unwrap();

        // End slice on track1
        let mut track1_end = TracePacket::default();
        track1_end.set_timestamp(4000);
        let mut track1_end_event = TrackEvent::default();
        track1_end_event.set_type(Type::TYPE_SLICE_END);
        track1_end_event.set_track_uuid(11111);
        track1_end.set_track_event(track1_end_event);
        extractor.process_packet(&track1_end).unwrap();

        // Verify both slices have correct durations
        assert_eq!(extractor.data.slices.len(), 2);
        assert_eq!(extractor.data.slices[0].name, "slice1");
        assert_eq!(extractor.data.slices[0].dur, 3000); // 4000 - 1000
        assert_eq!(extractor.data.slices[1].name, "slice2");
        assert_eq!(extractor.data.slices[1].dur, 1000); // 3000 - 2000
    }

    #[test]
    fn test_deeply_nested_slices() {
        let mut extractor = TraceExtractor::new();

        // Create a track descriptor
        let mut track_desc_packet = TracePacket::default();
        let mut track_desc = perfetto_protos::track_descriptor::TrackDescriptor::default();
        track_desc.set_uuid(99999);
        track_desc.set_name("deep_track".to_string());
        track_desc_packet.set_track_descriptor(track_desc);
        extractor.process_packet(&track_desc_packet).unwrap();

        // Begin 5 nested slices
        for i in 0..5 {
            let mut begin = TracePacket::default();
            begin.set_timestamp(1000 + (i * 100));
            let mut begin_event = TrackEvent::default();
            begin_event.set_type(Type::TYPE_SLICE_BEGIN);
            begin_event.set_track_uuid(99999);
            begin_event.set_name(format!("level_{i}"));
            begin.set_track_event(begin_event);
            extractor.process_packet(&begin).unwrap();
        }

        // End all 5 slices in LIFO order
        for i in (0..5).rev() {
            let mut end = TracePacket::default();
            end.set_timestamp(2000 + ((4 - i) * 100));
            let mut end_event = TrackEvent::default();
            end_event.set_type(Type::TYPE_SLICE_END);
            end_event.set_track_uuid(99999);
            end.set_track_event(end_event);
            extractor.process_packet(&end).unwrap();
        }

        // Verify all slices have correct durations
        assert_eq!(extractor.data.slices.len(), 5);
        for i in 0..5 {
            assert_eq!(extractor.data.slices[i].name, format!("level_{i}"));
            let expected_dur = 1000 + ((4 - i) * 100) - (i * 100);
            assert_eq!(extractor.data.slices[i].dur, expected_dur as i64);
        }
    }
}
