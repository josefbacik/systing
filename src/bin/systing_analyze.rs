//! systing-analyze: A tool for converting and querying Perfetto trace databases
//!
//! This tool converts Perfetto trace files directly to DuckDB databases for efficient
//! querying and analysis, supporting multiple traces aggregated into a single database.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use duckdb::{params, Connection};
use flate2::read::GzDecoder;
use indicatif::{ProgressBar, ProgressStyle};
use perfetto_protos::ftrace_event_bundle::ftrace_event_bundle::CompactSched;
use perfetto_protos::trace_packet::TracePacket;
use protobuf::Message;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

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
    /// Convert Perfetto trace files to DuckDB database
    Convert {
        /// Input trace files or directories
        #[arg(required = true)]
        inputs: Vec<PathBuf>,

        /// Output DuckDB database path
        #[arg(short, long)]
        output: PathBuf,

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
}

/// Information about a trace being processed
#[derive(Clone)]
struct TraceInfo {
    trace_id: String,
    source_path: PathBuf,
}

fn get_available_memory_gb() -> usize {
    use std::fs::read_to_string;
    // Try to read from /proc/meminfo (Linux)
    if let Ok(meminfo) = read_to_string("/proc/meminfo") {
        for line in meminfo.lines() {
            if line.starts_with("MemAvailable:") {
                if let Some(kb_str) = line.split_whitespace().nth(1) {
                    if let Ok(kb) = kb_str.parse::<usize>() {
                        return kb / 1024 / 1024; // Convert KB to GB
                    }
                }
            }
        }
    }
    // Fallback: assume 32GB available
    32
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

    if safe_id.chars().next().is_none_or(|c| c.is_numeric()) {
        format!("trace_{}", safe_id)
    } else {
        safe_id
    }
}

/// Find all trace files in the given inputs
fn find_trace_files(inputs: &[PathBuf], recursive: bool) -> Result<Vec<PathBuf>> {
    let mut traces = Vec::new();

    for input in inputs {
        if input.is_file() {
            traces.push(input.clone());
        } else if input.is_dir() {
            if recursive {
                for entry in walkdir(input)? {
                    if is_trace_file(&entry) {
                        traces.push(entry);
                    }
                }
            } else {
                for entry in fs::read_dir(input)? {
                    let entry = entry?;
                    let path = entry.path();
                    if path.is_file() && is_trace_file(&path) {
                        traces.push(path);
                    }
                }
            }
        } else {
            bail!("Input path does not exist: {}", input.display());
        }
    }

    Ok(traces)
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

/// Processed trace data ready for database insertion
struct ProcessedTrace {
    trace_id: String,
    source_path: PathBuf,
    data: ExtractedData,
    event_count: usize,
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
    end_state: Option<String>,
    priority: i32,
}

#[derive(Clone)]
struct ThreadStateRecord {
    ts: i64,
    dur: i64,
    utid: i64,
    state: String,
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
    ts: i64,
    dur: i64,
    track_id: i64,
    name: String,
    category: Option<String>,
    depth: i32,
}

struct TraceExtractor {
    data: ExtractedData,
    pid_to_upid: HashMap<i32, i64>,
    tid_to_utid: HashMap<i32, i64>,
    track_uuid_to_id: HashMap<u64, i64>,
    track_uuid_to_utid: HashMap<u64, i64>,
    next_upid: i64,
    next_utid: i64,
    next_track_id: i64,
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
            },
            pid_to_upid: HashMap::new(),
            tid_to_utid: HashMap::new(),
            track_uuid_to_id: HashMap::new(),
            track_uuid_to_utid: HashMap::new(),
            next_upid: 1,
            next_utid: 1,
            next_track_id: 1,
        }
    }

    fn into_data(self) -> ExtractedData {
        self.data
    }

    fn process_packet(&mut self, packet: &TracePacket) {
        self.process_descriptors(packet);
        self.process_events(packet);
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
                        format!("counter_{}", track_id)
                    },
                    unit: counter.unit_name.clone(),
                });
            } else if desc.has_uuid() && desc.has_name() {
                let track_id = self.next_track_id;
                self.next_track_id += 1;
                self.track_uuid_to_id.insert(desc.uuid(), track_id);
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

    fn process_events(&mut self, packet: &TracePacket) {
        if packet.has_ftrace_events() {
            let bundle = packet.ftrace_events();
            let cpu = bundle.cpu() as i32;

            if let Some(compact) = bundle.compact_sched.as_ref() {
                self.extract_compact_sched(compact, cpu);
            }

            for event in &bundle.event {
                let ts = event.timestamp() as i64;

                if event.has_sched_switch() {
                    let switch = event.sched_switch();
                    let next_pid = switch.next_pid();
                    let prev_pid = switch.prev_pid();

                    self.ensure_thread_exists(next_pid, Some(switch.next_comm()));
                    self.ensure_thread_exists(prev_pid, Some(switch.prev_comm()));

                    if let Some(&next_utid) = self.tid_to_utid.get(&next_pid) {
                        self.data.sched_slices.push(SchedSliceRecord {
                            ts,
                            dur: 0,
                            cpu,
                            utid: next_utid,
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
                            state: "R".to_string(),
                            cpu: Some(waking.target_cpu()),
                        });
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
                        let name = if event.has_name() {
                            event.name().to_string()
                        } else {
                            "unknown".to_string()
                        };
                        let track_id = self.track_uuid_to_id.get(&track_uuid).copied().unwrap_or(0);
                        self.data.slices.push(SliceRecord {
                            ts,
                            dur: 0,
                            track_id,
                            name,
                            category: event.categories.first().cloned(),
                            depth: 0,
                        });
                    }
                }
            }
        }
    }

    fn extract_compact_sched(&mut self, compact: &CompactSched, cpu: i32) {
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
            let comm = compact.intern_table.get(comm_idx).map(|s| s.as_str());

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
            let comm = compact.intern_table.get(comm_idx).map(|s| s.as_str());

            self.ensure_thread_exists(pid, comm);

            if let Some(&utid) = self.tid_to_utid.get(&pid) {
                self.data.thread_states.push(ThreadStateRecord {
                    ts: waking_ts,
                    dur: 0,
                    utid,
                    state: "R".to_string(),
                    cpu: Some(target_cpu),
                });
            }
        }
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
                    name: name.map(|s| s.to_string()),
                    parent_upid: None,
                });
                upid
            };

            self.data.threads.push(ThreadRecord {
                utid,
                tid,
                name: name.map(|s| s.to_string()),
                upid: Some(upid),
            });
        }
    }
}

fn extract_trace_data_streaming<R: BufRead>(reader: R) -> Result<ExtractedData> {
    let mut extractor = TraceExtractor::new();
    let packet_iter = TracePacketIterator::new(reader);

    for packet_result in packet_iter {
        let packet = packet_result?;
        extractor.process_packet(&packet);
    }

    Ok(extractor.into_data())
}

fn compute_sched_durations(slices: &mut [SchedSliceRecord]) {
    if slices.is_empty() {
        return;
    }

    slices.sort_unstable_by(|a, b| a.cpu.cmp(&b.cpu).then_with(|| a.ts.cmp(&b.ts)));

    for i in 0..slices.len() - 1 {
        if slices[i].cpu == slices[i + 1].cpu {
            slices[i].dur = slices[i + 1].ts - slices[i].ts;
        }
    }
}

fn create_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS _traces (
            trace_id VARCHAR PRIMARY KEY,
            source_path VARCHAR,
            import_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS process (
            trace_id VARCHAR,
            upid BIGINT,
            pid INTEGER,
            name VARCHAR,
            parent_upid BIGINT
        );

        CREATE TABLE IF NOT EXISTS thread (
            trace_id VARCHAR,
            utid BIGINT,
            tid INTEGER,
            name VARCHAR,
            upid BIGINT
        );

        CREATE TABLE IF NOT EXISTS sched_slice (
            trace_id VARCHAR,
            ts BIGINT,
            dur BIGINT,
            cpu INTEGER,
            utid BIGINT,
            end_state VARCHAR,
            priority INTEGER
        );

        CREATE TABLE IF NOT EXISTS thread_state (
            trace_id VARCHAR,
            ts BIGINT,
            dur BIGINT,
            utid BIGINT,
            state VARCHAR,
            cpu INTEGER
        );

        CREATE TABLE IF NOT EXISTS counter_track (
            trace_id VARCHAR,
            id BIGINT,
            name VARCHAR,
            unit VARCHAR
        );

        CREATE TABLE IF NOT EXISTS counter (
            trace_id VARCHAR,
            ts BIGINT,
            track_id BIGINT,
            value DOUBLE
        );

        CREATE TABLE IF NOT EXISTS slice (
            trace_id VARCHAR,
            ts BIGINT,
            dur BIGINT,
            track_id BIGINT,
            name VARCHAR,
            category VARCHAR,
            depth INTEGER
        );
        ",
    )?;

    Ok(())
}

/// Insert extracted data into DuckDB using Appender for bulk loading
fn insert_data(conn: &Connection, trace_id: &str, data: &ExtractedData) -> Result<()> {
    // Insert processes using appender
    if !data.processes.is_empty() {
        let mut appender = conn.appender("process")?;
        for proc in &data.processes {
            appender.append_row(params![
                trace_id,
                proc.upid,
                proc.pid,
                proc.name.as_deref(),
                proc.parent_upid
            ])?;
        }
    }

    // Insert threads using appender
    if !data.threads.is_empty() {
        let mut appender = conn.appender("thread")?;
        for thread in &data.threads {
            appender.append_row(params![
                trace_id,
                thread.utid,
                thread.tid,
                thread.name.as_deref(),
                thread.upid
            ])?;
        }
    }

    // Insert sched_slices using appender
    if !data.sched_slices.is_empty() {
        let mut appender = conn.appender("sched_slice")?;
        for slice in &data.sched_slices {
            appender.append_row(params![
                trace_id,
                slice.ts,
                slice.dur,
                slice.cpu,
                slice.utid,
                slice.end_state.as_deref(),
                slice.priority
            ])?;
        }
    }

    // Insert thread_states using appender
    if !data.thread_states.is_empty() {
        let mut appender = conn.appender("thread_state")?;
        for state in &data.thread_states {
            appender.append_row(params![
                trace_id,
                state.ts,
                state.dur,
                state.utid,
                state.state.as_str(),
                state.cpu
            ])?;
        }
    }

    // Insert counter_tracks using appender
    if !data.counter_tracks.is_empty() {
        let mut appender = conn.appender("counter_track")?;
        for track in &data.counter_tracks {
            appender.append_row(params![
                trace_id,
                track.id,
                track.name.as_str(),
                track.unit.as_deref()
            ])?;
        }
    }

    // Insert counters using appender
    if !data.counters.is_empty() {
        let mut appender = conn.appender("counter")?;
        for counter in &data.counters {
            appender.append_row(params![
                trace_id,
                counter.ts,
                counter.track_id,
                counter.value
            ])?;
        }
    }

    // Insert slices using appender
    if !data.slices.is_empty() {
        let mut appender = conn.appender("slice")?;
        for slice in &data.slices {
            appender.append_row(params![
                trace_id,
                slice.ts,
                slice.dur,
                slice.track_id,
                slice.name.as_str(),
                slice.category.as_deref(),
                slice.depth
            ])?;
        }
    }

    Ok(())
}

/// Run the convert command
fn run_convert(
    inputs: Vec<PathBuf>,
    output: PathBuf,
    recursive: bool,
    verbose: bool,
) -> Result<()> {
    let start_time = Instant::now();

    // Find all trace files
    let trace_files = find_trace_files(&inputs, recursive)?;
    if trace_files.is_empty() {
        bail!("No trace files found in the specified inputs");
    }
    eprintln!("Found {} trace files", trace_files.len());

    // Prepare trace info
    let traces: Vec<TraceInfo> = trace_files
        .iter()
        .map(|path| TraceInfo {
            trace_id: generate_trace_id(path),
            source_path: path.clone(),
        })
        .collect();

    // Make trace IDs unique if there are duplicates
    let mut id_counts: HashMap<String, usize> = HashMap::new();
    let traces: Vec<TraceInfo> = traces
        .into_iter()
        .map(|mut t| {
            let count = id_counts.entry(t.trace_id.clone()).or_insert(0);
            if *count > 0 {
                t.trace_id = format!("{}_{}", t.trace_id, count);
            }
            *count += 1;
            t
        })
        .collect();

    // Remove existing output database
    if output.exists() {
        fs::remove_file(&output)?;
    }

    // Create DuckDB database and schema
    let conn = Connection::open(&output)?;

    // Configure DuckDB for bulk loading performance
    conn.execute_batch(
        "
        SET threads TO 4;
        SET memory_limit = '2GB';
        ",
    )?;

    create_schema(&conn)?;

    let progress = ProgressBar::new(traces.len() as u64);
    progress.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} Processing traces...")
            .unwrap()
            .progress_chars("#>-"),
    );

    // Bound parallelism based on available memory: each large trace ~15GB peak on average
    // Use up to 80% of available memory, with minimum 2 and maximum 8 workers
    let available_mem_gb = get_available_memory_gb();
    let mem_per_worker_gb = 15;
    let num_workers = ((available_mem_gb * 80 / 100) / mem_per_worker_gb)
        .clamp(2, 8)
        .min(traces.len());
    if verbose {
        eprintln!(
            "Using {} parallel workers ({} GB available)",
            num_workers, available_mem_gb
        );
    }
    let num_traces = traces.len();
    // Buffer 2 results to allow overlap between loading and insertion while limiting memory
    let (tx, rx) = mpsc::sync_channel::<(usize, Result<ProcessedTrace>)>(2);
    let work_idx = AtomicUsize::new(0);

    thread::scope(|s| {
        for _ in 0..num_workers {
            let tx = tx.clone();
            let work_idx = &work_idx;
            let traces = &traces;
            s.spawn(move || loop {
                let idx = work_idx.fetch_add(1, Ordering::Relaxed);
                if idx >= num_traces {
                    break;
                }
                let result = load_and_extract_trace(&traces[idx]);
                if tx.send((idx, result)).is_err() {
                    break;
                }
            });
        }
        drop(tx);

        let mut total_events = 0usize;
        let mut errors: Vec<String> = Vec::new();

        for (idx, result) in rx {
            progress.inc(1);
            match result {
                Ok(processed) => {
                    if let Err(e) = insert_processed_trace(&conn, &processed) {
                        errors.push(format!("{}: {}", processed.source_path.display(), e));
                    } else {
                        total_events += processed.event_count;
                    }
                }
                Err(e) => {
                    errors.push(format!("{}: {}", traces[idx].source_path.display(), e));
                }
            }
        }

        progress.finish_with_message("Import complete");

        if verbose {
            eprintln!(
                "Processing time: {:.2}s",
                start_time.elapsed().as_secs_f64()
            );
        }

        if !errors.is_empty() {
            eprintln!("\nConversion errors:");
            for error in &errors {
                eprintln!("  {}", error);
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
        eprintln!(
            "  {} traces imported, {} total events",
            num_traces - errors.len(),
            total_events
        );
    });

    Ok(())
}

fn load_and_extract_trace(trace: &TraceInfo) -> Result<ProcessedTrace> {
    let reader = open_trace_reader(&trace.source_path)?;
    let mut data = extract_trace_data_streaming(reader)?;
    compute_sched_durations(&mut data.sched_slices);

    let event_count = data.sched_slices.len()
        + data.thread_states.len()
        + data.counters.len()
        + data.slices.len();

    Ok(ProcessedTrace {
        trace_id: trace.trace_id.clone(),
        source_path: trace.source_path.clone(),
        data,
        event_count,
    })
}

fn insert_processed_trace(conn: &Connection, processed: &ProcessedTrace) -> Result<()> {
    conn.execute(
        "INSERT INTO _traces (trace_id, source_path) VALUES (?, ?)",
        params![
            processed.trace_id,
            processed.source_path.to_string_lossy().to_string()
        ],
    )?;
    insert_data(conn, &processed.trace_id, &processed.data)?;
    Ok(())
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
    let column_count = rows.as_ref().map(|r| r.column_count()).unwrap_or(0);
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
                _ => format!("{:?}", value),
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

    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in rows {
        for (i, val) in row.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(val.len());
            }
        }
    }

    widths
        .iter_mut()
        .for_each(|w| *w = (*w).min(MAX_COLUMN_WIDTH));

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
                format!("{:width$}", truncated, width = width)
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
        eprintln!("  {}", name);
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
        eprint!("{}", prompt);
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
                    eprintln!("Error: {}", e);
                }
            }
            println!();
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Convert {
            inputs,
            output,
            recursive,
            verbose,
        } => run_convert(inputs, output, recursive, verbose),
        Commands::Query {
            database,
            sql,
            format,
        } => run_query(database, sql, format),
    }
}
