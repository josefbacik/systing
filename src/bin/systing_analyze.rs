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
use perfetto_protos::trace::Trace;
use protobuf::Message;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, Read};
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

fn read_trace(path: &Path) -> Result<Trace> {
    let file = File::open(path).with_context(|| format!("Failed to open {}", path.display()))?;
    let mut reader = BufReader::new(file);

    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let bytes = if name.ends_with(".gz") {
        let mut decoder = GzDecoder::new(reader);
        let mut bytes = Vec::new();
        decoder
            .read_to_end(&mut bytes)
            .with_context(|| "Failed to decompress gzip file")?;
        bytes
    } else {
        let mut bytes = Vec::new();
        reader
            .read_to_end(&mut bytes)
            .with_context(|| "Failed to read trace file")?;
        bytes
    };

    Trace::parse_from_bytes(&bytes).with_context(|| "Failed to parse Perfetto trace")
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

fn extract_trace_data_raw(trace: &Trace) -> ExtractedData {
    let packet_count = trace.packet.len();
    let estimated_slices = packet_count * 10;

    let mut data = ExtractedData {
        processes: Vec::with_capacity(1024),
        threads: Vec::with_capacity(4096),
        sched_slices: Vec::with_capacity(estimated_slices),
        thread_states: Vec::with_capacity(estimated_slices / 2),
        counters: Vec::with_capacity(packet_count),
        counter_tracks: Vec::with_capacity(256),
        slices: Vec::with_capacity(packet_count / 10),
    };

    let mut pid_to_upid: HashMap<i32, i64> = HashMap::with_capacity(1024);
    let mut tid_to_utid: HashMap<i32, i64> = HashMap::with_capacity(4096);
    let mut track_uuid_to_id: HashMap<u64, i64> = HashMap::with_capacity(512);
    let mut track_uuid_to_utid: HashMap<u64, i64> = HashMap::with_capacity(4096);
    let mut next_upid: i64 = 1;
    let mut next_utid: i64 = 1;
    let mut next_track_id: i64 = 1;

    // First pass: extract descriptors
    for packet in &trace.packet {
        if packet.has_track_descriptor() {
            let desc = packet.track_descriptor();

            if desc.process.is_some() {
                let proc = &desc.process;
                let pid = proc.pid();
                if let std::collections::hash_map::Entry::Vacant(e) = pid_to_upid.entry(pid) {
                    let upid = next_upid;
                    next_upid += 1;
                    e.insert(upid);
                    data.processes.push(ProcessRecord {
                        upid,
                        pid,
                        name: if proc.has_process_name() {
                            Some(proc.process_name().to_string())
                        } else {
                            None
                        },
                        parent_upid: None,
                    });
                }
                if let (true, Some(&upid)) = (desc.has_uuid(), pid_to_upid.get(&pid)) {
                    track_uuid_to_id.insert(desc.uuid(), upid);
                }
            }

            if desc.thread.is_some() {
                let thread = &desc.thread;
                let tid = thread.tid();
                let pid = thread.pid();

                if let std::collections::hash_map::Entry::Vacant(e) = pid_to_upid.entry(pid) {
                    let upid = next_upid;
                    next_upid += 1;
                    e.insert(upid);
                    data.processes.push(ProcessRecord {
                        upid,
                        pid,
                        name: None,
                        parent_upid: None,
                    });
                }

                if let std::collections::hash_map::Entry::Vacant(e) = tid_to_utid.entry(tid) {
                    let utid = next_utid;
                    next_utid += 1;
                    e.insert(utid);
                    data.threads.push(ThreadRecord {
                        utid,
                        tid,
                        name: if thread.has_thread_name() {
                            Some(thread.thread_name().to_string())
                        } else {
                            None
                        },
                        upid: pid_to_upid.get(&pid).copied(),
                    });
                }
                if let (true, Some(&utid)) = (desc.has_uuid(), tid_to_utid.get(&tid)) {
                    track_uuid_to_utid.insert(desc.uuid(), utid);
                }
            }

            if desc.counter.is_some() {
                let track_id = next_track_id;
                next_track_id += 1;
                if desc.has_uuid() {
                    track_uuid_to_id.insert(desc.uuid(), track_id);
                }
                let counter = &desc.counter;
                data.counter_tracks.push(CounterTrackRecord {
                    id: track_id,
                    name: if desc.has_name() {
                        desc.name().to_string()
                    } else {
                        format!("counter_{}", track_id)
                    },
                    unit: if counter.has_unit_name() {
                        Some(counter.unit_name().to_string())
                    } else {
                        None
                    },
                });
            } else if desc.has_uuid() && desc.has_name() {
                // Regular track (for slices)
                let track_id = next_track_id;
                next_track_id += 1;
                track_uuid_to_id.insert(desc.uuid(), track_id);
            }
        }

        if packet.has_process_tree() {
            let tree = packet.process_tree();
            for proc in &tree.processes {
                let pid = proc.pid();
                if let std::collections::hash_map::Entry::Vacant(e) = pid_to_upid.entry(pid) {
                    let upid = next_upid;
                    next_upid += 1;
                    e.insert(upid);
                    data.processes.push(ProcessRecord {
                        upid,
                        pid,
                        name: proc.cmdline.first().cloned(),
                        parent_upid: pid_to_upid.get(&proc.ppid()).copied(),
                    });
                }
            }
            for thread in &tree.threads {
                let tid = thread.tid();
                let tgid = thread.tgid();
                if let std::collections::hash_map::Entry::Vacant(e) = tid_to_utid.entry(tid) {
                    let utid = next_utid;
                    next_utid += 1;
                    e.insert(utid);

                    if let std::collections::hash_map::Entry::Vacant(e) = pid_to_upid.entry(tgid) {
                        let upid = next_upid;
                        next_upid += 1;
                        e.insert(upid);
                        data.processes.push(ProcessRecord {
                            upid,
                            pid: tgid,
                            name: None,
                            parent_upid: None,
                        });
                    }

                    data.threads.push(ThreadRecord {
                        utid,
                        tid,
                        name: if thread.has_name() {
                            Some(thread.name().to_string())
                        } else {
                            None
                        },
                        upid: pid_to_upid.get(&tgid).copied(),
                    });
                }
            }
        }
    }

    // Second pass: extract events
    for packet in &trace.packet {
        if packet.has_ftrace_events() {
            let bundle = packet.ftrace_events();
            let cpu = bundle.cpu() as i32;

            if let Some(compact) = bundle.compact_sched.as_ref() {
                extract_compact_sched(
                    compact,
                    cpu,
                    &mut data,
                    &mut tid_to_utid,
                    &mut pid_to_upid,
                    &mut next_utid,
                    &mut next_upid,
                );
            }

            for event in &bundle.event {
                let ts = event.timestamp() as i64;

                if event.has_sched_switch() {
                    let switch = event.sched_switch();
                    let next_pid = switch.next_pid();
                    let prev_pid = switch.prev_pid();

                    ensure_thread_exists(
                        next_pid,
                        Some(switch.next_comm()),
                        &mut tid_to_utid,
                        &mut pid_to_upid,
                        &mut data,
                        &mut next_utid,
                        &mut next_upid,
                    );
                    ensure_thread_exists(
                        prev_pid,
                        Some(switch.prev_comm()),
                        &mut tid_to_utid,
                        &mut pid_to_upid,
                        &mut data,
                        &mut next_utid,
                        &mut next_upid,
                    );

                    if let Some(&next_utid) = tid_to_utid.get(&next_pid) {
                        data.sched_slices.push(SchedSliceRecord {
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
                    ensure_thread_exists(
                        pid,
                        Some(waking.comm()),
                        &mut tid_to_utid,
                        &mut pid_to_upid,
                        &mut data,
                        &mut next_utid,
                        &mut next_upid,
                    );

                    if let Some(&utid) = tid_to_utid.get(&pid) {
                        data.thread_states.push(ThreadStateRecord {
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
                    if let Some(&track_id) = track_uuid_to_id.get(&track_uuid) {
                        data.counters.push(CounterRecord {
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
                        let track_id = track_uuid_to_id.get(&track_uuid).copied().unwrap_or(0);
                        data.slices.push(SliceRecord {
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

    data
}

fn extract_compact_sched(
    compact: &CompactSched,
    cpu: i32,
    data: &mut ExtractedData,
    tid_to_utid: &mut HashMap<i32, i64>,
    pid_to_upid: &mut HashMap<i32, i64>,
    next_utid: &mut i64,
    next_upid: &mut i64,
) {
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

        ensure_thread_exists(
            next_pid,
            comm,
            tid_to_utid,
            pid_to_upid,
            data,
            next_utid,
            next_upid,
        );

        if let Some(&utid) = tid_to_utid.get(&next_pid) {
            data.sched_slices.push(SchedSliceRecord {
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

        ensure_thread_exists(
            pid,
            comm,
            tid_to_utid,
            pid_to_upid,
            data,
            next_utid,
            next_upid,
        );

        if let Some(&utid) = tid_to_utid.get(&pid) {
            data.thread_states.push(ThreadStateRecord {
                ts: waking_ts,
                dur: 0,
                utid,
                state: "R".to_string(),
                cpu: Some(target_cpu),
            });
        }
    }
}

fn ensure_thread_exists(
    tid: i32,
    name: Option<&str>,
    tid_to_utid: &mut HashMap<i32, i64>,
    pid_to_upid: &mut HashMap<i32, i64>,
    data: &mut ExtractedData,
    next_utid: &mut i64,
    next_upid: &mut i64,
) {
    if let std::collections::hash_map::Entry::Vacant(e) = tid_to_utid.entry(tid) {
        let utid = *next_utid;
        *next_utid += 1;
        e.insert(utid);

        // Assume tid == pid when process info unavailable
        let upid = if let Some(&existing) = pid_to_upid.get(&tid) {
            existing
        } else {
            let upid = *next_upid;
            *next_upid += 1;
            pid_to_upid.insert(tid, upid);
            data.processes.push(ProcessRecord {
                upid,
                pid: tid,
                name: name.map(|s| s.to_string()),
                parent_upid: None,
            });
            upid
        };

        data.threads.push(ThreadRecord {
            utid,
            tid,
            name: name.map(|s| s.to_string()),
            upid: Some(upid),
        });
    } else if let Some(name_str) = name {
        if let Some(&utid) = tid_to_utid.get(&tid) {
            if let Some(thread) = data.threads.iter_mut().find(|t| t.utid == utid) {
                if thread.name.is_none() {
                    thread.name = Some(name_str.to_string());
                }
            }
        }
    }
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

    // Bound parallelism to control memory: each trace ~17GB, 2 workers = ~34GB peak
    let num_workers = 2.min(traces.len());
    let num_traces = traces.len();
    let (tx, rx) = mpsc::sync_channel::<(usize, Result<ProcessedTrace>)>(1);
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
    let parsed_trace = read_trace(&trace.source_path)?;
    let mut data = extract_trace_data_raw(&parsed_trace);
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
