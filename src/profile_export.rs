//! systing profile export (`.systing`) generation.
//!
//! Writes the line-oriented profile interchange format documented in
//! docs/PROFILE_EXPORT_FORMAT.md: a JSON header line followed by one JSON
//! array per record (process, thread, interned frame, interned stack,
//! aggregated sample tally). The export carries the sampling-profile view of
//! a trace only — everything else stays in the DuckDB database.
//!
//! Two producers share the writer:
//! - [`duckdb_to_profile_export`] reads an existing trace database
//!   (`systing-util convert trace.duckdb -o profile.systing`)
//! - [`parquet_to_profile_export`] reads the parquet files a recording just
//!   produced (`systing --output profile.systing`)

use anyhow::{bail, Context, Result};
use duckdb::Connection;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

/// Format version written in the header. Bump only for breaking changes; see
/// the Versioning section of docs/PROFILE_EXPORT_FORMAT.md.
pub const PROFILE_EXPORT_VERSION: u32 = 1;

/// Returns whether `path` names a profile export output (`.systing`, or the
/// gzipped `.systing.gz`).
pub fn is_profile_export_output(path: &Path) -> bool {
    path.file_name().and_then(|f| f.to_str()).is_some_and(|f| {
        let f = f.to_ascii_lowercase();
        f.ends_with(".systing") || f.ends_with(".systing.gz")
    })
}

/// Recording-level metadata for the header line.
#[derive(Debug, Default, Clone)]
pub struct ExportMeta {
    pub trace_id: String,
    /// The producing database's schema version (the current `SCHEMA_VERSION`
    /// when exporting from a fresh recording's parquet files). Carried in
    /// the header so consumers can reason about semantics that changed
    /// across schema versions.
    pub source_schema_version: Option<u32>,
    /// The systing version that recorded the selected trace
    /// (`_traces.systing_version`; this binary's version when exporting from
    /// a fresh recording). Informational — the exporter already normalizes
    /// legacy stack order (see [`stack_order_normalized`]) — but lets
    /// consumers reason about other per-version semantics.
    pub source_systing_version: Option<String>,
    pub sample_event: Option<String>,
    pub sample_period: Option<i64>,
    pub start_ts: i64,
    pub end_ts: i64,
    pub sysname: Option<String>,
    pub release: Option<String>,
    pub machine: Option<String>,
    pub hypervisor: Option<String>,
    pub sys_vendor: Option<String>,
    pub product_name: Option<String>,
    pub cpufreq_driver: Option<String>,
}

/// Streaming writer for the export format. Callers must respect the
/// define-before-use ordering the format guarantees (processes, then
/// threads, then frames, then stacks, then samples); the two producers in
/// this module do so by construction.
struct ExportWriter {
    out: ExportSink,
}

impl ExportWriter {
    fn new(mut out: ExportSink, meta: &ExportMeta) -> Result<Self> {
        let mut system = serde_json::Map::new();
        let mut sys_field = |key: &str, val: &Option<String>| {
            if let Some(v) = val {
                system.insert(key.to_string(), json!(v));
            }
        };
        sys_field("sysname", &meta.sysname);
        sys_field("release", &meta.release);
        sys_field("machine", &meta.machine);
        sys_field("hypervisor", &meta.hypervisor);
        sys_field("sys_vendor", &meta.sys_vendor);
        sys_field("product_name", &meta.product_name);
        sys_field("cpufreq_driver", &meta.cpufreq_driver);

        let header = json!({
            "systing_profile_export": PROFILE_EXPORT_VERSION,
            "producer": format!("systing {}", env!("CARGO_PKG_VERSION")),
            "trace_id": meta.trace_id,
            "source_schema_version": meta.source_schema_version,
            "source_systing_version": meta.source_systing_version,
            "sample_event": meta.sample_event,
            "sample_period": meta.sample_period,
            "event_types": {
                "0": "uninterruptible_sleep",
                "1": "cpu",
                "2": "interruptible_sleep",
            },
            "stack_order": "leaf_first",
            "start_ts": meta.start_ts,
            "end_ts": meta.end_ts,
            "system": system,
        });
        writeln!(out, "{header}")?;
        Ok(Self { out })
    }

    fn process(&mut self, upid: i64, pid: i32, name: Option<&str>) -> Result<()> {
        writeln!(self.out, "{}", json!(["p", upid, pid, name]))?;
        Ok(())
    }

    fn thread(&mut self, utid: i64, tid: i32, name: Option<&str>, upid: Option<i64>) -> Result<()> {
        writeln!(self.out, "{}", json!(["t", utid, tid, name, upid]))?;
        Ok(())
    }

    fn frame(&mut self, id: i64, name: &str) -> Result<()> {
        writeln!(self.out, "{}", json!(["f", id, name]))?;
        Ok(())
    }

    /// Writes a stack whose frame ids are already in leaf-first order.
    fn stack(&mut self, id: i64, frame_ids_leaf_first: &[i64]) -> Result<()> {
        writeln!(self.out, "{}", json!(["s", id, frame_ids_leaf_first]))?;
        Ok(())
    }

    fn sample(&mut self, utid: i64, stack_id: i64, event_type: i8, count: i64) -> Result<()> {
        writeln!(
            self.out,
            "{}",
            json!(["x", utid, stack_id, event_type, count])
        )?;
        Ok(())
    }

    fn finish(self) -> Result<()> {
        self.out.finish()
    }
}

/// The export's output sink: a plain buffered file or a gzip stream.
///
/// Exists so [`ExportSink::finish`] can end the gzip stream explicitly and
/// surface its errors — dropping a `GzEncoder` writes the gzip trailer too,
/// but swallows any I/O error, silently truncating the output.
enum ExportSink {
    Plain(BufWriter<File>),
    Gz(Box<GzEncoder<BufWriter<File>>>),
}

impl Write for ExportSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            ExportSink::Plain(w) => w.write(buf),
            ExportSink::Gz(w) => w.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            ExportSink::Plain(w) => w.flush(),
            ExportSink::Gz(w) => w.flush(),
        }
    }
}

impl ExportSink {
    fn finish(self) -> Result<()> {
        match self {
            ExportSink::Plain(mut w) => w.flush()?,
            ExportSink::Gz(w) => {
                w.finish()?.flush()?;
            }
        }
        Ok(())
    }
}

/// The systing release that normalized stack storage to uniform root-first
/// order across all segments. Stacks recorded by earlier versions store
/// their python segment (the leading run of the array, when present)
/// leaf-first while native segments are root-first.
const STACK_ORDER_NORMALIZED_SINCE: (u64, u64, u64) = (1, 11, 0);

/// Whether a recording systing version stores stacks in uniform root-first
/// order. Unparseable, empty, or missing versions (traces predating version
/// stamping) are treated as pre-normalization: their native-only stacks are
/// unaffected by the legacy fixup, and their python blends need it.
fn stack_order_normalized(systing_version: Option<&str>) -> bool {
    let Some(version) = systing_version else {
        return false;
    };
    let mut parts = version.split('.');
    let mut part = || {
        parts
            .next()
            .and_then(|p| p.split_whitespace().next())
            .and_then(|p| p.parse::<u64>().ok())
    };
    let (Some(major), Some(minor)) = (part(), part()) else {
        return false;
    };
    let patch = part().unwrap_or(0);
    (major, minor, patch) >= STACK_ORDER_NORMALIZED_SINCE
}

/// systing's pystacks frame rendering (`name (python) [file.py:line]`), the
/// grammar that distinguishes python frames within a stored stack.
fn is_python_frame(name: &str) -> bool {
    name.ends_with(']') && name.contains(" (python) [")
}

/// Whether a python frame is a root-side marker: the module toplevel,
/// CPython's interpreter entry trampoline, or the threading bootstrap.
/// These only ever appear at the root side of a python stack (the
/// trampoline sits beyond `<module>`), which makes a stored python run's
/// direction decidable from where its markers fall.
fn is_python_root_marker(name: &str) -> bool {
    if !is_python_frame(name) {
        return false;
    }
    let Some((func, location)) = name.split_once(" (python) [") else {
        return false;
    };
    func == "<module>"
        || func == "<interpreter trampoline>"
        || ((func == "_bootstrap" || func == "_bootstrap_inner")
            && location.starts_with("threading.py"))
}

/// Decides from structural evidence whether this trace's python segments are
/// stored leaf-first (pre-normalization order) rather than root-first.
///
/// Version stamps can lie about this — `_traces.systing_version` names the
/// binary that CONVERTED the trace, which for a reconverted parquet
/// directory is not the binary that recorded it — so structure is the
/// primary signal: root-side markers falling in the far half of a stack's
/// leading python run mean leaf-first storage, in the near half root-first.
/// Stacks without a decidable run (no python, truncated runs with no
/// marker, midpoint markers) abstain. Returns `None` when no stack votes,
/// for the caller to fall back on version keying.
fn python_runs_stored_leaf_first(
    stacks: &[(i64, Vec<i64>)],
    is_python: &HashSet<i64>,
    is_root_marker: &HashSet<i64>,
) -> Option<bool> {
    let mut leaf_first = 0usize;
    let mut root_first = 0usize;
    for (_, frame_ids) in stacks {
        let run = frame_ids
            .iter()
            .take_while(|id| is_python.contains(id))
            .count();
        if run < 2 {
            continue;
        }
        for (index, id) in frame_ids[..run].iter().enumerate() {
            if !is_root_marker.contains(id) {
                continue;
            }
            // Two markers can be adjacent (`<module>` under the
            // trampoline), so each votes by which half of the run it
            // falls in rather than by exact endpoint.
            match (2 * index + 1).cmp(&run) {
                std::cmp::Ordering::Greater => leaf_first += 1,
                std::cmp::Ordering::Less => root_first += 1,
                std::cmp::Ordering::Equal => {}
            }
        }
    }
    match leaf_first.cmp(&root_first) {
        std::cmp::Ordering::Greater => Some(true),
        std::cmp::Ordering::Less => Some(false),
        std::cmp::Ordering::Equal => None,
    }
}

/// Restores uniform root-first order for stacks whose python segments were
/// stored leaf-first: the python segment is always the leading run of the
/// array, so reversing that run in place makes the whole array root-first.
/// The export's uniform leaf-first reversal is then correct for every
/// segment. A no-op for native-only stacks (no leading python run).
fn normalize_legacy_python_run(frame_ids: &mut [i64], is_python: impl Fn(i64) -> bool) {
    let run = frame_ids.iter().take_while(|id| is_python(**id)).count();
    frame_ids[..run].reverse();
}

/// Opens the output file, transparently gzipping when the name ends in `.gz`.
fn open_output(path: &Path) -> Result<ExportSink> {
    let file = File::create(path)
        .with_context(|| format!("creating profile export '{}'", path.display()))?;
    let buffered = BufWriter::new(file);
    let is_gz = path
        .file_name()
        .and_then(|f| f.to_str())
        .is_some_and(|f| f.to_ascii_lowercase().ends_with(".gz"));
    if is_gz {
        Ok(ExportSink::Gz(Box::new(GzEncoder::new(
            buffered,
            Compression::default(),
        ))))
    } else {
        Ok(ExportSink::Plain(buffered))
    }
}

/// Export the stack-sampling profile of one trace in a DuckDB database.
///
/// `trace_id` must be given when the database contains more than one trace.
/// Only rows reachable from `stack_sample` are exported: the stack table is
/// shared with the memory recorder (memory_map/memory_fault/memory_alloc
/// reference it too), and those stacks are not part of the sampling profile.
pub fn duckdb_to_profile_export(
    db_path: &Path,
    output: &Path,
    trace_id: Option<&str>,
) -> Result<()> {
    let mut config = duckdb::Config::default();
    config = config.access_mode(duckdb::AccessMode::ReadOnly)?;
    let conn = Connection::open_with_flags(db_path, config)
        .with_context(|| format!("opening DuckDB database '{}'", db_path.display()))?;

    // Resolve the trace to export.
    let trace_ids: Vec<String> = conn
        .prepare("SELECT DISTINCT trace_id FROM stack_sample ORDER BY trace_id")?
        .query_map([], |row| row.get(0))?
        .collect::<duckdb::Result<_>>()?;
    let trace_id = match (trace_id, trace_ids.as_slice()) {
        (Some(id), _) => {
            if !trace_ids.iter().any(|t| t == id) {
                bail!(
                    "trace '{}' has no stack samples in '{}' (available: {})",
                    id,
                    db_path.display(),
                    if trace_ids.is_empty() {
                        "none".to_string()
                    } else {
                        trace_ids.join(", ")
                    }
                );
            }
            id.to_string()
        }
        (None, [only]) => only.clone(),
        (None, []) => bail!(
            "no stack samples in '{}'; nothing to export (was the recording \
             run with --no-stack-traces?)",
            db_path.display()
        ),
        (None, many) => bail!(
            "database contains {} traces with stack samples; pick one with \
             --trace-id (available: {})",
            many.len(),
            many.join(", ")
        ),
    };

    // Header metadata. sysinfo may be absent in old traces; sample_event /
    // sample_period may be NULL in traces recorded by systing < 1.9. The
    // recording version comes from the trace's own row: a database can mix
    // traces imported from different systing versions, so the db-level
    // schema version can't answer per-trace questions like stack order.
    let source_systing_version: Option<String> = conn
        .query_row(
            "SELECT systing_version FROM _traces WHERE trace_id = ?",
            [&trace_id],
            |row| row.get(0),
        )
        .ok();
    let mut meta = ExportMeta {
        trace_id: trace_id.clone(),
        source_schema_version: conn
            .query_row("SELECT version FROM _schema_version", [], |row| row.get(0))
            .ok(),
        source_systing_version: source_systing_version.clone(),
        ..Default::default()
    };
    let mut stmt = conn.prepare(
        "SELECT sysname, release, machine, hypervisor, sys_vendor, product_name, \
                cpufreq_driver, sample_event, sample_period \
         FROM sysinfo WHERE trace_id = ? LIMIT 1",
    )?;
    let mut rows = stmt.query([&trace_id])?;
    if let Some(row) = rows.next()? {
        meta.sysname = row.get(0)?;
        meta.release = row.get(1)?;
        meta.machine = row.get(2)?;
        meta.hypervisor = row.get(3)?;
        meta.sys_vendor = row.get(4)?;
        meta.product_name = row.get(5)?;
        meta.cpufreq_driver = row.get(6)?;
        meta.sample_event = row.get(7)?;
        meta.sample_period = row.get(8)?;
    }
    let (start_ts, end_ts): (i64, i64) = conn.query_row(
        "SELECT min(ts), max(ts) FROM stack_sample WHERE trace_id = ?",
        [&trace_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    meta.start_ts = start_ts;
    meta.end_ts = end_ts;

    let mut writer = ExportWriter::new(open_output(output)?, &meta)?;

    // Processes owning sampled threads.
    let mut stmt = conn.prepare(
        "SELECT DISTINCT p.upid, p.pid, p.name \
         FROM process p \
         JOIN thread t ON t.trace_id = p.trace_id AND t.upid = p.upid \
         WHERE p.trace_id = ? \
           AND t.utid IN (SELECT DISTINCT utid FROM stack_sample WHERE trace_id = ?) \
         ORDER BY p.upid",
    )?;
    let mut rows = stmt.query([&trace_id, &trace_id])?;
    while let Some(row) = rows.next()? {
        let upid: i64 = row.get(0)?;
        let pid: i32 = row.get(1)?;
        let name: Option<String> = row.get(2)?;
        writer.process(upid, pid, name.as_deref())?;
    }

    // Sampled threads.
    let mut stmt = conn.prepare(
        "SELECT t.utid, t.tid, t.name, t.upid \
         FROM thread t \
         WHERE t.trace_id = ? \
           AND t.utid IN (SELECT DISTINCT utid FROM stack_sample WHERE trace_id = ?) \
         ORDER BY t.utid",
    )?;
    let mut rows = stmt.query([&trace_id, &trace_id])?;
    while let Some(row) = rows.next()? {
        let utid: i64 = row.get(0)?;
        let tid: i32 = row.get(1)?;
        let name: Option<String> = row.get(2)?;
        let upid: Option<i64> = row.get(3)?;
        writer.thread(utid, tid, name.as_deref(), upid)?;
    }

    // Frames referenced by sampled stacks. Python frame ids and python root
    // markers are noted along the way: the stack-order handling below needs
    // to recognize a stack's leading python run and decide its direction.
    let mut python_frames: HashSet<i64> = HashSet::new();
    let mut python_root_markers: HashSet<i64> = HashSet::new();
    let mut stmt = conn.prepare(
        "SELECT DISTINCT f.id, f.name \
         FROM stack s, unnest(s.frame_ids) AS u(fid) \
         JOIN frame f ON f.trace_id = s.trace_id AND f.id = u.fid \
         WHERE s.trace_id = ? \
           AND s.id IN (SELECT DISTINCT stack_id FROM stack_sample WHERE trace_id = ?) \
         ORDER BY f.id",
    )?;
    let mut rows = stmt.query([&trace_id, &trace_id])?;
    while let Some(row) = rows.next()? {
        let id: i64 = row.get(0)?;
        let name: String = row.get(1)?;
        if is_python_frame(&name) {
            python_frames.insert(id);
            if is_python_root_marker(&name) {
                python_root_markers.insert(id);
            }
        }
        writer.frame(id, &name)?;
    }

    // Sampled stacks. frame_ids are stored root-first (outermost frame at
    // index 0 — verified against real dumps; the stack recorder reverses the
    // BPF capture before interning), except that recordings from systing
    // versions predating the stack-order normalization stored the python
    // segment leaf-first. Structural evidence decides which order this
    // trace's python runs are in (the version stamp is only a fallback — it
    // names the converting binary, which for a reconverted parquet
    // directory is not the recorder), and legacy runs are un-inverted so
    // the uniform reversal to the format's leaf-first order is correct for
    // every segment. duckdb-rs has no FromSql for Vec<i64>; flatten to a
    // delimited string like analyze/flamegraph.rs does.
    let mut stacks: Vec<(i64, Vec<i64>)> = Vec::new();
    let mut stmt = conn.prepare(
        "SELECT s.id, array_to_string([x::VARCHAR for x in s.frame_ids], chr(31)) \
         FROM stack s \
         WHERE s.trace_id = ? \
           AND s.id IN (SELECT DISTINCT stack_id FROM stack_sample WHERE trace_id = ?) \
         ORDER BY s.id",
    )?;
    let mut rows = stmt.query([&trace_id, &trace_id])?;
    while let Some(row) = rows.next()? {
        let id: i64 = row.get(0)?;
        let flat: String = row.get(1)?;
        let frame_ids: Vec<i64> = flat
            .split('\u{1f}')
            .filter(|s| !s.is_empty())
            .map(|s| s.parse::<i64>().context("parsing frame id"))
            .collect::<Result<_>>()?;
        stacks.push((id, frame_ids));
    }
    let legacy_python_order =
        python_runs_stored_leaf_first(&stacks, &python_frames, &python_root_markers)
            .unwrap_or_else(|| !stack_order_normalized(source_systing_version.as_deref()));
    for (id, frame_ids) in &mut stacks {
        if legacy_python_order {
            normalize_legacy_python_run(frame_ids, |id| python_frames.contains(&id));
        }
        frame_ids.reverse();
        writer.stack(*id, frame_ids)?;
    }

    // Aggregated sample tallies.
    let mut stmt = conn.prepare(
        "SELECT utid, stack_id, stack_event_type, count(*) \
         FROM stack_sample \
         WHERE trace_id = ? \
         GROUP BY utid, stack_id, stack_event_type \
         ORDER BY utid, stack_id, stack_event_type",
    )?;
    let mut rows = stmt.query([&trace_id])?;
    while let Some(row) = rows.next()? {
        let utid: i64 = row.get(0)?;
        let stack_id: i64 = row.get(1)?;
        let event_type: i8 = row.get(2)?;
        let count: i64 = row.get(3)?;
        writer.sample(utid, stack_id, event_type, count)?;
    }

    writer.finish()
}

/// Export the stack-sampling profile from the parquet files of a recording.
///
/// The parquet `stack` table carries frame name strings inline (interning is
/// a DuckDB-import concern), so this reader interns them itself to produce
/// the format's `f`/`s` records.
pub fn parquet_to_profile_export(input_dir: &Path, output: &Path, trace_id: &str) -> Result<()> {
    use arrow::array::{Array, Int32Array, Int64Array, Int8Array, ListArray, StringArray};
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

    // Streams a table's record batches through `visit` one at a time (an
    // absent file visits nothing), so no table is ever fully materialized.
    let for_each_batch = |name: &str,
                          visit: &mut dyn FnMut(arrow::record_batch::RecordBatch) -> Result<()>|
     -> Result<()> {
        let path = input_dir.join(name);
        if !path.exists() {
            return Ok(());
        }
        let file = File::open(&path).with_context(|| format!("opening '{}'", path.display()))?;
        let reader = ParquetRecordBatchReaderBuilder::try_new(file)?.build()?;
        for batch in reader {
            visit(batch.with_context(|| format!("reading '{}'", path.display()))?)?;
        }
        Ok(())
    };

    // Aggregate samples and note which threads/stacks they reference.
    let mut tallies: HashMap<(i64, i64, i8), i64> = HashMap::new();
    let mut used_utids: HashSet<i64> = HashSet::new();
    let mut used_stacks: HashSet<i64> = HashSet::new();
    let mut start_ts = i64::MAX;
    let mut end_ts = i64::MIN;
    for_each_batch("stack_sample.parquet", &mut |batch| {
        let ts = batch
            .column_by_name("ts")
            .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
            .context("stack_sample.parquet: missing ts column")?;
        let utids = batch
            .column_by_name("utid")
            .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
            .context("stack_sample.parquet: missing utid column")?;
        let stack_ids = batch
            .column_by_name("stack_id")
            .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
            .context("stack_sample.parquet: missing stack_id column")?;
        let event_types = batch
            .column_by_name("stack_event_type")
            .and_then(|c| c.as_any().downcast_ref::<Int8Array>())
            .context("stack_sample.parquet: missing stack_event_type column")?;
        for i in 0..batch.num_rows() {
            let (utid, stack_id, event_type) =
                (utids.value(i), stack_ids.value(i), event_types.value(i));
            *tallies.entry((utid, stack_id, event_type)).or_insert(0) += 1;
            used_utids.insert(utid);
            used_stacks.insert(stack_id);
            start_ts = start_ts.min(ts.value(i));
            end_ts = end_ts.max(ts.value(i));
        }
        Ok(())
    })?;
    if tallies.is_empty() {
        bail!(
            "no stack samples in '{}'; nothing to export (was the recording \
             run with --no-stack-traces?)",
            input_dir.display()
        );
    }

    // Header metadata from sysinfo.parquet (single row when present).
    let mut meta = ExportMeta {
        trace_id: trace_id.to_string(),
        // A fresh recording's parquet files carry no schema-version table or
        // trace metadata; the schema and recorder they follow are this
        // binary's.
        source_schema_version: Some(crate::duckdb::SCHEMA_VERSION),
        source_systing_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        start_ts,
        end_ts,
        ..Default::default()
    };
    for_each_batch("sysinfo.parquet", &mut |batch| {
        let get_str = |name: &str, row: usize| -> Option<String> {
            batch
                .column_by_name(name)
                .and_then(|c| c.as_any().downcast_ref::<StringArray>())
                .filter(|a| !a.is_null(row))
                .map(|a| a.value(row).to_string())
        };
        if batch.num_rows() > 0 {
            meta.sysname = get_str("sysname", 0);
            meta.release = get_str("release", 0);
            meta.machine = get_str("machine", 0);
            meta.hypervisor = get_str("hypervisor", 0);
            meta.sys_vendor = get_str("sys_vendor", 0);
            meta.product_name = get_str("product_name", 0);
            meta.cpufreq_driver = get_str("cpufreq_driver", 0);
            meta.sample_event = get_str("sample_event", 0);
            meta.sample_period = batch
                .column_by_name("sample_period")
                .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                .filter(|a| !a.is_null(0))
                .map(|a| a.value(0));
        }
        Ok(())
    })?;

    let mut writer = ExportWriter::new(open_output(output)?, &meta)?;

    // Threads and their processes, filtered to sampled utids.
    let mut used_upids: HashSet<i64> = HashSet::new();
    let mut threads: Vec<(i64, i32, Option<String>, Option<i64>)> = Vec::new();
    for_each_batch("thread.parquet", &mut |batch| {
        let utids = batch
            .column_by_name("utid")
            .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
            .context("thread.parquet: missing utid column")?;
        let tids = batch
            .column_by_name("tid")
            .and_then(|c| c.as_any().downcast_ref::<Int32Array>())
            .context("thread.parquet: missing tid column")?;
        let names = batch
            .column_by_name("name")
            .and_then(|c| c.as_any().downcast_ref::<StringArray>());
        let upids = batch
            .column_by_name("upid")
            .and_then(|c| c.as_any().downcast_ref::<Int64Array>());
        for i in 0..batch.num_rows() {
            let utid = utids.value(i);
            if !used_utids.contains(&utid) {
                continue;
            }
            let name = names
                .filter(|a| !a.is_null(i))
                .map(|a| a.value(i).to_string());
            let upid = upids.filter(|a| !a.is_null(i)).map(|a| a.value(i));
            if let Some(upid) = upid {
                used_upids.insert(upid);
            }
            threads.push((utid, tids.value(i), name, upid));
        }
        Ok(())
    })?;
    for_each_batch("process.parquet", &mut |batch| {
        let upids = batch
            .column_by_name("upid")
            .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
            .context("process.parquet: missing upid column")?;
        let pids = batch
            .column_by_name("pid")
            .and_then(|c| c.as_any().downcast_ref::<Int32Array>())
            .context("process.parquet: missing pid column")?;
        let names = batch
            .column_by_name("name")
            .and_then(|c| c.as_any().downcast_ref::<StringArray>());
        for i in 0..batch.num_rows() {
            let upid = upids.value(i);
            if !used_upids.contains(&upid) {
                continue;
            }
            let name = names
                .filter(|a| !a.is_null(i))
                .map(|a| a.value(i).to_string());
            writer.process(upid, pids.value(i), name.as_deref())?;
        }
        Ok(())
    })?;
    for (utid, tid, name, upid) in &threads {
        writer.thread(*utid, *tid, name.as_deref(), *upid)?;
    }

    // Stacks: intern the inline frame name strings, buffering each stack in
    // storage order (root-first — outermost at index 0, matching what the
    // stack recorder emits — except pre-normalization python segments; see
    // the duckdb producer). A parquet directory carries no recording-version
    // marker at all, so structural evidence is the primary signal here too,
    // with this binary's version (correct for the normal
    // record-then-export-own-files flow) as the fallback.
    let mut frame_ids: HashMap<String, i64> = HashMap::new();
    let mut python_frames: HashSet<i64> = HashSet::new();
    let mut python_root_markers: HashSet<i64> = HashSet::new();
    let mut stacks: Vec<(i64, Vec<i64>)> = Vec::new();
    for_each_batch("stack.parquet", &mut |batch| {
        let ids = batch
            .column_by_name("id")
            .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
            .context("stack.parquet: missing id column")?;
        let frame_names = batch
            .column_by_name("frame_names")
            .and_then(|c| c.as_any().downcast_ref::<ListArray>())
            .context("stack.parquet: missing frame_names column")?;
        for i in 0..batch.num_rows() {
            let id = ids.value(i);
            if !used_stacks.contains(&id) {
                continue;
            }
            let inner = frame_names.value(i);
            let strings = inner
                .as_any()
                .downcast_ref::<StringArray>()
                .context("stack.parquet: frame_names is not a string list")?;
            let mut ids_storage_order: Vec<i64> = Vec::with_capacity(strings.len());
            for j in 0..strings.len() {
                if strings.is_null(j) {
                    continue;
                }
                let name = strings.value(j);
                let next_id = frame_ids.len() as i64;
                let fid = *frame_ids.entry(name.to_string()).or_insert(next_id);
                if is_python_frame(name) {
                    python_frames.insert(fid);
                    if is_python_root_marker(name) {
                        python_root_markers.insert(fid);
                    }
                }
                ids_storage_order.push(fid);
            }
            stacks.push((id, ids_storage_order));
        }
        Ok(())
    })?;
    let legacy_python_order =
        python_runs_stored_leaf_first(&stacks, &python_frames, &python_root_markers)
            .unwrap_or_else(|| !stack_order_normalized(Some(env!("CARGO_PKG_VERSION"))));
    for (_, ids_storage_order) in &mut stacks {
        if legacy_python_order {
            normalize_legacy_python_run(ids_storage_order, |id| python_frames.contains(&id));
        }
        ids_storage_order.reverse();
    }

    let mut frames_sorted: Vec<(i64, String)> = frame_ids
        .iter()
        .map(|(name, id)| (*id, name.clone()))
        .collect();
    frames_sorted.sort_unstable_by_key(|(id, _)| *id);
    for (id, name) in &frames_sorted {
        writer.frame(*id, name)?;
    }
    for (id, ids_leaf_first) in &stacks {
        writer.stack(*id, ids_leaf_first)?;
    }

    let mut tallies_sorted: Vec<((i64, i64, i8), i64)> = tallies.into_iter().collect();
    tallies_sorted.sort_unstable_by_key(|(key, _)| *key);
    for ((utid, stack_id, event_type), count) in &tallies_sorted {
        writer.sample(*utid, *stack_id, *event_type, *count)?;
    }

    writer.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::duckdb::create_schema;

    fn read_lines(path: &Path) -> Vec<String> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn test_db(dir: &Path) -> Connection {
        let conn = Connection::open(dir.join("test.duckdb")).unwrap();
        create_schema(&conn).unwrap();
        conn
    }

    #[test]
    fn test_is_profile_export_output() {
        assert!(is_profile_export_output(Path::new("a/profile.systing")));
        assert!(is_profile_export_output(Path::new("P.SYSTING")));
        assert!(is_profile_export_output(Path::new("profile.systing.gz")));
        assert!(!is_profile_export_output(Path::new("trace.duckdb")));
        assert!(!is_profile_export_output(Path::new("systing")));
        assert!(!is_profile_export_output(Path::new("trace.pb")));
    }

    #[test]
    fn test_duckdb_export_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let conn = test_db(dir.path());

        // One process with one thread; a second thread that only appears in
        // memory events (must not be exported).
        conn.execute_batch(
            "INSERT INTO _schema_version VALUES (1, 11);
             INSERT INTO sysinfo VALUES ('t', 'Linux', '6.12.0', '#1', 'x86_64', \
                 NULL, NULL, NULL, NULL, 'cpu-clock', 1000000);
             INSERT INTO process VALUES ('t', 10, 100, 'workload', NULL, NULL, false, 0, NULL);
             INSERT INTO process VALUES ('t', 11, 200, 'bystander', NULL, NULL, false, 0, NULL);
             INSERT INTO thread VALUES ('t', 1, 101, 'worker', 10);
             INSERT INTO thread VALUES ('t', 2, 201, 'idle', 11);
             INSERT INTO frame VALUES ('t', 0, 'main (workload) <0x3>');
             INSERT INTO frame VALUES ('t', 1, 'middle (workload) <0x2>');
             INSERT INTO frame VALUES ('t', 2, 'leaf_fn (workload) <0x1>');
             INSERT INTO frame VALUES ('t', 3, 'alloc_only (workload) <0x9>');
             -- Storage order is root-first: main, middle, leaf_fn.
             INSERT INTO stack VALUES ('t', 7, [0, 1, 2], 3, 'main (workload) <0x3>');
             INSERT INTO stack VALUES ('t', 8, [3], 1, 'alloc_only (workload) <0x9>');
             INSERT INTO stack_sample VALUES ('t', 1000, 1, 0, 7, 1);
             INSERT INTO stack_sample VALUES ('t', 2000, 1, 0, 7, 1);
             INSERT INTO stack_sample VALUES ('t', 3000, 1, 0, 7, 2);
             -- Stack 8 is referenced only by the memory recorder.
             INSERT INTO memory_alloc VALUES ('t', 1, 1500, 2, 'malloc', 0, 64, NULL, 8);",
        )
        .unwrap();
        drop(conn);

        let out = dir.path().join("profile.systing");
        duckdb_to_profile_export(&dir.path().join("test.duckdb"), &out, None).unwrap();

        let lines = read_lines(&out);
        let header: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(header["systing_profile_export"], 1);
        assert_eq!(header["trace_id"], "t");
        assert_eq!(header["source_schema_version"], 11);
        assert_eq!(header["sample_event"], "cpu-clock");
        assert_eq!(header["sample_period"], 1000000);
        assert_eq!(header["stack_order"], "leaf_first");
        assert_eq!(header["start_ts"], 1000);
        assert_eq!(header["end_ts"], 3000);
        assert_eq!(header["system"]["sysname"], "Linux");

        let records: Vec<serde_json::Value> = lines[1..]
            .iter()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let of_tag = |tag: &str| -> Vec<&serde_json::Value> {
            records.iter().filter(|r| r[0] == tag).collect()
        };

        // Only the sampled process/thread appear.
        let procs = of_tag("p");
        assert_eq!(procs.len(), 1);
        assert_eq!(procs[0][1], 10);
        assert_eq!(procs[0][2], 100);
        assert_eq!(procs[0][3], "workload");
        let threads = of_tag("t");
        assert_eq!(threads.len(), 1);
        assert_eq!(threads[0][1], 1);

        // Only frames/stacks reachable from stack_sample appear, and the
        // stack's root-first storage order is reversed to leaf-first.
        let frames = of_tag("f");
        assert_eq!(frames.len(), 3);
        assert!(frames.iter().all(|f| f[2] != "alloc_only (workload) <0x9>"));
        let stacks = of_tag("s");
        assert_eq!(stacks.len(), 1);
        assert_eq!(stacks[0][1], 7);
        assert_eq!(stacks[0][2], json!([2, 1, 0]));

        // Tallies aggregate per (utid, stack_id, event_type): two cpu samples
        // (type 1) fold into one record, the interruptible sleep (type 2)
        // stays separate.
        let samples = of_tag("x");
        assert_eq!(samples.len(), 2);
        assert_eq!(samples[0], &json!(["x", 1, 7, 1, 2]));
        assert_eq!(samples[1], &json!(["x", 1, 7, 2, 1]));

        // Define-before-use ordering: frames before stacks before samples.
        let pos = |tag: &str| {
            lines
                .iter()
                .position(|l| l.contains(&format!("[\"{tag}\"")))
                .unwrap()
        };
        assert!(pos("f") < pos("s"));
        assert!(pos("s") < pos("x"));
    }

    #[test]
    fn test_duckdb_export_multi_trace_requires_id() {
        let dir = tempfile::tempdir().unwrap();
        let conn = test_db(dir.path());
        conn.execute_batch(
            "INSERT INTO frame VALUES ('a', 0, 'f0'), ('b', 0, 'f0');
             INSERT INTO stack VALUES ('a', 1, [0], 1, 'f0'), ('b', 1, [0], 1, 'f0');
             INSERT INTO thread VALUES ('a', 1, 1, NULL, NULL), ('b', 1, 1, NULL, NULL);
             INSERT INTO stack_sample VALUES ('a', 1, 1, 0, 1, 1), ('b', 1, 1, 0, 1, 1);",
        )
        .unwrap();
        drop(conn);

        let db = dir.path().join("test.duckdb");
        let out = dir.path().join("profile.systing");
        let err = duckdb_to_profile_export(&db, &out, None).unwrap_err();
        assert!(err.to_string().contains("--trace-id"), "{err}");

        duckdb_to_profile_export(&db, &out, Some("b")).unwrap();
        let header: serde_json::Value = serde_json::from_str(&read_lines(&out)[0]).unwrap();
        assert_eq!(header["trace_id"], "b");

        let err = duckdb_to_profile_export(&db, &out, Some("nope")).unwrap_err();
        assert!(err.to_string().contains("available"), "{err}");
    }

    #[test]
    fn test_duckdb_export_empty_bails() {
        let dir = tempfile::tempdir().unwrap();
        let conn = test_db(dir.path());
        drop(conn);
        let err = duckdb_to_profile_export(
            &dir.path().join("test.duckdb"),
            &dir.path().join("p.systing"),
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("no stack samples"), "{err}");
    }

    #[test]
    fn test_gzip_output() {
        let dir = tempfile::tempdir().unwrap();
        let conn = test_db(dir.path());
        conn.execute_batch(
            "INSERT INTO frame VALUES ('t', 0, 'f0');
             INSERT INTO stack VALUES ('t', 1, [0], 1, 'f0');
             INSERT INTO thread VALUES ('t', 1, 1, NULL, NULL);
             INSERT INTO stack_sample VALUES ('t', 1, 1, 0, 1, 1);",
        )
        .unwrap();
        drop(conn);

        let out = dir.path().join("profile.systing.gz");
        duckdb_to_profile_export(&dir.path().join("test.duckdb"), &out, None).unwrap();
        let bytes = std::fs::read(&out).unwrap();
        assert_eq!(&bytes[..2], &[0x1f, 0x8b], "expected gzip magic");

        use flate2::read::GzDecoder;
        use std::io::Read;
        let mut text = String::new();
        GzDecoder::new(&bytes[..])
            .read_to_string(&mut text)
            .unwrap();
        let header: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(header["systing_profile_export"], 1);
    }

    #[test]
    fn test_stack_order_normalized() {
        assert!(!stack_order_normalized(None));
        assert!(!stack_order_normalized(Some("")));
        assert!(!stack_order_normalized(Some("not a version")));
        assert!(!stack_order_normalized(Some("1.10.6")));
        assert!(!stack_order_normalized(Some("1.10")));
        assert!(!stack_order_normalized(Some("0.99.0")));
        assert!(stack_order_normalized(Some("1.11.0")));
        assert!(stack_order_normalized(Some("1.11")));
        assert!(stack_order_normalized(Some("1.11.1")));
        assert!(stack_order_normalized(Some("2.0.0")));
    }

    #[test]
    fn test_normalize_legacy_python_run() {
        let is_py = |id: i64| id >= 100;

        // Leading python run reverses in place; the native tail is untouched.
        let mut blended = vec![102, 101, 100, 0, 1, 2];
        normalize_legacy_python_run(&mut blended, is_py);
        assert_eq!(blended, vec![100, 101, 102, 0, 1, 2]);

        // Native-only and python-only stacks.
        let mut native = vec![0, 1, 2];
        normalize_legacy_python_run(&mut native, is_py);
        assert_eq!(native, vec![0, 1, 2]);
        let mut python = vec![102, 101, 100];
        normalize_legacy_python_run(&mut python, is_py);
        assert_eq!(python, vec![100, 101, 102]);

        // A python frame after the native run has begun is not part of the
        // leading segment (cannot occur in recorded data, but the fixup must
        // not scramble it).
        let mut interleaved = vec![0, 100, 1];
        normalize_legacy_python_run(&mut interleaved, is_py);
        assert_eq!(interleaved, vec![0, 100, 1]);
    }

    #[test]
    fn test_python_run_direction_vote() {
        let py: HashSet<i64> = [100, 101, 102].into();
        let markers: HashSet<i64> = [102].into();

        // Marker at the run's far end: stored leaf-first.
        let leaf_first = vec![(1, vec![100, 101, 102, 0, 1])];
        assert_eq!(
            python_runs_stored_leaf_first(&leaf_first, &py, &markers),
            Some(true)
        );

        // Marker at the run's start: stored root-first.
        let root_first = vec![(1, vec![102, 101, 100, 0, 1])];
        assert_eq!(
            python_runs_stored_leaf_first(&root_first, &py, &markers),
            Some(false)
        );

        // No markers anywhere (truncated runs), single-frame runs, and
        // native-only stacks all abstain.
        let indecisive = vec![
            (1, vec![100, 101, 0]),
            (2, vec![100, 0, 1]),
            (3, vec![0, 1, 2]),
        ];
        assert_eq!(
            python_runs_stored_leaf_first(&indecisive, &py, &markers),
            None
        );

        // Majority wins across stacks.
        let mixed = vec![
            (1, vec![100, 101, 102, 0]),
            (2, vec![101, 102, 0]),
            (3, vec![102, 101, 0]),
        ];
        assert_eq!(
            python_runs_stored_leaf_first(&mixed, &py, &markers),
            Some(true)
        );

        // The real pystacks shape: `<module>` sits one inside the run's far
        // end because the interpreter trampoline lies beyond it. Both are
        // markers in the far half, so the vote still lands leaf-first.
        let py5: HashSet<i64> = [100, 101, 102, 103, 104].into();
        let markers5: HashSet<i64> = [103, 104].into();
        let trampoline = vec![(1, vec![100, 101, 102, 103, 104, 0, 1])];
        assert_eq!(
            python_runs_stored_leaf_first(&trampoline, &py5, &markers5),
            Some(true)
        );
    }

    #[test]
    fn test_duckdb_export_grammar_overrides_lying_version() {
        // A reconverted parquet directory stamps the CONVERTING binary's
        // version onto data recorded by an older systing: the version says
        // normalized, the stacks are still leaf-first. The structural vote
        // (root marker at the python run's far end) must win over the
        // version stamp.
        let dir = tempfile::tempdir().unwrap();
        let conn = test_db(dir.path());
        conn.execute_batch(
            "INSERT INTO _traces (trace_id, source_path, systing_version) \
                 VALUES ('t', 'x', '1.11.0');
             INSERT INTO frame VALUES ('t', 0, 'py_leaf (python) [app.py:9]');
             INSERT INTO frame VALUES ('t', 1, '<module> (python) [app.py:1]');
             INSERT INTO frame VALUES ('t', 2, 'native_leaf (app) <0x1>');
             -- Leaf-first python storage despite the v1.11.0 stamp.
             INSERT INTO stack VALUES ('t', 7, [0, 1, 2], 3, 'py_leaf (python) [app.py:9]');
             INSERT INTO thread VALUES ('t', 1, 101, NULL, NULL);
             INSERT INTO stack_sample VALUES ('t', 1000, 1, 0, 7, 1);",
        )
        .unwrap();
        drop(conn);

        let out = dir.path().join("profile.systing");
        duckdb_to_profile_export(&dir.path().join("test.duckdb"), &out, None).unwrap();
        let lines = read_lines(&out);
        let stack = lines
            .iter()
            .find(|l| l.starts_with("[\"s\""))
            .expect("no stack record");
        let record: serde_json::Value = serde_json::from_str(stack).unwrap();
        // Un-inverted then reversed: native leaf, py leaf, <module>.
        assert_eq!(record[2], serde_json::json!([2, 0, 1]));
    }

    #[test]
    fn test_duckdb_export_grammar_confirms_normalized_despite_old_version() {
        // The mirror case: normalized (root-first) python storage carrying
        // an old version stamp must NOT be scrambled by the fixup.
        let dir = tempfile::tempdir().unwrap();
        let conn = test_db(dir.path());
        conn.execute_batch(
            "INSERT INTO _traces (trace_id, source_path, systing_version) \
                 VALUES ('t', 'x', '1.10.2');
             INSERT INTO frame VALUES ('t', 0, '<module> (python) [app.py:1]');
             INSERT INTO frame VALUES ('t', 1, 'py_leaf (python) [app.py:9]');
             INSERT INTO frame VALUES ('t', 2, 'native_leaf (app) <0x1>');
             INSERT INTO stack VALUES ('t', 7, [0, 1, 2], 3, 'native_leaf (app) <0x1>');
             INSERT INTO thread VALUES ('t', 1, 101, NULL, NULL);
             INSERT INTO stack_sample VALUES ('t', 1000, 1, 0, 7, 1);",
        )
        .unwrap();
        drop(conn);

        let out = dir.path().join("profile.systing");
        duckdb_to_profile_export(&dir.path().join("test.duckdb"), &out, None).unwrap();
        let lines = read_lines(&out);
        let stack = lines
            .iter()
            .find(|l| l.starts_with("[\"s\""))
            .expect("no stack record");
        let record: serde_json::Value = serde_json::from_str(stack).unwrap();
        // Plain uniform reverse: native leaf, py leaf, <module>.
        assert_eq!(record[2], serde_json::json!([2, 1, 0]));
    }

    #[test]
    fn test_duckdb_export_legacy_python_blend() {
        // A pre-normalization recording (systing_version < 1.11.0) stores
        // the python segment leaf-first while native segments are
        // root-first. This trace has no root markers, so the structural
        // vote abstains and the version fallback applies: the exporter must
        // un-invert the python run so the emitted stack is truly leaf-first
        // end to end.
        let dir = tempfile::tempdir().unwrap();
        let conn = test_db(dir.path());
        conn.execute_batch(
            "INSERT INTO _traces (trace_id, source_path, systing_version) \
                 VALUES ('t', 'x', '1.10.6');
             INSERT INTO frame VALUES ('t', 0, 'py_leaf (python) [app.py:9]');
             INSERT INTO frame VALUES ('t', 1, 'py_root (python) [app.py:1]');
             INSERT INTO frame VALUES ('t', 2, 'native_root (app) <0x2>');
             INSERT INTO frame VALUES ('t', 3, 'native_leaf (app) <0x1>');
             -- Storage: [py leaf, py root, native root, native leaf].
             INSERT INTO stack VALUES ('t', 7, [0, 1, 2, 3], 4, 'py_leaf (python) [app.py:9]');
             INSERT INTO thread VALUES ('t', 1, 101, NULL, NULL);
             INSERT INTO stack_sample VALUES ('t', 1000, 1, 0, 7, 1);",
        )
        .unwrap();
        drop(conn);

        let out = dir.path().join("profile.systing");
        duckdb_to_profile_export(&dir.path().join("test.duckdb"), &out, None).unwrap();
        let lines = read_lines(&out);
        let header: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(header["source_systing_version"], "1.10.6");

        // Expected leaf-first emit: native leaf, native root, py leaf, py
        // root — the python run was un-inverted before the uniform reverse.
        let stack = lines
            .iter()
            .find(|l| l.starts_with("[\"s\""))
            .expect("no stack record");
        let record: serde_json::Value = serde_json::from_str(stack).unwrap();
        assert_eq!(record[2], serde_json::json!([3, 2, 0, 1]));
    }

    #[test]
    fn test_duckdb_export_normalized_python_blend_untouched() {
        // A post-normalization recording stores everything root-first; with
        // no root markers the vote abstains, the version fallback says
        // normalized, and the exporter applies only the uniform reverse.
        let dir = tempfile::tempdir().unwrap();
        let conn = test_db(dir.path());
        conn.execute_batch(
            "INSERT INTO _traces (trace_id, source_path, systing_version) \
                 VALUES ('t', 'x', '1.11.0');
             INSERT INTO frame VALUES ('t', 0, 'py_root (python) [app.py:1]');
             INSERT INTO frame VALUES ('t', 1, 'py_leaf (python) [app.py:9]');
             INSERT INTO frame VALUES ('t', 2, 'native_root (app) <0x2>');
             INSERT INTO frame VALUES ('t', 3, 'native_leaf (app) <0x1>');
             -- Storage (uniform root-first): py root, py leaf, native root, native leaf.
             INSERT INTO stack VALUES ('t', 7, [0, 1, 2, 3], 4, 'native_leaf (app) <0x1>');
             INSERT INTO thread VALUES ('t', 1, 101, NULL, NULL);
             INSERT INTO stack_sample VALUES ('t', 1000, 1, 0, 7, 1);",
        )
        .unwrap();
        drop(conn);

        let out = dir.path().join("profile.systing");
        duckdb_to_profile_export(&dir.path().join("test.duckdb"), &out, None).unwrap();
        let lines = read_lines(&out);
        let stack = lines
            .iter()
            .find(|l| l.starts_with("[\"s\""))
            .expect("no stack record");
        let record: serde_json::Value = serde_json::from_str(stack).unwrap();
        assert_eq!(record[2], serde_json::json!([3, 2, 1, 0]));
    }
}
