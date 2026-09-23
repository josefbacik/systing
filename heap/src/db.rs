//! Writing snapshots into a systing DuckDB database.
//!
//! The database has systing's full schema ([`systing::duckdb::create_schema`]),
//! so it opens in `systing-analyze` and merges with other traces like any
//! capture. Stacks go into `frame` / `stack`, the tables every recorder
//! shares; the snapshots into `heap_snapshot` / `heap_sample`; each process
//! that wrote a dump gets a `process` row.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use duckdb::{params, Connection};
use systing::duckdb::{create_schema, SCHEMA_VERSION, SYSTING_VERSION};

use crate::symbolize::Symbolized;
use crate::Snapshot;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Written {
    pub snapshots: usize,
    pub samples: usize,
    pub stacks: usize,
    pub frames: usize,
}

/// Write `snapshots`, named by `symbolized`, as trace `trace_id` of a new
/// database at `out`.
pub fn write(
    out: &Path,
    trace_id: &str,
    source_path: &str,
    snapshots: &[Snapshot],
    symbolized: &Symbolized,
) -> Result<Written> {
    let mut conn = Connection::open(out).with_context(|| format!("creating {}", out.display()))?;
    let tx = conn.transaction()?;
    create_schema(&tx)?;
    tx.execute(
        "INSERT INTO _traces (trace_id, source_path, systing_version) VALUES (?, ?, ?)",
        params![trace_id, source_path, SYSTING_VERSION],
    )?;
    tx.execute(
        "INSERT OR REPLACE INTO _schema_version (id, version) VALUES (1, ?)",
        params![SCHEMA_VERSION],
    )?;

    // Dense ids: frames by name, stacks by their frame list, processes by pid.
    let mut frame_ids: HashMap<&str, i64> = HashMap::new();
    let mut stack_ids: HashMap<Vec<i64>, i64> = HashMap::new();
    let mut upids: HashMap<i32, i64> = HashMap::new();
    let mut written = Written::default();

    {
        let mut process = tx.appender("process")?;
        let mut snapshot_rows = tx.appender("heap_snapshot")?;
        let mut sample_rows = tx.appender("heap_sample")?;
        for (si, s) in snapshots.iter().enumerate() {
            let snapshot_id = si as i64 + 1;
            let upid = match s.pid {
                Some(pid) => Some(match upids.get(&pid) {
                    Some(&u) => u,
                    None => {
                        let u = upids.len() as i64 + 1;
                        upids.insert(pid, u);
                        // Only the columns a dump can fill; the rest take
                        // their defaults.
                        process.append_row(params![
                            trace_id,
                            u,
                            pid,
                            s.maps.exe_name(),
                            None::<i64>,
                            None::<String>,
                            false,
                            0u64,
                            None::<String>
                        ])?;
                        u
                    }
                }),
                None => None,
            };
            snapshot_rows.append_row(params![
                trace_id,
                snapshot_id,
                s.format.name(),
                s.source_path.to_string_lossy(),
                upid,
                s.seq.map(|v| v as i64),
                s.trigger,
                s.dumped_at_unix_ns,
                s.sample_period as i64,
                s.header_live_objects as i64,
                s.header_live_bytes as i64
            ])?;
            for (sample, names) in s.samples.iter().zip(&symbolized.frames[si]) {
                let ids: Vec<i64> = names
                    .iter()
                    .map(|n| {
                        let next = frame_ids.len() as i64 + 1;
                        *frame_ids.entry(n.as_str()).or_insert(next)
                    })
                    .collect();
                let next = stack_ids.len() as i64 + 1;
                let stack_id = *stack_ids.entry(ids).or_insert(next);
                sample_rows.append_row(params![
                    trace_id,
                    snapshot_id,
                    stack_id,
                    sample.live_objects as i64,
                    sample.live_bytes as i64,
                    sample.alloc_objects as i64,
                    sample.alloc_bytes as i64
                ])?;
                written.samples += 1;
            }
            written.snapshots += 1;
        }
        process.flush()?;
        snapshot_rows.flush()?;
        sample_rows.flush()?;
    }

    {
        let mut frames = tx.appender("frame")?;
        let mut frame_files = tx.appender("frame_file")?;
        for (name, id) in &frame_ids {
            frames.append_row(params![trace_id, id, name])?;
            if let Some(file) = symbolized.files.get(*name) {
                frame_files.append_row(params![trace_id, id, file])?;
            }
        }
        frames.flush()?;
        frame_files.flush()?;
    }

    // The appender takes no list values: stage (stack, position, frame) rows
    // and let DuckDB build the lists.
    tx.execute_batch(
        "CREATE TEMP TABLE heap_stack_frame (stack_id BIGINT, idx INTEGER, frame_id BIGINT)",
    )?;
    {
        let mut staged = tx.appender("heap_stack_frame")?;
        for (ids, stack_id) in &stack_ids {
            for (idx, fid) in ids.iter().enumerate() {
                staged.append_row(params![stack_id, idx as i32, fid])?;
            }
        }
        staged.flush()?;
    }
    tx.execute(
        "INSERT INTO stack (trace_id, id, frame_ids, depth, leaf_name)
         SELECT ?, s.stack_id, list(s.frame_id ORDER BY s.idx), count(*),
                arg_max(f.name, s.idx)
         FROM heap_stack_frame s
         JOIN frame f ON f.trace_id = ? AND f.id = s.frame_id
         GROUP BY s.stack_id",
        params![trace_id, trace_id],
    )?;
    tx.execute_batch("DROP TABLE heap_stack_frame")?;
    tx.commit()?;

    written.stacks = stack_ids.len();
    written.frames = frame_ids.len();
    Ok(written)
}
