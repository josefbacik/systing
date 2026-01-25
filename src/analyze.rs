//! Analysis logic for querying and analyzing systing trace databases.
//!
//! This module provides the core analysis functionality used by both the CLI
//! and MCP server interfaces. All methods are synchronous and work directly
//! with DuckDB connections.

use anyhow::{bail, Result};
use duckdb::Connection;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Maximum number of rows returned by a query.
pub const MAX_QUERY_ROWS: usize = 10_000;

/// Stack type filter for flamegraph analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackTypeFilter {
    Cpu,
    InterruptibleSleep,
    UninterruptibleSleep,
    AllSleep,
    All,
}

impl StackTypeFilter {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::InterruptibleSleep => "interruptible-sleep",
            Self::UninterruptibleSleep => "uninterruptible-sleep",
            Self::AllSleep => "all-sleep",
            Self::All => "all",
        }
    }
}

impl FromStr for StackTypeFilter {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "cpu" => Ok(Self::Cpu),
            "interruptible-sleep" => Ok(Self::InterruptibleSleep),
            "uninterruptible-sleep" => Ok(Self::UninterruptibleSleep),
            "all-sleep" => Ok(Self::AllSleep),
            "all" => Ok(Self::All),
            _ => bail!(
                "Invalid stack type: {s}. Must be one of: cpu, interruptible-sleep, \
                 uninterruptible-sleep, all-sleep, all"
            ),
        }
    }
}

/// Parameters for flamegraph analysis.
#[derive(Debug, Clone)]
pub struct FlamegraphParams {
    pub stack_type: StackTypeFilter,
    pub pid: Option<u32>,
    pub tid: Option<u32>,
    pub start_time: Option<f64>,
    pub end_time: Option<f64>,
    pub trace_id: Option<String>,
    pub min_count: u64,
    pub top_n: usize,
}

impl Default for FlamegraphParams {
    fn default() -> Self {
        Self {
            stack_type: StackTypeFilter::Cpu,
            pid: None,
            tid: None,
            start_time: None,
            end_time: None,
            trace_id: None,
            min_count: 1,
            top_n: 500,
        }
    }
}

/// Result of a SQL query.
#[derive(Debug, Serialize)]
pub struct QueryResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<serde_json::Value>>,
    pub row_count: usize,
    #[serde(skip_serializing_if = "is_false")]
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_row_count: Option<usize>,
}

fn is_false(b: &bool) -> bool {
    !b
}

/// Table information.
#[derive(Debug, Serialize)]
pub struct TableInfo {
    pub name: String,
    pub row_count: u64,
}

/// Column information.
#[derive(Debug, Serialize)]
pub struct ColumnInfo {
    pub name: String,
    #[serde(rename = "type")]
    pub data_type: String,
}

/// A single stack entry in flamegraph results.
#[derive(Debug, Serialize)]
pub struct StackEntry {
    pub frames: Vec<String>,
    pub count: u64,
}

/// Metadata about a flamegraph result.
#[derive(Debug, Serialize)]
pub struct FlamegraphMetadata {
    pub total_samples: u64,
    pub unique_stacks: u64,
    pub time_range_seconds: (f64, f64),
    pub stack_type: String,
}

/// Result of a flamegraph analysis.
#[derive(Debug, Serialize)]
pub struct FlamegraphResult {
    pub stacks: Vec<StackEntry>,
    pub metadata: FlamegraphMetadata,
    pub folded: String,
}

/// Process information.
#[derive(Debug, Serialize)]
pub struct ProcessInfo {
    pub pid: i64,
    pub name: String,
    pub thread_count: u64,
}

/// Time range information.
#[derive(Debug, Serialize)]
pub struct TimeRange {
    pub start_ns: i64,
    pub end_ns: i64,
    pub duration_seconds: f64,
}

/// Trace metadata.
#[derive(Debug, Serialize)]
pub struct TraceInfo {
    pub database_path: String,
    pub traces: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_range: Option<TimeRange>,
    pub tables: Vec<TableInfo>,
    pub processes: Vec<ProcessInfo>,
}

/// Wrapper around a DuckDB connection for trace analysis.
pub struct AnalyzeDb {
    conn: Connection,
    path: PathBuf,
}

impl AnalyzeDb {
    /// Open a trace database.
    pub fn open(path: &Path, read_only: bool) -> Result<Self> {
        if !path.exists() {
            bail!("Database not found: {}", path.display());
        }

        let conn = if read_only {
            let config = duckdb::Config::default().access_mode(duckdb::AccessMode::ReadOnly)?;
            Connection::open_with_flags(path, config)?
        } else {
            Connection::open(path)?
        };

        Ok(Self {
            conn,
            path: path.to_path_buf(),
        })
    }

    /// Execute a SQL query and return typed results.
    pub fn query(&self, sql: &str) -> Result<QueryResult> {
        let mut stmt = self.conn.prepare(sql)?;
        let mut rows = stmt.query([])?;

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

        let mut rows_data: Vec<Vec<serde_json::Value>> = Vec::new();
        let mut total_count: usize = 0;
        let mut truncated = false;

        while let Some(row) = rows.next()? {
            total_count += 1;
            if rows_data.len() >= MAX_QUERY_ROWS {
                truncated = true;
                continue; // Keep counting for total
            }

            let mut row_values = Vec::new();
            for i in 0..column_count {
                let value: duckdb::types::Value = row.get(i)?;
                let json_value = duckdb_value_to_json(value);
                row_values.push(json_value);
            }
            rows_data.push(row_values);
        }

        let row_count = rows_data.len();
        Ok(QueryResult {
            columns: column_names,
            rows: rows_data,
            row_count,
            truncated,
            total_row_count: if truncated { Some(total_count) } else { None },
        })
    }

    /// Execute a query and return rows as string vectors (for table/csv display).
    pub fn query_strings(&self, sql: &str) -> Result<(Vec<String>, Vec<Vec<String>>)> {
        let mut stmt = self.conn.prepare(sql)?;
        let mut rows = stmt.query([])?;

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
                let str_value = duckdb_value_to_string(value);
                row_values.push(str_value);
            }
            rows_data.push(row_values);
        }

        Ok((column_names, rows_data))
    }

    /// List all tables with row counts.
    pub fn list_tables(&self) -> Result<Vec<TableInfo>> {
        let mut stmt = self.conn.prepare(
            "SELECT table_name FROM information_schema.tables \
             WHERE table_schema = 'main' ORDER BY table_name",
        )?;
        let mut rows = stmt.query([])?;

        let mut tables = Vec::new();
        while let Some(row) = rows.next()? {
            let name: String = row.get(0)?;
            let count = self.table_row_count(&name).unwrap_or(0);
            tables.push(TableInfo {
                name,
                row_count: count,
            });
        }

        Ok(tables)
    }

    /// Describe a table's schema.
    pub fn describe_table(&self, table_name: &str) -> Result<Vec<ColumnInfo>> {
        if !self.table_exists(table_name)? {
            bail!("Table not found: {table_name}");
        }

        let mut stmt = self.conn.prepare(
            "SELECT column_name, data_type FROM information_schema.columns \
             WHERE table_schema = 'main' AND table_name = ? \
             ORDER BY ordinal_position",
        )?;
        let mut rows = stmt.query([table_name])?;

        let mut columns = Vec::new();
        while let Some(row) = rows.next()? {
            columns.push(ColumnInfo {
                name: row.get(0)?,
                data_type: row.get(1)?,
            });
        }

        Ok(columns)
    }

    /// Run flamegraph analysis and return structured results.
    pub fn flamegraph(&self, params: &FlamegraphParams) -> Result<FlamegraphResult> {
        if !self.table_exists("stack_sample")? || !self.table_exists("stack")? {
            bail!(
                "Database missing required tables (stack_sample, stack). \
                 Is this a systing trace database?"
            );
        }

        if matches!(
            params.stack_type,
            StackTypeFilter::InterruptibleSleep | StackTypeFilter::UninterruptibleSleep
        ) && !self.table_has_rows("sched_slice")?
        {
            bail!(
                "No sched_slice data available, required for {} filtering",
                params.stack_type.as_str()
            );
        }

        let (min_ts, max_ts, total_samples) = self.get_trace_time_range(&params.trace_id)?;

        let abs_start = params.start_time.map(|t| min_ts + (t * 1e9) as i64);
        let abs_end = params.end_time.map(|t| min_ts + (t * 1e9) as i64);

        let sql = build_flamegraph_query(
            &params.stack_type,
            &params.pid,
            &params.tid,
            &abs_start,
            &abs_end,
            &params.trace_id,
            params.min_count,
        );

        let mut stmt = self.conn.prepare(&sql)?;
        let mut rows = stmt.query([])?;

        let mut stacks = Vec::new();
        let mut folded_lines = Vec::new();
        let mut unique_stacks: u64 = 0;

        while let Some(row) = rows.next()? {
            let frames_str: String = row.get(0)?;
            let count: i64 = row.get(1)?;
            let count = count as u64;

            let folded = format_folded_stack(&frames_str);
            if folded.is_empty() {
                continue;
            }

            unique_stacks += 1;

            if stacks.len() < params.top_n {
                let frames: Vec<String> = folded.split(';').map(|s| s.to_string()).collect();
                folded_lines.push(format!("{folded} {count}"));
                stacks.push(StackEntry { frames, count });
            }
        }

        let duration_secs = (max_ts - min_ts) as f64 / 1e9;

        Ok(FlamegraphResult {
            stacks,
            metadata: FlamegraphMetadata {
                total_samples,
                unique_stacks,
                time_range_seconds: (0.0, duration_secs),
                stack_type: params.stack_type.as_str().to_string(),
            },
            folded: folded_lines.join("\n"),
        })
    }

    /// Get trace metadata.
    pub fn trace_info(&self) -> Result<TraceInfo> {
        let all_tables = self.list_tables()?;
        let tables: Vec<TableInfo> = all_tables.into_iter().filter(|t| t.row_count > 0).collect();

        let traces = self.get_trace_ids()?;

        let time_range =
            if self.table_exists("stack_sample")? && self.table_has_rows("stack_sample")? {
                match self.get_trace_time_range(&None) {
                    Ok((min_ts, max_ts, _)) => Some(TimeRange {
                        start_ns: min_ts,
                        end_ns: max_ts,
                        duration_seconds: (max_ts - min_ts) as f64 / 1e9,
                    }),
                    Err(_) => None,
                }
            } else {
                None
            };

        let processes = self.get_processes()?;

        Ok(TraceInfo {
            database_path: self.path.display().to_string(),
            traces,
            time_range,
            tables,
            processes,
        })
    }

    /// Get the database path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Get the underlying connection (for interactive mode).
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    // -- Internal helpers --

    fn table_exists(&self, table_name: &str) -> Result<bool> {
        table_exists(&self.conn, table_name)
    }

    fn table_has_rows(&self, table_name: &str) -> Result<bool> {
        table_has_rows(&self.conn, table_name)
    }

    fn table_row_count(&self, table_name: &str) -> Result<u64> {
        let sql = format!("SELECT COUNT(*) FROM \"{table_name}\"");
        let mut stmt = self.conn.prepare(&sql)?;
        let mut rows = stmt.query([])?;
        if let Some(row) = rows.next()? {
            let count: i64 = row.get(0)?;
            Ok(count as u64)
        } else {
            Ok(0)
        }
    }

    fn get_trace_time_range(&self, trace_id: &Option<String>) -> Result<(i64, i64, u64)> {
        get_trace_time_range(&self.conn, trace_id)
    }

    fn get_trace_ids(&self) -> Result<Vec<String>> {
        for table in &["stack_sample", "thread", "process", "sched_slice"] {
            if !self.table_exists(table)? {
                continue;
            }
            let sql = format!("SELECT DISTINCT trace_id FROM \"{table}\" ORDER BY trace_id");
            match self.conn.prepare(&sql) {
                Ok(mut stmt) => {
                    let mut rows = stmt.query([])?;
                    let mut traces = Vec::new();
                    while let Some(row) = rows.next()? {
                        let id: String = row.get(0)?;
                        traces.push(id);
                    }
                    if !traces.is_empty() {
                        return Ok(traces);
                    }
                }
                Err(_) => continue,
            }
        }
        Ok(Vec::new())
    }

    fn get_processes(&self) -> Result<Vec<ProcessInfo>> {
        if !self.table_exists("process")? {
            return Ok(Vec::new());
        }

        let has_thread = self.table_exists("thread")?;

        let sql = if has_thread {
            "SELECT p.pid, COALESCE(p.name, ''), COUNT(DISTINCT t.tid) as thread_count \
             FROM process p \
             LEFT JOIN thread t ON p.upid = t.upid AND p.trace_id = t.trace_id \
             GROUP BY p.pid, p.name \
             ORDER BY p.pid"
        } else {
            "SELECT pid, COALESCE(name, ''), 0 FROM process ORDER BY pid"
        };

        let mut stmt = self.conn.prepare(sql)?;
        let mut rows = stmt.query([])?;
        let mut processes = Vec::new();

        while let Some(row) = rows.next()? {
            processes.push(ProcessInfo {
                pid: row.get(0)?,
                name: row.get(1)?,
                thread_count: {
                    let c: i64 = row.get(2)?;
                    c as u64
                },
            });
        }

        Ok(processes)
    }
}

/// Convert a DuckDB value to a properly typed JSON value.
fn duckdb_value_to_json(value: duckdb::types::Value) -> serde_json::Value {
    match value {
        duckdb::types::Value::Null => serde_json::Value::Null,
        duckdb::types::Value::Boolean(b) => serde_json::Value::Bool(b),
        duckdb::types::Value::TinyInt(n) => serde_json::json!(n),
        duckdb::types::Value::SmallInt(n) => serde_json::json!(n),
        duckdb::types::Value::Int(n) => serde_json::json!(n),
        duckdb::types::Value::BigInt(n) => serde_json::json!(n),
        duckdb::types::Value::HugeInt(n) => {
            if let Ok(n64) = i64::try_from(n) {
                serde_json::json!(n64)
            } else {
                serde_json::Value::String(n.to_string())
            }
        }
        duckdb::types::Value::UTinyInt(n) => serde_json::json!(n),
        duckdb::types::Value::USmallInt(n) => serde_json::json!(n),
        duckdb::types::Value::UInt(n) => serde_json::json!(n),
        duckdb::types::Value::UBigInt(n) => serde_json::json!(n),
        duckdb::types::Value::Float(n) => {
            if n.is_finite() {
                serde_json::json!(n)
            } else {
                serde_json::Value::String(n.to_string())
            }
        }
        duckdb::types::Value::Double(n) => {
            if n.is_finite() {
                serde_json::json!(n)
            } else {
                serde_json::Value::String(n.to_string())
            }
        }
        duckdb::types::Value::Text(s) => serde_json::Value::String(s),
        other => serde_json::Value::String(format!("{other:?}")),
    }
}

/// Convert a DuckDB value to a display string.
fn duckdb_value_to_string(value: duckdb::types::Value) -> String {
    match value {
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
        other => format!("{other:?}"),
    }
}

// -- Free functions --

pub fn table_exists(conn: &Connection, table_name: &str) -> Result<bool> {
    let mut stmt = conn.prepare(
        "SELECT COUNT(*) FROM information_schema.tables \
         WHERE table_schema = 'main' AND table_name = ?",
    )?;
    let mut rows = stmt.query([table_name])?;
    if let Some(row) = rows.next()? {
        let count: i64 = row.get(0)?;
        Ok(count > 0)
    } else {
        Ok(false)
    }
}

pub fn table_has_rows(conn: &Connection, table_name: &str) -> Result<bool> {
    if !table_exists(conn, table_name)? {
        return Ok(false);
    }
    let sql = format!("SELECT 1 FROM \"{table_name}\" LIMIT 1");
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query([])?;
    Ok(rows.next()?.is_some())
}

pub fn get_trace_time_range(
    conn: &Connection,
    trace_id: &Option<String>,
) -> Result<(i64, i64, u64)> {
    let sql = if let Some(tid) = trace_id {
        let escaped = tid.replace('\'', "''");
        format!("SELECT MIN(ts), MAX(ts), COUNT(*) FROM stack_sample WHERE trace_id = '{escaped}'")
    } else {
        "SELECT MIN(ts), MAX(ts), COUNT(*) FROM stack_sample".to_string()
    };

    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query([])?;
    if let Some(row) = rows.next()? {
        let count: i64 = row.get(2)?;
        if count == 0 {
            bail!("No stack samples found in database");
        }
        let min_ts: i64 = row.get(0)?;
        let max_ts: i64 = row.get(1)?;
        Ok((min_ts, max_ts, count as u64))
    } else {
        bail!("No data in stack_sample table");
    }
}

pub fn build_flamegraph_query(
    stack_type: &StackTypeFilter,
    pid: &Option<u32>,
    tid: &Option<u32>,
    abs_start: &Option<i64>,
    abs_end: &Option<i64>,
    trace_id: &Option<String>,
    min_count: u64,
) -> String {
    let mut joins = String::new();
    let mut conditions = Vec::new();

    match stack_type {
        StackTypeFilter::Cpu => {
            conditions.push("ss.stack_event_type = 1".to_string());
        }
        StackTypeFilter::InterruptibleSleep => {
            conditions.push("ss.stack_event_type = 0".to_string());
            conditions.push("sl.end_state = 1".to_string());
            joins.push_str(
                " JOIN sched_slice sl ON ss.utid = sl.utid AND ss.trace_id = sl.trace_id \
                 AND ABS(ss.ts - (sl.ts + sl.dur)) <= 10000000",
            );
        }
        StackTypeFilter::UninterruptibleSleep => {
            conditions.push("ss.stack_event_type = 0".to_string());
            conditions.push("sl.end_state = 2".to_string());
            joins.push_str(
                " JOIN sched_slice sl ON ss.utid = sl.utid AND ss.trace_id = sl.trace_id \
                 AND ABS(ss.ts - (sl.ts + sl.dur)) <= 10000000",
            );
        }
        StackTypeFilter::AllSleep => {
            conditions.push("ss.stack_event_type = 0".to_string());
        }
        StackTypeFilter::All => {}
    }

    if pid.is_some() || tid.is_some() {
        joins.push_str(" JOIN thread t ON ss.utid = t.utid AND ss.trace_id = t.trace_id");
    }
    if pid.is_some() {
        joins.push_str(" JOIN process p ON t.upid = p.upid AND t.trace_id = p.trace_id");
    }

    if let Some(pid_val) = pid {
        conditions.push(format!("p.pid = {pid_val}"));
    }
    if let Some(tid_val) = tid {
        conditions.push(format!("t.tid = {tid_val}"));
    }

    if let Some(start) = abs_start {
        conditions.push(format!("ss.ts >= {start}"));
    }
    if let Some(end) = abs_end {
        conditions.push(format!("ss.ts <= {end}"));
    }

    if let Some(tid) = trace_id {
        let escaped = tid.replace('\'', "''");
        conditions.push(format!("ss.trace_id = '{escaped}'"));
    }

    conditions.push("s.frame_names IS NOT NULL".to_string());
    conditions.push("len(s.frame_names) > 0".to_string());

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", conditions.join(" AND "))
    };

    let having_clause = if min_count > 1 {
        format!(" HAVING COUNT(*) >= {min_count}")
    } else {
        String::new()
    };

    format!(
        "SELECT array_to_string(s.frame_names, chr(31)) as frames, \
         COUNT(*) as count \
         FROM stack_sample ss \
         JOIN stack s ON ss.stack_id = s.id AND ss.trace_id = s.trace_id\
         {joins}{where_clause} \
         GROUP BY s.frame_names{having_clause} \
         ORDER BY count DESC"
    )
}

/// Format a DuckDB frame_names array (as chr(31)-separated string) into folded stack format.
///
/// Frame names are stored leaf-to-root in the database, so they are reversed
/// to root-to-leaf order for flamegraph convention (root;child;...;leaf).
pub fn format_folded_stack(frames_str: &str) -> String {
    if frames_str.is_empty() {
        return String::new();
    }

    let frames: Vec<&str> = frames_str.split('\x1F').collect();

    // Reverse from leaf-to-root (storage order) to root-to-leaf (flamegraph convention)
    let formatted: Vec<String> = frames.iter().rev().map(|f| format_frame(f)).collect();

    formatted.join(";")
}

/// Simplify a frame name for folded output.
///
/// Input format: `function_name (module_name [file:line]) <0xaddr>`
/// Output format: `function_name [module_name]`
///
/// Unsymbolized frames (bare hex addresses like `0x5dbfa1`) become `0x5dbfa1 [unknown]`.
pub fn format_frame(frame: &str) -> String {
    let frame = frame.trim();
    if frame.is_empty() {
        return "[unknown]".to_string();
    }

    // Try to parse: "function_name (module_name [file:line]) <0xaddr>"
    // or: "function_name (module_name) <0xaddr>"
    if let Some(paren_pos) = frame.find(" (") {
        let func_name = &frame[..paren_pos];
        let rest = &frame[paren_pos + 2..];

        // Extract module name (up to ' [' for source location or ')' for end)
        let module_end = rest
            .find(" [")
            .or_else(|| rest.find(')'))
            .unwrap_or(rest.len());
        let module_name = &rest[..module_end];

        if module_name.is_empty() {
            func_name.to_string()
        } else {
            format!("{func_name} [{module_name}]")
        }
    } else if frame.starts_with("0x") {
        // Bare hex address (unsymbolized)
        format!("{frame} [unknown]")
    } else {
        // Unknown format, return as-is
        frame.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_frame_symbolized() {
        assert_eq!(
            format_frame("tcp_sendmsg (vmlinux [net/ipv4/tcp.c:1234]) <0xffffffff8ec7559e>"),
            "tcp_sendmsg [vmlinux]"
        );
    }

    #[test]
    fn test_format_frame_with_module_only() {
        assert_eq!(format_frame("main (myapp) <0x401234>"), "main [myapp]");
    }

    #[test]
    fn test_format_frame_kernel_unknown() {
        assert_eq!(
            format_frame("unknown ([kernel]) <0xffffffff8e000000>"),
            "unknown [[kernel]]"
        );
    }

    #[test]
    fn test_format_frame_bare_hex() {
        assert_eq!(format_frame("0x5dbfa1"), "0x5dbfa1 [unknown]");
    }

    #[test]
    fn test_format_frame_empty() {
        assert_eq!(format_frame(""), "[unknown]");
    }

    #[test]
    fn test_format_folded_stack_reversal() {
        // frame_names stored leaf-to-root: "leaf\x1Fmid\x1Froot"
        // Should output root-to-leaf: "root;mid;leaf"
        let input = "leaf (app) <0x1>\x1Fmid (app) <0x2>\x1Froot (app) <0x3>";
        let result = format_folded_stack(input);
        assert_eq!(result, "root [app];mid [app];leaf [app]");
    }

    #[test]
    fn test_format_folded_stack_empty() {
        assert_eq!(format_folded_stack(""), "");
    }

    #[test]
    fn test_format_folded_stack_single_frame() {
        let input = "main (myapp) <0x401234>";
        assert_eq!(format_folded_stack(input), "main [myapp]");
    }

    #[test]
    fn test_build_flamegraph_query_cpu() {
        let sql =
            build_flamegraph_query(&StackTypeFilter::Cpu, &None, &None, &None, &None, &None, 1);
        assert!(sql.contains("stack_event_type = 1"));
        assert!(!sql.contains("sched_slice"));
    }

    #[test]
    fn test_build_flamegraph_query_interruptible_sleep() {
        let sql = build_flamegraph_query(
            &StackTypeFilter::InterruptibleSleep,
            &None,
            &None,
            &None,
            &None,
            &None,
            1,
        );
        assert!(sql.contains("stack_event_type = 0"));
        assert!(sql.contains("sched_slice"));
        assert!(sql.contains("end_state = 1"));
    }

    #[test]
    fn test_build_flamegraph_query_with_pid() {
        let sql = build_flamegraph_query(
            &StackTypeFilter::Cpu,
            &Some(1234),
            &None,
            &None,
            &None,
            &None,
            1,
        );
        assert!(sql.contains("JOIN thread t"));
        assert!(sql.contains("JOIN process p"));
        assert!(sql.contains("p.pid = 1234"));
    }

    #[test]
    fn test_build_flamegraph_query_with_min_count() {
        let sql =
            build_flamegraph_query(&StackTypeFilter::All, &None, &None, &None, &None, &None, 10);
        assert!(sql.contains("HAVING COUNT(*) >= 10"));
    }

    #[test]
    fn test_build_flamegraph_query_no_having_for_min_count_1() {
        let sql =
            build_flamegraph_query(&StackTypeFilter::All, &None, &None, &None, &None, &None, 1);
        assert!(!sql.contains("HAVING"));
    }

    #[test]
    fn test_duckdb_value_to_json_types() {
        assert_eq!(
            duckdb_value_to_json(duckdb::types::Value::Null),
            serde_json::Value::Null
        );
        assert_eq!(
            duckdb_value_to_json(duckdb::types::Value::Boolean(true)),
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            duckdb_value_to_json(duckdb::types::Value::Int(42)),
            serde_json::json!(42)
        );
        assert_eq!(
            duckdb_value_to_json(duckdb::types::Value::BigInt(-100)),
            serde_json::json!(-100)
        );
        assert_eq!(
            duckdb_value_to_json(duckdb::types::Value::Double(1.23)),
            serde_json::json!(1.23)
        );
        assert_eq!(
            duckdb_value_to_json(duckdb::types::Value::Text("hello".to_string())),
            serde_json::json!("hello")
        );
    }

    #[test]
    fn test_duckdb_value_to_json_nan() {
        let val = duckdb_value_to_json(duckdb::types::Value::Double(f64::NAN));
        assert!(val.is_string());
    }

    #[test]
    fn test_duckdb_value_to_json_huge_int() {
        // Fits in i64
        assert_eq!(
            duckdb_value_to_json(duckdb::types::Value::HugeInt(42)),
            serde_json::json!(42)
        );
        // Too large for i64
        let big = i128::MAX;
        let val = duckdb_value_to_json(duckdb::types::Value::HugeInt(big));
        assert!(val.is_string());
        assert_eq!(val.as_str().unwrap(), big.to_string());
    }

    #[test]
    fn test_stack_type_filter_roundtrip() {
        for st in &[
            StackTypeFilter::Cpu,
            StackTypeFilter::InterruptibleSleep,
            StackTypeFilter::UninterruptibleSleep,
            StackTypeFilter::AllSleep,
            StackTypeFilter::All,
        ] {
            let s = st.as_str();
            let parsed: StackTypeFilter = s.parse().unwrap();
            assert_eq!(*st, parsed);
        }
    }

    #[test]
    fn test_stack_type_filter_invalid() {
        let result: Result<StackTypeFilter> = "invalid".parse();
        assert!(result.is_err());
    }
}
