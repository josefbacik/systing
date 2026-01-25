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

/// Parameters for sched stats analysis.
#[derive(Debug, Clone)]
pub struct SchedStatsParams {
    pub pid: Option<u32>,
    pub tid: Option<u32>,
    pub trace_id: Option<String>,
    pub top_n: usize,
}

impl Default for SchedStatsParams {
    fn default() -> Self {
        Self {
            pid: None,
            tid: None,
            trace_id: None,
            top_n: 20,
        }
    }
}

/// Result of sched stats analysis.
#[derive(Debug, Serialize)]
pub struct SchedStatsResult {
    pub summary: SchedSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processes: Option<Vec<ProcessSchedStats>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threads: Option<Vec<ThreadSchedStats>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_detail: Option<ThreadDetailStats>,
}

/// Summary-level scheduling statistics.
///
/// Note: `d_sleep_seconds` is an approximation. It measures the gap between
/// consecutive sched_slices when the prior slice ended with an uninterruptible
/// state (end_state & 2 != 0, covering both TASK_UNINTERRUPTIBLE and compound
/// states like TASK_UNINTERRUPTIBLE | TASK_NOLOAD). This gap includes both the
/// actual uninterruptible sleep time and any subsequent scheduler runqueue
/// latency before the thread was next scheduled.
#[derive(Debug, Serialize)]
pub struct SchedSummary {
    pub trace_duration_seconds: f64,
    pub total_events: u64,
    pub total_cpu_time_seconds: f64,
    pub d_sleep_seconds: f64,
    pub cpus_observed: u32,
    pub process_count: u32,
    pub thread_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
}

/// Per-process scheduling statistics.
#[derive(Debug, Serialize)]
pub struct ProcessSchedStats {
    pub pid: i64,
    pub name: String,
    pub thread_count: u32,
    pub cpu_time_seconds: f64,
    pub d_sleep_seconds: f64,
    pub event_count: u64,
    pub avg_slice_us: f64,
    pub preempt_pct: f64,
}

/// Per-thread scheduling statistics.
#[derive(Debug, Serialize)]
pub struct ThreadSchedStats {
    pub tid: i64,
    pub name: String,
    pub cpu_time_seconds: f64,
    pub d_sleep_seconds: f64,
    pub event_count: u64,
    pub avg_slice_us: f64,
    pub min_slice_us: f64,
    pub max_slice_us: f64,
    pub preempt_pct: f64,
}

/// Detailed stats for a single thread.
#[derive(Debug, Serialize)]
pub struct ThreadDetailStats {
    pub tid: i64,
    pub pid: i64,
    pub thread_name: String,
    pub process_name: String,
    pub cpu_time_seconds: f64,
    pub d_sleep_seconds: f64,
    pub event_count: u64,
    pub avg_slice_us: f64,
    pub min_slice_us: f64,
    pub max_slice_us: f64,
    pub cpu_migrations: u64,
    pub end_states: Vec<EndStateCount>,
}

/// Count and percentage for a particular end state.
#[derive(Debug, Serialize)]
pub struct EndStateCount {
    pub state: String,
    pub count: u64,
    pub percent: f64,
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

    /// Run sched stats analysis.
    pub fn sched_stats(&self, params: &SchedStatsParams) -> Result<SchedStatsResult> {
        // Validate required tables
        if !self.table_exists("sched_slice")? {
            bail!("Database missing sched_slice table. Is this a systing trace database?");
        }
        if !self.table_has_rows("sched_slice")? {
            bail!("No scheduling events found in database.");
        }
        if !self.table_exists("thread")? || !self.table_exists("process")? {
            bail!("Database missing thread/process tables required for sched stats.");
        }

        if let Some(tid) = params.tid {
            self.sched_stats_per_thread(tid, &params.trace_id)
        } else if let Some(pid) = params.pid {
            self.sched_stats_per_process(pid, &params.trace_id, params.top_n)
        } else {
            self.sched_stats_whole_trace(&params.trace_id, params.top_n)
        }
    }

    fn sched_stats_whole_trace(
        &self,
        trace_id: &Option<String>,
        top_n: usize,
    ) -> Result<SchedStatsResult> {
        // Summary aggregates
        let summary_sql = build_sched_summary_query(trace_id);
        let mut stmt = self.conn.prepare(&summary_sql)?;
        let mut rows = stmt.query([])?;
        let row = rows
            .next()?
            .ok_or_else(|| anyhow::anyhow!("No summary data"))?;
        let total_events: i64 = row.get(0)?;
        let total_cpu_time_s: f64 = row.get(1)?;
        let cpus: i64 = row.get(2)?;
        let thread_count: i64 = row.get(3)?;
        let trace_dur_s: f64 = row.get(4)?;

        // Process count
        let pcount_sql = build_process_count_query(trace_id);
        let mut stmt = self.conn.prepare(&pcount_sql)?;
        let mut rows = stmt.query([])?;
        let process_count: i64 = rows.next()?.map(|r| r.get(0).unwrap_or(0)).unwrap_or(0);

        // Total D-sleep time
        let dsleep_sql = build_total_d_sleep_query(trace_id);
        let mut stmt = self.conn.prepare(&dsleep_sql)?;
        let mut rows = stmt.query([])?;
        let d_sleep_s: f64 = rows.next()?.map(|r| r.get(0).unwrap_or(0.0)).unwrap_or(0.0);

        let summary = SchedSummary {
            trace_duration_seconds: trace_dur_s,
            total_events: u64::try_from(total_events).unwrap_or(0),
            total_cpu_time_seconds: total_cpu_time_s,
            d_sleep_seconds: d_sleep_s,
            cpus_observed: u32::try_from(cpus).unwrap_or(0),
            process_count: u32::try_from(process_count).unwrap_or(0),
            thread_count: u32::try_from(thread_count).unwrap_or(0),
            process_name: None,
        };

        // Per-process ranking
        let ranking_sql = build_process_ranking_query(trace_id, top_n);
        let mut stmt = self.conn.prepare(&ranking_sql)?;
        let mut rows = stmt.query([])?;
        let mut processes = Vec::new();
        while let Some(row) = rows.next()? {
            processes.push(ProcessSchedStats {
                pid: row.get(0)?,
                name: row.get(1)?,
                thread_count: u32::try_from(row.get::<_, i64>(2)?).unwrap_or(0),
                cpu_time_seconds: row.get(3)?,
                d_sleep_seconds: row.get(4)?,
                event_count: u64::try_from(row.get::<_, i64>(5)?).unwrap_or(0),
                avg_slice_us: row.get(6)?,
                preempt_pct: row.get(7)?,
            });
        }

        Ok(SchedStatsResult {
            summary,
            processes: Some(processes),
            threads: None,
            thread_detail: None,
        })
    }

    fn sched_stats_per_process(
        &self,
        pid: u32,
        trace_id: &Option<String>,
        top_n: usize,
    ) -> Result<SchedStatsResult> {
        // Process aggregate
        let agg_sql = build_process_aggregate_query(pid, trace_id);
        let mut stmt = self.conn.prepare(&agg_sql)?;
        let mut rows = stmt.query([])?;

        let summary = if let Some(row) = rows.next()? {
            let cpu_time_s: f64 = row.get(0)?;
            let d_sleep_s: f64 = row.get(1)?;
            let events: i64 = row.get(2)?;
            let tcount: i64 = row.get(3)?;
            let process_name: String = row.get(4)?;
            SchedSummary {
                trace_duration_seconds: 0.0, // not applicable for per-process
                total_events: u64::try_from(events).unwrap_or(0),
                total_cpu_time_seconds: cpu_time_s,
                d_sleep_seconds: d_sleep_s,
                cpus_observed: 0,
                process_count: 1,
                thread_count: u32::try_from(tcount).unwrap_or(0),
                process_name: Some(process_name),
            }
        } else {
            // PID not found — return zeroed summary
            SchedSummary {
                trace_duration_seconds: 0.0,
                total_events: 0,
                total_cpu_time_seconds: 0.0,
                d_sleep_seconds: 0.0,
                cpus_observed: 0,
                process_count: 0,
                thread_count: 0,
                process_name: None,
            }
        };

        // Per-thread breakdown
        let thread_sql = build_thread_breakdown_query(pid, trace_id, top_n);
        let mut stmt = self.conn.prepare(&thread_sql)?;
        let mut rows = stmt.query([])?;
        let mut threads = Vec::new();
        while let Some(row) = rows.next()? {
            threads.push(ThreadSchedStats {
                tid: row.get(0)?,
                name: row.get(1)?,
                cpu_time_seconds: row.get(2)?,
                d_sleep_seconds: row.get(3)?,
                event_count: u64::try_from(row.get::<_, i64>(4)?).unwrap_or(0),
                avg_slice_us: row.get(5)?,
                min_slice_us: row.get(6)?,
                max_slice_us: row.get(7)?,
                preempt_pct: row.get(8)?,
            });
        }

        Ok(SchedStatsResult {
            summary,
            processes: None,
            threads: Some(threads),
            thread_detail: None,
        })
    }

    fn sched_stats_per_thread(
        &self,
        tid: u32,
        trace_id: &Option<String>,
    ) -> Result<SchedStatsResult> {
        // Main stats
        let detail_sql = build_thread_detail_query(tid, trace_id);
        let mut stmt = self.conn.prepare(&detail_sql)?;
        let mut rows = stmt.query([])?;

        let detail = if let Some(row) = rows.next()? {
            let cpu_time_s: f64 = row.get(0)?;
            let d_sleep_s: f64 = row.get(1)?;
            let events: i64 = row.get(2)?;
            let avg_us: f64 = row.get(3)?;
            let min_us: f64 = row.get(4)?;
            let max_us: f64 = row.get(5)?;
            let migrations: i64 = row.get(6)?;
            let r_tid: i64 = row.get(7)?;
            let thread_name: String = row.get(8)?;
            let r_pid: i64 = row.get(9)?;
            let process_name: String = row.get(10)?;

            drop(rows);
            drop(stmt);

            // End state distribution
            let end_sql = build_end_state_query(tid, trace_id);
            let mut stmt2 = self.conn.prepare(&end_sql)?;
            let mut rows2 = stmt2.query([])?;
            let mut end_states = Vec::new();
            while let Some(row) = rows2.next()? {
                end_states.push(EndStateCount {
                    state: row.get(0)?,
                    count: u64::try_from(row.get::<_, i64>(1)?).unwrap_or(0),
                    percent: row.get(2)?,
                });
            }

            let events_u64 = u64::try_from(events).unwrap_or(0);
            let migrations_u64 = u64::try_from(migrations).unwrap_or(0);

            let summary = SchedSummary {
                trace_duration_seconds: 0.0,
                total_events: events_u64,
                total_cpu_time_seconds: cpu_time_s,
                d_sleep_seconds: d_sleep_s,
                cpus_observed: 0,
                process_count: 1,
                thread_count: 1,
                process_name: Some(process_name.clone()),
            };

            (
                summary,
                Some(ThreadDetailStats {
                    tid: r_tid,
                    pid: r_pid,
                    thread_name,
                    process_name,
                    cpu_time_seconds: cpu_time_s,
                    d_sleep_seconds: d_sleep_s,
                    event_count: events_u64,
                    avg_slice_us: avg_us,
                    min_slice_us: min_us,
                    max_slice_us: max_us,
                    cpu_migrations: migrations_u64,
                    end_states,
                }),
            )
        } else {
            // TID not found
            let summary = SchedSummary {
                trace_duration_seconds: 0.0,
                total_events: 0,
                total_cpu_time_seconds: 0.0,
                d_sleep_seconds: 0.0,
                cpus_observed: 0,
                process_count: 0,
                thread_count: 0,
                process_name: None,
            };
            (summary, None)
        };

        Ok(SchedStatsResult {
            summary: detail.0,
            processes: None,
            threads: None,
            thread_detail: detail.1,
        })
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
            conditions.push("ss.stack_event_type = 2".to_string());
        }
        StackTypeFilter::UninterruptibleSleep => {
            conditions.push("ss.stack_event_type = 0".to_string());
        }
        StackTypeFilter::AllSleep => {
            conditions.push("ss.stack_event_type IN (0, 2)".to_string());
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

// -- Sched stats query builders --

/// SQL expression for computing D-sleep time from the sched_next CTE.
/// Uses bitwise check (`& 2 != 0`) to catch compound uninterruptible states
/// like TASK_UNINTERRUPTIBLE | TASK_NOLOAD (130).
const D_SLEEP_SUM_EXPR: &str =
    "COALESCE(SUM(CASE WHEN sn.end_state & 2 != 0 AND sn.next_ts IS NOT NULL \
    THEN sn.next_ts - (sn.ts + sn.dur) ELSE 0 END), 0)";

/// Build the `sched_next` CTE that adds a `next_ts` column via LEAD().
fn build_sched_next_cte(filter: &str) -> String {
    format!(
        "WITH sched_next AS (\
         SELECT *, LEAD(ts) OVER (PARTITION BY utid ORDER BY ts) as next_ts \
         FROM sched_slice \
         WHERE dur > 0{filter})"
    )
}

fn trace_id_filter(trace_id: &Option<String>, table_alias: &str) -> String {
    match trace_id {
        Some(tid) => {
            let escaped = tid.replace('\'', "''");
            format!(" AND {table_alias}trace_id = '{escaped}'")
        }
        None => String::new(),
    }
}

pub(crate) fn build_sched_summary_query(trace_id: &Option<String>) -> String {
    let filter = trace_id_filter(trace_id, "ss.");
    format!(
        "SELECT COUNT(*) as events, \
         SUM(dur) / 1e9 as total_cpu_time_s, \
         COUNT(DISTINCT cpu) as cpus, \
         COUNT(DISTINCT ss.utid) as threads, \
         (MAX(ss.ts + ss.dur) - MIN(ss.ts)) / 1e9 as trace_dur_s \
         FROM sched_slice ss \
         WHERE ss.dur > 0{filter}"
    )
}

pub(crate) fn build_process_count_query(trace_id: &Option<String>) -> String {
    let ss_filter = trace_id_filter(trace_id, "ss.");
    let t_filter = trace_id_filter(trace_id, "t.");
    let p_filter = trace_id_filter(trace_id, "p.");
    format!(
        "SELECT COUNT(DISTINCT p.pid) as process_count \
         FROM sched_slice ss \
         JOIN thread t ON ss.utid = t.utid AND ss.trace_id = t.trace_id{t_filter} \
         JOIN process p ON t.upid = p.upid AND t.trace_id = p.trace_id{p_filter} \
         WHERE ss.dur > 0{ss_filter}"
    )
}

pub(crate) fn build_total_d_sleep_query(trace_id: &Option<String>) -> String {
    let filter = trace_id_filter(trace_id, "");
    // Use the same CTE structure but alias `sn` for consistency with D_SLEEP_SUM_EXPR
    format!(
        "{sched_next_cte} \
         SELECT {d_sleep_sum} / 1e9 as d_sleep_s \
         FROM sched_next sn",
        sched_next_cte = build_sched_next_cte(&filter),
        d_sleep_sum = D_SLEEP_SUM_EXPR,
    )
}

pub(crate) fn build_process_ranking_query(trace_id: &Option<String>, limit: usize) -> String {
    let cte_filter = trace_id_filter(trace_id, "");
    let t_filter = trace_id_filter(trace_id, "t.");
    let p_filter = trace_id_filter(trace_id, "p.");
    format!(
        "{sched_next_cte} \
         SELECT p.pid, COALESCE(p.name, '') as name, \
         COUNT(DISTINCT t.tid) as thread_count, \
         SUM(sn.dur) / 1e9 as cpu_time_s, \
         {d_sleep_sum} / 1e9 as d_sleep_s, \
         COUNT(*) as events, \
         AVG(sn.dur) / 1e3 as avg_slice_us, \
         100.0 * SUM(CASE WHEN sn.end_state IS NULL THEN 1 ELSE 0 END) \
         / NULLIF(COUNT(*), 0) as preempt_pct \
         FROM sched_next sn \
         JOIN thread t ON sn.utid = t.utid AND sn.trace_id = t.trace_id{t_filter} \
         JOIN process p ON t.upid = p.upid AND t.trace_id = p.trace_id{p_filter} \
         GROUP BY p.pid, p.name \
         ORDER BY cpu_time_s DESC \
         LIMIT {limit}",
        sched_next_cte = build_sched_next_cte(&cte_filter),
        d_sleep_sum = D_SLEEP_SUM_EXPR,
    )
}

pub(crate) fn build_process_aggregate_query(pid: u32, trace_id: &Option<String>) -> String {
    let cte_filter = trace_id_filter(trace_id, "");
    let t_filter = trace_id_filter(trace_id, "t.");
    let p_filter = trace_id_filter(trace_id, "p.");
    format!(
        "{sched_next_cte} \
         SELECT SUM(sn.dur) / 1e9 as cpu_time_s, \
         {d_sleep_sum} / 1e9 as d_sleep_s, \
         COUNT(*) as events, \
         COUNT(DISTINCT t.tid) as thread_count, \
         COALESCE(p.name, '') as process_name \
         FROM sched_next sn \
         JOIN thread t ON sn.utid = t.utid AND sn.trace_id = t.trace_id{t_filter} \
         JOIN process p ON t.upid = p.upid AND t.trace_id = p.trace_id{p_filter} \
         WHERE p.pid = {pid} \
         GROUP BY p.name",
        sched_next_cte = build_sched_next_cte(&cte_filter),
        d_sleep_sum = D_SLEEP_SUM_EXPR,
    )
}

pub(crate) fn build_thread_breakdown_query(
    pid: u32,
    trace_id: &Option<String>,
    limit: usize,
) -> String {
    let cte_filter = trace_id_filter(trace_id, "");
    let t_filter = trace_id_filter(trace_id, "t.");
    let p_filter = trace_id_filter(trace_id, "p.");
    format!(
        "{sched_next_cte} \
         SELECT t.tid, COALESCE(t.name, '') as name, \
         SUM(sn.dur) / 1e9 as cpu_time_s, \
         {d_sleep_sum} / 1e9 as d_sleep_s, \
         COUNT(*) as events, \
         AVG(sn.dur) / 1e3 as avg_slice_us, \
         MIN(sn.dur) / 1e3 as min_slice_us, \
         MAX(sn.dur) / 1e3 as max_slice_us, \
         100.0 * SUM(CASE WHEN sn.end_state IS NULL THEN 1 ELSE 0 END) \
         / NULLIF(COUNT(*), 0) as preempt_pct \
         FROM sched_next sn \
         JOIN thread t ON sn.utid = t.utid AND sn.trace_id = t.trace_id{t_filter} \
         JOIN process p ON t.upid = p.upid AND t.trace_id = p.trace_id{p_filter} \
         WHERE p.pid = {pid} \
         GROUP BY t.tid, t.name \
         ORDER BY cpu_time_s DESC \
         LIMIT {limit}",
        sched_next_cte = build_sched_next_cte(&cte_filter),
        d_sleep_sum = D_SLEEP_SUM_EXPR,
    )
}

pub(crate) fn build_thread_detail_query(tid: u32, trace_id: &Option<String>) -> String {
    let filter = trace_id_filter(trace_id, "");
    let t_filter = trace_id_filter(trace_id, "t.");
    let p_filter = trace_id_filter(trace_id, "p.");
    format!(
        "WITH sched_next AS (\
         SELECT *, \
         LAG(cpu) OVER (PARTITION BY utid ORDER BY ts) as prev_cpu, \
         LEAD(ts) OVER (PARTITION BY utid ORDER BY ts) as next_ts \
         FROM sched_slice \
         WHERE utid = (SELECT utid FROM thread WHERE tid = {tid}{filter} LIMIT 1) \
         AND dur > 0{filter}) \
         SELECT SUM(sn.dur) / 1e9 as cpu_time_s, \
         {d_sleep_sum} / 1e9 as d_sleep_s, \
         COUNT(*) as events, \
         AVG(sn.dur) / 1e3 as avg_slice_us, \
         MIN(sn.dur) / 1e3 as min_slice_us, \
         MAX(sn.dur) / 1e3 as max_slice_us, \
         SUM(CASE WHEN sn.cpu != sn.prev_cpu AND sn.prev_cpu IS NOT NULL \
         THEN 1 ELSE 0 END) as cpu_migrations, \
         t.tid, COALESCE(t.name, '') as thread_name, \
         p.pid, COALESCE(p.name, '') as process_name \
         FROM sched_next sn \
         JOIN thread t ON sn.utid = t.utid AND sn.trace_id = t.trace_id{t_filter} \
         JOIN process p ON t.upid = p.upid AND t.trace_id = p.trace_id{p_filter} \
         GROUP BY t.tid, t.name, p.pid, p.name",
        d_sleep_sum = D_SLEEP_SUM_EXPR,
    )
}

pub(crate) fn build_end_state_query(tid: u32, trace_id: &Option<String>) -> String {
    let ss_filter = trace_id_filter(trace_id, "ss.");
    let t_filter = trace_id_filter(trace_id, "t.");
    format!(
        "SELECT CASE \
         WHEN ss.end_state IS NULL THEN 'Preempted (running)' \
         WHEN ss.end_state & 2 != 0 THEN 'Uninterruptible sleep (D)' \
         WHEN ss.end_state & 1 != 0 THEN 'Interruptible sleep (S)' \
         WHEN ss.end_state & 4 != 0 THEN 'Stopped' \
         WHEN ss.end_state & 8 != 0 THEN 'Traced' \
         WHEN ss.end_state & 16 != 0 THEN 'Exit (dead)' \
         WHEN ss.end_state & 32 != 0 THEN 'Exit (zombie)' \
         ELSE 'Other (' || CAST(ss.end_state AS VARCHAR) || ')' \
         END as state, \
         COUNT(*) as count, \
         100.0 * COUNT(*) / NULLIF(SUM(COUNT(*)) OVER (), 0) as pct \
         FROM sched_slice ss \
         JOIN thread t ON ss.utid = t.utid AND ss.trace_id = t.trace_id{t_filter} \
         WHERE t.tid = {tid} AND ss.dur > 0{ss_filter} \
         GROUP BY ss.end_state \
         ORDER BY count DESC"
    )
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
        assert!(sql.contains("stack_event_type = 2"));
        assert!(!sql.contains("sched_slice"));
        assert!(!sql.contains("end_state"));
    }

    #[test]
    fn test_build_flamegraph_query_uninterruptible_sleep() {
        let sql = build_flamegraph_query(
            &StackTypeFilter::UninterruptibleSleep,
            &None,
            &None,
            &None,
            &None,
            &None,
            1,
        );
        assert!(sql.contains("stack_event_type = 0"));
        assert!(!sql.contains("sched_slice"));
        assert!(!sql.contains("end_state"));
    }

    #[test]
    fn test_build_flamegraph_query_all_sleep() {
        let sql = build_flamegraph_query(
            &StackTypeFilter::AllSleep,
            &None,
            &None,
            &None,
            &None,
            &None,
            1,
        );
        assert!(sql.contains("stack_event_type IN (0, 2)"));
        assert!(!sql.contains("sched_slice"));
        assert!(!sql.contains("end_state"));
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

    // -- Sched stats query builder tests --

    #[test]
    fn test_build_sched_summary_query_no_trace_id() {
        let sql = build_sched_summary_query(&None);
        assert!(sql.contains("FROM sched_slice ss"));
        assert!(sql.contains("WHERE ss.dur > 0"));
        assert!(!sql.contains("trace_id"));
    }

    #[test]
    fn test_build_sched_summary_query_with_trace_id() {
        let sql = build_sched_summary_query(&Some("trace-1".to_string()));
        assert!(sql.contains("ss.trace_id = 'trace-1'"));
    }

    #[test]
    fn test_build_process_ranking_query_has_limit() {
        let sql = build_process_ranking_query(&None, 10);
        assert!(sql.contains("LIMIT 10"));
        assert!(sql.contains("ORDER BY cpu_time_s DESC"));
        assert!(sql.contains("JOIN thread t"));
        assert!(sql.contains("JOIN process p"));
    }

    #[test]
    fn test_build_process_ranking_query_uses_cte() {
        let sql = build_process_ranking_query(&None, 20);
        assert!(sql.contains("WITH sched_next AS"));
        assert!(sql.contains("LEAD(ts) OVER (PARTITION BY utid ORDER BY ts)"));
    }

    #[test]
    fn test_build_thread_detail_query_has_migrations() {
        let sql = build_thread_detail_query(1234, &None);
        assert!(sql.contains("LAG(cpu) OVER (PARTITION BY utid ORDER BY ts)"));
        assert!(sql.contains("cpu_migrations"));
        assert!(sql.contains("WHERE utid = (SELECT utid FROM thread WHERE tid = 1234"));
    }

    #[test]
    fn test_build_thread_detail_query_with_trace_id() {
        let sql = build_thread_detail_query(42, &Some("t1".to_string()));
        assert!(sql.contains("t.trace_id = 't1'"));
        assert!(sql.contains("p.trace_id = 't1'"));
        // Subquery should use unaliased trace_id filter, not t. alias
        assert!(
            sql.contains("FROM thread WHERE tid = 42 AND trace_id = 't1'"),
            "subquery should use unaliased trace_id filter: {sql}"
        );
    }

    #[test]
    fn test_build_end_state_query_covers_all_states() {
        let sql = build_end_state_query(100, &None);
        assert!(sql.contains("Preempted (running)"));
        assert!(sql.contains("Interruptible sleep (S)"));
        assert!(sql.contains("Uninterruptible sleep (D)"));
        assert!(sql.contains("Stopped"));
        assert!(sql.contains("Exit (dead)"));
        assert!(sql.contains("Exit (zombie)"));
        assert!(sql.contains("ORDER BY count DESC"));
        // Verify bitwise checks for compound states
        assert!(
            sql.contains("end_state & 2 != 0"),
            "should use bitwise check for D-state"
        );
    }

    #[test]
    fn test_build_process_aggregate_query_filters_pid() {
        let sql = build_process_aggregate_query(5678, &None);
        assert!(sql.contains("WHERE p.pid = 5678"));
        assert!(sql.contains("GROUP BY p.name"));
    }

    #[test]
    fn test_build_thread_breakdown_query_filters_pid_with_limit() {
        let sql = build_thread_breakdown_query(1000, &None, 5);
        assert!(sql.contains("WHERE p.pid = 1000"));
        assert!(sql.contains("LIMIT 5"));
        assert!(sql.contains("ORDER BY cpu_time_s DESC"));
    }

    #[test]
    fn test_d_sleep_sum_expr_used_consistently() {
        // Verify the shared D_SLEEP_SUM_EXPR appears in queries that use it
        let total = build_total_d_sleep_query(&None);
        assert!(total.contains("end_state & 2 != 0"));
        assert!(total.contains("next_ts IS NOT NULL"));

        let ranking = build_process_ranking_query(&None, 10);
        assert!(ranking.contains("end_state & 2 != 0"));
        assert!(ranking.contains("next_ts IS NOT NULL"));
    }

    #[test]
    fn test_sched_stats_params_default() {
        let params = SchedStatsParams::default();
        assert_eq!(params.pid, None);
        assert_eq!(params.tid, None);
        assert_eq!(params.trace_id, None);
        assert_eq!(params.top_n, 20);
    }
}
