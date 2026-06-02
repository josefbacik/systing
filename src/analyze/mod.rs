//! Analysis logic for querying and analyzing systing trace databases.
//!
//! This module provides the core analysis functionality used by both the CLI
//! and MCP server interfaces. All methods are synchronous and work directly
//! with DuckDB connections.

mod cpu_stats;
mod flamegraph;
mod network_connections;
mod network_interfaces;
mod network_socket_pairs;
mod query;
mod sched_stats;

pub use cpu_stats::{CpuStatsParams, CpuStatsResult, CpuStatsSummary, PerCpuStats};
pub use flamegraph::{
    FlamegraphMetadata, FlamegraphParams, FlamegraphResult, StackEntry, StackTypeFilter,
};
pub use network_connections::{
    ConnectionStats, NetworkConnectionsParams, NetworkConnectionsResult, TraceConnectionStats,
};
pub use network_interfaces::{
    InterfaceStats, NetworkInterfacesParams, NetworkInterfacesResult, TraceNetworkStats,
    TrafficStats,
};
pub use network_socket_pairs::{
    NetworkSocketPairsParams, NetworkSocketPairsResult, SocketPair, SocketSide,
};
pub use sched_stats::{
    EndStateCount, ProcessSchedStats, SchedStatsParams, SchedStatsResult, SchedSummary,
    ThreadDetailStats, ThreadSchedStats,
};

use anyhow::{bail, Result};
use duckdb::Connection;
use serde::Serialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use query::{duckdb_value_to_json, duckdb_value_to_string};

/// Maximum number of rows returned by a query.
pub const MAX_QUERY_ROWS: usize = 10_000;

/// Maximum number of processes returned in trace info summaries.
const MAX_TRACE_INFO_PROCESSES: usize = 25;

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

/// Per-trace version information.
#[derive(Debug, Serialize)]
pub struct TraceVersionInfo {
    pub trace_id: String,
    pub systing_version: String,
}

/// Per-trace system/platform information (from the `sysinfo` table): what kind
/// of machine the trace was captured on. The platform columns were added in
/// schema v9 and read as `None` from older databases.
#[derive(Debug, Serialize)]
pub struct TraceSystemInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel_release: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub machine: Option<String>,
    /// Hypervisor the trace was captured under (e.g. "kvm"); `None` on bare
    /// metal (reliable on x86_64, best-effort elsewhere).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hypervisor: Option<String>,
    /// DMI system vendor (e.g. "Amazon EC2").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sys_vendor: Option<String>,
    /// DMI product name (e.g. "m7i.16xlarge").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_name: Option<String>,
    /// cpufreq scaling driver; `None` means the host had no cpufreq support,
    /// so CPU-frequency counter tracks are absent from the trace.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpufreq_driver: Option<String>,
}

/// Trace metadata.
#[derive(Debug, Serialize)]
pub struct TraceInfo {
    pub database_path: String,
    pub traces: Vec<String>,
    pub trace_versions: Vec<TraceVersionInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<u32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub system: Vec<TraceSystemInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_range: Option<TimeRange>,
    pub tables: Vec<TableInfo>,
    pub total_process_count: u64,
    pub processes: Vec<ProcessInfo>,
}

/// Extract column names from a DuckDB result set.
fn extract_column_names(rows: &duckdb::Rows<'_>) -> (usize, Vec<String>) {
    let column_count = rows.as_ref().map_or(0, |r| r.column_count());
    let names = if let Some(row_ref) = rows.as_ref() {
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
    (column_count, names)
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

        // Disable external access (reading/writing files, ATTACH, loading
        // extensions) so SQL run against an untrusted trace database -- e.g.
        // queries an AI assistant was prompt-injected into running via the MCP
        // server -- cannot touch anything outside the trace database. DuckDB
        // refuses to re-enable this setting while the database is running, so
        // it cannot be undone with a SET statement.
        let mut config = duckdb::Config::default().enable_external_access(false)?;
        if read_only {
            config = config.access_mode(duckdb::AccessMode::ReadOnly)?;
        }
        let conn = Connection::open_with_flags(path, config)?;

        Ok(Self {
            conn,
            path: path.to_path_buf(),
        })
    }

    /// Execute a SQL query and return typed results.
    pub fn query(&self, sql: &str) -> Result<QueryResult> {
        let mut stmt = self.conn.prepare(sql)?;
        let mut rows = stmt.query([])?;

        let (column_count, column_names) = extract_column_names(&rows);

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

        let (column_count, column_names) = extract_column_names(&rows);

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

    /// Get trace metadata.
    pub fn trace_info(&self) -> Result<TraceInfo> {
        let all_tables = self.list_tables()?;
        let tables: Vec<TableInfo> = all_tables.into_iter().filter(|t| t.row_count > 0).collect();

        let traces = self.get_trace_ids()?;
        let trace_versions = self.get_trace_versions();
        let schema_version = self.get_schema_version();
        let system = self.get_system_info();

        let time_range =
            if self.table_exists("stack_sample")? && self.table_has_rows("stack_sample")? {
                match self.get_trace_time_range(None) {
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

        let total_process_count = self.get_process_count()?;
        let processes = self.get_processes(MAX_TRACE_INFO_PROCESSES)?;

        Ok(TraceInfo {
            database_path: self.path.display().to_string(),
            traces,
            trace_versions,
            schema_version,
            system,
            time_range,
            tables,
            total_process_count,
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

    fn get_trace_time_range(&self, trace_id: Option<&str>) -> Result<(i64, i64, u64)> {
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

    /// Returns version info from `_traces`. Returns an empty vec for databases
    /// that predate the `systing_version` column.
    fn get_trace_versions(&self) -> Vec<TraceVersionInfo> {
        // Check if the systing_version column exists (older databases won't have it)
        let has_version: bool = self
            .conn
            .prepare(
                "SELECT COUNT(*) FROM information_schema.columns \
                 WHERE table_name = '_traces' AND column_name = 'systing_version'",
            )
            .and_then(|mut s| s.query_row([], |r| r.get::<_, u32>(0)))
            .map(|c| c > 0)
            .unwrap_or(false);

        if !has_version {
            return Vec::new();
        }

        let Ok(mut stmt) = self.conn.prepare(
            "SELECT trace_id, COALESCE(systing_version, '') FROM _traces ORDER BY trace_id",
        ) else {
            return Vec::new();
        };
        let Ok(rows) = stmt.query_map([], |row| {
            Ok(TraceVersionInfo {
                trace_id: row.get(0)?,
                systing_version: row.get(1)?,
            })
        }) else {
            return Vec::new();
        };
        rows.filter_map(|r| r.ok()).collect()
    }

    fn get_schema_version(&self) -> Option<u32> {
        let mut stmt = self
            .conn
            .prepare("SELECT version FROM _schema_version LIMIT 1")
            .ok()?;
        let mut rows = stmt.query([]).ok()?;
        let row = rows.next().ok()??;
        row.get(0).ok()
    }

    /// Per-trace system/platform info from the `sysinfo` table. Best-effort:
    /// the table may be missing entirely, and the platform columns
    /// (hypervisor, sys_vendor, product_name, cpufreq_driver) only exist from
    /// schema v9 on - missing columns are read as NULL so older databases
    /// still report kernel/machine.
    fn get_system_info(&self) -> Vec<TraceSystemInfo> {
        let existing: HashSet<String> = match self
            .conn
            .prepare(
                "SELECT column_name FROM information_schema.columns WHERE table_name = 'sysinfo'",
            )
            .and_then(|mut s| {
                s.query_map([], |r| r.get::<_, String>(0))
                    .map(|rows| rows.filter_map(|r| r.ok()).collect())
            }) {
            Ok(cols) => cols,
            Err(_) => return Vec::new(),
        };
        if existing.is_empty() {
            return Vec::new();
        }

        // Substitute NULL for any column this database predates.
        let col = |name: &str| -> String {
            if existing.contains(name) {
                format!("\"{name}\"")
            } else {
                "NULL".to_string()
            }
        };
        let sql = format!(
            "SELECT {}, {}, {}, {}, {}, {}, {} FROM sysinfo ORDER BY 1",
            col("trace_id"),
            col("release"),
            col("machine"),
            col("hypervisor"),
            col("sys_vendor"),
            col("product_name"),
            col("cpufreq_driver"),
        );

        let Ok(mut stmt) = self.conn.prepare(&sql) else {
            return Vec::new();
        };
        let Ok(rows) = stmt.query_map([], |row| {
            Ok(TraceSystemInfo {
                trace_id: row.get(0)?,
                kernel_release: row.get(1)?,
                machine: row.get(2)?,
                hypervisor: row.get(3)?,
                sys_vendor: row.get(4)?,
                product_name: row.get(5)?,
                cpufreq_driver: row.get(6)?,
            })
        }) else {
            return Vec::new();
        };
        rows.filter_map(|r| r.ok()).collect()
    }

    fn get_process_count(&self) -> Result<u64> {
        if !self.table_exists("process")? {
            return Ok(0);
        }
        // Use the same grouping as get_processes (pid, name) so the count
        // matches the number of rows that query would return without a LIMIT.
        let mut stmt = self
            .conn
            .prepare("SELECT COUNT(*) FROM (SELECT DISTINCT pid, name FROM process)")?;
        let mut rows = stmt.query([])?;
        match rows.next()? {
            Some(row) => {
                let count: i64 = row.get(0)?;
                Ok(count as u64)
            }
            None => Ok(0),
        }
    }

    fn get_processes(&self, limit: usize) -> Result<Vec<ProcessInfo>> {
        if !self.table_exists("process")? {
            return Ok(Vec::new());
        }

        let has_thread = self.table_exists("thread")?;

        let sql = if has_thread {
            format!(
                "SELECT p.pid, COALESCE(p.name, ''), COUNT(DISTINCT t.tid) as thread_count \
                 FROM process p \
                 LEFT JOIN thread t ON p.upid = t.upid AND p.trace_id = t.trace_id \
                 GROUP BY p.pid, p.name \
                 ORDER BY thread_count DESC, p.pid \
                 LIMIT {limit}"
            )
        } else {
            format!("SELECT pid, COALESCE(name, ''), 0 FROM process ORDER BY pid LIMIT {limit}")
        };

        let mut stmt = self.conn.prepare(&sql)?;
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

// -- Free functions (module-internal) --

fn table_exists(conn: &Connection, table_name: &str) -> Result<bool> {
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

fn table_has_rows(conn: &Connection, table_name: &str) -> Result<bool> {
    if !table_exists(conn, table_name)? {
        return Ok(false);
    }
    let sql = format!("SELECT 1 FROM \"{table_name}\" LIMIT 1");
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query([])?;
    Ok(rows.next()?.is_some())
}

/// Convert an i64 from DuckDB to u64, clamping negatives to 0.
pub(crate) fn to_u64(val: i64) -> u64 {
    u64::try_from(val).unwrap_or(0)
}

/// Build a trace_id SQL filter clause (e.g., ` AND ss.trace_id = '...'`).
/// trace_id values are escaped via single-quote doubling for safe SQL interpolation.
pub(crate) fn trace_id_filter(trace_id: Option<&str>, table_alias: &str) -> String {
    match trace_id {
        Some(tid) => {
            let escaped = tid.replace('\'', "''");
            format!(" AND {table_alias}trace_id = '{escaped}'")
        }
        None => String::new(),
    }
}

fn get_trace_time_range(conn: &Connection, trace_id: Option<&str>) -> Result<(i64, i64, u64)> {
    // trace_id is escaped via single-quote doubling for safe SQL interpolation
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_u64_positive() {
        assert_eq!(to_u64(42), 42);
        assert_eq!(to_u64(0), 0);
        assert_eq!(to_u64(i64::MAX), i64::MAX as u64);
    }

    #[test]
    fn test_to_u64_negative() {
        assert_eq!(to_u64(-1), 0);
        assert_eq!(to_u64(i64::MIN), 0);
    }

    /// Assert that an error is DuckDB refusing an operation because external
    /// access is disabled. DuckDB 1.4 phrases this "disabled by configuration"
    /// for file access and "disabled through configuration" for extension
    /// loading (older releases used the latter for both).
    fn assert_external_access_blocked(err: &anyhow::Error) {
        let msg = err.to_string();
        assert!(
            msg.contains("disabled by configuration")
                || msg.contains("disabled through configuration"),
            "expected external-access error, got: {msg}"
        );
    }

    #[test]
    fn test_open_blocks_external_access() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.duckdb");

        // Create a small database to analyze.
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch("CREATE TABLE t (x INTEGER); INSERT INTO t VALUES (1);")
                .unwrap();
        }

        // An external file that queries must not be able to read.
        let csv_path = dir.path().join("external.csv");
        std::fs::write(&csv_path, "a,b\n1,2\n").unwrap();

        for read_only in [true, false] {
            let db = AnalyzeDb::open(&db_path, read_only).unwrap();

            // Queries against the trace database itself still work.
            let result = db.query("SELECT x FROM t").unwrap();
            assert_eq!(result.row_count, 1);

            // Reading external files is blocked.
            let read_err = db
                .query(&format!(
                    "SELECT * FROM read_csv_auto('{}')",
                    csv_path.display()
                ))
                .unwrap_err();
            assert_external_access_blocked(&read_err);

            // Writing external files is blocked.
            let copy_err = db
                .query(&format!(
                    "COPY (SELECT 1) TO '{}'",
                    dir.path().join("out.csv").display()
                ))
                .unwrap_err();
            assert_external_access_blocked(&copy_err);

            // Attaching other database files is blocked.
            let attach_err = db
                .query(&format!(
                    "ATTACH '{}' AS other",
                    dir.path().join("other.duckdb").display()
                ))
                .unwrap_err();
            assert_external_access_blocked(&attach_err);

            // Installing or loading external extensions (e.g. httpfs for
            // network egress) is blocked.
            assert!(db.query("INSTALL httpfs").is_err());
            let load_err = db.query("LOAD httpfs").unwrap_err();
            assert_external_access_blocked(&load_err);

            // The setting cannot be re-enabled at runtime.
            let set_err = db.query("SET enable_external_access = true").unwrap_err();
            assert!(
                set_err
                    .to_string()
                    .contains("Cannot change enable_external_access"),
                "unexpected error: {set_err}"
            );
        }
    }

    #[test]
    fn test_trace_info_system_info() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.duckdb");

        {
            let conn = Connection::open(&db_path).unwrap();
            crate::duckdb::create_schema(&conn).unwrap();
            conn.execute_batch(
                "INSERT INTO sysinfo (trace_id, sysname, release, version, machine, \
                 cpufreq_driver, hypervisor, sys_vendor, product_name) \
                 VALUES ('t1', 'Linux', '6.12.0', '#1 SMP', 'x86_64', \
                 NULL, 'kvm', 'Amazon EC2', 'm7i.16xlarge')",
            )
            .unwrap();
        }

        let db = AnalyzeDb::open(&db_path, true).unwrap();
        let info = db.trace_info().unwrap();

        assert_eq!(info.system.len(), 1);
        let sys = &info.system[0];
        assert_eq!(sys.trace_id.as_deref(), Some("t1"));
        assert_eq!(sys.kernel_release.as_deref(), Some("6.12.0"));
        assert_eq!(sys.machine.as_deref(), Some("x86_64"));
        assert_eq!(sys.hypervisor.as_deref(), Some("kvm"));
        assert_eq!(sys.sys_vendor.as_deref(), Some("Amazon EC2"));
        assert_eq!(sys.product_name.as_deref(), Some("m7i.16xlarge"));
        assert_eq!(
            sys.cpufreq_driver, None,
            "NULL cpufreq_driver must come back as None"
        );
    }

    #[test]
    fn test_trace_info_system_info_pre_v9_schema() {
        // Databases produced before schema v9 have a sysinfo table without the
        // platform columns; trace_info must still report kernel/machine and
        // read the missing columns as None.
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("old.duckdb");

        {
            let conn = Connection::open(&db_path).unwrap();
            crate::duckdb::create_schema(&conn).unwrap();
            conn.execute_batch(
                "ALTER TABLE sysinfo DROP COLUMN cpufreq_driver; \
                 ALTER TABLE sysinfo DROP COLUMN hypervisor; \
                 ALTER TABLE sysinfo DROP COLUMN sys_vendor; \
                 ALTER TABLE sysinfo DROP COLUMN product_name; \
                 INSERT INTO sysinfo (trace_id, sysname, release, version, machine) \
                 VALUES ('t1', 'Linux', '5.10.0', '#1 SMP', 'aarch64')",
            )
            .unwrap();
        }

        let db = AnalyzeDb::open(&db_path, true).unwrap();
        let info = db.trace_info().unwrap();

        assert_eq!(info.system.len(), 1);
        let sys = &info.system[0];
        assert_eq!(sys.kernel_release.as_deref(), Some("5.10.0"));
        assert_eq!(sys.machine.as_deref(), Some("aarch64"));
        assert_eq!(sys.hypervisor, None);
        assert_eq!(sys.sys_vendor, None);
        assert_eq!(sys.product_name, None);
        assert_eq!(sys.cpufreq_driver, None);
    }

    #[test]
    fn test_trace_info_system_info_no_sysinfo_table() {
        // A database without a sysinfo table at all must yield an empty
        // system list, not an error.
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("bare.duckdb");

        {
            let conn = Connection::open(&db_path).unwrap();
            crate::duckdb::create_schema(&conn).unwrap();
            conn.execute_batch("DROP TABLE sysinfo").unwrap();
        }

        let db = AnalyzeDb::open(&db_path, true).unwrap();
        let info = db.trace_info().unwrap();
        assert!(info.system.is_empty());
    }
}
