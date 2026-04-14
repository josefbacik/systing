//! DuckDB-specific validation query implementation.
//!
//! This module implements `ValidationQueries` for DuckDB databases using
//! native SQL queries with efficient pushdown.

use anyhow::{Context, Result};
use duckdb::Connection;
use std::path::Path;

use super::config::ValidationConfig;
use super::queries::{
    CmdlineStats, FieldCheck, OrphanCheck, SchemaResult, StackViolation, TpuMetricCheck,
    ValidationQueries,
};
use super::result::{ValidationError, ValidationResult, ValidationWarning};
use super::runner::run_common_validations;

/// DuckDB-specific validation query implementation.
pub struct DuckDbQueries {
    conn: Connection,
}

impl DuckDbQueries {
    /// Create a new DuckDbQueries for the given database path.
    pub fn new(db_path: &Path) -> Result<Self> {
        let conn = Connection::open(db_path)?;
        Ok(Self { conn })
    }

    /// Check if a table exists in the database.
    fn table_exists(&self, table: &str) -> bool {
        self.conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM information_schema.tables WHERE table_name = ?",
                [table],
                |row| row.get::<_, bool>(0),
            )
            .unwrap_or(false)
    }

    /// Check if a column exists in a table.
    fn column_exists(&self, table: &str, column: &str) -> bool {
        self.conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM information_schema.columns
                 WHERE table_name = ? AND column_name = ?",
                [table, column],
                |row| row.get::<_, bool>(0),
            )
            .unwrap_or(false)
    }

    /// Find rows in `table` whose `utid` column is NULL on a thread-attributed
    /// custom track.
    ///
    /// Joins the table against `track` and excludes tracks that are not expected
    /// to carry per-thread utid:
    /// - Per-CPU tracks (`" CPU <digits>"` suffix from `events::mod`)
    /// - Network tracks (`"Network Packets"`, `"Network Interfaces"`, `"Socket ..."`)
    ///
    /// Must stay in sync with `is_non_thread_track` in `parquet_queries.rs`.
    ///
    /// Returns `FieldCheck::ok(0)` if the table, `track` table, or required
    /// columns are missing (e.g. a trace that did not collect any markers or
    /// custom events).
    fn find_utid_violations_table(&self, table: &str) -> Result<FieldCheck> {
        if !self.table_exists(table)
            || !self.column_exists(table, "utid")
            || !self.column_exists(table, "track_id")
            || !self.column_exists(table, "id")
            || !self.table_exists("track")
            || !self.column_exists("track", "id")
            || !self.column_exists("track", "name")
        {
            return Ok(FieldCheck::ok(0));
        }

        // Exclude tracks that legitimately have no thread attribution:
        // - CPU tracks (per-CPU event tracks from events::mod)
        // - Network hierarchy tracks (Network Packets, Network Interfaces,
        //   and all their descendants: socket tracks, namespace tracks,
        //   interface tracks)
        //
        // We use a recursive CTE to walk the parent_id chain and exclude
        // the entire network track subtree.
        let non_thread_tracks_cte = "\
            WITH RECURSIVE network_roots AS ( \
                SELECT id FROM track \
                WHERE name IN ('Network Packets', 'Network Interfaces') \
            ), network_tree AS ( \
                SELECT id FROM network_roots \
                UNION ALL \
                SELECT t.id FROM track t \
                JOIN network_tree nt ON t.parent_id = nt.id \
            ) ";

        let track_filter = "NOT regexp_matches(t.name, ' CPU [0-9]+$') \
               AND t.id NOT IN (SELECT id FROM network_tree)";

        let denom_sql = format!(
            "{non_thread_tracks_cte} \
             SELECT COUNT(*) \
             FROM {table} s \
             JOIN track t ON s.track_id = t.id \
             WHERE {track_filter}"
        );
        let total_count: i64 = self
            .conn
            .query_row(&denom_sql, [], |row| row.get(0))
            .with_context(|| format!("Failed to count thread-attributed {table} rows"))?;

        let viol_sql = format!(
            "{non_thread_tracks_cte} \
             SELECT COUNT(*) \
             FROM {table} s \
             JOIN track t ON s.track_id = t.id \
             WHERE s.utid IS NULL \
               AND {track_filter}"
        );
        let empty_count: i64 = self
            .conn
            .query_row(&viol_sql, [], |row| row.get(0))
            .with_context(|| format!("Failed to count utid violations in {table}"))?;

        let mut sample_ids = Vec::new();
        if empty_count > 0 {
            let sample_sql = format!(
                "{non_thread_tracks_cte} \
                 SELECT s.id \
                 FROM {table} s \
                 JOIN track t ON s.track_id = t.id \
                 WHERE s.utid IS NULL \
                   AND {track_filter} \
                 LIMIT 10"
            );
            let mut stmt = self.conn.prepare(&sample_sql)?;
            let rows = stmt.query_map([], |row| row.get::<_, i64>(0))?;
            for row in rows {
                sample_ids.push(row?);
            }
        }

        Ok(FieldCheck {
            empty_count,
            total_count,
            sample_ids,
        })
    }

    /// Get the data type of a column.
    fn get_column_type(&self, table: &str, column: &str) -> Option<String> {
        self.conn
            .query_row(
                "SELECT data_type FROM information_schema.columns
                 WHERE table_name = ? AND column_name = ?",
                [table, column],
                |row| row.get::<_, String>(0),
            )
            .ok()
    }
}

impl ValidationQueries for DuckDbQueries {
    fn format_name(&self) -> &'static str {
        "duckdb"
    }

    fn count_orphan_thread_upids(&mut self) -> Result<OrphanCheck> {
        if !self.table_exists("thread") || !self.table_exists("process") {
            return Ok(OrphanCheck::ok(0));
        }

        // Count total and orphans
        let (total_count, orphan_count): (i64, i64) = self
            .conn
            .query_row(
                "SELECT
                COUNT(*),
                COUNT(*) FILTER (WHERE upid IS NOT NULL
                    AND NOT EXISTS (SELECT 1 FROM process p WHERE p.upid = thread.upid))
             FROM thread",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .context("Failed to count orphan thread upids")?;

        // Get sample orphan IDs
        let mut sample_orphan_ids = Vec::new();
        if orphan_count > 0 {
            let mut stmt = self.conn.prepare(
                "SELECT DISTINCT t.upid FROM thread t
                 WHERE t.upid IS NOT NULL
                 AND NOT EXISTS (SELECT 1 FROM process p WHERE p.upid = t.upid)
                 LIMIT 10",
            )?;
            let rows = stmt.query_map([], |row| row.get::<_, i64>(0))?;
            for row in rows {
                sample_orphan_ids.push(row?);
            }
        }

        Ok(OrphanCheck {
            orphan_count,
            total_count,
            sample_orphan_ids,
        })
    }

    fn count_orphan_sched_utids(&mut self) -> Result<OrphanCheck> {
        if !self.table_exists("sched_slice") || !self.table_exists("thread") {
            return Ok(OrphanCheck::ok(0));
        }

        // Count total and orphans
        let (total_count, orphan_count): (i64, i64) = self
            .conn
            .query_row(
                "SELECT
                COUNT(*),
                COUNT(*) FILTER (WHERE utid IS NOT NULL
                    AND NOT EXISTS (SELECT 1 FROM thread t WHERE t.utid = sched_slice.utid))
             FROM sched_slice",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .context("Failed to count orphan sched utids")?;

        // Get sample orphan IDs
        let mut sample_orphan_ids = Vec::new();
        if orphan_count > 0 {
            let mut stmt = self.conn.prepare(
                "SELECT DISTINCT s.utid FROM sched_slice s
                 WHERE s.utid IS NOT NULL
                 AND NOT EXISTS (SELECT 1 FROM thread t WHERE t.utid = s.utid)
                 LIMIT 10",
            )?;
            let rows = stmt.query_map([], |row| row.get::<_, i64>(0))?;
            for row in rows {
                sample_orphan_ids.push(row?);
            }
        }

        Ok(OrphanCheck {
            orphan_count,
            total_count,
            sample_orphan_ids,
        })
    }

    fn count_orphan_network_utids(&mut self) -> Result<OrphanCheck> {
        if !self.table_exists("thread") {
            return Ok(OrphanCheck::ok(0));
        }
        let mut total_count = 0i64;
        let mut orphan_count = 0i64;
        let mut sample_orphan_ids = Vec::new();
        for tbl in ["network_syscall", "network_poll"] {
            if !self.table_exists(tbl) {
                continue;
            }
            let (t, o): (i64, i64) = self
                .conn
                .query_row(
                    &format!(
                        "SELECT COUNT(*), COUNT(*) FILTER (WHERE utid IS NOT NULL \
                         AND NOT EXISTS (SELECT 1 FROM thread th WHERE th.utid = {tbl}.utid)) \
                         FROM {tbl}"
                    ),
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .context("Failed to count orphan network utids")?;
            total_count += t;
            orphan_count += o;
            if o > 0 && sample_orphan_ids.len() < 10 {
                let mut stmt = self.conn.prepare(&format!(
                    "SELECT DISTINCT n.utid FROM {tbl} n \
                     WHERE n.utid IS NOT NULL \
                     AND NOT EXISTS (SELECT 1 FROM thread th WHERE th.utid = n.utid) LIMIT 10"
                ))?;
                let rows = stmt.query_map([], |row| row.get::<_, i64>(0))?;
                for row in rows {
                    sample_orphan_ids.push(row?);
                }
            }
        }
        Ok(OrphanCheck {
            orphan_count,
            total_count,
            sample_orphan_ids,
        })
    }

    fn count_empty_process_names(&mut self) -> Result<FieldCheck> {
        if !self.table_exists("process") {
            return Ok(FieldCheck::ok(0));
        }

        // Count total and empty (excluding pid=0)
        let (total_count, empty_count): (i64, i64) = self.conn.query_row(
            "SELECT
                COUNT(*) FILTER (WHERE pid != 0),
                COUNT(*) FILTER (WHERE pid != 0 AND (name IS NULL OR name = ''))
             FROM process",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;

        // Get sample IDs with empty names
        let mut sample_ids = Vec::new();
        if empty_count > 0 {
            let mut stmt = self.conn.prepare(
                "SELECT upid FROM process
                 WHERE pid != 0 AND (name IS NULL OR name = '')
                 LIMIT 10",
            )?;
            let rows = stmt.query_map([], |row| row.get::<_, i64>(0))?;
            for row in rows {
                sample_ids.push(row?);
            }
        }

        Ok(FieldCheck {
            empty_count,
            total_count,
            sample_ids,
        })
    }

    fn count_empty_thread_names(&mut self) -> Result<FieldCheck> {
        if !self.table_exists("thread") {
            return Ok(FieldCheck::ok(0));
        }

        // Count total and empty (excluding tid=0)
        let (total_count, empty_count): (i64, i64) = self.conn.query_row(
            "SELECT
                COUNT(*) FILTER (WHERE tid != 0),
                COUNT(*) FILTER (WHERE tid != 0 AND (name IS NULL OR name = ''))
             FROM thread",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;

        // Get sample IDs with empty names
        let mut sample_ids = Vec::new();
        if empty_count > 0 {
            let mut stmt = self.conn.prepare(
                "SELECT utid FROM thread
                 WHERE tid != 0 AND (name IS NULL OR name = '')
                 LIMIT 10",
            )?;
            let rows = stmt.query_map([], |row| row.get::<_, i64>(0))?;
            for row in rows {
                sample_ids.push(row?);
            }
        }

        Ok(FieldCheck {
            empty_count,
            total_count,
            sample_ids,
        })
    }

    fn find_slice_utid_violations(&mut self) -> Result<FieldCheck> {
        self.find_utid_violations_table("slice")
    }

    fn find_instant_utid_violations(&mut self) -> Result<FieldCheck> {
        self.find_utid_violations_table("instant")
    }

    fn get_cmdline_stats(&mut self) -> Result<CmdlineStats> {
        if !self.table_exists("process") {
            return Ok(CmdlineStats {
                has_column: false,
                empty_count: 0,
                total_count: 0,
            });
        }

        if !self.column_exists("process", "cmdline") {
            return Ok(CmdlineStats {
                has_column: false,
                empty_count: 0,
                total_count: 0,
            });
        }

        // Build filter: exclude pid=0 and kernel threads (if column exists)
        let has_kernel_col = self.column_exists("process", "is_kernel_thread");
        let filter = if has_kernel_col {
            "pid != 0 AND is_kernel_thread = FALSE"
        } else {
            "pid != 0"
        };

        // Count total and empty cmdlines (excluding pid=0 and kernel threads)
        let (total_count, empty_count): (i64, i64) = self.conn.query_row(
            &format!(
                "SELECT
                    COUNT(*) FILTER (WHERE {filter}),
                    COUNT(*) FILTER (WHERE {filter} AND (cmdline IS NULL OR len(cmdline) = 0))
                 FROM process"
            ),
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;

        Ok(CmdlineStats {
            has_column: true,
            empty_count,
            total_count,
        })
    }

    fn check_end_state_schema(&mut self) -> Result<SchemaResult> {
        if !self.table_exists("sched_slice") {
            return Ok(SchemaResult::missing());
        }

        match self.get_column_type("sched_slice", "end_state") {
            Some(data_type) => {
                let is_integer = is_duckdb_integer_type(&data_type);
                if is_integer {
                    Ok(SchemaResult::valid("INTEGER"))
                } else {
                    Ok(SchemaResult::wrong_type("INTEGER", data_type))
                }
            }
            None => Ok(SchemaResult::missing()),
        }
    }

    fn get_counter_unit_values(&mut self) -> Result<Vec<Option<String>>> {
        if !self.table_exists("counter_track") || !self.column_exists("counter_track", "unit") {
            return Ok(Vec::new());
        }

        let mut values = Vec::new();
        let mut stmt = self
            .conn
            .prepare("SELECT DISTINCT unit FROM counter_track")?;
        let rows = stmt.query_map([], |row| row.get::<_, Option<String>>(0))?;
        for row in rows {
            values.push(row?);
        }

        Ok(values)
    }

    fn find_stack_timing_violations(&mut self, tolerance_ns: i64) -> Result<Vec<StackViolation>> {
        if !self.table_exists("stack_sample") || !self.table_exists("sched_slice") {
            return Ok(Vec::new());
        }

        if !self.column_exists("stack_sample", "stack_event_type") {
            // Old format without stack_event_type - skip validation
            return Ok(Vec::new());
        }

        let mut violations = Vec::new();

        // Find STACK_SLEEP violations (type=0 uninterruptible, type=2 interruptible)
        // Should be near the end of a sleep slice (end_state != 0)
        let mut stmt = self.conn.prepare(&format!(
            "WITH first_sched AS (
                SELECT utid, MIN(ts) as first_ts FROM sched_slice GROUP BY utid
            )
            SELECT ss.ts, ss.utid, ss.stack_event_type,
                   'STACK_SLEEP not near sleep slice end' as message
            FROM stack_sample ss
            JOIN first_sched fs ON ss.utid = fs.utid
            WHERE ss.stack_event_type IN (0, 2)  -- STACK_SLEEP_UNINTERRUPTIBLE or STACK_SLEEP_INTERRUPTIBLE
            AND ss.ts >= fs.first_ts  -- Only check samples after first sched event
            AND NOT EXISTS (
                SELECT 1 FROM sched_slice s
                WHERE s.utid = ss.utid
                AND s.end_state IS NOT NULL AND s.end_state != 0  -- Sleep state
                AND ABS(ss.ts - (s.ts + s.dur)) <= {tolerance_ns}  -- Near slice end
            )
            LIMIT 50"
        ))?;

        let rows = stmt.query_map([], |row| {
            Ok(StackViolation {
                ts: row.get(0)?,
                utid: row.get(1)?,
                event_type: row.get(2)?,
                message: row.get(3)?,
            })
        })?;

        for row in rows {
            violations.push(row?);
        }

        // Find STACK_RUNNING violations (type=1)
        // Should be within a running slice
        let mut stmt = self.conn.prepare(
            "WITH first_sched AS (
                SELECT utid, MIN(ts) as first_ts FROM sched_slice GROUP BY utid
            )
            SELECT ss.ts, ss.utid, ss.stack_event_type,
                   'STACK_RUNNING not within slice' as message
            FROM stack_sample ss
            JOIN first_sched fs ON ss.utid = fs.utid
            WHERE ss.stack_event_type = 1  -- STACK_RUNNING
            AND ss.ts >= fs.first_ts  -- Only check samples after first sched event
            AND NOT EXISTS (
                SELECT 1 FROM sched_slice s
                WHERE s.utid = ss.utid
                AND ss.ts >= s.ts AND ss.ts < s.ts + s.dur  -- Within slice
            )
            LIMIT 50",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(StackViolation {
                ts: row.get(0)?,
                utid: row.get(1)?,
                event_type: row.get(2)?,
                message: row.get(3)?,
            })
        })?;

        for row in rows {
            violations.push(row?);
        }

        Ok(violations)
    }

    fn check_tpu_metrics(&mut self) -> Result<Option<TpuMetricCheck>> {
        if !self.table_exists("tpu_metric") {
            return Ok(None);
        }

        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM tpu_metric", [], |row| row.get(0))
            .unwrap_or(0);

        if count == 0 {
            return Ok(None);
        }

        let mut check = TpuMetricCheck {
            total_count: count,
            ..Default::default()
        };

        check.bad_timestamp_count = self
            .conn
            .query_row("SELECT COUNT(*) FROM tpu_metric WHERE ts <= 0", [], |row| {
                row.get(0)
            })
            .unwrap_or(0);

        check.empty_name_count = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM tpu_metric WHERE metric_name IS NULL OR metric_name = ''",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);

        check.non_finite_value_count = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM tpu_metric WHERE isnan(value) OR isinf(value)",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);

        check.negative_device_id_count = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM tpu_metric WHERE device_id < 0",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);

        Ok(Some(check))
    }
}

/// Check if a DuckDB type is an integer type.
fn is_duckdb_integer_type(data_type: &str) -> bool {
    let upper = data_type.to_uppercase();
    // DuckDB integer types: TINYINT, SMALLINT, INTEGER, BIGINT, HUGEINT
    // Also INT, INT2, INT4, INT8 aliases
    upper == "INTEGER"
        || upper == "INT"
        || upper == "INT4"
        || upper == "BIGINT"
        || upper == "INT8"
        || upper == "SMALLINT"
        || upper == "INT2"
        || upper == "TINYINT"
        || upper == "HUGEINT"
}

// ============================================================================
// Entry Point
// ============================================================================

/// Validate a DuckDB database for trace data correctness.
///
/// This function performs the same validation checks as `validate_parquet_dir` but
/// operates on a DuckDB database instead of Parquet files. It checks:
///
/// - Schema correctness (column types)
/// - Reference integrity (foreign key relationships)
/// - Required field validation (non-null constraints)
/// - Stack timing validation (stack samples occur at valid times)
///
/// # Arguments
///
/// * `db_path` - Path to the DuckDB database file
pub fn validate_duckdb(db_path: &Path) -> ValidationResult {
    let mut result = ValidationResult::default();

    // Use the unified validation framework
    let mut queries = match DuckDbQueries::new(db_path) {
        Ok(q) => q,
        Err(e) => {
            result.add_error(ValidationError::ReadError {
                table: "database".to_string(),
                message: format!("Failed to open DuckDB database: {e}"),
            });
            return result;
        }
    };

    let config = ValidationConfig::default();
    run_common_validations(&mut queries, &config, &mut result);

    // DuckDB-specific validation: Check required tables exist and end_state data quality
    let conn = match Connection::open(db_path) {
        Ok(c) => c,
        Err(_) => return result, // Already reported error above
    };

    validate_duckdb_required_tables(&conn, &mut result);
    validate_duckdb_sched_slice_end_state(&conn, &mut result);

    result
}

/// Validate that required DuckDB tables exist.
fn validate_duckdb_required_tables(conn: &Connection, result: &mut ValidationResult) {
    const REQUIRED_TABLES: &[&str] = &["process", "thread", "sched_slice"];

    for &table in REQUIRED_TABLES {
        let exists: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM information_schema.tables WHERE table_name = ?",
                [table],
                |row| row.get(0),
            )
            .unwrap_or(false);

        if !exists {
            result.add_error(ValidationError::MissingFile {
                table: table.to_string(),
                path: format!("table '{table}' not found in database"),
            });
        }
    }
}

/// Validate sched_slice.end_state data quality in DuckDB.
fn validate_duckdb_sched_slice_end_state(conn: &Connection, result: &mut ValidationResult) {
    // First check if the end_state column exists
    let column_exists: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM information_schema.columns
             WHERE table_name = 'sched_slice' AND column_name = 'end_state'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(false);

    if !column_exists {
        // Already handled by schema validation
        return;
    }

    // Get total row count and non-null count
    let counts: std::result::Result<(i64, i64), _> = conn.query_row(
        "SELECT COUNT(*), COUNT(end_state) FROM sched_slice",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    );

    match counts {
        Ok((total, non_null)) => {
            // Warn if there are rows but ALL end_states are NULL.
            // In a healthy trace, only the last slice per CPU should have NULL end_state
            // (because there's no subsequent switch to determine why it left).
            // If every single row is NULL, it indicates switch_prev_state was not extracted.
            if total > 0 && non_null == 0 {
                result.add_warning(ValidationWarning::AllNullColumn {
                    table: "sched_slice".to_string(),
                    column: "end_state".to_string(),
                    total_rows: total,
                });
            }
        }
        Err(_) => {
            // Query failed - table might be empty, which is fine
        }
    }
}
