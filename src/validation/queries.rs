//! Validation query trait and result types.
//!
//! This module defines the `ValidationQueries` trait that all format-specific
//! query providers must implement. The trait abstracts validation queries
//! rather than data access, allowing each format to use its native query mechanism.

use anyhow::Result;

/// Stack event type: captured when task went to uninterruptible sleep.
pub const STACK_SLEEP_UNINTERRUPTIBLE: i8 = 0;

/// Stack event type: captured while task was running (CPU sampling, probes).
pub const STACK_RUNNING: i8 = 1;

/// Stack event type: captured when task went to interruptible sleep.
pub const STACK_SLEEP_INTERRUPTIBLE: i8 = 2;

/// Trait for validation queries - each format implements using its native mechanism.
///
/// # Implementation Notes
/// - **Perfetto**: Must compute all answers in a single streaming pass. Cache results
///   internally and return from query methods.
/// - **Parquet**: Consider caching ID sets (upid, utid) on first access to avoid
///   re-reading files for multiple queries.
/// - **DuckDB**: Use SQL queries directly - pushdown is efficient.
///
/// Note: Methods use `&mut self` to allow implementations to cache results
/// (e.g., Parquet caching ID sets on first access).
pub trait ValidationQueries {
    /// Returns the format name for error messages (e.g., "parquet", "duckdb", "perfetto").
    fn format_name(&self) -> &'static str;

    // === Reference Integrity Queries ===

    /// Count threads with non-NULL upid values not found in process table.
    /// NULL upid is expected (kernel threads), not an orphan.
    ///
    /// Note: For Perfetto traces, this always returns `OrphanCheck::ok(0)` because
    /// Perfetto uses track hierarchies instead of upid/utid references. Reference
    /// integrity for Perfetto is validated through `validate_parent_uuid_hierarchy`.
    fn count_orphan_thread_upids(&mut self) -> Result<OrphanCheck>;

    /// Count sched_slices with utid values not found in thread table.
    ///
    /// Note: For Perfetto traces, this always returns `OrphanCheck::ok(0)` because
    /// Perfetto compact_sched uses pids directly, not utids.
    fn count_orphan_sched_utids(&mut self) -> Result<OrphanCheck>;

    // === Required Field Queries ===

    /// Count processes with empty/null names (excluding pid=0 kernel process).
    fn count_empty_process_names(&mut self) -> Result<FieldCheck>;

    /// Count threads with empty/null names (excluding tid=0 swapper).
    fn count_empty_thread_names(&mut self) -> Result<FieldCheck>;

    /// Get cmdline population statistics.
    fn get_cmdline_stats(&mut self) -> Result<CmdlineStats>;

    // === Schema Queries ===

    /// Check if end_state column exists and has integer type.
    fn check_end_state_schema(&mut self) -> Result<SchemaResult>;

    /// Get counter_track unit values for validation.
    /// Valid values: "", "count", "time_ns", "size_bytes", "Hz"
    fn get_counter_unit_values(&mut self) -> Result<Vec<Option<String>>>;

    // === Stack Timing Queries ===

    /// Find stack samples that occur outside valid sched slices.
    /// - STACK_SLEEP_UNINTERRUPTIBLE (0): Should be at/near end of a sleep slice
    /// - STACK_RUNNING (1): Should be within a running slice
    /// - STACK_SLEEP_INTERRUPTIBLE (2): Should be at/near end of a sleep slice
    fn find_stack_timing_violations(&mut self, tolerance_ns: i64) -> Result<Vec<StackViolation>>;
}

/// Result of reference integrity check - includes sample IDs for debugging.
#[derive(Debug, Default)]
pub struct OrphanCheck {
    /// Number of orphaned references found.
    pub orphan_count: i64,
    /// Total number of records checked.
    pub total_count: i64,
    /// First 10 orphan IDs for error messages.
    pub sample_orphan_ids: Vec<i64>,
}

impl OrphanCheck {
    /// Create an OrphanCheck with no orphans.
    pub fn ok(total_count: i64) -> Self {
        Self {
            orphan_count: 0,
            total_count,
            sample_orphan_ids: Vec::new(),
        }
    }

    /// Returns true if there are any orphans.
    pub fn has_orphans(&self) -> bool {
        self.orphan_count > 0
    }
}

/// Result of field population check - includes sample IDs for debugging.
#[derive(Debug, Default)]
pub struct FieldCheck {
    /// Number of records with empty/null values.
    pub empty_count: i64,
    /// Total number of records checked.
    pub total_count: i64,
    /// First 10 IDs with empty values for error messages.
    pub sample_ids: Vec<i64>,
}

impl FieldCheck {
    /// Create a FieldCheck with no empty values.
    pub fn ok(total_count: i64) -> Self {
        Self {
            empty_count: 0,
            total_count,
            sample_ids: Vec::new(),
        }
    }

    /// Returns true if there are any empty values.
    pub fn has_empty(&self) -> bool {
        self.empty_count > 0
    }
}

/// Cmdline population statistics.
#[derive(Debug, Default)]
pub struct CmdlineStats {
    /// Whether the cmdline column exists.
    pub has_column: bool,
    /// Number of records with empty/null cmdline.
    pub empty_count: i64,
    /// Total number of records (excluding pid=0).
    pub total_count: i64,
}

impl CmdlineStats {
    /// Returns the percentage of records with empty cmdline.
    pub fn empty_percentage(&self) -> f64 {
        if self.total_count == 0 {
            0.0
        } else {
            (self.empty_count as f64 / self.total_count as f64) * 100.0
        }
    }

    /// Returns true if more than half of records have empty cmdline.
    pub fn mostly_empty(&self) -> bool {
        self.total_count > 0 && self.empty_count * 2 > self.total_count
    }
}

/// Result of schema check.
#[derive(Debug)]
pub struct SchemaResult {
    /// Whether the column exists.
    pub exists: bool,
    /// Whether the column has a valid type.
    pub type_valid: bool,
    /// Expected type name.
    pub expected_type: &'static str,
    /// Actual type name (if column exists).
    pub actual_type: Option<String>,
}

impl SchemaResult {
    /// Create a result for a missing column.
    pub fn missing() -> Self {
        Self {
            exists: false,
            type_valid: false,
            expected_type: "",
            actual_type: None,
        }
    }

    /// Create a result for a column with correct type.
    pub fn valid(expected: &'static str) -> Self {
        Self {
            exists: true,
            type_valid: true,
            expected_type: expected,
            actual_type: Some(expected.to_string()),
        }
    }

    /// Create a result for a column with incorrect type.
    pub fn wrong_type(expected: &'static str, actual: String) -> Self {
        Self {
            exists: true,
            type_valid: false,
            expected_type: expected,
            actual_type: Some(actual),
        }
    }

    /// Returns true if the schema is valid (column exists with correct type).
    pub fn is_valid(&self) -> bool {
        self.exists && self.type_valid
    }
}

/// A stack timing violation.
#[derive(Debug)]
pub struct StackViolation {
    /// Timestamp of the stack sample.
    pub ts: i64,
    /// Unique thread ID.
    pub utid: i64,
    /// Event type: 0=STACK_SLEEP_UNINTERRUPTIBLE, 1=STACK_RUNNING, 2=STACK_SLEEP_INTERRUPTIBLE.
    pub event_type: i8,
    /// Description of the violation.
    pub message: String,
}
