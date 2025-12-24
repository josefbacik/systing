//! Trace validation module.
//!
//! This module provides validation for Parquet trace files and Perfetto protobuf traces.
//! It checks for schema correctness, reference integrity, and data consistency.
//!
//! # Example
//!
//! ```no_run
//! use systing::validate::{validate_parquet_dir, ValidationResult};
//! use std::path::Path;
//!
//! let result = validate_parquet_dir(Path::new("./traces"));
//! if result.has_errors() {
//!     for error in &result.errors {
//!         eprintln!("Error: {}", error);
//!     }
//! }
//! ```

use anyhow::{bail, Context, Result};
use arrow::array::Array;
use arrow::datatypes::DataType;
use flate2::read::GzDecoder;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use perfetto_protos::trace_packet::TracePacket;
use protobuf::Message;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

use crate::parquet_paths::ParquetPaths;

/// Minimum number of sched events required before validating swapper/idle presence.
/// Traces with fewer events may legitimately have no idle time if the system was busy.
const MIN_SCHED_EVENTS_FOR_SWAPPER_VALIDATION: u64 = 1000;

/// Result of validating a trace.
#[derive(Debug, Default)]
pub struct ValidationResult {
    /// Errors that indicate invalid trace data.
    pub errors: Vec<ValidationError>,
    /// Warnings that indicate potential issues.
    pub warnings: Vec<ValidationWarning>,
}

impl ValidationResult {
    /// Returns true if there are any validation errors.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    /// Returns true if there are any validation warnings.
    #[must_use]
    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }

    /// Returns true if the trace is valid (no errors).
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }

    /// Add an error to the result.
    pub fn add_error(&mut self, error: ValidationError) {
        self.errors.push(error);
    }

    /// Add a warning to the result.
    pub fn add_warning(&mut self, warning: ValidationWarning) {
        self.warnings.push(warning);
    }
}

/// Validation error types.
#[derive(Debug)]
pub enum ValidationError {
    /// A column has the wrong data type.
    WrongColumnType {
        table: String,
        column: String,
        expected: String,
        got: String,
    },
    /// An enum column contains an invalid value.
    InvalidEnumValue {
        table: String,
        column: String,
        value: String,
    },
    /// A foreign key reference is invalid (referenced row doesn't exist).
    MissingReference {
        table: String,
        column: String,
        value: i64,
        referenced_table: String,
    },
    /// A column contains a value outside the valid range.
    InvalidValue {
        table: String,
        column: String,
        message: String,
    },
    /// A required file is missing.
    MissingFile { table: String, path: String },
    /// Failed to read a file.
    ReadError { table: String, message: String },
    /// Perfetto trace structure error.
    PerfettoError { message: String },
    /// Cross-validation error between Parquet and Perfetto.
    CrossValidationError { message: String },
    /// Stack sample timing violation - stack captured at invalid time.
    StackTimingViolation {
        ts: i64,
        utid: i64,
        stack_event_type: i8,
        message: String,
    },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::WrongColumnType {
                table,
                column,
                expected,
                got,
            } => {
                write!(f, "{table}.{column}: expected type {expected}, got {got}")
            }
            ValidationError::InvalidEnumValue {
                table,
                column,
                value,
            } => {
                write!(f, "{table}.{column}: invalid enum value '{value}'")
            }
            ValidationError::MissingReference {
                table,
                column,
                value,
                referenced_table,
            } => {
                write!(
                    f,
                    "{table}.{column}: value {value} not found in {referenced_table}.{column}"
                )
            }
            ValidationError::InvalidValue {
                table,
                column,
                message,
            } => {
                write!(f, "{table}.{column}: {message}")
            }
            ValidationError::MissingFile { table, path } => {
                write!(f, "{table}: file not found: {path}")
            }
            ValidationError::ReadError { table, message } => {
                write!(f, "{table}: read error: {message}")
            }
            ValidationError::PerfettoError { message } => {
                write!(f, "Perfetto: {message}")
            }
            ValidationError::CrossValidationError { message } => {
                write!(f, "Cross-validation: {message}")
            }
            ValidationError::StackTimingViolation {
                ts,
                utid,
                stack_event_type,
                message,
            } => {
                let type_str = if *stack_event_type == 0 {
                    "STACK_SLEEP"
                } else {
                    "STACK_RUNNING"
                };
                write!(
                    f,
                    "Stack timing: utid={utid} ts={ts} type={type_str}: {message}"
                )
            }
        }
    }
}

/// Validation warning types.
#[derive(Debug)]
pub enum ValidationWarning {
    /// A file is empty (no rows).
    EmptyTable { table: String },
    /// An optional column is missing.
    MissingColumn { table: String, column: String },
    /// Too many errors of the same type - only showing first N.
    TooManyErrors { table: String, shown: usize },
}

impl fmt::Display for ValidationWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationWarning::EmptyTable { table } => {
                write!(f, "{table}: table is empty")
            }
            ValidationWarning::MissingColumn { table, column } => {
                write!(f, "{table}.{column}: optional column missing")
            }
            ValidationWarning::TooManyErrors { table, shown } => {
                write!(f, "{table}: showing first {shown} errors, more exist")
            }
        }
    }
}

/// Validate a Parquet trace directory.
///
/// Checks:
/// - Schema correctness (column types)
/// - Reference integrity (foreign keys)
/// - Data validity (ranges, enum values)
/// - Required fields are set (names not empty)
pub fn validate_parquet_dir(dir: &Path) -> ValidationResult {
    let mut result = ValidationResult::default();
    let paths = ParquetPaths::new(dir);

    // Phase 1: Schema validation
    validate_sched_slice_schema(&paths, &mut result);
    validate_thread_state_schema(&paths, &mut result);
    validate_counter_track_schema(&paths, &mut result);

    // Phase 2: Reference integrity
    let process_upids = collect_process_upids(&paths, &mut result);
    let thread_utids = collect_thread_utids(&paths, &mut result);

    validate_thread_upid_refs(&paths, &process_upids, &mut result);
    validate_sched_utid_refs(&paths, &thread_utids, &mut result);

    // Phase 3: Required field validation
    validate_process_names(&paths, &mut result);
    validate_thread_names(&paths, &mut result);

    // Phase 4: Stack timing validation
    validate_stack_timing(&paths, &mut result);

    result
}

/// Collect end_state value counts from sched_slice.parquet for cross-validation.
///
/// Returns a HashMap of end_state value -> count.
/// NULL values are counted as 0 (TASK_RUNNING/preempted).
fn collect_end_state_counts(paths: &ParquetPaths) -> anyhow::Result<HashMap<i64, u64>> {
    let mut counts: HashMap<i64, u64> = HashMap::new();
    let path = &paths.sched_slice;

    if !path.exists() {
        return Ok(counts);
    }

    let file = File::open(path)?;
    let builder = ParquetRecordBatchReaderBuilder::try_new(file)?;
    let reader = builder.build()?;

    for batch_result in reader {
        let batch = batch_result?;
        let schema = batch.schema();
        let end_state_idx = match schema.index_of("end_state") {
            Ok(idx) => idx,
            Err(_) => continue,
        };

        let end_state_array = batch.column(end_state_idx);
        if let Some(int_array) = end_state_array
            .as_any()
            .downcast_ref::<arrow::array::Int32Array>()
        {
            for i in 0..int_array.len() {
                let state = if int_array.is_null(i) {
                    0 // NULL = TASK_RUNNING (preempted)
                } else {
                    int_array.value(i) as i64
                };
                *counts.entry(state).or_insert(0) += 1;
            }
        }
    }

    Ok(counts)
}

/// Count stack samples in Parquet.
fn count_parquet_stack_samples(paths: &ParquetPaths) -> anyhow::Result<u64> {
    let path = &paths.stack_sample;
    if !path.exists() {
        return Ok(0);
    }

    let file = File::open(path)?;
    let builder = ParquetRecordBatchReaderBuilder::try_new(file)?;
    let reader = builder.build()?;

    let mut count = 0u64;
    for batch_result in reader {
        let batch = batch_result?;
        count += batch.num_rows() as u64;
    }

    Ok(count)
}

/// Cross-validate Parquet and Perfetto trace files.
///
/// This function validates that the conversion from Parquet to Perfetto
/// preserved the thread state information correctly by comparing:
/// - The end_state distribution in sched_slice.parquet
/// - The prev_state distribution in Perfetto's compact_sched
///
/// The distributions should match closely. Discrepancies may indicate
/// bugs in the Parquet-to-Perfetto conversion (e.g., incorrect prev_state assignment).
///
/// Note: The first sched_switch on each CPU has prev_state=0 regardless of
/// the actual end_state, so we expect some difference in the count of 0 values.
pub fn cross_validate_parquet_perfetto(
    parquet_dir: &Path,
    perfetto_path: &Path,
) -> ValidationResult {
    let mut result = ValidationResult::default();

    // Collect end_state counts from Parquet
    let paths = ParquetPaths::new(parquet_dir);
    let parquet_counts = match collect_end_state_counts(&paths) {
        Ok(counts) => counts,
        Err(e) => {
            result.add_error(ValidationError::CrossValidationError {
                message: format!("Failed to read sched_slice.parquet: {e}"),
            });
            return result;
        }
    };

    if parquet_counts.is_empty() {
        result.add_warning(ValidationWarning::EmptyTable {
            table: "sched_slice".to_string(),
        });
        return result;
    }

    // Collect prev_state counts from Perfetto
    let reader = match open_trace_reader(perfetto_path) {
        Ok(r) => r,
        Err(e) => {
            result.add_error(ValidationError::CrossValidationError {
                message: format!("Failed to open Perfetto trace: {e}"),
            });
            return result;
        }
    };

    let mut perfetto_counts: HashMap<i64, u64> = HashMap::new();
    let mut cpus_with_switches: HashSet<u32> = HashSet::new();
    let mut skipped_packets = 0u64;
    let mut perfetto_perf_sample_count = 0u64;

    for packet_result in TracePacketIterator::new(reader) {
        let packet = match packet_result {
            Ok(p) => p,
            Err(_) => {
                skipped_packets += 1;
                continue;
            }
        };

        if packet.has_ftrace_events() {
            let events = packet.ftrace_events();
            if let Some(compact) = events.compact_sched.as_ref() {
                if !compact.switch_prev_state.is_empty() {
                    // Track unique CPUs, not packets
                    cpus_with_switches.insert(events.cpu());
                }
                for &prev_state in &compact.switch_prev_state {
                    *perfetto_counts.entry(prev_state).or_insert(0) += 1;
                }
            }
        }

        // Count PerfSample packets for stack sample cross-validation
        if packet.has_perf_sample() {
            perfetto_perf_sample_count += 1;
        }
    }

    // Warn about skipped packets
    if skipped_packets > 0 {
        result.add_warning(ValidationWarning::MissingColumn {
            table: "Perfetto".to_string(),
            column: format!("{skipped_packets} packets failed to parse"),
        });
    }

    if perfetto_counts.is_empty() {
        result.add_warning(ValidationWarning::MissingColumn {
            table: "compact_sched".to_string(),
            column: "switch_prev_state".to_string(),
        });
        return result;
    }

    let num_cpus = cpus_with_switches.len() as u64;

    // Cross-validate the distributions using aggregate difference for non-zero states.
    // The first switch on each CPU has prev_state=0 forced, so:
    // - Perfetto should have approximately `num_cpus` MORE zeros than Parquet
    // - Perfetto should have approximately `num_cpus` FEWER non-zero states (in total)

    // Calculate aggregate difference for non-zero states
    // Parquet should have more non-zero states than Perfetto by approximately num_cpus
    let mut total_nonzero_parquet: u64 = 0;
    let mut total_nonzero_perfetto: u64 = 0;

    let mut all_states: HashSet<i64> = HashSet::new();
    all_states.extend(parquet_counts.keys());
    all_states.extend(perfetto_counts.keys());

    for &state in &all_states {
        let parquet_count = parquet_counts.get(&state).copied().unwrap_or(0);
        let perfetto_count = perfetto_counts.get(&state).copied().unwrap_or(0);

        if state != 0 {
            total_nonzero_parquet += parquet_count;
            total_nonzero_perfetto += perfetto_count;
        }
    }

    // Check aggregate non-zero difference
    // Parquet should have approximately num_cpus more non-zero states
    let nonzero_diff = total_nonzero_parquet.abs_diff(total_nonzero_perfetto);
    let tolerance = num_cpus * 2; // Allow 2x tolerance

    if nonzero_diff > tolerance && total_nonzero_perfetto > total_nonzero_parquet {
        // Perfetto has MORE non-zero states than Parquet - this is wrong
        result.add_error(ValidationError::CrossValidationError {
            message: format!(
                "Aggregate non-zero state mismatch: Perfetto has {total_nonzero_perfetto} \
                 non-zero prev_states but Parquet has {total_nonzero_parquet} non-zero end_states. \
                 Expected Parquet to have more (by ~{num_cpus} CPUs). \
                 This may indicate incorrect prev_state assignment in conversion."
            ),
        });
    }

    // Check state=0 specifically
    let parquet_zero = parquet_counts.get(&0).copied().unwrap_or(0);
    let perfetto_zero = perfetto_counts.get(&0).copied().unwrap_or(0);

    if perfetto_zero < parquet_zero {
        // Perfetto should have MORE zeros, not fewer
        result.add_error(ValidationError::CrossValidationError {
            message: format!(
                "State 0 (TASK_RUNNING): Perfetto has fewer ({perfetto_zero}) than \
                 Parquet ({parquet_zero}). Expected Perfetto to have more due to \
                 first-switch-per-CPU adjustment."
            ),
        });
    } else {
        // Check that the excess is reasonable (approximately num_cpus)
        let zero_excess = perfetto_zero - parquet_zero;
        if zero_excess.abs_diff(num_cpus) > num_cpus * 2 {
            result.add_warning(ValidationWarning::MissingColumn {
                table: "cross-validation".to_string(),
                column: format!(
                    "State 0 excess ({zero_excess}) differs significantly from expected ({num_cpus} CPUs)"
                ),
            });
        }
    }

    // Cross-validate stack sample counts
    let parquet_stack_sample_count = match count_parquet_stack_samples(&paths) {
        Ok(count) => count,
        Err(e) => {
            result.add_warning(ValidationWarning::MissingColumn {
                table: "stack_sample".to_string(),
                column: format!("Failed to count: {e}"),
            });
            0
        }
    };

    if (parquet_stack_sample_count > 0 || perfetto_perf_sample_count > 0)
        && parquet_stack_sample_count != perfetto_perf_sample_count
    {
        result.add_error(ValidationError::CrossValidationError {
            message: format!(
                "Stack sample count mismatch: Parquet has {parquet_stack_sample_count} \
                 but Perfetto has {perfetto_perf_sample_count} PerfSample packets"
            ),
        });
    }

    result
}

/// Validate sched_slice.parquet schema.
fn validate_sched_slice_schema(paths: &ParquetPaths, result: &mut ValidationResult) {
    let path = &paths.sched_slice;

    if !path.exists() {
        // sched_slice is a core table, so this is an error
        result.add_error(ValidationError::MissingFile {
            table: "sched_slice".to_string(),
            path: path.display().to_string(),
        });
        return;
    }

    match check_column_type(path, "end_state", DataType::Int32) {
        Ok(true) => {}
        Ok(false) => {
            // Column exists but wrong type - get the actual type
            if let Ok(Some(actual)) = get_column_type(path, "end_state") {
                result.add_error(ValidationError::WrongColumnType {
                    table: "sched_slice".to_string(),
                    column: "end_state".to_string(),
                    expected: "Int32".to_string(),
                    got: format!("{actual:?}"),
                });
            }
        }
        Err(e) => {
            result.add_error(ValidationError::ReadError {
                table: "sched_slice".to_string(),
                message: e.to_string(),
            });
        }
    }
}

/// Validate thread_state.parquet schema.
fn validate_thread_state_schema(paths: &ParquetPaths, result: &mut ValidationResult) {
    let path = &paths.thread_state;

    if !path.exists() {
        // thread_state might not exist in all traces
        return;
    }

    match check_column_type(path, "state", DataType::Int32) {
        Ok(true) => {}
        Ok(false) => {
            if let Ok(Some(actual)) = get_column_type(path, "state") {
                result.add_error(ValidationError::WrongColumnType {
                    table: "thread_state".to_string(),
                    column: "state".to_string(),
                    expected: "Int32".to_string(),
                    got: format!("{actual:?}"),
                });
            }
        }
        Err(e) => {
            result.add_error(ValidationError::ReadError {
                table: "thread_state".to_string(),
                message: e.to_string(),
            });
        }
    }
}

/// Validate counter_track.parquet schema and values.
fn validate_counter_track_schema(paths: &ParquetPaths, result: &mut ValidationResult) {
    let path = &paths.counter_track;

    if !path.exists() {
        // counter_track might not exist in all traces
        return;
    }

    // The unit column should be Utf8 (string)
    match check_column_type(path, "unit", DataType::Utf8) {
        Ok(true) => {
            // Check that unit values are valid
            validate_counter_track_unit_values(path, result);
        }
        Ok(false) => {
            if let Ok(Some(actual)) = get_column_type(path, "unit") {
                result.add_error(ValidationError::WrongColumnType {
                    table: "counter_track".to_string(),
                    column: "unit".to_string(),
                    expected: "Utf8".to_string(),
                    got: format!("{actual:?}"),
                });
            }
        }
        Err(e) => {
            result.add_error(ValidationError::ReadError {
                table: "counter_track".to_string(),
                message: e.to_string(),
            });
        }
    }
}

/// Valid counter unit values (from perfetto_protos CounterDescriptor::Unit and custom units).
const VALID_COUNTER_UNITS: &[&str] = &["", "count", "time_ns", "size_bytes", "Hz"];

/// Validate counter_track.unit values are in the known set.
fn validate_counter_track_unit_values(path: &Path, result: &mut ValidationResult) {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            result.add_error(ValidationError::ReadError {
                table: "counter_track".to_string(),
                message: e.to_string(),
            });
            return;
        }
    };

    let builder = match ParquetRecordBatchReaderBuilder::try_new(file) {
        Ok(b) => b,
        Err(e) => {
            result.add_error(ValidationError::ReadError {
                table: "counter_track".to_string(),
                message: e.to_string(),
            });
            return;
        }
    };

    let reader = match builder.build() {
        Ok(r) => r,
        Err(e) => {
            result.add_error(ValidationError::ReadError {
                table: "counter_track".to_string(),
                message: e.to_string(),
            });
            return;
        }
    };

    for batch_result in reader {
        let batch = match batch_result {
            Ok(b) => b,
            Err(e) => {
                result.add_error(ValidationError::ReadError {
                    table: "counter_track".to_string(),
                    message: e.to_string(),
                });
                continue;
            }
        };

        let schema = batch.schema();
        let unit_idx = match schema.index_of("unit") {
            Ok(idx) => idx,
            Err(_) => continue, // Column might be missing in some schemas
        };

        let unit_array = batch.column(unit_idx);
        if let Some(string_array) = unit_array
            .as_any()
            .downcast_ref::<arrow::array::StringArray>()
        {
            for i in 0..string_array.len() {
                if string_array.is_null(i) {
                    continue;
                }
                let value = string_array.value(i);
                if !VALID_COUNTER_UNITS.contains(&value) {
                    result.add_error(ValidationError::InvalidEnumValue {
                        table: "counter_track".to_string(),
                        column: "unit".to_string(),
                        value: value.to_string(),
                    });
                    // Only report the first invalid value to avoid flooding
                    return;
                }
            }
        }
    }
}

/// Check if a column has the expected data type.
fn check_column_type(path: &Path, column: &str, expected: DataType) -> anyhow::Result<bool> {
    let actual = get_column_type(path, column)?;
    Ok(actual.as_ref() == Some(&expected))
}

/// Get the data type of a column in a Parquet file.
fn get_column_type(path: &Path, column: &str) -> anyhow::Result<Option<DataType>> {
    let file = File::open(path)?;
    let builder = ParquetRecordBatchReaderBuilder::try_new(file)?;
    let schema = builder.schema();

    for field in schema.fields() {
        if field.name() == column {
            return Ok(Some(field.data_type().clone()));
        }
    }

    Ok(None)
}

/// Collect all upid values from process.parquet.
fn collect_process_upids(paths: &ParquetPaths, result: &mut ValidationResult) -> HashSet<i64> {
    let mut upids = HashSet::new();
    let path = &paths.process;

    if !path.exists() {
        result.add_error(ValidationError::MissingFile {
            table: "process".to_string(),
            path: path.display().to_string(),
        });
        return upids;
    }

    if let Err(e) = collect_i64_column(path, "upid", &mut upids) {
        result.add_error(ValidationError::ReadError {
            table: "process".to_string(),
            message: e.to_string(),
        });
    }

    if upids.is_empty() {
        result.add_warning(ValidationWarning::EmptyTable {
            table: "process".to_string(),
        });
    }

    upids
}

/// Collect all utid values from thread.parquet.
fn collect_thread_utids(paths: &ParquetPaths, result: &mut ValidationResult) -> HashSet<i64> {
    let mut utids = HashSet::new();
    let path = &paths.thread;

    if !path.exists() {
        result.add_error(ValidationError::MissingFile {
            table: "thread".to_string(),
            path: path.display().to_string(),
        });
        return utids;
    }

    if let Err(e) = collect_i64_column(path, "utid", &mut utids) {
        result.add_error(ValidationError::ReadError {
            table: "thread".to_string(),
            message: e.to_string(),
        });
    }

    if utids.is_empty() {
        result.add_warning(ValidationWarning::EmptyTable {
            table: "thread".to_string(),
        });
    }

    utids
}

/// Validate that all thread.upid values reference valid process.upid values.
fn validate_thread_upid_refs(
    paths: &ParquetPaths,
    valid_upids: &HashSet<i64>,
    result: &mut ValidationResult,
) {
    let path = &paths.thread;

    if !path.exists() {
        return;
    }

    if valid_upids.is_empty() {
        // No processes to check against
        return;
    }

    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            result.add_error(ValidationError::ReadError {
                table: "thread".to_string(),
                message: e.to_string(),
            });
            return;
        }
    };

    let builder = match ParquetRecordBatchReaderBuilder::try_new(file) {
        Ok(b) => b,
        Err(e) => {
            result.add_error(ValidationError::ReadError {
                table: "thread".to_string(),
                message: e.to_string(),
            });
            return;
        }
    };

    let reader = match builder.build() {
        Ok(r) => r,
        Err(e) => {
            result.add_error(ValidationError::ReadError {
                table: "thread".to_string(),
                message: e.to_string(),
            });
            return;
        }
    };

    for batch_result in reader {
        let batch = match batch_result {
            Ok(b) => b,
            Err(e) => {
                result.add_error(ValidationError::ReadError {
                    table: "thread".to_string(),
                    message: e.to_string(),
                });
                continue;
            }
        };

        let schema = batch.schema();
        let upid_idx = match schema.index_of("upid") {
            Ok(idx) => idx,
            Err(_) => continue,
        };

        let upid_array = batch.column(upid_idx);
        if let Some(int_array) = upid_array
            .as_any()
            .downcast_ref::<arrow::array::Int64Array>()
        {
            for i in 0..int_array.len() {
                if int_array.is_null(i) {
                    continue; // upid is nullable
                }
                let upid = int_array.value(i);
                if !valid_upids.contains(&upid) {
                    result.add_error(ValidationError::MissingReference {
                        table: "thread".to_string(),
                        column: "upid".to_string(),
                        value: upid,
                        referenced_table: "process".to_string(),
                    });
                    // Only report the first invalid reference to avoid flooding
                    return;
                }
            }
        }
    }
}

/// Validate that all sched_slice.utid values reference valid thread.utid values.
fn validate_sched_utid_refs(
    paths: &ParquetPaths,
    valid_utids: &HashSet<i64>,
    result: &mut ValidationResult,
) {
    let path = &paths.sched_slice;

    if !path.exists() {
        return;
    }

    if valid_utids.is_empty() {
        // No threads to check against
        return;
    }

    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            result.add_error(ValidationError::ReadError {
                table: "sched_slice".to_string(),
                message: e.to_string(),
            });
            return;
        }
    };

    let builder = match ParquetRecordBatchReaderBuilder::try_new(file) {
        Ok(b) => b,
        Err(e) => {
            result.add_error(ValidationError::ReadError {
                table: "sched_slice".to_string(),
                message: e.to_string(),
            });
            return;
        }
    };

    let reader = match builder.build() {
        Ok(r) => r,
        Err(e) => {
            result.add_error(ValidationError::ReadError {
                table: "sched_slice".to_string(),
                message: e.to_string(),
            });
            return;
        }
    };

    for batch_result in reader {
        let batch = match batch_result {
            Ok(b) => b,
            Err(e) => {
                result.add_error(ValidationError::ReadError {
                    table: "sched_slice".to_string(),
                    message: e.to_string(),
                });
                continue;
            }
        };

        let schema = batch.schema();
        let utid_idx = match schema.index_of("utid") {
            Ok(idx) => idx,
            Err(_) => continue,
        };

        let utid_array = batch.column(utid_idx);
        if let Some(int_array) = utid_array
            .as_any()
            .downcast_ref::<arrow::array::Int64Array>()
        {
            for i in 0..int_array.len() {
                if int_array.is_null(i) {
                    continue;
                }
                let utid = int_array.value(i);
                if !valid_utids.contains(&utid) {
                    result.add_error(ValidationError::MissingReference {
                        table: "sched_slice".to_string(),
                        column: "utid".to_string(),
                        value: utid,
                        referenced_table: "thread".to_string(),
                    });
                    // Only report the first invalid reference to avoid flooding
                    return;
                }
            }
        }
    }
}

/// Validate that all name values in a table are set (not null and not empty).
///
/// # Arguments
/// * `path` - Path to the parquet file
/// * `table` - Name of the table (for error messages)
/// * `id_column` - Name of the ID column (e.g., "upid" or "utid")
/// * `entity` - Name of the entity type (e.g., "process" or "thread")
/// * `result` - Validation result to add errors to
fn validate_names_not_empty(
    path: &Path,
    table: &str,
    id_column: &str,
    entity: &str,
    result: &mut ValidationResult,
) {
    if !path.exists() {
        return;
    }

    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            result.add_error(ValidationError::ReadError {
                table: table.to_string(),
                message: e.to_string(),
            });
            return;
        }
    };

    let builder = match ParquetRecordBatchReaderBuilder::try_new(file) {
        Ok(b) => b,
        Err(e) => {
            result.add_error(ValidationError::ReadError {
                table: table.to_string(),
                message: e.to_string(),
            });
            return;
        }
    };

    let reader = match builder.build() {
        Ok(r) => r,
        Err(e) => {
            result.add_error(ValidationError::ReadError {
                table: table.to_string(),
                message: e.to_string(),
            });
            return;
        }
    };

    for batch_result in reader {
        let batch = match batch_result {
            Ok(b) => b,
            Err(e) => {
                result.add_error(ValidationError::ReadError {
                    table: table.to_string(),
                    message: e.to_string(),
                });
                continue;
            }
        };

        let schema = batch.schema();
        let name_idx = match schema.index_of("name") {
            Ok(idx) => idx,
            Err(_) => continue, // Column might be missing
        };
        let id_idx = match schema.index_of(id_column) {
            Ok(idx) => idx,
            Err(_) => continue,
        };

        let name_array = batch.column(name_idx);
        let id_array = batch.column(id_idx);

        if let (Some(string_array), Some(int_array)) = (
            name_array
                .as_any()
                .downcast_ref::<arrow::array::StringArray>(),
            id_array.as_any().downcast_ref::<arrow::array::Int64Array>(),
        ) {
            for i in 0..string_array.len() {
                let id_value = if int_array.is_null(i) {
                    -1
                } else {
                    int_array.value(i)
                };

                if string_array.is_null(i) {
                    result.add_error(ValidationError::InvalidValue {
                        table: table.to_string(),
                        column: "name".to_string(),
                        message: format!("{entity} name is null ({id_column}={id_value})"),
                    });
                    return;
                }

                let value = string_array.value(i);
                if value.is_empty() {
                    result.add_error(ValidationError::InvalidValue {
                        table: table.to_string(),
                        column: "name".to_string(),
                        message: format!("{entity} name is empty ({id_column}={id_value})"),
                    });
                    return;
                }
            }
        }
    }
}

/// Validate that all process.name values are set (not null and not empty).
fn validate_process_names(paths: &ParquetPaths, result: &mut ValidationResult) {
    validate_names_not_empty(&paths.process, "process", "upid", "process", result);
}

/// Validate that all thread.name values are set (not null and not empty).
fn validate_thread_names(paths: &ParquetPaths, result: &mut ValidationResult) {
    validate_names_not_empty(&paths.thread, "thread", "utid", "thread", result);
}

/// Sched slice info for stack timing validation.
#[derive(Clone)]
struct SchedSliceInfo {
    ts: i64,
    dur: i64,
    end_state: Option<i32>,
}

/// Tolerance for timestamp comparisons (10 microseconds in nanoseconds).
/// This accounts for the slight delay between sched_switch and stack capture events.
/// Note: Under heavy system load or virtualized systems, this may need to be increased.
const STACK_TIMING_TOLERANCE_NS: i64 = 10_000;

/// Stack event type: captured when task went to sleep (blocking).
const STACK_SLEEP: i8 = 0;
/// Stack event type: captured while task was running (CPU sampling, probes).
const STACK_RUNNING: i8 = 1;

/// Load sched_slice data indexed by utid for efficient lookup.
fn load_sched_slices_by_utid(path: &Path) -> anyhow::Result<HashMap<i64, Vec<SchedSliceInfo>>> {
    let mut slices: HashMap<i64, Vec<SchedSliceInfo>> = HashMap::new();

    if !path.exists() {
        return Ok(slices);
    }

    let file = File::open(path)?;
    let builder = ParquetRecordBatchReaderBuilder::try_new(file)?;
    let reader = builder.build()?;

    for batch_result in reader {
        let batch = batch_result?;
        let schema = batch.schema();

        let ts_idx = schema.index_of("ts")?;
        let dur_idx = schema.index_of("dur")?;
        let utid_idx = schema.index_of("utid")?;
        let end_state_idx = schema.index_of("end_state")?;

        let ts_array = batch
            .column(ts_idx)
            .as_any()
            .downcast_ref::<arrow::array::Int64Array>()
            .context("ts column not Int64")?;
        let dur_array = batch
            .column(dur_idx)
            .as_any()
            .downcast_ref::<arrow::array::Int64Array>()
            .context("dur column not Int64")?;
        let utid_array = batch
            .column(utid_idx)
            .as_any()
            .downcast_ref::<arrow::array::Int64Array>()
            .context("utid column not Int64")?;
        let end_state_array = batch
            .column(end_state_idx)
            .as_any()
            .downcast_ref::<arrow::array::Int32Array>()
            .context("end_state column not Int32")?;

        for i in 0..batch.num_rows() {
            let utid = utid_array.value(i);
            let slice = SchedSliceInfo {
                ts: ts_array.value(i),
                dur: dur_array.value(i),
                end_state: if end_state_array.is_null(i) {
                    None
                } else {
                    Some(end_state_array.value(i))
                },
            };
            slices.entry(utid).or_default().push(slice);
        }
    }

    // Sort slices by timestamp for binary search
    for slices_vec in slices.values_mut() {
        slices_vec.sort_by_key(|s| s.ts);
    }

    Ok(slices)
}

/// Stack sample info for validation.
struct StackSampleInfo {
    ts: i64,
    utid: i64,
    stack_event_type: i8,
}

/// Load stack_sample data for validation.
fn load_stack_samples(path: &Path) -> anyhow::Result<Vec<StackSampleInfo>> {
    let mut samples = Vec::new();

    if !path.exists() {
        return Ok(samples);
    }

    let file = File::open(path)?;
    let builder = ParquetRecordBatchReaderBuilder::try_new(file)?;
    let reader = builder.build()?;

    for batch_result in reader {
        let batch = batch_result?;
        let schema = batch.schema();

        let ts_idx = schema.index_of("ts")?;
        let utid_idx = schema.index_of("utid")?;
        let stack_event_type_idx = match schema.index_of("stack_event_type") {
            Ok(idx) => idx,
            Err(_) => {
                // Old traces without stack_event_type - skip validation
                return Ok(Vec::new());
            }
        };

        let ts_array = batch
            .column(ts_idx)
            .as_any()
            .downcast_ref::<arrow::array::Int64Array>()
            .context("ts column not Int64")?;
        let utid_array = batch
            .column(utid_idx)
            .as_any()
            .downcast_ref::<arrow::array::Int64Array>()
            .context("utid column not Int64")?;
        let stack_event_type_array = batch
            .column(stack_event_type_idx)
            .as_any()
            .downcast_ref::<arrow::array::Int8Array>()
            .context("stack_event_type column not Int8")?;

        for i in 0..batch.num_rows() {
            samples.push(StackSampleInfo {
                ts: ts_array.value(i),
                utid: utid_array.value(i),
                stack_event_type: stack_event_type_array.value(i),
            });
        }
    }

    Ok(samples)
}

/// Find the sched slice that contains or is closest to the given timestamp.
/// Returns (slice, is_within_slice) where is_within_slice indicates if ts is inside the slice.
fn find_closest_slice(slices: &[SchedSliceInfo], ts: i64) -> Option<(&SchedSliceInfo, bool)> {
    if slices.is_empty() {
        return None;
    }

    // Binary search to find the first slice with ts > sample.ts
    let idx = slices.partition_point(|s| s.ts <= ts);

    if idx == 0 {
        // ts is before first slice - check if it's within tolerance of first slice start
        let slice = &slices[0];
        let is_within = ts >= slice.ts && ts < slice.ts + slice.dur;
        return Some((slice, is_within));
    }

    // Check the slice just before the partition point
    let prev_slice = &slices[idx - 1];
    let is_within = ts >= prev_slice.ts && ts < prev_slice.ts + prev_slice.dur;

    Some((prev_slice, is_within))
}

/// Validate stack sample timing constraints.
///
/// Stack samples should only occur at valid times:
/// - STACK_SLEEP (0): At the end of a sched_slice when task went to sleep
/// - STACK_RUNNING (1): Within a sched_slice when task was on CPU
///
/// Violations indicate bugs in the BPF capture logic or data corruption.
fn validate_stack_timing(paths: &ParquetPaths, result: &mut ValidationResult) {
    // Load sched_slice data indexed by utid
    let slices_by_utid = match load_sched_slices_by_utid(&paths.sched_slice) {
        Ok(slices) => slices,
        Err(e) => {
            result.add_error(ValidationError::ReadError {
                table: "sched_slice".to_string(),
                message: format!("Failed to load sched_slice: {e}"),
            });
            return;
        }
    };

    if slices_by_utid.is_empty() {
        // No scheduling data - can't validate
        return;
    }

    // Load stack samples
    let samples = match load_stack_samples(&paths.stack_sample) {
        Ok(samples) => samples,
        Err(e) => {
            result.add_error(ValidationError::ReadError {
                table: "stack_sample".to_string(),
                message: format!("Failed to load stack_sample: {e}"),
            });
            return;
        }
    };

    if samples.is_empty() {
        // No stack samples to validate
        return;
    }

    // Validate each stack sample
    let mut violation_count = 0;
    const MAX_VIOLATIONS_TO_REPORT: usize = 10;

    for sample in &samples {
        let slices = match slices_by_utid.get(&sample.utid) {
            Some(s) => s,
            None => {
                // No scheduling data for this utid - skip (could be kernel thread, etc.)
                continue;
            }
        };

        let closest = find_closest_slice(slices, sample.ts);

        let (is_valid, message) = match (sample.stack_event_type, closest) {
            // STACK_SLEEP: should be at/near the end of a sleep slice
            (STACK_SLEEP, Some((slice, _))) => {
                let slice_end = slice.ts + slice.dur;
                let is_sleep_state = slice.end_state.is_some() && slice.end_state != Some(0);
                let delta = sample.ts - slice_end;
                let is_at_end = delta.abs() <= STACK_TIMING_TOLERANCE_NS;
                if is_sleep_state && is_at_end {
                    (true, String::new())
                } else if !is_sleep_state {
                    (
                        false,
                        format!(
                            "STACK_SLEEP but slice end_state={:?} (not sleep); slice=[{}, {})",
                            slice.end_state, slice.ts, slice_end
                        ),
                    )
                } else {
                    (
                        false,
                        format!(
                            "STACK_SLEEP delta={}ns exceeds tolerance; slice=[{}, {})",
                            delta, slice.ts, slice_end
                        ),
                    )
                }
            }
            // STACK_RUNNING: should be within a running slice
            (STACK_RUNNING, Some((slice, is_within))) => {
                let slice_end = slice.ts + slice.dur;
                if is_within && slice.dur > 0 {
                    (true, String::new())
                } else {
                    (
                        false,
                        format!(
                            "STACK_RUNNING not within slice; slice=[{}, {}), sample_ts={}",
                            slice.ts, slice_end, sample.ts
                        ),
                    )
                }
            }
            // Known types but no slice found
            (STACK_SLEEP | STACK_RUNNING, None) => {
                (false, "No sched_slice found for this utid".to_string())
            }
            // Unknown stack_event_type
            (unknown, _) => (false, format!("Unknown stack_event_type: {unknown}")),
        };

        if !is_valid && violation_count < MAX_VIOLATIONS_TO_REPORT {
            result.add_error(ValidationError::StackTimingViolation {
                ts: sample.ts,
                utid: sample.utid,
                stack_event_type: sample.stack_event_type,
                message,
            });
            violation_count += 1;
        }
    }

    if violation_count >= MAX_VIOLATIONS_TO_REPORT {
        // Add a warning that there are more violations
        result.add_warning(ValidationWarning::TooManyErrors {
            table: "stack_sample".to_string(),
            shown: MAX_VIOLATIONS_TO_REPORT,
        });
    }
}

/// Collect all values from an Int64 column into a HashSet.
fn collect_i64_column(path: &Path, column: &str, set: &mut HashSet<i64>) -> anyhow::Result<()> {
    let file = File::open(path)?;
    let builder = ParquetRecordBatchReaderBuilder::try_new(file)?;
    let reader = builder.build()?;

    for batch_result in reader {
        let batch = batch_result?;
        let schema = batch.schema();
        let idx = schema.index_of(column)?;

        let array = batch.column(idx);
        if let Some(int_array) = array.as_any().downcast_ref::<arrow::array::Int64Array>() {
            for i in 0..int_array.len() {
                if !int_array.is_null(i) {
                    set.insert(int_array.value(i));
                }
            }
        }
    }

    Ok(())
}

// ============================================================================
// Perfetto Trace Validation
// ============================================================================

/// Validate a Perfetto trace file (.pb or .pb.gz).
///
/// Checks:
/// - All TracePackets parse correctly
/// - Track UUIDs are defined before being referenced
/// - Parent UUIDs form a valid tree
/// - CompactSched intern table bounds
/// - At least one ClockSnapshot exists
pub fn validate_perfetto_trace(path: &Path) -> ValidationResult {
    let mut result = ValidationResult::default();

    let reader = match open_trace_reader(path) {
        Ok(r) => r,
        Err(e) => {
            result.add_error(ValidationError::PerfettoError {
                message: format!("Failed to open trace file: {e}"),
            });
            return result;
        }
    };

    let mut context = PerfettoValidationContext::default();

    for packet_result in TracePacketIterator::new(reader) {
        match packet_result {
            Ok(packet) => {
                validate_packet(&packet, &mut context, &mut result);
            }
            Err(e) => {
                result.add_error(ValidationError::PerfettoError {
                    message: format!("Failed to parse packet: {e}"),
                });
                // Continue to try to parse more packets
            }
        }
    }

    // Post-processing validations
    validate_track_uuid_refs(&context, &mut result);
    validate_parent_uuid_hierarchy(&context, &mut result);
    validate_clock_snapshot_exists(&context, &mut result);
    validate_system_info_exists(&context, &mut result);
    validate_network_syscalls_on_network_tracks(&context, &mut result);
    validate_socket_tracks_have_socket_id(&context, &mut result);
    validate_swapper_thread_names(&context, &mut result);

    result
}

/// Context for Perfetto trace validation.
#[derive(Default)]
struct PerfettoValidationContext {
    /// All defined track UUIDs
    defined_tracks: HashSet<u64>,
    /// Track UUIDs referenced by events (track_uuid -> first timestamp seen)
    referenced_tracks: HashMap<u64, u64>,
    /// Parent UUID references (child_uuid -> parent_uuid)
    parent_refs: HashMap<u64, u64>,
    /// Track UUIDs that have ThreadDescriptor or ProcessDescriptor (per-thread tracks)
    thread_process_tracks: HashSet<u64>,
    /// Track names (track_uuid -> name)
    track_names: HashMap<u64, String>,
    /// Network syscall events that need to be on per-thread tracks
    /// Maps (track_uuid, event_name) -> timestamp for deferred validation
    network_syscall_events: HashMap<(u64, String), u64>,
    /// Whether we've seen a clock snapshot
    has_clock_snapshot: bool,
    /// Whether we've seen valid SystemInfo with utsname
    has_valid_system_info: bool,
    /// Counts of prev_state values from compact_sched.
    /// Used by cross_validate_parquet_perfetto() to compare with sched_slice.end_state.
    prev_state_counts: HashMap<i64, u64>,
    /// Track which CPUs we've seen first switch events for
    cpus_seen_first_switch: HashSet<u32>,
    /// UUID of the "Network Packets" root track, if present
    network_packets_root_uuid: Option<u64>,
    /// Comm strings seen for pid=0 (swapper/idle) in sched events.
    /// Maps comm_string -> count. Used to detect when idle events are
    /// incorrectly attributed to other threads (e.g., migration threads).
    pid_zero_comms: HashMap<String, u64>,
}

/// Validate a single TracePacket.
fn validate_packet(
    packet: &TracePacket,
    context: &mut PerfettoValidationContext,
    result: &mut ValidationResult,
) {
    // Check for clock snapshot
    if packet.has_clock_snapshot() {
        context.has_clock_snapshot = true;
    }

    // Check for track descriptors
    if packet.has_track_descriptor() {
        let desc = packet.track_descriptor();
        let uuid = desc.uuid();

        context.defined_tracks.insert(uuid);

        // Store track name if present
        if desc.has_name() {
            let name = desc.name().to_string();
            // Track the "Network Packets" root track UUID
            if name == "Network Packets" {
                context.network_packets_root_uuid = Some(uuid);
            }
            context.track_names.insert(uuid, name);
        }

        // Check parent UUID
        if desc.has_parent_uuid() {
            let parent_uuid = desc.parent_uuid();
            context.parent_refs.insert(uuid, parent_uuid);
        }

        // Check ThreadDescriptor: pid should not equal tid
        // When pid == tid, it's the main thread and should use ProcessDescriptor instead
        if let Some(thread) = desc.thread.as_ref() {
            // Track this as a thread/process track for network event validation
            context.thread_process_tracks.insert(uuid);

            if thread.has_pid() && thread.has_tid() && thread.pid() == thread.tid() {
                result.add_error(ValidationError::PerfettoError {
                    message: format!(
                        "ThreadDescriptor (track_uuid={}) has pid == tid ({}), main threads \
                         should use ProcessDescriptor instead",
                        uuid,
                        thread.pid()
                    ),
                });
            }

            // Check that thread_name is set and not empty
            if !thread.has_thread_name() || thread.thread_name().is_empty() {
                result.add_error(ValidationError::PerfettoError {
                    message: format!(
                        "ThreadDescriptor (track_uuid={}, tid={}) has empty or missing thread_name",
                        uuid,
                        thread.tid()
                    ),
                });
            }
        }

        // Check ProcessDescriptor: process_name should be set and not empty
        if let Some(process) = desc.process.as_ref() {
            // Track this as a thread/process track for network event validation
            context.thread_process_tracks.insert(uuid);

            if !process.has_process_name() || process.process_name().is_empty() {
                result.add_error(ValidationError::PerfettoError {
                    message: format!(
                        "ProcessDescriptor (track_uuid={}, pid={}) has empty or missing process_name",
                        uuid,
                        process.pid()
                    ),
                });
            }
        }
    }

    // Check for track events
    if packet.has_track_event() {
        let event = packet.track_event();
        if event.has_track_uuid() {
            let track_uuid = event.track_uuid();
            let ts = packet.timestamp();
            context.referenced_tracks.entry(track_uuid).or_insert(ts);

            // Check if this is a network syscall or poll event
            // These should be on per-thread/process tracks
            // Note: Only checking for event types actually emitted by network_recorder.rs
            let is_network_syscall = event.categories.iter().any(|c| c == "network")
                && event.has_name()
                && matches!(event.name(), "sendmsg" | "recvmsg" | "poll");

            if is_network_syscall {
                // Track this event for deferred validation
                // We validate after all packets are processed since track descriptors
                // may come after events in the trace
                let event_name = event.name().to_string();
                context
                    .network_syscall_events
                    .entry((track_uuid, event_name))
                    .or_insert(ts);
            }
        }
    }

    // Check for ftrace events with CompactSched
    if packet.has_ftrace_events() {
        let events = packet.ftrace_events();
        if events.compact_sched.is_some() {
            let cpu = events.cpu();
            validate_compact_sched(events.compact_sched.as_ref().unwrap(), cpu, context, result);
        }
    }

    // Check for PerfSample with invalid pid/tid
    if packet.has_perf_sample() {
        let sample = packet.perf_sample();
        // Only validate if both fields are explicitly set
        if sample.has_pid() && sample.has_tid() && sample.pid() == 0 && sample.tid() == 0 {
            result.add_error(ValidationError::PerfettoError {
                message: format!(
                    "PerfSample has both pid and tid set to 0 (timestamp={})",
                    packet.timestamp()
                ),
            });
        }
    }

    // Check for SystemInfo with valid utsname
    // Note: We use "first valid wins" semantics - once we've seen a valid SystemInfo,
    // we don't report errors for subsequent invalid ones. This handles traces that
    // might have multiple SystemInfo packets.
    if packet.has_system_info() && !context.has_valid_system_info {
        let system_info = packet.system_info();
        if let Some(utsname) = system_info.utsname.as_ref() {
            // Validate that all required utsname fields are set.
            // Note: We don't validate nodename as it contains the hostname,
            // which may be intentionally omitted for privacy reasons.
            let mut missing_fields = Vec::new();

            if !utsname.has_sysname() || utsname.sysname().is_empty() {
                missing_fields.push("sysname");
            }
            if !utsname.has_release() || utsname.release().is_empty() {
                missing_fields.push("release");
            }
            if !utsname.has_version() || utsname.version().is_empty() {
                missing_fields.push("version");
            }
            if !utsname.has_machine() || utsname.machine().is_empty() {
                missing_fields.push("machine");
            }

            if missing_fields.is_empty() {
                context.has_valid_system_info = true;
            } else {
                result.add_error(ValidationError::PerfettoError {
                    message: format!(
                        "SystemInfo.utsname is missing required fields: {}",
                        missing_fields.join(", ")
                    ),
                });
            }
        } else {
            result.add_error(ValidationError::PerfettoError {
                message: "SystemInfo.utsname is not set".to_string(),
            });
        }
    }
}

/// Validate CompactSched structure.
fn validate_compact_sched(
    compact: &perfetto_protos::ftrace_event_bundle::ftrace_event_bundle::CompactSched,
    cpu: u32,
    context: &mut PerfettoValidationContext,
    result: &mut ValidationResult,
) {
    let intern_len = compact.intern_table.len();

    // Validate switch_next_comm_index values are in bounds
    // If intern_table is empty but indices exist, that's still an error
    for (i, &comm_index) in compact.switch_next_comm_index.iter().enumerate() {
        if intern_len == 0 || (comm_index as usize) >= intern_len {
            result.add_error(ValidationError::PerfettoError {
                message: format!(
                    "CompactSched: switch_next_comm_index[{i}] = {comm_index} \
                     is out of bounds (intern_table.len = {intern_len})"
                ),
            });
            // Only report first error
            return;
        }
    }

    // Validate waking_comm_index values are in bounds
    for (i, &comm_index) in compact.waking_comm_index.iter().enumerate() {
        if intern_len == 0 || (comm_index as usize) >= intern_len {
            result.add_error(ValidationError::PerfettoError {
                message: format!(
                    "CompactSched: waking_comm_index[{i}] = {comm_index} \
                     is out of bounds (intern_table.len = {intern_len})"
                ),
            });
            // Only report first error
            return;
        }
    }

    // Validate first switch on each CPU has prev_state=0 (unknown at trace start).
    // If the first switch has a non-zero prev_state like 1 (interruptible) or 2 (uninterruptible),
    // it suggests the prev_state values may be incorrectly assigned (e.g., using the current
    // task's end_state instead of the previous task's end_state).
    if !compact.switch_prev_state.is_empty() && !context.cpus_seen_first_switch.contains(&cpu) {
        context.cpus_seen_first_switch.insert(cpu);
        let first_prev_state = compact.switch_prev_state[0];
        if first_prev_state != 0 {
            result.add_error(ValidationError::PerfettoError {
                message: format!(
                    "CompactSched CPU {cpu}: first switch has prev_state={first_prev_state}, \
                     expected 0 (at trace start, previous task state is unknown). \
                     This may indicate incorrect prev_state assignment in Parquet to Perfetto conversion."
                ),
            });
        }
    }

    // Collect prev_state distribution for cross-validation
    for &prev_state in &compact.switch_prev_state {
        *context.prev_state_counts.entry(prev_state).or_insert(0) += 1;
    }

    // Collect comm strings for pid=0 (swapper/idle) events.
    // This helps detect when idle time is incorrectly attributed to other threads.
    for (i, &next_pid) in compact.switch_next_pid.iter().enumerate() {
        if next_pid == 0 {
            let comm_idx = compact.switch_next_comm_index.get(i).copied().unwrap_or(0) as usize;
            let comm = compact
                .intern_table
                .get(comm_idx)
                .map(String::as_str)
                .unwrap_or("");
            *context.pid_zero_comms.entry(comm.to_string()).or_insert(0) += 1;
        }
    }
}

/// Validate that all referenced track UUIDs have been defined.
fn validate_track_uuid_refs(context: &PerfettoValidationContext, result: &mut ValidationResult) {
    for track_uuid in context.referenced_tracks.keys() {
        if !context.defined_tracks.contains(track_uuid) {
            result.add_error(ValidationError::PerfettoError {
                message: format!("TrackEvent references undefined track_uuid {track_uuid}"),
            });
            // Only report first error
            return;
        }
    }
}

/// Validate that parent_uuid references form a valid tree (no orphans or cycles).
fn validate_parent_uuid_hierarchy(
    context: &PerfettoValidationContext,
    result: &mut ValidationResult,
) {
    // Check for undefined parent references
    for (child_uuid, parent_uuid) in &context.parent_refs {
        if !context.defined_tracks.contains(parent_uuid) {
            result.add_error(ValidationError::PerfettoError {
                message: format!(
                    "TrackDescriptor {child_uuid} has parent_uuid {parent_uuid} \
                     which is not defined"
                ),
            });
            // Only report first error
            return;
        }
    }

    // Check for cycles in the parent hierarchy
    for start_uuid in context.parent_refs.keys() {
        let mut visited = HashSet::new();
        let mut current = *start_uuid;

        while let Some(&parent) = context.parent_refs.get(&current) {
            if !visited.insert(current) {
                // We've seen this node before - there's a cycle
                result.add_error(ValidationError::PerfettoError {
                    message: format!(
                        "Cycle detected in track parent hierarchy involving track {current}"
                    ),
                });
                return;
            }
            current = parent;
        }
    }
}

/// Validate that at least one ClockSnapshot exists.
fn validate_clock_snapshot_exists(
    context: &PerfettoValidationContext,
    result: &mut ValidationResult,
) {
    if !context.has_clock_snapshot {
        result.add_error(ValidationError::PerfettoError {
            message: "No ClockSnapshot packet found in trace".to_string(),
        });
    }
}

/// Validate that SystemInfo with valid utsname exists.
fn validate_system_info_exists(context: &PerfettoValidationContext, result: &mut ValidationResult) {
    if !context.has_valid_system_info {
        result.add_error(ValidationError::PerfettoError {
            message: "No SystemInfo packet with valid utsname found in trace".to_string(),
        });
    }
}

/// Validate that network syscall events (poll, sendmsg, recvmsg) are on dedicated "Network" tracks.
///
/// Network syscall events should be placed on tracks with names like "Network" or "Network (tid X)"
/// that are parented to thread/process tracks. This ensures proper visualization in Perfetto UI
/// where syscalls appear on dedicated network tracks under thread timelines.
fn validate_network_syscalls_on_network_tracks(
    context: &PerfettoValidationContext,
    result: &mut ValidationResult,
) {
    for ((track_uuid, event_name), ts) in &context.network_syscall_events {
        // Check that the track has a name
        let track_name = match context.track_names.get(track_uuid) {
            Some(name) => name,
            None => {
                result.add_error(ValidationError::PerfettoError {
                    message: format!(
                        "Network syscall event '{event_name}' (track_uuid={track_uuid}, ts={ts}) is on a track without a name. \
                         Network syscall events should be placed on tracks named 'Network' or 'Network (tid N)'."
                    ),
                });
                continue;
            }
        };

        // Check that the track name is exactly "Network" or "Network (tid N)"
        // Use a strict pattern to avoid matching unrelated track names like "NetworkBroken"
        let is_valid_network_track =
            track_name == "Network" || track_name.starts_with("Network (tid ");
        if !is_valid_network_track {
            result.add_error(ValidationError::PerfettoError {
                message: format!(
                    "Network syscall event '{event_name}' (track_uuid={track_uuid}, ts={ts}) is on track '{track_name}'. \
                     Network syscall events should be placed on tracks named 'Network' or 'Network (tid N)', \
                     not directly on thread/process tracks."
                ),
            });
            continue;
        }

        // Check that the track is parented to a thread/process track
        if let Some(&parent_uuid) = context.parent_refs.get(track_uuid) {
            if !context.thread_process_tracks.contains(&parent_uuid) {
                result.add_error(ValidationError::PerfettoError {
                    message: format!(
                        "Network syscall event '{event_name}' (track_uuid={track_uuid}, ts={ts}) is on track '{track_name}' \
                         which is not parented to a thread/process track. \
                         Network tracks should be children of ThreadDescriptor or ProcessDescriptor tracks."
                    ),
                });
            }
        } else {
            result.add_error(ValidationError::PerfettoError {
                message: format!(
                    "Network syscall event '{event_name}' (track_uuid={track_uuid}, ts={ts}) is on track '{track_name}' \
                     which has no parent. Network tracks should be parented to thread/process tracks."
                ),
            });
        }
    }
}

/// Validate that socket tracks under "Network Packets" include the socket_id in their name.
///
/// Socket tracks should be named like "Socket N:..." or "Socket N" where N is the socket_id.
/// This ensures that socket tracks can be correlated with socket_id annotations on syscall events.
fn validate_socket_tracks_have_socket_id(
    context: &PerfettoValidationContext,
    result: &mut ValidationResult,
) {
    // If there's no "Network Packets" root track, nothing to validate
    let Some(network_packets_uuid) = context.network_packets_root_uuid else {
        return;
    };

    // Find all tracks that are direct children of "Network Packets"
    for (track_uuid, parent_uuid) in &context.parent_refs {
        if *parent_uuid != network_packets_uuid {
            continue;
        }

        // Get the track name
        let Some(track_name) = context.track_names.get(track_uuid) else {
            result.add_error(ValidationError::PerfettoError {
                message: format!(
                    "Socket track (track_uuid={track_uuid}) under 'Network Packets' has no name"
                ),
            });
            continue;
        };

        // Socket tracks should start with "Socket " followed by the socket_id
        // Valid formats: "Socket 123:TCP:..." or "Socket 123" (fallback)
        if !track_name.starts_with("Socket ") {
            result.add_error(ValidationError::PerfettoError {
                message: format!(
                    "Socket track '{track_name}' under 'Network Packets' must start with \
                     'Socket N:...' where N is the socket_id (track_uuid={track_uuid})"
                ),
            });
        }
    }
}

/// Validate that pid=0 (swapper/idle) sched events exist and have appropriate comm strings.
///
/// In a correctly converted trace, sched events with next_pid=0 should have comm
/// strings like "swapper", "swapper/N" (where N is the CPU number), or empty.
/// If they have comm strings like "migration/N", it indicates that idle time
/// is being incorrectly attributed to migration threads instead of the idle thread.
///
/// Additionally, if there are NO pid=0 events at all but we have sched data,
/// it likely indicates a utid mapping collision bug where swapper events are
/// being attributed to other threads.
fn validate_swapper_thread_names(
    context: &PerfettoValidationContext,
    result: &mut ValidationResult,
) {
    // Calculate total sched events from prev_state_counts
    let total_sched_events: u64 = context.prev_state_counts.values().sum();

    // If we have sched events but NO pid=0 events, that's suspicious
    if context.pid_zero_comms.is_empty() {
        if total_sched_events > MIN_SCHED_EVENTS_FOR_SWAPPER_VALIDATION {
            // Only report if we have a reasonable amount of sched data
            result.add_error(ValidationError::PerfettoError {
                message: format!(
                    "No sched events with next_pid=0 (swapper/idle) found, but trace has \
                     {total_sched_events} total sched events. This indicates idle time is \
                     missing or being incorrectly attributed to other threads \
                     (likely a utid mapping collision from ProcessDescriptor handling for pid=0)."
                ),
            });
        }
        return;
    }

    // Check for incorrect comm strings for pid=0 events
    let mut invalid_comms: Vec<(String, u64)> = Vec::new();
    let mut total_pid_zero_events: u64 = 0;

    for (comm, count) in &context.pid_zero_comms {
        total_pid_zero_events += count;

        // Valid comm strings for pid=0 (swapper/idle):
        // - "swapper" or "swapper/N" (CPU-specific idle threads)
        // - Empty string (legacy format)
        // - "<idle>" (some traces use this)
        let is_valid = comm.is_empty()
            || comm == "swapper"
            || comm.starts_with("swapper/")
            || comm == "<idle>";

        if !is_valid {
            invalid_comms.push((comm.clone(), *count));
        }
    }

    // If we have invalid comms, report an error
    if !invalid_comms.is_empty() {
        // Sort by count descending to show the most common offenders first
        invalid_comms.sort_by(|a, b| b.1.cmp(&a.1));

        let invalid_count: u64 = invalid_comms.iter().map(|(_, c)| c).sum();
        let invalid_percent = if total_pid_zero_events > 0 {
            (invalid_count as f64 / total_pid_zero_events as f64) * 100.0
        } else {
            0.0
        };

        // Format the top offenders for the error message
        let top_offenders: Vec<String> = invalid_comms
            .iter()
            .take(5)
            .map(|(comm, count)| format!("'{comm}' ({count} events)"))
            .collect();

        result.add_error(ValidationError::PerfettoError {
            message: format!(
                "Idle thread (pid=0) has incorrect comm strings in {invalid_count}/{total_pid_zero_events} \
                 sched events ({invalid_percent:.1}%). Expected 'swapper' or 'swapper/N', \
                 but found: {}. This indicates idle time is being incorrectly attributed \
                 to other threads (regression in ProcessDescriptor handling for pid=0).",
                top_offenders.join(", ")
            ),
        });
    }
}

// ============================================================================
// Perfetto Trace Reader
// ============================================================================

/// Iterator that streams TracePackets from a Perfetto trace file.
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
        _ => bail!("Unknown wire type: {wire_type}"),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tempfile::TempDir;

    use arrow::array::{Int32Array, Int64Array, StringBuilder};
    use arrow::datatypes::{Field, Schema};
    use arrow::record_batch::RecordBatch;
    use parquet::arrow::ArrowWriter;
    use parquet::basic::Compression;
    use parquet::file::properties::WriterProperties;

    fn create_test_parquet(
        dir: &Path,
        name: &str,
        schema: Arc<Schema>,
        batch: RecordBatch,
    ) -> std::io::Result<()> {
        let path = dir.join(name);
        let file = File::create(path)?;
        let props = WriterProperties::builder()
            .set_compression(Compression::SNAPPY)
            .build();
        let mut writer = ArrowWriter::try_new(file, schema, Some(props)).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();
        Ok(())
    }

    #[test]
    fn test_valid_sched_slice_schema() {
        let dir = TempDir::new().unwrap();

        // Create sched_slice.parquet with correct schema
        let schema = Arc::new(Schema::new(vec![
            Field::new("ts", DataType::Int64, false),
            Field::new("dur", DataType::Int64, false),
            Field::new("cpu", DataType::Int32, false),
            Field::new("utid", DataType::Int64, false),
            Field::new("end_state", DataType::Int32, true),
            Field::new("priority", DataType::Int32, false),
        ]));

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Int64Array::from(vec![1000])),
                Arc::new(Int64Array::from(vec![100])),
                Arc::new(Int32Array::from(vec![0])),
                Arc::new(Int64Array::from(vec![1])),
                Arc::new(Int32Array::from(vec![Some(0)])),
                Arc::new(Int32Array::from(vec![120])),
            ],
        )
        .unwrap();

        create_test_parquet(dir.path(), "sched_slice.parquet", schema, batch).unwrap();

        // Create minimal process and thread tables
        let process_schema = Arc::new(Schema::new(vec![
            Field::new("upid", DataType::Int64, false),
            Field::new("pid", DataType::Int32, false),
            Field::new("name", DataType::Utf8, true),
            Field::new("parent_upid", DataType::Int64, true),
        ]));

        let mut name_builder = StringBuilder::new();
        name_builder.append_value("test");

        let process_batch = RecordBatch::try_new(
            process_schema.clone(),
            vec![
                Arc::new(Int64Array::from(vec![1])),
                Arc::new(Int32Array::from(vec![1000])),
                Arc::new(name_builder.finish()),
                Arc::new(Int64Array::from(vec![None])),
            ],
        )
        .unwrap();

        create_test_parquet(dir.path(), "process.parquet", process_schema, process_batch).unwrap();

        let thread_schema = Arc::new(Schema::new(vec![
            Field::new("utid", DataType::Int64, false),
            Field::new("tid", DataType::Int32, false),
            Field::new("name", DataType::Utf8, true),
            Field::new("upid", DataType::Int64, true),
        ]));

        let mut name_builder = StringBuilder::new();
        name_builder.append_value("main");

        let thread_batch = RecordBatch::try_new(
            thread_schema.clone(),
            vec![
                Arc::new(Int64Array::from(vec![1])),
                Arc::new(Int32Array::from(vec![1000])),
                Arc::new(name_builder.finish()),
                Arc::new(Int64Array::from(vec![Some(1)])),
            ],
        )
        .unwrap();

        create_test_parquet(dir.path(), "thread.parquet", thread_schema, thread_batch).unwrap();

        let result = validate_parquet_dir(dir.path());
        assert!(
            result.is_valid(),
            "Expected valid result, got errors: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_wrong_end_state_type() {
        let dir = TempDir::new().unwrap();

        // Create sched_slice.parquet with WRONG schema (end_state as Utf8 instead of Int32)
        let schema = Arc::new(Schema::new(vec![
            Field::new("ts", DataType::Int64, false),
            Field::new("dur", DataType::Int64, false),
            Field::new("cpu", DataType::Int32, false),
            Field::new("utid", DataType::Int64, false),
            Field::new("end_state", DataType::Utf8, true), // WRONG TYPE
            Field::new("priority", DataType::Int32, false),
        ]));

        let mut state_builder = StringBuilder::new();
        state_builder.append_value("S");

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Int64Array::from(vec![1000])),
                Arc::new(Int64Array::from(vec![100])),
                Arc::new(Int32Array::from(vec![0])),
                Arc::new(Int64Array::from(vec![1])),
                Arc::new(state_builder.finish()),
                Arc::new(Int32Array::from(vec![120])),
            ],
        )
        .unwrap();

        create_test_parquet(dir.path(), "sched_slice.parquet", schema, batch).unwrap();

        // Create minimal process and thread tables
        let process_schema = Arc::new(Schema::new(vec![
            Field::new("upid", DataType::Int64, false),
            Field::new("pid", DataType::Int32, false),
            Field::new("name", DataType::Utf8, true),
            Field::new("parent_upid", DataType::Int64, true),
        ]));

        let mut name_builder = StringBuilder::new();
        name_builder.append_value("test");

        let process_batch = RecordBatch::try_new(
            process_schema.clone(),
            vec![
                Arc::new(Int64Array::from(vec![1])),
                Arc::new(Int32Array::from(vec![1000])),
                Arc::new(name_builder.finish()),
                Arc::new(Int64Array::from(vec![None])),
            ],
        )
        .unwrap();

        create_test_parquet(dir.path(), "process.parquet", process_schema, process_batch).unwrap();

        let thread_schema = Arc::new(Schema::new(vec![
            Field::new("utid", DataType::Int64, false),
            Field::new("tid", DataType::Int32, false),
            Field::new("name", DataType::Utf8, true),
            Field::new("upid", DataType::Int64, true),
        ]));

        let mut name_builder = StringBuilder::new();
        name_builder.append_value("main");

        let thread_batch = RecordBatch::try_new(
            thread_schema.clone(),
            vec![
                Arc::new(Int64Array::from(vec![1])),
                Arc::new(Int32Array::from(vec![1000])),
                Arc::new(name_builder.finish()),
                Arc::new(Int64Array::from(vec![Some(1)])),
            ],
        )
        .unwrap();

        create_test_parquet(dir.path(), "thread.parquet", thread_schema, thread_batch).unwrap();

        let result = validate_parquet_dir(dir.path());
        assert!(result.has_errors(), "Expected errors for wrong type");
        assert!(result.errors.iter().any(|e| matches!(
            e,
            ValidationError::WrongColumnType {
                table,
                column,
                ..
            } if table == "sched_slice" && column == "end_state"
        )));
    }

    #[test]
    fn test_missing_upid_reference() {
        let dir = TempDir::new().unwrap();

        // Create process.parquet with upid=1
        let process_schema = Arc::new(Schema::new(vec![
            Field::new("upid", DataType::Int64, false),
            Field::new("pid", DataType::Int32, false),
            Field::new("name", DataType::Utf8, true),
            Field::new("parent_upid", DataType::Int64, true),
        ]));

        let mut name_builder = StringBuilder::new();
        name_builder.append_value("test");

        let process_batch = RecordBatch::try_new(
            process_schema.clone(),
            vec![
                Arc::new(Int64Array::from(vec![1])),
                Arc::new(Int32Array::from(vec![1000])),
                Arc::new(name_builder.finish()),
                Arc::new(Int64Array::from(vec![None])),
            ],
        )
        .unwrap();

        create_test_parquet(dir.path(), "process.parquet", process_schema, process_batch).unwrap();

        // Create thread.parquet with upid=999 (doesn't exist in process)
        let thread_schema = Arc::new(Schema::new(vec![
            Field::new("utid", DataType::Int64, false),
            Field::new("tid", DataType::Int32, false),
            Field::new("name", DataType::Utf8, true),
            Field::new("upid", DataType::Int64, true),
        ]));

        let mut name_builder = StringBuilder::new();
        name_builder.append_value("main");

        let thread_batch = RecordBatch::try_new(
            thread_schema.clone(),
            vec![
                Arc::new(Int64Array::from(vec![1])),
                Arc::new(Int32Array::from(vec![1000])),
                Arc::new(name_builder.finish()),
                Arc::new(Int64Array::from(vec![Some(999)])), // Invalid upid reference
            ],
        )
        .unwrap();

        create_test_parquet(dir.path(), "thread.parquet", thread_schema, thread_batch).unwrap();

        // Create sched_slice.parquet
        let sched_schema = Arc::new(Schema::new(vec![
            Field::new("ts", DataType::Int64, false),
            Field::new("dur", DataType::Int64, false),
            Field::new("cpu", DataType::Int32, false),
            Field::new("utid", DataType::Int64, false),
            Field::new("end_state", DataType::Int32, true),
            Field::new("priority", DataType::Int32, false),
        ]));

        let sched_batch = RecordBatch::try_new(
            sched_schema.clone(),
            vec![
                Arc::new(Int64Array::from(vec![1000])),
                Arc::new(Int64Array::from(vec![100])),
                Arc::new(Int32Array::from(vec![0])),
                Arc::new(Int64Array::from(vec![1])),
                Arc::new(Int32Array::from(vec![Some(0)])),
                Arc::new(Int32Array::from(vec![120])),
            ],
        )
        .unwrap();

        create_test_parquet(dir.path(), "sched_slice.parquet", sched_schema, sched_batch).unwrap();

        let result = validate_parquet_dir(dir.path());
        assert!(
            result.has_errors(),
            "Expected errors for missing upid reference"
        );
        assert!(result.errors.iter().any(|e| matches!(
            e,
            ValidationError::MissingReference {
                table,
                column,
                value: 999,
                ..
            } if table == "thread" && column == "upid"
        )));
    }

    #[test]
    fn test_perf_sample_zero_pid_tid() {
        use perfetto_protos::profile_packet::PerfSample;

        let mut context = PerfettoValidationContext::default();
        let mut result = ValidationResult::default();

        // Create a PerfSample with pid=0 and tid=0
        let mut sample = PerfSample::default();
        sample.set_pid(0);
        sample.set_tid(0);

        let mut packet = TracePacket::default();
        packet.set_perf_sample(sample);

        validate_packet(&packet, &mut context, &mut result);

        assert!(result.has_errors(), "Expected error for pid=0 and tid=0");
        assert!(result.errors.iter().any(|e| matches!(
            e,
            ValidationError::PerfettoError { message } if message.starts_with("PerfSample has both pid and tid set to 0")
        )));
    }

    #[test]
    fn test_perf_sample_valid_pid_tid() {
        use perfetto_protos::profile_packet::PerfSample;

        let mut context = PerfettoValidationContext::default();
        let mut result = ValidationResult::default();

        // Create a PerfSample with valid pid and tid
        let mut sample = PerfSample::default();
        sample.set_pid(1234);
        sample.set_tid(5678);

        let mut packet = TracePacket::default();
        packet.set_perf_sample(sample);

        validate_packet(&packet, &mut context, &mut result);

        assert!(
            !result.has_errors(),
            "Expected no errors for valid PerfSample, got: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_perf_sample_zero_pid_nonzero_tid() {
        use perfetto_protos::profile_packet::PerfSample;

        let mut context = PerfettoValidationContext::default();
        let mut result = ValidationResult::default();

        // pid=0 with valid tid is allowed (kernel thread scenario)
        let mut sample = PerfSample::default();
        sample.set_pid(0);
        sample.set_tid(5678);

        let mut packet = TracePacket::default();
        packet.set_perf_sample(sample);

        validate_packet(&packet, &mut context, &mut result);

        assert!(
            !result.has_errors(),
            "Expected no errors when only pid is 0, got: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_empty_process_name_parquet() {
        let dir = TempDir::new().unwrap();

        // Create process.parquet with empty name
        let process_schema = Arc::new(Schema::new(vec![
            Field::new("upid", DataType::Int64, false),
            Field::new("pid", DataType::Int32, false),
            Field::new("name", DataType::Utf8, true),
            Field::new("parent_upid", DataType::Int64, true),
        ]));

        let mut name_builder = StringBuilder::new();
        name_builder.append_value(""); // Empty name

        let process_batch = RecordBatch::try_new(
            process_schema.clone(),
            vec![
                Arc::new(Int64Array::from(vec![1])),
                Arc::new(Int32Array::from(vec![1000])),
                Arc::new(name_builder.finish()),
                Arc::new(Int64Array::from(vec![None])),
            ],
        )
        .unwrap();

        create_test_parquet(dir.path(), "process.parquet", process_schema, process_batch).unwrap();

        // Create thread.parquet with valid name
        let thread_schema = Arc::new(Schema::new(vec![
            Field::new("utid", DataType::Int64, false),
            Field::new("tid", DataType::Int32, false),
            Field::new("name", DataType::Utf8, true),
            Field::new("upid", DataType::Int64, true),
        ]));

        let mut name_builder = StringBuilder::new();
        name_builder.append_value("main");

        let thread_batch = RecordBatch::try_new(
            thread_schema.clone(),
            vec![
                Arc::new(Int64Array::from(vec![1])),
                Arc::new(Int32Array::from(vec![1000])),
                Arc::new(name_builder.finish()),
                Arc::new(Int64Array::from(vec![Some(1)])),
            ],
        )
        .unwrap();

        create_test_parquet(dir.path(), "thread.parquet", thread_schema, thread_batch).unwrap();

        // Create sched_slice.parquet
        let sched_schema = Arc::new(Schema::new(vec![
            Field::new("ts", DataType::Int64, false),
            Field::new("dur", DataType::Int64, false),
            Field::new("cpu", DataType::Int32, false),
            Field::new("utid", DataType::Int64, false),
            Field::new("end_state", DataType::Int32, true),
            Field::new("priority", DataType::Int32, false),
        ]));

        let sched_batch = RecordBatch::try_new(
            sched_schema.clone(),
            vec![
                Arc::new(Int64Array::from(vec![1000])),
                Arc::new(Int64Array::from(vec![100])),
                Arc::new(Int32Array::from(vec![0])),
                Arc::new(Int64Array::from(vec![1])),
                Arc::new(Int32Array::from(vec![Some(0)])),
                Arc::new(Int32Array::from(vec![120])),
            ],
        )
        .unwrap();

        create_test_parquet(dir.path(), "sched_slice.parquet", sched_schema, sched_batch).unwrap();

        let result = validate_parquet_dir(dir.path());
        assert!(
            result.has_errors(),
            "Expected errors for empty process name"
        );
        assert!(result.errors.iter().any(|e| matches!(
            e,
            ValidationError::InvalidValue {
                table,
                column,
                message,
            } if table == "process" && column == "name" && message.contains("empty")
        )));
    }

    #[test]
    fn test_empty_thread_name_parquet() {
        let dir = TempDir::new().unwrap();

        // Create process.parquet with valid name
        let process_schema = Arc::new(Schema::new(vec![
            Field::new("upid", DataType::Int64, false),
            Field::new("pid", DataType::Int32, false),
            Field::new("name", DataType::Utf8, true),
            Field::new("parent_upid", DataType::Int64, true),
        ]));

        let mut name_builder = StringBuilder::new();
        name_builder.append_value("test");

        let process_batch = RecordBatch::try_new(
            process_schema.clone(),
            vec![
                Arc::new(Int64Array::from(vec![1])),
                Arc::new(Int32Array::from(vec![1000])),
                Arc::new(name_builder.finish()),
                Arc::new(Int64Array::from(vec![None])),
            ],
        )
        .unwrap();

        create_test_parquet(dir.path(), "process.parquet", process_schema, process_batch).unwrap();

        // Create thread.parquet with empty name
        let thread_schema = Arc::new(Schema::new(vec![
            Field::new("utid", DataType::Int64, false),
            Field::new("tid", DataType::Int32, false),
            Field::new("name", DataType::Utf8, true),
            Field::new("upid", DataType::Int64, true),
        ]));

        let mut name_builder = StringBuilder::new();
        name_builder.append_value(""); // Empty name

        let thread_batch = RecordBatch::try_new(
            thread_schema.clone(),
            vec![
                Arc::new(Int64Array::from(vec![1])),
                Arc::new(Int32Array::from(vec![1000])),
                Arc::new(name_builder.finish()),
                Arc::new(Int64Array::from(vec![Some(1)])),
            ],
        )
        .unwrap();

        create_test_parquet(dir.path(), "thread.parquet", thread_schema, thread_batch).unwrap();

        // Create sched_slice.parquet
        let sched_schema = Arc::new(Schema::new(vec![
            Field::new("ts", DataType::Int64, false),
            Field::new("dur", DataType::Int64, false),
            Field::new("cpu", DataType::Int32, false),
            Field::new("utid", DataType::Int64, false),
            Field::new("end_state", DataType::Int32, true),
            Field::new("priority", DataType::Int32, false),
        ]));

        let sched_batch = RecordBatch::try_new(
            sched_schema.clone(),
            vec![
                Arc::new(Int64Array::from(vec![1000])),
                Arc::new(Int64Array::from(vec![100])),
                Arc::new(Int32Array::from(vec![0])),
                Arc::new(Int64Array::from(vec![1])),
                Arc::new(Int32Array::from(vec![Some(0)])),
                Arc::new(Int32Array::from(vec![120])),
            ],
        )
        .unwrap();

        create_test_parquet(dir.path(), "sched_slice.parquet", sched_schema, sched_batch).unwrap();

        let result = validate_parquet_dir(dir.path());
        assert!(result.has_errors(), "Expected errors for empty thread name");
        assert!(result.errors.iter().any(|e| matches!(
            e,
            ValidationError::InvalidValue {
                table,
                column,
                message,
            } if table == "thread" && column == "name" && message.contains("empty")
        )));
    }

    #[test]
    fn test_process_descriptor_empty_name() {
        use perfetto_protos::process_descriptor::ProcessDescriptor;
        use perfetto_protos::track_descriptor::TrackDescriptor;

        let mut context = PerfettoValidationContext::default();
        let mut result = ValidationResult::default();

        // Create a ProcessDescriptor with empty name
        let mut process = ProcessDescriptor::default();
        process.set_pid(1234);
        process.set_process_name(String::new()); // Empty name

        let mut desc = TrackDescriptor::default();
        desc.set_uuid(1);
        desc.process = Some(process).into();

        let mut packet = TracePacket::default();
        packet.set_track_descriptor(desc);

        validate_packet(&packet, &mut context, &mut result);

        assert!(result.has_errors(), "Expected error for empty process_name");
        assert!(result.errors.iter().any(|e| matches!(
            e,
            ValidationError::PerfettoError { message }
                if message.contains("ProcessDescriptor") && message.contains("empty")
        )));
    }

    #[test]
    fn test_thread_descriptor_empty_name() {
        use perfetto_protos::thread_descriptor::ThreadDescriptor;
        use perfetto_protos::track_descriptor::TrackDescriptor;

        let mut context = PerfettoValidationContext::default();
        let mut result = ValidationResult::default();

        // Create a ThreadDescriptor with empty name (pid != tid to avoid the main thread error)
        let mut thread = ThreadDescriptor::default();
        thread.set_pid(1234);
        thread.set_tid(5678); // Different from pid
        thread.set_thread_name(String::new()); // Empty name

        let mut desc = TrackDescriptor::default();
        desc.set_uuid(1);
        desc.thread = Some(thread).into();

        let mut packet = TracePacket::default();
        packet.set_track_descriptor(desc);

        validate_packet(&packet, &mut context, &mut result);

        assert!(result.has_errors(), "Expected error for empty thread_name");
        assert!(result.errors.iter().any(|e| matches!(
            e,
            ValidationError::PerfettoError { message }
                if message.contains("ThreadDescriptor") && message.contains("empty")
        )));
    }

    #[test]
    fn test_process_descriptor_valid_name() {
        use perfetto_protos::process_descriptor::ProcessDescriptor;
        use perfetto_protos::track_descriptor::TrackDescriptor;

        let mut context = PerfettoValidationContext::default();
        let mut result = ValidationResult::default();

        // Create a ProcessDescriptor with valid name
        let mut process = ProcessDescriptor::default();
        process.set_pid(1234);
        process.set_process_name("my_process".to_string());

        let mut desc = TrackDescriptor::default();
        desc.set_uuid(1);
        desc.process = Some(process).into();

        let mut packet = TracePacket::default();
        packet.set_track_descriptor(desc);

        validate_packet(&packet, &mut context, &mut result);

        assert!(
            !result.has_errors(),
            "Expected no errors for valid process_name, got: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_thread_descriptor_valid_name() {
        use perfetto_protos::thread_descriptor::ThreadDescriptor;
        use perfetto_protos::track_descriptor::TrackDescriptor;

        let mut context = PerfettoValidationContext::default();
        let mut result = ValidationResult::default();

        // Create a ThreadDescriptor with valid name (pid != tid)
        let mut thread = ThreadDescriptor::default();
        thread.set_pid(1234);
        thread.set_tid(5678); // Different from pid
        thread.set_thread_name("my_thread".to_string());

        let mut desc = TrackDescriptor::default();
        desc.set_uuid(1);
        desc.thread = Some(thread).into();

        let mut packet = TracePacket::default();
        packet.set_track_descriptor(desc);

        validate_packet(&packet, &mut context, &mut result);

        assert!(
            !result.has_errors(),
            "Expected no errors for valid thread_name, got: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_system_info_valid_utsname() {
        use perfetto_protos::system_info::{SystemInfo, Utsname};

        let mut context = PerfettoValidationContext::default();
        let mut result = ValidationResult::default();

        // Create a valid SystemInfo with all utsname fields
        let mut utsname = Utsname::default();
        utsname.set_sysname("Linux".to_string());
        utsname.set_release("5.10.0".to_string());
        utsname.set_version("#1 SMP".to_string());
        utsname.set_machine("x86_64".to_string());

        let system_info = SystemInfo {
            utsname: Some(utsname).into(),
            ..Default::default()
        };

        let mut packet = TracePacket::default();
        packet.set_system_info(system_info);

        validate_packet(&packet, &mut context, &mut result);

        assert!(
            !result.has_errors(),
            "Expected no errors for valid SystemInfo, got: {:?}",
            result.errors
        );
        assert!(
            context.has_valid_system_info,
            "Expected has_valid_system_info to be true"
        );
    }

    #[test]
    fn test_system_info_missing_utsname() {
        use perfetto_protos::system_info::SystemInfo;

        let mut context = PerfettoValidationContext::default();
        let mut result = ValidationResult::default();

        // Create SystemInfo without utsname
        let system_info = SystemInfo::default();

        let mut packet = TracePacket::default();
        packet.set_system_info(system_info);

        validate_packet(&packet, &mut context, &mut result);

        assert!(result.has_errors(), "Expected error for missing utsname");
        assert!(result.errors.iter().any(|e| matches!(
            e,
            ValidationError::PerfettoError { message }
                if message.contains("utsname is not set")
        )));
        assert!(
            !context.has_valid_system_info,
            "Expected has_valid_system_info to be false"
        );
    }

    #[test]
    fn test_system_info_utsname_missing_fields() {
        use perfetto_protos::system_info::{SystemInfo, Utsname};

        let mut context = PerfettoValidationContext::default();
        let mut result = ValidationResult::default();

        // Create SystemInfo with utsname missing some fields
        let mut utsname = Utsname::default();
        utsname.set_sysname("Linux".to_string());
        // Missing release, version, machine

        let system_info = SystemInfo {
            utsname: Some(utsname).into(),
            ..Default::default()
        };

        let mut packet = TracePacket::default();
        packet.set_system_info(system_info);

        validate_packet(&packet, &mut context, &mut result);

        assert!(
            result.has_errors(),
            "Expected error for missing utsname fields"
        );
        assert!(result.errors.iter().any(|e| matches!(
            e,
            ValidationError::PerfettoError { message }
                if message.contains("missing required fields")
        )));
        assert!(
            !context.has_valid_system_info,
            "Expected has_valid_system_info to be false"
        );
    }

    #[test]
    fn test_system_info_utsname_empty_fields() {
        use perfetto_protos::system_info::{SystemInfo, Utsname};

        let mut context = PerfettoValidationContext::default();
        let mut result = ValidationResult::default();

        // Create SystemInfo with utsname having empty fields
        let mut utsname = Utsname::default();
        utsname.set_sysname("Linux".to_string());
        utsname.set_release("".to_string()); // Empty
        utsname.set_version("".to_string()); // Empty
        utsname.set_machine("x86_64".to_string());

        let system_info = SystemInfo {
            utsname: Some(utsname).into(),
            ..Default::default()
        };

        let mut packet = TracePacket::default();
        packet.set_system_info(system_info);

        validate_packet(&packet, &mut context, &mut result);

        assert!(
            result.has_errors(),
            "Expected error for empty utsname fields"
        );
        assert!(result.errors.iter().any(|e| matches!(
            e,
            ValidationError::PerfettoError { message }
                if message.contains("missing required fields")
                    && message.contains("release")
                    && message.contains("version")
        )));
    }

    #[test]
    fn test_validate_system_info_exists() {
        let mut context = PerfettoValidationContext::default();
        let mut result = ValidationResult::default();

        // No SystemInfo was seen
        validate_system_info_exists(&context, &mut result);

        assert!(result.has_errors(), "Expected error for missing SystemInfo");
        assert!(result.errors.iter().any(|e| matches!(
            e,
            ValidationError::PerfettoError { message }
                if message.contains("No SystemInfo packet")
        )));

        // Now mark that we've seen valid SystemInfo
        context.has_valid_system_info = true;
        result = ValidationResult::default();

        validate_system_info_exists(&context, &mut result);

        assert!(
            !result.has_errors(),
            "Expected no errors when SystemInfo is present, got: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_system_info_utsname_all_fields_empty() {
        use perfetto_protos::system_info::{SystemInfo, Utsname};

        let mut context = PerfettoValidationContext::default();
        let mut result = ValidationResult::default();

        // Create SystemInfo with utsname having ALL fields empty
        let utsname = Utsname::default();

        let system_info = SystemInfo {
            utsname: Some(utsname).into(),
            ..Default::default()
        };

        let mut packet = TracePacket::default();
        packet.set_system_info(system_info);

        validate_packet(&packet, &mut context, &mut result);

        assert!(
            result.has_errors(),
            "Expected error for all empty utsname fields"
        );
        // Verify all four required fields are mentioned in the error
        assert!(result.errors.iter().any(|e| matches!(
            e,
            ValidationError::PerfettoError { message }
                if message.contains("missing required fields")
                    && message.contains("sysname")
                    && message.contains("release")
                    && message.contains("version")
                    && message.contains("machine")
        )));
    }

    #[test]
    fn test_system_info_first_valid_wins() {
        use perfetto_protos::system_info::{SystemInfo, Utsname};

        let mut context = PerfettoValidationContext::default();
        let mut result = ValidationResult::default();

        // First, send a valid SystemInfo
        let mut valid_utsname = Utsname::default();
        valid_utsname.set_sysname("Linux".to_string());
        valid_utsname.set_release("5.10.0".to_string());
        valid_utsname.set_version("#1 SMP".to_string());
        valid_utsname.set_machine("x86_64".to_string());

        let valid_system_info = SystemInfo {
            utsname: Some(valid_utsname).into(),
            ..Default::default()
        };

        let mut packet1 = TracePacket::default();
        packet1.set_system_info(valid_system_info);

        validate_packet(&packet1, &mut context, &mut result);

        assert!(
            !result.has_errors(),
            "Expected no errors for valid SystemInfo"
        );
        assert!(context.has_valid_system_info);

        // Now send an invalid SystemInfo (missing fields)
        let invalid_utsname = Utsname::default(); // All fields empty

        let invalid_system_info = SystemInfo {
            utsname: Some(invalid_utsname).into(),
            ..Default::default()
        };

        let mut packet2 = TracePacket::default();
        packet2.set_system_info(invalid_system_info);

        validate_packet(&packet2, &mut context, &mut result);

        // Should still have no errors - "first valid wins" means subsequent invalid
        // SystemInfo packets are ignored
        assert!(
            !result.has_errors(),
            "Expected no errors after valid SystemInfo was seen, got: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_compact_sched_first_switch_prev_state_zero() {
        use perfetto_protos::ftrace_event_bundle::ftrace_event_bundle::CompactSched;

        let mut context = PerfettoValidationContext::default();
        let mut result = ValidationResult::default();

        // Create a CompactSched with first prev_state=0 (correct)
        let mut compact = CompactSched::default();
        compact.switch_timestamp.push(1000);
        compact.switch_next_pid.push(1234);
        compact.switch_next_prio.push(120);
        compact.switch_prev_state.push(0); // First switch should have prev_state=0
        compact.intern_table.push("task".to_string());
        compact.switch_next_comm_index.push(0);

        validate_compact_sched(&compact, 0, &mut context, &mut result);

        assert!(
            !result.has_errors(),
            "Expected no errors for first switch with prev_state=0, got: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_compact_sched_first_switch_prev_state_nonzero() {
        use perfetto_protos::ftrace_event_bundle::ftrace_event_bundle::CompactSched;

        let mut context = PerfettoValidationContext::default();
        let mut result = ValidationResult::default();

        // Create a CompactSched with first prev_state=2 (suspicious - uninterruptible at trace start)
        let mut compact = CompactSched::default();
        compact.switch_timestamp.push(1000);
        compact.switch_next_pid.push(1234);
        compact.switch_next_prio.push(120);
        compact.switch_prev_state.push(2); // TASK_UNINTERRUPTIBLE at trace start is suspicious
        compact.intern_table.push("task".to_string());
        compact.switch_next_comm_index.push(0);

        validate_compact_sched(&compact, 0, &mut context, &mut result);

        assert!(
            result.has_errors(),
            "Expected error for first switch with non-zero prev_state"
        );
        assert!(result.errors.iter().any(|e| matches!(
            e,
            ValidationError::PerfettoError { message }
                if message.contains("first switch has prev_state=2")
        )));
    }

    #[test]
    fn test_compact_sched_subsequent_switch_prev_state_nonzero_ok() {
        use perfetto_protos::ftrace_event_bundle::ftrace_event_bundle::CompactSched;

        let mut context = PerfettoValidationContext::default();
        let mut result = ValidationResult::default();

        // First packet on CPU 0 with prev_state=0 (correct)
        let mut compact1 = CompactSched::default();
        compact1.switch_timestamp.push(1000);
        compact1.switch_next_pid.push(1234);
        compact1.switch_next_prio.push(120);
        compact1.switch_prev_state.push(0);
        compact1.intern_table.push("task".to_string());
        compact1.switch_next_comm_index.push(0);

        validate_compact_sched(&compact1, 0, &mut context, &mut result);
        assert!(
            !result.has_errors(),
            "Expected no errors for first switch, got: {:?}",
            result.errors
        );

        // Second packet on CPU 0 - prev_state can be non-zero now
        let mut compact2 = CompactSched::default();
        compact2.switch_timestamp.push(2000);
        compact2.switch_next_pid.push(5678);
        compact2.switch_next_prio.push(120);
        compact2.switch_prev_state.push(2); // TASK_UNINTERRUPTIBLE is fine after first switch
        compact2.intern_table.push("task2".to_string());
        compact2.switch_next_comm_index.push(0);

        validate_compact_sched(&compact2, 0, &mut context, &mut result);

        assert!(
            !result.has_errors(),
            "Expected no errors for subsequent switch with non-zero prev_state, got: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_compact_sched_multi_cpu_independent_validation() {
        use perfetto_protos::ftrace_event_bundle::ftrace_event_bundle::CompactSched;

        let mut context = PerfettoValidationContext::default();
        let mut result = ValidationResult::default();

        // CPU 0: first switch with prev_state=0 (correct)
        let mut compact_cpu0 = CompactSched::default();
        compact_cpu0.switch_timestamp.push(1000);
        compact_cpu0.switch_next_pid.push(1234);
        compact_cpu0.switch_next_prio.push(120);
        compact_cpu0.switch_prev_state.push(0);
        compact_cpu0.intern_table.push("task0".to_string());
        compact_cpu0.switch_next_comm_index.push(0);

        validate_compact_sched(&compact_cpu0, 0, &mut context, &mut result);
        assert!(
            !result.has_errors(),
            "CPU 0 first switch with prev_state=0 should not error"
        );

        // CPU 1: first switch with prev_state=2 (error - each CPU validated independently)
        let mut compact_cpu1 = CompactSched::default();
        compact_cpu1.switch_timestamp.push(1500);
        compact_cpu1.switch_next_pid.push(5678);
        compact_cpu1.switch_next_prio.push(120);
        compact_cpu1.switch_prev_state.push(2); // TASK_UNINTERRUPTIBLE on first switch is suspicious
        compact_cpu1.intern_table.push("task1".to_string());
        compact_cpu1.switch_next_comm_index.push(0);

        validate_compact_sched(&compact_cpu1, 1, &mut context, &mut result);
        assert!(
            result.has_errors(),
            "CPU 1 first switch with prev_state=2 should error"
        );
        assert!(result.errors.iter().any(|e| matches!(
            e,
            ValidationError::PerfettoError { message }
                if message.contains("CPU 1") && message.contains("prev_state=2")
        )));

        // Verify both CPUs are now tracked
        assert!(context.cpus_seen_first_switch.contains(&0));
        assert!(context.cpus_seen_first_switch.contains(&1));
    }

    #[test]
    fn test_collect_end_state_counts() {
        let dir = TempDir::new().unwrap();

        // Create sched_slice.parquet with various end_state values
        let schema = Arc::new(Schema::new(vec![
            Field::new("ts", DataType::Int64, false),
            Field::new("dur", DataType::Int64, false),
            Field::new("cpu", DataType::Int32, false),
            Field::new("utid", DataType::Int64, false),
            Field::new("end_state", DataType::Int32, true),
            Field::new("priority", DataType::Int32, false),
        ]));

        // end_state values: 0, 1, 1, 2, NULL (NULL counts as 0)
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Int64Array::from(vec![1000, 2000, 3000, 4000, 5000])),
                Arc::new(Int64Array::from(vec![100, 100, 100, 100, 100])),
                Arc::new(Int32Array::from(vec![0, 0, 1, 2, 3])),
                Arc::new(Int64Array::from(vec![1, 2, 3, 4, 5])),
                Arc::new(Int32Array::from(vec![
                    Some(0),
                    Some(1),
                    Some(1),
                    Some(2),
                    None,
                ])),
                Arc::new(Int32Array::from(vec![120, 120, 120, 120, 120])),
            ],
        )
        .unwrap();

        create_test_parquet(dir.path(), "sched_slice.parquet", schema, batch).unwrap();

        let paths = ParquetPaths::new(dir.path());
        let counts = collect_end_state_counts(&paths).unwrap();

        // Expected: state 0 = 2 (one explicit, one NULL), state 1 = 2, state 2 = 1
        assert_eq!(counts.get(&0).copied().unwrap_or(0), 2);
        assert_eq!(counts.get(&1).copied().unwrap_or(0), 2);
        assert_eq!(counts.get(&2).copied().unwrap_or(0), 1);
    }

    #[test]
    fn test_collect_end_state_counts_empty_file() {
        let dir = TempDir::new().unwrap();

        // Create empty sched_slice.parquet
        let schema = Arc::new(Schema::new(vec![
            Field::new("ts", DataType::Int64, false),
            Field::new("dur", DataType::Int64, false),
            Field::new("cpu", DataType::Int32, false),
            Field::new("utid", DataType::Int64, false),
            Field::new("end_state", DataType::Int32, true),
            Field::new("priority", DataType::Int32, false),
        ]));

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Int64Array::from(Vec::<i64>::new())),
                Arc::new(Int64Array::from(Vec::<i64>::new())),
                Arc::new(Int32Array::from(Vec::<i32>::new())),
                Arc::new(Int64Array::from(Vec::<i64>::new())),
                Arc::new(Int32Array::from(Vec::<Option<i32>>::new())),
                Arc::new(Int32Array::from(Vec::<i32>::new())),
            ],
        )
        .unwrap();

        create_test_parquet(dir.path(), "sched_slice.parquet", schema, batch).unwrap();

        let paths = ParquetPaths::new(dir.path());
        let counts = collect_end_state_counts(&paths).unwrap();

        assert!(counts.is_empty());
    }

    #[test]
    fn test_collect_end_state_counts_no_file() {
        let dir = TempDir::new().unwrap();
        // No sched_slice.parquet created

        let paths = ParquetPaths::new(dir.path());
        let counts = collect_end_state_counts(&paths).unwrap();

        assert!(counts.is_empty());
    }

    #[test]
    fn test_cross_validation_error_display() {
        let error = ValidationError::CrossValidationError {
            message: "Test mismatch".to_string(),
        };
        assert_eq!(format!("{error}"), "Cross-validation: Test mismatch");
    }

    #[test]
    fn test_network_syscalls_must_be_on_network_tracks() {
        let mut context = PerfettoValidationContext::default();
        let mut result = ValidationResult::default();

        // Create a thread track (simulating a thread track from ThreadDescriptor)
        let thread_track_uuid = 100u64;
        context.defined_tracks.insert(thread_track_uuid);
        context.thread_process_tracks.insert(thread_track_uuid);
        // Thread track gets name from ThreadDescriptor, which doesn't start with "Network"
        context
            .track_names
            .insert(thread_track_uuid, "my_thread".to_string());

        // Record a network syscall event on the thread track (this is wrong - should be on Network track)
        context
            .network_syscall_events
            .insert((thread_track_uuid, "sendmsg".to_string()), 1000);

        // Run validation
        validate_network_syscalls_on_network_tracks(&context, &mut result);

        // Should have an error because the event is on a track named "my_thread" not "Network"
        assert!(
            result.has_errors(),
            "Expected error for network syscall on non-Network track"
        );
        assert!(
            result.errors.iter().any(|e| matches!(
                e,
                ValidationError::PerfettoError { message }
                    if message.contains("sendmsg") && message.contains("my_thread")
            )),
            "Error should mention the event name and track name"
        );
    }

    #[test]
    fn test_network_syscalls_on_network_track_passes() {
        let mut context = PerfettoValidationContext::default();
        let mut result = ValidationResult::default();

        // Create a thread track
        let thread_track_uuid = 100u64;
        context.defined_tracks.insert(thread_track_uuid);
        context.thread_process_tracks.insert(thread_track_uuid);
        context
            .track_names
            .insert(thread_track_uuid, "my_thread".to_string());

        // Create a Network track parented to the thread track
        let network_track_uuid = 200u64;
        context.defined_tracks.insert(network_track_uuid);
        context
            .track_names
            .insert(network_track_uuid, "Network".to_string());
        context
            .parent_refs
            .insert(network_track_uuid, thread_track_uuid);

        // Record a network syscall event on the Network track (correct)
        context
            .network_syscall_events
            .insert((network_track_uuid, "sendmsg".to_string()), 1000);

        // Run validation
        validate_network_syscalls_on_network_tracks(&context, &mut result);

        // Should pass - event is on a "Network" track parented to a thread track
        assert!(
            !result.has_errors(),
            "Expected no errors for network syscall on properly parented Network track, got: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_network_syscalls_on_network_track_with_tid_suffix_passes() {
        let mut context = PerfettoValidationContext::default();
        let mut result = ValidationResult::default();

        // Create a thread track
        let thread_track_uuid = 100u64;
        context.defined_tracks.insert(thread_track_uuid);
        context.thread_process_tracks.insert(thread_track_uuid);
        context
            .track_names
            .insert(thread_track_uuid, "my_thread".to_string());

        // Create a Network track with tid suffix, parented to the thread track
        let network_track_uuid = 200u64;
        context.defined_tracks.insert(network_track_uuid);
        context
            .track_names
            .insert(network_track_uuid, "Network (tid 1234)".to_string());
        context
            .parent_refs
            .insert(network_track_uuid, thread_track_uuid);

        // Record a network syscall event on the Network track (correct)
        context
            .network_syscall_events
            .insert((network_track_uuid, "recvmsg".to_string()), 1000);

        // Run validation
        validate_network_syscalls_on_network_tracks(&context, &mut result);

        // Should pass - event is on a "Network (tid N)" track parented to a thread track
        assert!(
            !result.has_errors(),
            "Expected no errors for network syscall on 'Network (tid N)' track, got: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_network_syscalls_on_unparented_network_track_fails() {
        let mut context = PerfettoValidationContext::default();
        let mut result = ValidationResult::default();

        // Create a Network track with NO parent
        let network_track_uuid = 200u64;
        context.defined_tracks.insert(network_track_uuid);
        context
            .track_names
            .insert(network_track_uuid, "Network".to_string());
        // Note: no parent_ref added

        // Record a network syscall event on the Network track
        context
            .network_syscall_events
            .insert((network_track_uuid, "poll".to_string()), 1000);

        // Run validation
        validate_network_syscalls_on_network_tracks(&context, &mut result);

        // Should fail - track has no parent
        assert!(
            result.has_errors(),
            "Expected error for network syscall on unparented Network track"
        );
        assert!(
            result.errors.iter().any(|e| matches!(
                e,
                ValidationError::PerfettoError { message }
                    if message.contains("no parent")
            )),
            "Error should mention missing parent"
        );
    }

    #[test]
    fn test_socket_track_without_socket_id_fails() {
        let mut context = PerfettoValidationContext::default();
        let mut result = ValidationResult::default();

        // Create "Network Packets" root track
        let network_packets_uuid = 100u64;
        context.defined_tracks.insert(network_packets_uuid);
        context
            .track_names
            .insert(network_packets_uuid, "Network Packets".to_string());
        context.network_packets_root_uuid = Some(network_packets_uuid);

        // Create a socket track with incorrect name (missing "Socket " prefix)
        let socket_track_uuid = 200u64;
        context.defined_tracks.insert(socket_track_uuid);
        context.track_names.insert(
            socket_track_uuid,
            "TCP 10.0.0.1:12345 → 10.0.0.2:80".to_string(),
        );
        context
            .parent_refs
            .insert(socket_track_uuid, network_packets_uuid);

        // Run validation
        validate_socket_tracks_have_socket_id(&context, &mut result);

        // Should fail - socket track doesn't start with "Socket "
        assert!(
            result.has_errors(),
            "Expected error for socket track without 'Socket ' prefix"
        );
        assert!(
            result.errors.iter().any(|e| matches!(
                e,
                ValidationError::PerfettoError { message }
                    if message.contains("must start with")
            )),
            "Error should explain the naming requirement"
        );
    }

    #[test]
    fn test_socket_track_with_socket_id_passes() {
        let mut context = PerfettoValidationContext::default();
        let mut result = ValidationResult::default();

        // Create "Network Packets" root track
        let network_packets_uuid = 100u64;
        context.defined_tracks.insert(network_packets_uuid);
        context
            .track_names
            .insert(network_packets_uuid, "Network Packets".to_string());
        context.network_packets_root_uuid = Some(network_packets_uuid);

        // Create a socket track with correct name format
        let socket_track_uuid = 200u64;
        context.defined_tracks.insert(socket_track_uuid);
        context.track_names.insert(
            socket_track_uuid,
            "Socket 123:TCP:10.0.0.1:12345->10.0.0.2:80".to_string(),
        );
        context
            .parent_refs
            .insert(socket_track_uuid, network_packets_uuid);

        // Run validation
        validate_socket_tracks_have_socket_id(&context, &mut result);

        // Should pass - socket track has correct format
        assert!(
            !result.has_errors(),
            "Expected no errors for socket track with 'Socket N:...' format, got: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_socket_track_fallback_format_passes() {
        let mut context = PerfettoValidationContext::default();
        let mut result = ValidationResult::default();

        // Create "Network Packets" root track
        let network_packets_uuid = 100u64;
        context.defined_tracks.insert(network_packets_uuid);
        context
            .track_names
            .insert(network_packets_uuid, "Network Packets".to_string());
        context.network_packets_root_uuid = Some(network_packets_uuid);

        // Create a socket track with fallback format (just socket_id)
        let socket_track_uuid = 200u64;
        context.defined_tracks.insert(socket_track_uuid);
        context
            .track_names
            .insert(socket_track_uuid, "Socket 456".to_string());
        context
            .parent_refs
            .insert(socket_track_uuid, network_packets_uuid);

        // Run validation
        validate_socket_tracks_have_socket_id(&context, &mut result);

        // Should pass - socket track has fallback format
        assert!(
            !result.has_errors(),
            "Expected no errors for socket track with 'Socket N' fallback format, got: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_socket_track_validation_skipped_without_network_packets() {
        let mut context = PerfettoValidationContext::default();
        let mut result = ValidationResult::default();

        // No "Network Packets" root track - network_packets_root_uuid is None

        // Create a socket track with incorrect name format
        // This should not cause errors since there's no "Network Packets" parent to validate
        let socket_track_uuid = 200u64;
        context.defined_tracks.insert(socket_track_uuid);
        context.track_names.insert(
            socket_track_uuid,
            "TCP 10.0.0.1:12345 → 10.0.0.2:80".to_string(),
        );

        // Run validation
        validate_socket_tracks_have_socket_id(&context, &mut result);

        // Should pass - validation skipped when there's no Network Packets root
        assert!(
            !result.has_errors(),
            "Expected no errors when 'Network Packets' root is not present, got: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_swapper_validation_passes_with_correct_comm() {
        let mut context = PerfettoValidationContext::default();
        let mut result = ValidationResult::default();

        // Simulate sched events with pid=0 and all valid comm string variants
        context.pid_zero_comms.insert("swapper/0".to_string(), 1000);
        context.pid_zero_comms.insert("swapper/1".to_string(), 500);
        context.pid_zero_comms.insert("swapper".to_string(), 100);
        context.pid_zero_comms.insert("".to_string(), 50); // Empty string is valid (legacy)
        context.pid_zero_comms.insert("<idle>".to_string(), 25); // Alternative idle format

        // Also need some prev_state_counts to show we have sched data
        context.prev_state_counts.insert(0, 1675);

        validate_swapper_thread_names(&context, &mut result);

        assert!(
            !result.has_errors(),
            "Expected no errors for correct swapper comm strings, got: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_swapper_validation_fails_with_no_pid_zero_events() {
        let mut context = PerfettoValidationContext::default();
        let mut result = ValidationResult::default();

        // No pid=0 events in pid_zero_comms (empty)

        // But we have plenty of sched events (from prev_state_counts)
        context.prev_state_counts.insert(0, 100000);
        context.prev_state_counts.insert(1, 50000);

        validate_swapper_thread_names(&context, &mut result);

        assert!(
            result.has_errors(),
            "Expected error when no pid=0 events exist but sched data is present"
        );
        assert!(
            result.errors[0]
                .to_string()
                .contains("No sched events with next_pid=0"),
            "Error should mention missing pid=0 events: {}",
            result.errors[0]
        );
    }

    #[test]
    fn test_swapper_validation_fails_with_wrong_comm() {
        let mut context = PerfettoValidationContext::default();
        let mut result = ValidationResult::default();

        // Simulate pid=0 events with wrong comm strings (migration threads)
        context
            .pid_zero_comms
            .insert("migration/133".to_string(), 50000);
        context
            .pid_zero_comms
            .insert("migration/112".to_string(), 10000);
        context.pid_zero_comms.insert("swapper".to_string(), 100); // Some correct ones

        // Also need some prev_state_counts
        context.prev_state_counts.insert(0, 60100);

        validate_swapper_thread_names(&context, &mut result);

        assert!(
            result.has_errors(),
            "Expected error for incorrect comm strings on pid=0 events"
        );
        assert!(
            result.errors[0]
                .to_string()
                .contains("incorrect comm strings"),
            "Error should mention incorrect comm strings: {}",
            result.errors[0]
        );
        assert!(
            result.errors[0].to_string().contains("migration/133"),
            "Error should mention the migration thread: {}",
            result.errors[0]
        );
    }

    #[test]
    fn test_swapper_validation_skipped_with_few_sched_events() {
        let mut context = PerfettoValidationContext::default();
        let mut result = ValidationResult::default();

        // No pid=0 events, but also very few total sched events
        // (threshold is 1000)
        context.prev_state_counts.insert(0, 500);

        validate_swapper_thread_names(&context, &mut result);

        // Should not report error when we have few sched events
        assert!(
            !result.has_errors(),
            "Expected no error with few sched events, got: {:?}",
            result.errors
        );
    }
}
