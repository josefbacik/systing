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
    /// Whether we've seen a clock snapshot
    has_clock_snapshot: bool,
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

        // Check parent UUID
        if desc.has_parent_uuid() {
            let parent_uuid = desc.parent_uuid();
            context.parent_refs.insert(uuid, parent_uuid);
        }

        // Check ThreadDescriptor: pid should not equal tid
        // When pid == tid, it's the main thread and should use ProcessDescriptor instead
        if let Some(thread) = desc.thread.as_ref() {
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
        }
    }

    // Check for ftrace events with CompactSched
    if packet.has_ftrace_events() {
        let events = packet.ftrace_events();
        if events.compact_sched.is_some() {
            validate_compact_sched(events.compact_sched.as_ref().unwrap(), context, result);
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
}

/// Validate CompactSched structure.
fn validate_compact_sched(
    compact: &perfetto_protos::ftrace_event_bundle::ftrace_event_bundle::CompactSched,
    _context: &mut PerfettoValidationContext,
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
}
