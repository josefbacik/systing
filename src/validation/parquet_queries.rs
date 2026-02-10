//! Parquet-specific validation query implementation.
//!
//! This module implements `ValidationQueries` for Parquet trace files using
//! native Arrow columnar scans with HashSet lookups.

use anyhow::{Context, Result};
use arrow::array::{
    Array, BooleanArray, Int32Array, Int64Array, Int8Array, ListArray, StringArray,
};
use arrow::datatypes::DataType;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use std::collections::HashSet;
use std::fs::File;
use std::path::Path;

use crate::parquet_paths::ParquetPaths;

use super::config::ValidationConfig;
use super::queries::{
    CmdlineStats, FieldCheck, OrphanCheck, SchemaResult, StackViolation, ValidationQueries,
    STACK_RUNNING, STACK_SLEEP_INTERRUPTIBLE, STACK_SLEEP_UNINTERRUPTIBLE,
};
use super::result::{ValidationError, ValidationResult};
use super::runner::run_common_validations;

/// Parquet-specific validation query implementation.
pub struct ParquetQueries {
    paths: ParquetPaths,
    /// Cached process upids - populated on first access.
    process_upids: Option<HashSet<i64>>,
    /// Cached thread utids - populated on first access.
    thread_utids: Option<HashSet<i64>>,
}

impl ParquetQueries {
    /// Create a new ParquetQueries for the given trace directory.
    pub fn new(dir: &Path) -> Self {
        Self {
            paths: ParquetPaths::new(dir),
            process_upids: None,
            thread_utids: None,
        }
    }

    /// Get or load process upids.
    fn get_process_upids(&mut self) -> Result<&HashSet<i64>> {
        if self.process_upids.is_none() {
            let mut upids = HashSet::new();
            if self.paths.process.exists() {
                collect_i64_column(&self.paths.process, "upid", &mut upids)?;
            }
            self.process_upids = Some(upids);
        }
        Ok(self.process_upids.as_ref().unwrap())
    }

    /// Get or load thread utids.
    fn get_thread_utids(&mut self) -> Result<&HashSet<i64>> {
        if self.thread_utids.is_none() {
            let mut utids = HashSet::new();
            if self.paths.thread.exists() {
                collect_i64_column(&self.paths.thread, "utid", &mut utids)?;
            }
            self.thread_utids = Some(utids);
        }
        Ok(self.thread_utids.as_ref().unwrap())
    }
}

impl ValidationQueries for ParquetQueries {
    fn format_name(&self) -> &'static str {
        "parquet"
    }

    fn count_orphan_thread_upids(&mut self) -> Result<OrphanCheck> {
        let path = self.paths.thread.clone();
        if !path.exists() {
            return Ok(OrphanCheck::ok(0));
        }

        let valid_upids = self.get_process_upids()?.clone();
        if valid_upids.is_empty() {
            return Ok(OrphanCheck::ok(0));
        }

        let file = File::open(&path)?;
        let builder = ParquetRecordBatchReaderBuilder::try_new(file)?;
        let reader = builder.build()?;

        let mut orphan_count = 0i64;
        let mut total_count = 0i64;
        let mut sample_orphan_ids = Vec::new();

        for batch_result in reader {
            let batch = batch_result?;
            let schema = batch.schema();
            let upid_idx = match schema.index_of("upid") {
                Ok(idx) => idx,
                Err(_) => continue,
            };

            let upid_array = batch
                .column(upid_idx)
                .as_any()
                .downcast_ref::<Int64Array>()
                .context("upid column not Int64")?;

            for i in 0..upid_array.len() {
                total_count += 1;
                if upid_array.is_null(i) {
                    continue; // upid is nullable (kernel threads)
                }
                let upid = upid_array.value(i);
                if !valid_upids.contains(&upid) {
                    orphan_count += 1;
                    if sample_orphan_ids.len() < 10 {
                        sample_orphan_ids.push(upid);
                    }
                }
            }
        }

        Ok(OrphanCheck {
            orphan_count,
            total_count,
            sample_orphan_ids,
        })
    }

    fn count_orphan_sched_utids(&mut self) -> Result<OrphanCheck> {
        let path = self.paths.sched_slice.clone();
        if !path.exists() {
            return Ok(OrphanCheck::ok(0));
        }

        let valid_utids = self.get_thread_utids()?.clone();
        if valid_utids.is_empty() {
            return Ok(OrphanCheck::ok(0));
        }

        let file = File::open(&path)?;
        let builder = ParquetRecordBatchReaderBuilder::try_new(file)?;
        let reader = builder.build()?;

        let mut orphan_count = 0i64;
        let mut total_count = 0i64;
        let mut sample_orphan_ids = Vec::new();

        for batch_result in reader {
            let batch = batch_result?;
            let schema = batch.schema();
            let utid_idx = match schema.index_of("utid") {
                Ok(idx) => idx,
                Err(_) => continue,
            };

            let utid_array = batch
                .column(utid_idx)
                .as_any()
                .downcast_ref::<Int64Array>()
                .context("utid column not Int64")?;

            for i in 0..utid_array.len() {
                total_count += 1;
                if utid_array.is_null(i) {
                    continue;
                }
                let utid = utid_array.value(i);
                if !valid_utids.contains(&utid) {
                    orphan_count += 1;
                    if sample_orphan_ids.len() < 10 {
                        sample_orphan_ids.push(utid);
                    }
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
        count_empty_names(&self.paths.process, "upid", "pid", 0)
    }

    fn count_empty_thread_names(&mut self) -> Result<FieldCheck> {
        count_empty_names(&self.paths.thread, "utid", "tid", 0)
    }

    fn get_cmdline_stats(&mut self) -> Result<CmdlineStats> {
        let path = &self.paths.process;
        if !path.exists() {
            return Ok(CmdlineStats {
                has_column: false,
                empty_count: 0,
                total_count: 0,
            });
        }

        let file = File::open(path)?;
        let builder = ParquetRecordBatchReaderBuilder::try_new(file)?;

        // Check if cmdline column exists
        let schema = builder.schema();
        let has_cmdline = schema.fields().iter().any(|f| f.name() == "cmdline");
        if !has_cmdline {
            return Ok(CmdlineStats {
                has_column: false,
                empty_count: 0,
                total_count: 0,
            });
        }

        let has_kernel_col = schema
            .fields()
            .iter()
            .any(|f| f.name() == "is_kernel_thread");

        let reader = builder.build()?;
        let mut total_count = 0i64;
        let mut empty_count = 0i64;

        for batch_result in reader {
            let batch = batch_result?;
            let schema = batch.schema();
            let cmdline_idx = match schema.index_of("cmdline") {
                Ok(idx) => idx,
                Err(_) => continue,
            };
            let pid_idx = match schema.index_of("pid") {
                Ok(idx) => idx,
                Err(_) => continue,
            };

            let cmdline_array = batch
                .column(cmdline_idx)
                .as_any()
                .downcast_ref::<ListArray>();
            let pid_array = batch.column(pid_idx).as_any().downcast_ref::<Int32Array>();

            // Read is_kernel_thread column if present
            let kernel_array = if has_kernel_col {
                schema
                    .index_of("is_kernel_thread")
                    .ok()
                    .and_then(|idx| batch.column(idx).as_any().downcast_ref::<BooleanArray>())
            } else {
                None
            };

            if let (Some(list_array), Some(pid_int_array)) = (cmdline_array, pid_array) {
                for i in 0..list_array.len() {
                    let pid = if pid_int_array.is_null(i) {
                        -1
                    } else {
                        pid_int_array.value(i)
                    };

                    // Skip pid 0 (kernel/swapper process)
                    if pid == 0 {
                        continue;
                    }

                    // Skip kernel threads if column is present
                    if let Some(ka) = kernel_array {
                        if !ka.is_null(i) && ka.value(i) {
                            continue;
                        }
                    }

                    total_count += 1;

                    let is_empty = list_array.is_null(i) || list_array.value(i).is_empty();
                    if is_empty {
                        empty_count += 1;
                    }
                }
            }
        }

        Ok(CmdlineStats {
            has_column: true,
            empty_count,
            total_count,
        })
    }

    fn check_end_state_schema(&mut self) -> Result<SchemaResult> {
        let path = &self.paths.sched_slice;
        if !path.exists() {
            return Ok(SchemaResult::missing());
        }

        let file = File::open(path)?;
        let builder = ParquetRecordBatchReaderBuilder::try_new(file)?;
        let schema = builder.schema();

        for field in schema.fields() {
            if field.name() == "end_state" {
                let data_type = field.data_type();
                if matches!(data_type, DataType::Int32) {
                    return Ok(SchemaResult::valid("Int32"));
                } else {
                    return Ok(SchemaResult::wrong_type(
                        "Int32",
                        format!("{:?}", data_type),
                    ));
                }
            }
        }

        Ok(SchemaResult::missing())
    }

    fn get_counter_unit_values(&mut self) -> Result<Vec<Option<String>>> {
        let path = &self.paths.counter_track;
        if !path.exists() {
            return Ok(Vec::new());
        }

        let file = File::open(path)?;
        let builder = ParquetRecordBatchReaderBuilder::try_new(file)?;

        // Check if unit column exists
        let schema = builder.schema();
        let has_unit = schema.fields().iter().any(|f| f.name() == "unit");
        if !has_unit {
            return Ok(Vec::new());
        }

        let reader = builder.build()?;
        let mut values = Vec::new();

        for batch_result in reader {
            let batch = batch_result?;
            let schema = batch.schema();
            let unit_idx = match schema.index_of("unit") {
                Ok(idx) => idx,
                Err(_) => continue,
            };

            let unit_array = batch
                .column(unit_idx)
                .as_any()
                .downcast_ref::<StringArray>();

            if let Some(string_array) = unit_array {
                for i in 0..string_array.len() {
                    if string_array.is_null(i) {
                        values.push(None);
                    } else {
                        values.push(Some(string_array.value(i).to_string()));
                    }
                }
            }
        }

        Ok(values)
    }

    fn find_stack_timing_violations(&mut self, tolerance_ns: i64) -> Result<Vec<StackViolation>> {
        let stack_path = &self.paths.stack_sample;
        let sched_path = &self.paths.sched_slice;

        if !stack_path.exists() || !sched_path.exists() {
            return Ok(Vec::new());
        }

        // Load sched slices indexed by utid
        let slices_by_utid = load_sched_slices_by_utid(sched_path)?;
        if slices_by_utid.is_empty() {
            return Ok(Vec::new());
        }

        // Load stack samples
        let samples = load_stack_samples(stack_path)?;
        if samples.is_empty() {
            return Ok(Vec::new());
        }

        let mut violations = Vec::new();
        // Limit violations to avoid memory issues during processing.
        // The runner will further limit what's reported based on ValidationConfig.
        const MAX_VIOLATIONS: usize = 100;

        for sample in &samples {
            if violations.len() >= MAX_VIOLATIONS {
                break;
            }

            let slices = match slices_by_utid.get(&sample.utid) {
                Some(s) => s,
                None => continue, // No scheduling data for this utid
            };

            // Skip samples that occur before the first sched_slice for this utid
            let first_slice_ts = slices.first().map(|s| s.ts).unwrap_or(i64::MAX);
            if sample.ts < first_slice_ts {
                continue;
            }

            let closest = find_closest_slice(slices, sample.ts);

            let violation = match (sample.stack_event_type, closest) {
                // STACK_SLEEP_UNINTERRUPTIBLE/STACK_SLEEP_INTERRUPTIBLE: should be at/near the end of a sleep slice
                (STACK_SLEEP_UNINTERRUPTIBLE | STACK_SLEEP_INTERRUPTIBLE, Some((slice, _))) => {
                    let slice_end = slice.ts + slice.dur;
                    let is_sleep_state = slice.end_state.is_some() && slice.end_state != Some(0);
                    let delta = sample.ts - slice_end;
                    let is_at_end = delta.abs() <= tolerance_ns;

                    if !is_sleep_state {
                        Some(StackViolation {
                            ts: sample.ts,
                            utid: sample.utid,
                            event_type: sample.stack_event_type,
                            message: format!(
                                "STACK_SLEEP but slice end_state={:?} (not sleep); slice=[{}, {})",
                                slice.end_state, slice.ts, slice_end
                            ),
                        })
                    } else if !is_at_end {
                        Some(StackViolation {
                            ts: sample.ts,
                            utid: sample.utid,
                            event_type: sample.stack_event_type,
                            message: format!(
                                "STACK_SLEEP delta={}ns exceeds tolerance; slice=[{}, {})",
                                delta, slice.ts, slice_end
                            ),
                        })
                    } else {
                        None
                    }
                }
                // STACK_RUNNING: should be within a running slice
                (STACK_RUNNING, Some((slice, is_within))) => {
                    let slice_end = slice.ts + slice.dur;
                    if is_within && slice.dur > 0 {
                        None
                    } else {
                        Some(StackViolation {
                            ts: sample.ts,
                            utid: sample.utid,
                            event_type: sample.stack_event_type,
                            message: format!(
                                "STACK_RUNNING not within slice; slice=[{}, {}), sample_ts={}",
                                slice.ts, slice_end, sample.ts
                            ),
                        })
                    }
                }
                // Known types but no slice found
                (STACK_SLEEP_UNINTERRUPTIBLE | STACK_SLEEP_INTERRUPTIBLE | STACK_RUNNING, None) => {
                    Some(StackViolation {
                        ts: sample.ts,
                        utid: sample.utid,
                        event_type: sample.stack_event_type,
                        message: "No sched_slice found for this utid".to_string(),
                    })
                }
                // Unknown stack_event_type
                (unknown, _) => Some(StackViolation {
                    ts: sample.ts,
                    utid: sample.utid,
                    event_type: unknown,
                    message: format!("Unknown stack_event_type: {unknown}"),
                }),
            };

            if let Some(v) = violation {
                violations.push(v);
            }
        }

        Ok(violations)
    }
}

/// Count empty names in a parquet file.
fn count_empty_names(
    path: &Path,
    id_column: &str,
    skip_column: &str,
    skip_value: i32,
) -> Result<FieldCheck> {
    if !path.exists() {
        return Ok(FieldCheck::ok(0));
    }

    let file = File::open(path)?;
    let builder = ParquetRecordBatchReaderBuilder::try_new(file)?;
    let reader = builder.build()?;

    let mut empty_count = 0i64;
    let mut total_count = 0i64;
    let mut sample_ids = Vec::new();

    for batch_result in reader {
        let batch = batch_result?;
        let schema = batch.schema();

        let name_idx = match schema.index_of("name") {
            Ok(idx) => idx,
            Err(_) => continue,
        };
        let id_idx = match schema.index_of(id_column) {
            Ok(idx) => idx,
            Err(_) => continue,
        };
        let skip_idx = schema.index_of(skip_column).ok();

        let name_array = batch
            .column(name_idx)
            .as_any()
            .downcast_ref::<StringArray>();
        let id_array = batch.column(id_idx).as_any().downcast_ref::<Int64Array>();

        if let (Some(string_array), Some(int_array)) = (name_array, id_array) {
            for i in 0..string_array.len() {
                // Skip the specified value (e.g., pid=0 or tid=0)
                if let Some(skip_i) = skip_idx {
                    if let Some(skip_arr) =
                        batch.column(skip_i).as_any().downcast_ref::<Int32Array>()
                    {
                        if !skip_arr.is_null(i) && skip_arr.value(i) == skip_value {
                            continue;
                        }
                    }
                }

                total_count += 1;

                let id_value = if int_array.is_null(i) {
                    -1
                } else {
                    int_array.value(i)
                };

                if string_array.is_null(i) || string_array.value(i).is_empty() {
                    empty_count += 1;
                    if sample_ids.len() < 10 {
                        sample_ids.push(id_value);
                    }
                }
            }
        }
    }

    Ok(FieldCheck {
        empty_count,
        total_count,
        sample_ids,
    })
}

/// Collect all values from an Int64 column into a HashSet.
fn collect_i64_column(path: &Path, column: &str, set: &mut HashSet<i64>) -> Result<()> {
    let file = File::open(path)?;
    let builder = ParquetRecordBatchReaderBuilder::try_new(file)?;
    let reader = builder.build()?;

    for batch_result in reader {
        let batch = batch_result?;
        let schema = batch.schema();
        let idx = schema.index_of(column)?;

        let array = batch.column(idx);
        if let Some(int_array) = array.as_any().downcast_ref::<Int64Array>() {
            for i in 0..int_array.len() {
                if !int_array.is_null(i) {
                    set.insert(int_array.value(i));
                }
            }
        }
    }

    Ok(())
}

/// Sched slice info for stack timing validation.
#[derive(Clone)]
struct SchedSliceInfo {
    ts: i64,
    dur: i64,
    end_state: Option<i32>,
}

/// Load sched_slice data indexed by utid for efficient lookup.
fn load_sched_slices_by_utid(
    path: &Path,
) -> Result<std::collections::HashMap<i64, Vec<SchedSliceInfo>>> {
    use std::collections::HashMap;

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
            .downcast_ref::<Int64Array>()
            .context("ts column not Int64")?;
        let dur_array = batch
            .column(dur_idx)
            .as_any()
            .downcast_ref::<Int64Array>()
            .context("dur column not Int64")?;
        let utid_array = batch
            .column(utid_idx)
            .as_any()
            .downcast_ref::<Int64Array>()
            .context("utid column not Int64")?;
        let end_state_array = batch
            .column(end_state_idx)
            .as_any()
            .downcast_ref::<Int32Array>()
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
fn load_stack_samples(path: &Path) -> Result<Vec<StackSampleInfo>> {
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
            .downcast_ref::<Int64Array>()
            .context("ts column not Int64")?;
        let utid_array = batch
            .column(utid_idx)
            .as_any()
            .downcast_ref::<Int64Array>()
            .context("utid column not Int64")?;
        let stack_event_type_array = batch
            .column(stack_event_type_idx)
            .as_any()
            .downcast_ref::<Int8Array>()
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
        // ts is before first slice
        let slice = &slices[0];
        let is_within = ts >= slice.ts && ts < slice.ts + slice.dur;
        return Some((slice, is_within));
    }

    // Check the slice just before the partition point
    let prev_slice = &slices[idx - 1];
    let is_within = ts >= prev_slice.ts && ts < prev_slice.ts + prev_slice.dur;

    Some((prev_slice, is_within))
}

// ============================================================================
// Entry Point
// ============================================================================

/// Validate a Parquet trace directory.
///
/// Checks:
/// - Schema correctness (column types)
/// - Reference integrity (foreign keys)
/// - Data validity (ranges, enum values)
/// - Required fields are set (names not empty)
pub fn validate_parquet_dir(dir: &Path) -> ValidationResult {
    let mut result = ValidationResult::default();

    // Use the unified validation framework
    let mut queries = ParquetQueries::new(dir);
    let config = ValidationConfig::default();
    run_common_validations(&mut queries, &config, &mut result);

    // Additional Parquet-specific validation: thread_state schema
    let paths = ParquetPaths::new(dir);
    validate_thread_state_schema(&paths, &mut result);

    result
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tempfile::TempDir;

    use arrow::array::{Int32Array, Int64Array, ListBuilder, StringBuilder};
    use arrow::datatypes::{DataType, Field, Schema};
    use arrow::record_batch::RecordBatch;

    use crate::validation::test_utils::create_test_parquet;

    /// Helper to create a valid process.parquet with required cmdline field.
    fn create_valid_process_parquet(dir: &Path, upid: i64, pid: i32, name: &str) {
        use arrow::array::BooleanArray;

        let process_schema = Arc::new(Schema::new(vec![
            Field::new("upid", DataType::Int64, false),
            Field::new("pid", DataType::Int32, false),
            Field::new("name", DataType::Utf8, true),
            Field::new("parent_upid", DataType::Int64, true),
            Field::new(
                "cmdline",
                DataType::List(Arc::new(Field::new("item", DataType::Utf8, true))),
                false,
            ),
            Field::new("is_kernel_thread", DataType::Boolean, false),
        ]));

        let mut name_builder = StringBuilder::new();
        name_builder.append_value(name);

        let mut cmdline_builder = ListBuilder::new(StringBuilder::new());
        cmdline_builder.values().append_value(name);
        cmdline_builder.append(true);

        let process_batch = RecordBatch::try_new(
            process_schema.clone(),
            vec![
                Arc::new(Int64Array::from(vec![upid])),
                Arc::new(Int32Array::from(vec![pid])),
                Arc::new(name_builder.finish()),
                Arc::new(Int64Array::from(vec![None::<i64>])),
                Arc::new(cmdline_builder.finish()),
                Arc::new(BooleanArray::from(vec![false])),
            ],
        )
        .unwrap();

        create_test_parquet(dir, "process.parquet", process_schema, process_batch);
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

        create_test_parquet(dir.path(), "sched_slice.parquet", schema, batch);

        // Create minimal process and thread tables
        create_valid_process_parquet(dir.path(), 1, 1000, "test");

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

        create_test_parquet(dir.path(), "thread.parquet", thread_schema, thread_batch);

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

        create_test_parquet(dir.path(), "sched_slice.parquet", schema, batch);

        // Create minimal process and thread tables
        create_valid_process_parquet(dir.path(), 1, 1000, "test");

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

        create_test_parquet(dir.path(), "thread.parquet", thread_schema, thread_batch);

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
        create_valid_process_parquet(dir.path(), 1, 1000, "test");

        // Create thread.parquet referencing non-existent upid=999
        let thread_schema = Arc::new(Schema::new(vec![
            Field::new("utid", DataType::Int64, false),
            Field::new("tid", DataType::Int32, false),
            Field::new("name", DataType::Utf8, true),
            Field::new("upid", DataType::Int64, true),
        ]));

        let mut name_builder = StringBuilder::new();
        name_builder.append_value("orphan");

        let thread_batch = RecordBatch::try_new(
            thread_schema.clone(),
            vec![
                Arc::new(Int64Array::from(vec![1])),
                Arc::new(Int32Array::from(vec![1001])),
                Arc::new(name_builder.finish()),
                Arc::new(Int64Array::from(vec![Some(999)])), // Non-existent upid
            ],
        )
        .unwrap();

        create_test_parquet(dir.path(), "thread.parquet", thread_schema, thread_batch);

        let result = validate_parquet_dir(dir.path());
        assert!(result.has_errors(), "Expected errors for missing reference");
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
    fn test_empty_process_name_parquet() {
        let dir = TempDir::new().unwrap();

        // Create process.parquet with empty name
        let process_schema = Arc::new(Schema::new(vec![
            Field::new("upid", DataType::Int64, false),
            Field::new("pid", DataType::Int32, false),
            Field::new("name", DataType::Utf8, true),
            Field::new("parent_upid", DataType::Int64, true),
            Field::new(
                "cmdline",
                DataType::List(Arc::new(Field::new("item", DataType::Utf8, true))),
                false,
            ),
        ]));

        let mut name_builder = StringBuilder::new();
        name_builder.append_value(""); // Empty name

        let mut cmdline_builder = ListBuilder::new(StringBuilder::new());
        cmdline_builder.values().append_value("test");
        cmdline_builder.append(true);

        let process_batch = RecordBatch::try_new(
            process_schema.clone(),
            vec![
                Arc::new(Int64Array::from(vec![1])),
                Arc::new(Int32Array::from(vec![1000])),
                Arc::new(name_builder.finish()),
                Arc::new(Int64Array::from(vec![None::<i64>])),
                Arc::new(cmdline_builder.finish()),
            ],
        )
        .unwrap();

        create_test_parquet(dir.path(), "process.parquet", process_schema, process_batch);

        let result = validate_parquet_dir(dir.path());
        assert!(result.has_errors(), "Expected errors for empty name");
        assert!(result.errors.iter().any(|e| matches!(
            e,
            ValidationError::InvalidValue {
                table,
                column,
                ..
            } if table == "process" && column == "name"
        )));
    }

    #[test]
    fn test_empty_thread_name_parquet() {
        let dir = TempDir::new().unwrap();

        // Create process.parquet first
        create_valid_process_parquet(dir.path(), 1, 1000, "test");

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

        create_test_parquet(dir.path(), "thread.parquet", thread_schema, thread_batch);

        let result = validate_parquet_dir(dir.path());
        assert!(result.has_errors(), "Expected errors for empty name");
        assert!(result.errors.iter().any(|e| matches!(
            e,
            ValidationError::InvalidValue {
                table,
                column,
                ..
            } if table == "thread" && column == "name"
        )));
    }

    #[test]
    fn test_empty_process_cmdline_parquet() {
        use arrow::array::BooleanArray;

        let dir = TempDir::new().unwrap();

        // Create process.parquet with empty cmdline (non-kernel-thread)
        let process_schema = Arc::new(Schema::new(vec![
            Field::new("upid", DataType::Int64, false),
            Field::new("pid", DataType::Int32, false),
            Field::new("name", DataType::Utf8, true),
            Field::new("parent_upid", DataType::Int64, true),
            Field::new(
                "cmdline",
                DataType::List(Arc::new(Field::new("item", DataType::Utf8, true))),
                false,
            ),
            Field::new("is_kernel_thread", DataType::Boolean, false),
        ]));

        let mut name_builder = StringBuilder::new();
        name_builder.append_value("test");

        // Empty cmdline list
        let mut cmdline_builder = ListBuilder::new(StringBuilder::new());
        cmdline_builder.append(true); // Empty list

        let process_batch = RecordBatch::try_new(
            process_schema.clone(),
            vec![
                Arc::new(Int64Array::from(vec![1])),
                Arc::new(Int32Array::from(vec![1000])),
                Arc::new(name_builder.finish()),
                Arc::new(Int64Array::from(vec![None::<i64>])),
                Arc::new(cmdline_builder.finish()),
                Arc::new(BooleanArray::from(vec![false])),
            ],
        )
        .unwrap();

        create_test_parquet(dir.path(), "process.parquet", process_schema, process_batch);

        let result = validate_parquet_dir(dir.path());

        // Should have error about empty cmdline
        assert!(result.errors.iter().any(|e| matches!(
            e,
            super::super::ValidationError::InvalidValue {
                table,
                column,
                ..
            } if table == "process" && column == "cmdline"
        )));
    }
}
