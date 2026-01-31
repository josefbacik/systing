//! Cross-validation between Parquet and Perfetto trace files.
//!
//! This module provides cross-validation to verify that conversion from
//! Parquet to Perfetto preserved data correctly.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::path::Path;

use arrow::array::{Array, Int32Array};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

use crate::parquet_paths::ParquetPaths;

use super::perfetto_reader::{open_trace_reader, TracePacketIterator};
use super::result::{ValidationError, ValidationResult, ValidationWarning};

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

/// Collect end_state value distribution from sched_slice.parquet.
/// NULL values are counted as 0 (TASK_RUNNING/preempted).
pub fn collect_end_state_counts(paths: &ParquetPaths) -> anyhow::Result<HashMap<i64, u64>> {
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
        if let Some(int_array) = end_state_array.as_any().downcast_ref::<Int32Array>() {
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
pub fn count_parquet_stack_samples(paths: &ParquetPaths) -> anyhow::Result<u64> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tempfile::TempDir;

    use arrow::array::{Int32Array, Int64Array};
    use arrow::datatypes::{DataType, Field, Schema};
    use arrow::record_batch::RecordBatch;

    use crate::validation::test_utils::create_test_parquet;

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

        // Create slices with:
        // - 2 with end_state=0 (TASK_RUNNING)
        // - 1 with end_state=1 (TASK_INTERRUPTIBLE)
        // - 1 with end_state=NULL (counts as 0)
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Int64Array::from(vec![1000, 2000, 3000, 4000])),
                Arc::new(Int64Array::from(vec![100, 100, 100, 100])),
                Arc::new(Int32Array::from(vec![0, 0, 0, 0])),
                Arc::new(Int64Array::from(vec![1, 1, 1, 1])),
                Arc::new(Int32Array::from(vec![Some(0), Some(0), Some(1), None])),
                Arc::new(Int32Array::from(vec![120, 120, 120, 120])),
            ],
        )
        .unwrap();

        create_test_parquet(dir.path(), "sched_slice.parquet", schema, batch);

        let paths = ParquetPaths::new(dir.path());
        let counts = collect_end_state_counts(&paths).unwrap();

        assert_eq!(counts.get(&0), Some(&3)); // 2 explicit + 1 NULL
        assert_eq!(counts.get(&1), Some(&1));
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

        create_test_parquet(dir.path(), "sched_slice.parquet", schema, batch);

        let paths = ParquetPaths::new(dir.path());
        let counts = collect_end_state_counts(&paths).unwrap();

        assert!(counts.is_empty());
    }

    #[test]
    fn test_collect_end_state_counts_no_file() {
        let dir = TempDir::new().unwrap();
        // Don't create the file

        let paths = ParquetPaths::new(dir.path());
        let counts = collect_end_state_counts(&paths).unwrap();

        assert!(counts.is_empty());
    }
}
