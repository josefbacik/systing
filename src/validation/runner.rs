//! Common validation runner.
//!
//! This module contains the `run_common_validations` function that runs
//! the same set of validation checks across all formats using the
//! `ValidationQueries` trait.

use super::config::ValidationConfig;
use super::queries::{
    ValidationQueries, STACK_RUNNING, STACK_SLEEP_INTERRUPTIBLE, STACK_SLEEP_UNINTERRUPTIBLE,
};
use super::result::{ValidationError, ValidationResult, ValidationWarning};

/// Valid counter unit values (from perfetto_protos CounterDescriptor::Unit and custom units).
const VALID_COUNTER_UNITS: &[&str] = &["", "count", "time_ns", "size_bytes", "Hz"];

/// Run common validation checks on any format that implements `ValidationQueries`.
pub fn run_common_validations<Q: ValidationQueries>(
    queries: &mut Q,
    config: &ValidationConfig,
    result: &mut ValidationResult,
) {
    validate_reference_integrity(queries, config, result);
    validate_required_fields(queries, config, result);
    validate_schema(queries, result);
    validate_stack_timing(queries, config, result);
}

/// Validate reference integrity (foreign key relationships).
fn validate_reference_integrity<Q: ValidationQueries>(
    queries: &mut Q,
    _config: &ValidationConfig,
    result: &mut ValidationResult,
) {
    // Thread → Process
    match queries.count_orphan_thread_upids() {
        Ok(orphans) => {
            if orphans.has_orphans() {
                // Report one error with the first orphan ID as an example
                if let Some(&upid) = orphans.sample_orphan_ids.first() {
                    result.add_error(ValidationError::MissingReference {
                        table: "thread".into(),
                        column: "upid".into(),
                        value: upid,
                        referenced_table: "process".into(),
                    });
                }
            }
        }
        Err(e) => {
            result.add_error(ValidationError::ReadError {
                table: "thread".into(),
                message: format!("Failed to check upid references: {e}"),
            });
        }
    }

    // Sched → Thread
    match queries.count_orphan_sched_utids() {
        Ok(orphans) => {
            if orphans.has_orphans() {
                // Report one error with the first orphan ID as an example
                if let Some(&utid) = orphans.sample_orphan_ids.first() {
                    result.add_error(ValidationError::MissingReference {
                        table: "sched_slice".into(),
                        column: "utid".into(),
                        value: utid,
                        referenced_table: "thread".into(),
                    });
                }
            }
        }
        Err(e) => {
            result.add_error(ValidationError::ReadError {
                table: "sched_slice".into(),
                message: format!("Failed to check utid references: {e}"),
            });
        }
    }
}

/// Validate required fields are populated.
fn validate_required_fields<Q: ValidationQueries>(
    queries: &mut Q,
    _config: &ValidationConfig,
    result: &mut ValidationResult,
) {
    // Process names
    match queries.count_empty_process_names() {
        Ok(check) => {
            if check.has_empty() {
                // Get the first ID for the error message
                let id_msg = if let Some(&id) = check.sample_ids.first() {
                    format!(" (upid={})", id)
                } else {
                    String::new()
                };
                result.add_error(ValidationError::InvalidValue {
                    table: "process".into(),
                    column: "name".into(),
                    message: format!("process name is empty{}", id_msg),
                });
            }
        }
        Err(e) => {
            result.add_error(ValidationError::ReadError {
                table: "process".into(),
                message: format!("Failed to check process names: {e}"),
            });
        }
    }

    // Thread names
    match queries.count_empty_thread_names() {
        Ok(check) => {
            if check.has_empty() {
                // Get the first ID for the error message
                let id_msg = if let Some(&id) = check.sample_ids.first() {
                    format!(" (utid={})", id)
                } else {
                    String::new()
                };
                result.add_error(ValidationError::InvalidValue {
                    table: "thread".into(),
                    column: "name".into(),
                    message: format!("thread name is empty{}", id_msg),
                });
            }
        }
        Err(e) => {
            result.add_error(ValidationError::ReadError {
                table: "thread".into(),
                message: format!("Failed to check thread names: {e}"),
            });
        }
    }

    // Cmdline
    match queries.get_cmdline_stats() {
        Ok(stats) => {
            if !stats.has_column {
                result.add_error(ValidationError::InvalidValue {
                    table: "process".into(),
                    column: "cmdline".into(),
                    message: "missing required column: cmdline".into(),
                });
            } else if stats.mostly_empty() {
                result.add_warning(ValidationWarning::AllNullColumn {
                    table: "process".into(),
                    column: "cmdline".into(),
                    total_rows: stats.empty_count,
                });
            }
        }
        Err(e) => {
            result.add_error(ValidationError::ReadError {
                table: "process".into(),
                message: format!("Failed to check cmdline: {e}"),
            });
        }
    }
}

/// Validate schema correctness.
fn validate_schema<Q: ValidationQueries>(queries: &mut Q, result: &mut ValidationResult) {
    // Check end_state column
    match queries.check_end_state_schema() {
        Ok(schema) => {
            if schema.exists && !schema.type_valid {
                result.add_error(ValidationError::WrongColumnType {
                    table: "sched_slice".into(),
                    column: "end_state".into(),
                    expected: schema.expected_type.into(),
                    got: schema.actual_type.unwrap_or_else(|| "unknown".into()),
                });
            }
            // Missing end_state column is a warning, not an error
            if !schema.exists {
                result.add_warning(ValidationWarning::MissingColumn {
                    table: "sched_slice".into(),
                    column: "end_state".into(),
                });
            }
        }
        Err(e) => {
            result.add_error(ValidationError::ReadError {
                table: "sched_slice".into(),
                message: format!("Failed to check end_state schema: {e}"),
            });
        }
    }

    // Check counter_track unit values
    match queries.get_counter_unit_values() {
        Ok(values) => {
            for unit in values.into_iter().flatten() {
                if !VALID_COUNTER_UNITS.contains(&unit.as_str()) {
                    result.add_error(ValidationError::InvalidEnumValue {
                        table: "counter_track".into(),
                        column: "unit".into(),
                        value: unit,
                    });
                    // Only report first error
                    break;
                }
            }
        }
        Err(_) => {
            // Counter track is optional, so missing is fine
        }
    }
}

/// Validate stack timing constraints.
fn validate_stack_timing<Q: ValidationQueries>(
    queries: &mut Q,
    config: &ValidationConfig,
    result: &mut ValidationResult,
) {
    match queries.find_stack_timing_violations(config.stack_timing_tolerance_ns) {
        Ok(violations) => {
            let sleep_count = violations
                .iter()
                .filter(|v| {
                    v.event_type == STACK_SLEEP_UNINTERRUPTIBLE
                        || v.event_type == STACK_SLEEP_INTERRUPTIBLE
                })
                .count();
            let running_count = violations
                .iter()
                .filter(|v| v.event_type == STACK_RUNNING)
                .count();

            // Stack timing violations are reported as warnings, not errors.
            // BPF event loss (missed sched/IRQ events) creates gaps in sched_slice data,
            // causing valid stack samples to appear outside any slice. Under load,
            // especially with network recording, significant event loss is expected.
            if sleep_count > 0 {
                result.add_warning(ValidationWarning::StackTimingViolations {
                    sample_type: "STACK_SLEEP (uninterruptible + interruptible)".into(),
                    count: sleep_count as i64,
                });
            }
            if running_count > 0 {
                result.add_warning(ValidationWarning::StackTimingViolations {
                    sample_type: "STACK_RUNNING".into(),
                    count: running_count as i64,
                });
            }

            // Log first few individual violations for diagnostics
            for v in violations.iter().take(5) {
                let type_name = match v.event_type {
                    STACK_SLEEP_UNINTERRUPTIBLE => "SLEEP_UNINTERRUPTIBLE",
                    STACK_RUNNING => "RUNNING",
                    STACK_SLEEP_INTERRUPTIBLE => "SLEEP_INTERRUPTIBLE",
                    _ => "UNKNOWN",
                };
                eprintln!(
                    "  stack timing: utid={} ts={} type={type_name}: {}",
                    v.utid, v.ts, v.message
                );
            }
        }
        Err(_) => {
            // Stack sample table is optional
        }
    }
}
