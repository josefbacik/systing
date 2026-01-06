//! Validation result types.
//!
//! This module defines the core types for validation results:
//! - `ValidationResult` - container for errors and warnings
//! - `ValidationError` - error types
//! - `ValidationWarning` - warning types

use std::fmt;

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
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
pub enum ValidationWarning {
    /// A file is empty (no rows).
    EmptyTable { table: String },
    /// An optional column is missing.
    MissingColumn { table: String, column: String },
    /// Too many errors of the same type - only showing first N.
    TooManyErrors { table: String, shown: usize },
    /// Some entities have empty names.
    EmptyNames { table: String, count: i64 },
    /// Stack timing violations detected.
    StackTimingViolations { sample_type: String, count: i64 },
    /// A column that should have data is entirely NULL.
    AllNullColumn {
        table: String,
        column: String,
        total_rows: i64,
    },
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
            ValidationWarning::EmptyNames { table, count } => {
                write!(f, "{table}: {count} entries have empty names")
            }
            ValidationWarning::StackTimingViolations { sample_type, count } => {
                write!(
                    f,
                    "stack_sample: {count} {sample_type} samples have timing violations"
                )
            }
            ValidationWarning::AllNullColumn {
                table,
                column,
                total_rows,
            } => {
                write!(
                    f,
                    "{table}.{column}: all {total_rows} rows have NULL values - \
                     thread state transitions may not be captured correctly"
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cross_validation_error_display() {
        let error = ValidationError::CrossValidationError {
            message: "Test mismatch".to_string(),
        };
        assert_eq!(format!("{error}"), "Cross-validation: Test mismatch");
    }

    #[test]
    fn test_wrong_column_type_display() {
        let error = ValidationError::WrongColumnType {
            table: "sched_slice".to_string(),
            column: "end_state".to_string(),
            expected: "Int32".to_string(),
            got: "Utf8".to_string(),
        };
        assert_eq!(
            format!("{error}"),
            "sched_slice.end_state: expected type Int32, got Utf8"
        );
    }

    #[test]
    fn test_stack_timing_violation_sleep_display() {
        let error = ValidationError::StackTimingViolation {
            ts: 1000,
            utid: 42,
            stack_event_type: 0, // STACK_SLEEP
            message: "not at slice end".to_string(),
        };
        assert_eq!(
            format!("{error}"),
            "Stack timing: utid=42 ts=1000 type=STACK_SLEEP: not at slice end"
        );
    }

    #[test]
    fn test_stack_timing_violation_running_display() {
        let error = ValidationError::StackTimingViolation {
            ts: 2000,
            utid: 99,
            stack_event_type: 1, // STACK_RUNNING
            message: "outside running slice".to_string(),
        };
        assert_eq!(
            format!("{error}"),
            "Stack timing: utid=99 ts=2000 type=STACK_RUNNING: outside running slice"
        );
    }

    #[test]
    fn test_all_null_column_warning_display() {
        let warning = ValidationWarning::AllNullColumn {
            table: "process".to_string(),
            column: "cmdline".to_string(),
            total_rows: 100,
        };
        assert_eq!(
            format!("{warning}"),
            "process.cmdline: all 100 rows have NULL values - \
             thread state transitions may not be captured correctly"
        );
    }

    #[test]
    fn test_validation_result_methods() {
        let mut result = ValidationResult::default();
        assert!(result.is_valid());
        assert!(!result.has_errors());
        assert!(!result.has_warnings());

        result.add_warning(ValidationWarning::EmptyTable {
            table: "test".to_string(),
        });
        assert!(result.is_valid());
        assert!(result.has_warnings());

        result.add_error(ValidationError::CrossValidationError {
            message: "test".to_string(),
        });
        assert!(!result.is_valid());
        assert!(result.has_errors());
    }
}
