//! Unified validation module for Parquet, DuckDB, and Perfetto traces.
//!
//! This module provides a unified validation framework using the `ValidationQueries` trait
//! that allows each format to implement validation queries using their native mechanisms:
//! - **Parquet**: Arrow columnar scans with HashSet lookups
//! - **DuckDB**: SQL queries with WHERE clauses and JOINs
//! - **Perfetto**: Streaming accumulation with post-processing queries
//!
//! # Architecture
//!
//! The key insight is that instead of abstracting data access (which would force
//! materialization and lose query pushdown), we abstract the validation queries themselves.
//! Each format implements the `ValidationQueries` trait using its native query mechanism.
//!
//! The `run_common_validations` function takes any `ValidationQueries` implementation and
//! runs the same set of checks across all formats.
//!
//! # Entry Points
//!
//! - [`validate_parquet_dir`] - Validate a Parquet trace directory
//! - [`validate_duckdb`] - Validate a DuckDB database
//! - [`validate_perfetto_trace`] - Validate a Perfetto protobuf trace
//! - [`cross_validate_parquet_perfetto`] - Cross-validate Parquet and Perfetto

mod config;
pub mod cross_validate;
mod duckdb_queries;
mod parquet_queries;
mod perfetto_queries;
mod perfetto_reader;
mod queries;
mod result;
mod runner;
#[cfg(test)]
mod test_utils;

// Re-export configuration
pub use config::ValidationConfig;

// Re-export result types
pub use result::{ValidationError, ValidationResult, ValidationWarning};

// Re-export query trait and result types
pub use queries::{
    CmdlineStats, FieldCheck, OrphanCheck, SchemaResult, StackViolation, ValidationQueries,
    STACK_RUNNING, STACK_SLEEP,
};

// Re-export query implementations
pub use duckdb_queries::DuckDbQueries;
pub use parquet_queries::ParquetQueries;
pub use perfetto_queries::PerfettoQueries;

// Re-export runner
pub use runner::run_common_validations;

// Re-export entry point functions
pub use cross_validate::cross_validate_parquet_perfetto;
pub use duckdb_queries::validate_duckdb;
pub use parquet_queries::validate_parquet_dir;
pub use perfetto_queries::validate_perfetto_trace;

// Re-export perfetto reader utilities (used by cross_validate)
pub use perfetto_reader::{open_trace_reader, TracePacketIterator};
