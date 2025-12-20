//! Systing library - shared modules for systing and systing-analyze binaries.
//!
//! This library provides common functionality used by both the main `systing`
//! tracing binary and the `systing-analyze` analysis tool.
//!
//! # Modules
//!
//! - [`duckdb`] - DuckDB database generation from Parquet trace files
//! - [`parquet_paths`] - Path management for Parquet trace files
//! - [`validate`] - Trace validation for Parquet and Perfetto formats
//! - [`systing`] - Core tracing functionality
//!
//! # Example
//!
//! ```no_run
//! use systing::{ParquetPaths, duckdb};
//! use std::path::Path;
//!
//! // Get paths to all parquet files in a trace directory
//! let paths = ParquetPaths::new(Path::new("./traces"));
//!
//! // Convert parquet files to a DuckDB database
//! duckdb::parquet_to_duckdb(
//!     Path::new("./traces"),
//!     Path::new("./trace.duckdb"),
//!     "my_trace",
//! ).expect("Failed to create DuckDB database");
//! ```

// Core library modules
pub mod duckdb;
pub mod parquet_paths;
pub mod validate;

// Tracing modules (previously in binary only)
pub mod events;
pub mod network_recorder;
pub mod parquet;
pub mod parquet_to_perfetto;
pub mod parquet_writer;
pub mod perf;
pub mod perf_recorder;
pub mod perfetto;
pub mod pystacks;
pub mod record;
pub mod ringbuf;
pub mod sched;
pub mod session_recorder;
pub mod stack_recorder;
pub mod systing_core;
pub mod trace;
pub mod utid;

// Re-export for convenience
pub use parquet_paths::ParquetPaths;
pub use systing_core::{bump_memlock_rlimit, get_available_recorders, systing, Config};
pub use validate::{
    validate_parquet_dir, validate_perfetto_trace, ValidationError, ValidationResult,
    ValidationWarning,
};
