//! Systing library - shared modules for systing and systing-analyze binaries.
//!
//! This library provides common functionality used by both the main `systing`
//! tracing binary and the `systing-analyze` analysis tool.
//!
//! # Modules
//!
//! - [`duckdb`] - DuckDB database generation from Parquet trace files
//! - [`parquet_paths`] - Path management for Parquet trace files
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

pub mod duckdb;
pub mod parquet_paths;

// Re-export for convenience
pub use parquet_paths::ParquetPaths;
