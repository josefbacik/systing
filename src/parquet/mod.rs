//! Parquet I/O operations.
//!
//! This module provides functionality for reading and writing trace data
//! in Parquet format.

pub mod writer;

// Re-export ParquetPaths from the library for backwards compatibility
pub use systing::ParquetPaths;
pub use writer::StreamingParquetWriter;
