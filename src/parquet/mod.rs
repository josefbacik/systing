//! Parquet I/O operations.
//!
//! This module provides functionality for reading and writing trace data
//! in Parquet format.

pub mod writer;

// Re-export ParquetPaths from the crate root for backwards compatibility
pub use crate::ParquetPaths;
pub use writer::StreamingParquetWriter;
