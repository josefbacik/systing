//! Parquet I/O operations.
//!
//! This module provides functionality for reading and writing trace data
//! in Parquet format.

pub mod paths;
pub mod writer;

pub use paths::ParquetPaths;
pub use writer::StreamingParquetWriter;
