//! Shared test utilities for validation tests.
//!
//! This module provides common helper functions used across validation test modules.

use std::fs::File;
use std::path::Path;
use std::sync::Arc;

use arrow::datatypes::Schema;
use arrow::record_batch::RecordBatch;
use parquet::arrow::ArrowWriter;
use parquet::basic::Compression;
use parquet::file::properties::WriterProperties;

/// Create a test Parquet file in the given directory.
///
/// # Panics
///
/// Panics if file creation or writing fails. This is intentional for test code
/// where failures should cause test failure.
pub fn create_test_parquet(dir: &Path, name: &str, schema: Arc<Schema>, batch: RecordBatch) {
    let path = dir.join(name);
    let file = File::create(path).expect("Failed to create test parquet file");
    let props = WriterProperties::builder()
        .set_compression(Compression::SNAPPY)
        .build();
    let mut writer =
        ArrowWriter::try_new(file, schema, Some(props)).expect("Failed to create arrow writer");
    writer.write(&batch).expect("Failed to write batch");
    writer.close().expect("Failed to close writer");
}
