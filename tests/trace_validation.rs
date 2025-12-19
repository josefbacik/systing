//! Integration tests for trace validation.
//!
//! These tests run the full systing recording pipeline and validate the output.
//! They require root/BPF privileges and are marked as `#[ignore]` by default.
//!
//! To run these tests:
//! ```
//! sudo cargo test --test trace_validation -- --ignored
//! ```

use std::path::Path;
use systing::{
    bump_memlock_rlimit, systing, validate_parquet_dir, validate_perfetto_trace, Config,
};
use tempfile::TempDir;

/// Helper to set up the environment for BPF tests.
fn setup_bpf_environment() {
    bump_memlock_rlimit().expect("Failed to bump memlock rlimit");
}

#[test]
#[ignore] // Requires root/BPF privileges
fn test_e2e_parquet_validation() {
    setup_bpf_environment();

    let dir = TempDir::new().expect("Failed to create temp dir");

    // Create config for a 1-second trace with Parquet output only
    let config = Config {
        duration: 1,
        parquet_only: true,
        output_dir: dir.path().to_path_buf(),
        output: dir.path().join("trace.pb"),
        ..Config::default()
    };

    // Run the recording
    systing(config).expect("systing recording failed");

    // Verify essential files exist
    assert!(
        dir.path().join("process.parquet").exists(),
        "process.parquet not found"
    );
    assert!(
        dir.path().join("thread.parquet").exists(),
        "thread.parquet not found"
    );
    assert!(
        dir.path().join("sched_slice.parquet").exists(),
        "sched_slice.parquet not found"
    );

    // Validate the Parquet output using the library
    let result = validate_parquet_dir(dir.path());
    assert!(
        result.is_valid(),
        "Parquet validation failed:\nErrors: {:?}\nWarnings: {:?}",
        result.errors,
        result.warnings
    );
}

#[test]
#[ignore] // Requires root/BPF privileges
fn test_e2e_perfetto_validation() {
    setup_bpf_environment();

    let dir = TempDir::new().expect("Failed to create temp dir");
    let trace_path = dir.path().join("trace.pb");

    // Create config for a 1-second trace with Perfetto output
    let config = Config {
        duration: 1,
        output_dir: dir.path().to_path_buf(),
        output: trace_path.clone(),
        ..Config::default()
    };

    // Run the recording
    systing(config).expect("systing recording failed");

    // Verify trace file exists
    assert!(trace_path.exists(), "trace.pb not found");

    // Validate the Perfetto output using the library
    let result = validate_perfetto_trace(&trace_path);
    assert!(
        result.is_valid(),
        "Perfetto validation failed:\nErrors: {:?}\nWarnings: {:?}",
        result.errors,
        result.warnings
    );
}

#[test]
#[ignore] // Requires root/BPF privileges
fn test_e2e_both_validations() {
    setup_bpf_environment();

    let dir = TempDir::new().expect("Failed to create temp dir");
    let trace_path = dir.path().join("trace.pb");

    // Create config for a 1-second trace
    let config = Config {
        duration: 1,
        output_dir: dir.path().to_path_buf(),
        output: trace_path.clone(),
        ..Config::default()
    };

    // Run the recording
    systing(config).expect("systing recording failed");

    // Validate Parquet
    let parquet_result = validate_parquet_dir(dir.path());
    assert!(
        parquet_result.is_valid(),
        "Parquet validation failed:\nErrors: {:?}\nWarnings: {:?}",
        parquet_result.errors,
        parquet_result.warnings
    );

    // Validate Perfetto
    let perfetto_result = validate_perfetto_trace(&trace_path);
    assert!(
        perfetto_result.is_valid(),
        "Perfetto validation failed:\nErrors: {:?}\nWarnings: {:?}",
        perfetto_result.errors,
        perfetto_result.warnings
    );
}

#[test]
fn test_validate_nonexistent_path() {
    // This test doesn't require privileges - validates the library handles nonexistent paths
    let result = validate_parquet_dir(Path::new("/nonexistent/path"));

    // The validation should either return errors or handle gracefully
    // Since parquet_dir validation creates a ParquetPaths which just stores the path,
    // the actual errors would show up during validation checks
    // For now, we just verify it doesn't panic
    let _ = result;
}

#[test]
fn test_validate_unrecognized_file() {
    // This test doesn't require privileges - validates error handling for wrong file type
    use std::io::Write;

    let dir = TempDir::new().expect("Failed to create temp dir");
    let bad_file = dir.path().join("test.txt");

    std::fs::File::create(&bad_file)
        .unwrap()
        .write_all(b"not a trace file")
        .unwrap();

    // Validate as Perfetto trace - should not panic, may return errors
    let result = validate_perfetto_trace(&bad_file);

    // The validation should fail for an invalid file
    assert!(
        result.has_errors(),
        "Expected validation errors for invalid file, got: {result:?}"
    );
}
