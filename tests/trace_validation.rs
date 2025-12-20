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

/// Tests --parquet-first with --parquet-only (streaming parquet, no perfetto conversion).
///
/// This tests the streaming parquet writer that writes directly to parquet files
/// during recording, which is faster for large traces.
#[test]
#[ignore] // Requires root/BPF privileges
fn test_e2e_parquet_first_parquet_only() {
    setup_bpf_environment();

    let dir = TempDir::new().expect("Failed to create temp dir");

    // Create config for streaming parquet with no perfetto conversion
    let config = Config {
        duration: 1,
        parquet_first: true,
        parquet_only: true,
        output_dir: dir.path().to_path_buf(),
        output: dir.path().join("trace.pb"),
        ..Config::default()
    };

    // Run the recording
    systing(config).expect("systing recording failed");

    // Verify essential parquet files exist
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

    // Verify perfetto trace was NOT created (parquet_only mode)
    assert!(
        !dir.path().join("trace.pb").exists(),
        "trace.pb should not exist in parquet_only mode"
    );

    // Validate the Parquet output
    let result = validate_parquet_dir(dir.path());
    assert!(
        result.is_valid(),
        "Parquet validation failed with parquet_first:\nErrors: {:?}\nWarnings: {:?}",
        result.errors,
        result.warnings
    );
}

/// Tests --parquet-first with perfetto conversion (streaming parquet + parquet-to-perfetto).
///
/// This tests the full parquet-first workflow: streaming writes during recording,
/// followed by conversion to Perfetto format for compatibility.
#[test]
#[ignore] // Requires root/BPF privileges
fn test_e2e_parquet_first_with_perfetto() {
    setup_bpf_environment();

    let dir = TempDir::new().expect("Failed to create temp dir");
    let trace_path = dir.path().join("trace.pb");

    // Create config for streaming parquet with perfetto conversion
    let config = Config {
        duration: 1,
        parquet_first: true,
        parquet_only: false, // Enable perfetto conversion
        output_dir: dir.path().to_path_buf(),
        output: trace_path.clone(),
        ..Config::default()
    };

    // Run the recording
    systing(config).expect("systing recording failed");

    // Verify essential parquet files exist
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

    // Verify perfetto trace was created
    assert!(
        trace_path.exists(),
        "trace.pb not found after parquet-to-perfetto conversion"
    );

    // Validate the Parquet output
    let parquet_result = validate_parquet_dir(dir.path());
    assert!(
        parquet_result.is_valid(),
        "Parquet validation failed with parquet_first:\nErrors: {:?}\nWarnings: {:?}",
        parquet_result.errors,
        parquet_result.warnings
    );

    // Validate the Perfetto output
    let perfetto_result = validate_perfetto_trace(&trace_path);
    assert!(
        perfetto_result.is_valid(),
        "Perfetto validation failed after parquet-to-perfetto conversion:\nErrors: {:?}\nWarnings: {:?}",
        perfetto_result.errors,
        perfetto_result.warnings
    );
}

/// Tests that both parquet paths (legacy and parquet-first) produce valid output.
///
/// This is a sanity check that the parquet-first streaming path produces
/// structurally equivalent output to the legacy batch path.
#[test]
#[ignore] // Requires root/BPF privileges
fn test_e2e_parquet_first_vs_legacy_both_valid() {
    setup_bpf_environment();

    // Test legacy path (parquet_first: false)
    let legacy_dir = TempDir::new().expect("Failed to create temp dir");
    let legacy_config = Config {
        duration: 1,
        parquet_only: true,
        parquet_first: false,
        output_dir: legacy_dir.path().to_path_buf(),
        output: legacy_dir.path().join("trace.pb"),
        ..Config::default()
    };

    systing(legacy_config).expect("systing legacy recording failed");

    let legacy_result = validate_parquet_dir(legacy_dir.path());
    assert!(
        legacy_result.is_valid(),
        "Legacy parquet validation failed:\nErrors: {:?}\nWarnings: {:?}",
        legacy_result.errors,
        legacy_result.warnings
    );

    // Test parquet-first path (parquet_first: true)
    let streaming_dir = TempDir::new().expect("Failed to create temp dir");
    let streaming_config = Config {
        duration: 1,
        parquet_only: true,
        parquet_first: true,
        output_dir: streaming_dir.path().to_path_buf(),
        output: streaming_dir.path().join("trace.pb"),
        ..Config::default()
    };

    systing(streaming_config).expect("systing streaming recording failed");

    let streaming_result = validate_parquet_dir(streaming_dir.path());
    assert!(
        streaming_result.is_valid(),
        "Parquet-first streaming validation failed:\nErrors: {:?}\nWarnings: {:?}",
        streaming_result.errors,
        streaming_result.warnings
    );

    // Both paths should produce the same core files
    let core_files = ["process.parquet", "thread.parquet", "sched_slice.parquet"];
    for file in &core_files {
        assert!(
            legacy_dir.path().join(file).exists(),
            "Legacy path missing {file}"
        );
        assert!(
            streaming_dir.path().join(file).exists(),
            "Streaming path missing {file}"
        );
    }
}
