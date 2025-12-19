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
use std::process::Command;
use tempfile::TempDir;

/// Helper to build systing if needed.
fn ensure_built() {
    let status = Command::new("cargo")
        .args(["build", "--release"])
        .status()
        .expect("Failed to run cargo build");

    if !status.success() {
        panic!("Failed to build systing");
    }
}

/// Run systing with the given arguments and return the output directory.
fn run_systing(args: &[&str], output_dir: &Path) -> bool {
    let mut cmd = Command::new("./target/release/systing");
    cmd.args(args);
    cmd.arg("--output-dir").arg(output_dir);

    let output = cmd.output().expect("Failed to run systing");

    if !output.status.success() {
        eprintln!(
            "systing failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return false;
    }

    true
}

/// Run systing-analyze validate on the given path.
fn run_validate(path: &Path) -> (bool, String) {
    let output = Command::new("./target/release/systing-analyze")
        .args(["validate", path.to_str().unwrap()])
        .output()
        .expect("Failed to run systing-analyze validate");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    (output.status.success(), format!("{stdout}\n{stderr}"))
}

#[test]
#[ignore] // Requires root/BPF privileges
fn test_e2e_parquet_validation() {
    ensure_built();

    let dir = TempDir::new().expect("Failed to create temp dir");

    // Record a 1-second trace with Parquet output only
    let success = run_systing(&["--parquet-only", "--duration", "1"], dir.path());
    assert!(success, "systing recording failed");

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

    // Validate the Parquet output
    let (valid, output) = run_validate(dir.path());
    assert!(valid, "Parquet validation failed:\n{output}");
}

#[test]
#[ignore] // Requires root/BPF privileges
fn test_e2e_perfetto_validation() {
    ensure_built();

    let dir = TempDir::new().expect("Failed to create temp dir");
    let trace_path = dir.path().join("trace.pb");

    // Record a 1-second trace with Perfetto output
    let mut cmd = Command::new("./target/release/systing");
    cmd.args(["--duration", "1"]);
    cmd.arg("--output-dir").arg(dir.path());
    cmd.arg("--output").arg(&trace_path);

    let output = cmd.output().expect("Failed to run systing");
    assert!(
        output.status.success(),
        "systing recording failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify trace file exists
    assert!(trace_path.exists(), "trace.pb not found");

    // Validate the Perfetto output
    let (valid, output) = run_validate(&trace_path);
    assert!(valid, "Perfetto validation failed:\n{output}");
}

#[test]
#[ignore] // Requires root/BPF privileges
fn test_e2e_both_validations() {
    ensure_built();

    let dir = TempDir::new().expect("Failed to create temp dir");
    let trace_path = dir.path().join("trace.pb");

    // Record a 1-second trace
    let mut cmd = Command::new("./target/release/systing");
    cmd.args(["--duration", "1"]);
    cmd.arg("--output-dir").arg(dir.path());
    cmd.arg("--output").arg(&trace_path);

    let output = cmd.output().expect("Failed to run systing");
    assert!(
        output.status.success(),
        "systing recording failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Validate Parquet
    let (parquet_valid, parquet_output) = run_validate(dir.path());
    assert!(
        parquet_valid,
        "Parquet validation failed:\n{parquet_output}"
    );

    // Validate Perfetto
    let (perfetto_valid, perfetto_output) = run_validate(&trace_path);
    assert!(
        perfetto_valid,
        "Perfetto validation failed:\n{perfetto_output}"
    );
}

#[test]
fn test_validate_nonexistent_path() {
    // This test doesn't require privileges
    let output = Command::new("cargo")
        .args([
            "run",
            "--release",
            "--bin",
            "systing-analyze",
            "--",
            "validate",
            "/nonexistent/path",
        ])
        .output()
        .expect("Failed to run command");

    assert!(
        !output.status.success(),
        "Expected failure for nonexistent path"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Path not found") || stderr.contains("not found"),
        "Expected 'Path not found' error, got: {stderr}"
    );
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

    let output = Command::new("cargo")
        .args([
            "run",
            "--release",
            "--bin",
            "systing-analyze",
            "--",
            "validate",
            bad_file.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to run command");

    assert!(
        !output.status.success(),
        "Expected failure for unrecognized file type"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Unrecognized file type"),
        "Expected 'Unrecognized file type' error, got: {stderr}"
    );
}
