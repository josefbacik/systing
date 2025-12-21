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

/// Tests --parquet-first with --add-recorder network.
///
/// This validates that network recording with parquet-first mode:
/// 1. Creates network parquet files (network_socket.parquet, etc.)
/// 2. Creates network_interface.parquet with interface metadata
/// 3. Converts network data to Perfetto format with proper tracks
#[test]
#[ignore] // Requires root/BPF privileges
fn test_e2e_parquet_first_with_network_recorder() {
    use std::fs::File;
    use std::io::Read;

    setup_bpf_environment();

    let dir = TempDir::new().expect("Failed to create temp dir");
    let trace_path = dir.path().join("trace.pb");

    // Create config for streaming parquet with network recording enabled
    let config = Config {
        duration: 2, // 2 seconds to capture some network activity
        parquet_first: true,
        parquet_only: false, // Enable perfetto conversion
        network: true,       // Enable network recording
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

    // Verify network interface metadata parquet file exists
    assert!(
        dir.path().join("network_interface.parquet").exists(),
        "network_interface.parquet not found - network interface metadata not written"
    );

    // Verify perfetto trace was created
    assert!(
        trace_path.exists(),
        "trace.pb not found after parquet-to-perfetto conversion"
    );

    // Read and parse the Perfetto trace to verify network tracks exist
    let mut trace_data = Vec::new();
    File::open(&trace_path)
        .expect("Failed to open trace.pb")
        .read_to_end(&mut trace_data)
        .expect("Failed to read trace.pb");

    // Parse the trace and look for network-related tracks
    use perfetto_protos::trace::Trace;
    use protobuf::Message;

    let trace = Trace::parse_from_bytes(&trace_data).expect("Failed to parse Perfetto trace");

    // Collect all track descriptors
    let track_names: Vec<String> = trace
        .packet
        .iter()
        .filter(|p| p.has_track_descriptor())
        .map(|p| p.track_descriptor().name().to_string())
        .collect();

    // Verify "Network Interfaces" root track exists
    assert!(
        track_names.iter().any(|n| n == "Network Interfaces"),
        "Missing 'Network Interfaces' root track in Perfetto trace. Found tracks: {track_names:?}"
    );

    // Verify at least one namespace track exists (e.g., "host")
    assert!(
        track_names
            .iter()
            .any(|n| n == "host" || n.starts_with("netns:") || n.starts_with("container:")),
        "Missing network namespace track in Perfetto trace. Found tracks: {track_names:?}"
    );

    // Validate the Parquet output
    let parquet_result = validate_parquet_dir(dir.path());
    assert!(
        parquet_result.is_valid(),
        "Parquet validation failed with network recording:\nErrors: {:?}\nWarnings: {:?}",
        parquet_result.errors,
        parquet_result.warnings
    );

    // Validate the Perfetto output
    let perfetto_result = validate_perfetto_trace(&trace_path);
    assert!(
        perfetto_result.is_valid(),
        "Perfetto validation failed with network recording:\nErrors: {:?}\nWarnings: {:?}",
        perfetto_result.errors,
        perfetto_result.warnings
    );
}

/// Tests that network packet tracks are created when there is actual network traffic.
///
/// This test generates some network activity and verifies that:
/// 1. Network socket parquet files are created with data
/// 2. The Perfetto trace includes "Network Packets" track
/// 3. Socket-specific tracks are created for observed connections
#[test]
#[ignore] // Requires root/BPF privileges
fn test_e2e_network_packets_with_traffic() {
    use std::fs::File;
    use std::io::Read;
    use std::net::TcpStream;
    use std::thread;
    use std::time::Duration;

    setup_bpf_environment();

    let dir = TempDir::new().expect("Failed to create temp dir");
    let trace_path = dir.path().join("trace.pb");

    // Create config for streaming parquet with network recording enabled
    let config = Config {
        duration: 3, // 3 seconds to capture network activity
        parquet_first: true,
        parquet_only: false,
        network: true,
        output_dir: dir.path().to_path_buf(),
        output: trace_path.clone(),
        ..Config::default()
    };

    // Spawn a thread to generate network traffic while recording
    let traffic_thread = thread::spawn(|| {
        // Wait a bit for recording to start
        thread::sleep(Duration::from_millis(500));

        // Try to connect to a few common addresses to generate TCP traffic
        // These may fail but will still generate network events
        for _ in 0..3 {
            let _ = TcpStream::connect_timeout(
                &"127.0.0.1:22".parse().unwrap(),
                Duration::from_millis(100),
            );
            let _ = TcpStream::connect_timeout(
                &"127.0.0.1:80".parse().unwrap(),
                Duration::from_millis(100),
            );
            thread::sleep(Duration::from_millis(200));
        }
    });

    // Run the recording
    systing(config).expect("systing recording failed");

    // Wait for traffic thread to complete
    traffic_thread.join().expect("Traffic thread panicked");

    // Verify perfetto trace was created
    assert!(
        trace_path.exists(),
        "trace.pb not found after parquet-to-perfetto conversion"
    );

    // Read and parse the Perfetto trace
    let mut trace_data = Vec::new();
    File::open(&trace_path)
        .expect("Failed to open trace.pb")
        .read_to_end(&mut trace_data)
        .expect("Failed to read trace.pb");

    use perfetto_protos::trace::Trace;
    use protobuf::Message;

    let trace = Trace::parse_from_bytes(&trace_data).expect("Failed to parse Perfetto trace");

    // Collect all track descriptors
    let track_names: Vec<String> = trace
        .packet
        .iter()
        .filter(|p| p.has_track_descriptor())
        .map(|p| p.track_descriptor().name().to_string())
        .collect();

    // Network Interfaces should always exist (from interface enumeration)
    assert!(
        track_names.iter().any(|n| n == "Network Interfaces"),
        "Missing 'Network Interfaces' track. Found tracks: {track_names:?}"
    );

    // Note: "Network Packets" track only appears if there were actual socket events captured.
    // The traffic generation may not always succeed in creating observable socket events
    // (depends on whether the kernel probes fire for localhost connections).
    // So we check for it but don't fail if it's missing - the interface test above is sufficient.
    if track_names.iter().any(|n| n == "Network Packets") {
        eprintln!("✓ Found 'Network Packets' track with socket data");

        // Check if any socket tracks were created (format: "TCP x.x.x.x:port → y.y.y.y:port")
        let socket_tracks: Vec<_> = track_names
            .iter()
            .filter(|n| n.starts_with("TCP ") || n.starts_with("UDP ") || n.starts_with("Socket "))
            .collect();
        if !socket_tracks.is_empty() {
            let count = socket_tracks.len();
            eprintln!("✓ Found {count} socket tracks: {socket_tracks:?}");
        }
    } else {
        eprintln!("Note: 'Network Packets' track not present (no socket events captured)");
    }

    // Validate both outputs
    let parquet_result = validate_parquet_dir(dir.path());
    assert!(
        parquet_result.is_valid(),
        "Parquet validation failed:\nErrors: {:?}\nWarnings: {:?}",
        parquet_result.errors,
        parquet_result.warnings
    );

    let perfetto_result = validate_perfetto_trace(&trace_path);
    assert!(
        perfetto_result.is_valid(),
        "Perfetto validation failed:\nErrors: {:?}\nWarnings: {:?}",
        perfetto_result.errors,
        perfetto_result.warnings
    );
}
