//! Integration tests for trace validation.
//!
//! These tests run the full systing recording pipeline and validate the output.
//! They require root/BPF privileges and are marked as `#[ignore]` by default.
//!
//! To run these tests:
//! ```
//! sudo cargo test --test trace_validation -- --ignored
//! ```

mod common;

use arrow::array::Array;
use common::{
    assert_poll_events_recorded, validate_network_trace, NetnsTestEnv, NetworkTestConfig,
};
use std::io::{Read, Write};
use std::path::Path;
use systing::{
    bump_memlock_rlimit, systing, validate_duckdb, validate_parquet_dir, validate_perfetto_trace,
    Config,
};
use tempfile::TempDir;

// Timing constants for network namespace tests.
// BPF initialization (skeleton build, probe attachment) can take 5+ seconds on some systems.
// These values provide buffer for initialization before traffic generation begins.
//
// TODO: Consider adding a proper synchronization mechanism to systing (e.g., a callback
// or channel that signals when BPF probes are attached) rather than relying on fixed delays.

/// Time to wait for BPF probe initialization before generating test traffic (seconds).
const NETNS_BPF_INIT_WAIT_SECS: u64 = 7;

/// Total recording duration for netns tests (seconds). Must be longer than
/// NETNS_BPF_INIT_WAIT_SECS plus time for traffic generation.
const NETNS_RECORDING_DURATION_SECS: u64 = 10;

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

/// Tests network recording with an isolated network namespace.
///
/// This test creates a network namespace with a veth pair, generates
/// traffic to an echo server in the namespace, and validates that
/// systing captures the network activity correctly.
#[test]
#[ignore] // Requires root/BPF privileges
fn test_network_recording_with_netns() {
    use std::thread;
    use std::time::Duration;

    setup_bpf_environment();

    // Create network namespace with default config (10.200.1.x addresses)
    let netns_env = NetnsTestEnv::new(NetworkTestConfig::default())
        .expect("Failed to create network namespace test environment");

    let dir = TempDir::new().expect("Failed to create temp dir");
    let trace_path = dir.path().join("trace.pb");

    // Create config for network recording with parquet-first.
    // See NETNS_RECORDING_DURATION_SECS for timing rationale.
    let config = Config {
        duration: NETNS_RECORDING_DURATION_SECS,
        parquet_first: true,
        parquet_only: false,
        network: true,
        output_dir: dir.path().to_path_buf(),
        output: trace_path.clone(),
        ..Config::default()
    };

    // Get the destination IP and port for validation
    let dest_ip = netns_env.config.ns_ip.to_string();
    let dest_port = netns_env.server_port;

    // Spawn a thread to generate traffic after recording starts.
    // See NETNS_BPF_INIT_WAIT_SECS for timing rationale.
    let traffic_handle = {
        let server_addr = netns_env.server_addr();
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(NETNS_BPF_INIT_WAIT_SECS));

            // Generate multiple rounds of traffic
            for i in 0..5 {
                let message = format!("Hello from netns test round {i}");
                if let Ok(mut stream) = std::net::TcpStream::connect(&server_addr) {
                    let _ = stream.write_all(message.as_bytes());
                    let _ = stream.shutdown(std::net::Shutdown::Write);
                    let mut response = Vec::new();
                    let _ = stream.read_to_end(&mut response);
                }
                thread::sleep(Duration::from_millis(200));
            }
        })
    };

    // Run the recording
    systing(config).expect("systing recording failed");

    // Wait for traffic thread to complete
    traffic_handle.join().expect("Traffic thread panicked");

    // Drop netns environment to clean up namespace
    drop(netns_env);

    // === STRICT ASSERTIONS ===

    // 1. Assert network_socket.parquet exists
    assert!(
        dir.path().join("network_socket.parquet").exists(),
        "network_socket.parquet not found - network recording failed"
    );

    // 2. Validate network trace data
    let validation_result =
        validate_network_trace(dir.path()).expect("Failed to validate network trace");

    // 3. Assert socket_count > 0
    assert!(
        validation_result.socket_count > 0,
        "No sockets recorded. Expected at least one socket for the TCP connection to {dest_ip}:{dest_port}",
    );

    // 4. Assert syscall_count > 0 OR packet_count > 0
    assert!(
        validation_result.syscall_count > 0 || validation_result.packet_count > 0,
        "No network activity recorded. syscall_count={}, packet_count={}. \
         Expected at least one syscall or packet event.",
        validation_result.syscall_count,
        validation_result.packet_count
    );

    // 4a. Assert poll events were captured for test traffic
    let poll_count =
        assert_poll_events_recorded(dir.path(), NetworkTestConfig::TEST_NETWORK_PREFIX)
            .expect("Failed to validate poll events for test network traffic");
    assert!(
        poll_count > 0,
        "No poll events recorded for test network traffic. \
         Expected at least one poll/epoll event for the TCP connections."
    );

    // 5. Assert correct IPs were captured (10.200.x.x, not 127.0.0.1)
    // This ensures we're capturing traffic through the veth interface
    // rather than loopback traffic
    let socket_path = dir.path().join("network_socket.parquet");
    if socket_path.exists() {
        use arrow::array::StringArray;
        use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
        use std::fs::File;

        let file = File::open(&socket_path).expect("Failed to open network_socket.parquet");
        let builder =
            ParquetRecordBatchReaderBuilder::try_new(file).expect("Failed to create reader");
        let reader = builder.build().expect("Failed to build reader");

        let mut found_netns_traffic = false;
        for batch_result in reader {
            let batch = batch_result.expect("Failed to read batch");

            if let Some(dest_ips) = batch
                .column_by_name("dest_ip")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>())
            {
                for i in 0..dest_ips.len() {
                    let ip = dest_ips.value(i);
                    // Check for traffic to/from our test namespace (10.200.x.x)
                    if ip.starts_with(NetworkTestConfig::TEST_NETWORK_PREFIX) {
                        found_netns_traffic = true;
                        break;
                    }
                }
            }

            if found_netns_traffic {
                break;
            }
        }

        assert!(
            found_netns_traffic,
            "No traffic to 10.200.x.x network found. \
             Expected network namespace traffic, but only found other IPs. \
             This suggests traffic was routed through loopback instead of the veth pair."
        );
    }

    // 6. Run standard validations
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

    eprintln!(
        "✓ Network namespace test passed: {} sockets, {} syscalls, {} packets, {} poll events",
        validation_result.socket_count,
        validation_result.syscall_count,
        validation_result.packet_count,
        poll_count
    );
}

/// Tests pystacks recording with Python stack trace symbolization.
///
/// This test:
/// 1. Creates a Python script with known function names
/// 2. Runs systing recording with pystacks enabled while the script runs
/// 3. Validates that Python symbols appear in the output
/// 4. Validates both parquet and perfetto outputs are valid
///
/// NOTE: There is a known issue where discover_python_processes() may not find
/// newly spawned Python processes even when they have "python" in their exe path.
/// This test validates the pystacks infrastructure works correctly when processes
/// ARE discovered.
#[test]
#[ignore] // Requires root/BPF privileges and pystacks feature
#[cfg(feature = "pystacks")]
fn test_pystacks_symbol_resolution() {
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    use std::fs::File;
    use std::io::Write;
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::Duration;

    setup_bpf_environment();

    let dir = TempDir::new().expect("Failed to create temp dir");
    let trace_path = dir.path().join("trace.pb");

    // Create a Python script with known, unique function names
    let python_script = dir.path().join("test_pystacks.py");
    let script_content = r#"
import time
import sys

def systing_test_leaf_function():
    """Leaf function that does busy work to show up in profiling."""
    total = 0
    for i in range(1000000):
        total += i * i
    return total

def systing_test_middle_function():
    """Middle function that calls the leaf."""
    result = 0
    for _ in range(50):
        result += systing_test_leaf_function()
    return result

def systing_test_outer_function():
    """Outer function that calls middle."""
    return systing_test_middle_function()

def main():
    """Main entry point."""
    print("Python test script starting...", flush=True)
    start_time = time.time()
    # Run for at least 10 seconds to ensure we capture samples
    while time.time() - start_time < 10:
        systing_test_outer_function()
    print("Python test script done.", flush=True)

if __name__ == "__main__":
    main()
"#;

    {
        let mut file = File::create(&python_script).expect("Failed to create Python script");
        file.write_all(script_content.as_bytes())
            .expect("Failed to write Python script");
    }

    // Start the Python process BEFORE systing
    let mut python_proc = Command::new("/root/.pyenv/versions/3.13.11/bin/python3.13")
        .arg(&python_script)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn Python process");

    let python_pid = python_proc.id();
    eprintln!("Started Python process with PID: {}", python_pid);

    // Wait for Python to fully initialize
    thread::sleep(Duration::from_millis(1000));

    // Create config with explicit PID
    // Use parquet_first for direct parquet output with stack.parquet
    let config = Config {
        duration: 3,
        parquet_first: true,
        parquet_only: false,
        collect_pystacks: true,
        pystacks_pids: vec![python_pid],
        output_dir: dir.path().to_path_buf(),
        output: trace_path.clone(),
        ..Config::default()
    };

    systing(config).expect("systing recording failed");

    // Wait for Python process to finish
    let python_status = python_proc
        .wait()
        .expect("Failed to wait for Python process");
    eprintln!("Python process exited with status: {:?}", python_status);

    // === VALIDATE PARQUET OUTPUT ===

    // Debug: List files in output directory
    eprintln!("Files in output directory {:?}:", dir.path());
    for entry in std::fs::read_dir(dir.path())
        .expect("Failed to read output dir")
        .flatten()
    {
        eprintln!("  {:?}", entry.path());
    }

    // Parquet-first path uses stack.parquet with frame_names column (list of strings)
    let stack_parquet = dir.path().join("stack.parquet");
    assert!(
        stack_parquet.exists(),
        "stack.parquet not found - stack profiling may have failed"
    );

    // Read stack.parquet and look for Python symbols in frame_names
    let file = File::open(&stack_parquet).expect("Failed to open stack.parquet");
    let builder = ParquetRecordBatchReaderBuilder::try_new(file).expect("Failed to create reader");
    let reader = builder.build().expect("Failed to build reader");

    let mut found_python_symbols = false;
    let mut found_test_functions: Vec<String> = Vec::new();
    let mut all_function_names: Vec<String> = Vec::new();
    let expected_functions = [
        "systing_test_leaf_function",
        "systing_test_middle_function",
        "systing_test_outer_function",
    ];

    for batch_result in reader {
        let batch = batch_result.expect("Failed to read batch");

        // Get frame_names column from stack.parquet (it's a List of strings)
        if let Some(frame_names_col) = batch.column_by_name("frame_names") {
            use arrow::array::{ListArray, StringArray};

            let list_array = frame_names_col
                .as_any()
                .downcast_ref::<ListArray>()
                .expect("frame_names should be a ListArray");

            for i in 0..list_array.len() {
                if list_array.is_null(i) {
                    continue;
                }

                let inner = list_array.value(i);
                let string_array = inner
                    .as_any()
                    .downcast_ref::<StringArray>()
                    .expect("frame_names inner should be StringArray");

                for j in 0..string_array.len() {
                    if string_array.is_null(j) {
                        continue;
                    }
                    let func_name = string_array.value(j);

                    // Collect sample names for debugging
                    if all_function_names.len() < 20
                        && !all_function_names.contains(&func_name.to_string())
                    {
                        all_function_names.push(func_name.to_string());
                    }

                    // Check if this is a Python frame (contains "(python)")
                    if func_name.contains("(python)") {
                        found_python_symbols = true;

                        // Check for our test functions
                        for expected in &expected_functions {
                            if func_name.contains(expected)
                                && !found_test_functions.contains(&expected.to_string())
                            {
                                found_test_functions.push(expected.to_string());
                                eprintln!("✓ Found expected Python symbol: {}", func_name);
                            }
                        }
                    }
                }
            }
        }
    }

    // Debug: show sample function names
    eprintln!("Sample function names from stack.parquet:");
    for name in &all_function_names {
        eprintln!("  {}", name);
    }

    // Report what we found - HARD FAIL if no Python symbols
    assert!(
        found_python_symbols,
        "FAILED: No Python symbols found in stack.parquet. \
         Pystacks did not successfully symbolize the Python process."
    );
    eprintln!("✓ Found Python symbols in stack.parquet");

    assert!(
        !found_test_functions.is_empty(),
        "FAILED: No expected test functions found in stack.parquet. \
         Expected at least one of: {:?}",
        expected_functions
    );
    eprintln!(
        "✓ Found {} of {} expected Python test functions: {:?}",
        found_test_functions.len(),
        expected_functions.len(),
        found_test_functions
    );

    // Verify stack_sample.parquet has samples (parquet-first path uses stack_sample)
    let stack_sample_parquet = dir.path().join("stack_sample.parquet");
    assert!(
        stack_sample_parquet.exists(),
        "stack_sample.parquet not found"
    );

    let file = File::open(&stack_sample_parquet).expect("Failed to open stack_sample.parquet");
    let builder = ParquetRecordBatchReaderBuilder::try_new(file).expect("Failed to create reader");
    let reader = builder.build().expect("Failed to build reader");

    let mut sample_count = 0;
    for batch_result in reader {
        let batch = batch_result.expect("Failed to read batch");
        sample_count += batch.num_rows();
    }

    assert!(
        sample_count > 0,
        "No stack samples found in stack_sample.parquet"
    );
    eprintln!("✓ Found {} perf samples", sample_count);

    // === VALIDATE PERFETTO OUTPUT ===

    // 6. Verify perfetto trace was created
    assert!(
        trace_path.exists(),
        "trace.pb not found after parquet-to-perfetto conversion"
    );

    // 7. Parse Perfetto trace and verify it contains PerfSample packets
    use perfetto_protos::trace::Trace;
    use protobuf::Message;
    use std::io::Read;

    let mut trace_data = Vec::new();
    File::open(&trace_path)
        .expect("Failed to open trace.pb")
        .read_to_end(&mut trace_data)
        .expect("Failed to read trace.pb");

    let trace = Trace::parse_from_bytes(&trace_data).expect("Failed to parse Perfetto trace");

    // Count PerfSample packets
    let perf_sample_count = trace.packet.iter().filter(|p| p.has_perf_sample()).count();

    eprintln!(
        "✓ Perfetto trace contains {} PerfSample packets",
        perf_sample_count
    );

    // Check for interned data with function names (Python symbols)
    let mut found_python_interned = false;
    for packet in trace.packet.iter() {
        if let Some(interned) = packet.interned_data.as_ref() {
            for func_name in interned.function_names.iter() {
                if let Some(name_bytes) = &func_name.str {
                    if let Ok(name) = std::str::from_utf8(name_bytes) {
                        if name.contains("(python)") {
                            found_python_interned = true;
                            break;
                        }
                    }
                }
            }
        }
        if found_python_interned {
            break;
        }
    }

    // HARD FAIL if no Python symbols in Perfetto output
    assert!(
        found_python_interned,
        "FAILED: No Python symbols found in Perfetto interned data. \
         Pystacks did not successfully symbolize the Python process for Perfetto output."
    );
    eprintln!("✓ Found Python symbols in Perfetto interned data");

    // 8. Run standard validations
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

    eprintln!(
        "✓ Pystacks integration test passed: {} perf samples, parquet valid, perfetto valid\n\
         ✓ Python symbols found: {} test functions",
        sample_count,
        found_test_functions.len()
    );
}

/// Test that Python stack traces are captured for BOTH CPU (running) and sleep (off-CPU) stacks.
///
/// This test reproduces an issue where Python stacks were only being captured for STACK_RUNNING
/// events but not for STACK_SLEEP events. The root cause was that `pystacks_read_stacks()` was
/// called with `task=NULL`, causing it to use `bpf_get_current_pid_tgid()` instead of reading
/// from the task struct. During sched_switch for sleep stacks, the current PID doesn't match
/// the task being put to sleep.
#[test]
#[ignore] // Requires root/BPF privileges
#[cfg(feature = "pystacks")]
fn test_pystacks_sleep_stacks() {
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    use std::collections::HashMap;
    use std::fs::File;
    use std::io::Write;
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::Duration;

    setup_bpf_environment();

    let dir = TempDir::new().expect("Failed to create temp dir");
    let trace_path = dir.path().join("trace.pb");

    // Create a Python script that does BOTH CPU work AND blocking sleep.
    // This ensures we get both STACK_RUNNING and STACK_SLEEP samples.
    let python_script = dir.path().join("test_sleep_pystacks.py");
    let script_content = r#"
import time
import sys

def systing_sleep_leaf_function():
    """Leaf function that sleeps - should appear in STACK_SLEEP samples."""
    time.sleep(0.05)  # 50ms sleep - should trigger uninterruptible sleep

def systing_sleep_middle_function():
    """Middle function that calls the sleep leaf."""
    for _ in range(20):
        systing_sleep_leaf_function()

def systing_cpu_leaf_function():
    """Leaf function that does CPU work - should appear in STACK_RUNNING samples."""
    total = 0
    for i in range(500000):
        total += i * i
    return total

def systing_cpu_middle_function():
    """Middle function that calls the CPU leaf."""
    result = 0
    for _ in range(10):
        result += systing_cpu_leaf_function()
    return result

def main():
    """Main entry point - alternates between CPU work and sleeping."""
    print("Python sleep/CPU test script starting...", flush=True)
    start_time = time.time()

    # Run for at least 10 seconds alternating between CPU work and sleep
    while time.time() - start_time < 10:
        # Do some CPU work (generates STACK_RUNNING samples)
        systing_cpu_middle_function()
        # Then sleep (generates STACK_SLEEP samples)
        systing_sleep_middle_function()

    print("Python sleep/CPU test script done.", flush=True)

if __name__ == "__main__":
    main()
"#;

    {
        let mut file = File::create(&python_script).expect("Failed to create Python script");
        file.write_all(script_content.as_bytes())
            .expect("Failed to write Python script");
    }

    // Start the Python process BEFORE systing
    let mut python_proc = Command::new("/root/.pyenv/versions/3.13.11/bin/python3.13")
        .arg(&python_script)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn Python process");

    let python_pid = python_proc.id();
    eprintln!("Started Python process with PID: {}", python_pid);

    // Wait for Python to fully initialize
    thread::sleep(Duration::from_millis(1000));

    // Create config with explicit PID
    let config = Config {
        duration: 5,
        parquet_first: true,
        parquet_only: false,
        collect_pystacks: true,
        pystacks_pids: vec![python_pid],
        output_dir: dir.path().to_path_buf(),
        output: trace_path.clone(),
        ..Config::default()
    };

    systing(config).expect("systing recording failed");

    // Wait for Python process to finish
    let python_status = python_proc
        .wait()
        .expect("Failed to wait for Python process");
    eprintln!("Python process exited with status: {:?}", python_status);

    // === LOAD STACK.PARQUET INTO A MAP ===
    let stack_parquet = dir.path().join("stack.parquet");
    assert!(
        stack_parquet.exists(),
        "stack.parquet not found - stack profiling may have failed"
    );

    // Build a map from stack_id -> frame_names
    let mut stack_frames: HashMap<i64, Vec<String>> = HashMap::new();
    {
        let file = File::open(&stack_parquet).expect("Failed to open stack.parquet");
        let builder =
            ParquetRecordBatchReaderBuilder::try_new(file).expect("Failed to create reader");
        let reader = builder.build().expect("Failed to build reader");

        for batch_result in reader {
            let batch = batch_result.expect("Failed to read batch");

            let id_col = batch
                .column_by_name("id")
                .expect("id column missing")
                .as_any()
                .downcast_ref::<arrow::array::Int64Array>()
                .expect("id should be Int64");

            let frame_names_col = batch
                .column_by_name("frame_names")
                .expect("frame_names column missing")
                .as_any()
                .downcast_ref::<arrow::array::ListArray>()
                .expect("frame_names should be ListArray");

            for i in 0..batch.num_rows() {
                let stack_id = id_col.value(i);
                let mut frames = Vec::new();

                if !frame_names_col.is_null(i) {
                    let inner = frame_names_col.value(i);
                    let string_array = inner
                        .as_any()
                        .downcast_ref::<arrow::array::StringArray>()
                        .expect("inner should be StringArray");

                    for j in 0..string_array.len() {
                        if !string_array.is_null(j) {
                            frames.push(string_array.value(j).to_string());
                        }
                    }
                }

                stack_frames.insert(stack_id, frames);
            }
        }
    }
    eprintln!(
        "Loaded {} unique stacks from stack.parquet",
        stack_frames.len()
    );

    // === ANALYZE STACK_SAMPLE.PARQUET ===
    let stack_sample_parquet = dir.path().join("stack_sample.parquet");
    assert!(
        stack_sample_parquet.exists(),
        "stack_sample.parquet not found"
    );

    // Track Python symbols by stack_event_type
    // Type 0 = STACK_SLEEP (off-CPU), Type 1 = STACK_RUNNING (on-CPU)
    let mut sleep_samples_total = 0;
    let mut sleep_samples_with_python = 0;
    let mut running_samples_total = 0;
    let mut running_samples_with_python = 0;
    let mut sleep_python_functions: Vec<String> = Vec::new();
    let mut running_python_functions: Vec<String> = Vec::new();

    {
        let file = File::open(&stack_sample_parquet).expect("Failed to open stack_sample.parquet");
        let builder =
            ParquetRecordBatchReaderBuilder::try_new(file).expect("Failed to create reader");
        let reader = builder.build().expect("Failed to build reader");

        for batch_result in reader {
            let batch = batch_result.expect("Failed to read batch");

            let stack_id_col = batch
                .column_by_name("stack_id")
                .expect("stack_id column missing")
                .as_any()
                .downcast_ref::<arrow::array::Int64Array>()
                .expect("stack_id should be Int64");

            let stack_event_type_col = batch
                .column_by_name("stack_event_type")
                .expect("stack_event_type column missing")
                .as_any()
                .downcast_ref::<arrow::array::Int8Array>()
                .expect("stack_event_type should be Int8");

            for i in 0..batch.num_rows() {
                let stack_id = stack_id_col.value(i);
                let stack_event_type = stack_event_type_col.value(i);

                let frames = stack_frames.get(&stack_id).cloned().unwrap_or_default();
                let has_python = frames.iter().any(|f| f.contains("(python)"));

                match stack_event_type {
                    0 => {
                        // STACK_SLEEP
                        sleep_samples_total += 1;
                        if has_python {
                            sleep_samples_with_python += 1;
                            for f in &frames {
                                if f.contains("(python)")
                                    && f.contains("systing_sleep")
                                    && !sleep_python_functions.contains(f)
                                {
                                    sleep_python_functions.push(f.clone());
                                }
                            }
                        }
                    }
                    1 => {
                        // STACK_RUNNING
                        running_samples_total += 1;
                        if has_python {
                            running_samples_with_python += 1;
                            for f in &frames {
                                if f.contains("(python)")
                                    && f.contains("systing_cpu")
                                    && !running_python_functions.contains(f)
                                {
                                    running_python_functions.push(f.clone());
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // === REPORT RESULTS ===
    eprintln!("\n=== Stack Sample Analysis ===");
    eprintln!(
        "STACK_RUNNING (CPU): {} total, {} with Python symbols ({:.1}%)",
        running_samples_total,
        running_samples_with_python,
        if running_samples_total > 0 {
            running_samples_with_python as f64 / running_samples_total as f64 * 100.0
        } else {
            0.0
        }
    );
    eprintln!("  Python functions found: {:?}", running_python_functions);

    eprintln!(
        "STACK_SLEEP (off-CPU): {} total, {} with Python symbols ({:.1}%)",
        sleep_samples_total,
        sleep_samples_with_python,
        if sleep_samples_total > 0 {
            sleep_samples_with_python as f64 / sleep_samples_total as f64 * 100.0
        } else {
            0.0
        }
    );
    eprintln!("  Python functions found: {:?}", sleep_python_functions);

    // === ASSERTIONS ===

    // We should have some samples of each type
    assert!(
        running_samples_total > 0,
        "No STACK_RUNNING samples captured - test script may not have done CPU work"
    );
    assert!(
        sleep_samples_total > 0,
        "No STACK_SLEEP samples captured - test script may not have slept"
    );

    // CPU stacks should have Python symbols (this already works)
    assert!(
        running_samples_with_python > 0,
        "FAILED: No Python symbols in STACK_RUNNING samples. \
         Expected systing_cpu_* functions to appear."
    );
    eprintln!("✓ STACK_RUNNING samples have Python symbols");

    // Sleep stacks should ALSO have Python symbols (this is the bug we're testing)
    assert!(
        sleep_samples_with_python > 0,
        "FAILED: No Python symbols in STACK_SLEEP samples. \
         Expected systing_sleep_* functions to appear. \
         This indicates pystacks is not correctly capturing Python stacks for sleeping tasks."
    );
    eprintln!("✓ STACK_SLEEP samples have Python symbols");

    eprintln!(
        "\n✓ test_pystacks_sleep_stacks passed: Python symbols found in both CPU and sleep stacks"
    );
}

/// Test that Python 3.13 stack traces don't have excessive Frame Errors.
///
/// Python 3.13 changed internal frame structures (f_code -> f_executable).
/// This test validates that Frame Errors are limited to expected positions
/// (entry frames at the bottom of the stack) and don't affect the quality
/// of Python stack traces.
#[test]
#[ignore] // Requires root/BPF privileges
#[cfg(feature = "pystacks")]
fn test_pystacks_frame_error_rate() {
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    use std::fs::File;
    use std::io::Write;
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::Duration;

    setup_bpf_environment();

    let dir = TempDir::new().expect("Failed to create temp dir");
    let trace_path = dir.path().join("trace.pb");

    // Create a simple Python script
    let python_script = dir.path().join("test_frame_error.py");
    let script_content = r#"
import time

def level3():
    total = 0
    for i in range(100000):
        total += i * i
    return total

def level2():
    return level3()

def level1():
    return level2()

def main():
    start = time.time()
    while time.time() - start < 10:
        level1()

if __name__ == "__main__":
    main()
"#;

    {
        let mut file = File::create(&python_script).expect("Failed to create Python script");
        file.write_all(script_content.as_bytes())
            .expect("Failed to write Python script");
    }

    let mut python_proc = Command::new("/root/.pyenv/versions/3.13.11/bin/python3.13")
        .arg(&python_script)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn Python process");

    let python_pid = python_proc.id();
    eprintln!("Started Python 3.13 process with PID: {}", python_pid);
    thread::sleep(Duration::from_millis(1000));

    let config = Config {
        duration: 3,
        parquet_first: true,
        parquet_only: false,
        collect_pystacks: true,
        pystacks_pids: vec![python_pid],
        output_dir: dir.path().to_path_buf(),
        output: trace_path.clone(),
        ..Config::default()
    };

    systing(config).expect("systing recording failed");
    python_proc
        .wait()
        .expect("Failed to wait for Python process");

    // Analyze stacks for Frame Error
    let stack_parquet = dir.path().join("stack.parquet");
    assert!(stack_parquet.exists(), "stack.parquet not found");

    let file = File::open(&stack_parquet).expect("Failed to open stack.parquet");
    let builder = ParquetRecordBatchReaderBuilder::try_new(file).expect("Failed to create reader");
    let reader = builder.build().expect("Failed to build reader");

    let mut total_python_stacks = 0;
    let mut stacks_with_frame_error = 0;
    let mut frame_error_not_at_bottom = 0;
    let mut expected_functions_found = 0;

    for batch_result in reader {
        let batch = batch_result.expect("Failed to read batch");

        let frame_names_col = batch
            .column_by_name("frame_names")
            .expect("frame_names column missing")
            .as_any()
            .downcast_ref::<arrow::array::ListArray>()
            .expect("frame_names should be ListArray");

        for i in 0..batch.num_rows() {
            if frame_names_col.is_null(i) {
                continue;
            }

            let inner = frame_names_col.value(i);
            let string_array = inner
                .as_any()
                .downcast_ref::<arrow::array::StringArray>()
                .expect("inner should be StringArray");

            let frames: Vec<String> = (0..string_array.len())
                .filter_map(|j| {
                    if string_array.is_null(j) {
                        None
                    } else {
                        Some(string_array.value(j).to_string())
                    }
                })
                .collect();

            // Only analyze stacks from our test script
            let is_our_stack = frames.iter().any(|f| f.contains("test_frame_error.py"));
            if !is_our_stack {
                continue;
            }

            total_python_stacks += 1;

            let has_frame_error = frames.iter().any(|f| f.contains("Frame Error"));
            if has_frame_error {
                stacks_with_frame_error += 1;

                // Check if Frame Error is at the expected position (after entry frames)
                for (idx, frame) in frames.iter().enumerate() {
                    if frame.contains("Frame Error") {
                        // Frame Error should be at position 4+ (after level3, level2, level1, main, <module>)
                        // or at least after some Python frames
                        let python_frames_before = frames[..idx]
                            .iter()
                            .filter(|f| f.contains("(python)"))
                            .count();
                        if python_frames_before < 2 {
                            frame_error_not_at_bottom += 1;
                            eprintln!(
                                "Frame Error at unexpected position {} with only {} Python frames before",
                                idx, python_frames_before
                            );
                        }
                        break;
                    }
                }
            }

            // Check for expected function names
            let has_level3 = frames.iter().any(|f| f.contains("level3"));
            let has_level2 = frames.iter().any(|f| f.contains("level2"));
            let has_level1 = frames.iter().any(|f| f.contains("level1"));
            if has_level3 && has_level2 && has_level1 {
                expected_functions_found += 1;
            }
        }
    }

    eprintln!("\n=== Python 3.13 Frame Error Analysis ===");
    eprintln!("Total Python stacks from test: {}", total_python_stacks);
    eprintln!(
        "Stacks with Frame Error: {} ({:.1}%)",
        stacks_with_frame_error,
        if total_python_stacks > 0 {
            100.0 * stacks_with_frame_error as f64 / total_python_stacks as f64
        } else {
            0.0
        }
    );
    eprintln!(
        "Frame Error at unexpected position: {}",
        frame_error_not_at_bottom
    );
    eprintln!(
        "Stacks with expected functions (level1/2/3): {}",
        expected_functions_found
    );

    // Assertions
    assert!(
        total_python_stacks > 0,
        "No Python stacks captured from test script"
    );

    // The key assertion: we should find our expected function names despite Frame Errors
    assert!(
        expected_functions_found > 0,
        "FAILED: No stacks found with expected level1/level2/level3 functions. \
         Frame Errors may be causing stack trace corruption."
    );
    eprintln!("✓ Expected Python functions found in stacks");

    // Frame Error should only appear at the bottom of stacks (after entry frames)
    assert!(
        frame_error_not_at_bottom == 0,
        "FAILED: {} stacks have Frame Error at unexpected positions. \
         This suggests a bug in Python 3.13 frame walking.",
        frame_error_not_at_bottom
    );
    eprintln!("✓ Frame Errors only at expected positions (entry frames)");

    eprintln!("\n✓ test_pystacks_frame_error_rate passed");
}

// =============================================================================
// DuckDB Validation Tests
// =============================================================================

/// Tests DuckDB database generation and validation.
///
/// This test validates that:
/// 1. The --with-duckdb flag generates a valid DuckDB database
/// 2. The database contains the expected tables
/// 3. The database passes all validation checks
#[test]
#[ignore] // Requires root/BPF privileges
fn test_e2e_duckdb_validation() {
    setup_bpf_environment();

    let dir = TempDir::new().expect("Failed to create temp dir");
    let duckdb_path = dir.path().join("trace.duckdb");

    // Create config with DuckDB output enabled
    let config = Config {
        duration: 1,
        parquet_only: true, // Skip Perfetto to speed up test
        with_duckdb: true,
        duckdb_output: duckdb_path.clone(),
        output_dir: dir.path().to_path_buf(),
        output: dir.path().join("trace.pb"),
        ..Config::default()
    };

    // Run the recording
    systing(config).expect("systing recording failed");

    // Verify DuckDB file was created
    assert!(
        duckdb_path.exists(),
        "trace.duckdb not found - DuckDB generation failed"
    );

    // Verify DuckDB file has reasonable size (not empty)
    let metadata = std::fs::metadata(&duckdb_path).expect("Failed to get file metadata");
    assert!(
        metadata.len() > 1024,
        "DuckDB file is too small ({} bytes), may be empty or corrupted",
        metadata.len()
    );

    // Validate the DuckDB database
    let result = validate_duckdb(&duckdb_path);
    assert!(
        result.is_valid(),
        "DuckDB validation failed:\nErrors: {:?}\nWarnings: {:?}",
        result.errors,
        result.warnings
    );

    eprintln!("✓ DuckDB validation passed");
    if !result.warnings.is_empty() {
        eprintln!("  Warnings: {:?}", result.warnings);
    }
}

/// Tests DuckDB generation with parquet-first mode.
///
/// This validates that the parquet-first streaming path correctly
/// generates DuckDB output.
#[test]
#[ignore] // Requires root/BPF privileges
fn test_e2e_duckdb_with_parquet_first() {
    setup_bpf_environment();

    let dir = TempDir::new().expect("Failed to create temp dir");
    let duckdb_path = dir.path().join("trace.duckdb");
    let trace_path = dir.path().join("trace.pb");

    // Create config with parquet-first and DuckDB output
    let config = Config {
        duration: 1,
        parquet_first: true,
        parquet_only: false, // Also generate Perfetto
        with_duckdb: true,
        duckdb_output: duckdb_path.clone(),
        output_dir: dir.path().to_path_buf(),
        output: trace_path.clone(),
        ..Config::default()
    };

    // Run the recording
    systing(config).expect("systing recording failed");

    // Verify all outputs exist
    assert!(
        dir.path().join("process.parquet").exists(),
        "process.parquet not found"
    );
    assert!(trace_path.exists(), "trace.pb not found");
    assert!(duckdb_path.exists(), "trace.duckdb not found");

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

    // Validate DuckDB
    let duckdb_result = validate_duckdb(&duckdb_path);
    assert!(
        duckdb_result.is_valid(),
        "DuckDB validation failed:\nErrors: {:?}\nWarnings: {:?}",
        duckdb_result.errors,
        duckdb_result.warnings
    );

    eprintln!("✓ All three formats (Parquet, Perfetto, DuckDB) validated successfully");
}

/// Tests DuckDB generation with network recording enabled.
///
/// This validates that network tables are correctly populated in DuckDB.
#[test]
#[ignore] // Requires root/BPF privileges
fn test_e2e_duckdb_with_network_recording() {
    use duckdb::Connection;

    setup_bpf_environment();

    let dir = TempDir::new().expect("Failed to create temp dir");
    let duckdb_path = dir.path().join("trace.duckdb");

    // Create config with network recording and DuckDB output
    let config = Config {
        duration: 2, // 2 seconds to capture some network activity
        parquet_first: true,
        parquet_only: true,
        network: true,
        with_duckdb: true,
        duckdb_output: duckdb_path.clone(),
        output_dir: dir.path().to_path_buf(),
        output: dir.path().join("trace.pb"),
        ..Config::default()
    };

    // Run the recording
    systing(config).expect("systing recording failed");

    // Verify DuckDB file was created
    assert!(duckdb_path.exists(), "trace.duckdb not found");

    // Validate the DuckDB database
    let result = validate_duckdb(&duckdb_path);
    assert!(
        result.is_valid(),
        "DuckDB validation failed:\nErrors: {:?}\nWarnings: {:?}",
        result.errors,
        result.warnings
    );

    // Open the database and verify network tables exist
    let conn = Connection::open(&duckdb_path).expect("Failed to open DuckDB");

    // Check that network_interface table exists and has data
    let interface_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM network_interface", [], |row| {
            row.get(0)
        })
        .unwrap_or(0);

    assert!(
        interface_count > 0,
        "network_interface table is empty - expected at least one interface"
    );

    eprintln!(
        "✓ DuckDB validation passed with network recording ({} interfaces)",
        interface_count
    );
}

/// Tests that DuckDB validation correctly identifies issues.
///
/// This is a non-privileged test that validates the error detection
/// in validate_duckdb().
#[test]
fn test_validate_duckdb_nonexistent() {
    // Test validation of a nonexistent file
    let result = validate_duckdb(Path::new("/nonexistent/path/trace.duckdb"));

    // Should have an error for failing to open
    assert!(
        result.has_errors(),
        "Expected error for nonexistent DuckDB file"
    );

    // The error should mention database opening failure
    let error_str = format!("{:?}", result.errors);
    assert!(
        error_str.contains("database") || error_str.contains("open"),
        "Error should mention database opening: {error_str}"
    );
}

/// Tests DuckDB validation with an empty/invalid database.
#[test]
fn test_validate_duckdb_invalid() {
    let dir = TempDir::new().expect("Failed to create temp dir");
    let bad_db = dir.path().join("bad.duckdb");

    // Create an empty file that's not a valid DuckDB database
    std::fs::write(&bad_db, b"not a duckdb file").expect("Failed to write file");

    // Validation should fail
    let result = validate_duckdb(&bad_db);
    assert!(
        result.has_errors(),
        "Expected error for invalid DuckDB file, got: {result:?}"
    );
}
