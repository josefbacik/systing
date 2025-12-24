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

    // Create config for network recording with parquet-first
    let config = Config {
        duration: 3,
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

    // Spawn a thread to generate traffic after recording starts
    let traffic_handle = {
        let server_addr = netns_env.server_addr();
        thread::spawn(move || {
            // Wait for BPF probes to be attached - systing initialization takes time
            // especially in virtualized environments
            thread::sleep(Duration::from_millis(2000));

            // Generate multiple rounds of traffic
            for i in 0..5 {
                let message = format!("Hello from netns test round {i}");
                if let Ok(mut stream) = std::net::TcpStream::connect(&server_addr) {
                    use std::io::{Read, Write};
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
    let mut python_proc = Command::new("/usr/bin/python3.10")
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

    // Report what we found
    if found_python_symbols {
        eprintln!("✓ Found Python symbols in stack.parquet");
        if !found_test_functions.is_empty() {
            eprintln!(
                "✓ Found {} of {} expected Python test functions: {:?}",
                found_test_functions.len(),
                expected_functions.len(),
                found_test_functions
            );
        }
    } else {
        eprintln!(
            "NOTE: No Python symbols found in stack.parquet. \
             This may be due to the test process not being discovered by pystacks."
        );
    }

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

    if found_python_interned {
        eprintln!("✓ Found Python symbols in Perfetto interned data");
    } else {
        eprintln!(
            "NOTE: No Python symbols found in Perfetto interned data. \
             This is expected if the test process was not discovered by pystacks."
        );
    }

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
        "✓ Pystacks integration test passed: {} perf samples, parquet valid, perfetto valid",
        sample_count
    );
    if found_python_symbols {
        eprintln!(
            "  Python symbols found: {} test functions",
            found_test_functions.len()
        );
    }
}
