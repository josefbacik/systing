//! Integration tests for trace validation.
//!
//! These tests run the full systing recording pipeline and validate the output.
//! They require root/BPF privileges and are marked as `#[ignore]` by default.
//!
//! Tests are consolidated so that each systing recording is reused by multiple
//! checks, minimizing BPF setup/teardown overhead.
//!
//! To run these tests:
//! ```
//! ./scripts/run-integration-tests.sh trace_validation
//! ```

mod common;

use arrow::array::Array;
use common::{
    assert_poll_events_recorded, validate_network_trace, NetnsTestEnv, NetworkTestConfig,
};
use std::io::{Read, Write};
use std::path::Path;
#[cfg(feature = "pystacks")]
use std::path::PathBuf;
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

/// Recording duration for the basic validation suite (seconds).
/// Set to 2s (instead of 1s) to give the exit workload time to generate
/// EXIT_DEAD/EXIT_ZOMBIE states during the trace.
const VALIDATION_SUITE_DURATION_SECS: u64 = 2;

/// Recording duration for the network suite (seconds).
/// Set to 3s to allow time for traffic generation after BPF init (~500ms).
const NETWORK_SUITE_DURATION_SECS: u64 = 3;

/// Helper to set up the environment for BPF tests.
fn setup_bpf_environment() {
    bump_memlock_rlimit().expect("Failed to bump memlock rlimit");
}

/// Python versions used by pystacks integration tests.
/// Install these via: ./scripts/setup-pystacks.sh
#[cfg(feature = "pystacks")]
const PYTHON_313_VERSION: &str = "3.13.11";
#[cfg(feature = "pystacks")]
const PYTHON_311_VERSION: &str = "3.11.14";

/// Get the path to a pyenv-installed Python binary.
///
/// Resolves `$HOME/.pyenv/versions/<version>/bin/python<major.minor>`.
/// Panics with a helpful message if the binary is not found.
#[cfg(feature = "pystacks")]
fn pyenv_python(version: &str) -> PathBuf {
    let home = std::env::var("HOME").expect("HOME environment variable not set");
    let parts: Vec<&str> = version.split('.').collect();
    assert!(
        parts.len() == 3,
        "expected version in X.Y.Z format, got: {version}"
    );
    let short = format!("{}.{}", parts[0], parts[1]);
    let path = PathBuf::from(format!(
        "{home}/.pyenv/versions/{version}/bin/python{short}"
    ));
    assert!(
        path.exists(),
        "Python {version} not found at {}. Install it with: ./scripts/setup-pystacks.sh",
        path.display()
    );
    path
}

/// Scan a stack.parquet file for Python symbols and a specific target function name.
/// Returns `(found_python_symbols, found_target_function)`.
#[cfg(feature = "pystacks")]
fn find_python_symbols_in_parquet(
    parquet_path: &std::path::Path,
    target_function: &str,
) -> (bool, bool) {
    use arrow::array::ListArray;
    use arrow::array::StringArray;
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

    let file = std::fs::File::open(parquet_path).expect("Failed to open stack.parquet");
    let builder = ParquetRecordBatchReaderBuilder::try_new(file).expect("Failed to create reader");
    let reader = builder.build().expect("Failed to build reader");

    let mut found_python_symbols = false;
    let mut found_target_function = false;

    for batch_result in reader {
        let batch = batch_result.expect("Failed to read batch");

        if let Some(frame_names_col) = batch.column_by_name("frame_names") {
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
                    if func_name.contains("(python)") {
                        found_python_symbols = true;
                    }
                    if func_name.contains(target_function) {
                        found_target_function = true;
                    }
                }
            }
        }
    }

    (found_python_symbols, found_target_function)
}

// =============================================================================
// Non-privileged tests (no systing recording needed)
// =============================================================================

#[test]
fn test_validate_nonexistent_path() {
    let result = validate_parquet_dir(Path::new("/nonexistent/path"));
    let _ = result;
}

#[test]
fn test_validate_unrecognized_file() {
    use std::io::Write;

    let dir = TempDir::new().expect("Failed to create temp dir");
    let bad_file = dir.path().join("test.txt");

    std::fs::File::create(&bad_file)
        .unwrap()
        .write_all(b"not a trace file")
        .unwrap();

    let result = validate_perfetto_trace(&bad_file);
    assert!(
        result.has_errors(),
        "Expected validation errors for invalid file, got: {result:?}"
    );
}

#[test]
fn test_validate_duckdb_nonexistent() {
    let result = validate_duckdb(Path::new("/nonexistent/path/trace.duckdb"));
    assert!(
        result.has_errors(),
        "Expected error for nonexistent DuckDB file"
    );
    let error_str = format!("{:?}", result.errors);
    assert!(
        error_str.contains("database") || error_str.contains("open"),
        "Error should mention database opening: {error_str}"
    );
}

#[test]
fn test_validate_duckdb_invalid() {
    let dir = TempDir::new().expect("Failed to create temp dir");
    let bad_db = dir.path().join("bad.duckdb");
    std::fs::write(&bad_db, b"not a duckdb file").expect("Failed to write file");

    let result = validate_duckdb(&bad_db);
    assert!(
        result.has_errors(),
        "Expected error for invalid DuckDB file, got: {result:?}"
    );
}

#[test]
fn test_run_command_not_found() {
    let result = systing::traced_command::spawn_traced_child(&["nonexistent_cmd_xyz".to_string()]);
    assert!(result.is_err(), "Expected error for nonexistent command");
    let err = result.err().unwrap();
    let err_msg = format!("{:#}", err);
    assert!(
        err_msg.contains("not found"),
        "Expected 'not found' in error message, got: {}",
        err_msg
    );
}

#[test]
fn test_is_python_command() {
    use systing::traced_command::is_python_command;

    assert!(is_python_command(&[
        "python3".to_string(),
        "script.py".to_string()
    ]));
    assert!(is_python_command(&["python".to_string()]));
    assert!(is_python_command(&["/usr/bin/python3.11".to_string()]));
    assert!(!is_python_command(&["bash".to_string()]));
    assert!(!is_python_command(&["sleep".to_string(), "1".to_string()]));
    assert!(!is_python_command(&[]));
}

#[test]
fn test_run_command_not_executable() {
    use std::io::Write;
    let dir = TempDir::new().expect("Failed to create temp dir");
    let not_exec = dir.path().join("not_executable.sh");
    {
        let mut f = std::fs::File::create(&not_exec).expect("Failed to create file");
        writeln!(f, "#!/bin/sh\necho hello").expect("Failed to write");
    }

    let result =
        systing::traced_command::spawn_traced_child(&[not_exec.to_str().unwrap().to_string()]);
    assert!(result.is_err(), "Expected error for non-executable file");
    let err_msg = format!("{:#}", result.err().unwrap());
    assert!(
        err_msg.contains("not executable"),
        "Expected 'not executable' in error, got: {}",
        err_msg
    );
}

// =============================================================================
// Consolidated validation suite
//
// Records ONE trace (2s, parquet+perfetto, with exit workload) and runs all
// basic validation checks against it. This replaces 9 separate tests that
// each recorded their own trace.
// =============================================================================

#[test]
#[ignore] // Requires root/BPF privileges
fn test_e2e_validation_suite() {
    use arrow::array::Int32Array;
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    use perfetto_protos::trace::Trace;
    use protobuf::Message;
    use std::fs::File;
    use std::io::Read as IoRead;
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::Duration;
    use systing::validation::ValidationWarning;

    const EXIT_DEAD: i32 = 16;
    const EXIT_ZOMBIE: i32 = 32;

    setup_bpf_environment();

    let dir = TempDir::new().expect("Failed to create temp dir");
    let trace_path = dir.path().join("trace.pb");

    // Spawn exit workload to generate EXIT_DEAD/EXIT_ZOMBIE states
    let workload_handle = thread::spawn(move || {
        thread::sleep(Duration::from_millis(100));
        for _ in 0..2 {
            let mut child = Command::new("bash")
                .arg("-c")
                .arg("for i in $(seq 1 5); do sleep 0.01 & done; wait")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("Failed to spawn workload");
            child.wait().expect("Failed to wait for workload");
        }
    });

    // Record a trace with both parquet and perfetto output
    eprintln!(
        "Recording trace ({}s, with exit workload)...",
        VALIDATION_SUITE_DURATION_SECS
    );
    let config = Config {
        duration: VALIDATION_SUITE_DURATION_SECS,
        output_dir: dir.path().to_path_buf(),
        output: trace_path.clone(),
        ..Config::default()
    };

    systing(config, None).expect("systing recording failed");
    workload_handle.join().expect("Workload thread panicked");
    eprintln!("Recording complete.\n");

    // --- Check: parquet files exist (test_e2e_parquet_validation, test_e2e_with_perfetto) ---
    eprintln!("  parquet files exist...");
    assert!(
        dir.path().join("process.parquet").exists(),
        "[parquet files] process.parquet not found"
    );
    assert!(
        dir.path().join("thread.parquet").exists(),
        "[parquet files] thread.parquet not found"
    );
    assert!(
        dir.path().join("sched_slice.parquet").exists(),
        "[parquet files] sched_slice.parquet not found"
    );

    // --- Check: perfetto file exists (test_e2e_perfetto_validation, test_e2e_with_perfetto) ---
    eprintln!("  perfetto file exists...");
    assert!(
        trace_path.exists(),
        "[perfetto file] trace.pb not found after parquet-to-perfetto conversion"
    );

    // --- Check: parquet validation (test_e2e_parquet_validation) ---
    eprintln!("  parquet validation...");
    let parquet_result = validate_parquet_dir(dir.path());
    assert!(
        parquet_result.is_valid(),
        "[parquet validation] failed:\nErrors: {:?}\nWarnings: {:?}",
        parquet_result.errors,
        parquet_result.warnings
    );

    // --- Check: standalone parquet_to_perfetto::convert() (test_e2e_duckdb) ---
    // Tests the standalone conversion function directly, separate from the integrated recording path.
    eprintln!("  parquet -> perfetto (standalone convert)...");
    let manual_perfetto_path = dir.path().join("manual_convert.pb");
    systing::parquet_to_perfetto::convert(dir.path(), &manual_perfetto_path)
        .expect("Standalone parquet_to_perfetto::convert() failed");
    assert!(
        manual_perfetto_path.exists(),
        "[parquet->perfetto convert] manual_convert.pb not created by standalone convert()"
    );
    let manual_perfetto_result = validate_perfetto_trace(&manual_perfetto_path);
    assert!(
        manual_perfetto_result.is_valid(),
        "[parquet->perfetto convert] validation failed:\nErrors: {:?}\nWarnings: {:?}",
        manual_perfetto_result.errors,
        manual_perfetto_result.warnings
    );

    // --- Check: perfetto validation (test_e2e_perfetto_validation) ---
    eprintln!("  perfetto validation...");
    let perfetto_result = validate_perfetto_trace(&trace_path);
    assert!(
        perfetto_result.is_valid(),
        "[perfetto validation] failed:\nErrors: {:?}\nWarnings: {:?}",
        perfetto_result.errors,
        perfetto_result.warnings
    );

    // --- Check: exit states in parquet (test_e2e_task_exit_states) ---
    eprintln!("  exit states (parquet)...");
    {
        let sched_slice_path = dir.path().join("sched_slice.parquet");
        assert!(
            sched_slice_path.exists(),
            "[exit states parquet] sched_slice.parquet not found"
        );

        let file = File::open(&sched_slice_path).expect("Failed to open sched_slice.parquet");
        let builder =
            ParquetRecordBatchReaderBuilder::try_new(file).expect("Failed to create reader");
        let reader = builder.build().expect("Failed to build reader");

        let mut total_slices = 0;
        let mut exit_dead_count = 0;
        let mut exit_zombie_count = 0;

        for batch_result in reader {
            let batch = batch_result.expect("Failed to read batch");
            total_slices += batch.num_rows();

            if let Some(end_state_col) = batch.column_by_name("end_state") {
                let end_state_array = end_state_col
                    .as_any()
                    .downcast_ref::<Int32Array>()
                    .expect("end_state should be Int32");

                for i in 0..end_state_array.len() {
                    if !end_state_array.is_null(i) {
                        match end_state_array.value(i) {
                            EXIT_DEAD => exit_dead_count += 1,
                            EXIT_ZOMBIE => exit_zombie_count += 1,
                            _ => {}
                        }
                    }
                }
            }
        }

        let total_exits = exit_dead_count + exit_zombie_count;
        assert!(
            total_exits > 0,
            "[exit states parquet] No exit states (EXIT_DEAD or EXIT_ZOMBIE) found in sched_slice.parquet ({total_slices} total slices)"
        );
        eprintln!(
            "    found {} exit states ({} EXIT_DEAD, {} EXIT_ZOMBIE)",
            total_exits, exit_dead_count, exit_zombie_count
        );
    }

    // --- Check: process_exit.parquet exists and has entries ---
    eprintln!("  process exit events...");
    {
        let process_exit_path = dir.path().join("process_exit.parquet");
        assert!(
            process_exit_path.exists(),
            "[process exit] process_exit.parquet not found"
        );

        let file = File::open(&process_exit_path).expect("Failed to open process_exit.parquet");
        let builder =
            ParquetRecordBatchReaderBuilder::try_new(file).expect("Failed to create reader");
        let reader = builder.build().expect("Failed to build reader");

        let mut process_exit_count = 0;
        for batch_result in reader {
            let batch = batch_result.expect("Failed to read batch");
            process_exit_count += batch.num_rows();
        }

        assert!(
            process_exit_count > 0,
            "[process exit] No entries in process_exit.parquet"
        );
        eprintln!("    found {} process exit events", process_exit_count);
    }

    // --- Check: exit states in perfetto (test_e2e_task_exit_states) ---
    eprintln!("  exit states (perfetto)...");
    {
        let mut trace_data = Vec::new();
        File::open(&trace_path)
            .expect("Failed to open trace.pb")
            .read_to_end(&mut trace_data)
            .expect("Failed to read trace.pb");

        let trace = Trace::parse_from_bytes(&trace_data).expect("Failed to parse Perfetto trace");

        let mut perfetto_exit_dead = 0;
        let mut perfetto_exit_zombie = 0;

        for packet in trace.packet.iter() {
            if packet.has_ftrace_events() {
                let ftrace_events = packet.ftrace_events();
                if let Some(compact_sched) = ftrace_events.compact_sched.as_ref() {
                    for &prev_state in compact_sched.switch_prev_state.iter() {
                        match prev_state as i32 {
                            EXIT_DEAD => perfetto_exit_dead += 1,
                            EXIT_ZOMBIE => perfetto_exit_zombie += 1,
                            _ => {}
                        }
                    }
                }
            }
        }

        let perfetto_total_exits = perfetto_exit_dead + perfetto_exit_zombie;
        assert!(
            perfetto_total_exits > 0,
            "[exit states perfetto] No exit states found in Perfetto compact_sched events"
        );
        eprintln!(
            "    found {} exit states ({} EXIT_DEAD, {} EXIT_ZOMBIE)",
            perfetto_total_exits, perfetto_exit_dead, perfetto_exit_zombie
        );
    }

    // --- Check: DuckDB validation via parquet->duckdb (test_e2e_duckdb_validation, test_e2e_duckdb) ---
    eprintln!("  duckdb from parquet...");
    let duckdb_path = dir.path().join("trace.duckdb");
    systing::duckdb::parquet_to_duckdb(dir.path(), &duckdb_path, "test_trace")
        .expect("DuckDB conversion failed");
    assert!(
        duckdb_path.exists(),
        "[duckdb from parquet] trace.duckdb not found"
    );

    let metadata = std::fs::metadata(&duckdb_path).expect("Failed to get file metadata");
    assert!(
        metadata.len() > 1024,
        "[duckdb from parquet] DuckDB file is too small ({} bytes)",
        metadata.len()
    );

    let duckdb_result = validate_duckdb(&duckdb_path);
    assert!(
        duckdb_result.is_valid(),
        "[duckdb from parquet] validation failed:\nErrors: {:?}\nWarnings: {:?}",
        duckdb_result.errors,
        duckdb_result.warnings
    );

    // --- Check: exit states in duckdb (test_e2e_task_exit_states) ---
    eprintln!("  exit states (duckdb)...");
    {
        let conn = duckdb::Connection::open(&duckdb_path).expect("Failed to open DuckDB");

        let (duckdb_exit_dead, duckdb_exit_zombie): (i64, i64) = conn
            .query_row(
                "SELECT
                    COUNT(*) FILTER (WHERE end_state = 16),
                    COUNT(*) FILTER (WHERE end_state = 32)
                 FROM sched_slice",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("Failed to query sched_slice");

        let duckdb_total_exits = duckdb_exit_dead + duckdb_exit_zombie;
        assert!(
            duckdb_total_exits > 0,
            "[exit states duckdb] No exit states found in DuckDB sched_slice table"
        );
        eprintln!(
            "    found {} exit states ({} EXIT_DEAD, {} EXIT_ZOMBIE)",
            duckdb_total_exits, duckdb_exit_dead, duckdb_exit_zombie
        );
    }

    // --- Check: perfetto->duckdb preserves end_state (test_e2e_perfetto_to_duckdb_preserves_end_state) ---
    eprintln!("  perfetto -> duckdb end_state...");
    {
        let duckdb_from_perfetto = dir.path().join("from_perfetto.duckdb");
        let output = Command::new(env!("CARGO_BIN_EXE_systing-util"))
            .args([
                "convert",
                "-o",
                duckdb_from_perfetto.to_str().unwrap(),
                trace_path.to_str().unwrap(),
            ])
            .output()
            .expect("Failed to run systing-util convert");

        assert!(
            output.status.success(),
            "[perfetto->duckdb] systing-util convert failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            duckdb_from_perfetto.exists(),
            "[perfetto->duckdb] DuckDB not created from perfetto"
        );

        let result = validate_duckdb(&duckdb_from_perfetto);
        assert!(
            result.is_valid(),
            "[perfetto->duckdb] validation failed: {:?}",
            result.errors
        );

        // Check for the specific warning about all-NULL end_state
        let has_all_null_warning = result.warnings.iter().any(|w| {
            matches!(
                w,
                ValidationWarning::AllNullColumn {
                    table,
                    column,
                    ..
                } if table == "sched_slice" && column == "end_state"
            )
        });

        assert!(
            !has_all_null_warning,
            "[perfetto->duckdb] DuckDB has all-NULL end_state warning. Warnings: {:?}",
            result.warnings
        );

        // Verify end_state is populated
        let conn = duckdb::Connection::open(&duckdb_from_perfetto).expect("Failed to open DuckDB");

        let (total, non_null): (i64, i64) = conn
            .query_row(
                "SELECT COUNT(*), COUNT(end_state) FROM sched_slice",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("Failed to query sched_slice");

        assert!(
            total > 0,
            "[perfetto->duckdb] Expected sched_slice to have rows"
        );

        let non_null_pct = (non_null as f64 / total as f64) * 100.0;
        assert!(
            non_null_pct > 50.0,
            "[perfetto->duckdb] Expected >50% non-null end_state values, got {:.1}% ({}/{})",
            non_null_pct,
            non_null,
            total
        );
    }

    // --- Check: duckdb->perfetto conversion (test_e2e_duckdb_to_perfetto) ---
    eprintln!("  duckdb -> perfetto...");
    {
        let perfetto_from_duckdb = dir.path().join("from_duckdb.pb");
        let output = Command::new(env!("CARGO_BIN_EXE_systing-util"))
            .args([
                "convert",
                "-o",
                perfetto_from_duckdb.to_str().unwrap(),
                duckdb_path.to_str().unwrap(),
            ])
            .output()
            .expect("Failed to run systing-util convert");

        assert!(
            output.status.success(),
            "[duckdb->perfetto] systing-util convert failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        assert!(
            perfetto_from_duckdb.exists(),
            "[duckdb->perfetto] Perfetto trace not created from DuckDB"
        );

        let perfetto_result = validate_perfetto_trace(&perfetto_from_duckdb);
        assert!(
            perfetto_result.is_valid(),
            "[duckdb->perfetto] validation failed:\nErrors: {:?}\nWarnings: {:?}",
            perfetto_result.errors,
            perfetto_result.warnings
        );

        // Verify expected content
        let mut trace_data = Vec::new();
        File::open(&perfetto_from_duckdb)
            .expect("Failed to open perfetto trace")
            .read_to_end(&mut trace_data)
            .expect("Failed to read perfetto trace");

        let trace = Trace::parse_from_bytes(&trace_data).expect("Failed to parse Perfetto trace");

        let mut has_process_descriptor = false;
        let mut has_thread_descriptor = false;
        let mut has_ftrace_events = false;

        for packet in trace.packet.iter() {
            if packet.has_track_descriptor() {
                let td = packet.track_descriptor();
                if td.process.is_some() {
                    has_process_descriptor = true;
                }
                if td.thread.is_some() {
                    has_thread_descriptor = true;
                }
            }
            if packet.has_ftrace_events() {
                has_ftrace_events = true;
            }
        }

        assert!(
            has_process_descriptor,
            "[duckdb->perfetto] Missing process descriptors"
        );
        assert!(
            has_thread_descriptor,
            "[duckdb->perfetto] Missing thread descriptors"
        );
        assert!(
            has_ftrace_events,
            "[duckdb->perfetto] Missing ftrace events"
        );
    }

    eprintln!("\n  All validation suite checks passed");
}

// =============================================================================
// Consolidated network suite
//
// Records ONE trace (3s, network=true, with traffic) and runs all network
// validation checks. Replaces 3 separate tests.
// =============================================================================

#[test]
#[ignore] // Requires root/BPF privileges
fn test_e2e_network_suite() {
    use std::fs::File;
    use std::io::Read;
    use std::net::TcpStream;
    use std::thread;
    use std::time::Duration;

    setup_bpf_environment();

    let dir = TempDir::new().expect("Failed to create temp dir");
    let trace_path = dir.path().join("trace.pb");

    // Record a trace with network enabled and traffic generation
    let config = Config {
        duration: NETWORK_SUITE_DURATION_SECS,
        parquet_only: false,
        network: true,
        output_dir: dir.path().to_path_buf(),
        output: trace_path.clone(),
        ..Config::default()
    };

    // Spawn traffic generation thread
    let traffic_thread = thread::spawn(|| {
        thread::sleep(Duration::from_millis(500));

        // Start a local TCP listener and connect to it to guarantee socket data
        if let Ok(listener) = std::net::TcpListener::bind("127.0.0.1:0") {
            let addr = listener.local_addr().unwrap();
            for _ in 0..3 {
                if let Ok(_stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(100)) {
                    let _ = listener.accept();
                }
                thread::sleep(Duration::from_millis(200));
            }
        }

        // Also try connecting to common ports for additional network events
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

    eprintln!("Recording trace (3s, network=true, with traffic)...");
    systing(config, None).expect("systing recording failed");
    traffic_thread.join().expect("Traffic thread panicked");
    eprintln!("Recording complete.\n");

    // --- Check: basic parquet files exist ---
    eprintln!("  basic parquet files exist...");
    assert!(
        dir.path().join("process.parquet").exists(),
        "[network parquet] process.parquet not found"
    );
    assert!(
        dir.path().join("thread.parquet").exists(),
        "[network parquet] thread.parquet not found"
    );

    // --- Check: network parquet files exist (test_e2e_with_network_recorder) ---
    eprintln!("  network parquet files exist...");
    assert!(
        dir.path().join("network_interface.parquet").exists(),
        "[network] network_interface.parquet not found"
    );
    assert!(
        dir.path().join("network_socket.parquet").exists(),
        "[network] network_socket.parquet not found"
    );

    // --- Check: perfetto trace has network tracks (test_e2e_with_network_recorder) ---
    eprintln!("  perfetto network tracks...");
    assert!(trace_path.exists(), "[network perfetto] trace.pb not found");
    {
        let mut trace_data = Vec::new();
        File::open(&trace_path)
            .expect("Failed to open trace.pb")
            .read_to_end(&mut trace_data)
            .expect("Failed to read trace.pb");

        use perfetto_protos::trace::Trace;
        use protobuf::Message;

        let trace = Trace::parse_from_bytes(&trace_data).expect("Failed to parse Perfetto trace");

        let track_names: Vec<String> = trace
            .packet
            .iter()
            .filter(|p| p.has_track_descriptor())
            .map(|p| p.track_descriptor().name().to_string())
            .collect();

        // Verify "Network Interfaces" root track exists
        assert!(
            track_names.iter().any(|n| n == "Network Interfaces"),
            "[network perfetto] Missing 'Network Interfaces' root track. Found tracks: {track_names:?}"
        );

        // Verify at least one namespace track exists
        assert!(
            track_names
                .iter()
                .any(|n| n == "host" || n.starts_with("netns:") || n.starts_with("container:")),
            "[network perfetto] Missing network namespace track. Found tracks: {track_names:?}"
        );

        // Check for optional network packet tracks (test_e2e_network_packets_with_traffic)
        if track_names.iter().any(|n| n == "Network Packets") {
            eprintln!("    found 'Network Packets' track with socket data");

            let socket_tracks: Vec<_> = track_names
                .iter()
                .filter(|n| {
                    n.starts_with("TCP ") || n.starts_with("UDP ") || n.starts_with("Socket ")
                })
                .collect();
            if !socket_tracks.is_empty() {
                eprintln!("    found {} socket tracks", socket_tracks.len());
            }
        } else {
            eprintln!("    note: 'Network Packets' track not present (no socket events captured)");
        }
    }

    // --- Check: parquet and perfetto validation ---
    eprintln!("  parquet validation...");
    let parquet_result = validate_parquet_dir(dir.path());
    assert!(
        parquet_result.is_valid(),
        "[network parquet validation] failed:\nErrors: {:?}\nWarnings: {:?}",
        parquet_result.errors,
        parquet_result.warnings
    );

    eprintln!("  perfetto validation...");
    let perfetto_result = validate_perfetto_trace(&trace_path);
    assert!(
        perfetto_result.is_valid(),
        "[network perfetto validation] failed:\nErrors: {:?}\nWarnings: {:?}",
        perfetto_result.errors,
        perfetto_result.warnings
    );

    // --- Check: DuckDB with network recording (test_e2e_duckdb_with_network_recording) ---
    eprintln!("  duckdb with network recording...");
    {
        let duckdb_path = dir.path().join("trace.duckdb");
        systing::duckdb::parquet_to_duckdb(dir.path(), &duckdb_path, "network_test")
            .expect("DuckDB conversion failed");

        let result = validate_duckdb(&duckdb_path);
        assert!(
            result.is_valid(),
            "[network duckdb] validation failed:\nErrors: {:?}\nWarnings: {:?}",
            result.errors,
            result.warnings
        );

        let conn = duckdb::Connection::open(&duckdb_path).expect("Failed to open DuckDB");

        let interface_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM network_interface", [], |row| {
                row.get(0)
            })
            .unwrap_or(0);

        assert!(
            interface_count > 0,
            "[network duckdb] network_interface table is empty"
        );
        eprintln!("    {} interfaces in DuckDB", interface_count);
    }

    eprintln!("\n  All network suite checks passed");
}

// =============================================================================
// Network namespace test (unchanged, needs its own recording)
// =============================================================================

#[test]
#[ignore] // Requires root/BPF privileges
fn test_network_recording_with_netns() {
    use std::thread;
    use std::time::Duration;

    setup_bpf_environment();

    let netns_env = NetnsTestEnv::new(NetworkTestConfig::default())
        .expect("Failed to create network namespace test environment");

    let dir = TempDir::new().expect("Failed to create temp dir");
    let trace_path = dir.path().join("trace.pb");

    let config = Config {
        duration: NETNS_RECORDING_DURATION_SECS,
        parquet_only: false,
        network: true,
        output_dir: dir.path().to_path_buf(),
        output: trace_path.clone(),
        ..Config::default()
    };

    let dest_ip = netns_env.config.ns_ip.to_string();
    let dest_port = netns_env.server_port;

    let traffic_handle = {
        let server_addr = netns_env.server_addr();
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(NETNS_BPF_INIT_WAIT_SECS));

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

    systing(config, None).expect("systing recording failed");
    traffic_handle.join().expect("Traffic thread panicked");
    drop(netns_env);

    // === STRICT ASSERTIONS ===

    assert!(
        dir.path().join("network_socket.parquet").exists(),
        "network_socket.parquet not found"
    );

    let validation_result =
        validate_network_trace(dir.path()).expect("Failed to validate network trace");

    assert!(
        validation_result.socket_count > 0,
        "No sockets recorded. Expected at least one socket for {dest_ip}:{dest_port}",
    );

    assert!(
        validation_result.syscall_count > 0 || validation_result.packet_count > 0,
        "No network activity recorded. syscall_count={}, packet_count={}",
        validation_result.syscall_count,
        validation_result.packet_count
    );

    let poll_count =
        match assert_poll_events_recorded(dir.path(), NetworkTestConfig::TEST_NETWORK_PREFIX) {
            Ok(count) => {
                eprintln!("  Found {count} poll events for test network traffic");
                count
            }
            Err(e) => {
                eprintln!("  Note: poll event validation skipped: {e}");
                0
            }
        };

    // Check traffic through veth (not loopback)
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
            "No traffic to 10.200.x.x network found"
        );
    }

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
        "  Network namespace test passed: {} sockets, {} syscalls, {} packets, {} poll events",
        validation_result.socket_count,
        validation_result.syscall_count,
        validation_result.packet_count,
        poll_count
    );
}

// =============================================================================
// Pystacks tests (feature-gated, each needs its own Python process)
// =============================================================================

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

    let mut python_proc = Command::new(pyenv_python(PYTHON_313_VERSION))
        .arg(&python_script)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn Python process");

    let python_pid = python_proc.id();
    eprintln!("Started Python process with PID: {}", python_pid);

    thread::sleep(Duration::from_millis(1000));

    let config = Config {
        duration: 3,
        parquet_only: false,
        collect_pystacks: true,
        pystacks_pids: vec![python_pid],
        output_dir: dir.path().to_path_buf(),
        output: trace_path.clone(),
        ..Config::default()
    };

    systing(config, None).expect("systing recording failed");

    let python_status = python_proc
        .wait()
        .expect("Failed to wait for Python process");
    eprintln!("Python process exited with status: {:?}", python_status);

    // === VALIDATE PARQUET OUTPUT ===

    // List output files for diagnostic purposes
    eprintln!("  Output files:");
    if let Ok(entries) = std::fs::read_dir(dir.path()) {
        for entry in entries.flatten() {
            eprintln!("    {}", entry.file_name().to_string_lossy());
        }
    }

    let stack_parquet = dir.path().join("stack.parquet");
    assert!(
        stack_parquet.exists(),
        "[pystacks symbol] stack.parquet not found"
    );

    let file = File::open(&stack_parquet).expect("Failed to open stack.parquet");
    let builder = ParquetRecordBatchReaderBuilder::try_new(file).expect("Failed to create reader");
    let reader = builder.build().expect("Failed to build reader");

    let mut found_python_symbols = false;
    let mut found_test_functions: Vec<String> = Vec::new();
    let mut all_function_names: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    let expected_functions = [
        "systing_test_leaf_function",
        "systing_test_middle_function",
        "systing_test_outer_function",
    ];

    for batch_result in reader {
        let batch = batch_result.expect("Failed to read batch");

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

                    if func_name.contains("(python)") {
                        found_python_symbols = true;
                        all_function_names.insert(func_name.to_string());

                        for expected in &expected_functions {
                            if func_name.contains(expected)
                                && !found_test_functions.contains(&expected.to_string())
                            {
                                found_test_functions.push(expected.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    // Log discovered function names for CI debugging
    let sample_names: Vec<_> = all_function_names.iter().take(20).collect();
    eprintln!(
        "  Found {} unique Python function names (first 20): {:?}",
        all_function_names.len(),
        sample_names
    );

    assert!(
        found_python_symbols,
        "[pystacks symbol] No Python symbols found in stack.parquet"
    );

    assert!(
        !found_test_functions.is_empty(),
        "[pystacks symbol] No expected test functions found. Expected at least one of: {:?}",
        expected_functions
    );

    // Verify stack_sample.parquet has samples
    let stack_sample_parquet = dir.path().join("stack_sample.parquet");
    assert!(
        stack_sample_parquet.exists(),
        "[pystacks symbol] stack_sample.parquet not found"
    );

    let file = File::open(&stack_sample_parquet).expect("Failed to open stack_sample.parquet");
    let builder = ParquetRecordBatchReaderBuilder::try_new(file).expect("Failed to create reader");
    let reader = builder.build().expect("Failed to build reader");

    let mut sample_count = 0;
    for batch_result in reader {
        let batch = batch_result.expect("Failed to read batch");
        sample_count += batch.num_rows();
    }

    assert!(sample_count > 0, "[pystacks symbol] No stack samples found");

    // === VALIDATE PERFETTO OUTPUT ===

    assert!(trace_path.exists(), "trace.pb not found");

    use perfetto_protos::trace::Trace;
    use protobuf::Message;
    use std::io::Read;

    let mut trace_data = Vec::new();
    File::open(&trace_path)
        .expect("Failed to open trace.pb")
        .read_to_end(&mut trace_data)
        .expect("Failed to read trace.pb");

    let trace = Trace::parse_from_bytes(&trace_data).expect("Failed to parse Perfetto trace");

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

    assert!(
        found_python_interned,
        "[pystacks symbol] No Python symbols found in Perfetto interned data"
    );

    let parquet_result = validate_parquet_dir(dir.path());
    assert!(
        parquet_result.is_valid(),
        "[pystacks symbol] Parquet validation failed:\nErrors: {:?}\nWarnings: {:?}",
        parquet_result.errors,
        parquet_result.warnings
    );

    let perfetto_result = validate_perfetto_trace(&trace_path);
    assert!(
        perfetto_result.is_valid(),
        "[pystacks symbol] Perfetto validation failed:\nErrors: {:?}\nWarnings: {:?}",
        perfetto_result.errors,
        perfetto_result.warnings
    );

    eprintln!(
        "  Pystacks symbol resolution passed: {} samples, {} test functions",
        sample_count,
        found_test_functions.len()
    );
}

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

    let python_script = dir.path().join("test_sleep_pystacks.py");
    let script_content = r#"
import time
import sys

def systing_sleep_leaf_function():
    """Leaf function that sleeps - should appear in STACK_SLEEP samples."""
    time.sleep(0.05)

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
    while time.time() - start_time < 10:
        systing_cpu_middle_function()
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

    let mut python_proc = Command::new(pyenv_python(PYTHON_313_VERSION))
        .arg(&python_script)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn Python process");

    let python_pid = python_proc.id();
    eprintln!("Started Python process with PID: {}", python_pid);

    thread::sleep(Duration::from_millis(1000));

    let config = Config {
        duration: 5,
        parquet_only: false,
        collect_pystacks: true,
        pystacks_pids: vec![python_pid],
        output_dir: dir.path().to_path_buf(),
        output: trace_path.clone(),
        ..Config::default()
    };

    systing(config, None).expect("systing recording failed");

    let python_status = python_proc
        .wait()
        .expect("Failed to wait for Python process");
    eprintln!("Python process exited with status: {:?}", python_status);

    // === LOAD STACK.PARQUET INTO A MAP ===
    let stack_parquet = dir.path().join("stack.parquet");
    assert!(stack_parquet.exists(), "stack.parquet not found");

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

    // === ANALYZE STACK_SAMPLE.PARQUET ===
    let stack_sample_parquet = dir.path().join("stack_sample.parquet");
    assert!(
        stack_sample_parquet.exists(),
        "stack_sample.parquet not found"
    );

    let mut sleep_samples_total = 0;
    let mut sleep_samples_with_python = 0;
    let mut running_samples_total = 0;
    let mut running_samples_with_python = 0;

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
                    0 | 2 => {
                        sleep_samples_total += 1;
                        if has_python {
                            sleep_samples_with_python += 1;
                        }
                    }
                    1 => {
                        running_samples_total += 1;
                        if has_python {
                            running_samples_with_python += 1;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    assert!(
        running_samples_total > 0,
        "No STACK_RUNNING samples captured"
    );
    assert!(sleep_samples_total > 0, "No STACK_SLEEP samples captured");

    assert!(
        running_samples_with_python > 0,
        "No Python symbols in STACK_RUNNING samples"
    );

    assert!(
        sleep_samples_with_python > 0,
        "No Python symbols in STACK_SLEEP samples"
    );

    eprintln!(
        "  Pystacks sleep stacks passed: running={}/{}, sleep={}/{}",
        running_samples_with_python,
        running_samples_total,
        sleep_samples_with_python,
        sleep_samples_total
    );
}

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

    let mut python_proc = Command::new(pyenv_python(PYTHON_311_VERSION))
        .arg(&python_script)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn Python process");

    let python_pid = python_proc.id();
    thread::sleep(Duration::from_millis(1000));

    let config = Config {
        duration: 3,
        parquet_only: false,
        collect_pystacks: true,
        pystacks_pids: vec![python_pid],
        output_dir: dir.path().to_path_buf(),
        output: trace_path.clone(),
        ..Config::default()
    };

    systing(config, None).expect("systing recording failed");
    python_proc
        .wait()
        .expect("Failed to wait for Python process");

    let stack_parquet = dir.path().join("stack.parquet");
    assert!(stack_parquet.exists(), "stack.parquet not found");

    let file = File::open(&stack_parquet).expect("Failed to open stack.parquet");
    let builder = ParquetRecordBatchReaderBuilder::try_new(file).expect("Failed to create reader");
    let reader = builder.build().expect("Failed to build reader");

    let mut total_python_stacks = 0;
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

            let is_our_stack = frames.iter().any(|f| f.contains("test_frame_error.py"));
            if !is_our_stack {
                continue;
            }

            total_python_stacks += 1;

            let has_frame_error = frames.iter().any(|f| f.contains("Frame Error"));
            if has_frame_error {
                for (idx, frame) in frames.iter().enumerate() {
                    if frame.contains("Frame Error") {
                        let python_frames_before = frames[..idx]
                            .iter()
                            .filter(|f| f.contains("(python)"))
                            .count();
                        if python_frames_before < 2 {
                            frame_error_not_at_bottom += 1;
                        }
                        break;
                    }
                }
            }

            let has_level3 = frames.iter().any(|f| f.contains("level3"));
            let has_level2 = frames.iter().any(|f| f.contains("level2"));
            let has_level1 = frames.iter().any(|f| f.contains("level1"));
            if has_level3 && has_level2 && has_level1 {
                expected_functions_found += 1;
            }
        }
    }

    assert!(total_python_stacks > 0, "No Python stacks captured");

    assert!(
        expected_functions_found > 0,
        "No stacks with expected level1/level2/level3 functions"
    );

    assert!(
        frame_error_not_at_bottom == 0,
        "{} stacks have Frame Error at unexpected positions",
        frame_error_not_at_bottom
    );
}

// =============================================================================
// Consolidated run command suite
//
// Tests the `systing -- <command>` mode. Each sub-test needs its own systing
// invocation (different commands), but they're consolidated into one test
// function to reduce overhead. Also includes the parquet_only mode check.
// =============================================================================

#[test]
#[ignore] // Requires root/BPF privileges
fn test_run_command_suite() {
    use arrow::array::{Int32Array, StringArray};
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    use std::fs::File;

    setup_bpf_environment();

    // --- Sub-test: basic command with perfetto output (combines basic + perfetto_output) ---
    eprintln!("\n  run command: basic (sleep 0.5, with perfetto)...");
    {
        let dir = TempDir::new().expect("Failed to create temp dir");
        let trace_path = dir.path().join("trace.pb");

        let run_cmd = vec!["sleep".to_string(), "0.5".to_string()];
        let traced_child =
            systing::traced_command::spawn_traced_child(&run_cmd).expect("Failed to spawn child");
        let child_pid = traced_child.pid;

        let config = Config {
            parquet_only: false,
            output_dir: dir.path().to_path_buf(),
            output: trace_path.clone(),
            ..Config::default()
        };

        let exit_code = systing(config, Some(traced_child)).expect("systing recording failed");
        assert_eq!(
            exit_code, 0,
            "[run cmd basic] sleep should exit with code 0"
        );

        // Check parquet output
        assert!(
            dir.path().join("process.parquet").exists(),
            "[run cmd basic] process.parquet not found"
        );
        assert!(
            dir.path().join("sched_slice.parquet").exists(),
            "[run cmd basic] sched_slice.parquet not found"
        );

        // Verify traced command appears in process.parquet
        let file =
            File::open(dir.path().join("process.parquet")).expect("Failed to open process.parquet");
        let builder =
            ParquetRecordBatchReaderBuilder::try_new(file).expect("Failed to create reader");
        let reader = builder.build().expect("Failed to build reader");

        let mut found_child = false;
        for batch_result in reader {
            let batch = batch_result.expect("Failed to read batch");

            let pids = batch
                .column_by_name("pid")
                .and_then(|c| c.as_any().downcast_ref::<Int32Array>());
            let names = batch
                .column_by_name("name")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>());

            if let (Some(pids), Some(_names)) = (pids, names) {
                for i in 0..batch.num_rows() {
                    if pids.value(i) == child_pid as i32 {
                        found_child = true;
                    }
                }
            }
        }

        assert!(
            found_child,
            "[run cmd basic] Traced command (PID {}) not found in process.parquet",
            child_pid
        );

        // Validate parquet
        let result = validate_parquet_dir(dir.path());
        assert!(
            result.is_valid(),
            "[run cmd basic] Parquet validation failed:\nErrors: {:?}\nWarnings: {:?}",
            result.errors,
            result.warnings
        );

        // Validate perfetto
        assert!(trace_path.exists(), "[run cmd basic] trace.pb not found");
        let perfetto_result = validate_perfetto_trace(&trace_path);
        assert!(
            perfetto_result.is_valid(),
            "[run cmd basic] Perfetto validation failed:\nErrors: {:?}\nWarnings: {:?}",
            perfetto_result.errors,
            perfetto_result.warnings
        );
    }

    // --- Sub-test: exit code propagation + parquet_only mode check ---
    eprintln!("  run command: exit code (false, parquet_only)...");
    {
        let dir = TempDir::new().expect("Failed to create temp dir");

        let run_cmd = vec!["false".to_string()];
        let traced_child =
            systing::traced_command::spawn_traced_child(&run_cmd).expect("Failed to spawn child");

        let config = Config {
            parquet_only: true,
            output_dir: dir.path().to_path_buf(),
            output: dir.path().join("trace.pb"),
            ..Config::default()
        };

        let exit_code = systing(config, Some(traced_child)).expect("systing recording failed");
        assert_eq!(
            exit_code, 1,
            "Expected exit code 1 from 'false', got {}",
            exit_code
        );

        // Also verify parquet_only mode: trace.pb should NOT exist
        assert!(
            !dir.path().join("trace.pb").exists(),
            "[parquet_only] trace.pb should not exist in parquet_only mode"
        );

        // All core parquet files should exist in parquet_only mode
        assert!(
            dir.path().join("process.parquet").exists(),
            "[parquet_only] process.parquet not found"
        );
        assert!(
            dir.path().join("thread.parquet").exists(),
            "[parquet_only] thread.parquet not found"
        );
        assert!(
            dir.path().join("sched_slice.parquet").exists(),
            "[parquet_only] sched_slice.parquet not found"
        );
    }

    // --- Sub-test: child process tracking ---
    eprintln!("  run command: child tracking...");
    {
        let dir = TempDir::new().expect("Failed to create temp dir");

        let run_cmd = vec![
            "bash".to_string(),
            "-c".to_string(),
            "sleep 0.3 & sleep 0.3 & wait".to_string(),
        ];
        let traced_child =
            systing::traced_command::spawn_traced_child(&run_cmd).expect("Failed to spawn child");

        let config = Config {
            parquet_only: true,
            output_dir: dir.path().to_path_buf(),
            output: dir.path().join("trace.pb"),
            ..Config::default()
        };

        let exit_code = systing(config, Some(traced_child)).expect("systing recording failed");
        assert_eq!(
            exit_code, 0,
            "[run cmd child tracking] bash should exit with code 0"
        );

        // Count distinct TIDs in thread.parquet
        let thread_file =
            File::open(dir.path().join("thread.parquet")).expect("Failed to open thread.parquet");
        let thread_builder =
            ParquetRecordBatchReaderBuilder::try_new(thread_file).expect("Failed to create reader");
        let thread_reader = thread_builder.build().expect("Failed to build reader");

        let mut traced_tids = std::collections::HashSet::new();
        for batch_result in thread_reader {
            let batch = batch_result.expect("Failed to read batch");
            let tids = batch
                .column_by_name("tid")
                .and_then(|c| c.as_any().downcast_ref::<Int32Array>());
            if let Some(tids) = tids {
                for i in 0..tids.len() {
                    traced_tids.insert(tids.value(i));
                }
            }
        }

        assert!(
            traced_tids.len() >= 3,
            "[run cmd child tracking] Expected at least 3 traced threads (bash + 2 sleep children), got {}",
            traced_tids.len()
        );
    }

    // --- Sub-test: duration override ---
    eprintln!("  run command: duration override...");
    {
        let dir = TempDir::new().expect("Failed to create temp dir");

        let run_cmd = vec!["sleep".to_string(), "300".to_string()];
        let traced_child =
            systing::traced_command::spawn_traced_child(&run_cmd).expect("Failed to spawn child");

        let config = Config {
            duration: 1,
            parquet_only: true,
            output_dir: dir.path().to_path_buf(),
            output: dir.path().join("trace.pb"),
            ..Config::default()
        };

        let exit_code = systing(config, Some(traced_child)).expect("systing recording failed");

        assert_ne!(
            exit_code, 0,
            "[run cmd duration] Expected non-zero exit code (child should have been interrupted by duration)"
        );

        assert!(
            dir.path().join("process.parquet").exists(),
            "[run cmd duration] process.parquet not found"
        );

        let result = validate_parquet_dir(dir.path());
        assert!(
            result.is_valid(),
            "[run cmd duration] Parquet validation failed:\nErrors: {:?}\nWarnings: {:?}",
            result.errors,
            result.warnings
        );
    }

    // --- Sub-test: signal exit code ---
    eprintln!("  run command: signal exit code...");
    {
        let dir = TempDir::new().expect("Failed to create temp dir");

        let run_cmd = vec!["sh".to_string(), "-c".to_string(), "kill -9 $$".to_string()];
        let traced_child =
            systing::traced_command::spawn_traced_child(&run_cmd).expect("Failed to spawn child");

        let config = Config {
            parquet_only: true,
            output_dir: dir.path().to_path_buf(),
            output: dir.path().join("trace.pb"),
            ..Config::default()
        };

        let exit_code = systing(config, Some(traced_child)).expect("systing recording failed");
        assert_eq!(
            exit_code, 137,
            "[run cmd signal] Expected exit code 137 (128 + SIGKILL=9), got {}",
            exit_code
        );
    }

    eprintln!("\n  All run command checks passed");
}

// =============================================================================
// Pystacks + run-and-trace mode (regression test for Arc::get_mut failure)
// =============================================================================

#[test]
#[ignore] // Requires root/BPF privileges and pystacks feature
#[cfg(feature = "pystacks")]
fn test_pystacks_run_and_trace() {
    use std::fs::File;
    use std::io::Write;

    setup_bpf_environment();

    let dir = TempDir::new().expect("Failed to create temp dir");
    let trace_path = dir.path().join("trace.pb");

    let python_script = dir.path().join("test_pystacks_run_trace.py");
    let script_content = r#"
import time

def systing_run_trace_function():
    """Function that does busy work to show up in profiling."""
    total = 0
    for i in range(1000000):
        total += i * i
    return total

def main():
    start_time = time.time()
    while time.time() - start_time < 5:
        systing_run_trace_function()

if __name__ == "__main__":
    main()
"#;

    {
        let mut file = File::create(&python_script).expect("Failed to create Python script");
        file.write_all(script_content.as_bytes())
            .expect("Failed to write Python script");
    }

    let python_bin = pyenv_python(PYTHON_313_VERSION);
    let run_cmd = vec![
        python_bin.to_str().unwrap().to_string(),
        python_script.to_str().unwrap().to_string(),
    ];
    let traced_child =
        systing::traced_command::spawn_traced_child(&run_cmd).expect("Failed to spawn child");

    let config = Config {
        parquet_only: false,
        collect_pystacks: true,
        output_dir: dir.path().to_path_buf(),
        output: trace_path.clone(),
        ..Config::default()
    };

    // This previously failed with "Unable to initialize pystacks - Arc is already shared"
    let exit_code = systing(config, Some(traced_child)).expect("systing recording failed");
    assert_eq!(
        exit_code, 0,
        "[pystacks run-trace] Python script should exit with code 0"
    );

    // Verify Python symbols appear in stack.parquet
    let stack_parquet = dir.path().join("stack.parquet");
    assert!(
        stack_parquet.exists(),
        "[pystacks run-trace] stack.parquet not found"
    );

    let (found_python_symbols, found_test_function) =
        find_python_symbols_in_parquet(&stack_parquet, "systing_run_trace_function");

    assert!(
        found_python_symbols,
        "[pystacks run-trace] No Python symbols found in stack.parquet"
    );

    assert!(
        found_test_function,
        "[pystacks run-trace] Expected function 'systing_run_trace_function' not found"
    );

    let parquet_result = validate_parquet_dir(dir.path());
    assert!(
        parquet_result.is_valid(),
        "[pystacks run-trace] Parquet validation failed:\nErrors: {:?}\nWarnings: {:?}",
        parquet_result.errors,
        parquet_result.warnings
    );

    eprintln!("  Pystacks run-and-trace mode passed");
}

// =============================================================================
// Pystacks exec event dynamic discovery (wrapper script → Python)
// =============================================================================

/// Tests that the BPF sched_process_exec handler dynamically discovers Python
/// when the traced command is a shell wrapper that forks a child which execs
/// into Python. This exercises the exec event ringbuf → handle_exec_events()
/// → add_pid() path.
///
/// The wrapper script backgrounds Python (`python script.py &`), creating a
/// new child PID that execs into Python. This new PID was not seen during
/// pystacks init, so it must be dynamically discovered via the exec event
/// handler.
#[test]
#[ignore] // Requires root/BPF privileges and pystacks feature
#[cfg(feature = "pystacks")]
fn test_pystacks_exec_discovery() {
    use std::fs::File;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    setup_bpf_environment();

    let dir = TempDir::new().expect("Failed to create temp dir");
    let trace_path = dir.path().join("trace.pb");

    // Create a Python script with a distinctive function name
    let python_script = dir.path().join("test_exec_discovery.py");
    let script_content = r#"
import time

def exec_discovery_target_function():
    """Function that does busy work to show up in profiling."""
    total = 0
    for i in range(1000000):
        total += i * i
    return total

def main():
    start_time = time.time()
    while time.time() - start_time < 5:
        exec_discovery_target_function()

if __name__ == "__main__":
    main()
"#;
    {
        let mut file = File::create(&python_script).expect("Failed to create Python script");
        file.write_all(script_content.as_bytes())
            .expect("Failed to write Python script");
    }

    // Create a wrapper that forks a child which execs into Python.
    // The traced PID is the wrapper (sh), but the Python work happens in
    // a forked child — a NEW PID that was not seen during pystacks init.
    // The exec handler must detect this child's exec into Python and call
    // add_pid() for the child PID.
    let wrapper_script = dir.path().join("wrapper.sh");
    let python_bin = pyenv_python(PYTHON_313_VERSION);
    let wrapper_content = format!(
        "#!/bin/sh\n{} {} &\nPYPID=$!\nwait $PYPID\n",
        python_bin.display(),
        python_script.display()
    );
    {
        let mut file = File::create(&wrapper_script).expect("Failed to create wrapper script");
        file.write_all(wrapper_content.as_bytes())
            .expect("Failed to write wrapper script");
        let mut perms = file.metadata().unwrap().permissions();
        perms.set_mode(0o755);
        file.set_permissions(perms).unwrap();
    }

    // Trace the wrapper script, NOT Python directly
    let run_cmd = vec![wrapper_script.to_str().unwrap().to_string()];
    let traced_child =
        systing::traced_command::spawn_traced_child(&run_cmd).expect("Failed to spawn child");

    let config = Config {
        parquet_only: false,
        collect_pystacks: true,
        // pystacks_pids is intentionally empty — discovery must happen
        // via the BPF exec event handler detecting the child's exec into Python
        output_dir: dir.path().to_path_buf(),
        output: trace_path.clone(),
        ..Config::default()
    };

    let exit_code = systing(config, Some(traced_child)).expect("systing recording failed");
    assert_eq!(
        exit_code, 0,
        "[pystacks exec-discovery] Wrapper script should exit with code 0"
    );

    // Verify Python symbols appear in stack.parquet — this proves the exec
    // handler dynamically discovered the child Python PID
    let stack_parquet = dir.path().join("stack.parquet");
    assert!(
        stack_parquet.exists(),
        "[pystacks exec-discovery] stack.parquet not found"
    );

    let (found_python_symbols, found_test_function) =
        find_python_symbols_in_parquet(&stack_parquet, "exec_discovery_target_function");

    assert!(
        found_python_symbols,
        "[pystacks exec-discovery] No Python symbols found in stack.parquet. \
         The exec event handler should have detected the child's exec into Python."
    );

    assert!(
        found_test_function,
        "[pystacks exec-discovery] Expected function 'exec_discovery_target_function' not found. \
         The exec event handler should have added the child Python PID for stack walking."
    );

    let parquet_result = validate_parquet_dir(dir.path());
    assert!(
        parquet_result.is_valid(),
        "[pystacks exec-discovery] Parquet validation failed:\nErrors: {:?}\nWarnings: {:?}",
        parquet_result.errors,
        parquet_result.warnings
    );

    eprintln!("  Pystacks exec event discovery passed");
}
