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
use common::workload::{stoppable_workload, wait_until, SLOW_MACHINE_BUDGET};
use common::{
    assert_poll_events_recorded, validate_network_trace, NetnsTestEnv, NetworkTestConfig,
};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use systing::{systing, validate_duckdb, validate_parquet_dir, validate_perfetto_trace, Config};
use tempfile::TempDir;

/// Total recording duration for netns tests (seconds). Workloads loop until
/// teardown, so this only needs to exceed BPF attach latency.
const NETNS_RECORDING_DURATION_SECS: u64 = 10;

/// Recording duration for the basic validation suite (seconds).
/// Set to 4s to give the exit workload time to generate EXIT_DEAD/EXIT_ZOMBIE
/// states during the trace; the workload loops until told to stop, so it
/// overlaps the window regardless of BPF attach latency.
const VALIDATION_SUITE_DURATION_SECS: u64 = 4;

/// Recording duration for the network suite (seconds).
const NETWORK_SUITE_DURATION_SECS: u64 = 3;

/// Read the current process's cgroup v2 path (relative to the cgroup root, e.g.
/// "/system.slice/foo.service") from `/proc/self/cgroup`. Returns `None` on a
/// system without a cgroup v2 unified hierarchy (no `0::` line).
fn current_cgroup_v2_path() -> Option<String> {
    let contents = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    contents
        .lines()
        .find_map(|line| line.strip_prefix("0::").map(|p| p.to_string()))
}

/// Python versions used by pystacks integration tests.
/// Install these via: ./scripts/setup-pystacks.sh
///
/// Per-version tests (test_pystacks_python38 .. test_pystacks_python314)
/// exercise each version individually so failures can be narrowed down.
const PYTHON_38_VERSION: &str = "3.8.20";
const PYTHON_39_VERSION: &str = "3.9.25";
const PYTHON_310_VERSION: &str = "3.10.19";
const PYTHON_311_VERSION: &str = "3.11.14";
const PYTHON_312_VERSION: &str = "3.12.12";
const PYTHON_313_VERSION: &str = "3.13.11";
const PYTHON_314_VERSION: &str = "3.14.6";

/// Get the path to a pyenv-installed Python binary.
///
/// Checks `$PYENV_ROOT/versions/<version>/bin/python<major.minor>` first
/// (works under sudo -E where HOME is reset but PYENV_ROOT is preserved),
/// then falls back to `$HOME/.pyenv/versions/<version>/bin/python<major.minor>`.
/// Returns `None` if the binary is not found (caller decides whether to skip or panic).
fn try_pyenv_python(version: &str) -> Option<PathBuf> {
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let short = format!("{}.{}", parts[0], parts[1]);

    // Prefer PYENV_ROOT (preserved by sudo -E even when HOME is reset to /root)
    let pyenv_root = std::env::var("PYENV_ROOT")
        .ok()
        .or_else(|| std::env::var("HOME").ok().map(|h| format!("{h}/.pyenv")))?;

    let path = PathBuf::from(format!("{pyenv_root}/versions/{version}/bin/python{short}"));
    path.exists().then_some(path)
}

/// Get the path to a pyenv-installed Python binary, panicking if not found.
fn pyenv_python(version: &str) -> PathBuf {
    try_pyenv_python(version).unwrap_or_else(|| {
        panic!("Python {version} not found. Install it with: ./scripts/setup-pystacks.sh")
    })
}

/// A Python process running `loop_body` forever. Killed on drop.
struct PythonWorkload {
    child: std::process::Child,
    pid: u32,
}

impl Drop for PythonWorkload {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawn a Python process that runs `loop_body` in an infinite loop, blocking
/// until the interpreter has fully initialized and executed one warm-up
/// iteration. Replaces the flaky "spawn, sleep 1s, hope pyenv shim +
/// Py_Initialize finished" pattern. The returned handle kills the child on
/// drop.
fn spawn_python_workload(
    python_bin: impl AsRef<std::ffi::OsStr>,
    dir: &std::path::Path,
    script_name: &str,
    defs: &str,
    loop_body: &str,
) -> PythonWorkload {
    let indent = |s: &str, n| {
        let pad = " ".repeat(n);
        s.lines()
            .map(|l| format!("{pad}{l}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    // One warm-up iteration before writing the ready marker: proves the
    // workload is actually executing, not just that the interpreter finished
    // init. Pystacks discovery and the recorder both start only once this
    // fires, so every sample is known-good.
    let script = format!(
        "import sys, time\n\
         {defs}\n\
         if __name__ == \"__main__\":\n\
         {warmup}\n    \
             with open(sys.argv[1], \"w\") as f:\n        \
                 f.write(\"ready\")\n    \
             while True:\n\
         {body}\n",
        warmup = indent(loop_body, 4),
        body = indent(loop_body, 8),
    );
    let script_path = dir.join(script_name);
    std::fs::write(&script_path, &script).expect("write python script");
    let ready_marker = dir.join(format!("{script_name}.ready"));
    let _ = std::fs::remove_file(&ready_marker);

    let mut child = std::process::Command::new(python_bin)
        .arg(&script_path)
        .arg(&ready_marker)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn python");
    let pid = child.id();

    // No fixed estimate here: the warm-up iteration is real work (some tests
    // burn tens of millions of bytecodes) and scales with machine speed.
    wait_until("python ready marker", || {
        if let Ok(Some(status)) = child.try_wait() {
            let mut stderr = String::new();
            if let Some(mut e) = child.stderr.take() {
                let _ = std::io::Read::read_to_string(&mut e, &mut stderr);
            }
            panic!("python exited before ready: {status:?}\nstderr:\n{stderr}");
        }
        ready_marker.exists()
    });
    PythonWorkload { child, pid }
}

/// Scan a stack.parquet file for Python symbols and a specific target function name.
/// Returns `(found_python_symbols, found_target_function)`.
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

                if found_python_symbols && found_target_function {
                    return (true, true);
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

    let dir = TempDir::new().expect("Failed to create temp dir");
    let trace_path = dir.path().join("trace.pb");

    // Spawn exit workload to generate EXIT_DEAD/EXIT_ZOMBIE states. Loop until
    // told to stop so the workload is guaranteed to overlap the full record
    // window regardless of BPF attach latency.
    let workload = stoppable_workload(move |stop| {
        while !stop.load(std::sync::atomic::Ordering::Relaxed) {
            let mut child = Command::new("bash")
                .arg("-c")
                .arg("for i in $(seq 1 50); do (exit 0) & done; wait")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("Failed to spawn workload");
            child.wait().expect("Failed to wait for workload");
            thread::sleep(Duration::from_millis(50));
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
    workload.stop();
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

    // --- Check: profile export from both producers agrees (test_e2e_profile_export) ---
    // The parquet reader and the DuckDB reader must serialize the same
    // recording to the same profile: identical header semantics and identical
    // sample tallies once stacks are resolved to frame-name sequences (frame
    // ids are producer-internal).
    eprintln!("  profile export (parquet + duckdb producers)...");
    {
        use std::collections::HashMap;

        let from_parquet = dir.path().join("from_parquet.systing");
        systing::profile_export::parquet_to_profile_export(dir.path(), &from_parquet, "test_trace")
            .expect("parquet -> profile export failed");
        let from_duckdb = dir.path().join("from_duckdb.systing");
        systing::profile_export::duckdb_to_profile_export(&duckdb_path, &from_duckdb, None)
            .expect("duckdb -> profile export failed");

        // Canonical view of one export: (utid, leaf-first frame names, event
        // type) -> summed count, plus the header for field checks.
        type Tallies = HashMap<(i64, Vec<String>, i64), i64>;
        fn canonicalize(path: &Path) -> (serde_json::Value, Tallies) {
            let text = std::fs::read_to_string(path).expect("Failed to read profile export");
            let mut lines = text.lines();
            let header: serde_json::Value =
                serde_json::from_str(lines.next().expect("[profile export] empty file"))
                    .expect("[profile export] header is not JSON");

            let mut frames: HashMap<i64, String> = HashMap::new();
            let mut stacks: HashMap<i64, Vec<String>> = HashMap::new();
            let mut tallies: Tallies = HashMap::new();
            for line in lines {
                let record: serde_json::Value =
                    serde_json::from_str(line).expect("[profile export] record is not JSON");
                let tag = record[0].as_str().expect("[profile export] tagless record");
                match tag {
                    "f" => {
                        frames.insert(
                            record[1].as_i64().unwrap(),
                            record[2].as_str().unwrap().to_string(),
                        );
                    }
                    "s" => {
                        // Define-before-use: every frame id must already be
                        // interned.
                        let names = record[2]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|id| {
                                frames
                                    .get(&id.as_i64().unwrap())
                                    .expect("[profile export] stack references undefined frame")
                                    .clone()
                            })
                            .collect();
                        stacks.insert(record[1].as_i64().unwrap(), names);
                    }
                    "x" => {
                        let names = stacks
                            .get(&record[2].as_i64().unwrap())
                            .expect("[profile export] sample references undefined stack")
                            .clone();
                        let event_type = record[3].as_i64().unwrap();
                        assert!(
                            (0..=2).contains(&event_type),
                            "[profile export] unknown event type {event_type}"
                        );
                        *tallies
                            .entry((record[1].as_i64().unwrap(), names, event_type))
                            .or_insert(0) += record[4].as_i64().unwrap();
                    }
                    _ => {}
                }
            }
            (header, tallies)
        }

        let (parquet_header, parquet_tallies) = canonicalize(&from_parquet);
        let (duckdb_header, duckdb_tallies) = canonicalize(&from_duckdb);

        assert_eq!(
            parquet_header["systing_profile_export"], 1,
            "[profile export] unexpected format version"
        );
        assert_eq!(
            parquet_header["stack_order"], "leaf_first",
            "[profile export] unexpected stack order"
        );
        for key in [
            "source_schema_version",
            "sample_event",
            "sample_period",
            "start_ts",
            "end_ts",
        ] {
            assert_eq!(
                parquet_header[key], duckdb_header[key],
                "[profile export] producers disagree on header {key}"
            );
        }
        assert!(
            !parquet_tallies.is_empty(),
            "[profile export] no sample tallies exported"
        );
        assert_eq!(
            parquet_tallies, duckdb_tallies,
            "[profile export] parquet and duckdb producers disagree on tallies"
        );
    }

    // --- Check: cgroup ids recorded and resolved to paths (test_e2e_cgroup_resolution) ---
    eprintln!("  cgroup id resolution (duckdb)...");
    {
        use std::os::unix::fs::MetadataExt;

        let conn = duckdb::Connection::open(&duckdb_path).expect("Failed to open DuckDB");

        if systing::cgroup::cgroup2_root().is_none() {
            eprintln!("    skipping: no cgroup v2 unified hierarchy on this system");
        } else {
            // cgroup_id is captured in-kernel for every task; cgroup_path is resolved
            // by walking the live cgroup hierarchy when the trace is written. At least
            // some processes must therefore end up with a resolved cgroup_path.
            let resolved: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM process \
                     WHERE cgroup_id != 0 AND cgroup_path IS NOT NULL",
                    [],
                    |row| row.get(0),
                )
                .expect("Failed to query process cgroup columns");
            assert!(
                resolved > 0,
                "[cgroup resolution] no processes had a resolved cgroup_path"
            );
            eprintln!("    {resolved} processes have a resolved cgroup_path");

            // Correctness: every distinct (cgroup_id, cgroup_path) stored in the trace
            // must match what the live cgroup hierarchy resolves that id to. cgroups
            // that have since been removed simply won't be in the live map, so we skip
            // those and require at least one positive match.
            let live_map = systing::cgroup::build_cgroup_id_map();
            let mut stmt = conn
                .prepare(
                    "SELECT DISTINCT cgroup_id, cgroup_path FROM process \
                     WHERE cgroup_path IS NOT NULL",
                )
                .expect("Failed to prepare distinct cgroup query");
            let rows = stmt
                .query_map([], |row| {
                    Ok((row.get::<_, u64>(0)?, row.get::<_, String>(1)?))
                })
                .expect("Failed to query distinct cgroups");

            let mut matched = 0usize;
            for row in rows {
                let (id, path) = row.expect("Failed to read cgroup row");
                if let Some(live_path) = live_map.get(&id) {
                    assert_eq!(
                        &path, live_path,
                        "[cgroup resolution] cgroup_id {id} resolved to {path:?} in the trace \
                         but {live_path:?} in the live hierarchy"
                    );
                    matched += 1;
                }
            }
            assert!(
                matched > 0,
                "[cgroup resolution] no recorded cgroup id could be cross-checked against \
                 the live cgroup hierarchy"
            );
            eprintln!("    cross-checked {matched} cgroup id(s) against the live hierarchy");

            // Strongest check: the test harness drives the recording in-process, so its
            // own pid is captured. Verify the recorded id/path exactly match the cgroup
            // the test is running in, derived independently from /proc/self/cgroup.
            //
            // Assumption: the cgroup2 mount root equals this process's cgroup-namespace
            // root, so mount-relative paths (what build_cgroup_id_map produces) agree
            // with the namespace-relative `0::` path from /proc/self/cgroup. This holds
            // for the normal/container cases but can diverge if the host hierarchy is
            // bind-mounted in without a cgroup namespace; the broader `matched > 0`
            // cross-check above does not depend on it.
            if let Some(expected_path) = current_cgroup_v2_path() {
                let cgroup_root = systing::cgroup::cgroup2_root()
                    .expect("cgroup v2 path present but no cgroup2 mount found");
                let abs = if expected_path == "/" {
                    cgroup_root
                } else {
                    cgroup_root.join(expected_path.trim_start_matches('/'))
                };
                let expected_id = std::fs::metadata(&abs)
                    .unwrap_or_else(|e| panic!("Failed to stat cgroup dir {}: {e}", abs.display()))
                    .ino();

                let my_pid = std::process::id() as i32;
                let present: i64 = conn
                    .query_row(
                        "SELECT COUNT(*) FROM process WHERE pid = ?",
                        [my_pid],
                        |row| row.get(0),
                    )
                    .expect("Failed to count current pid in process table");
                if present > 0 {
                    let (db_id, db_path): (u64, Option<String>) = conn
                        .query_row(
                            "SELECT cgroup_id, cgroup_path FROM process WHERE pid = ?",
                            [my_pid],
                            |row| Ok((row.get(0)?, row.get(1)?)),
                        )
                        .expect("Failed to query current process row");
                    assert_eq!(
                        db_id, expected_id,
                        "[cgroup resolution] cgroup_id mismatch for the current process"
                    );
                    assert_eq!(
                        db_path.as_deref(),
                        Some(expected_path.as_str()),
                        "[cgroup resolution] cgroup_path mismatch for the current process"
                    );
                    eprintln!(
                        "    current process cgroup resolved: id={db_id} path={expected_path}"
                    );
                } else {
                    eprintln!("    current pid {my_pid} not captured; skipping self check");
                }
            }
        }
    }

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

    let dir = TempDir::new().expect("Failed to create temp dir");
    let trace_path = dir.path().join("trace.pb");

    // Record a trace with network enabled and traffic generation
    // network_packets defaults to false, so only TCP state tracking probes are
    // loaded (not the heavier packet-level kprobes). This keeps the test fast
    // while still exercising the network state change and DuckDB validation paths.
    let config = Config {
        duration: NETWORK_SUITE_DURATION_SECS,
        parquet_only: false,
        network: true,
        output_dir: dir.path().to_path_buf(),
        output: trace_path.clone(),
        ..Config::default()
    };

    // Spawn traffic generation thread that runs continuously until signaled to stop.
    // BPF setup with network probes can take several seconds, so the thread must
    // keep generating connections throughout the entire recording window.
    // We sleep 200ms between rounds to keep traffic volume reasonable.
    use std::sync::atomic::Ordering;
    let traffic = stoppable_workload(move |stop| {
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("Failed to bind traffic listener");
        let addr = listener.local_addr().unwrap();

        while !stop.load(Ordering::Relaxed) {
            // Make a single TCP connection per iteration
            if let Ok(_stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(100)) {
                let _ = listener.accept();
            }
            thread::sleep(Duration::from_millis(200));
        }
    });

    eprintln!(
        "Recording trace ({}s, network=true, with traffic)...",
        NETWORK_SUITE_DURATION_SECS
    );
    systing(config, None).expect("systing recording failed");
    traffic.stop();
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

        // --- Check: every network_syscall/network_poll utid joins to thread.utid ---
        let orphaned_utids: i64 = conn
            .query_row(
                "SELECT
                   (SELECT COUNT(*) FROM network_syscall s WHERE NOT EXISTS (SELECT 1 FROM thread t WHERE t.utid = s.utid))
                 + (SELECT COUNT(*) FROM network_poll    p WHERE NOT EXISTS (SELECT 1 FROM thread t WHERE t.utid = p.utid))",
                [],
                |row| row.get(0),
            )
            .expect("Failed to query utid FK integrity");
        assert_eq!(
            orphaned_utids, 0,
            "[network duckdb] {orphaned_utids} network_syscall/poll rows have utid not in thread"
        );

        // Check for TCP state change events
        let state_change_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM network_packet WHERE event_type = 'TCP state_change'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);
        eprintln!(
            "    {} TCP state change events in DuckDB",
            state_change_count
        );

        assert!(
            state_change_count > 0,
            "[network duckdb] No TCP state change events recorded. \
             The inet_sock_set_state tracepoint should capture connection lifecycle events."
        );

        // Verify state change events have valid old_state_str and new_state_str values
        let valid_states_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM network_packet \
                 WHERE event_type = 'TCP state_change' \
                 AND old_state_str IS NOT NULL \
                 AND new_state_str IS NOT NULL \
                 AND old_state_str != 'UNKNOWN' \
                 AND new_state_str != 'UNKNOWN'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);
        assert!(
            valid_states_count > 0,
            "[network duckdb] TCP state change events have no valid state strings"
        );

        // Check that we see at least ESTABLISHED transitions (from connection setup)
        let established_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM network_packet \
                 WHERE event_type = 'TCP state_change' \
                 AND new_state_str = 'ESTABLISHED'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);
        eprintln!("    {} transitions to ESTABLISHED state", established_count);
        assert!(
            established_count > 0,
            "[network duckdb] No ESTABLISHED state transitions found. \
             TCP connections should produce SYN_SENT/SYN_RECV -> ESTABLISHED transitions."
        );

        // Check that TIME_WAIT transitions are captured (via tcp_time_wait kprobe rewrite)
        let time_wait_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM network_packet \
                 WHERE event_type = 'TCP state_change' \
                 AND new_state_str = 'TIME_WAIT'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);
        eprintln!("    {} transitions to TIME_WAIT state", time_wait_count);
        assert!(
            time_wait_count > 0,
            "[network duckdb] No TIME_WAIT state transitions found. \
             TCP connections should produce FIN_WAIT2/CLOSING -> TIME_WAIT transitions."
        );

        // Check that TIME_WAIT -> CLOSE transitions exist (via inet_twsk_deschedule_put kprobe).
        // Note: these only appear if TIME_WAIT sockets are destroyed during the trace.
        // With short-lived connections on loopback, tw_reuse or RST may destroy them quickly.
        let tw_close_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM network_packet \
                 WHERE event_type = 'TCP state_change' \
                 AND old_state_str = 'TIME_WAIT' \
                 AND new_state_str = 'CLOSE'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);
        eprintln!("    {} transitions from TIME_WAIT to CLOSE", tw_close_count);
        // Don't assert on tw_close_count > 0 because TIME_WAIT lasts 60s and
        // the test trace is only 3s. TIME_WAIT → CLOSE may not happen during the trace.
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

    let server_addr = netns_env.server_addr();
    let traffic = stoppable_workload(move |stop| {
        let mut i = 0u64;
        while !stop.load(std::sync::atomic::Ordering::Relaxed) {
            let message = format!("Hello from netns test round {i}");
            if let Ok(mut stream) = std::net::TcpStream::connect(&server_addr) {
                let _ = stream.write_all(message.as_bytes());
                let _ = stream.shutdown(std::net::Shutdown::Write);
                let mut response = Vec::new();
                let _ = stream.read_to_end(&mut response);
            }
            thread::sleep(Duration::from_millis(200));
            i += 1;
        }
    });

    systing(config, None).expect("systing recording failed");
    traffic.stop();
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
// Pystacks tests (each needs its own Python process)
// =============================================================================

#[test]
#[ignore] // Requires root/BPF privileges
fn test_pystacks_symbol_resolution() {
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    use std::fs::File;

    let dir = TempDir::new().expect("Failed to create temp dir");
    let trace_path = dir.path().join("trace.pb");

    let defs = r#"
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
"#;

    let workload = spawn_python_workload(
        pyenv_python(PYTHON_313_VERSION),
        dir.path(),
        "test_pystacks.py",
        defs,
        "systing_test_outer_function()",
    );
    eprintln!("Started Python process with PID: {}", workload.pid);

    let config = Config {
        duration: 3,
        parquet_only: false,
        collect_pystacks: true,
        pystacks_pids: vec![workload.pid],
        output_dir: dir.path().to_path_buf(),
        output: trace_path.clone(),
        ..Config::default()
    };

    systing(config, None).expect("systing recording failed");
    drop(workload);

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
fn test_pystacks_sleep_stacks() {
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    use std::collections::HashMap;
    use std::fs::File;

    let dir = TempDir::new().expect("Failed to create temp dir");
    let trace_path = dir.path().join("trace.pb");

    let defs = r#"
def systing_sleep_leaf_function():
    """Leaf function that sleeps - should appear in STACK_SLEEP samples."""
    time.sleep(0.05)

def systing_sleep_middle_function():
    """Middle function that calls the sleep leaf."""
    for _ in range(2):
        systing_sleep_leaf_function()

def systing_cpu_leaf_function():
    """Leaf function that does CPU work - should appear in STACK_RUNNING samples."""
    total = 0
    for i in range(100000):
        total += i * i
    return total

def systing_cpu_middle_function():
    """Middle function that calls the CPU leaf."""
    return systing_cpu_leaf_function()
"#;

    // The assertions need samples of BOTH phases inside the trace window, so
    // each loop iteration keeps both phases short: a long CPU phase (CPU work
    // runs 10-20x slower under emulation) can otherwise swallow the whole
    // window and leave zero sleep samples, depending on where the window
    // lands relative to the alternation.
    let workload = spawn_python_workload(
        pyenv_python(PYTHON_313_VERSION),
        dir.path(),
        "test_sleep_pystacks.py",
        defs,
        "systing_cpu_middle_function()\nsysting_sleep_middle_function()",
    );
    eprintln!("Started Python process with PID: {}", workload.pid);

    let config = Config {
        duration: 5,
        parquet_only: false,
        collect_pystacks: true,
        pystacks_pids: vec![workload.pid],
        output_dir: dir.path().to_path_buf(),
        output: trace_path.clone(),
        ..Config::default()
    };

    systing(config, None).expect("systing recording failed");
    drop(workload);

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
fn test_pystacks_frame_error_rate() {
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    use std::fs::File;

    let python_bin = match try_pyenv_python(PYTHON_311_VERSION) {
        Some(p) => p,
        None => {
            println!(
                "SKIPPED: Python {} not installed. Install with: ./scripts/setup-pystacks.sh",
                PYTHON_311_VERSION
            );
            return;
        }
    };

    let dir = TempDir::new().expect("Failed to create temp dir");
    let trace_path = dir.path().join("trace.pb");

    let defs = r#"
def level3():
    total = 0
    for i in range(100000):
        total += i * i
    return total

def level2():
    return level3()

def level1():
    return level2()
"#;

    let workload = spawn_python_workload(
        &python_bin,
        dir.path(),
        "test_frame_error.py",
        defs,
        "level1()",
    );

    let config = Config {
        duration: 3,
        parquet_only: false,
        collect_pystacks: true,
        pystacks_pids: vec![workload.pid],
        output_dir: dir.path().to_path_buf(),
        output: trace_path.clone(),
        ..Config::default()
    };

    systing(config, None).expect("systing recording failed");
    drop(workload);

    let stack_parquet = dir.path().join("stack.parquet");
    assert!(stack_parquet.exists(), "stack.parquet not found");

    let file = File::open(&stack_parquet).expect("Failed to open stack.parquet");
    let builder = ParquetRecordBatchReaderBuilder::try_new(file).expect("Failed to create reader");
    let reader = builder.build().expect("Failed to build reader");

    let mut total_python_stacks = 0;
    let mut frame_error_not_at_bottom = 0;
    let mut expected_functions_found = 0;
    let mut total_rows = 0;
    let mut sample_other: Option<Vec<String>> = None;

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
            total_rows += 1;

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
                if sample_other.is_none() && frames.iter().any(|f| f.contains("(python)")) {
                    sample_other = Some(frames.clone());
                }
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

    assert!(
        total_python_stacks > 0,
        "No Python stacks captured: {total_rows} total stack rows, sample (python) stack that \
         didn't match test_frame_error.py: {sample_other:?}"
    );

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
// Per-version pystacks tests
//
// Each test validates that pystacks works with a specific Python version.
// Run individually to narrow down version-specific issues:
//   ./scripts/run-integration-tests.sh trace_validation test_pystacks_python38
//   ./scripts/run-integration-tests.sh trace_validation test_pystacks_python313
// =============================================================================

/// Helper: trace a Python script with pystacks and verify symbols appear.
fn run_pystacks_version_test(full_ver: &str) {
    let python_bin = pyenv_python(full_ver);

    let defs = r#"
def pystacks_version_test_function():
    """Function that does busy work to show up in profiling."""
    total = 0
    for i in range(1000000):
        total += i * i
    return total
"#;

    let dir = TempDir::new().expect("Failed to create temp dir");
    let trace_path = dir.path().join("trace.pb");

    let workload = spawn_python_workload(
        &python_bin,
        dir.path(),
        "test_version.py",
        defs,
        "pystacks_version_test_function()",
    );
    eprintln!("Started Python {} with PID: {}", full_ver, workload.pid);

    let config = Config {
        duration: 3,
        parquet_only: true,
        collect_pystacks: true,
        pystacks_pids: vec![workload.pid],
        output_dir: dir.path().to_path_buf(),
        output: trace_path,
        ..Config::default()
    };

    systing(config, None).expect("systing recording failed");
    drop(workload);

    let stack_parquet = dir.path().join("stack.parquet");
    assert!(
        stack_parquet.exists(),
        "[Python {}] stack.parquet not found",
        full_ver
    );

    let (found_python_symbols, found_test_function) =
        find_python_symbols_in_parquet(&stack_parquet, "pystacks_version_test_function");

    assert!(
        found_python_symbols,
        "[Python {}] No Python symbols found in stack.parquet. \
         The offsets for this version may be wrong.",
        full_ver
    );

    assert!(
        found_test_function,
        "[Python {}] Expected function 'pystacks_version_test_function' not found. \
         Python symbols were found but the target function was not resolved.",
        full_ver
    );

    eprintln!("  Python {} passed", full_ver);
}

#[test]
#[ignore]
fn test_pystacks_python38() {
    run_pystacks_version_test(PYTHON_38_VERSION);
}

#[test]
#[ignore]
fn test_pystacks_python39() {
    run_pystacks_version_test(PYTHON_39_VERSION);
}

#[test]
#[ignore]
fn test_pystacks_python310() {
    run_pystacks_version_test(PYTHON_310_VERSION);
}

#[test]
#[ignore]
fn test_pystacks_python311() {
    run_pystacks_version_test(PYTHON_311_VERSION);
}

#[test]
#[ignore]
fn test_pystacks_python312() {
    run_pystacks_version_test(PYTHON_312_VERSION);
}

#[test]
#[ignore]
fn test_pystacks_python313() {
    run_pystacks_version_test(PYTHON_313_VERSION);
}

#[test]
#[ignore]
fn test_pystacks_python314() {
    run_pystacks_version_test(PYTHON_314_VERSION);
}

// =============================================================================
// Pystacks dynamic process discovery
//
// These tests exercise the paths where Python work runs in a process that did
// NOT exist (or was not yet a Python process) when systing started. The
// recorder must keep the BPF `targeted_pids` / `pystacks_pid_config` maps in
// sync as the process tree changes:
//
//   - new threads share the parent's tgid, so they "just work" once the
//     process is registered (test_pystacks_threads validates this stays true)
//   - forked children get a new tgid, so the BPF fork tracepoint must
//     propagate the parent's pystacks config to the child
//     (test_pystacks_fork, test_pystacks_multiprocessing)
//   - fork+exec into a different python (subprocess re-exec) must re-discover
//     via the exec event handler (test_pystacks_fork_exec)
// =============================================================================

/// Run a pystacks workload, record a trace, and assert that `target_function`
/// shows up as a Python frame in `stack.parquet`.
///
/// `defs` and `loop_body` are passed straight to `spawn_python_workload`.
fn run_pystacks_workload_and_check(
    test_label: &str,
    defs: &str,
    loop_body: &str,
    target_function: &str,
    duration: u64,
) {
    let dir = TempDir::new().expect("Failed to create temp dir");
    let trace_path = dir.path().join("trace.pb");

    let workload = spawn_python_workload(
        pyenv_python(PYTHON_313_VERSION),
        dir.path(),
        &format!("{test_label}.py"),
        defs,
        loop_body,
    );
    eprintln!("[{test_label}] Started Python parent PID: {}", workload.pid);

    let config = Config {
        duration,
        parquet_only: true,
        collect_pystacks: true,
        // Filter to the workload pid so the trace stays small. Forked
        // descendants are added to the BPF `pids` map automatically by the
        // sched_process_fork tracepoint, so they remain in scope. We do NOT
        // pass `pystacks_pids` so the `--pid` filter path is exercised
        // (the more common usage and the one that drives auto-discovery).
        pid: vec![workload.pid],
        output_dir: dir.path().to_path_buf(),
        output: trace_path,
        ..Config::default()
    };

    systing(config, None).expect("systing recording failed");
    drop(workload);

    let stack_parquet = dir.path().join("stack.parquet");
    assert!(
        stack_parquet.exists(),
        "[{test_label}] stack.parquet not found"
    );

    let (found_python_symbols, found_target) =
        find_python_symbols_in_parquet(&stack_parquet, target_function);

    assert!(
        found_python_symbols,
        "[{test_label}] No Python symbols found in stack.parquet at all"
    );
    assert!(
        found_target,
        "[{test_label}] Expected python function '{target_function}' not found in stack.parquet. \
         Python stacks for the spawned worker were not captured."
    );

    eprintln!("[{test_label}] passed");
}

/// New threads share the parent's tgid, so the `targeted_pids` /
/// `pystacks_pid_config` lookups (keyed by tgid) cover them automatically.
/// This is a regression guard so that future changes don't accidentally key
/// on the per-thread pid.
#[test]
#[ignore] // Requires root/BPF privileges
fn test_pystacks_threads() {
    let defs = r#"
import threading

state = {"calls": 0}

def systing_thread_worker_function():
    """Runs only on the spawned thread; must show up in pystacks samples."""
    while True:
        total = 0
        for i in range(1000000):
            total += i * i

def systing_thread_step():
    state["calls"] += 1
    if state["calls"] == 1:
        # Warm-up iteration runs before the ready marker is written -- just
        # busy spin so the parent looks like a real python process.
        total = 0
        for i in range(1000000):
            total += i * i
        return
    if state["calls"] == 2:
        # Spawn the worker thread on the first post-ready iteration so it's
        # born after systing has started (and possibly after BPF attach).
        # Either way the tgid lookup covers it -- that's what the test
        # asserts -- but spawning here exercises the "thread born during
        # the trace" case rather than only "thread already alive at attach."
        t = threading.Thread(target=systing_thread_worker_function, daemon=True)
        t.start()
        return
    # Steady state: parent stays mostly idle so the worker thread gets the GIL.
    time.sleep(0.1)
"#;

    run_pystacks_workload_and_check(
        "test_pystacks_threads",
        defs,
        "systing_thread_step()",
        "systing_thread_worker_function",
        5,
    );
}

/// `os.fork()` children get a new tgid. The BPF sched_process_fork tracepoint
/// must propagate the parent's pystacks config to the child or all of the
/// child's Python stacks are dropped.
#[test]
#[ignore] // Requires root/BPF privileges
fn test_pystacks_fork() {
    let defs = r#"
import os

state = {"calls": 0, "worker": None}
PARENT_PID = os.getpid()

def systing_fork_worker_function():
    """Runs only in the forked child; must show up in pystacks samples."""
    total = 0
    for i in range(1000000):
        total += i * i
    return total

def systing_fork_step():
    state["calls"] += 1
    if state["calls"] == 1:
        # Warm-up iteration runs before the ready marker is written -- just
        # busy spin so the parent looks like a real python process.
        total = 0
        for i in range(1000000):
            total += i * i
        return
    # Kill the previous worker (if any) and fork a fresh one. systing's BPF
    # setup time is variable (skel.load() alone can take 2-3s on a debug
    # build), so a single fork at a fixed delay races against the
    # sched_process_fork tracepoint attaching. Re-forking once a second is
    # robust: at least one fork lands after the tracepoint is live, and
    # that fork's pystacks config gets propagated.
    if state["worker"] is not None:
        try:
            os.kill(state["worker"], 9)
            os.waitpid(state["worker"], 0)
        except (OSError, ChildProcessError):
            pass
    pid = os.fork()
    if pid == 0:
        # Exit when the parent disappears (drop() SIGKILLs it) so we
        # don't leave an orphan spinning forever after the test ends.
        while os.getppid() == PARENT_PID:
            systing_fork_worker_function()
        os._exit(0)
    state["worker"] = pid
    time.sleep(1.0)
"#;

    run_pystacks_workload_and_check(
        "test_pystacks_fork",
        defs,
        "systing_fork_step()",
        "systing_fork_worker_function",
        6,
    );
}

/// `multiprocessing.Process` with the (Linux default) `fork` start method
/// is the most common way Python apps fan out CPU work. It's the same
/// kernel-level fork as `os.fork()`, but goes through the multiprocessing
/// bootstrap, so it exercises a deeper Python stack and a longer setup
/// window before the worker reaches its target function.
#[test]
#[ignore] // Requires root/BPF privileges
fn test_pystacks_multiprocessing() {
    let defs = r#"
import multiprocessing, os

state = {"calls": 0, "worker": None}
PARENT_PID = os.getpid()

def systing_mp_worker_function():
    """multiprocessing target; must show up in pystacks samples."""
    # Exit when the parent disappears (drop() SIGKILLs it -- bypasses
    # multiprocessing's own daemon cleanup, which uses atexit).
    while os.getppid() == PARENT_PID:
        total = 0
        for i in range(1000000):
            total += i * i

def systing_mp_step():
    state["calls"] += 1
    if state["calls"] == 1:
        # Warm-up iteration: just busy spin (see test_pystacks_fork).
        total = 0
        for i in range(1000000):
            total += i * i
        return
    # Re-fork once a second so at least one fork lands after BPF attach
    # (see test_pystacks_fork for why a fixed delay is racy).
    if state["worker"] is not None:
        try:
            state["worker"].kill()
            state["worker"].join(timeout=2)
        except Exception:
            pass
    ctx = multiprocessing.get_context("fork")
    p = ctx.Process(target=systing_mp_worker_function, daemon=True)
    p.start()
    state["worker"] = p
    time.sleep(1.0)
"#;

    run_pystacks_workload_and_check(
        "test_pystacks_multiprocessing",
        defs,
        "systing_mp_step()",
        "systing_mp_worker_function",
        6,
    );
}

/// fork + exec into a fresh python (`subprocess.Popen([sys.executable, ...])`)
/// — the most common subprocess pattern for Python services. The forked child
/// inherits the parent's pystacks config (from the fork tracepoint) but then
/// execs into a brand new address space, so the inherited config is stale and
/// must be cleared. The exec event handler should then re-discover the new
/// python and re-register it.
#[test]
#[ignore] // Requires root/BPF privileges
fn test_pystacks_fork_exec() {
    let dir = TempDir::new().expect("Failed to create temp dir");
    let trace_path = dir.path().join("trace.pb");

    // The subprocess script: a busy loop with a unique function name so we
    // can find it in stack.parquet.
    let child_script = dir.path().join("test_pystacks_fork_exec_child.py");
    std::fs::write(
        &child_script,
        r#"
import os
_initial_ppid = os.getppid()

def systing_fork_exec_child_function():
    total = 0
    for i in range(1000000):
        total += i * i
    return total

# Exit when the parent disappears so we don't leave an orphan spinning forever.
while os.getppid() == _initial_ppid:
    systing_fork_exec_child_function()
"#,
    )
    .expect("write child script");
    let child_script_str = child_script.to_string_lossy();

    let defs = format!(
        r#"
import os, subprocess

state = {{"calls": 0, "worker": None}}
CHILD_SCRIPT = "{child_script_str}"

def systing_fork_exec_step():
    state["calls"] += 1
    if state["calls"] == 1:
        total = 0
        for i in range(1000000):
            total += i * i
        return
    # Re-fork+exec once a second so at least one lands after BPF attach
    # (see test_pystacks_fork for why a fixed delay is racy).
    if state["worker"] is not None:
        try:
            state["worker"].kill()
            state["worker"].wait(timeout=2)
        except Exception:
            pass
    # subprocess.Popen forks then execs into a fresh python. The forked
    # child briefly inherits the parent's pystacks config (correct, since
    # the address space is shared CoW until exec) and then execs into a
    # brand new address space (the inherited config must be cleared).
    p = subprocess.Popen([sys.executable, CHILD_SCRIPT])
    state["worker"] = p
    time.sleep(1.0)
"#
    );

    let workload = spawn_python_workload(
        pyenv_python(PYTHON_313_VERSION),
        dir.path(),
        "test_pystacks_fork_exec.py",
        &defs,
        "systing_fork_exec_step()",
    );
    eprintln!(
        "[test_pystacks_fork_exec] Started Python parent PID: {}",
        workload.pid
    );

    let config = Config {
        // Longer duration: the exec re-discovery path goes through userspace
        // (read /proc/<pid>/maps, parse ELF, ...) and may need the retry
        // backoff (~100ms). Give it plenty of room.
        duration: 8,
        parquet_only: true,
        collect_pystacks: true,
        pid: vec![workload.pid],
        output_dir: dir.path().to_path_buf(),
        output: trace_path,
        ..Config::default()
    };

    systing(config, None).expect("systing recording failed");
    drop(workload);

    // subprocess child can outlive the workload's drop; clean it up so it
    // doesn't keep burning CPU after the test.
    let _ = std::process::Command::new("pkill")
        .args(["-f", &child_script_str])
        .status();

    let stack_parquet = dir.path().join("stack.parquet");
    assert!(
        stack_parquet.exists(),
        "[test_pystacks_fork_exec] stack.parquet not found"
    );

    let (found_python_symbols, found_target) =
        find_python_symbols_in_parquet(&stack_parquet, "systing_fork_exec_child_function");

    assert!(
        found_python_symbols,
        "[test_pystacks_fork_exec] No Python symbols found in stack.parquet at all"
    );
    assert!(
        found_target,
        "[test_pystacks_fork_exec] Expected python function 'systing_fork_exec_child_function' \
         not found in stack.parquet. The exec-event re-discovery path is not registering the \
         re-exec'd python."
    );

    eprintln!("[test_pystacks_fork_exec] passed");
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
#[ignore] // Requires root/BPF privileges
fn test_pystacks_run_and_trace() {
    use std::fs::File;
    use std::io::Write;

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
#[ignore] // Requires root/BPF privileges
fn test_pystacks_exec_discovery() {
    use std::fs::File;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

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

// =============================================================================
// Marker recording integration test
// =============================================================================

/// Recording duration for marker tests (seconds).
/// 3s provides ~10+ loop iterations at 250ms/iteration, giving ample margin
/// for events to be captured after BPF initialization (~500ms).
const MARKER_RECORDING_DURATION_SECS: u64 = 3;

/// Search a parquet file's column for a row matching a predicate.
/// Returns true if any matching row is found.
fn parquet_column_matches(
    path: &std::path::Path,
    column: &str,
    pred: impl Fn(&str) -> bool,
) -> bool {
    use arrow::array::StringArray;
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

    let file = std::fs::File::open(path)
        .unwrap_or_else(|e| panic!("Failed to open {}: {e}", path.display()));
    let reader = ParquetRecordBatchReaderBuilder::try_new(file)
        .expect("Failed to create reader")
        .build()
        .expect("Failed to build reader");

    for batch in reader {
        let batch = batch.expect("Failed to read batch");
        if let Some(col) = batch.column_by_name(column) {
            let arr = col
                .as_any()
                .downcast_ref::<StringArray>()
                .expect("column is not StringArray");
            for i in 0..arr.len() {
                if !arr.is_null(i) && pred(arr.value(i)) {
                    return true;
                }
            }
        }
    }
    false
}

fn parquet_column_contains(path: &std::path::Path, column: &str, target: &str) -> bool {
    parquet_column_matches(path, column, |v| v == target)
}

/// Check whether a parquet file contains a specific i64 value in a named column.
fn parquet_int_column_contains(path: &std::path::Path, column: &str, target: i64) -> bool {
    use arrow::array::Int64Array;
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

    let file = std::fs::File::open(path)
        .unwrap_or_else(|e| panic!("Failed to open {}: {e}", path.display()));
    let reader = ParquetRecordBatchReaderBuilder::try_new(file)
        .expect("Failed to create reader")
        .build()
        .expect("Failed to build reader");

    for batch in reader {
        let batch = batch.expect("Failed to read batch");
        if let Some(col) = batch.column_by_name(column) {
            let arr = col
                .as_any()
                .downcast_ref::<Int64Array>()
                .expect("column is not Int64Array");
            for i in 0..arr.len() {
                if !arr.is_null(i) && arr.value(i) == target {
                    return true;
                }
            }
        }
    }
    false
}

fn parquet_column_contains_prefix(path: &std::path::Path, column: &str, prefix: &str) -> bool {
    parquet_column_matches(path, column, |v| v.starts_with(prefix))
}

/// Parameters for a marker workload used by [`run_marker_recording`].
struct MarkerWorkloadConfig {
    /// Syscall mode value passed as arg 2 to faccessat2.
    /// Use `-975i64` for the C sign-extended form, or `(-975i32 as u32) as i64` for
    /// the zero-extended form produced by Python ctypes and some JVM runtimes.
    mode: i64,
    /// Pathname for START/END range events. Format: `"Track:event"` or just `"event"`
    /// to use the default `"Markers"` track.
    range_name: &'static str,
    /// Pathname for INSTANT events.
    instant_name: &'static str,
    /// Info value passed as arg 3 (flags) for range START/END events.
    range_info: i64,
    /// Info value passed as arg 3 (flags) for INSTANT events.
    instant_info: i64,
    /// Also enable syscall tracing (`--syscalls`). The probe recorder then streams
    /// syscall slices into the same track/slice tables the markers are written to.
    syscalls: bool,
}

/// Run a marker-only systing recording while a workload thread emits faccessat2 marker events.
///
/// Spawns a thread that loops: START range → sleep 50 ms → END range → INSTANT → sleep 200 ms,
/// running until the recording completes so the events span BPF attach.
///
/// Returns the [`TempDir`] holding the output Parquet files. The caller is responsible
/// for asserting the expected contents.
fn run_marker_recording(cfg: MarkerWorkloadConfig) -> TempDir {
    use std::ffi::CString;
    use std::sync::atomic::Ordering;
    use std::thread;
    use std::time::Duration;
    use syscalls::Sysno;

    let dir = TempDir::new().expect("Failed to create temp dir");

    let mode = cfg.mode;
    let range_info = cfg.range_info;
    let instant_info = cfg.instant_info;
    let range_name = CString::new(cfg.range_name).unwrap();
    let instant_name = CString::new(cfg.instant_name).unwrap();
    let sysno = Sysno::faccessat2 as i64;

    // The loop spans BPF attach (markers emitted before the probes are live
    // are simply not recorded), so no head-start delay is needed.
    let workload = stoppable_workload(move |stop| {
        // SAFETY: CString pointers remain valid for the duration of each syscall.
        // faccessat2 reads the pathname argument but does not store the pointer.
        while !stop.load(Ordering::Relaxed) {
            unsafe {
                libc::syscall(sysno, 0i64, range_name.as_ptr(), mode, range_info);
                // START
            }
            thread::sleep(Duration::from_millis(50));
            unsafe {
                libc::syscall(sysno, 1i64, range_name.as_ptr(), mode, range_info);
                // END
            }
            unsafe {
                libc::syscall(sysno, 2i64, instant_name.as_ptr(), mode, instant_info);
                // INSTANT
            }
            thread::sleep(Duration::from_millis(200));
        }
    });

    let config = Config {
        duration: MARKER_RECORDING_DURATION_SECS,
        output_dir: dir.path().to_path_buf(),
        no_sched: true,
        no_cpu_stack_traces: true,
        no_sleep_stack_traces: true,
        no_interruptible_stack_traces: true,
        network: false,
        collect_pystacks: false,
        markers: true,
        syscalls: cfg.syscalls,
        parquet_only: true,
        ..Config::default()
    };

    systing(config, None).expect("systing recording failed");
    workload.stop();

    dir
}

#[test]
#[ignore] // Requires root/BPF privileges
fn test_e2e_marker_recording() {
    // Pass mode as i64 = -975: libc::syscall promotes this to a 64-bit register
    // value of 0xFFFFFFFFFFFFFC31 (sign-extended). This exercises the sign-extended
    // calling convention. See test_e2e_marker_recording_zero_extended for the
    // zero-extended path (e.g. Python ctypes, some JVM runtimes).

    let dir = run_marker_recording(MarkerWorkloadConfig {
        mode: -975i64,
        range_name: "MyTrack:range_event",
        instant_name: "checkpoint",
        range_info: 42,
        instant_info: 77,
        syscalls: false,
    });

    // --- Validate slice.parquet contains the range event ---
    eprintln!("  marker recording: validating slice.parquet...");
    let slice_path = dir.path().join("slice.parquet");
    assert!(
        slice_path.exists(),
        "slice.parquet not found - marker range event was not recorded"
    );
    assert!(
        parquet_column_contains(&slice_path, "name", "range_event"),
        "range_event not found in slice.parquet"
    );

    // --- Validate instant.parquet contains the instant event ---
    eprintln!("  marker recording: validating instant.parquet...");
    let instant_path = dir.path().join("instant.parquet");
    assert!(
        instant_path.exists(),
        "instant.parquet not found - marker instant event was not recorded"
    );
    assert!(
        parquet_column_contains(&instant_path, "name", "checkpoint"),
        "checkpoint instant not found in instant.parquet"
    );

    // --- Validate track.parquet has both track names ---
    eprintln!("  marker recording: validating track.parquet...");
    let track_path = dir.path().join("track.parquet");
    assert!(track_path.exists(), "track.parquet not found");
    assert!(
        parquet_column_contains(&track_path, "name", "MyTrack"),
        "MyTrack not found in track.parquet"
    );
    assert!(
        parquet_column_contains(&track_path, "name", "Markers"),
        "Markers track not found in track.parquet"
    );

    // --- Validate args.parquet contains the info value for the range event ---
    eprintln!("  marker recording: validating args.parquet...");
    let args_path = dir.path().join("args.parquet");
    assert!(
        args_path.exists(),
        "args.parquet not found - marker info was not recorded"
    );
    assert!(
        parquet_column_contains(&args_path, "key", "info"),
        "info key not found in args.parquet"
    );
    assert!(
        parquet_int_column_contains(&args_path, "int_value", 42),
        "info value 42 not found in args.parquet"
    );

    // --- Validate instant_args.parquet contains the info value for the instant event ---
    eprintln!("  marker recording: validating instant_args.parquet...");
    let instant_args_path = dir.path().join("instant_args.parquet");
    assert!(
        instant_args_path.exists(),
        "instant_args.parquet not found - marker instant info was not recorded"
    );
    assert!(
        parquet_column_contains(&instant_args_path, "key", "info"),
        "info key not found in instant_args.parquet"
    );
    assert!(
        parquet_int_column_contains(&instant_args_path, "int_value", 77),
        "info value 77 not found in instant_args.parquet"
    );

    eprintln!("  All marker recording checks passed");
}

/// Regression test for the zero-extended calling convention.
///
/// Some language runtimes (Python ctypes, certain JVM variants) pass a 32-bit
/// mode argument as an unsigned zero-extended 64-bit value. For -975, that
/// puts 0x00000000FFFFFC31 in the register instead of 0xFFFFFFFFFFFFFC31
/// (sign-extended, as C default-argument promotion produces). The BPF sentinel
/// check must use a 32-bit comparison to match both forms; this test exercises
/// the zero-extended path to ensure it is never broken again.
#[test]
#[ignore] // Requires root/BPF privileges
fn test_e2e_marker_recording_zero_extended() {
    // Cast i32(-975) to u32 (0xFFFFFC31), then to i64 (4294966321 = 0x00000000FFFFFC31).
    // libc::syscall places this directly in the register, simulating runtimes that
    // do not sign-extend their mode argument.
    let mode_zero_extended: i64 = (-975i32 as u32) as i64;
    debug_assert_ne!(
        mode_zero_extended,
        -975i64,
        "zero-extended and sign-extended representations must differ for this test to be meaningful"
    );

    let dir = run_marker_recording(MarkerWorkloadConfig {
        mode: mode_zero_extended,
        range_name: "ZETrack:ze_range",
        instant_name: "ze_instant",
        range_info: 0,
        instant_info: 0,
        syscalls: false,
    });

    eprintln!("  zero-extended marker: validating slice.parquet...");
    let slice_path = dir.path().join("slice.parquet");
    assert!(
        slice_path.exists(),
        "slice.parquet not found - zero-extended marker range was not recorded"
    );
    assert!(
        parquet_column_contains(&slice_path, "name", "ze_range"),
        "ze_range not found in slice.parquet - zero-extended sentinel comparison failed"
    );

    eprintln!("  zero-extended marker: validating instant.parquet...");
    let instant_path = dir.path().join("instant.parquet");
    assert!(
        instant_path.exists(),
        "instant.parquet not found - zero-extended marker instant was not recorded"
    );
    assert!(
        parquet_column_contains(&instant_path, "name", "ze_instant"),
        "ze_instant not found in instant.parquet"
    );

    eprintln!("  zero-extended marker: validating track.parquet...");
    let track_path = dir.path().join("track.parquet");
    assert!(track_path.exists(), "track.parquet not found");
    assert!(
        parquet_column_contains(&track_path, "name", "ZETrack"),
        "ZETrack not found in track.parquet"
    );

    eprintln!("  All zero-extended marker recording checks passed");
}

/// Regression test: markers and syscall tracing (probe recorder) enabled together.
///
/// Both the probe recorder (which streams syscall slices during recording) and the
/// marker recorder (which writes buffered markers at trace-generation time) emit rows
/// into the same track/slice/instant/args tables. They used to write through two
/// separate parquet writers targeting the same files, so whichever writer closed last
/// silently clobbered the other's data (markers won; all syscall slices were lost).
/// They also allocated track/slice/instant IDs from independent counters starting at
/// 1, so even without the clobber the merged tables would have had colliding IDs.
///
/// This test records with both enabled and verifies both data sets survive with
/// unique, mutually-consistent IDs.
#[test]
#[ignore] // Requires root/BPF privileges
fn test_e2e_marker_syscall_no_clobber() {
    // The marker workload's own syscalls (faccessat2 + nanosleep) provide the
    // syscall activity, so no extra workload is needed.
    let dir = run_marker_recording(MarkerWorkloadConfig {
        mode: -975i64,
        range_name: "ClobberTrack:clobber_range",
        instant_name: "clobber_checkpoint",
        range_info: 42,
        instant_info: 77,
        syscalls: true,
    });

    // --- Convert to DuckDB for SQL assertions ---
    let duckdb_path = dir.path().join("trace.duckdb");
    systing::duckdb::parquet_to_duckdb(dir.path(), &duckdb_path, "marker_syscall")
        .expect("DuckDB conversion failed");
    let conn = duckdb::Connection::open(&duckdb_path).expect("Failed to open DuckDB");

    // --- Check: syscall slices (probe recorder) survived ---
    eprintln!("  syscall slices...");
    let syscall_slices: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM slice WHERE category = 'syscall'",
            [],
            |row| row.get(0),
        )
        .expect("Failed to query syscall slices");
    assert!(
        syscall_slices > 0,
        "no syscall slices in the trace - the marker writer clobbered the probe \
         recorder's slice data"
    );
    eprintln!("    {syscall_slices} syscall slices");

    // --- Check: marker slices and instants (marker recorder) survived ---
    eprintln!("  marker slices and instants...");
    let marker_slices: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM slice WHERE name = 'clobber_range'",
            [],
            |row| row.get(0),
        )
        .expect("Failed to query marker slices");
    assert!(
        marker_slices > 0,
        "no marker range slices in the trace - the probe writer clobbered the marker data"
    );
    let marker_instants: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM instant WHERE name = 'clobber_checkpoint'",
            [],
            |row| row.get(0),
        )
        .expect("Failed to query marker instants");
    assert!(marker_instants > 0, "no marker instants in the trace");
    eprintln!("    {marker_slices} marker slices, {marker_instants} marker instants");

    // --- Check: tracks from both recorders coexist ---
    eprintln!("  tracks from both recorders...");
    for track in ["syscalls", "ClobberTrack"] {
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM track WHERE name = ?",
                [track],
                |row| row.get(0),
            )
            .expect("Failed to query track");
        assert!(count > 0, "track '{track}' missing from track table");
    }

    // --- Check: IDs are unique across both recorders ---
    eprintln!("  id uniqueness...");
    for table in ["track", "slice", "instant"] {
        let duplicates: i64 = conn
            .query_row(
                &format!(
                    "SELECT COUNT(*) FROM (SELECT id FROM {table} GROUP BY id HAVING COUNT(*) > 1)"
                ),
                [],
                |row| row.get(0),
            )
            .expect("Failed to query duplicate ids");
        assert_eq!(
            duplicates, 0,
            "{table} table has duplicate ids (probe and marker recorders must allocate \
             from a shared id sequence)"
        );
    }

    // --- Check: referential integrity across the merged tables ---
    eprintln!("  referential integrity...");
    let orphan_slices: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM slice s LEFT JOIN track t ON s.track_id = t.id \
             WHERE t.id IS NULL",
            [],
            |row| row.get(0),
        )
        .expect("Failed to query orphan slices");
    assert_eq!(orphan_slices, 0, "slice rows reference missing track ids");
    let orphan_args: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM args a LEFT JOIN slice s ON a.slice_id = s.id \
             WHERE s.id IS NULL",
            [],
            |row| row.get(0),
        )
        .expect("Failed to query orphan args");
    assert_eq!(orphan_args, 0, "args rows reference missing slice ids");
    let orphan_instant_args: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM instant_args ia LEFT JOIN instant i \
             ON ia.instant_id = i.id WHERE i.id IS NULL",
            [],
            |row| row.get(0),
        )
        .expect("Failed to query orphan instant_args");
    assert_eq!(
        orphan_instant_args, 0,
        "instant_args rows reference missing instant ids"
    );

    // --- Check: thread attribution survives for both recorders' rows ---
    // Both syscall slices and marker slices/instants carry a utid; every non-null
    // utid must resolve to a thread row.
    eprintln!("  utid attribution...");
    let orphan_utids: i64 = conn
        .query_row(
            "SELECT \
               (SELECT COUNT(*) FROM slice s LEFT JOIN thread t ON s.utid = t.utid \
                WHERE s.utid IS NOT NULL AND t.utid IS NULL) + \
               (SELECT COUNT(*) FROM instant i LEFT JOIN thread t ON i.utid = t.utid \
                WHERE i.utid IS NOT NULL AND t.utid IS NULL)",
            [],
            |row| row.get(0),
        )
        .expect("Failed to query orphan utids");
    assert_eq!(
        orphan_utids, 0,
        "slice/instant rows reference utids missing from the thread table"
    );

    eprintln!("  All marker+syscall coexistence checks passed");
}

/// Count rows in a parquet file.
fn parquet_row_count(path: &std::path::Path) -> usize {
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

    let file = std::fs::File::open(path)
        .unwrap_or_else(|e| panic!("Failed to open {}: {e}", path.display()));
    let reader = ParquetRecordBatchReaderBuilder::try_new(file)
        .expect("Failed to create reader")
        .build()
        .expect("Failed to build reader");

    reader
        .into_iter()
        .map(|batch| batch.expect("Failed to read batch").num_rows())
        .sum()
}

/// Integration test for marker threshold (instant event counting) in continuous mode.
///
/// Configures systing with `--continuous 3` (3-second ring buffer window) and
/// `--marker-threshold 3` (stop after 3 instant marker events). A workload
/// thread emits instant events in a loop. After the third instant event
/// the threshold triggers and systing stops. We validate that the trace
/// contains the expected instant events.
#[test]
#[ignore] // Requires root/BPF privileges
fn test_e2e_marker_threshold() {
    use std::ffi::CString;
    use std::sync::atomic::Ordering;
    use std::thread;
    use std::time::{Duration, Instant};
    use syscalls::Sysno;

    let dir = TempDir::new().expect("Failed to create temp dir");

    let mode = -975i64;
    let instant_name = CString::new("Threshold:ping").unwrap();
    let sysno = Sysno::faccessat2 as i64;

    // Workload: emit INSTANT events in a loop with 500ms pauses.
    // With marker_threshold=3 the third instant after BPF attach triggers
    // shutdown; the loop spans attach, so no head-start delay is needed.
    let workload = stoppable_workload(move |stop| {
        while !stop.load(Ordering::Relaxed) {
            unsafe {
                libc::syscall(sysno, 2i64, instant_name.as_ptr(), mode, 0i64); // INSTANT
            }
            thread::sleep(Duration::from_millis(500));
        }
    });

    let start = Instant::now();

    let config = Config {
        continuous: 3,             // 3-second ring buffer window
        marker_threshold: Some(3), // Stop after 3 instant events
        output_dir: dir.path().to_path_buf(),
        no_sched: true,
        no_cpu_stack_traces: true,
        no_sleep_stack_traces: true,
        no_interruptible_stack_traces: true,
        network: false,
        collect_pystacks: false,
        markers: true,
        parquet_only: true,
        ..Config::default()
    };

    systing(config, None).expect("systing recording failed");
    let elapsed = start.elapsed();
    workload.stop();

    eprintln!(
        "  marker threshold: recording took {:.1}s",
        elapsed.as_secs_f64()
    );
    assert!(
        elapsed < SLOW_MACHINE_BUDGET,
        "Threshold should have triggered well before timeout; took {:.1}s",
        elapsed.as_secs_f64()
    );

    // --- Validate instant.parquet contains the instant events ---
    eprintln!("  marker threshold: validating instant.parquet...");
    let instant_path = dir.path().join("instant.parquet");
    assert!(
        instant_path.exists(),
        "instant.parquet not found - marker instant events were not recorded"
    );
    assert!(
        parquet_column_contains(&instant_path, "name", "ping"),
        "ping not found in instant.parquet"
    );
    let instant_count = parquet_row_count(&instant_path);
    assert!(
        instant_count >= 3,
        "Expected at least 3 instant events, got {instant_count}"
    );

    // --- Validate track.parquet has the threshold track ---
    eprintln!("  marker threshold: validating track.parquet...");
    let track_path = dir.path().join("track.parquet");
    assert!(track_path.exists(), "track.parquet not found");
    assert!(
        parquet_column_contains(&track_path, "name", "Threshold"),
        "Threshold track not found in track.parquet"
    );

    eprintln!("  All marker threshold checks passed");
}

/// Integration test for marker duration threshold in continuous mode.
///
/// Configures systing with `--continuous 3` and `--marker-duration-threshold 800`
/// (stop when any marker range exceeds 800ms). A workload thread continuously
/// emits short ranges (200ms) followed by a long range (1000ms) in a loop.
/// The long range exceeds the 800ms threshold and triggers shutdown.
/// We validate that the trace captured the expected events and that the
/// triggering range's duration is >= 800ms.
#[test]
#[ignore] // Requires root/BPF privileges
fn test_e2e_marker_duration_threshold() {
    use std::ffi::CString;
    use std::sync::atomic::Ordering;
    use std::thread;
    use std::time::{Duration, Instant};
    use syscalls::Sysno;

    use arrow::array::Int64Array;
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

    let dir = TempDir::new().expect("Failed to create temp dir");

    let mode = -975i64;
    let range_name = CString::new("DurTest:slow_op").unwrap();
    let sysno = Sysno::faccessat2 as i64;

    // Workload: continuously emit a short range (200ms) then a long range (1000ms).
    // The long range exceeds the 800ms threshold and triggers shutdown.
    // The loop repeats until stopped and spans BPF attach.
    let workload = stoppable_workload(move |stop| {
        while !stop.load(Ordering::Relaxed) {
            // Short range (below threshold)
            unsafe {
                libc::syscall(sysno, 0i64, range_name.as_ptr(), mode, 0i64); // START
            }
            thread::sleep(Duration::from_millis(200));
            unsafe {
                libc::syscall(sysno, 1i64, range_name.as_ptr(), mode, 0i64); // END
            }
            thread::sleep(Duration::from_millis(50));

            if stop.load(Ordering::Relaxed) {
                break;
            }

            // Long range (exceeds 800ms threshold)
            unsafe {
                libc::syscall(sysno, 0i64, range_name.as_ptr(), mode, 0i64); // START
            }
            thread::sleep(Duration::from_millis(1000));
            unsafe {
                libc::syscall(sysno, 1i64, range_name.as_ptr(), mode, 0i64); // END
            }
            thread::sleep(Duration::from_millis(100));
        }
    });

    let start = Instant::now();

    let config = Config {
        continuous: 3,                        // 3-second ring buffer window
        marker_duration_threshold: Some(800), // Stop when any range >= 800ms
        output_dir: dir.path().to_path_buf(),
        no_sched: true,
        no_cpu_stack_traces: true,
        no_sleep_stack_traces: true,
        no_interruptible_stack_traces: true,
        network: false,
        collect_pystacks: false,
        markers: true,
        parquet_only: true,
        ..Config::default()
    };

    systing(config, None).expect("systing recording failed");
    let elapsed = start.elapsed();
    workload.stop();

    // The duration threshold should trigger once BPF captures a 1000ms range.
    eprintln!(
        "  marker duration threshold: recording took {:.1}s",
        elapsed.as_secs_f64()
    );
    assert!(
        elapsed < SLOW_MACHINE_BUDGET,
        "Duration threshold should have triggered well before timeout; took {:.1}s",
        elapsed.as_secs_f64()
    );

    // --- Validate slice.parquet contains the range events ---
    eprintln!("  marker duration threshold: validating slice.parquet...");
    let slice_path = dir.path().join("slice.parquet");
    assert!(
        slice_path.exists(),
        "slice.parquet not found - marker range events were not recorded"
    );
    assert!(
        parquet_column_contains(&slice_path, "name", "slow_op"),
        "slow_op not found in slice.parquet"
    );

    // At least the triggering range should be present
    let range_count = parquet_row_count(&slice_path);
    assert!(
        range_count >= 1,
        "Expected at least 1 completed range, got {range_count}"
    );

    // Verify that at least one range has dur >= 800ms (800_000_000 ns)
    let file = std::fs::File::open(&slice_path).expect("Failed to open slice.parquet");
    let reader = ParquetRecordBatchReaderBuilder::try_new(file)
        .expect("Failed to create reader")
        .build()
        .expect("Failed to build reader");

    let mut found_long_range = false;
    for batch in reader {
        let batch = batch.expect("Failed to read batch");
        if let Some(col) = batch.column_by_name("dur") {
            let arr = col
                .as_any()
                .downcast_ref::<Int64Array>()
                .expect("dur column is not Int64Array");
            for i in 0..arr.len() {
                if !arr.is_null(i) && arr.value(i) >= 800_000_000 {
                    found_long_range = true;
                    eprintln!(
                        "  marker duration threshold: found range with dur={}ms",
                        arr.value(i) / 1_000_000
                    );
                }
            }
        }
    }
    assert!(
        found_long_range,
        "No range with duration >= 800ms found in slice.parquet"
    );

    // --- Validate track.parquet has the DurTest track ---
    eprintln!("  marker duration threshold: validating track.parquet...");
    let track_path = dir.path().join("track.parquet");
    assert!(track_path.exists(), "track.parquet not found");
    assert!(
        parquet_column_contains(&track_path, "name", "DurTest"),
        "DurTest track not found in track.parquet"
    );

    eprintln!("  All marker duration threshold checks passed");
}

// =============================================================================
// Events / Probe integration tests
// =============================================================================

/// Recording duration for events integration tests (seconds).
const EVENTS_RECORDING_DURATION_SECS: u64 = 3;

/// Workload type for events integration tests.
enum EventsWorkload {
    /// Open /dev/null in a loop (triggers openat/do_sys_openat2).
    FileOpen,
    /// Send SIGUSR1 to self in a loop (triggers signal_generate).
    Signal,
}

/// Helper to run a systing recording with a workload and custom config overrides.
///
/// Spawns a workload thread of the specified type and records for
/// EVENTS_RECORDING_DURATION_SECS. The `customize` closure can modify the
/// Config before recording starts (e.g. to set trace_event_config or syscalls).
fn run_events_recording_with(
    workload: EventsWorkload,
    customize: impl FnOnce(&mut Config),
) -> TempDir {
    use std::sync::atomic::Ordering;
    use std::thread;
    use std::time::Duration;

    let dir = TempDir::new().expect("Failed to create temp dir");

    let workload = stoppable_workload(move |stop| match workload {
        EventsWorkload::FileOpen => {
            while !stop.load(Ordering::Relaxed) {
                let _ = std::fs::File::open("/dev/null");
                thread::sleep(Duration::from_millis(10));
            }
        }
        EventsWorkload::Signal => {
            let pid = unsafe { libc::getpid() };
            let prev = unsafe { libc::signal(libc::SIGUSR1, libc::SIG_IGN) };
            while !stop.load(Ordering::Relaxed) {
                unsafe {
                    libc::kill(pid, libc::SIGUSR1);
                }
                thread::sleep(Duration::from_millis(10));
            }
            unsafe {
                libc::signal(libc::SIGUSR1, prev);
            }
        }
    });

    let mut config = Config {
        duration: EVENTS_RECORDING_DURATION_SECS,
        output_dir: dir.path().to_path_buf(),
        no_sched: true,
        no_cpu_stack_traces: true,
        no_sleep_stack_traces: true,
        no_interruptible_stack_traces: true,
        network: false,
        collect_pystacks: false,
        parquet_only: true,
        ..Config::default()
    };
    customize(&mut config);

    systing(config, None).expect("systing recording failed");
    workload.stop();

    dir
}

/// Helper to run a systing recording with a JSON events config file.
///
/// Writes `config_json` to a temp file and delegates to run_events_recording_with.
fn run_events_recording(config_json: &str, workload: EventsWorkload) -> TempDir {
    // Write the JSON config to a temp file that outlives the recording
    let config_file = tempfile::NamedTempFile::new().expect("Failed to create temp config file");
    std::fs::write(config_file.path(), config_json).expect("Failed to write events config");
    let config_path = config_file.path().to_string_lossy().to_string();

    run_events_recording_with(workload, |config| {
        config.trace_event_config = vec![config_path];
    })
}

/// Integration test: tracepoint as instant event via JSON config.
///
/// Attaches `signal:signal_generate` as an instant event on a custom track.
/// A workload sends SIGUSR1 to itself in a loop to generate events.
#[test]
#[ignore] // Requires root/BPF privileges
fn test_e2e_tracepoint_instant() {
    let config_json = r#"
    {
        "events": [
            { "name": "sig_generate", "event": "tracepoint:signal:signal_generate" }
        ],
        "tracks": [
            { "track_name": "SignalEvents", "instants": [{ "event": "sig_generate" }] }
        ]
    }
    "#;

    let dir = run_events_recording(config_json, EventsWorkload::Signal);

    // --- Validate instant.parquet contains the tracepoint events ---
    eprintln!("  tracepoint instant: validating instant.parquet...");
    let instant_path = dir.path().join("instant.parquet");
    assert!(
        instant_path.exists(),
        "instant.parquet not found - tracepoint instant events were not recorded"
    );
    assert!(
        parquet_column_contains(&instant_path, "name", "tracepoint:signal:signal_generate"),
        "tracepoint:signal:signal_generate not found in instant.parquet"
    );

    // --- Validate track.parquet has the custom track ---
    eprintln!("  tracepoint instant: validating track.parquet...");
    let track_path = dir.path().join("track.parquet");
    assert!(track_path.exists(), "track.parquet not found");
    assert!(
        parquet_column_contains(&track_path, "name", "SignalEvents"),
        "SignalEvents not found in track.parquet"
    );

    eprintln!("  All tracepoint instant checks passed");
}

/// Integration test: tracepoint range event via JSON config.
///
/// Uses `raw_syscalls:sys_enter` as the start event and
/// `raw_syscalls:sys_exit` as the end event to form a range.
/// These are raw tracepoints that fire for every syscall.
#[test]
#[ignore] // Requires root/BPF privileges
fn test_e2e_tracepoint_range() {
    let config_json = r#"
    {
        "events": [
            { "name": "sys_enter", "event": "tracepoint:raw_syscalls:sys_enter" },
            { "name": "sys_exit", "event": "tracepoint:raw_syscalls:sys_exit" }
        ],
        "tracks": [
            {
                "track_name": "SyscallRanges",
                "ranges": [{ "name": "syscall_range", "start": "sys_enter", "end": "sys_exit" }]
            }
        ]
    }
    "#;

    let dir = run_events_recording(config_json, EventsWorkload::FileOpen);

    // --- Validate slice.parquet contains the range events ---
    eprintln!("  tracepoint range: validating slice.parquet...");
    let slice_path = dir.path().join("slice.parquet");
    assert!(
        slice_path.exists(),
        "slice.parquet not found - tracepoint range events were not recorded"
    );
    assert!(
        parquet_column_contains(&slice_path, "name", "syscall_range"),
        "syscall_range not found in slice.parquet"
    );

    // --- Validate track.parquet has the custom track ---
    eprintln!("  tracepoint range: validating track.parquet...");
    let track_path = dir.path().join("track.parquet");
    assert!(track_path.exists(), "track.parquet not found");
    assert!(
        parquet_column_contains(&track_path, "name", "SyscallRanges"),
        "SyscallRanges not found in track.parquet"
    );

    eprintln!("  All tracepoint range checks passed");
}

/// Integration test: kprobe/kretprobe range event via JSON config.
///
/// Uses `kprobe:do_sys_openat2` as the start event and
/// `kretprobe:do_sys_openat2` as the end event to form a range.
#[test]
#[ignore] // Requires root/BPF privileges
fn test_e2e_kprobe_range() {
    let config_json = r#"
    {
        "events": [
            { "name": "kp_openat", "event": "kprobe:do_sys_openat2" },
            { "name": "kretp_openat", "event": "kretprobe:do_sys_openat2" }
        ],
        "tracks": [
            {
                "track_name": "KprobeRanges",
                "ranges": [{ "name": "kp_openat_call", "start": "kp_openat", "end": "kretp_openat" }]
            }
        ]
    }
    "#;

    let dir = run_events_recording(config_json, EventsWorkload::FileOpen);

    // --- Validate slice.parquet contains the range events ---
    eprintln!("  kprobe range: validating slice.parquet...");
    let slice_path = dir.path().join("slice.parquet");
    assert!(
        slice_path.exists(),
        "slice.parquet not found - kprobe range events were not recorded"
    );
    assert!(
        parquet_column_contains(&slice_path, "name", "kp_openat_call"),
        "kp_openat_call not found in slice.parquet"
    );

    // --- Validate track.parquet has the custom track ---
    eprintln!("  kprobe range: validating track.parquet...");
    let track_path = dir.path().join("track.parquet");
    assert!(track_path.exists(), "track.parquet not found");
    assert!(
        parquet_column_contains(&track_path, "name", "KprobeRanges"),
        "KprobeRanges not found in track.parquet"
    );

    eprintln!("  All kprobe range checks passed");
}

/// Integration test: syscall tracking via `--syscalls` flag.
///
/// Enables built-in syscall tracking (no JSON config needed). A workload opens
/// `/dev/null` in a loop so `openat` syscalls appear in the trace.
#[test]
#[ignore] // Requires root/BPF privileges
fn test_e2e_syscall_tracking() {
    let dir = run_events_recording_with(EventsWorkload::FileOpen, |config| {
        config.syscalls = true;
    });

    // --- Validate slice.parquet contains syscall events ---
    eprintln!("  syscall tracking: validating slice.parquet...");
    let slice_path = dir.path().join("slice.parquet");
    assert!(
        slice_path.exists(),
        "slice.parquet not found - syscall events were not recorded"
    );
    assert!(
        parquet_column_contains(&slice_path, "name", "openat"),
        "openat syscall not found in slice.parquet"
    );

    // --- Validate track.parquet has the syscalls track ---
    eprintln!("  syscall tracking: validating track.parquet...");
    let track_path = dir.path().join("track.parquet");
    assert!(track_path.exists(), "track.parquet not found");
    assert!(
        parquet_column_contains(&track_path, "name", "syscalls"),
        "syscalls track not found in track.parquet"
    );

    eprintln!("  All syscall tracking checks passed");
}

/// Integration test: CPU scope tracepoint instant event.
///
/// Attaches `signal:signal_generate` with `"scope": "cpu"` so events
/// appear on per-CPU tracks rather than per-thread tracks.
#[test]
#[ignore] // Requires root/BPF privileges
fn test_e2e_event_scope_cpu() {
    let config_json = r#"
    {
        "events": [
            { "name": "sig_generate", "event": "tracepoint:signal:signal_generate", "scope": "cpu" }
        ],
        "tracks": [
            { "track_name": "CpuSignal", "instants": [{ "event": "sig_generate" }] }
        ]
    }
    "#;

    let dir = run_events_recording(config_json, EventsWorkload::Signal);

    // --- Validate instant.parquet contains the CPU-scoped events ---
    eprintln!("  event scope cpu: validating instant.parquet...");
    let instant_path = dir.path().join("instant.parquet");
    assert!(
        instant_path.exists(),
        "instant.parquet not found - CPU-scoped instant events were not recorded"
    );
    assert!(
        parquet_column_contains(&instant_path, "name", "tracepoint:signal:signal_generate"),
        "tracepoint:signal:signal_generate not found in instant.parquet"
    );

    // --- Validate track.parquet has the custom track ---
    eprintln!("  event scope cpu: validating track.parquet...");
    let track_path = dir.path().join("track.parquet");
    assert!(track_path.exists(), "track.parquet not found");
    assert!(
        parquet_column_contains_prefix(&track_path, "name", "CpuSignal CPU "),
        "CpuSignal CPU track not found in track.parquet"
    );

    eprintln!("  All event scope cpu checks passed");
}

/// Test that DNS resolution populates the network_dns table.
///
/// This test enables `resolve_addresses` and generates traffic to a well-known
/// hostname (google.com) so that at least one IP address resolves to a hostname.
/// It then validates that:
/// 1. The network_dns.parquet file is produced
/// 2. The network_dns DuckDB table has at least one entry
/// 3. The resolved hostname is not just the raw IP address
#[test]
#[ignore]
fn test_network_dns_resolution() {
    use std::net::TcpStream;
    use std::net::ToSocketAddrs;
    use std::sync::atomic::Ordering;
    use std::thread;
    use std::time::Duration;

    // Skip (rather than fail) when the environment has no DNS/network —
    // common in CI sandboxes and hermetic test VMs. Everything below needs
    // a resolvable, reachable google.com.
    let Ok(mut addrs) = "google.com:80".to_socket_addrs() else {
        eprintln!("SKIPPED: DNS resolution unavailable (no network access)");
        return;
    };
    let addr = addrs
        .next()
        .expect("resolved google.com but got no addresses");

    let dir = TempDir::new().expect("Failed to create temp dir");

    let config = Config {
        duration: NETWORK_SUITE_DURATION_SECS,
        parquet_only: true,
        network: true,
        resolve_addresses: true,
        output_dir: dir.path().to_path_buf(),
        output: dir.path().join("trace.duckdb"),
        ..Config::default()
    };

    // Spawn traffic thread that connects to google.com:80 repeatedly.
    // This ensures we have at least one socket with a publicly-resolvable IP.
    let traffic = stoppable_workload(move |stop| {
        while !stop.load(Ordering::Relaxed) {
            // Connect to google.com on HTTP port - we just need the TCP handshake
            // to create a socket with a resolvable IP address.
            if let Ok(stream) = TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
                drop(stream);
            }
            thread::sleep(Duration::from_millis(500));
        }
    });

    eprintln!(
        "Recording trace ({}s, network=true, resolve_addresses=true)...",
        NETWORK_SUITE_DURATION_SECS
    );
    systing(config, None).expect("systing recording failed");
    traffic.stop();

    // Validate network_dns.parquet exists
    let dns_parquet = dir.path().join("network_dns.parquet");
    assert!(
        dns_parquet.exists(),
        "network_dns.parquet not found in output directory"
    );

    // Convert to DuckDB and query
    let duckdb_path = dir.path().join("trace.duckdb");
    systing::duckdb::parquet_to_duckdb(dir.path(), &duckdb_path, "dns_test")
        .expect("DuckDB conversion failed");

    let conn = duckdb::Connection::open(&duckdb_path).expect("Failed to open DuckDB");

    // Check that network_dns table has entries
    let dns_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM network_dns", [], |row| row.get(0))
        .unwrap_or(0);

    eprintln!("  network_dns table has {dns_count} entries");
    assert!(
        dns_count > 0,
        "network_dns table is empty - DNS resolution produced no results"
    );

    // Verify that the hostname column contains something that is NOT just an IP address
    // (i.e., at least one entry actually resolved to a hostname)
    let has_hostname: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM network_dns WHERE hostname != ip_address",
            [],
            |row| row.get(0),
        )
        .unwrap_or(false);

    assert!(
        has_hostname,
        "network_dns has entries but none resolved to a hostname different from the IP"
    );

    // Log some entries for debugging
    let mut stmt = conn
        .prepare("SELECT ip_address, hostname FROM network_dns LIMIT 10")
        .expect("Failed to prepare query");
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0).unwrap_or_default(),
                row.get::<_, String>(1).unwrap_or_default(),
            ))
        })
        .expect("Failed to query");
    for (ip, hostname) in rows.flatten() {
        eprintln!("    {ip} -> {hostname}");
    }

    eprintln!("  All DNS resolution checks passed");
}

/// Regression test: `--only-recorder cpu-stacks` must still emit STACK_RUNNING
/// samples even though the scheduler recorder is disabled.
///
/// CPU stack samples are gated in BPF by `cpu_running_pid`, which is populated
/// by `systing_sched_switch`. If the sched programs are not loaded when only
/// cpu-stacks is requested, `cpu_running_pid` stays empty and every
/// STACK_RUNNING sample from the perf clock is dropped. The fix is to load the
/// sched_switch program when stack collection is enabled and to gate the
/// scheduler `task_event` emission separately on the sched recorder.
#[test]
#[ignore] // Requires root/BPF privileges
fn test_e2e_only_cpu_stacks_emits_samples() {
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    use std::fs::File;
    use std::sync::atomic::Ordering;

    let dir = TempDir::new().expect("Failed to create temp dir");

    // CPU-bound workload to give the perf clock something to sample.
    let workload = stoppable_workload(|stop| {
        let mut acc: u64 = 0;
        while !stop.load(Ordering::Relaxed) {
            for i in 0..100_000u64 {
                acc = acc.wrapping_add(i.wrapping_mul(i));
            }
            std::hint::black_box(acc);
        }
    });

    // Mirror what `--only-recorder cpu-stacks` produces in main.rs:
    // every other recorder is off, including the scheduler.
    let config = Config {
        duration: 4,
        output_dir: dir.path().to_path_buf(),
        no_sched: true,
        no_cpu_stack_traces: false,
        no_sleep_stack_traces: true,
        no_interruptible_stack_traces: true,
        syscalls: false,
        memory: false,
        memory_alloc: false,
        network: false,
        network_packets: false,
        markers: false,
        collect_pystacks: false,
        parquet_only: true,
        ..Config::default()
    };

    systing(config, None).expect("systing recording failed");
    workload.stop();

    let stack_sample_path = dir.path().join("stack_sample.parquet");
    assert!(
        stack_sample_path.exists(),
        "stack_sample.parquet not produced by --only-recorder cpu-stacks"
    );

    let file = File::open(&stack_sample_path).expect("Failed to open stack_sample.parquet");
    let builder = ParquetRecordBatchReaderBuilder::try_new(file).expect("Failed to create reader");
    let reader = builder.build().expect("Failed to build reader");

    let mut running_samples = 0u64;
    let mut other_samples = 0u64;
    for batch_result in reader {
        let batch = batch_result.expect("Failed to read batch");
        let event_type_col = batch
            .column_by_name("stack_event_type")
            .expect("stack_event_type column missing")
            .as_any()
            .downcast_ref::<arrow::array::Int8Array>()
            .expect("stack_event_type should be Int8");
        for i in 0..batch.num_rows() {
            match event_type_col.value(i) {
                1 => running_samples += 1,
                _ => other_samples += 1,
            }
        }
    }

    eprintln!(
        "  --only-recorder cpu-stacks produced running={running_samples}, other={other_samples}"
    );
    // The perf clock samples at ~1 kHz per CPU and the workload pegs a core
    // for 4s, so we expect hundreds of samples. Setting a floor (rather than
    // `> 0`) catches a "only one CPU's cpu_running_pid ever populated"
    // regression that a single sample would mask.
    assert!(
        running_samples > 10,
        "--only-recorder cpu-stacks produced too few STACK_RUNNING samples \
         (running={running_samples}, other={other_samples}); \
         sched_switch must load to populate cpu_running_pid on every CPU"
    );

    // Scheduler recorder is off, so no sleep stacks should sneak in.
    assert_eq!(
        other_samples, 0,
        "Unexpected non-RUNNING stack samples emitted while --only-recorder cpu-stacks: \
         got {other_samples}"
    );

    // Sanity: scheduler outputs must not be produced when sched is disabled.
    let sched_slice = dir.path().join("sched_slice.parquet");
    if sched_slice.exists() {
        let file = File::open(&sched_slice).expect("Failed to open sched_slice.parquet");
        let builder = ParquetRecordBatchReaderBuilder::try_new(file)
            .expect("Failed to create sched_slice reader");
        let reader = builder.build().expect("Failed to build sched_slice reader");
        let mut sched_rows = 0u64;
        for batch_result in reader {
            let batch = batch_result.expect("Failed to read sched_slice batch");
            sched_rows += batch.num_rows() as u64;
        }
        assert_eq!(
            sched_rows, 0,
            "--only-recorder cpu-stacks produced {sched_rows} sched_slice rows; \
             scheduler events should not be emitted to userspace when sched is off"
        );
    }
}

/// Not a real test: a busy-loop child process for
/// test_exited_process_recovery, run as systing's traced command via
/// `<test-binary> --exact burner_helper_busy_loop`. Deliberately NOT
/// `#[ignore]`: the VM integration runner selects ignored tests
/// (`--ignored`), and this helper must be excluded there while staying
/// spawnable by exact name. The loop is wall-clock bound (not iteration
/// bound) so TCG slowdown cannot shrink its lifetime, and two seconds is
/// enough on-CPU time for the sampler and the first-sample snapshot even
/// when the consumer side lags. The test binary carries a full symbol
/// table, so samples landing here are name-resolvable if (and only if)
/// symbolization has something to resolve against.
#[test]
fn burner_helper_busy_loop() {
    use std::time::{Duration, Instant};
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut counter: u64 = 0;
    while Instant::now() < deadline {
        counter = std::hint::black_box(counter.wrapping_add(1));
    }
    assert!(counter > 0);
}

#[test]
#[ignore] // Requires root/BPF privileges
fn test_exited_process_recovery() {
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    use std::fs::File;
    use std::time::Instant;
    use systing::traced_command::spawn_traced_child;

    // Record one trace of a single short-lived burner child and count how
    // its frames rendered. Returns (burner_named_frames, exited_frames).
    //
    // The burner runs as systing's traced command, which pins the whole
    // lifecycle to events instead of machine-speed guesses (QEMU TCG
    // stretches BPF setup to tens of seconds): the forked child blocks
    // until tracing is attached before it execs, so the burner cannot burn
    // out before the window opens, and the recording stops because the
    // child exited and was reaped (waitpid plus a drain delay), so the
    // burner is gone from /proc before end-of-trace symbolization runs.
    // Any name-resolved burner frame can therefore only come from the
    // first-sample mapping snapshot, on any machine speed. This is also
    // the population the feature exists for:
    // `systing record -- short_lived_command`.
    fn record_and_count(no_exited_recovery: bool) -> (usize, usize) {
        let dir = TempDir::new().expect("Failed to create temp dir");
        let trace_path = dir.path().join("trace.pb");
        let own_binary = std::env::current_exe().expect("current_exe");

        let child = spawn_traced_child(&[
            own_binary
                .to_str()
                .expect("test binary path not utf-8")
                .to_string(),
            "--exact".to_string(),
            "burner_helper_busy_loop".to_string(),
        ])
        .expect("failed to fork burner child");

        let start = Instant::now();
        let config = Config {
            duration: 300, // backstop only: the child's exit stops the trace
            no_exited_recovery,
            output_dir: dir.path().to_path_buf(),
            output: trace_path,
            ..Config::default()
        };
        systing(config, Some(child)).expect("systing recording failed");
        let elapsed = start.elapsed();
        eprintln!("  recording stopped after {:.1}s", elapsed.as_secs_f64());
        assert!(
            elapsed < SLOW_MACHINE_BUDGET,
            "recording should stop when the burner exits; took {:.1}s \
             (duration backstop reached - child-exit stop broken?)",
            elapsed.as_secs_f64()
        );

        let stack_parquet = dir.path().join("stack.parquet");
        assert!(
            stack_parquet.exists(),
            "[exited recovery] stack.parquet not found"
        );
        let file = File::open(&stack_parquet).expect("Failed to open stack.parquet");
        let reader = ParquetRecordBatchReaderBuilder::try_new(file)
            .expect("Failed to create reader")
            .build()
            .expect("Failed to build reader");

        let mut burner_named = 0usize;
        let mut exited = 0usize;
        for batch_result in reader {
            let batch = batch_result.expect("Failed to read batch");
            let Some(frame_names_col) = batch.column_by_name("frame_names") else {
                continue;
            };
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
                    let frame = string_array.value(j);
                    if frame.contains("burner_helper_busy_loop") {
                        burner_named += 1;
                    }
                    if frame.contains("[exited]") {
                        exited += 1;
                    }
                }
            }
        }
        (burner_named, exited)
    }

    // Negative control first: with recovery disabled, the burner must have
    // been sampled (its pid renders [exited] frames) and none of its frames
    // may carry a resolved name - this proves both that the traced child
    // gets sampled and that it is reliably gone by symbolization time,
    // which run 2 inherits.
    eprintln!("Recording with --no-exited-recovery (negative control)...");
    let (named_off, exited_off) = record_and_count(true);
    eprintln!("  control: burner_named={named_off} exited_frames={exited_off}");
    assert!(
        exited_off > 0,
        "[exited recovery control] expected [exited] frames from the dead burner, got none \
         (burner not sampled? sampling misconfigured?)"
    );
    assert_eq!(
        named_off, 0,
        "[exited recovery control] burner frames resolved with recovery disabled - \
         the burner survived to the live pass, control is invalid"
    );

    // With recovery enabled (default), the same dead burner resolves by name
    // from its first-sample mapping snapshot.
    eprintln!("Recording with exited recovery enabled...");
    let (named_on, exited_on) = record_and_count(false);
    eprintln!("  recovery: burner_named={named_on} exited_frames={exited_on}");
    assert!(
        named_on > 0,
        "[exited recovery] no burner frames resolved by name; first-sample \
         snapshot recovery is not working ({exited_on} [exited] frames present)"
    );
}
