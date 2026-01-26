//! Integration tests for systing-analyze CLI commands.
//!
//! These tests record a short trace to DuckDB, then exercise the various
//! systing-analyze subcommands against it. The recording happens once per
//! test to avoid redundant BPF overhead.
//!
//! To run these tests:
//! ```
//! ./scripts/run-integration-tests.sh analyze_commands
//! ```

use std::path::Path;
use std::process::{Command, Output};
use systing::{bump_memlock_rlimit, systing, validate_duckdb, Config};
use tempfile::TempDir;

/// Helper to set up the environment for BPF tests.
fn setup_bpf_environment() {
    bump_memlock_rlimit().expect("Failed to bump memlock rlimit");
}

/// Run systing-analyze with the given arguments, returning the full Output.
fn run_analyze(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_systing-analyze"))
        .args(args)
        .output()
        .expect("Failed to run systing-analyze")
}

/// Record a trace to DuckDB and return the temp dir (kept alive by caller).
fn record_trace() -> (TempDir, std::path::PathBuf) {
    setup_bpf_environment();

    let dir = TempDir::new().expect("Failed to create temp dir");
    let duckdb_path = dir.path().join("trace.duckdb");

    let config = Config {
        duration: 2,
        output_dir: dir.path().to_path_buf(),
        output: duckdb_path.clone(),
        ..Config::default()
    };

    systing(config).expect("systing recording failed");

    assert!(
        duckdb_path.exists(),
        "trace.duckdb not found after recording"
    );

    let result = validate_duckdb(&duckdb_path);
    assert!(
        result.is_valid(),
        "DuckDB validation failed after recording:\nErrors: {:?}\nWarnings: {:?}",
        result.errors,
        result.warnings
    );

    (dir, duckdb_path)
}

// ---------------------------------------------------------------------------
// query subcommand tests
// ---------------------------------------------------------------------------

fn test_query_table_format(db: &Path) {
    let output = run_analyze(&[
        "query",
        "-d",
        db.to_str().unwrap(),
        "-s",
        "SELECT COUNT(*) as cnt FROM stack_sample",
    ]);
    assert!(
        output.status.success(),
        "query (table) failed: {}",
        lossy(&output.stderr)
    );

    let stdout = lossy(&output.stdout);
    // Table output has a header line with column names and a separator
    assert!(
        stdout.contains("cnt"),
        "table output missing column header: {stdout}"
    );
}

fn test_query_csv_format(db: &Path) {
    let output = run_analyze(&[
        "query",
        "-d",
        db.to_str().unwrap(),
        "-f",
        "csv",
        "-s",
        "SELECT COUNT(*) as cnt FROM stack_sample",
    ]);
    assert!(
        output.status.success(),
        "query (csv) failed: {}",
        lossy(&output.stderr)
    );

    let stdout = lossy(&output.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(
        lines.len() >= 2,
        "csv output should have header + data, got: {stdout}"
    );
    assert_eq!(lines[0], "cnt", "csv header mismatch: {stdout}");
    let count: u64 = lines[1]
        .trim()
        .parse()
        .expect("csv data should be a number");
    assert!(count > 0, "expected at least 1 stack sample, got 0");
}

fn test_query_json_format(db: &Path) {
    let output = run_analyze(&[
        "query",
        "-d",
        db.to_str().unwrap(),
        "-f",
        "json",
        "-s",
        "SELECT COUNT(*) as cnt FROM stack_sample",
    ]);
    assert!(
        output.status.success(),
        "query (json) failed: {}",
        lossy(&output.stderr)
    );

    let stdout = lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("query json output should be valid JSON");
    assert!(
        parsed.is_array(),
        "json output should be an array: {stdout}"
    );
    let arr = parsed.as_array().unwrap();
    assert_eq!(arr.len(), 1, "expected 1 row");
    let cnt_val = &arr[0]["cnt"];
    let count: u64 = if let Some(n) = cnt_val.as_u64() {
        n
    } else if let Some(s) = cnt_val.as_str() {
        s.parse().expect("cnt should be numeric")
    } else {
        panic!("cnt is neither a number nor string: {cnt_val}");
    };
    assert!(count > 0, "expected at least 1 stack sample, got 0");
}

fn test_query_multi_table(db: &Path) {
    // Verify we can query the key tables that flamegraph depends on
    for table in &["stack_sample", "stack", "thread", "process"] {
        let sql = format!("SELECT COUNT(*) as cnt FROM {table}");
        let output = run_analyze(&["query", "-d", db.to_str().unwrap(), "-f", "csv", "-s", &sql]);
        assert!(
            output.status.success(),
            "query on {table} failed: {}",
            lossy(&output.stderr)
        );
        let stdout = lossy(&output.stdout);
        let data_line = stdout.lines().nth(1).unwrap_or("").trim();
        let count: u64 = data_line.parse().unwrap_or(0);
        eprintln!("  {table}: {count} rows");
    }
}

fn test_query_invalid_sql(db: &Path) {
    let output = run_analyze(&[
        "query",
        "-d",
        db.to_str().unwrap(),
        "-s",
        "SELECT * FROM nonexistent_table_xyz",
    ]);
    assert!(
        !output.status.success(),
        "query with invalid SQL should fail"
    );
}

// ---------------------------------------------------------------------------
// stacktrace flamegraph subcommand tests
// ---------------------------------------------------------------------------

/// Validate that output lines are valid folded-stack format: `frame;frame;... count`
fn assert_valid_folded_output(stdout: &str) {
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(!lines.is_empty(), "flamegraph produced no output lines");

    for (i, line) in lines.iter().enumerate() {
        let parts: Vec<&str> = line.rsplitn(2, ' ').collect();
        assert!(
            parts.len() == 2,
            "line {i} not valid folded format (missing count): {line}"
        );
        let count: u64 = parts[0]
            .parse()
            .unwrap_or_else(|_| panic!("line {i} count is not a number: {}", parts[0]));
        assert!(count > 0, "line {i} has zero count");
        let frames = parts[1];
        assert!(!frames.is_empty(), "line {i} has empty frame path");
        // Frames should be semicolon-separated
        assert!(
            !frames.contains('\t'),
            "line {i} contains tab in frame path"
        );
    }
}

/// Validate that stderr contains expected metadata header fields.
fn assert_flamegraph_metadata(stderr: &str, stack_type: &str) {
    assert!(
        stderr.contains("# Flamegraph:"),
        "missing Flamegraph header in stderr"
    );
    assert!(
        stderr.contains(&format!("# Stack type: {stack_type}")),
        "missing or wrong stack type in stderr: {stderr}"
    );
    assert!(
        stderr.contains("# Total trace samples:"),
        "missing total samples in stderr"
    );
    assert!(
        stderr.contains("# Output samples:"),
        "missing output samples in stderr"
    );
    assert!(
        stderr.contains("# Unique stacks:"),
        "missing unique stacks in stderr"
    );
    assert!(
        stderr.contains("# Time range:"),
        "missing time range in stderr"
    );
}

fn test_flamegraph_cpu(db: &Path) {
    let output = run_analyze(&["stacktrace", "flamegraph", "-d", db.to_str().unwrap()]);
    assert!(
        output.status.success(),
        "flamegraph (cpu) failed: {}",
        lossy(&output.stderr)
    );

    let stdout = lossy(&output.stdout);
    let stderr = lossy(&output.stderr);

    assert_valid_folded_output(&stdout);
    assert_flamegraph_metadata(&stderr, "cpu");
}

fn test_flamegraph_all(db: &Path) {
    let output = run_analyze(&[
        "stacktrace",
        "flamegraph",
        "-d",
        db.to_str().unwrap(),
        "-t",
        "all",
    ]);
    assert!(
        output.status.success(),
        "flamegraph (all) failed: {}",
        lossy(&output.stderr)
    );

    let stdout = lossy(&output.stdout);
    let stderr = lossy(&output.stderr);

    assert_valid_folded_output(&stdout);
    assert_flamegraph_metadata(&stderr, "all");

    // "all" should include at least as many samples as "cpu" alone
    let all_lines: usize = stdout.lines().count();
    let cpu_output = run_analyze(&["stacktrace", "flamegraph", "-d", db.to_str().unwrap()]);
    let cpu_lines: usize = lossy(&cpu_output.stdout).lines().count();
    assert!(
        all_lines >= cpu_lines,
        "all ({all_lines} stacks) should be >= cpu ({cpu_lines} stacks)"
    );
}

fn test_flamegraph_all_sleep(db: &Path) {
    let output = run_analyze(&[
        "stacktrace",
        "flamegraph",
        "-d",
        db.to_str().unwrap(),
        "-t",
        "all-sleep",
    ]);
    assert!(
        output.status.success(),
        "flamegraph (all-sleep) failed: {}",
        lossy(&output.stderr)
    );

    let stderr = lossy(&output.stderr);
    assert_flamegraph_metadata(&stderr, "all-sleep");

    // Sleep stacks may or may not exist in a 2s recording, but the command should succeed
}

fn test_flamegraph_with_time_range(db: &Path) {
    let output = run_analyze(&[
        "stacktrace",
        "flamegraph",
        "-d",
        db.to_str().unwrap(),
        "--start-time",
        "0",
        "--end-time",
        "1",
    ]);
    assert!(
        output.status.success(),
        "flamegraph (time range) failed: {}",
        lossy(&output.stderr)
    );

    let stderr = lossy(&output.stderr);
    assert_flamegraph_metadata(&stderr, "cpu");
    assert!(
        stderr.contains("# Filters:"),
        "time-bounded query should show filters in metadata"
    );
    assert!(
        stderr.contains("start=0s"),
        "missing start filter: {stderr}"
    );
    assert!(stderr.contains("end=1s"), "missing end filter: {stderr}");
}

fn test_flamegraph_with_min_count(db: &Path) {
    // First get total unique stacks with min_count=1
    let baseline = run_analyze(&[
        "stacktrace",
        "flamegraph",
        "-d",
        db.to_str().unwrap(),
        "-t",
        "all",
    ]);
    let baseline_lines: usize = lossy(&baseline.stdout).lines().count();

    // With a high min_count, should get fewer (or equal) stacks
    let output = run_analyze(&[
        "stacktrace",
        "flamegraph",
        "-d",
        db.to_str().unwrap(),
        "-t",
        "all",
        "--min-count",
        "5",
    ]);
    assert!(
        output.status.success(),
        "flamegraph (min-count) failed: {}",
        lossy(&output.stderr)
    );

    let filtered_lines: usize = lossy(&output.stdout).lines().count();
    assert!(
        filtered_lines <= baseline_lines,
        "min-count=5 ({filtered_lines} stacks) should be <= unfiltered ({baseline_lines} stacks)"
    );
}

fn test_flamegraph_nonexistent_db(db: &Path) {
    let _ = db; // unused, we test with a fake path
    let output = run_analyze(&[
        "stacktrace",
        "flamegraph",
        "-d",
        "/tmp/does_not_exist_systing_test.duckdb",
    ]);
    assert!(
        !output.status.success(),
        "flamegraph should fail for nonexistent database"
    );
}

// ---------------------------------------------------------------------------
// sched stats subcommand tests
// ---------------------------------------------------------------------------

/// Get a valid PID from the trace database for testing.
fn get_first_pid(db: &Path) -> u32 {
    let output = run_analyze(&[
        "query",
        "-d",
        db.to_str().unwrap(),
        "-f",
        "csv",
        "-s",
        "SELECT DISTINCT p.pid FROM sched_slice ss \
         JOIN thread t ON ss.utid = t.utid AND ss.trace_id = t.trace_id \
         JOIN process p ON t.upid = p.upid AND t.trace_id = p.trace_id \
         WHERE ss.dur > 0 LIMIT 1",
    ]);
    assert!(
        output.status.success(),
        "get_first_pid query failed: {}",
        lossy(&output.stderr)
    );
    let stdout = lossy(&output.stdout);
    let pid_str = stdout.lines().nth(1).expect("no PID found in trace").trim();
    pid_str.parse().expect("PID not a valid number")
}

/// Get a valid TID from the trace database for testing.
fn get_first_tid(db: &Path) -> u32 {
    let output = run_analyze(&[
        "query",
        "-d",
        db.to_str().unwrap(),
        "-f",
        "csv",
        "-s",
        "SELECT DISTINCT t.tid FROM sched_slice ss \
         JOIN thread t ON ss.utid = t.utid AND ss.trace_id = t.trace_id \
         WHERE ss.dur > 0 LIMIT 1",
    ]);
    assert!(
        output.status.success(),
        "get_first_tid query failed: {}",
        lossy(&output.stderr)
    );
    let stdout = lossy(&output.stdout);
    let tid_str = stdout.lines().nth(1).expect("no TID found in trace").trim();
    tid_str.parse().expect("TID not a valid number")
}

fn test_sched_stats_whole_trace(db: &Path) {
    let output = run_analyze(&["sched", "stats", "-d", db.to_str().unwrap()]);
    assert!(
        output.status.success(),
        "sched stats (whole trace) failed: {}",
        lossy(&output.stderr)
    );

    let stderr = lossy(&output.stderr);
    let stdout = lossy(&output.stdout);

    // Metadata headers on stderr
    assert!(
        stderr.contains("# Sched Stats:"),
        "missing Sched Stats header: {stderr}"
    );
    assert!(
        stderr.contains("# Total sched events:"),
        "missing total events: {stderr}"
    );
    assert!(
        stderr.contains("# Total CPU time:"),
        "missing total CPU time: {stderr}"
    );
    assert!(
        stderr.contains("# Trace duration:"),
        "missing trace duration: {stderr}"
    );

    // Table output on stdout should have PID column
    assert!(
        stdout.contains("PID"),
        "missing PID column in table output: {stdout}"
    );
    assert!(
        stdout.contains("Name"),
        "missing Name column in table output: {stdout}"
    );
}

fn test_sched_stats_json(db: &Path) {
    let output = run_analyze(&["sched", "stats", "-d", db.to_str().unwrap(), "-f", "json"]);
    assert!(
        output.status.success(),
        "sched stats (json) failed: {}",
        lossy(&output.stderr)
    );

    let stdout = lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("sched stats JSON should be valid");
    assert!(
        parsed.get("summary").is_some(),
        "JSON missing summary key: {stdout}"
    );
    let total_events = parsed["summary"]["total_events"]
        .as_u64()
        .expect("total_events should be a number");
    assert!(total_events > 0, "expected total_events > 0");
}

fn test_sched_stats_per_process(db: &Path) {
    let pid = get_first_pid(db);
    let pid_str = pid.to_string();
    let output = run_analyze(&["sched", "stats", "-d", db.to_str().unwrap(), "-p", &pid_str]);
    assert!(
        output.status.success(),
        "sched stats (per-process) failed: {}",
        lossy(&output.stderr)
    );

    let stderr = lossy(&output.stderr);
    let stdout = lossy(&output.stdout);

    assert!(
        stderr.contains("# Sched Stats:"),
        "missing header: {stderr}"
    );
    assert!(
        stderr.contains("# Thread count:"),
        "missing thread count: {stderr}"
    );

    // Per-thread table should have TID column
    assert!(
        stdout.contains("TID"),
        "missing TID column in per-process output: {stdout}"
    );
}

fn test_sched_stats_per_process_json(db: &Path) {
    let pid = get_first_pid(db);
    let pid_str = pid.to_string();
    let output = run_analyze(&[
        "sched",
        "stats",
        "-d",
        db.to_str().unwrap(),
        "-p",
        &pid_str,
        "-f",
        "json",
    ]);
    assert!(
        output.status.success(),
        "sched stats (per-process json) failed: {}",
        lossy(&output.stderr)
    );

    let stdout = lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("per-process JSON should be valid");
    assert!(
        parsed.get("threads").is_some(),
        "JSON missing threads key: {stdout}"
    );
    let threads = parsed["threads"]
        .as_array()
        .expect("threads should be array");
    assert!(!threads.is_empty(), "threads array should not be empty");
}

fn test_sched_stats_per_thread(db: &Path) {
    let tid = get_first_tid(db);
    let tid_str = tid.to_string();
    let output = run_analyze(&[
        "sched",
        "stats",
        "-d",
        db.to_str().unwrap(),
        "--tid",
        &tid_str,
    ]);
    assert!(
        output.status.success(),
        "sched stats (per-thread) failed: {}",
        lossy(&output.stderr)
    );

    let stderr = lossy(&output.stderr);
    assert!(
        stderr.contains("# Thread:"),
        "missing thread header: {stderr}"
    );
    assert!(
        stderr.contains("# CPU migrations:"),
        "missing CPU migrations: {stderr}"
    );
    assert!(
        stderr.contains("# End states:"),
        "missing end states: {stderr}"
    );
}

fn test_sched_stats_per_thread_json(db: &Path) {
    let tid = get_first_tid(db);
    let tid_str = tid.to_string();
    let output = run_analyze(&[
        "sched",
        "stats",
        "-d",
        db.to_str().unwrap(),
        "--tid",
        &tid_str,
        "--format",
        "json",
    ]);
    assert!(
        output.status.success(),
        "sched stats (per-thread json) failed: {}",
        lossy(&output.stderr)
    );

    let stdout = lossy(&output.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("per-thread json output should be valid JSON");
    assert!(
        json.get("thread_detail").is_some(),
        "per-thread json should have thread_detail key"
    );
    let detail = &json["thread_detail"];
    assert!(
        detail.get("end_states").is_some(),
        "thread_detail should have end_states"
    );
    let end_states = detail["end_states"]
        .as_array()
        .expect("end_states should be an array");
    assert!(
        !end_states.is_empty(),
        "end_states should not be empty for a valid thread"
    );
}

fn test_sched_stats_nonexistent_pid(db: &Path) {
    let output = run_analyze(&["sched", "stats", "-d", db.to_str().unwrap(), "-p", "999999"]);
    // Command should succeed even for a nonexistent PID
    assert!(
        output.status.success(),
        "sched stats (nonexistent pid) should succeed: {}",
        lossy(&output.stderr)
    );
    // Should warn about no events found
    let stderr = lossy(&output.stderr);
    assert!(
        stderr.contains("No scheduling events found"),
        "should warn about no events for nonexistent PID: {stderr}"
    );
}

fn test_sched_stats_nonexistent_db(_db: &Path) {
    let output = run_analyze(&[
        "sched",
        "stats",
        "-d",
        "/tmp/does_not_exist_systing_sched_test.duckdb",
    ]);
    assert!(
        !output.status.success(),
        "sched stats should fail for nonexistent database"
    );
}

// ---------------------------------------------------------------------------
// sched cpu-stats subcommand tests
// ---------------------------------------------------------------------------

fn test_sched_cpu_stats_table(db: &Path) {
    let output = run_analyze(&["sched", "cpu-stats", "-d", db.to_str().unwrap()]);
    assert!(
        output.status.success(),
        "sched cpu-stats (table) failed: {}",
        lossy(&output.stderr)
    );

    let stderr = lossy(&output.stderr);
    let stdout = lossy(&output.stdout);

    // Metadata headers on stderr
    assert!(
        stderr.contains("# CPU Stats:"),
        "missing CPU Stats header: {stderr}"
    );
    assert!(
        stderr.contains("# Trace duration:"),
        "missing trace duration: {stderr}"
    );
    assert!(stderr.contains("# CPUs:"), "missing CPUs count: {stderr}");
    assert!(
        stderr.contains("# Total sched events:"),
        "missing total sched events: {stderr}"
    );

    // Table output on stdout should have CPU column
    assert!(
        stdout.contains("CPU"),
        "missing CPU column in table output: {stdout}"
    );
    assert!(
        stdout.contains("Util%"),
        "missing Util% column in table output: {stdout}"
    );
    assert!(
        stdout.contains("Idle%"),
        "missing Idle% column in table output: {stdout}"
    );
}

fn test_sched_cpu_stats_json(db: &Path) {
    let output = run_analyze(&[
        "sched",
        "cpu-stats",
        "-d",
        db.to_str().unwrap(),
        "-f",
        "json",
    ]);
    assert!(
        output.status.success(),
        "sched cpu-stats (json) failed: {}",
        lossy(&output.stderr)
    );

    let stdout = lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("cpu-stats JSON should be valid");
    assert!(
        parsed.get("summary").is_some(),
        "JSON missing summary key: {stdout}"
    );
    assert!(
        parsed.get("cpus").is_some(),
        "JSON missing cpus key: {stdout}"
    );
    let cpus = parsed["cpus"].as_array().expect("cpus should be an array");
    assert!(!cpus.is_empty(), "cpus array should not be empty");

    let cpu_count = parsed["summary"]["cpu_count"]
        .as_u64()
        .expect("cpu_count should be a number");
    assert!(cpu_count > 0, "expected cpu_count > 0");
    assert_eq!(
        cpus.len() as u64,
        cpu_count,
        "cpus array length should match cpu_count"
    );

    // Each CPU entry should have expected fields
    let first_cpu = &cpus[0];
    assert!(
        first_cpu.get("cpu").is_some(),
        "CPU entry missing 'cpu' field"
    );
    assert!(
        first_cpu.get("utilization_pct").is_some(),
        "CPU entry missing 'utilization_pct' field"
    );
    assert!(
        first_cpu.get("idle_pct").is_some(),
        "CPU entry missing 'idle_pct' field"
    );
    assert!(
        first_cpu.get("irq_time_seconds").is_some(),
        "CPU entry missing 'irq_time_seconds' field"
    );
    assert!(
        first_cpu.get("softirq_time_seconds").is_some(),
        "CPU entry missing 'softirq_time_seconds' field"
    );

    // Verify utilization/idle percentages are within valid bounds
    for cpu_entry in cpus {
        let util = cpu_entry["utilization_pct"]
            .as_f64()
            .expect("utilization_pct should be a number");
        let idle = cpu_entry["idle_pct"]
            .as_f64()
            .expect("idle_pct should be a number");
        assert!(
            (0.0..=100.0).contains(&util),
            "utilization_pct out of range [0,100]: {util}"
        );
        assert!(
            (0.0..=100.0).contains(&idle),
            "idle_pct out of range [0,100]: {idle}"
        );
    }
}

fn test_sched_cpu_stats_nonexistent_db(_db: &Path) {
    let output = run_analyze(&[
        "sched",
        "cpu-stats",
        "-d",
        "/tmp/does_not_exist_systing_cpu_stats_test.duckdb",
    ]);
    assert!(
        !output.status.success(),
        "sched cpu-stats should fail for nonexistent database"
    );
}

// ---------------------------------------------------------------------------
// network interfaces subcommand tests
// ---------------------------------------------------------------------------

fn test_network_interfaces_table_format(db: &Path) {
    let output = run_analyze(&["network", "interfaces", "-d", db.to_str().unwrap()]);
    assert!(
        output.status.success(),
        "network interfaces (table) failed: {}",
        lossy(&output.stderr)
    );

    let stderr = lossy(&output.stderr);
    let stdout = lossy(&output.stdout);

    // Metadata headers on stderr
    assert!(
        stderr.contains("# Network Interfaces:"),
        "missing Network Interfaces header: {stderr}"
    );
    assert!(
        stderr.contains("# Traces:"),
        "missing Traces count: {stderr}"
    );

    // Table output should have expected columns
    assert!(
        stdout.contains("Namespace"),
        "missing Namespace column: {stdout}"
    );
    assert!(
        stdout.contains("Interface"),
        "missing Interface column: {stdout}"
    );
    assert!(stdout.contains("Proto"), "missing Proto column: {stdout}");
    assert!(
        stdout.contains("Retrans%"),
        "missing Retrans% column: {stdout}"
    );
}

fn test_network_interfaces_json(db: &Path) {
    let output = run_analyze(&[
        "network",
        "interfaces",
        "-d",
        db.to_str().unwrap(),
        "-f",
        "json",
    ]);
    assert!(
        output.status.success(),
        "network interfaces (json) failed: {}",
        lossy(&output.stderr)
    );

    let stdout = lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("network interfaces JSON should be valid");
    assert!(
        parsed.get("traces").is_some(),
        "JSON missing traces key: {stdout}"
    );
    let traces = parsed["traces"]
        .as_array()
        .expect("traces should be an array");
    assert!(!traces.is_empty(), "traces array should not be empty");

    // Each trace should have expected structure
    let first_trace = &traces[0];
    assert!(
        first_trace.get("trace_id").is_some(),
        "trace missing trace_id"
    );
    assert!(
        first_trace.get("interfaces").is_some(),
        "trace missing interfaces"
    );
    let interfaces = first_trace["interfaces"]
        .as_array()
        .expect("interfaces should be an array");
    assert!(
        !interfaces.is_empty(),
        "interfaces should not be empty (host always has at least lo)"
    );

    // Each interface should have expected fields
    let first_iface = &interfaces[0];
    assert!(first_iface.get("namespace").is_some(), "missing namespace");
    assert!(
        first_iface.get("interface_name").is_some(),
        "missing interface_name"
    );
    assert!(
        first_iface.get("ip_addresses").is_some(),
        "missing ip_addresses"
    );
    let ips = first_iface["ip_addresses"]
        .as_array()
        .expect("ip_addresses should be an array");
    assert!(!ips.is_empty(), "ip_addresses should not be empty");
    assert!(
        first_iface.get("total_send_bytes").is_some(),
        "missing total_send_bytes"
    );
    assert!(
        first_iface.get("total_recv_bytes").is_some(),
        "missing total_recv_bytes"
    );
}

fn test_network_interfaces_nonexistent_db(_db: &Path) {
    let output = run_analyze(&[
        "network",
        "interfaces",
        "-d",
        "/tmp/does_not_exist_systing_network_test.duckdb",
    ]);
    assert!(
        !output.status.success(),
        "network interfaces should fail for nonexistent database"
    );
}

// ---------------------------------------------------------------------------
// Main integration test: record once, then exercise all commands
// ---------------------------------------------------------------------------

#[test]
#[ignore] // Requires root/BPF privileges
fn test_analyze_commands() {
    // Phase 1: Record a trace to DuckDB
    eprintln!("Recording trace...");
    let (_dir, duckdb_path) = record_trace();
    eprintln!("Recording complete: {}", duckdb_path.display());

    // Phase 2: Test query subcommand
    eprintln!("\n--- query subcommand ---");

    eprintln!("  table format...");
    test_query_table_format(&duckdb_path);

    eprintln!("  csv format...");
    test_query_csv_format(&duckdb_path);

    eprintln!("  json format...");
    test_query_json_format(&duckdb_path);

    eprintln!("  multi-table queries...");
    test_query_multi_table(&duckdb_path);

    eprintln!("  invalid SQL...");
    test_query_invalid_sql(&duckdb_path);

    // Phase 3: Test stacktrace flamegraph subcommand
    eprintln!("\n--- stacktrace flamegraph subcommand ---");

    eprintln!("  cpu (default)...");
    test_flamegraph_cpu(&duckdb_path);

    eprintln!("  all...");
    test_flamegraph_all(&duckdb_path);

    eprintln!("  all-sleep...");
    test_flamegraph_all_sleep(&duckdb_path);

    eprintln!("  time range...");
    test_flamegraph_with_time_range(&duckdb_path);

    eprintln!("  min-count...");
    test_flamegraph_with_min_count(&duckdb_path);

    eprintln!("  nonexistent database...");
    test_flamegraph_nonexistent_db(&duckdb_path);

    // Phase 4: Test sched stats subcommand
    eprintln!("\n--- sched stats subcommand ---");

    eprintln!("  whole trace...");
    test_sched_stats_whole_trace(&duckdb_path);

    eprintln!("  json format...");
    test_sched_stats_json(&duckdb_path);

    eprintln!("  per-process...");
    test_sched_stats_per_process(&duckdb_path);

    eprintln!("  per-process json...");
    test_sched_stats_per_process_json(&duckdb_path);

    eprintln!("  per-thread...");
    test_sched_stats_per_thread(&duckdb_path);

    eprintln!("  per-thread json...");
    test_sched_stats_per_thread_json(&duckdb_path);

    eprintln!("  nonexistent pid...");
    test_sched_stats_nonexistent_pid(&duckdb_path);

    eprintln!("  nonexistent database...");
    test_sched_stats_nonexistent_db(&duckdb_path);

    // Phase 5: Test sched cpu-stats subcommand
    eprintln!("\n--- sched cpu-stats subcommand ---");

    eprintln!("  table format...");
    test_sched_cpu_stats_table(&duckdb_path);

    eprintln!("  json format...");
    test_sched_cpu_stats_json(&duckdb_path);

    eprintln!("  nonexistent database...");
    test_sched_cpu_stats_nonexistent_db(&duckdb_path);

    // Phase 6: Test network interfaces subcommand
    // network_interface table is always populated (interface metadata is recorded
    // regardless of the --network flag), so we can test against the existing trace.
    eprintln!("\n--- network interfaces subcommand ---");

    eprintln!("  table format...");
    test_network_interfaces_table_format(&duckdb_path);

    eprintln!("  json format...");
    test_network_interfaces_json(&duckdb_path);

    eprintln!("  nonexistent database...");
    test_network_interfaces_nonexistent_db(&duckdb_path);

    eprintln!("\n✓ All systing-analyze commands passed");
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}
