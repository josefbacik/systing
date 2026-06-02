//! Integration test for the perf-counter recorder.
//!
//! Records a trace with both `--perf-counter` and `--cpu-frequency` enabled and
//! verifies that the per-CPU perf-counter tracks and the CPU-frequency tracks
//! both survive into the final trace. This is a regression test for the
//! sysinfo (CPU frequency) writer clobbering `counter.parquet` /
//! `counter_track.parquet`, which silently dropped every perf-counter sample
//! whenever the two options were combined.
//!
//! Requires root/BPF privileges; run via:
//! ```
//! ./scripts/run-integration-tests.sh perf_counter
//! ```

use systing::{bump_memlock_rlimit, systing, Config};
use tempfile::TempDir;

/// Counters used by the test. `instructions` and `cpu-cycles` are backed by
/// fixed counters on x86, making them the events most likely to exist (and
/// actually count) even on virtualized hosts with a restricted vPMU.
const TEST_COUNTERS: [&str; 2] = ["instructions", "cpu-cycles"];

/// How long the busy workload (and therefore the recording) runs, in seconds.
/// Long enough for the sampling clock to read the counters many times and for
/// the CPU-frequency poller (100ms interval) to record plenty of samples.
const RECORDING_SECS: u64 = 3;

fn setup_bpf_environment() {
    bump_memlock_rlimit().expect("Failed to bump memlock rlimit");
}

/// Returns true if the host can actually open the hardware perf counters used
/// by the test. Virtualized/CI hosts frequently expose no PMU at all; in that
/// case the test is skipped rather than failed.
///
/// Note: the counter names come from the sysfs aliases of the `cpu` PMU, which
/// are spelled differently on some architectures (e.g. ARM uses `cpu_cycles` /
/// `inst_retired`), so the test also skips there.
fn perf_counters_available() -> bool {
    use systing::perf::{PerfCounters, PerfOpenEvents};

    let mut counters = PerfCounters::default();
    if counters.discover().is_err() {
        return false;
    }
    for name in TEST_COUNTERS {
        let Some(hwevents) = counters.event(name) else {
            return false;
        };
        // Probing a single CPU is enough to know whether the PMU is usable.
        let Some(mut event) = hwevents.into_iter().next() else {
            return false;
        };
        let Some(&cpu) = event.cpus.first() else {
            return false;
        };
        event.cpus = vec![cpu];

        let mut files = PerfOpenEvents::default();
        if files.add_hw_event(event).is_err() {
            return false;
        }
        if files.open_events(None, 0).is_err() {
            return false;
        }
        // open_events() tolerates ENODEV, so make sure an event fd was really
        // opened before declaring the counter usable.
        if files.iter().next().is_none() {
            return false;
        }
    }
    true
}

#[test]
#[ignore] // Requires root/BPF privileges
fn test_perf_counter_with_cpu_frequency() {
    setup_bpf_environment();

    if !perf_counters_available() {
        eprintln!("skipping: hardware perf counters are not available on this host");
        return;
    }

    let dir = TempDir::new().expect("Failed to create temp dir");
    let trace_path = dir.path().join("trace.pb");

    // Busy workload so the sampling clock fires on its CPU and the counters
    // accumulate non-zero deltas while the traced task is running.
    let run_cmd = vec![
        "bash".to_string(),
        "-c".to_string(),
        format!("end=$((SECONDS+{RECORDING_SECS})); while [ $SECONDS -lt $end ]; do :; done"),
    ];
    let traced_child =
        systing::traced_command::spawn_traced_child(&run_cmd).expect("Failed to spawn child");

    eprintln!(
        "Recording perf counters {:?} + CPU frequency (pid {}, ~{}s)...",
        TEST_COUNTERS, traced_child.pid, RECORDING_SECS
    );

    let config = Config {
        perf_counter: TEST_COUNTERS.iter().map(|s| s.to_string()).collect(),
        cpu_frequency: true,
        parquet_only: true,
        output_dir: dir.path().to_path_buf(),
        output: trace_path,
        ..Config::default()
    };

    let exit_code = systing(config, Some(traced_child)).expect("systing recording failed");
    assert_eq!(exit_code, 0, "busy workload should exit with code 0");
    eprintln!("Recording complete.\n");

    // --- Convert to DuckDB for SQL assertions ---
    let duckdb_path = dir.path().join("trace.duckdb");
    systing::duckdb::parquet_to_duckdb(dir.path(), &duckdb_path, "perfcounter")
        .expect("DuckDB conversion failed");
    let conn = duckdb::Connection::open(&duckdb_path).expect("Failed to open DuckDB");

    // --- Check: perf-counter tracks survived alongside the frequency tracks ---
    // (regression: the sysinfo writer used to clobber counter.parquet, wiping
    // every perf-counter sample whenever --cpu-frequency was also enabled)
    for counter in TEST_COUNTERS {
        eprintln!("  {counter} tracks...");
        let pattern = format!("{counter} CPU %");
        let (tracks, samples, max_value): (i64, i64, f64) = conn
            .query_row(
                "SELECT COUNT(DISTINCT ct.id), COUNT(c.ts), COALESCE(MAX(c.value), 0)
                 FROM counter_track ct
                 LEFT JOIN counter c ON c.track_id = ct.id
                 WHERE ct.name LIKE ?",
                [pattern.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("Failed to query perf counter tracks");
        assert!(
            tracks > 0,
            "[{counter}] no '{counter} CPU <n>' tracks in counter_track"
        );
        assert!(samples > 0, "[{counter}] no counter samples for any track");
        assert!(max_value > 0.0, "[{counter}] all counter samples are zero");
        eprintln!("    {tracks} tracks, {samples} samples, max delta {max_value}");
    }

    // --- Check: CPU-frequency tracks are also present ---
    eprintln!("  cpu-frequency tracks...");
    let (freq_tracks, freq_samples): (i64, i64) = conn
        .query_row(
            "SELECT COUNT(DISTINCT ct.id), COUNT(c.ts)
             FROM counter_track ct
             LEFT JOIN counter c ON c.track_id = ct.id
             WHERE ct.name LIKE 'CPU % frequency'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("Failed to query frequency tracks");
    assert!(
        freq_tracks > 0,
        "[cpu-frequency] no 'CPU <n> frequency' tracks in counter_track"
    );
    assert!(
        freq_samples > 0,
        "[cpu-frequency] no frequency samples recorded"
    );
    eprintln!("    {freq_tracks} tracks, {freq_samples} samples");

    // --- Check: counter_track IDs are unique across both recorders ---
    eprintln!("  counter_track id uniqueness...");
    let duplicate_ids: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM (
                 SELECT id FROM counter_track GROUP BY id HAVING COUNT(*) > 1
             )",
            [],
            |row| row.get(0),
        )
        .expect("Failed to query duplicate counter_track ids");
    assert_eq!(
        duplicate_ids, 0,
        "counter_track has duplicate track ids (perf-counter and cpu-frequency \
         tracks must come from a shared id sequence)"
    );

    // --- Check: every counter sample resolves to exactly one track ---
    eprintln!("  counter -> counter_track referential integrity...");
    let orphans: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM counter c
             LEFT JOIN counter_track ct ON c.track_id = ct.id
             WHERE ct.id IS NULL",
            [],
            |row| row.get(0),
        )
        .expect("Failed to query orphaned counter samples");
    assert_eq!(
        orphans, 0,
        "counter rows reference missing counter_track ids"
    );
}
