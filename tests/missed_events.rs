//! Integration test for the missed-events counter tracks.
//!
//! Records a short trace with the default recorders and verifies that the
//! per-class "Missed <class> events" counter tracks are present, sampled at
//! least twice (baseline plus the final post-quiesce sample), and
//! monotonically non-decreasing (the values are cumulative totals) — and
//! that classes whose subsystems are disabled in this run leave no tracks
//! behind.
//!
//! Requires root/BPF privileges; run via:
//! ```
//! ./scripts/run-integration-tests.sh missed_events
//! ```

use systing::{systing, Config};
use tempfile::TempDir;

/// How long the traced workload (and therefore the recording) runs, in
/// seconds. Long enough for the 1s missed-events poller to take several
/// samples on top of the baseline and final ones.
const RECORDING_SECS: u64 = 3;

/// Classes polled on every run (their subsystems are always active).
const ALWAYS_ON_TRACKS: [&str; 4] = [
    "Missed sched/IRQ events",
    "Missed stack events",
    "Missed probe events",
    "Missed cache events",
];

/// Classes whose subsystems are off in this run's config: no tracks allowed.
const DISABLED_TRACKS: [&str; 5] = [
    "Missed network events",
    "Missed packet events",
    "Missed poll events",
    "Missed marker events",
    "Missed memory events",
];

#[test]
#[ignore] // Requires root/BPF privileges
fn test_missed_events_counter_tracks() {
    let dir = TempDir::new().expect("Failed to create temp dir");
    let trace_path = dir.path().join("trace.pb");

    // Busy workload so the recording has real event flow while the poller
    // samples.
    let run_cmd = vec![
        "bash".to_string(),
        "-c".to_string(),
        format!("end=$((SECONDS+{RECORDING_SECS})); while [ $SECONDS -lt $end ]; do :; done"),
    ];
    let traced_child =
        systing::traced_command::spawn_traced_child(&run_cmd).expect("Failed to spawn child");

    eprintln!(
        "Recording default trace (pid {}, ~{}s)...",
        traced_child.pid, RECORDING_SECS
    );

    let config = Config {
        parquet_only: true,
        output_dir: dir.path().to_path_buf(),
        output: trace_path,
        ..Config::default()
    };

    let exit_code = systing(config, Some(traced_child)).expect("systing recording failed");
    assert_eq!(exit_code, 0, "busy workload should exit with code 0");
    eprintln!("Recording complete.\n");

    let duckdb_path = dir.path().join("trace.duckdb");
    systing::duckdb::parquet_to_duckdb(dir.path(), &duckdb_path, "missedevents")
        .expect("DuckDB conversion failed");
    let conn = duckdb::Connection::open(&duckdb_path).expect("Failed to open DuckDB");

    // --- Check: every always-on class has exactly one sampled, monotonic track ---
    for name in ALWAYS_ON_TRACKS {
        eprintln!("  {name}...");
        let (tracks, samples, monotonic_violations, min_value): (i64, i64, i64, f64) = conn
            .query_row(
                "WITH samples AS (
                     SELECT c.value,
                            LAG(c.value) OVER (ORDER BY c.ts) AS prev
                     FROM counter c
                     JOIN counter_track ct ON c.track_id = ct.id
                     WHERE ct.name = ?
                 )
                 SELECT (SELECT COUNT(*) FROM counter_track WHERE name = ?),
                        COUNT(*),
                        COALESCE(SUM(CASE WHEN value < prev THEN 1 ELSE 0 END), 0),
                        COALESCE(MIN(value), -1)
                 FROM samples",
                [name, name],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("Failed to query missed-events track");
        assert_eq!(tracks, 1, "[{name}] expected exactly one track");
        assert!(
            samples >= 2,
            "[{name}] expected at least baseline + final samples, got {samples}"
        );
        assert_eq!(
            monotonic_violations, 0,
            "[{name}] cumulative counter went backwards"
        );
        assert!(min_value >= 0.0, "[{name}] negative counter value");
        eprintln!("    1 track, {samples} samples, monotonic");
    }

    // --- Check: disabled classes leave no tracks ---
    for name in DISABLED_TRACKS {
        let tracks: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM counter_track WHERE name = ?",
                [name],
                |row| row.get(0),
            )
            .expect("Failed to query disabled-class track");
        assert_eq!(
            tracks, 0,
            "[{name}] class is disabled in this run but has a track"
        );
    }
    eprintln!("  disabled classes: no tracks, as expected");

    // --- Check: units stay inside the validated counter-unit vocabulary ---
    let bad_units: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM counter_track
             WHERE name LIKE 'Missed % events' AND (unit IS NULL OR unit <> 'count')",
            [],
            |row| row.get(0),
        )
        .expect("Failed to query missed-events track units");
    assert_eq!(
        bad_units, 0,
        "missed-events tracks must use unit='count' (validated vocabulary)"
    );

    // --- Check: counter_track IDs stay unique across all counter recorders ---
    let duplicate_ids: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM (
                 SELECT id FROM counter_track GROUP BY id HAVING COUNT(*) > 1
             )",
            [],
            |row| row.get(0),
        )
        .expect("Failed to query duplicate counter_track ids");
    assert_eq!(duplicate_ids, 0, "counter_track has duplicate track ids");

    // --- Check: every counter sample resolves to exactly one track ---
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
