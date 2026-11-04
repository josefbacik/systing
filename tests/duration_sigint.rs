//! Integration test for SIGINT (Ctrl-C) during a `--duration` capture: the
//! capture ends early, through the usual stop sequence, and its trace is
//! written.
//!
//! It runs the systing binary rather than calling `systing()`, so that the
//! signal goes to a process of its own: ctrlc allows one handler per process.
//!
//! Requires root/BPF privileges; run via:
//! ```
//! ./scripts/run-integration-tests.sh duration_sigint
//! ```

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use systing::validate_duckdb;
use tempfile::TempDir;

/// The window that the capture asks for. If it closes within its first half,
/// the signal closed it.
const DURATION: Duration = Duration::from_secs(60);

/// How long after the "Tracing for" line the test sends SIGINT.
const RECORDING: Duration = Duration::from_secs(2);

#[test]
#[ignore] // Requires root/BPF privileges
fn test_sigint_ends_a_duration_capture_early() {
    let dir = TempDir::new().expect("Failed to create temp dir");
    let trace_path = dir.path().join("trace.duckdb");
    let mut child = Command::new(env!("CARGO_BIN_EXE_systing"))
        .arg("--duration")
        .arg(DURATION.as_secs().to_string())
        .arg("--output-dir")
        .arg(dir.path())
        .arg("--output")
        .arg(&trace_path)
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to run systing");

    // systing installs its SIGINT handler before it prints "Tracing for N
    // seconds". A SIGINT before that line would kill it.
    let mut lines = BufReader::new(child.stdout.take().unwrap())
        .lines()
        .map_while(Result::ok);
    let tracing = lines.any(|line| line.starts_with("Tracing for "));
    let window_opened = Instant::now();
    if tracing {
        std::thread::sleep(RECORDING);
        // SAFETY: kill() takes no pointer, and the pid is that of our own child,
        // which has not been waited for yet.
        unsafe { libc::kill(child.id() as i32, libc::SIGINT) };
    }
    let stopped = lines.any(|line| line == "Stopping...");
    let window = window_opened.elapsed();
    // Read on to the end, so that systing never blocks on a full pipe.
    lines.for_each(drop);
    let status = child.wait().expect("Failed to wait for systing");

    assert!(tracing, "systing never printed \"Tracing for\": {status}");
    assert!(
        status.success(),
        "systing did not exit with code 0: {status}"
    );
    assert!(stopped, "systing never printed \"Stopping...\"");
    assert!(
        window < DURATION / 2,
        "SIGINT did not close the window: it lasted {window:?}"
    );

    let result = validate_duckdb(&trace_path);
    assert!(
        result.is_valid(),
        "DuckDB validation failed:\nErrors: {:?}\nWarnings: {:?}",
        result.errors,
        result.warnings
    );
    // The scheduler rows begin shortly before the "Tracing for" line and end where
    // the window closed. A capture that had ended by itself soon after that line
    // would cover less than half of RECORDING.
    let conn = duckdb::Connection::open(&trace_path).expect("Failed to open DuckDB");
    let recorded: f64 = conn
        .query_row(
            "SELECT (MAX(ts + dur) - MIN(ts)) / 1e9 FROM sched_slice",
            [],
            |row| row.get(0),
        )
        .expect("Failed to read the scheduler rows");
    assert!(
        recorded > RECORDING.as_secs_f64() / 2.0,
        "the trace covers {recorded} s, but the signal came {RECORDING:?} into the window"
    );
}
