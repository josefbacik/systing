//! Integration test for `--stream unix://...`.
//!
//! Starts a unix-socket receiver in a background thread, runs a short systing
//! trace with `Config::stream` set, and asserts that the receiver produced
//! valid parquet files. Requires root/BPF privileges; marked `#[ignore]`.
//!
//! Run with: ./scripts/run-integration-tests.sh stream_unix

mod common;

use common::workload::SLOW_MACHINE_BUDGET;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parquet::file::reader::{FileReader, SerializedFileReader};
use systing::stream::{receive, StreamTarget};
use systing::{systing, Config};
use tempfile::TempDir;

/// Tables that the default recorder set always emits.
const EXPECTED_TABLES: &[&str] = &["sched_slice", "sysinfo", "process", "thread"];

/// Return Ok(rows) once `path` is a complete parquet file with rows; Err
/// otherwise. A half-written file (footer not yet flushed) fails to parse,
/// so this also serves as the "io::copy finished" check.
fn parquet_rows(path: &Path) -> anyhow::Result<i64> {
    let file = std::fs::File::open(path)?;
    let reader = SerializedFileReader::new(file)?;
    Ok(reader.metadata().file_metadata().num_rows())
}

#[test]
#[ignore = "requires root/BPF; run via ./scripts/run-integration-tests.sh"]
fn test_stream_unix_roundtrip() {
    let recv_dir = TempDir::new().unwrap();
    let sock_path = recv_dir.path().join("systing.sock");
    let target = StreamTarget::Unix(sock_path.clone());

    // Receiver: accept loop in a background thread, one handler thread per
    // connection. `done` counts connections that have fully drained, so the
    // main thread can wait for in-flight streams to finish after systing()
    // returns.
    let listener = target.listen().expect("bind unix listener");
    let out = recv_dir.path().to_path_buf();
    let done = Arc::new(AtomicUsize::new(0));
    let done_rx = done.clone();
    std::thread::spawn(move || loop {
        let (stream, peer) = match listener.accept() {
            Ok(x) => x,
            Err(_) => return,
        };
        let out = out.clone();
        let done = done.clone();
        std::thread::spawn(move || {
            receive::handle_connection(stream, &peer, &out).expect("handle_connection");
            done.fetch_add(1, Ordering::SeqCst);
        });
    });

    // Sender: short whole-system trace, default recorders, streamed.
    let cfg = Config {
        duration: 2,
        stream: Some(target.clone()),
        ..Default::default()
    };
    systing(cfg, None).expect("systing run");

    // Connections close after the parquet footer is written (inside
    // generate_parquet_trace, before systing() returns), so by now every
    // sender is done; we only need to wait for the receiver-side io::copy
    // threads to drain. Poll the actual postcondition — every expected file
    // is a complete parquet with rows — rather than guessing a settle time.
    let deadline = Instant::now() + SLOW_MACHINE_BUDGET;
    loop {
        let ready = EXPECTED_TABLES.iter().all(|t| {
            let p = recv_dir.path().join(format!("{t}.parquet"));
            matches!(parquet_rows(&p), Ok(n) if n > 0)
        });
        if ready {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for receiver output; {} connections handled",
            done_rx.load(Ordering::SeqCst)
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        done_rx.load(Ordering::SeqCst) >= EXPECTED_TABLES.len(),
        "receiver handled fewer connections than expected tables"
    );
}
