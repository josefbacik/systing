//! End-to-end test for `--collect-build-id`: user frames of a process that
//! exits before end-of-trace symbolization resolve by NAME, because the
//! build-id capture makes their identity process-independent.
//!
//! The dead process is a child running this test binary itself, so the
//! binary is guaranteed to still be mapped by a live process (us) at
//! symbolization time — the store's host-wide live-process index picks it
//! up (we are alive, even though we were never sampled: the trace is
//! pid-filtered to the child) and the dead child's (build-id, offset)
//! frames resolve against it. That is the exact population the flag
//! exists for: `systing record -- short_cmd`.
//!
//! To run:
//! ```
//! ./scripts/run-integration-tests.sh build_id_record
//! ```

mod common;

use common::workload::SLOW_MACHINE_BUDGET;
use systing::{systing, Config};
use tempfile::TempDir;

/// Not a real test: a busy-loop child process for
/// test_build_id_dead_process_symbolization, run as systing's traced
/// command via `<test-binary> --exact burner_helper_busy_loop`.
/// Deliberately NOT `#[ignore]`: the VM integration runner selects ignored
/// tests (`--ignored`), and this helper must be excluded there while
/// staying spawnable by exact name. The loop is wall-clock bound (not
/// iteration bound) so TCG slowdown cannot shrink its lifetime, and two
/// seconds is enough on-CPU time for the sampler even when the consumer
/// side lags. The test binary carries a full symbol table and (linker
/// permitting) a GNU build-id note; samples landing here are
/// name-resolvable if and only if the dead-process path has something to
/// resolve against.
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

/// Frame-name census of one recorded trace of a single short-lived burner
/// child. Returns (burner_named, exited, buildid_deferred) frame counts.
///
/// The burner runs as systing's traced command, which pins the whole
/// lifecycle to events instead of machine-speed guesses (QEMU TCG
/// stretches BPF setup to tens of seconds): the forked child blocks until
/// tracing is attached before it execs, so the burner cannot burn out
/// before the window opens, and the recording stops because the child
/// exited and was reaped, so the burner is gone from /proc before
/// end-of-trace symbolization runs.
fn record_and_count(collect_build_id: bool) -> (usize, usize, usize) {
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    use std::fs::File;
    use std::time::Instant;
    use systing::traced_command::spawn_traced_child;

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
        collect_build_id,
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
    assert!(stack_parquet.exists(), "[build-id] stack.parquet not found");
    let file = File::open(&stack_parquet).expect("Failed to open stack.parquet");
    let reader = ParquetRecordBatchReaderBuilder::try_new(file)
        .expect("Failed to create reader")
        .build()
        .expect("Failed to build reader");

    let mut burner_named = 0usize;
    let mut exited = 0usize;
    let mut buildid_deferred = 0usize;
    for batch_result in reader {
        let batch = batch_result.expect("Failed to read batch");
        let Some(frame_names_col) = batch.column_by_name("frame_names") else {
            continue;
        };
        use arrow::array::{Array, ListArray, StringArray};
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
                if frame.contains("[buildid:") || frame.starts_with("buildid:") {
                    buildid_deferred += 1;
                }
            }
        }
    }
    (burner_named, exited, buildid_deferred)
}

#[test]
#[ignore] // Requires root/BPF privileges
fn test_build_id_dead_process_symbolization() {
    // The premise: this test binary must carry a GNU build-id note, or the
    // kernel walker has nothing to extract and the whole run is vacuous.
    // Fail loudly rather than skip — the VM gate builds with a toolchain
    // that emits the note, so absence there is a real regression.
    {
        use blazesym::helper::read_elf_build_id;
        let exe = std::env::current_exe().expect("current_exe");
        let bid = read_elf_build_id(&exe).expect("reading own build-id");
        assert!(
            bid.is_some(),
            "test binary carries no GNU build-id note; the build-id e2e \
             cannot run (check linker flags in the test environment)"
        );
    }

    // Negative control first: with the flag off, the burner must have been
    // sampled (its pid renders [exited] frames), none of its frames may
    // resolve by name, and no frame may carry build-id vocabulary. This
    // proves the traced child gets sampled, is reliably gone by
    // symbolization time, and that the mode is genuinely off — which run 2
    // inherits.
    eprintln!("Recording without --collect-build-id (negative control)...");
    let (named_off, exited_off, bid_off) = record_and_count(false);
    eprintln!("  control: burner_named={named_off} exited={exited_off} buildid={bid_off}");
    assert!(
        exited_off > 0,
        "[build-id control] expected [exited] frames from the dead burner, got none \
         (burner not sampled? sampling misconfigured?)"
    );
    assert_eq!(
        named_off, 0,
        "[build-id control] burner frames resolved with the flag off - \
         the burner survived to the live pass, control is invalid"
    );
    assert_eq!(
        bid_off, 0,
        "[build-id control] build-id frame vocabulary with the flag off"
    );

    // With build-id capture on, the same dead burner resolves by name: the
    // kernel walker recorded (build-id, offset) pairs, and the live pass
    // indexes this very binary (mapped by us) into the store.
    eprintln!("Recording with --collect-build-id...");
    let (named_on, exited_on, bid_on) = record_and_count(true);
    eprintln!("  build-id: burner_named={named_on} exited={exited_on} buildid={bid_on}");
    assert!(
        named_on > 0,
        "[build-id] no burner frames resolved by name; kernel build-id \
         capture or the store's live fill is not working \
         (exited={exited_on} buildid-deferred={bid_on})"
    );
}
