//! Integration test: record a stripped Go workload and validate that its
//! frames symbolize end-to-end from `.gopclntab`.
//!
//! The workload is built at test time with `-ldflags="-s -w"`, so it has no
//! ELF symbol table: its function names can only appear in the output if
//! the gopclntab fallback resolver engaged through the live process
//! symbolization flow (member dispatch, file-offset translation, pc
//! lookup). This is the assertion that the pclntab's link-time address
//! domain matches what the symbolizer hands member resolvers.
//!
//! Requires root/BPF privileges AND a `go` toolchain on PATH; skips
//! cleanly with a reason otherwise.
//!
//! To run:
//! ```
//! ./scripts/run-integration-tests.sh gopclntab_record
//! ```

mod common;

use std::io::Write as _;
use std::path::Path;
use std::process::Command;
use std::process::Stdio;

use arrow::array::Array;
use arrow::array::Int32Array;
use arrow::array::Int64Array;
use arrow::array::ListArray;
use arrow::array::StringArray;
use common::workload::wait_until;
use systing::{systing, Config};
use tempfile::TempDir;

/// Recording duration (seconds): BPF attach latency plus enough sampling
/// of a pure CPU spinner to observe its hot function many times over.
const RECORDING_DURATION_SECS: u64 = 10;

/// The workload source. `spinHot` is `noinline` so the hot leaf frame
/// carries a name this test can assert on; the module path of a file-mode
/// `go build` is the synthetic "command-line-arguments", so nothing
/// environment-specific lands in the binary.
const WORKLOAD_SOURCE: &str = "package main\n\
\n\
//go:noinline\n\
func spinHot(x uint64) uint64 {\n\
\tfor i := 0; i < 4096; i++ {\n\
\t\tx = x*2862933555777941757 + 3037000493\n\
\t}\n\
\treturn x\n\
}\n\
\n\
func main() {\n\
\tvar x uint64\n\
\tfor {\n\
\t\tx = spinHot(x)\n\
\t}\n\
}\n";

/// Read an integer column as i64 regardless of its physical width (the
/// schema mixes Int64 ids with Int32 tids).
fn read_int_column(batch: &arrow::record_batch::RecordBatch, name: &str) -> Vec<i64> {
    let column = batch
        .column_by_name(name)
        .unwrap_or_else(|| panic!("{name} column missing"));
    if let Some(values) = column.as_any().downcast_ref::<Int64Array>() {
        values.values().to_vec()
    } else if let Some(values) = column.as_any().downcast_ref::<Int32Array>() {
        values.values().iter().map(|v| i64::from(*v)).collect()
    } else {
        panic!("{name} should be an Int64Array or Int32Array");
    }
}

fn for_each_batch(path: &Path, mut f: impl FnMut(&arrow::record_batch::RecordBatch)) {
    let file = std::fs::File::open(path)
        .unwrap_or_else(|e| panic!("failed to open {}: {e}", path.display()));
    let reader = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(file)
        .expect("failed to create parquet reader")
        .build()
        .expect("failed to build parquet reader");
    for batch in reader {
        f(&batch.expect("failed to read record batch"));
    }
}

#[test]
#[ignore]
fn test_gopclntab_record() {
    if Command::new("go").arg("version").output().is_err() {
        eprintln!("skipping: no go toolchain on PATH");
        return;
    }

    // The Go linker mmaps its output and intermediates, which fails with
    // EINVAL on 9p-backed mounts — including /tmp inside the vng test VM.
    // Build on a guest-local tmpfs when one is available, then copy the
    // binary back to the regular temp dir to run it (exec from 9p works;
    // it is how the test binary itself runs).
    let build_base = Path::new("/dev/shm");
    let build_dir = if build_base.is_dir() {
        TempDir::new_in(build_base)
    } else {
        TempDir::new()
    }
    .expect("failed to create build dir");
    let src = build_dir.path().join("main.go");
    let mut f = std::fs::File::create(&src).expect("failed to create workload source");
    f.write_all(WORKLOAD_SOURCE.as_bytes())
        .expect("failed to write workload source");
    drop(f);

    let built = build_dir.path().join("gopclntab-fixture");
    let out = Command::new("go")
        .args(["build", "-trimpath", "-ldflags=-s -w", "-o"])
        .arg(&built)
        .arg(&src)
        .env("GOCACHE", build_dir.path().join("gocache"))
        .env("GOTMPDIR", build_dir.path())
        .env("CGO_ENABLED", "0")
        .output()
        .expect("failed to run go build");
    assert!(
        out.status.success(),
        "go build failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let run_dir = TempDir::new().expect("failed to create run dir");
    let bin = run_dir.path().join("gopclntab-fixture");
    std::fs::copy(&built, &bin).expect("failed to copy workload binary");

    let mut workload = Command::new(&bin)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn workload");
    let workload_pid = workload.id();
    wait_until("workload to be running", || {
        Path::new(&format!("/proc/{workload_pid}/stat")).exists()
    });

    // The Go runtime multiplexes goroutines across several OS threads and
    // the spinner may be sampled on any of them: attribute by the
    // process's full thread set (snapshot before and after recording, in
    // case the runtime spawns more threads while profiled).
    let collect_tids = |tids: &mut std::collections::HashSet<i64>| {
        if let Ok(tasks) = std::fs::read_dir(format!("/proc/{workload_pid}/task")) {
            for task in tasks.flatten() {
                if let Ok(tid) = task.file_name().to_string_lossy().parse::<i64>() {
                    tids.insert(tid);
                }
            }
        }
    };
    let mut workload_tids = std::collections::HashSet::new();
    collect_tids(&mut workload_tids);

    eprintln!(
        "Recording trace ({RECORDING_DURATION_SECS}s, stripped Go spinner pid {workload_pid})..."
    );
    let out_dir = TempDir::new().expect("failed to create output dir");
    let config = Config {
        duration: RECORDING_DURATION_SECS,
        output_dir: out_dir.path().to_path_buf(),
        output: out_dir.path().join("trace.pb"),
        ..Config::default()
    };
    let record_result = systing(config, None);
    collect_tids(&mut workload_tids);
    let _ = workload.kill();
    let _ = workload.wait();
    record_result.expect("systing recording failed");
    assert!(!workload_tids.is_empty(), "no workload tids collected");

    // thread.parquet: utid -> tid, to find workload-attributed samples.
    let mut workload_utids = std::collections::HashSet::new();
    for_each_batch(&out_dir.path().join("thread.parquet"), |batch| {
        let utids = read_int_column(batch, "utid");
        let tids = read_int_column(batch, "tid");
        for (utid, tid) in utids.iter().zip(tids.iter()) {
            if workload_tids.contains(tid) {
                workload_utids.insert(*utid);
            }
        }
    });
    assert!(
        !workload_utids.is_empty(),
        "workload pid {workload_pid} not present in thread.parquet"
    );

    // stack_sample.parquet: stacks attributed to the workload.
    let mut workload_stack_ids = std::collections::HashSet::new();
    for_each_batch(&out_dir.path().join("stack_sample.parquet"), |batch| {
        let utids = read_int_column(batch, "utid");
        let stack_ids = read_int_column(batch, "stack_id");
        for (utid, stack_id) in utids.iter().zip(stack_ids.iter()) {
            if workload_utids.contains(utid) {
                workload_stack_ids.insert(*stack_id);
            }
        }
    });
    assert!(
        !workload_stack_ids.is_empty(),
        "no CPU stack samples attributed to the workload"
    );

    // stack.parquet: the workload's frames must carry pclntab-resolved
    // names. The binary has no symbol table, so `main.spinHot` appearing
    // at all proves the gopclntab resolver ran end-to-end.
    let mut spin_hot_frames = 0usize;
    let mut hex_frames = 0usize;
    let mut total_frames = 0usize;
    for_each_batch(&out_dir.path().join("stack.parquet"), |batch| {
        let ids = read_int_column(batch, "id");
        let frames_col = batch
            .column_by_name("frame_names")
            .expect("frame_names column missing")
            .as_any()
            .downcast_ref::<ListArray>()
            .expect("frame_names should be a ListArray")
            .clone();
        for (row, id) in ids.iter().enumerate() {
            if !workload_stack_ids.contains(id) {
                continue;
            }
            let values = frames_col.value(row);
            let strings = values
                .as_any()
                .downcast_ref::<StringArray>()
                .expect("frame_names inner should be StringArray");
            for i in 0..strings.len() {
                let frame = strings.value(i);
                total_frames += 1;
                if frame.starts_with("main.spinHot ") {
                    spin_hot_frames += 1;
                } else if frame.starts_with("0x") || frame.starts_with("unknown") {
                    hex_frames += 1;
                }
            }
        }
    });
    eprintln!(
        "workload frames: {total_frames} total, {spin_hot_frames} main.spinHot, {hex_frames} unresolved"
    );
    assert!(
        spin_hot_frames > 0,
        "main.spinHot never resolved — gopclntab symbolization did not engage \
         ({total_frames} workload frames, {hex_frames} unresolved)"
    );
    // The spinner burns its CPU inside spinHot: resolved names should
    // dominate, not be a lucky one-off next to a wall of hex.
    assert!(
        spin_hot_frames > hex_frames,
        "unresolved frames ({hex_frames}) dominate resolved main.spinHot \
         ({spin_hot_frames}) — pclntab lookups are missing more than they hit"
    );
}
