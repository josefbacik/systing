//! Integration test pinning bounded symbolizer descriptor usage in the
//! exited-process symbolization pass.
//!
//! The exited pass symbolizes each dead process's user addresses through
//! `/proc/self/fd` paths of backing files pinned by the first-sample
//! snapshot layer (see `exit_snapshot`). The symbolizer opens its own
//! descriptor per distinct binary it touches, so without per-pass eviction
//! the pass holds the snapshot pins AND a duplicate of each — under a
//! lowered `RLIMIT_NOFILE` the duplicates exhaust the table and exited
//! frames silently degrade to `unknown ([exited])` (failed opens are
//! swallowed by design). This test runs many short-lived children, each
//! backed by its own copy of a symbol-bearing binary, under a descriptor
//! limit that only a bounded-eviction pass fits into, and requires their
//! frames to actually symbolize.
//!
//! Requires root/BPF privileges; run via:
//! ```
//! ./scripts/run-integration-tests.sh exited_fd_bound
//! ```

use std::collections::HashSet;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use systing::{systing, Config};
use tempfile::TempDir;

/// Number of short-lived child processes, each its own binary copy —
/// hence its own snapshot pin and its own symbolizer cache entry. Kept
/// well under the snapshot layer's pinned-file cap (with room for the
/// driver's shared objects), so the snapshot layer's own oldest-first pin
/// eviction never competes with the property under test. All children
/// are alive at once at the lifetime below, so the concurrent pin count
/// is the whole child count plus shared objects — under the cap by
/// arithmetic, not by scheduling.
const CHILD_COUNT: usize = 450;

/// Soft `RLIMIT_NOFILE` imposed on the tracing process: comfortably above
/// the patched peak (the snapshot pins + the eviction batch bound + the
/// runtime baseline asserted below) and well below the unpatched demand
/// (pins plus one duplicate per child binary, several hundred more).
const NOFILE_SOFT_LIMIT: libc::rlim_t = 700;

/// Seconds each child stays alive before exiting — long enough that the
/// sampler catches every child AND the first-sample snapshot layer
/// captures its mappings while it is still live, even on slow or
/// emulated machines. Short lifetimes lose that snapshot race, which
/// both starves resolution and deflates the very descriptor demand the
/// limit above is calibrated against.
const CHILD_BURN_SECS: f64 = 10.0;

/// Fraction of children whose frames must symbolize into their own binary.
/// The margin absorbs children that exit unsampled, not symbolization
/// failures: a descriptor-exhausted pass degrades far below this.
const RESOLVED_CHILD_FRACTION: f64 = 0.8;

/// CPU-burner for the children. Compiled locally so its symbol table is
/// present and the hot function's name is unmistakable in frame names.
const SPIN_C: &str = r#"
unsigned long long exited_fd_bound_spin(void) {
    volatile unsigned long long acc = 0;
    unsigned long long i;
    for (i = 0; i < 50000000ULL; i++) {
        acc += i;
    }
    return acc;
}

int main(void) {
    for (;;) {
        exited_fd_bound_spin();
    }
    return 0;
}
"#;

/// Lower the soft `RLIMIT_NOFILE`, returning the previous limits.
fn lower_nofile_soft_limit(limit: libc::rlim_t) -> libc::rlimit {
    let mut old = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit/setrlimit on this process with valid pointers.
    unsafe {
        assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut old), 0);
        let new = libc::rlimit {
            rlim_cur: limit,
            rlim_max: old.rlim_max,
        };
        assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &new), 0);
    }
    old
}

fn restore_nofile_soft_limit(old: libc::rlimit) {
    // SAFETY: restoring limits observed by lower_nofile_soft_limit.
    unsafe {
        assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &old), 0);
    }
}

/// Distinct child binaries appearing in a fully symbolized frame. A child
/// counts only when a frame names the spin function AND attributes it to
/// that child's binary copy — exactly what the snapshot path produces.
fn resolved_child_modules(parquet_path: &Path) -> HashSet<String> {
    use arrow::array::Array as _;
    use arrow::array::ListArray;
    use arrow::array::StringArray;
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

    let file = std::fs::File::open(parquet_path).expect("Failed to open stack.parquet");
    let builder = ParquetRecordBatchReaderBuilder::try_new(file).expect("Failed to create reader");
    let reader = builder.build().expect("Failed to build reader");

    let mut resolved = HashSet::new();
    for batch_result in reader {
        let batch = batch_result.expect("Failed to read batch");
        let Some(frame_names_col) = batch.column_by_name("frame_names") else {
            continue;
        };
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
                // Frames render as "name (module ...) <addr>"; capture the
                // module token of spin frames.
                let Some(rest) = frame.strip_prefix("exited_fd_bound_spin (") else {
                    continue;
                };
                if let Some(module) = rest.split([' ', ')']).next() {
                    if module.starts_with("exch-") {
                        resolved.insert(module.to_string());
                    }
                }
            }
        }
    }
    resolved
}

#[test]
#[ignore] // Requires root/BPF privileges
fn test_exited_pass_fd_bound() {
    let dir = TempDir::new().expect("Failed to create temp dir");

    // One compiled burner, copied CHILD_COUNT times: distinct inodes make
    // each child a distinct pinned file and a distinct symbolizer entry.
    let spin_src = dir.path().join("spin.c");
    std::fs::write(&spin_src, SPIN_C).expect("Failed to write spin.c");
    let spin_bin = dir.path().join("spin");
    let cc_status = Command::new("cc")
        .arg("-O0")
        .arg("-o")
        .arg(&spin_bin)
        .arg(&spin_src)
        .status()
        .expect("cc is required to build the child workload");
    assert!(cc_status.success(), "Failed to compile the child workload");
    for i in 0..CHILD_COUNT {
        std::fs::copy(&spin_bin, dir.path().join(format!("exch-{i}")))
            .expect("Failed to copy child binary");
    }

    // Driver script: staggered children, each burning CPU briefly and
    // exiting; all are dead when the driver (the traced child) exits, so
    // every child goes through the exited pass.
    let script_path = dir.path().join("driver.sh");
    let script = format!(
        "#!/bin/bash\n\
         for i in $(seq 0 {last}); do\n\
         \x20 timeout {burn} \"{dir}/exch-$i\" >/dev/null 2>&1 &\n\
         \x20 sleep 0.02\n\
         done\n\
         wait\n\
         exit 0\n",
        last = CHILD_COUNT - 1,
        burn = CHILD_BURN_SECS,
        dir = dir.path().display(),
    );
    std::fs::write(&script_path, script).expect("Failed to write driver script");
    let mut perms = std::fs::metadata(&script_path)
        .expect("Failed to stat driver script")
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&script_path, perms).expect("Failed to chmod driver script");

    let traced_child = systing::traced_command::spawn_traced_child(&[
        "bash".to_string(),
        script_path.to_str().unwrap().to_string(),
    ])
    .expect("Failed to spawn driver");

    eprintln!(
        "Recording {CHILD_COUNT} short-lived children under a soft descriptor limit of {NOFILE_SOFT_LIMIT}..."
    );
    // Calibration canary: the margin between the patched descriptor peak
    // and NOFILE_SOFT_LIMIT assumes a bounded pre-recording baseline. If
    // the harness or runtime grows past this budget, fail loud here
    // instead of silently eroding the discrimination margin.
    let baseline_fds = std::fs::read_dir("/proc/self/fd").unwrap().count();
    assert!(
        baseline_fds <= 200,
        "pre-recording descriptor baseline {baseline_fds} exceeds the \
         calibration budget (200): recalibrate NOFILE_SOFT_LIMIT"
    );
    let old_limit = lower_nofile_soft_limit(NOFILE_SOFT_LIMIT);
    let config = Config {
        parquet_only: true,
        output_dir: dir.path().to_path_buf(),
        output: dir.path().join("trace.pb"),
        ..Config::default()
    };
    let result = systing(config, Some(traced_child));
    restore_nofile_soft_limit(old_limit);
    let exit_code = result.expect("systing recording failed");
    assert_eq!(exit_code, 0, "driver workload should exit with code 0");

    let stack_parquet = dir.path().join("stack.parquet");
    assert!(
        stack_parquet.exists(),
        "stack.parquet not found — descriptor exhaustion at the parquet open?"
    );

    let resolved = resolved_child_modules(&stack_parquet);
    let required = (CHILD_COUNT as f64 * RESOLVED_CHILD_FRACTION) as usize;
    assert!(
        resolved.len() >= required,
        "only {}/{CHILD_COUNT} children symbolized into their binary (required {required}): \
         exited-pass symbolization degraded, consistent with descriptor exhaustion",
        resolved.len(),
    );
    eprintln!(
        "    {}/{CHILD_COUNT} children symbolized into their own binary",
        resolved.len()
    );
}
