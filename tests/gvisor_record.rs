//! Integration test: record a workload running inside a gVisor (runsc)
//! sandbox and validate that the recording pipeline handles it end-to-end —
//! sandbox stacks are captured, unresolvable frames carry the contextual
//! labels introduced with the sandbox_maps module, and guest user frames
//! symbolize through /proc/<pid>/map_files despite the gofer's private mount
//! namespace.
//!
//! Requires root/BPF privileges AND a runsc binary (found via
//! `SYSTING_TEST_RUNSC` or `$PATH`); skips cleanly with a reason otherwise.
//!
//! To run:
//! ```
//! ./scripts/run-integration-tests.sh gvisor_record
//! ```

mod common;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use arrow::array::{Array, Int32Array, Int64Array, ListArray, StringArray};
use common::workload::wait_until;
use systing::{systing, Config};
use tempfile::TempDir;

/// Recording duration (seconds). The sandboxed workload loops until torn
/// down, so this only needs to exceed BPF attach latency plus enough sampling
/// time to hit both guest text and sandbox-runtime code paths. The runtime
/// paths are sampled rarely when the Sentry dominates CPU (emulated / very
/// slow machines), hence the generous window.
const GVISOR_RECORDING_DURATION_SECS: u64 = 12;

/// Locate the runsc binary: `SYSTING_TEST_RUNSC` wins, then `$PATH`.
fn find_runsc() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("SYSTING_TEST_RUNSC") {
        let p = PathBuf::from(p);
        return p.is_file().then_some(p);
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join("runsc"))
        .find(|c| c.is_file())
}

/// Name of the test container within its private state root.
const CONTAINER_ID: &str = "systing-gvisor-test";

/// The sandboxed workload: pure shell builtins so the rootfs only needs
/// /bin/sh. Complementary guest profiles — a pure arithmetic spinner that
/// keeps CPU in *guest text* (its samples must symbolize through
/// map_files), plus several `cd /` loops making a real syscall every
/// iteration: each syscall executes the systrap trampoline/handler code in
/// the stub's runtime mappings, and multiple loops raise that code's
/// on-CPU share so the `[gvisor:*]` classification is reliably sampled
/// even when the Sentry dominates a slow machine.
const GUEST_WORKLOAD: &str = "for k in 1 2 3 4 5 6; do while :; do cd /; done & done; \
                              while :; do i=$((i+1)); done";

/// Copy `binary` plus its dynamic-linker closure (per `ldd`) into `rootfs`,
/// preserving absolute paths, and return the in-guest path of the binary.
/// Static binaries copy as-is. This keeps the container independent of how
/// the host filesystem is mounted (e.g. network filesystems in test VMs,
/// where gofer FD donation for mmap may not behave like local files).
fn install_with_libs(binary: &Path, rootfs: &Path) -> std::io::Result<PathBuf> {
    let target = std::fs::canonicalize(binary)?;
    let dest = rootfs.join("bin/sh");
    std::fs::create_dir_all(dest.parent().unwrap())?;
    std::fs::copy(&target, &dest)?;

    if let Ok(out) = Command::new("ldd").arg(&target).output() {
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            // "libc.so.6 => /lib/... (0x...)" or "/lib64/ld-linux... (0x...)"
            let path = match line.split_once("=>") {
                Some((_, rhs)) => rhs.trim(),
                None => line.trim(),
            };
            let path = path.split(" (").next().unwrap_or("").trim();
            if !path.starts_with('/') {
                continue; // vdso, "statically linked", etc.
            }
            let src = PathBuf::from(path);
            if let Ok(real) = std::fs::canonicalize(&src) {
                let dst = rootfs.join(path.trim_start_matches('/'));
                std::fs::create_dir_all(dst.parent().unwrap())?;
                std::fs::copy(&real, &dst)?;
            }
        }
    }
    Ok(PathBuf::from("/bin/sh"))
}

/// Everything needed to run and tear down one sandboxed workload.
struct SandboxedWorkload {
    child: Child,
    runsc: PathBuf,
    root: PathBuf,
}

impl SandboxedWorkload {
    /// Create an OCI bundle (self-contained tmpfs rootfs with just /bin/sh)
    /// and `runsc run` the workload in it.
    fn spawn(runsc: &Path, state_root: &Path, bundle: &Path) -> std::io::Result<Self> {
        let rootfs = bundle.join("rootfs");
        std::fs::create_dir_all(&rootfs)?;
        let sh = install_with_libs(Path::new("/bin/sh"), &rootfs)?;

        let spec = Command::new(runsc)
            .current_dir(bundle)
            .args(["spec", "--"])
            .arg(&sh)
            .args(["-c", GUEST_WORKLOAD])
            .output()?;
        assert!(
            spec.status.success(),
            "runsc spec failed: {}",
            String::from_utf8_lossy(&spec.stderr)
        );
        // No tty in the container.
        let config_path = bundle.join("config.json");
        let config = std::fs::read_to_string(&config_path)?;
        std::fs::write(
            &config_path,
            config.replace("\"terminal\": true", "\"terminal\": false"),
        )?;

        let child = Command::new(runsc)
            .arg("--root")
            .arg(state_root)
            .args(["--network=none", "--ignore-cgroups", "run", "-bundle"])
            .arg(bundle)
            .arg(CONTAINER_ID)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        Ok(Self {
            child,
            runsc: runsc.to_path_buf(),
            root: state_root.to_path_buf(),
        })
    }

    /// True once `runsc state` reports our container running.
    fn is_running(&mut self) -> bool {
        if let Ok(Some(status)) = self.child.try_wait() {
            panic!("runsc run exited before the sandbox came up: {status}");
        }
        Command::new(&self.runsc)
            .arg("--root")
            .arg(&self.root)
            .args(["state", CONTAINER_ID])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("\"running\""))
            .unwrap_or(false)
    }
}

impl Drop for SandboxedWorkload {
    fn drop(&mut self) {
        // Kill the container, then the foreground `runsc run` process. The
        // sandbox holds a parent-death signal, so this is belt-and-braces;
        // the temp state root disappears with the test.
        let _ = Command::new(&self.runsc)
            .arg("--root")
            .arg(&self.root)
            .args(["kill", CONTAINER_ID, "KILL"])
            .output();
        let _ = Command::new(&self.runsc)
            .arg("--root")
            .arg(&self.root)
            .args(["delete", "-force", CONTAINER_ID])
            .output();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// All host TIDs whose process executable is the runsc binary: the CLI,
/// gofer, sandbox (Sentry), and — because they fork without exec'ing — every
/// stub process mirroring a guest address space.
fn collect_runsc_tids(runsc: &Path) -> HashSet<i32> {
    let runsc = std::fs::canonicalize(runsc).unwrap_or_else(|_| runsc.to_path_buf());
    let mut tids = HashSet::new();
    let Ok(proc_dir) = std::fs::read_dir("/proc") else {
        return tids;
    };
    for entry in proc_dir.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<i32>().ok())
        else {
            continue;
        };
        let Ok(exe) = std::fs::read_link(format!("/proc/{pid}/exe")) else {
            continue;
        };
        if exe != runsc {
            continue;
        }
        let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
            continue;
        };
        for task in tasks.flatten() {
            if let Some(tid) = task
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<i32>().ok())
            {
                tids.insert(tid);
            }
        }
    }
    tids
}

fn read_i64_column(batch: &arrow::record_batch::RecordBatch, name: &str) -> Vec<i64> {
    let col = batch
        .column_by_name(name)
        .unwrap_or_else(|| panic!("column {name} missing"));
    if let Some(a) = col.as_any().downcast_ref::<Int64Array>() {
        (0..a.len()).map(|i| a.value(i)).collect()
    } else if let Some(a) = col.as_any().downcast_ref::<Int32Array>() {
        (0..a.len()).map(|i| a.value(i) as i64).collect()
    } else {
        panic!("column {name} is neither Int64 nor Int32");
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

/// Module portion of a rendered frame ("name (module ...) <addr>"), if any.
fn frame_module(frame: &str) -> Option<&str> {
    let start = frame.find(" (")? + 2;
    let rest = &frame[start..];
    let end = rest.find(" [").or_else(|| rest.find(')'))?;
    Some(&rest[..end])
}

/// A frame that symbolized to a real userland symbol: not bare hex, not an
/// `unknown (...)` miss, and not a kernel module.
fn is_resolved_user_frame(frame: &str) -> bool {
    if frame.starts_with("0x") || frame.starts_with("unknown") {
        return false;
    }
    match frame_module(frame) {
        Some(module) => module != "vmlinux" && !module.starts_with('['),
        None => false,
    }
}

#[test]
#[ignore]
fn test_gvisor_record() {
    let Some(runsc) = find_runsc() else {
        eprintln!(
            "skipping: no runsc binary found (set SYSTING_TEST_RUNSC or put runsc on PATH; \
             releases: https://storage.googleapis.com/gvisor/releases/release/latest/x86_64/runsc)"
        );
        return;
    };
    eprintln!("using runsc at {}", runsc.display());

    // Smoke-test the environment: `runsc do /bin/true` needs the same
    // privileges as the real workload (root, namespaces). Skip — with
    // runsc's own words — when it can't run here.
    let smoke_root = TempDir::new().expect("failed to create smoke state root");
    let smoke = Command::new(&runsc)
        .arg("--root")
        .arg(smoke_root.path())
        .args(["--network=none", "--ignore-cgroups", "do", "/bin/true"])
        .output()
        .expect("failed to spawn runsc");
    if !smoke.status.success() {
        eprintln!(
            "skipping: runsc cannot run sandboxes here ({}): {}",
            smoke.status,
            String::from_utf8_lossy(&smoke.stderr)
                .lines()
                .last()
                .unwrap_or("")
        );
        return;
    }

    let state_root = TempDir::new().expect("failed to create runsc state root");
    let bundle = TempDir::new().expect("failed to create bundle dir");
    let out_dir = TempDir::new().expect("failed to create output dir");

    let mut workload = SandboxedWorkload::spawn(&runsc, state_root.path(), bundle.path())
        .expect("failed to spawn runsc run");
    wait_until("gVisor sandbox to come up", || workload.is_running());

    // The stub processes mirroring guest address spaces exist once the
    // sandbox runs; collect the whole runsc process family (CLI, gofer,
    // Sentry, stubs — stubs fork without exec so they share the exe link).
    let mut runsc_tids = collect_runsc_tids(&runsc);
    eprintln!(
        "runsc process family before recording: {} tids",
        runsc_tids.len()
    );

    // Guest-side truth over the control socket: point discovery at our
    // private state root (also picked up by the recording below), dump the
    // live sandbox, and correlate a real stub's address space to the guest
    // shell — end to end against the running runsc.
    std::env::set_var("SYSTING_RUNSC_ROOTS", state_root.path());
    let sandbox_index = systing::gvisor_guest::SandboxIndex::load();
    assert!(
        !sandbox_index.is_empty(),
        "[gvisor guest maps] control socket in {} not reachable",
        state_root.path().display()
    );
    let correlated = runsc_tids.iter().find_map(|tid| {
        let maps = systing::sandbox_maps::ProcessMaps::load(*tid)?;
        if !maps.is_gvisor() {
            return None;
        }
        let ranges = maps.exec_file_ranges();
        sandbox_index
            .correlate(&ranges)
            .map(|g| g.comm().to_string())
    });
    eprintln!("stub correlation result: {correlated:?}");
    assert_eq!(
        correlated.as_deref(),
        Some("sh"),
        "[gvisor guest maps] no stub correlated to the guest shell"
    );

    eprintln!("Recording trace ({GVISOR_RECORDING_DURATION_SECS}s, sandboxed exec loop)...");
    let config = Config {
        duration: GVISOR_RECORDING_DURATION_SECS,
        output_dir: out_dir.path().to_path_buf(),
        output: out_dir.path().join("trace.pb"),
        ..Config::default()
    };
    systing(config, None).expect("systing recording failed");

    // Stubs are created lazily (new guest address space => new stub), so
    // re-collect after the recording and take the union.
    runsc_tids.extend(collect_runsc_tids(&runsc));
    drop(workload);
    eprintln!(
        "Recording complete; runsc family (union): {} tids",
        runsc_tids.len()
    );
    assert!(
        !runsc_tids.is_empty(),
        "no runsc processes observed while the sandbox was running"
    );

    // thread.parquet: utid -> tid, to find sandbox-attributed samples.
    let mut utid_to_tid: HashMap<i64, i32> = HashMap::new();
    for_each_batch(&out_dir.path().join("thread.parquet"), |batch| {
        let utids = read_i64_column(batch, "utid");
        let tids = read_i64_column(batch, "tid");
        for (u, t) in utids.iter().zip(tids.iter()) {
            utid_to_tid.insert(*u, *t as i32);
        }
    });

    // stack_sample.parquet: stack ids referenced by sandbox threads.
    let mut sandbox_stack_ids: HashSet<i64> = HashSet::new();
    let mut sandbox_sample_count = 0usize;
    for_each_batch(&out_dir.path().join("stack_sample.parquet"), |batch| {
        let utids = read_i64_column(batch, "utid");
        let stack_ids = read_i64_column(batch, "stack_id");
        for (u, s) in utids.iter().zip(stack_ids.iter()) {
            let is_sandbox = utid_to_tid
                .get(u)
                .is_some_and(|tid| runsc_tids.contains(tid));
            if is_sandbox {
                sandbox_stack_ids.insert(*s);
                sandbox_sample_count += 1;
            }
        }
    });
    eprintln!(
        "sandbox-attributed samples: {sandbox_sample_count} across {} unique stacks",
        sandbox_stack_ids.len()
    );
    assert!(
        sandbox_sample_count > 0,
        "[gvisor recording] no stack samples attributed to the runsc process family; \
         the sandboxed workload was not captured"
    );

    // stack.parquet: inspect the frames of sandbox stacks.
    let mut gvisor_labeled = 0usize;
    let mut resolved_user = 0usize;
    let mut resolved_guest = 0usize;
    let mut example_label: Option<String> = None;
    let mut example_guest: Option<String> = None;
    for_each_batch(&out_dir.path().join("stack.parquet"), |batch| {
        let ids = read_i64_column(batch, "id");
        let frames_col = batch
            .column_by_name("frame_names")
            .expect("frame_names column missing")
            .as_any()
            .downcast_ref::<ListArray>()
            .expect("frame_names should be a ListArray")
            .clone();
        for (row, id) in ids.iter().enumerate() {
            if !sandbox_stack_ids.contains(id) {
                continue;
            }
            let values = frames_col.value(row);
            let strings = values
                .as_any()
                .downcast_ref::<StringArray>()
                .expect("frame_names inner should be StringArray");
            for i in 0..strings.len() {
                let frame = strings.value(i);
                if frame.contains("([gvisor:") {
                    gvisor_labeled += 1;
                    example_label.get_or_insert_with(|| frame.to_string());
                }
                if is_resolved_user_frame(frame) {
                    resolved_user += 1;
                    // Frames from the runsc binary itself are the Sentry's
                    // own (Go) code — resolved from an ordinary host
                    // mapping. Frames from any OTHER module in a sandbox
                    // stack are guest text: they only resolve if the
                    // map_files-based path works through the gofer's
                    // private mount namespace.
                    let module = frame_module(frame).unwrap_or("");
                    if !module.starts_with("runsc") {
                        resolved_guest += 1;
                        example_guest.get_or_insert_with(|| frame.to_string());
                    }
                }
            }
        }
    });
    eprintln!(
        "sandbox frames: {gvisor_labeled} gvisor-labeled (e.g. {example_label:?}), \
         {resolved_user} resolved-user of which {resolved_guest} guest-module \
         (e.g. {example_guest:?})"
    );

    // The PR's value proposition, both halves:
    // (1) sandbox-runtime execution is classified instead of raw hex —
    //     the syscall loop bounces through the systrap trampolines all
    //     recording long, and preemption traffic adds to it;
    assert!(
        gvisor_labeled > 0,
        "[gvisor labels] no `unknown ([gvisor:*])` frames in sandbox stacks; \
         classification did not engage"
    );
    // (2) guest user text symbolizes from the host despite the gofer's
    //     private mount namespace (map_files-based resolution). The spinner
    //     process lives in guest text (/bin/sh), so its samples must
    //     resolve to a non-runsc module.
    assert!(
        resolved_guest > 0,
        "[gvisor symbolization] no resolved guest-module frames in sandbox \
         stacks ({resolved_user} resolved frames were all from the runsc \
         binary itself); guest text did not symbolize"
    );
}
