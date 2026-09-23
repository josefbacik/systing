//! End-to-end tests for `--include-task-context`: a program that uses the
//! task-context library (`crates/task-context`) runs under the tracer, and
//! the trace must carry what the program set - the id of each thread's
//! context in every running-stack sample, the named values of each id once
//! in the `task_context` table, the two joined by (`utid`, id).
//!
//! The traced program is the library's own example
//! (`crates/task-context/examples/tcx_example.c`), built here twice with the
//! system C compiler: once with the library's source linked into the
//! executable, once against a shared object the executable names as a
//! dependency. Those are the two ways a process is found (see
//! `src/task_context/discovery.rs`). Three threads go through three phases
//! and stay on a CPU after each, so every (thread, phase) pair is a context
//! the sampler must have seen:
//!
//! ```text
//! phase 0   request_id = "req-<n> 100%"   iteration_id = 1000 n + 1
//! phase 1   request_id unchanged          iteration_id = 1000 n + 2
//! phase 2   request_id cleared            iteration_id = 1000 n + 2
//! ```
//!
//! Two more tests hold what must NOT happen: a recipe that is wrong for its
//! process (planted over a busy process that does not use the library) reads
//! nothing, and under the kernel's confidentiality mode (forced here) a
//! process that does use the library leaves no id and no value in the trace.
//!
//! These need root, a kernel that loads the tracer's BPF object (6.12 or
//! newer is what the object is load-tested on) and a C compiler (`cc`, or
//! `$CC`). To run:
//! ```
//! ./scripts/run-integration-tests.sh task_context_record
//! ```

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use arrow::array::{Array, Int64Array, StringArray, UInt64Array};
use common::workload::SLOW_MACHINE_BUDGET;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use systing::traced_command::spawn_traced_child;
use systing::{systing, Config};
use tempfile::TempDir;

/// How long every thread of the example stays on a CPU after each phase.
const BUSY_MS: &str = "400";
/// The least number of samples that must carry each expected context. A
/// thread spins for `BUSY_MS` in each; a handful is far below what any
/// sampling rate gives and far above zero.
const MIN_SAMPLES_PER_CONTEXT: usize = 5;
/// Tells `busy_helper_without_the_library` how long to spin.
const SPIN_SECS_VAR: &str = "TASK_CONTEXT_TEST_SPIN_SECS";

// ---------------------------------------------------------------------------
// Building the example
// ---------------------------------------------------------------------------

fn library_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("crates/task-context")
}

fn compiler() -> String {
    std::env::var("CC").unwrap_or_else(|_| "cc".to_string())
}

fn run_tool(command: &mut Command) -> Result<(), String> {
    match command.output() {
        Err(error) => Err(format!("{command:?}: {error}")),
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => Err(format!(
            "{command:?}: {}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )),
    }
}

fn compile(arguments: &[&str], inputs: &[&Path], output: &Path) -> Result<(), String> {
    let mut command = Command::new(compiler());
    command
        .args(["-O2", "-g", "-pthread", "-I"])
        .arg(library_dir().join("include"))
        .args(arguments)
        .args(inputs)
        .arg("-o")
        .arg(output);
    run_tool(&mut command)
}

/// Without a C compiler there is nothing to trace. These tests are run by
/// hand, so that is said loudly and is not a failure.
fn have_a_compiler() -> bool {
    match Command::new(compiler()).arg("--version").output() {
        Ok(output) if output.status.success() => true,
        _ => {
            eprintln!("SKIPPED: no C compiler answers to `cc --version` (or to $CC)");
            false
        }
    }
}

/// The example with the library's source linked into the executable: the
/// library's record is in the executable itself.
fn build_linked_in(dir: &Path) -> PathBuf {
    let program = dir.join("tcx_example_linked_in");
    compile(
        &[],
        &[
            &library_dir().join("src/task_context.c"),
            &library_dir().join("examples/tcx_example.c"),
        ],
        &program,
    )
    .expect("the example builds with the library linked in");
    program
}

/// The example against a shared object: the executable only names the
/// library as a dependency, and the record is in the shared object.
fn build_against_shared_object(dir: &Path) -> PathBuf {
    let library = dir.join("libtask_context.so");
    let program = dir.join("tcx_example_shared");
    // nodelete: a thread's exit handler and the record point into the object.
    compile(
        &["-fPIC", "-shared", "-Wl,-z,nodelete"],
        &[&library_dir().join("src/task_context.c")],
        &library,
    )
    .expect("the shared object builds");
    let search = format!("-Wl,-rpath,{}", dir.display());
    let mut command = Command::new(compiler());
    command
        .args(["-O2", "-g", "-pthread", "-I"])
        .arg(library_dir().join("include"))
        .arg(library_dir().join("examples/tcx_example.c"))
        .arg("-L")
        .arg(dir)
        .arg("-ltask_context")
        .arg(&search)
        .arg("-o")
        .arg(&program);
    run_tool(&mut command).expect("the example links against the shared object");
    program
}

// ---------------------------------------------------------------------------
// Reading a trace back
// ---------------------------------------------------------------------------

/// One row of `stack_sample`: the thread, and the context id it carries.
struct Sample {
    utid: i64,
    id: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Value {
    Number(u64),
    Text(String),
}

/// (`utid`, id) -> the named values of that context.
type Contexts = BTreeMap<(i64, u64), BTreeMap<String, Value>>;

fn batches(path: &Path) -> impl Iterator<Item = arrow::record_batch::RecordBatch> {
    let file = File::open(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    ParquetRecordBatchReaderBuilder::try_new(file)
        .expect("a parquet reader")
        .build()
        .expect("a parquet reader")
        .map(|batch| batch.expect("a batch"))
}

fn samples(dir: &Path) -> Vec<Sample> {
    let path = dir.join("stack_sample.parquet");
    assert!(path.exists(), "stack_sample.parquet not found");
    let mut rows = Vec::new();
    for batch in batches(&path) {
        let utid = batch
            .column_by_name("utid")
            .expect("stack_sample.utid")
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("utid is Int64");
        let id = batch
            .column_by_name("task_context_id")
            .expect("every trace this build writes has stack_sample.task_context_id")
            .as_any()
            .downcast_ref::<UInt64Array>()
            .expect("task_context_id is UInt64");
        for row in 0..batch.num_rows() {
            rows.push(Sample {
                utid: utid.value(row),
                id: (!id.is_null(row)).then(|| id.value(row)),
            });
        }
    }
    rows
}

/// The `task_context` table. The file exists only when the capture wrote a
/// row to it.
fn contexts(dir: &Path) -> Contexts {
    let path = dir.join("task_context.parquet");
    let mut contexts = Contexts::new();
    if !path.exists() {
        return contexts;
    }
    for batch in batches(&path) {
        let utid = batch
            .column_by_name("utid")
            .expect("task_context.utid")
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("utid is Int64");
        let id = batch
            .column_by_name("id")
            .expect("task_context.id")
            .as_any()
            .downcast_ref::<UInt64Array>()
            .expect("id is UInt64");
        let name = batch
            .column_by_name("name")
            .expect("task_context.name")
            .as_any()
            .downcast_ref::<StringArray>()
            .expect("name is Utf8");
        let number = batch
            .column_by_name("value_u64")
            .expect("task_context.value_u64")
            .as_any()
            .downcast_ref::<UInt64Array>()
            .expect("value_u64 is UInt64");
        let text = batch
            .column_by_name("value_str")
            .expect("task_context.value_str")
            .as_any()
            .downcast_ref::<StringArray>()
            .expect("value_str is Utf8");
        for row in 0..batch.num_rows() {
            let value = match (number.is_null(row), text.is_null(row)) {
                (false, true) => Value::Number(number.value(row)),
                (true, false) => Value::Text(text.value(row).to_string()),
                other => panic!(
                    "row {row} of task_context sets {other:?} (value_u64 null, value_str null): \
                     exactly one of the two is set"
                ),
            };
            let previous = contexts
                .entry((utid.value(row), id.value(row)))
                .or_default()
                .insert(name.value(row).to_string(), value);
            assert!(
                previous.is_none(),
                "task_context has the name {:?} twice under one (utid, id)",
                name.value(row)
            );
        }
    }
    contexts
}

/// Every `utid` the `thread` table has.
fn thread_utids(dir: &Path) -> BTreeSet<i64> {
    let path = dir.join("thread.parquet");
    assert!(path.exists(), "thread.parquet not found");
    let mut utids = BTreeSet::new();
    for batch in batches(&path) {
        let utid = batch
            .column_by_name("utid")
            .expect("thread.utid")
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("utid is Int64");
        utids.extend((0..batch.num_rows()).map(|row| utid.value(row)));
    }
    utids
}

// ---------------------------------------------------------------------------
// Capturing
// ---------------------------------------------------------------------------

/// Record `command` as the tracer's own traced command, which pins the
/// lifecycle to events: the child waits until the programs are attached
/// before it execs, and the recording stops because the child exited.
fn record_command(command: &[String], configure: impl FnOnce(&mut Config)) -> TempDir {
    let dir = TempDir::new().expect("a directory for the trace");
    let child = spawn_traced_child(command).expect("the traced child forks");
    let mut config = Config {
        duration: 300, // backstop only: the child's exit stops the trace
        include_task_context: true,
        output_dir: dir.path().to_path_buf(),
        output: dir.path().join("trace.pb"),
        ..Config::default()
    };
    configure(&mut config);
    let start = Instant::now();
    systing(config, Some(child)).expect("the recording runs");
    assert!(
        start.elapsed() < SLOW_MACHINE_BUDGET,
        "the recording should stop when the traced command exits; it took {:.1}s",
        start.elapsed().as_secs_f64()
    );
    dir
}

fn example_command(program: &Path) -> Vec<String> {
    vec![
        program.to_str().expect("a utf-8 path").to_string(),
        "--busy-ms".to_string(),
        BUSY_MS.to_string(),
    ]
}

/// What thread `who` of the example has set after each of its three phases.
fn expected_phases(who: u64) -> [BTreeMap<String, Value>; 3] {
    let request = (
        "request_id".to_string(),
        Value::Text(format!("req-{who} 100%")),
    );
    let iteration = |n: u64| ("iteration_id".to_string(), Value::Number(n));
    [
        BTreeMap::from([request.clone(), iteration(1000 * who + 1)]),
        BTreeMap::from([request, iteration(1000 * who + 2)]),
        BTreeMap::from([iteration(1000 * who + 2)]),
    ]
}

/// The whole read: every thread's three contexts are in the table with the
/// values the program set, under one `utid` each; every sample that carries
/// an id finds its values; and each expected context was sampled.
fn check_example_trace(dir: &Path, how: &str) {
    let samples = samples(dir);
    let contexts = contexts(dir);
    assert!(!samples.is_empty(), "[{how}] the capture has no samples");
    assert!(
        !contexts.is_empty(),
        "[{how}] the task_context table is empty: the process was not found, or nothing was read \
         (the `task_context discovery:` and `task_context samples:` lines above say which)"
    );

    let mut threads = BTreeSet::new();
    for who in 0..3u64 {
        let phases = expected_phases(who);
        // The thread is the one utid that has the first phase's context.
        let owners: Vec<i64> = contexts
            .iter()
            .filter(|(_, values)| **values == phases[0])
            .map(|((utid, _), _)| *utid)
            .collect();
        assert_eq!(
            owners.len(),
            1,
            "[{how}] thread {who}: its first context {:?} is in the table {} times",
            phases[0],
            owners.len()
        );
        let utid = owners[0];
        assert!(
            threads.insert(utid),
            "[{how}] two threads of the example share utid {utid}"
        );
        for (phase, wanted) in phases.iter().enumerate() {
            let ids: Vec<u64> = contexts
                .iter()
                .filter(|((owner, _), values)| *owner == utid && *values == wanted)
                .map(|((_, id), _)| *id)
                .collect();
            assert_eq!(
                ids.len(),
                1,
                "[{how}] thread {who} phase {phase}: {wanted:?} is in the table {} times under utid {utid}",
                ids.len()
            );
            let carried = samples
                .iter()
                .filter(|sample| sample.utid == utid && sample.id == Some(ids[0]))
                .count();
            assert!(
                carried >= MIN_SAMPLES_PER_CONTEXT,
                "[{how}] thread {who} phase {phase}: {carried} samples carry id {:#x}; the thread \
                 spun for {BUSY_MS} ms with it",
                ids[0]
            );
        }
    }

    // Every row belongs to a thread the trace knows: no orphan utid.
    let known = thread_utids(dir);
    for (utid, id) in contexts.keys() {
        assert!(
            known.contains(utid),
            "[{how}] task_context has utid {utid} (id {id:#x}), which the thread table does not have"
        );
    }

    // Every id a sample carries has its values: none was dropped on the way
    // (three changes a thread are far inside the per-CPU budget).
    let mut with_id = 0usize;
    for sample in &samples {
        if let Some(id) = sample.id {
            with_id += 1;
            assert!(
                contexts.contains_key(&(sample.utid, id)),
                "[{how}] a sample of utid {} carries id {id:#x}, which the task_context table does not have",
                sample.utid
            );
            assert_ne!(id, 0, "[{how}] 0 means no context and is stored as NULL");
        }
    }
    eprintln!(
        "[{how}] {} samples, {with_id} with a context id, {} contexts of {} threads",
        samples.len(),
        contexts.len(),
        threads.len()
    );
}

/// Nothing of any process's context is in the trace.
fn check_nothing_was_read(dir: &Path, how: &str) {
    let samples = samples(dir);
    assert!(
        !samples.is_empty(),
        "[{how}] the capture has no samples, so it shows nothing"
    );
    let carrying = samples.iter().filter(|sample| sample.id.is_some()).count();
    assert_eq!(
        carrying,
        0,
        "[{how}] {carrying} of {} samples carry a context id",
        samples.len()
    );
    let contexts = contexts(dir);
    assert!(
        contexts.is_empty(),
        "[{how}] the task_context table has rows: {contexts:?}"
    );
}

// ---------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------

#[test]
#[ignore] // Requires root/BPF privileges
fn a_program_with_the_library_linked_in_is_traced_with_its_contexts() {
    if !have_a_compiler() {
        return;
    }
    let build = TempDir::new().expect("a directory to build in");
    let program = build_linked_in(build.path());
    let trace = record_command(&example_command(&program), |_| {});
    check_example_trace(trace.path(), "linked in");
}

#[test]
#[ignore] // Requires root/BPF privileges
fn a_program_that_names_the_library_as_a_dependency_is_traced_with_its_contexts() {
    if !have_a_compiler() {
        return;
    }
    let build = TempDir::new().expect("a directory to build in");
    let program = build_against_shared_object(build.path());
    let trace = record_command(&example_command(&program), |_| {});
    check_example_trace(trace.path(), "shared object");
}

/// The kernel's confidentiality mode, forced: the process uses the library
/// and publishes its recipe, and the trace still has no id and no value.
#[test]
#[ignore] // Requires root/BPF privileges
fn nothing_is_read_in_confidentiality_mode() {
    if !have_a_compiler() {
        return;
    }
    let build = TempDir::new().expect("a directory to build in");
    let program = build_linked_in(build.path());
    let trace = record_command(&example_command(&program), |config| {
        config.task_context_force_restricted = true;
    });
    check_nothing_was_read(trace.path(), "confidentiality mode");
}

/// Not a real test: a process that stays on a CPU and does NOT use the
/// library, run by `a_wrong_recipe_reads_nothing` as
/// `<test-binary> --exact busy_helper_without_the_library`. Deliberately NOT
/// `#[ignore]`: the integration runner selects ignored tests, and this helper
/// must stay out of that run while staying spawnable by exact name. Run
/// plainly it spins for a second and passes.
#[test]
fn busy_helper_without_the_library() {
    let seconds = std::env::var(SPIN_SECS_VAR)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1);
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut counter: u64 = 0;
    while Instant::now() < deadline {
        counter = std::hint::black_box(counter.wrapping_add(1));
    }
    assert!(counter > 0);
}

/// A recipe nobody validated, over a process it is wrong for. Whatever the
/// eight bytes at "thread pointer + offset" of that process happen to hold,
/// the reader's own checks must end the read: a NULL there is no context, an
/// address outside the region or off a block boundary is refused unread, and
/// a block that does not start with the library's header is a miss. The trace
/// must carry no id and no value either way.
#[test]
#[ignore] // Requires root/BPF privileges
fn a_wrong_recipe_reads_nothing() {
    // The side of the thread pointer the library's slot is on.
    let offset: i64 = if cfg!(target_arch = "aarch64") {
        16
    } else {
        -8
    };
    let recipes: [(&str, [u64; 3]); 2] = [
        // A region nothing of the process is in.
        ("a small region", [offset as u64, 0x10000, 16 * 1024 * 1024]),
        // A "region" that is the whole of user memory: only the block
        // boundary and the header test are left to say no.
        (
            "all of user memory",
            [offset as u64, 0x10000, 0x0000_7fff_ffff_0000 - 0x10000],
        ),
    ];
    let own_binary = std::env::current_exe().expect("the test binary's path");
    for (how, recipe) in recipes {
        let mut busy = Command::new(&own_binary)
            .args(["--exact", "busy_helper_without_the_library"])
            .env(SPIN_SECS_VAR, "600")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("the busy process starts");
        let dir = TempDir::new().expect("a directory for the trace");
        let result = systing(
            Config {
                duration: 3,
                pid: vec![busy.id()],
                include_task_context: true,
                task_context_planted_recipes: vec![(busy.id(), recipe)],
                output_dir: dir.path().to_path_buf(),
                output: dir.path().join("trace.pb"),
                ..Config::default()
            },
            None,
        );
        let _ = busy.kill();
        let _ = busy.wait();
        result.expect("the recording runs");
        check_nothing_was_read(dir.path(), how);
    }
}
