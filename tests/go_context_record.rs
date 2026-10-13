//! End-to-end tests for `--include-go-context`: a Go program runs under the
//! tracer, and the trace must carry what it did - the goroutine of every
//! running-stack sample of it, the id of the goroutine's profiler label set,
//! and each set once in the `go_labels` table, joined through the sample's
//! thread to its process.
//!
//! The program (built here with `go`) spins four goroutines for a while:
//! three inside `pprof.Do` with labels of their own, `worker=w<n>` and
//! `kind=spin`, and one with none. So the trace must hold three label sets,
//! each with exactly those two labels; the samples of each set must all be
//! of one goroutine, a goroutine of no other set; and the unlabelled
//! goroutine's samples must carry a goroutine and no set. Built twice: as it
//! is, and stripped (`-ldflags=-s -w`), whose recipe is read from its code
//! alone.
//!
//! A third program spins inside a C function (cgo) under labels of its own.
//! Go runs C on the thread's system stack, where the thread-local `g` is the
//! scheduler's, so its samples carry the goroutine and its labels only when
//! the reader follows `m.curg`, as Go's own profiler does.
//!
//! Three more programs hold the reader's corners: a goroutine under labels
//! that drives an `iter.Pull` iterator, whose switches leave a goroutine's m
//! briefly nil; a thread that C made, which keeps its goroutine after a
//! callback into Go and must carry none while it is back in C; and a
//! goroutine under an empty label set, which is no set.
//!
//! These need root, a kernel that loads the tracer's BPF object, and a Go
//! 1.26 or 1.27 toolchain (`go`, or `$GO`); without one they say so and pass.
//! To run:
//! ```
//! ./scripts/run-integration-tests.sh go_context_record
//! ```

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use arrow::array::{Array, Int32Array, Int64Array, Int8Array, StringArray, UInt64Array};
use arrow::record_batch::RecordBatch;
use common::workload::SLOW_MACHINE_BUDGET;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use systing::traced_command::spawn_traced_child;
use systing::{systing, Config};
use tempfile::TempDir;

/// How long the program spins, in milliseconds.
const SPIN_MS: &str = "5000";
/// The fewest samples each label set must have.
const MIN_SAMPLES_PER_SET: usize = 5;

const PROGRAM: &str = r#"package main

import (
	"context"
	"os"
	"runtime/pprof"
	"strconv"
	"sync"
	"time"
)

//go:noinline
func spin(until time.Time) {
	for time.Now().Before(until) {
	}
}

func main() {
	ms, _ := strconv.Atoi(os.Args[1])
	until := time.Now().Add(time.Duration(ms) * time.Millisecond)
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			labels := pprof.Labels("worker", "w"+strconv.Itoa(i), "kind", "spin")
			pprof.Do(context.Background(), labels, func(context.Context) { spin(until) })
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		spin(until)
	}()
	wg.Wait()
}
"#;

const CGO_PROGRAM: &str = r#"package main

/*
#include <time.h>
static void spin(long ms) {
	struct timespec start, now;
	clock_gettime(CLOCK_MONOTONIC, &start);
	do {
		clock_gettime(CLOCK_MONOTONIC, &now);
	} while ((now.tv_sec - start.tv_sec) * 1000 + (now.tv_nsec - start.tv_nsec) / 1000000 < ms);
}
*/
import "C"

import (
	"context"
	"os"
	"runtime/pprof"
	"strconv"
)

func main() {
	ms, _ := strconv.Atoi(os.Args[1])
	pprof.Do(context.Background(), pprof.Labels("worker", "cgo"), func(context.Context) {
		C.spin(C.long(ms))
	})
}
"#;

const PULL_PROGRAM: &str = r#"package main

import (
	"context"
	"iter"
	"os"
	"runtime/pprof"
	"strconv"
	"time"
)

func main() {
	ms, _ := strconv.Atoi(os.Args[1])
	until := time.Now().Add(time.Duration(ms) * time.Millisecond)
	pprof.Do(context.Background(), pprof.Labels("worker", "pull"), func(context.Context) {
		// The iterator's goroutine is made here, so it has the labels too.
		next, stop := iter.Pull(func(yield func(int) bool) {
			for i := 0; yield(i); i++ {
			}
		})
		defer stop()
		n := 0
		for time.Now().Before(until) {
			for j := 0; j < 1000; j++ {
				v, _ := next()
				n += v
			}
		}
		println(n)
	})
}
"#;

const C_THREAD_PROGRAM: &str = r#"package main

/*
#include <pthread.h>
#include <time.h>
extern void callback(void);
static long spin_ms;
static void *run(void *arg) {
	struct timespec start, now;
	callback();
	clock_gettime(CLOCK_MONOTONIC, &start);
	do {
		clock_gettime(CLOCK_MONOTONIC, &now);
	} while ((now.tv_sec - start.tv_sec) * 1000 + (now.tv_nsec - start.tv_nsec) / 1000000 < spin_ms);
	return 0;
}
static void start(long ms) {
	pthread_t thread;
	spin_ms = ms;
	pthread_create(&thread, 0, run, 0);
	pthread_join(thread, 0);
}
*/
import "C"

import (
	"context"
	"os"
	"runtime/pprof"
	"strconv"
	"time"
)

// Leaves its labels on the goroutine that the C thread keeps.
//
//export callback
func callback() {
	pprof.SetGoroutineLabels(pprof.WithLabels(context.Background(), pprof.Labels("worker", "callback")))
}

func main() {
	ms, _ := strconv.Atoi(os.Args[1])
	// First a while in Go under labels of its own: the samples of it show
	// that this program's goroutines are read at all.
	until := time.Now().Add(time.Duration(ms/2) * time.Millisecond)
	pprof.Do(context.Background(), pprof.Labels("worker", "main"), func(context.Context) {
		n := 0
		for time.Now().Before(until) {
			n++
		}
		println(n)
	})
	C.start(C.long(ms))
}
"#;

const EMPTY_SET_PROGRAM: &str = r#"package main

import (
	"context"
	"os"
	"runtime/pprof"
	"strconv"
	"time"
)

func main() {
	ms, _ := strconv.Atoi(os.Args[1])
	until := time.Now().Add(time.Duration(ms) * time.Millisecond)
	pprof.Do(context.Background(), pprof.Labels(), func(context.Context) {
		n := 0
		for time.Now().Before(until) {
			n++
		}
		println(n)
	})
}
"#;

fn go() -> String {
    std::env::var("GO").unwrap_or_else(|_| "go".to_string())
}

/// `program`, built into `dir` (stripped with `strip`, with cgo with `cgo`),
/// or `None` when no Go toolchain answers.
fn build(dir: &Path, program: &str, strip: bool, cgo: bool) -> Option<PathBuf> {
    if Command::new(go()).arg("version").output().is_err() {
        eprintln!("SKIPPED: no Go toolchain answers to `go version` (or to $GO)");
        return None;
    }
    let src = dir.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("main.go"), program).unwrap();
    std::fs::write(src.join("go.mod"), "module labels\n\ngo 1.26\n").unwrap();
    let out = dir.join(if strip { "labels_stripped" } else { "labels" });
    let mut command = Command::new(go());
    command
        .current_dir(&src)
        .env("CGO_ENABLED", if cgo { "1" } else { "0" })
        .env("GOTOOLCHAIN", "local")
        .args(["build", "-o"])
        .arg(&out);
    if strip {
        command.arg("-ldflags=-s -w");
    }
    let status = command.arg(".").status().expect("go build runs");
    assert!(status.success(), "go build failed");
    Some(out)
}

fn batches(path: &Path) -> Vec<RecordBatch> {
    let file = File::open(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    ParquetRecordBatchReaderBuilder::try_new(file)
        .unwrap()
        .build()
        .unwrap()
        .map(|b| b.unwrap())
        .collect()
}

fn column<'a, T: 'static>(batch: &'a RecordBatch, name: &str) -> &'a T {
    batch
        .column_by_name(name)
        .unwrap_or_else(|| panic!("no column {name}"))
        .as_any()
        .downcast_ref::<T>()
        .unwrap_or_else(|| panic!("{name} has another type"))
}

/// (utid, go_goid, go_labels_id) of every sample that has a goroutine.
fn goroutine_samples(dir: &Path) -> Vec<(i64, u64, Option<u64>)> {
    let mut out = Vec::new();
    for batch in batches(&dir.join("stack_sample.parquet")) {
        let utid = column::<Int64Array>(&batch, "utid");
        let goid = column::<UInt64Array>(&batch, "go_goid");
        let labels = column::<UInt64Array>(&batch, "go_labels_id");
        for row in 0..batch.num_rows() {
            if goid.is_null(row) {
                assert!(labels.is_null(row), "a label set without a goroutine");
                continue;
            }
            let set = (!labels.is_null(row)).then(|| labels.value(row));
            out.push((utid.value(row), goid.value(row), set));
        }
    }
    out
}

/// The running-stack samples of the threads of process `upid`, with their
/// label-set ids (NULL kept).
fn running_samples_of(dir: &Path, upid: i64) -> Vec<Option<u64>> {
    let threads = thread_processes(dir);
    let mut out = Vec::new();
    for batch in batches(&dir.join("stack_sample.parquet")) {
        let utid = column::<Int64Array>(&batch, "utid");
        let kind = column::<Int8Array>(&batch, "stack_event_type");
        let labels = column::<UInt64Array>(&batch, "go_labels_id");
        for row in 0..batch.num_rows() {
            if kind.value(row) == 1 && threads.get(&utid.value(row)) == Some(&upid) {
                out.push((!labels.is_null(row)).then(|| labels.value(row)));
            }
        }
    }
    out
}

/// A sample's goroutine and label-set id (NULL as `None`).
type Sample = (Option<u64>, Option<u64>);

/// The process that ran as `pid`, and the goroutine and label-set id of each
/// of its running-stack samples.
fn program_samples(dir: &Path, pid: u32) -> (i64, Vec<Sample>) {
    let mut upids = BTreeSet::new();
    for batch in batches(&dir.join("process.parquet")) {
        let upid = column::<Int64Array>(&batch, "upid");
        let pids = column::<Int32Array>(&batch, "pid");
        for row in 0..batch.num_rows() {
            if pids.value(row) as u32 == pid {
                upids.insert(upid.value(row));
            }
        }
    }
    assert_eq!(upids.len(), 1, "one process of pid {pid}: {upids:?}");
    let upid = *upids.first().unwrap();
    let threads = thread_processes(dir);
    let mut out = Vec::new();
    for batch in batches(&dir.join("stack_sample.parquet")) {
        let utid = column::<Int64Array>(&batch, "utid");
        let kind = column::<Int8Array>(&batch, "stack_event_type");
        let goid = column::<UInt64Array>(&batch, "go_goid");
        let labels = column::<UInt64Array>(&batch, "go_labels_id");
        for row in 0..batch.num_rows() {
            if kind.value(row) == 1 && threads.get(&utid.value(row)) == Some(&upid) {
                out.push((
                    (!goid.is_null(row)).then(|| goid.value(row)),
                    (!labels.is_null(row)).then(|| labels.value(row)),
                ));
            }
        }
    }
    assert!(
        out.len() >= 4 * MIN_SAMPLES_PER_SET,
        "{} samples of process {pid}",
        out.len()
    );
    (upid, out)
}

/// The label sets of process `upid` in the trace at `dir`: id -> labels.
fn sets_of(dir: &Path, upid: i64) -> BTreeMap<u64, BTreeMap<String, String>> {
    if !dir.join("go_labels.parquet").exists() {
        return BTreeMap::new();
    }
    label_sets(dir)
        .into_iter()
        .filter(|((of, _), _)| *of == upid)
        .map(|((_, id), labels)| (id, labels))
        .collect()
}

/// The `go_labels` table: (upid, id) -> its labels.
fn label_sets(dir: &Path) -> BTreeMap<(i64, u64), BTreeMap<String, String>> {
    let path = dir.join("go_labels.parquet");
    assert!(path.exists(), "go_labels.parquet not found");
    let mut sets: BTreeMap<(i64, u64), BTreeMap<String, String>> = BTreeMap::new();
    for batch in batches(&path) {
        let upid = column::<Int64Array>(&batch, "upid");
        let id = column::<UInt64Array>(&batch, "id");
        let key = column::<StringArray>(&batch, "name");
        let value = column::<StringArray>(&batch, "value_str");
        for row in 0..batch.num_rows() {
            let previous = sets
                .entry((upid.value(row), id.value(row)))
                .or_default()
                .insert(key.value(row).to_string(), value.value(row).to_string());
            assert!(previous.is_none(), "a key twice in one set");
        }
    }
    sets
}

/// The `thread` table: utid -> upid.
fn thread_processes(dir: &Path) -> BTreeMap<i64, i64> {
    let mut out = BTreeMap::new();
    for batch in batches(&dir.join("thread.parquet")) {
        let utid = column::<Int64Array>(&batch, "utid");
        let upid = column::<Int64Array>(&batch, "upid");
        for row in 0..batch.num_rows() {
            if !upid.is_null(row) {
                out.insert(utid.value(row), upid.value(row));
            }
        }
    }
    out
}

fn record(program: &Path) -> TempDir {
    record_with_pid(program).0
}

/// [`record`], and the pid the program ran as.
fn record_with_pid(program: &Path) -> (TempDir, u32) {
    let dir = TempDir::new().expect("a directory for the trace");
    let command = vec![
        program.to_str().expect("a utf-8 path").to_string(),
        SPIN_MS.to_string(),
    ];
    let child = spawn_traced_child(&command).expect("the traced child forks");
    let pid = child.pid;
    let config = Config {
        duration: 300, // backstop only: the child's exit stops the trace
        include_go_context: true,
        output_dir: dir.path().to_path_buf(),
        output: dir.path().join("trace.pb"),
        ..Config::default()
    };
    let start = Instant::now();
    systing(config, Some(child)).expect("the recording runs");
    assert!(start.elapsed() < SLOW_MACHINE_BUDGET);
    (dir, pid)
}

fn check(how: &str, strip: bool) {
    let build_dir = TempDir::new().unwrap();
    let Some(program) = build(build_dir.path(), PROGRAM, strip, false) else {
        return;
    };
    let trace = record(&program);
    let samples = goroutine_samples(trace.path());
    let sets = label_sets(trace.path());
    let processes = thread_processes(trace.path());

    let wanted: BTreeSet<BTreeMap<String, String>> = (0..3)
        .map(|i| {
            BTreeMap::from([
                ("worker".to_string(), format!("w{i}")),
                ("kind".to_string(), "spin".to_string()),
            ])
        })
        .collect();
    let program_sets: BTreeMap<(i64, u64), &BTreeMap<String, String>> = sets
        .iter()
        .filter(|(_, labels)| wanted.contains(*labels))
        .map(|(k, v)| (*k, v))
        .collect();
    assert_eq!(
        program_sets
            .values()
            .cloned()
            .cloned()
            .collect::<BTreeSet<_>>(),
        wanted,
        "[{how}] the label sets in go_labels"
    );
    let upid = program_sets.keys().next().unwrap().0;
    assert!(
        program_sets.keys().all(|(p, _)| *p == upid),
        "[{how}] the three sets are of one process"
    );

    // Each set: enough samples, all of one goroutine, of the program's
    // process, and that goroutine in no other set.
    let mut goroutine_of_set = BTreeMap::new();
    for (_, id) in program_sets.keys() {
        let of_set: Vec<&(i64, u64, Option<u64>)> =
            samples.iter().filter(|(_, _, s)| *s == Some(*id)).collect();
        assert!(
            of_set.len() >= MIN_SAMPLES_PER_SET,
            "[{how}] set {id:#x} has {} samples",
            of_set.len()
        );
        let goids: BTreeSet<u64> = of_set.iter().map(|(_, g, _)| *g).collect();
        assert_eq!(
            goids.len(),
            1,
            "[{how}] set {id:#x} is of goroutines {goids:?}"
        );
        assert!(
            of_set
                .iter()
                .all(|(utid, _, _)| processes.get(utid) == Some(&upid)),
            "[{how}] a sample of set {id:#x} is of a thread of another process"
        );
        goroutine_of_set.insert(*id, *goids.iter().next().unwrap());
    }
    let goids: BTreeSet<u64> = goroutine_of_set.values().copied().collect();
    assert_eq!(goids.len(), 3, "[{how}] the three sets share a goroutine");

    // The unlabelled goroutine: samples of the program with a goroutine
    // that is none of the three, and no set.
    let unlabelled = samples
        .iter()
        .filter(|(utid, g, s)| {
            processes.get(utid) == Some(&upid) && s.is_none() && !goids.contains(g)
        })
        .count();
    assert!(
        unlabelled >= MIN_SAMPLES_PER_SET,
        "[{how}] {unlabelled} samples of the program without labels"
    );
    println!(
        "go_context [{how}]: {} samples with a goroutine, 3 label sets, {unlabelled} without labels",
        samples.len()
    );
}

#[test]
#[ignore] // Requires root/BPF privileges, a Go toolchain and a C compiler
fn samples_in_a_cgo_call_carry_the_goroutines_labels() {
    let build_dir = TempDir::new().unwrap();
    let Some(program) = build(build_dir.path(), CGO_PROGRAM, false, true) else {
        return;
    };
    let trace = record(&program);
    let sets = label_sets(trace.path());
    let wanted = BTreeMap::from([("worker".to_string(), "cgo".to_string())]);
    let keys: Vec<(i64, u64)> = sets
        .iter()
        .filter(|(_, labels)| **labels == wanted)
        .map(|(key, _)| *key)
        .collect();
    assert_eq!(keys.len(), 1, "the set worker=cgo is in go_labels once");
    let (upid, id) = keys[0];
    // Nearly all the program's time is in C, on the thread's system stack:
    // without m.curg those samples would carry no goroutine at all. Every
    // running sample of the program is counted, those without a set too.
    let all = running_samples_of(trace.path(), upid);
    let of_set = all.iter().filter(|s| **s == Some(id)).count();
    assert!(
        all.len() >= 4 * MIN_SAMPLES_PER_SET,
        "{} samples of the program",
        all.len()
    );
    assert!(
        of_set * 10 >= all.len() * 9,
        "{of_set} of the program's {} samples carry the set worker=cgo",
        all.len()
    );
    println!(
        "go_context [cgo]: {of_set} of the program's {} samples carry its goroutine's labels",
        all.len()
    );
}

#[test]
#[ignore] // Requires root/BPF privileges and a Go toolchain
fn goroutines_and_their_labels_are_in_the_trace() {
    check("built as it is", false);
}

#[test]
#[ignore] // Requires root/BPF privileges and a Go toolchain
fn a_stripped_program_is_read_from_its_code() {
    check("stripped", true);
}

#[test]
#[ignore] // Requires root/BPF privileges and a Go toolchain
fn a_goroutine_that_drives_an_iterator_keeps_its_labels() {
    let build_dir = TempDir::new().unwrap();
    let Some(program) = build(build_dir.path(), PULL_PROGRAM, false, false) else {
        return;
    };
    let (trace, pid) = record_with_pid(&program);
    let (upid, samples) = program_samples(trace.path(), pid);
    let sets = sets_of(trace.path(), upid);
    let wanted = BTreeMap::from([("worker".to_string(), "pull".to_string())]);
    let ids: Vec<u64> = sets
        .iter()
        .filter(|(_, labels)| **labels == wanted)
        .map(|(id, _)| *id)
        .collect();
    assert_eq!(ids.len(), 1, "the set worker=pull is in go_labels once");
    // Both goroutines run under the set, and each switch between them runs on
    // the system stack, where a goroutine's m is for a moment nil.
    let of_set = samples.iter().filter(|(_, s)| *s == Some(ids[0])).count();
    assert!(
        of_set * 10 >= samples.len() * 9,
        "{of_set} of the program's {} samples carry the set worker=pull",
        samples.len()
    );
    println!(
        "go_context [iter.Pull]: {of_set} of the program's {} samples carry its goroutine's labels",
        samples.len()
    );
}

#[test]
#[ignore] // Requires root/BPF privileges, a Go toolchain and a C compiler
fn a_thread_that_c_made_carries_no_goroutine_while_in_c() {
    let build_dir = TempDir::new().unwrap();
    let Some(program) = build(build_dir.path(), C_THREAD_PROGRAM, false, true) else {
        return;
    };
    let (trace, pid) = record_with_pid(&program);
    let (upid, samples) = program_samples(trace.path(), pid);
    let sets = sets_of(trace.path(), upid);
    let ids_of = |worker: &str| -> Vec<u64> {
        sets.iter()
            .filter(|(_, labels)| labels.get("worker").map(String::as_str) == Some(worker))
            .map(|(id, _)| *id)
            .collect()
    };
    let (main_sets, callback_sets) = (ids_of("main"), ids_of("callback"));
    // The main goroutine's time in Go under its labels: the program's
    // goroutines were read.
    let (in_main, others): (Vec<_>, Vec<_>) = samples
        .iter()
        .partition(|(_, s)| s.is_some_and(|id| main_sets.contains(&id)));
    assert!(
        in_main.len() >= MIN_SAMPLES_PER_SET,
        "{} samples carry the set worker=main",
        in_main.len()
    );
    // Nearly all the rest is the C thread's, back in C after its callback: its
    // m still has the callback's goroutine and labels, and Go's profiler gives
    // such a sample neither.
    assert!(
        others.len() >= 4 * MIN_SAMPLES_PER_SET,
        "{} other samples",
        others.len()
    );
    let without = others.iter().filter(|(goid, _)| goid.is_none()).count();
    assert!(
        without * 10 >= others.len() * 9,
        "{without} of the program's {} other samples carry no goroutine",
        others.len()
    );
    let of_callback = others
        .iter()
        .filter(|(_, s)| s.is_some_and(|id| callback_sets.contains(&id)))
        .count();
    assert!(
        of_callback * 10 < others.len(),
        "{of_callback} of the program's {} other samples carry the callback's labels",
        others.len()
    );
    println!(
        "go_context [C thread]: {} samples in Go under its labels; {without} of the {} others carry no goroutine",
        in_main.len(),
        others.len()
    );
}

#[test]
#[ignore] // Requires root/BPF privileges and a Go toolchain
fn an_empty_label_set_is_no_set() {
    let build_dir = TempDir::new().unwrap();
    let Some(program) = build(build_dir.path(), EMPTY_SET_PROGRAM, false, false) else {
        return;
    };
    let (trace, pid) = record_with_pid(&program);
    let (upid, samples) = program_samples(trace.path(), pid);
    let with_goroutine = samples.iter().filter(|(goid, _)| goid.is_some()).count();
    assert!(
        with_goroutine * 10 >= samples.len() * 9,
        "{with_goroutine} of the program's {} samples carry a goroutine",
        samples.len()
    );
    let with_set = samples.iter().filter(|(_, s)| s.is_some()).count();
    assert_eq!(with_set, 0, "samples under an empty set carry a set's id");
    assert!(
        sets_of(trace.path(), upid).is_empty(),
        "rows for an empty set"
    );
    println!(
        "go_context [empty set]: {with_goroutine} of the program's {} samples carry a goroutine, none a label set",
        samples.len()
    );
}
