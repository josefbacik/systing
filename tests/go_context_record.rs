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
//! These need root, a kernel that loads the tracer's BPF object, and a Go
//! 1.26 toolchain (`go`, or `$GO`); without one they say so and pass. To run:
//! ```
//! ./scripts/run-integration-tests.sh go_context_record
//! ```

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use arrow::array::{Array, Int64Array, StringArray, UInt64Array};
use arrow::record_batch::RecordBatch;
use common::workload::SLOW_MACHINE_BUDGET;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use systing::traced_command::spawn_traced_child;
use systing::{systing, Config};
use tempfile::TempDir;

/// How long the program spins, in milliseconds.
const SPIN_MS: &str = "1500";
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

fn go() -> String {
    std::env::var("GO").unwrap_or_else(|_| "go".to_string())
}

/// The program, built into `dir` (stripped with `strip`), or `None` when no
/// Go toolchain answers.
fn build(dir: &Path, strip: bool) -> Option<PathBuf> {
    if Command::new(go()).arg("version").output().is_err() {
        eprintln!("SKIPPED: no Go toolchain answers to `go version` (or to $GO)");
        return None;
    }
    let src = dir.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("main.go"), PROGRAM).unwrap();
    std::fs::write(src.join("go.mod"), "module labels\n\ngo 1.26\n").unwrap();
    let out = dir.join(if strip { "labels_stripped" } else { "labels" });
    let mut command = Command::new(go());
    command
        .current_dir(&src)
        .env("CGO_ENABLED", "0")
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
    let dir = TempDir::new().expect("a directory for the trace");
    let command = vec![
        program.to_str().expect("a utf-8 path").to_string(),
        SPIN_MS.to_string(),
    ];
    let child = spawn_traced_child(&command).expect("the traced child forks");
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
    dir
}

fn check(how: &str, strip: bool) {
    let build_dir = TempDir::new().unwrap();
    let Some(program) = build(build_dir.path(), strip) else {
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
#[ignore] // Requires root/BPF privileges and a Go toolchain
fn goroutines_and_their_labels_are_in_the_trace() {
    check("built as it is", false);
}

#[test]
#[ignore] // Requires root/BPF privileges and a Go toolchain
fn a_stripped_program_is_read_from_its_code() {
    check("stripped", true);
}
