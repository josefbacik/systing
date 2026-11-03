//! End-to-end tests of the python-function-trace recorder: Python processes run
//! `tests/python_function_trace/workload.py`, which makes a known number of calls
//! of each kind, under one capture, and the `python_function_slice` table in the
//! DuckDB database must hold each of them, per process.
//!
//! They need root and a CPython 3.12 to 3.14 built with computed gotos. To run:
//! ```text
//! ./scripts/run-integration-tests.sh python_function_trace
//! ```

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

const WORKLOAD: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/python_function_trace/workload.py"
);

/// A Python this recorder can trace, by its version in the name; a machine
/// without one skips, and CI (`CI` set) fails, as pystacks' own tests have it.
fn pythons() -> Vec<String> {
    let mut found = Vec::new();
    for minor in [12, 13, 14] {
        let name = format!("python3.{minor}");
        let works = Command::new(&name)
            .args(["-c", "import asyncio"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if works {
            found.push(name);
        }
    }
    assert!(
        !found.is_empty() || std::env::var_os("CI").is_none(),
        "no Python 3.12 to 3.14 on PATH"
    );
    found
}

struct Workload {
    child: Child,
}

impl Workload {
    /// Started, and waiting for `go`.
    fn start(python: &str, go: &Path) -> Self {
        let mut child = Command::new(python)
            .arg(WORKLOAD)
            .arg(go)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("Failed to start the workload");
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .expect("the workload's output");
        assert_eq!(line.trim(), "ready");
        Self { child }
    }
}

impl Drop for Workload {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A capture of `args`, which calls `on_probes` with the count each time the
/// recorder says a process has its probes in. Returns the database it was
/// converted into, and what it said.
fn capture_with(
    args: &[String],
    mut on_probes: impl FnMut(usize),
    out: &TempDir,
) -> (duckdb::Connection, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_systing"))
        .args(["--only-recorder", "python-function-trace", "--parquet-only"])
        .arg("--output-dir")
        .arg(out.path())
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to run systing");
    let lines = BufReader::new(child.stderr.take().unwrap()).lines();
    let mut stderr = String::new();
    let mut in_place = 0;
    for line in lines {
        let line = line.expect("systing's stderr");
        stderr.push_str(&line);
        stderr.push('\n');
        if line.starts_with("python-function-trace: process ") {
            in_place += 1;
            on_probes(in_place);
        }
    }
    let status = child.wait().expect("systing");
    assert!(status.success(), "systing failed:\n{stderr}");
    let db = out.path().join("trace.duckdb");
    systing::duckdb::parquet_to_duckdb(out.path(), &db, "t").expect("the import");
    (duckdb::Connection::open(&db).expect("the database"), stderr)
}

/// [`capture_with`], calling `at_ready` once `processes` have their probes in.
fn capture(
    args: &[String],
    processes: usize,
    at_ready: impl FnOnce(),
    out: &TempDir,
) -> (duckdb::Connection, String) {
    let mut at_ready = Some(at_ready);
    if processes == 0 {
        at_ready.take().unwrap()();
    }
    let result = capture_with(
        args,
        |in_place| {
            if in_place == processes {
                if let Some(at_ready) = at_ready.take() {
                    at_ready();
                }
            }
        },
        out,
    );
    assert!(at_ready.is_none(), "not {processes} traced:\n{}", result.1);
    result
}

/// (function, how it ended) -> slices, of the workload's own functions, in one
/// process.
fn counts(conn: &duckdb::Connection, pid: Option<i64>) -> BTreeMap<(String, String), i64> {
    let mut statement = conn
        .prepare(
            "SELECT s.function, s.end_kind, count(*) FROM python_function_slice s \
             JOIN thread t ON t.utid = s.utid JOIN process p ON p.upid = t.upid \
             WHERE s.file LIKE '%workload.py' AND (? IS NULL OR p.pid = ?) GROUP BY 1, 2",
        )
        .unwrap();
    statement
        .query_map(duckdb::params![pid, pid], |row| {
            Ok((
                (
                    row.get::<_, String>(0)?
                        .rsplit(':')
                        .next()
                        .unwrap()
                        .to_string(),
                    row.get::<_, String>(1)?,
                ),
                row.get::<_, i64>(2)?,
            ))
        })
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

/// What the workload does, as (function, how it ended) -> slices.
fn expected() -> BTreeMap<(String, String), i64> {
    [
        ("leaf", "return", 713),
        ("mid", "return", 350),
        ("raiser", "unwound", 40),
        ("catcher", "return", 10),
        ("gen", "yield", 30),
        ("gen", "return", 1),
        ("K.__init__", "return", 25),
        ("K.method", "return", 20),
        ("<genexpr>", "yield", 20),
        ("<genexpr>", "return", 1),
        ("K.__getattr__", "unwound", 5),
        ("swallowed", "return", 5),
        ("via_c", "return", 1),
        ("co", "yield", 3),
        ("co", "return", 3),
        ("amain", "yield", 1),
        ("amain", "return", 1),
        ("worker", "return", 3),
        ("K", "return", 1),
    ]
    .into_iter()
    .map(|(f, e, n)| ((f.to_string(), e.to_string()), n))
    .collect()
}

/// On every thread a slice lies inside the slices around it, and its depth is
/// how many there are. Returns the slices that do not.
fn badly_nested(conn: &duckdb::Connection) -> usize {
    let mut statement = conn
        .prepare(
            "SELECT utid, ts, ts + dur, depth FROM python_function_slice ORDER BY utid, ts, depth",
        )
        .unwrap();
    let rows: Vec<(i64, i64, i64, i32)> = statement
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let mut bad = 0;
    let mut stack: Vec<(i64, i64)> = Vec::new();
    let mut thread = None;
    for (utid, start, end, depth) in rows {
        if thread != Some(utid) {
            thread = Some(utid);
            stack.clear();
        }
        while stack.last().is_some_and(|top| start >= top.1) {
            stack.pop();
        }
        if depth as usize != stack.len() || stack.last().is_some_and(|top| end > top.1) {
            bad += 1;
        }
        stack.push((start, end));
    }
    bad
}

#[allow(clippy::type_complexity)]
fn sysinfo(conn: &duckdb::Connection) -> (i64, i64, bool, Option<String>) {
    conn.query_row(
        "SELECT python_function_processes, python_function_events, \
         python_function_cap_reached, python_function_notes FROM sysinfo",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )
    .expect("the recorder's row in sysinfo")
}

fn touch(path: &PathBuf) {
    std::fs::write(path, b"go").expect("the go file");
}

fn pid_args(pids: &[u32]) -> Vec<String> {
    pids.iter()
        .flat_map(|pid| ["--pid".to_string(), pid.to_string()])
        .collect()
}

#[test]
#[ignore = "needs root and a CPython 3.12 to 3.14"]
fn every_call_of_every_process_is_a_slice() {
    for python in pythons() {
        let dir = TempDir::new().unwrap();
        let go = dir.path().join("go");
        // Three processes, more than one GIL, on one interpreter file.
        let workloads: Vec<Workload> = (0..3).map(|_| Workload::start(&python, &go)).collect();
        let bystander = Workload::start(&python, &go);
        let pids: Vec<u32> = workloads.iter().map(|w| w.child.id()).collect();
        let mut args = pid_args(&pids);
        args.extend(["--duration".to_string(), "4".to_string()]);
        let out = TempDir::new().unwrap();
        let (conn, stderr) = capture(&args, 3, || touch(&go), &out);

        for pid in &pids {
            assert_eq!(
                counts(&conn, Some(i64::from(*pid))),
                expected(),
                "{python}, process {pid}:\n{stderr}"
            );
        }
        let bystander_rows = counts(&conn, Some(i64::from(bystander.child.id())));
        assert!(bystander_rows.is_empty(), "{python}: {bystander_rows:?}");
        assert_eq!(badly_nested(&conn), 0, "{python}");

        // Each worker is a thread of its own, none the main thread.
        let threads: i64 = conn
            .query_row(
                "SELECT count(DISTINCT s.utid) FROM python_function_slice s \
                 WHERE s.function LIKE '%worker'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(threads, 9, "{python}");

        let (traced, events, cap_reached, _) = sysinfo(&conn);
        assert_eq!((traced, cap_reached), (3, false), "{python}");
        assert!(events > 0, "{python}");
        println!("{python}: {events} events from 3 processes, every call accounted for");
    }
}

#[test]
#[ignore = "needs root and a CPython 3.12 to 3.14"]
fn a_process_forked_from_a_target_is_traced_too() {
    for python in pythons() {
        let dir = TempDir::new().unwrap();
        let (fork_now, go) = (dir.path().join("fork_now"), dir.path().join("go"));
        let child = Command::new(&python)
            .arg(WORKLOAD)
            .arg(&go)
            .arg("fork")
            .arg(&fork_now)
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let child = Workload { child };
        std::thread::sleep(Duration::from_millis(500));
        let mut args = pid_args(&[child.child.id()]);
        args.extend(["--duration".to_string(), "5".to_string()]);
        let out = TempDir::new().unwrap();
        let (conn, stderr) = capture_with(
            &args,
            |in_place| match in_place {
                // The parent's probes, so the capture knows of the fork.
                1 => touch(&fork_now),
                2 => touch(&go),
                _ => {}
            },
            &out,
        );
        drop(child);

        let total: BTreeMap<_, _> = expected().into_iter().map(|(k, v)| (k, v * 2)).collect();
        assert_eq!(counts(&conn, None), total, "{python}:\n{stderr}");
        assert_eq!(sysinfo(&conn).0, 2, "{python}");
    }
}

#[test]
#[ignore = "needs root and a CPython 3.12 to 3.14"]
fn the_slice_cap_takes_the_probes_out_and_says_so() {
    for python in pythons() {
        let dir = TempDir::new().unwrap();
        let spin = dir.path().join("spin.py");
        std::fs::write(
            &spin,
            "import time\ndef f():\n    return 1\nend = time.monotonic() + 30\n\
             print('ready', flush=True)\nwhile time.monotonic() < end:\n    f()\n",
        )
        .unwrap();
        let mut child = Command::new(&python)
            .arg(&spin)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let mut args = pid_args(&[child.id()]);
        args.extend(
            ["--duration", "3", "--python-function-max-slices", "1000"].map(str::to_string),
        );
        let out = TempDir::new().unwrap();
        let (conn, _) = capture(&args, 1, || {}, &out);
        let _ = child.kill();
        let _ = child.wait();

        let (_, _, cap_reached, _) = sysinfo(&conn);
        assert!(cap_reached, "{python}");
        let (slices, span): (i64, i64) = conn
            .query_row(
                "SELECT count(*), max(ts + dur) - min(ts) FROM python_function_slice",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        // Long before the 3 s of the capture, with the slices begun by then.
        assert!((900..=1000).contains(&slices), "{python}: {slices}");
        assert!(
            Duration::from_nanos(span as u64) < Duration::from_secs(1),
            "{python}: {span} ns"
        );
    }
}

#[test]
#[ignore = "needs root"]
fn a_process_that_is_not_python_is_left_alone_and_a_capture_needs_a_target() {
    let mut sleeper = Command::new("sleep").arg("30").spawn().unwrap();
    let started = Instant::now();
    let mut args = pid_args(&[sleeper.id()]);
    args.extend(["--duration".to_string(), "1".to_string()]);
    let out = TempDir::new().unwrap();
    let (conn, _) = capture(&args, 0, || {}, &out);
    let _ = sleeper.kill();
    let _ = sleeper.wait();
    let (traced, _, _, notes) = sysinfo(&conn);
    assert_eq!(traced, 0);
    let notes = notes.expect("a named process that was not traced has a note");
    assert!(notes.contains("not a Python"), "{notes}");
    assert!(started.elapsed() < Duration::from_secs(20));

    // A pid that is not there says so too, and the capture still ends well.
    let mut args = pid_args(&[u32::MAX / 2]);
    args.extend(["--duration".to_string(), "1".to_string()]);
    let out = TempDir::new().unwrap();
    let (conn, _) = capture(&args, 0, || {}, &out);
    let notes = sysinfo(&conn).3.expect("a note");
    assert!(notes.contains("not there"), "{notes}");

    let refused = Command::new(env!("CARGO_BIN_EXE_systing"))
        .args([
            "--only-recorder",
            "python-function-trace",
            "--duration",
            "1",
        ])
        .output()
        .unwrap();
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("needs a target"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
}

#[test]
#[ignore = "needs root and a CPython 3.12 to 3.14"]
fn an_exec_ends_its_frames_and_the_new_image_is_traced_once() {
    for python in pythons() {
        let dir = TempDir::new().unwrap();
        let (go, again) = (dir.path().join("go"), dir.path().join("again"));
        let mut command = Command::new(&python);
        command
            .arg(WORKLOAD)
            .arg(&go)
            .arg("exec")
            .arg(&again)
            .stdout(Stdio::null());
        let child = Workload {
            child: command.spawn().unwrap(),
        };
        // Until its image is a Python's with the calls ahead of it.
        std::thread::sleep(Duration::from_millis(500));
        let mut args = pid_args(&[child.child.id()]);
        args.extend(["--duration".to_string(), "6".to_string()]);
        let out = TempDir::new().unwrap();
        let (conn, stderr) = capture_with(
            &args,
            |in_place| match in_place {
                1 => touch(&go),
                // The probes of the new image: the same links, the config anew.
                2 => touch(&again),
                _ => {}
            },
            &out,
        );
        drop(child);

        let total: BTreeMap<_, _> = expected().into_iter().map(|(k, v)| (k, v * 2)).collect();
        let mut got = counts(&conn, None);
        // The new image's own <module> shows when pystacks has it registered
        // before that runs, which is a race the workload does not depend on.
        got.remove(&("<module>".to_string(), "return".to_string()));
        assert_eq!(got, total, "{python}:\n{stderr}");
        assert_eq!(badly_nested(&conn), 0, "{python}");
        assert_eq!(sysinfo(&conn).0, 1, "{python}: one process, not two");
    }
}

#[test]
#[ignore = "needs root and a CPython 3.12 to 3.14"]
fn a_traced_command_is_traced() {
    for python in pythons() {
        let dir = TempDir::new().unwrap();
        let go = dir.path().join("go");
        let args: Vec<String> = ["--duration", "4", "--"]
            .into_iter()
            .map(str::to_string)
            .chain([
                python.clone(),
                WORKLOAD.to_string(),
                go.display().to_string(),
            ])
            .collect();
        let out = TempDir::new().unwrap();
        let (conn, stderr) = capture(&args, 1, || touch(&go), &out);
        assert_eq!(counts(&conn, None), expected(), "{python}:\n{stderr}");
    }
}

#[test]
#[ignore = "needs root, cgroup v2 and a CPython 3.12 to 3.14"]
fn a_cgroup_target_takes_its_processes_and_leaves_the_rest() {
    let mounts = std::fs::read_to_string("/proc/mounts").unwrap();
    let Some(root) = mounts
        .lines()
        .find(|l| l.split(' ').nth(2) == Some("cgroup2"))
        .and_then(|l| l.split(' ').nth(1))
        .map(PathBuf::from)
    else {
        eprintln!("skipping: no cgroup v2 mount");
        return;
    };
    for python in pythons() {
        let dir = TempDir::new().unwrap();
        let go = dir.path().join("go");
        let cgroup = root.join(format!("pyft_test_{}", std::process::id()));
        std::fs::create_dir(&cgroup).expect("a cgroup of the test's own");
        let inside = Workload::start(&python, &go);
        let outside = Workload::start(&python, &go);
        let joins_later = Workload::start(&python, &go);
        std::fs::write(cgroup.join("cgroup.procs"), inside.child.id().to_string())
            .expect("into the cgroup");
        let (joining, joined_id) = (cgroup.join("cgroup.procs"), joins_later.child.id());
        let args: Vec<String> = vec![
            "--cgroup".to_string(),
            cgroup.display().to_string(),
            "--duration".to_string(),
            "5".to_string(),
        ];
        let out = TempDir::new().unwrap();
        // No event says a process has moved in: the recorder finds it by looking.
        let (conn, stderr) = capture_with(
            &args,
            |in_place| match in_place {
                1 => std::fs::write(&joining, joined_id.to_string()).expect("into the cgroup"),
                2 => touch(&go),
                _ => {}
            },
            &out,
        );
        let outside_id = i64::from(outside.child.id());
        let inside_id = i64::from(inside.child.id());
        let joined = i64::from(joined_id);
        drop((inside, outside, joins_later));
        let _ = std::fs::remove_dir(&cgroup);

        assert_eq!(
            counts(&conn, Some(inside_id)),
            expected(),
            "{python}:\n{stderr}"
        );
        assert_eq!(
            counts(&conn, Some(joined)),
            expected(),
            "{python}:\n{stderr}"
        );
        assert!(counts(&conn, Some(outside_id)).is_empty(), "{python}");
    }
}

#[test]
#[ignore = "needs root and a CPython 3.12 to 3.14"]
fn a_recorder_that_cannot_run_leaves_the_capture_running_and_says_why() {
    let mut sleeper = Command::new("sleep").arg("30").spawn().unwrap();
    let out = TempDir::new().unwrap();
    let status = Command::new(env!("CARGO_BIN_EXE_systing"))
        .args([
            "--only-recorder",
            "python-function-trace",
            "--add-recorder",
            "sched",
        ])
        .args(["--parquet-only", "--duration", "1", "--output-dir"])
        .arg(out.path())
        .args(pid_args(&[sleeper.id()]))
        .env("SYSTING_PYTHON_FUNCTION_TRACE_REFUSE", "this test")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("systing");
    let _ = sleeper.kill();
    let _ = sleeper.wait();
    assert!(status.success());
    let db = out.path().join("trace.duckdb");
    systing::duckdb::parquet_to_duckdb(out.path(), &db, "t").expect("the import");
    let conn = duckdb::Connection::open(&db).unwrap();
    let notes = sysinfo(&conn).3.expect("a note");
    assert!(notes.contains("off for this capture: this test"), "{notes}");
}
