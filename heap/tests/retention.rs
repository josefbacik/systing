//! The prefix mode through the binary: one snapshot per pid, older dumps
//! deleted, and everything that is not clearly an old dump left alone.

use std::path::Path;
use std::process::Command;

use duckdb::Connection;

const BIN: &str = env!("CARGO_BIN_EXE_systing-heap");

fn dump(bytes: u64) -> String {
    format!("heap_v2/524288\n  t*: 1: {bytes} [0: 0]\n@ 0x10\n  t*: 1: {bytes} [0: 0]\n\nMAPPED_LIBRARIES:\n")
}

fn write(dir: &Path, name: &str, text: &str) {
    std::fs::write(dir.join(name), text).unwrap();
}

/// A dump directory with every case: pid 10 has three dumps, pid 11's newest
/// is truncated, plus files that match the prefix but must never be touched.
fn setup() -> (tempfile::TempDir, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    write(d, "jeprof.10.0.i0.heap", &dump(100));
    write(d, "jeprof.10.1.i1.heap", &dump(200));
    write(d, "jeprof.10.2.f.heap", &dump(300));
    write(d, "jeprof.11.0.i0.heap", &dump(400));
    write(
        d,
        "jeprof.11.1.i1.heap",
        "heap_v2/524288\n  t*: 1: 1 [0: 0]\n@ 0x10\n",
    );
    write(d, "jeprof.heap", &dump(1)); // no pid
    write(d, "jeprof.12.0.notes", "not a dump\n"); // pid, but not a dump
    write(d, "jeprof2.13.0.i0.heap", &dump(1)); // another prefix
    write(d, "other.14.0.i0.heap", &dump(1)); // no prefix match
    std::fs::create_dir(d.join("jeprof.sub")).unwrap();
    write(&d.join("jeprof.sub"), "jeprof.10.0.i0.heap", &dump(1));
    // A symlink with an old dump's name, pointing at a file elsewhere.
    let elsewhere = tempfile::tempdir().unwrap();
    write(elsewhere.path(), "precious.heap", &dump(1));
    std::os::unix::fs::symlink(
        elsewhere.path().join("precious.heap"),
        d.join("jeprof.10.0.i0.heap.link"),
    )
    .unwrap();
    (dir, elsewhere)
}

fn names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    v.sort();
    v
}

fn loaded(db: &Path) -> Vec<(i32, i64, i64)> {
    let conn = Connection::open(db).unwrap();
    conn.prepare(
        "SELECT p.pid, s.seq, h.live_bytes FROM heap_snapshot s
         JOIN process p USING (trace_id, upid)
         JOIN heap_sample h ON h.trace_id = s.trace_id AND h.snapshot_id = s.id
         ORDER BY p.pid, s.seq",
    )
    .unwrap()
    .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
    .unwrap()
    .collect::<Result<_, _>>()
    .unwrap()
}

#[test]
fn latest_per_pid_is_loaded_and_older_dumps_deleted() {
    let (dir, elsewhere) = setup();
    let d = dir.path();
    let db = d.join("out").join("heap.duckdb");
    std::fs::create_dir(d.join("out")).unwrap();
    let before = names(d);

    let out = Command::new(BIN)
        .arg(d.join("jeprof"))
        .arg("-o")
        .arg(&db)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // pid 10: seq 2; pid 11: seq 0, its newer seq 1 does not parse.
    assert_eq!(loaded(&db), vec![(10, 2, 300), (11, 0, 400)]);

    let after = names(d);
    let deleted: Vec<&String> = before.iter().filter(|n| !after.contains(n)).collect();
    assert_eq!(deleted, vec!["jeprof.10.0.i0.heap", "jeprof.10.1.i1.heap"]);
    assert!(elsewhere.path().join("precious.heap").exists());
    assert!(d.join("jeprof.sub/jeprof.10.0.i0.heap").exists());

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("kept, did not parse:") && stderr.contains("jeprof.11.1.i1.heap"),
        "{stderr}"
    );
    assert!(stderr.contains("jeprof.heap (no pid"), "{stderr}");
    assert!(
        stderr.contains("jeprof.12.0.notes (not a jemalloc"),
        "{stderr}"
    );

    // A second run replaces the database and deletes nothing more.
    let out = Command::new(BIN)
        .arg(d.join("jeprof"))
        .arg("-o")
        .arg(&db)
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(loaded(&db), vec![(10, 2, 300), (11, 0, 400)]);
    assert_eq!(names(d), after);
    // No temp files left beside the database.
    assert_eq!(names(&d.join("out")), vec!["heap.duckdb"]);
}

#[test]
fn keep_all_loads_everything_and_deletes_nothing() {
    let (dir, _elsewhere) = setup();
    let d = dir.path();
    let db = d.join("heap.duckdb");
    let before = names(d);
    let out = Command::new(BIN)
        .arg(d.join("jeprof"))
        .args(["--keep-all", "-o"])
        .arg(&db)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        loaded(&db),
        vec![(10, 0, 100), (10, 1, 200), (10, 2, 300), (11, 0, 400)]
    );
    let mut expected = before.clone();
    expected.push("heap.duckdb".into());
    expected.sort();
    assert_eq!(names(d), expected);
}

#[test]
fn dry_run_writes_and_deletes_nothing() {
    let (dir, _elsewhere) = setup();
    let d = dir.path();
    let before = names(d);
    let out = Command::new(BIN)
        .arg(d.join("jeprof"))
        .args(["--dry-run", "-o"])
        .arg(d.join("heap.duckdb"))
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("would delete:") && stdout.contains("jeprof.10.0.i0.heap"),
        "{stdout}"
    );
    assert_eq!(names(d), before);
}

#[test]
fn a_named_file_is_loaded_but_nothing_is_deleted() {
    let (dir, _elsewhere) = setup();
    let d = dir.path();
    let before = names(d);
    let db = d.join("heap.duckdb");
    let out = Command::new(BIN)
        .arg(d.join("jeprof.10.0.i0.heap"))
        .arg("-o")
        .arg(&db)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(loaded(&db), vec![(10, 0, 100)]);
    let mut expected = before;
    expected.push("heap.duckdb".into());
    expected.sort();
    assert_eq!(names(d), expected);
}

#[test]
fn without_sequence_numbers_the_newest_by_mtime_is_kept() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    // pid 30, no sequence number in either name: the newer file is loaded
    // and kept, whatever the names sort to.
    write(d, "jeprof.30.zzz.heap", &dump(100));
    write(d, "jeprof.30.aaa.heap", &dump(200));
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
    std::fs::File::options()
        .write(true)
        .open(d.join("jeprof.30.zzz.heap"))
        .unwrap()
        .set_modified(old)
        .unwrap();
    let db = d.join("heap.duckdb");
    let out = Command::new(BIN)
        .arg(d.join("jeprof"))
        .arg("-o")
        .arg(&db)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let conn = Connection::open(&db).unwrap();
    let bytes: i64 = conn
        .query_row("SELECT live_bytes FROM heap_sample", [], |r| r.get(0))
        .unwrap();
    assert_eq!(bytes, 200);
    assert!(d.join("jeprof.30.aaa.heap").exists());
    assert!(!d.join("jeprof.30.zzz.heap").exists());
}

#[test]
fn a_failed_write_deletes_nothing() {
    let (dir, _elsewhere) = setup();
    let d = dir.path();
    let before = names(d);
    // The output's directory does not exist, so the database cannot be
    // written: no dump may go.
    let out = Command::new(BIN)
        .arg(d.join("jeprof"))
        .arg("-o")
        .arg(d.join("no-such-dir").join("heap.duckdb"))
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert_eq!(names(d), before);
}
