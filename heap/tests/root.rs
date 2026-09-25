//! Reading a container's snapshots from outside it, through the binary:
//! `--root` and `--root-fd` keep the prefix, the binaries and the perf map
//! beneath the root, and take prefix inputs only.

use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use duckdb::Connection;

const BIN: &str = env!("CARGO_BIN_EXE_systing-heap");

const PERF_MAP: &str = "7f75cb8c7500 8 py::outer:/srv/app/alloc.py\n";

/// A dump with one stack in each of two mapped files.
fn dump(bytes: u64) -> String {
    format!(
        "heap_v2/524288\n  t*: 2: {bytes} [0: 0]\n\
         @ 0x400010\n  t*: 1: {bytes} [0: 0]\n\
         @ 0x500010\n  t*: 1: {bytes} [0: 0]\n\
         \nMAPPED_LIBRARIES:\n\
         00400000-00401000 r-xp 00000000 00:00 0 /lib/x.so\n\
         00500000-00501000 r-xp 00000000 00:00 0 /lib/y.so\n"
    )
}

/// A container's root as seen from outside it, and a directory outside it.
/// Process `pid` wrote two dumps under `/heap-dumps/jeprof` and its perf map
/// in `/tmp`. `/lib/x.so` is an absolute symlink to a file that exists outside
/// the root and not beneath it; `/lib/y.so` is a file beneath it.
fn container(pid: u32) -> (tempfile::TempDir, tempfile::TempDir) {
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("x.so"), "outside").unwrap();
    let root = tempfile::tempdir().unwrap();
    let r = root.path();
    for dir in ["heap-dumps", "lib", "tmp"] {
        std::fs::create_dir(r.join(dir)).unwrap();
    }
    let dumps = r.join("heap-dumps");
    std::fs::write(dumps.join(format!("jeprof.{pid}.0.i0.heap")), dump(100)).unwrap();
    std::fs::write(dumps.join(format!("jeprof.{pid}.1.i1.heap")), dump(200)).unwrap();
    std::os::unix::fs::symlink(outside.path().join("x.so"), r.join("lib/x.so")).unwrap();
    std::fs::write(r.join("lib/y.so"), "inside").unwrap();
    std::fs::write(r.join(format!("tmp/perf-{pid}.map")), PERF_MAP).unwrap();
    (root, outside)
}

fn run(args: &[&str], db: &Path, input: &str) -> Output {
    Command::new(BIN)
        .args(args)
        .arg("-o")
        .arg(db)
        .arg(input)
        .output()
        .unwrap()
}

fn loaded(db: &Path) -> Vec<(i32, i64)> {
    let conn = Connection::open(db).unwrap();
    conn.prepare(
        "SELECT p.pid, s.seq FROM heap_snapshot s
         JOIN process p USING (trace_id, upid)
         ORDER BY p.pid, s.seq",
    )
    .unwrap()
    .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
    .unwrap()
    .collect::<Result<_, _>>()
    .unwrap()
}

/// What a run beneath the container's root must show, however the root was
/// given.
fn assert_read_beneath_the_root(out: &Output, db: &Path, root: &Path) {
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert_eq!(loaded(db), vec![(123, 1)]);
    assert!(root.join("heap-dumps/jeprof.123.0.i0.heap").exists());
    assert!(root.join("heap-dumps/jeprof.123.1.i1.heap").exists());
    // The link's target exists outside the root only, so beneath the root
    // there is no such file; the file beneath the root was found.
    assert!(
        stderr.contains("/lib/x.so is not on this machine"),
        "{stderr}"
    );
    assert!(!stderr.contains("/lib/y.so is not"), "{stderr}");
    assert!(
        stderr.contains("pid 123: Python frames named from /tmp/perf-123.map"),
        "{stderr}"
    );
}

#[test]
fn a_root_keeps_the_prefix_the_binaries_and_the_perf_map_beneath_it() {
    let (root, _outside) = container(123);
    let out_dir = tempfile::tempdir().unwrap();
    let db = out_dir.path().join("heap.duckdb");
    let out = run(
        &["--root", root.path().to_str().unwrap(), "--latest-only"],
        &db,
        "/heap-dumps/jeprof",
    );
    assert_read_beneath_the_root(&out, &db, root.path());
}

#[test]
fn a_root_can_be_an_inherited_descriptor() {
    let (root, _outside) = container(123);
    let out_dir = tempfile::tempdir().unwrap();
    let db = out_dir.path().join("heap.duckdb");

    let dir = std::fs::File::open(root.path()).unwrap();
    // SAFETY: a descriptor this test owns; without close-on-exec the child
    // inherits it under the same number.
    assert_eq!(unsafe { libc::fcntl(dir.as_raw_fd(), libc::F_SETFD, 0) }, 0);
    let number = dir.as_raw_fd().to_string();
    let out = run(
        &["--root-fd", number.as_str(), "--latest-only"],
        &db,
        "/heap-dumps/jeprof",
    );
    assert_read_beneath_the_root(&out, &db, root.path());

    let file = std::fs::File::open(root.path().join("lib/y.so")).unwrap();
    // SAFETY: as above.
    assert_eq!(
        unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, 0) },
        0
    );
    let number = file.as_raw_fd().to_string();
    let out = run(&["--root-fd", number.as_str()], &db, "/heap-dumps/jeprof");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not a directory"), "{stderr}");
}

#[test]
fn the_readers_own_tmp_is_no_place_for_a_map_beneath_a_root() {
    // This process's id names no other process's map in /tmp.
    let pid = std::process::id();
    let (root, _outside) = container(pid);
    std::fs::remove_file(root.path().join(format!("tmp/perf-{pid}.map"))).unwrap();
    let planted = PathBuf::from(format!("/tmp/perf-{pid}.map"));
    std::fs::write(&planted, PERF_MAP).unwrap();
    let out_dir = tempfile::tempdir().unwrap();
    let db = out_dir.path().join("heap.duckdb");

    let beneath = run(
        &["--root", root.path().to_str().unwrap(), "--latest-only"],
        &db,
        "/heap-dumps/jeprof",
    );
    // The control: read as the reader's own files, the same dumps find it.
    let prefix = root.path().join("heap-dumps/jeprof");
    let direct = run(&["--latest-only"], &db, prefix.to_str().unwrap());
    std::fs::remove_file(&planted).unwrap();

    let stderr = String::from_utf8_lossy(&beneath.stderr);
    assert!(beneath.status.success(), "{stderr}");
    assert!(!stderr.contains("Python frames named from"), "{stderr}");
    let stderr = String::from_utf8_lossy(&direct.stderr);
    assert!(direct.status.success(), "{stderr}");
    assert!(
        stderr.contains(&format!(
            "pid {pid}: Python frames named from /tmp/perf-{pid}.map"
        )),
        "{stderr}"
    );
}

#[test]
fn a_file_or_directory_input_is_refused_beneath_a_root() {
    let (root, _outside) = container(123);
    let out_dir = tempfile::tempdir().unwrap();
    let db = out_dir.path().join("heap.duckdb");
    for input in ["/heap-dumps/jeprof.123.0.i0.heap", "/heap-dumps"] {
        let out = run(&["--root", root.path().to_str().unwrap()], &db, input);
        assert!(!out.status.success(), "{input}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("must be a jemalloc prof_prefix"),
            "{input}: {stderr}"
        );
    }
    assert!(!db.exists());
    assert!(root.path().join("heap-dumps/jeprof.123.0.i0.heap").exists());
}
