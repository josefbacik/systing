//! Reading a container's snapshots from outside it, through the binary:
//! `--pid` and `--root-fd` keep the prefix, the binaries, the perf map and the
//! code map beneath the root, and take prefix inputs only.

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

/// `path` opened so that a child inherits it under the same number; the
/// file is returned to keep the descriptor open.
fn inheritable(path: &Path) -> (std::fs::File, String) {
    let file = std::fs::File::open(path).unwrap();
    // SAFETY: a descriptor this test owns; without close-on-exec the child
    // inherits it under the same number.
    assert_eq!(
        unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, 0) },
        0
    );
    let number = file.as_raw_fd().to_string();
    (file, number)
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
    let (_dir, number) = inheritable(root.path());
    let out = run(
        &["--root-fd", number.as_str(), "--latest-only"],
        &db,
        "/heap-dumps/jeprof",
    );
    assert_read_beneath_the_root(&out, &db, root.path());
}

#[test]
fn a_descriptor_that_is_no_directory_is_refused() {
    let (root, _outside) = container(123);
    let out_dir = tempfile::tempdir().unwrap();
    let db = out_dir.path().join("heap.duckdb");
    let (_file, number) = inheritable(&root.path().join("lib/y.so"));
    let out = run(&["--root-fd", number.as_str()], &db, "/heap-dumps/jeprof");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not a directory"), "{stderr}");
    assert!(!db.exists());
}

#[test]
fn a_pid_names_the_root_of_that_process() {
    // This test's own root is the machine's, so the made-up container is
    // reached beneath it by its full path.
    let (root, _outside) = container(123);
    let out_dir = tempfile::tempdir().unwrap();
    let db = out_dir.path().join("heap.duckdb");
    let pid = std::process::id().to_string();

    let prefix = root.path().join("heap-dumps/jeprof");
    let out = run(
        &["--pid", pid.as_str(), "--latest-only"],
        &db,
        prefix.to_str().unwrap(),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert_eq!(loaded(&db), vec![(123, 1)]);
    assert!(root.path().join("heap-dumps/jeprof.123.0.i0.heap").exists());

    // The flag took a root: beneath one, only a prefix is an input.
    let dir = root.path().join("heap-dumps");
    let out = run(&["--pid", pid.as_str()], &db, dir.to_str().unwrap());
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("must be a jemalloc prof_prefix"),
        "{stderr}"
    );
}

#[test]
fn a_pid_that_names_no_process_is_refused() {
    let out_dir = tempfile::tempdir().unwrap();
    let db = out_dir.path().join("heap.duckdb");
    // Above any id the kernel gives out.
    let out = run(&["--pid", "4294967295"], &db, "/heap-dumps/jeprof");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("opening the root /proc/4294967295/root"),
        "{stderr}"
    );
    assert!(!db.exists());
}

#[test]
fn a_pid_and_a_descriptor_are_not_both_taken() {
    let (root, _outside) = container(123);
    let out_dir = tempfile::tempdir().unwrap();
    let db = out_dir.path().join("heap.duckdb");
    let pid = std::process::id().to_string();
    let (_dir, number) = inheritable(root.path());
    let out = run(
        &["--pid", pid.as_str(), "--root-fd", number.as_str()],
        &db,
        "/heap-dumps/jeprof",
    );
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("cannot be used with"), "{stderr}");
    assert!(!db.exists());
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
    let (_dir, number) = inheritable(root.path());

    let beneath = run(
        &["--root-fd", number.as_str(), "--latest-only"],
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
    let (_dir, number) = inheritable(root.path());
    for input in ["/heap-dumps/jeprof.123.0.i0.heap", "/heap-dumps"] {
        let out = run(&["--root-fd", number.as_str()], &db, input);
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

/// A dump of a process that ran the hooks' "python" backtrace: one stack
/// with a Python frame in it, and the mapping that names the process's code
/// map.
const PYTHON_DUMP: &str = "heap_v2/524288\n  t*: 1: 64 [0: 0]\n\
    @ 0x30008 0x5059000001000000 0x5059000000000000\n  t*: 1: 64 [0: 0]\n\
    \nMAPPED_LIBRARIES:\n\
    00030000-00031000 rw-p 00000000 00:00 0 \n\
    7fe5b7d00000-7fe5b7d01000 r--p 00000000 00:01 94950 /memfd:systing-pycode-dead0a9f94b985ac (deleted)\n";

const CODE_MAP: &str = "# systing-pycode 1 token=dead0a9f94b985ac pid=77 python=3.13\n\
    1 8 1:6c65616b 1:2f7372762f6170702f776f726b2e7079 8000dc0d1290318e58\n";

#[test]
fn a_code_map_is_looked_for_beneath_the_root() {
    let name = "pycode-77-dead0a9f94b985ac.map";
    // Beside the dump, where the hook writes it; then in --perf-map-dir,
    // which comes first.
    for (place, args) in [
        ("heap-dumps", vec![]),
        ("maps", vec!["--perf-map-dir", "/maps"]),
    ] {
        let root = tempfile::tempdir().unwrap();
        for dir in ["heap-dumps", "maps"] {
            std::fs::create_dir(root.path().join(dir)).unwrap();
        }
        std::fs::write(
            root.path().join("heap-dumps/jeprof.77.0.m0.heap"),
            PYTHON_DUMP,
        )
        .unwrap();
        std::fs::write(root.path().join(place).join(name), CODE_MAP).unwrap();
        let out_dir = tempfile::tempdir().unwrap();
        let db = out_dir.path().join("heap.duckdb");
        let (_dir, number) = inheritable(root.path());
        let mut all = vec!["--root-fd", number.as_str(), "--latest-only"];
        all.extend(args);
        let out = run(&all, &db, "/heap-dumps/jeprof");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{place}: {stderr}");
        assert!(
            stderr.contains(&format!("pid 77: Python frames named from /{place}/{name}")),
            "{place}: {stderr}"
        );
        assert!(!stderr.contains("no code map names"), "{place}: {stderr}");
        let conn = Connection::open(&db).unwrap();
        let named: i64 = conn
            .query_row(
                "SELECT count(*) FROM frame WHERE name = 'leak (python) [work.py:8]'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(named, 1, "{place}");
    }
}

#[test]
fn a_code_map_is_looked_for_beneath_the_root_a_pid_names() {
    // This test's own root is the machine's, so the dumps' folder is reached
    // beneath it by its full path.
    let name = "pycode-77-dead0a9f94b985ac.map";
    let pid = std::process::id().to_string();
    for place in ["heap-dumps", "maps"] {
        let dir = tempfile::tempdir().unwrap();
        for sub in ["heap-dumps", "maps"] {
            std::fs::create_dir(dir.path().join(sub)).unwrap();
        }
        std::fs::write(
            dir.path().join("heap-dumps/jeprof.77.0.m0.heap"),
            PYTHON_DUMP,
        )
        .unwrap();
        let map = dir.path().join(place).join(name);
        std::fs::write(&map, CODE_MAP).unwrap();
        let maps = dir.path().join("maps");
        let mut args = vec!["--pid", pid.as_str(), "--latest-only"];
        if place == "maps" {
            args.extend(["--perf-map-dir", maps.to_str().unwrap()]);
        }
        let out_dir = tempfile::tempdir().unwrap();
        let db = out_dir.path().join("heap.duckdb");
        let prefix = dir.path().join("heap-dumps/jeprof");
        let out = run(&args, &db, prefix.to_str().unwrap());
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{place}: {stderr}");
        assert!(
            stderr.contains(&format!(
                "pid 77: Python frames named from {}",
                map.display()
            )),
            "{place}: {stderr}"
        );
        assert!(!stderr.contains("no code map names"), "{place}: {stderr}");
        let conn = Connection::open(&db).unwrap();
        let named: i64 = conn
            .query_row(
                "SELECT count(*) FROM frame WHERE name = 'leak (python) [work.py:8]'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(named, 1, "{place}");
    }
}

#[test]
fn the_readers_own_files_are_no_place_for_a_code_map_beneath_a_root() {
    // The map is where the dump says, on the reader's side of the root and
    // not beneath it: it names nothing.
    let outside = tempfile::tempdir().unwrap();
    let dumps = outside.path().join("heap-dumps");
    std::fs::create_dir(&dumps).unwrap();
    std::fs::write(dumps.join("pycode-77-dead0a9f94b985ac.map"), CODE_MAP).unwrap();
    let root = tempfile::tempdir().unwrap();
    let inside = root.path().join(dumps.strip_prefix("/").unwrap());
    std::fs::create_dir_all(&inside).unwrap();
    std::fs::write(inside.join("jeprof.77.0.m0.heap"), PYTHON_DUMP).unwrap();
    let out_dir = tempfile::tempdir().unwrap();
    let db = out_dir.path().join("heap.duckdb");
    let (_dir, number) = inheritable(root.path());
    let out = run(
        &["--root-fd", number.as_str(), "--latest-only"],
        &db,
        dumps.join("jeprof").to_str().unwrap(),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(!stderr.contains("Python frames named from"), "{stderr}");
    assert!(stderr.contains("no code map names"), "{stderr}");
}
