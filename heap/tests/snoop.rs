//! `--snoop` (experimental): the heap profile read from a running process's
//! memory, against real jemalloc. Needs libjemalloc.so.2 and a C compiler; see
//! `common::skip`.
//!
//! Set `SYSTING_HEAP_TEST_JEMALLOC` to the path of another libjemalloc (one
//! built from source, say, that keeps its symbols) to run the same tests on it
//! as well.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Output, Stdio};

use duckdb::Connection;
use systing_heap::root::Root;
use systing_heap::{jemalloc, snoop};

const BIN: &str = env!("CARGO_BIN_EXE_systing-heap");
const TARGET_C: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/snoop_target.c");

/// The jemallocs to run on: the system's, and one named by the environment.
fn libs() -> Vec<PathBuf> {
    let mut libs: Vec<PathBuf> = common::jemalloc().into_iter().collect();
    if let Some(p) = std::env::var_os("SYSTING_HEAP_TEST_JEMALLOC") {
        libs.push(PathBuf::from(p));
    }
    libs
}

fn build_target(dir: &Path) -> Option<PathBuf> {
    let bin = dir.join("snoop_target");
    let built = Command::new(std::env::var("CC").unwrap_or_else(|_| "cc".into()))
        .args(["-O1", "-g", "-fno-omit-frame-pointer", "-pthread", "-o"])
        .arg(&bin)
        .arg(TARGET_C)
        .arg("-ldl")
        .status();
    if built.is_ok_and(|s| s.success()) {
        Some(bin)
    } else {
        common::skip("no C compiler to build the snoop target");
        None
    }
}

/// A running target that has allocated and is parked.
struct Target {
    child: Child,
    stdin: Option<ChildStdin>,
}

impl Target {
    fn start(bin: &Path, lib: Option<&Path>, malloc_conf: Option<&str>, dump: &str) -> Target {
        let mut cmd = Command::new(bin);
        cmd.arg(dump)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        if let Some(lib) = lib {
            cmd.env("LD_PRELOAD", lib);
        }
        if let Some(conf) = malloc_conf {
            cmd.env("MALLOC_CONF", conf);
        }
        let mut child = cmd.spawn().unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line, "READY\n", "the target did not get as far as READY");
        let stdin = child.stdin.take();
        Target { child, stdin }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Let it exit, and wait for it.
    fn stop(mut self) {
        let mut stdin = self.stdin.take().unwrap();
        stdin.write_all(b"x").unwrap();
        drop(stdin);
        assert!(self.child.wait().unwrap().success());
    }
}

impl Drop for Target {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn snoop_cli(pid: u32, out: &Path, cwd: &Path) -> Output {
    Command::new(BIN)
        .args(["--pid", &pid.to_string(), "--snoop", "-o"])
        .arg(out)
        .current_dir(cwd)
        .output()
        .unwrap()
}

fn names_of_stacks(conn: &Connection) -> Vec<(String, i64)> {
    // The frames of each stack, joined leaf-last with " > ", and its estimate.
    conn.prepare(
        "SELECT array_to_string(sf.frame_names, ' > '), h.est_live_bytes
         FROM heap_sample h
         JOIN stack_frames sf ON sf.trace_id = h.trace_id AND sf.id = h.stack_id",
    )
    .unwrap()
    .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
    .unwrap()
    .collect::<Result<_, _>>()
    .unwrap()
}

#[test]
fn the_live_profile_is_read_and_no_file_is_written() {
    for lib in libs() {
        let dir = tempfile::tempdir().unwrap();
        let Some(bin) = build_target(dir.path()) else {
            return;
        };
        // The profile is on and there is a place for dumps, but nothing asks
        // for one: no lg_prof_interval, no prof_final, no prof_gdump, and the
        // target never calls prof.dump. A file appearing would mean jemalloc
        // (or the tool) wrote one.
        let dumps = tempfile::tempdir().unwrap();
        let cwd = tempfile::tempdir().unwrap();
        let out_dir = tempfile::tempdir().unwrap();
        let conf = format!(
            "prof:true,lg_prof_sample:12,prof_prefix:{}/jeprof",
            dumps.path().display()
        );
        let target = Target::start(&bin, Some(&lib), Some(&conf), "-");

        let out = out_dir.path().join("heap.duckdb");
        let run = snoop_cli(target.pid(), &out, cwd.path());
        let stderr = String::from_utf8_lossy(&run.stderr);
        assert!(run.status.success(), "{lib:?}: {stderr}");
        assert!(stderr.contains("experimental"), "{stderr}");

        let conn = Connection::open(&out).unwrap();
        let (n, trigger, format, period): (i64, String, String, i64) = conn
            .query_row(
                "SELECT count(*) OVER (), dump_trigger, format, sample_period FROM heap_snapshot",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(
            (n, trigger.as_str(), format.as_str(), period),
            (1, "snoop", "jemalloc", 4096)
        );

        let stacks = names_of_stacks(&conn);
        assert!(stacks.len() > 50, "{lib:?}: {} stacks", stacks.len());

        // 256 buffers of 64 KiB, all sampled at a 4 KiB period: 16 MiB.
        let big: i64 = stacks
            .iter()
            .filter(|(names, _)| names.contains("snoop_test_big"))
            .map(|(_, bytes)| bytes)
            .sum();
        assert!(
            (16_777_216..=16_800_000).contains(&big),
            "{lib:?}: snoop_test_big holds {big}"
        );
        // Frames are named the way a dump's are, from the binary on disk.
        assert!(
            stacks
                .iter()
                .any(|(n, _)| n.contains("snoop_test_small (snoop_target")),
            "{stacks:?}"
        );
        // Allocated and freed at once: not live, so not in the profile.
        assert!(!stacks.iter().any(|(n, _)| n.contains("snoop_test_freed")));

        target.stop();
        // No file anywhere: not where dumps would go, not where we ran.
        for (what, d) in [
            ("prof_prefix directory", dumps.path()),
            ("working directory", cwd.path()),
        ] {
            let files: Vec<_> = std::fs::read_dir(d).unwrap().collect();
            assert!(files.is_empty(), "{lib:?}: files in the {what}: {files:?}");
        }
    }
}

/// Everything the profile says about each stack, keyed by its addresses.
type Rows = std::collections::BTreeMap<Vec<u64>, (u64, u64, u64, u64)>;

fn rows(samples: &[systing_heap::Sample]) -> Rows {
    samples
        .iter()
        .map(|s| {
            (
                s.addrs.clone(),
                (s.live_objects, s.live_bytes, s.alloc_objects, s.alloc_bytes),
            )
        })
        .collect()
}

/// What jemalloc dumps of a heap and what is read from its memory are the
/// same profile: every stack's four counts are identical, with `prof_accum`
/// on and off. (The heap is not touched between the dump and the read.)
#[test]
fn the_rows_are_the_ones_a_dump_of_the_same_heap_has() {
    for lib in libs() {
        for conf in [
            "prof:true,lg_prof_sample:9,prof_accum:true",
            "prof:true,lg_prof_sample:12,prof_accum:false",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let Some(bin) = build_target(dir.path()) else {
                return;
            };
            let dump = dir.path().join("reference.heap");
            let target = Target::start(&bin, Some(&lib), Some(conf), dump.to_str().unwrap());

            let dumped = jemalloc::read(&dump).unwrap();
            let root = Root::open(Path::new(&format!("/proc/{}/root", target.pid()))).unwrap();
            let (snooped, report) = snoop::read(target.pid(), &root).unwrap();

            let ctx = format!("{lib:?} with {conf}");
            assert_eq!(snooped.sample_period, dumped.sample_period, "{ctx}");
            assert!(
                dumped.samples.len() > 60,
                "{ctx}: {} stacks",
                dumped.samples.len()
            );
            let (want, got) = (rows(&dumped.samples), rows(&snooped.samples));
            assert_eq!(got.len(), want.len(), "{ctx}: {report:?}");
            for (addrs, counts) in &want {
                assert_eq!(got.get(addrs), Some(counts), "{ctx}: stack {addrs:x?}");
            }
            // So the estimates are the same too.
            let est = |s: &systing_heap::Snapshot| -> u64 {
                s.samples
                    .iter()
                    .map(|x| x.estimates(s.sample_period)[0])
                    .sum()
            };
            assert_eq!(est(&snooped), est(&dumped), "{ctx}");
            assert_eq!(snooped.trigger, Some("snoop"));
            // The same memory map, for symbolization.
            assert_eq!(snooped.maps.exe_name(), dumped.maps.exe_name());
            target.stop();
        }
    }
}

/// With `prof_unbias:false` a dump prints raw counts, which systing-heap then
/// scales at each stack's mean object size; a snoop has jemalloc's own
/// per-object estimate. They agree on the heap as a whole.
#[test]
fn without_unbiasing_the_total_estimate_still_agrees_with_a_dump() {
    for lib in libs() {
        let dir = tempfile::tempdir().unwrap();
        let Some(bin) = build_target(dir.path()) else {
            return;
        };
        let dump = dir.path().join("reference.heap");
        let conf = "prof:true,lg_prof_sample:12,prof_unbias:false";
        let target = Target::start(&bin, Some(&lib), Some(conf), dump.to_str().unwrap());

        let dumped = jemalloc::read(&dump).unwrap();
        let root = Root::open(Path::new(&format!("/proc/{}/root", target.pid()))).unwrap();
        let (snooped, _) = snoop::read(target.pid(), &root).unwrap();

        let total = |s: &systing_heap::Snapshot| -> f64 {
            s.samples
                .iter()
                .map(|x| x.estimates(s.sample_period)[0] as f64)
                .sum()
        };
        let (want, got) = (total(&dumped), total(&snooped));
        assert!(
            (got - want).abs() / want < 0.01,
            "{lib:?}: dump {want}, memory {got}"
        );
        target.stop();
    }
}

#[test]
fn a_process_with_profiling_off_is_refused_with_a_reason_and_writes_nothing() {
    let Some(lib) = common::jemalloc() else {
        common::skip("needs libjemalloc.so.2");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let Some(bin) = build_target(dir.path()) else {
        return;
    };
    let target = Target::start(&bin, Some(&lib), None, "-");
    let out = dir.path().join("heap.duckdb");
    let run = snoop_cli(target.pid(), &out, dir.path());
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(!run.status.success());
    assert!(stderr.contains("prof:true"), "{stderr}");
    assert!(!out.exists());
}

#[test]
fn a_process_without_jemalloc_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let Some(bin) = build_target(dir.path()) else {
        return;
    };
    // The same program on the system allocator.
    let target = Target::start(&bin, None, None, "-");
    let out = dir.path().join("heap.duckdb");
    let run = snoop_cli(target.pid(), &out, dir.path());
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(!run.status.success());
    assert!(stderr.contains("no jemalloc"), "{stderr}");
    assert!(!out.exists());
}

#[test]
fn snoop_needs_a_pid_and_takes_no_inputs() {
    let out = |args: &[&str]| {
        let o = Command::new(BIN).args(args).output().unwrap();
        (
            o.status.success(),
            String::from_utf8_lossy(&o.stderr).into_owned(),
        )
    };
    let (ok, err) = out(&["--snoop", "-o", "x.duckdb"]);
    assert!(!ok && err.contains("--pid"), "{err}");
    let (ok, err) = out(&["--snoop", "--pid", "1", "-o", "x.duckdb", "prefix"]);
    assert!(!ok && err.contains("cannot be used with"), "{err}");
    let (ok, err) = out(&["-o", "x.duckdb"]);
    assert!(!ok && err.contains("required"), "{err}");
}
