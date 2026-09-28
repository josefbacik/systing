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
use systing_heap::{jemalloc, snoop};

const BIN: &str = env!("CARGO_BIN_EXE_systing-heap");
const TARGET_C: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/snoop_target.c");

/// The jemallocs to run on: the system's, and one named by the environment.
fn libs() -> Vec<PathBuf> {
    let mut libs: Vec<PathBuf> = common::jemalloc().into_iter().collect();
    if let Some(p) = std::env::var_os("SYSTING_HEAP_TEST_JEMALLOC") {
        libs.push(PathBuf::from(p));
    }
    // With none, the loops over them run nothing: say so (or, in CI, fail).
    if libs.is_empty() {
        common::skip("needs libjemalloc.so.2");
    }
    libs
}

fn build_target(dir: &Path) -> Option<PathBuf> {
    build_target_as(dir, "snoop_target", &[])
}

/// The target, named `name`, built with more compiler arguments.
fn build_target_as(dir: &Path, name: &str, more: &[String]) -> Option<PathBuf> {
    let bin = dir.join(name);
    let built = Command::new(std::env::var("CC").unwrap_or_else(|_| "cc".into()))
        .args(["-O1", "-g", "-fno-omit-frame-pointer", "-pthread", "-o"])
        .arg(&bin)
        .args(more)
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
        match malloc_conf {
            Some(conf) => cmd.env("MALLOC_CONF", conf),
            None => cmd.env_remove("MALLOC_CONF"),
        };
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
/// same profile. With `prof_unbias:false` a dump prints the raw sampled counts,
/// and every stack's four counts must be identical, with `prof_accum` on and
/// off. (The heap is not touched between the dump and the read.)
#[test]
fn the_counts_are_the_ones_a_dump_of_the_same_heap_has() {
    for lib in libs() {
        for conf in [
            "prof:true,lg_prof_sample:9,prof_accum:true,prof_unbias:false",
            "prof:true,lg_prof_sample:12,prof_accum:false,prof_unbias:false",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let Some(bin) = build_target(dir.path()) else {
                return;
            };
            let dump = dir.path().join("reference.heap");
            let target = Target::start(&bin, Some(&lib), Some(conf), dump.to_str().unwrap());

            let dumped = jemalloc::read(&dump).unwrap();
            let process = snoop::Process::open(target.pid()).unwrap();
            let (snooped, report) = snoop::read(&process, &process.root().unwrap()).unwrap();

            let ctx = format!("{lib:?} with {conf}");
            assert_eq!(snooped.sample_period, dumped.sample_period, "{ctx}");
            assert!(
                dumped.samples.len() > 40,
                "{ctx}: {} stacks",
                dumped.samples.len()
            );
            let (want, got) = (rows(&dumped.samples), rows(&snooped.samples));
            assert_eq!(got.len(), want.len(), "{ctx}: {report:?}");
            for (addrs, counts) in &want {
                assert_eq!(got.get(addrs), Some(counts), "{ctx}: stack {addrs:x?}");
            }
            assert_eq!(snooped.trigger, Some("snoop"));
            // The checks over the whole walk had records to judge, and on a
            // real jemalloc found nothing out of place: the thread records
            // are in the order jemalloc keeps them, and the counters are
            // ones jemalloc keeps.
            let st = &report.stats;
            assert!(st.counters_checked > 10, "{ctx}: {st:?}");
            assert!(st.order_checked > 0, "{ctx}: {st:?}");
            assert_eq!(
                (st.counters_violated, st.order_violated),
                (0, 0),
                "{ctx}: {st:?}"
            );
            // The same memory map, for symbolization.
            assert_eq!(snooped.maps.exe_name(), dumped.maps.exe_name());
            target.stop();
        }
    }
}

/// A database says how the read of each snooped snapshot went, so that whoever
/// opens it later can tell a clean read from one that was not; a dump, which
/// jemalloc wrote under its own locks, has no such row.
#[test]
fn how_the_read_went_is_kept_with_the_snapshot() {
    for lib in libs() {
        let dir = tempfile::tempdir().unwrap();
        let Some(bin) = build_target(dir.path()) else {
            return;
        };
        let dump = dir.path().join("reference.heap");
        let conf = "prof:true,lg_prof_sample:9";
        let target = Target::start(&bin, Some(&lib), Some(conf), dump.to_str().unwrap());

        let out = dir.path().join("snooped.duckdb");
        let run = snoop_cli(target.pid(), &out, dir.path());
        assert!(
            run.status.success(),
            "{lib:?}: {}",
            String::from_utf8_lossy(&run.stderr)
        );
        let conn = Connection::open(&out).unwrap();
        // One row, of the one snapshot.
        let (rows, of_a_snapshot): (i64, i64) = conn
            .query_row(
                "SELECT count(*), count(s.id) FROM heap_live_read r
                 LEFT JOIN heap_snapshot s
                   ON s.trace_id = r.trace_id AND s.id = r.snapshot_id
                  AND s.dump_trigger = 'snoop'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((rows, of_a_snapshot), (1, 1), "{lib:?}");

        let (found_by, object, period_from): (String, String, String) = conn
            .query_row(
                "SELECT found_by, object_path, sample_period_from FROM heap_live_read",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert!(
            ["symbol", "shape"].contains(&found_by.as_str()),
            "{found_by}"
        );
        assert!(object.contains("jemalloc"), "{object}");
        // The period is in the target's MALLOC_CONF, whatever the library has.
        assert!(
            ["symbols", "malloc_conf"].contains(&period_from.as_str()),
            "{period_from}"
        );

        // The target is parked, so nothing moved under the read: it is clean,
        // and what was read is at least what is reported.
        let stacks: i64 = conn
            .query_row("SELECT count(*) FROM heap_sample", [], |r| r.get(0))
            .unwrap();
        let (unsteady, read, skipped, threads, off, reads, bytes): (
            bool,
            i64,
            i64,
            i64,
            i64,
            i64,
            i64,
        ) = conn
            .query_row(
                "SELECT unsteady, backtraces_read,
                        backtraces_skipped + thread_records_skipped, thread_records_read,
                        links_out_of_order + counters_off, reads, bytes_read
                 FROM heap_live_read",
                [],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                },
            )
            .unwrap();
        assert!(!unsteady, "{lib:?}");
        assert_eq!((skipped, off), (0, 0), "{lib:?}");
        assert!(
            read >= stacks && stacks > 40,
            "{lib:?}: {read} read, {stacks}"
        );
        assert!(threads >= stacks, "{lib:?}: {threads} thread records");
        assert!(reads > 0 && bytes > 0, "{lib:?}");

        // The same heap as jemalloc dumped it: snapshots, and no such row.
        let dumped = dir.path().join("dumped.duckdb");
        let run = Command::new(BIN)
            .arg("-o")
            .arg(&dumped)
            .arg(&dump)
            .output()
            .unwrap();
        assert!(
            run.status.success(),
            "{}",
            String::from_utf8_lossy(&run.stderr)
        );
        let conn = Connection::open(&dumped).unwrap();
        let (snapshots, live_reads): (i64, i64) = conn
            .query_row(
                "SELECT (SELECT count(*) FROM heap_snapshot),
                        (SELECT count(*) FROM heap_live_read)",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((snapshots, live_reads), (1, 0), "{lib:?}");
        target.stop();
    }
}

/// With unbiasing on (the default) a dump prints counts that jeprof scales
/// back to jemalloc's estimate, through integers; the estimate read from
/// memory is jemalloc's own, so the two agree to rounding.
#[test]
fn the_estimates_agree_with_those_of_a_dump_of_the_same_heap() {
    for lib in libs() {
        let dir = tempfile::tempdir().unwrap();
        let Some(bin) = build_target(dir.path()) else {
            return;
        };
        let dump = dir.path().join("reference.heap");
        let conf = "prof:true,lg_prof_sample:12";
        let target = Target::start(&bin, Some(&lib), Some(conf), dump.to_str().unwrap());

        let dumped = jemalloc::read(&dump).unwrap();
        let process = snoop::Process::open(target.pid()).unwrap();
        let (snooped, _) = snoop::read(&process, &process.root().unwrap()).unwrap();

        let by_addrs = |s: &systing_heap::Snapshot| -> std::collections::BTreeMap<Vec<u64>, f64> {
            s.samples
                .iter()
                .map(|x| (x.addrs.clone(), x.estimates(s.sample_period)[0] as f64))
                .collect()
        };
        let (want, got) = (by_addrs(&dumped), by_addrs(&snooped));
        let (w, g): (f64, f64) = (want.values().sum(), got.values().sum());
        assert!((g - w).abs() / w < 0.005, "{lib:?}: dump {w}, memory {g}");
        // Large stacks agree one by one.
        for (addrs, w) in want.iter().filter(|(_, w)| **w > 100_000.0) {
            let g = got[addrs];
            assert!(
                (g - w).abs() / w < 0.01,
                "{lib:?}: stack {addrs:x?}: dump {w}, memory {g}"
            );
        }
        target.stop();
    }
}

/// The estimate does not depend on the sampling period the tool has in mind:
/// with `prof_unbias:false` a dump prints raw counts and systing-heap scales
/// them at each stack's mean object size; a snoop has jemalloc's own
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
        let process = snoop::Process::open(target.pid()).unwrap();
        let (snooped, _) = snoop::read(&process, &process.root().unwrap()).unwrap();

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

/// A process that sets its options in the program (a `malloc_conf` it defines)
/// gives a stripped library no way to say what its sampling period is: neither
/// its environment nor a symbol does, so the tool guesses, and the guess is
/// only a label. The estimates are jemalloc's own and do not depend on it.
#[test]
fn a_guessed_period_does_not_spoil_the_estimates() {
    for lib in libs() {
        let dir = tempfile::tempdir().unwrap();
        let conf = "prof:true,lg_prof_sample:12";
        let define = format!("-DCOMPILED_MALLOC_CONF=\"{conf}\"");
        // Exported, so that the preloaded jemalloc finds the program's variable.
        let Some(bin) = build_target_as(
            dir.path(),
            "snoop_target_conf",
            &["-rdynamic".into(), define],
        ) else {
            return;
        };
        let dump = dir.path().join("reference.heap");
        // No MALLOC_CONF in the environment: only the program knows.
        let target = Target::start(&bin, Some(&lib), None, dump.to_str().unwrap());

        let dumped = jemalloc::read(&dump).unwrap();
        assert_eq!(
            dumped.sample_period,
            1 << 12,
            "{lib:?}: the program's own conf"
        );
        let process = snoop::Process::open(target.pid()).unwrap();
        let (snooped, report) = snoop::read(&process, &process.root().unwrap()).unwrap();

        let total = |s: &systing_heap::Snapshot| -> f64 {
            s.samples
                .iter()
                .map(|x| x.estimates(s.sample_period)[0] as f64)
                .sum()
        };
        // Without symbols the tool could only guess, and guessed wrong: that is
        // the case being tested. (With symbols it reads the right one.)
        if report.how == snoop::locate::How::Shape {
            assert_ne!(snooped.sample_period, dumped.sample_period, "{lib:?}");
            // And the snapshot says that its period is a guess.
            let kept = snooped.live_read.as_ref().unwrap();
            assert_eq!(kept.sample_period_from, "default", "{lib:?}");
        }
        let (want, got) = (total(&dumped), total(&snooped));
        assert!(
            (got - want).abs() / want < 0.005,
            "{lib:?}: dump {want}, memory {got}; period 2^{} from {:?}",
            report.lg_prof_sample,
            report.sample_period_from
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

/// A process is pinned when it is opened. While it lives it is read; after it
/// has exited the same handle fails, and does not reach whichever process
/// comes to have its number. (The process is one that can be read, so it is
/// its death, not a missing jemalloc, that the failure comes from.)
#[test]
fn a_pinned_process_that_has_exited_is_not_read() {
    let Some(lib) = common::jemalloc() else {
        common::skip("needs libjemalloc.so.2");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let Some(bin) = build_target(dir.path()) else {
        return;
    };
    let mut target = Target::start(&bin, Some(&lib), Some("prof:true,lg_prof_sample:12"), "-");
    let process = snoop::Process::open(target.pid()).unwrap();
    let root = process.root().unwrap();
    assert!(snoop::read(&process, &root).is_ok());

    target.child.kill().unwrap();
    target.child.wait().unwrap();
    assert!(snoop::read(&process, &root).is_err());
    assert!(snoop::read_within(&process, snoop::TIMEOUT).is_err());
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
