//! The hooks library and its Python helper, for real: Python under jemalloc
//! with perf trampolines, then systing-heap on the dump. Skipped (with a
//! note) where there is no jemalloc, C compiler, or Python 3.12+; see
//! `common::skip`.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use duckdb::Connection;

const BIN: &str = env!("CARGO_BIN_EXE_systing-heap");
const HOOKS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/hooks");

const APP: &str = r#"
import sys
import systing_heap_hooks
r = systing_heap_hooks.install(backtrace=sys.argv[1])
print(r["backtrace"], ";".join(r["reasons"]))
keep = []
def leak_in_python(n):
    for _ in range(n):
        keep.append(bytearray(64 * 1024))
def outer():
    leak_in_python(64)
outer()
"#;

// A pre-fork server: serve() is running when the worker forks, and the
// worker's own allocation happens under it.
const FORK_APP: &str = r#"
import ctypes, os, sys
import systing_heap_hooks
r = systing_heap_hooks.install(backtrace="libunwind", strict=True)
if sys.argv[1] == "keep":
    systing_heap_hooks.keep_perf_map_across_fork(strict=True)
keep = []
def leak_in_worker(n):
    for _ in range(n):
        keep.append(bytearray(64 * 1024))
def serve():
    pid = os.fork()
    if pid == 0:
        leak_in_worker(64)
        ctypes.CDLL(None).mallctl(b"prof.dump", None, None, None, ctypes.c_size_t(0))
        os._exit(0)
    os.waitpid(pid, 0)
    print(os.getpid(), pid)
serve()
"#;

struct Env {
    jemalloc: PathBuf,
    python: String,
    python_minor: u32,
    lib: PathBuf,
    dir: tempfile::TempDir,
}

fn setup() -> Option<Env> {
    let (Some(jemalloc), Some((python, python_minor))) = (common::jemalloc(), common::python())
    else {
        common::skip("needs libjemalloc.so.2 and Python 3.12+");
        return None;
    };
    let dir = tempfile::tempdir().unwrap();
    let lib = dir.path().join("libsysting_heap_hooks.so");
    let built = Command::new(std::env::var("CC").unwrap_or_else(|_| "cc".into()))
        .args([
            "-O2",
            "-Wall",
            "-fPIC",
            "-shared",
            "-fno-omit-frame-pointer",
            "-o",
        ])
        .arg(&lib)
        .arg(Path::new(HOOKS).join("systing_heap_hooks.c"))
        .args(["-ldl", "-lpthread"])
        .status();
    if !built.is_ok_and(|s| s.success()) {
        common::skip("no C compiler to build the hooks library");
        return None;
    }
    std::fs::write(dir.path().join("app.py"), APP).unwrap();
    std::fs::write(dir.path().join("fork_app.py"), FORK_APP).unwrap();
    Some(Env {
        jemalloc,
        python,
        python_minor,
        lib,
        dir,
    })
}

/// Run the app with `backtrace`; return what install() reported and the
/// root-first frames of the stack holding the most live bytes.
fn run(env: &Env, backtrace: &str, libunwind: Option<&str>) -> (String, Vec<String>) {
    let dumps = env
        .dir
        .path()
        .join(format!("dumps-{backtrace}-{}", libunwind.is_some()));
    std::fs::create_dir(&dumps).unwrap();
    let mut cmd = Command::new(&env.python);
    cmd.arg(env.dir.path().join("app.py"))
        .arg(backtrace)
        .env("LD_PRELOAD", &env.jemalloc)
        .env(
            "MALLOC_CONF",
            format!(
                "prof:true,lg_prof_sample:12,lg_prof_interval:21,prof_prefix:{}/jeprof",
                dumps.display()
            ),
        )
        .env("SYSTING_HEAP_HOOKS_LIB", &env.lib)
        .env("PYTHONPATH", HOOKS);
    if let Some(l) = libunwind {
        cmd.env("SYSTING_HEAP_HOOKS_LIBUNWIND", l);
    }
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let reported = String::from_utf8_lossy(&out.stdout).trim().to_string();

    // The last interval dump, while the leak is still live.
    let mut heaps: Vec<PathBuf> = std::fs::read_dir(&dumps)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "heap"))
        .collect();
    heaps.sort_by_key(|p| {
        let n = p.file_name().unwrap().to_str().unwrap().to_string();
        n.split('.').nth(2).and_then(|s| s.parse::<u64>().ok())
    });
    let dump = heaps.last().expect("jemalloc wrote no dump").clone();
    let pid = dump
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .split('.')
        .nth(1)
        .unwrap()
        .to_string();
    // The process wrote its perf map to /tmp; keep the test's copy beside
    // the dump, as users are told to, and leave /tmp as it was.
    let tmp_map = PathBuf::from(format!("/tmp/perf-{pid}.map"));
    if tmp_map.exists() {
        std::fs::copy(&tmp_map, dumps.join(format!("perf-{pid}.map"))).unwrap();
        let _ = std::fs::remove_file(&tmp_map);
    }

    let db = dumps.join("heap.duckdb");
    let st = Command::new(BIN)
        .arg(&dump)
        .arg("-o")
        .arg(&db)
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "{}",
        String::from_utf8_lossy(&st.stderr)
    );
    let conn = Connection::open(&db).unwrap();
    let frames: Vec<String> = conn
        .prepare(
            "SELECT unnest(sf.frame_names) FROM heap_sample h
             JOIN stack_frames sf ON sf.trace_id = h.trace_id AND sf.id = h.stack_id
             WHERE h.stack_id = (SELECT stack_id FROM heap_sample ORDER BY live_bytes DESC LIMIT 1)",
        )
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    (reported, frames)
}

fn python_frames(frames: &[String]) -> Vec<&str> {
    frames
        .iter()
        .filter(|f| f.contains(" (python) "))
        .map(String::as_str)
        .collect()
}

#[test]
fn libunwind_hook_keeps_every_python_caller() {
    let Some(env) = setup() else { return };
    if !common::have_libunwind() {
        common::skip("needs libunwind.so.8");
        return;
    }
    let (reported, frames) = run(&env, "libunwind", None);
    assert_eq!(reported, "libunwind");
    assert_eq!(
        python_frames(&frames),
        vec![
            "outer (python) [app.py]",
            "leak_in_python (python) [app.py]"
        ],
        "{frames:#?}"
    );
    // Native frames stay on both sides: the interpreter's start below,
    // jemalloc above.
    assert!(frames[0].starts_with("_start "), "{frames:#?}");
    assert!(
        frames.last().unwrap().contains("libjemalloc"),
        "{frames:#?}"
    );
}

#[test]
fn default_backtrace_stops_at_the_first_trampoline() {
    let Some(env) = setup() else { return };
    let (reported, frames) = run(&env, "default", None);
    assert_eq!(reported, "default");
    assert_eq!(
        python_frames(&frames),
        vec!["leak_in_python (python) [app.py]"],
        "{frames:#?}"
    );
}

#[test]
fn without_libunwind_install_falls_back_to_the_default() {
    let Some(env) = setup() else { return };
    let (reported, frames) = run(&env, "libunwind", Some("libsysting-no-such-libunwind.so"));
    assert_eq!(reported, "default libunwind.so.8 not found");
    assert_eq!(
        python_frames(&frames),
        vec!["leak_in_python (python) [app.py]"],
        "{frames:#?}"
    );
}

/// Run the pre-fork app; return the Python frames of the worker's largest
/// stack.
fn run_fork(env: &Env, mode: &str) -> Vec<String> {
    let dumps = env.dir.path().join(format!("fork-{mode}"));
    std::fs::create_dir(&dumps).unwrap();
    let out = Command::new(&env.python)
        .arg(env.dir.path().join("fork_app.py"))
        .arg(mode)
        .env("LD_PRELOAD", &env.jemalloc)
        .env(
            "MALLOC_CONF",
            format!(
                "prof:true,lg_prof_sample:12,prof_prefix:{}/jeprof",
                dumps.display()
            ),
        )
        .env("SYSTING_HEAP_HOOKS_LIB", &env.lib)
        .env("PYTHONPATH", HOOKS)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let pids = String::from_utf8_lossy(&out.stdout).to_string();
    let (parent, worker) = pids.trim().split_once(' ').unwrap();
    for pid in [parent, worker] {
        let tmp_map = PathBuf::from(format!("/tmp/perf-{pid}.map"));
        if tmp_map.exists() {
            if pid == worker {
                std::fs::copy(&tmp_map, dumps.join(format!("perf-{pid}.map"))).unwrap();
            }
            let _ = std::fs::remove_file(&tmp_map);
        }
    }
    let db = dumps.join("heap.duckdb");
    let st = Command::new(BIN)
        .arg(&dumps)
        .arg("-o")
        .arg(&db)
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "{}",
        String::from_utf8_lossy(&st.stderr)
    );
    let conn = Connection::open(&db).unwrap();
    let frames: Vec<String> = conn
        .prepare(
            "SELECT unnest(sf.frame_names) FROM heap_sample h
             JOIN stack_frames sf ON sf.trace_id = h.trace_id AND sf.id = h.stack_id
             WHERE h.stack_id = (SELECT stack_id FROM heap_sample ORDER BY live_bytes DESC LIMIT 1)",
        )
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    python_frames(&frames)
        .into_iter()
        .map(String::from)
        .collect()
}

#[test]
fn a_forked_worker_names_the_frames_it_inherited() {
    let Some(env) = setup() else { return };
    if !common::have_libunwind() {
        common::skip("needs libunwind.so.8");
        return;
    }
    // The CPython API it rests on is 3.13's; not a missing dependency.
    if env.python_minor < 13 {
        eprintln!("skipped: keep_perf_map_across_fork needs Python 3.13+");
        return;
    }
    // Without it, the worker's map starts empty: serve(), entered in the
    // parent, has no name there.
    assert_eq!(
        run_fork(&env, "plain"),
        vec!["leak_in_worker (python) [fork_app.py]"]
    );
    assert_eq!(
        run_fork(&env, "keep"),
        vec![
            "serve (python) [fork_app.py]",
            "leak_in_worker (python) [fork_app.py]"
        ]
    );
}
