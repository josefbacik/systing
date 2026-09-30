//! The hooks library and its Python helper, for real: Python under jemalloc
//! with perf trampolines, then systing-heap on the dump. Skipped (with a
//! note) where there is no jemalloc, C compiler, or Python 3.12+; see
//! `common::skip`. The "python" backtrace has its own file, `python_hook.rs`.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use duckdb::Connection;

const BIN: &str = env!("CARGO_BIN_EXE_systing-heap");
use common::HOOKS;

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
r = systing_heap_hooks.install(backtrace=sys.argv[2], strict=True)
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
    if !common::make_hooks(Path::new(HOOKS), dir.path()) {
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

#[cfg(target_arch = "x86_64")]
const CAN_HAVE_IT_APP: &str = r#"
import os
import systing_heap_hooks
print(systing_heap_hooks.install(backtrace="frame-pointer")["backtrace"])
os.unlink(f"/tmp/perf-{os.getpid()}.map")
"#;

/// `setup()` with a Python the "frame-pointer" backtrace gets through: one
/// built with frame pointers, which not every one is.
#[cfg(target_arch = "x86_64")]
fn setup_with_frame_pointers() -> Option<Env> {
    let mut env = setup()?;
    let app = env.dir.path().join("can_have_it_app.py");
    std::fs::write(&app, CAN_HAVE_IT_APP).unwrap();
    for (python, minor) in common::pythons() {
        let out = Command::new(&python)
            .args(["-W", "ignore"])
            .arg(&app)
            .env("LD_PRELOAD", &env.jemalloc)
            .env(
                "MALLOC_CONF",
                format!("prof:true,prof_prefix:{}/jeprof", env.dir.path().display()),
            )
            .env("SYSTING_HEAP_HOOKS_LIB", &env.lib)
            .env("PYTHONPATH", HOOKS)
            .output()
            .unwrap();
        if String::from_utf8_lossy(&out.stdout).trim() == "frame-pointer" {
            env.python = python;
            env.python_minor = minor;
            return Some(env);
        }
    }
    common::skip("needs a Python 3.12+ built with frame pointers");
    None
}

/// `setup()` where there is a libunwind to load.
fn setup_with_libunwind() -> Option<Env> {
    if !common::have_libunwind() {
        common::skip("needs libunwind.so.8");
        return None;
    }
    setup()
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

fn keeps_every_python_caller(env: &Env, backtrace: &str) {
    let (reported, frames) = run(env, backtrace, None);
    assert_eq!(reported, backtrace);
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
fn libunwind_hook_keeps_every_python_caller() {
    let Some(env) = setup_with_libunwind() else {
        return;
    };
    keeps_every_python_caller(&env, "libunwind");
}

#[test]
#[cfg(target_arch = "x86_64")]
fn the_frame_pointer_backtrace_keeps_every_python_caller() {
    let Some(env) = setup_with_frame_pointers() else {
        return;
    };
    keeps_every_python_caller(&env, "frame-pointer");
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

#[test]
fn a_backtrace_there_is_not_falls_back_to_the_default() {
    let Some(env) = setup() else { return };
    let (reported, frames) = run(&env, "no-such", None);
    assert_eq!(
        reported,
        "default unknown backtrace (expected \"default\", \"libunwind\", \"frame-pointer\" or \"python\")"
    );
    assert_eq!(
        python_frames(&frames),
        vec!["leak_in_python (python) [app.py]"],
        "{frames:#?}"
    );
}

#[test]
#[cfg(not(target_arch = "x86_64"))]
fn the_frame_pointer_backtrace_says_which_machines_it_is_for() {
    let Some(env) = setup() else { return };
    let (reported, _) = run(&env, "frame-pointer", None);
    assert_eq!(
        reported,
        "default the frame-pointer backtrace is for x86-64 only"
    );
}

// Whether the walk gets through is told by Python's perf map. With the map
// gone it cannot be told: the backtrace is not installed, and the result says
// why.
#[cfg(target_arch = "x86_64")]
const UNTOLD_APP: &str = r#"
import os, sys
import systing_heap_hooks
sys.activate_stack_trampoline("perf")
os.unlink(f"/tmp/perf-{os.getpid()}.map")
r = systing_heap_hooks.install(backtrace="frame-pointer")
print(r["backtrace"], ";".join(r["reasons"]))
"#;

#[test]
#[cfg(target_arch = "x86_64")]
fn a_walk_that_is_not_seen_to_get_through_is_not_installed() {
    let Some(env) = setup() else { return };
    std::fs::write(env.dir.path().join("untold_app.py"), UNTOLD_APP).unwrap();
    let out = Command::new(&env.python)
        .args(["-W", "ignore"])
        .arg(env.dir.path().join("untold_app.py"))
        .env("LD_PRELOAD", &env.jemalloc)
        .env(
            "MALLOC_CONF",
            format!("prof:true,prof_prefix:{}/jeprof", env.dir.path().display()),
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
    let reported = String::from_utf8_lossy(&out.stdout);
    assert!(
        reported.starts_with(
            "default frame pointers: whether the walk gets through Python's trampolines cannot be told"
        ),
        "{reported}"
    );
}

/// Run the pre-fork app; return the Python frames of the worker's largest
/// stack.
fn run_fork(env: &Env, mode: &str, backtrace: &str) -> Vec<String> {
    let dumps = env.dir.path().join(format!("fork-{mode}"));
    std::fs::create_dir(&dumps).unwrap();
    let out = Command::new(&env.python)
        .arg(env.dir.path().join("fork_app.py"))
        .arg(mode)
        .arg(backtrace)
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

fn names_the_frames_it_inherited(env: &Env, backtrace: &str) {
    // The CPython API it rests on is 3.13's; not a missing dependency.
    if env.python_minor < 13 {
        eprintln!("skipped: keep_perf_map_across_fork needs Python 3.13+");
        return;
    }
    // Without it, the worker's map starts empty: serve(), entered in the
    // parent, has no name there.
    assert_eq!(
        run_fork(env, "plain", backtrace),
        vec!["leak_in_worker (python) [fork_app.py]"]
    );
    assert_eq!(
        run_fork(env, "keep", backtrace),
        vec![
            "serve (python) [fork_app.py]",
            "leak_in_worker (python) [fork_app.py]"
        ]
    );
}

#[test]
fn a_forked_worker_names_the_frames_it_inherited() {
    let Some(env) = setup_with_libunwind() else {
        return;
    };
    names_the_frames_it_inherited(&env, "libunwind");
}

#[test]
#[cfg(target_arch = "x86_64")]
fn a_forked_worker_names_the_frames_it_inherited_by_frame_pointers() {
    let Some(env) = setup_with_frame_pointers() else {
        return;
    };
    names_the_frames_it_inherited(&env, "frame-pointer");
}

// A library whose fork handlers allocate, registered before install(): its
// handlers run inside fork(), where the library's own have run already, and with
// "libunwind" while the forking thread holds the hook's unwind lock.
const ALLOCATING_ATFORK_C: &str = r#"
#include <pthread.h>
#include <stdlib.h>
static void *volatile keep;
static void allocate(void) { free(keep); keep = malloc(4096); }
__attribute__((constructor)) static void init(void) { pthread_atfork(allocate, allocate, allocate); }
"#;

const ALLOCATING_ATFORK_APP: &str = r#"
import ctypes, os, sys
ctypes.CDLL(sys.argv[1])
import systing_heap_hooks
systing_heap_hooks.install(backtrace=sys.argv[2], strict=True)
pid = os.fork()
os.unlink(f"/tmp/perf-{os.getpid()}.map")
if pid == 0:
    os._exit(0)
os.waitpid(pid, 0)
"#;

fn a_fork_does_not_hang(env: &Env, backtrace: &str) {
    let dir = env.dir.path();
    let lib = dir.join("liballocating_atfork.so");
    let src = dir.join("allocating_atfork.c");
    std::fs::write(&src, ALLOCATING_ATFORK_C).unwrap();
    let built = Command::new(std::env::var("CC").unwrap_or_else(|_| "cc".into()))
        .args(["-O2", "-fPIC", "-shared", "-o"])
        .arg(&lib)
        .arg(&src)
        .arg("-lpthread")
        .status()
        .unwrap();
    assert!(built.success());
    std::fs::write(dir.join("atfork_app.py"), ALLOCATING_ATFORK_APP).unwrap();
    let dumps = dir.join("atfork-dumps");
    std::fs::create_dir(&dumps).unwrap();
    // Every allocation sampled, so the handlers' allocations reach the hook.
    let mut child = Command::new(&env.python)
        .arg(dir.join("atfork_app.py"))
        .arg(&lib)
        .arg(backtrace)
        .env("LD_PRELOAD", &env.jemalloc)
        .env(
            "MALLOC_CONF",
            format!(
                "prof:true,lg_prof_sample:0,prof_prefix:{}/jeprof",
                dumps.display()
            ),
        )
        .env("SYSTING_HEAP_HOOKS_LIB", &env.lib)
        .env("PYTHONPATH", HOOKS)
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "{status}");
            break;
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the fork hung on a fork handler's sampled allocation");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

#[test]
fn a_fork_with_allocating_fork_handlers_does_not_hang() {
    let Some(env) = setup_with_libunwind() else {
        return;
    };
    a_fork_does_not_hang(&env, "libunwind");
}

#[test]
#[cfg(target_arch = "x86_64")]
fn a_fork_with_allocating_fork_handlers_does_not_hang_on_frame_pointers() {
    let Some(env) = setup_with_frame_pointers() else {
        return;
    };
    a_fork_does_not_hang(&env, "frame-pointer");
}
