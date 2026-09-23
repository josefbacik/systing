//! The hooks library and its Python helper, for real: Python under jemalloc
//! with perf trampolines, then systing-heap on the dump. Skipped (with a
//! note) where there is no jemalloc, C compiler, or Python 3.12+.

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

struct Env {
    jemalloc: PathBuf,
    python: String,
    lib: PathBuf,
    dir: tempfile::TempDir,
}

fn setup() -> Option<Env> {
    let jemalloc = [
        "/lib/x86_64-linux-gnu/libjemalloc.so.2",
        "/usr/lib64/libjemalloc.so.2",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|p| p.exists());
    let python = ["python3.14", "python3.13", "python3.12"]
        .into_iter()
        .find(|p| {
            Command::new(p)
                .arg("-V")
                .output()
                .is_ok_and(|o| o.status.success())
        });
    let (Some(jemalloc), Some(python)) = (jemalloc, python) else {
        eprintln!("skipped: needs libjemalloc.so.2 and Python 3.12+");
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
        eprintln!("skipped: no C compiler to build the hooks library");
        return None;
    }
    std::fs::write(dir.path().join("app.py"), APP).unwrap();
    Some(Env {
        jemalloc,
        python: python.to_string(),
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

fn have_libunwind() -> bool {
    Command::new("ldconfig")
        .arg("-p")
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("libunwind.so.8 "))
}

#[test]
fn libunwind_hook_keeps_every_python_caller() {
    let Some(env) = setup() else { return };
    if !have_libunwind() {
        eprintln!("skipped: needs libunwind.so.8");
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
