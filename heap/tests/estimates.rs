//! The unbiased estimates against the real heap: a Python program under
//! jemalloc allocates a known mix of object sizes, jemalloc counts its live
//! bytes with sampling off (`stats.allocated`), and the sum of `heap_sample`'s
//! estimates for a dump of the same program must come close. Skipped (with a
//! note) where there is no jemalloc or Python 3.12+.

use std::path::{Path, PathBuf};
use std::process::Command;

use duckdb::Connection;

const BIN: &str = env!("CARGO_BIN_EXE_systing-heap");

// Small, medium and large objects, so the per-stack scaling matters: the
// small ones are sampled about once in 60 at the period used below.
const APP: &str = r#"
import ctypes, gc
je = ctypes.CDLL(None)
keep = [
    [(i, str(i)) for i in range(300_000)],
    [bytearray(700) for _ in range(20_000)],
    [bytearray(40 * 1024) for _ in range(300)],
    [bytearray(3 << 20) for _ in range(4)],
]
gc.collect()
epoch = ctypes.c_uint64(1)
size = ctypes.c_size_t(8)
je.mallctl(b"epoch", ctypes.byref(epoch), ctypes.byref(size), ctypes.byref(epoch), ctypes.c_size_t(8))
allocated = ctypes.c_size_t(0)
size = ctypes.c_size_t(ctypes.sizeof(allocated))
assert je.mallctl(b"stats.allocated", ctypes.byref(allocated), ctypes.byref(size), None, ctypes.c_size_t(0)) == 0
assert je.mallctl(b"prof.dump", None, None, None, ctypes.c_size_t(0)) == 0
print(allocated.value)
"#;

fn setup() -> Option<(PathBuf, String)> {
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
    match (jemalloc, python) {
        (Some(j), Some(p)) => Some((j, p.to_string())),
        _ => {
            eprintln!("skipped: needs libjemalloc.so.2 and Python 3.12+");
            None
        }
    }
}

/// Run the app; return jemalloc's live bytes and the dump it wrote.
fn run(jemalloc: &Path, python: &str, dir: &Path, conf: &str) -> (u64, Option<PathBuf>) {
    std::fs::create_dir_all(dir).unwrap();
    let app = dir.join("app.py");
    std::fs::write(&app, APP).unwrap();
    let out = Command::new(python)
        .arg(&app)
        .env("LD_PRELOAD", jemalloc)
        .env("PYTHONMALLOC", "malloc")
        .env(
            "MALLOC_CONF",
            format!("prof:true,{conf},prof_prefix:{}/jeprof", dir.display()),
        )
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let allocated = String::from_utf8_lossy(&out.stdout).trim().parse().unwrap();
    let dump = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "heap"));
    (allocated, dump)
}

#[test]
fn estimated_live_bytes_match_the_real_heap() {
    let Some((jemalloc, python)) = setup() else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();

    // The real heap: sampling off, so no sampled object takes extra room.
    let (real, _) = run(
        &jemalloc,
        &python,
        &dir.path().join("off"),
        "prof_active:false",
    );

    // A dump of the same program, sampling one allocation per 16 KiB.
    let (_, dump) = run(
        &jemalloc,
        &python,
        &dir.path().join("on"),
        "lg_prof_sample:14",
    );
    let dump = dump.expect("jemalloc wrote no dump");
    let db = dir.path().join("heap.duckdb");
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
    let (estimated, sampled): (i64, i64) = conn
        .query_row(
            "SELECT sum(est_live_bytes)::BIGINT, sum(live_bytes)::BIGINT FROM heap_sample",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    let ratio = estimated as f64 / real as f64;
    eprintln!("real {real} B, estimated {estimated} B ({ratio:.3}), sampled {sampled} B");
    assert!(
        (0.9..=1.1).contains(&ratio),
        "estimate {estimated} is {ratio:.3} of the real heap {real}"
    );
    // The sampled counts alone are nowhere near: they need the scaling.
    assert!((sampled as f64) < 0.2 * real as f64, "{sampled} vs {real}");
}
