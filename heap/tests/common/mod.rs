//! What the tests that run Python under jemalloc need, and how they skip.

// Each test file uses its own subset.
#![allow(dead_code)]

use std::path::PathBuf;
use std::process::Command;

/// Set in CI, where every dependency is installed: a test that would skip
/// fails instead, so a green run means it ran.
const REQUIRE: &str = "SYSTING_HEAP_REQUIRE_TEST_DEPS";

/// Note why a test is not running, or fail it when `REQUIRE` is set.
pub fn skip(why: &str) {
    if std::env::var_os(REQUIRE).is_some_and(|v| !v.is_empty()) {
        panic!("{why}, and {REQUIRE} is set");
    }
    eprintln!("skipped: {why}");
}

pub fn jemalloc() -> Option<PathBuf> {
    [
        "/lib/x86_64-linux-gnu/libjemalloc.so.2",
        "/lib/aarch64-linux-gnu/libjemalloc.so.2",
        "/usr/lib64/libjemalloc.so.2",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|p| p.exists())
}

/// A Python with perf trampolines (3.12+), and its minor version.
pub fn python() -> Option<(String, u32)> {
    pythons().into_iter().next()
}

/// Every Python the hooks support that is installed, newest first: what
/// reads the interpreter's own structures is run on each.
pub fn pythons() -> Vec<(String, u32)> {
    ["python3.14", "python3.13", "python3.12"]
        .into_iter()
        .filter(|p| {
            Command::new(p)
                .arg("-V")
                .output()
                .is_ok_and(|o| o.status.success())
        })
        .map(|p| (p.to_string(), p["python3.".len()..].parse().unwrap()))
        .collect()
}

pub fn have_libunwind() -> bool {
    Command::new("ldconfig")
        .arg("-p")
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("libunwind.so.8 "))
}
