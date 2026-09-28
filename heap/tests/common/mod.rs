//! What the tests that run Python under jemalloc need, and how they skip.

// Each test file uses its own subset.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
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

/// Where the hooks' sources are.
pub const HOOKS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/hooks");

/// The hooks libraries built into `out` from the sources in `hooks` ([`HOOKS`],
/// or a copy of it that a test has changed), as a service's image builds
/// them: with `make`, so that which files make up which library is said in
/// one place. Warnings fail the build. False, with a note, where there is
/// nothing to build with.
pub fn make_hooks(hooks: &Path, out: &Path) -> bool {
    let built = Command::new("make")
        .arg("-C")
        .arg(hooks)
        .arg(format!("OUT={}", out.display()))
        .arg("CFLAGS=-O2 -g -Werror")
        .output();
    match built {
        Ok(o) if o.status.success() => true,
        Ok(o) => panic!(
            "the hooks libraries did not build:\n{}",
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(_) => {
            skip("no make to build the hooks library with");
            false
        }
    }
}

/// A copy of the hooks' sources in `to`, which is made: every file of the
/// folders the libraries are built from.
pub fn copy_hooks(to: &Path) {
    fn copy(from: &Path, to: &Path) {
        std::fs::create_dir_all(to).unwrap();
        for entry in std::fs::read_dir(from).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap();
            if path.is_dir() {
                copy(&path, &to.join(name));
            } else if path.extension().is_some_and(|e| e == "c" || e == "h") || name == "Makefile" {
                std::fs::copy(&path, to.join(name)).unwrap();
            }
        }
    }
    copy(Path::new(HOOKS), to);
}
