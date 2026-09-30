//! The `libunwind` backtrace holds a lock of the hooks' for each unwind, and
//! libunwind asks for the dynamic loader's list lock while it is held. A thread
//! that allocates with the loader's lock held must therefore never wait for the
//! hooks': each would wait for the lock the other holds, for good.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use common::HOOKS;

fn cc(dir: &Path, name: &str, source: &str, shared: bool) -> PathBuf {
    let src = dir.join(format!("{name}.c"));
    std::fs::write(&src, source).unwrap();
    let out = dir.join(if shared {
        format!("{name}.so")
    } else {
        name.to_string()
    });
    let mut cmd = Command::new(std::env::var("CC").unwrap_or_else(|_| "cc".into()));
    cmd.args(["-O2", "-o"]).arg(&out).arg(&src);
    if shared {
        cmd.args(["-fPIC", "-shared"]);
    }
    let built = cmd.args(["-ldl", "-lpthread"]).output().unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    out
}

// Code libunwind has not seen: it looks for the library the code is in, which
// takes the loader's list lock.
const FRESH_C: &str = r#"
#include <stdlib.h>
void *volatile kept;
void fresh(void) { kept = malloc(1 << 16); }
"#;

// One thread allocates in a callback of dl_iterate_phdr(), which holds the
// loader's list lock across it: what a library that takes backtraces of its own
// does. The other allocates from the fresh code meanwhile.
const TWO_LOCKS_C: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <unistd.h>
static atomic_int go;
static void (*fresh)(void);
static void *volatile kept;
static void *other(void *arg)
{
    (void)arg;
    while (!go)
        usleep(1000);
    fresh();
    return NULL;
}
static int in_the_callback(struct dl_phdr_info *info, size_t size, void *arg)
{
    (void)info;
    (void)size;
    (void)arg;
    go = 1;
    usleep(300000);
    kept = malloc(1 << 16);
    return 1;
}
int main(int argc, char **argv)
{
    if (argc != 3)
        return 2;
    void *hooks = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!hooks || ((int (*)(const char *))dlsym(hooks, "systing_heap_hooks_install"))("libunwind") != 0)
        return 2;
    void *lib = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
    if (!lib)
        return 2;
    fresh = (void (*)(void))dlsym(lib, "fresh");
    pthread_t thread;
    if (pthread_create(&thread, NULL, other, NULL) != 0)
        return 2;
    dl_iterate_phdr(in_the_callback, NULL);
    pthread_join(thread, NULL);
    return 0;
}
"#;

#[test]
fn a_thread_that_holds_the_loaders_lock_does_not_wait_for_the_hooks() {
    let Some(jemalloc) = common::jemalloc() else {
        common::skip("needs libjemalloc.so.2");
        return;
    };
    if !common::have_libunwind() {
        common::skip("needs libunwind.so.8");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    if !common::make_hooks(Path::new(HOOKS), dir) {
        return;
    }
    let fresh = cc(dir, "fresh", FRESH_C, true);
    let program = cc(dir, "two_locks", TWO_LOCKS_C, false);
    let mut child = Command::new(program)
        .arg(dir.join("libsysting_heap_hooks.so"))
        .arg(&fresh)
        .env("LD_PRELOAD", &jemalloc)
        .env("MALLOC_CONF", "prof:true,lg_prof_sample:0")
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "{status}");
            break;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("each thread waits for the lock the other holds");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
