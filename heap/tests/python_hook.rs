//! The hooks' "python" backtrace, for real: each installed Python (3.12 to
//! 3.14) under jemalloc with the hook installed, then systing-heap on the
//! dump. Skipped (with a note) where there is no jemalloc, C compiler, or
//! Python 3.12+; see `common::skip`.

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use duckdb::Connection;

const BIN: &str = env!("CARGO_BIN_EXE_systing-heap");
const HOOKS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/hooks");

// Line numbers below are this file's: the first line is line 1.
const APP: &str = r#"import ctypes, sys, threading
import systing_heap_hooks
r = systing_heap_hooks.install(backtrace="python", strict=True)
print(r["backtrace"], r["trampolines"], ";".join(r["reasons"]))
libc = ctypes.CDLL(None)
libc.malloc.restype = ctypes.c_void_p
libc.malloc.argtypes = [ctypes.c_size_t]
keep = []
def leak_in_python(n):
    for _ in range(n):
        keep.append(bytearray(64 * 1024))
def outer():
    leak_in_python(64)
def leak_in_c(n):
    for _ in range(n):
        # ctypes releases the GIL for the call: C allocates without it.
        keep.append(libc.malloc(256 * 1024))
def in_thread():
    leak_in_c(64)
outer()
t = threading.Thread(target=in_thread)
t.start()
t.join()
libc.mallctl(b"prof.dump", None, None, None, ctypes.c_size_t(0))
"#;

// A pre-fork server: serve() is running when the worker forks.
const FORK_APP: &str = r#"import ctypes, os, sys
import systing_heap_hooks
systing_heap_hooks.install(backtrace="python", strict=True)
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

// A pre-fork server that fills a cache before it forks: the worker's heap
// holds what the parent allocated, under the ids the parent recorded, beside
// its own.
const PREFORK_APP: &str = r#"import ctypes, os, sys
import systing_heap_hooks
systing_heap_hooks.install(backtrace="python", strict=True)
keep = []
def warm_cache(n):
    for _ in range(n):
        keep.append(bytearray(64 * 1024))
def leak_in_worker(n):
    for _ in range(n):
        keep.append(bytearray(64 * 1024))
def load_config():
    warm_cache(64)
def serve():
    pid = os.fork()
    if pid == 0:
        leak_in_worker(64)
        ctypes.CDLL(None).mallctl(b"prof.dump", None, None, None, ctypes.c_size_t(0))
        os._exit(0)
    os.waitpid(pid, 0)
    print(os.getpid(), pid)
load_config()
serve()
"#;

// Names that are not ASCII, in each width Python stores a str with: Latin-1
// (a name with an e acute), UTF-16 (the file) and UTF-32 (a name beyond
// the basic plane).
const WIDE_NAMES_APP: &str = r#"import ctypes
import systing_heap_hooks
systing_heap_hooks.install(backtrace="python", strict=True)
source = """
keep = []
def caf\u00e9(n):
    for _ in range(n):
        keep.append(bytearray(64 * 1024))
def \U00020000(n):
    caf\u00e9(n)
\U00020000(64)
"""
exec(compile(source, "/srv/\u65e5\u672c/caf\u00e9.py", "exec"))
ctypes.CDLL(None).mallctl(b"prof.dump", None, None, None, ctypes.c_size_t(0))
"#;

// A process that may not use process_vm_readv, as under a seccomp profile
// that refuses it: the hook reads through /proc/self/mem. Preloaded, this
// stands in front of libc's.
const NO_PROCESS_VM_READV_C: &str = r#"#include <errno.h>
#include <sys/types.h>
#include <sys/uio.h>
ssize_t process_vm_readv(pid_t pid, const struct iovec *l, unsigned long ln,
			 const struct iovec *r, unsigned long rn, unsigned long flags)
{
	(void)pid, (void)l, (void)ln, (void)r, (void)rn, (void)flags;
	errno = EPERM;
	return -1;
}
"#;

// A forked worker there: the memory it may read is its own, and the
// descriptor on its parent's is not among those it holds.
const MEM_FORK_APP: &str = r#"import os, sys
if "WITHOUT_PROCESS_VM_READV" not in os.environ:
    env = dict(os.environ, WITHOUT_PROCESS_VM_READV="1",
               LD_PRELOAD=os.environ["LD_PRELOAD"] + ":" + sys.argv[1])
    os.execve(sys.executable, [sys.executable] + sys.argv, env)
import ctypes
import systing_heap_hooks
systing_heap_hooks.install(backtrace="python", strict=True)
keep = []
def memory_open():
    found = []
    for n in os.listdir("/proc/self/fd"):
        try:
            to = os.readlink(f"/proc/self/fd/{n}")
        except OSError:
            continue
        if to.endswith("/mem"):
            found.append(to)
    return found
def leak_in_worker(n):
    for _ in range(n):
        keep.append(bytearray(64 * 1024))
def serve():
    pid = os.fork()
    if pid == 0:
        leak_in_worker(64)
        ctypes.CDLL(None).mallctl(b"prof.dump", None, None, None, ctypes.c_size_t(0))
        os._exit(0 if memory_open() == [f"/proc/{os.getpid()}/mem"] else 3)
    return os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])
worker = serve()
mine = memory_open() == [f"/proc/{os.getpid()}/mem"]
# Stopped, the hook reads nothing and holds nothing open; a worker forked
# then has nothing of its parent's either.
ctypes.CDLL(os.environ["SYSTING_HEAP_HOOKS_LIB"]).systing_heap_hooks_python_stop()
stopped = memory_open()
pid = os.fork()
if pid == 0:
    os._exit(0 if memory_open() == [] else 3)
print(worker, mine, stopped, os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]))
"#;

// The code map replaced behind the hook, by someone who can write the dumps'
// folder: with a FIFO, which holds an open until it has a reader, or with
// another file. The hook opens the map inside malloc for each function it
// meets: it must neither wait nor write to what is there now.
const REPLACED_MAP_APP: &str = r#"import glob, os, signal, sys
import systing_heap_hooks
systing_heap_hooks.install(backtrace="python", strict=True)
signal.alarm(30)   # a hang ends here, and not in a test that never ends
keep = []
def before(n):
    for _ in range(n):
        keep.append(bytearray(64 * 1024))
def after(n):
    for _ in range(n):
        keep.append(bytearray(64 * 1024))
def forked(n):
    for _ in range(n):
        keep.append(bytearray(64 * 1024))
before(64)
[path] = glob.glob(os.path.join(sys.argv[1], "pycode-*.map"))
if sys.argv[2] == "fifo":
    os.unlink(path)
    os.mkfifo(path)
elif sys.argv[2] == "file":
    os.unlink(path)
    with open(path, "w") as f:
        f.write("application data\n")
else:
    # The same file by its number, as a file made where one has just gone
    # can be: what tells it from the map is what is in it, and when.
    with open(path, "w") as f:
        f.write("application data\n")
after(64)
pid = os.fork()
if pid == 0:
    forked(64)
    os._exit(0)
worker = os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])
if sys.argv[2] == "fifo":
    print(worker, "survived")
else:
    print(worker, open(path).read().strip())
"#;

// A child that goes straight to exec, as most do.
const EXEC_APP: &str = r#"import os
import systing_heap_hooks
systing_heap_hooks.install(backtrace="python", strict=True)
pid = os.fork()
if pid == 0:
    os.execv("/bin/true", ["true"])
os.waitpid(pid, 0)
print(os.getpid(), pid)
"#;

// A program that closes the descriptors it did not open, as daemonizing
// libraries do, and then opens files of its own: they get the numbers.
const CLOSED_FDS_APP: &str = r#"import os, sys
import systing_heap_hooks
systing_heap_hooks.install(backtrace="python", strict=True)
os.closerange(3, 256)
mine = [os.open(sys.argv[1] + str(i), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644) for i in range(16)]
for fd in mine:
    os.write(fd, b"application data\n")
keep = []
def first_seen_after_the_close(n):
    for _ in range(n):
        keep.append(bytearray(64 * 1024))
first_seen_after_the_close(64)
for fd in mine:
    os.write(fd, b"more application data\n")
import ctypes
ctypes.CDLL(None).mallctl(b"prof.dump", None, None, None, ctypes.c_size_t(0))
"#;

// A class whose __init__ allocates, called until the call site is
// specialized: from 3.13 the interpreter then runs __init__ under a frame of
// its own making, which Python shows in no stack.
const INIT_APP: &str = r#"import ctypes
import systing_heap_hooks
class Holder:
    def __init__(self, n, install=False):
        self.buf = bytearray(n)
        if install:
            self.r = systing_heap_hooks.install(backtrace="python", strict=True)
def build(n, install=False):
    return Holder(n, install)
for _ in range(200):
    build(16)
print(build(16, install=True).r["backtrace"])
keep = [build(64 * 1024) for _ in range(400)]
ctypes.CDLL(None).mallctl(b"prof.dump", None, None, None, ctypes.c_size_t(0))
"#;

// jemalloc's libunwind backtrace (a build with --enable-prof-libunwind)
// fills the whole array whatever length it is given; this one does as it
// does.
const FILLS_THE_ARRAY_C: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <execinfo.h>
#include <stddef.h>
static void fill(void **vec, unsigned *len, unsigned max_len) {
    (void)max_len;
    int n = backtrace(vec, 128);
    if (n > 0)
        *len = (unsigned)n;
}
int install_fill(void) {
    int (*mallctl)(const char *, void *, size_t *, void *, size_t) = dlsym(RTLD_DEFAULT, "mallctl");
    void (*hook)(void **, unsigned *, unsigned) = fill;
    void *warm[4];
    backtrace(warm, 4);
    return mallctl("experimental.hooks.prof_backtrace", NULL, NULL, &hook, sizeof(hook));
}
"#;

const DEEP_APP: &str = r#"import ctypes, sys
assert ctypes.CDLL(sys.argv[1]).install_fill() == 0
import systing_heap_hooks
systing_heap_hooks.install(backtrace="python", strict=True)
keep = []
def rec(n):
    if n == 0:
        for _ in range(64):
            keep.append(bytearray(64 * 1024))
        return 0
    # Through C and back: the native stack grows with every level.
    return max([n], key=lambda _: rec(n - 1))
rec(20)
ctypes.CDLL(None).mallctl(b"prof.dump", None, None, None, ctypes.c_size_t(0))
"#;

const TWICE_APP: &str = r#"import os
import systing_heap_hooks
lib = None
def install():
    r = systing_heap_hooks.install(backtrace="python", strict=True)
    return r["backtrace"], systing_heap_hooks._lib.systing_heap_hooks_python_map().decode()
first = install()
keep = [bytearray(64 * 1024) for _ in range(64)]
second = install()
print(first == second, first[0], os.path.getsize(first[1]) > 100)
"#;

// install() called from a method: a frame whose name and qualified name
// differ, so reading one for the other shows.
const REPORT_APP: &str = r#"import warnings
import systing_heap_hooks
warnings.simplefilter("ignore")
class App:
    def start(self):
        return systing_heap_hooks.install(backtrace="python")
r = App().start()
print(r["backtrace"], "|", ";".join(r["reasons"]))
"#;

// The frame chain, broken on purpose: the caller's link is overwritten while
// C allocates, every allocation sampled. A walk that followed it would fault.
const BROKEN_CHAIN_APP: &str = r#"import ctypes, sys
import systing_heap_hooks
systing_heap_hooks.install(backtrace="python", strict=True)
libc = ctypes.CDLL(None)
libc.malloc.restype = ctypes.c_void_p
libc.malloc.argtypes = [ctypes.c_size_t]
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t] + [ctypes.c_int] * 4
hole = libc.mmap(None, 4096, 0, 0x22, -1, 0)  # PROT_NONE, private anonymous
libc.munmap(ctypes.c_void_p(hole), ctypes.c_size_t(4096))
keep = []
def allocate(size):
    for _ in range(32):
        keep.append(libc.malloc(size))
def broken():
    frame = sys._getframe(0)
    # PyFrameObject: ob_refcnt, ob_type, f_back, f_frame; and
    # _PyInterpreterFrame.previous is its second word.
    iframe = ctypes.c_void_p.from_address(id(frame) + 24).value
    previous = ctypes.c_uint64.from_address(iframe + 8)
    whole = previous.value
    malloc, size, bad = libc.malloc, 128 * 1024, [
        hole,            # nothing mapped there
        0x1000,          # the NULL page
        whole + 1,       # not aligned
        0xdead0000beef0, # outside the address space
        id(frame),       # mapped, and not a frame
    ]
    for link in bad:
        previous.value = link
        a, b, c, d = malloc(size), malloc(size), malloc(size), malloc(size)
        previous.value = whole
        keep.append((a, b, c, d))
def caller():
    allocate(64 * 1024)
    broken()
caller()
libc.mallctl(b"prof.dump", None, None, None, ctypes.c_size_t(0))
print("survived")
"#;

// Threads still allocating in C, without the GIL, while the interpreter
// exits and frees their state.
const CHURN_C: &str = r#"
#include <stdlib.h>
#include <time.h>
void churn(int ms) {
    struct timespec a, b;
    clock_gettime(CLOCK_MONOTONIC, &a);
    do {
        for (int i = 0; i < 64; i++)
            free(malloc(4096));
        clock_gettime(CLOCK_MONOTONIC, &b);
    } while ((b.tv_sec - a.tv_sec) * 1000 + (b.tv_nsec - a.tv_nsec) / 1000000 < ms);
}
"#;

const EXIT_APP: &str = r#"import ctypes, sys, threading, time
import systing_heap_hooks
systing_heap_hooks.install(backtrace="python", strict=True)
churn = ctypes.CDLL(sys.argv[1]).churn
def deep(n):
    if n:
        return deep(n - 1)
    churn(5000)
for _ in range(8):
    threading.Thread(target=deep, args=(30,), daemon=True).start()
time.sleep(0.3)
"#;

// A program with no Python in it asks for Python frames.
const NO_PYTHON_C: &str = r#"
#include <dlfcn.h>
#include <stdio.h>
int main(int argc, char **argv) {
    void *lib = dlopen(argv[1], RTLD_NOW);
    if (!lib) { puts(dlerror()); return 2; }
    int (*install)(const char *) = dlsym(lib, "systing_heap_hooks_install");
    const char *(*active)(void) = dlsym(lib, "systing_heap_hooks_active");
    const char *(*why)(int) = dlsym(lib, "systing_heap_hooks_strerror");
    int rc = install("python");
    printf("%d %s: %s\n", rc, active(), why(rc));
    return 0;
}
"#;

struct Env {
    jemalloc: PathBuf,
    pythons: Vec<(String, u32)>,
    lib: PathBuf,
    dir: tempfile::TempDir,
}

fn cc() -> Command {
    Command::new(std::env::var("CC").unwrap_or_else(|_| "cc".into()))
}

fn setup() -> Option<Env> {
    let (Some(jemalloc), pythons) = (common::jemalloc(), common::pythons()) else {
        common::skip("needs libjemalloc.so.2");
        return None;
    };
    if pythons.is_empty() {
        common::skip("needs Python 3.12+");
        return None;
    }
    let dir = tempfile::tempdir().unwrap();
    let lib = dir.path().join("libsysting_heap_hooks.so");
    let built = cc()
        .args([
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fPIC",
            "-shared",
            "-fno-omit-frame-pointer",
            "-o",
        ])
        .arg(&lib)
        .arg(Path::new(HOOKS).join("systing_heap_hooks.c"))
        .arg(Path::new(HOOKS).join("systing_heap_hooks_python.c"))
        .args(["-ldl", "-lpthread"])
        .status();
    if !built.is_ok_and(|s| s.success()) {
        common::skip("no C compiler to build the hooks library");
        return None;
    }
    Some(Env {
        jemalloc,
        pythons,
        lib,
        dir,
    })
}

/// Run `app` on `python` under jemalloc, its dumps in a directory of their
/// own, sampling one allocation per `2^lg_sample` bytes.
fn run(
    env: &Env,
    python: &str,
    name: &str,
    app: &str,
    lg_sample: u32,
    args: &[&Path],
) -> (PathBuf, Output) {
    let dumps = env.dir.path().join(format!("{name}-{python}"));
    std::fs::create_dir(&dumps).unwrap();
    let script = dumps.join("app.py");
    std::fs::write(&script, app).unwrap();
    let out = Command::new(python)
        .arg(&script)
        .args(args)
        .env("LD_PRELOAD", &env.jemalloc)
        .env(
            "MALLOC_CONF",
            format!(
                "prof:true,lg_prof_sample:{lg_sample},prof_prefix:{}/jeprof",
                dumps.display()
            ),
        )
        .env("SYSTING_HEAP_HOOKS_LIB", &env.lib)
        .env("PYTHONPATH", HOOKS)
        .output()
        .unwrap();
    (dumps, out)
}

fn succeeded(python: &str, out: &Output) -> String {
    assert!(
        out.status.success(),
        "{python}: {}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// systing-heap on every dump in `dumps`; each stack's frames, root first,
/// the stack holding the most live bytes first.
fn stacks(dumps: &Path) -> Vec<Vec<String>> {
    let db = dumps.join("heap.duckdb");
    let st = Command::new(BIN)
        .arg(dumps)
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
    let mut rows = conn
        .prepare(
            "SELECT h.stack_id, u.name FROM heap_sample h
             JOIN stack_frames sf ON sf.trace_id = h.trace_id AND sf.id = h.stack_id,
                  unnest(sf.frame_names) WITH ORDINALITY AS u(name, idx)
             ORDER BY h.live_bytes DESC, h.stack_id, u.idx",
        )
        .unwrap();
    let mut out: Vec<(i64, Vec<String>)> = Vec::new();
    for row in rows
        .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))
        .unwrap()
    {
        let (id, name) = row.unwrap();
        match out.last_mut() {
            Some((last, frames)) if *last == id => frames.push(name),
            _ => out.push((id, vec![name])),
        }
    }
    out.into_iter().map(|(_, frames)| frames).collect()
}

fn is_python(frame: &str) -> bool {
    frame.contains(" (python) ")
}

fn python_frames(frames: &[String]) -> Vec<&str> {
    frames
        .iter()
        .filter(|f| is_python(f))
        .map(String::as_str)
        .collect()
}

/// The largest stack that has `function` among its Python frames.
fn stack_of<'a>(stacks: &'a [Vec<String>], function: &str) -> &'a [String] {
    stacks
        .iter()
        .find(|s| {
            s.iter()
                .any(|f| f.starts_with(&format!("{function} (python) ")))
        })
        .unwrap_or_else(|| panic!("no stack through {function}: {stacks:#?}"))
}

#[test]
fn python_callers_have_their_file_and_line() {
    let Some(env) = setup() else { return };
    for (python, _) in &env.pythons {
        let (dumps, out) = run(&env, python, "lines", APP, 12, &[]);
        assert_eq!(succeeded(python, &out), "python False", "{python}");
        let stacks = stacks(&dumps);
        let frames = stack_of(&stacks, "leak_in_python");
        assert_eq!(
            python_frames(frames),
            vec![
                "<module> (python) [app.py:20]",
                "outer (python) [app.py:13]",
                "leak_in_python (python) [app.py:11]",
            ],
            "{python}: {frames:#?}"
        );
        // Among the native frames, where the interpreter ran them: its
        // start below, what allocated above, no bytecode loop left over.
        assert!(frames[0].starts_with("_start "), "{python}: {frames:#?}");
        assert!(!is_python(frames.last().unwrap()), "{python}: {frames:#?}");
        assert!(
            !frames
                .iter()
                .any(|f| f.starts_with("_PyEval_EvalFrameDefault")),
            "{python}: {frames:#?}"
        );
        // The library's own frame is not in the stack.
        assert!(
            !frames.iter().any(|f| f.contains("libsysting_heap_hooks")),
            "{python}: {frames:#?}"
        );
    }
}

#[test]
fn an_allocation_made_without_the_gil_has_its_python_callers() {
    let Some(env) = setup() else { return };
    for (python, _) in &env.pythons {
        let (dumps, out) = run(&env, python, "nogil", APP, 12, &[]);
        succeeded(python, &out);
        let stacks = stacks(&dumps);
        let frames = stack_of(&stacks, "leak_in_c");
        let python_frames = python_frames(frames);
        // Under threading's own frames, whose lines are the version's.
        assert!(
            python_frames[0].starts_with("threading:Thread._bootstrap (python) [threading.py:"),
            "{python}: {frames:#?}"
        );
        assert_eq!(
            python_frames[python_frames.len() - 2..],
            [
                "in_thread (python) [app.py:19]",
                "leak_in_c (python) [app.py:17]",
            ],
            "{python}: {frames:#?}"
        );
        // ctypes and libffi stand between Python and malloc.
        let at = frames
            .iter()
            .position(|f| f.starts_with("leak_in_c "))
            .unwrap();
        assert!(
            frames[at + 1..].iter().any(|f| f.contains("ffi_call")),
            "{python}: {frames:#?}"
        );
    }
}

#[test]
fn a_forked_worker_writes_a_code_map_of_its_own() {
    let Some(env) = setup() else { return };
    for (python, _) in &env.pythons {
        let (dumps, out) = run(&env, python, "fork", FORK_APP, 12, &[]);
        let pids = succeeded(python, &out);
        let (parent, worker) = pids.split_once(' ').unwrap();
        let maps_of = |pid: &str| {
            std::fs::read_dir(&dumps)
                .unwrap()
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .filter(|n| n.starts_with(&format!("pycode-{pid}-")) && n.ends_with(".map"))
                .count()
        };
        assert_eq!((maps_of(parent), maps_of(worker)), (1, 1), "{python}");
        // serve() was entered in the parent: the worker names it all the same.
        let stacks = stacks(&dumps);
        let frames = stack_of(&stacks, "leak_in_worker");
        assert_eq!(
            python_frames(frames),
            vec![
                "<module> (python) [app.py:16]",
                "serve (python) [app.py:11]",
                "leak_in_worker (python) [app.py:7]",
            ],
            "{python}: {frames:#?}"
        );
    }
}

#[test]
fn names_that_are_not_ascii_are_read_whole() {
    let Some(env) = setup() else { return };
    for (python, _) in &env.pythons {
        let (dumps, out) = run(&env, python, "wide", WIDE_NAMES_APP, 12, &[]);
        succeeded(python, &out);
        let stacks = stacks(&dumps);
        let frames = stack_of(&stacks, "caf\u{e9}");
        assert_eq!(
            python_frames(frames)[1..],
            [
                "<module> (python) [caf\u{e9}.py:8]",
                "\u{20000} (python) [caf\u{e9}.py:7]",
                "caf\u{e9} (python) [caf\u{e9}.py:5]",
            ],
            "{python}: {frames:#?}"
        );
    }
}

#[test]
fn a_forked_worker_names_the_stacks_sampled_before_the_fork() {
    let Some(env) = setup() else { return };
    for (python, _) in &env.pythons {
        let (dumps, out) = run(&env, python, "prefork", PREFORK_APP, 12, &[]);
        succeeded(python, &out);
        // The one dump is the worker's. What the parent allocated is in it
        // under the parent's ids, which the worker's map must name as the
        // parent's did: not with the functions the worker met first.
        let stacks = stacks(&dumps);
        let frames = stack_of(&stacks, "warm_cache");
        assert_eq!(
            python_frames(frames),
            vec![
                "<module> (python) [app.py:21]",
                "load_config (python) [app.py:12]",
                "warm_cache (python) [app.py:7]",
            ],
            "{python}: {frames:#?}"
        );
        let frames = stack_of(&stacks, "leak_in_worker");
        assert_eq!(
            python_frames(frames),
            vec![
                "<module> (python) [app.py:22]",
                "serve (python) [app.py:16]",
                "leak_in_worker (python) [app.py:10]",
            ],
            "{python}: {frames:#?}"
        );
        let unknown: Vec<_> = stacks
            .iter()
            .flatten()
            .filter(|f| f.starts_with("unknown (python)"))
            .collect();
        assert!(unknown.is_empty(), "{python}: {unknown:#?}");
    }
}

#[test]
fn a_forked_worker_does_not_keep_its_parents_memory_open() {
    let Some(env) = setup() else { return };
    let shim = env.dir.path().join("libnopvr.so");
    let src = env.dir.path().join("nopvr.c");
    std::fs::write(&src, NO_PROCESS_VM_READV_C).unwrap();
    let built = cc()
        .args(["-O2", "-fPIC", "-shared", "-o"])
        .arg(&shim)
        .arg(&src)
        .status()
        .unwrap();
    assert!(built.success());
    for (python, _) in &env.pythons {
        let (dumps, out) = run(&env, python, "mem-fork", MEM_FORK_APP, 12, &[&shim]);
        // The worker holds its own memory open and no other; so does the
        // parent.
        assert_eq!(succeeded(python, &out), "0 True [] 0", "{python}");
        // And it reads through it: its frames are named.
        let stacks = stacks(&dumps);
        let frames = python_frames(stack_of(&stacks, "leak_in_worker"));
        assert_eq!(
            frames.last().copied(),
            Some("leak_in_worker (python) [app.py:22]"),
            "{python}: {frames:#?}"
        );
    }
}

#[test]
fn a_code_map_replaced_behind_the_hook_is_neither_waited_for_nor_written_to() {
    let Some(env) = setup() else { return };
    for (python, _) in &env.pythons {
        for (what, said) in [
            ("fifo", "0 survived"),
            ("file", "0 application data"),
            ("rewritten", "0 application data"),
        ] {
            let dumps = env.dir.path().join(format!("replaced-{what}-{python}"));
            let (_, out) = run(
                &env,
                python,
                &format!("replaced-{what}"),
                REPLACED_MAP_APP,
                12,
                &[&dumps, Path::new(what)],
            );
            assert_eq!(succeeded(python, &out), said, "{python}, {what}");
            // The worker's map begins with its parent's lines only where
            // the parent's map is still the file the parent made: here it
            // holds the worker's own and no more.
            let workers: Vec<String> = std::fs::read_dir(&dumps)
                .unwrap()
                .map(|e| e.unwrap().path())
                .filter(|p| {
                    let name = p.file_name().unwrap().to_string_lossy().into_owned();
                    name.starts_with("pycode-") && std::fs::metadata(p).unwrap().is_file()
                })
                .map(|p| std::fs::read_to_string(p).unwrap())
                .filter(|text| text.starts_with("# systing-pycode 1 "))
                .collect();
            assert_eq!(workers.len(), 1, "{python}, {what}: {workers:?}");
            assert!(
                !workers[0].contains("application data"),
                "{python}, {what}: {workers:?}"
            );
        }
    }
}

#[test]
fn a_child_that_records_nothing_leaves_no_code_map() {
    let Some(env) = setup() else { return };
    for (python, _) in &env.pythons {
        // A sample period no child reaches before it execs.
        let (dumps, out) = run(&env, python, "exec", EXEC_APP, 30, &[]);
        let pids = succeeded(python, &out);
        let (parent, _) = pids.split_once(' ').unwrap();
        let maps: Vec<String> = std::fs::read_dir(&dumps)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.starts_with("pycode-"))
            .collect();
        assert_eq!(maps.len(), 1, "{python}: {maps:?}");
        assert!(
            maps[0].starts_with(&format!("pycode-{parent}-")),
            "{python}: {maps:?}"
        );
    }
}

#[test]
fn a_descriptor_the_program_closed_is_not_written_to() {
    let Some(env) = setup() else { return };
    for (python, _) in &env.pythons {
        let files = env.dir.path().join(format!("app-{python}-"));
        let (dumps, out) = run(&env, python, "closed", CLOSED_FDS_APP, 12, &[&files]);
        succeeded(python, &out);
        // Every file the program opened holds what the program wrote.
        for i in 0..16 {
            let path = format!("{}{i}", files.display());
            assert_eq!(
                std::fs::read_to_string(&path).unwrap(),
                "application data\nmore application data\n",
                "{python}: {path}"
            );
        }
        // And the function first met after the close is in the code map.
        let stacks = stacks(&dumps);
        assert_eq!(
            python_frames(stack_of(&stacks, "first_seen_after_the_close")),
            vec![
                "<module> (python) [app.py:12]",
                "first_seen_after_the_close (python) [app.py:11]",
            ],
            "{python}"
        );
    }
}

#[test]
fn frames_the_interpreter_hides_are_not_shown() {
    let Some(env) = setup() else { return };
    for (python, _) in &env.pythons {
        // install() runs beneath the specialized call: its check of the
        // walk against Python's own stack passes there too.
        let (dumps, out) = run(&env, python, "init", INIT_APP, 12, &[]);
        assert_eq!(succeeded(python, &out), "python", "{python}");
        let stacks = stacks(&dumps);
        let frames = stack_of(&stacks, "Holder.__init__");
        assert_eq!(
            python_frames(frames),
            vec![
                "<module> (python) [app.py:13]",
                "build (python) [app.py:9]",
                "Holder.__init__ (python) [app.py:5]",
            ],
            "{python}: {frames:#?}"
        );
    }
}

#[test]
fn a_native_backtrace_that_fills_the_array_leaves_the_python_frames() {
    let Some(env) = setup() else { return };
    let fill = env.dir.path().join("libfill.so");
    let src = env.dir.path().join("fill.c");
    std::fs::write(&src, FILLS_THE_ARRAY_C).unwrap();
    let built = cc()
        .args(["-O2", "-fPIC", "-shared", "-o"])
        .arg(&fill)
        .arg(&src)
        .arg("-ldl")
        .status()
        .unwrap();
    assert!(built.success());
    for (python, _) in &env.pythons {
        let (dumps, out) = run(&env, python, "deep", DEEP_APP, 12, &[&fill]);
        succeeded(python, &out);
        let stacks = stacks(&dumps);
        let frames = stack_of(&stacks, "rec");
        let python_frames = python_frames(frames);
        // Every level is there: the native stack gave up its outermost
        // frames to make room, not the Python ones theirs.
        let count = |what: &str| python_frames.iter().filter(|f| f.starts_with(what)).count();
        assert_eq!(
            (
                count("rec "),
                count("rec.<locals>.<lambda> "),
                count("<module> ")
            ),
            (21, 20, 1),
            "{python}: {frames:#?}"
        );
        assert!(frames.len() <= 128, "{python}: {}", frames.len());
        assert!(
            frames.iter().any(|f| !is_python(f)),
            "{python}: {frames:#?}"
        );
    }
}

#[test]
fn installing_again_keeps_the_code_map() {
    let Some(env) = setup() else { return };
    for (python, _) in &env.pythons {
        let (_, out) = run(&env, python, "twice", TWICE_APP, 12, &[]);
        assert_eq!(succeeded(python, &out), "True python True", "{python}");
    }
}

/// The hooks library built with `field` of every version's offsets set to
/// `value`.
fn built_with(env: &Env, field: &str, value: u32) -> PathBuf {
    let dir = env.dir.path().join(format!("src-{field}"));
    std::fs::create_dir(&dir).unwrap();
    for file in std::fs::read_dir(HOOKS).unwrap() {
        let file = file.unwrap().path();
        if file.extension().is_some_and(|e| e == "c" || e == "h") {
            std::fs::copy(&file, dir.join(file.file_name().unwrap())).unwrap();
        }
    }
    let header = dir.join("py_offsets.h");
    let text = std::fs::read_to_string(&header).unwrap();
    let changed: String = text
        .lines()
        .map(|l| match l.trim().strip_prefix(&format!(".{field} = ")) {
            Some(_) => format!("\t\t.{field} = {value},\n"),
            None => format!("{l}\n"),
        })
        .collect();
    assert_ne!(changed, text, "no {field} in py_offsets.h");
    std::fs::write(&header, changed).unwrap();
    let lib = dir.join("libsysting_heap_hooks.so");
    let built = cc()
        .args(["-O2", "-fPIC", "-shared", "-o"])
        .arg(&lib)
        .arg(dir.join("systing_heap_hooks.c"))
        .arg(dir.join("systing_heap_hooks_python.c"))
        .args(["-ldl", "-lpthread"])
        .status()
        .unwrap();
    assert!(built.success());
    lib
}

#[test]
fn a_python_laid_out_otherwise_is_refused() {
    let Some(mut env) = setup() else { return };
    // One wrong offset at a time, each of a kind a different build of
    // Python would bring: the walk goes wrong in its own way for each, and
    // the check before install must notice every one.
    for (field, value) in [
        ("ts_frame", 80),
        ("frame_previous", 16),
        ("frame_code", 24),
        ("frame_instr", 48),
        ("frame_owner", 69),
        ("ob_type", 16),
        ("code_firstlineno", 64),
        ("code_filename", 120),
        ("code_qualname", 120),
        ("code_linetable", 144),
        ("code_adaptive", 216),
        ("str_length", 24),
        ("str_state", 28),
        ("str_ascii_size", 48),
        // Where the text of a name that is not ASCII is: the check runs
        // beneath one.
        ("str_compact_size", 40),
        ("bytes_size", 24),
        ("bytes_data", 40),
        // A frame that has started taken for one that has not.
        ("code_firsttraceable", 76),
        // One hop too many (3.13, 3.14), or to the wrong place (3.12).
        ("cframe_current_frame", 8),
    ] {
        env.lib = built_with(&env, field, value);
        for (python, _) in &env.pythons {
            let (dumps, out) = run(
                &env,
                python,
                &format!("refused-{field}"),
                REPORT_APP,
                12,
                &[],
            );
            let said = succeeded(python, &out);
            assert!(
                said.starts_with("default | ")
                    && (said
                        .contains("python frames: this interpreter is not laid out as expected")),
                "{python}, {field} = {value}: {said}"
            );
            // Nothing of a backtrace that was not installed is left.
            let left: Vec<_> = std::fs::read_dir(&dumps)
                .unwrap()
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .filter(|n| n.starts_with("pycode-"))
                .collect();
            assert!(left.is_empty(), "{python}, {field}: {left:?}");
        }
    }
}

#[test]
fn a_broken_frame_chain_shortens_the_stack_and_nothing_else() {
    let Some(env) = setup() else { return };
    for (python, _) in &env.pythons {
        // Every allocation sampled: each one made on the broken chain is
        // walked.
        let (dumps, out) = run(&env, python, "broken", BROKEN_CHAIN_APP, 0, &[]);
        assert_eq!(succeeded(python, &out), "survived", "{python}");
        let stacks = stacks(&dumps);
        // Whole, the chain reaches the module.
        let whole = python_frames(stack_of(&stacks, "allocate"));
        assert_eq!(
            whole[..2],
            [
                "<module> (python) [app.py:37]",
                "caller (python) [app.py:35]"
            ],
            "{python}"
        );
        // Broken, a walk ends where the chain does: the frame that was
        // running is there, its callers are not, and the native stack is.
        let broken: Vec<&Vec<String>> = stacks
            .iter()
            .filter(|s| s.iter().any(|f| f.starts_with("broken (python) ")))
            .collect();
        assert!(!broken.is_empty(), "{python}: {stacks:#?}");
        for frames in broken {
            assert!(
                !frames.iter().any(|f| f.starts_with("caller (python) ")),
                "{python}: {frames:#?}"
            );
            assert!(frames[0].starts_with("_start "), "{python}: {frames:#?}");
        }
    }
}

#[test]
fn threads_allocating_while_the_interpreter_exits_do_not_crash_it() {
    let Some(env) = setup() else { return };
    let churn = env.dir.path().join("libchurn.so");
    let src = env.dir.path().join("churn.c");
    std::fs::write(&src, CHURN_C).unwrap();
    let built = cc()
        .args(["-O2", "-fPIC", "-shared", "-o"])
        .arg(&churn)
        .arg(&src)
        .status()
        .unwrap();
    assert!(built.success());
    for (python, _) in &env.pythons {
        for round in 0..5 {
            let (_, out) = run(
                &env,
                python,
                &format!("exit{round}"),
                EXIT_APP,
                0,
                &[&churn],
            );
            succeeded(python, &out);
        }
    }
}

#[test]
fn a_program_without_python_keeps_jemallocs_own_backtrace() {
    let Some(env) = setup() else { return };
    let exe = env.dir.path().join("no_python");
    let src = env.dir.path().join("no_python.c");
    std::fs::write(&src, NO_PYTHON_C).unwrap();
    let built = cc()
        .args(["-O2", "-o"])
        .arg(&exe)
        .arg(&src)
        .arg("-ldl")
        .status()
        .unwrap();
    assert!(built.success());
    let out = Command::new(&exe)
        .arg(&env.lib)
        .env("LD_PRELOAD", &env.jemalloc)
        .env("MALLOC_CONF", "prof:true")
        .output()
        .unwrap();
    assert_eq!(
        succeeded("no_python", &out),
        "6 default: no Python interpreter in this process (its symbols are not exported)"
    );
}
