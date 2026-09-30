//! What a backtrace may not do. It runs inside malloc, on top of whatever
//! called malloc, and that can be the dynamic loader in the middle of its own
//! work: nothing a backtrace calls may enter the loader then.
//!
//! The case these tests make happen: a thread's table of thread-local blocks
//! has to grow after a library with thread-local variables is loaded, which
//! glibc does with realloc(). If that call is sampled and the backtrace reads a
//! thread-local variable through the loader's `__tls_get_addr()`, its own or
//! one of a library it calls, the loader starts the same update again, and
//! reallocates the same table. The outer realloc() then frees a block that has
//! been freed: from there on the allocator can give the same memory out twice.
//! "libunwind" did this through libunwind's variables, and "python" through the
//! interpreter's, where libpython is a shared library. `hooks/README.md` has the
//! whole account, and who else has met it.

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::HOOKS;

/// Enough libraries for the table to grow several times (glibc leaves room for
/// 14 more each time), the first of which is not by realloc().
const LIBRARIES: usize = 64;

/// What the shim ends the process with when it sees the table reallocated
/// inside its own reallocation.
const CAUGHT: i32 = 42;

const THREAD_LOCAL_C: &str = r#"
static __thread long v = 1;
long touch(void) { return ++v; }
"#;

// Goes in front of jemalloc. The programs here have one thread, so plain
// statics do, and the shim itself has nothing thread-local.
const SHIM_C: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>
#include <unistd.h>
static void *(*next)(void *, size_t);
static int depth;
static void *outer;
void *realloc(void *p, size_t n)
{
    if (!next)
        next = (void *(*)(void *, size_t))dlsym(RTLD_NEXT, "realloc");
    if (depth > 0 && p && p == outer) {
        static const char said[] = "realloc() of a block from inside realloc() of it\n";
        if (write(2, said, sizeof said - 1) < 0) {}
        _exit(42);
    }
    if (depth == 0)
        outer = p;
    depth++;
    void *r = next(p, n);
    depth--;
    return r;
}
"#;

// A backtrace that breaks the rule in the smallest way there is.
const BREAKS_THE_RULE_C: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>
typedef void (*backtrace_fn)(void **, unsigned *, unsigned);
static __thread volatile unsigned long calls;
static backtrace_fn jemallocs_own;
static void counts_its_calls(void **vec, unsigned *len, unsigned max_len)
{
    calls++;
    jemallocs_own(vec, len, max_len);
}
int systing_heap_hooks_install(const char *backtrace)
{
    (void)backtrace;
    int (*mallctl)(const char *, void *, size_t *, void *, size_t) = dlsym(RTLD_DEFAULT, "mallctl");
    backtrace_fn mine = counts_its_calls;
    size_t len = sizeof(jemallocs_own);
    return mallctl("experimental.hooks.prof_backtrace", &jemallocs_own, &len, &mine, sizeof(mine));
}
"#;

// Loads the libraries one after another and touches each one's variable, as a
// program that imports extension modules does.
const LOADS_LIBRARIES_C: &str = r#"
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv)
{
    if (argc != 5)
        return 2;
    void *hooks = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!hooks) {
        fprintf(stderr, "%s\n", dlerror());
        return 2;
    }
    int rc = ((int (*)(const char *))dlsym(hooks, "systing_heap_hooks_install"))(argv[2]);
    if (rc != 0) {
        fprintf(stderr, "install: %d\n", rc);
        return 2;
    }
    for (int i = 0; i < atoi(argv[4]); i++) {
        char path[4096];
        snprintf(path, sizeof path, "%s/thread_local_%d.so", argv[3], i);
        void *lib = dlopen(path, RTLD_NOW | RTLD_LOCAL);
        if (!lib) {
            fprintf(stderr, "%s\n", dlerror());
            return 2;
        }
        ((long (*)(void))dlsym(lib, "touch"))();
    }
    return 0;
}
"#;

const LOADS_LIBRARIES_PY: &str = r#"
import ctypes, os, sys
import systing_heap_hooks
systing_heap_hooks.install(backtrace=sys.argv[1], strict=True)
for i in range(int(sys.argv[3])):
    ctypes.CDLL(f"{sys.argv[2]}/thread_local_{i}.so").touch()
try:
    os.unlink(f"/tmp/perf-{os.getpid()}.map")
except OSError:
    pass
"#;

// Sampling is off until here, so that the first allocation sampled is this one:
// libunwind's first check of an address is the one that changes errno.
const ERRNO_C: &str = r#"
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
int mallctl(const char *, void *, size_t *, void *, size_t);
int errno_after_malloc(void)
{
    bool on = true;
    mallctl("prof.active", NULL, NULL, &on, sizeof on);
    errno = 4242;
    void *volatile p = malloc(1 << 16);
    int after = errno;
    free(p);
    return after;
}
"#;

// Under trampolines, which have no unwind tables: past them libunwind checks
// each address before it reads it, through a pipe that is empty the first time.
const ERRNO_PY: &str = r#"
import ctypes, os, sys
import systing_heap_hooks
systing_heap_hooks.install(backtrace=sys.argv[1], trampolines=True, strict=True)
lib = ctypes.CDLL(sys.argv[2])
def inner():
    return lib.errno_after_malloc()
def outer():
    return inner()
changed = {e for e in (outer() for _ in range(100)) if e != 4242}
os.unlink(f"/tmp/perf-{os.getpid()}.map")
sys.exit(f"errno after malloc: {changed}" if changed else 0)
"#;

// What `python3` is where libpython is a shared library.
const PYTHON_C: &str = r#"
int Py_BytesMain(int, char **);
int main(int argc, char **argv) { return Py_BytesMain(argc, argv); }
"#;

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
    let built = cmd.arg("-ldl").output().unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    out
}

struct Env {
    jemalloc: PathBuf,
    dir: tempfile::TempDir,
    shim: PathBuf,
}

fn setup() -> Option<Env> {
    let Some(jemalloc) = common::jemalloc() else {
        common::skip("needs libjemalloc.so.2");
        return None;
    };
    if !common::have_libunwind() {
        common::skip("needs libunwind.so.8");
        return None;
    }
    let dir = tempfile::tempdir().unwrap();
    if !common::make_hooks(Path::new(HOOKS), dir.path()) {
        return None;
    }
    // One library under many names is as many libraries to the loader.
    let one = cc(dir.path(), "thread_local", THREAD_LOCAL_C, true);
    for i in 0..LIBRARIES {
        std::fs::copy(&one, dir.path().join(format!("thread_local_{i}.so"))).unwrap();
    }
    let shim = cc(dir.path(), "shim", SHIM_C, true);
    Some(Env {
        jemalloc,
        dir,
        shim,
    })
}

/// Run `cmd` under the shim and jemalloc with every allocation sampled, so
/// that the table's reallocation is. A dump is written as the program ends.
fn sampled(env: &Env, cmd: &mut Command) -> Output {
    sampled_with(env, cmd, "")
}

/// The same, with more for jemalloc's configuration.
fn sampled_with(env: &Env, cmd: &mut Command, conf: &str) -> Output {
    cmd.env(
        "LD_PRELOAD",
        format!("{} {}", env.shim.display(), env.jemalloc.display()),
    )
    .env(
        "MALLOC_CONF",
        format!(
            "prof:true,lg_prof_sample:0,prof_final:true,prof_prefix:{}/jeprof{conf}",
            env.dir.path().display()
        ),
    )
    .output()
    .unwrap()
}

fn native(env: &Env, hooks: &Path, backtrace: &str) -> Output {
    let program = env.dir.path().join("loads_libraries");
    if !program.exists() {
        cc(env.dir.path(), "loads_libraries", LOADS_LIBRARIES_C, false);
    }
    sampled(
        env,
        Command::new(program)
            .arg(hooks)
            .arg(backtrace)
            .arg(env.dir.path())
            .arg(LIBRARIES.to_string()),
    )
}

/// Whether these tests can tell here: a backtrace that breaks the rule is
/// caught. Where it is not, the C library has changed and the tests below
/// would pass whatever the backtraces did.
fn the_trap_works(env: &Env) -> bool {
    let bad = cc(env.dir.path(), "breaks_the_rule", BREAKS_THE_RULE_C, true);
    let out = native(env, &bad, "");
    if out.status.code() == Some(CAUGHT) {
        return true;
    }
    common::skip(&format!(
        "a backtrace that reads a __thread variable is not caught here ({}): {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    ));
    false
}

#[test]
fn no_backtrace_of_a_native_program_enters_the_loader() {
    let Some(env) = setup() else { return };
    if !the_trap_works(&env) {
        return;
    }
    let hooks = env.dir.path().join("libsysting_heap_hooks.so");
    for backtrace in ["default", "libunwind"] {
        let out = native(&env, &hooks, backtrace);
        assert!(
            out.status.success(),
            "{backtrace}: {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// The stacks of a dump, innermost frame first, each frame as the file it is in.
fn stacks_by_file(dump: &Path) -> Vec<Vec<String>> {
    let text = std::fs::read_to_string(dump).unwrap();
    let (stacks, maps) = text.split_once("MAPPED_LIBRARIES:").unwrap();
    let hex = |s: &str| u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap();
    let maps: Vec<(u64, u64, &str)> = maps
        .lines()
        .filter_map(|l| {
            let (range, rest) = l.split_once(' ')?;
            let (start, end) = range.split_once('-')?;
            let file = rest.rsplit('/').next()?;
            Some((hex(start), hex(end), file))
        })
        .collect();
    stacks
        .lines()
        .filter_map(|l| l.strip_prefix("@ "))
        .map(|l| {
            l.split_whitespace()
                .map(|pc| {
                    let pc = hex(pc);
                    maps.iter()
                        .find(|(start, end, _)| (*start..*end).contains(&pc))
                        .map_or("?", |m| m.2)
                        .to_string()
                })
                .collect()
        })
        .collect()
}

/// Where the loader called malloc the stack is jemalloc's own, and starts where
/// jemalloc's own does: nothing of the hook's is between the two.
#[test]
fn what_the_loader_allocates_has_the_stack_jemalloc_gives_it() {
    let Some(env) = setup() else { return };
    let hooks = env.dir.path().join("libsysting_heap_hooks.so");
    let out = native(&env, &hooks, "libunwind");
    assert!(
        out.status.success(),
        "{}: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let dump = std::fs::read_dir(env.dir.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "heap"))
        .expect("jemalloc wrote no dump");
    let mut of_the_loader = 0;
    for stack in stacks_by_file(&dump) {
        let Some(loader) = stack.iter().position(|f| f.starts_with("ld-")) else {
            continue;
        };
        of_the_loader += 1;
        assert!(
            !stack[..loader]
                .iter()
                .any(|f| f.starts_with("libsysting") || f.starts_with("libunwind")),
            "{stack:#?}"
        );
    }
    assert!(of_the_loader > 0, "no allocation of the loader's is live");
}

/// Run the Python program with `python` under each backtrace it can have.
fn python_program(env: &Env, python: &Path) {
    let app = env.dir.path().join("loads_libraries.py");
    std::fs::write(&app, LOADS_LIBRARIES_PY).unwrap();
    for backtrace in ["default", "python", "libunwind"] {
        let mut child = Command::new(python);
        child
            .arg(&app)
            .arg(backtrace)
            .arg(env.dir.path())
            .arg(LIBRARIES.to_string())
            .env(
                "SYSTING_HEAP_HOOKS_LIB",
                env.dir.path().join("libsysting_heap_hooks.so"),
            )
            .env("PYTHONPATH", HOOKS);
        let out = sampled(env, &mut child);
        assert!(
            out.status.success(),
            "{} with {backtrace}: {}: {}",
            python.display(),
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn no_backtrace_of_a_python_program_enters_the_loader() {
    let Some(env) = setup() else { return };
    let pythons = common::pythons();
    if pythons.is_empty() {
        common::skip("needs Python 3.12+");
        return;
    }
    if !the_trap_works(&env) {
        return;
    }
    for (python, _) in pythons {
        python_program(&env, Path::new(&python));
    }
}

/// The shared libpython of `python`, if it has one that reads its thread-local
/// variables through the loader. Some are built so as not to
/// (`-ftls-model=initial-exec`), and a `python3` that has the interpreter
/// linked in does not either.
fn libpython_that_asks_the_loader(python: &str) -> Option<PathBuf> {
    let out = Command::new(python)
        .args([
            "-c",
            "import sysconfig as s; print(s.get_config_var('LIBDIR'), s.get_config_var('INSTSONAME'), sep='/')",
        ])
        .output()
        .ok()?;
    let lib = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim());
    if lib.extension().is_some_and(|e| e == "a") || !lib.exists() {
        return None;
    }
    let symbols = Command::new("readelf")
        .args(["--dyn-syms", "-W"])
        .arg(&lib)
        .output()
        .ok()?;
    String::from_utf8_lossy(&symbols.stdout)
        .contains("__tls_get_addr")
        .then_some(lib)
}

/// The interpreter's own thread state is a thread-local variable, and the
/// "python" backtrace asks the interpreter for it.
#[test]
fn nor_where_the_interpreters_own_variables_are_read_through_it() {
    let Some(env) = setup() else { return };
    let Some(lib) = common::pythons()
        .iter()
        .find_map(|(python, _)| libpython_that_asks_the_loader(python))
    else {
        common::skip(
            "needs a shared libpython that calls __tls_get_addr (Ubuntu: libpython3.12t64)",
        );
        return;
    };
    if !the_trap_works(&env) {
        return;
    }
    let src = env.dir.path().join("python.c");
    std::fs::write(&src, PYTHON_C).unwrap();
    let python = env.dir.path().join("python");
    let built = Command::new(std::env::var("CC").unwrap_or_else(|_| "cc".into()))
        .arg("-o")
        .arg(&python)
        .arg(&src)
        .arg(&lib)
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    python_program(&env, &python);
}

/// A malloc that succeeds is expected to leave errno alone.
#[test]
fn a_sampled_malloc_leaves_errno_as_it_was() {
    let Some(env) = setup() else { return };
    let Some((python, _)) = common::python() else {
        common::skip("needs Python 3.12+");
        return;
    };
    let lib = cc(env.dir.path(), "errno_after_malloc", ERRNO_C, true);
    let app = env.dir.path().join("errno.py");
    std::fs::write(&app, ERRNO_PY).unwrap();
    for backtrace in ["default", "python", "libunwind"] {
        let mut child = Command::new(&python);
        child
            .arg(&app)
            .arg(backtrace)
            .arg(&lib)
            .env(
                "SYSTING_HEAP_HOOKS_LIB",
                env.dir.path().join("libsysting_heap_hooks.so"),
            )
            .env("PYTHONPATH", HOOKS);
        let out = sampled_with(&env, &mut child, ",prof_active:false");
        assert!(
            out.status.success(),
            "{backtrace}: {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// The two ways into the loader that can be seen in the file: a thread-local
/// variable of the library's own, and a function left to be bound at its first
/// call.
#[test]
fn the_libraries_leave_the_loader_nothing_to_do_later() {
    let dir = tempfile::tempdir().unwrap();
    if !common::make_hooks(Path::new(HOOKS), dir.path()) {
        return;
    }
    for lib in ["libsysting_heap_hooks.so", "libsysting_heap_responder.so"] {
        let Ok(out) = Command::new("readelf")
            .args(["-ldW", "--dyn-syms"])
            .arg(dir.path().join(lib))
            .output()
        else {
            common::skip("needs readelf");
            return;
        };
        assert!(out.status.success());
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            !text
                .lines()
                .any(|l| l.split_whitespace().next() == Some("TLS")),
            "{lib} has thread-local variables:\n{text}"
        );
        assert!(
            !text.contains("__tls_get_addr"),
            "{lib} calls __tls_get_addr:\n{text}"
        );
        assert!(
            text.contains("BIND_NOW") || text.contains(" NOW"),
            "{lib} is not bound when it is loaded:\n{text}"
        );
    }
}
