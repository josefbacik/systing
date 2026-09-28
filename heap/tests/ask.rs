//! `--ask` (experimental): a running process asked for a heap dump, for
//! real. The responder on each installed Python (3.12 to 3.14) under jemalloc
//! with the hooks library; the interpreter's remote debugging interface on
//! Python 3.14. Skipped (with a note) where there is no jemalloc, C compiler
//! or Python; see `common::skip`.
//!
//! Set `SYSTING_HEAP_TEST_PYTHON` and `SYSTING_HEAP_TEST_JEMALLOC` to a
//! Python and a libjemalloc that loads into it to run the same tests on that
//! pair as well: a Python 3.14 that is not installed as `python3.14`, say.

mod common;

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use duckdb::Connection;

const BIN: &str = env!("CARGO_BIN_EXE_systing-heap");
use common::HOOKS;

// A service with the hooks: Python frames in its stacks, and a responder.
// Its main thread then waits in one call, as a service's does that leaves
// the work to other threads.
const SERVICE: &str = r#"import ctypes, os, sys, time
import systing_heap_hooks
# Its memory is read by a tool that the tests start beside it and not above
# it: where kernel.yama.ptrace_scope is 1 that takes the process's leave.
ctypes.CDLL(None).prctl(0x59616d61, ctypes.c_ulong(-1), 0, 0, 0)
systing_heap_hooks.install(backtrace="python", strict=True)
print("listening", systing_heap_hooks.listen(sys.argv[1], strict=True), flush=True)
keep = []
def leak_in_python(n):
    for _ in range(n):
        keep.append(bytearray(64 * 1024))
def outer():
    leak_in_python(256)
outer()
if sys.argv[2] == "fork":
    pid = os.fork()
    if pid == 0:
        print("child", os.getpid(), flush=True)
        time.sleep(3600)
print("ready", flush=True)
while sys.argv[2] == "loop":
    time.sleep(0.01)
time.sleep(3600)
"#;

// A service as it is: nothing of ours is imported or called, and its main
// thread waits in one call. With `fork` it has forked a worker first.
const UNCHANGED: &str = r#"import os, sys, time
keep = [bytearray(64 * 1024) for _ in range(256)]
if sys.argv[1] == "fork":
    pid = os.fork()
    if pid == 0:
        print("child", os.getpid(), flush=True)
        time.sleep(3600)
print("ready", flush=True)
time.sleep(3600)
"#;

// A Python that loaded nothing of ours. `loop` comes back to Python every few
// milliseconds; `sleep` is in one call that does not. Its memory is opened by
// the tool, which the tests start beside it and not above it: where
// kernel.yama.ptrace_scope is 1 that takes the process's leave.
const PLAIN: &str = r#"import ctypes, sys, time
PR_SET_PTRACER, PR_SET_PTRACER_ANY = 0x59616d61, ctypes.c_ulong(-1)
ctypes.CDLL(None).prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0)
keep = []
def leak_in_python(n):
    for _ in range(n):
        keep.append(bytearray(64 * 1024))
leak_in_python(256)
print("ready", flush=True)
if sys.argv[1] == "loop":
    while True:
        time.sleep(0.01)
time.sleep(3600)
"#;

/// A Python and a jemalloc that loads into it.
#[derive(Debug, Clone)]
struct Pair {
    python: String,
    minor: u32,
    jemalloc: PathBuf,
}

fn minor_of(python: &str) -> Option<u32> {
    let out = Command::new(python)
        .args(["-c", "import sys; print(sys.version_info[1])"])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

/// The pairs to run on: every installed Python with the system's jemalloc,
/// and the pair the environment names.
fn pairs() -> Vec<Pair> {
    let mut pairs = Vec::new();
    if let Some(jemalloc) = common::jemalloc() {
        for (python, minor) in common::pythons() {
            pairs.push(Pair {
                python,
                minor,
                jemalloc: jemalloc.clone(),
            });
        }
    }
    if let (Some(python), Some(jemalloc)) = (
        std::env::var_os("SYSTING_HEAP_TEST_PYTHON"),
        std::env::var_os("SYSTING_HEAP_TEST_JEMALLOC"),
    ) {
        let python = python.to_string_lossy().into_owned();
        match minor_of(&python) {
            Some(minor) => pairs.push(Pair {
                python,
                minor,
                jemalloc: PathBuf::from(jemalloc),
            }),
            None => panic!("SYSTING_HEAP_TEST_PYTHON={python} does not run"),
        }
    }
    pairs
}

/// The pairs whose Python is 3.14, or none with a note. It is a note also
/// where `common::skip` would fail the test: the runners CI has come with an
/// older Python, so a run there says nothing of what is asked of 3.14, and
/// the tests that need one say so in their output instead of failing.
fn pairs_314() -> Vec<Pair> {
    let pairs: Vec<Pair> = pairs().into_iter().filter(|p| p.minor == 14).collect();
    if pairs.is_empty() {
        eprintln!(
            "skipped: needs Python 3.14 and a libjemalloc.so.2 (SYSTING_HEAP_TEST_PYTHON \
             and SYSTING_HEAP_TEST_JEMALLOC name a pair)"
        );
    }
    pairs
}

struct Env {
    dir: tempfile::TempDir,
}

impl Env {
    /// Where sockets are: a short path, as a Unix socket's must be.
    fn sockets(&self) -> PathBuf {
        self.dir.path().join("s")
    }
}

/// A directory with the scripts in it and, with `hooks`, the library.
fn setup(hooks: bool) -> Option<Env> {
    // In /tmp by name: the socket's path has to fit a Unix socket's address,
    // and TMPDIR can be long.
    let dir = tempfile::Builder::new()
        .prefix("ask.")
        .tempdir_in("/tmp")
        .unwrap();
    std::fs::create_dir(dir.path().join("s")).unwrap();
    std::fs::write(dir.path().join("service.py"), SERVICE).unwrap();
    std::fs::write(dir.path().join("plain.py"), PLAIN).unwrap();
    std::fs::write(dir.path().join("unchanged.py"), UNCHANGED).unwrap();
    if hooks {
        if !common::make_hooks(Path::new(HOOKS), dir.path()) {
            return None;
        }
        std::fs::copy(
            Path::new(HOOKS).join("systing_heap_hooks.py"),
            dir.path().join("systing_heap_hooks.py"),
        )
        .unwrap();
    }
    Some(Env { dir })
}

/// How a target is run: the script and its arguments, options of Python's
/// own before them, more environment, jemalloc's `prof` setting and more
/// of its settings, and a library loaded into it beside jemalloc.
struct Run<'a> {
    script: &'a str,
    args: &'a [&'a str],
    options: &'a [&'a str],
    env: &'a [(&'a str, &'a str)],
    prof: bool,
    conf: &'a str,
    preload: Option<&'a Path>,
}

impl<'a> Run<'a> {
    fn of(script: &'a str, args: &'a [&'a str]) -> Run<'a> {
        Run {
            script,
            args,
            options: &[],
            env: &[],
            prof: true,
            conf: "",
            preload: None,
        }
    }
}

/// A running Python, killed when dropped.
struct Target {
    child: Child,
    lines: BufReader<std::process::ChildStdout>,
}

impl Target {
    /// A script of `env` under `pair`; it has printed "ready" when this
    /// returns.
    fn start(env: &Env, pair: &Pair, run: Run) -> Target {
        let mut target = Target::spawn(env, pair, run);
        target.wait_for("ready");
        target
    }

    fn spawn(env: &Env, pair: &Pair, run: Run) -> Target {
        let mut cmd = Command::new(&pair.python);
        cmd.args(run.options)
            .arg(env.dir.path().join(run.script))
            .args(run.args)
            .env(
                "LD_PRELOAD",
                match run.preload {
                    Some(library) => format!("{}:{}", pair.jemalloc.display(), library.display()),
                    None => pair.jemalloc.display().to_string(),
                },
            )
            .env("PYTHONMALLOC", "malloc")
            .env(
                "MALLOC_CONF",
                format!(
                    "prof:{},lg_prof_sample:16,prof_prefix:{}/jeprof{}",
                    run.prof,
                    env.dir.path().display(),
                    run.conf
                ),
            )
            .env("PYTHONPATH", env.dir.path())
            .env_remove("PYTHON_DISABLE_REMOTE_DEBUG")
            .envs(run.env.iter().copied())
            .current_dir(env.dir.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut child = cmd.spawn().unwrap();
        let lines = BufReader::new(child.stdout.take().unwrap());
        Target { child, lines }
    }

    /// The rest of the first line that starts with `word`.
    fn wait_for(&mut self, word: &str) -> String {
        self.wait_for_each(&[word]).remove(0)
    }

    /// The rest of the first line that starts with each of `words`, in the
    /// order of `words`: the lines may come in any order, as those of a
    /// process and of one it forked do.
    fn wait_for_each(&mut self, words: &[&str]) -> Vec<String> {
        let mut found: Vec<Option<String>> = vec![None; words.len()];
        while found.iter().any(Option::is_none) {
            let mut line = String::new();
            let n = self.lines.read_line(&mut line).unwrap();
            assert_ne!(n, 0, "the target ended before it said all of {words:?}");
            for (word, slot) in words.iter().zip(found.iter_mut()) {
                if let (None, Some(rest)) = (&slot, line.trim_end().strip_prefix(word)) {
                    *slot = Some(rest.trim().to_string());
                }
            }
        }
        found.into_iter().flatten().collect()
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn is_running(&mut self) -> bool {
        self.child.try_wait().unwrap().is_none()
    }
}

impl Drop for Target {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn kill(pid: u32) {
    // SAFETY: a signal to a process this test started.
    unsafe { libc::kill(pid as i32, libc::SIGKILL) };
}

/// `systing-heap --pid <pid> --ask <how> ...`, writing `out`.
fn ask(pid: u32, how: &str, out: &Path, more: &[&str]) -> Output {
    Command::new(BIN)
        .args(["--pid", &pid.to_string(), "--ask", how, "-o"])
        .arg(out)
        .args(more)
        .env("RUST_BACKTRACE", "0")
        .output()
        .unwrap()
}

fn said(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// The one snapshot in `db`: (trigger, source, samples).
fn snapshot(db: &Path) -> (String, String, i64) {
    let conn = Connection::open(db).unwrap();
    let (trigger, source): (String, String) = conn
        .query_row(
            "SELECT dump_trigger, source_path FROM heap_snapshot",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    let samples = conn
        .query_row("SELECT count(*) FROM heap_sample", [], |r| r.get(0))
        .unwrap();
    (trigger, source, samples)
}

/// Every frame name in `db`.
fn frames(db: &Path) -> Vec<String> {
    let conn = Connection::open(db).unwrap();
    let mut rows = conn
        .prepare(
            "SELECT DISTINCT u.name FROM heap_sample h
             JOIN stack_frames sf ON sf.trace_id = h.trace_id AND sf.id = h.stack_id,
                  unnest(sf.frame_names) AS u(name)",
        )
        .unwrap();
    rows.query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn names_python_function(frames: &[String], function: &str) -> bool {
    frames
        .iter()
        .any(|f| f.starts_with(&format!("{function} (python) ")))
}

/// What is left in `dir` of a request made through the interpreter.
fn left_behind(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with(".systing-heap-ask."))
        })
        .collect()
}

#[test]
fn a_responder_answers_while_the_main_thread_waits() {
    let Some(env) = setup(true) else { return };
    let pairs = pairs();
    if pairs.is_empty() {
        common::skip("needs libjemalloc.so.2 and Python 3.12+");
    }
    for pair in pairs {
        let sockets = env.sockets();
        let target = Target::start(
            &env,
            &pair,
            Run::of("service.py", &[sockets.to_str().unwrap(), "stay"]),
        );
        let db = env
            .dir
            .path()
            .join(format!("responder-{}.duckdb", pair.minor));
        let out = ask(
            target.pid(),
            "responder",
            &db,
            &["--ask-dir", sockets.to_str().unwrap()],
        );
        assert!(out.status.success(), "{pair:?}: {}", said(&out));
        let (trigger, source, samples) = snapshot(&db);
        assert_eq!(trigger, "asked", "{pair:?}");
        assert_eq!(
            Path::new(&source),
            sockets.join(format!(".systing-heap.{}", target.pid())),
            "{pair:?}"
        );
        assert!(samples > 0, "{pair:?}");
        // The code map came with the dump: nothing said where it is.
        let frames = frames(&db);
        assert!(
            names_python_function(&frames, "leak_in_python"),
            "{pair:?}: {frames:#?}"
        );
        assert!(
            names_python_function(&frames, "outer"),
            "{pair:?}: {frames:#?}"
        );
        // Nothing was written for it: the folder has the code map alone.
        let dumps: Vec<_> = std::fs::read_dir(env.dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".heap"))
            .collect();
        assert!(dumps.is_empty(), "{pair:?}: {dumps:?}");
    }
}

/// The sockets in `dir`, by the pid in their names.
fn sockets_in(dir: &Path) -> Vec<u32> {
    let mut pids: Vec<u32> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| {
            let name = e.unwrap().file_name();
            name.to_str()?.strip_prefix(".systing-heap.")?.parse().ok()
        })
        .collect();
    pids.sort();
    pids
}

#[test]
fn a_service_that_is_not_changed_answers_when_its_environment_says_so() {
    let Some(env) = setup(true) else { return };
    let Some(pair) = pairs().into_iter().next() else {
        common::skip("needs libjemalloc.so.2 and Python 3.12+");
        return;
    };
    let sockets = env.sockets();
    // The library that is the responder alone: it has nothing of Python in it.
    let library = env.dir.path().join("libsysting_heap_responder.so");
    let switched_on = [
        ("SYSTING_HEAP_HOOKS_LISTEN", "1"),
        ("SYSTING_HEAP_HOOKS_SOCKET_DIR", sockets.to_str().unwrap()),
    ];
    let target = Target::start(
        &env,
        &pair,
        Run {
            env: &switched_on,
            preload: Some(&library),
            ..Run::of("unchanged.py", &["stay"])
        },
    );
    assert_eq!(sockets_in(&sockets), vec![target.pid()]);
    let db = env.dir.path().join("unchanged.duckdb");
    let out = ask(
        target.pid(),
        "responder",
        &db,
        &["--ask-dir", sockets.to_str().unwrap()],
    );
    assert!(out.status.success(), "{}", said(&out));
    let (trigger, _, samples) = snapshot(&db);
    assert_eq!(trigger, "asked");
    assert!(samples > 0);
}

#[test]
fn a_library_that_is_loaded_and_not_asked_does_nothing() {
    let Some(env) = setup(true) else { return };
    let Some(pair) = pairs().into_iter().next() else {
        common::skip("needs libjemalloc.so.2 and Python 3.12+");
        return;
    };
    let sockets = env.sockets();
    for library in ["libsysting_heap_responder.so", "libsysting_heap_hooks.so"] {
        let library = env.dir.path().join(library);
        let target = Target::start(
            &env,
            &pair,
            Run {
                env: &[("SYSTING_HEAP_HOOKS_SOCKET_DIR", sockets.to_str().unwrap())],
                preload: Some(&library),
                ..Run::of("unchanged.py", &["stay"])
            },
        );
        assert_eq!(sockets_in(&sockets), Vec::<u32>::new(), "{library:?}");
        let threads = std::fs::read_dir(format!("/proc/{}/task", target.pid()))
            .unwrap()
            .count();
        assert_eq!(threads, 1, "{library:?}");
    }
}

#[test]
fn the_processes_a_service_forks_answer_when_its_environment_says_so() {
    let Some(env) = setup(true) else { return };
    let Some(pair) = pairs().into_iter().next() else {
        common::skip("needs libjemalloc.so.2 and Python 3.12+");
        return;
    };
    let library = env.dir.path().join("libsysting_heap_responder.so");
    for (how, children_listen) in [("fork", true), ("1", false)] {
        let sockets = env.dir.path().join(format!("s-{how}"));
        std::fs::create_dir(&sockets).unwrap();
        let mut target = Target::spawn(
            &env,
            &pair,
            Run {
                env: &[
                    ("SYSTING_HEAP_HOOKS_LISTEN", how),
                    ("SYSTING_HEAP_HOOKS_SOCKET_DIR", sockets.to_str().unwrap()),
                    // Python says that a process with a thread forks.
                    ("PYTHONWARNINGS", "ignore"),
                ],
                preload: Some(&library),
                ..Run::of("unchanged.py", &["fork"])
            },
        );
        let child: u32 = target.wait_for_each(&["child", "ready"])[0]
            .parse()
            .unwrap();
        let db = env.dir.path().join(format!("forked-{how}.duckdb"));
        let out = ask(
            child,
            "responder",
            &db,
            &["--ask-dir", sockets.to_str().unwrap()],
        );
        let parent = ask(
            target.pid(),
            "responder",
            &db,
            &["--ask-dir", sockets.to_str().unwrap()],
        );
        kill(child);
        assert!(parent.status.success(), "{how}: {}", said(&parent));
        assert_eq!(
            out.status.success(),
            children_listen,
            "{how}: {}",
            said(&out)
        );
        if !children_listen {
            assert!(
                said(&out).contains("has no responder"),
                "{how}: {}",
                said(&out)
            );
        }
    }
}

#[test]
fn a_switch_that_cannot_be_followed_says_so_and_the_service_runs() {
    let Some(env) = setup(true) else { return };
    let Some(pair) = pairs().into_iter().next() else {
        common::skip("needs libjemalloc.so.2 and Python 3.12+");
        return;
    };
    let library = env.dir.path().join("libsysting_heap_responder.so");
    let sockets = env.sockets();
    for (how, prof, why) in [
        ("yes", true, "expected 1"),
        ("1", false, "profiling is off"),
    ] {
        let mut cmd = Command::new(&pair.python);
        let out = cmd
            .args(["-c", "print('ran')"])
            .env(
                "LD_PRELOAD",
                format!("{}:{}", pair.jemalloc.display(), library.display()),
            )
            .env("MALLOC_CONF", format!("prof:{prof}"))
            .env("SYSTING_HEAP_HOOKS_LISTEN", how)
            .env("SYSTING_HEAP_HOOKS_SOCKET_DIR", &sockets)
            .output()
            .unwrap();
        assert!(out.status.success(), "{how}");
        assert_eq!(String::from_utf8_lossy(&out.stdout), "ran\n", "{how}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("SYSTING_HEAP_HOOKS_LISTEN") && err.contains(why),
            "{how}: {err}"
        );
    }
    assert_eq!(sockets_in(&sockets), Vec::<u32>::new());
}

#[test]
fn asking_without_saying_how_finds_the_responder() {
    let Some(env) = setup(true) else { return };
    let Some(pair) = pairs().into_iter().next() else {
        common::skip("needs libjemalloc.so.2 and Python 3.12+");
        return;
    };
    let sockets = env.sockets();
    let target = Target::start(
        &env,
        &pair,
        Run::of("service.py", &[sockets.to_str().unwrap(), "stay"]),
    );
    let db = env.dir.path().join("auto.duckdb");
    let out = Command::new(BIN)
        .args(["--pid", &target.pid().to_string(), "--ask", "--ask-dir"])
        .arg(&sockets)
        .arg("-o")
        .arg(&db)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", said(&out));
    assert!(
        said(&out).contains("asked through its responder"),
        "{}",
        said(&out)
    );
}

#[test]
fn a_forked_child_answers_for_itself_and_names_what_it_was_forked_with() {
    let Some(env) = setup(true) else { return };
    let Some(pair) = pairs().into_iter().next() else {
        common::skip("needs libjemalloc.so.2 and Python 3.12+");
        return;
    };
    let sockets = env.sockets();
    let mut target = Target::spawn(
        &env,
        &pair,
        Run::of("service.py", &[sockets.to_str().unwrap(), "fork"]),
    );
    let child: u32 = target.wait_for_each(&["child", "ready"])[0]
        .parse()
        .unwrap();

    let db = env.dir.path().join("child.duckdb");
    let out = ask(
        child,
        "responder",
        &db,
        &["--ask-dir", sockets.to_str().unwrap()],
    );
    kill(child);
    assert!(out.status.success(), "{}", said(&out));
    // The child has allocated nothing since the fork: what its dump holds
    // was sampled in the parent, and its own map names it.
    let frames = frames(&db);
    assert!(
        names_python_function(&frames, "leak_in_python"),
        "{frames:#?}"
    );

    let db = env.dir.path().join("parent.duckdb");
    let out = ask(
        target.pid(),
        "responder",
        &db,
        &["--ask-dir", sockets.to_str().unwrap()],
    );
    assert!(out.status.success(), "{}", said(&out));
}

#[test]
fn a_process_with_no_responder_is_said_to_have_none() {
    let Some(env) = setup(false) else { return };
    let Some(pair) = pairs().into_iter().next() else {
        common::skip("needs libjemalloc.so.2 and Python 3.12+");
        return;
    };
    let mut target = Target::start(&env, &pair, Run::of("plain.py", &["loop"]));
    let db = env.dir.path().join("none.duckdb");
    let sockets = env.sockets();
    let out = ask(
        target.pid(),
        "responder",
        &db,
        &["--ask-dir", sockets.to_str().unwrap()],
    );
    assert!(!out.status.success());
    assert!(said(&out).contains("has no responder"), "{}", said(&out));
    assert!(!db.exists());
    assert!(target.is_running());
}

#[test]
fn a_socket_another_process_answers_at_is_refused() {
    let Some(env) = setup(true) else { return };
    let Some(pair) = pairs().into_iter().next() else {
        common::skip("needs libjemalloc.so.2 and Python 3.12+");
        return;
    };
    let sockets = env.sockets();
    let target = Target::start(
        &env,
        &pair,
        Run::of("service.py", &[sockets.to_str().unwrap(), "stay"]),
    );
    let other = Target::start(&env, &pair, Run::of("plain.py", &["loop"]));
    // The socket of the one, under the name the other's would have.
    std::fs::hard_link(
        sockets.join(format!(".systing-heap.{}", target.pid())),
        sockets.join(format!(".systing-heap.{}", other.pid())),
    )
    .unwrap();
    let db = env.dir.path().join("other.duckdb");
    let out = ask(
        other.pid(),
        "responder",
        &db,
        &["--ask-dir", sockets.to_str().unwrap()],
    );
    assert!(!out.status.success());
    assert!(
        said(&out).contains(&format!("is answered by pid {}", target.pid())),
        "{}",
        said(&out)
    );
}

#[test]
fn python_314_is_asked_through_its_interpreter() {
    let Some(env) = setup(false) else { return };
    for pair in pairs_314() {
        let mut target = Target::start(&env, &pair, Run::of("plain.py", &["loop"]));
        let db = env.dir.path().join("python.duckdb");
        let place = env.dir.path().to_str().unwrap();
        let out = ask(target.pid(), "python", &db, &["--ask-dir", place]);
        assert!(out.status.success(), "{pair:?}: {}", said(&out));
        let (trigger, source, samples) = snapshot(&db);
        assert_eq!(trigger, "asked", "{pair:?}");
        assert!(source.ends_with("/heap"), "{pair:?}: {source}");
        assert!(samples > 0, "{pair:?}");
        assert_eq!(
            left_behind(env.dir.path()),
            Vec::<PathBuf>::new(),
            "{pair:?}"
        );
        assert!(target.is_running(), "{pair:?}");

        // And again: the first request left the interpreter as it was.
        let out = ask(target.pid(), "python", &db, &["--ask-dir", place]);
        assert!(out.status.success(), "{pair:?}: {}", said(&out));
        assert!(target.is_running(), "{pair:?}");
    }
}

#[test]
fn a_main_thread_that_does_not_come_back_is_given_up_on() {
    let Some(env) = setup(false) else { return };
    for pair in pairs_314() {
        let mut target = Target::start(&env, &pair, Run::of("plain.py", &["sleep"]));
        let db = env.dir.path().join("asleep.duckdb");
        let place = env.dir.path().to_str().unwrap();
        let started = Instant::now();
        let out = ask(
            target.pid(),
            "python",
            &db,
            &["--ask-dir", place, "--ask-wait", "1"],
        );
        assert!(!out.status.success(), "{pair:?}");
        assert!(started.elapsed() < Duration::from_secs(10), "{pair:?}");
        assert!(
            said(&out).contains("the request was withdrawn"),
            "{pair:?}: {}",
            said(&out)
        );
        assert!(!db.exists(), "{pair:?}");
        assert_eq!(
            left_behind(env.dir.path()),
            Vec::<PathBuf>::new(),
            "{pair:?}"
        );
        assert!(target.is_running(), "{pair:?}");

        // It was taken back: asked again, the thread has no request of the
        // first's still waiting.
        let out = ask(
            target.pid(),
            "python",
            &db,
            &["--ask-dir", place, "--ask-wait", "1"],
        );
        assert!(
            said(&out).contains("the request was withdrawn"),
            "{pair:?}: {}",
            said(&out)
        );
    }
}

#[test]
fn asking_without_saying_how_falls_to_python_where_no_one_listens() {
    let Some(env) = setup(false) else { return };
    for pair in pairs_314() {
        let target = Target::start(&env, &pair, Run::of("plain.py", &["loop"]));
        let db = env.dir.path().join("auto-python.duckdb");
        let out = Command::new(BIN)
            .args(["--pid", &target.pid().to_string(), "--ask", "--ask-dir"])
            .arg(env.dir.path())
            .arg("-o")
            .arg(&db)
            .env("RUST_BACKTRACE", "0")
            .output()
            .unwrap();
        assert!(out.status.success(), "{pair:?}: {}", said(&out));
        assert!(
            said(&out).contains("asked through its Python interpreter"),
            "{pair:?}: {}",
            said(&out)
        );
        assert_eq!(snapshot(&db).0, "asked", "{pair:?}");
    }
}

#[test]
fn an_interpreter_that_cannot_be_asked_says_why() {
    let Some(env) = setup(false) else { return };
    let place = env.dir.path().to_str().unwrap().to_string();
    let db = env.dir.path().join("refused.duckdb");
    for pair in pairs_314() {
        // Remote debugging turned off, by the environment and by the option.
        let by_environment = Run {
            env: &[("PYTHON_DISABLE_REMOTE_DEBUG", "1")],
            ..Run::of("plain.py", &["loop"])
        };
        let by_option = Run {
            options: &["-X", "disable-remote-debug"],
            ..Run::of("plain.py", &["loop"])
        };
        for run in [by_environment, by_option] {
            let mut target = Target::start(&env, &pair, run);
            let out = ask(target.pid(), "python", &db, &["--ask-dir", &place]);
            assert!(!out.status.success(), "{pair:?}");
            assert!(
                said(&out).contains("remote debugging is turned off"),
                "{pair:?}: {}",
                said(&out)
            );
            assert!(target.is_running(), "{pair:?}");
        }

        // Profiling off: the interpreter runs the request, and jemalloc
        // refuses.
        let without_prof = Run {
            prof: false,
            ..Run::of("plain.py", &["loop"])
        };
        let mut target = Target::start(&env, &pair, without_prof);
        let out = ask(target.pid(), "python", &db, &["--ask-dir", &place]);
        assert!(!out.status.success(), "{pair:?}");
        assert!(
            said(&out).contains("prof.dump failed"),
            "{pair:?}: {}",
            said(&out)
        );
        assert!(target.is_running(), "{pair:?}");
        assert_eq!(
            left_behind(env.dir.path()),
            Vec::<PathBuf>::new(),
            "{pair:?}"
        );
    }
    assert!(!db.exists());
}

#[test]
fn a_python_before_314_is_refused() {
    let Some(env) = setup(false) else { return };
    let older: Vec<Pair> = pairs().into_iter().filter(|p| p.minor < 14).collect();
    if older.is_empty() {
        common::skip("needs Python 3.12 or 3.13 and a libjemalloc.so.2");
    }
    for pair in older {
        let mut target = Target::start(&env, &pair, Run::of("plain.py", &["loop"]));
        let db = env.dir.path().join("older.duckdb");
        let place = env.dir.path().to_str().unwrap();
        let out = ask(target.pid(), "python", &db, &["--ask-dir", place]);
        assert!(!out.status.success(), "{pair:?}");
        let why = said(&out);
        assert!(
            why.contains("asking needs CPython 3.14") || why.contains("publishes no table"),
            "{pair:?}: {why}"
        );
        assert_eq!(
            left_behind(env.dir.path()),
            Vec::<PathBuf>::new(),
            "{pair:?}"
        );
        assert!(target.is_running(), "{pair:?}");
    }
}

#[test]
fn a_process_that_is_no_python_is_refused() {
    let mut child = Command::new("sleep").arg("60").spawn().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let out = ask(child.id(), "python", &dir.path().join("x.duckdb"), &[]);
    let _ = child.kill();
    let _ = child.wait();
    assert!(!out.status.success());
    assert!(
        said(&out).contains("maps no file named as a Python is"),
        "{}",
        said(&out)
    );
}

/// `systing-heap --pid <pid> --check ...`.
fn check(pid: u32, more: &[&str]) -> Output {
    Command::new(BIN)
        .args(["--pid", &pid.to_string(), "--check"])
        .args(more)
        .env("RUST_BACKTRACE", "0")
        .output()
        .unwrap()
}

/// The commands a report says will work.
fn commands_in(report: &str) -> Vec<String> {
    report
        .lines()
        .filter_map(|l| l.strip_prefix("  systing-heap "))
        .map(str::to_string)
        .collect()
}

#[test]
fn what_a_check_says_will_work_works() {
    let Some(env) = setup(true) else { return };
    let pairs = pairs();
    if pairs.is_empty() {
        common::skip("needs libjemalloc.so.2 and Python 3.12+");
    }
    for pair in pairs {
        // The socket's folder is one a shell would make several words of,
        // and more: the commands are run by a shell, as they are printed.
        let sockets = env.dir.path().join(format!("s {};$x", pair.minor));
        std::fs::create_dir(&sockets).unwrap();
        // A service that has everything: files at an interval, a responder,
        // Python functions in its stacks, and a main thread that comes back
        // to Python.
        let target = Target::start(
            &env,
            &pair,
            Run {
                conf: ",lg_prof_interval:22",
                env: &[("SYSTING_HEAP_HOOKS_SOCKET_DIR", sockets.to_str().unwrap())],
                ..Run::of("service.py", &[sockets.to_str().unwrap(), "loop"])
            },
        );
        let out = check(target.pid(), &[]);
        let report = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(out.status.success(), "{pair:?}: {report}{}", said(&out));
        let commands = commands_in(&report);
        let ways = |what: &str| commands.iter().filter(|c| c.contains(what)).count();
        assert_eq!(
            (
                ways("--latest-only"),
                ways("--ask responder"),
                ways("--ask python"),
                ways("--snoop"),
            ),
            (1, 1, usize::from(pair.minor == 14), 1),
            "{pair:?}: {report}"
        );
        // The socket is found where the service's environment says, and the
        // command has the folder in it, as one word.
        assert!(
            commands
                .iter()
                .any(|c| c.ends_with(&format!("--ask-dir '{}'", sockets.display()))),
            "{pair:?}: {report}"
        );
        for (n, command) in commands.iter().enumerate() {
            let db = env
                .dir
                .path()
                .join(format!("check-{}-{n}.duckdb", pair.minor));
            let ran = Command::new("sh")
                .arg("-c")
                .arg(format!(
                    "\"$BIN\" {}",
                    command.replace("-o heap.duckdb", "-o \"$DB\"")
                ))
                .env("BIN", BIN)
                .env("DB", &db)
                .env("RUST_BACKTRACE", "0")
                .output()
                .unwrap();
            assert!(ran.status.success(), "{pair:?}: {command}: {}", said(&ran));
            // Its stacks name Python functions, whichever way they were read.
            let frames = frames(&db);
            assert!(
                names_python_function(&frames, "leak_in_python"),
                "{pair:?}: {command}: {frames:#?}"
            );
        }
        // The Python was asked with its files in its /tmp, and they are gone.
        assert_eq!(
            left_behind(Path::new("/tmp")),
            Vec::<PathBuf>::new(),
            "{pair:?}"
        );
    }
}

#[test]
fn a_check_writes_no_request_into_a_python() {
    let Some(env) = setup(false) else { return };
    for pair in pairs_314() {
        // Its main thread does not come back to Python: a request that was
        // written would still be waiting.
        let mut target = Target::start(&env, &pair, Run::of("plain.py", &["sleep"]));
        let out = check(target.pid(), &[]);
        let report = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(out.status.success(), "{pair:?}: {report}{}", said(&out));
        assert!(report.contains("it can be asked"), "{pair:?}: {report}");

        let db = env.dir.path().join("after-check.duckdb");
        let place = env.dir.path().to_str().unwrap();
        let asked = ask(
            target.pid(),
            "python",
            &db,
            &["--ask-dir", place, "--ask-wait", "1"],
        );
        assert!(
            said(&asked).contains("the request was withdrawn"),
            "{pair:?}: {}",
            said(&asked)
        );
        assert!(target.is_running(), "{pair:?}");
    }
}

#[test]
fn a_check_of_a_service_with_jemalloc_alone_says_what_is_left_and_what_more_there_is() {
    let Some(env) = setup(false) else { return };
    let older: Vec<Pair> = pairs().into_iter().filter(|p| p.minor < 14).collect();
    if older.is_empty() {
        common::skip("needs Python 3.12 or 3.13 and a libjemalloc.so.2");
    }
    for pair in older {
        let mut target = Target::start(&env, &pair, Run::of("plain.py", &["sleep"]));
        let threads = |pid: u32| {
            std::fs::read_dir(format!("/proc/{pid}/task"))
                .unwrap()
                .count()
        };
        let before = threads(target.pid());
        let out = check(target.pid(), &[]);
        let report = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(out.status.success(), "{pair:?}: {report}{}", said(&out));
        let commands = commands_in(&report);
        assert_eq!(commands.len(), 1, "{pair:?}: {report}");
        assert!(commands[0].ends_with("--snoop"), "{pair:?}: {report}");
        for recipe in ["Files at an interval", "Asked, by environment"] {
            assert!(
                report.contains(&format!("recipe: {recipe}")),
                "{pair:?}: {report}"
            );
        }
        // Looking changed nothing.
        assert_eq!(threads(target.pid()), before, "{pair:?}");
        assert!(target.is_running(), "{pair:?}");
    }
}

#[test]
fn a_check_of_a_service_without_profiling_ends_with_an_error() {
    let Some(env) = setup(false) else { return };
    let Some(pair) = pairs().into_iter().next() else {
        common::skip("needs libjemalloc.so.2 and Python 3.12+");
        return;
    };
    let target = Target::start(
        &env,
        &pair,
        Run {
            prof: false,
            ..Run::of("plain.py", &["loop"])
        },
    );
    let out = check(target.pid(), &[]);
    let report = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(!out.status.success(), "{report}");
    assert!(commands_in(&report).is_empty(), "{report}");
    assert!(
        report.contains("off: its environment says prof:false"),
        "{report}"
    );
    assert!(
        report.contains("started with jemalloc and prof:true"),
        "{report}"
    );
}
