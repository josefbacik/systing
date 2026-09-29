//! `--ask`: a running process asked for a heap dump, for
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
const PLAIN: &str = r#"import ctypes, signal, sys, time
PR_SET_PTRACER, PR_SET_PTRACER_ANY = 0x59616d61, ctypes.c_ulong(-1)
ctypes.CDLL(None).prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0)
# What brings a main thread that waits back to Python, when a test says so.
signal.signal(signal.SIGUSR1, lambda *_: None)
keep = []
def leak_in_python(n):
    for _ in range(n):
        keep.append(bytearray(64 * 1024))
leak_in_python(256)
print("ready", flush=True)
if sys.argv[1] == "loop":
    while True:
        time.sleep(0.01)
while True:
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

/// The pairs whose Python is 3.14. Where there is none the test is skipped
/// as any other is: with a note, or in CI, where every dependency is
/// installed, by failing, so that a green run there means the Python way ran.
fn pairs_314() -> Vec<Pair> {
    let pairs: Vec<Pair> = pairs().into_iter().filter(|p| p.minor == 14).collect();
    if pairs.is_empty() {
        common::skip(
            "needs Python 3.14 and a libjemalloc.so.2 (SYSTING_HEAP_TEST_PYTHON and \
             SYSTING_HEAP_TEST_JEMALLOC name a pair)",
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
fn only_the_program_named_listens_of_those_that_inherit_the_environment() {
    let Some(env) = setup(true) else { return };
    let Some(pair) = pairs().into_iter().next() else {
        common::skip("needs libjemalloc.so.2 and Python 3.12+");
        return;
    };
    let library = env.dir.path().join("libsysting_heap_responder.so");
    let sockets = env.dir.path().join("only");
    std::fs::create_dir(&sockets).unwrap();
    // How many threads a program started with the environment has, and what
    // it says on standard error: the program is Python, and says how many
    // threads it finds itself with.
    let exe = std::fs::canonicalize(
        String::from_utf8(
            Command::new(&pair.python)
                .args(["-c", "import sys; print(sys.executable, end='')"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap(),
    )
    .unwrap();
    let name = exe.file_name().unwrap().to_str().unwrap();
    for (only, prof, threads) in [
        (name, true, "2"),
        ("another-program", true, "1"),
        // Nor does one that is not named say why it could not have listened.
        ("another-program", false, "1"),
    ] {
        let out = Command::new(&pair.python)
            .args([
                "-c",
                "import os; print(len(os.listdir('/proc/self/task')), end='')",
            ])
            .env(
                "LD_PRELOAD",
                format!("{}:{}", pair.jemalloc.display(), library.display()),
            )
            .env("MALLOC_CONF", format!("prof:{prof}"))
            .env("SYSTING_HEAP_HOOKS_LISTEN", "1")
            .env("SYSTING_HEAP_HOOKS_LISTEN_ONLY", only)
            .env("SYSTING_HEAP_HOOKS_SOCKET_DIR", &sockets)
            .output()
            .unwrap();
        assert!(out.status.success(), "{only}");
        assert_eq!(String::from_utf8_lossy(&out.stdout), threads, "{only}");
        assert_eq!(String::from_utf8_lossy(&out.stderr), "", "{only}");
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
fn asking_without_saying_how_writes_to_no_process() {
    let Some(env) = setup(false) else { return };
    for pair in pairs_314() {
        // A Python that could be asked through its interpreter, and that
        // would answer at once.
        let mut target = Target::start(&env, &pair, Run::of("plain.py", &["loop"]));
        let db = env.dir.path().join("bare.duckdb");
        let place = env.dir.path().join("bare");
        std::fs::create_dir(&place).unwrap();
        let out = Command::new(BIN)
            .args(["--pid", &target.pid().to_string(), "--ask", "--ask-dir"])
            .arg(&place)
            .arg("-o")
            .arg(&db)
            .env("RUST_BACKTRACE", "0")
            .output()
            .unwrap();
        assert!(!out.status.success(), "{pair:?}: {}", said(&out));
        let err = said(&out);
        assert!(
            err.contains("has no responder") && err.contains("nothing was asked of the process"),
            "{pair:?}: {err}"
        );
        // What is left is said, and was not done.
        assert!(err.contains("--ask python"), "{pair:?}: {err}");
        assert!(
            !err.contains("asked through its Python interpreter"),
            "{pair:?}: {err}"
        );
        assert!(!db.exists(), "{pair:?}");
        assert_eq!(std::fs::read_dir(&place).unwrap().count(), 0, "{pair:?}");
        assert!(target.is_running(), "{pair:?}");
    }
}

#[test]
fn a_dump_of_a_process_whose_sampling_is_paused_is_said_to_be_one() {
    let Some(env) = setup(true) else { return };
    let paused = "sampling is paused in the process";
    // Started with sampling on and paused, and not.
    for (conf, says) in [(",prof_active:false", true), ("", false)] {
        for pair in pairs() {
            let sockets = env
                .dir
                .path()
                .join(format!("p{}{}", pair.minor, u8::from(says)));
            std::fs::create_dir(&sockets).unwrap();
            let target = Target::start(
                &env,
                &pair,
                Run {
                    conf,
                    ..Run::of("service.py", &[sockets.to_str().unwrap(), "stay"])
                },
            );
            let db = env.dir.path().join("paused.duckdb");
            let out = ask(
                target.pid(),
                "responder",
                &db,
                &["--ask-dir", sockets.to_str().unwrap()],
            );
            assert!(out.status.success(), "{pair:?} {conf:?}: {}", said(&out));
            assert_eq!(
                said(&out).contains(paused),
                says,
                "{pair:?}: {}",
                said(&out)
            );
        }
        for pair in pairs_314() {
            let target = Target::start(
                &env,
                &pair,
                Run {
                    conf,
                    ..Run::of("plain.py", &["loop"])
                },
            );
            let db = env.dir.path().join("paused-python.duckdb");
            let place = env.dir.path().to_str().unwrap();
            let out = ask(target.pid(), "python", &db, &["--ask-dir", place]);
            assert!(out.status.success(), "{pair:?} {conf:?}: {}", said(&out));
            assert_eq!(
                said(&out).contains(paused),
                says,
                "{pair:?}: {}",
                said(&out)
            );
        }
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

/// `systing-heap --pid <pid> --ask python ...` under way, in `place`.
fn asking(pid: u32, out: &Path, place: &Path, wait: &str) -> std::process::Child {
    Command::new(BIN)
        .args(["--pid", &pid.to_string(), "--ask", "python", "-o"])
        .arg(out)
        .arg("--ask-dir")
        .arg(place)
        .args(["--ask-wait", wait])
        .env("RUST_BACKTRACE", "0")
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// The directory of the request that is with a process, once its script and
/// the directory to write to are there.
fn request_in(place: &Path) -> PathBuf {
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        let made = left_behind(place)
            .into_iter()
            .find(|d| d.join("ask.py").exists() && d.join("out").exists());
        match made {
            Some(dir) => {
                // The request is written once the files are.
                std::thread::sleep(Duration::from_millis(300));
                return dir;
            }
            None => assert!(Instant::now() < until, "no request was made in {place:?}"),
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn signal(pid: u32, signal: i32) {
    // SAFETY: a signal to a process this test started.
    unsafe { libc::kill(pid as i32, signal) };
}

/// What a program that ended said, and how it ended.
fn ended(child: std::process::Child) -> (std::process::ExitStatus, String) {
    let out = child.wait_with_output().unwrap();
    (
        out.status,
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::symlink_metadata(path)
        .unwrap()
        .permissions()
        .mode()
        & 0o7777
}

#[test]
fn an_asking_that_is_interrupted_takes_its_request_back() {
    let Some(env) = setup(false) else { return };
    for pair in pairs_314() {
        for (n, by) in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP]
            .into_iter()
            .enumerate()
        {
            let mut target = Target::start(&env, &pair, Run::of("plain.py", &["sleep"]));
            let place = env.dir.path().join(format!("interrupted-{n}"));
            std::fs::create_dir(&place).unwrap();
            let db = env.dir.path().join("interrupted.duckdb");

            let tool = asking(target.pid(), &db, &place, "60");
            request_in(&place);
            let started = Instant::now();
            signal(tool.id(), by);
            let (status, err) = ended(tool);
            // It ended at once, having said why, and as the signal ends a
            // program: whoever started it sees that it was interrupted.
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(status.signal(), Some(by), "signal {by}: {status:?}: {err}");
            assert!(started.elapsed() < Duration::from_secs(5), "signal {by}");
            assert!(
                err.contains("interrupted") && err.contains("the request was withdrawn"),
                "signal {by}: {err}"
            );
            assert_eq!(left_behind(&place), Vec::<PathBuf>::new(), "signal {by}");
            assert!(!db.exists(), "signal {by}");

            // Nothing waits in the process: it can be asked again.
            let again = ask(
                target.pid(),
                "python",
                &db,
                &["--ask-dir", place.to_str().unwrap(), "--ask-wait", "1"],
            );
            assert!(
                said(&again).contains("the request was withdrawn")
                    && !said(&again).contains("another request"),
                "signal {by}: {}",
                said(&again)
            );
            assert!(target.is_running(), "signal {by}");
        }
    }
}

#[test]
fn a_request_left_by_a_tool_that_was_killed_does_nothing_once_it_is_late() {
    let Some(env) = setup(false) else { return };
    for pair in pairs_314() {
        // Woken in time, and woken late. The script may run for the wait
        // (3 s, within which the tool is killed) and 5 s more.
        for (n, (woken_after, runs)) in [(0, true), (10, false)].into_iter().enumerate() {
            let mut target = Target::start(&env, &pair, Run::of("plain.py", &["sleep"]));
            let place = env.dir.path().join(format!("killed-{n}"));
            std::fs::create_dir(&place).unwrap();
            let db = env.dir.path().join("killed.duckdb");

            let mut tool = asking(target.pid(), &db, &place, "3");
            let request = request_in(&place);
            // Nothing can be done about this one.
            signal(tool.id(), libc::SIGKILL);
            tool.wait().unwrap();

            // The process reads the script and cannot write it, nor beside
            // it; where it writes is its own alone.
            assert_eq!(mode_of(&request), 0o755);
            assert_eq!(mode_of(&request.join("ask.py")), 0o444);
            assert_eq!(mode_of(&request.join("out")), 0o700);

            std::thread::sleep(Duration::from_secs(woken_after));
            signal(target.pid(), libc::SIGUSR1);
            // A script that runs is given a while; one that is not to is
            // given as long to show that it does not.
            let wrote = |f: &str| request.join("out").join(f).exists();
            let until = Instant::now() + Duration::from_secs(if runs { 10 } else { 2 });
            while Instant::now() < until && !wrote("done") {
                std::thread::sleep(Duration::from_millis(50));
            }
            assert_eq!(
                [wrote("started"), wrote("done"), wrote("heap")],
                [runs; 3],
                "woken after {woken_after} s"
            );
            assert!(target.is_running(), "woken after {woken_after} s");
        }
    }
}

#[test]
fn a_directory_that_anyone_can_rename_in_is_refused_whoever_asks() {
    use std::os::unix::fs::PermissionsExt;
    let Some(env) = setup(false) else { return };
    for pair in pairs_314() {
        // The process is this user's, as the tool is: anyone is more.
        let mut target = Target::start(&env, &pair, Run::of("plain.py", &["loop"]));
        let db = env.dir.path().join("open.duckdb");
        let place = env.dir.path().join("open");
        std::fs::create_dir(&place).unwrap();
        let mode =
            |mode| std::fs::set_permissions(&place, std::fs::Permissions::from_mode(mode)).unwrap();
        mode(0o777);
        let args = ["--ask-dir", place.to_str().unwrap()];
        let out = ask(target.pid(), "python", &db, &args);
        assert!(!out.status.success(), "{pair:?}: {}", said(&out));
        assert!(
            said(&out).contains("it has no sticky bit"),
            "{pair:?}: {}",
            said(&out)
        );
        assert_eq!(std::fs::read_dir(&place).unwrap().count(), 0, "{pair:?}");
        assert!(!db.exists(), "{pair:?}");

        // As /tmp is, it will do.
        mode(0o1777);
        let out = ask(target.pid(), "python", &db, &args);
        assert!(out.status.success(), "{pair:?}: {}", said(&out));
        assert!(target.is_running(), "{pair:?}");
    }
}

/// `program` run as root, with what this test's own programs need of the
/// environment; None, with a note, where root is not to be had for the asking.
fn as_root(program: &str) -> Option<Command> {
    let sudo = Command::new("sudo")
        .args(["-n", "true"])
        .stderr(Stdio::null())
        .status();
    // SAFETY: geteuid has no failure and no arguments.
    if !sudo.is_ok_and(|s| s.success()) || unsafe { libc::geteuid() } == 0 {
        common::skip("needs sudo without a password, and not to be root itself");
        return None;
    }
    let mut cmd = Command::new("sudo");
    cmd.args(["-n", "env", "RUST_BACKTRACE=0"]);
    if let Ok(path) = std::env::var("LD_LIBRARY_PATH") {
        cmd.arg(format!("LD_LIBRARY_PATH={path}"));
    }
    cmd.arg(program);
    Some(cmd)
}

/// A directory of root's in /tmp, as /tmp is, removed when dropped.
struct RootsOwn(PathBuf);

impl RootsOwn {
    fn make() -> Option<RootsOwn> {
        let made = as_root("mktemp")?
            .args(["-d", "/tmp/ask-root.XXXXXX"])
            .output()
            .unwrap();
        assert!(made.status.success(), "{}", said(&made));
        let dir = PathBuf::from(String::from_utf8(made.stdout).unwrap().trim_end());
        let dir = RootsOwn(dir);
        assert!(as_root("chmod")?
            .arg("1777")
            .arg(&dir.0)
            .status()
            .unwrap()
            .success());
        Some(dir)
    }
}

impl Drop for RootsOwn {
    fn drop(&mut self) {
        // What a test that failed left in it goes with it: the name is one
        // this test was given by mktemp, in a directory of root's.
        if let Some(mut rm) = as_root("rm") {
            let _ = rm.arg("-rf").arg("--").arg(&self.0).status();
        }
    }
}

#[test]
fn the_script_root_writes_is_not_the_processs_users_to_change() {
    use std::os::unix::fs::MetadataExt;
    let Some(env) = setup(false) else { return };
    for pair in pairs_314() {
        let Some(place) = RootsOwn::make() else {
            return;
        };
        let place = &place.0;
        // SAFETY: geteuid has no failure and no arguments.
        let me = unsafe { libc::geteuid() };
        // The process is this test's user's, and the tool root's.
        let mut target = Target::start(&env, &pair, Run::of("plain.py", &["sleep"]));
        let pid = target.pid().to_string();
        let db = place.join("asked.duckdb");
        let tool = |dir: &Path, wait: &str| {
            let mut cmd = as_root(BIN).unwrap();
            cmd.args(["--pid", &pid, "--ask", "python", "--ask-wait", wait, "-o"])
                .arg(&db)
                .arg("--ask-dir")
                .arg(dir)
                .stderr(Stdio::piped());
            cmd
        };

        // A directory of that user's own, or beneath one, is refused.
        let own = env.dir.path().join("own");
        std::fs::create_dir(&own).unwrap();
        let out = tool(&own, "1").output().unwrap();
        assert!(!out.status.success(), "{pair:?}: {}", said(&out));
        assert!(
            said(&out).contains("the process's user's own"),
            "{pair:?}: {}",
            said(&out)
        );
        assert_eq!(std::fs::read_dir(&own).unwrap().count(), 0, "{pair:?}");

        // In one of root's the request waits, and this user tries.
        let asking = tool(place, "60").spawn().unwrap();
        let request = request_in(place);
        let owner = |p: &Path| std::fs::symlink_metadata(p).unwrap().uid();
        assert_eq!(
            [
                owner(&request),
                owner(&request.join("ask.py")),
                owner(&request.join("out"))
            ],
            [0, 0, me],
            "{pair:?}"
        );
        let script = request.join("ask.py");
        let written = std::fs::read(&script).unwrap();
        let denied = |what: &str, tried: std::io::Result<()>| {
            let e = tried.expect_err(what);
            assert_eq!(
                e.kind(),
                std::io::ErrorKind::PermissionDenied,
                "{what}: {e}"
            );
        };
        denied("writing the script", std::fs::write(&script, "import os\n"));
        denied("removing the script", std::fs::remove_file(&script));
        denied(
            "putting another in its place",
            std::fs::rename(env.dir.path().join("plain.py"), &script),
        );
        denied("writing beside it", std::fs::write(request.join("x"), ""));
        denied(
            "renaming where it writes",
            std::fs::rename(request.join("out"), request.join("out2")),
        );
        denied(
            "renaming its directory",
            std::fs::rename(&request, place.join("aside")),
        );
        assert_eq!(std::fs::read(&script).unwrap(), written, "{pair:?}");

        // The process comes back to Python, runs what root wrote, and
        // writes where it may; root reads that and removes it all.
        signal(target.pid(), libc::SIGUSR1);
        let (status, err) = ended(asking);
        assert!(status.success(), "{pair:?}: {err}");
        assert!(
            err.contains("asked through its Python interpreter"),
            "{pair:?}: {err}"
        );
        assert!(!err.contains("this tool's own user"), "{pair:?}: {err}");
        assert_eq!(left_behind(place), Vec::<PathBuf>::new(), "{pair:?}");
        // The database is root's: a copy is this user's to open.
        let copy = env.dir.path().join("asked-by-root.duckdb");
        std::fs::copy(&db, &copy).unwrap();
        assert_eq!(snapshot(&copy).0, "asked", "{pair:?}");
        assert!(target.is_running(), "{pair:?}");
    }
}

#[test]
fn a_file_the_process_has_under_another_name_too_is_not_read() {
    let Some(env) = setup(false) else { return };
    for pair in pairs_314() {
        let mut target = Target::start(&env, &pair, Run::of("plain.py", &["sleep"]));
        let place = env.dir.path().join("linked");
        std::fs::create_dir(&place).unwrap();
        let db = env.dir.path().join("linked.duckdb");
        // A file that says all went well, which could as well be one that
        // this tool's user can read and the process's cannot.
        let other = env.dir.path().join("of-another");
        std::fs::write(&other, "ok\n").unwrap();

        let tool = asking(target.pid(), &db, &place, "30");
        let request = request_in(&place);
        std::fs::hard_link(&other, request.join("out/done")).unwrap();
        let (status, err) = ended(tool);
        assert!(!status.success(), "{err}");
        assert!(err.contains("under that name alone"), "{err}");
        assert!(!db.exists());
        assert_eq!(left_behind(&place), Vec::<PathBuf>::new());
        assert_eq!(std::fs::read_to_string(&other).unwrap(), "ok\n");
        assert!(target.is_running());
    }
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
        // /tmp is the whole machine's: what another run left there is not
        // this one's.
        let there_before = left_behind(Path::new("/tmp"));
        let out = check(target.pid(), &[]);
        let report = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(out.status.success(), "{pair:?}: {report}{}", said(&out));
        let commands = commands_in(&report);
        let ways = |what: &str| commands.iter().filter(|c| c.contains(what)).count();
        assert_eq!(
            (
                ways("--latest-only"),
                ways("--ask --ask-dir"),
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
        let new: Vec<PathBuf> = left_behind(Path::new("/tmp"))
            .into_iter()
            .filter(|p| !there_before.contains(p))
            .collect();
        assert_eq!(new, Vec::<PathBuf>::new(), "{pair:?}");
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
        assert!(
            report.contains("--ask python can be used"),
            "{pair:?}: {report}"
        );

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
        for section in [
            "Snapshot files at an interval",
            "Start here: collect over the socket",
        ] {
            assert!(
                report.contains(&format!("See \"{section}\".")),
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
        report.contains("off: MALLOC_CONF has prof:false"),
        "{report}"
    );
    assert!(
        report.contains("Start the service on jemalloc with prof:true"),
        "{report}"
    );
}

#[test]
fn the_socket_is_found_where_the_services_environment_says() {
    let Some(env) = setup(true) else { return };
    let Some(pair) = pairs().into_iter().next() else {
        common::skip("needs libjemalloc.so.2 and Python 3.12+");
        return;
    };
    let library = env.dir.path().join("libsysting_heap_responder.so");
    let sockets = env.dir.path().join("named in the environment");
    std::fs::create_dir(&sockets).unwrap();
    let target = Target::start(
        &env,
        &pair,
        Run {
            env: &[
                ("SYSTING_HEAP_HOOKS_LISTEN", "1"),
                ("SYSTING_HEAP_HOOKS_SOCKET_DIR", sockets.to_str().unwrap()),
            ],
            preload: Some(&library),
            ..Run::of("unchanged.py", &["stay"])
        },
    );
    // The first command of the guide and of --help: no directory is given.
    let db = env.dir.path().join("found.duckdb");
    let out = Command::new(BIN)
        .args(["--pid", &target.pid().to_string(), "--ask", "-o"])
        .arg(&db)
        .env("RUST_BACKTRACE", "0")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", said(&out));
    assert!(
        said(&out).contains(&format!("{}/.systing-heap.", sockets.display())),
        "{}",
        said(&out)
    );
    assert_eq!(snapshot(&db).0, "asked");
}

#[test]
fn what_a_services_environment_names_cannot_write_to_the_terminal() {
    let Some(env) = setup(false) else { return };
    let Some(pair) = pairs().into_iter().next() else {
        common::skip("needs libjemalloc.so.2 and Python 3.12+");
        return;
    };
    // A directory that need not exist: it is printed when it is not found.
    let hostile = "/x\x1b]0;owned\x07\x1b[2J\nheap.duckdb: 1 snapshot(s)";
    let target = Target::start(
        &env,
        &pair,
        Run {
            env: &[("SYSTING_HEAP_HOOKS_SOCKET_DIR", hostile)],
            ..Run::of("plain.py", &["loop"])
        },
    );
    let pid = target.pid().to_string();
    let db = env.dir.path().join("hostile.duckdb");
    let asked = Command::new(BIN)
        .args(["--pid", &pid, "--ask", "-o"])
        .arg(&db)
        .env("RUST_BACKTRACE", "0")
        .output()
        .unwrap();
    assert!(!asked.status.success());
    let checked = check(target.pid(), &[]);
    for out in [&asked, &checked] {
        let all = format!("{}{}", String::from_utf8_lossy(&out.stdout), said(out));
        assert!(!all.contains('\x1b') && !all.contains('\x07'), "{all:?}");
        assert!(!all.contains("\nheap.duckdb: 1 snapshot(s)"), "{all:?}");
    }
    // It is not gone by at all: the socket was looked for in /tmp.
    assert!(
        said(&asked).contains(&format!("there is no /tmp/.systing-heap.{pid}")),
        "{}",
        said(&asked)
    );
}

#[test]
fn a_check_says_of_the_directory_named_what_asking_would() {
    use std::os::unix::fs::PermissionsExt;
    let Some(env) = setup(false) else { return };
    for pair in pairs_314() {
        let target = Target::start(&env, &pair, Run::of("plain.py", &["loop"]));
        let place = env.dir.path().join("for the script");
        std::fs::create_dir(&place).unwrap();
        let mode =
            |mode| std::fs::set_permissions(&place, std::fs::Permissions::from_mode(mode)).unwrap();
        let report = || {
            let out = check(target.pid(), &["--ask-dir", place.to_str().unwrap()]);
            String::from_utf8_lossy(&out.stdout).into_owned()
        };
        // One that anyone can rename in: asking would refuse it.
        mode(0o777);
        let refused = report();
        assert!(
            refused.contains("--ask python cannot be used") && refused.contains("no sticky bit"),
            "{pair:?}: {refused}"
        );
        assert!(
            !commands_in(&refused)
                .iter()
                .any(|c| c.contains("--ask python")),
            "{pair:?}: {refused}"
        );

        // As /tmp is: the command names it, and works.
        mode(0o1777);
        let allowed = report();
        let commands = commands_in(&allowed);
        let command = commands
            .iter()
            .find(|c| c.contains("--ask python"))
            .unwrap_or_else(|| panic!("{pair:?}: {allowed}"));
        assert!(
            command.contains(&format!("--ask-dir '{}'", place.display())),
            "{pair:?}: {command}"
        );
        let db = env.dir.path().join("named.duckdb");
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
        assert_eq!(std::fs::read_dir(&place).unwrap().count(), 0, "{pair:?}");
    }
}

// A native service: it knows nothing of jemalloc or of the hooks.
const NATIVE: &str = r#"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static void *keep[4096];
static int n;
__attribute__((noinline)) static void leak_buffers(int k)
{
    for (int i = 0; i < k; i++) {
        keep[n] = malloc(64 * 1024);
        memset(keep[n++], 1, 64 * 1024);
    }
}
int main(void)
{
    leak_buffers(256);
    for (;;)
        pause();
}
"#;

/// [`NATIVE`] built as `name` in the test's directory, and the system's
/// jemalloc to load into it.
fn native_service(env: &Env, name: &str) -> Option<(PathBuf, PathBuf)> {
    let Some(jemalloc) = common::jemalloc() else {
        common::skip("needs libjemalloc.so.2");
        return None;
    };
    let source = env.dir.path().join(format!("{name}.c"));
    std::fs::write(&source, NATIVE).unwrap();
    let program = env.dir.path().join(name);
    let built = Command::new(std::env::var("CC").unwrap_or_else(|_| "cc".into()))
        .args(["-O1", "-g", "-fno-omit-frame-pointer", "-o"])
        .arg(&program)
        .arg(&source)
        .status();
    if !built.is_ok_and(|s| s.success()) {
        common::skip("no C compiler to build a native service with");
        return None;
    }
    Some((program, jemalloc))
}

/// The environment the guide gives a native service.
fn as_the_guide_says(cmd: &mut Command, env: &Env, jemalloc: &Path, name: &str, sockets: &str) {
    let library = env.dir.path().join("libsysting_heap_responder.so");
    cmd.env(
        "LD_PRELOAD",
        format!("{}:{}", jemalloc.display(), library.display()),
    )
    .env("MALLOC_CONF", "prof:true")
    .env("SYSTING_HEAP_HOOKS_LISTEN", "1")
    .env("SYSTING_HEAP_HOOKS_LISTEN_ONLY", name)
    .env("SYSTING_HEAP_HOOKS_SOCKET_DIR", sockets);
}

/// Wait for `ready` to give something, no longer than 10 s.
fn wait_until<T>(what: &str, mut ready: impl FnMut() -> Option<T>) -> T {
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(found) = ready() {
            return found;
        }
        assert!(Instant::now() < until, "{what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_native_service_answers_its_own_user_and_root() {
    let Some(env) = setup(true) else { return };
    let Some((program, jemalloc)) = native_service(&env, "native-svc") else {
        return;
    };
    let sockets = env.sockets();
    let mut cmd = Command::new(&program);
    as_the_guide_says(
        &mut cmd,
        &env,
        &jemalloc,
        "native-svc",
        sockets.to_str().unwrap(),
    );
    let mut service = cmd.spawn().unwrap();
    let pid = service.id();
    wait_until("the service did not listen", || {
        sockets_in(&sockets).contains(&pid).then_some(())
    });

    // The guide's command, as the service's own user.
    let db = env.dir.path().join("native.duckdb");
    let out = Command::new(BIN)
        .args(["--pid", &pid.to_string(), "--ask", "-o"])
        .arg(&db)
        .env("RUST_BACKTRACE", "0")
        .output()
        .unwrap();
    let named = out.status.success() && frames(&db).iter().any(|f| f.starts_with("leak_buffers ("));

    // And as root.
    let by_root = as_root(BIN).map(|mut tool| {
        let db = env.dir.path().join("native-by-root.duckdb");
        tool.args(["--pid", &pid.to_string(), "--ask", "-o"])
            .arg(&db)
            .output()
            .unwrap()
    });
    let _ = service.kill();
    let _ = service.wait();
    assert!(named, "{}", said(&out));
    if let Some(out) = by_root {
        assert!(out.status.success(), "{}", said(&out));
        assert!(
            said(&out).contains("asked through its responder"),
            "{}",
            said(&out)
        );
    }
}

#[test]
fn root_outside_asks_a_service_in_pid_and_mount_namespaces_of_its_own() {
    use std::os::unix::fs::MetadataExt;
    let Some(env) = setup(true) else { return };
    // Its name is looked for among all the machine's processes.
    let name = format!("ns-svc-{:x}", std::process::id() & 0xffff);
    let Some((program, jemalloc)) = native_service(&env, &name) else {
        return;
    };
    let Some(mut container) = as_root("unshare") else {
        return;
    };
    // Others must be able to reach the program and the library.
    let meta = std::fs::metadata(env.dir.path()).unwrap();
    std::fs::set_permissions(
        env.dir.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .unwrap();
    // As a container is: pid 1 to itself, and a /run of its own, which
    // nothing outside can see. It runs as this test's user, not as root.
    let library = env.dir.path().join("libsysting_heap_responder.so");
    let inside = format!(
        "mount -t tmpfs tmpfs /run && mkdir -m 0777 /run/my-service && \
         exec setpriv --reuid {} --regid {} --clear-groups env \
         LD_PRELOAD={}:{} MALLOC_CONF=prof:true SYSTING_HEAP_HOOKS_LISTEN=1 \
         SYSTING_HEAP_HOOKS_LISTEN_ONLY={name} SYSTING_HEAP_HOOKS_SOCKET_DIR=/run/my-service {}",
        meta.uid(),
        meta.gid(),
        jemalloc.display(),
        library.display(),
        program.display()
    );
    let mut container = container
        .args([
            "--pid",
            "--fork",
            "--mount",
            "--mount-proc",
            "sh",
            "-c",
            &inside,
        ])
        .spawn()
        .unwrap();
    let pid_of = || {
        std::fs::read_dir("/proc").unwrap().find_map(|e| {
            let pid: u32 = e.ok()?.file_name().to_str()?.parse().ok()?;
            let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
            (comm.trim_end() == name).then_some(pid)
        })
    };
    let pid = wait_until("the service did not start", pid_of);
    // Given a moment to listen: its socket cannot be seen from here.
    std::thread::sleep(Duration::from_millis(500));
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    let db = env.dir.path().join("namespaces.duckdb");
    let out = as_root(BIN)
        .unwrap()
        .args(["--pid", &pid.to_string(), "--ask", "-o"])
        .arg(&db)
        .output()
        .unwrap();
    // Nothing less ends it: a process that is pid 1 to itself gets only the
    // signals it has a handler for, from outside as well.
    let _ = as_root("kill")
        .unwrap()
        .args(["-KILL", &pid.to_string()])
        .status();
    let _ = container.wait();

    // It is pid 1 to itself, and the socket is named so, in its own /run.
    assert!(
        status
            .lines()
            .any(|l| l.starts_with("NSpid:") && l.ends_with("\t1")),
        "{status}"
    );
    assert!(!Path::new("/run/my-service").exists());
    assert!(out.status.success(), "{}", said(&out));
    assert!(
        said(&out).contains("(/run/my-service/.systing-heap.1)"),
        "{}",
        said(&out)
    );
    // Its frames are named from the binaries as it sees them.
    let copy = env.dir.path().join("namespaces-copy.duckdb");
    std::fs::copy(&db, &copy).unwrap();
    assert!(
        frames(&copy)
            .iter()
            .any(|f| f.starts_with("leak_buffers (")),
        "{:#?}",
        frames(&copy)
    );
}
