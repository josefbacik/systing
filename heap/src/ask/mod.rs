//! Asking a running process for a heap dump of its own.
//!
//! [`crate::snoop`] reads jemalloc's profile out of a process's memory,
//! without its help. Here the process is asked, and the dump is jemalloc's
//! own: written under its locks, in its documented format. There are two ways
//! to ask:
//!
//! - [`responder`]: the process loaded the hooks library and listens
//!   (`systing_heap_hooks_listen`). The request goes to its Unix socket, and
//!   the answer carries the dump as a descriptor. The dump is not written to
//!   disk, nothing is written to the process, and what its threads are doing
//!   does not matter.
//! - [`python`]: a CPython 3.14 that loaded nothing of ours. The interpreter's
//!   remote debugging interface (PEP 768) makes its main thread run a short
//!   script, which calls jemalloc's `prof.dump`. It runs when that thread next
//!   comes back to Python, which a thread that waits in one long call does
//!   not. It writes to the process's memory, so it is asked for by name:
//!   nothing falls back to it.
//!
//! Either way the process needs `prof:true` in its `MALLOC_CONF`, and it is
//! said when jemalloc's sampling is paused there.

pub mod python;
pub mod responder;

use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};

use crate::jemalloc;
use crate::root::{self, Root};
use crate::snoop::{self, Process};
use crate::Snapshot;

/// The value `Snapshot::trigger` has for a snapshot taken this way.
pub const TRIGGER: &str = "asked";

/// How long an asking that is given up on has to take its request back.
const GIVING_UP: Duration = Duration::from_secs(2);
/// How often it is looked at whether the asking was interrupted.
const LOOK: Duration = Duration::from_millis(100);

/// The signal that interrupted an asking, if one did: the request has been
/// dealt with, and the program is to end as that signal ends one
/// ([`end_by`]).
pub fn interrupted_by() -> Option<i32> {
    python::interrupted_by()
}

/// End this program as `signal` ends one that does nothing about it, so
/// that whoever started it sees that it was interrupted.
pub fn end_by(signal: i32) -> ! {
    // SAFETY: the default action is set for a signal this program was sent,
    // which is then sent again.
    unsafe {
        libc::signal(signal, libc::SIG_DFL);
        libc::raise(signal);
    }
    std::process::exit(128 + signal)
}

/// Where the responder's socket and the script's files are, in the process's
/// own filesystem, unless told otherwise.
pub const DEFAULT_DIR: &str = "/tmp";

/// The variable a process's environment names its responder's directory with.
const SOCKET_DIR: &[u8] = b"SYSTING_HEAP_HOOKS_SOCKET_DIR=";

/// The most read of a process's environment.
const MAX_ENVIRON_BYTES: u64 = 16 << 20;

/// `PATH_MAX`: no path the kernel takes is longer.
pub(crate) const MAX_PATH_BYTES: usize = 4096;

/// Where `process`'s responder may have its socket when nothing else is
/// said, the likeliest first: where the environment it was started with
/// says, then [`DEFAULT_DIR`]. Both, because what a process was told in a
/// call stands over what its environment says, and a call that says nothing
/// means [`DEFAULT_DIR`] where the environment says nothing. A directory the
/// environment names relative to the process's working directory is not
/// looked in: that process is asked with the directory given.
pub fn socket_dirs(process: &Process) -> Vec<PathBuf> {
    let named = process
        .read_capped("environ", MAX_ENVIRON_BYTES)
        .ok()
        .and_then(|environ| dir_in_environ(&environ));
    let mut dirs: Vec<PathBuf> = named.into_iter().collect();
    if !dirs.iter().any(|d| d == Path::new(DEFAULT_DIR)) {
        dirs.push(PathBuf::from(DEFAULT_DIR));
    }
    dirs
}

/// The directory `environ` names for the socket, if it is one to go by. The
/// first setting of the variable counts, as it does for `getenv`.
///
/// The value is the process's to choose, and it goes on into every message
/// about the socket, the snapshot's source path among them. So one that
/// could write to a terminal, or that is no text, or is longer than a path
/// can be, is not gone by at all, like one that is relative: that process is
/// asked with the directory given, which is then the caller's own word.
fn dir_in_environ(environ: &[u8]) -> Option<PathBuf> {
    let value = environ
        .split(|b| *b == 0)
        .find_map(|kv| kv.strip_prefix(SOCKET_DIR))?;
    let dir = std::str::from_utf8(value).ok()?;
    let usable = dir.starts_with('/') && dir.len() <= MAX_PATH_BYTES && !dir.chars().any(hidden);
    usable.then(|| PathBuf::from(dir))
}

/// The first of `dirs` in which `look` finds a responder. Where none has
/// one, what the first said; any other failure ends the looking, since it is
/// of a socket that is there.
pub(crate) fn in_the_first_of<T>(
    dirs: &[PathBuf],
    mut look: impl FnMut(&Path) -> Result<T>,
) -> Result<T> {
    let mut first: Option<anyhow::Error> = None;
    for dir in dirs {
        match look(dir) {
            Err(e) if e.downcast_ref::<responder::NoResponder>().is_some() => {
                first.get_or_insert(e);
            }
            found_or_failed => return found_or_failed,
        }
    }
    Err(first.unwrap_or_else(|| anyhow::anyhow!("no directory to look for a responder in")))
}

/// How long the process is given to answer, unless told otherwise.
pub const DEFAULT_WAIT: Duration = Duration::from_secs(30);

/// How to ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum How {
    /// The service's socket, from the hooks library. Answers whatever the
    /// service's threads are doing. Nothing is written to the process.
    Responder,
    /// CPython 3.14 only, nothing added to it. Writes to the process's memory
    /// to make its main thread run a short script. A main thread blocked in
    /// one long call does not answer.
    Python,
}

/// What asking got, besides the snapshot: for the caller to say.
#[derive(Debug)]
pub struct Report {
    /// `responder` or `python`.
    pub by: &'static str,
    /// Where the request went: the socket, or the script.
    pub through: PathBuf,
    pub dump_bytes: usize,
    pub millis: u128,
    /// jemalloc's sampling is paused in the process (`prof.active` is
    /// false): the dump holds what was sampled before, and no more.
    pub paused: bool,
}

impl Report {
    pub fn summary(&self, pid: u32) -> String {
        format!(
            "pid {pid}: asked through its {} ({}); it wrote a dump of {} bytes, {} ms after it was asked{}",
            match self.by {
                "responder" => "responder",
                _ => "Python interpreter",
            },
            self.through.display(),
            self.dump_bytes,
            self.millis,
            match self.paused {
                true =>
                    "\nwarning: jemalloc's sampling is paused in the process (prof.active is \
                     false): the dump holds what was sampled before it was paused, and \
                     nothing allocated since",
                false => "",
            }
        )
    }
}

/// Ask `process` for a dump, `how`, and wait for it no longer than `wait`.
/// `dir` is where the socket or the script is, as the process sees it: when
/// it is not given, the socket is looked for where the process's environment
/// says and in [`DEFAULT_DIR`] ([`socket_dirs`]), and the script is put in
/// [`DEFAULT_DIR`]. `root` must be the process's own ([`Process::root`]).
pub fn ask(
    process: &Process,
    root: &Root,
    how: How,
    dir: Option<&Path>,
    wait: Duration,
) -> Result<(Snapshot, Report)> {
    match how {
        How::Responder => in_the_first_of(
            &dir.map_or_else(|| socket_dirs(process), |dir| vec![dir.to_path_buf()]),
            |dir| responder::ask(process, root, dir, wait),
        )
        .map_err(|e| {
            match e.downcast_ref::<responder::NoResponder>() {
                // What is left is said, and not done: it writes to the process.
                Some(_) => e.context(
                    "nothing was asked of the process. A CPython 3.14 without a responder can \
                     be asked through its interpreter with --ask python, which writes to its \
                     memory; --snoop reads the profile and writes nothing",
                ),
                None => e,
            }
        }),
        How::Python => python::ask(process, root, dir.unwrap_or(Path::new(DEFAULT_DIR)), wait),
    }
}

/// [`ask`], given up on after `wait` and as long again: what is read of the
/// process's is files of its own, and one on a filesystem that stalls must
/// not hold the tool.
pub fn ask_within(
    process: &Process,
    how: How,
    dir: Option<&Path>,
    wait: Duration,
) -> Result<(Snapshot, Report)> {
    let process = process.try_clone()?;
    let dir = dir.map(Path::to_path_buf);
    // Asking waits `wait` for the request to be taken up and as long again
    // for it to be answered; the rest is for reading the answer.
    let limit = wait.saturating_mul(3) + Duration::from_secs(10);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let asked = process
            .root()
            .and_then(|root| ask(&process, &root, how, dir.as_deref(), wait));
        let _ = tx.send(asked);
    });
    use std::sync::mpsc::RecvTimeoutError::{Disconnected, Timeout};
    let until = std::time::Instant::now() + limit;
    // Waited for a little at a time: an interrupt is seen here as well,
    // should the asking be held up where it does not look.
    while interrupted_by().is_none() && std::time::Instant::now() < until {
        match rx.recv_timeout(LOOK) {
            Ok(result) => return result,
            Err(Timeout) => {}
            Err(Disconnected) => bail!("asking the process failed unexpectedly"),
        }
    }
    // A request that is with the process is taken back before this program
    // ends, if whatever holds the asking up lets it be.
    python::give_up();
    let ended = rx.recv_timeout(GIVING_UP);
    let left = "a request to its Python interpreter may still be with the process, with its \
                script and directory where they were made; the script does nothing once it \
                is late";
    match (interrupted_by(), ended) {
        (Some(_), Ok(result)) => result,
        (Some(_), Err(_)) => bail!("interrupted, and the asking did not end: {left}"),
        (None, ended) => bail!(
            "gave up after {} s: reading what the process answered did not finish{}",
            limit.as_secs(),
            match ended {
                Ok(_) => String::new(),
                Err(_) => format!("; {left}"),
            }
        ),
    }
}

/// A file the process handed over or wrote, read whole if it is a regular
/// file on a local filesystem of no more than `cap` bytes. It is the
/// process's to choose what is behind it.
fn read_handed(file: &File, what: &str, cap: u64) -> Result<Vec<u8>> {
    let meta = file
        .metadata()
        .with_context(|| format!("examining {what}"))?;
    if !meta.is_file() {
        bail!("{what} is not a regular file");
    }
    if root::on_remote_fs(file) {
        bail!("{what} is on a FUSE or network filesystem");
    }
    if meta.len() > cap {
        bail!("{what} is larger than {cap} bytes");
    }
    let mut bytes = Vec::new();
    // From the start, wherever the descriptor was left; and no more than the
    // cap, should the file grow as it is read.
    use std::os::unix::fs::FileExt;
    let mut at = 0u64;
    let mut buf = [0u8; 64 << 10];
    loop {
        let n = file
            .read_at(&mut buf, at)
            .with_context(|| format!("reading {what}"))?;
        if n == 0 {
            break;
        }
        at += n as u64;
        if at > cap {
            bail!("{what} is larger than {cap} bytes");
        }
        bytes.extend_from_slice(&buf[..n]);
    }
    Ok(bytes)
}

/// Text of the process's choosing, as it is shown: with its control
/// characters escaped, so that it cannot write to the terminal of whoever
/// runs the tool.
pub(crate) fn shown(text: &str) -> String {
    text.chars()
        .flat_map(|c| {
            let escaped = hidden(c).then(|| c.escape_default().collect::<Vec<_>>());
            escaped.unwrap_or_else(|| vec![c])
        })
        .collect()
}

/// Whether `c` does something to a terminal, or to how the text around it
/// is laid out, instead of being seen: a control character, or one of those
/// that reorder or hide text (U+202E and its like).
pub(crate) fn hidden(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2069}' | '\u{feff}')
}

/// The snapshot a dump's text is, taken from `process` just now.
fn snapshot_of(process: &Process, dump: &[u8], source: PathBuf) -> Result<Snapshot> {
    let text = std::str::from_utf8(dump).context("the dump is not text")?;
    let mut snapshot = jemalloc::parse(text).context("parsing the dump")?;
    snapshot.source_path = source;
    // A dump's file name has the pid the process saw for itself; so does this.
    snapshot.pid = i32::try_from(snoop::own_pid(process)).ok();
    snapshot.trigger = Some(TRIGGER);
    snapshot.dumped_at_unix_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_nanos()).ok());
    snapshot.owner_uid = process.owner().map(|(uid, _)| uid);
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use super::{dir_in_environ, in_the_first_of, responder, shown};

    #[test]
    fn a_directory_the_environment_names_is_gone_by_only_if_it_is_plain() {
        let named = |vars: &[&[u8]]| {
            let environ: Vec<u8> = vars
                .iter()
                .flat_map(|v| v.iter().copied().chain(std::iter::once(0)))
                .collect();
            dir_in_environ(&environ)
        };
        let var = |value: &str| format!("SYSTING_HEAP_HOOKS_SOCKET_DIR={value}").into_bytes();
        assert_eq!(
            named(&[b"PATH=/bin", &var("/run/my service")]),
            Some(PathBuf::from("/run/my service"))
        );
        assert_eq!(named(&[b"PATH=/bin"]), None);
        // The first counts, as for getenv.
        assert_eq!(
            named(&[&var("/first"), &var("/second")]),
            Some(PathBuf::from("/first"))
        );
        // Another variable that ends the same is another variable.
        assert_eq!(named(&[b"X_SYSTING_HEAP_HOOKS_SOCKET_DIR=/x"]), None);
        assert_eq!(named(&[&var("")]), None);
        assert_eq!(named(&[&var("relative/dir")]), None);
        // What would be printed to whoever asks, in every message.
        assert_eq!(named(&[&var("/x\x1b]0;owned\x07\x1b[2J")]), None);
        assert_eq!(named(&[&var("/x\nheap.duckdb: 1 snapshot(s)")]), None);
        assert_eq!(named(&[&var("/x\u{202e}gnp.exe")]), None);
        assert_eq!(named(&[b"SYSTING_HEAP_HOOKS_SOCKET_DIR=/x\xff\xfe"]), None);
        assert_eq!(named(&[&var(&format!("/{}", "a".repeat(4096)))]), None);
    }
    use std::path::PathBuf;

    #[test]
    fn a_responder_is_looked_for_in_each_directory_until_one_has_it() {
        let dirs = [PathBuf::from("/run/x"), PathBuf::from("/tmp")];
        let none = |dir: &std::path::Path| -> anyhow::Result<&'static str> {
            Err(responder::NoResponder::new(format!("none in {}", dir.display())).into())
        };
        let mut looked = Vec::new();
        let found = in_the_first_of(&dirs, |dir| {
            looked.push(dir.to_path_buf());
            match dir.ends_with("tmp") {
                true => Ok("answered"),
                false => none(dir),
            }
        });
        assert_eq!(found.unwrap(), "answered");
        assert_eq!(looked, dirs);
        // Where none has one, what is said is of the likeliest.
        let e = in_the_first_of(&dirs, none).unwrap_err();
        assert_eq!(e.to_string(), "none in /run/x");
        // A socket that is there and fails is not looked past.
        let mut looked = 0;
        let e = in_the_first_of(&dirs, |_| -> anyhow::Result<()> {
            looked += 1;
            anyhow::bail!("answered by another process")
        })
        .unwrap_err();
        assert_eq!(
            (looked, e.to_string().as_str()),
            (1, "answered by another process")
        );
    }

    #[test]
    fn what_a_process_says_cannot_write_to_the_terminal() {
        assert_eq!(
            shown("jemalloc's prof.dump failed"),
            "jemalloc's prof.dump failed"
        );
        assert_eq!(
            shown("\x1b[2Jall is well\r\n"),
            "\\u{1b}[2Jall is well\\r\\n"
        );
    }
}
