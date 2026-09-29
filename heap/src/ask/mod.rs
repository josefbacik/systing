//! EXPERIMENTAL. Asking a running process for a heap dump of its own.
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

/// How long the process is given to answer, unless told otherwise.
pub const DEFAULT_WAIT: Duration = Duration::from_secs(30);

/// How to ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum How {
    /// The hooks library's socket. Nothing is written to the process.
    Responder,
    /// CPython 3.14's remote debugging interface, which writes to the
    /// process's memory: it is asked for by name, and nothing falls back
    /// to it.
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
/// `dir` is where the socket or the script is, as the process sees it;
/// `root` must be the process's own ([`Process::root`]).
pub fn ask(
    process: &Process,
    root: &Root,
    how: How,
    dir: &Path,
    wait: Duration,
) -> Result<(Snapshot, Report)> {
    match how {
        How::Responder => responder::ask(process, root, dir, wait).map_err(|e| {
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
        How::Python => python::ask(process, root, dir, wait),
    }
}

/// [`ask`], given up on after `wait` and as long again: what is read of the
/// process's is files of its own, and one on a filesystem that stalls must
/// not hold the tool.
pub fn ask_within(
    process: &Process,
    how: How,
    dir: &Path,
    wait: Duration,
) -> Result<(Snapshot, Report)> {
    let process = process.try_clone()?;
    let dir = dir.to_path_buf();
    // Asking waits `wait` for the request to be taken up and as long again
    // for it to be answered; the rest is for reading the answer.
    let limit = wait.saturating_mul(3) + Duration::from_secs(10);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let asked = process
            .root()
            .and_then(|root| ask(&process, &root, how, &dir, wait));
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
fn shown(text: &str) -> String {
    text.chars()
        .flat_map(|c| {
            let escaped = c
                .is_control()
                .then(|| c.escape_default().collect::<Vec<_>>());
            escaped.unwrap_or_else(|| vec![c])
        })
        .collect()
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
    use super::shown;

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
