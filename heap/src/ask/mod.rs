//! EXPERIMENTAL. Asking a running process for a heap dump of its own.
//!
//! [`crate::snoop`] reads jemalloc's profile out of a process's memory,
//! without its help. Here the process is asked, and the dump is jemalloc's
//! own: written under its locks, in its documented format. There are two ways
//! to ask:
//!
//! - [`responder`]: the process loaded the hooks library and listens
//!   (`systing_heap_hooks_listen`). The request goes to its Unix socket, and
//!   the answer carries the dump as a descriptor. Nothing is written to disk,
//!   and what the process's threads are doing does not matter.
//! - [`python`]: a CPython 3.14 that loaded nothing of ours. The interpreter's
//!   remote debugging interface (PEP 768) makes its main thread run a short
//!   script, which calls jemalloc's `prof.dump`. It runs when that thread next
//!   comes back to Python, which a thread that waits in one long call does
//!   not.
//!
//! Either way the process needs `prof:true` in its `MALLOC_CONF`.

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

/// Where the responder's socket and the script's files are, in the process's
/// own filesystem, unless told otherwise.
pub const DEFAULT_DIR: &str = "/tmp";

/// How long the process is given to answer, unless told otherwise.
pub const DEFAULT_WAIT: Duration = Duration::from_secs(30);

/// How to ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum How {
    /// The responder if the process has one, else Python.
    Auto,
    /// The hooks library's socket.
    Responder,
    /// CPython 3.14's remote debugging interface.
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
}

impl Report {
    pub fn summary(&self, pid: u32) -> String {
        format!(
            "pid {pid}: asked through its {} ({}); it wrote a dump of {} bytes, {} ms after it was asked",
            match self.by {
                "responder" => "responder",
                _ => "Python interpreter",
            },
            self.through.display(),
            self.dump_bytes,
            self.millis
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
        How::Responder => responder::ask(process, root, dir, wait),
        How::Python => python::ask(process, root, dir, wait),
        How::Auto => match responder::ask(process, root, dir, wait) {
            Ok(asked) => Ok(asked),
            // No one listens there: the process may still be a Python.
            Err(e) if e.downcast_ref::<responder::NoResponder>().is_some() => {
                python::ask(process, root, dir, wait).with_context(|| {
                    format!("{e:#}, and asking its Python interpreter instead did not work either")
                })
            }
            Err(e) => Err(e),
        },
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
    match snoop::run_within(limit, move || {
        let root = process.root()?;
        ask(&process, &root, how, &dir, wait)
    }) {
        Ok(result) => result,
        Err(snoop::Wait::TimedOut) => bail!(
            "gave up after {} s: reading what the process answered did not finish",
            limit.as_secs()
        ),
        Err(snoop::Wait::Panicked) => bail!("asking the process failed unexpectedly"),
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
