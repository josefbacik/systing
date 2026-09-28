//! EXPERIMENTAL. Asking the hooks library's responder
//! (`systing_heap_hooks_listen`).
//!
//! The responder is a thread of the process that listens on a Unix socket in
//! the process's own filesystem, `<dir>/.systing-heap.<pid>`, the pid being
//! the one the process knows itself by. A request is one line and so is the
//! answer, which carries descriptors: the dump, in an anonymous file that can
//! no longer change, and the Python code map when the process writes one.
//!
//! ```text
//!   -> "systing-heap 1 dump\n"
//!   <- "ok 1 heap=<bytes> map=<0|1>\n"
//!   <- "error <why>\n"
//! ```
//!
//! The socket is opened beneath the process's root, as a name and no link,
//! and connected to through that handle. What answers is checked to be the
//! process that was asked about (the socket's peer is that pid), before
//! anything is said to it, and what it hands over is read as any file of
//! the process's is: a regular file, on a local filesystem, of no more than
//! so many bytes.

use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use super::{read_handed, shown, snapshot_of, Report};
use crate::jemalloc::MAX_DUMP_BYTES;
use crate::pycode::{self, CodeMap};
use crate::root::Root;
use crate::snoop::{self, Process};
use crate::{perfmap, Snapshot};

const REQUEST: &[u8] = b"systing-heap 1 dump\n";
/// The longest answer read: the library's are well under a hundred bytes.
const MAX_REPLY: usize = 256;
/// Descriptors an answer may carry: the dump and the code map.
const MAX_FDS: usize = 2;

/// The process has no responder: no socket where one would be, or one that
/// no one answers at. Another way of asking may still work.
#[derive(Debug)]
pub struct NoResponder(String);

impl NoResponder {
    #[cfg(test)]
    pub(crate) fn new(why: String) -> NoResponder {
        NoResponder(why)
    }
}

impl std::fmt::Display for NoResponder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for NoResponder {}

/// Where the process's socket is, as the process sees it.
fn socket_of(process: &Process, dir: &Path) -> (String, std::path::PathBuf) {
    let name = format!(".systing-heap.{}", snoop::own_pid(process));
    let shown = dir.join(&name);
    (name, shown)
}

/// A connection to the process's responder, which is that process's: what
/// answers at the socket has been checked to be the process asked about, and
/// nothing has been said to it yet.
fn connect(
    process: &Process,
    root: &Root,
    dir: &Path,
    wait: Duration,
) -> Result<(UnixStream, std::path::PathBuf)> {
    let pid = process.pid();
    let (name, shown) = socket_of(process, dir);

    // The directory is opened beneath the process's root and the socket is
    // named through that handle, which also keeps the name short of what a
    // Unix socket's address holds.
    let dir_handle = match root.open_at(dir, libc::O_PATH | libc::O_DIRECTORY) {
        Ok(d) => d,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(NoResponder(format!(
                "pid {pid} has no responder: it has no directory {}",
                dir.display()
            ))
            .into())
        }
        Err(e) => return Err(e).with_context(|| format!("opening {} of pid {pid}", dir.display())),
    };
    // The socket is opened as a name, a link not followed, and looked at and
    // connected to through that handle: what is connected to is what was
    // looked at, whatever the name comes to name meanwhile. A link there
    // would lead out of the process's root, into this tool's.
    let socket = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_NOFOLLOW)
        .open(format!("/proc/self/fd/{}/{name}", dir_handle.as_raw_fd()))
    {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(NoResponder(format!(
                "pid {pid} has no responder: there is no {} (the process calls \
                 systing_heap_hooks_listen to have one)",
                shown.display()
            ))
            .into())
        }
        Err(e) => return Err(e).with_context(|| format!("examining {}", shown.display())),
    };
    let is_socket = socket
        .metadata()
        .with_context(|| format!("examining {}", shown.display()))?
        .file_type()
        .is_socket();
    if !is_socket {
        bail!("{} of pid {pid} is not a socket", shown.display());
    }
    let address = format!("/proc/self/fd/{}", socket.as_raw_fd());
    let stream = match UnixStream::connect(&address) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
            return Err(NoResponder(format!(
                "pid {pid} has no responder: no one answers at {}, which a process that is \
                 gone left behind",
                shown.display()
            ))
            .into())
        }
        Err(e) => {
            return Err(e).with_context(|| {
                format!(
                    "connecting to {} of pid {pid}: the responder answers the process's own \
                     user and root",
                    shown.display()
                )
            })
        }
    };
    stream.set_read_timeout(Some(wait))?;
    stream.set_write_timeout(Some(wait))?;

    let peer = peer_pid(&stream).context("asking who answers")?;
    if peer != pid as i32 {
        bail!(
            "{} is answered by pid {peer}, not by pid {pid}",
            shown.display()
        );
    }

    Ok((stream, shown))
}

/// Whether the process has a responder that answers: the socket, as the
/// process sees it. Nothing is asked of it: the connection is made, what
/// answers is checked, and the connection is let go.
pub fn answers(process: &Process, root: &Root, dir: &Path) -> Result<std::path::PathBuf> {
    let (_, shown) = connect(process, root, dir, Duration::from_secs(5))?;
    Ok(shown)
}

pub fn ask(
    process: &Process,
    root: &Root,
    dir: &Path,
    wait: Duration,
) -> Result<(Snapshot, Report)> {
    let pid = process.pid();
    let started = Instant::now();
    let (stream, shown) = connect(process, root, dir, wait)?;

    (&stream)
        .write_all(REQUEST)
        .with_context(|| format!("asking pid {pid}"))?;
    let (line, mut fds) = receive(&stream).with_context(|| {
        format!(
            "waiting for pid {pid} to answer (no longer than {} s)",
            wait.as_secs()
        )
    })?;
    let has_map = parse_reply(&line, fds.len()).with_context(|| format!("pid {pid} answered"))?;
    let map = has_map.then(|| File::from(fds.remove(1)));
    let heap = File::from(fds.remove(0));

    let dump = read_handed(&heap, "the dump the process handed over", MAX_DUMP_BYTES)?;
    let mut snapshot = snapshot_of(process, &dump, shown.clone())?;
    if let Some(map) = map {
        match code_map(&map, &snapshot) {
            Ok(map) => {
                eprintln!("pid {pid}: Python frames named from the code map it handed over");
                snapshot.py_code = Some(Arc::new(map));
            }
            Err(e) => eprintln!("warning: not using the code map pid {pid} handed over: {e:#}"),
        }
    }
    let report = Report {
        by: "responder",
        through: shown,
        dump_bytes: dump.len(),
        millis: started.elapsed().as_millis(),
    };
    Ok((snapshot, report))
}

/// The process at the other end, as this one numbers it.
fn peer_pid(stream: &UnixStream) -> io::Result<i32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `cred` and `len` are this function's own, of the sizes given.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(cred.pid)
}

/// One answer: its line, to the newline, and the descriptors that came with
/// it. They are this process's from the moment they arrive, and are closed
/// when dropped, whatever else is wrong with the answer.
fn receive(stream: &UnixStream) -> io::Result<(Vec<u8>, Vec<OwnedFd>)> {
    let mut line = Vec::new();
    let mut fds: Vec<OwnedFd> = Vec::new();
    while !line.contains(&b'\n') && line.len() < MAX_REPLY {
        let mut buf = [0u8; MAX_REPLY];
        // Room for more descriptors than an answer has, aligned as the
        // headers in it must be.
        let mut control = [0u64; 8];
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len() - line.len(),
        };
        // SAFETY: a msghdr of zeroes is an empty one.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = size_of_val(&control) as _;
        let n = loop {
            // SAFETY: every pointer in `msg` is to a buffer above, of the
            // length given with it, that outlives the call.
            let n = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
            if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break n;
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        take_fds(&msg, &mut fds);
        if msg.msg_flags & libc::MSG_CTRUNC != 0 || fds.len() > MAX_FDS {
            return Err(io::Error::other("the answer carries too many descriptors"));
        }
        if n == 0 {
            break;
        }
        line.extend_from_slice(&buf[..n as usize]);
    }
    Ok((line, fds))
}

/// The descriptors a received message carries, owned from here on.
fn take_fds(msg: &libc::msghdr, fds: &mut Vec<OwnedFd>) {
    // SAFETY: the kernel wrote the control buffer `msg` points at, and these
    // macros walk it within the length the kernel gave back. Each descriptor
    // in it is new and this process's alone.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(msg);
        while !cmsg.is_null() {
            let header = &*cmsg;
            if header.cmsg_level == libc::SOL_SOCKET && header.cmsg_type == libc::SCM_RIGHTS {
                let bytes = (header.cmsg_len as usize).saturating_sub(libc::CMSG_LEN(0) as usize);
                let data = libc::CMSG_DATA(cmsg);
                for i in 0..bytes / size_of::<RawFd>() {
                    let fd = data.add(i * size_of::<RawFd>()).cast::<RawFd>();
                    fds.push(OwnedFd::from_raw_fd(fd.read_unaligned()));
                }
            }
            cmsg = libc::CMSG_NXTHDR(msg, cmsg);
        }
    }
}

/// Whether the answer, which came with `fds` descriptors, says there is a
/// code map among them; an error for an answer that is not a dump.
fn parse_reply(line: &[u8], fds: usize) -> Result<bool> {
    let text = String::from_utf8_lossy(line);
    let Some(text) = text.strip_suffix('\n') else {
        bail!("nothing, or a line with no end: {text:?}");
    };
    // What it says is the process's to choose: it is shown with its control
    // characters escaped.
    if let Some(why) = text.strip_prefix("error ") {
        bail!("{}", shown(why));
    }
    let mut words = text.split(' ');
    if (words.next(), words.next()) != (Some("ok"), Some("1")) {
        bail!("{text:?}, which is not an answer this version knows");
    }
    let mut has_map = None;
    for word in words {
        if let Some(v) = word.strip_prefix("map=") {
            has_map = match v {
                "0" => Some(false),
                "1" => Some(true),
                _ => None,
            };
        }
    }
    let Some(has_map) = has_map else {
        bail!("{text:?}, which does not say whether a code map comes with it");
    };
    if fds != 1 + usize::from(has_map) {
        bail!("{text:?} with {fds} descriptor(s), which is not what it says");
    }
    Ok(has_map)
}

/// The code map in `file`, if it is the one the dump's process wrote.
fn code_map(file: &File, snapshot: &Snapshot) -> Result<CodeMap> {
    let Some(token) = pycode::token_of(&snapshot.maps) else {
        bail!("the dump's process writes no code map");
    };
    let bytes = read_handed(file, "the code map", perfmap::MAX_BYTES)?;
    let map = CodeMap::parse(&String::from_utf8_lossy(&bytes)).context("not a code map")?;
    if map.token != token {
        bail!("its token is not the dump's, {token}");
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_answer_says_whether_a_code_map_comes_with_it() {
        assert!(!parse_reply(b"ok 1 heap=19328 map=0\n", 1).unwrap());
        assert!(parse_reply(b"ok 1 heap=19328 map=1\n", 2).unwrap());
        // A field this version does not know is passed over.
        assert!(!parse_reply(b"ok 1 heap=1 later=x map=0\n", 1).unwrap());
    }

    #[test]
    fn an_error_is_said_as_the_process_said_it() {
        let e = parse_reply(b"error jemalloc's prof.dump failed\n", 0).unwrap_err();
        assert_eq!(e.to_string(), "jemalloc's prof.dump failed");
    }

    #[test]
    fn an_answer_that_is_not_one_is_refused() {
        for (line, fds) in [
            (&b""[..], 0),
            (b"ok 1 heap=1 map=0", 1),
            (b"ok 2 heap=1 map=0\n", 1),
            (b"ok 1 heap=1\n", 1),
            (b"ok 1 heap=1 map=2\n", 1),
            (b"HTTP/1.1 400 Bad Request\n", 0),
        ] {
            assert!(parse_reply(line, fds).is_err(), "{line:?}");
        }
    }

    #[test]
    fn the_descriptors_must_be_as_many_as_the_answer_says() {
        assert!(parse_reply(b"ok 1 heap=1 map=1\n", 1).is_err());
        assert!(parse_reply(b"ok 1 heap=1 map=0\n", 2).is_err());
        assert!(parse_reply(b"ok 1 heap=1 map=0\n", 0).is_err());
    }
}
