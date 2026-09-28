//! EXPERIMENTAL. Asking a CPython 3.14 through its remote debugging interface
//! (PEP 768, what `sys.remote_exec` does): the interpreter is made to run a
//! short script, which calls jemalloc's `prof.dump`. The process loaded
//! nothing of ours.
//!
//! ```text
//!   _PyRuntime ─► its _Py_DebugOffsets (says where everything below is)
//!     interpreters.head ─► ... ─► the main interpreter (id 0)
//!       threads.main ─► the state of the thread that runs `__main__`
//!         remote_debugger_support: the script's path, and "a call is pending"
//!         eval_breaker: the bit that makes the thread look
//! ```
//!
//! Three things are written into the process, in the order CPython's own
//! writer has them: the path, the flag, the bit. The thread runs the script
//! when it next comes back to Python: between two bytecodes, or where it
//! checks for signals. A thread that waits in one long call (a sleep, a join,
//! a read) does not come back until the call does, and nothing here wakes it:
//! the request is then withdrawn, and said to have been.
//!
//! What is written and where:
//!
//! - Only the state of the thread that runs `__main__` is written to, the
//!   one the interpreter names as such. In a Python that was started as a
//!   program that is the main thread's, which lives as long as the
//!   interpreter does; another thread's is freed when the thread ends, and a
//!   write to one that has ended would land in whatever has the memory now.
//!   That the interpreter still names the same state is looked at again
//!   before each write.
//! - Of `eval_breaker` only the lowest byte is written, the one the bit is
//!   in. The process sets and clears bits there itself, and the rest of the
//!   word is not this tool's to put back as it was a moment ago. Within that
//!   byte a bit the process sets between the read and the write is lost, as
//!   it is with CPython's own writer: a request to give up the GIL is made
//!   again by whoever wants it, but a signal's handler, or a call queued for
//!   the thread, then waits for the next thing that makes the thread look.
//! - The script and what it writes are in a directory of their own, made for
//!   the one request in the process's filesystem, which the process's user
//!   alone can enter. Afterwards the files are removed by their names in
//!   that directory, and the directory if it is empty and still the one that
//!   was made: nothing is removed by following what the process put there.
//! - The script is run by the interpreter as the process's own code is: it
//!   imports `ctypes` there, if the process had not.
//!
//! The process is not stopped. Its own table of offsets is believed only as
//! far as it holds together: the cookie, the version, the size of the path's
//! buffer, and a thread state that points back at its interpreter.

use std::fs::File;
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use super::{read_handed, shown, snapshot_of, Report};
use crate::jemalloc::MAX_DUMP_BYTES;
use crate::root::{self, Root};
use crate::snoop::Process;
use crate::Snapshot;

const _: () = assert!(
    cfg!(target_endian = "little") && size_of::<usize>() == 8,
    "the lowest byte of a word is its first on a little-endian machine only"
);

/// What `_PyRuntime` starts with in a Python that publishes its offsets.
const COOKIE: &[u8; 8] = b"xdebugpy";

/// Where things are in the `_Py_DebugOffsets` of CPython 3.14
/// (`Include/internal/pycore_debug_offsets.h`): the cookie, then 64-bit
/// members only, the same in every build of 3.14. 3.15 has more members
/// before the last six, so its numbers are others.
mod at {
    pub const VERSION: usize = 8;
    pub const FREE_THREADED: usize = 16;
    pub const INTERPRETERS_HEAD: usize = 40;
    pub const INTERPRETER_ID: usize = 56;
    pub const INTERPRETER_NEXT: usize = 64;
    pub const THREADS_MAIN: usize = 80;
    pub const THREAD_INTERP: usize = 200;
    pub const EVAL_BREAKER: usize = 712;
    pub const SUPPORT: usize = 720;
    pub const ENABLED: usize = 728;
    pub const PENDING_CALL: usize = 736;
    pub const SCRIPT_PATH: usize = 744;
    pub const SCRIPT_PATH_SIZE: usize = 752;
    pub const SIZE: usize = 760;
}

/// `_Py_MAX_SCRIPT_PATH_SIZE`: the path's buffer, its end included.
const SCRIPT_PATH_SIZE: u64 = 512;
/// `_PY_EVAL_PLEASE_STOP_BIT`.
const PLEASE_STOP: u8 = 1 << 5;
/// No struct the offsets are into is anywhere near this big.
const MAX_OFFSET: u64 = 1 << 20;
/// Interpreters followed in search of the main one.
const MAX_INTERPRETERS: usize = 4096;
/// The most scanned for `_PyRuntime`: a Python's writable data is a few
/// megabytes.
const MAX_SCAN_BYTES: u64 = 256 << 20;
const SCAN_CHUNK: usize = 1 << 20;

/// How often the script's answer is looked for.
const POLL: Duration = Duration::from_millis(20);
/// How long a request that was withdrawn is given, in case the thread took
/// it between the look and the write.
const GRACE: Duration = Duration::from_millis(300);
/// The files of a request, which are all that is removed of it.
const FILES: [&str; 4] = ["ask.py", "done", "done.new", "heap"];
/// The most read of what the script says of how it went.
const MAX_SAID_BYTES: u64 = 4096;

/// A process's memory, to read and to write.
pub trait Memory {
    fn read(&self, addr: u64, buf: &mut [u8]) -> io::Result<()>;
    fn write(&self, addr: u64, bytes: &[u8]) -> io::Result<()>;

    fn u64_at(&self, addr: u64) -> io::Result<u64> {
        let mut b = [0u8; 8];
        self.read(addr, &mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn i32_at(&self, addr: u64) -> io::Result<i32> {
        let mut b = [0u8; 4];
        self.read(addr, &mut b)?;
        Ok(i32::from_le_bytes(b))
    }
}

/// `/proc/<pid>/mem`, open for both.
struct ProcMem(File);

impl Memory for ProcMem {
    fn read(&self, addr: u64, buf: &mut [u8]) -> io::Result<()> {
        self.0.read_exact_at(buf, addr)
    }

    fn write(&self, addr: u64, bytes: &[u8]) -> io::Result<()> {
        self.0.write_all_at(bytes, addr)
    }
}

/// `/proc/<pid>/mem`, open to read: what is only looked at is not opened to
/// be written.
struct ReadOnly(File);

impl Memory for ReadOnly {
    fn read(&self, addr: u64, buf: &mut [u8]) -> io::Result<()> {
        self.0.read_exact_at(buf, addr)
    }

    fn write(&self, _: u64, _: &[u8]) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::PermissionDenied))
    }
}

/// The offsets a request needs, out of the process's own table.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Offsets {
    /// `PY_VERSION_HEX`, as the interpreter says it.
    version: u64,
    interpreters_head: u64,
    interpreter_id: u64,
    interpreter_next: u64,
    threads_main: u64,
    thread_interp: u64,
    eval_breaker: u64,
    /// In a thread state: where `remote_debugger_support` is.
    support: u64,
    /// In an interpreter: whether remote debugging is on.
    enabled: u64,
    /// In `remote_debugger_support`.
    pending_call: u64,
    script_path: u64,
}

impl Offsets {
    /// The table at `runtime`, if it is one this can use; else why not.
    fn read(mem: &impl Memory, runtime: u64) -> Result<Offsets> {
        let mut table = [0u8; at::SIZE];
        mem.read(runtime, &mut table)
            .context("reading the interpreter's table of offsets")?;
        Offsets::parse(&table)
    }

    fn parse(table: &[u8; at::SIZE]) -> Result<Offsets> {
        let word = |at: usize| u64::from_le_bytes(table[at..at + 8].try_into().unwrap());
        if &table[..8] != COOKIE {
            bail!("no table of offsets where the interpreter's would be");
        }
        let version = word(at::VERSION);
        let (major, minor) = ((version >> 24) & 0xff, (version >> 16) & 0xff);
        if (major, minor) != (3, 14) {
            bail!("the process is Python {major}.{minor}: asking needs CPython 3.14");
        }
        if version & 0xf0 != 0xf0 {
            bail!(
                "the process is a pre-release of Python 3.14 ({version:#x}), whose layout may \
                 be another"
            );
        }
        if word(at::FREE_THREADED) != 0 {
            bail!("the process is a free-threaded Python, on which this has not been tried");
        }
        if word(at::SCRIPT_PATH_SIZE) != SCRIPT_PATH_SIZE {
            bail!(
                "the interpreter's table of offsets is not laid out as CPython 3.14's (a \
                 script path of {} bytes)",
                word(at::SCRIPT_PATH_SIZE)
            );
        }
        let offsets = Offsets {
            version,
            interpreters_head: word(at::INTERPRETERS_HEAD),
            interpreter_id: word(at::INTERPRETER_ID),
            interpreter_next: word(at::INTERPRETER_NEXT),
            threads_main: word(at::THREADS_MAIN),
            thread_interp: word(at::THREAD_INTERP),
            eval_breaker: word(at::EVAL_BREAKER),
            support: word(at::SUPPORT),
            enabled: word(at::ENABLED),
            pending_call: word(at::PENDING_CALL),
            script_path: word(at::SCRIPT_PATH),
        };
        let all = [
            offsets.interpreters_head,
            offsets.interpreter_id,
            offsets.interpreter_next,
            offsets.threads_main,
            offsets.thread_interp,
            offsets.eval_breaker,
            offsets.support,
            offsets.enabled,
            offsets.pending_call,
            offsets.script_path,
        ];
        // The flag and the path are apart in their struct, and the flag's
        // four bytes end before the path begins or begin after it ends.
        let apart = offsets.pending_call + 4 <= offsets.script_path
            || offsets.script_path + SCRIPT_PATH_SIZE <= offsets.pending_call;
        if all.iter().any(|o| *o >= MAX_OFFSET) || !apart {
            bail!("the interpreter's table of offsets holds offsets that cannot be");
        }
        Ok(offsets)
    }
}

/// One line of maps text that is a writable mapping of a file: its range and
/// the file's name.
fn writable_file_mapping(line: &str) -> Option<(u64, u64, &str)> {
    let mut fields = line.splitn(6, ' ');
    let (range, perms) = (fields.next()?, fields.next()?);
    let path = fields.nth(3)?.trim_start();
    if !perms.starts_with("rw") || !path.starts_with('/') {
        return None;
    }
    let (start, end) = range.split_once('-')?;
    Some((
        u64::from_str_radix(start, 16).ok()?,
        u64::from_str_radix(end, 16).ok()?,
        path,
    ))
}

/// Whether the file at `path` is named as a Python is: the program, or its
/// libpython.
fn is_named_python(path: &str) -> bool {
    path.rsplit('/')
        .next()
        .unwrap_or_default()
        .contains("python")
}

/// Whether the process maps a Python at all, which its maps say without its
/// memory being opened.
fn maps_a_python(maps_text: &str) -> bool {
    maps_text
        .lines()
        .filter_map(writable_file_mapping)
        .any(|(_, _, path)| is_named_python(path))
}

/// Where `_PyRuntime` is: in the writable data of the file that is the
/// Python (the program or its libpython, named so), at the cookie its table
/// of offsets starts with. CPython's own writer looks in the same files, for
/// the section of that name; here the file itself is not needed, and a
/// Python whose file has been replaced since it started is found as well.
/// Exactly one place must hold a table that can be used.
fn find_runtime(mem: &impl Memory, maps_text: &str) -> Result<(u64, Offsets)> {
    let mut found: Vec<(u64, Offsets)> = Vec::new();
    let mut refused: Option<anyhow::Error> = None;
    let mut scanned = 0u64;
    let mut pythons = 0usize;
    for (start, end, path) in maps_text.lines().filter_map(writable_file_mapping) {
        if !is_named_python(path) {
            continue;
        }
        pythons += 1;
        let mut at = start;
        let mut chunk = vec![0u8; SCAN_CHUNK];
        while at < end {
            let len = usize::try_from(end - at).map_or(SCAN_CHUNK, |l| l.min(SCAN_CHUNK));
            scanned += len as u64;
            if scanned > MAX_SCAN_BYTES {
                bail!("the process's Python has more writable data than is looked through");
            }
            // A chunk that cannot be read (a page the process has unmapped
            // since) holds nothing to find.
            if mem.read(at, &mut chunk[..len]).is_ok() {
                for offset in (0..len.saturating_sub(COOKIE.len() - 1)).step_by(8) {
                    if &chunk[offset..offset + COOKIE.len()] != COOKIE {
                        continue;
                    }
                    let runtime = at + offset as u64;
                    match Offsets::read(mem, runtime) {
                        Ok(offsets) => found.push((runtime, offsets)),
                        Err(e) => refused = Some(e),
                    }
                }
            }
            at += len as u64;
        }
    }
    match (found.len(), refused) {
        (1, _) => Ok(found.remove(0)),
        (0, Some(why)) => Err(why),
        (0, None) if pythons == 0 => {
            bail!("the process maps no file named as a Python is (python..., libpython...)")
        }
        (0, None) => bail!(
            "no interpreter found in the process's Python: it publishes no table of offsets \
             (CPython 3.13 and later do)"
        ),
        (n, _) => bail!("{n} places in the process look like an interpreter's: not guessing"),
    }
}

/// The main interpreter and the thread that runs its `__main__`:
/// (interpreter, thread state).
fn main_thread(mem: &impl Memory, runtime: u64, o: &Offsets) -> Result<(u64, u64)> {
    // The list is newest first, so with a subinterpreter alive its head is
    // the subinterpreter: the main one is the one numbered 0.
    let mut interp = mem
        .u64_at(runtime + o.interpreters_head)
        .context("reading the list of interpreters")?;
    let mut followed = 0;
    loop {
        if interp == 0 {
            bail!("the process has no running interpreter (it is starting, or exiting)");
        }
        let id = mem
            .u64_at(interp + o.interpreter_id)
            .context("reading an interpreter")?;
        if id == 0 {
            break;
        }
        followed += 1;
        if followed >= MAX_INTERPRETERS {
            bail!("no main interpreter among the first {MAX_INTERPRETERS}");
        }
        interp = mem
            .u64_at(interp + o.interpreter_next)
            .context("reading an interpreter")?;
    }
    if mem
        .i32_at(interp + o.enabled)
        .context("reading the interpreter's settings")?
        != 1
    {
        bail!(
            "remote debugging is turned off in the process (PYTHON_DISABLE_REMOTE_DEBUG, \
             -X disable-remote-debug, or a Python built without it)"
        );
    }
    let thread = mem
        .u64_at(interp + o.threads_main)
        .context("reading the interpreter's main thread")?;
    if thread == 0 {
        bail!(
            "the interpreter has no main thread running: it is embedded in a program that \
             does not say which one is, or it is starting or exiting"
        );
    }
    let back = mem
        .u64_at(thread + o.thread_interp)
        .context("reading the main thread's state")?;
    if back != interp {
        bail!("what would be the main thread's state does not point back at its interpreter");
    }
    Ok((interp, thread))
}

/// Whether the interpreter still names `thread` as the one that runs its
/// `__main__`. A state it names no more may have been freed.
fn still_runs_main(mem: &impl Memory, interp: u64, thread: u64, o: &Offsets) -> bool {
    mem.u64_at(interp + o.threads_main)
        .is_ok_and(|now| now == thread)
}

/// Make the thread run the script at `path` (as the process sees it) when it
/// next looks.
fn request(mem: &impl Memory, interp: u64, thread: u64, o: &Offsets, path: &[u8]) -> Result<()> {
    if path.len() as u64 >= SCRIPT_PATH_SIZE || path.contains(&0) {
        bail!(
            "the script's path is {} bytes, and the interpreter holds {} at most",
            path.len(),
            SCRIPT_PATH_SIZE - 1
        );
    }
    let support = thread + o.support;
    if mem
        .i32_at(support + o.pending_call)
        .context("reading the main thread's state")?
        != 0
    {
        bail!("another request is waiting for the process's main thread to run it");
    }
    if !still_runs_main(mem, interp, thread, o) {
        bail!("the interpreter's main thread changed while it was looked at");
    }
    let mut with_end = path.to_vec();
    with_end.push(0);
    mem.write(support + o.script_path, &with_end)
        .context("writing the script's path into the process")?;
    mem.write(support + o.pending_call, &1i32.to_le_bytes())
        .context("writing the request into the process")?;
    let breaker = thread + o.eval_breaker;
    let mut low = [0u8; 1];
    let woken = mem
        .read(breaker, &mut low)
        .and_then(|()| mem.write(breaker, &[low[0] | PLEASE_STOP]));
    if let Err(e) = woken {
        // Not left half made, for the thread to find whenever it looks.
        let _ = mem.write(support + o.pending_call, &0i32.to_le_bytes());
        return Err(e).context("writing the request into the process");
    }
    Ok(())
}

/// What became of a request that was to be taken back.
#[derive(Debug, PartialEq, Eq)]
enum Left {
    /// It had not been taken up, and is none now. The bit is left: the
    /// thread finds nothing pending when it looks.
    Withdrawn,
    /// The thread had taken it up already: the script runs, or has run.
    TakenUp,
    /// The interpreter names another thread state now, or none: nothing was
    /// written to the one that was asked.
    Gone,
}

/// Take a request back, if it has not been taken up.
fn withdraw(mem: &impl Memory, interp: u64, thread: u64, o: &Offsets) -> io::Result<Left> {
    if !still_runs_main(mem, interp, thread, o) {
        return Ok(Left::Gone);
    }
    let pending = thread + o.support + o.pending_call;
    if mem.i32_at(pending)? == 0 {
        return Ok(Left::TakenUp);
    }
    mem.write(pending, &0i32.to_le_bytes())?;
    Ok(Left::Withdrawn)
}

/// A request that has been made. One that is dropped unanswered is taken
/// back, so that however the asking ends the thread does not look, long
/// afterwards, for a script that is gone.
struct Asked<'a, M: Memory> {
    mem: &'a M,
    interp: u64,
    thread: u64,
    offsets: &'a Offsets,
    answered: bool,
}

impl<M: Memory> Drop for Asked<'_, M> {
    fn drop(&mut self) {
        if !self.answered {
            let _ = withdraw(self.mem, self.interp, self.thread, self.offsets);
        }
    }
}

/// `bytes` as a Python bytes literal, every byte written out: whatever is in
/// a path, the literal is that path and nothing else.
fn bytes_literal(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(4 * bytes.len() + 3);
    s.push_str("b\"");
    for b in bytes {
        write!(s, "\\x{b:02x}").unwrap();
    }
    s.push('"');
    s
}

/// The script: a dump into `heap` in the directory `dir` (as the process
/// sees it), then how it went into `done`, which is put in place whole. It
/// leaves nothing in the process but the modules it imported, and raises
/// nothing.
fn script(dir: &[u8]) -> String {
    format!(
        r#"# Written by systing-heap --ask, and run once by this process at its request:
# a heap dump from jemalloc, for systing-heap to read. Removed afterwards.
def _systing_heap_ask(d):
    import os
    said = b"error the script did not finish"
    try:
        import ctypes
        here = ctypes.CDLL(None)
        mallctl = None
        for name in ("mallctl", "je_mallctl", "_rjem_mallctl"):
            mallctl = getattr(here, name, None)
            if mallctl is not None:
                break
        if mallctl is None:
            said = b"error jemalloc is not the process's allocator (no mallctl)"
        else:
            path = ctypes.c_char_p(d + b"/heap")
            rc = mallctl(b"prof.dump", None, None, ctypes.byref(path),
                         ctypes.c_size_t(ctypes.sizeof(path)))
            if rc == 0:
                said = b"ok"
            else:
                said = (b"error jemalloc's prof.dump failed (%d): is profiling on "
                        b"(prof:true in MALLOC_CONF)?" % rc)
    except Exception as e:
        said = b"error " + repr(e).encode("utf-8", "replace")[:1000]
    try:
        fd = os.open(d + b"/done.new", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, said + b"\n")
        finally:
            os.close(fd)
        os.rename(d + b"/done.new", d + b"/done")
    except OSError:
        pass


_systing_heap_ask({dir})
"#,
        dir = bytes_literal(dir)
    )
}

/// Eight bytes no one can guess, as hex.
fn random_name() -> io::Result<String> {
    let mut bytes = [0u8; 8];
    // SAFETY: the buffer is this function's, of the length given.
    let n = unsafe { libc::getrandom(bytes.as_mut_ptr().cast(), bytes.len(), 0) };
    if n != bytes.len() as isize {
        return Err(io::Error::last_os_error());
    }
    Ok(format!(
        ".systing-heap-ask.{:016x}",
        u64::from_ne_bytes(bytes)
    ))
}

/// The directory made for one request, in the process's filesystem. Once it
/// is the process's user's, what is in it and what its name names are that
/// user's to change: it is used through its handle, and what is removed when
/// it is dropped is the files of [`FILES`] in it, by name, and the directory
/// itself if its name still names it and it is empty.
struct Place {
    base: File,
    name: String,
    handle: File,
    /// As the process sees it.
    seen: PathBuf,
}

impl Place {
    /// A directory in `dir` that the process's user alone can enter, with
    /// the script in it.
    fn make(process: &Process, root: &Root, dir: &Path) -> Result<Place> {
        let pid = process.pid();
        if !dir.is_absolute() {
            bail!("{}: the directory must be an absolute path", dir.display());
        }
        let base = root
            .open_at(dir, libc::O_RDONLY | libc::O_DIRECTORY)
            .with_context(|| format!("opening {} of pid {pid}", dir.display()))?;
        // Known before the process is asked for what could not be read.
        if root::on_remote_fs(&base) {
            bail!(
                "{} of pid {pid} is on a FUSE or network filesystem, where what the process \
                 wrote would be left unread: name another directory with --ask-dir",
                dir.display()
            );
        }
        let name = random_name().context("making a name for the directory")?;
        let path = format!("/proc/self/fd/{}/{name}", base.as_raw_fd());
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .with_context(|| format!("making a directory in {} of pid {pid}", dir.display()))?;
        let handle = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&path)
            .context("opening the directory just made")?;
        // What was opened is what was made: this user's, a directory, and
        // empty. Whoever can write `dir` could have put another there.
        let meta = handle
            .metadata()
            .context("examining the directory just made")?;
        // SAFETY: geteuid has no failure and no arguments.
        let me = unsafe { libc::geteuid() };
        let empty = std::fs::read_dir(format!("/proc/self/fd/{}", handle.as_raw_fd()))
            .is_ok_and(|mut entries| entries.next().is_none());
        if !meta.is_dir() || meta.uid() != me || !empty {
            bail!(
                "{}/{name} of pid {pid} is not the directory that was just made there",
                dir.display()
            );
        }
        let place = Place {
            seen: dir.join(&name),
            base,
            name,
            handle,
        };
        place
            .handle
            .set_permissions(std::fs::Permissions::from_mode(0o700))
            .context("closing the directory to other users")?;

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(place.inside("ask.py"))
            .context("writing the script")?;
        file.write_all(script(place.seen.as_os_str().as_bytes()).as_bytes())
            .context("writing the script")?;
        // The process reads the script and writes beside it as its own
        // user: both are given to that user, the file first.
        if let Some((uid, gid)) = process.owner() {
            for (what, f) in [("the script", &file), ("its directory", &place.handle)] {
                std::os::unix::fs::fchown(f, Some(uid), Some(gid)).with_context(|| {
                    format!("giving {what} to the process's user ({uid}:{gid})")
                })?;
            }
        }
        Ok(place)
    }

    /// `name` in the directory, through its handle.
    fn inside(&self, name: &str) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}/{name}", self.handle.as_raw_fd()))
    }

    /// `name` in the directory, open to read, if it is there.
    fn open(&self, name: &str) -> io::Result<Option<File>> {
        match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(self.inside(name))
        {
            Ok(f) => Ok(Some(f)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// What the script said of how it went, once it has.
    fn said(&self) -> Result<Option<String>> {
        let Some(file) = self
            .open("done")
            .context("looking for the script's answer")?
        else {
            return Ok(None);
        };
        let bytes = read_handed(&file, "the script's answer", MAX_SAID_BYTES)?;
        Ok(Some(String::from_utf8_lossy(&bytes).trim_end().to_string()))
    }

    /// Whether the directory's name, in the directory it was made in, still
    /// names it.
    fn is_still_named(&self) -> bool {
        let Ok(name) = std::ffi::CString::new(self.name.as_str()) else {
            return false;
        };
        // SAFETY: `st` is a plain struct the kernel fills, `name` a C string
        // that outlives the call, and the descriptor is open.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::fstatat(
                self.base.as_raw_fd(),
                name.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        rc == 0
            && self
                .handle
                .metadata()
                .is_ok_and(|m| (m.dev(), m.ino()) == (st.st_dev, st.st_ino))
    }

    /// `name` in the directory `dir`, removed: a file, or with `flags` an
    /// empty directory. A link is removed and not followed, and nothing is
    /// removed beneath a directory.
    fn remove(dir: &File, name: &str, flags: libc::c_int) -> io::Result<()> {
        let name = std::ffi::CString::new(name).map_err(io::Error::other)?;
        // SAFETY: `name` is a C string that outlives the call, and the
        // descriptor is open.
        match unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), flags) } {
            0 => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }
    }
}

impl Drop for Place {
    fn drop(&mut self) {
        for file in FILES {
            let _ = Place::remove(&self.handle, file, 0);
        }
        let removed = self.is_still_named()
            && Place::remove(&self.base, &self.name, libc::AT_REMOVEDIR).is_ok();
        if !removed {
            eprintln!(
                "warning: {} is left behind: it is not empty, or is no longer the directory \
                 that was made",
                shown(&self.seen.display().to_string())
            );
        }
    }
}

/// What asking a process through its interpreter would come to.
#[derive(Debug, PartialEq, Eq)]
pub enum Would {
    /// The process maps no Python.
    NotPython,
    /// It is a Python that cannot be asked, and why.
    Cannot(String),
    /// It is a CPython 3.14 that can be: its version. Whether it answers
    /// is then its main thread's to say, by coming back to Python.
    Answer(String),
}

/// What asking `process` would come to, as far as looking can tell: nothing
/// is written to the process, and its memory is opened to read alone.
pub fn would(process: &Process) -> Result<Would> {
    let pid = process.pid();
    let maps_text = process.maps_text()?;
    if !maps_a_python(&maps_text) {
        return Ok(Would::NotPython);
    }
    let mem = ReadOnly(
        File::open(process.file("mem")).with_context(|| format!("opening /proc/{pid}/mem"))?,
    );
    let found = find_runtime(&mem, &maps_text)
        .and_then(|(runtime, offsets)| main_thread(&mem, runtime, &offsets).map(|_| offsets));
    Ok(match found {
        Ok(offsets) => Would::Answer(format!(
            "{}.{}.{}",
            offsets.version >> 24 & 0xff,
            offsets.version >> 16 & 0xff,
            offsets.version >> 8 & 0xff
        )),
        Err(why) => Would::Cannot(format!("{why:#}")),
    })
}

pub fn ask(
    process: &Process,
    root: &Root,
    dir: &Path,
    wait: Duration,
) -> Result<(Snapshot, Report)> {
    let pid = process.pid();
    let started = Instant::now();
    // What the process maps says whether it is a Python, before its memory
    // is opened to be written.
    let maps_text = process.maps_text()?;
    if !maps_a_python(&maps_text) {
        bail!(
            "pid {pid} cannot be asked through a Python interpreter: the process maps no \
             file named as a Python is (python..., libpython...)"
        );
    }
    let mem = ProcMem(
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(process.file("mem"))
            .with_context(|| {
                format!(
                    "opening /proc/{pid}/mem to write: that needs the same user as the process \
                     (any other, root included, needs CAP_SYS_PTRACE), a process that is \
                     dumpable, and a kernel.yama.ptrace_scope that permits it"
                )
            })?,
    );
    let (runtime, offsets) = find_runtime(&mem, &maps_text)
        .with_context(|| format!("pid {pid} cannot be asked through a Python interpreter"))?;
    let (interp, thread) = main_thread(&mem, runtime, &offsets)
        .with_context(|| format!("pid {pid} cannot be asked through its Python interpreter"))?;

    let place = Place::make(process, root, dir)?;
    let script_path = place.seen.join("ask.py");
    request(
        &mem,
        interp,
        thread,
        &offsets,
        script_path.as_os_str().as_bytes(),
    )
    .with_context(|| format!("asking pid {pid}"))?;
    let mut asked = Asked {
        mem: &mem,
        interp,
        thread,
        offsets: &offsets,
        answered: false,
    };

    // Until the thread has taken the request up it is given `wait`; once it
    // has, the script is given as long again to say how it went.
    let mut taken_up = false;
    let mut until = Instant::now() + wait;
    let said = loop {
        if let Some(said) = place.said()? {
            break said;
        }
        if Instant::now() >= until {
            if taken_up {
                bail!(
                    "pid {pid} took the request up and has not said how it went within {} s \
                     more",
                    wait.as_secs()
                );
            }
            match withdraw(&mem, interp, thread, &offsets) {
                Ok(Left::TakenUp) => {
                    taken_up = true;
                    until = Instant::now() + wait;
                    continue;
                }
                // Taken back, or not to be reached: either way it may have
                // been taken up between the look and the write.
                Ok(Left::Withdrawn | Left::Gone) | Err(_) => {}
            }
            std::thread::sleep(GRACE);
            match place.said()? {
                Some(said) => break said,
                None => bail!(
                    "pid {pid}'s main thread did not run the request within {} s, and the \
                     request was withdrawn: the thread is in a call that does not come back \
                     to Python (a sleep, a join, a read). --snoop reads the profile without \
                     the process's help, and a process that loads the hooks library can \
                     answer whatever its threads do (systing_heap_hooks_listen)",
                    wait.as_secs()
                ),
            }
        }
        std::thread::sleep(POLL);
    };
    asked.answered = true;
    // What the script says is the process's to choose: it is shown with its
    // control characters escaped.
    if let Some(why) = said.strip_prefix("error ") {
        bail!("pid {pid} ran the request, and it failed: {}", shown(why));
    }
    if said != "ok" {
        bail!("pid {pid} ran the request, and answered {said:?}");
    }
    let Some(heap) = place.open("heap").context("opening the dump")? else {
        bail!("pid {pid} says it wrote a dump, and there is none");
    };
    let dump = read_handed(&heap, "the dump the process wrote", MAX_DUMP_BYTES)?;
    let snapshot = snapshot_of(process, &dump, place.seen.join("heap"))?;
    let report = Report {
        by: "python",
        through: script_path,
        dump_bytes: dump.len(),
        millis: started.elapsed().as_millis(),
    };
    Ok((snapshot, report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    /// Memory of a few regions, and the writes made to it, in order.
    #[derive(Default)]
    struct Fake {
        regions: RefCell<BTreeMap<u64, Vec<u8>>>,
        writes: RefCell<Vec<(u64, Vec<u8>)>>,
    }

    impl Fake {
        fn put(&self, addr: u64, bytes: Vec<u8>) {
            self.regions.borrow_mut().insert(addr, bytes);
        }

        fn put_u64(&self, addr: u64, v: u64) {
            self.write_through(addr, &v.to_le_bytes()).unwrap();
        }

        fn write_through(&self, addr: u64, bytes: &[u8]) -> io::Result<()> {
            let mut regions = self.regions.borrow_mut();
            let (start, region) = regions
                .range_mut(..=addr)
                .next_back()
                .ok_or_else(|| io::Error::from_raw_os_error(libc::EIO))?;
            let at = (addr - start) as usize;
            region
                .get_mut(at..at + bytes.len())
                .ok_or_else(|| io::Error::from_raw_os_error(libc::EIO))?
                .copy_from_slice(bytes);
            Ok(())
        }
    }

    impl Memory for Fake {
        fn read(&self, addr: u64, buf: &mut [u8]) -> io::Result<()> {
            let regions = self.regions.borrow();
            let (start, region) = regions
                .range(..=addr)
                .next_back()
                .ok_or_else(|| io::Error::from_raw_os_error(libc::EIO))?;
            let at = (addr - start) as usize;
            buf.copy_from_slice(
                region
                    .get(at..at + buf.len())
                    .ok_or_else(|| io::Error::from_raw_os_error(libc::EIO))?,
            );
            Ok(())
        }

        fn write(&self, addr: u64, bytes: &[u8]) -> io::Result<()> {
            self.writes.borrow_mut().push((addr, bytes.to_vec()));
            self.write_through(addr, bytes)
        }
    }

    const DATA: u64 = 0x7f00_0000_0000;
    const RUNTIME: u64 = DATA + 0x240;
    const INTERP: u64 = 0x5000_0000;
    const THREAD: u64 = 0x6000_0000;

    /// A table as CPython 3.14.7 has it, with offsets of this test's own.
    fn table() -> [u8; at::SIZE] {
        let mut t = [0u8; at::SIZE];
        t[..8].copy_from_slice(COOKIE);
        let mut set = |at: usize, v: u64| t[at..at + 8].copy_from_slice(&v.to_le_bytes());
        set(at::VERSION, 0x030e_07f0);
        set(at::INTERPRETERS_HEAD, 808);
        set(at::INTERPRETER_ID, 8);
        set(at::INTERPRETER_NEXT, 16);
        set(at::THREADS_MAIN, 32);
        set(at::THREAD_INTERP, 16);
        set(at::EVAL_BREAKER, 24);
        set(at::SUPPORT, 1000);
        set(at::ENABLED, 400);
        set(at::PENDING_CALL, 0);
        set(at::SCRIPT_PATH, 4);
        set(at::SCRIPT_PATH_SIZE, 512);
        t
    }

    const MAPS: &str = "\
55d0e0000000-55d0e0001000 r--p 00000000 fd:01 100 /usr/bin/python3.14
55d0e0001000-55d0e0002000 r-xp 00001000 fd:01 100 /usr/bin/python3.14
7f0000000000-7f0000001000 rw-p 00600000 fd:01 200 /usr/lib/libpython3.14.so.1.0
7f0000100000-7f0000101000 rw-p 00000000 fd:01 300 /usr/lib/libother.so
7f0000200000-7f0000201000 rw-p 00000000 00:00 0
";

    /// A process with one interpreter, its main thread, and other data.
    fn process(table: [u8; at::SIZE]) -> Fake {
        let mem = Fake::default();
        let mut data = vec![0u8; 0x1000];
        data[0x240..0x240 + at::SIZE].copy_from_slice(&table);
        mem.put(DATA, data);
        // Another library's data has the cookie too: it is not a Python's.
        let mut other = vec![0u8; 0x1000];
        other[..8].copy_from_slice(COOKIE);
        mem.put(0x7f00_0010_0000, other);
        mem.put(INTERP, vec![0u8; 0x1000]);
        mem.put(THREAD, vec![0u8; 0x2000]);
        mem.put_u64(RUNTIME + 808, INTERP);
        mem.put_u64(INTERP + 32, THREAD);
        mem.write_through(INTERP + 400, &1i32.to_le_bytes())
            .unwrap();
        mem.put_u64(THREAD + 16, INTERP);
        // Bits of the process's own, in the byte that is written and above it.
        mem.put_u64(THREAD + 24, 0xabcd_0000_0000_0102);
        mem
    }

    #[test]
    fn the_runtime_is_found_in_the_pythons_writable_data() {
        let mem = process(table());
        let (runtime, offsets) = find_runtime(&mem, MAPS).unwrap();
        assert_eq!(runtime, RUNTIME);
        assert_eq!(offsets.support, 1000);
        assert_eq!(
            main_thread(&mem, runtime, &offsets).unwrap(),
            (INTERP, THREAD)
        );
    }

    #[test]
    fn a_request_is_the_path_then_the_flag_then_the_bit() {
        let mem = process(table());
        let (_, offsets) = find_runtime(&mem, MAPS).unwrap();
        request(&mem, INTERP, THREAD, &offsets, b"/tmp/x/ask.py").unwrap();
        assert_eq!(
            *mem.writes.borrow(),
            vec![
                (THREAD + 1000 + 4, b"/tmp/x/ask.py\0".to_vec()),
                (THREAD + 1000, vec![1, 0, 0, 0]),
                // One byte: the bit, with the bits the process had there.
                (THREAD + 24, vec![0x02 | 0x20]),
            ]
        );
        // The rest of the word is as the process left it.
        assert_eq!(mem.u64_at(THREAD + 24).unwrap(), 0xabcd_0000_0000_0122);

        assert_eq!(
            withdraw(&mem, INTERP, THREAD, &offsets).unwrap(),
            Left::Withdrawn
        );
        assert_eq!(mem.i32_at(THREAD + 1000).unwrap(), 0);
    }

    #[test]
    fn a_request_the_thread_took_up_is_not_said_to_be_withdrawn() {
        let mem = process(table());
        let (_, offsets) = find_runtime(&mem, MAPS).unwrap();
        request(&mem, INTERP, THREAD, &offsets, b"/tmp/x/ask.py").unwrap();
        // The thread looks, and clears the flag before it runs the script.
        mem.write_through(THREAD + 1000, &0i32.to_le_bytes())
            .unwrap();
        let before = mem.writes.borrow().len();
        assert_eq!(
            withdraw(&mem, INTERP, THREAD, &offsets).unwrap(),
            Left::TakenUp
        );
        assert_eq!(mem.writes.borrow().len(), before);
    }

    #[test]
    fn a_thread_state_the_interpreter_names_no_more_is_not_written_to() {
        let mem = process(table());
        let (_, offsets) = find_runtime(&mem, MAPS).unwrap();
        request(&mem, INTERP, THREAD, &offsets, b"/tmp/x/ask.py").unwrap();
        let before = mem.writes.borrow().len();
        // Another state runs __main__ now: the one asked may be freed.
        mem.put_u64(INTERP + 32, 0x6100_0000);
        assert_eq!(
            withdraw(&mem, INTERP, THREAD, &offsets).unwrap(),
            Left::Gone
        );
        assert!(request(&mem, INTERP, THREAD, &offsets, b"/tmp/y/ask.py").is_err());
        assert_eq!(mem.writes.borrow().len(), before);
    }

    #[test]
    fn a_request_that_is_dropped_unanswered_is_taken_back() {
        let mem = process(table());
        let (_, offsets) = find_runtime(&mem, MAPS).unwrap();
        request(&mem, INTERP, THREAD, &offsets, b"/tmp/x/ask.py").unwrap();
        drop(Asked {
            mem: &mem,
            interp: INTERP,
            thread: THREAD,
            offsets: &offsets,
            answered: false,
        });
        assert_eq!(mem.i32_at(THREAD + 1000).unwrap(), 0);

        request(&mem, INTERP, THREAD, &offsets, b"/tmp/x/ask.py").unwrap();
        drop(Asked {
            mem: &mem,
            interp: INTERP,
            thread: THREAD,
            offsets: &offsets,
            answered: true,
        });
        assert_eq!(mem.i32_at(THREAD + 1000).unwrap(), 1);
    }

    #[test]
    fn a_process_is_known_for_a_python_by_what_it_maps() {
        assert!(maps_a_python(MAPS));
        assert!(!maps_a_python(
            "7f0000100000-7f0000101000 rw-p 00000000 fd:01 300 /usr/lib/libother.so\n"
        ));
        // A directory named so does not make a Python of what is in it.
        assert!(!maps_a_python(
            "7f0000100000-7f0000101000 rw-p 00000000 fd:01 300 /opt/python/lib/libz.so\n"
        ));
    }

    #[test]
    fn a_request_is_not_written_over_one_that_is_waiting() {
        let mem = process(table());
        let (_, offsets) = find_runtime(&mem, MAPS).unwrap();
        mem.write_through(THREAD + 1000, &1i32.to_le_bytes())
            .unwrap();
        let e = request(&mem, INTERP, THREAD, &offsets, b"/tmp/x/ask.py").unwrap_err();
        assert!(format!("{e:#}").contains("another request"), "{e:#}");
        assert!(mem.writes.borrow().is_empty());
    }

    #[test]
    fn a_path_the_interpreter_cannot_hold_is_not_written() {
        let mem = process(table());
        let (_, offsets) = find_runtime(&mem, MAPS).unwrap();
        assert!(request(&mem, INTERP, THREAD, &offsets, &[b'a'; 512]).is_err());
        assert!(request(&mem, INTERP, THREAD, &offsets, b"/tmp/\0/ask.py").is_err());
        assert!(mem.writes.borrow().is_empty());
        request(&mem, INTERP, THREAD, &offsets, &[b'a'; 511]).unwrap();
    }

    fn refused(change: impl FnOnce(&mut [u8; at::SIZE])) -> String {
        let mut t = table();
        change(&mut t);
        let e = find_runtime(&process(t), MAPS).unwrap_err();
        format!("{e:#}")
    }

    fn set(t: &mut [u8; at::SIZE], at: usize, v: u64) {
        t[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }

    #[test]
    fn a_python_this_was_not_written_for_is_refused_by_what_it_says_of_itself() {
        let why = refused(|t| set(t, at::VERSION, 0x030d_05f0));
        assert!(why.contains("Python 3.13"), "{why}");
        let why = refused(|t| set(t, at::VERSION, 0x030f_00f0));
        assert!(why.contains("Python 3.15"), "{why}");
        let why = refused(|t| set(t, at::VERSION, 0x030e_00b1));
        assert!(why.contains("pre-release"), "{why}");
        let why = refused(|t| set(t, at::FREE_THREADED, 1));
        assert!(why.contains("free-threaded"), "{why}");
        let why = refused(|t| set(t, at::SCRIPT_PATH_SIZE, 256));
        assert!(why.contains("not laid out"), "{why}");
        let why = refused(|t| set(t, at::SUPPORT, 1 << 40));
        assert!(why.contains("cannot be"), "{why}");
        // The flag inside the path's buffer.
        let why = refused(|t| set(t, at::PENDING_CALL, 100));
        assert!(why.contains("cannot be"), "{why}");
    }

    #[test]
    fn a_process_that_is_no_python_is_said_to_be_none() {
        let mem = process(table());
        let e = find_runtime(
            &mem,
            "7f0000100000-7f0000101000 rw-p 00000000 fd:01 300 /usr/lib/libother.so\n",
        )
        .unwrap_err();
        assert!(format!("{e:#}").contains("maps no file named"), "{e:#}");
    }

    #[test]
    fn two_tables_are_not_chosen_between() {
        let mem = process(table());
        let mut data = vec![0u8; 0x1000];
        data[0x240..0x240 + at::SIZE].copy_from_slice(&table());
        data[0x800..0x800 + at::SIZE].copy_from_slice(&table());
        mem.put(DATA, data);
        let e = find_runtime(&mem, MAPS).unwrap_err();
        assert!(format!("{e:#}").contains("not guessing"), "{e:#}");
    }

    #[test]
    fn the_main_interpreter_is_the_one_numbered_zero() {
        let mem = process(table());
        let (runtime, offsets) = find_runtime(&mem, MAPS).unwrap();
        // A subinterpreter, made later, is the head of the list.
        const SUB: u64 = 0x5800_0000;
        mem.put(SUB, vec![0u8; 0x1000]);
        mem.put_u64(SUB + 8, 1);
        mem.put_u64(SUB + 16, INTERP);
        mem.put_u64(RUNTIME + 808, SUB);
        assert_eq!(
            main_thread(&mem, runtime, &offsets).unwrap(),
            (INTERP, THREAD)
        );
    }

    #[test]
    fn an_interpreter_that_cannot_be_asked_says_why() {
        let why = |change: &dyn Fn(&Fake)| {
            let mem = process(table());
            let (runtime, offsets) = find_runtime(&mem, MAPS).unwrap();
            change(&mem);
            format!("{:#}", main_thread(&mem, runtime, &offsets).unwrap_err())
        };
        let off = why(&|m| m.write_through(INTERP + 400, &0i32.to_le_bytes()).unwrap());
        assert!(off.contains("turned off"), "{off}");
        let none = why(&|m| m.put_u64(INTERP + 32, 0));
        assert!(none.contains("no main thread"), "{none}");
        let other = why(&|m| m.put_u64(THREAD + 16, 0x1234));
        assert!(other.contains("does not point back"), "{other}");
        let gone = why(&|m| m.put_u64(RUNTIME + 808, 0));
        assert!(gone.contains("no running interpreter"), "{gone}");
    }

    #[test]
    fn a_path_is_written_into_the_script_byte_for_byte() {
        assert_eq!(bytes_literal(b"/t\"\\\n"), r#"b"\x2f\x74\x22\x5c\x0a""#);
        let s = script(b"/tmp/a b");
        assert!(s.ends_with("_systing_heap_ask(b\"\\x2f\\x74\\x6d\\x70\\x2f\\x61\\x20\\x62\")\n"));
    }

    #[test]
    fn only_writable_mappings_of_files_are_looked_in() {
        let lines: Vec<_> = MAPS.lines().filter_map(writable_file_mapping).collect();
        assert_eq!(
            lines,
            vec![
                (
                    0x7f00_0000_0000,
                    0x7f00_0000_1000,
                    "/usr/lib/libpython3.14.so.1.0"
                ),
                (0x7f00_0010_0000, 0x7f00_0010_1000, "/usr/lib/libother.so"),
            ]
        );
    }
}
