//! Keeping one snapshot per process: pick each pid's latest dump under a
//! jemalloc `prof_prefix`, and delete that pid's older dumps once the latest
//! is safely in the database.
//!
//! A file is a candidate when its name starts with the prefix's file name and
//! it sits directly in the prefix's directory. The pid and sequence number
//! are the two numbers jemalloc writes right after the prefix
//! (`<prefix>.<pid>.<seq>.<kind>.heap`). Nothing else about the name is
//! required, so names jemalloc extends further still match.
//!
//! Before a file is read or deleted it must be a regular file (not a
//! symlink, never followed) and start with `heap_v2/`. Every access goes
//! through one open handle on the directory (`openat`, `fstatat`,
//! `unlinkat` with a single name component), so nothing outside that
//! directory is ever removed and a symlink's target is never touched. A
//! delete first checks that the name still refers to the file examined (same
//! device, inode and mtime); Linux has no unlink-by-inode, so a file swapped
//! in between that check and the unlink is still removed, and only someone
//! who can write the directory can do that.
//!
//! Given a [`Root`], the prefix's directory is reached beneath it, so no
//! symlink on the way there leads outside the root either.
//!
//! One pid is one process: two processes that wrote the same pid into the
//! same directory (a restart that got its pid back, pid 1 in several
//! containers) count as one, and the higher sequence numbers win.
//!
//! Every read is bounded by [`crate::jemalloc::MAX_DUMP_BYTES`].

use std::collections::BTreeMap;
use std::ffi::{CString, OsStr, OsString};
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::root::Root;
use crate::{jemalloc, Snapshot};

/// A dump file found under the prefix, identified by pid and sequence.
#[derive(Debug, Clone)]
pub struct Dump {
    pub path: PathBuf,
    pub pid: i32,
    pub seq: Option<u64>,
    name: OsString,
    dev: u64,
    ino: u64,
    mtime_ns: i64,
    uid: u32,
}

/// A file that starts with the prefix but was left alone, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    pub path: PathBuf,
    pub reason: String,
}

/// What one prefix contributes to a run.
pub struct Plan {
    /// Parsed snapshots to load: each pid's latest, or every dump with
    /// `load_all`.
    pub load: Vec<Snapshot>,
    /// Older dumps to delete after the database is written.
    pub delete: Vec<Dump>,
    /// Newer dumps that did not parse (jemalloc may still be writing them),
    /// kept on disk.
    pub unparsed: Vec<Skipped>,
    /// Prefix-matching files that are not dumps this tool can place.
    pub skipped: Vec<Skipped>,
    dir: File,
}

/// Scan `prefix` (a jemalloc `prof_prefix`, e.g. `/data/heap/jeprof`).
/// Each pid's newest dump that parses is loaded; `load_all` loads the older
/// ones too, and `delete_older` deletes them once the output is written.
/// With a `root`, `prefix` is a path beneath it.
pub fn scan(
    prefix: &Path,
    load_all: bool,
    delete_older: bool,
    root: Option<&Root>,
) -> Result<Plan> {
    let name_prefix = prefix
        .file_name()
        .with_context(|| format!("{}: a prefix needs a file-name part", prefix.display()))?
        .as_bytes()
        .to_vec();
    let dir_path = match prefix.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let dir = match root {
        Some(root) => root.open_at(&dir_path, libc::O_RDONLY | libc::O_DIRECTORY),
        None => std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(&dir_path),
    }
    .with_context(|| format!("opening directory {}", dir_path.display()))?;

    let mut by_pid: BTreeMap<i32, Vec<Dump>> = BTreeMap::new();
    let mut skipped = Vec::new();
    // List through the handle itself, so the names are this directory's.
    let listing = format!("/proc/self/fd/{}", dir.as_raw_fd());
    let mut names: Vec<OsString> = std::fs::read_dir(&listing)
        .with_context(|| format!("listing {}", dir_path.display()))?
        .filter_map(|e| e.ok().map(|e| e.file_name()))
        .filter(|n| n.as_bytes().starts_with(&name_prefix))
        .collect();
    names.sort();

    for name in names {
        let path = dir_path.join(&name);
        let skip = |reason: &str| Skipped {
            path: path.clone(),
            reason: reason.to_string(),
        };
        let Some(st) = stat_at(&dir, &name) else {
            continue; // gone since the listing
        };
        if st.st_mode & libc::S_IFMT != libc::S_IFREG {
            skipped.push(skip("not a regular file"));
            continue;
        }
        match read_at(&dir, &name, Some(16)) {
            // The inode checked for the header is the one recorded: a swap
            // between the stat and this open is caught here.
            Ok((_, ino)) if ino != st.st_ino => {
                skipped.push(skip("changed while it was examined"));
                continue;
            }
            Ok((head, _)) if head.starts_with(b"heap_v2/") => {}
            Ok(_) => {
                skipped.push(skip("not a jemalloc heap_v2 dump"));
                continue;
            }
            Err(_) => {
                skipped.push(skip("unreadable"));
                continue;
            }
        }
        let Some((pid, seq)) = pid_and_seq(&name_prefix, name.as_bytes()) else {
            skipped.push(skip("no pid after the prefix, so its process is unknown"));
            continue;
        };
        by_pid.entry(pid).or_default().push(Dump {
            path,
            pid,
            seq,
            name,
            dev: st.st_dev,
            ino: st.st_ino,
            mtime_ns: st.st_mtime * 1_000_000_000 + st.st_mtime_nsec,
            uid: st.st_uid,
        });
    }

    let mut plan = Plan {
        load: Vec::new(),
        delete: Vec::new(),
        unparsed: Vec::new(),
        skipped,
        dir,
    };
    for (_, mut dumps) in by_pid {
        // Newest first: by sequence, or by mtime alone when any of this
        // pid's names has no sequence (one rule per pid keeps the order
        // total).
        if dumps.iter().all(|d| d.seq.is_some()) {
            dumps.sort_by_key(|d| std::cmp::Reverse((d.seq, d.mtime_ns)));
        } else {
            dumps.sort_by_key(|d| std::cmp::Reverse(d.mtime_ns));
        }
        let mut loaded_one = false;
        for d in dumps {
            let older = loaded_one;
            if older && !load_all {
                if delete_older {
                    plan.delete.push(d);
                }
                continue;
            }
            match load(&plan.dir, &d) {
                Ok(s) => {
                    plan.load.push(s);
                    loaded_one = true;
                    if older && delete_older {
                        plan.delete.push(d);
                    }
                }
                // An older dump goes whether or not it parses, as it would
                // unread.
                Err(_) if older && delete_older => plan.delete.push(d),
                // Kept: a newer dump may be mid-write, and with nothing
                // deleted an older one is still the user's data.
                Err(e) => plan.unparsed.push(Skipped {
                    path: d.path.clone(),
                    reason: format!("{e:#}"),
                }),
            }
        }
    }
    Ok(plan)
}

/// Delete `plan.delete`, each only if its name still refers to the regular
/// file that was examined. Returns the paths deleted; a file that changed is
/// reported and kept.
pub fn delete(plan: &Plan) -> (Vec<PathBuf>, Vec<Skipped>) {
    let mut deleted = Vec::new();
    let mut kept = Vec::new();
    for d in &plan.delete {
        let same = stat_at(&plan.dir, &d.name).is_some_and(|st| {
            st.st_mode & libc::S_IFMT == libc::S_IFREG
                && st.st_dev == d.dev
                && st.st_ino == d.ino
                && st.st_mtime * 1_000_000_000 + st.st_mtime_nsec == d.mtime_ns
        });
        if !same {
            kept.push(Skipped {
                path: d.path.clone(),
                reason: "changed since it was examined".into(),
            });
            continue;
        }
        let c = cstr(&d.name);
        // SAFETY: a valid directory fd and a NUL-terminated name.
        if unsafe { libc::unlinkat(plan.dir.as_raw_fd(), c.as_ptr(), 0) } == 0 {
            deleted.push(d.path.clone());
        } else {
            kept.push(Skipped {
                path: d.path.clone(),
                reason: format!("delete failed: {}", std::io::Error::last_os_error()),
            });
        }
    }
    (deleted, kept)
}

/// The pid and sequence jemalloc writes right after the prefix:
/// `<prefix>.<pid>.<seq>...`. A prefix given with its trailing dot
/// (`jeprof.`) works too.
fn pid_and_seq(prefix: &[u8], name: &[u8]) -> Option<(i32, Option<u64>)> {
    let rest = name.strip_prefix(prefix)?;
    let rest = if prefix.ends_with(b".") {
        rest
    } else {
        rest.strip_prefix(b".")?
    };
    let rest = std::str::from_utf8(rest).ok()?;
    let mut parts = rest.split('.');
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let pid = parts.next().filter(|s| digits(s))?.parse().ok()?;
    let seq = parts
        .next()
        .filter(|s| digits(s))
        .and_then(|s| s.parse().ok());
    Some((pid, seq))
}

fn load(dir: &File, d: &Dump) -> Result<Snapshot> {
    let cap = jemalloc::MAX_DUMP_BYTES;
    let (bytes, ino) = read_at(dir, &d.name, Some(cap + 1))?;
    if ino != d.ino {
        bail!("replaced since it was examined");
    }
    if bytes.len() as u64 > cap {
        bail!("larger than {cap} bytes");
    }
    let text = String::from_utf8(bytes).context("not UTF-8")?;
    let mut s = jemalloc::parse(&text)?;
    s.source_path = d.path.clone();
    s.pid = Some(d.pid);
    s.seq = d.seq;
    s.trigger = kind_letter(&d.name).and_then(jemalloc::trigger_for_kind);
    s.dumped_at_unix_ns = Some(d.mtime_ns);
    s.owner_uid = Some(d.uid);
    Ok(s)
}

/// The kind letter jemalloc puts after the sequence (`.<pid>.<seq>.<kind>`).
fn kind_letter(name: &OsStr) -> Option<char> {
    let name = name.to_str()?;
    let stem = name.strip_suffix(".heap")?;
    stem.rsplit('.').next()?.chars().next()
}

fn cstr(name: &OsStr) -> CString {
    // Directory entry names never contain NUL.
    CString::new(name.as_bytes()).expect("no NUL in a file name")
}

fn stat_at(dir: &File, name: &OsStr) -> Option<libc::stat> {
    let c = cstr(name);
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: valid fd, NUL-terminated name, st is a writable stat.
    let rc = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            c.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    (rc == 0).then_some(st)
}

/// Read a file in `dir` without following symlinks, its first `limit`
/// bytes, with the inode of what was read.
fn read_at(dir: &File, name: &OsStr, limit: Option<u64>) -> std::io::Result<(Vec<u8>, u64)> {
    let c = cstr(name);
    // O_NONBLOCK: a FIFO swapped in after the stat must not hang the open.
    // SAFETY: valid fd and NUL-terminated name.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fd was just opened and is owned here.
    let file = unsafe { File::from_raw_fd(fd) };
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    let mut buf = Vec::new();
    match limit {
        Some(n) => (&file).take(n).read_to_end(&mut buf)?,
        None => (&file).read_to_end(&mut buf)?,
    };
    Ok((buf, std::os::unix::fs::MetadataExt::ino(&meta)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_and_seq_come_right_after_the_prefix() {
        assert_eq!(
            pid_and_seq(b"jeprof", b"jeprof.21.6.f.heap"),
            Some((21, Some(6)))
        );
        assert_eq!(
            pid_and_seq(b"jeprof.", b"jeprof.21.6.i6.heap"),
            Some((21, Some(6)))
        );
        // Whatever jemalloc appends after the sequence is not examined.
        assert_eq!(
            pid_and_seq(b"jeprof", b"jeprof.7.3.anything.else"),
            Some((7, Some(3)))
        );
        assert_eq!(pid_and_seq(b"jeprof", b"jeprof.7.heap"), Some((7, None)));
        // Another prefix that starts with ours is not ours.
        assert_eq!(pid_and_seq(b"jeprof", b"jeprof2.5.1.f.heap"), None);
        assert_eq!(pid_and_seq(b"jeprof", b"jeprof.heap"), None);
    }

    #[test]
    fn kind_letter_is_the_last_part_before_heap() {
        assert_eq!(kind_letter(OsStr::new("jeprof.1.2.i2.heap")), Some('i'));
        assert_eq!(kind_letter(OsStr::new("jeprof.1.2.f.heap")), Some('f'));
    }
}
