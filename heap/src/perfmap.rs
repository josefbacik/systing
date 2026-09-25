//! Perf maps: `/tmp/perf-<pid>.map`, where a process names code it generated
//! at runtime. Python's perf trampolines (3.12+, `-X perf`,
//! `PYTHONPERFSUPPORT=1`) write one line per Python function,
//! `<start hex> <size hex> py::<qualname>:<file>`, so the trampoline frames in
//! a heap snapshot's stacks name the Python functions they ran.

use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use crate::root::Root;

/// The largest perf map read: far beyond any real process's (one short
/// line per Python function), small enough that a planted file cannot
/// exhaust memory.
pub const MAX_BYTES: u64 = 256 << 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub start: u64,
    pub end: u64,
    pub name: String,
}

/// A parsed perf map, sorted by start address.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PerfMap {
    entries: Vec<Entry>,
}

/// What a perf-map entry names.
#[derive(Debug, PartialEq, Eq)]
pub enum Symbol<'a> {
    /// A Python function's trampoline.
    Python { qualname: &'a str, file: &'a str },
    /// Anything else a JIT wrote there.
    Other(&'a str),
}

impl PerfMap {
    /// Parse perf-map text; lines that do not parse are skipped (the process
    /// may have been writing the last one).
    pub fn parse(text: &str) -> PerfMap {
        let mut entries: Vec<Entry> = text
            .lines()
            .filter_map(|l| {
                let mut f = l.splitn(3, ' ');
                let start = u64::from_str_radix(f.next()?, 16).ok()?;
                let size = u64::from_str_radix(f.next()?, 16).ok()?;
                let name = f.next()?.trim();
                (size > 0 && !name.is_empty()).then(|| Entry {
                    start,
                    end: start.saturating_add(size),
                    name: name.to_string(),
                })
            })
            .collect();
        // A later line for the same address wins: stable sort keeps file
        // order, and lookup takes the last match.
        entries.sort_by_key(|e| e.start);
        PerfMap { entries }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The entry holding `addr`.
    pub fn lookup(&self, addr: u64) -> Option<&Entry> {
        let i = self.entries.partition_point(|e| e.start <= addr);
        let e = self.entries.get(i.checked_sub(1)?)?;
        (addr < e.end).then_some(e)
    }
}

impl Entry {
    pub fn symbol(&self) -> Symbol<'_> {
        if let Some(rest) = self.name.strip_prefix("py::") {
            // Qualified names never contain ':'; file names may.
            if let Some((qualname, file)) = rest.split_once(':') {
                return Symbol::Python { qualname, file };
            }
        }
        Symbol::Other(&self.name)
    }
}

/// Where `perf-<pid>.map` may be, in order: `dir` (--perf-map-dir), beside
/// the snapshot, then /tmp where the process wrote it.
pub fn places(pid: i32, snapshot: &Path, dir: Option<&Path>) -> Vec<PathBuf> {
    let name = format!("perf-{pid}.map");
    let beside = snapshot.parent().map(|p| p.join(&name));
    [
        dir.map(|d| d.join(&name)),
        beside,
        Some(Path::new("/tmp").join(&name)),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// The [`places`] that exist; [`read`] decides whether one may be used, and a
/// refused one falls through to the next. Beneath a [`Root`] nothing filters
/// them: each place is tried with [`read_in`], and one that holds nothing
/// falls through too.
pub fn candidates(pid: i32, snapshot: &Path, dir: Option<&Path>) -> Vec<PathBuf> {
    places(pid, snapshot, dir)
        .into_iter()
        .filter(|p| p.symlink_metadata().is_ok())
        .collect()
}

/// Read a perf map found by [`find`]. Anyone can write /tmp, so the file is
/// opened without following a symlink and must be a regular file, checked on
/// the open handle, of at most [`MAX_BYTES`]. One in a world-writable
/// directory must also be owned by this user or root, as perf requires, or
/// another user could name our frames.
pub fn read(path: &Path) -> std::io::Result<PerfMap> {
    read_in(None, path, None)
}

/// As [`read`], with `path` beneath `root` when there is one. The reader is
/// then outside the container and is not the user its processes run as, so
/// the user who may own a map in a world-writable directory is the one who
/// owns the process's dump, `dump_owner`: the same process wrote both. No
/// other user in the container can then name that process's frames.
pub fn read_in(
    root: Option<&Root>,
    path: &Path,
    dump_owner: Option<u32>,
) -> std::io::Result<PerfMap> {
    use std::io::{Error, ErrorKind};
    let (file, world_writable_dir, trusted_owner) = match root {
        Some(root) => {
            let (file, world_writable_dir) = open_beneath(root, path)?;
            (file, world_writable_dir, dump_owner)
        }
        None => {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open(path)?;
            let world_writable_dir = path
                .parent()
                .and_then(|d| {
                    std::fs::metadata(if d.as_os_str().is_empty() {
                        Path::new(".")
                    } else {
                        d
                    })
                    .ok()
                })
                .is_some_and(|d| d.mode() & 0o002 != 0);
            // SAFETY: geteuid cannot fail.
            let euid = unsafe { libc::geteuid() };
            (file, world_writable_dir, Some(euid))
        }
    };
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(Error::new(ErrorKind::InvalidInput, "not a regular file"));
    }
    if meta.len() > MAX_BYTES {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("larger than {MAX_BYTES} bytes"),
        ));
    }
    if !owner_may_name_frames(world_writable_dir, meta.uid(), trusted_owner) {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "owned by uid {} in a world-writable directory; copy it beside the snapshot if you trust it",
                meta.uid()
            ),
        ));
    }
    let mut text = String::new();
    (&file).take(MAX_BYTES).read_to_string(&mut text)?;
    Ok(PerfMap::parse(&text))
}

/// Whether a map owned by `owner` may be used. Anywhere but in a
/// world-writable directory it may; there, only when root or the `trusted`
/// user owns it.
fn owner_may_name_frames(world_writable_dir: bool, owner: u32, trusted: Option<u32>) -> bool {
    !world_writable_dir || owner == 0 || trusted == Some(owner)
}

/// Open the map at `path` beneath `root`, and say whether its directory is
/// world-writable. The directory is reached beneath the root, and the map is
/// then opened inside it by its name alone, without following a symlink
/// there: the directory judged is the one the map is in.
fn open_beneath(root: &Root, path: &Path) -> std::io::Result<(std::fs::File, bool)> {
    let name = path
        .file_name()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a file path"))?;
    let parent = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let dir = root.open_at(parent, libc::O_PATH | libc::O_DIRECTORY)?;
    let remote = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "on a FUSE or network filesystem",
        )
    };
    if crate::root::on_remote_fs(&dir) {
        return Err(remote());
    }
    let world_writable_dir = dir.metadata()?.mode() & 0o002 != 0;
    let file = Root::from_dir(dir)?.open_at(
        Path::new(name),
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
    )?;
    if crate::root::on_remote_fs(&file) {
        return Err(remote());
    }
    Ok((file, world_writable_dir))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAP: &str = "\
7f75cb8c74e0 8 py::<module>:/srv/app/alloc.py
7f75cb8c7500 8 py::outer:/srv/app/alloc.py
7f75cb8c7520 8 py::Leaker.leak:C:/odd:path.py
7f75cb8c7600 20 some_jit_stub
garbage line
";

    #[test]
    fn lookup_names_python_functions() {
        let m = PerfMap::parse(MAP);
        let e = m.lookup(0x7f75cb8c7506).unwrap();
        assert_eq!(
            e.symbol(),
            Symbol::Python {
                qualname: "outer",
                file: "/srv/app/alloc.py"
            }
        );
        assert_eq!(
            m.lookup(0x7f75cb8c7520).unwrap().symbol(),
            Symbol::Python {
                qualname: "Leaker.leak",
                file: "C:/odd:path.py"
            }
        );
        assert_eq!(
            m.lookup(0x7f75cb8c7610).unwrap().symbol(),
            Symbol::Other("some_jit_stub")
        );
    }

    #[test]
    fn end_is_exclusive_and_gaps_miss() {
        let m = PerfMap::parse(MAP);
        assert!(m.lookup(0x7f75cb8c7508).is_none());
        assert!(m.lookup(0x10).is_none());
    }

    #[test]
    fn read_refuses_symlinks_and_non_files() {
        let d = tempfile::tempdir().unwrap();
        let real = d.path().join("real.map");
        std::fs::write(&real, MAP).unwrap();
        assert_eq!(read(&real).unwrap(), PerfMap::parse(MAP));
        let link = d.path().join("perf-1.map");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(read(&link).is_err(), "a symlink must not be followed");
        assert!(read(d.path()).is_err(), "a directory is not a map");
        assert!(
            read(Path::new("/dev/null")).is_err(),
            "a device is not a map"
        );
    }

    #[test]
    fn in_a_world_writable_directory_only_root_or_the_trusted_user_may_own_a_map() {
        // Elsewhere anyone may.
        assert!(owner_may_name_frames(false, 1000, Some(2000)));
        assert!(owner_may_name_frames(false, 1000, None));
        // The trusted user's own map, or root's.
        assert!(owner_may_name_frames(true, 1000, Some(1000)));
        assert!(owner_may_name_frames(true, 0, Some(1000)));
        assert!(owner_may_name_frames(true, 0, None));
        // Another user's; and anyone's but root's when no user is trusted.
        assert!(!owner_may_name_frames(true, 1001, Some(1000)));
        assert!(!owner_may_name_frames(true, 1000, None));
    }

    #[test]
    fn candidates_are_the_named_dir_then_beside_the_snapshot_then_tmp() {
        let d = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let snap = d.path().join("jeprof.4242.0.f.heap");
        let tmp = Path::new("/tmp/perf-4242.map");
        let tail: Vec<PathBuf> = tmp
            .symlink_metadata()
            .is_ok()
            .then(|| tmp.to_path_buf())
            .into_iter()
            .collect();
        assert_eq!(candidates(4242, &snap, None), tail);
        std::fs::write(d.path().join("perf-4242.map"), MAP).unwrap();
        assert_eq!(
            candidates(4242, &snap, None).first(),
            Some(&d.path().join("perf-4242.map"))
        );
        std::fs::write(other.path().join("perf-4242.map"), MAP).unwrap();
        assert_eq!(
            candidates(4242, &snap, Some(other.path()))[..2],
            [
                other.path().join("perf-4242.map"),
                d.path().join("perf-4242.map")
            ]
        );
    }
}
