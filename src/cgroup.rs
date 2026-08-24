//! Resolution of numeric cgroup ids to human-readable cgroup paths.
//!
//! The BPF side records, for every task, the id of its cgroup in the v2 unified
//! hierarchy (`dfl_cgrp->kn->id`). For cgroup v2 that id is the inode number of
//! the cgroup's directory under the cgroup2 mount, which is the same convention the
//! cgroup filter uses (it keys the BPF filter map by `std::fs::metadata(...).ino()`).
//!
//! This module walks the live cgroup2 hierarchy and builds a map from that id to the
//! cgroup's path (relative to the cgroup root, matching the `/proc/<pid>/cgroup`
//! representation, e.g. `/system.slice/foo.service`; the root cgroup is `/`).
//!
//! Resolution is best-effort and racy: it reflects the cgroup hierarchy as it
//! exists when the trace is written, not when each task was sampled. A cgroup that
//! has been removed by then is simply absent from the map, so its `cgroup_path` is
//! left unresolved. Note also that kernfs inode numbers can be reused: if a
//! captured id was freed and reassigned to a *different* cgroup before the walk, it
//! resolves to that different cgroup's path. The numeric id is always recorded
//! faithfully; treat the resolved path as a best-effort hint.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Locate the cgroup v2 unified hierarchy mount point by parsing
/// `/proc/self/mountinfo`. Falls back to the conventional `/sys/fs/cgroup` only if
/// it is actually a cgroup v2 hierarchy. Returns `None` when there is no cgroup v2
/// hierarchy (e.g. a pure cgroup v1 host).
pub fn cgroup2_root() -> Option<PathBuf> {
    if let Ok(contents) = fs::read_to_string("/proc/self/mountinfo") {
        for line in contents.lines() {
            // mountinfo lines have an optional set of fields, then a literal " - "
            // separator, then the filesystem type / source. Example:
            //   31 23 0:26 / /sys/fs/cgroup rw,nosuid ... - cgroup2 cgroup2 rw,...
            // The mount point is field index 4 (0-based) of the part before " - ".
            if let Some((mount_fields, fs_fields)) = line.split_once(" - ") {
                let fstype = fs_fields.split_whitespace().next().unwrap_or("");
                if fstype == "cgroup2" {
                    if let Some(mount_point) = mount_fields.split_whitespace().nth(4) {
                        return Some(PathBuf::from(unescape_mountinfo(mount_point)));
                    }
                }
            }
        }
    }
    // Fallback only if mountinfo was unavailable/unparseable. Crucially, validate
    // that the conventional path is really cgroup v2: on a pure cgroup v1 host
    // `/sys/fs/cgroup` is a tmpfs of v1 controller subdirs whose inodes are
    // unrelated to the BPF `dfl_cgrp->kn->id`, so walking it would yield a bogus
    // id->path map (paths all NULL at best, silently wrong on inode collision).
    let fallback = PathBuf::from("/sys/fs/cgroup");
    is_cgroup2_root(&fallback).then_some(fallback)
}

/// A cgroup v2 hierarchy root always contains a `cgroup.controllers` file; cgroup
/// v1 tmpfs roots and v1 controller subdirectories do not.
fn is_cgroup2_root(path: &Path) -> bool {
    path.join("cgroup.controllers").exists()
}

/// Decode the octal escapes (`\NNN`) that mountinfo uses for space, tab, newline
/// and backslash within path fields, passing everything else through verbatim.
fn unescape_mountinfo(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        // An escape is a backslash followed by exactly three octal digits encoding
        // one byte (e.g. space -> \040). Operate on raw bytes rather than `&s[..]`
        // slices so a backslash adjacent to a multi-byte UTF-8 character can never
        // slice on a non-char boundary (which would panic).
        if bytes[i] == b'\\' && i + 4 <= bytes.len() {
            let d = &bytes[i + 1..i + 4];
            if d.iter().all(|b| b.is_ascii_digit() && *b <= b'7') {
                let code = (u32::from(d[0] - b'0') << 6)
                    | (u32::from(d[1] - b'0') << 3)
                    | u32::from(d[2] - b'0');
                // Only valid single-byte escapes (\000..\377) are decoded; anything
                // larger is left literal.
                if code <= 0xFF {
                    out.push(code as u8);
                    i += 4;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    // Paths are conventionally UTF-8; tolerate the rare non-UTF-8 byte rather than
    // panicking or mangling it into Latin-1.
    String::from_utf8_lossy(&out).into_owned()
}

/// Build a map from cgroup id (the cgroup directory's inode, matching the BPF
/// `dfl_cgrp->kn->id`) to the cgroup's path relative to the cgroup root.
///
/// The root cgroup maps to `/`; nested cgroups map to e.g.
/// `/system.slice/foo.service`. Returns an empty map if no cgroup2 hierarchy is
/// found.
pub fn build_cgroup_id_map() -> HashMap<u64, String> {
    let mut map = HashMap::new();
    if let Some(root) = cgroup2_root() {
        // The root is always a directory, so this never errors in practice; ignore
        // the result to keep the best-effort contract.
        let _ = for_each_cgroup_dir(&root, &mut |path, meta| {
            map.insert(meta.ino(), relative_cgroup_path(&root, path));
        });
    }
    map
}

/// The cgroup id (directory inode, matching the kernel's `cgroup->kn->id`) of
/// the cgroup at `path`.
///
/// The `--cgroup` filter keys each target by it: the kernel decides membership
/// (a task's cgroup is the target or somewhere below it, cgroups created after
/// the trace started included), so the target's own id is all userspace ever
/// resolves — its subtree is never enumerated.
///
/// Failure to stat `path`, or `path` not being a directory, is reported to the
/// caller so an invalid `--cgroup` argument is a clear error rather than a
/// silently-empty filter.
pub fn cgroup_id(path: &Path) -> io::Result<u64> {
    let meta = fs::metadata(path)?;
    if !meta.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a cgroup directory", path.display()),
        ));
    }
    Ok(meta.ino())
}

/// Collect the pids listed in `cgroup.procs` of `start` and of every cgroup
/// nested beneath it, inserting them into `pids`.
///
/// This descends because a `--cgroup` target is often an interior node whose
/// own `cgroup.procs` is empty (the tasks live in child container/slice
/// cgroups). Best-effort: an unreadable or
/// non-existent `start` simply contributes nothing.
pub fn collect_cgroup_procs(start: &Path, pids: &mut HashSet<u32>) {
    let _ = for_each_cgroup_dir(start, &mut |path, _| {
        if let Ok(contents) = fs::read_to_string(path.join("cgroup.procs")) {
            for line in contents.lines() {
                if let Ok(pid) = line.trim().parse::<u32>() {
                    pids.insert(pid);
                }
            }
        }
    });
}

/// Recursively visit `start` and every cgroup directory nested beneath it,
/// invoking `visit(path, metadata)` once per cgroup, `start` first.
///
/// Symlinks are not followed (real cgroupfs contains none) and each directory
/// inode is visited at most once, so even a pathological bind-mount loop cannot
/// drive infinite recursion. Descendants that cannot be stat'd or read are
/// skipped (best-effort, since cgroups race in and out of existence); a `start`
/// that cannot be stat'd, or that is not a directory, is reported to the caller.
fn for_each_cgroup_dir(
    start: &Path,
    visit: &mut impl FnMut(&Path, &fs::Metadata),
) -> io::Result<()> {
    let meta = fs::metadata(start)?;
    if !meta.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a cgroup directory", start.display()),
        ));
    }
    let mut seen = HashSet::new();
    seen.insert(meta.ino());
    visit(start, &meta);
    visit_child_cgroup_dirs(start, &mut seen, visit);
    Ok(())
}

fn visit_child_cgroup_dirs(
    dir: &Path,
    seen: &mut HashSet<u64>,
    visit: &mut impl FnMut(&Path, &fs::Metadata),
) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        // file_type() does not follow symlinks; cgroupfs has none anyway, so this
        // descends only into real child cgroup directories.
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        // Gate both the visit and the recursion on first sighting of this inode so a
        // bind-mount loop can never recurse forever (and ids never duplicate).
        if seen.insert(meta.ino()) {
            let path = entry.path();
            visit(&path, &meta);
            visit_child_cgroup_dirs(&path, seen, visit);
        }
    }
}

/// Render `dir` (a path under `root`) as a cgroup path relative to the cgroup root,
/// with a leading slash. The root itself becomes `/`.
fn relative_cgroup_path(root: &Path, dir: &Path) -> String {
    match dir.strip_prefix(root) {
        Ok(rel) if rel.as_os_str().is_empty() => "/".to_string(),
        Ok(rel) => format!("/{}", rel.to_string_lossy()),
        Err(_) => dir.to_string_lossy().into_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unescape_mountinfo() {
        assert_eq!(unescape_mountinfo("/sys/fs/cgroup"), "/sys/fs/cgroup");
        assert_eq!(
            unescape_mountinfo("/path\\040with\\040space"),
            "/path with space"
        );
        // tab (\011) and newline (\012) escapes.
        assert_eq!(unescape_mountinfo("a\\011b\\012c"), "a\tb\nc");
        // A trailing lone backslash must not panic and is preserved verbatim.
        assert_eq!(unescape_mountinfo("/trailing\\"), "/trailing\\");
        // A backslash NOT followed by three octal digits is literal (note `é` is a
        // multi-byte UTF-8 char; byte-slicing here previously panicked).
        assert_eq!(unescape_mountinfo("/a\\xxé"), "/a\\xxé");
        // A genuine escape adjacent to a multi-byte char is decoded, char preserved.
        assert_eq!(unescape_mountinfo("/café\\040x"), "/café x");
        // Non-octal digits (8,9) are not an escape.
        assert_eq!(unescape_mountinfo("\\089"), "\\089");
    }

    #[test]
    fn test_relative_cgroup_path() {
        let root = Path::new("/sys/fs/cgroup");
        assert_eq!(relative_cgroup_path(root, root), "/");
        assert_eq!(
            relative_cgroup_path(root, Path::new("/sys/fs/cgroup/system.slice")),
            "/system.slice"
        );
        assert_eq!(
            relative_cgroup_path(root, Path::new("/sys/fs/cgroup/a/b/c")),
            "/a/b/c"
        );
    }

    #[test]
    fn test_cgroup_id_is_the_target_inode_only() {
        // The ancestry-matching filter loads just the target's own id: an
        // interior pod cgroup with children must yield exactly its inode, never
        // the children's (those are matched in-kernel through their ancestors).
        let tmp = tempfile::TempDir::new().unwrap();
        let pod = tmp.path().join("pod");
        let child = pod.join("container-a");
        fs::create_dir_all(&child).unwrap();
        fs::write(pod.join("cgroup.procs"), b"").unwrap();

        let id = cgroup_id(&pod).unwrap();
        assert_eq!(id, fs::metadata(&pod).unwrap().ino());
        assert_ne!(id, fs::metadata(&child).unwrap().ino());
    }

    #[test]
    fn test_cgroup_id_missing_path_errors() {
        let tmp = tempfile::TempDir::new().unwrap();
        assert!(cgroup_id(&tmp.path().join("does-not-exist")).is_err());
    }

    #[test]
    fn test_cgroup_id_non_dir_errors() {
        // A typo'd --cgroup pointing at a file must be a clear error, not a
        // silently-empty filter.
        let tmp = tempfile::TempDir::new().unwrap();
        let file = tmp.path().join("a-file");
        fs::write(&file, b"").unwrap();
        let err = cgroup_id(&file).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_collect_cgroup_procs_descends() {
        // Mimic an interior pod cgroup whose own cgroup.procs is empty while the
        // tasks live in descendant container cgroups at varying depths.
        let tmp = tempfile::TempDir::new().unwrap();
        let pod = tmp.path().join("pod");
        let a = pod.join("container-a");
        let a_leaf = a.join("leaf");
        let b = pod.join("container-b");
        for d in [&pod, &a, &a_leaf, &b] {
            fs::create_dir_all(d).unwrap();
        }
        // Interior node has an empty procs file (the original bug: only this was read).
        fs::write(pod.join("cgroup.procs"), b"").unwrap();
        fs::write(a.join("cgroup.procs"), b"10\n11\n").unwrap();
        fs::write(a_leaf.join("cgroup.procs"), b"20\n").unwrap();
        // Blank lines and stray whitespace must be tolerated.
        fs::write(b.join("cgroup.procs"), b"  30  \n\n31\n").unwrap();

        let mut pids = HashSet::new();
        collect_cgroup_procs(&pod, &mut pids);

        assert_eq!(pids, HashSet::from([10, 11, 20, 30, 31]));
    }

    #[test]
    fn test_collect_cgroup_procs_missing_path_is_noop() {
        let tmp = tempfile::TempDir::new().unwrap();
        let missing = tmp.path().join("does-not-exist");
        let mut pids = HashSet::new();
        collect_cgroup_procs(&missing, &mut pids);
        assert!(pids.is_empty());
    }
}
