//! Offline symbolization of snapshot stacks.
//!
//! A dump outlives its process, so addresses go through the memory map the
//! dump carries: an address in a file mapping becomes (file, file offset),
//! resolved against that file on this machine. That needs the same binaries
//! at the same paths (the host, or the image the process ran in), or, read
//! from outside the process's container, that container's root as a [`Root`].

use std::collections::{BTreeMap, HashMap, HashSet};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use blazesym::symbolize::source::{Elf, Source};
use blazesym::symbolize::{Input, Symbolizer};

use crate::perfmap::{Entry, Symbol};
use crate::root::Root;
use crate::Snapshot;

/// Frame names for every (snapshot, stack) in a set of snapshots.
pub struct Symbolized {
    /// `frames[snapshot][sample]`: frame names root (outermost) first, the
    /// order `stack.frame_ids` uses.
    pub frames: Vec<Vec<Vec<String>>>,
    /// The full source path of each frame name that has one (Python
    /// frames named from a perf map), for `frame_file`.
    pub files: HashMap<String, String>,
    pub stats: Stats,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Stats {
    /// Distinct (file, offset) lookups.
    pub lookups: usize,
    pub resolved: usize,
    /// Files the dumps name that are not on this machine.
    pub missing_files: Vec<PathBuf>,
    /// Paths the dumps name that are not regular files (devices, FIFOs,
    /// /proc, /dev, /sys), so they were not opened.
    pub refused_files: Vec<PathBuf>,
    /// Files beneath a root that are on a FUSE or network filesystem, so
    /// they were not opened (see [`crate::root::on_remote_fs`]).
    pub remote_files: Vec<PathBuf>,
    /// Files on this machine that are not the one the process mapped (the
    /// device or inode differs): a copy or another build, so their names
    /// may be wrong.
    pub changed_files: Vec<PathBuf>,
    /// Distinct return addresses named as Python functions from a perf map
    /// (Python's perf trampolines).
    pub perf_map_frames: usize,
    /// Snapshots with frames in generated code (anonymous executable
    /// memory) that no perf map names: Python ran without trampolines, or
    /// its perf-<pid>.map was not found.
    pub unnamed_generated: Vec<PathBuf>,
}

/// Where one address points.
enum Target<'a> {
    File {
        path: &'a str,
        lookup: u64,
    },
    /// Generated code a perf map names.
    Perf(&'a Entry),
    /// Anonymous executable memory no perf map names.
    Generated,
    /// Anonymous memory that is not executable: a PC here is recycled code
    /// or unwind garbage.
    AnonData,
    Label(&'a str),
    Unmapped,
}

pub fn symbolize(snapshots: &[Snapshot]) -> Symbolized {
    symbolize_in(snapshots, None)
}

/// As [`symbolize`], with the files the dumps name opened beneath `root` when
/// there is one, so their paths mean what they meant to the process.
pub fn symbolize_in(snapshots: &[Snapshot], root: Option<&Root>) -> Symbolized {
    // Every (file, offset) to look up, by file, so each file is opened once.
    let mut wanted: BTreeMap<&str, HashSet<u64>> = BTreeMap::new();
    let mut identities: HashMap<&str, ((u32, u32), u64)> = HashMap::new();
    for s in snapshots {
        for sample in &s.samples {
            for (i, &addr) in sample.addrs.iter().enumerate() {
                if let Target::File { path, lookup } = target(s, addr, i == 0) {
                    wanted.entry(path).or_default().insert(lookup);
                    let m = s.maps.lookup(addr).expect("target found it");
                    identities.entry(path).or_insert((m.dev, m.inode));
                }
            }
        }
    }

    let symbolizer = Symbolizer::new();
    let mut stats = Stats::default();
    // (file, offset) -> its symbol, or None when the file has none there.
    let mut names: HashMap<(&str, u64), Option<blazesym::symbolize::Sym<'_>>> = HashMap::new();
    // Every opened file stays open until symbolization ends: each is
    // symbolized as /proc/self/fd/N, and the symbolizer caches by path, so
    // a closed file's fd number reused by the next would get its symbols.
    let mut open_files: Vec<std::fs::File> = Vec::new();
    for (&path, offsets) in &wanted {
        let offsets: Vec<u64> = offsets.iter().copied().collect();
        stats.lookups += offsets.len();
        // The path comes from the dump, which anyone could have written.
        // An O_PATH handle names the file without opening it, so no device
        // or FIFO is opened before it is checked, and no pseudo-file read
        // can hang or never end; a file that passes is reopened through
        // that handle, so the file read is the one checked.
        let opened = match root {
            Some(root) => root.open_at(Path::new(path), libc::O_PATH),
            None => std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
                .open(path),
        };
        let handle = match opened {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                stats.missing_files.push(PathBuf::from(path));
                continue;
            }
            Err(_) => {
                stats.refused_files.push(PathBuf::from(path));
                continue;
            }
        };
        let Some(meta) = handle
            .metadata()
            .ok()
            .filter(|m| m.is_file() && !on_pseudo_fs(&handle))
        else {
            stats.refused_files.push(PathBuf::from(path));
            continue;
        };
        if root.is_some() && crate::root::on_remote_fs(&handle) {
            stats.remote_files.push(PathBuf::from(path));
            continue;
        }
        let Ok(file) = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(format!("/proc/self/fd/{}", handle.as_raw_fd()))
        else {
            stats.refused_files.push(PathBuf::from(path));
            continue;
        };
        if identities.get(path).is_some_and(|&((maj, min), ino)| {
            ino != 0
                && (ino != meta.ino()
                    || (maj, min) != (libc::major(meta.dev()), libc::minor(meta.dev())))
        }) {
            stats.changed_files.push(PathBuf::from(path));
        }
        let fd = file.as_raw_fd();
        open_files.push(file);
        let src = Source::Elf(elf_source(fd, root.is_some()));
        let Ok(results) = symbolizer.symbolize(&src, Input::FileOffset(&offsets)) else {
            continue;
        };
        for (off, r) in offsets.iter().zip(results) {
            let sym = r.into_sym();
            stats.resolved += usize::from(sym.is_some());
            names.insert((path, *off), sym);
        }
    }
    drop(open_files);

    let mut files: HashMap<String, String> = HashMap::new();
    for (si, s) in snapshots.iter().enumerate() {
        let generated = s.samples.iter().any(|sample| {
            sample
                .addrs
                .iter()
                .enumerate()
                .any(|(i, &a)| matches!(target(s, a, i == 0), Target::Generated))
        });
        if generated {
            stats
                .unnamed_generated
                .push(snapshots[si].source_path.clone());
        }
    }
    let mut rendered: HashMap<(u64, bool, usize), String> = HashMap::new();
    let frames = snapshots
        .iter()
        .enumerate()
        .map(|(si, s)| {
            s.samples
                .iter()
                .map(|sample| {
                    sample
                        .addrs
                        .iter()
                        .enumerate()
                        .rev()
                        .map(|(i, &addr)| {
                            rendered
                                .entry((addr, i == 0, si))
                                .or_insert_with(|| {
                                    let (name, file) = render(s, addr, i == 0, &names);
                                    if let Some(file) = file {
                                        stats.perf_map_frames += 1;
                                        files.entry(name.clone()).or_insert(file);
                                    }
                                    name
                                })
                                .clone()
                        })
                        .collect()
                })
                .collect()
        })
        .collect();
    Symbolized {
        frames,
        files,
        stats,
    }
}

/// Where `addr` points in `s`'s maps. Every frame but the leaf holds a
/// return address, the instruction after the call; one byte back lands in
/// the call itself, so an inlined call or a `noreturn` tail resolves to the
/// right line.
fn target(s: &Snapshot, addr: u64, leaf: bool) -> Target<'_> {
    let Some(m) = s.maps.lookup(addr) else {
        return Target::Unmapped;
    };
    if !m.is_file() {
        if let Some(label) = m.label() {
            return Target::Label(label);
        }
        if !m.exec {
            return Target::AnonData;
        }
        // Only where the dump's own map says there is generated code does
        // a perf map name it: a stale map cannot name data or a hole.
        let pc = if leaf || addr == m.start {
            addr
        } else {
            addr - 1
        };
        return s
            .perf_map
            .as_deref()
            .and_then(|p| p.lookup(pc))
            .map_or(Target::Generated, Target::Perf);
    }
    let pc = if leaf || addr == m.start {
        addr
    } else {
        addr - 1
    };
    Target::File {
        path: &m.path,
        lookup: pc - m.start + m.offset,
    }
}

/// A frame's name, in the form systing's recorders give it:
/// `function (module [file:line]) <0xaddr>`, `unknown (module) <0xaddr>` when
/// the module is known but the symbol is not, bare hex when neither is.
/// A Python function named by a perf map is `function (python) [file.py]`,
/// as pystacks names Python frames (without a line: a trampoline is per
/// function), and comes with its full path.
fn render(
    s: &Snapshot,
    addr: u64,
    leaf: bool,
    names: &HashMap<(&str, u64), Option<blazesym::symbolize::Sym<'_>>>,
) -> (String, Option<String>) {
    let name = match target(s, addr, leaf) {
        Target::Perf(e) => {
            return match e.symbol() {
                Symbol::Python { qualname, file } => {
                    let base = Path::new(file)
                        .file_name()
                        .and_then(|f| f.to_str())
                        .unwrap_or(file);
                    // pystacks' module prefix for library code, so a frame
                    // here and the same function in a capture share a name.
                    let module = systing::pystacks::symbols::get_module_name_from_filename(file);
                    let func = if module.is_empty() {
                        qualname.to_string()
                    } else {
                        format!("{module}:{qualname}")
                    };
                    (format!("{func} (python) [{base}]"), Some(file.to_string()))
                }
                Symbol::Other(name) => (format!("{name} ([jit]) <{addr:#x}>"), None),
            };
        }
        // The recorders' labels for these classes (sandbox_maps).
        Target::Generated => format!("unknown ([anon:exec]) <{addr:#x}>"),
        Target::AnonData => format!("unknown ([anon]) <{addr:#x}>"),
        Target::File { path, lookup } => {
            let module = Path::new(path)
                .file_name()
                .and_then(|f| f.to_str())
                .unwrap_or("unknown");
            match names.get(&(path, lookup)) {
                Some(Some(sym)) => systing::stack_recorder::format_symbolized_frame_forced_module(
                    sym, addr, module, false,
                ),
                _ => format!("unknown ({module}) <{addr:#x}>"),
            }
        }
        Target::Label(label) => format!("unknown ({label}) <{addr:#x}>"),
        Target::Unmapped => format!("unknown ([unmapped]) <{addr:#x}>"),
    };
    (name, None)
}

/// Whether `file` is on a kernel pseudo-filesystem, whose "regular" files
/// are generated, can be endless, and can act when read.
fn on_pseudo_fs(file: &std::fs::File) -> bool {
    // Magic numbers from linux/magic.h.
    const PSEUDO: [u32; 12] = [
        0x9fa0,      // proc
        0x6265_6572, // sysfs
        0x6462_6720, // debugfs
        0x7472_6163, // tracefs
        0x0027_e0eb, // cgroup
        0x6367_7270, // cgroup2
        0x7363_6673, // securityfs
        0x6265_6570, // configfs
        0xcafe_4a11, // bpf
        0xde5e_81e4, // efivarfs
        0x6165_676c, // pstore
        0xf97c_ff8c, // selinuxfs
    ];
    let mut sfs: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: a valid fd and a writable statfs.
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut sfs) } != 0 {
        return true;
    }
    // f_type is a long on some targets and an int on others; the magic
    // numbers are 32 bits either way.
    PSEUDO.contains(&(sfs.f_type as u32))
}

/// The symbolization source for a binary opened as descriptor `fd`.
///
/// Beneath a root only the file's own symbol table is read. With debug
/// information on, the symbolizer follows the binary's debug link and looks
/// for its `.dwp`, by paths of its own making: a build-id directory, its
/// debug directories, and the directory the binary's path names to the
/// reader. Those are the reader's files, not the container's; the name looked
/// up is the binary's to choose, an absolute one is taken as it stands, and
/// what is found is opened with a plain open. So beneath a root names come
/// from the symbol table (and the perf map), without inlined frames.
fn elf_source(fd: std::os::fd::RawFd, beneath_root: bool) -> Elf {
    let mut elf = Elf::new(format!("/proc/self/fd/{fd}"));
    elf.debug_syms = !beneath_root;
    elf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn beneath_a_root_debug_information_is_not_consulted() {
        assert!(elf_source(3, false).debug_syms);
        assert!(!elf_source(3, true).debug_syms);
    }
}
