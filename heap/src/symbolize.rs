//! Offline symbolization of snapshot stacks.
//!
//! A dump outlives its process, so addresses go through the memory map the
//! dump carries: an address in a file mapping becomes (file, file offset),
//! resolved against that file on this machine. That needs the same binaries
//! at the same paths (the host, or the image the process ran in).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use blazesym::symbolize::source::{Elf, Source};
use blazesym::symbolize::{Input, Symbolizer};

use crate::perfmap::{Entry, Symbol};
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
    /// Files on this machine whose inode differs from the dump's: possibly a
    /// different build, so their names may be wrong.
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
    Label(&'a str),
    Unmapped,
}

pub fn symbolize(snapshots: &[Snapshot]) -> Symbolized {
    // Every (file, offset) to look up, by file, so each file is opened once.
    let mut wanted: BTreeMap<&str, HashSet<u64>> = BTreeMap::new();
    let mut inodes: HashMap<&str, u64> = HashMap::new();
    for s in snapshots {
        for sample in &s.samples {
            for (i, &addr) in sample.addrs.iter().enumerate() {
                if let Target::File { path, lookup } = target(s, addr, i == 0) {
                    wanted.entry(path).or_default().insert(lookup);
                    let m = s.maps.lookup(addr).expect("target found it");
                    inodes.entry(path).or_insert(m.inode);
                }
            }
        }
    }

    let symbolizer = Symbolizer::new();
    let mut stats = Stats::default();
    // (file, offset) -> its symbol, or None when the file has none there.
    let mut names: HashMap<(&str, u64), Option<blazesym::symbolize::Sym<'_>>> = HashMap::new();
    for (&path, offsets) in &wanted {
        let offsets: Vec<u64> = offsets.iter().copied().collect();
        stats.lookups += offsets.len();
        // The path comes from the dump, which anyone could have written:
        // open only regular files, never a device, FIFO or pseudo-file that
        // could hang the read or never end.
        if ["/proc/", "/dev/", "/sys/"]
            .iter()
            .any(|p| path.starts_with(p))
        {
            stats.refused_files.push(PathBuf::from(path));
            continue;
        }
        let meta = match std::fs::metadata(path) {
            Ok(m) if m.is_file() => m,
            Ok(_) => {
                stats.refused_files.push(PathBuf::from(path));
                continue;
            }
            Err(_) => {
                stats.missing_files.push(PathBuf::from(path));
                continue;
            }
        };
        if inodes
            .get(path)
            .is_some_and(|&ino| ino != 0 && ino != meta.ino())
        {
            stats.changed_files.push(PathBuf::from(path));
        }
        let src = Source::Elf(Elf::new(path));
        let Ok(results) = symbolizer.symbolize(&src, Input::FileOffset(&offsets)) else {
            continue;
        };
        for (off, r) in offsets.iter().zip(results) {
            let sym = r.into_sym();
            stats.resolved += usize::from(sym.is_some());
            names.insert((path, *off), sym);
        }
    }

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
    let perf = |pc: u64| s.perf_map.as_deref().and_then(|p| p.lookup(pc));
    let Some(m) = s.maps.lookup(addr) else {
        let pc = if leaf { addr } else { addr.saturating_sub(1) };
        return perf(pc).map_or(Target::Unmapped, Target::Perf);
    };
    if !m.is_file() {
        let pc = if leaf || addr == m.start {
            addr
        } else {
            addr - 1
        };
        if let Some(e) = perf(pc) {
            return Target::Perf(e);
        }
        if m.exec && m.label().is_none() {
            return Target::Generated;
        }
        return m.label().map_or(Target::Unmapped, Target::Label);
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
                    (
                        format!("{qualname} (python) [{base}]"),
                        Some(file.to_string()),
                    )
                }
                Symbol::Other(name) => (format!("{name} ([jit]) <{addr:#x}>"), None),
            };
        }
        Target::Generated => format!("unknown ([anon]) <{addr:#x}>"),
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
        Target::Unmapped => format!("0x{addr:x}"),
    };
    (name, None)
}
