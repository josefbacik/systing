//! Post-mortem symbolization support for short-lived processes.
//!
//! blazesym symbolizes live processes through `/proc/<pid>/maps` and
//! `/proc/<pid>/map_files`; once a process exits both are gone and its user
//! frames render as `unknown ([exited]) <addr>`. On fork/exec-heavy hosts
//! (build and CI machines) that class can dominate the profile.
//!
//! This module closes most of it. The first time a stack sample arrives for
//! a tgid — the process is on-CPU, so it is alive right now — its executable
//! file-backed mappings are captured and each backing file is pinned with a
//! read-only descriptor, deduplicated by (device, inode). At end-of-trace
//! symbolization, a dead tgid with a snapshot resolves user addresses to
//! (pinned file, file offset) and symbolizes through `/proc/self/fd/<n>`;
//! addresses that miss the snapshot keep the `[exited]` rendering.
//!
//! Bounded on every axis: one capture attempt per tgid, a per-second capture
//! budget for fork storms, a per-process segment cap, and a global pinned-file
//! cap with oldest-first eviction. Every limit degrades to the existing
//! `[exited]` rendering, never to an error.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::time::Instant;

/// Executable mappings beyond this count are ignored; processes mapping more
/// executable file segments than this are not the short-lived class this
/// exists for.
const MAX_SEGMENTS_PER_PROC: usize = 128;

/// Default cap on distinct pinned files. Short-lived-process churn reuses the
/// same binaries (shells, compilers, interpreters), so the working set is far
/// smaller than the process count. Kept safely below common RLIMIT_NOFILE
/// soft limits since each pin holds a descriptor until the next reset.
const DEFAULT_MAX_FILES: usize = 512;

/// Default cap on capture attempts per second. A fork storm beyond this rate
/// degrades to the existing `[exited]` rendering for the overflow.
const DEFAULT_CAPTURES_PER_SEC: u32 = 500;

/// (device, inode) — identifies a mapped file independent of path or process.
type FileKey = (u64, u64);

struct PinnedFile {
    file: File,
    /// Basename of the mapping's pathname, for frame module attribution
    /// (the `/proc/self/fd/<n>` path would otherwise leak into frames).
    display: String,
}

struct ExecSegment {
    start: u64,
    end: u64,
    file_offset: u64,
    file: FileKey,
}

/// Executable-mapping snapshot for one process, sorted by start address.
struct ProcSnapshot {
    segments: Vec<ExecSegment>,
}

/// A user address resolved against a snapshot: where to symbolize from and
/// what to call the module.
pub struct ResolvedAddr {
    /// `/proc/self/fd/<n>` path of the pinned backing file.
    pub elf_path: PathBuf,
    /// Offset of the address within that file.
    pub file_offset: u64,
    /// Module name for frame rendering (original binary basename).
    pub module: String,
}

pub struct ExitSnapshots {
    enabled: bool,
    /// tgids already attempted (successfully or not) — one attempt each.
    seen: HashSet<i32>,
    snapshots: HashMap<i32, ProcSnapshot>,
    files: HashMap<FileKey, PinnedFile>,
    /// Pin order for oldest-first eviction.
    file_order: VecDeque<FileKey>,
    max_files: usize,
    captures_per_sec: u32,
    budget_window: Instant,
    budget_left: u32,
}

impl Default for ExitSnapshots {
    fn default() -> Self {
        Self::new()
    }
}

impl ExitSnapshots {
    pub fn new() -> Self {
        Self {
            enabled: true,
            seen: HashSet::new(),
            snapshots: HashMap::new(),
            files: HashMap::new(),
            file_order: VecDeque::new(),
            max_files: DEFAULT_MAX_FILES,
            captures_per_sec: DEFAULT_CAPTURES_PER_SEC,
            budget_window: Instant::now(),
            budget_left: DEFAULT_CAPTURES_PER_SEC,
        }
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Note a stack sample for `tgid`, capturing its executable mappings on
    /// first sighting. Called from the stack-event hot path: the steady-state
    /// cost is one HashSet lookup.
    pub fn observe_tgid(&mut self, tgid: i32) {
        if !self.enabled || tgid <= 0 {
            return;
        }
        if !self.seen.insert(tgid) {
            return;
        }
        let now = Instant::now();
        if now.duration_since(self.budget_window).as_secs() >= 1 {
            self.budget_window = now;
            self.budget_left = self.captures_per_sec;
        }
        if self.budget_left == 0 {
            // Over budget: the tgid stays marked seen and its frames keep the
            // [exited] rendering if it dies — same as before this feature.
            return;
        }
        self.budget_left -= 1;
        if let Some(snapshot) = self.capture(tgid) {
            if !snapshot.segments.is_empty() {
                self.snapshots.insert(tgid, snapshot);
            }
        }
    }

    /// Resolve a user address for a (dead) process against its snapshot.
    pub fn resolve(&self, tgid: i32, addr: u64) -> Option<ResolvedAddr> {
        let snapshot = self.snapshots.get(&tgid)?;
        let idx = snapshot
            .segments
            .partition_point(|segment| segment.end <= addr);
        let segment = snapshot.segments.get(idx)?;
        if addr < segment.start {
            return None;
        }
        let pinned = self.files.get(&segment.file)?;
        Some(ResolvedAddr {
            elf_path: PathBuf::from(format!("/proc/self/fd/{}", pinned.file.as_raw_fd())),
            file_offset: addr - segment.start + segment.file_offset,
            module: pinned.display.clone(),
        })
    }

    /// Whether a snapshot exists for `tgid`.
    pub fn has_snapshot(&self, tgid: i32) -> bool {
        self.snapshots.contains_key(&tgid)
    }

    /// Forget a tgid on exec. Exec replaced the address space, so an earlier
    /// snapshot describes mappings that no longer exist — and worse than
    /// being stale, it can overlap the new image's address ranges and
    /// symbolize post-exec addresses to confidently wrong names. Because the
    /// seen-set is one-attempt, the stale entry would also block the correct
    /// re-capture. Dropping both lets the process's next stack sample
    /// capture the new image; if it dies unsampled instead, its frames keep
    /// the honest [exited] rendering. Pinned files stay until reset(): other
    /// snapshots may share them, and the descriptor cap bounds the count.
    pub fn forget_on_exec(&mut self, tgid: i32) {
        self.seen.remove(&tgid);
        self.snapshots.remove(&tgid);
    }

    /// Drop all snapshots and release every pinned descriptor. Called at the
    /// end of each symbolization pass so continuous mode doesn't accumulate
    /// descriptors across ticks.
    pub fn reset(&mut self) {
        self.seen.clear();
        self.snapshots.clear();
        self.files.clear();
        self.file_order.clear();
        self.budget_left = self.captures_per_sec;
        self.budget_window = Instant::now();
    }

    fn capture(&mut self, tgid: i32) -> Option<ProcSnapshot> {
        let maps = std::fs::read_to_string(format!("/proc/{tgid}/maps")).ok()?;
        let mut segments = Vec::new();
        for line in maps.lines() {
            if segments.len() >= MAX_SEGMENTS_PER_PROC {
                break;
            }
            let Some(parsed) = parse_exec_maps_line(line) else {
                continue;
            };
            if self.pin_file(tgid, &parsed) {
                segments.push(ExecSegment {
                    start: parsed.start,
                    end: parsed.end,
                    file_offset: parsed.file_offset,
                    file: parsed.file,
                });
            }
        }
        // /proc/<pid>/maps is sorted by address, but don't rely on it.
        segments.sort_by_key(|segment| segment.start);
        Some(ProcSnapshot { segments })
    }

    /// Ensure the backing file of a parsed mapping is pinned. Returns false
    /// when the file cannot be opened (the segment is then not recorded and
    /// its addresses keep the [exited] rendering).
    fn pin_file(&mut self, tgid: i32, parsed: &ParsedMapsLine) -> bool {
        if self.files.contains_key(&parsed.file) {
            return true;
        }
        let Some(file) = open_mapping_file(tgid, parsed) else {
            return false;
        };
        if self.files.len() >= self.max_files {
            // A file evicted and later re-pinned leaves a stale key in the
            // order queue; skip such entries until one actually evicts.
            while let Some(oldest) = self.file_order.pop_front() {
                if self.files.remove(&oldest).is_some() {
                    break;
                }
            }
        }
        self.file_order.push_back(parsed.file);
        self.files.insert(
            parsed.file,
            PinnedFile {
                file,
                display: parsed.display.clone(),
            },
        );
        true
    }
}

/// Open the backing file of an executable mapping.
///
/// The map_files link is the primary path: its entry names are unpadded hex,
/// it re-opens the mapped file itself (namespace-independent, and it keeps
/// working after the file is unlinked), and it is authoritative by
/// construction so needs no verification. It requires CAP_SYS_ADMIN, so when
/// it is unavailable (reduced-capability environments), fall back to the
/// path through the process's root, then the plain path — each verified
/// against the mapping's (device, inode) so a recycled or namespace-mismatched
/// path can never pin the wrong file.
fn open_mapping_file(tgid: i32, parsed: &ParsedMapsLine) -> Option<File> {
    let link = format!("/proc/{tgid}/map_files/{:x}-{:x}", parsed.start, parsed.end);
    if let Ok(file) = File::open(link) {
        return Some(file);
    }
    for candidate in [
        format!("/proc/{tgid}/root{}", parsed.path),
        parsed.path.clone(),
    ] {
        if let Ok(file) = File::open(candidate) {
            if file_key(&file) == Some(parsed.file) {
                return Some(file);
            }
        }
    }
    None
}

/// (device, inode) of an open file, encoded like the maps-line key.
fn file_key(file: &File) -> Option<FileKey> {
    use std::os::unix::fs::MetadataExt;
    let meta = file.metadata().ok()?;
    let major = libc::major(meta.dev()) as u64;
    let minor = libc::minor(meta.dev()) as u64;
    Some(((major << 32) | minor, meta.ino()))
}

struct ParsedMapsLine {
    start: u64,
    end: u64,
    file_offset: u64,
    file: FileKey,
    path: String,
    display: String,
}

/// Parse one /proc/<pid>/maps line, returning Some only for executable,
/// file-backed mappings: `start-end perms offset dev inode path`.
fn parse_exec_maps_line(line: &str) -> Option<ParsedMapsLine> {
    let mut fields = line.split_whitespace();
    let range = fields.next()?;
    let perms = fields.next()?;
    let offset = fields.next()?;
    let dev = fields.next()?;
    let inode = fields.next()?;
    let path = fields.next()?;

    if !perms.contains('x') || !path.starts_with('/') {
        return None;
    }
    let inode: u64 = inode.parse().ok()?;
    if inode == 0 {
        return None;
    }

    let (start, end) = range.split_once('-')?;
    let start = u64::from_str_radix(start, 16).ok()?;
    let end = u64::from_str_radix(end, 16).ok()?;
    let file_offset = u64::from_str_radix(offset, 16).ok()?;

    let (major, minor) = dev.split_once(':')?;
    let major = u64::from_str_radix(major, 16).ok()?;
    let minor = u64::from_str_radix(minor, 16).ok()?;

    // Module display name: basename of the path field. When the binary has
    // been unlinked (common for ephemeral CI files), the kernel appends a
    // " (deleted)" marker that whitespace-splitting leaves in a trailing
    // field we never read — and the pinned descriptor reads the unlinked
    // file fine regardless.
    let display = path.rsplit('/').next().unwrap_or(path).to_string();

    Some(ParsedMapsLine {
        start,
        end,
        file_offset,
        file: ((major << 32) | minor, inode),
        path: path.to_string(),
        display,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_executable_file_mappings() {
        let parsed = parse_exec_maps_line(
            "7f2a1c400000-7f2a1c5b0000 r-xp 00028000 fd:01 1837462 /usr/lib/x86_64-linux-gnu/libc.so.6",
        )
        .expect("should parse");
        assert_eq!(parsed.start, 0x7f2a1c400000);
        assert_eq!(parsed.end, 0x7f2a1c5b0000);
        assert_eq!(parsed.file_offset, 0x28000);
        assert_eq!(parsed.file, ((0xfd << 32) | 0x01, 1837462));
        assert_eq!(parsed.display, "libc.so.6");
    }

    #[test]
    fn parse_rejects_non_executable_and_anonymous() {
        // Data segment: not executable.
        assert!(parse_exec_maps_line(
            "7f2a1c5b0000-7f2a1c5b4000 r--p 001b0000 fd:01 1837462 /usr/lib/libc.so.6"
        )
        .is_none());
        // Anonymous executable (JIT): no backing file to pin.
        assert!(parse_exec_maps_line("7f2a1d000000-7f2a1d100000 rwxp 00000000 00:00 0").is_none());
        // vdso: pseudo-path.
        assert!(
            parse_exec_maps_line("7ffe32bc0000-7ffe32bc2000 r-xp 00000000 00:00 0 [vdso]")
                .is_none()
        );
        // Garbage.
        assert!(parse_exec_maps_line("not a maps line").is_none());
        assert!(parse_exec_maps_line("").is_none());
    }

    #[test]
    fn parse_handles_deleted_and_plain_paths() {
        let plain = parse_exec_maps_line(
            "55d400000000-55d400001000 r-xp 00000000 fd:01 99 /tmp/build/prog",
        )
        .expect("should parse");
        assert_eq!(plain.display, "prog");
        // Unlinked binary: the kernel appends " (deleted)", which lands in a
        // trailing field the parser never reads.
        let deleted = parse_exec_maps_line(
            "55d400000000-55d400001000 r-xp 00000000 fd:01 99 /tmp/build/prog (deleted)",
        )
        .expect("should parse");
        assert_eq!(deleted.display, "prog");
    }

    #[test]
    fn observe_respects_seen_and_budget() {
        let mut snapshots = ExitSnapshots::new();
        snapshots.captures_per_sec = 1;
        snapshots.budget_left = 1;
        // Own pid: capture succeeds against our real /proc.
        let me = std::process::id() as i32;
        snapshots.observe_tgid(me);
        assert!(snapshots.has_snapshot(me), "own process should snapshot");
        // Second observe of the same tgid is a no-op (seen).
        snapshots.observe_tgid(me);
        // Budget exhausted: a different tgid is skipped even if alive.
        snapshots.budget_window = Instant::now(); // hold the window open
        snapshots.observe_tgid(1);
        assert!(
            !snapshots.has_snapshot(1),
            "over-budget tgid must be skipped"
        );
    }

    #[test]
    fn resolve_own_process_maps_to_file_offsets() {
        let mut snapshots = ExitSnapshots::new();
        let me = std::process::id() as i32;
        snapshots.observe_tgid(me);
        let snapshot = snapshots.snapshots.get(&me).expect("snapshot exists");
        let segment = snapshot.segments.first().expect("has exec segments");
        let (start, file_offset) = (segment.start, segment.file_offset);
        let probe = start + 0x100;
        let resolved = snapshots.resolve(me, probe).expect("resolves");
        assert_eq!(resolved.file_offset, 0x100 + file_offset);
        assert!(resolved.elf_path.starts_with("/proc/self/fd/"));
        assert!(!resolved.module.is_empty());
        // An address below every segment resolves to None.
        assert!(snapshots.resolve(me, 0x1000).is_none());
        // Unknown tgid resolves to None.
        assert!(snapshots.resolve(-1, probe).is_none());
    }

    #[test]
    fn reset_releases_everything() {
        let mut snapshots = ExitSnapshots::new();
        let me = std::process::id() as i32;
        snapshots.observe_tgid(me);
        assert!(snapshots.has_snapshot(me));
        snapshots.reset();
        assert!(!snapshots.has_snapshot(me));
        assert!(snapshots.files.is_empty());
        assert!(snapshots.seen.is_empty());
        // Observable again after reset.
        snapshots.observe_tgid(me);
        assert!(snapshots.has_snapshot(me));
    }

    #[test]
    fn forget_on_exec_drops_snapshot_and_allows_recapture() {
        let mut snapshots = ExitSnapshots::new();
        let me = std::process::id() as i32;
        snapshots.observe_tgid(me);
        assert!(snapshots.has_snapshot(me));
        snapshots.forget_on_exec(me);
        // Snapshot gone: post-exec addresses degrade to [exited] rather than
        // resolving against the pre-exec image.
        assert!(!snapshots.has_snapshot(me));
        assert!(!snapshots.seen.contains(&me));
        // The next sample re-captures (seen-set no longer blocks it), and a
        // forgotten tgid's pinned files remain until reset().
        snapshots.observe_tgid(me);
        assert!(snapshots.has_snapshot(me));
        // Unknown tgid is a no-op.
        snapshots.forget_on_exec(-1);
    }

    #[test]
    fn eviction_is_oldest_first_and_resolve_degrades() {
        let mut snapshots = ExitSnapshots::new();
        snapshots.max_files = 1;
        let me = std::process::id() as i32;
        snapshots.observe_tgid(me);
        // With a cap of one file, only the newest pin survives; addresses in
        // segments whose file was evicted resolve to None rather than
        // erroring.
        assert!(snapshots.files.len() <= 1);
        let snapshot = snapshots.snapshots.get(&me).expect("snapshot exists");
        let resolvable = snapshot
            .segments
            .iter()
            .filter(|segment| snapshots.files.contains_key(&segment.file))
            .count();
        assert!(resolvable <= 1);
    }
}
