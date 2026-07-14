//! Host-side analysis of a process's memory map for symbolizing sandboxed
//! (gVisor/runsc) workloads and labeling otherwise-unresolvable frames.
//!
//! Under gVisor's systrap platform, guest code executes in *stub* processes
//! whose address spaces mirror the guest's. Guest ELF text is mostly backed by
//! gofer-donated host file descriptors (symbolizable through
//! `/proc/<pid>/map_files/`), but three things still defeat a
//! `/proc/<pid>/maps`-driven symbolizer:
//!
//! 1. systrap's syscall patching COW-breaks the 4KiB text pages containing
//!    executed syscall sites into the Sentry's `runsc-memory` memfd, leaving
//!    memfd "islands" inside file-backed text. Island addresses still
//!    correspond to functions of the original file, so they can be recovered
//!    by re-deriving the file offset from the file-backed neighbors
//!    ("bridging", see [`ProcessMaps::bridge_for`]).
//! 2. The sysmsg/trampoline code every guest syscall executes lives in
//!    memfd/anonymous mappings outside the guest image range — those frames
//!    are gVisor runtime overhead, not application code.
//! 3. Anonymous guest ranges (JIT output, copied-up pages) are backed by the
//!    memory-pool memfd whose offsets have no relation to any file.
//!
//! This module parses `/proc/<pid>/maps` once per process at symbolization
//! time and answers, per address: "can this be bridged to a file?" and if
//! not, "what is the most specific label we can attach instead of raw hex?".
//! The labels reuse systing's existing miss format (`unknown (<module>)
//! <0xADDR>`), so downstream consumers see a module-shaped string:
//! `[gvisor:runtime]`, `[jit:<runtime>]`, `[anon:exec]`, `[anon]`,
//! `[unmapped]`, or the real module basename when only the symbol lookup
//! failed.

use std::fs;
use std::path::PathBuf;

/// What backs one `/proc/<pid>/maps` entry, as far as classification cares.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Backing {
    /// Regular file with an absolute path (may be namespace-relative and
    /// unopenable by path; `map_files` still works).
    File(PathBuf),
    /// A memfd (`/memfd:<name> (deleted)`); gVisor's memory pools land here.
    Memfd(String),
    /// No backing object at all (pure anonymous).
    Anon,
    /// Bracketed pseudo-entries (`[vdso]`, `[stack]`, ...) and
    /// `anon_inode:...` style components.
    Special(String),
}

#[derive(Debug, Clone)]
struct MapEntry {
    start: u64,
    end: u64,
    exec: bool,
    /// File offset field of the maps line (memfd offsets are pool offsets
    /// and meaningless for ELF math; file offsets are real).
    offset: u64,
    backing: Backing,
}

/// Result of a bridge lookup: symbolize `file_offset` against the ELF that
/// is reachable through `map_files_path` (a namespace-immune magic link of a
/// *file-backed* neighbor entry, not of the island itself).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgedAddr {
    pub map_files_path: PathBuf,
    pub module_name: String,
    pub file_offset: u64,
}

/// Per-process map analysis. Build once per tgid with [`ProcessMaps::load`]
/// (or [`ProcessMaps::parse`] for tests), query per unresolved address.
#[derive(Debug, Default)]
pub struct ProcessMaps {
    tgid: i32,
    entries: Vec<MapEntry>,
    /// Any gVisor memory-pool memfd present (`runsc-memory`,
    /// `systrap-memory`).
    gvisor_memfd: bool,
    /// `/proc/<tgid>/exe` resolves to a runsc binary.
    gvisor_exe: bool,
    /// Basename of a known JIT runtime found among file-backed entries.
    jit_runtime: Option<&'static str>,
    /// Address span of file-backed guest mappings ([lo, hi)); executable
    /// pool/anon mappings outside this span are runtime scaffolding, inside
    /// are guest anon (JIT or data made executable).
    file_span: Option<(u64, u64)>,
}

/// memfd names used by gVisor for application/stub memory. Entries here mark
/// a process as sandbox-related and their mappings as pool-backed.
const GVISOR_MEMFDS: &[&str] = &["runsc-memory", "systrap-memory"];

/// Module basenames whose presence marks a process as running a JIT runtime;
/// anonymous executable pages in such a process are labeled `[jit:<tag>]`,
/// and so are sampled addresses that are no longer mapped by the time maps
/// are read (JIT runtimes recycle code pages faster than a recording tick).
/// Deliberately short and conservative; matching requires a version or
/// extension boundary after the prefix (see [`runtime_matches`]).
const JIT_RUNTIMES: &[(&str, &str)] = &[
    ("beam.smp", "beam"),
    ("bun", "bun"),
    ("deno", "deno"),
    ("libcoreclr", "dotnet"),
    ("libjulia", "julia"),
    ("libjvm", "jvm"),
    ("libluajit", "lua"),
    ("libnode", "node"),
    ("libpypy", "pypy"),
    ("libpython3", "python"),
    ("libruby", "ruby"),
    ("libv8", "v8"),
    ("node", "node"),
    ("nodejs", "node"),
    ("pypy", "pypy"),
    ("python3", "python"),
    ("ruby", "ruby"),
];

/// Whether a module basename belongs to a runtime prefix: exact match, or
/// the prefix followed by a version/extension boundary — "node" matches
/// "node" and "node22", "libnode.so.115", but not "node_exporter".
fn runtime_matches(base: &str, prefix: &str) -> bool {
    match base.strip_prefix(prefix) {
        Some("") => true,
        Some(rest) => {
            let c = rest.as_bytes()[0];
            c == b'.' || c == b'-' || c.is_ascii_digit()
        }
        None => false,
    }
}

/// The JIT runtime tag for a mapped-module basename, if any.
pub(crate) fn detect_jit_runtime(base: &str) -> Option<&'static str> {
    JIT_RUNTIMES
        .iter()
        .find(|(prefix, _)| runtime_matches(base, prefix))
        .map(|(_, tag)| *tag)
}

impl ProcessMaps {
    /// Read and analyze `/proc/<tgid>/maps`. Returns `None` when the process
    /// is gone or unreadable — callers fall back to plain hex rendering.
    pub fn load(tgid: i32) -> Option<Self> {
        let maps = fs::read_to_string(format!("/proc/{tgid}/maps")).ok()?;
        let exe = fs::read_link(format!("/proc/{tgid}/exe"))
            .ok()
            .and_then(|p| {
                p.file_name()
                    .and_then(|f| f.to_str())
                    .map(|s| s.to_string())
            })
            .unwrap_or_default();
        Some(Self::parse(tgid, &maps, &exe))
    }

    /// Analyze pre-read maps content. `exe_basename` is the resolved
    /// basename of `/proc/<tgid>/exe` ("" when unknown).
    pub fn parse(tgid: i32, maps: &str, exe_basename: &str) -> Self {
        let mut pm = ProcessMaps {
            tgid,
            // The sandbox re-execs /proc/self/exe so its comm is "exe", but
            // the exe link still resolves to the runsc binary; stubs inherit
            // it across fork.
            gvisor_exe: exe_basename.starts_with("runsc"),
            ..Default::default()
        };

        for line in maps.lines() {
            let Some(entry) = parse_maps_line(line) else {
                continue;
            };
            match &entry.backing {
                Backing::Memfd(name) if GVISOR_MEMFDS.iter().any(|m| name == m) => {
                    pm.gvisor_memfd = true;
                }
                Backing::File(path) => {
                    if let Some(base) = path.file_name().and_then(|f| f.to_str()) {
                        if let Some(tag) = detect_jit_runtime(base) {
                            pm.jit_runtime = Some(tag);
                        }
                    }
                    let (lo, hi) = pm.file_span.unwrap_or((u64::MAX, 0));
                    pm.file_span = Some((lo.min(entry.start), hi.max(entry.end)));
                }
                _ => {}
            }
            pm.entries.push(entry);
        }
        pm
    }

    /// Whether this process belongs to a gVisor sandbox (Sentry, gofer, or a
    /// stub mirroring a guest address space).
    pub fn is_gvisor(&self) -> bool {
        self.gvisor_exe || self.gvisor_memfd
    }

    /// Executable file-backed ranges of this process — for a systrap stub,
    /// the fragments of guest text it maps directly. Used as the
    /// fingerprint for correlating a stub to the guest process it mirrors
    /// (stub VAs are guest VAs).
    pub fn exec_file_ranges(&self) -> Vec<(u64, u64)> {
        self.entries
            .iter()
            .filter(|e| e.exec && matches!(e.backing, Backing::File(_)))
            .map(|e| (e.start, e.end))
            .collect()
    }

    fn entry_for(&self, addr: u64) -> Option<&MapEntry> {
        // Entries are in address order as read from /proc.
        self.entries
            .iter()
            .find(|e| e.start <= addr && addr < e.end)
    }

    /// If `addr` falls in a pool-memfd island whose file-backed neighbors
    /// agree on the original file, return where to symbolize it instead.
    ///
    /// The island's own bytes are a patched copy, but its *addresses* still
    /// belong to the original binary, so `addr`'s file offset is derived
    /// from the left neighbor: `addr - L.start + L.offset`. Conservative
    /// rule: both neighbors must reference the same file with congruent
    /// offsets (`R.offset - L.offset == R.start - L.start`), so a pool page
    /// that merely happens to sit between two unrelated files never bridges.
    pub fn bridge_for(&self, addr: u64) -> Option<BridgedAddr> {
        let idx = self
            .entries
            .iter()
            .position(|e| e.start <= addr && addr < e.end)?;
        let island = &self.entries[idx];
        if !matches!(island.backing, Backing::Memfd(_)) || !island.exec {
            return None;
        }
        let left = self.entries.get(idx.checked_sub(1)?)?;
        let right = self.entries.get(idx + 1)?;
        let (Backing::File(lpath), Backing::File(rpath)) = (&left.backing, &right.backing) else {
            return None;
        };
        if lpath != rpath || !left.exec {
            return None;
        }
        // Neighbors must be address-adjacent to the island and offset-congruent.
        if left.end != island.start || island.end != right.start {
            return None;
        }
        if right.offset.wrapping_sub(left.offset) != right.start.wrapping_sub(left.start) {
            return None;
        }
        let module_name = lpath
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("unknown")
            .to_string();
        Some(BridgedAddr {
            // Open through the *neighbor's* map_files link: it references the
            // original ELF regardless of mount namespaces. The island's own
            // link would open the memory-pool memfd.
            map_files_path: PathBuf::from(format!(
                "/proc/{}/map_files/{:x}-{:x}",
                self.tgid, left.start, left.end
            )),
            module_name,
            file_offset: addr - left.start + left.offset,
        })
    }

    /// Most specific module-slot label for an address that did not
    /// symbolize. Returns `None` only for bracketed pseudo-entries
    /// (`[vdso]`, `[stack]`, ...) — those are the symbolizer's business;
    /// everything else gets at least a class name, so raw hex from a live
    /// process means the maps themselves were unreadable.
    ///
    /// gVisor classification leans on which backing object a mapping uses:
    /// ALL guest-created memory is served from the `runsc-memory` pool, the
    /// sysmsg machinery lives in `systrap-memory`, and pure host-anonymous
    /// mappings in a sandbox process can only come from the stub/Sentry
    /// itself (a guest cannot create host mappings outside the pool). The
    /// one exception is the usertrap trampoline table, which the Sentry
    /// injects from the pool *below* the guest image.
    pub fn label_for(&self, addr: u64) -> Option<String> {
        let entry = self.entry_for(addr);
        let gvisor = self.is_gvisor();
        match entry.map(|e| (&e.backing, e.exec)) {
            // Symbol lookup failed but the module is known — report it.
            // Covers stripped binaries (incl. release runsc builds) and
            // parse failures; strictly more information than hex.
            Some((Backing::File(path), _)) => Some(
                path.file_name()
                    .and_then(|f| f.to_str())
                    .unwrap_or("unknown")
                    .to_string(),
            ),
            Some((Backing::Memfd(name), exec)) if gvisor && name == "runsc-memory" => {
                let below_guest_image = self.file_span.map(|(lo, _)| addr < lo).unwrap_or(false);
                if below_guest_image && exec {
                    // usertrap trampoline table.
                    Some("[gvisor:runtime]".to_string())
                } else {
                    // Guest memory: JIT output if a JIT runtime is mapped
                    // and the page is executable, otherwise unidentifiable
                    // guest pages (COW'd data, heap made executable, ...).
                    match self.jit_runtime {
                        Some(rt) if exec => Some(format!("[jit:{rt}]")),
                        _ => Some("[gvisor:guest]".to_string()),
                    }
                }
            }
            // systrap-memory (sysmsg stacks/state) and stub-created host
            // mappings: sandbox runtime cost.
            Some((Backing::Memfd(_), _)) | Some((Backing::Anon, _)) if gvisor => {
                Some("[gvisor:runtime]".to_string())
            }
            // Non-gVisor JIT runtimes: anonymous executable pages are JIT
            // output with the same confidence as in the sandboxed case;
            // without a recognized runtime the page is still nameable as
            // what it observably is.
            Some((Backing::Memfd(_), true)) | Some((Backing::Anon, true)) => {
                Some(match self.jit_runtime {
                    Some(rt) => format!("[jit:{rt}]"),
                    None => "[anon:exec]".to_string(),
                })
            }
            // Non-executable anonymous memory: heap, arenas, or a W^X
            // code page caught in its writable phase. A PC here is either
            // recycled code or unwind garbage — name the class without
            // claiming a runtime.
            Some((Backing::Memfd(_), false)) | Some((Backing::Anon, false)) => {
                Some("[anon]".to_string())
            }
            // Bracketed pseudo-entries stay with the symbolizer.
            Some((Backing::Special(_), _)) => None,
            // In no current mapping at all. JIT runtimes allocate and free
            // code pages faster than a recording tick, so in a process
            // running one this is almost always reclaimed JIT code; the
            // maps snapshot postdates the sample. Otherwise unknowable.
            None => Some(match self.jit_runtime {
                Some(rt) => format!("[jit:{rt}]"),
                None => "[unmapped]".to_string(),
            }),
        }
    }
}

/// Parse one maps line: `start-end perms offset dev inode [path]`.
fn parse_maps_line(line: &str) -> Option<MapEntry> {
    let mut it = line.splitn(6, ' ');
    let range = it.next()?;
    let perms = it.next()?;
    let offset = it.next()?;
    let _dev = it.next()?;
    let _inode = it.next()?;
    let path = it.next().unwrap_or("").trim_start();

    let (start, end) = range.split_once('-')?;
    let start = u64::from_str_radix(start, 16).ok()?;
    let end = u64::from_str_radix(end, 16).ok()?;
    let offset = u64::from_str_radix(offset, 16).ok()?;
    let exec = perms.as_bytes().get(2) == Some(&b'x');

    let backing = if path.is_empty() {
        Backing::Anon
    } else if let Some(name) = path.strip_prefix("/memfd:") {
        Backing::Memfd(name.strip_suffix(" (deleted)").unwrap_or(name).to_string())
    } else if path.starts_with('/') {
        let p = path.strip_suffix(" (deleted)").unwrap_or(path);
        Backing::File(PathBuf::from(p))
    } else {
        Backing::Special(path.to_string())
    };

    Some(MapEntry {
        start,
        end,
        exec,
        offset,
        backing,
    })
}

/// Render the standard "symbolization failed" frame for `addr` given an
/// optional maps analysis: `unknown (<label>) <0xADDR>` when something is
/// known, plain `0xADDR` otherwise (preserving the historical format).
pub fn format_unresolved(addr: u64, maps: Option<&ProcessMaps>) -> String {
    match maps.and_then(|m| m.label_for(addr)) {
        Some(label) => format!("unknown ({label}) <{addr:#x}>"),
        None => format!("0x{addr:x}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Maps shape observed on a live runsc systrap stub (trimmed): guest
    /// text file-backed with 4KiB pool islands at patched syscall sites,
    /// usertrap trampolines below the image, stub text above it.
    const STUB_MAPS: &str = "\
64000-69000 r-xs 3ff26000 00:01 4                          /memfd:runsc-memory (deleted)
400000-4c2000 r-xs 00000000 00:13 426                      /root/bin/guestbox
4c2000-4c3000 r-xs 3ff1f000 00:01 4                        /memfd:runsc-memory (deleted)
4c3000-4cd000 r-xs 000c3000 00:13 426                      /root/bin/guestbox
4cd000-4ce000 r-xs 3ff20000 00:01 4                        /memfd:runsc-memory (deleted)
4ce000-512000 r-xs 000ce000 00:13 426                      /root/bin/guestbox
711000-714000 rw-s 3fe00000 00:01 4                        /memfd:runsc-memory (deleted)
7fa398efc000-7fa398eff000 r-xp 00000000 00:00 0
7fee63d08000-7fee63d09000 r--s 3fffe000 00:01 3            /memfd:systrap-memory (deleted)";

    #[test]
    fn test_parse_and_detect_gvisor() {
        let pm = ProcessMaps::parse(510, STUB_MAPS, "");
        assert!(pm.is_gvisor(), "memfd pools alone must flag gVisor");
        assert_eq!(pm.entries.len(), 9);
        assert_eq!(pm.file_span, Some((0x400000, 0x512000)));

        let pm_exe = ProcessMaps::parse(1, "", "runsc");
        assert!(pm_exe.is_gvisor(), "exe basename alone must flag gVisor");

        let pm_plain = ProcessMaps::parse(
            2,
            "400000-500000 r-xp 00000000 08:01 42 /usr/bin/foo",
            "foo",
        );
        assert!(!pm_plain.is_gvisor());
    }

    #[test]
    fn test_bridge_island() {
        let pm = ProcessMaps::parse(510, STUB_MAPS, "");
        // 0x4c2800 sits in the first island; left neighbor starts at
        // 0x400000 with file offset 0 -> file offset 0xc2800.
        let b = pm.bridge_for(0x4c2800).expect("island must bridge");
        assert_eq!(b.file_offset, 0xc2800);
        assert_eq!(b.module_name, "guestbox");
        assert_eq!(
            b.map_files_path,
            PathBuf::from("/proc/510/map_files/400000-4c2000")
        );

        // Offsets of the second island's neighbors are congruent too.
        let b2 = pm.bridge_for(0x4cd400).expect("second island bridges");
        assert_eq!(b2.file_offset, 0xcd400);
        assert_eq!(
            b2.map_files_path,
            PathBuf::from("/proc/510/map_files/4c3000-4cd000")
        );

        // File-backed addresses never bridge (they symbolize normally).
        assert_eq!(pm.bridge_for(0x400100), None);
        // The trampoline memfd below the image has no file neighbors.
        assert_eq!(pm.bridge_for(0x64100), None);
        // Non-exec pool data does not bridge.
        assert_eq!(pm.bridge_for(0x711100), None);
    }

    #[test]
    fn test_bridge_requires_congruent_neighbors() {
        // Right neighbor's offset is NOT congruent with the left one:
        // a pool page between unrelated mappings of the same file.
        let maps = "\
400000-401000 r-xs 00000000 00:13 426 /root/bin/app
401000-402000 r-xs 3ff00000 00:01 4   /memfd:runsc-memory (deleted)
402000-403000 r-xs 00005000 00:13 426 /root/bin/app";
        let pm = ProcessMaps::parse(1, maps, "");
        assert_eq!(pm.bridge_for(0x401800), None);

        // Different files on each side never bridge.
        let maps2 = "\
400000-401000 r-xs 00000000 00:13 426 /root/bin/app
401000-402000 r-xs 3ff00000 00:01 4   /memfd:runsc-memory (deleted)
402000-403000 r-xs 00002000 00:13 427 /root/lib/other.so";
        let pm2 = ProcessMaps::parse(1, maps2, "");
        assert_eq!(pm2.bridge_for(0x401800), None);

        // Address gaps between island and neighbor break the bridge.
        let maps3 = "\
400000-401000 r-xs 00000000 00:13 426 /root/bin/app
402000-403000 r-xs 3ff00000 00:01 4   /memfd:runsc-memory (deleted)
403000-404000 r-xs 00003000 00:13 426 /root/bin/app";
        let pm3 = ProcessMaps::parse(1, maps3, "");
        assert_eq!(pm3.bridge_for(0x402800), None);
    }

    #[test]
    fn test_labels() {
        let pm = ProcessMaps::parse(510, STUB_MAPS, "");
        // Below the guest image: runtime scaffolding.
        assert_eq!(pm.label_for(0x64100).as_deref(), Some("[gvisor:runtime]"));
        // Above the guest image (stub text): runtime scaffolding.
        assert_eq!(
            pm.label_for(0x7fa398efc100).as_deref(),
            Some("[gvisor:runtime]")
        );
        // Known module, failed symbol lookup: module basename.
        assert_eq!(pm.label_for(0x400100).as_deref(), Some("guestbox"));
        // Unmapped address in a non-JIT process: named as such.
        assert_eq!(pm.label_for(0xdead0000).as_deref(), Some("[unmapped]"));

        // Guest-anon exec page inside the image span of a JIT-runtime
        // process labels as JIT output.
        let jit_maps = "\
400000-500000 r-xs 00000000 00:13 426 /usr/bin/node
600000-700000 r-xs 3f000000 00:01 4   /memfd:runsc-memory (deleted)
800000-900000 r-xs 00400000 00:13 426 /usr/bin/node";
        let pmj = ProcessMaps::parse(1, jit_maps, "");
        assert_eq!(pmj.label_for(0x600100).as_deref(), Some("[jit:node]"));

        // Same shape without a JIT runtime: guest pages.
        let pm_nojit = ProcessMaps::parse(510, STUB_MAPS, "");
        assert_eq!(
            pm_nojit.label_for(0x711100).as_deref(),
            Some("[gvisor:guest]"),
            "non-exec runsc-memory page (COW'd guest data) is guest memory"
        );
        // sysmsg machinery (systrap-memory) is runtime cost.
        assert_eq!(
            pm_nojit.label_for(0x7fee63d08100).as_deref(),
            Some("[gvisor:runtime]")
        );

        // Non-gVisor process: anonymous exec page with a JIT runtime mapped.
        let plain_jit = "\
400000-500000 r-xp 00000000 08:01 42 /usr/lib/libjvm.so
7f0000000000-7f0000100000 rwxp 00000000 00:00 0 ";
        let pmp = ProcessMaps::parse(2, plain_jit, "java");
        assert_eq!(pmp.label_for(0x7f0000000100).as_deref(), Some("[jit:jvm]"));
        // An unmapped address in the same process: reclaimed JIT code —
        // pages are recycled between the sample and the maps read.
        assert_eq!(pmp.label_for(0xdead0000).as_deref(), Some("[jit:jvm]"));

        // Non-JIT, non-gVisor process: anon pages are named by observable
        // class instead of falling back to hex.
        let pm_none = ProcessMaps::parse(
            3,
            "400000-500000 r-xp 00000000 08:01 42 /usr/bin/foo\n\
             7f0000000000-7f0000001000 rw-p 00000000 00:00 0 \n\
             7f0000100000-7f0000101000 rwxp 00000000 00:00 0 ",
            "foo",
        );
        assert_eq!(pm_none.label_for(0x7f0000000100).as_deref(), Some("[anon]"));
        assert_eq!(
            pm_none.label_for(0x7f0000100100).as_deref(),
            Some("[anon:exec]")
        );
    }

    #[test]
    fn test_runtime_matching() {
        // Exact names and versioned/suffixed forms match.
        assert_eq!(detect_jit_runtime("node"), Some("node"));
        assert_eq!(detect_jit_runtime("node22"), Some("node"));
        assert_eq!(detect_jit_runtime("nodejs"), Some("node"));
        assert_eq!(detect_jit_runtime("libnode.so.115"), Some("node"));
        assert_eq!(detect_jit_runtime("libjvm.so"), Some("jvm"));
        assert_eq!(detect_jit_runtime("libpython3.14.so.1.0"), Some("python"));
        // Statically linked interpreters carry the runtime in the exe name.
        assert_eq!(detect_jit_runtime("python3.14"), Some("python"));
        assert_eq!(detect_jit_runtime("ruby3.2"), Some("ruby"));
        assert_eq!(detect_jit_runtime("libruby.so.3.2"), Some("ruby"));
        assert_eq!(detect_jit_runtime("libcoreclr.so"), Some("dotnet"));
        assert_eq!(detect_jit_runtime("beam.smp"), Some("beam"));
        assert_eq!(detect_jit_runtime("libluajit-5.1.so.2"), Some("lua"));
        assert_eq!(detect_jit_runtime("libjulia.so.1"), Some("julia"));
        assert_eq!(detect_jit_runtime("deno"), Some("deno"));
        assert_eq!(detect_jit_runtime("bun"), Some("bun"));
        assert_eq!(detect_jit_runtime("libpypy3.9-c.so"), Some("pypy"));
        // The boundary requirement rejects lookalike module names.
        assert_eq!(detect_jit_runtime("node_exporter"), None);
        assert_eq!(detect_jit_runtime("bundler"), None);
        assert_eq!(detect_jit_runtime("denoise"), None);
        assert_eq!(detect_jit_runtime("rubyfmt"), None);
        assert_eq!(detect_jit_runtime("libfoo.so"), None);
    }

    #[test]
    fn test_format_unresolved() {
        let pm = ProcessMaps::parse(510, STUB_MAPS, "");
        assert_eq!(
            format_unresolved(0x64100, Some(&pm)),
            "unknown ([gvisor:runtime]) <0x64100>"
        );
        assert_eq!(
            format_unresolved(0xdead0000, Some(&pm)),
            "unknown ([unmapped]) <0xdead0000>"
        );
        // No maps at all (unreadable /proc): hex is all that is left.
        assert_eq!(format_unresolved(0x1234, None), "0x1234");
    }

    #[test]
    fn test_parse_maps_line_variants() {
        // Deleted file suffix is stripped.
        let e =
            parse_maps_line("400000-401000 r-xp 00001000 08:01 42 /usr/bin/foo (deleted)").unwrap();
        assert_eq!(e.backing, Backing::File(PathBuf::from("/usr/bin/foo")));
        assert_eq!(e.offset, 0x1000);
        assert!(e.exec);

        // Special entries.
        let v = parse_maps_line("7ffe1000-7ffe2000 r-xp 00000000 00:00 0                  [vdso]")
            .unwrap();
        assert_eq!(v.backing, Backing::Special("[vdso]".to_string()));

        // Pure anonymous (trailing spaces, no path).
        let a = parse_maps_line("7f00000-7f01000 rw-p 00000000 00:00 0 ").unwrap();
        assert_eq!(a.backing, Backing::Anon);
        assert!(!a.exec);

        // Garbage lines are skipped, not fatal.
        assert!(parse_maps_line("not a maps line").is_none());
    }
}
