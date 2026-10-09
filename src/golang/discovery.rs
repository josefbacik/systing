//! Opening a Go program for reading: is it Go, which Go, and where are the
//! runtime's globals.
//!
//! The version is the one the linker wrote into `.go.buildinfo`, and it picks
//! the layout ([`super::offsets`]). The globals are found from the
//! executable's `.symtab` when it has one. A stripped binary
//! (`-ldflags=-s -w`) has none, but its `.gopclntab` still names every
//! function, and each global is the first one a known runtime function
//! loads (`RULES`): `runtime.memProfileInternal` loads `runtime.mbuckets`
//! first, `runtime.forEachG` loads `runtime.allgs`, and so on. The code is
//! read from the file, not from the process.

use std::cell::Cell;
use std::collections::HashMap;
use std::fs::File;
use std::path::Path;

use anyhow::{bail, Context, Result};
use gopclntab::{ElfPclntab, GoPclntab};
use object::{Object, ObjectKind, ObjectSection, ObjectSegment, ObjectSymbol};

use super::offsets::{self, Layout};
use crate::pystacks::process::{parse_maps, ProcessMemory, ReadMemory};

/// The runtime globals read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Global {
    /// The heap, block and mutex profiles' bucket lists.
    MBuckets,
    BBuckets,
    XBuckets,
    /// The slice of every goroutine.
    AllGs,
    MemProfileRate,
    /// `runtime.ticks`: CPU ticks per second, once the runtime has worked it
    /// out, and what it works it out from.
    Ticks,
    /// `runtime/trace.tracing`, which points at the flight recorder.
    Tracing,
}

/// Where a global is in a binary without symbols: the first 8-byte load from
/// memory in `function` (or with `lea`, the first address taken), the first
/// into `.noptrdata` where the function loads others before it. What is
/// loaded is `field` into the global.
struct Rule {
    global: Global,
    symbol: &'static str,
    function: &'static str,
    field: fn(&Layout) -> usize,
    only_noptrdata: bool,
    lea: bool,
}

fn at_start(_: &Layout) -> usize {
    0
}

fn ticks_val(l: &Layout) -> usize {
    l.ticks_val
}

const RULES: [Rule; 7] = [
    Rule {
        global: Global::MBuckets,
        symbol: "runtime.mbuckets",
        function: "runtime.memProfileInternal",
        field: at_start,
        only_noptrdata: false,
        lea: false,
    },
    Rule {
        global: Global::BBuckets,
        symbol: "runtime.bbuckets",
        function: "runtime.blockProfileInternal",
        field: at_start,
        only_noptrdata: false,
        lea: false,
    },
    Rule {
        global: Global::XBuckets,
        symbol: "runtime.xbuckets",
        function: "runtime.mutexProfileInternal",
        field: at_start,
        only_noptrdata: false,
        lea: false,
    },
    Rule {
        global: Global::AllGs,
        symbol: "runtime.allgs",
        function: "runtime.forEachG",
        field: at_start,
        only_noptrdata: false,
        lea: false,
    },
    Rule {
        global: Global::MemProfileRate,
        symbol: "runtime.MemProfileRate",
        function: "runtime.profilealloc",
        field: at_start,
        only_noptrdata: true,
        lea: false,
    },
    Rule {
        global: Global::Ticks,
        symbol: "runtime.ticks",
        function: "runtime.ticksPerSecond",
        field: ticks_val,
        only_noptrdata: false,
        lea: false,
    },
    // Only in programs that use the flight recorder: `Start` passes
    // `&tracing` to subscribe it.
    Rule {
        global: Global::Tracing,
        symbol: "runtime/trace.tracing",
        function: "runtime/trace.(*FlightRecorder).Start",
        field: at_start,
        only_noptrdata: false,
        lea: true,
    },
];

/// How the globals were found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FoundBy {
    Symbols,
    /// The binary is stripped: from the code of the functions that use them.
    Code,
}

impl FoundBy {
    pub fn name(self) -> &'static str {
        match self {
            FoundBy::Symbols => "symbols",
            FoundBy::Code => "code",
        }
    }
}

/// A process's memory, counting what is read.
pub(crate) struct Memory {
    inner: ProcessMemory,
    reads: Cell<u64>,
    bytes: Cell<u64>,
}

impl Memory {
    /// `len` bytes at `addr`, all of them or an error.
    pub(crate) fn bytes(&self, addr: u64, len: usize) -> Result<Vec<u8>> {
        self.reads.set(self.reads.get() + 1);
        self.bytes.set(self.bytes.get() + len as u64);
        let mut buf = vec![0u8; len];
        let at = usize::try_from(addr).context("an address out of range")?;
        if !self.inner.read_exact_at(at, &mut buf) {
            bail!("reading {len} bytes at {addr:#x}");
        }
        Ok(buf)
    }

    pub(crate) fn u64_at(&self, addr: u64) -> Result<u64> {
        Ok(u64_in(&self.bytes(addr, 8)?, 0))
    }

    /// (reads, bytes) so far.
    pub(crate) fn traffic(&self) -> (u64, u64) {
        (self.reads.get(), self.bytes.get())
    }
}

/// The little-endian word at `at` in `b`, which holds it.
pub(crate) fn u64_in(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

/// A running Go program, opened for reading.
pub struct GoProcess {
    pub pid: u32,
    /// The executable, as the process names it.
    pub exe: String,
    /// The Go release that built it, e.g. `go1.26.7`.
    pub version: String,
    pub found_by: FoundBy,
    pub(crate) mem: Memory,
    pub(crate) layout: Layout,
    pub(crate) pclntab: GoPclntab,
    /// Added to a file's virtual address to give its address in memory.
    pub(crate) bias: u64,
    globals: HashMap<Global, u64>,
}

/// Whether the executable at `path` is a Go program: it has a `.gopclntab`.
pub fn is_go(path: &Path) -> bool {
    matches!(ElfPclntab::from_path(path), Ok(Some(_)))
}

impl GoProcess {
    /// Open process `pid` through `proc_dir`, its directory in /proc
    /// (`/proc/<pid>`, or a path through a handle on it).
    pub fn open(pid: u32, proc_dir: &Path) -> Result<GoProcess> {
        let exe_path = proc_dir.join("exe");
        let exe = std::fs::read_link(&exe_path)
            .with_context(|| format!("reading /proc/{pid}/exe"))?
            .to_string_lossy()
            .into_owned();
        let elf = ElfPclntab::from_path(&exe_path)
            .with_context(|| format!("reading the Go function table of {exe}"))?
            .with_context(|| format!("{exe} is not a Go program (no .gopclntab)"))?;
        let file = File::open(&exe_path).with_context(|| format!("opening {exe}"))?;
        let cache = object::read::ReadCache::new(&file);
        let obj = object::File::parse(&cache).context("parsing the program's ELF")?;
        if obj.architecture() != object::Architecture::X86_64 {
            bail!("only x86-64 Go programs are supported");
        }
        let version = build_version(&obj).context("finding the Go version in .go.buildinfo")?;
        let layout = match version_numbers(&version).and_then(|(a, b)| offsets::for_version(a, b)) {
            Some(layout) => layout,
            None => bail!(
                "built with {version}: there are no bindings for its runtime's layout \
                 (scripts/generate_go_bindings.py makes them)"
            ),
        };
        let maps = std::fs::read_to_string(proc_dir.join("maps"))
            .with_context(|| format!("reading /proc/{pid}/maps"))?;
        let bias = load_bias(&obj, &parse_maps(&maps), &exe);
        let inner = ProcessMemory::open_path(&proc_dir.join("mem")).with_context(|| {
            format!(
                "opening /proc/{pid}/mem: reading a process's memory needs the same user as the \
                 process (any other, root included, needs CAP_SYS_PTRACE)"
            )
        })?;
        let (globals, found_by) = if elf.has_symtab {
            (globals_by_symbols(&obj, bias), FoundBy::Symbols)
        } else {
            (
                globals_by_code(&obj, &elf.table, &layout, bias),
                FoundBy::Code,
            )
        };
        Ok(GoProcess {
            pid,
            exe,
            version,
            found_by,
            mem: Memory {
                inner,
                reads: Cell::new(0),
                bytes: Cell::new(0),
            },
            layout,
            pclntab: elf.table,
            bias,
            globals,
        })
    }

    /// The address of `g` in the process.
    pub(crate) fn global(&self, g: Global) -> Result<u64> {
        self.globals
            .get(&g)
            .copied()
            .with_context(|| format!("could not find {g:?} in the program"))
    }

    /// The memory reads and bytes so far.
    pub fn traffic(&self) -> (u64, u64) {
        self.mem.traffic()
    }
}

fn globals_by_symbols<'a, R: object::ReadRef<'a>>(
    obj: &object::File<'a, R>,
    bias: u64,
) -> HashMap<Global, u64> {
    let wanted: HashMap<&str, Global> = RULES.iter().map(|r| (r.symbol, r.global)).collect();
    obj.symbols()
        .filter_map(|sym| {
            let global = *wanted.get(sym.name().ok()?)?;
            Some((global, sym.address().wrapping_add(bias)))
        })
        .collect()
}

fn globals_by_code<'a, R: object::ReadRef<'a>>(
    obj: &object::File<'a, R>,
    table: &GoPclntab,
    layout: &Layout,
    bias: u64,
) -> HashMap<Global, u64> {
    let mut globals = HashMap::new();
    let Some(text) = obj.section_by_name(".text") else {
        return globals;
    };
    let Ok(code) = text.data() else {
        return globals;
    };
    let noptrdata = section_range(obj, ".noptrdata");
    let data: Vec<(u64, u64)> = [".noptrdata", ".data", ".bss", ".noptrbss"]
        .iter()
        .filter_map(|n| section_range(obj, n))
        .collect();
    let functions = function_entries(table, &RULES.map(|r| r.function));
    for rule in &RULES {
        let Some(&(entry, size)) = functions.get(rule.function) else {
            continue;
        };
        let Some(start) = entry.checked_sub(text.address()) else {
            continue;
        };
        let start = start as usize;
        let end = start
            .saturating_add(size.min(4096) as usize)
            .min(code.len());
        let Some(body) = code.get(start..end) else {
            continue;
        };
        let allowed = |a: u64| match (rule.only_noptrdata, noptrdata) {
            (true, Some((s, e))) => a >= s && a < e,
            _ => data.iter().any(|&(s, e)| a >= s && a < e),
        };
        if let Some(target) = first_rip_relative(body, entry, rule.lea, allowed) {
            let base = target.wrapping_sub((rule.field)(layout) as u64);
            globals.insert(rule.global, base.wrapping_add(bias));
        }
    }
    globals
}

/// How far the executable was moved from its link addresses: nothing for a
/// fixed-address executable, else where its first page is mapped less where
/// it was linked.
fn load_bias<'a, R: object::ReadRef<'a>>(
    obj: &object::File<'a, R>,
    maps: &[crate::pystacks::process::MemoryMapping],
    exe: &str,
) -> u64 {
    if obj.kind() == ObjectKind::Executable {
        return 0;
    }
    let min_vaddr = obj.segments().map(|s| s.address()).min().unwrap_or(0);
    let deleted = format!("{exe} (deleted)");
    let base = maps
        .iter()
        .filter(|m| m.name == exe || m.name == deleted)
        .filter_map(|m| (m.start as u64).checked_sub(m.offset))
        .min()
        .unwrap_or(0);
    base.wrapping_sub(min_vaddr & !0xfff)
}

/// The Go version from `.go.buildinfo` (Go 1.18+, inline strings).
pub(crate) fn build_version<'a, R: object::ReadRef<'a>>(
    obj: &object::File<'a, R>,
) -> Result<String> {
    let section = obj
        .section_by_name(".go.buildinfo")
        .context("no .go.buildinfo section")?;
    let data = section.data().context("reading .go.buildinfo")?;
    if data.len() < 33 || &data[..14] != b"\xff Go buildinf:" || data[15] & 2 == 0 {
        bail!(".go.buildinfo is not the Go 1.18+ form");
    }
    let (len, n) = super::uvarint(&data[32..]).context("bad version length")?;
    let start = 32 + n;
    let version = usize::try_from(len)
        .ok()
        .and_then(|len| data.get(start..start.checked_add(len)?))
        .context("version runs off the section")?;
    Ok(String::from_utf8_lossy(version).into_owned())
}

/// (major, minor) of a version as the linker writes it: `go1.26.7`,
/// `go1.26rc1`, `go1.26.0-X:...`.
pub(crate) fn version_numbers(version: &str) -> Option<(u32, u32)> {
    let rest = version.strip_prefix("go")?;
    let (major, rest) = rest.split_once('.')?;
    let minor: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    Some((major.parse().ok()?, minor.parse().ok()?))
}

fn section_range<'a, R: object::ReadRef<'a>>(
    obj: &object::File<'a, R>,
    name: &str,
) -> Option<(u64, u64)> {
    obj.section_by_name(name)
        .map(|s| (s.address(), s.address() + s.size()))
}

/// The entry and size of each named function, from the pclntab.
fn function_entries(
    table: &GoPclntab,
    names: &[&'static str],
) -> HashMap<&'static str, (u64, u64)> {
    let mut out = HashMap::new();
    for i in 0..table.func_count() {
        let Some(f) = table.func_entry(i).and_then(|entry| table.find_func(entry)) else {
            continue;
        };
        if let Some(&name) = names.iter().find(|&&n| n == f.name) {
            out.insert(name, (f.entry, f.size));
        }
    }
    out
}

/// The address the first 8-byte RIP-relative load in `code` reads, among
/// those `allowed` accepts: `mov r64, [rip + disp32]` (REX.W 8B /r, mod 00,
/// r/m 101); with `lea`, the first address taken instead (REX.W 8D /r).
fn first_rip_relative(
    code: &[u8],
    entry: u64,
    lea: bool,
    allowed: impl Fn(u64) -> bool,
) -> Option<u64> {
    let opcode = if lea { 0x8d } else { 0x8b };
    code.windows(7).enumerate().find_map(|(i, w)| {
        let is_load = (w[0] == 0x48 || w[0] == 0x4c) && w[1] == opcode && (w[2] & 0xc7) == 0x05;
        if !is_load {
            return None;
        }
        let disp = i64::from(i32::from_le_bytes(w[3..7].try_into().unwrap()));
        let target = (entry as i64).wrapping_add(i as i64 + 7).wrapping_add(disp) as u64;
        allowed(target).then_some(target)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_first_rip_relative_load() {
        // lea rax,[rip+0x10]; mov rcx,[rip+0x20]; mov rdx,[rip+0x30]
        let code = [
            0x48, 0x8d, 0x05, 0x10, 0, 0, 0, //
            0x48, 0x8b, 0x0d, 0x20, 0, 0, 0, //
            0x48, 0x8b, 0x15, 0x30, 0, 0, 0,
        ];
        assert_eq!(
            first_rip_relative(&code, 0x1000, false, |_| true),
            Some(0x1000 + 14 + 0x20)
        );
        // The first one the caller accepts.
        assert_eq!(
            first_rip_relative(&code, 0x1000, false, |a| a == 0x1000 + 21 + 0x30),
            Some(0x1000 + 21 + 0x30)
        );
        // An address taken.
        assert_eq!(
            first_rip_relative(&code, 0x1000, true, |_| true),
            Some(0x1000 + 7 + 0x10)
        );
    }

    #[test]
    fn versions() {
        assert_eq!(version_numbers("go1.26.7"), Some((1, 26)));
        assert_eq!(version_numbers("go1.26rc1"), Some((1, 26)));
        assert_eq!(
            version_numbers("go1.26.0-X:nocoverageredesign"),
            Some((1, 26))
        );
        assert_eq!(version_numbers("devel +abc"), None);
    }
}
