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
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::path::Path;

use anyhow::{bail, Context, Result};
use gopclntab::{ElfPclntab, GoPclntab};
use object::elf::{
    FileHeader64, Sym64, PN_XNUM, SHN_XINDEX, SHT_DYNSYM, SHT_STRTAB, SHT_SYMTAB, SHT_SYMTAB_SHNDX,
};
use object::read::elf::{FileHeader, SectionHeader, SectionTable};
use object::read::{ReadCache, SectionIndex};
use object::{Endianness, Object, ObjectKind, ObjectSection, ObjectSegment};

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

/// What a program must be built for to be read: this machine's architecture,
/// x86-64 or arm64.
const NATIVE_ARCHITECTURE: object::Architecture = if cfg!(target_arch = "aarch64") {
    object::Architecture::Aarch64
} else {
    object::Architecture::X86_64
};

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

/// The most sections a file may state for this reader to look through them.
/// A Go program has a few dozen.
const SECTIONS_MAX: u16 = 128;
/// The most bytes, in all, that a file's headers may state for its symbol and
/// string tables, `.gopclntab` and `.go.buildinfo`.
const WHOLE_READS_MAX: u64 = 256 << 20;

type Sections<'data, 'file> =
    SectionTable<'data, FileHeader64<Endianness>, &'data ReadCache<&'file File>>;

/// The section header table of the 64-bit ELF file behind `data`, read as
/// `context::recipe` reads one: the file header, then at most
/// [`SECTIONS_MAX`] headers. Sizes that a file's headers state are checked
/// before anything is read by them.
fn sections<'data, 'file>(
    data: &'data ReadCache<&'file File>,
) -> Result<(Endianness, Sections<'data, 'file>)> {
    let header = FileHeader64::<Endianness>::parse(data).context("not a 64-bit ELF file")?;
    let endian = header.endian().context("not a 64-bit ELF file")?;
    // Extended numbering (a count kept in section 0) is for more sections or
    // segments than a Go program has.
    if header.e_phnum(endian) == PN_XNUM
        || header.e_shstrndx(endian) == SHN_XINDEX
        || (header.e_shnum(endian) == 0 && header.e_shoff(endian) != 0)
        || header.e_shnum(endian) > SECTIONS_MAX
    {
        bail!("it states more sections than this reader looks through");
    }
    let sections = header
        .sections(endian, data)
        .context("reading its section headers")?;
    Ok((endian, sections))
}

/// Refuse a file whose headers state more than [`WHOLE_READS_MAX`] bytes for
/// its symbol tables and Go tables.
fn check_stated_sizes(file: &File) -> Result<()> {
    let cache = ReadCache::new(file);
    let (endian, sections) = sections(&cache)?;
    let whole = sections
        .iter()
        .filter(|section| {
            matches!(
                section.sh_type(endian),
                SHT_SYMTAB | SHT_DYNSYM | SHT_SYMTAB_SHNDX | SHT_STRTAB
            ) || matches!(
                sections.section_name(endian, *section),
                Ok(b".gopclntab" | b".data.rel.ro.gopclntab" | b".go.buildinfo")
            )
        })
        .fold(0u64, |sum, section| {
            sum.saturating_add(section.sh_size(endian))
        });
    if whole > WHOLE_READS_MAX {
        bail!("it states {whole} bytes of symbol tables and Go tables");
    }
    Ok(())
}

/// The most of `/proc/<pid>/maps` that is read: the process chooses how long
/// its map is.
const MAPS_MAX: u64 = 64 << 20;

/// The text of the file at `path`, refused past `cap` bytes. Bytes that are not
/// UTF-8 cost their own place in the text, not the read.
fn text_capped(path: &Path, cap: u64) -> Result<String> {
    use std::io::Read as _;
    let mut bytes = Vec::new();
    File::open(path)?.take(cap + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > cap {
        bail!("it is larger than {cap} bytes");
    }
    Ok(String::from_utf8(bytes)
        .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned()))
}

/// Whether the executable at `path` is a Go program: it has Go's build
/// information (`.go.buildinfo`, Go 1.18+) or a function table of its own.
/// Whether it can be read is [`GoProcess::open`]'s to say. Only the file's
/// header and section headers are read.
pub fn is_go(path: &Path) -> bool {
    let Ok(file) = File::open(path) else {
        return false;
    };
    let cache = ReadCache::new(&file);
    sections(&cache).is_ok_and(|(endian, sections)| {
        sections.section_by_name(endian, b".go.buildinfo").is_some()
            || sections.section_by_name(endian, b".gopclntab").is_some()
    })
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
        let file = File::open(&exe_path).with_context(|| format!("opening {exe}"))?;
        check_stated_sizes(&file).with_context(|| format!("{exe} is not read"))?;
        // Through the handle that was checked: once the process execs, its
        // `exe` link names another file.
        let elf = ElfPclntab::from_path(format!("/proc/self/fd/{}", file.as_raw_fd()))
            .with_context(|| format!("reading the Go function table of {exe}"))?
            .with_context(|| {
                if is_go(&exe_path) {
                    format!(
                        "{exe} is a Go program whose function table cannot be read: where its \
                         code starts could not be found and checked"
                    )
                } else {
                    format!("{exe} is not a Go program")
                }
            })?;
        let cache = ReadCache::new(&file);
        let obj = object::File::parse(&cache).context("parsing the program's ELF")?;
        if obj.architecture() != NATIVE_ARCHITECTURE {
            bail!("only Go programs of this machine's architecture ({NATIVE_ARCHITECTURE:?}) are supported");
        }
        let version = build_version(&obj).context("finding the Go version in .go.buildinfo")?;
        let layout = match version_numbers(&version).and_then(|(a, b)| offsets::for_version(a, b)) {
            Some(layout) => layout,
            None => bail!(
                "built with {version}: there are no bindings for its runtime's layout \
                 (scripts/generate_go_bindings.py makes them)"
            ),
        };
        let maps = text_capped(&proc_dir.join("maps"), MAPS_MAX)
            .with_context(|| format!("reading /proc/{pid}/maps"))?;
        let bias = load_bias(&obj, &parse_maps(&maps), &exe);
        let inner = ProcessMemory::open_path(&proc_dir.join("mem")).with_context(|| {
            format!(
                "opening /proc/{pid}/mem: reading a process's memory needs the same user as the \
                 process (any other, root included, needs CAP_SYS_PTRACE)"
            )
        })?;
        let (globals, found_by) = if elf.has_symtab {
            (globals_by_symbols(&cache, bias), FoundBy::Symbols)
        } else {
            (
                globals_by_code(&obj, &file, &elf.table, &layout, bias),
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

fn globals_by_symbols(data: &ReadCache<&File>, bias: u64) -> HashMap<Global, u64> {
    let tables = || {
        let (endian, sections) = sections(data).ok()?;
        let symtab = sections
            .iter()
            .find(|section| section.sh_type(endian) == SHT_SYMTAB)?;
        let strtab = sections
            .section(SectionIndex(symtab.sh_link(endian) as usize))
            .ok()
            .filter(|section| section.sh_type(endian) == SHT_STRTAB)?;
        let symbols = symtab.data_as_array(endian, data).ok()?;
        // The names are looked up in one read of the string table.
        let names = strtab.data(endian, data).ok()?;
        Some((endian, symbols, names))
    };
    tables()
        .map(|(endian, symbols, names)| globals_in(symbols, names, endian, bias))
        .unwrap_or_default()
}

/// The address of each symbol of `symbols` that has a global's name, which
/// ends at its NUL in `names`.
fn globals_in(
    symbols: &[Sym64<Endianness>],
    names: &[u8],
    endian: Endianness,
    bias: u64,
) -> HashMap<Global, u64> {
    symbols
        .iter()
        .filter_map(|sym| {
            let name = names.get(sym.st_name.get(endian) as usize..)?;
            let rule = RULES.iter().find(|rule| {
                name.strip_prefix(rule.symbol.as_bytes())
                    .is_some_and(|rest| rest.first() == Some(&0))
            })?;
            Some((rule.global, sym.st_value.get(endian).wrapping_add(bias)))
        })
        .collect()
}

/// The most of a function's code that is read for its first load.
const MAX_FUNCTION_READ: u64 = 4096;

/// The globals of a stripped binary, from the code of the functions that use
/// them: each function's first [`MAX_FUNCTION_READ`] bytes are read from
/// `file`, and nothing else of the code.
fn globals_by_code<'a, R: object::ReadRef<'a>>(
    obj: &object::File<'a, R>,
    file: &File,
    table: &GoPclntab,
    layout: &Layout,
    bias: u64,
) -> HashMap<Global, u64> {
    let mut globals = HashMap::new();
    let Some(text) = obj.section_by_name(".text") else {
        return globals;
    };
    let Some((text_offset, text_size)) = text.file_range() else {
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
        let Some(start) = entry.checked_sub(text.address()).filter(|s| *s < text_size) else {
            continue;
        };
        let mut body = vec![0u8; size.min(MAX_FUNCTION_READ).min(text_size - start) as usize];
        if file.read_exact_at(&mut body, text_offset + start).is_err() {
            continue;
        }
        let allowed = |a: u64| match (rule.only_noptrdata, noptrdata) {
            (true, Some((s, e))) => a >= s && a < e,
            _ => data.iter().any(|&(s, e)| a >= s && a < e),
        };
        let target = match obj.architecture() {
            object::Architecture::Aarch64 => first_adrp_reference(&body, entry, rule.lea, allowed),
            _ => first_rip_relative(&body, entry, rule.lea, allowed),
        };
        if let Some(target) = target {
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
    version_in(section.data().context("reading .go.buildinfo")?)
}

/// The same from the section's bytes, or from its head alone: the version is
/// the first string in it.
pub(crate) fn version_in(data: &[u8]) -> Result<String> {
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

/// (major, minor) of a released Go as the linker writes it: `go1.26` or
/// `go1.26.7`. Anything else is refused: a release candidate or beta
/// (`go1.26rc1`), an experiment build (`go1.26.0-X:...`), a development
/// build. Their runtimes can differ from the release the bindings are of.
pub(crate) fn version_numbers(version: &str) -> Option<(u32, u32)> {
    let mut parts = version.strip_prefix("go")?.split('.');
    let number = |p: &str| {
        (!p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
            .then(|| p.parse().ok())
            .flatten()
    };
    let major = number(parts.next()?)?;
    let minor = number(parts.next()?)?;
    if let Some(patch) = parts.next() {
        number(patch)?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor))
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

/// The address the first 8-byte load in `code` reads, among those `allowed`
/// accepts, or with `lea` the first address taken instead. arm64 reaches a
/// global with `adrp xN, page` and, right after it, `ldr xM, [xN, #low]`, or
/// `add xM, xN, #low` to have its address: a load if an 8-byte load through
/// xM follows (an atomic load has no other form), else an address taken, as
/// for a lock passed to `lock`.
fn first_adrp_reference(
    code: &[u8],
    entry: u64,
    lea: bool,
    allowed: impl Fn(u64) -> bool,
) -> Option<u64> {
    let words: Vec<u32> = code
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| u32::from_le_bytes(*c))
        .collect();
    // An 8-byte load from register `base` itself: ldar, ldr, ldp.
    let loads_from = |word: u32, base: u32| {
        (word >> 5) & 31 == base
            && (word & 0xffff_fc00 == 0xc8df_fc00
                || word & 0xffff_fc00 == 0xf940_0000
                || word & 0xffff_8000 == 0xa940_0000)
    };
    words.windows(2).enumerate().find_map(|(i, w)| {
        let (adrp, next) = (w[0], w[1]);
        if adrp & 0x9f00_0000 != 0x9000_0000 || (next >> 5) & 31 != adrp & 31 {
            return None;
        }
        let low = u64::from((next >> 10) & 0xfff);
        let low = match next & 0xffc0_0000 {
            0x9100_0000 => {
                let then = words.get(i + 2).copied().unwrap_or(0);
                if loads_from(then, next & 31) == lea {
                    return None;
                }
                low
            }
            0xf940_0000 if !lea => low * 8,
            _ => return None,
        };
        // A signed count of pages: immhi in bits 5-23, immlo in bits 29-30.
        let pages = ((adrp >> 5) & 0x7_ffff) << 2 | (adrp >> 29) & 3;
        let pages = i64::from((pages << 11) as i32 >> 11);
        let at = entry.wrapping_add(i as u64 * 4);
        let target = (at & !0xfff).wrapping_add((pages << 12) as u64) + low;
        allowed(target).then_some(target)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_first_adrp_reference() {
        let code =
            |words: &[u32]| -> Vec<u8> { words.iter().flat_map(|w| w.to_le_bytes()).collect() };
        let find = |words: &[u32], lea| first_adrp_reference(&code(words), 0x1000, lea, |_| true);
        // At 0x1000, adrp x0, +2 pages.
        let adrp = 0xd000_0000;
        // ldr x1, [x0, #0x18]: a load.
        assert_eq!(find(&[adrp, 0xf940_0c01], false), Some(0x3018));
        assert_eq!(find(&[adrp, 0xf940_0c01], true), None);
        // add x1, x0, #0x18, then ldar x2, [x1]: a load.
        let add = 0x9100_6001;
        assert_eq!(find(&[adrp, add, 0xc8df_fc22], false), Some(0x3018));
        // The same then ldp x2, x3, [x1], and ldr x2, [x1].
        assert_eq!(find(&[adrp, add, 0xa940_0c22], false), Some(0x3018));
        assert_eq!(find(&[adrp, add, 0xf940_0022], false), Some(0x3018));
        // ldar w2, [x1] is 4 bytes, and a call takes the address.
        assert_eq!(find(&[adrp, add, 0x88df_fc22], false), None);
        assert_eq!(find(&[adrp, add, 0x9400_0010], false), None);
        assert_eq!(find(&[adrp, add, 0x9400_0010], true), Some(0x3018));
        // A load through another register is not this pair's.
        assert_eq!(find(&[adrp, 0xf940_0c21], false), None);
        // A refused address is passed over.
        let refused =
            first_adrp_reference(&code(&[adrp, 0xf940_0c01]), 0x1000, false, |a| a != 0x3018);
        assert_eq!(refused, None);
    }

    /// Every global the stripped-binary rules find must be where the symbol
    /// table says, in a program Go builds for each architecture: the code is
    /// only read, so no such machine is needed. Needs a Go with bindings;
    /// without one it says so and passes.
    #[test]
    fn the_code_rules_agree_with_the_symbols() {
        let workload = concat!(env!("CARGO_MANIFEST_DIR"), "/go-profile/e2e/workload");
        for arch in ["amd64", "arm64"] {
            let dir = tempfile::tempdir().unwrap();
            let bin = dir.path().join("workload");
            let built = std::process::Command::new("go")
                .args(["build", "-o"])
                .arg(&bin)
                .arg(".")
                .current_dir(workload)
                .env("GOOS", "linux")
                .env("GOARCH", arch)
                .env("CGO_ENABLED", "0")
                .status();
            if !built.is_ok_and(|s| s.success()) {
                eprintln!("no Go that builds the workload: skipped");
                return;
            }
            let file = File::open(&bin).unwrap();
            let cache = ReadCache::new(&file);
            let obj = object::File::parse(&cache).unwrap();
            let version = build_version(&obj).unwrap();
            let layout = version_numbers(&version)
                .and_then(|(major, minor)| offsets::for_version(major, minor));
            let Some(layout) = layout else {
                eprintln!("no bindings for {version}: skipped");
                return;
            };
            let elf = ElfPclntab::from_path(bin.to_str().unwrap())
                .unwrap()
                .unwrap();
            let by_code = globals_by_code(&obj, &file, &elf.table, &layout, 0);
            let by_symbols = globals_by_symbols(&cache, 0);
            assert_eq!(by_symbols.len(), RULES.len(), "{arch}: {by_symbols:?}");
            assert_eq!(by_code, by_symbols, "{arch} {version}");
        }
    }

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
    fn a_text_is_read_up_to_its_cap() {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"0-1 r-xp /a\xff\n").unwrap();
        assert_eq!(
            text_capped(file.path(), 13).unwrap(),
            "0-1 r-xp /a\u{fffd}\n"
        );
        assert!(text_capped(file.path(), 12).is_err());
    }

    #[test]
    fn versions() {
        assert_eq!(version_numbers("go1.26.7"), Some((1, 26)));
        assert_eq!(version_numbers("go1.26"), Some((1, 26)));
        // Not releases: refused.
        assert_eq!(version_numbers("go1.26rc1"), None);
        assert_eq!(version_numbers("go1.27beta1"), None);
        assert_eq!(version_numbers("go1.26.0-X:nocoverageredesign"), None);
        assert_eq!(version_numbers("devel +abc"), None);
        assert_eq!(version_numbers("go1.26.7.1"), None);
    }
}
