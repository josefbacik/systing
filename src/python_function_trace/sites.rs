//! Where in an interpreter binary the function trace attaches, found from the
//! file alone.
//!
//! The dispatch sites are the handlers of a few opcodes in CPython's bytecode
//! loop. The loop reaches a handler by an indirect jump through a table of 256
//! addresses (`opcode_targets` in `_PyEval_EvalFrameDefault`), so, unlike a
//! function the compiler may inline, every handler has an address that every
//! frame passes through, and the table says what it is. The table is a static
//! local: its symbol is there in an unstripped build and gone in a stripped
//! one, so it is found by shape — 256 consecutive pointers into executable
//! code, most of them into `_PyEval_EvalFrameDefault` itself — and a symbol,
//! where there is one, only breaks a tie.

use anyhow::{anyhow, bail, Context, Result};
use object::read::ReadCache;
use object::{
    Object, ObjectSection, ObjectSegment, ObjectSymbol, RelocationFlags, SectionFlags, SectionKind,
};
use std::collections::HashMap;
use std::fs::File;
use std::path::Path;

/// What an event at a site means. The values are the BPF side's `pyft_kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Kind {
    /// A frame starts or resumes running.
    Enter = 1,
    /// A frame returns.
    Exit = 2,
    /// A generator or coroutine frame suspends.
    Yield = 3,
    /// An exception handler starts running in a frame: every frame above it
    /// is gone.
    Sync = 4,
    /// `_PyEval_EvalFrameDefault` returned; paired by stack pointer.
    ExitSp = 5,
}

impl Kind {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Kind::Enter,
            2 => Kind::Exit,
            3 => Kind::Yield,
            4 => Kind::Sync,
            5 => Kind::ExitSp,
            _ => return None,
        })
    }
}

/// Where the BPF program finds the frame. The values are `pyft_frame_source`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameSource {
    ThreadState = 0,
    Arg2 = 1,
    None = 2,
}

/// One place to attach a probe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Site {
    pub name: String,
    pub kind: Kind,
    pub source: FrameSource,
    /// Offset in the file, as `perf_event_open` takes it.
    pub file_offset: u64,
    pub retprobe: bool,
}

impl Site {
    /// The attach cookie the BPF program decodes.
    pub fn cookie(&self) -> u64 {
        self.kind as u64 | (self.source as u64) << 8
    }
}

/// The opcodes whose handlers are sites, by CPython minor version. The numbers
/// are fixed for a minor version (they are part of the bytecode's magic
/// number); they are `opcode.opmap`, `opcode._specialized_opmap` and the
/// instrumented opcodes of each interpreter.
///
/// - `RESUME` is the first thing a function's body runs and the first thing a
///   generator or coroutine runs after each `yield`/`await`; the interpreter
///   rewrites it to `RESUME_CHECK` once warm (3.13+) and to
///   `INSTRUMENTED_RESUME` under `sys.monitoring`.
/// - `PUSH_EXC_INFO`, `CLEANUP_THROW` and `END_ASYNC_FOR` are where exception
///   handlers begin: the one place a frame that caught an exception is known
///   to be running again, with every frame the exception unwound gone.
fn opcodes(minor: i32) -> Option<&'static [(&'static str, u8, Kind)]> {
    use Kind::*;
    Some(match minor {
        12 => &[
            ("RESUME", 151, Enter),
            ("INSTRUMENTED_RESUME", 240, Enter),
            ("RETURN_VALUE", 83, Exit),
            ("RETURN_CONST", 121, Exit),
            ("INSTRUMENTED_RETURN_VALUE", 242, Exit),
            ("INSTRUMENTED_RETURN_CONST", 247, Exit),
            ("YIELD_VALUE", 150, Yield),
            ("INSTRUMENTED_YIELD_VALUE", 243, Yield),
            ("PUSH_EXC_INFO", 35, Sync),
            ("CLEANUP_THROW", 55, Sync),
            ("END_ASYNC_FOR", 54, Sync),
        ],
        13 => &[
            ("RESUME", 149, Enter),
            ("RESUME_CHECK", 207, Enter),
            ("INSTRUMENTED_RESUME", 236, Enter),
            ("RETURN_VALUE", 36, Exit),
            ("RETURN_CONST", 103, Exit),
            ("INSTRUMENTED_RETURN_VALUE", 239, Exit),
            ("INSTRUMENTED_RETURN_CONST", 240, Exit),
            ("YIELD_VALUE", 118, Yield),
            ("INSTRUMENTED_YIELD_VALUE", 241, Yield),
            ("PUSH_EXC_INFO", 33, Sync),
            ("CLEANUP_THROW", 8, Sync),
            ("END_ASYNC_FOR", 10, Sync),
        ],
        14 => &[
            ("RESUME", 128, Enter),
            ("RESUME_CHECK", 196, Enter),
            ("INSTRUMENTED_RESUME", 245, Enter),
            ("RETURN_VALUE", 35, Exit),
            ("INSTRUMENTED_RETURN_VALUE", 246, Exit),
            ("YIELD_VALUE", 120, Yield),
            ("INSTRUMENTED_YIELD_VALUE", 247, Yield),
            ("PUSH_EXC_INFO", 32, Sync),
            ("CLEANUP_THROW", 7, Sync),
            ("END_ASYNC_FOR", 68, Sync),
            ("INSTRUMENTED_END_ASYNC_FOR", 248, Sync),
        ],
        _ => return None,
    })
}

/// The opcode numbers a minor version leaves unassigned: in a build of that
/// version these, and only these, slots of the dispatch table go to the
/// unknown-opcode handler. Read from `dis._all_opmap` of 3.12.3, 3.13.15 and
/// 3.14.7, as inclusive ranges.
fn unassigned(minor: i32) -> Option<&'static [(u8, u8)]> {
    Some(match minor {
        12 => &[(169, 170), (177, 236), (255, 255)],
        13 => &[(119, 148), (223, 235), (255, 255)],
        14 => &[(121, 127), (212, 233)],
        _ => return None,
    })
}

/// Whether the dispatch sites are known for this version.
pub fn dispatch_supported(major: i32, minor: i32) -> bool {
    major == 3 && opcodes(minor).is_some()
}

const TABLE_LEN: usize = 256;
/// Of the 256 handlers, how many must lie in `_PyEval_EvalFrameDefault`
/// itself. The rest are the rare ones a compiler moves to the function's cold
/// part, outside the symbol's range (75 of 256 in Ubuntu's 3.12).
const MIN_IN_FUNCTION: usize = 100;

/// The bounds on what reading one interpreter file may cost; a file over any
/// of them is refused. The file is the traced process's choice, and the tool
/// runs as root. An interpreter has about 40 sections, a few executable ones,
/// a few MiB of data and relocations, and about 18,000 relative relocations.
const MAX_FILE_BYTES: u64 = 512 << 20;
const MAX_SECTIONS: usize = 128;
const MAX_EXEC_RANGES: usize = 64;
/// Data sections scanned for the table, all together.
const MAX_SCANNED_BYTES: u64 = 64 << 20;
/// The dynamic relocation sections, all together: the parser reads each one
/// whole. (Others, as `--emit-relocs` leaves, are never read.)
const MAX_RELOCATION_BYTES: u64 = 64 << 20;
/// Distinct runs that pass for the table; an interpreter has one.
const MAX_CANDIDATES: usize = 8;
const MAX_RELATIVE_RELOCATIONS: usize = 1 << 20;
const SHT_RELA: u32 = 4;
const SHT_REL: u32 = 9;

const R_X86_64_RELATIVE: u32 = 8;
const R_AARCH64_RELATIVE: u32 = 1027;
const SHF_EXECINSTR: u64 = 4;

/// How the dispatch table was told from its neighbours.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FoundBy {
    /// The only run of 256 code pointers that fits.
    Shape,
    /// Several fit; the one a symbol names.
    Symbol,
}

#[derive(Clone, Debug)]
pub struct DispatchTable {
    pub address: u64,
    pub targets: Vec<u64>,
    pub found_by: FoundBy,
}

/// What the function trace needs to know of one interpreter binary.
#[derive(Clone, Debug)]
pub struct Interpreter {
    /// `_PyEval_EvalFrameDefault`: address and size.
    pub eval_frame_default: (u64, u64),
    pub table: Option<DispatchTable>,
    /// Why there is no table, for the message that says so.
    pub no_table: Option<String>,
    /// `Py_Version` (`PY_VERSION_HEX`, 3.11+), as the file holds it.
    pub py_version: Option<u32>,
    /// `_Py_DebugOffsets.free_threaded` at the start of `_PyRuntime` (3.13+).
    pub free_threaded: Option<bool>,
    /// PT_LOAD segments: (address, file size, file offset).
    segments: Vec<(u64, u64, u64)>,
}

impl Interpreter {
    /// Reads `path`; `None` when it does not define `_PyEval_EvalFrameDefault`
    /// (a launcher whose interpreter is in libpython).
    pub fn open(path: &Path) -> Result<Option<Self>> {
        let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
        Self::from_file(&file, path)
    }

    /// [`Interpreter::open`] on a file already open; `path` names it in
    /// errors.
    pub fn from_file(file: &File, path: &Path) -> Result<Option<Self>> {
        let size = file
            .metadata()
            .with_context(|| format!("stat {}", path.display()))?
            .len();
        if size > MAX_FILE_BYTES {
            bail!(
                "{} is refused: {size} bytes, more than {MAX_FILE_BYTES}",
                path.display()
            );
        }
        // The section count, from the raw header, before the parser reads
        // the section headers and symbol tables.
        check_section_count(file).with_context(|| format!("{} is refused", path.display()))?;
        let cache = ReadCache::new(file);
        let elf = object::File::parse(&cache)
            .with_context(|| format!("{} is not an object file", path.display()))?;
        check_bounds(&elf).with_context(|| format!("{} is refused", path.display()))?;

        let Some(eval_frame_default) = find_function(&elf, "_PyEval_EvalFrameDefault") else {
            return Ok(None);
        };
        let segments: Vec<(u64, u64, u64)> = elf
            .segments()
            .map(|s| {
                let (offset, size) = s.file_range();
                (s.address(), size, offset)
            })
            .collect();
        let (table, no_table) = match find_table(&elf, eval_frame_default) {
            Ok(table) => (Some(table), None),
            Err(e) => (None, Some(format!("{e:#}"))),
        };
        let read = |name: &str, at: u64, len: usize| -> Option<Vec<u8>> {
            let symbol = find_symbol(&elf, name)?;
            let offset = offset_in(&segments, symbol.checked_add(at)?)?;
            object::ReadRef::read_bytes_at(&cache, offset, len as u64)
                .ok()
                .map(<[u8]>::to_vec)
        };
        let py_version =
            read("Py_Version", 0, 4).map(|b| u32::from_le_bytes(b[..4].try_into().unwrap()));
        // The debug offsets begin with the cookie "xdebugpy", then the version
        // and the free-threaded flag, eight bytes each.
        let free_threaded = read("_PyRuntime", 0, 24)
            .filter(|b| &b[..8] == b"xdebugpy")
            .map(|b| u64::from_le_bytes(b[16..24].try_into().unwrap()) != 0);
        Ok(Some(Self {
            eval_frame_default,
            table,
            no_table,
            py_version,
            free_threaded,
            segments,
        }))
    }

    fn file_offset(&self, address: u64) -> Result<u64> {
        offset_in(&self.segments, address)
            .ok_or_else(|| anyhow!("address {address:#x} is in no loaded segment of the file"))
    }

    /// Refuses a file that is not the build of `major.minor` the opcode lists
    /// are for: another version or a pre-release by its own `Py_Version`, or a
    /// free-threaded build, whose objects have another layout.
    pub fn check_build(&self, major: i32, minor: i32, dispatch: bool) -> Result<()> {
        if self.free_threaded == Some(true) {
            bail!("a free-threaded build: not supported (its objects have another layout)");
        }
        let Some(hex) = self.py_version else {
            if dispatch {
                bail!("the file has no Py_Version to check the opcode numbers against");
            }
            return Ok(());
        };
        let (file_major, file_minor) = ((hex >> 24) as i32, ((hex >> 16) & 0xff) as i32);
        if (file_major, file_minor) != (major, minor) {
            bail!(
                "the file says Python {file_major}.{file_minor} (Py_Version {hex:#010x}), \
                 discovery said {major}.{minor}"
            );
        }
        if dispatch && (hex >> 4) & 0xf != 0xf {
            bail!(
                "a pre-release of Python {major}.{minor} (Py_Version {hex:#010x}): its opcode \
                 numbers may not be the release's"
            );
        }
        Ok(())
    }

    /// The sites that see every frame, trampolines or not: the handlers of
    /// the entry, exit, yield and exception-handler opcodes.
    pub fn dispatch_sites(&self, major: i32, minor: i32) -> Result<Vec<Site>> {
        let ops = (major == 3)
            .then(|| opcodes(minor))
            .flatten()
            .ok_or_else(|| anyhow!("no opcode numbers for Python {major}.{minor}"))?;
        let table = self.table.as_ref().ok_or_else(|| {
            anyhow!(
                "no dispatch table: {}",
                self.no_table.as_deref().unwrap_or("not found")
            )
        })?;

        // Opcodes the build does not implement all jump to one handler, and
        // which those are is fixed for a minor version: the slots on the
        // table's most used target must be exactly the version's unassigned
        // numbers, or the numbers (or the table) are not this build's.
        let mut uses: HashMap<u64, usize> = HashMap::new();
        for t in &table.targets {
            *uses.entry(*t).or_default() += 1;
        }
        let unknown = uses
            .iter()
            .max_by_key(|(t, n)| (**n, std::cmp::Reverse(**t)))
            .filter(|(_, n)| **n > 1)
            .map(|(t, _)| *t);
        if let Some(ranges) = unassigned(minor) {
            let expected: Vec<usize> = ranges
                .iter()
                .flat_map(|&(a, b)| a as usize..=b as usize)
                .collect();
            let found: Vec<usize> = (0..TABLE_LEN)
                .filter(|&i| Some(table.targets[i]) == unknown)
                .collect();
            if found != expected {
                bail!(
                    "the table's unknown-opcode slots ({} of them) are not Python \
                     {major}.{minor}'s {}: the opcode numbers are not this build's",
                    found.len(),
                    expected.len()
                );
            }
        }

        let mut sites: Vec<Site> = Vec::new();
        for (name, number, kind) in ops {
            let target = table.targets[*number as usize];
            if Some(target) == unknown {
                bail!(
                    "opcode {name} ({number}) dispatches to the unknown-opcode handler: the \
                     opcode numbers of Python {major}.{minor} are not this build's"
                );
            }
            let file_offset = self.file_offset(target)?;
            if let Some(same) = sites.iter().find(|s| s.file_offset == file_offset) {
                if same.kind != *kind {
                    bail!("{name} and {} share a handler but not a meaning", same.name);
                }
                continue;
            }
            sites.push(Site {
                name: name.to_string(),
                kind: *kind,
                source: FrameSource::ThreadState,
                file_offset,
                retprobe: false,
            });
        }
        Ok(sites)
    }

    /// The sites that see every frame only while the interpreter's frame
    /// evaluator is replaced (perf trampolines, a PEP 523 evaluator): entry to
    /// and return from `_PyEval_EvalFrameDefault`.
    pub fn eval_frame_sites(&self) -> Result<Vec<Site>> {
        let file_offset = self.file_offset(self.eval_frame_default.0)?;
        Ok(vec![
            Site {
                name: "_PyEval_EvalFrameDefault".to_string(),
                kind: Kind::Enter,
                source: FrameSource::Arg2,
                file_offset,
                retprobe: false,
            },
            Site {
                name: "_PyEval_EvalFrameDefault (return)".to_string(),
                kind: Kind::ExitSp,
                source: FrameSource::None,
                file_offset,
                retprobe: true,
            },
        ])
    }
}

/// Refuses a 64-bit ELF file whose header gives more than [`MAX_SECTIONS`]
/// sections (counting the extended form, where the count is in section 0),
/// read straight from the file so that nothing is parsed first.
fn check_section_count(file: &File) -> Result<()> {
    use std::os::unix::fs::FileExt as _;
    let mut header = [0u8; 64];
    file.read_exact_at(&mut header, 0)
        .context("cannot read the ELF header")?;
    if &header[..4] != b"\x7fELF" || header[4] != 2 || header[5] != 1 {
        bail!("not a little-endian 64-bit ELF file");
    }
    let shoff = u64::from_le_bytes(header[40..48].try_into().unwrap());
    let shnum = u64::from(u16::from_le_bytes(header[60..62].try_into().unwrap()));
    let count = if shnum == 0 && shoff != 0 {
        // SHN_UNDEF: the count is section 0's sh_size.
        let mut size = [0u8; 8];
        file.read_exact_at(
            &mut size,
            shoff.checked_add(32).context("bad section offset")?,
        )
        .context("cannot read section 0")?;
        u64::from_le_bytes(size)
    } else {
        shnum
    };
    if count > MAX_SECTIONS as u64 {
        bail!("{count} sections, more than {MAX_SECTIONS}");
    }
    Ok(())
}

/// The file offset of `address` in one of `segments`.
fn offset_in(segments: &[(u64, u64, u64)], address: u64) -> Option<u64> {
    segments
        .iter()
        .find(|(start, size, _)| address >= *start && address - *start < *size)
        .and_then(|(start, _, offset)| (address - start).checked_add(*offset))
}

/// Refuses a file whose shape would make reading it cost more than an
/// interpreter's does (see [`MAX_SECTIONS`]).
fn check_bounds<'d, R: object::ReadRef<'d>>(elf: &object::File<'d, R>) -> Result<()> {
    check_bounds_with(elf, MAX_RELOCATION_BYTES)
}

fn check_bounds_with<'d, R: object::ReadRef<'d>>(
    elf: &object::File<'d, R>,
    max_relocation_bytes: u64,
) -> Result<()> {
    let sections = elf.sections().count();
    if sections > MAX_SECTIONS {
        bail!("{sections} sections, more than {MAX_SECTIONS}");
    }
    // A 64-bit ELF only: the interpreters this traces are, and the bound
    // below reads the 64-bit section headers.
    let object::File::Elf64(elf) = elf else {
        bail!("not a 64-bit ELF file");
    };
    use object::read::elf::SectionHeader as _;
    let endian = elf.endian();
    // The parser reads the relocation sections linked to the dynamic symbol
    // table by its section index. Every interpreter has one; a file without
    // one is refused, since the parser would then read those linked to index
    // 0.
    let dynsym = elf.elf_dynamic_symbol_table().section();
    if dynsym.0 == 0 {
        bail!("no dynamic symbol table");
    }
    let mut relocation_bytes = 0u64;
    for section in elf.sections() {
        let header = section.elf_section_header();
        if matches!(header.sh_type(endian), SHT_RELA | SHT_REL)
            && header.sh_link(endian) as usize == dynsym.0
        {
            relocation_bytes = relocation_bytes.saturating_add(header.sh_size(endian));
        }
    }
    if relocation_bytes > max_relocation_bytes {
        bail!("{relocation_bytes} bytes of relocations, more than {max_relocation_bytes}");
    }
    Ok(())
}

fn find_symbol<'d, R: object::ReadRef<'d>>(elf: &object::File<'d, R>, name: &str) -> Option<u64> {
    elf.dynamic_symbols()
        .chain(elf.symbols())
        .find(|s| s.name() == Ok(name) && s.address() != 0)
        .map(|s| s.address())
}

fn find_function<'d, R: object::ReadRef<'d>>(
    elf: &object::File<'d, R>,
    name: &str,
) -> Option<(u64, u64)> {
    elf.dynamic_symbols()
        .chain(elf.symbols())
        .find(|s| s.name() == Ok(name) && s.address() != 0)
        .map(|s| (s.address(), s.size()))
}

fn find_table<'d, R: object::ReadRef<'d>>(
    elf: &object::File<'d, R>,
    (func, func_size): (u64, u64),
) -> Result<DispatchTable> {
    if func_size == 0 {
        bail!("_PyEval_EvalFrameDefault has no size");
    }
    // The executable ranges, merged and sorted, so a word is looked up in a
    // short list.
    let mut exec: Vec<(u64, u64)> = elf
        .sections()
        .filter(|s| matches!(s.flags(), SectionFlags::Elf { sh_flags } if sh_flags & SHF_EXECINSTR != 0))
        .filter(|s| s.size() > 0)
        .filter_map(|s| Some((s.address(), s.address().checked_add(s.size())?)))
        .collect();
    exec.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for (a, b) in exec {
        match merged.last_mut() {
            Some(last) if a <= last.1 => last.1 = last.1.max(b),
            _ => merged.push((a, b)),
        }
    }
    if merged.len() > MAX_EXEC_RANGES {
        bail!(
            "{} executable ranges, more than {MAX_EXEC_RANGES}",
            merged.len()
        );
    }
    let in_exec = |v: u64| {
        let i = merged.partition_point(|(a, _)| *a <= v);
        i > 0 && v < merged[i - 1].1
    };
    let in_func = |v: u64| v >= func && v - func < func_size;

    // A position-independent build keeps the table as relative relocations:
    // the word at the place holds the link-time address (RELR, and most
    // linkers for RELA too) or nothing, with the address in the addend.
    let mut relative: HashMap<u64, u64> = HashMap::new();
    if let Some(relocations) = elf.dynamic_relocations() {
        for (place, r) in relocations {
            let RelocationFlags::Elf { r_type } = r.flags() else {
                continue;
            };
            if r_type != R_X86_64_RELATIVE && r_type != R_AARCH64_RELATIVE {
                continue;
            }
            let addend = r.addend() as u64;
            if in_exec(addend) {
                if relative.len() >= MAX_RELATIVE_RELOCATIONS {
                    bail!("more than {MAX_RELATIVE_RELOCATIONS} relative relocations");
                }
                relative.insert(place, addend);
            }
        }
    }

    // A symbol for the table, where the build kept one
    // (`opcode_targets.1`, `_PyEval_EvalFrameDefault.opcode_targets`).
    let named: Option<u64> = elf
        .symbols()
        .find(|s| {
            s.size() == (TABLE_LEN * 8) as u64
                && s.name().is_ok_and(|n| n.contains("opcode_targets"))
        })
        .map(|s| s.address());

    let mut candidates: Vec<(u64, Vec<u64>)> = Vec::new();
    let mut scanned: u64 = 0;
    for section in elf.sections() {
        let data_kind = matches!(
            section.kind(),
            SectionKind::Data | SectionKind::ReadOnlyData | SectionKind::ReadOnlyDataWithRel
        );
        if !data_kind || section.size() < (TABLE_LEN * 8) as u64 || section.address() % 8 != 0 {
            continue;
        }
        scanned = scanned.saturating_add(section.size());
        if scanned > MAX_SCANNED_BYTES {
            bail!("more than {MAX_SCANNED_BYTES} bytes of data sections");
        }
        let Ok(data) = section.data() else { continue };
        let base = section.address();
        let words: Vec<u64> = data
            .as_chunks::<8>()
            .0
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let v = u64::from_le_bytes(*c);
                if in_exec(v) {
                    v
                } else {
                    relative
                        .get(&base.wrapping_add(i as u64 * 8))
                        .copied()
                        .unwrap_or(v)
                }
            })
            .collect();

        let mut i = 0;
        while i < words.len() {
            if !in_exec(words[i]) {
                i += 1;
                continue;
            }
            let start = i;
            while i < words.len() && in_exec(words[i]) {
                i += 1;
            }
            let run = &words[start..i];
            if run.len() < TABLE_LEN {
                continue;
            }
            // Every 256-word window of the run with enough handlers in the
            // function; the best of a run stands for it.
            let mut inside = run[..TABLE_LEN].iter().filter(|v| in_func(**v)).count();
            let mut best = (inside, 0usize, 1usize);
            for w in 1..=run.len() - TABLE_LEN {
                inside -= usize::from(in_func(run[w - 1]));
                inside += usize::from(in_func(run[w + TABLE_LEN - 1]));
                match inside.cmp(&best.0) {
                    std::cmp::Ordering::Greater => best = (inside, w, 1),
                    std::cmp::Ordering::Equal => best.2 += 1,
                    std::cmp::Ordering::Less => {}
                }
            }
            let run_start = base.wrapping_add(start as u64 * 8);
            let named_window = named
                .and_then(|a| a.checked_sub(run_start))
                .filter(|d| d % 8 == 0)
                .and_then(|d| usize::try_from(d / 8).ok())
                .filter(|w| w.checked_add(TABLE_LEN).is_some_and(|end| end <= run.len()));
            let window =
                named_window.or((best.0 >= MIN_IN_FUNCTION && best.2 == 1).then_some(best.1));
            if let Some(w) = window {
                let targets = run[w..w + TABLE_LEN].to_vec();
                // A post-link optimiser can leave two equal copies of the
                // table; they are one candidate.
                if !candidates.iter().any(|(_, t)| *t == targets) {
                    if candidates.len() == MAX_CANDIDATES {
                        bail!("more than {MAX_CANDIDATES} runs pass for the table");
                    }
                    candidates.push((run_start.wrapping_add(w as u64 * 8), targets));
                }
            }
        }
    }

    match (candidates.len(), named) {
        (0, _) => bail!(
            "no run of {TABLE_LEN} code pointers with at least {MIN_IN_FUNCTION} in \
             _PyEval_EvalFrameDefault (an interpreter built without computed gotos or with \
             the tail-calling interpreter has none; a post-link optimiser's split, with the \
             table's symbol stripped, can hide one)"
        ),
        (1, _) => {
            let (address, targets) = candidates.pop().unwrap();
            let found_by = if named == Some(address) {
                FoundBy::Symbol
            } else {
                FoundBy::Shape
            };
            Ok(DispatchTable {
                address,
                targets,
                found_by,
            })
        }
        (n, Some(named)) => candidates
            .into_iter()
            .find(|(a, _)| *a == named)
            .map(|(address, targets)| DispatchTable {
                address,
                targets,
                found_by: FoundBy::Symbol,
            })
            .ok_or_else(|| anyhow!("{n} candidate tables and none at the symbol's address")),
        (n, None) => bail!("{n} candidate tables and no symbol to choose by"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cookie_carries_the_kind_and_the_frame_source() {
        let site = Site {
            name: "RESUME".into(),
            kind: Kind::Enter,
            source: FrameSource::ThreadState,
            file_offset: 0,
            retprobe: false,
        };
        assert_eq!(site.cookie(), 1);
        let site = Site {
            kind: Kind::ExitSp,
            source: FrameSource::None,
            ..site
        };
        assert_eq!(site.cookie(), 5 | 2 << 8);
    }

    #[test]
    fn every_version_has_an_entry_an_exit_a_yield_and_a_handler_opcode() {
        for minor in [12, 13, 14] {
            let ops = opcodes(minor).unwrap();
            for kind in [Kind::Enter, Kind::Exit, Kind::Yield, Kind::Sync] {
                assert!(ops.iter().any(|(_, _, k)| *k == kind), "3.{minor} {kind:?}");
            }
            let mut numbers: Vec<u8> = ops.iter().map(|(_, n, _)| *n).collect();
            numbers.sort_unstable();
            numbers.dedup();
            assert_eq!(numbers.len(), ops.len(), "3.{minor}: a number twice");
        }
        assert!(opcodes(11).is_none());
        assert!(!dispatch_supported(2, 12));
    }

    /// The interpreters on this machine: in each that has a table, every
    /// site of its version resolves to a distinct offset inside the file and
    /// the build check passes; one with no table (a tail-calling build) is
    /// refused with a reason and not a panic. Locally a machine without any
    /// skips with a note; in CI (`CI` set) that is a failure, as pystacks'
    /// own tests have it.
    #[test]
    fn the_table_is_found_in_the_interpreters_installed_here() {
        let mut checked = 0;
        for (path, minor) in installed_interpreters() {
            let Some(interp) = Interpreter::open(Path::new(&path)).unwrap() else {
                continue;
            };
            let Some(table) = interp.table.as_ref() else {
                let e = interp.dispatch_sites(3, minor).unwrap_err();
                eprintln!("{path}: no table, refused: {e:#}");
                continue;
            };
            assert_eq!(table.targets.len(), TABLE_LEN);
            interp
                .check_build(3, minor, true)
                .unwrap_or_else(|e| panic!("{path}: {e:#}"));
            let sites = interp
                .dispatch_sites(3, minor)
                .unwrap_or_else(|e| panic!("{path}: {e:#}"));
            assert_eq!(sites.len(), opcodes(minor).unwrap().len(), "{path}");
            let mut offsets: Vec<u64> = sites.iter().map(|s| s.file_offset).collect();
            offsets.sort_unstable();
            offsets.dedup();
            assert_eq!(offsets.len(), sites.len(), "{path}");
            assert_eq!(interp.eval_frame_sites().unwrap().len(), 2);
            // Another version's numbers are refused on this table.
            for other in [12, 13, 14].into_iter().filter(|m| *m != minor) {
                assert!(
                    interp.dispatch_sites(3, other).is_err(),
                    "{path}: 3.{other}"
                );
            }
            eprintln!("{path}: Python 3.{minor}, {} sites", sites.len());
            checked += 1;
        }
        if checked == 0 {
            assert!(
                std::env::var_os("CI").is_none(),
                "no CPython 3.12-3.14 with a dispatch table on this host: the check must not \
                 pass vacuously in CI"
            );
            eprintln!("no CPython 3.12-3.14 with a dispatch table here: nothing was checked");
        }
    }

    /// The relocation bound counts the relocations the parser reads: every
    /// installed interpreter has some, and a bound of one byte refuses it.
    #[test]
    fn the_relocation_bound_counts_the_dynamic_relocations() {
        let mut checked = 0;
        for (path, _) in installed_interpreters() {
            let file = File::open(&path).unwrap();
            let cache = ReadCache::new(&file);
            let elf = object::File::parse(&cache).unwrap();
            if elf
                .dynamic_relocations()
                .is_none_or(|mut r| r.next().is_none())
            {
                continue;
            }
            assert!(check_bounds_with(&elf, u64::MAX).is_ok(), "{path}");
            let e = check_bounds_with(&elf, 1).unwrap_err();
            assert!(
                format!("{e:#}").contains("bytes of relocations"),
                "{path}: {e:#}"
            );
            checked += 1;
        }
        if checked == 0 {
            assert!(
                std::env::var_os("CI").is_none(),
                "no interpreter with dynamic relocations here: the check must not pass vacuously in CI"
            );
        }
    }

    /// A minimal 64-bit ELF: the null section, a section-name table and one
    /// relocation section of `rela_size` bytes linked to section `link`, with
    /// no dynamic symbol table.
    fn elf_without_dynsym(rela_size: u64, link: u32) -> Vec<u8> {
        let names = b"\0.shstrtab\0.rela.x\0";
        let names_at = 64u64;
        let headers_at = (names_at + names.len() as u64 + 7) & !7;
        let mut f = vec![0u8; headers_at as usize + 3 * 64];
        f[..4].copy_from_slice(b"\x7fELF");
        f[4] = 2; // 64-bit
        f[5] = 1; // little-endian
        f[6] = 1; // version
        f[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
        f[18..20].copy_from_slice(&62u16.to_le_bytes()); // x86-64
        f[20..24].copy_from_slice(&1u32.to_le_bytes());
        f[40..48].copy_from_slice(&headers_at.to_le_bytes()); // e_shoff
        f[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        f[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
        f[60..62].copy_from_slice(&3u16.to_le_bytes()); // e_shnum
        f[62..64].copy_from_slice(&1u16.to_le_bytes()); // e_shstrndx
        f[names_at as usize..names_at as usize + names.len()].copy_from_slice(names);
        let mut header = |i: usize, name: u32, kind: u32, offset: u64, size: u64, link: u32| {
            let h = headers_at as usize + i * 64;
            f[h..h + 4].copy_from_slice(&name.to_le_bytes());
            f[h + 4..h + 8].copy_from_slice(&kind.to_le_bytes());
            f[h + 24..h + 32].copy_from_slice(&offset.to_le_bytes());
            f[h + 32..h + 40].copy_from_slice(&size.to_le_bytes());
            f[h + 40..h + 44].copy_from_slice(&link.to_le_bytes());
            f[h + 56..h + 64].copy_from_slice(&24u64.to_le_bytes()); // sh_entsize
        };
        header(1, 1, 3, names_at, names.len() as u64, 0); // .shstrtab
        header(2, 11, SHT_RELA, 0, rela_size, link); // .rela.x
        f
    }

    /// A file with no dynamic symbol table is refused before its relocations
    /// are looked at: the parser would read those linked to section 0.
    #[test]
    fn a_file_without_a_dynamic_symbol_table_is_refused() {
        let bytes = elf_without_dynsym(MAX_RELOCATION_BYTES + 1, 0);
        let elf = object::File::parse(&bytes[..]).unwrap();
        let e = check_bounds(&elf).unwrap_err();
        assert!(
            format!("{e:#}").contains("no dynamic symbol table"),
            "{e:#}"
        );
    }

    /// The section count is read from the raw header before anything is
    /// parsed, in its extended form too (count 0 in the header, the real one
    /// in section 0's size).
    #[test]
    fn too_many_sections_are_refused_before_parsing() {
        let dir = std::env::temp_dir().join(format!("pyft-sections-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("elf");
        let mut bytes = elf_without_dynsym(0, 0);
        std::fs::write(&path, &bytes).unwrap();
        assert!(check_section_count(&File::open(&path).unwrap()).is_ok());
        let headers_at = u64::from_le_bytes(bytes[40..48].try_into().unwrap()) as usize;
        bytes[60..62].copy_from_slice(&0u16.to_le_bytes());
        bytes[headers_at + 32..headers_at + 40].copy_from_slice(&600u64.to_le_bytes());
        std::fs::write(&path, &bytes).unwrap();
        let e = check_section_count(&File::open(&path).unwrap()).unwrap_err();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(format!("{e:#}").contains("600 sections"), "{e:#}");
    }

    /// (file, minor version) for each Python 3.12-3.14 on PATH and in the
    /// usual places: the executable a process runs and, for a shared build,
    /// its libpython, which is where the interpreter then is.
    fn installed_interpreters() -> Vec<(String, i32)> {
        let mut found: Vec<(String, i32)> = Vec::new();
        for minor in [12, 13, 14] {
            for python in [
                format!("python3.{minor}"),
                format!("/usr/bin/python3.{minor}"),
            ] {
                let Ok(out) = std::process::Command::new(&python)
                    .args([
                        "-c",
                        "import sys, sysconfig, os\n\
                         print(os.path.realpath(sys.executable))\n\
                         lib = os.path.join(sysconfig.get_config_var('LIBDIR') or '', \
                         sysconfig.get_config_var('INSTSONAME') or '')\n\
                         if sysconfig.get_config_var('Py_ENABLE_SHARED') and os.path.exists(lib):\n\
                         \x20   print(os.path.realpath(lib))",
                    ])
                    .output()
                else {
                    continue;
                };
                if !out.status.success() {
                    continue;
                }
                for path in String::from_utf8_lossy(&out.stdout).lines() {
                    let path = path.trim().to_string();
                    if !path.is_empty()
                        && Path::new(&path).exists()
                        && !found.iter().any(|(p, _)| *p == path)
                    {
                        found.push((path, minor));
                    }
                }
            }
        }
        found
    }
}
