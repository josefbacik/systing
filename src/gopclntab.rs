//! Fallback symbolization for stripped Go binaries via `.gopclntab`.
//!
//! Stripped Go binaries carry no ELF symbol table, but the Go runtime needs
//! its function table (pclntab) at run time for tracebacks and GC, so
//! `strip` and `-ldflags="-s -w"` always leave `.gopclntab` behind. blazesym
//! only reads `.symtab`/`.dynsym`, which has two failure modes on such
//! binaries:
//!
//! * fully stripped (e.g. upstream kube-state-metrics, etcd, cilium-agent
//!   release builds): every user frame renders as bare hex;
//! * stripped cgo builds that retain a handful of dynamic symbols (e.g.
//!   COS/boringcrypto kubelet builds): blazesym's nearest-symbol match
//!   attributes whole Go text ranges to whichever C/asm symbol happens to
//!   precede them, producing confidently *wrong* names.
//!
//! [`try_gopclntab_resolver`] probes a process member for exactly that
//! shape — no `.symtab`, `.gopclntab` present — and returns a resolver that
//! answers name lookups from the pclntab instead. Binaries with a real
//! symbol table never take this path, so the richer symtab+DWARF resolution
//! (source locations, inlined functions) is unaffected.
//!
//! Only function names are resolved here (no file/line, no inline
//! expansion): that is the difference between an unreadable profile and a
//! readable one, and pclntab line tables can be layered on later if wanted.
//!
//! Format reference: `go/src/debug/gosym/pclntab.go` and
//! `go/src/internal/abi/symtab.go`. Layouts for Go 1.16/1.17 (`ver116`) and
//! Go 1.18+ (`ver118`; the Go 1.20 magic shares the layout) are supported.
//! The Go 1.2–1.15 layout and big-endian tables are rejected, in which case
//! symbolization behaves exactly as before this module existed.

use std::ffi::OsString;
use std::fmt;
use std::fs::File;
use std::os::unix::fs::FileExt as _;
use std::path::Path;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;

use blazesym::helper::ElfResolver;
use blazesym::symbolize::FindSymOpts;
use blazesym::symbolize::Reason;
use blazesym::symbolize::Resolve;
use blazesym::symbolize::ResolvedSym;
use blazesym::symbolize::SrcLang;
use blazesym::symbolize::Symbolize;
use blazesym::symbolize::TranslateFileOffset;
use blazesym::Addr;

/// Go 1.2 through 1.15. Predates every Go release still in support; not
/// worth carrying the layout. Recognized only to be rejected explicitly.
const GO12_MAGIC: u32 = 0xFFFF_FFFB;
/// Go 1.16 and 1.17.
const GO116_MAGIC: u32 = 0xFFFF_FFFA;
/// Go 1.18 and 1.19: functab entries became u32 offsets from `textStart`.
const GO118_MAGIC: u32 = 0xFFFF_FFF0;
/// Go 1.20 and later. Same layout as [`GO118_MAGIC`] for everything read
/// here (the bump was about generated symbol naming).
const GO120_MAGIC: u32 = 0xFFFF_FFF1;

/// Header prefix: magic u32, two pad bytes, minLC u8, ptrsize u8.
const HEADER_PREFIX_LEN: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq)]
enum PclnVersion {
    /// Go 1.16/1.17: functab holds ptrsize-wide absolute entry addresses.
    V116,
    /// Go 1.18+: functab holds u32 entry offsets relative to `text_start`.
    V118,
}

/// A parsed `.gopclntab` section, exposing pc -> function-name lookups.
///
/// Owns the raw section bytes; the functab within them is already sorted by
/// entry address, so lookups binary-search the raw table directly and
/// parsing amounts to header validation.
pub struct GoPclntab {
    data: Vec<u8>,
    version: PclnVersion,
    ptrsize: usize,
    nfunctab: usize,
    /// Virtual address of the start of text, the base for V118 entry
    /// offsets. Taken from the `.text` section header (matching what the Go
    /// runtime relocates against) with the pclntab header value as
    /// fallback. Unused for V116.
    text_start: u64,
    /// Offset of the function-name string table within `data`.
    funcnametab: usize,
    /// Offset of the funcdata region within `data`; `funcoff` values in the
    /// functab are relative to this.
    funcdata: usize,
    /// Offset of the functab (pairs of entry/funcoff) within `data`.
    functab: usize,
    /// Width in bytes of one functab field: 4 for V118, ptrsize for V116.
    functab_field: usize,
}

impl fmt::Debug for GoPclntab {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GoPclntab")
            .field("version", &self.version)
            .field("nfunctab", &self.nfunctab)
            .field("text_start", &format_args!("{:#x}", self.text_start))
            .field("len", &self.data.len())
            .finish()
    }
}

/// A function resolved from the pclntab.
#[derive(Debug, PartialEq)]
pub struct GoFunc<'tab> {
    /// The function's name.
    pub name: &'tab str,
    /// Virtual address of the function's entry.
    pub entry: u64,
    /// Size in bytes, from the distance to the next functab entry.
    pub size: u64,
}

impl GoPclntab {
    /// Parse a `.gopclntab` section.
    ///
    /// `text_vaddr` is the virtual address of the binary's `.text` section
    /// when known; Go's own tooling prefers it over the header's stored
    /// value (which may be unrelocated in edge cases) and so do we.
    ///
    /// Every offset is bounds-checked here or read via checked accessors:
    /// malformed input must produce an error, never a panic, because this
    /// runs against arbitrary binaries found on the system.
    pub fn parse(data: Vec<u8>, text_vaddr: Option<u64>) -> Result<Self> {
        if data.len() < HEADER_PREFIX_LEN {
            bail!("pclntab too short for header: {} bytes", data.len());
        }
        let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let version = match magic {
            GO118_MAGIC | GO120_MAGIC => PclnVersion::V118,
            GO116_MAGIC => PclnVersion::V116,
            GO12_MAGIC => bail!("Go <= 1.15 pclntab layout is not supported"),
            // The magics are chosen so a byte-swapped read never matches:
            // an unknown value covers both corruption and big-endian tables.
            other => bail!("unrecognized pclntab magic {other:#x}"),
        };
        let ptrsize = data[7] as usize;
        if ptrsize != 4 && ptrsize != 8 {
            bail!("unsupported pclntab ptrsize {ptrsize}");
        }

        let word = |idx: usize| -> Result<u64> {
            let off = HEADER_PREFIX_LEN + idx * ptrsize;
            read_uint(&data, off, ptrsize)
                .with_context(|| format!("pclntab header word {idx} out of bounds"))
        };
        let tab_offset = |idx: usize, what: &str| -> Result<usize> {
            let off = word(idx)?;
            let off = usize::try_from(off).ok().filter(|o| *o <= data.len());
            off.with_context(|| format!("pclntab {what} offset out of bounds"))
        };

        let (nfunctab, text_start, funcnametab, funcdata) = match version {
            PclnVersion::V118 => (
                word(0)?,
                text_vaddr.unwrap_or(word(2)?),
                tab_offset(3, "funcnametab")?,
                tab_offset(7, "funcdata")?,
            ),
            PclnVersion::V116 => (
                word(0)?,
                0,
                tab_offset(2, "funcnametab")?,
                tab_offset(6, "funcdata")?,
            ),
        };
        let nfunctab = usize::try_from(nfunctab).context("pclntab nfunc overflows usize")?;
        let functab = funcdata;
        let functab_field = match version {
            PclnVersion::V118 => 4,
            PclnVersion::V116 => ptrsize,
        };

        // functab holds nfunctab (entry, funcoff) pairs plus one trailing
        // end-of-text sentinel entry.
        let functab_size = nfunctab
            .checked_mul(2)
            .and_then(|n| n.checked_add(1))
            .and_then(|n| n.checked_mul(functab_field))
            .context("pclntab functab size overflows")?;
        if functab
            .checked_add(functab_size)
            .is_none_or(|end| end > data.len())
        {
            bail!(
                "pclntab functab ({nfunctab} functions) exceeds section size {}",
                data.len()
            );
        }

        Ok(Self {
            data,
            version,
            ptrsize,
            nfunctab,
            text_start,
            funcnametab,
            funcdata,
            functab,
            functab_field,
        })
    }

    /// The number of functions in the table.
    pub fn func_count(&self) -> usize {
        self.nfunctab
    }

    /// Read functab word `idx` (words are laid out as
    /// `entry0, funcoff0, entry1, funcoff1, ..., entryN` with the trailing
    /// sentinel entry). Bounds were validated at parse time, but a miss is
    /// still an honest `None` rather than a panic: this data ultimately
    /// comes from arbitrary binaries found on the system.
    fn functab_word(&self, idx: usize) -> Option<u64> {
        let off = self
            .functab
            .checked_add(idx.checked_mul(self.functab_field)?)?;
        read_uint(&self.data, off, self.functab_field).ok()
    }

    /// The entry value (offset for V118, absolute address for V116) of
    /// functab slot `i`, `i <= nfunctab` (the last slot is the sentinel).
    fn entry_value(&self, i: usize) -> Option<u64> {
        self.functab_word(i * 2)
    }

    /// The virtual entry address of functab slot `i`.
    fn entry_vaddr(&self, i: usize) -> Option<u64> {
        let value = self.entry_value(i)?;
        Some(match self.version {
            PclnVersion::V118 => self.text_start.saturating_add(value),
            PclnVersion::V116 => value,
        })
    }

    /// Look up the function covering virtual address `pc`.
    ///
    /// Returns `None` for addresses outside the table's text range — which
    /// for cgo binaries legitimately includes the C/asm portions of text:
    /// those are not Go functions and the caller's fallback rendering
    /// (contextual `unknown` labels) is the honest answer there.
    pub fn find_func(&self, pc: u64) -> Option<GoFunc<'_>> {
        if self.nfunctab == 0 {
            return None;
        }
        let key = match self.version {
            PclnVersion::V118 => pc.checked_sub(self.text_start)?,
            PclnVersion::V116 => pc,
        };
        if key < self.entry_value(0)? {
            return None;
        }
        // The sentinel at slot nfunctab is the end of text: pcs at or past
        // it belong to no function.
        if key >= self.entry_value(self.nfunctab)? {
            return None;
        }
        // partition_point returns the first slot whose entry exceeds `key`;
        // the covering function is the slot before it. Entries are sorted
        // by construction (the linker emits them in address order); a
        // corrupt out-of-bounds read partitions as "exceeds" and can only
        // shift the search toward a miss.
        let upper = partition_point(self.nfunctab + 1, |i| {
            self.entry_value(i).is_some_and(|entry| entry <= key)
        });
        let idx = upper.checked_sub(1)?;

        let funcoff = usize::try_from(self.functab_word(idx * 2 + 1)?).ok()?;
        let name = self.func_name(funcoff)?;
        let entry = self.entry_vaddr(idx)?;
        let size = self.entry_vaddr(idx + 1)?.saturating_sub(entry);
        Some(GoFunc { name, entry, size })
    }

    /// Resolve a function's name from its funcdata record at `funcoff`.
    fn func_name(&self, funcoff: usize) -> Option<&str> {
        // The _func record starts with the entry (u32 offset for V118,
        // ptrsize address for V116) followed by a 4-byte name offset into
        // funcnametab.
        let entry_width = match self.version {
            PclnVersion::V118 => 4,
            PclnVersion::V116 => self.ptrsize,
        };
        let nameoff_pos = self
            .funcdata
            .checked_add(funcoff)?
            .checked_add(entry_width)?;
        let nameoff = usize::try_from(read_uint(&self.data, nameoff_pos, 4).ok()?).ok()?;
        let name_start = self.funcnametab.checked_add(nameoff)?;
        let rest = self.data.get(name_start..)?;
        let len = rest.iter().position(|b| *b == 0)?;
        std::str::from_utf8(&rest[..len]).ok()
    }
}

/// Little-endian unsigned read of `width` (4 or 8) bytes at `off`.
fn read_uint(data: &[u8], off: usize, width: usize) -> Result<u64> {
    let bytes = off
        .checked_add(width)
        .and_then(|end| data.get(off..end))
        .with_context(|| format!("read of {width} bytes at {off} out of bounds"))?;
    Ok(match width {
        4 => u64::from(u32::from_le_bytes(bytes.try_into().unwrap())),
        8 => u64::from_le_bytes(bytes.try_into().unwrap()),
        _ => bail!("unsupported read width {width}"),
    })
}

/// `[0, n)` partition point: the first index for which `pred` is false.
/// (Equivalent to `slice::partition_point`, over indices instead of a
/// materialized slice so the raw functab bytes can be searched in place.)
fn partition_point(n: usize, pred: impl Fn(usize) -> bool) -> usize {
    let mut lo = 0;
    let mut hi = n;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if pred(mid) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo
}

/// A [`Resolve`] implementation answering symbol lookups from a Go
/// binary's pclntab.
///
/// File-offset translation (needed by the process symbolization flow to
/// map memory offsets into ELF virtual addresses before calling
/// [`Symbolize::find_sym`]) is delegated to a regular [`ElfResolver`] over
/// the same file, which reads it from the program headers.
#[derive(Debug)]
pub struct GoPclntabResolver {
    pclntab: GoPclntab,
    elf: ElfResolver,
    /// Reporting name for the module, from the mapping's symbolic path.
    module: OsString,
}

impl Symbolize for GoPclntabResolver {
    fn find_sym(
        &self,
        addr: Addr,
        _opts: &FindSymOpts,
    ) -> blazesym::Result<std::result::Result<ResolvedSym<'_>, Reason>> {
        match self.pclntab.find_func(addr) {
            Some(func) => Ok(Ok(ResolvedSym {
                name: func.name,
                module: Some(self.module.as_os_str()),
                addr: func.entry,
                size: usize::try_from(func.size).ok(),
                // Go is not a variant blazesym knows; Unknown also keeps
                // the demangler away from names that are not mangled.
                lang: SrcLang::Unknown,
                code_info: None,
                inlined: Box::new([]),
                _non_exhaustive: (),
            })),
            None => Ok(Err(Reason::UnknownAddr)),
        }
    }
}

impl TranslateFileOffset for GoPclntabResolver {
    fn file_offset_to_virt_offset(&self, file_offset: u64) -> blazesym::Result<Option<Addr>> {
        self.elf.file_offset_to_virt_offset(file_offset)
    }
}

/// Probe a process member for the stripped-Go shape and build a resolver
/// for it.
///
/// Returns `Some` only when the ELF at `maps_file` has *no* `.symtab` but
/// does have a parseable `.gopclntab` — the case the default ELF resolver
/// renders as hex or misattributes from stray dynamic symbols. Binaries
/// with a symbol table keep the default (richer) path. Any error along the
/// way returns `None`, deliberately: this probe must never make
/// symbolization worse than it was without it.
pub fn try_gopclntab_resolver(maps_file: &Path, symbolic_path: &Path) -> Option<Box<dyn Resolve>> {
    let pclntab = match read_pclntab_from_stripped_elf(maps_file) {
        Ok(Some(tab)) => tab,
        Ok(None) => return None,
        Err(err) => {
            tracing::debug!(
                "ignoring unusable .gopclntab in {}: {err:#}",
                symbolic_path.display()
            );
            return None;
        }
    };
    let elf = ElfResolver::open(maps_file).ok()?;
    let module = symbolic_path
        .file_name()
        .unwrap_or(symbolic_path.as_os_str())
        .to_os_string();
    tracing::debug!(
        "using .gopclntab symbolization for stripped Go binary {} ({} functions)",
        symbolic_path.display(),
        pclntab.func_count()
    );
    Some(Box::new(GoPclntabResolver {
        pclntab,
        elf,
        module,
    }))
}

/// Section-header size caps. Every symbol-table-less member of every
/// profiled process gets probed, so reads must stay bounded and targeted:
/// ELF + section headers + shstrtab first (a few KiB), then exactly the
/// pclntab byte range for the binaries that have one. A binary whose
/// metadata exceeds these caps is skipped, not mis-parsed.
const MAX_SECTION_HEADERS: u64 = 4096;
const MAX_SHSTRTAB_SIZE: u64 = 1 << 20;
const MAX_PCLNTAB_SIZE: u64 = 1 << 30;

/// Read and parse `.gopclntab` from the ELF at `path`, returning
/// `Ok(None)` when the binary is not the stripped-Go shape this module
/// exists for: not a little-endian ELF64, has a `.symtab` (the default
/// symtab+DWARF path is strictly better), or has no `.gopclntab`.
fn read_pclntab_from_stripped_elf(path: &Path) -> Result<Option<GoPclntab>> {
    let file = File::open(path)?;

    let mut ehdr = [0u8; 64];
    if file.read_exact_at(&mut ehdr, 0).is_err() {
        return Ok(None);
    }
    // \x7fELF, 64-bit (class 2), little-endian (data 1). Anything else is
    // simply not a candidate.
    if ehdr[..4] != [0x7f, b'E', b'L', b'F'] || ehdr[4] != 2 || ehdr[5] != 1 {
        return Ok(None);
    }
    let e_shoff = u64::from_le_bytes(ehdr[0x28..0x30].try_into().unwrap());
    let e_shentsize = u64::from(u16::from_le_bytes(ehdr[0x3a..0x3c].try_into().unwrap()));
    let e_shnum = u64::from(u16::from_le_bytes(ehdr[0x3c..0x3e].try_into().unwrap()));
    let e_shstrndx = usize::from(u16::from_le_bytes(ehdr[0x3e..0x40].try_into().unwrap()));
    // e_shnum == 0 covers both section-header-stripped binaries and the
    // >= SHN_LORESERVE escape hatch; neither occurs for the Go release
    // builds this targets, so skipping is the fail-safe answer.
    if e_shentsize != 64 || e_shnum == 0 || e_shnum > MAX_SECTION_HEADERS {
        return Ok(None);
    }

    let mut shdrs = vec![0u8; (e_shnum * 64) as usize];
    if file.read_exact_at(&mut shdrs, e_shoff).is_err() {
        return Ok(None);
    }
    // Elf64_Shdr field offsets: sh_name +0 (u32), sh_type +4 (u32),
    // sh_addr +16, sh_offset +24, sh_size +32 (u64s).
    let shdr = |i: usize| shdrs.get(i * 64..(i + 1) * 64);
    let shdr_u32 = |s: &[u8], off: usize| u32::from_le_bytes(s[off..off + 4].try_into().unwrap());
    let shdr_u64 = |s: &[u8], off: usize| u64::from_le_bytes(s[off..off + 8].try_into().unwrap());

    let shstr = shdr(e_shstrndx).context("shstrndx out of range")?;
    let shstr_off = shdr_u64(shstr, 24);
    let shstr_size = shdr_u64(shstr, 32);
    if shstr_size > MAX_SHSTRTAB_SIZE {
        return Ok(None);
    }
    let mut shstrtab = vec![0u8; shstr_size as usize];
    if file.read_exact_at(&mut shstrtab, shstr_off).is_err() {
        return Ok(None);
    }
    let section_name = |s: &[u8]| -> &[u8] {
        let name_off = shdr_u32(s, 0) as usize;
        let rest = shstrtab.get(name_off..).unwrap_or(&[]);
        &rest[..rest.iter().position(|b| *b == 0).unwrap_or(rest.len())]
    };

    const SHT_SYMTAB: u32 = 2;
    let mut pclntab_range = None;
    let mut text_vaddr = None;
    for i in 0..e_shnum as usize {
        let s = shdr(i).context("section header out of range")?;
        if shdr_u32(s, 4) == SHT_SYMTAB {
            return Ok(None);
        }
        match section_name(s) {
            b".gopclntab" => pclntab_range = Some((shdr_u64(s, 24), shdr_u64(s, 32))),
            b".text" => text_vaddr = Some(shdr_u64(s, 16)),
            _ => {}
        }
    }
    let Some((offset, size)) = pclntab_range else {
        return Ok(None);
    };
    if size > MAX_PCLNTAB_SIZE {
        bail!(".gopclntab implausibly large ({size} bytes)");
    }

    let mut data = vec![0u8; size as usize];
    file.read_exact_at(&mut data, offset)
        .context("short read of .gopclntab")?;
    GoPclntab::parse(data, text_vaddr).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-level builder for synthetic pclntabs, so the parser and lookup
    /// logic are exercised without a Go toolchain and against layouts we
    /// control precisely (including corrupt ones).
    struct TabBuilder {
        magic: u32,
        ptrsize: usize,
        text_start: u64,
        /// (entry, name) pairs; entry is an offset for V118 layouts and an
        /// absolute address for V116.
        funcs: Vec<(u64, &'static str)>,
        /// Sentinel entry marking the end of text.
        end: u64,
    }

    impl TabBuilder {
        fn v118(text_start: u64) -> Self {
            Self {
                magic: GO120_MAGIC,
                ptrsize: 8,
                text_start,
                funcs: Vec::new(),
                end: 0,
            }
        }

        fn v116() -> Self {
            Self {
                magic: GO116_MAGIC,
                ptrsize: 8,
                text_start: 0,
                funcs: Vec::new(),
                end: 0,
            }
        }

        fn func(mut self, entry: u64, name: &'static str) -> Self {
            self.funcs.push((entry, name));
            self
        }

        fn end(mut self, end: u64) -> Self {
            self.end = end;
            self
        }

        fn build(&self) -> Vec<u8> {
            let v118 = self.magic != GO116_MAGIC;
            let nwords = if v118 { 8 } else { 7 };
            let header_len = HEADER_PREFIX_LEN + nwords * self.ptrsize;

            // Layout: header | funcnametab | functab pairs + sentinel
            // | _func records. funcoffs are relative to the functab base
            // (word 7 / word 6), mirroring real files where funcdata and
            // functab share a base.
            let mut names = Vec::new();
            let mut name_offs = Vec::new();
            for (_, name) in &self.funcs {
                name_offs.push(names.len() as u32);
                names.extend_from_slice(name.as_bytes());
                names.push(0);
            }

            let funcnametab_off = header_len;
            let functab_off = funcnametab_off + names.len();
            let field = if v118 { 4 } else { self.ptrsize };
            let functab_len = (self.funcs.len() * 2 + 1) * field;
            let func_rec_len = if v118 { 8 } else { self.ptrsize + 4 };

            let mut out = Vec::new();
            out.extend_from_slice(&self.magic.to_le_bytes());
            out.extend_from_slice(&[0, 0]); // pad
            out.push(1); // minLC
            out.push(self.ptrsize as u8);
            let word = |v: u64, out: &mut Vec<u8>| {
                out.extend_from_slice(&v.to_le_bytes()[..self.ptrsize]);
            };
            if v118 {
                // nfunc, nfiles, textStart, funcname, cu, filetab, pctab,
                // funcdata
                word(self.funcs.len() as u64, &mut out);
                word(0, &mut out);
                word(self.text_start, &mut out);
                word(funcnametab_off as u64, &mut out);
                word(0, &mut out);
                word(0, &mut out);
                word(0, &mut out);
                word(functab_off as u64, &mut out);
            } else {
                // nfunc, nfiles, funcname, cu, filetab, pctab, funcdata
                word(self.funcs.len() as u64, &mut out);
                word(0, &mut out);
                word(funcnametab_off as u64, &mut out);
                word(0, &mut out);
                word(0, &mut out);
                word(0, &mut out);
                word(functab_off as u64, &mut out);
            }
            assert_eq!(out.len(), header_len);
            out.extend_from_slice(&names);

            let field_bytes = |v: u64, out: &mut Vec<u8>| {
                out.extend_from_slice(&v.to_le_bytes()[..field]);
            };
            for (i, (entry, _)) in self.funcs.iter().enumerate() {
                let funcoff = functab_len + i * func_rec_len;
                field_bytes(*entry, &mut out);
                field_bytes(funcoff as u64, &mut out);
            }
            field_bytes(self.end, &mut out);

            for (i, (entry, _)) in self.funcs.iter().enumerate() {
                if v118 {
                    out.extend_from_slice(&(*entry as u32).to_le_bytes());
                } else {
                    out.extend_from_slice(&entry.to_le_bytes()[..self.ptrsize]);
                }
                out.extend_from_slice(&name_offs[i].to_le_bytes());
            }
            out
        }

        fn parse(&self) -> Result<GoPclntab> {
            GoPclntab::parse(self.build(), Some(self.text_start))
        }
    }

    fn sample_v118() -> GoPclntab {
        TabBuilder::v118(0x40_0000)
            .func(0x0, "runtime.main")
            .func(0x100, "main.main")
            .func(0x2c0, "main.helper")
            .end(0x400)
            .parse()
            .unwrap()
    }

    #[test]
    fn lookup_entry_and_interior() {
        let tab = sample_v118();
        // Exact entry pc.
        let f = tab.find_func(0x40_0100).unwrap();
        assert_eq!(f.name, "main.main");
        assert_eq!(f.entry, 0x40_0100);
        assert_eq!(f.size, 0x1c0);
        // Interior pc, same function.
        assert_eq!(tab.find_func(0x40_02bf).unwrap().name, "main.main");
        // First function at text start.
        assert_eq!(tab.find_func(0x40_0000).unwrap().name, "runtime.main");
    }

    #[test]
    fn lookup_last_function_and_sentinel() {
        let tab = sample_v118();
        // Last function runs to the sentinel.
        let f = tab.find_func(0x40_03ff).unwrap();
        assert_eq!(f.name, "main.helper");
        assert_eq!(f.size, 0x140);
        // At and past the sentinel: no function.
        assert_eq!(tab.find_func(0x40_0400), None);
        assert_eq!(tab.find_func(0x50_0000), None);
    }

    #[test]
    fn lookup_below_text_start() {
        let tab = sample_v118();
        assert_eq!(tab.find_func(0x3f_ffff), None);
        assert_eq!(tab.find_func(0), None);
    }

    #[test]
    fn v116_absolute_entries() {
        let tab = TabBuilder::v116()
            .func(0x40_1000, "runtime.gcBgMarkWorker")
            .func(0x40_1800, "main.main")
            .end(0x40_2000)
            .parse()
            .unwrap();
        assert_eq!(
            tab.find_func(0x40_1234).unwrap().name,
            "runtime.gcBgMarkWorker"
        );
        let f = tab.find_func(0x40_1fff).unwrap();
        assert_eq!(f.name, "main.main");
        assert_eq!(f.entry, 0x40_1800);
        assert_eq!(f.size, 0x800);
        assert_eq!(tab.find_func(0x40_0fff), None);
        assert_eq!(tab.find_func(0x40_2000), None);
    }

    #[test]
    fn go118_magic_accepted() {
        let mut builder = TabBuilder::v118(0x40_0000)
            .func(0x0, "main.main")
            .end(0x100);
        builder.magic = GO118_MAGIC;
        assert_eq!(
            builder.parse().unwrap().find_func(0x40_0000).unwrap().name,
            "main.main"
        );
    }

    #[test]
    fn empty_table_resolves_nothing() {
        let tab = TabBuilder::v118(0x40_0000).end(0).parse().unwrap();
        assert_eq!(tab.func_count(), 0);
        assert_eq!(tab.find_func(0x40_0000), None);
    }

    #[test]
    fn rejects_go12_and_unknown_magics() {
        let mut builder = TabBuilder::v118(0x40_0000)
            .func(0x0, "main.main")
            .end(0x100);
        builder.magic = GO12_MAGIC;
        assert!(builder.parse().is_err());
        builder.magic = 0xDEAD_BEEF;
        assert!(builder.parse().is_err());
        // Big-endian table: the LE read of a BE magic matches nothing.
        builder.magic = GO120_MAGIC.swap_bytes();
        assert!(builder.parse().is_err());
    }

    #[test]
    fn rejects_malformed_input_without_panicking() {
        // Too short for the header prefix.
        assert!(GoPclntab::parse(vec![0xF1, 0xFF, 0xFF], None).is_err());
        // Valid prefix, missing header words.
        let mut short = GO120_MAGIC.to_le_bytes().to_vec();
        short.extend_from_slice(&[0, 0, 1, 8]);
        assert!(GoPclntab::parse(short, None).is_err());
        // Bad ptrsize.
        let mut bad_ptr = GO120_MAGIC.to_le_bytes().to_vec();
        bad_ptr.extend_from_slice(&[0, 0, 1, 3]);
        bad_ptr.extend_from_slice(&[0u8; 64]);
        assert!(GoPclntab::parse(bad_ptr, None).is_err());
        // nfunc so large the functab cannot fit in the section.
        let mut builder = TabBuilder::v118(0x40_0000)
            .func(0x0, "main.main")
            .end(0x100);
        let mut bytes = builder.build();
        bytes[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(GoPclntab::parse(bytes, None).is_err());
        // Truncations at every length must error or lose the function, but
        // never panic.
        builder.magic = GO120_MAGIC;
        let full = builder.build();
        for len in 0..full.len() {
            let tab = GoPclntab::parse(full[..len].to_vec(), Some(0x40_0000));
            if let Ok(tab) = tab {
                let _ = tab.find_func(0x40_0000);
            }
        }
    }

    #[test]
    fn corrupt_name_offset_is_a_miss_not_a_panic() {
        let mut bytes = TabBuilder::v118(0x40_0000)
            .func(0x0, "main.main")
            .end(0x100)
            .build();
        // The single _func record is the last 8 bytes: entryoff u32 then
        // nameoff u32. Point the name offset far outside the section.
        let len = bytes.len();
        bytes[len - 4..].copy_from_slice(&u32::MAX.to_le_bytes());
        let tab = GoPclntab::parse(bytes, Some(0x40_0000)).unwrap();
        assert_eq!(tab.find_func(0x40_0000), None);
    }

    /// Parse the pclntab of a binary produced by the real Go toolchain,
    /// stripped the way release images are, and resolve its functions.
    /// Skips (with a notice) when no `go` binary is on PATH, mirroring how
    /// the pystacks tests skip without a usable Python.
    #[test]
    fn resolves_real_stripped_go_binary() {
        use std::io::Write as _;
        use std::process::Command;

        if Command::new("go").arg("version").output().is_err() {
            eprintln!("skipping: no go toolchain on PATH");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("main.go");
        let mut f = File::create(&src).unwrap();
        f.write_all(
            b"package main\n\nfunc main() {\n\tprintln(helper())\n}\n\n//go:noinline\nfunc helper() int {\n\treturn 42\n}\n",
        )
        .unwrap();
        drop(f);
        // File-mode build (no module) with -trimpath: the embedded module
        // path is the synthetic "command-line-arguments" and no local
        // filesystem paths land in the binary's metadata.
        let bin = dir.path().join("fixture");
        let out = Command::new("go")
            .args(["build", "-trimpath", "-ldflags=-s -w", "-o"])
            .arg(&bin)
            .arg(&src)
            .env("GOCACHE", dir.path().join("gocache"))
            .env("CGO_ENABLED", "0")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "go build failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        // The production probe must classify the fixture as stripped-Go.
        let tab = read_pclntab_from_stripped_elf(&bin)
            .unwrap()
            .expect("fixture not detected as a stripped Go binary");
        assert!(tab.func_count() > 100, "implausibly small function table");

        // Sweep every function entry: each must resolve back to itself,
        // and main.main / main.helper must both be present by name.
        let mut seen_main = false;
        let mut seen_helper = false;
        for i in 0..tab.func_count() {
            let entry = tab.entry_vaddr(i).unwrap();
            let func = tab
                .find_func(entry)
                .unwrap_or_else(|| panic!("entry {entry:#x} (functab slot {i}) failed to resolve"));
            assert_eq!(func.entry, entry);
            seen_main |= func.name == "main.main";
            seen_helper |= func.name == "main.helper";
        }
        assert!(seen_main, "main.main not found in pclntab");
        assert!(seen_helper, "main.helper not found in pclntab");

        // An unstripped build of the same source must be declined: the
        // symtab+DWARF path is richer and the probe must not shadow it.
        let unstripped = dir.path().join("fixture-unstripped");
        let out = Command::new("go")
            .args(["build", "-trimpath", "-o"])
            .arg(&unstripped)
            .arg(&src)
            .env("GOCACHE", dir.path().join("gocache"))
            .env("CGO_ENABLED", "0")
            .output()
            .unwrap();
        assert!(out.status.success());
        assert!(read_pclntab_from_stripped_elf(&unstripped)
            .unwrap()
            .is_none());
    }

    /// Parse the pclntab of an arbitrary Go ELF supplied via
    /// `GOPCLNTAB_TEST_BINARY` — handy for vetting against real release
    /// binaries (kubelet, etcd, kube-state-metrics). Skips when unset.
    #[test]
    fn resolves_binary_from_env() {
        let Some(path) = std::env::var_os("GOPCLNTAB_TEST_BINARY") else {
            return;
        };
        let tab = read_pclntab_from_stripped_elf(Path::new(&path))
            .unwrap()
            .expect("binary not detected as stripped Go");
        assert!(tab.func_count() > 0);
        let mut named = 0usize;
        for i in 0..tab.func_count() {
            if let Some(func) = tab.find_func(tab.entry_vaddr(i).unwrap()) {
                assert!(!func.name.is_empty());
                named += 1;
            }
        }
        eprintln!(
            "resolved {named}/{} functions from {}",
            tab.func_count(),
            Path::new(&path).display()
        );
        assert_eq!(named, tab.func_count());
    }

    #[test]
    fn noncontiguous_lookup_is_stable_across_all_pcs() {
        // Sweep every pc in a small range: each must either resolve to the
        // covering function or miss; ordering invariants hold throughout.
        let tab = sample_v118();
        for pc in 0x3f_fff0..0x40_0410 {
            if let Some(f) = tab.find_func(pc) {
                assert!(f.entry <= pc && pc < f.entry + f.size, "pc {pc:#x}");
            } else {
                assert!(
                    !(0x40_0000..0x40_0400).contains(&pc),
                    "pc {pc:#x} should resolve"
                );
            }
        }
    }
}
