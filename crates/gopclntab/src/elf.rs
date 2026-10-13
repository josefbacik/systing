//! Locate and extract the pclntab from ELF binaries.
//!
//! ELF parsing is delegated to the [`object`] crate; reads are targeted —
//! headers and the sections consulted, then exactly the pclntab byte
//! range — so probing large binaries (Go binaries run to hundreds of MiB)
//! never reads whole files. The exception is the sectionless fallback
//! below, which must read the data sections it scans.
//!
//! The table is located by section name first — `.gopclntab`, then the
//! `.data.rel.ro.gopclntab` name some PIE links use. When neither
//! exists, non-executable data sections are scanned for a validating
//! pclntab header: distro external-linking PIE builds (observed on
//! Amazon Linux 2023's containerd packages across go1.20–go1.23) merge
//! the table anonymously into `.data.rel.ro`, and the header is its only
//! remaining identification. See [`GoPclntab::scan`].
//!
//! The base of the table's entry offsets — Go's own start of code, the
//! runtime's `moduledata.text` — is resolved from the runtime's module
//! data record and never taken from the `.text` section: the two
//! addresses agree only under Go's own linker. Under the system linker
//! (`-linkmode=external`, the same distro builds as above) `.text` opens
//! with C start-up code, and a base taken from the section shifts every
//! lookup onto a neighboring function's name. A table whose base cannot
//! be validated makes the binary "not a candidate": a miss is better
//! than a wrong name.
//!
//! Binaries that are not ELF, or in which no table can be located,
//! report "not a candidate" (`Ok(None)`) rather than an error. Section
//! metadata is validated against the input's actual size, so the only
//! inputs rejected as malformed are ones whose headers are inconsistent
//! with the bytes on disk — there is no size threshold a large-but-valid
//! binary could trip over (the scan's own budget caps work done, not
//! input size), save five. The base step reads no relocation or data
//! section larger than what is left of its 256 MiB budget, so a binary
//! whose module data record can be reached only through a larger section
//! is "not a candidate"; and so is an image with more than 4,096
//! sections, a hundred times what a Go binary has, with more segments
//! than the file header's own field can count, with more than 256 MiB of
//! symbol tables, or with a function table of more than 256 MiB.
//!
//! Policy is deliberately left to the caller: this module reports whether
//! a symbol table is present ([`ElfPclntab::has_symtab`]) but does not
//! decide whether the pclntab *should* be used — a profiler may only want
//! it for stripped binaries, while other tools may always want it.

use std::fs::File;
use std::path::Path;

use object::read::elf::Rela as _;
use object::read::ReadCache;
use object::read::ReadRef;
use object::Object;
use object::ObjectSection;

use crate::Error;
use crate::GoPclntab;
use crate::MAX_TABLE;

/// A `.gopclntab` extracted from an ELF binary, with the context a caller
/// needs to decide how to use it.
#[derive(Debug)]
pub struct ElfPclntab {
    /// The parsed function table.
    pub table: GoPclntab,
    /// Whether the binary also carries a `.symtab`. Symbolizers typically
    /// prefer the symbol table (and its associated DWARF) when present —
    /// the pclntab is most valuable when this is `false`, i.e. the binary
    /// is stripped.
    pub has_symtab: bool,
}

impl ElfPclntab {
    /// Extract and parse `.gopclntab` from the ELF file at `path`.
    ///
    /// Returns `Ok(None)` when the file is not a candidate: not an ELF, or
    /// no `.gopclntab` section. Returns an error for I/O failures and for
    /// tables that exist but do not parse.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Option<Self>, Error> {
        let file = File::open(path)?;
        // ReadCache reads the byte ranges object asks for, not the whole
        // file.
        let cache = ReadCache::new(file);
        Self::from_read_ref(&cache)
    }

    /// Extract and parse `.gopclntab` from an in-memory ELF image.
    ///
    /// Same semantics as [`ElfPclntab::from_path`].
    pub fn from_bytes(data: &[u8]) -> Result<Option<Self>, Error> {
        Self::from_read_ref(data)
    }

    fn from_read_ref<'data, R: ReadRef<'data>>(source: R) -> Result<Option<Self>, Error> {
        // Counts and sizes are the file's own claims: they are looked at
        // first.
        if !stated_sizes_are_plausible(source) {
            return Ok(None);
        }
        let Ok(elf) = object::File::parse(source) else {
            // Not an object file this build recognizes (only the ELF
            // format is compiled in): not a candidate.
            return Ok(None);
        };

        let has_symtab = elf.symbol_table().is_some();
        let text_vaddr = elf.section_by_name(".text").map(|text| text.address());
        let input_len = source.len().unwrap_or(u64::MAX);

        // The dedicated section, under both names Go links emit.
        for name in [".gopclntab", ".data.rel.ro.gopclntab"] {
            let Some(section) = elf.section_by_name(name) else {
                continue;
            };
            let Some(data) = read_named_section(&section, input_len, name)? else {
                return Ok(None);
            };
            let mut table = GoPclntab::parse(data, text_vaddr)?;
            if !settle_text_start(&elf, &mut table, section.address(), input_len) {
                return Ok(None);
            }
            return Ok(Some(Self { table, has_symtab }));
        }

        // No dedicated section. The scan below reads whole data sections,
        // which every stripped ELF that reaches this point would pay —
        // so first require evidence the binary is Go at all. Both marker
        // sections survive external linking and stripping (they are
        // present on the sectionless distro builds this fallback exists
        // for), unlike `.gopclntab` itself. This also narrows foreign-
        // table adoption: a non-Go binary embedding a complete Go ELF in
        // its data is no longer scanned at all.
        if elf.section_by_name(".go.buildinfo").is_none()
            && elf.section_by_name(".note.go.buildid").is_none()
        {
            return Ok(None);
        }

        // Scan non-executable data sections for a validating header,
        // likeliest homes first. Failures here are "not a candidate",
        // not errors — this path is discovery, and sections that cannot
        // be read or hold no table are simply skipped. The budget bounds
        // total bytes read on adversarial inputs (candidate rejection
        // within a region is constant-time per candidate — see
        // [`GoPclntab::scan`]); real binaries put the table within the
        // first few dozen MiB of `.data.rel.ro` or `.rodata`.
        const SCAN_BUDGET: u64 = 1 << 30;
        let mut budget = SCAN_BUDGET;
        let mut sections: Vec<_> = elf
            .sections()
            .filter(|s| {
                matches!(
                    s.kind(),
                    object::SectionKind::Data | object::SectionKind::ReadOnlyData
                )
            })
            .collect();
        sections.sort_by_key(|s| match s.name() {
            Ok(".data.rel.ro") => 0,
            Ok(".rodata") => 1,
            _ => 2,
        });
        for section in sections {
            if section.size() == 0 || section.size() > budget {
                continue;
            }
            // A section claiming bytes past end-of-input cannot be read;
            // uncompressed_data fails and the section is skipped.
            let Ok(data) = section.uncompressed_data() else {
                continue;
            };
            budget = budget.saturating_sub(data.len() as u64);
            if let Some((offset, mut table)) = GoPclntab::scan_at(&data, text_vaddr) {
                let table_vaddr = section.address().saturating_add(offset as u64);
                if !settle_text_start(&elf, &mut table, table_vaddr, input_len) {
                    return Ok(None);
                }
                return Ok(Some(Self { table, has_symtab }));
            }
        }
        Ok(None)
    }
}

/// Whether an image's header tables and symbol tables are of sizes a real
/// binary has: at most [`MAX_SECTIONS`] section headers, no extended
/// numbering of sections or segments, and at most [`MAX_SYMBOL_TABLES`] bytes
/// of symbol tables in all. Judged from the file header and the section
/// headers alone. What is no ELF file passes: the parse says so itself.
fn stated_sizes_are_plausible<'data, R: ReadRef<'data>>(source: R) -> bool {
    fn check<'data, Elf, R>(source: R) -> Option<bool>
    where
        Elf: object::read::elf::FileHeader<Endian = object::Endianness>,
        R: ReadRef<'data>,
    {
        use object::read::elf::SectionHeader as _;
        let header = Elf::parse(source).ok()?;
        let endian = header.endian().ok()?;
        if header.e_phnum(endian) == object::elf::PN_XNUM
            || header.e_shstrndx(endian) == object::elf::SHN_XINDEX
            || (header.e_shnum(endian) == 0 && header.e_shoff(endian).into() != 0)
            || usize::from(header.e_shnum(endian)) > MAX_SECTIONS
        {
            return Some(false);
        }
        let tables = header
            .section_headers(endian, source)
            .ok()?
            .iter()
            .filter(|section| {
                matches!(
                    section.sh_type(endian),
                    object::elf::SHT_SYMTAB
                        | object::elf::SHT_DYNSYM
                        | object::elf::SHT_SYMTAB_SHNDX
                )
            })
            .fold(0u64, |sum, section| {
                sum.saturating_add(section.sh_size(endian).into())
            });
        Some(tables <= MAX_SYMBOL_TABLES)
    }
    match object::FileKind::parse(source) {
        Ok(object::FileKind::Elf32) => {
            check::<object::elf::FileHeader32<object::Endianness>, R>(source)
        }
        Ok(object::FileKind::Elf64) => {
            check::<object::elf::FileHeader64<object::Endianness>, R>(source)
        }
        _ => None,
    }
    .unwrap_or(true)
}

/// Read a named pclntab section's bytes, validating its metadata against
/// the input's real length first: a section header claiming bytes past
/// end-of-input is inconsistent with the file itself, which is the only
/// "too large" this module rejects as malformed. A section of more than
/// [`MAX_TABLE`] bytes is not read: `None`, not a candidate.
fn read_named_section<'data>(
    section: &object::Section<'data, '_, impl ReadRef<'data>>,
    input_len: u64,
    name: &str,
) -> Result<Option<Vec<u8>>, Error> {
    let range = section
        .compressed_file_range()
        .map_err(|_| Error::Malformed(format!("{name} has no file range")))?;
    if range.format != object::CompressionFormat::None {
        return Err(Error::Unsupported(format!("compressed {name} section")));
    }
    if range
        .offset
        .checked_add(range.uncompressed_size)
        .is_none_or(|end| end > input_len)
    {
        return Err(Error::Malformed(format!(
            "{name} claims {} bytes at offset {} but the input is {} bytes",
            range.uncompressed_size, range.offset, input_len
        )));
    }
    if range.uncompressed_size > MAX_TABLE as u64 {
        return Ok(None);
    }
    Ok(Some(
        section
            .uncompressed_data()
            .map_err(|_| Error::Malformed(format!("short read of {name}")))?
            .into_owned(),
    ))
}

/// Most sections an image may have to be looked at. A Go binary has a few
/// dozen.
const MAX_SECTIONS: usize = 4096;

/// Most bytes of symbol tables, in all, an image may state to be looked at.
const MAX_SYMBOL_TABLES: u64 = 256 << 20;

/// Words of the module data record searched for the (`minpc`, `maxpc`,
/// `text`) triple, counted from the record's first word. The triple stood
/// at words 20 to 22 in the binaries this was developed against; the
/// window is wider so that a field added ahead of it does not hide it.
const MODULEDATA_WINDOW_WORDS: u64 = 64;

/// Bound on the bytes of relocation and data sections read while looking
/// for the module data record. It bounds the bytes read, not the passes
/// made over them: those are one over the relocations to find the records
/// and one more per record followed ([`MODULEDATA_MAX_CANDIDATES`]), and
/// one over the data sections where no relocation names the table. It
/// bounds input as well: a section larger than what is left of it
/// is not read, so a record that can be reached only through such a
/// section goes unvalidated and the binary is not a candidate. Section
/// sizes come from the file, which is whatever the traced process mapped:
/// each read is checked against the input's real length and against what
/// is left of this budget first.
const TEXT_START_BUDGET: u64 = 256 << 20;

/// Most pointers to the table that are followed as module data records.
/// A Go binary holds one. Each record followed costs one pass over the
/// relocations and, for each of its words that no relocation names, a walk
/// over the sections, so this cap bounds the work a file tiled with the
/// table's address can cause together with [`TEXT_START_BUDGET`] and
/// [`MAX_SECTIONS`], not alone.
const MODULEDATA_MAX_CANDIDATES: usize = 16;

/// Give `table` the base its entry offsets are relative to — Go's own
/// start of code, the runtime's `moduledata.text` — or report `false`
/// when none could be validated, in which case the binary is not a
/// candidate.
///
/// The `.text` section's address is that base only when Go's own linker
/// linked the binary. Under the system linker (`-linkmode=external`:
/// distro PIE builds, any program with non-standard cgo) the section
/// opens with C start-up code and Go's code starts later, so a base taken
/// from the section shifts every lookup by the gap and yields
/// real-looking names of the wrong functions. The runtime itself resolves
/// against its module data record, whose first word points at this table
/// and which holds `minpc`, `maxpc` and `text` side by side; that record
/// needs no symbol to find. A triple is accepted only where `minpc - text`
/// is the table's first entry offset and `maxpc - text` its end sentinel
/// — the runtime's own invariant — and where the code it spans lies
/// inside `.text` when that section exists. A miss is better than a wrong
/// name, so nothing falls back to the section's address.
fn settle_text_start<'data, R: ReadRef<'data>>(
    elf: &object::File<'data, R>,
    table: &mut GoPclntab,
    table_vaddr: u64,
    input_len: u64,
) -> bool {
    // V116 entries are absolute addresses: there is no base to settle.
    let Some((first, end)) = table.text_extent() else {
        return true;
    };
    match moduledata_text(elf, table_vaddr, table.ptrsize(), first, end, input_len) {
        Some(text_start) => {
            table.set_text_start(text_start);
            true
        }
        None => false,
    }
}

/// Find the runtime's module data record by its pointer to the table at
/// `table_vaddr` and return its validated `text` (see
/// [`settle_text_start`] for the validation).
fn moduledata_text<'data, R: ReadRef<'data>>(
    elf: &object::File<'data, R>,
    table_vaddr: u64,
    ptrsize: usize,
    first: u64,
    end: u64,
    input_len: u64,
) -> Option<u64> {
    // A table at address zero has no pointer to tell from empty words,
    // and the table parser accepts little-endian tables alone.
    if table_vaddr == 0 || !elf.is_little_endian() {
        return None;
    }
    let mut image = ImageWords {
        elf,
        input_len,
        budget: TEXT_START_BUDGET,
        ptrsize,
        loaded: Vec::new(),
    };
    let relas = image.relative_relas();
    let text_section = elf
        .section_by_name(".text")
        .map(|text| (text.address(), text.size()));
    image
        .pointers_to(table_vaddr, &relas)
        .into_iter()
        .find_map(|record| {
            let words = image.record_words(record, &relas);
            validated_text(&words, first, end, text_section)
        })
}

/// The `text` of the first (`minpc`, `maxpc`, `text`) triple of
/// consecutive `words` that holds the runtime's invariant against the
/// table's own extent and spans code inside `.text` where that section
/// exists. Word 0 is the pointer to the table and is part of no triple.
fn validated_text(
    words: &[Option<u64>],
    first: u64,
    end: u64,
    text_section: Option<(u64, u64)>,
) -> Option<u64> {
    words.windows(3).skip(1).find_map(|triple| {
        let &[Some(minpc), Some(maxpc), Some(text)] = triple else {
            return None;
        };
        // The runtime sets minpc = text + first and maxpc = text + end.
        if text == 0 || minpc.wrapping_sub(text) != first || maxpc.wrapping_sub(text) != end {
            return None;
        }
        let inside_text = text_section.is_none_or(|(address, size)| {
            text >= address
                && text
                    .checked_add(end)
                    .is_some_and(|stop| stop <= address.saturating_add(size))
        });
        inside_text.then_some(text)
    })
}

/// The RELA-form relocations of a 64-bit image's `.rela.dyn`, read through
/// `object`'s typed view; [`Relas::iter`] yields the relative ones. Empty
/// for an image that has none this module reads.
struct Relas<'data> {
    entries: &'data [object::elf::Rela64<object::Endianness>],
    endian: object::Endianness,
    /// The architecture's `R_*_RELATIVE` type.
    relative: u32,
}

impl Relas<'_> {
    /// The (`r_offset`, `r_addend`) pair of each relative relocation. The
    /// addend is a signed field that holds an address here.
    fn iter(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        let (endian, relative) = (self.endian, self.relative);
        self.entries
            .iter()
            .filter(move |entry| entry.r_type(endian, false) == relative)
            .map(move |entry| (entry.r_offset(endian), entry.r_addend(endian) as u64))
    }
}

/// Symbol-free reader of the pointer-sized words of an ELF image as the
/// loader would leave them: enough to follow the runtime's module data
/// record. Every section read is charged to one budget and checked
/// against the input's real length first.
struct ImageWords<'data, 'file, R: ReadRef<'data>> {
    elf: &'file object::File<'data, R>,
    input_len: u64,
    budget: u64,
    ptrsize: usize,
    /// The sections read so far: each one's address and bytes.
    loaded: Vec<(u64, &'data [u8])>,
}

impl<'data, 'file, R: ReadRef<'data>> ImageWords<'data, 'file, R> {
    /// One little-endian pointer-sized word from the head of `bytes`.
    fn decode(&self, bytes: &[u8]) -> Option<u64> {
        match self.ptrsize {
            8 => Some(u64::from_le_bytes(bytes.get(..8)?.try_into().ok()?)),
            4 => Some(u64::from(u32::from_le_bytes(
                bytes.get(..4)?.try_into().ok()?,
            ))),
            _ => None,
        }
    }

    /// Addresses of the words that point at `table_vaddr`, each a
    /// candidate for the module data record's first word, at most
    /// [`MODULEDATA_MAX_CANDIDATES`] of them. A position-independent file
    /// with explicit addends (RELA) keeps the pointer's value in a
    /// relative relocation. A fixed-address file, or one whose relative
    /// relocations keep their addends in place (REL, RELR), holds it in a
    /// writable data section, where the runtime's module data lives.
    fn pointers_to(&mut self, table_vaddr: u64, relas: &Relas<'data>) -> Vec<u64> {
        let mut records: Vec<u64> = relas
            .iter()
            .filter(|(_, addend)| *addend == table_vaddr)
            .map(|(offset, _)| offset)
            .take(MODULEDATA_MAX_CANDIDATES)
            .collect();
        if !records.is_empty() {
            return records;
        }
        let width = self.ptrsize as u64;
        let elf = self.elf;
        for section in elf.sections() {
            if section.kind() != object::SectionKind::Data {
                continue;
            }
            let address = section.address();
            let Some(bytes) = self.section_bytes(&section) else {
                continue;
            };
            self.loaded.push((address, bytes));
            let lead = ((width - address % width) % width) as usize;
            let aligned = bytes.get(lead..).unwrap_or(&[]);
            for (i, word) in aligned.chunks_exact(self.ptrsize).enumerate() {
                if self.decode(word) == Some(table_vaddr) {
                    records.push(address.saturating_add((lead + i * self.ptrsize) as u64));
                    if records.len() == MODULEDATA_MAX_CANDIDATES {
                        return records;
                    }
                }
            }
        }
        records
    }

    /// The first [`MODULEDATA_WINDOW_WORDS`] words of the record at
    /// `record` as the loader would leave them: a relocated word reads its
    /// addend, any other the file's bytes. A word that cannot be read is
    /// `None`.
    fn record_words(&mut self, record: u64, relas: &Relas<'data>) -> Vec<Option<u64>> {
        let width = self.ptrsize as u64;
        // One pass over the relocations, into one slot per word: the file
        // chooses how many entries there are and where they point, so
        // nothing here may grow with them or be searched once per word.
        let mut overlay = [None; MODULEDATA_WINDOW_WORDS as usize];
        // The width is 4 or 8 (the table parser takes no other).
        let shift = width.trailing_zeros();
        for (offset, addend) in relas.iter() {
            let Some(delta) = offset.checked_sub(record) else {
                continue;
            };
            if delta >> shift < MODULEDATA_WINDOW_WORDS && delta & (width - 1) == 0 {
                // The first entry for a word wins.
                overlay[(delta >> shift) as usize].get_or_insert(addend);
            }
        }
        (0..MODULEDATA_WINDOW_WORDS)
            .map(|i| {
                let vaddr = record.saturating_add(i * width);
                let relocated = overlay[i as usize];
                relocated.or_else(|| {
                    let in_place = self.bytes_at(vaddr, width);
                    in_place.and_then(|bytes| self.decode(bytes))
                })
            })
            .collect()
    }

    /// A section's bytes, charged to the budget. `None` when the section
    /// is compressed, claims bytes past end-of-input, exceeds what is
    /// left of the budget or cannot be read.
    fn section_bytes(&mut self, section: &object::Section<'data, 'file, R>) -> Option<&'data [u8]> {
        let range = section.compressed_file_range().ok()?;
        if range.format != object::CompressionFormat::None {
            return None;
        }
        if range
            .offset
            .checked_add(range.uncompressed_size)
            .is_none_or(|end| end > self.input_len)
        {
            return None;
        }
        if range.uncompressed_size > self.budget {
            return None;
        }
        let bytes = section.data().ok()?;
        self.budget -= range.uncompressed_size;
        Some(bytes)
    }

    /// The bytes backing `[vaddr, vaddr + len)`, reading (once) the
    /// initialized section that holds them.
    fn bytes_at(&mut self, vaddr: u64, len: u64) -> Option<&'data [u8]> {
        let stop = vaddr.checked_add(len)?;
        let within = |address: u64, bytes: &'data [u8]| -> Option<&'data [u8]> {
            let start = usize::try_from(vaddr.checked_sub(address)?).ok()?;
            bytes.get(start..start.checked_add(usize::try_from(len).ok()?)?)
        };
        for &(address, bytes) in &self.loaded {
            if vaddr >= address && stop <= address.saturating_add(bytes.len() as u64) {
                return within(address, bytes);
            }
        }
        let elf = self.elf;
        for section in elf.sections() {
            // Sections without file bytes hold no words, and a thread-local
            // one shares its addresses with the section that follows it.
            if matches!(
                section.kind(),
                object::SectionKind::UninitializedData | object::SectionKind::UninitializedTls
            ) {
                continue;
            }
            let address = section.address();
            if address == 0 || vaddr < address || stop > address.saturating_add(section.size()) {
                continue;
            }
            let bytes = self.section_bytes(&section)?;
            self.loaded.push((address, bytes));
            return within(address, bytes);
        }
        None
    }

    /// The image's RELA-form relocations, where this module knows the
    /// architecture's relative type. A section that is no whole number of
    /// aligned entries reads as empty. The entries are viewed through
    /// `object`'s low-level `Rela64` rather than taken from
    /// `Object::dynamic_relocations()`, which would read the relocation
    /// sections with no bound of this module's.
    fn relative_relas(&mut self) -> Relas<'data> {
        let elf = self.elf;
        let relative = match elf.architecture() {
            object::Architecture::X86_64 => Some(object::elf::R_X86_64_RELATIVE),
            object::Architecture::Aarch64 => Some(object::elf::R_AARCH64_RELATIVE),
            _ => None,
        };
        let bytes = match (relative, elf.is_64(), elf.section_by_name(".rela.dyn")) {
            (Some(_), true, Some(section)) => self.section_bytes(&section),
            _ => None,
        };
        Relas {
            entries: bytes
                .and_then(|bytes| object::pod::slice_from_all_bytes(bytes).ok())
                .unwrap_or(&[]),
            endian: elf.endianness(),
            relative: relative.unwrap_or(u32::MAX),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::process::Command;

    /// Build the same tiny program stripped and unstripped, and validate
    /// the whole ELF path against the real Go toolchain: extraction,
    /// symtab detection, full-table resolution, and the `main.*` names.
    /// Skips (with a notice) when no `go` binary is on PATH.
    #[test]
    fn resolves_real_go_binaries() {
        if Command::new("go").arg("version").output().is_err() {
            eprintln!("skipping: no go toolchain on PATH");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("main.go");
        let mut f = std::fs::File::create(&src).unwrap();
        f.write_all(
            b"package main\n\nfunc main() {\n\tprintln(helper())\n}\n\n//go:noinline\nfunc helper() int {\n\treturn 42\n}\n",
        )
        .unwrap();
        drop(f);

        // File-mode build (no module) with -trimpath: the embedded module
        // path is the synthetic "command-line-arguments" and no local
        // filesystem paths land in the binary's metadata.
        let build = |out: &Path, ldflags: &str| {
            let mut cmd = Command::new("go");
            cmd.arg("build").arg("-trimpath");
            if !ldflags.is_empty() {
                cmd.arg(format!("-ldflags={ldflags}"));
            }
            let result = cmd
                .arg("-o")
                .arg(out)
                .arg(&src)
                .env("GOCACHE", out.parent().unwrap().join("gocache"))
                .env("CGO_ENABLED", "0")
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "go build failed: {}",
                String::from_utf8_lossy(&result.stderr)
            );
        };

        let stripped = dir.path().join("fixture-stripped");
        build(&stripped, "-s -w");
        let elf = ElfPclntab::from_path(&stripped)
            .unwrap()
            .expect("stripped fixture has no detectable .gopclntab");
        assert!(!elf.has_symtab, "stripped fixture reports a symtab");
        let tab = elf.table;
        assert!(tab.func_count() > 100, "implausibly small function table");

        // Sweep every function entry: each must resolve back to itself,
        // and main.main / main.helper must both be present by name.
        let mut seen_main = false;
        let mut seen_helper = false;
        for i in 0..tab.func_count() {
            let entry = tab.func_entry(i).unwrap();
            let func = tab
                .find_func(entry)
                .unwrap_or_else(|| panic!("entry {entry:#x} (functab slot {i}) failed to resolve"));
            assert_eq!(func.entry, entry);
            seen_main |= func.name == "main.main";
            seen_helper |= func.name == "main.helper";
        }
        assert!(seen_main, "main.main not found in pclntab");
        assert!(seen_helper, "main.helper not found in pclntab");

        // The unstripped twin: same table, but the symtab is reported so
        // callers preferring symtab+DWARF can decline.
        let unstripped = dir.path().join("fixture-unstripped");
        build(&unstripped, "");
        let elf = ElfPclntab::from_path(&unstripped)
            .unwrap()
            .expect("unstripped fixture has no detectable .gopclntab");
        assert!(elf.has_symtab, "unstripped fixture reports no symtab");
        assert!(elf.table.func_count() > 100);

        // The bytes-based entry point agrees with the file-based one.
        let bytes = std::fs::read(&stripped).unwrap();
        let elf = ElfPclntab::from_bytes(&bytes).unwrap().unwrap();
        assert!(!elf.has_symtab);
        assert_eq!(elf.table.func_count(), tab.func_count());

        // The sectionless shape (distro external-linking PIE builds, e.g.
        // Amazon Linux 2023 containerd): no section is named
        // ".gopclntab", the table sits anonymously inside a data section
        // and only its header identifies it. Simulated by renaming the
        // section — the bytes stay exactly where they were — the scan
        // fallback must find the table and agree with the named path.
        let renamed = rename_section(&bytes, ".gopclntab", ".mystery00");
        let elf = ElfPclntab::from_bytes(&renamed)
            .unwrap()
            .expect("scan fallback missed the renamed pclntab");
        assert!(!elf.has_symtab);
        assert_eq!(elf.table.func_count(), tab.func_count());
        let f = elf.table.find_func(tab.func_entry(0).unwrap()).unwrap();
        assert_eq!(
            f.name,
            tab.find_func(tab.func_entry(0).unwrap()).unwrap().name
        );
        // ...and it proves the Go-ness gate passes real Go binaries: the
        // marker sections were still present for that scan.

        // With the marker sections renamed away as well, nothing
        // identifies the binary as Go and the scan tier is skipped —
        // not-a-candidate, though the (renamed) table bytes are all
        // still in the file.
        let mut gateless = renamed.clone();
        let mut markers = 0;
        for (from, to) in [
            (".note.go.buildid", ".note.no.buildid"),
            (".go.buildinfo", ".no.buildinfo"),
        ] {
            if section_exists(&gateless, from) {
                gateless = rename_section(&gateless, from, to);
                markers += 1;
            }
        }
        assert!(markers > 0, "fixture carries no Go marker sections at all");
        assert!(
            ElfPclntab::from_bytes(&gateless).unwrap().is_none(),
            "gate failed: scan ran on a binary with no Go evidence"
        );

        // Corrupt the section header so .gopclntab claims to extend past
        // end-of-file: the only "too large" that gets rejected is metadata
        // inconsistent with the input itself.
        let corrupt = corrupt_gopclntab_size(&bytes);
        assert!(matches!(
            ElfPclntab::from_bytes(&corrupt),
            Err(Error::Malformed(_))
        ));
    }

    /// The base under each linker. Under the system linker
    /// (`-linkmode=external`) `.text` opens with C start-up code, so Go's
    /// own start of code — the base of the table's entry offsets — lies
    /// after the section's start; under Go's own the two agree. Names are
    /// asserted at addresses read from the unstripped twin's symbol table,
    /// the one check a wrong base cannot pass; the self-resolving sweep
    /// above holds under any base. Four shapes: the system linker, where
    /// the gap is, and Go's own, where a base that could not be settled
    /// would turn a working binary into a miss; each at a fixed address
    /// and position-independent, whose pointers live in relocations.
    /// Skips (with a notice) when no `go` binary is on PATH or a shape
    /// cannot be built (typically no C compiler).
    #[test]
    fn settles_the_text_base_under_both_linkers() {
        use object::ObjectSymbol as _;

        if Command::new("go").arg("version").output().is_err() {
            eprintln!("skipping: no go toolchain on PATH");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("main.go");
        std::fs::write(
            &src,
            b"package main\n\nfunc main() {\n\tprintln(helper())\n}\n\n//go:noinline\nfunc helper() int {\n\treturn 42\n}\n",
        )
        .unwrap();

        // `false` when the shape cannot be built here: the test skips.
        let build = |out: &Path, buildmode: &str, linkmode: &str, strip: bool| -> bool {
            let strip = if strip { "-s -w " } else { "" };
            let result = Command::new("go")
                .arg("build")
                .arg("-trimpath")
                .arg(format!("-buildmode={buildmode}"))
                .arg(format!("-ldflags={strip}-linkmode={linkmode}"))
                .arg("-o")
                .arg(out)
                .arg(&src)
                .env("GOCACHE", out.parent().unwrap().join("gocache"))
                // External linking pulls in runtime/cgo.
                .env(
                    "CGO_ENABLED",
                    if linkmode == "external" { "1" } else { "0" },
                )
                .output()
                .unwrap();
            if !result.status.success() {
                eprintln!(
                    "skipping: go build -buildmode={buildmode} -linkmode={linkmode} failed: {}",
                    String::from_utf8_lossy(&result.stderr)
                );
            }
            result.status.success()
        };

        // Shapes whose stripped fixture kept a section of the table's own,
        // so that the rename at the end of the loop ran for them.
        let mut renamed_shapes = 0;
        for (buildmode, linkmode) in [
            ("exe", "external"),
            ("pie", "external"),
            ("exe", "internal"),
            ("pie", "internal"),
        ] {
            let shape = format!("{buildmode}-{linkmode}");
            let stripped = dir.path().join(format!("{shape}-stripped"));
            let twin = dir.path().join(format!("{shape}-twin"));
            if !build(&stripped, buildmode, linkmode, true)
                || !build(&twin, buildmode, linkmode, false)
            {
                return;
            }

            let elf = ElfPclntab::from_path(&stripped)
                .unwrap()
                .unwrap_or_else(|| panic!("{shape}: fixture is not a candidate"));
            assert!(
                !elf.has_symtab,
                "{shape}: stripped fixture reports a symtab"
            );
            let tab = elf.table;

            let twin_bytes = std::fs::read(&twin).unwrap();
            let twin_elf = object::File::parse(&*twin_bytes).unwrap();
            let symbol = |names: &[&str]| -> u64 {
                twin_elf
                    .symbols()
                    .find(|symbol| symbol.name().is_ok_and(|name| names.contains(&name)))
                    .unwrap_or_else(|| panic!("{shape}: twin has none of {names:?}"))
                    .address()
            };

            // The base is Go's own start of code, whatever `.text` opens
            // with.
            let runtime_text = symbol(&["runtime.text"]);
            assert_eq!(tab.text_start, runtime_text, "{shape}: wrong base");
            let text_section = twin_elf.section_by_name(".text").unwrap().address();
            eprintln!(
                "{shape}: .text {text_section:#x}, runtime.text {runtime_text:#x}, gap {:#x}",
                runtime_text - text_section
            );

            // Assembly functions carry an ABI suffix in the symbol table
            // and none in the pclntab.
            for (symbols, want) in [
                (&["main.main"][..], "main.main"),
                (&["main.helper"][..], "main.helper"),
                (
                    &["runtime.goexit.abi0", "runtime.goexit"][..],
                    "runtime.goexit",
                ),
                (
                    &["runtime.mstart.abi0", "runtime.mstart"][..],
                    "runtime.mstart",
                ),
            ] {
                let entry = symbol(symbols);
                let func = tab
                    .find_func(entry + 1)
                    .unwrap_or_else(|| panic!("{shape}: {want} at {entry:#x} did not resolve"));
                assert_eq!(func.name, want, "{shape}: address {entry:#x}");
                assert_eq!(func.entry, entry, "{shape}: {want}");
            }

            // The scan road settles the same base: with the section
            // renamed, only the header identifies the table. Go's own
            // linker names the section after its segment in a
            // position-independent build. Where the system linker folded
            // the table into `.data.rel.ro` (see the module docs), no
            // section is left to rename, and `from_path` above already
            // went the scan road for this shape.
            let bytes = std::fs::read(&stripped).unwrap();
            let named = [
                (".gopclntab", ".mystery00"),
                (".data.rel.ro.gopclntab", ".data.rel.ro.mystery00"),
            ]
            .into_iter()
            .find(|(from, _)| section_exists(&bytes, from));
            let Some((from, to)) = named else {
                eprintln!("{shape}: the table has no section of its own; the scan road ran above");
                continue;
            };
            let renamed = rename_section(&bytes, from, to);
            let scanned = ElfPclntab::from_bytes(&renamed)
                .unwrap()
                .unwrap_or_else(|| panic!("{shape}: scan road lost the fixture"));
            assert_eq!(scanned.table.text_start, runtime_text, "{shape}: scan road");
            renamed_shapes += 1;
        }
        assert!(
            renamed_shapes > 0,
            "no shape kept a section of the table's own to rename"
        );

        // No validating record, no candidate: with every in-place pointer
        // to the table zeroed in the fixed-address fixture, nothing names
        // the module data record, and the section's address is not
        // trusted in its place.
        let bytes = std::fs::read(dir.path().join("exe-external-stripped")).unwrap();
        // Stop ahead of the section header table: its own `sh_addr` for
        // the table holds the same eight bytes and must stay as it is.
        let (table_vaddr, e_shoff) = {
            use object::read::elf::{ElfFile64, FileHeader as _};
            let parsed: ElfFile64 = ElfFile64::parse(&*bytes).unwrap();
            let table_vaddr = parsed.section_by_name(".gopclntab").unwrap().address();
            let e_shoff = parsed.elf_header().e_shoff(parsed.endian());
            (table_vaddr, e_shoff as usize)
        };
        let needle = table_vaddr.to_le_bytes();
        let mut orphaned = bytes.clone();
        let mut zeroed = 0;
        let mut at = 0;
        while at + 8 <= e_shoff.min(orphaned.len()) {
            if orphaned[at..at + 8] == needle {
                orphaned[at..at + 8].fill(0);
                zeroed += 1;
            }
            at += 8;
        }
        assert!(zeroed > 0, "fixture holds no pointer to its own table");
        assert!(
            ElfPclntab::from_bytes(&orphaned).unwrap().is_none(),
            "a table with no validating module data record was adopted"
        );
    }

    /// Whether the ELF has a section with this exact name.
    fn section_exists(elf: &[u8], name: &str) -> bool {
        use object::read::elf::ElfFile64;
        let parsed: ElfFile64 = ElfFile64::parse(elf).unwrap();
        parsed.section_by_name(name).is_some()
    }

    /// Overwrite a section's name in `.shstrtab` with an unknown
    /// same-length name, so name-based lookups fail while the section's
    /// bytes and headers otherwise stay intact — the closest simulation
    /// of a link that never emitted that name. Pokes the ELF64 layout
    /// directly, like [`corrupt_gopclntab_size`].
    fn rename_section(elf: &[u8], from: &str, to: &str) -> Vec<u8> {
        use object::read::elf::ElfFile64;
        assert_eq!(from.len(), to.len(), "rename must preserve name length");
        let parsed: ElfFile64 = ElfFile64::parse(elf).unwrap();
        let section = parsed.section_by_name(from).unwrap();
        let index = section.index().0;

        let e_shoff = u64::from_le_bytes(elf[0x28..0x30].try_into().unwrap()) as usize;
        let e_shentsize = u16::from_le_bytes(elf[0x3a..0x3c].try_into().unwrap()) as usize;
        let e_shstrndx = u16::from_le_bytes(elf[0x3e..0x40].try_into().unwrap()) as usize;

        // The section's name offset within .shstrtab (sh_name, u32 at +0
        // of its Elf64_Shdr), and .shstrtab's own file offset (sh_offset,
        // u64 at +0x18 of its header).
        let sh_name = u32::from_le_bytes(
            elf[e_shoff + index * e_shentsize..][..4]
                .try_into()
                .unwrap(),
        ) as usize;
        let strtab_off = u64::from_le_bytes(
            elf[e_shoff + e_shstrndx * e_shentsize + 0x18..][..8]
                .try_into()
                .unwrap(),
        ) as usize;

        let mut out = elf.to_vec();
        let name_at = strtab_off + sh_name;
        assert_eq!(&out[name_at..name_at + from.len()], from.as_bytes());
        out[name_at..name_at + to.len()].copy_from_slice(to.as_bytes());
        out
    }

    /// Flip the `sh_size` of `.gopclntab` to a value larger than the file.
    /// object's read API is read-only, so the edit pokes the ELF64
    /// section-header layout directly (stable ABI; fine for a test).
    fn corrupt_gopclntab_size(elf: &[u8]) -> Vec<u8> {
        use object::read::elf::ElfFile64;
        let parsed: ElfFile64 = ElfFile64::parse(elf).unwrap();
        let section = parsed.section_by_name(".gopclntab").unwrap();
        let index = section.index().0;

        let mut out = elf.to_vec();
        let e_shoff = u64::from_le_bytes(elf[0x28..0x30].try_into().unwrap()) as usize;
        let e_shentsize = u16::from_le_bytes(elf[0x3a..0x3c].try_into().unwrap()) as usize;
        // sh_size lives at +0x20 within an Elf64_Shdr.
        let sh_size_at = e_shoff + index * e_shentsize + 0x20;
        out[sh_size_at..sh_size_at + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        out
    }

    /// Parse the pclntab of an arbitrary Go ELF supplied via
    /// `GOPCLNTAB_TEST_BINARY` — handy for vetting against real release
    /// binaries (kubelet, etcd, kube-state-metrics). Skips when unset.
    #[test]
    fn resolves_binary_from_env() {
        let Some(path) = std::env::var_os("GOPCLNTAB_TEST_BINARY") else {
            return;
        };
        let elf = ElfPclntab::from_path(Path::new(&path))
            .unwrap()
            .expect("binary has no detectable .gopclntab");
        let tab = elf.table;
        assert!(tab.func_count() > 0);
        let mut named = 0usize;
        for i in 0..tab.func_count() {
            if let Some(func) = tab.find_func(tab.func_entry(i).unwrap()) {
                assert!(!func.name.is_empty());
                named += 1;
            }
        }
        eprintln!(
            "resolved {named}/{} functions from {} (symtab: {}, text base {:#x})",
            tab.func_count(),
            Path::new(&path).display(),
            elf.has_symtab,
            tab.text_start,
        );
        assert_eq!(named, tab.func_count());
    }

    #[test]
    fn non_elf_and_truncated_inputs_are_not_candidates() {
        assert!(ElfPclntab::from_bytes(b"").unwrap().is_none());
        assert!(ElfPclntab::from_bytes(b"not an elf at all")
            .unwrap()
            .is_none());
        // A bare ELF header with nothing behind it must not become a
        // candidate (and must not panic).
        let mut ehdr = vec![0u8; 64];
        ehdr[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        ehdr[4] = 2;
        ehdr[5] = 1;
        assert!(matches!(ElfPclntab::from_bytes(&ehdr), Ok(None)));
    }
}
