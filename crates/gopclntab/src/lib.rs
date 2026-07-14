//! Parse the Go runtime's function table (pclntab) and resolve program
//! counters to function names.
//!
//! Stripped Go binaries carry no ELF symbol table, but the Go runtime
//! needs its pclntab at run time for tracebacks and garbage collection, so
//! `strip` and `-ldflags="-s -w"` always leave the `.gopclntab` section
//! behind. Symbolizers that only read `.symtab`/`.dynsym` render such
//! binaries as hex (or worse, misattribute addresses to the few surviving
//! dynamic symbols of a cgo build); the pclntab has the real answer.
//!
//! # Scope
//!
//! Name-only resolution: given a virtual address, find the covering Go
//! function's name, entry address, and size. Source locations and inline
//! expansion (which the pclntab also encodes) are not read yet.
//!
//! Layouts for Go 1.16/1.17 (`ver116`) and Go 1.18+ (`ver118`; the Go
//! 1.20 magic shares the layout) are supported, little-endian. The Go
//! 1.2–1.15 layout and big-endian tables are rejected with
//! [`Error::Unsupported`].
//!
//! Robustness is a design requirement: the input is untrusted (arbitrary
//! binaries found on a system), so every offset is bounds-checked and
//! malformed tables produce an [`Error`] or a lookup miss, never a panic.
//!
//! # Example
//!
//! ```no_run
//! let elf = gopclntab::ElfPclntab::from_path("/usr/bin/some-go-binary")?
//!     .expect("not a Go binary");
//! // Symbol-table-less binary: the pclntab is the only symbolization
//! // source. (Binaries with a symbol table have richer options.)
//! assert!(!elf.has_symtab);
//! if let Some(func) = elf.table.find_func(0x4a6e40) {
//!     println!("{} ({:#x}, {} bytes)", func.name, func.entry, func.size);
//! }
//! # Ok::<(), gopclntab::Error>(())
//! ```
//!
//! Format reference: `go/src/debug/gosym/pclntab.go` and
//! `go/src/internal/abi/symtab.go`.

mod elf;
mod error;

pub use elf::ElfPclntab;
pub use error::Error;

/// Go 1.2 through 1.15. Predates every Go release still in support;
/// recognized only to be rejected explicitly.
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

/// Whether `b` starts with a plausible pclntab header: a supported magic,
/// the two mandatory zero pad bytes, an instruction-size quantum Go
/// actually emits (1 on x86, 2 on arm, 4 on arm64/riscv), and a sane
/// pointer size. Eight constrained bytes — cheap enough to test at every
/// aligned offset of a scan, selective enough that full parse validation
/// only runs on real candidates.
fn header_signature(b: &[u8]) -> bool {
    if b.len() < HEADER_PREFIX_LEN {
        return false;
    }
    let magic = u32::from_le_bytes(b[0..4].try_into().unwrap());
    matches!(magic, GO116_MAGIC | GO118_MAGIC | GO120_MAGIC)
        && b[4] == 0
        && b[5] == 0
        && matches!(b[6], 1 | 2 | 4)
        && matches!(b[7], 4 | 8)
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum PclnVersion {
    /// Go 1.16/1.17: functab holds ptrsize-wide absolute entry addresses.
    V116,
    /// Go 1.18+: functab holds u32 entry offsets relative to `text_start`.
    V118,
}

/// A parsed pclntab, exposing pc -> function-name lookups.
///
/// Owns the raw table bytes; the functab within them is already sorted by
/// entry address, so lookups binary-search the raw table directly and
/// parsing amounts to header validation.
pub struct GoPclntab {
    data: Vec<u8>,
    version: PclnVersion,
    ptrsize: usize,
    nfunctab: usize,
    /// Virtual address of the start of text, the base for V118 entry
    /// offsets. Callers should prefer the `.text` section address
    /// (matching what the Go runtime relocates against); the pclntab
    /// header value is the fallback. Unused for V116.
    text_start: u64,
    /// Offset of the function-name string table within `data`.
    funcnametab: usize,
    /// Offset of the funcdata region within `data`; `funcoff` values in
    /// the functab are relative to this.
    funcdata: usize,
    /// Offset of the functab (pairs of entry/funcoff) within `data`.
    functab: usize,
    /// Width in bytes of one functab field: 4 for V118, ptrsize for V116.
    functab_field: usize,
}

impl std::fmt::Debug for GoPclntab {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
    /// Parse a pclntab from its raw bytes (e.g. the contents of the
    /// `.gopclntab` ELF section).
    ///
    /// `text_vaddr` is the virtual address of the binary's `.text` section
    /// when known; Go's own tooling prefers it over the header's stored
    /// value (which may be unrelocated in edge cases) and so does this
    /// crate. [`ElfPclntab`] supplies it automatically.
    pub fn parse(data: Vec<u8>, text_vaddr: Option<u64>) -> Result<Self, Error> {
        if data.len() < HEADER_PREFIX_LEN {
            return Err(Error::Malformed(format!(
                "too short for header: {} bytes",
                data.len()
            )));
        }
        let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let version = match magic {
            GO118_MAGIC | GO120_MAGIC => PclnVersion::V118,
            GO116_MAGIC => PclnVersion::V116,
            GO12_MAGIC => return Err(Error::Unsupported("Go <= 1.15 pclntab layout".to_string())),
            // The magics are chosen so a byte-swapped read never matches:
            // an unknown value covers both corruption and big-endian
            // tables.
            other => return Err(Error::Unsupported(format!("magic {other:#x}"))),
        };
        let ptrsize = data[7] as usize;
        if ptrsize != 4 && ptrsize != 8 {
            return Err(Error::Unsupported(format!("ptrsize {ptrsize}")));
        }

        let word = |idx: usize| -> Result<u64, Error> {
            let off = HEADER_PREFIX_LEN + idx * ptrsize;
            read_uint(&data, off, ptrsize)
                .ok_or_else(|| Error::Malformed(format!("header word {idx} out of bounds")))
        };
        let tab_offset = |idx: usize, what: &str| -> Result<usize, Error> {
            let off = word(idx)?;
            usize::try_from(off)
                .ok()
                .filter(|off| *off <= data.len())
                .ok_or_else(|| Error::Malformed(format!("{what} offset out of bounds")))
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
        let nfunctab = usize::try_from(nfunctab)
            .map_err(|_| Error::Malformed("nfunc overflows usize".to_string()))?;
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
            .ok_or_else(|| Error::Malformed("functab size overflows".to_string()))?;
        if functab
            .checked_add(functab_size)
            .is_none_or(|end| end > data.len())
        {
            return Err(Error::Malformed(format!(
                "functab ({nfunctab} functions) exceeds table size {}",
                data.len()
            )));
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

    /// Locate and parse a pclntab embedded at an unknown offset inside a
    /// larger byte region.
    ///
    /// Some links emit no dedicated `.gopclntab` section — distro
    /// external-linking PIE builds merge the table anonymously into
    /// `.data.rel.ro` — leaving its header as the only identification.
    /// The scan matches the 8-byte header signature (a known magic, two
    /// zero pad bytes, a plausible instruction quantum and pointer size)
    /// at 8-byte alignment, then validates each candidate by fully
    /// parsing it: the header's offset words must all land inside the
    /// region, which rejects signature lookalikes. The first candidate
    /// that parses wins; `None` means the region holds no parseable
    /// table.
    pub fn scan(region: &[u8], text_vaddr: Option<u64>) -> Option<Self> {
        let mut off = 0;
        while off + HEADER_PREFIX_LEN <= region.len() {
            if header_signature(&region[off..]) {
                match Self::parse(region[off..].to_vec(), text_vaddr) {
                    // An empty table parses but resolves nothing; keep
                    // scanning rather than let it shadow a real one.
                    Ok(table) if table.func_count() > 0 => return Some(table),
                    _ => {}
                }
            }
            off += 8;
        }
        None
    }

    /// The number of functions in the table.
    pub fn func_count(&self) -> usize {
        self.nfunctab
    }

    /// The virtual entry address of functab slot `i`, `i < func_count()`.
    /// Useful for enumerating the table; [`GoPclntab::find_func`] on the
    /// returned address resolves the same slot.
    pub fn func_entry(&self, i: usize) -> Option<u64> {
        if i >= self.nfunctab {
            return None;
        }
        self.entry_vaddr(i)
    }

    /// Read functab word `idx` (words are laid out as
    /// `entry0, funcoff0, entry1, funcoff1, ..., entryN` with the trailing
    /// sentinel entry). Bounds were validated at parse time, but a miss is
    /// still an honest `None` rather than a panic: this data ultimately
    /// comes from untrusted binaries.
    fn functab_word(&self, idx: usize) -> Option<u64> {
        let off = self
            .functab
            .checked_add(idx.checked_mul(self.functab_field)?)?;
        read_uint(&self.data, off, self.functab_field)
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
    /// those are not Go functions and have no entry here.
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
        // partition_point returns the first slot whose entry exceeds
        // `key`; the covering function is the slot before it. Entries are
        // sorted by construction (the linker emits them in address order);
        // a corrupt out-of-bounds read partitions as "exceeds" and can
        // only shift the search toward a miss.
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
        let nameoff = usize::try_from(read_uint(&self.data, nameoff_pos, 4)?).ok()?;
        let name_start = self.funcnametab.checked_add(nameoff)?;
        let rest = self.data.get(name_start..)?;
        let len = rest.iter().position(|b| *b == 0)?;
        std::str::from_utf8(&rest[..len]).ok()
    }
}

/// Little-endian unsigned read of `width` (4 or 8) bytes at `off`.
fn read_uint(data: &[u8], off: usize, width: usize) -> Option<u64> {
    let bytes = off.checked_add(width).and_then(|end| data.get(off..end))?;
    Some(match width {
        4 => u64::from(u32::from_le_bytes(bytes.try_into().unwrap())),
        8 => u64::from_le_bytes(bytes.try_into().unwrap()),
        _ => return None,
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

        fn parse(&self) -> Result<GoPclntab, Error> {
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
    fn scan_finds_embedded_table() {
        let table = TabBuilder::v118(0x40_0000)
            .func(0x0, "runtime.main")
            .func(0x100, "main.main")
            .end(0x400)
            .build();

        // Embed the table at an aligned offset in a larger region, with a
        // decoy earlier: a valid 8-byte signature whose header words are
        // garbage. The decoy must be rejected by full parse validation and
        // the scan must carry on to the real table.
        let mut region = vec![0u8; 64 * 1024];
        region[0..4].copy_from_slice(&GO120_MAGIC.to_le_bytes());
        region[6] = 1;
        region[7] = 8;
        for b in &mut region[8..72] {
            *b = 0xFF;
        }
        let off = 4096;
        region[off..off + table.len()].copy_from_slice(&table);

        let tab = GoPclntab::scan(&region, Some(0x40_0000)).expect("scan missed embedded table");
        assert_eq!(tab.func_count(), 2);
        assert_eq!(tab.find_func(0x40_0100).unwrap().name, "main.main");
    }

    #[test]
    fn scan_rejects_empty_and_garbage() {
        assert!(GoPclntab::scan(&[], None).is_none());
        assert!(GoPclntab::scan(&[0u8; 4096], None).is_none());
        // Signature at an UNALIGNED offset is not considered.
        let mut region = vec![0u8; 4096];
        let table = TabBuilder::v118(0).end(0).build();
        region[100..100 + table.len()].copy_from_slice(&table);
        assert!(GoPclntab::scan(&region, None).is_none());
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
    fn func_entry_enumeration_round_trips() {
        let tab = sample_v118();
        for i in 0..tab.func_count() {
            let entry = tab.func_entry(i).unwrap();
            assert_eq!(tab.find_func(entry).unwrap().entry, entry);
        }
        assert_eq!(tab.func_entry(tab.func_count()), None);
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
        assert!(matches!(builder.parse(), Err(Error::Unsupported(_))));
        builder.magic = 0xDEAD_BEEF;
        assert!(matches!(builder.parse(), Err(Error::Unsupported(_))));
        // Big-endian table: the LE read of a BE magic matches nothing.
        builder.magic = GO120_MAGIC.swap_bytes();
        assert!(matches!(builder.parse(), Err(Error::Unsupported(_))));
    }

    #[test]
    fn rejects_malformed_input_without_panicking() {
        // Too short for the header prefix.
        assert!(matches!(
            GoPclntab::parse(vec![0xF1, 0xFF, 0xFF], None),
            Err(Error::Malformed(_))
        ));
        // Valid prefix, missing header words.
        let mut short = GO120_MAGIC.to_le_bytes().to_vec();
        short.extend_from_slice(&[0, 0, 1, 8]);
        assert!(matches!(
            GoPclntab::parse(short, None),
            Err(Error::Malformed(_))
        ));
        // Bad ptrsize.
        let mut bad_ptr = GO120_MAGIC.to_le_bytes().to_vec();
        bad_ptr.extend_from_slice(&[0, 0, 1, 3]);
        bad_ptr.extend_from_slice(&[0u8; 64]);
        assert!(matches!(
            GoPclntab::parse(bad_ptr, None),
            Err(Error::Unsupported(_))
        ));
        // nfunc so large the functab cannot fit in the section.
        let builder = TabBuilder::v118(0x40_0000)
            .func(0x0, "main.main")
            .end(0x100);
        let mut bytes = builder.build();
        bytes[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(GoPclntab::parse(bytes, None).is_err());
        // Truncations at every length must error or lose the function, but
        // never panic.
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
