//! Locate and extract `.gopclntab` from ELF binaries.
//!
//! ELF parsing is delegated to the [`object`] crate; reads are targeted —
//! headers and the sections consulted, then exactly the pclntab byte
//! range — so probing large binaries (Go binaries run to hundreds of MiB)
//! never reads whole files.
//!
//! Binaries that are not ELF, or have no `.gopclntab` section, report
//! "not a candidate" (`Ok(None)`) rather than an error. Section metadata
//! is validated against the input's actual size, so the only inputs
//! rejected as malformed are ones whose headers are inconsistent with the
//! bytes on disk — there is no size threshold a large-but-valid binary
//! could trip over.
//!
//! Policy is deliberately left to the caller: this module reports whether
//! a symbol table is present ([`ElfPclntab::has_symtab`]) but does not
//! decide whether the pclntab *should* be used — a profiler may only want
//! it for stripped binaries, while other tools may always want it.

use std::fs::File;
use std::path::Path;

use object::read::ReadCache;
use object::read::ReadRef;
use object::Object;
use object::ObjectSection;

use crate::Error;
use crate::GoPclntab;

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
        let Ok(elf) = object::File::parse(source) else {
            // Not an object file this build recognizes (only the ELF
            // format is compiled in): not a candidate.
            return Ok(None);
        };

        let Some(section) = elf.section_by_name(".gopclntab") else {
            return Ok(None);
        };
        // Resolving the section's (offset, size) before reading lets the
        // metadata be validated against the input's real length: a section
        // header claiming bytes past end-of-input is inconsistent with the
        // file itself, which is the only "too large" this module rejects.
        let range = section
            .compressed_file_range()
            .map_err(|_| Error::Malformed(".gopclntab has no file range".to_string()))?;
        if range.format != object::CompressionFormat::None {
            return Err(Error::Unsupported(
                "compressed .gopclntab section".to_string(),
            ));
        }
        let input_len = source.len().unwrap_or(u64::MAX);
        if range
            .offset
            .checked_add(range.uncompressed_size)
            .is_none_or(|end| end > input_len)
        {
            return Err(Error::Malformed(format!(
                ".gopclntab claims {} bytes at offset {} but the input is {} bytes",
                range.uncompressed_size, range.offset, input_len
            )));
        }
        let data = section
            .uncompressed_data()
            .map_err(|_| Error::Malformed("short read of .gopclntab".to_string()))?
            .into_owned();

        let has_symtab = elf.symbol_table().is_some();
        let text_vaddr = elf.section_by_name(".text").map(|text| text.address());
        let table = GoPclntab::parse(data, text_vaddr)?;
        Ok(Some(Self { table, has_symtab }))
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

        // Corrupt the section header so .gopclntab claims to extend past
        // end-of-file: the only "too large" that gets rejected is metadata
        // inconsistent with the input itself.
        let corrupt = corrupt_gopclntab_size(&bytes);
        assert!(matches!(
            ElfPclntab::from_bytes(&corrupt),
            Err(Error::Malformed(_))
        ));
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
            "resolved {named}/{} functions from {} (symtab: {})",
            tab.func_count(),
            Path::new(&path).display(),
            elf.has_symtab,
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
