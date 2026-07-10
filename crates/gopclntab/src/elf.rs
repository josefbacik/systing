//! Locate and extract `.gopclntab` from ELF binaries.
//!
//! Reads are targeted and bounded — ELF header, section headers, and the
//! section-name string table first (a few KiB, explicitly capped), then
//! exactly the pclntab byte range — so probing large binaries (Go binaries
//! run to hundreds of MiB) never reads whole files.
//!
//! Only little-endian ELF64 is supported; anything else reports "not a
//! candidate" (`Ok(None)`) rather than an error, as do binaries without a
//! `.gopclntab` section. Policy is deliberately left to the caller: this
//! module reports whether a symbol table is present ([`ElfPclntab::
//! has_symtab`]) but does not decide whether the pclntab *should* be used
//! — a profiler may only want it for stripped binaries, while other tools
//! may always want it.

use std::fs::File;
use std::path::Path;

use crate::Error;
use crate::GoPclntab;

/// Caps on metadata reads. A binary whose metadata exceeds these is
/// skipped (`Ok(None)`), not mis-parsed; a `.gopclntab` larger than the
/// cap is reported as malformed (real tables in very large binaries run
/// to tens of MiB).
const MAX_SECTION_HEADERS: u64 = 4096;
const MAX_SHSTRTAB_SIZE: u64 = 1 << 20;
const MAX_PCLNTAB_SIZE: u64 = 1 << 30;

const SHT_SYMTAB: u32 = 2;

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

/// A bounded random-access byte source: implemented for files (pread) and
/// in-memory slices.
trait ReadAt {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<()>;
}

impl ReadAt for File {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
        std::os::unix::fs::FileExt::read_exact_at(self, buf, offset)
    }
}

impl ReadAt for &[u8] {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
        let start = usize::try_from(offset).ok().filter(|start| {
            start
                .checked_add(buf.len())
                .is_some_and(|end| end <= self.len())
        });
        match start {
            Some(start) => {
                buf.copy_from_slice(&self[start..start + buf.len()]);
                Ok(())
            }
            None => Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
        }
    }
}

impl ElfPclntab {
    /// Extract and parse `.gopclntab` from the ELF file at `path`.
    ///
    /// Returns `Ok(None)` when the file is not a candidate: not a
    /// little-endian ELF64, no section headers, or no `.gopclntab`
    /// section. Returns an error for I/O failures and for tables that
    /// exist but do not parse.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Option<Self>, Error> {
        let file = File::open(path)?;
        Self::from_read_at(&file)
    }

    /// Extract and parse `.gopclntab` from an in-memory ELF image.
    ///
    /// Same semantics as [`ElfPclntab::from_path`].
    pub fn from_bytes(data: &[u8]) -> Result<Option<Self>, Error> {
        Self::from_read_at(&data)
    }

    fn from_read_at<R: ReadAt>(source: &R) -> Result<Option<Self>, Error> {
        let mut ehdr = [0u8; 64];
        if source.read_exact_at(&mut ehdr, 0).is_err() {
            return Ok(None);
        }
        // \x7fELF, 64-bit (class 2), little-endian (data 1).
        if ehdr[..4] != [0x7f, b'E', b'L', b'F'] || ehdr[4] != 2 || ehdr[5] != 1 {
            return Ok(None);
        }
        let e_shoff = u64::from_le_bytes(ehdr[0x28..0x30].try_into().unwrap());
        let e_shentsize = u64::from(u16::from_le_bytes(ehdr[0x3a..0x3c].try_into().unwrap()));
        let e_shnum = u64::from(u16::from_le_bytes(ehdr[0x3c..0x3e].try_into().unwrap()));
        let e_shstrndx = usize::from(u16::from_le_bytes(ehdr[0x3e..0x40].try_into().unwrap()));
        // e_shnum == 0 covers both section-header-stripped binaries and
        // the >= SHN_LORESERVE escape hatch; neither occurs for Go
        // release builds, so skipping is the fail-safe answer.
        if e_shentsize != 64 || e_shnum == 0 || e_shnum > MAX_SECTION_HEADERS {
            return Ok(None);
        }

        let mut shdrs = vec![0u8; (e_shnum * 64) as usize];
        if source.read_exact_at(&mut shdrs, e_shoff).is_err() {
            return Ok(None);
        }
        // Elf64_Shdr field offsets: sh_name +0 (u32), sh_type +4 (u32),
        // sh_addr +16, sh_offset +24, sh_size +32 (u64s).
        let shdr = |i: usize| shdrs.get(i * 64..(i + 1) * 64);
        let shdr_u32 =
            |s: &[u8], off: usize| u32::from_le_bytes(s[off..off + 4].try_into().unwrap());
        let shdr_u64 =
            |s: &[u8], off: usize| u64::from_le_bytes(s[off..off + 8].try_into().unwrap());

        let Some(shstr) = shdr(e_shstrndx) else {
            return Ok(None);
        };
        let shstr_off = shdr_u64(shstr, 24);
        let shstr_size = shdr_u64(shstr, 32);
        if shstr_size > MAX_SHSTRTAB_SIZE {
            return Ok(None);
        }
        let mut shstrtab = vec![0u8; shstr_size as usize];
        if source.read_exact_at(&mut shstrtab, shstr_off).is_err() {
            return Ok(None);
        }
        let section_name = |s: &[u8]| -> &[u8] {
            let name_off = shdr_u32(s, 0) as usize;
            let rest = shstrtab.get(name_off..).unwrap_or(&[]);
            &rest[..rest.iter().position(|b| *b == 0).unwrap_or(rest.len())]
        };

        let mut has_symtab = false;
        let mut pclntab_range = None;
        let mut text_vaddr = None;
        for i in 0..e_shnum as usize {
            let Some(s) = shdr(i) else {
                return Ok(None);
            };
            if shdr_u32(s, 4) == SHT_SYMTAB {
                has_symtab = true;
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
            return Err(Error::Malformed(format!(
                ".gopclntab implausibly large ({size} bytes)"
            )));
        }

        let mut data = vec![0u8; size as usize];
        source
            .read_exact_at(&mut data, offset)
            .map_err(|_| Error::Malformed("short read of .gopclntab".to_string()))?;
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
        // Valid magic, wrong class (32-bit).
        let mut ehdr = vec![0u8; 64];
        ehdr[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        ehdr[4] = 1;
        ehdr[5] = 1;
        assert!(ElfPclntab::from_bytes(&ehdr).unwrap().is_none());
        // 64-bit LE but no section headers.
        ehdr[4] = 2;
        assert!(ElfPclntab::from_bytes(&ehdr).unwrap().is_none());
    }
}
