//! blazesym integration for the [`gopclntab`] crate: symbolize stripped Go
//! binaries from the Go runtime's function table.
//!
//! The parsing and ELF mechanics live in the workspace's `gopclntab`
//! crate (published for reuse); this module supplies systing's two pieces
//! on top:
//!
//! * the **activation policy** — a process member is claimed only when it
//!   has no ELF symbol table but does carry a parseable `.gopclntab`
//!   (i.e. a stripped Go binary). Binaries with a symbol table keep the
//!   richer symtab+DWARF path, and blazesym's nearest-symbol matching
//!   against sparse cgo dynamic symbols (which produces confidently wrong
//!   names on e.g. COS/boringcrypto kubelet builds) is bypassed entirely
//!   when the resolver is active;
//! * the **[`Resolve`] implementation** wiring pc lookups into blazesym's
//!   process symbolization flow.
//!
//! Only function names are resolved (no file/line, no inline expansion):
//! that is the difference between an unreadable profile and a readable
//! one. Addresses outside the table (the C/asm portions of cgo text)
//! return unknown and render through the existing contextual labels.

use std::ffi::OsString;
use std::path::Path;

use blazesym::symbolize::FindSymOpts;
use blazesym::symbolize::Reason;
use blazesym::symbolize::Resolve;
use blazesym::symbolize::ResolvedSym;
use blazesym::symbolize::SrcLang;
use blazesym::symbolize::Symbolize;
use blazesym::symbolize::TranslateFileOffset;
use blazesym::Addr;

use gopclntab::ElfPclntab;
use gopclntab::GoPclntab;
use gopclntab::LoadSegments;

/// A [`Resolve`] implementation answering symbol lookups from a Go
/// binary's pclntab.
///
/// File-offset translation (needed by the process symbolization flow to
/// map memory offsets into ELF virtual addresses before calling
/// [`Symbolize::find_sym`]) goes by the program headers that the probe read
/// along with the table, in [`try_gopclntab_resolver`].
///
/// Symbols are reported under the module name that the probe takes from
/// the mapping's symbolic path.
#[derive(Debug)]
pub struct GoPclntabResolver {
    pclntab: GoPclntab,
    load_segments: LoadSegments,
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
        Ok(self.load_segments.file_offset_to_vaddr(file_offset))
    }
}

/// Probe a process member for the stripped-Go shape and build a resolver
/// for it.
///
/// Returns `Some` only when the ELF at `maps_file` has *no* `.symtab` but
/// does have a parseable `.gopclntab` — the case the default ELF resolver
/// renders as hex or misattributes from stray dynamic symbols. Binaries
/// with a symbol table keep the default (richer) path. Any error along
/// the way returns `None`, deliberately: this probe must never make
/// symbolization worse than it was without it.
pub fn try_gopclntab_resolver(maps_file: &Path, symbolic_path: &Path) -> Option<Box<dyn Resolve>> {
    let elf = match ElfPclntab::from_path(maps_file) {
        Ok(Some(elf)) => elf,
        Ok(None) => return None,
        Err(err) => {
            tracing::debug!(
                "ignoring unusable .gopclntab in {}: {err}",
                symbolic_path.display()
            );
            return None;
        }
    };
    if elf.has_symtab {
        return None;
    }
    let module = symbolic_path
        .file_name()
        .unwrap_or(symbolic_path.as_os_str())
        .to_os_string();
    tracing::debug!(
        "using .gopclntab symbolization for stripped Go binary {} ({} functions)",
        symbolic_path.display(),
        elf.table.func_count()
    );
    Some(Box::new(GoPclntabResolver {
        pclntab: elf.table,
        load_segments: elf.load_segments,
        module,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::process::Command;

    use object::Object as _;
    use object::ObjectSection as _;

    /// A stripped Go binary is claimed: a file offset inside `main.main`
    /// translates and resolves. Skips (with a notice) when no `go` binary is
    /// on PATH.
    #[test]
    fn names_a_stripped_go_binary() {
        if Command::new("go").arg("version").output().is_err() {
            eprintln!("skipping: no go toolchain on PATH");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("main.go");
        std::fs::write(&src, b"package main\n\nfunc main() {\n\tprintln(42)\n}\n").unwrap();
        let built = dir.path().join("fixture");
        let result = Command::new("go")
            .arg("build")
            .arg("-trimpath")
            .arg("-ldflags=-s -w")
            .arg("-o")
            .arg(&built)
            .arg(&src)
            .env("GOCACHE", dir.path().join("gocache"))
            .env("CGO_ENABLED", "0")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "go build failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );

        let bytes = std::fs::read(&built).unwrap();
        let parsed = object::File::parse(&*bytes).unwrap();
        let text = parsed.section_by_name(".text").unwrap();
        let table = ElfPclntab::from_path(&built).unwrap().unwrap().table;
        let entry = (0..table.func_count())
            .filter_map(|i| table.func_entry(i))
            .find(|entry| {
                table
                    .find_func(*entry)
                    .is_some_and(|f| f.name == "main.main")
            })
            .expect("main.main not found in pclntab");

        let resolver = try_gopclntab_resolver(&built, Path::new("/somewhere/fixture"))
            .expect("the probe declined a stripped Go binary");
        let vaddr = resolver
            .file_offset_to_virt_offset(entry - text.address() + text.file_range().unwrap().0)
            .unwrap()
            .expect("an offset inside .text did not translate");
        assert_eq!(vaddr, entry);
        let sym = resolver
            .find_sym(vaddr, &FindSymOpts::Basic)
            .unwrap()
            .expect("the entry of main.main did not resolve");
        assert_eq!(sym.name, "main.main");
        assert_eq!(sym.module, Some(std::ffi::OsStr::new("fixture")));
    }

    /// Files without a Go table are left to the default handling: this test's
    /// own executable, and a file that is not an ELF image.
    #[test]
    fn leaves_other_files_to_the_default_handling() {
        let exe = std::env::current_exe().unwrap();
        assert!(try_gopclntab_resolver(&exe, &exe).is_none());

        let text = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(text.path(), b"not an image\n").unwrap();
        assert!(try_gopclntab_resolver(text.path(), text.path()).is_none());
    }
}
