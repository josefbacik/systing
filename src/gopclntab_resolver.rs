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

use blazesym::helper::ElfResolver;
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
    let resolver = ElfResolver::open(maps_file).ok()?;
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
        elf: resolver,
        module,
    }))
}
