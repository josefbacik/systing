//! Which snapshot format a file is, decided by its extension.

use std::path::Path;

use anyhow::{bail, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    /// jemalloc `prof.dump` output (`heap_v2`), e.g. `jeprof.1234.0.f.heap`.
    Jemalloc,
    /// A Go pprof heap profile (`profile.proto`, gzipped or not), as
    /// `/debug/pprof/heap` serves it.
    Pprof,
}

impl Format {
    /// The name stored in `heap_snapshot.format`.
    pub fn name(self) -> &'static str {
        match self {
            Format::Jemalloc => "jemalloc",
            Format::Pprof => "pprof",
        }
    }

    /// The format a file's extension names. `.heap` is jemalloc's; gperftools
    /// (tcmalloc) uses `.heap` too, which the jemalloc parser turns away by
    /// its header.
    pub fn from_path(path: &Path) -> Result<Format> {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if name.ends_with(".heap") {
            return Ok(Format::Jemalloc);
        }
        if name.ends_with(".pb.gz") || name.ends_with(".pprof") || name.ends_with(".pb") {
            return Ok(Format::Pprof);
        }
        bail!(
            "{}: unknown snapshot format (expected a .heap file); pass --format to name one",
            path.display()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heap_extension_is_jemalloc() {
        let f = Format::from_path(Path::new("/tmp/out/jeprof.7.3.i3.heap")).unwrap();
        assert_eq!(f, Format::Jemalloc);
    }

    #[test]
    fn pprof_extensions_are_pprof() {
        for name in ["heap.pb.gz", "heap.pprof", "heap.pb"] {
            assert_eq!(Format::from_path(Path::new(name)).unwrap(), Format::Pprof);
        }
    }

    #[test]
    fn unknown_extension_is_refused() {
        assert!(Format::from_path(Path::new("x.txt")).is_err());
    }
}
