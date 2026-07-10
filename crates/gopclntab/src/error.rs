use std::fmt;

/// Errors produced while locating or parsing a pclntab.
///
/// The distinction matters to callers deciding whether to fall back:
/// [`Error::Unsupported`] means the input is (or may be) a real pclntab in
/// a layout this crate does not read; [`Error::Malformed`] means the input
/// claims to be a pclntab but is structurally inconsistent.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// An I/O error while reading from a file.
    Io(std::io::Error),
    /// A recognized-but-unsupported table: Go 1.2–1.15 layouts, big-endian
    /// tables, or unknown magic values.
    Unsupported(String),
    /// A structurally invalid table: truncated data, out-of-bounds
    /// offsets, or implausible sizes.
    Malformed(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(err) => write!(f, "i/o error: {err}"),
            Error::Unsupported(what) => write!(f, "unsupported pclntab: {what}"),
            Error::Malformed(what) => write!(f, "malformed pclntab: {what}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}
