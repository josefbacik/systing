//! Output sink abstraction for the streaming parquet writer.
//!
//! `ParquetSink` is what `StreamingParquetWriter` opens per-table writers
//! against: either a local directory of `<table>.parquet` files (the default)
//! or a socket endpoint when `--stream` is in use. Either way the writer gets
//! back a `Box<dyn Write + Send>`, which is all `ArrowWriter` needs.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use tempfile::TempDir;

use crate::stream::StreamTarget;

/// Where parquet table data goes.
#[derive(Debug, Clone)]
pub enum ParquetSink {
    /// One `<table>.parquet` file per table under this directory.
    Directory(PathBuf),
    /// One socket connection per table, header-tagged. The `tmp` directory is
    /// a private (mode 0700) scratch area for stack/memory interner spill
    /// files; it is removed when the last clone of this sink drops.
    Stream {
        target: StreamTarget,
        tmp: Arc<TempDir>,
    },
}

impl ParquetSink {
    /// Create a directory sink, creating the directory if it doesn't exist.
    pub fn directory(dir: &Path) -> Result<Self> {
        if !dir.exists() {
            fs::create_dir_all(dir)
                .with_context(|| format!("Failed to create output directory: {}", dir.display()))?;
        } else if !dir.is_dir() {
            bail!(
                "Output path exists but is not a directory: {}",
                dir.display()
            );
        }
        Ok(Self::Directory(dir.to_path_buf()))
    }

    /// Create a stream sink with a private spill directory.
    pub fn stream(target: StreamTarget) -> Result<Self> {
        let tmp = tempfile::Builder::new()
            .prefix("systing-spill-")
            .tempdir()
            .context("creating spill tempdir for stream sink")?;
        Ok(Self::Stream {
            target,
            tmp: Arc::new(tmp),
        })
    }

    /// Open the writer for a single table.
    pub fn open(&self, table: &str) -> Result<Box<dyn Write + Send>> {
        match self {
            Self::Directory(dir) => {
                let path = dir.join(format!("{table}.parquet"));
                let file = File::create(&path)
                    .with_context(|| format!("Failed to create file: {}", path.display()))?;
                Ok(Box::new(file))
            }
            Self::Stream { target, .. } => target.connect(table),
        }
    }

    /// Directory for stack/memory interner spill files.
    pub fn spill_dir(&self) -> &Path {
        match self {
            Self::Directory(d) => d,
            Self::Stream { tmp, .. } => tmp.path(),
        }
    }
}

impl std::fmt::Display for ParquetSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Directory(d) => write!(f, "{}", d.display()),
            Self::Stream { target, .. } => write!(f, "{target}"),
        }
    }
}
