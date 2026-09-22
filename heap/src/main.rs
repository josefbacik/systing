//! systing-heap: read heap snapshots into a systing DuckDB database.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::Parser;
use systing_heap::{db, jemalloc, retention, symbolize, Format, Snapshot};

/// Parse allocator heap snapshots (jemalloc prof dumps), symbolize their
/// stacks, and write them into a systing DuckDB database.
///
/// An input that is a jemalloc prof_prefix (e.g. /data/heap/jeprof, the
/// value given to MALLOC_CONF) loads the latest snapshot of each process
/// and deletes that process's older dumps once the database is written. A
/// file or directory input is only loaded, never deleted.
#[derive(Parser)]
#[command(name = "systing-heap", version)]
struct Cli {
    /// jemalloc prof_prefixes, snapshot files, or directories to load every
    /// snapshot file in (not recursively).
    #[arg(required = true)]
    inputs: Vec<PathBuf>,

    /// The DuckDB database to write. It is replaced on every run.
    #[arg(short, long)]
    output: PathBuf,

    /// Read every file or directory input as this format instead of going
    /// by its extension. Prefix inputs are always jemalloc.
    #[arg(long, value_enum)]
    format: Option<Format>,

    /// The trace id the snapshots are stored under.
    #[arg(long, default_value = "heap")]
    trace_id: String,

    /// With a prefix input, load every snapshot and delete nothing.
    #[arg(long)]
    keep_all: bool,

    /// Print what would be loaded and deleted; write and delete nothing.
    #[arg(long)]
    dry_run: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let mut snapshots: Vec<Snapshot> = Vec::new();
    let mut plans: Vec<retention::Plan> = Vec::new();
    for input in &cli.inputs {
        if input.is_file() || input.is_dir() {
            for (path, format) in collect_inputs(input, cli.format)? {
                snapshots.push(read(&path, format)?);
            }
        } else {
            let mut plan = retention::scan(input, cli.keep_all)?;
            snapshots.append(&mut plan.load);
            plans.push(plan);
        }
    }
    for plan in &plans {
        for s in &plan.skipped {
            eprintln!("left alone: {} ({})", s.path.display(), s.reason);
        }
        for s in &plan.unparsed {
            eprintln!("kept, did not parse: {} ({})", s.path.display(), s.reason);
        }
    }
    if snapshots.is_empty() {
        bail!("no snapshots found in {:?}", cli.inputs);
    }
    // Ids follow dump order: by process, then the allocator's sequence.
    snapshots.sort_by(|a, b| (a.pid, a.seq, &a.source_path).cmp(&(b.pid, b.seq, &b.source_path)));

    if cli.dry_run {
        for s in &snapshots {
            println!("would load: {}", s.source_path.display());
        }
        for plan in &plans {
            for d in &plan.delete {
                println!("would delete: {}", d.path.display());
            }
        }
        return Ok(());
    }

    let symbolized = symbolize::symbolize(&snapshots);
    let stats = &symbolized.stats;
    for f in &stats.missing_files {
        eprintln!(
            "warning: {} is not on this machine; its frames stay unresolved",
            f.display()
        );
    }
    for f in &stats.refused_files {
        eprintln!(
            "warning: {} is not a regular file; not opened, its frames stay unresolved",
            f.display()
        );
    }
    for f in &stats.changed_files {
        eprintln!(
            "warning: {} is not the file the process mapped (different inode); its names may be wrong",
            f.display()
        );
    }

    let source = cli
        .inputs
        .iter()
        .map(|p| p.to_string_lossy())
        .collect::<Vec<_>>()
        .join(",");
    let written = write_replacing(&cli.output, |tmp| {
        db::write(tmp, &cli.trace_id, &source, &snapshots, &symbolized)
    })?;
    println!(
        "{}: {} snapshot(s), {} sample(s), {} stack(s), {} frame(s); {}/{} addresses symbolized",
        cli.output.display(),
        written.snapshots,
        written.samples,
        written.stacks,
        written.frames,
        stats.resolved,
        stats.lookups
    );

    // Only now that the database is in place do older dumps go.
    for plan in &plans {
        let (deleted, kept) = retention::delete(plan);
        for p in deleted {
            println!("deleted: {}", p.display());
        }
        for s in kept {
            eprintln!("kept: {} ({})", s.path.display(), s.reason);
        }
    }
    Ok(())
}

/// Write a new database in a private, randomly named directory beside `out`
/// and rename it over `out`, so a failed run leaves the previous database
/// whole and no one else can plant a file or symlink at the temporary path.
fn write_replacing<T>(out: &Path, write: impl FnOnce(&Path) -> Result<T>) -> Result<T> {
    let parent = match out.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let name = out
        .file_name()
        .with_context(|| format!("{}: not a file path", out.display()))?;
    // Created with mode 0700 and a random name; removed with its contents
    // when dropped, whether or not the write succeeded.
    let tmp_dir = tempfile::Builder::new()
        .prefix(".systing-heap.")
        .tempdir_in(parent)
        .with_context(|| format!("creating a temporary directory in {}", parent.display()))?;
    let tmp = tmp_dir.path().join(name);
    let result = write(&tmp)?;
    // A write-ahead log left by a crashed writer of the old database would
    // be replayed against the new one.
    let _ = std::fs::remove_file(wal_path(out));
    std::fs::rename(&tmp, out)
        .with_context(|| format!("renaming {} to {}", tmp.display(), out.display()))?;
    Ok(result)
}

fn wal_path(db: &Path) -> PathBuf {
    let mut p = db.as_os_str().to_owned();
    p.push(".wal");
    PathBuf::from(p)
}

fn read(path: &Path, format: Format) -> Result<Snapshot> {
    match format {
        Format::Jemalloc => jemalloc::read(path),
    }
}

/// Files to load and their formats. A directory contributes the files whose
/// extension names a format; an unrecognized file named on its own is an
/// error.
fn collect_inputs(input: &Path, forced: Option<Format>) -> Result<Vec<(PathBuf, Format)>> {
    if !input.is_dir() {
        let format = match forced {
            Some(f) => f,
            None => Format::from_path(input)?,
        };
        return Ok(vec![(input.to_path_buf(), format)]);
    }
    let mut entries: Vec<PathBuf> = std::fs::read_dir(input)
        .with_context(|| format!("reading {}", input.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file())
        .collect();
    entries.sort();
    Ok(entries
        .into_iter()
        .filter_map(|path| {
            let format = forced.or_else(|| Format::from_path(&path).ok())?;
            Some((path, format))
        })
        .collect())
}
