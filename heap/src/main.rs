//! systing-heap: read heap snapshots into a systing DuckDB database.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::Parser;
use std::collections::HashMap;
use std::sync::Arc;

use systing_heap::perfmap::{self, PerfMap};
use systing_heap::pycode::{self, CodeMap};
use systing_heap::root::Root;
use systing_heap::{
    ask, check, db, jemalloc, perfetto, retention, snoop, symbolize, Format, Snapshot,
};

/// Parse allocator heap snapshots (jemalloc prof dumps), symbolize their
/// stacks, and write them into a systing DuckDB database.
///
/// An input that is a jemalloc prof_prefix (e.g. /data/heap/jeprof, the
/// value given to MALLOC_CONF) loads the latest snapshot of each process
/// and deletes that process's older dumps once the database is written. A
/// file or directory input is only loaded, never deleted.
///
/// With --pid or --root-fd, the inputs and every path the snapshots name are
/// resolved beneath that root, to read a container's snapshots from outside
/// it.
///
/// With --pid and --snoop (EXPERIMENTAL) there is no snapshot file: the
/// process's current jemalloc heap profile is read out of its memory.
///
/// With --pid and --ask (EXPERIMENTAL) the process is asked to write a dump
/// now, and that dump is loaded.
///
/// With --pid and --check (EXPERIMENTAL) nothing is loaded: what the process
/// has is looked at, and the commands that will work on it are printed.
#[derive(Parser)]
#[command(name = "systing-heap", version)]
struct Cli {
    /// jemalloc prof_prefixes, snapshot files, or directories to load every
    /// snapshot file in (not recursively).
    #[arg(required_unless_present_any = ["snoop", "ask", "check"])]
    inputs: Vec<PathBuf>,

    /// The output, replaced on every run: a DuckDB database, or a Perfetto
    /// trace of native heap profiles when it ends in .pb, .perfetto, .pftrace
    /// or .perfetto-trace (open it at ui.perfetto.dev).
    #[arg(short, long, required_unless_present = "check")]
    output: Option<PathBuf>,

    /// Read every file or directory input as this format instead of going
    /// by its extension. Prefix inputs are always jemalloc.
    #[arg(long, value_enum)]
    format: Option<Format>,

    /// The trace id the snapshots are stored under.
    #[arg(long, default_value = "heap")]
    trace_id: String,

    /// With a prefix input, load every snapshot and delete nothing. (A
    /// Perfetto output loads every snapshot anyway, for its timeline, and
    /// without this deletes the older ones once it is written.)
    #[arg(long)]
    keep_all: bool,

    /// With a prefix input, load only each process's latest snapshot, also
    /// for a Perfetto output, and delete nothing.
    #[arg(long, conflicts_with = "keep_all")]
    latest_only: bool,

    /// Print what would be loaded and deleted; write and delete nothing.
    #[arg(long)]
    dry_run: bool,

    /// Where to look first for the file that names each process's Python
    /// frames: its code map (pycode-<pid>-<token>.map, the hooks' "python"
    /// backtrace), else beside the snapshot; its perf map (perf-<pid>.map,
    /// perf trampolines), else beside the snapshot, then /tmp. With --pid
    /// or --root-fd all of these are beneath the root, /tmp being the
    /// container's own.
    #[arg(long)]
    perf_map_dir: Option<PathBuf>,

    /// Resolve the inputs and every path the snapshots name (the binaries,
    /// the perf maps) beneath the root of the running process PID, as the
    /// kernel would for that process: absolute symlinks and ".." cannot leave
    /// it. For reading a container's snapshots from outside it, PID being a
    /// process in the container: its id as this tool sees it, which is not
    /// the number in its dumps' names. The root, /proc/PID/root, is opened
    /// once at start. Takes prefix inputs only, and names frames from the
    /// binaries' symbol tables alone, without debug information. The output
    /// is not beneath the root. Needs Linux 5.6 or later.
    #[arg(short, long, value_name = "PID", conflicts_with = "root_fd")]
    pid: Option<u32>,

    /// As --pid, the root being a directory descriptor inherited from the
    /// caller, by its number: any directory the caller opened and left open.
    /// A caller that has checked which process a number names should pass
    /// the directory it checked this way, since a number can come to name
    /// another process.
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(i32).range(0..))]
    root_fd: Option<i32>,

    /// EXPERIMENTAL. With --pid, read the process's current jemalloc heap
    /// profile from its memory, instead of from a snapshot file: no input, no
    /// dump interval to wait for, and no file is written. It relies on
    /// jemalloc's private data structures and refuses a jemalloc whose layout
    /// it does not know. The process needs `prof:true` in its MALLOC_CONF;
    /// reading its memory needs the same user as the process (ptrace is not used,
    /// and CAP_SYS_PTRACE is not needed then). A Python code map
    /// is looked for only in --perf-map-dir (there is no dump for it to be
    /// beside).
    #[arg(
        long,
        requires = "pid",
        conflicts_with_all = ["inputs", "format", "keep_all", "latest_only", "dry_run"]
    )]
    snoop: bool,

    /// EXPERIMENTAL. With --pid, ask the process to write a dump now, and
    /// load that: jemalloc's own dump, where --snoop reads the profile
    /// without the process's help. `responder` asks the thread a process
    /// starts with the hooks library's systing_heap_hooks_listen, on its
    /// socket, and nothing is written to disk. `python` makes a CPython 3.14
    /// that loaded nothing of ours run a short script (its remote debugging
    /// interface, as sys.remote_exec uses it): that writes to the process's
    /// memory, the script and the dump are files in a directory made for
    /// them and removed afterwards, and the script runs when the process's
    /// main thread next comes back to Python, which a thread waiting in one
    /// long call does not. `auto`, which --ask alone means, is the responder
    /// if the process has one, else python. The process needs `prof:true` in
    /// its MALLOC_CONF. A Python code map is the one the responder hands
    /// over, else looked for only in --perf-map-dir.
    #[arg(
        long,
        value_enum,
        value_name = "HOW",
        num_args = 0..=1,
        default_missing_value = "auto",
        requires = "pid",
        group = "asking",
        conflicts_with_all = ["inputs", "format", "keep_all", "latest_only", "dry_run", "snoop"]
    )]
    ask: Option<ask::How>,

    /// EXPERIMENTAL. With --pid, load nothing: look at what the process has
    /// for its heap to be read, and print which of the commands will work
    /// on it, the one to try first first, and what the service would have to
    /// be given for more. For a service someone else set up. Nothing is
    /// written to the process and nothing is asked of it: what it maps, the
    /// environment it was started with and its memory are read, and its
    /// responder's socket is connected to and let go. It gives up after 90
    /// seconds, and ends with an error when nothing will work.
    #[arg(
        long,
        requires = "pid",
        group = "asking",
        conflicts_with_all = [
            "inputs", "output", "format", "keep_all", "latest_only", "dry_run", "snoop",
            "perf_map_dir"
        ]
    )]
    check: bool,

    /// EXPERIMENTAL. With --ask or --check, the directory the responder's
    /// socket is in, and the one the script's files are made in: as the
    /// process sees it, and for `python` one the process's user may write
    /// to. Not given, the socket is looked for where the environment the
    /// process was started with says (SYSTING_HEAP_HOOKS_SOCKET_DIR), then
    /// in its /tmp, and the script's files are made in its /tmp.
    #[arg(long, value_name = "DIR", requires = "asking")]
    ask_dir: Option<PathBuf>,

    /// EXPERIMENTAL. With --ask, how long the process is given to answer.
    #[arg(
        long,
        value_name = "SECONDS",
        requires = "ask",
        default_value_t = ask::DEFAULT_WAIT.as_secs(),
        value_parser = clap::value_parser!(u64).range(1..=3600)
    )]
    ask_wait: u64,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // A snoop pins the process once, and takes the root from that handle, so
    // its memory and its root are surely one process. So does asking.
    let pinned = match (cli.snoop || cli.ask.is_some() || cli.check, cli.pid) {
        (true, Some(pid)) => Some(snoop::Process::open(pid)?),
        _ => None,
    };
    if let (true, Some(process)) = (cli.check, pinned.as_ref()) {
        let facts = check::check_within(process, cli.ask_dir.as_deref(), check::WITHIN)?;
        print!("{}", facts.report());
        if facts.ways().is_empty() {
            bail!(
                "nothing here can look at the heap of pid {} as it runs now",
                process.pid()
            );
        }
        return Ok(());
    }
    let Some(output) = cli.output.clone() else {
        bail!("no output named (-o)");
    };
    let pid_root = cli
        .pid
        .filter(|_| pinned.is_none())
        .map(|pid| PathBuf::from(format!("/proc/{pid}/root")));
    let root = match (pinned.as_ref(), pid_root.as_ref(), cli.root_fd) {
        (Some(process), _, _) => Some(process.root()?),
        (None, Some(dir), _) => {
            Some(Root::open(dir).with_context(|| format!("opening the root {}", dir.display()))?)
        }
        (None, None, Some(fd)) => {
            Some(Root::from_fd(fd).with_context(|| format!("taking descriptor {fd} as the root"))?)
        }
        (None, None, None) => None,
    };
    let root = root.as_ref();

    let as_perfetto = perfetto::is_perfetto_output(&output);
    let load_all = !cli.latest_only && (cli.keep_all || as_perfetto);
    let delete_older = !cli.keep_all && !cli.latest_only;
    let mut snapshots: Vec<Snapshot> = Vec::new();
    let mut plans: Vec<retention::Plan> = Vec::new();
    if let (Some(process), Some(how)) = (pinned.as_ref(), cli.ask) {
        let pid = process.pid();
        eprintln!(
            "warning: --ask is experimental: process {pid} is asked to write a heap dump, \
             which for a Python that has no responder means writing to its memory"
        );
        let wait = std::time::Duration::from_secs(cli.ask_wait);
        let (snapshot, report) = ask::ask_within(process, how, cli.ask_dir.as_deref(), wait)?;
        eprintln!("{}", report.summary(pid));
        snapshots.push(snapshot);
    } else if let Some(process) = pinned.as_ref() {
        let pid = process.pid();
        eprintln!(
            "warning: --snoop is experimental: it reads jemalloc's private data structures \
             out of process {pid}'s memory, and may fail or refuse on a jemalloc it does not know"
        );
        let (snapshot, report) = snoop::read_within(process, snoop::TIMEOUT)?;
        eprintln!("{}", report.summary(pid));
        snapshots.push(snapshot);
    }
    for input in &cli.inputs {
        if is_file_or_dir(input, root)? {
            if root.is_some() {
                bail!(
                    "{}: beneath a root an input must be a jemalloc prof_prefix, not a file or directory",
                    input.display()
                );
            }
            for (path, format) in collect_inputs(input, cli.format)? {
                snapshots.push(read(&path, format)?);
            }
        } else {
            let mut plan = retention::scan(input, load_all, delete_older, root)?;
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
    attach_perf_maps(&mut snapshots, cli.perf_map_dir.as_deref(), root);
    attach_code_maps(&mut snapshots, cli.perf_map_dir.as_deref(), root);
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

    let symbolized = symbolize::symbolize_in(&snapshots, root);
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
    for f in &stats.remote_files {
        eprintln!(
            "warning: {} is on a FUSE or network filesystem; not opened beneath a root, its frames stay unresolved",
            f.display()
        );
    }
    for f in &stats.unnamed_generated {
        eprintln!(
            "warning: {} has frames in generated code (Python perf trampolines?) that no perf-<pid>.map names; \
             keep the process's /tmp/perf-<pid>.map beside the snapshot or pass --perf-map-dir",
            f.display()
        );
    }
    for f in &stats.unnamed_python {
        eprintln!(
            "warning: {} has Python frames that no code map names; \
             keep the process's pycode-<pid>-<token>.map beside the snapshot or pass --perf-map-dir",
            f.display()
        );
    }
    for f in &stats.changed_files {
        eprintln!(
            "warning: {} is not the file the process mapped (different inode); its names may be wrong",
            f.display()
        );
    }

    let source = match (cli.snoop, cli.ask, cli.pid) {
        (true, _, Some(pid)) => format!("snoop:{pid}"),
        (_, Some(_), Some(pid)) => format!("ask:{pid}"),
        _ => cli
            .inputs
            .iter()
            .map(|p| p.to_string_lossy())
            .collect::<Vec<_>>()
            .join(","),
    };
    let written = write_replacing(&output, !as_perfetto, |tmp| {
        if as_perfetto {
            perfetto::write(tmp, &snapshots, &symbolized)
        } else {
            db::write(tmp, &cli.trace_id, &source, &snapshots, &symbolized)
        }
    })?;
    println!(
        "{}: {} snapshot(s), {} sample(s), {} stack(s), {} frame(s); {}/{} addresses symbolized, \
         {} Python function(s) from perf maps, {} Python frame(s) from code maps",
        output.display(),
        written.snapshots,
        written.samples,
        written.stacks,
        written.frames,
        stats.resolved,
        stats.lookups,
        stats.perf_map_frames,
        stats.code_map_frames
    );

    // Only now that the output is in place do older dumps go.
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

/// Whether `input` exists as a file or a directory, beneath `root` when
/// there is one; anything else is taken as a prefix.
fn is_file_or_dir(input: &Path, root: Option<&Root>) -> Result<bool> {
    let Some(root) = root else {
        return Ok(input.is_file() || input.is_dir());
    };
    match root.open_at(input, libc::O_PATH) {
        Ok(handle) => {
            let meta = handle
                .metadata()
                .with_context(|| format!("examining {}", input.display()))?;
            Ok(meta.is_file() || meta.is_dir())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(anyhow::Error::new(e).context(format!("looking up {}", input.display()))),
    }
}

/// Give each snapshot its process's perf map: the first candidate that may
/// be read, a refused one falling through to the next. A map is read once
/// however many snapshots share it, and the one used is printed, so a wrong
/// or stale map is visible.
fn attach_perf_maps(snapshots: &mut [Snapshot], dir: Option<&Path>, root: Option<&Root>) {
    // Beneath a root, whether a map may be used turns on who owns the dump
    // whose frames it would name, so a map is cached for that owner.
    let mut cache: HashMap<(PathBuf, Option<u32>), Option<Arc<PerfMap>>> = HashMap::new();
    let mut announced: std::collections::HashSet<PathBuf> = Default::default();
    for s in snapshots {
        let Some(pid) = s.pid else { continue };
        let paths = match root {
            Some(_) => perfmap::places(pid, &s.source_path, dir),
            None => perfmap::candidates(pid, &s.source_path, dir),
        };
        let dump_owner = root.and(s.owner_uid);
        for path in paths {
            let map = cache
                .entry((path.clone(), dump_owner))
                .or_insert_with_key(|(path, owner)| {
                    match perfmap::read_in(root, path, *owner) {
                        Ok(map) => Some(Arc::new(map)),
                        // Beneath a root nothing has yet said the place holds a map.
                        Err(e) if root.is_some() && e.kind() == std::io::ErrorKind::NotFound => {
                            None
                        }
                        Err(e) => {
                            eprintln!("warning: not using {}: {e}", path.display());
                            None
                        }
                    }
                })
                .clone();
            if let Some(map) = map {
                if announced.insert(path.clone()) {
                    eprintln!("pid {pid}: Python frames named from {}", path.display());
                }
                s.perf_map = Some(map);
                break;
            }
        }
    }
}

/// Give each snapshot with Python frames of the hooks' own its process's
/// code map: the one whose token the dump's maps name, so a process that
/// got a recycled pid cannot name another's frames.
fn attach_code_maps(snapshots: &mut [Snapshot], dir: Option<&Path>, root: Option<&Root>) {
    // As for a perf map: beneath a root a map is judged by who owns the dump,
    // so it is cached for that owner.
    let mut cache: HashMap<(PathBuf, Option<u32>), Option<Arc<CodeMap>>> = HashMap::new();
    for s in snapshots {
        // A process that was asked may have handed its map over.
        if s.py_code.is_some() {
            continue;
        }
        let (Some(pid), Some(token)) = (s.pid, pycode::token_of(&s.maps)) else {
            continue;
        };
        let paths = match root {
            Some(_) => pycode::places(pid, token, &s.source_path, dir),
            None => pycode::candidates(pid, token, &s.source_path, dir),
        };
        let dump_owner = root.and(s.owner_uid);
        for path in paths {
            let map = cache
                .entry((path.clone(), dump_owner))
                .or_insert_with_key(|(path, owner)| {
                    match pycode::read_in(root, path, token, *owner) {
                        Ok(map) => {
                            eprintln!("pid {pid}: Python frames named from {}", path.display());
                            Some(Arc::new(map))
                        }
                        // Beneath a root nothing has yet said the place holds a map.
                        Err(e) if root.is_some() && e.kind() == std::io::ErrorKind::NotFound => {
                            None
                        }
                        Err(e) => {
                            eprintln!("warning: not using {}: {e}", path.display());
                            None
                        }
                    }
                })
                .clone();
            if map.is_some() {
                s.py_code = map;
                break;
            }
        }
    }
}

/// Write a new database in a private, randomly named directory beside `out`
/// and rename it over `out`, so a failed run leaves the previous database
/// whole and no one else can plant a file or symlink at the temporary path.
fn write_replacing<T>(
    out: &Path,
    duckdb: bool,
    write: impl FnOnce(&Path) -> Result<T>,
) -> Result<T> {
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
    if duckdb {
        let _ = std::fs::remove_file(wal_path(out));
    }
    std::fs::rename(&tmp, out)
        .with_context(|| format!("renaming {} to {}", tmp.display(), out.display()))?;
    // Make the rename durable before any dump is deleted: after a power
    // loss the deletions must not survive without the new database.
    std::fs::File::open(parent)
        .and_then(|d| d.sync_all())
        .with_context(|| format!("syncing {}", parent.display()))?;
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
