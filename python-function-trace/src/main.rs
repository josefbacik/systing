//! systing-python-function-trace: the Python function trace (experimental).
//!
//! Records every entry to and exit from a Python function in the process it
//! is pointed at, with uprobes on the interpreter (no ptrace, no code of ours
//! in the process), and writes a summary, a Perfetto trace and optionally a
//! table of the slices.

use anyhow::{bail, Context, Result};
use clap::Parser;
use std::os::unix::process::CommandExt as _;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use systing::pystacks::discovery;
use systing::python_function_trace::{self, output, Mode, Options};

#[derive(Parser)]
#[command(name = "systing-python-function-trace")]
#[command(about = "Trace entries to and exits from Python functions (experimental)")]
struct Cli {
    /// Process to trace (all of its threads). Processes it forks later are
    /// not followed
    #[arg(short, long)]
    pid: Option<u32>,

    /// Seconds to trace; 0 traces until Ctrl-C or until the process exits.
    /// Every Python call of the process pays for the probes while they are in
    #[arg(short, long, default_value_t = 10.0)]
    duration: f64,

    /// Where to probe: `dispatch` (the bytecode loop's handlers for the
    /// function-entry, return, yield and exception-handler opcodes: every
    /// Python frame, with or without perf trampolines; CPython 3.12-3.14
    /// built with computed gotos), `eval-frame` (entry to and return from
    /// _PyEval_EvalFrameDefault: every Python frame only while perf
    /// trampolines are on, i.e. `python -X perf` or PYTHONPERFSUPPORT=1;
    /// Python 3.12 to 3.14; puts a return probe in the process, under which the
    /// kernel kills a process that switches C stacks, as greenlet does) or
    /// `auto` (dispatch, or a refusal that says why there are no dispatch
    /// sites)
    #[arg(long, default_value = "auto")]
    mode: Mode,

    /// Perfetto trace to write (open at ui.perfetto.dev)
    #[arg(short, long, default_value = "python-function-trace.pb")]
    output: PathBuf,

    /// Also write the slices as a tab-separated table
    #[arg(long)]
    slices: Option<PathBuf>,

    /// Keep only slices at least this long, in microseconds. Every slice is
    /// still counted in the summary
    #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u64).range(..=u64::MAX / 1000))]
    min_duration_us: u64,

    /// The most slices to keep. Reaching it ends the trace
    #[arg(long, default_value_t = 5_000_000)]
    max_slices: usize,

    /// Size of the events ring, in MiB
    #[arg(long, default_value_t = 256, value_parser = clap::value_parser!(u32).range(1..=2048))]
    ringbuf_size_mib: u32,

    /// Also write every raw probe event as a tab-separated line (timestamp,
    /// kind, tid, frame, stack pointer, symbol id, first line): for checking
    /// the trace against what the probes saw
    #[arg(long, hide = true)]
    events: Option<PathBuf>,

    /// Functions to list in the summary, by self time
    #[arg(long, default_value_t = 25)]
    top: usize,

    /// Command to run and trace: everything after `--`. It must be, or exec,
    /// the Python interpreter. It runs as this tool's user (root), is held
    /// stopped until the probes are in, and gets SIGINT when the trace ends
    /// before it does
    #[arg(last = true)]
    command: Vec<String>,
}

/// Set by SIGINT, SIGTERM and SIGHUP: each ends the trace with its result.
static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_stop_signal(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

fn handle_stop_signals() -> Result<()> {
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        // SAFETY: the handler only stores to an atomic, which is
        // async-signal-safe; the sigaction is ours and zeroed otherwise.
        let failed = unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = on_stop_signal as *const () as usize;
            libc::sigemptyset(&mut action.sa_mask);
            libc::sigaction(signal, &action, std::ptr::null_mut()) != 0
        };
        if failed {
            return Err(std::io::Error::last_os_error()).context("Failed to set a signal handler");
        }
    }
    Ok(())
}

/// The scheduling state of `pid` from `/proc/PID/stat`; `None` once it is
/// gone. Read as bytes: the command name before it need not be UTF-8.
fn state_of(pid: u32) -> Option<u8> {
    let stat = std::fs::read(format!("/proc/{pid}/stat")).ok()?;
    let close = stat.iter().rposition(|b| *b == b')')?;
    stat[close + 1..]
        .iter()
        .copied()
        .find(|b| !b.is_ascii_whitespace())
}

/// The command, while this tool holds it: dropped without [`Held::release`]
/// (an error, a panic), it is continued and killed, so it is never left
/// stopped. It also dies with this tool (PR_SET_PDEATHSIG).
struct Held(Option<Child>);

impl Held {
    fn pid(&self) -> u32 {
        self.0.as_ref().map_or(0, Child::id)
    }

    fn signal(&self, signal: libc::c_int) {
        if let Some(child) = &self.0 {
            // SAFETY: signalling our own child, which we have not reaped.
            unsafe { libc::kill(child.id() as i32, signal) };
        }
    }

    fn release(mut self) -> Child {
        self.0.take().expect("held")
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            // SAFETY: signalling our own child, which we have not reaped.
            unsafe {
                libc::kill(child.id() as i32, libc::SIGKILL);
                libc::kill(child.id() as i32, libc::SIGCONT);
            }
            let _ = child.wait();
        }
    }
}

/// Starts `command` and returns it stopped (SIGSTOP, no ptrace) at the first
/// moment its interpreter is mapped, so the probes go in before the program's
/// first call. The child is stopped before each look, never after it: a short
/// script would otherwise be over before the look was.
fn spawn_held(command: &[String]) -> Result<Held> {
    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..]);
    // SAFETY: prctl is async-signal-safe and touches nothing of the parent's.
    unsafe {
        cmd.pre_exec(|| {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let held = Held(Some(
        cmd.spawn()
            .with_context(|| format!("Failed to run {}", command[0]))?,
    ));
    let pid = held.pid();
    let began = Instant::now();
    loop {
        if STOP.load(Ordering::Relaxed) {
            bail!("stopped before the trace began");
        }
        held.signal(libc::SIGSTOP);
        loop {
            match state_of(pid) {
                Some(b'T') => break,
                Some(b'Z') | Some(b'X') | None => {
                    bail!("{} exited before its interpreter was seen", command[0])
                }
                Some(_) => std::thread::sleep(Duration::from_micros(50)),
            }
        }
        // A shim that execs the interpreter keeps its pid, and the dynamic
        // loader maps libpython a moment after exec: look until it is there.
        if discovery::check_python_process(pid as i32).is_some() {
            return Ok(held);
        }
        if began.elapsed() > Duration::from_secs(10) {
            bail!(
                "{} did not become a Python process within 10 s (the command must be, or \
                 exec, the interpreter)",
                command[0]
            );
        }
        held.signal(libc::SIGCONT);
        std::thread::sleep(Duration::from_micros(200));
    }
}

/// Lets the command finish: SIGINT if it is still running, then up to
/// `grace` before SIGKILL. Returns its exit status.
fn finish_command(mut child: Child, grace: Duration) -> Option<ExitStatus> {
    let pid = child.id() as i32;
    if let Ok(Some(status)) = child.try_wait() {
        return Some(status);
    }
    eprintln!("python-function-trace: the trace ended first; sending SIGINT to {pid}");
    // SAFETY: signalling our own child, which we have not reaped.
    unsafe { libc::kill(pid, libc::SIGINT) };
    let deadline = Instant::now() + grace;
    while Instant::now() < deadline {
        if let Ok(Some(status)) = child.try_wait() {
            return Some(status);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    eprintln!(
        "python-function-trace: {pid} still runs after {:.0} s; killing it",
        grace.as_secs_f64()
    );
    // SAFETY: as above.
    unsafe { libc::kill(pid, libc::SIGKILL) };
    child.wait().ok()
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.pid.is_some() != cli.command.is_empty() {
        bail!("give either --pid or a command after `--`");
    }
    if !cli.duration.is_finite() || cli.duration < 0.0 {
        bail!("--duration must be a number of seconds, 0 or more");
    }
    handle_stop_signals()?;

    let opts = Options {
        pids: Vec::new(),
        mode: cli.mode,
        ringbuf_bytes: cli.ringbuf_size_mib.saturating_mul(1024 * 1024),
        min_slice_ns: cli.min_duration_us * 1000,
        max_slices: cli.max_slices,
        events_path: cli.events.clone(),
        verbose: false,
    };
    let duration = (cli.duration > 0.0).then(|| Duration::from_secs_f64(cli.duration));

    let held = if cli.command.is_empty() {
        None
    } else {
        Some(spawn_held(&cli.command)?)
    };
    let opts = Options {
        pids: vec![cli
            .pid
            .unwrap_or_else(|| held.as_ref().map_or(0, Held::pid))],
        ..opts
    };

    // The command runs on from the moment the probes are in.
    let trace = python_function_trace::run_with(&opts, duration, &STOP, || {
        if let Some(held) = &held {
            held.signal(libc::SIGCONT);
        }
    });
    // With no trace there is nothing to wait for: the guard kills the
    // command as it drops.
    let trace = trace?;
    let child = held.map(|held| {
        held.signal(libc::SIGCONT);
        held.release()
    });

    // The files first, so neither a command that will not end, a second
    // signal nor a terminal that hung up loses the trace; the summary last,
    // and a failed write to stdout ends nothing.
    let written = (|| -> Result<()> {
        output::write_perfetto(&trace, &cli.output)?;
        if let Some(path) = &cli.slices {
            output::write_tsv(&trace, path)?;
        }
        Ok(())
    })();
    {
        use std::io::Write as _;
        let mut out = std::io::stdout().lock();
        let _ = write!(out, "{}", output::summary(&trace, cli.top));
        if written.is_ok() {
            let _ = writeln!(out, "\nPerfetto trace: {}", cli.output.display());
            if let Some(path) = &cli.slices {
                let _ = writeln!(out, "Slices: {}", path.display());
            }
        }
        let _ = out.flush();
    }
    let status = child.and_then(|child| finish_command(child, Duration::from_secs(5)));
    written?;
    // The command's own exit code, or 128 + the signal that ended it, as
    // systing's `-- command` has it.
    if let Some(status) = status {
        use std::os::unix::process::ExitStatusExt as _;
        if let Some(code) = status.code() {
            std::process::exit(code);
        }
        if let Some(signal) = status.signal() {
            eprintln!("python-function-trace: the command was ended by signal {signal}");
            std::process::exit(128 + signal);
        }
    }
    Ok(())
}
