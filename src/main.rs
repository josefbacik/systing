mod events;
mod network_recorder;
mod parquet;
mod parquet_to_perfetto;
mod parquet_writer;
mod perf;
mod perf_recorder;
mod perfetto;
mod pystacks;
mod record;
mod ringbuf;
mod sched;
mod session_recorder;
mod stack_recorder;
mod trace;

use std::collections::HashMap;
use std::env;
use std::fs;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::process;
use std::process::{Command as ProcessCommand, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::events::{EventKeyType, EventProbe, SystingProbeRecorder};
use crate::perf::{PerfCounters, PerfHwEvent, PerfOpenEvents};
use crate::perf_recorder::PerfCounterRecorder;
use crate::ringbuf::RingBuffer;
use crate::sched::SchedEventRecorder;
use crate::session_recorder::{get_clock_value, SessionRecorder, SysInfoEvent};
use crate::stack_recorder::StackRecorder;

// Library imports for shared functionality
use ::systing::duckdb as systing_duckdb;

use anyhow::Result;
use anyhow::{bail, Context};
use clap::{ArgAction, Parser};

use tracing::subscriber::set_global_default as set_global_subscriber;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::time::SystemTime;
use tracing_subscriber::FmtSubscriber;

use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{
    MapCore, RawTracepointOpts, RingBufferBuilder, TracepointOpts, UprobeOpts, UsdtOpts,
};

use crate::parquet_writer::ParquetTraceWriter;
use plain::Plain;

/// Sample period for perf clock events (1ms = 1000 samples/sec)
const PERF_CLOCK_SAMPLE_PERIOD: u64 = 1000;

/// Memory lock limit for BPF programs (128 MiB)
const MEMLOCK_RLIMIT_BYTES: u64 = 128 << 20;

/// Sleep duration before stopping in continuous mode (1 second)
const CONTINUOUS_MODE_STOP_DELAY_SECS: u64 = 1;

/// Interval for refreshing system info like CPU frequency (100ms)
const SYSINFO_REFRESH_INTERVAL_MS: u64 = 100;

struct ShutdownSignal {
    eventfd: OwnedFd,
}

impl ShutdownSignal {
    fn new() -> io::Result<Self> {
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            eventfd: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }

    fn signal(&self) {
        let val: u64 = 1;
        let _ = unsafe {
            libc::write(
                self.eventfd.as_raw_fd(),
                &val as *const u64 as *const libc::c_void,
                8,
            )
        };
    }

    fn fd(&self) -> RawFd {
        self.eventfd.as_raw_fd()
    }
}

fn create_ringbuf_epoll(ringbuf_fd: RawFd, shutdown_fd: RawFd) -> io::Result<OwnedFd> {
    let epoll_fd = {
        let fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        unsafe { OwnedFd::from_raw_fd(fd) }
    };

    let mut ev = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: 0,
    };
    if unsafe {
        libc::epoll_ctl(
            epoll_fd.as_raw_fd(),
            libc::EPOLL_CTL_ADD,
            ringbuf_fd,
            &mut ev,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }

    let mut ev = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: 1,
    };
    if unsafe {
        libc::epoll_ctl(
            epoll_fd.as_raw_fd(),
            libc::EPOLL_CTL_ADD,
            shutdown_fd,
            &mut ev,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }

    Ok(epoll_fd)
}

struct RecorderInfo {
    name: &'static str,
    description: &'static str,
    default_enabled: bool,
}

fn get_available_recorders() -> Vec<RecorderInfo> {
    #[allow(unused_mut)]
    let mut recorders = vec![
        RecorderInfo {
            name: "sched",
            description: "Scheduler event tracing",
            default_enabled: true,
        },
        RecorderInfo {
            name: "syscalls",
            description: "Syscall tracing",
            default_enabled: false,
        },
        RecorderInfo {
            name: "sleep-stacks",
            description: "Sleep stack traces",
            default_enabled: true,
        },
        RecorderInfo {
            name: "interruptible-stacks",
            description: "Interruptible sleep stack traces",
            default_enabled: true,
        },
        RecorderInfo {
            name: "cpu-stacks",
            description: "CPU perf stack traces",
            default_enabled: true,
        },
        RecorderInfo {
            name: "network",
            description: "Network traffic recording",
            default_enabled: false,
        },
    ];

    #[cfg(feature = "pystacks")]
    recorders.push(RecorderInfo {
        name: "pystacks",
        description: "Python stack tracing",
        default_enabled: false,
    });

    recorders
}

fn validate_recorder_names(names: &[String]) -> Result<()> {
    let available_recorders = get_available_recorders();
    let valid_names: Vec<&str> = available_recorders.iter().map(|r| r.name).collect();

    for name in names {
        if !valid_names.contains(&name.as_str()) {
            bail!(
                "Invalid recorder name '{}'. Valid recorders: {}",
                name,
                valid_names.join(", ")
            );
        }
    }
    Ok(())
}

fn enable_recorder(opts: &mut Command, recorder_name: &str, enable: bool) {
    match recorder_name {
        "syscalls" => opts.syscalls = enable,
        "sched" => opts.no_sched = !enable,
        "sleep-stacks" => opts.no_sleep_stack_traces = !enable,
        "interruptible-stacks" => opts.no_interruptible_stack_traces = !enable,
        "cpu-stacks" => opts.no_cpu_stack_traces = !enable,
        "network" => opts.network = enable,
        #[cfg(feature = "pystacks")]
        "pystacks" => opts.collect_pystacks = enable,
        _ => {}
    }
}

fn process_recorder_options(opts: &mut Command) -> Result<()> {
    validate_recorder_names(&opts.add_recorder)?;
    validate_recorder_names(&opts.only_recorder)?;

    // If --only-recorder is specified, disable all recorders first
    if !opts.only_recorder.is_empty() {
        opts.no_sched = true;
        opts.syscalls = false;
        opts.no_sleep_stack_traces = true;
        opts.no_interruptible_stack_traces = true;
        opts.no_cpu_stack_traces = true;
        opts.network = false;
        #[cfg(feature = "pystacks")]
        {
            opts.collect_pystacks = false;
        }

        // Then enable only the specified recorders
        let recorders = opts.only_recorder.clone();
        for recorder_name in &recorders {
            enable_recorder(opts, recorder_name, true);
        }
    }

    // Process --add-recorder to enable additional recorders
    let recorders = opts.add_recorder.clone();
    for recorder_name in &recorders {
        enable_recorder(opts, recorder_name, true);
    }
    Ok(())
}

#[derive(Debug, Parser)]
struct Command {
    /// Increase verbosity (can be supplied multiple times).
    #[arg(short = 'v', long = "verbose", action = ArgAction::Count)]
    verbosity: u8,
    #[arg(short, long)]
    pid: Vec<u32>,
    #[arg(short, long)]
    cgroup: Vec<String>,
    #[arg(short, long, default_value = "0")]
    duration: u64,
    #[arg(short, long)]
    no_stack_traces: bool,
    #[arg(long, default_value = "0")]
    ringbuf_size_mib: u32,
    #[arg(long)]
    trace_event: Vec<String>,
    #[arg(long)]
    trace_event_pid: Vec<u32>,
    #[arg(short, long)]
    sw_event: bool,
    #[arg(long)]
    cpu_frequency: bool,
    #[arg(long)]
    perf_counter: Vec<String>,
    #[arg(long)]
    no_cpu_stack_traces: bool,
    #[arg(long)]
    no_sleep_stack_traces: bool,
    #[arg(long)]
    no_interruptible_stack_traces: bool,
    #[arg(long)]
    trace_event_config: Vec<String>,
    #[arg(long, default_value = "0")]
    continuous: u64,
    #[cfg(feature = "pystacks")]
    #[arg(long)]
    collect_pystacks: bool,
    /// Enable debuginfod for enhanced symbol resolution (requires DEBUGINFOD_URLS environment variable)
    #[arg(long)]
    enable_debuginfod: bool,
    /// Disable scheduler event tracing (sched_* tracepoints and scheduler event recorder)
    #[arg(long)]
    no_sched: bool,
    /// Enable syscall tracing (raw_syscalls:sys_enter and sys_exit tracepoints)
    #[arg(long)]
    syscalls: bool,
    // Network recording enabled state (set by recorder management, not a CLI flag)
    #[arg(skip)]
    network: bool,
    /// Skip DNS resolution for network addresses (show IP addresses instead of hostnames)
    #[arg(long)]
    no_resolve_addresses: bool,
    /// List all available recorders and their default states
    #[arg(long)]
    list_recorders: bool,
    /// Enable a specific recorder by name (can be specified multiple times)
    #[arg(long)]
    add_recorder: Vec<String>,
    /// Disable all recorders and only enable the specified ones (can be specified multiple times)
    #[arg(long)]
    only_recorder: Vec<String>,
    /// Directory for parquet trace files
    #[arg(long, default_value = "./traces")]
    output_dir: PathBuf,

    /// Path for the Perfetto trace file
    #[arg(long, default_value = "trace.pb")]
    output: PathBuf,

    /// Skip Perfetto trace generation, keep only parquet files
    #[arg(long)]
    parquet_only: bool,

    /// Use Parquet-first trace generation (writes Parquet directly during recording).
    /// This is faster for large traces as it avoids intermediate Perfetto protobuf
    /// generation. By default, Parquet files are still converted to Perfetto format
    /// for compatibility; use --parquet-only to skip this conversion step.
    #[arg(long)]
    parquet_first: bool,

    /// Generate a DuckDB database from the parquet files after recording.
    /// The database can be queried using standard SQL for trace analysis.
    #[arg(long)]
    with_duckdb: bool,

    /// Path for the DuckDB database output (default: trace.duckdb in output-dir)
    #[arg(long, default_value = "trace.duckdb")]
    duckdb_output: PathBuf,
}

/// Configuration for the systing system tracing.
/// This struct contains all the runtime options needed by the system() function
/// and its helpers, separated from the CLI parsing concerns of Command.
#[derive(Debug)]
pub struct Config {
    /// Verbosity level (0 = warn, 1 = info, 2 = debug, 3+ = trace)
    pub verbosity: u8,
    /// PIDs to trace
    pub pid: Vec<u32>,
    /// Cgroups to trace
    pub cgroup: Vec<String>,
    /// Duration in seconds (0 = indefinite)
    pub duration: u64,
    /// Disable all stack traces
    pub no_stack_traces: bool,
    /// Ring buffer size in MiB (0 = default)
    pub ringbuf_size_mib: u32,
    /// Trace events to attach
    pub trace_event: Vec<String>,
    /// PIDs for trace events
    pub trace_event_pid: Vec<u32>,
    /// Use software events instead of hardware
    pub sw_event: bool,
    /// Record CPU frequency
    pub cpu_frequency: bool,
    /// Perf counters to collect
    pub perf_counter: Vec<String>,
    /// Disable CPU stack traces
    pub no_cpu_stack_traces: bool,
    /// Disable sleep stack traces
    pub no_sleep_stack_traces: bool,
    /// Disable interruptible sleep stack traces
    pub no_interruptible_stack_traces: bool,
    /// Trace event config files
    pub trace_event_config: Vec<String>,
    /// Continuous mode duration in seconds (0 = disabled)
    pub continuous: u64,
    /// Collect Python stack traces
    #[cfg(feature = "pystacks")]
    pub collect_pystacks: bool,
    /// Enable debuginfod for symbol resolution
    pub enable_debuginfod: bool,
    /// Disable scheduler tracing
    pub no_sched: bool,
    /// Enable syscall tracing
    pub syscalls: bool,
    /// Enable network recording
    pub network: bool,
    /// Skip DNS resolution for network addresses
    pub no_resolve_addresses: bool,
    /// Output directory for parquet files
    pub output_dir: PathBuf,
    /// Output path for Perfetto trace
    pub output: PathBuf,
    /// Skip Perfetto generation, keep only parquet
    pub parquet_only: bool,
    /// Use Parquet-first trace generation
    pub parquet_first: bool,
    /// Generate DuckDB database
    pub with_duckdb: bool,
    /// Path for DuckDB output
    pub duckdb_output: PathBuf,
}

impl From<Command> for Config {
    fn from(cmd: Command) -> Self {
        Config {
            verbosity: cmd.verbosity,
            pid: cmd.pid,
            cgroup: cmd.cgroup,
            duration: cmd.duration,
            no_stack_traces: cmd.no_stack_traces,
            ringbuf_size_mib: cmd.ringbuf_size_mib,
            trace_event: cmd.trace_event,
            trace_event_pid: cmd.trace_event_pid,
            sw_event: cmd.sw_event,
            cpu_frequency: cmd.cpu_frequency,
            perf_counter: cmd.perf_counter,
            no_cpu_stack_traces: cmd.no_cpu_stack_traces,
            no_sleep_stack_traces: cmd.no_sleep_stack_traces,
            no_interruptible_stack_traces: cmd.no_interruptible_stack_traces,
            trace_event_config: cmd.trace_event_config,
            continuous: cmd.continuous,
            #[cfg(feature = "pystacks")]
            collect_pystacks: cmd.collect_pystacks,
            enable_debuginfod: cmd.enable_debuginfod,
            no_sched: cmd.no_sched,
            syscalls: cmd.syscalls,
            network: cmd.network,
            no_resolve_addresses: cmd.no_resolve_addresses,
            output_dir: cmd.output_dir,
            output: cmd.output,
            parquet_only: cmd.parquet_only,
            parquet_first: cmd.parquet_first,
            with_duckdb: cmd.with_duckdb,
            duckdb_output: cmd.duckdb_output,
        }
    }
}

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: MEMLOCK_RLIMIT_BYTES,
        rlim_max: MEMLOCK_RLIMIT_BYTES,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!(
            "Failed to increase RLIMIT_MEMLOCK to {} bytes ({} MiB). This is required for BPF programs.",
            MEMLOCK_RLIMIT_BYTES,
            MEMLOCK_RLIMIT_BYTES >> 20
        );
    }

    Ok(())
}

/// Prepare the output directory for parquet files.
/// Creates the directory if it doesn't exist.
/// Renames existing .parquet files to .parquet.old (removing any previous .old files).
fn prepare_output_dir(dir: &std::path::Path) -> Result<()> {
    if !dir.exists() {
        fs::create_dir_all(dir)?;
        return Ok(());
    }

    // Rename existing .parquet files to .parquet.old
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension() == Some(std::ffi::OsStr::new("parquet")) {
            let old_path = path.with_extension("parquet.old");
            if old_path.exists() {
                fs::remove_file(&old_path)?;
            }
            fs::rename(&path, &old_path)?;
        }
    }
    Ok(())
}

/// Get the device and inode number of our PID namespace
/// Returns (dev, ino) or (0, 0) if the file doesn't exist or fails
fn detect_confidentiality_mode() -> u32 {
    // Read /sys/kernel/security/lockdown to check if confidentiality mode is enabled
    match fs::read_to_string("/sys/kernel/security/lockdown") {
        Ok(content) => {
            // The file contains "[none] integrity confidentiality" with the active mode in brackets
            if content.contains("[confidentiality]") {
                eprintln!(
                    "Kernel confidentiality mode detected - some BPF helpers will be restricted"
                );
                1
            } else {
                0
            }
        }
        Err(_) => {
            // If we can't read the file, assume no confidentiality mode
            0
        }
    }
}

fn get_pid_namespace_info() -> (u64, u64) {
    use std::fs;

    match fs::metadata("/proc/self/ns/pid") {
        Ok(metadata) => {
            // Get the device and inode numbers
            let dev = metadata.dev();
            let ino = metadata.ino();
            (dev, ino)
        }
        Err(_) => {
            // If we can't access the namespace file, return zeros
            (0, 0)
        }
    }
}

mod systing {
    include!(concat!(env!("OUT_DIR"), "/systing_system.skel.rs"));
}

pub trait SystingRecordEvent<T> {
    fn use_ringbuf(&self) -> bool {
        self.ringbuf().max_duration() > 0
    }
    fn ringbuf(&self) -> &RingBuffer<T>;
    fn ringbuf_mut(&mut self) -> &mut RingBuffer<T>;
    fn maybe_trigger(&mut self, _event: &T) -> bool {
        false
    }
    fn record_event(&mut self, event: T) -> bool
    where
        T: SystingEvent,
    {
        if self.use_ringbuf() {
            let ret = self.maybe_trigger(&event);
            self.ringbuf_mut().push_front(event);
            ret
        } else {
            self.handle_event(event);
            false
        }
    }
    fn drain_ringbuf(&mut self) {
        while let Some(event) = self.ringbuf_mut().pop_back() {
            self.handle_event(event);
        }
    }
    fn handle_event(&mut self, _event: T);
}

pub trait SystingEvent {
    fn ts(&self) -> u64;
    fn next_task_info(&self) -> Option<&task_info> {
        None
    }
    fn prev_task_info(&self) -> Option<&task_info> {
        None
    }
}

use systing::types::arg_desc;
use systing::types::arg_desc_array;
use systing::types::arg_type;
use systing::types::epoll_event_bpf;
use systing::types::event_type;
use systing::types::marker_match;
use systing::types::network_event;
use systing::types::packet_event;
use systing::types::perf_counter_event;
use systing::types::probe_event;
use systing::types::stack_event;
use systing::types::task_event;
use systing::types::task_info;

unsafe impl Plain for task_event {}
unsafe impl Plain for stack_event {}
unsafe impl Plain for perf_counter_event {}
unsafe impl Plain for probe_event {}
unsafe impl Plain for network_event {}
unsafe impl Plain for packet_event {}
unsafe impl Plain for epoll_event_bpf {}
unsafe impl Plain for arg_desc {}
unsafe impl Plain for arg_desc_array {}

impl SystingEvent for task_event {
    fn ts(&self) -> u64 {
        self.ts
    }
    fn next_task_info(&self) -> Option<&task_info> {
        match self.r#type {
            event_type::SCHED_SWITCH
            | event_type::SCHED_WAKING
            | event_type::SCHED_WAKEUP
            | event_type::SCHED_WAKEUP_NEW => Some(&self.next),
            _ => None,
        }
    }
    fn prev_task_info(&self) -> Option<&task_info> {
        Some(&self.prev)
    }
}

impl SystingEvent for stack_event {
    fn ts(&self) -> u64 {
        self.ts
    }
    fn next_task_info(&self) -> Option<&task_info> {
        Some(&self.task)
    }
}

impl SystingEvent for perf_counter_event {
    fn ts(&self) -> u64 {
        self.ts
    }
    fn next_task_info(&self) -> Option<&task_info> {
        Some(&self.task)
    }
}

impl SystingEvent for probe_event {
    fn ts(&self) -> u64 {
        self.ts
    }
    fn next_task_info(&self) -> Option<&task_info> {
        Some(&self.task)
    }
}

impl SystingEvent for network_event {
    fn ts(&self) -> u64 {
        self.start_ts
    }
    fn next_task_info(&self) -> Option<&task_info> {
        Some(&self.task)
    }
}

impl SystingEvent for packet_event {
    fn ts(&self) -> u64 {
        self.ts
    }
    fn next_task_info(&self) -> Option<&task_info> {
        None
    }
}

impl SystingEvent for epoll_event_bpf {
    fn ts(&self) -> u64 {
        self.ts
    }
    fn next_task_info(&self) -> Option<&task_info> {
        Some(&self.task)
    }
}

fn create_ring<'a, T>(
    map: &dyn libbpf_rs::MapCore,
    tx: Sender<T>,
) -> Result<libbpf_rs::RingBuffer<'a>, libbpf_rs::Error>
where
    T: Default + Plain + 'a,
{
    let mut builder = RingBufferBuilder::new();
    builder.add(map, move |data: &[u8]| {
        let mut event = T::default();
        plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");
        if tx.send(event).is_err() {
            // Receiver has been dropped, we can silently ignore this
            return -1;
        }
        0
    })?;
    builder.build()
}

fn consume_loop<T, N>(
    recorder: &Mutex<T>,
    rx: Receiver<N>,
    stop_tx: Sender<()>,
    task_info_tx: Sender<task_info>,
    pystack_symbol_tx: Option<Sender<N>>,
) where
    T: SystingRecordEvent<N>,
    N: Plain + SystingEvent + Copy,
{
    // Use a HashSet for deduplication - bloom filters have false positives which
    // can cause threads to not be recorded if the filter incorrectly says "seen"
    let mut seen_tasks: std::collections::HashSet<u64> = std::collections::HashSet::new();

    loop {
        let Ok(event) = rx.recv() else {
            break;
        };

        // Send task_info to process discovery thread only if not already seen
        if let Some(task_info) = event.next_task_info() {
            if seen_tasks.insert(task_info.tgidpid) {
                let _ = task_info_tx.send(*task_info);
            }
        }
        if let Some(task_info) = event.prev_task_info() {
            if seen_tasks.insert(task_info.tgidpid) {
                let _ = task_info_tx.send(*task_info);
            }
        }

        // Send event to pystack symbol loading thread (with rate limiting)
        if let Some(ref tx) = pystack_symbol_tx {
            tx.send(event)
                .expect("Failed to send event to pystack symbol loader thread");
        }

        let ret = recorder.lock().unwrap().record_event(event);

        if ret {
            stop_tx.send(()).expect("Failed to send stop signal");
            break;
        }
    }
}

fn spawn_recorder_threads(
    recorder: &Arc<SessionRecorder>,
    channels: RecorderChannels,
    opts: &Config,
    stop_tx: &Sender<()>,
    perf_counter_names: &[String],
    task_info_tx: &Sender<task_info>,
    pystack_symbol_tx: &Option<Sender<stack_event>>,
) -> Result<Vec<thread::JoinHandle<i32>>> {
    let RecorderChannels {
        event_rx,
        stack_rx,
        cache_rx,
        probe_rx,
        network_rx,
        packet_rx,
        epoll_rx,
    } = channels;

    let mut threads = Vec::new();

    // Always spawn sched recorder
    {
        let session_recorder = recorder.clone();
        let my_stop_tx = stop_tx.clone();
        let my_task_tx = task_info_tx.clone();
        threads.push(
            thread::Builder::new()
                .name("sched_recorder".to_string())
                .spawn(move || {
                    consume_loop::<SchedEventRecorder, task_event>(
                        &session_recorder.event_recorder,
                        event_rx,
                        my_stop_tx,
                        my_task_tx,
                        None,
                    );
                    0
                })?,
        );
    }

    // Always spawn stack recorder
    {
        let session_recorder = recorder.clone();
        let my_stop_tx = stop_tx.clone();
        let my_task_tx = task_info_tx.clone();
        let my_pystack_tx = pystack_symbol_tx.clone();
        threads.push(
            thread::Builder::new()
                .name("stack_recorder".to_string())
                .spawn(move || {
                    consume_loop::<StackRecorder, stack_event>(
                        &session_recorder.stack_recorder,
                        stack_rx,
                        my_stop_tx,
                        my_task_tx,
                        my_pystack_tx,
                    );
                    0
                })?,
        );
    }

    // Spawn probe recorder
    {
        let session_recorder = recorder.clone();
        let my_stop_tx = stop_tx.clone();
        let my_task_tx = task_info_tx.clone();
        threads.push(
            thread::Builder::new()
                .name("probe_recorder".to_string())
                .spawn(move || {
                    consume_loop::<SystingProbeRecorder, probe_event>(
                        &session_recorder.probe_recorder,
                        probe_rx,
                        my_stop_tx,
                        my_task_tx,
                        None,
                    );
                    0
                })?,
        );
    }

    // Spawn network recorder if network recording is enabled
    if opts.network {
        let session_recorder = recorder.clone();
        let my_stop_tx = stop_tx.clone();
        let my_task_tx = task_info_tx.clone();
        threads.push(
            thread::Builder::new()
                .name("network_recorder".to_string())
                .spawn(move || {
                    consume_loop::<network_recorder::NetworkRecorder, network_event>(
                        &session_recorder.network_recorder,
                        network_rx,
                        my_stop_tx,
                        my_task_tx,
                        None,
                    );
                    0
                })?,
        );

        // Packet recorder: processes packet events into network_recorder
        let session_recorder = recorder.clone();
        threads.push(
            thread::Builder::new()
                .name("packet_recorder".to_string())
                .spawn(move || {
                    // Use HashSet for deduplication - bloom filters have false positives
                    let mut seen_tasks: std::collections::HashSet<u64> =
                        std::collections::HashSet::new();
                    while let Ok(event) = packet_rx.recv() {
                        if let Some(task_info) = event.next_task_info() {
                            if seen_tasks.insert(task_info.tgidpid) {
                                session_recorder.maybe_record_task(task_info);
                            }
                        }
                        session_recorder
                            .network_recorder
                            .lock()
                            .unwrap()
                            .handle_packet_event(event);
                    }
                    0
                })?,
        );

        // Epoll recorder thread
        let session_recorder = recorder.clone();
        threads.push(
            thread::Builder::new()
                .name("epoll_recorder".to_string())
                .spawn(move || {
                    // Use HashSet for deduplication
                    let mut seen_tasks: std::collections::HashSet<u64> =
                        std::collections::HashSet::new();
                    while let Ok(event) = epoll_rx.recv() {
                        if let Some(task_info) = event.next_task_info() {
                            if seen_tasks.insert(task_info.tgidpid) {
                                session_recorder.maybe_record_task(task_info);
                            }
                        }
                        session_recorder
                            .network_recorder
                            .lock()
                            .unwrap()
                            .handle_epoll_event(event);
                    }
                    0
                })?,
        );
    }

    // Conditionally spawn perf counter recorder
    if perf_counter_names.is_empty() {
        // Drop the channel receiver if not using perf counters
        drop(cache_rx);
    } else {
        let session_recorder = recorder.clone();
        let my_stop_tx = stop_tx.clone();
        let my_task_tx = task_info_tx.clone();
        threads.push(
            thread::Builder::new()
                .name("perf_counter_recorder".to_string())
                .spawn(move || {
                    consume_loop::<PerfCounterRecorder, perf_counter_event>(
                        &session_recorder.perf_counter_recorder,
                        cache_rx,
                        my_stop_tx,
                        my_task_tx,
                        None,
                    );
                    0
                })?,
        );
    }

    Ok(threads)
}

fn dump_missed_events(skel: &systing::SystingSystemSkel, index: u32) -> u64 {
    let index = index.to_ne_bytes();
    let result = skel
        .maps
        .missed_events
        .lookup_percpu(&index, libbpf_rs::MapFlags::ANY);
    let mut missed = 0;
    if let Ok(Some(results)) = result {
        for cpu_data in results {
            let mut missed_events: u64 = 0;
            plain::copy_from_bytes(&mut missed_events, &cpu_data).unwrap();
            missed += missed_events;
        }
    }
    missed
}

fn is_old_kernel() -> bool {
    if let Some(kernel_version) = sysinfo::System::kernel_version() {
        let parts = kernel_version.split('.').collect::<Vec<&str>>();

        if parts.len() >= 2 {
            let major = parts[0].parse::<u64>().unwrap_or(0);
            let minor = parts[1].parse::<u64>().unwrap_or(0);

            // 6.10 is when they added bpf_get_attach_cookie() to raw_tracepoint
            !(major >= 6 && minor >= 10)
        } else {
            false
        }
    } else {
        false
    }
}

fn setup_perf_counters(
    opts: &Config,
    counters: &mut PerfCounters,
    perf_counter_names: &mut Vec<String>,
) -> Result<()> {
    if !opts.perf_counter.is_empty() {
        counters
            .discover()
            .with_context(|| "Failed to discover available perf counters on this system")?;

        // We can do things like topdown* to get all of the topdown counters, so we have to loop
        // through all of our options and populate the actual counter names that we want
        for counter in opts.perf_counter.iter() {
            let events = counters.event(counter);
            if events.is_none() {
                return Err(anyhow::anyhow!(
                    "Invalid perf counter: '{}'. Use a valid counter name or pattern (e.g., 'instructions', 'cycles', 'topdown*')",
                    counter
                ));
            }
            for event in events.unwrap() {
                if !perf_counter_names.contains(&event.name) {
                    perf_counter_names.push(event.name.clone());
                }
            }
        }
    }
    Ok(())
}

fn set_ringbuf_duration(recorder: &Arc<SessionRecorder>, duration_nanos: u64) {
    recorder
        .event_recorder
        .lock()
        .unwrap()
        .ringbuf
        .set_max_duration(duration_nanos);
    recorder
        .stack_recorder
        .lock()
        .unwrap()
        .ringbuf
        .set_max_duration(duration_nanos);
    recorder
        .perf_counter_recorder
        .lock()
        .unwrap()
        .ringbuf
        .set_max_duration(duration_nanos);
    recorder
        .sysinfo_recorder
        .lock()
        .unwrap()
        .ringbuf
        .set_max_duration(duration_nanos);
    recorder
        .probe_recorder
        .lock()
        .unwrap()
        .ringbuf
        .set_max_duration(duration_nanos);
}

fn configure_recorder(opts: &Config, recorder: &Arc<SessionRecorder>) {
    if opts.continuous > 0 {
        let duration_nanos = Duration::from_secs(opts.continuous).as_nanos() as u64;
        set_ringbuf_duration(recorder, duration_nanos);
    }
}

fn sd_notify() -> Result<()> {
    let Some(socket_path) = env::var_os("NOTIFY_SOCKET") else {
        return Ok(());
    };

    let sock = UnixDatagram::unbound().with_context(|| {
        "Failed to create unbound Unix datagram socket for systemd notification"
    })?;
    sock.connect(&socket_path)
        .with_context(|| format!("Failed to connect to systemd notify socket: {socket_path:?}"))?;
    sock.send("READY=1".as_bytes())
        .with_context(|| "Failed to send READY=1 message to systemd")?;
    Ok(())
}

/// Resolves the actual library path for a PID, handling chrooted processes.
/// Returns the resolved path with /proc/$PID/root prefix, or None if not found.
fn resolve_library_path_for_pid(pid: u32, lib_name: &str) -> Option<String> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use std::path::{Path, PathBuf};

    // Early return for empty library names
    if lib_name.is_empty() {
        return None;
    }

    let maps_path = PathBuf::from("/proc").join(pid.to_string()).join("maps");

    let maps_file = match File::open(&maps_path) {
        Ok(file) => file,
        Err(_) => return None, // Process may have exited, silent failure is acceptable
    };
    let reader = BufReader::new(maps_file);

    let lib_path = Path::new(lib_name);
    let is_absolute = lib_path.is_absolute();
    let lib_filename = lib_path.file_name()?.to_string_lossy();

    for line in reader.lines().map_while(Result::ok) {
        if !line.contains('/') {
            continue;
        }

        let mapped_path = match line.split_whitespace().nth(5) {
            Some(path) => path,
            None => continue,
        };

        // Validate that the mapped path is absolute
        if !mapped_path.starts_with('/') {
            continue;
        }

        let matches = if is_absolute {
            mapped_path == lib_name
        } else if let Some(mapped_filename) = Path::new(mapped_path).file_name() {
            mapped_filename
                .to_string_lossy()
                .contains(lib_filename.as_ref())
        } else {
            false
        };

        if matches {
            return Some(format!("/proc/{pid}/root{mapped_path}"));
        }
    }

    None
}

/// Convenience function to discover all Python processes by checking their main executable.
fn discover_python_processes() -> Vec<u32> {
    // Only discover main Python processes (TGIDs), not threads
    discover_processes_with_mapping("python", false)
        .map(|map| map.keys().cloned().collect())
        .unwrap_or_else(|_| Vec::new())
}

/// Discovers processes with a specific binary or library mapped.
/// Returns a map of PID -> resolved library path (with /proc/PID/root prefix).
/// Note: TOCTOU race - processes may exit between discovery and attachment.
fn discover_processes_with_mapping(
    target_path: &str,
    check_maps: bool,
) -> Result<HashMap<u32, String>> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use std::path::{Path, PathBuf};

    let mut discovered_pids = HashMap::new();

    let target_normalized = if target_path.contains('/') && !Path::new(target_path).is_absolute() {
        std::fs::canonicalize(target_path).unwrap_or_else(|e| {
            eprintln!("Warning: Could not resolve path '{target_path}': {e} - using as-is");
            PathBuf::from(target_path)
        })
    } else {
        PathBuf::from(target_path)
    };

    let target_str = target_normalized.to_string_lossy();
    let is_absolute = target_normalized.is_absolute();

    let proc_dir = match std::fs::read_dir("/proc") {
        Ok(dir) => dir,
        Err(e) => return Err(anyhow::anyhow!("Failed to read /proc: {e}")),
    };

    for entry in proc_dir.filter_map(Result::ok) {
        let pid_u32: u32 = match entry.file_name().to_str().and_then(|s| s.parse().ok()) {
            Some(pid) if pid > 2 => pid,
            _ => continue,
        };

        let proc_path = entry.path();

        // Skip threads - only process thread group leaders
        if let Ok(status) = std::fs::read_to_string(proc_path.join("status")) {
            let mut is_thread = false;
            for line in status.lines() {
                if let Some(tgid_str) = line.strip_prefix("Tgid:\t") {
                    if let Ok(tgid) = tgid_str.trim().parse::<u32>() {
                        if tgid != pid_u32 {
                            is_thread = true;
                            break;
                        }
                    }
                    break;
                }
            }
            if is_thread {
                continue;
            }
        }

        if let Ok(exe) = std::fs::read_link(proc_path.join("exe")) {
            if is_absolute {
                if exe == target_normalized {
                    let exe_str = exe.to_string_lossy();
                    let resolved_path = format!("/proc/{pid_u32}/root{exe_str}");
                    discovered_pids.insert(pid_u32, resolved_path);
                    continue; // Skip checking maps after finding exe match
                }
            } else if let Some(exe_filename) = exe.file_name() {
                let exe_name = exe_filename.to_string_lossy();
                if exe_name.contains(&*target_str) {
                    let exe_str = exe.to_string_lossy();
                    let resolved_path = format!("/proc/{pid_u32}/root{exe_str}");
                    discovered_pids.insert(pid_u32, resolved_path);
                    continue; // Skip checking maps after finding exe match
                }
            }
        }

        if check_maps {
            let maps_file = match File::open(proc_path.join("maps")) {
                Ok(file) => file,
                Err(_) => continue,
            };

            let reader = BufReader::new(maps_file);

            for line in reader.lines().map_while(Result::ok) {
                if !line.contains('/') {
                    continue;
                }

                let mapped_path = match line.split_whitespace().nth(5) {
                    Some(path) => path,
                    None => continue,
                };

                if !mapped_path.starts_with('/') {
                    continue;
                }

                let found = if is_absolute {
                    mapped_path == &*target_str
                } else if let Some(mapping_filename) = Path::new(mapped_path).file_name() {
                    mapping_filename.to_string_lossy().contains(&*target_str)
                } else {
                    false
                };

                if found {
                    let resolved_path = format!("/proc/{pid_u32}/root{mapped_path}");
                    discovered_pids.insert(pid_u32, resolved_path);
                    break;
                }
            }
        }
    }

    Ok(discovered_pids)
}

struct RecorderChannels {
    event_rx: Receiver<task_event>,
    stack_rx: Receiver<stack_event>,
    cache_rx: Receiver<perf_counter_event>,
    probe_rx: Receiver<probe_event>,
    network_rx: Receiver<network_event>,
    packet_rx: Receiver<packet_event>,
    epoll_rx: Receiver<epoll_event_bpf>,
}

fn setup_ringbuffers<'a>(
    skel: &systing::SystingSystemSkel,
    opts: &Config,
    perf_counter_names: &[String],
) -> Result<(Vec<(String, libbpf_rs::RingBuffer<'a>)>, RecorderChannels)> {
    let mut rings = Vec::new();
    let (event_tx, event_rx) = channel();
    let (stack_tx, stack_rx) = channel();
    let (cache_tx, cache_rx) = channel();
    let (probe_tx, probe_rx) = channel();
    let (network_tx, network_rx) = channel();
    let (packet_tx, packet_rx) = channel();
    let (epoll_tx, epoll_rx) = channel();

    let object = skel.object();

    for (i, map) in object.maps().enumerate() {
        let name = map.name().to_str().unwrap();
        if name.starts_with("ringbuf_events") {
            let ring = create_ring::<task_event>(&map, event_tx.clone())?;
            rings.push((format!("events_{i}").to_string(), ring));
        } else if name.starts_with("ringbuf_stack") {
            let ring = create_ring::<stack_event>(&map, stack_tx.clone())?;
            rings.push((name.to_string(), ring));
        } else if name.starts_with("ringbuf_perf_counter") {
            if !perf_counter_names.is_empty() {
                let ring = create_ring::<perf_counter_event>(&map, cache_tx.clone())?;
                rings.push((name.to_string(), ring));
            }
        } else if name.starts_with("ringbuf_probe") {
            let ring = create_ring::<probe_event>(&map, probe_tx.clone())?;
            rings.push((name.to_string(), ring));
        } else if name.starts_with("ringbuf_network") && opts.network {
            let ring = create_ring::<network_event>(&map, network_tx.clone())?;
            rings.push((name.to_string(), ring));
        } else if name.starts_with("ringbuf_packet") && opts.network {
            let ring = create_ring::<packet_event>(&map, packet_tx.clone())?;
            rings.push((name.to_string(), ring));
        } else if name.starts_with("ringbuf_epoll") && opts.network {
            let ring = create_ring::<epoll_event_bpf>(&map, epoll_tx.clone())?;
            rings.push((name.to_string(), ring));
        }
    }

    let channels = RecorderChannels {
        event_rx,
        stack_rx,
        cache_rx,
        probe_rx,
        network_rx,
        packet_rx,
        epoll_rx,
    };

    Ok((rings, channels))
}

/// Checks for probes that failed to attach and warns about them.
/// Uses the program's autoload() status to determine if it was expected to load,
/// eliminating the need to duplicate autoload conditions from configure_bpf_skeleton.
fn warn_failed_probe_attachments(skel: &systing::SystingSystemSkel) {
    use libbpf_rs::skel::Skel;

    let mut failed_count = 0;

    // Iterate over all programs and check if they were expected to load but failed to attach
    for prog in skel.object().progs() {
        let name = prog.name().to_string_lossy();

        // Skip programs that weren't set to autoload (they were intentionally disabled)
        if !prog.autoload() {
            continue;
        }

        // Check if this program's link exists in the skeleton
        // Programs that don't support auto-attach (like generic kprobe/uprobe/usdt handlers)
        // are skipped since they're attached manually
        let link_is_none = match name.as_ref() {
            // Scheduler probes
            "systing_sched_wakeup" => skel.links.systing_sched_wakeup.is_none(),
            "systing_sched_wakeup_new" => skel.links.systing_sched_wakeup_new.is_none(),
            "systing_sched_switch" => skel.links.systing_sched_switch.is_none(),
            "systing_sched_waking" => skel.links.systing_sched_waking.is_none(),
            "systing_sched_process_exit" => skel.links.systing_sched_process_exit.is_none(),
            "systing_sched_process_fork" => skel.links.systing_sched_process_fork.is_none(),
            // IRQ probes
            "systing_irq_handler_entry" => skel.links.systing_irq_handler_entry.is_none(),
            "systing_irq_handler_exit" => skel.links.systing_irq_handler_exit.is_none(),
            "systing_softirq_entry" => skel.links.systing_softirq_entry.is_none(),
            "systing_softirq_exit" => skel.links.systing_softirq_exit.is_none(),
            // Syscall probes
            "tracepoint__raw_syscalls__sys_enter" => {
                skel.links.tracepoint__raw_syscalls__sys_enter.is_none()
            }
            "tracepoint__raw_syscalls__sys_exit" => {
                skel.links.tracepoint__raw_syscalls__sys_exit.is_none()
            }
            // Network probes
            "tcp_sendmsg_entry" => skel.links.tcp_sendmsg_entry.is_none(),
            "tcp_sendmsg_exit" => skel.links.tcp_sendmsg_exit.is_none(),
            "udp_sendmsg_entry" => skel.links.udp_sendmsg_entry.is_none(),
            "udp_sendmsg_exit" => skel.links.udp_sendmsg_exit.is_none(),
            "tcp_recvmsg_entry" => skel.links.tcp_recvmsg_entry.is_none(),
            "tcp_recvmsg_exit" => skel.links.tcp_recvmsg_exit.is_none(),
            "udp_recvmsg_entry" => skel.links.udp_recvmsg_entry.is_none(),
            "udp_recvmsg_exit" => skel.links.udp_recvmsg_exit.is_none(),
            "skb_recv_udp_exit" => skel.links.skb_recv_udp_exit.is_none(),
            "udp_send_skb_entry" => skel.links.udp_send_skb_entry.is_none(),
            "udp_queue_rcv_one_skb_entry" => skel.links.udp_queue_rcv_one_skb_entry.is_none(),
            "udp_enqueue_schedule_skb_entry" => skel.links.udp_enqueue_schedule_skb_entry.is_none(),
            "tcp_transmit_skb_entry" => skel.links.tcp_transmit_skb_entry.is_none(),
            "net_dev_start_xmit" => skel.links.net_dev_start_xmit.is_none(),
            "tcp_rcv_established_entry" => skel.links.tcp_rcv_established_entry.is_none(),
            "tcp_queue_rcv_entry" => skel.links.tcp_queue_rcv_entry.is_none(),
            "tcp_data_queue_entry" => skel.links.tcp_data_queue_entry.is_none(),
            "skb_copy_datagram_iovec" => skel.links.skb_copy_datagram_iovec.is_none(),
            "tcp_send_probe0_entry" => skel.links.tcp_send_probe0_entry.is_none(),
            "tcp_send_ack_entry" => skel.links.tcp_send_ack_entry.is_none(),
            "tcp_retransmit_timer_entry" => skel.links.tcp_retransmit_timer_entry.is_none(),
            // Socket poll probes (for epoll/poll/select tracking)
            "tcp_poll_entry" => skel.links.tcp_poll_entry.is_none(),
            "tcp_poll_exit" => skel.links.tcp_poll_exit.is_none(),
            // Programs that are manually attached (skip auto-attach check)
            // These include: systing_usdt, systing_uprobe, systing_kprobe,
            // systing_tracepoint, systing_raw_tracepoint, systing_perf_event_clock
            _ => continue,
        };

        if link_is_none {
            eprintln!(
                "Warning: Probe '{}' ({}) failed to attach - some data may be missing",
                name,
                prog.section().to_string_lossy()
            );
            failed_count += 1;
        }
    }

    if failed_count > 0 {
        eprintln!("Warning: {failed_count} probe(s) failed to attach. Check dmesg for BPF errors.");
    }
}

fn configure_bpf_skeleton(
    open_skel: &mut systing::OpenSystingSystemSkel,
    opts: &Config,
    num_cpus: u32,
    old_kernel: bool,
    collect_pystacks: bool,
    recorder: &Arc<SessionRecorder>,
) -> Result<()> {
    // Setup probe recorder with trace events FIRST
    // We need to know if any marker events are configured before setting up rodata
    let has_markers = {
        let mut probe_recorder = recorder.probe_recorder.lock().unwrap();
        let mut rng = rand::rng();
        for tracepoint in opts.trace_event.iter() {
            probe_recorder
                .add_event_from_str(tracepoint, &mut rng)
                .with_context(|| format!("Failed to parse trace event: '{tracepoint}'"))?;
        }

        for config in opts.trace_event_config.iter() {
            probe_recorder
                .load_config(config, &mut rng)
                .with_context(|| format!("Failed to load trace event config file: '{config}'"))?;
        }

        // UPROBE/USDT validation removed: PIDs are now auto-discovered if not specified

        // Check if any marker events are configured
        probe_recorder
            .cookies
            .values()
            .any(|e| matches!(e.event, EventProbe::Marker(_)))
    };

    // Configure rodata with tool settings
    {
        let rodata = open_skel
            .maps
            .rodata_data
            .as_deref_mut()
            .expect("'rodata' is not mmap'ed, your kernel is too old");

        let (my_dev, my_ino) = get_pid_namespace_info();
        rodata.tool_config.num_cpus = num_cpus;
        rodata.tool_config.my_tgid = process::id();
        rodata.tool_config.my_dev = my_dev;
        rodata.tool_config.my_ino = my_ino;
        rodata.tool_config.no_cpu_stack_traces = opts.no_cpu_stack_traces as u32;
        rodata.tool_config.no_sleep_stack_traces = opts.no_sleep_stack_traces as u32;
        rodata.tool_config.no_interruptible_stack_traces =
            opts.no_interruptible_stack_traces as u32;
        rodata.tool_config.confidentiality_mode = detect_confidentiality_mode();
        if !opts.cgroup.is_empty() {
            rodata.tool_config.filter_cgroup = 1;
        }
        if opts.no_stack_traces {
            rodata.tool_config.no_stack_traces = 1;
        }
        if !opts.pid.is_empty() {
            rodata.tool_config.filter_pid = 1;
        }
        if collect_pystacks {
            rodata.tool_config.collect_pystacks = 1;
        }
        if opts.syscalls {
            rodata.tool_config.collect_syscalls = 1;
        }

        if has_markers {
            use syscalls::Sysno;
            rodata.tool_config.marker_syscall_nr = Sysno::faccessat2 as u32;
        }

        // Set wakeup threshold to 50% of ringbuf size for batched wakeups
        // Default ringbuf size is 50 MiB if not specified
        let ringbuf_size = if opts.ringbuf_size_mib > 0 {
            opts.ringbuf_size_mib as u64 * 1024 * 1024
        } else {
            50 * 1024 * 1024 // Default 50 MiB
        };
        rodata.tool_config.wakeup_data_size = ringbuf_size / 2;
    }

    // Configure ringbuf size if specified
    if opts.ringbuf_size_mib > 0 {
        let size = opts.ringbuf_size_mib * 1024 * 1024;
        let object = open_skel.open_object_mut();
        for mut map in object.maps_mut() {
            let name = map.name().to_str().unwrap().to_string();
            if name.starts_with("node") {
                map.set_max_entries(size).with_context(|| {
                    format!(
                        "Failed to set ringbuf size to {} MiB for map '{}'",
                        opts.ringbuf_size_mib, name
                    )
                })?;
            }
        }
    }

    // Set network ringbuffer maps to zero capacity if network recording is disabled
    if !opts.network {
        let object = open_skel.open_object_mut();
        for mut map in object.maps_mut() {
            let name = map.name().to_str().unwrap().to_string();
            if name.starts_with("ringbuf_network_events_")
                || name.starts_with("ringbuf_packet_events_")
                || name.starts_with("ringbuf_epoll_events_")
            {
                map.set_max_entries(1).with_context(|| {
                    format!("Failed to set network ringbuf map '{name}' to zero capacity")
                })?;
            }
        }
    }

    // Configure program autoload based on kernel version and options
    // If we're on an older kernel we can't use the raw_tracepoint version since it doesn't
    // have the cookie support. Newer kernels will use the raw_tracepoint version so don't need
    // to load the old tracepoint program.
    if old_kernel {
        open_skel.progs.systing_raw_tracepoint.set_autoload(false);
    } else {
        open_skel.progs.systing_tracepoint.set_autoload(false);
    }

    // Don't load scheduler tracepoints if --no-sched is set
    // This prevents them from being loaded into the kernel at all
    if opts.no_sched {
        open_skel.progs.systing_sched_wakeup.set_autoload(false);
        open_skel.progs.systing_sched_wakeup_new.set_autoload(false);
        open_skel.progs.systing_sched_switch.set_autoload(false);
        open_skel.progs.systing_sched_waking.set_autoload(false);
        open_skel
            .progs
            .systing_sched_process_exit
            .set_autoload(false);
    }

    // Only load fork tracepoint when --pid is specified
    // This hook tracks child processes created by traced processes
    if opts.pid.is_empty() {
        open_skel
            .progs
            .systing_sched_process_fork
            .set_autoload(false);
    }

    // Only load syscall tracepoints when syscall tracing is enabled OR marker events are configured
    // Marker events use the sys_enter tracepoint to intercept faccessat2 syscalls
    // This prevents unnecessary overhead from loading unused tracepoints
    if !opts.syscalls && !has_markers {
        open_skel
            .progs
            .tracepoint__raw_syscalls__sys_enter
            .set_autoload(false);
        open_skel
            .progs
            .tracepoint__raw_syscalls__sys_exit
            .set_autoload(false);
    }

    // Only load network programs when network recording is enabled
    // This prevents unnecessary overhead from loading unused kprobes and tracepoints
    if !opts.network {
        open_skel.progs.tcp_sendmsg_entry.set_autoload(false);
        open_skel.progs.tcp_sendmsg_exit.set_autoload(false);
        open_skel.progs.udp_sendmsg_entry.set_autoload(false);
        open_skel.progs.udp_sendmsg_exit.set_autoload(false);
        open_skel.progs.tcp_recvmsg_entry.set_autoload(false);
        open_skel.progs.tcp_recvmsg_exit.set_autoload(false);
        open_skel.progs.udp_recvmsg_entry.set_autoload(false);
        open_skel.progs.udp_recvmsg_exit.set_autoload(false);
        open_skel.progs.udp_send_skb_entry.set_autoload(false);
        open_skel
            .progs
            .udp_queue_rcv_one_skb_entry
            .set_autoload(false);
        open_skel
            .progs
            .udp_enqueue_schedule_skb_entry
            .set_autoload(false);
        open_skel.progs.tcp_transmit_skb_entry.set_autoload(false);
        open_skel
            .progs
            .tcp_rcv_established_entry
            .set_autoload(false);
        open_skel.progs.tcp_queue_rcv_entry.set_autoload(false);
        open_skel.progs.tcp_data_queue_entry.set_autoload(false);
        open_skel.progs.net_dev_start_xmit.set_autoload(false);
        open_skel.progs.skb_copy_datagram_iovec.set_autoload(false);
        open_skel.progs.skb_recv_udp_exit.set_autoload(false);
        open_skel.progs.tcp_send_probe0_entry.set_autoload(false);
        open_skel.progs.tcp_send_ack_entry.set_autoload(false);
        open_skel
            .progs
            .tcp_retransmit_timer_entry
            .set_autoload(false);
        // Disable socket poll probes when network is disabled
        open_skel.progs.tcp_poll_entry.set_autoload(false);
        open_skel.progs.tcp_poll_exit.set_autoload(false);
    }

    Ok(())
}

fn setup_perf_events(
    skel: &mut systing::SystingSystemSkel,
    opts: &Config,
    counters: &PerfCounters,
    perf_counter_names: &[String],
    num_cpus: u32,
) -> Result<(Vec<libbpf_rs::Link>, Vec<PerfOpenEvents>)> {
    let mut perf_links = Vec::new();
    let mut event_files_vec = Vec::new();

    // Set up clock perf events with automatic VM detection and fallback
    let clock_files = {
        let mut clock_files = PerfOpenEvents::default();
        let mut clock_event = PerfHwEvent {
            name: "clock".to_string(),
            event_type: if opts.sw_event {
                perf::PERF_TYPE_SOFTWARE
            } else {
                perf::PERF_TYPE_HARDWARE
            },
            event_config: if opts.sw_event {
                perf::PERF_COUNT_SW_CPU_CLOCK
            } else {
                perf::PERF_COUNT_HW_CPU_CYCLES
            },
            disabled: false,
            need_slots: false,
            cpus: (0..num_cpus).collect(),
        };

        clock_files.add_hw_event(clock_event.clone())?;

        // Try to open the events, handle VM detection
        if let Err(e) = clock_files.open_events(None, PERF_CLOCK_SAMPLE_PERIOD) {
            // Check if this is a VM-related error (ErrorKind::NotFound)
            if e.kind() == std::io::ErrorKind::NotFound && !opts.sw_event {
                // Detected VM environment, automatically retry with software events
                eprintln!("Detected virtualized environment, automatically switching to software events (--sw-event)");

                // Modify the event to use software events
                clock_event.event_type = perf::PERF_TYPE_SOFTWARE;
                clock_event.event_config = perf::PERF_COUNT_SW_CPU_CLOCK;

                // Recreate clock_files with the modified event
                clock_files = PerfOpenEvents::default();
                clock_files.add_hw_event(clock_event)?;
                clock_files.open_events(None, PERF_CLOCK_SAMPLE_PERIOD)?;
            } else {
                // Not a VM error or already using software events, propagate the error
                return Err(e.into());
            }
        }

        clock_files
    };

    // Attach clock events to BPF program
    for (_, file) in clock_files {
        let link = skel
            .progs
            .systing_perf_event_clock
            .attach_perf_event_with_opts(
                file.as_raw_fd(),
                libbpf_rs::PerfEventOpts {
                    cookie: 0,
                    ..Default::default()
                },
            )?;
        perf_links.push(link);
    }

    // Determine if we need slots for topdown counters
    let need_slots = perf_counter_names
        .iter()
        .any(|counter| counter.starts_with("topdown"));

    // Setup slots files if needed
    let mut slots_files = PerfOpenEvents::default();
    if need_slots {
        let slot_hwevents = counters.event("slots");
        let slot_hwevents = if let Some(slot_hwevents) = slot_hwevents {
            slot_hwevents
        } else {
            Err(anyhow::anyhow!(
                "Failed to find 'slots' perf event required for topdown counters. This may not be supported on your CPU."
            ))?
        };
        for event in slot_hwevents.iter() {
            slots_files.add_hw_event(event.clone())?;
        }
        slots_files
            .open_events(None, 0)
            .with_context(|| "Failed to open 'slots' perf events for topdown counters")?;
        slots_files
            .enable()
            .with_context(|| "Failed to enable 'slots' perf events")?;
    }

    // Setup counter events and populate perf_counters map
    for (index, event_name) in perf_counter_names.iter().enumerate() {
        let mut event_files = PerfOpenEvents::default();
        let hwevents = counters.event(event_name).unwrap();

        for hwevent in hwevents {
            event_files.add_hw_event(hwevent)?;
        }
        event_files.open_events(Some(&slots_files), 0)?;

        let floor = index * num_cpus as usize;
        for (cpu, file) in &event_files {
            let key: u32 = (floor + *cpu as usize).try_into().unwrap();
            let key_val = key.to_ne_bytes();
            let fd_val = file.as_raw_fd().to_ne_bytes();
            skel.maps
                .perf_counters
                .update(&key_val, &fd_val, libbpf_rs::MapFlags::ANY)?;
        }
        event_files.enable()?;
        event_files_vec.push(event_files);
    }

    // Keep slots_files alive if used
    if need_slots {
        event_files_vec.push(slots_files);
    }

    Ok((perf_links, event_files_vec))
}

/// Returns PIDs to attach probes to with their resolved library paths.
/// Returns (pid_to_path_map, is_auto_discovered).
fn resolve_pids_for_probe(
    opts: &Config,
    target_path: &str,
    probe_type: &str,
    probe_name: &str,
) -> Result<(HashMap<u32, String>, bool)> {
    if opts.trace_event_pid.is_empty() {
        let discovered = discover_processes_with_mapping(target_path, true).with_context(|| {
            format!("Failed to discover processes for {probe_type} probe {probe_name}")
        })?;
        if discovered.is_empty() {
            eprintln!(
                "Warning: No processes found with {target_path} loaded for {probe_type} probe {probe_name}"
            );
        } else {
            let pids: Vec<u32> = discovered.keys().cloned().collect();
            println!(
                "Auto-discovered {} process(es) with {target_path} loaded: {:?}",
                discovered.len(),
                pids
            );
        }
        Ok((discovered, true))
    } else {
        // For user-specified PIDs, resolve paths individually
        let mut pid_map = HashMap::new();
        for pid in &opts.trace_event_pid {
            if let Some(resolved_path) = resolve_library_path_for_pid(*pid, target_path) {
                pid_map.insert(*pid, resolved_path);
            } else {
                pid_map.insert(*pid, target_path.to_string());
            }
        }
        Ok((pid_map, false))
    }
}

fn attach_probes(
    skel: &mut systing::SystingSystemSkel,
    recorder: &Arc<SessionRecorder>,
    opts: &Config,
    old_kernel: bool,
) -> Result<Vec<libbpf_rs::Link>> {
    let mut probe_links = Vec::new();
    let probe_recorder = recorder.probe_recorder.lock().unwrap();

    for event in probe_recorder.config_events.values() {
        let mut desc_array = arg_desc_array {
            num_args: event.args.len() as u8,
            pad: [0; 3],
            args: [arg_desc {
                arg_type: arg_type::ARG_NONE,
                arg_index: 0,
            }; 4],
        };

        for (i, arg) in event.args.iter().enumerate() {
            let bpf_arg_type = match arg.arg_type {
                EventKeyType::String => arg_type::ARG_STRING,
                EventKeyType::Long => arg_type::ARG_LONG,
                EventKeyType::Retval => arg_type::ARG_RETVAL,
            };

            desc_array.args[i] = arg_desc {
                arg_type: bpf_arg_type,
                arg_index: arg.arg_index as i32,
            };
        }

        // Safe because we're not padded
        let desc_data = unsafe { plain::as_bytes(&desc_array) };
        skel.maps.event_key_types.update(
            &event.cookie.to_ne_bytes(),
            desc_data,
            libbpf_rs::MapFlags::ANY,
        )?;

        if event.stack {
            let stack_flag: u8 = 1;
            skel.maps.event_stack_capture.update(
                &event.cookie.to_ne_bytes(),
                &stack_flag.to_ne_bytes(),
                libbpf_rs::MapFlags::ANY,
            )?;
        }

        match &event.event {
            EventProbe::Usdt(usdt) => {
                // Skip USDT probes in confidentiality mode as they use restricted helpers
                if detect_confidentiality_mode() == 1 {
                    eprintln!(
                        "Skipping USDT probe {}:{}:{} - not supported in confidentiality mode",
                        usdt.path, usdt.provider, usdt.name
                    );
                } else {
                    let (pid_path_map, is_auto_discovered) = resolve_pids_for_probe(
                        opts,
                        &usdt.path,
                        "USDT",
                        &format!("{}:{}", usdt.provider, usdt.name),
                    )?;

                    for (pid, resolved_path) in pid_path_map.iter() {
                        // For USDT, libbpf needs the actual path to the ELF file to read USDT metadata.
                        // Check if we can use the direct path or need the resolved path
                        let direct_path_exists = std::path::Path::new(&usdt.path).exists();

                        let usdt_path = if direct_path_exists {
                            &usdt.path
                        } else {
                            resolved_path.as_str()
                        };

                        let attach_result = skel.progs.systing_usdt.attach_usdt_with_opts(
                            *pid as i32,
                            usdt_path,
                            &usdt.provider,
                            &usdt.name,
                            UsdtOpts {
                                cookie: event.cookie,
                                ..Default::default()
                            },
                        );

                        match attach_result {
                            Ok(link) => {
                                if usdt_path != usdt.path.as_str() {
                                    println!(
                                        "Attached USDT probe {}:{} to PID {} using path: {}",
                                        usdt.provider, usdt.name, *pid, usdt_path
                                    );
                                }
                                probe_links.push(link);
                            }
                            Err(e) => {
                                if is_auto_discovered {
                                    // Non-fatal for auto-discovered PIDs (process may have exited)
                                    eprintln!(
                                        "Warning: Failed to attach USDT probe {}:{}:{} to PID {} (using: {}): {}",
                                        usdt.path, usdt.provider, usdt.name, *pid, usdt_path, e
                                    );
                                } else {
                                    // Fatal for user-specified PIDs
                                    return Err(e).with_context(|| {
                                        format!(
                                            "Failed to attach USDT probe {}:{}:{} to PID {} (using: {})",
                                            usdt.path, usdt.provider, usdt.name, *pid, usdt_path
                                        )
                                    });
                                }
                            }
                        }
                    }
                }
            }
            EventProbe::UProbe(uprobe) => {
                let (pid_path_map, is_auto_discovered) = resolve_pids_for_probe(
                    opts,
                    &uprobe.path,
                    if uprobe.retprobe {
                        "uretprobe"
                    } else {
                        "uprobe"
                    },
                    &uprobe.func_name,
                )?;

                for (pid, resolved_path) in pid_path_map.iter() {
                    // For uprobes, use the actual file path if it exists
                    let uprobe_path = if std::path::Path::new(&uprobe.path).exists() {
                        &uprobe.path
                    } else {
                        resolved_path.as_str()
                    };

                    let attach_result = skel.progs.systing_uprobe.attach_uprobe_with_opts(
                        *pid as i32,
                        uprobe_path,
                        uprobe.offset as usize,
                        UprobeOpts {
                            cookie: event.cookie,
                            retprobe: uprobe.retprobe,
                            func_name: Some(uprobe.func_name.clone()),
                            ..Default::default()
                        },
                    );

                    match attach_result {
                        Ok(link) => {
                            if uprobe_path != uprobe.path.as_str() {
                                println!(
                                    "Attached {} '{}' to PID {} using path: {}",
                                    if uprobe.retprobe {
                                        "uretprobe"
                                    } else {
                                        "uprobe"
                                    },
                                    uprobe.func_name,
                                    *pid,
                                    uprobe_path
                                );
                            }
                            probe_links.push(link);
                        }
                        Err(e) => {
                            if is_auto_discovered {
                                // Non-fatal for auto-discovered PIDs (process may have exited)
                                eprintln!(
                                    "Warning: Failed to attach {} '{}' at {}+{:#x} to PID {} (using: {}): {}",
                                    if uprobe.retprobe { "uretprobe" } else { "uprobe" },
                                    uprobe.func_name,
                                    uprobe.path,
                                    uprobe.offset,
                                    *pid,
                                    uprobe_path,
                                    e
                                );
                            } else {
                                // Fatal for user-specified PIDs
                                return Err(e).with_context(|| {
                                    format!(
                                        "Failed to attach {} '{}' at {}+{:#x} to PID {} (using: {})",
                                        if uprobe.retprobe { "uretprobe" } else { "uprobe" },
                                        uprobe.func_name,
                                        uprobe.path,
                                        uprobe.offset,
                                        *pid,
                                        uprobe_path
                                    )
                                });
                            }
                        }
                    }
                }
            }
            EventProbe::KProbe(kprobe) => {
                let link = skel
                    .progs
                    .systing_kprobe
                    .attach_kprobe_with_opts(
                        kprobe.retprobe,
                        &kprobe.func_name,
                        libbpf_rs::KprobeOpts {
                            cookie: event.cookie,
                            ..Default::default()
                        },
                    )
                    .with_context(|| format!(
                        "Failed to attach kprobe '{}' ({}retprobe). Ensure the function exists in the kernel.",
                        kprobe.func_name,
                        if kprobe.retprobe { "" } else { "not " }
                    ))?;
                probe_links.push(link);
            }
            EventProbe::Tracepoint(tracepoint) => {
                // Validate that we're not trying to capture arguments on old kernels
                // where raw_tracepoint doesn't support bpf_get_attach_cookie()
                if old_kernel && !event.args.is_empty() {
                    return Err(anyhow::anyhow!(
                        "Cannot capture tracepoint arguments on kernel < 6.10. \
                         Tracepoint '{}:{}' has {} argument(s) configured, but this kernel \
                         version doesn't support bpf_get_attach_cookie() for raw_tracepoint programs. \
                         Either upgrade to kernel 6.10+ or remove the argument specifications from the event configuration.",
                        tracepoint.category,
                        tracepoint.name,
                        event.args.len()
                    ));
                }

                let link = if old_kernel {
                    let category =
                        libbpf_rs::TracepointCategory::Custom(tracepoint.category.clone());
                    skel.progs.systing_tracepoint.attach_tracepoint_with_opts(
                        category,
                        &tracepoint.name,
                        TracepointOpts {
                            cookie: event.cookie,
                            ..Default::default()
                        },
                    )
                } else {
                    skel.progs
                        .systing_raw_tracepoint
                        .attach_raw_tracepoint_with_opts(
                            &tracepoint.name,
                            RawTracepointOpts {
                                cookie: event.cookie,
                                ..Default::default()
                            },
                        )
                }
                .with_context(|| format!(
                    "Failed to attach tracepoint '{}:{}'. Verify the tracepoint exists with: ls /sys/kernel/debug/tracing/events/{}/{}",
                    tracepoint.category, tracepoint.name, tracepoint.category, tracepoint.name
                ))?;
                probe_links.push(link);
            }
            EventProbe::Marker(marker) => {
                let mut key = [0u8; 64];
                let bytes = marker.match_string.as_bytes();
                let len = bytes.len().min(63);
                key[..len].copy_from_slice(&bytes[..len]);

                let mut args = [arg_desc {
                    arg_type: arg_type::ARG_NONE,
                    arg_index: 0,
                }; 4];
                for (i, arg) in event.args.iter().enumerate() {
                    let bpf_arg_type = match arg.arg_type {
                        EventKeyType::String => arg_type::ARG_STRING,
                        EventKeyType::Long => arg_type::ARG_LONG,
                        EventKeyType::Retval => arg_type::ARG_RETVAL,
                    };
                    args[i] = arg_desc {
                        arg_type: bpf_arg_type,
                        arg_index: arg.arg_index as i32,
                    };
                }

                let marker_match_value = marker_match {
                    cookie: event.cookie,
                    num_args: event.args.len() as u8,
                    args,
                    ..Default::default()
                };

                let value_data = unsafe { plain::as_bytes(&marker_match_value) };
                skel.maps
                    .marker_matches
                    .update(&key, value_data, libbpf_rs::MapFlags::ANY)?;
            }
            _ => {}
        }
    }

    Ok(probe_links)
}

struct ThreadHandles {
    ringbuf_threads: Vec<thread::JoinHandle<i32>>,
    sysinfo_thread: Option<thread::JoinHandle<i32>>,
    recorder_threads: Vec<thread::JoinHandle<i32>>,
    discovery_thread: thread::JoinHandle<i32>,
    symbol_loader_thread: thread::JoinHandle<i32>,
    task_info_tx: Sender<task_info>,
    pystack_symbol_tx: Sender<stack_event>,
}

fn run_tracing_loop(
    handles: ThreadHandles,
    opts: &Config,
    stop_tx: Sender<()>,
    stop_rx: Receiver<()>,
    ringbuf_shutdown: Arc<ShutdownSignal>,
    shutdown_signal: Arc<AtomicBool>,
    skel: &mut systing::SystingSystemSkel,
) -> Result<()> {
    sd_notify()?;

    if opts.duration > 0 {
        println!("Tracing for {} seconds", opts.duration);
        thread::sleep(Duration::from_secs(opts.duration));
    } else {
        ctrlc::set_handler(move || stop_tx.send(()).expect("Could not send signal on channel."))
            .expect("Error setting Ctrl-C handler");
        if opts.continuous > 0 {
            println!("Tracing in a continues loop of {} seconds", opts.continuous);
            println!("Will stop if a trigger is specified, otherwise Ctrl-C to stop");
        } else {
            println!("Tracing indefinitely...");
            println!("Press Ctrl-C to stop");
        }
        stop_rx
            .recv()
            .expect("Could not receive signal on channel.");
    }

    if opts.continuous > 0 {
        println!("Asked to stop, waiting {CONTINUOUS_MODE_STOP_DELAY_SECS} second before stopping");
        thread::sleep(Duration::from_secs(CONTINUOUS_MODE_STOP_DELAY_SECS));
    }
    println!("Stopping...");
    skel.maps.data_data.as_deref_mut().unwrap().tracing_enabled = false;
    ringbuf_shutdown.signal();
    for thread in handles.ringbuf_threads {
        thread.join().expect("Failed to join thread");
    }
    shutdown_signal.store(true, Ordering::Relaxed);
    if let Some(thread) = handles.sysinfo_thread {
        thread.join().expect("Failed to join sysinfo thread");
    }
    for thread in handles.recorder_threads {
        thread.join().expect("Failed to join receiver thread");
    }
    // Drop senders to allow background threads to exit
    drop(handles.task_info_tx);
    drop(handles.pystack_symbol_tx);
    handles
        .discovery_thread
        .join()
        .expect("Failed to join discovery thread");
    handles
        .symbol_loader_thread
        .join()
        .expect("Failed to join symbol thread");

    println!("Missed sched/IRQ events: {}", dump_missed_events(skel, 0));
    println!("Missed stack events: {}", dump_missed_events(skel, 1));
    println!("Missed probe events: {}", dump_missed_events(skel, 2));
    println!("Missed cache events: {}", dump_missed_events(skel, 3));
    if opts.network {
        println!("Missed network events: {}", dump_missed_events(skel, 4));
        println!("Missed packet events: {}", dump_missed_events(skel, 5));
        println!("Missed poll events: {}", dump_missed_events(skel, 6));
    }

    Ok(())
}

fn system(opts: Config) -> Result<()> {
    let num_cpus = libbpf_rs::num_possible_cpus().unwrap() as u32;
    let mut perf_counter_names = Vec::new();
    let mut counters = PerfCounters::default();
    let (stop_tx, stop_rx) = channel();
    let old_kernel = is_old_kernel();

    setup_perf_counters(&opts, &mut counters, &mut perf_counter_names)?;

    let recorder = Arc::new(SessionRecorder::new(
        opts.enable_debuginfod,
        !opts.no_resolve_addresses,
    ));
    configure_recorder(&opts, &recorder);
    recorder.snapshot_clocks();

    // If using parquet_first mode, initialize streaming parquet output BEFORE recording starts
    if opts.parquet_first {
        prepare_output_dir(&opts.output_dir)?;
        recorder.init_streaming_parquet(&opts.output_dir)?;
        eprintln!(
            "Initialized streaming parquet output to {:?}",
            opts.output_dir
        );
    }

    {
        let mut skel_builder = systing::SystingSystemSkelBuilder::default();
        if opts.verbosity > 0 {
            skel_builder.obj_builder.debug(true);
        }

        #[cfg(not(feature = "pystacks"))] // set to false when feature is off
        let collect_pystacks = false;
        #[cfg(feature = "pystacks")] // use option value if feature is on
        let collect_pystacks = opts.collect_pystacks;

        let mut open_object = MaybeUninit::uninit();
        let mut open_skel = skel_builder.open(&mut open_object).with_context(|| {
            "Failed to open BPF skeleton. Ensure BPF is supported on your kernel."
        })?;

        // Configure the BPF skeleton with all settings
        configure_bpf_skeleton(
            &mut open_skel,
            &opts,
            num_cpus,
            old_kernel,
            collect_pystacks,
            &recorder,
        )?;

        for counter in perf_counter_names.iter() {
            recorder
                .perf_counter_recorder
                .lock()
                .unwrap()
                .perf_counters
                .push(counter.clone());
        }

        let num_events = perf_counter_names.len() as u32;
        open_skel
            .maps
            .rodata_data
            .as_deref_mut()
            .unwrap()
            .tool_config
            .num_perf_counters = num_events;
        open_skel
            .maps
            .perf_counters
            .set_max_entries(num_cpus * num_events)
            .with_context(|| {
                format!(
                    "Failed to set perf_counters map size to {} entries",
                    num_cpus * num_events
                )
            })?;
        if num_events > 0 {
            open_skel
                .maps
                .last_perf_counter_value
                .set_max_entries(num_events)
                .with_context(|| {
                    format!(
                        "Failed to set last_perf_counter_value map size to {num_events} entries"
                    )
                })?;
        }

        open_skel
            .maps
            .missed_events
            .set_max_entries(num_cpus)
            .with_context(|| {
                format!("Failed to set missed_events map size to {num_cpus} entries")
            })?;

        let mut skel = open_skel.load().with_context(|| {
            "Failed to load BPF skeleton into kernel. Check dmesg for BPF verifier errors."
        })?;
        for cgroup in opts.cgroup.iter() {
            let metadata = std::fs::metadata(cgroup)
                .with_context(|| format!("Failed to access cgroup path: {cgroup}"))?;
            let cgroupid = metadata.ino().to_ne_bytes();
            let val = (1_u8).to_ne_bytes();
            skel.maps
                .cgroups
                .update(&cgroupid, &val, libbpf_rs::MapFlags::ANY)
                .with_context(|| format!("Failed to add cgroup {cgroup} to BPF map"))?;
        }

        for pid in opts.pid.iter() {
            let val = (1_u8).to_ne_bytes();
            skel.maps
                .pids
                .update(&pid.to_ne_bytes(), &val, libbpf_rs::MapFlags::ANY)
                .with_context(|| format!("Failed to add PID {pid} to BPF map"))?;
        }

        if collect_pystacks {
            // Determine which PIDs to use for pystacks
            let pystacks_pids = if opts.pid.is_empty() {
                // No PIDs specified, discover all Python processes
                let discovered = discover_python_processes();
                if discovered.is_empty() {
                    println!("Warning: No Python processes found on the system");
                } else {
                    println!(
                        "Discovered {} Python process(es) for pystacks: {:?}",
                        discovered.len(),
                        discovered
                    );
                }
                discovered
            } else {
                // Use the PIDs specified by the user
                println!("Using specified PIDs for pystacks: {:?}", opts.pid);
                opts.pid.clone()
            };

            recorder
                .stack_recorder
                .lock()
                .unwrap()
                .init_pystacks(&pystacks_pids, skel.object());
        }

        let (rings, channels) = setup_ringbuffers(&skel, &opts, &perf_counter_names)?;

        // Create shutdown signal for receiver threads
        let shutdown_signal = Arc::new(AtomicBool::new(false));

        // Create channel for process discovery
        let (task_info_tx, task_info_rx) = channel();

        // Spawn dedicated process discovery thread
        let discovery_recorder = recorder.clone();
        let discovery_thread = thread::Builder::new()
            .name("process_discovery".to_string())
            .spawn(move || {
                while let Ok(task_info) = task_info_rx.recv() {
                    discovery_recorder.maybe_record_task(&task_info);
                }
                0
            })?;

        // Create channel for Python symbol loading
        let (pystack_symbol_tx, pystack_symbol_rx) = channel();

        // Spawn dedicated Python symbol loading thread
        // Clone the Arc<StackWalkerRun> directly to avoid locking the entire StackRecorder
        let psr = recorder.stack_recorder.lock().unwrap().psr.clone();
        let symbol_thread = thread::Builder::new()
            .name("pystack_symbol_loader".to_string())
            .spawn(move || {
                while let Ok(event) = pystack_symbol_rx.recv() {
                    psr.load_pystack_symbols(&event);
                }
                0
            })?;

        // Spawn all recorder threads
        let recv_threads = spawn_recorder_threads(
            &recorder,
            channels,
            &opts,
            &stop_tx,
            &perf_counter_names,
            &task_info_tx,
            &Some(pystack_symbol_tx.clone()),
        )?;

        // Set up perf events (clock events and counter events)
        let (_perf_links, _events_files) =
            setup_perf_events(&mut skel, &opts, &counters, &perf_counter_names, num_cpus)?;

        skel.attach().with_context(|| {
            "Failed to attach BPF programs to tracepoints. Check if tracepoints are enabled."
        })?;

        // Check for any probes that failed to attach and warn about them
        warn_failed_probe_attachments(&skel);

        // Attach any usdt's that we may have
        let _probe_links = attach_probes(&mut skel, &recorder, &opts, old_kernel)?;

        let mut ringbuf_threads = Vec::new();
        let ringbuf_shutdown = Arc::new(ShutdownSignal::new()?);
        for (name, ring) in rings {
            let shutdown_fd = ringbuf_shutdown.fd();
            let epoll_fd = create_ringbuf_epoll(ring.epoll_fd(), shutdown_fd)?;
            ringbuf_threads.push(thread::Builder::new().name(name).spawn(move || {
                let mut events = [libc::epoll_event { events: 0, u64: 0 }; 2];
                loop {
                    let n = unsafe {
                        libc::epoll_wait(epoll_fd.as_raw_fd(), events.as_mut_ptr(), 2, -1)
                    };

                    if n < 0 {
                        let err = io::Error::last_os_error();
                        if err.kind() == io::ErrorKind::Interrupted {
                            continue;
                        }
                        break;
                    }

                    let mut should_exit = false;
                    for event in events.iter().take(n as usize) {
                        if event.u64 == 1 {
                            should_exit = true;
                        }
                    }

                    let _ = ring.consume();

                    if should_exit {
                        break;
                    }
                }
                0
            })?);
        }

        // Start the sysinfo recorder if it's enabled
        let mut sysinfo_thread = None;
        if opts.cpu_frequency {
            let shutdown_clone = shutdown_signal.clone();
            let sysinfo_recorder = recorder.clone();
            sysinfo_thread = Some(
                thread::Builder::new()
                    .name("sysinfo_recorder".to_string())
                    .spawn(move || {
                        let mut sys = sysinfo::System::new_with_specifics(
                            sysinfo::RefreshKind::nothing()
                                .with_cpu(sysinfo::CpuRefreshKind::nothing().with_frequency()),
                        );

                        loop {
                            if shutdown_clone.load(Ordering::Relaxed) {
                                break;
                            }
                            sys.refresh_cpu_frequency();
                            let ts = get_clock_value(libc::CLOCK_BOOTTIME);
                            {
                                let mut recorder =
                                    sysinfo_recorder.sysinfo_recorder.lock().unwrap();
                                for (i, cpu) in sys.cpus().iter().enumerate() {
                                    let event = SysInfoEvent {
                                        ts,
                                        cpu: i as u32,
                                        frequency: cpu.frequency() as i64,
                                    };
                                    recorder.record_event(event);
                                }
                            }
                            thread::sleep(Duration::from_millis(SYSINFO_REFRESH_INTERVAL_MS));
                        }
                        0
                    })?,
            );
        }

        let handles = ThreadHandles {
            ringbuf_threads,
            sysinfo_thread,
            recorder_threads: recv_threads,
            discovery_thread,
            symbol_loader_thread: symbol_thread,
            task_info_tx,
            pystack_symbol_tx,
        };

        run_tracing_loop(
            handles,
            &opts,
            stop_tx,
            stop_rx,
            ringbuf_shutdown,
            shutdown_signal,
            &mut skel,
        )?;

        // Load socket metadata from BPF map after tracing completes
        // This must be done while skel is still alive
        if opts.network {
            recorder
                .network_recorder
                .lock()
                .unwrap()
                .load_socket_metadata(&skel.maps.socket_metadata_map);
        }
    }

    if opts.continuous > 0 {
        println!("Draining recorder ringbuffers...");
        recorder.drain_all_ringbufs();
    }

    // Prepare output directory (if not already done for streaming)
    if !opts.parquet_first {
        prepare_output_dir(&opts.output_dir)?;
    }

    // Write trace files using either Parquet-first or legacy path
    if opts.parquet_first {
        // Parquet-first path: write directly to Parquet files
        println!(
            "Writing Parquet trace files (direct) to {}...",
            opts.output_dir.display()
        );
        recorder.generate_parquet_trace(&opts.output_dir)?;
        println!("Successfully wrote Parquet trace files");
    } else {
        // Legacy path: generate TracePackets, extract to Parquet
        println!(
            "Writing parquet trace files to {}...",
            opts.output_dir.display()
        );
        let mut parquet_writer = ParquetTraceWriter::new(&opts.output_dir)?;
        recorder.generate_trace(&mut parquet_writer)?;
        let _paths = parquet_writer.flush()?;
        println!(
            "Successfully wrote {} trace packets to parquet files",
            parquet_writer.packet_count()
        );
    }

    // Convert to Perfetto (unless --parquet-only)
    if !opts.parquet_only {
        println!(
            "Converting to Perfetto format: {}...",
            opts.output.display()
        );
        parquet_to_perfetto::convert(&opts.output_dir, &opts.output)?;
        println!("Successfully wrote {}", opts.output.display());
    }

    // Generate DuckDB database (if --with-duckdb)
    if opts.with_duckdb {
        let db_path = if opts.duckdb_output.is_absolute() {
            opts.duckdb_output.clone()
        } else {
            opts.output_dir.join(&opts.duckdb_output)
        };

        // Generate trace_id from output directory name
        let trace_id = opts
            .output_dir
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "trace".to_string());

        println!("Generating DuckDB database: {}...", db_path.display());
        systing_duckdb::parquet_to_duckdb(&opts.output_dir, &db_path, &trace_id)?;
        println!("Successfully wrote {}", db_path.display());
    }

    Ok(())
}

/// Check if we have the necessary capabilities to run BPF programs
/// We need CAP_BPF, CAP_PERFMON, or at a minimum CAP_SYS_ADMIN
fn has_bpf_capabilities() -> bool {
    // If we're root, we have all capabilities
    if unsafe { libc::getuid() } == 0 {
        return true;
    }

    // Try to load a simple BPF program to check if we have the necessary capabilities
    // This is the most reliable way to check since capability APIs may not accurately
    // reflect the effective capabilities needed for BPF

    // For now, we'll do a simple check: if we can bump memlock rlimit,
    // we likely have capabilities. Otherwise, we need systemd-run.
    // A better approach would be to actually try loading a minimal BPF program,
    // but that's more complex.

    // Check if we can set rlimit - this is a good proxy for having needed capabilities
    let rlimit = libc::rlimit {
        rlim_cur: MEMLOCK_RLIMIT_BYTES,
        rlim_max: MEMLOCK_RLIMIT_BYTES,
    };

    unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) == 0 }
}

/// Re-execute the current program using systemd-run to get elevated privileges
/// Returns an exit code to use for process exit
fn reexec_with_systemd_run() -> Result<i32> {
    let current_exe =
        env::current_exe().with_context(|| "Failed to determine current executable path")?;
    let args: Vec<String> = env::args().skip(1).collect();

    // Get the current user for --uid parameter
    let uid = unsafe { libc::getuid() };

    println!("Insufficient capabilities detected, re-executing with systemd-run...");
    println!("You may be prompted for authentication.");

    // Build the systemd-run command
    let mut cmd = ProcessCommand::new("systemd-run");
    cmd.arg(format!("--uid={uid}"))
        .arg("--wait")
        .arg("--pty")
        .arg("--same-dir")
        .arg("--quiet");

    // Preserve important environment variables
    let env_vars = ["DEBUGINFOD_URLS", "PATH", "HOME", "USER"];
    for var in &env_vars {
        if env::var(var).is_ok() {
            cmd.arg(format!("--setenv={var}"));
        }
    }

    // Clear ambient capabilities - systemd will handle granting the right capabilities
    cmd.arg("--property=AmbientCapabilities=~");

    // Add the current executable and all arguments
    cmd.arg(&current_exe);
    cmd.args(&args);

    // Add an environment variable to prevent infinite recursion
    cmd.env("SYSTING_REEXECED", "1");

    // Execute and wait for completion
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let status = cmd.status().with_context(|| {
        "Failed to execute systemd-run. Ensure systemd is available on your system."
    })?;

    Ok(status.code().unwrap_or(1))
}

fn main() -> Result<()> {
    // Check if we've already been re-executed to prevent infinite loops
    let already_reexeced = env::var("SYSTING_REEXECED").is_ok();

    // Check if we have the necessary capabilities
    if !already_reexeced && !has_bpf_capabilities() {
        let exit_code = reexec_with_systemd_run()?;
        process::exit(exit_code);
    }

    let mut opts = Command::parse();

    if opts.list_recorders {
        println!("Available recorders:");
        for recorder in get_available_recorders() {
            let default_text = if recorder.default_enabled {
                " (on by default)"
            } else {
                ""
            };
            println!(
                "  {:<14} - {}{}",
                recorder.name, recorder.description, default_text
            );
        }
        return Ok(());
    }

    process_recorder_options(&mut opts)?;

    // Set up tracing subscriber with level based on verbosity
    let level = match opts.verbosity {
        0 => LevelFilter::WARN,
        1 => LevelFilter::INFO,
        2 => LevelFilter::DEBUG,
        _ => LevelFilter::TRACE,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_timer(SystemTime)
        .finish();

    set_global_subscriber(subscriber).expect("Failed to set tracing subscriber");

    bump_memlock_rlimit()?;

    let config = Config::from(opts);
    system(config)
}
