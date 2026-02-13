//! Core tracing functionality for systing.
//!
//! This module contains the main `systing()` function and all supporting code
//! for BPF-based system tracing.

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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::events::{EventKeyType, EventProbe, SystingProbeRecorder};
use crate::network_recorder;
use crate::parquet_to_perfetto;
use crate::perf::{PerfCounters, PerfHwEvent, PerfOpenEvents};
use crate::perf_recorder::PerfCounterRecorder;
use crate::ringbuf::RingBuffer;
use crate::sched::SchedEventRecorder;
use crate::session_recorder::{get_clock_value, SessionRecorder, SysInfoEvent};
use crate::stack_recorder::StackRecorder;

// Library imports for shared functionality
use crate::duckdb as systing_duckdb;

use anyhow::Result;
use anyhow::{bail, Context};

use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{
    MapCore, RawTracepointOpts, RingBufferBuilder, TracepointOpts, UprobeOpts, UsdtOpts,
};

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

/// Information about an available recorder.
pub struct RecorderInfo {
    pub name: &'static str,
    pub description: &'static str,
    pub default_enabled: bool,
}

/// Get list of all available recorders.
pub fn get_available_recorders() -> Vec<RecorderInfo> {
    vec![
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
        RecorderInfo {
            name: "pystacks",
            description: "Python stack tracing",
            default_enabled: false,
        },
        RecorderInfo {
            name: "markers",
            description: "Userspace marker events (faccessat2 with mode=-975)",
            default_enabled: false,
        },
    ]
}

/// Validate that recorder names are valid.
pub fn validate_recorder_names(names: &[String]) -> Result<()> {
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

/// Configuration for the systing system tracing.
/// This struct contains all the runtime options needed by the systing() function
/// and its helpers, separated from the CLI parsing concerns.
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
    pub collect_pystacks: bool,
    /// Explicit PIDs for pystacks (bypasses auto-discovery)
    pub pystacks_pids: Vec<u32>,
    /// Enable debug output for pystacks
    pub pystacks_debug: bool,
    /// Enable debuginfod for symbol resolution
    pub enable_debuginfod: bool,
    /// Disable scheduler tracing
    pub no_sched: bool,
    /// Enable syscall tracing
    pub syscalls: bool,
    /// Enable marker recording (faccessat2-based userspace markers)
    pub markers: bool,
    /// Enable network recording
    pub network: bool,
    /// Skip DNS resolution for network addresses
    pub no_resolve_addresses: bool,
    /// Output directory for parquet files
    pub output_dir: PathBuf,
    /// Output path (format auto-detected from extension: .pb = Perfetto, .duckdb = DuckDB)
    pub output: PathBuf,
    /// Skip trace generation, keep only parquet
    pub parquet_only: bool,
    /// Command to run and trace (everything after --)
    pub run_command: Option<Vec<String>>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            verbosity: 0,
            pid: Vec::new(),
            cgroup: Vec::new(),
            duration: 0,
            no_stack_traces: false,
            ringbuf_size_mib: 0,
            trace_event: Vec::new(),
            trace_event_pid: Vec::new(),
            sw_event: false,
            cpu_frequency: false,
            perf_counter: Vec::new(),
            no_cpu_stack_traces: false,
            no_sleep_stack_traces: false,
            no_interruptible_stack_traces: false,
            trace_event_config: Vec::new(),
            continuous: 0,
            collect_pystacks: false,
            pystacks_pids: Vec::new(),
            pystacks_debug: false,
            enable_debuginfod: false,
            no_sched: false,
            syscalls: false,
            markers: false,
            network: false,
            no_resolve_addresses: false,
            output_dir: PathBuf::from("./traces"),
            output: PathBuf::from("trace.pb"),
            parquet_only: false,
            run_command: None,
        }
    }
}

/// Bump the memory lock rlimit for BPF programs.
pub fn bump_memlock_rlimit() -> Result<()> {
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

// Include BPF skeleton in a module to allow suppressing warnings from generated code
#[allow(unused_imports)]
mod bpf {
    include!(concat!(env!("OUT_DIR"), "/systing_system.skel.rs"));
}

// Re-export skeleton types
pub use bpf::types;
pub use bpf::OpenSystingSystemSkel;
pub use bpf::SystingSystemSkel;
pub use bpf::SystingSystemSkelBuilder;

// Re-export commonly used types for convenience
pub use types::arg_desc;
pub use types::arg_desc_array;
pub use types::arg_type;
pub use types::epoll_event_bpf;
pub use types::event_type;
pub use types::marker_event;
pub use types::network_event;
pub use types::packet_event;
pub use types::perf_counter_event;
pub use types::probe_event;
pub use types::stack_event;
pub use types::task_event;
pub use types::task_info;

unsafe impl Plain for task_event {}
unsafe impl Plain for stack_event {}
unsafe impl Plain for perf_counter_event {}
unsafe impl Plain for probe_event {}
unsafe impl Plain for network_event {}
unsafe impl Plain for packet_event {}
unsafe impl Plain for epoll_event_bpf {}
unsafe impl Plain for arg_desc {}
unsafe impl Plain for arg_desc_array {}
unsafe impl Plain for marker_event {}

/// BPF exec event - delivered via dedicated ringbuf when a traced process execs.
/// Used to dynamically discover Python PIDs for pystacks.
#[repr(C)]
#[derive(Default, Clone, Copy)]
#[allow(non_camel_case_types)]
struct exec_event {
    pid: u32,
}
unsafe impl Plain for exec_event {}

/// Trait for events that can be recorded in a ring buffer.
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

/// Trait for systing events.
pub trait SystingEvent {
    fn ts(&self) -> u64;
    fn next_task_info(&self) -> Option<&task_info> {
        None
    }
    fn prev_task_info(&self) -> Option<&task_info> {
        None
    }
    /// Returns true if this event contains Python stack data that needs symbol loading.
    /// Default is false; only stack_event overrides this.
    fn has_pystack(&self) -> bool {
        false
    }
}

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
    fn has_pystack(&self) -> bool {
        self.py_msg_buffer.stack_len > 0
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

impl SystingEvent for marker_event {
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

        // Send event to pystack symbol loading thread only if it has Python stack data
        // This avoids waking up the symbol loader thread for events without Python stacks
        if let Some(ref tx) = pystack_symbol_tx {
            if event.has_pystack() {
                tx.send(event)
                    .expect("Failed to send event to pystack symbol loader thread");
            }
        }

        let ret = recorder.lock().unwrap().record_event(event);

        if ret {
            let _ = stop_tx.send(());
            break;
        }
    }
}

struct RecorderChannels {
    event_rx: Receiver<task_event>,
    stack_rx: Receiver<stack_event>,
    cache_rx: Receiver<perf_counter_event>,
    probe_rx: Receiver<probe_event>,
    network_rx: Receiver<network_event>,
    packet_rx: Receiver<packet_event>,
    epoll_rx: Receiver<epoll_event_bpf>,
    marker_rx: Receiver<marker_event>,
    exec_event_rx: Option<Receiver<exec_event>>,
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
        marker_rx,
        ..
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

    // Conditionally spawn marker recorder
    if opts.markers {
        let session_recorder = recorder.clone();
        let my_stop_tx = stop_tx.clone();
        let my_task_tx = task_info_tx.clone();
        threads.push(
            thread::Builder::new()
                .name("marker_recorder".to_string())
                .spawn(move || {
                    consume_loop::<crate::marker_recorder::MarkerRecorder, marker_event>(
                        &session_recorder.marker_recorder,
                        marker_rx,
                        my_stop_tx,
                        my_task_tx,
                        None,
                    );
                    0
                })?,
        );
    } else {
        drop(marker_rx);
    }

    Ok(threads)
}

fn dump_missed_events(skel: &SystingSystemSkel, index: u32) -> u64 {
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
fn discover_python_processes(debug: bool) -> Vec<u32> {
    use std::io::{BufRead, BufReader};

    if debug {
        eprintln!("[pystacks debug] Starting Python process discovery...");
    }

    let proc_dir = match std::fs::read_dir("/proc") {
        Ok(dir) => dir,
        Err(e) => {
            if debug {
                eprintln!("[pystacks debug] Failed to read /proc: {e}");
            }
            return Vec::new();
        }
    };

    let mut discovered = Vec::new();

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

        // Check /proc/PID/exe for python
        if let Ok(exe) = std::fs::read_link(proc_path.join("exe")) {
            let exe_str = exe.to_string_lossy();
            if exe_str.contains("python") {
                if debug {
                    // Get comm for additional info
                    let comm = std::fs::read_to_string(proc_path.join("comm"))
                        .unwrap_or_else(|_| "unknown".to_string())
                        .trim()
                        .to_string();
                    eprintln!(
                        "[pystacks debug] Found Python process: PID={pid_u32} exe={exe_str} comm={comm}"
                    );
                }
                discovered.push(pid_u32);
                continue;
            }
        }

        // Also check /proc/PID/maps for libpython (embedded Python)
        let maps_path = proc_path.join("maps");
        if let Ok(file) = std::fs::File::open(&maps_path) {
            let reader = BufReader::new(file);
            for line in reader.lines().map_while(Result::ok) {
                if line.contains("libpython") {
                    if debug {
                        let comm = std::fs::read_to_string(proc_path.join("comm"))
                            .unwrap_or_else(|_| "unknown".to_string())
                            .trim()
                            .to_string();
                        let exe = std::fs::read_link(proc_path.join("exe"))
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_else(|_| "unknown".to_string());
                        eprintln!(
                            "[pystacks debug] Found embedded Python: PID={pid_u32} exe={exe} comm={comm} (has libpython)"
                        );
                    }
                    discovered.push(pid_u32);
                    break;
                }
            }
        }
    }

    if debug {
        eprintln!(
            "[pystacks debug] Discovery complete: found {} Python process(es): {:?}",
            discovered.len(),
            discovered
        );
    }

    discovered
}

/// Handles exec events from the BPF ringbuf, dynamically adding Python PIDs to pystacks.
///
/// When a traced process execs into Python directly, adds it to pystacks immediately.
/// When a traced process execs into a pyenv launcher (e.g., forkapple's `fa`), scans
/// /proc for all Python processes since the actual Python workers may be outside the
/// traced process tree (pre-forked by a server like forkapple).
fn handle_exec_events(
    exec_rx: Receiver<exec_event>,
    psr: Arc<crate::pystacks::stack_walker::StackWalkerRun>,
    pids_map: libbpf_rs::MapHandle,
    pystacks_debug: bool,
) {
    let mut added_pids = std::collections::HashSet::new();
    // Single scan flag: we only scan /proc once per trace session because
    // the forkapple server's Python workers are long-lived and pre-forked,
    // so subsequent pyenv exec events won't reveal new Python PIDs.
    let mut did_scan = false;
    while let Ok(event) = exec_rx.recv() {
        let pid = event.pid;
        let Ok(exe) = std::fs::read_link(format!("/proc/{pid}/exe")) else {
            if pystacks_debug {
                eprintln!(
                    "[pystacks debug] Exec event for PID {} but readlink failed",
                    pid
                );
            }
            continue;
        };
        let exe_str = exe.to_string_lossy();

        if exe_str.contains("python") {
            // Direct Python exec within a traced process — add to pystacks.
            // No pids_map update needed here: the process is already in the
            // BPF pids map (trace_task() passed in the BPF handler), so
            // sched/stack events are already being generated for it.
            if added_pids.insert(pid) {
                eprintln!(
                    "[pystacks] Dynamically added Python PID {} ({})",
                    pid, exe_str
                );
                psr.add_pid(pid as i32);
            }
        } else if !did_scan && exe_str.contains(".pyenv/") {
            // A pyenv binary but not Python itself (e.g., forkapple's `fa`).
            // The actual Python process may be outside our traced tree.
            // Scan /proc for all Python processes and add them.
            if pystacks_debug {
                eprintln!(
                    "[pystacks debug] Exec event for pyenv binary PID {} ({}), scanning for Python processes",
                    pid, exe_str
                );
            }
            did_scan = true;
            let discovered = discover_python_processes(pystacks_debug);
            for py_pid in discovered {
                if added_pids.insert(py_pid) {
                    eprintln!(
                        "[pystacks] Dynamically added Python PID {} (discovered via pyenv exec)",
                        py_pid
                    );
                    psr.add_pid(py_pid as i32);
                    // Also add to the BPF pids map so this process
                    // generates sched/stack events
                    let val = (1_u8).to_ne_bytes();
                    if let Err(e) =
                        pids_map.update(&py_pid.to_ne_bytes(), &val, libbpf_rs::MapFlags::ANY)
                    {
                        eprintln!(
                            "[pystacks] Warning: failed to add PID {} to BPF pids map: {}",
                            py_pid, e
                        );
                    }
                }
            }
        } else if pystacks_debug {
            eprintln!(
                "[pystacks debug] Exec event for PID {} ({}), not Python",
                pid, exe_str
            );
        }
    }
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

fn setup_ringbuffers<'a>(
    skel: &SystingSystemSkel,
    opts: &Config,
    perf_counter_names: &[String],
    collect_pystacks: bool,
) -> Result<(Vec<(String, libbpf_rs::RingBuffer<'a>)>, RecorderChannels)> {
    let mut rings = Vec::new();
    let (event_tx, event_rx) = channel();
    let (stack_tx, stack_rx) = channel();
    let (cache_tx, cache_rx) = channel();
    let (probe_tx, probe_rx) = channel();
    let (network_tx, network_rx) = channel();
    let (packet_tx, packet_rx) = channel();
    let (epoll_tx, epoll_rx) = channel();
    let (marker_tx, marker_rx) = channel();
    let (exec_tx, exec_rx) = channel();
    let mut has_exec_ringbuf = false;

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

    if collect_pystacks {
        for map in object.maps() {
            if map.name().to_str().unwrap() == "ringbuf_exec_events" {
                let ring = create_ring::<exec_event>(&map, exec_tx.clone())?;
                rings.push(("ringbuf_exec_events".to_string(), ring));
                has_exec_ringbuf = true;
                break;
            }
        }
    }

    if opts.markers {
        let mut found_ringbuf = false;
        for map in object.maps() {
            if map.name().to_str().unwrap() == "ringbuf_marker" {
                let ring = create_ring::<marker_event>(&map, marker_tx.clone())?;
                rings.push(("ringbuf_marker".to_string(), ring));
                found_ringbuf = true;
                break;
            }
        }
        if !found_ringbuf {
            eprintln!("ERROR: ringbuf_marker map not found in BPF object - marker events will not be collected");
        }
    }

    let exec_event_rx = if has_exec_ringbuf {
        Some(exec_rx)
    } else {
        None
    };

    let channels = RecorderChannels {
        event_rx,
        stack_rx,
        cache_rx,
        probe_rx,
        network_rx,
        packet_rx,
        epoll_rx,
        marker_rx,
        exec_event_rx,
    };

    Ok((rings, channels))
}

/// Checks for probes that failed to attach and warns about them.
/// Uses the program's autoload() status to determine if it was expected to load,
/// eliminating the need to duplicate autoload conditions from configure_bpf_skeleton.
fn warn_failed_probe_attachments(skel: &SystingSystemSkel) {
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
            "systing_sched_process_exec" => skel.links.systing_sched_process_exec.is_none(),
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
    open_skel: &mut OpenSystingSystemSkel,
    opts: &Config,
    num_cpus: u32,
    old_kernel: bool,
    collect_pystacks: bool,
    recorder: &Arc<SessionRecorder>,
) -> Result<()> {
    // Setup probe recorder with trace events
    {
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
    }

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

        if opts.markers {
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

    // Only load exec tracepoint when pystacks is enabled with PID filtering.
    // This delivers exec events so userspace can dynamically add Python PIDs.
    if !collect_pystacks || opts.pid.is_empty() {
        open_skel
            .progs
            .systing_sched_process_exec
            .set_autoload(false);
    }

    // Only load syscall tracepoints when syscall tracing is enabled OR marker recording is enabled
    // Marker recording uses the sys_enter tracepoint to intercept faccessat2 syscalls
    // This prevents unnecessary overhead from loading unused tracepoints
    if !opts.syscalls && !opts.markers {
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
    skel: &mut SystingSystemSkel,
    opts: &Config,
    counters: &PerfCounters,
    perf_counter_names: &[String],
    num_cpus: u32,
) -> Result<(Vec<libbpf_rs::Link>, Vec<PerfOpenEvents>)> {
    use crate::perf;

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
    skel: &mut SystingSystemSkel,
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
    exec_handler_thread: Option<thread::JoinHandle<()>>,
    task_info_tx: Sender<task_info>,
    pystack_symbol_tx: Sender<stack_event>,
}

#[allow(clippy::too_many_arguments)]
fn run_tracing_loop(
    handles: ThreadHandles,
    opts: &Config,
    stop_tx: Sender<()>,
    stop_rx: Receiver<()>,
    ringbuf_shutdown: Arc<ShutdownSignal>,
    shutdown_signal: Arc<AtomicBool>,
    skel: &mut SystingSystemSkel,
    traced_child: &Option<crate::traced_command::TracedChild>,
) -> Result<()> {
    sd_notify()?;

    if let Some(child) = traced_child.as_ref() {
        // Command mode: trace until child exits, duration expires, or Ctrl-C
        let stop_for_child = stop_tx.clone();
        let child_pid = child.pid as i32;
        let child_waited = child.waited.clone();
        let child_exit_status = child.exit_status.clone();

        // Background thread to wait for child exit
        thread::spawn(move || {
            let mut status: i32 = 0;
            let ret = unsafe { libc::waitpid(child_pid, &mut status, 0) };
            if ret > 0 {
                let exit_code = if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status)
                } else if libc::WIFSIGNALED(status) {
                    128 + libc::WTERMSIG(status)
                } else {
                    1
                };
                *child_exit_status.lock().unwrap() = Some(exit_code);
                // Set waited AFTER exit_status so Acquire readers see both
                child_waited.store(true, Ordering::Release);
            }
            // Small delay to drain remaining BPF events from the child's final moments
            thread::sleep(Duration::from_millis(100));
            let _ = stop_for_child.send(());
        });

        // Duration timeout thread (if --duration is set)
        let duration = opts.duration;
        if duration > 0 {
            let stop_for_duration = stop_tx.clone();
            thread::spawn(move || {
                thread::sleep(Duration::from_secs(duration));
                let _ = stop_for_duration.send(());
            });
            eprintln!(
                "Tracing command (PID {}) for up to {} seconds...",
                child.pid, opts.duration
            );
        } else {
            eprintln!("Tracing command (PID {})...", child.pid);
        }

        // Forward SIGINT to the child so it gets graceful cleanup.
        // Ignore MultipleHandlers error (e.g., in test harnesses).
        let _ = ctrlc::set_handler(move || {
            unsafe {
                libc::kill(child_pid, libc::SIGINT);
            }
            let _ = stop_tx.send(());
        });

        eprintln!("Press Ctrl-C to stop early");
        let _ = stop_rx.recv();
    } else if opts.duration > 0 {
        // Duration mode (no command): trace for a fixed time
        println!("Tracing for {} seconds", opts.duration);
        thread::sleep(Duration::from_secs(opts.duration));
    } else {
        // Indefinite mode: trace until Ctrl-C
        let _ = ctrlc::set_handler(move || {
            let _ = stop_tx.send(());
        });
        if opts.continuous > 0 {
            println!("Tracing in a continues loop of {} seconds", opts.continuous);
            println!("Will stop if a trigger is specified, otherwise Ctrl-C to stop");
        } else {
            println!("Tracing indefinitely...");
            println!("Press Ctrl-C to stop");
        }
        let _ = stop_rx.recv();
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
    // The exec handler thread reads from a channel fed by ringbuf callbacks,
    // so it terminates after ringbuf threads exit and senders are dropped.
    if let Some(thread) = handles.exec_handler_thread {
        thread.join().expect("Failed to join exec handler thread");
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
    if opts.markers {
        println!("Missed marker events (ringbuf full): {}", dump_missed_events(skel, 7));
    }

    Ok(())
}

/// Main tracing function that sets up and runs the BPF-based system tracer.
///
/// If `traced_child` is provided, the child's PID is added to the PID filter,
/// the child is signaled to exec after BPF is attached, and tracing stops when
/// the child exits. Returns the child's exit code (or 0 if no child).
pub fn systing(
    mut opts: Config,
    mut traced_child: Option<crate::traced_command::TracedChild>,
) -> Result<i32> {
    bump_memlock_rlimit()?;

    // Add the traced child's PID to the PID filter list
    if let Some(ref child) = traced_child {
        opts.pid.push(child.pid);
    }

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

    // Initialize streaming parquet output BEFORE recording starts
    prepare_output_dir(&opts.output_dir)?;
    recorder.init_streaming_parquet(&opts.output_dir)?;
    eprintln!(
        "Initialized streaming parquet output to {:?}",
        opts.output_dir
    );

    {
        let mut skel_builder = SystingSystemSkelBuilder::default();
        if opts.verbosity > 0 {
            skel_builder.obj_builder.debug(true);
        }

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

        // Initialize pystacks for the non-run-command case (normal path).
        // When tracing a run command, pystacks init is deferred until after the
        // child has exec'd (so /proc/PID/exe points to the real Python binary).
        if collect_pystacks && traced_child.is_none() {
            let pystacks_debug = opts.pystacks_debug;

            if pystacks_debug {
                eprintln!("[pystacks debug] Pystacks collection enabled");
            }

            // Determine which PIDs to use for pystacks
            // Priority: 1) explicit pystacks_pids, 2) general pid filter, 3) auto-discovery
            let pystacks_pids = if !opts.pystacks_pids.is_empty() {
                // Explicit pystacks PIDs specified (bypasses discovery)
                println!("Using explicit pystacks PIDs: {:?}", opts.pystacks_pids);
                if pystacks_debug {
                    eprintln!(
                        "[pystacks debug] Using {} explicit PIDs (bypassing discovery)",
                        opts.pystacks_pids.len()
                    );
                }
                opts.pystacks_pids.clone()
            } else if opts.pid.is_empty() {
                // No PIDs specified, discover all Python processes
                let discovered = discover_python_processes(pystacks_debug);
                if discovered.is_empty() {
                    println!("Warning: No Python processes found on the system");
                    if pystacks_debug {
                        eprintln!("[pystacks debug] WARNING: No Python processes discovered - pystacks will have no targets");
                    }
                } else {
                    println!(
                        "Discovered {} Python process(es) for pystacks: {:?}",
                        discovered.len(),
                        discovered
                    );
                }
                discovered
            } else {
                // Use the general PIDs specified by the user
                println!("Using specified PIDs for pystacks: {:?}", opts.pid);
                if pystacks_debug {
                    eprintln!(
                        "[pystacks debug] Using {} user-specified PIDs for pystacks",
                        opts.pid.len()
                    );
                }
                opts.pid.clone()
            };

            if pystacks_debug {
                eprintln!(
                    "[pystacks debug] Initializing pystacks library with {} PIDs: {:?}",
                    pystacks_pids.len(),
                    pystacks_pids
                );
            }

            recorder.stack_recorder.lock().unwrap().init_pystacks(
                &pystacks_pids,
                skel.object(),
                pystacks_debug,
            );
        }

        let (rings, mut channels) =
            setup_ringbuffers(&skel, &opts, &perf_counter_names, collect_pystacks)?;
        // Take exec_event_rx out before channels is moved into spawn_recorder_threads
        let exec_event_rx = channels.exec_event_rx.take();

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

        // Signal the traced child to exec now that BPF is fully attached.
        // All tracing is active, so we capture everything from exec onwards.
        if let Some(ref mut child) = traced_child {
            child.signal_exec()?;
            child.wait_for_exec()?;
            eprintln!("Traced command started (PID {})", child.pid);
        }

        // Deferred pystacks init for run-command case.
        // Now the child has exec'd and /proc/PID/exe points to the real executable.
        // Note: The initial exec may be to a shell wrapper (e.g., a bash pytest
        // script), not to Python directly. pystacks_init will find 0 Python
        // processes in that case, but the library is still initialized correctly.
        // The symbol loader thread below handles adding PIDs when they later
        // exec into Python.
        if collect_pystacks && traced_child.is_some() {
            let pystacks_debug = opts.pystacks_debug;
            // Use all PIDs in the filter (includes child PID + any --pid args)
            let pystacks_pids = if !opts.pystacks_pids.is_empty() {
                opts.pystacks_pids.clone()
            } else {
                opts.pid.clone()
            };

            if pystacks_debug {
                eprintln!(
                    "[pystacks debug] Deferred pystacks init (after exec) with PIDs: {:?}",
                    pystacks_pids
                );
            }

            recorder.stack_recorder.lock().unwrap().init_pystacks(
                &pystacks_pids,
                skel.object(),
                pystacks_debug,
            );
        }

        // Spawn the symbol loader thread AFTER pystacks initialization (both normal
        // and deferred paths) because init_pystacks requires Arc::get_mut (exclusive
        // access), which fails if the Arc has been cloned. Events queue in the
        // unbounded mpsc channel until this thread starts draining them.
        let psr = recorder.stack_recorder.lock().unwrap().psr.clone();

        // Spawn exec event handler thread to dynamically add Python PIDs.
        // See handle_exec_events() for details.
        let mut exec_handler_thread: Option<thread::JoinHandle<()>> = None;
        if let Some(exec_rx) = exec_event_rx {
            let exec_psr = psr.clone();
            let pystacks_debug = opts.pystacks_debug;
            let pids_map = libbpf_rs::MapHandle::try_from(&skel.maps.pids)
                .context("Failed to get handle to BPF pids map")?;
            exec_handler_thread = Some(
                thread::Builder::new()
                    .name("pystacks_exec_handler".to_string())
                    .spawn(move || {
                        handle_exec_events(exec_rx, exec_psr, pids_map, pystacks_debug);
                    })?,
            );
        }

        let symbol_thread = thread::Builder::new()
            .name("pystack_symbol_loader".to_string())
            .spawn(move || {
                while let Ok(event) = pystack_symbol_rx.recv() {
                    psr.load_pystack_symbols(&event);
                }
                0
            })?;

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
            exec_handler_thread,
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
            &traced_child,
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

    // Write trace files directly to Parquet
    println!(
        "Writing Parquet trace files to {}...",
        opts.output_dir.display()
    );
    recorder.generate_parquet_trace(&opts.output_dir)?;
    println!("Successfully wrote Parquet trace files");

    // Generate output trace (unless --parquet-only)
    // Format is auto-detected from the file extension
    if !opts.parquet_only {
        let extension = opts
            .output
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase());

        match extension.as_deref() {
            Some("pb") | Some("perfetto") => {
                println!(
                    "Converting to Perfetto format: {}...",
                    opts.output.display()
                );
                parquet_to_perfetto::convert(&opts.output_dir, &opts.output)?;
                println!("Successfully wrote {}", opts.output.display());
            }
            Some("duckdb") => {
                // Generate trace_id from output directory name
                let trace_id = opts
                    .output_dir
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "trace".to_string());

                println!("Generating DuckDB database: {}...", opts.output.display());
                systing_duckdb::parquet_to_duckdb(&opts.output_dir, &opts.output, &trace_id)?;
                println!("Successfully wrote {}", opts.output.display());
            }
            Some(ext) => {
                bail!(
                    "Unknown file extension '.{}' for '{}'. Use .pb for Perfetto or .duckdb for DuckDB.",
                    ext,
                    opts.output.display()
                );
            }
            None => {
                bail!(
                    "Missing file extension for '{}'. Use .pb for Perfetto or .duckdb for DuckDB.",
                    opts.output.display()
                );
            }
        }
    }

    // Clean up the traced child if it's still alive (e.g., --duration expired before child exited)
    let exit_code = if let Some(ref child) = traced_child {
        if !child.waited.load(Ordering::Acquire) {
            // Try non-blocking waitpid first to see if child already exited
            let mut status: i32 = 0;
            let ret = unsafe { libc::waitpid(child.pid as i32, &mut status, libc::WNOHANG) };
            if ret > 0 {
                // Child already exited
                child.waited.store(true, Ordering::Release);
                let code = if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status)
                } else if libc::WIFSIGNALED(status) {
                    128 + libc::WTERMSIG(status)
                } else {
                    1
                };
                *child.exit_status.lock().unwrap() = Some(code);
            } else {
                // Child still running - send SIGINT for graceful cleanup
                unsafe {
                    libc::kill(child.pid as i32, libc::SIGINT);
                }
                eprintln!("Sent SIGINT to traced command (PID {})", child.pid);
                // Wait for the background waitpid thread to reap it.
                // exit_status is set before waited (Release ordering), so
                // Acquire load of waited==true guarantees exit_status is visible.
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                while !child.waited.load(Ordering::Acquire) {
                    if std::time::Instant::now() > deadline {
                        // Timeout - Drop will SIGKILL and reap
                        break;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }
        child.exit_code().unwrap_or(0)
    } else {
        0
    };

    Ok(exit_code)
}
