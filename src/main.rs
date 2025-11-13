mod events;
mod network_recorder;
mod perf;
mod perf_recorder;
mod perfetto;
mod pystacks;
mod ringbuf;
mod sched;
mod session_recorder;
mod stack_recorder;
mod syscall_recorder;

use std::env;
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixDatagram;
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
use crate::syscall_recorder::SyscallRecorder;

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
use perfetto_protos::trace::Trace;

use plain::Plain;
use protobuf::Message;

/// Duration to poll ringbuffers before checking for shutdown
const RINGBUF_POLL_DURATION_MS: u64 = 100;

/// Sample period for perf clock events (1ms = 1000 samples/sec)
const PERF_CLOCK_SAMPLE_PERIOD: u64 = 1000;

/// Memory lock limit for BPF programs (128 MiB)
const MEMLOCK_RLIMIT_BYTES: u64 = 128 << 20;

/// Sleep duration before stopping in continuous mode (1 second)
const CONTINUOUS_MODE_STOP_DELAY_SECS: u64 = 1;

/// Interval for refreshing system info like CPU frequency (100ms)
const SYSINFO_REFRESH_INTERVAL_MS: u64 = 100;

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
    process_sched_stats: bool,
    #[arg(long)]
    cpu_sched_stats: bool,
    #[arg(long)]
    cpu_frequency: bool,
    #[arg(long)]
    perf_counter: Vec<String>,
    #[arg(long)]
    no_cpu_stack_traces: bool,
    #[arg(long)]
    no_sleep_stack_traces: bool,
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
    /// List all available recorders and their default states
    #[arg(long)]
    list_recorders: bool,
    /// Enable a specific recorder by name (can be specified multiple times)
    #[arg(long)]
    add_recorder: Vec<String>,
    /// Disable all recorders and only enable the specified ones (can be specified multiple times)
    #[arg(long)]
    only_recorder: Vec<String>,
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

/// Get the device and inode number of our PID namespace
/// Returns (dev, ino) or (0, 0) if the file doesn't exist or fails
fn detect_confidentiality_mode() -> u32 {
    use std::fs;

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
use systing::types::event_type;
use systing::types::network_event;
use systing::types::packet_event;
use systing::types::perf_counter_event;
use systing::types::probe_event;
use systing::types::stack_event;
use systing::types::syscall_event;
use systing::types::task_event;
use systing::types::task_info;

unsafe impl Plain for task_event {}
unsafe impl Plain for stack_event {}
unsafe impl Plain for perf_counter_event {}
unsafe impl Plain for probe_event {}
unsafe impl Plain for syscall_event {}
unsafe impl Plain for network_event {}
unsafe impl Plain for packet_event {}
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

impl SystingEvent for syscall_event {
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
        self.start_ts
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
    session_recorder: &Arc<SessionRecorder>,
    recorder: &Mutex<T>,
    rx: Receiver<N>,
    stop_tx: Sender<()>,
) where
    T: SystingRecordEvent<N>,
    N: Plain + SystingEvent,
{
    loop {
        let res = rx.recv();
        if res.is_err() {
            break;
        }
        let event = res.unwrap();
        if let Some(task_info) = event.next_task_info() {
            session_recorder.maybe_record_task(task_info);
        }
        if let Some(task_info) = event.prev_task_info() {
            session_recorder.maybe_record_task(task_info);
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
    opts: &Command,
    stop_tx: &Sender<()>,
    perf_counter_names: &[String],
) -> Result<Vec<thread::JoinHandle<i32>>> {
    let RecorderChannels {
        event_rx,
        stack_rx,
        cache_rx,
        probe_rx,
        syscall_rx,
        network_rx,
        packet_rx,
    } = channels;

    let mut threads = Vec::new();

    // Always spawn sched recorder
    {
        let session_recorder = recorder.clone();
        let my_stop_tx = stop_tx.clone();
        threads.push(
            thread::Builder::new()
                .name("sched_recorder".to_string())
                .spawn(move || {
                    consume_loop::<SchedEventRecorder, task_event>(
                        &session_recorder,
                        &session_recorder.event_recorder,
                        event_rx,
                        my_stop_tx,
                    );
                    0
                })?,
        );
    }

    // Always spawn stack recorder
    {
        let session_recorder = recorder.clone();
        let my_stop_tx = stop_tx.clone();
        threads.push(
            thread::Builder::new()
                .name("stack_recorder".to_string())
                .spawn(move || {
                    consume_loop::<StackRecorder, stack_event>(
                        &session_recorder,
                        &session_recorder.stack_recorder,
                        stack_rx,
                        my_stop_tx,
                    );
                    0
                })?,
        );
    }

    // Always spawn probe recorder
    {
        let session_recorder = recorder.clone();
        let my_stop_tx = stop_tx.clone();
        threads.push(
            thread::Builder::new()
                .name("probe_recorder".to_string())
                .spawn(move || {
                    consume_loop::<SystingProbeRecorder, probe_event>(
                        &session_recorder,
                        &session_recorder.probe_recorder,
                        probe_rx,
                        my_stop_tx,
                    );
                    0
                })?,
        );
    }

    // Conditionally spawn syscall recorder
    if opts.syscalls {
        let session_recorder = recorder.clone();
        let my_stop_tx = stop_tx.clone();
        threads.push(
            thread::Builder::new()
                .name("syscall_recorder".to_string())
                .spawn(move || {
                    consume_loop::<SyscallRecorder, syscall_event>(
                        &session_recorder,
                        &session_recorder.syscall_recorder,
                        syscall_rx,
                        my_stop_tx,
                    );
                    0
                })?,
        );
    }

    // Spawn network recorder if network recording is enabled
    if opts.network {
        let session_recorder = recorder.clone();
        let my_stop_tx = stop_tx.clone();
        threads.push(
            thread::Builder::new()
                .name("network_recorder".to_string())
                .spawn(move || {
                    consume_loop::<network_recorder::NetworkRecorder, network_event>(
                        &session_recorder,
                        &session_recorder.network_recorder,
                        network_rx,
                        my_stop_tx,
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
                    while let Ok(event) = packet_rx.recv() {
                        if let Some(task_info) = event.next_task_info() {
                            session_recorder.maybe_record_task(task_info);
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
    }

    // Conditionally spawn perf counter recorder
    if perf_counter_names.is_empty() {
        // Drop the channel receiver if not using perf counters
        drop(cache_rx);
    } else {
        let session_recorder = recorder.clone();
        let my_stop_tx = stop_tx.clone();
        threads.push(
            thread::Builder::new()
                .name("perf_counter_recorder".to_string())
                .spawn(move || {
                    consume_loop::<PerfCounterRecorder, perf_counter_event>(
                        &session_recorder,
                        &session_recorder.perf_counter_recorder,
                        cache_rx,
                        my_stop_tx,
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
    opts: &Command,
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

fn configure_recorder(opts: &Command, recorder: &Arc<SessionRecorder>) {
    if opts.continuous > 0 {
        let duration_nanos = Duration::from_secs(opts.continuous).as_nanos() as u64;
        set_ringbuf_duration(recorder, duration_nanos);
    }

    let mut event_recorder = recorder.event_recorder.lock().unwrap();
    event_recorder.set_process_sched_stats(opts.process_sched_stats);
    event_recorder.set_cpu_sched_stats(opts.cpu_sched_stats);
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

/// Discover all Python processes on the system by examining /proc
fn discover_python_processes() -> Vec<u32> {
    use std::fs;
    use std::path::PathBuf;

    let mut python_pids = Vec::new();

    // Read /proc directory
    let proc_dir = match fs::read_dir("/proc") {
        Ok(dir) => dir,
        Err(_) => return python_pids,
    };

    for entry in proc_dir.flatten() {
        // Only look at numeric directories (PIDs)
        let dir_name = entry.file_name();
        let dir_name_str = dir_name.to_string_lossy();
        if !dir_name_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }

        let pid: u32 = match dir_name_str.parse() {
            Ok(pid) => pid,
            Err(_) => continue,
        };

        // Check if /proc/[pid]/exe points to a python executable
        let exe_path = PathBuf::from("/proc")
            .join(dir_name_str.as_ref())
            .join("exe");
        if let Ok(exe_link) = fs::read_link(exe_path) {
            let exe_str = exe_link.to_string_lossy();
            // Check if the executable name contains "python"
            // This catches python, python2, python3, python3.11, etc.
            if exe_str.contains("python") {
                python_pids.push(pid);
            }
        }
    }

    python_pids
}

struct RecorderChannels {
    event_rx: Receiver<task_event>,
    stack_rx: Receiver<stack_event>,
    cache_rx: Receiver<perf_counter_event>,
    probe_rx: Receiver<probe_event>,
    syscall_rx: Receiver<syscall_event>,
    network_rx: Receiver<network_event>,
    packet_rx: Receiver<packet_event>,
}

fn setup_ringbuffers<'a>(
    skel: &systing::SystingSystemSkel,
    opts: &Command,
    perf_counter_names: &[String],
) -> Result<(Vec<(String, libbpf_rs::RingBuffer<'a>)>, RecorderChannels)> {
    let mut rings = Vec::new();
    let (event_tx, event_rx) = channel();
    let (stack_tx, stack_rx) = channel();
    let (cache_tx, cache_rx) = channel();
    let (probe_tx, probe_rx) = channel();
    let (syscall_tx, syscall_rx) = channel();
    let (network_tx, network_rx) = channel();
    let (packet_tx, packet_rx) = channel();

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
        } else if name.starts_with("ringbuf_syscall") && opts.syscalls {
            let ring = create_ring::<syscall_event>(&map, syscall_tx.clone())?;
            rings.push((name.to_string(), ring));
        } else if name.starts_with("ringbuf_network") && opts.network {
            let ring = create_ring::<network_event>(&map, network_tx.clone())?;
            rings.push((name.to_string(), ring));
        } else if name.starts_with("ringbuf_packet") && opts.network {
            let ring = create_ring::<packet_event>(&map, packet_tx.clone())?;
            rings.push((name.to_string(), ring));
        }
    }

    let channels = RecorderChannels {
        event_rx,
        stack_rx,
        cache_rx,
        probe_rx,
        syscall_rx,
        network_rx,
        packet_rx,
    };

    Ok((rings, channels))
}

fn configure_bpf_skeleton(
    open_skel: &mut systing::OpenSystingSystemSkel,
    opts: &Command,
    num_cpus: u32,
    old_kernel: bool,
    collect_pystacks: bool,
    recorder: &Arc<SessionRecorder>,
) -> Result<()> {
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
            {
                map.set_max_entries(1).with_context(|| {
                    format!("Failed to set network ringbuf map '{name}' to zero capacity")
                })?;
            }
        }
    }

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

        if opts.trace_event_pid.is_empty() {
            for event in probe_recorder.config_events.values() {
                match event.event {
                    EventProbe::Usdt(_) => {
                        Err(anyhow::anyhow!(
                            "USDT events must be specified with --trace-event-pid"
                        ))?;
                    }
                    EventProbe::UProbe(_) => {
                        Err(anyhow::anyhow!(
                            "UPROBE events must be specified with --trace-event-pid"
                        ))?;
                    }
                    _ => {}
                }
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

    // Only load syscall tracepoints when syscall tracing is enabled
    // This prevents unnecessary overhead from loading unused tracepoints
    if !opts.syscalls {
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
        open_skel.progs.udp4_lib_rcv_entry.set_autoload(false);
        open_skel
            .progs
            .udp_queue_rcv_one_skb_entry
            .set_autoload(false);
        open_skel
            .progs
            .udp_enqueue_schedule_skb_entry
            .set_autoload(false);
        open_skel.progs.tcp_transmit_skb_entry.set_autoload(false);
        open_skel.progs.dev_queue_xmit_entry.set_autoload(false);
        open_skel
            .progs
            .tcp_rcv_established_entry
            .set_autoload(false);
        open_skel.progs.tcp_queue_rcv_entry.set_autoload(false);
        open_skel.progs.tcp_data_queue_entry.set_autoload(false);
        open_skel.progs.net_dev_start_xmit.set_autoload(false);
        open_skel.progs.skb_copy_datagram_iovec.set_autoload(false);
    }

    Ok(())
}

fn setup_perf_events(
    skel: &mut systing::SystingSystemSkel,
    opts: &Command,
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

fn attach_probes(
    skel: &mut systing::SystingSystemSkel,
    recorder: &Arc<SessionRecorder>,
    opts: &Command,
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

        match &event.event {
            EventProbe::Usdt(usdt) => {
                // Skip USDT probes in confidentiality mode as they use restricted helpers
                if detect_confidentiality_mode() == 1 {
                    eprintln!(
                        "Skipping USDT probe {}:{}:{} - not supported in confidentiality mode",
                        usdt.path, usdt.provider, usdt.name
                    );
                } else {
                    for pid in opts.trace_event_pid.iter() {
                        let link = skel
                            .progs
                            .systing_usdt
                            .attach_usdt_with_opts(
                                *pid as i32,
                                &usdt.path,
                                &usdt.provider,
                                &usdt.name,
                                UsdtOpts {
                                    cookie: event.cookie,
                                    ..Default::default()
                                },
                            )
                            .with_context(|| {
                                format!(
                                    "Failed to attach USDT probe {}:{}:{} to PID {}",
                                    usdt.path, usdt.provider, usdt.name, *pid
                                )
                            })?;
                        probe_links.push(link);
                    }
                }
            }
            EventProbe::UProbe(uprobe) => {
                for pid in opts.trace_event_pid.iter() {
                    let link = skel
                        .progs
                        .systing_uprobe
                        .attach_uprobe_with_opts(
                            *pid as i32,
                            &uprobe.path,
                            uprobe.offset as usize,
                            UprobeOpts {
                                cookie: event.cookie,
                                retprobe: uprobe.retprobe,
                                func_name: Some(uprobe.func_name.clone()),
                                ..Default::default()
                            },
                        )
                        .with_context(|| {
                            format!(
                                "Failed to attach uprobe '{}' ({}retprobe) at {}+{:#x} to PID {}",
                                uprobe.func_name,
                                if uprobe.retprobe { "" } else { "not " },
                                uprobe.path,
                                uprobe.offset,
                                *pid
                            )
                        })?;
                    probe_links.push(link);
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

fn run_tracing_loop(
    threads: Vec<thread::JoinHandle<i32>>,
    recv_threads: Vec<thread::JoinHandle<i32>>,
    opts: &Command,
    stop_tx: Sender<()>,
    stop_rx: Receiver<()>,
    thread_done: Arc<AtomicBool>,
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
    thread_done.store(true, Ordering::Relaxed);
    for thread in threads {
        thread.join().expect("Failed to join thread");
    }
    println!("Stopping receiver threads...");
    for thread in recv_threads {
        thread.join().expect("Failed to join receiver thread");
    }

    println!("Missed sched/IRQ events: {}", dump_missed_events(skel, 0));
    println!("Missed stack events: {}", dump_missed_events(skel, 1));
    println!("Missed probe events: {}", dump_missed_events(skel, 2));
    println!("Missed perf events: {}", dump_missed_events(skel, 3));
    if opts.syscalls {
        println!("Missed syscall events: {}", dump_missed_events(skel, 4));
    }

    Ok(())
}

fn system(opts: Command) -> Result<()> {
    let num_cpus = libbpf_rs::num_possible_cpus().unwrap() as u32;
    let mut perf_counter_names = Vec::new();
    let mut counters = PerfCounters::default();
    let (stop_tx, stop_rx) = channel();
    let old_kernel = is_old_kernel();

    setup_perf_counters(&opts, &mut counters, &mut perf_counter_names)?;

    let recorder = Arc::new(SessionRecorder::new(opts.enable_debuginfod));
    configure_recorder(&opts, &recorder);
    recorder.snapshot_clocks();
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

        // Spawn all recorder threads
        let recv_threads =
            spawn_recorder_threads(&recorder, channels, &opts, &stop_tx, &perf_counter_names)?;

        // Set up perf events (clock events and counter events)
        let (_perf_links, _events_files) =
            setup_perf_events(&mut skel, &opts, &counters, &perf_counter_names, num_cpus)?;

        skel.attach().with_context(|| {
            "Failed to attach BPF programs to tracepoints. Check if tracepoints are enabled."
        })?;

        // Attach any usdt's that we may have
        let _probe_links = attach_probes(&mut skel, &recorder, &opts, old_kernel)?;

        let mut threads = Vec::new();
        let thread_done = Arc::new(AtomicBool::new(false));
        for (name, ring) in rings {
            let thread_done_clone = thread_done.clone();
            threads.push(thread::Builder::new().name(name).spawn(move || {
                loop {
                    if thread_done_clone.load(Ordering::Relaxed) {
                        // Flush whatever is left in the ringbuf
                        let _ = ring.consume();
                        break;
                    }
                    let res = ring.poll(Duration::from_millis(RINGBUF_POLL_DURATION_MS));
                    if res.is_err() {
                        break;
                    }
                }
                0
            })?);
        }

        // Start the sysinfo recorder if it's enabled
        if opts.cpu_frequency {
            let thread_done_clone = thread_done.clone();
            let sysinfo_recorder = recorder.clone();
            threads.push(
                thread::Builder::new()
                    .name("sysinfo_recorder".to_string())
                    .spawn(move || {
                        let mut sys = sysinfo::System::new_with_specifics(
                            sysinfo::RefreshKind::nothing()
                                .with_cpu(sysinfo::CpuRefreshKind::nothing().with_frequency()),
                        );

                        loop {
                            if thread_done_clone.load(Ordering::Relaxed) {
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

        run_tracing_loop(
            threads,
            recv_threads,
            &opts,
            stop_tx,
            stop_rx,
            thread_done,
            &mut skel,
        )?;
    }

    if opts.continuous > 0 {
        println!("Draining recorder ringbuffers...");
        recorder.drain_all_ringbufs();
    }

    println!("Generating trace...");
    let mut trace = Trace::default();
    trace.packet.extend(recorder.generate_trace());
    let mut file = std::fs::File::create("trace.pb")
        .with_context(|| "Failed to create output file 'trace.pb' in current directory")?;
    trace
        .write_to_writer(&mut file)
        .with_context(|| "Failed to write trace data to 'trace.pb'")?;
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

    system(opts)
}
