use std::env;
use std::path::PathBuf;
use std::process;
use std::process::{Command as ProcessCommand, Stdio};

use anyhow::Context;
use anyhow::Result;
use clap::{ArgAction, Parser};

use tracing::subscriber::set_global_default as set_global_subscriber;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::time::SystemTime;
use tracing_subscriber::FmtSubscriber;

use systing::traced_command;
use systing::{get_available_recorders, systing, Config};

/// Memory lock limit used for capability probing (128 MiB).
/// This value should match the limit in systing_core::MEMLOCK_RLIMIT_BYTES.
const CAPABILITY_PROBE_MEMLOCK_BYTES: u64 = 128 << 20;

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
    #[arg(long)]
    collect_pystacks: bool,
    /// Enable debug output for pystacks (Python stack tracing)
    #[arg(long)]
    pystacks_debug: bool,
    /// Enable debuginfod for enhanced symbol resolution (requires DEBUGINFOD_URLS environment variable)
    #[arg(long)]
    enable_debuginfod: bool,
    /// Disable scheduler event tracing (sched_* tracepoints and scheduler event recorder)
    #[arg(long)]
    no_sched: bool,
    /// Enable syscall tracing (raw_syscalls:sys_enter and sys_exit tracepoints)
    #[arg(long)]
    syscalls: bool,
    // Memory recording enabled state (set by recorder management, not a CLI flag)
    #[arg(skip)]
    memory: bool,
    /// Sample 1 in N user page faults when the memory recorder is enabled (0 or 1 = record all)
    #[arg(long, default_value = "97")]
    memory_fault_sample_rate: u32,
    // Heap-allocator tracing enabled state (set by recorder management, not a CLI flag)
    #[arg(skip)]
    memory_alloc: bool,
    /// Sample 1 in N allocator calls (malloc/free/...) when the memory-alloc recorder is enabled (0 or 1 = record all)
    #[arg(long, default_value = "1")]
    memory_alloc_sample_rate: u32,
    // Network recording enabled state (set by recorder management, not a CLI flag)
    #[arg(skip)]
    network: bool,
    // Network packet-level probes (set by recorder management, not a CLI flag)
    #[arg(skip)]
    network_packets: bool,
    // Marker recording enabled state (set by recorder management, not a CLI flag)
    #[arg(skip)]
    markers: bool,
    /// Stop tracing after this many marker instant events are observed
    #[arg(long)]
    marker_threshold: Option<u64>,
    /// Stop tracing when any marker range event exceeds this duration in milliseconds
    #[arg(long)]
    marker_duration_threshold: Option<u64>,
    /// Resolve network IP addresses to hostnames via DNS (off by default)
    #[arg(long)]
    resolve_addresses: bool,
    /// Enable TPU profiling (auto-discovers profiler service on port 8466)
    #[arg(long)]
    tpu_profile: bool,
    /// TPU profiler service address (host:port, overrides auto-discovery)
    #[arg(long)]
    tpu_service_addr: Option<String>,
    /// Enable lightweight TPU metrics polling (port 8431, always available)
    #[arg(long)]
    tpu_metrics: bool,
    /// TPU metrics service address (host:port, overrides auto-discovery)
    #[arg(long)]
    tpu_metrics_addr: Option<String>,
    /// TPU metrics polling interval in milliseconds (default: 1000)
    #[arg(long, default_value = "1000")]
    tpu_metrics_interval: u64,
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

    /// Output file path. Format is auto-detected from extension:
    /// - .pb or .perfetto: Perfetto trace
    /// - .duckdb: DuckDB database
    #[arg(long, default_value = "trace.pb")]
    output: PathBuf,

    /// Skip trace generation, keep only parquet files
    #[arg(long)]
    parquet_only: bool,

    /// Command to run and trace. Everything after -- is treated as the command.
    /// Only the command and its children/threads will be traced.
    /// Example: systing -- python3 myscript.py
    #[arg(last = true)]
    run_command: Vec<String>,
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
            collect_pystacks: cmd.collect_pystacks,
            pystacks_pids: Vec::new(), // CLI doesn't expose this yet, uses discovery
            pystacks_debug: cmd.pystacks_debug,
            enable_debuginfod: cmd.enable_debuginfod,
            no_sched: cmd.no_sched,
            syscalls: cmd.syscalls,
            markers: cmd.markers,
            marker_threshold: cmd.marker_threshold,
            marker_duration_threshold: cmd.marker_duration_threshold,
            memory: cmd.memory,
            memory_fault_sample_rate: cmd.memory_fault_sample_rate,
            memory_alloc: cmd.memory_alloc,
            memory_alloc_sample_rate: cmd.memory_alloc_sample_rate,
            network: cmd.network,
            network_packets: cmd.network_packets,
            resolve_addresses: cmd.resolve_addresses,
            tpu_profile: cmd.tpu_profile,
            tpu_service_addr: cmd.tpu_service_addr,
            tpu_metrics: cmd.tpu_metrics,
            tpu_metrics_addr: cmd.tpu_metrics_addr,
            tpu_metrics_interval: cmd.tpu_metrics_interval,
            output_dir: cmd.output_dir,
            output: cmd.output,
            parquet_only: cmd.parquet_only,
            run_command: if cmd.run_command.is_empty() {
                None
            } else {
                Some(cmd.run_command)
            },
        }
    }
}

fn enable_recorder(opts: &mut Command, recorder_name: &str, enable: bool) {
    match recorder_name {
        "syscalls" => opts.syscalls = enable,
        "sched" => opts.no_sched = !enable,
        "sleep-stacks" => opts.no_sleep_stack_traces = !enable,
        "interruptible-stacks" => opts.no_interruptible_stack_traces = !enable,
        "tpu" => opts.tpu_profile = enable,
        "cpu-stacks" => opts.no_cpu_stack_traces = !enable,
        "network" => {
            opts.network = enable;
            // Network and packet-level tracing are coupled: enabling network also
            // enables packets by default, disabling network also disables packets.
            // Users can override with --only-recorder network to get state-only.
            opts.network_packets = enable;
        }
        "network-packets" => {
            opts.network_packets = enable;
            // Packet probes require the network infrastructure (ringbufs, consumers),
            // so enabling network-packets also enables the base network recorder.
            if enable {
                opts.network = true;
            }
        }
        "memory" => opts.memory = enable,
        "memory-alloc" => {
            opts.memory_alloc = enable;
            // memory-alloc shares the memory ringbuf/consumer; enabling it also
            // enables the base memory recorder.
            if enable {
                opts.memory = true;
            }
        }
        "pystacks" => opts.collect_pystacks = enable,
        "markers" => opts.markers = enable,
        "tpu-metrics" => opts.tpu_metrics = enable,
        _ => unreachable!("validated recorder name not handled: {recorder_name}"),
    }
}

fn process_recorder_options(opts: &mut Command) -> Result<()> {
    systing::systing_core::validate_recorder_names(&opts.add_recorder)?;
    systing::systing_core::validate_recorder_names(&opts.only_recorder)?;

    // If --only-recorder is specified, disable all recorders first
    if !opts.only_recorder.is_empty() {
        opts.no_sched = true;
        opts.syscalls = false;
        opts.no_sleep_stack_traces = true;
        opts.no_interruptible_stack_traces = true;
        opts.no_cpu_stack_traces = true;
        opts.memory = false;
        opts.memory_alloc = false;
        opts.network = false;
        opts.network_packets = false;
        opts.collect_pystacks = false;
        opts.markers = false;
        opts.tpu_profile = false;
        opts.tpu_metrics = false;

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
        rlim_cur: CAPABILITY_PROBE_MEMLOCK_BYTES,
        rlim_max: CAPABILITY_PROBE_MEMLOCK_BYTES,
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

    // Check if we've already been re-executed to prevent infinite loops
    let already_reexeced = env::var("SYSTING_REEXECED").is_ok();

    // Check if we have the necessary capabilities
    if !already_reexeced && !has_bpf_capabilities() {
        let exit_code = reexec_with_systemd_run()?;
        process::exit(exit_code);
    }

    process_recorder_options(&mut opts)?;

    // Validate incompatible options
    if !opts.run_command.is_empty() && opts.continuous > 0 {
        anyhow::bail!("--continuous cannot be used with a run command (-- <command>)");
    }

    // Auto-enable markers when marker-threshold or marker-duration-threshold is set
    if opts.marker_threshold.is_some() || opts.marker_duration_threshold.is_some() {
        opts.markers = true;
        if opts.continuous == 0 {
            anyhow::bail!(
                "--marker-threshold/--marker-duration-threshold requires --continuous <seconds>"
            );
        }
    }

    // Auto-enable pystacks for Python commands
    if !opts.run_command.is_empty()
        && !opts.collect_pystacks
        && traced_command::is_python_command(&opts.run_command)
    {
        eprintln!("Detected Python command, auto-enabling --collect-pystacks");
        opts.collect_pystacks = true;
    }

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

    let config = Config::from(opts);

    // Fork the traced child BEFORE systing() to ensure single-threaded context.
    // The child blocks on a pipe until BPF is ready, then exec's the command.
    let traced_child = if let Some(ref cmd) = config.run_command {
        Some(traced_command::spawn_traced_child(cmd)?)
    } else {
        None
    };

    let exit_code = systing(config, traced_child)?;
    if exit_code != 0 {
        process::exit(exit_code);
    }
    Ok(())
}
