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

use systing::stream::StreamTarget;
use systing::traced_command;
use systing::{get_available_recorders, systing, Config};

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
    /// Target CPU stack-sampling rate in Hz (samples per second per CPU). The
    /// perf clock event runs in fixed-period mode, so this is exact for
    /// --sw-event and the rate at max CPU frequency for cpu-cycles.
    #[arg(long, default_value_t = systing::DEFAULT_SAMPLE_FREQ_HZ,
          value_parser = clap::value_parser!(u64).range(1..))]
    sample_freq: u64,
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
    /// Capture user stacks as (build-id, file offset) pairs instead of raw
    /// IPs, so frames of exited processes remain symbolizable from a
    /// build-id-keyed store; unresolved frames render as
    /// "unknown ([buildid:<hex>]) <0x<offset>>" and stay resolvable offline
    #[arg(long)]
    collect_build_id: bool,
    /// Enable debug output for pystacks (Python stack tracing)
    #[arg(long)]
    pystacks_debug: bool,
    /// Enable debuginfod for enhanced symbol resolution (requires DEBUGINFOD_URLS environment variable)
    #[arg(long)]
    enable_debuginfod: bool,
    /// Render frames that fail symbolization as bare hex instead of contextual
    /// labels like "unknown ([gvisor:runtime]) <0x...>" or "unknown ([jit:node]) <0x...>"
    #[arg(long)]
    no_frame_labels: bool,
    /// Do not query gVisor sandboxes' control sockets for guest maps during
    /// symbolization
    #[arg(long)]
    no_gvisor_guest_maps: bool,
    /// Do not symbolize stripped Go binaries from their .gopclntab (revert
    /// to symbol-table-only resolution, which renders them as hex)
    #[arg(long)]
    no_gopclntab: bool,
    /// Resolve user-space symbols from ELF symbol tables only: skips DWARF
    /// debug info, source line info, inlined-function resolution, and
    /// debuginfod. Function names are unchanged for binaries that carry a
    /// symbol table; frames lose their "[file:line]" suffix and inlined
    /// frames collapse into their caller. Bounds symbolization memory on
    /// hosts running many freshly-built debug binaries (CI), where parsed
    /// debug info — cached per binary with no eviction — otherwise reaches
    /// GiBs.
    #[arg(long)]
    symbolize_names_only: bool,
    /// Collapse generic/template argument groups in over-long symbol names:
    /// names longer than 256 bytes render as `path::func<...>` instead of
    /// carrying the full monomorphized argument list, keeping their path
    /// head and function segment. Deeply generic Rust and C++ names
    /// legitimately demangle to multi-kilobyte strings; one hot name
    /// repeated across millions of recorded frames dominates recorder
    /// memory and trace size. Names of 256 bytes or less are unchanged.
    #[arg(long)]
    symbolize_elide_generics: bool,
    /// Disable scheduler event tracing (sched_* tracepoints and scheduler event recorder)
    #[arg(long)]
    no_sched: bool,
    /// Disable IRQ and softirq event tracing (irq_handler_* and softirq_* tracepoints)
    #[arg(long)]
    no_irq: bool,
    /// Enable syscall tracing (raw_syscalls:sys_enter and sys_exit tracepoints)
    #[arg(long)]
    syscalls: bool,
    // Memory recording enabled state (set by recorder management, not a CLI flag)
    #[arg(skip)]
    memory: bool,
    /// Sample 1 in N user page faults when the memory recorder is enabled (0 or 1 = record all)
    #[arg(long, default_value = "97")]
    memory_fault_sample_rate: u32,
    /// Override the minimum byte-drift between emitted rss_stat events (default: max(16 MiB, 64*nr_cpus*page_size); 0 = emit every event)
    #[arg(long)]
    memory_rss_threshold_bytes: Option<u64>,
    /// Force the classic tracepoint/kmem/rss_stat attach path even when tp_btf/rss_stat is available (testing only)
    #[arg(long, hide = true)]
    memory_rss_force_classic: bool,
    // Heap-allocator tracing enabled state (set by recorder management, not a CLI flag)
    #[arg(skip)]
    memory_alloc: bool,
    /// Sample 1 in N allocator calls (malloc/free/...) when the memory-alloc recorder is enabled (0 or 1 = record all). Note: values > 1 sample alloc and free independently, so addr-based alloc/free pairing for leak detection is unreliable; use for hotspot profiling.
    #[arg(long, default_value = "1")]
    memory_alloc_sample_rate: u32,
    /// Override allocator library for memory-alloc uprobes. Absolute path is used verbatim (host namespace); bare name is resolved per-pid via /proc/<pid>/maps (container-safe). An absolute path also works around the pre-exec limitation when tracing via `-- <cmd>`.
    #[arg(long)]
    memory_alloc_lib: Option<String>,
    /// Prefix prepended to malloc/free/... symbol names when attaching memory-alloc uprobes (e.g. "je_" for jemalloc built with --with-jemalloc-prefix).
    #[arg(long)]
    memory_alloc_symbol_prefix: Option<String>,
    // Network recording enabled state (set by recorder management, not a CLI flag)
    #[arg(skip)]
    network: bool,
    // Network packet-level probes (set by recorder management, not a CLI flag)
    #[arg(skip)]
    network_packets: bool,
    // Network syscall-level probes (set by recorder management, not a CLI flag)
    #[arg(skip)]
    network_syscalls: bool,
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
    /// - .systing or .systing.gz: profile export (docs/PROFILE_EXPORT_FORMAT.md)
    #[arg(long, default_value = "trace.pb")]
    output: PathBuf,

    /// Skip trace generation, keep only parquet files
    #[arg(long)]
    parquet_only: bool,

    /// Stream parquet over a socket instead of writing to disk.
    /// URI: vsock://CID:PORT | unix:///path/to.sock | tcp://host:port
    /// (tcp is unauthenticated; trusted networks only).
    #[arg(long, value_name = "URI", conflicts_with_all = ["output", "parquet_only"])]
    stream: Option<StreamTarget>,

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
            sample_freq: cmd.sample_freq,
            cpu_frequency: cmd.cpu_frequency,
            perf_counter: cmd.perf_counter,
            no_cpu_stack_traces: cmd.no_cpu_stack_traces,
            no_sleep_stack_traces: cmd.no_sleep_stack_traces,
            no_interruptible_stack_traces: cmd.no_interruptible_stack_traces,
            trace_event_config: cmd.trace_event_config,
            continuous: cmd.continuous,
            collect_pystacks: cmd.collect_pystacks,
            collect_build_id: cmd.collect_build_id,
            pystacks_pids: Vec::new(), // CLI doesn't expose this yet, uses discovery
            pystacks_debug: cmd.pystacks_debug,
            enable_debuginfod: cmd.enable_debuginfod,
            no_frame_labels: cmd.no_frame_labels,
            no_gvisor_guest_maps: cmd.no_gvisor_guest_maps,
            no_gopclntab: cmd.no_gopclntab,
            symbolize_names_only: cmd.symbolize_names_only,
            symbolize_elide_generics: cmd.symbolize_elide_generics,
            no_sched: cmd.no_sched,
            no_irq: cmd.no_irq,
            syscalls: cmd.syscalls,
            markers: cmd.markers,
            marker_threshold: cmd.marker_threshold,
            marker_duration_threshold: cmd.marker_duration_threshold,
            memory: cmd.memory,
            memory_fault_sample_rate: cmd.memory_fault_sample_rate,
            memory_rss_threshold_bytes: cmd.memory_rss_threshold_bytes,
            memory_rss_force_classic: cmd.memory_rss_force_classic,
            memory_alloc: cmd.memory_alloc,
            memory_alloc_sample_rate: cmd.memory_alloc_sample_rate,
            memory_alloc_lib: cmd.memory_alloc_lib,
            memory_alloc_symbol_prefix: cmd.memory_alloc_symbol_prefix,
            network: cmd.network,
            network_packets: cmd.network_packets,
            network_syscalls: cmd.network_syscalls,
            resolve_addresses: cmd.resolve_addresses,
            tpu_profile: cmd.tpu_profile,
            tpu_service_addr: cmd.tpu_service_addr,
            tpu_metrics: cmd.tpu_metrics,
            tpu_metrics_addr: cmd.tpu_metrics_addr,
            tpu_metrics_interval: cmd.tpu_metrics_interval,
            output_dir: cmd.output_dir,
            output: cmd.output,
            parquet_only: cmd.parquet_only,
            stream: cmd.stream,
            run_command: if cmd.run_command.is_empty() {
                None
            } else {
                Some(cmd.run_command)
            },
        }
    }
}

/// How a recorder name was selected on the command line. `--add-recorder`
/// also enables the companion recorders a name defaults to (network brings
/// in packet-level tracing); `--only-recorder` enables exactly the named
/// recorders.
#[derive(Clone, Copy, PartialEq)]
enum Selection {
    WithCompanions,
    Exact,
}

fn enable_recorder(opts: &mut Command, recorder_name: &str, enable: bool, selection: Selection) {
    match recorder_name {
        "syscalls" => opts.syscalls = enable,
        "sched" => opts.no_sched = !enable,
        "irq" => opts.no_irq = !enable,
        "sleep-stacks" => opts.no_sleep_stack_traces = !enable,
        "interruptible-stacks" => opts.no_interruptible_stack_traces = !enable,
        "tpu" => opts.tpu_profile = enable,
        "cpu-stacks" => opts.no_cpu_stack_traces = !enable,
        "network" => {
            opts.network = enable;
            // --add-recorder network also enables packet-level tracing (the
            // common investigation shape), while --only-recorder network is
            // state-only: TCP connection/state tracking without the
            // per-packet kprobes. Disabling network always disables packets,
            // which cannot run without it.
            if selection == Selection::WithCompanions || !enable {
                opts.network_packets = enable;
            }
            // The syscalls tier also cannot run without the base recorder,
            // but it is never a companion default — only the disable cascades.
            if !enable {
                opts.network_syscalls = false;
            }
        }
        "network-packets" => {
            opts.network_packets = enable;
            // Packet probes require the network infrastructure (ringbufs, consumers),
            // so enabling network-packets also enables the base network recorder.
            if enable {
                opts.network = true;
            }
        }
        "network-syscalls" => {
            opts.network_syscalls = enable;
            // Syscall probes require the network infrastructure (ringbufs,
            // consumers), so enabling network-syscalls also enables the base
            // network recorder.
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
        opts.no_irq = true;
        opts.syscalls = false;
        opts.no_sleep_stack_traces = true;
        opts.no_interruptible_stack_traces = true;
        opts.no_cpu_stack_traces = true;
        opts.memory = false;
        opts.memory_alloc = false;
        opts.network = false;
        opts.network_packets = false;
        opts.network_syscalls = false;
        opts.markers = false;
        opts.tpu_profile = false;
        opts.tpu_metrics = false;

        // Then enable exactly the specified recorders — no companion
        // defaults, so `--only-recorder network` yields state-only tracing.
        let recorders = opts.only_recorder.clone();
        for recorder_name in &recorders {
            enable_recorder(opts, recorder_name, true, Selection::Exact);
        }
    }

    // Process --add-recorder to enable additional recorders, with their
    // companion defaults (network brings in network-packets).
    let recorders = opts.add_recorder.clone();
    for recorder_name in &recorders {
        enable_recorder(opts, recorder_name, true, Selection::WithCompanions);
    }
    Ok(())
}

/// Check if we have the necessary capabilities to run BPF programs.
///
/// systing needs to load BPF programs and open tracing perf events, which on
/// modern kernels requires CAP_BPF + CAP_PERFMON (split out in 5.8), or
/// CAP_SYS_ADMIN as the legacy catch-all. Checks the effective set via
/// capget(2) so file capabilities / ambient caps are honored even when
/// euid != 0.
fn has_bpf_capabilities() -> bool {
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;
    const CAP_SYS_ADMIN: u32 = 21;
    const CAP_PERFMON: u32 = 38;
    const CAP_BPF: u32 = 39;

    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: libc::c_int,
    }
    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    let mut hdr = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapData::default(); 2];
    // SAFETY: hdr/data are #[repr(C)] with the kernel ABI layout for capget(2);
    // version 3 always writes exactly two cap_data structs.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_capget,
            &mut hdr as *mut CapHeader,
            data.as_mut_ptr(),
        )
    };
    if ret != 0 {
        return false;
    }

    let has = |cap: u32| data[(cap >> 5) as usize].effective & (1u32 << (cap & 31)) != 0;
    has(CAP_SYS_ADMIN) || (has(CAP_BPF) && has(CAP_PERFMON))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn opts_from(args: &[&str]) -> Command {
        let mut opts = Command::parse_from(std::iter::once("systing").chain(args.iter().copied()));
        process_recorder_options(&mut opts).expect("valid recorder names");
        opts
    }

    #[test]
    fn only_recorder_network_is_state_only() {
        let opts = opts_from(&["--only-recorder", "network"]);
        assert!(opts.network);
        assert!(
            !opts.network_packets,
            "--only-recorder network must not enable packet-level tracing"
        );
        // Everything outside the named recorder stays off.
        assert!(opts.no_sched);
        assert!(opts.no_cpu_stack_traces);
        assert!(!opts.memory);
    }

    #[test]
    fn only_recorder_network_packets_enables_base_network() {
        let opts = opts_from(&["--only-recorder", "network-packets"]);
        assert!(
            opts.network,
            "packet probes require the base network recorder"
        );
        assert!(opts.network_packets);
    }

    #[test]
    fn only_recorder_network_order_independent() {
        for args in [
            [
                "--only-recorder",
                "network",
                "--only-recorder",
                "network-packets",
            ],
            [
                "--only-recorder",
                "network-packets",
                "--only-recorder",
                "network",
            ],
        ] {
            let opts = opts_from(&args);
            assert!(opts.network);
            assert!(opts.network_packets);
        }
    }

    #[test]
    fn add_recorder_network_keeps_packet_companion() {
        let opts = opts_from(&["--add-recorder", "network"]);
        assert!(opts.network);
        assert!(
            opts.network_packets,
            "--add-recorder network keeps enabling packet tracing by default"
        );
        // Default recorders stay on in add mode.
        assert!(!opts.no_sched);
        assert!(!opts.no_cpu_stack_traces);
    }

    #[test]
    fn add_recorder_network_packets_enables_base_network() {
        let opts = opts_from(&["--add-recorder", "network-packets"]);
        assert!(opts.network);
        assert!(opts.network_packets);
    }

    #[test]
    fn no_recorder_flags_leave_network_off() {
        let opts = opts_from(&[]);
        assert!(!opts.network);
        assert!(!opts.network_packets);
    }

    #[test]
    fn only_recorder_memory_alloc_enables_base_memory() {
        let opts = opts_from(&["--only-recorder", "memory-alloc"]);
        assert!(
            opts.memory,
            "memory-alloc shares the memory ringbuf/consumer"
        );
        assert!(opts.memory_alloc);
        assert!(!opts.network);
    }

    #[test]
    fn only_recorder_network_syscalls_omits_packets() {
        let opts = opts_from(&["--only-recorder", "network-syscalls"]);
        assert!(
            opts.network,
            "syscall probes require the base network recorder"
        );
        assert!(opts.network_syscalls);
        assert!(
            !opts.network_packets,
            "network-syscalls must not enable per-packet tracing"
        );
    }

    #[test]
    fn add_recorder_network_syscalls_omits_packets() {
        let opts = opts_from(&["--add-recorder", "network-syscalls"]);
        assert!(opts.network);
        assert!(opts.network_syscalls);
        assert!(!opts.network_packets);
    }

    #[test]
    fn add_recorder_network_does_not_imply_syscalls_tier() {
        let opts = opts_from(&["--add-recorder", "network"]);
        assert!(opts.network_packets, "packets stay the add-mode companion");
        assert!(
            !opts.network_syscalls,
            "the syscalls tier is never implied; name it"
        );
    }

    #[test]
    fn only_recorder_syscalls_and_packets_tiers_union() {
        let opts = opts_from(&[
            "--only-recorder",
            "network-syscalls",
            "--only-recorder",
            "network-packets",
        ]);
        assert!(opts.network);
        assert!(opts.network_syscalls);
        assert!(opts.network_packets);
    }
}
