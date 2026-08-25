//! Trace data model structs shared between systing and systing-analyze.
//!
//! These structs represent the canonical format for trace data stored in Parquet files.
//! Both the recording path (systing) and analysis path (systing-analyze) use these types.

/// Process information extracted from trace.
///
/// # Fields
/// - `upid`: Unique process ID (internal, not the OS pid)
/// - `pid`: OS process ID
/// - `name`: Process name (from /proc/pid/comm or similar)
/// - `parent_upid`: Parent process's upid (for process tree)
/// - `cmdline`: Full command line arguments (from /proc/pid/cmdline).
///   May be empty for short-lived processes that exit before cmdline can be read,
///   or for kernel threads which have no cmdline (see `is_kernel_thread`).
/// - `is_kernel_thread`: Whether this process is a kernel thread (e.g., kworker,
///   migration, ksoftirqd). Kernel threads have no executable or cmdline.
/// - `cgroup_id`: Numeric id of the process's cgroup in the v2 unified hierarchy
///   (the cgroup directory's kernfs node id / inode). Captured in-kernel at event
///   time, so it is available even for short-lived processes that exit before their
///   `/proc` entry can be read. `0` means unknown.
/// - `cgroup_path`: Best-effort path of that cgroup relative to the cgroup root
///   (e.g. `/system.slice/foo.service`), resolved by walking the live cgroup
///   hierarchy when the trace is written. `None` if the cgroup could not be
///   resolved (e.g. it was removed before the trace was written). Resolution is
///   racy: because kernfs inode numbers can be reused, an id whose cgroup was
///   removed and replaced before the walk may resolve to a *different* cgroup's
///   path. `cgroup_id` is always faithful; treat the path as a hint.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct ProcessRecord {
    pub upid: i64,
    pub pid: i32,
    pub name: Option<String>,
    pub parent_upid: Option<i64>,
    pub cmdline: Vec<String>,
    pub is_kernel_thread: bool,
    pub cgroup_id: u64,
    pub cgroup_path: Option<String>,
}

/// Thread information extracted from trace.
///
/// # Fields
/// - `utid`: Unique thread ID (internal, not the OS tid)
/// - `tid`: OS thread ID
/// - `name`: Thread name
/// - `upid`: Parent process's upid (references `ProcessRecord.upid`)
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct ThreadRecord {
    pub utid: i64,
    pub tid: i32,
    pub name: Option<String>,
    pub upid: Option<i64>,
}

/// Scheduler slice record - represents time a thread ran on a CPU.
///
/// # Fields
/// - `ts`: Start timestamp in nanoseconds (trace clock)
/// - `dur`: Duration in nanoseconds (0 if slice is still open)
/// - `cpu`: CPU core number where the thread ran
/// - `utid`: Unique thread ID (references `ThreadRecord.utid`)
/// - `end_state`: Raw kernel task state value when the thread stopped running.
///   `None` means TASK_RUNNING (0), i.e., the thread was preempted while still runnable.
///   Common values: 1=TASK_INTERRUPTIBLE, 2=TASK_UNINTERRUPTIBLE, 4=__TASK_STOPPED.
/// - `priority`: Thread priority (nice value)
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SchedSliceRecord {
    pub ts: i64,
    pub dur: i64,
    pub cpu: i32,
    pub utid: i64,
    pub end_state: Option<i32>,
    pub priority: i32,
}

/// Thread state record - represents thread state changes.
///
/// # Fields
/// - `ts`: Timestamp when state change occurred
/// - `dur`: Duration in this state (0 if still in state)
/// - `utid`: Unique thread ID (references `ThreadRecord.utid`)
/// - `state`: Raw kernel task state value.
///   Common values: 0=TASK_RUNNING (runnable), 1=TASK_INTERRUPTIBLE,
///   2=TASK_UNINTERRUPTIBLE, 4=__TASK_STOPPED, 8=__TASK_TRACED.
/// - `cpu`: Target CPU for wakeups (only set for state=0/runnable)
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ThreadStateRecord {
    pub ts: i64,
    pub dur: i64,
    pub utid: i64,
    pub state: i32,
    pub cpu: Option<i32>,
}

/// IRQ slice record - represents time an IRQ handler ran on a CPU.
///
/// # Fields
/// - `ts`: Start timestamp in nanoseconds (handler entry)
/// - `dur`: Duration in nanoseconds
/// - `cpu`: CPU core number where the IRQ was handled
/// - `irq`: IRQ number
/// - `name`: IRQ handler name (e.g., "ahci", "xhci_hcd")
/// - `ret`: Return value from the handler
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IrqSliceRecord {
    pub ts: i64,
    pub dur: i64,
    pub cpu: i32,
    pub irq: i32,
    pub name: Option<String>,
    pub ret: Option<i32>,
}

/// Softirq slice record - represents time a softirq ran on a CPU.
///
/// # Fields
/// - `ts`: Start timestamp in nanoseconds
/// - `dur`: Duration in nanoseconds
/// - `cpu`: CPU core number where the softirq ran
/// - `vec`: Softirq vector (0=HI, 1=TIMER, 2=NET_TX, 3=NET_RX, 4=BLOCK, etc.)
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SoftirqSliceRecord {
    pub ts: i64,
    pub dur: i64,
    pub cpu: i32,
    pub vec: i32,
}

/// Wakeup new record - represents a new process/thread being woken for the first time.
///
/// # Fields
/// - `ts`: Wakeup timestamp in nanoseconds
/// - `cpu`: CPU where the wakeup event was processed
/// - `utid`: Unique thread ID of the new thread
/// - `target_cpu`: CPU where the new thread will run
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WakeupNewRecord {
    pub ts: i64,
    pub cpu: i32,
    pub utid: i64,
    pub target_cpu: i32,
}

/// Sched migrate record - a task's CPU changed (`sched_migrate_task`).
///
/// Emitted at wakeup when the scheduler placed the task on a CPU other than
/// the one it last ran on (the runnable marker in `thread_state` is recorded
/// before that choice and carries only the previous CPU), and whenever the
/// load balancer, NUMA balancing, or an affinity change moves a runnable
/// task. A woken task with no migrate record before its next slice ran on
/// its previous CPU.
///
/// # Fields
/// - `ts`: Timestamp in nanoseconds
/// - `utid`: Unique thread ID of the migrated thread
/// - `orig_cpu`: CPU the task is leaving (its CPU before the move)
/// - `dest_cpu`: CPU the task is moved to
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SchedMigrateRecord {
    pub ts: i64,
    pub utid: i64,
    pub orig_cpu: i32,
    pub dest_cpu: i32,
}

/// Process exit record - represents a process/thread exiting.
///
/// # Fields
/// - `ts`: Exit timestamp in nanoseconds
/// - `cpu`: CPU where the exit occurred
/// - `utid`: Unique thread ID of the exiting thread
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProcessExitRecord {
    pub ts: i64,
    pub cpu: i32,
    pub utid: i64,
}

/// Counter value record.
///
/// Note: Cannot derive `Eq` because `value` is `f64`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CounterRecord {
    pub ts: i64,
    pub track_id: i64,
    pub value: f64,
}

/// Counter track metadata.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CounterTrackRecord {
    pub id: i64,
    pub name: String,
    pub unit: Option<String>,
}

/// Slice record - represents a time range event (function call, etc).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SliceRecord {
    pub id: i64,
    pub ts: i64,
    pub dur: i64,
    pub track_id: i64,
    pub utid: Option<i64>,
    pub name: String,
    pub category: Option<String>,
    pub depth: i32,
}

/// Track metadata record.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrackRecord {
    pub id: i64,
    pub name: String,
    pub parent_id: Option<i64>,
}

/// Instant event record.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InstantRecord {
    pub id: i64,
    pub ts: i64,
    pub track_id: i64,
    pub utid: Option<i64>,
    pub name: String,
    pub category: Option<String>,
}

/// Argument record for slice events.
///
/// Note: Cannot derive `Eq` because `real_value` is `f64`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ArgRecord {
    pub slice_id: i64,
    pub key: String,
    pub int_value: Option<i64>,
    pub string_value: Option<String>,
    pub real_value: Option<f64>,
}

/// Argument record for instant events.
///
/// Note: Cannot derive `Eq` because `real_value` is `f64`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct InstantArgRecord {
    pub instant_id: i64,
    pub key: String,
    pub int_value: Option<i64>,
    pub string_value: Option<String>,
    pub real_value: Option<f64>,
}

// Stack profiling records

/// Stack record - represents a complete call stack as arrays.
///
/// This is a query-friendly representation that stores the entire stack
/// in arrays, avoiding the need for recursive CTEs to reconstruct stacks.
///
/// Frame names contain embedded information in the format:
/// `function_name (module_name [file:line]) <0xaddr>`
/// This allows Perfetto conversion to extract module names on-the-fly.
///
/// # Fields
/// - `id`: Unique stack ID
/// - `frame_names`: Function names from root to leaf (with embedded module/location info)
/// - `depth`: Number of frames in the stack
/// - `leaf_name`: Innermost (executing) frame's name — the last entry of
///   `frame_names` (redundant but enables fast filtering)
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StackRecord {
    pub id: i64,
    pub frame_names: Vec<String>,
    pub depth: i32,
    pub leaf_name: String,
}

/// Stack sample record - represents a single profiling sample.
///
/// References a StackRecord by stack_id rather than using a callsite chain.
///
/// # Fields
/// - `ts`: Timestamp in nanoseconds
/// - `utid`: Unique thread ID (references ThreadRecord.utid)
/// - `cpu`: CPU core number (optional)
/// - `stack_id`: Reference to StackRecord.id
/// - `stack_event_type`: Type of stack capture (0=STACK_SLEEP_UNINTERRUPTIBLE, 1=STACK_RUNNING, 2=STACK_SLEEP_INTERRUPTIBLE)
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StackSampleRecord {
    pub ts: i64,
    pub utid: i64,
    pub cpu: Option<i32>,
    pub stack_id: i64,
    pub stack_event_type: i8,
}

// Network metadata records

/// Network interface record.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetworkInterfaceRecord {
    pub namespace: String,
    pub interface_name: String,
    pub ip_address: String,
    pub address_type: String,
    /// Inode of the network namespace this interface/IP belongs to. Lets the
    /// fold join a flow's `network_socket.netns_inum` to its owning netns
    /// without going through the IP (unambiguous for loopback). 0 if unknown.
    pub netns_inum: i64,
}

/// Socket connection record.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SocketConnectionRecord {
    pub socket_id: i64,
    pub track_id: i64,
    pub protocol: String,
    pub src_ip: String,
    pub src_port: i32,
    pub dest_ip: String,
    pub dest_port: i32,
    pub address_family: String,
}

// New network schema records (Phase 1 of network recorder refactor)

/// Network syscall record - represents network syscalls with flattened fields.
///
/// Replaces slice + args for network events, enabling direct column access
/// instead of key-value pivot queries.
///
/// # Fields
/// - `id`: Unique event ID
/// - `ts`: Start timestamp in nanoseconds
/// - `dur`: Duration in nanoseconds
/// - `utid`: Unique thread ID (joins `thread.utid`)
/// - `event_type`: Type like "tcp_send", "tcp_recv", "udp_send"
/// - `socket_id`: Socket identifier (FK to network_socket)
/// - `bytes`: Bytes transferred
/// - `seq`: TCP sequence number (optional)
/// - `sndbuf_used`: Send buffer usage (optional)
/// - `sndbuf_limit`: Send buffer limit (optional)
/// - `sndbuf_fill_pct`: Buffer fill percentage (optional)
/// - `recv_seq_start`: TCP recv: copied_seq at entry (optional)
/// - `recv_seq_end`: TCP recv: copied_seq at exit (optional)
/// - `rcv_nxt`: TCP recv: next expected seq (optional)
/// - `bytes_available`: TCP recv: data buffered (optional)
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetworkSyscallRecord {
    pub id: i64,
    pub ts: i64,
    pub dur: i64,
    pub utid: i64,
    pub event_type: String,
    pub socket_id: i64,
    pub bytes: i64,
    pub seq: Option<i64>,
    pub sndbuf_used: Option<i64>,
    pub sndbuf_limit: Option<i64>,
    pub sndbuf_fill_pct: Option<i16>,
    pub recv_seq_start: Option<i64>,
    pub recv_seq_end: Option<i64>,
    pub rcv_nxt: Option<i64>,
    pub bytes_available: Option<i64>,
}

/// Network packet record - represents packet-level events with flattened fields.
///
/// Replaces instant + instant_args for network events. Single table for all packet
/// event types with nullable fields (Parquet handles sparse columns efficiently).
///
/// Event types: packet_enqueue, packet_send, packet_rcv_established, packet_queue_rcv,
/// buffer_queue, zero_window_probe, zero_window_ack, rto_timeout, udp_send, udp_receive,
/// udp_enqueue, packet_drop, cpu_backlog_drop, mem_pressure, tsq_throttle, qdisc_enqueue,
/// qdisc_dequeue, tx_queue_stop, tx_queue_wake
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkPacketRecord {
    pub id: i64,
    pub ts: i64,
    pub socket_id: i64,
    pub event_type: &'static str,
    pub seq: Option<i64>,
    pub length: i32,
    pub tcp_flags: Option<u8>,
    // Send buffer fields
    pub sndbuf_used: Option<i64>,
    pub sndbuf_limit: Option<i64>,
    pub sndbuf_fill_pct: Option<i16>,
    // Retransmit fields
    pub is_retransmit: bool,
    pub retransmit_count: Option<i16>,
    pub rto_ms: Option<i32>,
    pub srtt_ms: Option<i32>,
    pub rttvar_us: Option<i32>,
    pub backoff: Option<i16>,
    // Zero window fields
    pub is_zero_window_probe: bool,
    pub is_zero_window_ack: bool,
    pub probe_count: Option<i16>,
    // Window fields
    pub snd_wnd: Option<i32>,
    pub rcv_wnd: Option<i32>,
    pub rcv_buf_used: Option<i64>,
    pub rcv_buf_limit: Option<i64>,
    pub window_clamp: Option<i32>,
    pub rcv_wscale: Option<i16>,
    // Timer fields
    pub icsk_pending: Option<i16>,
    pub icsk_timeout: Option<i64>,
    // Drop fields
    pub drop_reason: Option<i32>,
    pub drop_location: Option<i64>,
    // Queue fields
    pub qlen: Option<i32>,
    pub qlen_limit: Option<i32>,
    // TSQ fields
    pub sk_wmem_alloc: Option<i64>,
    pub tsq_limit: Option<i64>,
    // TX queue fields
    pub txq_state: Option<i32>,
    pub qdisc_state: Option<i32>,
    pub qdisc_backlog: Option<i64>,
    // SKB correlation
    pub skb_addr: Option<i64>,
    pub qdisc_latency_us: Option<i32>,
    // TCP state change fields
    pub old_state: Option<i16>,
    pub new_state: Option<i16>,
}

/// Network socket record - represents socket metadata.
///
/// Replaces socket_connection with a cleaner schema (no track_id needed).
/// Socket info extracted directly from BPF events for true streaming.
///
/// Normally one record per socket per capture. A socket whose identity
/// was created by an event that fires before the kernel has filled in
/// the tuple emits its first record with the degraded tuple and ONE
/// upgraded record with the complete tuple when a later event carries
/// it. Two events do this: a pre-bind state transition (connect-start
/// fires before the ephemeral port is assigned — `src_port` 0), and on
/// kernels before 6.15 the LISTEN→SYN_RECV transition of a passive open
/// (fires before the peer is copied into the child socket — `dest_ip`
/// the wildcard `0.0.0.0` / `::` and `dest_port` 0; Linux a3a128f611a9
/// reordered it in 6.15). Readers keeping one row per `socket_id`
/// should prefer the row whose `src_port` is nonzero AND whose peer is
/// not the wildcard-with-port-0 shape; a socket that only ever shows a
/// degraded tuple (a real listener, an unconnected UDP socket) has one
/// record.
///
/// # Fields
/// - `socket_id`: Unique socket ID (primary key)
/// - `protocol`: "TCP" or "UDP"
/// - `address_family`: "IPv4" or "IPv6"
/// - `src_ip`: Source IP address
/// - `src_port`: Source port
/// - `dest_ip`: Destination IP address
/// - `dest_port`: Destination port
/// - `first_seen_ts`: First event timestamp (optional)
/// - `last_seen_ts`: Last event timestamp (optional)
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetworkSocketRecord {
    pub socket_id: i64,
    /// Inode of the socket's network namespace. Joins `network_interface.netns_inum`
    /// to attribute the flow to its owning netns (hence pod) directly, without
    /// inferring from src_ip (which cannot disambiguate loopback). 0 if unknown.
    pub netns_inum: i64,
    pub protocol: String,
    pub address_family: String,
    pub src_ip: String,
    pub src_port: i32,
    pub dest_ip: String,
    pub dest_port: i32,
    pub first_seen_ts: Option<i64>,
    pub last_seen_ts: Option<i64>,
}

/// Network DNS record - maps IP addresses to resolved hostnames.
///
/// # Fields
/// - `ip_address`: IP address string
/// - `hostname`: Resolved hostname
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetworkDnsRecord {
    pub ip_address: String,
    pub hostname: String,
}

/// Network poll record - represents socket poll events.
///
/// Dedicated table for poll events that were previously mixed with other events.
///
/// # Fields
/// - `id`: Unique event ID
/// - `ts`: Timestamp in nanoseconds
/// - `utid`: Unique thread ID (joins `thread.utid`)
/// - `socket_id`: Socket identifier
/// - `requested_events`: Events requested (e.g., "IN|OUT|PRI")
/// - `returned_events`: Events returned (e.g., "IN")
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetworkPollRecord {
    pub id: i64,
    pub ts: i64,
    pub utid: i64,
    pub socket_id: i64,
    pub requested_events: String,
    pub returned_events: String,
}

/// Clock snapshot record - for timestamp correlation between clock domains.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClockSnapshotRecord {
    pub clock_id: i32,
    pub clock_name: String,
    pub timestamp_ns: i64,
    pub is_primary: bool,
}

/// System info record - kernel version, machine, and platform information.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SysInfoRecord {
    pub sysname: String,
    pub release: String,
    pub version: String,
    pub machine: String,
    /// cpufreq scaling driver name (e.g. "intel_pstate"); `None` when the
    /// kernel has no cpufreq support (typical for VM guests), in which case
    /// CPU-frequency counter data is absent or meaningless.
    pub cpufreq_driver: Option<String>,
    /// Hypervisor the trace was captured under (e.g. "kvm"). `None` means no
    /// hypervisor was detected; on x86_64 (CPUID-based) that reliably means
    /// bare metal, on other architectures the check is best-effort and `None`
    /// may just mean detection was unavailable.
    pub hypervisor: Option<String>,
    /// DMI system vendor (e.g. "Amazon EC2"), if exposed.
    pub sys_vendor: Option<String>,
    /// DMI product name (e.g. "m7i.16xlarge"), if exposed.
    pub product_name: Option<String>,
    /// Perf event driving CPU stack sampling: "cpu-cycles" (hardware) or
    /// "cpu-clock" (software fallback). `None` in traces from systing < 1.9
    /// (which sampled cycles in adaptive frequency mode at a nominal 1000 Hz).
    pub sample_event: Option<String>,
    /// Stack sampling period in event units: each `stack_sample` row with
    /// `stack_event_type` = 1 represents this many cycles ("cpu-cycles") or
    /// nanoseconds ("cpu-clock") of execution. `None` in traces from
    /// systing < 1.9.
    pub sample_period: Option<i64>,
    /// How the memory recorder's page-fault leg ran: "tracepoint" (x86,
    /// `exceptions:page_fault_user`), "perf_sw" (every other arch, one
    /// PERF_COUNT_SW_PAGE_FAULTS event per CPU) or "off:<cause>" (the
    /// perf-event leg could not be opened or attached on this host, e.g.
    /// "off:EMFILE", and the capture ran without it — `memory_fault` is then
    /// empty by construction). `None` when the memory recorder was not
    /// enabled, and in traces from systing < 1.14.
    pub memory_fault_leg: Option<String>,
    /// `--memory-fault-sample-rate` as configured: `memory_fault` holds 1 in
    /// N user page faults (0 and 1 both mean every fault). `None` when the
    /// memory recorder was not enabled, and in traces from systing < 1.14.
    pub memory_fault_sample_rate: Option<i64>,
    /// `--memory-map-sample-rate` as configured: each `memory_map` event
    /// type is sampled 1 in N (1 = every event). `None` when the memory
    /// recorder was not enabled, and in traces from systing < 1.14.
    pub memory_map_sample_rate: Option<i64>,
    /// `--memory-alloc-sample-rate` as configured (1 = every call). `None`
    /// when the `memory-alloc` recorder was not enabled, and in traces from
    /// systing < 1.14.
    pub memory_alloc_sample_rate: Option<i64>,
}

/// Per-CPU static frequency limits from sysfs cpufreq, in kHz.
///
/// One row per CPU that exposes cpufreq data; the table is empty on systems
/// without cpufreq support (typical for VM guests). With cycles-based stack
/// sampling (`sysinfo.sample_event` = "cpu-cycles") these bound the
/// cycles-to-time conversion for each CPU; per-CPU rows matter on
/// heterogeneous parts (P/E cores) where limits differ between CPUs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CpuInfoRecord {
    pub cpu: i32,
    pub min_freq_khz: Option<i64>,
    pub max_freq_khz: Option<i64>,
    /// Sustained (non-turbo) frequency; only exposed by some drivers
    /// (e.g. intel_pstate's `base_frequency`).
    pub base_freq_khz: Option<i64>,
}

/// Container for all extracted trace data.
/// Per-process RSS / VM counter sample.
///
/// `member` indexes the kernel `rss_stat` counter (0=file, 1=anon, 2=swap, 3=shmem).
/// Negative members are synthetic, from periodic mm snapshots: -1 = hiwater_rss
/// bytes, -2 = total_vm bytes, -3 = maj_flt (major fault count for the sampled
/// thread), -4 = delayacct thrashing stall count, -5 = delayacct thrashing
/// stall delay in ns. -4/-5 rows are emitted (zero values included) whenever
/// delayacct was readable on the host, so zero-valued rows mean "delayacct
/// on, no thrash", and their complete absence while -3 rows are present means
/// delayacct is not enabled (`CONFIG_TASK_DELAY_ACCT` plus the `delayacct`
/// boot parameter or `kernel.task_delayacct` sysctl).
///
/// Emission cadence: rss_stat samples are threshold-batched in BPF (one event
/// per ≥ `memory_rss_threshold_bytes` of drift per (tgid, member), default
/// max(16 MiB, 64·nr_cpus·page_size)), not one per kernel tracepoint firing.
/// On the `tp_btf/rss_stat` attach path (kernels ≥6.2 with BTF), `size` is
/// an approximate `percpu_counter_read()` of `mm->rss_stat[member]` — it
/// misses the per-CPU batch slots, so its worst-case error is
/// ±(percpu_counter_batch · nr_online_cpus) pages where the kernel sets
/// batch = max(32, 2·nr_online_cpus). On the classic `tracepoint/kmem/rss_stat`
/// fallback the kernel's own exact sum is used.
///
/// `external` is true when the sampled counter update was performed from
/// outside the process's own thread group — an external reclaimer (kswapd,
/// khugepaged, another process's direct reclaim, a memory.reclaim or
/// process_madvise writer) evicted or migrated the process's pages. False for
/// the process's own faults/maps/unmaps/exit teardown, for all synthetic
/// members, for exit-flush residuals (mixed provenance), and always on the
/// classic fallback attach path (which cannot resolve remote updates and
/// drops them instead). Under threshold batching the flag carries the
/// provenance of the update that crossed the threshold; the sub-threshold
/// drift folded into that emission may mix self and external updates.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MemoryRssRecord {
    pub ts: i64,
    pub utid: i64,
    pub member: i8,
    pub size: i64,
    pub external: bool,
}

/// Virtual address space change: mmap / munmap / brk.
///
/// `addr` and `size` describe the affected region (for brk, `addr` is the new
/// break and `size` is the signed delta in bytes, negative on shrink). For
/// munmap, `size` is the requested length bounded by the process's total
/// mapped size at call time -- an upper bound on what the call could free,
/// not necessarily a region of that size at `addr`.
///
/// `rss_delta_bytes` is the SIGNED change in the process's resident set across the
/// syscall, in bytes -- pages actually committed or freed, where `size` is
/// only the virtual-address range the arguments named. munmap is typically
/// negative (what the call really freed), mmap typically ~0 (mapping commits
/// nothing; faults do), brk either sign. `None` when either resident read was
/// unavailable, and on all pre-v15 rows. Three documented approximations:
/// concurrent faults/reclaim on other threads inside the syscall window land
/// in the delta (microsecond window, small drift); the resident reads carry
/// the same worst-case ±(percpu batch x nr_cpus pages) error as rss_stat
/// samples; and under `--memory-map-sample-rate` 1:N sampling, per-event
/// deltas exist only for sampled events -- aggregates scale by the stamped
/// rate like the byte sums.
/// `stack_id` joins to the `stack` table for allocation-site attribution.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MemoryMapRecord {
    pub id: i64,
    pub ts: i64,
    pub utid: i64,
    pub event_type: String,
    pub addr: i64,
    pub size: i64,
    pub rss_delta_bytes: Option<i64>,
    pub prot: Option<i32>,
    pub flags: Option<i32>,
    pub stack_id: Option<i64>,
}

/// Sampled user page fault with the faulting stack.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MemoryFaultRecord {
    pub ts: i64,
    pub utid: i64,
    pub addr: i64,
    pub error_code: i32,
    pub stack_id: Option<i64>,
}

/// Heap allocator call (malloc/calloc/realloc/aligned_alloc/posix_memalign/free)
/// captured via libc uprobes.
///
/// For `op == "free"`, `size` is 0. For `op == "realloc"`, `old_addr` is the
/// pointer passed in (implicitly freed when `addr != old_addr`). `stack_id`
/// joins to the `stack` table for allocation-site attribution.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MemoryAllocRecord {
    pub id: i64,
    pub ts: i64,
    pub utid: i64,
    pub op: String,
    pub addr: i64,
    pub size: i64,
    pub old_addr: Option<i64>,
    pub stack_id: Option<i64>,
}

#[derive(Debug, Default)]
pub struct ExtractedData {
    pub processes: Vec<ProcessRecord>,
    pub threads: Vec<ThreadRecord>,
    pub sched_slices: Vec<SchedSliceRecord>,
    pub thread_states: Vec<ThreadStateRecord>,
    pub irq_slices: Vec<IrqSliceRecord>,
    pub softirq_slices: Vec<SoftirqSliceRecord>,
    pub wakeup_news: Vec<WakeupNewRecord>,
    pub sched_migrates: Vec<SchedMigrateRecord>,
    pub process_exits: Vec<ProcessExitRecord>,
    pub counters: Vec<CounterRecord>,
    pub counter_tracks: Vec<CounterTrackRecord>,
    pub slices: Vec<SliceRecord>,
    pub tracks: Vec<TrackRecord>,
    pub instants: Vec<InstantRecord>,
    pub args: Vec<ArgRecord>,
    pub instant_args: Vec<InstantArgRecord>,
    pub stacks: Vec<StackRecord>,
    pub stack_samples: Vec<StackSampleRecord>,
    pub network_interfaces: Vec<NetworkInterfaceRecord>,
    pub socket_connections: Vec<SocketConnectionRecord>,
    pub network_syscalls: Vec<NetworkSyscallRecord>,
    pub network_packets: Vec<NetworkPacketRecord>,
    pub network_sockets: Vec<NetworkSocketRecord>,
    pub network_polls: Vec<NetworkPollRecord>,
    pub network_dns: Vec<NetworkDnsRecord>,
    pub memory_rss: Vec<MemoryRssRecord>,
    pub memory_maps: Vec<MemoryMapRecord>,
    pub memory_faults: Vec<MemoryFaultRecord>,
    pub memory_allocs: Vec<MemoryAllocRecord>,
    pub clock_snapshots: Vec<ClockSnapshotRecord>,
    pub sysinfo: Option<SysInfoRecord>,
    pub cpu_infos: Vec<CpuInfoRecord>,
    pub tpu_devices: Vec<TpuDeviceRecord>,
    pub tpu_ops: Vec<TpuOpRecord>,
    pub tpu_metrics: Vec<TpuMetricRecord>,
}
// TPU profiling records

/// TPU device metadata record.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TpuDeviceRecord {
    pub id: i64,
    pub device_ordinal: i32,
    pub chip_id: i32,
    pub core_id: i32,
    pub hostname: String,
    pub device_type: String,
    pub topology_x: i32,
    pub topology_y: i32,
    pub topology_z: i32,
    pub clock_rate_ghz: f64,
    pub hbm_size_bytes: i64,
    pub hbm_bandwidth_gbps: f64,
}

/// TPU per-HLO-operation execution record.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TpuOpRecord {
    pub id: i64,
    pub tpu_device_id: i64,
    pub ts: i64,
    pub dur: i64,
    /// XSpace group_id (training step identifier). Raw value from XLA profiler.
    pub group_id: Option<i64>,
    pub op_name: String,
    pub category: String,
    pub stream: String,
    pub flops: i64,
    pub bytes_accessed: i64,
    pub bytes_hbm: i64,
    pub bytes_cmem: i64,
    pub bytes_vmem: i64,
}

/// TPU runtime metric record (lightweight polling from RuntimeMetricService).
///
/// Stores a single metric value per device per sample in a normalized format.
/// Metric names come directly from the RuntimeMetricService, so the schema
/// adapts automatically to new metrics without code changes.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TpuMetricRecord {
    pub id: i64,
    pub ts: i64,
    pub device_id: i32,
    pub metric_name: String,
    pub value: f64,
}
