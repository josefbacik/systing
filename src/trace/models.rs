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
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct ProcessRecord {
    pub upid: i64,
    pub pid: i32,
    pub name: Option<String>,
    pub parent_upid: Option<i64>,
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
/// - `state`: State string (e.g., "R" for running, "S" for sleeping)
/// - `cpu`: Target CPU for wakeups
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ThreadStateRecord {
    pub ts: i64,
    pub dur: i64,
    pub utid: i64,
    pub state: String,
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
/// - `frame_names`: Function names from leaf to root (with embedded module/location info)
/// - `depth`: Number of frames in the stack
/// - `leaf_name`: Leaf function name (redundant but enables fast filtering)
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
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StackSampleRecord {
    pub ts: i64,
    pub utid: i64,
    pub cpu: Option<i32>,
    pub stack_id: i64,
}

// Network metadata records

/// Network interface record.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetworkInterfaceRecord {
    pub namespace: String,
    pub interface_name: String,
    pub ip_address: String,
    pub address_type: String,
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
/// - `tid`: Thread ID (from tgidpid)
/// - `pid`: Process ID (from tgidpid)
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
    pub tid: i32,
    pub pid: i32,
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
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetworkPacketRecord {
    pub id: i64,
    pub ts: i64,
    pub socket_id: i64,
    pub event_type: String,
    pub seq: Option<i64>,
    pub length: i32,
    pub tcp_flags: Option<String>,
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
    pub drop_reason_str: Option<String>,
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
}

/// Network socket record - represents socket metadata.
///
/// Replaces socket_connection with a cleaner schema (no track_id needed).
/// Socket info extracted directly from BPF events for true streaming.
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
    pub protocol: String,
    pub address_family: String,
    pub src_ip: String,
    pub src_port: i32,
    pub dest_ip: String,
    pub dest_port: i32,
    pub first_seen_ts: Option<i64>,
    pub last_seen_ts: Option<i64>,
}

/// Network poll record - represents socket poll events.
///
/// Dedicated table for poll events that were previously mixed with other events.
///
/// # Fields
/// - `id`: Unique event ID
/// - `ts`: Timestamp in nanoseconds
/// - `tid`: Thread ID
/// - `pid`: Process ID
/// - `socket_id`: Socket identifier
/// - `requested_events`: Events requested (e.g., "IN|OUT|PRI")
/// - `returned_events`: Events returned (e.g., "IN")
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetworkPollRecord {
    pub id: i64,
    pub ts: i64,
    pub tid: i32,
    pub pid: i32,
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

/// Container for all extracted trace data.
#[derive(Debug, Default)]
pub struct ExtractedData {
    pub processes: Vec<ProcessRecord>,
    pub threads: Vec<ThreadRecord>,
    pub sched_slices: Vec<SchedSliceRecord>,
    pub thread_states: Vec<ThreadStateRecord>,
    pub irq_slices: Vec<IrqSliceRecord>,
    pub softirq_slices: Vec<SoftirqSliceRecord>,
    pub wakeup_news: Vec<WakeupNewRecord>,
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
    pub clock_snapshots: Vec<ClockSnapshotRecord>,
}
