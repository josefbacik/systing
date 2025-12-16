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
/// - `end_state`: Thread state when it stopped running (e.g., "S" for sleeping)
/// - `priority`: Thread priority (nice value)
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SchedSliceRecord {
    pub ts: i64,
    pub dur: i64,
    pub cpu: i32,
    pub utid: i64,
    pub end_state: Option<String>,
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

/// Performance sample record.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PerfSampleRecord {
    pub ts: i64,
    pub utid: i64,
    pub callsite_id: Option<i64>,
    pub cpu: Option<i32>,
}

// Stack profiling records

/// Symbol record - function name.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct SymbolRecord {
    pub id: i64,
    pub name: String,
}

/// Frame record - stack frame information.
/// module_name is stored directly on frame (from blazesym Sym.module).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FrameRecord {
    pub id: i64,
    pub name: Option<String>,
    pub module_name: Option<String>,
    pub symbol_id: Option<i64>,
}

/// Callsite record - represents a position in a call stack.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CallsiteRecord {
    pub id: i64,
    pub parent_id: Option<i64>,
    pub frame_id: i64,
    pub depth: i32,
}

/// Stack record - represents a complete call stack as arrays.
///
/// This is a query-friendly representation that stores the entire stack
/// in arrays, avoiding the need for recursive CTEs to reconstruct stacks.
///
/// # Fields
/// - `id`: Unique stack ID
/// - `frame_names`: Function names from leaf to root
/// - `frame_ids`: Frame IDs for Perfetto generation
/// - `depth`: Number of frames in the stack
/// - `leaf_name`: Leaf function name (redundant but enables fast filtering)
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StackRecord {
    pub id: i64,
    pub frame_names: Vec<String>,
    pub frame_ids: Vec<i64>,
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
    pub counters: Vec<CounterRecord>,
    pub counter_tracks: Vec<CounterTrackRecord>,
    pub slices: Vec<SliceRecord>,
    pub tracks: Vec<TrackRecord>,
    pub instants: Vec<InstantRecord>,
    pub args: Vec<ArgRecord>,
    pub instant_args: Vec<InstantArgRecord>,
    pub perf_samples: Vec<PerfSampleRecord>,
    pub symbols: Vec<SymbolRecord>,
    pub frames: Vec<FrameRecord>,
    pub callsites: Vec<CallsiteRecord>,
    pub stacks: Vec<StackRecord>,
    pub stack_samples: Vec<StackSampleRecord>,
    pub network_interfaces: Vec<NetworkInterfaceRecord>,
    pub socket_connections: Vec<SocketConnectionRecord>,
    pub clock_snapshots: Vec<ClockSnapshotRecord>,
}
