//! Intermediate data structures for trace output
//!
//! These types provide a format-agnostic representation of trace data.
//! They are designed to be easily convertible to both Perfetto protobuf
//! and SQLite database formats.

use std::collections::HashMap;

/// Clock information for synchronizing timestamps across different clock sources
#[derive(Debug, Clone)]
pub struct ClockInfo {
    #[allow(dead_code)]
    pub clock_id: u32,
    pub clock_name: String,
    pub timestamp: u64,
}

/// Track information for organizing events in the trace viewer
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TrackInfo {
    pub uuid: u64,
    pub name: String,
    pub parent_uuid: Option<u64>,
    pub track_type: TrackType,
    pub pid: Option<i32>,
    pub tid: Option<i32>,
}

/// Types of tracks for different event categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(dead_code)]
pub enum TrackType {
    Process,
    Thread,
    Cpu,
}

/// Scheduler event data with various event types
#[derive(Debug, Clone)]
pub struct SchedEventData {
    pub ts: u64,
    pub cpu: u32,
    pub event_type: SchedEventType,
    pub prev_pid: Option<i32>,
    pub prev_state: Option<String>,
    pub prev_prio: Option<i32>,
    pub next_pid: Option<i32>,
    pub next_prio: Option<i32>,
    #[allow(dead_code)]
    pub target_cpu: Option<u32>,
    #[allow(dead_code)]
    pub latency: Option<u64>,
}

/// Types of scheduler events
///
/// Uses `#[repr(i32)]` for efficient SQLite storage (INTEGER vs TEXT).
/// The discriminant values (0-4) are explicitly assigned for database stability.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SchedEventType {
    Switch = 0,
    Waking = 1,
    Wakeup = 2,
    WakeupNew = 3,
    Exit = 4,
}

impl SchedEventType {
    /// Convert to string (for debugging and compatibility)
    pub fn as_str(self) -> &'static str {
        match self {
            SchedEventType::Switch => "switch",
            SchedEventType::Waking => "waking",
            SchedEventType::Wakeup => "wakeup",
            SchedEventType::WakeupNew => "wakeup_new",
            SchedEventType::Exit => "exit",
        }
    }
}

impl TryFrom<i32> for SchedEventType {
    type Error = String;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SchedEventType::Switch),
            1 => Ok(SchedEventType::Waking),
            2 => Ok(SchedEventType::Wakeup),
            3 => Ok(SchedEventType::WakeupNew),
            4 => Ok(SchedEventType::Exit),
            _ => Err(format!("Invalid SchedEventType value: {value}")),
        }
    }
}

/// Symbol information for stack traces
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SymbolInfo {
    pub function_name: String,
    pub file_name: Option<String>,
    pub line_number: Option<u32>,
    pub build_id: Option<String>,
    pub mapping_name: Option<String>,
    pub mapping_offset: Option<u64>,
}

/// Stack trace data with separate kernel, user, and Python symbols
#[derive(Debug, Clone)]
pub struct StackTraceData {
    pub kernel_symbols: Vec<SymbolInfo>,
    pub user_symbols: Vec<SymbolInfo>,
    pub py_symbols: Vec<SymbolInfo>,
}

/// Performance sampling event data
#[derive(Debug, Clone)]
pub struct PerfSampleData {
    pub ts: u64,
    pub tid: i32,
    pub stack: StackTraceData,
}

/// Performance counter definition
#[derive(Debug, Clone)]
pub struct PerfCounterDef {
    pub track_uuid: u64,
    pub counter_name: String,
    pub cpu: Option<u32>,
    pub unit: String,
    pub is_incremental: bool,
}

/// Generic counter track information (for runqueue size, latency, etc.)
#[derive(Debug, Clone)]
pub struct CounterTrackInfo {
    pub name: String,
    pub unit: CounterUnit,
    pub is_incremental: bool,
    pub cpu: Option<u32>,
    pub pid: Option<i32>,
    pub tid: Option<i32>,
}

/// Units for counter tracks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CounterUnit {
    Count,
    TimeNs,
    #[allow(dead_code)]
    Bytes,
    #[allow(dead_code)]
    Custom(u32),
}

/// Event definition for probe events
#[derive(Debug, Clone)]
pub struct EventDefinition {
    pub event_name: String,
    pub event_type: String,
    pub track_name: Option<String>,
    pub category: Option<String>,
    pub cookie: u64,
}

/// Probe event data with arguments
#[derive(Debug, Clone)]
pub struct ProbeEventData {
    pub ts: u64,
    pub tid: i32,
    pub event_def_id: u64,
    pub args: HashMap<String, ArgValue>,
}

/// Argument value types for probe events
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ArgValue {
    String(String),
    Long(i64),
}

/// Network connection identification
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NetworkConnection {
    pub protocol: String,
    pub address_family: String,
    pub dest_addr: String,
    pub dest_port: u16,
}

/// Network event data
#[derive(Debug, Clone)]
pub struct NetworkEventData {
    pub connection_id: u64,
    pub tid: i32,
    pub track_uuid: u64,
    pub event_type: String,
    pub start_ts: u64,
    pub end_ts: Option<u64>,
    pub bytes: Option<u32>,
    pub sequence_num: Option<u32>,
    pub tcp_flags: Option<u8>,
}

/// Type of interrupt
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IrqType {
    Hardware,
    Software,
}

/// IRQ/SoftIRQ event data
#[derive(Debug, Clone)]
pub struct IrqEventData {
    /// Timestamp of the event
    pub ts: u64,
    /// CPU where the interrupt occurred
    pub cpu: u32,
    /// Type of interrupt (hardware or software)
    pub irq_type: IrqType,
    /// True for entry into IRQ handler, false for exit
    pub is_entry: bool,
    /// IRQ number - None for software IRQs that don't have a number
    pub irq_number: Option<u32>,
    /// IRQ name/description - None if not available
    pub name: Option<String>,
}
