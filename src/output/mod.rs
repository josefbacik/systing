//! Output format abstraction layer
//!
//! This module provides a format-agnostic abstraction layer for writing trace data.
//! The `TraceOutput` trait allows recorders to write events without knowing the
//! specific output format (Perfetto protobuf, SQLite database, etc.).
//!
//! # Design
//!
//! The abstraction uses intermediate data structures (defined in `types`) that sit
//! between the BPF event structures and the final output format. This allows:
//!
//! - Format-agnostic recording: Recorders don't need to know about Perfetto/SQLite
//! - Easy format conversion: Same data can be written to different formats
//! - Testability: Mock implementations can be created for testing
//! - Future extensibility: New formats can be added without changing recorders

mod types;

pub use types::*;

use anyhow::Result;

/// Trait for abstracting trace output formats (Perfetto, SQLite, etc.)
///
/// This trait provides a format-agnostic interface for writing trace data.
/// Implementations can convert the intermediate data structures to their
/// specific format requirements.
pub trait TraceOutput {
    // Metadata operations

    /// Write trace metadata including start/end timestamps and tool version
    fn write_metadata(&mut self, start_ts: u64, end_ts: u64, version: &str) -> Result<()>;

    /// Write clock snapshot for timestamp synchronization
    fn write_clock_snapshot(&mut self, clocks: &[ClockInfo]) -> Result<()>;

    // Process and thread management

    /// Write process information
    fn write_process(&mut self, pid: i32, name: &str, cmdline: &[String]) -> Result<()>;

    /// Write thread information
    fn write_thread(&mut self, tid: i32, pid: i32, name: &str) -> Result<()>;

    /// Write process/thread exit event
    fn write_process_exit(&mut self, tid: i32, ts: u64) -> Result<()>;

    // Track management

    /// Write track information for organizing events
    fn write_track(&mut self, track: &TrackInfo) -> Result<()>;

    // Scheduler events

    /// Write scheduler event (switch, wakeup, etc.)
    fn write_sched_event(&mut self, event: &SchedEventData) -> Result<()>;

    /// Write IRQ/SoftIRQ event (entry or exit)
    fn write_irq_event(&mut self, event: &IrqEventData) -> Result<()>;

    // Stack traces and symbols

    /// Write symbol information and return its ID for deduplication
    fn write_symbol(&mut self, symbol: &SymbolInfo) -> Result<u64>;

    /// Write stack trace and return its ID for deduplication
    fn write_stack_trace(&mut self, stack: &StackTraceData) -> Result<u64>;

    /// Write performance sample with stack trace
    fn write_perf_sample(&mut self, sample: &PerfSampleData) -> Result<()>;

    // Performance counters

    /// Write performance counter definition
    fn write_perf_counter(&mut self, counter: &PerfCounterDef) -> Result<()>;

    /// Write performance counter value at a specific timestamp
    fn write_perf_counter_value(&mut self, counter_id: u64, ts: u64, value: i64) -> Result<()>;

    // Probe events

    /// Write event definition and return its ID
    fn write_event_definition(&mut self, def: &EventDefinition) -> Result<u64>;

    /// Write probe event occurrence
    fn write_probe_event(&mut self, event: &ProbeEventData) -> Result<()>;

    // Network events

    /// Write network connection and return its ID for deduplication
    fn write_network_connection(&mut self, conn: &NetworkConnection) -> Result<u64>;

    /// Write network event data
    fn write_network_event(&mut self, event: &NetworkEventData) -> Result<()>;

    // System information

    /// Write CPU frequency change event
    fn write_cpu_frequency(&mut self, cpu: u32, ts: u64, freq: i64, track_uuid: u64) -> Result<()>;

    // Finalization

    /// Flush any buffered data to the output
    fn flush(&mut self) -> Result<()>;
}
