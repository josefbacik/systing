//! RecordCollector trait for streaming trace data to storage.
//!
//! This trait defines the interface for collecting trace records during recording.
//! Implementations can buffer records and flush them to storage (e.g., Parquet files)
//! when thresholds are reached.

use anyhow::Result;

use crate::trace::{
    ArgRecord, CallsiteRecord, ClockSnapshotRecord, CounterRecord, CounterTrackRecord,
    ExtractedData, FrameRecord, InstantArgRecord, InstantRecord, MappingRecord,
    NetworkInterfaceRecord, PerfSampleRecord, ProcessRecord, SchedSliceRecord, SliceRecord,
    SocketConnectionRecord, StackRecord, StackSampleRecord, SymbolRecord, ThreadRecord,
    ThreadStateRecord, TrackRecord,
};

/// Trait for collecting trace records during recording.
///
/// Implementations should buffer records and flush to storage when appropriate.
/// The default batch size is defined in [`crate::trace::PARQUET_BATCH_SIZE`].
///
/// # Example
///
/// ```ignore
/// let mut collector = StreamingParquetWriter::new(output_dir)?;
/// collector.add_process(ProcessRecord { upid: 1, pid: 1234, ... })?;
/// collector.add_thread(ThreadRecord { utid: 1, tid: 1234, ... })?;
/// // ... add more records ...
/// collector.finish()?;
/// ```
#[allow(dead_code)] // Some methods may not be used in all configurations
pub trait RecordCollector {
    /// Add a process record.
    fn add_process(&mut self, record: ProcessRecord) -> Result<()>;

    /// Add a thread record.
    fn add_thread(&mut self, record: ThreadRecord) -> Result<()>;

    /// Add a scheduler slice record.
    fn add_sched_slice(&mut self, record: SchedSliceRecord) -> Result<()>;

    /// Add a thread state record.
    fn add_thread_state(&mut self, record: ThreadStateRecord) -> Result<()>;

    /// Add a counter record.
    fn add_counter(&mut self, record: CounterRecord) -> Result<()>;

    /// Add a counter track record.
    fn add_counter_track(&mut self, record: CounterTrackRecord) -> Result<()>;

    /// Add a slice record.
    fn add_slice(&mut self, record: SliceRecord) -> Result<()>;

    /// Add a track record.
    fn add_track(&mut self, record: TrackRecord) -> Result<()>;

    /// Add an instant record.
    fn add_instant(&mut self, record: InstantRecord) -> Result<()>;

    /// Add an argument record for a slice.
    fn add_arg(&mut self, record: ArgRecord) -> Result<()>;

    /// Add an argument record for an instant.
    fn add_instant_arg(&mut self, record: InstantArgRecord) -> Result<()>;

    /// Add a performance sample record.
    fn add_perf_sample(&mut self, record: PerfSampleRecord) -> Result<()>;

    /// Add a symbol record.
    fn add_symbol(&mut self, record: SymbolRecord) -> Result<()>;

    /// Add a mapping record.
    fn add_mapping(&mut self, record: MappingRecord) -> Result<()>;

    /// Add a frame record.
    fn add_frame(&mut self, record: FrameRecord) -> Result<()>;

    /// Add a callsite record.
    fn add_callsite(&mut self, record: CallsiteRecord) -> Result<()>;

    /// Add a network interface record.
    fn add_network_interface(&mut self, record: NetworkInterfaceRecord) -> Result<()>;

    /// Add a socket connection record.
    fn add_socket_connection(&mut self, record: SocketConnectionRecord) -> Result<()>;

    /// Add a clock snapshot record.
    fn add_clock_snapshot(&mut self, record: ClockSnapshotRecord) -> Result<()>;

    /// Add a stack record (query-friendly complete stack).
    fn add_stack(&mut self, record: StackRecord) -> Result<()>;

    /// Add a stack sample record (links sample to stack).
    fn add_stack_sample(&mut self, record: StackSampleRecord) -> Result<()>;

    /// Flush any buffered records to storage.
    fn flush(&mut self) -> Result<()>;

    /// Finish writing and close all files.
    fn finish(self) -> Result<()>;
}

/// A simple in-memory collector that stores all records in `ExtractedData`.
///
/// This is useful for testing and for cases where you want to collect
/// all records before writing them at once.
#[derive(Default)]
#[allow(dead_code)] // Used for testing and debugging
pub struct InMemoryCollector {
    data: ExtractedData,
}

#[allow(dead_code)] // Used for testing and debugging
impl InMemoryCollector {
    /// Create a new in-memory collector.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the collected data.
    pub fn into_data(self) -> ExtractedData {
        self.data
    }

    /// Get a reference to the collected data.
    pub fn data(&self) -> &ExtractedData {
        &self.data
    }
}

impl RecordCollector for InMemoryCollector {
    fn add_process(&mut self, record: ProcessRecord) -> Result<()> {
        self.data.processes.push(record);
        Ok(())
    }

    fn add_thread(&mut self, record: ThreadRecord) -> Result<()> {
        self.data.threads.push(record);
        Ok(())
    }

    fn add_sched_slice(&mut self, record: SchedSliceRecord) -> Result<()> {
        self.data.sched_slices.push(record);
        Ok(())
    }

    fn add_thread_state(&mut self, record: ThreadStateRecord) -> Result<()> {
        self.data.thread_states.push(record);
        Ok(())
    }

    fn add_counter(&mut self, record: CounterRecord) -> Result<()> {
        self.data.counters.push(record);
        Ok(())
    }

    fn add_counter_track(&mut self, record: CounterTrackRecord) -> Result<()> {
        self.data.counter_tracks.push(record);
        Ok(())
    }

    fn add_slice(&mut self, record: SliceRecord) -> Result<()> {
        self.data.slices.push(record);
        Ok(())
    }

    fn add_track(&mut self, record: TrackRecord) -> Result<()> {
        self.data.tracks.push(record);
        Ok(())
    }

    fn add_instant(&mut self, record: InstantRecord) -> Result<()> {
        self.data.instants.push(record);
        Ok(())
    }

    fn add_arg(&mut self, record: ArgRecord) -> Result<()> {
        self.data.args.push(record);
        Ok(())
    }

    fn add_instant_arg(&mut self, record: InstantArgRecord) -> Result<()> {
        self.data.instant_args.push(record);
        Ok(())
    }

    fn add_perf_sample(&mut self, record: PerfSampleRecord) -> Result<()> {
        self.data.perf_samples.push(record);
        Ok(())
    }

    fn add_symbol(&mut self, record: SymbolRecord) -> Result<()> {
        self.data.symbols.push(record);
        Ok(())
    }

    fn add_mapping(&mut self, record: MappingRecord) -> Result<()> {
        self.data.mappings.push(record);
        Ok(())
    }

    fn add_frame(&mut self, record: FrameRecord) -> Result<()> {
        self.data.frames.push(record);
        Ok(())
    }

    fn add_callsite(&mut self, record: CallsiteRecord) -> Result<()> {
        self.data.callsites.push(record);
        Ok(())
    }

    fn add_network_interface(&mut self, record: NetworkInterfaceRecord) -> Result<()> {
        self.data.network_interfaces.push(record);
        Ok(())
    }

    fn add_socket_connection(&mut self, record: SocketConnectionRecord) -> Result<()> {
        self.data.socket_connections.push(record);
        Ok(())
    }

    fn add_clock_snapshot(&mut self, record: ClockSnapshotRecord) -> Result<()> {
        self.data.clock_snapshots.push(record);
        Ok(())
    }

    fn add_stack(&mut self, record: StackRecord) -> Result<()> {
        self.data.stacks.push(record);
        Ok(())
    }

    fn add_stack_sample(&mut self, record: StackSampleRecord) -> Result<()> {
        self.data.stack_samples.push(record);
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        // In-memory collector doesn't need to flush
        Ok(())
    }

    fn finish(self) -> Result<()> {
        // Nothing to do for in-memory collector
        Ok(())
    }
}
