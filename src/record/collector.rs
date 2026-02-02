//! RecordCollector trait for streaming trace data to storage.
//!
//! This trait defines the interface for collecting trace records during recording.
//! Implementations can buffer records and flush them to storage (e.g., Parquet files)
//! when thresholds are reached.

use anyhow::Result;

use crate::trace::{
    ArgRecord, ClockSnapshotRecord, CounterRecord, CounterTrackRecord, ExtractedData,
    InstantArgRecord, InstantRecord, IrqSliceRecord, NetworkInterfaceRecord, NetworkPacketRecord,
    NetworkPollRecord, NetworkSocketRecord, NetworkSyscallRecord, ProcessExitRecord, ProcessRecord,
    SchedSliceRecord, SliceRecord, SocketConnectionRecord, SoftirqSliceRecord, StackRecord,
    StackSampleRecord, SysInfoRecord, ThreadRecord, ThreadStateRecord, TrackRecord,
    WakeupNewRecord,
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

    /// Add an IRQ slice record.
    fn add_irq_slice(&mut self, record: IrqSliceRecord) -> Result<()>;

    /// Add a softirq slice record.
    fn add_softirq_slice(&mut self, record: SoftirqSliceRecord) -> Result<()>;

    /// Add a wakeup new record.
    fn add_wakeup_new(&mut self, record: WakeupNewRecord) -> Result<()>;

    /// Add a process exit record.
    fn add_process_exit(&mut self, record: ProcessExitRecord) -> Result<()>;

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

    /// Add a network syscall record.
    fn add_network_syscall(&mut self, record: NetworkSyscallRecord) -> Result<()>;

    /// Add a network packet record.
    fn add_network_packet(&mut self, record: NetworkPacketRecord) -> Result<()>;

    /// Add a network socket record.
    fn add_network_socket(&mut self, record: NetworkSocketRecord) -> Result<()>;

    /// Add a network poll record.
    fn add_network_poll(&mut self, record: NetworkPollRecord) -> Result<()>;

    /// Set the system info record (only one per trace).
    fn set_sysinfo(&mut self, record: SysInfoRecord) -> Result<()>;

    /// Flush any buffered records to storage.
    fn flush(&mut self) -> Result<()>;

    /// Finish writing and close all files.
    /// Takes self by value to properly close resources.
    fn finish(self) -> Result<()>;

    /// Finish writing and close all files (boxed version for trait objects).
    /// This is the same as finish() but takes a Box to work with trait objects.
    fn finish_boxed(self: Box<Self>) -> Result<()>;
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

    fn add_irq_slice(&mut self, record: IrqSliceRecord) -> Result<()> {
        self.data.irq_slices.push(record);
        Ok(())
    }

    fn add_softirq_slice(&mut self, record: SoftirqSliceRecord) -> Result<()> {
        self.data.softirq_slices.push(record);
        Ok(())
    }

    fn add_wakeup_new(&mut self, record: WakeupNewRecord) -> Result<()> {
        self.data.wakeup_news.push(record);
        Ok(())
    }

    fn add_process_exit(&mut self, record: ProcessExitRecord) -> Result<()> {
        self.data.process_exits.push(record);
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

    fn add_network_syscall(&mut self, record: NetworkSyscallRecord) -> Result<()> {
        self.data.network_syscalls.push(record);
        Ok(())
    }

    fn add_network_packet(&mut self, record: NetworkPacketRecord) -> Result<()> {
        self.data.network_packets.push(record);
        Ok(())
    }

    fn add_network_socket(&mut self, record: NetworkSocketRecord) -> Result<()> {
        self.data.network_sockets.push(record);
        Ok(())
    }

    fn add_network_poll(&mut self, record: NetworkPollRecord) -> Result<()> {
        self.data.network_polls.push(record);
        Ok(())
    }

    fn set_sysinfo(&mut self, record: SysInfoRecord) -> Result<()> {
        self.data.sysinfo = Some(record);
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

    fn finish_boxed(self: Box<Self>) -> Result<()> {
        (*self).finish()
    }
}
