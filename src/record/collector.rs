//! RecordCollector trait for streaming trace data to storage.
//!
//! This trait defines the interface for collecting trace records during recording.
//! Implementations can buffer records and flush them to storage (e.g., Parquet files)
//! when thresholds are reached.

use std::sync::{Arc, Mutex, MutexGuard};

use anyhow::Result;

use crate::trace::{
    ArgRecord, ClockSnapshotRecord, CounterRecord, CounterTrackRecord, ExtractedData,
    InstantArgRecord, InstantRecord, IrqSliceRecord, MemoryAllocRecord, MemoryFaultRecord,
    MemoryMapRecord, MemoryRssRecord, NetworkDnsRecord, NetworkInterfaceRecord,
    NetworkPacketRecord, NetworkPollRecord, NetworkSocketRecord, NetworkSyscallRecord,
    ProcessExitRecord, ProcessRecord, SchedSliceRecord, SliceRecord, SocketConnectionRecord,
    SoftirqSliceRecord, StackRecord, StackSampleRecord, SysInfoRecord, ThreadRecord,
    ThreadStateRecord, TpuDeviceRecord, TpuMetricRecord, TpuOpRecord, TrackRecord, WakeupNewRecord,
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

    /// Add a network DNS record.
    fn add_network_dns(&mut self, record: NetworkDnsRecord) -> Result<()>;

    /// Add a memory RSS counter record.
    fn add_memory_rss(&mut self, record: MemoryRssRecord) -> Result<()>;

    /// Add a memory map (mmap/munmap/brk) record.
    fn add_memory_map(&mut self, record: MemoryMapRecord) -> Result<()>;

    /// Add a sampled page fault record.
    fn add_memory_fault(&mut self, record: MemoryFaultRecord) -> Result<()>;

    /// Add a heap allocator (malloc/free/...) record.
    fn add_memory_alloc(&mut self, record: MemoryAllocRecord) -> Result<()>;

    /// Set the system info record (only one per trace).
    fn set_sysinfo(&mut self, record: SysInfoRecord) -> Result<()>;

    // TPU profiling records

    /// Add a TPU device metadata record.
    fn add_tpu_device(&mut self, record: TpuDeviceRecord) -> Result<()>;

    /// Add a TPU operation execution record.
    fn add_tpu_op(&mut self, record: TpuOpRecord) -> Result<()>;

    /// Add a TPU runtime metric record.
    fn add_tpu_metric(&mut self, record: TpuMetricRecord) -> Result<()>;

    /// Flush any buffered records to storage.
    fn flush(&mut self) -> Result<()>;

    /// Finish writing and close all files.
    /// Takes self by value to properly close resources.
    fn finish(self) -> Result<()>;

    /// Finish writing and close all files (boxed version for trait objects).
    /// This is the same as finish() but takes a Box to work with trait objects.
    fn finish_boxed(self: Box<Self>) -> Result<()>;
}

/// A cloneable, thread-safe handle that lets several recorders stream into one
/// shared underlying collector.
///
/// Some recorders emit rows for the same logical tables: the perf-counter
/// recorder and the sysinfo (CPU frequency) recorder both emit `counter` /
/// `counter_track` rows. If each held its own `StreamingParquetWriter`, both
/// writers would target the same `counter.parquet` / `counter_track.parquet`
/// paths and the last one to finish would silently clobber the other's data.
/// Wrapping a single writer in a `SharedCollector` and handing a clone to each
/// recorder makes them append to the same writer instead.
///
/// `finish()` / `finish_boxed()` only finalize the inner collector when called
/// on the last live handle; earlier handles just flush. This keeps the existing
/// per-recorder "finish your collector when you're done" flow unchanged.
///
/// Usage requirements:
/// - Every handle must eventually be finished (or dropped) during trace
///   generation; a handle whose finish is skipped keeps the inner collector
///   open and the data only gets closed by the writer's `Drop` fallback.
/// - Handles must not be finished concurrently from different threads: the
///   "last live handle" check is not atomic across racing finishes, so two
///   concurrent finishes could both see another live handle and neither would
///   finalize the writer. `SessionRecorder::generate_parquet_trace` finishes
///   all recorders sequentially on one thread, which satisfies this.
pub struct SharedCollector {
    inner: Arc<Mutex<Box<dyn RecordCollector + Send>>>,
}

impl SharedCollector {
    /// Wrap a collector so it can be shared by multiple recorders.
    pub fn new(inner: Box<dyn RecordCollector + Send>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Box<dyn RecordCollector + Send>> {
        // A poisoned mutex means another recorder panicked mid-write; trace
        // generation is already broken at that point, so propagate the panic.
        self.inner.lock().unwrap()
    }

    /// Finish this handle. The inner collector is only finalized once the last
    /// handle finishes (i.e. this handle holds the only remaining reference);
    /// earlier handles just flush what they have written. Handles are expected
    /// to be finished sequentially - see the type-level docs.
    fn finish_shared(self) -> Result<()> {
        match Arc::try_unwrap(self.inner) {
            Ok(mutex) => mutex.into_inner().unwrap().finish_boxed(),
            Err(arc) => arc.lock().unwrap().flush(),
        }
    }
}

impl Clone for SharedCollector {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

/// Generates the record-forwarding methods of [`RecordCollector`] for
/// [`SharedCollector`]: each method locks the shared inner collector and
/// delegates to it.
macro_rules! shared_delegate {
    ($($method:ident($record:ty)),* $(,)?) => {
        $(
            fn $method(&mut self, record: $record) -> Result<()> {
                self.lock().$method(record)
            }
        )*
    };
}

impl RecordCollector for SharedCollector {
    shared_delegate! {
        add_process(ProcessRecord),
        add_thread(ThreadRecord),
        add_sched_slice(SchedSliceRecord),
        add_thread_state(ThreadStateRecord),
        add_irq_slice(IrqSliceRecord),
        add_softirq_slice(SoftirqSliceRecord),
        add_wakeup_new(WakeupNewRecord),
        add_process_exit(ProcessExitRecord),
        add_counter(CounterRecord),
        add_counter_track(CounterTrackRecord),
        add_slice(SliceRecord),
        add_track(TrackRecord),
        add_instant(InstantRecord),
        add_arg(ArgRecord),
        add_instant_arg(InstantArgRecord),
        add_network_interface(NetworkInterfaceRecord),
        add_socket_connection(SocketConnectionRecord),
        add_clock_snapshot(ClockSnapshotRecord),
        add_stack(StackRecord),
        add_stack_sample(StackSampleRecord),
        add_network_syscall(NetworkSyscallRecord),
        add_network_packet(NetworkPacketRecord),
        add_network_socket(NetworkSocketRecord),
        add_network_poll(NetworkPollRecord),
        add_network_dns(NetworkDnsRecord),
        add_memory_rss(MemoryRssRecord),
        add_memory_map(MemoryMapRecord),
        add_memory_fault(MemoryFaultRecord),
        add_memory_alloc(MemoryAllocRecord),
        set_sysinfo(SysInfoRecord),
        add_tpu_device(TpuDeviceRecord),
        add_tpu_op(TpuOpRecord),
        add_tpu_metric(TpuMetricRecord),
    }

    fn flush(&mut self) -> Result<()> {
        self.lock().flush()
    }

    fn finish(self) -> Result<()> {
        self.finish_shared()
    }

    fn finish_boxed(self: Box<Self>) -> Result<()> {
        (*self).finish_shared()
    }
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

    fn add_network_dns(&mut self, record: NetworkDnsRecord) -> Result<()> {
        self.data.network_dns.push(record);
        Ok(())
    }

    fn add_memory_rss(&mut self, record: MemoryRssRecord) -> Result<()> {
        self.data.memory_rss.push(record);
        Ok(())
    }

    fn add_memory_map(&mut self, record: MemoryMapRecord) -> Result<()> {
        self.data.memory_maps.push(record);
        Ok(())
    }

    fn add_memory_fault(&mut self, record: MemoryFaultRecord) -> Result<()> {
        self.data.memory_faults.push(record);
        Ok(())
    }

    fn add_memory_alloc(&mut self, record: MemoryAllocRecord) -> Result<()> {
        self.data.memory_allocs.push(record);
        Ok(())
    }

    fn set_sysinfo(&mut self, record: SysInfoRecord) -> Result<()> {
        self.data.sysinfo = Some(record);
        Ok(())
    }

    fn add_tpu_device(&mut self, record: TpuDeviceRecord) -> Result<()> {
        self.data.tpu_devices.push(record);
        Ok(())
    }

    fn add_tpu_op(&mut self, record: TpuOpRecord) -> Result<()> {
        self.data.tpu_ops.push(record);
        Ok(())
    }

    fn add_tpu_metric(&mut self, record: TpuMetricRecord) -> Result<()> {
        self.data.tpu_metrics.push(record);
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
