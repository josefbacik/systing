//! RecordCollector trait for streaming trace data to storage.
//!
//! This trait defines the interface for collecting trace records during recording.
//! Implementations can buffer records and flush them to storage (e.g., Parquet files)
//! when thresholds are reached.

use std::sync::{Arc, Mutex, MutexGuard};

use anyhow::Result;

use crate::trace::{
    ArgRecord, ClockSnapshotRecord, CounterRecord, CounterTrackRecord, CpuInfoRecord,
    ExtractedData, InstantArgRecord, InstantRecord, IrqSliceRecord, MemoryAllocRecord,
    MemoryFaultRecord, MemoryIommuRecord, MemoryMapRecord, MemoryRssRecord, MemoryThpRecord,
    MemoryVfioRecord, MemoryVmstatRecord, NetworkDnsRecord, NetworkInterfaceRecord,
    NetworkPacketRecord, NetworkPollRecord, NetworkSocketRecord, NetworkSyscallRecord,
    ProcessExitRecord, ProcessRecord, SchedMigrateRecord, SchedSliceRecord, SliceRecord,
    SocketConnectionRecord, SoftirqSliceRecord, StackRecord, StackSampleRecord, SysInfoRecord,
    ThreadRecord, ThreadStateRecord, TpuDeviceRecord, TpuMetricRecord, TpuOpRecord, TrackRecord,
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

    /// Add a sched migrate record.
    fn add_sched_migrate(&mut self, record: SchedMigrateRecord) -> Result<()>;

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

    /// Add a VFIO DMA region map/unmap record.
    fn add_memory_vfio(&mut self, record: MemoryVfioRecord) -> Result<()>;

    /// Add an IOMMU map/unmap run-size histogram row.
    fn add_memory_iommu(&mut self, record: MemoryIommuRecord) -> Result<()>;

    /// Add a sampled THP split record.
    fn add_memory_thp(&mut self, record: MemoryThpRecord) -> Result<()>;

    /// Add a start/end vmstat counter sample.
    fn add_memory_vmstat(&mut self, record: MemoryVmstatRecord) -> Result<()>;

    /// Set the system info record (only one per trace).
    fn set_sysinfo(&mut self, record: SysInfoRecord) -> Result<()>;

    /// Add a per-CPU frequency-limit record (one per CPU with cpufreq data).
    fn add_cpu_info(&mut self, record: CpuInfoRecord) -> Result<()>;

    // TPU profiling records

    /// Add a TPU device metadata record.
    fn add_tpu_device(&mut self, record: TpuDeviceRecord) -> Result<()>;

    /// Add a TPU operation execution record.
    fn add_tpu_op(&mut self, record: TpuOpRecord) -> Result<()>;

    /// Add a TPU runtime metric record.
    fn add_tpu_metric(&mut self, record: TpuMetricRecord) -> Result<()>;

    /// Add a batch of scheduler-lane records, draining every buffer in the
    /// batch. Returns the number of records that could not be added; each
    /// failure is warned about and dropped rather than aborting the batch, so
    /// one bad record cannot silently discard the rest of a buffer.
    ///
    /// The default forwards record by record through the `add_*` methods.
    /// A collector that guards shared state should override it so the whole
    /// batch goes through one guard acquisition: the sched recorder's ring
    /// shards flush tens of thousands of records at a time into one
    /// [`SharedCollector`], and taking its mutex per record turns every flush
    /// into a futex storm between the shards.
    fn add_sched_batch(&mut self, batch: SchedRecordBatch<'_>) -> usize {
        let mut failed = 0usize;
        let mut warn = |what: &str, e: anyhow::Error| {
            eprintln!("Warning: Failed to stream {what}: {e}");
            failed += 1;
        };
        for record in batch.slices.drain(..) {
            if let Err(e) = self.add_sched_slice(record) {
                warn("sched slice", e);
            }
        }
        for record in batch.thread_states.drain(..) {
            if let Err(e) = self.add_thread_state(record) {
                warn("thread state", e);
            }
        }
        for record in batch.irq_slices.drain(..) {
            if let Err(e) = self.add_irq_slice(record) {
                warn("IRQ slice", e);
            }
        }
        for record in batch.softirq_slices.drain(..) {
            if let Err(e) = self.add_softirq_slice(record) {
                warn("softirq slice", e);
            }
        }
        for record in batch.wakeup_news.drain(..) {
            if let Err(e) = self.add_wakeup_new(record) {
                warn("wakeup_new", e);
            }
        }
        for record in batch.sched_migrates.drain(..) {
            if let Err(e) = self.add_sched_migrate(record) {
                warn("sched_migrate", e);
            }
        }
        for record in batch.process_exits.drain(..) {
            if let Err(e) = self.add_process_exit(record) {
                warn("process_exit", e);
            }
        }
        failed
    }

    /// Flush any buffered records to storage.
    fn flush(&mut self) -> Result<()>;

    /// Finish writing and close all files.
    /// Takes self by value to properly close resources.
    fn finish(self) -> Result<()>;

    /// Finish writing and close all files (boxed version for trait objects).
    /// This is the same as finish() but takes a Box to work with trait objects.
    fn finish_boxed(self: Box<Self>) -> Result<()>;
}

/// The scheduler lane's locally buffered records, handed to a collector in
/// one [`RecordCollector::add_sched_batch`] call. The buffers are borrowed
/// and drained in place so the recorder keeps their capacity across flushes.
pub struct SchedRecordBatch<'a> {
    pub slices: &'a mut Vec<SchedSliceRecord>,
    pub thread_states: &'a mut Vec<ThreadStateRecord>,
    pub irq_slices: &'a mut Vec<IrqSliceRecord>,
    pub softirq_slices: &'a mut Vec<SoftirqSliceRecord>,
    pub wakeup_news: &'a mut Vec<WakeupNewRecord>,
    pub sched_migrates: &'a mut Vec<SchedMigrateRecord>,
    pub process_exits: &'a mut Vec<ProcessExitRecord>,
}

impl SchedRecordBatch<'_> {
    /// Total number of records across all buffers.
    pub fn len(&self) -> usize {
        self.slices.len()
            + self.thread_states.len()
            + self.irq_slices.len()
            + self.softirq_slices.len()
            + self.wakeup_news.len()
            + self.sched_migrates.len()
            + self.process_exits.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
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
        add_sched_migrate(SchedMigrateRecord),
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
        add_memory_vfio(MemoryVfioRecord),
        add_memory_iommu(MemoryIommuRecord),
        add_memory_thp(MemoryThpRecord),
        add_memory_vmstat(MemoryVmstatRecord),
        set_sysinfo(SysInfoRecord),
        add_cpu_info(CpuInfoRecord),
        add_tpu_device(TpuDeviceRecord),
        add_tpu_op(TpuOpRecord),
        add_tpu_metric(TpuMetricRecord),
    }

    fn add_sched_batch(&mut self, batch: SchedRecordBatch<'_>) -> usize {
        // One acquisition for the whole batch: the inner collector's default
        // loop runs under it, so the shards contend once per flush instead of
        // once per record.
        self.lock().add_sched_batch(batch)
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

    fn add_sched_migrate(&mut self, record: SchedMigrateRecord) -> Result<()> {
        self.data.sched_migrates.push(record);
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

    fn add_memory_vfio(&mut self, record: MemoryVfioRecord) -> Result<()> {
        self.data.memory_vfio.push(record);
        Ok(())
    }

    fn add_memory_iommu(&mut self, record: MemoryIommuRecord) -> Result<()> {
        self.data.memory_iommu.push(record);
        Ok(())
    }

    fn add_memory_thp(&mut self, record: MemoryThpRecord) -> Result<()> {
        self.data.memory_thp.push(record);
        Ok(())
    }

    fn add_memory_vmstat(&mut self, record: MemoryVmstatRecord) -> Result<()> {
        self.data.memory_vmstat.push(record);
        Ok(())
    }

    fn set_sysinfo(&mut self, record: SysInfoRecord) -> Result<()> {
        self.data.sysinfo = Some(record);
        Ok(())
    }

    fn add_cpu_info(&mut self, record: CpuInfoRecord) -> Result<()> {
        self.data.cpu_infos.push(record);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Forwards every per-record method to an inner [`InMemoryCollector`],
    /// so a test double only has to spell out the methods it observes.
    macro_rules! forward_to_inner {
        ($($method:ident($record:ty)),* $(,)?) => {
            $(
                fn $method(&mut self, record: $record) -> Result<()> {
                    self.inner.$method(record)
                }
            )*
        };
    }

    macro_rules! forward_all_but_sched {
        () => {
            forward_to_inner! {
                add_process(ProcessRecord),
                add_thread(ThreadRecord),
                add_irq_slice(IrqSliceRecord),
                add_softirq_slice(SoftirqSliceRecord),
                add_wakeup_new(WakeupNewRecord),
                add_sched_migrate(SchedMigrateRecord),
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
                add_memory_vfio(MemoryVfioRecord),
                add_memory_iommu(MemoryIommuRecord),
                add_memory_thp(MemoryThpRecord),
                add_memory_vmstat(MemoryVmstatRecord),
                set_sysinfo(SysInfoRecord),
                add_cpu_info(CpuInfoRecord),
                add_tpu_device(TpuDeviceRecord),
                add_tpu_op(TpuOpRecord),
                add_tpu_metric(TpuMetricRecord),
            }

            fn flush(&mut self) -> Result<()> {
                self.inner.flush()
            }

            fn finish(self) -> Result<()> {
                self.inner.finish()
            }

            fn finish_boxed(self: Box<Self>) -> Result<()> {
                (*self).finish()
            }
        };
    }

    /// Counts how many times it is handed a sched batch (and how many records
    /// it carried), then drains the batch without going through the
    /// per-record methods. Its counters outlive it through the `Arc`s so the
    /// test can read them after the collector has been boxed into a
    /// [`SharedCollector`].
    struct BatchProbe {
        inner: InMemoryCollector,
        batches: Arc<AtomicUsize>,
        records: Arc<AtomicUsize>,
        per_record_adds: Arc<AtomicUsize>,
    }

    impl RecordCollector for BatchProbe {
        forward_all_but_sched!();

        fn add_sched_slice(&mut self, record: SchedSliceRecord) -> Result<()> {
            self.per_record_adds.fetch_add(1, Ordering::SeqCst);
            self.inner.add_sched_slice(record)
        }

        fn add_thread_state(&mut self, record: ThreadStateRecord) -> Result<()> {
            self.per_record_adds.fetch_add(1, Ordering::SeqCst);
            self.inner.add_thread_state(record)
        }

        fn add_sched_batch(&mut self, batch: SchedRecordBatch<'_>) -> usize {
            self.batches.fetch_add(1, Ordering::SeqCst);
            self.records.fetch_add(batch.len(), Ordering::SeqCst);
            batch.slices.clear();
            batch.thread_states.clear();
            batch.irq_slices.clear();
            batch.softirq_slices.clear();
            batch.wakeup_news.clear();
            batch.sched_migrates.clear();
            batch.process_exits.clear();
            0
        }
    }

    /// Uses the trait's default `add_sched_batch`, and refuses thread-state
    /// records whose `state` is `REJECTED_STATE`.
    struct FlakyCollector {
        inner: InMemoryCollector,
    }

    const REJECTED_STATE: i32 = 7;

    impl RecordCollector for FlakyCollector {
        forward_all_but_sched!();

        fn add_sched_slice(&mut self, record: SchedSliceRecord) -> Result<()> {
            self.inner.add_sched_slice(record)
        }

        fn add_thread_state(&mut self, record: ThreadStateRecord) -> Result<()> {
            if record.state == REJECTED_STATE {
                anyhow::bail!("rejected thread state at ts {}", record.ts);
            }
            self.inner.add_thread_state(record)
        }
    }

    fn slices(n: usize) -> Vec<SchedSliceRecord> {
        (0..n)
            .map(|i| SchedSliceRecord {
                ts: i as i64 * 1000,
                dur: 500,
                cpu: (i % 4) as i32,
                utid: 10 + i as i64,
                end_state: None,
                priority: 120,
            })
            .collect()
    }

    fn thread_states(states: &[i32]) -> Vec<ThreadStateRecord> {
        states
            .iter()
            .enumerate()
            .map(|(i, &state)| ThreadStateRecord {
                ts: i as i64 * 1000 + 1,
                dur: 0,
                utid: 10 + i as i64,
                state,
                cpu: Some((i % 4) as i32),
            })
            .collect()
    }

    fn process_exits(n: usize) -> Vec<ProcessExitRecord> {
        (0..n)
            .map(|i| ProcessExitRecord {
                ts: i as i64 * 1000 + 2,
                cpu: 0,
                utid: 10 + i as i64,
            })
            .collect()
    }

    #[test]
    fn shared_collector_hands_a_sched_batch_to_the_inner_in_one_call() {
        let batches = Arc::new(AtomicUsize::new(0));
        let records = Arc::new(AtomicUsize::new(0));
        let per_record_adds = Arc::new(AtomicUsize::new(0));
        let probe = BatchProbe {
            inner: InMemoryCollector::new(),
            batches: Arc::clone(&batches),
            records: Arc::clone(&records),
            per_record_adds: Arc::clone(&per_record_adds),
        };
        let mut shared: Box<dyn RecordCollector + Send> =
            Box::new(SharedCollector::new(Box::new(probe)));

        let mut slices = slices(1000);
        let mut thread_states = thread_states(&[0; 500]);
        let mut irq_slices = Vec::new();
        let mut softirq_slices = Vec::new();
        let mut wakeup_news = Vec::new();
        let mut sched_migrates = Vec::new();
        let mut process_exits = process_exits(7);
        let failed = shared.add_sched_batch(SchedRecordBatch {
            slices: &mut slices,
            thread_states: &mut thread_states,
            irq_slices: &mut irq_slices,
            softirq_slices: &mut softirq_slices,
            wakeup_news: &mut wakeup_news,
            sched_migrates: &mut sched_migrates,
            process_exits: &mut process_exits,
        });

        assert_eq!(failed, 0);
        // One batch call carried every record; the shared handle did not fall
        // back to locking per record.
        assert_eq!(batches.load(Ordering::SeqCst), 1);
        assert_eq!(records.load(Ordering::SeqCst), 1507);
        assert_eq!(per_record_adds.load(Ordering::SeqCst), 0);
        assert!(slices.is_empty() && thread_states.is_empty() && process_exits.is_empty());
    }

    #[test]
    fn default_sched_batch_drains_every_buffer_and_counts_failures() {
        let mut flaky = FlakyCollector {
            inner: InMemoryCollector::new(),
        };
        let mut slices = slices(5);
        let mut thread_states = thread_states(&[0, REJECTED_STATE, 2, REJECTED_STATE]);
        let mut irq_slices = Vec::new();
        let mut softirq_slices = Vec::new();
        let mut wakeup_news = Vec::new();
        let mut sched_migrates = Vec::new();
        let mut process_exits = process_exits(3);
        let slice_capacity = slices.capacity();

        let failed = flaky.add_sched_batch(SchedRecordBatch {
            slices: &mut slices,
            thread_states: &mut thread_states,
            irq_slices: &mut irq_slices,
            softirq_slices: &mut softirq_slices,
            wakeup_news: &mut wakeup_news,
            sched_migrates: &mut sched_migrates,
            process_exits: &mut process_exits,
        });

        // The two rejected records are counted and dropped; everything else
        // arrives in order, and the buffers are drained but keep their
        // capacity for the next flush.
        assert_eq!(failed, 2);
        let data = flaky.inner.data();
        assert_eq!(data.sched_slices.len(), 5);
        assert!(data.sched_slices.windows(2).all(|w| w[0].ts < w[1].ts));
        assert_eq!(
            data.thread_states
                .iter()
                .map(|t| t.state)
                .collect::<Vec<_>>(),
            vec![0, 2]
        );
        assert_eq!(data.process_exits.len(), 3);
        assert!(slices.is_empty() && thread_states.is_empty() && process_exits.is_empty());
        assert_eq!(slices.capacity(), slice_capacity);
    }
}
