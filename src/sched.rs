use std::collections::HashMap;
use std::ffi::CStr;
use std::sync::Arc;

use anyhow::Result;

use crate::record::RecordCollector;
use crate::ringbuf::RingBuffer;
use crate::systing_core::types::event_type;
use crate::systing_core::types::task_event;
use crate::systing_core::SystingRecordEvent;
use crate::trace::{
    IrqSliceRecord, ProcessExitRecord, SchedSliceRecord, SoftirqSliceRecord, ThreadStateRecord,
    WakeupNewRecord,
};
use crate::utid::{ThreadAwareRecorder, UtidGenerator};

/// Threshold for flushing locally buffered streaming records to the collector.
/// Lower than Parquet batch size (200K) to reduce peak memory while maintaining I/O efficiency.
/// Also bounds how often a recorder touches the collector: with per-ring
/// consumers all sharing one underlying parquet writer (see
/// `SharedCollector`), per-record adds would serialize the consumers on the
/// writer lock, so every record type is buffered locally and handed over in
/// batches.
const STREAMING_SCHED_FLUSH_THRESHOLD: usize = 10_000;

/// Convert a kernel prev_state value to an Option<i32> for storage.
///
/// Returns `None` for TASK_RUNNING (0), meaning the task was preempted while still runnable.
/// Returns `Some(state)` for sleep states (1=TASK_INTERRUPTIBLE, 2=TASK_UNINTERRUPTIBLE, etc.).
///
/// Note: Kernel task states are masked with TASK_REPORT in BPF, so values fit in i32.
/// Compound states (e.g., TASK_UNINTERRUPTIBLE | TASK_NOLOAD = 130) are also possible.
#[inline]
fn prev_state_to_end_state(state: i64) -> Option<i32> {
    (state != 0).then_some(state as i32)
}

/// Per-CPU state tracking for streaming scheduler events.
/// Stores information about the currently running task on each CPU.
struct CpuRunningState {
    start_ts: i64,
    tid: i32,
    prio: i32,
}

/// Pending IRQ entry waiting for matching exit.
#[derive(Clone)]
struct PendingIrq {
    ts: u64,
    irq: i32,
    name: String,
}

impl PendingIrq {
    /// Returns the name as Option, converting empty string to None.
    fn name_option(&self) -> Option<String> {
        (!self.name.is_empty()).then(|| self.name.clone())
    }
}

/// Pending softirq entry waiting for matching exit.
#[derive(Clone)]
struct PendingSoftirq {
    ts: u64,
    vec: i32,
}

pub struct SchedEventRecorder {
    pub ringbuf: RingBuffer<task_event>,
    // Pending IRQ/softirq events keyed by (cpu, irq/vec).
    // IRQs and softirqs cannot nest on the same CPU with the same IRQ number or
    // softirq vector, so (cpu, irq/vec) uniquely identifies a pending entry.
    // When we receive an exit event, we look up the matching entry by this key.
    pending_irqs: HashMap<(u32, i32), PendingIrq>,
    pending_softirqs: HashMap<(u32, i32), PendingSoftirq>,
    // Per-CPU state for building sched slices
    cpu_states: HashMap<u32, CpuRunningState>,
    // Locally buffered records, flushed to the collector in batches (see
    // STREAMING_SCHED_FLUSH_THRESHOLD). The collector may be shared with the
    // other per-ring recorder shards, so nothing writes to it per-event.
    pending_slices: Vec<SchedSliceRecord>,
    pending_thread_states: Vec<ThreadStateRecord>,
    pending_irq_slices: Vec<IrqSliceRecord>,
    pending_softirq_slices: Vec<SoftirqSliceRecord>,
    pending_wakeup_news: Vec<WakeupNewRecord>,
    pending_process_exits: Vec<ProcessExitRecord>,
    streaming_collector: Option<Box<dyn RecordCollector + Send>>,
    // Shared utid generator for consistent thread IDs across all recorders
    utid_generator: Arc<UtidGenerator>,
}

impl SystingRecordEvent<task_event> for SchedEventRecorder {
    fn ringbuf(&self) -> &RingBuffer<task_event> {
        &self.ringbuf
    }

    fn ringbuf_mut(&mut self) -> &mut RingBuffer<task_event> {
        &mut self.ringbuf
    }

    fn handle_event(&mut self, event: task_event) {
        debug_assert!(
            self.streaming_collector.is_some(),
            "streaming_collector must be set before handling events"
        );

        match event.r#type {
            // SCHED_SWITCH and SCHED_WAKING use compact sched format
            event_type::SCHED_SWITCH | event_type::SCHED_WAKING => {
                // Thread state model for Perfetto:
                // - Wakeup events (SCHED_WAKING): emit ThreadStateRecord with state=0 (runnable)
                // - Sleep events (SCHED_SWITCH with prev_state != 0): emit ThreadStateRecord
                //   with the kernel state (1=interruptible, 2=uninterruptible, etc.)
                // - The sched_slice.end_state captures the same info for the slice-based view
                if event.r#type == event_type::SCHED_SWITCH && self.streaming_collector.is_some() {
                    // Emit completed slice for previous running task
                    if let Some(prev_state) = self.cpu_states.get(&event.cpu) {
                        let dur = event.ts as i64 - prev_state.start_ts;
                        let end_state = prev_state_to_end_state(event.prev_state as i64);

                        self.pending_slices.push(SchedSliceRecord {
                            ts: prev_state.start_ts,
                            dur,
                            cpu: event.cpu as i32,
                            utid: self.utid_generator.get_or_create_utid(prev_state.tid),
                            end_state,
                            priority: prev_state.prio,
                        });

                        // Emit sleep state record when task leaves CPU with non-zero state
                        // This is critical for Perfetto to show correct off-CPU thread states
                        if let Some(state) = end_state {
                            let utid = self.utid_generator.get_or_create_utid(prev_state.tid);
                            self.pending_thread_states.push(ThreadStateRecord {
                                ts: event.ts as i64,
                                dur: 0,
                                utid,
                                state,
                                cpu: None, // CPU not relevant for sleep state
                            });
                        }

                        self.maybe_flush_pending();
                    }

                    // Update state for next task
                    self.cpu_states.insert(
                        event.cpu,
                        CpuRunningState {
                            start_ts: event.ts as i64,
                            tid: event.next.tgidpid as i32,
                            prio: event.next_prio as i32,
                        },
                    );
                }

                // SCHED_WAKING: emit ThreadStateRecord
                if event.r#type == event_type::SCHED_WAKING {
                    // Extract tid from lower 32 bits of tgidpid
                    // Get utid before borrowing collector mutably
                    let tid = event.next.tgidpid as i32;
                    let utid = self.utid_generator.get_or_create_utid(tid);

                    if self.streaming_collector.is_some() {
                        self.pending_thread_states.push(ThreadStateRecord {
                            ts: event.ts as i64,
                            dur: 0,
                            utid,
                            state: 0, // TASK_RUNNING (runnable)
                            cpu: Some(event.target_cpu as i32),
                        });
                        self.maybe_flush_pending();
                    }
                }
            }

            // IRQ handler entry - track for pairing with exit
            event_type::SCHED_IRQ_ENTER => {
                let irq = event.target_cpu as i32;
                let name = CStr::from_bytes_until_nul(&event.next.comm)
                    .map(|c| c.to_str().unwrap_or("").to_string())
                    .unwrap_or_default();
                self.pending_irqs.insert(
                    (event.cpu, irq),
                    PendingIrq {
                        ts: event.ts,
                        irq,
                        name,
                    },
                );
            }

            // IRQ handler exit - pair with entry to create slice
            event_type::SCHED_IRQ_EXIT => {
                let irq = event.target_cpu as i32;
                let ret = event.next_prio as i32;
                if let Some(pending) = self.pending_irqs.remove(&(event.cpu, irq)) {
                    let dur = event.ts.saturating_sub(pending.ts) as i64;

                    if self.streaming_collector.is_some() {
                        self.pending_irq_slices.push(IrqSliceRecord {
                            ts: pending.ts as i64,
                            dur,
                            cpu: event.cpu as i32,
                            irq: pending.irq,
                            name: pending.name_option(),
                            ret: Some(ret),
                        });
                        self.maybe_flush_pending();
                    }
                }
            }

            // Softirq entry - track for pairing with exit
            event_type::SCHED_SOFTIRQ_ENTER => {
                let vec = event.target_cpu as i32;
                self.pending_softirqs
                    .insert((event.cpu, vec), PendingSoftirq { ts: event.ts, vec });
            }

            // Softirq exit - pair with entry to create slice
            event_type::SCHED_SOFTIRQ_EXIT => {
                let vec = event.target_cpu as i32;
                if let Some(pending) = self.pending_softirqs.remove(&(event.cpu, vec)) {
                    let dur = event.ts.saturating_sub(pending.ts) as i64;

                    if self.streaming_collector.is_some() {
                        self.pending_softirq_slices.push(SoftirqSliceRecord {
                            ts: pending.ts as i64,
                            dur,
                            cpu: event.cpu as i32,
                            vec: pending.vec,
                        });
                        self.maybe_flush_pending();
                    }
                }
            }

            // New process wakeup - the `next` field contains the newly woken process info
            event_type::SCHED_WAKEUP_NEW => {
                // Extract tid from lower 32 bits of tgidpid
                // Get utid before borrowing collector mutably
                let tid = event.next.tgidpid as i32;
                let utid = self.utid_generator.get_or_create_utid(tid);

                if self.streaming_collector.is_some() {
                    self.pending_wakeup_news.push(WakeupNewRecord {
                        ts: event.ts as i64,
                        cpu: event.cpu as i32,
                        utid,
                        target_cpu: event.target_cpu as i32,
                    });
                    self.maybe_flush_pending();
                }
            }

            // Process exit - the `prev` field contains the exiting process info
            event_type::SCHED_PROCESS_EXIT => {
                // Extract tid from lower 32 bits of tgidpid
                // Get utid before borrowing collector mutably
                let tid = event.prev.tgidpid as i32;
                let utid = self.utid_generator.get_or_create_utid(tid);

                if self.streaming_collector.is_some() {
                    self.pending_process_exits.push(ProcessExitRecord {
                        ts: event.ts as i64,
                        cpu: event.cpu as i32,
                        utid,
                    });
                    self.maybe_flush_pending();
                }
            }

            // SCHED_WAKEUP is no longer emitted (redundant with SCHED_WAKING;
            // the sched_wakeup program isn't attached). The arm stays so a
            // stray event is ignored rather than hitting the catch-all.
            event_type::SCHED_WAKEUP => {}

            _ => {}
        }
    }
}

impl ThreadAwareRecorder for SchedEventRecorder {
    fn utid_generator(&self) -> &UtidGenerator {
        &self.utid_generator
    }
}

impl SchedEventRecorder {
    /// Create a new SchedEventRecorder with the given utid generator.
    pub fn new(utid_generator: Arc<UtidGenerator>) -> Self {
        Self {
            ringbuf: RingBuffer::default(),
            pending_irqs: HashMap::new(),
            pending_softirqs: HashMap::new(),
            cpu_states: HashMap::new(),
            pending_slices: Vec::new(),
            pending_thread_states: Vec::new(),
            pending_irq_slices: Vec::new(),
            pending_softirq_slices: Vec::new(),
            pending_wakeup_news: Vec::new(),
            pending_process_exits: Vec::new(),
            streaming_collector: None,
            utid_generator,
        }
    }

    /// Set the streaming collector for real-time event emission.
    pub fn set_streaming_collector(&mut self, collector: Box<dyn RecordCollector + Send>) {
        self.streaming_collector = Some(collector);
    }

    /// Total number of locally buffered records awaiting a batched handover
    /// to the collector.
    fn pending_len(&self) -> usize {
        self.pending_slices.len()
            + self.pending_thread_states.len()
            + self.pending_irq_slices.len()
            + self.pending_softirq_slices.len()
            + self.pending_wakeup_news.len()
            + self.pending_process_exits.len()
    }

    /// Hand all locally buffered records to the collector. The collector may
    /// be shared with the other per-ring recorder shards, so this is the only
    /// place that writes records to it: batching keeps the shards from
    /// serializing on the shared writer's lock.
    ///
    /// Every buffer is fully drained even when individual adds fail: a failed
    /// record is warned about and dropped (matching the previous per-record
    /// behaviour) rather than aborting the batch, so one bad write can't
    /// silently discard the rest of a buffer. Returns an error summarizing
    /// the failure count so finish() can surface it; mid-recording callers
    /// ignore it (the per-record warnings have already been printed).
    fn flush_pending(&mut self) -> Result<()> {
        let Some(collector) = &mut self.streaming_collector else {
            return Ok(());
        };
        let mut failed = 0usize;
        let warn = |what: &str, e: anyhow::Error, failed: &mut usize| {
            eprintln!("Warning: Failed to stream {what}: {e}");
            *failed += 1;
        };
        for record in self.pending_slices.drain(..) {
            if let Err(e) = collector.add_sched_slice(record) {
                warn("sched slice", e, &mut failed);
            }
        }
        for record in self.pending_thread_states.drain(..) {
            if let Err(e) = collector.add_thread_state(record) {
                warn("thread state", e, &mut failed);
            }
        }
        for record in self.pending_irq_slices.drain(..) {
            if let Err(e) = collector.add_irq_slice(record) {
                warn("IRQ slice", e, &mut failed);
            }
        }
        for record in self.pending_softirq_slices.drain(..) {
            if let Err(e) = collector.add_softirq_slice(record) {
                warn("softirq slice", e, &mut failed);
            }
        }
        for record in self.pending_wakeup_news.drain(..) {
            if let Err(e) = collector.add_wakeup_new(record) {
                warn("wakeup_new", e, &mut failed);
            }
        }
        for record in self.pending_process_exits.drain(..) {
            if let Err(e) = collector.add_process_exit(record) {
                warn("process_exit", e, &mut failed);
            }
        }
        if failed > 0 {
            anyhow::bail!("failed to stream {failed} sched/IRQ records");
        }
        Ok(())
    }

    /// Flush the local buffers once enough records have accumulated.
    /// Failures were already warned about per record inside flush_pending,
    /// and event consumption keeps going regardless.
    fn maybe_flush_pending(&mut self) {
        if self.pending_len() >= STREAMING_SCHED_FLUSH_THRESHOLD {
            let _ = self.flush_pending();
        }
    }

    /// Finish streaming and emit final records for incomplete events.
    ///
    /// This method should be called at the end of recording to:
    /// 1. Emit final slices for still-running tasks on each CPU
    /// 2. Emit unpaired IRQs/softirqs with dur=0
    /// 3. Drain every locally buffered record type to the collector
    ///
    /// Returns the streaming collector so the caller can call finish() on it.
    pub fn finish(&mut self, end_ts: i64) -> Result<Option<Box<dyn RecordCollector + Send>>> {
        if self.streaming_collector.is_some() {
            // Emit final slices for still-running tasks on each CPU
            let final_slices: Vec<_> = self
                .cpu_states
                .iter()
                .map(|(cpu, state)| {
                    let dur = end_ts - state.start_ts;
                    SchedSliceRecord {
                        ts: state.start_ts,
                        dur,
                        cpu: *cpu as i32,
                        utid: self.utid_generator.get_or_create_utid(state.tid),
                        end_state: None, // Still running at trace end
                        priority: state.prio,
                    }
                })
                .collect();
            self.pending_slices.extend(final_slices);

            // Emit unpaired IRQs with dur=0 to indicate incomplete
            let unpaired_irqs: Vec<_> = self
                .pending_irqs
                .iter()
                .map(|((cpu, _irq), pending)| IrqSliceRecord {
                    ts: pending.ts as i64,
                    dur: 0, // Incomplete - no exit event received
                    cpu: *cpu as i32,
                    irq: pending.irq,
                    name: pending.name_option(),
                    ret: None, // No return value without exit
                })
                .collect();
            self.pending_irq_slices.extend(unpaired_irqs);

            // Emit unpaired softirqs with dur=0
            let unpaired_softirqs: Vec<_> = self
                .pending_softirqs
                .iter()
                .map(|((cpu, _vec), pending)| SoftirqSliceRecord {
                    ts: pending.ts as i64,
                    dur: 0, // Incomplete - no exit event received
                    cpu: *cpu as i32,
                    vec: pending.vec,
                })
                .collect();
            self.pending_softirq_slices.extend(unpaired_softirqs);

            // Hand everything buffered locally to the collector, then flush
            // the collector's own buffers before returning it.
            self.flush_pending()?;
            if let Some(collector) = &mut self.streaming_collector {
                collector.flush()?;
            }
        }

        // Take ownership of the collector and return it
        Ok(self.streaming_collector.take())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::collector::InMemoryCollector;
    use crate::systing_core::types::event_type;
    use crate::systing_core::types::task_info;
    use crate::utid::UtidGenerator;

    fn copy_to_comm(comm: &mut [u8], value: &CStr) {
        let bytes = value.to_bytes_with_nul();
        comm[..bytes.len()].copy_from_slice(bytes);
    }

    fn create_test_recorder() -> SchedEventRecorder {
        SchedEventRecorder::new(Arc::new(UtidGenerator::new()))
    }

    /// A RecordCollector that delegates to a shared InMemoryCollector, so a
    /// test can keep a handle to the data after handing the collector to the
    /// recorder (SchedEventRecorder::finish returns an opaque trait object).
    #[derive(Clone)]
    struct SharedInMemoryCollector(std::sync::Arc<std::sync::Mutex<InMemoryCollector>>);

    impl SharedInMemoryCollector {
        fn new() -> Self {
            Self(std::sync::Arc::new(std::sync::Mutex::new(
                InMemoryCollector::new(),
            )))
        }
    }

    macro_rules! delegate_to_inner {
        ($($method:ident($record:ty)),* $(,)?) => {
            $(
                fn $method(&mut self, record: $record) -> Result<()> {
                    self.0.lock().unwrap().$method(record)
                }
            )*
        };
    }

    impl RecordCollector for SharedInMemoryCollector {
        delegate_to_inner! {
            add_process(crate::trace::ProcessRecord),
            add_thread(crate::trace::ThreadRecord),
            add_sched_slice(SchedSliceRecord),
            add_thread_state(ThreadStateRecord),
            add_irq_slice(IrqSliceRecord),
            add_softirq_slice(SoftirqSliceRecord),
            add_wakeup_new(WakeupNewRecord),
            add_process_exit(ProcessExitRecord),
            add_counter(crate::trace::CounterRecord),
            add_counter_track(crate::trace::CounterTrackRecord),
            add_slice(crate::trace::SliceRecord),
            add_track(crate::trace::TrackRecord),
            add_instant(crate::trace::InstantRecord),
            add_arg(crate::trace::ArgRecord),
            add_instant_arg(crate::trace::InstantArgRecord),
            add_network_interface(crate::trace::NetworkInterfaceRecord),
            add_socket_connection(crate::trace::SocketConnectionRecord),
            add_clock_snapshot(crate::trace::ClockSnapshotRecord),
            add_stack(crate::trace::StackRecord),
            add_stack_sample(crate::trace::StackSampleRecord),
            add_network_syscall(crate::trace::NetworkSyscallRecord),
            add_network_packet(crate::trace::NetworkPacketRecord),
            add_network_socket(crate::trace::NetworkSocketRecord),
            add_network_poll(crate::trace::NetworkPollRecord),
            add_network_dns(crate::trace::NetworkDnsRecord),
            add_memory_rss(crate::trace::MemoryRssRecord),
            add_memory_map(crate::trace::MemoryMapRecord),
            add_memory_fault(crate::trace::MemoryFaultRecord),
            add_memory_alloc(crate::trace::MemoryAllocRecord),
            set_sysinfo(crate::trace::SysInfoRecord),
            add_cpu_info(crate::trace::CpuInfoRecord),
            add_tpu_device(crate::trace::TpuDeviceRecord),
            add_tpu_op(crate::trace::TpuOpRecord),
            add_tpu_metric(crate::trace::TpuMetricRecord),
        }

        fn flush(&mut self) -> Result<()> {
            self.0.lock().unwrap().flush()
        }

        fn finish(self) -> Result<()> {
            Ok(())
        }

        fn finish_boxed(self: Box<Self>) -> Result<()> {
            Ok(())
        }
    }

    /// Every record type the recorder buffers locally must actually reach the
    /// collector: mid-recording the buffers hold records below the flush
    /// threshold, and finish() must drain all of them (not just sched slices).
    #[test]
    fn test_finish_drains_all_buffered_record_types() {
        let mut recorder = create_test_recorder();
        let handle = SharedInMemoryCollector::new();
        recorder.set_streaming_collector(Box::new(handle.clone()));

        let mk = |r#type, ts: u64, cpu: u32, target_cpu: u32, tgidpid: u64| task_event {
            r#type,
            ts,
            cpu,
            target_cpu,
            next: task_info {
                tgidpid,
                ..Default::default()
            },
            prev: task_info {
                tgidpid,
                ..Default::default()
            },
            ..Default::default()
        };

        // Two switches on one CPU complete one sched slice; the second has
        // prev_state != 0, which also emits a sleep thread_state.
        let mut switch1 = mk(event_type::SCHED_SWITCH, 1000, 0, 0, 100);
        switch1.prev_state = 0;
        recorder.handle_event(switch1);
        let mut switch2 = mk(event_type::SCHED_SWITCH, 2000, 0, 0, 200);
        switch2.prev_state = 2; // TASK_UNINTERRUPTIBLE
        recorder.handle_event(switch2);

        // Waking emits a runnable thread_state.
        recorder.handle_event(mk(event_type::SCHED_WAKING, 2500, 1, 3, 300));

        // Paired IRQ and softirq entry/exit emit one slice each.
        recorder.handle_event(mk(event_type::SCHED_IRQ_ENTER, 3000, 2, 42, 400));
        recorder.handle_event(mk(event_type::SCHED_IRQ_EXIT, 3100, 2, 42, 400));
        recorder.handle_event(mk(event_type::SCHED_SOFTIRQ_ENTER, 4000, 3, 6, 500));
        recorder.handle_event(mk(event_type::SCHED_SOFTIRQ_EXIT, 4200, 3, 6, 500));

        recorder.handle_event(mk(event_type::SCHED_WAKEUP_NEW, 5000, 4, 5, 600));
        recorder.handle_event(mk(event_type::SCHED_PROCESS_EXIT, 6000, 5, 0, 700));

        // Below the flush threshold, everything is still buffered locally.
        {
            let inner = handle.0.lock().unwrap();
            assert!(inner.data().sched_slices.is_empty());
            assert!(inner.data().thread_states.is_empty());
            assert!(inner.data().irq_slices.is_empty());
            assert!(inner.data().softirq_slices.is_empty());
            assert!(inner.data().wakeup_news.is_empty());
            assert!(inner.data().process_exits.is_empty());
        }

        // finish() must hand every buffered record type to the collector.
        recorder.finish(10_000).unwrap();
        let inner = handle.0.lock().unwrap();
        let data = inner.data();
        // One completed slice (switch1 -> switch2) plus one final slice for
        // the still-running task on CPU 0.
        assert_eq!(data.sched_slices.len(), 2);
        // One sleep state (switch2, prev_state != 0) + one runnable (waking).
        assert_eq!(data.thread_states.len(), 2);
        assert_eq!(data.irq_slices.len(), 1);
        assert_eq!(data.softirq_slices.len(), 1);
        assert_eq!(data.wakeup_news.len(), 1);
        assert_eq!(data.process_exits.len(), 1);
    }

    #[test]
    fn test_streaming_sched_waking_emits_runnable_state() {
        use crate::record::collector::InMemoryCollector;

        let mut recorder = create_test_recorder();
        let collector = Box::new(InMemoryCollector::new());
        recorder.set_streaming_collector(collector);

        let next_comm = c"woken_task";
        let mut event = task_event {
            r#type: event_type::SCHED_WAKING,
            ts: 1000,
            next: task_info {
                tgidpid: 1234,
                ..Default::default()
            },
            target_cpu: 2,
            ..Default::default()
        };
        copy_to_comm(&mut event.next.comm, next_comm);
        recorder.handle_event(event);

        // Verify we can finish without errors - the collector received the record
        let result = recorder.finish(2000);
        assert!(result.is_ok());
        assert!(result.unwrap().is_some()); // Collector was returned
    }

    #[test]
    fn test_streaming_sched_switch_emits_sleep_state() {
        use crate::record::collector::InMemoryCollector;

        let mut recorder = create_test_recorder();
        let collector = Box::new(InMemoryCollector::new());
        recorder.set_streaming_collector(collector);

        let prev_comm = c"sleeping_task";
        let next_comm = c"next_task";

        // First event: task starts running
        let mut event1 = task_event {
            r#type: event_type::SCHED_SWITCH,
            ts: 1000,
            cpu: 0,
            next: task_info {
                tgidpid: 1234, // Task that starts running
                ..Default::default()
            },
            prev: task_info {
                tgidpid: 0, // Idle task
                ..Default::default()
            },
            prev_state: 0, // Was running (preempted)
            ..Default::default()
        };
        copy_to_comm(&mut event1.next.comm, next_comm);
        recorder.handle_event(event1);

        // Second event: task goes to uninterruptible sleep (state=2)
        let mut event2 = task_event {
            r#type: event_type::SCHED_SWITCH,
            ts: 2000,
            cpu: 0,
            next: task_info {
                tgidpid: 5678, // New task
                ..Default::default()
            },
            prev: task_info {
                tgidpid: 1234, // Previous task (the one going to sleep)
                ..Default::default()
            },
            prev_state: 2, // TASK_UNINTERRUPTIBLE
            ..Default::default()
        };
        copy_to_comm(&mut event2.next.comm, prev_comm);
        copy_to_comm(&mut event2.prev.comm, next_comm);
        recorder.handle_event(event2);

        // The recorder should have emitted a ThreadStateRecord with state=2
        // for the task that went to sleep. We can't easily extract this from
        // InMemoryCollector in the current design, but the test validates
        // the code path doesn't panic.

        // Verify we can finish without errors
        let result = recorder.finish(3000);
        assert!(result.is_ok());
    }

    #[test]
    fn test_thread_state_record_uses_numeric_state() {
        // Verify that ThreadStateRecord uses i32 for state field
        let record = ThreadStateRecord {
            ts: 1000,
            dur: 0,
            utid: 1234,
            state: 2, // TASK_UNINTERRUPTIBLE
            cpu: Some(0),
        };
        assert_eq!(record.state, 2);

        // Verify runnable state is 0
        let runnable = ThreadStateRecord {
            ts: 1000,
            dur: 0,
            utid: 1234,
            state: 0, // TASK_RUNNING (runnable)
            cpu: Some(1),
        };
        assert_eq!(runnable.state, 0);
    }
}
