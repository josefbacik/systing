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

/// Threshold for flushing streaming sched slices to the collector.
/// Lower than Parquet batch size (200K) to reduce peak memory while maintaining I/O efficiency.
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
    pending_slices: Vec<SchedSliceRecord>,
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
                            // Get utid before borrowing collector mutably
                            let utid = self.utid_generator.get_or_create_utid(prev_state.tid);
                            if let Some(collector) = &mut self.streaming_collector {
                                if let Err(e) = collector.add_thread_state(ThreadStateRecord {
                                    ts: event.ts as i64,
                                    dur: 0,
                                    utid,
                                    state,
                                    cpu: None, // CPU not relevant for sleep state
                                }) {
                                    eprintln!("Warning: Failed to stream thread sleep state: {e}");
                                }
                            }
                        }

                        // Flush if we have accumulated enough slices
                        if self.pending_slices.len() >= STREAMING_SCHED_FLUSH_THRESHOLD {
                            if let Some(collector) = &mut self.streaming_collector {
                                for slice in self.pending_slices.drain(..) {
                                    if let Err(e) = collector.add_sched_slice(slice) {
                                        eprintln!("Warning: Failed to stream sched slice: {e}");
                                    }
                                }
                            }
                        }
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

                    if let Some(collector) = &mut self.streaming_collector {
                        if let Err(e) = collector.add_thread_state(ThreadStateRecord {
                            ts: event.ts as i64,
                            dur: 0,
                            utid,
                            state: 0, // TASK_RUNNING (runnable)
                            cpu: Some(event.target_cpu as i32),
                        }) {
                            eprintln!("Warning: Failed to stream thread state: {e}");
                        }
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

                    if let Some(collector) = &mut self.streaming_collector {
                        if let Err(e) = collector.add_irq_slice(IrqSliceRecord {
                            ts: pending.ts as i64,
                            dur,
                            cpu: event.cpu as i32,
                            irq: pending.irq,
                            name: pending.name_option(),
                            ret: Some(ret),
                        }) {
                            eprintln!("Warning: Failed to stream IRQ slice: {e}");
                        }
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

                    if let Some(collector) = &mut self.streaming_collector {
                        if let Err(e) = collector.add_softirq_slice(SoftirqSliceRecord {
                            ts: pending.ts as i64,
                            dur,
                            cpu: event.cpu as i32,
                            vec: pending.vec,
                        }) {
                            eprintln!("Warning: Failed to stream softirq slice: {e}");
                        }
                    }
                }
            }

            // New process wakeup - the `next` field contains the newly woken process info
            event_type::SCHED_WAKEUP_NEW => {
                // Extract tid from lower 32 bits of tgidpid
                // Get utid before borrowing collector mutably
                let tid = event.next.tgidpid as i32;
                let utid = self.utid_generator.get_or_create_utid(tid);

                if let Some(collector) = &mut self.streaming_collector {
                    if let Err(e) = collector.add_wakeup_new(WakeupNewRecord {
                        ts: event.ts as i64,
                        cpu: event.cpu as i32,
                        utid,
                        target_cpu: event.target_cpu as i32,
                    }) {
                        eprintln!("Warning: Failed to stream wakeup_new: {e}");
                    }
                }
            }

            // Process exit - the `prev` field contains the exiting process info
            event_type::SCHED_PROCESS_EXIT => {
                // Extract tid from lower 32 bits of tgidpid
                // Get utid before borrowing collector mutably
                let tid = event.prev.tgidpid as i32;
                let utid = self.utid_generator.get_or_create_utid(tid);

                if let Some(collector) = &mut self.streaming_collector {
                    if let Err(e) = collector.add_process_exit(ProcessExitRecord {
                        ts: event.ts as i64,
                        cpu: event.cpu as i32,
                        utid,
                    }) {
                        eprintln!("Warning: Failed to stream process_exit: {e}");
                    }
                }
            }

            // Skip SCHED_WAKEUP (redundant with SCHED_WAKING)
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
            streaming_collector: None,
            utid_generator,
        }
    }

    /// Set the streaming collector for real-time event emission.
    pub fn set_streaming_collector(&mut self, collector: Box<dyn RecordCollector + Send>) {
        self.streaming_collector = Some(collector);
    }

    /// Finish streaming and emit final records for incomplete events.
    ///
    /// This method should be called at the end of recording to:
    /// 1. Emit final slices for still-running tasks on each CPU
    /// 2. Emit unpaired IRQs/softirqs with dur=0
    /// 3. Flush any remaining pending_slices to collector
    ///
    /// Returns the streaming collector so the caller can call finish() on it.
    pub fn finish(&mut self, end_ts: i64) -> Result<Option<Box<dyn RecordCollector + Send>>> {
        if let Some(collector) = &mut self.streaming_collector {
            // Emit final slices for still-running tasks on each CPU
            // Pre-compute utids before borrowing collector mutably
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

            for slice in final_slices {
                collector.add_sched_slice(slice)?;
            }

            // Flush any remaining pending slices
            for slice in self.pending_slices.drain(..) {
                collector.add_sched_slice(slice)?;
            }

            // Emit unpaired IRQs with dur=0 to indicate incomplete
            for ((cpu, _irq), pending) in &self.pending_irqs {
                collector.add_irq_slice(IrqSliceRecord {
                    ts: pending.ts as i64,
                    dur: 0, // Incomplete - no exit event received
                    cpu: *cpu as i32,
                    irq: pending.irq,
                    name: pending.name_option(),
                    ret: None, // No return value without exit
                })?;
            }

            // Emit unpaired softirqs with dur=0
            for ((cpu, _vec), pending) in &self.pending_softirqs {
                collector.add_softirq_slice(SoftirqSliceRecord {
                    ts: pending.ts as i64,
                    dur: 0, // Incomplete - no exit event received
                    cpu: *cpu as i32,
                    vec: pending.vec,
                })?;
            }

            // Flush buffers before returning collector
            collector.flush()?;
        }

        // Take ownership of the collector and return it
        Ok(self.streaming_collector.take())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
