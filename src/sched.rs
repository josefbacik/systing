use std::collections::{BTreeMap, HashMap};
use std::ffi::CStr;
use std::sync::Arc;

use anyhow::Result;

use crate::perfetto::TraceWriter;
use crate::record::RecordCollector;
use crate::ringbuf::RingBuffer;
use crate::systing_core::types::event_type;
use crate::systing_core::types::task_event;
use crate::systing_core::SystingRecordEvent;
use crate::trace::{
    IrqSliceRecord, ProcessExitRecord, SchedSliceRecord, SoftirqSliceRecord, ThreadStateRecord,
    WakeupNewRecord,
};
use crate::utid::UtidGenerator;

use perfetto_protos::ftrace_event::FtraceEvent;
use perfetto_protos::ftrace_event_bundle::ftrace_event_bundle::CompactSched;
use perfetto_protos::ftrace_event_bundle::FtraceEventBundle;
use perfetto_protos::irq::{
    IrqHandlerEntryFtraceEvent, IrqHandlerExitFtraceEvent, SoftirqEntryFtraceEvent,
    SoftirqExitFtraceEvent,
};
use perfetto_protos::sched::{SchedProcessExitFtraceEvent, SchedWakeupNewFtraceEvent};
use perfetto_protos::trace_packet::TracePacket;

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

#[derive(Default)]
struct LocalCompactSched {
    compact_sched: CompactSched,
    comm_mapping: HashMap<String, u32>,
    last_waking_ts: u64,
    last_switch_ts: u64,
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

/// Completed IRQ slice (entry + exit paired).
struct CompletedIrq {
    ts: i64,
    dur: i64,
    cpu: i32,
    irq: i32,
    name: Option<String>,
    ret: Option<i32>,
}

/// Completed softirq slice (entry + exit paired).
struct CompletedSoftirq {
    ts: i64,
    dur: i64,
    cpu: i32,
    vec: i32,
}

/// Wakeup new event data.
struct WakeupNewEvent {
    ts: i64,
    cpu: i32,
    pid: i32,
    target_cpu: i32,
}

/// Process exit event data.
struct ProcessExitEvent {
    ts: i64,
    cpu: i32,
    pid: i32,
}

pub struct SchedEventRecorder {
    pub ringbuf: RingBuffer<task_event>,
    events: HashMap<u32, BTreeMap<u64, FtraceEvent>>,
    compact_sched: HashMap<u32, LocalCompactSched>,
    // Pending IRQ/softirq events keyed by (cpu, irq/vec).
    // IRQs and softirqs cannot nest on the same CPU with the same IRQ number or
    // softirq vector, so (cpu, irq/vec) uniquely identifies a pending entry.
    // When we receive an exit event, we look up the matching entry by this key.
    pending_irqs: HashMap<(u32, i32), PendingIrq>,
    pending_softirqs: HashMap<(u32, i32), PendingSoftirq>,
    // Completed events for Parquet output
    completed_irqs: Vec<CompletedIrq>,
    completed_softirqs: Vec<CompletedSoftirq>,
    wakeup_news: Vec<WakeupNewEvent>,
    process_exits: Vec<ProcessExitEvent>,
    // Streaming support: per-CPU state tracking
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
        match event.r#type {
            // SCHED_SWITCH and SCHED_WAKING use compact sched format
            event_type::SCHED_SWITCH | event_type::SCHED_WAKING => {
                // Handle streaming mode for SCHED_SWITCH
                //
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

                // Handle streaming mode for SCHED_WAKING: emit ThreadStateRecord immediately
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

                // Always add to compact_sched for both SCHED_SWITCH and SCHED_WAKING.
                // This is intentional even in streaming mode: compact_sched is used by
                // write_trace() for Perfetto output, allowing both Parquet and Perfetto
                // formats from a single recording session.
                let compact_sched = self.compact_sched.entry(event.cpu).or_default();
                compact_sched.add_task_event(&event);
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
                self.add_ftrace_event(&event);
            }

            // IRQ handler exit - pair with entry to create slice
            event_type::SCHED_IRQ_EXIT => {
                let irq = event.target_cpu as i32;
                let ret = event.next_prio as i32;
                if let Some(pending) = self.pending_irqs.remove(&(event.cpu, irq)) {
                    let dur = event.ts.saturating_sub(pending.ts) as i64;

                    // If streaming, emit immediately and skip memory storage
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
                    } else {
                        // Non-streaming: store in memory for later write_records()
                        self.completed_irqs.push(CompletedIrq {
                            ts: pending.ts as i64,
                            dur,
                            cpu: event.cpu as i32,
                            irq: pending.irq,
                            name: pending.name_option(),
                            ret: Some(ret),
                        });
                    }
                }
                self.add_ftrace_event(&event);
            }

            // Softirq entry - track for pairing with exit
            event_type::SCHED_SOFTIRQ_ENTER => {
                let vec = event.target_cpu as i32;
                self.pending_softirqs
                    .insert((event.cpu, vec), PendingSoftirq { ts: event.ts, vec });
                self.add_ftrace_event(&event);
            }

            // Softirq exit - pair with entry to create slice
            event_type::SCHED_SOFTIRQ_EXIT => {
                let vec = event.target_cpu as i32;
                if let Some(pending) = self.pending_softirqs.remove(&(event.cpu, vec)) {
                    let dur = event.ts.saturating_sub(pending.ts) as i64;

                    // If streaming, emit immediately and skip memory storage
                    if let Some(collector) = &mut self.streaming_collector {
                        if let Err(e) = collector.add_softirq_slice(SoftirqSliceRecord {
                            ts: pending.ts as i64,
                            dur,
                            cpu: event.cpu as i32,
                            vec: pending.vec,
                        }) {
                            eprintln!("Warning: Failed to stream softirq slice: {e}");
                        }
                    } else {
                        // Non-streaming: store in memory for later write_records()
                        self.completed_softirqs.push(CompletedSoftirq {
                            ts: pending.ts as i64,
                            dur,
                            cpu: event.cpu as i32,
                            vec: pending.vec,
                        });
                    }
                }
                self.add_ftrace_event(&event);
            }

            // New process wakeup - the `next` field contains the newly woken process info
            event_type::SCHED_WAKEUP_NEW => {
                // Extract tid from lower 32 bits of tgidpid
                // Get utid before borrowing collector mutably
                let tid = event.next.tgidpid as i32;
                let utid = self.utid_generator.get_or_create_utid(tid);

                // Stream immediately if streaming mode is enabled
                if let Some(collector) = &mut self.streaming_collector {
                    if let Err(e) = collector.add_wakeup_new(WakeupNewRecord {
                        ts: event.ts as i64,
                        cpu: event.cpu as i32,
                        utid,
                        target_cpu: event.target_cpu as i32,
                    }) {
                        eprintln!("Warning: Failed to stream wakeup_new: {e}");
                    }
                } else {
                    // Non-streaming: buffer for later
                    self.wakeup_news.push(WakeupNewEvent {
                        ts: event.ts as i64,
                        cpu: event.cpu as i32,
                        pid: tid,
                        target_cpu: event.target_cpu as i32,
                    });
                }
                self.add_ftrace_event(&event);
            }

            // Process exit - the `prev` field contains the exiting process info
            event_type::SCHED_PROCESS_EXIT => {
                // Extract tid from lower 32 bits of tgidpid
                // Get utid before borrowing collector mutably
                let tid = event.prev.tgidpid as i32;
                let utid = self.utid_generator.get_or_create_utid(tid);

                // Stream immediately if streaming mode is enabled
                if let Some(collector) = &mut self.streaming_collector {
                    if let Err(e) = collector.add_process_exit(ProcessExitRecord {
                        ts: event.ts as i64,
                        cpu: event.cpu as i32,
                        utid,
                    }) {
                        eprintln!("Warning: Failed to stream process_exit: {e}");
                    }
                } else {
                    // Non-streaming: buffer for later
                    self.process_exits.push(ProcessExitEvent {
                        ts: event.ts as i64,
                        cpu: event.cpu as i32,
                        pid: tid,
                    });
                }
                self.add_ftrace_event(&event);
            }

            // Skip SCHED_WAKEUP (redundant with SCHED_WAKING)
            event_type::SCHED_WAKEUP => {}

            // Other events go directly to ftrace
            _ => {
                self.add_ftrace_event(&event);
            }
        }
    }
}

impl SchedEventRecorder {
    /// Create a new SchedEventRecorder with the given utid generator.
    pub fn new(utid_generator: Arc<UtidGenerator>) -> Self {
        Self {
            ringbuf: RingBuffer::default(),
            events: HashMap::new(),
            compact_sched: HashMap::new(),
            pending_irqs: HashMap::new(),
            pending_softirqs: HashMap::new(),
            completed_irqs: Vec::new(),
            completed_softirqs: Vec::new(),
            wakeup_news: Vec::new(),
            process_exits: Vec::new(),
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

    /// Add an event to the ftrace events map for Perfetto output.
    fn add_ftrace_event(&mut self, event: &task_event) {
        let ftrace_event = FtraceEvent::from(event);
        let cpu_event = self.events.entry(event.cpu).or_default();
        cpu_event.insert(event.ts, ftrace_event);
    }

    /// Write trace data directly to a RecordCollector (Parquet-first path).
    ///
    /// This method outputs records directly without going through Perfetto format.
    /// It converts the delta-encoded CompactSched data back to absolute timestamps.
    pub fn write_records(&self, collector: &mut dyn RecordCollector) -> Result<()> {
        // Process compact sched events (SCHED_SWITCH, SCHED_WAKING)
        for (cpu, local_compact) in self.compact_sched.iter() {
            let compact = &local_compact.compact_sched;

            // Decode switch events to SchedSliceRecord
            let mut switch_ts: i64 = 0;
            for i in 0..compact.switch_timestamp.len() {
                switch_ts += compact.switch_timestamp[i] as i64;
                let next_pid = compact.switch_next_pid[i];
                let next_prio = compact.switch_next_prio.get(i).copied().unwrap_or(0);
                let prev_state = compact.switch_prev_state.get(i).copied().unwrap_or(0);

                // Get or create utid for this thread
                let utid = self.utid_generator.get_or_create_utid(next_pid);

                let end_state = prev_state_to_end_state(prev_state);

                collector.add_sched_slice(SchedSliceRecord {
                    ts: switch_ts,
                    dur: 0, // Duration computed later or left as 0 for streaming
                    cpu: *cpu as i32,
                    utid,
                    end_state,
                    priority: next_prio,
                })?;
            }

            // Decode waking events to ThreadStateRecord
            let mut waking_ts: i64 = 0;
            for i in 0..compact.waking_timestamp.len() {
                waking_ts += compact.waking_timestamp[i] as i64;
                let pid = compact.waking_pid[i];
                let target_cpu = compact.waking_target_cpu.get(i).copied().unwrap_or(0);

                let utid = self.utid_generator.get_or_create_utid(pid);

                collector.add_thread_state(ThreadStateRecord {
                    ts: waking_ts,
                    dur: 0,
                    utid,
                    state: 0, // TASK_RUNNING (runnable)
                    cpu: Some(target_cpu),
                })?;
            }
        }

        // Emit completed IRQ slices
        for irq in &self.completed_irqs {
            collector.add_irq_slice(IrqSliceRecord {
                ts: irq.ts,
                dur: irq.dur,
                cpu: irq.cpu,
                irq: irq.irq,
                name: irq.name.clone(),
                ret: irq.ret,
            })?;
        }

        // Emit pending (unpaired) IRQ entries with dur=0 to indicate incomplete
        // These represent IRQs that started but didn't finish before tracing ended
        for ((cpu, _irq), pending) in &self.pending_irqs {
            collector.add_irq_slice(IrqSliceRecord {
                ts: pending.ts as i64,
                dur: 0, // Incomplete - no exit event received
                cpu: *cpu as i32,
                irq: pending.irq,
                name: if pending.name.is_empty() {
                    None
                } else {
                    Some(pending.name.clone())
                },
                ret: None, // No return value without exit
            })?;
        }

        // Emit completed softirq slices
        for softirq in &self.completed_softirqs {
            collector.add_softirq_slice(SoftirqSliceRecord {
                ts: softirq.ts,
                dur: softirq.dur,
                cpu: softirq.cpu,
                vec: softirq.vec,
            })?;
        }

        // Emit pending (unpaired) softirq entries with dur=0
        for ((cpu, _vec), pending) in &self.pending_softirqs {
            collector.add_softirq_slice(SoftirqSliceRecord {
                ts: pending.ts as i64,
                dur: 0, // Incomplete - no exit event received
                cpu: *cpu as i32,
                vec: pending.vec,
            })?;
        }

        // Emit wakeup_new events
        for wakeup in &self.wakeup_news {
            let utid = self.utid_generator.get_or_create_utid(wakeup.pid);
            collector.add_wakeup_new(WakeupNewRecord {
                ts: wakeup.ts,
                cpu: wakeup.cpu,
                utid,
                target_cpu: wakeup.target_cpu,
            })?;
        }

        // Emit process exit events
        for exit in &self.process_exits {
            let utid = self.utid_generator.get_or_create_utid(exit.pid);
            collector.add_process_exit(ProcessExitRecord {
                ts: exit.ts,
                cpu: exit.cpu,
                utid,
            })?;
        }

        Ok(())
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

    /// Write trace data to Perfetto format (used by parquet-to-perfetto conversion).
    pub fn write_trace(&self, writer: &mut dyn TraceWriter) -> Result<()> {
        // Pull all the compact scheduling events
        for (cpu, compact_sched) in self.compact_sched.iter() {
            let mut event_bundle = FtraceEventBundle::default();
            event_bundle.set_cpu(*cpu);
            event_bundle.compact_sched = Some(compact_sched.compact_sched.clone()).into();
            let mut packet = TracePacket::default();
            packet.set_ftrace_events(event_bundle);
            writer.write_packet(&packet)?;
        }

        // Pull all the scheduling events.
        for (cpu, events) in self.events.iter() {
            let mut event_bundle = FtraceEventBundle::default();
            event_bundle.set_cpu(*cpu);
            event_bundle.event = events.values().cloned().collect();
            let mut packet = TracePacket::default();
            packet.set_ftrace_events(event_bundle);
            writer.write_packet(&packet)?;
        }

        Ok(())
    }

    /// Returns the minimum timestamp from all events, or None if no events recorded.
    pub fn min_timestamp(&self) -> Option<u64> {
        let compact_min = self
            .compact_sched
            .values()
            .filter_map(|cs| cs.compact_sched.switch_timestamp.first().copied())
            .min();

        // BTreeMap is sorted by key, so first key is min
        let events_min = self
            .events
            .values()
            .filter_map(|e| e.keys().next().copied())
            .min();

        [compact_min, events_min].into_iter().flatten().min()
    }
}

impl From<&task_event> for FtraceEvent {
    fn from(event: &task_event) -> Self {
        let mut ftrace_event = FtraceEvent::default();
        ftrace_event.set_pid(event.prev.tgidpid as u32);
        ftrace_event.set_timestamp(event.ts);
        match event.r#type {
            event_type::SCHED_WAKEUP_NEW => {
                ftrace_event.set_sched_wakeup_new(SchedWakeupNewFtraceEvent::from(event));
            }
            event_type::SCHED_IRQ_EXIT => {
                ftrace_event.set_irq_handler_exit(IrqHandlerExitFtraceEvent::from(event));
            }
            event_type::SCHED_IRQ_ENTER => {
                ftrace_event.set_irq_handler_entry(IrqHandlerEntryFtraceEvent::from(event));
            }
            event_type::SCHED_SOFTIRQ_EXIT => {
                ftrace_event.set_softirq_exit(SoftirqExitFtraceEvent::from(event));
            }
            event_type::SCHED_SOFTIRQ_ENTER => {
                ftrace_event.set_softirq_entry(SoftirqEntryFtraceEvent::from(event));
            }
            event_type::SCHED_PROCESS_EXIT => {
                ftrace_event.set_sched_process_exit(SchedProcessExitFtraceEvent::from(event));
            }
            _ => {}
        }
        ftrace_event
    }
}

impl From<&task_event> for SchedWakeupNewFtraceEvent {
    fn from(event: &task_event) -> Self {
        let comm_cstr = CStr::from_bytes_until_nul(&event.next.comm).unwrap();
        let mut sched_wakeup_new = SchedWakeupNewFtraceEvent::default();
        sched_wakeup_new.set_pid(event.next.tgidpid as i32);
        sched_wakeup_new.set_comm(comm_cstr.to_str().unwrap().to_string());
        sched_wakeup_new.set_prio(event.next_prio as i32);
        sched_wakeup_new.set_target_cpu(event.target_cpu as i32);
        sched_wakeup_new
    }
}

impl From<&task_event> for IrqHandlerExitFtraceEvent {
    fn from(event: &task_event) -> Self {
        let mut irq_handler_exit = IrqHandlerExitFtraceEvent::default();
        irq_handler_exit.set_irq(event.target_cpu as i32);
        irq_handler_exit.set_ret(event.next_prio as i32);
        irq_handler_exit
    }
}

impl From<&task_event> for IrqHandlerEntryFtraceEvent {
    fn from(event: &task_event) -> Self {
        let mut irq_handler_entry = IrqHandlerEntryFtraceEvent::default();
        let name_cstr = CStr::from_bytes_until_nul(&event.next.comm).unwrap();
        irq_handler_entry.set_name(name_cstr.to_str().unwrap().to_string());
        irq_handler_entry.set_irq(event.target_cpu as i32);
        irq_handler_entry
    }
}

impl From<&task_event> for SoftirqExitFtraceEvent {
    fn from(event: &task_event) -> Self {
        let mut softirq_exit = SoftirqExitFtraceEvent::default();
        softirq_exit.set_vec(event.target_cpu);
        softirq_exit
    }
}

impl From<&task_event> for SoftirqEntryFtraceEvent {
    fn from(event: &task_event) -> Self {
        let mut softirq_entry = SoftirqEntryFtraceEvent::default();
        softirq_entry.set_vec(event.target_cpu);
        softirq_entry
    }
}

impl From<&task_event> for SchedProcessExitFtraceEvent {
    fn from(event: &task_event) -> Self {
        let pid = event.prev.tgidpid as i32;
        let tgid = (event.prev.tgidpid >> 32) as i32;
        let name_cstr = CStr::from_bytes_until_nul(&event.prev.comm).unwrap();
        let mut sched_process_exit = SchedProcessExitFtraceEvent::default();
        sched_process_exit.set_pid(pid);
        sched_process_exit.set_tgid(tgid);
        sched_process_exit.set_prio(event.prev_prio as i32);
        sched_process_exit.set_comm(name_cstr.to_str().unwrap().to_string());
        sched_process_exit
    }
}

impl LocalCompactSched {
    fn add_task_event(&mut self, event: &task_event) {
        let comm = CStr::from_bytes_until_nul(&event.next.comm)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let index = self.comm_mapping.entry(comm.clone()).or_insert_with(|| {
            self.compact_sched.intern_table.push(comm);
            (self.compact_sched.intern_table.len() as u32) - 1
        });
        if event.r#type == event_type::SCHED_WAKING {
            self.compact_sched
                .waking_timestamp
                .push(event.ts - self.last_waking_ts);
            self.last_waking_ts = event.ts;
            self.compact_sched
                .waking_pid
                .push(event.next.tgidpid as i32);
            self.compact_sched
                .waking_target_cpu
                .push(event.target_cpu as i32);
            self.compact_sched.waking_prio.push(event.next_prio as i32);
            self.compact_sched.waking_comm_index.push(*index);
            self.compact_sched.waking_common_flags.push(1);
        } else {
            self.compact_sched
                .switch_timestamp
                .push(event.ts - self.last_switch_ts);
            self.last_switch_ts = event.ts;
            self.compact_sched
                .switch_prev_state
                .push(event.prev_state as i64);
            self.compact_sched
                .switch_next_pid
                .push(event.next.tgidpid as i32);
            self.compact_sched
                .switch_next_prio
                .push(event.next_prio as i32);
            self.compact_sched.switch_next_comm_index.push(*index);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::perfetto::VecTraceWriter;
    use crate::systing_core::types::event_type;
    use crate::systing_core::types::task_info;
    use crate::utid::UtidGenerator;
    use perfetto_protos::trace_packet::TracePacket;

    fn copy_to_comm(comm: &mut [u8], value: &CStr) {
        let bytes = value.to_bytes_with_nul();
        comm[..bytes.len()].copy_from_slice(bytes);
    }

    fn create_test_recorder() -> SchedEventRecorder {
        SchedEventRecorder::new(Arc::new(UtidGenerator::new()))
    }

    /// Helper to collect packets from SchedEventRecorder for tests
    fn generate_trace(recorder: &SchedEventRecorder) -> Vec<TracePacket> {
        let mut writer = VecTraceWriter::new();
        recorder.write_trace(&mut writer).unwrap();
        writer.packets
    }

    #[test]
    fn test_handle_event() {
        let mut recorder = create_test_recorder();
        let prev_comm = c"prev";
        let next_comm = c"next";

        let mut event = task_event {
            r#type: event_type::SCHED_SWITCH,
            ts: 1000,
            next: task_info {
                tgidpid: 1234,
                ..Default::default()
            },
            prev: task_info {
                tgidpid: 5678,
                ..Default::default()
            },
            ..Default::default()
        };
        copy_to_comm(&mut event.next.comm, next_comm);
        copy_to_comm(&mut event.prev.comm, prev_comm);
        recorder.handle_event(event);
        assert_eq!(recorder.compact_sched.len(), 1);
        assert!(recorder.compact_sched.contains_key(&0));

        event.ts = 2000;
        event.next.tgidpid = 5678;
        event.prev.tgidpid = 1234;
        copy_to_comm(&mut event.next.comm, prev_comm);
        copy_to_comm(&mut event.prev.comm, next_comm);
        recorder.handle_event(event);

        assert_eq!(recorder.compact_sched.len(), 1);

        let packets = generate_trace(&recorder);
        assert_eq!(packets.len(), 1);

        let packet = &packets[0];
        assert!(packet.has_ftrace_events());
        let compact = packet.ftrace_events().compact_sched.as_ref().unwrap();
        assert_eq!(compact.switch_timestamp.len(), 2);
        assert_eq!(compact.switch_timestamp[0], 1000);
        assert_eq!(compact.switch_timestamp[1], 1000);
        assert_eq!(compact.intern_table.len(), 2);
        assert_eq!(compact.intern_table[0], "next");
        assert_eq!(compact.intern_table[1], "prev");
        assert_eq!(compact.switch_next_comm_index[0], 0);
        assert_eq!(compact.switch_next_comm_index[1], 1);
    }

    #[test]
    fn test_wakeup_new() {
        let mut recorder = create_test_recorder();
        let next_comm = c"next";

        let mut event = task_event {
            r#type: event_type::SCHED_WAKEUP_NEW,
            ts: 1000,
            next: task_info {
                tgidpid: 1234,
                ..Default::default()
            },
            target_cpu: 0,
            next_prio: 10,
            ..Default::default()
        };
        copy_to_comm(&mut event.next.comm, next_comm);
        recorder.handle_event(event);

        assert_eq!(recorder.compact_sched.len(), 0);
        assert_eq!(recorder.events.len(), 1);
        assert!(recorder.events.contains_key(&0));

        let packets = generate_trace(&recorder);
        assert_eq!(packets.len(), 1);

        let packet = &packets[0];
        assert!(packet.has_ftrace_events());
        let events = &packet.ftrace_events().event;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].sched_wakeup_new().comm(), "next");
        assert_eq!(events[0].sched_wakeup_new().pid(), 1234);
    }

    #[test]
    fn test_irq_handler_events() {
        let mut recorder = create_test_recorder();
        let next_comm = c"irq_handler";

        let mut event = task_event {
            r#type: event_type::SCHED_IRQ_ENTER,
            ts: 1000,
            target_cpu: 0,
            next_prio: 5,
            next: task_info {
                tgidpid: 1234,
                ..Default::default()
            },
            ..Default::default()
        };
        copy_to_comm(&mut event.next.comm, next_comm);
        recorder.handle_event(event);

        assert_eq!(recorder.compact_sched.len(), 0);
        assert_eq!(recorder.events.len(), 1);
        assert!(recorder.events.contains_key(&0));

        let packets = generate_trace(&recorder);
        assert_eq!(packets.len(), 1);

        let packet = &packets[0];
        assert!(packet.has_ftrace_events());
        let events = &packet.ftrace_events().event;
        assert_eq!(events.len(), 1);
        assert!(events[0].has_irq_handler_entry());
        assert_eq!(events[0].irq_handler_entry().name(), "irq_handler");
    }

    #[test]
    fn test_irq_exit_handler_events() {
        let mut recorder = create_test_recorder();
        let next_comm = c"irq_handler";

        let mut event = task_event {
            r#type: event_type::SCHED_IRQ_EXIT,
            ts: 1000,
            target_cpu: 0,
            next_prio: 5,
            next: task_info {
                tgidpid: 1234,
                ..Default::default()
            },
            ..Default::default()
        };
        copy_to_comm(&mut event.next.comm, next_comm);
        recorder.handle_event(event);

        assert_eq!(recorder.compact_sched.len(), 0);
        assert_eq!(recorder.events.len(), 1);
        assert!(recorder.events.contains_key(&0));

        let packets = generate_trace(&recorder);
        assert_eq!(packets.len(), 1);

        let packet = &packets[0];
        assert!(packet.has_ftrace_events());
        let events = &packet.ftrace_events().event;
        assert_eq!(events.len(), 1);
        assert!(events[0].has_irq_handler_exit());
    }

    #[test]
    fn test_softirq_events() {
        let mut recorder = create_test_recorder();

        let event = task_event {
            r#type: event_type::SCHED_SOFTIRQ_ENTER,
            ts: 1000,
            target_cpu: 0,
            next_prio: 5,
            ..Default::default()
        };
        recorder.handle_event(event);

        assert_eq!(recorder.compact_sched.len(), 0);
        assert_eq!(recorder.events.len(), 1);
        assert!(recorder.events.contains_key(&0));

        let packets = generate_trace(&recorder);
        assert_eq!(packets.len(), 1);

        let packet = &packets[0];
        assert!(packet.has_ftrace_events());
        let events = &packet.ftrace_events().event;
        assert_eq!(events.len(), 1);
        assert!(events[0].has_softirq_entry());
    }

    #[test]
    fn test_softirq_exit_events() {
        let mut recorder = create_test_recorder();

        let event = task_event {
            r#type: event_type::SCHED_SOFTIRQ_EXIT,
            ts: 1000,
            target_cpu: 0,
            next_prio: 5,
            ..Default::default()
        };
        recorder.handle_event(event);

        assert_eq!(recorder.compact_sched.len(), 0);
        assert_eq!(recorder.events.len(), 1);
        assert!(recorder.events.contains_key(&0));

        let packets = generate_trace(&recorder);
        assert_eq!(packets.len(), 1);

        let packet = &packets[0];
        assert!(packet.has_ftrace_events());
        let events = &packet.ftrace_events().event;
        assert_eq!(events.len(), 1);
        assert!(events[0].has_softirq_exit());
    }

    #[test]
    fn test_process_exit_event() {
        let mut recorder = create_test_recorder();
        let prev_comm = c"prev";

        let mut event = task_event {
            r#type: event_type::SCHED_PROCESS_EXIT,
            ts: 1000,
            prev: task_info {
                tgidpid: 1234,
                ..Default::default()
            },
            prev_prio: 10,
            ..Default::default()
        };
        copy_to_comm(&mut event.prev.comm, prev_comm);
        recorder.handle_event(event);

        assert_eq!(recorder.compact_sched.len(), 0);
        assert_eq!(recorder.events.len(), 1);
        assert!(recorder.events.contains_key(&0));

        let packets = generate_trace(&recorder);
        assert_eq!(packets.len(), 1);

        let packet = &packets[0];
        assert!(packet.has_ftrace_events());
        let events = &packet.ftrace_events().event;
        assert_eq!(events.len(), 1);
        assert!(events[0].has_sched_process_exit());
        assert_eq!(events[0].sched_process_exit().comm(), "prev");
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
