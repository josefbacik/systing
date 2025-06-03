use std::collections::{BTreeMap, HashMap};
use std::ffi::CStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::perfetto::TrackCounter;
use crate::ringbuf::RingBuffer;
use crate::systing::types::event_type;
use crate::systing::types::task_event;

use perfetto_protos::counter_descriptor::counter_descriptor::Unit;
use perfetto_protos::counter_descriptor::CounterDescriptor;
use perfetto_protos::ftrace_event::FtraceEvent;
use perfetto_protos::ftrace_event_bundle::ftrace_event_bundle::CompactSched;
use perfetto_protos::ftrace_event_bundle::FtraceEventBundle;
use perfetto_protos::irq::{
    IrqHandlerEntryFtraceEvent, IrqHandlerExitFtraceEvent, SoftirqEntryFtraceEvent,
    SoftirqExitFtraceEvent,
};
use perfetto_protos::sched::{SchedProcessExitFtraceEvent, SchedWakeupNewFtraceEvent};
use perfetto_protos::trace_packet::TracePacket;
use perfetto_protos::track_descriptor::TrackDescriptor;

#[derive(Default)]
struct LocalCompactSched {
    compact_sched: CompactSched,
    comm_mapping: HashMap<String, u32>,
    last_waking_ts: u64,
    last_switch_ts: u64,
}

#[derive(Default)]
pub struct SchedEventRecorder {
    pub ringbuf: RingBuffer<task_event>,
    events: HashMap<u32, BTreeMap<u64, FtraceEvent>>,
    compact_sched: HashMap<u32, LocalCompactSched>,
    runqueue: HashMap<i32, Vec<TrackCounter>>,
    cpu_latencies: HashMap<u32, Vec<TrackCounter>>,
    process_latencies: HashMap<u64, Vec<TrackCounter>>,
    rq_counters: HashMap<i32, i64>,
    pub cpu_sched_stats: bool,
    pub process_sched_stats: bool,
}

impl SchedEventRecorder {
    pub fn handle_event(&mut self, event: task_event) {
        // SCHED_SWITCH and SCHED_WAKING are handled in compact sched events.
        // We skip SCHED_WAKEUP because we're just using that for runqueue tracking.
        if event.r#type == event_type::SCHED_SWITCH || event.r#type == event_type::SCHED_WAKING {
            let compact_sched = self.compact_sched.entry(event.cpu).or_default();
            compact_sched.add_task_event(&event);
        } else if event.r#type != event_type::SCHED_WAKEUP {
            let ftrace_event = FtraceEvent::from(&event);
            let cpu_event = self.events.entry(event.cpu).or_default();
            cpu_event.insert(event.ts, ftrace_event);
        }

        // We want to keep a running count of the per-cpu runqueue size. We could do this
        // inside of BPF, but that's a map lookup and runnning counter, so we'll just keep the
        // complexity here instead of adding it to the BPF hook.
        if self.cpu_sched_stats
            && (event.r#type == event_type::SCHED_SWITCH
                || event.r#type == event_type::SCHED_WAKEUP
                || event.r#type == event_type::SCHED_WAKEUP_NEW)
        {
            let cpu = if event.r#type == event_type::SCHED_SWITCH {
                event.cpu as i32
            } else {
                event.target_cpu as i32
            };
            let rq = self.runqueue.entry(cpu).or_default();
            let count = self.rq_counters.entry(cpu).or_insert(0);

            if event.r#type == event_type::SCHED_SWITCH {
                // If we haven't seen a wakeup event yet we could have a runqueue size of 0, so
                // we need to make sure we don't go negative.
                if *count > 0 {
                    *count -= 1;
                }
            } else {
                *count += 1;
            }

            rq.push(TrackCounter {
                ts: event.ts,
                count: *count,
            });
        }

        // SCHED_SWITCH is going to have latency for this CPU and TGIDPID
        if self.process_sched_stats && event.r#type == event_type::SCHED_SWITCH && event.latency > 0
        {
            let cpu = event.cpu;
            let lat = self.cpu_latencies.entry(cpu).or_default();
            let plat = self
                .process_latencies
                .entry(event.next.tgidpid)
                .or_default();

            plat.push(TrackCounter {
                ts: event.ts,
                count: event.latency as i64,
            });

            lat.push(TrackCounter {
                ts: event.ts,
                count: event.latency as i64,
            });
        }
    }

    pub fn drain_ringbuf(&mut self) {
        while let Some(event) = self.ringbuf.pop_back() {
            self.handle_event(event);
        }
    }

    pub fn generate_trace(
        &self,
        pid_uuids: &HashMap<i32, u64>,
        thread_uuids: &HashMap<i32, u64>,
        id_counter: &mut Arc<AtomicUsize>,
    ) -> Vec<TracePacket> {
        let mut packets = Vec::new();

        // Pull all the compact scheduling events
        for (cpu, compact_sched) in self.compact_sched.iter() {
            let mut event_bundle = FtraceEventBundle::default();
            event_bundle.set_cpu(*cpu);
            event_bundle.compact_sched = Some(compact_sched.compact_sched.clone()).into();
            let mut packet = TracePacket::default();
            packet.set_ftrace_events(event_bundle);
            packets.push(packet);
        }

        // Pull all the scheduling events.
        for (cpu, events) in self.events.iter() {
            let mut event_bundle = FtraceEventBundle::default();
            event_bundle.set_cpu(*cpu);
            event_bundle.event = events.values().cloned().collect();
            let mut packet = TracePacket::default();
            packet.set_ftrace_events(event_bundle);
            packets.push(packet);
        }

        // Populate the per-cpu runqueue sizes
        for (cpu, runqueue) in self.runqueue.iter() {
            let desc_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;

            let mut counter_desc = CounterDescriptor::default();
            counter_desc.set_unit(Unit::UNIT_COUNT);
            counter_desc.set_is_incremental(false);

            let mut desc = TrackDescriptor::default();
            desc.set_name(format!("runqueue_size_cpu{}", cpu));
            desc.set_uuid(desc_uuid);
            desc.counter = Some(counter_desc).into();

            let mut packet = TracePacket::default();
            packet.set_track_descriptor(desc);
            packets.push(packet);

            let seq = id_counter.fetch_add(1, Ordering::Relaxed) as u32;
            for event in runqueue.iter() {
                packets.push(event.to_track_event(desc_uuid, seq));
            }
        }

        // Populate the per-cpu latencies
        for (cpu, events) in self.cpu_latencies.iter() {
            let desc_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;

            let mut counter_desc = CounterDescriptor::default();
            counter_desc.set_unit(Unit::UNIT_TIME_NS);
            counter_desc.set_is_incremental(false);

            let mut desc = TrackDescriptor::default();
            desc.set_name(format!("latency_cpu{}", cpu));
            desc.set_uuid(desc_uuid);
            desc.counter = Some(counter_desc).into();

            let mut packet = TracePacket::default();
            packet.set_track_descriptor(desc);
            packets.push(packet);

            let seq = id_counter.fetch_add(1, Ordering::Relaxed) as u32;
            for event in events.iter() {
                packets.push(event.to_track_event(desc_uuid, seq));
            }
        }

        // Populate the per-process latencies
        for (pidtgid, events) in self.process_latencies.iter() {
            let desc_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;

            let mut counter_desc = CounterDescriptor::default();
            counter_desc.set_unit(Unit::UNIT_TIME_NS);
            counter_desc.set_is_incremental(false);

            let mut desc = crate::perfetto::generate_pidtgid_track_descriptor(
                pid_uuids,
                thread_uuids,
                pidtgid,
                "Wake latency".to_string(),
                desc_uuid,
            );
            desc.counter = Some(counter_desc).into();

            let mut packet = TracePacket::default();
            packet.set_track_descriptor(desc);
            packets.push(packet);

            let seq = id_counter.fetch_add(1, Ordering::Relaxed) as u32;
            for event in events.iter() {
                packets.push(event.to_track_event(desc_uuid, seq));
            }
        }
        packets
    }

    pub fn set_cpu_sched_stats(&mut self, enabled: bool) {
        self.cpu_sched_stats = enabled;
    }

    pub fn set_process_sched_stats(&mut self, enabled: bool) {
        self.process_sched_stats = enabled;
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
