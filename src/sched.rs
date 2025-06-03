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
    cpu_sched_stats: bool,
    process_sched_stats: bool,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::systing::types::event_type;
    use crate::systing::types::task_info;

    fn copy_to_comm(comm: &mut [u8], value: &CStr) {
        let bytes = value.to_bytes_with_nul();
        comm[..bytes.len()].copy_from_slice(bytes);
    }

    #[test]
    fn test_handle_event() {
        let mut recorder = SchedEventRecorder::default();
        let prev_comm = CStr::from_bytes_with_nul(b"prev\0").unwrap();
        let next_comm = CStr::from_bytes_with_nul(b"next\0").unwrap();

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
        copy_to_comm(&mut event.next.comm, &next_comm);
        copy_to_comm(&mut event.prev.comm, &prev_comm);
        recorder.handle_event(event);
        assert_eq!(recorder.compact_sched.len(), 1);
        assert!(recorder.compact_sched.contains_key(&0));

        event.ts = 2000;
        event.next.tgidpid = 5678;
        event.prev.tgidpid = 1234;
        copy_to_comm(&mut event.next.comm, &prev_comm);
        copy_to_comm(&mut event.prev.comm, &next_comm);
        recorder.handle_event(event);

        assert_eq!(recorder.compact_sched.len(), 1);

        let mut thread_uuids = HashMap::new();
        thread_uuids.insert(1234, 1);
        thread_uuids.insert(5678, 2);
        let packets = recorder.generate_trace(
            &HashMap::new(),
            &thread_uuids,
            &mut Arc::new(AtomicUsize::new(0)),
        );
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
        let mut recorder = SchedEventRecorder::default();
        let next_comm = CStr::from_bytes_with_nul(b"next\0").unwrap();

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
        copy_to_comm(&mut event.next.comm, &next_comm);
        recorder.handle_event(event);

        assert_eq!(recorder.compact_sched.len(), 0);
        assert_eq!(recorder.events.len(), 1);
        assert!(recorder.events.contains_key(&0));

        let mut thread_uuids = HashMap::new();
        thread_uuids.insert(1234, 1);
        let packets = recorder.generate_trace(
            &HashMap::new(),
            &thread_uuids,
            &mut Arc::new(AtomicUsize::new(0)),
        );
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
        let mut recorder = SchedEventRecorder::default();
        let next_comm = CStr::from_bytes_with_nul(b"irq_handler\0").unwrap();

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
        copy_to_comm(&mut event.next.comm, &next_comm);
        recorder.handle_event(event);

        assert_eq!(recorder.compact_sched.len(), 0);
        assert_eq!(recorder.events.len(), 1);
        assert!(recorder.events.contains_key(&0));

        let mut thread_uuids = HashMap::new();
        thread_uuids.insert(1234, 1);
        let packets = recorder.generate_trace(
            &HashMap::new(),
            &thread_uuids,
            &mut Arc::new(AtomicUsize::new(0)),
        );
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
        let mut recorder = SchedEventRecorder::default();
        let next_comm = CStr::from_bytes_with_nul(b"irq_handler\0").unwrap();

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
        copy_to_comm(&mut event.next.comm, &next_comm);
        recorder.handle_event(event);

        assert_eq!(recorder.compact_sched.len(), 0);
        assert_eq!(recorder.events.len(), 1);
        assert!(recorder.events.contains_key(&0));

        let mut thread_uuids = HashMap::new();
        thread_uuids.insert(1234, 1);
        let packets = recorder.generate_trace(
            &HashMap::new(),
            &thread_uuids,
            &mut Arc::new(AtomicUsize::new(0)),
        );
        assert_eq!(packets.len(), 1);

        let packet = &packets[0];
        assert!(packet.has_ftrace_events());
        let events = &packet.ftrace_events().event;
        assert_eq!(events.len(), 1);
        assert!(events[0].has_irq_handler_exit());
    }

    #[test]
    fn test_softirq_events() {
        let mut recorder = SchedEventRecorder::default();

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

        let packets = recorder.generate_trace(
            &HashMap::new(),
            &HashMap::new(),
            &mut Arc::new(AtomicUsize::new(0)),
        );
        assert_eq!(packets.len(), 1);

        let packet = &packets[0];
        assert!(packet.has_ftrace_events());
        let events = &packet.ftrace_events().event;
        assert_eq!(events.len(), 1);
        assert!(events[0].has_softirq_entry());
    }

    #[test]
    fn test_softirq_exit_events() {
        let mut recorder = SchedEventRecorder::default();

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

        let packets = recorder.generate_trace(
            &HashMap::new(),
            &HashMap::new(),
            &mut Arc::new(AtomicUsize::new(0)),
        );
        assert_eq!(packets.len(), 1);

        let packet = &packets[0];
        assert!(packet.has_ftrace_events());
        let events = &packet.ftrace_events().event;
        assert_eq!(events.len(), 1);
        assert!(events[0].has_softirq_exit());
    }

    #[test]
    fn test_process_exit_event() {
        let mut recorder = SchedEventRecorder::default();
        let prev_comm = CStr::from_bytes_with_nul(b"prev\0").unwrap();

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
        copy_to_comm(&mut event.prev.comm, &prev_comm);
        recorder.handle_event(event);

        assert_eq!(recorder.compact_sched.len(), 0);
        assert_eq!(recorder.events.len(), 1);
        assert!(recorder.events.contains_key(&0));

        let mut thread_uuids = HashMap::new();
        thread_uuids.insert(1234, 1);
        let packets = recorder.generate_trace(
            &HashMap::new(),
            &thread_uuids,
            &mut Arc::new(AtomicUsize::new(0)),
        );
        assert_eq!(packets.len(), 1);

        let packet = &packets[0];
        assert!(packet.has_ftrace_events());
        let events = &packet.ftrace_events().event;
        assert_eq!(events.len(), 1);
        assert!(events[0].has_sched_process_exit());
        assert_eq!(events[0].sched_process_exit().comm(), "prev");
    }

    #[test]
    fn test_runqueue_size_tracking() {
        let mut recorder = SchedEventRecorder::default();
        recorder.set_cpu_sched_stats(true);

        let event = task_event {
            r#type: event_type::SCHED_WAKEUP,
            ts: 1000,
            target_cpu: 0,
            next: task_info {
                tgidpid: 1234,
                ..Default::default()
            },
            next_prio: 10,
            ..Default::default()
        };
        recorder.handle_event(event);

        let packets = recorder.generate_trace(
            &HashMap::new(),
            &HashMap::new(),
            &mut Arc::new(AtomicUsize::new(0)),
        );
        assert_eq!(packets.len(), 2);
        assert!(packets[0].has_track_descriptor());
    }

    #[test]
    fn test_process_latency_tracking() {
        let mut recorder = SchedEventRecorder::default();
        recorder.set_process_sched_stats(true);

        let event = task_event {
            r#type: event_type::SCHED_SWITCH,
            ts: 1000,
            cpu: 0,
            next: task_info {
                tgidpid: 1234,
                ..Default::default()
            },
            prev: task_info {
                tgidpid: 5678,
                ..Default::default()
            },
            latency: 500,
            next_prio: 10,
            prev_state: 0,
            ..Default::default()
        };
        recorder.handle_event(event);

        let mut thread_uuids = HashMap::new();
        thread_uuids.insert(1234, 1);

        let packets = recorder.generate_trace(
            &HashMap::new(),
            &thread_uuids,
            &mut Arc::new(AtomicUsize::new(0)),
        );
        assert_eq!(packets.len(), 5);
        assert!(packets[0].has_ftrace_events());
        assert!(packets[1].has_track_descriptor());
        assert_eq!(packets[2].track_event().counter_value(), 500);
        assert!(packets[3].has_track_descriptor());
        assert_eq!(packets[4].track_event().counter_value(), 500);
    }
}
