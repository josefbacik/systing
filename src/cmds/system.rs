use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::CStr;
use std::io;
use std::mem;
use std::mem::MaybeUninit;
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::events::{PerfCounters, PerfHwEvent};
use crate::symbolize::Stack;
use crate::syscall;
use crate::SystemOpts;

use anyhow::Result;
use blazesym::symbolize::{Input, Kernel, Process, Source, Sym, Symbolized, Symbolizer};
use blazesym::Pid;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::AsRawLibbpf;
use libbpf_rs::{ErrorExt, Link, MapCore, RingBufferBuilder, UsdtOpts};
use libbpf_sys;
use libc;
use perfetto_protos::builtin_clock::BuiltinClock;
use perfetto_protos::clock_snapshot::clock_snapshot::Clock;
use perfetto_protos::clock_snapshot::ClockSnapshot;
use perfetto_protos::counter_descriptor::counter_descriptor::Unit;
use perfetto_protos::counter_descriptor::CounterDescriptor;
use perfetto_protos::ftrace_event::FtraceEvent;
use perfetto_protos::ftrace_event_bundle::ftrace_event_bundle::CompactSched;
use perfetto_protos::ftrace_event_bundle::FtraceEventBundle;
use perfetto_protos::interned_data::InternedData;
use perfetto_protos::irq::{
    IrqHandlerEntryFtraceEvent, IrqHandlerExitFtraceEvent, SoftirqEntryFtraceEvent,
    SoftirqExitFtraceEvent,
};
use perfetto_protos::process_descriptor::ProcessDescriptor;
use perfetto_protos::profile_common::{Callstack, Frame, InternedString, Mapping};
use perfetto_protos::profile_packet::PerfSample;
use perfetto_protos::sched::{SchedProcessExitFtraceEvent, SchedWakeupNewFtraceEvent};
use perfetto_protos::thread_descriptor::ThreadDescriptor;
use perfetto_protos::trace::Trace;
use perfetto_protos::trace_packet::trace_packet::SequenceFlags;
use perfetto_protos::trace_packet::TracePacket;
use perfetto_protos::track_descriptor::TrackDescriptor;
use perfetto_protos::track_event::track_event::Type;
use perfetto_protos::track_event::TrackEvent;
use rand::RngCore;
use sysinfo::System;

use plain::Plain;
use protobuf::Message;

mod systing {
    include!(concat!(env!("OUT_DIR"), "/systing_system.skel.rs"));
}

use systing::types::event_type;
use systing::types::perf_counter_event;
use systing::types::stack_event;
use systing::types::task_event;
use systing::types::task_info;
use systing::types::usdt_event;

unsafe impl Plain for task_event {}
unsafe impl Plain for usdt_event {}
unsafe impl Plain for stack_event {}
unsafe impl Plain for perf_counter_event {}

struct TrackCounter {
    ts: u64,
    count: i64,
}

struct TrackInstant {
    ts: u64,
    name: String,
}

#[derive(Clone)]
struct StackEvent {
    tgidpid: u64,
    ts_start: u64,
    stack: Stack,
}

#[derive(Default)]
struct LocalFrame {
    frame: Frame,
    mapping: Mapping,
}

#[derive(Default)]
struct LocalCompactSched {
    compact_sched: CompactSched,
    comm_mapping: HashMap<String, u32>,
    last_waking_ts: u64,
    last_switch_ts: u64,
}

#[derive(Clone)]
struct UsdtProbe {
    cookie: u64,
    path: String,
    provider: String,
    name: String,
}

#[derive(Default)]
struct EventRecorder {
    clock_snapshot: ClockSnapshot,
    events: HashMap<u32, BTreeMap<u64, FtraceEvent>>,
    compact_sched: HashMap<u32, LocalCompactSched>,
    threads: HashMap<u64, ThreadDescriptor>,
    processes: HashMap<u64, ProcessDescriptor>,
    runqueue: HashMap<i32, Vec<TrackCounter>>,
    cpu_latencies: HashMap<u32, Vec<TrackCounter>>,
    process_latencies: HashMap<u64, Vec<TrackCounter>>,
    rq_counters: HashMap<i32, i64>,
    cpu_sched_stats: bool,
    process_sched_stats: bool,
}

#[derive(Default)]
struct UsdtRecorder {
    usdt_cookies: HashMap<u64, UsdtProbe>,
    usdt_events: HashMap<u64, Vec<TrackInstant>>,
}

#[derive(Default)]
struct StackRecorder {
    stacks: HashMap<i32, Vec<StackEvent>>,
}

#[derive(Default, PartialEq, Eq, Hash)]
struct PerfCounterKey {
    tgidpid: u64,
    cookie: u64,
}

#[derive(Default)]
struct PerfCounterRecorder {
    perf_cookies: HashMap<u64, PerfHwEvent>,
    perf_events: HashMap<PerfCounterKey, Vec<TrackCounter>>,
}

#[derive(Default)]
struct SysinfoRecorder {
    frequency: HashMap<u32, Vec<TrackCounter>>,
}

#[derive(Default)]
struct SessionRecorder {
    event_recorder: Mutex<EventRecorder>,
    usdt_recorder: Mutex<UsdtRecorder>,
    stack_recorder: Mutex<StackRecorder>,
    perf_counter_recorder: Mutex<PerfCounterRecorder>,
    sysinfo_recorder: Mutex<SysinfoRecorder>,
}

fn get_clock_value(clock_id: libc::c_int) -> u64 {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(clock_id, &mut ts) } != 0 {
        return 0;
    }
    (ts.tv_sec as u64 * 1_000_000_000) + ts.tv_nsec as u64
}

fn stack_to_frames_mapping<'a, I>(
    symbolizer: &mut Symbolizer,
    frame_map: &mut HashMap<u64, LocalFrame>,
    func_map: &mut HashMap<String, InternedString>,
    source: &Source<'a>,
    rng: &mut dyn rand::RngCore,
    stack: I,
) where
    I: IntoIterator<Item = &'a u64>,
{
    for input_addr in stack {
        if frame_map.contains_key(input_addr) {
            continue;
        }

        match symbolizer.symbolize_single(source, Input::AbsAddr(*input_addr)) {
            Ok(Symbolized::Sym(Sym {
                addr, name, offset, ..
            })) => {
                let mut frame = Frame::default();
                let my_func = func_map.entry(name.to_string()).or_insert_with(|| {
                    let mut interned_str = InternedString::default();
                    interned_str.set_iid(rng.next_u64());
                    interned_str.set_str(name.to_string().into_bytes());
                    interned_str
                });
                frame.set_iid(rng.next_u64());
                frame.set_function_name_id(my_func.iid());
                frame.set_rel_pc(offset as u64);

                let mut mapping = Mapping::default();
                mapping.set_iid(rng.next_u64());
                mapping.set_exact_offset(*input_addr);
                mapping.set_start_offset(addr);

                frame.set_mapping_id(mapping.iid());
                let frame = LocalFrame { frame, mapping };
                frame_map.insert(*input_addr, frame);
            }
            _ => {
                let name = format!("<unknown>");
                let mut frame = Frame::default();
                let my_func = func_map.entry(name.to_string()).or_insert_with(|| {
                    let mut interned_str = InternedString::default();
                    interned_str.set_iid(rng.next_u64());
                    interned_str.set_str(name.into_bytes());
                    interned_str
                });
                frame.set_iid(rng.next_u64());
                frame.set_function_name_id(my_func.iid());
                frame.set_rel_pc(0);

                let mut mapping = Mapping::default();
                mapping.set_iid(rng.next_u64());
                mapping.set_exact_offset(*input_addr);
                mapping.set_start_offset(0);

                frame.set_mapping_id(mapping.iid());
                let frame = LocalFrame { frame, mapping };
                frame_map.insert(*input_addr, frame);
            }
        }
    }
}

fn generate_pidtgid_track_descriptor(
    pid_uuids: &HashMap<i32, u64>,
    thread_uuids: &HashMap<i32, u64>,
    tgidpid: &u64,
    name: String,
    desc_uuid: u64,
) -> TracePacket {
    let pid = *tgidpid as i32;
    let tgid = (*tgidpid >> 32) as i32;

    let uuid = if pid == tgid {
        *pid_uuids.get(&tgid).unwrap()
    } else {
        *thread_uuids.get(&pid).unwrap()
    };

    let mut desc = TrackDescriptor::default();
    desc.set_name(name);
    desc.set_uuid(desc_uuid);
    desc.set_parent_uuid(uuid);

    let mut counter_desc = CounterDescriptor::default();
    counter_desc.set_unit(Unit::UNIT_COUNT);
    counter_desc.set_is_incremental(false);
    desc.counter = Some(counter_desc).into();

    let mut packet = TracePacket::default();
    packet.set_track_descriptor(desc);
    packet
}

impl From<task_info> for ProcessDescriptor {
    fn from(task: task_info) -> Self {
        let comm = CStr::from_bytes_until_nul(&task.comm).unwrap();
        let mut process = ProcessDescriptor::default();
        process.set_pid(task.tgidpid as i32);
        process.set_process_name(comm.to_str().unwrap().to_string());
        process
    }
}

impl From<task_info> for ThreadDescriptor {
    fn from(task: task_info) -> Self {
        let comm = CStr::from_bytes_until_nul(&task.comm).unwrap();
        let mut thread = ThreadDescriptor::default();
        thread.set_tid(task.tgidpid as i32);
        thread.set_pid((task.tgidpid >> 32) as i32);
        thread.set_thread_name(comm.to_str().unwrap().to_string());
        thread
    }
}

trait TaskEventBuilder {
    fn from_task_event(event: &task_event) -> Self;
}

impl TaskEventBuilder for FtraceEvent {
    fn from_task_event(event: &task_event) -> Self {
        let mut ftrace_event = FtraceEvent::default();
        ftrace_event.set_pid(event.prev.tgidpid as u32);
        ftrace_event.set_timestamp(event.ts);
        match event.r#type {
            event_type::SCHED_WAKEUP_NEW => {
                ftrace_event
                    .set_sched_wakeup_new(SchedWakeupNewFtraceEvent::from_task_event(event));
            }
            event_type::SCHED_IRQ_EXIT => {
                ftrace_event
                    .set_irq_handler_exit(IrqHandlerExitFtraceEvent::from_task_event(event));
            }
            event_type::SCHED_IRQ_ENTER => {
                ftrace_event
                    .set_irq_handler_entry(IrqHandlerEntryFtraceEvent::from_task_event(event));
            }
            event_type::SCHED_SOFTIRQ_EXIT => {
                ftrace_event.set_softirq_exit(SoftirqExitFtraceEvent::from_task_event(event));
            }
            event_type::SCHED_SOFTIRQ_ENTER => {
                ftrace_event.set_softirq_entry(SoftirqEntryFtraceEvent::from_task_event(event));
            }
            event_type::SCHED_PROCESS_EXIT => {
                ftrace_event
                    .set_sched_process_exit(SchedProcessExitFtraceEvent::from_task_event(event));
            }
            _ => {}
        }
        ftrace_event
    }
}

impl TaskEventBuilder for SchedWakeupNewFtraceEvent {
    fn from_task_event(event: &task_event) -> Self {
        let comm_cstr = CStr::from_bytes_until_nul(&event.next.comm).unwrap();
        let mut sched_wakeup_new = SchedWakeupNewFtraceEvent::default();
        sched_wakeup_new.set_pid(event.next.tgidpid as i32);
        sched_wakeup_new.set_comm(comm_cstr.to_str().unwrap().to_string());
        sched_wakeup_new.set_prio(event.next_prio as i32);
        sched_wakeup_new.set_target_cpu(event.target_cpu as i32);
        sched_wakeup_new
    }
}

impl TaskEventBuilder for IrqHandlerExitFtraceEvent {
    fn from_task_event(event: &task_event) -> Self {
        let mut irq_handler_exit = IrqHandlerExitFtraceEvent::default();
        irq_handler_exit.set_irq(event.target_cpu as i32);
        irq_handler_exit.set_ret(event.next_prio as i32);
        irq_handler_exit
    }
}

impl TaskEventBuilder for IrqHandlerEntryFtraceEvent {
    fn from_task_event(event: &task_event) -> Self {
        let mut irq_handler_entry = IrqHandlerEntryFtraceEvent::default();
        let name_cstr = CStr::from_bytes_until_nul(&event.prev.comm).unwrap();
        irq_handler_entry.set_name(name_cstr.to_str().unwrap().to_string());
        irq_handler_entry.set_irq(event.target_cpu as i32);
        irq_handler_entry
    }
}

impl TaskEventBuilder for SoftirqExitFtraceEvent {
    fn from_task_event(event: &task_event) -> Self {
        let mut softirq_exit = SoftirqExitFtraceEvent::default();
        softirq_exit.set_vec(event.target_cpu);
        softirq_exit
    }
}

impl TaskEventBuilder for SoftirqEntryFtraceEvent {
    fn from_task_event(event: &task_event) -> Self {
        let mut softirq_entry = SoftirqEntryFtraceEvent::default();
        softirq_entry.set_vec(event.target_cpu);
        softirq_entry
    }
}

impl TaskEventBuilder for SchedProcessExitFtraceEvent {
    fn from_task_event(event: &task_event) -> Self {
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

impl TrackCounter {
    fn to_track_event(&self, track_uuid: u64, seq: u32) -> TracePacket {
        let mut packet = TracePacket::default();
        let mut track_event = TrackEvent::default();
        track_event.set_type(Type::TYPE_COUNTER);
        track_event.set_counter_value(self.count);
        track_event.set_track_uuid(track_uuid);

        packet.set_track_event(track_event);
        packet.set_timestamp(self.ts);
        packet.set_trusted_packet_sequence_id(seq);
        packet
    }
}

impl LocalCompactSched {
    fn add_task_event(&mut self, event: &task_event) {
        let comm = CStr::from_bytes_until_nul(&event.next.comm)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let index = self.comm_mapping.entry(comm.clone()).or_insert({
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

impl EventRecorder {
    fn record_event(&mut self, event: &task_event) {
        // SCHED_SWITCH and SCHED_WAKING are handled in compact sched events.
        // We skip SCHED_WAKEUP because we're just using that for runqueue tracking.
        if event.r#type == event_type::SCHED_SWITCH || event.r#type == event_type::SCHED_WAKING {
            let compact_sched = self
                .compact_sched
                .entry(event.cpu)
                .or_insert_with(LocalCompactSched::default);
            compact_sched.add_task_event(event);
        } else if event.r#type != event_type::SCHED_WAKEUP {
            let ftrace_event = FtraceEvent::from_task_event(&event);
            let cpu_event = self.events.entry(event.cpu).or_insert_with(BTreeMap::new);
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
            let rq = self.runqueue.entry(cpu).or_insert_with(Vec::new);
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
            let lat = self.cpu_latencies.entry(cpu).or_insert_with(Vec::new);
            let plat = self
                .process_latencies
                .entry(event.next.tgidpid)
                .or_insert_with(Vec::new);

            plat.push(TrackCounter {
                ts: event.ts,
                count: event.latency as i64,
            });

            lat.push(TrackCounter {
                ts: event.ts,
                count: event.latency as i64,
            });
        }

        if event.r#type == event_type::SCHED_SOFTIRQ_EXIT
            || event.r#type == event_type::SCHED_IRQ_EXIT
            || event.r#type == event_type::SCHED_IRQ_ENTER
            || event.r#type == event_type::SCHED_SOFTIRQ_ENTER
        {
            return;
        }

        let tgid = (event.prev.tgidpid >> 32) as i32;
        let pid = event.prev.tgidpid as i32;
        if pid == tgid {
            if !self.processes.contains_key(&event.prev.tgidpid) {
                self.processes
                    .insert(event.prev.tgidpid, ProcessDescriptor::from(event.prev));
            }
        } else {
            if !self.threads.contains_key(&event.prev.tgidpid) {
                self.threads
                    .insert(event.prev.tgidpid, ThreadDescriptor::from(event.prev));
            }
        }

        if event.r#type == event_type::SCHED_PROCESS_EXIT {
            return;
        }

        let pid = event.next.tgidpid as i32;
        let tgid = (event.next.tgidpid >> 32) as i32;
        if pid == tgid {
            if !self.processes.contains_key(&event.next.tgidpid) {
                self.processes
                    .insert(event.next.tgidpid, ProcessDescriptor::from(event.next));
            }
        } else {
            if !self.threads.contains_key(&event.next.tgidpid) {
                self.threads
                    .insert(event.next.tgidpid, ThreadDescriptor::from(event.next));
            }
        }
    }

    fn generate_trace(
        &self,
        pid_uuids: &mut HashMap<i32, u64>,
        thread_uuids: &mut HashMap<i32, u64>,
        rng: &mut dyn rand::RngCore,
    ) -> Vec<TracePacket> {
        let mut packets = Vec::new();

        // First emit the clock snapshot
        let mut packet = TracePacket::default();
        packet.set_clock_snapshot(self.clock_snapshot.clone());
        packet.set_trusted_packet_sequence_id(rng.next_u32());
        packets.push(packet);

        // Ppopulate all the process tracks
        for (_, process) in self.processes.iter() {
            let uuid = rng.next_u64();
            pid_uuids.insert(process.pid(), uuid);

            let mut desc = TrackDescriptor::default();
            desc.set_uuid(uuid);
            desc.process = Some(process.clone()).into();

            let mut packet = TracePacket::default();
            packet.set_track_descriptor(desc);
            packets.push(packet);
        }

        for (_, thread) in self.threads.iter() {
            let uuid = rng.next_u64();
            thread_uuids.insert(thread.tid(), uuid);

            let mut desc = TrackDescriptor::default();
            desc.set_uuid(uuid);
            desc.thread = Some(thread.clone()).into();

            let mut packet = TracePacket::default();
            packet.set_track_descriptor(desc);
            packets.push(packet);
        }

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
            let desc_uuid = rng.next_u64();

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

            let seq = rng.next_u32();
            for event in runqueue.iter() {
                packets.push(event.to_track_event(desc_uuid, seq));
            }
        }

        // Populate the per-cpu latencies
        for (cpu, events) in self.cpu_latencies.iter() {
            let desc_uuid = rng.next_u64();

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

            let seq = rng.next_u32();
            for event in events.iter() {
                packets.push(event.to_track_event(desc_uuid, seq));
            }
        }

        // Populate the per-process latencies
        for (pidtgid, events) in self.process_latencies.iter() {
            let desc_uuid = rng.next_u64();
            packets.push(generate_pidtgid_track_descriptor(
                pid_uuids,
                thread_uuids,
                pidtgid,
                "Wake latency".to_string(),
                desc_uuid,
            ));

            let seq = rng.next_u32();
            for event in events.iter() {
                packets.push(event.to_track_event(desc_uuid, seq));
            }
        }
        packets
    }

    fn snapshot_clocks(&mut self) {
        self.clock_snapshot
            .set_primary_trace_clock(BuiltinClock::BUILTIN_CLOCK_BOOTTIME);

        let mut clock = Clock::default();
        clock.set_clock_id(BuiltinClock::BUILTIN_CLOCK_MONOTONIC as u32);
        clock.set_timestamp(get_clock_value(libc::CLOCK_MONOTONIC));
        self.clock_snapshot.clocks.push(clock);

        let mut clock = Clock::default();
        clock.set_clock_id(BuiltinClock::BUILTIN_CLOCK_BOOTTIME as u32);
        clock.set_timestamp(get_clock_value(libc::CLOCK_BOOTTIME));
        self.clock_snapshot.clocks.push(clock);

        let mut clock = Clock::default();
        clock.set_clock_id(BuiltinClock::BUILTIN_CLOCK_REALTIME as u32);
        clock.set_timestamp(get_clock_value(libc::CLOCK_REALTIME));
        self.clock_snapshot.clocks.push(clock);

        let mut clock = Clock::default();
        clock.set_clock_id(BuiltinClock::BUILTIN_CLOCK_REALTIME_COARSE as u32);
        clock.set_timestamp(get_clock_value(libc::CLOCK_REALTIME_COARSE));
        self.clock_snapshot.clocks.push(clock);

        let mut clock = Clock::default();
        clock.set_clock_id(BuiltinClock::BUILTIN_CLOCK_MONOTONIC_COARSE as u32);
        clock.set_timestamp(get_clock_value(libc::CLOCK_MONOTONIC_COARSE));
        self.clock_snapshot.clocks.push(clock);

        let mut clock = Clock::default();
        clock.set_clock_id(BuiltinClock::BUILTIN_CLOCK_MONOTONIC_RAW as u32);
        clock.set_timestamp(get_clock_value(libc::CLOCK_MONOTONIC_RAW));
        self.clock_snapshot.clocks.push(clock);
    }
}

impl StackRecorder {
    fn record_stack_event(&mut self, event: &stack_event) {
        if event.user_stack_length > 0 || event.kernel_stack_length > 0 {
            let kstack_vec = Vec::from(&event.kernel_stack[..event.kernel_stack_length as usize]);
            let ustack_vec = Vec::from(&event.user_stack[..event.user_stack_length as usize]);
            let stack_key = (event.task.tgidpid >> 32) as i32;
            let stack = StackEvent {
                tgidpid: event.task.tgidpid,
                ts_start: event.ts,
                stack: Stack::new(&kstack_vec, &ustack_vec),
            };
            let stacks = self.stacks.entry(stack_key).or_insert_with(Vec::new);
            stacks.push(stack);
        }
    }

    fn generate_trace(&self, rng: &mut dyn rand::RngCore) -> Vec<TracePacket> {
        let mut packets = Vec::new();

        // Resolve the stacks, generate the interned data for them, and populate the trace.
        let mut src_cache: HashMap<i32, Source> = HashMap::new();
        let kernel_src = Source::Kernel(Kernel::default());
        let mut symbolizer = Symbolizer::new();

        for (tgid, stacks) in self.stacks.iter() {
            let user_src = src_cache
                .entry(*tgid)
                .or_insert(Source::Process(Process::new(Pid::from(*tgid as u32))));

            // We have to symbolize all of the addresses in the stacks and fill
            // out the hashmap with all of the frames.
            let mut frame_map = HashMap::new();
            let mut func_name_map = HashMap::new();
            for stack in stacks.iter() {
                let raw_stack = &stack.stack;
                stack_to_frames_mapping(
                    &mut symbolizer,
                    &mut frame_map,
                    &mut func_name_map,
                    &user_src,
                    rng,
                    raw_stack.user_stack.iter(),
                );
                stack_to_frames_mapping(
                    &mut symbolizer,
                    &mut frame_map,
                    &mut func_name_map,
                    &kernel_src,
                    rng,
                    raw_stack.kernel_stack.iter(),
                );
            }

            // Collect into a HashSet to dedup the stacks, and then iterate that to symbolize the
            // stacks and generate the interned data.
            let interned_stacks: HashMap<Stack, Callstack> = stacks
                .iter()
                .map(|stack| stack.stack.clone())
                .collect::<HashSet<_>>()
                .into_iter()
                .map(|stack| {
                    let mut callstack = Callstack::default();
                    callstack.set_iid(rng.next_u64());
                    callstack.frame_ids = stack
                        .user_stack
                        .iter()
                        .chain(stack.kernel_stack.iter())
                        .map(|addr| {
                            let frame = frame_map.get(&addr).unwrap();
                            frame.frame.iid()
                        })
                        .collect();
                    (stack, callstack)
                })
                .collect();

            let seq = rng.next_u32();
            let mut packet = TracePacket::default();
            let mut interned_data = InternedData::default();
            interned_data.callstacks = interned_stacks.values().cloned().collect();
            interned_data.function_names = func_name_map.values().cloned().collect();
            interned_data.frames = frame_map
                .values()
                .map(|frame| frame.frame.clone())
                .collect();
            interned_data.mappings = frame_map
                .values()
                .map(|frame| frame.mapping.clone())
                .collect();
            packet.interned_data = Some(interned_data).into();
            packet.set_trusted_packet_sequence_id(seq);
            packet.set_sequence_flags(
                SequenceFlags::SEQ_INCREMENTAL_STATE_CLEARED as u32
                    | SequenceFlags::SEQ_NEEDS_INCREMENTAL_STATE as u32,
            );
            packets.push(packet);

            for stack in stacks.iter() {
                let pid = stack.tgidpid as u32;
                let tgid = (stack.tgidpid >> 32) as u32;
                let mut packet = TracePacket::default();
                packet.set_timestamp(stack.ts_start);

                let mut sample = PerfSample::default();
                sample.set_callstack_iid(interned_stacks.get(&stack.stack).unwrap().iid());
                sample.set_pid(tgid);
                sample.set_tid(pid);
                packet.set_perf_sample(sample);
                packet.set_trusted_packet_sequence_id(seq);
                packets.push(packet);
            }
        }
        packets
    }
}

impl UsdtRecorder {
    fn record_usdt_event(&mut self, event: &usdt_event) {
        let mut extra = "".to_string();

        // Capture arg0 if there is one.
        match event.arg_type {
            systing::types::usdt_arg_type::ARG_LONG => {
                let mut bytes: [u8; 8] = [0; 8];
                let _ = bytes.copy_from_bytes(&event.usdt_arg0[..8]);
                let val = u64::from_ne_bytes(bytes);
                extra = format!(":{}", val);
            }
            systing::types::usdt_arg_type::ARG_STRING => {
                let arg0_str = CStr::from_bytes_until_nul(&event.usdt_arg0);
                if !arg0_str.is_err() {
                    let arg0_str = arg0_str.unwrap();
                    let bytes = arg0_str.to_bytes();
                    if bytes.len() > 0 && !bytes.starts_with(&[0]) {
                        extra = format!(":{}", arg0_str.to_string_lossy());
                    }
                }
            }
            _ => {}
        }

        let usdt = self.usdt_cookies.get(&event.cookie).unwrap();
        let entry = self
            .usdt_events
            .entry(event.task.tgidpid)
            .or_insert_with(Vec::new);
        entry.push(TrackInstant {
            ts: event.ts,
            name: format!("{}:{}:{}{}", usdt.path, usdt.provider, usdt.name, extra),
        });
    }

    fn generate_trace(
        &self,
        pid_uuids: &HashMap<i32, u64>,
        thread_uuids: &HashMap<i32, u64>,
        rng: &mut dyn rand::RngCore,
    ) -> Vec<TracePacket> {
        let mut packets = Vec::new();

        // Populate the USDT events
        for (pidtgid, events) in self.usdt_events.iter() {
            let desc_uuid = rng.next_u64();
            packets.push(generate_pidtgid_track_descriptor(
                pid_uuids,
                thread_uuids,
                pidtgid,
                "USDT events".to_string(),
                desc_uuid,
            ));

            let seq = rng.next_u32();
            for event in events.iter() {
                let mut tevent = TrackEvent::default();
                tevent.set_type(Type::TYPE_INSTANT);
                tevent.set_name(event.name.clone());
                tevent.set_track_uuid(desc_uuid);

                let mut packet = TracePacket::default();
                packet.set_timestamp(event.ts);
                packet.set_track_event(tevent);
                packet.set_trusted_packet_sequence_id(seq);
                packets.push(packet);
            }
        }
        packets
    }
}

impl PerfCounterRecorder {
    fn record_perf_counter_event(&mut self, event: &perf_counter_event) {
        let key = PerfCounterKey {
            tgidpid: event.task.tgidpid,
            cookie: event.cookie,
        };
        let entry = self.perf_events.entry(key).or_insert_with(Vec::new);
        entry.push(TrackCounter {
            ts: event.ts,
            count: event.value as i64,
        });
    }

    fn generate_trace(
        &self,
        pid_uuids: &HashMap<i32, u64>,
        thread_uuids: &HashMap<i32, u64>,
        rng: &mut dyn rand::RngCore,
    ) -> Vec<TracePacket> {
        let mut packets = Vec::new();

        // Populate the cache counter events
        for (key, counters) in self.perf_events.iter() {
            let desc_uuid = rng.next_u64();
            let track_name = self.perf_cookies.get(&key.cookie).unwrap().name.clone();
            packets.push(generate_pidtgid_track_descriptor(
                pid_uuids,
                thread_uuids,
                &key.tgidpid,
                track_name,
                desc_uuid,
            ));

            let seq = rng.next_u32();
            for event in counters.iter() {
                packets.push(event.to_track_event(desc_uuid, seq));
            }
        }

        packets
    }
}

impl SysinfoRecorder {
    fn record_cpu_frequency(&mut self, sys: &System) {
        let ts = get_clock_value(libc::CLOCK_BOOTTIME);
        for (i, cpu) in sys.cpus().iter().enumerate() {
            let freq = self.frequency.entry(i as u32).or_insert_with(Vec::new);
            freq.push(TrackCounter {
                ts,
                count: cpu.frequency() as i64,
            });
        }
    }

    fn generate_trace(&self, rng: &mut dyn rand::RngCore) -> Vec<TracePacket> {
        let mut packets = Vec::new();

        // Populate the sysinfo events
        for (cpu, events) in self.frequency.iter() {
            let desc_uuid = rng.next_u64();

            let mut counter_desc = CounterDescriptor::default();
            counter_desc.set_unit(Unit::UNIT_COUNT);
            counter_desc.set_is_incremental(false);

            let mut desc = TrackDescriptor::default();
            desc.set_name(format!("CPU {} frequency", cpu).to_string());
            desc.set_uuid(desc_uuid);
            desc.counter = Some(counter_desc).into();

            let mut packet = TracePacket::default();
            packet.set_track_descriptor(desc);
            packets.push(packet);

            let seq = rng.next_u32();
            for event in events.iter() {
                packets.push(event.to_track_event(desc_uuid, seq));
            }
        }
        packets
    }
}

fn create_ring<'a, T>(
    map: &dyn libbpf_rs::MapCore,
    tx: Sender<T>,
) -> Result<libbpf_rs::RingBuffer<'a>, libbpf_rs::Error>
where
    T: Default + Plain + 'a,
{
    let mut builder = RingBufferBuilder::new();
    builder.add(map, move |data: &[u8]| {
        let mut event = T::default();
        plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");
        tx.send(event).expect("Could not send event on channel.");
        0
    })?;
    builder.build()
}

fn init_perf_monitor(freq: u64, hwevent: &PerfHwEvent) -> Result<Vec<i32>, libbpf_rs::Error> {
    let nprocs = libbpf_rs::num_possible_cpus().unwrap() as u32;
    let buf: Vec<u8> = vec![0; mem::size_of::<syscall::perf_event_attr>()];
    let mut attr = unsafe {
        Box::<syscall::perf_event_attr>::from_raw(
            buf.leak().as_mut_ptr() as *mut syscall::perf_event_attr
        )
    };
    attr._type = hwevent.event_type;
    attr.size = mem::size_of::<syscall::perf_event_attr>() as u32;
    attr.config = hwevent.event_config;
    attr.sample.sample_freq = freq;
    attr.flags = 1 << 10; // freq = 1i
    let mut pidfds = Vec::new();
    let cpus = if hwevent.cpus.is_empty() {
        (0..nprocs).collect::<Vec<u32>>()
    } else {
        hwevent.cpus.clone()
    };
    for cpu in cpus {
        let fd = syscall::perf_event_open(attr.as_ref(), -1, cpu as i32, -1, 0) as i32;
        if fd == -1 {
            let os_error = io::Error::last_os_error();
            let mut error_context = "Failed to open perf event.";

            if let Some(libc::ENODEV) = os_error.raw_os_error() {
                // Sometimes available cpus < num_cpus, so we just break here.
                break;
            }

            if os_error.kind() == io::ErrorKind::NotFound {
                error_context = "Failed to open perf event.\n\
                                Try running the profile example with the `--sw-event` option.";
            }
            return Err(libbpf_rs::Error::from(os_error)).context(error_context);
        }
        pidfds.push(fd);
    }
    Ok(pidfds)
}

// We're just doing this until the libbpf-rs crate gets updated with my patch.
trait LibbpfPerfOptions {
    fn attach_perf_event_with_opts(
        &self,
        pefd: i32,
        cookie: u64,
    ) -> Result<libbpf_rs::Link, libbpf_rs::Error>;
}

impl LibbpfPerfOptions for libbpf_rs::ProgramMut<'_> {
    fn attach_perf_event_with_opts(
        &self,
        pefd: i32,
        cookie: u64,
    ) -> Result<libbpf_rs::Link, libbpf_rs::Error> {
        let mut opts = libbpf_sys::bpf_perf_event_opts::default();
        opts.bpf_cookie = cookie;
        opts.sz = mem::size_of::<libbpf_sys::bpf_perf_event_opts>() as u64;
        let ptr = unsafe {
            libbpf_sys::bpf_program__attach_perf_event_opts(
                self.as_libbpf_object().as_ptr(),
                pefd,
                &opts as *const _ as *const _,
            )
        };
        let ret = unsafe { libbpf_sys::libbpf_get_error(ptr as *const _) };
        if ret != 0 {
            return Err(libbpf_rs::Error::from_raw_os_error(-ret as i32));
        }
        let ptr = unsafe { std::ptr::NonNull::new_unchecked(ptr) };
        let link = unsafe { Link::from_ptr(ptr) };
        Ok(link)
    }
}

fn attach_perf_event(
    pefds: &[i32],
    prog: &libbpf_rs::ProgramMut,
    cookie: u64,
) -> Vec<Result<libbpf_rs::Link, libbpf_rs::Error>> {
    pefds
        .iter()
        .map(|pefd| prog.attach_perf_event_with_opts(*pefd, cookie))
        .collect()
}

fn dump_missed_events(skel: &systing::SystingSystemSkel, index: u32) -> u64 {
    let index = index.to_ne_bytes();
    let result = skel
        .maps
        .missed_events
        .lookup_percpu(&index, libbpf_rs::MapFlags::ANY);
    let mut missed = 0;
    match result {
        Ok(results) => {
            for val in results.unwrap() {
                let mut missed_events: u64 = 0;
                plain::copy_from_bytes(&mut missed_events, &val).unwrap();
                missed += missed_events;
            }
        }
        _ => {}
    }
    missed
}

pub fn system(opts: SystemOpts) -> Result<()> {
    let record_perf_events = opts.perf_counter.len() > 0;

    let mut counters = PerfCounters::new();
    if record_perf_events {
        counters.discover()?;
    }

    for event in counters.events() {
        let mut first: i32 = -1;
        let mut last = 0;
        let mut cpustring = String::new();
        for cpu in event.cpus.iter() {
            if first == -1 {
                first = *cpu as i32;
            } else if *cpu != last + 1 {
                cpustring += &format!("{}-{},", first, last);
                first = *cpu as i32;
            }
            last = *cpu;
        }
        cpustring += &format!("{}-{}", first, last);
        println!(
            "Event: {}, type {}, config {:#x}, cpus {}",
            event.name, event.event_type, event.event_config, cpustring
        );
    }
    let recorder = Arc::new(SessionRecorder::default());
    recorder.event_recorder.lock().unwrap().snapshot_clocks();
    {
        let mut skel_builder = systing::SystingSystemSkelBuilder::default();
        if opts.verbose {
            skel_builder.obj_builder.debug(true);
        }

        let mut open_object = MaybeUninit::uninit();
        let mut open_skel = skel_builder.open(&mut open_object)?;

        if opts.cgroup.len() > 0 {
            open_skel.maps.rodata_data.tool_config.filter_cgroup = 1;
        }
        if opts.no_stack_traces {
            open_skel.maps.rodata_data.tool_config.no_stack_traces = 1;
        }
        if opts.pid.len() > 0 {
            open_skel.maps.rodata_data.tool_config.filter_pid = 1;
        }
        if opts.ringbuf_size_mib > 0 {
            let size = opts.ringbuf_size_mib * 1024 * 1024;
            let object = open_skel.open_object_mut();
            for mut map in object.maps_mut() {
                let name = map.name().to_str().unwrap();
                if name.starts_with("node") {
                    map.set_max_entries(size)?;
                }
            }
        }
        if opts.process_sched_stats {
            recorder.event_recorder.lock().unwrap().process_sched_stats = true;
        }
        if opts.cpu_sched_stats {
            recorder.event_recorder.lock().unwrap().cpu_sched_stats = true;
        }

        let mut rng = rand::rng();
        let mut usdts: Vec<UsdtProbe> = Vec::new();
        for tracepoint in opts.trace_event.iter() {
            let parts = tracepoint.split(':').collect::<Vec<&str>>();
            match parts[0] {
                "usdt" => {
                    if parts.len() != 4 {
                        Err(anyhow::anyhow!("Invalid USDT probe format"))?;
                    }
                    let usdt = UsdtProbe {
                        cookie: rng.next_u64(),
                        path: parts[1].to_string(),
                        provider: parts[2].to_string(),
                        name: parts[3].to_string(),
                    };
                    usdts.push(usdt.clone());
                    recorder
                        .usdt_recorder
                        .lock()
                        .unwrap()
                        .usdt_cookies
                        .insert(usdt.cookie, usdt);
                }
                _ => {
                    Err(anyhow::anyhow!("Invalid probe type"))?;
                }
            }
        }

        if usdts.len() > 0 && opts.trace_event_pid.len() == 0 {
            Err(anyhow::anyhow!("USDT probes require a PID to attach to"))?;
        }

        let mut perf_counters = Vec::new();
        for counter in opts.perf_counter.iter() {
            let hwevent = counters.events().find(|e| e.name == *counter);
            if hwevent.is_none() {
                Err(anyhow::anyhow!("Invalid perf counter"))?;
            }
            let cookie = rng.next_u64();
            recorder
                .perf_counter_recorder
                .lock()
                .unwrap()
                .perf_cookies
                .insert(cookie, hwevent.unwrap().clone());
            perf_counters.push((cookie, hwevent.unwrap().clone()));
        }

        let nr_cpus = thread::available_parallelism()?.get() as u32;
        open_skel.maps.missed_events.set_max_entries(nr_cpus)?;

        let mut skel = open_skel.load()?;
        for cgroup in opts.cgroup.iter() {
            let metadata = std::fs::metadata(cgroup)?;
            let cgroupid = metadata.ino().to_ne_bytes();
            let val = (1 as u8).to_ne_bytes();
            skel.maps
                .cgroups
                .update(&cgroupid, &val, libbpf_rs::MapFlags::ANY)?;
        }

        for pid in opts.pid.iter() {
            let val = (1 as u8).to_ne_bytes();
            skel.maps
                .pids
                .update(&pid.to_ne_bytes(), &val, libbpf_rs::MapFlags::ANY)?;
        }

        let mut rings = Vec::new();
        let (event_tx, event_rx) = channel();
        let (usdt_tx, usdt_rx) = channel();
        let (stack_tx, stack_rx) = channel();
        let (cache_tx, cache_rx) = channel();

        let object = skel.object();
        for (i, map) in object.maps().enumerate() {
            let name = map.name().to_str().unwrap();
            if name.starts_with("ringbuf_events") {
                let ring = create_ring::<task_event>(&map, event_tx.clone())?;
                rings.push((format!("events_{}", i).to_string(), ring));
            } else if name.starts_with("ringbuf_usdt") {
                let ring = create_ring::<usdt_event>(&map, usdt_tx.clone())?;
                rings.push((name.to_string(), ring));
            } else if name.starts_with("ringbuf_stack") {
                let ring = create_ring::<stack_event>(&map, stack_tx.clone())?;
                rings.push((name.to_string(), ring));
            } else if name.starts_with("ringbuf_perf_counter") {
                if record_perf_events {
                    let ring = create_ring::<perf_counter_event>(&map, cache_tx.clone())?;
                    rings.push((name.to_string(), ring));
                }
            }
        }

        // Drop the extra tx references
        drop(event_tx);
        drop(usdt_tx);
        drop(stack_tx);
        drop(cache_tx);

        let mut recv_threads = Vec::new();
        let session_recorder = recorder.clone();
        recv_threads.push(
            thread::Builder::new()
                .name("sched_recorder".to_string())
                .spawn(move || {
                    loop {
                        let res = event_rx.recv();
                        if res.is_err() {
                            break;
                        }
                        let event = res.unwrap();
                        session_recorder
                            .event_recorder
                            .lock()
                            .unwrap()
                            .record_event(&event);
                    }
                    0
                })?,
        );
        let session_recorder = recorder.clone();
        recv_threads.push(
            thread::Builder::new()
                .name("usdt_recorder".to_string())
                .spawn(move || {
                    loop {
                        let res = usdt_rx.recv();
                        if res.is_err() {
                            break;
                        }
                        let event = res.unwrap();
                        session_recorder
                            .usdt_recorder
                            .lock()
                            .unwrap()
                            .record_usdt_event(&event);
                    }
                    0
                })?,
        );
        let session_recorder = recorder.clone();
        recv_threads.push(
            thread::Builder::new()
                .name("stack_recorder".to_string())
                .spawn(move || {
                    loop {
                        let res = stack_rx.recv();
                        if res.is_err() {
                            break;
                        }
                        let event = res.unwrap();
                        session_recorder
                            .stack_recorder
                            .lock()
                            .unwrap()
                            .record_stack_event(&event);
                    }
                    0
                })?,
        );
        if record_perf_events {
            let session_recorder = recorder.clone();
            recv_threads.push(
                thread::Builder::new()
                    .name("perf_counter_recorder".to_string())
                    .spawn(move || {
                        loop {
                            let res = cache_rx.recv();
                            if res.is_err() {
                                break;
                            }
                            let event = res.unwrap();
                            session_recorder
                                .perf_counter_recorder
                                .lock()
                                .unwrap()
                                .record_perf_counter_event(&event);
                        }
                        0
                    })?,
            );
        } else {
            drop(cache_rx);
        }

        let mut perf_fds = Vec::new();
        let mut perf_links = Vec::new();
        for (cookie, hwevent) in perf_counters {
            let pefds = init_perf_monitor(1000, &hwevent)?;
            let links = attach_perf_event(&pefds, &skel.progs.systing_perf_event_counter, cookie);
            perf_fds.extend(pefds);
            perf_links.extend(links);
        }
        skel.attach()?;

        // Attach any usdt's that we may have
        let mut usdt_links = Vec::new();
        for usdt in usdts {
            for pid in opts.trace_event_pid.iter() {
                let link = skel.progs.systing_usdt.attach_usdt_with_opts(
                    *pid as i32,
                    &usdt.path,
                    &usdt.provider,
                    &usdt.name,
                    UsdtOpts {
                        cookie: usdt.cookie,
                        ..Default::default()
                    },
                );
                if link.is_err() {
                    Err(anyhow::anyhow!("Failed to connect pid {}", *pid))?;
                }
                usdt_links.push(link);
            }
        }

        let mut threads = Vec::new();
        let thread_done = Arc::new(AtomicBool::new(false));
        for (name, ring) in rings {
            let thread_done_clone = thread_done.clone();
            threads.push(thread::Builder::new().name(name).spawn(move || {
                loop {
                    if thread_done_clone.load(Ordering::Relaxed) {
                        // Flush whatever is left in the ringbuf
                        let _ = ring.consume();
                        break;
                    }
                    let res = ring.poll(Duration::from_millis(100));
                    if res.is_err() {
                        break;
                    }
                }
                0
            })?);
        }

        // Start the sysinfo recorder if it's enabled
        if opts.cpu_frequency {
            let thread_done_clone = thread_done.clone();
            let sysinfo_recorder = recorder.clone();
            threads.push(
                thread::Builder::new()
                    .name("sysinfo_recorder".to_string())
                    .spawn(move || {
                        let mut sys = sysinfo::System::new_with_specifics(
                            sysinfo::RefreshKind::nothing()
                                .with_cpu(sysinfo::CpuRefreshKind::nothing().with_frequency()),
                        );

                        loop {
                            if thread_done_clone.load(Ordering::Relaxed) {
                                break;
                            }
                            sys.refresh_cpu_frequency();
                            sysinfo_recorder
                                .sysinfo_recorder
                                .lock()
                                .unwrap()
                                .record_cpu_frequency(&sys);
                            thread::sleep(Duration::from_millis(100));
                        }
                        0
                    })?,
            );
        }

        if opts.duration > 0 {
            thread::sleep(Duration::from_secs(opts.duration));
        } else {
            let (tx, rx) = channel();
            ctrlc::set_handler(move || tx.send(()).expect("Could not send signal on channel."))
                .expect("Error setting Ctrl-C handler");
            println!("Press Ctrl-C to stop");
            rx.recv().expect("Could not receive signal on channel.");
        }

        println!("Stopping...");
        skel.maps.data_data.tracing_enabled = false;
        thread_done.store(true, Ordering::Relaxed);
        for thread in threads {
            thread.join().expect("Failed to join thread");
        }
        println!("Stopping receiver threads...");
        for thread in recv_threads {
            thread.join().expect("Failed to join receiver thread");
        }

        println!("Missed sched events: {}", dump_missed_events(&skel, 0));
        println!("Missed stack events: {}", dump_missed_events(&skel, 1));
        println!("Missed USDT events: {}", dump_missed_events(&skel, 2));
        if record_perf_events {
            println!("Missed cache events: {}", dump_missed_events(&skel, 3));
        }
    }

    println!("Generating trace...");
    let mut trace = Trace::default();
    let mut pid_uuids = HashMap::new();
    let mut thread_uuids = HashMap::new();
    let mut rng = rand::rng();
    trace
        .packet
        .extend(recorder.event_recorder.lock().unwrap().generate_trace(
            &mut pid_uuids,
            &mut thread_uuids,
            &mut rng,
        ));
    trace.packet.extend(
        recorder
            .stack_recorder
            .lock()
            .unwrap()
            .generate_trace(&mut rng),
    );
    trace
        .packet
        .extend(recorder.usdt_recorder.lock().unwrap().generate_trace(
            &pid_uuids,
            &thread_uuids,
            &mut rng,
        ));
    trace.packet.extend(
        recorder
            .perf_counter_recorder
            .lock()
            .unwrap()
            .generate_trace(&pid_uuids, &thread_uuids, &mut rng),
    );
    trace.packet.extend(
        recorder
            .sysinfo_recorder
            .lock()
            .unwrap()
            .generate_trace(&mut rng),
    );
    let mut file = std::fs::File::create("trace.pb")?;
    trace.write_to_writer(&mut file)?;
    Ok(())
}
