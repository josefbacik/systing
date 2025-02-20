use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::CStr;
use std::io::Write;
use std::mem::MaybeUninit;
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::symbolize::{Stack, SymbolizerCache};
use crate::SystemOpts;

use anyhow::Result;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{MapCore, RingBufferBuilder};
use perfetto_protos::counter_descriptor::counter_descriptor::Unit;
use perfetto_protos::counter_descriptor::CounterDescriptor;
use perfetto_protos::ftrace_event::FtraceEvent;
use perfetto_protos::ftrace_event_bundle::FtraceEventBundle;
use perfetto_protos::interned_data::InternedData;
use perfetto_protos::process_descriptor::ProcessDescriptor;
use perfetto_protos::process_tree::process_tree::{Process, Thread};
use perfetto_protos::process_tree::ProcessTree;
use perfetto_protos::profile_common::InternedString;
use perfetto_protos::sched::{
    SchedSwitchFtraceEvent, SchedWakeupNewFtraceEvent, SchedWakingFtraceEvent,
};
use perfetto_protos::thread_descriptor::ThreadDescriptor;
use perfetto_protos::trace::Trace;
use perfetto_protos::trace_packet::TracePacket;
use perfetto_protos::track_descriptor::TrackDescriptor;
use perfetto_protos::track_event::track_event::Type;
use perfetto_protos::track_event::TrackEvent;
use rand::RngCore;

use plain::Plain;
use protobuf::Message;

mod systing {
    include!(concat!(env!("OUT_DIR"), "/systing_system.skel.rs"));
}

unsafe impl Plain for systing::types::task_event {}

struct TrackCounter {
    ts: u64,
    count: i64,
}

#[derive(Clone)]
struct SleepStack {
    pid: i32,
    ts_start: u64,
    ts_end: u64,
    stack: Stack,
}

struct LocalInternedString {
    iid: u64,
    val: String,
}

#[derive(Default)]
struct EventRecorder<'a> {
    events: HashMap<u32, BTreeMap<u64, FtraceEvent>>,
    threads: HashMap<u64, Thread>,
    processes: HashMap<u64, Process>,
    sleepers: HashMap<i32, Vec<SleepStack>>,
    pending_wakeups: HashMap<u64, SleepStack>,
    runqueue: HashMap<i32, Vec<TrackCounter>>,
    cpu_latencies: HashMap<u32, Vec<TrackCounter>>,
    process_latencies: HashMap<u64, Vec<TrackCounter>>,
    rq_counters: HashMap<i32, i64>,
    symbolizer: SymbolizerCache<'a>,
    pids: HashSet<i32>,
    last_ts: u64,
}

fn generate_interned_data<'a, I>(iter: I) -> Vec<TracePacket>
where
    I: IntoIterator<Item = &'a LocalInternedString>,
{
    let mut packets = Vec::new();
    for local_is in iter {
        let mut interned_data = InternedData::default();
        let mut interned_string = InternedString::default();
        interned_string.set_iid(local_is.iid);
        interned_string.set_str(local_is.val.clone().into_bytes());
        interned_data.function_names = vec![interned_string].into();
        let mut packet = TracePacket::default();
        packet.interned_data = Some(interned_data).into();
        packets.push(packet);
    }
    packets
}

fn generate_thread_track_descriptor(pidtgid: u64, uuid: u64, name: String) -> TrackDescriptor {
    let pid = pidtgid as i32;
    let tgid = (pidtgid >> 32) as i32;

    let mut desc = TrackDescriptor::default();
    desc.set_name(name);
    desc.set_uuid(uuid);

    let mut thread_desc = ThreadDescriptor::default();
    thread_desc.set_pid(tgid);
    thread_desc.set_tid(pid);
    desc.thread = Some(thread_desc).into();

    desc
}

trait TaskEventBuilder {
    fn from_task_event(event: &systing::types::task_event) -> Self;
}

impl TaskEventBuilder for FtraceEvent {
    fn from_task_event(event: &systing::types::task_event) -> Self {
        let mut ftrace_event = FtraceEvent::default();
        ftrace_event.set_pid(event.prev_tgidpid as u32);
        ftrace_event.set_timestamp(event.ts);
        match event.r#type {
            systing::types::event_type::SCHED_SWITCH => {
                ftrace_event.set_sched_switch(SchedSwitchFtraceEvent::from_task_event(event));
            }
            systing::types::event_type::SCHED_WAKING => {
                ftrace_event.set_sched_waking(SchedWakingFtraceEvent::from_task_event(event));
            }
            systing::types::event_type::SCHED_WAKEUP_NEW => {
                ftrace_event
                    .set_sched_wakeup_new(SchedWakeupNewFtraceEvent::from_task_event(event));
            }
            _ => {}
        }
        ftrace_event
    }
}

impl TaskEventBuilder for SchedSwitchFtraceEvent {
    fn from_task_event(event: &systing::types::task_event) -> Self {
        let prev_comm_cstr = CStr::from_bytes_until_nul(&event.prev_comm).unwrap();
        let next_comm_cstr = CStr::from_bytes_until_nul(&event.next_comm).unwrap();
        let mut sched_switch = SchedSwitchFtraceEvent::default();
        sched_switch.set_prev_pid(event.prev_tgidpid as i32);
        sched_switch.set_next_pid(event.next_tgidpid as i32);
        sched_switch.set_prev_comm(prev_comm_cstr.to_str().unwrap().to_string());
        sched_switch.set_next_comm(next_comm_cstr.to_str().unwrap().to_string());
        sched_switch.set_prev_prio(event.prev_prio as i32);
        sched_switch.set_next_prio(event.next_prio as i32);
        sched_switch.set_prev_state(event.prev_state as i64);
        sched_switch
    }
}

impl TaskEventBuilder for SchedWakingFtraceEvent {
    fn from_task_event(event: &systing::types::task_event) -> Self {
        let comm_cstr = CStr::from_bytes_until_nul(&event.next_comm).unwrap();
        let mut sched_waking = SchedWakingFtraceEvent::default();
        sched_waking.set_pid(event.next_tgidpid as i32);
        sched_waking.set_comm(comm_cstr.to_str().unwrap().to_string());
        sched_waking.set_prio(event.next_prio as i32);
        sched_waking.set_target_cpu(event.target_cpu as i32);
        sched_waking
    }
}

impl TaskEventBuilder for SchedWakeupNewFtraceEvent {
    fn from_task_event(event: &systing::types::task_event) -> Self {
        let comm_cstr = CStr::from_bytes_until_nul(&event.next_comm).unwrap();
        let mut sched_wakeup_new = SchedWakeupNewFtraceEvent::default();
        sched_wakeup_new.set_pid(event.next_tgidpid as i32);
        sched_wakeup_new.set_comm(comm_cstr.to_str().unwrap().to_string());
        sched_wakeup_new.set_prio(event.next_prio as i32);
        sched_wakeup_new.set_target_cpu(event.target_cpu as i32);
        sched_wakeup_new
    }
}

impl TrackCounter {
    fn to_track_event(&self, track_uuid: u64, seq: u32) -> TracePacket {
        let mut packet = TracePacket::default();
        let mut track_event = TrackEvent::default();
        track_event.set_timestamp_absolute_us((self.ts / 1000) as i64);
        track_event.set_type(Type::TYPE_COUNTER);
        track_event.set_counter_value(self.count);
        track_event.set_track_uuid(track_uuid);

        packet.set_track_event(track_event);
        packet.set_timestamp(self.ts);
        packet.set_trusted_packet_sequence_id(seq);
        packet
    }
}

impl SleepStack {
    fn start_track_event(&self, iid: u64, track_uuid: u64) -> TrackEvent {
        let mut track_event = TrackEvent::default();
        track_event.set_timestamp_absolute_us((self.ts_start / 1000) as i64);
        track_event.set_type(Type::TYPE_SLICE_BEGIN);
        track_event.set_track_uuid(track_uuid);
        track_event.set_name_iid(iid);
        track_event
    }

    fn end_track_event(&self, track_uuid: u64) -> TrackEvent {
        let mut track_event = TrackEvent::default();
        track_event.set_timestamp_absolute_us((self.ts_end / 1000) as i64);
        track_event.set_type(Type::TYPE_SLICE_END);
        track_event.set_track_uuid(track_uuid);
        track_event
    }

    fn to_trace_packets(&self, iid: u64, track_uuid: u64, seq: u32) -> Vec<TracePacket> {
        let mut packets = Vec::new();

        let mut packet = TracePacket::default();
        packet.set_timestamp(self.ts_start);
        packet.set_track_event(self.start_track_event(iid, track_uuid));
        packet.set_trusted_packet_sequence_id(seq);
        packets.push(packet);

        let mut packet = TracePacket::default();
        packet.set_timestamp(self.ts_end);
        packet.set_track_event(self.end_track_event(track_uuid));
        packet.set_trusted_packet_sequence_id(seq);
        packets.push(packet);
        packets
    }
}

impl<'a> EventRecorder<'a> {
    fn record_event(&mut self, event: &systing::types::task_event) {
        // We don't want to track wakeup events, they're not interesting for this analysis.
        if event.r#type != systing::types::event_type::SCHED_WAKEUP {
            let ftrace_event = FtraceEvent::from_task_event(&event);
            let cpu_event = self.events.entry(event.cpu).or_insert_with(BTreeMap::new);
            cpu_event.insert(event.ts, ftrace_event);
        }

        if event.user_stack_length > 0 || event.kernel_stack_length > 0 {
            let kstack_vec = Vec::from(&event.kernel_stack[..event.kernel_stack_length as usize]);
            let ustack_vec = Vec::from(&event.user_stack[..event.user_stack_length as usize]);
            let stack_key = event.prev_tgidpid;
            let stack = SleepStack {
                pid: event.prev_tgidpid as i32,
                ts_start: event.ts,
                ts_end: 0,
                stack: Stack::new(&kstack_vec, &ustack_vec),
            };
            self.pending_wakeups.insert(stack_key, stack);
        }

        // We want to keep a running count of the per-cpu runqueue size. We could do this
        // inside of BPF, but that's a map lookup and runnning counter, so we'll just keep the
        // complexity here instead of adding it to the BPF hook.
        if event.r#type == systing::types::event_type::SCHED_SWITCH
            || event.r#type == systing::types::event_type::SCHED_WAKEUP
            || event.r#type == systing::types::event_type::SCHED_WAKEUP_NEW
        {
            let cpu = if event.r#type == systing::types::event_type::SCHED_SWITCH {
                event.cpu as i32
            } else {
                event.target_cpu as i32
            };
            let rq = self.runqueue.entry(cpu).or_insert_with(Vec::new);
            let count = self.rq_counters.entry(cpu).or_insert(0);

            if event.r#type == systing::types::event_type::SCHED_SWITCH {
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
        if event.r#type == systing::types::event_type::SCHED_SWITCH && event.latency > 0 {
            let cpu = event.cpu;
            let lat = self.cpu_latencies.entry(cpu).or_insert_with(Vec::new);
            let plat = self
                .process_latencies
                .entry(event.next_tgidpid)
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

        let tgid = (event.prev_tgidpid >> 32) as i32;
        let pid = event.prev_tgidpid as i32;
        if pid != tgid {
            if !self.threads.contains_key(&event.prev_tgidpid) {
                let thread_entry = self
                    .threads
                    .entry(event.prev_tgidpid)
                    .or_insert_with(Thread::default);
                let comm = CStr::from_bytes_until_nul(&event.prev_comm).unwrap();
                thread_entry.set_tid(pid);
                thread_entry.set_tgid(tgid);
                thread_entry.set_name(comm.to_str().unwrap().to_string());
            }
        }

        if !self.processes.contains_key(&event.prev_tgidpid) {
            let process_entry = self
                .processes
                .entry(event.prev_tgidpid)
                .or_insert_with(Process::default);
            process_entry.set_pid(tgid);
        }

        let pid = event.next_tgidpid as i32;
        let tgid = (event.next_tgidpid >> 32) as i32;
        if pid != tgid {
            if !self.threads.contains_key(&event.next_tgidpid) {
                let thread_entry = self
                    .threads
                    .entry(event.next_tgidpid)
                    .or_insert_with(Thread::default);
                let comm = CStr::from_bytes_until_nul(&event.next_comm).unwrap();
                thread_entry.set_tid(pid);
                thread_entry.set_tgid(tgid);
                thread_entry.set_name(comm.to_str().unwrap().to_string());
            }
        }

        if !self.processes.contains_key(&event.next_tgidpid) {
            let process_entry = self
                .processes
                .entry(event.next_tgidpid)
                .or_insert_with(Process::default);
            process_entry.set_pid(tgid);
        }

        if self.pending_wakeups.contains_key(&event.next_tgidpid) {
            let mut stack = self.pending_wakeups.remove(&event.next_tgidpid).unwrap();
            let stacks = self.sleepers.entry(stack.pid).or_insert_with(Vec::new);
            stack.ts_end = event.ts;
            stacks.push(stack);
        }
        self.last_ts = event.ts;
    }

    fn wake_all_pending_wakeups(&mut self) {
        for (_, stack) in self.pending_wakeups.iter_mut() {
            let stacks = self.sleepers.entry(stack.pid).or_insert_with(Vec::new);
            stack.ts_end = self.last_ts;
            stacks.push(stack.clone());
        }
        self.pending_wakeups.clear();
    }

    fn generate_trace(&mut self) -> Trace {
        let mut trace = Trace::default();
        let mut rng = rand::rng();

        // Pull all the threads and populate the processes
        let mut process_tree = ProcessTree::default();
        process_tree.threads = self.threads.values().cloned().collect();
        process_tree.processes = self.processes.values().cloned().collect();
        for process in process_tree.processes.iter_mut() {
            crate::perfetto::profetto_fill_process(process);
        }
        let mut packet = TracePacket::default();
        packet.set_process_tree(process_tree);
        trace.packet.push(packet);

        // Pull all the scheduling events.
        for (cpu, events) in self.events.iter() {
            let mut event_bundle = FtraceEventBundle::default();
            event_bundle.set_cpu(*cpu);
            event_bundle.event = events.values().cloned().collect();
            let mut packet = TracePacket::default();
            packet.set_ftrace_events(event_bundle);
            trace.packet.push(packet);
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
            trace.packet.push(packet);

            let seq = rng.next_u32();
            for event in runqueue.iter() {
                trace.packet.push(event.to_track_event(desc_uuid, seq));
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
            trace.packet.push(packet);

            let seq = rng.next_u32();
            for event in events.iter() {
                trace.packet.push(event.to_track_event(desc_uuid, seq));
            }
        }

        // Populate the per-process latencies
        for (pidtgid, events) in self.process_latencies.iter() {
            let desc_uuid = rng.next_u64();

            let mut desc = generate_thread_track_descriptor(
                *pidtgid,
                desc_uuid,
                "Wakeup Latency".to_string(),
            );

            let mut counter_desc = CounterDescriptor::default();
            counter_desc.set_unit(Unit::UNIT_TIME_NS);
            counter_desc.set_is_incremental(false);

            desc.counter = Some(counter_desc).into();

            let mut packet = TracePacket::default();
            packet.set_track_descriptor(desc);
            trace.packet.push(packet);

            let seq = rng.next_u32();
            for event in events.iter() {
                trace.packet.push(event.to_track_event(desc_uuid, seq));
            }
        }

/*
        // Resolve the stacks, generate the interned data for them, and populate the trace.
        for (pid, stacks) in self.sleepers.iter() {
            // Collect into a HashSet to dedup the stacks, and then iterate that to symbolize the
            // stacks and generate the interned data.
            let interned_stacks: HashMap<Stack, LocalInternedString> = stacks
                .iter()
                .map(|stack| stack.stack.clone())
                .collect::<HashSet<_>>()
                .into_iter()
                .map(|stack| {
                    let symbols = match self.symbolizer.symbolize_stack(*pid as u32, &stack) {
                        Ok(s) => s.join(";"),
                        Err(_) => "<unknown>".to_string(),
                    };
                    let local_is = LocalInternedString {
                        iid: rng.next_u64(),
                        val: symbols,
                    };
                    (stack, local_is)
                })
                .collect();

            // Generate the interned data packets for the stacks.
            trace.packet.extend(generate_interned_data(interned_stacks.values()));

            for stack in stacks.iter() {
                let stack_uuid = rng.next_u64();
                let mut packets = Vec::new();
                for (stack, local_is) in interned_stacks.iter() {
                    if stack == &stack.stack {
                        let mut desc = TrackDescriptor::default();
                        desc.set_name(format!("Sleep Stack {}", pid));
                        desc.set_uuid(stack_uuid);

                        let mut packet = TracePacket::default();
                        packet.set_track_descriptor(desc);
                        trace.packet.push(packet);

                        let mut packet = TracePacket::default();
                        packet.set_timestamp(stack.ts_start);
                        packet.set_track_event(stack.stack.start_track_event(stack_uuid));
                        packet.set_trusted_packet_sequence_id(rng.next_u32());
                        trace.packet.push(packet);

                        let mut packet = TracePacket::default();
                        packet.set_timestamp(stack.ts_end);
                        packet.set_track_event(stack.stack.end_track_event(stack_uuid));
                        packet.set_trusted_packet_sequence_id(rng.next_u32());
                        trace.packet.push(packet);
                    }
                }
            }
        }
*/
        trace
    }
}

pub fn system(opts: SystemOpts) -> Result<()> {
    let recorder = Arc::new(Mutex::new(EventRecorder::default()));
    let thread_done = Arc::new(AtomicBool::new(false));
    let mut missed_events: u64 = 0;

    {
        let mut skel_builder = systing::SystingSystemSkelBuilder::default();
        if opts.verbose {
            skel_builder.obj_builder.debug(true);
        }

        let mut open_object = MaybeUninit::uninit();
        let open_skel = skel_builder.open(&mut open_object)?;

        if opts.cgroup.len() > 0 {
            open_skel.maps.rodata_data.tool_config.filter_cgroup = 1;
        }

        open_skel.maps.rodata_data.tool_config.tgid = opts.pid;
        let mut skel = open_skel.load()?;
        for cgroup in opts.cgroup.iter() {
            let metadata = std::fs::metadata(cgroup)?;
            let cgroupid = metadata.ino().to_ne_bytes();
            let val = (1 as u8).to_ne_bytes();
            skel.maps
                .cgroups
                .update(&cgroupid, &val, libbpf_rs::MapFlags::ANY)?;
        }

        let event_recorder = recorder.clone();
        let thread_done_clone = thread_done.clone();
        let mut builder = RingBufferBuilder::new();

        builder.add(&skel.maps.events, move |data: &[u8]| {
            let mut event = systing::types::task_event::default();
            plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");
            event_recorder.lock().unwrap().record_event(&event);
            0
        })?;

        let ring = builder.build()?;
        skel.attach()?;

        let t = thread::spawn(move || {
            loop {
                if thread_done_clone.load(Ordering::Relaxed) {
                    break;
                }
                let res = ring.poll(Duration::from_millis(100));
                if res.is_err() {
                    break;
                }
            }
            0
        });

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
        thread_done.store(true, Ordering::Relaxed);
        t.join().expect("Failed to join thread");

        let missed_events_key = 0_u64.to_ne_bytes();
        let results = skel
            .maps
            .missed_events
            .lookup(&missed_events_key, libbpf_rs::MapFlags::ANY)?;
        if let Some(results) = results {
            plain::copy_from_bytes(&mut missed_events, &results)
                .expect("Data buffer was too short");
        }
        println!("Stopped: missed events: {}", missed_events);
    }

    let mut my_recorder = std::mem::take(&mut *recorder.lock().unwrap());
    my_recorder.wake_all_pending_wakeups();

    let trace = my_recorder.generate_trace();
    let bytes = trace.write_to_bytes()?;
    let mut file = std::fs::File::create("trace.pb")?;
    file.write_all(&bytes)?;
    Ok(())
}
