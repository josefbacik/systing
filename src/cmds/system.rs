use std::collections::{BTreeMap, HashMap};
use std::ffi::CStr;
use std::io::Write;
use std::mem::MaybeUninit;
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::SystemOpts;

use anyhow::Result;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{MapCore, RingBufferBuilder};
use perfetto_protos::counter_descriptor::counter_descriptor::Unit;
use perfetto_protos::counter_descriptor::CounterDescriptor;
use perfetto_protos::ftrace_event::FtraceEvent;
use perfetto_protos::ftrace_event_bundle::FtraceEventBundle;
use perfetto_protos::process_descriptor::ProcessDescriptor;
use perfetto_protos::process_tree::process_tree::{Process, Thread};
use perfetto_protos::process_tree::ProcessTree;
use perfetto_protos::sched::{
    SchedSwitchFtraceEvent, SchedWakeupNewFtraceEvent, SchedWakingFtraceEvent,
};
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

struct RunqueueCounter {
    pub ts: u64,
    pub count: u32,
}

struct LatencyCounter {
    pub ts: u64,
    pub latency: u64,
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

pub fn system(opts: SystemOpts) -> Result<()> {
    let cpu_events = Arc::new(Mutex::new(HashMap::<u32, BTreeMap<u64, FtraceEvent>>::new()));
    let threads = Arc::new(Mutex::new(HashMap::<i32, Thread>::new()));
    let proceses = Arc::new(Mutex::new(HashMap::<i32, Process>::new()));
    let runqueue = Arc::new(Mutex::new(HashMap::<i32, Vec<RunqueueCounter>>::new()));
    let cpu_latencies = Arc::new(Mutex::new(HashMap::<u32, Vec<LatencyCounter>>::new()));
    let process_latencies = Arc::new(Mutex::new(HashMap::<u32, Vec<LatencyCounter>>::new()));
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

        let thread_done_clone = thread_done.clone();
        let cpu_events_clone = cpu_events.clone();
        let threads_clone = threads.clone();
        let process_clone = proceses.clone();
        let runqueue_clone = runqueue.clone();
        let cpu_latencies_clone = cpu_latencies.clone();
        let process_latencies_clone = process_latencies.clone();
        let mut counters = HashMap::<i32, u32>::new();
        let mut builder = RingBufferBuilder::new();

        builder.add(&skel.maps.events, move |data: &[u8]| {
            let mut event = systing::types::task_event::default();
            plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");

            {
                let ftrace_event = FtraceEvent::from_task_event(&event);
                let mut events = cpu_events_clone.lock().unwrap();
                let cpu_event = events.entry(event.cpu).or_insert_with(BTreeMap::new);
                cpu_event.insert(event.ts, ftrace_event);
            }

            // We want to keep a running count of the per-cpu runqueue size. We could do this
            // inside of BPF, but that's a map lookup and runnning counter, so we'll just keep the
            // complexity here instead of adding it to the BPF hook.
            if event.r#type == systing::types::event_type::SCHED_SWITCH
                || event.r#type == systing::types::event_type::SCHED_WAKEUP
                || event.r#type == systing::types::event_type::SCHED_WAKEUP_NEW
            {
                let mut runqueue = runqueue_clone.lock().unwrap();
                let cpu = if event.r#type == systing::types::event_type::SCHED_SWITCH {
                    event.cpu as i32
                } else {
                    event.target_cpu as i32
                };
                let rq = runqueue.entry(cpu).or_insert_with(Vec::new);
                let count = counters.entry(cpu).or_insert(0);

                if event.r#type == systing::types::event_type::SCHED_SWITCH {
                    // If we haven't seen a wakeup event yet we could have a runqueue size of 0, so
                    // we need to make sure we don't go negative.
                    if *count > 0 {
                        *count -= 1;
                    }
                } else {
                    *count += 1;
                }

                rq.push(RunqueueCounter {
                    ts: event.ts,
                    count: *count,
                });
            }

            // SCHED_SWITCH is going to have latency for this CPU and TGIDPID
            if event.r#type == systing::types::event_type::SCHED_SWITCH && event.latency > 0 {
                let mut latencies = cpu_latencies_clone.lock().unwrap();
                let mut process_latencies = process_latencies_clone.lock().unwrap();
                let cpu = event.cpu;
                let lat = latencies.entry(cpu).or_insert_with(Vec::new);
                let plat = process_latencies
                    .entry((event.next_tgidpid >> 32) as u32)
                    .or_insert_with(Vec::new);

                plat.push(LatencyCounter {
                    ts: event.ts,
                    latency: event.latency,
                });

                lat.push(LatencyCounter {
                    ts: event.ts,
                    latency: event.latency,
                });
            }

            let tgid = (event.prev_tgidpid >> 32) as i32;
            let pid = event.prev_tgidpid as i32;
            if pid != tgid {
                let mut thread = threads_clone.lock().unwrap();
                if !thread.contains_key(&pid) {
                    let thread_entry = thread.entry(pid).or_insert_with(Thread::default);
                    let comm = CStr::from_bytes_until_nul(&event.prev_comm).unwrap();
                    thread_entry.set_tid(pid);
                    thread_entry.set_tgid(tgid);
                    thread_entry.set_name(comm.to_str().unwrap().to_string());
                }
            }

            {
                let mut process = process_clone.lock().unwrap();
                if !process.contains_key(&tgid) {
                    let process_entry = process.entry(tgid).or_insert_with(Process::default);
                    process_entry.set_pid(tgid);
                }
            }

            let pid = event.next_tgidpid as i32;
            let tgid = (event.next_tgidpid >> 32) as i32;
            if pid != tgid {
                let mut thread = threads_clone.lock().unwrap();
                if !thread.contains_key(&pid) {
                    let thread_entry = thread.entry(pid).or_insert_with(Thread::default);
                    let comm = CStr::from_bytes_until_nul(&event.next_comm).unwrap();
                    thread_entry.set_tid(pid);
                    thread_entry.set_tgid(tgid);
                    thread_entry.set_name(comm.to_str().unwrap().to_string());
                }
            }

            {
                let mut process = process_clone.lock().unwrap();
                if !process.contains_key(&tgid) {
                    let process_entry = process.entry(tgid).or_insert_with(Process::default);
                    process_entry.set_pid(tgid);
                }
            }
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

    // Pull all the scheduling events.
    let events = std::mem::take(&mut *cpu_events.lock().unwrap());
    let mut trace = Trace::default();
    for (cpu, events) in events {
        println!("doing cpu {}", cpu);
        let mut event_bundle = FtraceEventBundle::default();
        event_bundle.set_cpu(cpu);
        event_bundle.event = events.into_values().collect();
        let mut packet = TracePacket::default();
        packet.set_ftrace_events(event_bundle);
        trace.packet.push(packet);
    }

    // Populate the per-cpu runqueue sizes
    let runqueues = std::mem::take(&mut *runqueue.lock().unwrap());
    let mut rng = rand::rng();
    for (cpu, runqueue) in runqueues {
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
            let mut track_event = TrackEvent::default();
            track_event.set_timestamp_absolute_us((event.ts / 1000) as i64);
            track_event.set_type(Type::TYPE_COUNTER);
            track_event.set_counter_value(event.count as i64);
            track_event.set_track_uuid(desc_uuid);

            let mut packet = TracePacket::default();
            packet.set_timestamp(event.ts);
            packet.set_trusted_packet_sequence_id(seq);
            packet.set_track_event(track_event);
            trace.packet.push(packet);
        }
    }

    // Populate the per-cpu latencies
    let latencies = std::mem::take(&mut *cpu_latencies.lock().unwrap());
    for (cpu, events) in latencies {
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
            let mut track_event = TrackEvent::default();
            track_event.set_timestamp_absolute_us((event.ts / 1000) as i64);
            track_event.set_type(Type::TYPE_COUNTER);
            track_event.set_counter_value(event.latency as i64);
            track_event.set_track_uuid(desc_uuid);

            let mut packet = TracePacket::default();
            packet.set_timestamp(event.ts);
            packet.set_trusted_packet_sequence_id(seq);
            packet.set_track_event(track_event);
            trace.packet.push(packet);
        }
    }

    // Populate the per-process latencies
    let latencies = std::mem::take(&mut *process_latencies.lock().unwrap());
    for (pid, events) in latencies {
        let process_uuid = rng.next_u64();
        let desc_uuid = rng.next_u64();

        let mut process_desc = ProcessDescriptor::default();
        process_desc.set_pid(pid as i32);

        let mut desc = TrackDescriptor::default();
        desc.set_name("Scheduler Latency".to_string());
        desc.set_uuid(process_uuid);
        desc.process = Some(process_desc).into();

        let mut packet = TracePacket::default();
        packet.set_track_descriptor(desc);
        trace.packet.push(packet);

        let mut counter_desc = CounterDescriptor::default();
        counter_desc.set_unit(Unit::UNIT_TIME_NS);
        counter_desc.set_is_incremental(false);

        let mut desc = TrackDescriptor::default();
        desc.set_name("Wakeup Latency".to_string());
        desc.set_uuid(desc_uuid);
        desc.set_parent_uuid(process_uuid);
        desc.counter = Some(counter_desc).into();

        let mut packet = TracePacket::default();
        packet.set_track_descriptor(desc);
        trace.packet.push(packet);

        let seq = rng.next_u32();
        for event in events.iter() {
            let mut track_event = TrackEvent::default();
            track_event.set_timestamp_absolute_us((event.ts / 1000) as i64);
            track_event.set_type(Type::TYPE_COUNTER);
            track_event.set_counter_value(event.latency as i64);
            track_event.set_track_uuid(desc_uuid);

            let mut packet = TracePacket::default();
            packet.set_timestamp(event.ts);
            packet.set_trusted_packet_sequence_id(seq);
            packet.set_track_event(track_event);
            trace.packet.push(packet);
        }
    }

    // Pull all the threads and populate the processes
    let threads = std::mem::take(&mut *threads.lock().unwrap());
    let processes = std::mem::take(&mut *proceses.lock().unwrap());
    let mut process_tree = ProcessTree::default();
    process_tree.threads = threads.into_values().collect();
    process_tree.processes = processes.into_values().collect();
    for process in process_tree.processes.iter_mut() {
        crate::perfetto::profetto_fill_process(process);
    }
    let mut packet = TracePacket::default();
    packet.set_process_tree(process_tree);
    trace.packet.push(packet);

    let bytes = trace.write_to_bytes()?;
    let mut file = std::fs::File::create("trace.pb")?;
    file.write_all(&bytes)?;
    Ok(())
}
