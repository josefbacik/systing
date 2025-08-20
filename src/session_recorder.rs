use std::collections::HashMap;
use std::ffi::CStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use crate::events::SystingProbeRecorder;
use crate::perf_recorder::PerfCounterRecorder;
use crate::perfetto::TrackCounter;
use crate::ringbuf::RingBuffer;
use crate::sched::SchedEventRecorder;
use crate::stack_recorder::StackRecorder;
use crate::systing::types::task_info;
use crate::SystingRecordEvent;

use fb_procfs::ProcReader;
use perfetto_protos::builtin_clock::BuiltinClock;
use perfetto_protos::clock_snapshot::clock_snapshot::Clock;
use perfetto_protos::clock_snapshot::ClockSnapshot;
use perfetto_protos::counter_descriptor::counter_descriptor::Unit;
use perfetto_protos::counter_descriptor::CounterDescriptor;
use perfetto_protos::process_descriptor::ProcessDescriptor;
use perfetto_protos::process_tree::{process_tree::Process as ProtoProcess, ProcessTree};
use perfetto_protos::thread_descriptor::ThreadDescriptor;
use perfetto_protos::trace_packet::TracePacket;
use perfetto_protos::track_descriptor::TrackDescriptor;

#[derive(Default)]
pub struct SysInfoEvent {
    pub cpu: u32,
    pub ts: u64,
    pub frequency: i64,
}

#[derive(Default)]
pub struct SysinfoRecorder {
    pub ringbuf: RingBuffer<SysInfoEvent>,
    pub frequency: HashMap<u32, Vec<TrackCounter>>,
}

#[derive(Default)]
pub struct SessionRecorder {
    pub clock_snapshot: Mutex<ClockSnapshot>,
    pub event_recorder: Mutex<SchedEventRecorder>,
    pub stack_recorder: Mutex<StackRecorder>,
    pub perf_counter_recorder: Mutex<PerfCounterRecorder>,
    pub sysinfo_recorder: Mutex<SysinfoRecorder>,
    pub probe_recorder: Mutex<SystingProbeRecorder>,
    pub process_descriptors: RwLock<HashMap<u64, ProcessDescriptor>>,
    pub processes: RwLock<HashMap<u64, ProtoProcess>>,
    pub threads: RwLock<HashMap<u64, ThreadDescriptor>>,
    pub proc_reader: Mutex<ProcReader>,
}

pub fn get_clock_value(clock_id: libc::c_int) -> u64 {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(clock_id, &mut ts) } != 0 {
        return 0;
    }
    (ts.tv_sec as u64 * 1_000_000_000) + ts.tv_nsec as u64
}

impl From<&task_info> for ProcessDescriptor {
    fn from(task: &task_info) -> Self {
        let comm = CStr::from_bytes_until_nul(&task.comm).unwrap();
        let mut process = ProcessDescriptor::default();
        process.set_pid(task.tgidpid as i32);
        process.set_process_name(comm.to_str().unwrap().to_string());
        process
    }
}

pub fn proto_process_from_parts(task: &task_info, proc_reader: &ProcReader) -> ProtoProcess {
    ProtoProcess {
        cmdline: if let Ok(Some(cmd)) = proc_reader.read_pid_cmdline((task.tgidpid >> 32) as u32) {
            cmd
        } else {
            vec![]
        },
        pid: Some(task.tgidpid as i32),
        ..ProtoProcess::default()
    }
}

impl From<&task_info> for ThreadDescriptor {
    fn from(task: &task_info) -> Self {
        let comm = CStr::from_bytes_until_nul(&task.comm).unwrap();
        let mut thread = ThreadDescriptor::default();
        thread.set_tid(task.tgidpid as i32);
        thread.set_pid((task.tgidpid >> 32) as i32);
        thread.set_thread_name(comm.to_str().unwrap().to_string());
        thread
    }
}

impl SystingRecordEvent<SysInfoEvent> for SysinfoRecorder {
    fn ringbuf(&self) -> &RingBuffer<SysInfoEvent> {
        &self.ringbuf
    }
    fn ringbuf_mut(&mut self) -> &mut RingBuffer<SysInfoEvent> {
        &mut self.ringbuf
    }
    fn handle_event(&mut self, event: SysInfoEvent) {
        let freq = self.frequency.entry(event.cpu).or_default();
        freq.push(TrackCounter {
            ts: event.ts,
            count: event.frequency,
        });
    }
}

impl SysinfoRecorder {
    pub fn generate_trace(&self, id_counter: &mut Arc<AtomicUsize>) -> Vec<TracePacket> {
        let mut packets = Vec::new();

        // Populate the sysinfo events
        for (cpu, events) in self.frequency.iter() {
            let desc_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;

            let mut counter_desc = CounterDescriptor::default();
            counter_desc.set_unit(Unit::UNIT_COUNT);
            counter_desc.set_is_incremental(false);

            let mut desc = TrackDescriptor::default();
            desc.set_name(format!("CPU {cpu} frequency").to_string());
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
        packets
    }
}

impl SessionRecorder {
    pub fn snapshot_clocks(&self) {
        let mut clock_snapshot = self.clock_snapshot.lock().unwrap();
        clock_snapshot.set_primary_trace_clock(BuiltinClock::BUILTIN_CLOCK_BOOTTIME);

        let mut clock = Clock::default();
        clock.set_clock_id(BuiltinClock::BUILTIN_CLOCK_MONOTONIC as u32);
        clock.set_timestamp(get_clock_value(libc::CLOCK_MONOTONIC));
        clock_snapshot.clocks.push(clock);

        let mut clock = Clock::default();
        clock.set_clock_id(BuiltinClock::BUILTIN_CLOCK_BOOTTIME as u32);
        clock.set_timestamp(get_clock_value(libc::CLOCK_BOOTTIME));
        clock_snapshot.clocks.push(clock);

        let mut clock = Clock::default();
        clock.set_clock_id(BuiltinClock::BUILTIN_CLOCK_REALTIME as u32);
        clock.set_timestamp(get_clock_value(libc::CLOCK_REALTIME));
        clock_snapshot.clocks.push(clock);

        let mut clock = Clock::default();
        clock.set_clock_id(BuiltinClock::BUILTIN_CLOCK_REALTIME_COARSE as u32);
        clock.set_timestamp(get_clock_value(libc::CLOCK_REALTIME_COARSE));
        clock_snapshot.clocks.push(clock);

        let mut clock = Clock::default();
        clock.set_clock_id(BuiltinClock::BUILTIN_CLOCK_MONOTONIC_COARSE as u32);
        clock.set_timestamp(get_clock_value(libc::CLOCK_MONOTONIC_COARSE));
        clock_snapshot.clocks.push(clock);

        let mut clock = Clock::default();
        clock.set_clock_id(BuiltinClock::BUILTIN_CLOCK_MONOTONIC_RAW as u32);
        clock.set_timestamp(get_clock_value(libc::CLOCK_MONOTONIC_RAW));
        clock_snapshot.clocks.push(clock);
    }

    pub fn generate_trace(&self) -> Vec<TracePacket> {
        let mut packets = Vec::new();
        let mut id_counter = Arc::new(AtomicUsize::new(1));
        let mut pid_uuids = HashMap::new();
        let mut thread_uuids = HashMap::new();
        let systing_desc_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;

        // First emit the clock snapshot
        let mut packet = TracePacket::default();
        packet.set_clock_snapshot(self.clock_snapshot.lock().unwrap().clone());
        packet.set_trusted_packet_sequence_id(id_counter.fetch_add(1, Ordering::Relaxed) as u32);
        packets.push(packet);

        let mut desc = TrackDescriptor::default();
        desc.set_uuid(systing_desc_uuid);
        desc.set_name("Systing".to_string());

        let mut packet = TracePacket::default();
        packet.set_track_descriptor(desc);
        packets.push(packet);

        // Populate all the process tracks
        for process in self.process_descriptors.read().unwrap().values() {
            let uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;
            pid_uuids.insert(process.pid(), uuid);

            let mut desc = TrackDescriptor::default();
            desc.set_uuid(uuid);
            desc.process = Some(process.clone()).into();

            let mut packet = TracePacket::default();
            packet.set_track_descriptor(desc);
            packets.push(packet);
        }

        // Populate all the process trees
        for process in self.processes.read().unwrap().values() {
            let process_tree = ProcessTree {
                processes: vec![process.clone()],
                ..ProcessTree::default()
            };

            let mut packet = TracePacket::default();
            packet.set_process_tree(process_tree);
            packets.push(packet);
        }

        for thread in self.threads.read().unwrap().values() {
            let uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;
            thread_uuids.insert(thread.tid(), uuid);

            let mut desc = TrackDescriptor::default();
            desc.set_uuid(uuid);
            desc.thread = Some(thread.clone()).into();

            let mut packet = TracePacket::default();
            packet.set_track_descriptor(desc);
            packets.push(packet);
        }

        // Generate the trace for all the event recorders
        packets.extend(self.event_recorder.lock().unwrap().generate_trace(
            &pid_uuids,
            &thread_uuids,
            &mut id_counter,
        ));
        packets.extend(
            self.stack_recorder
                .lock()
                .unwrap()
                .generate_trace(&mut id_counter),
        );
        packets.extend(
            self.perf_counter_recorder
                .lock()
                .unwrap()
                .generate_trace(&mut id_counter),
        );
        packets.extend(
            self.sysinfo_recorder
                .lock()
                .unwrap()
                .generate_trace(&mut id_counter),
        );
        packets.extend(self.probe_recorder.lock().unwrap().generate_trace(
            &pid_uuids,
            &thread_uuids,
            &mut id_counter,
        ));
        packets
    }
}

pub fn maybe_record_task(info: &task_info, session_recorder: &Arc<SessionRecorder>) {
    let pid = info.tgidpid as i32;
    let tgid = (info.tgidpid >> 32) as i32;
    if pid == tgid {
        if !session_recorder
            .process_descriptors
            .read()
            .unwrap()
            .contains_key(&info.tgidpid)
        {
            session_recorder
                .process_descriptors
                .write()
                .unwrap()
                .insert(info.tgidpid, ProcessDescriptor::from(info));

            let proc_reader = session_recorder.proc_reader.lock().unwrap();
            session_recorder
                .processes
                .write()
                .unwrap()
                .insert(info.tgidpid, proto_process_from_parts(info, &proc_reader));
        }
    } else if !session_recorder
        .threads
        .read()
        .unwrap()
        .contains_key(&info.tgidpid)
    {
        session_recorder
            .threads
            .write()
            .unwrap()
            .insert(info.tgidpid, ThreadDescriptor::from(info));
    }
}

impl crate::SystingEvent for SysInfoEvent {
    fn ts(&self) -> u64 {
        self.ts
    }
}
