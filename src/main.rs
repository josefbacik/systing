pub mod events;
pub mod perf;
mod perf_recorder;
pub mod perfetto;
pub mod pystacks;
pub mod ringbuf;
mod sched;
pub mod symbolize;

use std::collections::{HashMap, HashSet};
use std::ffi::CStr;
use std::mem;
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::process;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::Duration;

use crate::events::{EventKeyType, EventProbe, SystingProbeRecorder};
use crate::perf::{PerfCounters, PerfHwEvent, PerfOpenEvents};
use crate::perf_recorder::PerfCounterRecorder;
use crate::perfetto::TrackCounter;
use crate::pystacks::stack_walker::{
    get_pystack_from_event, init_pystacks, load_pystack_symbols, merge_pystacks,
    pystacks_to_frames_mapping, user_stack_to_python_calls, StackWalkerRun,
};
use crate::ringbuf::RingBuffer;
use crate::sched::SchedEventRecorder;
use crate::symbolize::Stack;

use anyhow::bail;
use anyhow::Result;
use clap::Parser;

use blazesym::symbolize::source::{Kernel, Process, Source};
use blazesym::symbolize::{cache, Input, Sym, Symbolized, Symbolizer};
use blazesym::Pid;
use fb_procfs::ProcReader;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{
    MapCore, RawTracepointOpts, RingBufferBuilder, TracepointOpts, UprobeOpts, UsdtOpts,
};
use perfetto_protos::builtin_clock::BuiltinClock;
use perfetto_protos::clock_snapshot::clock_snapshot::Clock;
use perfetto_protos::clock_snapshot::ClockSnapshot;
use perfetto_protos::counter_descriptor::counter_descriptor::Unit;
use perfetto_protos::counter_descriptor::CounterDescriptor;
use perfetto_protos::interned_data::InternedData;
use perfetto_protos::process_descriptor::ProcessDescriptor;
use perfetto_protos::process_tree::{process_tree::Process as ProtoProcess, ProcessTree};
use perfetto_protos::profile_common::{Callstack, Frame, InternedString, Mapping};
use perfetto_protos::profile_packet::PerfSample;
use perfetto_protos::thread_descriptor::ThreadDescriptor;
use perfetto_protos::trace::Trace;
use perfetto_protos::trace_packet::trace_packet::SequenceFlags;
use perfetto_protos::trace_packet::TracePacket;
use perfetto_protos::track_descriptor::TrackDescriptor;

use plain::Plain;
use protobuf::Message;

#[derive(Debug, Parser)]
struct Command {
    #[arg(short, long)]
    verbose: bool,
    #[arg(short, long)]
    pid: Vec<u32>,
    #[arg(short, long)]
    cgroup: Vec<String>,
    #[arg(short, long, default_value = "0")]
    duration: u64,
    #[arg(short, long)]
    no_stack_traces: bool,
    #[arg(long, default_value = "0")]
    ringbuf_size_mib: u32,
    #[arg(long)]
    trace_event: Vec<String>,
    #[arg(long)]
    trace_event_pid: Vec<u32>,
    #[arg(short, long)]
    sw_event: bool,
    #[arg(long)]
    process_sched_stats: bool,
    #[arg(long)]
    cpu_sched_stats: bool,
    #[arg(long)]
    cpu_frequency: bool,
    #[arg(long)]
    perf_counter: Vec<String>,
    #[arg(long)]
    no_cpu_stack_traces: bool,
    #[arg(long)]
    no_sleep_stack_traces: bool,
    #[arg(long)]
    trace_event_config: Vec<String>,
    #[arg(long, default_value = "0")]
    continuous: u64,
    #[cfg(feature = "pystacks")]
    #[arg(long)]
    collect_pystacks: bool,
}

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

mod systing {
    include!(concat!(env!("OUT_DIR"), "/systing_system.skel.rs"));
}

pub trait SystingRecordEvent<T> {
    fn use_ringbuf(&self) -> bool {
        self.ringbuf().max_duration() > 0
    }
    fn ringbuf(&self) -> &RingBuffer<T>;
    fn ringbuf_mut(&mut self) -> &mut RingBuffer<T>;
    fn maybe_trigger(&mut self, _event: &T) -> bool {
        false
    }
    fn record_event(&mut self, event: T) -> bool
    where
        T: SystingEvent,
    {
        if self.use_ringbuf() {
            let ret = self.maybe_trigger(&event);
            self.ringbuf_mut().push_front(event);
            ret
        } else {
            self.handle_event(event);
            false
        }
    }
    fn drain_ringbuf(&mut self) {
        while let Some(event) = self.ringbuf_mut().pop_back() {
            self.handle_event(event);
        }
    }
    fn handle_event(&mut self, _event: T);
}

pub trait SystingEvent {
    fn ts(&self) -> u64;
    fn next_task_info(&self) -> Option<&task_info> {
        None
    }
    fn prev_task_info(&self) -> Option<&task_info> {
        None
    }
}

use systing::types::arg_desc;
use systing::types::arg_type;
use systing::types::event_type;
use systing::types::perf_counter_event;
use systing::types::probe_event;
use systing::types::stack_event;
use systing::types::task_event;
use systing::types::task_info;

unsafe impl Plain for task_event {}
unsafe impl Plain for stack_event {}
unsafe impl Plain for perf_counter_event {}
unsafe impl Plain for probe_event {}
unsafe impl Plain for arg_desc {}

impl SystingEvent for task_event {
    fn ts(&self) -> u64 {
        self.ts
    }
    fn next_task_info(&self) -> Option<&task_info> {
        match self.r#type {
            event_type::SCHED_SWITCH
            | event_type::SCHED_WAKING
            | event_type::SCHED_WAKEUP
            | event_type::SCHED_WAKEUP_NEW => Some(&self.next),
            _ => None,
        }
    }
    fn prev_task_info(&self) -> Option<&task_info> {
        Some(&self.prev)
    }
}

impl SystingEvent for stack_event {
    fn ts(&self) -> u64 {
        self.ts
    }
    fn next_task_info(&self) -> Option<&task_info> {
        Some(&self.task)
    }
}

impl SystingEvent for perf_counter_event {
    fn ts(&self) -> u64 {
        self.ts
    }
    fn next_task_info(&self) -> Option<&task_info> {
        Some(&self.task)
    }
}

impl SystingEvent for probe_event {
    fn ts(&self) -> u64 {
        self.ts
    }
    fn next_task_info(&self) -> Option<&task_info> {
        Some(&self.task)
    }
}

impl SystingEvent for SysInfoEvent {
    fn ts(&self) -> u64 {
        self.ts
    }
}

#[derive(Default)]
struct SysInfoEvent {
    cpu: u32,
    ts: u64,
    frequency: i64,
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
struct StackRecorder {
    ringbuf: RingBuffer<stack_event>,
    stacks: HashMap<i32, Vec<StackEvent>>,
    psr: Arc<StackWalkerRun>,
}

#[derive(Default)]
struct SysinfoRecorder {
    ringbuf: RingBuffer<SysInfoEvent>,
    frequency: HashMap<u32, Vec<TrackCounter>>,
}

#[derive(Default)]
struct SessionRecorder {
    clock_snapshot: Mutex<ClockSnapshot>,
    event_recorder: Mutex<SchedEventRecorder>,
    stack_recorder: Mutex<StackRecorder>,
    perf_counter_recorder: Mutex<PerfCounterRecorder>,
    sysinfo_recorder: Mutex<SysinfoRecorder>,
    probe_recorder: Mutex<SystingProbeRecorder>,
    process_descriptors: RwLock<HashMap<u64, ProcessDescriptor>>,
    processes: RwLock<HashMap<u64, ProtoProcess>>,
    threads: RwLock<HashMap<u64, ThreadDescriptor>>,
    proc_reader: Mutex<ProcReader>,
}

fn get_clock_value(clock_id: libc::c_int) -> u64 {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(clock_id, &mut ts) } != 0 {
        return 0;
    }
    (ts.tv_sec as u64 * 1_000_000_000) + ts.tv_nsec as u64
}

pub(crate) fn add_frame(
    frame_map: &mut HashMap<u64, Vec<LocalFrame>>,
    func_map: &mut HashMap<String, InternedString>,
    id_counter: &mut Arc<AtomicUsize>,
    input_addr: u64,
    start_addr: u64,
    offset: u64,
    name: String,
) {
    let mut frame = Frame::default();
    let my_func = func_map.entry(name.to_string()).or_insert_with(|| {
        let mut interned_str = InternedString::default();
        let iid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;
        interned_str.set_iid(iid);
        interned_str.set_str(name.into_bytes());
        interned_str
    });
    let iid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;
    frame.set_iid(iid);
    frame.set_function_name_id(my_func.iid());
    frame.set_rel_pc(offset);

    let mut mapping = Mapping::default();
    let iid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;
    mapping.set_iid(iid);
    mapping.set_exact_offset(input_addr);
    mapping.set_start_offset(start_addr);

    frame.set_mapping_id(mapping.iid());
    let frame = LocalFrame { frame, mapping };
    let frame_vec = frame_map.entry(input_addr).or_default();
    frame_vec.push(frame);
}

fn stack_to_frames_mapping<'a, I>(
    symbolizer: &mut Symbolizer,
    frame_map: &mut HashMap<u64, Vec<LocalFrame>>,
    func_map: &mut HashMap<String, InternedString>,
    source: &Source<'a>,
    id_counter: &mut Arc<AtomicUsize>,
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
                addr,
                name,
                offset,
                inlined,
                ..
            })) => {
                add_frame(
                    frame_map,
                    func_map,
                    id_counter,
                    *input_addr,
                    addr,
                    offset as u64,
                    name.to_string(),
                );

                for inline in inlined {
                    let name = format!("{} (inlined)", inline.name);
                    add_frame(frame_map, func_map, id_counter, *input_addr, addr, 0, name);
                }
            }
            _ => {
                let name = "<unknown>".to_string();
                add_frame(
                    frame_map,
                    func_map,
                    id_counter,
                    *input_addr,
                    *input_addr,
                    0,
                    name.clone(),
                );
            }
        }
    }
}

fn generate_stack_packets(
    packets: &mut Arc<Mutex<Vec<TracePacket>>>,
    tgid: u32,
    stacks: Vec<StackEvent>,
    id_counter: &mut Arc<AtomicUsize>,
    psr: &mut Arc<StackWalkerRun>,
) {
    let user_src = Source::Process(Process::new(Pid::from(tgid)));
    let kernel_src = Source::Kernel(Kernel::default());
    let mut symbolizer = Symbolizer::builder()
        .enable_code_info(true)
        .enable_inlined_fns(true)
        .build();

    let _ = symbolizer.cache(&cache::Cache::from(cache::Process::new(tgid.into())));

    // We have to symbolize all of the addresses in the stacks and fill
    // out the hashmap with all of the frames.
    let mut frame_map = HashMap::new();
    let mut func_name_map = HashMap::new();
    let mut python_calls = Vec::new();
    let mut python_stack_markers = Vec::new();
    for stack in stacks.iter() {
        let raw_stack = &stack.stack;
        stack_to_frames_mapping(
            &mut symbolizer,
            &mut frame_map,
            &mut func_name_map,
            &user_src,
            id_counter,
            raw_stack.user_stack.iter(),
        );
        user_stack_to_python_calls(&mut frame_map, &mut func_name_map, &mut python_calls);
        stack_to_frames_mapping(
            &mut symbolizer,
            &mut frame_map,
            &mut func_name_map,
            &kernel_src,
            id_counter,
            raw_stack.kernel_stack.iter(),
        );
        pystacks_to_frames_mapping(
            psr,
            &mut frame_map,
            &mut func_name_map,
            id_counter,
            &mut python_stack_markers,
            &raw_stack.py_stack,
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
            let iid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;
            callstack.set_iid(iid);
            callstack.frame_ids = if stack.py_stack.is_empty() {
                stack
                    .user_stack
                    .iter()
                    .chain(stack.kernel_stack.iter())
                    .flat_map(|addr| {
                        let frame_vec = frame_map.get(addr).unwrap();
                        frame_vec
                            .iter()
                            .map(|frame| frame.frame.iid())
                            .collect::<Vec<u64>>()
                    })
                    .collect()
            } else {
                let merged_addrs = merge_pystacks(&stack, &python_calls, &python_stack_markers);

                merged_addrs
                    .iter()
                    .chain(stack.kernel_stack.iter())
                    .flat_map(|addr| {
                        let frame_vec = frame_map.get(addr).unwrap();
                        frame_vec
                            .iter()
                            .map(|frame| frame.frame.iid())
                            .collect::<Vec<u64>>()
                    })
                    .collect()
            };
            (stack, callstack)
        })
        .collect();

    let seq = id_counter.fetch_add(1, Ordering::Relaxed) as u32;
    let mut packet = TracePacket::default();
    let interned_data = InternedData {
        callstacks: interned_stacks.values().cloned().collect(),
        function_names: func_name_map.values().cloned().collect(),
        frames: frame_map
            .values()
            .flat_map(|frame_vec| {
                frame_vec
                    .iter()
                    .map(|frame| frame.frame.clone())
                    .collect::<Vec<Frame>>()
            })
            .collect(),
        mappings: frame_map
            .values()
            .flat_map(|frame_vec| {
                frame_vec
                    .iter()
                    .map(|frame| frame.mapping.clone())
                    .collect::<Vec<Mapping>>()
            })
            .collect(),
        ..Default::default()
    };
    packet.interned_data = Some(interned_data).into();
    packet.set_trusted_packet_sequence_id(seq);
    packet.set_sequence_flags(
        SequenceFlags::SEQ_INCREMENTAL_STATE_CLEARED as u32
            | SequenceFlags::SEQ_NEEDS_INCREMENTAL_STATE as u32,
    );
    packets.lock().unwrap().push(packet);

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
        packets.lock().unwrap().push(packet);
    }
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

fn proto_process_from_parts(task: &task_info, proc_reader: &ProcReader) -> ProtoProcess {
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

impl SystingRecordEvent<stack_event> for StackRecorder {
    fn ringbuf(&self) -> &RingBuffer<stack_event> {
        &self.ringbuf
    }
    fn ringbuf_mut(&mut self) -> &mut RingBuffer<stack_event> {
        &mut self.ringbuf
    }
    fn handle_event(&mut self, event: stack_event) {
        if event.user_stack_length > 0 || event.kernel_stack_length > 0 {
            let kstack_vec = Vec::from(&event.kernel_stack[..event.kernel_stack_length as usize]);
            let ustack_vec = Vec::from(&event.user_stack[..event.user_stack_length as usize]);
            let stack_key = (event.task.tgidpid >> 32) as i32;
            let py_stack = get_pystack_from_event(&event);

            let stack = StackEvent {
                tgidpid: event.task.tgidpid,
                ts_start: event.ts,
                stack: Stack::new(&kstack_vec, &ustack_vec, &py_stack),
            };
            let stacks = self.stacks.entry(stack_key).or_default();
            stacks.push(stack);
        }

        load_pystack_symbols(&mut self.psr, &event);
    }
}

impl StackRecorder {
    fn generate_trace(&self, id_counter: &mut Arc<AtomicUsize>) -> Vec<TracePacket> {
        use workerpool::thunk::{Thunk, ThunkWorker};
        use workerpool::Pool;

        let packets = Arc::new(Mutex::new(Vec::new()));
        let pool = Pool::<ThunkWorker<()>>::new(4);

        // Resolve the stacks, generate the interned data for them, and populate the trace.
        for (tgid, stacks) in self.stacks.iter() {
            let mut id_counter = id_counter.clone();
            let mut psr = self.psr.clone();
            let stacks = stacks.clone();
            let tgid = *tgid as u32;
            let mut packets = packets.clone();
            pool.execute(Thunk::of(move || {
                generate_stack_packets(&mut packets, tgid, stacks, &mut id_counter, &mut psr)
            }));
        }
        pool.join();
        let packets = mem::take(&mut *packets.lock().unwrap());
        packets
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
    fn generate_trace(&self, id_counter: &mut Arc<AtomicUsize>) -> Vec<TracePacket> {
        let mut packets = Vec::new();

        // Populate the sysinfo events
        for (cpu, events) in self.frequency.iter() {
            let desc_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;

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

            let seq = id_counter.fetch_add(1, Ordering::Relaxed) as u32;
            for event in events.iter() {
                packets.push(event.to_track_event(desc_uuid, seq));
            }
        }
        packets
    }
}

impl SessionRecorder {
    fn snapshot_clocks(&self) {
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

    fn generate_trace(&self) -> Vec<TracePacket> {
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

fn maybe_record_task(info: &task_info, session_recorder: &Arc<SessionRecorder>) {
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

fn consume_loop<T, N>(
    session_recorder: &Arc<SessionRecorder>,
    recorder: &Mutex<T>,
    rx: Receiver<N>,
    stop_tx: Sender<()>,
) where
    T: SystingRecordEvent<N>,
    N: Plain + SystingEvent,
{
    loop {
        let res = rx.recv();
        if res.is_err() {
            break;
        }
        let event = res.unwrap();
        if let Some(task_info) = event.next_task_info() {
            maybe_record_task(task_info, session_recorder);
        }
        if let Some(task_info) = event.prev_task_info() {
            maybe_record_task(task_info, session_recorder);
        }
        let ret = recorder.lock().unwrap().record_event(event);
        if ret {
            stop_tx.send(()).expect("Failed to send stop signal");
            break;
        }
    }
}

fn dump_missed_events(skel: &systing::SystingSystemSkel, index: u32) -> u64 {
    let index = index.to_ne_bytes();
    let result = skel
        .maps
        .missed_events
        .lookup_percpu(&index, libbpf_rs::MapFlags::ANY);
    let mut missed = 0;
    if let Ok(results) = result {
        for val in results.unwrap() {
            let mut missed_events: u64 = 0;
            plain::copy_from_bytes(&mut missed_events, &val).unwrap();
            missed += missed_events;
        }
    }
    missed
}

fn system(opts: Command) -> Result<()> {
    let num_cpus = libbpf_rs::num_possible_cpus().unwrap() as u32;
    let mut perf_counter_names = Vec::new();
    let mut counters = PerfCounters::default();
    let (stop_tx, stop_rx) = channel();
    let old_kernel = if let Some(kernel_version) = sysinfo::System::kernel_version() {
        let parts = kernel_version.split('.').collect::<Vec<&str>>();

        if parts.len() >= 2 {
            let major = parts[0].parse::<u64>().unwrap_or(0);
            let minor = parts[1].parse::<u64>().unwrap_or(0);

            // 6.10 is when they added bpf_get_attach_cookie() to raw_tracepoint
            !(major >= 6 && minor >= 10)
        } else {
            false
        }
    } else {
        false
    };

    if !opts.perf_counter.is_empty() {
        counters.discover()?;

        // We can do things like topdown* to get all of the topdown counters, so we have to loop
        // through all of our options and populate the actual counter names that we want
        for counter in opts.perf_counter.iter() {
            let events = counters.event(counter);
            if events.is_none() {
                Err(anyhow::anyhow!("Invalid perf counter"))?;
            }
            for event in events.unwrap() {
                if !perf_counter_names.contains(&event.name) {
                    perf_counter_names.push(event.name.clone());
                }
            }
        }
    }

    let recorder = Arc::new(SessionRecorder::default());

    if opts.continuous > 0 {
        let duration = Duration::from_secs(opts.continuous);
        recorder
            .event_recorder
            .lock()
            .unwrap()
            .ringbuf
            .set_max_duration(duration.as_nanos() as u64);
        recorder
            .stack_recorder
            .lock()
            .unwrap()
            .ringbuf
            .set_max_duration(duration.as_nanos() as u64);
        recorder
            .perf_counter_recorder
            .lock()
            .unwrap()
            .ringbuf
            .set_max_duration(duration.as_nanos() as u64);
        recorder
            .sysinfo_recorder
            .lock()
            .unwrap()
            .ringbuf
            .set_max_duration(duration.as_nanos() as u64);
        recorder
            .probe_recorder
            .lock()
            .unwrap()
            .ringbuf
            .set_max_duration(duration.as_nanos() as u64);
    }

    recorder.snapshot_clocks();
    {
        let mut skel_builder = systing::SystingSystemSkelBuilder::default();
        if opts.verbose {
            skel_builder.obj_builder.debug(true);
        }

        #[cfg(not(feature = "pystacks"))] // set to false when feature is off
        let collect_pystacks = false;
        #[cfg(feature = "pystacks")] // use option value if feature is on
        let collect_pystacks = opts.collect_pystacks;

        let mut open_object = MaybeUninit::uninit();
        let mut open_skel = skel_builder.open(&mut open_object)?;
        {
            let rodata = open_skel
                .maps
                .rodata_data
                .as_deref_mut()
                .expect("'rodata' is not mmap'ed, your kernel is too old");

            rodata.tool_config.num_cpus = num_cpus;
            rodata.tool_config.my_tgid = process::id();
            rodata.tool_config.no_cpu_stack_traces = opts.no_cpu_stack_traces as u32;
            rodata.tool_config.no_sleep_stack_traces = opts.no_sleep_stack_traces as u32;
            if !opts.cgroup.is_empty() {
                rodata.tool_config.filter_cgroup = 1;
            }
            if opts.no_stack_traces {
                rodata.tool_config.no_stack_traces = 1;
            }
            if !opts.pid.is_empty() {
                rodata.tool_config.filter_pid = 1;
            }
            if collect_pystacks {
                rodata.tool_config.collect_pystacks = 1;
            }
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

        recorder
            .event_recorder
            .lock()
            .unwrap()
            .set_process_sched_stats(opts.process_sched_stats);
        recorder
            .event_recorder
            .lock()
            .unwrap()
            .set_cpu_sched_stats(opts.cpu_sched_stats);

        {
            let mut probe_recorder = recorder.probe_recorder.lock().unwrap();
            let mut rng = rand::rng();
            for tracepoint in opts.trace_event.iter() {
                probe_recorder.add_event_from_str(tracepoint, &mut rng)?;
            }

            for config in opts.trace_event_config.iter() {
                probe_recorder.load_config(config, &mut rng)?;
            }

            if opts.trace_event_pid.is_empty() {
                for event in probe_recorder.config_events.values() {
                    match event.event {
                        EventProbe::Usdt(_) => {
                            Err(anyhow::anyhow!(
                                "USDT events must be specified with --trace-event-pid"
                            ))?;
                        }
                        EventProbe::UProbe(_) => {
                            Err(anyhow::anyhow!(
                                "UPROBE events must be specified with --trace-event-pid"
                            ))?;
                        }
                        _ => {}
                    }
                }
            }
        }

        // If we're on an older kernel we can't use the raw_tracepoint version since it doesn't
        // have the cookie support. Newer kernels will use the raw_tracepoint version so don't need
        // to load the old tracepoint program.
        if old_kernel {
            open_skel.progs.systing_raw_tracepoint.set_autoload(false);
        } else {
            open_skel.progs.systing_tracepoint.set_autoload(false);
        }

        let mut need_slots = false;
        for counter in perf_counter_names.iter() {
            recorder
                .perf_counter_recorder
                .lock()
                .unwrap()
                .perf_counters
                .push(counter.clone());
            if !need_slots && counter.starts_with("topdown") {
                need_slots = true;
            }
        }

        let num_events = perf_counter_names.len() as u32;
        open_skel
            .maps
            .rodata_data
            .as_deref_mut()
            .unwrap()
            .tool_config
            .num_perf_counters = num_events;
        open_skel
            .maps
            .perf_counters
            .set_max_entries(num_cpus * num_events)?;
        if num_events > 0 {
            open_skel
                .maps
                .last_perf_counter_value
                .set_max_entries(num_events)?;
        }

        open_skel.maps.missed_events.set_max_entries(num_cpus)?;

        let mut skel = open_skel.load()?;
        for cgroup in opts.cgroup.iter() {
            let metadata = std::fs::metadata(cgroup)?;
            let cgroupid = metadata.ino().to_ne_bytes();
            let val = (1_u8).to_ne_bytes();
            skel.maps
                .cgroups
                .update(&cgroupid, &val, libbpf_rs::MapFlags::ANY)?;
        }

        for pid in opts.pid.iter() {
            let val = (1_u8).to_ne_bytes();
            skel.maps
                .pids
                .update(&pid.to_ne_bytes(), &val, libbpf_rs::MapFlags::ANY)?;
        }

        let mut rings = Vec::new();
        let (event_tx, event_rx) = channel();
        let (stack_tx, stack_rx) = channel();
        let (cache_tx, cache_rx) = channel();
        let (probe_tx, probe_rx) = channel();

        let object = skel.object();

        if collect_pystacks {
            init_pystacks(
                &opts.pid,
                Arc::<StackWalkerRun>::get_mut(&mut recorder.stack_recorder.lock().unwrap().psr)
                    .expect("unable to get psr from Arc"),
                skel.object(),
            );
        }

        for (i, map) in object.maps().enumerate() {
            let name = map.name().to_str().unwrap();
            if name.starts_with("ringbuf_events") {
                let ring = create_ring::<task_event>(&map, event_tx.clone())?;
                rings.push((format!("events_{}", i).to_string(), ring));
            } else if name.starts_with("ringbuf_stack") {
                let ring = create_ring::<stack_event>(&map, stack_tx.clone())?;
                rings.push((name.to_string(), ring));
            } else if name.starts_with("ringbuf_perf_counter") {
                if !perf_counter_names.is_empty() {
                    let ring = create_ring::<perf_counter_event>(&map, cache_tx.clone())?;
                    rings.push((name.to_string(), ring));
                }
            } else if name.starts_with("ringbuf_probe") {
                let ring = create_ring::<probe_event>(&map, probe_tx.clone())?;
                rings.push((name.to_string(), ring));
            }
        }

        // Drop the extra tx references
        drop(event_tx);
        drop(stack_tx);
        drop(cache_tx);
        drop(probe_tx);

        let mut recv_threads = Vec::new();
        let session_recorder = recorder.clone();
        let my_stop_tx = stop_tx.clone();
        recv_threads.push(
            thread::Builder::new()
                .name("sched_recorder".to_string())
                .spawn(move || {
                    consume_loop::<SchedEventRecorder, task_event>(
                        &session_recorder,
                        &session_recorder.event_recorder,
                        event_rx,
                        my_stop_tx,
                    );
                    0
                })?,
        );
        let session_recorder = recorder.clone();
        let my_stop_tx = stop_tx.clone();
        recv_threads.push(
            thread::Builder::new()
                .name("stack_recorder".to_string())
                .spawn(move || {
                    consume_loop::<StackRecorder, stack_event>(
                        &session_recorder,
                        &session_recorder.stack_recorder,
                        stack_rx,
                        my_stop_tx,
                    );
                    0
                })?,
        );
        let session_recorder = recorder.clone();
        let my_stop_tx = stop_tx.clone();
        recv_threads.push(
            thread::Builder::new()
                .name("probe_recorder".to_string())
                .spawn(move || {
                    consume_loop::<SystingProbeRecorder, probe_event>(
                        &session_recorder,
                        &session_recorder.probe_recorder,
                        probe_rx,
                        my_stop_tx,
                    );
                    0
                })?,
        );
        if !perf_counter_names.is_empty() {
            let session_recorder = recorder.clone();
            let my_stop_tx = stop_tx.clone();
            recv_threads.push(
                thread::Builder::new()
                    .name("perf_counter_recorder".to_string())
                    .spawn(move || {
                        consume_loop::<PerfCounterRecorder, perf_counter_event>(
                            &session_recorder,
                            &session_recorder.perf_counter_recorder,
                            cache_rx,
                            my_stop_tx,
                        );
                        0
                    })?,
            );
        } else {
            drop(cache_rx);
        }

        let mut clock_files = PerfOpenEvents::default();
        clock_files.add_hw_event(PerfHwEvent {
            name: "clock".to_string(),
            event_type: if opts.sw_event {
                perf::PERF_TYPE_SOFTWARE
            } else {
                perf::PERF_TYPE_HARDWARE
            },
            event_config: if opts.sw_event {
                perf::PERF_COUNT_SW_CPU_CLOCK
            } else {
                perf::PERF_COUNT_HW_CPU_CYCLES
            },
            disabled: false,
            need_slots: false,
            cpus: (0..num_cpus).collect(),
        })?;
        clock_files.open_events(None, 1000)?;
        let mut perf_links = Vec::new();
        for (_, file) in clock_files {
            let link = skel
                .progs
                .systing_perf_event_clock
                .attach_perf_event_with_opts(
                    file.as_raw_fd(),
                    libbpf_rs::PerfEventOpts {
                        cookie: 0,
                        ..Default::default()
                    },
                )?;
            perf_links.push(link);
        }

        let mut slots_files = PerfOpenEvents::default();
        if need_slots {
            let slot_hwevents = counters.event("slots");
            if slot_hwevents.is_none() {
                Err(anyhow::anyhow!("Failed to find slot event"))?;
            }
            let slot_hwevents = slot_hwevents.unwrap();
            for event in slot_hwevents.iter() {
                slots_files.add_hw_event(event.clone())?;
            }
            slots_files.open_events(None, 0)?;
            slots_files.enable()?;
        }

        let mut events_files = Vec::new();
        for (index, event_name) in perf_counter_names.iter().enumerate() {
            let mut event_files = PerfOpenEvents::default();
            let hwevents = counters.event(event_name).unwrap();

            for hwevent in hwevents {
                event_files.add_hw_event(hwevent)?;
            }
            event_files.open_events(Some(&slots_files), 0)?;

            let floor = index * num_cpus as usize;
            for (cpu, file) in &event_files {
                let key: u32 = (floor + *cpu as usize).try_into().unwrap();
                let key_val = key.to_ne_bytes();
                let fd_val = file.as_raw_fd().to_ne_bytes();
                skel.maps
                    .perf_counters
                    .update(&key_val, &fd_val, libbpf_rs::MapFlags::ANY)?;
            }
            event_files.enable()?;
            events_files.push(event_files);
        }

        skel.attach()?;

        // Attach any usdt's that we may have
        let mut probe_links = Vec::new();
        {
            let probe_recorder = recorder.probe_recorder.lock().unwrap();
            for event in probe_recorder.config_events.values() {
                for key in event.keys.iter() {
                    let key_type = match key.key_type {
                        EventKeyType::String => arg_type::ARG_STRING,
                        EventKeyType::Long => arg_type::ARG_LONG,
                    };

                    let desc = arg_desc {
                        arg_type: key_type,
                        arg_index: key.key_index as i32,
                    };

                    // Safe because we're not padded
                    let desc_data = unsafe { plain::as_bytes(&desc) };
                    skel.maps.event_key_types.update(
                        &event.cookie.to_ne_bytes(),
                        desc_data,
                        libbpf_rs::MapFlags::ANY,
                    )?;
                }

                match &event.event {
                    EventProbe::Usdt(usdt) => {
                        for pid in opts.trace_event_pid.iter() {
                            let link = skel.progs.systing_usdt.attach_usdt_with_opts(
                                *pid as i32,
                                &usdt.path,
                                &usdt.provider,
                                &usdt.name,
                                UsdtOpts {
                                    cookie: event.cookie,
                                    ..Default::default()
                                },
                            );
                            if link.is_err() {
                                Err(anyhow::anyhow!("Failed to connect pid {}", *pid))?;
                            }
                            probe_links.push(link);
                        }
                    }
                    EventProbe::UProbe(uprobe) => {
                        for pid in opts.trace_event_pid.iter() {
                            let link = skel.progs.systing_uprobe.attach_uprobe_with_opts(
                                *pid as i32,
                                &uprobe.path,
                                uprobe.offset as usize,
                                UprobeOpts {
                                    cookie: event.cookie,
                                    retprobe: uprobe.retprobe,
                                    func_name: Some(uprobe.func_name.clone()),
                                    ..Default::default()
                                },
                            );
                            if link.is_err() {
                                Err(anyhow::anyhow!("Failed to connect pid {}", *pid))?;
                            }
                            probe_links.push(link);
                        }
                    }
                    EventProbe::KProbe(kprobe) => {
                        let link = skel.progs.systing_kprobe.attach_kprobe_with_opts(
                            kprobe.retprobe,
                            &kprobe.func_name,
                            libbpf_rs::KprobeOpts {
                                cookie: event.cookie,
                                ..Default::default()
                            },
                        );
                        if link.is_err() {
                            Err(anyhow::anyhow!(
                                "Failed to attach kprobe {}",
                                kprobe.func_name
                            ))?;
                        }
                        probe_links.push(link);
                    }
                    EventProbe::Tracepoint(tracepoint) => {
                        let link = if old_kernel {
                            let category =
                                libbpf_rs::TracepointCategory::Custom(tracepoint.category.clone());
                            skel.progs.systing_tracepoint.attach_tracepoint_with_opts(
                                category,
                                &tracepoint.name,
                                TracepointOpts {
                                    cookie: event.cookie,
                                    ..Default::default()
                                },
                            )
                        } else {
                            skel.progs
                                .systing_raw_tracepoint
                                .attach_raw_tracepoint_with_opts(
                                    &tracepoint.name,
                                    RawTracepointOpts {
                                        cookie: event.cookie,
                                        ..Default::default()
                                    },
                                )
                        };
                        if link.is_err() {
                            Err(anyhow::anyhow!(
                                "Failed to attach tracepoint {}",
                                tracepoint.name
                            ))?;
                        }
                        probe_links.push(link);
                    }
                    _ => {}
                }
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
                            let ts = get_clock_value(libc::CLOCK_BOOTTIME);
                            {
                                let mut recorder =
                                    sysinfo_recorder.sysinfo_recorder.lock().unwrap();
                                for (i, cpu) in sys.cpus().iter().enumerate() {
                                    let event = SysInfoEvent {
                                        ts,
                                        cpu: i as u32,
                                        frequency: cpu.frequency() as i64,
                                    };
                                    recorder.record_event(event);
                                }
                            }
                            thread::sleep(Duration::from_millis(100));
                        }
                        0
                    })?,
            );
        }

        if opts.duration > 0 {
            println!("Tracing for {} seconds", opts.duration);
            thread::sleep(Duration::from_secs(opts.duration));
        } else {
            ctrlc::set_handler(move || {
                stop_tx.send(()).expect("Could not send signal on channel.")
            })
            .expect("Error setting Ctrl-C handler");
            if opts.continuous > 0 {
                println!("Tracing in a continues loop of {} seconds", opts.continuous);
                println!("Will stop if a trigger is specified, otherwise Ctrl-C to stop");
            } else {
                println!("Tracing indefinitely...");
                println!("Press Ctrl-C to stop");
            }
            stop_rx
                .recv()
                .expect("Could not receive signal on channel.");
        }

        if opts.continuous > 0 {
            println!("Asked to stop, waiting 1 second before stopping");
            thread::sleep(Duration::from_secs(1));
        }
        println!("Stopping...");
        skel.maps.data_data.as_deref_mut().unwrap().tracing_enabled = false;
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
        println!("Missed probe events: {}", dump_missed_events(&skel, 2));
        println!("Missed perf events: {}", dump_missed_events(&skel, 3));
    }

    if opts.continuous > 0 {
        println!("Draining recorder ringbuffers...");
        recorder.event_recorder.lock().unwrap().drain_ringbuf();
        recorder.stack_recorder.lock().unwrap().drain_ringbuf();
        recorder
            .perf_counter_recorder
            .lock()
            .unwrap()
            .drain_ringbuf();
        recorder.sysinfo_recorder.lock().unwrap().drain_ringbuf();
        recorder.probe_recorder.lock().unwrap().drain_ringbuf();
    }

    println!("Generating trace...");
    let mut trace = Trace::default();
    trace.packet.extend(recorder.generate_trace());
    let mut file = std::fs::File::create("trace.pb")?;
    trace.write_to_writer(&mut file)?;
    Ok(())
}

fn main() -> Result<()> {
    let opts = Command::parse();
    bump_memlock_rlimit()?;

    system(opts)
}
