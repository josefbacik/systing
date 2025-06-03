pub mod events;
pub mod perf;
mod perf_recorder;
pub mod perfetto;
pub mod ringbuf;
pub mod symbolize;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::CStr;
use std::mem;
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::process;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::Duration;

use crate::events::{EventProbe, SystingProbeEvent, SystingProbeRecorder};
use crate::perf::{PerfCounters, PerfHwEvent, PerfOpenEvents};
use crate::perf_recorder::{PerfCounterEvent, PerfCounterRecorder};
use crate::perfetto::TrackCounter;
use crate::ringbuf::RingBuffer;
use crate::symbolize::Stack;

use anyhow::bail;
use anyhow::Result;
use clap::Parser;

use blazesym::symbolize::source::{Kernel, Process, Source};
use blazesym::symbolize::{cache, Input, Sym, Symbolized, Symbolizer};
use blazesym::Pid;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{MapCore, RingBufferBuilder, TracepointOpts, UprobeOpts, UsdtOpts};
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
    fn record_event(&mut self, event: T) -> bool;
}

pub trait SystingEventTS {
    fn ts(&self) -> u64;
}

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

impl SystingEventTS for task_event {
    fn ts(&self) -> u64 {
        self.ts
    }
}

impl SystingEventTS for stack_event {
    fn ts(&self) -> u64 {
        self.ts
    }
}

impl SystingEventTS for perf_counter_event {
    fn ts(&self) -> u64 {
        self.ts
    }
}

impl SystingEventTS for probe_event {
    fn ts(&self) -> u64 {
        self.ts
    }
}

impl SystingEventTS for SysInfoEvent {
    fn ts(&self) -> u64 {
        self.ts
    }
}

impl From<&perf_counter_event> for PerfCounterEvent {
    fn from(event: &perf_counter_event) -> Self {
        PerfCounterEvent {
            cpu: event.cpu,
            index: event.counter_num as usize,
            value: event.value.counter as i64,
            ts: event.ts,
        }
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
struct LocalCompactSched {
    compact_sched: CompactSched,
    comm_mapping: HashMap<String, u32>,
    last_waking_ts: u64,
    last_switch_ts: u64,
}

#[derive(Default)]
struct EventRecorder {
    ringbuf: RingBuffer<task_event>,
    events: HashMap<u32, BTreeMap<u64, FtraceEvent>>,
    compact_sched: HashMap<u32, LocalCompactSched>,
    runqueue: HashMap<i32, Vec<TrackCounter>>,
    cpu_latencies: HashMap<u32, Vec<TrackCounter>>,
    process_latencies: HashMap<u64, Vec<TrackCounter>>,
    rq_counters: HashMap<i32, i64>,
    cpu_sched_stats: bool,
    process_sched_stats: bool,
}

#[derive(Default)]
struct StackRecorder {
    ringbuf: RingBuffer<stack_event>,
    stacks: HashMap<i32, Vec<StackEvent>>,
}

#[derive(Default)]
struct SysinfoRecorder {
    ringbuf: RingBuffer<SysInfoEvent>,
    frequency: HashMap<u32, Vec<TrackCounter>>,
}

#[derive(Default)]
struct SessionRecorder {
    clock_snapshot: Mutex<ClockSnapshot>,
    event_recorder: Mutex<EventRecorder>,
    stack_recorder: Mutex<StackRecorder>,
    perf_counter_recorder: Mutex<PerfCounterRecorder>,
    sysinfo_recorder: Mutex<SysinfoRecorder>,
    probe_recorder: Mutex<SystingProbeRecorder>,
    processes: RwLock<HashMap<u64, ProcessDescriptor>>,
    threads: RwLock<HashMap<u64, ThreadDescriptor>>,
}

fn get_clock_value(clock_id: libc::c_int) -> u64 {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(clock_id, &mut ts) } != 0 {
        return 0;
    }
    (ts.tv_sec as u64 * 1_000_000_000) + ts.tv_nsec as u64
}

fn add_frame(
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
        stack_to_frames_mapping(
            &mut symbolizer,
            &mut frame_map,
            &mut func_name_map,
            &kernel_src,
            id_counter,
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
            let iid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;
            callstack.set_iid(iid);
            callstack.frame_ids = stack
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
                .collect();
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

impl SystingRecordEvent<task_event> for EventRecorder {
    fn record_event(&mut self, event: task_event) -> bool {
        if self.ringbuf.max_duration() == 0 {
            // If the ring buffer is not enabled, we just handle the event directly.
            self.handle_event(event);
        } else {
            // Otherwise, we push the event into the ring buffer.
            self.ringbuf.push_front(event);
        }
        false
    }
}

impl EventRecorder {
    fn handle_event(&mut self, event: task_event) {
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

    fn drain_ringbuf(&mut self) {
        while let Some(event) = self.ringbuf.pop_back() {
            self.handle_event(event);
        }
    }

    fn generate_trace(
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
}

impl SystingRecordEvent<stack_event> for StackRecorder {
    fn record_event(&mut self, event: stack_event) -> bool {
        if self.ringbuf.max_duration() == 0 {
            // If the ring buffer is not enabled, we just handle the event directly.
            self.handle_event(event);
        } else {
            // Otherwise, we push the event into the ring buffer.
            self.ringbuf.push_front(event);
        }
        false
    }
}

impl StackRecorder {
    fn handle_event(&mut self, event: stack_event) {
        if event.user_stack_length > 0 || event.kernel_stack_length > 0 {
            let kstack_vec = Vec::from(&event.kernel_stack[..event.kernel_stack_length as usize]);
            let ustack_vec = Vec::from(&event.user_stack[..event.user_stack_length as usize]);
            let stack_key = (event.task.tgidpid >> 32) as i32;
            let stack = StackEvent {
                tgidpid: event.task.tgidpid,
                ts_start: event.ts,
                stack: Stack::new(&kstack_vec, &ustack_vec),
            };
            let stacks = self.stacks.entry(stack_key).or_default();
            stacks.push(stack);
        }
    }

    fn drain_ringbuf(&mut self) {
        while let Some(event) = self.ringbuf.pop_back() {
            self.handle_event(event);
        }
    }

    fn generate_trace(&self, id_counter: &mut Arc<AtomicUsize>) -> Vec<TracePacket> {
        use workerpool::thunk::{Thunk, ThunkWorker};
        use workerpool::Pool;

        let packets = Arc::new(Mutex::new(Vec::new()));
        let pool = Pool::<ThunkWorker<()>>::new(4);

        // Resolve the stacks, generate the interned data for them, and populate the trace.
        for (tgid, stacks) in self.stacks.iter() {
            let mut id_counter = id_counter.clone();
            let stacks = stacks.clone();
            let tgid = *tgid as u32;
            let mut packets = packets.clone();
            pool.execute(Thunk::of(move || {
                generate_stack_packets(&mut packets, tgid, stacks, &mut id_counter)
            }));
        }
        pool.join();
        let packets = mem::take(&mut *packets.lock().unwrap());
        packets
    }
}

impl SystingRecordEvent<perf_counter_event> for PerfCounterRecorder {
    fn record_event(&mut self, event: perf_counter_event) -> bool {
        let event = PerfCounterEvent::from(&event);
        if self.ringbuf.max_duration() == 0 {
            // If the ring buffer is not enabled, we just handle the event directly.
            self.handle_event(event);
        } else {
            // Otherwise, we push the event into the ring buffer.
            self.ringbuf.push_front(event);
        }
        false
    }
}

impl SystingRecordEvent<probe_event> for SystingProbeRecorder {
    fn record_event(&mut self, event: probe_event) -> bool {
        let mut extra = "".to_string();

        // Capture the arg if there is one.
        match event.arg_type {
            systing::types::arg_type::ARG_LONG => {
                let mut bytes: [u8; 8] = [0; 8];
                let _ = bytes.copy_from_bytes(&event.arg[..8]);
                let val = u64::from_ne_bytes(bytes);
                extra = format!(":{}", val);
            }
            systing::types::arg_type::ARG_STRING => {
                let arg_str = CStr::from_bytes_until_nul(&event.arg);
                if arg_str.is_ok() {
                    let arg_str = arg_str.unwrap();
                    let bytes = arg_str.to_bytes();
                    if !bytes.is_empty() && !bytes.starts_with(&[0]) {
                        extra = format!(":{}", arg_str.to_string_lossy());
                    }
                }
            }
            _ => {}
        }
        let probe_event = SystingProbeEvent {
            tgidpid: event.task.tgidpid,
            cookie: event.cookie,
            ts: event.ts,
            extra,
        };

        // If the ring buffer is not enabled, we just handle the event directly.
        if self.ringbuf.max_duration() == 0 {
            self.handle_event(probe_event);
        } else {
            let ret = self.maybe_trigger(&probe_event);
            // Otherwise, we push the event into the ring buffer.
            self.ringbuf.push_front(probe_event);
            return ret;
        }
        false
    }
}

impl SystingRecordEvent<SysInfoEvent> for SysinfoRecorder {
    fn record_event(&mut self, event: SysInfoEvent) -> bool {
        if self.ringbuf.max_duration() == 0 {
            // If the ring buffer is not enabled, we just handle the event directly.
            self.handle_event(event);
        } else {
            // Otherwise, we push the event into the ring buffer.
            self.ringbuf.push_front(event);
        }
        false
    }
}

impl SysinfoRecorder {
    fn handle_event(&mut self, event: SysInfoEvent) {
        let freq = self.frequency.entry(event.cpu).or_default();
        freq.push(TrackCounter {
            ts: event.ts,
            count: event.frequency,
        });
    }

    fn drain_ringbuf(&mut self) {
        while let Some(event) = self.ringbuf.pop_back() {
            self.handle_event(event);
        }
    }

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
        let mut id_counter = Arc::new(AtomicUsize::new(0));
        let mut pid_uuids = HashMap::new();
        let mut thread_uuids = HashMap::new();

        // First emit the clock snapshot
        let mut packet = TracePacket::default();
        packet.set_clock_snapshot(self.clock_snapshot.lock().unwrap().clone());
        packet.set_trusted_packet_sequence_id(id_counter.fetch_add(1, Ordering::Relaxed) as u32);
        packets.push(packet);

        // Ppopulate all the process tracks
        for process in self.processes.read().unwrap().values() {
            let uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;
            pid_uuids.insert(process.pid(), uuid);

            let mut desc = TrackDescriptor::default();
            desc.set_uuid(uuid);
            desc.process = Some(process.clone()).into();

            let mut packet = TracePacket::default();
            packet.set_track_descriptor(desc);
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
            .processes
            .read()
            .unwrap()
            .contains_key(&info.tgidpid)
        {
            session_recorder
                .processes
                .write()
                .unwrap()
                .insert(info.tgidpid, ProcessDescriptor::from(info));
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
                    loop {
                        let res = event_rx.recv();
                        if res.is_err() {
                            break;
                        }
                        let event = res.unwrap();
                        maybe_record_task(&event.prev, &session_recorder);
                        match event.r#type {
                            event_type::SCHED_SWITCH
                            | event_type::SCHED_WAKING
                            | event_type::SCHED_WAKEUP
                            | event_type::SCHED_WAKEUP_NEW => {
                                maybe_record_task(&event.next, &session_recorder);
                            }
                            _ => {}
                        }
                        let stop = session_recorder
                            .event_recorder
                            .lock()
                            .unwrap()
                            .record_event(event);
                        if stop {
                            my_stop_tx.send(()).expect("Failed to send stop signal");
                        }
                    }
                    0
                })?,
        );
        let session_recorder = recorder.clone();
        let my_stop_tx = stop_tx.clone();
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
                        maybe_record_task(&event.task, &session_recorder);
                        let ret = session_recorder
                            .stack_recorder
                            .lock()
                            .unwrap()
                            .record_event(event);
                        if ret {
                            my_stop_tx.send(()).expect("Failed to send stop signal");
                        }
                    }
                    0
                })?,
        );
        let session_recorder = recorder.clone();
        let my_stop_tx = stop_tx.clone();
        recv_threads.push(
            thread::Builder::new()
                .name("probe_recorder".to_string())
                .spawn(move || {
                    loop {
                        let res = probe_rx.recv();
                        if res.is_err() {
                            break;
                        }
                        let event = res.unwrap();
                        maybe_record_task(&event.task, &session_recorder);
                        let ret = session_recorder
                            .probe_recorder
                            .lock()
                            .unwrap()
                            .record_event(event);
                        if ret {
                            my_stop_tx.send(()).expect("Failed to send stop signal");
                        }
                    }
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
                        loop {
                            let res = cache_rx.recv();
                            if res.is_err() {
                                break;
                            }
                            let event = res.unwrap();
                            maybe_record_task(&event.task, &session_recorder);
                            let ret = session_recorder
                                .perf_counter_recorder
                                .lock()
                                .unwrap()
                                .record_event(event);
                            if ret {
                                my_stop_tx.send(()).expect("Failed to send stop signal");
                            }
                        }
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
                        let category =
                            libbpf_rs::TracepointCategory::Custom(tracepoint.category.clone());
                        let link = skel.progs.systing_tracepoint.attach_tracepoint_with_opts(
                            category,
                            &tracepoint.name,
                            TracepointOpts {
                                cookie: event.cookie,
                                ..Default::default()
                            },
                        );
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
            let my_stop_tx = stop_tx.clone();
            ctrlc::set_handler(move || {
                my_stop_tx
                    .send(())
                    .expect("Could not send signal on channel.")
            })
            .expect("Error setting Ctrl-C handler");
            if opts.continuous > 0 {
                println!("Tracing in a continues loop of {} seconds", opts.continuous);
                println!("Will stop if a trigger is specified, otherwise Ctrl-C to stop");
            } else {
                println!("Tracing indefinitely...");
                println!("Press Ctrl-C to stop");
            }
            drop(stop_tx);
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
