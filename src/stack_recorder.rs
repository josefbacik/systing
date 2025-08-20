use std::collections::{HashMap, HashSet};
use std::mem;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::pystacks::stack_walker::{
    get_pystack_from_event, load_pystack_symbols, merge_pystacks, pystacks_to_frames_mapping,
    user_stack_to_python_calls, StackWalkerRun,
};
use crate::ringbuf::RingBuffer;
use crate::symbolize::Stack;
use crate::systing::types::stack_event;
use crate::SystingRecordEvent;

use blazesym::symbolize::source::{Kernel, Process, Source};
use blazesym::symbolize::{cache, Input, Sym, Symbolized, Symbolizer};
use blazesym::Pid;
use perfetto_protos::interned_data::InternedData;
use perfetto_protos::profile_common::{Callstack, Frame, InternedString, Mapping};
use perfetto_protos::profile_packet::PerfSample;
use perfetto_protos::trace_packet::trace_packet::SequenceFlags;
use perfetto_protos::trace_packet::TracePacket;

#[derive(Clone)]
pub struct StackEvent {
    pub tgidpid: u64,
    pub ts_start: u64,
    pub stack: Stack,
}

#[derive(Default)]
pub struct LocalFrame {
    pub frame: Frame,
    pub mapping: Mapping,
}

#[derive(Default)]
pub struct StackRecorder {
    pub ringbuf: RingBuffer<stack_event>,
    pub stacks: HashMap<i32, Vec<StackEvent>>,
    pub psr: Arc<StackWalkerRun>,
}

pub fn add_frame(
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

pub fn stack_to_frames_mapping<'a, I>(
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

pub fn generate_stack_packets(
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
    pub fn generate_trace(&self, id_counter: &mut Arc<AtomicUsize>) -> Vec<TracePacket> {
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
