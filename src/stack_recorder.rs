use std::collections::{HashMap, HashSet};
use std::mem;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::pystacks::stack_walker::{PyAddr, StackWalkerRun};
use crate::ringbuf::RingBuffer;
use crate::systing::types::stack_event;
use crate::SystingRecordEvent;

use blazesym::symbolize::source::{Kernel, Process, Source};
use blazesym::symbolize::{cache, Input, Sym, Symbolized, Symbolizer};
use blazesym::{Addr, Pid};
use perfetto_protos::interned_data::InternedData;
use perfetto_protos::profile_common::{Callstack, Frame, InternedString, Mapping};
use perfetto_protos::profile_packet::PerfSample;
use perfetto_protos::trace_packet::trace_packet::SequenceFlags;
use perfetto_protos::trace_packet::TracePacket;

// Constants for special stack markers
pub const KERNEL_THREAD_STACK_STUB: u64 = 1234;
pub const PREEMPT_EVENT_STACK_STUB: u64 = 5678;

// Stack structure representing kernel, user, and Python stacks
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Stack {
    pub kernel_stack: Vec<Addr>,
    pub user_stack: Vec<Addr>,
    pub py_stack: Vec<PyAddr>,
}

impl Stack {
    pub fn new(kernel_stack: &[u64], user_stack: &[u64], py_stack: &[PyAddr]) -> Self {
        let first_kernel_element = if kernel_stack.is_empty() {
            0
        } else {
            kernel_stack[0]
        };
        let first_user_element = if user_stack.is_empty() {
            0
        } else {
            user_stack[0]
        };
        let my_kernel_stack = match first_kernel_element {
            PREEMPT_EVENT_STACK_STUB => vec![],
            _ => kernel_stack
                .iter()
                .rev()
                .filter(|x| **x > 0)
                .copied()
                .collect(),
        };
        let my_user_stack = match first_user_element {
            KERNEL_THREAD_STACK_STUB => vec![],
            PREEMPT_EVENT_STACK_STUB => vec![PREEMPT_EVENT_STACK_STUB],
            _ => user_stack
                .iter()
                .rev()
                .filter(|x| **x > 0)
                .copied()
                .collect(),
        };
        Stack {
            kernel_stack: my_kernel_stack,
            user_stack: my_user_stack,
            py_stack: py_stack.to_vec(),
        }
    }
}

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

/// Holds the resolved stack information after symbolization
pub struct ResolvedStackInfo {
    pub frame_map: HashMap<u64, Vec<LocalFrame>>,
    pub func_name_map: HashMap<String, InternedString>,
    pub python_calls: Vec<u64>,
    pub python_stack_markers: Vec<u64>,
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

/// Symbolizes all stacks (user, kernel, and Python) and returns the resolved information
fn symbolize_stacks(
    stacks: &[StackEvent],
    tgid: u32,
    id_counter: &mut Arc<AtomicUsize>,
    psr: &mut Arc<StackWalkerRun>,
) -> ResolvedStackInfo {
    let user_src = Source::Process(Process::new(Pid::from(tgid)));
    let kernel_src = Source::Kernel(Kernel::default());
    let mut symbolizer = Symbolizer::builder()
        .enable_code_info(true)
        .enable_inlined_fns(true)
        .build();

    let _ = symbolizer.cache(&cache::Cache::from(cache::Process::new(tgid.into())));

    let mut frame_map = HashMap::new();
    let mut func_name_map = HashMap::new();
    let mut python_calls = Vec::new();
    let mut python_stack_markers = Vec::new();

    for stack in stacks.iter() {
        let raw_stack = &stack.stack;
        // Symbolize user space stack
        stack_to_frames_mapping(
            &mut symbolizer,
            &mut frame_map,
            &mut func_name_map,
            &user_src,
            id_counter,
            raw_stack.user_stack.iter(),
        );
        psr.user_stack_to_python_calls(&mut frame_map, &mut func_name_map, &mut python_calls);
        // Symbolize kernel stack
        stack_to_frames_mapping(
            &mut symbolizer,
            &mut frame_map,
            &mut func_name_map,
            &kernel_src,
            id_counter,
            raw_stack.kernel_stack.iter(),
        );
        // Symbolize Python stack
        psr.pystacks_to_frames_mapping(
            &mut frame_map,
            &mut func_name_map,
            id_counter,
            &mut python_stack_markers,
            &raw_stack.py_stack,
        );
    }

    ResolvedStackInfo {
        frame_map,
        func_name_map,
        python_calls,
        python_stack_markers,
    }
}

/// Deduplicates stacks and creates callstack mappings
fn deduplicate_stacks(
    stacks: &[StackEvent],
    resolved_info: &ResolvedStackInfo,
    id_counter: &mut Arc<AtomicUsize>,
    psr: &Arc<StackWalkerRun>,
) -> HashMap<Stack, Callstack> {
    stacks
        .iter()
        .map(|stack| stack.stack.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .map(|stack| {
            let mut callstack = Callstack::default();
            let iid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;
            callstack.set_iid(iid);
            callstack.frame_ids = if stack.py_stack.is_empty() {
                // No Python stack - just chain user and kernel stacks
                stack
                    .user_stack
                    .iter()
                    .chain(stack.kernel_stack.iter())
                    .flat_map(|addr| {
                        let frame_vec = resolved_info.frame_map.get(addr).unwrap();
                        frame_vec
                            .iter()
                            .map(|frame| frame.frame.iid())
                            .collect::<Vec<u64>>()
                    })
                    .collect()
            } else {
                // Merge Python stacks with user stacks
                let merged_addrs = psr.merge_pystacks(
                    &stack,
                    &resolved_info.python_calls,
                    &resolved_info.python_stack_markers,
                );

                merged_addrs
                    .iter()
                    .chain(stack.kernel_stack.iter())
                    .flat_map(|addr| {
                        let frame_vec = resolved_info.frame_map.get(addr).unwrap();
                        frame_vec
                            .iter()
                            .map(|frame| frame.frame.iid())
                            .collect::<Vec<u64>>()
                    })
                    .collect()
            };
            (stack, callstack)
        })
        .collect()
}

/// Generates trace packets from the deduplicated stacks and resolved information
fn generate_trace_packets(
    stacks: &[StackEvent],
    interned_stacks: &HashMap<Stack, Callstack>,
    resolved_info: &ResolvedStackInfo,
    id_counter: &mut Arc<AtomicUsize>,
) -> Vec<TracePacket> {
    let mut packets = Vec::new();
    let seq = id_counter.fetch_add(1, Ordering::Relaxed) as u32;
    // Generate interned data packet
    let mut packet = TracePacket::default();
    let interned_data = InternedData {
        callstacks: interned_stacks.values().cloned().collect(),
        function_names: resolved_info.func_name_map.values().cloned().collect(),
        frames: resolved_info
            .frame_map
            .values()
            .flat_map(|frame_vec| {
                frame_vec
                    .iter()
                    .map(|frame| frame.frame.clone())
                    .collect::<Vec<Frame>>()
            })
            .collect(),
        mappings: resolved_info
            .frame_map
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
    packets.push(packet);

    // Generate sample packets for each stack
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
    packets
}

pub fn generate_stack_packets(
    packets: &mut Arc<Mutex<Vec<TracePacket>>>,
    tgid: u32,
    stacks: Vec<StackEvent>,
    id_counter: &mut Arc<AtomicUsize>,
    psr: &mut Arc<StackWalkerRun>,
) {
    // Step 1: Symbolize all stacks
    let resolved_info = symbolize_stacks(&stacks, tgid, id_counter, psr);
    // Step 2: Deduplicate stacks
    let interned_stacks = deduplicate_stacks(&stacks, &resolved_info, id_counter, psr);
    // Step 3: Generate trace packets
    let trace_packets =
        generate_trace_packets(&stacks, &interned_stacks, &resolved_info, id_counter);
    // Add packets to the shared collection
    packets.lock().unwrap().extend(trace_packets);
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
            let py_stack = self.psr.get_pystack_from_event(&event);

            let stack = StackEvent {
                tgidpid: event.task.tgidpid,
                ts_start: event.ts,
                stack: Stack::new(&kstack_vec, &ustack_vec, &py_stack),
            };
            let stacks = self.stacks.entry(stack_key).or_default();
            stacks.push(stack);
        }

        self.psr.load_pystack_symbols(&event);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    fn create_test_stack_event(
        tgidpid: u64,
        ts: u64,
        user_addrs: Vec<u64>,
        kernel_addrs: Vec<u64>,
    ) -> StackEvent {
        StackEvent {
            tgidpid,
            ts_start: ts,
            stack: Stack::new(&kernel_addrs, &user_addrs, &Vec::new()),
        }
    }

    fn create_test_resolved_info() -> ResolvedStackInfo {
        let mut frame_map = HashMap::new();
        let mut func_name_map = HashMap::new();
        let mut id_counter = Arc::new(AtomicUsize::new(1));

        // Add test frames for addresses using add_frame()
        add_frame(
            &mut frame_map,
            &mut func_name_map,
            &mut id_counter,
            0x1000,
            0x1000,
            0,
            "test_func1".to_string(),
        );
        add_frame(
            &mut frame_map,
            &mut func_name_map,
            &mut id_counter,
            0x2000,
            0x2000,
            16,
            "test_func1".to_string(),
        );
        add_frame(
            &mut frame_map,
            &mut func_name_map,
            &mut id_counter,
            0x3000,
            0x3000,
            0,
            "test_func2".to_string(),
        );
        add_frame(
            &mut frame_map,
            &mut func_name_map,
            &mut id_counter,
            0x4000,
            0x4000,
            32,
            "test_func2".to_string(),
        );

        ResolvedStackInfo {
            frame_map,
            func_name_map,
            python_calls: Vec::new(),
            python_stack_markers: Vec::new(),
        }
    }

    #[test]
    fn test_add_frame_new_address() {
        let mut frame_map = HashMap::new();
        let mut func_map = HashMap::new();
        let mut id_counter = Arc::new(AtomicUsize::new(100));

        add_frame(
            &mut frame_map,
            &mut func_map,
            &mut id_counter,
            0x5000, // input_addr
            0x4800, // start_addr
            0x200,  // offset
            "my_function".to_string(),
        );

        // Check that the frame was added to the map
        assert!(frame_map.contains_key(&0x5000));
        let frames = frame_map.get(&0x5000).unwrap();
        assert_eq!(frames.len(), 1);

        // Check frame properties
        let frame = &frames[0].frame;
        assert!(frame.iid() >= 100);
        assert_eq!(frame.rel_pc(), 0x200);

        // Check mapping properties
        let mapping = &frames[0].mapping;
        assert!(mapping.iid() >= 100);
        assert_eq!(mapping.exact_offset(), 0x5000);
        assert_eq!(mapping.start_offset(), 0x4800);

        // Check that function was added to func_map
        assert!(func_map.contains_key("my_function"));
        let func = func_map.get("my_function").unwrap();
        assert!(func.iid() >= 100);
        assert_eq!(func.str(), b"my_function");
    }

    #[test]
    fn test_add_frame_multiple_frames_same_address() {
        let mut frame_map = HashMap::new();
        let mut func_map = HashMap::new();
        let mut id_counter = Arc::new(AtomicUsize::new(100));

        // Add first frame
        add_frame(
            &mut frame_map,
            &mut func_map,
            &mut id_counter,
            0x5000,
            0x4800,
            0x200,
            "function1".to_string(),
        );

        // Add second frame at same address (e.g., inlined function)
        add_frame(
            &mut frame_map,
            &mut func_map,
            &mut id_counter,
            0x5000,
            0x4800,
            0,
            "function2 (inlined)".to_string(),
        );

        // Check that both frames are in the vector for this address
        let frames = frame_map.get(&0x5000).unwrap();
        assert_eq!(frames.len(), 2);

        // Check that each frame has unique IIDs
        assert_ne!(frames[0].frame.iid(), frames[1].frame.iid());
        assert_ne!(frames[0].mapping.iid(), frames[1].mapping.iid());

        // Check that both functions are in func_map
        assert_eq!(func_map.len(), 2);
        assert!(func_map.contains_key("function1"));
        assert!(func_map.contains_key("function2 (inlined)"));
    }

    #[test]
    fn test_add_frame_reuses_existing_function() {
        let mut frame_map = HashMap::new();
        let mut func_map = HashMap::new();
        let mut id_counter = Arc::new(AtomicUsize::new(100));

        // Add first frame with function "common_func"
        add_frame(
            &mut frame_map,
            &mut func_map,
            &mut id_counter,
            0x5000,
            0x4800,
            0x200,
            "common_func".to_string(),
        );

        let func_iid_first = func_map.get("common_func").unwrap().iid();

        // Add second frame with same function name but different address
        add_frame(
            &mut frame_map,
            &mut func_map,
            &mut id_counter,
            0x6000,
            0x5800,
            0x200,
            "common_func".to_string(),
        );

        // Check that function map still has only one entry for "common_func"
        assert_eq!(func_map.len(), 1);

        // Check that the same function IID is reused
        let func_iid_second = func_map.get("common_func").unwrap().iid();
        assert_eq!(func_iid_first, func_iid_second);

        // Check that frames at different addresses reference the same function
        let frame1 = &frame_map.get(&0x5000).unwrap()[0].frame;
        let frame2 = &frame_map.get(&0x6000).unwrap()[0].frame;
        assert_eq!(frame1.function_name_id(), frame2.function_name_id());
    }

    #[test]
    fn test_add_frame_id_counter_increments() {
        let mut frame_map = HashMap::new();
        let mut func_map = HashMap::new();
        let mut id_counter = Arc::new(AtomicUsize::new(100));

        let initial_count = id_counter.load(Ordering::Relaxed);

        add_frame(
            &mut frame_map,
            &mut func_map,
            &mut id_counter,
            0x5000,
            0x4800,
            0x200,
            "test_func".to_string(),
        );

        let final_count = id_counter.load(Ordering::Relaxed);

        // Should have incremented for: function IID, frame IID, mapping IID
        // That's 3 increments minimum
        assert!(final_count >= initial_count + 3);
    }

    #[test]
    fn test_deduplicate_stacks_empty() {
        let stacks = vec![];
        let resolved_info = create_test_resolved_info();
        let mut id_counter = Arc::new(AtomicUsize::new(100));

        let result = deduplicate_stacks(&stacks, &resolved_info, &mut id_counter, &Arc::new(StackWalkerRun::default()));

        assert!(result.is_empty());
    }

    #[test]
    fn test_deduplicate_stacks_single_stack() {
        let stack = create_test_stack_event(
            (1234 << 32) | 5678,
            1000000,
            vec![0x1000, 0x2000],
            vec![0x3000, 0x4000],
        );
        let stacks = vec![stack.clone()];
        let resolved_info = create_test_resolved_info();
        let mut id_counter = Arc::new(AtomicUsize::new(100));

        let result = deduplicate_stacks(&stacks, &resolved_info, &mut id_counter, &Arc::new(StackWalkerRun::default()));

        assert_eq!(result.len(), 1);
        assert!(result.contains_key(&stack.stack));

        let callstack = result.get(&stack.stack).unwrap();
        assert!(callstack.iid() >= 100); // Should have assigned an ID
        assert!(!callstack.frame_ids.is_empty());
    }

    #[test]
    fn test_deduplicate_stacks_duplicate_stacks() {
        let stack1 = create_test_stack_event(
            (1234 << 32) | 5678,
            1000000,
            vec![0x1000, 0x2000],
            vec![0x3000, 0x4000],
        );
        let stack2 = create_test_stack_event(
            (1234 << 32) | 5679, // Different PID, same stack
            2000000,
            vec![0x1000, 0x2000],
            vec![0x3000, 0x4000],
        );
        let stacks = vec![stack1.clone(), stack2.clone()];
        let resolved_info = create_test_resolved_info();
        let mut id_counter = Arc::new(AtomicUsize::new(100));

        let result = deduplicate_stacks(&stacks, &resolved_info, &mut id_counter, &Arc::new(StackWalkerRun::default()));

        // Should only have one unique stack
        assert_eq!(result.len(), 1);
        assert!(result.contains_key(&stack1.stack));
    }

    #[test]
    fn test_deduplicate_stacks_different_stacks() {
        let stack1 =
            create_test_stack_event((1234 << 32) | 5678, 1000000, vec![0x1000], vec![0x3000]);
        let stack2 =
            create_test_stack_event((1234 << 32) | 5679, 2000000, vec![0x2000], vec![0x4000]);
        let stacks = vec![stack1.clone(), stack2.clone()];
        let resolved_info = create_test_resolved_info();
        let mut id_counter = Arc::new(AtomicUsize::new(100));

        let result = deduplicate_stacks(&stacks, &resolved_info, &mut id_counter, &Arc::new(StackWalkerRun::default()));

        // Should have two unique stacks
        assert_eq!(result.len(), 2);
        assert!(result.contains_key(&stack1.stack));
        assert!(result.contains_key(&stack2.stack));
    }

    #[test]
    fn test_generate_trace_packets_empty() {
        let stacks = vec![];
        let interned_stacks = HashMap::new();
        let resolved_info = create_test_resolved_info();
        let mut id_counter = Arc::new(AtomicUsize::new(100));

        let packets =
            generate_trace_packets(&stacks, &interned_stacks, &resolved_info, &mut id_counter);

        // Should still have at least one packet with interned data
        assert!(packets.len() >= 1);

        // First packet should be interned data
        assert!(packets[0].interned_data.is_some());
        let interned_data = packets[0].interned_data.as_ref().unwrap();
        assert!(interned_data.callstacks.is_empty());
    }

    #[test]
    fn test_generate_trace_packets_single_stack() {
        let stack = create_test_stack_event(
            (1234 << 32) | 5678,
            1000000,
            vec![0x1000, 0x2000],
            vec![0x3000, 0x4000],
        );
        let stacks = vec![stack.clone()];

        let mut interned_stacks = HashMap::new();
        let mut callstack = Callstack::default();
        callstack.set_iid(42);
        callstack.frame_ids = vec![1, 2, 3, 4];
        interned_stacks.insert(stack.stack.clone(), callstack);

        let resolved_info = create_test_resolved_info();
        let mut id_counter = Arc::new(AtomicUsize::new(100));

        let packets =
            generate_trace_packets(&stacks, &interned_stacks, &resolved_info, &mut id_counter);

        // Should have 2 packets: interned data + 1 sample
        assert_eq!(packets.len(), 2);

        // First packet should be interned data
        assert!(packets[0].interned_data.is_some());
        let interned_data = packets[0].interned_data.as_ref().unwrap();
        assert_eq!(interned_data.callstacks.len(), 1);
        assert_eq!(interned_data.function_names.len(), 2); // test_func1 and test_func2

        // Second packet should be the sample
        let sample = packets[1].perf_sample();
        assert_eq!(sample.callstack_iid(), 42);
        assert_eq!(sample.pid(), 1234);
        assert_eq!(sample.tid(), 5678);
    }

    #[test]
    fn test_generate_trace_packets_multiple_stacks() {
        let stack1 =
            create_test_stack_event((1234 << 32) | 5678, 1000000, vec![0x1000], vec![0x3000]);
        let stack2 =
            create_test_stack_event((5678 << 32) | 9012, 2000000, vec![0x2000], vec![0x4000]);
        let stacks = vec![stack1.clone(), stack2.clone()];

        let mut interned_stacks = HashMap::new();
        let mut callstack1 = Callstack::default();
        callstack1.set_iid(42);
        interned_stacks.insert(stack1.stack.clone(), callstack1);

        let mut callstack2 = Callstack::default();
        callstack2.set_iid(43);
        interned_stacks.insert(stack2.stack.clone(), callstack2);

        let resolved_info = create_test_resolved_info();
        let mut id_counter = Arc::new(AtomicUsize::new(100));

        let packets =
            generate_trace_packets(&stacks, &interned_stacks, &resolved_info, &mut id_counter);

        // Should have 3 packets: interned data + 2 samples
        assert_eq!(packets.len(), 3);

        // First packet should be interned data
        assert!(packets[0].interned_data.is_some());
        let interned_data = packets[0].interned_data.as_ref().unwrap();
        assert_eq!(interned_data.callstacks.len(), 2);

        // Second and third packets should be samples
        // Verify the PIDs and TIDs
        let sample1 = packets[1].perf_sample();
        assert_eq!(sample1.pid(), 1234);
        assert_eq!(sample1.tid(), 5678);

        let sample2 = packets[2].perf_sample();
        assert_eq!(sample2.pid(), 5678);
        assert_eq!(sample2.tid(), 9012);
    }

    #[test]
    fn test_generate_trace_packets_timestamps() {
        let stack1 =
            create_test_stack_event((1234 << 32) | 5678, 1000000, vec![0x1000], vec![0x3000]);
        let stack2 =
            create_test_stack_event((1234 << 32) | 5679, 2000000, vec![0x1000], vec![0x3000]);
        let stacks = vec![stack1.clone(), stack2.clone()];

        let mut interned_stacks = HashMap::new();
        let mut callstack = Callstack::default();
        callstack.set_iid(42);
        interned_stacks.insert(stack1.stack.clone(), callstack);

        let resolved_info = create_test_resolved_info();
        let mut id_counter = Arc::new(AtomicUsize::new(100));

        let packets =
            generate_trace_packets(&stacks, &interned_stacks, &resolved_info, &mut id_counter);

        // Check that timestamps are preserved
        assert_eq!(packets[1].timestamp(), 1000000);
        assert_eq!(packets[2].timestamp(), 2000000);
    }
}
