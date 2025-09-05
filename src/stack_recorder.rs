use std::collections::{HashMap, HashSet};
use std::mem;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::pystacks::stack_walker::{PyAddr, StackWalkerRun};
use crate::ringbuf::RingBuffer;
use crate::systing::types::stack_event;
use crate::SystingRecordEvent;

use blazesym::helper::{read_elf_build_id, ElfResolver};
use blazesym::symbolize::source::{Kernel, Process, Source};
use blazesym::symbolize::{
    cache, Input, ProcessMemberInfo, ProcessMemberType, Resolve, Sym, Symbolized, Symbolizer,
};
use blazesym::Error as BlazeErr;
use blazesym::{Addr, Pid};

// Type alias for the dispatch function
type ProcessDispatcher = Box<
    dyn for<'a> Fn(ProcessMemberInfo<'a>) -> Result<Option<Box<dyn Resolve>>, BlazeErr>
        + Send
        + Sync,
>;
use debuginfod::{BuildId, CachingClient, Client};
use perfetto_protos::interned_data::InternedData;
use perfetto_protos::profile_common::{Callstack, Frame, InternedString, Mapping};
use perfetto_protos::profile_packet::PerfSample;
use perfetto_protos::trace_packet::trace_packet::SequenceFlags;
use perfetto_protos::trace_packet::TracePacket;

// Stack structure representing kernel, user, and Python stacks
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Stack {
    pub kernel_stack: Vec<Addr>,
    pub user_stack: Vec<Addr>,
    pub py_stack: Vec<PyAddr>,
}

impl Stack {
    pub fn new(kernel_stack: &[u64], user_stack: &[u64], py_stack: &[PyAddr]) -> Self {
        let my_kernel_stack = kernel_stack
            .iter()
            .rev()
            .filter(|x| **x > 0)
            .copied()
            .collect();
        let my_user_stack = user_stack
            .iter()
            .rev()
            .filter(|x| **x > 0)
            .copied()
            .collect();
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

pub struct StackRecorder {
    pub ringbuf: RingBuffer<stack_event>,
    pub stacks: HashMap<i32, Vec<StackEvent>>,
    pub psr: Arc<StackWalkerRun>,
    pub process_dispatcher: Option<Arc<ProcessDispatcher>>,
}

impl Default for StackRecorder {
    fn default() -> Self {
        Self {
            ringbuf: RingBuffer::default(),
            stacks: HashMap::new(),
            psr: Arc::new(StackWalkerRun::default()),
            process_dispatcher: None,
        }
    }
}

impl StackRecorder {
    pub fn new(enable_debuginfod: bool) -> Self {
        let process_dispatcher = if enable_debuginfod {
            create_debuginfod_dispatcher()
        } else {
            None
        };

        Self {
            ringbuf: RingBuffer::default(),
            stacks: HashMap::new(),
            psr: Arc::new(StackWalkerRun::default()),
            process_dispatcher,
        }
    }

    #[cfg(test)]
    pub fn with_process_dispatcher(mut self, dispatcher: ProcessDispatcher) -> Self {
        self.process_dispatcher = Some(Arc::new(dispatcher));
        self
    }
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
                let name = format!("{} <{:#x}>", name, *input_addr);
                add_frame(
                    frame_map,
                    func_map,
                    id_counter,
                    *input_addr,
                    addr,
                    offset as u64,
                    name,
                );

                for inline in inlined {
                    let name = format!("{} (inlined) <{:#x}>", inline.name, *input_addr);
                    add_frame(frame_map, func_map, id_counter, *input_addr, addr, 0, name);
                }
            }
            _ => {
                let name = format!("unknown <{:#x}>", *input_addr);
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

/// Create a debuginfod dispatcher if debuginfod is available in the environment
fn create_debuginfod_dispatcher() -> Option<Arc<ProcessDispatcher>> {
    match Client::from_env() {
        Ok(Some(client)) => match CachingClient::from_env(client) {
            Ok(caching_client) => {
                println!("Debuginfod enabled: using debuginfod for symbol resolution");

                // Wrap the CachingClient in an Arc so it can be shared across threads.
                // The closure below will take ownership of this Arc (via the `move` keyword),
                // storing it as part of the closure's captured state. When the closure is
                // called during symbolization, it will clone the Arc to pass to
                // dispatch_process_with_client. The CachingClient itself remains shared
                // across all threads (only the Arc reference is cloned, not the client).
                // The closure and its captured Arc<CachingClient> will live as long as the
                // StackRecorder that owns the process_dispatcher field.
                let client = Arc::new(caching_client);
                Some(Arc::new(Box::new(move |info: ProcessMemberInfo<'_>| -> Result<Option<Box<dyn Resolve>>, BlazeErr> {
                    dispatch_process_with_client(info, client.clone())
                }) as ProcessDispatcher))
            }
            Err(e) => {
                println!(
                    "Failed to create caching debuginfod client: {}, using default resolver",
                    e
                );
                None
            }
        },
        Ok(None) => {
            println!("No debuginfod URLs found in environment, using default resolver. If using sudo try --preserve-env");
            None
        }
        Err(e) => {
            println!(
                "Failed to create debuginfod client: {}, using default resolver",
                e
            );
            None
        }
    }
}

/// Callback function for process dispatcher that fetches debug info using debuginfod
fn dispatch_process_with_client(
    info: ProcessMemberInfo<'_>,
    client: Arc<CachingClient>,
) -> Result<Option<Box<dyn Resolve>>, BlazeErr> {
    let ProcessMemberInfo {
        member_entry: entry,
        ..
    } = info;

    match entry {
        ProcessMemberType::Path(path) => {
            let build_id = if let Some(build_id) = read_elf_build_id(&path.maps_file)? {
                BuildId::raw(build_id)
            } else {
                // The binary does not contain a build ID, so we cannot
                // retrieve symbol data. Just let the default resolver do
                // its thing.
                return Ok(None);
            };

            println!("Fetching debug info for build ID: {}", &build_id);
            let path = if let Some(path) = client.fetch_debug_info(&build_id).map_err(Box::from)? {
                path
            } else {
                // If we were unable to find debug information for the provided
                // build ID we let the default resolver see what it can do.
                return Ok(None);
            };
            println!("Fetched debug info from debuginfod: {}", path.display());

            let resolver = ElfResolver::open(&path).map_err(Box::from)?;
            Ok(Some(Box::new(resolver)))
        }
        ProcessMemberType::Component(..) => Ok(None),
        _ => Ok(None),
    }
}

/// Symbolizes all stacks (user, kernel, and Python) and returns the resolved information
fn symbolize_stacks(
    stacks: &[StackEvent],
    tgid: u32,
    id_counter: &mut Arc<AtomicUsize>,
    psr: &mut Arc<StackWalkerRun>,
    process_dispatcher: &Option<Arc<ProcessDispatcher>>,
) -> ResolvedStackInfo {
    let user_src = Source::Process(Process::new(Pid::from(tgid)));
    let kernel_src = Source::Kernel(Kernel::default());

    let mut symbolizer = if let Some(dispatcher) = process_dispatcher {
        // Use the custom dispatcher if provided
        let dispatcher = dispatcher.clone();
        Symbolizer::builder()
            .enable_code_info(true)
            .enable_inlined_fns(true)
            .set_process_dispatcher(move |info| dispatcher(info))
            .build()
    } else {
        // Use default symbolizer
        Symbolizer::builder()
            .enable_code_info(true)
            .enable_inlined_fns(true)
            .build()
    };

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
    process_dispatcher: &Option<Arc<ProcessDispatcher>>,
) {
    // Step 1: Symbolize all stacks
    let resolved_info = symbolize_stacks(&stacks, tgid, id_counter, psr, process_dispatcher);
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
            let process_dispatcher = self.process_dispatcher.clone();
            pool.execute(Thunk::of(move || {
                generate_stack_packets(
                    &mut packets,
                    tgid,
                    stacks,
                    &mut id_counter,
                    &mut psr,
                    &process_dispatcher,
                )
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
    use blazesym::symbolize::{FindSymOpts, Reason, ResolvedSym, SrcLang};
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    /// Mock resolver for testing that maps specific addresses to known function names
    #[derive(Debug)]
    struct MockResolver {
        addr_to_func: HashMap<u64, String>,
    }

    impl MockResolver {
        fn new() -> Self {
            let mut addr_to_func = HashMap::new();
            // Set up some test mappings
            addr_to_func.insert(0x1000, "mock_func_1000".to_string());
            addr_to_func.insert(0x2000, "mock_func_2000".to_string());
            addr_to_func.insert(0x3000, "mock_kernel_func_3000".to_string());
            addr_to_func.insert(0x4000, "mock_kernel_func_4000".to_string());
            addr_to_func.insert(0x5000, "mock_func_5000".to_string());
            addr_to_func.insert(0x6000, "mock_func_6000".to_string());
            MockResolver { addr_to_func }
        }
    }

    impl blazesym::symbolize::Symbolize for MockResolver {
        fn find_sym(
            &self,
            addr: u64,
            _opts: &FindSymOpts,
        ) -> Result<Result<ResolvedSym<'_>, Reason>, BlazeErr> {
            if let Some(name) = self.addr_to_func.get(&addr) {
                Ok(Ok(ResolvedSym {
                    name: name.as_str(),
                    addr,
                    code_info: None,
                    inlined: Box::new([]),
                    size: None,
                    module: None,
                    lang: SrcLang::Unknown,
                }))
            } else {
                Ok(Err(Reason::UnknownAddr))
            }
        }
    }

    impl blazesym::symbolize::TranslateFileOffset for MockResolver {
        fn file_offset_to_virt_offset(&self, _file_offset: u64) -> Result<Option<u64>, BlazeErr> {
            // For testing, just return the same offset
            Ok(Some(0))
        }
    }

    /// Create a test dispatcher that returns our mock resolver
    fn create_test_dispatcher() -> ProcessDispatcher {
        Box::new(|_info| Ok(Some(Box::new(MockResolver::new()) as Box<dyn Resolve>)))
    }

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

        let result = deduplicate_stacks(
            &stacks,
            &resolved_info,
            &mut id_counter,
            &Arc::new(StackWalkerRun::default()),
        );

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

        let result = deduplicate_stacks(
            &stacks,
            &resolved_info,
            &mut id_counter,
            &Arc::new(StackWalkerRun::default()),
        );

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

        let result = deduplicate_stacks(
            &stacks,
            &resolved_info,
            &mut id_counter,
            &Arc::new(StackWalkerRun::default()),
        );

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

        let result = deduplicate_stacks(
            &stacks,
            &resolved_info,
            &mut id_counter,
            &Arc::new(StackWalkerRun::default()),
        );

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
        assert!(!packets.is_empty());

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
    fn test_symbolize_stacks_with_mock_resolver() {
        // Test that custom dispatcher can be set and passed through
        let stack = create_test_stack_event(
            (1234 << 32) | 5678,
            1000000,
            vec![0x1000, 0x2000],
            vec![0x3000, 0x4000],
        );
        let stacks = vec![stack];
        let mut id_counter = Arc::new(AtomicUsize::new(100));
        let mut psr = Arc::new(StackWalkerRun::default());
        let dispatcher = Arc::new(create_test_dispatcher());

        // Symbolize with our custom dispatcher - even though it may not be called for all addresses,
        // this tests that the dispatcher is correctly passed through the system
        let resolved_info =
            symbolize_stacks(&stacks, 1234, &mut id_counter, &mut psr, &Some(dispatcher));

        // Basic sanity checks - frames should still be created even if using default names
        assert!(resolved_info.frame_map.contains_key(&0x1000));
        assert!(resolved_info.frame_map.contains_key(&0x2000));
        assert!(resolved_info.frame_map.contains_key(&0x3000));
        assert!(resolved_info.frame_map.contains_key(&0x4000));

        // Function names should be created (even if just "unknown")
        assert!(!resolved_info.func_name_map.is_empty());
    }

    #[test]
    fn test_stack_recorder_with_custom_dispatcher() {
        // Test that StackRecorder can be constructed with a custom dispatcher
        let mut recorder =
            StackRecorder::default().with_process_dispatcher(create_test_dispatcher());

        // Verify the dispatcher was set
        assert!(recorder.process_dispatcher.is_some());

        // Add a test stack event
        let tgidpid = (1234 << 32) | 5678;
        let stack = StackEvent {
            tgidpid,
            ts_start: 1000000,
            stack: Stack::new(&[0x3000, 0x4000], &[0x1000, 0x2000], &Vec::new()),
        };
        let tgid = (tgidpid >> 32) as i32;
        recorder.stacks.entry(tgid).or_default().push(stack);

        // Generate trace - this tests that the dispatcher is correctly passed through
        let mut id_counter = Arc::new(AtomicUsize::new(100));
        let packets = recorder.generate_trace(&mut id_counter);

        // Verify we got packets
        assert!(!packets.is_empty());

        // Check that the interned data was generated
        let interned_packet = packets.iter().find(|p| p.interned_data.is_some()).unwrap();
        let interned_data = interned_packet.interned_data.as_ref().unwrap();

        // Basic checks that symbolization occurred (even if using defaults)
        assert!(!interned_data.function_names.is_empty());
        assert!(!interned_data.frames.is_empty());
        assert!(!interned_data.callstacks.is_empty());
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
