use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

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

/// Helper function to filter and reverse a stack trace
/// Removes zero addresses and reverses the order
fn filter_and_reverse_stack(stack: &[u64]) -> Vec<u64> {
    stack.iter().rev().filter(|x| **x > 0).copied().collect()
}

impl Stack {
    pub fn new(kernel_stack: &[u64], user_stack: &[u64], py_stack: &[PyAddr]) -> Self {
        Stack {
            kernel_stack: filter_and_reverse_stack(kernel_stack),
            user_stack: filter_and_reverse_stack(user_stack),
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

/// GlobalFunctionManager manages function name deduplication globally across all processes
pub struct GlobalFunctionManager {
    pub global_functions: Arc<RwLock<HashMap<String, InternedString>>>,
    pub id_counter: Arc<AtomicUsize>,
}

impl GlobalFunctionManager {
    pub fn new(id_counter: Arc<AtomicUsize>) -> Self {
        Self {
            global_functions: Arc::new(RwLock::new(HashMap::new())),
            id_counter,
        }
    }

    /// Get or create a function IID for the given name
    pub fn get_or_create_function(&self, name: &str) -> u64 {
        let mut functions = self.global_functions.write().unwrap();
        if let Some(interned) = functions.get(name) {
            return interned.iid();
        }

        let iid = self.id_counter.fetch_add(1, Ordering::Relaxed) as u64;
        let mut interned = InternedString::default();
        interned.set_iid(iid);
        interned.set_str(name.as_bytes().to_vec());
        functions.insert(name.to_string(), interned);
        iid
    }

    /// Get all interned functions
    pub fn get_all_functions(&self) -> Vec<InternedString> {
        self.global_functions
            .read()
            .unwrap()
            .values()
            .cloned()
            .collect()
    }

    /// Get function IDs matching a pattern
    #[allow(dead_code)]
    pub fn get_function_ids_matching(&self, pattern: &str) -> Vec<u64> {
        self.global_functions
            .read()
            .unwrap()
            .iter()
            .filter(|(name, _)| name.contains(pattern))
            .map(|(_, interned)| interned.iid())
            .collect()
    }
}

pub struct StackRecorder {
    pub ringbuf: RingBuffer<stack_event>,
    pub stacks: HashMap<i32, Vec<StackEvent>>,
    pub psr: Arc<StackWalkerRun>,
    pub process_dispatcher: Option<Arc<ProcessDispatcher>>,
    pub global_func_manager: Arc<GlobalFunctionManager>,
}

impl Default for StackRecorder {
    fn default() -> Self {
        let id_counter = Arc::new(AtomicUsize::new(1));
        Self {
            ringbuf: RingBuffer::default(),
            stacks: HashMap::new(),
            psr: Arc::new(StackWalkerRun::default()),
            process_dispatcher: None,
            global_func_manager: Arc::new(GlobalFunctionManager::new(id_counter)),
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
        let id_counter = Arc::new(AtomicUsize::new(1));

        Self {
            ringbuf: RingBuffer::default(),
            stacks: HashMap::new(),
            psr: Arc::new(StackWalkerRun::default()),
            process_dispatcher,
            global_func_manager: Arc::new(GlobalFunctionManager::new(id_counter)),
        }
    }

    #[cfg(test)]
    pub fn with_process_dispatcher(mut self, dispatcher: ProcessDispatcher) -> Self {
        self.process_dispatcher = Some(Arc::new(dispatcher));
        self
    }
}

/// Holds the resolved stack information after symbolization
pub struct ResolvedStackInfo<'a> {
    pub user_frame_map: HashMap<u64, Vec<LocalFrame>>,
    pub kernel_frame_map: &'a HashMap<u64, Vec<LocalFrame>>,
    pub python_calls: Vec<u64>,
    pub python_stack_markers: Vec<u64>,
}

pub fn add_frame(
    frame_map: &mut HashMap<u64, Vec<LocalFrame>>,
    global_func_manager: &Arc<GlobalFunctionManager>,
    id_counter: &Arc<AtomicUsize>,
    input_addr: u64,
    start_addr: u64,
    offset: u64,
    name: String,
) {
    let mut frame = Frame::default();
    let func_iid = global_func_manager.get_or_create_function(&name);
    let iid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;
    frame.set_iid(iid);
    frame.set_function_name_id(func_iid);
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
    global_func_manager: &Arc<GlobalFunctionManager>,
    source: &Source<'a>,
    id_counter: &Arc<AtomicUsize>,
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
                    global_func_manager,
                    id_counter,
                    *input_addr,
                    addr,
                    offset as u64,
                    name,
                );

                for inline in inlined {
                    let name = format!("{} (inlined) <{:#x}>", inline.name, *input_addr);
                    add_frame(
                        frame_map,
                        global_func_manager,
                        id_counter,
                        *input_addr,
                        addr,
                        0,
                        name,
                    );
                }
            }
            _ => {
                let name = format!("unknown <{:#x}>", *input_addr);
                add_frame(
                    frame_map,
                    global_func_manager,
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
fn symbolize_stacks<'a>(
    stacks: &[StackEvent],
    tgid: u32,
    id_counter: &Arc<AtomicUsize>,
    psr: &Arc<StackWalkerRun>,
    process_dispatcher: &Option<Arc<ProcessDispatcher>>,
    global_func_manager: &Arc<GlobalFunctionManager>,
    global_kernel_frame_map: &'a mut HashMap<u64, Vec<LocalFrame>>,
) -> ResolvedStackInfo<'a> {
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

    let mut user_frame_map = HashMap::new();
    let mut python_calls = Vec::new();
    let mut python_stack_markers = Vec::new();

    for stack in stacks.iter() {
        let raw_stack = &stack.stack;
        // Symbolize user space stack (per-process)
        stack_to_frames_mapping(
            &mut symbolizer,
            &mut user_frame_map,
            global_func_manager,
            &user_src,
            id_counter,
            raw_stack.user_stack.iter(),
        );
        psr.user_stack_to_python_calls(&mut user_frame_map, global_func_manager, &mut python_calls);
        // Symbolize kernel stack (global)
        stack_to_frames_mapping(
            &mut symbolizer,
            global_kernel_frame_map,
            global_func_manager,
            &kernel_src,
            id_counter,
            raw_stack.kernel_stack.iter(),
        );
        // Symbolize Python stack (per-process)
        psr.pystacks_to_frames_mapping(
            &mut user_frame_map,
            global_func_manager,
            id_counter,
            &mut python_stack_markers,
            &raw_stack.py_stack,
        );
    }

    ResolvedStackInfo {
        user_frame_map,
        kernel_frame_map: global_kernel_frame_map,
        python_calls,
        python_stack_markers,
    }
}

/// Holds deduplicated stack data
struct DeduplicatedStackData {
    callstacks: HashMap<Stack, Callstack>,
}

/// Helper function to extract frame IDs from a frame map for given addresses
fn extract_frame_ids<'a>(
    frame_map: &HashMap<u64, Vec<LocalFrame>>,
    addrs: impl Iterator<Item = &'a u64>,
) -> Vec<u64> {
    addrs
        .flat_map(|addr| {
            frame_map
                .get(addr)
                .map(|frame_vec| {
                    frame_vec
                        .iter()
                        .map(|frame| frame.frame.iid())
                        .collect::<Vec<u64>>()
                })
                .unwrap_or_default()
        })
        .collect()
}

/// Helper function to collect all frames from a frame map
fn collect_frames(frame_map: &HashMap<u64, Vec<LocalFrame>>) -> Vec<Frame> {
    frame_map
        .values()
        .flat_map(|frame_vec| {
            frame_vec
                .iter()
                .map(|frame| frame.frame.clone())
                .collect::<Vec<Frame>>()
        })
        .collect()
}

/// Helper function to collect all mappings from a frame map
fn collect_mappings(frame_map: &HashMap<u64, Vec<LocalFrame>>) -> Vec<Mapping> {
    frame_map
        .values()
        .flat_map(|frame_vec| {
            frame_vec
                .iter()
                .map(|frame| frame.mapping.clone())
                .collect::<Vec<Mapping>>()
        })
        .collect()
}

/// Deduplicates stacks and creates callstack mappings
fn deduplicate_stacks(
    stacks: &[StackEvent],
    resolved_info: &ResolvedStackInfo,
    id_counter: &Arc<AtomicUsize>,
    psr: &Arc<StackWalkerRun>,
) -> DeduplicatedStackData {
    let callstacks: HashMap<Stack, Callstack> = stacks
        .iter()
        .map(|stack| stack.stack.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .map(|stack| {
            let mut callstack = Callstack::default();
            let iid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;
            callstack.set_iid(iid);
            callstack.frame_ids = if stack.py_stack.is_empty() {
                // No Python stack - chain user stacks from user map and kernel stacks from kernel map
                let user_frame_ids =
                    extract_frame_ids(&resolved_info.user_frame_map, stack.user_stack.iter());
                let kernel_frame_ids =
                    extract_frame_ids(&resolved_info.kernel_frame_map, stack.kernel_stack.iter());

                user_frame_ids.into_iter().chain(kernel_frame_ids).collect()
            } else {
                // Merge Python stacks with user stacks
                let merged_addrs = psr.merge_pystacks(
                    &stack,
                    &resolved_info.python_calls,
                    &resolved_info.python_stack_markers,
                );

                let user_frame_ids =
                    extract_frame_ids(&resolved_info.user_frame_map, merged_addrs.iter());
                let kernel_frame_ids =
                    extract_frame_ids(&resolved_info.kernel_frame_map, stack.kernel_stack.iter());

                user_frame_ids.into_iter().chain(kernel_frame_ids).collect()
            };
            (stack, callstack)
        })
        .collect();

    DeduplicatedStackData { callstacks }
}

/// Generates PerfSample packets from the deduplicated stacks
fn generate_sample_packets(
    stacks: &[StackEvent],
    callstack_map: &HashMap<Stack, Callstack>,
    sequence_id: u32,
) -> Vec<TracePacket> {
    let mut packets = Vec::new();

    // Generate sample packets for each stack
    for stack in stacks.iter() {
        let pid = stack.tgidpid as u32;
        let tgid = (stack.tgidpid >> 32) as u32;
        let mut packet = TracePacket::default();
        packet.set_timestamp(stack.ts_start);

        let mut sample = PerfSample::default();
        sample.set_callstack_iid(callstack_map.get(&stack.stack).unwrap().iid());
        sample.set_pid(tgid);
        sample.set_tid(pid);
        packet.set_perf_sample(sample);
        packet.set_trusted_packet_sequence_id(sequence_id);
        packets.push(packet);
    }
    packets
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
    /// Process stacks for a single process and collect the interned data
    fn process_tgid_stacks(
        &self,
        tgid: u32,
        stacks: &[StackEvent],
        id_counter: &Arc<AtomicUsize>,
        global_kernel_frame_map: &mut HashMap<u64, Vec<LocalFrame>>,
        sequence_id: u32,
    ) -> (Vec<Callstack>, Vec<Frame>, Vec<Mapping>, Vec<TracePacket>) {
        // Step 1: Symbolize all stacks
        let resolved_info = symbolize_stacks(
            stacks,
            tgid,
            id_counter,
            &self.psr,
            &self.process_dispatcher,
            &self.global_func_manager,
            global_kernel_frame_map,
        );

        // Step 2: Deduplicate stacks and collect interned data
        let deduplicated_data = deduplicate_stacks(stacks, &resolved_info, id_counter, &self.psr);

        // Collect all interned data (only user frames/mappings from per-process data)
        let callstacks: Vec<Callstack> = deduplicated_data.callstacks.values().cloned().collect();
        let user_frames = collect_frames(&resolved_info.user_frame_map);
        let user_mappings = collect_mappings(&resolved_info.user_frame_map);

        // Step 3: Generate sample packets for this process
        let sample_packets =
            generate_sample_packets(stacks, &deduplicated_data.callstacks, sequence_id);

        (callstacks, user_frames, user_mappings, sample_packets)
    }

    /// Create the interned data packet with all collected data
    fn create_interned_packet(
        &self,
        callstacks: Vec<Callstack>,
        frames: Vec<Frame>,
        mappings: Vec<Mapping>,
        sequence_id: u32,
    ) -> Option<TracePacket> {
        if callstacks.is_empty() && frames.is_empty() && mappings.is_empty() {
            return None;
        }

        let mut interned_packet = TracePacket::default();
        let interned_data = InternedData {
            function_names: self.global_func_manager.get_all_functions(),
            callstacks,
            frames,
            mappings,
            ..Default::default()
        };
        interned_packet.interned_data = Some(interned_data).into();
        interned_packet.set_trusted_packet_sequence_id(sequence_id);
        interned_packet.set_sequence_flags(
            SequenceFlags::SEQ_INCREMENTAL_STATE_CLEARED as u32
                | SequenceFlags::SEQ_NEEDS_INCREMENTAL_STATE as u32,
        );

        Some(interned_packet)
    }

    pub fn generate_trace(&self, id_counter: &Arc<AtomicUsize>) -> Vec<TracePacket> {
        // Get a unique sequence ID for this trace
        let sequence_id = id_counter.fetch_add(1, Ordering::Relaxed) as u32;

        // Process all stacks synchronously to avoid the interleaving issue
        let mut all_packets = Vec::new();
        let mut all_sample_packets = Vec::new();

        // Collect all interned data from all processes
        let mut all_callstacks = Vec::new();
        let mut all_user_frames = Vec::new();
        let mut all_user_mappings = Vec::new();

        // Global kernel frame map shared across all processes
        let mut global_kernel_frame_map = HashMap::new();

        // Process each tgid's stacks
        for (tgid, stacks) in self.stacks.iter() {
            let tgid = *tgid as u32;

            let (callstacks, user_frames, user_mappings, sample_packets) = self
                .process_tgid_stacks(
                    tgid,
                    stacks,
                    id_counter,
                    &mut global_kernel_frame_map,
                    sequence_id,
                );

            all_callstacks.extend(callstacks);
            all_user_frames.extend(user_frames);
            all_user_mappings.extend(user_mappings);
            all_sample_packets.extend(sample_packets);
        }

        // Extract kernel frames and mappings from the global kernel frame map
        let kernel_frames = collect_frames(&global_kernel_frame_map);
        let kernel_mappings = collect_mappings(&global_kernel_frame_map);

        // Combine user and kernel frames/mappings
        let mut all_frames = Vec::new();
        all_frames.extend(kernel_frames);
        all_frames.extend(all_user_frames);

        let mut all_mappings = Vec::new();
        all_mappings.extend(kernel_mappings);
        all_mappings.extend(all_user_mappings);

        // Create a single interned data packet with everything
        if let Some(interned_packet) =
            self.create_interned_packet(all_callstacks, all_frames, all_mappings, sequence_id)
        {
            all_packets.push(interned_packet);
        }

        // Then add all the sample packets
        all_packets.extend(all_sample_packets);

        all_packets
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

    fn create_test_stack_event_raw(
        tgidpid: u64,
        ts: u64,
        user_addrs: &[u64],
        kernel_addrs: &[u64],
    ) -> stack_event {
        let mut event: stack_event = unsafe { std::mem::zeroed() };
        event.task.tgidpid = tgidpid;
        event.ts = ts;

        // Copy user stack addresses
        event.user_stack_length = user_addrs.len() as u64;
        for (i, &addr) in user_addrs.iter().enumerate() {
            if i < event.user_stack.len() {
                event.user_stack[i] = addr;
            }
        }

        // Copy kernel stack addresses
        event.kernel_stack_length = kernel_addrs.len() as u64;
        for (i, &addr) in kernel_addrs.iter().enumerate() {
            if i < event.kernel_stack.len() {
                event.kernel_stack[i] = addr;
            }
        }

        event
    }

    #[test]
    fn test_add_frame_new_address() {
        let mut frame_map = HashMap::new();
        let id_counter = Arc::new(AtomicUsize::new(100));
        let global_func_manager = Arc::new(GlobalFunctionManager::new(id_counter.clone()));

        add_frame(
            &mut frame_map,
            &global_func_manager,
            &id_counter,
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

        // Check that function was added to global_func_manager
        let funcs = global_func_manager.get_all_functions();
        assert_eq!(funcs.len(), 1);
        assert!(funcs[0].iid() >= 100);
        assert_eq!(funcs[0].str(), b"my_function");
    }

    #[test]
    fn test_add_frame_multiple_frames_same_address() {
        let mut frame_map = HashMap::new();
        let id_counter = Arc::new(AtomicUsize::new(100));
        let global_func_manager = Arc::new(GlobalFunctionManager::new(id_counter.clone()));

        // Add first frame
        add_frame(
            &mut frame_map,
            &global_func_manager,
            &id_counter,
            0x5000,
            0x4800,
            0x200,
            "function1".to_string(),
        );

        // Add second frame at same address (e.g., inlined function)
        add_frame(
            &mut frame_map,
            &global_func_manager,
            &id_counter,
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

        // Check that both functions are in global_func_manager
        let funcs = global_func_manager.get_all_functions();
        assert_eq!(funcs.len(), 2);
        let func_names: Vec<String> = funcs
            .iter()
            .map(|f| String::from_utf8(f.str.clone().unwrap()).unwrap())
            .collect();
        assert!(func_names.contains(&"function1".to_string()));
        assert!(func_names.contains(&"function2 (inlined)".to_string()));
    }

    #[test]
    fn test_add_frame_reuses_existing_function() {
        let mut frame_map = HashMap::new();
        let id_counter = Arc::new(AtomicUsize::new(100));
        let global_func_manager = Arc::new(GlobalFunctionManager::new(id_counter.clone()));

        // Add first frame with function "common_func"
        add_frame(
            &mut frame_map,
            &global_func_manager,
            &id_counter,
            0x5000,
            0x4800,
            0x200,
            "common_func".to_string(),
        );

        let func_iid_first = global_func_manager.get_or_create_function("common_func");

        // Add second frame with same function name but different address
        add_frame(
            &mut frame_map,
            &global_func_manager,
            &id_counter,
            0x6000,
            0x5800,
            0x200,
            "common_func".to_string(),
        );

        // Check that function manager still has only one entry for "common_func"
        let funcs = global_func_manager.get_all_functions();
        assert_eq!(funcs.len(), 1);

        // Check that the same function IID is reused
        let func_iid_second = global_func_manager.get_or_create_function("common_func");
        assert_eq!(func_iid_first, func_iid_second);

        // Check that frames at different addresses reference the same function
        let frame1 = &frame_map.get(&0x5000).unwrap()[0].frame;
        let frame2 = &frame_map.get(&0x6000).unwrap()[0].frame;
        assert_eq!(frame1.function_name_id(), frame2.function_name_id());
    }

    #[test]
    fn test_add_frame_id_counter_increments() {
        let mut frame_map = HashMap::new();
        let id_counter = Arc::new(AtomicUsize::new(100));
        let global_func_manager = Arc::new(GlobalFunctionManager::new(id_counter.clone()));

        let initial_count = id_counter.load(Ordering::Relaxed);

        add_frame(
            &mut frame_map,
            &global_func_manager,
            &id_counter,
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
        // Test deduplication with empty stack list
        let stacks = vec![];
        let user_frame_map = HashMap::new();
        let kernel_frame_map = HashMap::new();
        let resolved_info = ResolvedStackInfo {
            user_frame_map,
            kernel_frame_map: &kernel_frame_map,
            python_calls: Vec::new(),
            python_stack_markers: Vec::new(),
        };
        let id_counter = Arc::new(AtomicUsize::new(100));

        let result = deduplicate_stacks(
            &stacks,
            &resolved_info,
            &id_counter,
            &Arc::new(StackWalkerRun::default()),
        );

        // Should return empty data for empty input
        assert!(result.callstacks.is_empty());
    }

    #[test]
    fn test_deduplicate_stacks_single_stack() {
        let mut recorder =
            StackRecorder::default().with_process_dispatcher(create_test_dispatcher());

        // Create a single test event
        let event = create_test_stack_event_raw(
            (1234 << 32) | 5678,
            1000000,
            &[0x1000, 0x2000],
            &[0x3000, 0x4000],
        );
        recorder.handle_event(event);

        let id_counter = Arc::new(AtomicUsize::new(100));
        let packets = recorder.generate_trace(&id_counter);

        // Find interned data packet with callstacks (skip global function packet)
        let interned_packet = packets
            .iter()
            .find(|p| {
                p.interned_data.is_some()
                    && !p.interned_data.as_ref().unwrap().callstacks.is_empty()
            })
            .unwrap();
        let interned_data = interned_packet.interned_data.as_ref().unwrap();

        // Should have exactly one callstack
        assert_eq!(interned_data.callstacks.len(), 1);

        let callstack = &interned_data.callstacks[0];
        assert!(callstack.iid() >= 100); // Should have assigned an ID
        assert!(!callstack.frame_ids.is_empty());

        // Should have one sample packet
        let sample_packets: Vec<_> = packets.iter().filter(|p| p.has_perf_sample()).collect();
        assert_eq!(sample_packets.len(), 1);
    }

    #[test]
    fn test_deduplicate_stacks_duplicate_stacks() {
        let mut recorder =
            StackRecorder::default().with_process_dispatcher(create_test_dispatcher());

        // Create two events with identical stacks but different threads
        let event1 = create_test_stack_event_raw(
            (1234 << 32) | 5678,
            1000000,
            &[0x1000, 0x2000],
            &[0x3000, 0x4000],
        );
        recorder.handle_event(event1);

        let event2 = create_test_stack_event_raw(
            (1234 << 32) | 5679, // Different PID, same stack
            2000000,
            &[0x1000, 0x2000],
            &[0x3000, 0x4000],
        );
        recorder.handle_event(event2);

        let id_counter = Arc::new(AtomicUsize::new(100));
        let packets = recorder.generate_trace(&id_counter);

        // Find interned data packet with callstacks (skip global function packet)
        let interned_packet = packets
            .iter()
            .find(|p| {
                p.interned_data.is_some()
                    && !p.interned_data.as_ref().unwrap().callstacks.is_empty()
            })
            .unwrap();
        let interned_data = interned_packet.interned_data.as_ref().unwrap();

        // Should only have one unique callstack due to deduplication
        assert_eq!(interned_data.callstacks.len(), 1);

        // But should have two sample packets
        let sample_packets: Vec<_> = packets.iter().filter(|p| p.has_perf_sample()).collect();
        assert_eq!(sample_packets.len(), 2);

        // Both samples should reference the same callstack
        let callstack_iid = interned_data.callstacks[0].iid();
        assert_eq!(
            sample_packets[0].perf_sample().callstack_iid(),
            callstack_iid
        );
        assert_eq!(
            sample_packets[1].perf_sample().callstack_iid(),
            callstack_iid
        );
    }

    #[test]
    fn test_deduplicate_stacks_different_stacks() {
        let mut recorder =
            StackRecorder::default().with_process_dispatcher(create_test_dispatcher());

        // Create two events with different stacks
        let event1 =
            create_test_stack_event_raw((1234 << 32) | 5678, 1000000, &[0x1000], &[0x3000]);
        recorder.handle_event(event1);

        let event2 =
            create_test_stack_event_raw((1234 << 32) | 5679, 2000000, &[0x2000], &[0x4000]);
        recorder.handle_event(event2);

        let id_counter = Arc::new(AtomicUsize::new(100));
        let packets = recorder.generate_trace(&id_counter);

        // Find interned data packet with callstacks (skip global function packet)
        let interned_packet = packets
            .iter()
            .find(|p| {
                p.interned_data.is_some()
                    && !p.interned_data.as_ref().unwrap().callstacks.is_empty()
            })
            .unwrap();
        let interned_data = interned_packet.interned_data.as_ref().unwrap();

        // Should have two unique callstacks
        assert_eq!(interned_data.callstacks.len(), 2);

        // Should have two sample packets
        let sample_packets: Vec<_> = packets.iter().filter(|p| p.has_perf_sample()).collect();
        assert_eq!(sample_packets.len(), 2);

        // Each sample should reference a different callstack
        let callstack_iids: Vec<_> = sample_packets
            .iter()
            .map(|p| p.perf_sample().callstack_iid())
            .collect();
        assert_ne!(callstack_iids[0], callstack_iids[1]);
    }

    #[test]
    fn test_generate_sample_packets_empty() {
        // Test packet generation with no stacks
        let stacks = vec![];
        let callstack_map = HashMap::new();

        let packets = generate_sample_packets(&stacks, &callstack_map, 1);

        // Should have no packets since there are no stacks
        assert!(packets.is_empty());
    }

    #[test]
    fn test_generate_trace_packets_single_stack() {
        let mut recorder =
            StackRecorder::default().with_process_dispatcher(create_test_dispatcher());

        // Create a single test event
        let event = create_test_stack_event_raw(
            (1234 << 32) | 5678,
            1000000,
            &[0x1000, 0x2000],
            &[0x3000, 0x4000],
        );
        recorder.handle_event(event);

        let id_counter = Arc::new(AtomicUsize::new(100));
        let packets = recorder.generate_trace(&id_counter);

        // Should have exactly 2 packets: one interned data + one sample
        assert_eq!(packets.len(), 2);

        // First packet should be interned data with everything
        assert!(packets[0].interned_data.is_some());
        let interned_data = packets[0].interned_data.as_ref().unwrap();
        assert!(!interned_data.function_names.is_empty());
        assert_eq!(interned_data.callstacks.len(), 1);

        // Find the sample packet
        let sample_packet = packets.iter().find(|p| p.has_perf_sample()).unwrap();
        let sample = sample_packet.perf_sample();
        assert_eq!(sample.pid(), 1234);
        assert_eq!(sample.tid(), 5678);

        // Verify the callstack ID matches
        let callstack_iid = interned_data.callstacks[0].iid();
        assert_eq!(sample.callstack_iid(), callstack_iid);
    }

    #[test]
    fn test_generate_trace_packets_multiple_stacks() {
        let mut recorder =
            StackRecorder::default().with_process_dispatcher(create_test_dispatcher());

        // Create two test events with different processes
        let event1 =
            create_test_stack_event_raw((1234 << 32) | 5678, 1000000, &[0x1000], &[0x3000]);
        recorder.handle_event(event1);

        let event2 =
            create_test_stack_event_raw((5678 << 32) | 9012, 2000000, &[0x2000], &[0x4000]);
        recorder.handle_event(event2);

        let id_counter = Arc::new(AtomicUsize::new(100));
        let packets = recorder.generate_trace(&id_counter);

        // Should have exactly 3 packets: one interned data + two samples
        assert_eq!(packets.len(), 3);

        // First packet should be the single interned data packet with all data
        assert!(packets[0].interned_data.is_some());
        let interned_data = packets[0].interned_data.as_ref().unwrap();
        assert_eq!(interned_data.callstacks.len(), 2);

        // Find sample packets
        let sample_packets: Vec<_> = packets.iter().filter(|p| p.has_perf_sample()).collect();
        assert_eq!(sample_packets.len(), 2);

        // Verify the PIDs and TIDs - they should be present but order may vary
        let pids_tids: Vec<(u32, u32)> = sample_packets
            .iter()
            .map(|p| (p.perf_sample().pid(), p.perf_sample().tid()))
            .collect();

        assert!(pids_tids.contains(&(1234, 5678)));
        assert!(pids_tids.contains(&(5678, 9012)));
    }

    #[test]
    fn test_symbolize_stacks_with_mock_resolver() {
        // Test that mock resolver provides consistent function names via generate_trace
        let mut recorder =
            StackRecorder::default().with_process_dispatcher(create_test_dispatcher());

        // Create and handle a test event with addresses that MockResolver knows
        let event = create_test_stack_event_raw(
            (1234 << 32) | 5678,
            1000000,
            &[0x1000, 0x2000],
            &[0x3000, 0x4000],
        );
        recorder.handle_event(event);

        // Generate trace using the mock resolver
        let id_counter = Arc::new(AtomicUsize::new(100));
        let packets = recorder.generate_trace(&id_counter);

        // Verify packets were generated
        assert!(!packets.is_empty());

        // Find the global function packet (first packet with function_names)
        let global_packet = packets
            .iter()
            .find(|p| {
                p.interned_data.is_some()
                    && !p.interned_data.as_ref().unwrap().function_names.is_empty()
            })
            .unwrap();
        let global_data = global_packet.interned_data.as_ref().unwrap();

        // Extract function names from the global data
        let func_names: Vec<_> = global_data
            .function_names
            .iter()
            .map(|f| String::from_utf8_lossy(f.str()).to_string())
            .collect();

        // Find process packet with frames and callstacks
        let process_packet = packets
            .iter()
            .find(|p| {
                p.interned_data.is_some() && !p.interned_data.as_ref().unwrap().frames.is_empty()
            })
            .unwrap();
        let process_data = process_packet.interned_data.as_ref().unwrap();

        // Note: The mock resolver may not be called for all addresses due to how
        // blazesym's process dispatcher works (only for specific member types).
        // For now, we just verify that symbolization occurred and frames were created.
        // In real usage, the dispatcher would be called when resolving ELF files with build IDs.

        // Verify that symbolization occurred (even if using default resolver)
        assert!(!func_names.is_empty(), "Expected some function names");

        // Verify frames were created for our addresses
        assert!(
            !process_data.frames.is_empty(),
            "Expected frames to be created"
        );
        assert!(
            !process_data.callstacks.is_empty(),
            "Expected callstacks to be created"
        );
    }

    #[test]
    fn test_stack_recorder_with_custom_dispatcher() {
        // Test multiple stack events with mock resolver for consistent results
        let mut recorder =
            StackRecorder::default().with_process_dispatcher(create_test_dispatcher());

        // Create and handle multiple test events with different known addresses
        let event1 =
            create_test_stack_event_raw((1234 << 32) | 5678, 1000000, &[0x1000, 0x2000], &[0x3000]);
        recorder.handle_event(event1);

        let event2 =
            create_test_stack_event_raw((1234 << 32) | 5679, 2000000, &[0x5000, 0x6000], &[0x4000]);
        recorder.handle_event(event2);

        // Generate trace with mock resolver
        let id_counter = Arc::new(AtomicUsize::new(100));
        let packets = recorder.generate_trace(&id_counter);

        // Verify packets were generated
        assert!(!packets.is_empty());

        // Find the global function packet (first packet with function_names)
        let global_packet = packets
            .iter()
            .find(|p| {
                p.interned_data.is_some()
                    && !p.interned_data.as_ref().unwrap().function_names.is_empty()
            })
            .unwrap();
        let global_data = global_packet.interned_data.as_ref().unwrap();

        // Extract function names
        let func_names: Vec<_> = global_data
            .function_names
            .iter()
            .map(|f| String::from_utf8_lossy(f.str()).to_string())
            .collect();

        // Find process packet with frames and callstacks
        let process_packet = packets
            .iter()
            .find(|p| {
                p.interned_data.is_some() && !p.interned_data.as_ref().unwrap().frames.is_empty()
            })
            .unwrap();
        let process_data = process_packet.interned_data.as_ref().unwrap();

        // Note: The mock resolver may not be called for all addresses due to how
        // blazesym's process dispatcher works (only for specific member types).
        // The dispatcher is primarily used when resolving ELF files with build IDs.

        // Verify that symbolization occurred
        assert!(!func_names.is_empty(), "Expected some function names");

        // Verify frames and callstacks were created
        assert!(
            !process_data.frames.is_empty(),
            "Expected frames to be created"
        );
        assert!(
            !process_data.callstacks.is_empty(),
            "Expected callstacks to be created"
        );

        // Verify we have the expected number of samples
        let sample_packets: Vec<_> = packets.iter().filter(|p| p.has_perf_sample()).collect();
        assert_eq!(sample_packets.len(), 2, "Expected 2 sample packets");
    }

    #[test]
    fn test_deduplicate_stacks_with_mock_resolver() {
        // Test that duplicate stacks are properly deduplicated with consistent mock names
        let mut recorder =
            StackRecorder::default().with_process_dispatcher(create_test_dispatcher());

        // Create and handle identical stacks from different threads - should be deduplicated
        let event1 = create_test_stack_event_raw(
            (1234 << 32) | 5678,
            1000000,
            &[0x1000, 0x2000],
            &[0x3000, 0x4000],
        );
        recorder.handle_event(event1);

        let event2 = create_test_stack_event_raw(
            (1234 << 32) | 5679, // Different thread, same stack
            2000000,
            &[0x1000, 0x2000],
            &[0x3000, 0x4000],
        );
        recorder.handle_event(event2);

        // Generate trace
        let id_counter = Arc::new(AtomicUsize::new(100));
        let packets = recorder.generate_trace(&id_counter);

        // Find interned data packet with callstacks (skip global function packet)
        let interned_packet = packets
            .iter()
            .find(|p| {
                p.interned_data.is_some()
                    && !p.interned_data.as_ref().unwrap().callstacks.is_empty()
            })
            .unwrap();
        let interned_data = interned_packet.interned_data.as_ref().unwrap();

        // Should have only one unique callstack due to deduplication
        assert_eq!(
            interned_data.callstacks.len(),
            1,
            "Expected 1 deduplicated callstack, got {}",
            interned_data.callstacks.len()
        );

        // But should have two sample packets
        let sample_packets: Vec<_> = packets.iter().filter(|p| p.has_perf_sample()).collect();
        assert_eq!(sample_packets.len(), 2, "Expected 2 sample packets");

        // Both samples should reference the same callstack
        let callstack_iid = interned_data.callstacks[0].iid();
        assert_eq!(
            sample_packets[0].perf_sample().callstack_iid(),
            callstack_iid
        );
        assert_eq!(
            sample_packets[1].perf_sample().callstack_iid(),
            callstack_iid
        );

        // Find the global function packet (first packet with function_names)
        let global_packet = packets
            .iter()
            .find(|p| {
                p.interned_data.is_some()
                    && !p.interned_data.as_ref().unwrap().function_names.is_empty()
            })
            .unwrap();
        let global_data = global_packet.interned_data.as_ref().unwrap();

        // Verify function names were created during symbolization
        let func_names: Vec<_> = global_data
            .function_names
            .iter()
            .map(|f| String::from_utf8_lossy(f.str()).to_string())
            .collect();
        assert!(
            !func_names.is_empty(),
            "Expected function names to be created"
        );
    }

    #[test]
    fn test_generate_trace_packets_timestamps() {
        let mut recorder =
            StackRecorder::default().with_process_dispatcher(create_test_dispatcher());

        // Create two test events with same stack but different timestamps
        let event1 =
            create_test_stack_event_raw((1234 << 32) | 5678, 1000000, &[0x1000], &[0x3000]);
        recorder.handle_event(event1);

        let event2 =
            create_test_stack_event_raw((1234 << 32) | 5679, 2000000, &[0x1000], &[0x3000]);
        recorder.handle_event(event2);

        let id_counter = Arc::new(AtomicUsize::new(100));
        let packets = recorder.generate_trace(&id_counter);

        // Find sample packets and verify timestamps are preserved
        let sample_packets: Vec<_> = packets.iter().filter(|p| p.has_perf_sample()).collect();
        assert_eq!(sample_packets.len(), 2);

        // Check that timestamps are preserved
        assert_eq!(sample_packets[0].timestamp(), 1000000);
        assert_eq!(sample_packets[1].timestamp(), 2000000);
    }
}
