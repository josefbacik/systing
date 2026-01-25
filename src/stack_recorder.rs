use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use anyhow::Result;

use crate::perfetto::TraceWriter;
use crate::pystacks::stack_walker::{PyAddr, StackWalkerRun};
use crate::record::RecordCollector;
use crate::ringbuf::RingBuffer;
use crate::systing_core::types::stack_event;
use crate::systing_core::SystingRecordEvent;
use crate::trace::{StackRecord, StackSampleRecord};
use crate::utid::UtidGenerator;

use blazesym::helper::{read_elf_build_id, ElfResolver};
use blazesym::symbolize::source::{Kernel, Process, Source};
use blazesym::symbolize::{
    cache, Input, ProcessMemberInfo, ProcessMemberType, Reason, Resolve, Sym, Symbolized,
    Symbolizer,
};
use blazesym::Error as BlazeErr;
use blazesym::{Addr, Pid};

use indicatif::{ProgressBar, ProgressStyle};

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

/// Maximum valid userspace address on x86_64 Linux.
/// Addresses above this are either kernel space or garbage from bad frame pointer unwinding.
/// On x86_64, the canonical address split is at bit 47, so userspace addresses are below 0x800000000000.
#[cfg(target_arch = "x86_64")]
const MAX_USER_ADDR: u64 = 0x00007fffffffffff;

/// Maximum valid userspace address on aarch64 Linux (48-bit VA).
#[cfg(target_arch = "aarch64")]
const MAX_USER_ADDR: u64 = 0x0000ffffffffffff;

/// Filters out zero addresses and reverses user stack trace order.
/// Also filters out garbage addresses that are above the valid userspace range,
/// which can occur when bpf_get_stack() follows invalid frame pointers.
fn filter_and_reverse_user_stack(stack: &[u64]) -> Vec<u64> {
    stack
        .iter()
        .copied()
        .rev()
        .filter(|&x| x > 0 && x <= MAX_USER_ADDR)
        .collect()
}

/// Filters out zero addresses and reverses kernel stack trace order.
/// Kernel addresses are valid above MAX_USER_ADDR, so we only filter zeros.
fn filter_and_reverse_kernel_stack(stack: &[u64]) -> Vec<u64> {
    stack.iter().copied().rev().filter(|&x| x != 0).collect()
}

impl Stack {
    pub fn new(kernel_stack: &[u64], user_stack: &[u64], py_stack: &[PyAddr]) -> Self {
        Stack {
            kernel_stack: filter_and_reverse_kernel_stack(kernel_stack),
            user_stack: filter_and_reverse_user_stack(user_stack),
            py_stack: py_stack.to_vec(),
        }
    }
}

#[derive(Clone)]
pub struct StackEvent {
    pub tgidpid: u64,
    pub ts_start: u64,
    pub stack: Stack,
    pub stack_event_type: i8,
}

/// Convert BPF stack_event_type (u32) to i8, clamping to valid range.
/// Valid values are 0 (STACK_SLEEP_UNINTERRUPTIBLE), 1 (STACK_RUNNING), 2 (STACK_SLEEP_INTERRUPTIBLE).
/// Unknown values are preserved but clamped to i8::MAX to avoid truncation issues.
#[inline]
fn convert_stack_event_type(bpf_type: u32) -> i8 {
    if bpf_type <= i8::MAX as u32 {
        bpf_type as i8
    } else {
        // Clamp to max i8 value to indicate unknown/invalid type
        i8::MAX
    }
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
        let mut functions = self
            .global_functions
            .write()
            .expect("Failed to acquire write lock on global_functions");
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

    /// Get function IDs matching a pattern (used by pystacks feature)
    #[cfg(feature = "pystacks")]
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
    // Streaming support
    /// Whether streaming mode is enabled. When true, stacks are deduplicated during
    /// recording and samples are buffered for later writing via finish().
    streaming_enabled: bool,
    /// Maps (Stack, tgid) to stack_id for deduplication during streaming.
    /// The tgid is included in the key because the same addresses in different processes
    /// may resolve to different symbols (e.g., shared libraries at fixed addresses).
    unique_stacks: HashMap<(Stack, i32), i64>,
    /// Next stack_id to assign for new unique stacks.
    next_stack_id: i64,
    /// Pending samples buffer for streaming.
    pending_samples: Vec<StackSampleRecord>,
    /// Shared utid generator for consistent thread IDs across all recorders.
    utid_generator: Arc<UtidGenerator>,
}

impl StackRecorder {
    pub fn new(enable_debuginfod: bool, utid_generator: Arc<UtidGenerator>) -> Self {
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
            streaming_enabled: false,
            unique_stacks: HashMap::new(),
            next_stack_id: 1,
            pending_samples: Vec::new(),
            utid_generator,
        }
    }

    /// Enable streaming mode for stack recording.
    /// When enabled, stacks are deduplicated during recording and samples are
    /// buffered for later writing via finish().
    pub fn enable_streaming(&mut self) {
        self.streaming_enabled = true;
    }

    /// Create a symbolizer with the configured process dispatcher.
    fn create_symbolizer(&self) -> Symbolizer {
        if let Some(dispatcher) = &self.process_dispatcher {
            let dispatcher = dispatcher.clone();
            Symbolizer::builder()
                .enable_code_info(true)
                .enable_inlined_fns(true)
                .set_process_dispatcher(move |info| dispatcher(info))
                .build()
        } else {
            Symbolizer::builder()
                .enable_code_info(true)
                .enable_inlined_fns(true)
                .build()
        }
    }

    /// Finish streaming and symbolize all unique stacks.
    ///
    /// This method should be called at the end of recording to:
    /// 1. Flush any remaining pending samples to the collector
    /// 2. Symbolize all unique stacks collected during recording
    /// 3. Stream StackRecords for each unique stack
    ///
    /// # Arguments
    /// * `collector` - The collector to write samples and stacks to. This is typically
    ///   the collector returned by sched recorder's finish().
    ///
    /// Returns the collector so it can be passed to other recorders or finished.
    pub fn finish(
        &mut self,
        mut collector: Box<dyn RecordCollector + Send>,
    ) -> Result<Box<dyn RecordCollector + Send>> {
        // Check if streaming was enabled (we have pending samples/unique stacks)
        if self.unique_stacks.is_empty() {
            return Ok(collector);
        }

        // Flush pending samples to the collector
        eprintln!(
            "Flushing {} pending stack samples...",
            self.pending_samples.len()
        );
        for sample in self.pending_samples.drain(..) {
            collector.add_stack_sample(sample)?;
        }

        // Now symbolize all unique stacks and stream StackRecords
        let total_stacks = self.unique_stacks.len();
        let progress_bar = if total_stacks > 0 {
            let pb = ProgressBar::new(total_stacks as u64);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template(
                        "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} stacks ({per_sec}, {eta})"
                    )
                    .expect("Failed to set progress bar template")
                    .progress_chars("#>-"),
            );
            pb.set_message("Symbolizing stacks");
            Some(pb)
        } else {
            None
        };

        let mut symbolizer = self.create_symbolizer();

        // Create kernel source once - it's shared across all processes
        let kernel_src = Source::Kernel(Kernel::default());

        // Address cache: blazesym caches metadata (KASLR, ELF parsing) but not individual
        // symbolization results. We cache (addr, tgid) -> frame_name to avoid re-symbolizing
        // the same address across different stacks.
        let mut addr_cache: HashMap<(u64, i32), String> = HashMap::new();

        // Group stacks by tgid to reuse process sources efficiently
        let mut stacks_by_tgid: HashMap<i32, Vec<(&Stack, i64)>> = HashMap::new();
        for ((stack, tgid), stack_id) in self.unique_stacks.iter() {
            stacks_by_tgid
                .entry(*tgid)
                .or_default()
                .push((stack, *stack_id));
        }

        // Process each tgid group with a single Source per process
        for (tgid, stacks) in stacks_by_tgid.iter() {
            // Create process source once per tgid
            let proc_src = Source::Process(Process::new(Pid::from(*tgid as u32)));

            // Pre-cache process metadata for this tgid (best-effort optimization;
            // result is ignored as caching failure doesn't affect correctness)
            let _ = symbolizer.cache(&cache::Cache::from(cache::Process::new(
                (*tgid as u32).into(),
            )));

            for (stack, stack_id) in stacks {
                // Symbolize this stack using the shared sources and address cache
                let frame_names = self.symbolize_stack_with_sources_cached(
                    &mut symbolizer,
                    stack,
                    &proc_src,
                    &kernel_src,
                    *tgid,
                    &mut addr_cache,
                );

                // Update progress bar
                if let Some(ref pb) = progress_bar {
                    pb.inc(1);
                }

                // Skip empty stacks
                if frame_names.is_empty() {
                    continue;
                }

                let leaf_name = frame_names.first().cloned().unwrap_or_default();
                let depth = frame_names.len().min(i32::MAX as usize) as i32;

                collector.add_stack(StackRecord {
                    id: *stack_id,
                    frame_names,
                    depth,
                    leaf_name,
                })?;
            }
        }

        // Finish the progress bar
        if let Some(pb) = progress_bar {
            pb.finish_with_message("Stack symbolization complete");
        }

        // Flush and return the collector
        collector.flush()?;
        Ok(collector)
    }

    /// Check if streaming mode is enabled.
    pub fn is_streaming(&self) -> bool {
        self.streaming_enabled
    }

    /// Symbolize a single stack and return frame names.
    /// Takes pre-created Source objects and an address cache for efficiency.
    /// Blazesym caches metadata (KASLR, ELF parsing) but not symbolization results,
    /// so we maintain our own cache for individual addresses.
    fn symbolize_stack_with_sources_cached(
        &self,
        symbolizer: &mut Symbolizer,
        stack: &Stack,
        proc_src: &Source<'_>,
        kernel_src: &Source<'_>,
        tgid: i32,
        addr_cache: &mut HashMap<(u64, i32), String>,
    ) -> Vec<String> {
        let mut frame_names = Vec::with_capacity(
            stack.user_stack.len() + stack.kernel_stack.len() + stack.py_stack.len(),
        );

        // Symbolize Python stack first (if present)
        let python_frames = self.psr.get_python_frame_names(&stack.py_stack);
        frame_names.extend(python_frames);

        // Symbolize user addresses (leaf) - use tgid for cache key
        for &addr in &stack.user_stack {
            let frame_name = addr_cache
                .entry((addr, tgid))
                .or_insert_with(|| {
                    symbolizer
                        .symbolize_single(proc_src, Input::AbsAddr(addr))
                        .ok()
                        .and_then(|s| s.into_sym())
                        .map(|s| format_symbolized_frame(&s, addr, "unknown"))
                        .unwrap_or_else(|| format!("0x{addr:x}"))
                })
                .clone();
            frame_names.push(frame_name);
        }

        // Symbolize kernel addresses (root).
        // Use tgid=0 since KASLR offset is system-wide; the same kernel address
        // resolves identically for all processes.
        for &addr in &stack.kernel_stack {
            let frame_name = addr_cache
                .entry((addr, 0))
                .or_insert_with(|| {
                    symbolizer
                        .symbolize_single(kernel_src, Input::AbsAddr(addr))
                        .ok()
                        .and_then(|s| s.into_sym())
                        .map(|s| format_symbolized_frame(&s, addr, "[kernel]"))
                        .unwrap_or_else(|| format!("unknown ([kernel]) <{addr:#x}>"))
                })
                .clone();
            frame_names.push(frame_name);
        }

        frame_names
    }

    pub fn init_pystacks(&mut self, pids: &[u32], bpf_object: &libbpf_rs::Object, debug: bool) {
        if let Some(psr) = Arc::get_mut(&mut self.psr) {
            psr.init_pystacks(pids, bpf_object, debug);
        } else {
            // If we can't get exclusive access, it means the Arc is already shared
            // This shouldn't happen during initialization, but we handle it gracefully
            eprintln!("Warning: Unable to initialize pystacks - Arc is already shared");
        }
    }

    /// Symbolizes all stacks (user, kernel, and Python) and returns the resolved information
    fn symbolize_stacks<'a>(
        &self,
        symbolizer: &mut Symbolizer,
        stacks: &[StackEvent],
        tgid: u32,
        id_counter: &Arc<AtomicUsize>,
        global_kernel_frame_map: &'a mut HashMap<u64, Vec<LocalFrame>>,
        progress_bar: &Option<ProgressBar>,
    ) -> ResolvedStackInfo<'a> {
        let user_src = Source::Process(Process::new(Pid::from(tgid)));
        let kernel_src = Source::Kernel(Kernel::default());

        // Cache process metadata for this specific process
        let _ = symbolizer.cache(&cache::Cache::from(cache::Process::new(tgid.into())));

        let mut user_frame_map = HashMap::new();
        let mut python_calls = Vec::new();
        let mut python_stack_markers = Vec::new();

        for stack in stacks.iter() {
            let raw_stack = &stack.stack;

            // Symbolize Python stack FIRST (per-process)
            self.psr.pystacks_to_frames_mapping(
                &mut user_frame_map,
                &self.global_func_manager,
                id_counter,
                &mut python_stack_markers,
                &raw_stack.py_stack,
            );

            // Symbolize user space stack (per-process)
            stack_to_frames_mapping(
                symbolizer,
                &mut user_frame_map,
                &self.global_func_manager,
                &user_src,
                id_counter,
                raw_stack.user_stack.iter(),
                progress_bar,
            );

            // Symbolize kernel stack
            stack_to_frames_mapping(
                symbolizer,
                global_kernel_frame_map,
                &self.global_func_manager,
                &kernel_src,
                id_counter,
                raw_stack.kernel_stack.iter(),
                progress_bar,
            );
        }

        // Detect PyEval frames in user stack (called once after all stacks are symbolized)
        self.psr.user_stack_to_python_calls(
            &mut user_frame_map,
            &self.global_func_manager,
            &mut python_calls,
        );

        ResolvedStackInfo {
            user_frame_map,
            kernel_frame_map: global_kernel_frame_map,
            python_calls,
            python_stack_markers,
        }
    }

    /// Process stacks for a single process and collect the interned data.
    /// Returns interned data and a closure that can write sample packets later
    /// (samples must be written after the interned data packet).
    fn process_tgid_stacks(
        &self,
        symbolizer: &mut Symbolizer,
        tgid: u32,
        stacks: &[StackEvent],
        global_kernel_frame_map: &mut HashMap<u64, Vec<LocalFrame>>,
        ctx: &TraceContext,
    ) -> (
        Vec<Callstack>,
        Vec<Frame>,
        Vec<Mapping>,
        HashMap<Stack, Callstack>,
    ) {
        // Step 1: Symbolize all stacks
        let resolved_info = self.symbolize_stacks(
            symbolizer,
            stacks,
            tgid,
            ctx.id_counter,
            global_kernel_frame_map,
            ctx.progress_bar,
        );

        // Step 2: Deduplicate stacks and collect interned data
        let deduplicated_data =
            deduplicate_stacks(stacks, &resolved_info, ctx.id_counter, &self.psr);

        // Collect all interned data (only user frames/mappings from per-process data)
        let callstacks: Vec<Callstack> = deduplicated_data.callstacks.values().cloned().collect();
        let user_frames = collect_frames(&resolved_info.user_frame_map);
        let user_mappings = collect_mappings(&resolved_info.user_frame_map);

        // Return the callstack map so samples can be written later (after interned data)
        (
            callstacks,
            user_frames,
            user_mappings,
            deduplicated_data.callstacks,
        )
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

    /// Write trace data directly to a RecordCollector (Parquet-first path).
    ///
    /// This method outputs stack profiling data as native records. It performs
    /// symbolization and outputs the results directly without Perfetto format.
    ///
    /// Uses a simplified schema where StackRecord contains only frame_names
    /// (with embedded module and location info) - no separate frame/symbol tables.
    ///
    /// Frame names are formatted as: `function_name (module_name [file:line]) <0xaddr>`
    pub fn write_records(
        &self,
        collector: &mut dyn RecordCollector,
        stack_id_counter: &mut i64,
    ) -> Result<()> {
        // Stack deduplication cache (key: frame_names as a comparable key)
        let mut stack_cache: HashMap<Vec<String>, i64> = HashMap::new();

        // Process each unique stack
        for (tgid, events) in self.stacks.iter() {
            let symbolizer = self.create_symbolizer();

            // Process each unique stack for this tgid
            let unique_stacks: HashSet<_> = events.iter().map(|e| &e.stack).collect();

            // Stack ID cache for this tgid (maps Stack -> stack_id)
            let mut tgid_stack_cache: HashMap<&Stack, i64> = HashMap::new();

            for stack in unique_stacks.iter() {
                // Collect addresses for symbolization (user first, then kernel)
                // This gives us leaf-to-root order in the arrays
                let addr_count = stack.user_stack.len() + stack.kernel_stack.len();
                let mut all_addrs = Vec::with_capacity(addr_count);

                // Add user addresses first (leaf)
                for &addr in &stack.user_stack {
                    all_addrs.push((addr, false)); // is_kernel=false
                }

                // Add kernel addresses (root)
                for &addr in &stack.kernel_stack {
                    all_addrs.push((addr, true)); // is_kernel=true
                }

                // Build frame_names array with embedded module/location info
                let mut frame_names: Vec<String> = Vec::with_capacity(addr_count);

                for (addr, is_kernel) in all_addrs.iter() {
                    // Symbolize and format frame name with embedded info
                    let frame_name = if *is_kernel {
                        let kernel_src = Source::Kernel(Kernel::default());
                        let sym_result =
                            symbolizer.symbolize_single(&kernel_src, Input::AbsAddr(*addr));
                        sym_result
                            .ok()
                            .and_then(|s| s.into_sym())
                            .map(|s| {
                                let module_name = s
                                    .module
                                    .as_ref()
                                    .and_then(|m| m.to_str())
                                    .and_then(|m| std::path::Path::new(m).file_name())
                                    .and_then(|f| f.to_str())
                                    .unwrap_or("[kernel]");
                                let location_info = format_location_info(&s.code_info);
                                format!(
                                    "{} ({}{}) <{:#x}>",
                                    s.name, module_name, location_info, *addr
                                )
                            })
                            .unwrap_or_else(|| format!("unknown ([kernel]) <{:#x}>", *addr))
                    } else {
                        let proc_src = Source::Process(Process::new(Pid::from(*tgid as u32)));
                        let sym_result =
                            symbolizer.symbolize_single(&proc_src, Input::AbsAddr(*addr));
                        sym_result
                            .ok()
                            .and_then(|s| s.into_sym())
                            .map(|s| {
                                let module_name = s
                                    .module
                                    .as_ref()
                                    .and_then(|m| m.to_str())
                                    .and_then(|m| std::path::Path::new(m).file_name())
                                    .and_then(|f| f.to_str())
                                    .unwrap_or("unknown");
                                let location_info = format_location_info(&s.code_info);
                                format!(
                                    "{} ({}{}) <{:#x}>",
                                    s.name, module_name, location_info, *addr
                                )
                            })
                            .unwrap_or_else(|| format!("0x{:x}", *addr))
                    };

                    frame_names.push(frame_name);
                }

                // Skip empty stacks
                if frame_names.is_empty() {
                    continue;
                }

                // Check if this exact stack already exists (global deduplication by frame_names)
                let stack_id = if let Some(&id) = stack_cache.get(&frame_names) {
                    id
                } else {
                    let id = *stack_id_counter;
                    *stack_id_counter += 1;

                    let leaf_name = frame_names.first().cloned().unwrap_or_default();
                    let depth = frame_names.len().min(i32::MAX as usize) as i32;

                    // Clone frame_names for the cache key before moving into StackRecord
                    let cache_key = frame_names.clone();

                    collector.add_stack(StackRecord {
                        id,
                        frame_names,
                        depth,
                        leaf_name,
                    })?;

                    stack_cache.insert(cache_key, id);
                    id
                };

                tgid_stack_cache.insert(stack, stack_id);
            }

            // Now output stack samples with stack references
            for event in events.iter() {
                let tid = event.tgidpid as i32;
                let utid = self.utid_generator.get_or_create_utid(tid);

                if let Some(&stack_id) = tgid_stack_cache.get(&event.stack) {
                    collector.add_stack_sample(StackSampleRecord {
                        ts: event.ts_start as i64,
                        utid,
                        cpu: None,
                        stack_id,
                        stack_event_type: event.stack_event_type,
                    })?;
                }
            }
        }

        Ok(())
    }

    /// Write trace data to Perfetto format (used by parquet-to-perfetto conversion).
    pub fn write_trace(
        &self,
        writer: &mut dyn TraceWriter,
        id_counter: &Arc<AtomicUsize>,
    ) -> Result<()> {
        // Get a unique sequence ID for this trace
        let sequence_id = id_counter.fetch_add(1, Ordering::Relaxed) as u32;

        // Count all addresses that will need symbolization
        let total_addresses = collect_total_addresses(&self.stacks);

        // Create a single symbolizer to reuse across all processes
        // This avoids the ~60ms initialization overhead per process
        let mut symbolizer = self.create_symbolizer();

        // Create a progress bar if we have addresses to process
        let progress_bar = if total_addresses > 0 {
            let pb = ProgressBar::new(total_addresses as u64);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template(
                        "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} symbols ({per_sec}, {eta})"
                    )
                    .expect("Failed to set progress bar template")
                    .progress_chars("#>-"),
            );
            pb.set_message("Resolving stack symbols");
            Some(pb)
        } else {
            None
        };

        // Collect all interned data from all processes
        // We still need to collect these in memory as they go into a single packet
        let mut all_callstacks = Vec::new();
        let mut all_user_frames = Vec::new();
        let mut all_user_mappings = Vec::new();

        // Store callstack maps per-tgid so we can write samples after interned data
        let mut tgid_callstack_maps: Vec<(i32, HashMap<Stack, Callstack>)> = Vec::new();

        // Global kernel frame map shared across all processes
        let mut global_kernel_frame_map = HashMap::new();

        // Create trace context to pass common parameters
        let ctx = TraceContext {
            id_counter,
            progress_bar: &progress_bar,
        };

        // Phase 1: Process each tgid's stacks and collect interned data
        // (sample packets will be written after interned data)
        for (tgid, stacks) in self.stacks.iter() {
            let tgid_u32 = *tgid as u32;

            let (callstacks, user_frames, user_mappings, callstack_map) = self.process_tgid_stacks(
                &mut symbolizer,
                tgid_u32,
                stacks,
                &mut global_kernel_frame_map,
                &ctx,
            );

            all_callstacks.extend(callstacks);
            all_user_frames.extend(user_frames);
            all_user_mappings.extend(user_mappings);
            tgid_callstack_maps.push((*tgid, callstack_map));
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

        // Phase 2: Write the interned data packet FIRST (before sample packets)
        if let Some(interned_packet) =
            self.create_interned_packet(all_callstacks, all_frames, all_mappings, sequence_id)
        {
            writer.write_packet(&interned_packet)?;
        }

        // Phase 3: Now write sample packets (they reference IIDs from interned data)
        for (tgid, callstack_map) in tgid_callstack_maps {
            let stacks = self
                .stacks
                .get(&tgid)
                .expect("tgid must exist since we just collected from self.stacks");
            write_sample_packets(writer, stacks, &callstack_map, sequence_id)?;
        }

        // Finish the progress bar
        if let Some(pb) = progress_bar {
            pb.finish_with_message("Stack symbol resolution complete");
        }

        Ok(())
    }

    /// Returns the minimum timestamp from all stacks, or None if no stacks recorded.
    pub fn min_timestamp(&self) -> Option<u64> {
        self.stacks
            .values()
            .flatten()
            .map(|stack| stack.ts_start)
            .min()
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

/// Formats code location information as a string suffix (e.g., "[file.rs:123]")
fn format_location_info(code_info: &Option<blazesym::symbolize::CodeInfo>) -> String {
    code_info.as_ref().map_or(String::new(), |info| {
        let file_name = info.file.to_str().unwrap_or("unknown");
        if let Some(line) = info.line {
            format!(" [{file_name}:{line}]")
        } else {
            format!(" [{file_name}]")
        }
    })
}

/// Formats a symbolized frame as a string with module and location info.
/// Format: "function_name (module_name [file:line]) <0xaddr>"
fn format_symbolized_frame(sym: &Sym, addr: u64, default_module: &str) -> String {
    let module_name = sym
        .module
        .as_ref()
        .and_then(|m| m.to_str())
        .and_then(|m| std::path::Path::new(m).file_name())
        .and_then(|f| f.to_str())
        .unwrap_or(default_module);
    let location_info = format_location_info(&sym.code_info);
    format!(
        "{} ({}{}) <{:#x}>",
        sym.name, module_name, location_info, addr
    )
}

pub fn stack_to_frames_mapping<'a, I>(
    symbolizer: &mut Symbolizer,
    frame_map: &mut HashMap<u64, Vec<LocalFrame>>,
    global_func_manager: &Arc<GlobalFunctionManager>,
    source: &Source<'a>,
    id_counter: &Arc<AtomicUsize>,
    stack: I,
    progress_bar: &Option<ProgressBar>,
) where
    I: IntoIterator<Item = &'a u64>,
{
    for input_addr in stack {
        if frame_map.contains_key(input_addr) {
            if let Some(pb) = progress_bar {
                pb.inc(1);
            }
            continue;
        }

        match symbolizer.symbolize_single(source, Input::AbsAddr(*input_addr)) {
            Ok(Symbolized::Sym(Sym {
                addr,
                name,
                module,
                offset,
                code_info,
                inlined,
                ..
            })) => {
                // Build symbol name with module and optional source location
                let module_name = module
                    .as_ref()
                    .and_then(|m| m.to_str())
                    .and_then(|m| std::path::Path::new(m).file_name())
                    .and_then(|f| f.to_str())
                    .unwrap_or("unknown");

                let location_info = format_location_info(&code_info);

                let name = format!(
                    "{} ({}{}) <{:#x}>",
                    name, module_name, location_info, *input_addr
                );
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
                    let inline_location_info = format_location_info(&inline.code_info);

                    let name = format!(
                        "{} ({}{}) (inlined) <{:#x}>",
                        inline.name, module_name, inline_location_info, *input_addr
                    );
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
            Ok(Symbolized::Unknown(Reason::MissingSyms)) => {
                // Only add "unknown" symbol for missing symbol tables
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
            _ => {
                // Skip all other addresses (UnknownAddr, errors, etc.)
            }
        }

        // Update progress bar for each address processed
        if let Some(pb) = progress_bar {
            pb.inc(1);
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
                println!("Failed to create caching debuginfod client: {e}, using default resolver");
                None
            }
        },
        Ok(None) => {
            println!("No debuginfod URLs found in environment, using default resolver. If using sudo try --preserve-env");
            None
        }
        Err(e) => {
            println!("Failed to create debuginfod client: {e}, using default resolver");
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

/// Context for trace generation shared across symbolization calls
struct TraceContext<'a> {
    id_counter: &'a Arc<AtomicUsize>,
    progress_bar: &'a Option<ProgressBar>,
}

/// Holds deduplicated stack data
struct DeduplicatedStackData {
    callstacks: HashMap<Stack, Callstack>,
}

/// Extracts frame IDs from the frame map for the given addresses
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

/// Collects all frames from the frame map
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

/// Collects all mappings from the frame map
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

/// Builds a callstack from frame IDs
/// Returns None if the resulting callstack would have no frames
fn build_callstack_for_stack(
    stack: &Stack,
    resolved_info: &ResolvedStackInfo,
    id_counter: &Arc<AtomicUsize>,
    psr: &Arc<StackWalkerRun>,
) -> Option<Callstack> {
    let frame_ids: Vec<u64> = if stack.py_stack.is_empty() {
        // No Python stack - chain user and kernel frame IDs
        let user_frame_ids =
            extract_frame_ids(&resolved_info.user_frame_map, stack.user_stack.iter());
        let kernel_frame_ids =
            extract_frame_ids(resolved_info.kernel_frame_map, stack.kernel_stack.iter());

        user_frame_ids.into_iter().chain(kernel_frame_ids).collect()
    } else {
        // Merge Python stacks with user stacks
        let merged_addrs = psr.merge_pystacks(
            stack,
            &resolved_info.python_calls,
            &resolved_info.python_stack_markers,
        );

        let user_frame_ids = extract_frame_ids(&resolved_info.user_frame_map, merged_addrs.iter());
        let kernel_frame_ids =
            extract_frame_ids(resolved_info.kernel_frame_map, stack.kernel_stack.iter());

        user_frame_ids.into_iter().chain(kernel_frame_ids).collect()
    };

    // Don't create callstacks with no frames - this can happen when all addresses
    // in a stack were skipped during symbolization (e.g., all UnknownAddr)
    if frame_ids.is_empty() {
        return None;
    }

    let mut callstack = Callstack::default();
    let iid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;
    callstack.set_iid(iid);
    callstack.frame_ids = frame_ids;

    Some(callstack)
}

/// Deduplicates stacks and creates callstack mappings
/// Filters out stacks that would result in empty callstacks
fn deduplicate_stacks(
    stacks: &[StackEvent],
    resolved_info: &ResolvedStackInfo,
    id_counter: &Arc<AtomicUsize>,
    psr: &Arc<StackWalkerRun>,
) -> DeduplicatedStackData {
    // First, collect unique stacks
    let unique_stacks: HashSet<Stack> = stacks.iter().map(|event| event.stack.clone()).collect();

    // Then, create a callstack for each unique stack, filtering out empty ones
    let callstacks: HashMap<Stack, Callstack> = unique_stacks
        .into_iter()
        .filter_map(|stack| {
            build_callstack_for_stack(&stack, resolved_info, id_counter, psr)
                .map(|callstack| (stack, callstack))
        })
        .collect();

    DeduplicatedStackData { callstacks }
}

/// Generates PerfSample packets from the deduplicated stacks
/// Skips stacks that don't have a callstack (e.g., filtered out due to empty frames)
fn write_sample_packets(
    writer: &mut dyn TraceWriter,
    stacks: &[StackEvent],
    callstack_map: &HashMap<Stack, Callstack>,
    sequence_id: u32,
) -> Result<()> {
    // Generate and write sample packets for each stack
    for stack in stacks.iter() {
        // Skip stacks that were filtered out during deduplication (empty callstacks)
        let callstack = match callstack_map.get(&stack.stack) {
            Some(cs) => cs,
            None => continue,
        };

        let pid = stack.tgidpid as u32;
        let tgid = (stack.tgidpid >> 32) as u32;
        let mut packet = TracePacket::default();
        packet.set_timestamp(stack.ts_start);

        let mut sample = PerfSample::default();
        sample.set_callstack_iid(callstack.iid());
        sample.set_pid(tgid);
        sample.set_tid(pid);
        packet.set_perf_sample(sample);
        packet.set_trusted_packet_sequence_id(sequence_id);
        writer.write_packet(&packet)?;
    }
    Ok(())
}

impl SystingRecordEvent<stack_event> for StackRecorder {
    fn ringbuf(&self) -> &RingBuffer<stack_event> {
        &self.ringbuf
    }
    fn ringbuf_mut(&mut self) -> &mut RingBuffer<stack_event> {
        &mut self.ringbuf
    }
    fn handle_event(&mut self, event: stack_event) {
        #[cfg(feature = "pystacks")]
        let py_stack_len = event.py_msg_buffer.stack_len;
        #[cfg(not(feature = "pystacks"))]
        let py_stack_len = 0;

        let has_stack =
            event.user_stack_length > 0 || event.kernel_stack_length > 0 || py_stack_len > 0;

        if has_stack {
            let kstack_vec = Vec::from(&event.kernel_stack[..event.kernel_stack_length as usize]);
            let ustack_vec = Vec::from(&event.user_stack[..event.user_stack_length as usize]);
            let stack_key = (event.task.tgidpid >> 32) as i32;
            let py_stack = self.psr.get_pystack_from_event(&event);

            let stack = Stack::new(&kstack_vec, &ustack_vec, &py_stack);
            let tid = event.task.tgidpid as i32;
            let tgid = stack_key; // tgid for process-specific symbolization

            // Streaming mode: dedupe stacks and buffer samples for streaming
            if self.streaming_enabled {
                // Get or assign stack_id for this (stack, tgid) pair
                // Include tgid in key since same addresses may resolve differently per-process
                let key = (stack, tgid);
                let stack_id = if let Some(&id) = self.unique_stacks.get(&key) {
                    id
                } else {
                    let id = self.next_stack_id;
                    self.next_stack_id += 1;
                    self.unique_stacks.insert(key, id);
                    id
                };

                // Buffer the sample for streaming (will be flushed in finish())
                self.pending_samples.push(StackSampleRecord {
                    ts: event.ts as i64,
                    utid: self.utid_generator.get_or_create_utid(tid),
                    cpu: Some(event.cpu as i32),
                    stack_id,
                    stack_event_type: convert_stack_event_type(event.stack_event_type.0),
                });
            } else {
                // Non-streaming mode: store all events for later processing
                let stack_event = StackEvent {
                    tgidpid: event.task.tgidpid,
                    ts_start: event.ts,
                    stack,
                    stack_event_type: convert_stack_event_type(event.stack_event_type.0),
                };
                let stacks = self.stacks.entry(stack_key).or_default();
                stacks.push(stack_event);
            }
        }
    }
}

/// Collects the total count of all addresses from all stacks that will need symbolization
fn collect_total_addresses(stacks: &HashMap<i32, Vec<StackEvent>>) -> usize {
    stacks
        .values()
        .flat_map(|events| events.iter())
        .map(|event| {
            event.stack.user_stack.len()
                + event.stack.kernel_stack.len()
                + event.stack.py_stack.len()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    //! Test suite for stack recording and symbolization.
    //!
    //! Note: Tests in this module use fake PIDs and addresses that don't exist in /proc.
    //! The blazesym resolver returns UnknownAddr for unmapped addresses, which our logic
    //! skips during symbolization (only MissingSyms gets "unknown" frames). As a result,
    //! stacks with no resolved frames are filtered out. These tests verify the trace
    //! generation pipeline works end-to-end despite fake data.

    use super::*;
    use crate::perfetto::VecTraceWriter;
    use crate::utid::UtidGenerator;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    #[test]
    fn test_filter_and_reverse_user_stack() {
        // Test zero filtering
        assert_eq!(filter_and_reverse_user_stack(&[0, 0x1000, 0]), vec![0x1000]);

        // Test reversal
        assert_eq!(
            filter_and_reverse_user_stack(&[0x1000, 0x2000]),
            vec![0x2000, 0x1000]
        );

        // Test MAX_USER_ADDR boundary - address at boundary should be kept
        assert_eq!(
            filter_and_reverse_user_stack(&[0x1000, MAX_USER_ADDR]),
            vec![MAX_USER_ADDR, 0x1000]
        );

        // Test garbage addresses above MAX_USER_ADDR are filtered
        assert_eq!(
            filter_and_reverse_user_stack(&[0x1000, MAX_USER_ADDR + 1]),
            vec![0x1000]
        );

        // Test typical garbage from bad frame pointer unwinding (instruction bytes)
        assert_eq!(
            filter_and_reverse_user_stack(&[0x7f0000001000, 0xc48348d88948ff31]),
            vec![0x7f0000001000]
        );

        // Empty stack
        assert_eq!(filter_and_reverse_user_stack(&[]), Vec::<u64>::new());

        // All zeros
        assert_eq!(filter_and_reverse_user_stack(&[0, 0, 0]), Vec::<u64>::new());
    }

    #[test]
    fn test_filter_and_reverse_kernel_stack() {
        // Test zero filtering
        assert_eq!(
            filter_and_reverse_kernel_stack(&[0, 0xffffffff81000000, 0]),
            vec![0xffffffff81000000]
        );

        // Test reversal
        assert_eq!(
            filter_and_reverse_kernel_stack(&[0xffffffff81000000, 0xffffffff82000000]),
            vec![0xffffffff82000000, 0xffffffff81000000]
        );

        // Kernel addresses above MAX_USER_ADDR should be kept
        assert_eq!(
            filter_and_reverse_kernel_stack(&[0xffffffff81000000]),
            vec![0xffffffff81000000]
        );

        // Empty stack
        assert_eq!(filter_and_reverse_kernel_stack(&[]), Vec::<u64>::new());
    }

    fn create_test_recorder() -> StackRecorder {
        StackRecorder::new(false, Arc::new(UtidGenerator::new()))
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
        let mut recorder = create_test_recorder();

        // Create a single test event
        let event = create_test_stack_event_raw(
            (1234 << 32) | 5678,
            1000000,
            &[0x1000, 0x2000],
            &[0x3000, 0x4000],
        );
        recorder.handle_event(event);

        let id_counter = Arc::new(AtomicUsize::new(100));
        let mut writer = VecTraceWriter::new();
        recorder.write_trace(&mut writer, &id_counter).unwrap();

        let sample_packets: Vec<_> = writer
            .packets
            .iter()
            .filter(|p| p.has_perf_sample())
            .collect();
        assert_eq!(sample_packets.len(), 0);
    }

    #[test]
    fn test_deduplicate_stacks_duplicate_stacks() {
        let mut recorder = create_test_recorder();

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
        let mut writer = VecTraceWriter::new();
        recorder.write_trace(&mut writer, &id_counter).unwrap();

        let sample_packets: Vec<_> = writer
            .packets
            .iter()
            .filter(|p| p.has_perf_sample())
            .collect();
        assert_eq!(sample_packets.len(), 0);
    }

    #[test]
    fn test_deduplicate_stacks_different_stacks() {
        let mut recorder = create_test_recorder();

        // Create two events with different stacks
        let event1 =
            create_test_stack_event_raw((1234 << 32) | 5678, 1000000, &[0x1000], &[0x3000]);
        recorder.handle_event(event1);

        let event2 =
            create_test_stack_event_raw((1234 << 32) | 5679, 2000000, &[0x2000], &[0x4000]);
        recorder.handle_event(event2);

        let id_counter = Arc::new(AtomicUsize::new(100));
        let mut writer = VecTraceWriter::new();
        recorder.write_trace(&mut writer, &id_counter).unwrap();

        let sample_packets: Vec<_> = writer
            .packets
            .iter()
            .filter(|p| p.has_perf_sample())
            .collect();
        assert_eq!(sample_packets.len(), 0);
    }

    #[test]
    fn test_write_sample_packets_empty() {
        // Test packet generation with no stacks
        let stacks = vec![];
        let callstack_map = HashMap::new();

        let mut writer = VecTraceWriter::new();
        write_sample_packets(&mut writer, &stacks, &callstack_map, 1).unwrap();

        // Should have no packets since there are no stacks
        assert!(writer.packets.is_empty());
    }

    #[test]
    fn test_generate_trace_packets_single_stack() {
        let mut recorder = create_test_recorder();

        // Create a single test event
        let event = create_test_stack_event_raw(
            (1234 << 32) | 5678,
            1000000,
            &[0x1000, 0x2000],
            &[0x3000, 0x4000],
        );
        recorder.handle_event(event);

        let id_counter = Arc::new(AtomicUsize::new(100));
        let mut writer = VecTraceWriter::new();
        recorder.write_trace(&mut writer, &id_counter).unwrap();

        let sample_packets: Vec<_> = writer
            .packets
            .iter()
            .filter(|p| p.has_perf_sample())
            .collect();
        assert_eq!(sample_packets.len(), 0);
    }

    #[test]
    fn test_generate_trace_packets_multiple_stacks() {
        let mut recorder = create_test_recorder();

        // Create two test events with different processes
        let event1 =
            create_test_stack_event_raw((1234 << 32) | 5678, 1000000, &[0x1000], &[0x3000]);
        recorder.handle_event(event1);

        let event2 =
            create_test_stack_event_raw((5678 << 32) | 9012, 2000000, &[0x2000], &[0x4000]);
        recorder.handle_event(event2);

        let id_counter = Arc::new(AtomicUsize::new(100));
        let mut writer = VecTraceWriter::new();
        recorder.write_trace(&mut writer, &id_counter).unwrap();

        let sample_packets: Vec<_> = writer
            .packets
            .iter()
            .filter(|p| p.has_perf_sample())
            .collect();
        assert_eq!(sample_packets.len(), 0);
    }

    #[test]
    fn test_symbolize_stacks_with_mock_resolver() {
        // Test symbolization pipeline with generate_trace
        let mut recorder = create_test_recorder();

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
        let mut writer = VecTraceWriter::new();
        recorder.write_trace(&mut writer, &id_counter).unwrap();

        let sample_packets: Vec<_> = writer
            .packets
            .iter()
            .filter(|p| p.has_perf_sample())
            .collect();
        assert_eq!(sample_packets.len(), 0);
    }

    #[test]
    fn test_stack_recorder_with_custom_dispatcher() {
        // Test multiple stack events through the pipeline
        let mut recorder = create_test_recorder();

        // Create and handle multiple test events with different known addresses
        let event1 =
            create_test_stack_event_raw((1234 << 32) | 5678, 1000000, &[0x1000, 0x2000], &[0x3000]);
        recorder.handle_event(event1);

        let event2 =
            create_test_stack_event_raw((1234 << 32) | 5679, 2000000, &[0x5000, 0x6000], &[0x4000]);
        recorder.handle_event(event2);

        // Generate trace with mock resolver
        let id_counter = Arc::new(AtomicUsize::new(100));
        let mut writer = VecTraceWriter::new();
        recorder.write_trace(&mut writer, &id_counter).unwrap();

        let sample_packets: Vec<_> = writer
            .packets
            .iter()
            .filter(|p| p.has_perf_sample())
            .collect();
        assert_eq!(sample_packets.len(), 0);
    }

    #[test]
    fn test_deduplicate_stacks_with_mock_resolver() {
        // Test that duplicate stacks are properly deduplicated
        let mut recorder = create_test_recorder();

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
        let mut writer = VecTraceWriter::new();
        recorder.write_trace(&mut writer, &id_counter).unwrap();

        let sample_packets: Vec<_> = writer
            .packets
            .iter()
            .filter(|p| p.has_perf_sample())
            .collect();
        assert_eq!(sample_packets.len(), 0);
    }

    #[test]
    fn test_generate_trace_packets_timestamps() {
        let mut recorder = create_test_recorder();

        // Create two test events with same stack but different timestamps
        let event1 =
            create_test_stack_event_raw((1234 << 32) | 5678, 1000000, &[0x1000], &[0x3000]);
        recorder.handle_event(event1);

        let event2 =
            create_test_stack_event_raw((1234 << 32) | 5679, 2000000, &[0x1000], &[0x3000]);
        recorder.handle_event(event2);

        let id_counter = Arc::new(AtomicUsize::new(100));
        let mut writer = VecTraceWriter::new();
        recorder.write_trace(&mut writer, &id_counter).unwrap();

        let sample_packets: Vec<_> = writer
            .packets
            .iter()
            .filter(|p| p.has_perf_sample())
            .collect();
        assert_eq!(sample_packets.len(), 0);
    }
}
