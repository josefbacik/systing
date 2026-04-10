use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;

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
    cache, Input, ProcessMemberInfo, ProcessMemberType, Resolve, Sym, Symbolizer,
};
use blazesym::Error as BlazeErr;
use blazesym::Pid;

use indicatif::{ProgressBar, ProgressStyle};

type ProcessDispatcher = Box<
    dyn for<'a> Fn(ProcessMemberInfo<'a>) -> Result<Option<Box<dyn Resolve>>, BlazeErr>
        + Send
        + Sync,
>;
use debuginfod::{BuildId, CachingClient, Client};

// Stack structure representing kernel, user, and Python stacks
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Stack {
    pub(crate) kernel_stack: Vec<u64>,
    pub(crate) user_stack: Vec<u64>,
    pub(crate) py_stack: Vec<PyAddr>,
}

/// Maximum valid user-space address (48-bit virtual address space boundary).
/// Addresses above this threshold in the user stack are garbage from bad frame pointer
/// unwinding (typically instruction bytes or other non-address data that leaked into
/// the stack frame chain).
const MAX_USER_ADDR: u64 = 0x0000_FFFF_FFFF_FFFF;

/// Filters out zero and garbage addresses from user stack and reverses to get root-to-leaf order.
fn filter_and_reverse_user_stack(addrs: &[u64]) -> Vec<u64> {
    addrs
        .iter()
        .copied()
        .filter(|&addr| addr != 0 && addr <= MAX_USER_ADDR)
        .rev()
        .collect()
}

/// Filters out zero addresses from kernel stack and reverses to get root-to-leaf order.
fn filter_and_reverse_kernel_stack(addrs: &[u64]) -> Vec<u64> {
    addrs
        .iter()
        .copied()
        .filter(|&addr| addr != 0)
        .rev()
        .collect()
}

impl Stack {
    pub fn new(kernel_stack: &[u64], user_stack: &[u64], py_stack: &[PyAddr]) -> Self {
        Self {
            kernel_stack: filter_and_reverse_kernel_stack(kernel_stack),
            user_stack: filter_and_reverse_user_stack(user_stack),
            py_stack: py_stack.to_vec(),
        }
    }
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

pub struct StackRecorder {
    pub(crate) ringbuf: RingBuffer<stack_event>,
    pub(crate) psr: Arc<StackWalkerRun>,
    process_dispatcher: Option<Arc<ProcessDispatcher>>,
    // Streaming support
    /// Collector for emitting StackSampleRecords as they arrive. When set, samples
    /// are written immediately in handle_event() and stacks are deduplicated during
    /// recording for end-of-trace symbolization via finish().
    streaming_collector: Option<Box<dyn RecordCollector + Send>>,
    /// Maps (Stack, tgid) to stack_id for deduplication during streaming.
    /// The tgid is included in the key because the same addresses in different processes
    /// may resolve to different symbols (e.g., shared libraries at fixed addresses).
    unique_stacks: HashMap<(Stack, i32), i64>,
    /// External stack_ids that collided with an existing unique_stacks key during
    /// merge_external_stacks. Emitted as duplicate StackRecords in finish so every
    /// id referenced by a streamed record resolves.
    alias_stacks: Vec<(Stack, i32, i64)>,
    /// Next stack_id to assign for new unique stacks.
    next_stack_id: i64,
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

        Self {
            ringbuf: RingBuffer::default(),
            psr: Arc::new(StackWalkerRun::default()),
            process_dispatcher,
            streaming_collector: None,
            unique_stacks: HashMap::new(),
            alias_stacks: Vec::new(),
            next_stack_id: 1,
            utid_generator,
        }
    }

    /// Enable streaming mode and attach a collector so that StackSampleRecords
    /// are emitted immediately in handle_event() rather than accumulated for the
    /// entire trace. unique_stacks is still retained for end-of-trace symbolization.
    pub fn set_streaming_collector(&mut self, collector: Box<dyn RecordCollector + Send>) {
        self.streaming_collector = Some(collector);
    }

    /// Merge externally-deduped stacks (from another recorder) so they are
    /// symbolized and emitted alongside profiler stacks in `finish()`. When an
    /// external key collides with an existing entry, the external id is kept as
    /// an alias so both ids are emitted as StackRecords.
    pub fn merge_external_stacks(&mut self, stacks: HashMap<(Stack, i32), i64>) {
        for (key, id) in stacks {
            if let Some(&existing) = self.unique_stacks.get(&key) {
                if existing != id {
                    self.alias_stacks.push((key.0, key.1, id));
                }
            } else {
                self.unique_stacks.insert(key, id);
            }
        }
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
        collector: Box<dyn RecordCollector + Send>,
    ) -> Result<Box<dyn RecordCollector + Send>> {
        debug_assert!(
            self.streaming_collector.is_some(),
            "StackRecorder requires a streaming collector; non-streaming mode has been removed"
        );

        // Stack samples have already been written to the streaming collector
        // incrementally. Route the symbolized stacks through it as well, finish
        // it, and hand the caller's collector back untouched.
        let mut own = self
            .streaming_collector
            .take()
            .expect("streaming collector must be set");
        self.finish_inner(own.as_mut())?;
        own.flush()?;
        own.finish_boxed()?;
        Ok(collector)
    }

    fn finish_inner(&mut self, collector: &mut dyn RecordCollector) -> Result<()> {
        if self.unique_stacks.is_empty() && self.alias_stacks.is_empty() {
            return Ok(());
        }

        // Symbolize all unique stacks and stream StackRecords
        let pb = ProgressBar::new((self.unique_stacks.len() + self.alias_stacks.len()) as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} stacks ({per_sec}, {eta})"
                )
                .expect("Failed to set progress bar template")
                .progress_chars("#>-"),
        );
        pb.set_message("Symbolizing stacks");

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
        for (stack, tgid, stack_id) in self.alias_stacks.iter() {
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

                pb.inc(1);

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

        pb.finish_with_message("Stack symbolization complete");

        Ok(())
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
        let psr = Arc::get_mut(&mut self.psr).expect(
            "Unable to initialize pystacks: Arc is already shared. \
             The symbol loader thread must not be spawned before init_pystacks.",
        );
        psr.init_pystacks(pids, bpf_object, debug);
    }
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
                return Ok(None);
            };

            println!("Fetching debug info for build ID: {}", &build_id);
            let path = if let Some(path) = client.fetch_debug_info(&build_id).map_err(Box::from)? {
                path
            } else {
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

impl SystingRecordEvent<stack_event> for StackRecorder {
    fn ringbuf(&self) -> &RingBuffer<stack_event> {
        &self.ringbuf
    }
    fn ringbuf_mut(&mut self) -> &mut RingBuffer<stack_event> {
        &mut self.ringbuf
    }
    fn handle_event(&mut self, event: stack_event) {
        let py_stack_len = event.py_msg_buffer.stack_len;

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

            debug_assert!(
                self.streaming_collector.is_some(),
                "StackRecorder requires a streaming collector; non-streaming mode has been removed"
            );

            // Streaming mode: dedupe stacks and emit samples directly to the collector
            if let Some(collector) = &mut self.streaming_collector {
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

                let sample = StackSampleRecord {
                    ts: event.ts as i64,
                    utid: self.utid_generator.get_or_create_utid(tid),
                    cpu: Some(event.cpu as i32),
                    stack_id,
                    stack_event_type: convert_stack_event_type(event.stack_event_type.0),
                };

                if let Err(e) = collector.add_stack_sample(sample) {
                    eprintln!("Warning: Failed to stream stack sample: {e}");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_convert_stack_event_type() {
        assert_eq!(convert_stack_event_type(0), 0);
        assert_eq!(convert_stack_event_type(1), 1);
        assert_eq!(convert_stack_event_type(2), 2);
        assert_eq!(convert_stack_event_type(127), 127);
        assert_eq!(convert_stack_event_type(128), i8::MAX);
        assert_eq!(convert_stack_event_type(u32::MAX), i8::MAX);
    }
}
