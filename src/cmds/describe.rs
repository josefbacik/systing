use std::collections::HashMap;
use std::hash::Hash;
use std::io::Write;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::DescribeOpts;
use anyhow::{Error, Result};
use blazesym::symbolize::{CodeInfo, Input, Kernel, Process, Source, Sym, Symbolized, Symbolizer};
use blazesym::{Addr, Pid};
use inferno::flamegraph::Options;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::RingBufferBuilder;
use libbpf_rs::Iter;
use petgraph::graphmap::DiGraphMap;
use plain::Plain;

mod systing {
    include!(concat!(env!("OUT_DIR"), "/systing_describe.skel.rs"));
}

unsafe impl Plain for systing::types::wake_event {}

const ADDR_WIDTH: usize = 16;

fn pid_comm(pid: u32) -> String {
    let path = format!("/proc/{}/comm", pid);
    let comm = std::fs::read_to_string(path);
    if comm.is_err() {
        return "<unknown>".to_string();
    }
    comm.unwrap().trim().to_string()
}

fn print_frame(
    name: &str,
    addr_info: Option<(Addr, Addr, usize)>,
    code_info: &Option<CodeInfo>,
) -> String {
    let code_info = code_info.as_ref().map(|code_info| {
        let path = code_info.to_path();
        let path = path.display();

        match (code_info.line, code_info.column) {
            (Some(line), Some(col)) => format!(" {path}:{line}:{col}"),
            (Some(line), None) => format!(" {path}:{line}"),
            (None, _) => format!(" {path}"),
        }
    });

    if let Some((input_addr, addr, offset)) = addr_info {
        // If we have various address information bits we have a new symbol.
        format!(
            "  {input_addr:#0width$x}: {name} @ {addr:#x}+{offset:#x}{code_info}",
            code_info = code_info.as_deref().unwrap_or(""),
            width = ADDR_WIDTH
        )
        .to_string()
    } else {
        // Otherwise we are dealing with an inlined call.
        format!(
            "  {:width$}  {name}{code_info} [inlined]",
            " ",
            code_info = code_info
                .map(|info| format!(" @{info}"))
                .as_deref()
                .unwrap_or(""),
            width = ADDR_WIDTH
        )
        .to_string()
    }
}

fn print_symbols<'a, I>(syms: I) -> Vec<String>
where
    I: IntoIterator<Item = (Addr, Symbolized<'a>)>,
{
    let mut ret = Vec::new();
    for (input_addr, sym) in syms {
        match sym {
            Symbolized::Sym(Sym {
                addr,
                name,
                offset,
                code_info,
                inlined,
                ..
            }) => {
                ret.push(print_frame(
                    &name,
                    Some((input_addr, addr, offset)),
                    &code_info,
                ));
                for inline in inlined {
                    ret.push(print_frame(&inline.name, None, &inline.code_info));
                }
            }
            Symbolized::Unknown(e) => {
                ret.push(format!(
                    "  {input_addr:#0width$x}: <unknown: {e}>",
                    width = ADDR_WIDTH,
                    e = e
                ));
            }
        }
    }
    ret
}

struct SymbolizerCache<'a> {
    symbolizer: Symbolizer,
    kernel_src: Source<'a>,
    src_cache: HashMap::<u32, Source<'a>>,
}

enum StackType {
    Kernel,
    User,
}

struct Stack {
    kernel_stack: Vec<Addr>,
    user_stack: Vec<Addr>,
}

#[derive(Debug, Hash, Eq, PartialEq)]
struct WakeEventKey {
    waker: u64,
    wakee: u64,
    waker_stack: Stack,
    wakee_stack: Stack,
}

struct WakeEventValue {
    count: u64,
    duration_us: u64,
}

struct WakeEvent {
    key: WakeEventKey,
    value: WakeEventValue,
}

impl<'a> SymbolizerCache<'a> {
    pub fn new() -> Self {
        SymbolizerCache {
            symbolizer: Symbolizer::new(),
            kernel_src: Source::Kernel(Kernel::default()),
            src_cache: HashMap::new(),
        }
    }

    pub fn symbolize_stack(
        &mut self,
        pid: u32,
        stack: &Stack,
        stack_type: StackType,
    ) -> Result<Vec<String>, Error> {
        let src = match stack_type {
            StackType::Kernel => &self.kernel_src,
            StackType::User => {
                if !self.src_cache.contains_key(&pid) {
                    self.src_cache
                        .insert(pid, Source::Process(Process::new(Pid::from(pid))));
                }
                self.src_cache.get(&pid).unwrap()
            }
        };
        let raw_stack = match stack_type {
            StackType::Kernel => &stack.kernel_stack,
            StackType::User => &stack.user_stack,
        };
        match self.symbolizer.symbolize(src, Input::AbsAddr(raw_stack)) {
            Ok(syms) => Ok(print_symbols(raw_stack.iter().copied().zip(syms))),
            Err(e) => Err(e.into()),
        }
    }
}

impl Stack {
    pub fn new(kernel_stack: Vec<Addr>, user_stack: Vec<Addr>) -> Self {
        Stack {
            kernel_stack,
            user_stack,
        }
    }

    pub fn symbolize(
        &self,
        symbolizer: &Symbolizer,
        src: &Source,
        stack_type: StackType,
    ) -> Result<Vec<String>, Error> {
        let stack = match stack_type {
            StackType::Kernel => &self.kernel_stack,
            StackType::User => &self.user_stack,
        };

        match symbolizer.symbolize(src, Input::AbsAddr(stack)) {
            Ok(syms) => Ok(print_symbols(stack.iter().copied().zip(syms))),
            Err(e) => Err(e.into()),
        }
    }
}

impl WakeEventKey {
    pub fn new(event: systing::types::wake_event) -> Self {
        // The waker can be the kernel, to avoid the overhead of memsetting the whole stack we use
        // a magic number for the first element so we can just zero out the stack.
        let waker_stack = match event.waker_user_stack[0] {
            1234 => vec![],
            _ => event
                .waker_user_stack
                .into_iter()
                .filter(|x| *x > 0)
                .collect(),
        };

        WakeEventKey {
            waker: event.waker_tgidpid,
            wakee: event.wakee_tgidpid,
            waker_kernel_stack: event
                .waker_kernel_stack
                .into_iter()
                .filter(|x| *x > 0)
                .collect(),
            wakee_kernel_stack: event
                .wakee_kernel_stack
                .into_iter()
                .filter(|x| *x > 0)
                .collect(),
            waker_user_stack: waker_stack,
            wakee_user_stack: event
                .wakee_user_stack
                .into_iter()
                .filter(|x| *x > 0)
                .collect(),
        }
    }

    pub fn symbolize_stack(
        &self,
        symbolizer: &Symbolizer,
        src: &Source,
        stack_type: StackType,
    ) -> Result<Vec<String>, Error> {
        let stack = match stack_type {
            StackType::WakerKernel => &self.waker_kernel_stack,
            StackType::WakeeKernel => &self.wakee_kernel_stack,
            StackType::WakerUser => &self.waker_user_stack,
            StackType::WakeeUser => &self.wakee_user_stack,
        };

        match symbolizer.symbolize(src, Input::AbsAddr(stack)) {
            Ok(syms) => Ok(print_symbols(stack.iter().copied().zip(syms))),
            Err(e) => Err(e.into()),
        }
    }
}

struct ProcessEvents {
    pidtgid: u64,
    duration_us: u64,
    events: HashMap<WakeEventKey, WakeEventValue>,
}

impl ProcessEvents {
    pub fn new(pidtgid: u64) -> Self {
        ProcessEvents {
            pidtgid,
            duration_us: 0,
            events: HashMap::new(),
        }
    }

    pub fn add_event(&mut self, event: systing::types::wake_event) {
        let key = WakeEventKey::new(event);
        self.duration_us += event.sleep_time_us;
        match self.events.get_mut(&key) {
            Some(ref mut value) => {
                value.count += 1;
                value.duration_us += event.sleep_time_us;
            }
            None => {
                self.events.insert(
                    key,
                    WakeEventValue {
                        count: 1,
                        duration_us: event.sleep_time_us,
                    },
                );
            }
        };
    }

    pub fn write_flamegraph(
        &self,
        src_cache: &mut SymbolizerCache,
        w: &mut dyn Write,
    ) {
        let mut opts = Options::default();
        opts.min_width = 0.1;
        opts.title = format!(
            "Process: tgid {} pid {} comm {}",
            self.pidtgid >> 32,
            self.pidtgid as u32,
            pid_comm(self.pidtgid as u32)
        );

        let mut lines = Vec::new();
        for (key, value) in self.events.iter() {
            let mut syms = Vec::new();
            let waker_pid = key.waker as u32;
            let wakee_pid = key.wakee as u32;

            syms.extend(
                src_cache.symbolize_stack(wakee_pid, &key.wakee_stack, StackType::Kernel)
                    .unwrap_or(Vec::new()),
            );
            syms.extend(
                src_cache.symbolize_stack(wakee_pid, &key.wakee_stack, StackType::Kernel)
                    .unwrap_or(Vec::new()),
            );
            syms.push(format!("{}_{}", pid_comm(waker_pid), waker_pid).to_string());
            syms.extend(
                src_cache.symbolize_stack(waker_pid, &key.waker_stack, StackType::Kernel)
                    .unwrap_or(Vec::new()),
            );
            syms.extend(
                src_cache.symbolize_stack(waker_pid, &key.waker_stack, StackType::User)
                    .unwrap_or(Vec::new()),
            );
            lines.push(format!("{} {}", syms.join(";"), value.duration_us));
        }
        inferno::flamegraph::from_lines(&mut opts, lines.iter().map(|x| x.as_str()), w).unwrap();
    }
}

impl WakeEvent {
    pub fn print(
        &self,
        symbolizer: &Symbolizer,
        waker_src: &Source,
        wakee_src: &Source,
        kernel_src: &Source,
    ) {
        println!(
            "  Waker: tgid {} pid {} comm {}",
            self.key.waker >> 32,
            self.key.waker as u32,
            pid_comm(self.key.waker as u32)
        );
        println!(
            "  Count: {}, Duration: {}",
            self.value.count, self.value.duration_us
        );
        println!("  Waker kernel stack:");
        match self
            .key
            .waker_stack
            .symbolize(symbolizer, kernel_src, StackType::Kernel)
        {
            Ok(syms) => println!("{}", syms.join("\n")),
            Err(e) => eprintln!("Failed to symbolize waker kernel stack: {}", e),
        };

        match self
            .key
            .waker_stack
            .symbolize(symbolizer, waker_src, StackType::User)
        {
            Ok(syms) => {
                if !syms.is_empty() {
                    println!("  Waker user stack:");
                    println!("{}", syms.join("\n"));
                }
            }
            Err(e) => eprintln!("Failed to symbolize waker user stack: {}", e),
        };

        println!("  Wakee kernel stack:");
        match self
            .key
            .wakee_stack
            .symbolize(symbolizer, kernel_src, StackType::Kernel)
        {
            Ok(syms) => println!("{}", syms.join("\n")),
            Err(e) => eprintln!("Failed to symbolize wakee kernel stack: {}", e),
        };
        match self
            .key
            .symbolize_stack(symbolizer, wakee_src, StackType::WakeeUser)
        {
            Ok(syms) => {
                if !syms.is_empty() {
                    println!("  Wakee user stack:");
                    println!("{}", syms.join("\n"));
                }
            }
            Err(e) => eprintln!("Failed to symbolize wakee user stack: {}", e),
        };
        println!();
    }
}

fn print_graphviz(pids: Vec<u64>, graph: DiGraphMap<u64, u64>) -> Result<()> {
    use graphviz_rust::cmd::{CommandArg, Format};
    use graphviz_rust::dot_generator::*;
    use graphviz_rust::dot_structures::*;
    use graphviz_rust::exec;
    use graphviz_rust::printer::PrinterContext;

    let nodes: Vec<_> = pids
        .iter()
        .filter(|pid| **pid != 0)
        .map(|pid| {
            let label = format!("{} {}", pid_comm(*pid as u32), *pid as u32);
            stmt!(node!(esc pid; attr!("label", esc label)))
        })
        .collect();
    let edges: Vec<_> = graph
        .all_edges()
        .filter(|(waker, wakee, _)| *waker != 0 && *wakee != 0)
        .map(|(waker, wakee, duration)| {
            stmt!(edge!(node_id!(waker) => node_id!(wakee); attr!("label", duration)))
        })
        .collect();
    let g = graph!(strict di id!("describe"), vec![nodes, edges].into_iter().flatten().collect());
    exec(
        g,
        &mut PrinterContext::default(),
        vec![
            Format::Svg.into(),
            CommandArg::Output("systing-describe/graph.svg".to_string()),
        ],
    )?;
    Ok(())
}

fn print_stdout(process_events_vec: Vec<ProcessEvents>) -> Result<()> {
    let mut src_cache = HashMap::<u32, Source>::new();
    let symbolizer = Symbolizer::new();
    let kernel_src = Source::Kernel(Kernel::default());

    for process_events in process_events_vec {
        let mut events_vec: Vec<WakeEvent> = process_events
            .events
            .into_iter()
            .map(|(key, value)| WakeEvent { key, value })
            .collect();
        events_vec.sort_by_key(|k| (k.value.duration_us, k.value.count));
        let mut first = true;
        for event in events_vec {
            let wakee_pid = event.key.wakee as u32;
            let waker_pid = event.key.waker as u32;

            if first {
                println!(
                    "Process: tgid {} pid {} comm {}",
                    (event.key.wakee >> 32) as u32,
                    wakee_pid,
                    pid_comm(wakee_pid)
                );
                first = false;
            }

            if !src_cache.contains_key(&waker_pid) {
                src_cache.insert(
                    waker_pid,
                    Source::Process(Process::new(Pid::from(waker_pid))),
                );
            }
            if !src_cache.contains_key(&wakee_pid) {
                src_cache.insert(
                    wakee_pid,
                    Source::Process(Process::new(Pid::from(wakee_pid))),
                );
            }
            let waker_src = src_cache.get(&waker_pid).unwrap();
            let wakee_src = src_cache.get(&wakee_pid).unwrap();
            event.print(&symbolizer, waker_src, wakee_src, &kernel_src);
        }
    }
    Ok(())
}

fn generate_flamegraphs(process_events_vec: Vec<ProcessEvents>) -> Result<()> {
    let mut src_cache = SymbolizerCache::new();
    for process_events in process_events_vec {
        let mut file = std::fs::File::create(format!(
            "systing-describe/flamegraph-{}.svg",
            process_events.pidtgid as u32
        ))?;
        process_events.write_flamegraph(&mut src_cache, &mut file);
    }
    Ok(())
}

pub fn describe(opts: DescribeOpts) -> Result<()> {
    let mut skel_builder = systing::SystingDescribeSkelBuilder::default();
    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }

    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;

    open_skel.maps.rodata_data.tool_config.tgid = opts.pid;
    let mut skel = open_skel.load()?;
    skel.attach()?;

    let events = Arc::new(Mutex::new(HashMap::<u64, ProcessEvents>::new()));
    let events_clone = events.clone();
    let thread_done = Arc::new(AtomicBool::new(false));
    let thread_done_clone = thread_done.clone();
    let mut builder = RingBufferBuilder::new();
    builder
        .add(&skel.maps.events, move |data: &[u8]| {
            let mut event = systing::types::wake_event::default();
            plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");
            let pidtgid = event.wakee_tgidpid;
            let mut myevents = events_clone.lock().unwrap();
            match myevents.get_mut(&pidtgid) {
                Some(ref mut process_events) => {
                    process_events.add_event(event);
                }
                None => {
                    let mut process_events = ProcessEvents::new(pidtgid);
                    process_events.add_event(event);
                    myevents.insert(pidtgid, process_events);
                }
            };
            0
        })
        .expect("Failed to add ring buffer");
    let ring = builder.build().expect("Failed to build ring buffer");

    let t = thread::spawn(move || {
        loop {
            let res = ring.poll(Duration::from_millis(100));
            if res.is_err() {
                break;
            }
            if thread_done_clone.load(Ordering::Relaxed) {
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

    thread_done.store(true, Ordering::Relaxed);
    t.join().expect("Failed to join thread");

    let mut process_events_vec: Vec<ProcessEvents> = Vec::new();
    let mut graph = DiGraphMap::new();
    let mut pids: Vec<u64> = Vec::new();
    {
        let events_hash = std::mem::take(&mut *events.lock().unwrap());
        for (pidtgid, process_events) in events_hash {
            let mut edges = HashMap::<u64, u64>::new();
            for (key, value) in process_events.events.iter() {
                if edges.contains_key(&key.waker) {
                    *edges.get_mut(&key.waker).unwrap() += value.duration_us;
                } else {
                    edges.insert(key.waker, value.duration_us);
                    if !pids.contains(&key.waker) {
                        pids.push(key.waker);
                    }
                }
            }
            for edge in edges {
                graph.add_edge(edge.0, pidtgid, edge.1);
            }
            process_events_vec.push(process_events);
            if !pids.contains(&pidtgid) {
                pids.push(pidtgid);
            }
        }
    }
    process_events_vec.sort_by_key(|k| k.duration_us);

    std::fs::create_dir_all("systing-describe")?;
    print_graphviz(pids, graph)?;
    if opts.raw_output {
        print_stdout(process_events_vec)?;
    } else {
        generate_flamegraphs(process_events_vec)?;
    }

    Ok(())
}
