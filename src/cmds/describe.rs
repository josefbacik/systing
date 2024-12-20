use std::collections::HashMap;
use std::hash::Hash;
use std::io;
use std::mem;
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
use libbpf_rs::ErrorExt;
use libbpf_rs::RingBufferBuilder;
use nix::unistd::close;
use petgraph::graphmap::DiGraphMap;
use plain::Plain;

mod systing {
    include!(concat!(env!("OUT_DIR"), "/systing_describe.skel.rs"));
}

mod syscall;

unsafe impl Plain for systing::types::wake_event {}
unsafe impl Plain for systing::types::wakee_stack {}

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
    src_cache: HashMap<u32, Source<'a>>,
}

enum StackType {
    Kernel,
    User,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct Stack {
    kernel_stack: Vec<Addr>,
    user_stack: Vec<Addr>,
}

#[derive(Debug, Hash, Eq, PartialEq)]
enum EventKeyType {
    WakeEvent,
    SampleEvent,
}

#[derive(Debug, Hash, Eq, PartialEq)]
struct EventKey {
    event_type: EventKeyType,
    waker: u64,
    wakee: u64,
    waker_stack: Stack,
    wakee_stack: Stack,
}

struct EventValue {
    count: u64,
    duration_us: u64,
}

struct Event {
    key: EventKey,
    value: EventValue,
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
}

impl EventKey {
    pub fn new(event: systing::types::wake_event) -> Self {
        // The waker can be the kernel, to avoid the overhead of memsetting the whole stack we use
        // a magic number for the first element so we can just zero out the stack.
        let waker_stack = match event.waker_user_stack[0] {
            1234 => vec![],
            _ => event
                .waker_user_stack
                .into_iter()
                .rev()
                .filter(|x| *x > 0)
                .collect(),
        };
        let my_event_type = match event.waker_tgidpid {
            u64::MAX => EventKeyType::SampleEvent,
            _ => EventKeyType::WakeEvent,
        };
        EventKey {
            event_type: my_event_type,
            waker: event.waker_tgidpid,
            wakee: event.wakee_tgidpid,
            waker_stack: Stack::new(
                event
                    .waker_kernel_stack
                    .into_iter()
                    .rev()
                    .filter(|x| *x > 0)
                    .collect(),
                waker_stack,
            ),
            wakee_stack: Stack::new(
                event
                    .wakee_kernel_stack
                    .into_iter()
                    .rev()
                    .filter(|x| *x > 0)
                    .collect(),
                event
                    .wakee_user_stack
                    .into_iter()
                    .rev()
                    .filter(|x| *x > 0)
                    .collect(),
            ),
        }
    }
}

struct ProcessEvents {
    pidtgid: u64,
    duration_us: u64,
    events: HashMap<EventKey, EventValue>,
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
        let key = EventKey::new(event);
        self.duration_us += event.sleep_time_us;
        match self.events.get_mut(&key) {
            Some(ref mut value) => {
                value.count += 1;
                value.duration_us += event.sleep_time_us;
            }
            None => {
                self.events.insert(
                    key,
                    EventValue {
                        count: 1,
                        duration_us: event.sleep_time_us,
                    },
                );
            }
        };
    }

    pub fn write_wakers_flamegraph(&self, src_cache: &mut SymbolizerCache) -> Result<()> {
        let mut opts = Options::default();
        opts.min_width = 0.1;
        opts.title = format!(
            "Process: tgid {} pid {} comm {} Off-CPU Flamegraph",
            self.pidtgid >> 32,
            self.pidtgid as u32,
            pid_comm(self.pidtgid as u32)
        );

        let mut lines = Vec::new();
        for (key, value) in self
            .events
            .iter()
            .filter(|(key, _)| key.event_type == EventKeyType::WakeEvent)
        {
            let mut syms = Vec::new();
            let waker_pid = key.waker as u32;

            syms.push(format!("{}_{}", pid_comm(waker_pid), waker_pid).to_string());
            syms.extend(
                src_cache
                    .symbolize_stack(waker_pid, &key.waker_stack, StackType::User)
                    .unwrap_or(Vec::new()),
            );
            syms.extend(
                src_cache
                    .symbolize_stack(waker_pid, &key.waker_stack, StackType::Kernel)
                    .unwrap_or(Vec::new()),
            );
            lines.push(format!("{} {}", syms.join(";"), value.count));
        }
        if lines.len() > 0 {
            let mut file = std::fs::File::create(format!(
                "systing-describe/flamegraph-{}-wakers.svg",
                self.pidtgid as u32
            ))?;
            inferno::flamegraph::from_lines(&mut opts, lines.iter().map(|x| x.as_str()), &mut file)?;
        }
        Ok(())
    }

    pub fn write_offcpu_flamegraph(&self, src_cache: &mut SymbolizerCache) -> Result<()> {
        let mut opts = Options::default();
        opts.min_width = 0.1;
        opts.title = format!(
            "Process: tgid {} pid {} comm {} Off-CPU Flamegraph",
            self.pidtgid >> 32,
            self.pidtgid as u32,
            pid_comm(self.pidtgid as u32)
        );

        let mut lines = Vec::new();
        for (key, value) in self
            .events
            .iter()
            .filter(|(key, _)| key.event_type == EventKeyType::WakeEvent)
        {
            let mut syms = Vec::new();
            let wakee_pid = key.wakee as u32;

            syms.extend(
                src_cache
                    .symbolize_stack(wakee_pid, &key.wakee_stack, StackType::User)
                    .unwrap_or(Vec::new()),
            );
            syms.extend(
                src_cache
                    .symbolize_stack(wakee_pid, &key.wakee_stack, StackType::Kernel)
                    .unwrap_or(Vec::new()),
            );
            lines.push(format!("{} {}", syms.join(";"), value.duration_us));
        }
        if lines.len() > 0 {
            let mut file = std::fs::File::create(format!(
                "systing-describe/flamegraph-{}-offcpu.svg",
                self.pidtgid as u32
            ))?;
            inferno::flamegraph::from_lines(&mut opts, lines.iter().map(|x| x.as_str()), &mut file)?;
        }
        Ok(())
    }

    fn write_latency_flamegraph(&self, src_cache: &mut SymbolizerCache) -> Result<()> {
        let mut opts = Options::default();
        let pid = self.pidtgid as u32;
        opts.min_width = 0.1;
        opts.title = format!(
            "Process: tgid {} pid {} comm {} Off-CPU Flamegraph",
            self.pidtgid >> 32,
            pid,
            pid_comm(pid as u32)
        );

        let mut lines = Vec::new();
        let mut max_samples = 0;
        let mut max_sleep_samples = 0;
        let mut stacks = HashMap::<Stack, u64>::new();
        for (key, value) in self.events.iter() {
            let count = stacks.entry(key.wakee_stack.clone()).or_insert(0);
            match key.event_type {
                EventKeyType::WakeEvent => {
                    *count += value.duration_us / 1000;
                    max_sleep_samples = max_sleep_samples.max(value.duration_us / 1000);
                }
                EventKeyType::SampleEvent => {
                    *count += value.count;
                    max_samples = max_samples.max(value.count);
                }
            };
        }
        for (key, value) in stacks {
            let mut syms = Vec::new();

            syms.extend(
                src_cache
                    .symbolize_stack(pid, &key, StackType::User)
                    .unwrap_or(Vec::new()),
            );
            syms.extend(
                src_cache
                    .symbolize_stack(pid, &key, StackType::Kernel)
                    .unwrap_or(Vec::new()),
            );
            lines.push(format!("{} {}", syms.join(";"), value));
        }
        println!(
            "{}: max_samples: {}, max_sleep_samples: {}",
            self.pidtgid as u32, max_samples, max_sleep_samples
        );
        if lines.len() > 0 {
            let mut file = std::fs::File::create(format!(
                "systing-describe/flamegraph-{}-latency.svg",
                pid
            ))?;
            inferno::flamegraph::from_lines(&mut opts, lines.iter().map(|x| x.as_str()), &mut file).unwrap();
        }
        Ok(())
    }
}

impl Event {
    pub fn print(&self, src_cache: &mut SymbolizerCache) {
        println!(
            "  r: tgid {} pid {} comm {}",
            self.key.waker >> 32,
            self.key.waker as u32,
            pid_comm(self.key.waker as u32)
        );
        println!(
            "  Count: {}, Duration: {}",
            self.value.count, self.value.duration_us
        );
        println!("  r kernel stack:");
        match src_cache.symbolize_stack(
            self.key.waker as u32,
            &self.key.waker_stack,
            StackType::Kernel,
        ) {
            Ok(syms) => println!("{}", syms.join("\n")),
            Err(e) => eprintln!("Failed to symbolize waker kernel stack: {}", e),
        };

        match src_cache.symbolize_stack(
            self.key.waker as u32,
            &self.key.waker_stack,
            StackType::User,
        ) {
            Ok(syms) => {
                if !syms.is_empty() {
                    println!("  r user stack:");
                    println!("{}", syms.join("\n"));
                }
            }
            Err(e) => eprintln!("Failed to symbolize waker user stack: {}", e),
        };

        println!("  e kernel stack:");
        match src_cache.symbolize_stack(
            self.key.wakee as u32,
            &self.key.wakee_stack,
            StackType::Kernel,
        ) {
            Ok(syms) => println!("{}", syms.join("\n")),
            Err(e) => eprintln!("Failed to symbolize wakee kernel stack: {}", e),
        };

        match src_cache.symbolize_stack(
            self.key.wakee as u32,
            &self.key.wakee_stack,
            StackType::User,
        ) {
            Ok(syms) => {
                if !syms.is_empty() {
                    println!("  e user stack:");
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
    let mut src_cache = SymbolizerCache::new();

    for process_events in process_events_vec {
        let mut events_vec: Vec<Event> = process_events
            .events
            .into_iter()
            .map(|(key, value)| Event { key, value })
            .collect();
        events_vec.sort_by_key(|k| (k.value.duration_us, k.value.count));
        let mut first = true;
        for event in events_vec {
            if first {
                let wakee_pid = event.key.wakee as u32;
                println!(
                    "Process: tgid {} pid {} comm {}",
                    (event.key.wakee >> 32) as u32,
                    wakee_pid,
                    pid_comm(wakee_pid)
                );
                first = false;
            }

            event.print(&mut src_cache);
        }
    }
    Ok(())
}

fn init_perf_monitor(freq: u64, sw_event: bool) -> Result<Vec<i32>, libbpf_rs::Error> {
    let nprocs = libbpf_rs::num_possible_cpus().unwrap();
    let pid = -1;
    let buf: Vec<u8> = vec![0; mem::size_of::<syscall::perf_event_attr>()];
    let mut attr = unsafe {
        Box::<syscall::perf_event_attr>::from_raw(
            buf.leak().as_mut_ptr() as *mut syscall::perf_event_attr
        )
    };
    attr._type = if sw_event {
        syscall::PERF_TYPE_SOFTWARE
    } else {
        syscall::PERF_TYPE_HARDWARE
    };
    attr.size = mem::size_of::<syscall::perf_event_attr>() as u32;
    attr.config = if sw_event {
        syscall::PERF_COUNT_SW_CPU_CLOCK
    } else {
        syscall::PERF_COUNT_HW_CPU_CYCLES
    };
    attr.sample.sample_freq = freq;
    attr.flags = 1 << 10; // freq = 1i
    let mut pidfds = Vec::new();
    for cpu in 0..nprocs {
        let fd = syscall::perf_event_open(attr.as_ref(), pid, cpu as i32, -1, 0) as i32;
        if fd == -1 {
            let os_error = io::Error::last_os_error();
            let mut error_context = "Failed to open perf event.";

            if let Some(libc::ENODEV) = os_error.raw_os_error() {
                // Sometimes available cpus < num_cpus, so we just break here.
                break;
            }

            if !sw_event && os_error.kind() == io::ErrorKind::NotFound {
                error_context = "Failed to open perf event.\n\
                                Try running the profile example with the `--sw-event` option.";
            }
            return Err(libbpf_rs::Error::from(os_error)).context(error_context);
        }
        pidfds.push(fd);
    }
    Ok(pidfds)
}

fn attach_perf_event(
    pefds: &[i32],
    prog: &libbpf_rs::ProgramMut,
) -> Vec<Result<libbpf_rs::Link, libbpf_rs::Error>> {
    pefds
        .iter()
        .map(|pefd| prog.attach_perf_event(*pefd))
        .collect()
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

    let pefds = init_perf_monitor(1000, opts.sw_event)?;
    let _links = attach_perf_event(&pefds, &skel.progs.sample_process);
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
            for (key, value) in process_events
                .events
                .iter()
                .filter(|(key, _)| key.event_type == EventKeyType::WakeEvent)
            {
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

    std::fs::create_dir_all("systing-describe")?;
    print_graphviz(pids, graph)?;
    if opts.raw_output {
        process_events_vec.sort_by_key(|k| k.duration_us);
        print_stdout(process_events_vec)?;
    } else {
        let mut src_cache = SymbolizerCache::new();
        for process_events in process_events_vec {
            process_events.write_offcpu_flamegraph(&mut src_cache)?;
            process_events.write_wakers_flamegraph(&mut src_cache)?;
            process_events.write_latency_flamegraph(&mut src_cache)?;
        }
    }

    for pefd in pefds {
        close(pefd)
            .map_err(io::Error::from)
            .map_err(libbpf_rs::Error::from)
            .context("failed to close perf event")?;
    }
    Ok(())
}
