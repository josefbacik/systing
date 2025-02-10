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
use anyhow::Result;
use inferno::flamegraph::Options;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::ErrorExt;
use libbpf_rs::RingBufferBuilder;
use nix::unistd::close;
use petgraph::graphmap::DiGraphMap;
use plain::Plain;

use crate::symbolize::{Stack, SymbolizerCache};

mod systing {
    include!(concat!(env!("OUT_DIR"), "/systing_describe.skel.rs"));
}

mod syscall;

unsafe impl Plain for systing::types::wake_event {}
unsafe impl Plain for systing::types::wakee_stack {}

// We set the perf frequency to 1000 Hz, which means 1ms ~= 1 sample, since all times are measured
// in ns we need to divide the duration by 1_000_000 to convert to a sample count.
const NS_TO_SAMPLES: u64 = 1_000_000;

fn pid_comm(pid: u32) -> String {
    let path = format!("/proc/{}/comm", pid);
    let comm = std::fs::read_to_string(path);
    if comm.is_err() {
        return "<unknown>".to_string();
    }
    comm.unwrap().trim().to_string()
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
    duration_ns: u64,
}

struct Event {
    key: EventKey,
    value: EventValue,
}

impl EventKey {
    pub fn new(event: systing::types::wake_event) -> Self {
        let my_event_type = match event.waker_tgidpid {
            u64::MAX => EventKeyType::SampleEvent,
            _ => EventKeyType::WakeEvent,
        };
        let waker_k_stack = Vec::from(event.waker_kernel_stack);
        let wakee_k_stack = Vec::from(event.wakee_kernel_stack);
        let waker_u_stack = Vec::from(event.waker_user_stack);
        let wakee_u_stack = Vec::from(event.wakee_user_stack);
        EventKey {
            event_type: my_event_type,
            waker: event.waker_tgidpid,
            wakee: event.wakee_tgidpid,
            waker_stack: Stack::new(&waker_k_stack, &waker_u_stack),
            wakee_stack: Stack::new(&wakee_k_stack, &wakee_u_stack),
        }
    }
}

struct ProcessEvents {
    pidtgid: u64,
    duration_ns: u64,
    events: HashMap<EventKey, EventValue>,
}

impl ProcessEvents {
    pub fn new(pidtgid: u64) -> Self {
        ProcessEvents {
            pidtgid,
            duration_ns: 0,
            events: HashMap::new(),
        }
    }

    pub fn add_event(&mut self, event: systing::types::wake_event) {
        let key = EventKey::new(event);
        self.duration_ns += event.sleep_time_ns;
        match self.events.get_mut(&key) {
            Some(ref mut value) => {
                value.count += 1;
                value.duration_ns += event.sleep_time_ns;
            }
            None => {
                self.events.insert(
                    key,
                    EventValue {
                        count: 1,
                        duration_ns: event.sleep_time_ns,
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
                    .symbolize_stack(waker_pid, &key.waker_stack)
                    .unwrap_or(Vec::new()),
            );
            lines.push(format!("{} {}", syms.join(";"), value.count));
        }
        if lines.len() > 0 {
            let mut file = std::fs::File::create(format!(
                "systing-describe/flamegraph-{}-wakers.svg",
                self.pidtgid as u32
            ))?;
            inferno::flamegraph::from_lines(
                &mut opts,
                lines.iter().map(|x| x.as_str()),
                &mut file,
            )?;
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
            let wakee_pid = key.wakee as u32;
            let syms = src_cache
                .symbolize_stack(wakee_pid, &key.wakee_stack)
                .unwrap_or(Vec::new());
            lines.push(format!("{} {}", syms.join(";"), value.duration_ns));
        }
        if lines.len() > 0 {
            let mut file = std::fs::File::create(format!(
                "systing-describe/flamegraph-{}-offcpu.svg",
                self.pidtgid as u32
            ))?;
            inferno::flamegraph::from_lines(
                &mut opts,
                lines.iter().map(|x| x.as_str()),
                &mut file,
            )?;
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
                    *count += value.duration_ns / NS_TO_SAMPLES;
                    max_sleep_samples = max_sleep_samples.max(value.duration_ns / NS_TO_SAMPLES);
                }
                EventKeyType::SampleEvent => {
                    *count += value.count;
                    max_samples = max_samples.max(value.count);
                }
            };
        }

        for (key, value) in stacks {
            let syms = src_cache.symbolize_stack(pid, &key).unwrap_or(Vec::new());
            lines.push(format!("{} {}", syms.join(";"), value));
        }
        if lines.len() > 0 {
            let mut file =
                std::fs::File::create(format!("systing-describe/flamegraph-{}-latency.svg", pid))?;
            inferno::flamegraph::from_lines(&mut opts, lines.iter().map(|x| x.as_str()), &mut file)
                .unwrap();
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
            self.value.count, self.value.duration_ns
        );
        println!("  r stack:");
        match src_cache.symbolize_stack(self.key.waker as u32, &self.key.waker_stack) {
            Ok(syms) => println!("{}", syms.join("\n")),
            Err(e) => eprintln!("Failed to symbolize waker stack: {}", e),
        };

        println!("  e stack:");
        match src_cache.symbolize_stack(self.key.wakee as u32, &self.key.wakee_stack) {
            Ok(syms) => println!("{}", syms.join("\n")),
            Err(e) => eprintln!("Failed to symbolize wakee stack: {}", e),
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
        events_vec.sort_by_key(|k| (k.value.duration_ns, k.value.count));
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
        let fd = syscall::perf_event_open(attr.as_ref(), -1, cpu as i32, -1, 0) as i32;
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
                    *edges.get_mut(&key.waker).unwrap() += value.duration_ns;
                } else {
                    edges.insert(key.waker, value.duration_ns);
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
        process_events_vec.sort_by_key(|k| k.duration_ns);
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
