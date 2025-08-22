pub mod events;
pub mod perf;
mod perf_recorder;
pub mod perfetto;
pub mod pystacks;
pub mod ringbuf;
mod sched;
mod session_recorder;
mod stack_recorder;
pub mod symbolize;

use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::events::{EventKeyType, EventProbe, SystingProbeRecorder};
use crate::perf::{PerfCounters, PerfHwEvent, PerfOpenEvents};
use crate::perf_recorder::PerfCounterRecorder;
use crate::pystacks::stack_walker::StackWalkerRun;
use crate::ringbuf::RingBuffer;
use crate::sched::SchedEventRecorder;
use crate::session_recorder::{get_clock_value, SessionRecorder, SysInfoEvent};
use crate::stack_recorder::StackRecorder;

use anyhow::bail;
use anyhow::Result;
use clap::Parser;

use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{
    MapCore, RawTracepointOpts, RingBufferBuilder, TracepointOpts, UprobeOpts, UsdtOpts,
};
use perfetto_protos::trace::Trace;

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
    #[cfg(feature = "pystacks")]
    #[arg(long)]
    collect_pystacks: bool,
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
    fn use_ringbuf(&self) -> bool {
        self.ringbuf().max_duration() > 0
    }
    fn ringbuf(&self) -> &RingBuffer<T>;
    fn ringbuf_mut(&mut self) -> &mut RingBuffer<T>;
    fn maybe_trigger(&mut self, _event: &T) -> bool {
        false
    }
    fn record_event(&mut self, event: T) -> bool
    where
        T: SystingEvent,
    {
        if self.use_ringbuf() {
            let ret = self.maybe_trigger(&event);
            self.ringbuf_mut().push_front(event);
            ret
        } else {
            self.handle_event(event);
            false
        }
    }
    fn drain_ringbuf(&mut self) {
        while let Some(event) = self.ringbuf_mut().pop_back() {
            self.handle_event(event);
        }
    }
    fn handle_event(&mut self, _event: T);
}

pub trait SystingEvent {
    fn ts(&self) -> u64;
    fn next_task_info(&self) -> Option<&task_info> {
        None
    }
    fn prev_task_info(&self) -> Option<&task_info> {
        None
    }
}

use systing::types::arg_desc;
use systing::types::arg_type;
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
unsafe impl Plain for arg_desc {}

impl SystingEvent for task_event {
    fn ts(&self) -> u64 {
        self.ts
    }
    fn next_task_info(&self) -> Option<&task_info> {
        match self.r#type {
            event_type::SCHED_SWITCH
            | event_type::SCHED_WAKING
            | event_type::SCHED_WAKEUP
            | event_type::SCHED_WAKEUP_NEW => Some(&self.next),
            _ => None,
        }
    }
    fn prev_task_info(&self) -> Option<&task_info> {
        Some(&self.prev)
    }
}

impl SystingEvent for stack_event {
    fn ts(&self) -> u64 {
        self.ts
    }
    fn next_task_info(&self) -> Option<&task_info> {
        Some(&self.task)
    }
}

impl SystingEvent for perf_counter_event {
    fn ts(&self) -> u64 {
        self.ts
    }
    fn next_task_info(&self) -> Option<&task_info> {
        Some(&self.task)
    }
}

impl SystingEvent for probe_event {
    fn ts(&self) -> u64 {
        self.ts
    }
    fn next_task_info(&self) -> Option<&task_info> {
        Some(&self.task)
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
        if tx.send(event).is_err() {
            // Receiver has been dropped, we can silently ignore this
            return -1;
        }
        0
    })?;
    builder.build()
}

fn consume_loop<T, N>(
    session_recorder: &Arc<SessionRecorder>,
    recorder: &Mutex<T>,
    rx: Receiver<N>,
    stop_tx: Sender<()>,
) where
    T: SystingRecordEvent<N>,
    N: Plain + SystingEvent,
{
    loop {
        let res = rx.recv();
        if res.is_err() {
            break;
        }
        let event = res.unwrap();
        if let Some(task_info) = event.next_task_info() {
            session_recorder.maybe_record_task(task_info);
        }
        if let Some(task_info) = event.prev_task_info() {
            session_recorder.maybe_record_task(task_info);
        }
        let ret = recorder.lock().unwrap().record_event(event);
        if ret {
            stop_tx.send(()).expect("Failed to send stop signal");
            break;
        }
    }
}

fn dump_missed_events(skel: &systing::SystingSystemSkel, index: u32) -> u64 {
    let index = index.to_ne_bytes();
    let result = skel
        .maps
        .missed_events
        .lookup_percpu(&index, libbpf_rs::MapFlags::ANY);
    let mut missed = 0;
    if let Ok(Some(results)) = result {
        for cpu_data in results {
            let mut missed_events: u64 = 0;
            plain::copy_from_bytes(&mut missed_events, &cpu_data).unwrap();
            missed += missed_events;
        }
    }
    missed
}

fn is_old_kernel() -> bool {
    if let Some(kernel_version) = sysinfo::System::kernel_version() {
        let parts = kernel_version.split('.').collect::<Vec<&str>>();

        if parts.len() >= 2 {
            let major = parts[0].parse::<u64>().unwrap_or(0);
            let minor = parts[1].parse::<u64>().unwrap_or(0);

            // 6.10 is when they added bpf_get_attach_cookie() to raw_tracepoint
            !(major >= 6 && minor >= 10)
        } else {
            false
        }
    } else {
        false
    }
}

fn setup_perf_counters(
    opts: &Command,
    counters: &mut PerfCounters,
    perf_counter_names: &mut Vec<String>,
) -> Result<()> {
    if !opts.perf_counter.is_empty() {
        counters.discover()?;

        // We can do things like topdown* to get all of the topdown counters, so we have to loop
        // through all of our options and populate the actual counter names that we want
        for counter in opts.perf_counter.iter() {
            let events = counters.event(counter);
            if events.is_none() {
                return Err(anyhow::anyhow!("Invalid perf counter"));
            }
            for event in events.unwrap() {
                if !perf_counter_names.contains(&event.name) {
                    perf_counter_names.push(event.name.clone());
                }
            }
        }
    }
    Ok(())
}

fn configure_recorder(opts: &Command, recorder: &Arc<SessionRecorder>) {
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

    recorder
        .event_recorder
        .lock()
        .unwrap()
        .set_process_sched_stats(opts.process_sched_stats);
    recorder
        .event_recorder
        .lock()
        .unwrap()
        .set_cpu_sched_stats(opts.cpu_sched_stats);
}

fn system(opts: Command) -> Result<()> {
    let num_cpus = libbpf_rs::num_possible_cpus().unwrap() as u32;
    let mut perf_counter_names = Vec::new();
    let mut counters = PerfCounters::default();
    let (stop_tx, stop_rx) = channel();
    let old_kernel = is_old_kernel();

    setup_perf_counters(&opts, &mut counters, &mut perf_counter_names)?;

    let recorder = Arc::new(SessionRecorder::default());
    configure_recorder(&opts, &recorder);
    recorder.snapshot_clocks();
    {
        let mut skel_builder = systing::SystingSystemSkelBuilder::default();
        if opts.verbose {
            skel_builder.obj_builder.debug(true);
        }

        #[cfg(not(feature = "pystacks"))] // set to false when feature is off
        let collect_pystacks = false;
        #[cfg(feature = "pystacks")] // use option value if feature is on
        let collect_pystacks = opts.collect_pystacks;

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
            if collect_pystacks {
                rodata.tool_config.collect_pystacks = 1;
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

        // If we're on an older kernel we can't use the raw_tracepoint version since it doesn't
        // have the cookie support. Newer kernels will use the raw_tracepoint version so don't need
        // to load the old tracepoint program.
        if old_kernel {
            open_skel.progs.systing_raw_tracepoint.set_autoload(false);
        } else {
            open_skel.progs.systing_tracepoint.set_autoload(false);
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

        if collect_pystacks {
            Arc::<StackWalkerRun>::get_mut(&mut recorder.stack_recorder.lock().unwrap().psr)
                .expect("unable to get psr from Arc")
                .init_pystacks(&opts.pid, skel.object());
        }

        for (i, map) in object.maps().enumerate() {
            let name = map.name().to_str().unwrap();
            if name.starts_with("ringbuf_events") {
                let ring = create_ring::<task_event>(&map, event_tx.clone())?;
                rings.push((format!("events_{i}").to_string(), ring));
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
                    consume_loop::<SchedEventRecorder, task_event>(
                        &session_recorder,
                        &session_recorder.event_recorder,
                        event_rx,
                        my_stop_tx,
                    );
                    0
                })?,
        );
        let session_recorder = recorder.clone();
        let my_stop_tx = stop_tx.clone();
        recv_threads.push(
            thread::Builder::new()
                .name("stack_recorder".to_string())
                .spawn(move || {
                    consume_loop::<StackRecorder, stack_event>(
                        &session_recorder,
                        &session_recorder.stack_recorder,
                        stack_rx,
                        my_stop_tx,
                    );
                    0
                })?,
        );
        let session_recorder = recorder.clone();
        let my_stop_tx = stop_tx.clone();
        recv_threads.push(
            thread::Builder::new()
                .name("probe_recorder".to_string())
                .spawn(move || {
                    consume_loop::<SystingProbeRecorder, probe_event>(
                        &session_recorder,
                        &session_recorder.probe_recorder,
                        probe_rx,
                        my_stop_tx,
                    );
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
                        consume_loop::<PerfCounterRecorder, perf_counter_event>(
                            &session_recorder,
                            &session_recorder.perf_counter_recorder,
                            cache_rx,
                            my_stop_tx,
                        );
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
            let slot_hwevents = if let Some(slot_hwevents) = slot_hwevents {
                slot_hwevents
            } else {
                Err(anyhow::anyhow!("Failed to find slot event"))?
            };
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
                for key in event.keys.iter() {
                    let key_type = match key.key_type {
                        EventKeyType::String => arg_type::ARG_STRING,
                        EventKeyType::Long => arg_type::ARG_LONG,
                    };

                    let desc = arg_desc {
                        arg_type: key_type,
                        arg_index: key.key_index as i32,
                    };

                    // Safe because we're not padded
                    let desc_data = unsafe { plain::as_bytes(&desc) };
                    skel.maps.event_key_types.update(
                        &event.cookie.to_ne_bytes(),
                        desc_data,
                        libbpf_rs::MapFlags::ANY,
                    )?;
                }

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
                        let link = if old_kernel {
                            let category =
                                libbpf_rs::TracepointCategory::Custom(tracepoint.category.clone());
                            skel.progs.systing_tracepoint.attach_tracepoint_with_opts(
                                category,
                                &tracepoint.name,
                                TracepointOpts {
                                    cookie: event.cookie,
                                    ..Default::default()
                                },
                            )
                        } else {
                            skel.progs
                                .systing_raw_tracepoint
                                .attach_raw_tracepoint_with_opts(
                                    &tracepoint.name,
                                    RawTracepointOpts {
                                        cookie: event.cookie,
                                        ..Default::default()
                                    },
                                )
                        };
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
            ctrlc::set_handler(move || {
                stop_tx.send(()).expect("Could not send signal on channel.")
            })
            .expect("Error setting Ctrl-C handler");
            if opts.continuous > 0 {
                println!("Tracing in a continues loop of {} seconds", opts.continuous);
                println!("Will stop if a trigger is specified, otherwise Ctrl-C to stop");
            } else {
                println!("Tracing indefinitely...");
                println!("Press Ctrl-C to stop");
            }
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
