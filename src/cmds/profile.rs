use std::collections::HashMap;
use std::mem::MaybeUninit;
use std::os::unix::fs::MetadataExt;
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::Result;
use chrono::{DateTime, Local};
use ctrlc;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::MapCore;
use libbpf_rs::RingBufferBuilder;
use libbpf_rs::MapFlags;
use plain::Plain;

mod systing {
    include!(concat!(
        env!("OUT_DIR"),
        "/systing_profile.skel.rs"
    ));
}

pub mod process;
pub mod tree_view;

use systing::*;
use process::Process;
use crate::ProfileSchedOpts;

unsafe impl Plain for systing::types::task_stat {}
unsafe impl Plain for systing::types::preempt_event {}

// Maximum number of nanoseconds in a day.
const MAXNSECS: u64 = 86_400_000_000_000;

fn sanitize_stat(stat: &mut systing::types::task_stat) -> Result<()> {
    if stat.run_time > MAXNSECS {
        stat.run_time = 0;
    }
    if stat.preempt_time > MAXNSECS {
        stat.preempt_time = 0;
    }
    if stat.queue_time > MAXNSECS {
        stat.wait_time = 0;
    }
    if stat.sleep_time > MAXNSECS {
        stat.sleep_time = 0;
    }
    if stat.irq_time > MAXNSECS {
        stat.irq_time = 0;
    }
    if stat.softirq_time > MAXNSECS {
        stat.softirq_time = 0;
    }
    if stat.wait_time > MAXNSECS {
        stat.wait_time = 0;
    }
    if stat.waking_time > MAXNSECS {
        stat.waking_time = 0;
    }
    stat.run_time = stat.run_time / 1000;
    stat.preempt_time = stat.preempt_time / 1000;
    stat.queue_time = stat.queue_time / 1000;
    stat.sleep_time = stat.sleep_time / 1000;
    stat.irq_time = stat.irq_time / 1000;
    stat.softirq_time = stat.softirq_time / 1000;
    stat.wait_time = stat.wait_time / 1000;
    stat.waking_time = stat.waking_time / 1000;
    Ok(())
}

fn collect_results(
    skel: &SystingProfileSkel,
    start: DateTime<Local>,
    processes: &mut HashMap<u32, Process>,
    preempt_events: Vec<systing::types::preempt_event>,
) -> Result<()> {
    let results = skel.maps.stats.lookup_and_delete_batch(1024, MapFlags::ANY, MapFlags::ANY)?;
    for (rawkey, rawvalue) in results {
        let mut key: u64 = 0;
        plain::copy_from_bytes(&mut key, &rawkey).expect("Data buffer was too short");
        let pid = key as u32;
        let tgid: u32 = (key >> 32) as u32;
        let mut value: systing::types::task_stat = systing::types::task_stat::default();
        plain::copy_from_bytes(&mut value, rawvalue.as_slice()).expect("Data buffer was too short");
        sanitize_stat(&mut value)?;

        let process = match processes.get_mut(&tgid) {
            Some(process) => {
                if tgid != pid {
                    let thread = Process::new(pid);
                    process.add_thread(thread);
                }
                process
            }
            None => {
                let mut process = Process::new(tgid);
                if tgid != pid {
                    let thread = Process::new(pid);
                    process.add_thread(thread);
                }
                processes.insert(tgid, process);
                processes.get_mut(&tgid).unwrap()
            }
        };

        process.add_run(pid, start, &value);
        process.update_comm(pid, value);
    }

    // Now we need to go through the preempt events and add them to the process or thread.
    for event in preempt_events.iter() {
        let tgid: u32 = (event.tgidpid >> 32) as u32;
        match processes.get_mut(&tgid) {
            Some(process) => {
                process.add_preempt_event(event);
            }
            None => {}
        }
    }
    Ok(())
}

pub fn profile_sched(opts: ProfileSchedOpts) -> Result<()> {
    let mut skel_builder = SystingProfileSkelBuilder::default();
    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }

    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;

    open_skel.maps.rodata_data.tool_config.tgid = opts.pid;
    if opts.aggregate {
        open_skel.maps.rodata_data.tool_config.aggregate = 1;
    }

    if opts.cgroup.len() > 0 {
        open_skel.maps.rodata_data.tool_config.filter_cgroup = 1;
    }

    let mut skel = open_skel.load()?;

    {
        let pid = (std::process::id() as u32).to_ne_bytes();
        let val = (1 as u8).to_ne_bytes();
        skel.maps
            .ignore_pids
            .update(&pid, &val, libbpf_rs::MapFlags::ANY)?;
    }

    for cgroup in opts.cgroup.iter() {
        let metadata = std::fs::metadata(cgroup)?;
        let cgroupid = metadata.ino().to_ne_bytes();
        let val = (1 as u8).to_ne_bytes();
        skel.maps
            .cgroups
            .update(&cgroupid, &val, libbpf_rs::MapFlags::ANY)?;
    }

    skel.attach()?;

    // Start the ring buffer, start a thread to poll for the events and add them to the
    // preempt_events vector.
    let preempt_events = Arc::new(Mutex::new(Vec::new()));
    let preempt_clone = Arc::clone(&preempt_events);
    let thread_done = Arc::new(Mutex::new(false));
    let thread_done_clone = Arc::clone(&thread_done);
    let mut builder = RingBufferBuilder::new();
    builder
        .add(&skel.maps.events, move |data: &[u8]| {
            let mut event = systing::types::preempt_event::default();
            plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");
            preempt_clone.lock().unwrap().push(event);
            0
        })
        .expect("Failed to add ring buffer");
    let ring = builder.build().expect("Failed to build ring buffer");

    let t = thread::spawn(move || -> i32 {
        loop {
            let res = ring.poll(Duration::from_millis(100));
            if res.is_err() {
                break;
            }
            if *thread_done_clone.lock().unwrap() {
                break;
            }
        }
        0
    });

    let mut processes: HashMap<u32, Process> = HashMap::new();
    for _ in 0..opts.loops {
        let start = Local::now();
        // Wait for the duration to expire or for a Ctrl-C signal.
        if opts.duration > 0 {
            thread::sleep(Duration::from_secs(opts.duration));
        } else {
            let (tx, rx) = channel();
            ctrlc::set_handler(move || tx.send(()).expect("Could not send signal on channel."))
                .expect("Error setting Ctrl-C handler");
            println!("Press Ctrl-C to stop");
            rx.recv().expect("Could not receive signal on channel.");
        }
        let pevents_vec = std::mem::take(&mut *preempt_events.lock().unwrap());
        collect_results(&skel, start, &mut processes, pevents_vec)?;
    }

    *thread_done.lock().unwrap() = true;
    t.join().expect("Failed to join thread");

    let mut process_vec: Vec<Process> = processes.into_iter().map(|(_, v)| v).collect();
    process_vec.sort_by(|a, b| {
        let a_total = a.total_potential_runtime();
        let b_total = b.total_potential_runtime();
        b_total.cmp(&a_total)
    });

    for process in process_vec.iter_mut() {
        // In case we didn't get any data for a process, we need to update the comm.
        process.update_comm(process.pid, systing::types::task_stat::default());
        process.sort_runs();
        process.sort_preempt_events();
    }

    if opts.tui {
        tree_view::launch_tui(process_vec);
    } else {
        for process in process_vec {
            if opts.summary {
                process.print_summary();
            } else {
                process.print(false);
            }
        }
    }
    Ok(())
}
