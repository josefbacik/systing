use std::collections::HashMap;
use std::mem::MaybeUninit;
use std::os::unix::fs::MetadataExt;
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use plain::Plain;
use anyhow::bail;
use anyhow::Result;
use clap::Parser;
use ctrlc;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::MapCore;
use libbpf_rs::RingBufferBuilder;

mod systing {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/systing.skel.rs"
    ));
}

mod process;
use systing::*;
use process::{PreemptEvent, Process};

unsafe impl Plain for systing::types::task_stat {}
unsafe impl Plain for systing::types::preempt_event {}

#[derive(Debug, Parser)]
struct Command {
    #[arg(short, long)]
    verbose: bool,
    #[arg(short, long, default_value = "0")]
    pid: u32,
    #[arg(short, long, default_value = "")]
    cgroup: String,
    #[arg(short, long)]
    summary: bool,
    #[arg(short, long, default_value = "0")]
    duration: u64,
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

fn dump_all_results(process_vec: Vec<Process>) -> Result<()> {
    for process in process_vec.iter() {
        let total_time: u64 = process.stat.run_time
            + process.stat.preempt_time
            + process.stat.queue_time
            + process.stat.sleep_time
            + process.stat.wait_time
            + process.stat.irq_time
            + process.stat.softirq_time
            + 1;
        let total_potential_runtime = process.stat.run_time
            + process.stat.preempt_time
            + process.stat.queue_time
            + process.stat.irq_time
            + process.stat.softirq_time
            + 1;

        println!(
            "{} pid {} cgid {} runtime {}({}% total time, {}% runtime) sleeptime {}({}%) waittime {}({}%) preempttime {}({}% total time, {}% runtime) queuetime {}({}% total time, {}% runtime) irq time {}({}% total time, {}% runtime) softirq time {}({}% total time, {}% runtime)",
            process.comm(),
            process.pid,
            process.stat.cgid,
            process.stat.run_time,
            process.stat.run_time * 100 / total_time,
            process.stat.run_time * 100 / total_potential_runtime,
            process.stat.sleep_time,
            process.stat.sleep_time * 100 / total_time,
            process.stat.wait_time,
            process.stat.wait_time * 100 / total_time,
            process.stat.preempt_time,
            process.stat.preempt_time * 100 / total_time,
            process.stat.preempt_time * 100 / total_potential_runtime,
            process.stat.queue_time,
            process.stat.queue_time * 100 / total_time,
            process.stat.queue_time * 100 / total_potential_runtime,
            process.stat.irq_time,
            process.stat.irq_time * 100 / total_time,
            process.stat.irq_time * 100 / total_potential_runtime,
            process.stat.softirq_time,
            process.stat.softirq_time * 100 / total_time,
            process.stat.softirq_time * 100 / total_potential_runtime
        );

        for pevent in process.preempt_events.iter() {
            println!(
                "  Preempted by {} pid {} tgid {} cgid {} times {}",
                pevent.comm, pevent.preempt_pid, pevent.preempt_tgid, pevent.cgid, pevent.count
            );
        }
        for thread in process.threads.iter() {
            let total_time: u64 = thread.stat.run_time
                + thread.stat.preempt_time
                + thread.stat.queue_time
                + thread.stat.sleep_time
                + thread.stat.wait_time
                + thread.stat.irq_time
                + thread.stat.softirq_time
                + 1;
            let total_potential_runtime = thread.stat.run_time
                + thread.stat.preempt_time
                + thread.stat.queue_time
                + thread.stat.irq_time
                + thread.stat.softirq_time
                + 1;
            println!(
                "\t{} pid {} cgid {} runtime {}({}% total time, {}% runtime) sleeptime {}({}%) waittime {}({}%) preempttime {}({}% total time, {}% runtime) queuetime {}({}% total time, {}% runtime) irq time {}({}% total time, {}% runtime) softirq time {}({}% total time, {}% runtime)",
                thread.comm(),
                thread.pid,
                thread.stat.cgid,
                thread.stat.run_time,
                thread.stat.run_time * 100 / total_time,
                thread.stat.run_time * 100 / total_potential_runtime,
                thread.stat.sleep_time,
                thread.stat.sleep_time * 100 / total_time,
                thread.stat.wait_time,
                thread.stat.wait_time * 100 / total_time,
                thread.stat.preempt_time,
                thread.stat.preempt_time * 100 / total_time,
                thread.stat.preempt_time * 100 / total_potential_runtime,
                thread.stat.queue_time,
                thread.stat.queue_time * 100 / total_time,
                thread.stat.queue_time * 100 / total_potential_runtime,
                thread.stat.irq_time,
                thread.stat.irq_time * 100 / total_time,
                thread.stat.irq_time * 100 / total_potential_runtime,
                thread.stat.softirq_time,
                thread.stat.softirq_time * 100 / total_time,
                thread.stat.softirq_time * 100 / total_potential_runtime
            );
            for pevent in thread.preempt_events.iter() {
                println!(
                    "\t  Preempted by {} pid {} tgid {} cgid {} times {}",
                    pevent.comm, pevent.preempt_pid, pevent.preempt_tgid, pevent.cgid, pevent.count
                );
            }
        }
    }
    Ok(())
}

fn summarize_results(process_vec: Vec<Process>) -> Result<()> {
    for process in process_vec.iter() {
        let mut total_time: u64 = process.stat.run_time
            + process.stat.preempt_time
            + process.stat.queue_time
            + process.stat.sleep_time
            + process.stat.wait_time
            + process.stat.irq_time
            + process.stat.softirq_time;
        let total_threads = process.threads.len();
        let mut total_runtime = process.stat.run_time;
        let mut total_sleep = process.stat.sleep_time;
        let mut total_wait = process.stat.wait_time;
        let mut total_preempt = process.stat.preempt_time;
        let mut total_queue = process.stat.queue_time;
        let mut total_irq = process.stat.irq_time;
        let mut total_softirq = process.stat.softirq_time;
        let mut total_potential_runtime = process.stat.run_time
            + process.stat.preempt_time
            + process.stat.queue_time
            + process.stat.irq_time
            + process.stat.softirq_time;
        let mut pevents = Vec::new();

        for thread in process.threads.iter() {
            total_time += thread.stat.run_time
                + thread.stat.preempt_time
                + thread.stat.queue_time
                + thread.stat.sleep_time
                + thread.stat.wait_time
                + thread.stat.irq_time
                + thread.stat.softirq_time;
            total_runtime += thread.stat.run_time;
            total_sleep += thread.stat.sleep_time;
            total_wait += thread.stat.wait_time;
            total_preempt += thread.stat.preempt_time;
            total_queue += thread.stat.queue_time;
            total_irq += thread.stat.irq_time;
            total_softirq += thread.stat.softirq_time;
            total_potential_runtime += thread.stat.run_time
                + thread.stat.preempt_time
                + thread.stat.queue_time
                + thread.stat.irq_time
                + thread.stat.softirq_time;
            pevents.extend(&thread.preempt_events);
        }
        pevents.extend(&process.preempt_events);

        println!(
            "{} pid {} threads {} runtime {}({}% total time, {}% runtime) sleeptime {}({}%) waittime {}({}%) preempttime {}({}% total time, {}% runtime) queuetime {}({}% total time, {}% runtime) irq time {}({}% total time, {}% runtime) softirq time {}({}% total time, {}% runtime)",
            process.comm(),
            process.pid,
            total_threads,
            total_runtime,
            total_runtime * 100 / total_time,
            total_runtime * 100 / total_potential_runtime,
            total_sleep,
            total_sleep * 100 / total_time,
            total_wait,
            total_wait * 100 / total_time,
            total_preempt,
            total_preempt * 100 / total_time,
            total_preempt * 100 / total_potential_runtime,
            total_queue,
            total_queue * 100 / total_time,
            total_queue * 100 / total_potential_runtime,
            total_irq,
            total_irq * 100 / total_time,
            total_irq * 100 / total_potential_runtime,
            total_softirq,
            total_softirq * 100 / total_time,
            total_softirq * 100 / total_potential_runtime
        );
        pevents.sort_by(|a, b| b.count.cmp(&a.count));
        for pevent in pevents.iter() {
            println!(
                "\tPreempted by {} pid {} tgid {} times {}",
                pevent.comm, pevent.preempt_pid, pevent.preempt_tgid, pevent.count
            );
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let opts = Command::parse();

    let mut skel_builder = SystingSkelBuilder::default();
    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }
    bump_memlock_rlimit()?;

    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;

    open_skel.maps.rodata_data.tool_config.tgid = opts.pid;

    if opts.cgroup != "" {
        let metadata = std::fs::metadata(&opts.cgroup)?;
        open_skel.maps.rodata_data.tool_config.cgroupid = metadata.ino();
    }

    let mut skel = open_skel.load()?;

    {
        let pid = (std::process::id() as u32).to_ne_bytes();
        let val = (1 as u8).to_ne_bytes();
        skel.maps
            .ignore_pids
            .update(&pid, &val, libbpf_rs::MapFlags::ANY)?;
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

    println!("Stopping");
    *thread_done.lock().unwrap() = true;
    t.join().expect("Failed to join thread");

    let mut processes = HashMap::new();
    for rawkey in skel.maps.stats.keys() {
        let mut key: u64 = 0;
        plain::copy_from_bytes(&mut key, &rawkey).expect("Data buffer was too short");
        let pid = key as u32;
        let tgid: u32 = (key >> 32) as u32;
        let rawvalue: Vec<u8> = skel
            .maps
            .stats
            .lookup(&rawkey, libbpf_rs::MapFlags::ANY)
            .expect("Failed to get value")
            .expect("No value found");
        let mut value: systing::types::task_stat = systing::types::task_stat::default();
        plain::copy_from_bytes(&mut value, rawvalue.as_slice()).expect("Data buffer was too short");

        if pid == tgid && processes.contains_key(&pid) {
            // We found a thread before the process, so we need to update the process.
            let process: &mut Process = processes.get_mut(&pid).unwrap();
            process.stat = value;
            continue;
        } else if pid == tgid {
            // This is the tg leader, insert it and carry on.
            let process = Process::with_stat(pid, value);
            processes.insert(pid, process);
            continue;
        } else if !processes.contains_key(&tgid) {
            // We found a thread before the process, so we need to create a blank process to update
            // later.
            let process = Process::new(tgid);
            processes.insert(tgid, process);
        }
        let process = Process::with_stat(pid, value);
        let leader = processes.get_mut(&tgid).unwrap();
        leader.add_thread(process);
    }

    // Now we need to go through the preempt events and add them to the process or thread.
    for event in preempt_events.lock().unwrap().iter() {
        let pid = event.tgidpid as u32;
        let tgid: u32 = (event.tgidpid >> 32) as u32;

        if !processes.contains_key(&tgid) {
            continue;
        }

        let process = processes.get_mut(&tgid).unwrap();

        if pid == tgid {
            let mut found = false;
            for pevent in process.preempt_events.iter_mut() {
                if pevent.preempt_pid == preempt_pid {
                    pevent.count += 1;
                    found = true;
                    break;
                }
            }
            if !found {
                process.preempt_events.push(PreemptEvent::with_stat(event));
            }
        } else {
            for thread in process.threads.iter_mut() {
                if thread.pid == pid {
                    let mut found = false;
                    for pevent in thread.preempt_events.iter_mut() {
                        if pevent.preempt_pid == preempt_pid {
                            pevent.count += 1;
                            found = true;
                            break;
                        }
                    }

                    if !found {
                        thread.preempt_events.push(PreemptEvent::new(event));
                    }
                }
            }
        }
    }

    let mut process_vec: Vec<Process> = processes.into_iter().map(|(_, v)| v).collect();
    process_vec.sort_by(|a, b| {
        let mut a_total = a.stat.run_time + a.stat.preempt_time + a.stat.queue_time;
        let mut b_total = b.stat.run_time + b.stat.preempt_time + b.stat.queue_time;

        for thread in a.threads.iter() {
            a_total += thread.stat.run_time + thread.stat.preempt_time + thread.stat.queue_time;
        }

        for thread in b.threads.iter() {
            b_total += thread.stat.run_time + thread.stat.preempt_time + thread.stat.queue_time;
        }
        b_total.cmp(&a_total)
    });

    for process in process_vec.iter_mut() {
        process.threads.sort_by(|a, b| {
            let a_total = a.stat.run_time + a.stat.preempt_time + a.stat.queue_time;
            let b_total = b.stat.run_time + b.stat.preempt_time + b.stat.queue_time;
            b_total.cmp(&a_total)
        });
        process.preempt_events.sort_by(|a, b| b.count.cmp(&a.count));
        for thread in process.threads.iter_mut() {
            thread.preempt_events.sort_by(|a, b| b.count.cmp(&a.count));
        }
    }

    if opts.summary {
        summarize_results(process_vec)?;
    } else {
        dump_all_results(process_vec)?;
    }
    Ok(())
}
