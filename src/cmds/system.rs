use std::collections::HashMap;
use std::ffi::CStr;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;

use crate::SystemOpts;
use timeline_svg::{Timeline, TimeUnit};

use anyhow::Result;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::RingBufferBuilder;
use plain::Plain;

mod systing {
    include!(concat!(env!("OUT_DIR"), "/systing_system.skel.rs"));
}

unsafe impl Plain for systing::types::task_event {}

struct CommCache {
    cache: HashMap<u32, String>,
}

impl CommCache {
    fn new() -> Self {
        CommCache {
            cache: HashMap::new(),
        }
    }

    fn get(&mut self, event: systing::types::task_event) -> String {
        let pid = event.tgidpid as u32;
        let comm = self.cache.get(&pid);
        match comm {
            Some(comm) => comm.clone(),
            None => {
                let comm_cstr = CStr::from_bytes_until_nul(&event.comm).unwrap();
                let bytes = comm_cstr.to_bytes();
                if bytes.len() == 0 || bytes.starts_with(&[0]) {
                    let comm = std::fs::read_to_string(format!("/proc/{}/comm", pid))
                        .unwrap_or_else(|_| "unknown".to_string());
                    self.cache.insert(pid, format!("{} ({})", comm.trim(), pid));
                    comm
                } else {
                    let comm = comm_cstr.to_str().unwrap().to_string();
                    self.cache.insert(pid, format!("{} ({})", comm, pid));
                    comm
                }
            }
        }
    }
}

pub fn system(opts: SystemOpts) -> Result<()> {
    let timeline = Arc::new(Mutex::new(Timeline::default()));
    let thread_done = Arc::new(AtomicBool::new(false));

    {
        let mut skel_builder = systing::SystingSystemSkelBuilder::default();
        if opts.verbose {
            skel_builder.obj_builder.debug(true);
        }

        let mut open_object = MaybeUninit::uninit();
        let open_skel = skel_builder.open(&mut open_object)?;

        open_skel.maps.rodata_data.tool_config.tgid = opts.pid;
        let mut skel = open_skel.load()?;

        let thread_done_clone = thread_done.clone();
        let timeline_clone = timeline.clone();
        let mut builder = RingBufferBuilder::new();
        let comm_cache_shared = Arc::new(Mutex::new(CommCache::new()));
        let comm_cache_clone = comm_cache_shared.clone();
        let runners_shared = Arc::new(Mutex::new(HashMap::new()));
        let runners_clone = runners_shared.clone();
        let last_ts_shared = Arc::new(Mutex::new(0u64));
        let last_ts_clone = last_ts_shared.clone();

        builder.add(&skel.maps.events, move |data: &[u8]| {
            let mut event = systing::types::task_event::default();
            plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");
            let mut my_timeline = timeline_clone.lock().unwrap();
            *last_ts_clone.lock().unwrap() = event.ts;

            let mut runners = runners_clone.lock().unwrap();
            match event.r#type {
                systing::types::event_type::EVENT_TASK_SLEEP => {
                    let mut comm_cache = comm_cache_clone.lock().unwrap();
                    match runners.remove(&event.tgidpid) {
                        Some(runner) => {
                            my_timeline.add_event(
                                comm_cache.get(runner),
                                runner.ts,
                                event.ts,
                                format!("CPU {}", runner.cpu),
                            );
                        }
                        None => {}
                    }
                }
                systing::types::event_type::EVENT_TASK_WAKEUP => {
                    my_timeline.add_trigger(
                        format!("CPU {}", event.waker_cpu),
                        format!("CPU {}", event.cpu),
                        event.extra,
                    );
                    runners.insert(event.tgidpid, event);
                }
                systing::types::event_type::EVENT_TASK_RUN => {
                    runners.insert(event.tgidpid, event);
                }
                _ => {}
            }
            0
        })?;

        let ring = builder.build()?;
        skel.attach()?;

        let t = thread::spawn(move || {
            loop {
                if thread_done_clone.load(Ordering::Relaxed) {
                    break;
                }
                let res = ring.poll(Duration::from_millis(100));
                if res.is_err() {
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

        println!("Stopping...");
        thread_done.store(true, Ordering::Relaxed);
        t.join().expect("Failed to join thread");
        println!("Stopped");

        let last_ts = *last_ts_shared.lock().unwrap();
        let runners = runners_shared.lock().unwrap();
        let mut comm_cache = comm_cache_shared.lock().unwrap();
        for (_, runner) in runners.iter() {
            let mut my_timeline = timeline.lock().unwrap();
            my_timeline.add_event(
                comm_cache.get(*runner),
                runner.ts,
                last_ts,
                format!("CPU {}", runner.cpu),
            );
        }
    }

    let mut timeline = timeline.lock().unwrap();
    timeline.set_units(TimeUnit::Nanoseconds);
    timeline.save("timeline.svg")?;
    Ok(())
}
