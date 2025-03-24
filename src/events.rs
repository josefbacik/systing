use regex::Regex;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use anyhow::Result;
use libbpf_rs;
use nix::ioctl_none;

#[derive(Default, Clone)]
pub struct PerfHwEvent {
    pub name: String,
    pub event_type: u32,
    pub event_config: u64,
    pub flags: u64,
    pub cpus: Vec<u32>,
}

pub struct PerfCounters {
    pub events: HashMap<String, Vec<PerfHwEvent>>,
}

const PERF_EVENT_MAGIC: u8 = b'$';
const PERF_EVENT_IOC_ENABLE: u8 = 0;
ioctl_none!(
    perf_event_ioc_enable,
    PERF_EVENT_MAGIC,
    PERF_EVENT_IOC_ENABLE
);

fn visit_events(dir: &Path, events: &mut Vec<PerfHwEvent>) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let buf = fs::read_to_string(&path)?;
        let event_re = Regex::new(r"event=0x([0-9a-fA-F]+)").unwrap();
        let umask_re = Regex::new(r"umask=0x([0-9a-fA-F]+)").unwrap();
        let event = event_re.captures(&buf);
        let umask = umask_re.captures(&buf);
        let mut hwevent = PerfHwEvent::default();

        hwevent.name = path.file_name().unwrap().to_str().unwrap().to_string();

        if event.is_some() {
            let event = event.unwrap();
            let event = u64::from_str_radix(&event[1], 16).unwrap();
            hwevent.event_config = event;
        }
        if umask.is_some() {
            let umask = umask.unwrap();
            let umask = u64::from_str_radix(&umask[1], 16).unwrap();
            hwevent.event_config |= umask << 8;
        }

        // Slots events should be disabled
        if hwevent.name == "slots" {
            hwevent.flags = 1 << 0; // disabled
        }
        events.push(hwevent);
    }
    Ok(())
}

fn visit_dirs(dir: &Path, counters: &mut PerfCounters, toplevel: bool) -> Result<()> {
    if dir.is_dir() {
        let mut event_type: u32 = 0;
        let mut cpus: Vec<u32> = Vec::new();
        let mut events: Vec<PerfHwEvent> = Vec::new();
        let cpus_re = Regex::new(r"(\d+)-(\d+)").unwrap();

        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let filename = path.file_name().unwrap().to_str().unwrap();
            if path.is_dir() {
                if toplevel && filename.starts_with("cpu") {
                    visit_dirs(&path, counters, false)?;
                } else if filename == "events" {
                    visit_events(&path, &mut events)?;
                }
            } else {
                match filename {
                    "type" => {
                        let buf = fs::read_to_string(&path)?;
                        event_type = buf.trim().parse().unwrap();
                    }
                    "cpus" => {
                        let buf = fs::read_to_string(&path)?;
                        for cap in cpus_re.captures_iter(&buf) {
                            let start = cap[1].parse().unwrap();
                            let end = cap[2].parse().unwrap();
                            for cpu in start..=end {
                                cpus.push(cpu);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        if cpus.len() == 0 {
            let num_cpus = libbpf_rs::num_possible_cpus()?;
            cpus = (0..num_cpus as u32).collect();
        }
        for mut event in events {
            event.event_type = event_type;
            event.cpus = cpus.clone();
            let entry = counters
                .events
                .entry(event.name.clone())
                .or_insert(Vec::new());
            entry.push(event);
        }
    }
    Ok(())
}

impl PerfCounters {
    pub fn new() -> Self {
        PerfCounters {
            events: HashMap::new(),
        }
    }

    pub fn discover(&mut self) -> Result<()> {
        if self.events.len() > 0 {
            return Ok(());
        }
        let path = Path::new("/sys/bus/event_source/devices");
        visit_dirs(path, self, true)?;
        Ok(())
    }
}
