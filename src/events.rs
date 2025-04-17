use regex::Regex;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use anyhow::Result;
use libbpf_rs;

#[derive(Default, Debug, Clone)]
pub struct PerfHwEvent {
    pub name: String,
    pub event_type: u32,
    pub event_config: u64,
    pub disabled: bool,
    pub need_slots: bool,
    pub cpus: Vec<u32>,
}

pub struct PerfCounters {
    events: HashMap<String, Vec<PerfHwEvent>>,
}

fn visit_events(dir: &Path, events: &mut Vec<PerfHwEvent>) -> Result<()> {
    let entries = fs::read_dir(dir)?
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();

    // Some of the topdown metrics exposted by Intel Atom don't have a slots entry, so we have to
    // check and see if there's a slots file in this events directory to decide if any topdown
    // metrics require a slots fd.
    let need_slots = match entries.iter().find(|entry| {
        let filename = entry.file_name().unwrap().to_str().unwrap();
        filename == "slots"
    }) {
        Some(_) => true,
        None => false,
    };

    for path in entries {
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
            hwevent.disabled = true;
        }

        // Topdown events need slots
        if hwevent.name.starts_with("topdown") {
            hwevent.need_slots = need_slots;
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

    pub fn event(&self, name: &str) -> Option<Vec<PerfHwEvent>> {
        let result = self.events.get(name);
        if result.is_some() {
            return Some(result.unwrap().clone());
        }

        if !name.contains("*") {
            return None;
        }

        let pattern = name.replace('*', ".*");
        let re = Regex::new(pattern.as_str());
        if re.is_err() {
            return None;
        }
        let re = re.unwrap();

        let mut result = Vec::new();
        for (key, value) in &self.events {
            if re.is_match(key) {
                result.extend(value.iter().cloned());
            }
        }
        if result.len() > 0 {
            return Some(result);
        }
        None
    }
}
