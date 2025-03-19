use regex::Regex;
use std::fs;
use std::io;
use std::path::Path;

#[derive(Default, Clone)]
pub struct PerfHwEvent {
    pub name: String,
    pub event_type: u32,
    pub event_config: u64,
    pub cpus: Vec<u32>,
}

pub struct PerfCounters {
    events: Vec<PerfHwEvent>,
}

fn visit_events(dir: &Path, events: &mut Vec<PerfHwEvent>) -> io::Result<()> {
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
        events.push(hwevent);
    }
    Ok(())
}

fn visit_dirs(dir: &Path, counters: &mut PerfCounters, toplevel: bool) -> io::Result<()> {
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
        for mut event in events {
            event.event_type = event_type;
            event.cpus = cpus.clone();
            counters.events.push(event);
        }
    }
    Ok(())
}

impl PerfCounters {
    pub fn new() -> Self {
        PerfCounters { events: Vec::new() }
    }

    pub fn discover(&mut self) -> io::Result<()> {
        if self.events.len() > 0 {
            return Ok(());
        }
        let path = Path::new("/sys/bus/event_source/devices");
        visit_dirs(path, self, true)?;
        Ok(())
    }

    pub fn events(&self) -> impl Iterator<Item = &PerfHwEvent> {
        self.events.iter()
    }
}
