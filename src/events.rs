use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::Path;

use anyhow::Result;
use serde::Deserialize;
use serde_json;

#[derive(Clone, Default)]
pub struct UsdtProbeEvent {
    pub path: String,
    pub provider: String,
    pub name: String,
}

#[derive(Clone, Default)]
pub struct UProbeEvent {
    pub path: String,
    pub offset: u64,
    pub func_name: String,
    pub retprobe: bool,
}

#[derive(Clone, Default)]
pub enum EventProbe {
    UProbe(UProbeEvent),
    Usdt(UsdtProbeEvent),
    #[default]
    Undefined,
}

#[derive(Clone, Default)]
pub enum EventKeyType {
    String,
    #[default]
    Long,
}

#[derive(Clone, Default)]
pub struct SystingEvent {
    pub name: String,
    pub cookie: u64,
    pub event: EventProbe,
    pub key_index: u8,
    pub key_type: EventKeyType,
}

#[derive(Default)]
pub struct SystingEventsConfig {
    pub events: HashMap<String, SystingEvent>,

    // Map the events to the range/instant names
    pub start_events: HashMap<String, String>,
    pub stop_events: HashMap<String, String>,
    pub instant_events: HashMap<String, String>,
}

#[derive(Deserialize, Debug)]
struct SystingJSONTrackConfig {
    events: Vec<SystingJSONEvent>,
    tracks: Vec<SystingTrack>,
}

#[derive(Deserialize, Debug)]
struct SystingJSONEvent {
    name: String,
    event: String,
    key_index: Option<u8>,
    key_type: Option<String>,
}

#[derive(Deserialize, Debug)]
struct SystingTrack {
    track_name: String,
    ranges: Option<Vec<SystingRange>>,
    instant: Option<SystingInstant>,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct SystingRange {
    name: String,
    start: String,
    end: String,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct SystingInstant {
    name: String,
    event: String,
}

impl UProbeEvent {
    fn from_parts(parts: Vec<&str>) -> Result<Self, anyhow::Error> {
        // Format is
        // uprobe:<path>:<offset>
        // uprobe:<path>:<symbol>
        // uprobe:<path>:<symbol>+<offset>
        // uretprobe:<path>:<offset>
        // uretprobe:<path>:<symbol>
        // uretprobe:<path>:<symbol>+<offset>
        if parts.len() != 3 {
            return Err(anyhow::anyhow!(
                "Invalid uprobe format: {}",
                parts.join(":")
            ));
        }
        let mut probe = UProbeEvent::default();
        probe.path = parts[1].to_string();
        probe.retprobe = parts[0] == "uretprobe";

        match parts[2].parse::<u64>() {
            Ok(val) => {
                probe.offset = val;
            }
            Err(_) => {
                let symbol = parts[2].to_string();
                let mut symbol_parts = symbol.split('+');
                let symbol = symbol_parts.next().unwrap();
                let offset = symbol_parts.next();
                if offset.is_some() {
                    probe.offset = offset.unwrap().parse::<u64>()?;
                } else {
                    probe.offset = 0;
                }
                probe.func_name = symbol.to_string();
            }
        }
        Ok(probe)
    }
}

impl fmt::Display for UProbeEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = if self.retprobe { "uretprobe" } else { "uprobe" };
        if self.func_name != "" {
            if self.offset != 0 {
                write!(f, "{}:{}+0x{:x}", name, self.func_name, self.offset,)
            } else {
                write!(f, "{}:{}", name, self.func_name)
            }
        } else {
            if self.offset != 0 {
                write!(f, "{}:0x{:x}", name, self.offset)
            } else {
                write!(f, "{}", name)
            }
        }
    }
}

impl fmt::Display for UsdtProbeEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "usdt:{}:{}:{}", self.path, self.provider, self.name)
    }
}

impl UsdtProbeEvent {
    fn from_parts(parts: Vec<&str>) -> Result<Self, anyhow::Error> {
        // Format is
        // usdt:<path>:<provider>:<name>
        if parts.len() != 4 {
            Err(anyhow::anyhow!("Invalid USDT probe format"))?;
        }
        let usdt = UsdtProbeEvent {
            path: parts[1].to_string(),
            provider: parts[2].to_string(),
            name: parts[3].to_string(),
        };
        Ok(usdt)
    }
}

impl fmt::Display for SystingEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.event {
            EventProbe::UProbe(uprobe) => write!(f, "{}", uprobe),
            EventProbe::Usdt(usdt) => write!(f, "{}", usdt),
            _ => write!(f, "Invalid event"),
        }
    }
}

impl SystingEventsConfig {
    pub fn add_event_from_str(&mut self, event: &str, rng: &mut dyn rand::RngCore) -> Result<()> {
        let parts = event.split(':').collect::<Vec<&str>>();
        let mut systing_event = SystingEvent::default();
        systing_event.key_index = u8::MAX;
        systing_event.cookie = rng.next_u64();
        match parts[0] {
            "usdt" => {
                let usdt = UsdtProbeEvent::from_parts(parts)?;
                systing_event.name = format!("{}:{}", usdt.provider, usdt.name);
                systing_event.event = EventProbe::Usdt(usdt);
            }
            "uprobe" => {
                let uprobe = UProbeEvent::from_parts(parts)?;
                systing_event.name = uprobe.func_name.clone();
                systing_event.event = EventProbe::UProbe(uprobe);
            }
            _ => {
                return Err(anyhow::anyhow!("Invalid event type: {}", parts[0]));
            }
        }
        self.events
            .insert(systing_event.name.clone(), systing_event);
        Ok(())
    }

    fn add_event_from_json(
        &mut self,
        event: &SystingJSONEvent,
        rng: &mut dyn rand::RngCore,
    ) -> Result<()> {
        let key_type = match event.key_type.as_deref() {
            Some("string") => EventKeyType::String,
            Some("long") => EventKeyType::Long,
            _ => EventKeyType::default(),
        };
        let key_index = event.key_index.unwrap_or(u8::MAX);
        let parts = event.event.split(':').collect::<Vec<&str>>();
        let event = SystingEvent {
            name: event.name.clone(),
            cookie: rng.next_u64(),
            key_index,
            key_type,
            event: match parts[0] {
                "usdt" => EventProbe::Usdt(UsdtProbeEvent::from_parts(parts)?),
                "uprobe" => EventProbe::UProbe(UProbeEvent::from_parts(parts)?),
                _ => return Err(anyhow::anyhow!("Invalid event type")),
            },
        };
        self.events.insert(event.name.clone(), event);
        Ok(())
    }

    pub fn load_config(&mut self, config: &str, rng: &mut dyn rand::RngCore) -> Result<()> {
        let path = Path::new(config);
        let buf = fs::read_to_string(path)?;

        let config: SystingJSONTrackConfig = serde_json::from_str(&buf)?;
        for event in config.events.iter() {
            self.add_event_from_json(&event, rng)?;
        }

        for track in config.tracks {
            let track_name = track.track_name.clone();
            if let Some(ranges) = &track.ranges {
                for range in ranges.iter() {
                    let start_event = range.start.clone();
                    let end_event = range.end.clone();
                    if self.start_events.contains_key(&start_event) {
                        Err(anyhow::anyhow!(
                            "Start event {} already exists",
                            start_event
                        ))?;
                    }
                    if self.stop_events.contains_key(&end_event) {
                        Err(anyhow::anyhow!(
                            "Stop event {} already exists",
                            end_event
                        ))?;
                    }
                    self.start_events.insert(start_event, track_name.clone());
                    self.stop_events.insert(end_event, track_name.clone());
                }
            }
            if let Some(instant) = &track.instant {
                self.instant_events.insert(instant.name.clone(), track_name.clone());
            }
        }
        Ok(())
    }
}
