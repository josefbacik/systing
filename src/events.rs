use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::Result;
use serde::Deserialize;
use serde_json;

use perfetto_protos::trace_packet::TracePacket;
use perfetto_protos::track_event::track_event::Type;
use perfetto_protos::track_event::TrackEvent;

struct TrackInstant {
    ts: u64,
    name: String,
}

struct TrackRange {
    range_name: String,
    start: u64,
    end: u64,
}

// This is the main recorder struct, we keep track of the configuration for the events, as well as
// the events we've seen so far.
#[derive(Default)]
pub struct SystingProbeRecorder {
    // The events tied to the cookie, so we know what event we're dealing with when we get a cookie
    // from bpf.
    pub cookies: HashMap<u64, SystingEvent>,

    // The instant events that we've recorded so far, the key is the tgidpid of the thread, and the
    // value is another hashmap with the track name as the key and the list of TrackInstant's that
    // we've recorded.
    events: HashMap<u64, HashMap<String, Vec<TrackInstant>>>,

    // The recorded ranges, this is a hashmap of the tgidpid of the thread, and then a hashmap of
    // the track name to track name, and then there's a list of TrackRange entries in there.  We
    // keep track of the range name in here because perfetto expects that it sees all the packets
    // for a track in chronological order, which means if we have something like
    //
    // range1 -> event1:event2
    // range2 -> event2:event3
    //
    // We need to make sure the packets show up with
    //
    // [packet BEGIN range1][packet END range1][packet BEGIN range2][packet END range2]
    recorded_ranges: HashMap<u64, HashMap<String, Vec<TrackRange>>>,

    // The ranges that we've recorded a start event for, the key is the tgidpid of the thread, and
    // the value is a hashmap of the track_name with a TrackRange that has the start time set.
    outstanding_ranges: HashMap<u64, HashMap<String, TrackRange>>,

    // The configured events that we've loaded from a config file or from --trace-event.
    pub config_events: HashMap<String, SystingEvent>,

    // The mapping of start event name -> range name
    start_events: HashMap<String, String>,

    // The mapping of stop event name -> range name
    stop_events: HashMap<String, String>,

    // The mapping of instant event name -> track name
    instant_events: HashMap<String, String>,

    // The mapping of the range name -> track name.
    ranges: HashMap<String, String>,
}

// usdt:<path>:<provider>:<name>
#[derive(Clone, Default)]
pub struct UsdtProbeEvent {
    pub path: String,
    pub provider: String,
    pub name: String,
}

// Format is
// uprobe:<path>:<offset>
// uprobe:<path>:<symbol>
// uprobe:<path>:<symbol>+<offset>
// uretprobe:<path>:<offset>
// uretprobe:<path>:<symbol>
// uretprobe:<path>:<symbol>+<offset>
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

// Any configured event is turned into this object
#[derive(Clone, Default)]
pub struct SystingEvent {
    pub name: String,
    pub cookie: u64,
    pub event: EventProbe,
    pub key_index: u8,
    pub key_type: EventKeyType,
}

// The JSON config file format is
// {
//   "events": [
//     {
//       "name": "event_name",
//       "event": "<PROBE TYPE SPECIFIC FORMAT>",
//       "key_index": 0,
//       "key_type": "string"
//     }
//   ],
//   "tracks": [
//     {
//       "name": "track_name",
//       "ranges": [
//         {
//           "name": "range_name",
//           "start": "event_name",
//           "end": "event_name"
//         }
//       ],
//       "instant": {
//         "name": "event_name"
//       }
//     }
//   ]
// }
//
// The event names cannot be duplicated in the tracks, with the sole exception of ranges, where you
// can have the same start and end event name, but they must be different from the instant event.
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
struct SystingRange {
    name: String,
    start: String,
    end: String,
}

#[derive(Deserialize, Debug)]
struct SystingInstant {
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

impl SystingProbeRecorder {
    pub fn handle_event(&mut self, tgidpid: u64, cookie: u64, ts: u64, extra: String) {
        let systing_event = self.cookies.get(&cookie).unwrap();

        // If this is an instant event just add it to the list of events
        if self.instant_events.contains_key(&systing_event.name) {
            let entry = self.events.entry(tgidpid).or_insert_with(HashMap::new);
            let instant_track = self.instant_events.get(&systing_event.name).unwrap();
            let entry = entry.entry(instant_track.clone()).or_insert_with(Vec::new);
            entry.push(TrackInstant {
                ts,
                name: format!("{}{}", systing_event, extra),
            });
            return;
        }

        // First check to see if this is an end event, since we can have the same event for a start
        // event and an end event
        if let Some(range_name) = self.stop_events.get(&systing_event.name) {
            if let Some(ranges) = self.outstanding_ranges.get_mut(&tgidpid) {
                if let Some(mut range) = ranges.remove(range_name) {
                    let track_name = self.ranges.get(range_name).unwrap().clone();
                    range.end = ts;
                    let track_hash = self
                        .recorded_ranges
                        .entry(tgidpid)
                        .or_insert_with(HashMap::new);
                    let entry = track_hash.entry(track_name).or_insert_with(Vec::new);
                    entry.push(range);
                }
            }
        }

        // Now handle the start event case
        if let Some(range_name) = self.start_events.get(&systing_event.name) {
            if let Some(ranges) = self.outstanding_ranges.get_mut(&tgidpid) {
                if let Some(range) = ranges.get_mut(range_name) {
                    range.start = ts;
                } else {
                    let range = TrackRange {
                        range_name: range_name.clone(),
                        start: ts,
                        end: 0,
                    };
                    ranges.insert(range_name.clone(), range);
                }
            } else {
                let mut ranges = HashMap::new();
                let range = TrackRange {
                    range_name: range_name.clone(),
                    start: ts,
                    end: 0,
                };
                ranges.insert(range_name.clone(), range);
                self.outstanding_ranges.insert(tgidpid, ranges);
            }
        }
    }

    pub fn generate_trace(
        &self,
        pid_uuids: &HashMap<i32, u64>,
        thread_uuids: &HashMap<i32, u64>,
        id_counter: &mut Arc<AtomicUsize>,
    ) -> Vec<TracePacket> {
        let mut packets = Vec::new();

        // Populate the instant events
        for (pidtgid, events) in self.events.iter() {
            for (track_name, track_events) in events.iter() {
                let desc_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;
                let desc = crate::perfetto::generate_pidtgid_track_descriptor(
                    pid_uuids,
                    thread_uuids,
                    pidtgid,
                    track_name.clone(),
                    desc_uuid,
                );
                let mut packet = TracePacket::default();
                packet.set_track_descriptor(desc);
                packets.push(packet);

                let seq = id_counter.fetch_add(1, Ordering::Relaxed) as u32;
                for event in track_events.iter() {
                    let mut tevent = TrackEvent::default();
                    tevent.set_type(Type::TYPE_INSTANT);
                    tevent.set_name(event.name.clone());
                    tevent.set_track_uuid(desc_uuid);

                    let mut packet = TracePacket::default();
                    packet.set_timestamp(event.ts);
                    packet.set_track_event(tevent);
                    packet.set_trusted_packet_sequence_id(seq);
                    packets.push(packet);
                }
            }
        }

        // Populate the ranges
        for (tgidpid, tracks) in self.recorded_ranges.iter() {
            for (track_name, ranges) in tracks.iter() {
                let desc_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;
                let desc = crate::perfetto::generate_pidtgid_track_descriptor(
                    pid_uuids,
                    thread_uuids,
                    tgidpid,
                    track_name.clone(),
                    desc_uuid,
                );
                let mut packet = TracePacket::default();
                packet.set_track_descriptor(desc);
                packets.push(packet);

                let seq = id_counter.fetch_add(1, Ordering::Relaxed) as u32;
                for range in ranges.iter() {
                    let mut tevent = TrackEvent::default();
                    tevent.set_type(Type::TYPE_SLICE_BEGIN);
                    tevent.set_name(range.range_name.clone());
                    tevent.set_track_uuid(desc_uuid);

                    let mut packet = TracePacket::default();
                    packet.set_timestamp(range.start);
                    packet.set_track_event(tevent);
                    packet.set_trusted_packet_sequence_id(seq);
                    packets.push(packet);

                    let mut tevent = TrackEvent::default();
                    tevent.set_type(Type::TYPE_SLICE_END);
                    tevent.set_name(range.range_name.clone());
                    tevent.set_track_uuid(desc_uuid);

                    let mut packet = TracePacket::default();
                    packet.set_timestamp(range.end);
                    packet.set_track_event(tevent);
                    packet.set_trusted_packet_sequence_id(seq);
                    packets.push(packet);
                }
            }
        }
        packets
    }

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
        if self.config_events.contains_key(&systing_event.name) {
            return Err(anyhow::anyhow!(
                "Event {} already exists",
                systing_event.name
            ));
        }
        self.cookies
            .insert(systing_event.cookie, systing_event.clone());
        self.instant_events
            .insert(systing_event.name.clone(), systing_event.name.clone());
        self.config_events
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
        if self.config_events.contains_key(&event.name) {
            return Err(anyhow::anyhow!("Event {} already exists", event.name));
        }
        self.cookies.insert(event.cookie, event.clone());
        self.config_events.insert(event.name.clone(), event);
        Ok(())
    }

    fn load_config_from_json(&mut self, buf: &str, rng: &mut dyn rand::RngCore) -> Result<()> {
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
                    if !self.config_events.contains_key(&start_event) {
                        Err(anyhow::anyhow!(
                            "Start event {} does not exist",
                            start_event
                        ))?;
                    }
                    if !self.config_events.contains_key(&end_event) {
                        Err(anyhow::anyhow!("Stop event {} does not exist", end_event))?;
                    }
                    if self.start_events.contains_key(&start_event) {
                        Err(anyhow::anyhow!(
                            "Start event {} already exists",
                            start_event
                        ))?;
                    }
                    if self.stop_events.contains_key(&end_event) {
                        Err(anyhow::anyhow!("Stop event {} already exists", end_event))?;
                    }
                    self.start_events.insert(start_event, range.name.clone());
                    self.stop_events.insert(end_event, range.name.clone());

                    if self.ranges.contains_key(&range.name) {
                        Err(anyhow::anyhow!("Range {} already exists", range.name))?;
                    }
                    self.ranges.insert(range.name.clone(), track_name.clone());
                }
            }
            if let Some(instant) = &track.instant {
                if !self.config_events.contains_key(&instant.event) {
                    Err(anyhow::anyhow!(
                        "Instant event {} does not exist",
                        instant.event
                    ))?;
                }
                if self.instant_events.contains_key(&instant.event) {
                    Err(anyhow::anyhow!(
                        "Instant event {} already exists",
                        instant.event
                    ))?;
                }
                if self.start_events.contains_key(&instant.event) {
                    Err(anyhow::anyhow!(
                        "Start event {} already exists",
                        instant.event
                    ))?;
                }
                if self.stop_events.contains_key(&instant.event) {
                    Err(anyhow::anyhow!(
                        "Stop event {} already exists",
                        instant.event
                    ))?;
                }
                self.instant_events
                    .insert(instant.event.clone(), track_name.clone());
            }
        }
        Ok(())
    }

    pub fn load_config(&mut self, config: &str, rng: &mut dyn rand::RngCore) -> Result<()> {
        let path = Path::new(config);
        let buf = fs::read_to_string(path)?;

        self.load_config_from_json(&buf, rng)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::mock::StepRng;

    #[test]
    fn test_add_event() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        recorder
            .add_event_from_str("usdt:/path/to/file:provider:name", &mut rng)
            .unwrap();
        assert_eq!(recorder.cookies.len(), 1);
        assert_eq!(recorder.config_events.len(), 1);
        assert_eq!(recorder.instant_events.len(), 1);
    }

    #[test]
    fn test_add_event_invalid() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        assert!(recorder
            .add_event_from_str("invalid:/path/to/file:provider:name", &mut rng)
            .is_err());
    }

    #[test]
    fn test_add_event_json() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "event_name",
                    "event": "usdt:/path/to/file:provider:name",
                    "key_index": 0,
                    "key_type": "string"
                }
            ],
            "tracks": []
        }
        "#;
        let result = recorder.load_config_from_json(json, &mut rng);
        assert!(result.is_ok());
        assert_eq!(recorder.cookies.len(), 1);
        assert_eq!(recorder.config_events.len(), 1);
    }

    #[test]
    fn test_add_event_json_invalid() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "event_name",
                    "event": "invalid:/path/to/file:provider:name",
                    "key_index": 0,
                    "key_type": "string"
                }
            ],
            "tracks": []
        }
        "#;
        let result = recorder.load_config_from_json(json, &mut rng);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_event_json_duplicate() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "event_name",
                    "event": "usdt:/path/to/file:provider:name",
                    "key_index": 0,
                    "key_type": "string"
                },
                {
                    "name": "event_name",
                    "event": "usdt:/path/to/file:provider:name",
                    "key_index": 0,
                    "key_type": "string"
                }
            ],
            "tracks": []
        }
        "#;
        let result = recorder.load_config_from_json(json, &mut rng);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_event_json_range() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "event_name1",
                    "event": "usdt:/path/to/file:provider:name",
                    "key_index": 0,
                    "key_type": "string"
                },
                {
                    "name": "event_name2",
                    "event": "usdt:/path/to/file:provider:name",
                    "key_index": 0,
                    "key_type": "string"
                }
            ],
            "tracks": [
                {
                    "track_name": "track_name",
                    "ranges": [
                        {
                            "name": "range_name",
                            "start": "event_name1",
                            "end": "event_name2"
                        }
                    ]
                }
            ]
        }
        "#;
        let result = recorder.load_config_from_json(json, &mut rng);
        assert!(result.is_ok());
        assert_eq!(recorder.start_events.len(), 1);
        assert_eq!(recorder.stop_events.len(), 1);
    }

    #[test]
    fn test_add_event_json_range_invalid() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [],
            "tracks": [
                {
                    "track_name": "track_name",
                    "ranges": [
                        {
                            "name": "range_name",
                            "start": "invalid_event_name",
                            "end": "event_name"
                        }
                    ]
                }
            ]
        }
        "#;
        let result = recorder.load_config_from_json(json, &mut rng);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_event_json_range_duplicate() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [],
            "tracks": [
                {
                    "track_name": "track_name",
                    "ranges": [
                        {
                            "name": "range_name",
                            "start": "event_name",
                            "end": "event_name"
                        },
                        {
                            "name": "range_name",
                            "start": "event_name",
                            "end": "event_name"
                        }
                    ]
                }
            ]
        }
        "#;
        let result = recorder.load_config_from_json(json, &mut rng);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_event_json_instant() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "event_name",
                    "event": "usdt:/path/to/file:provider:name",
                    "key_index": 0,
                    "key_type": "string"
                }
            ],
            "tracks": [
                {
                    "track_name": "track_name",
                    "ranges": [],
                    "instant": {
                        "event": "event_name"
                    }
                }
            ]
        }
        "#;

        let result = recorder.load_config_from_json(json, &mut rng);
        assert!(result.is_ok());
        assert_eq!(recorder.instant_events.len(), 1);
    }

    #[test]
    fn test_add_event_json_instant_invalid() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [],
            "tracks": [
                {
                    "track_name": "track_name",
                    "ranges": [],
                    "instant": {
                        "event": "invalid_event_name"
                    }
                }
            ]
        }
        "#;

        let result = recorder.load_config_from_json(json, &mut rng);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_event_json_instant_duplicate() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "event_name",
                    "event": "usdt:/path/to/file:provider:name",
                    "key_index": 0,
                    "key_type": "string"
                }
            ],
            "tracks": [
                {
                    "track_name": "track_name",
                    "ranges": [],
                    "instant": {
                        "event": "event_name"
                    }
                },
                {
                    "track_name": "track_name_2",
                    "ranges": [],
                    "instant": {
                        "event": "event_name"
                    }
                }
            ]
        }
        "#;

        let result = recorder.load_config_from_json(json, &mut rng);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_event_json_instant_range() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "event_name1",
                    "event": "usdt:/path/to/file:provider:name",
                    "key_index": 0,
                    "key_type": "string"
                },
                {
                    "name": "event_name2",
                    "event": "usdt:/path/to/file:provider:name",
                    "key_index": 0,
                    "key_type": "string"
                }
            ],
            "tracks": [
                {
                    "track_name": "track_name",
                    "ranges": [
                        {
                            "name": "range_name",
                            "start": "event_name1",
                            "end": "event_name2"
                        }
                    ],
                    "instant": {
                        "event": "event_name1"
                    }
                }
            ]
        }
        "#;

        let result = recorder.load_config_from_json(json, &mut rng);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_event_json_instant_range_duplicate() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "event_name1",
                    "event": "usdt:/path/to/file:provider:name",
                    "key_index": 0,
                    "key_type": "string"
                },
                {
                    "name": "event_name2",
                    "event": "usdt:/path/to/file:provider:name",
                    "key_index": 0,
                    "key_type": "string"
                },
                {
                    "name": "event_name3",
                    "event": "usdt:/path/to/file:provider:name",
                    "key_index": 0,
                    "key_type": "string"
                }
            ],
            "tracks": [
                {
                    "track_name": "track_name",
                    "ranges": [
                        {
                            "name": "range_name",
                            "start": "event_name1",
                            "end": "event_name2"
                        },
                        {
                            "name": "range_name",
                            "start": "event_name2",
                            "end": "event_name3"
                        }
                    ],
                }
            ]
        }
        "#;

        let result = recorder.load_config_from_json(json, &mut rng);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_event_json_overlapping_events() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "event_name1",
                    "event": "usdt:/path/to/file:provider:name",
                    "key_index": 0,
                    "key_type": "string"
                },
                {
                    "name": "event_name2",
                    "event": "usdt:/path/to/file:provider:name",
                    "key_index": 0,
                    "key_type": "string"
                },
                {
                    "name": "event_name3",
                    "event": "usdt:/path/to/file:provider:name",
                    "key_index": 0,
                    "key_type": "string"
                }
            ],
            "tracks": [
                {
                    "track_name": "track_name",
                    "ranges": [
                        {
                            "name": "range_name",
                            "start": "event_name1",
                            "end": "event_name2"
                        },
                        {
                            "name": "range_name1",
                            "start": "event_name2",
                            "end": "event_name3"
                        }
                    ]
                }
            ]
        }
        "#;

        let result = recorder.load_config_from_json(json, &mut rng);
        assert!(result.is_ok());
        assert_eq!(recorder.start_events.len(), 2);
        assert_eq!(recorder.stop_events.len(), 2);
        assert_eq!(recorder.ranges.len(), 2);
        assert_eq!(recorder.instant_events.len(), 0);
        assert_eq!(recorder.config_events.len(), 3);
        assert_eq!(recorder.cookies.len(), 3);
    }

    #[test]
    fn test_instant_packet() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "event_name",
                    "event": "usdt:/path/to/file:provider:name",
                    "key_index": 0,
                    "key_type": "string"
                }
            ],
            "tracks": [
                {
                    "track_name": "track_name",
                    "instant": {
                        "event": "event_name"
                    }
                }
            ]
        }
        "#;

        recorder.load_config_from_json(json, &mut rng).unwrap();
        recorder.handle_event(1234, 0, 1000, String::new());
        let mut thread_uuids = HashMap::new();
        thread_uuids.insert(1234, 1);
        let packets = recorder.generate_trace(
            &HashMap::new(),
            &thread_uuids,
            &mut Arc::new(AtomicUsize::new(0)),
        );
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].track_descriptor().name(), "track_name");
        assert_eq!(
            packets[1].track_event().name(),
            "usdt:/path/to/file:provider:name"
        );
    }

    #[test]
    fn test_range_packet() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "event_name1",
                    "event": "usdt:/path/to/file:provider:name",
                    "key_index": 0,
                    "key_type": "string"
                },
                {
                    "name": "event_name2",
                    "event": "usdt:/path/to/file:provider:name",
                    "key_index": 0,
                    "key_type": "string"
                }
            ],
            "tracks": [
                {
                    "track_name": "track_name",
                    "ranges": [
                        {
                            "name": "range_name",
                            "start": "event_name1",
                            "end": "event_name2"
                        }
                    ]
                }
            ]
        }
        "#;

        recorder.load_config_from_json(json, &mut rng).unwrap();
        recorder.handle_event(1234, 0, 1000, String::new());
        recorder.handle_event(1234, 1, 2000, String::new());
        let mut thread_uuids = HashMap::new();
        thread_uuids.insert(1234, 1);
        let packets = recorder.generate_trace(
            &HashMap::new(),
            &thread_uuids,
            &mut Arc::new(AtomicUsize::new(0)),
        );
        assert_eq!(packets.len(), 3);
        assert_eq!(packets[0].track_descriptor().name(), "track_name");
        assert_eq!(packets[1].track_event().name(), "range_name");
        assert_eq!(packets[2].track_event().name(), "range_name");
        assert_eq!(packets[1].track_event().type_(), Type::TYPE_SLICE_BEGIN);
        assert_eq!(packets[2].track_event().type_(), Type::TYPE_SLICE_END);
        assert_eq!(packets[1].timestamp(), 1000);
        assert_eq!(packets[2].timestamp(), 2000);
        assert_eq!(
            packets[1].track_event().track_uuid(),
            packets[0].track_descriptor().uuid()
        );
        assert_eq!(
            packets[2].track_event().track_uuid(),
            packets[0].track_descriptor().uuid()
        );
    }

    #[test]
    fn test_range_packet_no_end() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "event_name1",
                    "event": "usdt:/path/to/file:provider:name",
                    "key_index": 0,
                    "key_type": "string"
                },
                {
                    "name": "event_name2",
                    "event": "usdt:/path/to/file:provider:name",
                    "key_index": 0,
                    "key_type": "string"
                }
            ],
            "tracks": [
                {
                    "track_name": "track_name",
                    "ranges": [
                        {
                            "name": "range_name",
                            "start": "event_name1",
                            "end": "event_name2"
                        }
                    ]
                }
            ]
        }
        "#;

        recorder.load_config_from_json(json, &mut rng).unwrap();
        recorder.handle_event(1234, 0, 1000, String::new());
        let mut thread_uuids = HashMap::new();
        thread_uuids.insert(1234, 1);
        let packets = recorder.generate_trace(
            &HashMap::new(),
            &thread_uuids,
            &mut Arc::new(AtomicUsize::new(0)),
        );
        assert_eq!(packets.len(), 0);
    }

    #[test]
    fn test_range_packet_no_start() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "event_name1",
                    "event": "usdt:/path/to/file:provider:name",
                    "key_index": 0,
                    "key_type": "string"
                },
                {
                    "name": "event_name2",
                    "event": "usdt:/path/to/file:provider:name",
                    "key_index": 0,
                    "key_type": "string"
                }
            ],
            "tracks": [
                {
                    "track_name": "track_name",
                    "ranges": [
                        {
                            "name": "range_name",
                            "start": "event_name1",
                            "end": "event_name2"
                        }
                    ]
                }
            ]
        }
        "#;

        recorder.load_config_from_json(json, &mut rng).unwrap();
        recorder.handle_event(1234, 1, 2000, String::new());
        let mut thread_uuids = HashMap::new();
        thread_uuids.insert(1234, 1);
        let packets = recorder.generate_trace(
            &HashMap::new(),
            &thread_uuids,
            &mut Arc::new(AtomicUsize::new(0)),
        );
        assert_eq!(packets.len(), 0);
    }

    #[test]
    fn test_range_packet_multiple_ranges() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "event_name1",
                    "event": "usdt:/path/to/file:provider:name",
                    "key_index": 0,
                    "key_type": "string"
                },
                {
                    "name": "event_name2",
                    "event": "usdt:/path/to/file:provider:name",
                    "key_index": 0,
                    "key_type": "string"
                },
                {
                    "name": "event_name3",
                    "event": "usdt:/path/to/file:provider:name",
                    "key_index": 0,
                    "key_type": "string"
                }
            ],
            "tracks": [
                {
                    "track_name": "track_name",
                    "ranges": [
                        {
                            "name": "range_name",
                            "start": "event_name1",
                            "end": "event_name2"
                        },
                        {
                            "name": "range_name2",
                            "start": "event_name2",
                            "end": "event_name3"
                        }
                    ]
                }
            ]
        }
        "#;

        recorder.load_config_from_json(json, &mut rng).unwrap();
        recorder.handle_event(1234, 0, 1000, String::new());
        recorder.handle_event(1234, 1, 2000, String::new());
        recorder.handle_event(1234, 2, 3000, String::new());
        let mut thread_uuids = HashMap::new();
        thread_uuids.insert(1234, 1);
        let packets = recorder.generate_trace(
            &HashMap::new(),
            &thread_uuids,
            &mut Arc::new(AtomicUsize::new(0)),
        );
        assert_eq!(packets.len(), 5);
        assert_eq!(packets[0].track_descriptor().name(), "track_name");

        assert_eq!(packets[1].track_event().name(), "range_name");
        assert_eq!(packets[1].track_event().type_(), Type::TYPE_SLICE_BEGIN);
        assert_eq!(packets[1].timestamp(), 1000);
        assert_eq!(
            packets[1].track_event().track_uuid(),
            packets[0].track_descriptor().uuid()
        );

        assert_eq!(packets[2].track_event().name(), "range_name");
        assert_eq!(packets[2].track_event().type_(), Type::TYPE_SLICE_END);
        assert_eq!(packets[2].timestamp(), 2000);
        assert_eq!(
            packets[2].track_event().track_uuid(),
            packets[0].track_descriptor().uuid()
        );

        assert_eq!(packets[3].track_event().name(), "range_name2");
        assert_eq!(packets[3].track_event().type_(), Type::TYPE_SLICE_BEGIN);
        assert_eq!(packets[3].timestamp(), 2000);
        assert_eq!(
            packets[3].track_event().track_uuid(),
            packets[0].track_descriptor().uuid()
        );

        assert_eq!(packets[4].track_event().name(), "range_name2");
        assert_eq!(packets[4].track_event().type_(), Type::TYPE_SLICE_END);
        assert_eq!(packets[4].timestamp(), 3000);
        assert_eq!(
            packets[4].track_event().track_uuid(),
            packets[0].track_descriptor().uuid()
        );
    }

    #[test]
    fn test_range_packet_multiple_ranges_multi_packet() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "event_name1",
                    "event": "usdt:/path/to/file:provider:name",
                    "key_index": 0,
                    "key_type": "string"
                },
                {
                    "name": "event_name2",
                    "event": "usdt:/path/to/file:provider:name",
                    "key_index": 0,
                    "key_type": "string"
                },
                {
                    "name": "event_name3",
                    "event": "usdt:/path/to/file:provider:name",
                    "key_index": 0,
                    "key_type": "string"
                }
            ],
            "tracks": [
                {
                    "track_name": "track_name",
                    "ranges": [
                        {
                            "name": "range_name",
                            "start": "event_name1",
                            "end": "event_name2"
                        },
                        {
                            "name": "range_name2",
                            "start": "event_name2",
                            "end": "event_name3"
                        }
                    ]
                }
            ]
        }
        "#;

        recorder.load_config_from_json(json, &mut rng).unwrap();
        recorder.handle_event(1234, 0, 1000, String::new());
        recorder.handle_event(1234, 1, 2000, String::new());
        recorder.handle_event(1234, 2, 3000, String::new());
        recorder.handle_event(1234, 0, 4000, String::new());
        recorder.handle_event(1234, 1, 5000, String::new());
        recorder.handle_event(1234, 2, 6000, String::new());
        let mut thread_uuids = HashMap::new();
        thread_uuids.insert(1234, 1);
        let packets = recorder.generate_trace(
            &HashMap::new(),
            &thread_uuids,
            &mut Arc::new(AtomicUsize::new(0)),
        );
        assert_eq!(packets.len(), 9);
        assert_eq!(packets[0].track_descriptor().name(), "track_name");

        assert_eq!(packets[1].track_event().name(), "range_name");
        assert_eq!(packets[1].track_event().type_(), Type::TYPE_SLICE_BEGIN);
        assert_eq!(packets[1].timestamp(), 1000);
        assert_eq!(
            packets[1].track_event().track_uuid(),
            packets[0].track_descriptor().uuid()
        );

        assert_eq!(packets[2].track_event().name(), "range_name");
        assert_eq!(packets[2].track_event().type_(), Type::TYPE_SLICE_END);
        assert_eq!(packets[2].timestamp(), 2000);
        assert_eq!(
            packets[2].track_event().track_uuid(),
            packets[0].track_descriptor().uuid()
        );

        assert_eq!(packets[3].track_event().name(), "range_name2");
        assert_eq!(packets[3].track_event().type_(), Type::TYPE_SLICE_BEGIN);
        assert_eq!(packets[3].timestamp(), 2000);
        assert_eq!(
            packets[3].track_event().track_uuid(),
            packets[0].track_descriptor().uuid()
        );

        assert_eq!(packets[4].track_event().name(), "range_name2");
        assert_eq!(packets[4].track_event().type_(), Type::TYPE_SLICE_END);
        assert_eq!(packets[4].timestamp(), 3000);
        assert_eq!(
            packets[4].track_event().track_uuid(),
            packets[0].track_descriptor().uuid()
        );

        assert_eq!(packets[5].track_event().name(), "range_name");
        assert_eq!(packets[5].track_event().type_(), Type::TYPE_SLICE_BEGIN);
        assert_eq!(packets[5].timestamp(), 4000);
        assert_eq!(
            packets[5].track_event().track_uuid(),
            packets[0].track_descriptor().uuid()
        );

        assert_eq!(packets[6].track_event().name(), "range_name");
        assert_eq!(packets[6].track_event().type_(), Type::TYPE_SLICE_END);
        assert_eq!(packets[6].timestamp(), 5000);
        assert_eq!(
            packets[6].track_event().track_uuid(),
            packets[0].track_descriptor().uuid()
        );

        assert_eq!(packets[7].track_event().name(), "range_name2");
        assert_eq!(packets[7].track_event().type_(), Type::TYPE_SLICE_BEGIN);
        assert_eq!(packets[7].timestamp(), 5000);
        assert_eq!(
            packets[7].track_event().track_uuid(),
            packets[0].track_descriptor().uuid()
        );

        assert_eq!(packets[8].track_event().name(), "range_name2");
        assert_eq!(packets[8].track_event().type_(), Type::TYPE_SLICE_END);
        assert_eq!(packets[8].timestamp(), 6000);
        assert_eq!(
            packets[8].track_event().track_uuid(),
            packets[0].track_descriptor().uuid()
        );
    }
}
