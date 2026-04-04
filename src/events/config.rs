use std::fs;
use std::path::Path;

use anyhow::Result;
use serde::Deserialize;

use super::probe::*;
use super::SystingProbeRecorder;

pub(super) struct ThresholdStopTrigger {
    pub(super) start_cookie: u64,
    pub(super) duration_us: u64,
}

// The JSON config file format is
// {
//   "events": [
//     {
//       "name": "event_name",
//       "event": "<PROBE TYPE SPECIFIC FORMAT>",
//       "scope": "thread",
//       "stack": false,
//       "args": [
//         {
//           "arg_index": 0,
//           "arg_type": "string",
//           "arg_name": "filename"
//         },
//         {
//           "arg_index": 1,
//           "arg_type": "long",
//           "arg_name": "size"
//         }
//      ]
//     }
//   ],
//
//   Args are optional and will show up as debug annotations on the events in the trace.
//   Up to 4 args can be specified per event. The arg_index specifies which argument
//   to capture (0-based), arg_type specifies the type ("string", "long", or "retval"),
//   and arg_name specifies the name of the annotation. The "retval" type captures the
//   function return value and is only valid for kretprobe and uretprobe events. The
//   arg_index field is not used for "retval" type and should be omitted.
//
//   The "stack" field is optional (defaults to false). When set to true, systing will
//   capture and emit a stack trace whenever this event fires.
//
//   Supported event formats:
//     - "usdt:<path>:<provider>:<name>" - User Statically Defined Tracepoint
//     - "uprobe:<path>:<symbol>" or "uprobe:<path>:<symbol>+<offset>" - User probe
//     - "uretprobe:<path>:<symbol>" - User return probe
//     - "kprobe:<symbol>" or "kprobe:<symbol>+<offset>" - Kernel probe
//     - "kretprobe:<symbol>" - Kernel return probe
//     - "tracepoint:<category>:<name>" - Kernel tracepoint
//
//   "tracks": [
//     {
//       "track_name": "track_name",
//       "ranges": [
//         {
//           "name": "range_name",
//           "start": "event_name",
//           "end": "event_name"
//         }
//       ],
//     },
//     {
//       track_name: "instant_track_name",
//       "instant": {
//         "event": "event_name"
//       }
//     }
//   ],
//   "stop_triggers": {
//     "thresholds": [
//       {
//         "start": "event_name",
//         "end": "event_name",
//         "duration_us": 1000
//       }
//     ],
//     "instants": [
//       {
//         "event": "event_name"
//       }
//     ]
//   }
// }
//
// The event names cannot be duplicated in the tracks, with the sole exception of ranges, where you
// can have the same start and end event name, but they must be different from the instant event.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct SystingJSONTrackConfig {
    events: Vec<SystingJSONEvent>,
    tracks: Option<Vec<SystingTrack>>,
    stop_triggers: Option<SystingJSONStopTrigger>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct SystingJSONEvent {
    name: String,
    event: String,
    scope: Option<EventScope>,
    args: Option<Vec<SystingJSONEventKey>>,
    stack: Option<bool>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct SystingTrack {
    track_name: String,
    ranges: Option<Vec<SystingRange>>,
    instants: Option<Vec<SystingInstant>>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct SystingJSONStopTrigger {
    thresholds: Option<Vec<SystingThreshold>>,
    instants: Option<Vec<SystingInstant>>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct SystingThreshold {
    start: String,
    end: String,
    duration_us: u64,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct SystingRange {
    name: String,
    start: String,
    end: String,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct SystingInstant {
    event: String,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct SystingJSONEventKey {
    #[serde(default)]
    arg_index: u8,
    arg_type: String,
    arg_name: String,
}

impl SystingProbeRecorder {
    pub fn add_event_from_str(&mut self, event: &str, rng: &mut dyn rand::RngCore) -> Result<()> {
        let parts = event.split(':').collect::<Vec<&str>>();
        let mut systing_event = SystingEvent {
            cookie: rng.next_u64(),
            ..Default::default()
        };
        match parts[0] {
            "usdt" => {
                let usdt = UsdtProbeEvent::from_parts(parts)?;
                systing_event.name = format!("{}:{}", usdt.provider, usdt.name);
                systing_event.event = EventProbe::Usdt(usdt);
            }
            "uprobe" | "uretprobe" => {
                let uprobe = UProbeEvent::from_parts(parts)?;
                systing_event.name = uprobe.func_name.clone();
                systing_event.event = EventProbe::UProbe(uprobe);
            }
            "kprobe" | "kretprobe" => {
                let kprobe = KProbeEvent::from_parts(parts)?;
                systing_event.name = kprobe.func_name.clone();
                systing_event.event = EventProbe::KProbe(kprobe);
            }
            "tracepoint" => {
                let tracepoint = TracepointEvent::from_parts(parts)?;
                systing_event.name = format!("{}:{}", tracepoint.category, tracepoint.name);
                systing_event.event = EventProbe::Tracepoint(tracepoint);
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
        let mut args = Vec::new();
        let arg_count = event.args.iter().flatten().count();
        if arg_count > 4 {
            return Err(anyhow::anyhow!(
                "Maximum 4 args allowed per event, got {} for event: {}",
                arg_count,
                event.name
            ));
        }
        for json_arg in event.args.iter().flatten() {
            let arg_type = match json_arg.arg_type.as_str() {
                "string" => EventKeyType::String,
                "long" => EventKeyType::Long,
                "retval" => EventKeyType::Retval,
                _ => return Err(anyhow::anyhow!("Invalid arg type: {}", json_arg.arg_type)),
            };

            // Validate arg_index is not used with retval
            if arg_type == EventKeyType::Retval && json_arg.arg_index != 0 {
                return Err(anyhow::anyhow!(
                    "arg_index must be 0 or omitted for retval type in event: {}",
                    event.name
                ));
            }

            args.push(EventKey {
                arg_index: json_arg.arg_index,
                arg_type,
                arg_name: json_arg.arg_name.clone(),
            });
        }
        let parts = event.event.split(':').collect::<Vec<&str>>();
        let probe = match parts[0] {
            "usdt" => EventProbe::Usdt(UsdtProbeEvent::from_parts(parts)?),
            "uprobe" | "uretprobe" => EventProbe::UProbe(UProbeEvent::from_parts(parts)?),
            "kprobe" | "kretprobe" => EventProbe::KProbe(KProbeEvent::from_parts(parts)?),
            "tracepoint" => EventProbe::Tracepoint(TracepointEvent::from_parts(parts)?),
            _ => return Err(anyhow::anyhow!("Invalid event type")),
        };

        // Validate retval args are only used with retprobes
        for arg in args.iter() {
            if matches!(arg.arg_type, EventKeyType::Retval) {
                match &probe {
                    EventProbe::UProbe(uprobe) if uprobe.retprobe => {}
                    EventProbe::KProbe(kprobe) if kprobe.retprobe => {}
                    EventProbe::UProbe(_) => {
                        return Err(anyhow::anyhow!(
                            "retval arg type requires uretprobe, not uprobe: {}",
                            event.name
                        ));
                    }
                    EventProbe::KProbe(_) => {
                        return Err(anyhow::anyhow!(
                            "retval arg type requires kretprobe, not kprobe: {}",
                            event.name
                        ));
                    }
                    EventProbe::Usdt(_) => {
                        return Err(anyhow::anyhow!(
                            "retval arg type is not supported for usdt probes: {}",
                            event.name
                        ));
                    }
                    EventProbe::Tracepoint(_) => {
                        return Err(anyhow::anyhow!(
                            "retval arg type is not supported for tracepoint events: {}",
                            event.name
                        ));
                    }
                    _ => {
                        return Err(anyhow::anyhow!(
                            "retval arg type is only valid for kretprobe and uretprobe events: {}",
                            event.name
                        ));
                    }
                }
            }
        }

        let event = SystingEvent {
            name: event.name.clone(),
            cookie: rng.next_u64(),
            event: probe,
            args,
            scope: event.scope.unwrap_or_default(),
            stack: event.stack.unwrap_or(false),
        };
        if self.config_events.contains_key(&event.name) {
            return Err(anyhow::anyhow!("Event {} already exists", event.name));
        }
        self.cookies.insert(event.cookie, event.clone());
        self.config_events.insert(event.name.clone(), event);
        Ok(())
    }

    fn add_trigger(&mut self, trigger: &SystingJSONStopTrigger) -> Result<()> {
        if let Some(thresholds) = &trigger.thresholds {
            for t in thresholds.iter() {
                if !self.config_events.contains_key(&t.start) {
                    return Err(anyhow::anyhow!("Start event {} does not exist", t.start));
                }
                if !self.config_events.contains_key(&t.end) {
                    return Err(anyhow::anyhow!("Stop event {} does not exist", t.end));
                }
                let start_event = self.config_events.get(&t.start).unwrap();
                let stop_event = self.config_events.get(&t.end).unwrap();
                if self.start_triggers.contains(&start_event.cookie) {
                    return Err(anyhow::anyhow!("Start event {} already exists", t.start));
                }
                if self.end_triggers.contains_key(&stop_event.cookie) {
                    return Err(anyhow::anyhow!("Stop event {} already exists", t.end));
                }
                self.start_triggers.insert(start_event.cookie);
                self.stop_triggers.push(ThresholdStopTrigger {
                    start_cookie: start_event.cookie,
                    duration_us: t.duration_us,
                });
                self.end_triggers
                    .insert(stop_event.cookie, self.stop_triggers.len() - 1);
            }
        } else if let Some(instants) = &trigger.instants {
            for instant in instants.iter() {
                if !self.config_events.contains_key(&instant.event) {
                    return Err(anyhow::anyhow!(
                        "Instant event {} does not exist",
                        instant.event
                    ));
                }
                let event = self.config_events.get(&instant.event).unwrap();
                if self.instant_events.contains_key(&instant.event) {
                    return Err(anyhow::anyhow!(
                        "Instant event {} already exists",
                        instant.event
                    ));
                }
                if self.start_events.contains_key(&instant.event) {
                    return Err(anyhow::anyhow!(
                        "Start event {} already exists",
                        instant.event
                    ));
                }
                if self.stop_events.contains_key(&instant.event) {
                    return Err(anyhow::anyhow!(
                        "Stop event {} already exists",
                        instant.event
                    ));
                }
                if !self.instant_triggers.insert(event.cookie) {
                    return Err(anyhow::anyhow!(
                        "Instant trigger for event {} already exists",
                        instant.event
                    ));
                }
            }
        } else {
            return Err(anyhow::anyhow!("Invalid trigger format"));
        }
        Ok(())
    }

    pub(super) fn load_config_from_json(
        &mut self,
        buf: &str,
        rng: &mut dyn rand::RngCore,
    ) -> Result<()> {
        let config: SystingJSONTrackConfig = serde_json::from_str(buf)?;
        for event in config.events.iter() {
            self.add_event_from_json(event, rng)?;
        }
        if let Some(stop_triggers) = config.stop_triggers {
            self.add_trigger(&stop_triggers)?;
        }

        let tracks = config.tracks.unwrap_or_default();
        for track in tracks {
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
                    let start_scope = self.config_events.get(&start_event).unwrap().scope;
                    let end_scope = self.config_events.get(&end_event).unwrap().scope;
                    if start_scope != end_scope {
                        Err(anyhow::anyhow!(
                            "Range '{}': start event '{}' has scope {:?} but end event '{}' has scope {:?}; they must match",
                            range.name, start_event, start_scope, end_event, end_scope
                        ))?;
                    }
                    self.start_events.insert(start_event, range.name.clone());
                    self.stop_events.insert(end_event, range.name.clone());

                    if self.ranges.contains_key(&range.name) {
                        Err(anyhow::anyhow!("Range {} already exists", range.name))?;
                    }
                    self.ranges.insert(range.name.clone(), track_name.clone());
                }
            }
            if let Some(instants) = &track.instants {
                for instant in instants.iter() {
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
        }
        Ok(())
    }

    pub fn load_config(&mut self, config: &str, rng: &mut dyn rand::RngCore) -> Result<()> {
        let path = Path::new(config);
        let buf = fs::read_to_string(path)?;

        self.load_config_from_json(&buf, rng)
    }
}
