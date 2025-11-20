use std::collections::{HashMap, HashSet};
use std::ffi::CStr;
use std::fmt;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::output::{ArgValue as OutputArgValue, EventDefinition, ProbeEventData, TraceOutput};
use crate::ringbuf::RingBuffer;
use crate::systing::types::probe_event;
use crate::utils::tid_from_tgidpid;
use crate::SystingRecordEvent;

use anyhow::Result;
use plain::Plain;
use serde::Deserialize;

use perfetto_protos::debug_annotation::DebugAnnotation;
use perfetto_protos::interned_data::InternedData;
use perfetto_protos::trace_packet::trace_packet::SequenceFlags;
use perfetto_protos::trace_packet::TracePacket;
use perfetto_protos::track_event::track_event::Type;
use perfetto_protos::track_event::{EventName, TrackEvent};

const SYS_ENTER_COOKIE: u64 = 0xFFFFFFFFFFFFFFFE;

enum ArgValue {
    String(String),
    Long(u64),
}

struct TrackInstant {
    ts: u64,
    name: String,
    args: Vec<(String, ArgValue)>,
}

struct TrackRange {
    range_name: String,
    start: u64,
    end: u64,
    args: Vec<(String, ArgValue)>,
}

struct ThresholdStopTrigger {
    start_cookie: u64,
    duration_us: u64,
}

// This is the main recorder struct, we keep track of the configuration for the events, as well as
// the events we've seen so far.
#[derive(Default)]
pub struct SystingProbeRecorder {
    pub ringbuf: RingBuffer<probe_event>,

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

    // CPU instant events, this works like events, but is indexed by CPU
    cpu_events: HashMap<u32, HashMap<String, Vec<TrackInstant>>>,

    // CPU range events, this works like recorded_ranges, but is indexed by CPU
    cpu_ranges: HashMap<u32, HashMap<String, Vec<TrackRange>>>,

    // The ranges that we've recorded a start event for, the key is the tgidpid of the thread, and
    // the value is a hashmap of the track_name with a TrackRange that has the start time set.
    outstanding_ranges: HashMap<u64, HashMap<String, TrackRange>>,

    // These are the outstanding CPU ranges, similar to outstanding_ranges, but indexed by CPU
    outstanding_cpu_ranges: HashMap<u32, HashMap<String, TrackRange>>,

    // The configured events that we've loaded from a config file or from --trace-event.
    pub config_events: HashMap<String, SystingEvent>,

    // The mapping of start event name -> range name
    start_events: HashMap<String, String>,

    // The mapping of stop event name -> range name
    stop_events: HashMap<String, String>,

    // The mapping of instant event name -> track name
    instant_events: HashMap<String, String>,

    // The vector of the threshold stop trigger events
    stop_triggers: Vec<ThresholdStopTrigger>,

    // The set of cookies that are start events
    start_triggers: HashSet<u64>,

    // The map of end triggers to the index in the stop_triggers vec of their corresponding
    // ThresholdStopTrigger
    end_triggers: HashMap<u64, usize>,

    // The set of cookies that are instant stop triggers
    instant_triggers: HashSet<u64>,

    // The map of outstanding start trigger events with their ts, indexed on tgipid
    outstanding_triggers: HashMap<u64, HashMap<u64, u64>>,

    // The mapping of the range name -> track name.
    ranges: HashMap<String, String>,

    // Syscall tracking state (cookies >= SYS_ENTER_COOKIE)
    pending_syscalls: HashMap<u64, HashMap<u64, u64>>,
    completed_syscalls: HashMap<u64, Vec<(u64, u64, u64)>>,
    syscall_iids: HashMap<u64, u64>,
    syscall_name_ids: HashMap<String, u64>,
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

// Format is
// kprobe:<offset>
// kprobe:<symbol>
// kprobe:<symbol>+<offset>
// kretprobe:<offset>
// kretprobe:<symbol>
// kretprobe:<symbol>+<offset>
#[derive(Clone, Default)]
pub struct KProbeEvent {
    pub offset: u64,
    pub func_name: String,
    pub retprobe: bool,
}

// Format is
// tracepoint:<category>:<name>
#[derive(Clone, Default)]
pub struct TracepointEvent {
    pub category: String,
    pub name: String,
}

#[derive(Clone, Default)]
pub enum EventProbe {
    UProbe(UProbeEvent),
    Usdt(UsdtProbeEvent),
    KProbe(KProbeEvent),
    Tracepoint(TracepointEvent),
    #[default]
    Undefined,
}

#[derive(Clone, Default, PartialEq)]
pub enum EventKeyType {
    String,
    #[default]
    Long,
    Retval,
}

#[derive(Clone, Default)]
pub struct EventKey {
    pub arg_index: u8,
    pub arg_type: EventKeyType,
    pub arg_name: String,
}

#[derive(Clone, Default)]
pub struct SystingEvent {
    pub name: String,
    pub cookie: u64,
    pub event: EventProbe,
    pub args: Vec<EventKey>,
    percpu: bool,
    pub stack: bool,
}

// The JSON config file format is
// {
//   "events": [
//     {
//       "name": "event_name",
//       "event": "<PROBE TYPE SPECIFIC FORMAT>",
//       "percpu": false,
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
    percpu: Option<bool>,
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
        let mut probe = UProbeEvent {
            path: parts[1].to_string(),
            retprobe: parts[0] == "uretprobe",
            ..Default::default()
        };

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
        if !self.func_name.is_empty() {
            if self.offset != 0 {
                write!(f, "{}:{}+0x{:x}", name, self.func_name, self.offset,)
            } else {
                write!(f, "{}:{}", name, self.func_name)
            }
        } else if self.offset != 0 {
            write!(f, "{}:0x{:x}", name, self.offset)
        } else {
            write!(f, "{name}")
        }
    }
}

impl KProbeEvent {
    fn from_parts(parts: Vec<&str>) -> Result<Self, anyhow::Error> {
        // Format is
        // kprobe:<offset>
        // kprobe:<symbol>
        // kprobe:<symbol>+<offset>
        // kretprobe:<offset>
        // kretprobe:<symbol>
        // kretprobe:<symbol>+<offset>
        if parts.len() != 2 {
            return Err(anyhow::anyhow!(
                "Invalid kprobe format: {}",
                parts.join(":")
            ));
        }
        let mut probe = KProbeEvent {
            retprobe: parts[0] == "kretprobe",
            ..Default::default()
        };

        match parts[1].parse::<u64>() {
            Ok(val) => {
                probe.offset = val;
            }
            Err(_) => {
                let symbol = parts[1].to_string();
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

impl fmt::Display for KProbeEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = if self.retprobe { "kretprobe" } else { "kprobe" };
        if !self.func_name.is_empty() {
            if self.offset != 0 {
                write!(f, "{}:{}+0x{:x}", name, self.func_name, self.offset,)
            } else {
                write!(f, "{}:{}", name, self.func_name)
            }
        } else if self.offset != 0 {
            write!(f, "{}:0x{:x}", name, self.offset)
        } else {
            write!(f, "{name}")
        }
    }
}

impl TracepointEvent {
    fn from_parts(parts: Vec<&str>) -> Result<Self, anyhow::Error> {
        // Format is
        // tracepoint:<category>:<name>
        if parts.len() != 3 {
            Err(anyhow::anyhow!("Invalid tracepoint format"))?;
        }
        let tracepoint = TracepointEvent {
            category: parts[1].to_string(),
            name: parts[2].to_string(),
        };
        Ok(tracepoint)
    }
}

impl fmt::Display for TracepointEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "tracepoint:{}:{}", self.category, self.name)
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
            EventProbe::UProbe(uprobe) => write!(f, "{uprobe}"),
            EventProbe::Usdt(usdt) => write!(f, "{usdt}"),
            EventProbe::KProbe(kprobe) => write!(f, "{kprobe}"),
            EventProbe::Tracepoint(tracepoint) => write!(f, "{tracepoint}"),
            _ => write!(f, "Invalid event"),
        }
    }
}

impl SystingRecordEvent<probe_event> for SystingProbeRecorder {
    fn ringbuf(&self) -> &RingBuffer<probe_event> {
        &self.ringbuf
    }
    fn ringbuf_mut(&mut self) -> &mut RingBuffer<probe_event> {
        &mut self.ringbuf
    }

    fn handle_event(&mut self, event: probe_event) {
        if event.cookie >= SYS_ENTER_COOKIE {
            self.handle_syscall_event(event);
            return;
        }

        let systing_event = match self.cookies.get(&event.cookie) {
            Some(evt) => evt,
            None => return,
        };
        let mut arg_data: Vec<(String, ArgValue)> = Vec::new();

        let num_args = event.num_args.min(event.args.len() as u8);
        for i in 0..num_args as usize {
            if i >= systing_event.args.len() {
                break;
            }

            let bpf_arg = &event.args[i];
            let event_key = &systing_event.args[i];

            match bpf_arg.r#type {
                crate::systing::types::arg_type::ARG_LONG => {
                    let mut bytes: [u8; 8] = [0; 8];
                    let _ = bytes.copy_from_bytes(&bpf_arg.value[..8]);
                    let val = u64::from_ne_bytes(bytes);
                    arg_data.push((event_key.arg_name.clone(), ArgValue::Long(val)));
                }
                crate::systing::types::arg_type::ARG_RETVAL => {
                    let mut bytes: [u8; 8] = [0; 8];
                    let _ = bytes.copy_from_bytes(&bpf_arg.value[..8]);
                    let val = u64::from_ne_bytes(bytes);
                    arg_data.push((event_key.arg_name.clone(), ArgValue::Long(val)));
                }
                crate::systing::types::arg_type::ARG_STRING => {
                    let arg_str = CStr::from_bytes_until_nul(&bpf_arg.value);
                    if let Ok(arg_str) = arg_str {
                        let bytes = arg_str.to_bytes();
                        if !bytes.is_empty() && !bytes.starts_with(&[0]) {
                            arg_data.push((
                                event_key.arg_name.clone(),
                                ArgValue::String(arg_str.to_string_lossy().to_string()),
                            ));
                        }
                    }
                }
                _ => {}
            }
        }
        if systing_event.percpu {
            self.handle_cpu_event(event, arg_data);
        } else {
            self.handle_process_event(event, arg_data);
        }
    }

    fn maybe_trigger(&mut self, event: &probe_event) -> bool {
        // If this is an instant event we trigger immediately
        if self.instant_triggers.contains(&event.cookie) {
            println!(
                "Instant event triggered on TGID {} PID {}",
                event.task.tgidpid >> 32_u32,
                event.task.tgidpid as u32
            );
            return true;
        }

        // If this is a start event record the ts and continue
        if self.start_triggers.contains(&event.cookie) {
            let entry = self
                .outstanding_triggers
                .entry(event.task.tgidpid)
                .or_default();
            entry.insert(event.cookie, event.ts);
            return false;
        }

        // If this isn't an end trigger event we're done
        if !self.end_triggers.contains_key(&event.cookie) {
            return false;
        }

        // If this is an end event, we need to check if we have a start trigger for it
        if let Some(start_map) = self.outstanding_triggers.get_mut(&event.task.tgidpid) {
            let trigger_index = self.end_triggers.get(&event.cookie).unwrap();
            let trigger = &self.stop_triggers[*trigger_index];
            if let Some(start_ts) = start_map.remove(&trigger.start_cookie) {
                let start = Duration::from_nanos(start_ts);
                let end = Duration::from_nanos(event.ts);
                let threshold = Duration::from_micros(trigger.duration_us);
                // We took longer than our threshold, we're done
                if start + threshold <= end {
                    println!(
                        "Threshold exceeded on TGID {} PID {}",
                        event.task.tgidpid >> 32_u32,
                        event.task.tgidpid as u32
                    );
                    return true;
                }
            }
        }

        false
    }
}

impl SystingProbeRecorder {
    fn handle_syscall_event(&mut self, event: probe_event) {
        if event.num_args == 0 {
            return;
        }

        let mut bytes: [u8; 8] = [0; 8];
        let _ = bytes.copy_from_bytes(&event.args[0].value[..8]);
        let syscall_nr = u64::from_ne_bytes(bytes);
        let tgidpid = event.task.tgidpid;

        if event.cookie == SYS_ENTER_COOKIE {
            self.pending_syscalls
                .entry(tgidpid)
                .or_default()
                .insert(syscall_nr, event.ts);
        } else if let Some(pid_pending) = self.pending_syscalls.get_mut(&tgidpid) {
            if let Some(enter_ts) = pid_pending.remove(&syscall_nr) {
                self.completed_syscalls
                    .entry(tgidpid)
                    .or_default()
                    .push((enter_ts, event.ts, syscall_nr));
            }
        }
    }

    fn get_or_create_syscall_name_iid(
        &mut self,
        syscall_nr: u64,
        id_counter: &Arc<AtomicUsize>,
    ) -> u64 {
        use syscalls::Sysno;

        if let Some(&iid) = self.syscall_iids.get(&syscall_nr) {
            return iid;
        }

        let syscall_name = match Sysno::new(syscall_nr as usize) {
            Some(sysno) => sysno.name().to_string(),
            None => format!("syscall_{syscall_nr}"),
        };

        let iid = if let Some(&existing_iid) = self.syscall_name_ids.get(&syscall_name) {
            existing_iid
        } else {
            let new_iid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;
            self.syscall_name_ids.insert(syscall_name, new_iid);
            new_iid
        };

        self.syscall_iids.insert(syscall_nr, iid);
        iid
    }

    fn add_arg_annotations(tevent: &mut TrackEvent, args: &[(String, ArgValue)]) {
        for (name, value) in args {
            let mut annotation = DebugAnnotation::default();
            annotation.set_name(name.clone());
            match value {
                ArgValue::String(s) => annotation.set_string_value(s.clone()),
                ArgValue::Long(v) => annotation.set_uint_value(*v),
            }
            tevent.debug_annotations.push(annotation);
        }
    }

    fn handle_cpu_event(&mut self, event: probe_event, arg_data: Vec<(String, ArgValue)>) {
        let systing_event = self.cookies.get(&event.cookie).unwrap();

        // If this is an instant event just add it to the list of events
        if self.instant_events.contains_key(&systing_event.name) {
            let instant_track = self.instant_events.get(&systing_event.name).unwrap();
            let entry = self.cpu_events.entry(event.cpu).or_default();
            let entry = entry.entry(instant_track.clone()).or_default();
            entry.push(TrackInstant {
                ts: event.ts,
                name: format!("{systing_event}"),
                args: arg_data,
            });
            return;
        }

        // First check to see if this is an end event, since we can have the same event for a start
        // event and an end event
        if let Some(range_name) = self.stop_events.get(&systing_event.name) {
            if let Some(ranges) = self.outstanding_cpu_ranges.get_mut(&event.cpu) {
                if let Some(mut range) = ranges.remove(range_name) {
                    let track_name = self.ranges.get(range_name).unwrap().clone();
                    range.end = event.ts;
                    let track_hash = self.cpu_ranges.entry(event.cpu).or_default();
                    let entry = track_hash.entry(track_name).or_default();
                    entry.push(range);
                }
            }
        }

        // Now handle the start event case
        if let Some(range_name) = self.start_events.get(&systing_event.name) {
            if let Some(ranges) = self.outstanding_cpu_ranges.get_mut(&event.cpu) {
                if let Some(range) = ranges.get_mut(range_name) {
                    range.start = event.ts;
                    range.args = arg_data;
                } else {
                    let range = TrackRange {
                        range_name: range_name.clone(),
                        start: event.ts,
                        end: 0,
                        args: arg_data,
                    };
                    ranges.insert(range_name.clone(), range);
                }
            } else {
                let mut ranges = HashMap::new();
                let range = TrackRange {
                    range_name: range_name.clone(),
                    start: event.ts,
                    end: 0,
                    args: arg_data,
                };
                ranges.insert(range_name.clone(), range);
                self.outstanding_cpu_ranges.insert(event.cpu, ranges);
            }
        }
    }

    fn handle_process_event(&mut self, event: probe_event, arg_data: Vec<(String, ArgValue)>) {
        let systing_event = self.cookies.get(&event.cookie).unwrap();

        // If this is an instant event just add it to the list of events
        if self.instant_events.contains_key(&systing_event.name) {
            let instant_track = self.instant_events.get(&systing_event.name).unwrap();
            let entry = self.events.entry(event.task.tgidpid).or_default();
            let entry = entry.entry(instant_track.clone()).or_default();
            entry.push(TrackInstant {
                ts: event.ts,
                name: format!("{systing_event}"),
                args: arg_data,
            });
            return;
        }

        // First check to see if this is an end event, since we can have the same event for a start
        // event and an end event
        if let Some(range_name) = self.stop_events.get(&systing_event.name) {
            if let Some(ranges) = self.outstanding_ranges.get_mut(&event.task.tgidpid) {
                if let Some(mut range) = ranges.remove(range_name) {
                    let track_name = self.ranges.get(range_name).unwrap().clone();
                    range.end = event.ts;
                    let track_hash = self.recorded_ranges.entry(event.task.tgidpid).or_default();
                    let entry = track_hash.entry(track_name).or_default();
                    entry.push(range);
                }
            }
        }

        // Now handle the start event case
        if let Some(range_name) = self.start_events.get(&systing_event.name) {
            if let Some(ranges) = self.outstanding_ranges.get_mut(&event.task.tgidpid) {
                if let Some(range) = ranges.get_mut(range_name) {
                    range.start = event.ts;
                    range.args = arg_data;
                } else {
                    let range = TrackRange {
                        range_name: range_name.clone(),
                        start: event.ts,
                        end: 0,
                        args: arg_data,
                    };
                    ranges.insert(range_name.clone(), range);
                }
            } else {
                let mut ranges = HashMap::new();
                let range = TrackRange {
                    range_name: range_name.clone(),
                    start: event.ts,
                    end: 0,
                    args: arg_data,
                };
                ranges.insert(range_name.clone(), range);
                self.outstanding_ranges.insert(event.task.tgidpid, ranges);
            }
        }
    }

    pub fn generate_trace(
        &mut self,
        pid_uuids: &HashMap<i32, u64>,
        thread_uuids: &HashMap<i32, u64>,
        id_counter: &Arc<AtomicUsize>,
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
                    Self::add_arg_annotations(&mut tevent, &event.args);

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
                    Self::add_arg_annotations(&mut tevent, &range.args);

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

        // Populate the per cpu range tracks
        let mut cpu_desc_uuids: HashMap<String, u64> = HashMap::new();
        for (cpu, tracks) in self.cpu_ranges.iter() {
            for (track_name, ranges) in tracks.iter() {
                let mut descs = crate::perfetto::generate_cpu_track_descriptors(
                    &mut cpu_desc_uuids,
                    *cpu,
                    track_name.clone(),
                    id_counter,
                );

                let desc = descs.pop().unwrap();
                let desc_uuid = desc.uuid();

                if let Some(new_desc) = descs.pop() {
                    let mut packet = TracePacket::default();
                    packet.set_track_descriptor(new_desc);
                    packets.push(packet);
                }

                let mut packet = TracePacket::default();
                packet.set_track_descriptor(desc);
                packets.push(packet);

                let seq = id_counter.fetch_add(1, Ordering::Relaxed) as u32;
                for range in ranges.iter() {
                    let mut tevent = TrackEvent::default();
                    tevent.set_type(Type::TYPE_SLICE_BEGIN);
                    tevent.set_name(range.range_name.clone());
                    tevent.set_track_uuid(desc_uuid);
                    Self::add_arg_annotations(&mut tevent, &range.args);

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

        // Populate the instant CPU events
        for (cpu, events) in self.cpu_events.iter() {
            for (track_name, track_events) in events.iter() {
                let mut descs = crate::perfetto::generate_cpu_track_descriptors(
                    &mut cpu_desc_uuids,
                    *cpu,
                    track_name.clone(),
                    id_counter,
                );

                let desc = descs.pop().unwrap();
                let desc_uuid = desc.uuid();

                if let Some(new_desc) = descs.pop() {
                    let mut packet = TracePacket::default();
                    packet.set_track_descriptor(new_desc);
                    packets.push(packet);
                }

                let mut packet = TracePacket::default();
                packet.set_track_descriptor(desc);
                packets.push(packet);

                let seq = id_counter.fetch_add(1, Ordering::Relaxed) as u32;
                for event in track_events.iter() {
                    let mut tevent = TrackEvent::default();
                    tevent.set_type(Type::TYPE_INSTANT);
                    tevent.set_name(event.name.clone());
                    tevent.set_track_uuid(desc_uuid);
                    Self::add_arg_annotations(&mut tevent, &event.args);

                    let mut packet = TracePacket::default();
                    packet.set_timestamp(event.ts);
                    packet.set_track_event(tevent);
                    packet.set_trusted_packet_sequence_id(seq);
                    packets.push(packet);
                }
            }
        }

        // Generate syscall trace packets
        let sequence_id = id_counter.fetch_add(1, Ordering::Relaxed) as u32;

        // Collect unique syscall numbers first
        let mut syscall_numbers: Vec<u64> = Vec::new();
        for (_pid, syscalls) in self.completed_syscalls.iter() {
            for (_start_ts, _end_ts, syscall_nr) in syscalls {
                syscall_numbers.push(*syscall_nr);
            }
        }

        // Intern all unique syscall numbers
        for syscall_nr in syscall_numbers {
            self.get_or_create_syscall_name_iid(syscall_nr, id_counter);
        }

        // Generate interned data packet with syscall names
        if !self.syscall_name_ids.is_empty() {
            let mut event_names = Vec::new();
            for (name, iid) in &self.syscall_name_ids {
                let mut event_name = EventName::default();
                event_name.set_iid(*iid);
                event_name.set_name(name.clone());
                event_names.push(event_name);
            }
            event_names.sort_by_key(|e| e.iid());

            let mut interned_packet = TracePacket::default();
            let interned_data = InternedData {
                event_names,
                ..Default::default()
            };
            interned_packet.interned_data = Some(interned_data).into();
            interned_packet.set_trusted_packet_sequence_id(sequence_id);
            interned_packet.set_sequence_flags(
                SequenceFlags::SEQ_INCREMENTAL_STATE_CLEARED as u32
                    | SequenceFlags::SEQ_NEEDS_INCREMENTAL_STATE as u32,
            );
            packets.push(interned_packet);
        }

        // Generate per-thread syscall tracks and events
        for (tgidpid, syscalls) in self.completed_syscalls.iter() {
            if syscalls.is_empty() {
                continue;
            }

            let track_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;
            let desc = crate::perfetto::generate_pidtgid_track_descriptor(
                pid_uuids,
                thread_uuids,
                tgidpid,
                "Syscalls".to_string(),
                track_uuid,
            );

            let mut packet = TracePacket::default();
            packet.set_track_descriptor(desc);
            packets.push(packet);

            for (start_ts, end_ts, syscall_nr) in syscalls {
                let name_iid = *self.syscall_iids.get(syscall_nr).unwrap();

                let mut begin_event = TrackEvent::default();
                begin_event.set_type(Type::TYPE_SLICE_BEGIN);
                begin_event.set_name_iid(name_iid);
                begin_event.set_track_uuid(track_uuid);

                let mut begin_packet = TracePacket::default();
                begin_packet.set_timestamp(*start_ts);
                begin_packet.set_track_event(begin_event);
                begin_packet.set_trusted_packet_sequence_id(sequence_id);
                packets.push(begin_packet);

                let mut end_event = TrackEvent::default();
                end_event.set_type(Type::TYPE_SLICE_END);
                end_event.set_track_uuid(track_uuid);

                let mut end_packet = TracePacket::default();
                end_packet.set_timestamp(*end_ts);
                end_packet.set_track_event(end_event);
                end_packet.set_trusted_packet_sequence_id(sequence_id);
                packets.push(end_packet);
            }
        }

        // Clear syscall state after generating packets
        self.completed_syscalls.clear();
        self.pending_syscalls.clear();
        self.syscall_iids.clear();
        self.syscall_name_ids.clear();

        packets
    }

    pub fn write_output(
        &self,
        output: &mut dyn TraceOutput,
        _id_counter: &Arc<AtomicUsize>,
    ) -> Result<()> {
        // First pass: Define all event types and store their definition IDs
        // We need to collect all unique event definitions from all event sources
        let mut event_defs: HashMap<String, u64> = HashMap::new();

        // Helper function to convert local ArgValue to output ArgValue
        let convert_arg = |arg: &ArgValue| -> OutputArgValue {
            match arg {
                ArgValue::String(s) => OutputArgValue::String(s.clone()),
                ArgValue::Long(l) => OutputArgValue::Long(*l as i64),
            }
        };

        // Collect event definitions from instant events (thread-based)
        for (_tgidpid, events) in self.events.iter() {
            for (track_name, track_events) in events.iter() {
                for event in track_events.iter() {
                    let event_key = format!("instant:{}:{}", track_name, event.name);
                    if !event_defs.contains_key(&event_key) {
                        // Find the cookie for this event
                        let cookie = self
                            .cookies
                            .iter()
                            .find(|(_, e)| e.name == event.name)
                            .map(|(c, _)| *c)
                            .unwrap_or(0);

                        let def = EventDefinition {
                            event_name: event.name.clone(),
                            event_type: "instant".to_string(),
                            track_name: Some(track_name.clone()),
                            category: None,
                            cookie,
                        };
                        let def_id = output.write_event_definition(&def)?;
                        event_defs.insert(event_key, def_id);
                    }
                }
            }
        }

        // Collect event definitions from range events (thread-based)
        for (_tgidpid, tracks) in self.recorded_ranges.iter() {
            for (track_name, ranges) in tracks.iter() {
                for range in ranges.iter() {
                    // Range start event
                    let start_key = format!("range_start:{}:{}", track_name, range.range_name);
                    if !event_defs.contains_key(&start_key) {
                        let cookie = self
                            .cookies
                            .iter()
                            .find(|(_, e)| e.name == range.range_name)
                            .map(|(c, _)| *c)
                            .unwrap_or(0);

                        let def = EventDefinition {
                            event_name: range.range_name.clone(),
                            event_type: "range_start".to_string(),
                            track_name: Some(track_name.clone()),
                            category: None,
                            cookie,
                        };
                        let def_id = output.write_event_definition(&def)?;
                        event_defs.insert(start_key, def_id);
                    }

                    // Range end event
                    let end_key = format!("range_end:{}:{}", track_name, range.range_name);
                    if !event_defs.contains_key(&end_key) {
                        let cookie = self
                            .cookies
                            .iter()
                            .find(|(_, e)| e.name == range.range_name)
                            .map(|(c, _)| *c)
                            .unwrap_or(0);

                        let def = EventDefinition {
                            event_name: range.range_name.clone(),
                            event_type: "range_end".to_string(),
                            track_name: Some(track_name.clone()),
                            category: None,
                            cookie,
                        };
                        let def_id = output.write_event_definition(&def)?;
                        event_defs.insert(end_key, def_id);
                    }
                }
            }
        }

        // Collect event definitions from CPU instant events
        for (_cpu, events) in self.cpu_events.iter() {
            for (track_name, track_events) in events.iter() {
                for event in track_events.iter() {
                    let event_key = format!("instant:{}:{}", track_name, event.name);
                    if !event_defs.contains_key(&event_key) {
                        let cookie = self
                            .cookies
                            .iter()
                            .find(|(_, e)| e.name == event.name)
                            .map(|(c, _)| *c)
                            .unwrap_or(0);

                        let def = EventDefinition {
                            event_name: event.name.clone(),
                            event_type: "instant".to_string(),
                            track_name: Some(track_name.clone()),
                            category: None,
                            cookie,
                        };
                        let def_id = output.write_event_definition(&def)?;
                        event_defs.insert(event_key, def_id);
                    }
                }
            }
        }

        // Collect event definitions from CPU range events
        for (_cpu, tracks) in self.cpu_ranges.iter() {
            for (track_name, ranges) in tracks.iter() {
                for range in ranges.iter() {
                    // Range start event
                    let start_key = format!("range_start:{}:{}", track_name, range.range_name);
                    if !event_defs.contains_key(&start_key) {
                        let cookie = self
                            .cookies
                            .iter()
                            .find(|(_, e)| e.name == range.range_name)
                            .map(|(c, _)| *c)
                            .unwrap_or(0);

                        let def = EventDefinition {
                            event_name: range.range_name.clone(),
                            event_type: "range_start".to_string(),
                            track_name: Some(track_name.clone()),
                            category: None,
                            cookie,
                        };
                        let def_id = output.write_event_definition(&def)?;
                        event_defs.insert(start_key, def_id);
                    }

                    // Range end event
                    let end_key = format!("range_end:{}:{}", track_name, range.range_name);
                    if !event_defs.contains_key(&end_key) {
                        let cookie = self
                            .cookies
                            .iter()
                            .find(|(_, e)| e.name == range.range_name)
                            .map(|(c, _)| *c)
                            .unwrap_or(0);

                        let def = EventDefinition {
                            event_name: range.range_name.clone(),
                            event_type: "range_end".to_string(),
                            track_name: Some(track_name.clone()),
                            category: None,
                            cookie,
                        };
                        let def_id = output.write_event_definition(&def)?;
                        event_defs.insert(end_key, def_id);
                    }
                }
            }
        }

        // Second pass: Write all probe event occurrences

        // Write instant events (thread-based)
        for (tgidpid, events) in self.events.iter() {
            for (track_name, track_events) in events.iter() {
                for event in track_events.iter() {
                    let event_key = format!("instant:{}:{}", track_name, event.name);
                    if let Some(&def_id) = event_defs.get(&event_key) {
                        let mut args = HashMap::new();
                        for (arg_name, arg_value) in &event.args {
                            args.insert(arg_name.clone(), convert_arg(arg_value));
                        }

                        let probe_event = ProbeEventData {
                            ts: event.ts,
                            tid: tid_from_tgidpid(*tgidpid),
                            event_def_id: def_id,
                            args,
                        };
                        output.write_probe_event(&probe_event)?;
                    }
                }
            }
        }

        // Write range events (thread-based)
        for (tgidpid, tracks) in self.recorded_ranges.iter() {
            for (track_name, ranges) in tracks.iter() {
                for range in ranges.iter() {
                    // Write range start event
                    let start_key = format!("range_start:{}:{}", track_name, range.range_name);
                    if let Some(&def_id) = event_defs.get(&start_key) {
                        let mut args = HashMap::new();
                        for (arg_name, arg_value) in &range.args {
                            args.insert(arg_name.clone(), convert_arg(arg_value));
                        }

                        let probe_event = ProbeEventData {
                            ts: range.start,
                            tid: tid_from_tgidpid(*tgidpid),
                            event_def_id: def_id,
                            args,
                        };
                        output.write_probe_event(&probe_event)?;
                    }

                    // Write range end event
                    let end_key = format!("range_end:{}:{}", track_name, range.range_name);
                    if let Some(&def_id) = event_defs.get(&end_key) {
                        let probe_event = ProbeEventData {
                            ts: range.end,
                            tid: tid_from_tgidpid(*tgidpid),
                            event_def_id: def_id,
                            args: HashMap::new(), // End events don't have args
                        };
                        output.write_probe_event(&probe_event)?;
                    }
                }
            }
        }

        // Write CPU instant events
        for (_cpu, events) in self.cpu_events.iter() {
            for (track_name, track_events) in events.iter() {
                for event in track_events.iter() {
                    let event_key = format!("instant:{}:{}", track_name, event.name);
                    if let Some(&def_id) = event_defs.get(&event_key) {
                        let mut args = HashMap::new();
                        for (arg_name, arg_value) in &event.args {
                            args.insert(arg_name.clone(), convert_arg(arg_value));
                        }

                        // CPU events don't have a TID, use 0
                        let probe_event = ProbeEventData {
                            ts: event.ts,
                            tid: 0,
                            event_def_id: def_id,
                            args,
                        };
                        output.write_probe_event(&probe_event)?;
                    }
                }
            }
        }

        // Write CPU range events
        for (_cpu, tracks) in self.cpu_ranges.iter() {
            for (track_name, ranges) in tracks.iter() {
                for range in ranges.iter() {
                    // Write range start event
                    let start_key = format!("range_start:{}:{}", track_name, range.range_name);
                    if let Some(&def_id) = event_defs.get(&start_key) {
                        let mut args = HashMap::new();
                        for (arg_name, arg_value) in &range.args {
                            args.insert(arg_name.clone(), convert_arg(arg_value));
                        }

                        let probe_event = ProbeEventData {
                            ts: range.start,
                            tid: 0, // CPU events don't have a TID
                            event_def_id: def_id,
                            args,
                        };
                        output.write_probe_event(&probe_event)?;
                    }

                    // Write range end event
                    let end_key = format!("range_end:{}:{}", track_name, range.range_name);
                    if let Some(&def_id) = event_defs.get(&end_key) {
                        let probe_event = ProbeEventData {
                            ts: range.end,
                            tid: 0, // CPU events don't have a TID
                            event_def_id: def_id,
                            args: HashMap::new(), // End events don't have args
                        };
                        output.write_probe_event(&probe_event)?;
                    }
                }
            }
        }

        Ok(())
    }

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
            percpu: event.percpu.unwrap_or(false),
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

    fn load_config_from_json(&mut self, buf: &str, rng: &mut dyn rand::RngCore) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::systing::types::task_info;
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
                    "event": "usdt:/path/to/file:provider:name"
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
                    "event": "invalid:/path/to/file:provider:name"
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
                    "event": "usdt:/path/to/file:provider:name"
                },
                {
                    "name": "event_name",
                    "event": "usdt:/path/to/file:provider:name"
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
                    "event": "usdt:/path/to/file:provider:name"
                },
                {
                    "name": "event_name2",
                    "event": "usdt:/path/to/file:provider:name"
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
                    "event": "usdt:/path/to/file:provider:name"
                }
            ],
            "tracks": [
                {
                    "track_name": "track_name",
                    "ranges": [],
                    "instants": [
                      {
                        "event": "event_name"
                      }
                    ]
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
                    "instants": [
                      {
                        "event": "invalid_event_name"
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
    fn test_add_event_json_instant_duplicate() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "event_name",
                    "event": "usdt:/path/to/file:provider:name"
                }
            ],
            "tracks": [
                {
                    "track_name": "track_name",
                    "ranges": [],
                    "instants": [
                      {
                        "event": "event_name"
                      }
                    ]
                },
                {
                    "track_name": "track_name_2",
                    "ranges": [],
                    "instants": [
                      {
                        "event": "event_name"
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
    fn test_add_event_json_instant_range() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "event_name1",
                    "event": "usdt:/path/to/file:provider:name"
                },
                {
                    "name": "event_name2",
                    "event": "usdt:/path/to/file:provider:name"
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
                    "instants": [
                      {
                        "event": "event_name1"
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
    fn test_add_event_json_instant_range_duplicate() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "event_name1",
                    "event": "usdt:/path/to/file:provider:name"
                },
                {
                    "name": "event_name2",
                    "event": "usdt:/path/to/file:provider:name"
                },
                {
                    "name": "event_name3",
                    "event": "usdt:/path/to/file:provider:name"
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
                    "event": "usdt:/path/to/file:provider:name"
                },
                {
                    "name": "event_name2",
                    "event": "usdt:/path/to/file:provider:name"
                },
                {
                    "name": "event_name3",
                    "event": "usdt:/path/to/file:provider:name"
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
                    "event": "usdt:/path/to/file:provider:name"
                }
            ],
            "tracks": [
                {
                    "track_name": "track_name",
                    "instants": [
                      {
                        "event": "event_name"
                      }
                    ]
                }
            ]
        }
        "#;

        recorder.load_config_from_json(json, &mut rng).unwrap();
        let event = probe_event {
            task: task_info {
                tgidpid: 1234,
                ..Default::default()
            },
            ts: 1000,
            ..Default::default()
        };
        recorder.handle_event(event);
        let mut thread_uuids = HashMap::new();
        thread_uuids.insert(1234, 1);
        let packets = recorder.generate_trace(
            &HashMap::new(),
            &thread_uuids,
            &Arc::new(AtomicUsize::new(0)),
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
                    "event": "usdt:/path/to/file:provider:name"
                },
                {
                    "name": "event_name2",
                    "event": "usdt:/path/to/file:provider:name"
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
        let mut event = probe_event {
            task: task_info {
                tgidpid: 1234,
                ..Default::default()
            },
            ts: 1000,
            ..Default::default()
        };
        recorder.handle_event(event);
        event.cookie = 1;
        event.ts = 2000;
        recorder.handle_event(event);
        let mut thread_uuids = HashMap::new();
        thread_uuids.insert(1234, 1);
        let packets = recorder.generate_trace(
            &HashMap::new(),
            &thread_uuids,
            &Arc::new(AtomicUsize::new(0)),
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
                    "event": "usdt:/path/to/file:provider:name"
                },
                {
                    "name": "event_name2",
                    "event": "usdt:/path/to/file:provider:name"
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
        let event = probe_event {
            task: task_info {
                tgidpid: 1234,
                ..Default::default()
            },
            ts: 1000,
            ..Default::default()
        };
        recorder.handle_event(event);
        let mut thread_uuids = HashMap::new();
        thread_uuids.insert(1234, 1);
        let packets = recorder.generate_trace(
            &HashMap::new(),
            &thread_uuids,
            &Arc::new(AtomicUsize::new(0)),
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
                    "event": "usdt:/path/to/file:provider:name"
                },
                {
                    "name": "event_name2",
                    "event": "usdt:/path/to/file:provider:name"
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
        let event = probe_event {
            task: task_info {
                tgidpid: 1234,
                ..Default::default()
            },
            ts: 2000,
            cookie: 1,
            ..Default::default()
        };
        recorder.handle_event(event);
        let mut thread_uuids = HashMap::new();
        thread_uuids.insert(1234, 1);
        let packets = recorder.generate_trace(
            &HashMap::new(),
            &thread_uuids,
            &Arc::new(AtomicUsize::new(0)),
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
                    "event": "usdt:/path/to/file:provider:name"
                },
                {
                    "name": "event_name2",
                    "event": "usdt:/path/to/file:provider:name"
                },
                {
                    "name": "event_name3",
                    "event": "usdt:/path/to/file:provider:name"
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
        let mut event = probe_event {
            task: task_info {
                tgidpid: 1234,
                ..Default::default()
            },
            ts: 1000,
            ..Default::default()
        };
        recorder.handle_event(event);
        event.cookie = 1;
        event.ts = 2000;
        recorder.handle_event(event);
        event.cookie = 2;
        event.ts = 3000;
        recorder.handle_event(event);
        let mut thread_uuids = HashMap::new();
        thread_uuids.insert(1234, 1);
        let packets = recorder.generate_trace(
            &HashMap::new(),
            &thread_uuids,
            &Arc::new(AtomicUsize::new(0)),
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
                    "event": "usdt:/path/to/file:provider:name"
                },
                {
                    "name": "event_name2",
                    "event": "usdt:/path/to/file:provider:name"
                },
                {
                    "name": "event_name3",
                    "event": "usdt:/path/to/file:provider:name"
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
        let mut event = probe_event {
            task: task_info {
                tgidpid: 1234,
                ..Default::default()
            },
            ts: 1000,
            ..Default::default()
        };
        recorder.handle_event(event);
        event.cookie = 1;
        event.ts = 2000;
        recorder.handle_event(event);
        event.cookie = 2;
        event.ts = 3000;
        recorder.handle_event(event);
        event.cookie = 0;
        event.ts = 4000;
        recorder.handle_event(event);
        event.cookie = 1;
        event.ts = 5000;
        recorder.handle_event(event);
        event.cookie = 2;
        event.ts = 6000;
        recorder.handle_event(event);
        let mut thread_uuids = HashMap::new();
        thread_uuids.insert(1234, 1);
        let packets = recorder.generate_trace(
            &HashMap::new(),
            &thread_uuids,
            &Arc::new(AtomicUsize::new(0)),
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

    #[test]
    fn test_uretprobe_packet() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "uretprobe_event",
                    "event": "uretprobe:/path/to/file:symbol"
                }
            ],
            "tracks": [
                {
                    "track_name": "uretprobe_track",
                    "instants": [
                      {
                        "event": "uretprobe_event"
                      }
                    ]
                }
            ]
        }
        "#;

        recorder.load_config_from_json(json, &mut rng).unwrap();
        let event = probe_event {
            task: task_info {
                tgidpid: 1234,
                ..Default::default()
            },
            ts: 1000,
            ..Default::default()
        };
        recorder.handle_event(event);
        let mut thread_uuids = HashMap::new();
        thread_uuids.insert(1234, 1);
        let packets = recorder.generate_trace(
            &HashMap::new(),
            &thread_uuids,
            &Arc::new(AtomicUsize::new(0)),
        );
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].track_descriptor().name(), "uretprobe_track");
        assert_eq!(packets[1].track_event().name(), "uretprobe:symbol");
    }

    #[test]
    fn test_uprobe_packet() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "uprobe_event",
                    "event": "uprobe:/path/to/file:symbol"
                }
            ],
            "tracks": [
                {
                    "track_name": "uprobe_track",
                    "instants": [
                      {
                        "event": "uprobe_event"
                      }
                    ]
                }
            ]
        }
        "#;

        recorder.load_config_from_json(json, &mut rng).unwrap();
        let event = probe_event {
            task: task_info {
                tgidpid: 1234,
                ..Default::default()
            },
            ts: 1000,
            ..Default::default()
        };
        recorder.handle_event(event);
        let mut thread_uuids = HashMap::new();
        thread_uuids.insert(1234, 1);
        let packets = recorder.generate_trace(
            &HashMap::new(),
            &thread_uuids,
            &Arc::new(AtomicUsize::new(0)),
        );
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].track_descriptor().name(), "uprobe_track");
        assert_eq!(packets[1].track_event().name(), "uprobe:symbol");
    }

    #[test]
    fn test_invalid_event_type() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let result = recorder.add_event_from_str("invalid:/path/to/file:provider:name", &mut rng);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Invalid event type: invalid"
        );
    }

    #[test]
    fn test_uprobe_variants() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "uprobe_event",
                    "event": "uprobe:/path/to/file:symbol"
                },
                {
                    "name": "uretprobe_event",
                    "event": "uretprobe:/path/to/file:symbol"
                },
                {
                    "name": "uretprobe_event_plus_offset",
                    "event": "uretprobe:/path/to/file:symbol+64"
                },
                {
                    "name": "uprobe_event_plus_offset",
                    "event": "uprobe:/path/to/file:symbol+64"
                }
            ],
            "tracks": []
        }
        "#;

        recorder.load_config_from_json(json, &mut rng).unwrap();
        assert_eq!(recorder.config_events.len(), 4);
        assert!(recorder.config_events.contains_key("uprobe_event"));
        assert!(recorder.config_events.contains_key("uretprobe_event"));
        assert!(recorder
            .config_events
            .contains_key("uretprobe_event_plus_offset"));
        assert!(recorder
            .config_events
            .contains_key("uprobe_event_plus_offset"));
        let event = recorder.config_events.get("uprobe_event").unwrap();
        assert!(matches!(event.event, EventProbe::UProbe(_)));
        assert_eq!(event.name, "uprobe_event");
        let event = recorder.config_events.get("uretprobe_event").unwrap();
        assert!(matches!(event.event, EventProbe::UProbe(_)));
        assert_eq!(event.name, "uretprobe_event");
        let event = recorder
            .config_events
            .get("uretprobe_event_plus_offset")
            .unwrap();
        assert!(matches!(event.event, EventProbe::UProbe(_)));
        let event = recorder
            .config_events
            .get("uprobe_event_plus_offset")
            .unwrap();
        assert!(matches!(event.event, EventProbe::UProbe(_)));
        assert_eq!(event.name, "uprobe_event_plus_offset");
    }

    #[test]
    fn test_uprobe_variants_from_str() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let result = recorder.add_event_from_str("uprobe:/path/to/file:symbol", &mut rng);
        assert!(result.is_ok());
        let result = recorder.add_event_from_str("uretprobe:/path/to/file:symbol1", &mut rng);
        assert!(result.is_ok());
        let result = recorder.add_event_from_str("uretprobe:/path/to/file:symbol2+64", &mut rng);
        assert!(result.is_ok());
        let result = recorder.add_event_from_str("uprobe:/path/to/file:symbol3+64", &mut rng);
        assert!(result.is_ok());

        assert_eq!(recorder.config_events.len(), 4);
        assert!(recorder.config_events.contains_key("symbol"));
        assert!(recorder.config_events.contains_key("symbol1"));
        assert!(recorder.config_events.contains_key("symbol2"));
        assert!(recorder.config_events.contains_key("symbol3"));
        let event = recorder.config_events.get("symbol").unwrap();
        assert!(matches!(event.event, EventProbe::UProbe(_)));
        assert_eq!(event.name, "symbol");
        assert_eq!(event.args.len(), 0);
        let event = recorder.config_events.get("symbol1").unwrap();
        assert!(matches!(event.event, EventProbe::UProbe(_)));
        assert_eq!(event.name, "symbol1");
        assert_eq!(event.args.len(), 0);
        let event = recorder.config_events.get("symbol2").unwrap();
        assert!(matches!(event.event, EventProbe::UProbe(_)));
        assert_eq!(event.name, "symbol2");
        assert_eq!(event.args.len(), 0);
        let event = recorder.config_events.get("symbol3").unwrap();
        assert!(matches!(event.event, EventProbe::UProbe(_)));
        assert_eq!(event.name, "symbol3");
        assert_eq!(event.args.len(), 0);
    }

    #[test]
    fn test_threshold_trigger() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "start_event",
                    "event": "usdt:/path/to/file:provider:name"
                },
                {
                    "name": "stop_event",
                    "event": "usdt:/path/to/file:provider:name"
                }
            ],
            "stop_triggers": {
                "thresholds": [
                  {
                    "start": "start_event",
                    "end": "stop_event",
                    "duration_us": 1000
                  }
                ]
            }
        }
        "#;

        recorder.load_config_from_json(json, &mut rng).unwrap();
        assert_eq!(recorder.start_triggers.len(), 1);
        assert_eq!(recorder.end_triggers.len(), 1);
        assert_eq!(recorder.stop_triggers.len(), 1);
    }

    #[test]
    fn test_threshold_trigger_invalid() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "start_event",
                    "event": "usdt:/path/to/file:provider:name"
                },
                {
                    "name": "stop_event",
                    "event": "usdt:/path/to/file:provider:name"
                }
            ],
            "stop_triggers": {
                "thresholds": [
                  {
                    "start": "invalid_start_event",
                    "end": "stop_event",
                    "duration_us": 1000
                  }
                ]
            }
        }
        "#;

        let result = recorder.load_config_from_json(json, &mut rng);
        assert!(result.is_err());
    }

    #[test]
    fn test_threshold_trigger_invalid_end() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "start_event",
                    "event": "usdt:/path/to/file:provider:name"
                },
                {
                    "name": "stop_event",
                    "event": "usdt:/path/to/file:provider:name"
                }
            ],
            "stop_triggers": {
                "thresholds": [
                  {
                    "start": "start_event",
                    "end": "invalid_stop_event",
                    "duration_us": 1000
                  }
                ]
            }
        }
        "#;

        let result = recorder.load_config_from_json(json, &mut rng);
        assert!(result.is_err());
    }

    #[test]
    fn test_instant_trigger() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "event_name",
                    "event": "usdt:/path/to/file:provider:name"
                }
            ],
            "stop_triggers": {
                "instants": [
                    {
                        "event": "event_name"
                    }
                ]
            }
        }
        "#;

        recorder.load_config_from_json(json, &mut rng).unwrap();
        assert_eq!(recorder.instant_triggers.len(), 1);
    }

    #[test]
    fn test_trip_threshold() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "start_event",
                    "event": "usdt:/path/to/file:provider:name"
                },
                {
                    "name": "stop_event",
                    "event": "usdt:/path/to/file:provider:name"
                }
            ],
            "stop_triggers": {
                "thresholds": [
                  {
                    "start": "start_event",
                    "end": "stop_event",
                    "duration_us": 1000
                  }
                ]
            }
        }
        "#;

        recorder.load_config_from_json(json, &mut rng).unwrap();
        let mut event = probe_event {
            task: task_info {
                tgidpid: 1234,
                ..Default::default()
            },
            ..Default::default()
        };
        let ret = recorder.maybe_trigger(&event);
        assert!(!ret, "Trip threshold should not be triggered yet");
        event.cookie = 1;
        event.ts = 2_000_000;
        let ret = recorder.maybe_trigger(&event);
        assert!(ret, "Trip threshold should be triggered");
    }

    #[test]
    fn test_no_trip_threshold() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "start_event",
                    "event": "usdt:/path/to/file:provider:name"
                },
                {
                    "name": "stop_event",
                    "event": "usdt:/path/to/file:provider:name"
                }
            ],
            "stop_triggers": {
                "thresholds": [
                  {
                    "start": "start_event",
                    "end": "stop_event",
                    "duration_us": 1000
                  }
                ]
            }
        }
        "#;

        recorder.load_config_from_json(json, &mut rng).unwrap();
        let mut event = probe_event {
            task: task_info {
                tgidpid: 1234,
                ..Default::default()
            },
            ..Default::default()
        };
        let ret = recorder.maybe_trigger(&event);
        assert!(!ret, "Trip threshold should not be triggered yet");
        event.cookie = 1;
        event.ts = 500_000; // Less than the threshold of 1000 microseconds
        let ret = recorder.maybe_trigger(&event);
        assert!(!ret, "Trip threshold should not be triggered");
    }

    #[test]
    fn test_trip_instant() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "event_name",
                    "event": "usdt:/path/to/file:provider:name"
                }
            ],
            "stop_triggers": {
                "instants": [
                    {
                        "event": "event_name"
                    }
                ]
            }
        }
        "#;

        recorder.load_config_from_json(json, &mut rng).unwrap();
        let event = probe_event {
            task: task_info {
                tgidpid: 1234,
                ..Default::default()
            },
            ts: 1000,
            ..Default::default()
        };
        let ret = recorder.maybe_trigger(&event);
        assert!(ret, "Instant trigger should be activated");
    }

    #[test]
    fn test_kprobe_packet() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "kprobe_event",
                    "event": "kprobe:symbol"
                }
            ],
            "tracks": [
                {
                    "track_name": "kprobe_track",
                    "instants": [
                      {
                        "event": "kprobe_event"
                      }
                    ]
                }
            ]
        }
        "#;

        recorder.load_config_from_json(json, &mut rng).unwrap();
        let event = probe_event {
            task: task_info {
                tgidpid: 1234,
                ..Default::default()
            },
            ts: 1000,
            ..Default::default()
        };
        recorder.handle_event(event);
        let mut thread_uuids = HashMap::new();
        thread_uuids.insert(1234, 1);
        let packets = recorder.generate_trace(
            &HashMap::new(),
            &thread_uuids,
            &Arc::new(AtomicUsize::new(0)),
        );
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].track_descriptor().name(), "kprobe_track");
        assert_eq!(packets[1].track_event().name(), "kprobe:symbol");
    }

    #[test]
    fn test_kretprobe_packet() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "kretprobe_event",
                    "event": "kretprobe:symbol"
                }
            ],
            "tracks": [
                {
                    "track_name": "kretprobe_track",
                    "instants": [
                      {
                        "event": "kretprobe_event"
                      }
                    ]
                }
            ]
        }
        "#;

        recorder.load_config_from_json(json, &mut rng).unwrap();
        let event = probe_event {
            task: task_info {
                tgidpid: 1234,
                ..Default::default()
            },
            ts: 1000,
            ..Default::default()
        };
        recorder.handle_event(event);
        let mut thread_uuids = HashMap::new();
        thread_uuids.insert(1234, 1);
        let packets = recorder.generate_trace(
            &HashMap::new(),
            &thread_uuids,
            &Arc::new(AtomicUsize::new(0)),
        );
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].track_descriptor().name(), "kretprobe_track");
        assert_eq!(packets[1].track_event().name(), "kretprobe:symbol");
    }

    #[test]
    fn test_tracepoint_packet() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "tracepoint_event",
                    "event": "tracepoint:category:name"
                }
            ],
            "tracks": [
                {
                    "track_name": "tracepoint_track",
                    "instants": [
                      {
                        "event": "tracepoint_event"
                      }
                    ]
                }
            ]
        }
        "#;

        recorder.load_config_from_json(json, &mut rng).unwrap();
        let event = probe_event {
            task: task_info {
                tgidpid: 1234,
                ..Default::default()
            },
            ts: 1000,
            ..Default::default()
        };
        recorder.handle_event(event);
        let mut thread_uuids = HashMap::new();
        thread_uuids.insert(1234, 1);
        let packets = recorder.generate_trace(
            &HashMap::new(),
            &thread_uuids,
            &Arc::new(AtomicUsize::new(0)),
        );
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].track_descriptor().name(), "tracepoint_track");
        assert_eq!(packets[1].track_event().name(), "tracepoint:category:name");
    }

    #[test]
    fn test_event_with_args() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "event_with_string_arg",
                    "event": "usdt:/path/to/file:provider:name",
                    "args": [
                      {
                        "arg_index": 0,
                        "arg_type": "string",
                        "arg_name": "filename"
                      }
                    ]
                },
                {
                    "name": "event_with_long_arg",
                    "event": "usdt:/path/to/file:provider:name",
                    "args": [
                      {
                        "arg_index": 1,
                        "arg_type": "long",
                        "arg_name": "size"
                      }
                    ]
                }
            ],
            "tracks": []
        }
        "#;

        let result = recorder.load_config_from_json(json, &mut rng);
        assert!(result.is_ok());
        assert_eq!(recorder.config_events.len(), 2);
        let event = recorder.config_events.get("event_with_string_arg").unwrap();
        assert_eq!(event.name, "event_with_string_arg");
        assert_eq!(event.args.len(), 1);
        assert_eq!(event.args[0].arg_index, 0);
        assert!(matches!(event.args[0].arg_type, EventKeyType::String));
        assert_eq!(event.args[0].arg_name, "filename");
        let event = recorder.config_events.get("event_with_long_arg").unwrap();
        assert_eq!(event.args.len(), 1);
        assert_eq!(event.args[0].arg_index, 1);
        assert!(matches!(event.args[0].arg_type, EventKeyType::Long));
        assert_eq!(event.args[0].arg_name, "size");
    }

    #[test]
    fn test_event_bad_arg_type() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "event_with_bad_arg",
                    "event": "usdt:/path/to/file:provider:name",
                    "args": [
                      {
                        "arg_index": 0,
                        "arg_type": "invalid_type",
                        "arg_name": "test"
                      }
                    ]
                }
            ],
            "tracks": []
        }
        "#;

        let result = recorder.load_config_from_json(json, &mut rng);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Invalid arg type: invalid_type"
        );
    }

    #[test]
    fn test_event_with_multiple_args() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "event_with_multiple_args",
                    "event": "usdt:/path/to/file:provider:name",
                    "args": [
                      {
                        "arg_index": 0,
                        "arg_type": "string",
                        "arg_name": "filename"
                      },
                      {
                        "arg_index": 1,
                        "arg_type": "long",
                        "arg_name": "size"
                      },
                      {
                        "arg_index": 2,
                        "arg_type": "long",
                        "arg_name": "offset"
                      }
                    ]
                }
            ],
            "tracks": []
        }
        "#;

        let result = recorder.load_config_from_json(json, &mut rng);
        assert!(result.is_ok());
        assert_eq!(recorder.config_events.len(), 1);
        let event = recorder
            .config_events
            .get("event_with_multiple_args")
            .unwrap();
        assert_eq!(event.args.len(), 3);
        assert_eq!(event.args[0].arg_index, 0);
        assert!(matches!(event.args[0].arg_type, EventKeyType::String));
        assert_eq!(event.args[0].arg_name, "filename");
        assert_eq!(event.args[1].arg_index, 1);
        assert!(matches!(event.args[1].arg_type, EventKeyType::Long));
        assert_eq!(event.args[1].arg_name, "size");
        assert_eq!(event.args[2].arg_index, 2);
        assert!(matches!(event.args[2].arg_type, EventKeyType::Long));
        assert_eq!(event.args[2].arg_name, "offset");
    }

    #[test]
    fn test_event_with_retval() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "uretprobe_event",
                    "event": "uretprobe:/path/to/file:symbol",
                    "args": [
                      {
                        "arg_type": "retval",
                        "arg_name": "return_value"
                      }
                    ]
                },
                {
                    "name": "kretprobe_event",
                    "event": "kretprobe:symbol",
                    "args": [
                      {
                        "arg_type": "retval",
                        "arg_name": "result"
                      }
                    ]
                }
            ],
            "tracks": []
        }
        "#;

        let result = recorder.load_config_from_json(json, &mut rng);
        assert!(result.is_ok());
        let event = recorder.config_events.get("uretprobe_event").unwrap();
        assert_eq!(event.args.len(), 1);
        assert!(matches!(event.args[0].arg_type, EventKeyType::Retval));
        assert_eq!(event.args[0].arg_name, "return_value");
        let event = recorder.config_events.get("kretprobe_event").unwrap();
        assert_eq!(event.args.len(), 1);
        assert!(matches!(event.args[0].arg_type, EventKeyType::Retval));
        assert_eq!(event.args[0].arg_name, "result");
    }

    #[test]
    fn test_event_with_retval_no_arg_index() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "uretprobe_event",
                    "event": "uretprobe:/path/to/file:symbol",
                    "args": [
                      {
                        "arg_type": "retval",
                        "arg_name": "return_value"
                      }
                    ]
                }
            ],
            "tracks": []
        }
        "#;

        let result = recorder.load_config_from_json(json, &mut rng);
        assert!(result.is_ok());
        let event = recorder.config_events.get("uretprobe_event").unwrap();
        assert_eq!(event.args.len(), 1);
        assert!(matches!(event.args[0].arg_type, EventKeyType::Retval));
        assert_eq!(event.args[0].arg_name, "return_value");
        assert_eq!(event.args[0].arg_index, 0);
    }

    #[test]
    fn test_retval_with_nonzero_arg_index_rejected() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "uretprobe_event",
                    "event": "uretprobe:/path/to/file:symbol",
                    "args": [
                      {
                        "arg_index": 1,
                        "arg_type": "retval",
                        "arg_name": "return_value"
                      }
                    ]
                }
            ],
            "tracks": []
        }
        "#;

        let result = recorder.load_config_from_json(json, &mut rng);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "arg_index must be 0 or omitted for retval type in event: uretprobe_event"
        );
    }

    #[test]
    fn test_retval_invalid_on_uprobe() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "uprobe_event",
                    "event": "uprobe:/path/to/file:symbol",
                    "args": [
                      {
                        "arg_index": 0,
                        "arg_type": "retval",
                        "arg_name": "return_value"
                      }
                    ]
                }
            ],
            "tracks": []
        }
        "#;

        let result = recorder.load_config_from_json(json, &mut rng);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "retval arg type requires uretprobe, not uprobe: uprobe_event"
        );
    }

    #[test]
    fn test_retval_invalid_on_kprobe() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "kprobe_event",
                    "event": "kprobe:symbol",
                    "args": [
                      {
                        "arg_index": 0,
                        "arg_type": "retval",
                        "arg_name": "return_value"
                      }
                    ]
                }
            ],
            "tracks": []
        }
        "#;

        let result = recorder.load_config_from_json(json, &mut rng);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "retval arg type requires kretprobe, not kprobe: kprobe_event"
        );
    }

    #[test]
    fn test_retval_invalid_on_usdt() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "usdt_event",
                    "event": "usdt:/path/to/file:provider:name",
                    "args": [
                      {
                        "arg_index": 0,
                        "arg_type": "retval",
                        "arg_name": "return_value"
                      }
                    ]
                }
            ],
            "tracks": []
        }
        "#;

        let result = recorder.load_config_from_json(json, &mut rng);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "retval arg type is not supported for usdt probes: usdt_event"
        );
    }

    #[test]
    fn test_retval_invalid_on_tracepoint() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "tracepoint_event",
                    "event": "tracepoint:category:name",
                    "args": [
                      {
                        "arg_index": 0,
                        "arg_type": "retval",
                        "arg_name": "return_value"
                      }
                    ]
                }
            ],
            "tracks": []
        }
        "#;

        let result = recorder.load_config_from_json(json, &mut rng);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "retval arg type is not supported for tracepoint events: tracepoint_event"
        );
    }

    #[test]
    fn test_event_too_many_args() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "event_with_too_many_args",
                    "event": "usdt:/path/to/file:provider:name",
                    "args": [
                      {
                        "arg_index": 0,
                        "arg_type": "string",
                        "arg_name": "file"
                      },
                      {
                        "arg_index": 1,
                        "arg_type": "long",
                        "arg_name": "size"
                      },
                      {
                        "arg_index": 2,
                        "arg_type": "string",
                        "arg_name": "extra"
                      },
                      {
                        "arg_index": 3,
                        "arg_type": "long",
                        "arg_name": "fourth"
                      },
                      {
                        "arg_index": 4,
                        "arg_type": "long",
                        "arg_name": "fifth"
                      }
                    ]
                }
            ],
            "tracks": []
        }
        "#;

        let result = recorder.load_config_from_json(json, &mut rng);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Maximum 4 args allowed per event, got 5 for event: event_with_too_many_args"
        );
    }

    #[test]
    fn test_event_percpu() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "event_percpu",
                    "event": "usdt:/path/to/file:provider:name",
                    "percpu": true
                }
            ],
            "tracks": [
                {
                    "track_name": "percpu_track",
                    "instants": [
                      {
                        "event": "event_percpu"
                      }
                    ]
                }
            ]
        }
        "#;

        let result = recorder.load_config_from_json(json, &mut rng);
        assert!(result.is_ok());
        assert_eq!(recorder.config_events.len(), 1);
        let event = recorder.config_events.get("event_percpu").unwrap();
        assert!(event.percpu);

        let event = probe_event {
            task: task_info {
                tgidpid: 1234,
                ..Default::default()
            },
            ts: 1000,
            cpu: 1,
            ..Default::default()
        };
        recorder.handle_event(event);
        assert!(recorder.cpu_events.contains_key(&1));
        let packets = recorder.generate_trace(
            &HashMap::new(),
            &HashMap::new(),
            &Arc::new(AtomicUsize::new(0)),
        );
        assert_eq!(packets.len(), 3);
        assert_eq!(packets[0].track_descriptor().name(), "percpu_track");
        assert_eq!(packets[1].track_descriptor().name(), "CPU 1");
        assert_eq!(
            packets[0].track_descriptor().uuid(),
            packets[1].track_descriptor().parent_uuid()
        );
        assert_eq!(
            packets[2].track_event().name(),
            "usdt:/path/to/file:provider:name"
        );
        assert_eq!(packets[2].track_event().type_(), Type::TYPE_INSTANT);
        assert_eq!(packets[2].timestamp(), 1000);
        assert_eq!(
            packets[2].track_event().track_uuid(),
            packets[1].track_descriptor().uuid()
        );
    }

    #[test]
    fn test_stack_field_true() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "event_with_stack",
                    "event": "usdt:/path/to/file:provider:name",
                    "stack": true
                }
            ],
            "tracks": []
        }
        "#;

        let result = recorder.load_config_from_json(json, &mut rng);
        assert!(result.is_ok());
        assert_eq!(recorder.config_events.len(), 1);
        let event = recorder.config_events.get("event_with_stack").unwrap();
        assert!(event.stack);
    }

    #[test]
    fn test_stack_field_false() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "event_without_stack",
                    "event": "usdt:/path/to/file:provider:name",
                    "stack": false
                }
            ],
            "tracks": []
        }
        "#;

        let result = recorder.load_config_from_json(json, &mut rng);
        assert!(result.is_ok());
        assert_eq!(recorder.config_events.len(), 1);
        let event = recorder.config_events.get("event_without_stack").unwrap();
        assert!(!event.stack);
    }

    #[test]
    fn test_stack_field_default() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "event_default_stack",
                    "event": "usdt:/path/to/file:provider:name"
                }
            ],
            "tracks": []
        }
        "#;

        let result = recorder.load_config_from_json(json, &mut rng);
        assert!(result.is_ok());
        assert_eq!(recorder.config_events.len(), 1);
        let event = recorder.config_events.get("event_default_stack").unwrap();
        assert!(!event.stack);
    }

    #[test]
    fn test_stack_field_with_args() {
        let mut rng = StepRng::new(0, 1);
        let mut recorder = SystingProbeRecorder::default();
        let json = r#"
        {
            "events": [
                {
                    "name": "event_with_stack_and_args",
                    "event": "uprobe:/path/to/file:symbol",
                    "stack": true,
                    "args": [
                        {
                            "arg_index": 0,
                            "arg_type": "long",
                            "arg_name": "arg1"
                        }
                    ]
                }
            ],
            "tracks": []
        }
        "#;

        let result = recorder.load_config_from_json(json, &mut rng);
        assert!(result.is_ok());
        assert_eq!(recorder.config_events.len(), 1);
        let event = recorder
            .config_events
            .get("event_with_stack_and_args")
            .unwrap();
        assert!(event.stack);
        assert_eq!(event.args.len(), 1);
    }

    fn create_test_task_info(tgid: u32, pid: u32) -> task_info {
        task_info {
            tgidpid: ((tgid as u64) << 32) | (pid as u64),
            comm: [0; 16],
        }
    }

    fn create_syscall_enter_event(tgid: u32, pid: u32, ts: u64, syscall_nr: u64) -> probe_event {
        let mut event = probe_event {
            task: create_test_task_info(tgid, pid),
            ts,
            cookie: SYS_ENTER_COOKIE,
            num_args: 1,
            ..Default::default()
        };
        event.args[0].r#type = crate::systing::types::arg_type::ARG_LONG;
        event.args[0].size = 8;
        let bytes = syscall_nr.to_ne_bytes();
        event.args[0].value[..8].copy_from_slice(&bytes);
        event
    }

    fn create_syscall_exit_event(
        tgid: u32,
        pid: u32,
        ts: u64,
        syscall_nr: u64,
        ret: u64,
    ) -> probe_event {
        let mut event = probe_event {
            task: create_test_task_info(tgid, pid),
            ts,
            cookie: SYS_ENTER_COOKIE + 1,
            num_args: 2,
            ..Default::default()
        };
        event.args[0].r#type = crate::systing::types::arg_type::ARG_LONG;
        event.args[0].size = 8;
        let bytes = syscall_nr.to_ne_bytes();
        event.args[0].value[..8].copy_from_slice(&bytes);
        event.args[1].r#type = crate::systing::types::arg_type::ARG_LONG;
        event.args[1].size = 8;
        let ret_bytes = ret.to_ne_bytes();
        event.args[1].value[..8].copy_from_slice(&ret_bytes);
        event
    }

    #[test]
    fn test_syscall_sys_enter() {
        let mut recorder = SystingProbeRecorder::default();
        let event = create_syscall_enter_event(100, 101, 1000, 1);

        recorder.handle_event(event);

        let tgidpid = (100u64 << 32) | 101u64;
        assert_eq!(recorder.pending_syscalls.len(), 1);
        assert!(recorder.pending_syscalls.contains_key(&tgidpid));
        assert_eq!(recorder.pending_syscalls[&tgidpid].len(), 1);
        assert!(recorder.pending_syscalls[&tgidpid].contains_key(&1));
        assert!(recorder.completed_syscalls.is_empty());
    }

    #[test]
    fn test_syscall_sys_exit_without_enter() {
        let mut recorder = SystingProbeRecorder::default();
        let event = create_syscall_exit_event(100, 101, 2000, 1, 42);

        recorder.handle_event(event);

        assert!(recorder.pending_syscalls.is_empty());
        assert!(recorder.completed_syscalls.is_empty());
    }

    #[test]
    fn test_syscall_complete_pair() {
        let mut recorder = SystingProbeRecorder::default();
        let enter = create_syscall_enter_event(100, 101, 1000, 1);
        let exit = create_syscall_exit_event(100, 101, 2000, 1, 42);

        recorder.handle_event(enter);
        recorder.handle_event(exit);

        let tgidpid = (100u64 << 32) | 101u64;
        assert_eq!(recorder.pending_syscalls.len(), 1);
        assert!(recorder.pending_syscalls[&tgidpid].is_empty());
        assert_eq!(recorder.completed_syscalls.len(), 1);
        assert_eq!(recorder.completed_syscalls[&tgidpid].len(), 1);
        assert_eq!(recorder.completed_syscalls[&tgidpid][0], (1000, 2000, 1));
    }

    #[test]
    fn test_syscall_multiple_threads() {
        let mut recorder = SystingProbeRecorder::default();

        let enter1 = create_syscall_enter_event(100, 101, 1000, 1);
        let enter2 = create_syscall_enter_event(200, 201, 1500, 2);
        let exit1 = create_syscall_exit_event(100, 101, 2000, 1, 10);
        let exit2 = create_syscall_exit_event(200, 201, 2500, 2, 20);

        recorder.handle_event(enter1);
        recorder.handle_event(enter2);
        recorder.handle_event(exit1);
        recorder.handle_event(exit2);

        let tgidpid1 = (100u64 << 32) | 101u64;
        let tgidpid2 = (200u64 << 32) | 201u64;
        assert_eq!(recorder.completed_syscalls.len(), 2);
        assert_eq!(recorder.completed_syscalls[&tgidpid1].len(), 1);
        assert_eq!(recorder.completed_syscalls[&tgidpid2].len(), 1);
        assert_eq!(recorder.completed_syscalls[&tgidpid1][0], (1000, 2000, 1));
        assert_eq!(recorder.completed_syscalls[&tgidpid2][0], (1500, 2500, 2));
    }

    #[test]
    fn test_syscall_generate_trace_packets() {
        let mut recorder = SystingProbeRecorder::default();
        let mut thread_uuids = HashMap::new();
        thread_uuids.insert(101, 500);
        let pid_uuids: HashMap<i32, u64> = HashMap::new();
        let id_counter = Arc::new(AtomicUsize::new(1000));

        let enter = create_syscall_enter_event(100, 101, 1000, 1);
        let exit = create_syscall_exit_event(100, 101, 2000, 1, 42);

        recorder.handle_event(enter);
        recorder.handle_event(exit);

        let packets = recorder.generate_trace(&pid_uuids, &thread_uuids, &id_counter);

        let syscall_packets: Vec<_> = packets
            .iter()
            .filter(|p| p.has_track_descriptor() && p.track_descriptor().name() == "Syscalls")
            .collect();
        assert_eq!(syscall_packets.len(), 1);

        let slice_packets: Vec<_> = packets.iter().filter(|p| p.has_track_event()).collect();
        assert!(slice_packets.len() >= 2);

        let interned_packets: Vec<_> = packets
            .iter()
            .filter(|p| p.interned_data.is_some())
            .collect();
        assert_eq!(interned_packets.len(), 1);

        assert!(recorder.completed_syscalls.is_empty());
        assert!(recorder.pending_syscalls.is_empty());
    }

    #[test]
    fn test_syscall_name_interning() {
        let mut recorder = SystingProbeRecorder::default();
        let id_counter = Arc::new(AtomicUsize::new(1000));

        let iid1 = recorder.get_or_create_syscall_name_iid(1, &id_counter);
        let iid2 = recorder.get_or_create_syscall_name_iid(1, &id_counter);
        let iid3 = recorder.get_or_create_syscall_name_iid(2, &id_counter);

        assert_eq!(iid1, iid2);
        assert_ne!(iid1, iid3);
        assert_eq!(recorder.syscall_iids.len(), 2);
    }
}
