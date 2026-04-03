mod config;
mod probe;
mod writer;

use config::ThresholdStopTrigger;

#[cfg(test)]
mod tests;

pub use probe::{
    EventKey, EventKeyType, EventProbe, EventScope, KProbeEvent, SystingEvent, TracepointEvent,
    UProbeEvent, UsdtProbeEvent,
};

use std::collections::{HashMap, HashSet};
use std::ffi::CStr;
use std::sync::Arc;
use std::time::Duration;

use crate::record::RecordCollector;
use crate::ringbuf::RingBuffer;
use crate::systing_core::types::probe_event;
use crate::systing_core::SystingRecordEvent;
use crate::trace::{ArgRecord, InstantArgRecord, InstantRecord, SliceRecord, TrackRecord};
use crate::utid::UtidGenerator;

use anyhow::Result;
use plain::Plain;

const SYS_ENTER_COOKIE: u64 = 0xFFFFFFFFFFFFFFFE;
const SYSCALLS_TRACK_NAME: &str = "syscalls";

enum ArgValue {
    String(String),
    Long(u64),
}

/// Convert ArgValue to record fields (key, int_value, string_value).
fn convert_arg(arg: &(String, ArgValue)) -> (String, Option<i64>, Option<String>) {
    match &arg.1 {
        ArgValue::String(s) => (arg.0.clone(), None, Some(s.clone())),
        ArgValue::Long(v) => (arg.0.clone(), Some(*v as i64), None),
    }
}

/// Get the name for a syscall number.
fn syscall_name(nr: u64) -> String {
    use syscalls::Sysno;
    Sysno::new(nr as usize)
        .map(|sysno| sysno.name().to_string())
        .unwrap_or_else(|| format!("syscall_{nr}"))
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

/// Key for track ID caching during streaming.
#[derive(Hash, Eq, PartialEq, Clone)]
enum TrackCacheKey {
    Thread { tgidpid: u64, track_name: String },
    Cpu { cpu: u32, track_name: String },
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

    // Streaming mode support
    streaming_collector: Option<Box<dyn RecordCollector + Send>>,
    streaming_enabled: bool, // Track if streaming was ever enabled (survives finish())
    track_id_counter: i64,
    slice_id_counter: i64,
    instant_id_counter: i64,
    track_cache: HashMap<TrackCacheKey, i64>,

    // Shared utid generator for consistent thread IDs across all recorders
    utid_generator: Arc<UtidGenerator>,
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
            let config_idx = i;
            if config_idx >= systing_event.args.len() {
                break;
            }

            let bpf_arg = &event.args[i];
            let event_key = &systing_event.args[config_idx];

            match bpf_arg.r#type {
                crate::systing_core::types::arg_type::ARG_LONG => {
                    let mut bytes: [u8; 8] = [0; 8];
                    let _ = bytes.copy_from_bytes(&bpf_arg.value[..8]);
                    let val = u64::from_ne_bytes(bytes);
                    arg_data.push((event_key.arg_name.clone(), ArgValue::Long(val)));
                }
                crate::systing_core::types::arg_type::ARG_RETVAL => {
                    let mut bytes: [u8; 8] = [0; 8];
                    let _ = bytes.copy_from_bytes(&bpf_arg.value[..8]);
                    let val = u64::from_ne_bytes(bytes);
                    arg_data.push((event_key.arg_name.clone(), ArgValue::Long(val)));
                }
                crate::systing_core::types::arg_type::ARG_STRING => {
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
        let scope = systing_event.scope;
        match scope {
            EventScope::Cpu => self.handle_cpu_event(event, arg_data),
            EventScope::Thread | EventScope::Process => {
                self.handle_process_event(event, arg_data, scope)
            }
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
    /// Create a new SystingProbeRecorder with the given utid generator.
    pub fn new(utid_generator: Arc<UtidGenerator>) -> Self {
        Self {
            utid_generator,
            ..Default::default()
        }
    }

    /// Set the streaming collector for Parquet output during recording.
    pub fn set_streaming_collector(&mut self, collector: Box<dyn RecordCollector + Send>) {
        self.streaming_collector = Some(collector);
        self.streaming_enabled = true;
    }

    /// Check if streaming mode is currently active (collector present).
    pub fn is_streaming(&self) -> bool {
        self.streaming_collector.is_some()
    }

    /// Get or create a track ID, caching to avoid duplicates.
    fn get_or_create_track(
        &mut self,
        key: TrackCacheKey,
        collector: &mut dyn RecordCollector,
    ) -> Result<i64> {
        if let Some(&id) = self.track_cache.get(&key) {
            return Ok(id);
        }

        self.track_id_counter += 1;
        let track_id = self.track_id_counter;

        let name = match &key {
            TrackCacheKey::Thread { track_name, .. } => track_name.clone(),
            TrackCacheKey::Cpu { cpu, track_name } => format!("{track_name} CPU {cpu}"),
        };

        collector.add_track(TrackRecord {
            id: track_id,
            name,
            parent_id: None,
        })?;

        self.track_cache.insert(key, track_id);
        Ok(track_id)
    }

    /// Finish streaming and return the collector.
    /// Incomplete events (outstanding_ranges, pending_syscalls) are discarded,
    /// matching current write_records() behavior.
    pub fn finish(&mut self) -> Result<Option<Box<dyn RecordCollector + Send>>> {
        if let Some(mut collector) = self.streaming_collector.take() {
            collector.flush()?;
            Ok(Some(collector))
        } else {
            Ok(None)
        }
    }

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
                // Discard syscalls with out-of-order timestamps.
                if event.ts < enter_ts {
                    return;
                }

                // Stream the completed syscall if streaming is enabled
                if let Some(mut collector) = self.streaming_collector.take() {
                    let key = TrackCacheKey::Thread {
                        tgidpid,
                        track_name: SYSCALLS_TRACK_NAME.to_string(),
                    };
                    if let Ok(track_id) = self.get_or_create_track(key, &mut *collector) {
                        self.slice_id_counter += 1;
                        let slice_id = self.slice_id_counter;

                        // Get consistent utid from shared generator
                        let tid = tgidpid as i32;
                        let utid = Some(self.utid_generator.get_or_create_utid(tid));

                        if let Err(e) = collector.add_slice(SliceRecord {
                            id: slice_id,
                            ts: enter_ts as i64,
                            dur: (event.ts - enter_ts) as i64,
                            track_id,
                            utid,
                            name: syscall_name(syscall_nr),
                            category: Some("syscall".to_string()),
                            depth: 0,
                        }) {
                            eprintln!("Warning: Failed to stream syscall slice: {e}");
                        }

                        if let Err(e) = collector.add_arg(ArgRecord {
                            slice_id,
                            key: "nr".to_string(),
                            int_value: Some(syscall_nr as i64),
                            string_value: None,
                            real_value: None,
                        }) {
                            eprintln!("Warning: Failed to stream syscall arg: {e}");
                        }
                    }
                    self.streaming_collector = Some(collector);
                } else {
                    // Non-streaming path: store for batch write
                    self.completed_syscalls
                        .entry(tgidpid)
                        .or_default()
                        .push((enter_ts, event.ts, syscall_nr));
                }
            }
        }
    }

    fn handle_cpu_event(&mut self, event: probe_event, arg_data: Vec<(String, ArgValue)>) {
        // Clone data we need from systing_event early to avoid borrow conflicts
        let systing_event = self.cookies.get(&event.cookie).unwrap();
        let systing_event_name = systing_event.name.clone();
        let event_display_name = format!("{systing_event}");

        // If this is an instant event just add it to the list of events
        if self.instant_events.contains_key(&systing_event_name) {
            let instant_track = self
                .instant_events
                .get(&systing_event_name)
                .unwrap()
                .clone();

            // Stream if enabled
            if let Some(mut collector) = self.streaming_collector.take() {
                let key = TrackCacheKey::Cpu {
                    cpu: event.cpu,
                    track_name: instant_track,
                };
                if let Ok(track_id) = self.get_or_create_track(key, &mut *collector) {
                    self.instant_id_counter += 1;
                    let instant_id = self.instant_id_counter;

                    if let Err(e) = collector.add_instant(InstantRecord {
                        id: instant_id,
                        ts: event.ts as i64,
                        track_id,
                        utid: None,
                        name: event_display_name,
                        category: None,
                    }) {
                        eprintln!("Warning: Failed to stream CPU instant: {e}");
                    }

                    for arg in &arg_data {
                        let (key, int_value, string_value) = convert_arg(arg);
                        if let Err(e) = collector.add_instant_arg(InstantArgRecord {
                            instant_id,
                            key,
                            int_value,
                            string_value,
                            real_value: None,
                        }) {
                            eprintln!("Warning: Failed to stream CPU instant arg: {e}");
                        }
                    }
                }
                self.streaming_collector = Some(collector);
            } else {
                // Non-streaming path
                let entry = self.cpu_events.entry(event.cpu).or_default();
                let instant_track = self.instant_events.get(&systing_event_name).unwrap();
                let entry = entry.entry(instant_track.clone()).or_default();
                entry.push(TrackInstant {
                    ts: event.ts,
                    name: event_display_name,
                    args: arg_data,
                });
            }
            return;
        }

        // First check to see if this is an end event, since we can have the same event for a start
        // event and an end event
        if let Some(range_name) = self.stop_events.get(&systing_event_name) {
            if let Some(ranges) = self.outstanding_cpu_ranges.get_mut(&event.cpu) {
                if let Some(mut range) = ranges.remove(range_name) {
                    let track_name = self.ranges.get(range_name).unwrap().clone();
                    range.end = event.ts;

                    // Discard ranges with out-of-order timestamps (can happen
                    // across CPUs with skewed TSC values).
                    if range.end >= range.start {
                        // Stream if enabled
                        if let Some(mut collector) = self.streaming_collector.take() {
                            let key = TrackCacheKey::Cpu {
                                cpu: event.cpu,
                                track_name: track_name.clone(),
                            };
                            if let Ok(track_id) = self.get_or_create_track(key, &mut *collector) {
                                self.slice_id_counter += 1;
                                let slice_id = self.slice_id_counter;

                                if let Err(e) = collector.add_slice(SliceRecord {
                                    id: slice_id,
                                    ts: range.start as i64,
                                    dur: (range.end - range.start) as i64,
                                    track_id,
                                    utid: None,
                                    name: range.range_name.clone(),
                                    category: None,
                                    depth: 0,
                                }) {
                                    eprintln!("Warning: Failed to stream CPU range slice: {e}");
                                }

                                for arg in &range.args {
                                    let (key, int_value, string_value) = convert_arg(arg);
                                    if let Err(e) = collector.add_arg(ArgRecord {
                                        slice_id,
                                        key,
                                        int_value,
                                        string_value,
                                        real_value: None,
                                    }) {
                                        eprintln!("Warning: Failed to stream CPU range arg: {e}");
                                    }
                                }
                            }
                            self.streaming_collector = Some(collector);
                        } else {
                            // Non-streaming path
                            let track_hash = self.cpu_ranges.entry(event.cpu).or_default();
                            let entry = track_hash.entry(track_name).or_default();
                            entry.push(range);
                        }
                    }
                }
            }
        }

        // Now handle the start event case
        if let Some(range_name) = self.start_events.get(&systing_event_name) {
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

    fn handle_process_event(
        &mut self,
        event: probe_event,
        arg_data: Vec<(String, ArgValue)>,
        scope: EventScope,
    ) {
        // Clone data we need from systing_event early to avoid borrow conflicts
        let systing_event = self.cookies.get(&event.cookie).unwrap();
        let systing_event_name = systing_event.name.clone();
        let event_display_name = format!("{systing_event}");

        // If this is an instant event just add it to the list of events
        if self.instant_events.contains_key(&systing_event_name) {
            let instant_track = self
                .instant_events
                .get(&systing_event_name)
                .unwrap()
                .clone();

            // Stream if enabled
            if let Some(mut collector) = self.streaming_collector.take() {
                let key = TrackCacheKey::Thread {
                    tgidpid: event.task.tgidpid,
                    track_name: instant_track,
                };
                if let Ok(track_id) = self.get_or_create_track(key, &mut *collector) {
                    self.instant_id_counter += 1;
                    let instant_id = self.instant_id_counter;
                    // Get consistent utid from shared generator
                    let tid = event.task.tgidpid as i32;
                    let utid = Some(self.utid_generator.get_or_create_utid(tid));

                    if let Err(e) = collector.add_instant(InstantRecord {
                        id: instant_id,
                        ts: event.ts as i64,
                        track_id,
                        utid,
                        name: event_display_name,
                        category: None,
                    }) {
                        eprintln!("Warning: Failed to stream instant: {e}");
                    }

                    for arg in &arg_data {
                        let (key, int_value, string_value) = convert_arg(arg);
                        if let Err(e) = collector.add_instant_arg(InstantArgRecord {
                            instant_id,
                            key,
                            int_value,
                            string_value,
                            real_value: None,
                        }) {
                            eprintln!("Warning: Failed to stream instant arg: {e}");
                        }
                    }
                }
                self.streaming_collector = Some(collector);
            } else {
                // Non-streaming path
                let entry = self.events.entry(event.task.tgidpid).or_default();
                let instant_track = self.instant_events.get(&systing_event_name).unwrap();
                let entry = entry.entry(instant_track.clone()).or_default();
                entry.push(TrackInstant {
                    ts: event.ts,
                    name: event_display_name,
                    args: arg_data,
                });
            }
            return;
        }

        // Use TGID (process ID) as the range key for process-scoped events, allowing
        // start/end matching when async tasks migrate between threads. For thread-scoped
        // events use the full TGIDPID.
        let range_key = match scope {
            EventScope::Process => event.task.tgidpid >> 32,
            EventScope::Thread | EventScope::Cpu => event.task.tgidpid,
        };

        // First check to see if this is an end event, since we can have the same event for a start
        // event and an end event
        if let Some(range_name) = self.stop_events.get(&systing_event_name) {
            let lookup_key = range_name.to_string();
            if let Some(ranges) = self.outstanding_ranges.get_mut(&range_key) {
                if let Some(mut range) = ranges.remove(&lookup_key) {
                    let track_name = self.ranges.get(range_name).unwrap().clone();
                    range.end = event.ts;

                    // Discard ranges with out-of-order timestamps (can happen
                    // across CPUs with skewed TSC values).
                    if range.end >= range.start {
                        // Stream if enabled (thread that receives END owns the track)
                        if let Some(mut collector) = self.streaming_collector.take() {
                            let key = TrackCacheKey::Thread {
                                tgidpid: event.task.tgidpid,
                                track_name: track_name.clone(),
                            };
                            if let Ok(track_id) = self.get_or_create_track(key, &mut *collector) {
                                self.slice_id_counter += 1;
                                let slice_id = self.slice_id_counter;
                                // Get consistent utid from shared generator
                                let tid = event.task.tgidpid as i32;
                                let utid = Some(self.utid_generator.get_or_create_utid(tid));

                                if let Err(e) = collector.add_slice(SliceRecord {
                                    id: slice_id,
                                    ts: range.start as i64,
                                    dur: (range.end - range.start) as i64,
                                    track_id,
                                    utid,
                                    name: range.range_name.clone(),
                                    category: None,
                                    depth: 0,
                                }) {
                                    eprintln!("Warning: Failed to stream range slice: {e}");
                                }

                                for arg in &range.args {
                                    let (key, int_value, string_value) = convert_arg(arg);
                                    if let Err(e) = collector.add_arg(ArgRecord {
                                        slice_id,
                                        key,
                                        int_value,
                                        string_value,
                                        real_value: None,
                                    }) {
                                        eprintln!("Warning: Failed to stream range arg: {e}");
                                    }
                                }
                            }
                            self.streaming_collector = Some(collector);
                        } else {
                            // Non-streaming path
                            let track_hash =
                                self.recorded_ranges.entry(event.task.tgidpid).or_default();
                            let entry = track_hash.entry(track_name).or_default();
                            entry.push(range);
                        }
                    }
                }
            }
        }

        // Now handle the start event case
        if let Some(range_name) = self.start_events.get(&systing_event_name) {
            let lookup_key = range_name.to_string();
            if let Some(ranges) = self.outstanding_ranges.get_mut(&range_key) {
                if let Some(range) = ranges.get_mut(&lookup_key) {
                    range.start = event.ts;
                    range.args = arg_data;
                } else {
                    let range = TrackRange {
                        range_name: range_name.clone(),
                        start: event.ts,
                        end: 0,
                        args: arg_data,
                    };
                    ranges.insert(lookup_key, range);
                }
            } else {
                let mut ranges = HashMap::new();
                let range = TrackRange {
                    range_name: range_name.clone(),
                    start: event.ts,
                    end: 0,
                    args: arg_data,
                };
                ranges.insert(lookup_key, range);
                self.outstanding_ranges.insert(range_key, ranges);
            }
        }
    }
}
