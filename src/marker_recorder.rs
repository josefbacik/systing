use std::collections::HashMap;
use std::ffi::CStr;
use std::sync::Arc;

use anyhow::Result;

use crate::record::RecordCollector;
use crate::ringbuf::RingBuffer;
use crate::systing_core::{marker_event, SystingRecordEvent};
use crate::trace::{ArgRecord, InstantArgRecord, InstantRecord, SliceRecord, TrackRecord};
use crate::utid::UtidGenerator;

struct MarkerRange {
    track: String,
    name: String,
    start: u64,
    end: u64,
    info: u64,
    tgidpid: u64,
}

struct MarkerInstant {
    track: String,
    name: String,
    ts: u64,
    info: u64,
    tgidpid: u64,
}

pub struct MarkerRecorder {
    pub ringbuf: RingBuffer<marker_event>,
    // Key: (tgidpid, track, name) -> (start_ts, info)
    outstanding_ranges: HashMap<(u64, String, String), (u64, u64)>,
    recorded_ranges: Vec<MarkerRange>,
    instants: Vec<MarkerInstant>,
    // Count threshold: count instant events and stop when threshold is hit
    instant_count: u64,
    threshold: Option<u64>,
    // Duration threshold in nanoseconds: stop when any range exceeds this duration
    duration_threshold_ns: Option<u64>,
    // Separate from `outstanding_ranges` because `maybe_trigger` runs on the
    // ingestion path (before events enter the ring buffer), while `handle_event`
    // runs on the drain path. They observe events at different times.
    outstanding_triggers: HashMap<(u64, String, String), u64>,
    utid_generator: Arc<UtidGenerator>,
}

/// Marker type values passed in the `dirfd` argument of the `faccessat2` syscall.
/// These must stay in sync with the BPF-side definitions in `systing_system.bpf.c`.
pub const MARKER_TYPE_START: u32 = 0;
pub const MARKER_TYPE_END: u32 = 1;
pub const MARKER_TYPE_INSTANT: u32 = 2;

fn parse_name(raw: &[u8; 64]) -> (String, String) {
    let s = CStr::from_bytes_until_nul(raw)
        .ok()
        .and_then(|c| c.to_str().ok())
        .unwrap_or("");
    match s.find(':') {
        Some(i) => (s[..i].to_string(), s[i + 1..].to_string()),
        None => ("Markers".to_string(), s.to_string()),
    }
}

impl SystingRecordEvent<marker_event> for MarkerRecorder {
    fn ringbuf(&self) -> &RingBuffer<marker_event> {
        &self.ringbuf
    }
    fn ringbuf_mut(&mut self) -> &mut RingBuffer<marker_event> {
        &mut self.ringbuf
    }
    fn maybe_trigger(&mut self, event: &marker_event) -> bool {
        if self.threshold.is_none() && self.duration_threshold_ns.is_none() {
            return false;
        }

        match event.marker_type {
            MARKER_TYPE_INSTANT => {
                // Count threshold: count instant events
                if let Some(threshold) = self.threshold {
                    self.instant_count += 1;
                    if self.instant_count >= threshold {
                        println!(
                            "Marker threshold reached: {} instant events observed",
                            self.instant_count
                        );
                        return true;
                    }
                }
                false
            }
            MARKER_TYPE_START => {
                // Duration threshold: record start timestamp
                if self.duration_threshold_ns.is_some() {
                    let (track, name) = parse_name(&event.name);
                    let tgidpid = event.task.tgidpid;
                    self.outstanding_triggers
                        .insert((tgidpid, track, name), event.ts);
                }
                false
            }
            MARKER_TYPE_END => {
                // Duration threshold: check completed range duration
                if let Some(dur_threshold_ns) = self.duration_threshold_ns {
                    let (track, name) = parse_name(&event.name);
                    let tgidpid = event.task.tgidpid;
                    let key = (tgidpid, track, name);
                    if let Some(start_ts) = self.outstanding_triggers.remove(&key) {
                        let duration_ns = event.ts.saturating_sub(start_ts);
                        if duration_ns >= dur_threshold_ns {
                            println!(
                                "Marker duration threshold reached: range lasted {}ms (threshold {}ms)",
                                duration_ns / 1_000_000,
                                dur_threshold_ns / 1_000_000
                            );
                            return true;
                        }
                    }
                }
                false
            }
            _ => false,
        }
    }

    fn handle_event(&mut self, event: marker_event) {
        let (track, name) = parse_name(&event.name);
        let tgidpid = event.task.tgidpid;
        let ts = event.ts;
        let info = event.info;

        match event.marker_type {
            MARKER_TYPE_START => {
                self.outstanding_ranges
                    .insert((tgidpid, track, name), (ts, info));
            }
            MARKER_TYPE_END => {
                let key = (tgidpid, track.clone(), name.clone());
                // Info is captured from the START event; the END event's info is intentionally ignored.
                if let Some((start, start_info)) = self.outstanding_ranges.remove(&key) {
                    self.recorded_ranges.push(MarkerRange {
                        track,
                        name,
                        start,
                        end: ts,
                        info: start_info,
                        tgidpid,
                    });
                }
            }
            MARKER_TYPE_INSTANT => {
                self.instants.push(MarkerInstant {
                    track,
                    name,
                    ts,
                    info,
                    tgidpid,
                });
            }
            _ => {}
        }
    }
}

impl MarkerRecorder {
    pub fn new(utid_generator: Arc<UtidGenerator>) -> Self {
        Self {
            ringbuf: RingBuffer::default(),
            outstanding_ranges: HashMap::new(),
            recorded_ranges: Vec::new(),
            instants: Vec::new(),
            instant_count: 0,
            threshold: None,
            duration_threshold_ns: None,
            outstanding_triggers: HashMap::new(),
            utid_generator,
        }
    }

    pub fn with_threshold(mut self, threshold: Option<u64>) -> Self {
        self.threshold = threshold;
        self
    }

    pub fn with_duration_threshold(mut self, duration_threshold_ms: Option<u64>) -> Self {
        self.duration_threshold_ns = duration_threshold_ms.map(|ms| ms.saturating_mul(1_000_000));
        self
    }

    pub fn has_data(&self) -> bool {
        !self.recorded_ranges.is_empty() || !self.instants.is_empty()
    }

    pub fn min_timestamp(&self) -> Option<u64> {
        let range_min = self.recorded_ranges.iter().map(|r| r.start).min();
        let instant_min = self.instants.iter().map(|i| i.ts).min();
        [range_min, instant_min].into_iter().flatten().min()
    }

    pub fn write_records(
        &self,
        collector: &mut dyn RecordCollector,
        track_id_counter: &mut i64,
        slice_id_counter: &mut i64,
        instant_id_counter: &mut i64,
    ) -> Result<()> {
        if !self.outstanding_ranges.is_empty() {
            eprintln!(
                "Warning: {} marker range(s) had START but no END and will be dropped",
                self.outstanding_ranges.len()
            );
        }

        // Per-thread track id keyed by (tid, track_name) — rows are
        // thread-attributed via slice.utid / instant.utid. Resolve each row's
        // track id in a single pass so the emission loops below do zero
        // hashmap lookups.
        let mut track_ids: HashMap<(i32, String), i64> = HashMap::new();
        let mut range_track_ids: Vec<i64> = Vec::with_capacity(self.recorded_ranges.len());
        let mut instant_track_ids: Vec<i64> = Vec::with_capacity(self.instants.len());
        for r in &self.recorded_ranges {
            let tid = r.tgidpid as i32;
            let id = *track_ids.entry((tid, r.track.clone())).or_insert_with(|| {
                let id = *track_id_counter;
                *track_id_counter += 1;
                id
            });
            range_track_ids.push(id);
        }
        for i in &self.instants {
            let tid = i.tgidpid as i32;
            let id = *track_ids.entry((tid, i.track.clone())).or_insert_with(|| {
                let id = *track_id_counter;
                *track_id_counter += 1;
                id
            });
            instant_track_ids.push(id);
        }

        // Emit track descriptors in stable id order (HashMap iteration is
        // non-deterministic; ids are monotonic from track_id_counter).
        let mut ordered_tracks: Vec<(&(i32, String), &i64)> = track_ids.iter().collect();
        ordered_tracks.sort_by_key(|(_, &id)| id);
        for ((_tid, name), &id) in ordered_tracks {
            collector.add_track(TrackRecord {
                id,
                name: name.clone(),
                parent_id: None,
            })?;
        }

        // Emit slices
        for (r, &track_id) in self.recorded_ranges.iter().zip(range_track_ids.iter()) {
            let tid = r.tgidpid as i32;
            let utid = Some(self.utid_generator.get_or_create_utid(tid));
            let slice_id = *slice_id_counter;
            *slice_id_counter += 1;

            collector.add_slice(SliceRecord {
                id: slice_id,
                ts: r.start as i64,
                dur: (r.end - r.start) as i64,
                track_id,
                utid,
                name: r.name.clone(),
                category: None,
                depth: 0,
            })?;
            // u64 -> i64: values with the high bit set will appear negative in queries
            collector.add_arg(ArgRecord {
                slice_id,
                key: "info".to_string(),
                int_value: Some(r.info as i64),
                string_value: None,
                real_value: None,
            })?;
        }

        // Emit instants
        for (i, &track_id) in self.instants.iter().zip(instant_track_ids.iter()) {
            let tid = i.tgidpid as i32;
            let utid = Some(self.utid_generator.get_or_create_utid(tid));
            let instant_id = *instant_id_counter;
            *instant_id_counter += 1;

            collector.add_instant(InstantRecord {
                id: instant_id,
                ts: i.ts as i64,
                track_id,
                utid,
                name: i.name.clone(),
                category: None,
            })?;
            // u64 -> i64: values with the high bit set will appear negative in queries
            collector.add_instant_arg(InstantArgRecord {
                instant_id,
                key: "info".to_string(),
                int_value: Some(i.info as i64),
                string_value: None,
                real_value: None,
            })?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::systing_core::task_info;

    fn new_recorder() -> MarkerRecorder {
        MarkerRecorder::new(Arc::new(UtidGenerator::new()))
    }

    fn make_event(marker_type: u32, name: &str, tgidpid: u64, ts: u64) -> marker_event {
        make_event_with_info(marker_type, name, tgidpid, ts, 0)
    }

    fn make_event_with_info(
        marker_type: u32,
        name: &str,
        tgidpid: u64,
        ts: u64,
        info: u64,
    ) -> marker_event {
        let bytes = name.as_bytes();
        let len = bytes.len().min(63);
        let mut raw_name = [0u8; 64];
        raw_name[..len].copy_from_slice(&bytes[..len]);
        marker_event {
            marker_type,
            ts,
            info,
            task: task_info {
                tgidpid,
                ..Default::default()
            },
            name: raw_name,
            ..Default::default()
        }
    }

    #[test]
    fn test_parse_name_with_colon() {
        let mut raw = [0u8; 64];
        let s = b"Training:fwd_bwd";
        raw[..s.len()].copy_from_slice(s);
        let (track, name) = parse_name(&raw);
        assert_eq!(track, "Training");
        assert_eq!(name, "fwd_bwd");
    }

    #[test]
    fn test_parse_name_without_colon() {
        let mut raw = [0u8; 64];
        let s = b"checkpoint";
        raw[..s.len()].copy_from_slice(s);
        let (track, name) = parse_name(&raw);
        assert_eq!(track, "Markers");
        assert_eq!(name, "checkpoint");
    }

    #[test]
    fn test_range_start_end() {
        let mut recorder = new_recorder();
        recorder.handle_event(make_event(0, "T:evt", 1234, 1000));
        recorder.handle_event(make_event(1, "T:evt", 1234, 2000));

        assert_eq!(recorder.recorded_ranges.len(), 1);
        assert_eq!(recorder.recorded_ranges[0].start, 1000);
        assert_eq!(recorder.recorded_ranges[0].end, 2000);
        assert_eq!(recorder.recorded_ranges[0].track, "T");
        assert_eq!(recorder.recorded_ranges[0].name, "evt");
    }

    #[test]
    fn test_instant() {
        let mut recorder = new_recorder();
        recorder.handle_event(make_event(2, "Markers:check", 1234, 5000));

        assert_eq!(recorder.instants.len(), 1);
        assert_eq!(recorder.instants[0].ts, 5000);
        assert_eq!(recorder.instants[0].name, "check");
    }

    #[test]
    fn test_orphan_end_dropped() {
        let mut recorder = new_recorder();
        recorder.handle_event(make_event(1, "T:evt", 1234, 2000));
        assert!(recorder.recorded_ranges.is_empty());
    }

    #[test]
    fn test_orphan_start_not_emitted() {
        let mut recorder = new_recorder();
        recorder.handle_event(make_event(0, "T:evt", 1234, 1000));
        assert!(recorder.recorded_ranges.is_empty());
        assert_eq!(recorder.outstanding_ranges.len(), 1);
    }

    #[test]
    fn test_cross_thread_not_matched() {
        let mut recorder = new_recorder();
        recorder.handle_event(make_event(0, "T:evt", 1001, 1000));
        recorder.handle_event(make_event(1, "T:evt", 1002, 2000));
        // Different tgidpid -> no match
        assert!(recorder.recorded_ranges.is_empty());
    }

    #[test]
    fn test_shared_track_for_ranges_and_instants() {
        // Ranges and instants on the same track name must share one TrackRecord.
        let mut recorder = new_recorder();
        recorder.handle_event(make_event(0, "T:range", 1, 100));
        recorder.handle_event(make_event(1, "T:range", 1, 200));
        recorder.handle_event(make_event(2, "T:instant", 1, 150));

        let mut collector = crate::record::collector::InMemoryCollector::new();
        recorder
            .write_records(&mut collector, &mut 0, &mut 0, &mut 0)
            .unwrap();

        let data = collector.into_data();
        // Only one track "T" should be created
        assert_eq!(data.tracks.len(), 1);
        assert_eq!(data.tracks[0].name, "T");
        // The slice and instant share the same track_id
        assert_eq!(data.slices[0].track_id, data.tracks[0].id);
        assert_eq!(data.instants[0].track_id, data.tracks[0].id);
    }

    #[test]
    fn test_threshold_none_never_triggers() {
        let mut recorder = new_recorder();
        // No threshold set, instants should never trigger
        for i in 0..100 {
            assert!(!recorder.maybe_trigger(&make_event(2, "T:check", 1, i * 100)));
        }
    }

    #[test]
    fn test_threshold_triggers_at_count() {
        let mut recorder = new_recorder().with_threshold(Some(3));
        // First two instants should not trigger
        assert!(!recorder.maybe_trigger(&make_event(2, "T:check", 1, 100)));
        assert!(!recorder.maybe_trigger(&make_event(2, "T:check", 1, 200)));
        // Third instant should trigger
        assert!(recorder.maybe_trigger(&make_event(2, "T:check", 1, 300)));
    }

    #[test]
    fn test_threshold_one_triggers_immediately() {
        let mut recorder = new_recorder().with_threshold(Some(1));
        assert!(recorder.maybe_trigger(&make_event(2, "T:check", 1, 100)));
    }

    #[test]
    fn test_threshold_ignores_ranges() {
        let mut recorder = new_recorder().with_threshold(Some(1));
        // Start/end range events should not count toward instant threshold
        assert!(!recorder.maybe_trigger(&make_event(0, "T:evt", 1, 100)));
        assert!(!recorder.maybe_trigger(&make_event(1, "T:evt", 1, 200)));
        // Only an instant should trigger
        assert!(recorder.maybe_trigger(&make_event(2, "T:check", 1, 300)));
    }

    #[test]
    fn test_duration_threshold_triggers_on_long_range() {
        // 100ms threshold in milliseconds -> 100_000_000 ns internally
        let mut recorder = new_recorder().with_duration_threshold(Some(100));
        // Range lasting 50ms (50_000_000 ns) - should NOT trigger
        assert!(!recorder.maybe_trigger(&make_event(0, "T:evt", 1, 0)));
        assert!(!recorder.maybe_trigger(&make_event(1, "T:evt", 1, 50_000_000)));
        // Range lasting 150ms (150_000_000 ns) - should trigger
        assert!(!recorder.maybe_trigger(&make_event(0, "T:evt", 1, 200_000_000)));
        assert!(recorder.maybe_trigger(&make_event(1, "T:evt", 1, 350_000_000)));
    }

    #[test]
    fn test_duration_threshold_exact_boundary() {
        // Exactly at threshold should trigger
        let mut recorder = new_recorder().with_duration_threshold(Some(100));
        assert!(!recorder.maybe_trigger(&make_event(0, "T:evt", 1, 0)));
        assert!(recorder.maybe_trigger(&make_event(1, "T:evt", 1, 100_000_000)));
    }

    #[test]
    fn test_duration_threshold_none_never_triggers() {
        let mut recorder = new_recorder();
        // No thresholds set, even very long ranges should not trigger
        assert!(!recorder.maybe_trigger(&make_event(0, "T:evt", 1, 0)));
        assert!(!recorder.maybe_trigger(&make_event(1, "T:evt", 1, 999_000_000_000)));
    }

    #[test]
    fn test_duration_threshold_ignores_instants() {
        let mut recorder = new_recorder().with_duration_threshold(Some(100));
        assert!(!recorder.maybe_trigger(&make_event(2, "T:check", 1, 0)));
        assert!(!recorder.maybe_trigger(&make_event(2, "T:check", 1, 999_000_000_000)));
    }

    #[test]
    fn test_duration_threshold_ignores_orphan_end() {
        let mut recorder = new_recorder().with_duration_threshold(Some(1));
        assert!(!recorder.maybe_trigger(&make_event(1, "T:evt", 1, 999_000_000_000)));
    }

    #[test]
    fn test_both_thresholds_duration_fires_first() {
        // Both instant count (10) and duration (100ms) thresholds set
        // A long range should fire duration before enough instants are seen
        let mut recorder = new_recorder()
            .with_threshold(Some(10))
            .with_duration_threshold(Some(100));
        // Instants don't fire yet (only 2 of 10)
        assert!(!recorder.maybe_trigger(&make_event(2, "T:check", 1, 0)));
        assert!(!recorder.maybe_trigger(&make_event(2, "T:check", 1, 10_000_000)));
        // Long range fires duration threshold
        assert!(!recorder.maybe_trigger(&make_event(0, "T:evt", 1, 100_000_000)));
        assert!(recorder.maybe_trigger(&make_event(1, "T:evt", 1, 300_000_000)));
    }

    #[test]
    fn test_both_thresholds_count_fires_first() {
        // Both instant count (2) and duration (1s) thresholds set
        // Instants trigger count before any range is long enough for duration
        let mut recorder = new_recorder()
            .with_threshold(Some(2))
            .with_duration_threshold(Some(1000));
        // Short range - no duration trigger
        assert!(!recorder.maybe_trigger(&make_event(0, "T:evt", 1, 0)));
        assert!(!recorder.maybe_trigger(&make_event(1, "T:evt", 1, 1_000_000)));
        // First instant - not yet
        assert!(!recorder.maybe_trigger(&make_event(2, "T:check", 1, 2_000_000)));
        // Second instant - count threshold fires
        assert!(recorder.maybe_trigger(&make_event(2, "T:check", 1, 3_000_000)));
    }

    #[test]
    fn test_range_captures_info() {
        let mut recorder = new_recorder();
        recorder.handle_event(make_event_with_info(0, "T:evt", 1, 1000, 42));
        recorder.handle_event(make_event_with_info(1, "T:evt", 1, 2000, 99));

        assert_eq!(recorder.recorded_ranges.len(), 1);
        // Info comes from the START event
        assert_eq!(recorder.recorded_ranges[0].info, 42);
    }

    #[test]
    fn test_instant_captures_info() {
        let mut recorder = new_recorder();
        recorder.handle_event(make_event_with_info(2, "T:check", 1, 5000, 123));

        assert_eq!(recorder.instants.len(), 1);
        assert_eq!(recorder.instants[0].info, 123);
    }

    #[test]
    fn test_info_emitted_as_arg_records() {
        let mut recorder = new_recorder();
        recorder.handle_event(make_event_with_info(0, "T:range", 1, 100, 42));
        recorder.handle_event(make_event_with_info(1, "T:range", 1, 200, 0));
        recorder.handle_event(make_event_with_info(2, "T:instant", 1, 150, 77));

        let mut collector = crate::record::collector::InMemoryCollector::new();
        recorder
            .write_records(&mut collector, &mut 0, &mut 0, &mut 0)
            .unwrap();

        let data = collector.into_data();
        // Should have one arg for the slice
        assert_eq!(data.args.len(), 1);
        assert_eq!(data.args[0].key, "info");
        assert_eq!(data.args[0].int_value, Some(42));
        assert_eq!(data.args[0].slice_id, data.slices[0].id);

        // Should have one instant_arg for the instant
        assert_eq!(data.instant_args.len(), 1);
        assert_eq!(data.instant_args[0].key, "info");
        assert_eq!(data.instant_args[0].int_value, Some(77));
        assert_eq!(data.instant_args[0].instant_id, data.instants[0].id);
    }

    #[test]
    fn test_slice_and_instant_utid_populated() {
        // Markers must carry per-thread utid so downstream queries can join
        // slice.utid = thread.utid for correct per-thread attribution.
        let gen = Arc::new(UtidGenerator::new());
        let tid: i32 = 4242;
        let tgidpid = ((tid as u64) << 32) | (tid as u64);
        let mut recorder = MarkerRecorder::new(Arc::clone(&gen));
        recorder.handle_event(make_event(0, "T:evt", tgidpid, 1000));
        recorder.handle_event(make_event(1, "T:evt", tgidpid, 2000));
        recorder.handle_event(make_event(2, "T:inst", tgidpid, 1500));

        let mut collector = crate::record::collector::InMemoryCollector::new();
        recorder
            .write_records(&mut collector, &mut 0, &mut 0, &mut 0)
            .unwrap();
        let data = collector.into_data();

        let expected_utid = gen.get_utid(tid).expect("utid should exist after write");
        assert_eq!(data.slices.len(), 1);
        assert_eq!(data.slices[0].utid, Some(expected_utid));
        assert_eq!(data.instants.len(), 1);
        assert_eq!(data.instants[0].utid, Some(expected_utid));
    }

    #[test]
    fn test_distinct_threads_get_distinct_track_ids_and_utids() {
        // Same track name from two different threads must produce two distinct
        // TrackRecords, and each slice must carry its own thread's utid so
        // narrowest-enclosing queries do not cross-attribute.
        let gen = Arc::new(UtidGenerator::new());
        let tid_a: i32 = 1001;
        let tid_b: i32 = 1002;
        let tgidpid_a = ((tid_a as u64) << 32) | (tid_a as u64);
        let tgidpid_b = ((tid_b as u64) << 32) | (tid_b as u64);
        let mut recorder = MarkerRecorder::new(Arc::clone(&gen));
        recorder.handle_event(make_event(0, "T:evt", tgidpid_a, 100));
        recorder.handle_event(make_event(1, "T:evt", tgidpid_a, 200));
        recorder.handle_event(make_event(0, "T:evt", tgidpid_b, 150));
        recorder.handle_event(make_event(1, "T:evt", tgidpid_b, 250));

        let mut collector = crate::record::collector::InMemoryCollector::new();
        recorder
            .write_records(&mut collector, &mut 0, &mut 0, &mut 0)
            .unwrap();
        let data = collector.into_data();

        assert_eq!(data.tracks.len(), 2, "expected one track per thread");
        assert_eq!(data.slices.len(), 2);

        let utid_a = gen.get_utid(tid_a).unwrap();
        let utid_b = gen.get_utid(tid_b).unwrap();
        assert_ne!(utid_a, utid_b);

        let slice_a = data
            .slices
            .iter()
            .find(|s| s.ts == 100)
            .expect("slice A missing");
        let slice_b = data
            .slices
            .iter()
            .find(|s| s.ts == 150)
            .expect("slice B missing");
        assert_eq!(slice_a.utid, Some(utid_a));
        assert_eq!(slice_b.utid, Some(utid_b));
        assert_ne!(
            slice_a.track_id, slice_b.track_id,
            "cross-thread same-name tracks must be distinct"
        );
    }

    #[test]
    fn test_same_thread_same_name_collapses_to_one_track() {
        // Sanity: a single thread emitting both range and instant with the same
        // track prefix should still share a single TrackRecord (no regression).
        let gen = Arc::new(UtidGenerator::new());
        let tid: i32 = 77;
        let tgidpid = ((tid as u64) << 32) | (tid as u64);
        let mut recorder = MarkerRecorder::new(Arc::clone(&gen));
        recorder.handle_event(make_event(0, "T:range", tgidpid, 100));
        recorder.handle_event(make_event(1, "T:range", tgidpid, 200));
        recorder.handle_event(make_event(2, "T:inst", tgidpid, 150));

        let mut collector = crate::record::collector::InMemoryCollector::new();
        recorder
            .write_records(&mut collector, &mut 0, &mut 0, &mut 0)
            .unwrap();
        let data = collector.into_data();

        let expected_utid = gen.get_utid(tid).unwrap();
        assert_eq!(data.tracks.len(), 1);
        assert_eq!(data.slices[0].track_id, data.tracks[0].id);
        assert_eq!(data.instants[0].track_id, data.tracks[0].id);
        assert_eq!(data.slices[0].utid, Some(expected_utid));
        assert_eq!(data.instants[0].utid, Some(expected_utid));
    }
}
