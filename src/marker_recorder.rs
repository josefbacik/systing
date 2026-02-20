use std::collections::HashMap;
use std::ffi::CStr;

use anyhow::Result;

use crate::record::RecordCollector;
use crate::ringbuf::RingBuffer;
use crate::systing_core::{marker_event, SystingRecordEvent};
use crate::trace::{InstantRecord, SliceRecord, TrackRecord};

struct MarkerRange {
    track: String,
    name: String,
    start: u64,
    end: u64,
}

struct MarkerInstant {
    track: String,
    name: String,
    ts: u64,
}

#[derive(Default)]
pub struct MarkerRecorder {
    pub ringbuf: RingBuffer<marker_event>,
    // Key: (tgidpid, track, name) -> start_ts
    outstanding_ranges: HashMap<(u64, String, String), u64>,
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

        match event.marker_type {
            MARKER_TYPE_START => {
                self.outstanding_ranges.insert((tgidpid, track, name), ts);
            }
            MARKER_TYPE_END => {
                let key = (tgidpid, track.clone(), name.clone());
                if let Some(start) = self.outstanding_ranges.remove(&key) {
                    self.recorded_ranges.push(MarkerRange {
                        track,
                        name,
                        start,
                        end: ts,
                    });
                }
            }
            MARKER_TYPE_INSTANT => {
                self.instants.push(MarkerInstant { track, name, ts });
            }
            _ => {}
        }
    }
}

impl MarkerRecorder {
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

        // Assign a single track ID per unique track name, shared by ranges and instants.
        let mut track_ids: HashMap<&str, i64> = HashMap::new();
        for r in &self.recorded_ranges {
            track_ids.entry(&r.track).or_insert_with(|| {
                let id = *track_id_counter;
                *track_id_counter += 1;
                id
            });
        }
        for i in &self.instants {
            track_ids.entry(&i.track).or_insert_with(|| {
                let id = *track_id_counter;
                *track_id_counter += 1;
                id
            });
        }

        // Emit track descriptors
        for (name, &id) in &track_ids {
            collector.add_track(TrackRecord {
                id,
                name: name.to_string(),
                parent_id: None,
            })?;
        }

        // Emit slices
        for r in &self.recorded_ranges {
            let track_id = track_ids[r.track.as_str()];
            let slice_id = *slice_id_counter;
            *slice_id_counter += 1;

            collector.add_slice(SliceRecord {
                id: slice_id,
                ts: r.start as i64,
                dur: (r.end - r.start) as i64,
                track_id,
                utid: None,
                name: r.name.clone(),
                category: None,
                depth: 0,
            })?;
        }

        // Emit instants
        for i in &self.instants {
            let track_id = track_ids[i.track.as_str()];
            let instant_id = *instant_id_counter;
            *instant_id_counter += 1;

            collector.add_instant(InstantRecord {
                id: instant_id,
                ts: i.ts as i64,
                track_id,
                utid: None,
                name: i.name.clone(),
                category: None,
            })?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::systing_core::task_info;

    fn make_event(marker_type: u32, name: &str, tgidpid: u64, ts: u64) -> marker_event {
        let bytes = name.as_bytes();
        let len = bytes.len().min(63);
        let mut raw_name = [0u8; 64];
        raw_name[..len].copy_from_slice(&bytes[..len]);
        marker_event {
            marker_type,
            ts,
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
        let mut recorder = MarkerRecorder::default();
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
        let mut recorder = MarkerRecorder::default();
        recorder.handle_event(make_event(2, "Markers:check", 1234, 5000));

        assert_eq!(recorder.instants.len(), 1);
        assert_eq!(recorder.instants[0].ts, 5000);
        assert_eq!(recorder.instants[0].name, "check");
    }

    #[test]
    fn test_orphan_end_dropped() {
        let mut recorder = MarkerRecorder::default();
        recorder.handle_event(make_event(1, "T:evt", 1234, 2000));
        assert!(recorder.recorded_ranges.is_empty());
    }

    #[test]
    fn test_orphan_start_not_emitted() {
        let mut recorder = MarkerRecorder::default();
        recorder.handle_event(make_event(0, "T:evt", 1234, 1000));
        assert!(recorder.recorded_ranges.is_empty());
        assert_eq!(recorder.outstanding_ranges.len(), 1);
    }

    #[test]
    fn test_cross_thread_not_matched() {
        let mut recorder = MarkerRecorder::default();
        recorder.handle_event(make_event(0, "T:evt", 1001, 1000));
        recorder.handle_event(make_event(1, "T:evt", 1002, 2000));
        // Different tgidpid -> no match
        assert!(recorder.recorded_ranges.is_empty());
    }

    #[test]
    fn test_shared_track_for_ranges_and_instants() {
        // Ranges and instants on the same track name must share one TrackRecord.
        let mut recorder = MarkerRecorder::default();
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
        let mut recorder = MarkerRecorder::default();
        // No threshold set, instants should never trigger
        for i in 0..100 {
            assert!(!recorder.maybe_trigger(&make_event(2, "T:check", 1, i * 100)));
        }
    }

    #[test]
    fn test_threshold_triggers_at_count() {
        let mut recorder = MarkerRecorder::default().with_threshold(Some(3));
        // First two instants should not trigger
        assert!(!recorder.maybe_trigger(&make_event(2, "T:check", 1, 100)));
        assert!(!recorder.maybe_trigger(&make_event(2, "T:check", 1, 200)));
        // Third instant should trigger
        assert!(recorder.maybe_trigger(&make_event(2, "T:check", 1, 300)));
    }

    #[test]
    fn test_threshold_one_triggers_immediately() {
        let mut recorder = MarkerRecorder::default().with_threshold(Some(1));
        assert!(recorder.maybe_trigger(&make_event(2, "T:check", 1, 100)));
    }

    #[test]
    fn test_threshold_ignores_ranges() {
        let mut recorder = MarkerRecorder::default().with_threshold(Some(1));
        // Start/end range events should not count toward instant threshold
        assert!(!recorder.maybe_trigger(&make_event(0, "T:evt", 1, 100)));
        assert!(!recorder.maybe_trigger(&make_event(1, "T:evt", 1, 200)));
        // Only an instant should trigger
        assert!(recorder.maybe_trigger(&make_event(2, "T:check", 1, 300)));
    }

    #[test]
    fn test_duration_threshold_triggers_on_long_range() {
        // 100ms threshold in milliseconds -> 100_000_000 ns internally
        let mut recorder = MarkerRecorder::default().with_duration_threshold(Some(100));
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
        let mut recorder = MarkerRecorder::default().with_duration_threshold(Some(100));
        assert!(!recorder.maybe_trigger(&make_event(0, "T:evt", 1, 0)));
        assert!(recorder.maybe_trigger(&make_event(1, "T:evt", 1, 100_000_000)));
    }

    #[test]
    fn test_duration_threshold_none_never_triggers() {
        let mut recorder = MarkerRecorder::default();
        // No thresholds set, even very long ranges should not trigger
        assert!(!recorder.maybe_trigger(&make_event(0, "T:evt", 1, 0)));
        assert!(!recorder.maybe_trigger(&make_event(1, "T:evt", 1, 999_000_000_000)));
    }

    #[test]
    fn test_duration_threshold_ignores_instants() {
        let mut recorder = MarkerRecorder::default().with_duration_threshold(Some(100));
        assert!(!recorder.maybe_trigger(&make_event(2, "T:check", 1, 0)));
        assert!(!recorder.maybe_trigger(&make_event(2, "T:check", 1, 999_000_000_000)));
    }

    #[test]
    fn test_duration_threshold_ignores_orphan_end() {
        let mut recorder = MarkerRecorder::default().with_duration_threshold(Some(1));
        assert!(!recorder.maybe_trigger(&make_event(1, "T:evt", 1, 999_000_000_000)));
    }

    #[test]
    fn test_both_thresholds_duration_fires_first() {
        // Both instant count (10) and duration (100ms) thresholds set
        // A long range should fire duration before enough instants are seen
        let mut recorder = MarkerRecorder::default()
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
        let mut recorder = MarkerRecorder::default()
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
}
