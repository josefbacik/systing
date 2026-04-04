use std::collections::HashMap;

use anyhow::Result;

use crate::record::RecordCollector;
use crate::ringbuf::RingBuffer;
use crate::systing_core::types::perf_counter_event;
use crate::systing_core::SystingRecordEvent;
use crate::trace::{CounterRecord, CounterTrackRecord};

#[derive(Default, PartialEq, Eq, Hash)]
struct PerfCounterKey {
    cpu: u32,
    index: usize,
}

pub struct PerfCounterRecorder {
    pub ringbuf: RingBuffer<perf_counter_event>,
    pub perf_counters: Vec<String>,
    // Streaming support
    streaming_collector: Option<Box<dyn RecordCollector + Send>>,
    track_ids: HashMap<PerfCounterKey, i64>,
    next_track_id: i64,
}

impl Default for PerfCounterRecorder {
    fn default() -> Self {
        Self {
            ringbuf: RingBuffer::default(),
            perf_counters: Vec::new(),
            streaming_collector: None,
            track_ids: HashMap::new(),
            next_track_id: 1,
        }
    }
}

impl From<&perf_counter_event> for PerfCounterKey {
    fn from(event: &perf_counter_event) -> Self {
        PerfCounterKey {
            cpu: event.cpu,
            index: event.counter_num as usize,
        }
    }
}

impl SystingRecordEvent<perf_counter_event> for PerfCounterRecorder {
    fn ringbuf(&self) -> &RingBuffer<perf_counter_event> {
        &self.ringbuf
    }
    fn ringbuf_mut(&mut self) -> &mut RingBuffer<perf_counter_event> {
        &mut self.ringbuf
    }
    fn handle_event(&mut self, event: perf_counter_event) {
        let key = PerfCounterKey::from(&event);

        debug_assert!(
            self.streaming_collector.is_some(),
            "streaming collector must be set before handling events"
        );

        let Some(ref mut collector) = self.streaming_collector else {
            return;
        };

        // Defensive bounds check - BPF should ensure valid indices, but be safe
        let counter_name = match self.perf_counters.get(key.index) {
            Some(name) => name,
            None => {
                eprintln!(
                    "Warning: Invalid counter index {}, skipping event",
                    key.index
                );
                return;
            }
        };

        // Get or create track for this (cpu, counter) combination
        let track_id = if let Some(&id) = self.track_ids.get(&key) {
            id
        } else {
            // First event for this key - create the track
            let track_id = self.next_track_id;
            self.next_track_id += 1;

            let track_name = format!("{} CPU {}", counter_name, key.cpu);

            // Log errors but continue (consistent with scheduler pattern)
            if let Err(e) = collector.add_counter_track(CounterTrackRecord {
                id: track_id,
                name: track_name,
                unit: Some("count".to_string()),
            }) {
                eprintln!("Warning: Failed to create counter track: {e}");
            }

            self.track_ids.insert(key, track_id);
            track_id
        };

        // Emit the counter record immediately
        if let Err(e) = collector.add_counter(CounterRecord {
            ts: event.ts as i64,
            track_id,
            value: event.value.counter as f64,
        }) {
            eprintln!("Warning: Failed to stream counter record: {e}");
        }
    }
}

impl PerfCounterRecorder {
    /// Set the streaming collector for direct parquet output.
    ///
    /// When set, events will be streamed directly to the collector during
    /// handle_event() instead of being accumulated in memory.
    pub fn set_streaming_collector(&mut self, collector: Box<dyn RecordCollector + Send>) {
        self.streaming_collector = Some(collector);
    }

    /// Finish streaming and return the collector.
    ///
    /// Since data is already streamed during handle_event(), this method
    /// just flushes the collector and returns it.
    pub fn finish(&mut self) -> Result<Option<Box<dyn RecordCollector + Send>>> {
        if let Some(mut collector) = self.streaming_collector.take() {
            // Data already streamed during handle_event, just flush
            collector.flush()?;
            // Clear track_ids cache
            self.track_ids.clear();
            self.next_track_id = 1;
            Ok(Some(collector))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_perf_counter_streaming() {
        use crate::record::collector::InMemoryCollector;

        let mut recorder = PerfCounterRecorder::default();
        recorder.perf_counters.push("cycles".to_string());

        // Set up streaming with InMemoryCollector
        let collector = Box::new(InMemoryCollector::new());
        recorder.set_streaming_collector(collector);

        // Add event - should stream immediately
        let event = perf_counter_event {
            cpu: 0,
            counter_num: 0,
            ts: 100000,
            value: crate::systing_core::types::bpf_perf_event_value {
                counter: 42,
                ..Default::default()
            },
            ..Default::default()
        };
        recorder.handle_event(event);

        // Track should be created
        assert_eq!(recorder.track_ids.len(), 1);

        // Add another event for same counter
        let event2 = perf_counter_event {
            cpu: 0,
            counter_num: 0,
            ts: 200000,
            value: crate::systing_core::types::bpf_perf_event_value {
                counter: 84,
                ..Default::default()
            },
            ..Default::default()
        };
        recorder.handle_event(event2);

        // Still same track
        assert_eq!(recorder.track_ids.len(), 1);

        // Add event for different CPU - should create new track
        let event3 = perf_counter_event {
            cpu: 1,
            counter_num: 0,
            ts: 300000,
            value: crate::systing_core::types::bpf_perf_event_value {
                counter: 100,
                ..Default::default()
            },
            ..Default::default()
        };
        recorder.handle_event(event3);

        // Now 2 tracks
        assert_eq!(recorder.track_ids.len(), 2);

        // Finish streaming
        let result = recorder.finish().unwrap();
        assert!(result.is_some());
        assert!(recorder.track_ids.is_empty()); // Cache cleared

        // Second finish returns None
        let result2 = recorder.finish().unwrap();
        assert!(result2.is_none());
    }
}
