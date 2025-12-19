use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::Result;

use crate::perfetto::{TraceWriter, TrackCounter};
use crate::record::RecordCollector;
use crate::ringbuf::RingBuffer;
use crate::systing::types::perf_counter_event;
use crate::systing::SystingRecordEvent;
use crate::trace::{CounterRecord, CounterTrackRecord};

use perfetto_protos::counter_descriptor::counter_descriptor::Unit;
use perfetto_protos::counter_descriptor::CounterDescriptor;
use perfetto_protos::trace_packet::TracePacket;

#[derive(Clone, Default, PartialEq, Eq, Hash)]
struct PerfCounterKey {
    cpu: u32,
    index: usize,
}

pub struct PerfCounterRecorder {
    pub ringbuf: RingBuffer<perf_counter_event>,
    pub perf_counters: Vec<String>,
    perf_events: HashMap<PerfCounterKey, Vec<TrackCounter>>,
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
            perf_events: HashMap::new(),
            streaming_collector: None,
            track_ids: HashMap::new(),
            next_track_id: 1,
        }
    }
}

impl From<&perf_counter_event> for TrackCounter {
    fn from(event: &perf_counter_event) -> Self {
        TrackCounter {
            ts: event.ts,
            count: event.value.counter as i64,
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

        if let Some(ref mut collector) = self.streaming_collector {
            // STREAMING PATH: emit directly to collector

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
        } else {
            // NON-STREAMING PATH: accumulate in HashMap (existing behavior)
            let entry = self.perf_events.entry(key).or_default();
            entry.push(TrackCounter::from(&event));
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

    /// Returns true if streaming mode is enabled.
    ///
    /// When streaming is enabled, events are written directly to the collector
    /// during `handle_event()` rather than being accumulated in memory.
    /// Use `set_streaming_collector()` to enable streaming mode.
    pub fn is_streaming(&self) -> bool {
        self.streaming_collector.is_some()
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

    /// Write trace data directly to a RecordCollector (Parquet-first path).
    ///
    /// This method outputs records directly without going through Perfetto format.
    pub fn write_records(
        &self,
        collector: &mut dyn RecordCollector,
        track_id_counter: &mut i64,
    ) -> Result<()> {
        // Track IDs we've already created for each (cpu, counter) combination
        let mut track_ids: HashMap<PerfCounterKey, i64> = HashMap::new();

        for (key, counters) in self.perf_events.iter() {
            // Create a track for this counter
            let track_id = *track_id_counter;
            *track_id_counter += 1;
            track_ids.insert(key.clone(), track_id);

            let counter_name = &self.perf_counters[key.index];
            let track_name = format!("{} CPU {}", counter_name, key.cpu);

            collector.add_counter_track(CounterTrackRecord {
                id: track_id,
                name: track_name,
                unit: Some("count".to_string()),
            })?;

            // Output all counter values for this track
            for event in counters.iter() {
                collector.add_counter(CounterRecord {
                    ts: event.ts as i64,
                    track_id,
                    value: event.count as f64,
                })?;
            }
        }

        Ok(())
    }

    /// Write trace data to Perfetto format (legacy path).
    pub fn write_trace(
        &self,
        writer: &mut dyn TraceWriter,
        id_counter: &Arc<AtomicUsize>,
    ) -> Result<()> {
        let mut desc_uuids: HashMap<String, u64> = HashMap::new();

        // Populate the cache counter events
        for (key, counters) in self.perf_events.iter() {
            let mut descs = crate::perfetto::generate_cpu_track_descriptors(
                &mut desc_uuids,
                key.cpu,
                self.perf_counters[key.index].clone(),
                id_counter,
            );

            let mut counter_desc = CounterDescriptor::default();
            counter_desc.set_unit(Unit::UNIT_COUNT);
            counter_desc.set_is_incremental(false);
            let mut desc = descs.pop().unwrap();
            let uuid = desc.uuid();
            desc.counter = Some(counter_desc).into();

            if let Some(new_desc) = descs.pop() {
                let mut packet = TracePacket::default();
                packet.set_track_descriptor(new_desc);
                writer.write_packet(&packet)?;
            }

            let mut packet = TracePacket::default();
            packet.set_track_descriptor(desc);
            writer.write_packet(&packet)?;

            let seq = id_counter.fetch_add(1, Ordering::Relaxed) as u32;
            for event in counters.iter() {
                writer.write_packet(&event.to_track_event(uuid, seq))?;
            }
        }

        Ok(())
    }

    /// Returns the minimum timestamp from all perf counter events, or None if no events recorded.
    pub fn min_timestamp(&self) -> Option<u64> {
        self.perf_events
            .values()
            .filter_map(|counters| counters.first())
            .map(|c| c.ts)
            .min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::perfetto::VecTraceWriter;
    use perfetto_protos::trace_packet::TracePacket;

    /// Helper to collect packets from PerfCounterRecorder for tests
    fn generate_trace(
        recorder: &PerfCounterRecorder,
        id_counter: &Arc<AtomicUsize>,
    ) -> Vec<TracePacket> {
        let mut writer = VecTraceWriter::new();
        recorder.write_trace(&mut writer, id_counter).unwrap();
        writer.packets
    }

    #[test]
    fn test_perf_counter_recorder() {
        let mut recorder = PerfCounterRecorder::default();
        recorder.perf_counters.push("test_counter".to_string());

        let event = perf_counter_event {
            cpu: 0,
            counter_num: 0,
            ts: 123456789,
            value: crate::systing::types::bpf_perf_event_value {
                counter: 42,
                ..Default::default()
            },
            ..Default::default()
        };

        recorder.handle_event(event);
        assert_eq!(recorder.perf_events.len(), 1);

        let packets = generate_trace(&recorder, &Arc::new(AtomicUsize::new(0)));
        assert!(!packets.is_empty());
        assert_eq!(packets[0].track_descriptor().name(), "test_counter");
        assert_eq!(packets[0].track_descriptor().parent_uuid(), 1);
        assert_eq!(
            packets[0].track_descriptor().uuid(),
            packets[1].track_descriptor().parent_uuid()
        );
        assert_eq!(packets[1].track_descriptor().name(), "CPU 0");
        assert_eq!(
            packets[1].track_descriptor().counter.unit(),
            Unit::UNIT_COUNT
        );
        assert!(!packets[1].track_descriptor().counter.is_incremental());
        assert_eq!(
            packets[2].track_event().track_uuid(),
            packets[1].track_descriptor().uuid()
        );
        assert_eq!(packets[2].timestamp(), 123456789);
        assert_eq!(packets[2].track_event().counter_value(), 42);
    }

    #[test]
    fn test_perf_counter_streaming() {
        use crate::record::collector::InMemoryCollector;

        let mut recorder = PerfCounterRecorder::default();
        recorder.perf_counters.push("cycles".to_string());

        // Set up streaming with InMemoryCollector
        let collector = Box::new(InMemoryCollector::new());
        recorder.set_streaming_collector(collector);
        assert!(recorder.is_streaming());

        // Add event - should stream immediately
        let event = perf_counter_event {
            cpu: 0,
            counter_num: 0,
            ts: 100000,
            value: crate::systing::types::bpf_perf_event_value {
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
            value: crate::systing::types::bpf_perf_event_value {
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
            value: crate::systing::types::bpf_perf_event_value {
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
        assert!(!recorder.is_streaming()); // Collector was taken
        assert!(recorder.track_ids.is_empty()); // Cache cleared

        // Second finish returns None
        let result2 = recorder.finish().unwrap();
        assert!(result2.is_none());
    }

    #[test]
    fn test_perf_counter_non_streaming() {
        let mut recorder = PerfCounterRecorder::default();
        recorder.perf_counters.push("cycles".to_string());

        // No streaming collector set
        assert!(!recorder.is_streaming());

        // Add event - should accumulate in HashMap
        let event = perf_counter_event {
            cpu: 0,
            counter_num: 0,
            ts: 100000,
            value: crate::systing::types::bpf_perf_event_value {
                counter: 42,
                ..Default::default()
            },
            ..Default::default()
        };
        recorder.handle_event(event);

        // Should be in perf_events HashMap, not streaming
        assert_eq!(recorder.perf_events.len(), 1);
        assert!(recorder.track_ids.is_empty());

        // finish() returns None (no streaming collector)
        let result = recorder.finish().unwrap();
        assert!(result.is_none());
    }
}
