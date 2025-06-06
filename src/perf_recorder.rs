use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::perfetto::TrackCounter;
use crate::ringbuf::RingBuffer;
use crate::systing::types::perf_counter_event;

use perfetto_protos::counter_descriptor::counter_descriptor::Unit;
use perfetto_protos::counter_descriptor::CounterDescriptor;
use perfetto_protos::trace_packet::TracePacket;
use perfetto_protos::track_descriptor::TrackDescriptor;

#[derive(Default, PartialEq, Eq, Hash)]
struct PerfCounterKey {
    cpu: u32,
    index: usize,
}

#[derive(Default)]
pub struct PerfCounterRecorder {
    pub ringbuf: RingBuffer<perf_counter_event>,
    pub perf_counters: Vec<String>,
    perf_events: HashMap<PerfCounterKey, Vec<TrackCounter>>,
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

impl PerfCounterRecorder {
    pub fn handle_event(&mut self, event: perf_counter_event) {
        let key = PerfCounterKey::from(&event);
        let entry = self.perf_events.entry(key).or_default();
        entry.push(TrackCounter::from(&event));
    }

    pub fn drain_ringbuf(&mut self) {
        while let Some(event) = self.ringbuf.pop_back() {
            self.handle_event(event);
        }
    }

    pub fn generate_trace(&self, id_counter: &mut Arc<AtomicUsize>) -> Vec<TracePacket> {
        let mut packets = Vec::new();

        // Populate the cache counter events
        for (key, counters) in self.perf_events.iter() {
            let desc_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;
            let track_name = format!("{}_{}", self.perf_counters[key.index], key.cpu);
            let mut desc = TrackDescriptor::default();
            desc.set_name(track_name);
            desc.set_uuid(desc_uuid);

            let mut counter_desc = CounterDescriptor::default();
            counter_desc.set_unit(Unit::UNIT_COUNT);
            counter_desc.set_is_incremental(false);
            desc.counter = Some(counter_desc).into();

            let mut packet = TracePacket::default();
            packet.set_track_descriptor(desc);
            packets.push(packet);

            let seq = id_counter.fetch_add(1, Ordering::Relaxed) as u32;
            for event in counters.iter() {
                packets.push(event.to_track_event(desc_uuid, seq));
            }
        }

        packets
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let packets = recorder.generate_trace(&mut Arc::new(AtomicUsize::new(0)));
        assert!(!packets.is_empty());
        assert_eq!(packets[0].track_descriptor().name(), "test_counter_0");
        assert_eq!(
            packets[0].track_descriptor().counter.unit(),
            Unit::UNIT_COUNT
        );
        assert_eq!(
            packets[0].track_descriptor().counter.is_incremental(),
            false
        );
        assert_eq!(
            packets[1].track_event().track_uuid(),
            packets[0].track_descriptor().uuid()
        );
        assert_eq!(packets[1].timestamp(), 123456789);
        assert_eq!(packets[1].track_event().counter_value(), 42);
    }
}
