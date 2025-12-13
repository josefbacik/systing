use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::Result;

use crate::perfetto::{TraceWriter, TrackCounter};
use crate::ringbuf::RingBuffer;
use crate::systing::types::perf_counter_event;
use crate::SystingRecordEvent;

use perfetto_protos::counter_descriptor::counter_descriptor::Unit;
use perfetto_protos::counter_descriptor::CounterDescriptor;
use perfetto_protos::trace_packet::TracePacket;

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

impl SystingRecordEvent<perf_counter_event> for PerfCounterRecorder {
    fn ringbuf(&self) -> &RingBuffer<perf_counter_event> {
        &self.ringbuf
    }
    fn ringbuf_mut(&mut self) -> &mut RingBuffer<perf_counter_event> {
        &mut self.ringbuf
    }
    fn handle_event(&mut self, event: perf_counter_event) {
        let key = PerfCounterKey::from(&event);
        let entry = self.perf_events.entry(key).or_default();
        entry.push(TrackCounter::from(&event));
    }
}

impl PerfCounterRecorder {
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
}
