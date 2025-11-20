use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::Result;

use crate::output::{PerfCounterDef, TraceOutput};
use crate::perfetto::TrackCounter;
use crate::ringbuf::RingBuffer;
use crate::systing::types::perf_counter_event;
use crate::SystingRecordEvent;

use perfetto_protos::counter_descriptor::counter_descriptor::Unit;
use perfetto_protos::counter_descriptor::CounterDescriptor;
use perfetto_protos::trace_packet::TracePacket;

#[derive(Default, PartialEq, Eq, Hash, Clone)]
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
    pub fn write_output(
        &self,
        output: &mut dyn TraceOutput,
        id_counter: &Arc<AtomicUsize>,
    ) -> Result<()> {
        // Map to store counter ID for each (cpu, counter_index) pair
        let mut counter_ids: HashMap<PerfCounterKey, u64> = HashMap::new();

        // First pass: Define all counters and store their IDs
        for (key, _) in self.perf_events.iter() {
            // Generate a unique track UUID for this counter
            let track_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;

            // Create counter definition
            let counter_def = PerfCounterDef {
                track_uuid,
                counter_name: self.perf_counters[key.index].clone(),
                cpu: Some(key.cpu),
                unit: "count".to_string(),
                is_incremental: false,
            };

            // Write the counter definition
            output.write_perf_counter(&counter_def)?;

            // Store the mapping for later use
            counter_ids.insert(key.clone(), track_uuid);
        }

        // Second pass: Write all counter values
        for (key, counters) in self.perf_events.iter() {
            // Get the counter ID we stored earlier
            let counter_id = counter_ids
                .get(key)
                .expect("Counter ID should exist from first pass");

            // Write each counter value
            for event in counters.iter() {
                output.write_perf_counter_value(*counter_id, event.ts, event.count)?;
            }
        }

        Ok(())
    }

    pub fn generate_trace(&self, id_counter: &Arc<AtomicUsize>) -> Vec<TracePacket> {
        let mut packets = Vec::new();
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
                packets.push(packet);
            }

            let mut packet = TracePacket::default();
            packet.set_track_descriptor(desc);
            packets.push(packet);

            let seq = id_counter.fetch_add(1, Ordering::Relaxed) as u32;
            for event in counters.iter() {
                packets.push(event.to_track_event(uuid, seq));
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

        let packets = recorder.generate_trace(&Arc::new(AtomicUsize::new(0)));
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
    fn test_perf_counter_write_output() {
        use crate::output::{PerfCounterDef, TraceOutput};

        // Mock TraceOutput implementation for testing
        struct MockOutput {
            counters: Vec<PerfCounterDef>,
            values: Vec<(u64, u64, i64)>, // (counter_id, ts, value)
        }

        impl MockOutput {
            fn new() -> Self {
                MockOutput {
                    counters: Vec::new(),
                    values: Vec::new(),
                }
            }
        }

        impl TraceOutput for MockOutput {
            fn write_metadata(
                &mut self,
                _start_ts: u64,
                _end_ts: u64,
                _version: &str,
            ) -> Result<()> {
                Ok(())
            }

            fn write_clock_snapshot(&mut self, _clocks: &[crate::output::ClockInfo]) -> Result<()> {
                Ok(())
            }

            fn write_process(&mut self, _pid: i32, _name: &str, _cmdline: &[String]) -> Result<()> {
                Ok(())
            }

            fn write_thread(&mut self, _tid: i32, _pid: i32, _name: &str) -> Result<()> {
                Ok(())
            }

            fn write_process_exit(&mut self, _tid: i32, _ts: u64) -> Result<()> {
                Ok(())
            }

            fn write_track(&mut self, _track: &crate::output::TrackInfo) -> Result<()> {
                Ok(())
            }

            fn write_sched_event(&mut self, _event: &crate::output::SchedEventData) -> Result<()> {
                Ok(())
            }

            fn write_irq_event(&mut self, _event: &crate::output::IrqEventData) -> Result<()> {
                Ok(())
            }

            fn write_symbol(&mut self, _symbol: &crate::output::SymbolInfo) -> Result<u64> {
                Ok(0)
            }

            fn write_stack_trace(&mut self, _stack: &crate::output::StackTraceData) -> Result<u64> {
                Ok(0)
            }

            fn write_perf_sample(&mut self, _sample: &crate::output::PerfSampleData) -> Result<()> {
                Ok(())
            }

            fn write_perf_counter(&mut self, counter: &PerfCounterDef) -> Result<()> {
                self.counters.push(counter.clone());
                Ok(())
            }

            fn write_perf_counter_value(
                &mut self,
                counter_id: u64,
                ts: u64,
                value: i64,
            ) -> Result<()> {
                self.values.push((counter_id, ts, value));
                Ok(())
            }

            fn write_event_definition(
                &mut self,
                _def: &crate::output::EventDefinition,
            ) -> Result<u64> {
                Ok(0)
            }

            fn write_probe_event(&mut self, _event: &crate::output::ProbeEventData) -> Result<()> {
                Ok(())
            }

            fn write_network_connection(
                &mut self,
                _conn: &crate::output::NetworkConnection,
            ) -> Result<u64> {
                Ok(0)
            }

            fn write_network_event(
                &mut self,
                _event: &crate::output::NetworkEventData,
            ) -> Result<()> {
                Ok(())
            }

            fn write_cpu_frequency(
                &mut self,
                _cpu: u32,
                _ts: u64,
                _freq: i64,
                _track_uuid: u64,
            ) -> Result<()> {
                Ok(())
            }

            fn flush(&mut self) -> Result<()> {
                Ok(())
            }
        }

        // Create a recorder with test data
        let mut recorder = PerfCounterRecorder::default();
        recorder.perf_counters.push("test_counter_1".to_string());
        recorder.perf_counters.push("test_counter_2".to_string());

        // Add events for counter 0 on CPU 0
        let event1 = perf_counter_event {
            cpu: 0,
            counter_num: 0,
            ts: 100,
            value: crate::systing::types::bpf_perf_event_value {
                counter: 10,
                ..Default::default()
            },
            ..Default::default()
        };
        recorder.handle_event(event1);

        let event2 = perf_counter_event {
            cpu: 0,
            counter_num: 0,
            ts: 200,
            value: crate::systing::types::bpf_perf_event_value {
                counter: 20,
                ..Default::default()
            },
            ..Default::default()
        };
        recorder.handle_event(event2);

        // Add events for counter 1 on CPU 1
        let event3 = perf_counter_event {
            cpu: 1,
            counter_num: 1,
            ts: 150,
            value: crate::systing::types::bpf_perf_event_value {
                counter: 15,
                ..Default::default()
            },
            ..Default::default()
        };
        recorder.handle_event(event3);

        // Write output
        let mut output = MockOutput::new();
        let id_counter = Arc::new(AtomicUsize::new(100));
        recorder.write_output(&mut output, &id_counter).unwrap();

        // Verify counter definitions were written
        assert_eq!(output.counters.len(), 2);

        // Find each counter by name instead of assuming order
        let counter_1 = output
            .counters
            .iter()
            .find(|c| c.counter_name == "test_counter_1")
            .expect("test_counter_1 not found");
        assert_eq!(counter_1.cpu, Some(0));
        assert_eq!(counter_1.unit, "count");
        assert!(!counter_1.is_incremental);

        let counter_2 = output
            .counters
            .iter()
            .find(|c| c.counter_name == "test_counter_2")
            .expect("test_counter_2 not found");
        assert_eq!(counter_2.cpu, Some(1));

        // Verify counter values were written
        assert_eq!(output.values.len(), 3);

        // Find values for the first counter (CPU 0, counter 0) using the actual track UUID
        let counter_id_0 = counter_1.track_uuid;
        let values_0: Vec<_> = output
            .values
            .iter()
            .filter(|(id, _, _)| *id == counter_id_0)
            .collect();
        assert_eq!(values_0.len(), 2);
        assert_eq!(values_0[0].1, 100);
        assert_eq!(values_0[0].2, 10);
        assert_eq!(values_0[1].1, 200);
        assert_eq!(values_0[1].2, 20);

        // Find values for the second counter (CPU 1, counter 1) using the actual track UUID
        let counter_id_1 = counter_2.track_uuid;
        let values_1: Vec<_> = output
            .values
            .iter()
            .filter(|(id, _, _)| *id == counter_id_1)
            .collect();
        assert_eq!(values_1.len(), 1);
        assert_eq!(values_1[0].1, 150);
        assert_eq!(values_1[0].2, 15);
    }
}
