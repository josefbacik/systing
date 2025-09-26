use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::perfetto::TrackCounter;
use crate::ringbuf::RingBuffer;
use crate::systing::types::{latency_key, task_info};
use crate::SystingRecordEvent;

use perfetto_protos::counter_descriptor::counter_descriptor::Unit;
use perfetto_protos::counter_descriptor::CounterDescriptor;
use perfetto_protos::trace_packet::TracePacket;

#[derive(Default, Debug, Clone, PartialEq, Eq, Hash)]
pub struct TcpSendLatencyKey {
    pub tgidpid: u64,
    pub dst_addr_v6: [u32; 4],
    pub family: u16,
}

impl From<&latency_key> for TcpSendLatencyKey {
    fn from(key: &latency_key) -> Self {
        TcpSendLatencyKey {
            tgidpid: key.tgidpid,
            dst_addr_v6: key.dst_addr_v6,
            family: key.family,
        }
    }
}

impl TcpSendLatencyKey {
    pub fn format_address(&self) -> String {
        if self.family == 2 {
            let ipv4 = Ipv4Addr::from(self.dst_addr_v6[0].to_be());
            format!("{ipv4}")
        } else if self.family == 10 {
            let ipv6 = Ipv6Addr::from([
                (self.dst_addr_v6[0] & 0xff) as u8,
                ((self.dst_addr_v6[0] >> 8) & 0xff) as u8,
                ((self.dst_addr_v6[0] >> 16) & 0xff) as u8,
                ((self.dst_addr_v6[0] >> 24) & 0xff) as u8,
                (self.dst_addr_v6[1] & 0xff) as u8,
                ((self.dst_addr_v6[1] >> 8) & 0xff) as u8,
                ((self.dst_addr_v6[1] >> 16) & 0xff) as u8,
                ((self.dst_addr_v6[1] >> 24) & 0xff) as u8,
                (self.dst_addr_v6[2] & 0xff) as u8,
                ((self.dst_addr_v6[2] >> 8) & 0xff) as u8,
                ((self.dst_addr_v6[2] >> 16) & 0xff) as u8,
                ((self.dst_addr_v6[2] >> 24) & 0xff) as u8,
                (self.dst_addr_v6[3] & 0xff) as u8,
                ((self.dst_addr_v6[3] >> 8) & 0xff) as u8,
                ((self.dst_addr_v6[3] >> 16) & 0xff) as u8,
                ((self.dst_addr_v6[3] >> 24) & 0xff) as u8,
            ]);
            format!("{ipv6}")
        } else {
            format!("unknown:{}", self.family)
        }
    }
}

#[derive(Debug, Clone)]
pub struct TcpSendLatencyEvent {
    pub ts: u64,
    pub key: TcpSendLatencyKey,
    pub avg_latency: u64,
    pub bytes_sent: u64,
    pub avg_ack_latency: u64,
    task: task_info,
}

impl Default for TcpSendLatencyEvent {
    fn default() -> Self {
        Self {
            ts: 0,
            key: TcpSendLatencyKey::default(),
            avg_latency: 0,
            bytes_sent: 0,
            avg_ack_latency: 0,
            task: task_info {
                tgidpid: 0,
                comm: [0; 16],
            },
        }
    }
}

impl TcpSendLatencyEvent {
    pub fn new(
        ts: u64,
        key: TcpSendLatencyKey,
        avg_latency: u64,
        bytes_sent: u64,
        avg_ack_latency: u64,
    ) -> Self {
        Self {
            ts,
            task: task_info {
                tgidpid: key.tgidpid,
                comm: [0; 16],
            },
            key,
            avg_latency,
            bytes_sent,
            avg_ack_latency,
        }
    }
}

impl crate::SystingEvent for TcpSendLatencyEvent {
    fn ts(&self) -> u64 {
        self.ts
    }

    fn next_task_info(&self) -> Option<&task_info> {
        Some(&self.task)
    }
}

#[derive(Default)]
pub struct TcpSendLatencyRecorder {
    pub ringbuf: RingBuffer<TcpSendLatencyEvent>,
    pub latency_events: HashMap<TcpSendLatencyKey, Vec<TrackCounter>>,
    pub bytes_events: HashMap<TcpSendLatencyKey, Vec<TrackCounter>>,
    pub ack_latency_events: HashMap<TcpSendLatencyKey, Vec<TrackCounter>>,
    // Track UUIDs for destination address parent tracks, keyed by (tgidpid, dst_addr)
    dst_track_uuids: HashMap<TcpSendLatencyKey, u64>,
}

impl SystingRecordEvent<TcpSendLatencyEvent> for TcpSendLatencyRecorder {
    fn ringbuf(&self) -> &RingBuffer<TcpSendLatencyEvent> {
        &self.ringbuf
    }

    fn ringbuf_mut(&mut self) -> &mut RingBuffer<TcpSendLatencyEvent> {
        &mut self.ringbuf
    }

    fn handle_event(&mut self, event: TcpSendLatencyEvent) {
        let latency_entry = self.latency_events.entry(event.key.clone()).or_default();
        latency_entry.push(TrackCounter {
            ts: event.ts,
            count: event.avg_latency as i64,
        });

        let bytes_entry = self.bytes_events.entry(event.key.clone()).or_default();
        bytes_entry.push(TrackCounter {
            ts: event.ts,
            count: event.bytes_sent as i64,
        });

        let ack_latency_entry = self.ack_latency_events.entry(event.key).or_default();
        ack_latency_entry.push(TrackCounter {
            ts: event.ts,
            count: event.avg_ack_latency as i64,
        });
    }
}

impl TcpSendLatencyRecorder {
    pub fn generate_trace(
        &mut self,
        pid_uuids: &HashMap<i32, u64>,
        thread_uuids: &HashMap<i32, u64>,
        id_counter: &Arc<AtomicUsize>,
    ) -> Vec<TracePacket> {
        let mut packets = Vec::new();

        // Collect all unique destination address keys
        let mut all_keys: HashSet<TcpSendLatencyKey> = HashSet::new();
        for key in self.latency_events.keys() {
            all_keys.insert(key.clone());
        }
        for key in self.bytes_events.keys() {
            all_keys.insert(key.clone());
        }
        for key in self.ack_latency_events.keys() {
            all_keys.insert(key.clone());
        }

        // Create parent tracks for each unique destination address
        for key in all_keys.iter() {
            if !self.dst_track_uuids.contains_key(key) {
                let dst_track_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;
                self.dst_track_uuids.insert(key.clone(), dst_track_uuid);

                // Create parent track descriptor for this destination address
                let desc = crate::perfetto::generate_pidtgid_track_descriptor(
                    pid_uuids,
                    thread_uuids,
                    &key.tgidpid,
                    format!("TCP to {}", key.format_address()),
                    dst_track_uuid,
                );

                let mut packet = TracePacket::default();
                packet.set_track_descriptor(desc);
                packets.push(packet);
            }
        }

        // Generate latency track as child of destination track
        for (key, counters) in self.latency_events.iter() {
            let parent_uuid = *self.dst_track_uuids.get(key).unwrap();
            let track_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;

            let mut counter_desc = CounterDescriptor::default();
            counter_desc.set_unit(Unit::UNIT_TIME_NS);
            counter_desc.set_is_incremental(false);

            let mut desc = perfetto_protos::track_descriptor::TrackDescriptor::default();
            desc.set_name("Latency".to_string());
            desc.set_uuid(track_uuid);
            desc.set_parent_uuid(parent_uuid);
            desc.counter = Some(counter_desc).into();

            let mut packet = TracePacket::default();
            packet.set_track_descriptor(desc);
            packets.push(packet);

            let seq = id_counter.fetch_add(1, Ordering::Relaxed) as u32;
            for counter in counters.iter() {
                packets.push(counter.to_track_event(track_uuid, seq));
            }
        }

        // Generate bytes sent track as child of destination track
        for (key, counters) in self.bytes_events.iter() {
            let parent_uuid = *self.dst_track_uuids.get(key).unwrap();
            let track_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;

            let mut counter_desc = CounterDescriptor::default();
            counter_desc.set_unit(Unit::UNIT_SIZE_BYTES);
            counter_desc.set_is_incremental(false);

            let mut desc = perfetto_protos::track_descriptor::TrackDescriptor::default();
            desc.set_name("Bytes sent".to_string());
            desc.set_uuid(track_uuid);
            desc.set_parent_uuid(parent_uuid);
            desc.counter = Some(counter_desc).into();

            let mut packet = TracePacket::default();
            packet.set_track_descriptor(desc);
            packets.push(packet);

            let seq = id_counter.fetch_add(1, Ordering::Relaxed) as u32;
            for counter in counters.iter() {
                packets.push(counter.to_track_event(track_uuid, seq));
            }
        }

        // Generate ACK latency track as child of destination track
        for (key, counters) in self.ack_latency_events.iter() {
            let parent_uuid = *self.dst_track_uuids.get(key).unwrap();
            let track_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;

            let mut counter_desc = CounterDescriptor::default();
            counter_desc.set_unit(Unit::UNIT_TIME_NS);
            counter_desc.set_is_incremental(false);

            let mut desc = perfetto_protos::track_descriptor::TrackDescriptor::default();
            desc.set_name("ACK Latency".to_string());
            desc.set_uuid(track_uuid);
            desc.set_parent_uuid(parent_uuid);
            desc.counter = Some(counter_desc).into();

            let mut packet = TracePacket::default();
            packet.set_track_descriptor(desc);
            packets.push(packet);

            let seq = id_counter.fetch_add(1, Ordering::Relaxed) as u32;
            for counter in counters.iter() {
                packets.push(counter.to_track_event(track_uuid, seq));
            }
        }

        packets
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_ipv4_address() {
        let key = TcpSendLatencyKey {
            tgidpid: 0,
            dst_addr_v6: [0x0100007f, 0, 0, 0],
            family: 2,
        };
        assert_eq!(key.format_address(), "127.0.0.1");
    }

    #[test]
    fn test_format_ipv6_address() {
        let key = TcpSendLatencyKey {
            tgidpid: 0,
            dst_addr_v6: [0x00000000, 0x00000000, 0x00000000, 0x01000000],
            family: 10,
        };
        assert_eq!(key.format_address(), "::1");
    }

    #[test]
    fn test_record_event() {
        let mut recorder = TcpSendLatencyRecorder::default();
        let key = TcpSendLatencyKey {
            tgidpid: (1234u64 << 32) | 1234,
            dst_addr_v6: [0x0100007f, 0, 0, 0],
            family: 2,
        };
        let event = TcpSendLatencyEvent::new(123456789, key.clone(), 50000, 1024, 75000);

        recorder.handle_event(event);
        assert_eq!(recorder.latency_events.len(), 1);
        assert_eq!(recorder.latency_events.get(&key).unwrap().len(), 1);
        assert_eq!(recorder.latency_events.get(&key).unwrap()[0].ts, 123456789);
        assert_eq!(recorder.latency_events.get(&key).unwrap()[0].count, 50000);
        assert_eq!(recorder.bytes_events.len(), 1);
        assert_eq!(recorder.bytes_events.get(&key).unwrap().len(), 1);
        assert_eq!(recorder.bytes_events.get(&key).unwrap()[0].ts, 123456789);
        assert_eq!(recorder.bytes_events.get(&key).unwrap()[0].count, 1024);
        assert_eq!(recorder.ack_latency_events.len(), 1);
        assert_eq!(recorder.ack_latency_events.get(&key).unwrap().len(), 1);
        assert_eq!(
            recorder.ack_latency_events.get(&key).unwrap()[0].ts,
            123456789
        );
        assert_eq!(
            recorder.ack_latency_events.get(&key).unwrap()[0].count,
            75000
        );
    }

    #[test]
    fn test_generate_trace() {
        let mut recorder = TcpSendLatencyRecorder::default();
        let key = TcpSendLatencyKey {
            tgidpid: (1234u64 << 32) | 1234,
            dst_addr_v6: [0x0100007f, 0, 0, 0],
            family: 2,
        };
        let event = TcpSendLatencyEvent::new(123456789, key.clone(), 50000, 1024, 75000);

        recorder.handle_event(event);

        let mut pid_uuids = HashMap::new();
        pid_uuids.insert(1234, 999);
        let thread_uuids = HashMap::new();
        let id_counter = Arc::new(AtomicUsize::new(100));
        let packets = recorder.generate_trace(&pid_uuids, &thread_uuids, &id_counter);

        assert!(!packets.is_empty());
        // First packet should be the parent destination track
        assert_eq!(packets[0].track_descriptor().uuid(), 100);
        assert_eq!(packets[0].track_descriptor().name(), "TCP to 127.0.0.1");
        // Second packet should be the latency child track
        assert_eq!(packets[1].track_descriptor().uuid(), 101);
        assert_eq!(packets[1].track_descriptor().name(), "Latency");
        assert_eq!(packets[1].track_descriptor().parent_uuid(), 100);
        // Check that we have bytes track as well
        let bytes_track = packets
            .iter()
            .find(|p| p.track_descriptor().name() == "Bytes sent");
        assert!(bytes_track.is_some());
        assert_eq!(bytes_track.unwrap().track_descriptor().parent_uuid(), 100);
        // Check that we have ACK latency track as well
        let ack_track = packets
            .iter()
            .find(|p| p.track_descriptor().name() == "ACK Latency");
        assert!(ack_track.is_some());
        assert_eq!(ack_track.unwrap().track_descriptor().parent_uuid(), 100);
    }
}
