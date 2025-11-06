use std::collections::HashMap;
use std::fmt;
use std::net::Ipv4Addr;

use crate::ringbuf::RingBuffer;
use crate::systing::types::network_event;
use crate::SystingRecordEvent;

use perfetto_protos::debug_annotation::DebugAnnotation;
use perfetto_protos::interned_data::InternedData;
use perfetto_protos::trace_packet::trace_packet::SequenceFlags;
use perfetto_protos::trace_packet::TracePacket;
use perfetto_protos::track_descriptor::TrackDescriptor;
use perfetto_protos::track_event::track_event::Type;
use perfetto_protos::track_event::{EventName, TrackEvent};

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

// Unique identifier for a network connection
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
struct ConnectionId {
    protocol: u32, // Cast from network_protocol enum
    dest_addr: u32,
    dest_port: u16,
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use crate::systing::types::network_protocol;
        let protocol_str = if self.protocol == network_protocol::NETWORK_TCP.0 {
            "TCP"
        } else if self.protocol == network_protocol::NETWORK_UDP.0 {
            "UDP"
        } else {
            "UNKNOWN"
        };
        let addr = Ipv4Addr::from(u32::from_be(self.dest_addr));
        write!(f, "{}:{}:{}", protocol_str, addr, self.dest_port)
    }
}

// A single network send event
#[derive(Clone)]
struct NetworkSendEvent {
    ts: u64,
    bytes: u32,
}

pub struct NetworkRecorder {
    pub ringbuf: RingBuffer<network_event>,
    // Map from tgidpid to connections to send events
    network_events: HashMap<u64, HashMap<ConnectionId, Vec<NetworkSendEvent>>>,
    // Map from event name to interned id (for deduplication)
    event_name_ids: HashMap<String, u64>,
    // Counter for generating unique interned IDs
    next_name_iid: u64,
}

impl Default for NetworkRecorder {
    fn default() -> Self {
        Self {
            ringbuf: RingBuffer::default(),
            network_events: HashMap::new(),
            event_name_ids: HashMap::new(),
            next_name_iid: 2000, // Start IIDs at 2000 to avoid conflicts with other interned data
        }
    }
}

impl NetworkRecorder {
    fn get_or_create_event_name_iid(&mut self, name: String) -> u64 {
        if let Some(&iid) = self.event_name_ids.get(&name) {
            return iid;
        }

        let iid = self.next_name_iid;
        self.next_name_iid += 1;
        self.event_name_ids.insert(name, iid);
        iid
    }

    pub fn generate_trace_packets(
        &mut self,
        pid_uuids: &HashMap<i32, u64>,
        thread_uuids: &HashMap<i32, u64>,
        id_counter: &Arc<AtomicUsize>,
    ) -> Vec<TracePacket> {
        let mut packets = Vec::new();
        let sequence_id = id_counter.fetch_add(1, Ordering::Relaxed) as u32;

        // Collect all unique protocols used in recorded events
        use crate::systing::types::network_protocol;
        let mut protocols_used = std::collections::HashSet::new();
        for connections in self.network_events.values() {
            for conn_id in connections.keys() {
                protocols_used.insert(conn_id.protocol);
            }
        }

        // Create IIDs only for protocols that were actually used
        for protocol in protocols_used {
            let event_name = if protocol == network_protocol::NETWORK_TCP.0 {
                "tcp_send"
            } else if protocol == network_protocol::NETWORK_UDP.0 {
                "udp_send"
            } else {
                "network_send"
            };
            self.get_or_create_event_name_iid(event_name.to_string());
        }

        // Generate interned data packet with event names
        let mut event_names = Vec::new();
        for (name, iid) in &self.event_name_ids {
            let mut event_name = EventName::default();
            event_name.set_iid(*iid);
            event_name.set_name(name.clone());
            event_names.push(event_name);
        }

        // Sort by iid for consistency
        event_names.sort_by_key(|e| e.iid());

        if !event_names.is_empty() {
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

        // Generate per-thread network tracks
        for (tgidpid, connections) in self.network_events.iter() {
            if connections.is_empty() {
                continue;
            }

            // Create a "Network Connections" track group for this thread
            let group_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;

            let group_desc = crate::perfetto::generate_pidtgid_track_descriptor(
                pid_uuids,
                thread_uuids,
                tgidpid,
                "Network Connections".to_string(),
                group_uuid,
            );

            let mut group_packet = TracePacket::default();
            group_packet.set_track_descriptor(group_desc);
            packets.push(group_packet);

            // Create a track for each unique connection
            for (conn_id, events) in connections.iter() {
                if events.is_empty() {
                    continue;
                }

                let track_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;

                let mut track_desc = TrackDescriptor::default();
                track_desc.set_uuid(track_uuid);
                track_desc.set_name(conn_id.to_string());
                track_desc.set_parent_uuid(group_uuid);

                let mut track_packet = TracePacket::default();
                track_packet.set_track_descriptor(track_desc);
                packets.push(track_packet);

                // Get the event name IID based on protocol
                use crate::systing::types::network_protocol;
                let event_name = if conn_id.protocol == network_protocol::NETWORK_TCP.0 {
                    "tcp_send"
                } else if conn_id.protocol == network_protocol::NETWORK_UDP.0 {
                    "udp_send"
                } else {
                    "network_send"
                };
                let name_iid = *self.event_name_ids.get(event_name).unwrap();

                // Generate instant events for each send
                for send_event in events {
                    let mut track_event = TrackEvent::default();
                    track_event.set_type(Type::TYPE_INSTANT);
                    track_event.set_name_iid(name_iid);
                    track_event.set_track_uuid(track_uuid);

                    // Add debug annotation for the size
                    let mut debug_annotation = DebugAnnotation::default();
                    debug_annotation.set_name("bytes".to_string());
                    debug_annotation.set_uint_value(send_event.bytes as u64);
                    track_event.debug_annotations.push(debug_annotation);

                    let mut packet = TracePacket::default();
                    packet.set_timestamp(send_event.ts);
                    packet.set_track_event(track_event);
                    packet.set_trusted_packet_sequence_id(sequence_id);
                    packets.push(packet);
                }
            }
        }

        // Clear events after generating packets
        self.network_events.clear();

        packets
    }
}

impl SystingRecordEvent<network_event> for NetworkRecorder {
    fn ringbuf(&self) -> &RingBuffer<network_event> {
        &self.ringbuf
    }

    fn ringbuf_mut(&mut self) -> &mut RingBuffer<network_event> {
        &mut self.ringbuf
    }

    fn handle_event(&mut self, event: network_event) {
        let tgidpid = event.task.tgidpid;

        let conn_id = ConnectionId {
            protocol: event.protocol.0,
            dest_addr: event.dest_addr,
            dest_port: event.dest_port,
        };

        let send_event = NetworkSendEvent {
            ts: event.ts,
            bytes: event.bytes,
        };

        self.network_events
            .entry(tgidpid)
            .or_default()
            .entry(conn_id)
            .or_default()
            .push(send_event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::systing::types::{network_protocol, task_info};

    fn create_test_task_info(tgid: u32, pid: u32) -> task_info {
        task_info {
            tgidpid: ((tgid as u64) << 32) | (pid as u64),
            comm: [0; 16],
        }
    }

    fn test_protocol_tcp() -> network_protocol {
        network_protocol::NETWORK_TCP
    }

    fn test_protocol_udp() -> network_protocol {
        network_protocol::NETWORK_UDP
    }

    #[test]
    fn test_network_recorder_tcp_send() {
        let mut recorder = NetworkRecorder::default();

        let event = network_event {
            ts: 1000,
            task: create_test_task_info(100, 101),
            protocol: test_protocol_tcp(),
            dest_addr: 0x0100007f, // 127.0.0.1 in network byte order
            dest_port: 8080,
            bytes: 1024,
            cpu: 0,
            ..Default::default()
        };

        recorder.handle_event(event);

        let tgidpid = (100u64 << 32) | 101u64;
        assert_eq!(recorder.network_events.len(), 1);
        assert!(recorder.network_events.contains_key(&tgidpid));

        let connections = &recorder.network_events[&tgidpid];
        assert_eq!(connections.len(), 1);

        let conn_id = ConnectionId {
            protocol: network_protocol::NETWORK_TCP.0,
            dest_addr: 0x0100007f,
            dest_port: 8080,
        };
        assert!(connections.contains_key(&conn_id));
        assert_eq!(connections[&conn_id].len(), 1);
        assert_eq!(connections[&conn_id][0].bytes, 1024);
    }

    #[test]
    fn test_network_recorder_multiple_sends() {
        let mut recorder = NetworkRecorder::default();

        // Send 1
        let event1 = network_event {
            ts: 1000,
            task: create_test_task_info(100, 101),
            protocol: test_protocol_tcp(),
            dest_addr: 0x0100007f,
            dest_port: 8080,
            bytes: 1024,
            cpu: 0,
            ..Default::default()
        };

        // Send 2 to same connection
        let event2 = network_event {
            ts: 2000,
            task: create_test_task_info(100, 101),
            protocol: test_protocol_tcp(),
            dest_addr: 0x0100007f,
            dest_port: 8080,
            bytes: 2048,
            cpu: 0,
            ..Default::default()
        };

        recorder.handle_event(event1);
        recorder.handle_event(event2);

        let tgidpid = (100u64 << 32) | 101u64;
        let connections = &recorder.network_events[&tgidpid];
        let conn_id = ConnectionId {
            protocol: network_protocol::NETWORK_TCP.0,
            dest_addr: 0x0100007f,
            dest_port: 8080,
        };

        assert_eq!(connections[&conn_id].len(), 2);
        assert_eq!(connections[&conn_id][0].bytes, 1024);
        assert_eq!(connections[&conn_id][1].bytes, 2048);
    }

    #[test]
    fn test_network_recorder_multiple_connections() {
        let mut recorder = NetworkRecorder::default();

        // TCP send
        let event1 = network_event {
            ts: 1000,
            task: create_test_task_info(100, 101),
            protocol: test_protocol_tcp(),
            dest_addr: 0x0100007f,
            dest_port: 8080,
            bytes: 1024,
            cpu: 0,
            ..Default::default()
        };

        // UDP send
        let event2 = network_event {
            ts: 2000,
            task: create_test_task_info(100, 101),
            protocol: test_protocol_udp(),
            dest_addr: 0x0100007f,
            dest_port: 9090,
            bytes: 512,
            cpu: 0,
            ..Default::default()
        };

        recorder.handle_event(event1);
        recorder.handle_event(event2);

        let tgidpid = (100u64 << 32) | 101u64;
        let connections = &recorder.network_events[&tgidpid];
        assert_eq!(connections.len(), 2);
    }

    #[test]
    fn test_generate_trace_packets() {
        let mut recorder = NetworkRecorder::default();
        let mut thread_uuids = HashMap::new();
        thread_uuids.insert(101, 500);
        let pid_uuids: HashMap<i32, u64> = HashMap::new();
        let id_counter = Arc::new(AtomicUsize::new(1000));

        let event = network_event {
            ts: 1000,
            task: create_test_task_info(100, 101),
            protocol: test_protocol_tcp(),
            dest_addr: 0x0100007f,
            dest_port: 8080,
            bytes: 1024,
            cpu: 0,
            ..Default::default()
        };

        recorder.handle_event(event);

        let packets = recorder.generate_trace_packets(&pid_uuids, &thread_uuids, &id_counter);

        // Should have:
        // 1. Interned data packet with event names
        // 2. Track group descriptor for "Network Connections"
        // 3. Track descriptor for the connection
        // 4. Instant event for the send
        assert_eq!(packets.len(), 4);

        // Check interned data
        let interned_packet = &packets[0];
        assert!(interned_packet.interned_data.is_some());

        // Check track group
        let group_packet = &packets[1];
        assert!(group_packet.has_track_descriptor());
        let group_desc = group_packet.track_descriptor();
        assert_eq!(group_desc.name(), "Network Connections");

        // Check connection track
        let track_packet = &packets[2];
        assert!(track_packet.has_track_descriptor());
        let track_desc = track_packet.track_descriptor();
        assert!(track_desc.name().starts_with("TCP:"));
        assert_eq!(track_desc.parent_uuid(), group_desc.uuid());

        // Check instant event
        let event_packet = &packets[3];
        assert!(event_packet.has_track_event());
        assert_eq!(event_packet.timestamp(), 1000);
        let track_event = event_packet.track_event();
        assert_eq!(track_event.type_(), Type::TYPE_INSTANT);
        assert_eq!(track_event.track_uuid(), track_desc.uuid());
        assert_eq!(track_event.debug_annotations.len(), 1);
        assert_eq!(track_event.debug_annotations[0].name(), "bytes");
        assert_eq!(track_event.debug_annotations[0].uint_value(), 1024);

        // Events should be cleared after generating packets
        assert!(recorder.network_events.is_empty());
    }
}
