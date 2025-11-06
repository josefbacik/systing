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
        // dest_addr is stored in network byte order (big-endian), convert to native for display
        let addr = Ipv4Addr::from(u32::from_be(self.dest_addr));
        write!(f, "{}:{}:{}", protocol_str, addr, self.dest_port)
    }
}

// A single network event (send or receive)
#[derive(Clone)]
struct NetworkEvent {
    start_ts: u64,
    end_ts: u64,
    bytes: u32,
}

// Events grouped by operation type
#[derive(Clone, Default)]
struct ConnectionEvents {
    sends: Vec<NetworkEvent>,
    recvs: Vec<NetworkEvent>,
}

#[derive(Default)]
pub struct NetworkRecorder {
    pub ringbuf: RingBuffer<network_event>,
    // Map from tgidpid to connections to events (sends and receives)
    network_events: HashMap<u64, HashMap<ConnectionId, ConnectionEvents>>,
    // Map from event name to interned id (for deduplication)
    event_name_ids: HashMap<String, u64>,
}

impl NetworkRecorder {
    fn protocol_to_str(protocol: u32) -> &'static str {
        use crate::systing::types::network_protocol;
        if protocol == network_protocol::NETWORK_TCP.0 {
            "tcp"
        } else if protocol == network_protocol::NETWORK_UDP.0 {
            "udp"
        } else {
            "network"
        }
    }

    fn get_or_create_event_name_iid(&mut self, name: String, id_counter: &Arc<AtomicUsize>) -> u64 {
        if let Some(&iid) = self.event_name_ids.get(&name) {
            return iid;
        }

        let iid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;
        self.event_name_ids.insert(name, iid);
        iid
    }

    fn add_slice_events(
        &self,
        packets: &mut Vec<TracePacket>,
        sequence_id: u32,
        track_uuid: u64,
        name_iid: u64,
        event: &NetworkEvent,
    ) {
        // Slice begin event
        let mut begin_event = TrackEvent::default();
        begin_event.set_type(Type::TYPE_SLICE_BEGIN);
        begin_event.set_name_iid(name_iid);
        begin_event.set_track_uuid(track_uuid);

        // Add debug annotation for the size on begin event
        let mut debug_annotation = DebugAnnotation::default();
        debug_annotation.set_name("bytes".to_string());
        debug_annotation.set_uint_value(event.bytes as u64);
        begin_event.debug_annotations.push(debug_annotation);

        let mut begin_packet = TracePacket::default();
        begin_packet.set_timestamp(event.start_ts);
        begin_packet.set_track_event(begin_event);
        begin_packet.set_trusted_packet_sequence_id(sequence_id);
        packets.push(begin_packet);

        // Slice end event
        let mut end_event = TrackEvent::default();
        end_event.set_type(Type::TYPE_SLICE_END);
        end_event.set_track_uuid(track_uuid);

        let mut end_packet = TracePacket::default();
        end_packet.set_timestamp(event.end_ts);
        end_packet.set_track_event(end_event);
        end_packet.set_trusted_packet_sequence_id(sequence_id);
        packets.push(end_packet);
    }

    pub fn generate_trace_packets(
        &mut self,
        pid_uuids: &HashMap<i32, u64>,
        thread_uuids: &HashMap<i32, u64>,
        id_counter: &Arc<AtomicUsize>,
    ) -> Vec<TracePacket> {
        let mut packets = Vec::new();
        let sequence_id = id_counter.fetch_add(1, Ordering::Relaxed) as u32;

        // Collect all unique protocol/operation combinations used in recorded events
        use crate::systing::types::network_operation;
        let mut protocol_ops_used = std::collections::HashSet::new();
        for connections in self.network_events.values() {
            for (conn_id, events) in connections.iter() {
                if !events.sends.is_empty() {
                    protocol_ops_used.insert((conn_id.protocol, network_operation::NETWORK_SEND.0));
                }
                if !events.recvs.is_empty() {
                    protocol_ops_used.insert((conn_id.protocol, network_operation::NETWORK_RECV.0));
                }
            }
        }

        // Create IIDs for all protocol/operation combinations that were used
        for (protocol, operation) in protocol_ops_used {
            let proto_str = Self::protocol_to_str(protocol);

            let op_str = if operation == network_operation::NETWORK_SEND.0 {
                "send"
            } else if operation == network_operation::NETWORK_RECV.0 {
                "recv"
            } else {
                "op"
            };

            let event_name = format!("{}_{}", proto_str, op_str);
            self.get_or_create_event_name_iid(event_name, id_counter);
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
            let thread_group_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;

            let thread_group_desc = crate::perfetto::generate_pidtgid_track_descriptor(
                pid_uuids,
                thread_uuids,
                tgidpid,
                "Network Connections".to_string(),
                thread_group_uuid,
            );

            let mut thread_group_packet = TracePacket::default();
            thread_group_packet.set_track_descriptor(thread_group_desc);
            packets.push(thread_group_packet);

            // Create a track group for each unique connection
            for (conn_id, events) in connections.iter() {
                if events.sends.is_empty() && events.recvs.is_empty() {
                    continue;
                }

                // Create connection track group
                let conn_group_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;

                let mut conn_group_desc = TrackDescriptor::default();
                conn_group_desc.set_uuid(conn_group_uuid);
                conn_group_desc.set_name(conn_id.to_string());
                conn_group_desc.set_parent_uuid(thread_group_uuid);

                let mut conn_group_packet = TracePacket::default();
                conn_group_packet.set_track_descriptor(conn_group_desc);
                packets.push(conn_group_packet);

                // Create send track if we have send events
                if !events.sends.is_empty() {
                    let send_track_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;

                    let mut send_track_desc = TrackDescriptor::default();
                    send_track_desc.set_uuid(send_track_uuid);
                    send_track_desc.set_name("Sends".to_string());
                    send_track_desc.set_parent_uuid(conn_group_uuid);

                    let mut send_track_packet = TracePacket::default();
                    send_track_packet.set_track_descriptor(send_track_desc);
                    packets.push(send_track_packet);

                    // Get the event name IID for sends
                    let proto_str = Self::protocol_to_str(conn_id.protocol);
                    let send_event_name = format!("{}_send", proto_str);
                    let send_name_iid = *self
                        .event_name_ids
                        .get(&send_event_name)
                        .expect("send event name should exist after IID generation");

                    // Generate slice events for sends
                    for event in &events.sends {
                        self.add_slice_events(
                            &mut packets,
                            sequence_id,
                            send_track_uuid,
                            send_name_iid,
                            event,
                        );
                    }
                }

                // Create receive track if we have receive events
                if !events.recvs.is_empty() {
                    let recv_track_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;

                    let mut recv_track_desc = TrackDescriptor::default();
                    recv_track_desc.set_uuid(recv_track_uuid);
                    recv_track_desc.set_name("Receives".to_string());
                    recv_track_desc.set_parent_uuid(conn_group_uuid);

                    let mut recv_track_packet = TracePacket::default();
                    recv_track_packet.set_track_descriptor(recv_track_desc);
                    packets.push(recv_track_packet);

                    // Get the event name IID for receives
                    let proto_str = Self::protocol_to_str(conn_id.protocol);
                    let recv_event_name = format!("{}_recv", proto_str);
                    let recv_name_iid = *self
                        .event_name_ids
                        .get(&recv_event_name)
                        .expect("recv event name should exist after IID generation");

                    // Generate slice events for receives
                    for event in &events.recvs {
                        self.add_slice_events(
                            &mut packets,
                            sequence_id,
                            recv_track_uuid,
                            recv_name_iid,
                            event,
                        );
                    }
                }
            }
        }

        // Clear events and IID state after generating packets
        // This ensures we start fresh for the next trace generation with
        // the SEQ_INCREMENTAL_STATE_CLEARED flag
        self.network_events.clear();
        self.event_name_ids.clear();

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
        use crate::systing::types::network_operation;

        let tgidpid = event.task.tgidpid;

        let conn_id = ConnectionId {
            protocol: event.protocol.0,
            dest_addr: event.dest_addr,
            dest_port: event.dest_port,
        };

        let net_event = NetworkEvent {
            start_ts: event.start_ts,
            end_ts: event.end_ts,
            bytes: event.bytes,
        };

        let conn_events = self
            .network_events
            .entry(tgidpid)
            .or_default()
            .entry(conn_id)
            .or_default();

        if event.operation.0 == network_operation::NETWORK_SEND.0 {
            conn_events.sends.push(net_event);
        } else if event.operation.0 == network_operation::NETWORK_RECV.0 {
            conn_events.recvs.push(net_event);
        }
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
        use crate::systing::types::network_operation;

        let mut recorder = NetworkRecorder::default();

        let event = network_event {
            start_ts: 1000,
            end_ts: 2000,
            task: create_test_task_info(100, 101),
            protocol: test_protocol_tcp(),
            operation: network_operation::NETWORK_SEND,
            dest_addr: 0x0100007f, // 127.0.0.1 in network byte order
            dest_port: 8080,
            bytes: 1024,
            cpu: 0,
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
        assert_eq!(connections[&conn_id].sends.len(), 1);
        assert_eq!(connections[&conn_id].sends[0].bytes, 1024);
        assert_eq!(connections[&conn_id].recvs.len(), 0);
    }

    #[test]
    fn test_network_recorder_multiple_sends() {
        use crate::systing::types::network_operation;

        let mut recorder = NetworkRecorder::default();

        // Send 1
        let event1 = network_event {
            start_ts: 1000,
            end_ts: 1500,
            task: create_test_task_info(100, 101),
            protocol: test_protocol_tcp(),
            operation: network_operation::NETWORK_SEND,
            dest_addr: 0x0100007f,
            dest_port: 8080,
            bytes: 1024,
            cpu: 0,
        };

        // Send 2 to same connection
        let event2 = network_event {
            start_ts: 2000,
            end_ts: 2500,
            task: create_test_task_info(100, 101),
            protocol: test_protocol_tcp(),
            operation: network_operation::NETWORK_SEND,
            dest_addr: 0x0100007f,
            dest_port: 8080,
            bytes: 2048,
            cpu: 0,
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

        assert_eq!(connections[&conn_id].sends.len(), 2);
        assert_eq!(connections[&conn_id].sends[0].bytes, 1024);
        assert_eq!(connections[&conn_id].sends[1].bytes, 2048);
    }

    #[test]
    fn test_network_recorder_multiple_connections() {
        use crate::systing::types::network_operation;

        let mut recorder = NetworkRecorder::default();

        // TCP send
        let event1 = network_event {
            start_ts: 1000,
            end_ts: 1500,
            task: create_test_task_info(100, 101),
            protocol: test_protocol_tcp(),
            operation: network_operation::NETWORK_SEND,
            dest_addr: 0x0100007f,
            dest_port: 8080,
            bytes: 1024,
            cpu: 0,
        };

        // UDP send
        let event2 = network_event {
            start_ts: 2000,
            end_ts: 2500,
            task: create_test_task_info(100, 101),
            protocol: test_protocol_udp(),
            operation: network_operation::NETWORK_SEND,
            dest_addr: 0x0100007f,
            dest_port: 9090,
            bytes: 512,
            cpu: 0,
        };

        recorder.handle_event(event1);
        recorder.handle_event(event2);

        let tgidpid = (100u64 << 32) | 101u64;
        let connections = &recorder.network_events[&tgidpid];
        assert_eq!(connections.len(), 2);
    }

    #[test]
    fn test_generate_trace_packets() {
        use crate::systing::types::network_operation;

        let mut recorder = NetworkRecorder::default();
        let mut thread_uuids = HashMap::new();
        thread_uuids.insert(101, 500);
        let pid_uuids: HashMap<i32, u64> = HashMap::new();
        let id_counter = Arc::new(AtomicUsize::new(1000));

        let event = network_event {
            start_ts: 1000,
            end_ts: 2000,
            task: create_test_task_info(100, 101),
            protocol: test_protocol_tcp(),
            operation: network_operation::NETWORK_SEND,
            dest_addr: 0x0100007f,
            dest_port: 8080,
            bytes: 1024,
            cpu: 0,
        };

        recorder.handle_event(event);

        let packets = recorder.generate_trace_packets(&pid_uuids, &thread_uuids, &id_counter);

        // Should have:
        // 1. Interned data packet with event names
        // 2. Thread track group descriptor for "Network Connections"
        // 3. Connection track group (e.g., "TCP:127.0.0.1:8080")
        // 4. Send track descriptor ("Sends")
        // 5. Slice begin event for the send
        // 6. Slice end event for the send
        assert_eq!(packets.len(), 6);

        // Check interned data
        let interned_packet = &packets[0];
        assert!(interned_packet.interned_data.is_some());

        // Check thread track group
        let thread_group_packet = &packets[1];
        assert!(thread_group_packet.has_track_descriptor());
        let thread_group_desc = thread_group_packet.track_descriptor();
        assert_eq!(thread_group_desc.name(), "Network Connections");

        // Check connection track group
        let conn_group_packet = &packets[2];
        assert!(conn_group_packet.has_track_descriptor());
        let conn_group_desc = conn_group_packet.track_descriptor();
        assert!(conn_group_desc.name().starts_with("TCP:"));
        assert_eq!(conn_group_desc.parent_uuid(), thread_group_desc.uuid());

        // Check send track
        let send_track_packet = &packets[3];
        assert!(send_track_packet.has_track_descriptor());
        let send_track_desc = send_track_packet.track_descriptor();
        assert_eq!(send_track_desc.name(), "Sends");
        assert_eq!(send_track_desc.parent_uuid(), conn_group_desc.uuid());

        // Check slice begin event
        let begin_packet = &packets[4];
        assert!(begin_packet.has_track_event());
        assert_eq!(begin_packet.timestamp(), 1000);
        let begin_event = begin_packet.track_event();
        assert_eq!(begin_event.type_(), Type::TYPE_SLICE_BEGIN);
        assert_eq!(begin_event.track_uuid(), send_track_desc.uuid());
        assert_eq!(begin_event.debug_annotations.len(), 1);
        assert_eq!(begin_event.debug_annotations[0].name(), "bytes");
        assert_eq!(begin_event.debug_annotations[0].uint_value(), 1024);

        // Check slice end event
        let end_packet = &packets[5];
        assert!(end_packet.has_track_event());
        assert_eq!(end_packet.timestamp(), 2000);
        let end_event = end_packet.track_event();
        assert_eq!(end_event.type_(), Type::TYPE_SLICE_END);
        assert_eq!(end_event.track_uuid(), send_track_desc.uuid());

        // Events should be cleared after generating packets
        assert!(recorder.network_events.is_empty());
    }

    #[test]
    fn test_network_recorder_sends_and_receives() {
        use crate::systing::types::network_operation;

        let mut recorder = NetworkRecorder::default();

        // TCP send
        let send_event = network_event {
            start_ts: 1000,
            end_ts: 1500,
            task: create_test_task_info(100, 101),
            protocol: test_protocol_tcp(),
            operation: network_operation::NETWORK_SEND,
            dest_addr: 0x0100007f,
            dest_port: 8080,
            bytes: 1024,
            cpu: 0,
        };

        // TCP receive from same connection
        let recv_event = network_event {
            start_ts: 2000,
            end_ts: 2500,
            task: create_test_task_info(100, 101),
            protocol: test_protocol_tcp(),
            operation: network_operation::NETWORK_RECV,
            dest_addr: 0x0100007f,
            dest_port: 8080,
            bytes: 512,
            cpu: 0,
        };

        recorder.handle_event(send_event);
        recorder.handle_event(recv_event);

        let tgidpid = (100u64 << 32) | 101u64;
        let connections = &recorder.network_events[&tgidpid];
        assert_eq!(connections.len(), 1);

        let conn_id = ConnectionId {
            protocol: network_protocol::NETWORK_TCP.0,
            dest_addr: 0x0100007f,
            dest_port: 8080,
        };
        assert!(connections.contains_key(&conn_id));
        assert_eq!(connections[&conn_id].sends.len(), 1);
        assert_eq!(connections[&conn_id].sends[0].bytes, 1024);
        assert_eq!(connections[&conn_id].recvs.len(), 1);
        assert_eq!(connections[&conn_id].recvs[0].bytes, 512);
    }
}
