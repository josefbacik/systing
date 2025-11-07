use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
    protocol: u32,       // Cast from network_protocol enum
    af: u32,             // Cast from network_address_family enum
    dest_addr: [u8; 16], // IPv4 (first 4 bytes) or IPv6 (all 16 bytes) in network byte order
    dest_port: u16,
}

impl ConnectionId {
    fn ip_addr(&self) -> IpAddr {
        use crate::systing::types::network_address_family;
        if self.af == network_address_family::NETWORK_AF_INET.0 {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&self.dest_addr[0..4]);
            IpAddr::V4(Ipv4Addr::from(bytes))
        } else if self.af == network_address_family::NETWORK_AF_INET6.0 {
            IpAddr::V6(Ipv6Addr::from(self.dest_addr))
        } else {
            // Invalid af value - default to IPv4
            IpAddr::V4(Ipv4Addr::from([0, 0, 0, 0]))
        }
    }
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
        let addr = self.ip_addr();
        write!(f, "{}:{}:{}", protocol_str, addr, self.dest_port)
    }
}

// A single network event (send or receive)
#[derive(Clone)]
struct NetworkEvent {
    start_ts: u64,
    end_ts: u64,
    bytes: u32,
    sendmsg_seq: u32, // TCP sequence at sendmsg time (TCP sends only)
}

// A single packet event (TCP packet transmission)
#[derive(Clone)]
struct PacketEvent {
    start_ts: u64,
    end_ts: u64,
    seq: u32,
    length: u32,
    tcp_flags: u8,
}

// Events grouped by operation type
#[derive(Clone, Default)]
struct ConnectionEvents {
    sends: Vec<NetworkEvent>,
    recvs: Vec<NetworkEvent>,
    enqueue_packets: Vec<PacketEvent>,
    send_packets: Vec<PacketEvent>,
}

#[derive(Default)]
pub struct NetworkRecorder {
    pub ringbuf: RingBuffer<network_event>,
    // Map from tgidpid to connections to events (sends and receives, and packets)
    network_events: HashMap<u64, HashMap<ConnectionId, ConnectionEvents>>,
    // Map from event name to interned id (for deduplication)
    event_name_ids: HashMap<String, u64>,
    // Cache of resolved hostnames (IP address -> hostname)
    hostname_cache: HashMap<IpAddr, String>,
}

impl NetworkRecorder {
    fn format_tcp_flags(flags: u8) -> String {
        if flags == 0 {
            return "NONE".to_string();
        }

        let mut result = String::with_capacity(32);
        let mut first = true;

        for (mask, name) in [
            (0x01, "FIN"),
            (0x02, "SYN"),
            (0x04, "RST"),
            (0x08, "PSH"),
            (0x10, "ACK"),
            (0x20, "URG"),
            (0x40, "ECE"),
            (0x80, "CWR"),
        ] {
            if flags & mask != 0 {
                if !first {
                    result.push('|');
                }
                result.push_str(name);
                first = false;
            }
        }

        result
    }

    pub fn handle_packet_event(&mut self, event: crate::systing::types::packet_event) {
        use crate::systing::types::{network_protocol, packet_event_type};

        let tgidpid = event.task.tgidpid;

        let conn_id = ConnectionId {
            protocol: network_protocol::NETWORK_TCP.0, // Packets are always TCP
            af: event.af.0,
            dest_addr: event.dest_addr,
            dest_port: event.dest_port,
        };

        let pkt_event = PacketEvent {
            start_ts: event.start_ts,
            end_ts: event.end_ts,
            seq: event.seq,
            length: event.length,
            tcp_flags: event.tcp_flags,
        };

        let conn_events = self
            .network_events
            .entry(tgidpid)
            .or_default()
            .entry(conn_id)
            .or_default();

        if event.event_type.0 == packet_event_type::PACKET_ENQUEUE.0 {
            conn_events.enqueue_packets.push(pkt_event);
        } else if event.event_type.0 == packet_event_type::PACKET_SEND.0 {
            conn_events.send_packets.push(pkt_event);
        }
    }

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

    /// Resolve an IP address to a hostname, with caching and fallback to IP string.
    /// Returns the hostname if resolution succeeds, otherwise returns the IP address as a string.
    fn resolve_hostname(&mut self, addr: IpAddr) -> &str {
        self.hostname_cache.entry(addr).or_insert_with(|| {
            // Attempt reverse DNS lookup
            match dns_lookup::lookup_addr(&addr) {
                Ok(name) => name,
                Err(err) => {
                    // Log failure and fallback to IP address string
                    tracing::debug!("DNS lookup failed for {}: {}", addr, err);
                    addr.to_string()
                }
            }
        })
    }

    /// Format a connection identifier with hostname resolution.
    /// Returns a string like "TCP:example.com:8080" or "TCP:127.0.0.1:8080" (if lookup fails)
    fn format_connection_name(&mut self, conn_id: &ConnectionId) -> String {
        let protocol_str =
            if conn_id.protocol == crate::systing::types::network_protocol::NETWORK_TCP.0 {
                "TCP"
            } else if conn_id.protocol == crate::systing::types::network_protocol::NETWORK_UDP.0 {
                "UDP"
            } else {
                "UNKNOWN"
            };

        let addr = conn_id.ip_addr();
        let host = self.resolve_hostname(addr);
        format!("{}:{}:{}", protocol_str, host, conn_id.dest_port)
    }

    fn get_or_create_event_name_iid(&mut self, name: String, id_counter: &Arc<AtomicUsize>) -> u64 {
        if let Some(&iid) = self.event_name_ids.get(&name) {
            return iid;
        }

        let iid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;
        self.event_name_ids.insert(name, iid);
        iid
    }

    fn add_packet_slice_events(
        &self,
        packets: &mut Vec<TracePacket>,
        sequence_id: u32,
        track_uuid: u64,
        name_iid: u64,
        packet_events: &[PacketEvent],
    ) {
        for pkt in packet_events {
            let mut begin_event = TrackEvent::default();
            begin_event.set_type(Type::TYPE_SLICE_BEGIN);
            begin_event.set_name_iid(name_iid);
            begin_event.set_track_uuid(track_uuid);

            let mut seq_annotation = DebugAnnotation::default();
            seq_annotation.set_name("seq".to_string());
            seq_annotation.set_uint_value(pkt.seq as u64);
            begin_event.debug_annotations.push(seq_annotation);

            let mut len_annotation = DebugAnnotation::default();
            len_annotation.set_name("length".to_string());
            len_annotation.set_uint_value(pkt.length as u64);
            begin_event.debug_annotations.push(len_annotation);

            let mut flags_annotation = DebugAnnotation::default();
            flags_annotation.set_name("flags".to_string());
            flags_annotation.set_string_value(Self::format_tcp_flags(pkt.tcp_flags));
            begin_event.debug_annotations.push(flags_annotation);

            let mut begin_packet = TracePacket::default();
            begin_packet.set_timestamp(pkt.start_ts);
            begin_packet.set_track_event(begin_event);
            begin_packet.set_trusted_packet_sequence_id(sequence_id);
            packets.push(begin_packet);

            let mut end_event = TrackEvent::default();
            end_event.set_type(Type::TYPE_SLICE_END);
            end_event.set_track_uuid(track_uuid);

            let mut end_packet = TracePacket::default();
            end_packet.set_timestamp(pkt.end_ts);
            end_packet.set_track_event(end_event);
            end_packet.set_trusted_packet_sequence_id(sequence_id);
            packets.push(end_packet);
        }
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

        // Collect all unique connection IDs and protocol/operation combinations
        use crate::systing::types::network_operation;
        let mut protocol_ops_used = std::collections::HashSet::new();
        let mut connection_ids = Vec::new();
        let mut has_enqueue_packets = false;
        let mut has_send_packets = false;

        for connections in self.network_events.values() {
            for (conn_id, events) in connections.iter() {
                connection_ids.push(*conn_id);

                if !events.sends.is_empty() {
                    protocol_ops_used.insert((conn_id.protocol, network_operation::NETWORK_SEND.0));
                }
                if !events.recvs.is_empty() {
                    protocol_ops_used.insert((conn_id.protocol, network_operation::NETWORK_RECV.0));
                }
                if !events.enqueue_packets.is_empty() {
                    has_enqueue_packets = true;
                }
                if !events.send_packets.is_empty() {
                    has_send_packets = true;
                }
            }
        }

        // Resolve hostnames before packet generation to cache them
        let mut connection_names = HashMap::new();
        for conn_id in connection_ids {
            connection_names
                .entry(conn_id)
                .or_insert_with(|| self.format_connection_name(&conn_id));
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

        // Create IIDs for packet events if we have any
        if has_enqueue_packets {
            self.get_or_create_event_name_iid("TCP packet_enqueue".to_string(), id_counter);
        }
        if has_send_packets {
            self.get_or_create_event_name_iid("TCP packet_send".to_string(), id_counter);
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
                if events.sends.is_empty()
                    && events.recvs.is_empty()
                    && events.enqueue_packets.is_empty()
                    && events.send_packets.is_empty()
                {
                    continue;
                }

                // Create connection track group
                let conn_group_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;

                let mut conn_group_desc = TrackDescriptor::default();
                conn_group_desc.set_uuid(conn_group_uuid);
                conn_group_desc.set_name(connection_names[conn_id].clone());
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
                        // Slice begin event
                        let mut begin_event = TrackEvent::default();
                        begin_event.set_type(Type::TYPE_SLICE_BEGIN);
                        begin_event.set_name_iid(send_name_iid);
                        begin_event.set_track_uuid(send_track_uuid);

                        // Add debug annotation for the size
                        let mut debug_annotation = DebugAnnotation::default();
                        debug_annotation.set_name("bytes".to_string());
                        debug_annotation.set_uint_value(event.bytes as u64);
                        begin_event.debug_annotations.push(debug_annotation);

                        // Add seq annotation for TCP sends
                        if event.sendmsg_seq > 0 {
                            let mut seq_annotation = DebugAnnotation::default();
                            seq_annotation.set_name("seq".to_string());
                            seq_annotation.set_uint_value(event.sendmsg_seq as u64);
                            begin_event.debug_annotations.push(seq_annotation);
                        }

                        let mut begin_packet = TracePacket::default();
                        begin_packet.set_timestamp(event.start_ts);
                        begin_packet.set_track_event(begin_event);
                        begin_packet.set_trusted_packet_sequence_id(sequence_id);
                        packets.push(begin_packet);

                        // Slice end event
                        let mut end_event = TrackEvent::default();
                        end_event.set_type(Type::TYPE_SLICE_END);
                        end_event.set_track_uuid(send_track_uuid);

                        let mut end_packet = TracePacket::default();
                        end_packet.set_timestamp(event.end_ts);
                        end_packet.set_track_event(end_event);
                        end_packet.set_trusted_packet_sequence_id(sequence_id);
                        packets.push(end_packet);
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

                // Create packets track if we have any packet events (TCP only)
                if !events.enqueue_packets.is_empty() || !events.send_packets.is_empty() {
                    let packets_track_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;

                    let mut packets_track_desc = TrackDescriptor::default();
                    packets_track_desc.set_uuid(packets_track_uuid);
                    packets_track_desc.set_name("Packets".to_string());
                    packets_track_desc.set_parent_uuid(conn_group_uuid);

                    let mut packets_track_packet = TracePacket::default();
                    packets_track_packet.set_track_descriptor(packets_track_desc);
                    packets.push(packets_track_packet);

                    if !events.enqueue_packets.is_empty() {
                        let enqueue_iid = *self
                            .event_name_ids
                            .get("TCP packet_enqueue")
                            .expect("enqueue packet event name should exist after IID generation");

                        self.add_packet_slice_events(
                            &mut packets,
                            sequence_id,
                            packets_track_uuid,
                            enqueue_iid,
                            &events.enqueue_packets,
                        );
                    }

                    if !events.send_packets.is_empty() {
                        let send_iid = *self
                            .event_name_ids
                            .get("TCP packet_send")
                            .expect("send packet event name should exist after IID generation");

                        self.add_packet_slice_events(
                            &mut packets,
                            sequence_id,
                            packets_track_uuid,
                            send_iid,
                            &events.send_packets,
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
        self.hostname_cache.clear();

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
            af: event.af.0,
            dest_addr: event.dest_addr,
            dest_port: event.dest_port,
        };

        let net_event = NetworkEvent {
            start_ts: event.start_ts,
            end_ts: event.end_ts,
            bytes: event.bytes,
            sendmsg_seq: event.sendmsg_seq,
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
        use crate::systing::types::{network_address_family, network_operation};

        let mut recorder = NetworkRecorder::default();

        let mut dest_addr = [0u8; 16];
        dest_addr[0..4].copy_from_slice(&[127, 0, 0, 1]); // 127.0.0.1 in network byte order

        let event = network_event {
            start_ts: 1000,
            end_ts: 2000,
            task: create_test_task_info(100, 101),
            protocol: test_protocol_tcp(),
            operation: network_operation::NETWORK_SEND,
            af: network_address_family::NETWORK_AF_INET,
            dest_addr,
            dest_port: 8080,
            bytes: 1024,
            sendmsg_seq: 0,
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
            af: network_address_family::NETWORK_AF_INET.0,
            dest_addr,
            dest_port: 8080,
        };
        assert!(connections.contains_key(&conn_id));
        assert_eq!(connections[&conn_id].sends.len(), 1);
        assert_eq!(connections[&conn_id].sends[0].bytes, 1024);
        assert_eq!(connections[&conn_id].recvs.len(), 0);
    }

    #[test]
    fn test_network_recorder_multiple_sends() {
        use crate::systing::types::{network_address_family, network_operation};

        let mut recorder = NetworkRecorder::default();

        let mut dest_addr = [0u8; 16];
        dest_addr[0..4].copy_from_slice(&[127, 0, 0, 1]); // 127.0.0.1 in network byte order

        // Send 1
        let event1 = network_event {
            start_ts: 1000,
            end_ts: 1500,
            task: create_test_task_info(100, 101),
            protocol: test_protocol_tcp(),
            operation: network_operation::NETWORK_SEND,
            af: network_address_family::NETWORK_AF_INET,
            dest_addr,
            dest_port: 8080,
            bytes: 1024,
            sendmsg_seq: 0,
            cpu: 0,
            ..Default::default()
        };

        // Send 2 to same connection
        let event2 = network_event {
            start_ts: 2000,
            end_ts: 2500,
            task: create_test_task_info(100, 101),
            protocol: test_protocol_tcp(),
            operation: network_operation::NETWORK_SEND,
            af: network_address_family::NETWORK_AF_INET,
            dest_addr,
            dest_port: 8080,
            bytes: 2048,
            sendmsg_seq: 0,
            cpu: 0,
            ..Default::default()
        };

        recorder.handle_event(event1);
        recorder.handle_event(event2);

        let tgidpid = (100u64 << 32) | 101u64;
        let connections = &recorder.network_events[&tgidpid];
        let conn_id = ConnectionId {
            protocol: network_protocol::NETWORK_TCP.0,
            af: network_address_family::NETWORK_AF_INET.0,
            dest_addr,
            dest_port: 8080,
        };

        assert_eq!(connections[&conn_id].sends.len(), 2);
        assert_eq!(connections[&conn_id].sends[0].bytes, 1024);
        assert_eq!(connections[&conn_id].sends[1].bytes, 2048);
    }

    #[test]
    fn test_network_recorder_multiple_connections() {
        use crate::systing::types::{network_address_family, network_operation};

        let mut recorder = NetworkRecorder::default();

        let mut dest_addr = [0u8; 16];
        dest_addr[0..4].copy_from_slice(&[127, 0, 0, 1]); // 127.0.0.1 in network byte order

        // TCP send
        let event1 = network_event {
            start_ts: 1000,
            end_ts: 1500,
            task: create_test_task_info(100, 101),
            protocol: test_protocol_tcp(),
            operation: network_operation::NETWORK_SEND,
            af: network_address_family::NETWORK_AF_INET,
            dest_addr,
            dest_port: 8080,
            bytes: 1024,
            sendmsg_seq: 0,
            cpu: 0,
            ..Default::default()
        };

        // UDP send
        let event2 = network_event {
            start_ts: 2000,
            end_ts: 2500,
            task: create_test_task_info(100, 101),
            protocol: test_protocol_udp(),
            operation: network_operation::NETWORK_SEND,
            af: network_address_family::NETWORK_AF_INET,
            dest_addr,
            dest_port: 9090,
            bytes: 512,
            sendmsg_seq: 0,
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
        use crate::systing::types::{network_address_family, network_operation};

        let mut recorder = NetworkRecorder::default();
        let mut thread_uuids = HashMap::new();
        thread_uuids.insert(101, 500);
        let pid_uuids: HashMap<i32, u64> = HashMap::new();
        let id_counter = Arc::new(AtomicUsize::new(1000));

        let mut dest_addr = [0u8; 16];
        dest_addr[0..4].copy_from_slice(&[127, 0, 0, 1]); // 127.0.0.1 in network byte order

        let event = network_event {
            start_ts: 1000,
            end_ts: 2000,
            task: create_test_task_info(100, 101),
            protocol: test_protocol_tcp(),
            operation: network_operation::NETWORK_SEND,
            af: network_address_family::NETWORK_AF_INET,
            dest_addr,
            dest_port: 8080,
            bytes: 1024,
            sendmsg_seq: 0,
            cpu: 0,
            ..Default::default()
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
        use crate::systing::types::{network_address_family, network_operation};

        let mut recorder = NetworkRecorder::default();

        let mut dest_addr = [0u8; 16];
        dest_addr[0..4].copy_from_slice(&[127, 0, 0, 1]); // 127.0.0.1 in network byte order

        // TCP send
        let send_event = network_event {
            start_ts: 1000,
            end_ts: 1500,
            task: create_test_task_info(100, 101),
            protocol: test_protocol_tcp(),
            operation: network_operation::NETWORK_SEND,
            af: network_address_family::NETWORK_AF_INET,
            dest_addr,
            dest_port: 8080,
            bytes: 1024,
            sendmsg_seq: 0,
            cpu: 0,
            ..Default::default()
        };

        // TCP receive from same connection
        let recv_event = network_event {
            start_ts: 2000,
            end_ts: 2500,
            task: create_test_task_info(100, 101),
            protocol: test_protocol_tcp(),
            operation: network_operation::NETWORK_RECV,
            af: network_address_family::NETWORK_AF_INET,
            dest_addr,
            dest_port: 8080,
            bytes: 512,
            sendmsg_seq: 0,
            cpu: 0,
            ..Default::default()
        };

        recorder.handle_event(send_event);
        recorder.handle_event(recv_event);

        let tgidpid = (100u64 << 32) | 101u64;
        let connections = &recorder.network_events[&tgidpid];
        assert_eq!(connections.len(), 1);

        let conn_id = ConnectionId {
            protocol: network_protocol::NETWORK_TCP.0,
            af: network_address_family::NETWORK_AF_INET.0,
            dest_addr,
            dest_port: 8080,
        };
        assert!(connections.contains_key(&conn_id));
        assert_eq!(connections[&conn_id].sends.len(), 1);
        assert_eq!(connections[&conn_id].sends[0].bytes, 1024);
        assert_eq!(connections[&conn_id].recvs.len(), 1);
        assert_eq!(connections[&conn_id].recvs[0].bytes, 512);
    }

    #[test]
    fn test_network_recorder_ipv6_tcp_send() {
        use crate::systing::types::{network_address_family, network_operation};

        let mut recorder = NetworkRecorder::default();

        // IPv6 address 2001:db8::1
        let mut dest_addr = [0u8; 16];
        dest_addr.copy_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]);

        let event = network_event {
            start_ts: 1000,
            end_ts: 2000,
            task: create_test_task_info(100, 101),
            protocol: test_protocol_tcp(),
            operation: network_operation::NETWORK_SEND,
            af: network_address_family::NETWORK_AF_INET6,
            dest_addr,
            dest_port: 8080,
            bytes: 2048,
            sendmsg_seq: 0,
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
            af: network_address_family::NETWORK_AF_INET6.0,
            dest_addr,
            dest_port: 8080,
        };
        assert!(connections.contains_key(&conn_id));
        assert_eq!(connections[&conn_id].sends.len(), 1);
        assert_eq!(connections[&conn_id].sends[0].bytes, 2048);
        assert_eq!(connections[&conn_id].recvs.len(), 0);

        // Verify IPv6 address parsing
        let ip = conn_id.ip_addr();
        assert!(matches!(ip, IpAddr::V6(_)));
        assert_eq!(ip.to_string(), "2001:db8::1");
    }

    #[test]
    fn test_network_recorder_ipv6_udp_send() {
        use crate::systing::types::{network_address_family, network_operation};

        let mut recorder = NetworkRecorder::default();

        // IPv6 localhost ::1
        let mut dest_addr = [0u8; 16];
        dest_addr[15] = 1; // ::1

        let event = network_event {
            start_ts: 1000,
            end_ts: 2000,
            task: create_test_task_info(100, 101),
            protocol: test_protocol_udp(),
            operation: network_operation::NETWORK_SEND,
            af: network_address_family::NETWORK_AF_INET6,
            dest_addr,
            dest_port: 9090,
            bytes: 512,
            sendmsg_seq: 0,
            cpu: 0,
            ..Default::default()
        };

        recorder.handle_event(event);

        let tgidpid = (100u64 << 32) | 101u64;
        let connections = &recorder.network_events[&tgidpid];
        assert_eq!(connections.len(), 1);

        let conn_id = ConnectionId {
            protocol: network_protocol::NETWORK_UDP.0,
            af: network_address_family::NETWORK_AF_INET6.0,
            dest_addr,
            dest_port: 9090,
        };
        assert!(connections.contains_key(&conn_id));
        assert_eq!(connections[&conn_id].sends.len(), 1);
        assert_eq!(connections[&conn_id].sends[0].bytes, 512);

        // Verify IPv6 localhost address
        let ip = conn_id.ip_addr();
        assert_eq!(ip.to_string(), "::1");
    }

    #[test]
    fn test_network_recorder_ipv6_and_ipv4_mixed() {
        use crate::systing::types::{network_address_family, network_operation};

        let mut recorder = NetworkRecorder::default();

        // IPv4 address 127.0.0.1
        let mut ipv4_addr = [0u8; 16];
        ipv4_addr[0..4].copy_from_slice(&[127, 0, 0, 1]);

        // IPv6 address 2001:db8::2
        let mut ipv6_addr = [0u8; 16];
        ipv6_addr.copy_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ]);

        // IPv4 TCP send
        let ipv4_event = network_event {
            start_ts: 1000,
            end_ts: 1500,
            task: create_test_task_info(100, 101),
            protocol: test_protocol_tcp(),
            operation: network_operation::NETWORK_SEND,
            af: network_address_family::NETWORK_AF_INET,
            dest_addr: ipv4_addr,
            dest_port: 8080,
            bytes: 1024,
            sendmsg_seq: 0,
            cpu: 0,
            ..Default::default()
        };

        // IPv6 TCP send
        let ipv6_event = network_event {
            start_ts: 2000,
            end_ts: 2500,
            task: create_test_task_info(100, 101),
            protocol: test_protocol_tcp(),
            operation: network_operation::NETWORK_SEND,
            af: network_address_family::NETWORK_AF_INET6,
            dest_addr: ipv6_addr,
            dest_port: 8080,
            bytes: 2048,
            sendmsg_seq: 0,
            cpu: 0,
            ..Default::default()
        };

        recorder.handle_event(ipv4_event);
        recorder.handle_event(ipv6_event);

        let tgidpid = (100u64 << 32) | 101u64;
        let connections = &recorder.network_events[&tgidpid];

        // Should have 2 distinct connections (IPv4 and IPv6 are different)
        assert_eq!(connections.len(), 2);

        // Verify IPv4 connection
        let ipv4_conn_id = ConnectionId {
            protocol: network_protocol::NETWORK_TCP.0,
            af: network_address_family::NETWORK_AF_INET.0,
            dest_addr: ipv4_addr,
            dest_port: 8080,
        };
        assert!(connections.contains_key(&ipv4_conn_id));
        assert_eq!(connections[&ipv4_conn_id].sends[0].bytes, 1024);

        // Verify IPv6 connection
        let ipv6_conn_id = ConnectionId {
            protocol: network_protocol::NETWORK_TCP.0,
            af: network_address_family::NETWORK_AF_INET6.0,
            dest_addr: ipv6_addr,
            dest_port: 8080,
        };
        assert!(connections.contains_key(&ipv6_conn_id));
        assert_eq!(connections[&ipv6_conn_id].sends[0].bytes, 2048);
    }

    #[test]
    fn test_network_recorder_ipv6_address_formatting() {
        use crate::systing::types::network_address_family;

        // Test various IPv6 addresses
        let test_cases = vec![
            (
                [
                    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x01,
                ],
                "2001:db8::1",
            ),
            (
                [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                "::1", // localhost
            ),
            (
                [
                    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x5e, 0xff, 0xfe,
                    0x00, 0x00, 0x53,
                ],
                "fe80::200:5eff:fe00:53",
            ),
        ];

        for (addr_bytes, expected_str) in test_cases {
            let conn_id = ConnectionId {
                protocol: network_protocol::NETWORK_TCP.0,
                af: network_address_family::NETWORK_AF_INET6.0,
                dest_addr: addr_bytes,
                dest_port: 443,
            };

            let ip = conn_id.ip_addr();
            assert_eq!(ip.to_string(), expected_str);

            // Test Display formatting for ConnectionId
            let display_str = conn_id.to_string();
            assert!(display_str.starts_with("TCP:"));
            assert!(display_str.contains(expected_str));
            assert!(display_str.contains(":443"));
        }
    }

    #[test]
    fn test_network_recorder_ipv6_sends_and_receives() {
        use crate::systing::types::{network_address_family, network_operation};

        let mut recorder = NetworkRecorder::default();

        // IPv6 address 2001:db8::1
        let mut dest_addr = [0u8; 16];
        dest_addr.copy_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]);

        // TCP send
        let send_event = network_event {
            start_ts: 1000,
            end_ts: 1500,
            task: create_test_task_info(100, 101),
            protocol: test_protocol_tcp(),
            operation: network_operation::NETWORK_SEND,
            af: network_address_family::NETWORK_AF_INET6,
            dest_addr,
            dest_port: 8080,
            bytes: 1024,
            sendmsg_seq: 0,
            cpu: 0,
            ..Default::default()
        };

        // TCP receive from same connection
        let recv_event = network_event {
            start_ts: 2000,
            end_ts: 2500,
            task: create_test_task_info(100, 101),
            protocol: test_protocol_tcp(),
            operation: network_operation::NETWORK_RECV,
            af: network_address_family::NETWORK_AF_INET6,
            dest_addr,
            dest_port: 8080,
            bytes: 512,
            sendmsg_seq: 0,
            cpu: 0,
            ..Default::default()
        };

        recorder.handle_event(send_event);
        recorder.handle_event(recv_event);

        let tgidpid = (100u64 << 32) | 101u64;
        let connections = &recorder.network_events[&tgidpid];
        assert_eq!(connections.len(), 1);

        let conn_id = ConnectionId {
            protocol: network_protocol::NETWORK_TCP.0,
            af: network_address_family::NETWORK_AF_INET6.0,
            dest_addr,
            dest_port: 8080,
        };
        assert!(connections.contains_key(&conn_id));
        assert_eq!(connections[&conn_id].sends.len(), 1);
        assert_eq!(connections[&conn_id].sends[0].bytes, 1024);
        assert_eq!(connections[&conn_id].recvs.len(), 1);
        assert_eq!(connections[&conn_id].recvs[0].bytes, 512);
    }
}
