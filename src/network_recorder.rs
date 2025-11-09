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

#[derive(Clone, Copy)]
struct NetworkEvent {
    start_ts: u64,
    end_ts: u64,
    bytes: u32,
    sendmsg_seq: u32,
}

#[derive(Clone, Copy)]
struct PacketEvent {
    start_ts: u64,
    end_ts: u64,
    seq: u32,
    length: u32,
    tcp_flags: u8,
}

enum EventEntry {
    Send(NetworkEvent),
    Recv(NetworkEvent),
    TcpEnqueue(PacketEvent),
    TcpRcvEstablished(PacketEvent),
    TcpQueueRcv(PacketEvent),
    TcpBufferQueue(PacketEvent),
    UdpSend(PacketEvent),
    UdpRcv(PacketEvent),
    UdpEnqueue(PacketEvent),
    SharedSend(PacketEvent),
}

#[derive(Default)]
struct ConnectionEvents {
    events: Vec<EventEntry>,
}

impl ConnectionEvents {
    fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    fn iter_sends(&self) -> impl Iterator<Item = &NetworkEvent> {
        self.events.iter().filter_map(|e| match e {
            EventEntry::Send(evt) => Some(evt),
            _ => None,
        })
    }

    #[allow(dead_code)]
    fn iter_recvs(&self) -> impl Iterator<Item = &NetworkEvent> {
        self.events.iter().filter_map(|e| match e {
            EventEntry::Recv(evt) => Some(evt),
            _ => None,
        })
    }

    #[allow(dead_code)]
    fn iter_tcp_enqueue_packets(&self) -> impl Iterator<Item = &PacketEvent> {
        self.events.iter().filter_map(|e| match e {
            EventEntry::TcpEnqueue(pkt) => Some(pkt),
            _ => None,
        })
    }

    #[allow(dead_code)]
    fn iter_tcp_rcv_established_packets(&self) -> impl Iterator<Item = &PacketEvent> {
        self.events.iter().filter_map(|e| match e {
            EventEntry::TcpRcvEstablished(pkt) => Some(pkt),
            _ => None,
        })
    }

    #[allow(dead_code)]
    fn iter_tcp_queue_rcv_packets(&self) -> impl Iterator<Item = &PacketEvent> {
        self.events.iter().filter_map(|e| match e {
            EventEntry::TcpQueueRcv(pkt) => Some(pkt),
            _ => None,
        })
    }

    #[allow(dead_code)]
    fn iter_tcp_buffer_queue_packets(&self) -> impl Iterator<Item = &PacketEvent> {
        self.events.iter().filter_map(|e| match e {
            EventEntry::TcpBufferQueue(pkt) => Some(pkt),
            _ => None,
        })
    }

    #[allow(dead_code)]
    fn iter_udp_send_packets(&self) -> impl Iterator<Item = &PacketEvent> {
        self.events.iter().filter_map(|e| match e {
            EventEntry::UdpSend(pkt) => Some(pkt),
            _ => None,
        })
    }

    #[allow(dead_code)]
    fn iter_udp_rcv_packets(&self) -> impl Iterator<Item = &PacketEvent> {
        self.events.iter().filter_map(|e| match e {
            EventEntry::UdpRcv(pkt) => Some(pkt),
            _ => None,
        })
    }

    #[allow(dead_code)]
    fn iter_udp_enqueue_packets(&self) -> impl Iterator<Item = &PacketEvent> {
        self.events.iter().filter_map(|e| match e {
            EventEntry::UdpEnqueue(pkt) => Some(pkt),
            _ => None,
        })
    }

    #[allow(dead_code)]
    fn iter_shared_send_packets(&self) -> impl Iterator<Item = &PacketEvent> {
        self.events.iter().filter_map(|e| match e {
            EventEntry::SharedSend(pkt) => Some(pkt),
            _ => None,
        })
    }
}

#[derive(Default)]
struct DnsStats {
    attempted: usize,
    ipv4_succeeded: usize,
    ipv4_failed: usize,
    ipv6_succeeded: usize,
    ipv6_failed: usize,
}

impl DnsStats {
    fn succeeded(&self) -> usize {
        self.ipv4_succeeded + self.ipv6_succeeded
    }

    fn success_rate(&self) -> f64 {
        if self.attempted == 0 {
            0.0
        } else {
            (self.succeeded() as f64 / self.attempted as f64) * 100.0
        }
    }
}

#[derive(Default)]
pub struct NetworkRecorder {
    pub ringbuf: RingBuffer<network_event>,
    network_events: HashMap<u64, HashMap<ConnectionId, ConnectionEvents>>,
    event_name_ids: HashMap<String, u64>,
    hostname_cache: HashMap<IpAddr, String>,
    dns_stats: DnsStats,
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
        use crate::systing::types::packet_event_type;

        let tgidpid = event.task.tgidpid;

        // Use protocol field from event (explicitly set in BPF code)
        let protocol = event.protocol.0;

        let conn_id = ConnectionId {
            protocol,
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

        // TCP packet events
        if event.event_type.0 == packet_event_type::PACKET_ENQUEUE.0 {
            conn_events.events.push(EventEntry::TcpEnqueue(pkt_event));
        } else if event.event_type.0 == packet_event_type::PACKET_SEND.0 {
            // PACKET_SEND is shared by TCP and UDP for qdisc->NIC transmission
            conn_events.events.push(EventEntry::SharedSend(pkt_event));
        } else if event.event_type.0 == packet_event_type::PACKET_RCV_ESTABLISHED.0 {
            conn_events
                .events
                .push(EventEntry::TcpRcvEstablished(pkt_event));
        } else if event.event_type.0 == packet_event_type::PACKET_QUEUE_RCV.0 {
            conn_events.events.push(EventEntry::TcpQueueRcv(pkt_event));
        } else if event.event_type.0 == packet_event_type::PACKET_BUFFER_QUEUE.0 {
            conn_events
                .events
                .push(EventEntry::TcpBufferQueue(pkt_event));
        }
        // UDP packet events
        else if event.event_type.0 == packet_event_type::PACKET_UDP_SEND.0 {
            conn_events.events.push(EventEntry::UdpSend(pkt_event));
        } else if event.event_type.0 == packet_event_type::PACKET_UDP_RCV.0 {
            conn_events.events.push(EventEntry::UdpRcv(pkt_event));
        } else if event.event_type.0 == packet_event_type::PACKET_UDP_ENQUEUE.0 {
            conn_events.events.push(EventEntry::UdpEnqueue(pkt_event));
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

    fn resolve_hostname(&mut self, addr: IpAddr) -> &str {
        self.hostname_cache.entry(addr).or_insert_with(|| {
            self.dns_stats.attempted += 1;

            let lookup_addr = addr.to_canonical();

            let (succeeded, hostname) = match dns_lookup::lookup_addr(&lookup_addr) {
                Ok(name) => {
                    tracing::debug!("DNS lookup succeeded for {}: {}", lookup_addr, name);
                    (true, name)
                }
                Err(err) => {
                    tracing::debug!("DNS lookup failed for {}: {}", lookup_addr, err);
                    (false, lookup_addr.to_string())
                }
            };

            match (lookup_addr, succeeded) {
                (IpAddr::V4(_), true) => self.dns_stats.ipv4_succeeded += 1,
                (IpAddr::V4(_), false) => self.dns_stats.ipv4_failed += 1,
                (IpAddr::V6(_), true) => self.dns_stats.ipv6_succeeded += 1,
                (IpAddr::V6(_), false) => self.dns_stats.ipv6_failed += 1,
            }

            hostname
        })
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

            // Only show seq annotation for TCP packets (where seq != 0)
            if pkt.seq != 0 {
                let mut seq_annotation = DebugAnnotation::default();
                seq_annotation.set_name("seq".to_string());
                seq_annotation.set_uint_value(pkt.seq as u64);
                begin_event.debug_annotations.push(seq_annotation);
            }

            let mut len_annotation = DebugAnnotation::default();
            len_annotation.set_name("length".to_string());
            len_annotation.set_uint_value(pkt.length as u64);
            begin_event.debug_annotations.push(len_annotation);

            // Only show TCP flags annotation for TCP packets (where flags != 0)
            if pkt.tcp_flags != 0 {
                let mut flags_annotation = DebugAnnotation::default();
                flags_annotation.set_name("flags".to_string());
                flags_annotation.set_string_value(Self::format_tcp_flags(pkt.tcp_flags));
                begin_event.debug_annotations.push(flags_annotation);
            }

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
        use crate::systing::types::network_operation;

        let mut packets = Vec::new();
        let sequence_id = id_counter.fetch_add(1, Ordering::Relaxed) as u32;
        let mut protocol_ops_used = std::collections::HashSet::new();
        let mut connection_ids = Vec::new();

        for connections in self.network_events.values() {
            for (conn_id, events) in connections.iter() {
                connection_ids.push(*conn_id);
                if events.iter_sends().next().is_some() {
                    protocol_ops_used.insert((conn_id.protocol, network_operation::NETWORK_SEND.0));
                }
                if events.iter_recvs().next().is_some() {
                    protocol_ops_used.insert((conn_id.protocol, network_operation::NETWORK_RECV.0));
                }
            }
        }

        for conn_id in &connection_ids {
            self.resolve_hostname(conn_id.ip_addr());
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

        // Create IIDs for packet event types unconditionally (only 9 strings)
        self.get_or_create_event_name_iid("TCP packet_enqueue".to_string(), id_counter);
        self.get_or_create_event_name_iid("TCP packet_send".to_string(), id_counter);
        self.get_or_create_event_name_iid("TCP packet_rcv_established".to_string(), id_counter);
        self.get_or_create_event_name_iid("TCP packet_queue_rcv".to_string(), id_counter);
        self.get_or_create_event_name_iid("TCP buffer_queue".to_string(), id_counter);
        self.get_or_create_event_name_iid("UDP send".to_string(), id_counter);
        self.get_or_create_event_name_iid("UDP packet_send".to_string(), id_counter);
        self.get_or_create_event_name_iid("UDP receive".to_string(), id_counter);
        self.get_or_create_event_name_iid("UDP enqueue".to_string(), id_counter);
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
                if events.is_empty() {
                    continue;
                }

                // Create connection track group
                let conn_group_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;

                let mut conn_group_desc = TrackDescriptor::default();
                conn_group_desc.set_uuid(conn_group_uuid);
                let protocol_str = if conn_id.protocol
                    == crate::systing::types::network_protocol::NETWORK_TCP.0
                {
                    "TCP"
                } else if conn_id.protocol == crate::systing::types::network_protocol::NETWORK_UDP.0
                {
                    "UDP"
                } else {
                    "UNKNOWN"
                };
                let hostname = self
                    .hostname_cache
                    .get(&conn_id.ip_addr())
                    .map(|s| s.as_str())
                    .unwrap_or_else(|| "unknown");
                conn_group_desc.set_name(format!(
                    "{}:{}:{}",
                    protocol_str, hostname, conn_id.dest_port
                ));
                conn_group_desc.set_parent_uuid(thread_group_uuid);

                let mut conn_group_packet = TracePacket::default();
                conn_group_packet.set_track_descriptor(conn_group_desc);
                packets.push(conn_group_packet);

                // Create send track if we have send events
                if events.iter_sends().next().is_some() {
                    let send_track_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;

                    let mut send_track_desc = TrackDescriptor::default();
                    send_track_desc.set_uuid(send_track_uuid);
                    send_track_desc.set_name("Sends".to_string());
                    send_track_desc.set_parent_uuid(conn_group_uuid);

                    let mut send_track_packet = TracePacket::default();
                    send_track_packet.set_track_descriptor(send_track_desc);
                    packets.push(send_track_packet);

                    let proto_str = Self::protocol_to_str(conn_id.protocol);
                    let send_event_name = format!("{}_send", proto_str);
                    let send_name_iid = *self.event_name_ids.get(&send_event_name).unwrap();

                    for event in events.iter_sends() {
                        let mut begin_event = TrackEvent::default();
                        begin_event.set_type(Type::TYPE_SLICE_BEGIN);
                        begin_event.set_name_iid(send_name_iid);
                        begin_event.set_track_uuid(send_track_uuid);

                        let mut debug_annotation = DebugAnnotation::default();
                        debug_annotation.set_name("bytes".to_string());
                        debug_annotation.set_uint_value(event.bytes as u64);
                        begin_event.debug_annotations.push(debug_annotation);

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
                if events.iter_recvs().next().is_some() {
                    let recv_track_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;

                    let mut recv_track_desc = TrackDescriptor::default();
                    recv_track_desc.set_uuid(recv_track_uuid);
                    recv_track_desc.set_name("Receives".to_string());
                    recv_track_desc.set_parent_uuid(conn_group_uuid);

                    let mut recv_track_packet = TracePacket::default();
                    recv_track_packet.set_track_descriptor(recv_track_desc);
                    packets.push(recv_track_packet);

                    let proto_str = Self::protocol_to_str(conn_id.protocol);
                    let recv_event_name = format!("{}_recv", proto_str);
                    let recv_name_iid = *self.event_name_ids.get(&recv_event_name).unwrap();
                    for event in events.iter_recvs() {
                        self.add_slice_events(
                            &mut packets,
                            sequence_id,
                            recv_track_uuid,
                            recv_name_iid,
                            event,
                        );
                    }
                }

                // Create TCP Packets track if we have TCP packet events
                let is_tcp =
                    conn_id.protocol == crate::systing::types::network_protocol::NETWORK_TCP.0;
                let has_tcp_packets = is_tcp
                    && (events.iter_tcp_enqueue_packets().next().is_some()
                        || events.iter_shared_send_packets().next().is_some()
                        || events.iter_tcp_rcv_established_packets().next().is_some()
                        || events.iter_tcp_queue_rcv_packets().next().is_some()
                        || events.iter_tcp_buffer_queue_packets().next().is_some());

                if has_tcp_packets {
                    let packets_track_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;

                    let mut packets_track_desc = TrackDescriptor::default();
                    packets_track_desc.set_uuid(packets_track_uuid);
                    packets_track_desc.set_name("Packets".to_string());
                    packets_track_desc.set_parent_uuid(conn_group_uuid);

                    let mut packets_track_packet = TracePacket::default();
                    packets_track_packet.set_track_descriptor(packets_track_desc);
                    packets.push(packets_track_packet);

                    let enqueue_pkts: Vec<_> = events.iter_tcp_enqueue_packets().copied().collect();
                    if !enqueue_pkts.is_empty() {
                        let enqueue_iid = *self.event_name_ids.get("TCP packet_enqueue").unwrap();
                        self.add_packet_slice_events(
                            &mut packets,
                            sequence_id,
                            packets_track_uuid,
                            enqueue_iid,
                            &enqueue_pkts,
                        );
                    }

                    let send_pkts: Vec<_> = events.iter_shared_send_packets().copied().collect();
                    if !send_pkts.is_empty() {
                        let send_iid = *self.event_name_ids.get("TCP packet_send").unwrap();
                        self.add_packet_slice_events(
                            &mut packets,
                            sequence_id,
                            packets_track_uuid,
                            send_iid,
                            &send_pkts,
                        );
                    }

                    let rcv_est_pkts: Vec<_> =
                        events.iter_tcp_rcv_established_packets().copied().collect();
                    if !rcv_est_pkts.is_empty() {
                        let rcv_established_iid = *self
                            .event_name_ids
                            .get("TCP packet_rcv_established")
                            .unwrap();
                        self.add_packet_slice_events(
                            &mut packets,
                            sequence_id,
                            packets_track_uuid,
                            rcv_established_iid,
                            &rcv_est_pkts,
                        );
                    }

                    let queue_rcv_pkts: Vec<_> =
                        events.iter_tcp_queue_rcv_packets().copied().collect();
                    if !queue_rcv_pkts.is_empty() {
                        let queue_rcv_iid =
                            *self.event_name_ids.get("TCP packet_queue_rcv").unwrap();
                        self.add_packet_slice_events(
                            &mut packets,
                            sequence_id,
                            packets_track_uuid,
                            queue_rcv_iid,
                            &queue_rcv_pkts,
                        );
                    }

                    let buffer_queue_pkts: Vec<_> =
                        events.iter_tcp_buffer_queue_packets().copied().collect();
                    if !buffer_queue_pkts.is_empty() {
                        let buffer_queue_iid =
                            *self.event_name_ids.get("TCP buffer_queue").unwrap();
                        self.add_packet_slice_events(
                            &mut packets,
                            sequence_id,
                            packets_track_uuid,
                            buffer_queue_iid,
                            &buffer_queue_pkts,
                        );
                    }
                }

                // Create UDP Packets track if we have UDP packet events
                let is_udp =
                    conn_id.protocol == crate::systing::types::network_protocol::NETWORK_UDP.0;
                let has_udp_packets = is_udp
                    && (events.iter_udp_send_packets().next().is_some()
                        || events.iter_shared_send_packets().next().is_some()
                        || events.iter_udp_rcv_packets().next().is_some()
                        || events.iter_udp_enqueue_packets().next().is_some());

                if has_udp_packets {
                    let packets_track_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;

                    let mut packets_track_desc = TrackDescriptor::default();
                    packets_track_desc.set_uuid(packets_track_uuid);
                    packets_track_desc.set_name("Packets".to_string());
                    packets_track_desc.set_parent_uuid(conn_group_uuid);

                    let mut packets_track_packet = TracePacket::default();
                    packets_track_packet.set_track_descriptor(packets_track_desc);
                    packets.push(packets_track_packet);

                    let udp_send_pkts: Vec<_> = events.iter_udp_send_packets().copied().collect();
                    if !udp_send_pkts.is_empty() {
                        let send_iid = *self.event_name_ids.get("UDP send").unwrap();
                        self.add_packet_slice_events(
                            &mut packets,
                            sequence_id,
                            packets_track_uuid,
                            send_iid,
                            &udp_send_pkts,
                        );
                    }

                    let udp_rcv_pkts: Vec<_> = events.iter_udp_rcv_packets().copied().collect();
                    if !udp_rcv_pkts.is_empty() {
                        let rcv_iid = *self.event_name_ids.get("UDP receive").unwrap();
                        self.add_packet_slice_events(
                            &mut packets,
                            sequence_id,
                            packets_track_uuid,
                            rcv_iid,
                            &udp_rcv_pkts,
                        );
                    }

                    let udp_enqueue_pkts: Vec<_> =
                        events.iter_udp_enqueue_packets().copied().collect();
                    if !udp_enqueue_pkts.is_empty() {
                        let enqueue_iid = *self.event_name_ids.get("UDP enqueue").unwrap();
                        self.add_packet_slice_events(
                            &mut packets,
                            sequence_id,
                            packets_track_uuid,
                            enqueue_iid,
                            &udp_enqueue_pkts,
                        );
                    }

                    // UDP also uses PACKET_SEND (SharedSend) for qdisc->NIC transmission
                    let shared_send_pkts: Vec<_> =
                        events.iter_shared_send_packets().copied().collect();
                    if !shared_send_pkts.is_empty() {
                        let send_iid = *self.event_name_ids.get("UDP packet_send").unwrap();
                        self.add_packet_slice_events(
                            &mut packets,
                            sequence_id,
                            packets_track_uuid,
                            send_iid,
                            &shared_send_pkts,
                        );
                    }
                }
            }
        }

        if self.dns_stats.attempted > 0 {
            tracing::info!(
                "DNS resolution stats: {} attempted, {} succeeded ({:.1}%), IPv4: {} succeeded / {} failed, IPv6: {} succeeded / {} failed",
                self.dns_stats.attempted,
                self.dns_stats.succeeded(),
                self.dns_stats.success_rate(),
                self.dns_stats.ipv4_succeeded,
                self.dns_stats.ipv4_failed,
                self.dns_stats.ipv6_succeeded,
                self.dns_stats.ipv6_failed
            );
        }

        self.network_events.clear();
        self.event_name_ids.clear();
        self.hostname_cache.clear();
        self.dns_stats = Default::default();

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
            conn_events.events.push(EventEntry::Send(net_event));
        } else if event.operation.0 == network_operation::NETWORK_RECV.0 {
            conn_events.events.push(EventEntry::Recv(net_event));
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
        let sends: Vec<_> = connections[&conn_id].iter_sends().collect();
        assert_eq!(sends.len(), 1);
        assert_eq!(sends[0].bytes, 1024);
        assert_eq!(connections[&conn_id].iter_recvs().count(), 0);
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

        let sends: Vec<_> = connections[&conn_id].iter_sends().collect();
        assert_eq!(sends.len(), 2);
        assert_eq!(sends[0].bytes, 1024);
        assert_eq!(sends[1].bytes, 2048);
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
        let sends: Vec<_> = connections[&conn_id].iter_sends().collect();
        assert_eq!(sends.len(), 1);
        assert_eq!(sends[0].bytes, 1024);
        let recvs: Vec<_> = connections[&conn_id].iter_recvs().collect();
        assert_eq!(recvs.len(), 1);
        assert_eq!(recvs[0].bytes, 512);
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
        let sends: Vec<_> = connections[&conn_id].iter_sends().collect();
        assert_eq!(sends.len(), 1);
        assert_eq!(sends[0].bytes, 2048);
        assert_eq!(connections[&conn_id].iter_recvs().count(), 0);

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
        let sends: Vec<_> = connections[&conn_id].iter_sends().collect();
        assert_eq!(sends.len(), 1);
        assert_eq!(sends[0].bytes, 512);

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
        let ipv4_sends: Vec<_> = connections[&ipv4_conn_id].iter_sends().collect();
        assert_eq!(ipv4_sends[0].bytes, 1024);

        // Verify IPv6 connection
        let ipv6_conn_id = ConnectionId {
            protocol: network_protocol::NETWORK_TCP.0,
            af: network_address_family::NETWORK_AF_INET6.0,
            dest_addr: ipv6_addr,
            dest_port: 8080,
        };
        assert!(connections.contains_key(&ipv6_conn_id));
        let ipv6_sends: Vec<_> = connections[&ipv6_conn_id].iter_sends().collect();
        assert_eq!(ipv6_sends[0].bytes, 2048);
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
        let sends: Vec<_> = connections[&conn_id].iter_sends().collect();
        assert_eq!(sends.len(), 1);
        assert_eq!(sends[0].bytes, 1024);
        let recvs: Vec<_> = connections[&conn_id].iter_recvs().collect();
        assert_eq!(recvs.len(), 1);
        assert_eq!(recvs[0].bytes, 512);
    }

    #[test]
    fn test_packet_event_rcv_established() {
        use crate::systing::types::{network_address_family, packet_event_type};

        let mut recorder = NetworkRecorder::default();

        let mut dest_addr = [0u8; 16];
        dest_addr[0..4].copy_from_slice(&[192, 168, 1, 100]);

        let event = crate::systing::types::packet_event {
            start_ts: 1000,
            end_ts: 1100,
            task: create_test_task_info(200, 201),
            af: network_address_family::NETWORK_AF_INET,
            dest_addr,
            dest_port: 8080,
            seq: 1000,
            length: 500,
            tcp_flags: 0x10,
            event_type: packet_event_type::PACKET_RCV_ESTABLISHED,
            cpu: 0,
            ..Default::default()
        };

        recorder.handle_packet_event(event);

        let tgidpid = (200u64 << 32) | 201u64;
        assert_eq!(recorder.network_events.len(), 1);
        let connections = &recorder.network_events[&tgidpid];
        assert_eq!(connections.len(), 1);

        let conn_id = ConnectionId {
            protocol: network_protocol::NETWORK_TCP.0,
            af: network_address_family::NETWORK_AF_INET.0,
            dest_addr,
            dest_port: 8080,
        };
        assert!(connections.contains_key(&conn_id));
        let rcv_est: Vec<_> = connections[&conn_id]
            .iter_tcp_rcv_established_packets()
            .collect();
        assert_eq!(rcv_est.len(), 1);
        assert_eq!(rcv_est[0].seq, 1000);
        assert_eq!(rcv_est[0].length, 500);
    }

    #[test]
    fn test_packet_event_queue_rcv() {
        use crate::systing::types::{network_address_family, packet_event_type};

        let mut recorder = NetworkRecorder::default();

        let mut dest_addr = [0u8; 16];
        dest_addr[0..4].copy_from_slice(&[192, 168, 1, 100]);

        let event = crate::systing::types::packet_event {
            start_ts: 1100,
            end_ts: 1110,
            task: create_test_task_info(200, 201),
            af: network_address_family::NETWORK_AF_INET,
            dest_addr,
            dest_port: 8080,
            seq: 1000,
            length: 500,
            tcp_flags: 0x10,
            event_type: packet_event_type::PACKET_QUEUE_RCV,
            cpu: 0,
            ..Default::default()
        };

        recorder.handle_packet_event(event);

        let tgidpid = (200u64 << 32) | 201u64;
        let connections = &recorder.network_events[&tgidpid];
        let conn_id = ConnectionId {
            protocol: network_protocol::NETWORK_TCP.0,
            af: network_address_family::NETWORK_AF_INET.0,
            dest_addr,
            dest_port: 8080,
        };
        let queue_rcv: Vec<_> = connections[&conn_id].iter_tcp_queue_rcv_packets().collect();
        assert_eq!(queue_rcv.len(), 1);
        assert_eq!(queue_rcv[0].seq, 1000);
    }

    #[test]
    fn test_packet_event_buffer_queue() {
        use crate::systing::types::{network_address_family, packet_event_type};

        let mut recorder = NetworkRecorder::default();

        let mut dest_addr = [0u8; 16];
        dest_addr[0..4].copy_from_slice(&[192, 168, 1, 100]);

        let event = crate::systing::types::packet_event {
            start_ts: 1110,
            end_ts: 50000000,
            task: create_test_task_info(200, 201),
            af: network_address_family::NETWORK_AF_INET,
            dest_addr,
            dest_port: 8080,
            seq: 1000,
            length: 500,
            tcp_flags: 0,
            event_type: packet_event_type::PACKET_BUFFER_QUEUE,
            cpu: 0,
            ..Default::default()
        };

        recorder.handle_packet_event(event);

        let tgidpid = (200u64 << 32) | 201u64;
        let connections = &recorder.network_events[&tgidpid];
        let conn_id = ConnectionId {
            protocol: network_protocol::NETWORK_TCP.0,
            af: network_address_family::NETWORK_AF_INET.0,
            dest_addr,
            dest_port: 8080,
        };
        let buffer_queue: Vec<_> = connections[&conn_id]
            .iter_tcp_buffer_queue_packets()
            .collect();
        assert_eq!(buffer_queue.len(), 1);
        assert_eq!(buffer_queue[0].start_ts, 1110);
        assert_eq!(buffer_queue[0].end_ts, 50000000);
    }

    #[test]
    fn test_multiple_receive_packet_events() {
        use crate::systing::types::{network_address_family, packet_event_type};

        let mut recorder = NetworkRecorder::default();

        let mut dest_addr = [0u8; 16];
        dest_addr[0..4].copy_from_slice(&[192, 168, 1, 100]);

        let rcv_est_event = crate::systing::types::packet_event {
            start_ts: 1000,
            end_ts: 1100,
            task: create_test_task_info(200, 201),
            af: network_address_family::NETWORK_AF_INET,
            dest_addr,
            dest_port: 8080,
            seq: 1000,
            length: 500,
            tcp_flags: 0x10,
            event_type: packet_event_type::PACKET_RCV_ESTABLISHED,
            cpu: 0,
            ..Default::default()
        };

        let queue_rcv_event = crate::systing::types::packet_event {
            start_ts: 1100,
            end_ts: 1110,
            task: create_test_task_info(200, 201),
            af: network_address_family::NETWORK_AF_INET,
            dest_addr,
            dest_port: 8080,
            seq: 1000,
            length: 500,
            tcp_flags: 0x10,
            event_type: packet_event_type::PACKET_QUEUE_RCV,
            cpu: 0,
            ..Default::default()
        };

        let buffer_queue_event = crate::systing::types::packet_event {
            start_ts: 1110,
            end_ts: 100000000,
            task: create_test_task_info(200, 201),
            af: network_address_family::NETWORK_AF_INET,
            dest_addr,
            dest_port: 8080,
            seq: 1000,
            length: 500,
            tcp_flags: 0,
            event_type: packet_event_type::PACKET_BUFFER_QUEUE,
            cpu: 0,
            ..Default::default()
        };

        recorder.handle_packet_event(rcv_est_event);
        recorder.handle_packet_event(queue_rcv_event);
        recorder.handle_packet_event(buffer_queue_event);

        let tgidpid = (200u64 << 32) | 201u64;
        let connections = &recorder.network_events[&tgidpid];
        assert_eq!(connections.len(), 1);

        let conn_id = ConnectionId {
            protocol: network_protocol::NETWORK_TCP.0,
            af: network_address_family::NETWORK_AF_INET.0,
            dest_addr,
            dest_port: 8080,
        };
        assert!(connections.contains_key(&conn_id));
        assert_eq!(
            connections[&conn_id]
                .iter_tcp_rcv_established_packets()
                .count(),
            1
        );
        assert_eq!(
            connections[&conn_id].iter_tcp_queue_rcv_packets().count(),
            1
        );
        assert_eq!(
            connections[&conn_id]
                .iter_tcp_buffer_queue_packets()
                .count(),
            1
        );
    }

    #[test]
    fn test_multiple_packets_different_sequences() {
        use crate::systing::types::{network_address_family, packet_event_type};

        let mut recorder = NetworkRecorder::default();

        let mut dest_addr = [0u8; 16];
        dest_addr[0..4].copy_from_slice(&[192, 168, 1, 100]);

        let packet1 = crate::systing::types::packet_event {
            start_ts: 1000,
            end_ts: 2000,
            task: create_test_task_info(200, 201),
            af: network_address_family::NETWORK_AF_INET,
            dest_addr,
            dest_port: 8080,
            seq: 1000,
            length: 100,
            tcp_flags: 0x10,
            event_type: packet_event_type::PACKET_BUFFER_QUEUE,
            cpu: 0,
            ..Default::default()
        };

        let packet2 = crate::systing::types::packet_event {
            start_ts: 1100,
            end_ts: 2100,
            task: create_test_task_info(200, 201),
            af: network_address_family::NETWORK_AF_INET,
            dest_addr,
            dest_port: 8080,
            seq: 1100,
            length: 100,
            tcp_flags: 0x10,
            event_type: packet_event_type::PACKET_BUFFER_QUEUE,
            cpu: 0,
            ..Default::default()
        };

        recorder.handle_packet_event(packet1);
        recorder.handle_packet_event(packet2);

        let tgidpid = (200u64 << 32) | 201u64;
        let connections = &recorder.network_events[&tgidpid];
        let conn_id = ConnectionId {
            protocol: network_protocol::NETWORK_TCP.0,
            af: network_address_family::NETWORK_AF_INET.0,
            dest_addr,
            dest_port: 8080,
        };
        let buffer_queue: Vec<_> = connections[&conn_id]
            .iter_tcp_buffer_queue_packets()
            .collect();
        assert_eq!(buffer_queue.len(), 2);
        assert_eq!(buffer_queue[0].seq, 1000);
        assert_eq!(buffer_queue[1].seq, 1100);
    }

    #[test]
    fn test_generate_trace_packets_with_receive_packets() {
        use crate::systing::types::{network_address_family, packet_event_type};

        let mut recorder = NetworkRecorder::default();
        let mut thread_uuids = HashMap::new();
        thread_uuids.insert(201, 500);
        let pid_uuids: HashMap<i32, u64> = HashMap::new();
        let id_counter = Arc::new(AtomicUsize::new(1000));

        let mut dest_addr = [0u8; 16];
        dest_addr[0..4].copy_from_slice(&[192, 168, 1, 100]);

        let rcv_est = crate::systing::types::packet_event {
            start_ts: 1000,
            end_ts: 1100,
            task: create_test_task_info(200, 201),
            af: network_address_family::NETWORK_AF_INET,
            dest_addr,
            dest_port: 8080,
            seq: 1000,
            length: 500,
            tcp_flags: 0x10,
            event_type: packet_event_type::PACKET_RCV_ESTABLISHED,
            cpu: 0,
            ..Default::default()
        };

        let queue_rcv = crate::systing::types::packet_event {
            start_ts: 1100,
            end_ts: 1110,
            task: create_test_task_info(200, 201),
            af: network_address_family::NETWORK_AF_INET,
            dest_addr,
            dest_port: 8080,
            seq: 1000,
            length: 500,
            tcp_flags: 0x10,
            event_type: packet_event_type::PACKET_QUEUE_RCV,
            cpu: 0,
            ..Default::default()
        };

        let buffer_queue = crate::systing::types::packet_event {
            start_ts: 1110,
            end_ts: 100000000,
            task: create_test_task_info(200, 201),
            af: network_address_family::NETWORK_AF_INET,
            dest_addr,
            dest_port: 8080,
            seq: 1000,
            length: 500,
            tcp_flags: 0,
            event_type: packet_event_type::PACKET_BUFFER_QUEUE,
            cpu: 0,
            ..Default::default()
        };

        recorder.handle_packet_event(rcv_est);
        recorder.handle_packet_event(queue_rcv);
        recorder.handle_packet_event(buffer_queue);

        let packets = recorder.generate_trace_packets(&pid_uuids, &thread_uuids, &id_counter);

        assert!(!packets.is_empty());
        let interned_packet = &packets[0];
        assert!(interned_packet.interned_data.is_some());

        let thread_group_packet = &packets[1];
        assert!(thread_group_packet.has_track_descriptor());
        assert_eq!(
            thread_group_packet.track_descriptor().name(),
            "Network Connections"
        );

        assert!(recorder.network_events.is_empty());
    }

    #[test]
    fn test_packet_events_send_and_receive() {
        use crate::systing::types::{network_address_family, packet_event_type};

        let mut recorder = NetworkRecorder::default();

        let mut dest_addr = [0u8; 16];
        dest_addr[0..4].copy_from_slice(&[192, 168, 1, 100]);

        let send_enqueue = crate::systing::types::packet_event {
            start_ts: 1000,
            end_ts: 1010,
            task: create_test_task_info(200, 201),
            af: network_address_family::NETWORK_AF_INET,
            dest_addr,
            dest_port: 8080,
            seq: 500,
            length: 200,
            tcp_flags: 0x18,
            event_type: packet_event_type::PACKET_ENQUEUE,
            cpu: 0,
            ..Default::default()
        };

        let recv_buffer = crate::systing::types::packet_event {
            start_ts: 2000,
            end_ts: 50000000,
            task: create_test_task_info(200, 201),
            af: network_address_family::NETWORK_AF_INET,
            dest_addr,
            dest_port: 8080,
            seq: 1000,
            length: 300,
            tcp_flags: 0,
            event_type: packet_event_type::PACKET_BUFFER_QUEUE,
            cpu: 0,
            ..Default::default()
        };

        recorder.handle_packet_event(send_enqueue);
        recorder.handle_packet_event(recv_buffer);

        let tgidpid = (200u64 << 32) | 201u64;
        let connections = &recorder.network_events[&tgidpid];
        assert_eq!(connections.len(), 1);

        let conn_id = ConnectionId {
            protocol: network_protocol::NETWORK_TCP.0,
            af: network_address_family::NETWORK_AF_INET.0,
            dest_addr,
            dest_port: 8080,
        };
        assert_eq!(connections[&conn_id].iter_tcp_enqueue_packets().count(), 1);
        assert_eq!(
            connections[&conn_id]
                .iter_tcp_buffer_queue_packets()
                .count(),
            1
        );
    }

    #[test]
    fn test_udp_packet_events_protocol_classification() {
        use crate::systing::types::{network_address_family, packet_event_type};

        let mut recorder = NetworkRecorder::default();

        let mut dest_addr = [0u8; 16];
        dest_addr[0..4].copy_from_slice(&[8, 8, 8, 8]); // 8.8.8.8

        // Create UDP PACKET_UDP_SEND event
        let udp_send_event = crate::systing::types::packet_event {
            start_ts: 1000,
            end_ts: 2000,
            task: create_test_task_info(100, 101),
            protocol: network_protocol::NETWORK_UDP,
            af: network_address_family::NETWORK_AF_INET,
            dest_addr,
            dest_port: 53,
            seq: 0,
            length: 64,
            tcp_flags: 0,
            event_type: packet_event_type::PACKET_UDP_SEND,
            cpu: 0,
        };

        // Create UDP PACKET_SEND event (qdisc->NIC, shared type)
        let udp_packet_send_event = crate::systing::types::packet_event {
            start_ts: 2000,
            end_ts: 3000,
            task: create_test_task_info(100, 101),
            protocol: network_protocol::NETWORK_UDP, // Explicit protocol field
            af: network_address_family::NETWORK_AF_INET,
            dest_addr,
            dest_port: 53,
            seq: 0,
            length: 64,
            tcp_flags: 0,
            event_type: packet_event_type::PACKET_SEND, // Shared with TCP!
            cpu: 0,
        };

        // Create TCP PACKET_SEND event for comparison
        let tcp_packet_send_event = crate::systing::types::packet_event {
            start_ts: 4000,
            end_ts: 5000,
            task: create_test_task_info(100, 101),
            protocol: network_protocol::NETWORK_TCP, // Explicit protocol field
            af: network_address_family::NETWORK_AF_INET,
            dest_addr,
            dest_port: 80,
            seq: 12345,
            length: 1024,
            tcp_flags: 0x10,
            event_type: packet_event_type::PACKET_SEND, // Same event type!
            cpu: 0,
        };

        recorder.handle_packet_event(udp_send_event);
        recorder.handle_packet_event(udp_packet_send_event);
        recorder.handle_packet_event(tcp_packet_send_event);

        let tgidpid = (100u64 << 32) | 101u64;
        let connections = &recorder.network_events[&tgidpid];

        // Verify UDP connection exists with correct protocol
        let udp_conn_id = ConnectionId {
            protocol: network_protocol::NETWORK_UDP.0,
            af: network_address_family::NETWORK_AF_INET.0,
            dest_addr,
            dest_port: 53,
        };
        assert!(
            connections.contains_key(&udp_conn_id),
            "UDP connection should exist"
        );

        // Verify TCP connection exists with correct protocol
        let tcp_conn_id = ConnectionId {
            protocol: network_protocol::NETWORK_TCP.0,
            af: network_address_family::NETWORK_AF_INET.0,
            dest_addr,
            dest_port: 80,
        };
        assert!(
            connections.contains_key(&tcp_conn_id),
            "TCP connection should exist"
        );

        // Verify UDP events went to UDP connection
        let udp_events = &connections[&udp_conn_id];
        assert_eq!(
            udp_events.iter_udp_send_packets().count(),
            1,
            "Should have 1 UDP send event"
        );
        assert_eq!(
            udp_events.iter_shared_send_packets().count(),
            1,
            "Should have 1 UDP PACKET_SEND event (qdisc->NIC)"
        );

        // Verify TCP events went to TCP connection
        let tcp_events = &connections[&tcp_conn_id];
        assert_eq!(
            tcp_events.iter_shared_send_packets().count(),
            1,
            "Should have 1 TCP PACKET_SEND event"
        );

        // Verify UDP connection doesn't have TCP events
        assert_eq!(
            udp_events.iter_tcp_enqueue_packets().count(),
            0,
            "UDP connection shouldn't have TCP enqueue events"
        );

        // Verify TCP connection doesn't have UDP events
        assert_eq!(
            tcp_events.iter_udp_send_packets().count(),
            0,
            "TCP connection shouldn't have UDP send events"
        );
    }

    #[test]
    fn test_udp_receive_packet_events() {
        use crate::systing::types::{network_address_family, packet_event_type};

        let mut recorder = NetworkRecorder::default();

        let mut dest_addr = [0u8; 16];
        dest_addr[0..4].copy_from_slice(&[1, 1, 1, 1]); // 1.1.1.1

        // UDP receive event (IP->UDP)
        let udp_rcv_event = crate::systing::types::packet_event {
            start_ts: 1000,
            end_ts: 1500,
            task: create_test_task_info(200, 201),
            protocol: network_protocol::NETWORK_UDP,
            af: network_address_family::NETWORK_AF_INET,
            dest_addr,
            dest_port: 443,
            seq: 0,
            length: 1200,
            tcp_flags: 0,
            event_type: packet_event_type::PACKET_UDP_RCV,
            cpu: 0,
        };

        // UDP enqueue event (UDP->buffer)
        let udp_enqueue_event = crate::systing::types::packet_event {
            start_ts: 1500,
            end_ts: 2000,
            task: create_test_task_info(200, 201),
            protocol: network_protocol::NETWORK_UDP,
            af: network_address_family::NETWORK_AF_INET,
            dest_addr,
            dest_port: 443,
            seq: 0,
            length: 1200,
            tcp_flags: 0,
            event_type: packet_event_type::PACKET_UDP_ENQUEUE,
            cpu: 0,
        };

        recorder.handle_packet_event(udp_rcv_event);
        recorder.handle_packet_event(udp_enqueue_event);

        let tgidpid = (200u64 << 32) | 201u64;
        let connections = &recorder.network_events[&tgidpid];

        let udp_conn_id = ConnectionId {
            protocol: network_protocol::NETWORK_UDP.0,
            af: network_address_family::NETWORK_AF_INET.0,
            dest_addr,
            dest_port: 443,
        };

        assert!(
            connections.contains_key(&udp_conn_id),
            "UDP connection should exist"
        );

        let udp_events = &connections[&udp_conn_id];
        assert_eq!(
            udp_events.iter_udp_rcv_packets().count(),
            1,
            "Should have 1 UDP receive event"
        );
        assert_eq!(
            udp_events.iter_udp_enqueue_packets().count(),
            1,
            "Should have 1 UDP enqueue event"
        );
    }

    #[test]
    fn test_udp_packet_length_excludes_headers() {
        use crate::systing::types::{network_address_family, packet_event_type};

        let mut recorder = NetworkRecorder::default();

        let mut dest_addr = [0u8; 16];
        dest_addr[0..4].copy_from_slice(&[8, 8, 8, 8]);

        // Simulate UDP packet with application payload of 512 bytes
        // At BPF level, this should be reported as 512 (not 512+8 or 512+28)
        let payload_size = 512;

        // UDP send event - length should be payload only (not including headers)
        let udp_send_event = crate::systing::types::packet_event {
            start_ts: 1000,
            end_ts: 2000,
            task: create_test_task_info(100, 101),
            protocol: network_protocol::NETWORK_UDP,
            af: network_address_family::NETWORK_AF_INET,
            dest_addr,
            dest_port: 53,
            seq: 0,
            length: payload_size, // Should be payload only (BPF subtracts 28 bytes)
            tcp_flags: 0,
            event_type: packet_event_type::PACKET_UDP_SEND,
            cpu: 0,
        };

        // UDP receive event - length should be payload only (not including headers)
        let udp_rcv_event = crate::systing::types::packet_event {
            start_ts: 3000,
            end_ts: 4000,
            task: create_test_task_info(100, 101),
            protocol: network_protocol::NETWORK_UDP,
            af: network_address_family::NETWORK_AF_INET,
            dest_addr,
            dest_port: 53,
            seq: 0,
            length: payload_size, // Should be payload only (BPF subtracts 8 bytes)
            tcp_flags: 0,
            event_type: packet_event_type::PACKET_UDP_RCV,
            cpu: 0,
        };

        recorder.handle_packet_event(udp_send_event);
        recorder.handle_packet_event(udp_rcv_event);

        let tgidpid = (100u64 << 32) | 101u64;
        let connections = &recorder.network_events[&tgidpid];

        let udp_conn_id = ConnectionId {
            protocol: network_protocol::NETWORK_UDP.0,
            af: network_address_family::NETWORK_AF_INET.0,
            dest_addr,
            dest_port: 53,
        };

        let udp_events = &connections[&udp_conn_id];

        // Verify lengths are payload only (headers excluded)
        let udp_send: Vec<_> = udp_events.iter_udp_send_packets().collect();
        assert_eq!(
            udp_send[0].length, payload_size,
            "UDP send packet length should be {} bytes (payload only, no IP+UDP headers)",
            payload_size
        );

        let udp_rcv: Vec<_> = udp_events.iter_udp_rcv_packets().collect();
        assert_eq!(
            udp_rcv[0].length, payload_size,
            "UDP receive packet length should be {} bytes (payload only, no UDP header)",
            payload_size
        );

        // Verify this matches what the application would see in sendto()/recvfrom()
        // If app sends 512 bytes, that's what should be reported (not 512+8 or 512+28)
    }

    #[test]
    fn test_udp_packet_send_does_not_create_tcp_track() {
        use crate::systing::types::{network_address_family, packet_event_type};
        use std::sync::atomic::AtomicUsize;
        use std::sync::Arc;

        let mut recorder = NetworkRecorder::default();

        let mut dest_addr = [0u8; 16];
        dest_addr[0..4].copy_from_slice(&[8, 8, 8, 8]); // 8.8.8.8

        // Create UDP PACKET_SEND event (qdisc->NIC, shared event type with TCP)
        let udp_packet_send_event = crate::systing::types::packet_event {
            start_ts: 1000,
            end_ts: 2000,
            task: create_test_task_info(100, 101),
            protocol: network_protocol::NETWORK_UDP, // UDP protocol
            af: network_address_family::NETWORK_AF_INET,
            dest_addr,
            dest_port: 53,
            seq: 0,
            length: 512,
            tcp_flags: 0,
            event_type: packet_event_type::PACKET_SEND, // Shared with TCP!
            cpu: 0,
        };

        recorder.handle_packet_event(udp_packet_send_event);

        let id_counter = Arc::new(AtomicUsize::new(1000));
        let mut pid_uuids = std::collections::HashMap::new();
        let mut thread_uuids = std::collections::HashMap::new();

        // Add UUIDs for the test task
        pid_uuids.insert(100, 5000); // tgid 100
        thread_uuids.insert(101, 5001); // tid 101

        let packets = recorder.generate_trace_packets(&pid_uuids, &thread_uuids, &id_counter);

        // Count track descriptors to ensure we don't have duplicate "Packets" tracks
        let packets_tracks: Vec<_> = packets
            .iter()
            .filter(|p| p.has_track_descriptor())
            .filter(|p| p.track_descriptor().name() == "Packets")
            .collect();

        assert_eq!(
            packets_tracks.len(), 1,
            "Should only create ONE 'Packets' track for UDP connection, not duplicate TCP+UDP tracks"
        );

        // Note: Event name IIDs are now created unconditionally (only ~9 strings, so no overhead)
        // The important check is that we don't create duplicate track descriptors above
    }
}
