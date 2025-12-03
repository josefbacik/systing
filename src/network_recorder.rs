use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::ringbuf::RingBuffer;
use crate::systing::types::network_event;
use crate::SystingRecordEvent;

/// Unique socket identifier assigned by BPF during tracing
pub type SocketId = u64;

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

/// Metadata for a socket connection, read from BPF map after tracing
#[derive(Debug, Clone)]
pub struct SocketMetadata {
    pub protocol: u32,
    pub af: u32,
    pub dest_addr: [u8; 16],
    pub dest_port: u16,
    #[allow(dead_code)]
    pub tgidpid: u64,
}

impl SocketMetadata {
    fn connection_id(&self) -> ConnectionId {
        ConnectionId {
            protocol: self.protocol,
            af: self.af,
            dest_addr: self.dest_addr,
            dest_port: self.dest_port,
        }
    }

    fn ip_addr(&self) -> IpAddr {
        self.connection_id().ip_addr()
    }

    fn protocol_str(&self) -> &'static str {
        use crate::systing::types::network_protocol;
        if self.protocol == network_protocol::NETWORK_TCP.0 {
            "TCP"
        } else if self.protocol == network_protocol::NETWORK_UDP.0 {
            "UDP"
        } else {
            "UNKNOWN"
        }
    }
}

#[derive(Clone, Copy)]
struct NetworkEvent {
    start_ts: u64,
    end_ts: u64,
    bytes: u32,
    sendmsg_seq: u32,
    sndbuf_used: u32,  // Bytes in send buffer after sendmsg (sk_wmem_queued)
    sndbuf_limit: u32, // Max send buffer size (sk_sndbuf)
}

#[derive(Clone, Copy)]
struct PacketEvent {
    start_ts: u64,
    end_ts: u64,
    seq: u32,
    length: u32,
    tcp_flags: u8,
    sndbuf_used: u32, // Bytes in send buffer (sk_wmem_queued) - shows buffer drain on ACK
    sndbuf_limit: u32, // Max send buffer size (sk_sndbuf)
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

    /// Per-thread syscall events (sendmsg/recvmsg, buffer queue)
    /// Key: tgidpid -> socket_id -> ConnectionEvents
    syscall_events: HashMap<u64, HashMap<SocketId, ConnectionEvents>>,

    /// Global packet events by socket_id (not per-thread)
    /// Key: socket_id -> ConnectionEvents
    packet_events: HashMap<SocketId, ConnectionEvents>,

    /// Socket metadata cache (populated from BPF map after tracing)
    socket_metadata: HashMap<SocketId, SocketMetadata>,

    event_name_ids: HashMap<String, u64>,
    hostname_cache: HashMap<IpAddr, String>,
    dns_stats: DnsStats,
}

impl NetworkRecorder {
    /// Load socket metadata from BPF map after tracing completes.
    /// This populates the socket_metadata cache with socket ID -> address info mapping.
    pub fn load_socket_metadata<M: libbpf_rs::MapCore>(&mut self, map: &M) {
        use crate::systing::types::socket_metadata;

        let mut count = 0;
        for key in map.keys() {
            if let Ok(Some(value_bytes)) = map.lookup(&key, libbpf_rs::MapFlags::ANY) {
                // Parse the value as socket_metadata
                if value_bytes.len() >= std::mem::size_of::<socket_metadata>() {
                    let bpf_meta: &socket_metadata =
                        unsafe { &*(value_bytes.as_ptr() as *const socket_metadata) };

                    let metadata = SocketMetadata {
                        protocol: bpf_meta.protocol.0,
                        af: bpf_meta.af.0,
                        dest_addr: bpf_meta.dest_addr,
                        dest_port: bpf_meta.dest_port,
                        tgidpid: bpf_meta.tgidpid,
                    };

                    self.socket_metadata.insert(bpf_meta.socket_id, metadata);
                    count += 1;
                }
            }
        }

        if count > 0 {
            tracing::info!("Loaded {} socket metadata entries from BPF map", count);
        }
    }

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

        let socket_id = event.socket_id;
        let tgidpid = event.task.tgidpid;

        // Skip events without socket_id (shouldn't happen in normal operation)
        if socket_id == 0 {
            return;
        }

        let pkt_event = PacketEvent {
            start_ts: event.start_ts,
            end_ts: event.end_ts,
            seq: event.seq,
            length: event.length,
            tcp_flags: event.tcp_flags,
            sndbuf_used: event.sndbuf_used,
            sndbuf_limit: event.sndbuf_limit,
        };

        // Buffer queue events go to per-thread syscall_events (app-relevant)
        // All other packet events go to global packet_events
        let is_buffer_queue_event = event.event_type.0 == packet_event_type::PACKET_BUFFER_QUEUE.0
            || event.event_type.0 == packet_event_type::PACKET_UDP_ENQUEUE.0;

        if is_buffer_queue_event {
            // Route to per-thread syscall_events
            let conn_events = self
                .syscall_events
                .entry(tgidpid)
                .or_default()
                .entry(socket_id)
                .or_default();

            if event.event_type.0 == packet_event_type::PACKET_BUFFER_QUEUE.0 {
                conn_events
                    .events
                    .push(EventEntry::TcpBufferQueue(pkt_event));
            } else {
                conn_events.events.push(EventEntry::UdpEnqueue(pkt_event));
            }
        } else {
            // Route to global packet_events
            let conn_events = self.packet_events.entry(socket_id).or_default();

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
            }
            // UDP packet events
            else if event.event_type.0 == packet_event_type::PACKET_UDP_SEND.0 {
                conn_events.events.push(EventEntry::UdpSend(pkt_event));
            } else if event.event_type.0 == packet_event_type::PACKET_UDP_RCV.0 {
                conn_events.events.push(EventEntry::UdpRcv(pkt_event));
            }
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

            // Add send buffer info (shows buffer drain on ACK receipt)
            if pkt.sndbuf_limit > 0 {
                let mut sndbuf_used_annotation = DebugAnnotation::default();
                sndbuf_used_annotation.set_name("sndbuf_used".to_string());
                sndbuf_used_annotation.set_uint_value(pkt.sndbuf_used as u64);
                begin_event.debug_annotations.push(sndbuf_used_annotation);

                let mut sndbuf_limit_annotation = DebugAnnotation::default();
                sndbuf_limit_annotation.set_name("sndbuf_limit".to_string());
                sndbuf_limit_annotation.set_uint_value(pkt.sndbuf_limit as u64);
                begin_event.debug_annotations.push(sndbuf_limit_annotation);

                // Add fill percentage for easier analysis
                let fill_pct = (pkt.sndbuf_used as u64 * 100) / pkt.sndbuf_limit as u64;
                let mut fill_annotation = DebugAnnotation::default();
                fill_annotation.set_name("sndbuf_fill_pct".to_string());
                fill_annotation.set_uint_value(fill_pct);
                begin_event.debug_annotations.push(fill_annotation);
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

    /// Prepares all metadata needed for packet generation, including:
    /// - Resolving hostnames for all sockets
    /// - Creating IIDs for protocol operations and packet events
    /// - Building the event names array
    fn prepare_event_metadata(&mut self, id_counter: &Arc<AtomicUsize>) -> Vec<EventName> {
        use crate::systing::types::network_operation;

        // Collect IP addresses first to avoid borrow issues
        let ip_addrs: Vec<_> = self.socket_metadata.values().map(|m| m.ip_addr()).collect();

        // Resolve hostnames for all sockets
        for ip_addr in ip_addrs {
            self.resolve_hostname(ip_addr);
        }

        // Collect protocol operations used across all syscall events
        let mut protocol_ops_used = std::collections::HashSet::new();
        for connections in self.syscall_events.values() {
            for (socket_id, events) in connections.iter() {
                if let Some(metadata) = self.socket_metadata.get(socket_id) {
                    if events.iter_sends().next().is_some() {
                        protocol_ops_used
                            .insert((metadata.protocol, network_operation::NETWORK_SEND.0));
                    }
                    if events.iter_recvs().next().is_some() {
                        protocol_ops_used
                            .insert((metadata.protocol, network_operation::NETWORK_RECV.0));
                    }
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

            let event_name = format!("{proto_str}_{op_str}");
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

        // Build and sort event names array
        let mut event_names = Vec::new();
        for (name, iid) in &self.event_name_ids {
            let mut event_name = EventName::default();
            event_name.set_iid(*iid);
            event_name.set_name(name.clone());
            event_names.push(event_name);
        }
        event_names.sort_by_key(|e| e.iid());

        event_names
    }

    /// Helper to get socket track name from metadata
    fn socket_track_name(&self, socket_id: SocketId) -> String {
        if let Some(metadata) = self.socket_metadata.get(&socket_id) {
            let hostname = self
                .hostname_cache
                .get(&metadata.ip_addr())
                .map(|s| s.as_str())
                .unwrap_or("unknown");
            format!(
                "Socket {}:{}:{}:{}",
                socket_id,
                metadata.protocol_str(),
                hostname,
                metadata.dest_port
            )
        } else {
            format!("Socket {}", socket_id)
        }
    }

    pub fn generate_trace_packets(
        &mut self,
        pid_uuids: &HashMap<i32, u64>,
        thread_uuids: &HashMap<i32, u64>,
        id_counter: &Arc<AtomicUsize>,
    ) -> Vec<TracePacket> {
        let mut packets = Vec::new();
        let sequence_id = id_counter.fetch_add(1, Ordering::Relaxed) as u32;

        // Phase 1: Prepare all metadata (event names, IIDs, DNS resolution)
        let event_names = self.prepare_event_metadata(id_counter);

        // Phase 2: Create interned data packet if we have event names
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

        // ====================================================================
        // Phase 3: Generate global "Network Packets" root with per-socket tracks
        // ====================================================================
        if !self.packet_events.is_empty() {
            // Create global "Network Packets" root track
            let network_packets_root_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;

            let mut root_track_desc = TrackDescriptor::default();
            root_track_desc.set_uuid(network_packets_root_uuid);
            root_track_desc.set_name("Network Packets".to_string());

            let mut root_track_packet = TracePacket::default();
            root_track_packet.set_track_descriptor(root_track_desc);
            packets.push(root_track_packet);

            // Create per-socket packet tracks (flat - events directly under socket)
            for (socket_id, events) in self.packet_events.iter() {
                if events.is_empty() {
                    continue;
                }

                // Create socket track under root
                let socket_track_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;

                let mut socket_track_desc = TrackDescriptor::default();
                socket_track_desc.set_uuid(socket_track_uuid);
                socket_track_desc.set_name(self.socket_track_name(*socket_id));
                socket_track_desc.set_parent_uuid(network_packets_root_uuid);

                let mut socket_track_packet = TracePacket::default();
                socket_track_packet.set_track_descriptor(socket_track_desc);
                packets.push(socket_track_packet);

                // Determine protocol for this socket
                let is_tcp = self
                    .socket_metadata
                    .get(socket_id)
                    .map(|m| m.protocol == crate::systing::types::network_protocol::NETWORK_TCP.0)
                    .unwrap_or(false);

                // Emit all packet events directly on this socket track (flat)
                if is_tcp {
                    // TCP packet events
                    let enqueue_pkts: Vec<_> = events.iter_tcp_enqueue_packets().copied().collect();
                    if !enqueue_pkts.is_empty() {
                        let enqueue_iid = *self.event_name_ids.get("TCP packet_enqueue").unwrap();
                        self.add_packet_slice_events(
                            &mut packets,
                            sequence_id,
                            socket_track_uuid,
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
                            socket_track_uuid,
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
                            socket_track_uuid,
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
                            socket_track_uuid,
                            queue_rcv_iid,
                            &queue_rcv_pkts,
                        );
                    }
                } else {
                    // UDP packet events
                    let udp_send_pkts: Vec<_> = events.iter_udp_send_packets().copied().collect();
                    if !udp_send_pkts.is_empty() {
                        let send_iid = *self.event_name_ids.get("UDP send").unwrap();
                        self.add_packet_slice_events(
                            &mut packets,
                            sequence_id,
                            socket_track_uuid,
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
                            socket_track_uuid,
                            rcv_iid,
                            &udp_rcv_pkts,
                        );
                    }

                    // UDP uses PACKET_SEND (SharedSend) for qdisc->NIC transmission
                    let shared_send_pkts: Vec<_> =
                        events.iter_shared_send_packets().copied().collect();
                    if !shared_send_pkts.is_empty() {
                        let send_iid = *self.event_name_ids.get("UDP packet_send").unwrap();
                        self.add_packet_slice_events(
                            &mut packets,
                            sequence_id,
                            socket_track_uuid,
                            send_iid,
                            &shared_send_pkts,
                        );
                    }
                }
            }
        }

        // ====================================================================
        // Phase 4: Generate per-thread "Network Syscalls" tracks
        // ====================================================================
        for (tgidpid, connections) in self.syscall_events.iter() {
            if connections.is_empty() {
                continue;
            }

            // Create a "Network Syscalls" track group for this thread
            let thread_group_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;

            let thread_group_desc = crate::perfetto::generate_pidtgid_track_descriptor(
                pid_uuids,
                thread_uuids,
                tgidpid,
                "Network Syscalls".to_string(),
                thread_group_uuid,
            );

            let mut thread_group_packet = TracePacket::default();
            thread_group_packet.set_track_descriptor(thread_group_desc);
            packets.push(thread_group_packet);

            // Create per-socket syscall tracks
            for (socket_id, events) in connections.iter() {
                if events.is_empty() {
                    continue;
                }

                // Create socket track group
                let socket_group_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;

                let mut socket_group_desc = TrackDescriptor::default();
                socket_group_desc.set_uuid(socket_group_uuid);
                socket_group_desc.set_name(self.socket_track_name(*socket_id));
                socket_group_desc.set_parent_uuid(thread_group_uuid);

                let mut socket_group_packet = TracePacket::default();
                socket_group_packet.set_track_descriptor(socket_group_desc);
                packets.push(socket_group_packet);

                // Get protocol from metadata
                let protocol = self
                    .socket_metadata
                    .get(socket_id)
                    .map(|m| m.protocol)
                    .unwrap_or(0);

                // Create Sends track if we have send events
                if events.iter_sends().next().is_some() {
                    let send_track_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;

                    let mut send_track_desc = TrackDescriptor::default();
                    send_track_desc.set_uuid(send_track_uuid);
                    send_track_desc.set_name("Sends".to_string());
                    send_track_desc.set_parent_uuid(socket_group_uuid);

                    let mut send_track_packet = TracePacket::default();
                    send_track_packet.set_track_descriptor(send_track_desc);
                    packets.push(send_track_packet);

                    let proto_str = Self::protocol_to_str(protocol);
                    let send_event_name = format!("{proto_str}_send");
                    let send_name_iid = self
                        .event_name_ids
                        .get(&send_event_name)
                        .copied()
                        .unwrap_or(0);

                    for event in events.iter_sends() {
                        let mut begin_event = TrackEvent::default();
                        begin_event.set_type(Type::TYPE_SLICE_BEGIN);
                        if send_name_iid > 0 {
                            begin_event.set_name_iid(send_name_iid);
                        }
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

                        // Add send buffer info (TCP only, when available)
                        if event.sndbuf_limit > 0 {
                            let mut sndbuf_used_annotation = DebugAnnotation::default();
                            sndbuf_used_annotation.set_name("sndbuf_used".to_string());
                            sndbuf_used_annotation.set_uint_value(event.sndbuf_used as u64);
                            begin_event.debug_annotations.push(sndbuf_used_annotation);

                            let mut sndbuf_limit_annotation = DebugAnnotation::default();
                            sndbuf_limit_annotation.set_name("sndbuf_limit".to_string());
                            sndbuf_limit_annotation.set_uint_value(event.sndbuf_limit as u64);
                            begin_event.debug_annotations.push(sndbuf_limit_annotation);

                            // Add fill percentage for easier analysis
                            let fill_pct =
                                (event.sndbuf_used as u64 * 100) / event.sndbuf_limit as u64;
                            let mut fill_annotation = DebugAnnotation::default();
                            fill_annotation.set_name("sndbuf_fill_pct".to_string());
                            fill_annotation.set_uint_value(fill_pct);
                            begin_event.debug_annotations.push(fill_annotation);
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

                // Create Receives track if we have receive events
                if events.iter_recvs().next().is_some() {
                    let recv_track_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;

                    let mut recv_track_desc = TrackDescriptor::default();
                    recv_track_desc.set_uuid(recv_track_uuid);
                    recv_track_desc.set_name("Receives".to_string());
                    recv_track_desc.set_parent_uuid(socket_group_uuid);

                    let mut recv_track_packet = TracePacket::default();
                    recv_track_packet.set_track_descriptor(recv_track_desc);
                    packets.push(recv_track_packet);

                    let proto_str = Self::protocol_to_str(protocol);
                    let recv_event_name = format!("{proto_str}_recv");
                    let recv_name_iid = self
                        .event_name_ids
                        .get(&recv_event_name)
                        .copied()
                        .unwrap_or(0);
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

                // Create Buffer Queue track if we have buffer queue events (app-relevant)
                let has_buffer_queue = events.iter_tcp_buffer_queue_packets().next().is_some()
                    || events.iter_udp_enqueue_packets().next().is_some();

                if has_buffer_queue {
                    let buffer_track_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;

                    let mut buffer_track_desc = TrackDescriptor::default();
                    buffer_track_desc.set_uuid(buffer_track_uuid);
                    buffer_track_desc.set_name("Buffer Queue".to_string());
                    buffer_track_desc.set_parent_uuid(socket_group_uuid);

                    let mut buffer_track_packet = TracePacket::default();
                    buffer_track_packet.set_track_descriptor(buffer_track_desc);
                    packets.push(buffer_track_packet);

                    // TCP buffer queue events
                    let buffer_queue_pkts: Vec<_> =
                        events.iter_tcp_buffer_queue_packets().copied().collect();
                    if !buffer_queue_pkts.is_empty() {
                        let buffer_queue_iid =
                            *self.event_name_ids.get("TCP buffer_queue").unwrap();
                        self.add_packet_slice_events(
                            &mut packets,
                            sequence_id,
                            buffer_track_uuid,
                            buffer_queue_iid,
                            &buffer_queue_pkts,
                        );
                    }

                    // UDP enqueue events
                    let udp_enqueue_pkts: Vec<_> =
                        events.iter_udp_enqueue_packets().copied().collect();
                    if !udp_enqueue_pkts.is_empty() {
                        let enqueue_iid = *self.event_name_ids.get("UDP enqueue").unwrap();
                        self.add_packet_slice_events(
                            &mut packets,
                            sequence_id,
                            buffer_track_uuid,
                            enqueue_iid,
                            &udp_enqueue_pkts,
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

        self.syscall_events.clear();
        self.packet_events.clear();
        self.socket_metadata.clear();
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
        let socket_id = event.socket_id;

        // Skip events without socket_id (shouldn't happen in normal operation)
        if socket_id == 0 {
            return;
        }

        let net_event = NetworkEvent {
            start_ts: event.start_ts,
            end_ts: event.end_ts,
            bytes: event.bytes,
            sendmsg_seq: event.sendmsg_seq,
            sndbuf_used: event.sndbuf_used,
            sndbuf_limit: event.sndbuf_limit,
        };

        // Route to per-thread syscall_events by tgidpid then socket_id
        let conn_events = self
            .syscall_events
            .entry(tgidpid)
            .or_default()
            .entry(socket_id)
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

    /// Helper to insert socket metadata for tests
    fn insert_test_socket_metadata(
        recorder: &mut NetworkRecorder,
        socket_id: SocketId,
        protocol: u32,
        af: u32,
        dest_addr: [u8; 16],
        dest_port: u16,
        tgidpid: u64,
    ) {
        recorder.socket_metadata.insert(
            socket_id,
            SocketMetadata {
                protocol,
                af,
                dest_addr,
                dest_port,
                tgidpid,
            },
        );
    }

    #[test]
    fn test_network_recorder_tcp_send() {
        use crate::systing::types::{network_address_family, network_operation};

        let mut recorder = NetworkRecorder::default();

        let mut dest_addr = [0u8; 16];
        dest_addr[0..4].copy_from_slice(&[127, 0, 0, 1]); // 127.0.0.1 in network byte order
        let socket_id: SocketId = 1;

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
            socket_id,
            ..Default::default()
        };

        recorder.handle_event(event);

        let tgidpid = (100u64 << 32) | 101u64;
        assert_eq!(recorder.syscall_events.len(), 1);
        assert!(recorder.syscall_events.contains_key(&tgidpid));

        let connections = &recorder.syscall_events[&tgidpid];
        assert_eq!(connections.len(), 1);

        assert!(connections.contains_key(&socket_id));
        let sends: Vec<_> = connections[&socket_id].iter_sends().collect();
        assert_eq!(sends.len(), 1);
        assert_eq!(sends[0].bytes, 1024);
        assert_eq!(connections[&socket_id].iter_recvs().count(), 0);
    }

    #[test]
    fn test_network_recorder_multiple_sends() {
        use crate::systing::types::{network_address_family, network_operation};

        let mut recorder = NetworkRecorder::default();

        let mut dest_addr = [0u8; 16];
        dest_addr[0..4].copy_from_slice(&[127, 0, 0, 1]); // 127.0.0.1 in network byte order
        let socket_id: SocketId = 1;

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
            socket_id,
            ..Default::default()
        };

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
            socket_id,
            ..Default::default()
        };

        recorder.handle_event(event1);
        recorder.handle_event(event2);

        let tgidpid = (100u64 << 32) | 101u64;
        let connections = &recorder.syscall_events[&tgidpid];

        let sends: Vec<_> = connections[&socket_id].iter_sends().collect();
        assert_eq!(sends.len(), 2);
        assert_eq!(sends[0].bytes, 1024);
        assert_eq!(sends[1].bytes, 2048);
    }

    #[test]
    fn test_network_recorder_multiple_connections() {
        use crate::systing::types::{network_address_family, network_operation};

        let mut recorder = NetworkRecorder::default();

        let mut dest_addr = [0u8; 16];
        dest_addr[0..4].copy_from_slice(&[127, 0, 0, 1]);
        let tcp_socket_id: SocketId = 1;
        let udp_socket_id: SocketId = 2;

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
            socket_id: tcp_socket_id,
            ..Default::default()
        };

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
            socket_id: udp_socket_id,
            ..Default::default()
        };

        recorder.handle_event(event1);
        recorder.handle_event(event2);

        let tgidpid = (100u64 << 32) | 101u64;
        let connections = &recorder.syscall_events[&tgidpid];
        assert_eq!(connections.len(), 2);
        assert!(connections.contains_key(&tcp_socket_id));
        assert!(connections.contains_key(&udp_socket_id));
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
        let socket_id: SocketId = 1;
        let tgidpid = (100u64 << 32) | 101u64;

        insert_test_socket_metadata(
            &mut recorder,
            socket_id,
            network_protocol::NETWORK_TCP.0,
            network_address_family::NETWORK_AF_INET.0,
            dest_addr,
            8080,
            tgidpid,
        );

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
            socket_id,
            ..Default::default()
        };

        recorder.handle_event(event);

        let packets = recorder.generate_trace_packets(&pid_uuids, &thread_uuids, &id_counter);

        // Packets: interned data, thread track group, socket track, send track, slice begin, slice end
        assert_eq!(packets.len(), 6);

        let interned_packet = &packets[0];
        assert!(interned_packet.interned_data.is_some());

        let thread_group_packet = &packets[1];
        assert!(thread_group_packet.has_track_descriptor());
        let thread_group_desc = thread_group_packet.track_descriptor();
        assert_eq!(thread_group_desc.name(), "Network Syscalls");

        let socket_group_packet = &packets[2];
        assert!(socket_group_packet.has_track_descriptor());
        let socket_group_desc = socket_group_packet.track_descriptor();
        assert!(socket_group_desc.name().starts_with("Socket 1:TCP:"));
        assert_eq!(socket_group_desc.parent_uuid(), thread_group_desc.uuid());

        let send_track_packet = &packets[3];
        assert!(send_track_packet.has_track_descriptor());
        let send_track_desc = send_track_packet.track_descriptor();
        assert_eq!(send_track_desc.name(), "Sends");
        assert_eq!(send_track_desc.parent_uuid(), socket_group_desc.uuid());

        let begin_packet = &packets[4];
        assert!(begin_packet.has_track_event());
        assert_eq!(begin_packet.timestamp(), 1000);
        let begin_event = begin_packet.track_event();
        assert_eq!(begin_event.type_(), Type::TYPE_SLICE_BEGIN);
        assert_eq!(begin_event.track_uuid(), send_track_desc.uuid());
        assert_eq!(begin_event.debug_annotations.len(), 1);
        assert_eq!(begin_event.debug_annotations[0].name(), "bytes");
        assert_eq!(begin_event.debug_annotations[0].uint_value(), 1024);

        let end_packet = &packets[5];
        assert!(end_packet.has_track_event());
        assert_eq!(end_packet.timestamp(), 2000);
        let end_event = end_packet.track_event();
        assert_eq!(end_event.type_(), Type::TYPE_SLICE_END);
        assert_eq!(end_event.track_uuid(), send_track_desc.uuid());

        assert!(recorder.syscall_events.is_empty());
    }

    #[test]
    fn test_network_recorder_sends_and_receives() {
        use crate::systing::types::{network_address_family, network_operation};

        let mut recorder = NetworkRecorder::default();

        let mut dest_addr = [0u8; 16];
        dest_addr[0..4].copy_from_slice(&[127, 0, 0, 1]);
        let socket_id: SocketId = 1;

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
            socket_id,
            ..Default::default()
        };

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
            socket_id,
            ..Default::default()
        };

        recorder.handle_event(send_event);
        recorder.handle_event(recv_event);

        let tgidpid = (100u64 << 32) | 101u64;
        let connections = &recorder.syscall_events[&tgidpid];
        assert_eq!(connections.len(), 1);

        assert!(connections.contains_key(&socket_id));
        let sends: Vec<_> = connections[&socket_id].iter_sends().collect();
        assert_eq!(sends.len(), 1);
        assert_eq!(sends[0].bytes, 1024);
        let recvs: Vec<_> = connections[&socket_id].iter_recvs().collect();
        assert_eq!(recvs.len(), 1);
        assert_eq!(recvs[0].bytes, 512);
    }

    #[test]
    fn test_network_recorder_ipv6_tcp_send() {
        use crate::systing::types::{network_address_family, network_operation};

        let mut recorder = NetworkRecorder::default();

        let mut dest_addr = [0u8; 16]; // 2001:db8::1
        dest_addr.copy_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]);
        let socket_id: SocketId = 1;

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
            socket_id,
            ..Default::default()
        };

        recorder.handle_event(event);

        let tgidpid = (100u64 << 32) | 101u64;
        assert_eq!(recorder.syscall_events.len(), 1);
        assert!(recorder.syscall_events.contains_key(&tgidpid));

        let connections = &recorder.syscall_events[&tgidpid];
        assert_eq!(connections.len(), 1);

        assert!(connections.contains_key(&socket_id));
        let sends: Vec<_> = connections[&socket_id].iter_sends().collect();
        assert_eq!(sends.len(), 1);
        assert_eq!(sends[0].bytes, 2048);
        assert_eq!(connections[&socket_id].iter_recvs().count(), 0);
    }

    #[test]
    fn test_network_recorder_ipv6_udp_send() {
        use crate::systing::types::{network_address_family, network_operation};

        let mut recorder = NetworkRecorder::default();

        let mut dest_addr = [0u8; 16];
        dest_addr[15] = 1; // ::1
        let socket_id: SocketId = 1;

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
            socket_id,
            ..Default::default()
        };

        recorder.handle_event(event);

        let tgidpid = (100u64 << 32) | 101u64;
        let connections = &recorder.syscall_events[&tgidpid];
        assert_eq!(connections.len(), 1);

        assert!(connections.contains_key(&socket_id));
        let sends: Vec<_> = connections[&socket_id].iter_sends().collect();
        assert_eq!(sends.len(), 1);
        assert_eq!(sends[0].bytes, 512);
    }

    #[test]
    fn test_network_recorder_ipv6_and_ipv4_mixed() {
        use crate::systing::types::{network_address_family, network_operation};

        let mut recorder = NetworkRecorder::default();

        let mut ipv4_addr = [0u8; 16];
        ipv4_addr[0..4].copy_from_slice(&[127, 0, 0, 1]);

        let mut ipv6_addr = [0u8; 16]; // 2001:db8::2
        ipv6_addr.copy_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ]);
        let ipv4_socket_id: SocketId = 1;
        let ipv6_socket_id: SocketId = 2;

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
            socket_id: ipv4_socket_id,
            ..Default::default()
        };

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
            socket_id: ipv6_socket_id,
            ..Default::default()
        };

        recorder.handle_event(ipv4_event);
        recorder.handle_event(ipv6_event);

        let tgidpid = (100u64 << 32) | 101u64;
        let connections = &recorder.syscall_events[&tgidpid];

        // Should have 2 distinct sockets (IPv4 and IPv6)
        assert_eq!(connections.len(), 2);

        // Verify IPv4 socket
        assert!(connections.contains_key(&ipv4_socket_id));
        let ipv4_sends: Vec<_> = connections[&ipv4_socket_id].iter_sends().collect();
        assert_eq!(ipv4_sends[0].bytes, 1024);

        // Verify IPv6 socket
        assert!(connections.contains_key(&ipv6_socket_id));
        let ipv6_sends: Vec<_> = connections[&ipv6_socket_id].iter_sends().collect();
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

        let mut dest_addr = [0u8; 16]; // 2001:db8::1
        dest_addr.copy_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]);
        let socket_id: SocketId = 1;

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
            socket_id,
            ..Default::default()
        };

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
            socket_id,
            ..Default::default()
        };

        recorder.handle_event(send_event);
        recorder.handle_event(recv_event);

        let tgidpid = (100u64 << 32) | 101u64;
        let connections = &recorder.syscall_events[&tgidpid];
        assert_eq!(connections.len(), 1);

        assert!(connections.contains_key(&socket_id));
        let sends: Vec<_> = connections[&socket_id].iter_sends().collect();
        assert_eq!(sends.len(), 1);
        assert_eq!(sends[0].bytes, 1024);
        let recvs: Vec<_> = connections[&socket_id].iter_recvs().collect();
        assert_eq!(recvs.len(), 1);
        assert_eq!(recvs[0].bytes, 512);
    }

    #[test]
    fn test_packet_event_rcv_established() {
        use crate::systing::types::{network_address_family, packet_event_type};

        let mut recorder = NetworkRecorder::default();

        let mut dest_addr = [0u8; 16];
        dest_addr[0..4].copy_from_slice(&[192, 168, 1, 100]);
        let socket_id: SocketId = 1;

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
            socket_id,
            ..Default::default()
        };

        recorder.handle_packet_event(event);

        // PACKET_RCV_ESTABLISHED goes to global packet_events
        assert_eq!(recorder.packet_events.len(), 1);
        assert!(recorder.packet_events.contains_key(&socket_id));

        let rcv_est: Vec<_> = recorder.packet_events[&socket_id]
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
        let socket_id: SocketId = 1;

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
            socket_id,
            ..Default::default()
        };

        recorder.handle_packet_event(event);

        // PACKET_QUEUE_RCV goes to global packet_events
        assert!(recorder.packet_events.contains_key(&socket_id));
        let queue_rcv: Vec<_> = recorder.packet_events[&socket_id]
            .iter_tcp_queue_rcv_packets()
            .collect();
        assert_eq!(queue_rcv.len(), 1);
        assert_eq!(queue_rcv[0].seq, 1000);
    }

    #[test]
    fn test_packet_event_buffer_queue() {
        use crate::systing::types::{network_address_family, packet_event_type};

        let mut recorder = NetworkRecorder::default();

        let mut dest_addr = [0u8; 16];
        dest_addr[0..4].copy_from_slice(&[192, 168, 1, 100]);
        let socket_id: SocketId = 1;

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
            socket_id,
            ..Default::default()
        };

        recorder.handle_packet_event(event);

        // PACKET_BUFFER_QUEUE goes to per-thread syscall_events (app-relevant)
        let tgidpid = (200u64 << 32) | 201u64;
        let connections = &recorder.syscall_events[&tgidpid];
        assert!(connections.contains_key(&socket_id));

        let buffer_queue: Vec<_> = connections[&socket_id]
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
        let socket_id: SocketId = 1;
        let tgidpid = (200u64 << 32) | 201u64;

        insert_test_socket_metadata(
            &mut recorder,
            socket_id,
            network_protocol::NETWORK_TCP.0,
            network_address_family::NETWORK_AF_INET.0,
            dest_addr,
            8080,
            tgidpid,
        );

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
            socket_id,
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
            socket_id,
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
            socket_id,
            ..Default::default()
        };

        recorder.handle_packet_event(rcv_est_event);
        recorder.handle_packet_event(queue_rcv_event);
        recorder.handle_packet_event(buffer_queue_event);

        // PACKET_RCV_ESTABLISHED and PACKET_QUEUE_RCV go to global packet_events
        assert_eq!(recorder.packet_events.len(), 1);
        assert!(recorder.packet_events.contains_key(&socket_id));
        assert_eq!(
            recorder.packet_events[&socket_id]
                .iter_tcp_rcv_established_packets()
                .count(),
            1
        );
        assert_eq!(
            recorder.packet_events[&socket_id]
                .iter_tcp_queue_rcv_packets()
                .count(),
            1
        );

        // PACKET_BUFFER_QUEUE goes to per-thread syscall_events
        let connections = &recorder.syscall_events[&tgidpid];
        assert_eq!(connections.len(), 1);
        assert!(connections.contains_key(&socket_id));
        assert_eq!(
            connections[&socket_id]
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
        let socket_id: SocketId = 1;
        let tgidpid = (200u64 << 32) | 201u64;

        insert_test_socket_metadata(
            &mut recorder,
            socket_id,
            network_protocol::NETWORK_TCP.0,
            network_address_family::NETWORK_AF_INET.0,
            dest_addr,
            8080,
            tgidpid,
        );

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
            socket_id,
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
            socket_id,
            ..Default::default()
        };

        recorder.handle_packet_event(packet1);
        recorder.handle_packet_event(packet2);

        // PACKET_BUFFER_QUEUE goes to per-thread syscall_events
        let connections = &recorder.syscall_events[&tgidpid];
        assert!(connections.contains_key(&socket_id));
        let buffer_queue: Vec<_> = connections[&socket_id]
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
        let socket_id: SocketId = 1;
        let tgidpid = (200u64 << 32) | 201u64;

        insert_test_socket_metadata(
            &mut recorder,
            socket_id,
            network_protocol::NETWORK_TCP.0,
            network_address_family::NETWORK_AF_INET.0,
            dest_addr,
            8080,
            tgidpid,
        );

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
            socket_id,
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
            socket_id,
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
            socket_id,
            ..Default::default()
        };

        recorder.handle_packet_event(rcv_est);
        recorder.handle_packet_event(queue_rcv);
        recorder.handle_packet_event(buffer_queue);

        let packets = recorder.generate_trace_packets(&pid_uuids, &thread_uuids, &id_counter);

        assert!(!packets.is_empty());
        let interned_packet = &packets[0];
        assert!(interned_packet.interned_data.is_some());

        let has_network_packets_track = packets
            .iter()
            .any(|p| p.has_track_descriptor() && p.track_descriptor().name() == "Network Packets");
        assert!(
            has_network_packets_track,
            "Should have 'Network Packets' track"
        );

        let has_syscall_track = packets
            .iter()
            .any(|p| p.has_track_descriptor() && p.track_descriptor().name() == "Network Syscalls");
        assert!(has_syscall_track, "Should have 'Network Syscalls' track");
    }

    #[test]
    fn test_packet_events_send_and_receive() {
        use crate::systing::types::{network_address_family, packet_event_type};

        let mut recorder = NetworkRecorder::default();

        let mut dest_addr = [0u8; 16];
        dest_addr[0..4].copy_from_slice(&[192, 168, 1, 100]);
        let socket_id: SocketId = 1;
        let tgidpid = (200u64 << 32) | 201u64;

        insert_test_socket_metadata(
            &mut recorder,
            socket_id,
            network_protocol::NETWORK_TCP.0,
            network_address_family::NETWORK_AF_INET.0,
            dest_addr,
            8080,
            tgidpid,
        );

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
            socket_id,
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
            socket_id,
            ..Default::default()
        };

        recorder.handle_packet_event(send_enqueue);
        recorder.handle_packet_event(recv_buffer);

        // PACKET_ENQUEUE goes to global packet_events
        assert_eq!(recorder.packet_events.len(), 1);
        assert!(recorder.packet_events.contains_key(&socket_id));
        assert_eq!(
            recorder.packet_events[&socket_id]
                .iter_tcp_enqueue_packets()
                .count(),
            1
        );

        // PACKET_BUFFER_QUEUE goes to per-thread syscall_events
        let connections = &recorder.syscall_events[&tgidpid];
        assert_eq!(connections.len(), 1);
        assert!(connections.contains_key(&socket_id));
        assert_eq!(
            connections[&socket_id]
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
        let udp_socket_id: SocketId = 1;
        let tcp_socket_id: SocketId = 2;
        let tgidpid = (100u64 << 32) | 101u64;

        insert_test_socket_metadata(
            &mut recorder,
            udp_socket_id,
            network_protocol::NETWORK_UDP.0,
            network_address_family::NETWORK_AF_INET.0,
            dest_addr,
            53,
            tgidpid,
        );
        insert_test_socket_metadata(
            &mut recorder,
            tcp_socket_id,
            network_protocol::NETWORK_TCP.0,
            network_address_family::NETWORK_AF_INET.0,
            dest_addr,
            80,
            tgidpid,
        );

        // Create UDP PACKET_UDP_SEND event - goes to global packet_events
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
            socket_id: udp_socket_id,
            ..Default::default()
        };

        // Create UDP PACKET_SEND event (qdisc->NIC, shared type) - goes to global packet_events
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
            socket_id: udp_socket_id,
            ..Default::default()
        };

        // Create TCP PACKET_SEND event for comparison - goes to global packet_events
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
            socket_id: tcp_socket_id,
            ..Default::default()
        };

        recorder.handle_packet_event(udp_send_event);
        recorder.handle_packet_event(udp_packet_send_event);
        recorder.handle_packet_event(tcp_packet_send_event);

        // All these packet types go to global packet_events (not syscall_events)
        assert_eq!(recorder.packet_events.len(), 2);
        assert!(recorder.packet_events.contains_key(&udp_socket_id));
        assert!(recorder.packet_events.contains_key(&tcp_socket_id));

        // Verify UDP events went to UDP socket_id
        let udp_events = &recorder.packet_events[&udp_socket_id];
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

        // Verify TCP events went to TCP socket_id
        let tcp_events = &recorder.packet_events[&tcp_socket_id];
        assert_eq!(
            tcp_events.iter_shared_send_packets().count(),
            1,
            "Should have 1 TCP PACKET_SEND event"
        );

        // Verify UDP socket doesn't have TCP events
        assert_eq!(
            udp_events.iter_tcp_enqueue_packets().count(),
            0,
            "UDP socket shouldn't have TCP enqueue events"
        );

        // Verify TCP socket doesn't have UDP events
        assert_eq!(
            tcp_events.iter_udp_send_packets().count(),
            0,
            "TCP socket shouldn't have UDP send events"
        );
    }

    #[test]
    fn test_udp_receive_packet_events() {
        use crate::systing::types::{network_address_family, packet_event_type};

        let mut recorder = NetworkRecorder::default();

        let mut dest_addr = [0u8; 16];
        dest_addr[0..4].copy_from_slice(&[1, 1, 1, 1]); // 1.1.1.1
        let socket_id: SocketId = 1;
        let tgidpid = (200u64 << 32) | 201u64;

        insert_test_socket_metadata(
            &mut recorder,
            socket_id,
            network_protocol::NETWORK_UDP.0,
            network_address_family::NETWORK_AF_INET.0,
            dest_addr,
            443,
            tgidpid,
        );

        // UDP receive event (IP->UDP) - goes to global packet_events
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
            socket_id,
            ..Default::default()
        };

        // UDP enqueue event (UDP->buffer) - goes to per-thread syscall_events
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
            socket_id,
            ..Default::default()
        };

        recorder.handle_packet_event(udp_rcv_event);
        recorder.handle_packet_event(udp_enqueue_event);

        // PACKET_UDP_RCV goes to global packet_events
        assert_eq!(recorder.packet_events.len(), 1);
        assert!(recorder.packet_events.contains_key(&socket_id));
        assert_eq!(
            recorder.packet_events[&socket_id]
                .iter_udp_rcv_packets()
                .count(),
            1,
            "Should have 1 UDP receive event"
        );

        // PACKET_UDP_ENQUEUE goes to per-thread syscall_events
        let connections = &recorder.syscall_events[&tgidpid];
        assert!(
            connections.contains_key(&socket_id),
            "UDP connection should exist"
        );
        assert_eq!(
            connections[&socket_id].iter_udp_enqueue_packets().count(),
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
        let socket_id: SocketId = 1;
        let tgidpid = (100u64 << 32) | 101u64;

        insert_test_socket_metadata(
            &mut recorder,
            socket_id,
            network_protocol::NETWORK_UDP.0,
            network_address_family::NETWORK_AF_INET.0,
            dest_addr,
            53,
            tgidpid,
        );

        let payload_size = 512;

        let udp_send_event = crate::systing::types::packet_event {
            start_ts: 1000,
            end_ts: 2000,
            task: create_test_task_info(100, 101),
            protocol: network_protocol::NETWORK_UDP,
            af: network_address_family::NETWORK_AF_INET,
            dest_addr,
            dest_port: 53,
            seq: 0,
            length: payload_size,
            tcp_flags: 0,
            event_type: packet_event_type::PACKET_UDP_SEND,
            cpu: 0,
            socket_id,
            ..Default::default()
        };

        let udp_rcv_event = crate::systing::types::packet_event {
            start_ts: 3000,
            end_ts: 4000,
            task: create_test_task_info(100, 101),
            protocol: network_protocol::NETWORK_UDP,
            af: network_address_family::NETWORK_AF_INET,
            dest_addr,
            dest_port: 53,
            seq: 0,
            length: payload_size,
            tcp_flags: 0,
            event_type: packet_event_type::PACKET_UDP_RCV,
            cpu: 0,
            socket_id,
            ..Default::default()
        };

        recorder.handle_packet_event(udp_send_event);
        recorder.handle_packet_event(udp_rcv_event);

        assert!(recorder.packet_events.contains_key(&socket_id));
        let udp_events = &recorder.packet_events[&socket_id];

        let udp_send: Vec<_> = udp_events.iter_udp_send_packets().collect();
        assert_eq!(
            udp_send[0].length, payload_size,
            "Length should be payload only"
        );

        let udp_rcv: Vec<_> = udp_events.iter_udp_rcv_packets().collect();
        assert_eq!(
            udp_rcv[0].length, payload_size,
            "Length should be payload only"
        );
    }

    #[test]
    fn test_udp_packet_send_does_not_create_tcp_track() {
        use crate::systing::types::{network_address_family, packet_event_type};
        use std::sync::atomic::AtomicUsize;
        use std::sync::Arc;

        let mut recorder = NetworkRecorder::default();

        let mut dest_addr = [0u8; 16];
        dest_addr[0..4].copy_from_slice(&[8, 8, 8, 8]); // 8.8.8.8
        let socket_id: SocketId = 1;
        let tgidpid = (100u64 << 32) | 101u64;

        insert_test_socket_metadata(
            &mut recorder,
            socket_id,
            network_protocol::NETWORK_UDP.0,
            network_address_family::NETWORK_AF_INET.0,
            dest_addr,
            53,
            tgidpid,
        );

        // Create UDP PACKET_SEND event (qdisc->NIC, shared event type with TCP)
        // Goes to global packet_events
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
            socket_id,
            ..Default::default()
        };

        recorder.handle_packet_event(udp_packet_send_event);

        let id_counter = Arc::new(AtomicUsize::new(1000));
        let pid_uuids = std::collections::HashMap::new();
        let thread_uuids = std::collections::HashMap::new();

        let packets = recorder.generate_trace_packets(&pid_uuids, &thread_uuids, &id_counter);

        // Find socket-level track descriptors
        let socket_tracks: Vec<_> = packets
            .iter()
            .filter(|p| p.has_track_descriptor())
            .filter(|p| p.track_descriptor().name().starts_with("Socket "))
            .collect();

        // Should have exactly 1 socket track for the UDP connection
        assert_eq!(
            socket_tracks.len(),
            1,
            "Should only create ONE socket track for UDP connection, not duplicate TCP+UDP tracks"
        );

        // Verify it's identified as UDP
        let socket_track_name = socket_tracks[0].track_descriptor().name();
        assert!(
            socket_track_name.contains("UDP"),
            "Socket track should be identified as UDP: {}",
            socket_track_name
        );
    }
}
