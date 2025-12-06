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
    sndbuf_used: u32,      // Bytes in send buffer after sendmsg (sk_wmem_queued)
    sndbuf_limit: u32,     // Max send buffer size (sk_sndbuf)
    recv_seq_start: u32,   // TCP copied_seq at recvmsg entry (TCP recv only)
    recv_seq_end: u32,     // TCP copied_seq at recvmsg exit (TCP recv only)
    rcv_nxt_at_entry: u32, // TCP rcv_nxt at entry - kernel's next expected seq (TCP recv only)
    socket_id: SocketId,   // Socket identifier for this event
}

#[derive(Clone, Copy)]
struct PacketEvent {
    ts: u64, // Instant event timestamp
    seq: u32,
    length: u32,
    tcp_flags: u8,
    sndbuf_used: u32, // Bytes in send buffer (sk_wmem_queued) - shows buffer drain on ACK
    sndbuf_limit: u32, // Max send buffer size (sk_sndbuf)
    is_retransmit: bool, // True if this packet is a TCP retransmit
    is_zero_window_probe: bool, // True if this is a zero window probe (sender-side)
    is_zero_window_ack: bool, // True if this is a zero window ACK (receiver-side)
    probe_count: u8,  // Number of probes sent (icsk_probes_out)
    snd_wnd: u32,     // Current send window (0 for zero window condition)
    // Receiver-side fields (populated only for PACKET_ZERO_WINDOW_ACK events)
    rcv_wnd: u32,       // Receiver's current advertised window (unscaled)
    rcv_buf_used: u32,  // Receive buffer bytes used (sk_backlog.rmem_alloc)
    rcv_buf_limit: u32, // Receive buffer limit (sk_rcvbuf)
    window_clamp: u32,  // Maximum window (tp->window_clamp)
    rcv_wscale: u8,     // Receive window scale (actual window = rcv_wnd << rcv_wscale)
    // RTO-specific fields (populated only for PACKET_RTO_TIMEOUT events)
    rto_jiffies: u32,     // Current RTO value in kernel jiffies
    srtt_us: u32,         // Smoothed RTT in microseconds
    rttvar_us: u32,       // RTT variance in microseconds
    retransmit_count: u8, // Number of consecutive RTO timeouts (icsk_retransmits + 1)
    backoff: u8,          // Exponential backoff multiplier (icsk_backoff)
    // Persist timer fields (populated on packet send events)
    icsk_pending: u8, // What timer is pending: 0=none, 1=retrans, 2=delack, 3=probe/persist
    icsk_timeout: u64, // When timer fires (jiffies)
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
    TcpZeroWindowProbe(PacketEvent), // Zero window probe sent (sender-side)
    TcpZeroWindowAck(PacketEvent),   // Zero window ACK sent (receiver-side)
    TcpRtoTimeout(PacketEvent),      // RTO timeout fired (tcp_retransmit_timer)
}

impl EventEntry {
    fn ts(&self) -> u64 {
        match self {
            EventEntry::Send(e) | EventEntry::Recv(e) => e.start_ts,
            EventEntry::TcpEnqueue(e)
            | EventEntry::TcpRcvEstablished(e)
            | EventEntry::TcpQueueRcv(e)
            | EventEntry::TcpBufferQueue(e)
            | EventEntry::UdpSend(e)
            | EventEntry::UdpRcv(e)
            | EventEntry::UdpEnqueue(e)
            | EventEntry::SharedSend(e)
            | EventEntry::TcpZeroWindowProbe(e)
            | EventEntry::TcpZeroWindowAck(e)
            | EventEntry::TcpRtoTimeout(e) => e.ts,
        }
    }
}

#[derive(Default)]
struct ConnectionEvents {
    events: Vec<EventEntry>,
}

impl ConnectionEvents {
    fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    fn iter_tcp_enqueue_packets(&self) -> impl Iterator<Item = &PacketEvent> {
        self.events.iter().filter_map(|e| match e {
            EventEntry::TcpEnqueue(pkt) => Some(pkt),
            _ => None,
        })
    }

    fn iter_tcp_rcv_established_packets(&self) -> impl Iterator<Item = &PacketEvent> {
        self.events.iter().filter_map(|e| match e {
            EventEntry::TcpRcvEstablished(pkt) => Some(pkt),
            _ => None,
        })
    }

    fn iter_tcp_queue_rcv_packets(&self) -> impl Iterator<Item = &PacketEvent> {
        self.events.iter().filter_map(|e| match e {
            EventEntry::TcpQueueRcv(pkt) => Some(pkt),
            _ => None,
        })
    }

    fn iter_tcp_buffer_queue_packets(&self) -> impl Iterator<Item = &PacketEvent> {
        self.events.iter().filter_map(|e| match e {
            EventEntry::TcpBufferQueue(pkt) => Some(pkt),
            _ => None,
        })
    }

    fn iter_udp_send_packets(&self) -> impl Iterator<Item = &PacketEvent> {
        self.events.iter().filter_map(|e| match e {
            EventEntry::UdpSend(pkt) => Some(pkt),
            _ => None,
        })
    }

    fn iter_udp_rcv_packets(&self) -> impl Iterator<Item = &PacketEvent> {
        self.events.iter().filter_map(|e| match e {
            EventEntry::UdpRcv(pkt) => Some(pkt),
            _ => None,
        })
    }

    fn iter_udp_enqueue_packets(&self) -> impl Iterator<Item = &PacketEvent> {
        self.events.iter().filter_map(|e| match e {
            EventEntry::UdpEnqueue(pkt) => Some(pkt),
            _ => None,
        })
    }

    fn iter_shared_send_packets(&self) -> impl Iterator<Item = &PacketEvent> {
        self.events.iter().filter_map(|e| match e {
            EventEntry::SharedSend(pkt) => Some(pkt),
            _ => None,
        })
    }

    fn iter_zero_window_probes(&self) -> impl Iterator<Item = &PacketEvent> {
        self.events.iter().filter_map(|e| match e {
            EventEntry::TcpZeroWindowProbe(pkt) => Some(pkt),
            _ => None,
        })
    }

    fn iter_zero_window_acks(&self) -> impl Iterator<Item = &PacketEvent> {
        self.events.iter().filter_map(|e| match e {
            EventEntry::TcpZeroWindowAck(pkt) => Some(pkt),
            _ => None,
        })
    }

    fn iter_rto_timeouts(&self) -> impl Iterator<Item = &PacketEvent> {
        self.events.iter().filter_map(|e| match e {
            EventEntry::TcpRtoTimeout(pkt) => Some(pkt),
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

pub struct NetworkRecorder {
    pub ringbuf: RingBuffer<network_event>,

    /// Per-thread syscall events (sendmsg/recvmsg)
    /// Key: tgidpid -> list of events (each event includes socket_id)
    ///
    /// Uses a flat Vec<EventEntry> per thread rather than nested HashMap<SocketId, Events>
    /// because: better cache locality (single contiguous allocation), less HashMap overhead,
    /// and acceptable linear scan cost during trace generation (not recording hot path).
    syscall_events: HashMap<u64, Vec<EventEntry>>,

    /// Global packet events by socket_id (not per-thread)
    /// Key: socket_id -> ConnectionEvents
    packet_events: HashMap<SocketId, ConnectionEvents>,

    /// Socket metadata cache (populated from BPF map after tracing)
    socket_metadata: HashMap<SocketId, SocketMetadata>,

    event_name_ids: HashMap<String, u64>,
    hostname_cache: HashMap<IpAddr, String>,
    dns_stats: DnsStats,

    /// Whether to resolve IP addresses to hostnames via DNS
    resolve_addresses: bool,
}

impl Default for NetworkRecorder {
    fn default() -> Self {
        Self {
            ringbuf: RingBuffer::default(),
            syscall_events: HashMap::new(),
            packet_events: HashMap::new(),
            socket_metadata: HashMap::new(),
            event_name_ids: HashMap::new(),
            hostname_cache: HashMap::new(),
            dns_stats: DnsStats::default(),
            resolve_addresses: true,
        }
    }
}

impl NetworkRecorder {
    pub fn new(resolve_addresses: bool) -> Self {
        Self {
            resolve_addresses,
            ..Default::default()
        }
    }

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

        // Skip events without socket_id (shouldn't happen in normal operation)
        if socket_id == 0 {
            return;
        }

        let pkt_event = PacketEvent {
            ts: event.ts,
            seq: event.seq,
            length: event.length,
            tcp_flags: event.tcp_flags,
            sndbuf_used: event.sndbuf_used,
            sndbuf_limit: event.sndbuf_limit,
            is_retransmit: event.is_retransmit != 0,
            is_zero_window_probe: event.is_zero_window_probe != 0,
            is_zero_window_ack: event.is_zero_window_ack != 0,
            probe_count: event.probe_count,
            snd_wnd: event.snd_wnd,
            rcv_wnd: event.rcv_wnd,
            rcv_buf_used: event.rcv_buf_used,
            rcv_buf_limit: event.rcv_buf_limit,
            window_clamp: event.window_clamp,
            rcv_wscale: event.rcv_wscale,
            rto_jiffies: event.rto_jiffies,
            srtt_us: event.srtt_us,
            rttvar_us: event.rttvar_us,
            retransmit_count: event.retransmit_count,
            backoff: event.backoff,
            icsk_pending: event.icsk_pending,
            icsk_timeout: event.icsk_timeout,
        };

        // All packet events go to global packet_events
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
        // Zero window probe events (sender-side)
        else if event.event_type.0 == packet_event_type::PACKET_ZERO_WINDOW_PROBE.0 {
            conn_events
                .events
                .push(EventEntry::TcpZeroWindowProbe(pkt_event));
        }
        // Zero window ACK events (receiver-side)
        else if event.event_type.0 == packet_event_type::PACKET_ZERO_WINDOW_ACK.0 {
            conn_events
                .events
                .push(EventEntry::TcpZeroWindowAck(pkt_event));
        }
        // RTO timeout events
        else if event.event_type.0 == packet_event_type::PACKET_RTO_TIMEOUT.0 {
            conn_events
                .events
                .push(EventEntry::TcpRtoTimeout(pkt_event));
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
        let resolve = self.resolve_addresses;
        self.hostname_cache.entry(addr).or_insert_with(|| {
            if !resolve {
                return addr.to_canonical().to_string();
            }

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

    fn add_packet_instant_events(
        &self,
        packets: &mut Vec<TracePacket>,
        sequence_id: u32,
        track_uuid: u64,
        name_iid: u64,
        packet_events: &[PacketEvent],
    ) {
        for pkt in packet_events {
            let mut instant_event = TrackEvent::default();
            instant_event.set_type(Type::TYPE_INSTANT);
            instant_event.set_name_iid(name_iid);
            instant_event.set_track_uuid(track_uuid);

            // Only show seq annotation for TCP packets (where seq != 0)
            if pkt.seq != 0 {
                let mut seq_annotation = DebugAnnotation::default();
                seq_annotation.set_name("seq".to_string());
                seq_annotation.set_uint_value(pkt.seq as u64);
                instant_event.debug_annotations.push(seq_annotation);
            }

            let mut len_annotation = DebugAnnotation::default();
            len_annotation.set_name("length".to_string());
            len_annotation.set_uint_value(pkt.length as u64);
            instant_event.debug_annotations.push(len_annotation);

            // Only show TCP flags annotation for TCP packets (where flags != 0)
            if pkt.tcp_flags != 0 {
                let mut flags_annotation = DebugAnnotation::default();
                flags_annotation.set_name("flags".to_string());
                flags_annotation.set_string_value(Self::format_tcp_flags(pkt.tcp_flags));
                instant_event.debug_annotations.push(flags_annotation);
            }

            // Add send buffer info (shows buffer drain on ACK receipt)
            if pkt.sndbuf_limit > 0 {
                let mut sndbuf_used_annotation = DebugAnnotation::default();
                sndbuf_used_annotation.set_name("sndbuf_used".to_string());
                sndbuf_used_annotation.set_uint_value(pkt.sndbuf_used as u64);
                instant_event.debug_annotations.push(sndbuf_used_annotation);

                let mut sndbuf_limit_annotation = DebugAnnotation::default();
                sndbuf_limit_annotation.set_name("sndbuf_limit".to_string());
                sndbuf_limit_annotation.set_uint_value(pkt.sndbuf_limit as u64);
                instant_event
                    .debug_annotations
                    .push(sndbuf_limit_annotation);

                // Add fill percentage for easier analysis
                let fill_pct = (pkt.sndbuf_used as u64 * 100) / pkt.sndbuf_limit as u64;
                let mut fill_annotation = DebugAnnotation::default();
                fill_annotation.set_name("sndbuf_fill_pct".to_string());
                fill_annotation.set_uint_value(fill_pct);
                instant_event.debug_annotations.push(fill_annotation);
            }

            // Add persist timer state (icsk_pending: 0=none, 1=retrans, 2=delack, 3=probe/persist)
            if pkt.icsk_pending > 0 {
                let mut pending_annotation = DebugAnnotation::default();
                pending_annotation.set_name("icsk_pending".to_string());
                pending_annotation.set_uint_value(pkt.icsk_pending as u64);
                instant_event.debug_annotations.push(pending_annotation);

                let mut timeout_annotation = DebugAnnotation::default();
                timeout_annotation.set_name("icsk_timeout".to_string());
                timeout_annotation.set_uint_value(pkt.icsk_timeout);
                instant_event.debug_annotations.push(timeout_annotation);

                // Also add RTO and backoff for context
                if pkt.rto_jiffies > 0 {
                    let mut rto_annotation = DebugAnnotation::default();
                    rto_annotation.set_name("rto_jiffies".to_string());
                    rto_annotation.set_uint_value(pkt.rto_jiffies as u64);
                    instant_event.debug_annotations.push(rto_annotation);
                }

                if pkt.backoff > 0 {
                    let mut backoff_annotation = DebugAnnotation::default();
                    backoff_annotation.set_name("backoff".to_string());
                    backoff_annotation.set_uint_value(pkt.backoff as u64);
                    instant_event.debug_annotations.push(backoff_annotation);
                }

                if pkt.probe_count > 0 {
                    let mut probes_annotation = DebugAnnotation::default();
                    probes_annotation.set_name("probe_count".to_string());
                    probes_annotation.set_uint_value(pkt.probe_count as u64);
                    instant_event.debug_annotations.push(probes_annotation);
                }
            }

            // Add retransmit flag if this packet is a TCP retransmit
            if pkt.is_retransmit {
                let mut retransmit_annotation = DebugAnnotation::default();
                retransmit_annotation.set_name("is_retransmit".to_string());
                retransmit_annotation.set_uint_value(1);
                instant_event.debug_annotations.push(retransmit_annotation);
            }

            // Add zero window probe annotations (sender-side)
            if pkt.is_zero_window_probe {
                let mut zwp_annotation = DebugAnnotation::default();
                zwp_annotation.set_name("is_zero_window_probe".to_string());
                zwp_annotation.set_uint_value(1);
                instant_event.debug_annotations.push(zwp_annotation);

                let mut probe_count_annotation = DebugAnnotation::default();
                probe_count_annotation.set_name("probe_count".to_string());
                probe_count_annotation.set_uint_value(pkt.probe_count as u64);
                instant_event.debug_annotations.push(probe_count_annotation);

                let mut snd_wnd_annotation = DebugAnnotation::default();
                snd_wnd_annotation.set_name("snd_wnd".to_string());
                snd_wnd_annotation.set_uint_value(pkt.snd_wnd as u64);
                instant_event.debug_annotations.push(snd_wnd_annotation);
            }

            // Add zero window ACK annotations (receiver-side)
            if pkt.is_zero_window_ack {
                let mut zwa_annotation = DebugAnnotation::default();
                zwa_annotation.set_name("is_zero_window_ack".to_string());
                zwa_annotation.set_uint_value(1);
                instant_event.debug_annotations.push(zwa_annotation);

                let mut rcv_wnd_annotation = DebugAnnotation::default();
                rcv_wnd_annotation.set_name("rcv_wnd".to_string());
                rcv_wnd_annotation.set_uint_value(pkt.rcv_wnd as u64);
                instant_event.debug_annotations.push(rcv_wnd_annotation);

                let mut rcv_buf_used_annotation = DebugAnnotation::default();
                rcv_buf_used_annotation.set_name("rcv_buf_used".to_string());
                rcv_buf_used_annotation.set_uint_value(pkt.rcv_buf_used as u64);
                instant_event
                    .debug_annotations
                    .push(rcv_buf_used_annotation);

                let mut rcv_buf_limit_annotation = DebugAnnotation::default();
                rcv_buf_limit_annotation.set_name("rcv_buf_limit".to_string());
                rcv_buf_limit_annotation.set_uint_value(pkt.rcv_buf_limit as u64);
                instant_event
                    .debug_annotations
                    .push(rcv_buf_limit_annotation);

                // Calculate and emit buffer fill percentage
                if pkt.rcv_buf_limit > 0 {
                    let fill_pct = (pkt.rcv_buf_used as u64 * 100) / pkt.rcv_buf_limit as u64;
                    let mut fill_annotation = DebugAnnotation::default();
                    fill_annotation.set_name("rcv_buf_fill_pct".to_string());
                    fill_annotation.set_uint_value(fill_pct);
                    instant_event.debug_annotations.push(fill_annotation);
                }

                let mut window_clamp_annotation = DebugAnnotation::default();
                window_clamp_annotation.set_name("window_clamp".to_string());
                window_clamp_annotation.set_uint_value(pkt.window_clamp as u64);
                instant_event
                    .debug_annotations
                    .push(window_clamp_annotation);

                let mut rcv_wscale_annotation = DebugAnnotation::default();
                rcv_wscale_annotation.set_name("rcv_wscale".to_string());
                rcv_wscale_annotation.set_uint_value(pkt.rcv_wscale as u64);
                instant_event.debug_annotations.push(rcv_wscale_annotation);
            }

            // Add RTO timeout annotations
            if pkt.rto_jiffies > 0 {
                // Convert jiffies to microseconds using system HZ
                // HZ is typically 100 on modern Linux (1 jiffy = 10000us)
                // We read it at runtime via sysconf(_SC_CLK_TCK)
                let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u64;
                let hz = if hz > 0 { hz } else { 100 }; // fallback to 100
                let rto_us = (pkt.rto_jiffies as u64 * 1_000_000) / hz;

                let mut rto_jiffies_annotation = DebugAnnotation::default();
                rto_jiffies_annotation.set_name("rto_jiffies".to_string());
                rto_jiffies_annotation.set_uint_value(pkt.rto_jiffies as u64);
                instant_event.debug_annotations.push(rto_jiffies_annotation);

                let mut rto_annotation = DebugAnnotation::default();
                rto_annotation.set_name("rto_us".to_string());
                rto_annotation.set_uint_value(rto_us);
                instant_event.debug_annotations.push(rto_annotation);

                let mut srtt_annotation = DebugAnnotation::default();
                srtt_annotation.set_name("srtt_us".to_string());
                srtt_annotation.set_uint_value(pkt.srtt_us as u64);
                instant_event.debug_annotations.push(srtt_annotation);

                let mut rttvar_annotation = DebugAnnotation::default();
                rttvar_annotation.set_name("rttvar_us".to_string());
                rttvar_annotation.set_uint_value(pkt.rttvar_us as u64);
                instant_event.debug_annotations.push(rttvar_annotation);

                let mut retransmit_count_annotation = DebugAnnotation::default();
                retransmit_count_annotation.set_name("retransmit_count".to_string());
                retransmit_count_annotation.set_uint_value(pkt.retransmit_count as u64);
                instant_event
                    .debug_annotations
                    .push(retransmit_count_annotation);

                let mut backoff_annotation = DebugAnnotation::default();
                backoff_annotation.set_name("backoff".to_string());
                backoff_annotation.set_uint_value(pkt.backoff as u64);
                instant_event.debug_annotations.push(backoff_annotation);

                // Convert RTO to milliseconds for easier reading
                let mut rto_ms_annotation = DebugAnnotation::default();
                rto_ms_annotation.set_name("rto_ms".to_string());
                rto_ms_annotation.set_uint_value(rto_us / 1000);
                instant_event.debug_annotations.push(rto_ms_annotation);

                // Convert SRTT to milliseconds for easier reading
                if pkt.srtt_us > 0 {
                    let mut srtt_ms_annotation = DebugAnnotation::default();
                    srtt_ms_annotation.set_name("srtt_ms".to_string());
                    srtt_ms_annotation.set_uint_value((pkt.srtt_us / 1000) as u64);
                    instant_event.debug_annotations.push(srtt_ms_annotation);
                }
            }

            let mut packet = TracePacket::default();
            packet.set_timestamp(pkt.ts);
            packet.set_track_event(instant_event);
            packet.set_trusted_packet_sequence_id(sequence_id);
            packets.push(packet);
        }
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
        for events in self.syscall_events.values() {
            for event in events.iter() {
                let socket_id = match event {
                    EventEntry::Send(e) | EventEntry::Recv(e) => e.socket_id,
                    _ => continue,
                };
                if let Some(metadata) = self.socket_metadata.get(&socket_id) {
                    match event {
                        EventEntry::Send(_) => {
                            protocol_ops_used
                                .insert((metadata.protocol, network_operation::NETWORK_SEND.0));
                        }
                        EventEntry::Recv(_) => {
                            protocol_ops_used
                                .insert((metadata.protocol, network_operation::NETWORK_RECV.0));
                        }
                        _ => {}
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

        // Create IIDs for packet event types unconditionally (only 10 strings)
        self.get_or_create_event_name_iid("TCP packet_enqueue".to_string(), id_counter);
        self.get_or_create_event_name_iid("TCP packet_send".to_string(), id_counter);
        self.get_or_create_event_name_iid("TCP packet_rcv_established".to_string(), id_counter);
        self.get_or_create_event_name_iid("TCP packet_queue_rcv".to_string(), id_counter);
        self.get_or_create_event_name_iid("TCP buffer_queue".to_string(), id_counter);
        self.get_or_create_event_name_iid("TCP zero_window_probe".to_string(), id_counter);
        self.get_or_create_event_name_iid("TCP zero_window_ack".to_string(), id_counter);
        self.get_or_create_event_name_iid("TCP rto_timeout".to_string(), id_counter);
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
                        self.add_packet_instant_events(
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
                        self.add_packet_instant_events(
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
                        self.add_packet_instant_events(
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
                        self.add_packet_instant_events(
                            &mut packets,
                            sequence_id,
                            socket_track_uuid,
                            queue_rcv_iid,
                            &queue_rcv_pkts,
                        );
                    }

                    // Zero window probe events (sender-side)
                    let zwp_pkts: Vec<_> = events.iter_zero_window_probes().copied().collect();
                    if !zwp_pkts.is_empty() {
                        let zwp_iid = *self.event_name_ids.get("TCP zero_window_probe").unwrap();
                        self.add_packet_instant_events(
                            &mut packets,
                            sequence_id,
                            socket_track_uuid,
                            zwp_iid,
                            &zwp_pkts,
                        );
                    }

                    // Zero window ACK events (receiver-side)
                    let zwa_pkts: Vec<_> = events.iter_zero_window_acks().copied().collect();
                    if !zwa_pkts.is_empty() {
                        let zwa_iid = *self.event_name_ids.get("TCP zero_window_ack").unwrap();
                        self.add_packet_instant_events(
                            &mut packets,
                            sequence_id,
                            socket_track_uuid,
                            zwa_iid,
                            &zwa_pkts,
                        );
                    }

                    // RTO timeout events
                    let rto_pkts: Vec<_> = events.iter_rto_timeouts().copied().collect();
                    if !rto_pkts.is_empty() {
                        let rto_iid = *self.event_name_ids.get("TCP rto_timeout").unwrap();
                        self.add_packet_instant_events(
                            &mut packets,
                            sequence_id,
                            socket_track_uuid,
                            rto_iid,
                            &rto_pkts,
                        );
                    }

                    // TCP buffer queue events
                    let buffer_queue_pkts: Vec<_> =
                        events.iter_tcp_buffer_queue_packets().copied().collect();
                    if !buffer_queue_pkts.is_empty() {
                        let buffer_queue_iid =
                            *self.event_name_ids.get("TCP buffer_queue").unwrap();
                        self.add_packet_instant_events(
                            &mut packets,
                            sequence_id,
                            socket_track_uuid,
                            buffer_queue_iid,
                            &buffer_queue_pkts,
                        );
                    }
                } else {
                    // UDP packet events
                    let udp_send_pkts: Vec<_> = events.iter_udp_send_packets().copied().collect();
                    if !udp_send_pkts.is_empty() {
                        let send_iid = *self.event_name_ids.get("UDP send").unwrap();
                        self.add_packet_instant_events(
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
                        self.add_packet_instant_events(
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
                        self.add_packet_instant_events(
                            &mut packets,
                            sequence_id,
                            socket_track_uuid,
                            send_iid,
                            &shared_send_pkts,
                        );
                    }

                    // UDP enqueue events
                    let udp_enqueue_pkts: Vec<_> =
                        events.iter_udp_enqueue_packets().copied().collect();
                    if !udp_enqueue_pkts.is_empty() {
                        let enqueue_iid = *self.event_name_ids.get("UDP enqueue").unwrap();
                        self.add_packet_instant_events(
                            &mut packets,
                            sequence_id,
                            socket_track_uuid,
                            enqueue_iid,
                            &udp_enqueue_pkts,
                        );
                    }
                }
            }
        }

        // ====================================================================
        // Phase 4: Generate per-thread "Network" tracks (single flat track per thread)
        // ====================================================================
        for (tgidpid, events) in self.syscall_events.iter() {
            if events.is_empty() {
                continue;
            }

            // Create a single "Network" track for this thread
            let network_track_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;

            let network_track_desc = crate::perfetto::generate_pidtgid_track_descriptor(
                pid_uuids,
                thread_uuids,
                tgidpid,
                "Network".to_string(),
                network_track_uuid,
            );

            let mut network_track_packet = TracePacket::default();
            network_track_packet.set_track_descriptor(network_track_desc);
            packets.push(network_track_packet);

            // Emit all events directly on this single track
            for event_entry in events.iter() {
                match event_entry {
                    EventEntry::Send(event) => {
                        let protocol = match self.socket_metadata.get(&event.socket_id) {
                            Some(m) => m.protocol,
                            None => {
                                tracing::debug!(
                                    "Missing socket metadata for socket_id {}",
                                    event.socket_id
                                );
                                0
                            }
                        };
                        let proto_str = Self::protocol_to_str(protocol);
                        let send_event_name = format!("{proto_str}_send");
                        let send_name_iid = self
                            .event_name_ids
                            .get(&send_event_name)
                            .copied()
                            .unwrap_or(0);

                        let mut begin_event = TrackEvent::default();
                        begin_event.set_type(Type::TYPE_SLICE_BEGIN);
                        if send_name_iid > 0 {
                            begin_event.set_name_iid(send_name_iid);
                        }
                        begin_event.set_track_uuid(network_track_uuid);

                        // Add socket_id annotation
                        let mut socket_annotation = DebugAnnotation::default();
                        socket_annotation.set_name("socket_id".to_string());
                        socket_annotation.set_uint_value(event.socket_id);
                        begin_event.debug_annotations.push(socket_annotation);

                        // Add socket info string for readability
                        let socket_info = self.socket_track_name(event.socket_id);
                        let mut socket_info_annotation = DebugAnnotation::default();
                        socket_info_annotation.set_name("socket".to_string());
                        socket_info_annotation.set_string_value(socket_info);
                        begin_event.debug_annotations.push(socket_info_annotation);

                        let mut bytes_annotation = DebugAnnotation::default();
                        bytes_annotation.set_name("bytes".to_string());
                        bytes_annotation.set_uint_value(event.bytes as u64);
                        begin_event.debug_annotations.push(bytes_annotation);

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
                        end_event.set_track_uuid(network_track_uuid);

                        let mut end_packet = TracePacket::default();
                        end_packet.set_timestamp(event.end_ts);
                        end_packet.set_track_event(end_event);
                        end_packet.set_trusted_packet_sequence_id(sequence_id);
                        packets.push(end_packet);
                    }
                    EventEntry::Recv(event) => {
                        let protocol = match self.socket_metadata.get(&event.socket_id) {
                            Some(m) => m.protocol,
                            None => {
                                tracing::debug!(
                                    "Missing socket metadata for socket_id {}",
                                    event.socket_id
                                );
                                0
                            }
                        };
                        let proto_str = Self::protocol_to_str(protocol);
                        let recv_event_name = format!("{proto_str}_recv");
                        let recv_name_iid = self
                            .event_name_ids
                            .get(&recv_event_name)
                            .copied()
                            .unwrap_or(0);

                        let mut begin_event = TrackEvent::default();
                        begin_event.set_type(Type::TYPE_SLICE_BEGIN);
                        if recv_name_iid > 0 {
                            begin_event.set_name_iid(recv_name_iid);
                        }
                        begin_event.set_track_uuid(network_track_uuid);

                        // Add socket_id annotation
                        let mut socket_annotation = DebugAnnotation::default();
                        socket_annotation.set_name("socket_id".to_string());
                        socket_annotation.set_uint_value(event.socket_id);
                        begin_event.debug_annotations.push(socket_annotation);

                        // Add socket info string for readability
                        let socket_info = self.socket_track_name(event.socket_id);
                        let mut socket_info_annotation = DebugAnnotation::default();
                        socket_info_annotation.set_name("socket".to_string());
                        socket_info_annotation.set_string_value(socket_info);
                        begin_event.debug_annotations.push(socket_info_annotation);

                        // Add bytes annotation
                        let mut bytes_annotation = DebugAnnotation::default();
                        bytes_annotation.set_name("bytes".to_string());
                        bytes_annotation.set_uint_value(event.bytes as u64);
                        begin_event.debug_annotations.push(bytes_annotation);

                        // Add TCP receive sequence annotations (when fields are non-zero)
                        if event.recv_seq_start > 0 || event.recv_seq_end > 0 {
                            let mut seq_start_annotation = DebugAnnotation::default();
                            seq_start_annotation.set_name("recv_seq_start".to_string());
                            seq_start_annotation.set_uint_value(event.recv_seq_start as u64);
                            begin_event.debug_annotations.push(seq_start_annotation);

                            let mut seq_end_annotation = DebugAnnotation::default();
                            seq_end_annotation.set_name("recv_seq_end".to_string());
                            seq_end_annotation.set_uint_value(event.recv_seq_end as u64);
                            begin_event.debug_annotations.push(seq_end_annotation);

                            if event.rcv_nxt_at_entry > 0 {
                                let mut rcv_nxt_annotation = DebugAnnotation::default();
                                rcv_nxt_annotation.set_name("rcv_nxt".to_string());
                                rcv_nxt_annotation.set_uint_value(event.rcv_nxt_at_entry as u64);
                                begin_event.debug_annotations.push(rcv_nxt_annotation);

                                // Calculate and add bytes_available (data buffered in kernel)
                                let bytes_available =
                                    event.rcv_nxt_at_entry.wrapping_sub(event.recv_seq_start);
                                if bytes_available > 0 && bytes_available < 64 * 1024 * 1024 {
                                    let mut available_annotation = DebugAnnotation::default();
                                    available_annotation.set_name("bytes_available".to_string());
                                    available_annotation.set_uint_value(bytes_available as u64);
                                    begin_event.debug_annotations.push(available_annotation);
                                }
                            }
                        }

                        let mut begin_packet = TracePacket::default();
                        begin_packet.set_timestamp(event.start_ts);
                        begin_packet.set_track_event(begin_event);
                        begin_packet.set_trusted_packet_sequence_id(sequence_id);
                        packets.push(begin_packet);

                        let mut end_event = TrackEvent::default();
                        end_event.set_type(Type::TYPE_SLICE_END);
                        end_event.set_track_uuid(network_track_uuid);

                        let mut end_packet = TracePacket::default();
                        end_packet.set_timestamp(event.end_ts);
                        end_packet.set_track_event(end_event);
                        end_packet.set_trusted_packet_sequence_id(sequence_id);
                        packets.push(end_packet);
                    }
                    _ => {
                        // Packet events are handled separately in Phase 3
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

    /// Returns the minimum timestamp from all network events, or None if no events recorded.
    pub fn min_timestamp(&self) -> Option<u64> {
        let syscall_min = self
            .syscall_events
            .values()
            .filter_map(|events| events.first())
            .map(|e| e.ts())
            .min();

        let packet_min = self
            .packet_events
            .values()
            .filter_map(|conn| conn.events.first())
            .map(|e| e.ts())
            .min();

        syscall_min.into_iter().chain(packet_min).min()
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
            recv_seq_start: event.recv_seq_start,
            recv_seq_end: event.recv_seq_end,
            rcv_nxt_at_entry: event.rcv_nxt_at_entry,
            socket_id,
        };

        // Route to per-thread syscall_events list (pre-allocate to reduce reallocations)
        let thread_events = self
            .syscall_events
            .entry(tgidpid)
            .or_insert_with(|| Vec::with_capacity(64));

        if event.operation.0 == network_operation::NETWORK_SEND.0 {
            thread_events.push(EventEntry::Send(net_event));
        } else if event.operation.0 == network_operation::NETWORK_RECV.0 {
            thread_events.push(EventEntry::Recv(net_event));
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
    ) {
        recorder.socket_metadata.insert(
            socket_id,
            SocketMetadata {
                protocol,
                af,
                dest_addr,
                dest_port,
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

        let events = &recorder.syscall_events[&tgidpid];
        assert_eq!(events.len(), 1);

        // Check the send event
        let sends: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                EventEntry::Send(evt) => Some(evt),
                _ => None,
            })
            .collect();
        assert_eq!(sends.len(), 1);
        assert_eq!(sends[0].bytes, 1024);
        assert_eq!(sends[0].socket_id, socket_id);
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
        let events = &recorder.syscall_events[&tgidpid];

        let sends: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                EventEntry::Send(evt) => Some(evt),
                _ => None,
            })
            .collect();
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
        let events = &recorder.syscall_events[&tgidpid];
        // Now we have 2 events in a single list (not separate by socket)
        assert_eq!(events.len(), 2);

        // Check that both socket IDs are present
        let socket_ids: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                EventEntry::Send(evt) => Some(evt.socket_id),
                _ => None,
            })
            .collect();
        assert!(socket_ids.contains(&tcp_socket_id));
        assert!(socket_ids.contains(&udp_socket_id));
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

        insert_test_socket_metadata(
            &mut recorder,
            socket_id,
            network_protocol::NETWORK_TCP.0,
            network_address_family::NETWORK_AF_INET.0,
            dest_addr,
            8080,
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

        // Packets: interned data, network track, slice begin, slice end
        assert_eq!(packets.len(), 4);

        let interned_packet = &packets[0];
        assert!(interned_packet.interned_data.is_some());

        let network_track_packet = &packets[1];
        assert!(network_track_packet.has_track_descriptor());
        let network_track_desc = network_track_packet.track_descriptor();
        assert_eq!(network_track_desc.name(), "Network");

        let begin_packet = &packets[2];
        assert!(begin_packet.has_track_event());
        assert_eq!(begin_packet.timestamp(), 1000);
        let begin_event = begin_packet.track_event();
        assert_eq!(begin_event.type_(), Type::TYPE_SLICE_BEGIN);
        assert_eq!(begin_event.track_uuid(), network_track_desc.uuid());

        // Check debug annotations include socket_id, socket, and bytes
        assert!(begin_event.debug_annotations.len() >= 3);
        let socket_id_annotation = begin_event
            .debug_annotations
            .iter()
            .find(|a| a.name() == "socket_id");
        assert!(socket_id_annotation.is_some());
        assert_eq!(socket_id_annotation.unwrap().uint_value(), socket_id);

        let bytes_annotation = begin_event
            .debug_annotations
            .iter()
            .find(|a| a.name() == "bytes");
        assert!(bytes_annotation.is_some());
        assert_eq!(bytes_annotation.unwrap().uint_value(), 1024);

        let end_packet = &packets[3];
        assert!(end_packet.has_track_event());
        assert_eq!(end_packet.timestamp(), 2000);
        let end_event = end_packet.track_event();
        assert_eq!(end_event.type_(), Type::TYPE_SLICE_END);
        assert_eq!(end_event.track_uuid(), network_track_desc.uuid());

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
        let events = &recorder.syscall_events[&tgidpid];
        // 2 events: 1 send + 1 recv
        assert_eq!(events.len(), 2);

        let sends: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                EventEntry::Send(evt) => Some(evt),
                _ => None,
            })
            .collect();
        assert_eq!(sends.len(), 1);
        assert_eq!(sends[0].bytes, 1024);

        let recvs: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                EventEntry::Recv(evt) => Some(evt),
                _ => None,
            })
            .collect();
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

        let events = &recorder.syscall_events[&tgidpid];
        assert_eq!(events.len(), 1);

        let sends: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                EventEntry::Send(evt) => Some(evt),
                _ => None,
            })
            .collect();
        assert_eq!(sends.len(), 1);
        assert_eq!(sends[0].bytes, 2048);
        assert_eq!(sends[0].socket_id, socket_id);
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
        let events = &recorder.syscall_events[&tgidpid];
        assert_eq!(events.len(), 1);

        let sends: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                EventEntry::Send(evt) => Some(evt),
                _ => None,
            })
            .collect();
        assert_eq!(sends.len(), 1);
        assert_eq!(sends[0].bytes, 512);
        assert_eq!(sends[0].socket_id, socket_id);
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
        let events = &recorder.syscall_events[&tgidpid];

        // Should have 2 events (both sockets have sends)
        assert_eq!(events.len(), 2);

        // Collect sends by socket_id
        let sends: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                EventEntry::Send(evt) => Some(evt),
                _ => None,
            })
            .collect();

        // Verify IPv4 socket
        let ipv4_send = sends.iter().find(|s| s.socket_id == ipv4_socket_id);
        assert!(ipv4_send.is_some());
        assert_eq!(ipv4_send.unwrap().bytes, 1024);

        // Verify IPv6 socket
        let ipv6_send = sends.iter().find(|s| s.socket_id == ipv6_socket_id);
        assert!(ipv6_send.is_some());
        assert_eq!(ipv6_send.unwrap().bytes, 2048);
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
        let events = &recorder.syscall_events[&tgidpid];
        // 2 events: 1 send + 1 recv
        assert_eq!(events.len(), 2);

        let sends: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                EventEntry::Send(evt) => Some(evt),
                _ => None,
            })
            .collect();
        assert_eq!(sends.len(), 1);
        assert_eq!(sends[0].bytes, 1024);
        assert_eq!(sends[0].socket_id, socket_id);

        let recvs: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                EventEntry::Recv(evt) => Some(evt),
                _ => None,
            })
            .collect();
        assert_eq!(recvs.len(), 1);
        assert_eq!(recvs[0].bytes, 512);
        assert_eq!(recvs[0].socket_id, socket_id);
    }

    #[test]
    fn test_packet_event_rcv_established() {
        use crate::systing::types::{network_address_family, packet_event_type};

        let mut recorder = NetworkRecorder::default();

        let mut dest_addr = [0u8; 16];
        dest_addr[0..4].copy_from_slice(&[192, 168, 1, 100]);
        let socket_id: SocketId = 1;

        let event = crate::systing::types::packet_event {
            ts: 1000,
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
            ts: 1100,
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
            ts: 1110,
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

        // PACKET_BUFFER_QUEUE goes to global packet_events
        assert!(recorder.packet_events.contains_key(&socket_id));

        let buffer_queue: Vec<_> = recorder.packet_events[&socket_id]
            .iter_tcp_buffer_queue_packets()
            .collect();
        assert_eq!(buffer_queue.len(), 1);
        assert_eq!(buffer_queue[0].ts, 1110);
    }

    #[test]
    fn test_multiple_receive_packet_events() {
        use crate::systing::types::{network_address_family, packet_event_type};

        let mut recorder = NetworkRecorder::default();

        let mut dest_addr = [0u8; 16];
        dest_addr[0..4].copy_from_slice(&[192, 168, 1, 100]);
        let socket_id: SocketId = 1;

        insert_test_socket_metadata(
            &mut recorder,
            socket_id,
            network_protocol::NETWORK_TCP.0,
            network_address_family::NETWORK_AF_INET.0,
            dest_addr,
            8080,
        );

        let rcv_est_event = crate::systing::types::packet_event {
            ts: 1000,
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
            ts: 1100,
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
            ts: 1110,
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

        // PACKET_BUFFER_QUEUE also goes to global packet_events (no longer per-thread)
        assert_eq!(
            recorder.packet_events[&socket_id]
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

        insert_test_socket_metadata(
            &mut recorder,
            socket_id,
            network_protocol::NETWORK_TCP.0,
            network_address_family::NETWORK_AF_INET.0,
            dest_addr,
            8080,
        );

        let packet1 = crate::systing::types::packet_event {
            ts: 1000,
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
            ts: 1100,
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

        // PACKET_BUFFER_QUEUE goes to global packet_events (no longer per-thread)
        assert!(recorder.packet_events.contains_key(&socket_id));
        let buffer_queue: Vec<_> = recorder.packet_events[&socket_id]
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

        insert_test_socket_metadata(
            &mut recorder,
            socket_id,
            network_protocol::NETWORK_TCP.0,
            network_address_family::NETWORK_AF_INET.0,
            dest_addr,
            8080,
        );

        let rcv_est = crate::systing::types::packet_event {
            ts: 1000,
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
            ts: 1100,
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
            ts: 1110,
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

        // No syscall events in this test, so no "Network" track should be created
        // (only packet events are present)
    }

    #[test]
    fn test_packet_events_send_and_receive() {
        use crate::systing::types::{network_address_family, packet_event_type};

        let mut recorder = NetworkRecorder::default();

        let mut dest_addr = [0u8; 16];
        dest_addr[0..4].copy_from_slice(&[192, 168, 1, 100]);
        let socket_id: SocketId = 1;

        insert_test_socket_metadata(
            &mut recorder,
            socket_id,
            network_protocol::NETWORK_TCP.0,
            network_address_family::NETWORK_AF_INET.0,
            dest_addr,
            8080,
        );

        let send_enqueue = crate::systing::types::packet_event {
            ts: 1000,
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
            ts: 2000,
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

        // PACKET_BUFFER_QUEUE also goes to global packet_events (no longer per-thread)
        assert_eq!(
            recorder.packet_events[&socket_id]
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

        insert_test_socket_metadata(
            &mut recorder,
            udp_socket_id,
            network_protocol::NETWORK_UDP.0,
            network_address_family::NETWORK_AF_INET.0,
            dest_addr,
            53,
        );
        insert_test_socket_metadata(
            &mut recorder,
            tcp_socket_id,
            network_protocol::NETWORK_TCP.0,
            network_address_family::NETWORK_AF_INET.0,
            dest_addr,
            80,
        );

        // Create UDP PACKET_UDP_SEND event - goes to global packet_events
        let udp_send_event = crate::systing::types::packet_event {
            ts: 1000,
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
            ts: 2000,
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
            ts: 4000,
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

        insert_test_socket_metadata(
            &mut recorder,
            socket_id,
            network_protocol::NETWORK_UDP.0,
            network_address_family::NETWORK_AF_INET.0,
            dest_addr,
            443,
        );

        // UDP receive event (IP->UDP) - goes to global packet_events
        let udp_rcv_event = crate::systing::types::packet_event {
            ts: 1000,
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

        // UDP enqueue event (UDP->buffer) - goes to global packet_events
        let udp_enqueue_event = crate::systing::types::packet_event {
            ts: 1500,
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

        // Both PACKET_UDP_RCV and PACKET_UDP_ENQUEUE go to global packet_events
        assert_eq!(recorder.packet_events.len(), 1);
        assert!(recorder.packet_events.contains_key(&socket_id));
        assert_eq!(
            recorder.packet_events[&socket_id]
                .iter_udp_rcv_packets()
                .count(),
            1,
            "Should have 1 UDP receive event"
        );

        assert_eq!(
            recorder.packet_events[&socket_id]
                .iter_udp_enqueue_packets()
                .count(),
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

        insert_test_socket_metadata(
            &mut recorder,
            socket_id,
            network_protocol::NETWORK_UDP.0,
            network_address_family::NETWORK_AF_INET.0,
            dest_addr,
            53,
        );

        let payload_size = 512;

        let udp_send_event = crate::systing::types::packet_event {
            ts: 1000,
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
            ts: 3000,
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

        insert_test_socket_metadata(
            &mut recorder,
            socket_id,
            network_protocol::NETWORK_UDP.0,
            network_address_family::NETWORK_AF_INET.0,
            dest_addr,
            53,
        );

        // Create UDP PACKET_SEND event (qdisc->NIC, shared event type with TCP)
        // Goes to global packet_events
        let udp_packet_send_event = crate::systing::types::packet_event {
            ts: 1000,
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
