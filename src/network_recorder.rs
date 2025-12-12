use std::collections::HashMap;
#[cfg(test)]
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
use std::sync::{Arc, OnceLock};

/// Cached system HZ value (clock ticks per second).
/// This is constant for the lifetime of the process.
static SYSTEM_HZ: OnceLock<u64> = OnceLock::new();

/// Get the system HZ value, caching it on first call.
fn system_hz() -> u64 {
    *SYSTEM_HZ.get_or_init(|| {
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u64;
        if hz > 0 {
            hz
        } else {
            100
        }
    })
}

/// Extension trait for easier debug annotation building on TrackEvent.
/// Reduces the 4-line annotation pattern to a single method call.
trait DebugAnnotationBuilder {
    fn add_uint(&mut self, name: &str, value: u64);
    fn add_string(&mut self, name: &str, value: String);
    fn add_uint_nonzero(&mut self, name: &str, value: u64);
    fn add_bool(&mut self, name: &str, value: bool);
}

impl DebugAnnotationBuilder for TrackEvent {
    fn add_uint(&mut self, name: &str, value: u64) {
        let mut annotation = DebugAnnotation::default();
        annotation.set_name(name.to_string());
        annotation.set_uint_value(value);
        self.debug_annotations.push(annotation);
    }

    fn add_string(&mut self, name: &str, value: String) {
        let mut annotation = DebugAnnotation::default();
        annotation.set_name(name.to_string());
        annotation.set_string_value(value);
        self.debug_annotations.push(annotation);
    }

    fn add_uint_nonzero(&mut self, name: &str, value: u64) {
        if value > 0 {
            self.add_uint(name, value);
        }
    }

    fn add_bool(&mut self, name: &str, value: bool) {
        if value {
            self.add_uint(name, 1);
        }
    }
}

/// Unique identifier for a network connection (full 4-tuple).
/// Used for testing Display formatting and IP address parsing.
#[cfg(test)]
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
struct ConnectionId {
    protocol: u32,
    af: u32,
    src_addr: [u8; 16],
    src_port: u16,
    dest_addr: [u8; 16],
    dest_port: u16,
}

fn parse_ip_addr(af: u32, addr: &[u8; 16]) -> IpAddr {
    use crate::systing::types::network_address_family;
    if af == network_address_family::NETWORK_AF_INET.0 {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&addr[0..4]);
        IpAddr::V4(Ipv4Addr::from(bytes))
    } else if af == network_address_family::NETWORK_AF_INET6.0 {
        IpAddr::V6(Ipv6Addr::from(*addr))
    } else {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    }
}

fn protocol_str(protocol: u32) -> &'static str {
    use crate::systing::types::network_protocol;
    if protocol == network_protocol::NETWORK_TCP.0 {
        "TCP"
    } else if protocol == network_protocol::NETWORK_UDP.0 {
        "UDP"
    } else {
        "UNKNOWN"
    }
}

/// Convert SKB_DROP_REASON_* code to human-readable string
/// Based on enum skb_drop_reason from include/net/dropreason-core.h
fn drop_reason_str(reason: u32) -> &'static str {
    match reason {
        0 => "NOT_DROPPED_YET",
        1 => "CONSUMED",
        2 => "NOT_SPECIFIED",
        3 => "NO_SOCKET",
        4 => "SOCKET_CLOSE",
        5 => "SOCKET_FILTER",
        6 => "SOCKET_RCVBUFF",
        7 => "UNIX_DISCONNECT",
        8 => "UNIX_SKIP_OOB",
        9 => "PKT_TOO_SMALL",
        10 => "TCP_CSUM",
        11 => "UDP_CSUM",
        12 => "NETFILTER_DROP",
        13 => "OTHERHOST",
        14 => "IP_CSUM",
        15 => "IP_INHDR",
        16 => "IP_RPFILTER",
        17 => "UNICAST_IN_L2_MULTICAST",
        18 => "XFRM_POLICY",
        19 => "IP_NOPROTO",
        20 => "PROTO_MEM",
        21 => "TCP_AUTH_HDR",
        22 => "TCP_MD5NOTFOUND",
        23 => "TCP_MD5UNEXPECTED",
        24 => "TCP_MD5FAILURE",
        25 => "TCP_AONOTFOUND",
        26 => "TCP_AOUNEXPECTED",
        27 => "TCP_AOKEYNOTFOUND",
        28 => "TCP_AOFAILURE",
        29 => "SOCKET_BACKLOG",
        30 => "TCP_FLAGS",
        31 => "TCP_ABORT_ON_DATA",
        32 => "TCP_ZEROWINDOW",
        33 => "TCP_OLD_DATA",
        34 => "TCP_OVERWINDOW",
        35 => "TCP_OFOMERGE",
        36 => "TCP_RFC7323_PAWS",
        37 => "TCP_RFC7323_PAWS_ACK",
        38 => "TCP_OLD_SEQUENCE",
        39 => "TCP_INVALID_SEQUENCE",
        40 => "TCP_INVALID_ACK_SEQUENCE",
        41 => "TCP_RESET",
        42 => "TCP_INVALID_SYN",
        43 => "TCP_CLOSE",
        44 => "TCP_FASTOPEN",
        45 => "TCP_OLD_ACK",
        46 => "TCP_TOO_OLD_ACK",
        47 => "TCP_ACK_UNSENT_DATA",
        48 => "TCP_OFO_QUEUE_PRUNE",
        49 => "TCP_OFO_DROP",
        50 => "IP_OUTNOROUTES",
        51 => "BPF_CGROUP_EGRESS",
        52 => "IPV6DISABLED",
        53 => "NEIGH_CREATEFAIL",
        54 => "NEIGH_FAILED",
        55 => "NEIGH_QUEUEFULL",
        56 => "NEIGH_DEAD",
        57 => "TC_EGRESS",
        58 => "SECURITY_HOOK",
        59 => "QDISC_DROP",
        60 => "QDISC_OVERLIMIT",
        61 => "QDISC_CONGESTED",
        62 => "CAKE_FLOOD",
        63 => "FQ_BAND_LIMIT",
        64 => "FQ_HORIZON_LIMIT",
        65 => "FQ_FLOW_LIMIT",
        66 => "CPU_BACKLOG",
        67 => "XDP",
        68 => "TC_INGRESS",
        69 => "UNHANDLED_PROTO",
        70 => "SKB_CSUM",
        71 => "SKB_GSO_SEG",
        72 => "SKB_UCOPY_FAULT",
        73 => "DEV_HDR",
        74 => "DEV_READY",
        75 => "FULL_RING",
        76 => "NOMEM",
        77 => "HDR_TRUNC",
        78 => "TAP_FILTER",
        79 => "TAP_TXFILTER",
        80 => "ICMP_CSUM",
        81 => "INVALID_PROTO",
        82 => "IP_INADDRERRORS",
        83 => "IP_INNOROUTES",
        84 => "IP_LOCAL_SOURCE",
        85 => "IP_INVALID_SOURCE",
        86 => "IP_LOCALNET",
        87 => "IP_INVALID_DEST",
        88 => "PKT_TOO_BIG",
        89 => "DUP_FRAG",
        90 => "FRAG_REASM_TIMEOUT",
        91 => "FRAG_TOO_FAR",
        92 => "TCP_MINTTL",
        93 => "IPV6_BAD_EXTHDR",
        94 => "IPV6_NDISC_FRAG",
        95 => "IPV6_NDISC_HOP_LIMIT",
        96 => "IPV6_NDISC_BAD_CODE",
        97 => "IPV6_NDISC_BAD_OPTIONS",
        98 => "IPV6_NDISC_NS_OTHERHOST",
        99 => "QUEUE_PURGE",
        100 => "TC_COOKIE_ERROR",
        101 => "PACKET_SOCK_ERROR",
        102 => "TC_CHAIN_NOTFOUND",
        103 => "TC_RECLASSIFY_LOOP",
        104 => "VXLAN_INVALID_HDR",
        105 => "VXLAN_VNI_NOT_FOUND",
        106 => "MAC_INVALID_SOURCE",
        107 => "VXLAN_ENTRY_EXISTS",
        108 => "NO_TX_TARGET",
        109 => "IP_TUNNEL_ECN",
        110 => "TUNNEL_TXINFO",
        111 => "LOCAL_MAC",
        112 => "ARP_PVLAN_DISABLE",
        113 => "MAC_IEEE_MAC_CONTROL",
        114 => "BRIDGE_INGRESS_STP_STATE",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
impl ConnectionId {
    fn src_ip_addr(&self) -> IpAddr {
        parse_ip_addr(self.af, &self.src_addr)
    }

    fn dest_ip_addr(&self) -> IpAddr {
        parse_ip_addr(self.af, &self.dest_addr)
    }
}

#[cfg(test)]
impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}->{}:{}",
            protocol_str(self.protocol),
            self.src_ip_addr(),
            self.src_port,
            self.dest_ip_addr(),
            self.dest_port
        )
    }
}

/// Metadata for a socket connection, read from BPF map after tracing
#[derive(Debug, Clone)]
pub struct SocketMetadata {
    pub protocol: u32,
    pub af: u32,
    pub src_addr: [u8; 16],
    pub src_port: u16,
    pub dest_addr: [u8; 16],
    pub dest_port: u16,
}

impl SocketMetadata {
    fn src_ip_addr(&self) -> IpAddr {
        parse_ip_addr(self.af, &self.src_addr)
    }

    fn dest_ip_addr(&self) -> IpAddr {
        parse_ip_addr(self.af, &self.dest_addr)
    }

    fn protocol_str(&self) -> &'static str {
        protocol_str(self.protocol)
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
    // Drop event fields (for PACKET_SKB_DROP, PACKET_CPU_BACKLOG_DROP, etc.)
    drop_reason: u32,   // SKB_DROP_REASON_* code
    drop_location: u64, // Kernel code address that dropped the packet
    qlen: u32,          // Queue length at time of event
    qlen_limit: u32,    // Queue limit (for backlog: netdev_max_backlog)
    // TSQ/memory pressure fields
    sk_wmem_alloc: u32, // TCP Small Queue: current allocated memory
    tsq_limit: u32,     // TCP Small Queue: limit that was exceeded
    // Qdisc tracing fields (for PACKET_QDISC_* events)
    txq_state: u32,        // TX queue state: XOFF (driver stopped), FROZEN, etc.
    qdisc_state: u32,      // Qdisc state: MISSED, DRAINING, etc.
    qdisc_backlog: u32,    // Bytes queued in qdisc
    skb_addr: u64,         // SKB address for packet correlation
    qdisc_latency_us: u32, // Qdisc residence time in microseconds (dequeue only)
}

#[derive(Clone, Copy)]
struct PollEvent {
    ts: u64,
    socket_id: SocketId,
    requested_events: u32,
    returned_events: u32,
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
    TcpRtoTimeout(PacketEvent),
    PollReady(PollEvent),
    // New drop/throttle events
    SkbDrop(PacketEvent),        // SKB dropped (kfree_skb tracepoint)
    CpuBacklogDrop(PacketEvent), // CPU backlog queue drop
    MemPressure(PacketEvent),    // TCP memory pressure (send buffer blocked)
    // Qdisc tracing events
    QdiscEnqueue(PacketEvent), // Packet entered qdisc queue
    QdiscDequeue(PacketEvent), // Packet left qdisc queue
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
            | EventEntry::TcpRtoTimeout(e)
            | EventEntry::SkbDrop(e)
            | EventEntry::CpuBacklogDrop(e)
            | EventEntry::MemPressure(e)
            | EventEntry::QdiscEnqueue(e)
            | EventEntry::QdiscDequeue(e) => e.ts,
            EventEntry::PollReady(e) => e.ts,
        }
    }
}

/// Macro to generate iterator methods for ConnectionEvents that filter by event type.
macro_rules! packet_event_iter {
    ($fn_name:ident, $variant:ident) => {
        fn $fn_name(&self) -> impl Iterator<Item = &PacketEvent> {
            self.events.iter().filter_map(|e| match e {
                EventEntry::$variant(pkt) => Some(pkt),
                _ => None,
            })
        }
    };
}

#[derive(Default)]
struct ConnectionEvents {
    events: Vec<EventEntry>,
}

impl ConnectionEvents {
    fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    // TCP packet events
    packet_event_iter!(iter_tcp_enqueue_packets, TcpEnqueue);
    packet_event_iter!(iter_tcp_rcv_established_packets, TcpRcvEstablished);
    packet_event_iter!(iter_tcp_queue_rcv_packets, TcpQueueRcv);
    packet_event_iter!(iter_tcp_buffer_queue_packets, TcpBufferQueue);
    packet_event_iter!(iter_zero_window_probes, TcpZeroWindowProbe);
    packet_event_iter!(iter_zero_window_acks, TcpZeroWindowAck);
    packet_event_iter!(iter_rto_timeouts, TcpRtoTimeout);

    // UDP packet events
    packet_event_iter!(iter_udp_send_packets, UdpSend);
    packet_event_iter!(iter_udp_rcv_packets, UdpRcv);
    packet_event_iter!(iter_udp_enqueue_packets, UdpEnqueue);

    // Shared events
    packet_event_iter!(iter_shared_send_packets, SharedSend);

    // Drop/throttle events
    packet_event_iter!(iter_skb_drops, SkbDrop);
    packet_event_iter!(iter_cpu_backlog_drops, CpuBacklogDrop);
    packet_event_iter!(iter_mem_pressure, MemPressure);

    // Qdisc events
    packet_event_iter!(iter_qdisc_enqueue, QdiscEnqueue);
    packet_event_iter!(iter_qdisc_dequeue, QdiscDequeue);
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
                        src_addr: bpf_meta.src_addr,
                        src_port: bpf_meta.src_port,
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

    fn poll_events_to_str(events: u32) -> String {
        if events == 0 {
            return "NONE".to_string();
        }

        let mut result = String::with_capacity(32);
        let mut first = true;

        for (mask, name) in [
            (0x001, "IN"),
            (0x002, "PRI"),
            (0x004, "OUT"),
            (0x008, "ERR"),
            (0x010, "HUP"),
            (0x2000, "RDHUP"),
        ] {
            if events & mask != 0 {
                if !first {
                    result.push('|');
                }
                result.push_str(name);
                first = false;
            }
        }

        if result.is_empty() {
            format!("0x{events:x}")
        } else {
            result
        }
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
            // Drop event fields
            drop_reason: event.drop_reason,
            drop_location: event.drop_location,
            qlen: event.qlen,
            qlen_limit: event.qlen_limit,
            // TSQ/memory pressure fields
            sk_wmem_alloc: event.sk_wmem_alloc,
            tsq_limit: event.tsq_limit,
            // Qdisc tracing fields
            txq_state: event.txq_state,
            qdisc_state: event.qdisc_state,
            qdisc_backlog: event.qdisc_backlog,
            skb_addr: event.skb_addr,
            qdisc_latency_us: event.qdisc_latency_us,
        };

        // All packet events go to global packet_events
        let conn_events = self.packet_events.entry(socket_id).or_default();

        // Dispatch based on event type using match for clearer code
        let event_entry = match event.event_type.0 {
            // TCP packet events
            x if x == packet_event_type::PACKET_ENQUEUE.0 => EventEntry::TcpEnqueue(pkt_event),
            x if x == packet_event_type::PACKET_SEND.0 => EventEntry::SharedSend(pkt_event),
            x if x == packet_event_type::PACKET_RCV_ESTABLISHED.0 => {
                EventEntry::TcpRcvEstablished(pkt_event)
            }
            x if x == packet_event_type::PACKET_QUEUE_RCV.0 => EventEntry::TcpQueueRcv(pkt_event),
            x if x == packet_event_type::PACKET_BUFFER_QUEUE.0 => {
                EventEntry::TcpBufferQueue(pkt_event)
            }
            // UDP packet events
            x if x == packet_event_type::PACKET_UDP_SEND.0 => EventEntry::UdpSend(pkt_event),
            x if x == packet_event_type::PACKET_UDP_RCV.0 => EventEntry::UdpRcv(pkt_event),
            x if x == packet_event_type::PACKET_UDP_ENQUEUE.0 => EventEntry::UdpEnqueue(pkt_event),
            // Zero window events
            x if x == packet_event_type::PACKET_ZERO_WINDOW_PROBE.0 => {
                EventEntry::TcpZeroWindowProbe(pkt_event)
            }
            x if x == packet_event_type::PACKET_ZERO_WINDOW_ACK.0 => {
                EventEntry::TcpZeroWindowAck(pkt_event)
            }
            // RTO timeout events
            x if x == packet_event_type::PACKET_RTO_TIMEOUT.0 => {
                EventEntry::TcpRtoTimeout(pkt_event)
            }
            // Drop/throttle events
            x if x == packet_event_type::PACKET_SKB_DROP.0 => EventEntry::SkbDrop(pkt_event),
            x if x == packet_event_type::PACKET_CPU_BACKLOG_DROP.0 => {
                EventEntry::CpuBacklogDrop(pkt_event)
            }
            x if x == packet_event_type::PACKET_MEM_PRESSURE.0 => {
                EventEntry::MemPressure(pkt_event)
            }
            // Qdisc tracing events
            x if x == packet_event_type::PACKET_QDISC_ENQUEUE.0 => {
                EventEntry::QdiscEnqueue(pkt_event)
            }
            x if x == packet_event_type::PACKET_QDISC_DEQUEUE.0 => {
                EventEntry::QdiscDequeue(pkt_event)
            }
            // Unknown event type - skip
            _ => return,
        };

        conn_events.events.push(event_entry);
    }

    pub fn handle_epoll_event(&mut self, event: crate::systing::types::epoll_event_bpf) {
        let socket_id = event.socket_id;
        if socket_id == 0 {
            return;
        }

        let poll_event = PollEvent {
            ts: event.ts,
            socket_id,
            requested_events: event.requested_events,
            returned_events: event.returned_events,
        };

        self.syscall_events
            .entry(event.task.tgidpid)
            .or_insert_with(|| Vec::with_capacity(64))
            .push(EventEntry::PollReady(poll_event));
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

    /// Add basic packet annotations: seq, length, flags
    fn add_basic_annotations(event: &mut TrackEvent, pkt: &PacketEvent) {
        event.add_uint_nonzero("seq", pkt.seq as u64);
        event.add_uint("length", pkt.length as u64);
        if pkt.tcp_flags != 0 {
            event.add_string("flags", Self::format_tcp_flags(pkt.tcp_flags));
        }
    }

    /// Add send buffer annotations: sndbuf_used, sndbuf_limit, fill_pct
    fn add_sndbuf_annotations(event: &mut TrackEvent, pkt: &PacketEvent) {
        if pkt.sndbuf_limit > 0 {
            event.add_uint("sndbuf_used", pkt.sndbuf_used as u64);
            event.add_uint("sndbuf_limit", pkt.sndbuf_limit as u64);
            let fill_pct = (pkt.sndbuf_used as u64 * 100) / pkt.sndbuf_limit as u64;
            event.add_uint("sndbuf_fill_pct", fill_pct);
        }
    }

    /// Add persist timer state annotations (icsk_pending, icsk_timeout, etc.)
    fn add_timer_annotations(event: &mut TrackEvent, pkt: &PacketEvent) {
        if pkt.icsk_pending > 0 {
            event.add_uint("icsk_pending", pkt.icsk_pending as u64);
            event.add_uint("icsk_timeout", pkt.icsk_timeout);
            event.add_uint_nonzero("rto_jiffies", pkt.rto_jiffies as u64);
            event.add_uint_nonzero("backoff", pkt.backoff as u64);
            event.add_uint_nonzero("probe_count", pkt.probe_count as u64);
        }
    }

    /// Add retransmit flag annotation
    fn add_retransmit_annotations(event: &mut TrackEvent, pkt: &PacketEvent) {
        event.add_bool("is_retransmit", pkt.is_retransmit);
    }

    /// Add zero window probe annotations (sender-side)
    fn add_zero_window_probe_annotations(event: &mut TrackEvent, pkt: &PacketEvent) {
        if pkt.is_zero_window_probe {
            event.add_bool("is_zero_window_probe", true);
            event.add_uint("probe_count", pkt.probe_count as u64);
            event.add_uint("snd_wnd", pkt.snd_wnd as u64);
        }
    }

    /// Add zero window ACK annotations (receiver-side)
    fn add_zero_window_ack_annotations(event: &mut TrackEvent, pkt: &PacketEvent) {
        if pkt.is_zero_window_ack {
            event.add_bool("is_zero_window_ack", true);
            event.add_uint("rcv_wnd", pkt.rcv_wnd as u64);
            event.add_uint("rcv_buf_used", pkt.rcv_buf_used as u64);
            event.add_uint("rcv_buf_limit", pkt.rcv_buf_limit as u64);
            if pkt.rcv_buf_limit > 0 {
                let fill_pct = (pkt.rcv_buf_used as u64 * 100) / pkt.rcv_buf_limit as u64;
                event.add_uint("rcv_buf_fill_pct", fill_pct);
            }
            event.add_uint("window_clamp", pkt.window_clamp as u64);
            event.add_uint("rcv_wscale", pkt.rcv_wscale as u64);
        }
    }

    /// Add RTO timeout annotations with jiffies-to-microseconds conversion
    fn add_rto_annotations(event: &mut TrackEvent, pkt: &PacketEvent) {
        if pkt.rto_jiffies > 0 {
            // Convert jiffies to microseconds using cached system HZ
            let rto_us = (pkt.rto_jiffies as u64 * 1_000_000) / system_hz();

            event.add_uint("rto_jiffies", pkt.rto_jiffies as u64);
            event.add_uint("rto_us", rto_us);
            event.add_uint("srtt_us", pkt.srtt_us as u64);
            event.add_uint("rttvar_us", pkt.rttvar_us as u64);
            event.add_uint("retransmit_count", pkt.retransmit_count as u64);
            event.add_uint("backoff", pkt.backoff as u64);
            event.add_uint("rto_ms", rto_us / 1000);
            event.add_uint_nonzero("srtt_ms", (pkt.srtt_us / 1000) as u64);
        }
    }

    /// Add drop event annotations (drop_reason, drop_location)
    fn add_drop_annotations(event: &mut TrackEvent, pkt: &PacketEvent) {
        if pkt.drop_reason > 0 {
            event.add_uint("drop_reason", pkt.drop_reason as u64);
            event.add_string(
                "drop_reason_str",
                drop_reason_str(pkt.drop_reason).to_string(),
            );
            event.add_uint_nonzero("drop_location", pkt.drop_location);
        }
    }

    /// Add queue state annotations (qlen, qlen_limit)
    fn add_queue_annotations(event: &mut TrackEvent, pkt: &PacketEvent) {
        if pkt.qlen > 0 || pkt.qlen_limit > 0 {
            event.add_uint("qlen", pkt.qlen as u64);
            event.add_uint_nonzero("qlen_limit", pkt.qlen_limit as u64);
        }
    }

    /// Add TSQ/memory pressure annotations
    fn add_memory_pressure_annotations(event: &mut TrackEvent, pkt: &PacketEvent) {
        if pkt.sk_wmem_alloc > 0 {
            event.add_uint("sk_wmem_alloc", pkt.sk_wmem_alloc as u64);
            event.add_uint_nonzero("tsq_limit", pkt.tsq_limit as u64);
        }
    }

    /// Add qdisc-specific annotations
    fn add_qdisc_annotations(event: &mut TrackEvent, pkt: &PacketEvent) {
        event.add_uint_nonzero("txq_state", pkt.txq_state as u64);
        event.add_uint_nonzero("qdisc_state", pkt.qdisc_state as u64);
        event.add_uint_nonzero("qdisc_backlog", pkt.qdisc_backlog as u64);
        event.add_uint_nonzero("skb_addr", pkt.skb_addr);
        event.add_uint_nonzero("qdisc_latency_us", pkt.qdisc_latency_us as u64);
    }

    /// Helper to emit packet events for a given event type.
    /// Uses peekable to check emptiness without collecting, then emits events directly.
    fn emit_packet_events<'a>(
        &self,
        packets: &mut Vec<TracePacket>,
        sequence_id: u32,
        track_uuid: u64,
        event_name: &str,
        pkt_iter: impl Iterator<Item = &'a PacketEvent>,
    ) {
        let mut pkt_iter = pkt_iter.peekable();
        if pkt_iter.peek().is_none() {
            return;
        }
        let iid = self.event_name_ids.get(event_name).copied().unwrap_or(0);
        if iid == 0 {
            tracing::warn!("Missing event name IID for: {}", event_name);
            return;
        }
        for pkt in pkt_iter {
            self.emit_single_packet_event(packets, sequence_id, track_uuid, iid, pkt);
        }
    }

    /// Emit a single packet instant event
    fn emit_single_packet_event(
        &self,
        packets: &mut Vec<TracePacket>,
        sequence_id: u32,
        track_uuid: u64,
        name_iid: u64,
        pkt: &PacketEvent,
    ) {
        let mut instant_event = TrackEvent::default();
        instant_event.set_type(Type::TYPE_INSTANT);
        instant_event.set_name_iid(name_iid);
        instant_event.set_track_uuid(track_uuid);

        // Add all annotation groups
        Self::add_basic_annotations(&mut instant_event, pkt);
        Self::add_sndbuf_annotations(&mut instant_event, pkt);
        Self::add_timer_annotations(&mut instant_event, pkt);
        Self::add_retransmit_annotations(&mut instant_event, pkt);
        Self::add_zero_window_probe_annotations(&mut instant_event, pkt);
        Self::add_zero_window_ack_annotations(&mut instant_event, pkt);
        Self::add_rto_annotations(&mut instant_event, pkt);
        Self::add_drop_annotations(&mut instant_event, pkt);
        Self::add_queue_annotations(&mut instant_event, pkt);
        Self::add_memory_pressure_annotations(&mut instant_event, pkt);
        Self::add_qdisc_annotations(&mut instant_event, pkt);

        let mut packet = TracePacket::default();
        packet.set_timestamp(pkt.ts);
        packet.set_track_event(instant_event);
        packet.set_trusted_packet_sequence_id(sequence_id);
        packets.push(packet);
    }

    /// Emit a syscall slice event (Send or Recv) with begin and end packets.
    fn emit_syscall_slice(
        &self,
        packets: &mut Vec<TracePacket>,
        sequence_id: u32,
        track_uuid: u64,
        event: &NetworkEvent,
        is_send: bool,
    ) {
        let protocol = self
            .socket_metadata
            .get(&event.socket_id)
            .map(|m| m.protocol)
            .unwrap_or_else(|| {
                tracing::debug!("Missing socket metadata for socket_id {}", event.socket_id);
                0
            });

        let proto_str = Self::protocol_to_str(protocol);
        let event_name = if is_send {
            format!("{proto_str}_send")
        } else {
            format!("{proto_str}_recv")
        };
        let name_iid = self.event_name_ids.get(&event_name).copied().unwrap_or(0);

        // Build begin event
        let mut begin_event = TrackEvent::default();
        begin_event.set_type(Type::TYPE_SLICE_BEGIN);
        if name_iid > 0 {
            begin_event.set_name_iid(name_iid);
        }
        begin_event.set_track_uuid(track_uuid);

        // Common annotations
        begin_event.add_uint("socket_id", event.socket_id);
        begin_event.add_string("socket", self.socket_track_name(event.socket_id));
        begin_event.add_uint("bytes", event.bytes as u64);

        if is_send {
            // Send-specific annotations
            begin_event.add_uint_nonzero("seq", event.sendmsg_seq as u64);
            if event.sndbuf_limit > 0 {
                begin_event.add_uint("sndbuf_used", event.sndbuf_used as u64);
                begin_event.add_uint("sndbuf_limit", event.sndbuf_limit as u64);
                let fill_pct = (event.sndbuf_used as u64 * 100) / event.sndbuf_limit as u64;
                begin_event.add_uint("sndbuf_fill_pct", fill_pct);
            }
        } else {
            // Recv-specific annotations
            if event.recv_seq_start > 0 || event.recv_seq_end > 0 {
                begin_event.add_uint("recv_seq_start", event.recv_seq_start as u64);
                begin_event.add_uint("recv_seq_end", event.recv_seq_end as u64);
                if event.rcv_nxt_at_entry > 0 {
                    begin_event.add_uint("rcv_nxt", event.rcv_nxt_at_entry as u64);
                    let bytes_available = event.rcv_nxt_at_entry.wrapping_sub(event.recv_seq_start);
                    if bytes_available > 0 && bytes_available < 64 * 1024 * 1024 {
                        begin_event.add_uint("bytes_available", bytes_available as u64);
                    }
                }
            }
        }

        let mut begin_packet = TracePacket::default();
        begin_packet.set_timestamp(event.start_ts);
        begin_packet.set_track_event(begin_event);
        begin_packet.set_trusted_packet_sequence_id(sequence_id);
        packets.push(begin_packet);

        // Build end event
        let mut end_event = TrackEvent::default();
        end_event.set_type(Type::TYPE_SLICE_END);
        end_event.set_track_uuid(track_uuid);

        let mut end_packet = TracePacket::default();
        end_packet.set_timestamp(event.end_ts);
        end_packet.set_track_event(end_event);
        end_packet.set_trusted_packet_sequence_id(sequence_id);
        packets.push(end_packet);
    }

    /// Emit a poll_ready instant event
    fn emit_poll_ready(
        &self,
        packets: &mut Vec<TracePacket>,
        sequence_id: u32,
        track_uuid: u64,
        event: &PollEvent,
    ) {
        let poll_name_iid = *self.event_name_ids.get("poll_ready").unwrap_or(&0);

        let mut instant_event = TrackEvent::default();
        instant_event.set_type(Type::TYPE_INSTANT);
        instant_event.set_name_iid(poll_name_iid);
        instant_event.set_track_uuid(track_uuid);

        instant_event.add_uint("socket_id", event.socket_id);
        instant_event.add_string("socket", self.socket_track_name(event.socket_id));
        instant_event.add_string(
            "requested",
            Self::poll_events_to_str(event.requested_events),
        );
        instant_event.add_string("returned", Self::poll_events_to_str(event.returned_events));

        let mut instant_packet = TracePacket::default();
        instant_packet.set_timestamp(event.ts);
        instant_packet.set_track_event(instant_event);
        instant_packet.set_trusted_packet_sequence_id(sequence_id);
        packets.push(instant_packet);
    }

    /// Prepares all metadata needed for packet generation, including:
    /// - Resolving hostnames for all sockets
    /// - Creating IIDs for protocol operations and packet events
    /// - Building the event names array
    fn prepare_event_metadata(&mut self, id_counter: &Arc<AtomicUsize>) -> Vec<EventName> {
        use crate::systing::types::network_operation;

        // Collect IP addresses first to avoid borrow issues
        // We resolve both src and dest addresses for potential hostname lookups
        let ip_addrs: Vec<_> = self
            .socket_metadata
            .values()
            .flat_map(|m| [m.src_ip_addr(), m.dest_ip_addr()])
            .collect();

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
        self.get_or_create_event_name_iid("poll_ready".to_string(), id_counter);
        // New drop/throttle event types
        self.get_or_create_event_name_iid("packet_drop".to_string(), id_counter);
        self.get_or_create_event_name_iid("cpu_backlog_drop".to_string(), id_counter);
        self.get_or_create_event_name_iid("TCP mem_pressure".to_string(), id_counter);
        // Qdisc tracing event types
        self.get_or_create_event_name_iid("qdisc_enqueue".to_string(), id_counter);
        self.get_or_create_event_name_iid("qdisc_dequeue".to_string(), id_counter);

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

    fn socket_track_name(&self, socket_id: SocketId) -> String {
        if let Some(metadata) = self.socket_metadata.get(&socket_id) {
            let src_ip = metadata.src_ip_addr();
            let dest_ip = metadata.dest_ip_addr();
            let src_host = self
                .hostname_cache
                .get(&src_ip)
                .cloned()
                .unwrap_or_else(|| src_ip.to_string());
            let dest_host = self
                .hostname_cache
                .get(&dest_ip)
                .cloned()
                .unwrap_or_else(|| dest_ip.to_string());
            format!(
                "Socket {}:{}:{}:{}->{}:{}",
                socket_id,
                metadata.protocol_str(),
                src_host,
                metadata.src_port,
                dest_host,
                metadata.dest_port
            )
        } else {
            format!("Socket {socket_id}")
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
                    self.emit_packet_events(
                        &mut packets,
                        sequence_id,
                        socket_track_uuid,
                        "TCP packet_enqueue",
                        events.iter_tcp_enqueue_packets(),
                    );
                    self.emit_packet_events(
                        &mut packets,
                        sequence_id,
                        socket_track_uuid,
                        "TCP packet_send",
                        events.iter_shared_send_packets(),
                    );
                    self.emit_packet_events(
                        &mut packets,
                        sequence_id,
                        socket_track_uuid,
                        "TCP packet_rcv_established",
                        events.iter_tcp_rcv_established_packets(),
                    );
                    self.emit_packet_events(
                        &mut packets,
                        sequence_id,
                        socket_track_uuid,
                        "TCP packet_queue_rcv",
                        events.iter_tcp_queue_rcv_packets(),
                    );
                    self.emit_packet_events(
                        &mut packets,
                        sequence_id,
                        socket_track_uuid,
                        "TCP zero_window_probe",
                        events.iter_zero_window_probes(),
                    );
                    self.emit_packet_events(
                        &mut packets,
                        sequence_id,
                        socket_track_uuid,
                        "TCP zero_window_ack",
                        events.iter_zero_window_acks(),
                    );
                    self.emit_packet_events(
                        &mut packets,
                        sequence_id,
                        socket_track_uuid,
                        "TCP rto_timeout",
                        events.iter_rto_timeouts(),
                    );
                    self.emit_packet_events(
                        &mut packets,
                        sequence_id,
                        socket_track_uuid,
                        "TCP buffer_queue",
                        events.iter_tcp_buffer_queue_packets(),
                    );
                } else {
                    // UDP packet events
                    self.emit_packet_events(
                        &mut packets,
                        sequence_id,
                        socket_track_uuid,
                        "UDP send",
                        events.iter_udp_send_packets(),
                    );
                    self.emit_packet_events(
                        &mut packets,
                        sequence_id,
                        socket_track_uuid,
                        "UDP receive",
                        events.iter_udp_rcv_packets(),
                    );
                    self.emit_packet_events(
                        &mut packets,
                        sequence_id,
                        socket_track_uuid,
                        "UDP packet_send",
                        events.iter_shared_send_packets(),
                    );
                    self.emit_packet_events(
                        &mut packets,
                        sequence_id,
                        socket_track_uuid,
                        "UDP enqueue",
                        events.iter_udp_enqueue_packets(),
                    );
                }

                // Drop/throttle events (apply to both TCP and UDP)
                self.emit_packet_events(
                    &mut packets,
                    sequence_id,
                    socket_track_uuid,
                    "packet_drop",
                    events.iter_skb_drops(),
                );
                self.emit_packet_events(
                    &mut packets,
                    sequence_id,
                    socket_track_uuid,
                    "cpu_backlog_drop",
                    events.iter_cpu_backlog_drops(),
                );
                self.emit_packet_events(
                    &mut packets,
                    sequence_id,
                    socket_track_uuid,
                    "TCP mem_pressure",
                    events.iter_mem_pressure(),
                );
                self.emit_packet_events(
                    &mut packets,
                    sequence_id,
                    socket_track_uuid,
                    "qdisc_enqueue",
                    events.iter_qdisc_enqueue(),
                );
                self.emit_packet_events(
                    &mut packets,
                    sequence_id,
                    socket_track_uuid,
                    "qdisc_dequeue",
                    events.iter_qdisc_dequeue(),
                );
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
                        self.emit_syscall_slice(
                            &mut packets,
                            sequence_id,
                            network_track_uuid,
                            event,
                            true,
                        );
                    }
                    EventEntry::Recv(event) => {
                        self.emit_syscall_slice(
                            &mut packets,
                            sequence_id,
                            network_track_uuid,
                            event,
                            false,
                        );
                    }
                    EventEntry::PollReady(event) => {
                        self.emit_poll_ready(&mut packets, sequence_id, network_track_uuid, event);
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

    /// Helper to get a default test source address (10.0.0.1)
    fn test_src_addr() -> [u8; 16] {
        let mut addr = [0u8; 16];
        addr[0..4].copy_from_slice(&[10, 0, 0, 1]);
        addr
    }

    /// Helper to insert socket metadata for tests (uses default src addr/port)
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
                src_addr: test_src_addr(),
                src_port: 12345,
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
        dest_addr[0..4].copy_from_slice(&[127, 0, 0, 1]);
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
        dest_addr[0..4].copy_from_slice(&[127, 0, 0, 1]);
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
        dest_addr[0..4].copy_from_slice(&[127, 0, 0, 1]);
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
                src_addr: [0; 16], // Use zeroed source for this test
                src_port: 12345,
                dest_addr: addr_bytes,
                dest_port: 443,
            };

            let ip = conn_id.dest_ip_addr();
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
            "Socket track should be identified as UDP: {socket_track_name}"
        );
    }
}
