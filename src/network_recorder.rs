use std::collections::{HashMap, HashSet};
#[cfg(test)]
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::Result;

use crate::record::RecordCollector;
use crate::ringbuf::RingBuffer;
use crate::systing_core::types::network_event;
use crate::systing_core::SystingRecordEvent;
use crate::trace::{
    NetworkDnsRecord, NetworkPacketRecord, NetworkPollRecord, NetworkSocketRecord,
    NetworkSyscallRecord,
};
use indicatif::{ProgressBar, ProgressStyle};

/// Unique socket identifier assigned by BPF during tracing
pub type SocketId = u64;

use std::sync::OnceLock;

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
    use crate::systing_core::types::network_address_family;
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

#[cfg(test)]
fn protocol_str(protocol: u32) -> &'static str {
    use crate::systing_core::types::network_protocol;
    if protocol == network_protocol::NETWORK_TCP.0 {
        "TCP"
    } else if protocol == network_protocol::NETWORK_UDP.0 {
        "UDP"
    } else {
        "UNKNOWN"
    }
}

/// Convert TCP state code to human-readable string.
/// Based on enum tcp_state from include/uapi/linux/tcp.h.
pub(crate) fn tcp_state_name(state: u8) -> &'static str {
    match state {
        1 => "ESTABLISHED",
        2 => "SYN_SENT",
        3 => "SYN_RECV",
        4 => "FIN_WAIT1",
        5 => "FIN_WAIT2",
        6 => "TIME_WAIT",
        7 => "CLOSE",
        8 => "CLOSE_WAIT",
        9 => "LAST_ACK",
        10 => "LISTEN",
        11 => "CLOSING",
        12 => "NEW_SYN_RECV",
        _ => "UNKNOWN",
    }
}

/// Convert SKB_DROP_REASON_* code to human-readable string
/// Based on enum skb_drop_reason from include/net/dropreason-core.h
pub(crate) fn drop_reason_str(reason: u32) -> &'static str {
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

pub(crate) fn format_tcp_flags(flags: u8) -> String {
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
}

pub struct NetworkRecorder {
    pub ringbuf: RingBuffer<network_event>,

    /// Socket metadata cache (populated from BPF map after tracing)
    socket_metadata: HashMap<SocketId, SocketMetadata>,

    hostname_cache: HashMap<IpAddr, String>,

    /// Whether to resolve IP addresses to hostnames via DNS
    resolve_addresses: bool,

    /// Minimum timestamp seen across all events (updated incrementally)
    min_ts: Option<u64>,

    // Streaming support fields
    /// Track which sockets have had their NetworkSocketRecord emitted
    seen_sockets: HashSet<SocketId>,
    /// Collector for streaming records during recording
    streaming_collector: Option<Box<dyn RecordCollector + Send>>,
    /// Next record ID counters for streaming
    next_syscall_id: i64,
    next_packet_id: i64,
    next_poll_id: i64,
}

impl Default for NetworkRecorder {
    fn default() -> Self {
        Self {
            ringbuf: RingBuffer::default(),
            socket_metadata: HashMap::new(),
            hostname_cache: HashMap::new(),
            resolve_addresses: true,
            min_ts: None,
            seen_sockets: HashSet::new(),
            streaming_collector: None,
            next_syscall_id: 1,
            next_packet_id: 1,
            next_poll_id: 1,
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

    /// Enable streaming mode for buffering events during recording.
    ///
    /// When streaming is enabled, events are buffered in memory and written
    /// to the collector at finish() time. This is similar to how the stack
    /// recorder works - it buffers during recording and writes at the end.
    /// Set the streaming collector for real-time event emission.
    pub fn set_streaming_collector(&mut self, collector: Box<dyn RecordCollector + Send>) {
        self.streaming_collector = Some(collector);
    }

    /// Helper to emit NetworkSocketRecord if not yet seen for this socket.
    /// Returns true if a new socket record was emitted.
    #[allow(clippy::too_many_arguments)]
    fn maybe_emit_socket_record(
        &mut self,
        socket_id: SocketId,
        protocol: u32,
        af: u32,
        src_addr: &[u8; 16],
        src_port: u16,
        dest_addr: &[u8; 16],
        dest_port: u16,
        ts: i64,
    ) -> Result<bool> {
        use crate::systing_core::types::{network_address_family, network_protocol};

        // Check if we've already emitted a record for this socket
        if self.seen_sockets.contains(&socket_id) {
            return Ok(false);
        }

        // Mark as seen
        self.seen_sockets.insert(socket_id);

        // Get collector (must be present in streaming mode)
        let collector = self.streaming_collector.as_mut().ok_or_else(|| {
            anyhow::anyhow!("Streaming collector not set in maybe_emit_socket_record")
        })?;

        // Convert protocol
        let protocol_str = if protocol == network_protocol::NETWORK_TCP.0 {
            "TCP"
        } else if protocol == network_protocol::NETWORK_UDP.0 {
            "UDP"
        } else {
            "UNKNOWN"
        }
        .to_string();

        // Convert address family
        let af_str = if af == network_address_family::NETWORK_AF_INET.0 {
            "IPv4"
        } else if af == network_address_family::NETWORK_AF_INET6.0 {
            "IPv6"
        } else {
            "UNKNOWN"
        }
        .to_string();

        // Convert addresses to strings
        let src_ip = parse_ip_addr(af, src_addr).to_string();
        let dest_ip = parse_ip_addr(af, dest_addr).to_string();

        // Emit NetworkSocketRecord
        collector.add_network_socket(NetworkSocketRecord {
            socket_id: socket_id as i64,
            protocol: protocol_str,
            address_family: af_str,
            src_ip,
            src_port: src_port as i32,
            dest_ip,
            dest_port: dest_port as i32,
            first_seen_ts: Some(ts),
            last_seen_ts: Some(ts),
        })?;

        Ok(true)
    }

    /// Helper function to convert kernel jiffies to microseconds for streaming.
    fn jiffies_to_us(jiffies: u64) -> i64 {
        ((jiffies as u128 * 1_000_000) / system_hz() as u128) as i64
    }

    /// Helper function to convert kernel jiffies to milliseconds for streaming.
    fn jiffies_to_ms(jiffies: u32) -> i32 {
        // u32::MAX * 1000 fits in u64, so no widening needed here
        ((jiffies as u64 * 1000) / system_hz()) as i32
    }

    /// Stream a syscall event (send/recv) - emit NetworkSyscallRecord immediately.
    /// Also emits NetworkSocketRecord if this is the first event for this socket.
    fn stream_syscall_event(
        &mut self,
        event: &crate::systing_core::types::network_event,
        is_send: bool,
    ) -> Result<()> {
        let socket_id = event.socket_id;
        let ts = event.start_ts as i64;
        let tid = (event.task.tgidpid & 0xFFFFFFFF) as i32;
        let pid = (event.task.tgidpid >> 32) as i32;

        // Emit NetworkSocketRecord if first time seeing this socket
        self.maybe_emit_socket_record(
            socket_id,
            event.protocol.0,
            event.af.0,
            &event.src_addr,
            event.src_port,
            &event.dest_addr,
            event.dest_port,
            ts,
        )?;

        // Get collector
        let collector = self.streaming_collector.as_mut().ok_or_else(|| {
            anyhow::anyhow!("Streaming collector not set in stream_syscall_event")
        })?;

        // Get ID and increment
        let id = self.next_syscall_id;
        self.next_syscall_id += 1;

        // Build syscall record
        let event_type = if is_send { "sendmsg" } else { "recvmsg" }.to_string();
        let dur = (event.end_ts as i64)
            .saturating_sub(event.start_ts as i64)
            .max(0);

        let mut record = NetworkSyscallRecord {
            id,
            ts,
            dur,
            tid,
            pid,
            event_type,
            socket_id: socket_id as i64,
            bytes: event.bytes as i64,
            seq: None,
            sndbuf_used: None,
            sndbuf_limit: None,
            sndbuf_fill_pct: None,
            recv_seq_start: None,
            recv_seq_end: None,
            rcv_nxt: None,
            bytes_available: None,
        };

        if is_send {
            // Send-specific fields
            if event.sendmsg_seq > 0 {
                record.seq = Some(event.sendmsg_seq as i64);
            }
            if event.sndbuf_limit > 0 {
                record.sndbuf_used = Some(event.sndbuf_used as i64);
                record.sndbuf_limit = Some(event.sndbuf_limit as i64);
                let fill_pct =
                    ((event.sndbuf_used as u64 * 100) / event.sndbuf_limit as u64) as i16;
                record.sndbuf_fill_pct = Some(fill_pct);
            }
        } else {
            // Recv-specific fields
            if event.recv_seq_start > 0 || event.recv_seq_end > 0 {
                record.recv_seq_start = Some(event.recv_seq_start as i64);
                record.recv_seq_end = Some(event.recv_seq_end as i64);
                if event.rcv_nxt_at_entry > 0 {
                    record.rcv_nxt = Some(event.rcv_nxt_at_entry as i64);
                    let bytes_available = event.rcv_nxt_at_entry.wrapping_sub(event.recv_seq_start);
                    if bytes_available > 0 && bytes_available < 64 * 1024 * 1024 {
                        record.bytes_available = Some(bytes_available as i64);
                    }
                }
            }
        }

        // Emit the record
        collector.add_network_syscall(record)?;
        Ok(())
    }

    /// Stream a packet event - emit NetworkPacketRecord immediately.
    /// Also emits NetworkSocketRecord if this is the first event for this socket.
    fn stream_packet_event(
        &mut self,
        event: &crate::systing_core::types::packet_event,
        event_name: &'static str,
    ) -> Result<()> {
        let socket_id = event.socket_id;
        let ts = event.ts as i64;

        // Emit NetworkSocketRecord if first time seeing this socket
        self.maybe_emit_socket_record(
            socket_id,
            event.protocol.0,
            event.af.0,
            &event.src_addr,
            event.src_port,
            &event.dest_addr,
            event.dest_port,
            ts,
        )?;

        // Get collector
        let collector = self
            .streaming_collector
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Streaming collector not set in stream_packet_event"))?;

        // Get ID and increment
        let id = self.next_packet_id;
        self.next_packet_id += 1;

        // Build packet record
        let mut record = NetworkPacketRecord {
            id,
            ts,
            socket_id: socket_id as i64,
            event_type: event_name,
            seq: if event.seq > 0 {
                Some(event.seq as i64)
            } else {
                None
            },
            length: event.length as i32,
            tcp_flags: if event.tcp_flags != 0 {
                Some(event.tcp_flags)
            } else {
                None
            },
            sndbuf_used: None,
            sndbuf_limit: None,
            sndbuf_fill_pct: None,
            is_retransmit: event.is_retransmit != 0,
            retransmit_count: if event.retransmit_count > 0 {
                Some(event.retransmit_count as i16)
            } else {
                None
            },
            rto_ms: if event.rto_jiffies > 0 {
                Some(Self::jiffies_to_ms(event.rto_jiffies))
            } else {
                None
            },
            srtt_ms: if event.srtt_us > 0 {
                Some((event.srtt_us / 1000) as i32)
            } else {
                None
            },
            rttvar_us: if event.rttvar_us > 0 {
                Some(event.rttvar_us as i32)
            } else {
                None
            },
            backoff: if event.backoff > 0 {
                Some(event.backoff as i16)
            } else {
                None
            },
            is_zero_window_probe: event.is_zero_window_probe != 0,
            probe_count: if event.probe_count > 0 {
                Some(event.probe_count as i16)
            } else {
                None
            },
            snd_wnd: if event.snd_wnd > 0 || event.is_zero_window_probe != 0 {
                Some(event.snd_wnd as i32)
            } else {
                None
            },
            is_zero_window_ack: event.is_zero_window_ack != 0,
            rcv_wnd: if event.rcv_wnd > 0 || event.is_zero_window_ack != 0 {
                Some(event.rcv_wnd as i32)
            } else {
                None
            },
            rcv_buf_used: if event.rcv_buf_used > 0 {
                Some(event.rcv_buf_used as i64)
            } else {
                None
            },
            rcv_buf_limit: if event.rcv_buf_limit > 0 {
                Some(event.rcv_buf_limit as i64)
            } else {
                None
            },
            window_clamp: if event.window_clamp > 0 {
                Some(event.window_clamp as i32)
            } else {
                None
            },
            rcv_wscale: if event.rcv_wscale > 0 {
                Some(event.rcv_wscale as i16)
            } else {
                None
            },
            // Timer fields
            icsk_pending: if event.icsk_pending > 0 {
                Some(event.icsk_pending as i16)
            } else {
                None
            },
            icsk_timeout: if event.icsk_timeout > 0 {
                Some(Self::jiffies_to_us(event.icsk_timeout))
            } else {
                None
            },
            // Drop fields
            drop_reason: if event.drop_reason > 0 {
                Some(event.drop_reason as i32)
            } else {
                None
            },
            drop_location: if event.drop_location > 0 {
                Some(event.drop_location as i64)
            } else {
                None
            },
            qlen: if event.qlen > 0 {
                Some(event.qlen as i32)
            } else {
                None
            },
            qlen_limit: if event.qlen_limit > 0 {
                Some(event.qlen_limit as i32)
            } else {
                None
            },
            sk_wmem_alloc: if event.sk_wmem_alloc > 0 {
                Some(event.sk_wmem_alloc as i64)
            } else {
                None
            },
            tsq_limit: if event.tsq_limit > 0 {
                Some(event.tsq_limit as i64)
            } else {
                None
            },
            txq_state: if event.txq_state > 0 {
                Some(event.txq_state as i32)
            } else {
                None
            },
            qdisc_state: if event.qdisc_state > 0 {
                Some(event.qdisc_state as i32)
            } else {
                None
            },
            qdisc_backlog: if event.qdisc_backlog > 0 {
                Some(event.qdisc_backlog as i64)
            } else {
                None
            },
            qdisc_latency_us: if event.qdisc_latency_us > 0 {
                Some(event.qdisc_latency_us as i32)
            } else {
                None
            },
            skb_addr: if event.skb_addr > 0 {
                Some(event.skb_addr as i64)
            } else {
                None
            },
            // TCP state change fields
            old_state: if event.old_state > 0 {
                Some(event.old_state as i16)
            } else {
                None
            },
            new_state: if event.new_state > 0 {
                Some(event.new_state as i16)
            } else {
                None
            },
        };

        // Add send buffer fields
        if event.sndbuf_limit > 0 {
            record.sndbuf_used = Some(event.sndbuf_used as i64);
            record.sndbuf_limit = Some(event.sndbuf_limit as i64);
            let fill_pct = ((event.sndbuf_used as u64 * 100) / event.sndbuf_limit as u64) as i16;
            record.sndbuf_fill_pct = Some(fill_pct);
        }

        // Emit the record
        collector.add_network_packet(record)?;
        Ok(())
    }

    /// Stream a poll event - emit NetworkPollRecord immediately.
    fn stream_poll_event(
        &mut self,
        event: &crate::systing_core::types::epoll_event_bpf,
    ) -> Result<()> {
        let socket_id = event.socket_id;
        let ts = event.ts as i64;
        let tid = (event.task.tgidpid & 0xFFFFFFFF) as i32;
        let pid = (event.task.tgidpid >> 32) as i32;

        // Note: Poll events don't have socket metadata (src/dest), so we can't emit NetworkSocketRecord here

        // Get collector
        let collector = self
            .streaming_collector
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Streaming collector not set in stream_poll_event"))?;

        // Get ID and increment
        let id = self.next_poll_id;
        self.next_poll_id += 1;

        // Build poll record
        let record = NetworkPollRecord {
            id,
            ts,
            tid,
            pid,
            socket_id: socket_id as i64,
            requested_events: Self::poll_events_to_str(event.requested_events),
            returned_events: Self::poll_events_to_str(event.returned_events),
        };

        // Emit the record
        collector.add_network_poll(record)?;
        Ok(())
    }

    /// Resolve hostnames for all known IPs and emit DNS records to the collector.
    ///
    /// Iterates all unique IPs from `socket_metadata`, resolves each via DNS,
    /// and emits `NetworkDnsRecord` entries for successfully resolved addresses.
    /// Shows a progress bar during resolution.
    fn emit_dns_records(&mut self, collector: &mut dyn RecordCollector) -> Result<()> {
        if !self.resolve_addresses {
            return Ok(());
        }

        // Collect unique IPs from socket metadata
        let ip_addrs: HashSet<_> = self
            .socket_metadata
            .values()
            .flat_map(|m| [m.src_ip_addr(), m.dest_ip_addr()])
            .collect();

        if ip_addrs.is_empty() {
            return Ok(());
        }

        // Create progress bar
        let pb = ProgressBar::new(ip_addrs.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} DNS lookups ({per_sec}, {eta})"
                )
                .expect("valid progress bar template")
                .progress_chars("##-"),
        );

        // Resolve all IPs (populates hostname_cache)
        for ip_addr in &ip_addrs {
            self.resolve_hostname(*ip_addr);
            pb.inc(1);
        }

        pb.finish_with_message("DNS resolution complete");

        // Emit DNS records for successfully resolved addresses
        for (ip, hostname) in &self.hostname_cache {
            let ip_str = ip.to_canonical().to_string();
            if *hostname != ip_str {
                collector.add_network_dns(NetworkDnsRecord {
                    ip_address: ip_str,
                    hostname: hostname.clone(),
                })?;
            }
        }

        Ok(())
    }

    /// Finish streaming and flush the collector.
    ///
    /// In the new streaming architecture, records are emitted immediately during recording.
    /// This method also resolves DNS for all seen addresses and emits DNS records.
    ///
    /// Returns the collector so the caller can chain or finish it.
    pub fn finish(&mut self) -> Result<Option<Box<dyn RecordCollector + Send>>> {
        // Take ownership of the streaming collector if present
        if let Some(mut collector) = self.streaming_collector.take() {
            // Resolve hostnames and emit DNS records before flushing
            self.emit_dns_records(collector.as_mut())?;
            // Flush the collector
            collector.flush()?;
            Ok(Some(collector))
        } else {
            // No streaming collector - return None
            Ok(None)
        }
    }

    /// Load socket metadata from BPF map after tracing completes.
    /// This populates the socket_metadata cache with socket ID -> address info mapping.
    pub fn load_socket_metadata<M: libbpf_rs::MapCore>(&mut self, map: &M) {
        use crate::systing_core::types::socket_metadata;

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

    pub fn handle_packet_event(&mut self, event: crate::systing_core::types::packet_event) {
        debug_assert!(
            self.streaming_collector.is_some(),
            "streaming_collector must be set before handling events"
        );

        use crate::systing_core::types::packet_event_type;

        // Skip events without socket_id (shouldn't happen in normal operation)
        if event.socket_id == 0 {
            return;
        }

        self.track_min_ts(event.ts);

        let event_name = match event.event_type.0 {
            // TCP packet events
            x if x == packet_event_type::PACKET_ENQUEUE.0 => "TCP packet_enqueue",
            x if x == packet_event_type::PACKET_SEND.0 => "TCP packet_send",
            x if x == packet_event_type::PACKET_RCV_ESTABLISHED.0 => "TCP packet_rcv_established",
            x if x == packet_event_type::PACKET_QUEUE_RCV.0 => "TCP packet_queue_rcv",
            x if x == packet_event_type::PACKET_BUFFER_QUEUE.0 => "TCP buffer_queue",
            // UDP packet events
            x if x == packet_event_type::PACKET_UDP_SEND.0 => "UDP send",
            x if x == packet_event_type::PACKET_UDP_RCV.0 => "UDP receive",
            x if x == packet_event_type::PACKET_UDP_ENQUEUE.0 => "UDP enqueue",
            // Zero window events
            x if x == packet_event_type::PACKET_ZERO_WINDOW_PROBE.0 => "TCP zero_window_probe",
            x if x == packet_event_type::PACKET_ZERO_WINDOW_ACK.0 => "TCP zero_window_ack",
            // RTO timeout events
            x if x == packet_event_type::PACKET_RTO_TIMEOUT.0 => "TCP rto_timeout",
            // Drop/throttle events
            x if x == packet_event_type::PACKET_SKB_DROP.0 => "packet drop",
            x if x == packet_event_type::PACKET_CPU_BACKLOG_DROP.0 => "cpu backlog drop",
            x if x == packet_event_type::PACKET_MEM_PRESSURE.0 => "memory pressure",
            // Qdisc tracing events
            x if x == packet_event_type::PACKET_QDISC_ENQUEUE.0 => "qdisc_enqueue",
            x if x == packet_event_type::PACKET_QDISC_DEQUEUE.0 => "qdisc_dequeue",
            // TCP state change events
            x if x == packet_event_type::PACKET_TCP_STATE_CHANGE.0 => "TCP state_change",
            // Unknown event type - skip
            _ => return,
        };

        if let Err(e) = self.stream_packet_event(&event, event_name) {
            eprintln!("Warning: Failed to stream network packet event: {e}");
        }
    }

    pub fn handle_epoll_event(&mut self, event: crate::systing_core::types::epoll_event_bpf) {
        debug_assert!(
            self.streaming_collector.is_some(),
            "streaming_collector must be set before handling events"
        );

        if event.socket_id == 0 {
            return;
        }

        self.track_min_ts(event.ts);

        if let Err(e) = self.stream_poll_event(&event) {
            eprintln!("Warning: Failed to stream network poll event: {e}");
        }
    }

    fn resolve_hostname(&mut self, addr: IpAddr) -> &str {
        let resolve = self.resolve_addresses;
        self.hostname_cache.entry(addr).or_insert_with(|| {
            if !resolve {
                return addr.to_canonical().to_string();
            }

            let lookup_addr = addr.to_canonical();

            match dns_lookup::lookup_addr(&lookup_addr) {
                Ok(name) => {
                    tracing::debug!("DNS lookup succeeded for {}: {}", lookup_addr, name);
                    name
                }
                Err(err) => {
                    tracing::debug!("DNS lookup failed for {}: {}", lookup_addr, err);
                    lookup_addr.to_string()
                }
            }
        })
    }

    /// Returns the minimum timestamp from all network events, or None if no events recorded.
    pub fn min_timestamp(&self) -> Option<u64> {
        self.min_ts
    }

    fn track_min_ts(&mut self, ts: u64) {
        self.min_ts = Some(self.min_ts.map_or(ts, |prev| prev.min(ts)));
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
        debug_assert!(
            self.streaming_collector.is_some(),
            "streaming_collector must be set before handling events"
        );

        use crate::systing_core::types::network_operation;

        // Skip events without socket_id (shouldn't happen in normal operation)
        if event.socket_id == 0 {
            return;
        }

        self.track_min_ts(event.start_ts);

        let is_send = event.operation.0 == network_operation::NETWORK_SEND.0;
        let is_recv = event.operation.0 == network_operation::NETWORK_RECV.0;

        if is_send || is_recv {
            if let Err(e) = self.stream_syscall_event(&event, is_send) {
                eprintln!("Warning: Failed to stream network syscall event: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::systing_core::types::network_protocol;

    #[test]
    fn test_network_recorder_ipv6_address_formatting() {
        use crate::systing_core::types::network_address_family;

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
    fn test_tcp_state_name_values() {
        assert_eq!(tcp_state_name(0), "UNKNOWN");
        assert_eq!(tcp_state_name(1), "ESTABLISHED");
        assert_eq!(tcp_state_name(2), "SYN_SENT");
        assert_eq!(tcp_state_name(3), "SYN_RECV");
        assert_eq!(tcp_state_name(4), "FIN_WAIT1");
        assert_eq!(tcp_state_name(5), "FIN_WAIT2");
        assert_eq!(tcp_state_name(6), "TIME_WAIT");
        assert_eq!(tcp_state_name(7), "CLOSE");
        assert_eq!(tcp_state_name(8), "CLOSE_WAIT");
        assert_eq!(tcp_state_name(9), "LAST_ACK");
        assert_eq!(tcp_state_name(10), "LISTEN");
        assert_eq!(tcp_state_name(11), "CLOSING");
        assert_eq!(tcp_state_name(12), "NEW_SYN_RECV");
        assert_eq!(tcp_state_name(13), "UNKNOWN");
        assert_eq!(tcp_state_name(255), "UNKNOWN");
    }
}
