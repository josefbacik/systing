# Network Event Schema in systing-analyze

This document describes how network events are stored in Parquet files and queried in DuckDB.

## Overview

Network events are stored in dedicated tables (not shared with other recorders):

- **`network_syscall`** - Syscall events (sendmsg/recvmsg) with flattened fields
- **`network_packet`** - Packet-level events with all TCP/UDP fields as columns
- **`network_socket`** - Socket metadata (4-tuple: src/dest IP:port)
- **`network_poll`** - Poll/epoll/select events
- **`network_interface`** - Local network interface metadata

**Key Benefits of This Schema:**
1. **No shared tables** - Network events don't overlap with other recorders
2. **Flattened schema** - All fields as explicit columns (no key/value args)
3. **Simple queries** - Direct column access without pivot/CASE WHEN
4. **True streaming** - Events written immediately during recording

## Tables

### `network_syscall`

Network syscall events (sendmsg/recvmsg) with duration.

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| id | BIGINT | No | Unique event ID |
| ts | BIGINT | No | Start timestamp (nanoseconds) |
| dur | BIGINT | No | Duration (nanoseconds) |
| tid | INTEGER | No | Thread ID |
| pid | INTEGER | No | Process ID |
| event_type | VARCHAR | No | "sendmsg" or "recvmsg" |
| socket_id | BIGINT | No | Socket identifier (FK to network_socket) |
| bytes | BIGINT | No | Bytes transferred |
| seq | BIGINT | Yes | TCP sequence number (send only) |
| sndbuf_used | BIGINT | Yes | Send buffer usage in bytes |
| sndbuf_limit | BIGINT | Yes | Send buffer limit in bytes |
| sndbuf_fill_pct | SMALLINT | Yes | Send buffer fill percentage |
| recv_seq_start | BIGINT | Yes | TCP recv: copied_seq at entry |
| recv_seq_end | BIGINT | Yes | TCP recv: copied_seq at exit |
| rcv_nxt | BIGINT | Yes | TCP recv: next expected sequence |
| bytes_available | BIGINT | Yes | TCP recv: data buffered in kernel |

### `network_packet`

Packet-level events with all TCP/UDP fields as explicit columns.

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| id | BIGINT | No | Unique event ID |
| ts | BIGINT | No | Timestamp (nanoseconds) |
| socket_id | BIGINT | No | Socket identifier |
| event_type | VARCHAR | No | Packet event type (see below) |
| seq | BIGINT | Yes | TCP sequence number |
| length | INTEGER | No | Packet length in bytes |
| tcp_flags | VARCHAR | Yes | TCP flags string ("SYN\|ACK") |
| sndbuf_used | BIGINT | Yes | Send buffer usage |
| sndbuf_limit | BIGINT | Yes | Send buffer limit |
| sndbuf_fill_pct | SMALLINT | Yes | Send buffer fill % |
| is_retransmit | BOOLEAN | No | TCP retransmit flag |
| retransmit_count | SMALLINT | Yes | Consecutive retransmit count |
| rto_ms | INTEGER | Yes | RTO value in milliseconds |
| srtt_ms | INTEGER | Yes | Smoothed RTT in milliseconds |
| rttvar_us | INTEGER | Yes | RTT variance in microseconds |
| backoff | SMALLINT | Yes | Exponential backoff multiplier |
| is_zero_window_probe | BOOLEAN | No | Zero window probe flag |
| is_zero_window_ack | BOOLEAN | No | Zero window ACK flag |
| probe_count | SMALLINT | Yes | Number of ZWP probes sent |
| snd_wnd | INTEGER | Yes | Send window |
| rcv_wnd | INTEGER | Yes | Receive window |
| rcv_buf_used | BIGINT | Yes | Receive buffer used |
| rcv_buf_limit | BIGINT | Yes | Receive buffer limit |
| window_clamp | INTEGER | Yes | Max window |
| rcv_wscale | SMALLINT | Yes | Receive window scale |
| icsk_pending | SMALLINT | Yes | Timer type pending |
| icsk_timeout | BIGINT | Yes | Timer timeout (jiffies) |
| drop_reason | INTEGER | Yes | SKB_DROP_REASON_* code |
| drop_reason_str | VARCHAR | Yes | Human-readable drop reason |
| drop_location | BIGINT | Yes | Kernel address of drop |
| qlen | INTEGER | Yes | Queue length |
| qlen_limit | INTEGER | Yes | Queue limit |
| sk_wmem_alloc | BIGINT | Yes | TSQ allocated memory |
| tsq_limit | BIGINT | Yes | TSQ limit |
| txq_state | INTEGER | Yes | TX queue state flags |
| qdisc_state | INTEGER | Yes | Qdisc state flags |
| qdisc_backlog | BIGINT | Yes | Qdisc bytes queued |
| skb_addr | BIGINT | Yes | SKB address for correlation |
| qdisc_latency_us | INTEGER | Yes | Qdisc residence time |

**Packet Event Types:**
- TCP: `packet_enqueue`, `packet_send`, `packet_rcv_established`, `packet_queue_rcv`, `buffer_queue`, `zero_window_probe`, `zero_window_ack`, `rto_timeout`
- UDP: `UDP send`, `UDP receive`, `UDP enqueue`
- Drop: `packet_drop`, `cpu_backlog_drop`, `mem_pressure`, `tsq_throttle`
- Qdisc: `qdisc_enqueue`, `qdisc_dequeue`, `tx_queue_stop`, `tx_queue_wake`

### `network_socket`

Socket metadata with the connection 4-tuple.

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| socket_id | BIGINT | No | Unique socket ID (PK) |
| protocol | VARCHAR | No | "TCP" or "UDP" |
| address_family | VARCHAR | No | "IPv4" or "IPv6" |
| src_ip | VARCHAR | No | Source IP address |
| src_port | INTEGER | No | Source port |
| dest_ip | VARCHAR | No | Destination IP address |
| dest_port | INTEGER | No | Destination port |
| first_seen_ts | BIGINT | Yes | First event timestamp |
| last_seen_ts | BIGINT | Yes | Last event timestamp |

### `network_poll`

Poll/epoll/select events.

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| id | BIGINT | No | Unique event ID |
| ts | BIGINT | No | Timestamp (nanoseconds) |
| tid | INTEGER | No | Thread ID |
| pid | INTEGER | No | Process ID |
| socket_id | BIGINT | No | Socket identifier |
| requested_events | VARCHAR | No | Poll events requested ("IN\|OUT") |
| returned_events | VARCHAR | No | Poll events returned ("IN") |

### `network_interface`

Local network interface metadata for cross-trace correlation.

| Column | Type | Description |
|--------|------|-------------|
| trace_id | VARCHAR | Trace identifier (added during DuckDB import) |
| namespace | VARCHAR | Network namespace name |
| interface_name | VARCHAR | Interface name (e.g., "eth0", "lo") |
| ip_address | VARCHAR | IP address assigned to interface |
| address_type | VARCHAR | "ipv4" or "ipv6" |

## Common Queries

### 1. Bytes Sent/Received Per Socket

```sql
SELECT sock.dest_ip, sock.dest_port, sock.protocol,
       SUM(CASE WHEN ns.event_type = 'sendmsg' THEN ns.bytes ELSE 0 END) as bytes_sent,
       SUM(CASE WHEN ns.event_type = 'recvmsg' THEN ns.bytes ELSE 0 END) as bytes_recv
FROM network_syscall ns
JOIN network_socket sock ON ns.socket_id = sock.socket_id
GROUP BY sock.dest_ip, sock.dest_port, sock.protocol
ORDER BY bytes_sent + bytes_recv DESC
LIMIT 20;
```

### 2. Network Traffic by Process

```sql
SELECT p.name as process, p.pid,
       COUNT(*) as syscalls,
       SUM(ns.bytes) / 1048576.0 as total_mb
FROM network_syscall ns
JOIN thread t ON ns.tid = t.tid
JOIN process p ON ns.pid = p.pid
GROUP BY p.name, p.pid
ORDER BY total_mb DESC;
```

### 3. Find TCP Retransmissions

```sql
SELECT sock.dest_ip, sock.dest_port,
       COUNT(*) as retransmit_count,
       SUM(np.length) as retransmit_bytes
FROM network_packet np
JOIN network_socket sock ON np.socket_id = sock.socket_id
WHERE np.is_retransmit = true
GROUP BY sock.dest_ip, sock.dest_port
ORDER BY retransmit_count DESC;
```

### 4. Retransmit Timeline with Details

```sql
SELECT np.ts / 1e9 as time_sec,
       sock.dest_ip, sock.dest_port,
       np.seq, np.length, np.rto_ms, np.retransmit_count
FROM network_packet np
JOIN network_socket sock ON np.socket_id = sock.socket_id
WHERE np.is_retransmit = true
ORDER BY np.ts
LIMIT 100;
```

### 5. Find Zero Window Probes

```sql
SELECT sock.dest_ip, sock.dest_port,
       COUNT(*) as probe_count,
       MIN(np.ts) / 1e9 as first_probe_sec,
       MAX(np.ts) / 1e9 as last_probe_sec
FROM network_packet np
JOIN network_socket sock ON np.socket_id = sock.socket_id
WHERE np.is_zero_window_probe = true
GROUP BY sock.dest_ip, sock.dest_port
ORDER BY probe_count DESC;
```

### 6. Analyze Send Buffer Pressure

```sql
SELECT sock.dest_ip, sock.dest_port,
       AVG(ns.sndbuf_fill_pct) as avg_fill_pct,
       MAX(ns.sndbuf_fill_pct) as max_fill_pct,
       COUNT(*) as events
FROM network_syscall ns
JOIN network_socket sock ON ns.socket_id = sock.socket_id
WHERE ns.event_type = 'sendmsg' AND ns.sndbuf_fill_pct IS NOT NULL
GROUP BY sock.dest_ip, sock.dest_port
HAVING avg_fill_pct > 50
ORDER BY avg_fill_pct DESC;
```

### 7. Find Packet Drops by Reason

```sql
SELECT np.drop_reason_str,
       COUNT(*) as drop_count,
       SUM(np.length) as bytes_dropped
FROM network_packet np
WHERE np.drop_reason IS NOT NULL
GROUP BY np.drop_reason_str
ORDER BY drop_count DESC;
```

### 8. Packet Drop Timeline

```sql
SELECT np.ts / 1e9 as time_sec,
       sock.dest_ip, sock.dest_port,
       np.drop_reason_str, np.length
FROM network_packet np
JOIN network_socket sock ON np.socket_id = sock.socket_id
WHERE np.drop_reason IS NOT NULL
ORDER BY np.ts;
```

### 9. RTO Timeout Analysis

```sql
SELECT sock.dest_ip, sock.dest_port,
       COUNT(*) as rto_count,
       AVG(np.rto_ms) as avg_rto_ms,
       MAX(np.retransmit_count) as max_retransmits
FROM network_packet np
JOIN network_socket sock ON np.socket_id = sock.socket_id
WHERE np.event_type = 'rto_timeout'
GROUP BY sock.dest_ip, sock.dest_port
ORDER BY rto_count DESC;
```

### 10. Find Connections by Destination Port

```sql
SELECT src_ip, src_port, dest_ip, dest_port
FROM network_socket
WHERE protocol = 'TCP' AND dest_port = 443
ORDER BY socket_id;
```

### 11. Connection Summary by Protocol

```sql
SELECT protocol, address_family, COUNT(*) as connection_count
FROM network_socket
GROUP BY protocol, address_family
ORDER BY connection_count DESC;
```

### 12. Poll Events by Socket

```sql
SELECT sock.dest_ip, sock.dest_port,
       COUNT(*) as poll_count,
       COUNT(DISTINCT np.tid) as threads_polling
FROM network_poll np
JOIN network_socket sock ON np.socket_id = sock.socket_id
GROUP BY sock.dest_ip, sock.dest_port
ORDER BY poll_count DESC;
```

### 13. TCP Recv Sequence Tracking

```sql
SELECT ns.ts / 1e9 as time_sec,
       ns.dur / 1e6 as duration_ms,
       sock.dest_ip, sock.dest_port,
       ns.bytes as bytes_read,
       ns.recv_seq_start, ns.recv_seq_end,
       ns.rcv_nxt, ns.bytes_available
FROM network_syscall ns
JOIN network_socket sock ON ns.socket_id = sock.socket_id
WHERE ns.event_type = 'recvmsg'
ORDER BY ns.ts;
```

### 14. Qdisc Latency Analysis

```sql
SELECT sock.dest_ip, sock.dest_port,
       AVG(np.qdisc_latency_us) as avg_latency_us,
       MAX(np.qdisc_latency_us) as max_latency_us,
       COUNT(*) as events
FROM network_packet np
JOIN network_socket sock ON np.socket_id = sock.socket_id
WHERE np.event_type = 'qdisc_dequeue' AND np.qdisc_latency_us IS NOT NULL
GROUP BY sock.dest_ip, sock.dest_port
ORDER BY avg_latency_us DESC;
```

### 15. Cross-Container Communication (Using network_interface)

```sql
SELECT
    ni.namespace as source_namespace,
    ni.ip_address as source_ip,
    sock.dest_ip, sock.dest_port
FROM network_interface ni
JOIN network_socket sock ON ni.ip_address = sock.src_ip
WHERE ni.namespace LIKE 'container:%';
```

## Notes

### Send Buffer Metrics
- `sndbuf_used`: Bytes currently queued in send buffer (sk_wmem_queued)
- `sndbuf_limit`: Maximum send buffer size (sk_sndbuf)
- `sndbuf_fill_pct`: Percentage of buffer used (can exceed 100% temporarily)

High `sndbuf_fill_pct` values indicate potential backpressure.

### Receive Buffer Metrics (recvmsg only)
- `recv_seq_start`: Application's read position at recvmsg() entry
- `recv_seq_end`: Application's read position after recvmsg()
- `rcv_nxt`: Kernel's next expected sequence at entry
- `bytes_available`: Data buffered in kernel (rcv_nxt - recv_seq_start)

High `bytes_available` values indicate the application is reading slower than data arrives.

### TCP Flags Format
TCP flags are stored as pipe-separated strings: `SYN|ACK`, `FIN|ACK`, `PSH|ACK`, etc.

### Socket ID
The socket_id is a unique identifier assigned during tracing. It's consistent within a single trace but not across traces.
