# Network Event Schema in systing-analyze

This document describes how network events are stored in DuckDB after conversion from Perfetto traces.

## Overview

Network events are tracked through eight related tables:
- **`track`** - Track metadata (per-thread "Network" track for syscalls, per-socket for packets)
- **`slice`** - Network syscall events (tcp_send, tcp_recv, udp_send) - range-based with duration
- **`args`** - Debug annotations for slice events (socket_id, socket, bytes, buffer info)
- **`instant`** - Packet-level events (packet_enqueue, packet_send, etc.) - point-in-time events
- **`instant_args`** - Debug annotations for instant events (seq numbers, length, flags)
- **`network_interface`** - Local network interface metadata (for cross-trace correlation)
- **`clock_snapshot`** - Clock correlation data for timestamp conversion between clock domains
- **`socket_connection`** - Structured socket connection data (protocol, src/dest IP:port, address family)

**Note:** Syscall events (tcp_send, tcp_recv, etc.) are range-based slices with duration because they represent the time a thread spends in a syscall. Packet events are instant events because they represent discrete points in the kernel packet processing pipeline.

**Track Structure:** Syscall events are stored on a single "Network" track per thread, with socket information embedded in each event's annotations. Packet events are stored on per-socket tracks under a global "Network Packets" root.

## Tables

### `track`
Maps track IDs to descriptive names and maintains parent-child hierarchy.

| Column | Type | Description |
|--------|------|-------------|
| trace_id | VARCHAR | Trace identifier |
| id | BIGINT | Unique track ID (matches `slice.track_id`) |
| name | VARCHAR | Track name (e.g., "Network" or "Socket 1:TCP:10.0.0.1:8080") |
| parent_id | BIGINT | FK to parent track's ID (for hierarchy) |

**Track Name Format:**
- Per-thread syscall track: `Network` - single track per thread for all network syscall events
- Per-socket packet tracks: `Socket {socket_id}:{protocol}:{src_host}:{src_port}->{dest_host}:{dest_port}`
  - Example: `Socket 42:TCP:10.128.0.5:12345->192.168.1.100:8080`
  - Example: `Socket 15:UDP:api.example.com:54321->dns.example.com:53`
- Root packet track: `Network Packets`

### `slice`
Network syscall events (range-based with duration). Each event has a track_id linking to the track table and a utid for direct thread correlation.

| Column | Type | Description |
|--------|------|-------------|
| trace_id | VARCHAR | Trace identifier |
| id | BIGINT | Unique slice ID (for joining with args) |
| ts | BIGINT | Start timestamp in nanoseconds |
| dur | BIGINT | Duration in nanoseconds |
| track_id | BIGINT | FK to `track.id` |
| utid | BIGINT | FK to `thread.utid` (direct thread link) |
| name | VARCHAR | Event type (see below) |
| category | VARCHAR | Event category (usually NULL) |
| depth | INTEGER | Nesting depth (always 0) |

**Note:** The `utid` column enables direct correlation between network syscall events and threads/processes without traversing the track hierarchy.

**Syscall Event Types:**
- `tcp_send` - TCP send syscall (sendto, write, etc.)
- `tcp_recv` - TCP receive syscall (recvfrom, read, etc.)
- `udp_send` - UDP send syscall

### `instant`
Packet-level events (point-in-time). These represent discrete points in the kernel packet processing pipeline.

| Column | Type | Description |
|--------|------|-------------|
| trace_id | VARCHAR | Trace identifier |
| id | BIGINT | Unique instant ID (for joining with instant_args) |
| ts | BIGINT | Timestamp in nanoseconds |
| track_id | BIGINT | FK to `track.id` |
| utid | BIGINT | FK to `thread.utid` (NULL for most packet events) |
| name | VARCHAR | Event type (see below) |
| category | VARCHAR | Event category (usually NULL) |

**Packet Event Types:**
- TCP: `TCP packet_enqueue`, `TCP packet_send`, `TCP packet_rcv_established`, `TCP packet_queue_rcv`, `TCP buffer_queue`, `TCP zero_window_probe`, `TCP zero_window_ack`, `TCP rto_timeout`
- UDP: `UDP send`, `UDP receive`, `UDP enqueue`
- Poll: `poll_ready` - Socket became ready during poll/epoll/select
- Drop/Throttle: `packet_drop`, `cpu_backlog_drop`, `TCP tsq_throttle`, `TCP mem_pressure`, `qdisc_enqueue`, `qdisc_drop`

### `args`
Debug annotations for syscall slice events. Multiple args can exist per slice.

| Column | Type | Description |
|--------|------|-------------|
| trace_id | VARCHAR | Trace identifier |
| slice_id | BIGINT | FK to `slice.id` |
| key | VARCHAR | Annotation name |
| int_value | BIGINT | Integer value (most common) |
| string_value | VARCHAR | String value |
| real_value | DOUBLE | Floating point value |

**Available Annotation Keys (for syscall events):**

| Key | Type | Events | Description |
|-----|------|--------|-------------|
| `socket_id` | int | All syscall events | Unique socket identifier (for grouping events by socket) |
| `socket` | string | All syscall events | Socket info string: "Socket {id}:{protocol}:{src_host}:{src_port}->{dest_host}:{dest_port}" |
| `bytes` | int | tcp_send, tcp_recv, udp_send | Bytes transferred |
| `sndbuf_used` | int | tcp_send | Current send buffer usage (sk_wmem_queued) |
| `sndbuf_limit` | int | tcp_send | Max send buffer size (sk_sndbuf) |
| `sndbuf_fill_pct` | int | tcp_send | Buffer fill percentage (used/limit * 100) |
| `recv_seq_start` | int | tcp_recv | App's read position at recvmsg() entry (copied_seq) |
| `recv_seq_end` | int | tcp_recv | App's read position after recvmsg() (start + bytes) |
| `rcv_nxt` | int | tcp_recv | Kernel's next expected sequence at entry |
| `bytes_available` | int | tcp_recv | Data buffered in kernel (rcv_nxt - recv_seq_start) |

### `instant_args`
Debug annotations for packet instant events. Multiple args can exist per instant.

| Column | Type | Description |
|--------|------|-------------|
| trace_id | VARCHAR | Trace identifier |
| instant_id | BIGINT | FK to `instant.id` |
| key | VARCHAR | Annotation name |
| int_value | BIGINT | Integer value (most common) |
| string_value | VARCHAR | String value (e.g., TCP flags) |
| real_value | DOUBLE | Floating point value |

**Available Annotation Keys (for packet events):**

| Key | Type | Events | Description |
|-----|------|--------|-------------|
| `seq` | int | TCP packets | TCP sequence number |
| `length` | int | All packet events | Packet length in bytes |
| `flags` | string | TCP packets | TCP flags (e.g., "SYN\|ACK") |
| `sndbuf_used` | int | TCP TX packets | Current send buffer usage |
| `sndbuf_limit` | int | TCP TX packets | Max send buffer size |
| `is_retransmit` | int | `packet_enqueue` only | 1 if TCP retransmit (see note below) |
| `is_zero_window_probe` | int | TCP zero_window_probe, TCP rto_timeout | 1 for zero window probe events (also set on RTO if snd_wnd=0) |
| `probe_count` | int | TCP zero_window_probe | Number of probes sent (icsk_probes_out) |
| `snd_wnd` | int | TCP zero_window_probe, TCP rto_timeout | Current send window (0 for zero window condition) |
| `rto_jiffies` | int | TCP rto_timeout, TCP packet_enqueue | RTO value in kernel jiffies (raw kernel value) |
| `rto_us` | int | TCP rto_timeout | RTO value in microseconds (converted using system HZ) |
| `rto_ms` | int | TCP rto_timeout | RTO value in milliseconds (for easier reading) |
| `srtt_us` | int | TCP rto_timeout | Smoothed RTT in microseconds |
| `srtt_ms` | int | TCP rto_timeout | Smoothed RTT in milliseconds |
| `rttvar_us` | int | TCP rto_timeout | RTT variance in microseconds |
| `retransmit_count` | int | TCP rto_timeout | Number of consecutive RTO timeouts (1 = first timeout) |
| `backoff` | int | TCP rto_timeout, TCP packet_enqueue | Exponential backoff multiplier (0, 1, 2, 3, ...) |
| `icsk_pending` | int | TCP packet_enqueue | Timer pending: 0=none, 1=retrans, 2=delack, 3=probe/persist |
| `icsk_timeout` | int | TCP packet_enqueue | When timer fires (jiffies, lower 32 bits) |
| `socket_id` | int | poll_ready | Unique socket identifier (for correlation with other events) |
| `socket` | string | poll_ready | Socket info string: "Socket {id}:{protocol}:{src_host}:{src_port}->{dest_host}:{dest_port}" |
| `requested` | string | poll_ready | Poll events requested (e.g., "IN\|OUT") |
| `returned` | string | poll_ready | Poll events returned (e.g., "IN") |
| `drop_reason` | int | packet_drop, cpu_backlog_drop, qdisc_drop | SKB_DROP_REASON_* code from kfree_skb tracepoint |
| `drop_reason_str` | string | packet_drop, cpu_backlog_drop, qdisc_drop | Human-readable drop reason (e.g., "QDISC_DROP", "CPU_BACKLOG") |
| `drop_location` | int | packet_drop | Kernel code address that dropped the packet |
| `qlen` | int | cpu_backlog_drop, qdisc_enqueue, qdisc_drop | Queue length at time of event |
| `qlen_limit` | int | cpu_backlog_drop, qdisc_enqueue, qdisc_drop | Queue limit (for backlog: netdev_max_backlog, default 1000) |
| `sk_wmem_alloc` | int | TCP tsq_throttle, TCP mem_pressure | Current sk_wmem_alloc (TSQ allocated memory) |
| `tsq_limit` | int | TCP tsq_throttle | TCP Small Queue limit that was exceeded |

**Poll Event Flags:**
The `requested` and `returned` fields use pipe-separated poll event names:
- `IN` - Data available to read (POLLIN/EPOLLIN)
- `OUT` - Ready to write (POLLOUT/EPOLLOUT)
- `PRI` - Priority data available (POLLPRI/EPOLLPRI)
- `ERR` - Error condition (POLLERR/EPOLLERR)
- `HUP` - Hang up (POLLHUP/EPOLLHUP)
- `RDHUP` - Peer closed connection (EPOLLRDHUP)

**Note on Persist Timer Fields:** The `icsk_pending`, `icsk_timeout`, `rto_jiffies`, `backoff`, and `probe_count` fields are populated on TCP packet_enqueue events when a timer is pending (`icsk_pending > 0`). These fields help understand TCP persist timer behavior during zero-window conditions:
- `icsk_pending=3` indicates the persist (probe) timer is armed
- `icsk_timeout` shows when the timer will fire (compare with packet timestamp to calculate time remaining)
- `rto_jiffies` shows the current RTO value (persist timer uses this as base interval)
- `backoff` shows how many times the timer has doubled due to exponential backoff
- `probe_count` shows how many zero-window probes have been sent

**Note on RTO Timeout Events:** RTO (Retransmission Timeout) events fire when the TCP retransmit timer expires because an ACK wasn't received in time. The `retransmit_count` shows how many consecutive RTOs have occurred (1 = first timeout). The `backoff` shows the exponential backoff multiplier applied to the RTO. If `snd_wnd=0`, the RTO is handling a zero-window condition rather than packet loss, and `is_zero_window_probe` will be set to 1.

**Note on Retransmit Detection:** The `is_retransmit` field is only available on `TCP packet_enqueue` events, NOT on `TCP packet_send` events. This is because the retransmit flag (`TCPCB_RETRANS`) is read from the kernel's `tcp_skb_cb` control block, which is only accessible at the TCP layer probe point (`__tcp_transmit_skb`), not at the device layer (`net_dev_start_xmit`).

**Note on Packet Drop Events:** The `packet_drop` event captures all packet drops via the `kfree_skb` kernel tracepoint. The `drop_reason` field contains the SKB_DROP_REASON_* enum value, and `drop_reason_str` provides the human-readable string. Common drop reasons include:
- `QDISC_DROP` (59) - Queue discipline dropped packet (queue overflow)
- `CPU_BACKLOG` (66) - CPU backlog queue was full
- `NOMEM` (76) - Memory allocation failed
- `PROTO_MEM` (20) - Protocol memory pressure
- `SOCKET_RCVBUFF` (6) - Socket receive buffer full
- `FULL_RING` (75) - NIC ring buffer full

**Note on TSQ Throttle Events:** TSQ (TCP Small Queue) events fire when `tcp_tsq_write` is called with significant data queued. The `sk_wmem_alloc` field shows current allocated memory in the qdisc, and `tsq_limit` shows the estimated limit. High values indicate the TCP layer is throttling transmission to prevent qdisc overflow.

**Note on Memory Pressure Events:** These events fire when `sk_stream_wait_memory` is called, indicating the application's write is blocked waiting for send buffer space. The `sndbuf_used` and `sndbuf_limit` fields show current buffer state. Frequent memory pressure events indicate the receiver cannot keep up with the sender.

### `network_interface`
Local network interface metadata captured at trace start, organized by network namespace. This captures interfaces from:
- The host network namespace
- Container network namespaces (Docker, containerd, cri-o)
- Any other network namespaces used by traced processes

Used for cross-trace correlation and to identify container-specific IP addresses.

| Column | Type | Description |
|--------|------|-------------|
| trace_id | VARCHAR | Trace identifier |
| namespace | VARCHAR | Network namespace name (see format below) |
| interface_name | VARCHAR | Interface name (e.g., "eth0", "lo", "docker0") |
| ip_address | VARCHAR | IP address assigned to the interface |
| address_type | VARCHAR | Address type: "ipv4" or "ipv6" |

**Namespace Name Format:**
- `host` - The host (init) network namespace
- `container:<id> (<comm>)` - Container namespace with detected container ID and process name
  - Example: `container:2a104e5e92a3 (nginx)`
- `netns:<inode> (<comm>:<pid>)` - Fallback for namespaces without container ID
  - Example: `netns:4026532890 (java:12345)`

**Example Data:**
```
trace_id | namespace                       | interface_name | ip_address     | address_type
---------+---------------------------------+----------------+----------------+-------------
trace_a  | host                            | eth0           | 10.128.0.5     | ipv4
trace_a  | host                            | docker0        | 172.17.0.1     | ipv4
trace_a  | container:abc123 (nginx)        | eth0           | 172.17.0.2     | ipv4
trace_a  | container:abc123 (nginx)        | lo             | 127.0.0.1      | ipv4
trace_a  | container:def456 (redis)        | eth0           | 172.17.0.3     | ipv4
```

**Note:** Network namespace deduplication is based on the namespace inode. Multiple processes sharing the same network namespace will only have their interfaces enumerated once.

### `clock_snapshot`
Clock snapshot data for correlating timestamps between different clock domains. Each trace typically has one clock snapshot at the start, containing simultaneous readings from multiple clock sources.

| Column | Type | Description |
|--------|------|-------------|
| trace_id | VARCHAR | Trace identifier |
| clock_id | INTEGER | Clock type ID (see table below) |
| clock_name | VARCHAR | Human-readable clock name |
| timestamp_ns | BIGINT | Timestamp in nanoseconds for this clock |
| is_primary | BOOLEAN | True if this is the primary trace clock |

**Clock Types:**

| ID | Name | Description |
|----|------|-------------|
| 0 | UNKNOWN | Unknown clock type |
| 1 | REALTIME | Wall clock time (can jump due to NTP) |
| 2 | REALTIME_COARSE | Coarse-grained wall clock |
| 3 | MONOTONIC | Monotonic clock (excludes suspend time) |
| 4 | MONOTONIC_COARSE | Coarse-grained monotonic |
| 5 | MONOTONIC_RAW | Raw hardware monotonic |
| 6 | BOOTTIME | Time since boot (includes suspend) |
| 9 | TSC | CPU timestamp counter |
| 10 | PERF | perf_event clock |

**Use Cases:**
- Convert trace timestamps (typically BOOTTIME) to wall clock time (REALTIME)
- Compare start times across traces from different machines
- Correlate events from multiple traces captured at the same time

**Example: Get trace start time in wall clock:**
```sql
SELECT trace_id,
       to_timestamp(timestamp_ns / 1e9) as start_time
FROM clock_snapshot
WHERE clock_name = 'REALTIME'
ORDER BY timestamp_ns;
```

**Example: Find gaps between trace starts:**
```sql
WITH ordered AS (
    SELECT trace_id, timestamp_ns,
           LAG(timestamp_ns) OVER (ORDER BY timestamp_ns) as prev_ts
    FROM clock_snapshot
    WHERE clock_name = 'REALTIME'
)
SELECT trace_id,
       (timestamp_ns - prev_ts) / 1e9 as gap_sec
FROM ordered
WHERE prev_ts IS NOT NULL
ORDER BY gap_sec DESC;
```

### `socket_connection`
Structured socket connection data extracted from track names for efficient querying. This table provides direct access to the 4-tuple (src_ip, src_port, dest_ip, dest_port) without needing to parse track names.

| Column | Type | Description |
|--------|------|-------------|
| trace_id | VARCHAR | Trace identifier |
| socket_id | BIGINT | Unique socket identifier (from track name) |
| track_id | BIGINT | FK to `track.id` |
| protocol | VARCHAR | Protocol: "TCP" or "UDP" |
| src_ip | VARCHAR | Source IP address or hostname |
| src_port | INTEGER | Source port number |
| dest_ip | VARCHAR | Destination IP address or hostname |
| dest_port | INTEGER | Destination port number |
| address_family | VARCHAR | "IPv4" or "IPv6" (inferred from IP format) |

**Example Data:**
```
trace_id | socket_id | track_id | protocol | src_ip     | src_port | dest_ip       | dest_port | address_family
---------+-----------+----------+----------+------------+----------+---------------+-----------+---------------
trace_a  | 42        | 100      | TCP      | 10.128.0.5 | 12345    | 192.168.1.100 | 8080      | IPv4
trace_a  | 15        | 101      | UDP      | 10.128.0.5 | 54321    | 8.8.8.8       | 53        | IPv4
trace_b  | 1         | 200      | TCP      | ::1        | 40000    | ::1           | 6379      | IPv6
```

**Note:** This table is populated by parsing socket track names during trace conversion. Each row corresponds to a socket track under "Network Packets". Use this table for efficient filtering and joins instead of parsing track names with regex.

## Data Model

```
track (Root: "Network Packets")
└── track (Socket 1:TCP:10.0.0.1:12345->10.0.0.2:8080, parent_id = root)
    ├── instant (TCP packet_enqueue, track_id = socket)
    │   └── instant_args (length=1460, seq=12345, flags="ACK")
    ├── instant (TCP packet_send, track_id = socket)
    │   └── instant_args (length=1460, seq=12345)
    ├── instant (TCP packet_rcv_established, track_id = socket)
    │   └── instant_args (length=64, seq=67890)
    └── instant (TCP buffer_queue, track_id = socket)
        └── instant_args (length=4096, sndbuf_used=8192, sndbuf_limit=65536)

socket_connection (extracted from track names)
└── (trace_id, socket_id=1, track_id, protocol="TCP", src_ip="10.0.0.1", src_port=12345, dest_ip="10.0.0.2", dest_port=8080, address_family="IPv4")

track (Thread, parent of "Network" track)
└── track (Network, parent_id = thread)
    ├── slice (tcp_send, track_id = network, dur=12345)
    │   └── args (socket_id=1, socket="Socket 1:TCP:10.0.0.1:12345->10.0.0.2:8080", bytes=4096, ...)
    ├── slice (tcp_recv, track_id = network, dur=5678)
    │   └── args (socket_id=1, socket="Socket 1:TCP:10.0.0.1:12345->10.0.0.2:8080", bytes=2048, ...)
    └── slice (tcp_send, track_id = network, dur=3000)
        └── args (socket_id=2, socket="Socket 2:TCP:10.0.0.1:23456->10.0.0.3:443", bytes=1024, ...)
```

## Common Queries

### 1. Network Traffic by Process (Using utid)
The simplest way to correlate network events with processes:
```sql
SELECT p.name as process,
       COUNT(*) as events,
       SUM(CASE WHEN a.key = 'bytes' THEN a.int_value ELSE 0 END) / 1073741824.0 as total_gb
FROM slice s
JOIN thread t ON s.utid = t.utid AND s.trace_id = t.trace_id
JOIN process p ON t.upid = p.upid AND t.trace_id = p.trace_id
LEFT JOIN args a ON s.id = a.slice_id AND s.trace_id = a.trace_id AND a.key = 'bytes'
WHERE s.name IN ('tcp_send', 'tcp_recv')
GROUP BY p.name
ORDER BY total_gb DESC
LIMIT 20;
```

### 2. Network Traffic by Process with Socket Count
```sql
SELECT p.name as process, p.pid,
       COUNT(DISTINCT a_socket.int_value) as sockets,
       COUNT(s.id) as events,
       SUM(CASE WHEN a.key = 'bytes' THEN a.int_value ELSE 0 END) / 1073741824.0 as total_gb
FROM slice s
JOIN thread t ON s.utid = t.utid AND s.trace_id = t.trace_id
JOIN process p ON t.upid = p.upid AND t.trace_id = p.trace_id
LEFT JOIN args a ON s.id = a.slice_id AND s.trace_id = a.trace_id AND a.key = 'bytes'
LEFT JOIN args a_socket ON s.id = a_socket.slice_id AND s.trace_id = a_socket.trace_id AND a_socket.key = 'socket_id'
WHERE s.name IN ('tcp_send', 'tcp_recv')
GROUP BY p.name, p.pid
ORDER BY total_gb DESC
LIMIT 20;
```

### 3. Find Network Traffic for a Specific Thread
```sql
SELECT a_socket.string_value as socket, s.name as event_type,
       COUNT(*) as events,
       SUM(CASE WHEN a.key = 'bytes' THEN a.int_value ELSE 0 END) / 1048576.0 as total_mb
FROM slice s
JOIN thread t ON s.utid = t.utid AND s.trace_id = t.trace_id
LEFT JOIN args a ON s.id = a.slice_id AND s.trace_id = a.trace_id AND a.key = 'bytes'
LEFT JOIN args a_socket ON s.id = a_socket.slice_id AND s.trace_id = a_socket.trace_id AND a_socket.key = 'socket'
WHERE t.name = 'loco-run:0' AND s.name IN ('tcp_send', 'tcp_recv')
GROUP BY a_socket.string_value, s.name
ORDER BY total_mb DESC;
```

### 4. Find All TCP Connections
```sql
-- From syscall events (using args)
SELECT DISTINCT a.string_value as socket
FROM args a
WHERE a.key = 'socket' AND a.string_value LIKE 'Socket%TCP%';

-- OR from packet events (using track names)
SELECT DISTINCT name
FROM track
WHERE name LIKE 'Socket%TCP%';
```

### 5. Total Bytes Transferred Per Socket
```sql
SELECT a_socket.string_value as socket,
       SUM(a_bytes.int_value) / 1048576.0 as total_mb,
       COUNT(*) as events
FROM slice s
JOIN args a_socket ON s.id = a_socket.slice_id AND s.trace_id = a_socket.trace_id AND a_socket.key = 'socket'
JOIN args a_bytes ON s.id = a_bytes.slice_id AND s.trace_id = a_bytes.trace_id AND a_bytes.key = 'bytes'
WHERE s.name IN ('tcp_send', 'tcp_recv', 'udp_send')
GROUP BY a_socket.string_value
ORDER BY total_mb DESC
LIMIT 20;
```

### 6. Analyze Send Buffer Pressure
Find sockets with high send buffer utilization:
```sql
SELECT a_socket.string_value as socket,
       AVG(a_fill.int_value) as avg_fill_pct,
       MAX(a_fill.int_value) as max_fill_pct,
       COUNT(*) as events
FROM slice s
JOIN args a_socket ON s.id = a_socket.slice_id AND s.trace_id = a_socket.trace_id AND a_socket.key = 'socket'
JOIN args a_fill ON s.id = a_fill.slice_id AND s.trace_id = a_fill.trace_id AND a_fill.key = 'sndbuf_fill_pct'
WHERE s.name = 'tcp_send'
GROUP BY a_socket.string_value
HAVING avg_fill_pct > 50
ORDER BY avg_fill_pct DESC;
```

### 7. TCP Packet Flow for a Specific Connection
```sql
SELECT i.ts, i.name as event,
       MAX(CASE WHEN a.key = 'seq' THEN a.int_value END) as seq,
       MAX(CASE WHEN a.key = 'length' THEN a.int_value END) as length,
       MAX(CASE WHEN a.key = 'flags' THEN a.string_value END) as flags
FROM instant i
JOIN track t ON i.track_id = t.id AND i.trace_id = t.trace_id
LEFT JOIN instant_args a ON i.id = a.instant_id AND i.trace_id = a.trace_id
WHERE t.name = 'Socket 1:TCP:10.0.0.1:12345->10.0.0.2:8080'
GROUP BY i.id, i.ts, i.name
ORDER BY i.ts
LIMIT 100;
```

### 8. Find High-Volume Connections
Connections with most packet events:
```sql
SELECT t.name as socket,
       COUNT(*) as packet_events,
       SUM(CASE WHEN a.key = 'length' THEN a.int_value ELSE 0 END) / 1048576.0 as total_mb
FROM instant i
JOIN track t ON i.track_id = t.id AND i.trace_id = t.trace_id
LEFT JOIN instant_args a ON i.id = a.instant_id AND i.trace_id = a.trace_id AND a.key = 'length'
WHERE i.name LIKE 'TCP packet%' AND t.name LIKE 'Socket%'
GROUP BY t.name
ORDER BY packet_events DESC
LIMIT 20;
```

### 9. Find TCP Retransmitted Packets
Find all packets that were retransmitted, grouped by socket:
```sql
SELECT t.name as socket,
       COUNT(*) as retransmit_count,
       SUM(CASE WHEN a_len.key = 'length' THEN a_len.int_value ELSE 0 END) as retransmit_bytes
FROM instant i
JOIN track t ON i.track_id = t.id AND i.trace_id = t.trace_id
JOIN instant_args a ON i.id = a.instant_id AND i.trace_id = a.trace_id AND a.key = 'is_retransmit' AND a.int_value = 1
LEFT JOIN instant_args a_len ON i.id = a_len.instant_id AND i.trace_id = a_len.trace_id AND a_len.key = 'length'
WHERE i.name LIKE 'TCP packet%'
GROUP BY t.name
ORDER BY retransmit_count DESC;
```

### 10. Detailed Retransmit Analysis
Show retransmit events with sequence numbers and timing:
```sql
SELECT i.ts / 1e9 as time_sec,
       t.name as socket,
       MAX(CASE WHEN a.key = 'seq' THEN a.int_value END) as seq,
       MAX(CASE WHEN a.key = 'length' THEN a.int_value END) as length,
       MAX(CASE WHEN a.key = 'flags' THEN a.string_value END) as flags
FROM instant i
JOIN track t ON i.track_id = t.id AND i.trace_id = t.trace_id
JOIN instant_args a_retrans ON i.id = a_retrans.instant_id AND i.trace_id = a_retrans.trace_id
    AND a_retrans.key = 'is_retransmit' AND a_retrans.int_value = 1
LEFT JOIN instant_args a ON i.id = a.instant_id AND i.trace_id = a.trace_id
WHERE i.name LIKE 'TCP packet%'
GROUP BY i.id, i.ts, t.name
ORDER BY i.ts
LIMIT 100;
```

### 11. Find All Zero Window Probe Events
Find all zero window probe events, grouped by socket:
```sql
SELECT t.name as socket,
       COUNT(*) as probe_count,
       MIN(i.ts) / 1e9 as first_probe_sec,
       MAX(i.ts) / 1e9 as last_probe_sec,
       (MAX(i.ts) - MIN(i.ts)) / 1e9 as duration_sec
FROM instant i
JOIN track t ON i.track_id = t.id AND i.trace_id = t.trace_id
WHERE i.name = 'TCP zero_window_probe'
GROUP BY t.name
ORDER BY probe_count DESC;
```

### 12. Zero Window Probe Timeline
Show zero window probe events with probe count progression:
```sql
SELECT i.ts / 1e9 as time_sec,
       t.name as socket,
       MAX(CASE WHEN a.key = 'probe_count' THEN a.int_value END) as probe_num,
       MAX(CASE WHEN a.key = 'snd_wnd' THEN a.int_value END) as snd_wnd,
       MAX(CASE WHEN a.key = 'seq' THEN a.int_value END) as seq
FROM instant i
JOIN track t ON i.track_id = t.id AND i.trace_id = t.trace_id
LEFT JOIN instant_args a ON i.id = a.instant_id AND i.trace_id = a.trace_id
WHERE i.name = 'TCP zero_window_probe'
GROUP BY i.id, i.ts, t.name
ORDER BY i.ts;
```

### 13. Correlate Zero Window Probes with High Buffer Utilization
Find sockets that have both zero window probes and high send buffer utilization:
```sql
WITH zwp_sockets AS (
    SELECT DISTINCT t.name as socket, i.trace_id
    FROM instant i
    JOIN track t ON i.track_id = t.id AND i.trace_id = t.trace_id
    WHERE i.name = 'TCP zero_window_probe'
),
high_buffer AS (
    SELECT a_socket.string_value as socket, s.trace_id, AVG(a_fill.int_value) as avg_fill_pct
    FROM slice s
    JOIN args a_socket ON s.id = a_socket.slice_id AND s.trace_id = a_socket.trace_id AND a_socket.key = 'socket'
    JOIN args a_fill ON s.id = a_fill.slice_id AND s.trace_id = a_fill.trace_id AND a_fill.key = 'sndbuf_fill_pct'
    WHERE s.name = 'tcp_send'
    GROUP BY a_socket.string_value, s.trace_id
    HAVING avg_fill_pct > 80
)
SELECT z.socket, h.avg_fill_pct
FROM zwp_sockets z
JOIN high_buffer h ON z.socket = h.socket AND z.trace_id = h.trace_id;
```

### 14. TCP Recv Sequence Tracking
Show tcp_recv events with sequence progression to analyze receive buffering:
```sql
SELECT s.ts/1e9 as time_sec,
       s.dur/1e6 as duration_ms,
       MAX(CASE WHEN a.key = 'socket' THEN a.string_value END) as socket,
       MAX(CASE WHEN a.key = 'bytes' THEN a.int_value END) as bytes_read,
       MAX(CASE WHEN a.key = 'recv_seq_start' THEN a.int_value END) as seq_start,
       MAX(CASE WHEN a.key = 'recv_seq_end' THEN a.int_value END) as seq_end,
       MAX(CASE WHEN a.key = 'rcv_nxt' THEN a.int_value END) as rcv_nxt,
       MAX(CASE WHEN a.key = 'bytes_available' THEN a.int_value END) as buffered_bytes
FROM slice s
LEFT JOIN args a ON s.id = a.slice_id AND s.trace_id = a.trace_id
WHERE s.name = 'tcp_recv'
GROUP BY s.id, s.ts, s.dur
ORDER BY s.ts;
```

### 15. Identify Receive Bottlenecks
Find sockets where the kernel had more data buffered than the app consumed:
```sql
SELECT a_socket.string_value as socket,
       COUNT(*) as recv_calls,
       AVG(CASE WHEN a_avail.int_value > a_bytes.int_value
           THEN a_avail.int_value - a_bytes.int_value ELSE 0 END) as avg_unconsumed_bytes,
       MAX(a_avail.int_value) as max_bytes_available
FROM slice s
LEFT JOIN args a_socket ON s.id = a_socket.slice_id AND s.trace_id = a_socket.trace_id
    AND a_socket.key = 'socket'
LEFT JOIN args a_bytes ON s.id = a_bytes.slice_id AND s.trace_id = a_bytes.trace_id
    AND a_bytes.key = 'bytes'
LEFT JOIN args a_avail ON s.id = a_avail.slice_id AND s.trace_id = a_avail.trace_id
    AND a_avail.key = 'bytes_available'
WHERE s.name = 'tcp_recv'
GROUP BY a_socket.string_value
HAVING MAX(a_avail.int_value) > 0
ORDER BY avg_unconsumed_bytes DESC;
```

### 16. Find All RTO Timeout Events
Find all RTO timeout events, grouped by socket with timing statistics:
```sql
SELECT t.name as socket,
       COUNT(*) as rto_count,
       MIN(i.ts) / 1e9 as first_rto_sec,
       MAX(i.ts) / 1e9 as last_rto_sec,
       (MAX(i.ts) - MIN(i.ts)) / 1e9 as duration_sec,
       AVG(CASE WHEN a.key = 'rto_ms' THEN a.int_value END) as avg_rto_ms,
       MAX(CASE WHEN a.key = 'retransmit_count' THEN a.int_value END) as max_retransmits
FROM instant i
JOIN track t ON i.track_id = t.id AND i.trace_id = t.trace_id
LEFT JOIN instant_args a ON i.id = a.instant_id AND i.trace_id = a.trace_id
WHERE i.name = 'TCP rto_timeout'
GROUP BY t.name
ORDER BY rto_count DESC;
```

### 17. RTO Timeout Timeline with RTT Information
Show RTO timeout events with RTO and RTT values to analyze retransmission behavior:
```sql
SELECT i.ts / 1e9 as time_sec,
       t.name as socket,
       MAX(CASE WHEN a.key = 'rto_ms' THEN a.int_value END) as rto_ms,
       MAX(CASE WHEN a.key = 'srtt_ms' THEN a.int_value END) as srtt_ms,
       MAX(CASE WHEN a.key = 'rttvar_us' THEN a.int_value END) / 1000.0 as rttvar_ms,
       MAX(CASE WHEN a.key = 'retransmit_count' THEN a.int_value END) as retransmit_count,
       MAX(CASE WHEN a.key = 'backoff' THEN a.int_value END) as backoff,
       MAX(CASE WHEN a.key = 'snd_wnd' THEN a.int_value END) as snd_wnd
FROM instant i
JOIN track t ON i.track_id = t.id AND i.trace_id = t.trace_id
LEFT JOIN instant_args a ON i.id = a.instant_id AND i.trace_id = a.trace_id
WHERE i.name = 'TCP rto_timeout'
GROUP BY i.id, i.ts, t.name
ORDER BY i.ts;
```

### 18. Correlate RTO Timeouts with Retransmitted Packets
Find sockets with both RTO timeouts and packet retransmissions to understand the full retransmit picture:
```sql
WITH rto_sockets AS (
    SELECT DISTINCT t.name as socket, i.trace_id,
           COUNT(*) as rto_count
    FROM instant i
    JOIN track t ON i.track_id = t.id AND i.trace_id = t.trace_id
    WHERE i.name = 'TCP rto_timeout'
    GROUP BY t.name, i.trace_id
),
retransmit_sockets AS (
    SELECT t.name as socket, i.trace_id,
           COUNT(*) as retransmit_count
    FROM instant i
    JOIN track t ON i.track_id = t.id AND i.trace_id = t.trace_id
    JOIN instant_args a ON i.id = a.instant_id AND i.trace_id = a.trace_id
        AND a.key = 'is_retransmit' AND a.int_value = 1
    WHERE i.name LIKE 'TCP packet%'
    GROUP BY t.name, i.trace_id
)
SELECT COALESCE(r.socket, rt.socket) as socket,
       COALESCE(r.rto_count, 0) as rto_timeouts,
       COALESCE(rt.retransmit_count, 0) as retransmit_packets
FROM rto_sockets r
FULL OUTER JOIN retransmit_sockets rt
    ON r.socket = rt.socket AND r.trace_id = rt.trace_id
ORDER BY COALESCE(r.rto_count, 0) + COALESCE(rt.retransmit_count, 0) DESC;
```

### 19. Identify RTO Events During Zero Window Conditions
Find RTO timeouts that occurred during zero window conditions (when the receiver's window was exhausted):
```sql
SELECT t.name as socket,
       i.ts / 1e9 as time_sec,
       MAX(CASE WHEN a.key = 'rto_ms' THEN a.int_value END) as rto_ms,
       MAX(CASE WHEN a.key = 'snd_wnd' THEN a.int_value END) as snd_wnd,
       MAX(CASE WHEN a.key = 'is_zero_window_probe' THEN a.int_value END) as is_zwp,
       MAX(CASE WHEN a.key = 'retransmit_count' THEN a.int_value END) as retransmit_count
FROM instant i
JOIN track t ON i.track_id = t.id AND i.trace_id = t.trace_id
LEFT JOIN instant_args a ON i.id = a.instant_id AND i.trace_id = a.trace_id
WHERE i.name = 'TCP rto_timeout'
GROUP BY i.id, i.ts, t.name
HAVING MAX(CASE WHEN a.key = 'snd_wnd' THEN a.int_value END) = 0
ORDER BY i.ts;
```

### 20. Analyze RTO Exponential Backoff
Track how RTO values increase with exponential backoff during persistent failures:
```sql
SELECT t.name as socket,
       MAX(CASE WHEN a.key = 'retransmit_count' THEN a.int_value END) as attempt,
       MAX(CASE WHEN a.key = 'backoff' THEN a.int_value END) as backoff,
       MAX(CASE WHEN a.key = 'rto_ms' THEN a.int_value END) as rto_ms,
       MAX(CASE WHEN a.key = 'srtt_ms' THEN a.int_value END) as base_srtt_ms
FROM instant i
JOIN track t ON i.track_id = t.id AND i.trace_id = t.trace_id
LEFT JOIN instant_args a ON i.id = a.instant_id AND i.trace_id = a.trace_id
WHERE i.name = 'TCP rto_timeout'
GROUP BY i.id, t.name
ORDER BY t.name,
         MAX(CASE WHEN a.key = 'retransmit_count' THEN a.int_value END);
```

### 21. Analyze Persist Timer State on Packet Send Events
Track TCP persist timer behavior during zero-window conditions to understand why ZWP probes have long gaps:
```sql
SELECT t.name as socket,
       ROUND(i.ts/1e9, 3) as time_sec,
       MAX(CASE WHEN a.key = 'sndbuf_fill_pct' THEN a.int_value END) as sndbuf_pct,
       MAX(CASE WHEN a.key = 'icsk_pending' THEN a.int_value END) as timer_pending,
       MAX(CASE WHEN a.key = 'icsk_timeout' THEN a.int_value END) as timeout_jiffies,
       MAX(CASE WHEN a.key = 'rto_jiffies' THEN a.int_value END) as rto_jiffies,
       MAX(CASE WHEN a.key = 'backoff' THEN a.int_value END) as backoff,
       MAX(CASE WHEN a.key = 'probe_count' THEN a.int_value END) as probes_sent
FROM instant i
JOIN track t ON i.track_id = t.id AND i.trace_id = t.trace_id
LEFT JOIN instant_args a ON i.id = a.instant_id AND i.trace_id = a.trace_id
WHERE i.name = 'TCP packet_enqueue'
  AND t.name LIKE 'Socket%'
GROUP BY i.id, i.ts, t.name
HAVING MAX(CASE WHEN a.key = 'icsk_pending' THEN a.int_value END) = 3  -- Persist timer armed
ORDER BY i.ts;
```

### 22. Find Sockets with Long Persist Timer Backoff
Identify connections where the persist timer has backed off significantly (indicating prolonged zero-window conditions):
```sql
SELECT t.name as socket,
       COUNT(*) as packets_with_persist,
       MAX(CASE WHEN a.key = 'backoff' THEN a.int_value END) as max_backoff,
       MAX(CASE WHEN a.key = 'probe_count' THEN a.int_value END) as max_probes,
       MAX(CASE WHEN a.key = 'rto_jiffies' THEN a.int_value END) as max_rto_jiffies
FROM instant i
JOIN track t ON i.track_id = t.id AND i.trace_id = t.trace_id
LEFT JOIN instant_args a ON i.id = a.instant_id AND i.trace_id = a.trace_id
WHERE i.name = 'TCP packet_enqueue'
GROUP BY t.name
HAVING MAX(CASE WHEN a.key = 'icsk_pending' THEN a.int_value END) = 3
   AND MAX(CASE WHEN a.key = 'backoff' THEN a.int_value END) >= 2
ORDER BY max_backoff DESC;
```

### 23. Find All Poll Ready Events
Find all poll_ready events grouped by socket to see which sockets are most frequently polled:
```sql
SELECT MAX(CASE WHEN a.key = 'socket' THEN a.string_value END) as socket,
       COUNT(*) as poll_count,
       COUNT(DISTINCT i.utid) as threads_polling
FROM instant i
LEFT JOIN instant_args a ON i.id = a.instant_id AND i.trace_id = a.trace_id
WHERE i.name = 'poll_ready'
GROUP BY MAX(CASE WHEN a.key = 'socket_id' THEN a.int_value END)
ORDER BY poll_count DESC;
```

### 24. Poll Events by Thread
Find which threads are doing the most polling:
```sql
SELECT t.name as thread, p.name as process,
       COUNT(*) as poll_events,
       COUNT(DISTINCT CASE WHEN a.key = 'socket_id' THEN a.int_value END) as sockets_polled
FROM instant i
JOIN thread t ON i.utid = t.utid AND i.trace_id = t.trace_id
JOIN process p ON t.upid = p.upid AND t.trace_id = p.trace_id
LEFT JOIN instant_args a ON i.id = a.instant_id AND i.trace_id = a.trace_id
WHERE i.name = 'poll_ready'
GROUP BY t.name, p.name
ORDER BY poll_events DESC;
```

### 25. Poll Event Timeline for a Socket
Show poll events for a specific socket with the events that triggered them:
```sql
SELECT i.ts / 1e9 as time_sec,
       MAX(CASE WHEN a.key = 'socket' THEN a.string_value END) as socket,
       MAX(CASE WHEN a.key = 'requested' THEN a.string_value END) as requested,
       MAX(CASE WHEN a.key = 'returned' THEN a.string_value END) as returned
FROM instant i
LEFT JOIN instant_args a ON i.id = a.instant_id AND i.trace_id = a.trace_id
WHERE i.name = 'poll_ready'
GROUP BY i.id, i.ts
ORDER BY i.ts
LIMIT 100;
```

### 26. Correlate Poll Events with Subsequent Reads
Find poll events followed by tcp_recv on the same socket within 1ms:
```sql
WITH poll_events AS (
    SELECT i.ts, i.utid,
           MAX(CASE WHEN a.key = 'socket_id' THEN a.int_value END) as socket_id
    FROM instant i
    LEFT JOIN instant_args a ON i.id = a.instant_id AND i.trace_id = a.trace_id
    WHERE i.name = 'poll_ready'
    GROUP BY i.id, i.ts, i.utid
),
recv_events AS (
    SELECT s.ts, s.utid,
           MAX(CASE WHEN a.key = 'socket_id' THEN a.int_value END) as socket_id,
           MAX(CASE WHEN a.key = 'bytes' THEN a.int_value END) as bytes
    FROM slice s
    LEFT JOIN args a ON s.id = a.slice_id AND s.trace_id = a.trace_id
    WHERE s.name = 'tcp_recv'
    GROUP BY s.id, s.ts, s.utid
)
SELECT p.ts / 1e9 as poll_time_sec,
       (r.ts - p.ts) / 1e6 as delay_ms,
       r.bytes
FROM poll_events p
JOIN recv_events r ON p.socket_id = r.socket_id
    AND p.utid = r.utid
    AND r.ts > p.ts
    AND r.ts < p.ts + 1000000  -- within 1ms
ORDER BY p.ts;
```

### 27. Find Connections by Destination Port (Using socket_connection)
Find all TCP connections to a specific port:
```sql
SELECT trace_id, socket_id, src_ip, src_port, dest_ip, dest_port
FROM socket_connection
WHERE protocol = 'TCP' AND dest_port = 8080
ORDER BY trace_id, socket_id;
```

### 28. Find Connections from a Specific Source IP
```sql
SELECT protocol, src_port, dest_ip, dest_port
FROM socket_connection
WHERE src_ip = '10.0.0.1'
ORDER BY protocol, dest_port;
```

### 29. Correlate Sender and Receiver Traces (4-tuple Match)
Find matching connections between two traces (one sending, one receiving):
```sql
SELECT
    s.trace_id as sender_trace,
    r.trace_id as receiver_trace,
    s.protocol,
    s.src_ip || ':' || s.src_port as sender_endpoint,
    s.dest_ip || ':' || s.dest_port as receiver_endpoint
FROM socket_connection s
JOIN socket_connection r
    ON s.src_ip = r.dest_ip
    AND s.src_port = r.dest_port
    AND s.dest_ip = r.src_ip
    AND s.dest_port = r.src_port
    AND s.protocol = r.protocol
WHERE s.trace_id != r.trace_id;
```

### 30. Join socket_connection with Packet Events
Get timing info for packets on a specific connection:
```sql
SELECT
    sc.protocol, sc.src_ip, sc.src_port, sc.dest_ip, sc.dest_port,
    i.name as event_name,
    i.ts / 1e9 as time_sec,
    MAX(CASE WHEN a.key = 'length' THEN a.int_value END) as length,
    MAX(CASE WHEN a.key = 'seq' THEN a.int_value END) as seq
FROM socket_connection sc
JOIN instant i ON i.track_id = sc.track_id AND i.trace_id = sc.trace_id
LEFT JOIN instant_args a ON i.id = a.instant_id AND i.trace_id = a.trace_id
WHERE sc.protocol = 'TCP' AND sc.dest_port = 8080
GROUP BY sc.protocol, sc.src_ip, sc.src_port, sc.dest_ip, sc.dest_port, i.id, i.name, i.ts
ORDER BY i.ts
LIMIT 50;
```

### 31. Connection Summary by Address Family
```sql
SELECT address_family, protocol, COUNT(*) as connection_count
FROM socket_connection
GROUP BY address_family, protocol
ORDER BY connection_count DESC;
```

### 32. Find All Connections to External IPs (Non-Private)
```sql
SELECT *
FROM socket_connection
WHERE dest_ip NOT LIKE '10.%'
  AND dest_ip NOT LIKE '172.16.%'
  AND dest_ip NOT LIKE '172.17.%'
  AND dest_ip NOT LIKE '172.18.%'
  AND dest_ip NOT LIKE '172.19.%'
  AND dest_ip NOT LIKE '172.2_.%'
  AND dest_ip NOT LIKE '172.30.%'
  AND dest_ip NOT LIKE '172.31.%'
  AND dest_ip NOT LIKE '192.168.%'
  AND dest_ip NOT LIKE '127.%'
  AND dest_ip NOT LIKE '::%'
  AND dest_ip != '::1';
```

## Track Hierarchy

Network tracks are organized hierarchically:

**Network Interface Metadata:**
```
Network Interfaces (root)
├── host
│   ├── eth0 (instant event with ipv4/ipv6 annotations)
│   ├── docker0
│   └── lo
├── container:abc123 (nginx)
│   ├── eth0
│   └── lo
└── netns:4026532890 (java:12345)
    ├── eth0
    └── lo
```

**Packet Events (global, not per-thread, stored in `instant` table):**
```
Network Packets (root)
└── Socket {id}:{protocol}:{src}:{src_port}->{dest}:{dest_port}
    ├── TCP packet_enqueue (instant)
    ├── TCP packet_send (instant)
    ├── TCP packet_rcv_established (instant)
    ├── TCP packet_queue_rcv (instant)
    ├── TCP buffer_queue (instant)
    ├── TCP zero_window_probe (instant)
    ├── TCP zero_window_ack (instant)
    ├── TCP rto_timeout (instant)
    ├── UDP send (instant)
    ├── UDP receive (instant)
    ├── UDP enqueue (instant)
    ├── packet_drop (instant) - SKB dropped via kfree_skb
    ├── cpu_backlog_drop (instant) - CPU backlog queue overflow
    ├── TCP tsq_throttle (instant) - TSQ throttling
    ├── TCP mem_pressure (instant) - Send buffer blocked
    ├── qdisc_enqueue (instant) - Qdisc enqueue state
    └── qdisc_drop (instant) - Qdisc drop
```

**Syscall Events (per-thread, stored in `slice` table):**
```
Thread (from PID/TGID track descriptor)
└── Network
    ├── tcp_send (slice with socket_id, socket annotations)
    ├── tcp_recv (slice with socket_id, socket annotations)
    ├── udp_send (slice with socket_id, socket annotations)
    └── poll_ready (instant with socket_id, requested, returned)
```

**Note:** All syscall events from a thread are on a single "Network" track. Socket information is stored in the `args` table (for slices) or `instant_args` table (for poll_ready):
- `socket_id`: numeric socket identifier (for grouping/filtering)
- `socket`: human-readable string like "Socket 1:TCP:10.0.0.1:12345->10.0.0.2:8080"

## Notes

### Send Buffer Metrics
- `sndbuf_used`: Bytes currently queued in send buffer (sk_wmem_queued)
- `sndbuf_limit`: Maximum send buffer size (sk_sndbuf)
- `sndbuf_fill_pct`: Percentage of buffer used (can exceed 100% temporarily)

High `sndbuf_fill_pct` values indicate potential backpressure - the application is sending faster than the network can transmit.

### Receive Buffer Metrics (tcp_recv)
- `recv_seq_start`: Application's read position at recvmsg() entry (from `tcp_sock->copied_seq`)
- `recv_seq_end`: Application's read position after recvmsg() (`recv_seq_start + bytes`)
- `rcv_nxt`: Kernel's next expected sequence at entry (from `tcp_sock->rcv_nxt`)
- `bytes_available`: Data buffered in kernel (`rcv_nxt - recv_seq_start`)

High `bytes_available` values indicate the application is reading slower than data is arriving. If `bytes_available` consistently exceeds `bytes` read, the receive buffer is building up.

**Note:** `bytes_available` uses wrapping arithmetic to handle TCP sequence number wraparound and is only emitted when < 64MB.

### TCP Flags Format
TCP flags are stored as pipe-separated strings: `SYN|ACK`, `FIN|ACK`, `PSH|ACK`, etc.

Available flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR

### Socket ID
The socket ID in track names is a unique identifier assigned by the BPF tracer during tracing. It's consistent within a single trace but not across traces.

## Cross-Trace Correlation

When analyzing traces from multiple machines, use the `network_interface` table to identify which machine each trace came from and correlate network connections.

### List All Namespaces and Their Interfaces
```sql
SELECT trace_id, namespace, interface_name, ip_address
FROM network_interface
WHERE address_type = 'ipv4' AND interface_name != 'lo'
ORDER BY trace_id, namespace, interface_name;
```

### List Unique Namespaces Per Trace
```sql
SELECT trace_id, namespace, COUNT(*) as interface_count
FROM network_interface
WHERE address_type = 'ipv4'
GROUP BY trace_id, namespace
ORDER BY trace_id, namespace;
```

### Find Container IP Addresses
```sql
SELECT namespace, interface_name, ip_address
FROM network_interface
WHERE namespace LIKE 'container:%' AND address_type = 'ipv4';
```

### Find Which Trace/Namespace Has a Specific IP
```sql
SELECT trace_id, namespace, interface_name
FROM network_interface
WHERE ip_address = '172.17.0.2';
```

### Correlate Sockets to Source Machines/Containers
Find which machine/container (trace+namespace) owns the IP that appears in another trace's socket connections:
```sql
SELECT
    ni.trace_id as source_trace,
    ni.namespace as source_namespace,
    ni.interface_name as source_interface,
    ni.ip_address as source_ip,
    t.trace_id as dest_trace,
    t.name as socket_name
FROM network_interface ni
JOIN track t ON t.trace_id != ni.trace_id
    AND t.name LIKE '%' || ni.ip_address || '%'
WHERE ni.address_type = 'ipv4'
  AND ni.interface_name != 'lo';
```

### Build a Connection Map Between Nodes (Including Containers)
```sql
-- For each trace, find which other traces/containers it communicated with
-- Using the socket_connection table for easier querying
SELECT DISTINCT
    sc.trace_id as from_trace,
    ni.trace_id as to_trace,
    ni.namespace as to_namespace,
    sc.dest_ip
FROM socket_connection sc
JOIN network_interface ni ON sc.dest_ip = ni.ip_address
WHERE ni.address_type = 'ipv4'
  AND sc.trace_id != ni.trace_id;
```

**Alternative using REGEXP_EXTRACT on track names (for backward compatibility):**
```sql
WITH socket_destinations AS (
    SELECT DISTINCT
        trace_id,
        -- Extract dest_ip from socket name like "Socket 1:TCP:10.0.0.5:12345->10.0.0.6:8080"
        REGEXP_EXTRACT(name, 'Socket \d+:\w+:[^:]+:\d+->([^:]+):\d+', 1) as dest_ip
    FROM track
    WHERE name LIKE 'Socket%'
)
SELECT
    sd.trace_id as from_trace,
    ni.trace_id as to_trace,
    ni.namespace as to_namespace,
    sd.dest_ip
FROM socket_destinations sd
JOIN network_interface ni ON sd.dest_ip = ni.ip_address
WHERE ni.address_type = 'ipv4';
```

### Find Cross-Container Communication Within a Trace
```sql
-- Find traffic between containers on the same host
WITH container_ips AS (
    SELECT namespace, ip_address
    FROM network_interface
    WHERE namespace LIKE 'container:%' AND address_type = 'ipv4'
)
SELECT DISTINCT
    t.name as socket,
    ci.namespace as destination_container,
    ci.ip_address as destination_ip
FROM track t
JOIN container_ips ci ON t.name LIKE '%' || ci.ip_address || '%'
WHERE t.name LIKE 'Socket%';
```

### 33. Find All Packet Drop Events
Find all packet drops grouped by socket and drop reason:
```sql
SELECT t.name as socket,
       MAX(CASE WHEN a.key = 'drop_reason_str' THEN a.string_value END) as drop_reason,
       COUNT(*) as drop_count,
       SUM(CASE WHEN a.key = 'length' THEN a.int_value ELSE 0 END) as dropped_bytes
FROM instant i
JOIN track t ON i.track_id = t.id AND i.trace_id = t.trace_id
LEFT JOIN instant_args a ON i.id = a.instant_id AND i.trace_id = a.trace_id
WHERE i.name = 'packet_drop'
GROUP BY t.name, MAX(CASE WHEN a.key = 'drop_reason_str' THEN a.string_value END)
ORDER BY drop_count DESC;
```

### 34. Packet Drop Timeline
Show packet drops with reason codes and timing:
```sql
SELECT i.ts / 1e9 as time_sec,
       t.name as socket,
       MAX(CASE WHEN a.key = 'drop_reason' THEN a.int_value END) as reason_code,
       MAX(CASE WHEN a.key = 'drop_reason_str' THEN a.string_value END) as reason,
       MAX(CASE WHEN a.key = 'length' THEN a.int_value END) as length
FROM instant i
JOIN track t ON i.track_id = t.id AND i.trace_id = t.trace_id
LEFT JOIN instant_args a ON i.id = a.instant_id AND i.trace_id = a.trace_id
WHERE i.name = 'packet_drop'
GROUP BY i.id, i.ts, t.name
ORDER BY i.ts;
```

### 35. Find Memory Pressure Events
Find sockets experiencing send buffer pressure:
```sql
SELECT t.name as socket,
       COUNT(*) as pressure_events,
       AVG(CASE WHEN a_used.key = 'sndbuf_used' THEN a_used.int_value END) as avg_sndbuf_used,
       MAX(CASE WHEN a_used.key = 'sndbuf_used' THEN a_used.int_value END) as max_sndbuf_used,
       MAX(CASE WHEN a_limit.key = 'sndbuf_limit' THEN a_limit.int_value END) as sndbuf_limit
FROM instant i
JOIN track t ON i.track_id = t.id AND i.trace_id = t.trace_id
LEFT JOIN instant_args a_used ON i.id = a_used.instant_id AND i.trace_id = a_used.trace_id AND a_used.key = 'sndbuf_used'
LEFT JOIN instant_args a_limit ON i.id = a_limit.instant_id AND i.trace_id = a_limit.trace_id AND a_limit.key = 'sndbuf_limit'
WHERE i.name = 'TCP mem_pressure'
GROUP BY t.name
ORDER BY pressure_events DESC;
```

### 36. Correlate Drops with Memory Pressure
Find sockets with both drops and memory pressure:
```sql
WITH drop_sockets AS (
    SELECT DISTINCT t.name as socket, i.trace_id,
           COUNT(*) as drop_count
    FROM instant i
    JOIN track t ON i.track_id = t.id AND i.trace_id = t.trace_id
    WHERE i.name = 'packet_drop'
    GROUP BY t.name, i.trace_id
),
pressure_sockets AS (
    SELECT DISTINCT t.name as socket, i.trace_id,
           COUNT(*) as pressure_count
    FROM instant i
    JOIN track t ON i.track_id = t.id AND i.trace_id = t.trace_id
    WHERE i.name = 'TCP mem_pressure'
    GROUP BY t.name, i.trace_id
)
SELECT COALESCE(d.socket, p.socket) as socket,
       COALESCE(d.drop_count, 0) as drops,
       COALESCE(p.pressure_count, 0) as pressure_events
FROM drop_sockets d
FULL OUTER JOIN pressure_sockets p ON d.socket = p.socket AND d.trace_id = p.trace_id
WHERE d.drop_count > 0 OR p.pressure_count > 0
ORDER BY COALESCE(d.drop_count, 0) + COALESCE(p.pressure_count, 0) DESC;
```

### 37. TSQ Throttle Analysis
Find sockets experiencing TSQ throttling:
```sql
SELECT t.name as socket,
       COUNT(*) as throttle_events,
       AVG(CASE WHEN a.key = 'sk_wmem_alloc' THEN a.int_value END) as avg_wmem_alloc,
       MAX(CASE WHEN a.key = 'sk_wmem_alloc' THEN a.int_value END) as max_wmem_alloc
FROM instant i
JOIN track t ON i.track_id = t.id AND i.trace_id = t.trace_id
LEFT JOIN instant_args a ON i.id = a.instant_id AND i.trace_id = a.trace_id
WHERE i.name = 'TCP tsq_throttle'
GROUP BY t.name
ORDER BY throttle_events DESC;
```
