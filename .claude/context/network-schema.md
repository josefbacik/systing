# Network Event Schema in systing-analyze

This document describes how network events are stored in DuckDB after conversion from Perfetto traces.

## Overview

Network events are tracked through seven related tables:
- **`track`** - Track metadata including socket connection info
- **`slice`** - Network syscall events (tcp_send, tcp_recv, udp_send) - range-based with duration
- **`args`** - Debug annotations for slice events (bytes, buffer info)
- **`instant`** - Packet-level events (packet_enqueue, packet_send, etc.) - point-in-time events
- **`instant_args`** - Debug annotations for instant events (seq numbers, length, flags)
- **`network_interface`** - Local network interface metadata (for cross-trace correlation)
- **`clock_snapshot`** - Clock correlation data for timestamp conversion between clock domains

**Note:** Syscall events (tcp_send, tcp_recv, etc.) are range-based slices with duration because they represent the time a thread spends in a syscall. Packet events are instant events because they represent discrete points in the kernel packet processing pipeline.

## Tables

### `track`
Maps track IDs to descriptive names and maintains parent-child hierarchy.

| Column | Type | Description |
|--------|------|-------------|
| trace_id | VARCHAR | Trace identifier |
| id | BIGINT | Unique track ID (matches `slice.track_id`) |
| name | VARCHAR | Track name (e.g., "Socket 1:TCP:10.0.0.1:8080") |
| parent_id | BIGINT | FK to parent track's ID (for hierarchy) |

**Track Name Format:**
- Socket tracks: `Socket {socket_id}:{protocol}:{hostname/IP}:{port}`
  - Example: `Socket 42:TCP:10.128.0.5:8080`
  - Example: `Socket 15:UDP:api.example.com:53`
- Sub-tracks: `Sends`, `Receives`, `Buffer Queue`
- Root tracks: `Network Packets`, `Network Syscalls`

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

**Note on Persist Timer Fields:** The `icsk_pending`, `icsk_timeout`, `rto_jiffies`, `backoff`, and `probe_count` fields are populated on TCP packet_enqueue events when a timer is pending (`icsk_pending > 0`). These fields help understand TCP persist timer behavior during zero-window conditions:
- `icsk_pending=3` indicates the persist (probe) timer is armed
- `icsk_timeout` shows when the timer will fire (compare with packet timestamp to calculate time remaining)
- `rto_jiffies` shows the current RTO value (persist timer uses this as base interval)
- `backoff` shows how many times the timer has doubled due to exponential backoff
- `probe_count` shows how many zero-window probes have been sent

**Note on RTO Timeout Events:** RTO (Retransmission Timeout) events fire when the TCP retransmit timer expires because an ACK wasn't received in time. The `retransmit_count` shows how many consecutive RTOs have occurred (1 = first timeout). The `backoff` shows the exponential backoff multiplier applied to the RTO. If `snd_wnd=0`, the RTO is handling a zero-window condition rather than packet loss, and `is_zero_window_probe` will be set to 1.

**Note on Retransmit Detection:** The `is_retransmit` field is only available on `TCP packet_enqueue` events, NOT on `TCP packet_send` events. This is because the retransmit flag (`TCPCB_RETRANS`) is read from the kernel's `tcp_skb_cb` control block, which is only accessible at the TCP layer probe point (`__tcp_transmit_skb`), not at the device layer (`net_dev_start_xmit`).

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

## Data Model

```
track (Root: "Network Packets")
└── track (Socket 1:TCP:10.0.0.1:8080, parent_id = root)
    ├── instant (TCP packet_enqueue, track_id = socket)
    │   └── instant_args (length=1460, seq=12345, flags="ACK")
    ├── instant (TCP packet_send, track_id = socket)
    │   └── instant_args (length=1460, seq=12345)
    └── instant (TCP packet_rcv_established, track_id = socket)
        └── instant_args (length=64, seq=67890)

track (Root: "Network Syscalls" per thread)
└── track (Socket 1:TCP:10.0.0.1:8080, parent_id = thread_group)
    ├── track (Sends, parent_id = socket)
    │   └── slice (tcp_send, track_id = sends, dur=12345)
    │       └── args (bytes=4096, sndbuf_used=8192, sndbuf_limit=65536, sndbuf_fill_pct=12)
    └── track (Receives, parent_id = socket)
        └── slice (tcp_recv, track_id = receives, dur=5678)
            └── args (bytes=2048)
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
       COUNT(DISTINCT CASE WHEN ptr.name LIKE 'Socket%' THEN ptr.name END) as sockets,
       COUNT(s.id) as events,
       SUM(CASE WHEN a.key = 'bytes' THEN a.int_value ELSE 0 END) / 1073741824.0 as total_gb
FROM slice s
JOIN thread t ON s.utid = t.utid AND s.trace_id = t.trace_id
JOIN process p ON t.upid = p.upid AND t.trace_id = p.trace_id
JOIN track tr ON s.track_id = tr.id AND s.trace_id = tr.trace_id
LEFT JOIN track ptr ON tr.parent_id = ptr.id AND tr.trace_id = ptr.trace_id
LEFT JOIN args a ON s.id = a.slice_id AND s.trace_id = a.trace_id AND a.key = 'bytes'
WHERE s.name IN ('tcp_send', 'tcp_recv')
GROUP BY p.name, p.pid
ORDER BY total_gb DESC
LIMIT 20;
```

### 3. Find Network Traffic for a Specific Thread
```sql
SELECT ptr.name as socket, s.name as event_type,
       COUNT(*) as events,
       SUM(CASE WHEN a.key = 'bytes' THEN a.int_value ELSE 0 END) / 1048576.0 as total_mb
FROM slice s
JOIN thread t ON s.utid = t.utid AND s.trace_id = t.trace_id
JOIN track tr ON s.track_id = tr.id AND s.trace_id = tr.trace_id
LEFT JOIN track ptr ON tr.parent_id = ptr.id AND tr.trace_id = ptr.trace_id
LEFT JOIN args a ON s.id = a.slice_id AND s.trace_id = a.trace_id AND a.key = 'bytes'
WHERE t.name = 'loco-run:0' AND s.name IN ('tcp_send', 'tcp_recv')
GROUP BY ptr.name, s.name
ORDER BY total_mb DESC;
```

### 4. Find All TCP Connections
```sql
SELECT DISTINCT name
FROM track
WHERE name LIKE 'Socket%TCP%';
```

### 5. Total Bytes Transferred Per Socket
```sql
SELECT parent.name as socket,
       SUM(a.int_value) / 1048576.0 as total_mb,
       COUNT(*) as events
FROM slice s
JOIN track t ON s.track_id = t.id AND s.trace_id = t.trace_id
JOIN track parent ON t.parent_id = parent.id AND t.trace_id = parent.trace_id
JOIN args a ON s.id = a.slice_id AND s.trace_id = a.trace_id AND a.key = 'bytes'
WHERE parent.name LIKE 'Socket%'
GROUP BY parent.name
ORDER BY total_mb DESC
LIMIT 20;
```

### 6. Analyze Send Buffer Pressure
Find sockets with high send buffer utilization:
```sql
SELECT parent.name as socket,
       AVG(a.int_value) as avg_fill_pct,
       MAX(a.int_value) as max_fill_pct,
       COUNT(*) as events
FROM slice s
JOIN track t ON s.track_id = t.id AND s.trace_id = t.trace_id
JOIN track parent ON t.parent_id = parent.id AND t.trace_id = parent.trace_id
JOIN args a ON s.id = a.slice_id AND s.trace_id = a.trace_id
WHERE a.key = 'sndbuf_fill_pct' AND parent.name LIKE 'Socket%'
GROUP BY parent.name
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
WHERE t.name = 'Socket 1:TCP:10.0.0.1:8080'
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
    SELECT t.name as socket, s.trace_id, AVG(a.int_value) as avg_fill_pct
    FROM slice s
    JOIN track t ON s.track_id = t.id AND s.trace_id = t.trace_id
    JOIN args a ON s.id = a.slice_id AND s.trace_id = a.trace_id
    WHERE a.key = 'sndbuf_fill_pct'
    GROUP BY t.name, s.trace_id
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
       t.name as socket,
       MAX(CASE WHEN a.key = 'bytes' THEN a.int_value END) as bytes_read,
       MAX(CASE WHEN a.key = 'recv_seq_start' THEN a.int_value END) as seq_start,
       MAX(CASE WHEN a.key = 'recv_seq_end' THEN a.int_value END) as seq_end,
       MAX(CASE WHEN a.key = 'rcv_nxt' THEN a.int_value END) as rcv_nxt,
       MAX(CASE WHEN a.key = 'bytes_available' THEN a.int_value END) as buffered_bytes
FROM slice s
JOIN track t ON s.track_id = t.id AND s.trace_id = t.trace_id
LEFT JOIN args a ON s.id = a.slice_id AND s.trace_id = a.trace_id
WHERE s.name = 'tcp_recv'
GROUP BY s.id, s.ts, s.dur, t.name
ORDER BY s.ts;
```

### 15. Identify Receive Bottlenecks
Find sockets where the kernel had more data buffered than the app consumed:
```sql
SELECT t.name as socket,
       COUNT(*) as recv_calls,
       AVG(CASE WHEN a_avail.int_value > a_bytes.int_value
           THEN a_avail.int_value - a_bytes.int_value ELSE 0 END) as avg_unconsumed_bytes,
       MAX(a_avail.int_value) as max_bytes_available
FROM slice s
JOIN track t ON s.track_id = t.id AND s.trace_id = t.trace_id
LEFT JOIN args a_bytes ON s.id = a_bytes.slice_id AND s.trace_id = a_bytes.trace_id
    AND a_bytes.key = 'bytes'
LEFT JOIN args a_avail ON s.id = a_avail.slice_id AND s.trace_id = a_avail.trace_id
    AND a_avail.key = 'bytes_available'
WHERE s.name = 'tcp_recv'
GROUP BY t.id, t.name
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
└── Socket {id}:{protocol}:{addr}:{port}
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
    └── UDP enqueue (instant)
```

**Syscall Events (per-thread, stored in `slice` table):**
```
Thread (from PID/TGID track descriptor)
└── Network Syscalls
    └── Socket {id}:{protocol}:{addr}:{port}
        ├── Sends
        │   └── tcp_send / udp_send (slice with duration)
        └── Receives
            └── tcp_recv (slice with duration)
```

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
WITH socket_destinations AS (
    SELECT DISTINCT
        trace_id,
        -- Extract IP from socket name like "Socket 1:TCP:10.0.0.5:8080"
        REGEXP_EXTRACT(name, 'Socket \d+:\w+:([^:]+):\d+', 1) as dest_ip
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
