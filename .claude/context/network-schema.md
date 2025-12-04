# Network Event Schema in systing-analyze

This document describes how network events are stored in DuckDB after conversion from Perfetto traces.

## Overview

Network events are tracked through four related tables:
- **`track`** - Track metadata including socket connection info
- **`slice`** - Network events (tcp_send, tcp_recv, packet events, etc.)
- **`args`** - Debug annotations containing event details (bytes, seq numbers, buffer info)
- **`network_interface`** - Local network interface metadata (for cross-trace correlation)

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
Individual network events. Each event has a track_id linking to the track table and optionally a utid for direct thread correlation.

| Column | Type | Description |
|--------|------|-------------|
| trace_id | VARCHAR | Trace identifier |
| id | BIGINT | Unique slice ID (for joining with args) |
| ts | BIGINT | Timestamp in nanoseconds |
| dur | BIGINT | Duration (0 for instant events) |
| track_id | BIGINT | FK to `track.id` |
| utid | BIGINT | FK to `thread.utid` (direct thread link, NULL for packet events) |
| name | VARCHAR | Event type (see Event Types below) |
| category | VARCHAR | Event category (usually NULL) |
| depth | INTEGER | Nesting depth (always 0) |

**Note:** The `utid` column enables direct correlation between network syscall events and threads/processes without traversing the track hierarchy. For syscall events (tcp_send, tcp_recv, etc.), utid links directly to the thread that performed the syscall.

**Event Types:**
- Syscall events: `tcp_send`, `tcp_recv`, `udp_send`
- Packet events: `TCP packet_enqueue`, `TCP packet_send`, `TCP packet_rcv_established`, `TCP packet_queue_rcv`, `TCP buffer_queue`
- UDP packet events: `UDP send`, `UDP receive`, `UDP enqueue`

### `args`
Debug annotations containing event details. Multiple args can exist per slice.

| Column | Type | Description |
|--------|------|-------------|
| trace_id | VARCHAR | Trace identifier |
| slice_id | BIGINT | FK to `slice.id` |
| key | VARCHAR | Annotation name |
| int_value | BIGINT | Integer value (most common) |
| string_value | VARCHAR | String value (e.g., TCP flags) |
| real_value | DOUBLE | Floating point value |

**Available Annotation Keys:**

| Key | Type | Events | Description |
|-----|------|--------|-------------|
| `bytes` | int | tcp_send, tcp_recv, udp_send | Bytes transferred |
| `seq` | int | TCP events | TCP sequence number |
| `length` | int | Packet events | Packet length in bytes |
| `flags` | string | TCP packets | TCP flags (e.g., "SYN\|ACK") |
| `sndbuf_used` | int | TCP events | Current send buffer usage (sk_wmem_queued) |
| `sndbuf_limit` | int | TCP events | Max send buffer size (sk_sndbuf) |
| `sndbuf_fill_pct` | int | TCP events | Buffer fill percentage (used/limit * 100) |

### `network_interface`
Local network interface metadata captured at trace start. Used for cross-trace correlation to identify which machine a trace came from and match destination IPs to source machines.

| Column | Type | Description |
|--------|------|-------------|
| trace_id | VARCHAR | Trace identifier |
| interface_name | VARCHAR | Interface name (e.g., "eth0", "lo", "docker0") |
| ip_address | VARCHAR | IP address assigned to the interface |
| address_type | VARCHAR | Address type: "ipv4" or "ipv6" |

**Example Data:**
```
trace_id | interface_name | ip_address              | address_type
---------+----------------+-------------------------+-------------
trace_a  | eth0           | 10.128.0.5              | ipv4
trace_a  | eth0           | fe80::d40c:ff:feb8:f7f1 | ipv6
trace_a  | lo             | 127.0.0.1               | ipv4
trace_a  | lo             | ::1                     | ipv6
trace_b  | eth0           | 10.128.0.10             | ipv4
```

## Data Model

```
track (Root: "Network Packets")
└── track (Socket 1:TCP:10.0.0.1:8080, parent_id = root)
    ├── slice (TCP packet_enqueue, track_id = socket)
    │   └── args (length=1460, seq=12345, flags="ACK")
    ├── slice (TCP packet_send, track_id = socket)
    │   └── args (length=1460, seq=12345)
    └── slice (TCP packet_rcv_established, track_id = socket)
        └── args (length=64, seq=67890)

track (Root: "Network Syscalls" per thread)
└── track (Socket 1:TCP:10.0.0.1:8080, parent_id = thread_group)
    ├── track (Sends, parent_id = socket)
    │   └── slice (tcp_send, track_id = sends)
    │       └── args (bytes=4096, sndbuf_used=8192, sndbuf_limit=65536, sndbuf_fill_pct=12)
    └── track (Receives, parent_id = socket)
        └── slice (tcp_recv, track_id = receives)
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
SELECT s.ts, s.name as event,
       MAX(CASE WHEN a.key = 'seq' THEN a.int_value END) as seq,
       MAX(CASE WHEN a.key = 'length' THEN a.int_value END) as length,
       MAX(CASE WHEN a.key = 'flags' THEN a.string_value END) as flags
FROM slice s
JOIN track t ON s.track_id = t.id AND s.trace_id = t.trace_id
LEFT JOIN args a ON s.id = a.slice_id AND s.trace_id = a.trace_id
WHERE t.name = 'Socket 1:TCP:10.0.0.1:8080'
GROUP BY s.id, s.ts, s.name
ORDER BY s.ts
LIMIT 100;
```

### 8. Find High-Volume Connections
Connections with most packet events:
```sql
SELECT t.name as socket,
       COUNT(*) as packet_events,
       SUM(CASE WHEN a.key = 'length' THEN a.int_value ELSE 0 END) / 1048576.0 as total_mb
FROM slice s
JOIN track t ON s.track_id = t.id AND s.trace_id = t.trace_id
LEFT JOIN args a ON s.id = a.slice_id AND s.trace_id = a.trace_id AND a.key = 'length'
WHERE s.name LIKE 'TCP packet%' AND t.name LIKE 'Socket%'
GROUP BY t.name
ORDER BY packet_events DESC
LIMIT 20;
```

## Track Hierarchy

Network tracks are organized hierarchically:

**Packet Events (global, not per-thread):**
```
Network Packets (root)
└── Socket {id}:{protocol}:{addr}:{port}
    ├── TCP packet_enqueue events
    ├── TCP packet_send events
    ├── TCP packet_rcv_established events
    └── TCP packet_queue_rcv events
```

**Syscall Events (per-thread):**
```
Thread (from PID/TGID track descriptor)
└── Network Syscalls
    └── Socket {id}:{protocol}:{addr}:{port}
        ├── Sends
        │   └── tcp_send / udp_send events
        ├── Receives
        │   └── tcp_recv events
        └── Buffer Queue
            └── TCP buffer_queue / UDP enqueue events
```

## Notes

### Send Buffer Metrics
- `sndbuf_used`: Bytes currently queued in send buffer (sk_wmem_queued)
- `sndbuf_limit`: Maximum send buffer size (sk_sndbuf)
- `sndbuf_fill_pct`: Percentage of buffer used (can exceed 100% temporarily)

High `sndbuf_fill_pct` values indicate potential backpressure - the application is sending faster than the network can transmit.

### TCP Flags Format
TCP flags are stored as pipe-separated strings: `SYN|ACK`, `FIN|ACK`, `PSH|ACK`, etc.

Available flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR

### Socket ID
The socket ID in track names is a unique identifier assigned by the BPF tracer during tracing. It's consistent within a single trace but not across traces.

## Cross-Trace Correlation

When analyzing traces from multiple machines, use the `network_interface` table to identify which machine each trace came from and correlate network connections.

### List All Interfaces Across Traces
```sql
SELECT trace_id, interface_name, ip_address, address_type
FROM network_interface
WHERE address_type = 'ipv4' AND interface_name != 'lo'
ORDER BY trace_id, interface_name;
```

### Find Which Trace Has a Specific IP
```sql
SELECT trace_id, interface_name
FROM network_interface
WHERE ip_address = '10.128.0.5';
```

### Correlate Sockets to Source Machines
Find which machine (trace) owns the IP that appears in another trace's socket connections:
```sql
SELECT
    ni.trace_id as source_trace,
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

### Build a Connection Map Between Nodes
```sql
-- For each trace, find which other traces it communicated with
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
    sd.dest_ip
FROM socket_destinations sd
JOIN network_interface ni ON sd.dest_ip = ni.ip_address
WHERE sd.trace_id != ni.trace_id
  AND ni.address_type = 'ipv4';
```
