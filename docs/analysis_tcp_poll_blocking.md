# TCP Poll Blocking Analysis

This document summarizes an investigation into TCP send blocking behavior in a Tokio-based application (fabulous), using the new `poll_ready` tracking feature in systing.

## Overview

The investigation aimed to understand why `send_chunk` operations in the fabulous TCP backend sometimes take several seconds to complete. Using systing's new socket poll tracking, we were able to correlate epoll behavior with TCP send/recv operations to identify the root cause.

## Tools and Features Used

### New poll_ready Event

A new `poll_ready` instant event was added to systing that captures when `tcp_poll` is called. This hooks the kernel's `tcp_poll` function which is called whenever epoll/poll/select checks a TCP socket's readiness.

**Event annotations:**
- `socket_id` - Unique socket identifier for correlation
- `socket` - Human-readable socket info (e.g., "Socket 47:TCP:254.139.55.91:55272")
- `requested` - Poll events requested (e.g., "IN|OUT|ERR|HUP|RDHUP")
- `returned` - Poll events that occurred (e.g., "IN|OUT")

### Trace Analyzed

- **File:** `/root/traces/io-1118-tcp-4d4r/trace-gke-tpu-df210be8-db1f.pb.gz`
- **Converted to DuckDB:** `/tmp/trace.duckdb` (610.3 MB, 26M events)

## Analysis Steps

### Step 1: Identify Polling Behavior

Initial observation: Thread 2482156 was seen polling many sockets without doing any actual I/O.

**Query: What sockets is thread 2482156 polling?**
```sql
WITH poll_activity AS (
    SELECT MAX(CASE WHEN a.key = 'socket' THEN a.string_value END) as socket
    FROM instant i
    JOIN thread t ON i.utid = t.utid AND i.trace_id = t.trace_id
    LEFT JOIN instant_args a ON i.id = a.instant_id AND i.trace_id = a.trace_id
    WHERE i.name = 'poll_ready'
      AND t.tid = 2482156
      AND i.ts >= 780126255741565
      AND i.ts <= 780134565219557
    GROUP BY i.id
)
SELECT
    REGEXP_EXTRACT(socket, 'TCP:([^:]+):', 1) as dest_ip,
    COUNT(DISTINCT socket) as socket_count,
    COUNT(*) as total_polls
FROM poll_activity
GROUP BY REGEXP_EXTRACT(socket, 'TCP:([^:]+):', 1)
ORDER BY total_polls DESC;
```

**Result:** Thread 2482156 polled 69 unique sockets (12,660 poll events) to two main destinations:
- 254.139.55.91 - 32 sockets, 6,705 polls
- 254.149.43.144 - 32 sockets, 5,950 polls

### Step 2: Understand Tokio Work-Stealing Pattern

**Query: Who else is operating on these sockets?**
```sql
-- Combines poll_ready and tcp_send/tcp_recv events for sockets 38 and 77
SELECT tid, thread_name, socket_id, event_type, COUNT(*) as event_count
FROM (
    SELECT t.tid, t.name as thread_name,
           MAX(CASE WHEN a.key = 'socket_id' THEN a.int_value END) as socket_id,
           'poll_ready' as event_type
    FROM instant i
    JOIN thread t ON i.utid = t.utid ...
    UNION ALL
    SELECT t.tid, t.name as thread_name,
           MAX(CASE WHEN a.key = 'socket_id' THEN a.int_value END) as socket_id,
           s.name as event_type
    FROM slice s
    JOIN thread t ON s.utid = t.utid ...
)
GROUP BY tid, thread_name, socket_id, event_type;
```

**Result (in 2ms window):**
| TID | Thread | Socket | Event | Count |
|-----|--------|--------|-------|-------|
| 2482156 | tokio-runtime-w | Socket 38 | poll_ready | 48 |
| 2482467 | tokio-runtime-w | Socket 38 | tcp_recv | 8 |
| 2482156 | tokio-runtime-w | Socket 77 | poll_ready | 43 |
| 2482401 | tokio-runtime-w | Socket 77 | tcp_recv | 9 |

**Finding:** Thread 2482156 acts as the epoll I/O driver, detecting ready sockets. Other worker threads (2482467, 2482401) execute the actual recv operations. This is Tokio's work-stealing pattern - any worker can drive the I/O reactor when idle.

### Step 3: Find Long-Duration Blocking

**Query: Find large gaps between tcp_send events on the same socket**
```sql
WITH sends AS (
    SELECT s.ts, s.dur, t.tid,
           MAX(CASE WHEN a.key = 'socket_id' THEN a.int_value END) as socket_id,
           MAX(CASE WHEN a.key = 'socket' THEN a.string_value END) as socket,
           LAG(s.ts + s.dur) OVER (PARTITION BY socket_id ORDER BY s.ts) as prev_end
    FROM slice s
    JOIN thread t ON s.utid = t.utid ...
    WHERE s.name = 'tcp_send'
    GROUP BY s.id, s.ts, s.dur, t.tid
)
SELECT ts, socket, (ts - prev_end) / 1e6 as gap_ms
FROM sends
WHERE (socket LIKE '%254.139.55.91%' OR socket LIKE '%254.149.43.144%')
  AND (ts - prev_end) > 100000000  -- gaps > 100ms
ORDER BY (ts - prev_end) DESC;
```

**Result:** Found 13+ second gaps between tcp_send events:
| Socket | Gap (seconds) |
|--------|---------------|
| Socket 47:TCP:254.139.55.91:55272 | 13.54 |
| Socket 49:TCP:254.139.55.91:55274 | 13.50 |
| Socket 52:TCP:254.139.55.91:55286 | 13.46 |
| ... (30 sockets with 13+ second gaps) | ... |

### Step 4: Correlate Blocking with Poll Activity

**Query: What happened on Socket 47 during the 13.5 second gap?**
```sql
-- All events on Socket 47 during the gap period
SELECT ts/1e9 as time_sec, event, dur/1e6 as dur_ms, info
FROM (
    SELECT ts, 'poll_ready' as event, NULL as dur, returned as info ...
    UNION ALL
    SELECT ts, 'tcp_send' as event, dur, bytes as info ...
    UNION ALL
    SELECT ts, 'tcp_recv' as event, dur, bytes as info ...
)
WHERE socket_id = 47
  AND ts BETWEEN 780190403000000 AND 780204000000000
ORDER BY ts;
```

**Result:**
| Time (sec) | Event | Info |
|------------|-------|------|
| 780190.402 | tcp_send | 3948568 bytes |
| 780190.771 | poll_ready | IN\|OUT |
| 780190.771 | tcp_recv | 24 bytes |
| 780190.771 | tcp_recv | 114948 bytes |
| ... (burst of activity) | ... | ... |
| 780190.772 | tcp_recv | 313684 bytes |
| **13.17 seconds of silence** | | |
| 780203.945 | tcp_send | 3948568 bytes |

### Step 5: Verify Epoll Was Still Active

**Query: Were there poll events on OTHER sockets during the silence?**
```sql
SELECT COUNT(*) as total_polls, COUNT(DISTINCT socket_id) as unique_sockets
FROM instant i
WHERE i.name = 'poll_ready'
  AND i.ts BETWEEN 780190773000000 AND 780203945000000;
```

**Result:** 133,340 poll events on 355 different sockets during the 13 seconds that Socket 47 was silent. The epoll driver was actively running, but Socket 47 was not being returned as ready.

## Root Cause

The `send_chunk` blocking is caused by TCP send buffer exhaustion:

1. **Application sends large chunk** (3.9MB) via `write_vectored`
2. **Send buffer fills up** (70-95% full after send)
3. **Next write attempt blocks** - socket not writable
4. **Task yields to Tokio runtime** - registers interest with epoll for write readiness
5. **Epoll driver polls other sockets** - 133k events on 355 other sockets
6. **Remote receiver is slow to ACK** - 13+ seconds pass
7. **Buffer drains, socket becomes writable** - epoll returns Socket 47 as ready
8. **Task wakes up, send resumes**

The blocking is NOT visible as a long `tcp_send` syscall (longest was 40ms). It's the **gap between syscalls** while the task is yielded waiting for the socket to become writable.

## Architectural Context

### Fabulous TCP Backend

Located in `/root/src/anthropic/fabulous/src/tcp/tokio_backend.rs`:

```rust
// Two separate Tokio runtimes for send/recv
static SEND_RUNTIME: LazyLock<Runtime> = LazyLock::new(create_runtime);
static RECV_RUNTIME: LazyLock<Runtime> = LazyLock::new(create_runtime);

fn create_runtime() -> Runtime {
    Builder::new_multi_thread()
        .enable_io()    // Enables epoll-based I/O
        .enable_time()
        .build()
}
```

### send_chunk Function (lines 325-414)

```rust
async fn send_chunk(...) {
    loop {
        // This yields to epoll when buffer is full
        let result = poll_fn(|cx| writer.poll_write_vectored(cx, &bufs)).await;

        if iter_elapsed.as_millis() > 900 {
            // Logs TCP_INFO, send queue sizes
        }

        if total_elapsed.as_secs() > 3 {
            // Logs comprehensive TCP diagnostics
        }
    }
}
```

### Work-Stealing Pattern

```
┌─────────────────────────────────────────────────────────────┐
│                    Tokio Runtime                             │
├─────────────────────────────────────────────────────────────┤
│  Thread A (I/O Driver)     │  Thread B, C, D (Workers)      │
│  ─────────────────────     │  ─────────────────────────     │
│  epoll_wait() on 64 fds    │  Execute send_chunk tasks      │
│  Detects: socket 38 ready  │  write_vectored() blocks       │
│  Wakes task for socket 38  │  Task yields, re-registers     │
│  Detects: socket 77 ready  │  with epoll                    │
│  ...                       │  ...                           │
└─────────────────────────────────────────────────────────────┘
```

## Key Findings

1. **Poll tracking reveals I/O driver behavior** - The new `poll_ready` events show which thread is running epoll and which sockets are being monitored.

2. **Tokio work-stealing is working as designed** - Different threads handle polling vs actual I/O operations.

3. **13+ second blocking is receiver-induced** - The remote endpoint (254.139.55.91) was slow to ACK data, causing send buffer exhaustion.

4. **Blocking is between syscalls, not during them** - The gap between `tcp_send` events shows the blocking period, not the syscall duration.

5. **Multiple sockets affected simultaneously** - 30+ sockets to the same destinations experienced similar 13-second blocking, suggesting a systemic receiver-side issue.

## Useful Queries

### Find threads doing the most polling
```sql
SELECT t.tid, t.name, COUNT(*) as poll_count
FROM instant i
JOIN thread t ON i.utid = t.utid AND i.trace_id = t.trace_id
WHERE i.name = 'poll_ready'
GROUP BY t.tid, t.name
ORDER BY poll_count DESC
LIMIT 15;
```

### Find sockets with longest send gaps
```sql
WITH sends AS (
    SELECT s.ts,
           MAX(CASE WHEN a.key = 'socket' THEN a.string_value END) as socket,
           LAG(s.ts + s.dur) OVER (PARTITION BY
               MAX(CASE WHEN a.key = 'socket_id' THEN a.int_value END)
               ORDER BY s.ts) as prev_end
    FROM slice s
    LEFT JOIN args a ON s.id = a.slice_id AND s.trace_id = a.trace_id
    WHERE s.name = 'tcp_send'
    GROUP BY s.id, s.ts, s.dur
)
SELECT socket, MAX((ts - prev_end) / 1e9) as max_gap_seconds
FROM sends
WHERE prev_end IS NOT NULL
GROUP BY socket
ORDER BY max_gap_seconds DESC
LIMIT 20;
```

### Correlate poll events with subsequent I/O
```sql
WITH poll_events AS (
    SELECT i.ts, i.utid,
           MAX(CASE WHEN a.key = 'socket_id' THEN a.int_value END) as socket_id
    FROM instant i
    LEFT JOIN instant_args a ON i.id = a.instant_id
    WHERE i.name = 'poll_ready'
    GROUP BY i.id, i.ts, i.utid
),
recv_events AS (
    SELECT s.ts, s.utid,
           MAX(CASE WHEN a.key = 'socket_id' THEN a.int_value END) as socket_id,
           MAX(CASE WHEN a.key = 'bytes' THEN a.int_value END) as bytes
    FROM slice s
    LEFT JOIN args a ON s.id = a.slice_id
    WHERE s.name = 'tcp_recv'
    GROUP BY s.id, s.ts, s.utid
)
SELECT p.socket_id,
       AVG((r.ts - p.ts) / 1e6) as avg_poll_to_recv_ms
FROM poll_events p
JOIN recv_events r ON p.socket_id = r.socket_id
    AND r.ts > p.ts
    AND r.ts < p.ts + 1000000  -- within 1ms
GROUP BY p.socket_id;
```
