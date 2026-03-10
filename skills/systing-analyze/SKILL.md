---
name: systing-analyze
description: Analyze a systing trace database (.duckdb). Use when the user asks about a systing trace — flamegraphs, scheduling latency, CPU hotspots, network behavior, off-CPU time, TPU op/metric data, or any question about what's in a trace.duckdb file. Orchestrates the systing-analyze MCP tools (trace_info, query, flamegraph, sched_stats, cpu_stats, network_*).
---

# Analyzing systing traces

Systing stores traces in **DuckDB**. The `systing-analyze` MCP server exposes structured tools to query them. This skill tells you which tool to reach for and how the data is laid out.

## Recommended workflow

1. **`trace_info`** — Always start here. Pass the `path` to the `.duckdb` file. Returns trace IDs, time range, available tables/row counts, and top processes. This also caches the DB so later calls can omit `path`.
2. **`list_tables`** / **`describe_table`** — Discover schema for ad-hoc queries.
3. **High-level tools** for common questions — see below.
4. **`query`** — For anything the high-level tools don't cover, write SQL. Results cap at 10k rows; use `LIMIT`/`OFFSET` for more.

## Tool cheatsheet

| Question | Tool | Notes |
|---|---|---|
| What's in this trace? | `trace_info` | First call; pass `path` |
| Where is CPU time going? | `flamegraph` | filter `stack_type=cpu`; optionally filter by `pid` or `tid` |
| Why is the process blocked / off-CPU? | `flamegraph` | filter `stack_type=uninterruptible` (D-state) or `interruptible` (S-state) |
| Is the scheduler oversubscribed? Latency? | `sched_stats` | no filter = whole-trace; `pid` = per-thread breakdown; `tid` = single thread |
| Which CPUs are busy / idle? | `cpu_stats` | per-CPU utilization, IRQ time, runqueue depth |
| What's the network doing? | `network_connections` | per-connection bytes, retransmit rate |
| Interface-level network? | `network_interfaces` | per-interface, per-protocol breakdown |
| Both sides of a connection (multi-node)? | `network_socket_pairs` | matched socket pairs across traces |
| What ran on the TPU? Duty cycle? HBM? | `query` | no dedicated tool yet — see TPU schema below |
| Anything else | `query` | raw SQL; see schema below |

## Key schema for `query`

### Timestamps
All `ts` columns are **nanoseconds** from an arbitrary epoch. Convert durations: `dur / 1e6` → ms, `dur / 1e9` → sec.

### Thread / process identity
- `utid` / `upid` are **internal** IDs (dense, unique within DB).
- Join to `thread` (utid → tid, name, upid) and `process` (upid → pid, name) for the Linux IDs.

### Stack traces
Two representations exist:

**Flattened (easier)** — `stack` table: one row per sampled stack with `frame_names` as an array (leaf-to-root order). Joins to `stack_sample` on `stack_id`.
```sql
-- Top 10 hottest leaf functions (on-CPU samples)
SELECT frame_names[1] AS leaf, count(*) AS samples
FROM stack_sample JOIN stack USING (stack_id)
WHERE stack_event_type = 1  -- 1=cpu, 0=uninterruptible, 2=interruptible
GROUP BY 1 ORDER BY 2 DESC LIMIT 10;
```

**Normalized (Perfetto-style)** — `perf_sample` → `stack_profile_callsite` (parent-child tree) → `stack_profile_frame` → `stack_profile_symbol`. Use when you need mapping/build-id info. Walk the `parent_id` chain to reconstruct stacks.

### Scheduling
`sched_slice`: one row per scheduled slice.
- `ts`, `dur` — nanoseconds
- `utid`, `cpu`
- `end_state`: `1`=S (interruptible sleep), `2`=D (uninterruptible sleep), others = preempted/running
- `end_state_str` — human-readable state string

```sql
-- Longest uninterruptible-sleep episodes
SELECT t.name, ss.dur/1e6 AS ms, ss.ts
FROM sched_slice ss JOIN thread t USING (utid)
WHERE end_state = 2
ORDER BY dur DESC LIMIT 20;
```

### Network
- `network_syscall` — sendmsg/recvmsg calls: `ts`, `dur`, `tid`, `pid`, `event_type`, `socket_id`, `bytes`, buffer usage.
- `network_packet` — packet-level: `seq`, `length`, `is_retransmit`, `srtt_ms`, `drop_reason_str`, `tcp_flags`.
- `network_socket` — socket metadata: `socket_id`, `protocol`, src/dest IP:port.
- Join syscall/packet → socket on `socket_id`.

```sql
-- Retransmits by connection
SELECT s.src_ip, s.src_port, s.dest_ip, s.dest_port,
       count(*) FILTER (WHERE p.is_retransmit) AS retransmits,
       count(*) AS total_packets
FROM network_packet p JOIN network_socket s USING (socket_id)
GROUP BY 1,2,3,4 HAVING retransmits > 0
ORDER BY retransmits DESC;
```

### TPU
No dedicated MCP tool yet — use `query`. Three tables:

- **`tpu_device`** — one row per TPU core. `id` (join key), `device_ordinal`, `chip_id`, `core_id`, `hostname`, `device_type`, `topology_{x,y,z}`, `clock_rate_ghz`, `hbm_size_bytes`, `hbm_bandwidth_gbps`.
- **`tpu_op`** — XLA op execution slices (from `--tpu-profile`). `ts`, `dur` (ns), `tpu_device_id` (FK → tpu_device.id), `op_name`, `category`, `stream`, `group_id`, `flops`, `bytes_accessed`, `bytes_hbm`, `bytes_cmem`, `bytes_vmem`.
- **`tpu_metric`** — polled runtime counters (from `--tpu-metrics`). `ts`, `device_id` (ordinal), `metric_name`, `value`. Default metrics: `tpu.runtime.tensorcore.dutycycle.percent`, `tpu.runtime.hbm.memory.usage.bytes`.

```sql
-- Top 20 TPU ops by total device time
SELECT op_name, category,
       count(*)              AS calls,
       sum(dur)/1e6          AS total_ms,
       avg(dur)/1e3          AS avg_us,
       sum(flops)            AS total_flops,
       sum(bytes_hbm)        AS total_hbm_bytes
FROM tpu_op
GROUP BY 1,2 ORDER BY total_ms DESC LIMIT 20;

-- TPU utilization (duty cycle) over time, per device
SELECT device_id, ts, value AS dutycycle_pct
FROM tpu_metric
WHERE metric_name = 'tpu.runtime.tensorcore.dutycycle.percent'
ORDER BY device_id, ts;

-- Correlate TPU gaps with host-side blocking: find intervals where no TPU op
-- is running for >1ms and check sched_slice for what the host thread was doing
WITH gaps AS (
  SELECT ts + dur AS gap_start,
         lead(ts) OVER (PARTITION BY tpu_device_id ORDER BY ts) AS gap_end
  FROM tpu_op
)
SELECT gap_start, (gap_end - gap_start)/1e6 AS gap_ms
FROM gaps
WHERE gap_end - gap_start > 1000000  -- >1ms
ORDER BY gap_ms DESC LIMIT 20;
```

### Multi-trace databases
Tables have a `trace_id` column. Filter on it when the DB contains multiple captures.

## Using `flamegraph`

The `flamegraph` tool returns folded-stack output (one line per unique stack, semicolon-separated frames root→leaf, space, sample count). Filter options:
- `stack_type` — `cpu` / `uninterruptible` / `interruptible` / `all`
- `pid` / `tid` — restrict to a process or thread
- `min_samples` — drop noise
- `trace_id` — for multi-trace DBs

Pipe the result into your preferred flamegraph renderer, or just scan for the heaviest stacks in the text.

## Common investigation patterns

**"Why is my process slow?"**
1. `sched_stats` with `pid` — is it on-CPU (CPU-bound), or mostly sleeping (blocked)?
2. If CPU-bound → `flamegraph stack_type=cpu pid=<pid>` for hotspots.
3. If blocked → `flamegraph stack_type=uninterruptible pid=<pid>` (I/O, locks) and `stack_type=interruptible` (waits, timers).

**"Is the machine overloaded?"**
1. `cpu_stats` — look for CPUs with near-zero idle % and high runqueue depth percentiles.
2. `sched_stats` (no filter) — check preemption rates and CPU migrations.

**"Network slow / dropping?"**
1. `network_connections` — any connection with high retransmit rate?
2. `query` on `network_packet` — filter `drop_reason_str IS NOT NULL` for kernel drop reasons.
3. `query` on `network_syscall` — sort by `dur` to find stalled recv/send calls.

**"TPU underutilized?"**
1. `query` on `tpu_metric` — look at `tensorcore.dutycycle.percent`; sustained low values mean the device is starved.
2. `query` on `tpu_op` — find large gaps between consecutive ops on the same device (see gap query above).
3. Cross-reference gap timestamps with `sched_slice` / `flamegraph` on the host to find what the feeding process was doing (sleeping? blocked on recv? GIL?).

## Arguments

If the user passed a path as an argument to this skill (`$ARGUMENTS`), use it as the `path` parameter in your first `trace_info` call.
