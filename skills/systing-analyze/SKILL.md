---
name: systing-analyze
description: Analyze a systing trace database (.duckdb). Use when the user asks about a systing trace — flamegraphs, scheduling latency, CPU hotspots, network behavior, memory/allocation activity, off-CPU time, TPU op/metric data, or any question about what's in a trace.duckdb file. Orchestrates the systing-analyze MCP tools (trace_info, query, flamegraph, sched_stats, cpu_stats, sched_aggregate, network_*).
---

# Analyzing systing traces

Systing stores traces in **DuckDB**. The `systing-analyze` MCP server exposes structured tools to query them. This skill tells you which tool to reach for and how the data is laid out.

## Recommended workflow

1. **`trace_info`** — Always start here. Pass the `path` to the `.duckdb` file. Returns trace IDs, time range, per-trace system/platform info (kernel, arch, hypervisor, cpufreq driver, sampling event/period), non-empty tables with row counts, and the top 25 processes by thread count. This also caches the DB so later calls can omit `path`.
2. **`list_tables`** / **`describe_table`** — Discover schema for ad-hoc queries.
3. **High-level tools** for common questions — see below.
4. **`query`** — For anything the high-level tools don't cover, write SQL. Results cap at 10k rows (`truncated: true` when hit); use `LIMIT`/`OFFSET` for more. The DB is opened read-only.

## Tool cheatsheet

| Question | Tool | Notes |
|---|---|---|
| What's in this trace? | `trace_info` | First call; pass `path` |
| Where is CPU time going? | `flamegraph` | `stack_type="cpu"` (default); optionally `pid`/`tid` |
| Why is the process blocked / off-CPU? | `flamegraph` | `stack_type="uninterruptible-sleep"` (D) or `"interruptible-sleep"` (S), or `"all-sleep"` |
| Is the scheduler oversubscribed? Latency? | `sched_stats` | no filter = whole-trace ranking; `pid` = per-thread breakdown; `tid` = single thread with end-state distribution |
| Which CPUs are busy / idle? | `cpu_stats` | per-CPU utilization, idle%, IRQ/softIRQ time, runqueue depth p50/p90/p99 |
| How does the scheduler behave overall? Compare two schedulers/hosts? | `sched_aggregate` | one summary per capture: wakeup latency (ran on previous CPU / migrated), preempt wait, slice length, switch + migration rates, migrate-event counts, time-weighted runqueue length, per-CPU load vectors (incl. placement) + imbalance metrics, log2 histograms, tail threads; percentiles within ~6%; per-CPU runqueue exact on traces with `sched_migrate` (`meta.placement_exact`), approximate before |
| What's the network doing? | `network_connections` | per-connection bytes, retransmit % |
| Interface-level network? | `network_interfaces` | per-interface, per-protocol breakdown |
| Both sides of a connection (multi-node)? | `network_socket_pairs` | matched socket pairs, within or across traces |
| Memory / allocations? | `query` | no dedicated tool — see memory schema below |
| What ran on the TPU? Duty cycle? HBM? | `query` | no dedicated tool — see TPU schema below |
| Anything else | `query` | raw SQL; see schema below |

There is also a CLI with the same analyses: `systing-analyze query|stacktrace flamegraph|sched stats|sched cpu-stats|sched aggregate|network connections|network interfaces|network socket-pairs` (and `systing-analyze mcp` to start this server).

## Key schema for `query`

### Timestamps
All `ts` columns are **nanoseconds** from an arbitrary epoch. Convert durations: `dur / 1e6` → ms, `dur / 1e9` → sec.

### Thread / process identity
- `utid` / `upid` are **internal** IDs (dense, unique within DB).
- Join to `thread` (utid → tid, name, upid) and `process` (upid → pid, name) for the Linux IDs.

### Stack traces
Two representations exist:

**Interned (the normal one)** — `stack_sample` → `stack` → `frame`:
- `stack_sample(ts, utid, cpu, stack_id, stack_event_type)`. `stack_event_type`: `0` = uninterruptible sleep, `1` = CPU, `2` = interruptible sleep.
- `stack(id, frame_ids BIGINT[], depth, leaf_name)`. **`frame_ids` is root-to-leaf** (outermost caller first, innermost executing frame last); `leaf_name` is the last frame's name.
- `frame(id, name)` — interned strings, dense per-trace ids.
- Join on **both** `trace_id` and the id: `JOIN stack s ON s.trace_id = ss.trace_id AND s.id = ss.stack_id`.
- The `stack_frames` **view** reconstructs a `frame_names VARCHAR[]` column (root-to-leaf) for ad-hoc queries — convenient but slower than joining `frame` directly.

```sql
-- Top 10 hottest leaf functions (on-CPU samples) — leaf_name avoids any join
SELECT leaf_name, count(*) AS samples
FROM stack_sample ss
JOIN stack s ON s.trace_id = ss.trace_id AND s.id = ss.stack_id
WHERE ss.stack_event_type = 1  -- 1=cpu, 0=uninterruptible, 2=interruptible
GROUP BY 1 ORDER BY 2 DESC LIMIT 10;

-- Samples containing a given frame anywhere in the stack
SELECT count(*)
FROM stack_sample ss
JOIN stack_frames sf ON sf.trace_id = ss.trace_id AND sf.id = ss.stack_id
WHERE list_contains(sf.frame_names, 'do_futex_wait');
```

**Normalized (Perfetto-style)** — `perf_sample` → `stack_profile_callsite` (parent-child tree) → `stack_profile_frame` → `stack_profile_symbol` / `stack_profile_mapping`. Use when you need mapping/build-id info. Walk the `parent_id` chain to reconstruct stacks.

### Sample weighting
`sysinfo.sample_event` / `sysinfo.sample_period` say what one CPU sample represents: `sample_period` **cycles** for `cpu-cycles` (so sample density tracks cycles consumed, not wall time — use `sched_slice` for time, and `cpu_info` min/max/base frequencies in kHz to convert), or `sample_period` **nanoseconds** for `cpu-clock`. NULL/absent in traces from systing < 1.9 (adaptive frequency mode, nominally 1000 Hz).

### Scheduling
`sched_slice(ts, dur, cpu, utid, end_state, priority)`: one row per scheduled slice.
- `end_state` is a **bitmask of the task state at slice end**, not an enum, and there is **no `end_state_str` column**:
  - `NULL` → preempted (still runnable)
  - `& 1` → interruptible sleep (S)
  - `& 2` → uninterruptible sleep (D)
  - `& 4` stopped, `& 8` traced, `& 16` exit/dead, `& 32` exit/zombie
  - Test bits (`end_state & 2 != 0`), don't compare for equality — compound states occur.

Related: `thread_state(ts, dur, utid, state, cpu)` (a `state = 0` row is a runnable marker; its `cpu` is the CPU the thread last ran on, recorded before the scheduler picked one), `wakeup_new`, `sched_migrate(ts, utid, orig_cpu, dest_cpu)` (schema ≥ 16: every change of a task's CPU — placement away from the previous CPU at wakeup, or a balancer/affinity move of a runnable task; a woken thread with no row before its next slice ran on its previous CPU), `process_exit`, `irq_slice(irq, name, ret)`, `softirq_slice(vec)`.

```sql
-- Longest uninterruptible-sleep episodes
SELECT t.name, ss.dur/1e6 AS ms, ss.ts
FROM sched_slice ss JOIN thread t ON t.trace_id = ss.trace_id AND t.utid = ss.utid
WHERE ss.end_state & 2 != 0
ORDER BY ss.dur DESC LIMIT 20;
```

### Network
- `network_syscall` — sendmsg/recvmsg: `ts`, `dur`, `utid`, `event_type` (`sendmsg`/`recvmsg`), `socket_id`, `bytes`, send-buffer fill (`sndbuf_used/limit/fill_pct`), recv-side (`recv_seq_start/end`, `rcv_nxt`, `bytes_available`).
- `network_packet` — packet-level: `seq`, `length`, `tcp_flags`, `is_retransmit`, `retransmit_count`, `rto_ms`, `srtt_ms`, windows (`snd_wnd`, `rcv_wnd`, zero-window probes), qdisc (`qlen`, `qdisc_backlog`, `qdisc_latency_us`), drops (`drop_reason`, `drop_reason_str`), TCP state changes (`old_state_str`, `new_state_str`).
- `network_socket` — socket metadata: `socket_id`, `netns_inum`, `protocol`, `address_family`, src/dest IP:port, first/last seen ts.
- `network_poll` — poll/epoll/select events per socket.
- `network_interface` — local interface metadata (namespace, name, IPs, `netns_inum`).
- `network_dns` — IP→hostname, only when the trace was captured with `--resolve-addresses`.
- Join syscall/packet → socket on `socket_id` (plus `trace_id`).

```sql
-- Retransmits by connection
SELECT s.src_ip, s.src_port, s.dest_ip, s.dest_port,
       count(*) FILTER (WHERE p.is_retransmit) AS retransmits,
       count(*) AS total_packets
FROM network_packet p
JOIN network_socket s ON s.trace_id = p.trace_id AND s.socket_id = p.socket_id
GROUP BY 1,2,3,4 HAVING retransmits > 0
ORDER BY retransmits DESC;
```

### Memory
From the `memory` / `memory-alloc` recorders. `stack_id` columns join to `stack.id` like sample stacks.

- `memory_rss(ts, utid, member, size, external)` — RSS tracking. `member`: `0`=file, `1`=anon, `2`=swap, `3`=shmem, `-1`=hiwater_rss, `-2`=total_vm, `-3`=maj_flt, `-4`=thrashing_count, `-5`=thrashing_delay_ns (negatives are synthetic periodic samples). Units vary by member: `size` is bytes for `0..3`/`-1`/`-2`, a cumulative fault count for `-3`, a stall count for `-4`, and nanoseconds for `-5` — never aggregate across members. `external` is true when the update came from an external reclaimer (kswapd, direct reclaim by another process) rather than the process itself; `-4`/`-5` rows appear only on delayacct-enabled hosts (zero-valued rows there mean "no thrash").
- `memory_map(ts, utid, event_type, addr, size, prot, flags, stack_id)` — mmap/munmap/brk.
- `memory_fault(ts, utid, addr, error_code, stack_id)` — user page faults (sampled 1-in-N, default 97).
- `memory_alloc(ts, utid, op, addr, size, old_addr, stack_id)` — malloc/calloc/realloc/free uprobes.

```sql
-- Anon RSS over time for the biggest process
SELECT p.name, r.ts, r.size
FROM memory_rss r
JOIN thread t ON t.trace_id = r.trace_id AND t.utid = r.utid
JOIN process p ON p.trace_id = t.trace_id AND p.upid = t.upid
WHERE r.member = 1 ORDER BY r.ts;

-- Allocation hotspots by stack leaf
SELECT s.leaf_name, count(*) AS allocs, sum(a.size) AS bytes
FROM memory_alloc a
JOIN stack s ON s.trace_id = a.trace_id AND s.id = a.stack_id
WHERE a.op = 'malloc'
GROUP BY 1 ORDER BY bytes DESC LIMIT 20;
```

### Counters and slices
`counter(ts, track_id, value)` + `counter_track(id, name, unit)` for perf counters and CPU frequency; `slice`/`track`/`args` and `instant`/`instant_args` for custom trace events and markers.

### TPU
No dedicated MCP tool — use `query`. Three tables:

- **`tpu_device`** — one row per TPU core. `id` (join key), `device_ordinal`, `chip_id`, `core_id`, `hostname`, `device_type`, `topology_{x,y,z}`, `clock_rate_ghz`, `hbm_size_bytes`, `hbm_bandwidth_gbps`.
- **`tpu_op`** — XLA op execution slices (from `--tpu-profile`). `ts`, `dur` (ns), `tpu_device_id` (FK → `tpu_device.id`), `op_name`, `category`, `stream`, `group_id`, `flops`, `bytes_accessed`, `bytes_hbm`, `bytes_cmem`, `bytes_vmem`.
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

-- Correlate TPU gaps with host-side blocking: intervals with no TPU op
-- running for >1ms; check sched_slice for what the host thread was doing
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
Every table has a `trace_id` column. Always include it in joins, and filter on it when the DB contains multiple captures (`_traces` lists them, with the systing version that produced each).

## Using `flamegraph`

Returns `stacks` (array of `{frames, count}`), `metadata` (total_samples, matched_samples, unique_stacks, time_range, stack_type), and `folded` — folded-stack text (semicolon-separated frames root→leaf, space, count) for inferno / brendangregg's FlameGraph. `total_samples` is the whole trace; `matched_samples` and `unique_stacks` count what passed the filters BEFORE the `top_n` cut, so you can tell how much was cut. Parameters:
- `stack_type` — `"cpu"` (default), `"interruptible-sleep"`, `"uninterruptible-sleep"`, `"all-sleep"`, `"all"`
- `pid` / `tid` — restrict to a process or thread
- `start_time` / `end_time` — seconds offset from trace start
- `min_count` — minimum sample count per stack (default 1)
- `top_n` — keep the top N stacks (default 500); the cut happens inside the database, so large traces stay cheap
- `max_depth` — truncate every stack to its D root-most frames before merging (stacks that only differ deeper than D count as one); default full depth
- `trace_id` — for multi-trace DBs

## Common investigation patterns

**"Why is my process slow?"**
1. `sched_stats` with `pid` — is it on-CPU (CPU-bound), or mostly sleeping (blocked)? Note `d_sleep_seconds` is approximate: it folds in runqueue latency after the sleep.
2. If CPU-bound → `flamegraph stack_type="cpu" pid=<pid>` for hotspots.
3. If blocked → `flamegraph stack_type="uninterruptible-sleep" pid=<pid>` (I/O, locks) and `"interruptible-sleep"` (waits, timers).

**"Is the machine overloaded?"**
1. `cpu_stats` — CPUs with near-zero idle % and high runqueue depth percentiles. (Runqueue estimates model sleep→wake→run cycles only, exclude preempted threads, and are event-weighted, not time-weighted.)
2. `sched_stats` (no filter) — preemption rates and CPU migrations.

**"Network slow / dropping?"**
1. `network_connections` — any connection with a high retransmit rate?
2. `query` on `network_packet` — `drop_reason_str IS NOT NULL` for kernel drop reasons; `qdisc_latency_us` for queueing.
3. `query` on `network_syscall` — sort by `dur` for stalled recv/send, and check `sndbuf_fill_pct` / `bytes_available`.

**"Memory growing?"**
1. `query` on `memory_rss` — anon (`member=1`) trend per process.
2. `query` on `memory_map` — large mmaps grouped by `stack_id` → `stack.leaf_name`.
3. `query` on `memory_alloc` — allocation hotspots. Only trust alloc/free pairing if the trace used `--memory-alloc-sample-rate 1`.

**"TPU underutilized?"**
1. `query` on `tpu_metric` — `tensorcore.dutycycle.percent`; sustained low values mean the device is starved.
2. `query` on `tpu_op` — large gaps between consecutive ops on the same device (see gap query above).
3. Cross-reference gap timestamps with `sched_slice` / `flamegraph` on the host to find what the feeding process was doing (sleeping? blocked on recv? GIL?).

## Arguments

If the user passed a path as an argument to this skill (`$ARGUMENTS`), use it as the `path` parameter in your first `trace_info` call.
