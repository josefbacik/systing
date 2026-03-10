---
name: systing-trace
description: Capture a Linux system trace with systing. Use when the user wants to profile, trace, or record system activity (scheduling, stacks, network, syscalls, Python stacks, TPU ops/metrics) into a DuckDB or Perfetto file. Guides correct invocation of the `systing` binary as root, choosing recorders, targeting PIDs/cgroups/commands, and output formats.
---

# Capturing a trace with `systing`

`systing` is a BPF-based Linux tracer. It captures scheduling events, stack traces, network activity, syscalls, and more into a DuckDB database (or Perfetto trace) for later analysis.

## Prerequisites

- **Must run as root** (BPF requires privileges). Use `sudo`.
- Output: prefer `--output foo.duckdb` for analysis with the `systing-analyze` MCP server.

## Common invocations

### Trace a command from start to finish
```bash
sudo systing --output trace.duckdb -- python3 myscript.py
```
Everything after `--` is the command. Only the command, its threads, and children are traced.

### Trace an existing PID for N seconds
```bash
sudo systing -p <PID> -d 10 --output trace.duckdb
```

### Trace a cgroup
```bash
sudo systing -c /sys/fs/cgroup/my.slice -d 30 --output trace.duckdb
```

### System-wide trace (no PID/cgroup filter)
```bash
sudo systing -d 5 --output trace.duckdb
```

## Recorders (what to capture)

List available recorders:
```bash
systing --list-recorders
```

| Recorder | Default | Captures |
|---|---|---|
| `sched` | on | Scheduler events (context switches, runqueue) |
| `cpu-stacks` | on | On-CPU stack samples (perf) |
| `sleep-stacks` | on | Uninterruptible sleep (D-state) stacks |
| `interruptible-stacks` | on | Interruptible sleep (S-state) stacks |
| `syscalls` | off | All syscall entry/exit |
| `network` | off | TCP/UDP packets, syscalls, retransmits, RTT |
| `pystacks` | off | Python stack frames (CPython 3.8–3.13) |
| `markers` | off | Userspace marker events (via `faccessat2`) |
| `tpu` | off | TPU op-level profile via XLA runtime gRPC (port 8466) |
| `tpu-metrics` | off | TPU runtime metrics polling (port 8431, lightweight) |

Enable extras with `--add-recorder`:
```bash
sudo systing --add-recorder network --add-recorder syscalls -d 10 --output trace.duckdb
```

Or restrict to only specific recorders with `--only-recorder`:
```bash
sudo systing --only-recorder sched --only-recorder network -d 10 --output trace.duckdb
```

## Key options

| Flag | Purpose |
|---|---|
| `-p <PID>` | Target a specific process (repeatable) |
| `-c <CGROUP>` | Target a cgroup path |
| `-d <SEC>` | Duration in seconds (0 = until Ctrl-C or command exits) |
| `--output <PATH>` | Output file; `.duckdb` extension → DuckDB, `.pb`/`.perfetto` → Perfetto |
| `--output-dir <DIR>` | Directory for intermediate parquet files (default `./traces`) |
| `--collect-pystacks` | Enable Python stack tracing (shortcut for `--add-recorder pystacks`) |
| `--enable-debuginfod` | Better symbol resolution (requires `DEBUGINFOD_URLS` env var) |
| `--no-stack-traces` | Disable all stack trace collection |
| `--marker-threshold <N>` | Stop after N marker instant events |
| `--marker-duration-threshold <MS>` | Stop when any marker range exceeds MS milliseconds |
| `--ringbuf-size-mib <N>` | Increase BPF ring buffer size if seeing lost events |
| `--sw-event` | Use software event for sampling (for VMs without PMU) |
| `--tpu-profile` | Enable TPU op profiling (shortcut for `--add-recorder tpu`) |
| `--tpu-service-addr <HOST:PORT>` | Override auto-discovery for the TPU profiler service (port 8466) |
| `--tpu-metrics` | Enable TPU metrics polling (shortcut for `--add-recorder tpu-metrics`) |
| `--tpu-metrics-addr <HOST:PORT>` | Override auto-discovery for the TPU metrics service (port 8431) |
| `--tpu-metrics-interval <MS>` | Polling interval for TPU metrics (default 1000 ms) |

## TPU profiling

Systing can talk to the XLA/TPU runtime's gRPC services to correlate TPU activity with host-side scheduling and stacks in the same trace.

Two modes (use either or both):

- **`--tpu-profile`** — Full op-level profile. Connects to the XLA profiler service (port 8466), captures an XSpace profile for the trace duration, and records per-op timing, flops, and memory-bytes into `tpu_op` / `tpu_device` tables. Heavier; only available while a workload is actively running.
- **`--tpu-metrics`** — Lightweight polling. Connects to the RuntimeMetricService (port 8431), samples counters (duty cycle, HBM usage, latency distributions) at `--tpu-metrics-interval` into the `tpu_metric` table. Always available while the runtime is up.

**Auto-discovery**: By default systing scans `/proc/net/tcp` (across all network namespaces) for a single listener on the well-known port and connects to it, using `setns` if the service is in a container's netns. If discovery finds zero listeners it errors ("Is a TPU workload running?"); if it finds multiple you must disambiguate with `--tpu-service-addr` / `--tpu-metrics-addr`.

```bash
# Op-level TPU profile + host scheduling for 10s
sudo systing --tpu-profile -d 10 --output trace.duckdb

# Lightweight metrics at 500ms alongside network & sched
sudo systing --tpu-metrics --tpu-metrics-interval 500 \
    --add-recorder network -d 30 --output trace.duckdb

# Explicit address (container / multi-device host)
sudo systing --tpu-profile --tpu-service-addr 127.0.0.1:8466 -d 10 --output trace.duckdb
```

## Output formats

- **`.duckdb`** — Recommended. Queryable with `systing-analyze` CLI and MCP tools.
- **`.pb` / `.perfetto`** — Perfetto trace, viewable at [ui.perfetto.dev](https://ui.perfetto.dev).
- **`--parquet-only`** — Skip final output, keep raw parquet files in `--output-dir`.

## After capturing

Once you have a `.duckdb` file, use the **`systing-analyze` MCP tools** (if available) or the `systing-analyze` CLI to analyze it. See the `/systing-analyze` skill.

## Troubleshooting

- **"Operation not permitted"** → run with `sudo`.
- **Lost events / ring buffer full** → increase `--ringbuf-size-mib` (e.g. `64`).
- **No stack frames resolved** → add `--enable-debuginfod` with `DEBUGINFOD_URLS` set, or install debug symbols for the target binaries.
- **VM without hardware perf counters** → add `--sw-event`.
- **"No TPU profiler/metrics service detected"** → the XLA runtime isn't listening on 8466/8431. Make sure a TPU workload is running. If it's in a non-host netns systing will find it automatically; if there are multiple listeners, pass `--tpu-service-addr` / `--tpu-metrics-addr`.
