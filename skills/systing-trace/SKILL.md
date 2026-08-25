---
name: systing-trace
description: Capture a Linux system trace with systing. Use when the user wants to profile, trace, or record system activity (scheduling, stacks, network, memory, syscalls, Python stacks, TPU ops/metrics) into a DuckDB or Perfetto file. Guides correct invocation of the `systing` binary as root, choosing recorders, targeting PIDs/cgroups/commands, and output formats.
---

# Capturing a trace with `systing`

`systing` is a BPF-based Linux tracer. It captures scheduling events, IRQs, stack traces, network activity, memory events, syscalls, and more into a DuckDB database (or Perfetto trace) for later analysis.

## Prerequisites

- **Must run as root**, or hold `CAP_BPF` + `CAP_PERFMON` (`CAP_SYS_ADMIN` also works). Use `sudo`.
- Output: prefer `--output foo.duckdb` for analysis with the `systing-analyze` MCP server. **The default is `trace.pb`** (Perfetto), so always pass `--output` explicitly when you want DuckDB.

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

`-d 0` (the default) means "run until Ctrl-C, or until the `--` command exits".

## Recorders (what to capture)

List available recorders and their defaults:
```bash
systing --list-recorders
```

| Recorder | Default | Captures |
|---|---|---|
| `sched` | on | Scheduler events (context switches, wakeups, runqueue) |
| `irq` | on | IRQ and softirq events (`irq_handler_*`, `softirq_*`) |
| `cpu-stacks` | on | On-CPU perf stack samples |
| `sleep-stacks` | on | Uninterruptible sleep (D-state) stacks |
| `interruptible-stacks` | on | Interruptible sleep (S-state) stacks |
| `syscalls` | off | All syscall entry/exit (`raw_syscalls:sys_enter`/`sys_exit`) |
| `network` | off | Base network recorder: socket/TCP connection state tracking |
| `network-syscalls` | off | Network syscall-level tracing (send/recv bytes, buffer fill, stalls) — no per-packet probes |
| `network-packets` | off | Packet-level tracing (sendmsg, recvmsg, qdisc, drops, retransmits, RTT) |
| `memory` | off | RSS tracking, mmap/munmap/brk, page faults |
| `memory-alloc` | off | Heap allocator uprobes (malloc/calloc/realloc/free) with stacks |
| `markers` | off | Userspace marker events (`faccessat2` with `mode=-975`) |
| `tpu` | off | TPU op-level profile via XLA runtime gRPC (port 8466) |
| `tpu-metrics` | off | TPU runtime metrics polling (port 8431, lightweight) |

Enable extras with `--add-recorder`:
```bash
sudo systing --add-recorder network --add-recorder syscalls -d 10 --output trace.duckdb
```

Or restrict to only specific recorders with `--only-recorder` (disables every default first):
```bash
sudo systing --only-recorder sched --only-recorder network -d 10 --output trace.duckdb
```

### Recorder dependencies and companions

- `--add-recorder network` **also enables `network-packets`** (the common investigation shape). `--only-recorder network` is state-only: connection/state tracking with no per-packet kprobes.
- `network-packets` and `network-syscalls` each require the base `network` recorder and enable it implicitly.
- `memory-alloc` requires and implicitly enables `memory`.
- Recorders that are on by default can also be turned off directly: `--no-sched`, `--no-irq`, `--no-cpu-stack-traces`, `--no-sleep-stack-traces`, `--no-interruptible-stack-traces`, `-n`/`--no-stack-traces` (all stacks).

## Key options

### Targeting and duration
| Flag | Purpose |
|---|---|
| `-p, --pid <PID>` | Target a specific process (repeatable) |
| `-c, --cgroup <CGROUP>` | Target a cgroup path |
| `-d, --duration <SEC>` | Duration in seconds (default `0` = until Ctrl-C or command exits) |
| `--continuous <SEC>` | Rolling-window mode: keep only the last `<SEC>` seconds in the ring buffers. Cannot be combined with a `-- <command>` |
| `-v, --verbose` | Increase verbosity (repeatable) |

### Output
| Flag | Purpose |
|---|---|
| `--output <PATH>` | Output file, format from extension: `.duckdb`, `.pb`/`.perfetto`, `.systing`/`.systing.gz` (profile export, see `docs/PROFILE_EXPORT_FORMAT.md`). Default `trace.pb` |
| `--output-dir <DIR>` | Directory for intermediate parquet files (default `./traces`) |
| `--parquet-only` | Skip final trace generation, keep only the parquet files |
| `--stream <URI>` | Stream parquet over a socket instead of writing to disk: `vsock://CID:PORT`, `unix:///path.sock`, `tcp://host:port` (tcp is unauthenticated — trusted networks only) |

### Sampling and counters
| Flag | Purpose |
|---|---|
| `--sample-freq <HZ>` | CPU stack-sampling rate per CPU (default 1000). Fixed-period mode: exact with `--sw-event`, and the rate at max CPU frequency for `cpu-cycles` |
| `-s, --sw-event` | Use a software clock event for sampling (VMs without a PMU) |
| `--perf-counter <NAME>` | Sample a hardware/software counter, e.g. `instructions`, `cycles`, `topdown*` (repeatable) |
| `--cpu-frequency` | Record CPU frequency tracks |

### Symbolization
| Flag | Purpose |
|---|---|
| `--collect-pystacks` | Resolve Python frames in user stacks |
| `--pystacks-debug` | Debug output for Python stack tracing |
| `--enable-debuginfod` | Better symbol resolution (requires `DEBUGINFOD_URLS`) |
| `--collect-build-id` | Store user frames as (build-id, file offset) so exited processes stay symbolizable offline |
| `--symbolize-names-only` | ELF symbol tables only — no DWARF, no line info, no inline frames. Bounds symbolization memory on hosts with many debug binaries |
| `--symbolize-elide-generics` | Collapse generic/template args in symbol names longer than 256 bytes |
| `--no-frame-labels` | Render unsymbolized frames as bare hex instead of contextual labels |
| `--no-gopclntab` | Don't symbolize stripped Go binaries from `.gopclntab` |
| `--no-gvisor-guest-maps` | Don't query gVisor sandboxes' control sockets for guest maps |

### Memory recorder tuning
| Flag | Purpose |
|---|---|
| `--memory-fault-sample-rate <N>` | Sample 1 in N user page faults (default 97; 0/1 = all) |
| `--memory-rss-threshold-bytes <N>` | Min byte drift between `rss_stat` events (default `max(16 MiB, 64*nr_cpus*page_size)`; 0 = every event) |
| `--memory-alloc-sample-rate <N>` | Sample 1 in N allocator calls (default 1). Values > 1 sample alloc/free independently, so alloc/free pairing for leak detection is unreliable — hotspot profiling only |
| `--memory-alloc-lib <LIB>` | Override allocator library. Absolute path = host namespace verbatim; bare name resolved per-pid via `/proc/<pid>/maps` |
| `--memory-alloc-symbol-prefix <P>` | Prefix for malloc/free symbol names (e.g. `je_` for prefixed jemalloc) |

### Custom events, markers, misc
| Flag | Purpose |
|---|---|
| `--trace-event <EVENT>` / `--trace-event-pid <PID>` | Attach to additional probe points |
| `--trace-event-config <FILE>` | JSON config defining custom events/tracks/stop triggers (see `docs/TRACE_CONFIG_FORMAT.md`) |
| `--marker-threshold <N>` | Stop after N marker instant events — **requires `--continuous`** |
| `--marker-duration-threshold <MS>` | Stop when a marker range exceeds MS ms — **requires `--continuous`** |
| `--ringbuf-size-mib <N>` | Increase BPF ring buffer size if events are lost |
| `--ringbuf-shards <N>` | Rings per ring-buffer family: `0` (default) = one per CPU up to 64 at a constant family byte budget, except on kernels before 6.8, which keep 8; `8` restores the fixed eight-ring layout exactly |
| `--resolve-addresses` | Resolve network IPs to hostnames via DNS (off by default) |

### TPU
| Flag | Purpose |
|---|---|
| `--tpu-profile` | Op-level TPU profile (same as `--add-recorder tpu`); **requires a fixed `--duration`** |
| `--tpu-service-addr <HOST:PORT>` | Override auto-discovery for the profiler service (port 8466) |
| `--tpu-metrics` | Metrics polling (same as `--add-recorder tpu-metrics`) |
| `--tpu-metrics-addr <HOST:PORT>` | Override auto-discovery for the metrics service (port 8431) |
| `--tpu-metrics-interval <MS>` | Metrics polling interval (default 1000 ms) |

## TPU profiling

Systing can talk to the XLA/TPU runtime's gRPC services to correlate TPU activity with host-side scheduling and stacks in the same trace.

Two modes (use either or both):

- **`--tpu-profile`** — Full op-level profile. Connects to the XLA profiler service (port 8466), captures an XSpace profile for the trace duration, and records per-op timing, flops, and memory bytes into `tpu_op` / `tpu_device`. Heavier; only available while a workload is actively running, and requires a fixed `--duration`.
- **`--tpu-metrics`** — Lightweight polling. Connects to the RuntimeMetricService (port 8431), samples counters (duty cycle, HBM usage, latency distributions) at `--tpu-metrics-interval` into `tpu_metric`. Always available while the runtime is up.

**Auto-discovery**: By default systing scans `/proc/net/tcp` (across all network namespaces) for a single listener on the well-known port and connects to it, using `setns` if the service is in a container's netns. Zero listeners → error ("Is a TPU workload running?"); multiple listeners → disambiguate with `--tpu-service-addr` / `--tpu-metrics-addr`.

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

- **`.duckdb`** — Recommended. Queryable with the `systing-analyze` CLI and MCP tools.
- **`.pb` / `.perfetto`** — Perfetto trace, viewable at [ui.perfetto.dev](https://ui.perfetto.dev). This is the default if `--output` is omitted.
- **`.systing` / `.systing.gz`** — Line-oriented profile summary (interned stacks + counts + thread metadata), no DuckDB needed. See `docs/PROFILE_EXPORT_FORMAT.md`.
- **`--parquet-only`** — Skip final output, keep raw parquet files in `--output-dir`.

## After capturing

Once you have a `.duckdb` file, use the **`systing-analyze` MCP tools** (if available) or the `systing-analyze` CLI to analyze it. See the `systing-analyze` skill.

## Troubleshooting

- **"Operation not permitted"** → run with `sudo` (or grant `CAP_BPF`+`CAP_PERFMON`).
- **Lost events / ring buffer full** → increase `--ringbuf-size-mib` (e.g. `64`).
- **No stack frames resolved** → add `--enable-debuginfod` with `DEBUGINFOD_URLS` set, or install debug symbols for the target binaries.
- **Symbolization eating memory** (CI hosts, many debug binaries) → `--symbolize-names-only`, and `--symbolize-elide-generics` for heavily generic Rust/C++.
- **VM without hardware perf counters** → add `-s`/`--sw-event`.
- **`--marker-threshold` rejected** → marker thresholds require `--continuous <seconds>`.
- **"No TPU profiler/metrics service detected"** → the XLA runtime isn't listening on 8466/8431. Make sure a TPU workload is running. If it's in a non-host netns systing will find it automatically; with multiple listeners, pass `--tpu-service-addr` / `--tpu-metrics-addr`.
