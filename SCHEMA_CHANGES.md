# Schema Changes

This file tracks changes to the systing DuckDB database schema. Each entry
corresponds to a `SCHEMA_VERSION` increment in `src/duckdb.rs`.

When making schema changes:
- Increment `SCHEMA_VERSION` in `src/duckdb.rs`
- Add an entry here describing the change
- Bump the **minor** version in `Cargo.toml` (e.g., 1.0.0 → 1.1.0)

---

## Schema Version 1 (systing 1.0.0) — 2026-02-23

Initial schema baseline.

### Metadata tables
- `_traces` — Trace provenance (trace_id, source_path, import_time, systing_version)
- `_schema_version` — Database schema version

### Data tables
- `process` — Process metadata (upid, pid, name, parent_upid, cmdline, is_kernel_thread)
- `thread` — Thread metadata (utid, tid, name, upid)
- `sched_slice` — Scheduler events (ts, dur, cpu, utid, end_state, priority)
- `thread_state` — Thread state spans (ts, dur, utid, state, cpu)
- `irq_slice` — Hardware IRQ events
- `softirq_slice` — Software IRQ events
- `wakeup_new` — New process wakeup events
- `process_exit` — Process exit events
- `counter_track` — Counter track metadata
- `counter` — Counter values over time
- `slice` — Duration events (slices)
- `track` — Track metadata
- `args` — Slice arguments
- `instant` — Instant (point) events
- `instant_args` — Instant event arguments
- `stack_profile_symbol` — Stack symbols (legacy Perfetto format)
- `stack_profile_mapping` — Stack mappings (legacy Perfetto format)
- `stack_profile_frame` — Stack frames (legacy Perfetto format)
- `stack_profile_callsite` — Stack callsites (legacy Perfetto format)
- `perf_sample` — Perf samples (legacy Perfetto format)
- `stack` — Query-friendly stacks (frame_names[], depth, leaf_name)
- `stack_sample` — Stack samples (ts, utid, cpu, stack_id, stack_event_type)
- `network_interface` — Network interface metadata
- `socket_connection` — Socket connection metadata
- `network_syscall` — Network syscall events
- `network_packet` — Network packet events
- `network_socket` — Network socket metadata
- `network_poll` — Network poll events
- `clock_snapshot` — Clock snapshot data
- `sysinfo` — System information (sysname, release, version, machine)

## Schema Version 2 (systing 1.1.0) — 2026-02-26

Added TPU profiling tables for capturing XLA/TPU runtime profiling data.

### New tables
- `tpu_device` — TPU device metadata and topology (device_ordinal, chip_id, core_id, hostname, device_type, topology coordinates, clock rate, HBM size/bandwidth)
- `tpu_op` — Per-HLO-operation execution events (ts, dur, tpu_device_id, step_id, op_name, category, stream, flops, bytes_accessed, bytes per memory type)
- `tpu_step` — Training step boundaries with timing breakdowns (dur_compute, dur_infeed, dur_outfeed, dur_allreduce, dur_send, dur_recv, dur_idle, dur_megacore_sync). **Note: Removed in schema version 4 — never populated.**
- `tpu_counter` — TPU hardware performance counter samples (mxu_utilization, vector_alu_utilization, scalar_alu_utilization, xlu_utilization, hbm_bandwidth_utilization, ici_bandwidth_utilization). **Note: Removed in schema version 4 — never populated.**

## Schema Version 3 (systing 1.2.0) — 2026-02-26

Added lightweight TPU runtime metrics table for polling data from RuntimeMetricService (port 8431).

### New tables
- `tpu_metric` — TPU runtime metric samples in normalized name/value format (ts, device_id, metric_name, value). Adapts automatically to any metrics the RuntimeMetricService exposes.

## Schema Version 4 (systing 1.3.0) — 2026-03-02

Cleanup of unused TPU tables and rename of `tpu_op.step_id`.

### Removed tables
- `tpu_step` — never populated (XSpace step parsing was not implemented)
- `tpu_counter` — never populated (XSpace hardware counter extraction was not implemented)

### Changed columns
- `tpu_op.step_id` → `tpu_op.group_id` — Now stores the raw XSpace `group_id` (training step identifier) directly. Previously this was always NULL due to a remapping bug.

## Schema Version 5 (systing 1.4.0) — 2026-04-03

Added DNS resolution lookup table for network traces.

### New tables
- `network_dns` — Maps IP addresses to resolved hostnames (ip_address, hostname). Populated at the end of recording when `--resolve-addresses` is enabled. Can be joined with `network_socket.src_ip` or `network_socket.dest_ip` for hostname lookups.

## Schema Version 6 (systing 1.5.0) — 2026-04-09

Added memory-usage tables for the new `memory` recorder (enable with `--add-recorder memory`).

### New tables
- `memory_rss` — Per-process resident-set counter samples (ts, utid, member, size). `member` indexes the kernel rss_stat counters: 0=file, 1=anon, 2=swap, 3=shmem. Synthetic members -1=hiwater_rss and -2=total_vm are emitted from periodic mm_struct snapshots.
- `memory_map` — Virtual address-space changes (id, ts, utid, event_type, addr, size, prot, flags, stack_id). `event_type` is `mmap`, `munmap`, or `brk`. For `brk`, `addr` is the new program break and `size` is the signed delta in bytes (negative on shrink). `stack_id` joins to `stack` for allocation-site attribution.
- `memory_fault` — Sampled user page faults (ts, utid, addr, error_code, stack_id). Sampling rate is controlled by `--memory-fault-sample-rate`.
- `memory_alloc` — Heap allocator calls via libc uprobes (id, ts, utid, op, addr, size, old_addr, stack_id). `op` is one of `malloc`, `calloc`, `realloc`, `aligned_alloc`, `posix_memalign`, `free`. For `free`, `size` is 0 and `stack_id` is NULL. When `--memory-alloc-sample-rate` > 1, alloc and free are sampled independently, so addr-based pairing is unreliable. For `realloc`, `old_addr` is the input pointer (implicitly freed when `addr != old_addr`). Enable with `--add-recorder memory-alloc`; sampling rate via `--memory-alloc-sample-rate`.

All four memory tables key on `utid` (joins to `thread.utid`); for process attribution join through `thread.upid -> process.upid`.

## Schema Version 7 (systing 1.6.0) — 2026-04-14

Switched network per-thread tables to key on `utid`, matching `sched_slice`/`stack_sample`/`memory_*`.

### Changed columns
- `network_syscall`: dropped `tid INTEGER, pid INTEGER`; added `utid BIGINT` (joins `thread.utid`).
- `network_poll`: dropped `tid INTEGER, pid INTEGER`; added `utid BIGINT` (joins `thread.utid`).

For process attribution join through `network_*.utid -> thread.utid -> thread.upid -> process.upid`.

---

## Schema Version 8 (systing 1.7.0) — 2026-05-21

Record each process's cgroup so short-lived processes can still be attributed to a
cgroup even when they exit before their `/proc` entry can be read. The numeric
cgroup id is captured in-kernel at event time (BPF `task_info`), and resolved to a
path by walking the live cgroup v2 hierarchy when the trace is written.

### Added columns
- `process`: added `cgroup_id UBIGINT NOT NULL DEFAULT 0` — the cgroup directory's
  kernfs node id (its inode) in the v2 unified hierarchy. `0` means unknown.
- `process`: added `cgroup_path VARCHAR` — best-effort path of that cgroup relative
  to the cgroup root (e.g. `/system.slice/foo.service`); `NULL` if it could not be
  resolved (e.g. the cgroup was removed before the trace was written). Resolution is
  racy and reflects the hierarchy at write time; because kernfs inode numbers can be
  reused, a removed-and-replaced id may resolve to a different cgroup's path. Trust
  `cgroup_id`; treat `cgroup_path` as a hint.

Older databases without these columns import cleanly: `cgroup_id` falls back to its
`0` default and `cgroup_path` to `NULL`.

## Schema Version 9 (systing 1.8.0) — 2026-06-02

Record platform provenance in the `sysinfo` table so a trace identifies what kind
of machine it was captured on — in particular whether CPU-frequency data could
exist at all (VM guests have no cpufreq driver, so `--cpu-frequency` is now
skipped there) and whether the host was virtualized.

### Added columns
- `sysinfo`: added `cpufreq_driver VARCHAR` — the kernel's cpufreq scaling driver
  (e.g. `intel_pstate`, `acpi-cpufreq`); `NULL` when the system has no cpufreq
  support, in which case CPU-frequency counter tracks are absent.
- `sysinfo`: added `hypervisor VARCHAR` — the hypervisor the trace was captured
  under, detected via the CPUID hypervisor bit and vendor signature on x86_64
  (e.g. `kvm`, `xen`, `hyper-v`, `vmware`); `NULL` on bare metal.
- `sysinfo`: added `sys_vendor VARCHAR` — DMI system vendor (e.g. `Amazon EC2`),
  `NULL` if DMI is not exposed.
- `sysinfo`: added `product_name VARCHAR` — DMI product name (e.g.
  `m7i.16xlarge`), `NULL` if DMI is not exposed.

Older parquet directories without these columns import cleanly: both the
record-time import (`src/duckdb.rs`) and `systing-util convert` (which
previously used positional inserts and would have failed on any added column,
including v8's `process` columns) now use `INSERT ... BY NAME`, which fills
missing columns with `NULL`.

---

## Schema Version 10 (systing 1.9.0) — 2026-06-04

Stack sampling moved from the kernel's adaptive frequency mode (nominal 1000 Hz
on cpu-cycles) to fixed-period mode: the frequency estimator shrinks the period
toward its floor while a CPU idles, then floods samples the moment the CPU
wakes, oversampling wakeup paths on mostly-idle CPUs. With a fixed period each
CPU stack sample represents an exact, constant amount of execution — but
interpreting it requires knowing the period, and converting cycles to time
requires CPU frequency data, so both are now recorded.

### Added columns
- `sysinfo`: added `sample_event VARCHAR` — the perf event that drove CPU stack
  sampling: `cpu-cycles` (hardware) or `cpu-clock` (software fallback, used
  with `--sw-event` or when the PMU is unavailable, e.g. most VMs). `NULL` in
  traces recorded by systing < 1.9.
- `sysinfo`: added `sample_period BIGINT` — the sampling period in event units:
  each `stack_sample` row with `stack_event_type = 1` represents
  `sample_period` cycles (`cpu-cycles`) or nanoseconds (`cpu-clock`) of
  execution. The period is chosen at startup so sampling runs at ~1000 Hz at
  the fastest CPU's maximum frequency. `NULL` in traces from systing < 1.9.

### Added tables
- `cpu_info` — per-CPU static frequency limits from sysfs cpufreq, in kHz:
  `cpu INTEGER`, `min_freq_khz BIGINT`, `max_freq_khz BIGINT`,
  `base_freq_khz BIGINT` (sustained non-turbo frequency; only exposed by some
  drivers, e.g. intel_pstate). One row per CPU with cpufreq data; empty on
  systems without cpufreq support (typical for VM guests). With cycles-based
  sampling these bound the cycles-to-time conversion per CPU; with a fixed
  period, effective frequency is also derivable directly from the trace as
  `sample_period / Δts` between consecutive samples on a continuously-busy CPU.

## Schema Version 11 (systing 1.10.0) — 2026-06-17

Stack frame strings are now interned. DuckDB cannot compress strings inside
list columns, so the previous `stack.frame_names VARCHAR[]` column was stored
raw and routinely accounted for over half the database. Frames are now stored
once each in a new `frame` table and referenced by integer id, cutting the
stack-table footprint by roughly 5–6x. Parquet output is unchanged
(`stack.parquet` still carries `frame_names`; ZSTD already deduplicates the
strings there) — the normalization happens at DuckDB import time.

### Added tables
- `frame` — interned stack-frame strings: `id BIGINT`, `name VARCHAR`. Ids are
  dense, zero-based, and scoped per `trace_id`.

### Changed columns
- `stack`: `frame_names VARCHAR[]` is replaced by `frame_ids BIGINT[]`, indexing
  into `frame` on `(trace_id, id)`. `depth`, `leaf_name`, and the leaf-to-root
  ordering are unchanged.

### Added views
- `stack_frames` — backward-compat view exposing the pre-v11 `stack` columns
  (`trace_id, id, frame_names, depth, leaf_name`). Ad-hoc queries can use it as
  a drop-in replacement; for hot paths join `frame` directly, since the view
  re-aggregates names per row.
