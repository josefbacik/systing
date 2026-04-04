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
