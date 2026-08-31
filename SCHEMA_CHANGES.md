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
- `memory_map` — Virtual address-space changes (id, ts, utid, event_type, addr, size, prot, flags, stack_id). `event_type` is `mmap`, `munmap`, or `brk`. For `brk`, `addr` is the new program break and `size` is the signed delta in bytes (negative on shrink). `stack_id` joins to `stack` for allocation-site attribution. For `munmap`, `size` is the requested unmap length bounded by the process's total mapped size at call time: the kernel removes whatever is mapped in the requested range and succeeds even where nothing is mapped, so an oversized request (common for sparse address spaces such as gVisor sentries) is bounded by the process's mapped size — no munmap can remove more than the process has mapped — rather than recorded as the raw length. This is an upper bound, not the exact amount freed, and it remains a VA-range figure, not resident/physical bytes. When `--memory-map-sample-rate` > 1 each of the three event types is sampled 1:N independently: address-based pairing of a specific mmap with its own munmap is unreliable (both, one, or neither may be recorded), and byte or count aggregates represent 1/N of actual activity and must be scaled by the configured rate — which is a capture-time setting, not carried in the trace, so a consumer that needs absolute figures reads the rate from the recorder's configuration. The default 1 records every event.
- `memory_fault` — Sampled user page faults (ts, utid, addr, error_code, stack_id). Sampling rate is controlled by `--memory-fault-sample-rate`. `error_code` is the x86 page-fault error code (present / write / user / reserved-bit / instruction-fetch bits) and is x86-only: on every other architecture the leg is a perf software event that carries no fault kind (systing 1.13.13+, see `sysinfo.memory_fault_leg`), so `error_code` is 0 there. 0 is an unambiguous sentinel because a user-mode fault on x86 always has the user bit (`X86_PF_USER`, 0x4) set.
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

## Schema Version 12 (systing 1.11.0) — 2026-07-09

Stack frame ordering is now uniform. Recorded stacks are a concatenation of
three segments — python, user, kernel — and through v11 the segments disagreed
on direction: the BPF unwinder's user and kernel segments were reversed to
root-to-leaf at capture, while the python segment kept pystacks' leaf-first
buffer order. `leaf_name` took the first entry of the combined array, which is
the python leaf when python frames are present but the ROOT frame for
native-only stacks. (The v11 entry's claim that ordering was "leaf-to-root"
described the reader's assumption, not the data: native segments have been
root-to-leaf since capture-time reversal was introduced.)

No table shapes change. The version bump marks the data-semantics change so
tools can distinguish uniformly-ordered databases.

### Changed semantics
- `stack.frame_ids` (and `frame_names` in parquet / the `stack_frames` view):
  the python segment is now stored root-to-leaf like the user and kernel
  segments, making the whole array one coherent root-to-leaf sequence
  (outermost caller first, innermost executing frame last). Segment layout is
  unchanged: python (outermost), then user, then kernel. v11 and older
  databases keep the mixed order they were written with — the python segment
  cannot be re-ordered after the fact without classifying frames by name
  (note for anyone attempting that: root-side markers — `<module>`, threading
  bootstraps, and on CPython 3.12+ an `<interpreter trampoline>` frame that
  sits beyond `<module>` — fall in the run's root-side half, not necessarily
  at its literal end); native-only stacks are identical either way. Importing an older trace into
  a v12 database does not re-order it either. `_traces.systing_version` is
  the per-trace discriminator, with one caveat: it is stamped at
  parquet-to-DuckDB conversion time with the converting binary's version
  (then preserved across database-to-database imports), so it names the
  recorder only when recording and conversion happen in the same run — true
  for the normal pipeline, not for a retained parquet directory converted
  later by a newer binary. Embedding the recorder's version in the parquet
  directory itself is planned follow-up.
- `stack.leaf_name` now holds the name of the innermost executing frame (the
  last array entry). Through v11 it held the first entry — the root frame for
  native-only stacks, despite the column name.
- `systing analyze flamegraph` (and the MCP flamegraph tool) previously
  reversed the array on output under the leaf-to-root assumption, emitting
  inverted folded stacks for native frames. It now emits storage order, which
  is correct for all schema versions' native segments; python segments in
  pre-v12 databases remain leaf-first within the blend.

## Perfetto import callsite order (no schema version change)

`systing-util`'s perfetto-trace importer previously read `Callstack.frame_ids`
as leaf-first and built the callsite tree from the reversed array. Perfetto's
convention is root-first (and systing's own exporter emits storage order,
uniformly root-first since v12), so importing any spec-compliant trace —
including systing's own exports — produced an inverted tree: the real leaf
became the parentless root, the returned "leaf" id pointed at the real root,
and `depth` counted leaf=0. The importer now reads frame_ids root-first and
writes `depth` root=0 increasing toward the leaf, matching perfetto trace
processor's `stack_profile_callsite`. Table shapes are unchanged (no
SCHEMA_VERSION bump); `callsites` tables written by older systing-util
binaries from spec-compliant inputs carry the inverted parent/depth shape and
cannot be distinguished in-band — re-import with a fixed binary if the tree
direction matters.

## Schema Version 13 (systing 1.12.0) — 2026-07-29

`network_socket` and `network_interface` each gain a `netns_inum BIGINT` column:
the inode of the network namespace that owns the socket (for a flow row) or the
interface/IP (for an interface row). It lets a reader attribute a flow to its
owning netns — and therefore its pod — by joining
`network_socket.netns_inum = network_interface.netns_inum`, instead of matching
the socket's `src_ip` against the interface map. The IP match cannot
disambiguate loopback (every netns has `127.0.0.1`/`::1` on `lo`), so
intra-pod-localhost flows were unattributable before; the netns inode is
unambiguous. It also attributes inbound flows (whose `src_ip` is the remote
peer, not a local interface) and IPv4-mapped-IPv6 sockets correctly.

### New columns
- `network_socket.netns_inum` (BIGINT): read in BPF from the socket's
  `struct sock` (`sk->__sk_common.skc_net.net->ns.inum`) at send/recv event
  emission; the netns is stable over the socket's lifetime. `0` when the sock
  pointer was unavailable.
- `network_interface.netns_inum` (BIGINT): the inode of the enumerated netns
  (the same value userspace reads from `/proc/<pid>/ns/net`), emitted alongside
  the existing `namespace` display string by the per-namespace interface walk.

Pre-v13 databases and traces have neither column; readers join on `netns_inum`
where present and fall back to the `src_ip`→interface heuristic otherwise.

## Schema Version 14 (systing 1.12.0) — 2026-08-11

`memory_rss` gains an `external BOOLEAN` column and three synthetic members
(-3/-4/-5), fixing rss_stat attribution in reclaim context and adding passive
per-task thrash signals.

### Attribution fix (no column)
rss_stat events are now attributed to the mm's owner rather than to the task
that happened to be running. Reclaim (`try_to_unmap_one`) decrements the
victim's counters from the reclaimer's context, so reclaim-driven RSS drops of
a traced process were previously dropped in cgroup-targeted mode (kswapd fails
the filter) and misattributed to the reclaimer in whole-system mode (with the
threshold batching state keyed by the wrong tgid). The common self-update case
is unchanged, and a process's own exit teardown stays self-attributed — even
when `mm_update_next_owner()` has already cleared `mm->owner` — so per-process
RSS still falls to zero at exit. On the classic (non-BTF) fallback attach path
the raw tracepoint carries no mm pointer, so remote updates are dropped there
instead of misattributed.

### New columns
- `memory_rss.external` (BOOLEAN): true when the counter update was performed
  from outside the process's own thread group — an external reclaimer (kswapd,
  khugepaged, another process's direct reclaim, a `memory.reclaim` /
  `process_madvise` writer) evicted or migrated the process's pages. False for
  the process's own faults/maps/unmaps/exit teardown, for synthetic members,
  and for exit-flush residuals (mixed provenance). Splitting cumulative member
  deltas by this flag yields a per-process evicted-bytes timeline (under
  threshold batching the flag reflects the update that crossed the threshold).

### New synthetic members (periodic mm snapshots, `utid` = sampled thread)
- `-3` maj_flt: cumulative major fault count for the sampled thread — a page
  the process needed came back from disk/swap. Count, not bytes.
- `-4` thrashing_count / `-5` thrashing_delay_ns: delayacct's thrash metrics
  (stalls on `PG_workingset` pages — pages that refaulted soon after reclaim).
  Emitted (zero values included) whenever delayacct was readable for the
  sampled task, so zero-valued rows mean "delayacct on, no thrash", and their
  complete absence while -3 rows are present means delayacct is not enabled
  on the host (`CONFIG_TASK_DELAY_ACCT` plus the `delayacct` boot parameter
  or the `kernel.task_delayacct` sysctl — runtime-enableable, but only tasks
  forked after enablement carry the counters).

"RSS flat while maj_flt and thrashing_delay climb" is a direct per-process
thrash signature; `external` tells you whose pages reclaim is taking. Pre-v14
databases and traces have neither the column nor the members: merging a
pre-v14 DuckDB into a v14 database (`systing-util convert`) NULL-fills
`external` via the column-intersection import, and readers of raw pre-v14
parquet must treat the column as absent.

## Schema Version 15 (systing 1.13.0) — 2026-08-13

`memory_map` gains `rss_delta_bytes BIGINT` (nullable): the SIGNED change in
the process's resident set across each mmap/munmap/brk call — pages actually
committed or freed, where `size` only names the virtual-address range the
arguments described.

Why: the VA number misrepresents reality on both sides. mmap commits nothing
(page faults do), so huge mmaps of sparse reservations recorded as if memory
appeared; munmap frees only what was resident in the range, so sparse unmaps
recorded far more than the machine gave back. `rss_delta_bytes` is measured
from the mm's resident counters at syscall enter and success-gated exit:
munmap rows are typically negative (the real release), mmap rows typically
~0, brk either sign.

Read rules, stated once here and in the record docs:
- NULL means the resident read was unavailable on either side of the call —
  and every pre-v15 row. Never treat NULL as zero.
- Three approximations, all bounded and deliberate: concurrent faults or
  reclaim on the process's other threads inside the syscall window land in
  the delta (microsecond window); the resident reads carry the rss_stat
  sampling's worst-case ±(percpu batch x nr_cpus pages) error (the kernel's
  counter caching — the same slop rss_stat rows already document); and under
  `--memory-map-sample-rate` 1:N sampling only sampled events carry a delta.
- Sampling composition: a sampled-in row carries the FULL delta of its own
  call — the rate scales aggregate event mass (multiply sums by N), never
  divides a row's delta. At rates above 1 the scaled estimate is unbiased
  but heavy-tail-noisy: one huge munmap missed by sampling is invisible,
  the same property the VA sums always had. Zero-delta events are NOT
  suppressed — every sampled successful call emits a row, so event-rate
  reads on this stream stay valid.
- Churn built from this column: freed = sum(-rss_delta_bytes) over negative
  rows; committed-at-map = sum over positive rows. The old `size` sums remain
  VA-range churn and keep their v13/v14 meaning for historical continuity.

## Schema Version 16 (systing 1.13.9) — 2026-08-20

New table `sched_migrate (trace_id, ts, utid, orig_cpu, dest_cpu)`: one row
per `sched_migrate_task` event, i.e. every change of a task's CPU. The kernel
fires it from `set_task_cpu()`: at wakeup, right after `sched_waking`, when
the scheduler picked a CPU other than the one the task last ran on; and when
the load balancer, NUMA balancing or an affinity change moves a runnable task.

Why: the runnable marker in `thread_state` (`state = 0`) is recorded at
`sched_waking`, which fires BEFORE the scheduler picks a CPU, so its `cpu` is
the CPU the thread last ran on — not where it was queued. Without this table
a trace cannot say which CPU a woken thread was placed on until the thread
runs, so per-CPU runqueue lengths and work-conservation analysis had to treat
woken threads as unplaced. With it, placement is exact: a woken thread with no
`sched_migrate` row before its next `sched_slice` stayed on its previous CPU;
otherwise the row's `dest_cpu` is the placement (and later rows are moves).

Recorded only with the `sched` recorder (the program is part of its set). The
Perfetto export does not carry these rows yet. `systing-analyze sched
aggregate` switches to exact placement when the table is present
(`meta.placement_exact`) and reports the event counts under `switches.migrate_*`
and the placement vector `per_cpu.wakeups_placed`.

## Schema Version 17 (systing 1.14.0) — 2026-08-25

The memory recorder's capture-time configuration is now in the trace. Until
now the three `--memory-*-sample-rate` values were "a capture-time setting,
not carried in the trace" (see schema v6), so a consumer that needed absolute
figures had to know how the capture was launched; and since 1.13.13 the
page-fault leg has two implementations (the x86 tracepoint and the perf
software event everywhere else), the second of which can now fail to attach on
a host without refusing the capture, so an empty `memory_fault` table needed a
column that says why.

### Added columns
- `sysinfo`: added `memory_fault_leg VARCHAR` — how the page-fault leg ran:
  `tracepoint` (x86, `exceptions:page_fault_user`), `perf_sw` (every other
  architecture, one `PERF_COUNT_SW_PAGE_FAULTS` software event per CPU) or
  `off:<cause>` (the perf-event leg could not be opened or attached on this
  host — `off:EMFILE`, `off:EPERM`, `off:errno=<n>`, `off:error` — and the
  capture ran without it, so `memory_fault` is empty by construction while
  the other memory tables and the stack sampler are intact). `NULL` when the
  memory recorder was not enabled, and in traces from systing < 1.14.
- `sysinfo`: added `memory_fault_sample_rate BIGINT` — `--memory-fault-sample-rate`
  as configured: `memory_fault` holds 1 in N sampled user page faults (0 and
  1 both mean every fault). `NULL` as above.
- `sysinfo`: added `memory_map_sample_rate BIGINT` — `--memory-map-sample-rate`
  as configured: each `memory_map` event type is sampled 1 in N independently
  (1 = every event). `NULL` as above.
- `sysinfo`: added `memory_alloc_sample_rate BIGINT` — `--memory-alloc-sample-rate`
  as configured (1 = every call). `NULL` when the `memory-alloc` recorder was
  not enabled, and in traces from systing < 1.14.

### Behaviour change (no schema effect)
On non-x86 hosts a failure to open or attach the page-fault perf events (any
error other than ENODEV for a missing CPU, e.g. EMFILE when the process's
descriptor limit is exhausted) no longer fails the whole capture: the memory
lane continues without the fault leg, one line is logged, and
`sysinfo.memory_fault_leg` records `off:<cause>`. The clock sampler keeps its
old behaviour — a capture without its CPU stack sampler is not a capture.
`systing-analyze trace info` (and the MCP `trace_info` tool) report the four
new fields under `system`.

## Schema Version 20 (systing 1.17.0) — 2026-08-28

Two `sysinfo` columns record the FORM of the recorders' kernel-function
hooks, and the form is now a switch. systing 1.17.0 introduced a trampoline
form of the memory recorder's mmap/munmap/brk hooks — fentry/fexit programs
on the arch syscall wrappers (`__x64_sys_mmap` …, `__arm64_sys_*`,
`__riscv_sys_*`) in place of the six `syscalls/sys_{enter,exit}_
{mmap,munmap,brk}` tracepoints attached through perf_event_open — and of
the network recorder's TIME_WAIT hooks (`tcp_time_wait`,
`inet_twsk_hashdance_schedule`, `inet_twsk_deschedule_put`: fentry in
place of kprobes), as the DEFAULT, on the claim that trampolines detach in
milliseconds. That claim was wrong, and the next release (unreleased at
the time of writing; 1.17.0–1.17.2 shipped the trampoline default) makes
the classic form the default again with the trampoline form opt-in
(`--kernel-hooks trampoline`; `sysinfo.memory_syscall_leg` /
`network_tw_leg` say which ran). What the kernel does, read at v6.6, v6.12
and v6.18: a perf-attached
tracepoint's detach runs `tracepoint_synchronize_unregister()` — one SRCU
and one RCU grace period per program — while dropping the last program on
a kernel-function trampoline runs `bpf_trampoline_update` →
`unregister_fentry` → `unregister_ftrace_direct` → `ftrace_shutdown()`,
whose tail waits `synchronize_rcu_tasks_rude()` and then
`synchronize_rcu_tasks()` (kernel/trace/ftrace.c, v6.12 lines 3181 and
3190) — two Tasks-RCU grace periods, each of which sleeps at least 100 ms
whenever any task is runnable at its scan — once per hooked FUNCTION,
serialized on the capture's stop path. The three TIME_WAIT kprobes share
one `ftrace_ops` and pay that shutdown once; three trampolines pay it three
times. Measured on the printed `stop-phase: detach bpf programs` line, 2
vCPU guests with two busy loops and a live mmap/TCP workload, 3-second
whole-system captures (systing 1.16.3 = classic vs 1.17.1 = trampoline):
on vanilla 6.12.0, memory recorder only 116 ms → 672 ms (medians of 4),
network recorder only 140 ms → 622 ms, the default set plus both recorders
957 ms → 2146 ms; on 6.12.85, 188 ms → 648 ms, 179 ms → 604 ms and 1418 ms
→ 2378 ms (medians of 2). The trampoline form's one real saving is during
the capture — the syscalls tracepoints keep every task of the host on the
syscall slow path (`SYSCALL_WORK_SYSCALL_TRACEPOINT`) for the whole
capture, the trampolines put nothing on other syscalls — which is why the
form stays available. The x86 `exceptions/page_fault_user` tracepoint's
move from perf to a raw (BTF-typed) attach stands in both forms: a raw
tracepoint's last detach is `release_probes()`' `call_rcu`, with no wait.
The tables keep their columns; the new columns are nullable.

### Added columns
- `sysinfo`: added `memory_syscall_leg VARCHAR` — how the mmap/munmap/brk
  hooks attached for the capture: `tracepoint` (the classic tracepoints as
  the default form, from the correction release), `fentry` (the trampoline
  set — the default in 1.17.0–1.17.2, opt-in after), `tracepoint:nosym` (the
  classic tracepoints under the trampoline form, because the arch syscall
  wrappers are not in kallsyms — riscv before 6.6), `tracepoint:nobtf` (the
  classic tracepoints under the trampoline form, because vmlinux BTF has no
  FUNC entry for the wrappers — an fentry program's target is resolved at
  load, so the set is not loaded there), `tracepoint:notramp` (the classic
  tracepoints, because a trampoline program loaded but did not attach — an
  arm64 kernel without `DYNAMIC_FTRACE_WITH_DIRECT_CALLS` refuses the
  trampoline while resolving the BTF target fine) or `off:<cause>` (neither
  set attached: the capture has no `mmap` / `munmap` / `brk` rows in
  `memory_map`, by construction rather than for lack of syscalls). NULL
  when the memory recorder did not run, and in traces from systing < 1.17,
  which always attached the classic tracepoints. `memory_fault_leg` keeps
  reading `tracepoint` on x86 for the raw-attached tracepoint — the same
  event, the same rows.
- `sysinfo`: added `network_tw_leg VARCHAR` — how the network recorder's
  TIME_WAIT leg (the `tcp_time_wait` / `inet_twsk_hashdance_schedule` /
  `inet_twsk_deschedule_put` hooks that turn `tcp_time_wait()`'s CLOSE into
  a TIME_WAIT transition and emit TIME_WAIT -> CLOSE at teardown) attached:
  `kprobe` (the kprobe set as the default form, from the correction
  release), `fentry` (the trampoline set — the default in 1.17.0–1.17.2,
  opt-in after),
  `kprobe:notramp` (a trampoline program loaded but did not attach — the
  same arm64 case — and the kprobe set ran instead), `kprobe:nobtf` (under
  the trampoline form, vmlinux BTF lacks one of the three functions, so the
  trampoline set was never loaded — an fentry program whose target is
  missing from BTF fails the whole object at LOAD, which no attach-time
  fallback could catch — and the kprobe set ran), or `off:<cause>` —
  `off:nosym` when the kernel lacks one of the functions
  (`inet_twsk_hashdance_schedule` exists from 6.11, kernel commit
  b334b924c9b7; a 6.6-series kernel has no leg) and `off:attach` when
  neither set attached. With the leg off the trace carries NO TIME_WAIT
  transitions: a socket entering TIME_WAIT reads as a plain CLOSE and no
  TIME_WAIT -> CLOSE teardown row exists, so a `network_packet` consumer
  counting TIME_WAIT reads this column first. NULL when the network
  recorder was off, and in traces from systing < 1.17, which always
  attached the kprobes.

### Changed meaning (same columns)
- `memory_map` `mmap` / `munmap` / `brk` rows are unchanged in value
  whichever form attached: the trampoline programs read the same arguments
  from the wrapper's `pt_regs` and the same return from the fexit, and the
  row-building code is shared with the classic programs. Native-only
  semantics hold as before (the compat `__ia32_sys_*` wrappers are separate
  symbols and are not attached; the syscalls tracepoints excluded compat
  calls the same way). One difference in the stacks under the trampoline
  form: the kernel half of a syscall row's stack at fentry/fexit is the
  trampoline's frame above the wrapper, where the tracepoint's is the
  syscall-entry glue — plumbing either way; the user half is the same walk
  of the task's user registers.
- `network_packet` TIME_WAIT rows are unchanged in value: the fentry and
  kprobe programs share one body per hook, so the rows are identical
  whichever set attached.
- `memory_thp` `result` for `kind = 'pmd'` rows from the worker probe
  (`__split_huge_pmd_locked`, `memory_thp_leg = on` / `on:pmd-only`): the
  kprobe now reads the worker's `freeze` parameter as a whole register and
  masks its low byte (the x86-64 psABI leaves a `_Bool` argument's upper
  register bits unspecified, and the old cast tested the whole register),
  so a split whose caller left stale upper bits no longer reads as
  `freeze = true`. Rows from 1.16.x may carry a spurious `true` on such
  splits; from 1.17.0 the value is the flag the kernel passed.

### Behaviour change (no schema effect)
- The capture's `detach bpf programs` stop phase: under the default classic
  form it is what it was through 1.16 (the seven perf-attached programs'
  serialized SRCU + RCU grace periods — hundreds of ms on a many-core host,
  seconds on the biggest); under the opt-in trampoline form it is longer by
  two Tasks-RCU grace periods per hooked function (the numbers above), and
  the `attach bpf programs` phase then also carries the trampolines' text
  pokes (an IPI batch each), before the clock sampler starts, so no capture
  contains them. In 1.17.0–1.17.2 the trampoline form was the default, so
  those releases stop a memory or network capture more slowly than 1.16.x
  did.
- Under the default classic form only the classic set is loaded (the
  object a 1.16 capture loaded, plus the raw page-fault tracepoint on x86);
  under the trampoline form the classic set is loaded beside the trampoline
  set (both verified by the kernel at every load) and attached only when
  needed. The network recorder's kprobe trio and fentry trio behave the
  same way.
- The network recorder no longer fails the whole capture on a kernel
  without `inet_twsk_hashdance_schedule` (pre-6.11): the TIME_WAIT leg is
  gated on the symbol before the object is loaded and left off
  (`off:nosym`), and a leg whose programs fail to ATTACH is turned off for
  that capture (`off:attach`) while the rest of the recorder — and the CPU
  profile — runs. Before, `skel.attach()` failed every capture on such a
  node, CPU lane included.

## Schema Version 19 (systing 1.16.0) — 2026-08-26

Follow-ups to the VFIO/THP legs from reading the kernel they probe: the
PMD-split probe moves to the worker every split reaches, device-container
teardown gets its own window, the per-process AnonHugePages walk is bounded,
and two facts a reader needed from stdout now sit in `sysinfo`. The tables
keep their columns; the new columns are nullable.

### Added columns
- `sysinfo`: added `memory_iommu_overflow BIGINT` — how many `iommu:map` /
  `iommu:unmap` runs or VFIO windows the `memory_iommu` histogram could not
  count (its BPF hash or the in-flight table was full): 0 means the
  histogram is complete, anything else that it is a floor; NULL when the
  VFIO leg did not run. Added `memory_anon_huge_walk VARCHAR` — what the
  end-of-capture AnonHugePages walk (the `memory_rss` member -6 rows) did:
  `complete:<read>/<candidates>` when every live candidate was read,
  `capped:<read>/<candidates>` when the per-capture cap of 64 processes
  stopped it, `budget:<read>/<candidates>` when its 500 ms budget did
  (`candidates` = every process that produced a memory event; those gone
  by capture end are neither). A capped or budgeted walk read the
  processes whose memory events moved the most bytes first, so a process
  without a member -6 row under `capped:` / `budget:` was a small one, not
  a gone one. NULL when the THP leg did not run.

### Changed meaning (same columns)
- `memory_thp` rows with `kind = 'pmd'`: the probe now sits at
  `__split_huge_pmd_locked`, the worker every PMD split reaches and where
  `/proc/vmstat` counts `thp_split_pmd`, when the kernel exports it
  (`sysinfo.memory_thp_leg = on` / `on:pmd-only`). A row is then one counted
  split — the `split_huge_pmd()` callers AND the rmap paths
  (`try_to_unmap` / `try_to_migrate` on 6.10+), so the per-process rows are
  bounded by the vmstat delta — and `result` carries the split's `freeze`
  flag (1: the PTEs were written as migration entries — the migrate path,
  `try_to_migrate` and the folio split's own unmap of anon folios; 0: a
  plain split, which includes reclaim's `try_to_unmap` — the kernel passes
  `freeze = false` there). On a build that inlined the worker
  the probe falls back to the public entry `__split_huge_pmd`
  (`memory_thp_leg = on:pmd-entry` / `on:pmd-only:entry`), which is also
  reached for a PMD that is not huge (`split_huge_pmd_address` calls it for
  any populated PMD on a VMA adjust): those rows over-count on VMA churn,
  miss the rmap paths, and carry `result = 0` — read the vmstat delta as
  the host-wide truth there, as before.
- `memory_vfio`: a container's regions are also unmapped WITHOUT an
  ioctl — when the last file of the container is closed
  (`vfio_iommu_type1_release`: every region) or a group detaches from a
  domain (`vfio_iommu_type1_detach_group`). The release now writes one
  `op = 'unmap'` row with `flags` bit 31 set — `flags < 0` in the INTEGER
  column (not a uapi flag; the uapi `VFIO_DMA_UNMAP_FLAG_ALL` bit is set
  beside it), `iova = 0`, `size = -1` (all ones: every region), `vaddr`
  NULL and the stack of the closing thread — so a model unload that just
  closes its device files shows up; a detach writes no
  row (how much it unmaps depends on whether it was the domain's last
  group) but opens the histogram window, so its `iommu:unmap` runs are
  counted in `memory_iommu` like an ioctl's. Both are probed only when
  kallsyms lists the two functions: `sysinfo.memory_vfio_leg` reads
  `on:noteardown` when the ioctl pair attached but the teardown pair did
  not (close-path unmaps then stay invisible, as in v18), `on` when both
  did. The `VFIO_DMA_UNMAP_FLAG_ALL` ioctl row keeps `size = 0` and
  `flags >= 0` as in v18; the teardown row's `size = -1` / `flags < 0`
  tells the two "everything" rows apart.
- `sysinfo.memory_vfio_leg` / `memory_thp_leg`: a leg whose probes fail to
  ATTACH (a module unloaded between the symbol read and the attach, a
  symbol the kernel will not probe) now turns only that leg off —
  `off:attach`, or `on:noteardown` for the teardown pair alone — and the
  capture runs; before, `skel.attach()` failed the whole capture, CPU
  profile included.

### Behaviour change (no schema effect)
- `memory_map` `brk` rows: an `-EINTR` return from `brk` (the process is
  being killed while the syscall waits for the mmap lock) no longer
  produces a row. The exit handler used to compute `ret - old_brk` with
  `ret = -4`, recording a delta of `-(old_brk + 4)` — a negative value of
  tens of TB whose magnitude is ≡ 4 (mod 4096). An error return carries
  no break.
- The AnonHugePages walk at the end of a THP-leg capture is bounded (64
  processes, heaviest first, 500 ms), see `memory_anon_huge_walk` above.

## Schema Version 18 (systing 1.15.0) — 2026-08-25

The memory recorder learns about device DMA mappings and transparent huge
pages: how often VFIO regions are mapped and unmapped, how fragmented the
memory behind them is, and how often THPs split or fail to be allocated on
the host. Motivation: a model-unload regression whose suspected cause is
4 KiB-fragmented VFIO-pinned arenas (the unmap/unpin walk has 512x the
entries of a 2 MiB-backed one). New tables are empty unless the leg was
asked for (`--memory-vfio`, `--memory-thp-sample-rate`); `memory_vmstat`
is written whenever the memory recorder runs.

### Added tables
- `memory_vfio` — one row per VFIO DMA region mapped or unmapped through
  vfio_iommu_type1 (`VFIO_IOMMU_MAP_DMA` / `UNMAP_DMA`, kprobes on
  `vfio_dma_do_map` / `vfio_dma_do_unmap`): `id`, `ts`, `utid`, `op`
  (`map` / `unmap`), `iova`, `vaddr` (the user address backing a map; NULL
  on unmap), `size` (bytes), `flags` (the ioctl flags), `stack_id`.
  Unsampled — a region is one ioctl. The kprobes sit at the handlers'
  entry, so a row is the region AS REQUESTED: an ioctl the kernel then
  refuses still produces it, and an unmap with `VFIO_DMA_UNMAP_FLAG_ALL`
  (flags bit 1) carries `iova = 0, size = 0` and means every region of the
  container.
- `memory_iommu` — the IOMMU map/unmap run-size histogram per process
  and per GiB of IOVA space, counted in BPF from the `iommu:map` /
  `iommu:unmap` tracepoints and drained once at the end of the capture
  (`ts`): `utid` (the mapping process's main thread), `op` (`map` /
  `unmap`), `iova_gib` (`iova >> 30` — where in the device address space
  the runs sit), `size_order` (log2 of the run size in bytes: 12 = 4 KiB,
  21 = 2 MiB, 30 = 1 GiB), `count`, `bytes`. vfio_iommu_type1 maps and
  unmaps a region one physically contiguous run per `iommu_map()` /
  `iommu_unmap()` call, so this is the contiguity of the memory behind the
  device mappings: the share of `bytes` at `size_order >= 21` is the
  THP-backed share, `sum(count)` over `memory_vfio` rows of the same
  process is the number of runs per region, and grouping by `iova_gib`
  shows which GiBs of a device's arena are fragmented. Only runs inside
  the region the counting task is mapping or unmapping through a
  `VFIO_IOMMU_MAP_DMA` / `UNMAP_DMA` ioctl at that moment are counted
  (the kprobe/kretprobe pair brackets the window), so the table is VFIO's
  by construction — the host's other IOMMU users (NIC / NVMe DMA-API
  mappings on an IOMMU-translated host) are never in it. The BPF map holds
  131072 entries (≈23 processes with 150 GiB arenas at every size order);
  runs that find it full are dropped and counted, as is an ioctl whose
  window could not be opened (more than 1024 traced tasks inside a VFIO
  ioctl at once) — systing prints `memory-vfio: N iommu map/unmap runs or
  VFIO ioctl windows not counted` — so the table is a floor in that case.
  Two more reading rules: a container attached to several IOMMU domains
  fires the tracepoints once per domain, so its runs are counted once per
  domain (compare `count` against `memory_vfio` sizes per domain count);
  and `size_order` is floor(log2) of the run, so a run that is not a
  power of two (a partially huge-page-backed tail) lands in the order
  below its size — `bytes` is exact, `count` per order is the rounding.
  Only the vfio_iommu_type1 container path is instrumented: a host whose
  devices are attached through iommufd (`/dev/iommu`, the cdev path) maps
  through `iommufd_ioas_map` instead and gets no `memory_vfio` /
  `memory_iommu` rows although DMA mappings happen — it reads
  `memory_vfio_leg = off:nosym` only when the vfio_iommu_type1 module is
  not loaded at all (with the module loaded beside iommufd the leg reads
  `on` and simply sees nothing). The same `off:nosym` appears when the
  kernel's symbols carry a `.isra` / `.constprop` suffix the exact-name
  probe does not match.
- `memory_thp` — sampled transparent-huge-page splits: `id`, `ts`, `utid`,
  `kind` (`pmd`: a PMD mapping split into PTEs, `addr` = the virtual
  address, what `/proc/vmstat` counts as `thp_split_pmd` — probed at
  `__split_huge_pmd`, so the rmap-path splits of `try_to_unmap` /
  `try_to_migrate` on 6.10+ are in the vmstat delta but not here; `page`:
  the folio itself split, `result` = the kernel's return value, 0 = split,
  negative errno = failed — `thp_split_page` / `thp_split_page_failed`),
  `addr` (NULL for `page`), `result`, `stack_id`. 1 in N sampled
  (`sysinfo.memory_thp_sample_rate`). Kernel-version notes: on 6.9+ the
  `page` kretprobe is `split_huge_page_to_list_to_order`, which every
  large-folio split goes through (file and shmem folios included), so its
  rows are a superset of the vmstat `thp_split_page` family; on 6.15+ the
  `folio_split` path can bypass it, so the vmstat delta stays the
  host-wide truth and the rows are the sampled, attributed subset.
- `memory_vmstat` — `/proc/vmstat` counters sampled at the start and the
  end of the capture: `name`, `ts_start`, `value_start`, `ts_end`,
  `value_end`. The THP allocation and split families (`thp_fault_alloc`,
  `thp_fault_fallback`, `thp_fault_fallback_charge`, `thp_collapse_*`,
  `thp_split_page`, `thp_split_page_failed`, `thp_deferred_split_page`,
  `thp_split_pmd`, `thp_zero_page_alloc`, `thp_swpout`), compaction
  (`compact_stall` / `_success` / `_fail` / `_migrate_scanned` /
  `_free_scanned`), direct reclaim (`pgscan_direct`, `pgsteal_direct`),
  migration (`pgmigrate_success` / `_fail`) and the instantaneous
  `nr_anon_transparent_hugepages`. `value_end - value_start` is the
  host-wide count over the capture (for `nr_*` gauges it is the change in
  level); a counter the kernel lacks is absent.

### Added columns
- `memory_rss`: a new synthetic `member` -6 (`anon_huge`): the process's
  THP-backed anonymous bytes (`AnonHugePages` from
  `/proc/<pid>/smaps_rollup`), sampled once at the end of the capture for
  every process that produced a memory event and was still alive — "did
  this process get huge pages", beside its `anon` rows. Present only when
  the THP-split leg ran (`--memory-thp-sample-rate` > 0, i.e.
  `sysinfo.memory_thp_leg` is not NULL): each sample is a kernel
  page-table walk of that process, which is why the plain memory recorder
  does not take it (from v1.15.4; v1.15.0–v1.15.3 took it on every memory
  capture).
- `sysinfo`: added `memory_vfio_leg VARCHAR` (`on`, or `off:nosym` when
  the vfio_iommu_type1 module is not loaded / `off:notracepoint` when the
  kernel has no iommu tracepoints; NULL when `--memory-vfio` was not
  given), `memory_thp_leg VARCHAR` (`on` when both the PMD-split kprobe
  (`__split_huge_pmd`) and the folio-split kretprobe
  (`split_huge_page_to_list_to_order` on 6.9+, `split_huge_page_to_list` on
  the 6.6 series) attached, `on:pmd-only` / `on:page-only` when one symbol
  is missing, `off:nosym`; NULL when the sample rate was 0),
  `memory_thp_sample_rate BIGINT`.
  An unavailable leg turns only that leg off and says so here; the
  capture runs.

### Reading the new tables (the three questions, as queries)
```sql
-- 1. VFIO map/unmap rate: regions and bytes per process and op
SELECT p.name, v.op, count(*) AS regions, sum(v.size) / 1073741824.0 AS gib
FROM memory_vfio v JOIN thread t ON t.utid = v.utid JOIN process p ON p.upid = t.upid
GROUP BY 1, 2 ORDER BY 1, 2;

-- 2. Fragmentation: share of mapped bytes in >= 2 MiB runs, per process and
--    op (and where: add iova_gib to the GROUP BY for the per-GiB picture)
SELECT p.name, i.op,
       sum(i.bytes) FILTER (WHERE i.size_order >= 21) * 1.0 / sum(i.bytes) AS huge_share,
       sum(i.count) AS runs, sum(i.bytes) / 1073741824.0 AS gib
FROM memory_iommu i JOIN thread t ON t.utid = i.utid JOIN process p ON p.upid = t.upid
GROUP BY 1, 2 ORDER BY 1, 2;

-- 3. THP: host-wide deltas over the capture, and who split
SELECT name, value_end - value_start AS delta FROM memory_vmstat
WHERE name LIKE 'thp_%' OR name LIKE 'compact_%' ORDER BY 1;
SELECT p.name, m.kind, count(*) AS splits, count(*) FILTER (WHERE m.result <> 0) AS failed
FROM memory_thp m JOIN thread t ON t.utid = m.utid JOIN process p ON p.upid = t.upid
GROUP BY 1, 2 ORDER BY 3 DESC;
-- and per process: AnonHugePages (member -6) beside anon (member 1) in memory_rss.
```

### Behaviour change (no schema effect)
The new legs are off by default and attach only the kernel symbols the
running host has (probed in /proc/kallsyms and tracefs before the BPF
programs are selected), on 6.6, 6.12 and 6.18-series kernels alike.
