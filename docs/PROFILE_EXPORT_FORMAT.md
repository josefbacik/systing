# systing profile export format (`.systing`)

A lightweight, line-oriented profile interchange format for systing
recordings. It carries the *sampling profile* view of a trace — interned
stacks, per-stack sample tallies, and the process/thread metadata needed to
attribute them — in a form any tool can parse without DuckDB: one JSON value
per line, first line identifying the format.

This is a **profile summary**, not the full trace. Timestamps, scheduler
slices, counters, network/memory events, and everything else systing records
stay in the DuckDB database (`--output trace.duckdb`); use the export when a
downstream tool only needs "which stacks, how often, in which threads"
(flamegraphs, Markdown reports, LLM pipelines).

Produced by:

```sh
# directly from a recording
systing --duration 30 --output profile.systing -- ./my-workload

# from an existing DuckDB trace database
systing-util convert trace.duckdb --output profile.systing
```

The file is plain UTF-8 text. Producers may gzip it (`profile.systing.gz`);
consumers are encouraged to sniff the two-byte gzip magic rather than trust
file names.

## Structure

Each line is one JSON value. Line 1 is the **header object**; every
subsequent line is a **record array** whose first element is a one-letter
type tag. Parsers must ignore record types they do not recognize (future
minor additions), and must reject the file if the header is missing or its
`systing_profile_export` version is greater than what they support.

### Header (line 1, JSON object)

```json
{"systing_profile_export":1,"producer":"systing 1.10.6","trace_id":"trace",
 "source_schema_version":11,
 "sample_event":"cpu-clock","sample_period":1000000,
 "event_types":{"0":"uninterruptible_sleep","1":"cpu","2":"interruptible_sleep"},
 "stack_order":"leaf_first",
 "start_ts":81290174000,"end_ts":91314520381,
 "system":{"sysname":"Linux","release":"6.12.0","machine":"x86_64"}}
```

| Key | Type | Meaning |
| --- | --- | --- |
| `systing_profile_export` | integer | Format version. This document describes version **1**. Required; parsers key detection on it. |
| `producer` | string | Tool and version that wrote the file. |
| `trace_id` | string | Trace identifier (matches `_traces.trace_id` when exported from DuckDB). |
| `source_schema_version` | integer \| null | The producing database's schema version (see SCHEMA_CHANGES.md), or the recording binary's schema version when exporting straight from a recording. `null` when the source database carries no version row. Database-level: a database can contain traces imported from several systing versions. |
| `source_systing_version` | string \| null | The systing version that recorded the selected trace (`_traces.systing_version`; the recording binary's version when exporting straight from a recording). May be an empty string or `null` for traces predating version stamping. Informational — the exporter already normalizes per-version stack-order differences (see Stack order below). |
| `sample_event` | string \| null | Perf event driving CPU stack sampling: `"cpu-cycles"` or `"cpu-clock"`. `null` when unknown (traces recorded by systing < 1.9). |
| `sample_period` | integer \| null | Event units per CPU sample: **cycles** for `cpu-cycles`, **nanoseconds** for `cpu-clock`. One `cpu` sample represents this much execution. |
| `event_types` | object | Legend for the `x` record's `event_type` field. Fixed in version 1 to the three values shown above. |
| `stack_order` | string | Always `"leaf_first"` in version 1: a stack's frame list runs callee → caller (index 0 is the innermost, sampled frame). Stated explicitly so consumers never guess. |
| `start_ts`, `end_ts` | integer | First/last sample timestamp in the recording, nanoseconds on the trace clock (arbitrary epoch). Their difference is the sampled wall-clock window. |
| `system` | object | Recording host: `uname` fields, plus optional `hypervisor`, `sys_vendor`, `product_name`, `cpufreq_driver` when known. |

### Records (lines 2+, JSON arrays)

| Tag | Shape | Meaning |
| --- | --- | --- |
| `p` | `["p", upid, pid, name]` | Process. `upid` is the trace-internal unique id; `pid` the Linux pid; `name` may be `null` when unknown. |
| `t` | `["t", utid, tid, name, upid]` | Thread. `utid`/`tid` analogous to `upid`/`pid`; `upid` may be `null` for threads with no resolved process. |
| `f` | `["f", frame_id, name]` | Interned stack frame string (see Frame strings below). |
| `s` | `["s", stack_id, [frame_id, ...]]` | Interned call stack. Frame ids run **leaf first** (callee → caller). Never empty. |
| `x` | `["x", utid, stack_id, event_type, count]` | Sample tally: `count` samples of `stack_id` were taken in thread `utid` with the given `event_type` (see legend). `count` ≥ 1. |

Define-before-use ordering is guaranteed: an `f` line precedes any `s` line
referencing it, `s` and `t` lines precede any `x` line referencing them, and
`p` lines precede the `t` lines that reference them. A one-pass streaming
parser needs no lookahead.

Samples are pre-aggregated: producers fold identical
`(utid, stack_id, event_type)` triples into one `x` record. Consumers must
still tolerate duplicate triples (summing counts) — a streaming producer may
flush in chunks.

### Sample semantics

- `event_type` **1 (`cpu`)**: taken by the perf sampling event. One count
  represents `sample_period` cycles (`cpu-cycles`) or nanoseconds
  (`cpu-clock`) of on-CPU execution. With `cpu-cycles`, counts track cycles
  consumed, not wall time — conversion to time depends on clock frequency,
  which this format does not carry.
- `event_type` **0 (`uninterruptible_sleep`)** and **2
  (`interruptible_sleep`)**: taken when a thread entered that sleep state
  with the given stack. Counts are *occurrences*, not durations.

### Stack order

`stack_order` is always `"leaf_first"`, and the exporter enforces it rather
than passing storage order through. Recordings made by systing versions
before the stack-order normalization stored a blended stack's python segment
leaf-first while native segments were root-first; the exporter un-inverts
such python runs before the uniform reversal, deciding a trace's python
storage order as follows:

1. **Structural evidence first:** python root-side markers (`<module>`, the
   interpreter trampoline, threading bootstrap frames) only ever appear at
   the root side of a python stack, so which half of a stack's leading
   python run they fall in reveals the stored direction. The per-trace
   majority across stacks decides.
2. **Version keying as fallback**, when no stack yields structural evidence:
   `_traces.systing_version` below the normalization release means
   leaf-first. The fallback is second choice because version stamps can
   mislead: `_traces.systing_version` names the binary that *converted* the
   trace, which for a parquet directory reconverted by a newer
   `systing-util` is not the binary that recorded it (parquet directories
   carry no recording-version marker of their own).

Consumers therefore never need to reason about stack order themselves;
`source_systing_version` is informational.

### Frame strings

Frame strings are exactly systing's symbolized frame names:

- Native: `name (module [file:line]) <0xaddr>` — location suffix and
  `<0xaddr>` optional pieces depending on available symbol data. `module`
  may be a label rather than a binary basename: `[kernel]`,
  `[gvisor:runtime]`, `[gvisor:guest]`, `[jit:<runtime>]`, `[exited]`,
  `[vdso]` and similar. Unresolvable frames use the function name `unknown`.
- Python (pystacks): `name (python) [file.py:line]` — no address suffix.
- With `--no-frame-labels`: bare hex addresses (`0x7f95bfdb6e12`).

Consumers should treat the frame string as opaque if they do not need
structure, or parse the suffixes per the grammar above if they do.

## Versioning

The header's `systing_profile_export` value increments only for breaking
changes (removed/retyped fields, changed semantics). Additive changes — new
record tags, new optional header keys — do not bump it; that is why parsers
must skip unknown record tags and unknown header keys.
