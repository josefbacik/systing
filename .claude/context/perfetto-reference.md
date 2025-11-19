# Perfetto Proto Quick Reference

## Proto File Location

**Full Protobuf Definition:**
```
protos/perfetto_trace.proto
```
(Located in this repository)

**File Stats:**
- ~17,770 lines
- Auto-generated (merges all Perfetto protos)
- Format: Protocol Buffers v2 syntax

**WARNING:** This file is too large to load in full context. Use targeted searches instead.

## Quick Message Lookup

When you need to look up a specific message definition, use grep:

```bash
# Find message definition
grep -n "^message MessageName" protos/perfetto_trace.proto

# Find enum definition
grep -n "^enum EnumName" protos/perfetto_trace.proto
```

## Key Message Line Numbers

Quick reference for jumping to important message definitions:

| Message | Line | Description |
|---------|------|-------------|
| `Trace` | 17760 | Top-level trace container |
| `TracePacket` | 17480 | Fundamental data unit |
| `TrackDescriptor` | 17046 | Track definition |
| `TrackEvent` | 14701 | Events on tracks |
| `InternedData` | 15172 | String/data interning |
| `DebugAnnotation` | 13803 | Event annotations |
| `CounterDescriptor` | 16957 | Counter metadata |
| `ProcessDescriptor` | 16771 | Process info |
| `FtraceEventBundle` | 13017 | Ftrace events |
| `ClockSnapshot` | ~6000 | Clock sync |
| `ProfilePacket` | ~11000 | Profile data container |
| `PerfSample` | ~17533 | Perf samples |

## Searching the Proto File

### Find All Fields of a Message

```bash
# Get full message definition (adjust line count as needed)
sed -n '17480,17680p' protos/perfetto_trace.proto
```

### Find Messages by Pattern

```bash
# Find all sched-related messages
grep -n "message.*Sched" protos/perfetto_trace.proto

# Find all counter-related messages
grep -n "message.*Counter" protos/perfetto_trace.proto
```

### Search for Specific Fields

```bash
# Find where a field is defined
grep -n "optional.*field_name" protos/perfetto_trace.proto
```

## Rust Bindings

Systing uses the `perfetto_protos` Rust crate (v0.48.1) which auto-generates bindings from these proto files.

### Common Import Patterns

```rust
// Core types
use perfetto_protos::trace::Trace;
use perfetto_protos::trace_packet::TracePacket;

// Track system
use perfetto_protos::track_descriptor::TrackDescriptor;
use perfetto_protos::track_event::TrackEvent;
use perfetto_protos::track_event::track_event::Type;

// Interning
use perfetto_protos::interned_data::InternedData;
use perfetto_protos::trace_packet::trace_packet::SequenceFlags;

// Annotations
use perfetto_protos::debug_annotation::DebugAnnotation;

// Descriptors
use perfetto_protos::counter_descriptor::CounterDescriptor;
use perfetto_protos::counter_descriptor::counter_descriptor::Unit;
use perfetto_protos::process_descriptor::ProcessDescriptor;
use perfetto_protos::thread_descriptor::ThreadDescriptor;

// Ftrace
use perfetto_protos::ftrace_event::FtraceEvent;
use perfetto_protos::ftrace_event_bundle::FtraceEventBundle;
use perfetto_protos::ftrace_event_bundle::ftrace_event_bundle::CompactSched;

// Profiling
use perfetto_protos::profile_packet::PerfSample;
use perfetto_protos::profile_common::{Callstack, Frame, Mapping, InternedString};

// Clocks
use perfetto_protos::clock_snapshot::ClockSnapshot;
use perfetto_protos::clock_snapshot::clock_snapshot::Clock;
use perfetto_protos::builtin_clock::BuiltinClock;

// Process tree
use perfetto_protos::process_tree::ProcessTree;
use perfetto_protos::process_tree::process_tree::Process as ProtoProcess;
```

## Message Type Categories

### Metadata Messages
- `ClockSnapshot` - Time synchronization
- `ProcessTree` - Process hierarchy snapshot
- `ProcessDescriptor` - Process metadata
- `ThreadDescriptor` - Thread metadata

### Track System Messages
- `TrackDescriptor` - Define a track
- `TrackEvent` - Event on a track
- `CounterDescriptor` - Counter track metadata

### Event Data Messages
- `FtraceEventBundle` - Kernel ftrace events
- `PerfSample` - Perf profiling data
- `NetworkPacketEvent` - Network packets

### Supporting Messages
- `InternedData` - String/data deduplication
- `DebugAnnotation` - Key-value annotations

## Perfetto Documentation

Official Perfetto documentation: https://perfetto.dev/docs/

Key sections:
- **Trace format:** https://perfetto.dev/docs/reference/trace-packet-proto
- **TrackEvent guide:** https://perfetto.dev/docs/instrumentation/track-events
- **Clock sync:** https://perfetto.dev/docs/concepts/clock-sync

## Usage Pattern: Finding a New Message Type

1. **Identify what you need:** "I need to record X type of data"
2. **Search the proto file:** `grep -i "message.*X" perfetto_trace.proto`
3. **Find the line number:** Note the line from grep output
4. **Read the definition:** Use `sed -n 'START,ENDp'` to read it
5. **Check systing usage:** `grep -r "X" src/` to see if already used
6. **Refer to perfetto_protos:** Check how the Rust binding is named

## Example: Looking Up FtraceEvent

```bash
# 1. Find the message
$ grep -n "^message FtraceEvent" protos/perfetto_trace.proto
# Output: 12345:message FtraceEvent {

# 2. Read the definition
$ sed -n '12345,12445p' protos/perfetto_trace.proto

# 3. Check systing usage
$ grep -r "FtraceEvent" src/
# Output: src/sched.rs:use perfetto_protos::ftrace_event::FtraceEvent;
```

## Common Perfetto Concepts

### Tracks
Tracks are timelines that group related events. Types:
- **Process track** - Events for a process
- **Thread track** - Events for a thread
- **Counter track** - Time-series numeric data
- **Async track** - Asynchronous operations
- **Custom track** - User-defined groupings

### Interning
To reduce trace size, repeated strings/data are "interned":
1. String appears first in `InternedData` with an ID (iid)
2. Later references use the iid instead of the full string
3. Scoped to a packet sequence (sequence_id)

### Sequence Flags
- `SEQ_NEEDS_INCREMENTAL_STATE` - Reader needs interned data
- `SEQ_INCREMENTAL_STATE_CLEARED` - Interned data was reset

### Clock Domains
Common clocks:
- `BOOTTIME` - Default, counts during suspend
- `MONOTONIC` - Monotonic time, doesn't count suspend
- `REALTIME` - Wall-clock time
- `MONOTONIC_RAW` - Hardware time, no NTP adjustments

## Systing-Specific Notes

### Where Messages Are Used

See `perfetto-messages.md` for detailed usage patterns. Quick map:

- **src/main.rs** - Creates root `Trace` message
- **src/session_recorder.rs** - Process/thread descriptors, clock snapshots
- **src/perfetto.rs** - Track descriptor helpers
- **src/events.rs** - Probe event track events
- **src/sched.rs** - Ftrace scheduling events
- **src/stack_recorder.rs** - Perf samples and stack traces
- **src/network_recorder.rs** - Network events
- **src/perf_recorder.rs** - Performance counters

### Trace Assembly Flow

1. Record events to internal structures (ringbuffers, hashmaps)
2. Process events into Perfetto messages
3. Add all `TracePacket`s to a `Trace` message
4. Serialize to file using protobuf

### ID Management

Systing uses `Arc<AtomicUsize>` for generating unique IDs:
- Track UUIDs
- Interned string IIDs
- Sequence IDs

IDs must be unique within their scope (e.g., track UUIDs globally unique).
