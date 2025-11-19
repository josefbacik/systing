# Perfetto Protobuf Message Reference for Systing

This document describes the key Perfetto protobuf message types used by systing for generating trace files.

## Overview

Systing creates Perfetto-format trace files that can be visualized in tools like the Perfetto UI. The trace format is defined in protobuf and consists of a hierarchy of messages.

## Core Message Hierarchy

```
Trace (top-level)
└── TracePacket (repeated)
    ├── timestamp
    ├── trusted_packet_sequence_id
    ├── interned_data (InternedData)
    └── data (oneof):
        ├── track_descriptor (TrackDescriptor)
        ├── track_event (TrackEvent)
        ├── ftrace_events (FtraceEventBundle)
        ├── perf_sample (PerfSample)
        ├── process_tree (ProcessTree)
        ├── clock_snapshot (ClockSnapshot)
        ├── process_descriptor (ProcessDescriptor)
        └── thread_descriptor (ThreadDescriptor)
```

## Message Types Used by Systing

### 1. Trace (Line 17760)

**Purpose:** Top-level container for the entire trace file.

**Key Fields:**
- `repeated TracePacket packet` - All trace packets in the file

**Usage in Systing:**
- Created in `src/main.rs` as the root message
- All other packets are added to this container

### 2. TracePacket (Line 17480)

**Purpose:** The fundamental unit of data in a Perfetto trace. Each packet has a timestamp and contains one type of data.

**Key Fields:**
- `optional uint64 timestamp` - Timestamp in nanoseconds (default: CLOCK_BOOTTIME)
- `optional uint32 timestamp_clock_id` - Clock domain for the timestamp
- `optional uint32 trusted_packet_sequence_id` - Sequence ID (producer + writer pair)
- `optional InternedData interned_data` - Incrementally emitted interned strings/data
- `oneof data` - The actual payload (one of many types)

**Common data field values:**
- `TrackEvent track_event` - Events on tracks (slices, instants, counters)
- `TrackDescriptor track_descriptor` - Describes a track
- `FtraceEventBundle ftrace_events` - Linux ftrace events
- `ProcessTree process_tree` - Process hierarchy
- `ClockSnapshot clock_snapshot` - Clock synchronization
- `PerfSample perf_sample` - Perf sampling data (stack traces)

**Usage in Systing:**
- Created throughout the codebase for different event types
- session_recorder.rs: Process/thread descriptors, clock snapshots
- events.rs: Track events for probe events
- sched.rs: Ftrace events for scheduling
- stack_recorder.rs: Perf samples for stack traces
- network_recorder.rs: Network events

### 3. TrackDescriptor (Line 17046)

**Purpose:** Defines a track for events. Tracks group related events together (e.g., all events on a thread, or a custom counter track).

**Key Fields:**
- `optional uint64 uuid` - Unique ID for this track (global to the trace)
- `optional uint64 parent_uuid` - Parent track for nesting
- `optional string name` - Display name for the track
- `optional ProcessDescriptor process` - Associate with a process
- `optional ThreadDescriptor thread` - Associate with a thread
- `optional CounterDescriptor counter` - For counter tracks

**Usage in Systing:**
- `src/perfetto.rs`: `generate_pidtgid_track_descriptor()` - Creates process/thread tracks
- `src/perfetto.rs`: `generate_cpu_track_descriptors()` - Creates CPU-specific tracks
- `src/session_recorder.rs`: Creates frequency counter tracks
- `src/sched.rs`: Creates scheduler counter tracks
- `src/network_recorder.rs`: Creates network event tracks

**Track Types in Systing:**
1. Process tracks (parent for thread tracks)
2. Thread tracks (for thread-scoped events)
3. CPU tracks (for per-CPU events like scheduling)
4. Counter tracks (for time-series data like CPU frequency, network bytes)

### 4. TrackEvent (Line 14701)

**Purpose:** An event that occurs on a track at a specific timestamp.

**Key Fields:**
- `repeated string categories` - Event categories
- `optional string name` - Event name
- `optional Type type` - Event type (SLICE_BEGIN, SLICE_END, INSTANT, COUNTER)
- `optional uint64 track_uuid` - Which track this event belongs to
- `optional int64 counter_value` - Value for TYPE_COUNTER events
- `repeated DebugAnnotation debug_annotations` - Key-value annotations

**Event Types:**
- `TYPE_SLICE_BEGIN` - Start of a duration event (paired with TYPE_SLICE_END)
- `TYPE_SLICE_END` - End of a duration event
- `TYPE_INSTANT` - Instantaneous event (no duration)
- `TYPE_COUNTER` - Counter value update

**Usage in Systing:**
- `src/events.rs`: Creates track events for probe events (SLICE_BEGIN/END, INSTANT)
- `src/perfetto.rs`: `TrackCounter::to_track_event()` - Creates TYPE_COUNTER events
- `src/network_recorder.rs`: Creates instant events for network packets

**Common Patterns:**
```rust
// Counter event
let mut track_event = TrackEvent::default();
track_event.set_type(Type::TYPE_COUNTER);
track_event.set_counter_value(count);
track_event.set_track_uuid(track_uuid);

// Slice event (duration)
let mut begin_event = TrackEvent::default();
begin_event.set_type(Type::TYPE_SLICE_BEGIN);
begin_event.set_name("operation_name");
// ... later ...
let mut end_event = TrackEvent::default();
end_event.set_type(Type::TYPE_SLICE_END);

// Instant event
let mut instant = TrackEvent::default();
instant.set_type(Type::TYPE_INSTANT);
instant.set_name("event_name");
```

### 5. InternedData (Line 15172)

**Purpose:** Stores strings and other data that are referenced multiple times, to reduce trace size. Instead of repeating the same string, it's stored once with an ID (iid), and events reference it by ID.

**Key Fields:**
- `repeated EventName event_names` - Interned event names
- `repeated DebugAnnotationName debug_annotation_names` - Interned annotation names
- `repeated InternedString function_names` - Interned function names
- `repeated Mapping mappings` - Executable mappings
- `repeated Frame frames` - Stack frames
- `repeated Callstack callstacks` - Callstacks

**Usage in Systing:**
- `src/events.rs`: Interns event names for probe events
- `src/stack_recorder.rs`: Interns function names, mappings, frames, callstacks
- `src/network_recorder.rs`: Interns network event names

**SequenceFlags:**
- `SEQ_INCREMENTAL_STATE_CLEARED` - Indicates interned data was reset

### 6. DebugAnnotation (Line 13803)

**Purpose:** Arbitrary key-value pairs attached to events for additional context.

**Key Fields:**
- `optional string name` - Annotation key
- `oneof value` - The value (supports multiple types):
  - `bool bool_value`
  - `uint64 uint_value`
  - `int64 int_value`
  - `double double_value`
  - `string string_value`
  - `uint64 pointer_value`
  - `repeated DebugAnnotation dict_entries` - Nested dictionaries
  - `repeated DebugAnnotation array_values` - Arrays

**Usage in Systing:**
- `src/events.rs`: Attaches probe event arguments
- `src/network_recorder.rs`: Attaches network packet details (size, address, port)

**Example:**
```rust
let mut annotation = DebugAnnotation::default();
annotation.set_name("packet_size");
annotation.set_uint_value(packet_len as u64);
```

### 7. CounterDescriptor (Line 16957)

**Purpose:** Describes the metadata for a counter track.

**Key Fields:**
- `optional Unit unit` - Unit type for counter values
- `optional string unit_name` - Free-form unit name
- `optional bool is_incremental` - Whether values are deltas or absolute
- `repeated string categories` - Counter categories

**Unit Types:**
- `UNIT_TIME_NS` - Nanoseconds
- `UNIT_COUNT` - Dimensionless count
- `UNIT_SIZE_BYTES` - Bytes

**Usage in Systing:**
- `src/session_recorder.rs`: CPU frequency counters (UNIT_COUNT)
- `src/sched.rs`: Scheduler state counters
- `src/perf_recorder.rs`: Performance counters

### 8. FtraceEventBundle (Line 13017)

**Purpose:** Container for ftrace events from the Linux kernel.

**Key Fields:**
- `optional uint32 cpu` - CPU number
- `repeated FtraceEvent event` - Individual ftrace events
- `optional bool lost_events` - Data loss indicator
- `optional CompactSched compact_sched` - Compact encoding of sched events

**Usage in Systing:**
- `src/sched.rs`: Emits scheduling events (sched_switch, sched_waking)
- Uses CompactSched for efficient encoding

### 9. ProcessDescriptor / ThreadDescriptor (Line 16771)

**Purpose:** Describes process and thread metadata.

**ProcessDescriptor Fields:**
- `optional int32 pid` - Process ID
- `optional string process_name` - Process name
- `optional int32 ppid` - Parent process ID

**ThreadDescriptor Fields:**
- `optional int32 pid` - Thread ID
- `optional int32 tid` - Thread ID (same as pid for threads)
- `optional string thread_name` - Thread name

**Usage in Systing:**
- `src/session_recorder.rs`: Creates descriptors for processes and threads
- Embedded in TrackDescriptor messages

### 10. ProcessTree (Line ~16700)

**Purpose:** Snapshot of the process hierarchy at a point in time.

**Key Fields:**
- `repeated Process processes` - All processes

**Usage in Systing:**
- `src/session_recorder.rs`: Generates process tree from task_info events

### 11. ClockSnapshot (Line ~17000)

**Purpose:** Synchronizes different clock domains (BOOTTIME, MONOTONIC, REALTIME).

**Key Fields:**
- `repeated Clock clocks` - Clock values at the same instant

**Usage in Systing:**
- `src/session_recorder.rs`: `get_clock_value()` - Captures clock snapshots
- Ensures trace timestamps can be correlated with wall-clock time

### 12. PerfSample (Line ~17533)

**Purpose:** Contains perf sampling data, primarily stack traces.

**Key Fields:**
- `optional uint64 timestamp` - Sample timestamp
- `optional uint32 tid` - Thread ID
- `optional uint64 callstack_iid` - Reference to interned callstack

**Related Types:**
- `Callstack` - Sequence of frames
- `Frame` - Single stack frame (function name, file, line)
- `Mapping` - Executable/library mapping
- `InternedString` - Interned string data

**Usage in Systing:**
- `src/stack_recorder.rs`: Captures and interns stack traces

## Systing Usage Patterns

### Pattern 1: Creating a Counter Track

```rust
// 1. Create counter descriptor
let mut counter_desc = CounterDescriptor::default();
counter_desc.set_unit(Unit::UNIT_COUNT);

// 2. Create track descriptor
let mut desc = TrackDescriptor::default();
desc.set_name("Counter Name");
desc.set_uuid(unique_id);
desc.counter = Some(counter_desc).into();

// 3. Emit track descriptor packet
let mut packet = TracePacket::default();
packet.set_track_descriptor(desc);

// 4. Emit counter values
let mut track_event = TrackEvent::default();
track_event.set_type(Type::TYPE_COUNTER);
track_event.set_counter_value(value);
track_event.set_track_uuid(unique_id);

let mut packet = TracePacket::default();
packet.set_track_event(track_event);
packet.set_timestamp(ts);
```

### Pattern 2: Creating a Slice Event (Duration)

```rust
// 1. Emit BEGIN event
let mut begin_event = TrackEvent::default();
begin_event.set_type(Type::TYPE_SLICE_BEGIN);
begin_event.set_name("Operation");
begin_event.set_track_uuid(track_id);

let mut begin_packet = TracePacket::default();
begin_packet.set_track_event(begin_event);
begin_packet.set_timestamp(start_ts);

// 2. Emit END event
let mut end_event = TrackEvent::default();
end_event.set_type(Type::TYPE_SLICE_END);
end_event.set_track_uuid(track_id);

let mut end_packet = TracePacket::default();
end_packet.set_track_event(end_event);
end_packet.set_timestamp(end_ts);
```

### Pattern 3: String Interning

```rust
// 1. Add to InternedData
let mut interned = InternedData::default();
let mut event_name = EventName::default();
event_name.set_iid(name_iid);
event_name.set_name("event_name");
interned.event_names.push(event_name);

// 2. Set in packet with SEQ_INCREMENTAL_STATE_CLEARED
let mut packet = TracePacket::default();
packet.set_interned_data(interned);
packet.set_sequence_flags(SequenceFlags::SEQ_INCREMENTAL_STATE_CLEARED.into());

// 3. Reference by IID in later events
track_event.set_name_iid(name_iid);
```

### Pattern 4: Attaching Debug Annotations

```rust
let mut annotation = DebugAnnotation::default();
annotation.set_name("arg_name");
annotation.set_uint_value(value);

track_event.debug_annotations.push(annotation);
```

## File Organization in Systing

- **src/perfetto.rs** - Helper functions for creating TrackDescriptors and TrackEvents
- **src/session_recorder.rs** - Process/thread/clock management
- **src/events.rs** - Probe event recording (slices and instants)
- **src/sched.rs** - Ftrace scheduling events
- **src/stack_recorder.rs** - Perf samples and stack traces
- **src/network_recorder.rs** - Network packet events
- **src/perf_recorder.rs** - Performance counter events
- **src/main.rs** - Assembles final Trace message

## Proto File Location

Full protobuf definition: `protos/perfetto_trace.proto` (in this repository)

This is a ~18K line auto-generated file that merges all Perfetto proto definitions.

## Rust Bindings

Systing uses the `perfetto_protos` crate (version 0.48.1) which provides Rust bindings for these messages.

Import pattern:
```rust
use perfetto_protos::trace_packet::TracePacket;
use perfetto_protos::track_descriptor::TrackDescriptor;
use perfetto_protos::track_event::TrackEvent;
```
