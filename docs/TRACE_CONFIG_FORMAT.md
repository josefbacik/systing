# Systing Trace Configuration File Format

This document provides a comprehensive reference for writing JSON configuration files used with the `--trace-event-config` option in systing. These configuration files allow you to define custom trace events, capture arguments, and create visualization tracks in Perfetto.

## Table of Contents

- [Overview](#overview)
- [JSON Schema](#json-schema)
- [Event Types](#event-types)
- [Event Arguments](#event-arguments)
- [Track Types](#track-types)
- [Stop Triggers](#stop-triggers)
- [Complete Examples](#complete-examples)
- [Validation Rules](#validation-rules)
- [Best Practices](#best-practices)

## Overview

A trace configuration file is a JSON document that specifies:
1. **Events** - Which probe points to attach to and what data to capture
2. **Tracks** - How to visualize the captured events in Perfetto
3. **Stop Triggers** (optional) - Conditions to automatically stop tracing

## JSON Schema

The top-level structure of a trace configuration file:

```json
{
  "events": [ ... ],         // Required: Array of event definitions
  "tracks": [ ... ],         // Optional: Array of track definitions
  "stop_triggers": { ... }   // Optional: Trigger conditions to stop tracing
}
```

### Root Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `events` | Array of Event objects | **Yes** | Defines the trace events to capture |
| `tracks` | Array of Track objects | No | Defines how to visualize events in Perfetto |
| `stop_triggers` | StopTrigger object | No | Conditions to automatically stop tracing |

## Event Types

### Event Object Structure

```json
{
  "name": "event_name",
  "event": "<probe_specification>",
  "scope": "thread",
  "stack": false,
  "args": [ ... ]
}
```

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | String | **Yes** | - | Unique identifier for this event (used in tracks) |
| `event` | String | **Yes** | - | Probe specification (format depends on probe type) |
| `scope` | String | No | `"thread"` | Track attribution: `"thread"` (TGIDPID), `"process"` (TGID, for async tasks that migrate between threads), or `"cpu"` (per-CPU tracks) |
| `stack` | Boolean | No | `false` | If true, captures stack trace when event fires |
| `args` | Array of Argument objects | No | `[]` | Arguments to capture (max 4 per event) |

### Probe Type Formats

#### 1. USDT (User Statically-Defined Tracing)

Attach to USDT probe points in user-space applications.

**Format:** `usdt:<path>:<provider>:<name>`

```json
{
  "name": "mutex_entry",
  "event": "usdt:/usr/lib64/libc.so.6:libc:mutex_entry"
}
```

**Components:**
- `<path>` - Full path to the executable or library
- `<provider>` - USDT provider name (e.g., `libc`, `python`, `node`)
- `<name>` - Specific probe name within the provider

**Discovery:** Use `bpftrace -l 'usdt:<path>:*'` or examine with `readelf -n <binary>`

**Restrictions:**
- Optionally use `--trace-event-pid` to target specific process ID(s)
- If no PIDs specified, automatically discovers all processes with the binary/library loaded
- Not supported in confidentiality mode
- Path must be accessible to the profiled process

---

#### 2. uprobe/uretprobe (User-space Probes)

Attach to function entry/exit points in user-space binaries.

**Format (uprobe):** `uprobe:<path>:<symbol_or_offset>`

**Format (uretprobe):** `uretprobe:<path>:<symbol_or_offset>`

```json
{
  "name": "malloc_entry",
  "event": "uprobe:/lib/x86_64-linux-gnu/libc.so.6:malloc"
}
```

**Supported formats for `<symbol_or_offset>`:**
- `<offset>` - Numeric offset in hex (e.g., `0x1234`) or decimal
- `<symbol>` - Function symbol name (e.g., `malloc`)
- `<symbol>+<offset>` - Symbol with offset (e.g., `malloc+0x10`)

**Examples:**
```json
// Entry probe on malloc
{ "event": "uprobe:/lib/x86_64-linux-gnu/libc.so.6:malloc" }

// Return probe on malloc
{ "event": "uretprobe:/lib/x86_64-linux-gnu/libc.so.6:malloc" }

// Probe at specific offset
{ "event": "uprobe:/usr/bin/myapp:0x401000" }

// Probe at symbol + offset
{ "event": "uprobe:/usr/bin/myapp:process_request+0x24" }
```

**Restrictions:**
- Optionally use `--trace-event-pid` to target specific process ID(s)
- If no PIDs specified, automatically discovers all processes with the binary/library loaded
- Symbol must exist in the binary's symbol table
- `retval` argument type only valid for `uretprobe` (not `uprobe`)

---

#### 3. kprobe/kretprobe (Kernel Probes)

Attach to kernel function entry/exit points.

**Format (kprobe):** `kprobe:<symbol_or_offset>`

**Format (kretprobe):** `kretprobe:<symbol_or_offset>`

```json
{
  "name": "do_sys_open_entry",
  "event": "kprobe:do_sys_openat2"
}
```

**Supported formats for `<symbol_or_offset>`:**
- `<offset>` - Numeric kernel address offset
- `<symbol>` - Kernel function symbol name
- `<symbol>+<offset>` - Symbol with offset

**Examples:**
```json
// Entry probe
{ "event": "kprobe:tcp_sendmsg" }

// Return probe
{ "event": "kretprobe:tcp_sendmsg" }

// Probe with offset
{ "event": "kprobe:tcp_sendmsg+0x10" }
```

**Restrictions:**
- Must run with root/CAP_SYS_ADMIN privileges
- Function must be available in `/proc/kallsyms`
- `retval` argument type only valid for `kretprobe` (not `kprobe`)

---

#### 4. tracepoint

Attach to kernel tracepoint events.

**Format:** `tracepoint:<category>:<name>`

```json
{
  "name": "sched_switch",
  "event": "tracepoint:sched:sched_switch"
}
```

**Components:**
- `<category>` - Tracepoint subsystem (e.g., `sched`, `syscalls`, `net`)
- `<name>` - Specific tracepoint name

**Examples:**
```json
// Scheduler tracepoint
{ "event": "tracepoint:sched:sched_switch" }

// Syscall entry
{ "event": "tracepoint:syscalls:sys_enter_mmap" }

// Syscall exit
{ "event": "tracepoint:syscalls:sys_exit_mmap" }

// Network tracepoint
{ "event": "tracepoint:net:netif_receive_skb" }
```

**Discovery:** List available tracepoints:
```bash
ls /sys/kernel/debug/tracing/events/
ls /sys/kernel/debug/tracing/events/<category>/
cat /sys/kernel/debug/tracing/events/<category>/<name>/format
```

**⚠️ Kernel Version Requirement:**

**Capturing arguments from tracepoint events requires Linux kernel 6.10 or newer.**

Prior to kernel 6.10, the BPF `raw_tracepoint` infrastructure did not support `bpf_get_attach_cookie()`, which systing uses to capture tracepoint arguments.

- ✅ **Kernel 6.10+**: Tracepoint events with arguments fully supported
- ⚠️ **Kernel < 6.10**: Tracepoint events without arguments work; events WITH `args` will fail with an error

Check your kernel version:
```bash
uname -r
```

If you have kernel < 6.10:
- Use tracepoint events without `args` field
- Use `kprobe`/`uprobe` instead (work on all kernel versions)
- Upgrade to kernel 6.10+ for full tracepoint argument support

**Restrictions:**
- Argument capture requires kernel 6.10+ (see warning above)
- `retval` argument type not supported (use `sys_exit_*` tracepoints instead)
- Tracepoint must exist in `/sys/kernel/debug/tracing/events/`

## Event Arguments

The `args` field allows capturing probe arguments that appear as debug annotations in the Perfetto trace.

### Argument Object Structure

```json
{
  "arg_index": 0,
  "arg_type": "long",
  "arg_name": "size"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `arg_index` | Integer (0-7) | Conditional | Argument position (0-based). Required for `long` and `string`, must be 0 or omitted for `retval` |
| `arg_type` | String | **Yes** | Type of argument: `"long"`, `"string"`, or `"retval"` |
| `arg_name` | String | **Yes** | Name displayed in Perfetto annotations |

### Argument Types

#### `"long"` - 64-bit Integer

Captures a 64-bit integer argument.

```json
{
  "arg_index": 1,
  "arg_type": "long",
  "arg_name": "size"
}
```

**Use cases:**
- Numeric parameters (size, count, flags)
- Memory addresses
- File descriptors
- Return values from `sys_exit_*` tracepoints

**Valid for:** All probe types

---

#### `"string"` - String Pointer

Captures a null-terminated string from a pointer argument.

```json
{
  "arg_index": 0,
  "arg_type": "string",
  "arg_name": "filename"
}
```

**Use cases:**
- File paths
- Function names
- Error messages
- String parameters

**Valid for:** All probe types

**⚠️ Safety:** Ensure the pointer is valid in the probe context, or you may get truncated/empty strings.

---

#### `"retval"` - Return Value

Captures the function's return value. Only valid for return probes.

```json
{
  "arg_index": 0,
  "arg_type": "retval",
  "arg_name": "return_value"
}
```

**Requirements:**
- `arg_index` must be 0 or omitted
- Only valid for `kretprobe` and `uretprobe` events
- **NOT valid for tracepoints** (use `sys_exit_*` tracepoints with `arg_index: 0` instead)

**Valid for:** `kretprobe`, `uretprobe` only

### Argument Count Limit

**Maximum 4 arguments per event.**

```json
{
  "name": "syscall_enter",
  "event": "tracepoint:syscalls:sys_enter_mmap",
  "args": [
    { "arg_index": 0, "arg_type": "long", "arg_name": "addr" },
    { "arg_index": 1, "arg_type": "long", "arg_name": "length" },
    { "arg_index": 2, "arg_type": "long", "arg_name": "prot" },
    { "arg_index": 3, "arg_type": "long", "arg_name": "flags" }
    // Cannot add a 5th argument
  ]
}
```

### Argument Index Reference

For **tracepoint** events, argument indices correspond to the tracepoint definition. View the format:

```bash
cat /sys/kernel/debug/tracing/events/<category>/<name>/format
```

**Example: `sys_enter_mmap`**

```
name: sys_enter_mmap
ID: 718
format:
	field:unsigned short common_type;
	field:unsigned char common_flags;
	field:unsigned char common_preempt_count;
	field:int common_pid;

	field:int __syscall_nr;
	field:unsigned long addr;       <- arg_index: 0
	field:unsigned long len;        <- arg_index: 1
	field:unsigned long prot;       <- arg_index: 2
	field:unsigned long flags;      <- arg_index: 3
	field:unsigned long fd;         <- arg_index: 4
	field:unsigned long off;        <- arg_index: 5
```

For **uprobe/kprobe** events, argument indices follow the function's calling convention:
- x86_64: RDI (0), RSI (1), RDX (2), RCX (3), R8 (4), R9 (5), then stack
- ARM64: X0-X7 (0-7), then stack

## Track Types

Tracks define how events are visualized in Perfetto. A track groups related events together in the UI.

### Track Object Structure

```json
{
  "track_name": "My Track",
  "ranges": [ ... ],
  "instants": [ ... ]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `track_name` | String | **Yes** | Display name for the track in Perfetto |
| `ranges` | Array of Range objects | No | Duration events with start/end times |
| `instants` | Array of Instant objects | No | Point-in-time event markers |

**At least one of `ranges` or `instants` must be specified.**

### Range Tracks

Range tracks show duration events with explicit start and end times, useful for measuring time spent in operations.

#### Range Object Structure

```json
{
  "name": "operation_name",
  "start": "start_event_name",
  "end": "end_event_name"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | String | **Yes** | Label for this range in Perfetto |
| `start` | String | **Yes** | Name of event that starts the range |
| `end` | String | **Yes** | Name of event that ends the range |

#### Example: Mutex Locking

```json
{
  "events": [
    { "name": "mutex_entry", "event": "usdt:/lib/libc.so.6:libc:mutex_entry" },
    { "name": "mutex_acquired", "event": "usdt:/lib/libc.so.6:libc:mutex_acquired" },
    { "name": "mutex_release", "event": "usdt:/lib/libc.so.6:libc:mutex_release" }
  ],
  "tracks": [
    {
      "track_name": "Mutex Operations",
      "ranges": [
        {
          "name": "locking",
          "start": "mutex_entry",
          "end": "mutex_acquired"
        },
        {
          "name": "locked",
          "start": "mutex_acquired",
          "end": "mutex_release"
        }
      ]
    }
  ]
}
```

This creates a track showing:
- "locking" ranges: Time spent waiting to acquire the mutex
- "locked" ranges: Time the mutex was held

**Behavior:**
- Events are matched per-thread by default
- Multiple concurrent ranges on the same thread will nest
- Unmatched start/end events are ignored (no error)

---

### Instant Tracks

Instant tracks show point-in-time event markers, useful for logging specific occurrences.

#### Instant Object Structure

```json
{
  "event": "event_name"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `event` | String | **Yes** | Name of event to display as instant marker |

#### Example: Instant Events

```json
{
  "events": [
    { "name": "allocation", "event": "kprobe:kmalloc" },
    { "name": "free", "event": "kprobe:kfree" }
  ],
  "tracks": [
    {
      "track_name": "Memory Events",
      "instants": [
        { "event": "allocation" },
        { "event": "free" }
      ]
    }
  ]
}
```

This creates a track with instant markers for each kmalloc/kfree call.

**Use cases:**
- Logging specific function calls
- Marking important state changes
- Recording events without duration

---

### Multiple Tracks

You can define multiple tracks to organize events:

```json
{
  "events": [
    { "name": "lock_enter", "event": "kprobe:mutex_lock" },
    { "name": "lock_exit", "event": "kretprobe:mutex_lock" },
    { "name": "unlock", "event": "kprobe:mutex_unlock" }
  ],
  "tracks": [
    {
      "track_name": "Lock Duration",
      "ranges": [
        { "name": "locking", "start": "lock_enter", "end": "lock_exit" }
      ]
    },
    {
      "track_name": "Lock Events",
      "instants": [
        { "event": "lock_enter" },
        { "event": "unlock" }
      ]
    }
  ]
}
```

## Stop Triggers

Stop triggers allow automatic termination of tracing when specific conditions are met. Useful for capturing rare events or threshold violations.

### StopTrigger Object Structure

```json
{
  "thresholds": [ ... ],
  "instants": [ ... ]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `thresholds` | Array of Threshold objects | No | Duration-based triggers |
| `instants` | Array of Instant objects | No | Event-based triggers |

### Threshold Triggers

Stop tracing when a duration exceeds a threshold.

#### Threshold Object Structure

```json
{
  "start": "start_event_name",
  "end": "end_event_name",
  "duration_us": 1000000
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `start` | String | **Yes** | Event that starts the duration measurement |
| `end` | String | **Yes** | Event that ends the duration measurement |
| `duration_us` | Integer | **Yes** | Threshold in microseconds |

#### Example: Stop on Long Mutex Hold

```json
{
  "events": [
    { "name": "mutex_acquired", "event": "usdt:/lib/libc.so.6:libc:mutex_acquired" },
    { "name": "mutex_release", "event": "usdt:/lib/libc.so.6:libc:mutex_release" }
  ],
  "stop_triggers": {
    "thresholds": [
      {
        "start": "mutex_acquired",
        "end": "mutex_release",
        "duration_us": 1000000
      }
    ]
  }
}
```

This stops tracing if any mutex is held for more than 1 second (1,000,000 microseconds).

**Use with `--continuous`:**
```bash
sudo systing --continuous 60 --trace-event-config config.json
```

Tracing runs in a 60-second rolling buffer until the threshold is exceeded.

---

### Instant Triggers

Stop tracing when a specific event fires.

```json
{
  "events": [
    { "name": "error_handler", "event": "kprobe:handle_error" }
  ],
  "stop_triggers": {
    "instants": [
      { "event": "error_handler" }
    ]
  }
}
```

This stops tracing immediately when `handle_error` is called.

## Complete Examples

### Example 1: Basic USDT Tracing

```json
{
  "events": [
    {
      "name": "mutex_entry",
      "event": "usdt:/usr/lib64/libc.so.6:libc:mutex_entry"
    },
    {
      "name": "mutex_acquired",
      "event": "usdt:/usr/lib64/libc.so.6:libc:mutex_acquired"
    },
    {
      "name": "mutex_release",
      "event": "usdt:/usr/lib64/libc.so.6:libc:mutex_release"
    }
  ],
  "tracks": [
    {
      "track_name": "pthread_mutex",
      "ranges": [
        {
          "name": "locking",
          "start": "mutex_entry",
          "end": "mutex_acquired"
        },
        {
          "name": "locked",
          "start": "mutex_acquired",
          "end": "mutex_release"
        }
      ]
    }
  ]
}
```

**Usage:**
```bash
sudo systing --duration 30 --trace-event-config pthread.json --trace-event-pid 12345
```

---

### Example 2: Syscall Tracing with Arguments (Kernel 6.10+)

```json
{
  "events": [
    {
      "name": "mmap_enter",
      "event": "tracepoint:syscalls:sys_enter_mmap",
      "stack": true,
      "args": [
        { "arg_index": 1, "arg_type": "long", "arg_name": "size" },
        { "arg_index": 2, "arg_type": "long", "arg_name": "prot" },
        { "arg_index": 3, "arg_type": "long", "arg_name": "flags" }
      ]
    },
    {
      "name": "mmap_exit",
      "event": "tracepoint:syscalls:sys_exit_mmap",
      "args": [
        { "arg_index": 0, "arg_type": "long", "arg_name": "addr" }
      ]
    }
  ],
  "tracks": [
    {
      "track_name": "mmap calls",
      "instants": [
        { "event": "mmap_enter" }
      ]
    }
  ]
}
```

**Usage:**
```bash
sudo systing --duration 30 --trace-event-config mmap.json --trace-event-pid 12345
```

---

### Example 3: Kernel Probes with Return Value

```json
{
  "events": [
    {
      "name": "tcp_sendmsg_entry",
      "event": "kprobe:tcp_sendmsg",
      "args": [
        { "arg_index": 2, "arg_type": "long", "arg_name": "size" }
      ]
    },
    {
      "name": "tcp_sendmsg_exit",
      "event": "kretprobe:tcp_sendmsg",
      "args": [
        { "arg_type": "retval", "arg_name": "bytes_sent" }
      ]
    }
  ],
  "tracks": [
    {
      "track_name": "TCP Send",
      "ranges": [
        {
          "name": "sending",
          "start": "tcp_sendmsg_entry",
          "end": "tcp_sendmsg_exit"
        }
      ]
    }
  ]
}
```

**Usage:**
```bash
sudo systing --duration 30 --trace-event-config tcp.json
```

---

### Example 4: Threshold Trigger with Continuous Mode

```json
{
  "events": [
    {
      "name": "request_start",
      "event": "uprobe:/usr/bin/myapp:handle_request"
    },
    {
      "name": "request_end",
      "event": "uretprobe:/usr/bin/myapp:handle_request"
    }
  ],
  "tracks": [
    {
      "track_name": "Request Processing",
      "ranges": [
        {
          "name": "request",
          "start": "request_start",
          "end": "request_end"
        }
      ]
    }
  ],
  "stop_triggers": {
    "thresholds": [
      {
        "start": "request_start",
        "end": "request_end",
        "duration_us": 500000
      }
    ]
  }
}
```

**Usage:**
```bash
sudo systing --continuous 60 --trace-event-config slow_request.json --trace-event-pid 12345
```

Traces in a 60-second rolling buffer and stops when any request takes longer than 500ms.

---

### Example 5: Per-CPU Events

```json
{
  "events": [
    {
      "name": "sched_switch",
      "event": "tracepoint:sched:sched_switch",
      "scope": "cpu"
    }
  ],
  "tracks": [
    {
      "track_name": "Context Switches",
      "instants": [
        { "event": "sched_switch" }
      ]
    }
  ]
}
```

**Usage:**
```bash
sudo systing --duration 10 --trace-event-config sched.json
```

Creates a separate "Context Switches" track for each CPU in the system.

## Validation Rules

### Event Validation

1. **Event names must be unique** within a configuration file
2. **Maximum 4 arguments per event**
3. **Argument type restrictions:**
   - `retval` only valid for `kretprobe` and `uretprobe`
   - `retval` must have `arg_index: 0` or omitted
   - Tracepoint argument capture requires kernel 6.10+
4. **Probe format requirements:**
   - USDT: `usdt:<path>:<provider>:<name>` (4 parts)
   - uprobe/uretprobe: `<type>:<path>:<symbol_or_offset>` (3 parts)
   - kprobe/kretprobe: `<type>:<symbol_or_offset>` (2 parts)
   - tracepoint: `tracepoint:<category>:<name>` (3 parts)

### Track Validation

1. **Track must have at least one of `ranges` or `instants`**
2. **Event references in tracks must exist in events array**
3. **Range start/end events must be valid event names**

### Stop Trigger Validation

1. **Threshold start/end events must exist in events array**
2. **Threshold duration_us must be positive**
3. **Instant trigger events must exist in events array**

### Common Errors

**Error: "Maximum 4 args allowed per event"**
```json
// ❌ TOO MANY ARGS
{
  "args": [
    { "arg_index": 0, "arg_type": "long", "arg_name": "arg0" },
    { "arg_index": 1, "arg_type": "long", "arg_name": "arg1" },
    { "arg_index": 2, "arg_type": "long", "arg_name": "arg2" },
    { "arg_index": 3, "arg_type": "long", "arg_name": "arg3" },
    { "arg_index": 4, "arg_type": "long", "arg_name": "arg4" }  // Error!
  ]
}
```

**Error: "retval arg type is only valid for kretprobe and uretprobe events"**
```json
// ❌ RETVAL ON WRONG PROBE TYPE
{
  "name": "syscall_exit",
  "event": "tracepoint:syscalls:sys_exit_open",
  "args": [
    { "arg_type": "retval", "arg_name": "result" }  // Error! Use arg_index: 0 instead
  ]
}

// ✅ CORRECT - Use arg_index for tracepoint sys_exit
{
  "name": "syscall_exit",
  "event": "tracepoint:syscalls:sys_exit_open",
  "args": [
    { "arg_index": 0, "arg_type": "long", "arg_name": "result" }
  ]
}
```

**Error: "arg_index must be 0 or omitted for retval type"**
```json
// ❌ RETVAL WITH NON-ZERO ARG_INDEX
{
  "event": "kretprobe:do_sys_open",
  "args": [
    { "arg_index": 1, "arg_type": "retval", "arg_name": "fd" }  // Error!
  ]
}

// ✅ CORRECT
{
  "event": "kretprobe:do_sys_open",
  "args": [
    { "arg_type": "retval", "arg_name": "fd" }  // arg_index omitted or 0
  ]
}
```

**Error: "Cannot capture tracepoint arguments on kernel < 6.10"**
```json
// ❌ TRACEPOINT WITH ARGS ON OLD KERNEL
{
  "event": "tracepoint:syscalls:sys_enter_mmap",
  "args": [
    { "arg_index": 1, "arg_type": "long", "arg_name": "size" }  // Error on kernel < 6.10
  ]
}

// ✅ WORKAROUND 1: Remove args
{
  "event": "tracepoint:syscalls:sys_enter_mmap"
  // No args field
}

// ✅ WORKAROUND 2: Use kprobe instead (works on all kernels)
{
  "event": "kprobe:__x64_sys_mmap"
}
```

## Best Practices

### 1. Event Naming

Use descriptive, consistent names:

```json
// ✅ GOOD - Clear, consistent naming
{
  "name": "malloc_entry",
  "event": "uprobe:/lib/libc.so.6:malloc"
}
{
  "name": "malloc_exit",
  "event": "uretprobe:/lib/libc.so.6:malloc"
}

// ❌ BAD - Unclear names
{
  "name": "e1",
  "event": "uprobe:/lib/libc.so.6:malloc"
}
{
  "name": "malloc_2",
  "event": "uretprobe:/lib/libc.so.6:malloc"
}
```

---

### 2. Stack Traces

Only enable stack traces when needed, as they add significant overhead:

```json
// ✅ GOOD - Stack traces only on entry
{
  "name": "malloc_entry",
  "event": "uprobe:/lib/libc.so.6:malloc",
  "stack": true
}
{
  "name": "malloc_exit",
  "event": "uretprobe:/lib/libc.so.6:malloc",
  "stack": false  // No need for stack on exit
}

// ❌ BAD - Unnecessary stack traces everywhere
{
  "name": "frequent_event",
  "event": "tracepoint:sched:sched_switch",
  "stack": true  // High overhead on frequent event!
}
```

---

### 3. Argument Selection

Capture only necessary arguments:

```json
// ✅ GOOD - Only capture relevant args
{
  "name": "mmap_enter",
  "event": "tracepoint:syscalls:sys_enter_mmap",
  "args": [
    { "arg_index": 1, "arg_type": "long", "arg_name": "size" }
  ]
}

// ❌ BAD - Capturing unnecessary arguments
{
  "name": "mmap_enter",
  "event": "tracepoint:syscalls:sys_enter_mmap",
  "args": [
    { "arg_index": 0, "arg_type": "long", "arg_name": "addr" },
    { "arg_index": 1, "arg_type": "long", "arg_name": "size" },
    { "arg_index": 2, "arg_type": "long", "arg_name": "prot" },
    { "arg_index": 3, "arg_type": "long", "arg_name": "flags" }
  ]
}
```

---

### 4. Track Organization

Group related events logically:

```json
// ✅ GOOD - Logical grouping
{
  "tracks": [
    {
      "track_name": "Mutex Operations",
      "ranges": [
        { "name": "locking", "start": "mutex_entry", "end": "mutex_acquired" },
        { "name": "locked", "start": "mutex_acquired", "end": "mutex_release" }
      ]
    },
    {
      "track_name": "Memory Allocations",
      "instants": [
        { "event": "malloc" },
        { "event": "free" }
      ]
    }
  ]
}

// ❌ BAD - Mixing unrelated events
{
  "tracks": [
    {
      "track_name": "Everything",
      "ranges": [
        { "name": "locking", "start": "mutex_entry", "end": "mutex_acquired" }
      ],
      "instants": [
        { "event": "malloc" },
        { "event": "syscall_open" },
        { "event": "network_send" }
      ]
    }
  ]
}
```

---

### 5. Testing and Iteration

Start simple and add complexity:

1. **Step 1:** Basic events without arguments
2. **Step 2:** Add necessary arguments
3. **Step 3:** Add stack traces where needed
4. **Step 4:** Add tracks for visualization
5. **Step 5:** Add stop triggers if needed

```bash
# Test configuration syntax
jq . config.json

# Test with short duration first
sudo systing --duration 5 --trace-event-config config.json --trace-event-pid <pid>

# Verify events in Perfetto
# Upload trace.pb.gz to https://ui.perfetto.dev

# Increase duration once verified
sudo systing --duration 60 --trace-event-config config.json --trace-event-pid <pid>
```

---

### 6. Kernel Version Compatibility

Always check kernel compatibility for tracepoint arguments:

```json
// ✅ GOOD - Include kernel version comment
{
  "comment": "Requires kernel 6.10+ for tracepoint argument capture",
  "events": [
    {
      "name": "mmap_enter",
      "event": "tracepoint:syscalls:sys_enter_mmap",
      "args": [
        { "arg_index": 1, "arg_type": "long", "arg_name": "size" }
      ]
    }
  ]
}

// ✅ ALTERNATIVE - Provide fallback config for older kernels
// config-new.json (kernel 6.10+)
{
  "events": [
    {
      "name": "mmap_enter",
      "event": "tracepoint:syscalls:sys_enter_mmap",
      "args": [...]
    }
  ]
}

// config-old.json (kernel < 6.10)
{
  "events": [
    {
      "name": "mmap_enter",
      "event": "kprobe:__x64_sys_mmap"
    }
  ]
}
```

## Troubleshooting

### Configuration Not Loading

**Check JSON syntax:**
```bash
jq . config.json
```

If this fails, you have invalid JSON.

---

### Events Not Firing

**For USDT/uprobe events:**
1. Verify process ID is correct: `ps -p <pid>`
2. Check probe exists: `bpftrace -l 'usdt:<path>:*'`
3. Ensure `--trace-event-pid` is specified

**For kprobe events:**
1. Verify function exists: `grep <function> /proc/kallsyms`
2. Check function is not inlined
3. Try with `kprobe:<function>+0x0` for function entry

**For tracepoint events:**
1. Check tracepoint exists: `ls /sys/kernel/debug/tracing/events/<category>/<name>/`
2. Verify tracepoint is enabled: `cat /sys/kernel/debug/tracing/events/<category>/<name>/enable`
3. For argument capture on kernel < 6.10, see kernel version error

---

### Arguments Not Showing

1. **Verify argument indices match probe definition:**
   ```bash
   cat /sys/kernel/debug/tracing/events/<category>/<name>/format
   ```

2. **Check argument type is correct** (long vs string)

3. **Ensure maximum 4 arguments** per event

4. **For tracepoints:** Verify kernel version 6.10+ if capturing arguments

---

### Track Not Appearing in Perfetto

1. **Verify events are firing** (check instant track for same events)
2. **Check event names match** between events and track references
3. **For range tracks:** Ensure start/end events are paired (same thread)
4. **Try instant track first** to verify events are captured

---

### Permission Errors

**Error: "Failed to attach probe"**
- Run with `sudo`
- Check process exists and is accessible
- For confidentiality mode: USDT probes not supported

## Additional Resources

- **Perfetto Documentation:** https://perfetto.dev/
- **BPF Documentation:** https://www.kernel.org/doc/html/latest/bpf/
- **bpftrace Tutorial:** https://github.com/iovisor/bpftrace/blob/master/docs/tutorial_one_liners.md
- **Systing Examples:** See `examples/` directory in repository
- **Command-Line Options:** See `docs/USAGE.adoc`

## Summary

This document covered:
- ✅ Complete JSON schema for trace configuration files
- ✅ All 4 event types: USDT, uprobe/uretprobe, kprobe/kretprobe, tracepoint
- ✅ Argument capture with 3 types: long, string, retval
- ✅ Track visualization: ranges and instants
- ✅ Stop triggers: thresholds and instants
- ✅ Validation rules and restrictions
- ✅ Complete examples and best practices
- ✅ Kernel version compatibility (6.10+ for tracepoint args)

For questions or issues, please refer to the main documentation or file an issue in the repository.
