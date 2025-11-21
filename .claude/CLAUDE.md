# Systing Development Guide for Claude

This document provides guidance for AI assistants working on the systing codebase.

## Project Overview

Systing is a Linux BPF (Berkeley Packet Filter) tracer that captures system-level events and generates trace files for performance analysis. It supports two output formats:
- **Perfetto protobuf**: Binary format for Perfetto UI visualization
- **SQLite database**: Relational format for SQL analysis

## Architecture

### Core Components

1. **BPF Programs** (`src/bpf/systing_system.bpf.c`)
   - Kernel-space event collection
   - Tracepoints, kprobes, uprob es for event capture
   - Ringbuffer delivery to userspace

2. **Recorders** (6 types)
   - `SchedEventRecorder` - Scheduler events (context switches, waking, IRQs)
   - `StackRecorder` - Stack traces with symbol resolution
   - `PerfCounterRecorder` - Hardware performance counters
   - `SystingProbeRecorder` - Custom USDT/kprobe/tracepoint events
   - `NetworkRecorder` - TCP/UDP connection tracking
   - `SysinfoRecorder` - CPU frequency monitoring

3. **Output Abstraction** (`src/output/`)
   - `TraceOutput` trait - Format-agnostic output interface
   - Intermediate data structures (`SchedEventData`, `StackTraceData`, etc.)
   - Decouples recorders from output formats

4. **Output Implementations**
   - `SqliteOutput` (`src/sqlite/writer.rs`) - SQLite database writer
   - Perfetto generation (existing `generate_trace()` methods)

5. **Format Conversion** (`src/convert/`)
   - Bidirectional conversion between Perfetto and SQLite
   - Auto-detection from file extensions

### Data Flow

```
BPF Programs → Ringbuffers → Recorder Threads → Recorders (in-memory)
→ TraceOutput trait → SqliteOutput OR Perfetto → trace.db OR trace.pb
```

## SQLite Implementation

### Schema Design Philosophy

**DO NOT replicate Perfetto's complex interning system**. The SQLite schema uses simple relational deduplication:
- Foreign keys instead of interned IDs
- UNIQUE constraints for deduplication
- Junction tables for many-to-many relationships

### Schema Structure (18 tables)

Core tables:
- `metadata` - Trace metadata (timestamps, version)
- `schema_version` - Schema versioning for migrations
- `clocks` - Clock synchronization
- `processes`, `threads` - Process/thread information
- `tracks` - Track descriptors (for event organization)

Event tables:
- `sched_events` - Scheduler events
- `symbols`, `stack_traces`, `stack_trace_frames` - Stack traces
- `perf_samples` - Performance samples with stacks
- `perf_counters`, `perf_counter_values` - Counter data
- `event_definitions`, `probe_events` - Custom probe events
- `network_connections`, `network_events` - Network traffic
- `cpu_frequency` - CPU frequency tracking

### Critical Design Decisions

1. **SHA-256 for Stack Hashing**: Uses `sha2` crate for deterministic, cross-platform hashing (NOT `DefaultHasher`)

2. **Junction Tables for Stacks**: `stack_trace_frames` table provides better queryability than JSON arrays

3. **Single Transaction + WAL Checkpoints**: Maximizes performance without intermediate commits

4. **Foreign Key Validation**: Pre-scan scheduler events to create placeholder processes/threads

5. **ID Independence**: SQLite IDs differ from Perfetto IIDs by design - tests verify semantic equivalence, not ID equality

### Adding New Event Types

To add a new event type to SQLite:

1. **Add intermediate type** in `src/output/types.rs`
2. **Add method to TraceOutput** trait in `src/output/mod.rs`
3. **Implement in SqliteOutput** (`src/sqlite/writer.rs`)
4. **Update recorder** to call new method in its `write_output()`
5. **Add schema table** if needed in `src/sqlite/schema.rs`
6. **Update conversion** in `src/convert/` for both directions

## Testing Philosophy

### Semantic Equivalence, Not ID Equality

**CRITICAL**: Tests must allow for ID changes between formats.

```rust
// ❌ WRONG: Comparing IDs
assert_eq!(original_frame.iid, converted_frame.iid);

// ✅ CORRECT: Comparing semantic content
assert_eq!(
    get_function_name(&original, original_frame.iid),
    get_function_name(&converted, converted_frame.iid)
);
```

Verify:
- ✅ Same number and types of events
- ✅ Same timestamps and relationships
- ✅ Same process/thread names (by PID/TID, not IID)
- ✅ Same stack traces (by symbol names, not frame IDs)
- ❌ Don't compare internal IDs

## Common Development Tasks

### Building and Testing

```bash
# Build
cargo build --release

# Run tests
cargo test

# Format code (required before commit)
cargo fmt

# Record SQLite trace
sudo ./target/release/systing record --format sqlite --duration 5

# Convert formats
./target/release/systing convert trace.pb trace.db
./target/release/systing convert trace.db trace.pb
```

### Git Workflow

Pre-commit hooks enforce `cargo fmt`. Enable with:
```bash
./setup-hooks.sh
```

Commit message format:
```
Brief description

Detailed explanation of changes

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>
```

## File Organization

```
src/
├── main.rs              # CLI and main recording loop
├── session_recorder.rs  # SessionRecorder and SysinfoRecorder
├── sched.rs             # SchedEventRecorder
├── stack_recorder.rs    # StackRecorder
├── perf_recorder.rs     # PerfCounterRecorder
├── events.rs            # SystingProbeRecorder
├── network_recorder.rs  # NetworkRecorder
├── output/
│   ├── mod.rs           # TraceOutput trait
│   └── types.rs         # Intermediate data structures
├── sqlite/
│   ├── mod.rs           # Module exports
│   ├── schema.rs        # SQLite schema definition
│   └── writer.rs        # SqliteOutput implementation
├── convert/
│   ├── mod.rs           # Module exports
│   ├── perfetto_to_sqlite.rs  # Perfetto → SQLite
│   └── sqlite_to_perfetto.rs  # SQLite → Perfetto
└── bpf/
    └── systing_system.bpf.c    # BPF programs
```

- Place all temporary files, scratch scripts, and working files in `./scratch/`
- Never create `.md`, `.py`, or `.sh` files in the project root unless explicitly requested
- The `scratch/` directory is gitignored

## Dependencies

Key dependencies:
- `libbpf-rs` - BPF program loading
- `perfetto_protos` - Perfetto protobuf definitions
- `rusqlite` - SQLite database interface
- `sha2` - Cryptographic hashing for stacks
- `blazesym` - Symbol resolution
- `clap` - CLI argument parsing

## Performance Considerations

1. **WAL Mode**: SQLite uses Write-Ahead Logging for better concurrency
2. **Prepared Statements**: Use `prepare_cached()` for frequent operations
3. **Single Transaction**: One transaction per trace for maximum performance
4. **Deduplication Caching**: In-memory caches reduce database queries
5. **Batch Operations**: Group operations where possible

## Troubleshooting

### Foreign Key Constraint Errors
- Check that parent processes exist before writing threads
- Verify scheduler events reference valid TIDs
- Use placeholder entries for missing parents

### WAL Checkpoint Warnings
- Non-fatal warnings during checkpoint
- Database is locked during writes (expected)
- Final commit ensures data persistence

### Symbol Resolution Issues
- Enable debuginfod: `--enable-debuginfod`
- Check symbol files are available
- Verify build IDs match

## Future Enhancements

Documented areas for improvement:
1. **Event Conversion**: Full event conversion in `convert/` module (currently basic metadata only)
2. **Schema Migrations**: Framework exists, needs migration implementations
3. **Query Optimization**: Additional composite indexes based on usage patterns
4. **Streaming Conversion**: Process large files in chunks
5. **Export Formats**: JSON, CSV, Parquet outputs

## Resources

- [Perfetto Protobuf Docs](context/perfetto_protos.md)
- [Implementation Plan](../SQLITE_IMPLEMENTATION_PLAN.md)
- [Usage Documentation](../docs/USAGE.adoc)
