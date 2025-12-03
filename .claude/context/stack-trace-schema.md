# Stack Trace Schema in systing-analyze

This document describes how stack traces are stored in DuckDB after conversion from Perfetto traces.

## Overview

Stack traces are stored using a **parent-child callsite tree** structure that:
- Deduplicates common stack prefixes for space efficiency
- Enables efficient recursive queries for stack reconstruction
- Supports flame graph generation and hot function analysis

## Tables

### `perf_sample`
Links timestamps to stack traces. This is the main entry point for analysis.

| Column | Type | Description |
|--------|------|-------------|
| trace_id | VARCHAR | Trace identifier |
| ts | BIGINT | Timestamp in nanoseconds |
| utid | BIGINT | FK to `thread.utid` |
| callsite_id | BIGINT | FK to `stack_profile_callsite.id` (the leaf/top frame) |
| cpu | INTEGER | CPU number where sample was taken |

### `stack_profile_callsite`
Tree structure representing call stacks. Each row is a single frame in a stack.

| Column | Type | Description |
|--------|------|-------------|
| trace_id | VARCHAR | Trace identifier |
| id | BIGINT | Unique callsite ID |
| parent_id | BIGINT | FK to parent callsite (NULL for root frames) |
| frame_id | BIGINT | FK to `stack_profile_frame.id` |
| depth | INTEGER | Depth hint (0 = leaf). Note: may be inconsistent due to callsite reuse |

**Important**: The `parent_id` chain is the authoritative way to reconstruct stacks. The `depth` column is a hint that may be inconsistent when callsites are reused across different stack depths.

### `stack_profile_frame`
Individual stack frames with resolved function names.

| Column | Type | Description |
|--------|------|-------------|
| trace_id | VARCHAR | Trace identifier |
| id | BIGINT | Unique frame ID |
| name | VARCHAR | Resolved function name (e.g., "tcp_sendmsg (kernel)") |
| mapping_id | BIGINT | FK to `stack_profile_mapping.id` |
| rel_pc | BIGINT | Relative program counter |
| symbol_id | BIGINT | FK to `stack_profile_symbol.id` |

### `stack_profile_symbol`
Deduplicated function name strings.

| Column | Type | Description |
|--------|------|-------------|
| trace_id | VARCHAR | Trace identifier |
| id | BIGINT | Unique symbol ID |
| name | VARCHAR | Function name string |

### `stack_profile_mapping`
Executable mappings (shared libraries, kernel, etc.).

| Column | Type | Description |
|--------|------|-------------|
| trace_id | VARCHAR | Trace identifier |
| id | BIGINT | Unique mapping ID |
| build_id | VARCHAR | Build ID of the binary |
| name | VARCHAR | Path or name (e.g., "libc.so.6", "[kernel]") |
| exact_offset | BIGINT | Offset into the mapped file |
| start_offset | BIGINT | Start offset of first mapping |

## Data Model

```
perf_sample
    │
    └── callsite_id ──► stack_profile_callsite (leaf frame, depth=0)
                              │
                              ├── frame_id ──► stack_profile_frame ──► stack_profile_symbol
                              │                       │
                              │                       └── mapping_id ──► stack_profile_mapping
                              │
                              └── parent_id ──► stack_profile_callsite (depth=1)
                                                    │
                                                    └── parent_id ──► ... (continues to root)
```

## Common Queries

### 1. Hot Functions (Leaf Frames)
Find the most frequently sampled functions at the top of the stack:

```sql
SELECT f.name, COUNT(*) as samples
FROM perf_sample ps
JOIN stack_profile_callsite c ON ps.callsite_id = c.id
JOIN stack_profile_frame f ON c.frame_id = f.id
GROUP BY f.name
ORDER BY samples DESC
LIMIT 20;
```

### 2. Reconstruct a Full Stack
Walk from leaf to root to see the complete call chain:

```sql
WITH RECURSIVE stack_walk AS (
    -- Start at the leaf callsite
    SELECT id, parent_id, frame_id, 0 as level
    FROM stack_profile_callsite
    WHERE id = <callsite_id>

    UNION ALL

    -- Walk up to parent
    SELECT c.id, c.parent_id, c.frame_id, sw.level + 1
    FROM stack_profile_callsite c
    JOIN stack_walk sw ON c.id = sw.parent_id
)
SELECT sw.level, f.name
FROM stack_walk sw
JOIN stack_profile_frame f ON sw.frame_id = f.id
ORDER BY sw.level;  -- 0 = leaf/top, higher = deeper/root
```

### 3. Find Stacks Containing a Function
Find all samples where a specific function appears anywhere in the stack:

```sql
WITH RECURSIVE leaf_to_root AS (
    -- Start from all sampled leaf callsites
    SELECT c.id as leaf_id, c.id, c.parent_id, c.frame_id
    FROM stack_profile_callsite c
    WHERE c.id IN (SELECT DISTINCT callsite_id FROM perf_sample WHERE callsite_id > 0)

    UNION ALL

    -- Walk up the tree
    SELECT lr.leaf_id, p.id, p.parent_id, p.frame_id
    FROM leaf_to_root lr
    JOIN stack_profile_callsite p ON lr.parent_id = p.id
)
SELECT COUNT(DISTINCT leaf_id) as matching_stacks
FROM leaf_to_root lr
JOIN stack_profile_frame f ON lr.frame_id = f.id
WHERE f.name LIKE '%tcp_sendmsg%';
```

### 4. Stacks for a Specific Thread
Get all stack samples for a particular thread:

```sql
SELECT ps.ts, ps.callsite_id, f.name as leaf_function
FROM perf_sample ps
JOIN thread t ON ps.utid = t.utid
JOIN stack_profile_callsite c ON ps.callsite_id = c.id
JOIN stack_profile_frame f ON c.frame_id = f.id
WHERE t.tid = 1234
ORDER BY ps.ts;
```

### 5. Flame Graph Data
Aggregate samples by stack for flame graph visualization:

```sql
WITH RECURSIVE stack_walk AS (
    SELECT
        ps.callsite_id as leaf_id,
        c.id, c.parent_id, c.frame_id,
        ARRAY[f.name] as stack_path
    FROM perf_sample ps
    JOIN stack_profile_callsite c ON ps.callsite_id = c.id
    JOIN stack_profile_frame f ON c.frame_id = f.id
    WHERE ps.callsite_id > 0

    UNION ALL

    SELECT
        sw.leaf_id,
        p.id, p.parent_id, p.frame_id,
        array_append(sw.stack_path, f.name)
    FROM stack_walk sw
    JOIN stack_profile_callsite p ON sw.parent_id = p.id
    JOIN stack_profile_frame f ON p.frame_id = f.id
)
SELECT stack_path, COUNT(*) as samples
FROM stack_walk
WHERE parent_id IS NULL  -- Only complete stacks (reached root)
GROUP BY stack_path
ORDER BY samples DESC
LIMIT 100;
```

### 6. Correlate with Thread State
Find what stacks were active during blocked/sleeping states:

```sql
SELECT f.name as function, ts.state, COUNT(*) as samples
FROM perf_sample ps
JOIN stack_profile_callsite c ON ps.callsite_id = c.id
JOIN stack_profile_frame f ON c.frame_id = f.id
JOIN thread_state ts ON ps.utid = ts.utid
    AND ps.ts >= ts.ts
    AND ps.ts < ts.ts + ts.dur
WHERE ts.state IN ('S', 'D')  -- Sleeping or Disk sleep
GROUP BY f.name, ts.state
ORDER BY samples DESC
LIMIT 20;
```

## Design Notes

### Callsite Deduplication
The same callsite can be the parent of multiple different leaf frames. This significantly reduces storage for traces with many samples sharing common stack prefixes. For example, if 1000 samples all have `main() -> foo() -> bar()` at the bottom, those 3 callsites are stored once and reused.

### Depth Column Caveat
Due to callsite reuse, the `depth` column may not accurately reflect the actual depth in all stacks. Always use the recursive `parent_id` walk to get accurate stack reconstruction. The `depth` column is useful as a hint but not authoritative.

### Samples with callsite_id = 0
Some samples may have `callsite_id = 0` which means no stack was captured (e.g., stack unwinding failed). Filter these out with `WHERE callsite_id > 0`.

### Frame Name Format
Function names typically include:
- Function name
- Library/binary name in parentheses
- Relative address in angle brackets

Example: `tcp_sendmsg_locked (unknown) <0xffffffff8ec7559e>`

The "unknown" indicates the binary wasn't identified; kernel functions often show this way.
