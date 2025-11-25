-- ============================================================================
-- Systing Trace Analysis SQL Queries
-- ============================================================================
-- Usage: trace_processor trace.pb -q trace_queries.sql
-- Or interactively: trace_processor trace.pb
--                   > .read trace_queries.sql
-- ============================================================================

-- ============================================================================
-- SCHEDULING LATENCY ANALYSIS
-- ============================================================================

-- System-wide scheduling latency percentiles
SELECT
    'System-wide Scheduling Latency' as metric,
    COUNT(*) as total_samples,
    CAST(MIN(dur) / 1000.0 AS INTEGER) as min_us,
    CAST(AVG(dur) / 1000.0 AS INTEGER) as avg_us,
    CAST(MAX(dur) / 1000.0 AS INTEGER) as max_us
FROM sched_slice
WHERE dur > 0;

-- Per-CPU scheduling statistics
SELECT
    cpu,
    COUNT(*) as context_switches,
    CAST(AVG(dur) / 1000.0 AS INTEGER) as avg_latency_us,
    CAST(MAX(dur) / 1000.0 AS INTEGER) as max_latency_us,
    CAST(SUM(dur) / 1e9 AS REAL) as total_time_sec
FROM sched_slice
WHERE dur > 0
GROUP BY cpu
ORDER BY cpu;

-- Top 20 processes by maximum scheduling latency
SELECT
    p.name as process,
    p.pid,
    COUNT(*) as samples,
    CAST(AVG(s.dur) / 1000.0 AS INTEGER) as avg_us,
    CAST(MAX(s.dur) / 1000.0 AS INTEGER) as max_us,
    CAST(SUM(s.dur) / 1e6 AS REAL) as total_ms
FROM sched_slice s
JOIN thread t ON s.utid = t.utid
JOIN process p ON t.upid = p.upid
WHERE s.dur > 0 AND p.pid > 0
GROUP BY p.pid
ORDER BY max_us DESC
LIMIT 20;

-- Top 20 threads by maximum scheduling latency
SELECT
    p.name as process,
    t.name as thread,
    t.tid,
    COUNT(*) as samples,
    CAST(AVG(s.dur) / 1000.0 AS INTEGER) as avg_us,
    CAST(MAX(s.dur) / 1000.0 AS INTEGER) as max_us
FROM sched_slice s
JOIN thread t ON s.utid = t.utid
JOIN process p ON t.upid = p.upid
WHERE s.dur > 0 AND p.pid > 0
GROUP BY t.tid
ORDER BY max_us DESC
LIMIT 20;


-- ============================================================================
-- LONG BLOCKING / UNINTERRUPTIBLE SLEEP ANALYSIS
-- ============================================================================

-- Find all scheduling events > 10ms (potential D-state or lock contention)
SELECT
    p.name as process,
    p.pid,
    t.name as thread,
    t.tid,
    CAST(s.ts / 1e9 AS REAL) as time_sec,
    CAST(s.dur / 1e6 AS REAL) as duration_ms,
    s.end_state as state
FROM sched_slice s
JOIN thread t ON s.utid = t.utid
JOIN process p ON t.upid = p.upid
WHERE s.dur > 10000000  -- > 10ms
AND p.pid > 0
ORDER BY s.dur DESC
LIMIT 50;

-- Group long blocking events by process
SELECT
    p.name as process,
    p.pid,
    COUNT(*) as blocking_events,
    CAST(AVG(s.dur) / 1e6 AS REAL) as avg_ms,
    CAST(MAX(s.dur) / 1e6 AS REAL) as max_ms,
    CAST(SUM(s.dur) / 1e6 AS REAL) as total_blocked_ms
FROM sched_slice s
JOIN thread t ON s.utid = t.utid
JOIN process p ON t.upid = p.upid
WHERE s.dur > 10000000  -- > 10ms
AND p.pid > 0
GROUP BY p.pid
ORDER BY total_blocked_ms DESC
LIMIT 20;

-- Group long blocking events by thread
SELECT
    p.name as process,
    t.name as thread,
    t.tid,
    COUNT(*) as blocking_events,
    CAST(AVG(s.dur) / 1e6 AS REAL) as avg_ms,
    CAST(MAX(s.dur) / 1e6 AS REAL) as max_ms,
    CAST(SUM(s.dur) / 1e6 AS REAL) as total_blocked_ms
FROM sched_slice s
JOIN thread t ON s.utid = t.utid
JOIN process p ON t.upid = p.upid
WHERE s.dur > 10000000  -- > 10ms
AND p.pid > 0
GROUP BY t.tid
ORDER BY total_blocked_ms DESC
LIMIT 30;

-- Histogram of blocking durations
SELECT
    CASE
        WHEN dur < 1000000 THEN '0-1ms'
        WHEN dur < 5000000 THEN '1-5ms'
        WHEN dur < 10000000 THEN '5-10ms'
        WHEN dur < 50000000 THEN '10-50ms'
        WHEN dur < 100000000 THEN '50-100ms'
        WHEN dur < 500000000 THEN '100-500ms'
        ELSE '>500ms'
    END as latency_bucket,
    COUNT(*) as count,
    CAST(SUM(dur) / 1e9 AS REAL) as total_sec
FROM sched_slice
WHERE dur > 0
GROUP BY latency_bucket
ORDER BY
    CASE latency_bucket
        WHEN '0-1ms' THEN 1
        WHEN '1-5ms' THEN 2
        WHEN '5-10ms' THEN 3
        WHEN '10-50ms' THEN 4
        WHEN '50-100ms' THEN 5
        WHEN '100-500ms' THEN 6
        ELSE 7
    END;


-- ============================================================================
-- CPU / STACK TRACE ANALYSIS
-- ============================================================================

-- Top functions by CPU sample count
SELECT
    f.name as function_name,
    f.mapping_name as module,
    COUNT(*) as sample_count,
    ROUND(100.0 * COUNT(*) / (SELECT COUNT(*) FROM perf_sample WHERE callsite_id IS NOT NULL), 2) as pct
FROM perf_sample ps
JOIN stack_profile_callsite c ON ps.callsite_id = c.id
JOIN stack_profile_frame f ON c.frame_id = f.id
WHERE f.name IS NOT NULL AND f.name != ''
GROUP BY f.name
ORDER BY sample_count DESC
LIMIT 30;

-- Top functions by CPU time in kernel
SELECT
    f.name as function_name,
    COUNT(*) as sample_count,
    ROUND(100.0 * COUNT(*) / (SELECT COUNT(*) FROM perf_sample WHERE callsite_id IS NOT NULL), 2) as pct
FROM perf_sample ps
JOIN stack_profile_callsite c ON ps.callsite_id = c.id
JOIN stack_profile_frame f ON c.frame_id = f.id
WHERE f.name IS NOT NULL
AND (f.mapping_name LIKE '%vmlinux%' OR f.mapping_name LIKE '%kernel%' OR f.mapping_name IS NULL)
GROUP BY f.name
ORDER BY sample_count DESC
LIMIT 20;

-- Top functions in user space
SELECT
    f.name as function_name,
    f.mapping_name as module,
    COUNT(*) as sample_count,
    ROUND(100.0 * COUNT(*) / (SELECT COUNT(*) FROM perf_sample WHERE callsite_id IS NOT NULL), 2) as pct
FROM perf_sample ps
JOIN stack_profile_callsite c ON ps.callsite_id = c.id
JOIN stack_profile_frame f ON c.frame_id = f.id
WHERE f.name IS NOT NULL
AND f.mapping_name IS NOT NULL
AND f.mapping_name NOT LIKE '%vmlinux%'
AND f.mapping_name NOT LIKE '%kernel%'
GROUP BY f.name, f.mapping_name
ORDER BY sample_count DESC
LIMIT 20;

-- CPU time by process
SELECT
    p.name as process,
    p.pid,
    COUNT(*) as samples,
    CAST(SUM(s.dur) / 1e9 AS REAL) as cpu_time_sec,
    ROUND(100.0 * SUM(s.dur) / (SELECT SUM(dur) FROM sched_slice WHERE dur > 0), 2) as pct
FROM sched_slice s
JOIN thread t ON s.utid = t.utid
JOIN process p ON t.upid = p.upid
WHERE s.dur > 0 AND p.pid > 0
GROUP BY p.pid
ORDER BY cpu_time_sec DESC
LIMIT 20;

-- CPU time by thread
SELECT
    p.name as process,
    t.name as thread,
    t.tid,
    COUNT(*) as samples,
    CAST(SUM(s.dur) / 1e9 AS REAL) as cpu_time_sec,
    ROUND(100.0 * SUM(s.dur) / (SELECT SUM(dur) FROM sched_slice WHERE dur > 0), 2) as pct
FROM sched_slice s
JOIN thread t ON s.utid = t.utid
JOIN process p ON t.upid = p.upid
WHERE s.dur > 0 AND p.pid > 0
GROUP BY t.tid
ORDER BY cpu_time_sec DESC
LIMIT 30;


-- ============================================================================
-- STACK TRACE ANALYSIS (SYSTING-SPECIFIC)
-- ============================================================================

-- Systing stores stacks in stack_profile_callsite/frame tables
-- Stack samples are linked to thread_state via timestamp correlation

-- ============================================================================
-- SLEEP-WEIGHTED STACK ANALYSIS (THE IMPORTANT ONE!)
-- ============================================================================

-- Top stacks weighted by ACTUAL SLEEP TIME (not sample count)
-- This is what you want for finding blocking bottlenecks
WITH sleep_weighted AS (
    SELECT
        ps.callsite_id,
        ts.state,
        SUM(ts.dur) / 1e6 as total_sleep_ms,
        COUNT(*) as samples,
        MAX(ts.dur) / 1e6 as max_sleep_ms,
        AVG(ts.dur) / 1e6 as avg_sleep_ms
    FROM perf_sample ps
    JOIN thread_state ts ON ps.utid = ts.utid
        AND ps.ts >= ts.ts
        AND ps.ts < ts.ts + ts.dur
    WHERE ts.state IN ('S', 'D')  -- S=interruptible, D=uninterruptible sleep
    GROUP BY ps.callsite_id, ts.state
)
SELECT
    sw.callsite_id,
    sw.state as sleep_state,
    sw.total_sleep_ms,
    sw.max_sleep_ms,
    sw.avg_sleep_ms,
    sw.samples,
    f.name as leaf_function
FROM sleep_weighted sw
JOIN stack_profile_callsite c ON sw.callsite_id = c.id
JOIN stack_profile_frame f ON c.frame_id = f.id
WHERE sw.total_sleep_ms > 1
ORDER BY sw.total_sleep_ms DESC
LIMIT 30;

-- Top UNINTERRUPTIBLE sleep stacks only (D-state = I/O blocking)
-- These are the ones blocking on disk, network, or locks
WITH d_state_weighted AS (
    SELECT
        ps.callsite_id,
        SUM(ts.dur) / 1e6 as total_sleep_ms,
        COUNT(*) as samples,
        MAX(ts.dur) / 1e6 as max_sleep_ms
    FROM perf_sample ps
    JOIN thread_state ts ON ps.utid = ts.utid
        AND ps.ts >= ts.ts
        AND ps.ts < ts.ts + ts.dur
    WHERE ts.state = 'D'  -- Uninterruptible sleep only
    GROUP BY ps.callsite_id
)
SELECT
    dw.callsite_id,
    dw.total_sleep_ms,
    dw.max_sleep_ms,
    dw.samples,
    f.name as leaf_function
FROM d_state_weighted dw
JOIN stack_profile_callsite c ON dw.callsite_id = c.id
JOIN stack_profile_frame f ON c.frame_id = f.id
WHERE dw.total_sleep_ms > 0.1
ORDER BY dw.total_sleep_ms DESC
LIMIT 20;

-- Top functions at sample points (leaf functions)

-- Top functions across ALL stack frames (hotspots)
SELECT
    f.name as function_name,
    COUNT(*) as appearances
FROM stack_profile_callsite c
JOIN stack_profile_frame f ON c.frame_id = f.id
WHERE f.name IS NOT NULL
AND f.name != ''
GROUP BY f.name
ORDER BY appearances DESC
LIMIT 40;

-- Stack depth distribution
SELECT
    depth,
    COUNT(*) as callsites_at_depth
FROM stack_profile_callsite
GROUP BY depth
ORDER BY depth;

-- Get full stack trace for a specific callsite_id
-- Replace 651 with actual callsite_id from leaf query above
-- Example: Show stack for deepest leaf callsite
WITH RECURSIVE stack_walk AS (
    SELECT id, parent_id, frame_id, 0 as level
    FROM stack_profile_callsite
    WHERE id = 651  -- Replace with actual callsite_id
    UNION ALL
    SELECT c.id, c.parent_id, c.frame_id, sw.level + 1
    FROM stack_profile_callsite c
    JOIN stack_walk sw ON c.id = sw.parent_id
)
SELECT
    sw.level,
    f.name as function_name
FROM stack_walk sw
JOIN stack_profile_frame f ON sw.frame_id = f.id
ORDER BY sw.level DESC;

-- Find stacks containing a specific function (e.g., 'schedule')
SELECT DISTINCT c.id as callsite_id, c.depth
FROM stack_profile_callsite c
JOIN stack_profile_frame f ON c.frame_id = f.id
WHERE f.name LIKE '%schedule%'
ORDER BY c.depth DESC
LIMIT 20;

-- Count leaf stacks by common ancestor functions
-- Useful for finding what subsystem is causing most samples
SELECT
    f.name as ancestor_function,
    COUNT(DISTINCT leaf.id) as leaf_count
FROM stack_profile_callsite leaf
JOIN stack_profile_callsite ancestor ON leaf.id != ancestor.id
JOIN stack_profile_frame f ON ancestor.frame_id = f.id
WHERE leaf.id NOT IN (
    SELECT DISTINCT parent_id
    FROM stack_profile_callsite
    WHERE parent_id IS NOT NULL
)
AND ancestor.depth < 5  -- Look at early frames (near root)
AND f.name IS NOT NULL
GROUP BY f.name
ORDER BY leaf_count DESC
LIMIT 20;


-- ============================================================================
-- CUSTOM EVENTS / SLICES
-- ============================================================================

-- Summary of all slice events (custom probes, syscalls, etc.)
SELECT
    name,
    COUNT(*) as count,
    CAST(AVG(dur) / 1000.0 AS REAL) as avg_us,
    CAST(MAX(dur) / 1000.0 AS REAL) as max_us,
    CAST(MIN(dur) / 1000.0 AS REAL) as min_us,
    CAST(SUM(dur) / 1e6 AS REAL) as total_ms
FROM slice
WHERE dur > 0
GROUP BY name
ORDER BY count DESC
LIMIT 30;

-- Slowest individual slice events
SELECT
    name,
    CAST(ts / 1e9 AS REAL) as time_sec,
    CAST(dur / 1e6 AS REAL) as duration_ms,
    track_id
FROM slice
WHERE dur > 0
ORDER BY dur DESC
LIMIT 30;


-- ============================================================================
-- COUNTER ANALYSIS
-- ============================================================================

-- All counter tracks with summary statistics
SELECT
    track.name as counter_name,
    COUNT(*) as samples,
    AVG(counter.value) as avg_value,
    MAX(counter.value) as max_value,
    MIN(counter.value) as min_value
FROM counter
JOIN counter_track track ON counter.track_id = track.id
GROUP BY track.name
ORDER BY track.name;

-- Runqueue size statistics (if captured with --cpu-sched-stats)
SELECT
    track.name as counter_name,
    AVG(counter.value) as avg_rq_size,
    MAX(counter.value) as max_rq_size,
    COUNT(*) as samples
FROM counter
JOIN counter_track track ON counter.track_id = track.id
WHERE track.name LIKE '%runqueue%'
GROUP BY track.name
ORDER BY track.name;


-- ============================================================================
-- TIME-SERIES ANALYSIS
-- ============================================================================

-- Scheduling latency over time (1-second buckets)
SELECT
    CAST(ts / 1e9 AS INTEGER) as time_bucket_sec,
    COUNT(*) as events,
    CAST(AVG(dur) / 1000.0 AS INTEGER) as avg_latency_us,
    CAST(MAX(dur) / 1000.0 AS INTEGER) as max_latency_us
FROM sched_slice
WHERE dur > 0
GROUP BY time_bucket_sec
ORDER BY time_bucket_sec;

-- CPU utilization over time (per CPU, 1-second buckets)
SELECT
    cpu,
    CAST(ts / 1e9 AS INTEGER) as time_bucket_sec,
    COUNT(*) as context_switches,
    CAST(SUM(dur) / 1e6 AS REAL) as cpu_time_ms
FROM sched_slice
WHERE dur > 0
GROUP BY cpu, time_bucket_sec
ORDER BY time_bucket_sec, cpu;


-- ============================================================================
-- PROCESS LIFECYCLE
-- ============================================================================

-- All processes in the trace
SELECT
    p.pid,
    p.name as process_name,
    p.parent_upid,
    COUNT(DISTINCT t.tid) as thread_count
FROM process p
LEFT JOIN thread t ON p.upid = t.upid
WHERE p.pid > 0
GROUP BY p.pid
ORDER BY thread_count DESC;

-- All threads in the trace
SELECT
    p.name as process,
    p.pid,
    t.name as thread,
    t.tid
FROM thread t
JOIN process p ON t.upid = p.upid
WHERE p.pid > 0
ORDER BY p.pid, t.tid;


-- ============================================================================
-- ANOMALY DETECTION
-- ============================================================================

-- Find scheduling spikes (latency > 5x average)
WITH avg_latency AS (
    SELECT AVG(dur) as avg_dur FROM sched_slice WHERE dur > 0
)
SELECT
    p.name as process,
    t.name as thread,
    t.tid,
    CAST(s.ts / 1e9 AS REAL) as time_sec,
    CAST(s.dur / 1e6 AS REAL) as latency_ms,
    CAST(s.dur / (SELECT avg_dur FROM avg_latency) AS REAL) as times_avg
FROM sched_slice s
JOIN thread t ON s.utid = t.utid
JOIN process p ON t.upid = p.upid
WHERE s.dur > (SELECT avg_dur * 5 FROM avg_latency)
AND p.pid > 0
ORDER BY s.dur DESC
LIMIT 50;

-- Find potential lock contention (multiple threads blocked simultaneously)
-- This looks for time periods where many context switches happen close together
SELECT
    CAST(ts / 100000000 AS INTEGER) * 100 as time_window_ms,  -- 100ms windows
    COUNT(*) as events_in_window,
    COUNT(DISTINCT utid) as threads_scheduled
FROM sched_slice
GROUP BY time_window_ms
HAVING events_in_window > 100  -- High activity periods
ORDER BY events_in_window DESC
LIMIT 20;
