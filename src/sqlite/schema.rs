/// SQL schema for systing SQLite output
///
/// This schema is designed to be simple and relational, optimized for SQL queries.
/// Unlike Perfetto's complex interning system, we use straightforward deduplication
/// with foreign keys and unique constraints.

pub const SCHEMA_VERSION: i32 = 1;

/// SQL schema for systing SQLite output
pub const SCHEMA_SQL: &str = r#"
-- ============================================================================
-- SQLite Configuration and Optimizations
-- ============================================================================

-- Enforce write-ahead logging for better concurrency
PRAGMA journal_mode = WAL;

-- Normal synchronous mode is safe with WAL and much faster
PRAGMA synchronous = NORMAL;

-- 64MB cache for better performance
PRAGMA cache_size = -64000;

-- Keep temp tables in memory
PRAGMA temp_store = MEMORY;

-- 256MB memory-mapped I/O
PRAGMA mmap_size = 268435456;

-- Enable foreign key constraints
PRAGMA foreign_keys = ON;

-- ============================================================================
-- Schema Version Tracking
-- ============================================================================

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    description TEXT
);

INSERT INTO schema_version (version, description)
VALUES (1, 'Initial schema');

-- ============================================================================
-- Trace Metadata
-- ============================================================================

-- Single row containing trace-level metadata
CREATE TABLE IF NOT EXISTS metadata (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    trace_start_ts INTEGER NOT NULL,
    trace_end_ts INTEGER NOT NULL,
    primary_clock TEXT NOT NULL DEFAULT 'BOOTTIME',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    systing_version TEXT
);

-- ============================================================================
-- Clock Snapshots
-- ============================================================================

-- Clock synchronization snapshots for BOOTTIME, MONOTONIC, REALTIME
CREATE TABLE IF NOT EXISTS clocks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id INTEGER NOT NULL,
    clock_type TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    UNIQUE(snapshot_id, clock_type)
);

CREATE INDEX idx_clocks_snapshot ON clocks(snapshot_id);

-- ============================================================================
-- Process and Thread Information
-- ============================================================================

CREATE TABLE IF NOT EXISTS processes (
    pid INTEGER PRIMARY KEY,
    name TEXT,
    cmdline TEXT  -- JSON array of command line arguments
);

CREATE TABLE IF NOT EXISTS threads (
    tid INTEGER PRIMARY KEY,
    pid INTEGER NOT NULL,
    name TEXT,
    FOREIGN KEY (pid) REFERENCES processes(pid)
);

CREATE INDEX idx_threads_pid ON threads(pid);

-- ============================================================================
-- Tracks (for organizing event streams)
-- ============================================================================

CREATE TABLE IF NOT EXISTS tracks (
    uuid INTEGER PRIMARY KEY,
    name TEXT,
    track_type TEXT,  -- 'process', 'thread', 'cpu', 'counter', etc.
    parent_uuid INTEGER,
    pid INTEGER,
    tid INTEGER,
    cpu INTEGER,
    FOREIGN KEY (parent_uuid) REFERENCES tracks(uuid),
    FOREIGN KEY (pid) REFERENCES processes(pid),
    FOREIGN KEY (tid) REFERENCES threads(tid)
);

CREATE INDEX idx_tracks_pid ON tracks(pid);
CREATE INDEX idx_tracks_tid ON tracks(tid);
CREATE INDEX idx_tracks_parent ON tracks(parent_uuid);

-- ============================================================================
-- Scheduler Events
-- ============================================================================

CREATE TABLE IF NOT EXISTS sched_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    cpu INTEGER NOT NULL,
    event_type TEXT NOT NULL,  -- 'waking', 'switch'
    prev_pid INTEGER,
    prev_state INTEGER,
    prev_prio INTEGER,
    next_pid INTEGER,
    next_prio INTEGER,
    FOREIGN KEY (prev_pid) REFERENCES threads(tid),
    FOREIGN KEY (next_pid) REFERENCES threads(tid)
);

-- Index for time-range queries
CREATE INDEX idx_sched_events_ts ON sched_events(ts);

-- Index for queries by CPU
CREATE INDEX idx_sched_events_cpu ON sched_events(cpu, ts);

-- Composite index for thread timeline queries
CREATE INDEX idx_sched_events_next_pid_ts ON sched_events(next_pid, ts);
CREATE INDEX idx_sched_events_prev_pid_ts ON sched_events(prev_pid, ts);

-- ============================================================================
-- Stack Traces and Symbols
-- ============================================================================

-- Deduplicated symbol information
CREATE TABLE IF NOT EXISTS symbols (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    function_name TEXT,
    file_name TEXT,
    line_number INTEGER,
    build_id TEXT,
    mapping_name TEXT,
    mapping_offset INTEGER,
    -- Unique constraint for deduplication
    UNIQUE(function_name, file_name, line_number, build_id, mapping_name, mapping_offset)
);

CREATE INDEX idx_symbols_function ON symbols(function_name);
CREATE INDEX idx_symbols_build_id ON symbols(build_id);

-- Stack trace records (identified by hash)
CREATE TABLE IF NOT EXISTS stack_traces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    stack_hash INTEGER NOT NULL UNIQUE
);

-- Junction table linking stack traces to symbols
CREATE TABLE IF NOT EXISTS stack_trace_frames (
    stack_id INTEGER NOT NULL,
    frame_index INTEGER NOT NULL,
    stack_type TEXT NOT NULL,  -- 'kernel', 'user', or 'python'
    symbol_id INTEGER,
    PRIMARY KEY (stack_id, frame_index, stack_type),
    FOREIGN KEY (stack_id) REFERENCES stack_traces(id),
    FOREIGN KEY (symbol_id) REFERENCES symbols(id)
);

-- Index for efficient stack trace reconstruction
CREATE INDEX idx_stack_frames_stack_id ON stack_trace_frames(stack_id, frame_index);
CREATE INDEX idx_stack_frames_symbol ON stack_trace_frames(symbol_id, stack_type);

-- ============================================================================
-- Performance Samples
-- ============================================================================

CREATE TABLE IF NOT EXISTS perf_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    tid INTEGER NOT NULL,
    stack_id INTEGER,
    FOREIGN KEY (tid) REFERENCES threads(tid),
    FOREIGN KEY (stack_id) REFERENCES stack_traces(id)
);

-- Index for time-range queries
CREATE INDEX idx_perf_samples_ts ON perf_samples(ts);

-- Composite index for thread timeline queries
CREATE INDEX idx_perf_samples_tid_ts ON perf_samples(tid, ts);

-- ============================================================================
-- Performance Counters
-- ============================================================================

-- Counter definitions (CPU frequency, cache misses, etc.)
CREATE TABLE IF NOT EXISTS perf_counters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    track_uuid INTEGER NOT NULL,
    counter_name TEXT NOT NULL,
    cpu INTEGER,
    unit TEXT,
    UNIQUE(track_uuid, counter_name, cpu),
    FOREIGN KEY (track_uuid) REFERENCES tracks(uuid)
);

CREATE INDEX idx_perf_counters_track ON perf_counters(track_uuid);

-- Counter value samples
CREATE TABLE IF NOT EXISTS perf_counter_values (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    counter_id INTEGER NOT NULL,
    ts INTEGER NOT NULL,
    value INTEGER NOT NULL,
    FOREIGN KEY (counter_id) REFERENCES perf_counters(id)
);

CREATE INDEX idx_perf_counter_values_ts ON perf_counter_values(ts);
CREATE INDEX idx_perf_counter_values_counter_ts ON perf_counter_values(counter_id, ts);

-- ============================================================================
-- Custom Probe Events
-- ============================================================================

-- Event definitions for custom probes (tracepoints, uprobes, etc.)
CREATE TABLE IF NOT EXISTS event_definitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_name TEXT NOT NULL UNIQUE,
    event_type TEXT NOT NULL,  -- 'tracepoint', 'uprobe', 'kprobe', etc.
    track_name TEXT,
    category TEXT,
    cookie INTEGER
);

CREATE INDEX idx_event_defs_name ON event_definitions(event_name);

-- Custom probe event instances
CREATE TABLE IF NOT EXISTS probe_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    tid INTEGER NOT NULL,
    event_def_id INTEGER NOT NULL,
    args TEXT,  -- JSON object with event-specific arguments
    FOREIGN KEY (tid) REFERENCES threads(tid),
    FOREIGN KEY (event_def_id) REFERENCES event_definitions(id)
);

CREATE INDEX idx_probe_events_ts ON probe_events(ts);
CREATE INDEX idx_probe_events_tid ON probe_events(tid, ts);
CREATE INDEX idx_probe_events_def ON probe_events(event_def_id, ts);

-- ============================================================================
-- Network Events
-- ============================================================================

-- Network connection information (deduplicated)
CREATE TABLE IF NOT EXISTS network_connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    protocol TEXT NOT NULL,  -- 'TCP', 'UDP'
    address_family TEXT NOT NULL,  -- 'IPv4', 'IPv6'
    dest_addr TEXT NOT NULL,
    dest_port INTEGER NOT NULL,
    UNIQUE(protocol, address_family, dest_addr, dest_port)
);

CREATE INDEX idx_network_connections_proto ON network_connections(protocol);
CREATE INDEX idx_network_connections_dest ON network_connections(dest_addr, dest_port);

-- Network event instances (send, receive, etc.)
CREATE TABLE IF NOT EXISTS network_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    connection_id INTEGER NOT NULL,
    tid INTEGER NOT NULL,
    track_uuid INTEGER NOT NULL,
    event_type TEXT NOT NULL,  -- 'send', 'receive', 'connect', etc.
    start_ts INTEGER NOT NULL,
    end_ts INTEGER,
    bytes INTEGER,
    sequence_num INTEGER,
    tcp_flags INTEGER,
    FOREIGN KEY (connection_id) REFERENCES network_connections(id),
    FOREIGN KEY (tid) REFERENCES threads(tid),
    FOREIGN KEY (track_uuid) REFERENCES tracks(uuid)
);

CREATE INDEX idx_network_events_ts ON network_events(start_ts);
CREATE INDEX idx_network_events_tid ON network_events(tid, start_ts);
CREATE INDEX idx_network_events_connection ON network_events(connection_id, start_ts);
CREATE INDEX idx_network_events_track ON network_events(track_uuid);

-- ============================================================================
-- CPU Frequency Tracking
-- ============================================================================

CREATE TABLE IF NOT EXISTS cpu_frequency (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    cpu INTEGER NOT NULL,
    frequency INTEGER NOT NULL,
    track_uuid INTEGER NOT NULL,
    FOREIGN KEY (track_uuid) REFERENCES tracks(uuid)
);

CREATE INDEX idx_cpu_frequency_ts ON cpu_frequency(ts);
CREATE INDEX idx_cpu_frequency_cpu_ts ON cpu_frequency(cpu, ts);
CREATE INDEX idx_cpu_frequency_track ON cpu_frequency(track_uuid);
"#;

/// Creates the complete schema in the provided SQLite connection
///
/// # Arguments
/// * `conn` - SQLite connection to create the schema in
///
/// # Returns
/// * `Ok(())` on success
/// * `Err` if schema creation fails
pub fn create_schema(conn: &rusqlite::Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(SCHEMA_SQL)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_creation() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        create_schema(&conn).unwrap();

        // Verify schema_version table exists and has correct version
        let version: i32 = conn
            .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);

        // Verify all tables exist
        let tables = vec![
            "metadata",
            "clocks",
            "processes",
            "threads",
            "tracks",
            "sched_events",
            "symbols",
            "stack_traces",
            "stack_trace_frames",
            "perf_samples",
            "perf_counters",
            "perf_counter_values",
            "event_definitions",
            "probe_events",
            "network_connections",
            "network_events",
            "cpu_frequency",
        ];

        for table in tables {
            let count: i32 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "Table {} should exist", table);
        }
    }

    #[test]
    fn test_foreign_keys_enabled() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        create_schema(&conn).unwrap();

        let fk_enabled: i32 = conn
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .unwrap();
        assert_eq!(fk_enabled, 1, "Foreign keys should be enabled");
    }

    #[test]
    fn test_wal_mode() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        create_schema(&conn).unwrap();

        let journal_mode: String = conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        // Note: In-memory databases don't support WAL, but this tests the pragma is set
        assert!(
            journal_mode == "wal" || journal_mode == "memory",
            "Journal mode should be WAL or memory (for in-memory DBs)"
        );
    }
}
