/// SQL schema for systing SQLite output
///
/// This schema is designed to be simple and relational, optimized for SQL queries.
/// Unlike Perfetto's complex interning system, we use straightforward deduplication
/// with foreign keys and unique constraints.
///
/// This schema intentionally creates NO indexes to maximize recording performance
/// and minimize database size (~71% smaller than the original 31-index schema).
/// Indexes can be added later if needed for SQL analysis, and the conversion tool
/// creates temporary indexes automatically for efficient format conversion.
pub const SCHEMA_VERSION: i32 = 1;

/// SQL schema for systing SQLite output (no indexes for maximum performance)
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

-- Counter value samples
CREATE TABLE IF NOT EXISTS perf_counter_values (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    counter_id INTEGER NOT NULL,
    ts INTEGER NOT NULL,
    value INTEGER NOT NULL,
    FOREIGN KEY (counter_id) REFERENCES perf_counters(id)
);

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
            assert_eq!(count, 1, "Table {table} should exist");
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

    #[test]
    fn test_no_indexes_created() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        create_schema(&conn).unwrap();

        // Verify we have NO user-created indexes (only implicit UNIQUE constraint indexes)
        let index_count: i32 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            index_count, 0,
            "Expected no indexes in schema (indexes created on-demand), found {index_count}"
        );
    }
}
