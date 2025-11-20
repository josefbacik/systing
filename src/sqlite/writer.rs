//! SQLite writer implementation for trace data
//!
//! This module implements `SqliteOutput`, which writes trace data to a SQLite database
//! using the schema defined in `schema.rs`. It handles deduplication of symbols, stacks,
//! and network connections using in-memory caches and database constraints.

use crate::output::*;
use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// SQLite output writer with deduplication support
///
/// This struct implements the `TraceOutput` trait and writes all trace data to a SQLite
/// database. It maintains in-memory caches for deduplication of symbols, stack traces,
/// network connections, and event definitions.
///
/// # Transaction Management
///
/// The writer uses a single transaction for the entire trace to maximize performance.
/// Periodic WAL checkpoints (every 10,000 events) are used for memory management instead
/// of commits. The final commit happens in `flush()`.
pub struct SqliteOutput {
    conn: Connection,

    // Deduplication caches mapping entities to their database IDs
    symbol_cache: HashMap<SymbolInfo, u64>,
    stack_cache: HashMap<String, u64>, // Stack hash -> ID
    connection_cache: HashMap<NetworkConnection, u64>,
    event_def_cache: HashMap<String, u64>, // event_name -> ID
    perf_counter_cache: HashMap<(u64, String, Option<u32>), u64>, // (track_uuid, name, cpu) -> ID

    // ID counters for new entities
    next_symbol_id: u64,
    next_stack_id: u64,
    next_connection_id: u64,
    next_event_def_id: u64,
    next_perf_counter_id: u64,

    // Event counter for periodic checkpointing
    event_count: u64,
    checkpoint_interval: u64,
}

impl SqliteOutput {
    /// Create a new SQLite output file at the specified path
    ///
    /// This will create the database file, set up the schema, and begin a transaction.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the SQLite database file to create
    ///
    /// # Returns
    ///
    /// A new `SqliteOutput` instance ready to receive trace data
    pub fn create(path: &str) -> Result<Self> {
        let conn = Connection::open(path).context("Failed to open SQLite database")?;

        // Create the schema
        crate::sqlite::create_schema(&conn).context("Failed to create SQLite schema")?;

        // Begin a single transaction for the entire trace
        conn.execute_batch("BEGIN TRANSACTION")
            .context("Failed to begin transaction")?;

        Ok(Self {
            conn,
            symbol_cache: HashMap::new(),
            stack_cache: HashMap::new(),
            connection_cache: HashMap::new(),
            event_def_cache: HashMap::new(),
            perf_counter_cache: HashMap::new(),
            next_symbol_id: 1,
            next_stack_id: 1,
            next_connection_id: 1,
            next_event_def_id: 1,
            next_perf_counter_id: 1,
            event_count: 0,
            checkpoint_interval: 10_000,
        })
    }

    /// Perform a WAL checkpoint if we've processed enough events
    ///
    /// This helps manage memory usage during long traces without committing
    /// the transaction.
    fn maybe_checkpoint(&mut self) -> Result<()> {
        self.event_count += 1;
        if self.event_count % self.checkpoint_interval == 0 {
            self.conn
                .execute_batch("PRAGMA wal_checkpoint(PASSIVE)")
                .context("Failed to checkpoint WAL")?;
        }
        Ok(())
    }

    /// Compute a SHA-256 hash of a stack trace for deduplication
    ///
    /// The hash includes all symbol information (function name, file, line, etc.)
    /// from kernel, user, and Python symbols to ensure uniqueness.
    fn compute_stack_hash(stack: &StackTraceData) -> String {
        let mut hasher = Sha256::new();

        // Hash kernel symbols
        for symbol in &stack.kernel_symbols {
            hasher.update(b"kernel:");
            hasher.update(symbol.function_name.as_bytes());
            if let Some(ref file) = symbol.file_name {
                hasher.update(b"|file:");
                hasher.update(file.as_bytes());
            }
            if let Some(line) = symbol.line_number {
                hasher.update(b"|line:");
                hasher.update(&line.to_le_bytes());
            }
            if let Some(ref build_id) = symbol.build_id {
                hasher.update(b"|build:");
                hasher.update(build_id.as_bytes());
            }
            if let Some(ref mapping) = symbol.mapping_name {
                hasher.update(b"|map:");
                hasher.update(mapping.as_bytes());
            }
            if let Some(offset) = symbol.mapping_offset {
                hasher.update(b"|off:");
                hasher.update(&offset.to_le_bytes());
            }
            hasher.update(b";");
        }

        // Hash user symbols
        for symbol in &stack.user_symbols {
            hasher.update(b"user:");
            hasher.update(symbol.function_name.as_bytes());
            if let Some(ref file) = symbol.file_name {
                hasher.update(b"|file:");
                hasher.update(file.as_bytes());
            }
            if let Some(line) = symbol.line_number {
                hasher.update(b"|line:");
                hasher.update(&line.to_le_bytes());
            }
            if let Some(ref build_id) = symbol.build_id {
                hasher.update(b"|build:");
                hasher.update(build_id.as_bytes());
            }
            if let Some(ref mapping) = symbol.mapping_name {
                hasher.update(b"|map:");
                hasher.update(mapping.as_bytes());
            }
            if let Some(offset) = symbol.mapping_offset {
                hasher.update(b"|off:");
                hasher.update(&offset.to_le_bytes());
            }
            hasher.update(b";");
        }

        // Hash Python symbols
        for symbol in &stack.py_symbols {
            hasher.update(b"python:");
            hasher.update(symbol.function_name.as_bytes());
            if let Some(ref file) = symbol.file_name {
                hasher.update(b"|file:");
                hasher.update(file.as_bytes());
            }
            if let Some(line) = symbol.line_number {
                hasher.update(b"|line:");
                hasher.update(&line.to_le_bytes());
            }
            if let Some(ref build_id) = symbol.build_id {
                hasher.update(b"|build:");
                hasher.update(build_id.as_bytes());
            }
            if let Some(ref mapping) = symbol.mapping_name {
                hasher.update(b"|map:");
                hasher.update(mapping.as_bytes());
            }
            if let Some(offset) = symbol.mapping_offset {
                hasher.update(b"|off:");
                hasher.update(&offset.to_le_bytes());
            }
            hasher.update(b";");
        }

        format!("{:x}", hasher.finalize())
    }
}

impl TraceOutput for SqliteOutput {
    fn write_metadata(&mut self, start_ts: u64, end_ts: u64, version: &str) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO metadata (id, trace_start_ts, trace_end_ts, systing_version)
             VALUES (1, ?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET
                trace_end_ts = ?2,
                systing_version = ?3",
                params![start_ts as i64, end_ts as i64, version],
            )
            .context("Failed to write metadata")?;
        Ok(())
    }

    fn write_clock_snapshot(&mut self, clocks: &[ClockInfo]) -> Result<()> {
        // Use the same snapshot_id for all clocks in this snapshot
        // We'll use the timestamp of the first clock as the snapshot ID
        let snapshot_id = if let Some(first) = clocks.first() {
            first.timestamp as i64
        } else {
            return Ok(()); // No clocks to write
        };

        for clock in clocks {
            self.conn
                .execute(
                    "INSERT OR IGNORE INTO clocks (snapshot_id, clock_type, timestamp)
                 VALUES (?1, ?2, ?3)",
                    params![snapshot_id, clock.clock_name, clock.timestamp as i64],
                )
                .context("Failed to write clock snapshot")?;
        }
        Ok(())
    }

    fn write_process(&mut self, pid: i32, name: &str, cmdline: &[String]) -> Result<()> {
        // Serialize cmdline as JSON array
        let cmdline_json = serde_json::to_string(cmdline).context("Failed to serialize cmdline")?;

        self.conn
            .execute(
                "INSERT OR IGNORE INTO processes (pid, name, cmdline)
             VALUES (?1, ?2, ?3)",
                params![pid, name, cmdline_json],
            )
            .context("Failed to write process")?;
        Ok(())
    }

    fn write_thread(&mut self, tid: i32, pid: i32, name: &str) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO threads (tid, pid, name)
             VALUES (?1, ?2, ?3)",
                params![tid, pid, name],
            )
            .context("Failed to write thread")?;
        Ok(())
    }

    fn write_process_exit(&mut self, _tid: i32, _ts: u64) -> Result<()> {
        // The schema doesn't currently have a process_exit table
        // This could be added to track exit events if needed
        // For now, we'll just acknowledge the event
        Ok(())
    }

    fn write_track(&mut self, track: &TrackInfo) -> Result<()> {
        let track_type = match track.track_type {
            TrackType::Process => "process",
            TrackType::Thread => "thread",
            TrackType::Cpu => "cpu",
            TrackType::Counter => "counter",
            TrackType::Global => "global",
        };

        self.conn
            .execute(
                "INSERT OR IGNORE INTO tracks (uuid, name, track_type, parent_uuid, pid, tid, cpu)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
                params![
                    track.uuid as i64,
                    track.name,
                    track_type,
                    track.parent_uuid.map(|u| u as i64),
                    track.pid,
                    track.tid,
                ],
            )
            .context("Failed to write track")?;
        Ok(())
    }

    fn write_sched_event(&mut self, event: &SchedEventData) -> Result<()> {
        let event_type = match event.event_type {
            SchedEventType::Switch => "switch",
            SchedEventType::Waking => "waking",
            SchedEventType::Wakeup => "wakeup",
            SchedEventType::WakeupNew => "wakeup_new",
            SchedEventType::Exit => "exit",
        };

        // Convert prev_state Option<String> to Option<i32> for database
        let prev_state_val: Option<i32> = event.prev_state.as_ref().and_then(|s| {
            // Try to parse as integer if it's numeric
            s.parse::<i32>().ok()
        });

        self.conn
            .execute(
                "INSERT INTO sched_events (ts, cpu, event_type, prev_pid, prev_state, next_pid)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    event.ts as i64,
                    event.cpu,
                    event_type,
                    event.prev_pid,
                    prev_state_val,
                    event.next_pid,
                ],
            )
            .context("Failed to write scheduler event")?;

        self.maybe_checkpoint()?;
        Ok(())
    }

    fn write_irq_event(&mut self, _event: &IrqEventData) -> Result<()> {
        // The schema doesn't currently have an IRQ events table
        // This could be added if IRQ tracking is needed
        // For now, we'll just acknowledge the event
        Ok(())
    }

    fn write_symbol(&mut self, symbol: &SymbolInfo) -> Result<u64> {
        // Check cache first
        if let Some(&id) = self.symbol_cache.get(symbol) {
            return Ok(id);
        }

        let id = self.next_symbol_id;

        // Insert symbol with OR IGNORE to handle database-level deduplication
        self.conn.execute(
            "INSERT OR IGNORE INTO symbols (id, function_name, file_name, line_number, build_id, mapping_name, mapping_offset)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                id as i64,
                symbol.function_name,
                symbol.file_name,
                symbol.line_number.map(|l| l as i64),
                symbol.build_id,
                symbol.mapping_name,
                symbol.mapping_offset.map(|o| o as i64),
            ],
        ).context("Failed to write symbol")?;

        // Check if the insert actually happened by querying back
        // This handles the case where the symbol already existed in the database
        let actual_id: i64 = self
            .conn
            .query_row(
                "SELECT id FROM symbols WHERE function_name = ?1 AND
             file_name IS ?2 AND line_number IS ?3 AND
             build_id IS ?4 AND mapping_name IS ?5 AND mapping_offset IS ?6",
                params![
                    symbol.function_name,
                    symbol.file_name,
                    symbol.line_number.map(|l| l as i64),
                    symbol.build_id,
                    symbol.mapping_name,
                    symbol.mapping_offset.map(|o| o as i64),
                ],
                |row| row.get(0),
            )
            .context("Failed to query symbol ID")?;

        let actual_id = actual_id as u64;

        // Update cache with actual ID
        self.symbol_cache.insert(symbol.clone(), actual_id);

        // Only increment counter if we actually inserted
        if actual_id == id {
            self.next_symbol_id += 1;
        }

        Ok(actual_id)
    }

    fn write_stack_trace(&mut self, stack: &StackTraceData) -> Result<u64> {
        // Compute hash for deduplication
        let hash = Self::compute_stack_hash(stack);

        // Check cache first
        if let Some(&id) = self.stack_cache.get(&hash) {
            return Ok(id);
        }

        let id = self.next_stack_id;

        // Insert stack trace record
        self.conn
            .execute(
                "INSERT OR IGNORE INTO stack_traces (id, stack_hash)
             VALUES (?1, ?2)",
                params![id as i64, hash],
            )
            .context("Failed to write stack trace")?;

        // Check if the insert actually happened
        let actual_id: i64 = self
            .conn
            .query_row(
                "SELECT id FROM stack_traces WHERE stack_hash = ?1",
                params![hash],
                |row| row.get(0),
            )
            .context("Failed to query stack trace ID")?;

        let actual_id = actual_id as u64;

        // Only insert frames if this is a new stack
        if actual_id == id {
            let mut frame_index = 0;

            // Insert kernel symbols
            for symbol in &stack.kernel_symbols {
                let symbol_id = self.write_symbol(symbol)?;
                self.conn.execute(
                    "INSERT INTO stack_trace_frames (stack_id, frame_index, stack_type, symbol_id)
                     VALUES (?1, ?2, 'kernel', ?3)",
                    params![id as i64, frame_index, symbol_id as i64],
                ).context("Failed to write kernel frame")?;
                frame_index += 1;
            }

            // Insert user symbols
            for symbol in &stack.user_symbols {
                let symbol_id = self.write_symbol(symbol)?;
                self.conn.execute(
                    "INSERT INTO stack_trace_frames (stack_id, frame_index, stack_type, symbol_id)
                     VALUES (?1, ?2, 'user', ?3)",
                    params![id as i64, frame_index, symbol_id as i64],
                ).context("Failed to write user frame")?;
                frame_index += 1;
            }

            // Insert Python symbols
            for symbol in &stack.py_symbols {
                let symbol_id = self.write_symbol(symbol)?;
                self.conn.execute(
                    "INSERT INTO stack_trace_frames (stack_id, frame_index, stack_type, symbol_id)
                     VALUES (?1, ?2, 'python', ?3)",
                    params![id as i64, frame_index, symbol_id as i64],
                ).context("Failed to write python frame")?;
                frame_index += 1;
            }

            self.next_stack_id += 1;
        }

        // Update cache
        self.stack_cache.insert(hash, actual_id);

        Ok(actual_id)
    }

    fn write_perf_sample(&mut self, sample: &PerfSampleData) -> Result<()> {
        let stack_id = self.write_stack_trace(&sample.stack)?;

        self.conn
            .execute(
                "INSERT INTO perf_samples (ts, tid, stack_id)
             VALUES (?1, ?2, ?3)",
                params![sample.ts as i64, sample.tid, stack_id as i64],
            )
            .context("Failed to write perf sample")?;

        self.maybe_checkpoint()?;
        Ok(())
    }

    fn write_perf_counter(&mut self, counter: &PerfCounterDef) -> Result<()> {
        // Create cache key
        let key = (
            counter.track_uuid,
            counter.counter_name.clone(),
            counter.cpu,
        );

        // Check cache first
        if self.perf_counter_cache.contains_key(&key) {
            return Ok(());
        }

        let id = self.next_perf_counter_id;

        self.conn
            .execute(
                "INSERT OR IGNORE INTO perf_counters (id, track_uuid, counter_name, cpu, unit)
             VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    id as i64,
                    counter.track_uuid as i64,
                    counter.counter_name,
                    counter.cpu,
                    counter.unit,
                ],
            )
            .context("Failed to write perf counter")?;

        // Get actual ID
        let actual_id: i64 = self.conn.query_row(
            "SELECT id FROM perf_counters WHERE track_uuid = ?1 AND counter_name = ?2 AND cpu IS ?3",
            params![counter.track_uuid as i64, counter.counter_name, counter.cpu],
            |row| row.get(0),
        ).context("Failed to query perf counter ID")?;

        let actual_id = actual_id as u64;

        // Update cache
        self.perf_counter_cache.insert(key, actual_id);

        // Only increment if we actually inserted
        if actual_id == id {
            self.next_perf_counter_id += 1;
        }

        Ok(())
    }

    fn write_perf_counter_value(&mut self, counter_id: u64, ts: u64, value: i64) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO perf_counter_values (counter_id, ts, value)
             VALUES (?1, ?2, ?3)",
                params![counter_id as i64, ts as i64, value],
            )
            .context("Failed to write perf counter value")?;

        self.maybe_checkpoint()?;
        Ok(())
    }

    fn write_event_definition(&mut self, def: &EventDefinition) -> Result<u64> {
        // Check cache first
        if let Some(&id) = self.event_def_cache.get(&def.event_name) {
            return Ok(id);
        }

        let id = self.next_event_def_id;

        self.conn.execute(
            "INSERT OR IGNORE INTO event_definitions (id, event_name, event_type, track_name, category, cookie)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                id as i64,
                def.event_name,
                def.event_type,
                def.track_name,
                def.category,
                def.cookie as i64,
            ],
        ).context("Failed to write event definition")?;

        // Get actual ID
        let actual_id: i64 = self
            .conn
            .query_row(
                "SELECT id FROM event_definitions WHERE event_name = ?1",
                params![def.event_name],
                |row| row.get(0),
            )
            .context("Failed to query event definition ID")?;

        let actual_id = actual_id as u64;

        // Update cache
        self.event_def_cache
            .insert(def.event_name.clone(), actual_id);

        // Only increment if we actually inserted
        if actual_id == id {
            self.next_event_def_id += 1;
        }

        Ok(actual_id)
    }

    fn write_probe_event(&mut self, event: &ProbeEventData) -> Result<()> {
        // Serialize args as JSON
        let args_json =
            serde_json::to_string(&event.args).context("Failed to serialize probe event args")?;

        self.conn
            .execute(
                "INSERT INTO probe_events (ts, tid, event_def_id, args)
             VALUES (?1, ?2, ?3, ?4)",
                params![
                    event.ts as i64,
                    event.tid,
                    event.event_def_id as i64,
                    args_json,
                ],
            )
            .context("Failed to write probe event")?;

        self.maybe_checkpoint()?;
        Ok(())
    }

    fn write_network_connection(&mut self, conn: &NetworkConnection) -> Result<u64> {
        // Check cache first
        if let Some(&id) = self.connection_cache.get(conn) {
            return Ok(id);
        }

        let id = self.next_connection_id;

        self.conn.execute(
            "INSERT OR IGNORE INTO network_connections (id, protocol, address_family, dest_addr, dest_port)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                id as i64,
                conn.protocol,
                conn.address_family,
                conn.dest_addr,
                conn.dest_port,
            ],
        ).context("Failed to write network connection")?;

        // Get actual ID
        let actual_id: i64 = self.conn.query_row(
            "SELECT id FROM network_connections WHERE protocol = ?1 AND address_family = ?2 AND dest_addr = ?3 AND dest_port = ?4",
            params![conn.protocol, conn.address_family, conn.dest_addr, conn.dest_port],
            |row| row.get(0),
        ).context("Failed to query network connection ID")?;

        let actual_id = actual_id as u64;

        // Update cache
        self.connection_cache.insert(conn.clone(), actual_id);

        // Only increment if we actually inserted
        if actual_id == id {
            self.next_connection_id += 1;
        }

        Ok(actual_id)
    }

    fn write_network_event(&mut self, event: &NetworkEventData) -> Result<()> {
        self.conn.execute(
            "INSERT INTO network_events (connection_id, tid, track_uuid, event_type, start_ts, end_ts, bytes, sequence_num, tcp_flags)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                event.connection_id as i64,
                event.tid,
                event.track_uuid as i64,
                event.event_type,
                event.start_ts as i64,
                event.end_ts.map(|t| t as i64),
                event.bytes,
                event.sequence_num,
                event.tcp_flags,
            ],
        ).context("Failed to write network event")?;

        self.maybe_checkpoint()?;
        Ok(())
    }

    fn write_cpu_frequency(&mut self, cpu: u32, ts: u64, freq: i64, track_uuid: u64) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO cpu_frequency (ts, cpu, frequency, track_uuid)
             VALUES (?1, ?2, ?3, ?4)",
                params![ts as i64, cpu, freq, track_uuid as i64],
            )
            .context("Failed to write CPU frequency")?;

        self.maybe_checkpoint()?;
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        // Commit the transaction
        self.conn
            .execute_batch("COMMIT")
            .context("Failed to commit transaction")?;

        // Final checkpoint
        self.conn
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .context("Failed to perform final WAL checkpoint")?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_db() -> SqliteOutput {
        SqliteOutput::create(":memory:").expect("Failed to create test database")
    }

    #[test]
    fn test_symbol_deduplication() {
        let mut output = create_test_db();

        let symbol = SymbolInfo {
            function_name: "test_function".to_string(),
            file_name: Some("test.c".to_string()),
            line_number: Some(42),
            build_id: None,
            mapping_name: None,
            mapping_offset: None,
        };

        // Write the same symbol twice
        let id1 = output
            .write_symbol(&symbol)
            .expect("Failed to write symbol");
        let id2 = output
            .write_symbol(&symbol)
            .expect("Failed to write symbol");

        // Should get the same ID both times
        assert_eq!(id1, id2, "Duplicate symbols should have the same ID");

        // Verify only one symbol in database
        let count: i64 = output
            .conn
            .query_row("SELECT COUNT(*) FROM symbols", [], |row| row.get(0))
            .expect("Failed to count symbols");
        assert_eq!(count, 1, "Should only have one symbol in database");
    }

    #[test]
    fn test_stack_trace_deduplication() {
        let mut output = create_test_db();

        let symbol1 = SymbolInfo {
            function_name: "func1".to_string(),
            file_name: Some("file1.c".to_string()),
            line_number: Some(10),
            build_id: None,
            mapping_name: None,
            mapping_offset: None,
        };

        let symbol2 = SymbolInfo {
            function_name: "func2".to_string(),
            file_name: Some("file2.c".to_string()),
            line_number: Some(20),
            build_id: None,
            mapping_name: None,
            mapping_offset: None,
        };

        let stack = StackTraceData {
            kernel_symbols: vec![symbol1.clone(), symbol2.clone()],
            user_symbols: vec![],
            py_symbols: vec![],
        };

        // Write the same stack twice
        let id1 = output
            .write_stack_trace(&stack)
            .expect("Failed to write stack");
        let id2 = output
            .write_stack_trace(&stack)
            .expect("Failed to write stack");

        // Should get the same ID both times
        assert_eq!(id1, id2, "Duplicate stacks should have the same ID");

        // Verify only one stack in database
        let count: i64 = output
            .conn
            .query_row("SELECT COUNT(*) FROM stack_traces", [], |row| row.get(0))
            .expect("Failed to count stacks");
        assert_eq!(count, 1, "Should only have one stack in database");
    }

    #[test]
    fn test_network_connection_deduplication() {
        let mut output = create_test_db();

        let conn = NetworkConnection {
            protocol: "TCP".to_string(),
            address_family: "IPv4".to_string(),
            dest_addr: "192.168.1.1".to_string(),
            dest_port: 443,
        };

        // Write the same connection twice
        let id1 = output
            .write_network_connection(&conn)
            .expect("Failed to write connection");
        let id2 = output
            .write_network_connection(&conn)
            .expect("Failed to write connection");

        // Should get the same ID both times
        assert_eq!(id1, id2, "Duplicate connections should have the same ID");

        // Verify only one connection in database
        let count: i64 = output
            .conn
            .query_row("SELECT COUNT(*) FROM network_connections", [], |row| {
                row.get(0)
            })
            .expect("Failed to count connections");
        assert_eq!(count, 1, "Should only have one connection in database");
    }

    #[test]
    fn test_event_definition_deduplication() {
        let mut output = create_test_db();

        let event_def = EventDefinition {
            event_name: "test_event".to_string(),
            event_type: "tracepoint".to_string(),
            track_name: Some("test_track".to_string()),
            category: Some("test".to_string()),
            cookie: 12345,
        };

        // Write the same event definition twice
        let id1 = output
            .write_event_definition(&event_def)
            .expect("Failed to write event def");
        let id2 = output
            .write_event_definition(&event_def)
            .expect("Failed to write event def");

        // Should get the same ID both times
        assert_eq!(
            id1, id2,
            "Duplicate event definitions should have the same ID"
        );

        // Verify only one event definition in database
        let count: i64 = output
            .conn
            .query_row("SELECT COUNT(*) FROM event_definitions", [], |row| {
                row.get(0)
            })
            .expect("Failed to count event definitions");
        assert_eq!(
            count, 1,
            "Should only have one event definition in database"
        );
    }

    #[test]
    fn test_metadata_write() {
        let mut output = create_test_db();

        output
            .write_metadata(1000, 2000, "test-version")
            .expect("Failed to write metadata");

        // Verify metadata in database
        let (start, end, version): (i64, i64, String) = output
            .conn
            .query_row(
                "SELECT trace_start_ts, trace_end_ts, systing_version FROM metadata WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("Failed to read metadata");

        assert_eq!(start, 1000);
        assert_eq!(end, 2000);
        assert_eq!(version, "test-version");
    }

    #[test]
    fn test_process_and_thread_write() {
        let mut output = create_test_db();

        let cmdline = vec!["test".to_string(), "--arg".to_string()];
        output
            .write_process(1234, "test_process", &cmdline)
            .expect("Failed to write process");

        output
            .write_thread(5678, 1234, "test_thread")
            .expect("Failed to write thread");

        // Verify process in database
        let (pid, name, cmdline_json): (i32, String, String) = output
            .conn
            .query_row(
                "SELECT pid, name, cmdline FROM processes WHERE pid = 1234",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("Failed to read process");

        assert_eq!(pid, 1234);
        assert_eq!(name, "test_process");
        let parsed_cmdline: Vec<String> =
            serde_json::from_str(&cmdline_json).expect("Failed to parse cmdline");
        assert_eq!(parsed_cmdline, cmdline);

        // Verify thread in database
        let (tid, thread_pid, thread_name): (i32, i32, String) = output
            .conn
            .query_row(
                "SELECT tid, pid, name FROM threads WHERE tid = 5678",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("Failed to read thread");

        assert_eq!(tid, 5678);
        assert_eq!(thread_pid, 1234);
        assert_eq!(thread_name, "test_thread");
    }

    #[test]
    fn test_stack_hash_computation() {
        // Create two identical stacks
        let symbol1 = SymbolInfo {
            function_name: "func1".to_string(),
            file_name: Some("file1.c".to_string()),
            line_number: Some(10),
            build_id: Some("abc123".to_string()),
            mapping_name: Some("libc.so".to_string()),
            mapping_offset: Some(0x1000),
        };

        let stack1 = StackTraceData {
            kernel_symbols: vec![symbol1.clone()],
            user_symbols: vec![],
            py_symbols: vec![],
        };

        let stack2 = StackTraceData {
            kernel_symbols: vec![symbol1.clone()],
            user_symbols: vec![],
            py_symbols: vec![],
        };

        // Hashes should be identical
        let hash1 = SqliteOutput::compute_stack_hash(&stack1);
        let hash2 = SqliteOutput::compute_stack_hash(&stack2);
        assert_eq!(hash1, hash2);

        // Different stack should have different hash
        let symbol2 = SymbolInfo {
            function_name: "func2".to_string(),
            file_name: Some("file2.c".to_string()),
            line_number: Some(20),
            build_id: None,
            mapping_name: None,
            mapping_offset: None,
        };

        let stack3 = StackTraceData {
            kernel_symbols: vec![symbol2],
            user_symbols: vec![],
            py_symbols: vec![],
        };

        let hash3 = SqliteOutput::compute_stack_hash(&stack3);
        assert_ne!(hash1, hash3);
    }
}
