//! Thread-safe generator for unique thread and process IDs (utid/upid).
//!
//! During streaming mode, this generator maintains consistent tid->utid and pid->upid
//! mappings across all recorders, ensuring that sched events, stack samples, and thread
//! records all use the same utid values.
//!
//! # Thread Safety
//!
//! The generator uses `AtomicI64` for lock-free ID generation and `RwLock<HashMap>` for
//! thread-safe mapping storage. The double-checked locking pattern ensures correctness
//! when multiple threads attempt to register the same tid/pid simultaneously.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::RwLock;

/// Thread-safe generator for utid (unique thread ID) and upid (unique process ID) values.
///
/// This structure maintains mappings from OS thread/process IDs to unique internal IDs
/// and generates sequential values for new threads/processes.
#[derive(Debug)]
pub struct UtidGenerator {
    /// Counter for generating sequential utid values
    next_utid: AtomicI64,

    /// Mapping from tid -> utid
    tid_to_utid: RwLock<HashMap<i32, i64>>,

    /// Counter for generating sequential upid values
    next_upid: AtomicI64,

    /// Mapping from pid -> upid
    pid_to_upid: RwLock<HashMap<i32, i64>>,
}

impl UtidGenerator {
    /// Create a new UtidGenerator with counters starting at 1.
    pub fn new() -> Self {
        Self {
            next_utid: AtomicI64::new(1),
            tid_to_utid: RwLock::new(HashMap::new()),
            next_upid: AtomicI64::new(1),
            pid_to_upid: RwLock::new(HashMap::new()),
        }
    }

    /// Get or create a utid for the given tid.
    ///
    /// If this is the first time seeing this tid, a new sequential utid is
    /// assigned and returned. Thread-safe via double-checked locking.
    pub fn get_or_create_utid(&self, tid: i32) -> i64 {
        // Fast path: check if already exists (read lock)
        {
            let map = self
                .tid_to_utid
                .read()
                .expect("utid map read lock poisoned");
            if let Some(&utid) = map.get(&tid) {
                return utid;
            }
        }

        // Slow path: need to insert (write lock)
        let mut map = self
            .tid_to_utid
            .write()
            .expect("utid map write lock poisoned");
        // Double-check after acquiring write lock (another thread may have inserted)
        if let Some(&utid) = map.get(&tid) {
            return utid;
        }

        let utid = self.next_utid.fetch_add(1, Ordering::Relaxed);
        map.insert(tid, utid);
        utid
    }

    /// Get utid for a tid if it exists, without creating a new one.
    pub fn get_utid(&self, tid: i32) -> Option<i64> {
        self.tid_to_utid
            .read()
            .expect("utid map read lock poisoned")
            .get(&tid)
            .copied()
    }

    /// Get or create an upid for the given pid.
    ///
    /// If this is the first time seeing this pid, a new sequential upid is
    /// assigned and returned. Thread-safe via double-checked locking.
    pub fn get_or_create_upid(&self, pid: i32) -> i64 {
        // Fast path: check if already exists (read lock)
        {
            let map = self
                .pid_to_upid
                .read()
                .expect("upid map read lock poisoned");
            if let Some(&upid) = map.get(&pid) {
                return upid;
            }
        }

        // Slow path: need to insert (write lock)
        let mut map = self
            .pid_to_upid
            .write()
            .expect("upid map write lock poisoned");
        // Double-check after acquiring write lock (another thread may have inserted)
        if let Some(&upid) = map.get(&pid) {
            return upid;
        }

        let upid = self.next_upid.fetch_add(1, Ordering::Relaxed);
        map.insert(pid, upid);
        upid
    }

    /// Get upid for a pid if it exists, without creating a new one.
    pub fn get_upid(&self, pid: i32) -> Option<i64> {
        self.pid_to_upid
            .read()
            .expect("upid map read lock poisoned")
            .get(&pid)
            .copied()
    }

    /// Get the complete tid_to_utid mapping.
    pub fn get_tid_to_utid_map(&self) -> HashMap<i32, i64> {
        self.tid_to_utid
            .read()
            .expect("utid map read lock poisoned")
            .clone()
    }

    /// Get the complete pid_to_upid mapping.
    pub fn get_pid_to_upid_map(&self) -> HashMap<i32, i64> {
        self.pid_to_upid
            .read()
            .expect("upid map read lock poisoned")
            .clone()
    }
}

impl Default for UtidGenerator {
    fn default() -> Self {
        Self::new()
    }
}
