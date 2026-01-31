//! Thread-safe generator for unique thread and process IDs (utid/upid).
//!
//! During streaming mode, this generator maintains consistent tid->utid and pid->upid
//! mappings across all recorders, ensuring that sched events, stack samples, and thread
//! records all use the same utid values.
//!
//! # Thread Safety
//!
//! The generator uses `AtomicI64` for lock-free ID generation and `DashMap` for
//! lock-free concurrent mapping storage. DashMap uses fine-grained sharded locking
//! internally, providing much better concurrent performance than RwLock<HashMap>.
//!
//! # ID Sequentiality
//!
//! Under concurrent access from multiple threads, ID values may not be strictly
//! sequential (gaps can occur due to concurrent insertions racing on the same key).
//! However, uniqueness is always guaranteed. This is acceptable for trace analysis
//! where only uniqueness matters, not density of ID values.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};

use dashmap::DashMap;

/// Thread-safe generator for utid (unique thread ID) and upid (unique process ID) values.
///
/// This structure maintains mappings from OS thread/process IDs to unique internal IDs
/// and generates sequential values for new threads/processes.
#[derive(Debug)]
pub struct UtidGenerator {
    /// Counter for generating sequential utid values
    next_utid: AtomicI64,

    /// Mapping from tid -> utid (using DashMap for lock-free concurrent access)
    tid_to_utid: DashMap<i32, i64>,

    /// Counter for generating sequential upid values
    next_upid: AtomicI64,

    /// Mapping from pid -> upid (using DashMap for lock-free concurrent access)
    pid_to_upid: DashMap<i32, i64>,
}

/// Initial capacity for thread ID map. Sized to handle typical systems without rehashing.
const INITIAL_TID_CAPACITY: usize = 4096;

/// Initial capacity for process ID map. Typically fewer processes than threads.
const INITIAL_PID_CAPACITY: usize = 1024;

impl UtidGenerator {
    /// Create a new UtidGenerator with counters starting at 1.
    pub fn new() -> Self {
        Self {
            next_utid: AtomicI64::new(1),
            tid_to_utid: DashMap::with_capacity(INITIAL_TID_CAPACITY),
            next_upid: AtomicI64::new(1),
            pid_to_upid: DashMap::with_capacity(INITIAL_PID_CAPACITY),
        }
    }

    /// Get or create a utid for the given tid.
    ///
    /// If this is the first time seeing this tid, a new sequential utid is
    /// assigned and returned. Thread-safe via DashMap's internal sharded locking.
    pub fn get_or_create_utid(&self, tid: i32) -> i64 {
        // DashMap's entry API handles the get-or-insert atomically.
        // Relaxed ordering is sufficient - we only need uniqueness, not synchronization.
        *self
            .tid_to_utid
            .entry(tid)
            .or_insert_with(|| self.next_utid.fetch_add(1, Ordering::Relaxed))
    }

    /// Get utid for a tid if it exists, without creating a new one.
    pub fn get_utid(&self, tid: i32) -> Option<i64> {
        self.tid_to_utid.get(&tid).as_deref().copied()
    }

    /// Get or create an upid for the given pid.
    ///
    /// If this is the first time seeing this pid, a new sequential upid is
    /// assigned and returned. Thread-safe via DashMap's internal sharded locking.
    pub fn get_or_create_upid(&self, pid: i32) -> i64 {
        // DashMap's entry API handles the get-or-insert atomically.
        // Relaxed ordering is sufficient - we only need uniqueness, not synchronization.
        *self
            .pid_to_upid
            .entry(pid)
            .or_insert_with(|| self.next_upid.fetch_add(1, Ordering::Relaxed))
    }

    /// Get upid for a pid if it exists, without creating a new one.
    pub fn get_upid(&self, pid: i32) -> Option<i64> {
        self.pid_to_upid.get(&pid).as_deref().copied()
    }

    /// Get the complete tid_to_utid mapping.
    pub fn get_tid_to_utid_map(&self) -> HashMap<i32, i64> {
        self.tid_to_utid
            .iter()
            .map(|r| (*r.key(), *r.value()))
            .collect()
    }

    /// Get the complete pid_to_upid mapping.
    pub fn get_pid_to_upid_map(&self) -> HashMap<i32, i64> {
        self.pid_to_upid
            .iter()
            .map(|r| (*r.key(), *r.value()))
            .collect()
    }
}

impl Default for UtidGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_utid_generator_handles_tid_zero() {
        // Regression test: tid=0 (swapper/idle) must get a unique utid that
        // won't collide with other threads' utids.
        let gen = UtidGenerator::new();

        // First thread with tid=0 (swapper/idle)
        let utid_swapper = gen.get_or_create_utid(0);

        // Different thread with tid=1234
        let utid_other = gen.get_or_create_utid(1234);

        // They should have different utids
        assert_ne!(utid_swapper, utid_other);

        // utid should be positive (non-zero) to avoid confusion with tid=0
        assert!(utid_swapper > 0);

        // Looking up tid=0 again should return the same utid
        assert_eq!(gen.get_or_create_utid(0), utid_swapper);
    }

    #[test]
    fn test_utid_generator_sequential() {
        let gen = UtidGenerator::new();

        // First utid should be 1
        assert_eq!(gen.get_or_create_utid(100), 1);
        // Second utid should be 2
        assert_eq!(gen.get_or_create_utid(200), 2);
        // Looking up existing tid returns same utid
        assert_eq!(gen.get_or_create_utid(100), 1);
    }

    #[test]
    fn test_upid_generator_sequential() {
        let gen = UtidGenerator::new();

        // First upid should be 1
        assert_eq!(gen.get_or_create_upid(1000), 1);
        // Second upid should be 2
        assert_eq!(gen.get_or_create_upid(2000), 2);
        // Looking up existing pid returns same upid
        assert_eq!(gen.get_or_create_upid(1000), 1);
    }

    #[test]
    fn test_concurrent_utid_creation() {
        use std::sync::Arc;
        use std::thread;

        let gen = Arc::new(UtidGenerator::new());
        let mut handles = vec![];

        // Spawn multiple threads that all try to create utids for the same tids
        for _ in 0..10 {
            let gen = Arc::clone(&gen);
            handles.push(thread::spawn(move || {
                for tid in 0..100 {
                    gen.get_or_create_utid(tid);
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        // Verify all tids got unique utids
        let map = gen.get_tid_to_utid_map();
        assert_eq!(map.len(), 100);

        // Verify all utids are unique
        let mut utids: Vec<_> = map.values().copied().collect();
        utids.sort();
        utids.dedup();
        assert_eq!(utids.len(), 100);
    }
}
