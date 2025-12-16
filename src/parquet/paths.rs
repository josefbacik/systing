//! Parquet file path management.

use std::path::{Path, PathBuf};

/// Paths to all parquet output files.
pub struct ParquetPaths {
    pub process: PathBuf,
    pub thread: PathBuf,
    pub sched_slice: PathBuf,
    pub thread_state: PathBuf,
    pub counter: PathBuf,
    pub counter_track: PathBuf,
    pub slice: PathBuf,
    pub track: PathBuf,
    pub instant: PathBuf,
    pub args: PathBuf,
    pub instant_args: PathBuf,
    pub perf_sample: PathBuf,
    // Stack profiling tables
    pub symbol: PathBuf,
    pub frame: PathBuf,
    pub callsite: PathBuf,
    // Query-friendly stack tables
    pub stack: PathBuf,
    pub stack_sample: PathBuf,
    // Network metadata tables
    pub network_interface: PathBuf,
    pub socket_connection: PathBuf,
    // Clock snapshot table
    pub clock_snapshot: PathBuf,
}

/// Named path entry for iteration with names.
struct PathEntry<'a> {
    path: &'a PathBuf,
    name: &'static str,
}

impl ParquetPaths {
    /// Create paths for parquet files in the given directory.
    /// Files are named simply (e.g., `process.parquet`, not `trace_process.parquet`).
    pub fn new(dir: &Path) -> Self {
        Self {
            process: dir.join("process.parquet"),
            thread: dir.join("thread.parquet"),
            sched_slice: dir.join("sched_slice.parquet"),
            thread_state: dir.join("thread_state.parquet"),
            counter: dir.join("counter.parquet"),
            counter_track: dir.join("counter_track.parquet"),
            slice: dir.join("slice.parquet"),
            track: dir.join("track.parquet"),
            instant: dir.join("instant.parquet"),
            args: dir.join("args.parquet"),
            instant_args: dir.join("instant_args.parquet"),
            perf_sample: dir.join("perf_sample.parquet"),
            // Stack profiling tables
            symbol: dir.join("symbol.parquet"),
            frame: dir.join("frame.parquet"),
            callsite: dir.join("callsite.parquet"),
            // Query-friendly stack tables
            stack: dir.join("stack.parquet"),
            stack_sample: dir.join("stack_sample.parquet"),
            // Network metadata tables
            network_interface: dir.join("network_interface.parquet"),
            socket_connection: dir.join("socket_connection.parquet"),
            // Clock snapshot table
            clock_snapshot: dir.join("clock_snapshot.parquet"),
        }
    }

    /// Returns all paths with their names (single source of truth for path iteration).
    fn all_paths_with_names(&self) -> [PathEntry<'_>; 20] {
        [
            PathEntry {
                path: &self.process,
                name: "process",
            },
            PathEntry {
                path: &self.thread,
                name: "thread",
            },
            PathEntry {
                path: &self.sched_slice,
                name: "sched_slice",
            },
            PathEntry {
                path: &self.thread_state,
                name: "thread_state",
            },
            PathEntry {
                path: &self.counter,
                name: "counter",
            },
            PathEntry {
                path: &self.counter_track,
                name: "counter_track",
            },
            PathEntry {
                path: &self.slice,
                name: "slice",
            },
            PathEntry {
                path: &self.track,
                name: "track",
            },
            PathEntry {
                path: &self.instant,
                name: "instant",
            },
            PathEntry {
                path: &self.args,
                name: "args",
            },
            PathEntry {
                path: &self.instant_args,
                name: "instant_args",
            },
            PathEntry {
                path: &self.perf_sample,
                name: "perf_sample",
            },
            PathEntry {
                path: &self.symbol,
                name: "symbol",
            },
            PathEntry {
                path: &self.frame,
                name: "frame",
            },
            PathEntry {
                path: &self.callsite,
                name: "callsite",
            },
            PathEntry {
                path: &self.stack,
                name: "stack",
            },
            PathEntry {
                path: &self.stack_sample,
                name: "stack_sample",
            },
            PathEntry {
                path: &self.network_interface,
                name: "network_interface",
            },
            PathEntry {
                path: &self.socket_connection,
                name: "socket_connection",
            },
            PathEntry {
                path: &self.clock_snapshot,
                name: "clock_snapshot",
            },
        ]
    }

    /// Get total size of all parquet files in bytes.
    #[allow(dead_code)]
    pub fn total_size(&self) -> std::io::Result<u64> {
        let mut total = 0u64;
        for entry in self.all_paths_with_names() {
            if entry.path.exists() {
                total += std::fs::metadata(entry.path)?.len();
            }
        }
        Ok(total)
    }

    /// List all files with their sizes.
    #[allow(dead_code)]
    pub fn file_sizes(&self) -> Vec<(String, u64)> {
        self.all_paths_with_names()
            .into_iter()
            .filter_map(|entry| {
                if entry.path.exists() {
                    std::fs::metadata(entry.path)
                        .ok()
                        .map(|m| (entry.name.to_string(), m.len()))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Get all file paths as a vector.
    #[allow(dead_code)]
    pub fn all_paths(&self) -> Vec<&PathBuf> {
        self.all_paths_with_names()
            .into_iter()
            .map(|entry| entry.path)
            .collect()
    }
}
