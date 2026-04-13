//! Parquet file path management.
//!
//! This module provides the `ParquetPaths` struct for managing paths to all
//! parquet output files. It is shared between the systing binary and
//! systing-analyze tool.

use std::path::{Path, PathBuf};

/// Paths to all parquet output files.
#[derive(Debug, Clone)]
pub struct ParquetPaths {
    pub process: PathBuf,
    pub thread: PathBuf,
    pub sched_slice: PathBuf,
    pub thread_state: PathBuf,
    // IRQ/softirq tables
    pub irq_slice: PathBuf,
    pub softirq_slice: PathBuf,
    pub wakeup_new: PathBuf,
    pub process_exit: PathBuf,
    pub counter: PathBuf,
    pub counter_track: PathBuf,
    pub slice: PathBuf,
    pub track: PathBuf,
    pub instant: PathBuf,
    pub args: PathBuf,
    pub instant_args: PathBuf,
    // Stack tables (query-friendly format, used by systing record)
    pub stack: PathBuf,
    pub stack_sample: PathBuf,
    // Legacy stack profile tables (used by systing-analyze for Perfetto .pb extraction)
    pub symbol: PathBuf,
    pub stack_mapping: PathBuf,
    pub frame: PathBuf,
    pub callsite: PathBuf,
    pub perf_sample: PathBuf,
    // Network metadata tables (legacy)
    pub network_interface: PathBuf,
    pub socket_connection: PathBuf,
    // New network tables (Phase 1 of network recorder refactor)
    pub network_syscall: PathBuf,
    pub network_packet: PathBuf,
    pub network_socket: PathBuf,
    pub network_poll: PathBuf,
    pub network_dns: PathBuf,
    // Memory tables
    pub memory_rss: PathBuf,
    pub memory_map: PathBuf,
    pub memory_fault: PathBuf,
    pub memory_alloc: PathBuf,
    // Clock snapshot table
    pub clock_snapshot: PathBuf,
    // System info table
    pub sysinfo: PathBuf,
    // TPU tables
    pub tpu_device: PathBuf,
    pub tpu_op: PathBuf,
    pub tpu_metric: PathBuf,
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
            // IRQ/softirq tables
            irq_slice: dir.join("irq_slice.parquet"),
            softirq_slice: dir.join("softirq_slice.parquet"),
            wakeup_new: dir.join("wakeup_new.parquet"),
            process_exit: dir.join("process_exit.parquet"),
            counter: dir.join("counter.parquet"),
            counter_track: dir.join("counter_track.parquet"),
            slice: dir.join("slice.parquet"),
            track: dir.join("track.parquet"),
            instant: dir.join("instant.parquet"),
            args: dir.join("args.parquet"),
            instant_args: dir.join("instant_args.parquet"),
            // Stack tables (query-friendly format)
            stack: dir.join("stack.parquet"),
            stack_sample: dir.join("stack_sample.parquet"),
            // Legacy stack profile tables (for Perfetto .pb extraction)
            symbol: dir.join("symbol.parquet"),
            stack_mapping: dir.join("mapping.parquet"),
            frame: dir.join("frame.parquet"),
            callsite: dir.join("callsite.parquet"),
            perf_sample: dir.join("perf_sample.parquet"),
            // Network metadata tables (legacy)
            network_interface: dir.join("network_interface.parquet"),
            socket_connection: dir.join("socket_connection.parquet"),
            // New network tables
            network_syscall: dir.join("network_syscall.parquet"),
            network_packet: dir.join("network_packet.parquet"),
            network_socket: dir.join("network_socket.parquet"),
            network_poll: dir.join("network_poll.parquet"),
            network_dns: dir.join("network_dns.parquet"),
            // Memory tables
            memory_rss: dir.join("memory_rss.parquet"),
            memory_map: dir.join("memory_map.parquet"),
            memory_fault: dir.join("memory_fault.parquet"),
            memory_alloc: dir.join("memory_alloc.parquet"),
            // Clock snapshot table
            clock_snapshot: dir.join("clock_snapshot.parquet"),
            // System info table
            sysinfo: dir.join("sysinfo.parquet"),
            // TPU tables
            tpu_device: dir.join("tpu_device.parquet"),
            tpu_op: dir.join("tpu_op.parquet"),
            tpu_metric: dir.join("tpu_metric.parquet"),
        }
    }

    /// Create paths for parquet files with a trace_id prefix.
    /// Files are named with the trace_id (e.g., `{trace_id}_process.parquet`).
    /// Used by systing-analyze when extracting from Perfetto .pb files.
    pub fn with_trace_prefix(dir: &Path, trace_id: &str) -> Self {
        Self {
            process: dir.join(format!("{trace_id}_process.parquet")),
            thread: dir.join(format!("{trace_id}_thread.parquet")),
            sched_slice: dir.join(format!("{trace_id}_sched_slice.parquet")),
            thread_state: dir.join(format!("{trace_id}_thread_state.parquet")),
            irq_slice: dir.join(format!("{trace_id}_irq_slice.parquet")),
            softirq_slice: dir.join(format!("{trace_id}_softirq_slice.parquet")),
            wakeup_new: dir.join(format!("{trace_id}_wakeup_new.parquet")),
            process_exit: dir.join(format!("{trace_id}_process_exit.parquet")),
            counter: dir.join(format!("{trace_id}_counter.parquet")),
            counter_track: dir.join(format!("{trace_id}_counter_track.parquet")),
            slice: dir.join(format!("{trace_id}_slice.parquet")),
            track: dir.join(format!("{trace_id}_track.parquet")),
            instant: dir.join(format!("{trace_id}_instant.parquet")),
            args: dir.join(format!("{trace_id}_args.parquet")),
            instant_args: dir.join(format!("{trace_id}_instant_args.parquet")),
            stack: dir.join(format!("{trace_id}_stack.parquet")),
            stack_sample: dir.join(format!("{trace_id}_stack_sample.parquet")),
            symbol: dir.join(format!("{trace_id}_symbol.parquet")),
            stack_mapping: dir.join(format!("{trace_id}_stack_mapping.parquet")),
            frame: dir.join(format!("{trace_id}_frame.parquet")),
            callsite: dir.join(format!("{trace_id}_callsite.parquet")),
            perf_sample: dir.join(format!("{trace_id}_perf_sample.parquet")),
            network_interface: dir.join(format!("{trace_id}_network_interface.parquet")),
            socket_connection: dir.join(format!("{trace_id}_socket_connection.parquet")),
            network_syscall: dir.join(format!("{trace_id}_network_syscall.parquet")),
            network_packet: dir.join(format!("{trace_id}_network_packet.parquet")),
            network_socket: dir.join(format!("{trace_id}_network_socket.parquet")),
            network_poll: dir.join(format!("{trace_id}_network_poll.parquet")),
            network_dns: dir.join(format!("{trace_id}_network_dns.parquet")),
            memory_rss: dir.join(format!("{trace_id}_memory_rss.parquet")),
            memory_map: dir.join(format!("{trace_id}_memory_map.parquet")),
            memory_fault: dir.join(format!("{trace_id}_memory_fault.parquet")),
            memory_alloc: dir.join(format!("{trace_id}_memory_alloc.parquet")),
            clock_snapshot: dir.join(format!("{trace_id}_clock_snapshot.parquet")),
            sysinfo: dir.join(format!("{trace_id}_sysinfo.parquet")),
            // TPU tables
            tpu_device: dir.join(format!("{trace_id}_tpu_device.parquet")),
            tpu_op: dir.join(format!("{trace_id}_tpu_op.parquet")),
            tpu_metric: dir.join(format!("{trace_id}_tpu_metric.parquet")),
        }
    }

    /// Returns all paths with their names (single source of truth for path iteration).
    fn all_paths_with_names(&self) -> [PathEntry<'_>; 38] {
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
                path: &self.irq_slice,
                name: "irq_slice",
            },
            PathEntry {
                path: &self.softirq_slice,
                name: "softirq_slice",
            },
            PathEntry {
                path: &self.wakeup_new,
                name: "wakeup_new",
            },
            PathEntry {
                path: &self.process_exit,
                name: "process_exit",
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
                path: &self.stack,
                name: "stack",
            },
            PathEntry {
                path: &self.stack_sample,
                name: "stack_sample",
            },
            // Legacy stack profile tables
            PathEntry {
                path: &self.symbol,
                name: "symbol",
            },
            PathEntry {
                path: &self.stack_mapping,
                name: "stack_mapping",
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
                path: &self.perf_sample,
                name: "perf_sample",
            },
            PathEntry {
                path: &self.memory_rss,
                name: "memory_rss",
            },
            PathEntry {
                path: &self.memory_map,
                name: "memory_map",
            },
            PathEntry {
                path: &self.memory_fault,
                name: "memory_fault",
            },
            PathEntry {
                path: &self.memory_alloc,
                name: "memory_alloc",
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
                path: &self.network_syscall,
                name: "network_syscall",
            },
            PathEntry {
                path: &self.network_packet,
                name: "network_packet",
            },
            PathEntry {
                path: &self.network_socket,
                name: "network_socket",
            },
            PathEntry {
                path: &self.network_poll,
                name: "network_poll",
            },
            PathEntry {
                path: &self.network_dns,
                name: "network_dns",
            },
            PathEntry {
                path: &self.clock_snapshot,
                name: "clock_snapshot",
            },
            PathEntry {
                path: &self.sysinfo,
                name: "sysinfo",
            },
            PathEntry {
                path: &self.tpu_device,
                name: "tpu_device",
            },
            PathEntry {
                path: &self.tpu_op,
                name: "tpu_op",
            },
            PathEntry {
                path: &self.tpu_metric,
                name: "tpu_metric",
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
