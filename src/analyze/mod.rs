//! Analysis logic for querying and analyzing systing trace databases.
//!
//! This module provides the core analysis functionality used by both the CLI
//! and MCP server interfaces. All methods are synchronous and work directly
//! with DuckDB connections.

mod cpu_stats;
mod flamegraph;
mod network_connections;
mod network_interfaces;
mod network_socket_pairs;
mod query;
mod sched_aggregate;
mod sched_stats;

pub use cpu_stats::{CpuStatsParams, CpuStatsResult, CpuStatsSummary, PerCpuStats};
pub use flamegraph::{
    FlamegraphMetadata, FlamegraphParams, FlamegraphResult, StackEntry, StackTypeFilter,
};
pub use network_connections::{
    ConnectionStats, NetworkConnectionsParams, NetworkConnectionsResult, TraceConnectionStats,
};
pub use network_interfaces::{
    InterfaceStats, NetworkInterfacesParams, NetworkInterfacesResult, TraceNetworkStats,
    TrafficStats,
};
pub use network_socket_pairs::{
    NetworkSocketPairsParams, NetworkSocketPairsResult, SocketPair, SocketSide,
};
pub use sched_aggregate::{
    Dist, Imbalance, PerCpu, RqDist, SchedAggregate, SchedAggregateMeta, SchedAggregateParams,
    SwitchStats, TailContributor, HIST_BASE_LOG2, HIST_OCTAVES,
};
pub use sched_stats::{
    EndStateCount, ProcessSchedStats, SchedStatsParams, SchedStatsResult, SchedSummary,
    ThreadDetailStats, ThreadSchedStats,
};

use anyhow::{bail, Context as _, Result};
use duckdb::Connection;
use serde::Serialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use query::{duckdb_value_to_json, duckdb_value_to_string, statement_shape, StatementShape};

/// Distinguishes the spill directories of databases opened by one process:
/// DuckDB names temp files by block id, which is only unique per instance, so
/// instances sharing a temp_directory could clobber each other's spills.
static SPILL_DIR_SEQ: AtomicU64 = AtomicU64::new(0);

/// Best-effort removal of spill directories left behind by dead processes.
/// DuckDB only cleans its temp files up on graceful shutdown, so an OOM-killed
/// or SIGKILLed process leaves its whole spill directory behind; reclaim it
/// once the owning pid is gone. Directories whose embedded pid is alive (or
/// reused) are skipped — a stale dir then just waits for a later sweep.
fn sweep_stale_spill_dirs(tmp: &Path) {
    let Ok(entries) = std::fs::read_dir(tmp) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(rest) = name
            .to_str()
            .and_then(|n| n.strip_prefix("systing-analyze-spill-"))
        else {
            continue;
        };
        let Some(pid) = rest.split('-').next().and_then(|p| p.parse::<u32>().ok()) else {
            continue;
        };
        if pid != std::process::id() && !Path::new(&format!("/proc/{pid}")).exists() {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// Create a per-instance spill directory under `tmp`, owner-only (0700): left
/// to DuckDB it would be created lazily with umask-default permissions, and
/// spill files contain trace contents (stack frames, process names, network
/// endpoints) that should not be world-readable on multi-user hosts.
///
/// Returns `None` if the directory cannot be created — some container
/// environments have no writable temp dir at all. The caller then disables
/// spilling entirely rather than inheriting DuckDB's default location (a
/// lazily-created, umask-permission `.tmp` directory next to the database),
/// which would quietly drop the owner-only protection. Without spilling, an
/// oversized aggregation gets a query error at the memory limit, which still
/// beats the OOM killer.
fn create_spill_dir(tmp: &Path) -> Option<PathBuf> {
    let spill_dir = tmp.join(format!(
        "systing-analyze-spill-{}-{}",
        std::process::id(),
        SPILL_DIR_SEQ.fetch_add(1, Ordering::Relaxed),
    ));
    use std::os::unix::fs::DirBuilderExt;
    // Non-recursive create: the directory name is predictable, so in a shared
    // temp dir it could be pre-created by another user with open permissions
    // (or as a symlink to a directory they control). AlreadyExists then lands
    // in the spilling-disabled fallback instead of adopting their directory.
    match std::fs::DirBuilder::new().mode(0o700).create(&spill_dir) {
        Ok(()) => Some(spill_dir),
        Err(e) => {
            eprintln!(
                "duckdb: cannot create spill dir {}: {e}; spilling disabled",
                spill_dir.display()
            );
            None
        }
    }
}

/// Maximum number of rows returned by a query.
pub const MAX_QUERY_ROWS: usize = 10_000;

/// Maximum number of processes returned in trace info summaries.
const MAX_TRACE_INFO_PROCESSES: usize = 25;

/// Result of a SQL query.
///
/// Serialized as `columns`, `rows`, `row_count`, and — only when the result
/// was cut at `MAX_QUERY_ROWS` — `truncated: true` plus `total_row_count`,
/// which is `null` when the separate count could not be computed.
#[derive(Debug)]
pub struct QueryResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<serde_json::Value>>,
    pub row_count: usize,
    pub truncated: bool,
    pub total_row_count: Option<usize>,
}

impl Serialize for QueryResult {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let fields = if self.truncated { 5 } else { 3 };
        let mut s = serializer.serialize_struct("QueryResult", fields)?;
        s.serialize_field("columns", &self.columns)?;
        s.serialize_field("rows", &self.rows)?;
        s.serialize_field("row_count", &self.row_count)?;
        if self.truncated {
            s.serialize_field("truncated", &true)?;
            s.serialize_field("total_row_count", &self.total_row_count)?;
        }
        s.end()
    }
}

/// Table information.
#[derive(Debug, Serialize)]
pub struct TableInfo {
    pub name: String,
    pub row_count: u64,
}

/// Column information.
#[derive(Debug, Serialize)]
pub struct ColumnInfo {
    pub name: String,
    #[serde(rename = "type")]
    pub data_type: String,
}

/// Process information.
#[derive(Debug, Serialize)]
pub struct ProcessInfo {
    pub pid: i64,
    pub name: String,
    pub thread_count: u64,
}

/// Time range information.
#[derive(Debug, Serialize)]
pub struct TimeRange {
    pub start_ns: i64,
    pub end_ns: i64,
    pub duration_seconds: f64,
}

/// Per-trace version information.
#[derive(Debug, Serialize)]
pub struct TraceVersionInfo {
    pub trace_id: String,
    pub systing_version: String,
}

/// Per-trace system/platform information (from the `sysinfo` table): what kind
/// of machine the trace was captured on. The platform columns were added in
/// schema v9 and read as `None` from older databases.
#[derive(Debug, Serialize)]
pub struct TraceSystemInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel_release: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub machine: Option<String>,
    /// Hypervisor the trace was captured under (e.g. "kvm"); `None` on bare
    /// metal (reliable on x86_64, best-effort elsewhere).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hypervisor: Option<String>,
    /// DMI system vendor (e.g. "Amazon EC2").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sys_vendor: Option<String>,
    /// DMI product name (e.g. "m7i.16xlarge").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_name: Option<String>,
    /// cpufreq scaling driver; `None` means the host had no cpufreq support,
    /// so CPU-frequency counter tracks are absent from the trace.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpufreq_driver: Option<String>,
    /// Perf event that drove CPU stack sampling: "cpu-cycles" (hardware) or
    /// "cpu-clock" (software fallback). `None` for traces from systing < 1.9,
    /// which sampled cpu-cycles in adaptive frequency mode at a nominal 1kHz.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_event: Option<String>,
    /// Stack sampling period in event units: one CPU stack sample
    /// (stack_event_type = 1) represents this many cycles ("cpu-cycles") or
    /// nanoseconds ("cpu-clock") of execution.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_period: Option<i64>,
    /// How the memory recorder's page-fault leg ran: "tracepoint" (x86),
    /// "perf_sw" (other arches) or "off:<cause>" (the leg could not be
    /// opened/attached on this host, so `memory_fault` is empty by
    /// construction). `None` when the memory recorder was off, and for
    /// traces from systing < 1.14.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_fault_leg: Option<String>,
    /// `--memory-fault-sample-rate` at capture time (1 in N; 0 or 1 = every
    /// fault): the factor to scale `memory_fault` counts by.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_fault_sample_rate: Option<i64>,
    /// `--memory-map-sample-rate` at capture time (1 in N per event type).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_map_sample_rate: Option<i64>,
    /// `--memory-alloc-sample-rate` at capture time; `None` when the
    /// `memory-alloc` recorder was off.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_alloc_sample_rate: Option<i64>,
    /// How the VFIO/IOMMU legs ran ("on" / "off:<cause>"); `None` when not
    /// requested or for traces from systing < 1.15.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_vfio_leg: Option<String>,
    /// How the THP split leg ran ("on"; "on:pmd-global" / "on:pmd-entry"
    /// when the PMD probe sat at the 6.10+ funnel / the public entry on a
    /// build that inlined the worker; "on:pmd-only" (or ":global" /
    /// ":entry" suffixed), "on:page-only" or "off:<cause>"); `None` when
    /// its sample rate was 0.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_thp_leg: Option<String>,
    /// `--memory-thp-sample-rate` at capture time (1 in N splits).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_thp_sample_rate: Option<i64>,
    /// iommu runs / VFIO windows the `memory_iommu` histogram could not
    /// count (0 = complete, else a floor); `None` when the VFIO leg did not
    /// run or for traces from systing < 1.16.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_iommu_overflow: Option<i64>,
    /// What the end-of-capture AnonHugePages walk did
    /// ("complete:<read>/<candidates>", "capped:…", "budget:…"); `None` when
    /// the THP leg did not run or for traces from systing < 1.16.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_anon_huge_walk: Option<String>,
    /// How the memory recorder's mmap/munmap/brk hooks attached ("tracepoint"
    /// — the classic set as the default form; "fentry" — the opt-in
    /// trampoline set, the default in 1.17.0–1.17.2; "tracepoint:nosym",
    /// "tracepoint:nobtf", "tracepoint:notramp" — the classic set under the
    /// trampoline form, with why; or "off:<cause>" — the capture has no
    /// mmap/munmap/brk rows in memory_map); `None` when the memory recorder
    /// did not run or for traces from systing < 1.17, which always attached
    /// the classic tracepoints.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_syscall_leg: Option<String>,
    /// How the network recorder's TIME_WAIT leg attached ("kprobe" — the
    /// default form; "fentry" — the opt-in trampoline set, the default in
    /// 1.17.0–1.17.2; "kprobe:notramp", "kprobe:nobtf" — the kprobe set
    /// under the trampoline form, with why; or "off:<cause>" — off means the
    /// trace carries no TIME_WAIT transitions); `None` when the network
    /// recorder was off or for traces from systing < 1.17.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_tw_leg: Option<String>,
}

/// Trace metadata.
#[derive(Debug, Serialize)]
pub struct TraceInfo {
    pub database_path: String,
    pub traces: Vec<String>,
    pub trace_versions: Vec<TraceVersionInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<u32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub system: Vec<TraceSystemInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_range: Option<TimeRange>,
    pub tables: Vec<TableInfo>,
    pub total_process_count: u64,
    pub processes: Vec<ProcessInfo>,
}

/// Extract column names from a DuckDB result set.
fn extract_column_names(rows: &duckdb::Rows<'_>) -> (usize, Vec<String>) {
    let column_count = rows.as_ref().map_or(0, |r| r.column_count());
    let names = if let Some(row_ref) = rows.as_ref() {
        (0..column_count)
            .map(|i| {
                row_ref
                    .column_name(i)
                    .map_or("?".to_string(), |s| s.to_string())
            })
            .collect()
    } else {
        Vec::new()
    };
    (column_count, names)
}

/// Wrapper around a DuckDB connection for trace analysis.
pub struct AnalyzeDb {
    conn: Connection,
    path: PathBuf,
    /// DuckDB's configured `memory_limit` in MiB, when one was derived from
    /// the cgroup at open; named in the error a query gets when it exceeds it.
    mem_limit_mib: Option<u64>,
}

/// Text DuckDB puts at the front of every `OutOfMemoryException` message,
/// whether the buffer pool hit `memory_limit` or a spill hit
/// `max_temp_directory_size` ("failed to offload data block"): both bounds
/// throw that one exception class (DuckDB 1.5.4, the version `libduckdb-sys`
/// pins: the block-offload throw in `src/storage/temporary_file_manager.cpp`
/// for the spill bound, `src/storage/buffer/buffer_pool.cpp` for the buffer
/// pool), and the class renders with the "Out of Memory Error" prefix
/// (`src/common/exception.cpp`, `ExceptionType::OUT_OF_MEMORY`). The
/// binding's `Display` prints the engine's message bare, so it is matched as
/// a prefix: a user's own string literal that happens to contain the words
/// cannot trigger the rewrite.
const DUCKDB_OOM_MARKER: &str = "Out of Memory Error";

/// Whether `err` is DuckDB reporting that a query ran into the memory bound
/// (`memory_limit`) or the spill bound (`max_temp_directory_size`) — the
/// class `classify_query_error` rewrites, and the one a failed `prepare`
/// must not be retried on.
fn is_memory_bound_error(err: &duckdb::Error) -> bool {
    err.to_string().starts_with(DUCKDB_OOM_MARKER)
}

impl AnalyzeDb {
    /// Open a trace database.
    pub fn open(path: &Path, read_only: bool) -> Result<Self> {
        Self::open_with_spill_cap(path, read_only, None)
    }

    /// Open a trace database, optionally bounding DuckDB's on-disk spill.
    ///
    /// DuckDB derives its default `max_temp_directory_size` from the
    /// filesystem's free space, which quota-limited environments misreport:
    /// a Kubernetes emptyDir `sizeLimit` is enforced by a periodic kubelet
    /// scan, not by the filesystem, so `statvfs` reports the whole node's
    /// free disk and a single spilling query can blow past the quota and get
    /// the pod evicted mid-run. A caller that knows its real scratch budget
    /// passes it here (any DuckDB size string, e.g. "8GiB") so an oversized
    /// aggregation fails that one query instead of killing the process.
    ///
    /// The cap is applied twice on purpose. On the `Config` before the open,
    /// where DuckDB validates the size string (a malformed cap fails the open
    /// loudly) and records the value `current_setting` echoes — but DuckDB
    /// 1.5.4, the version `libduckdb-sys` pins, never hands a pre-open value
    /// to its buffer manager: `DatabaseInstance::Initialize` builds the
    /// buffer manager from the temp directory alone and only the setting's
    /// post-open path calls `BufferManager::SetSwapLimit`
    /// (`src/main/settings/custom_settings.cpp`, `src/main/database.cpp`), so
    /// a Config-only cap leaves the 90 %-of-free-space default in force while
    /// reading back as the requested bound. Then with a `SET` on the opened
    /// connection, which does reach the buffer manager and takes effect at
    /// the first spill. Because the readback cannot tell the two apart, the
    /// bound is proven by behaviour (`test_open_with_spill_cap_applies_bound`
    /// makes a query spill past it), never by `current_setting`.
    ///
    /// On its own this is a structural default, not a jail: unlike
    /// `temp_directory`, DuckDB does not lock this setting when external
    /// access is disabled, so in-session SQL can still raise it (covered by a
    /// test), which keeps deliberate tuning possible on the CLI. The MCP
    /// server, whose SQL is untrusted, freezes it along with every other
    /// setting by calling [`AnalyzeDb::lock_configuration`] right after open.
    pub fn open_with_spill_cap(
        path: &Path,
        read_only: bool,
        spill_cap: Option<&str>,
    ) -> Result<Self> {
        if !path.exists() {
            bail!("Database not found: {}", path.display());
        }

        // DuckDB sizes its buffer pool and thread pool from the host (80% of
        // physical RAM, one thread per CPU), not the cgroup, so analyzing a
        // large trace from a small container on a big node gets the whole
        // container OOM-killed mid-aggregation. Bound both from the cgroup
        // limit — 50% rather than the import path's 75%, because an analysis
        // container typically also hosts whatever is driving the MCP server —
        // and point spills at the system temp dir so oversized aggregations
        // hit disk instead of the OOM killer. Note temp_dir() honors TMPDIR;
        // if /tmp is a tmpfs (whose pages are charged to the same cgroup,
        // defeating the spill), point TMPDIR at a disk-backed directory.
        let (mem_limit_mib, threads) = crate::duckdb::duckdb_resource_limits(50, 512);
        let tmp = std::env::temp_dir();
        sweep_stale_spill_dirs(&tmp);
        let mut config = duckdb::Config::default().threads(threads as i64)?;
        // temp_directory must be set before enable_external_access(false):
        // DuckDB refuses to modify it once external access is disabled, even
        // on a Config that has not opened a database yet. An empty value
        // disables spilling, so the unwritable-temp-dir fallback never lands
        // spill files in DuckDB's umask-permission default location.
        config = match create_spill_dir(&tmp) {
            Some(spill_dir) => config.with("temp_directory", spill_dir.to_string_lossy())?,
            None => config.with("temp_directory", "")?,
        };
        if let Some(cap) = spill_cap {
            // Set on the Config, like temp_directory above: DuckDB validates
            // the size string at open, so a malformed cap fails loudly here
            // rather than being silently ignored, and `current_setting`
            // reports this value. It does NOT bound anything on its own (see
            // the doc-comment): the enforcing SET follows the open below.
            config = config.with("max_temp_directory_size", cap)?;
        }
        if let Some(m) = mem_limit_mib {
            config = config.max_memory(&format!("{m}MiB"))?;
            eprintln!("duckdb: memory_limit={m}MiB threads={threads}");
        } else {
            eprintln!("duckdb: threads={threads} (no cgroup memory limit detected)");
        }

        // Disable external access (reading/writing files, ATTACH, loading
        // extensions) so SQL run against an untrusted trace database -- e.g.
        // queries an AI assistant was prompt-injected into running via the MCP
        // server -- cannot touch anything outside the trace database. DuckDB
        // refuses to re-enable this setting while the database is running, so
        // it cannot be undone with a SET statement; it also locks
        // temp_directory, so injected SQL cannot redirect spills either.
        config = config.enable_external_access(false)?;
        if read_only {
            config = config.access_mode(duckdb::AccessMode::ReadOnly)?;
        }

        let conn = Connection::open_with_flags(path, config)?;

        if let Some(cap) = spill_cap {
            // The enforcing half: on a live database the setting's global
            // setter calls `BufferManager::SetSwapLimit`, which the buffer
            // manager carries until its temp directory is created and
            // applies at the first spill. This runs before any caller's
            // `lock_configuration`, which is what freezes it afterwards. The
            // string was validated by the Config above; the single quotes
            // are doubled anyway so a size string can never end the literal.
            let literal = cap.replace('\'', "''");
            conn.execute_batch(&format!("SET max_temp_directory_size = '{literal}'"))
                .with_context(|| format!("failed to apply max_temp_directory_size={cap}"))?;
            eprintln!("duckdb: max_temp_directory_size={cap}");
        }

        Ok(Self {
            conn,
            path: path.to_path_buf(),
            mem_limit_mib,
        })
    }

    /// Rewrite a DuckDB out-of-memory failure into a fixed, actionable message
    /// that names the bound instead of echoing the engine's allocation text;
    /// every other error is returned as-is so SQL mistakes keep naming the
    /// offending column or table.
    fn classify_query_error(&self, err: duckdb::Error) -> anyhow::Error {
        if is_memory_bound_error(&err) {
            let bound = match self.mem_limit_mib {
                Some(m) => format!(" ({m} MiB)"),
                None => String::new(),
            };
            anyhow::anyhow!(
                "query exceeded the DuckDB memory bound{bound}: narrow the time window, add LIMIT, or aggregate"
            )
        } else {
            err.into()
        }
    }

    /// Freeze DuckDB's configuration for the rest of this connection's life:
    /// every later `SET` / `RESET` / `PRAGMA` of a configuration option
    /// (`memory_limit`, `threads`, `max_temp_directory_size`, ...) fails with
    /// DuckDB's own "configuration has been locked" error, and the lock
    /// itself cannot be undone. The MCP server calls this right after
    /// `open`, so SQL that reaches it — including SQL an AI assistant was
    /// talked into running — cannot lift the memory and spill bounds the
    /// server was started with. The CLI does not lock, so an operator's own
    /// in-session tuning keeps working there.
    pub fn lock_configuration(&self) -> Result<()> {
        self.conn
            .execute_batch("SET lock_configuration = true")
            .map_err(|e| anyhow::anyhow!("failed to lock the DuckDB configuration: {e}"))
    }

    /// Execute a SQL query and return typed results.
    ///
    /// At most `MAX_QUERY_ROWS` rows come back. The bound is applied inside
    /// DuckDB — the statement runs as `SELECT * FROM (<sql>) LIMIT
    /// MAX_QUERY_ROWS + 1` — so a query whose full result would be millions of
    /// rows never materializes them: the binding fetches the whole result set
    /// of whatever statement it executes, outside DuckDB's `memory_limit`
    /// accounting, and an unbounded result on a large trace is what grew the
    /// process past its cgroup limit. When the result is truncated,
    /// `total_row_count` comes from a separate `SELECT count(*) FROM (<sql>)`,
    /// which re-runs the query's pipeline once under DuckDB's memory bound
    /// without materializing rows (the inner ORDER BY runs again too; that is
    /// time, not memory).
    ///
    /// The text is classified first (`statement_shape`): comments and
    /// leading/trailing `;` are stripped so they cannot hide a statement
    /// from the wrapper, more than one statement is refused, and so is any
    /// bare `$` (dollar-quoted strings, `$n` parameters) — the one lexical
    /// construct under which the classifier and DuckDB could disagree about
    /// where a statement ends. That agreement matters: the binding's
    /// `prepare` is not parse-only, it EXECUTES every statement but the last
    /// of the text it is handed, so nothing may reach `prepare` unless the
    /// classifier has established that it is exactly one statement. One
    /// statement of the user's can still become two inside DuckDB: a
    /// `PIVOT` with no `IN (...)` list is expanded by the parser into a
    /// `CREATE TYPE ... AS ENUM (SELECT DISTINCT ...)` ahead of the SELECT,
    /// so that shape is refused too, and a prepare that nevertheless runs
    /// into the memory bound is reported as the bound and never retried. A
    /// statement that reads rows (`SELECT`, `WITH`, `FROM`, `VALUES`, ...)
    /// runs ONLY in wrapped form: if it cannot be wrapped it is refused, and
    /// a SQL error in it is reported against the user's own text by
    /// preparing the raw statement — safe only because it is one statement.
    /// Statements that cannot be embedded as a subquery (`SHOW`, `PRAGMA`,
    /// `DESCRIBE`, `SUMMARIZE`, `EXPLAIN`, ...) run as written with the cap
    /// applied as rows are read; their results are small by nature. A
    /// failure while *executing* the wrapped statement is reported directly
    /// — the raw statement is never re-run unbounded.
    ///
    /// Execution-time errors from the wrapped form name line numbers
    /// relative to the user's text plus the wrapper's first line.
    pub fn query(&self, sql: &str) -> Result<QueryResult> {
        let (inner, must_wrap) = match statement_shape(sql) {
            StatementShape::Empty => bail!("empty query"),
            StatementShape::Multiple => bail!(
                "only one statement per query is supported; remove the `;`-separated statement that follows the first one"
            ),
            StatementShape::Dollar => bail!(
                "dollar-quoted strings ($$...$$) and $-parameters are not supported here; use a single-quoted string literal"
            ),
            StatementShape::PivotWithoutIn => bail!(
                "PIVOT without an IN (...) value list is not supported here: DuckDB expands it into a CREATE TYPE ... AS ENUM (SELECT DISTINCT ...) statement ahead of the SELECT, which would run outside the row cap; name the pivot values with ON <column> IN (...)"
            ),
            StatementShape::Single { text, must_wrap } => (text, must_wrap),
        };
        // The newline before the closing paren is a belt on top of the
        // comment stripping: a `--` the classifier missed still cannot
        // swallow it.
        let wrapped = format!(
            "SELECT * FROM (\n{inner}\n) AS __systing_query LIMIT {}",
            MAX_QUERY_ROWS + 1
        );

        match self.conn.prepare(&wrapped) {
            Ok(mut stmt) => {
                let (mut result, beyond_cap) = self.run_capped(&mut stmt, false)?;
                if beyond_cap > 0 {
                    result.truncated = true;
                    result.total_row_count = self.count_rows(&inner);
                }
                Ok(result)
            }
            Err(err) => self.query_after_wrapped_prepare_failed(err, &inner, must_wrap),
        }
    }

    /// The rest of [`Self::query`] once the wrapped form failed to prepare
    /// with `err`. Split out so the decision below can be driven directly.
    ///
    /// The binding's `prepare` is not parse-only: it executes every
    /// statement but the last of the text it is handed, so a prepare can
    /// already have run a scan (a DuckDB-expanded statement the classifier
    /// let through) and hit the memory bound. That failure is reported as
    /// the bound — never as the engine's allocation text, which would tell
    /// the caller to raise a locked setting — and the text is not prepared
    /// a second time, which would run the same scan again for the same
    /// answer. Any other prepare failure falls through to the raw form.
    fn query_after_wrapped_prepare_failed(
        &self,
        err: duckdb::Error,
        inner: &str,
        must_wrap: bool,
    ) -> Result<QueryResult> {
        if is_memory_bound_error(&err) {
            return Err(self.classify_query_error(err));
        }
        // Prepare the user's own text so a SQL error names their line and
        // column, not the wrapper's.
        let mut stmt = self
            .conn
            .prepare(inner)
            .map_err(|e| self.classify_query_error(e))?;
        if must_wrap {
            // It prepares on its own but not inside the wrapper: a shape
            // that can read rows and that the cap cannot bound, so it does
            // not run at all rather than run unbounded.
            bail!(
                "query could not be bounded by the {MAX_QUERY_ROWS}-row cap; rewrite it as a single SELECT statement"
            );
        }
        // A non-row-reading statement: run it as written. Its result is
        // small by nature and already materialized, so the rows beyond the
        // cap are drained and counted.
        let (mut result, beyond_cap) = self.run_capped(&mut stmt, true)?;
        if beyond_cap > 0 {
            result.truncated = true;
            result.total_row_count = Some(result.row_count + beyond_cap);
        }
        Ok(result)
    }

    /// Execute a prepared statement and read up to `MAX_QUERY_ROWS` rows into
    /// a `QueryResult`. The second value is the number of rows seen beyond
    /// the cap: with `drain` set, every remaining row is read and counted;
    /// otherwise reading stops at the first one (so the value is 0 or 1).
    fn run_capped(
        &self,
        stmt: &mut duckdb::Statement<'_>,
        drain: bool,
    ) -> Result<(QueryResult, usize)> {
        let mut rows = stmt.query([]).map_err(|e| self.classify_query_error(e))?;
        let (column_count, column_names) = extract_column_names(&rows);

        let mut rows_data: Vec<Vec<serde_json::Value>> = Vec::new();
        let mut beyond_cap = 0usize;

        while let Some(row) = rows.next().map_err(|e| self.classify_query_error(e))? {
            if rows_data.len() >= MAX_QUERY_ROWS {
                beyond_cap += 1;
                if drain {
                    continue;
                }
                break;
            }
            let mut row_values = Vec::with_capacity(column_count);
            for i in 0..column_count {
                let value: duckdb::types::Value = row.get(i)?;
                row_values.push(duckdb_value_to_json(value));
            }
            rows_data.push(row_values);
        }

        let row_count = rows_data.len();
        Ok((
            QueryResult {
                columns: column_names,
                rows: rows_data,
                row_count,
                truncated: false,
                total_row_count: None,
            },
            beyond_cap,
        ))
    }

    /// Count the rows `sql` would produce, without materializing them. `None`
    /// if the count itself fails — the caller still reports the truncation.
    fn count_rows(&self, inner: &str) -> Option<usize> {
        let count_sql = format!("SELECT count(*) FROM (\n{inner}\n) AS __systing_query");
        self.conn
            .query_row(&count_sql, [], |r| r.get::<_, i64>(0))
            .ok()
            .and_then(|n| usize::try_from(n).ok())
    }

    /// Execute a query and return rows as string vectors (for table/csv display).
    pub fn query_strings(&self, sql: &str) -> Result<(Vec<String>, Vec<Vec<String>>)> {
        let mut stmt = self.conn.prepare(sql)?;
        let mut rows = stmt.query([])?;

        let (column_count, column_names) = extract_column_names(&rows);

        let mut rows_data: Vec<Vec<String>> = Vec::new();

        while let Some(row) = rows.next()? {
            let mut row_values = Vec::new();
            for i in 0..column_count {
                let value: duckdb::types::Value = row.get(i)?;
                let str_value = duckdb_value_to_string(value);
                row_values.push(str_value);
            }
            rows_data.push(row_values);
        }

        Ok((column_names, rows_data))
    }

    /// List all tables with row counts.
    pub fn list_tables(&self) -> Result<Vec<TableInfo>> {
        let mut stmt = self.conn.prepare(
            "SELECT table_name FROM information_schema.tables \
             WHERE table_schema = 'main' ORDER BY table_name",
        )?;
        let mut rows = stmt.query([])?;

        let mut tables = Vec::new();
        while let Some(row) = rows.next()? {
            let name: String = row.get(0)?;
            let count = self.table_row_count(&name).unwrap_or(0);
            tables.push(TableInfo {
                name,
                row_count: count,
            });
        }

        Ok(tables)
    }

    /// Describe a table's schema.
    pub fn describe_table(&self, table_name: &str) -> Result<Vec<ColumnInfo>> {
        if !self.table_exists(table_name)? {
            bail!("Table not found: {table_name}");
        }

        let mut stmt = self.conn.prepare(
            "SELECT column_name, data_type FROM information_schema.columns \
             WHERE table_schema = 'main' AND table_name = ? \
             ORDER BY ordinal_position",
        )?;
        let mut rows = stmt.query([table_name])?;

        let mut columns = Vec::new();
        while let Some(row) = rows.next()? {
            columns.push(ColumnInfo {
                name: row.get(0)?,
                data_type: row.get(1)?,
            });
        }

        Ok(columns)
    }

    /// Get trace metadata.
    pub fn trace_info(&self) -> Result<TraceInfo> {
        let all_tables = self.list_tables()?;
        let tables: Vec<TableInfo> = all_tables.into_iter().filter(|t| t.row_count > 0).collect();

        let traces = self.get_trace_ids()?;
        let trace_versions = self.get_trace_versions();
        let schema_version = self.get_schema_version();
        let system = self.get_system_info();

        let time_range =
            if self.table_exists("stack_sample")? && self.table_has_rows("stack_sample")? {
                match self.get_trace_time_range(None) {
                    Ok((min_ts, max_ts, _)) => Some(TimeRange {
                        start_ns: min_ts,
                        end_ns: max_ts,
                        duration_seconds: (max_ts - min_ts) as f64 / 1e9,
                    }),
                    Err(_) => None,
                }
            } else {
                None
            };

        let total_process_count = self.get_process_count()?;
        let processes = self.get_processes(MAX_TRACE_INFO_PROCESSES)?;

        Ok(TraceInfo {
            database_path: self.path.display().to_string(),
            traces,
            trace_versions,
            schema_version,
            system,
            time_range,
            tables,
            total_process_count,
            processes,
        })
    }

    /// Get the database path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Get the underlying connection (for interactive mode).
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    // -- Internal helpers --

    fn table_exists(&self, table_name: &str) -> Result<bool> {
        table_exists(&self.conn, table_name)
    }

    fn table_has_rows(&self, table_name: &str) -> Result<bool> {
        table_has_rows(&self.conn, table_name)
    }

    fn table_row_count(&self, table_name: &str) -> Result<u64> {
        let sql = format!("SELECT COUNT(*) FROM \"{table_name}\"");
        let mut stmt = self.conn.prepare(&sql)?;
        let mut rows = stmt.query([])?;
        if let Some(row) = rows.next()? {
            let count: i64 = row.get(0)?;
            Ok(count as u64)
        } else {
            Ok(0)
        }
    }

    fn get_trace_time_range(&self, trace_id: Option<&str>) -> Result<(i64, i64, u64)> {
        get_trace_time_range(&self.conn, trace_id)
    }

    fn get_trace_ids(&self) -> Result<Vec<String>> {
        for table in &["stack_sample", "thread", "process", "sched_slice"] {
            if !self.table_exists(table)? {
                continue;
            }
            let sql = format!("SELECT DISTINCT trace_id FROM \"{table}\" ORDER BY trace_id");
            match self.conn.prepare(&sql) {
                Ok(mut stmt) => {
                    let mut rows = stmt.query([])?;
                    let mut traces = Vec::new();
                    while let Some(row) = rows.next()? {
                        let id: String = row.get(0)?;
                        traces.push(id);
                    }
                    if !traces.is_empty() {
                        return Ok(traces);
                    }
                }
                Err(_) => continue,
            }
        }
        Ok(Vec::new())
    }

    /// Returns version info from `_traces`. Returns an empty vec for databases
    /// that predate the `systing_version` column.
    fn get_trace_versions(&self) -> Vec<TraceVersionInfo> {
        // Check if the systing_version column exists (older databases won't have it)
        let has_version: bool = self
            .conn
            .prepare(
                "SELECT COUNT(*) FROM information_schema.columns \
                 WHERE table_name = '_traces' AND column_name = 'systing_version'",
            )
            .and_then(|mut s| s.query_row([], |r| r.get::<_, u32>(0)))
            .map(|c| c > 0)
            .unwrap_or(false);

        if !has_version {
            return Vec::new();
        }

        let Ok(mut stmt) = self.conn.prepare(
            "SELECT trace_id, COALESCE(systing_version, '') FROM _traces ORDER BY trace_id",
        ) else {
            return Vec::new();
        };
        let Ok(rows) = stmt.query_map([], |row| {
            Ok(TraceVersionInfo {
                trace_id: row.get(0)?,
                systing_version: row.get(1)?,
            })
        }) else {
            return Vec::new();
        };
        rows.filter_map(|r| r.ok()).collect()
    }

    fn get_schema_version(&self) -> Option<u32> {
        let mut stmt = self
            .conn
            .prepare("SELECT version FROM _schema_version LIMIT 1")
            .ok()?;
        let mut rows = stmt.query([]).ok()?;
        let row = rows.next().ok()??;
        row.get(0).ok()
    }

    /// Per-trace system/platform info from the `sysinfo` table. Best-effort:
    /// the table may be missing entirely, and the platform columns
    /// (hypervisor, sys_vendor, product_name, cpufreq_driver) only exist from
    /// schema v9 on - missing columns are read as NULL so older databases
    /// still report kernel/machine.
    fn get_system_info(&self) -> Vec<TraceSystemInfo> {
        let existing: HashSet<String> = match self
            .conn
            .prepare(
                "SELECT column_name FROM information_schema.columns WHERE table_name = 'sysinfo'",
            )
            .and_then(|mut s| {
                s.query_map([], |r| r.get::<_, String>(0))
                    .map(|rows| rows.filter_map(|r| r.ok()).collect())
            }) {
            Ok(cols) => cols,
            Err(_) => return Vec::new(),
        };
        if existing.is_empty() {
            return Vec::new();
        }

        // Substitute NULL for any column this database predates.
        let col = |name: &str| -> String {
            if existing.contains(name) {
                format!("\"{name}\"")
            } else {
                "NULL".to_string()
            }
        };
        let sql = format!(
            "SELECT {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {} FROM sysinfo ORDER BY 1",
            col("trace_id"),
            col("release"),
            col("machine"),
            col("hypervisor"),
            col("sys_vendor"),
            col("product_name"),
            col("cpufreq_driver"),
            col("sample_event"),
            col("sample_period"),
            col("memory_fault_leg"),
            col("memory_fault_sample_rate"),
            col("memory_map_sample_rate"),
            col("memory_alloc_sample_rate"),
            col("memory_vfio_leg"),
            col("memory_thp_leg"),
            col("memory_thp_sample_rate"),
            col("memory_iommu_overflow"),
            col("memory_anon_huge_walk"),
            col("memory_syscall_leg"),
            col("network_tw_leg"),
        );

        let Ok(mut stmt) = self.conn.prepare(&sql) else {
            return Vec::new();
        };
        let Ok(rows) = stmt.query_map([], |row| {
            Ok(TraceSystemInfo {
                trace_id: row.get(0)?,
                kernel_release: row.get(1)?,
                machine: row.get(2)?,
                hypervisor: row.get(3)?,
                sys_vendor: row.get(4)?,
                product_name: row.get(5)?,
                cpufreq_driver: row.get(6)?,
                sample_event: row.get(7)?,
                sample_period: row.get(8)?,
                memory_fault_leg: row.get(9)?,
                memory_fault_sample_rate: row.get(10)?,
                memory_map_sample_rate: row.get(11)?,
                memory_alloc_sample_rate: row.get(12)?,
                memory_vfio_leg: row.get(13)?,
                memory_thp_leg: row.get(14)?,
                memory_thp_sample_rate: row.get(15)?,
                memory_iommu_overflow: row.get(16)?,
                memory_anon_huge_walk: row.get(17)?,
                memory_syscall_leg: row.get(18)?,
                network_tw_leg: row.get(19)?,
            })
        }) else {
            return Vec::new();
        };
        rows.filter_map(|r| r.ok()).collect()
    }

    fn get_process_count(&self) -> Result<u64> {
        if !self.table_exists("process")? {
            return Ok(0);
        }
        // Use the same grouping as get_processes (pid, name) so the count
        // matches the number of rows that query would return without a LIMIT.
        let mut stmt = self
            .conn
            .prepare("SELECT COUNT(*) FROM (SELECT DISTINCT pid, name FROM process)")?;
        let mut rows = stmt.query([])?;
        match rows.next()? {
            Some(row) => {
                let count: i64 = row.get(0)?;
                Ok(count as u64)
            }
            None => Ok(0),
        }
    }

    fn get_processes(&self, limit: usize) -> Result<Vec<ProcessInfo>> {
        if !self.table_exists("process")? {
            return Ok(Vec::new());
        }

        let has_thread = self.table_exists("thread")?;

        let sql = if has_thread {
            format!(
                "SELECT p.pid, COALESCE(p.name, ''), COUNT(DISTINCT t.tid) as thread_count \
                 FROM process p \
                 LEFT JOIN thread t ON p.upid = t.upid AND p.trace_id = t.trace_id \
                 GROUP BY p.pid, p.name \
                 ORDER BY thread_count DESC, p.pid \
                 LIMIT {limit}"
            )
        } else {
            format!("SELECT pid, COALESCE(name, ''), 0 FROM process ORDER BY pid LIMIT {limit}")
        };

        let mut stmt = self.conn.prepare(&sql)?;
        let mut rows = stmt.query([])?;
        let mut processes = Vec::new();

        while let Some(row) = rows.next()? {
            processes.push(ProcessInfo {
                pid: row.get(0)?,
                name: row.get(1)?,
                thread_count: {
                    let c: i64 = row.get(2)?;
                    c as u64
                },
            });
        }

        Ok(processes)
    }
}

// -- Free functions (module-internal) --

fn table_exists(conn: &Connection, table_name: &str) -> Result<bool> {
    let mut stmt = conn.prepare(
        "SELECT COUNT(*) FROM information_schema.tables \
         WHERE table_schema = 'main' AND table_name = ?",
    )?;
    let mut rows = stmt.query([table_name])?;
    if let Some(row) = rows.next()? {
        let count: i64 = row.get(0)?;
        Ok(count > 0)
    } else {
        Ok(false)
    }
}

fn table_has_rows(conn: &Connection, table_name: &str) -> Result<bool> {
    if !table_exists(conn, table_name)? {
        return Ok(false);
    }
    let sql = format!("SELECT 1 FROM \"{table_name}\" LIMIT 1");
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query([])?;
    Ok(rows.next()?.is_some())
}

/// Convert an i64 from DuckDB to u64, clamping negatives to 0.
pub(crate) fn to_u64(val: i64) -> u64 {
    u64::try_from(val).unwrap_or(0)
}

/// Build a trace_id SQL filter clause (e.g., ` AND ss.trace_id = '...'`).
/// trace_id values are escaped via single-quote doubling for safe SQL interpolation.
pub(crate) fn trace_id_filter(trace_id: Option<&str>, table_alias: &str) -> String {
    match trace_id {
        Some(tid) => {
            let escaped = tid.replace('\'', "''");
            format!(" AND {table_alias}trace_id = '{escaped}'")
        }
        None => String::new(),
    }
}

fn get_trace_time_range(conn: &Connection, trace_id: Option<&str>) -> Result<(i64, i64, u64)> {
    // trace_id is escaped via single-quote doubling for safe SQL interpolation
    let sql = if let Some(tid) = trace_id {
        let escaped = tid.replace('\'', "''");
        format!("SELECT MIN(ts), MAX(ts), COUNT(*) FROM stack_sample WHERE trace_id = '{escaped}'")
    } else {
        "SELECT MIN(ts), MAX(ts), COUNT(*) FROM stack_sample".to_string()
    };

    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query([])?;
    if let Some(row) = rows.next()? {
        let count: i64 = row.get(2)?;
        if count == 0 {
            bail!("No stack samples found in database");
        }
        let min_ts: i64 = row.get(0)?;
        let max_ts: i64 = row.get(1)?;
        Ok((min_ts, max_ts, count as u64))
    } else {
        bail!("No data in stack_sample table");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_u64_positive() {
        assert_eq!(to_u64(42), 42);
        assert_eq!(to_u64(0), 0);
        assert_eq!(to_u64(i64::MAX), i64::MAX as u64);
    }

    #[test]
    fn test_to_u64_negative() {
        assert_eq!(to_u64(-1), 0);
        assert_eq!(to_u64(i64::MIN), 0);
    }

    /// Assert that an error is DuckDB refusing an operation because external
    /// access is disabled. DuckDB 1.4 phrases this "disabled by configuration"
    /// for file access and "disabled through configuration" for extension
    /// loading (older releases used the latter for both).
    fn assert_external_access_blocked(err: &anyhow::Error) {
        let msg = err.to_string();
        assert!(
            msg.contains("disabled by configuration")
                || msg.contains("disabled through configuration"),
            "expected external-access error, got: {msg}"
        );
    }

    #[test]
    fn test_open_blocks_external_access() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.duckdb");

        // Create a small database to analyze.
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch("CREATE TABLE t (x INTEGER); INSERT INTO t VALUES (1);")
                .unwrap();
        }

        // An external file that queries must not be able to read.
        let csv_path = dir.path().join("external.csv");
        std::fs::write(&csv_path, "a,b\n1,2\n").unwrap();

        for read_only in [true, false] {
            let db = AnalyzeDb::open(&db_path, read_only).unwrap();

            // Queries against the trace database itself still work.
            let result = db.query("SELECT x FROM t").unwrap();
            assert_eq!(result.row_count, 1);

            // Reading external files is blocked.
            let read_err = db
                .query(&format!(
                    "SELECT * FROM read_csv_auto('{}')",
                    csv_path.display()
                ))
                .unwrap_err();
            assert_external_access_blocked(&read_err);

            // Writing external files is blocked.
            let copy_err = db
                .query(&format!(
                    "COPY (SELECT 1) TO '{}'",
                    dir.path().join("out.csv").display()
                ))
                .unwrap_err();
            assert_external_access_blocked(&copy_err);

            // Attaching other database files is blocked.
            let attach_err = db
                .query(&format!(
                    "ATTACH '{}' AS other",
                    dir.path().join("other.duckdb").display()
                ))
                .unwrap_err();
            assert_external_access_blocked(&attach_err);

            // Installing or loading external extensions (e.g. httpfs for
            // network egress) is blocked.
            assert!(db.query("INSTALL httpfs").is_err());
            let load_err = db.query("LOAD httpfs").unwrap_err();
            assert_external_access_blocked(&load_err);

            // The setting cannot be re-enabled at runtime. The exact wording
            // varies across libduckdb builds, so assert only on the setting
            // name — what matters is that the SET is refused.
            let set_err = db.query("SET enable_external_access = true").unwrap_err();
            let msg = set_err.to_string();
            assert!(
                msg.contains("external_access") || msg.contains("external access"),
                "unexpected error: {set_err}"
            );
        }
    }

    /// The spill bound is proven by BEHAVIOUR, never by `current_setting`:
    /// DuckDB 1.5.4 echoes a Config-time `max_temp_directory_size` from the
    /// config while its buffer manager can be enforcing the default (90 % of
    /// the filesystem's free space), so a readback assertion held for as long
    /// as the cap was dead. A hash aggregate with millions of groups must go
    /// out of core under a small memory limit — a `LIMIT`-wrapped `ORDER BY`
    /// would become a top-N heap and never spill — and under a 1MiB cap the
    /// spill is refused by DuckDB's out-of-memory class naming the setting;
    /// the same aggregate under a 10GiB cap completes, which pins the refusal
    /// on the spill bound rather than on the memory limit.
    #[test]
    fn test_open_with_spill_cap_applies_bound() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.duckdb");
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch("CREATE TABLE t (x INTEGER); INSERT INTO t VALUES (1);")
                .unwrap();
        }
        // 12M distinct groups: hundreds of MB of hash table, far past 1MiB of
        // spill under a 128MiB memory limit, comfortably under 10GiB.
        const SPILLING_AGGREGATE: &str = "SELECT count(*) FROM \
             (SELECT hash(v) AS h, count(*) AS c FROM range(12000000) t(v) GROUP BY h) \
             WHERE c = 1";
        // The memory limit is not under test: large enough that the
        // aggregate spills instead of failing on memory, small enough that it
        // must spill.
        const SPILLING_MEMORY_LIMIT: &str = "SET memory_limit = '128MiB'";

        let capped = AnalyzeDb::open_with_spill_cap(&db_path, true, Some("1MiB")).unwrap();
        capped.conn.execute_batch(SPILLING_MEMORY_LIMIT).unwrap();
        // The raw engine error names the bound that refused the spill.
        let raw = capped
            .conn
            .execute_batch(SPILLING_AGGREGATE)
            .expect_err("a spill past a 1MiB cap completed: the cap is not in force")
            .to_string();
        assert!(
            raw.contains("max_temp_directory_size"),
            "the spill was refused by something other than the spill bound: {raw}"
        );
        // Through the query path the tool sees the fixed memory-bound message.
        let err = capped.query(SPILLING_AGGREGATE).unwrap_err().to_string();
        assert!(
            err.starts_with("query exceeded the DuckDB memory bound"),
            "unexpected error: {err}"
        );

        // Control: the same aggregate under a cap it never reaches completes,
        // so the refusal above is the spill bound, not the memory limit.
        let roomy = AnalyzeDb::open_with_spill_cap(&db_path, true, Some("10GiB")).unwrap();
        roomy.conn.execute_batch(SPILLING_MEMORY_LIMIT).unwrap();
        let result = roomy
            .query(SPILLING_AGGREGATE)
            .expect("the aggregate under a 10GiB cap");
        assert_eq!(result.row_count, 1);

        // Secondary: the readback still reports the requested value.
        let v = capped
            .query("SELECT current_setting('max_temp_directory_size')")
            .unwrap();
        assert_eq!(v.rows[0][0].as_str().unwrap(), "1.0 MiB");
    }

    #[test]
    fn test_open_with_invalid_spill_cap_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.duckdb");
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch("CREATE TABLE t (x INTEGER);").unwrap();
        }

        // A malformed size string must fail the open loudly, not be ignored.
        let err = AnalyzeDb::open_with_spill_cap(&db_path, true, Some("not-a-size"));
        assert!(err.is_err(), "malformed spill cap was silently accepted");
    }

    /// Documents the cap's trust boundary on an UNLOCKED connection (the CLI):
    /// `enable_external_access(false)` locks `temp_directory` but NOT
    /// `max_temp_directory_size`, so SQL run in-session can still raise the
    /// bound. The flag alone is a structural default protecting against
    /// queries that never think about spill (the real-world failure mode);
    /// the MCP server closes the adversarial case with `lock_configuration`
    /// (see `test_lock_configuration_refuses_settings`). If DuckDB ever
    /// starts locking this setting alongside temp_directory, this test
    /// fails and the doc-comments should be updated to promise more.
    #[test]
    fn test_spill_cap_is_session_overridable() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.duckdb");
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch("CREATE TABLE t (x INTEGER);").unwrap();
        }
        let db = AnalyzeDb::open_with_spill_cap(&db_path, true, Some("100MiB")).unwrap();
        db.query("SET max_temp_directory_size = '999GiB'")
            .expect("session SET is currently allowed for this setting");
        let v = db
            .query("SELECT current_setting('max_temp_directory_size')")
            .unwrap();
        assert_eq!(v.rows[0][0].as_str().unwrap(), "999.0 GiB");
    }

    #[test]
    fn test_create_spill_dir_unwritable_parent() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().unwrap();
        let ro = base.path().join("ro");
        std::fs::create_dir(&ro).unwrap();
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o500)).unwrap();

        // Root ignores directory write bits, so the failure path can only be
        // exercised as an unprivileged user; probe instead of checking uid.
        if std::fs::write(ro.join("probe"), b"").is_err() {
            assert!(create_spill_dir(&ro).is_none());
        }

        // Restore write permission so TempDir cleanup succeeds.
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o700)).unwrap();

        // The fallback feeds '' to DuckDB to disable spilling; make sure that
        // is accepted at config time and sticks.
        let conn = Connection::open_in_memory_with_flags(
            duckdb::Config::default()
                .with("temp_directory", "")
                .unwrap(),
        )
        .unwrap();
        let temp_directory: String = conn
            .query_row("SELECT current_setting('temp_directory')", [], |r| r.get(0))
            .unwrap();
        assert_eq!(temp_directory, "");
    }

    #[test]
    fn test_open_bounds_duckdb_resources() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.duckdb");
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch("CREATE TABLE t (x INTEGER); INSERT INTO t VALUES (1);")
                .unwrap();
        }

        let setting = |db: &AnalyzeDb, name: &str| -> String {
            let result = db
                .query(&format!("SELECT current_setting('{name}')"))
                .unwrap();
            match &result.rows[0][0] {
                serde_json::Value::String(s) => s.clone(),
                v => v.to_string(),
            }
        };

        // A spill dir left behind by a dead process (this pid is above the
        // kernel's PID_MAX_LIMIT, so it cannot be alive) is swept on open.
        let stale = std::env::temp_dir().join("systing-analyze-spill-4294967294-0");
        std::fs::create_dir_all(&stale).unwrap();

        for read_only in [true, false] {
            let db = AnalyzeDb::open(&db_path, read_only).unwrap();

            // Spills are redirected away from the database's directory into a
            // per-instance directory under the system temp dir, pre-created
            // owner-only since spill files contain trace contents.
            let temp_directory = setting(&db, "temp_directory");
            assert!(
                temp_directory.contains("systing-analyze-spill-"),
                "unexpected temp_directory: {temp_directory}"
            );
            let mode = std::fs::metadata(&temp_directory).unwrap().permissions();
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(mode.mode() & 0o777, 0o700);

            assert!(!stale.exists(), "stale spill dir not swept");

            // Threads are capped, not one per host CPU.
            let threads: u64 = setting(&db, "threads").parse().unwrap();
            assert!(threads >= 2, "threads clamped below floor: {threads}");
            assert!(threads <= 32 || crate::duckdb::detect_cgroup_memory_limit().is_some());

            // Inside a cgroup the memory limit comes from the cgroup, not
            // from 80% of host RAM. Compare against a reference connection
            // configured with the same value so the test doesn't depend on
            // how DuckDB formats the setting for display.
            if let Some(cgroup_bytes) = crate::duckdb::detect_cgroup_memory_limit() {
                let expected_mib = (cgroup_bytes / 2 / (1024 * 1024)).max(512);
                let reference = Connection::open_in_memory_with_flags(
                    duckdb::Config::default()
                        .max_memory(&format!("{expected_mib}MiB"))
                        .unwrap(),
                )
                .unwrap();
                let expected: String = reference
                    .query_row("SELECT current_setting('memory_limit')", [], |r| r.get(0))
                    .unwrap();
                assert_eq!(setting(&db, "memory_limit"), expected);
            }
        }
    }

    #[test]
    fn test_trace_info_system_info() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.duckdb");

        {
            let conn = Connection::open(&db_path).unwrap();
            crate::duckdb::create_schema(&conn).unwrap();
            conn.execute_batch(
                "INSERT INTO sysinfo (trace_id, sysname, release, version, machine, \
                 cpufreq_driver, hypervisor, sys_vendor, product_name, \
                 sample_event, sample_period, memory_fault_leg, \
                 memory_fault_sample_rate, memory_map_sample_rate, \
                 memory_alloc_sample_rate, memory_vfio_leg, memory_thp_leg, \
                 memory_thp_sample_rate, memory_iommu_overflow, \
                 memory_anon_huge_walk, memory_syscall_leg, network_tw_leg) \
                 VALUES ('t1', 'Linux', '6.12.0', '#1 SMP', 'x86_64', \
                 NULL, 'kvm', 'Amazon EC2', 'm7i.16xlarge', 'cpu-clock', 1000000, \
                 'tracepoint', 97, 1, NULL, 'on', NULL, NULL, 0, NULL, 'fentry', \
                 'kprobe:nobtf')",
            )
            .unwrap();
        }

        let db = AnalyzeDb::open(&db_path, true).unwrap();
        let info = db.trace_info().unwrap();

        assert_eq!(info.system.len(), 1);
        let sys = &info.system[0];
        assert_eq!(sys.trace_id.as_deref(), Some("t1"));
        assert_eq!(sys.kernel_release.as_deref(), Some("6.12.0"));
        assert_eq!(sys.machine.as_deref(), Some("x86_64"));
        assert_eq!(sys.hypervisor.as_deref(), Some("kvm"));
        assert_eq!(sys.sys_vendor.as_deref(), Some("Amazon EC2"));
        assert_eq!(sys.product_name.as_deref(), Some("m7i.16xlarge"));
        assert_eq!(
            sys.cpufreq_driver, None,
            "NULL cpufreq_driver must come back as None"
        );
        assert_eq!(sys.sample_event.as_deref(), Some("cpu-clock"));
        assert_eq!(sys.sample_period, Some(1_000_000));
        assert_eq!(sys.memory_fault_leg.as_deref(), Some("tracepoint"));
        assert_eq!(sys.memory_fault_sample_rate, Some(97));
        assert_eq!(sys.memory_map_sample_rate, Some(1));
        assert_eq!(
            sys.memory_alloc_sample_rate, None,
            "NULL memory_alloc_sample_rate (memory-alloc off) must come back as None"
        );
        assert_eq!(sys.memory_vfio_leg.as_deref(), Some("on"));
        assert_eq!(sys.memory_thp_leg, None);
        assert_eq!(sys.memory_thp_sample_rate, None);
        assert_eq!(
            sys.memory_iommu_overflow,
            Some(0),
            "0 overflow = the histogram is complete"
        );
        assert_eq!(sys.memory_anon_huge_walk, None);
        assert_eq!(sys.memory_syscall_leg.as_deref(), Some("fentry"));
        assert_eq!(sys.network_tw_leg.as_deref(), Some("kprobe:nobtf"));
    }

    #[test]
    fn test_trace_info_system_info_pre_v9_schema() {
        // Databases produced before schema v9 have a sysinfo table without the
        // platform columns; trace_info must still report kernel/machine and
        // read the missing columns as None.
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("old.duckdb");

        {
            let conn = Connection::open(&db_path).unwrap();
            crate::duckdb::create_schema(&conn).unwrap();
            conn.execute_batch(
                "ALTER TABLE sysinfo DROP COLUMN cpufreq_driver; \
                 ALTER TABLE sysinfo DROP COLUMN hypervisor; \
                 ALTER TABLE sysinfo DROP COLUMN sys_vendor; \
                 ALTER TABLE sysinfo DROP COLUMN product_name; \
                 ALTER TABLE sysinfo DROP COLUMN sample_event; \
                 ALTER TABLE sysinfo DROP COLUMN sample_period; \
                 ALTER TABLE sysinfo DROP COLUMN memory_fault_leg; \
                 ALTER TABLE sysinfo DROP COLUMN memory_fault_sample_rate; \
                 ALTER TABLE sysinfo DROP COLUMN memory_map_sample_rate; \
                 ALTER TABLE sysinfo DROP COLUMN memory_alloc_sample_rate; \
                 ALTER TABLE sysinfo DROP COLUMN memory_vfio_leg; \
                 ALTER TABLE sysinfo DROP COLUMN memory_thp_leg; \
                 ALTER TABLE sysinfo DROP COLUMN memory_thp_sample_rate; \
                 ALTER TABLE sysinfo DROP COLUMN memory_syscall_leg; \
                 ALTER TABLE sysinfo DROP COLUMN network_tw_leg; \
                 INSERT INTO sysinfo (trace_id, sysname, release, version, machine) \
                 VALUES ('t1', 'Linux', '5.10.0', '#1 SMP', 'aarch64')",
            )
            .unwrap();
        }

        let db = AnalyzeDb::open(&db_path, true).unwrap();
        let info = db.trace_info().unwrap();

        assert_eq!(info.system.len(), 1);
        let sys = &info.system[0];
        assert_eq!(sys.kernel_release.as_deref(), Some("5.10.0"));
        assert_eq!(sys.machine.as_deref(), Some("aarch64"));
        assert_eq!(sys.hypervisor, None);
        assert_eq!(sys.sys_vendor, None);
        assert_eq!(sys.product_name, None);
        assert_eq!(sys.cpufreq_driver, None);
        assert_eq!(sys.sample_event, None);
        assert_eq!(sys.sample_period, None);
        assert_eq!(sys.memory_fault_leg, None);
        assert_eq!(sys.memory_fault_sample_rate, None);
        assert_eq!(sys.memory_map_sample_rate, None);
        assert_eq!(sys.memory_alloc_sample_rate, None);
        assert_eq!(sys.memory_vfio_leg, None);
        assert_eq!(sys.memory_thp_leg, None);
        assert_eq!(sys.memory_thp_sample_rate, None);
        assert_eq!(sys.memory_syscall_leg, None);
        assert_eq!(sys.network_tw_leg, None);
    }

    #[test]
    fn test_trace_info_system_info_no_sysinfo_table() {
        // A database without a sysinfo table at all must yield an empty
        // system list, not an error.
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("bare.duckdb");

        {
            let conn = Connection::open(&db_path).unwrap();
            crate::duckdb::create_schema(&conn).unwrap();
            conn.execute_batch("DROP TABLE sysinfo").unwrap();
        }

        let db = AnalyzeDb::open(&db_path, true).unwrap();
        let info = db.trace_info().unwrap();
        assert!(info.system.is_empty());
    }

    /// A small database for the query-bound tests: one table, 25,000 rows.
    fn open_query_test_db(dir: &Path) -> AnalyzeDb {
        let db_path = dir.join("query.duckdb");
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE t AS SELECT range AS id, range % 7 AS bucket FROM range(25000)",
            )
            .unwrap();
        }
        AnalyzeDb::open(&db_path, true).unwrap()
    }

    #[test]
    fn test_query_caps_rows_and_counts_total() {
        let dir = tempfile::tempdir().unwrap();
        let db = open_query_test_db(dir.path());

        let result = db.query("SELECT id FROM t ORDER BY id").unwrap();
        assert_eq!(result.row_count, MAX_QUERY_ROWS);
        assert_eq!(result.rows.len(), MAX_QUERY_ROWS);
        assert!(result.truncated);
        assert_eq!(result.total_row_count, Some(25000));
        // The kept rows are the first MAX_QUERY_ROWS in the query's own order.
        assert_eq!(result.rows[0][0], serde_json::json!(0));
        assert_eq!(
            result.rows[MAX_QUERY_ROWS - 1][0],
            serde_json::json!(MAX_QUERY_ROWS - 1)
        );
    }

    #[test]
    fn test_query_below_cap_is_not_truncated() {
        let dir = tempfile::tempdir().unwrap();
        let db = open_query_test_db(dir.path());

        let result = db.query("SELECT id FROM t WHERE id < 5").unwrap();
        assert_eq!(result.row_count, 5);
        assert!(!result.truncated);
        assert_eq!(result.total_row_count, None);

        // Exactly at the cap is not truncated either.
        let result = db
            .query(&format!("SELECT id FROM t WHERE id < {MAX_QUERY_ROWS}"))
            .unwrap();
        assert_eq!(result.row_count, MAX_QUERY_ROWS);
        assert!(!result.truncated);
        assert_eq!(result.total_row_count, None);
    }

    #[test]
    fn test_query_wraps_common_select_shapes() {
        let dir = tempfile::tempdir().unwrap();
        let db = open_query_test_db(dir.path());

        // Trailing terminator and whitespace.
        let result = db.query("SELECT count(*) AS n FROM t;  \n").unwrap();
        assert_eq!(result.columns, vec!["n"]);
        assert_eq!(result.rows[0][0], serde_json::json!(25000));

        // Trailing line comment must not swallow the wrapper's closing paren.
        let result = db.query("SELECT bucket FROM t -- all of them").unwrap();
        assert!(result.truncated);
        assert_eq!(result.total_row_count, Some(25000));

        // A CTE embeds as a subquery.
        let result = db
            .query("WITH b AS (SELECT bucket, count(*) AS n FROM t GROUP BY bucket) SELECT * FROM b ORDER BY bucket")
            .unwrap();
        assert_eq!(result.row_count, 7);
        assert_eq!(result.columns, vec!["bucket", "n"]);

        // Column names survive the wrapper, duplicates included.
        let result = db
            .query("SELECT id, id, bucket AS id FROM t WHERE id < 3")
            .unwrap();
        assert_eq!(result.row_count, 3);
        assert_eq!(result.columns.len(), 3);
        assert_eq!(
            result.rows[2],
            vec![
                serde_json::json!(2),
                serde_json::json!(2),
                serde_json::json!(2)
            ]
        );
    }

    #[test]
    fn test_query_falls_back_for_non_select_statements() {
        let dir = tempfile::tempdir().unwrap();
        let db = open_query_test_db(dir.path());

        // Statements that cannot be embedded as a subquery still run.
        let result = db.query("PRAGMA table_info('t')").unwrap();
        assert_eq!(result.row_count, 2);
        let result = db.query("SHOW TABLES").unwrap();
        assert_eq!(result.row_count, 1);
        assert_eq!(result.rows[0][0], serde_json::json!("t"));

        // A SQL error is reported against the user's own statement, with the
        // engine's text intact (it names the missing column).
        let err = db.query("SELECT nope FROM t").unwrap_err().to_string();
        assert!(err.contains("nope"), "unexpected error: {err}");
        assert!(!err.contains("__systing_query"), "wrapper leaked: {err}");
    }

    #[test]
    fn test_query_out_of_memory_is_reported_as_the_bound() {
        let dir = tempfile::tempdir().unwrap();
        let db = open_query_test_db(dir.path());

        // The classifier alone, on DuckDB's message shapes for both the
        // buffer-pool limit and a full spill directory.
        for text in [
            "Out of Memory Error: failed to allocate data of size 256.0 KiB (3.9 GiB/4.0 GiB used)",
            "Out of Memory Error: failed to offload data block of size 256.0 KiB (1.0 MiB/1.0 MiB used)",
        ] {
            let err = duckdb::Error::DuckDBFailure(
                duckdb::ffi::Error::new(1),
                Some(text.to_string()),
            );
            let msg = db.classify_query_error(err).to_string();
            assert!(
                msg.starts_with("query exceeded the DuckDB memory bound"),
                "unexpected: {msg}"
            );
            assert!(!msg.contains("failed to"), "engine text leaked: {msg}");
        }
        let other = duckdb::Error::DuckDBFailure(
            duckdb::ffi::Error::new(1),
            Some("Binder Error: Referenced column \"nope\" not found".to_string()),
        );
        assert!(db.classify_query_error(other).to_string().contains("nope"));
        // A user's own string literal containing the marker is not an OOM.
        let literal = duckdb::Error::DuckDBFailure(
            duckdb::ffi::Error::new(1),
            Some("Binder Error: column \"Out of Memory Error\" not found".to_string()),
        );
        assert!(db
            .classify_query_error(literal)
            .to_string()
            .starts_with("Binder Error"));

        // End to end: a sort that cannot fit in a tiny memory limit with a
        // tiny spill cap is refused by DuckDB's out-of-memory class, and the
        // tool sees the fixed message, not the allocation text. Both settings
        // are session-level and stay adjustable with external access off.
        db.conn
            .execute_batch("SET memory_limit = '1MB'; SET max_temp_directory_size = '1MB'")
            .unwrap();
        let err = db
            .query("SELECT * FROM (SELECT range AS v FROM range(20000000)) ORDER BY hash(v)")
            .unwrap_err()
            .to_string();
        assert!(
            err.starts_with("query exceeded the DuckDB memory bound"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_query_comments_and_terminators_cannot_bypass_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        let db = open_query_test_db(dir.path());

        // Each of these used to fail the wrapped prepare on the internal `;`
        // and fall back to an unbounded raw run.
        for sql in [
            "SELECT bucket FROM t; -- all of them",
            "SELECT bucket FROM t;\n-- note",
            "SELECT bucket FROM t; /* x */",
            ";SELECT bucket FROM t",
            "/* leading */ SELECT bucket FROM t /* trailing */ ;",
        ] {
            let result = db.query(sql).unwrap();
            assert_eq!(result.row_count, MAX_QUERY_ROWS, "{sql:?}");
            assert!(result.truncated, "{sql:?} was not capped");
            assert_eq!(result.total_row_count, Some(25000), "{sql:?}");
        }

        // A comment-looking sequence inside a string literal is data.
        let result = db
            .query("SELECT '-- not a comment; still one statement' AS s, id FROM t")
            .unwrap();
        assert!(result.truncated);
        assert_eq!(
            result.rows[0][0],
            serde_json::json!("-- not a comment; still one statement")
        );

        // More than one statement is refused outright, whatever the second
        // one is — it never runs.
        for sql in [
            "SELECT 1; SELECT 2",
            "SELECT id FROM t; SET memory_limit = '100GB'",
            "SELECT id FROM t LIMIT 1; PRAGMA max_temp_directory_size = '100GB'",
        ] {
            let err = db.query(sql).unwrap_err().to_string();
            assert!(err.contains("one statement"), "{sql:?}: {err}");
        }
        let err = db.query("  -- nothing here\n;").unwrap_err().to_string();
        assert!(err.contains("empty query"), "{err}");

        // A dollar-quoted string holding a quote character used to make the
        // classifier believe the rest of the text was a literal, and the
        // binding's `prepare` then EXECUTED the hidden statements (it runs
        // every statement but the last). Both shapes are refused before
        // anything reaches `prepare`, and the hidden SET never ran.
        let before = db.query("SELECT current_setting('memory_limit')").unwrap();
        for sql in [
            "SELECT $$'$$; SET memory_limit='100GB'; SELECT $$'$$",
            "SELECT $$'$$) AS x; SET memory_limit='100GB'; SELECT * FROM (SELECT $$'$$",
            "SELECT $$a--b$$",
        ] {
            let err = db.query(sql).unwrap_err().to_string();
            assert!(err.contains("dollar-quoted"), "{sql:?}: {err}");
        }
        let after = db.query("SELECT current_setting('memory_limit')").unwrap();
        assert_eq!(before.rows, after.rows);

        // A PIVOT with no IN (...) list is parser-expanded by DuckDB into a
        // `CREATE TYPE __pivot_enum_<uuid> AS ENUM (SELECT DISTINCT ...)`
        // ahead of the SELECT, and the binding's `prepare` executed that
        // scan at prepare time — outside the row cap, twice on the failure
        // path, and leaving the type in the temp catalog on success. The
        // shape is refused before it reaches `prepare`, so no such type is
        // ever created; the same pivot with its values named runs wrapped
        // (one row per id here, so the cap and the count are exercised).
        // Only the pivot's own ON clause counts: the bypass probe, a
        // pivot whose only `IN (` sits in its source subquery, is refused
        // too (DuckDB still expands it; it left a type behind before).
        for sql in [
            "PIVOT t ON bucket USING count(id)",
            "pivot_wider t on bucket using count(id) group by id",
            "PIVOT t ON bucket USING count(id) -- IN (0, 1)",
            "PIVOT (SELECT * FROM t WHERE id IN (3, 4, 5)) ON bucket USING count(id)",
            "PIVOT t ON bucket IN (0, 1), id USING count(*)",
        ] {
            let err = db.query(sql).unwrap_err().to_string();
            assert!(err.contains("PIVOT without an IN"), "{sql:?}: {err}");
        }
        let enums = db
            .query("SELECT count(*) FROM duckdb_types() WHERE type_name LIKE '__pivot_enum%'")
            .unwrap();
        assert_eq!(enums.rows[0][0], serde_json::json!(0));
        let pivoted = db
            .query("PIVOT t ON bucket IN (0, 1) USING count(id) GROUP BY id")
            .unwrap();
        assert_eq!(pivoted.row_count, MAX_QUERY_ROWS);
        assert!(pivoted.truncated);
        assert_eq!(pivoted.total_row_count, Some(25000));
        let pivoted = db
            .query(
                "PIVOT (SELECT * FROM t WHERE id IN (3, 4, 5)) ON bucket IN (3, 4, 5) USING count(id) GROUP BY id",
            )
            .unwrap();
        assert_eq!(pivoted.row_count, 3);
        assert!(!pivoted.truncated);
        let enums = db
            .query("SELECT count(*) FROM duckdb_types() WHERE type_name LIKE '__pivot_enum%'")
            .unwrap();
        assert_eq!(enums.rows[0][0], serde_json::json!(0));
    }

    #[test]
    fn test_query_reports_a_prepare_time_memory_failure_as_the_bound() {
        // `is_memory_bound_error` is what keeps a prepare that hit the bound
        // from being retried unwrapped and from surfacing the engine's
        // allocation text (which names the setting the lock refuses).
        let oom = || {
            duckdb::Error::DuckDBFailure(
                duckdb::ffi::Error::new(1),
                Some(format!("{DUCKDB_OOM_MARKER}: could not allocate block")),
            )
        };
        let other = || {
            duckdb::Error::DuckDBFailure(
                duckdb::ffi::Error::new(1),
                Some("Binder Error: column nope not found".to_string()),
            )
        };
        assert!(is_memory_bound_error(&oom()));
        assert!(!is_memory_bound_error(&other()));

        // The decision itself, driven with a statement whose raw form would
        // prepare and run fine: after a memory-bound failure of the wrapped
        // prepare the raw form is NOT prepared (no rows come back, the
        // error is the bound's fixed text, not the engine's); after any
        // other failure it is, and a non-row-reading statement runs raw.
        let dir = tempfile::tempdir().unwrap();
        let db = open_query_test_db(dir.path());
        let err = db
            .query_after_wrapped_prepare_failed(oom(), "SELECT 1 AS one", false)
            .unwrap_err()
            .to_string();
        assert!(
            err.starts_with("query exceeded the DuckDB memory bound"),
            "unexpected: {err}"
        );
        assert!(!err.contains("allocate"), "engine text leaked: {err}");
        let err = db
            .query_after_wrapped_prepare_failed(oom(), "SELECT 1 AS one", true)
            .unwrap_err()
            .to_string();
        assert!(err.starts_with("query exceeded the DuckDB memory bound"));
        let raw = db
            .query_after_wrapped_prepare_failed(other(), "SELECT 1 AS one", false)
            .unwrap();
        assert_eq!(raw.rows, vec![vec![serde_json::json!(1)]]);
        let err = db
            .query_after_wrapped_prepare_failed(other(), "SELECT 1 AS one", true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("could not be bounded"), "{err}");
    }

    #[test]
    fn test_query_refuses_row_readers_it_cannot_wrap() {
        let dir = tempfile::tempdir().unwrap();
        let db = open_query_test_db(dir.path());

        // `CALL` and `EXECUTE` run whatever they name, so they may not take
        // the raw path; neither can be a subquery, so both are refused with
        // the fixed message — never run unbounded.
        db.conn
            .execute_batch("PREPARE q AS SELECT id FROM t")
            .unwrap();
        for sql in ["EXECUTE q", "CALL pragma_table_info('t')"] {
            let err = db.query(sql).unwrap_err().to_string();
            assert!(err.contains("could not be bounded"), "{sql:?}: {err}");
        }
        // The same rows are reachable through a bounded SELECT.
        assert_eq!(
            db.query("SELECT * FROM pragma_table_info('t')")
                .unwrap()
                .row_count,
            2
        );
    }

    #[test]
    fn test_query_cap_boundaries_and_order() {
        let dir = tempfile::tempdir().unwrap();
        let db = open_query_test_db(dir.path());

        // Descending order is kept through the wrapper: the first cap-many
        // rows of the query's own order come back.
        let result = db.query("SELECT id FROM t ORDER BY id DESC").unwrap();
        assert!(result.truncated);
        assert_eq!(result.rows[0][0], serde_json::json!(24999));
        assert_eq!(
            result.rows[MAX_QUERY_ROWS - 1][0],
            serde_json::json!(25000 - MAX_QUERY_ROWS)
        );

        // Exactly cap + 1 rows is the smallest truncated result.
        let result = db
            .query(&format!("SELECT id FROM t WHERE id <= {MAX_QUERY_ROWS}"))
            .unwrap();
        assert_eq!(result.row_count, MAX_QUERY_ROWS);
        assert!(result.truncated);
        assert_eq!(result.total_row_count, Some(MAX_QUERY_ROWS + 1));
    }

    #[test]
    fn test_query_result_json_shape() {
        let not_truncated = QueryResult {
            columns: vec!["a".into()],
            rows: vec![vec![serde_json::json!(1)]],
            row_count: 1,
            truncated: false,
            total_row_count: None,
        };
        assert_eq!(
            serde_json::to_value(&not_truncated).unwrap(),
            serde_json::json!({"columns": ["a"], "rows": [[1]], "row_count": 1})
        );
        let uncounted = QueryResult {
            columns: vec!["a".into()],
            rows: vec![],
            row_count: 0,
            truncated: true,
            total_row_count: None,
        };
        assert_eq!(
            serde_json::to_value(&uncounted).unwrap(),
            serde_json::json!({"columns": ["a"], "rows": [], "row_count": 0, "truncated": true, "total_row_count": null})
        );
    }

    #[test]
    fn test_lock_configuration_refuses_settings() {
        let dir = tempfile::tempdir().unwrap();
        let db = open_query_test_db(dir.path());
        let before = db.query("SELECT current_setting('memory_limit')").unwrap();
        db.lock_configuration().unwrap();

        // Every spelling of "raise the bound" is refused with DuckDB's
        // locked-configuration class, and none changes the setting.
        for sql in [
            "SET memory_limit = '100GB'",
            "SET max_memory = '100GB'",
            "SET threads = 1",
            "SET max_temp_directory_size = '100GB'",
            "PRAGMA max_temp_directory_size = '100GB'",
            "PRAGMA memory_limit = '100GB'",
            "RESET memory_limit",
            "SET GLOBAL memory_limit = '100GB'",
            "SET lock_configuration = false",
        ] {
            let err = db.query(sql).unwrap_err().to_string();
            assert!(err.contains("locked"), "{sql:?}: {err}");
        }
        let after = db.query("SELECT current_setting('memory_limit')").unwrap();
        assert_eq!(before.rows, after.rows);

        // Reads are unaffected, including the statements that take the raw
        // path.
        assert_eq!(
            db.query("SELECT count(*) FROM t").unwrap().rows[0][0],
            serde_json::json!(25000)
        );
        assert_eq!(db.query("PRAGMA table_info('t')").unwrap().row_count, 2);
        assert_eq!(db.query("SHOW TABLES").unwrap().row_count, 1);
        assert!(db.query("SELECT id FROM t").unwrap().truncated);
    }
}
