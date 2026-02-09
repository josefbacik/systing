//! MCP (Model Context Protocol) server for systing-analyze.
//!
//! Provides an MCP server that exposes trace database analysis tools to AI
//! assistants. Uses a dedicated DB thread to handle DuckDB's non-Send connection.

use crate::analyze::{
    AnalyzeDb, CpuStatsParams, FlamegraphParams, NetworkConnectionsParams, NetworkInterfacesParams,
    NetworkSocketPairsParams, SchedStatsParams, StackTypeFilter,
};
use anyhow::Result;
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::*,
    schemars, tool, tool_handler, tool_router,
    transport::stdio,
    ErrorData as McpError, ServerHandler, ServiceExt,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

// -- Database thread communication --

enum DbRequest {
    Query(Option<PathBuf>, String),
    ListTables(Option<PathBuf>),
    DescribeTable(Option<PathBuf>, String),
    Flamegraph(Option<PathBuf>, FlamegraphParams),
    SchedStats(Option<PathBuf>, SchedStatsParams),
    CpuStats(Option<PathBuf>, CpuStatsParams),
    TraceInfo(Option<PathBuf>),
    NetworkConnections(Option<PathBuf>, NetworkConnectionsParams),
    NetworkInterfaces(Option<PathBuf>, NetworkInterfacesParams),
    NetworkSocketPairs(Option<PathBuf>, NetworkSocketPairsParams),
}

type DbResponse = std::result::Result<serde_json::Value, String>;

/// Async handle to the database thread. Sends requests via channel and receives
/// results via oneshot.
struct DbHandle {
    sender: mpsc::Sender<(DbRequest, oneshot::Sender<DbResponse>)>,
}

impl DbHandle {
    /// Spawn the database thread, optionally opening an initial database.
    fn new(initial_db: Option<PathBuf>) -> Result<Self> {
        let (sender, mut receiver) = mpsc::channel::<(DbRequest, oneshot::Sender<DbResponse>)>(32);

        std::thread::spawn(move || {
            let mut dbs: HashMap<PathBuf, AnalyzeDb> = HashMap::new();
            let mut last_used: Option<PathBuf> = None;

            if let Some(path) = initial_db {
                match std::fs::canonicalize(&path) {
                    Ok(canonical) => match AnalyzeDb::open(&canonical, true) {
                        Ok(db) => {
                            dbs.insert(canonical.clone(), db);
                            last_used = Some(canonical);
                        }
                        Err(e) => eprintln!("Warning: failed to open initial database: {e}"),
                    },
                    Err(e) => eprintln!("Warning: cannot resolve path '{}': {e}", path.display()),
                }
            }

            while let Some((request, reply)) = receiver.blocking_recv() {
                let result = handle_db_request(&mut dbs, &mut last_used, request);
                let _ = reply.send(result);
            }
        });

        Ok(Self { sender })
    }

    /// Send a request to the DB thread and wait for the response.
    async fn request(&self, req: DbRequest) -> DbResponse {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.sender
            .send((req, reply_tx))
            .await
            .map_err(|_| "Database thread has shut down".to_string())?;
        reply_rx
            .await
            .map_err(|_| "Database thread did not respond".to_string())?
    }
}

const MAX_CACHED_DBS: usize = 8;

fn get_or_open<'a>(
    dbs: &'a mut HashMap<PathBuf, AnalyzeDb>,
    last_used: &mut Option<PathBuf>,
    path: Option<PathBuf>,
) -> Result<&'a AnalyzeDb, String> {
    let raw_path = match path {
        Some(p) => p,
        None => last_used.clone().ok_or_else(|| {
            "No database path provided and no database has been used yet. \
             Pass a 'path' parameter."
                .to_string()
        })?,
    };

    let canonical = std::fs::canonicalize(&raw_path)
        .map_err(|e| format!("Cannot resolve path '{}': {e}", raw_path.display()))?;

    if !dbs.contains_key(&canonical) {
        if dbs.len() >= MAX_CACHED_DBS {
            // Keep the last-used database, evict the rest.
            let kept = last_used.as_ref().and_then(|k| {
                let db = dbs.remove(k)?;
                Some((k.clone(), db))
            });
            dbs.clear();
            if let Some((k, db)) = kept {
                dbs.insert(k, db);
            }
        }
        let db = AnalyzeDb::open(&canonical, true)
            .map_err(|e| format!("Failed to open database '{}': {e}", canonical.display()))?;
        dbs.insert(canonical.clone(), db);
    }

    let db_ref = dbs.get(&canonical).unwrap();
    *last_used = Some(canonical);
    Ok(db_ref)
}

/// Process a single database request on the DB thread.
fn handle_db_request(
    dbs: &mut HashMap<PathBuf, AnalyzeDb>,
    last_used: &mut Option<PathBuf>,
    request: DbRequest,
) -> DbResponse {
    match request {
        DbRequest::Query(path, sql) => {
            let db = get_or_open(dbs, last_used, path)?;
            db.query(&sql)
                .and_then(|r| {
                    serde_json::to_value(r).map_err(|e| anyhow::anyhow!("Serialization error: {e}"))
                })
                .map_err(|e| format!("Query error: {e}"))
        }
        DbRequest::ListTables(path) => {
            let db = get_or_open(dbs, last_used, path)?;
            db.list_tables()
                .and_then(|r| {
                    serde_json::to_value(r).map_err(|e| anyhow::anyhow!("Serialization error: {e}"))
                })
                .map_err(|e| format!("Error listing tables: {e}"))
        }
        DbRequest::DescribeTable(path, name) => {
            let db = get_or_open(dbs, last_used, path)?;
            db.describe_table(&name)
                .and_then(|r| {
                    serde_json::to_value(r).map_err(|e| anyhow::anyhow!("Serialization error: {e}"))
                })
                .map_err(|e| format!("Error describing table: {e}"))
        }
        DbRequest::Flamegraph(path, params) => {
            let db = get_or_open(dbs, last_used, path)?;
            db.flamegraph(&params)
                .and_then(|r| {
                    serde_json::to_value(r).map_err(|e| anyhow::anyhow!("Serialization error: {e}"))
                })
                .map_err(|e| format!("Flamegraph error: {e}"))
        }
        DbRequest::SchedStats(path, params) => {
            let db = get_or_open(dbs, last_used, path)?;
            db.sched_stats(&params)
                .and_then(|r| {
                    serde_json::to_value(r).map_err(|e| anyhow::anyhow!("Serialization error: {e}"))
                })
                .map_err(|e| format!("Sched stats error: {e}"))
        }
        DbRequest::CpuStats(path, params) => {
            let db = get_or_open(dbs, last_used, path)?;
            db.cpu_stats(&params)
                .and_then(|r| {
                    serde_json::to_value(r).map_err(|e| anyhow::anyhow!("Serialization error: {e}"))
                })
                .map_err(|e| format!("CPU stats error: {e}"))
        }
        DbRequest::TraceInfo(path) => {
            let db = get_or_open(dbs, last_used, path)?;
            db.trace_info()
                .and_then(|r| {
                    serde_json::to_value(r).map_err(|e| anyhow::anyhow!("Serialization error: {e}"))
                })
                .map_err(|e| format!("Error getting trace info: {e}"))
        }
        DbRequest::NetworkConnections(path, params) => {
            let db = get_or_open(dbs, last_used, path)?;
            db.network_connections(&params)
                .and_then(|r| {
                    serde_json::to_value(r).map_err(|e| anyhow::anyhow!("Serialization error: {e}"))
                })
                .map_err(|e| format!("Network connections error: {e}"))
        }
        DbRequest::NetworkInterfaces(path, params) => {
            let db = get_or_open(dbs, last_used, path)?;
            db.network_interfaces(&params)
                .and_then(|r| {
                    serde_json::to_value(r).map_err(|e| anyhow::anyhow!("Serialization error: {e}"))
                })
                .map_err(|e| format!("Network interfaces error: {e}"))
        }
        DbRequest::NetworkSocketPairs(path, params) => {
            let db = get_or_open(dbs, last_used, path)?;
            db.network_socket_pairs(&params)
                .and_then(|r| {
                    serde_json::to_value(r).map_err(|e| anyhow::anyhow!("Serialization error: {e}"))
                })
                .map_err(|e| format!("Network socket pairs error: {e}"))
        }
    }
}

// -- Serde helpers: accept both JSON numbers and stringified numbers --
// MCP clients (including Claude Code) often send numeric parameters as strings.

mod string_or_number {
    use serde::{self, Deserialize, Deserializer};
    use std::fmt;
    use std::marker::PhantomData;
    use std::str::FromStr;

    struct StringOrNumberVisitor<T>(PhantomData<T>);

    impl<'de, T> serde::de::Visitor<'de> for StringOrNumberVisitor<T>
    where
        T: FromStr + Deserialize<'de>,
        T::Err: fmt::Display,
    {
        type Value = T;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a number or a string containing a number")
        }

        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<T, E> {
            v.parse::<T>().map_err(serde::de::Error::custom)
        }

        fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<T, E> {
            T::deserialize(serde::de::value::U64Deserializer::new(v))
        }

        fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<T, E> {
            T::deserialize(serde::de::value::I64Deserializer::new(v))
        }

        fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<T, E> {
            T::deserialize(serde::de::value::F64Deserializer::new(v))
        }
    }

    fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
    where
        T: FromStr + Deserialize<'de>,
        T::Err: fmt::Display,
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StringOrNumberVisitor(PhantomData))
    }

    pub mod option {
        use super::*;

        pub fn deserialize<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
        where
            T: FromStr + Deserialize<'de>,
            T::Err: fmt::Display,
            D: Deserializer<'de>,
        {
            deserializer.deserialize_option(OptionVisitor(PhantomData))
        }

        struct OptionVisitor<T>(PhantomData<T>);

        impl<'de, T> serde::de::Visitor<'de> for OptionVisitor<T>
        where
            T: FromStr + Deserialize<'de>,
            T::Err: fmt::Display,
        {
            type Value = Option<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("null, a number, or a string containing a number")
            }

            fn visit_none<E: serde::de::Error>(self) -> Result<Option<T>, E> {
                Ok(None)
            }

            fn visit_unit<E: serde::de::Error>(self) -> Result<Option<T>, E> {
                Ok(None)
            }

            fn visit_some<D2: Deserializer<'de>>(
                self,
                deserializer: D2,
            ) -> Result<Option<T>, D2::Error> {
                super::deserialize(deserializer).map(Some)
            }
        }
    }
}

// -- Tool parameter types --

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct DatabasePathParams {
    /// Absolute path to a .duckdb trace database file. If omitted, uses the most recently accessed database.
    path: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct QueryParams {
    /// Absolute path to a .duckdb trace database file. If omitted, uses the most recently accessed database.
    path: Option<String>,

    /// SQL query to execute. The database is opened read-only, so DML/DDL will fail.
    sql: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct DescribeTableParams {
    /// Absolute path to a .duckdb trace database file. If omitted, uses the most recently accessed database.
    path: Option<String>,

    /// Name of the table to describe.
    table_name: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct FlamegraphToolParams {
    /// Absolute path to a .duckdb trace database file. If omitted, uses the most recently accessed database.
    path: Option<String>,

    /// Stack type filter: "cpu", "interruptible-sleep", "uninterruptible-sleep",
    /// "all-sleep", or "all". Defaults to "cpu".
    stack_type: Option<String>,

    /// Filter to a specific process ID.
    // `default` handles missing fields (=> None); `deserialize_with` handles
    // present fields that may be strings or numbers.
    #[serde(default, deserialize_with = "string_or_number::option::deserialize")]
    pid: Option<u32>,

    /// Filter to a specific thread ID.
    #[serde(default, deserialize_with = "string_or_number::option::deserialize")]
    tid: Option<u32>,

    /// Start time offset in seconds from trace start.
    #[serde(default, deserialize_with = "string_or_number::option::deserialize")]
    start_time: Option<f64>,

    /// End time offset in seconds from trace start.
    #[serde(default, deserialize_with = "string_or_number::option::deserialize")]
    end_time: Option<f64>,

    /// Filter to a specific trace ID (for multi-trace databases).
    trace_id: Option<String>,

    /// Minimum sample count to include a stack. Default: 1.
    #[serde(default, deserialize_with = "string_or_number::option::deserialize")]
    min_count: Option<u64>,

    /// Limit to top N stacks by sample count. Default: 500.
    #[serde(default, deserialize_with = "string_or_number::option::deserialize")]
    top_n: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SchedStatsToolParams {
    /// Absolute path to a .duckdb trace database file. If omitted, uses the most recently accessed database.
    path: Option<String>,

    /// Filter to a specific process ID.
    #[serde(default, deserialize_with = "string_or_number::option::deserialize")]
    pid: Option<u32>,

    /// Filter to a specific thread ID (mutually exclusive with pid).
    #[serde(default, deserialize_with = "string_or_number::option::deserialize")]
    tid: Option<u32>,

    /// Filter to a specific trace ID (for multi-trace databases).
    trace_id: Option<String>,

    /// Max processes/threads to return. Default: 20.
    #[serde(default, deserialize_with = "string_or_number::option::deserialize")]
    top_n: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct CpuStatsToolParams {
    /// Absolute path to a .duckdb trace database file. If omitted, uses the most recently accessed database.
    path: Option<String>,

    /// Filter to a specific trace ID (for multi-trace databases).
    trace_id: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct NetworkConnectionsToolParams {
    /// Absolute path to a .duckdb trace database file. If omitted, uses the most recently accessed database.
    path: Option<String>,

    /// Filter to a specific trace ID (for multi-trace databases).
    trace_id: Option<String>,

    /// Filter to a specific process ID.
    #[serde(default, deserialize_with = "string_or_number::option::deserialize")]
    pid: Option<u32>,

    /// Filter to a specific thread ID (mutually exclusive with pid).
    #[serde(default, deserialize_with = "string_or_number::option::deserialize")]
    tid: Option<u32>,

    /// Max connections per trace to return. Default: 50. Null for no limit.
    #[serde(default, deserialize_with = "string_or_number::option::deserialize")]
    top_n: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct NetworkInterfacesToolParams {
    /// Absolute path to a .duckdb trace database file. If omitted, uses the most recently accessed database.
    path: Option<String>,

    /// Filter to a specific trace ID (for multi-trace databases).
    trace_id: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct NetworkSocketPairsToolParams {
    /// Absolute path to a .duckdb trace database file. If omitted, uses the most recently accessed database.
    path: Option<String>,

    /// Filter to a specific trace ID. Shows pairs where at least one side is in this trace.
    trace_id: Option<String>,

    /// Filter to connections involving this service port (either side's dest_port).
    #[serde(default, deserialize_with = "string_or_number::option::deserialize")]
    dest_port: Option<i32>,

    /// Filter to connections involving this IP address (matches src or dest on either side).
    ip: Option<String>,

    /// Max pairs to return. Default: 50. Null for no limit.
    #[serde(default, deserialize_with = "string_or_number::option::deserialize")]
    top_n: Option<usize>,

    /// Exclude loopback pairs (127.x, ::1, ::ffff:127.x). Default: false.
    exclude_loopback: Option<bool>,
}

// -- Helper functions --

fn make_tool_result(value: serde_json::Value) -> CallToolResult {
    CallToolResult::success(vec![Content::text(
        serde_json::to_string_pretty(&value).unwrap_or_default(),
    )])
}

fn make_error_result(msg: &str) -> CallToolResult {
    let mut result = CallToolResult::success(vec![Content::text(msg.to_string())]);
    result.is_error = Some(true);
    result
}

// -- MCP Server --

#[derive(Clone)]
struct SystingMcpServer {
    db: Arc<DbHandle>,
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl SystingMcpServer {
    fn new(db: DbHandle) -> Self {
        Self {
            db: Arc::new(db),
            tool_router: Self::tool_router(),
        }
    }

    #[tool(
        name = "query",
        description = "Execute a read-only SQL query against a trace database. Returns JSON with 'columns' (array of column names), 'rows' (array of arrays with properly typed values — numbers as numbers, not strings), and 'row_count'. Results are capped at 10,000 rows; if truncated, includes 'truncated: true' and 'total_row_count'. Use SQL LIMIT/OFFSET for pagination. The database is read-only, so INSERT/UPDATE/DELETE will fail."
    )]
    async fn query(
        &self,
        Parameters(params): Parameters<QueryParams>,
    ) -> std::result::Result<CallToolResult, McpError> {
        let path = params.path.map(PathBuf::from);
        match self.db.request(DbRequest::Query(path, params.sql)).await {
            Ok(value) => Ok(make_tool_result(value)),
            Err(e) => Ok(make_error_result(&e)),
        }
    }

    #[tool(
        name = "list_tables",
        description = "List all tables in the database with their row counts."
    )]
    async fn list_tables(
        &self,
        Parameters(params): Parameters<DatabasePathParams>,
    ) -> std::result::Result<CallToolResult, McpError> {
        let path = params.path.map(PathBuf::from);
        match self.db.request(DbRequest::ListTables(path)).await {
            Ok(value) => Ok(make_tool_result(value)),
            Err(e) => Ok(make_error_result(&e)),
        }
    }

    #[tool(
        name = "describe_table",
        description = "Get column names and types for a specific table in the database."
    )]
    async fn describe_table(
        &self,
        Parameters(params): Parameters<DescribeTableParams>,
    ) -> std::result::Result<CallToolResult, McpError> {
        let path = params.path.map(PathBuf::from);
        match self
            .db
            .request(DbRequest::DescribeTable(path, params.table_name))
            .await
        {
            Ok(value) => Ok(make_tool_result(value)),
            Err(e) => Ok(make_error_result(&e)),
        }
    }

    #[tool(
        name = "flamegraph",
        description = "Query stack traces and return structured results for flame graph analysis. Returns 'stacks' (array of {frames, count}), 'metadata' (total_samples, unique_stacks, time_range, stack_type), and 'folded' (folded-stack text compatible with flamegraph tools like inferno or brendangregg/FlameGraph)."
    )]
    async fn flamegraph(
        &self,
        Parameters(params): Parameters<FlamegraphToolParams>,
    ) -> std::result::Result<CallToolResult, McpError> {
        let path = params.path.map(PathBuf::from);
        let stack_type_str = params.stack_type.as_deref().unwrap_or("cpu");
        let stack_type = match stack_type_str.parse::<StackTypeFilter>() {
            Ok(st) => st,
            Err(e) => return Ok(make_error_result(&e.to_string())),
        };

        let fg_params = FlamegraphParams {
            stack_type,
            pid: params.pid,
            tid: params.tid,
            start_time: params.start_time,
            end_time: params.end_time,
            trace_id: params.trace_id,
            min_count: params.min_count.unwrap_or(1),
            top_n: params.top_n.unwrap_or(500),
        };

        match self
            .db
            .request(DbRequest::Flamegraph(path, fg_params))
            .await
        {
            Ok(value) => Ok(make_tool_result(value)),
            Err(e) => Ok(make_error_result(&e)),
        }
    }

    #[tool(
        name = "trace_info",
        description = "Get metadata about a trace database: database path, trace IDs, time range (in nanoseconds and seconds), non-empty tables with row counts, total process count, and the top 25 processes by thread count. Use the query tool to explore the full process list if needed."
    )]
    async fn trace_info(
        &self,
        Parameters(params): Parameters<DatabasePathParams>,
    ) -> std::result::Result<CallToolResult, McpError> {
        let path = params.path.map(PathBuf::from);
        match self.db.request(DbRequest::TraceInfo(path)).await {
            Ok(value) => Ok(make_tool_result(value)),
            Err(e) => Ok(make_error_result(&e)),
        }
    }

    #[tool(
        name = "sched_stats",
        description = "Scheduling timing statistics. Shows CPU time, event counts, slice durations, preemption rates, and CPU migrations. d_sleep_seconds is approximate: it includes both actual uninterruptible sleep and subsequent runqueue latency. Three modes: no filter = whole-trace with per-process ranking, pid = process detail with per-thread breakdown, tid = single thread detail with end-state distribution."
    )]
    async fn sched_stats(
        &self,
        Parameters(params): Parameters<SchedStatsToolParams>,
    ) -> std::result::Result<CallToolResult, McpError> {
        let path = params.path.map(PathBuf::from);
        if params.pid.is_some() && params.tid.is_some() {
            return Ok(make_error_result(
                "pid and tid are mutually exclusive. Provide one or neither.",
            ));
        }

        let sched_params = SchedStatsParams {
            pid: params.pid,
            tid: params.tid,
            trace_id: params.trace_id,
            top_n: params.top_n.unwrap_or(20),
        };

        match self
            .db
            .request(DbRequest::SchedStats(path, sched_params))
            .await
        {
            Ok(value) => Ok(make_tool_result(value)),
            Err(e) => Ok(make_error_result(&e)),
        }
    }

    #[tool(
        name = "cpu_stats",
        description = "Per-CPU scheduling statistics. Shows utilization, idle%, thread count, IRQ/softIRQ time, and runqueue depth percentiles (p50/p90/p99) for each CPU. IRQ/softIRQ times are zero if the corresponding tables are absent. Runqueue percentiles are null if thread_state table is absent. Runqueue estimates are approximate: they model sleep-to-wake-to-run cycles only (preempted threads excluded), target_cpu is the CPU at wakeup time (migration not tracked), and percentiles are event-weighted not time-weighted."
    )]
    async fn cpu_stats(
        &self,
        Parameters(params): Parameters<CpuStatsToolParams>,
    ) -> std::result::Result<CallToolResult, McpError> {
        let path = params.path.map(PathBuf::from);
        let cpu_params = CpuStatsParams {
            trace_id: params.trace_id,
        };

        match self.db.request(DbRequest::CpuStats(path, cpu_params)).await {
            Ok(value) => Ok(make_tool_result(value)),
            Err(e) => Ok(make_error_result(&e)),
        }
    }

    #[tool(
        name = "network_connections",
        description = "Per-connection network traffic summary. Shows protocol, address family, source/destination IP:port, interface, namespace, send/recv bytes, and TCP retransmit percentage for each socket. Results are grouped by trace and sorted by total bytes descending within each trace."
    )]
    async fn network_connections(
        &self,
        Parameters(params): Parameters<NetworkConnectionsToolParams>,
    ) -> std::result::Result<CallToolResult, McpError> {
        let path = params.path.map(PathBuf::from);
        if params.pid.is_some() && params.tid.is_some() {
            return Ok(make_error_result(
                "pid and tid are mutually exclusive. Provide one or neither.",
            ));
        }

        let nc_params = NetworkConnectionsParams {
            trace_id: params.trace_id,
            pid: params.pid,
            tid: params.tid,
            top_n: params.top_n.or(Some(50)),
        };

        match self
            .db
            .request(DbRequest::NetworkConnections(path, nc_params))
            .await
        {
            Ok(value) => Ok(make_tool_result(value)),
            Err(e) => Ok(make_error_result(&e)),
        }
    }

    #[tool(
        name = "network_interfaces",
        description = "Per-interface network traffic summary. Shows namespace, interface name, IP addresses, and per-protocol traffic breakdown (send/recv bytes, socket count, TCP retransmit percentage). Results are grouped by trace."
    )]
    async fn network_interfaces(
        &self,
        Parameters(params): Parameters<NetworkInterfacesToolParams>,
    ) -> std::result::Result<CallToolResult, McpError> {
        let path = params.path.map(PathBuf::from);
        let ni_params = NetworkInterfacesParams {
            trace_id: params.trace_id,
        };

        match self
            .db
            .request(DbRequest::NetworkInterfaces(path, ni_params))
            .await
        {
            Ok(value) => Ok(make_tool_result(value)),
            Err(e) => Ok(make_error_result(&e)),
        }
    }

    #[tool(
        name = "network_socket_pairs",
        description = "Find matched socket pairs — connections where both the sender and receiver side are captured in the database. Matches by 4-tuple (src_ip, src_port, dest_ip, dest_port) reversal with same protocol and address family. Shows traffic stats and retransmit info for both sides. Pairs can be within the same trace or across different traces (cross_trace=true). Side A is the client (higher ephemeral src_port), Side B is the server."
    )]
    async fn network_socket_pairs(
        &self,
        Parameters(params): Parameters<NetworkSocketPairsToolParams>,
    ) -> std::result::Result<CallToolResult, McpError> {
        let path = params.path.map(PathBuf::from);
        let nsp_params = NetworkSocketPairsParams {
            trace_id: params.trace_id,
            dest_port: params.dest_port,
            ip: params.ip,
            top_n: params.top_n.or(Some(50)),
            exclude_loopback: params.exclude_loopback.unwrap_or(false),
        };

        match self
            .db
            .request(DbRequest::NetworkSocketPairs(path, nsp_params))
            .await
        {
            Ok(value) => Ok(make_tool_result(value)),
            Err(e) => Ok(make_error_result(&e)),
        }
    }
}

const SERVER_INSTRUCTIONS: &str = "\
systing-analyze MCP server: Query and analyze systing trace databases.

# What are systing traces?
systing is a Linux tracing tool that captures scheduling events, stack traces, \
network activity, and performance counters. Traces are stored in DuckDB databases.

# Key tables and their contents
- stack_sample: Stack trace samples with timestamps (ts in nanoseconds). \
  stack_event_type: 0=uninterruptible-sleep, 1=cpu, 2=interruptible-sleep.
- stack: Flattened stack frames (frame_names array, leaf-to-root order).
- thread: Thread metadata (utid=internal unique ID, tid=Linux TID).
- process: Process metadata (upid=internal unique ID, pid=Linux PID, name).
- sched_slice: Scheduling events with durations.
- counter: Performance counter values over time.
- network_syscall: Network send/recv syscalls with bytes and buffer metrics.
- network_packet: Packet-level events (TCP/UDP) with sequence numbers, \
  retransmits, RTT, drops.
- network_socket: Socket metadata (protocol, src/dest IP:port).

# Important conventions
- All timestamps (ts) are in nanoseconds since an arbitrary epoch.
- utid/upid are internal unique thread/process IDs (not Linux TID/PID). \
  Use thread.tid / process.pid for the Linux IDs.
- stack_sample.stack_event_type: 0 = uninterruptible-sleep, 1 = CPU sample, 2 = interruptible-sleep.
- sched_slice.end_state: 1 = interruptible sleep (S), 2 = uninterruptible sleep (D).
- Tables are linked by trace_id (for multi-trace databases).

# Recommended workflow
All tools accept an optional `path` parameter pointing to a .duckdb trace database file. \
The database is opened automatically on first use and cached for subsequent calls. \
If `path` is omitted, the most recently accessed database is used.
1. trace_info \u{2014} Get overview: traces, time range, tables, processes. \
   Good first call with a new database path.
2. list_tables \u{2014} See all tables and row counts.
3. describe_table \u{2014} Get column names and types for a table of interest.
4. query \u{2014} Run SQL queries. Results are capped at 10,000 rows; \
   use SQL LIMIT/OFFSET for larger result sets.
5. flamegraph \u{2014} Structured stack trace analysis with filtering.
6. sched_stats \u{2014} Scheduling timing statistics. Shows CPU time, event counts, \
   slice durations, preemption rates, and CPU migrations. Three modes: \
   no filter = whole-trace with per-process ranking, \
   pid = process detail with per-thread breakdown, \
   tid = single thread detail with end-state distribution.
7. cpu_stats \u{2014} Per-CPU scheduling statistics. Shows utilization, idle%, \
   thread count, IRQ/softIRQ time, and runqueue depth percentiles per CPU.
8. network_connections \u{2014} Per-connection traffic summary. Shows protocol, \
   source/dest IP:port, interface, send/recv bytes, and TCP retransmit rate.
9. network_interfaces \u{2014} Per-interface traffic summary. Shows namespace, \
   interface, IP addresses, and per-protocol traffic breakdown.
10. network_socket_pairs \u{2014} Find matched socket pairs (both sides of a \
    connection captured). Shows traffic stats for both sides, useful for \
    analyzing cross-node or same-node connection pairs in multi-trace databases.

# Query result limits
Queries return at most 10,000 rows. If results are truncated, the response \
includes truncated=true and total_row_count. Use SQL LIMIT and OFFSET clauses \
to paginate through larger result sets.";

#[tool_handler]
impl ServerHandler for SystingMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(SERVER_INSTRUCTIONS.into()),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

/// Run the MCP server over stdio transport.
pub async fn run_mcp_server(database: Option<PathBuf>) -> Result<()> {
    let db_handle = DbHandle::new(database)?;
    let server = SystingMcpServer::new(db_handle);

    let service = server.serve(stdio()).await?;
    service.waiting().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Verify that the MCP tool router contains exactly the expected set of tools.
    ///
    /// When adding a new analysis subcommand to systing-analyze, you must also add
    /// a corresponding MCP tool in this file and update the expected list below.
    /// This test will fail if tools are added to the router without updating the
    /// list, or if expected tools are missing from the router.
    #[test]
    fn test_mcp_tools_match_expected_set() {
        let router = SystingMcpServer::tool_router();
        let registered: BTreeSet<String> = router
            .list_all()
            .into_iter()
            .map(|t| t.name.to_string())
            .collect();

        // Every AnalyzeDb analysis method that has a CLI subcommand should have
        // a corresponding MCP tool listed here. Update this list when adding
        // new analysis tools.
        let expected: BTreeSet<String> = [
            // Core utilities
            "query",
            "list_tables",
            "describe_table",
            "trace_info",
            // Analysis tools (each corresponds to an AnalyzeDb method + CLI subcommand)
            "flamegraph",
            "sched_stats",
            "cpu_stats",
            "network_connections",
            "network_interfaces",
            "network_socket_pairs",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        let missing: BTreeSet<_> = expected.difference(&registered).collect();
        let extra: BTreeSet<_> = registered.difference(&expected).collect();

        assert!(
            missing.is_empty() && extra.is_empty(),
            "MCP tool registration mismatch!\n\
             Missing from router (need #[tool] impl): {missing:?}\n\
             In router but not in expected list (update test_mcp_tools_match_expected_set): {extra:?}\n\
             \n\
             If you added a new analysis subcommand, add a corresponding MCP tool \
             in src/mcp.rs and add its name to the expected list in this test."
        );
    }

    // -- string_or_number deserialization tests --

    #[derive(Debug, Deserialize, PartialEq)]
    struct TestU32Params {
        #[serde(default, deserialize_with = "string_or_number::option::deserialize")]
        value: Option<u32>,
    }

    #[derive(Debug, Deserialize, PartialEq)]
    struct TestF64Params {
        #[serde(default, deserialize_with = "string_or_number::option::deserialize")]
        value: Option<f64>,
    }

    #[derive(Debug, Deserialize, PartialEq)]
    struct TestI32Params {
        #[serde(default, deserialize_with = "string_or_number::option::deserialize")]
        value: Option<i32>,
    }

    #[test]
    fn test_string_or_number_u32_from_number() {
        let p: TestU32Params = serde_json::from_str(r#"{"value": 42}"#).unwrap();
        assert_eq!(p.value, Some(42));
    }

    #[test]
    fn test_string_or_number_u32_from_string() {
        let p: TestU32Params = serde_json::from_str(r#"{"value": "42"}"#).unwrap();
        assert_eq!(p.value, Some(42));
    }

    #[test]
    fn test_string_or_number_null() {
        let p: TestU32Params = serde_json::from_str(r#"{"value": null}"#).unwrap();
        assert_eq!(p.value, None);
    }

    #[test]
    fn test_string_or_number_missing_field() {
        let p: TestU32Params = serde_json::from_str(r#"{}"#).unwrap();
        assert_eq!(p.value, None);
    }

    #[test]
    fn test_string_or_number_invalid_string() {
        let result = serde_json::from_str::<TestU32Params>(r#"{"value": "not_a_number"}"#);
        assert!(result.is_err());
    }

    #[test]
    fn test_string_or_number_f64_from_string() {
        let p: TestF64Params = serde_json::from_str(r#"{"value": "1.25"}"#).unwrap();
        assert!((p.value.unwrap() - 1.25).abs() < f64::EPSILON);
    }

    #[test]
    fn test_string_or_number_f64_from_number() {
        let p: TestF64Params = serde_json::from_str(r#"{"value": 1.25}"#).unwrap();
        assert!((p.value.unwrap() - 1.25).abs() < f64::EPSILON);
    }

    #[test]
    fn test_string_or_number_i32_from_negative_string() {
        let p: TestI32Params = serde_json::from_str(r#"{"value": "-80"}"#).unwrap();
        assert_eq!(p.value, Some(-80));
    }

    #[test]
    fn test_string_or_number_i32_from_negative_number() {
        let p: TestI32Params = serde_json::from_str(r#"{"value": -80}"#).unwrap();
        assert_eq!(p.value, Some(-80));
    }

    #[test]
    fn test_string_or_number_rejects_boolean() {
        let result = serde_json::from_str::<TestU32Params>(r#"{"value": true}"#);
        assert!(result.is_err());
    }
}
