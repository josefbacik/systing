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
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

// -- Database thread communication --

enum DbRequest {
    OpenDatabase(PathBuf),
    Query(String),
    ListTables,
    DescribeTable(String),
    Flamegraph(FlamegraphParams),
    SchedStats(SchedStatsParams),
    CpuStats(CpuStatsParams),
    TraceInfo,
    NetworkConnections(NetworkConnectionsParams),
    NetworkInterfaces(NetworkInterfacesParams),
    NetworkSocketPairs(NetworkSocketPairsParams),
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
            let mut db: Option<AnalyzeDb> =
                initial_db.and_then(|p| match AnalyzeDb::open(&p, true) {
                    Ok(db) => Some(db),
                    Err(e) => {
                        eprintln!("Warning: failed to open initial database: {e}");
                        None
                    }
                });

            while let Some((request, reply)) = receiver.blocking_recv() {
                let result = handle_db_request(&mut db, request);
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

/// Process a single database request on the DB thread.
fn handle_db_request(db: &mut Option<AnalyzeDb>, request: DbRequest) -> DbResponse {
    match request {
        DbRequest::OpenDatabase(path) => match AnalyzeDb::open(&path, true) {
            Ok(new_db) => {
                let info = new_db.trace_info();
                *db = Some(new_db);
                match info {
                    Ok(info) => {
                        serde_json::to_value(info).map_err(|e| format!("Serialization error: {e}"))
                    }
                    Err(e) => Ok(serde_json::json!({
                        "status": "opened",
                        "note": format!("Database opened but error getting full info: {e}")
                    })),
                }
            }
            Err(e) => Err(format!("Failed to open database: {e}")),
        },
        _ => {
            let Some(db) = db.as_ref() else {
                return Err("No database is open. Use the open_database tool first.".to_string());
            };
            match request {
                DbRequest::Query(sql) => db
                    .query(&sql)
                    .map(|r| serde_json::to_value(r).unwrap_or_default())
                    .map_err(|e| format!("Query error: {e}")),
                DbRequest::ListTables => db
                    .list_tables()
                    .map(|r| serde_json::to_value(r).unwrap_or_default())
                    .map_err(|e| format!("Error listing tables: {e}")),
                DbRequest::DescribeTable(name) => db
                    .describe_table(&name)
                    .map(|r| serde_json::to_value(r).unwrap_or_default())
                    .map_err(|e| format!("Error describing table: {e}")),
                DbRequest::Flamegraph(params) => db
                    .flamegraph(&params)
                    .map(|r| serde_json::to_value(r).unwrap_or_default())
                    .map_err(|e| format!("Flamegraph error: {e}")),
                DbRequest::SchedStats(params) => db
                    .sched_stats(&params)
                    .map(|r| serde_json::to_value(r).unwrap_or_default())
                    .map_err(|e| format!("Sched stats error: {e}")),
                DbRequest::CpuStats(params) => db
                    .cpu_stats(&params)
                    .map(|r| serde_json::to_value(r).unwrap_or_default())
                    .map_err(|e| format!("CPU stats error: {e}")),
                DbRequest::TraceInfo => db
                    .trace_info()
                    .map(|r| serde_json::to_value(r).unwrap_or_default())
                    .map_err(|e| format!("Error getting trace info: {e}")),
                DbRequest::NetworkConnections(params) => db
                    .network_connections(&params)
                    .map(|r| serde_json::to_value(r).unwrap_or_default())
                    .map_err(|e| format!("Network connections error: {e}")),
                DbRequest::NetworkInterfaces(params) => db
                    .network_interfaces(&params)
                    .map(|r| serde_json::to_value(r).unwrap_or_default())
                    .map_err(|e| format!("Network interfaces error: {e}")),
                DbRequest::NetworkSocketPairs(params) => db
                    .network_socket_pairs(&params)
                    .map(|r| serde_json::to_value(r).unwrap_or_default())
                    .map_err(|e| format!("Network socket pairs error: {e}")),
                DbRequest::OpenDatabase(_) => unreachable!(),
            }
        }
    }
}

// -- Tool parameter types --

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct OpenDatabaseParams {
    /// Absolute path to a .duckdb trace database file.
    path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct QueryParams {
    /// SQL query to execute. The database is opened read-only, so DML/DDL will fail.
    sql: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct DescribeTableParams {
    /// Name of the table to describe.
    table_name: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct FlamegraphToolParams {
    /// Stack type filter: "cpu", "interruptible-sleep", "uninterruptible-sleep",
    /// "all-sleep", or "all". Defaults to "cpu".
    stack_type: Option<String>,

    /// Filter to a specific process ID.
    pid: Option<u32>,

    /// Filter to a specific thread ID.
    tid: Option<u32>,

    /// Start time offset in seconds from trace start.
    start_time: Option<f64>,

    /// End time offset in seconds from trace start.
    end_time: Option<f64>,

    /// Filter to a specific trace ID (for multi-trace databases).
    trace_id: Option<String>,

    /// Minimum sample count to include a stack. Default: 1.
    min_count: Option<u64>,

    /// Limit to top N stacks by sample count. Default: 500.
    top_n: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SchedStatsToolParams {
    /// Filter to a specific process ID.
    pid: Option<u32>,

    /// Filter to a specific thread ID (mutually exclusive with pid).
    tid: Option<u32>,

    /// Filter to a specific trace ID (for multi-trace databases).
    trace_id: Option<String>,

    /// Max processes/threads to return. Default: 20.
    top_n: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct CpuStatsToolParams {
    /// Filter to a specific trace ID (for multi-trace databases).
    trace_id: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct NetworkConnectionsToolParams {
    /// Filter to a specific trace ID (for multi-trace databases).
    trace_id: Option<String>,

    /// Filter to a specific process ID.
    pid: Option<u32>,

    /// Filter to a specific thread ID (mutually exclusive with pid).
    tid: Option<u32>,

    /// Max connections per trace to return. Default: 50. Null for no limit.
    top_n: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct NetworkInterfacesToolParams {
    /// Filter to a specific trace ID (for multi-trace databases).
    trace_id: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct NetworkSocketPairsToolParams {
    /// Filter to a specific trace ID. Shows pairs where at least one side is in this trace.
    trace_id: Option<String>,

    /// Filter to connections involving this service port (either side's dest_port).
    dest_port: Option<i32>,

    /// Filter to connections involving this IP address (matches src or dest on either side).
    ip: Option<String>,

    /// Max pairs to return. Default: 50. Null for no limit.
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
        name = "open_database",
        description = "Open a DuckDB trace database for analysis. Replaces any previously opened database. The database is opened read-only. Returns basic info about the database contents including table counts, trace IDs, and processes."
    )]
    async fn open_database(
        &self,
        Parameters(params): Parameters<OpenDatabaseParams>,
    ) -> std::result::Result<CallToolResult, McpError> {
        let path = PathBuf::from(&params.path);
        match self.db.request(DbRequest::OpenDatabase(path)).await {
            Ok(value) => Ok(make_tool_result(value)),
            Err(e) => Ok(make_error_result(&e)),
        }
    }

    #[tool(
        name = "query",
        description = "Execute a read-only SQL query against the open trace database. Returns JSON with 'columns' (array of column names), 'rows' (array of arrays with properly typed values — numbers as numbers, not strings), and 'row_count'. Results are capped at 10,000 rows; if truncated, includes 'truncated: true' and 'total_row_count'. Use SQL LIMIT/OFFSET for pagination. The database is read-only, so INSERT/UPDATE/DELETE will fail."
    )]
    async fn query(
        &self,
        Parameters(params): Parameters<QueryParams>,
    ) -> std::result::Result<CallToolResult, McpError> {
        match self.db.request(DbRequest::Query(params.sql)).await {
            Ok(value) => Ok(make_tool_result(value)),
            Err(e) => Ok(make_error_result(&e)),
        }
    }

    #[tool(
        name = "list_tables",
        description = "List all tables in the open database with their row counts."
    )]
    async fn list_tables(&self) -> std::result::Result<CallToolResult, McpError> {
        match self.db.request(DbRequest::ListTables).await {
            Ok(value) => Ok(make_tool_result(value)),
            Err(e) => Ok(make_error_result(&e)),
        }
    }

    #[tool(
        name = "describe_table",
        description = "Get column names and types for a specific table in the open database."
    )]
    async fn describe_table(
        &self,
        Parameters(params): Parameters<DescribeTableParams>,
    ) -> std::result::Result<CallToolResult, McpError> {
        match self
            .db
            .request(DbRequest::DescribeTable(params.table_name))
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

        match self.db.request(DbRequest::Flamegraph(fg_params)).await {
            Ok(value) => Ok(make_tool_result(value)),
            Err(e) => Ok(make_error_result(&e)),
        }
    }

    #[tool(
        name = "trace_info",
        description = "Get metadata about the open trace database: database path, trace IDs, time range (in nanoseconds and seconds), non-empty tables with row counts, and a list of processes with PID, name, and thread count."
    )]
    async fn trace_info(&self) -> std::result::Result<CallToolResult, McpError> {
        match self.db.request(DbRequest::TraceInfo).await {
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

        match self.db.request(DbRequest::SchedStats(sched_params)).await {
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
        let cpu_params = CpuStatsParams {
            trace_id: params.trace_id,
        };

        match self.db.request(DbRequest::CpuStats(cpu_params)).await {
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
            .request(DbRequest::NetworkConnections(nc_params))
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
        let ni_params = NetworkInterfacesParams {
            trace_id: params.trace_id,
        };

        match self
            .db
            .request(DbRequest::NetworkInterfaces(ni_params))
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
        let nsp_params = NetworkSocketPairsParams {
            trace_id: params.trace_id,
            dest_port: params.dest_port,
            ip: params.ip,
            top_n: params.top_n.or(Some(50)),
            exclude_loopback: params.exclude_loopback.unwrap_or(false),
        };

        match self
            .db
            .request(DbRequest::NetworkSocketPairs(nsp_params))
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
1. open_database — Open a trace .duckdb file (required first step).
2. trace_info — Get overview: traces, time range, tables, processes.
3. list_tables — See all tables and row counts.
4. describe_table — Get column names and types for a table of interest.
5. query — Run SQL queries. Results are capped at 10,000 rows; \
   use SQL LIMIT/OFFSET for larger result sets.
6. flamegraph — Structured stack trace analysis with filtering.
7. sched_stats — Scheduling timing statistics. Shows CPU time, event counts, \
   slice durations, preemption rates, and CPU migrations. Three modes: \
   no filter = whole-trace with per-process ranking, \
   pid = process detail with per-thread breakdown, \
   tid = single thread detail with end-state distribution.
8. cpu_stats — Per-CPU scheduling statistics. Shows utilization, idle%, \
   thread count, IRQ/softIRQ time, and runqueue depth percentiles per CPU.
9. network_connections — Per-connection traffic summary. Shows protocol, \
   source/dest IP:port, interface, send/recv bytes, and TCP retransmit rate.
10. network_interfaces — Per-interface traffic summary. Shows namespace, \
   interface, IP addresses, and per-protocol traffic breakdown.
11. network_socket_pairs — Find matched socket pairs (both sides of a \
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
            "open_database",
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
}
