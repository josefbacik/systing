//! MCP (Model Context Protocol) server for systing-analyze.
//!
//! Provides an MCP server that exposes trace database analysis tools to AI
//! assistants. Uses a dedicated DB thread to handle DuckDB's non-Send connection.

use crate::analyze::{AnalyzeDb, FlamegraphParams, StackTypeFilter};
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
    TraceInfo,
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
                DbRequest::TraceInfo => db
                    .trace_info()
                    .map(|r| serde_json::to_value(r).unwrap_or_default())
                    .map_err(|e| format!("Error getting trace info: {e}")),
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
