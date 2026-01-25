//! systing-analyze: Query and analyze trace databases
//!
//! This tool runs SQL queries against DuckDB trace databases, supporting both
//! one-shot queries, interactive mode, and specialized analysis commands.

use anyhow::{bail, Result};
use clap::{Args, Parser, Subcommand};
use duckdb::Connection;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "systing-analyze")]
#[command(about = "Query and analyze trace databases")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run SQL queries against a DuckDB database
    Query {
        /// Path to DuckDB database
        #[arg(short, long)]
        database: PathBuf,

        /// SQL query to execute (if not provided, starts interactive mode)
        #[arg(short, long)]
        sql: Option<String>,

        /// Output format: table, csv, json
        #[arg(short, long, default_value = "table")]
        format: String,
    },
    /// Stack trace analysis commands
    Stacktrace(StacktraceArgs),
}

#[derive(Args)]
struct StacktraceArgs {
    #[command(subcommand)]
    command: StacktraceCommands,
}

#[derive(Subcommand)]
enum StacktraceCommands {
    /// Generate folded-stack flamegraph output
    Flamegraph(FlamegraphArgs),
}

#[derive(Args)]
struct FlamegraphArgs {
    /// Path to DuckDB database
    #[arg(short, long)]
    database: PathBuf,

    /// Stack type filter
    #[arg(short = 't', long, default_value = "cpu")]
    stack_type: StackTypeFilter,

    /// Filter to a specific process (all its threads)
    #[arg(short, long)]
    pid: Option<u32>,

    /// Filter to a specific thread
    #[arg(long)]
    tid: Option<u32>,

    /// Start time offset in seconds from trace start
    #[arg(long)]
    start_time: Option<f64>,

    /// End time offset in seconds from trace start
    #[arg(long)]
    end_time: Option<f64>,

    /// Filter to a specific trace (for multi-trace DBs)
    #[arg(long)]
    trace_id: Option<String>,

    /// Minimum sample count to include a stack
    #[arg(long, default_value = "1")]
    min_count: u64,
}

#[derive(Clone, clap::ValueEnum)]
enum StackTypeFilter {
    Cpu,
    InterruptibleSleep,
    UninterruptibleSleep,
    AllSleep,
    All,
}

/// Run the query command
fn run_query(database: PathBuf, sql: Option<String>, format: String) -> Result<()> {
    if !database.exists() {
        bail!("Database not found: {}", database.display());
    }

    let conn = Connection::open(&database)?;

    match sql {
        Some(query) => {
            execute_query(&conn, &query, &format)?;
        }
        None => {
            // Interactive mode
            run_interactive(&conn, &format)?;
        }
    }

    Ok(())
}

/// Execute a single query and display results
fn execute_query(conn: &Connection, sql: &str, format: &str) -> Result<()> {
    let mut stmt = conn.prepare(sql)?;
    let mut rows = stmt.query([])?;

    // Get column info from the first row or statement
    let column_count = rows.as_ref().map_or(0, |r| r.column_count());
    let column_names: Vec<String> = if let Some(row_ref) = rows.as_ref() {
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

    let mut rows_data: Vec<Vec<String>> = Vec::new();

    while let Some(row) = rows.next()? {
        let mut row_values = Vec::new();
        for i in 0..column_count {
            let value: duckdb::types::Value = row.get(i)?;
            let str_value = match value {
                duckdb::types::Value::Null => "NULL".to_string(),
                duckdb::types::Value::Boolean(b) => b.to_string(),
                duckdb::types::Value::TinyInt(n) => n.to_string(),
                duckdb::types::Value::SmallInt(n) => n.to_string(),
                duckdb::types::Value::Int(n) => n.to_string(),
                duckdb::types::Value::BigInt(n) => n.to_string(),
                duckdb::types::Value::HugeInt(n) => n.to_string(),
                duckdb::types::Value::UTinyInt(n) => n.to_string(),
                duckdb::types::Value::USmallInt(n) => n.to_string(),
                duckdb::types::Value::UInt(n) => n.to_string(),
                duckdb::types::Value::UBigInt(n) => n.to_string(),
                duckdb::types::Value::Float(n) => n.to_string(),
                duckdb::types::Value::Double(n) => n.to_string(),
                duckdb::types::Value::Text(s) => s,
                _ => format!("{value:?}"),
            };
            row_values.push(str_value);
        }
        rows_data.push(row_values);
    }

    match format {
        "csv" => {
            println!("{}", column_names.join(","));
            for row in &rows_data {
                println!("{}", row.join(","));
            }
        }
        "json" => {
            let json_rows: Vec<serde_json::Value> = rows_data
                .iter()
                .map(|row| {
                    let obj: serde_json::Map<String, serde_json::Value> = column_names
                        .iter()
                        .zip(row.iter())
                        .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                        .collect();
                    serde_json::Value::Object(obj)
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&json_rows)?);
        }
        _ => {
            // Table format
            print_table(&column_names, &rows_data);
        }
    }

    eprintln!("\n{} rows returned", rows_data.len());
    Ok(())
}

const MAX_COLUMN_WIDTH: usize = 50;

fn print_table(headers: &[String], rows: &[Vec<String>]) {
    if rows.is_empty() {
        println!("(no results)");
        return;
    }

    let mut widths: Vec<usize> = headers.iter().map(String::len).collect();
    for row in rows {
        for (i, val) in row.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(val.len());
            }
        }
    }

    for w in &mut widths {
        *w = (*w).min(MAX_COLUMN_WIDTH);
    }

    let header_line: Vec<String> = headers
        .iter()
        .enumerate()
        .map(|(i, h)| format!("{:width$}", h, width = widths.get(i).copied().unwrap_or(10)))
        .collect();
    println!("{}", header_line.join(" | "));

    let sep: Vec<String> = widths.iter().map(|w| "-".repeat(*w)).collect();
    println!("{}", sep.join("-+-"));

    for row in rows {
        let row_line: Vec<String> = row
            .iter()
            .enumerate()
            .map(|(i, v)| {
                let width = widths.get(i).copied().unwrap_or(10);
                let truncated = if v.len() > width && width > 3 {
                    format!("{}...", &v[..width.saturating_sub(3)])
                } else {
                    v.clone()
                };
                format!("{truncated:width$}")
            })
            .collect();
        println!("{}", row_line.join(" | "));
    }
}

fn run_interactive(conn: &Connection, format: &str) -> Result<()> {
    use std::io::{self, BufRead, Write};

    eprintln!("systing-analyze interactive mode");
    eprintln!("Enter SQL queries (end with ';'), or 'quit' to exit.\n");

    eprintln!("Available tables:");
    let mut stmt = conn.prepare(
        "SELECT table_name FROM information_schema.tables
         WHERE table_schema = 'main' ORDER BY table_name",
    )?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(0)?;
        eprintln!("  {name}");
    }
    eprintln!();

    let stdin = io::stdin();
    let mut query_buffer = String::new();

    loop {
        let prompt = if query_buffer.is_empty() {
            "sql> "
        } else {
            "...> "
        };
        eprint!("{prompt}");
        io::stderr().flush()?;

        let mut line = String::new();
        if stdin.lock().read_line(&mut line)? == 0 {
            break;
        }

        let trimmed = line.trim();
        if trimmed.eq_ignore_ascii_case("quit") || trimmed.eq_ignore_ascii_case("exit") {
            break;
        }

        query_buffer.push_str(&line);

        if query_buffer.trim().ends_with(';') {
            let query = query_buffer.trim().trim_end_matches(';').to_string();
            query_buffer.clear();

            if !query.is_empty() {
                if let Err(e) = execute_query(conn, &query, format) {
                    eprintln!("Error: {e}");
                }
            }
            println!();
        }
    }

    Ok(())
}

/// Run the flamegraph subcommand: query stack traces and output folded-stack format.
fn run_flamegraph(args: FlamegraphArgs) -> Result<()> {
    if !args.database.exists() {
        bail!("Database not found: {}", args.database.display());
    }

    let conn = Connection::open(&args.database)?;

    // Check that required tables exist
    if !table_exists(&conn, "stack_sample")? || !table_exists(&conn, "stack")? {
        bail!(
            "Database missing required tables (stack_sample, stack). \
             Is this a systing trace database?"
        );
    }

    // For sleep types requiring sched_slice correlation, verify the table exists
    if matches!(
        args.stack_type,
        StackTypeFilter::InterruptibleSleep | StackTypeFilter::UninterruptibleSleep
    ) && !table_has_rows(&conn, "sched_slice")?
    {
        bail!(
            "No sched_slice data available, required for {} filtering",
            stack_type_str(&args.stack_type)
        );
    }

    // Get time range for offset calculations
    let (min_ts, max_ts, total_samples) = get_trace_time_range(&conn, &args.trace_id)?;

    // Convert time offsets to absolute nanosecond timestamps
    let abs_start = args.start_time.map(|t| min_ts + (t * 1e9) as i64);
    let abs_end = args.end_time.map(|t| min_ts + (t * 1e9) as i64);

    // Build and execute the query
    let sql = build_flamegraph_query(
        &args.stack_type,
        &args.pid,
        &args.tid,
        &abs_start,
        &abs_end,
        &args.trace_id,
        args.min_count,
    );

    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query([])?;

    let mut total_output_samples: u64 = 0;
    let mut unique_stacks: u64 = 0;
    let mut output_lines: Vec<(String, u64)> = Vec::new();

    while let Some(row) = rows.next()? {
        let frames_str: String = row.get(0)?;
        let count: i64 = row.get(1)?;
        let count = count as u64;

        let folded = format_folded_stack(&frames_str);
        if !folded.is_empty() {
            output_lines.push((folded, count));
            total_output_samples += count;
            unique_stacks += 1;
        }
    }

    // Print metadata to stderr
    let duration_secs = (max_ts - min_ts) as f64 / 1e9;
    eprintln!("# Flamegraph: {}", args.database.display());
    eprintln!("# Stack type: {}", stack_type_str(&args.stack_type));
    eprintln!("# Total trace samples: {}", total_samples);
    eprintln!("# Output samples: {}", total_output_samples);
    eprintln!("# Unique stacks: {}", unique_stacks);
    eprintln!("# Time range: 0.000s - {:.3}s", duration_secs);

    let mut filters = Vec::new();
    if let Some(p) = &args.pid {
        filters.push(format!("pid={p}"));
    }
    if let Some(t) = &args.tid {
        filters.push(format!("tid={t}"));
    }
    if let Some(s) = &args.start_time {
        filters.push(format!("start={s}s"));
    }
    if let Some(e) = &args.end_time {
        filters.push(format!("end={e}s"));
    }
    if let Some(t) = &args.trace_id {
        filters.push(format!("trace_id={t}"));
    }
    if !filters.is_empty() {
        eprintln!("# Filters: {}", filters.join(", "));
    }

    // Print folded stacks to stdout
    for (folded, count) in &output_lines {
        println!("{folded} {count}");
    }

    Ok(())
}

fn stack_type_str(stack_type: &StackTypeFilter) -> &'static str {
    match stack_type {
        StackTypeFilter::Cpu => "cpu",
        StackTypeFilter::InterruptibleSleep => "interruptible-sleep",
        StackTypeFilter::UninterruptibleSleep => "uninterruptible-sleep",
        StackTypeFilter::AllSleep => "all-sleep",
        StackTypeFilter::All => "all",
    }
}

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
    // Use the table name directly - it's a known internal constant, not user input
    let sql = format!("SELECT 1 FROM {table_name} LIMIT 1");
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query([])?;
    Ok(rows.next()?.is_some())
}

fn get_trace_time_range(conn: &Connection, trace_id: &Option<String>) -> Result<(i64, i64, u64)> {
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

fn build_flamegraph_query(
    stack_type: &StackTypeFilter,
    pid: &Option<u32>,
    tid: &Option<u32>,
    abs_start: &Option<i64>,
    abs_end: &Option<i64>,
    trace_id: &Option<String>,
    min_count: u64,
) -> String {
    let mut joins = String::new();
    let mut conditions = Vec::new();

    // Stack type filter and potential sched_slice join
    match stack_type {
        StackTypeFilter::Cpu => {
            conditions.push("ss.stack_event_type = 1".to_string());
        }
        StackTypeFilter::InterruptibleSleep => {
            conditions.push("ss.stack_event_type = 0".to_string());
            conditions.push("sl.end_state = 1".to_string());
            joins.push_str(
                " JOIN sched_slice sl ON ss.utid = sl.utid AND ss.trace_id = sl.trace_id \
                 AND ABS(ss.ts - (sl.ts + sl.dur)) <= 10000000",
            );
        }
        StackTypeFilter::UninterruptibleSleep => {
            conditions.push("ss.stack_event_type = 0".to_string());
            conditions.push("sl.end_state = 2".to_string());
            joins.push_str(
                " JOIN sched_slice sl ON ss.utid = sl.utid AND ss.trace_id = sl.trace_id \
                 AND ABS(ss.ts - (sl.ts + sl.dur)) <= 10000000",
            );
        }
        StackTypeFilter::AllSleep => {
            conditions.push("ss.stack_event_type = 0".to_string());
        }
        StackTypeFilter::All => {}
    }

    // PID/TID filters require thread/process joins
    if pid.is_some() || tid.is_some() {
        joins.push_str(" JOIN thread t ON ss.utid = t.utid AND ss.trace_id = t.trace_id");
    }
    if pid.is_some() {
        joins.push_str(" JOIN process p ON t.upid = p.upid AND t.trace_id = p.trace_id");
    }

    if let Some(pid_val) = pid {
        conditions.push(format!("p.pid = {pid_val}"));
    }
    if let Some(tid_val) = tid {
        conditions.push(format!("t.tid = {tid_val}"));
    }

    // Time range
    if let Some(start) = abs_start {
        conditions.push(format!("ss.ts >= {start}"));
    }
    if let Some(end) = abs_end {
        conditions.push(format!("ss.ts <= {end}"));
    }

    // Trace ID
    if let Some(tid) = trace_id {
        let escaped = tid.replace('\'', "''");
        conditions.push(format!("ss.trace_id = '{escaped}'"));
    }

    // Filter out NULL/empty frame_names
    conditions.push("s.frame_names IS NOT NULL".to_string());
    conditions.push("len(s.frame_names) > 0".to_string());

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", conditions.join(" AND "))
    };

    let having_clause = if min_count > 1 {
        format!(" HAVING COUNT(*) >= {min_count}")
    } else {
        String::new()
    };

    format!(
        "SELECT array_to_string(s.frame_names, chr(31)) as frames, \
         COUNT(*) as count \
         FROM stack_sample ss \
         JOIN stack s ON ss.stack_id = s.id AND ss.trace_id = s.trace_id\
         {joins}{where_clause} \
         GROUP BY s.frame_names{having_clause} \
         ORDER BY count DESC"
    )
}

/// Format a DuckDB frame_names array (as chr(31)-separated string) into folded stack format.
///
/// Frame names are stored leaf-to-root in the database, so they are reversed
/// to root-to-leaf order for flamegraph convention (root;child;...;leaf).
fn format_folded_stack(frames_str: &str) -> String {
    if frames_str.is_empty() {
        return String::new();
    }

    let frames: Vec<&str> = frames_str.split('\x1F').collect();

    // Reverse from leaf-to-root (storage order) to root-to-leaf (flamegraph convention)
    let formatted: Vec<String> = frames.iter().rev().map(|f| format_frame(f)).collect();

    formatted.join(";")
}

/// Simplify a frame name for folded output.
///
/// Input format: `function_name (module_name [file:line]) <0xaddr>`
/// Output format: `function_name [module_name]`
///
/// Unsymbolized frames (bare hex addresses like `0x5dbfa1`) become `0x5dbfa1 [unknown]`.
fn format_frame(frame: &str) -> String {
    let frame = frame.trim();
    if frame.is_empty() {
        return "[unknown]".to_string();
    }

    // Try to parse: "function_name (module_name [file:line]) <0xaddr>"
    // or: "function_name (module_name) <0xaddr>"
    if let Some(paren_pos) = frame.find(" (") {
        let func_name = &frame[..paren_pos];
        let rest = &frame[paren_pos + 2..];

        // Extract module name (up to ' [' for source location or ')' for end)
        let module_end = rest
            .find(" [")
            .or_else(|| rest.find(')'))
            .unwrap_or(rest.len());
        let module_name = &rest[..module_end];

        if module_name.is_empty() {
            func_name.to_string()
        } else {
            format!("{func_name} [{module_name}]")
        }
    } else if frame.starts_with("0x") {
        // Bare hex address (unsymbolized)
        format!("{frame} [unknown]")
    } else {
        // Unknown format, return as-is
        frame.to_string()
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Query {
            database,
            sql,
            format,
        } => run_query(database, sql, format),
        Commands::Stacktrace(args) => match args.command {
            StacktraceCommands::Flamegraph(flamegraph_args) => run_flamegraph(flamegraph_args),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_frame_symbolized() {
        assert_eq!(
            format_frame("tcp_sendmsg (vmlinux [net/ipv4/tcp.c:1234]) <0xffffffff8ec7559e>"),
            "tcp_sendmsg [vmlinux]"
        );
    }

    #[test]
    fn test_format_frame_with_module_only() {
        assert_eq!(format_frame("main (myapp) <0x401234>"), "main [myapp]");
    }

    #[test]
    fn test_format_frame_kernel_unknown() {
        assert_eq!(
            format_frame("unknown ([kernel]) <0xffffffff8e000000>"),
            "unknown [[kernel]]"
        );
    }

    #[test]
    fn test_format_frame_bare_hex() {
        assert_eq!(format_frame("0x5dbfa1"), "0x5dbfa1 [unknown]");
    }

    #[test]
    fn test_format_frame_empty() {
        assert_eq!(format_frame(""), "[unknown]");
    }

    #[test]
    fn test_format_folded_stack_reversal() {
        // frame_names stored leaf-to-root: "leaf\x1Fmid\x1Froot"
        // Should output root-to-leaf: "root;mid;leaf"
        let input = "leaf (app) <0x1>\x1Fmid (app) <0x2>\x1Froot (app) <0x3>";
        let result = format_folded_stack(input);
        assert_eq!(result, "root [app];mid [app];leaf [app]");
    }

    #[test]
    fn test_format_folded_stack_empty() {
        assert_eq!(format_folded_stack(""), "");
    }

    #[test]
    fn test_format_folded_stack_single_frame() {
        let input = "main (myapp) <0x401234>";
        assert_eq!(format_folded_stack(input), "main [myapp]");
    }

    #[test]
    fn test_build_flamegraph_query_cpu() {
        let sql =
            build_flamegraph_query(&StackTypeFilter::Cpu, &None, &None, &None, &None, &None, 1);
        assert!(sql.contains("stack_event_type = 1"));
        assert!(!sql.contains("sched_slice"));
    }

    #[test]
    fn test_build_flamegraph_query_interruptible_sleep() {
        let sql = build_flamegraph_query(
            &StackTypeFilter::InterruptibleSleep,
            &None,
            &None,
            &None,
            &None,
            &None,
            1,
        );
        assert!(sql.contains("stack_event_type = 0"));
        assert!(sql.contains("sched_slice"));
        assert!(sql.contains("end_state = 1"));
    }

    #[test]
    fn test_build_flamegraph_query_with_pid() {
        let sql = build_flamegraph_query(
            &StackTypeFilter::Cpu,
            &Some(1234),
            &None,
            &None,
            &None,
            &None,
            1,
        );
        assert!(sql.contains("JOIN thread t"));
        assert!(sql.contains("JOIN process p"));
        assert!(sql.contains("p.pid = 1234"));
    }

    #[test]
    fn test_build_flamegraph_query_with_min_count() {
        let sql =
            build_flamegraph_query(&StackTypeFilter::All, &None, &None, &None, &None, &None, 10);
        assert!(sql.contains("HAVING COUNT(*) >= 10"));
    }

    #[test]
    fn test_build_flamegraph_query_no_having_for_min_count_1() {
        let sql =
            build_flamegraph_query(&StackTypeFilter::All, &None, &None, &None, &None, &None, 1);
        assert!(!sql.contains("HAVING"));
    }
}
