//! systing-analyze: Query and analyze trace databases
//!
//! This tool runs SQL queries against DuckDB trace databases, supporting both
//! one-shot queries, interactive mode, specialized analysis commands, and an
//! MCP server mode for AI assistant integration.

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;
use systing::analyze::{self, AnalyzeDb};

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
    /// Scheduling analysis commands
    Sched(SchedArgs),
    /// Start MCP (Model Context Protocol) server for AI assistant integration
    Mcp {
        /// Path to DuckDB database to open on startup (optional)
        #[arg(short, long)]
        database: Option<PathBuf>,
    },
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
    stack_type: CliStackType,

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
enum CliStackType {
    Cpu,
    InterruptibleSleep,
    UninterruptibleSleep,
    AllSleep,
    All,
}

impl From<CliStackType> for analyze::StackTypeFilter {
    fn from(s: CliStackType) -> Self {
        match s {
            CliStackType::Cpu => Self::Cpu,
            CliStackType::InterruptibleSleep => Self::InterruptibleSleep,
            CliStackType::UninterruptibleSleep => Self::UninterruptibleSleep,
            CliStackType::AllSleep => Self::AllSleep,
            CliStackType::All => Self::All,
        }
    }
}

#[derive(Args)]
struct SchedArgs {
    #[command(subcommand)]
    command: SchedCommands,
}

#[derive(Subcommand)]
enum SchedCommands {
    /// Show scheduling timing statistics
    Stats(SchedStatsArgs),
    /// Show per-CPU scheduling statistics
    CpuStats(SchedCpuStatsArgs),
}

#[derive(Args)]
struct SchedStatsArgs {
    /// Path to DuckDB database
    #[arg(short, long)]
    database: PathBuf,

    /// Filter to a specific process (all its threads)
    #[arg(short, long, conflicts_with = "tid")]
    pid: Option<u32>,

    /// Filter to a specific thread
    #[arg(long, conflicts_with = "pid")]
    tid: Option<u32>,

    /// Output format: table or json
    #[arg(short, long, default_value = "table")]
    format: String,

    /// Filter to a specific trace (for multi-trace DBs)
    #[arg(long)]
    trace_id: Option<String>,

    /// Max processes/threads to show (minimum 1)
    #[arg(long, default_value = "20", value_parser = clap::value_parser!(u64).range(1..))]
    top: u64,
}

#[derive(Args)]
struct SchedCpuStatsArgs {
    /// Path to DuckDB database
    #[arg(short, long)]
    database: PathBuf,

    /// Output format: table or json
    #[arg(short, long, default_value = "table")]
    format: String,

    /// Filter to a specific trace (for multi-trace DBs)
    #[arg(long)]
    trace_id: Option<String>,
}

/// Run the query command
fn run_query(database: PathBuf, sql: Option<String>, format: String) -> Result<()> {
    let db = AnalyzeDb::open(&database, false)?;

    match sql {
        Some(query) => {
            execute_query(&db, &query, &format)?;
        }
        None => {
            run_interactive(&db, &format)?;
        }
    }

    Ok(())
}

/// Execute a single query and display results
fn execute_query(db: &AnalyzeDb, sql: &str, format: &str) -> Result<()> {
    match format {
        "json" => {
            let result = db.query(sql)?;
            let json_rows: Vec<serde_json::Value> = result
                .rows
                .iter()
                .map(|row| {
                    let obj: serde_json::Map<String, serde_json::Value> = result
                        .columns
                        .iter()
                        .zip(row.iter())
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect();
                    serde_json::Value::Object(obj)
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&json_rows)?);
            eprintln!("\n{} rows returned", result.row_count);
        }
        _ => {
            // Table/CSV: use string-based query for display
            let (column_names, rows_data) = db.query_strings(sql)?;
            match format {
                "csv" => {
                    println!("{}", column_names.join(","));
                    for row in &rows_data {
                        println!("{}", row.join(","));
                    }
                }
                _ => {
                    print_table(&column_names, &rows_data);
                }
            }
            eprintln!("\n{} rows returned", rows_data.len());
        }
    }
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
                    let trunc_chars: String = v.chars().take(width.saturating_sub(3)).collect();
                    format!("{trunc_chars}...")
                } else {
                    v.clone()
                };
                format!("{truncated:width$}")
            })
            .collect();
        println!("{}", row_line.join(" | "));
    }
}

fn run_interactive(db: &AnalyzeDb, format: &str) -> Result<()> {
    use std::io::{self, BufRead, Write};

    eprintln!("systing-analyze interactive mode");
    eprintln!("Enter SQL queries (end with ';'), or 'quit' to exit.\n");

    eprintln!("Available tables:");
    match db.list_tables() {
        Ok(tables) => {
            for table in &tables {
                eprintln!("  {}", table.name);
            }
        }
        Err(e) => eprintln!("  Error listing tables: {e}"),
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
                if let Err(e) = execute_query(db, &query, format) {
                    eprintln!("Error: {e}");
                }
            }
            println!();
        }
    }

    Ok(())
}

/// Run the flamegraph subcommand
fn run_flamegraph(args: FlamegraphArgs) -> Result<()> {
    let db = AnalyzeDb::open(&args.database, true)?;

    let params = analyze::FlamegraphParams {
        stack_type: args.stack_type.into(),
        pid: args.pid,
        tid: args.tid,
        start_time: args.start_time,
        end_time: args.end_time,
        trace_id: args.trace_id.clone(),
        min_count: args.min_count,
        top_n: usize::MAX, // No limit for CLI output
    };

    let result = db.flamegraph(&params)?;

    // Print metadata to stderr
    eprintln!("# Flamegraph: {}", args.database.display());
    eprintln!("# Stack type: {}", result.metadata.stack_type);
    eprintln!("# Total trace samples: {}", result.metadata.total_samples);
    eprintln!(
        "# Output samples: {}",
        result.stacks.iter().map(|s| s.count).sum::<u64>()
    );
    eprintln!("# Unique stacks: {}", result.metadata.unique_stacks);
    eprintln!(
        "# Time range: {:.3}s - {:.3}s",
        result.metadata.time_range_seconds.0, result.metadata.time_range_seconds.1
    );

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
    for stack in &result.stacks {
        let folded = stack.frames.join(";");
        println!("{folded} {}", stack.count);
    }

    Ok(())
}

/// Format a duration in seconds for display.
fn format_duration(seconds: f64) -> String {
    if seconds < 0.0 {
        format!("-{}", format_duration(-seconds))
    } else if seconds >= 1.0 {
        format!("{:.3}s", seconds)
    } else if seconds >= 0.001 {
        format!("{:.3}ms", seconds * 1e3)
    } else {
        format!("{:.3}us", seconds * 1e6)
    }
}

/// Format a value in microseconds for display.
fn format_us(us: f64) -> String {
    if us >= 1e6 {
        format!("{:.3}s", us / 1e6)
    } else if us >= 1e3 {
        format!("{:.3}ms", us / 1e3)
    } else {
        format!("{:.3}us", us)
    }
}

/// Run the sched stats subcommand
fn run_sched_stats(args: SchedStatsArgs) -> Result<()> {
    let db = AnalyzeDb::open(&args.database, true)?;

    let params = analyze::SchedStatsParams {
        pid: args.pid,
        tid: args.tid,
        trace_id: args.trace_id,
        top_n: args.top as usize,
    };

    let result = db.sched_stats(&params)?;

    if args.format == "json" {
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(());
    }

    // Warn if no scheduling data matched the filter
    if result.summary.total_events == 0 {
        eprintln!("# Sched Stats: {}", args.database.display());
        eprintln!("# No scheduling events found for the specified filter.");
        return Ok(());
    }

    // Table output: metadata to stderr, data to stdout
    if let Some(ref detail) = result.thread_detail {
        // Per-thread view
        eprintln!("# Sched Stats: {}", args.database.display());
        eprintln!(
            "# Thread: {} (TID {}, PID {}, Process: {})",
            detail.thread_name, detail.tid, detail.pid, detail.process_name
        );
        eprintln!("# CPU time: {}", format_duration(detail.cpu_time_seconds));
        eprintln!(
            "# Uninterruptible sleep (D): {}",
            format_duration(detail.d_sleep_seconds)
        );
        eprintln!("# Events: {}", detail.event_count);
        eprintln!("# Avg slice: {}", format_us(detail.avg_slice_us));
        eprintln!("# Min slice: {}", format_us(detail.min_slice_us));
        eprintln!("# Max slice: {}", format_us(detail.max_slice_us));
        eprintln!("# CPU migrations: {}", detail.cpu_migrations);
        eprintln!("# End states:");
        for es in &detail.end_states {
            eprintln!("#   {}: {} ({:.1}%)", es.state, es.count, es.percent);
        }
    } else if let Some(ref threads) = result.threads {
        // Per-process view
        eprintln!("# Sched Stats: {}", args.database.display());
        if let Some(ref name) = result.summary.process_name {
            eprintln!("# Process: {} (PID {})", name, args.pid.unwrap_or(0));
        } else {
            eprintln!("# Process: (PID {})", args.pid.unwrap_or(0));
        }
        eprintln!(
            "# Total CPU time: {}",
            format_duration(result.summary.total_cpu_time_seconds)
        );
        eprintln!(
            "# Uninterruptible sleep (D): {}",
            format_duration(result.summary.d_sleep_seconds)
        );
        eprintln!("# Total events: {}", result.summary.total_events);
        eprintln!("# Thread count: {}", result.summary.thread_count);

        // Table header
        println!(
            "{:<8} {:<20} {:>12} {:>12} {:>8} {:>12} {:>12} {:>12} {:>8}",
            "TID",
            "Name",
            "CPU Time",
            "D Sleep",
            "Events",
            "Avg Slice",
            "Min Slice",
            "Max Slice",
            "Preempt%"
        );
        for t in threads {
            println!(
                "{:<8} {:<20} {:>12} {:>12} {:>8} {:>12} {:>12} {:>12} {:>7.1}%",
                t.tid,
                truncate_name(&t.name, 20),
                format_duration(t.cpu_time_seconds),
                format_duration(t.d_sleep_seconds),
                t.event_count,
                format_us(t.avg_slice_us),
                format_us(t.min_slice_us),
                format_us(t.max_slice_us),
                t.preempt_pct,
            );
        }
    } else if let Some(ref processes) = result.processes {
        // Whole-trace view
        eprintln!("# Sched Stats: {}", args.database.display());
        eprintln!(
            "# Trace duration: {}",
            format_duration(result.summary.trace_duration_seconds)
        );
        eprintln!("# Total sched events: {}", result.summary.total_events);
        eprintln!(
            "# Total CPU time: {}",
            format_duration(result.summary.total_cpu_time_seconds)
        );
        eprintln!(
            "# Uninterruptible sleep (D): {}",
            format_duration(result.summary.d_sleep_seconds)
        );
        eprintln!("# CPUs observed: {}", result.summary.cpus_observed);
        eprintln!("# Processes: {}", result.summary.process_count);
        eprintln!("# Threads: {}", result.summary.thread_count);

        // Table header
        println!(
            "{:<8} {:<20} {:>8} {:>12} {:>12} {:>8} {:>12} {:>8}",
            "PID", "Name", "Threads", "CPU Time", "D Sleep", "Events", "Avg Slice", "Preempt%"
        );
        for p in processes {
            println!(
                "{:<8} {:<20} {:>8} {:>12} {:>12} {:>8} {:>12} {:>7.1}%",
                p.pid,
                truncate_name(&p.name, 20),
                p.thread_count,
                format_duration(p.cpu_time_seconds),
                format_duration(p.d_sleep_seconds),
                p.event_count,
                format_us(p.avg_slice_us),
                p.preempt_pct,
            );
        }
    }

    Ok(())
}

/// Run the sched cpu-stats subcommand
fn run_sched_cpu_stats(args: SchedCpuStatsArgs) -> Result<()> {
    let db = AnalyzeDb::open(&args.database, true)?;

    let params = analyze::CpuStatsParams {
        trace_id: args.trace_id,
    };

    let result = db.cpu_stats(&params)?;

    if args.format == "json" {
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(());
    }

    // Table output: metadata to stderr, data to stdout
    eprintln!("# CPU Stats: {}", args.database.display());
    eprintln!(
        "# Trace duration: {}",
        format_duration(result.summary.trace_duration_seconds)
    );
    eprintln!("# CPUs: {}", result.summary.cpu_count);
    eprintln!(
        "# Total sched events: {}",
        result.summary.total_sched_events
    );
    eprintln!("# Note: IRQ/SoftIRQ time is stolen from scheduled tasks and included in Util%.");
    eprintln!("# Note: RQ estimates are approximate (see --format json for details).");

    // Check if any CPU has runqueue data
    let has_rq = result.cpus.iter().any(|c| c.rq_p50.is_some());

    // Table header
    if has_rq {
        println!(
            "{:>3}  {:>6}  {:>6}  {:>7}  {:>8}  {:>10}  {:>10}  {:>6}  {:>6}  {:>6}",
            "CPU",
            "Util%",
            "Idle%",
            "Threads",
            "Events",
            "IRQ Time",
            "SoftIRQ",
            "RQ p50",
            "RQ p90",
            "RQ p99"
        );
    } else {
        println!(
            "{:>3}  {:>6}  {:>6}  {:>7}  {:>8}  {:>10}  {:>10}",
            "CPU", "Util%", "Idle%", "Threads", "Events", "IRQ Time", "SoftIRQ"
        );
    }

    let fmt_rq = |v: Option<f64>| v.map(|x| format!("{x:.2}")).unwrap_or_else(|| "-".into());

    for c in &result.cpus {
        let rq_p50 = fmt_rq(c.rq_p50);
        let rq_p90 = fmt_rq(c.rq_p90);
        let rq_p99 = fmt_rq(c.rq_p99);

        if has_rq {
            println!(
                "{:>3}  {:>5.1}%  {:>5.1}%  {:>7}  {:>8}  {:>10}  {:>10}  {:>6}  {:>6}  {:>6}",
                c.cpu,
                c.utilization_pct,
                c.idle_pct,
                c.thread_count,
                c.sched_events,
                format_duration(c.irq_time_seconds),
                format_duration(c.softirq_time_seconds),
                rq_p50,
                rq_p90,
                rq_p99,
            );
        } else {
            println!(
                "{:>3}  {:>5.1}%  {:>5.1}%  {:>7}  {:>8}  {:>10}  {:>10}",
                c.cpu,
                c.utilization_pct,
                c.idle_pct,
                c.thread_count,
                c.sched_events,
                format_duration(c.irq_time_seconds),
                format_duration(c.softirq_time_seconds),
            );
        }
    }

    Ok(())
}

/// Truncate a name to fit within a column width (UTF-8 safe).
fn truncate_name(name: &str, max: usize) -> String {
    if name.len() <= max {
        name.to_string()
    } else {
        let trunc_len = max.saturating_sub(3);
        let truncated: String = name.chars().take(trunc_len).collect();
        format!("{truncated}...")
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
        Commands::Sched(args) => match args.command {
            SchedCommands::Stats(stats_args) => run_sched_stats(stats_args),
            SchedCommands::CpuStats(cpu_stats_args) => run_sched_cpu_stats(cpu_stats_args),
        },
        Commands::Mcp { database } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(systing::mcp::run_mcp_server(database))
        }
    }
}
