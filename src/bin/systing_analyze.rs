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
        Commands::Mcp { database } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(systing::mcp::run_mcp_server(database))
        }
    }
}
