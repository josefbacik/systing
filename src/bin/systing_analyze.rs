//! systing-analyze: Query and analyze trace databases
//!
//! This tool runs SQL queries against DuckDB trace databases, supporting both
//! one-shot queries and interactive mode.

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
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

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Query {
            database,
            sql,
            format,
        } => run_query(database, sql, format),
    }
}
