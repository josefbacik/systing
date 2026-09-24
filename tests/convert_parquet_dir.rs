//! `systing-util convert` on a parquet directory imports every table the
//! directory holds.
//!
//! The command had a list of tables of its own, kept beside the library's, and
//! a table added to the recorder and the library's importer was silently
//! dropped by the command: the file was known (so it was not reported as an
//! unknown file) and never read. This test writes one row of every table the
//! schema has a parquet file for, converts the directory, and expects that row
//! back, so a table missing from the command's import fails here by name.
//!
//! No root needed: the directory is made from a DuckDB file with the library's
//! own exporter, and nothing is recorded.

use std::process::Command;

use duckdb::Connection;
use systing::duckdb::{create_schema, duckdb_to_parquet, DATA_TABLES};
use tempfile::TempDir;

/// Tables in the schema that are not one parquet file of their own: `stack`
/// is interned into `frame` and `stack` (and `frame_file` is rebuilt from the
/// same file), and the heap tables are written into a database by
/// `systing-heap` and never have a parquet file.
const NOT_ONE_PARQUET_FILE: &[&str] = &[
    "stack",
    "frame",
    "frame_file",
    "heap_snapshot",
    "heap_sample",
];

#[test]
fn convert_imports_every_table_of_a_parquet_directory() {
    let tables: Vec<&str> = DATA_TABLES
        .iter()
        .copied()
        .filter(|t| !NOT_ONE_PARQUET_FILE.contains(t))
        .collect();

    let tmp = TempDir::new().unwrap();
    let source = tmp.path().join("source.duckdb");
    {
        let conn = Connection::open(&source).unwrap();
        create_schema(&conn).unwrap();
        for table in &tables {
            conn.execute_batch(&format!("INSERT INTO {table} (trace_id) VALUES ('t')"))
                .unwrap_or_else(|e| panic!("cannot insert a row into {table}: {e}"));
        }
    }
    let dir = tmp.path().join("trace");
    duckdb_to_parquet(&source, &dir, "t").unwrap();

    let converted = tmp.path().join("converted.duckdb");
    let output = Command::new(env!("CARGO_BIN_EXE_systing-util"))
        .args(["convert", "-o"])
        .arg(&converted)
        .arg(&dir)
        .output()
        .expect("failed to run systing-util convert");
    assert!(
        output.status.success(),
        "systing-util convert failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let conn = Connection::open(&converted).unwrap();
    let missing: Vec<&str> = tables
        .iter()
        .copied()
        .filter(|table| {
            let rows: i64 = conn
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
                .unwrap();
            rows != 1
        })
        .collect();
    assert!(
        missing.is_empty(),
        "the converted database has no row for these tables of the directory: {missing:?}"
    );
}
