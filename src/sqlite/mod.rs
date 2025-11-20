/// SQLite database support for systing trace data
///
/// This module provides a simple, relational database schema for storing and querying
/// systing trace data. The design is optimized for SQL queries rather than replicating
/// Perfetto's complex interning system.
pub mod schema;
pub mod writer;

pub use schema::create_schema;

// Re-export for testing, documentation, and future use
#[allow(unused)]
pub use schema::{SCHEMA_SQL, SCHEMA_VERSION};
#[allow(unused)]
pub use writer::SqliteOutput;
