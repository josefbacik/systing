//! Trace format conversion utilities
//!
//! This module provides functionality for converting between different trace formats,
//! such as Perfetto protobuf traces and SQLite databases.

mod perfetto_to_sqlite;
mod sqlite_to_perfetto;

pub use perfetto_to_sqlite::convert_perfetto_to_sqlite;
pub use sqlite_to_perfetto::convert_sqlite_to_perfetto;
