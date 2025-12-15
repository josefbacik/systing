//! Shared trace data types and schemas.
//!
//! This module provides the canonical data types used by both systing (recording)
//! and systing-analyze (analysis) for trace data. By sharing these types, we ensure
//! consistency between the recording and analysis paths.
//!
//! # Module Organization
//!
//! - [`models`]: Record structs for all 19 Parquet tables
//! - [`schema`]: Arrow schema definitions matching each record type
//! - [`constants`]: Shared constants (batch sizes, regex patterns)

pub mod constants;
pub mod models;
pub mod schema;

// Re-export commonly used types
pub use models::*;
pub use schema::*;
