//! Arrow schema definitions for trace data.
//!
//! These schemas define the structure of Parquet files written by systing
//! and read by systing-analyze.
//!
//! # Stack Trace Schemas
//!
//! There are two parallel schemas for stack trace data:
//!
//! ## Legacy Schema (Perfetto-compatible)
//! - `callsite.parquet` - Linked-list of callsites with `parent_id` chains
//! - `perf_sample.parquet` - Samples referencing leaf `callsite_id`
//!
//! This schema mirrors Perfetto's internal representation and requires recursive
//! CTEs to reconstruct full stack traces for queries.
//!
//! ## Query-Friendly Schema (New)
//! - `stack.parquet` - Complete stacks with `frame_names[]` and `frame_ids[]` arrays
//! - `stack_sample.parquet` - Samples referencing `stack_id`
//!
//! This schema stores complete stacks as arrays, enabling simple JOINs and
//! `list_contains()` queries without recursive CTEs.
//!
//! ## Usage
//! - The `--parquet-first` flag uses the new query-friendly schema
//! - The default Perfetto path still generates the legacy schema
//! - When converting new schema to Perfetto format, callsite chains are
//!   reconstructed on-the-fly from the `frame_ids` arrays

use std::sync::Arc;

use arrow::datatypes::{DataType, Field, Schema};

/// Schema for process.parquet
pub fn process_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("upid", DataType::Int64, false),
        Field::new("pid", DataType::Int32, false),
        Field::new("name", DataType::Utf8, true),
        Field::new("parent_upid", DataType::Int64, true),
    ]))
}

/// Schema for thread.parquet
pub fn thread_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("utid", DataType::Int64, false),
        Field::new("tid", DataType::Int32, false),
        Field::new("name", DataType::Utf8, true),
        Field::new("upid", DataType::Int64, true),
    ]))
}

/// Schema for sched_slice.parquet
pub fn sched_slice_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("ts", DataType::Int64, false),
        Field::new("dur", DataType::Int64, false),
        Field::new("cpu", DataType::Int32, false),
        Field::new("utid", DataType::Int64, false),
        Field::new("end_state", DataType::Utf8, true),
        Field::new("priority", DataType::Int32, false),
    ]))
}

/// Schema for thread_state.parquet
pub fn thread_state_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("ts", DataType::Int64, false),
        Field::new("dur", DataType::Int64, false),
        Field::new("utid", DataType::Int64, false),
        Field::new("state", DataType::Utf8, false),
        Field::new("cpu", DataType::Int32, true),
    ]))
}

/// Schema for counter.parquet
pub fn counter_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("ts", DataType::Int64, false),
        Field::new("track_id", DataType::Int64, false),
        Field::new("value", DataType::Float64, false),
    ]))
}

/// Schema for counter_track.parquet
pub fn counter_track_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("name", DataType::Utf8, false),
        Field::new("unit", DataType::Utf8, true),
    ]))
}

/// Schema for slice.parquet
pub fn slice_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("ts", DataType::Int64, false),
        Field::new("dur", DataType::Int64, false),
        Field::new("track_id", DataType::Int64, false),
        Field::new("utid", DataType::Int64, true),
        Field::new("name", DataType::Utf8, false),
        Field::new("category", DataType::Utf8, true),
        Field::new("depth", DataType::Int32, false),
    ]))
}

/// Schema for track.parquet
pub fn track_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("name", DataType::Utf8, false),
        Field::new("parent_id", DataType::Int64, true),
    ]))
}

/// Schema for instant.parquet
pub fn instant_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("ts", DataType::Int64, false),
        Field::new("track_id", DataType::Int64, false),
        Field::new("utid", DataType::Int64, true),
        Field::new("name", DataType::Utf8, false),
        Field::new("category", DataType::Utf8, true),
    ]))
}

/// Schema for args.parquet
pub fn args_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("slice_id", DataType::Int64, false),
        Field::new("key", DataType::Utf8, false),
        Field::new("int_value", DataType::Int64, true),
        Field::new("string_value", DataType::Utf8, true),
        Field::new("real_value", DataType::Float64, true),
    ]))
}

/// Schema for instant_args.parquet
pub fn instant_args_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("instant_id", DataType::Int64, false),
        Field::new("key", DataType::Utf8, false),
        Field::new("int_value", DataType::Int64, true),
        Field::new("string_value", DataType::Utf8, true),
        Field::new("real_value", DataType::Float64, true),
    ]))
}

/// Schema for perf_sample.parquet
pub fn perf_sample_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("ts", DataType::Int64, false),
        Field::new("utid", DataType::Int64, false),
        Field::new("callsite_id", DataType::Int64, true),
        Field::new("cpu", DataType::Int32, true),
    ]))
}

/// Schema for symbol.parquet
pub fn symbol_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("name", DataType::Utf8, false),
    ]))
}

/// Schema for frame.parquet
/// module_name stored directly on frame (from blazesym Sym.module).
pub fn frame_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("name", DataType::Utf8, true),
        Field::new("module_name", DataType::Utf8, true),
        Field::new("symbol_id", DataType::Int64, true),
    ]))
}

/// Schema for callsite.parquet
pub fn callsite_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("parent_id", DataType::Int64, true),
        Field::new("frame_id", DataType::Int64, false),
        Field::new("depth", DataType::Int32, false),
    ]))
}

/// Schema for network_interface.parquet
pub fn network_interface_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("namespace", DataType::Utf8, false),
        Field::new("interface_name", DataType::Utf8, false),
        Field::new("ip_address", DataType::Utf8, false),
        Field::new("address_type", DataType::Utf8, false),
    ]))
}

/// Schema for socket_connection.parquet
pub fn socket_connection_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("socket_id", DataType::Int64, false),
        Field::new("track_id", DataType::Int64, false),
        Field::new("protocol", DataType::Utf8, false),
        Field::new("src_ip", DataType::Utf8, false),
        Field::new("src_port", DataType::Int32, false),
        Field::new("dest_ip", DataType::Utf8, false),
        Field::new("dest_port", DataType::Int32, false),
        Field::new("address_family", DataType::Utf8, false),
    ]))
}

/// Schema for clock_snapshot.parquet
pub fn clock_snapshot_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("clock_id", DataType::Int32, false),
        Field::new("clock_name", DataType::Utf8, false),
        Field::new("timestamp_ns", DataType::Int64, false),
        Field::new("is_primary", DataType::Boolean, false),
    ]))
}

/// Schema for stack.parquet
///
/// Stores complete stack traces with frame information denormalized into lists.
pub fn stack_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new(
            "frame_names",
            DataType::List(Arc::new(Field::new("item", DataType::Utf8, true))),
            false,
        ),
        Field::new(
            "frame_ids",
            DataType::List(Arc::new(Field::new("item", DataType::Int64, true))),
            false,
        ),
        Field::new("depth", DataType::Int32, false),
        Field::new("leaf_name", DataType::Utf8, false),
    ]))
}

/// Schema for stack_sample.parquet
///
/// Links perf samples to stack traces.
pub fn stack_sample_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("ts", DataType::Int64, false),
        Field::new("utid", DataType::Int64, false),
        Field::new("cpu", DataType::Int32, true),
        Field::new("stack_id", DataType::Int64, false),
    ]))
}
