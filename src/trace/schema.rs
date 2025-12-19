//! Arrow schema definitions for trace data.
//!
//! These schemas define the structure of Parquet files written by systing.
//!
//! # Stack Trace Schema
//!
//! Stack traces use a query-friendly schema:
//! - `stack.parquet` - Complete stacks with `frame_names[]` array
//! - `stack_sample.parquet` - Samples referencing `stack_id`
//!
//! This schema stores complete stacks as arrays with embedded module/location
//! info in each frame name string. Frame names are formatted as:
//! `function_name (module_name [file:line]) <0xaddr>`
//!
//! When converting to Perfetto format, frames and mappings are generated
//! on-the-fly by parsing module names from frame_names strings.

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
        Field::new("end_state", DataType::Int32, true),
        Field::new("priority", DataType::Int32, false),
    ]))
}

/// Schema for thread_state.parquet
///
/// The `state` field contains raw kernel task state values:
/// - 0 = TASK_RUNNING (runnable/woken)
/// - 1 = TASK_INTERRUPTIBLE (sleeping)
/// - 2 = TASK_UNINTERRUPTIBLE (disk sleep)
/// - 4 = __TASK_STOPPED
/// - 8 = __TASK_TRACED
///
/// Compound states are also possible (e.g., 130 = TASK_UNINTERRUPTIBLE | TASK_NOLOAD).
pub fn thread_state_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("ts", DataType::Int64, false),
        Field::new("dur", DataType::Int64, false),
        Field::new("utid", DataType::Int64, false),
        Field::new("state", DataType::Int32, false),
        Field::new("cpu", DataType::Int32, true),
    ]))
}

/// Schema for irq_slice.parquet
pub fn irq_slice_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("ts", DataType::Int64, false),
        Field::new("dur", DataType::Int64, false),
        Field::new("cpu", DataType::Int32, false),
        Field::new("irq", DataType::Int32, false),
        Field::new("name", DataType::Utf8, true),
        Field::new("ret", DataType::Int32, true),
    ]))
}

/// Schema for softirq_slice.parquet
pub fn softirq_slice_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("ts", DataType::Int64, false),
        Field::new("dur", DataType::Int64, false),
        Field::new("cpu", DataType::Int32, false),
        Field::new("vec", DataType::Int32, false),
    ]))
}

/// Schema for wakeup_new.parquet
pub fn wakeup_new_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("ts", DataType::Int64, false),
        Field::new("cpu", DataType::Int32, false),
        Field::new("utid", DataType::Int64, false),
        Field::new("target_cpu", DataType::Int32, false),
    ]))
}

/// Schema for process_exit.parquet
pub fn process_exit_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("ts", DataType::Int64, false),
        Field::new("cpu", DataType::Int32, false),
        Field::new("utid", DataType::Int64, false),
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
/// Stores complete stack traces with frame names denormalized into a list.
/// Frame names contain embedded module and location information in the format:
/// `function_name (module_name [file:line]) <0xaddr>`
pub fn stack_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new(
            "frame_names",
            DataType::List(Arc::new(Field::new("item", DataType::Utf8, true))),
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

/// Schema for network_syscall.parquet
///
/// Network syscall records with flattened fields for direct column access.
pub fn network_syscall_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("ts", DataType::Int64, false),
        Field::new("dur", DataType::Int64, false),
        Field::new("tid", DataType::Int32, false),
        Field::new("pid", DataType::Int32, false),
        Field::new("event_type", DataType::Utf8, false),
        Field::new("socket_id", DataType::Int64, false),
        Field::new("bytes", DataType::Int64, false),
        Field::new("seq", DataType::Int64, true),
        Field::new("sndbuf_used", DataType::Int64, true),
        Field::new("sndbuf_limit", DataType::Int64, true),
        Field::new("sndbuf_fill_pct", DataType::Int16, true),
        Field::new("recv_seq_start", DataType::Int64, true),
        Field::new("recv_seq_end", DataType::Int64, true),
        Field::new("rcv_nxt", DataType::Int64, true),
        Field::new("bytes_available", DataType::Int64, true),
    ]))
}

/// Schema for network_packet.parquet
///
/// Network packet records with flattened fields for all event types.
pub fn network_packet_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("ts", DataType::Int64, false),
        Field::new("socket_id", DataType::Int64, false),
        Field::new("event_type", DataType::Utf8, false),
        Field::new("seq", DataType::Int64, true),
        Field::new("length", DataType::Int32, false),
        Field::new("tcp_flags", DataType::Utf8, true),
        // Send buffer fields
        Field::new("sndbuf_used", DataType::Int64, true),
        Field::new("sndbuf_limit", DataType::Int64, true),
        Field::new("sndbuf_fill_pct", DataType::Int16, true),
        // Retransmit fields
        Field::new("is_retransmit", DataType::Boolean, false),
        Field::new("retransmit_count", DataType::Int16, true),
        Field::new("rto_ms", DataType::Int32, true),
        Field::new("srtt_ms", DataType::Int32, true),
        Field::new("rttvar_us", DataType::Int32, true),
        Field::new("backoff", DataType::Int16, true),
        // Zero window fields
        Field::new("is_zero_window_probe", DataType::Boolean, false),
        Field::new("is_zero_window_ack", DataType::Boolean, false),
        Field::new("probe_count", DataType::Int16, true),
        // Window fields
        Field::new("snd_wnd", DataType::Int32, true),
        Field::new("rcv_wnd", DataType::Int32, true),
        Field::new("rcv_buf_used", DataType::Int64, true),
        Field::new("rcv_buf_limit", DataType::Int64, true),
        Field::new("window_clamp", DataType::Int32, true),
        Field::new("rcv_wscale", DataType::Int16, true),
        // Timer fields
        Field::new("icsk_pending", DataType::Int16, true),
        Field::new("icsk_timeout", DataType::Int64, true),
        // Drop fields
        Field::new("drop_reason", DataType::Int32, true),
        Field::new("drop_reason_str", DataType::Utf8, true),
        Field::new("drop_location", DataType::Int64, true),
        // Queue fields
        Field::new("qlen", DataType::Int32, true),
        Field::new("qlen_limit", DataType::Int32, true),
        // TSQ fields
        Field::new("sk_wmem_alloc", DataType::Int64, true),
        Field::new("tsq_limit", DataType::Int64, true),
        // TX queue fields
        Field::new("txq_state", DataType::Int32, true),
        Field::new("qdisc_state", DataType::Int32, true),
        Field::new("qdisc_backlog", DataType::Int64, true),
        // SKB correlation
        Field::new("skb_addr", DataType::Int64, true),
        Field::new("qdisc_latency_us", DataType::Int32, true),
    ]))
}

/// Schema for network_socket.parquet
///
/// Network socket metadata records.
pub fn network_socket_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("socket_id", DataType::Int64, false),
        Field::new("protocol", DataType::Utf8, false),
        Field::new("address_family", DataType::Utf8, false),
        Field::new("src_ip", DataType::Utf8, false),
        Field::new("src_port", DataType::Int32, false),
        Field::new("dest_ip", DataType::Utf8, false),
        Field::new("dest_port", DataType::Int32, false),
        Field::new("first_seen_ts", DataType::Int64, true),
        Field::new("last_seen_ts", DataType::Int64, true),
    ]))
}

/// Schema for network_poll.parquet
///
/// Network poll event records.
pub fn network_poll_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("ts", DataType::Int64, false),
        Field::new("tid", DataType::Int32, false),
        Field::new("pid", DataType::Int32, false),
        Field::new("socket_id", DataType::Int64, false),
        Field::new("requested_events", DataType::Utf8, false),
        Field::new("returned_events", DataType::Utf8, false),
    ]))
}
