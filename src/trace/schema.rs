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
        Field::new(
            "cmdline",
            DataType::List(Arc::new(Field::new("item", DataType::Utf8, true))),
            false,
        ),
        Field::new("is_kernel_thread", DataType::Boolean, false),
        Field::new("cgroup_id", DataType::UInt64, false),
        Field::new("cgroup_path", DataType::Utf8, true),
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

/// Schema for sched_migrate.parquet
pub fn sched_migrate_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("ts", DataType::Int64, false),
        Field::new("utid", DataType::Int64, false),
        Field::new("orig_cpu", DataType::Int32, false),
        Field::new("dest_cpu", DataType::Int32, false),
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
        Field::new("netns_inum", DataType::Int64, false),
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

/// Schema for sysinfo.parquet
pub fn sysinfo_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("sysname", DataType::Utf8, false),
        Field::new("release", DataType::Utf8, false),
        Field::new("version", DataType::Utf8, false),
        Field::new("machine", DataType::Utf8, false),
        Field::new("cpufreq_driver", DataType::Utf8, true),
        Field::new("hypervisor", DataType::Utf8, true),
        Field::new("sys_vendor", DataType::Utf8, true),
        Field::new("product_name", DataType::Utf8, true),
        Field::new("sample_event", DataType::Utf8, true),
        Field::new("sample_period", DataType::Int64, true),
        Field::new("memory_fault_leg", DataType::Utf8, true),
        Field::new("memory_fault_sample_rate", DataType::Int64, true),
        Field::new("memory_map_sample_rate", DataType::Int64, true),
        Field::new("memory_alloc_sample_rate", DataType::Int64, true),
        Field::new("memory_vfio_leg", DataType::Utf8, true),
        Field::new("memory_thp_leg", DataType::Utf8, true),
        Field::new("memory_thp_sample_rate", DataType::Int64, true),
        Field::new("memory_iommu_overflow", DataType::Int64, true),
        Field::new("memory_anon_huge_walk", DataType::Utf8, true),
        Field::new("memory_syscall_leg", DataType::Utf8, true),
        Field::new("network_tw_leg", DataType::Utf8, true),
    ]))
}

/// Schema for cpu_info.parquet
///
/// Per-CPU static frequency limits (kHz) from sysfs cpufreq. Empty on systems
/// without cpufreq support.
pub fn cpu_info_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("cpu", DataType::Int32, false),
        Field::new("min_freq_khz", DataType::Int64, true),
        Field::new("max_freq_khz", DataType::Int64, true),
        Field::new("base_freq_khz", DataType::Int64, true),
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
///
/// The `stack_event_type` field indicates when the stack was captured:
/// - 0 = STACK_SLEEP_UNINTERRUPTIBLE: Captured when task went to uninterruptible sleep
/// - 1 = STACK_RUNNING: Captured while task was running (CPU sampling, probes)
/// - 2 = STACK_SLEEP_INTERRUPTIBLE: Captured when task went to interruptible sleep
pub fn stack_sample_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("ts", DataType::Int64, false),
        Field::new("utid", DataType::Int64, false),
        Field::new("cpu", DataType::Int32, true),
        Field::new("stack_id", DataType::Int64, false),
        Field::new("stack_event_type", DataType::Int8, false),
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
        Field::new("utid", DataType::Int64, false),
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
        // TCP state change fields
        Field::new("old_state", DataType::Int16, true),
        Field::new("old_state_str", DataType::Utf8, true),
        Field::new("new_state", DataType::Int16, true),
        Field::new("new_state_str", DataType::Utf8, true),
    ]))
}

/// Schema for network_socket.parquet
///
/// Network socket metadata records.
pub fn network_socket_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("socket_id", DataType::Int64, false),
        Field::new("netns_inum", DataType::Int64, false),
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
        Field::new("utid", DataType::Int64, false),
        Field::new("socket_id", DataType::Int64, false),
        Field::new("requested_events", DataType::Utf8, false),
        Field::new("returned_events", DataType::Utf8, false),
    ]))
}

/// Schema for network_dns.parquet
///
/// DNS resolution records mapping IP addresses to hostnames.
pub fn network_dns_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("ip_address", DataType::Utf8, false),
        Field::new("hostname", DataType::Utf8, false),
    ]))
}

/// Schema for memory_rss.parquet
pub fn memory_rss_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("ts", DataType::Int64, false),
        Field::new("utid", DataType::Int64, false),
        Field::new("member", DataType::Int8, false),
        Field::new("size", DataType::Int64, false),
        Field::new("external", DataType::Boolean, false),
    ]))
}

/// Schema for memory_map.parquet
pub fn memory_map_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("ts", DataType::Int64, false),
        Field::new("utid", DataType::Int64, false),
        Field::new("event_type", DataType::Utf8, false),
        Field::new("addr", DataType::Int64, false),
        Field::new("size", DataType::Int64, false),
        Field::new("rss_delta_bytes", DataType::Int64, true),
        Field::new("prot", DataType::Int32, true),
        Field::new("flags", DataType::Int32, true),
        Field::new("stack_id", DataType::Int64, true),
    ]))
}

/// Schema for memory_fault.parquet
pub fn memory_fault_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("ts", DataType::Int64, false),
        Field::new("utid", DataType::Int64, false),
        Field::new("addr", DataType::Int64, false),
        Field::new("error_code", DataType::Int32, false),
        Field::new("stack_id", DataType::Int64, true),
    ]))
}

/// Schema for memory_alloc.parquet
pub fn memory_alloc_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("ts", DataType::Int64, false),
        Field::new("utid", DataType::Int64, false),
        Field::new("op", DataType::Utf8, false),
        Field::new("addr", DataType::Int64, false),
        Field::new("size", DataType::Int64, false),
        Field::new("old_addr", DataType::Int64, true),
        Field::new("stack_id", DataType::Int64, true),
    ]))
}

/// Schema for memory_vfio.parquet
pub fn memory_vfio_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("ts", DataType::Int64, false),
        Field::new("utid", DataType::Int64, false),
        Field::new("op", DataType::Utf8, false),
        Field::new("iova", DataType::Int64, false),
        Field::new("vaddr", DataType::Int64, true),
        Field::new("size", DataType::Int64, false),
        Field::new("flags", DataType::Int32, false),
        Field::new("stack_id", DataType::Int64, true),
    ]))
}

/// Schema for memory_iommu.parquet
pub fn memory_iommu_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("ts", DataType::Int64, false),
        Field::new("utid", DataType::Int64, false),
        Field::new("op", DataType::Utf8, false),
        Field::new("iova_gib", DataType::Int64, false),
        Field::new("size_order", DataType::Int32, false),
        Field::new("count", DataType::Int64, false),
        Field::new("bytes", DataType::Int64, false),
    ]))
}

/// Schema for memory_thp.parquet
pub fn memory_thp_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("ts", DataType::Int64, false),
        Field::new("utid", DataType::Int64, false),
        Field::new("kind", DataType::Utf8, false),
        Field::new("addr", DataType::Int64, true),
        Field::new("result", DataType::Int32, false),
        Field::new("stack_id", DataType::Int64, true),
    ]))
}

/// Schema for memory_vmstat.parquet
pub fn memory_vmstat_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("name", DataType::Utf8, false),
        Field::new("ts_start", DataType::Int64, false),
        Field::new("value_start", DataType::Int64, false),
        Field::new("ts_end", DataType::Int64, false),
        Field::new("value_end", DataType::Int64, false),
    ]))
}

// TPU profiling schemas

/// Schema for tpu_device.parquet
pub fn tpu_device_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("device_ordinal", DataType::Int32, false),
        Field::new("chip_id", DataType::Int32, false),
        Field::new("core_id", DataType::Int32, false),
        Field::new("hostname", DataType::Utf8, false),
        Field::new("device_type", DataType::Utf8, false),
        Field::new("topology_x", DataType::Int32, false),
        Field::new("topology_y", DataType::Int32, false),
        Field::new("topology_z", DataType::Int32, false),
        Field::new("clock_rate_ghz", DataType::Float64, false),
        Field::new("hbm_size_bytes", DataType::Int64, false),
        Field::new("hbm_bandwidth_gbps", DataType::Float64, false),
    ]))
}

/// Schema for tpu_op.parquet
pub fn tpu_op_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("tpu_device_id", DataType::Int64, false),
        Field::new("ts", DataType::Int64, false),
        Field::new("dur", DataType::Int64, false),
        Field::new("group_id", DataType::Int64, true),
        Field::new("op_name", DataType::Utf8, false),
        Field::new("category", DataType::Utf8, false),
        Field::new("stream", DataType::Utf8, false),
        Field::new("flops", DataType::Int64, false),
        Field::new("bytes_accessed", DataType::Int64, false),
        Field::new("bytes_hbm", DataType::Int64, false),
        Field::new("bytes_cmem", DataType::Int64, false),
        Field::new("bytes_vmem", DataType::Int64, false),
    ]))
}

/// Schema for tpu_metric.parquet
pub fn tpu_metric_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("ts", DataType::Int64, false),
        Field::new("device_id", DataType::Int32, false),
        Field::new("metric_name", DataType::Utf8, false),
        Field::new("value", DataType::Float64, false),
    ]))
}
