//! XSpace parsing and conversion to systing TPU records.
//!
//! Parses XSpace protobufs from the TPU profiler service and converts them
//! into record types suitable for writing to Parquet/DuckDB.
//!
//! Uses `crate::trace` record types directly to avoid duplicate struct definitions.

use std::collections::HashMap;

use tracing::{debug, warn};

use super::gen::xplane::{self, x_stat};
use crate::trace::{TpuCounterRecord, TpuDeviceRecord, TpuOpRecord, TpuStepRecord};

/// Parsed TPU record data ready for writing to Parquet.
///
/// All timestamps have been converted from CLOCK_REALTIME to CLOCK_BOOTTIME.
/// IDs are placeholders — final globally-unique IDs are assigned during
/// `TpuRecorder::write_records()`.
#[derive(Debug, Default)]
pub struct TpuRecordData {
    pub devices: Vec<TpuDeviceRecord>,
    pub ops: Vec<TpuOpRecord>,
    pub steps: Vec<TpuStepRecord>,
    pub counters: Vec<TpuCounterRecord>,
}

/// Well-known XPlane names from the XLA profiler.
mod plane_names {
    pub const DEVICE_PREFIX: &str = "/device:TPU:";
}

/// Well-known stat metadata names from XLA.
mod stat_names {
    pub const FLOPS: &str = "flops";
    pub const BYTES_ACCESSED: &str = "bytes_accessed";
    pub const HBM_BYTES: &str = "memory_space_hbm";
    pub const CMEM_BYTES: &str = "memory_space_cmem";
    pub const VMEM_BYTES: &str = "memory_space_vmem";
    pub const GROUP_ID: &str = "group_id";
}

/// Parse an XSpace protobuf into TPU records.
///
/// `clock_offset_ns` is the offset to apply to convert CLOCK_REALTIME timestamps
/// (from XSpace) to CLOCK_BOOTTIME (used by systing BPF events).
/// Computed as: `boottime_ns - realtime_ns` at the time of capture.
///
/// Note: Step and counter parsing is not yet implemented — the `tpu_step` and
/// `tpu_counter` tables will be empty until XSpace step-grouping and hardware
/// counter extraction logic is added.
pub fn parse_xspace(xspace: &xplane::XSpace, clock_offset_ns: i64) -> TpuRecordData {
    let mut data = TpuRecordData::default();
    let mut device_id_counter: i64 = 0;
    let mut op_id_counter: i64 = 0;

    for plane in &xspace.planes {
        if !plane.name.starts_with(plane_names::DEVICE_PREFIX) {
            debug!("Skipping non-device plane: {}", plane.name);
            continue;
        }

        let device_ordinal = plane
            .name
            .strip_prefix(plane_names::DEVICE_PREFIX)
            .and_then(|s| s.parse::<i32>().ok())
            .unwrap_or(device_id_counter as i32);

        let device_id = device_id_counter;
        device_id_counter += 1;

        let stat_name_map: HashMap<i64, &str> = plane
            .stat_metadata
            .iter()
            .map(|(&id, meta)| (id, meta.name.as_str()))
            .collect();

        let mut device = TpuDeviceRecord {
            id: device_id,
            device_ordinal,
            ..Default::default()
        };
        extract_device_metadata(plane, &stat_name_map, &mut device);

        // Set hostname from XSpace if available
        if let Some(hostname) = xspace.hostnames.first() {
            device.hostname = hostname.clone();
        }

        data.devices.push(device);

        let event_name_map: HashMap<i64, &str> = plane
            .event_metadata
            .iter()
            .map(|(&id, meta)| (id, meta.name.as_str()))
            .collect();

        for line in &plane.lines {
            let stream_name = if !line.display_name.is_empty() {
                &line.display_name
            } else {
                &line.name
            };

            let line_base_ns = line.timestamp_ns;

            for event in &line.events {
                let event_name = event_name_map
                    .get(&event.metadata_id)
                    .copied()
                    .unwrap_or("unknown");

                let category = get_event_category(plane, event.metadata_id, &stat_name_map);

                let offset_ns = match &event.data {
                    Some(xplane::x_event::Data::OffsetPs(ps)) => ps / 1000,
                    _ => 0,
                };
                let ts_realtime = line_base_ns + offset_ns;
                let ts_boottime = ts_realtime + clock_offset_ns;

                let dur_ns = event.duration_ps / 1000;

                let mut flops: i64 = 0;
                let mut bytes_accessed: i64 = 0;
                let mut bytes_hbm: i64 = 0;
                let mut bytes_cmem: i64 = 0;
                let mut bytes_vmem: i64 = 0;
                let mut group_id: Option<i64> = None;

                for stat in &event.stats {
                    let stat_name = stat_name_map.get(&stat.metadata_id).copied().unwrap_or("");
                    let value = get_stat_int_value(stat);

                    match stat_name {
                        stat_names::FLOPS => flops = value,
                        stat_names::BYTES_ACCESSED => bytes_accessed = value,
                        stat_names::HBM_BYTES => bytes_hbm = value,
                        stat_names::CMEM_BYTES => bytes_cmem = value,
                        stat_names::VMEM_BYTES => bytes_vmem = value,
                        stat_names::GROUP_ID => group_id = Some(value),
                        _ => {}
                    }
                }

                let op_id = op_id_counter;
                op_id_counter += 1;

                data.ops.push(TpuOpRecord {
                    id: op_id,
                    tpu_device_id: device_id,
                    ts: ts_boottime,
                    dur: dur_ns,
                    step_id: group_id,
                    op_name: event_name.to_string(),
                    category,
                    stream: stream_name.to_string(),
                    flops,
                    bytes_accessed,
                    bytes_hbm,
                    bytes_cmem,
                    bytes_vmem,
                });
            }
        }
    }

    if data.devices.is_empty() {
        warn!("No TPU device planes found in XSpace");
    } else {
        debug!(
            "Parsed {} devices, {} ops from XSpace",
            data.devices.len(),
            data.ops.len()
        );
    }

    data
}

/// Extract device metadata from plane-level stats.
fn extract_device_metadata(
    plane: &xplane::XPlane,
    stat_name_map: &HashMap<i64, &str>,
    device: &mut TpuDeviceRecord,
) {
    for stat in &plane.stats {
        let name = stat_name_map.get(&stat.metadata_id).copied().unwrap_or("");
        match name {
            "device_type" => {
                if let Some(x_stat::Value::StrValue(s)) = &stat.value {
                    device.device_type = s.clone();
                }
            }
            "clock_rate" => {
                device.clock_rate_ghz = get_stat_double_value(stat);
            }
            "memory_size" => {
                device.hbm_size_bytes = get_stat_int_value(stat);
            }
            "memory_bandwidth" => {
                device.hbm_bandwidth_gbps = get_stat_double_value(stat);
            }
            "chip_id" => device.chip_id = get_stat_int_value(stat) as i32,
            "core_id" => device.core_id = get_stat_int_value(stat) as i32,
            "topology_x" => device.topology_x = get_stat_int_value(stat) as i32,
            "topology_y" => device.topology_y = get_stat_int_value(stat) as i32,
            "topology_z" => device.topology_z = get_stat_int_value(stat) as i32,
            _ => {}
        }
    }
}

/// Get event category from event metadata stats.
fn get_event_category(
    plane: &xplane::XPlane,
    metadata_id: i64,
    stat_name_map: &HashMap<i64, &str>,
) -> String {
    if let Some(meta) = plane.event_metadata.get(&metadata_id) {
        for stat in &meta.stats {
            let name = stat_name_map.get(&stat.metadata_id).copied().unwrap_or("");
            if name == "hlo_category" || name == "category" {
                if let Some(x_stat::Value::StrValue(s)) = &stat.value {
                    return s.clone();
                }
            }
        }
    }
    String::new()
}

/// Extract an integer value from an XStat.
fn get_stat_int_value(stat: &xplane::XStat) -> i64 {
    match &stat.value {
        Some(x_stat::Value::Int64Value(v)) => *v,
        Some(x_stat::Value::Uint64Value(v)) => *v as i64,
        Some(x_stat::Value::DoubleValue(v)) => *v as i64,
        _ => 0,
    }
}

/// Extract a double value from an XStat.
fn get_stat_double_value(stat: &xplane::XStat) -> f64 {
    match &stat.value {
        Some(x_stat::Value::DoubleValue(v)) => *v,
        Some(x_stat::Value::Int64Value(v)) => *v as f64,
        Some(x_stat::Value::Uint64Value(v)) => *v as f64,
        _ => 0.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpu::gen::xplane::*;

    fn make_event_metadata(id: i64, name: &str) -> (i64, XEventMetadata) {
        (
            id,
            XEventMetadata {
                id,
                name: name.to_string(),
                display_name: String::new(),
                metadata: Vec::new(),
                stats: Vec::new(),
                child_id: Vec::new(),
            },
        )
    }

    #[test]
    fn test_parse_empty_xspace() {
        let xspace = XSpace::default();
        let data = parse_xspace(&xspace, 0);
        assert!(data.devices.is_empty());
        assert!(data.ops.is_empty());
    }

    #[test]
    fn test_parse_single_device_plane() {
        let xspace = XSpace {
            planes: vec![XPlane {
                id: 0,
                name: "/device:TPU:0".to_string(),
                lines: vec![XLine {
                    id: 0,
                    name: "TensorCore".to_string(),
                    display_name: String::new(),
                    display_id: 0,
                    timestamp_ns: 1_000_000_000,
                    duration_ps: 0,
                    events: vec![XEvent {
                        metadata_id: 1,
                        data: Some(x_event::Data::OffsetPs(500_000_000)),
                        duration_ps: 1_000_000_000,
                        stats: vec![],
                    }],
                }],
                event_metadata: HashMap::from([make_event_metadata(1, "fusion.0")]),
                stat_metadata: HashMap::new(),
                stats: vec![],
            }],
            errors: vec![],
            warnings: vec![],
            hostnames: vec!["tpu-host-0".to_string()],
        };

        let clock_offset = 100;
        let data = parse_xspace(&xspace, clock_offset);

        assert_eq!(data.devices.len(), 1);
        assert_eq!(data.devices[0].device_ordinal, 0);
        assert_eq!(data.devices[0].hostname, "tpu-host-0");

        assert_eq!(data.ops.len(), 1);
        let op = &data.ops[0];
        assert_eq!(op.op_name, "fusion.0");
        assert_eq!(op.stream, "TensorCore");
        assert_eq!(op.ts, 1_000_000_000 + 500_000 + 100);
        assert_eq!(op.dur, 1_000_000);
    }

    #[test]
    fn test_skips_non_device_planes() {
        let xspace = XSpace {
            planes: vec![
                XPlane {
                    name: "/host:CPU".to_string(),
                    ..Default::default()
                },
                XPlane {
                    name: "/device:TPU:0".to_string(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };

        let data = parse_xspace(&xspace, 0);
        assert_eq!(data.devices.len(), 1);
    }
}
