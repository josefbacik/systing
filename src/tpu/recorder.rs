//! TPU profiling recorder.
//!
//! Follows the MarkerRecorder pattern: captures TPU profiling data via gRPC,
//! buffers parsed records in memory, and writes them during `generate_parquet_trace`
//! finalization.

use anyhow::{Context, Result};
use tracing::{error, info};

use crate::record::RecordCollector;
use crate::tpu::client::TpuProfilerClient;
use crate::tpu::xspace::{self, TpuRecordData};
use crate::trace::{TpuCounterRecord, TpuDeviceRecord, TpuOpRecord, TpuStepRecord};

/// TPU profiling recorder.
///
/// Created with a target service address (discovered or user-specified) and
/// the desired profiling duration. Runs `capture()` in a dedicated thread,
/// then `write_records()` is called during `generate_parquet_trace` with the
/// shared ID counters.
pub struct TpuRecorder {
    service_addr: String,
    duration_ms: u64,
    records: Option<TpuRecordData>,
}

impl TpuRecorder {
    pub fn new(service_addr: String, duration_ms: u64) -> Self {
        Self {
            service_addr,
            duration_ms,
            records: None,
        }
    }

    /// Capture TPU profiling data. This is a blocking call that:
    /// 1. Records CLOCK_BOOTTIME and CLOCK_REALTIME for timestamp conversion
    /// 2. Connects to the TPU profiler service via gRPC
    /// 3. Captures a profile for the configured duration
    /// 4. Parses the XSpace response into TPU records
    ///
    /// Call this from a dedicated thread.
    pub fn capture(&mut self) -> Result<()> {
        info!(
            "Starting TPU profile capture from {} for {}ms",
            self.service_addr, self.duration_ms
        );

        let clock_offset_ns = compute_clock_offset()?;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("Failed to create tokio runtime for TPU profiling")?;

        let client = TpuProfilerClient::new(self.service_addr.clone());

        let xspace = rt
            .block_on(client.capture_profile(self.duration_ms))
            .context("TPU profile capture failed")?;

        let data = xspace::parse_xspace(&xspace, clock_offset_ns);

        info!(
            "TPU profile captured: {} devices, {} ops, {} steps, {} counters",
            data.devices.len(),
            data.ops.len(),
            data.steps.len(),
            data.counters.len()
        );

        self.records = Some(data);
        Ok(())
    }

    /// Write TPU records to the collector during `generate_parquet_trace`.
    ///
    /// Uses the shared ID counter to assign globally unique IDs.
    /// Returns `Ok(())` even if no TPU data was captured.
    pub fn write_records(
        &self,
        collector: &mut dyn RecordCollector,
        id_counter: &mut i64,
    ) -> Result<()> {
        let records = match &self.records {
            Some(r) => r,
            None => return Ok(()),
        };

        if records.devices.is_empty() && records.ops.is_empty() {
            return Ok(());
        }

        let mut device_id_map: std::collections::HashMap<i64, i64> =
            std::collections::HashMap::new();

        for device in &records.devices {
            let final_id = *id_counter;
            *id_counter += 1;
            device_id_map.insert(device.id, final_id);

            collector.add_tpu_device(TpuDeviceRecord {
                id: final_id,
                ..device.clone()
            })?;
        }

        let mut step_id_map: std::collections::HashMap<i64, i64> = std::collections::HashMap::new();
        for step in &records.steps {
            let final_id = *id_counter;
            *id_counter += 1;
            step_id_map.insert(step.id, final_id);
            let final_device_id = device_id_map.get(&step.tpu_device_id).copied().unwrap_or(0);

            collector.add_tpu_step(TpuStepRecord {
                id: final_id,
                tpu_device_id: final_device_id,
                ..step.clone()
            })?;
        }

        for op in &records.ops {
            let final_id = *id_counter;
            *id_counter += 1;
            let final_device_id = device_id_map.get(&op.tpu_device_id).copied().unwrap_or(0);
            let final_step_id = op.step_id.and_then(|sid| step_id_map.get(&sid).copied());

            collector.add_tpu_op(TpuOpRecord {
                id: final_id,
                tpu_device_id: final_device_id,
                step_id: final_step_id,
                ..op.clone()
            })?;
        }

        for counter in &records.counters {
            let final_id = *id_counter;
            *id_counter += 1;
            let final_device_id = device_id_map
                .get(&counter.tpu_device_id)
                .copied()
                .unwrap_or(0);
            let final_step_id = counter
                .step_id
                .and_then(|sid| step_id_map.get(&sid).copied());

            collector.add_tpu_counter(TpuCounterRecord {
                id: final_id,
                tpu_device_id: final_device_id,
                step_id: final_step_id,
                ..counter.clone()
            })?;
        }

        Ok(())
    }
}

/// Compute the offset from CLOCK_REALTIME to CLOCK_BOOTTIME.
///
/// Returns `boottime_ns - realtime_ns`. Add this to any CLOCK_REALTIME timestamp
/// to convert it to CLOCK_BOOTTIME.
fn compute_clock_offset() -> Result<i64> {
    let mut boottime = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let mut realtime = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };

    // SAFETY: boottime and realtime are valid, mutable libc::timespec pointers.
    // CLOCK_BOOTTIME and CLOCK_REALTIME are valid clock IDs on Linux.
    unsafe {
        if libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut boottime) != 0 {
            anyhow::bail!("clock_gettime(CLOCK_BOOTTIME) failed");
        }
        if libc::clock_gettime(libc::CLOCK_REALTIME, &mut realtime) != 0 {
            anyhow::bail!("clock_gettime(CLOCK_REALTIME) failed");
        }
    }

    let boottime_ns = boottime.tv_sec * 1_000_000_000 + boottime.tv_nsec;
    let realtime_ns = realtime.tv_sec * 1_000_000_000 + realtime.tv_nsec;

    Ok(boottime_ns - realtime_ns)
}

/// Spawn the TPU recording thread.
///
/// Returns a join handle that yields the TpuRecorder (with captured data) on success.
pub fn spawn_tpu_thread(
    service_addr: String,
    duration_ms: u64,
) -> Result<std::thread::JoinHandle<Result<TpuRecorder>>> {
    std::thread::Builder::new()
        .name("tpu-profiler".to_string())
        .spawn(move || {
            let mut recorder = TpuRecorder::new(service_addr, duration_ms);
            match recorder.capture() {
                Ok(()) => Ok(recorder),
                Err(e) => {
                    error!("TPU profile capture failed: {:#}", e);
                    Err(e)
                }
            }
        })
        .context("Failed to spawn TPU profiler thread")
}
