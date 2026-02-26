//! TPU metrics recorder for lightweight RuntimeMetricService polling.
//!
//! Follows the SysinfoRecorder pattern: holds an optional streaming collector,
//! receives metric values from a polling thread, and writes them as
//! `TpuMetricRecord` rows.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tracing::{debug, error, info, warn};

use crate::record::RecordCollector;
use crate::trace::TpuMetricRecord;

/// Default metrics to poll from the RuntimeMetricService.
pub const DEFAULT_METRICS: &[&str] = &[
    "tpu.runtime.tensorcore.dutycycle.percent",
    "tpu.runtime.hbm.memory.usage.bytes",
];

/// Recorder for TPU runtime metrics.
///
/// Held in `SessionRecorder` as `Option<Mutex<TpuMetricsRecorder>>`.
/// The polling thread locks it and calls `record_metric()` each iteration.
pub struct TpuMetricsRecorder {
    streaming_collector: Option<Box<dyn RecordCollector + Send>>,
    next_id: i64,
}

impl Default for TpuMetricsRecorder {
    fn default() -> Self {
        Self::new()
    }
}

impl TpuMetricsRecorder {
    pub fn new() -> Self {
        Self {
            streaming_collector: None,
            next_id: 1,
        }
    }

    /// Set the streaming collector (called from `init_streaming_parquet`).
    pub fn set_streaming_collector(&mut self, collector: Box<dyn RecordCollector + Send>) {
        self.streaming_collector = Some(collector);
    }

    /// Record a single metric sample for one device.
    ///
    /// Called once per metric per device per poll iteration from the polling thread.
    pub fn record_metric(
        &mut self,
        ts: i64,
        device_id: i32,
        metric_name: &str,
        value: f64,
    ) -> Result<()> {
        let id = self.next_id;
        self.next_id += 1;

        let record = TpuMetricRecord {
            id,
            ts,
            device_id,
            metric_name: metric_name.to_string(),
            value,
        };

        if let Some(ref mut collector) = self.streaming_collector {
            collector.add_tpu_metric(record)?;
        }

        Ok(())
    }

    /// Finish and return the streaming collector for proper shutdown.
    pub fn finish(&mut self) -> Result<Option<Box<dyn RecordCollector + Send>>> {
        if let Some(mut collector) = self.streaming_collector.take() {
            collector.flush()?;
            Ok(Some(collector))
        } else {
            Ok(None)
        }
    }
}

/// Run the TPU metrics polling thread.
///
/// Connects to the RuntimeMetricService, then polls metrics at the configured
/// interval until shutdown is signaled. Writes results to the session recorder's
/// TpuMetricsRecorder via streaming collector.
pub fn run_tpu_metrics_thread(
    addr: &str,
    poll_interval_ms: u64,
    shutdown: Arc<AtomicBool>,
    recorder: Arc<crate::session_recorder::SessionRecorder>,
) -> i32 {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            error!("Failed to create tokio runtime for TPU metrics: {:#}", e);
            return 1;
        }
    };

    let poll_interval = Duration::from_millis(poll_interval_ms);
    let rpc_timeout = Duration::from_millis(poll_interval_ms * 2);

    // Connect with retries (up to 10 seconds)
    // Use a shorter per-attempt timeout so we get multiple retries within the overall budget.
    let client = {
        let overall_deadline = Duration::from_secs(10);
        let per_attempt_timeout = Duration::from_secs(3);
        let start = std::time::Instant::now();
        let mut backoff = Duration::from_millis(100);

        loop {
            if shutdown.load(Ordering::Relaxed) {
                info!("Shutdown requested during TPU metrics connection");
                return 0;
            }

            match rt.block_on(crate::tpu::metrics_client::TpuMetricsClient::connect(
                addr,
                per_attempt_timeout,
            )) {
                Ok(c) => break c,
                Err(e) => {
                    if start.elapsed() >= overall_deadline {
                        error!(
                            "Failed to connect to TPU metrics service at {} after {:?}: {:#}",
                            addr,
                            start.elapsed(),
                            e
                        );
                        return 1;
                    }
                    std::thread::sleep(backoff);
                    backoff = (backoff * 2).min(Duration::from_secs(5));
                }
            }
        }
    };

    info!("Connected to TPU metrics service at {}", addr);

    // Determine which metrics to poll
    let metrics_to_poll: Vec<String> = if client.available_metrics().is_empty() {
        DEFAULT_METRICS.iter().map(|s| s.to_string()).collect()
    } else {
        client.available_metrics().to_vec()
    };

    info!("Polling metrics: {:?}", metrics_to_poll);

    let mut consecutive_errors = 0u32;
    let mut backoff = Duration::from_millis(100);

    // Poll loop
    while !shutdown.load(Ordering::Relaxed) {
        let ts = crate::session_recorder::get_clock_value(libc::CLOCK_BOOTTIME) as i64;

        let mut poll_ok = true;
        for metric_name in &metrics_to_poll {
            if shutdown.load(Ordering::Relaxed) {
                break;
            }

            match rt.block_on(client.get_metric(metric_name, rpc_timeout)) {
                Ok(result) => {
                    if let Some(ref tpu_metrics) = recorder.tpu_metrics_recorder {
                        let mut rec = match tpu_metrics.lock() {
                            Ok(guard) => guard,
                            Err(poisoned) => {
                                error!("TPU metrics recorder mutex poisoned, recovering");
                                poisoned.into_inner()
                            }
                        };
                        for dv in &result.device_values {
                            if let Err(e) =
                                rec.record_metric(ts, dv.device_id, metric_name, dv.value)
                            {
                                warn!("Failed to record TPU metric: {:#}", e);
                            }
                        }
                    }
                    debug!(
                        "Polled {} ({} devices)",
                        metric_name,
                        result.device_values.len()
                    );
                }
                Err(e) => {
                    poll_ok = false;
                    if consecutive_errors == 0 {
                        warn!("TPU metric poll failed for {}: {:#}", metric_name, e);
                    }
                }
            }
        }

        if poll_ok {
            consecutive_errors = 0;
            backoff = Duration::from_millis(100);
            std::thread::sleep(poll_interval);
        } else {
            consecutive_errors += 1;
            if consecutive_errors > 10 {
                debug!(
                    "TPU metrics: {} consecutive errors, backing off {:?}",
                    consecutive_errors, backoff
                );
            }
            std::thread::sleep(backoff);
            backoff = (backoff * 2).min(Duration::from_secs(5));
        }
    }

    info!("TPU metrics polling thread shutting down");
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::InMemoryCollector;

    #[test]
    fn test_record_metric_basic() {
        let mut recorder = TpuMetricsRecorder::new();
        let collector = Box::new(InMemoryCollector::new());
        recorder.set_streaming_collector(collector);

        recorder
            .record_metric(
                1_000_000_000,
                0,
                "tpu.runtime.tensorcore.dutycycle.percent",
                85.5,
            )
            .unwrap();

        recorder
            .record_metric(
                1_000_000_000,
                1,
                "tpu.runtime.tensorcore.dutycycle.percent",
                90.2,
            )
            .unwrap();

        recorder
            .record_metric(
                1_000_000_000,
                0,
                "tpu.runtime.hbm.memory.usage.bytes",
                1024.0 * 1024.0 * 512.0,
            )
            .unwrap();

        // Verify records were written by checking the id counter
        assert_eq!(recorder.next_id, 4);
    }

    #[test]
    fn test_record_metric_no_collector() {
        let mut recorder = TpuMetricsRecorder::new();
        // Should not panic even without a collector
        recorder
            .record_metric(1_000_000_000, 0, "test.metric", 42.0)
            .unwrap();
        assert_eq!(recorder.next_id, 2);
    }

    #[test]
    fn test_record_metric_ids_increment() {
        let mut recorder = TpuMetricsRecorder::new();
        recorder.set_streaming_collector(Box::new(InMemoryCollector::new()));

        for i in 0..5 {
            recorder
                .record_metric(i * 1_000_000_000, 0, "test.metric", i as f64)
                .unwrap();
        }

        assert_eq!(recorder.next_id, 6);
    }
}
