//! gRPC client for the TPU RuntimeMetricService.
//!
//! Uses pre-generated prost types from `gen/tpu_metric_service.rs` for type-safe
//! metric request/response handling.

use std::time::Duration;

use anyhow::{Context, Result};
use tonic::transport::Channel;
use tracing::{debug, info, warn};

use super::gen::tpu_metric_service::{
    self, Gauge, ListSupportedMetricsRequest, MetricRequest, MetricResponse,
    RuntimeMetricServiceClient,
};

/// A single metric value for one device.
#[derive(Debug, Clone)]
pub struct DeviceMetricValue {
    pub device_id: i32,
    pub value: f64,
}

/// Client for the TPU RuntimeMetricService.
pub struct TpuMetricsClient {
    client: RuntimeMetricServiceClient<Channel>,
    /// Metrics available from the service.
    available_metrics: Vec<String>,
}

impl TpuMetricsClient {
    /// Connect to the RuntimeMetricService and discover available metrics.
    pub async fn connect(addr: &str, timeout: Duration) -> Result<Self> {
        let endpoint = format!("http://{}", addr);
        info!("Connecting to TPU metrics service at {}", endpoint);

        let channel = Channel::from_shared(endpoint.clone())
            .context("invalid metrics service address")?
            .connect_timeout(timeout)
            .timeout(timeout)
            .connect()
            .await
            .with_context(|| format!("Failed to connect to TPU metrics service at {}", addr))?;

        let mut client = RuntimeMetricServiceClient::new(channel);

        // Discover available metrics
        let available_metrics = match client
            .list_supported_metrics(ListSupportedMetricsRequest { filter: None })
            .await
        {
            Ok(resp) => {
                let metrics: Vec<String> = resp
                    .into_inner()
                    .supported_metric
                    .into_iter()
                    .filter_map(|m| m.metric_name)
                    .collect();
                if !metrics.is_empty() {
                    info!("Available TPU metrics: {:?}", metrics);
                }
                metrics
            }
            Err(e) => {
                warn!(
                    "Could not list supported metrics: {:#}. Will use defaults.",
                    e
                );
                Vec::new()
            }
        };

        Ok(Self {
            client,
            available_metrics,
        })
    }

    /// Get the list of available metrics discovered from the service.
    pub fn available_metrics(&self) -> &[String] {
        &self.available_metrics
    }

    /// Fetch a single metric from the service.
    ///
    /// Returns per-device values (one entry per TPU device that reported).
    pub async fn get_metric(
        &mut self,
        metric_name: &str,
        timeout: Duration,
    ) -> Result<Vec<DeviceMetricValue>> {
        let request = MetricRequest {
            metric_name: Some(metric_name.to_string()),
            skip_node_aggregation: None,
        };

        let response: MetricResponse =
            tokio::time::timeout(timeout, self.client.get_runtime_metric(request))
                .await
                .context("metric RPC timed out")?
                .context("metric RPC failed")?
                .into_inner();

        let device_values = extract_metric_values(&response, metric_name);

        debug!(
            "Polled '{}': {} device values, type={:?}",
            metric_name,
            device_values.len(),
            response.metric_type,
        );

        Ok(device_values)
    }
}

/// Extract per-device metric values from a MetricResponse.
fn extract_metric_values(response: &MetricResponse, metric_name: &str) -> Vec<DeviceMetricValue> {
    // TPUMetric (MetricType::LIBTPU) has typed fields
    if let Some(ref tpu_metric) = response.metric {
        let mut values = Vec::new();
        for (i, metric) in tpu_metric.metrics.iter().enumerate() {
            let device_id = extract_device_id(metric).unwrap_or(i as i32);
            let value = extract_value(metric);

            if let Some(v) = value {
                values.push(DeviceMetricValue {
                    device_id,
                    value: v,
                });
            }
        }

        if values.is_empty() && !tpu_metric.metrics.is_empty() {
            debug!(
                "TPUMetric '{}' has {} metrics but no extractable values",
                metric_name,
                tpu_metric.metrics.len()
            );
        }

        return values;
    }

    // StreamzMetric (MetricType::STREAMZ) — extract values from PointSet -> Point.
    //
    // Note: device_id is a running index across all points. The real device identity
    // is in the Column labels (field #1 of StreamzPoint, not currently parsed). Using
    // a flat index is a heuristic that works when the TPU runtime emits one point per
    // device in stable order.
    if let Some(ref streamz) = response.streamz_metric {
        let mut values = Vec::new();
        let mut idx: i32 = 0;
        for read_resp in &streamz.read_response {
            for point_set in &read_resp.point_set {
                for point in &point_set.point {
                    let v = point
                        .double_value
                        .or(point.int64_value.map(|v| v as f64))
                        .or(point.distribution_value.as_ref().and_then(|d| d.mean));
                    if let Some(v) = v {
                        values.push(DeviceMetricValue {
                            device_id: idx,
                            value: v,
                        });
                    }
                    idx += 1;
                }
            }
        }
        if !values.is_empty() {
            return values;
        }
        debug!(
            "StreamzMetric '{}' has read_responses but no extractable point values",
            metric_name
        );
    }

    Vec::new()
}

/// Extract a numeric value from a Metric.
fn extract_value(metric: &tpu_metric_service::Metric) -> Option<f64> {
    // Try gauge → counter → distribution.mean → summary.sample_sum
    if let Some(ref gauge) = metric.gauge {
        return extract_gauge_value(gauge);
    }
    if let Some(ref counter) = metric.counter {
        return counter.as_double.or(counter.as_int.map(|v| v as f64));
    }
    if let Some(ref dist) = metric.distribution {
        return dist.mean;
    }
    if let Some(ref summary) = metric.summary {
        return summary.sample_sum;
    }
    None
}

/// Extract value from a Gauge message.
fn extract_gauge_value(gauge: &Gauge) -> Option<f64> {
    gauge.as_double.or(gauge.as_int.map(|v| v as f64))
}

/// Extract device_id from a Metric's attribute.
fn extract_device_id(metric: &tpu_metric_service::Metric) -> Option<i32> {
    let value = metric.attribute.as_ref()?.value.as_ref()?;
    value
        .int_attr
        .map(|v| v as i32)
        .or_else(|| value.string_attr.as_ref()?.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpu::gen::tpu_metric_service::{
        AttrValue, Attribute, Metric, StreamzMetric, StreamzPoint, StreamzPointSet,
        StreamzReadResponse, TpuMetric,
    };

    fn point_f64(v: f64) -> StreamzPoint {
        StreamzPoint {
            double_value: Some(v),
            ..Default::default()
        }
    }

    /// Regression test: device_id must be a running counter across ALL point_sets,
    /// not reset per point_set. With 2 point_sets × 2 points each, IDs should be
    /// [0,1,2,3], not [0,1,0,1].
    #[test]
    fn test_streamz_device_id_runs_across_point_sets() {
        let resp = MetricResponse {
            metric: None,
            metric_type: None,
            streamz_metric: Some(StreamzMetric {
                name: None,
                read_response: vec![StreamzReadResponse {
                    point_set: vec![
                        StreamzPointSet {
                            metric_name: None,
                            point: vec![point_f64(10.0), point_f64(20.0)],
                        },
                        StreamzPointSet {
                            metric_name: None,
                            point: vec![point_f64(30.0), point_f64(40.0)],
                        },
                    ],
                }],
            }),
        };

        let values = extract_metric_values(&resp, "test.metric");
        assert_eq!(values.len(), 4);
        let ids: Vec<i32> = values.iter().map(|v| v.device_id).collect();
        assert_eq!(ids, vec![0, 1, 2, 3]);
        let vals: Vec<f64> = values.iter().map(|v| v.value).collect();
        assert_eq!(vals, vec![10.0, 20.0, 30.0, 40.0]);
    }

    /// The index should track point position, not extraction count. If a point
    /// has no extractable value, the next point's device_id should still be
    /// its positional index.
    #[test]
    fn test_streamz_device_id_increments_on_skip() {
        let resp = MetricResponse {
            metric: None,
            metric_type: None,
            streamz_metric: Some(StreamzMetric {
                name: None,
                read_response: vec![StreamzReadResponse {
                    point_set: vec![StreamzPointSet {
                        metric_name: None,
                        point: vec![
                            point_f64(1.0),
                            StreamzPoint::default(), // no extractable value
                            point_f64(3.0),
                        ],
                    }],
                }],
            }),
        };

        let values = extract_metric_values(&resp, "test.metric");
        assert_eq!(values.len(), 2);
        assert_eq!(values[0].device_id, 0);
        assert_eq!(values[0].value, 1.0);
        // Device 1 had no value, so index 1 is skipped.
        assert_eq!(values[1].device_id, 2);
        assert_eq!(values[1].value, 3.0);
    }

    #[test]
    fn test_libtpu_gauge_extraction() {
        let resp = MetricResponse {
            streamz_metric: None,
            metric_type: None,
            metric: Some(TpuMetric {
                name: None,
                description: None,
                metrics: vec![
                    Metric {
                        attribute: Some(Attribute {
                            key: Some("device".to_string()),
                            value: Some(AttrValue {
                                int_attr: Some(7),
                                ..Default::default()
                            }),
                        }),
                        gauge: Some(Gauge {
                            as_double: Some(85.5),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    Metric {
                        // No attribute: device_id falls back to array index (1)
                        gauge: Some(Gauge {
                            as_int: Some(42),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                ],
            }),
        };

        let values = extract_metric_values(&resp, "test.metric");
        assert_eq!(values.len(), 2);
        assert_eq!(values[0].device_id, 7);
        assert_eq!(values[0].value, 85.5);
        assert_eq!(values[1].device_id, 1); // fallback to index
        assert_eq!(values[1].value, 42.0);
    }

    #[test]
    fn test_extract_device_id_from_string_attr() {
        let metric = Metric {
            attribute: Some(Attribute {
                key: None,
                value: Some(AttrValue {
                    string_attr: Some("3".to_string()),
                    ..Default::default()
                }),
            }),
            ..Default::default()
        };
        assert_eq!(extract_device_id(&metric), Some(3));
    }

    #[test]
    fn test_extract_device_id_none_when_missing() {
        let metric = Metric::default();
        assert_eq!(extract_device_id(&metric), None);
    }
}
