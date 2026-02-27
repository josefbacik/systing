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

/// Result of a single metric poll.
#[derive(Debug, Clone)]
pub struct MetricResult {
    pub metric_name: String,
    pub device_values: Vec<DeviceMetricValue>,
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
    pub async fn get_metric(
        &mut self,
        metric_name: &str,
        timeout: Duration,
    ) -> Result<MetricResult> {
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

        Ok(MetricResult {
            metric_name: metric_name.to_string(),
            device_values,
        })
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

    // StreamzMetric (MetricType::STREAMZ) — extract values from PointSet -> Point
    if let Some(ref streamz) = response.streamz_metric {
        let mut values = Vec::new();
        for read_resp in &streamz.read_response {
            for point_set in &read_resp.point_set {
                for (i, point) in point_set.point.iter().enumerate() {
                    if let Some(v) = point.double_value {
                        values.push(DeviceMetricValue {
                            device_id: i as i32,
                            value: v,
                        });
                    } else if let Some(v) = point.int64_value {
                        values.push(DeviceMetricValue {
                            device_id: i as i32,
                            value: v as f64,
                        });
                    }
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
    // Try gauge first
    if let Some(ref gauge) = metric.gauge {
        return extract_gauge_value(gauge);
    }

    // Try counter
    if let Some(ref counter) = metric.counter {
        if let Some(v) = counter.as_double {
            return Some(v);
        }
        if let Some(v) = counter.as_int {
            return Some(v as f64);
        }
    }

    // Try distribution (use mean as the representative value)
    if let Some(ref dist) = metric.distribution {
        if let Some(mean) = dist.mean {
            return Some(mean);
        }
    }

    // Try summary
    if let Some(ref summary) = metric.summary {
        if let Some(sum) = summary.sample_sum {
            return Some(sum);
        }
    }

    None
}

/// Extract value from a Gauge message.
fn extract_gauge_value(gauge: &Gauge) -> Option<f64> {
    if let Some(v) = gauge.as_double {
        return Some(v);
    }
    if let Some(v) = gauge.as_int {
        return Some(v as f64);
    }
    None
}

/// Extract device_id from a Metric's attribute.
fn extract_device_id(metric: &tpu_metric_service::Metric) -> Option<i32> {
    if let Some(ref attr) = metric.attribute {
        if let Some(ref value) = attr.value {
            if let Some(v) = value.int_attr {
                return Some(v as i32);
            }
            if let Some(ref s) = value.string_attr {
                if let Ok(v) = s.parse::<i32>() {
                    return Some(v);
                }
            }
        }
    }
    None
}

// === Proto dump functionality (for --dump-tpu-proto) ===

/// Dump proto file descriptors from a TPU RuntimeMetricService via gRPC reflection.
pub async fn dump_tpu_protos(addr: &str) -> Result<()> {
    use prost::Message;
    use std::collections::HashSet;
    use tonic_reflection::pb::v1alpha::server_reflection_client::ServerReflectionClient;

    let endpoint = format!("http://{}", addr);
    println!("Connecting to {}...", endpoint);

    let channel = Channel::from_shared(endpoint)?
        .connect_timeout(Duration::from_secs(10))
        .connect()
        .await
        .context("failed to connect")?;

    let mut client = ServerReflectionClient::new(channel);

    println!("\n=== Services ===");
    let services = reflection_list_services(&mut client).await?;
    for svc in &services {
        println!("  {}", svc);
    }

    let target = services
        .iter()
        .find(|s| s.contains("RuntimeMetric"))
        .or_else(|| services.iter().find(|s| s.contains("runtime")))
        .context("RuntimeMetricService not found")?
        .clone();

    println!("\nFetching proto descriptors for: {}", target);

    let mut all_fds = Vec::new();
    let mut seen = HashSet::new();
    let mut pending = vec![target.clone()];
    let mut is_first = true;

    while let Some(name) = pending.pop() {
        if seen.contains(name.as_str()) {
            continue;
        }

        let fds = if is_first {
            is_first = false;
            reflection_file_containing_symbol(&mut client, &name).await?
        } else {
            match reflection_file_by_name(&mut client, &name).await {
                Ok(fds) => fds,
                Err(e) => {
                    eprintln!("  Could not fetch '{}': {:#}", name, e);
                    seen.insert(name);
                    continue;
                }
            }
        };

        for fd in fds {
            let fname = fd.name.clone().unwrap_or_default();
            for dep in &fd.dependency {
                if !seen.contains(dep.as_str()) {
                    pending.push(dep.clone());
                }
            }
            if seen.insert(fname.clone()) {
                all_fds.push(fd);
            }
        }
    }

    println!("\n=== Proto File Descriptors ({} files) ===", all_fds.len());
    for fd in &all_fds {
        let name = fd.name.as_deref().unwrap_or("<unknown>");
        let pkg = fd.package.as_deref().unwrap_or("");
        println!("\n--- {} (package: {}) ---", name, pkg);
        println!("  Dependencies: {:?}", fd.dependency);
        for msg in &fd.message_type {
            print_message_type(msg, 1);
        }
        for svc in &fd.service {
            let svc_name = svc.name.as_deref().unwrap_or("?");
            println!("  service {} {{", svc_name);
            for method in &svc.method {
                println!(
                    "    rpc {}({}) returns ({});",
                    method.name.as_deref().unwrap_or("?"),
                    method.input_type.as_deref().unwrap_or("?"),
                    method.output_type.as_deref().unwrap_or("?"),
                );
            }
            println!("  }}");
        }
        for en in &fd.enum_type {
            println!("  enum {} {{", en.name.as_deref().unwrap_or("?"));
            for val in &en.value {
                println!(
                    "    {} = {};",
                    val.name.as_deref().unwrap_or("?"),
                    val.number.unwrap_or(0)
                );
            }
            println!("  }}");
        }
    }

    let fds = prost_types::FileDescriptorSet {
        file: all_fds.clone(),
    };
    let encoded = fds.encode_to_vec();
    let dump_path = "tpu_metrics_descriptor.bin";
    std::fs::write(dump_path, &encoded)?;
    println!(
        "\nWrote serialized FileDescriptorSet to {} ({} bytes, {} files)",
        dump_path,
        encoded.len(),
        all_fds.len()
    );

    Ok(())
}

fn print_message_type(msg: &prost_types::DescriptorProto, indent: usize) {
    let pad = "  ".repeat(indent);
    let name = msg.name.as_deref().unwrap_or("?");
    println!("{}message {} {{", pad, name);
    for field in &msg.field {
        let f_name = field.name.as_deref().unwrap_or("?");
        let f_num = field.number.unwrap_or(0);
        let f_type_name = field.type_name.as_deref().unwrap_or("");
        let label = match field.label.unwrap_or(0) {
            1 => "optional ",
            2 => "required ",
            3 => "repeated ",
            _ => "",
        };
        let type_str = match field.r#type.unwrap_or(0) {
            1 => "double".to_string(),
            2 => "float".to_string(),
            3 => "int64".to_string(),
            4 => "uint64".to_string(),
            5 => "int32".to_string(),
            8 => "bool".to_string(),
            9 => "string".to_string(),
            11 => format!("message {}", f_type_name),
            12 => "bytes".to_string(),
            13 => "uint32".to_string(),
            14 => format!("enum {}", f_type_name),
            _ => format!("type({})", field.r#type.unwrap_or(0)),
        };
        println!("{}  {}{} {} = {};", pad, label, type_str, f_name, f_num);
    }
    for nested in &msg.nested_type {
        print_message_type(nested, indent + 1);
    }
    for en in &msg.enum_type {
        println!("{}  enum {} {{", pad, en.name.as_deref().unwrap_or("?"));
        for val in &en.value {
            println!(
                "{}    {} = {};",
                pad,
                val.name.as_deref().unwrap_or("?"),
                val.number.unwrap_or(0)
            );
        }
        println!("{}  }}", pad);
    }
    println!("{}}}", pad);
}

async fn reflection_list_services(
    client: &mut tonic_reflection::pb::v1alpha::server_reflection_client::ServerReflectionClient<
        Channel,
    >,
) -> Result<Vec<String>> {
    use tonic_reflection::pb::v1alpha::server_reflection_request::MessageRequest;
    use tonic_reflection::pb::v1alpha::ServerReflectionRequest;
    let request = ServerReflectionRequest {
        message_request: Some(MessageRequest::ListServices(String::new())),
        ..Default::default()
    };
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    tx.send(request).await?;
    use tokio_stream::StreamExt;
    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    let mut resp = client.server_reflection_info(stream).await?.into_inner();
    let mut names = Vec::new();
    if let Some(r) = resp.next().await {
        let r = r?;
        if let Some(tonic_reflection::pb::v1alpha::server_reflection_response::MessageResponse::ListServicesResponse(list)) = r.message_response {
            for svc in &list.service {
                names.push(svc.name.clone());
            }
        }
    }
    Ok(names)
}

async fn reflection_file_containing_symbol(
    client: &mut tonic_reflection::pb::v1alpha::server_reflection_client::ServerReflectionClient<
        Channel,
    >,
    symbol: &str,
) -> Result<Vec<prost_types::FileDescriptorProto>> {
    use tonic_reflection::pb::v1alpha::server_reflection_request::MessageRequest;
    use tonic_reflection::pb::v1alpha::ServerReflectionRequest;
    reflection_fetch_fds(
        client,
        ServerReflectionRequest {
            message_request: Some(MessageRequest::FileContainingSymbol(symbol.to_string())),
            ..Default::default()
        },
    )
    .await
}

async fn reflection_file_by_name(
    client: &mut tonic_reflection::pb::v1alpha::server_reflection_client::ServerReflectionClient<
        Channel,
    >,
    filename: &str,
) -> Result<Vec<prost_types::FileDescriptorProto>> {
    use tonic_reflection::pb::v1alpha::server_reflection_request::MessageRequest;
    use tonic_reflection::pb::v1alpha::ServerReflectionRequest;
    reflection_fetch_fds(
        client,
        ServerReflectionRequest {
            message_request: Some(MessageRequest::FileByFilename(filename.to_string())),
            ..Default::default()
        },
    )
    .await
}

async fn reflection_fetch_fds(
    client: &mut tonic_reflection::pb::v1alpha::server_reflection_client::ServerReflectionClient<
        Channel,
    >,
    request: tonic_reflection::pb::v1alpha::ServerReflectionRequest,
) -> Result<Vec<prost_types::FileDescriptorProto>> {
    use prost::Message;
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    tx.send(request).await?;
    use tokio_stream::StreamExt;
    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    let mut resp = client.server_reflection_info(stream).await?.into_inner();
    let mut fds = Vec::new();
    if let Some(r) = resp.next().await {
        let r = r?;
        if let Some(tonic_reflection::pb::v1alpha::server_reflection_response::MessageResponse::FileDescriptorResponse(fdr)) = r.message_response {
            for fd_bytes in &fdr.file_descriptor_proto {
                fds.push(prost_types::FileDescriptorProto::decode(fd_bytes.as_slice())?);
            }
        }
    }
    Ok(fds)
}
