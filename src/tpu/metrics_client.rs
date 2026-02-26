//! gRPC client for the TPU RuntimeMetricService.
//!
//! Uses runtime gRPC reflection to discover the proto schema dynamically,
//! then fetches metrics using `DynamicMessage` from `prost-reflect`.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use prost::Message;
use prost_reflect::{DescriptorPool, DynamicMessage, ReflectMessage, Value};
use tonic::transport::Channel;
use tracing::{debug, info, warn};

use tonic_reflection::pb::v1alpha::server_reflection_client::ServerReflectionClient;
use tonic_reflection::pb::v1alpha::server_reflection_request::MessageRequest;
use tonic_reflection::pb::v1alpha::ServerReflectionRequest;

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

/// Client for the TPU RuntimeMetricService using dynamic gRPC reflection.
pub struct TpuMetricsClient {
    channel: Channel,
    request_desc: prost_reflect::MessageDescriptor,
    response_desc: prost_reflect::MessageDescriptor,
    /// Full gRPC method path.
    method_path: String,
    /// Metrics available from the service.
    available_metrics: Vec<String>,
}

impl TpuMetricsClient {
    /// Connect to the RuntimeMetricService, perform reflection discovery,
    /// and validate available metrics.
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

        // Step 1: Use gRPC reflection to discover the proto schema
        let pool = Self::discover_schema(channel.clone()).await?;

        // Step 2: Find the service and method descriptors
        let service_name = Self::find_runtime_metric_service(&pool)?;
        let service = pool
            .get_service_by_name(&service_name)
            .with_context(|| format!("Service {} not found in descriptor pool", service_name))?;

        // Find the GetRuntimeMetric method
        let method = service
            .methods()
            .find(|m| m.name() == "GetRuntimeMetric")
            .with_context(|| format!("GetRuntimeMetric method not found in {}", service_name))?;

        let request_desc = method.input();
        let response_desc = method.output();
        let method_path = format!("/{}/{}", service_name, method.name());

        info!(
            "Discovered method: {} (request: {}, response: {})",
            method_path,
            request_desc.full_name(),
            response_desc.full_name()
        );

        // Log the response schema so users can see what fields are available
        info!("Response schema for {}:", response_desc.full_name());
        for field in response_desc.fields() {
            info!(
                "  field #{}: '{}' type={:?} cardinality={:?}",
                field.number(),
                field.name(),
                field.kind(),
                field.cardinality()
            );
        }

        // Step 3: Discover available metrics via ListSupportedMetrics
        let available_metrics = Self::list_supported_metrics(&pool, &service_name, channel.clone())
            .await
            .unwrap_or_else(|e| {
                warn!(
                    "Could not list supported metrics: {:#}. Will attempt default metrics.",
                    e
                );
                Vec::new()
            });

        if !available_metrics.is_empty() {
            info!("Available TPU metrics: {:?}", available_metrics);
        }

        Ok(Self {
            channel,
            request_desc,
            response_desc,
            method_path,
            available_metrics,
        })
    }

    /// Get the list of available metrics discovered from the service.
    pub fn available_metrics(&self) -> &[String] {
        &self.available_metrics
    }

    /// Fetch a single metric from the service.
    pub async fn get_metric(&self, metric_name: &str, timeout: Duration) -> Result<MetricResult> {
        // Build request using DynamicMessage
        let mut request = DynamicMessage::new(self.request_desc.clone());
        request.set_field_by_name("metric_name", Value::String(metric_name.to_string()));
        let request_bytes = request.encode_to_vec();

        // Make raw gRPC call
        let mut grpc = tonic::client::Grpc::new(self.channel.clone());
        grpc.ready().await.context("channel not ready")?;

        let path = http::uri::PathAndQuery::from_maybe_shared(self.method_path.clone())
            .context("invalid method path")?;

        let codec = tonic_prost::ProstCodec::<Vec<u8>, Vec<u8>>::default();
        let response: tonic::Response<Vec<u8>> = tokio::time::timeout(timeout, async {
            grpc.unary(tonic::Request::new(request_bytes), path, codec)
                .await
        })
        .await
        .context("metric RPC timed out")?
        .context("metric RPC failed")?;

        let response_bytes = response.into_inner();
        debug!(
            "Got response for '{}': {} bytes",
            metric_name,
            response_bytes.len()
        );

        // Decode response
        let response_msg =
            DynamicMessage::decode(self.response_desc.clone(), response_bytes.as_slice())
                .context("failed to decode metric response")?;

        // Log the decoded response structure for debugging
        debug!(
            "Decoded response for '{}': {}",
            metric_name,
            format_dynamic_message(&response_msg)
        );

        // Extract per-device values from the response
        let device_values = Self::extract_device_values(&response_msg);
        if device_values.is_empty() {
            warn!(
                "No device values extracted from response for '{}'. \
                 Response fields: {}",
                metric_name,
                format_dynamic_message(&response_msg)
            );
        }

        Ok(MetricResult {
            metric_name: metric_name.to_string(),
            device_values,
        })
    }

    /// Perform gRPC reflection to discover the proto schema.
    async fn discover_schema(channel: Channel) -> Result<DescriptorPool> {
        let mut reflection_client = ServerReflectionClient::new(channel);

        // First, list all services
        let request = ServerReflectionRequest {
            message_request: Some(MessageRequest::ListServices(String::new())),
            ..Default::default()
        };

        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tx.send(request)
            .await
            .context("failed to send reflection request")?;

        let request_stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        let mut response_stream = reflection_client
            .server_reflection_info(request_stream)
            .await
            .context("reflection RPC failed")?
            .into_inner();

        // Collect service names
        use tokio_stream::StreamExt;
        let mut service_names = Vec::new();
        if let Some(response) = response_stream.next().await {
            let response = response.context("reflection response error")?;
            if let Some(
                tonic_reflection::pb::v1alpha::server_reflection_response::MessageResponse::ListServicesResponse(list),
            ) = response.message_response
            {
                for svc in &list.service {
                    debug!("Discovered service: {}", svc.name);
                    service_names.push(svc.name.clone());
                }
            }
        }
        drop(response_stream);

        if service_names.is_empty() {
            bail!("No services found via gRPC reflection");
        }

        // Find the RuntimeMetric service
        let target_service = service_names
            .iter()
            .find(|s| {
                s.contains("RuntimeMetric")
                    || s.contains("runtime_metric")
                    || s.contains("runtime.RuntimeMetric")
            })
            .or_else(|| {
                service_names
                    .iter()
                    .find(|s| s.contains("runtime") || s.contains("monitoring"))
            })
            .with_context(|| {
                format!(
                    "No RuntimeMetricService found. Available services: {:?}",
                    service_names
                )
            })?
            .clone();

        info!("Using service for reflection: {}", target_service);

        // Get the file descriptor for this service
        let request2 = ServerReflectionRequest {
            message_request: Some(MessageRequest::FileContainingSymbol(target_service.clone())),
            ..Default::default()
        };

        let (tx2, rx2) = tokio::sync::mpsc::channel(1);
        tx2.send(request2)
            .await
            .context("failed to send reflection request")?;

        let request_stream2 = tokio_stream::wrappers::ReceiverStream::new(rx2);
        let mut response_stream2 = reflection_client
            .server_reflection_info(request_stream2)
            .await
            .context("reflection RPC for file descriptor failed")?
            .into_inner();

        let mut pool = DescriptorPool::new();

        if let Some(response) = response_stream2.next().await {
            let response = response.context("reflection file descriptor response error")?;
            if let Some(
                tonic_reflection::pb::v1alpha::server_reflection_response::MessageResponse::FileDescriptorResponse(fdr),
            ) = response.message_response
            {
                for fd_bytes in &fdr.file_descriptor_proto {
                    let fd_proto =
                        prost_types::FileDescriptorProto::decode(fd_bytes.as_slice())
                            .context("failed to decode FileDescriptorProto")?;
                    let fds = prost_types::FileDescriptorSet {
                        file: vec![fd_proto],
                    };
                    if let Err(e) = pool.add_file_descriptor_set(fds) {
                        debug!(
                            "Skipping file descriptor (may have deps already loaded): {}",
                            e
                        );
                    }
                }
            }
        }

        Ok(pool)
    }

    /// Find the RuntimeMetricService name in the descriptor pool.
    fn find_runtime_metric_service(pool: &DescriptorPool) -> Result<String> {
        let candidates = [
            "tpu.monitoring.runtime.RuntimeMetricService",
            "tpu.monitoring.RuntimeMetricService",
            "RuntimeMetricService",
        ];

        for name in &candidates {
            if pool.get_service_by_name(name).is_some() {
                return Ok(name.to_string());
            }
        }

        // Search all services in the pool
        for service in pool.services() {
            let full_name = service.full_name().to_string();
            if full_name.contains("RuntimeMetric") || full_name.contains("runtime_metric") {
                return Ok(full_name);
            }
        }

        bail!("RuntimeMetricService not found in descriptor pool")
    }

    /// Call ListSupportedMetrics to discover available metrics.
    async fn list_supported_metrics(
        pool: &DescriptorPool,
        service_name: &str,
        channel: Channel,
    ) -> Result<Vec<String>> {
        let service = pool
            .get_service_by_name(service_name)
            .context("service not found")?;

        let method = match service
            .methods()
            .find(|m| m.name() == "ListSupportedMetrics")
        {
            Some(m) => m,
            None => {
                debug!("ListSupportedMetrics method not found, skipping metric discovery");
                return Ok(Vec::new());
            }
        };

        let request = DynamicMessage::new(method.input());
        let request_bytes = request.encode_to_vec();

        let method_path = format!("/{}/{}", service_name, method.name());
        let path = http::uri::PathAndQuery::from_maybe_shared(method_path)
            .context("invalid method path")?;

        let mut grpc = tonic::client::Grpc::new(channel);
        grpc.ready().await.context("channel not ready")?;

        let codec = tonic_prost::ProstCodec::<Vec<u8>, Vec<u8>>::default();
        let response: tonic::Response<Vec<u8>> = grpc
            .unary(tonic::Request::new(request_bytes), path, codec)
            .await
            .context("ListSupportedMetrics RPC failed")?;

        let response_bytes = response.into_inner();
        let response_msg = DynamicMessage::decode(method.output(), response_bytes.as_slice())
            .context("failed to decode ListSupportedMetrics response")?;

        // Extract metric names from the response
        let mut metrics = Vec::new();
        for field_name in &["metrics", "metric_names", "supported_metrics"] {
            if let Some(value) = response_msg.get_field_by_name(field_name) {
                if let Value::List(list) = value.as_ref() {
                    for item in list {
                        if let Value::String(s) = item {
                            metrics.push(s.clone());
                        } else if let Value::Message(msg) = item {
                            if let Some(name_val) = msg.get_field_by_name("name") {
                                if let Value::String(s) = name_val.as_ref() {
                                    metrics.push(s.clone());
                                }
                            }
                            if let Some(name_val) = msg.get_field_by_name("metric_name") {
                                if let Value::String(s) = name_val.as_ref() {
                                    metrics.push(s.clone());
                                }
                            }
                        }
                    }
                    break;
                }
            }
        }

        Ok(metrics)
    }

    /// Extract per-device metric values from a response message.
    ///
    /// Uses heuristics to find per-device results in the dynamically-discovered
    /// response proto. Prefers list fields (repeated per-device messages) over
    /// scalar fields. Logs which field was matched for debuggability.
    fn extract_device_values(response: &DynamicMessage) -> Vec<DeviceMetricValue> {
        let mut values = Vec::new();

        // Count scalar numeric fields for ambiguity detection
        let numeric_field_count = response
            .descriptor()
            .fields()
            .filter(|f| {
                response
                    .get_field_by_name(f.name())
                    .map(|v| {
                        matches!(
                            v.as_ref(),
                            Value::F64(_)
                                | Value::F32(_)
                                | Value::I64(_)
                                | Value::U64(_)
                                | Value::I32(_)
                                | Value::U32(_)
                        )
                    })
                    .unwrap_or(false)
            })
            .count();
        if numeric_field_count > 1 {
            debug!(
                "Response has {} candidate fields; extraction may be ambiguous",
                numeric_field_count
            );
        }

        for field in response.descriptor().fields() {
            let field_name = field.name();
            if let Some(val) = response.get_field_by_name(field_name) {
                debug!(
                    "  field '{}': type={}",
                    field_name,
                    format_value_type(val.as_ref())
                );
                match val.as_ref() {
                    Value::List(list) => {
                        debug!("    list field '{}' has {} items", field_name, list.len());
                        for (i, item) in list.iter().enumerate() {
                            if let Value::Message(msg) = item {
                                debug!("      item[{}]: {}", i, format_dynamic_message(msg));
                                let device_id = Self::extract_int_field(
                                    msg,
                                    &["device_id", "device_ordinal", "chip_id"],
                                )
                                .unwrap_or(i as i64)
                                    as i32;
                                if let Some(value) = Self::extract_float_field(
                                    msg,
                                    &["value", "metric_value", "duty_cycle", "usage", "percent"],
                                ) {
                                    values.push(DeviceMetricValue { device_id, value });
                                } else {
                                    debug!(
                                        "      item[{}]: no float value found in known field names",
                                        i
                                    );
                                }
                            } else {
                                debug!(
                                    "      item[{}]: not a message, type={}",
                                    i,
                                    format_value_type(item)
                                );
                            }
                        }
                        if !values.is_empty() {
                            debug!(
                                "Extracted {} device values from list field '{}'",
                                values.len(),
                                field_name
                            );
                            return values;
                        }
                    }
                    Value::Message(msg) => {
                        if let Some(value) =
                            Self::extract_float_field(msg, &["value", "metric_value"])
                        {
                            let device_id =
                                Self::extract_int_field(msg, &["device_id", "device_ordinal"])
                                    .unwrap_or(0) as i32;
                            values.push(DeviceMetricValue { device_id, value });
                            return values;
                        }
                    }
                    val @ (Value::F64(_)
                    | Value::F32(_)
                    | Value::I64(_)
                    | Value::U64(_)
                    | Value::I32(_)
                    | Value::U32(_)) => {
                        let v = match val {
                            Value::F64(v) => *v,
                            Value::F32(v) => *v as f64,
                            Value::I64(v) => *v as f64,
                            Value::U64(v) => *v as f64,
                            Value::I32(v) => *v as f64,
                            Value::U32(v) => *v as f64,
                            _ => unreachable!(),
                        };
                        values.push(DeviceMetricValue {
                            device_id: 0,
                            value: v,
                        });
                        return values;
                    }
                    _ => {}
                }
            }
        }

        values
    }

    fn extract_int_field(msg: &DynamicMessage, field_names: &[&str]) -> Option<i64> {
        for name in field_names {
            if let Some(val) = msg.get_field_by_name(name) {
                match val.as_ref() {
                    Value::I32(v) => return Some(*v as i64),
                    Value::I64(v) => return Some(*v),
                    Value::U32(v) => return Some(*v as i64),
                    Value::U64(v) => return Some(*v as i64),
                    _ => {}
                }
            }
        }
        None
    }

    fn extract_float_field(msg: &DynamicMessage, field_names: &[&str]) -> Option<f64> {
        for name in field_names {
            if let Some(val) = msg.get_field_by_name(name) {
                match val.as_ref() {
                    Value::F64(v) => return Some(*v),
                    Value::F32(v) => return Some(*v as f64),
                    Value::I64(v) => return Some(*v as f64),
                    Value::U64(v) => return Some(*v as f64),
                    Value::I32(v) => return Some(*v as f64),
                    Value::U32(v) => return Some(*v as f64),
                    _ => {}
                }
            }
        }
        None
    }
}

/// Format a DynamicMessage for debug logging, showing field names and values.
fn format_dynamic_message(msg: &DynamicMessage) -> String {
    let mut parts = Vec::new();
    for field in msg.descriptor().fields() {
        let name = field.name();
        if let Some(val) = msg.get_field_by_name(name) {
            parts.push(format!("{}={}", name, format_value_brief(val.as_ref())));
        }
    }
    if parts.is_empty() {
        format!("{{}} (type: {})", msg.descriptor().full_name())
    } else {
        format!("{{{}}}", parts.join(", "))
    }
}

/// Format a Value type name for debug logging.
fn format_value_type(val: &Value) -> &'static str {
    match val {
        Value::Bool(_) => "bool",
        Value::I32(_) => "i32",
        Value::I64(_) => "i64",
        Value::U32(_) => "u32",
        Value::U64(_) => "u64",
        Value::F32(_) => "f32",
        Value::F64(_) => "f64",
        Value::String(_) => "string",
        Value::Bytes(_) => "bytes",
        Value::EnumNumber(_) => "enum",
        Value::Message(_) => "message",
        Value::List(_) => "list",
        Value::Map(_) => "map",
    }
}

/// Format a Value briefly for debug logging.
fn format_value_brief(val: &Value) -> String {
    match val {
        Value::Bool(v) => format!("{}", v),
        Value::I32(v) => format!("{}", v),
        Value::I64(v) => format!("{}", v),
        Value::U32(v) => format!("{}", v),
        Value::U64(v) => format!("{}", v),
        Value::F32(v) => format!("{}", v),
        Value::F64(v) => format!("{}", v),
        Value::String(v) => {
            if v.len() > 50 {
                format!("\"{}...\"", &v[..50])
            } else {
                format!("\"{}\"", v)
            }
        }
        Value::Bytes(v) => format!("<{} bytes>", v.len()),
        Value::EnumNumber(v) => format!("enum({})", v),
        Value::Message(msg) => {
            let field_count = msg.descriptor().fields().len();
            format!("<{} with {} fields>", msg.descriptor().name(), field_count)
        }
        Value::List(list) => format!("[{} items]", list.len()),
        Value::Map(map) => format!("{{{}}} entries", map.len()),
    }
}
