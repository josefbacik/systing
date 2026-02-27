//! gRPC client for the TPU RuntimeMetricService.
//!
//! Uses raw protobuf encoding/decoding to avoid depending on prost-reflect's
//! DescriptorPool, which panics on some TPU runtime proto schemas.
//! The gRPC reflection API is used only to discover the service name and
//! method path — the actual metric request/response is hand-encoded/decoded.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use prost::bytes::{Buf, BufMut, Bytes};
use prost::Message;
use tonic::transport::Channel;
use tracing::{debug, info};

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

/// Client for the TPU RuntimeMetricService.
///
/// Uses gRPC reflection to discover the service method path, then makes
/// raw gRPC calls with hand-encoded protobuf. This avoids prost-reflect's
/// DescriptorPool which panics on some proto schemas.
pub struct TpuMetricsClient {
    channel: Channel,
    /// Full gRPC method path (e.g. "/tpu.monitoring.runtime.RuntimeMetricService/GetRuntimeMetric").
    method_path: String,
    /// Metrics available from the service.
    available_metrics: Vec<String>,
}

impl TpuMetricsClient {
    /// Connect to the RuntimeMetricService and discover the method path via reflection.
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

        // Use reflection just to discover the service name (no DescriptorPool needed)
        let service_name = Self::discover_service_name(channel.clone()).await?;
        let method_path = format!("/{}/GetRuntimeMetric", service_name);

        info!("Discovered TPU metrics method: {}", method_path);

        // Try to discover available metrics (optional, best-effort)
        let list_method = format!("/{}/ListSupportedMetrics", service_name);
        let available_metrics = Self::try_list_metrics(channel.clone(), &list_method)
            .await
            .unwrap_or_else(|e| {
                debug!("Could not list supported metrics: {:#}", e);
                Vec::new()
            });

        if !available_metrics.is_empty() {
            info!("Available TPU metrics: {:?}", available_metrics);
        }

        Ok(Self {
            channel,
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
        // Hand-encode the request: a simple message with field 1 = metric_name (string)
        let request_bytes = encode_string_field(1, metric_name);

        debug!(
            "Requesting metric '{}' ({} request bytes)",
            metric_name,
            request_bytes.len()
        );

        // Make raw gRPC call
        let mut grpc = tonic::client::Grpc::new(self.channel.clone());
        grpc.ready().await.context("channel not ready")?;

        let path = http::uri::PathAndQuery::from_maybe_shared(self.method_path.clone())
            .context("invalid method path")?;

        let codec = RawBytesCodec;
        let response: tonic::Response<Bytes> = tokio::time::timeout(timeout, async {
            grpc.unary(tonic::Request::new(request_bytes.into()), path, codec)
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

        // Log the raw field structure for debugging
        log_proto_fields(metric_name, &response_bytes);

        // Parse the raw protobuf response to extract numeric values
        let device_values = parse_metric_response(&response_bytes);
        if device_values.is_empty() {
            debug!(
                "No device values extracted from response for '{}'",
                metric_name,
            );
        } else {
            debug!(
                "Extracted {} device values for '{}': {:?}",
                device_values.len(),
                metric_name,
                device_values
            );
        }

        Ok(MetricResult {
            metric_name: metric_name.to_string(),
            device_values,
        })
    }

    /// Use gRPC reflection to discover the RuntimeMetricService name.
    async fn discover_service_name(channel: Channel) -> Result<String> {
        let mut reflection_client = ServerReflectionClient::new(channel);

        let request = ServerReflectionRequest {
            message_request: Some(MessageRequest::ListServices(String::new())),
            ..Default::default()
        };

        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tx.send(request)
            .await
            .context("failed to send reflection request")?;

        use tokio_stream::StreamExt;
        let request_stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        let mut response_stream = reflection_client
            .server_reflection_info(request_stream)
            .await
            .context("reflection RPC failed")?
            .into_inner();

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

        if service_names.is_empty() {
            bail!("No services found via gRPC reflection");
        }

        // Find the RuntimeMetric service
        let target = service_names
            .iter()
            .find(|s| s.contains("RuntimeMetric"))
            .or_else(|| service_names.iter().find(|s| s.contains("runtime")))
            .with_context(|| {
                format!(
                    "No RuntimeMetricService found. Available services: {:?}",
                    service_names
                )
            })?
            .clone();

        Ok(target)
    }

    /// Try to list supported metrics via a ListSupportedMetrics RPC.
    /// Returns empty vec on failure (this is best-effort).
    async fn try_list_metrics(channel: Channel, method_path: &str) -> Result<Vec<String>> {
        let mut grpc = tonic::client::Grpc::new(channel);
        grpc.ready().await.context("channel not ready")?;

        let path = http::uri::PathAndQuery::try_from(method_path).context("invalid method path")?;

        // Empty request
        let codec = RawBytesCodec;
        let response: tonic::Response<Bytes> = grpc
            .unary(tonic::Request::new(Bytes::new()), path, codec)
            .await
            .context("ListSupportedMetrics RPC failed")?;

        let response_bytes = response.into_inner();
        // Parse response for string fields (metric names)
        Ok(extract_all_strings(&response_bytes))
    }
}

/// Dump proto file descriptors from a TPU RuntimeMetricService via gRPC reflection.
///
/// Connects to the service, fetches all proto file descriptors recursively,
/// and prints them in a human-readable format. Used for one-time proto capture.
pub async fn dump_tpu_protos(addr: &str) -> Result<()> {
    use prost::Message;
    use std::collections::HashSet;

    let endpoint = format!("http://{}", addr);
    println!("Connecting to {}...", endpoint);

    let channel = Channel::from_shared(endpoint)?
        .connect_timeout(Duration::from_secs(10))
        .connect()
        .await
        .context("failed to connect")?;

    let mut client = ServerReflectionClient::new(channel);

    // List all services
    println!("\n=== Services ===");
    let services = list_services_raw(&mut client).await?;
    for svc in &services {
        println!("  {}", svc);
    }

    // Find the RuntimeMetric service
    let target = services
        .iter()
        .find(|s| s.contains("RuntimeMetric"))
        .or_else(|| services.iter().find(|s| s.contains("runtime")))
        .context("RuntimeMetricService not found")?
        .clone();

    println!("\nFetching proto descriptors for: {}", target);

    // Recursively fetch all file descriptors
    let mut all_fds = Vec::new();
    let mut seen = HashSet::new();
    let mut pending = vec![target.clone()];
    let mut is_first = true;

    while let Some(name) = pending.pop() {
        if seen.contains(&name) {
            continue;
        }

        let fds = if is_first {
            is_first = false;
            fetch_file_containing_symbol(&mut client, &name).await?
        } else {
            match fetch_file_by_name(&mut client, &name).await {
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
            let svc_name = svc.name.as_deref().unwrap_or("<unknown>");
            println!("  service {} {{", svc_name);
            for method in &svc.method {
                let m_name = method.name.as_deref().unwrap_or("?");
                let input = method.input_type.as_deref().unwrap_or("?");
                let output = method.output_type.as_deref().unwrap_or("?");
                println!("    rpc {}({}) returns ({});", m_name, input, output);
            }
            println!("  }}");
        }
        for en in &fd.enum_type {
            let en_name = en.name.as_deref().unwrap_or("<unknown>");
            println!("  enum {} {{", en_name);
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

    // Also dump the raw serialized FileDescriptorSet for codegen
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
    println!("Use this with prost-build to generate Rust types.");

    Ok(())
}

fn print_message_type(msg: &prost_types::DescriptorProto, indent: usize) {
    let pad = "  ".repeat(indent);
    let name = msg.name.as_deref().unwrap_or("<unknown>");
    println!("{}message {} {{", pad, name);
    for field in &msg.field {
        let f_name = field.name.as_deref().unwrap_or("?");
        let f_num = field.number.unwrap_or(0);
        let f_type = field.r#type.unwrap_or(0);
        let f_type_name = field.type_name.as_deref().unwrap_or("");
        let label = match field.label.unwrap_or(0) {
            1 => "optional ",
            2 => "required ",
            3 => "repeated ",
            _ => "",
        };
        let type_str = match f_type {
            1 => "double".to_string(),
            2 => "float".to_string(),
            3 => "int64".to_string(),
            4 => "uint64".to_string(),
            5 => "int32".to_string(),
            6 => "fixed64".to_string(),
            7 => "fixed32".to_string(),
            8 => "bool".to_string(),
            9 => "string".to_string(),
            11 => format!("message {}", f_type_name),
            12 => "bytes".to_string(),
            13 => "uint32".to_string(),
            14 => format!("enum {}", f_type_name),
            15 => "sfixed32".to_string(),
            16 => "sfixed64".to_string(),
            17 => "sint32".to_string(),
            18 => "sint64".to_string(),
            _ => format!("type({})", f_type),
        };
        println!("{}  {}{} {} = {};", pad, label, type_str, f_name, f_num);
    }
    for nested in &msg.nested_type {
        print_message_type(nested, indent + 1);
    }
    for en in &msg.enum_type {
        let en_name = en.name.as_deref().unwrap_or("?");
        println!("{}  enum {} {{", pad, en_name);
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

async fn list_services_raw(client: &mut ServerReflectionClient<Channel>) -> Result<Vec<String>> {
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

async fn fetch_file_containing_symbol(
    client: &mut ServerReflectionClient<Channel>,
    symbol: &str,
) -> Result<Vec<prost_types::FileDescriptorProto>> {
    let request = ServerReflectionRequest {
        message_request: Some(MessageRequest::FileContainingSymbol(symbol.to_string())),
        ..Default::default()
    };
    fetch_file_descriptors(client, request).await
}

async fn fetch_file_by_name(
    client: &mut ServerReflectionClient<Channel>,
    filename: &str,
) -> Result<Vec<prost_types::FileDescriptorProto>> {
    let request = ServerReflectionRequest {
        message_request: Some(MessageRequest::FileByFilename(filename.to_string())),
        ..Default::default()
    };
    fetch_file_descriptors(client, request).await
}

async fn fetch_file_descriptors(
    client: &mut ServerReflectionClient<Channel>,
    request: ServerReflectionRequest,
) -> Result<Vec<prost_types::FileDescriptorProto>> {
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
                let fd = prost_types::FileDescriptorProto::decode(fd_bytes.as_slice())?;
                fds.push(fd);
            }
        }
    }
    Ok(fds)
}

// === Raw protobuf encoding/decoding helpers ===

/// Log the protobuf field structure of a response for debugging.
fn log_proto_fields(metric_name: &str, data: &[u8]) {
    let fields = parse_proto_fields(data);
    debug!("  Response fields for '{}':", metric_name);
    for (i, field) in fields.iter().enumerate() {
        let wire_name = match field.wire_type {
            0 => "varint",
            1 => "64bit",
            2 => "len-delim",
            5 => "32bit",
            _ => "unknown",
        };
        match field.wire_type {
            0 => debug!(
                "    field[{}] #{} {}: varint={}",
                i,
                field.field_number,
                wire_name,
                field.varint_value.unwrap_or(0)
            ),
            1 => {
                let bits = field.fixed64_value.unwrap_or(0);
                debug!(
                    "    field[{}] #{} {}: 0x{:016x} (as f64: {}, as i64: {})",
                    i,
                    field.field_number,
                    wire_name,
                    bits,
                    f64::from_bits(bits),
                    bits as i64
                );
            }
            2 => {
                let preview = if field.data.len() <= 40 {
                    if let Ok(s) = std::str::from_utf8(&field.data) {
                        format!("\"{}\"", s)
                    } else {
                        format!("{:02x?}", &field.data)
                    }
                } else {
                    format!("{} bytes", field.data.len())
                };
                // Try to parse as sub-message and show its fields
                let sub_info = if let Some(sub_fields) = try_parse_as_message(&field.data) {
                    let sub_descs: Vec<String> = sub_fields
                        .iter()
                        .map(|sf| match sf.wire_type {
                            0 => format!(
                                "#{}=varint({})",
                                sf.field_number,
                                sf.varint_value.unwrap_or(0)
                            ),
                            1 => {
                                let bits = sf.fixed64_value.unwrap_or(0);
                                format!("#{}=f64({})", sf.field_number, f64::from_bits(bits))
                            }
                            2 => {
                                // Recurse one more level to show sub-sub-message fields
                                if let Some(ssf) = try_parse_as_message(&sf.data) {
                                    let ss_descs: Vec<String> = ssf
                                        .iter()
                                        .map(|f| match f.wire_type {
                                            0 => format!(
                                                "#{}=v({})",
                                                f.field_number,
                                                f.varint_value.unwrap_or(0)
                                            ),
                                            1 => format!(
                                                "#{}=f64({})",
                                                f.field_number,
                                                f64::from_bits(f.fixed64_value.unwrap_or(0))
                                            ),
                                            2 => format!("#{}=b({})", f.field_number, f.data.len()),
                                            5 => format!(
                                                "#{}=f32({})",
                                                f.field_number,
                                                f32::from_bits(f.fixed32_value.unwrap_or(0))
                                            ),
                                            _ => format!("#{}=?", f.field_number),
                                        })
                                        .collect();
                                    format!("#{}=msg[{}]", sf.field_number, ss_descs.join(", "))
                                } else {
                                    format!("#{}=bytes({})", sf.field_number, sf.data.len())
                                }
                            }
                            5 => format!(
                                "#{}=f32({})",
                                sf.field_number,
                                f32::from_bits(sf.fixed32_value.unwrap_or(0))
                            ),
                            _ => format!("#{}=?", sf.field_number),
                        })
                        .collect();
                    format!(" -> sub-message: [{}]", sub_descs.join(", "))
                } else {
                    String::new()
                };
                debug!(
                    "    field[{}] #{} {}: {}{}",
                    i, field.field_number, wire_name, preview, sub_info
                );
            }
            5 => debug!(
                "    field[{}] #{} {}: 0x{:08x} (as f32: {})",
                i,
                field.field_number,
                wire_name,
                field.fixed32_value.unwrap_or(0),
                f32::from_bits(field.fixed32_value.unwrap_or(0))
            ),
            _ => debug!("    field[{}] #{} {}", i, field.field_number, wire_name),
        }
    }
}

/// Encode a protobuf message with a single string field.
fn encode_string_field(field_number: u32, value: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    // Wire type 2 (length-delimited) for strings
    let tag = (field_number << 3) | 2;
    prost::encoding::encode_varint(tag as u64, &mut buf);
    prost::encoding::encode_varint(value.len() as u64, &mut buf);
    buf.extend_from_slice(value.as_bytes());
    buf
}

/// Parse a metric response to extract per-device values.
///
/// Tries multiple strategies since we don't know the exact proto schema:
/// 1. Look for repeated sub-messages containing numeric values (per-device results)
/// 2. Look for top-level numeric values (single-device response)
fn parse_metric_response(data: &[u8]) -> Vec<DeviceMetricValue> {
    let fields = parse_proto_fields(data);

    // Strategy 1: Look for repeated sub-messages (field type = length-delimited)
    // that contain numeric fields (likely per-device results)
    for field in &fields {
        if field.wire_type == 2 {
            // Could be a sub-message or a string
            if try_parse_as_message(&field.data).is_some() {
                // Check if this sub-message has numeric fields
                let mut values_from_submessages = Vec::new();
                // First occurrence is already parsed, collect from all same-field-number entries
                let all_same_field: Vec<_> = fields
                    .iter()
                    .filter(|f| f.field_number == field.field_number && f.wire_type == 2)
                    .collect();

                for (i, sub) in all_same_field.iter().enumerate() {
                    if let Some(sub_fields) = try_parse_as_message(&sub.data) {
                        let device_id = find_int_field(&sub_fields).unwrap_or(i as i64) as i32;
                        if let Some(value) = find_float_field(&sub_fields) {
                            values_from_submessages.push(DeviceMetricValue { device_id, value });
                        }
                    }
                }

                if !values_from_submessages.is_empty() {
                    return values_from_submessages;
                }
            }
        }
    }

    // Strategy 2: Top-level numeric value (single device)
    if let Some(value) = find_float_field(&fields) {
        return vec![DeviceMetricValue {
            device_id: 0,
            value,
        }];
    }
    if let Some(value) = find_int_field(&fields) {
        return vec![DeviceMetricValue {
            device_id: 0,
            value: value as f64,
        }];
    }

    Vec::new()
}

/// A parsed protobuf field.
struct ProtoField {
    field_number: u32,
    wire_type: u32,
    data: Vec<u8>,
    /// For varint fields, the decoded value.
    varint_value: Option<u64>,
    /// For 64-bit fixed fields, the raw bytes.
    fixed64_value: Option<u64>,
    /// For 32-bit fixed fields, the raw bytes.
    fixed32_value: Option<u32>,
}

/// Parse raw protobuf bytes into fields.
fn parse_proto_fields(data: &[u8]) -> Vec<ProtoField> {
    let mut fields = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        let (tag, bytes_read) = match decode_varint(&data[pos..]) {
            Some(v) => v,
            None => break,
        };
        pos += bytes_read;

        let field_number = (tag >> 3) as u32;
        let wire_type = (tag & 0x7) as u32;

        if field_number == 0 {
            break; // Invalid
        }

        match wire_type {
            0 => {
                // Varint
                if let Some((value, vbytes)) = decode_varint(&data[pos..]) {
                    pos += vbytes;
                    fields.push(ProtoField {
                        field_number,
                        wire_type,
                        data: Vec::new(),
                        varint_value: Some(value),
                        fixed64_value: None,
                        fixed32_value: None,
                    });
                } else {
                    break;
                }
            }
            1 => {
                // 64-bit (fixed64, double)
                if pos + 8 <= data.len() {
                    let value = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
                    pos += 8;
                    fields.push(ProtoField {
                        field_number,
                        wire_type,
                        data: Vec::new(),
                        varint_value: None,
                        fixed64_value: Some(value),
                        fixed32_value: None,
                    });
                } else {
                    break;
                }
            }
            2 => {
                // Length-delimited (string, bytes, sub-message)
                if let Some((len, lbytes)) = decode_varint(&data[pos..]) {
                    pos += lbytes;
                    let len = len as usize;
                    if pos + len <= data.len() {
                        fields.push(ProtoField {
                            field_number,
                            wire_type,
                            data: data[pos..pos + len].to_vec(),
                            varint_value: None,
                            fixed64_value: None,
                            fixed32_value: None,
                        });
                        pos += len;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
            5 => {
                // 32-bit (fixed32, float)
                if pos + 4 <= data.len() {
                    let value = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
                    pos += 4;
                    fields.push(ProtoField {
                        field_number,
                        wire_type,
                        data: Vec::new(),
                        varint_value: None,
                        fixed64_value: None,
                        fixed32_value: Some(value),
                    });
                } else {
                    break;
                }
            }
            _ => break, // Unknown wire type (3, 4 are deprecated groups)
        }
    }

    fields
}

/// Try to parse bytes as a protobuf sub-message. Returns None if it doesn't look like valid protobuf.
fn try_parse_as_message(data: &[u8]) -> Option<Vec<ProtoField>> {
    if data.is_empty() {
        return None;
    }
    let fields = parse_proto_fields(data);
    // Heuristic: if we parsed at least one field and consumed most of the data,
    // it's probably a valid sub-message
    if fields.is_empty() {
        return None;
    }
    Some(fields)
}

/// Find the first float/double field value in a set of proto fields.
fn find_float_field(fields: &[ProtoField]) -> Option<f64> {
    for field in fields {
        // Wire type 1 = 64-bit (could be double or fixed64)
        if field.wire_type == 1 {
            if let Some(bits) = field.fixed64_value {
                let value = f64::from_bits(bits);
                if value.is_finite() {
                    return Some(value);
                }
            }
        }
        // Wire type 5 = 32-bit (could be float or fixed32)
        if field.wire_type == 5 {
            if let Some(bits) = field.fixed32_value {
                let value = f32::from_bits(bits) as f64;
                if value.is_finite() {
                    return Some(value);
                }
            }
        }
    }
    None
}

/// Find the first integer field value (varint or fixed).
fn find_int_field(fields: &[ProtoField]) -> Option<i64> {
    for field in fields {
        if field.wire_type == 0 {
            if let Some(v) = field.varint_value {
                return Some(v as i64);
            }
        }
    }
    None
}

/// Extract all string values from a protobuf message (for ListSupportedMetrics).
fn extract_all_strings(data: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();
    let fields = parse_proto_fields(data);
    for field in &fields {
        if field.wire_type == 2 {
            // Try as UTF-8 string
            if let Ok(s) = std::str::from_utf8(&field.data) {
                if !s.is_empty() && s.chars().all(|c| c.is_ascii_graphic() || c == '.') {
                    strings.push(s.to_string());
                }
            }
            // Also check sub-messages for nested strings
            if let Some(sub_fields) = try_parse_as_message(&field.data) {
                for sf in &sub_fields {
                    if sf.wire_type == 2 {
                        if let Ok(s) = std::str::from_utf8(&sf.data) {
                            if !s.is_empty() && s.chars().all(|c| c.is_ascii_graphic() || c == '.')
                            {
                                strings.push(s.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    strings
}

/// Decode a varint from a byte slice. Returns (value, bytes_consumed).
fn decode_varint(data: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    for (i, &byte) in data.iter().enumerate() {
        if shift >= 64 {
            return None;
        }
        value |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
        shift += 7;
    }
    None
}

// === Raw bytes gRPC codec ===

/// A gRPC codec that passes raw bytes through without protobuf encoding/decoding.
#[derive(Debug, Clone, Copy)]
struct RawBytesCodec;

impl tonic::codec::Codec for RawBytesCodec {
    type Encode = Bytes;
    type Decode = Bytes;
    type Encoder = RawBytesEncoder;
    type Decoder = RawBytesDecoder;

    fn encoder(&mut self) -> Self::Encoder {
        RawBytesEncoder
    }

    fn decoder(&mut self) -> Self::Decoder {
        RawBytesDecoder
    }
}

#[derive(Debug, Clone)]
struct RawBytesEncoder;

impl tonic::codec::Encoder for RawBytesEncoder {
    type Item = Bytes;
    type Error = tonic::Status;

    fn encode(
        &mut self,
        item: Self::Item,
        dst: &mut tonic::codec::EncodeBuf<'_>,
    ) -> Result<(), Self::Error> {
        dst.put(item);
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct RawBytesDecoder;

impl tonic::codec::Decoder for RawBytesDecoder {
    type Item = Bytes;
    type Error = tonic::Status;

    fn decode(
        &mut self,
        src: &mut tonic::codec::DecodeBuf<'_>,
    ) -> Result<Option<Self::Item>, Self::Error> {
        let len = src.remaining();
        if len == 0 {
            return Ok(None);
        }
        Ok(Some(src.copy_to_bytes(len)))
    }
}
