//! gRPC reflection utility to dump TPU RuntimeMetricService proto descriptors.
//!
//! Used by `systing-util dump-tpu-proto` to capture the proto schema from a live
//! TPU runtime. The hand-written prost types in `gen/tpu_metric_service.rs` were
//! reverse-engineered from the output of this tool.

use std::collections::HashSet;
use std::time::Duration;

use anyhow::{Context, Result};
use prost::Message;
use tokio_stream::StreamExt;
use tonic::transport::Channel;
use tonic_reflection::pb::v1alpha::server_reflection_client::ServerReflectionClient;
use tonic_reflection::pb::v1alpha::server_reflection_request::MessageRequest;
use tonic_reflection::pb::v1alpha::{server_reflection_response, ServerReflectionRequest};

/// Dump proto file descriptors from a TPU RuntimeMetricService via gRPC reflection.
///
/// Prints all proto definitions to stdout and writes a serialized
/// `FileDescriptorSet` to `tpu_metrics_descriptor.bin` in the current directory.
pub async fn dump_tpu_protos(addr: &str) -> Result<()> {
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

    let num_files = all_fds.len();
    let fds = prost_types::FileDescriptorSet { file: all_fds };
    let encoded = fds.encode_to_vec();
    let dump_path = std::env::current_dir()
        .unwrap_or_default()
        .join("tpu_metrics_descriptor.bin");
    std::fs::write(&dump_path, &encoded)?;
    println!(
        "\nWrote serialized FileDescriptorSet to {} ({} bytes, {} files)",
        dump_path.display(),
        encoded.len(),
        num_files
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
    client: &mut ServerReflectionClient<Channel>,
) -> Result<Vec<String>> {
    let request = ServerReflectionRequest {
        message_request: Some(MessageRequest::ListServices(String::new())),
        ..Default::default()
    };
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    tx.send(request).await?;
    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    let mut resp = client.server_reflection_info(stream).await?.into_inner();
    let mut names = Vec::new();
    if let Some(r) = resp.next().await {
        let r = r?;
        if let Some(server_reflection_response::MessageResponse::ListServicesResponse(list)) =
            r.message_response
        {
            for svc in &list.service {
                names.push(svc.name.clone());
            }
        }
    }
    Ok(names)
}

async fn reflection_file_containing_symbol(
    client: &mut ServerReflectionClient<Channel>,
    symbol: &str,
) -> Result<Vec<prost_types::FileDescriptorProto>> {
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
    client: &mut ServerReflectionClient<Channel>,
    filename: &str,
) -> Result<Vec<prost_types::FileDescriptorProto>> {
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
    client: &mut ServerReflectionClient<Channel>,
    request: ServerReflectionRequest,
) -> Result<Vec<prost_types::FileDescriptorProto>> {
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    tx.send(request).await?;
    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    let mut resp = client.server_reflection_info(stream).await?.into_inner();
    let mut fds = Vec::new();
    if let Some(r) = resp.next().await {
        let r = r?;
        if let Some(server_reflection_response::MessageResponse::FileDescriptorResponse(fdr)) =
            r.message_response
        {
            for fd_bytes in &fdr.file_descriptor_proto {
                fds.push(prost_types::FileDescriptorProto::decode(
                    fd_bytes.as_slice(),
                )?);
            }
        }
    }
    Ok(fds)
}
