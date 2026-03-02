//! gRPC client for the TPU profiler service.
//!
//! Connects to the XLA runtime's profiler service on port 8466 and captures
//! TPU profiling data as XSpace protobufs.

use std::time::Duration;

use anyhow::{Context, Result};
use tonic::transport::Channel;
use tracing::{debug, info};

use super::gen::profiler_service::{
    profile_options, ProfileOptions, ProfileRequest, ProfilerServiceClient,
};
use super::gen::xplane::XSpace;

/// Client for the TPU profiler gRPC service.
pub struct TpuProfilerClient {
    service_addr: String,
}

impl TpuProfilerClient {
    pub fn new(service_addr: String) -> Self {
        Self { service_addr }
    }

    /// Capture a TPU profile for the specified duration.
    ///
    /// Connects to the profiler service, issues a `Profile` RPC, and returns the
    /// XSpace protobuf containing all profiling data.
    pub async fn capture_profile(&self, duration_ms: u64) -> Result<XSpace> {
        let endpoint = format!("http://{}", self.service_addr);
        debug!("Connecting to TPU profiler at {}", endpoint);

        let channel = Channel::from_shared(endpoint)
            .context("invalid service address")?
            .connect_timeout(Duration::from_secs(10))
            // Profile capture can take duration + overhead
            .timeout(Duration::from_secs(duration_ms / 1000 + 120))
            .connect()
            .await
            .with_context(|| {
                format!(
                    "Failed to connect to TPU profiler service at {}",
                    self.service_addr
                )
            })?;

        let mut client =
            ProfilerServiceClient::new(channel).max_decoding_message_size(i32::MAX as usize);

        let request = ProfileRequest {
            duration_ms,
            emit_xspace: true,
            opts: Some(ProfileOptions {
                device_type: profile_options::DeviceType::Tpu as i32,
                device_tracer_level: 1,
                host_tracer_level: 1,
                ..Default::default()
            }),
            ..Default::default()
        };

        info!(
            "Requesting TPU profile capture for {}ms from {}",
            duration_ms, self.service_addr
        );

        let response = client
            .profile(request)
            .await
            .context("TPU profile capture RPC failed")?
            .into_inner();

        if response.empty_trace {
            anyhow::bail!(
                "TPU profiler returned an empty trace. Is a TPU workload actively running?"
            );
        }

        let xspace = response
            .xspace
            .context("TPU profiler response did not contain XSpace data")?;

        info!(
            "Received TPU profile: {} planes, {} hostnames",
            xspace.planes.len(),
            xspace.hostnames.len()
        );

        Ok(xspace)
    }
}
