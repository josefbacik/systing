//! Shared constants for trace processing.
//!
//! These constants are used across different parts of the trace system.
//! Some may appear unused in certain build configurations.

use std::sync::LazyLock;

use regex::Regex;

/// Track name for network interface metadata in Perfetto traces.
#[allow(dead_code)]
pub const NETWORK_INTERFACES_TRACK_NAME: &str = "Network Interfaces";

/// Batch size for writing records to parquet.
#[allow(dead_code)]
pub const PARQUET_BATCH_SIZE: usize = 100_000;

/// Static regex for parsing socket track names. Compiled once at first use.
/// Pattern: Socket {socket_id}:{protocol}:{src_ip}:{src_port}->{dest_ip}:{dest_port}
/// Uses non-greedy matching (.+?) to correctly handle IPv6 addresses with colons.
#[allow(dead_code)]
pub static SOCKET_TRACK_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^Socket (\d+):([A-Z]+):(.+?):(\d+)->(.+?):(\d+)$")
        .expect("Invalid socket track regex pattern")
});
