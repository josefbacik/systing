//! Auto-discovery of TPU services by scanning for listeners on well-known ports.
//!
//! - Port 8466: XLA/TPU runtime profiler service
//! - Port 8431: TPU RuntimeMetricService (lightweight metrics)
//!
//! Scans `/proc/net/tcp` (and network namespaces) for listeners on these ports.
//!
//! Use `-v` (info) or `-vv` (debug) to see discovery diagnostics.

use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use anyhow::{bail, Result};
use tracing::{debug, info, warn};

/// The well-known port used by the XLA/TPU runtime's profiler service.
pub const TPU_PROFILER_PORT: u16 = 8466;

/// The well-known port used by the TPU RuntimeMetricService.
pub const TPU_METRICS_PORT: u16 = 8431;

/// Discover the TPU profiler service address by scanning for listeners on port 8466.
///
/// Returns `Some(addr)` if exactly one listener is found, `None` if no listeners are found.
/// Returns an error if multiple listeners are found (user must specify `--tpu-service-addr`).
pub fn discover_profiler_service() -> Result<Option<String>> {
    discover_service_on_port(TPU_PROFILER_PORT, "TPU profiler")
}

/// Discover the TPU metrics service address by scanning for listeners on port 8431.
///
/// Returns `Some(addr)` if exactly one listener is found, `None` if no listeners are found.
/// Returns an error if multiple listeners are found (user must specify `--tpu-metrics-addr`).
pub fn discover_metrics_service() -> Result<Option<String>> {
    discover_service_on_port(TPU_METRICS_PORT, "TPU metrics")
}

/// Shared discovery logic: scan `/proc/net/tcp` (and network namespaces)
/// for listeners on the given port.
fn discover_service_on_port(port: u16, service_name: &str) -> Result<Option<String>> {
    info!("Searching for {} service on port {}...", service_name, port);

    let mut addrs = Vec::new();
    let mut total_listeners_scanned = 0u64;
    let mut total_namespaces_scanned = 0u64;

    // Scan host /proc/net/tcp first — this covers the host network namespace
    for path in &["/proc/net/tcp", "/proc/net/tcp6"] {
        let p = Path::new(path);
        match scan_proc_net_tcp(p, port) {
            Ok((found, listener_count)) => {
                total_listeners_scanned += listener_count;
                total_namespaces_scanned += 1;
                if !found.is_empty() {
                    info!("Found {} match(es) in {}", found.len(), path);
                    addrs.extend(found);
                } else {
                    debug!(
                        "{}: scanned {} listeners, no match on port {}",
                        path, listener_count, port
                    );
                }
            }
            Err(e) => {
                debug!("Could not read {}: {}", path, e);
            }
        }
    }

    // Only scan per-PID network namespaces if the host scan found nothing.
    if addrs.is_empty() {
        info!("No match in host netns, scanning other network namespaces...");
        let mut seen_ns_inodes = std::collections::HashSet::new();

        // Record the host netns inode to skip duplicates
        if let Ok(link) = fs::read_link("/proc/1/ns/net") {
            debug!("Host network namespace inode: {:?}", link);
            seen_ns_inodes.insert(link);
        } else {
            debug!("Could not read /proc/1/ns/net (not running as PID 1's namespace?)");
        }

        let mut pids_checked = 0u64;
        let mut namespaces_skipped = 0u64;

        if let Ok(pids) = fs::read_dir("/proc") {
            for entry in pids.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if !name_str.chars().all(|c| c.is_ascii_digit()) {
                    continue;
                }
                pids_checked += 1;

                // Deduplicate by network namespace inode
                let ns_path = entry.path().join("ns/net");
                if let Ok(link) = fs::read_link(&ns_path) {
                    if !seen_ns_inodes.insert(link) {
                        namespaces_skipped += 1;
                        continue;
                    }
                }

                total_namespaces_scanned += 1;

                for suffix in &["net/tcp", "net/tcp6"] {
                    let tcp_path = entry.path().join(suffix);
                    match scan_proc_net_tcp(&tcp_path, port) {
                        Ok((found, listener_count)) => {
                            total_listeners_scanned += listener_count;
                            if !found.is_empty() {
                                info!(
                                    "Found {} match(es) in {} (pid {})",
                                    found.len(),
                                    tcp_path.display(),
                                    name_str
                                );
                            }
                            for addr in found {
                                if !addrs.contains(&addr) {
                                    addrs.push(addr);
                                }
                            }
                        }
                        Err(e) => {
                            debug!("Could not read {}: {}", tcp_path.display(), e);
                        }
                    }
                }
            }
        } else {
            warn!("Could not read /proc directory");
        }

        info!(
            "Scanned {} PIDs, {} unique network namespaces ({} skipped as duplicates)",
            pids_checked, total_namespaces_scanned, namespaces_skipped
        );
    }

    addrs.sort();
    addrs.dedup();

    info!(
        "Discovery complete: {} total listeners scanned across {} namespace(s), {} match(es) on port {}",
        total_listeners_scanned, total_namespaces_scanned, addrs.len(), port
    );

    match addrs.len() {
        0 => {
            warn!(
                "No {} service detected on port {}. Is a TPU workload running?",
                service_name, port
            );
            Ok(None)
        }
        1 => {
            let addr = &addrs[0];
            info!("Discovered {} service at {}", service_name, addr);
            Ok(Some(addr.clone()))
        }
        _ => {
            bail!(
                "Multiple {} service listeners found on port {}: {}. \
                 Please specify the address explicitly.",
                service_name,
                port,
                addrs.join(", ")
            );
        }
    }
}

/// Scan a /proc/net/tcp file for listeners on the given port.
///
/// Returns (matching addresses in "host:port" format, total listener count).
fn scan_proc_net_tcp(path: &Path, target_port: u16) -> Result<(Vec<String>, u64)> {
    let content = fs::read_to_string(path)?;
    let mut addrs = Vec::new();
    let mut listener_count = 0u64;

    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }

        let local_addr = fields[1];
        let state = fields[3];

        // 0A = TCP_LISTEN
        if state != "0A" {
            continue;
        }

        listener_count += 1;

        if let Some((ip, port)) = parse_proc_net_addr(local_addr) {
            debug!(
                "  listener: {} port {} (raw: {}) in {:?}",
                ip, port, local_addr, path
            );
            if port == target_port {
                let host = if ip.is_unspecified() {
                    format!("127.0.0.1:{}", port)
                } else {
                    format!("{}:{}", ip, port)
                };
                info!("Match! listener: {} (from {:?})", host, path);
                addrs.push(host);
            }
        } else {
            debug!(
                "  could not parse listener address: {} in {:?}",
                local_addr, path
            );
        }
    }

    Ok((addrs, listener_count))
}

/// Parse a hex address from /proc/net/tcp format (e.g., "0100007F:2112").
///
/// Returns (IpAddr, port) or None if parsing fails.
fn parse_proc_net_addr(addr_str: &str) -> Option<(IpAddr, u16)> {
    let (ip_hex, port_hex) = addr_str.split_once(':')?;

    let port = u16::from_str_radix(port_hex, 16).ok()?;

    match ip_hex.len() {
        8 => {
            // IPv4: stored as little-endian hex in /proc/net/tcp on x86
            let ip_bytes = u32::from_str_radix(ip_hex, 16).ok()?;
            let octets = ip_bytes.to_le_bytes();
            let ip = IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]));
            Some((ip, port))
        }
        32 => {
            // IPv6: stored as 4 groups of little-endian 32-bit hex words
            let mut bytes = [0u8; 16];
            for group in 0..4 {
                let word_hex = &ip_hex[group * 8..(group + 1) * 8];
                let word = u32::from_str_radix(word_hex, 16).ok()?;
                let word_bytes = word.to_le_bytes();
                bytes[group * 4..group * 4 + 4].copy_from_slice(&word_bytes);
            }

            let ip: IpAddr = if bytes[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] {
                // IPv4-mapped IPv6
                IpAddr::V4(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]))
            } else {
                IpAddr::V6(bytes.into())
            };
            Some((ip, port))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn test_parse_ipv4_loopback() {
        // 0100007F = 127.0.0.1 in little-endian, port 0x2112 = 8466
        let result = parse_proc_net_addr("0100007F:2112");
        assert!(result.is_some());
        let (ip, port) = result.unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(port, 8466);
    }

    #[test]
    fn test_parse_ipv4_any() {
        let result = parse_proc_net_addr("00000000:2112");
        assert!(result.is_some());
        let (ip, port) = result.unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(port, 8466);
    }

    #[test]
    fn test_parse_ipv6_any() {
        // :: (all zeros) in /proc/net/tcp6 format
        let result = parse_proc_net_addr("00000000000000000000000000000000:2112");
        assert!(result.is_some());
        let (ip, port) = result.unwrap();
        assert_eq!(ip, IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        assert_eq!(port, 8466);
    }

    #[test]
    fn test_parse_ipv6_mapped_ipv4() {
        // ::ffff:127.0.0.1 in /proc/net/tcp6 little-endian format
        // IPv6 = 0000:0000:0000:0000:0000:ffff:7f00:0001
        // 32-bit words in network order: 00000000 00000000 0000FFFF 7F000001
        // In little-endian host order:    00000000 00000000 FFFF0000 0100007F
        let result = parse_proc_net_addr("0000000000000000FFFF00000100007F:2112");
        assert!(result.is_some());
        let (ip, port) = result.unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(port, 8466);
    }

    #[test]
    fn test_parse_invalid_addr() {
        assert!(parse_proc_net_addr("invalid").is_none());
        assert!(parse_proc_net_addr("ZZZZZZZZ:2112").is_none());
        assert!(parse_proc_net_addr("0100007F").is_none());
    }
}
