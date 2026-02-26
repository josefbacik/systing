//! Auto-discovery of TPU profiler service on port 8466.
//!
//! Scans `/proc/net/tcp` (and network namespaces) for listeners on the
//! well-known TPU profiler service port.

use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use anyhow::{bail, Result};
use tracing::{debug, info, warn};

/// The well-known port used by the XLA/TPU runtime's profiler service.
pub const TPU_PROFILER_PORT: u16 = 8466;

/// Discover the TPU profiler service address by scanning for listeners on port 8466.
///
/// Returns `Some(addr)` if exactly one listener is found, `None` if no listeners are found.
/// Returns an error if multiple listeners are found (user must specify `--tpu-service-addr`).
pub fn discover_profiler_service() -> Result<Option<String>> {
    let mut addrs = Vec::new();

    // Scan host /proc/net/tcp first — this covers the host network namespace
    if let Ok(found) = scan_proc_net_tcp(Path::new("/proc/net/tcp")) {
        addrs.extend(found);
    }
    if let Ok(found) = scan_proc_net_tcp(Path::new("/proc/net/tcp6")) {
        addrs.extend(found);
    }

    // Only scan per-PID network namespaces if the host scan found nothing.
    // Most processes share the host network namespace, so per-PID scanning
    // is only useful for finding listeners in other network namespaces (e.g., pods).
    if addrs.is_empty() {
        let mut seen_ns_inodes = std::collections::HashSet::new();

        // Record the host netns inode to skip duplicates
        if let Ok(link) = fs::read_link("/proc/1/ns/net") {
            seen_ns_inodes.insert(link);
        }

        if let Ok(pids) = fs::read_dir("/proc") {
            for entry in pids.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if !name_str.chars().all(|c| c.is_ascii_digit()) {
                    continue;
                }

                // Deduplicate by network namespace inode
                let ns_path = entry.path().join("ns/net");
                if let Ok(link) = fs::read_link(&ns_path) {
                    if !seen_ns_inodes.insert(link) {
                        continue; // Already scanned this network namespace
                    }
                }

                let tcp_path = entry.path().join("net/tcp");
                if let Ok(found) = scan_proc_net_tcp(&tcp_path) {
                    for addr in found {
                        if !addrs.contains(&addr) {
                            addrs.push(addr);
                        }
                    }
                }
                let tcp6_path = entry.path().join("net/tcp6");
                if let Ok(found) = scan_proc_net_tcp(&tcp6_path) {
                    for addr in found {
                        if !addrs.contains(&addr) {
                            addrs.push(addr);
                        }
                    }
                }
            }
        }
    }

    addrs.sort();
    addrs.dedup();

    match addrs.len() {
        0 => {
            warn!(
                "No TPU profiler service detected on port {}. Is a TPU workload running?",
                TPU_PROFILER_PORT
            );
            Ok(None)
        }
        1 => {
            let addr = &addrs[0];
            info!("Discovered TPU profiler service at {}", addr);
            Ok(Some(addr.clone()))
        }
        _ => {
            bail!(
                "Multiple TPU profiler service listeners found on port {}: {}. \
                 Please specify --tpu-service-addr to select one.",
                TPU_PROFILER_PORT,
                addrs.join(", ")
            );
        }
    }
}

/// Scan a /proc/net/tcp file for listeners on the TPU profiler port.
///
/// Returns addresses in "host:port" format.
fn scan_proc_net_tcp(path: &Path) -> Result<Vec<String>> {
    let content = fs::read_to_string(path)?;
    let mut addrs = Vec::new();

    for line in content.lines().skip(1) {
        // Format: sl local_address rem_address st ...
        // local_address is hex_ip:hex_port
        // st: 0A = TCP_LISTEN
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }

        let local_addr = fields[1];
        let state = fields[3];

        if state != "0A" {
            continue;
        }

        if let Some((ip, port)) = parse_proc_net_addr(local_addr) {
            if port == TPU_PROFILER_PORT {
                let host = if ip.is_unspecified() {
                    // Listening on 0.0.0.0 / :: — connect via loopback
                    format!("127.0.0.1:{}", port)
                } else {
                    format!("{}:{}", ip, port)
                };
                debug!("Found TPU profiler listener: {} (from {:?})", host, path);
                addrs.push(host);
            }
        }
    }

    Ok(addrs)
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
