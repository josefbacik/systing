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
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use tracing::{debug, info, warn};

/// Result of service discovery, including namespace information.
#[derive(Debug, Clone)]
pub struct DiscoveredService {
    /// Address to connect to (host:port).
    pub addr: String,
    /// PID whose network namespace contains the service.
    /// `None` means the service is in the host namespace.
    /// When `Some`, the caller should `setns` into `/proc/{pid}/ns/net`
    /// before connecting.
    pub namespace_pid: Option<u32>,
}

/// The well-known port used by the XLA/TPU runtime's profiler service.
pub const TPU_PROFILER_PORT: u16 = 8466;

/// The well-known port used by the TPU RuntimeMetricService.
pub const TPU_METRICS_PORT: u16 = 8431;

/// Discover the TPU profiler service address by scanning for listeners on port 8466.
///
/// Returns `Some(DiscoveredService)` if exactly one listener is found, `None` if no listeners
/// are found. Returns an error if multiple listeners are found (user must specify
/// `--tpu-service-addr`).
pub fn discover_profiler_service() -> Result<Option<DiscoveredService>> {
    discover_service_on_port(TPU_PROFILER_PORT, "TPU profiler")
}

/// Discover the TPU metrics service address by scanning for listeners on port 8431.
///
/// Returns `Some(DiscoveredService)` if exactly one listener is found.
/// The result includes namespace info so the caller can `setns` if needed.
pub fn discover_metrics_service() -> Result<Option<DiscoveredService>> {
    discover_service_on_port(TPU_METRICS_PORT, "TPU metrics")
}

/// Switch the calling thread's network namespace to that of the given PID.
///
/// **IMPORTANT**: This does NOT restore the original namespace. The calling thread
/// stays in the target namespace for the remainder of its lifetime. Intended for
/// dedicated worker threads that do all their I/O in the target namespace.
///
/// For callers that need to restore (e.g. brief enumeration), save
/// `/proc/self/ns/net` before calling and `setns` back manually.
pub fn enter_netns_permanent(pid: u32) -> Result<()> {
    let ns_path = format!("/proc/{}/ns/net", pid);
    let fd =
        std::fs::File::open(&ns_path).with_context(|| format!("Failed to open {}", ns_path))?;
    // SAFETY: fd is a valid open file descriptor to a namespace file.
    // CLONE_NEWNET is a valid namespace type. setns only affects the calling thread.
    let ret = unsafe { libc::setns(fd.as_raw_fd(), libc::CLONE_NEWNET) };
    if ret != 0 {
        bail!(
            "setns to {} failed: {}",
            ns_path,
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

/// A candidate listener found during the scan, with provenance for deduplication.
#[derive(Debug)]
struct Candidate {
    addr: String,
    /// PID whose namespace contains this listener. `None` for host namespace.
    namespace_pid: Option<u32>,
    /// Namespace inode symlink target, for deduplication.
    ns_inode: Option<PathBuf>,
}

/// Shared discovery logic: scan `/proc/net/tcp` (and network namespaces)
/// for listeners on the given port.
fn discover_service_on_port(port: u16, service_name: &str) -> Result<Option<DiscoveredService>> {
    info!("Searching for {} service on port {}...", service_name, port);

    let mut candidates: Vec<Candidate> = Vec::new();
    let mut total_listeners_scanned = 0u64;
    let mut total_namespaces_scanned = 0u64;

    let host_ns_inode = fs::read_link("/proc/1/ns/net").ok();

    // Scan host /proc/net/tcp first — this covers the host network namespace
    for path in &["/proc/net/tcp", "/proc/net/tcp6"] {
        let p = Path::new(path);
        match scan_proc_net_tcp(p, port) {
            Ok((found, listener_count)) => {
                total_listeners_scanned += listener_count;
                total_namespaces_scanned += 1;
                if !found.is_empty() {
                    info!("Found {} match(es) in {}", found.len(), path);
                    for addr in found {
                        candidates.push(Candidate {
                            addr,
                            namespace_pid: None,
                            ns_inode: host_ns_inode.clone(),
                        });
                    }
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
    if candidates.is_empty() {
        info!("No match in host netns, scanning other network namespaces...");
        let mut seen_ns_inodes = std::collections::HashSet::new();

        // Record the host netns inode to skip duplicates
        if let Some(ref link) = host_ns_inode {
            debug!("Host network namespace inode: {:?}", link);
            seen_ns_inodes.insert(link.clone());
        } else {
            debug!("Could not read /proc/1/ns/net (not running as PID 1's namespace?)");
        }

        let mut pids_checked = 0u64;
        let mut namespaces_skipped = 0u64;

        if let Ok(pids) = fs::read_dir("/proc") {
            for entry in pids.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                let pid: u32 = match name_str.parse() {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                pids_checked += 1;

                // Deduplicate by network namespace inode. If we can't read the
                // ns link (race: process exited, or permission denied), skip —
                // we can't setns into an unknown namespace anyway.
                let ns_path = entry.path().join("ns/net");
                let ns_link = match fs::read_link(&ns_path) {
                    Ok(link) => link,
                    Err(_) => continue,
                };
                if !seen_ns_inodes.insert(ns_link.clone()) {
                    namespaces_skipped += 1;
                    continue;
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
                                    pid
                                );
                            }
                            for addr in found {
                                candidates.push(Candidate {
                                    addr,
                                    namespace_pid: Some(pid),
                                    ns_inode: Some(ns_link.clone()),
                                });
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

    // Dedup by (addr, ns_inode) so two containers each binding 127.0.0.1:PORT
    // are correctly reported as distinct listeners.
    candidates.sort_by(|a, b| (a.addr.as_str(), &a.ns_inode).cmp(&(b.addr.as_str(), &b.ns_inode)));
    candidates.dedup_by(|a, b| a.addr == b.addr && a.ns_inode == b.ns_inode);

    info!(
        "Discovery complete: {} total listeners scanned across {} namespace(s), {} match(es) on port {}",
        total_listeners_scanned, total_namespaces_scanned, candidates.len(), port
    );

    match candidates.len() {
        0 => {
            warn!(
                "No {} service detected on port {}. Is a TPU workload running?",
                service_name, port
            );
            Ok(None)
        }
        1 => {
            let c = candidates.into_iter().next().unwrap();
            info!(
                "Discovered {} service at {}{}",
                service_name,
                c.addr,
                c.namespace_pid
                    .map(|p| format!(" (in netns of PID {})", p))
                    .unwrap_or_default()
            );
            Ok(Some(DiscoveredService {
                addr: c.addr,
                namespace_pid: c.namespace_pid,
            }))
        }
        _ => {
            let addrs: Vec<String> = candidates
                .iter()
                .map(|c| match c.namespace_pid {
                    Some(p) => format!("{} (netns pid {})", c.addr, p),
                    None => c.addr.clone(),
                })
                .collect();
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
/// Listeners on 0.0.0.0/:: are translated to 127.0.0.1 for the address string.
/// The caller is responsible for determining reachability (e.g. via `setns` for
/// services in non-host namespaces).
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

    /// Helper to write a synthetic /proc/net/tcp file for testing.
    fn write_proc_net_tcp(dir: &std::path::Path, lines: &[&str]) -> std::path::PathBuf {
        let path = dir.join("net_tcp");
        let mut content = String::from(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
        );
        for line in lines {
            content.push_str(line);
            content.push('\n');
        }
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn test_scan_unspecified_uses_loopback() {
        let dir = tempfile::TempDir::new().unwrap();
        // 0.0.0.0:8431 listening (port 0x20EF = 8431, state 0A = LISTEN)
        let path = write_proc_net_tcp(dir.path(), &[
            "   0: 00000000:20EF 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0",
        ]);
        let (addrs, count) = scan_proc_net_tcp(&path, 8431).unwrap();
        assert_eq!(count, 1);
        assert_eq!(addrs, vec!["127.0.0.1:8431"]);
    }

    #[test]
    fn test_scan_specific_ip() {
        let dir = tempfile::TempDir::new().unwrap();
        // 10.0.1.10:8431 listening
        let path = write_proc_net_tcp(dir.path(), &[
            "   0: 0A01000A:20EF 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0",
        ]);
        let (addrs, count) = scan_proc_net_tcp(&path, 8431).unwrap();
        assert_eq!(count, 1);
        assert_eq!(addrs, vec!["10.0.1.10:8431"]);
    }

    #[test]
    fn test_scan_no_match() {
        let dir = tempfile::TempDir::new().unwrap();
        // Listener on port 9090, not 8431
        let path = write_proc_net_tcp(dir.path(), &[
            "   0: 00000000:2382 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0",
        ]);
        let (addrs, count) = scan_proc_net_tcp(&path, 8431).unwrap();
        assert_eq!(count, 1); // 1 listener scanned
        assert!(addrs.is_empty()); // but no match on our port
    }
}
