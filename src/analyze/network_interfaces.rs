use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Result};
use serde::Serialize;

use super::{to_u64, trace_id_filter, AnalyzeDb};

/// Parameters for network interfaces analysis.
#[derive(Debug, Clone, Default)]
pub struct NetworkInterfacesParams {
    pub trace_id: Option<String>,
}

/// Result of network interfaces analysis.
#[derive(Debug, Serialize)]
pub struct NetworkInterfacesResult {
    pub traces: Vec<TraceNetworkStats>,
}

/// Per-trace network stats (each trace_id corresponds to one tracing session).
#[derive(Debug, Serialize)]
pub struct TraceNetworkStats {
    pub trace_id: String,
    pub interfaces: Vec<InterfaceStats>,
}

/// Per-interface summary.
#[derive(Debug, Serialize)]
pub struct InterfaceStats {
    pub namespace: String,
    pub interface_name: String,
    /// IP addresses assigned to this interface (only shown in JSON output).
    pub ip_addresses: Vec<String>,
    pub traffic: Vec<TrafficStats>,
    pub total_send_bytes: u64,
    pub total_recv_bytes: u64,
}

/// Per-protocol+address_family traffic with retransmit data (TCP only).
#[derive(Debug, Serialize)]
pub struct TrafficStats {
    pub protocol: String,
    pub address_family: String,
    pub send_bytes: u64,
    pub recv_bytes: u64,
    pub socket_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retransmit_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_tcp_packets: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retransmit_pct: Option<f64>,
}

/// Key for identifying an interface within a trace.
type IfaceKey = (String, String, String); // (trace_id, namespace, interface_name)

/// Per-interface traffic data grouped by (protocol, address_family).
struct IfaceTrafficData {
    entries: Vec<TrafficEntry>,
}

struct TrafficEntry {
    protocol: String,
    address_family: String,
    socket_count: u64,
    send_bytes: u64,
    recv_bytes: u64,
}

impl AnalyzeDb {
    /// Run network interfaces analysis.
    pub fn network_interfaces(
        &self,
        params: &NetworkInterfacesParams,
    ) -> Result<NetworkInterfacesResult> {
        if !self.table_exists("network_interface")? {
            bail!(
                "Database missing network_interface table. \
                 Is this a systing trace with network recording?"
            );
        }
        if !self.table_has_rows("network_interface")? {
            bail!("No network interface data found in database.");
        }

        let trace_id = params.trace_id.as_deref();

        // 1. Get all interfaces and their IP addresses (driving set)
        let ip_sql = build_ip_addresses_query(trace_id);
        let mut stmt = self.conn.prepare(&ip_sql)?;
        let mut rows = stmt.query([])?;

        // Collect: (trace_id, namespace, iface_name) -> set of IP addresses
        // Use BTreeMap for deterministic ordering
        let mut iface_ips: BTreeMap<IfaceKey, BTreeSet<String>> = BTreeMap::new();

        while let Some(row) = rows.next()? {
            let tid: String = row.get(0)?;
            let namespace: String = row.get(1)?;
            let interface_name: String = row.get(2)?;
            let ip_address: String = row.get(3)?;

            iface_ips
                .entry((tid, namespace, interface_name))
                .or_default()
                .insert(ip_address);
        }
        // Must drop before preparing next statement on the same connection
        drop(rows);
        drop(stmt);

        // 2. Get traffic stats grouped by interface
        let has_syscall =
            self.table_exists("network_syscall")? && self.table_exists("network_socket")?;

        let mut traffic_map: BTreeMap<IfaceKey, IfaceTrafficData> = BTreeMap::new();

        if has_syscall {
            let traffic_sql = build_traffic_query(trace_id);
            let mut stmt = self.conn.prepare(&traffic_sql)?;
            let mut rows = stmt.query([])?;

            while let Some(row) = rows.next()? {
                let tid: String = row.get(0)?;
                let namespace: String = row.get(1)?;
                let interface_name: String = row.get(2)?;
                let protocol: String = row.get(3)?;
                let address_family: String = row.get(4)?;
                let socket_count: i64 = row.get(5)?;
                let send_bytes: i64 = row.get(6)?;
                let recv_bytes: i64 = row.get(7)?;

                traffic_map
                    .entry((tid, namespace, interface_name))
                    .or_insert_with(|| IfaceTrafficData {
                        entries: Vec::new(),
                    })
                    .entries
                    .push(TrafficEntry {
                        protocol,
                        address_family,
                        socket_count: to_u64(socket_count),
                        send_bytes: to_u64(send_bytes),
                        recv_bytes: to_u64(recv_bytes),
                    });
            }
            drop(rows);
            drop(stmt);
        }

        // 3. Get retransmit stats (TCP only, keyed by interface + address_family)
        let has_packet =
            self.table_exists("network_packet")? && self.table_exists("network_socket")?;

        // Key: (trace_id, namespace, interface_name, address_family) -> (total_packets, retransmit_count)
        let mut retransmit_map: BTreeMap<(String, String, String, String), (u64, u64)> =
            BTreeMap::new();

        if has_packet {
            let retransmit_sql = build_retransmit_query(trace_id);
            let mut stmt = self.conn.prepare(&retransmit_sql)?;
            let mut rows = stmt.query([])?;

            while let Some(row) = rows.next()? {
                let tid: String = row.get(0)?;
                let namespace: String = row.get(1)?;
                let interface_name: String = row.get(2)?;
                let address_family: String = row.get(3)?;
                let total_packets: i64 = row.get(4)?;
                let retransmit_count: i64 = row.get(5)?;

                retransmit_map.insert(
                    (tid, namespace, interface_name, address_family),
                    (to_u64(total_packets), to_u64(retransmit_count)),
                );
            }
            drop(rows);
            drop(stmt);
        }

        // 4. Assemble results
        // Group interfaces by trace_id
        let mut trace_map: BTreeMap<String, Vec<InterfaceStats>> = BTreeMap::new();

        for ((tid, namespace, iface_name), ips) in &iface_ips {
            let ip_addresses: Vec<String> = ips.iter().cloned().collect();

            // Look up traffic entries directly by interface key
            let mut traffic: Vec<TrafficStats> = Vec::new();
            let mut total_send: u64 = 0;
            let mut total_recv: u64 = 0;

            if let Some(iface_traffic) =
                traffic_map.get(&(tid.clone(), namespace.clone(), iface_name.clone()))
            {
                for entry in &iface_traffic.entries {
                    total_send += entry.send_bytes;
                    total_recv += entry.recv_bytes;

                    let (retransmit_count, total_tcp_packets, retransmit_pct) =
                        if entry.protocol == "TCP" {
                            // Retransmit map is TCP-only by construction (query filters to TCP)
                            let key = (
                                tid.clone(),
                                namespace.clone(),
                                iface_name.clone(),
                                entry.address_family.clone(),
                            );
                            if let Some((total_pkt, retx)) = retransmit_map.get(&key) {
                                let pct = if *total_pkt > 0 {
                                    *retx as f64 / *total_pkt as f64 * 100.0
                                } else {
                                    0.0
                                };
                                (Some(*retx), Some(*total_pkt), Some(pct))
                            } else {
                                (Some(0), Some(0), Some(0.0))
                            }
                        } else {
                            (None, None, None)
                        };

                    traffic.push(TrafficStats {
                        protocol: entry.protocol.clone(),
                        address_family: entry.address_family.clone(),
                        send_bytes: entry.send_bytes,
                        recv_bytes: entry.recv_bytes,
                        socket_count: entry.socket_count,
                        retransmit_count,
                        total_tcp_packets,
                        retransmit_pct,
                    });
                }
            }

            let iface_stats = InterfaceStats {
                namespace: namespace.clone(),
                interface_name: iface_name.clone(),
                ip_addresses,
                traffic,
                total_send_bytes: total_send,
                total_recv_bytes: total_recv,
            };

            trace_map.entry(tid.clone()).or_default().push(iface_stats);
        }

        let traces: Vec<TraceNetworkStats> = trace_map
            .into_iter()
            .map(|(trace_id, interfaces)| TraceNetworkStats {
                trace_id,
                interfaces,
            })
            .collect();

        Ok(NetworkInterfacesResult { traces })
    }
}

// -- Network interfaces query builders --

fn build_ip_addresses_query(trace_id: Option<&str>) -> String {
    let filter = trace_id_filter(trace_id, "ni.");
    format!(
        "SELECT ni.trace_id, ni.namespace, ni.interface_name, ni.ip_address \
         FROM network_interface ni \
         WHERE 1=1{filter} \
         ORDER BY ni.trace_id, ni.namespace, ni.interface_name, ni.ip_address"
    )
}

fn build_traffic_query(trace_id: Option<&str>) -> String {
    let filter = trace_id_filter(trace_id, "ni.");
    format!(
        "SELECT ni.trace_id, ni.namespace, ni.interface_name, \
         s.protocol, s.address_family, \
         COUNT(DISTINCT s.socket_id) as socket_count, \
         COALESCE(SUM(CASE WHEN ns.event_type = 'sendmsg' THEN ns.bytes ELSE 0 END), 0) as send_bytes, \
         COALESCE(SUM(CASE WHEN ns.event_type = 'recvmsg' THEN ns.bytes ELSE 0 END), 0) as recv_bytes \
         FROM network_interface ni \
         JOIN network_socket s ON ni.ip_address = s.src_ip AND ni.trace_id = s.trace_id \
         LEFT JOIN network_syscall ns ON s.socket_id = ns.socket_id AND s.trace_id = ns.trace_id \
         WHERE 1=1{filter} \
         GROUP BY ni.trace_id, ni.namespace, ni.interface_name, s.protocol, s.address_family \
         ORDER BY ni.trace_id, ni.namespace, ni.interface_name, s.protocol, s.address_family"
    )
}

fn build_retransmit_query(trace_id: Option<&str>) -> String {
    let filter = trace_id_filter(trace_id, "ni.");
    format!(
        "SELECT ni.trace_id, ni.namespace, ni.interface_name, \
         s.address_family, \
         COUNT(*) as total_packets, \
         SUM(CASE WHEN np.is_retransmit THEN 1 ELSE 0 END) as retransmit_count \
         FROM network_interface ni \
         JOIN network_socket s ON ni.ip_address = s.src_ip AND ni.trace_id = s.trace_id \
         JOIN network_packet np ON s.socket_id = np.socket_id AND s.trace_id = np.trace_id \
         WHERE s.protocol = 'TCP' \
         AND np.event_type IN (\
             'TCP packet_send', 'TCP packet_enqueue', 'TCP rto_timeout'\
         ){filter} \
         GROUP BY ni.trace_id, ni.namespace, ni.interface_name, s.address_family \
         ORDER BY ni.trace_id, ni.namespace, ni.interface_name, s.address_family"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_ip_addresses_query_no_filter() {
        let sql = build_ip_addresses_query(None);
        assert!(sql.contains("FROM network_interface ni"));
        assert!(sql.contains("WHERE 1=1"));
        assert!(sql.contains("ORDER BY ni.trace_id"));
        assert!(!sql.contains("trace_id ="));
    }

    #[test]
    fn test_build_ip_addresses_query_with_filter() {
        let sql = build_ip_addresses_query(Some("trace-1"));
        assert!(sql.contains("ni.trace_id = 'trace-1'"));
    }

    #[test]
    fn test_build_traffic_query_joins() {
        let sql = build_traffic_query(None);
        assert!(sql.contains(
            "JOIN network_socket s ON ni.ip_address = s.src_ip AND ni.trace_id = s.trace_id"
        ));
        assert!(sql.contains(
            "LEFT JOIN network_syscall ns ON s.socket_id = ns.socket_id AND s.trace_id = ns.trace_id"
        ));
        assert!(sql.contains("COUNT(DISTINCT s.socket_id)"));
        assert!(sql.contains(
            "GROUP BY ni.trace_id, ni.namespace, ni.interface_name, s.protocol, s.address_family"
        ));
    }

    #[test]
    fn test_build_traffic_query_with_filter() {
        let sql = build_traffic_query(Some("t1"));
        assert!(sql.contains("ni.trace_id = 't1'"));
    }

    #[test]
    fn test_build_retransmit_query_filters_send_side() {
        let sql = build_retransmit_query(None);
        assert!(sql.contains("s.protocol = 'TCP'"));
        assert!(sql.contains("'TCP packet_send', 'TCP packet_enqueue', 'TCP rto_timeout'"));
        assert!(!sql.contains("'packet_send'"));
        assert!(sql.contains("SUM(CASE WHEN np.is_retransmit THEN 1 ELSE 0 END)"));
        assert!(
            sql.contains("GROUP BY ni.trace_id, ni.namespace, ni.interface_name, s.address_family")
        );
    }

    #[test]
    fn test_build_retransmit_query_with_filter() {
        let sql = build_retransmit_query(Some("t1"));
        assert!(sql.contains("ni.trace_id = 't1'"));
    }

    #[test]
    fn test_network_interfaces_params_default() {
        let params = NetworkInterfacesParams::default();
        assert!(params.trace_id.is_none());
    }
}
