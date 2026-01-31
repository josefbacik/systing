use std::collections::BTreeMap;

use anyhow::{bail, Result};
use serde::Serialize;

use super::{to_u64, trace_id_filter, AnalyzeDb};

/// Parameters for network connections analysis.
pub struct NetworkConnectionsParams {
    pub trace_id: Option<String>,
    pub pid: Option<u32>,
    pub tid: Option<u32>,
    /// Limit to top N connections per trace by total bytes. None means no limit.
    pub top_n: Option<usize>,
}

/// Result of network connections analysis.
#[derive(Debug, Serialize)]
pub struct NetworkConnectionsResult {
    pub traces: Vec<TraceConnectionStats>,
}

/// Per-trace connection stats.
#[derive(Debug, Serialize)]
pub struct TraceConnectionStats {
    pub trace_id: String,
    pub connections: Vec<ConnectionStats>,
}

/// Per-connection summary.
#[derive(Debug, Serialize)]
pub struct ConnectionStats {
    pub protocol: String,
    pub address_family: String,
    pub src_ip: String,
    pub src_port: i32,
    pub dest_ip: String,
    pub dest_port: i32,
    pub interface_name: String,
    pub namespace: String,
    pub send_bytes: u64,
    pub recv_bytes: u64,
    pub total_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retransmit_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_tcp_packets: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retransmit_pct: Option<f64>,
}

/// Intermediate struct for collecting raw connection data from Step 1 query.
struct RawConnection {
    trace_id: String,
    socket_id: i64,
    protocol: String,
    address_family: String,
    src_ip: String,
    src_port: i32,
    dest_ip: String,
    dest_port: i32,
    interface_name: String,
    namespace: String,
    send_bytes: u64,
    recv_bytes: u64,
}

impl AnalyzeDb {
    /// Run network connections analysis.
    pub fn network_connections(
        &self,
        params: &NetworkConnectionsParams,
    ) -> Result<NetworkConnectionsResult> {
        if params.pid.is_some() && params.tid.is_some() {
            bail!("Cannot filter by both pid and tid simultaneously.");
        }

        if !self.table_exists("network_socket")? {
            bail!(
                "Database missing network_socket table. \
                 Is this a systing trace with network recording?"
            );
        }
        if !self.table_has_rows("network_socket")? {
            bail!("No network socket data found in database.");
        }

        let trace_id = params.trace_id.as_deref();
        let has_interface = self.table_exists("network_interface")?;
        let has_syscall = self.table_exists("network_syscall")?;

        if (params.pid.is_some() || params.tid.is_some()) && !has_syscall {
            bail!(
                "Cannot filter by pid/tid: network_syscall table not found. \
                 The trace may not have captured syscall data."
            );
        }

        // Step 1: Get connections with traffic data
        let traffic_sql = build_connections_query(
            trace_id,
            params.pid,
            params.tid,
            params.top_n,
            has_interface,
            has_syscall,
        );
        let mut stmt = self.conn.prepare(&traffic_sql)?;
        let mut rows = stmt.query([])?;

        let mut connections: Vec<RawConnection> = Vec::new();

        while let Some(row) = rows.next()? {
            connections.push(RawConnection {
                trace_id: row.get(0)?,
                socket_id: row.get(1)?,
                protocol: row.get(2)?,
                address_family: row.get(3)?,
                src_ip: row.get(4)?,
                src_port: row.get(5)?,
                dest_ip: row.get(6)?,
                dest_port: row.get(7)?,
                interface_name: row.get(8)?,
                namespace: row.get(9)?,
                send_bytes: {
                    let v: i64 = row.get(10)?;
                    to_u64(v)
                },
                recv_bytes: {
                    let v: i64 = row.get(11)?;
                    to_u64(v)
                },
            });
        }
        // Must drop before preparing next statement on the same connection
        drop(rows);
        drop(stmt);

        // Step 2: Get TCP retransmit data
        let has_packet = self.table_exists("network_packet")?;

        // Key: (trace_id, socket_id) -> (total_packets, retransmit_count)
        let mut retransmit_map: BTreeMap<(String, i64), (u64, u64)> = BTreeMap::new();

        if has_packet {
            // Collect unique TCP socket_ids from Step 1 results
            let tcp_socket_ids: Vec<i64> = connections
                .iter()
                .filter(|c| c.protocol == "TCP")
                .map(|c| c.socket_id)
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();

            if !tcp_socket_ids.is_empty() {
                let retransmit_sql = build_retransmit_query(trace_id, &tcp_socket_ids);
                let mut stmt = self.conn.prepare(&retransmit_sql)?;
                let mut rows = stmt.query([])?;

                while let Some(row) = rows.next()? {
                    let tid: String = row.get(0)?;
                    let sid: i64 = row.get(1)?;
                    let total_packets: i64 = row.get(2)?;
                    let retransmit_count: i64 = row.get(3)?;

                    retransmit_map.insert(
                        (tid, sid),
                        (to_u64(total_packets), to_u64(retransmit_count)),
                    );
                }
                drop(rows);
                drop(stmt);
            }
        }

        // Step 3: Assemble results grouped by trace_id
        let mut trace_map: BTreeMap<String, Vec<ConnectionStats>> = BTreeMap::new();

        for conn in connections {
            let (retransmit_count, total_tcp_packets, retransmit_pct) = if conn.protocol == "TCP" {
                let key = (conn.trace_id.clone(), conn.socket_id);
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

            let total_bytes = conn.send_bytes + conn.recv_bytes;

            trace_map
                .entry(conn.trace_id)
                .or_default()
                .push(ConnectionStats {
                    protocol: conn.protocol,
                    address_family: conn.address_family,
                    src_ip: conn.src_ip,
                    src_port: conn.src_port,
                    dest_ip: conn.dest_ip,
                    dest_port: conn.dest_port,
                    interface_name: conn.interface_name,
                    namespace: conn.namespace,
                    send_bytes: conn.send_bytes,
                    recv_bytes: conn.recv_bytes,
                    total_bytes,
                    retransmit_count,
                    total_tcp_packets,
                    retransmit_pct,
                });
        }

        let traces: Vec<TraceConnectionStats> = trace_map
            .into_iter()
            .map(|(trace_id, connections)| TraceConnectionStats {
                trace_id,
                connections,
            })
            .collect();

        Ok(NetworkConnectionsResult { traces })
    }
}

// -- Query builders --

fn build_connections_query(
    trace_id: Option<&str>,
    pid: Option<u32>,
    tid: Option<u32>,
    top_n: Option<usize>,
    has_interface: bool,
    has_syscall: bool,
) -> String {
    let trace_filter = trace_id_filter(trace_id, "ns.");

    // Interface join pieces
    let iface_select = if has_interface {
        "COALESCE(ni.interface_name, 'unknown') AS interface_name, \
         COALESCE(ni.namespace, 'unknown') AS namespace"
    } else {
        "'unknown' AS interface_name, 'unknown' AS namespace"
    };

    let iface_join = if has_interface {
        "LEFT JOIN network_interface ni \
         ON ns.trace_id = ni.trace_id AND ns.src_ip = ni.ip_address"
    } else {
        ""
    };

    let iface_group = if has_interface {
        ", ni.interface_name, ni.namespace"
    } else {
        ""
    };

    // Syscall join pieces
    // pid/tid filter goes in WHERE clause: when active, this effectively converts
    // the LEFT JOIN into an INNER JOIN, so only connections with matching syscalls
    // are returned. When not active, the LEFT JOIN is preserved and connections
    // with zero bytes still appear.
    let pid_tid_where = if let Some(pid_val) = pid {
        format!(" AND nsc.pid = {pid_val}")
    } else if let Some(tid_val) = tid {
        format!(" AND nsc.tid = {tid_val}")
    } else {
        String::new()
    };

    let (syscall_select, syscall_join) = if has_syscall {
        (
            "COALESCE(SUM(CASE WHEN nsc.event_type = 'sendmsg' THEN nsc.bytes ELSE 0 END), 0) \
             AS send_bytes, \
             COALESCE(SUM(CASE WHEN nsc.event_type = 'recvmsg' THEN nsc.bytes ELSE 0 END), 0) \
             AS recv_bytes"
                .to_string(),
            "LEFT JOIN network_syscall nsc \
             ON ns.trace_id = nsc.trace_id AND ns.socket_id = nsc.socket_id"
                .to_string(),
        )
    } else {
        (
            "0 AS send_bytes, 0 AS recv_bytes".to_string(),
            String::new(),
        )
    };

    // When top_n is set, use QUALIFY with ROW_NUMBER to limit per-trace
    // rather than globally. This ensures each trace gets up to top_n connections.
    let qualify_clause = match top_n {
        Some(n) => format!(
            "QUALIFY ROW_NUMBER() OVER (\
             PARTITION BY ns.trace_id \
             ORDER BY (send_bytes + recv_bytes) DESC\
             ) <= {n}"
        ),
        None => String::new(),
    };

    format!(
        "SELECT ns.trace_id, ns.socket_id, ns.protocol, ns.address_family, \
         ns.src_ip, ns.src_port, ns.dest_ip, ns.dest_port, \
         {iface_select}, \
         {syscall_select} \
         FROM network_socket ns \
         {iface_join} \
         {syscall_join} \
         WHERE 1=1{trace_filter}{pid_tid_where} \
         GROUP BY ns.trace_id, ns.socket_id, ns.protocol, ns.address_family, \
         ns.src_ip, ns.src_port, ns.dest_ip, ns.dest_port{iface_group} \
         {qualify_clause} \
         ORDER BY ns.trace_id, (send_bytes + recv_bytes) DESC"
    )
}

fn build_retransmit_query(trace_id: Option<&str>, socket_ids: &[i64]) -> String {
    let trace_filter = trace_id_filter(trace_id, "np.");

    // Build socket_id IN clause
    let id_list: Vec<String> = socket_ids.iter().map(|sid| sid.to_string()).collect();
    let socket_in = format!(" AND np.socket_id IN ({})", id_list.join(", "));

    format!(
        "SELECT np.trace_id, np.socket_id, \
         COUNT(*) AS total_packets, \
         SUM(CASE WHEN np.is_retransmit THEN 1 ELSE 0 END) AS retransmit_count \
         FROM network_packet np \
         JOIN network_socket ns \
         ON np.trace_id = ns.trace_id AND np.socket_id = ns.socket_id \
         WHERE ns.protocol = 'TCP' \
         AND np.event_type IN (\
         'TCP packet_send', 'TCP packet_enqueue', 'TCP rto_timeout'\
         ){trace_filter}{socket_in} \
         GROUP BY np.trace_id, np.socket_id"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_connections_query_no_filters() {
        let sql = build_connections_query(None, None, None, Some(50), true, true);
        assert!(sql.contains("FROM network_socket ns"));
        assert!(sql.contains("LEFT JOIN network_interface ni"));
        assert!(sql.contains("LEFT JOIN network_syscall nsc"));
        assert!(sql.contains("WHERE 1=1"));
        assert!(sql.contains("QUALIFY ROW_NUMBER()"));
        assert!(sql.contains("PARTITION BY ns.trace_id"));
        assert!(sql.contains("<= 50"));
        assert!(!sql.contains("nsc.pid"));
        assert!(!sql.contains("nsc.tid"));
        assert!(!sql.contains("ns.trace_id = '"));
    }

    #[test]
    fn test_build_connections_query_with_trace_id() {
        let sql = build_connections_query(Some("trace-1"), None, None, Some(50), true, true);
        assert!(sql.contains("ns.trace_id = 'trace-1'"));
    }

    #[test]
    fn test_build_connections_query_with_pid() {
        let sql = build_connections_query(None, Some(1234), None, Some(50), true, true);
        assert!(sql.contains("nsc.pid = 1234"));
        assert!(!sql.contains("nsc.tid"));
    }

    #[test]
    fn test_build_connections_query_with_tid() {
        let sql = build_connections_query(None, None, Some(5678), Some(50), true, true);
        assert!(sql.contains("nsc.tid = 5678"));
        assert!(!sql.contains("nsc.pid"));
    }

    #[test]
    fn test_build_connections_query_no_interface_table() {
        let sql = build_connections_query(None, None, None, Some(50), false, true);
        assert!(!sql.contains("network_interface"));
        assert!(sql.contains("'unknown' AS interface_name"));
        assert!(sql.contains("'unknown' AS namespace"));
    }

    #[test]
    fn test_build_connections_query_no_syscall_table() {
        let sql = build_connections_query(None, None, None, Some(50), true, false);
        assert!(!sql.contains("network_syscall"));
        assert!(sql.contains("0 AS send_bytes"));
        assert!(sql.contains("0 AS recv_bytes"));
    }

    #[test]
    fn test_build_connections_query_event_type_exact_match() {
        let sql = build_connections_query(None, None, None, Some(50), true, true);
        assert!(sql.contains("nsc.event_type = 'sendmsg'"));
        assert!(sql.contains("nsc.event_type = 'recvmsg'"));
        assert!(!sql.contains("LIKE"));
    }

    #[test]
    fn test_build_connections_query_group_by_includes_socket_id() {
        let sql = build_connections_query(None, None, None, Some(50), true, true);
        assert!(sql.contains("ns.socket_id"));
        assert!(sql.contains("GROUP BY ns.trace_id, ns.socket_id"));
    }

    #[test]
    fn test_build_connections_query_no_limit() {
        let sql = build_connections_query(None, None, None, None, true, true);
        assert!(!sql.contains("QUALIFY"));
        assert!(!sql.contains("ROW_NUMBER"));
        assert!(sql.contains("ORDER BY ns.trace_id"));
    }

    #[test]
    fn test_build_retransmit_query_basic() {
        let socket_ids = vec![100i64, 200i64];
        let sql = build_retransmit_query(None, &socket_ids);
        assert!(sql.contains("ns.protocol = 'TCP'"));
        assert!(sql.contains("'TCP packet_send', 'TCP packet_enqueue', 'TCP rto_timeout'"));
        assert!(sql.contains("SUM(CASE WHEN np.is_retransmit THEN 1 ELSE 0 END)"));
        assert!(sql.contains("COUNT(*)"));
        assert!(sql.contains("np.socket_id IN (100, 200)"));
        assert!(sql.contains("GROUP BY np.trace_id, np.socket_id"));
    }

    #[test]
    fn test_build_retransmit_query_with_trace_id() {
        let socket_ids = vec![1i64];
        let sql = build_retransmit_query(Some("t1"), &socket_ids);
        assert!(sql.contains("np.trace_id = 't1'"));
    }
}
