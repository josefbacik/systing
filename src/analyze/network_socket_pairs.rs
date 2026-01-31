use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Result};
use serde::Serialize;

use super::{to_u64, AnalyzeDb};

/// Parameters for network socket pairs analysis.
pub struct NetworkSocketPairsParams {
    pub trace_id: Option<String>,
    pub dest_port: Option<i32>,
    pub ip: Option<String>,
    pub top_n: Option<usize>,
    pub exclude_loopback: bool,
}

/// Result of network socket pairs analysis.
#[derive(Debug, Serialize)]
pub struct NetworkSocketPairsResult {
    pub pairs: Vec<SocketPair>,
}

/// A matched socket pair (both sides of a connection).
#[derive(Debug, Serialize)]
pub struct SocketPair {
    pub protocol: String,
    pub address_family: String,
    pub total_bytes: u64,
    pub cross_trace: bool,
    pub side_a: SocketSide,
    pub side_b: SocketSide,
}

/// One side of a socket pair.
#[derive(Debug, Serialize)]
pub struct SocketSide {
    pub trace_id: String,
    pub socket_id: i64,
    pub src_ip: String,
    pub src_port: i32,
    pub dest_ip: String,
    pub dest_port: i32,
    pub interface_name: String,
    pub namespace: String,
    pub send_bytes: u64,
    pub recv_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retransmit_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_tcp_packets: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retransmit_pct: Option<f64>,
}

/// Raw pair from the self-join query (Step 1).
struct RawPair {
    trace_a: String,
    sock_a: i64,
    protocol: String,
    address_family: String,
    a_src_ip: String,
    a_src_port: i32,
    a_dest_ip: String,
    a_dest_port: i32,
    trace_b: String,
    sock_b: i64,
    b_src_ip: String,
    b_src_port: i32,
    b_dest_ip: String,
    b_dest_port: i32,
}

impl AnalyzeDb {
    /// Run network socket pairs analysis.
    pub fn network_socket_pairs(
        &self,
        params: &NetworkSocketPairsParams,
    ) -> Result<NetworkSocketPairsResult> {
        if !self.table_exists("network_socket")? {
            bail!(
                "Database missing network_socket table. \
                 Is this a systing trace with network recording?"
            );
        }
        if !self.table_has_rows("network_socket")? {
            bail!("No network socket data found in database.");
        }

        // Step 1: Find matched socket pairs via self-join
        let pairs_sql = build_pairs_query(params);
        let mut stmt = self.conn.prepare(&pairs_sql)?;
        let mut rows = stmt.query([])?;

        let mut raw_pairs: Vec<RawPair> = Vec::new();
        while let Some(row) = rows.next()? {
            raw_pairs.push(RawPair {
                trace_a: row.get(0)?,
                sock_a: row.get(1)?,
                protocol: row.get(2)?,
                address_family: row.get(3)?,
                a_src_ip: row.get(4)?,
                a_src_port: row.get(5)?,
                a_dest_ip: row.get(6)?,
                a_dest_port: row.get(7)?,
                trace_b: row.get(8)?,
                sock_b: row.get(9)?,
                b_src_ip: row.get(10)?,
                b_src_port: row.get(11)?,
                b_dest_ip: row.get(12)?,
                b_dest_port: row.get(13)?,
            });
        }
        drop(rows);
        drop(stmt);

        if raw_pairs.is_empty() {
            return Ok(NetworkSocketPairsResult { pairs: Vec::new() });
        }

        // Collect all unique (trace_id, socket_id) pairs
        let mut all_socket_keys: BTreeSet<(String, i64)> = BTreeSet::new();
        for rp in &raw_pairs {
            all_socket_keys.insert((rp.trace_a.clone(), rp.sock_a));
            all_socket_keys.insert((rp.trace_b.clone(), rp.sock_b));
        }

        // Step 2: Get traffic data
        let has_syscall = self.table_exists("network_syscall")?;
        let mut traffic_map: BTreeMap<(String, i64), (u64, u64)> = BTreeMap::new();

        if has_syscall {
            let traffic_sql = build_traffic_query(&all_socket_keys);
            let mut stmt = self.conn.prepare(&traffic_sql)?;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let tid: String = row.get(0)?;
                let sid: i64 = row.get(1)?;
                let send: i64 = row.get(2)?;
                let recv: i64 = row.get(3)?;
                traffic_map.insert((tid, sid), (to_u64(send), to_u64(recv)));
            }
            drop(rows);
            drop(stmt);
        }

        // Step 3: Get TCP retransmit data
        let has_packet = self.table_exists("network_packet")?;
        let mut retransmit_map: BTreeMap<(String, i64), (u64, u64)> = BTreeMap::new();

        if has_packet {
            // Collect TCP socket keys
            let tcp_socket_keys: BTreeSet<(String, i64)> = raw_pairs
                .iter()
                .filter(|rp| rp.protocol == "TCP")
                .flat_map(|rp| {
                    vec![
                        (rp.trace_a.clone(), rp.sock_a),
                        (rp.trace_b.clone(), rp.sock_b),
                    ]
                })
                .collect();

            if !tcp_socket_keys.is_empty() {
                let retransmit_sql = build_retransmit_query(&tcp_socket_keys);
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

        // Step 4: Get interface/namespace info
        let has_interface = self.table_exists("network_interface")?;
        let mut iface_map: BTreeMap<(String, i64), (String, String)> = BTreeMap::new();

        if has_interface {
            let iface_sql = build_interface_query(&all_socket_keys);
            let mut stmt = self.conn.prepare(&iface_sql)?;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let tid: String = row.get(0)?;
                let sid: i64 = row.get(1)?;
                let iface_name: String = row.get(2)?;
                let namespace: String = row.get(3)?;
                iface_map.insert((tid, sid), (iface_name, namespace));
            }
            drop(rows);
            drop(stmt);
        }

        // Step 5: Assemble results
        let mut pairs: Vec<SocketPair> = Vec::with_capacity(raw_pairs.len());

        for rp in raw_pairs {
            let key_a = (rp.trace_a.clone(), rp.sock_a);
            let key_b = (rp.trace_b.clone(), rp.sock_b);

            let (send_a, recv_a) = traffic_map.get(&key_a).copied().unwrap_or((0, 0));
            let (send_b, recv_b) = traffic_map.get(&key_b).copied().unwrap_or((0, 0));

            let (iface_a, ns_a) = iface_map
                .get(&key_a)
                .cloned()
                .unwrap_or_else(|| ("unknown".to_string(), "unknown".to_string()));
            let (iface_b, ns_b) = iface_map
                .get(&key_b)
                .cloned()
                .unwrap_or_else(|| ("unknown".to_string(), "unknown".to_string()));

            let make_retransmit =
                |key: &(String, i64), proto: &str| -> (Option<u64>, Option<u64>, Option<f64>) {
                    if proto != "TCP" {
                        return (None, None, None);
                    }
                    if let Some((total_pkt, retx)) = retransmit_map.get(key) {
                        let pct = if *total_pkt > 0 {
                            *retx as f64 / *total_pkt as f64 * 100.0
                        } else {
                            0.0
                        };
                        (Some(*retx), Some(*total_pkt), Some(pct))
                    } else {
                        (Some(0), Some(0), Some(0.0))
                    }
                };

            let (retx_count_a, total_pkt_a, retx_pct_a) = make_retransmit(&key_a, &rp.protocol);
            let (retx_count_b, total_pkt_b, retx_pct_b) = make_retransmit(&key_b, &rp.protocol);

            let mut side_a = SocketSide {
                trace_id: rp.trace_a.clone(),
                socket_id: rp.sock_a,
                src_ip: rp.a_src_ip,
                src_port: rp.a_src_port,
                dest_ip: rp.a_dest_ip,
                dest_port: rp.a_dest_port,
                interface_name: iface_a,
                namespace: ns_a,
                send_bytes: send_a,
                recv_bytes: recv_a,
                retransmit_count: retx_count_a,
                total_tcp_packets: total_pkt_a,
                retransmit_pct: retx_pct_a,
            };

            let mut side_b = SocketSide {
                trace_id: rp.trace_b.clone(),
                socket_id: rp.sock_b,
                src_ip: rp.b_src_ip,
                src_port: rp.b_src_port,
                dest_ip: rp.b_dest_ip,
                dest_port: rp.b_dest_port,
                interface_name: iface_b,
                namespace: ns_b,
                send_bytes: send_b,
                recv_bytes: recv_b,
                retransmit_count: retx_count_b,
                total_tcp_packets: total_pkt_b,
                retransmit_pct: retx_pct_b,
            };

            // Normalize: Side A = client (higher ephemeral src_port),
            // Side B = server (lower service src_port).
            if side_a.src_port < side_b.src_port {
                std::mem::swap(&mut side_a, &mut side_b);
            }

            let total_bytes =
                side_a.send_bytes + side_a.recv_bytes + side_b.send_bytes + side_b.recv_bytes;
            let cross_trace = rp.trace_a != rp.trace_b;

            pairs.push(SocketPair {
                protocol: rp.protocol,
                address_family: rp.address_family,
                total_bytes,
                cross_trace,
                side_a,
                side_b,
            });
        }

        // Sort by total_bytes descending
        pairs.sort_by(|a, b| b.total_bytes.cmp(&a.total_bytes));

        // Apply top_n limit
        if let Some(n) = params.top_n {
            pairs.truncate(n);
        }

        Ok(NetworkSocketPairsResult { pairs })
    }
}

// -- Query builders --

/// Build a SQL filter clause from a set of (trace_id, socket_id) keys.
///
/// Groups socket IDs by trace_id and produces per-trace conditions like:
/// `(alias.trace_id = 'X' AND alias.socket_id IN (1, 2, 3))`
/// joined with `OR`.
fn build_socket_key_filter(
    socket_keys: &BTreeSet<(String, i64)>,
    trace_col: &str,
    socket_col: &str,
) -> String {
    let mut trace_sockets: BTreeMap<&str, Vec<i64>> = BTreeMap::new();
    for (tid, sid) in socket_keys {
        trace_sockets.entry(tid.as_str()).or_default().push(*sid);
    }

    let conditions: Vec<String> = trace_sockets
        .iter()
        .map(|(tid, sids)| {
            let escaped = tid.replace('\'', "''");
            let id_list: Vec<String> = sids.iter().map(|s| s.to_string()).collect();
            format!(
                "({trace_col} = '{escaped}' AND {socket_col} IN ({}))",
                id_list.join(", ")
            )
        })
        .collect();

    conditions.join(" OR ")
}

fn build_pairs_query(params: &NetworkSocketPairsParams) -> String {
    let mut where_clauses = Vec::new();

    // Trace ID filter: at least one side matches
    if let Some(ref tid) = params.trace_id {
        let escaped = tid.replace('\'', "''");
        where_clauses.push(format!(
            "(a.trace_id = '{escaped}' OR b.trace_id = '{escaped}')"
        ));
    }

    // Dest port filter: either side's dest_port matches
    if let Some(port) = params.dest_port {
        where_clauses.push(format!("(a.dest_port = {port} OR b.dest_port = {port})"));
    }

    // IP filter: IP appears on either side of side A.
    // Checking only side A is sufficient because the join guarantees
    // a.src_ip = b.dest_ip and a.dest_ip = b.src_ip, so any IP on side A
    // also appears on side B.
    if let Some(ref ip) = params.ip {
        let escaped = ip.replace('\'', "''");
        where_clauses.push(format!(
            "(a.src_ip = '{escaped}' OR a.dest_ip = '{escaped}')"
        ));
    }

    // Loopback exclusion: checking side A is sufficient due to join symmetry
    // (a.src_ip = b.dest_ip, a.dest_ip = b.src_ip).
    if params.exclude_loopback {
        where_clauses.push(
            "a.src_ip NOT LIKE '127.%' \
             AND a.src_ip != '::1' \
             AND a.src_ip NOT LIKE '::ffff:127.%' \
             AND a.dest_ip NOT LIKE '127.%' \
             AND a.dest_ip != '::1' \
             AND a.dest_ip NOT LIKE '::ffff:127.%'"
                .to_string(),
        );
    }

    let where_str = if where_clauses.is_empty() {
        String::new()
    } else {
        format!(" AND {}", where_clauses.join(" AND "))
    };

    format!(
        "SELECT a.trace_id AS trace_a, a.socket_id AS sock_a, \
         a.protocol, a.address_family, \
         a.src_ip AS a_src_ip, a.src_port AS a_src_port, \
         a.dest_ip AS a_dest_ip, a.dest_port AS a_dest_port, \
         b.trace_id AS trace_b, b.socket_id AS sock_b, \
         b.src_ip AS b_src_ip, b.src_port AS b_src_port, \
         b.dest_ip AS b_dest_ip, b.dest_port AS b_dest_port \
         FROM network_socket a \
         JOIN network_socket b ON \
         a.src_ip = b.dest_ip AND a.src_port = b.dest_port AND \
         a.dest_ip = b.src_ip AND a.dest_port = b.src_port AND \
         a.protocol = b.protocol AND \
         a.address_family = b.address_family AND \
         (a.trace_id < b.trace_id OR \
         (a.trace_id = b.trace_id AND a.socket_id < b.socket_id)) \
         WHERE 1=1{where_str} \
         ORDER BY a.trace_id, b.trace_id, a.socket_id"
    )
}

fn build_traffic_query(socket_keys: &BTreeSet<(String, i64)>) -> String {
    let filter = build_socket_key_filter(socket_keys, "nsc.trace_id", "nsc.socket_id");

    format!(
        "SELECT nsc.trace_id, nsc.socket_id, \
         COALESCE(SUM(CASE WHEN nsc.event_type = 'sendmsg' THEN nsc.bytes ELSE 0 END), 0) AS send_bytes, \
         COALESCE(SUM(CASE WHEN nsc.event_type = 'recvmsg' THEN nsc.bytes ELSE 0 END), 0) AS recv_bytes \
         FROM network_syscall nsc \
         WHERE ({filter}) \
         GROUP BY nsc.trace_id, nsc.socket_id"
    )
}

fn build_retransmit_query(tcp_socket_keys: &BTreeSet<(String, i64)>) -> String {
    // Socket keys are already pre-filtered to TCP-only sockets, so no need to
    // join back to network_socket for protocol filtering.
    let filter = build_socket_key_filter(tcp_socket_keys, "np.trace_id", "np.socket_id");

    format!(
        "SELECT np.trace_id, np.socket_id, \
         COUNT(*) AS total_packets, \
         SUM(CASE WHEN np.is_retransmit THEN 1 ELSE 0 END) AS retransmit_count \
         FROM network_packet np \
         WHERE np.event_type IN ('TCP packet_send', 'TCP packet_enqueue', 'TCP rto_timeout') \
         AND ({filter}) \
         GROUP BY np.trace_id, np.socket_id"
    )
}

fn build_interface_query(socket_keys: &BTreeSet<(String, i64)>) -> String {
    let filter = build_socket_key_filter(socket_keys, "ns.trace_id", "ns.socket_id");

    format!(
        "SELECT ns.trace_id, ns.socket_id, \
         COALESCE(ni.interface_name, 'unknown') AS interface_name, \
         COALESCE(ni.namespace, 'unknown') AS namespace \
         FROM network_socket ns \
         LEFT JOIN network_interface ni ON ns.trace_id = ni.trace_id AND ns.src_ip = ni.ip_address \
         WHERE ({filter})"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_pairs_query_no_filters() {
        let params = NetworkSocketPairsParams {
            trace_id: None,
            dest_port: None,
            ip: None,
            top_n: None,
            exclude_loopback: false,
        };
        let sql = build_pairs_query(&params);
        assert!(sql.contains("FROM network_socket a"));
        assert!(sql.contains("JOIN network_socket b ON"));
        assert!(sql.contains("a.src_ip = b.dest_ip"));
        assert!(sql.contains("a.src_port = b.dest_port"));
        assert!(sql.contains("a.dest_ip = b.src_ip"));
        assert!(sql.contains("a.dest_port = b.src_port"));
        assert!(sql.contains("a.protocol = b.protocol"));
        assert!(sql.contains("a.address_family = b.address_family"));
        assert!(sql.contains("a.trace_id < b.trace_id"));
        assert!(sql.contains("a.socket_id < b.socket_id"));
        assert!(sql.contains("WHERE 1=1"));
        // No extra filters beyond the join
        assert!(!sql.contains("a.trace_id = '"));
        assert!(!sql.contains("OR b.dest_port ="));
        assert!(!sql.contains("NOT LIKE '127.%'"));
    }

    #[test]
    fn test_build_pairs_query_with_trace_id() {
        let params = NetworkSocketPairsParams {
            trace_id: Some("trace-abc".to_string()),
            dest_port: None,
            ip: None,
            top_n: None,
            exclude_loopback: false,
        };
        let sql = build_pairs_query(&params);
        assert!(sql.contains("a.trace_id = 'trace-abc' OR b.trace_id = 'trace-abc'"));
    }

    #[test]
    fn test_build_pairs_query_with_dest_port() {
        let params = NetworkSocketPairsParams {
            trace_id: None,
            dest_port: Some(9000),
            ip: None,
            top_n: None,
            exclude_loopback: false,
        };
        let sql = build_pairs_query(&params);
        assert!(sql.contains("a.dest_port = 9000 OR b.dest_port = 9000"));
    }

    #[test]
    fn test_build_pairs_query_with_ip() {
        let params = NetworkSocketPairsParams {
            trace_id: None,
            dest_port: None,
            ip: Some("10.0.0.1".to_string()),
            top_n: None,
            exclude_loopback: false,
        };
        let sql = build_pairs_query(&params);
        assert!(sql.contains("a.src_ip = '10.0.0.1' OR a.dest_ip = '10.0.0.1'"));
    }

    #[test]
    fn test_build_pairs_query_exclude_loopback() {
        let params = NetworkSocketPairsParams {
            trace_id: None,
            dest_port: None,
            ip: None,
            top_n: None,
            exclude_loopback: true,
        };
        let sql = build_pairs_query(&params);
        assert!(sql.contains("a.src_ip NOT LIKE '127.%'"));
        assert!(sql.contains("a.src_ip != '::1'"));
        assert!(sql.contains("a.src_ip NOT LIKE '::ffff:127.%'"));
        assert!(sql.contains("a.dest_ip NOT LIKE '127.%'"));
        assert!(sql.contains("a.dest_ip != '::1'"));
        assert!(sql.contains("a.dest_ip NOT LIKE '::ffff:127.%'"));
    }

    #[test]
    fn test_build_pairs_query_address_family_in_join() {
        let params = NetworkSocketPairsParams {
            trace_id: None,
            dest_port: None,
            ip: None,
            top_n: None,
            exclude_loopback: false,
        };
        let sql = build_pairs_query(&params);
        assert!(sql.contains("a.address_family = b.address_family"));
    }

    #[test]
    fn test_build_traffic_query() {
        let mut keys: BTreeSet<(String, i64)> = BTreeSet::new();
        keys.insert(("trace1".to_string(), 10));
        keys.insert(("trace1".to_string(), 20));
        keys.insert(("trace2".to_string(), 30));

        let sql = build_traffic_query(&keys);
        assert!(sql.contains("FROM network_syscall nsc"));
        assert!(sql.contains("nsc.event_type = 'sendmsg'"));
        assert!(sql.contains("nsc.event_type = 'recvmsg'"));
        assert!(sql.contains("nsc.trace_id = 'trace1'"));
        assert!(sql.contains("nsc.socket_id IN (10, 20)"));
        assert!(sql.contains("nsc.trace_id = 'trace2'"));
        assert!(sql.contains("nsc.socket_id IN (30)"));
        assert!(sql.contains("GROUP BY nsc.trace_id, nsc.socket_id"));
    }

    #[test]
    fn test_build_retransmit_query() {
        let mut keys: BTreeSet<(String, i64)> = BTreeSet::new();
        keys.insert(("t1".to_string(), 100));
        keys.insert(("t1".to_string(), 200));

        let sql = build_retransmit_query(&keys);
        assert!(sql.contains("'TCP packet_send', 'TCP packet_enqueue', 'TCP rto_timeout'"));
        assert!(sql.contains("SUM(CASE WHEN np.is_retransmit THEN 1 ELSE 0 END)"));
        assert!(sql.contains("COUNT(*)"));
        assert!(sql.contains("np.trace_id = 't1'"));
        assert!(sql.contains("np.socket_id IN (100, 200)"));
        assert!(sql.contains("GROUP BY np.trace_id, np.socket_id"));
        // Should NOT join back to network_socket (socket keys are pre-filtered to TCP)
        assert!(!sql.contains("JOIN network_socket"));
    }

    #[test]
    fn test_build_interface_query() {
        let mut keys: BTreeSet<(String, i64)> = BTreeSet::new();
        keys.insert(("t1".to_string(), 5));

        let sql = build_interface_query(&keys);
        assert!(sql.contains("FROM network_socket ns"));
        assert!(sql.contains("LEFT JOIN network_interface ni"));
        assert!(sql.contains("ns.src_ip = ni.ip_address"));
        assert!(sql.contains("COALESCE(ni.interface_name, 'unknown')"));
        assert!(sql.contains("COALESCE(ni.namespace, 'unknown')"));
        assert!(sql.contains("ns.trace_id = 't1'"));
        assert!(sql.contains("ns.socket_id IN (5)"));
    }

    #[test]
    fn test_build_socket_key_filter() {
        let mut keys: BTreeSet<(String, i64)> = BTreeSet::new();
        keys.insert(("t1".to_string(), 1));
        keys.insert(("t1".to_string(), 2));
        keys.insert(("t2".to_string(), 3));

        let filter = build_socket_key_filter(&keys, "x.trace_id", "x.socket_id");
        assert!(filter.contains("x.trace_id = 't1' AND x.socket_id IN (1, 2)"));
        assert!(filter.contains("x.trace_id = 't2' AND x.socket_id IN (3)"));
        assert!(filter.contains(" OR "));
    }
}
