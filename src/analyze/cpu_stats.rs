use std::collections::HashMap;

use anyhow::{bail, Result};
use serde::Serialize;

use super::{trace_id_filter, AnalyzeDb};

/// Parameters for CPU stats analysis.
#[derive(Debug, Clone, Default)]
pub struct CpuStatsParams {
    pub trace_id: Option<String>,
}

/// Result of CPU stats analysis.
#[derive(Debug, Serialize)]
pub struct CpuStatsResult {
    pub summary: CpuStatsSummary,
    pub cpus: Vec<PerCpuStats>,
}

/// Summary-level CPU statistics.
#[derive(Debug, Serialize)]
pub struct CpuStatsSummary {
    pub trace_duration_seconds: f64,
    pub cpu_count: u32,
    pub total_sched_events: u64,
}

/// Per-CPU scheduling statistics.
#[derive(Debug, Serialize)]
pub struct PerCpuStats {
    pub cpu: i32,
    pub utilization_pct: f64,
    pub idle_pct: f64,
    pub thread_count: u32,
    pub sched_events: u64,
    pub irq_time_seconds: f64,
    pub softirq_time_seconds: f64,
    pub rq_p50: Option<f64>,
    pub rq_p90: Option<f64>,
    pub rq_p99: Option<f64>,
}

/// Intermediate per-CPU data collected from the base query before normalization.
struct CpuBaseData {
    busy_ns: f64,
    thread_count: u32,
    sched_events: u64,
}

impl AnalyzeDb {
    /// Run per-CPU stats analysis.
    pub fn cpu_stats(&self, params: &CpuStatsParams) -> Result<CpuStatsResult> {
        if !self.table_exists("sched_slice")? {
            bail!("Database missing sched_slice table. Is this a systing trace database?");
        }
        if !self.table_has_rows("sched_slice")? {
            bail!("No scheduling events found in database.");
        }

        let trace_id = params.trace_id.as_deref();

        // Base stats from sched_slice
        let base_sql = build_cpu_base_query(trace_id);
        let mut stmt = self.conn.prepare(&base_sql)?;
        let mut rows = stmt.query([])?;

        let mut base_map: HashMap<i32, CpuBaseData> = HashMap::new();
        let mut total_events: u64 = 0;

        while let Some(row) = rows.next()? {
            let cpu: i32 = row.get(0)?;
            let busy_ns: f64 = row.get(1)?;
            let events: i64 = row.get(2)?;
            let threads: i64 = row.get(3)?;

            let events_u64 = events as u64;
            total_events += events_u64;
            base_map.insert(
                cpu,
                CpuBaseData {
                    busy_ns,
                    thread_count: threads as u32,
                    sched_events: events_u64,
                },
            );
        }
        drop(rows);
        drop(stmt);

        if base_map.is_empty() {
            bail!("No scheduling events with nonzero duration found.");
        }

        // Trace duration
        let dur_sql = build_trace_duration_query(trace_id);
        let mut stmt = self.conn.prepare(&dur_sql)?;
        let mut rows = stmt.query([])?;
        let trace_dur_s: f64 = rows.next()?.map(|r| r.get(0).unwrap_or(0.0)).unwrap_or(0.0);
        drop(rows);
        drop(stmt);

        // Build the final per-CPU stats with utilization computed from base data
        let trace_dur_ns = trace_dur_s * 1e9;
        let mut cpu_map: HashMap<i32, PerCpuStats> = base_map
            .into_iter()
            .map(|(cpu, base)| {
                let utilization_pct = if trace_dur_ns > 0.0 {
                    (base.busy_ns / trace_dur_ns * 100.0).min(100.0)
                } else {
                    0.0
                };
                (
                    cpu,
                    PerCpuStats {
                        cpu,
                        utilization_pct,
                        idle_pct: (100.0 - utilization_pct).max(0.0),
                        thread_count: base.thread_count,
                        sched_events: base.sched_events,
                        irq_time_seconds: 0.0,
                        softirq_time_seconds: 0.0,
                        rq_p50: None,
                        rq_p90: None,
                        rq_p99: None,
                    },
                )
            })
            .collect();

        // IRQ time (optional)
        if self.table_exists("irq_slice")? && self.table_has_rows("irq_slice")? {
            let irq_sql = build_irq_time_query(trace_id);
            let mut stmt = self.conn.prepare(&irq_sql)?;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let cpu: i32 = row.get(0)?;
                let irq_s: f64 = row.get(1)?;
                if let Some(stats) = cpu_map.get_mut(&cpu) {
                    stats.irq_time_seconds = irq_s;
                }
            }
        }

        // SoftIRQ time (optional)
        if self.table_exists("softirq_slice")? && self.table_has_rows("softirq_slice")? {
            let softirq_sql = build_softirq_time_query(trace_id);
            let mut stmt = self.conn.prepare(&softirq_sql)?;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let cpu: i32 = row.get(0)?;
                let softirq_s: f64 = row.get(1)?;
                if let Some(stats) = cpu_map.get_mut(&cpu) {
                    stats.softirq_time_seconds = softirq_s;
                }
            }
        }

        // Runqueue depth percentiles (optional)
        if self.table_exists("thread_state")? && self.table_has_rows("thread_state")? {
            let rq_sql = build_runqueue_query(trace_id);
            let mut stmt = self.conn.prepare(&rq_sql)?;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let cpu: i32 = row.get(0)?;
                let p50: f64 = row.get(1)?;
                let p90: f64 = row.get(2)?;
                let p99: f64 = row.get(3)?;
                if let Some(stats) = cpu_map.get_mut(&cpu) {
                    stats.rq_p50 = Some(p50);
                    stats.rq_p90 = Some(p90);
                    stats.rq_p99 = Some(p99);
                }
            }
        }

        let cpu_count = cpu_map.len() as u32;
        let mut cpus: Vec<PerCpuStats> = cpu_map.into_values().collect();
        cpus.sort_by_key(|c| c.cpu);

        Ok(CpuStatsResult {
            summary: CpuStatsSummary {
                trace_duration_seconds: trace_dur_s,
                cpu_count,
                total_sched_events: total_events,
            },
            cpus,
        })
    }
}

// -- CPU stats query builders --

fn build_cpu_base_query(trace_id: Option<&str>) -> String {
    let filter = trace_id_filter(trace_id, "ss.");
    format!(
        "SELECT ss.cpu, \
         SUM(ss.dur) as busy_ns, \
         COUNT(*) as events, \
         COUNT(DISTINCT ss.utid) as threads \
         FROM sched_slice ss \
         WHERE ss.dur > 0{filter} \
         GROUP BY ss.cpu \
         ORDER BY ss.cpu"
    )
}

fn build_trace_duration_query(trace_id: Option<&str>) -> String {
    let filter = trace_id_filter(trace_id, "ss.");
    format!(
        "SELECT (MAX(ss.ts + ss.dur) - MIN(ss.ts)) / 1e9 as trace_dur_s \
         FROM sched_slice ss \
         WHERE ss.dur > 0{filter}"
    )
}

fn build_irq_time_query(trace_id: Option<&str>) -> String {
    let filter = trace_id_filter(trace_id, "i.");
    format!(
        "SELECT i.cpu, SUM(i.dur) / 1e9 as irq_s \
         FROM irq_slice i \
         WHERE i.dur > 0{filter} \
         GROUP BY i.cpu"
    )
}

fn build_softirq_time_query(trace_id: Option<&str>) -> String {
    let filter = trace_id_filter(trace_id, "s.");
    format!(
        "SELECT s.cpu, SUM(s.dur) / 1e9 as softirq_s \
         FROM softirq_slice s \
         WHERE s.dur > 0{filter} \
         GROUP BY s.cpu"
    )
}

fn build_runqueue_query(trace_id: Option<&str>) -> String {
    let filter_ts = trace_id_filter(trace_id, "ts.");
    let filter_ss = trace_id_filter(trace_id, "ss.");
    // Deduplicate wakeups per (utid, scheduling-window) so that spurious
    // wakeups between the same pair of sched_slices produce only one +1 event.
    // The -1 side already uses DISTINCT, so this keeps +1/-1 balanced.
    format!(
        "WITH dedup_wakeups AS (\
             SELECT ts.ts, ts.utid, ts.cpu as target_cpu, \
                    ROW_NUMBER() OVER (PARTITION BY ts.utid, ts.cpu, ts.ts ORDER BY ts.ts) as rn \
             FROM thread_state ts \
             WHERE ts.state = 0 AND ts.cpu IS NOT NULL{filter_ts}\
         ), \
         wakeups AS (\
             SELECT ts, utid, target_cpu FROM dedup_wakeups WHERE rn = 1\
         ), \
         sched_with_prev AS (\
             SELECT ss.ts, ss.cpu, ss.utid, \
                    LAG(ss.ts + ss.dur) OVER (PARTITION BY ss.utid ORDER BY ss.ts) as prev_end_ts \
             FROM sched_slice ss \
             WHERE ss.dur > 0{filter_ss}\
         ), \
         matched_schedules AS (\
             SELECT DISTINCT s.ts, s.cpu, s.utid, w.target_cpu, w.ts as wakeup_ts \
             FROM sched_with_prev s \
             INNER JOIN wakeups w ON w.utid = s.utid \
                 AND w.ts >= COALESCE(s.prev_end_ts, 0) \
                 AND w.ts <= s.ts\
         ), \
         events AS (\
             SELECT target_cpu as cpu, ts, 1 as delta \
             FROM wakeups \
             UNION ALL \
             SELECT target_cpu as cpu, wakeup_ts as ts, -1 as delta \
             FROM matched_schedules\
         ), \
         rq_depth AS (\
             SELECT cpu, ts, \
                    SUM(delta) OVER (PARTITION BY cpu ORDER BY ts \
                                     ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) as depth \
             FROM events\
         ) \
         SELECT cpu, \
                QUANTILE_CONT(GREATEST(depth, 0), 0.5) as p50, \
                QUANTILE_CONT(GREATEST(depth, 0), 0.9) as p90, \
                QUANTILE_CONT(GREATEST(depth, 0), 0.99) as p99 \
         FROM rq_depth \
         WHERE depth IS NOT NULL \
         GROUP BY cpu \
         ORDER BY cpu"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_cpu_base_query_no_trace_id() {
        let sql = build_cpu_base_query(None);
        assert!(sql.contains("FROM sched_slice ss"));
        assert!(sql.contains("WHERE ss.dur > 0"));
        assert!(sql.contains("GROUP BY ss.cpu"));
        assert!(!sql.contains("trace_id"));
    }

    #[test]
    fn test_build_cpu_base_query_with_trace_id() {
        let sql = build_cpu_base_query(Some("trace-1"));
        assert!(sql.contains("ss.trace_id = 'trace-1'"));
    }

    #[test]
    fn test_build_trace_duration_query() {
        let sql = build_trace_duration_query(None);
        assert!(sql.contains("MAX(ss.ts + ss.dur)"));
        assert!(sql.contains("MIN(ss.ts)"));
        assert!(sql.contains("/ 1e9"));
    }

    #[test]
    fn test_build_irq_time_query() {
        let sql = build_irq_time_query(None);
        assert!(sql.contains("FROM irq_slice i"));
        assert!(sql.contains("SUM(i.dur) / 1e9"));
        assert!(sql.contains("GROUP BY i.cpu"));
    }

    #[test]
    fn test_build_irq_time_query_with_trace_id() {
        let sql = build_irq_time_query(Some("t1"));
        assert!(sql.contains("i.trace_id = 't1'"));
    }

    #[test]
    fn test_build_softirq_time_query() {
        let sql = build_softirq_time_query(None);
        assert!(sql.contains("FROM softirq_slice s"));
        assert!(sql.contains("SUM(s.dur) / 1e9"));
        assert!(sql.contains("GROUP BY s.cpu"));
    }

    #[test]
    fn test_build_runqueue_query_structure() {
        let sql = build_runqueue_query(None);
        assert!(sql.contains("WITH dedup_wakeups AS"));
        assert!(sql.contains("wakeups AS"));
        assert!(sql.contains("sched_with_prev AS"));
        assert!(sql.contains("matched_schedules AS"));
        assert!(sql.contains("events AS"));
        assert!(sql.contains("rq_depth AS"));
        assert!(sql.contains("QUANTILE_CONT"));
        assert!(sql.contains("GREATEST(depth, 0)"));
        assert!(sql.contains("GROUP BY cpu"));
    }

    #[test]
    fn test_build_runqueue_query_with_trace_id() {
        let sql = build_runqueue_query(Some("t1"));
        assert!(sql.contains("ts.trace_id = 't1'"));
        assert!(sql.contains("ss.trace_id = 't1'"));
    }

    #[test]
    fn test_build_runqueue_query_uses_target_cpu() {
        let sql = build_runqueue_query(None);
        // -1 events should use target_cpu, not sched cpu
        assert!(sql.contains("SELECT target_cpu as cpu, wakeup_ts as ts, -1 as delta"));
        // +1 events should also use target_cpu
        assert!(sql.contains("SELECT target_cpu as cpu, ts, 1 as delta"));
    }

    #[test]
    fn test_build_runqueue_query_matched_schedules_join() {
        let sql = build_runqueue_query(None);
        // Should join on utid and require wakeup between prev_end and current start
        assert!(sql.contains("INNER JOIN wakeups w ON w.utid = s.utid"));
        assert!(sql.contains("w.ts >= COALESCE(s.prev_end_ts, 0)"));
        assert!(sql.contains("w.ts <= s.ts"));
    }

    #[test]
    fn test_build_runqueue_query_percentiles() {
        let sql = build_runqueue_query(None);
        assert!(sql.contains("QUANTILE_CONT(GREATEST(depth, 0), 0.5) as p50"));
        assert!(sql.contains("QUANTILE_CONT(GREATEST(depth, 0), 0.9) as p90"));
        assert!(sql.contains("QUANTILE_CONT(GREATEST(depth, 0), 0.99) as p99"));
    }

    #[test]
    fn test_build_runqueue_query_deduplicates_wakeups() {
        let sql = build_runqueue_query(None);
        // Should have a dedup CTE that uses ROW_NUMBER to eliminate duplicates
        assert!(sql.contains("dedup_wakeups"));
        assert!(sql.contains("ROW_NUMBER()"));
        assert!(sql.contains("WHERE rn = 1"));
    }

    #[test]
    fn test_build_runqueue_query_matched_includes_wakeup_ts() {
        let sql = build_runqueue_query(None);
        // matched_schedules should include w.ts as wakeup_ts for balanced +1/-1
        assert!(sql.contains("w.ts as wakeup_ts"));
        // -1 events should use wakeup_ts (not schedule ts)
        assert!(sql.contains("wakeup_ts as ts, -1 as delta"));
    }

    #[test]
    fn test_cpu_stats_params_default() {
        let params = CpuStatsParams::default();
        assert!(params.trace_id.is_none());
    }
}
