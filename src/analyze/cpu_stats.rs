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
    // Deduplicate wakeups per (utid, target cpu, ts) so that spurious wakeups
    // between the same pair of sched_slices produce only one +1 event. The -1
    // side is one row per matched wakeup, so this keeps +1/-1 balanced.
    //
    // A wakeup is matched to the sched_slice it precedes: the first slice of
    // the same utid that starts at or after the wakeup, provided the wakeup
    // came after the thread's previous slice ended (a wakeup that lands inside
    // the previous run is spurious and stays unmatched). Consecutive slices of
    // one utid have disjoint [prev_end_ts, ts] windows, so at most one slice
    // qualifies per wakeup, and an ASOF JOIN -- one ordered merge over both
    // sides -- yields the same matches as the range join
    // `w.ts BETWEEN COALESCE(s.prev_end_ts, 0) AND s.ts` it replaces. That
    // range join built an intermediate DuckDB cannot spill: on a 192-CPU trace
    // of 62 M rows it took 58 s and failed with an out-of-memory error under a
    // 1.5 GiB memory_limit, and at 186 M rows it took 428 s at 8 GiB and
    // failed at 4 GiB, while this form takes 15 s / 53 s and spills gracefully
    // under the same limits.
    format!(
        "WITH wakeups AS (\
             SELECT DISTINCT ts.ts, ts.utid, ts.cpu as target_cpu \
             FROM thread_state ts \
             WHERE ts.state = 0 AND ts.cpu IS NOT NULL{filter_ts}\
         ), \
         sched_with_prev AS (\
             SELECT ss.ts, ss.cpu, ss.utid, \
                    LAG(ss.ts + ss.dur) OVER (PARTITION BY ss.utid ORDER BY ss.ts) as prev_end_ts \
             FROM sched_slice ss \
             WHERE ss.dur > 0{filter_ss}\
         ), \
         matched_schedules AS (\
             SELECT s.ts, s.cpu, s.utid, w.target_cpu, w.ts as wakeup_ts \
             FROM wakeups w \
             ASOF JOIN sched_with_prev s \
                 ON w.utid = s.utid AND w.ts <= s.ts \
             WHERE w.ts >= COALESCE(s.prev_end_ts, 0)\
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
        assert!(sql.contains("WITH wakeups AS"));
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
        // Each wakeup is matched to the first slice of its utid starting at or
        // after it (ASOF), and only counts when it fell after the previous
        // slice ended -- the same match set as the range join this replaced.
        assert!(sql.contains("FROM wakeups w ASOF JOIN sched_with_prev s"));
        assert!(sql.contains("ON w.utid = s.utid AND w.ts <= s.ts"));
        assert!(sql.contains("WHERE w.ts >= COALESCE(s.prev_end_ts, 0)"));
        // No range join and no DISTINCT on the match side: ASOF is 1:1.
        assert!(!sql.contains("INNER JOIN"));
        assert!(!sql.contains("SELECT DISTINCT s.ts"));
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
        // One +1 event per (ts, utid, target cpu): duplicate wakeup rows and
        // spurious repeats between the same pair of slices collapse.
        assert!(sql.contains("SELECT DISTINCT ts.ts, ts.utid, ts.cpu as target_cpu"));
        assert!(!sql.contains("ROW_NUMBER()"));
    }

    #[test]
    fn test_build_runqueue_query_matched_includes_wakeup_ts() {
        let sql = build_runqueue_query(None);
        // matched_schedules should include w.ts as wakeup_ts for balanced +1/-1
        assert!(sql.contains("w.ts as wakeup_ts"));
        // -1 events should use wakeup_ts (not schedule ts)
        assert!(sql.contains("wakeup_ts as ts, -1 as delta"));
    }

    /// The range-join form of the runqueue query this module shipped before
    /// the ASOF JOIN, kept verbatim as the oracle for
    /// `test_runqueue_query_asof_matches_range_join`.
    fn legacy_range_join_runqueue_query() -> String {
        "WITH dedup_wakeups AS (\
             SELECT ts.ts, ts.utid, ts.cpu as target_cpu, \
                    ROW_NUMBER() OVER (PARTITION BY ts.utid, ts.cpu, ts.ts ORDER BY ts.ts) as rn \
             FROM thread_state ts \
             WHERE ts.state = 0 AND ts.cpu IS NOT NULL\
         ), \
         wakeups AS (\
             SELECT ts, utid, target_cpu FROM dedup_wakeups WHERE rn = 1\
         ), \
         sched_with_prev AS (\
             SELECT ss.ts, ss.cpu, ss.utid, \
                    LAG(ss.ts + ss.dur) OVER (PARTITION BY ss.utid ORDER BY ss.ts) as prev_end_ts \
             FROM sched_slice ss \
             WHERE ss.dur > 0\
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
            .to_string()
    }

    /// Rewrite a full runqueue query so it returns the `events` multiset
    /// (one row per (cpu, ts) with the summed delta and the row count) instead
    /// of the percentiles: the part of the query the join change can alter.
    fn events_multiset_query(sql: &str) -> String {
        let (prefix, _) = sql
            .split_once("rq_depth AS (")
            .expect("runqueue query has an rq_depth CTE");
        let prefix = prefix.trim_end().trim_end_matches(',');
        format!(
            "{prefix} SELECT cpu, ts, CAST(SUM(delta) AS BIGINT), COUNT(*) \
             FROM events GROUP BY cpu, ts ORDER BY cpu, ts"
        )
    }

    /// Same, but counting the matched wakeups, so the fixture can be shown to
    /// exercise both the matched and the unmatched branches.
    fn matched_count_query(sql: &str) -> String {
        let (prefix, _) = sql
            .split_once("events AS (")
            .expect("runqueue query has an events CTE");
        let prefix = prefix.trim_end().trim_end_matches(',');
        format!("{prefix} SELECT COUNT(*) FROM matched_schedules")
    }

    fn query_rows<T, F>(conn: &duckdb::Connection, sql: &str, map: F) -> Vec<T>
    where
        F: Fn(&duckdb::Row<'_>) -> duckdb::Result<T>,
    {
        let mut stmt = conn.prepare(sql).unwrap();
        let rows = stmt.query_map([], |r| map(r)).unwrap();
        rows.map(|r| r.unwrap()).collect()
    }

    /// A deterministic CI-node-shaped fixture: 4 CPUs, 5 threads pinned to
    /// each, 300 slices per CPU, a wakeup before most slices (matched), some
    /// wakeups inside the thread's previous run (spurious, unmatched), cross-
    /// CPU wakeup targets, duplicate wakeup rows, a thread that wakes but
    /// never runs, and thread_state rows that are not wakeups.
    fn fixture_db() -> duckdb::Connection {
        let conn = duckdb::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE sched_slice (trace_id VARCHAR, ts BIGINT, dur BIGINT, cpu INTEGER, utid BIGINT, end_state INTEGER, priority INTEGER); \
             CREATE TABLE thread_state (trace_id VARCHAR, ts BIGINT, dur BIGINT, utid BIGINT, state INTEGER, cpu INTEGER);",
        )
        .unwrap();
        let mut seed: u64 = 0x5eed_1234_abcd;
        let mut lcg = move |modulus: i64| -> i64 {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            ((seed >> 33) as i64) % modulus
        };
        let mut slices: Vec<(i64, i64, i32, i64)> = Vec::new();
        let mut wakeups: Vec<(i64, i64, i32)> = Vec::new();
        // Per-utid end of the previous slice, to place spurious wakeups inside it.
        let mut prev_end: std::collections::HashMap<i64, (i64, i64)> = Default::default();
        for cpu in 0..4i32 {
            // Disjoint timestamp ranges per CPU keep the only tied event
            // timestamps the +1/-1 pair of one matched wakeup.
            let mut t: i64 = i64::from(cpu) * 10_000_000_000;
            for i in 0..300i64 {
                let utid = i64::from(cpu) * 5 + (i % 5);
                let gap = 1_000 + lcg(20_000);
                let dur = 50_000 + lcg(400_000);
                let ts = t + gap;
                let target = if i % 5 == 0 { (cpu + 1) % 4 } else { cpu };
                if i % 7 == 3 {
                    // Spurious: the wakeup lands inside the thread's previous
                    // run, so neither form matches it to this slice.
                    if let Some(&(pts, pdur)) = prev_end.get(&utid) {
                        wakeups.push((pts + pdur / 2, utid, target));
                    }
                } else {
                    let w = ts - 1 - lcg(gap.max(1));
                    wakeups.push((w, utid, target));
                    if i % 11 == 0 {
                        // Exact duplicate wakeup row: must collapse to one +1.
                        wakeups.push((w, utid, target));
                    }
                }
                slices.push((ts, dur, cpu, utid));
                prev_end.insert(utid, (ts, dur));
                t = ts + dur;
            }
        }
        // A thread that wakes up but never gets a slice.
        for k in 0..5i64 {
            wakeups.push((5_000_000 + k * 777, 999, 2));
        }
        for (ts, dur, cpu, utid) in &slices {
            conn.execute(
                "INSERT INTO sched_slice VALUES ('t', ?, ?, ?, ?, 1, 120)",
                duckdb::params![ts, dur, cpu, utid],
            )
            .unwrap();
        }
        for (ts, utid, cpu) in &wakeups {
            conn.execute(
                "INSERT INTO thread_state VALUES ('t', ?, 0, ?, 0, ?)",
                duckdb::params![ts, utid, cpu],
            )
            .unwrap();
        }
        // Not wakeups: a sleeping state and a wakeup with no CPU.
        conn.execute_batch(
            "INSERT INTO thread_state VALUES ('t', 123456, 1000, 1, 2, 0); \
             INSERT INTO thread_state VALUES ('t', 234567, 0, 1, 0, NULL);",
        )
        .unwrap();
        conn
    }

    #[test]
    fn test_runqueue_query_asof_matches_range_join() {
        let conn = fixture_db();
        let new_sql = build_runqueue_query(None);
        let old_sql = legacy_range_join_runqueue_query();

        // The join is the only thing that changed, and it feeds `events`:
        // the (cpu, ts, summed delta, row count) multiset must be identical.
        let events = |sql: &str| {
            query_rows(&conn, &events_multiset_query(sql), |r| {
                Ok((
                    r.get::<_, i32>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })
        };
        let old_events = events(&old_sql);
        let new_events = events(&new_sql);
        assert!(!old_events.is_empty());
        assert_eq!(old_events, new_events);

        // The fixture exercises both branches: most wakeups match a slice,
        // the spurious ones, the duplicates and the never-running thread's
        // do not.
        let matched =
            |sql: &str| query_rows(&conn, &matched_count_query(sql), |r| r.get::<_, i64>(0))[0];
        let old_matched = matched(&old_sql);
        assert_eq!(old_matched, matched(&new_sql));
        let distinct_wakeups: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM (SELECT DISTINCT ts, utid, cpu FROM thread_state \
                 WHERE state = 0 AND cpu IS NOT NULL)",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(old_matched > 0);
        assert!(old_matched < distinct_wakeups);

        // The percentile stage is untouched; with identical events its only
        // freedom is the order of the +1/-1 pair a matched wakeup puts at one
        // timestamp, which can move a percentile by at most one depth step.
        let percentiles = |sql: &str| {
            query_rows(&conn, sql, |r| {
                Ok((
                    r.get::<_, i32>(0)?,
                    r.get::<_, f64>(1)?,
                    r.get::<_, f64>(2)?,
                    r.get::<_, f64>(3)?,
                ))
            })
        };
        let old_pct = percentiles(&old_sql);
        let new_pct = percentiles(&new_sql);
        assert_eq!(old_pct.len(), 4);
        assert_eq!(old_pct.len(), new_pct.len());
        for (o, n) in old_pct.iter().zip(new_pct.iter()) {
            assert_eq!(o.0, n.0);
            assert!(
                (o.1 - n.1).abs() <= 1.0,
                "p50 cpu {}: {} vs {}",
                o.0,
                o.1,
                n.1
            );
            assert!(
                (o.2 - n.2).abs() <= 1.0,
                "p90 cpu {}: {} vs {}",
                o.0,
                o.2,
                n.2
            );
            assert!(
                (o.3 - n.3).abs() <= 1.0,
                "p99 cpu {}: {} vs {}",
                o.0,
                o.3,
                n.3
            );
        }
        assert!(old_pct.iter().any(|p| p.3 > 0.0));
    }

    #[test]
    fn test_cpu_stats_params_default() {
        let params = CpuStatsParams::default();
        assert!(params.trace_id.is_none());
    }
}
