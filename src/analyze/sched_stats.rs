use anyhow::{bail, Result};
use serde::Serialize;

use super::AnalyzeDb;

/// Parameters for sched stats analysis.
#[derive(Debug, Clone)]
pub struct SchedStatsParams {
    pub pid: Option<u32>,
    pub tid: Option<u32>,
    pub trace_id: Option<String>,
    pub top_n: usize,
}

impl Default for SchedStatsParams {
    fn default() -> Self {
        Self {
            pid: None,
            tid: None,
            trace_id: None,
            top_n: 20,
        }
    }
}

/// Result of sched stats analysis.
#[derive(Debug, Serialize)]
pub struct SchedStatsResult {
    pub summary: SchedSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processes: Option<Vec<ProcessSchedStats>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threads: Option<Vec<ThreadSchedStats>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_detail: Option<ThreadDetailStats>,
}

/// Summary-level scheduling statistics.
///
/// Note: `d_sleep_seconds` is an approximation. It measures the gap between
/// consecutive sched_slices when the prior slice ended with an uninterruptible
/// state (end_state & 2 != 0, covering both TASK_UNINTERRUPTIBLE and compound
/// states like TASK_UNINTERRUPTIBLE | TASK_NOLOAD). This gap includes both the
/// actual uninterruptible sleep time and any subsequent scheduler runqueue
/// latency before the thread was next scheduled.
#[derive(Debug, Serialize)]
pub struct SchedSummary {
    pub trace_duration_seconds: f64,
    pub total_events: u64,
    pub total_cpu_time_seconds: f64,
    pub d_sleep_seconds: f64,
    pub cpus_observed: u32,
    pub process_count: u32,
    pub thread_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
}

/// Per-process scheduling statistics.
#[derive(Debug, Serialize)]
pub struct ProcessSchedStats {
    pub pid: i64,
    pub name: String,
    pub thread_count: u32,
    pub cpu_time_seconds: f64,
    pub d_sleep_seconds: f64,
    pub event_count: u64,
    pub avg_slice_us: f64,
    pub preempt_pct: f64,
}

/// Per-thread scheduling statistics.
#[derive(Debug, Serialize)]
pub struct ThreadSchedStats {
    pub tid: i64,
    pub name: String,
    pub cpu_time_seconds: f64,
    pub d_sleep_seconds: f64,
    pub event_count: u64,
    pub avg_slice_us: f64,
    pub min_slice_us: f64,
    pub max_slice_us: f64,
    pub preempt_pct: f64,
}

/// Detailed stats for a single thread.
#[derive(Debug, Serialize)]
pub struct ThreadDetailStats {
    pub tid: i64,
    pub pid: i64,
    pub thread_name: String,
    pub process_name: String,
    pub cpu_time_seconds: f64,
    pub d_sleep_seconds: f64,
    pub event_count: u64,
    pub avg_slice_us: f64,
    pub min_slice_us: f64,
    pub max_slice_us: f64,
    pub cpu_migrations: u64,
    pub end_states: Vec<EndStateCount>,
}

/// Count and percentage for a particular end state.
#[derive(Debug, Serialize)]
pub struct EndStateCount {
    pub state: String,
    pub count: u64,
    pub percent: f64,
}

impl AnalyzeDb {
    /// Run sched stats analysis.
    pub fn sched_stats(&self, params: &SchedStatsParams) -> Result<SchedStatsResult> {
        // Validate required tables
        if !self.table_exists("sched_slice")? {
            bail!("Database missing sched_slice table. Is this a systing trace database?");
        }
        if !self.table_has_rows("sched_slice")? {
            bail!("No scheduling events found in database.");
        }
        if !self.table_exists("thread")? || !self.table_exists("process")? {
            bail!("Database missing thread/process tables required for sched stats.");
        }

        let trace_id = params.trace_id.as_deref();

        if let Some(tid) = params.tid {
            self.sched_stats_per_thread(tid, trace_id)
        } else if let Some(pid) = params.pid {
            self.sched_stats_per_process(pid, trace_id, params.top_n)
        } else {
            self.sched_stats_whole_trace(trace_id, params.top_n)
        }
    }

    fn sched_stats_whole_trace(
        &self,
        trace_id: Option<&str>,
        top_n: usize,
    ) -> Result<SchedStatsResult> {
        // Summary aggregates
        let summary_sql = build_sched_summary_query(trace_id);
        let mut stmt = self.conn.prepare(&summary_sql)?;
        let mut rows = stmt.query([])?;
        let row = rows
            .next()?
            .ok_or_else(|| anyhow::anyhow!("No summary data"))?;
        let total_events: i64 = row.get(0)?;
        let total_cpu_time_s: f64 = row.get(1)?;
        let cpus: i64 = row.get(2)?;
        let thread_count: i64 = row.get(3)?;
        let trace_dur_s: f64 = row.get(4)?;

        // Process count
        let pcount_sql = build_process_count_query(trace_id);
        let mut stmt = self.conn.prepare(&pcount_sql)?;
        let mut rows = stmt.query([])?;
        let process_count: i64 = rows.next()?.map(|r| r.get(0).unwrap_or(0)).unwrap_or(0);

        // Total D-sleep time (uses D_SLEEP_SUM_EXPR via build_total_d_sleep_query)
        let dsleep_sql = build_total_d_sleep_query(trace_id);
        let mut stmt = self.conn.prepare(&dsleep_sql)?;
        let mut rows = stmt.query([])?;
        let d_sleep_s: f64 = rows.next()?.map(|r| r.get(0).unwrap_or(0.0)).unwrap_or(0.0);

        let summary = SchedSummary {
            trace_duration_seconds: trace_dur_s,
            total_events: u64::try_from(total_events).unwrap_or(0),
            total_cpu_time_seconds: total_cpu_time_s,
            d_sleep_seconds: d_sleep_s,
            cpus_observed: u32::try_from(cpus).unwrap_or(0),
            process_count: u32::try_from(process_count).unwrap_or(0),
            thread_count: u32::try_from(thread_count).unwrap_or(0),
            process_name: None,
        };

        // Per-process ranking (includes D_SLEEP_SUM_EXPR for per-process d-sleep)
        let ranking_sql = build_process_ranking_query(trace_id, top_n);
        let mut stmt = self.conn.prepare(&ranking_sql)?;
        let mut rows = stmt.query([])?;
        let mut processes = Vec::new();
        while let Some(row) = rows.next()? {
            processes.push(ProcessSchedStats {
                pid: row.get(0)?,
                name: row.get(1)?,
                thread_count: u32::try_from(row.get::<_, i64>(2)?).unwrap_or(0),
                cpu_time_seconds: row.get(3)?,
                d_sleep_seconds: row.get(4)?,
                event_count: u64::try_from(row.get::<_, i64>(5)?).unwrap_or(0),
                avg_slice_us: row.get(6)?,
                preempt_pct: row.get(7)?,
            });
        }

        Ok(SchedStatsResult {
            summary,
            processes: Some(processes),
            threads: None,
            thread_detail: None,
        })
    }

    fn sched_stats_per_process(
        &self,
        pid: u32,
        trace_id: Option<&str>,
        top_n: usize,
    ) -> Result<SchedStatsResult> {
        // Process aggregate (includes D_SLEEP_SUM_EXPR for process-level d-sleep)
        let agg_sql = build_process_aggregate_query(pid, trace_id);
        let mut stmt = self.conn.prepare(&agg_sql)?;
        let mut rows = stmt.query([])?;

        let summary = if let Some(row) = rows.next()? {
            let cpu_time_s: f64 = row.get(0)?;
            let d_sleep_s: f64 = row.get(1)?;
            let events: i64 = row.get(2)?;
            let tcount: i64 = row.get(3)?;
            let process_name: String = row.get(4)?;
            SchedSummary {
                trace_duration_seconds: 0.0, // not applicable for per-process
                total_events: u64::try_from(events).unwrap_or(0),
                total_cpu_time_seconds: cpu_time_s,
                d_sleep_seconds: d_sleep_s,
                cpus_observed: 0,
                process_count: 1,
                thread_count: u32::try_from(tcount).unwrap_or(0),
                process_name: Some(process_name),
            }
        } else {
            // PID not found -- return zeroed summary
            SchedSummary {
                trace_duration_seconds: 0.0,
                total_events: 0,
                total_cpu_time_seconds: 0.0,
                d_sleep_seconds: 0.0,
                cpus_observed: 0,
                process_count: 0,
                thread_count: 0,
                process_name: None,
            }
        };

        // Per-thread breakdown (includes D_SLEEP_SUM_EXPR for per-thread d-sleep)
        let thread_sql = build_thread_breakdown_query(pid, trace_id, top_n);
        let mut stmt = self.conn.prepare(&thread_sql)?;
        let mut rows = stmt.query([])?;
        let mut threads = Vec::new();
        while let Some(row) = rows.next()? {
            threads.push(ThreadSchedStats {
                tid: row.get(0)?,
                name: row.get(1)?,
                cpu_time_seconds: row.get(2)?,
                d_sleep_seconds: row.get(3)?,
                event_count: u64::try_from(row.get::<_, i64>(4)?).unwrap_or(0),
                avg_slice_us: row.get(5)?,
                min_slice_us: row.get(6)?,
                max_slice_us: row.get(7)?,
                preempt_pct: row.get(8)?,
            });
        }

        Ok(SchedStatsResult {
            summary,
            processes: None,
            threads: Some(threads),
            thread_detail: None,
        })
    }

    fn sched_stats_per_thread(&self, tid: u32, trace_id: Option<&str>) -> Result<SchedStatsResult> {
        // Main stats (includes D_SLEEP_SUM_EXPR for thread-level d-sleep)
        let detail_sql = build_thread_detail_query(tid, trace_id);
        let mut stmt = self.conn.prepare(&detail_sql)?;
        let mut rows = stmt.query([])?;

        let (summary, thread_detail) = if let Some(row) = rows.next()? {
            let cpu_time_s: f64 = row.get(0)?;
            let d_sleep_s: f64 = row.get(1)?;
            let events: i64 = row.get(2)?;
            let avg_us: f64 = row.get(3)?;
            let min_us: f64 = row.get(4)?;
            let max_us: f64 = row.get(5)?;
            let migrations: i64 = row.get(6)?;
            let r_tid: i64 = row.get(7)?;
            let thread_name: String = row.get(8)?;
            let r_pid: i64 = row.get(9)?;
            let process_name: String = row.get(10)?;

            drop(rows);
            drop(stmt);

            // End state distribution
            let end_sql = build_end_state_query(tid, trace_id);
            let mut stmt2 = self.conn.prepare(&end_sql)?;
            let mut rows2 = stmt2.query([])?;
            let mut end_states = Vec::new();
            while let Some(row) = rows2.next()? {
                end_states.push(EndStateCount {
                    state: row.get(0)?,
                    count: u64::try_from(row.get::<_, i64>(1)?).unwrap_or(0),
                    percent: row.get(2)?,
                });
            }

            let events_u64 = u64::try_from(events).unwrap_or(0);
            let migrations_u64 = u64::try_from(migrations).unwrap_or(0);

            let summary = SchedSummary {
                trace_duration_seconds: 0.0,
                total_events: events_u64,
                total_cpu_time_seconds: cpu_time_s,
                d_sleep_seconds: d_sleep_s,
                cpus_observed: 0,
                process_count: 1,
                thread_count: 1,
                process_name: Some(process_name.clone()),
            };

            let detail = ThreadDetailStats {
                tid: r_tid,
                pid: r_pid,
                thread_name,
                process_name,
                cpu_time_seconds: cpu_time_s,
                d_sleep_seconds: d_sleep_s,
                event_count: events_u64,
                avg_slice_us: avg_us,
                min_slice_us: min_us,
                max_slice_us: max_us,
                cpu_migrations: migrations_u64,
                end_states,
            };

            (summary, Some(detail))
        } else {
            // TID not found
            let summary = SchedSummary {
                trace_duration_seconds: 0.0,
                total_events: 0,
                total_cpu_time_seconds: 0.0,
                d_sleep_seconds: 0.0,
                cpus_observed: 0,
                process_count: 0,
                thread_count: 0,
                process_name: None,
            };
            (summary, None)
        };

        Ok(SchedStatsResult {
            summary,
            processes: None,
            threads: None,
            thread_detail,
        })
    }
}

// -- Sched stats query builders --

/// SQL expression for computing D-sleep time from the sched_next CTE.
/// Uses bitwise check (`& 2 != 0`) to catch compound uninterruptible states
/// like TASK_UNINTERRUPTIBLE | TASK_NOLOAD (130).
const D_SLEEP_SUM_EXPR: &str =
    "COALESCE(SUM(CASE WHEN sn.end_state & 2 != 0 AND sn.next_ts IS NOT NULL \
    THEN sn.next_ts - (sn.ts + sn.dur) ELSE 0 END), 0)";

/// Build the `sched_next` CTE that adds a `next_ts` column via LEAD().
fn build_sched_next_cte(filter: &str) -> String {
    format!(
        "WITH sched_next AS (\
         SELECT *, LEAD(ts) OVER (PARTITION BY utid ORDER BY ts) as next_ts \
         FROM sched_slice \
         WHERE dur > 0{filter})"
    )
}

/// Build a trace_id SQL filter clause (e.g., ` AND ss.trace_id = '...'`).
/// trace_id values are escaped via single-quote doubling for safe SQL interpolation.
fn trace_id_filter(trace_id: Option<&str>, table_alias: &str) -> String {
    match trace_id {
        Some(tid) => {
            let escaped = tid.replace('\'', "''");
            format!(" AND {table_alias}trace_id = '{escaped}'")
        }
        None => String::new(),
    }
}

fn build_sched_summary_query(trace_id: Option<&str>) -> String {
    let filter = trace_id_filter(trace_id, "ss.");
    format!(
        "SELECT COUNT(*) as events, \
         SUM(dur) / 1e9 as total_cpu_time_s, \
         COUNT(DISTINCT cpu) as cpus, \
         COUNT(DISTINCT ss.utid) as threads, \
         (MAX(ss.ts + ss.dur) - MIN(ss.ts)) / 1e9 as trace_dur_s \
         FROM sched_slice ss \
         WHERE ss.dur > 0{filter}"
    )
}

fn build_process_count_query(trace_id: Option<&str>) -> String {
    let ss_filter = trace_id_filter(trace_id, "ss.");
    let t_filter = trace_id_filter(trace_id, "t.");
    let p_filter = trace_id_filter(trace_id, "p.");
    format!(
        "SELECT COUNT(DISTINCT p.pid) as process_count \
         FROM sched_slice ss \
         JOIN thread t ON ss.utid = t.utid AND ss.trace_id = t.trace_id{t_filter} \
         JOIN process p ON t.upid = p.upid AND t.trace_id = p.trace_id{p_filter} \
         WHERE ss.dur > 0{ss_filter}"
    )
}

fn build_total_d_sleep_query(trace_id: Option<&str>) -> String {
    let filter = trace_id_filter(trace_id, "");
    format!(
        "{sched_next_cte} \
         SELECT {d_sleep_sum} / 1e9 as d_sleep_s \
         FROM sched_next sn",
        sched_next_cte = build_sched_next_cte(&filter),
        d_sleep_sum = D_SLEEP_SUM_EXPR,
    )
}

fn build_process_ranking_query(trace_id: Option<&str>, limit: usize) -> String {
    let cte_filter = trace_id_filter(trace_id, "");
    let t_filter = trace_id_filter(trace_id, "t.");
    let p_filter = trace_id_filter(trace_id, "p.");
    format!(
        "{sched_next_cte} \
         SELECT p.pid, COALESCE(p.name, '') as name, \
         COUNT(DISTINCT t.tid) as thread_count, \
         SUM(sn.dur) / 1e9 as cpu_time_s, \
         {d_sleep_sum} / 1e9 as d_sleep_s, \
         COUNT(*) as events, \
         AVG(sn.dur) / 1e3 as avg_slice_us, \
         100.0 * SUM(CASE WHEN sn.end_state IS NULL THEN 1 ELSE 0 END) \
         / NULLIF(COUNT(*), 0) as preempt_pct \
         FROM sched_next sn \
         JOIN thread t ON sn.utid = t.utid AND sn.trace_id = t.trace_id{t_filter} \
         JOIN process p ON t.upid = p.upid AND t.trace_id = p.trace_id{p_filter} \
         GROUP BY p.pid, p.name \
         ORDER BY cpu_time_s DESC \
         LIMIT {limit}",
        sched_next_cte = build_sched_next_cte(&cte_filter),
        d_sleep_sum = D_SLEEP_SUM_EXPR,
    )
}

fn build_process_aggregate_query(pid: u32, trace_id: Option<&str>) -> String {
    let cte_filter = trace_id_filter(trace_id, "");
    let t_filter = trace_id_filter(trace_id, "t.");
    let p_filter = trace_id_filter(trace_id, "p.");
    format!(
        "{sched_next_cte} \
         SELECT SUM(sn.dur) / 1e9 as cpu_time_s, \
         {d_sleep_sum} / 1e9 as d_sleep_s, \
         COUNT(*) as events, \
         COUNT(DISTINCT t.tid) as thread_count, \
         COALESCE(p.name, '') as process_name \
         FROM sched_next sn \
         JOIN thread t ON sn.utid = t.utid AND sn.trace_id = t.trace_id{t_filter} \
         JOIN process p ON t.upid = p.upid AND t.trace_id = p.trace_id{p_filter} \
         WHERE p.pid = {pid} \
         GROUP BY p.name",
        sched_next_cte = build_sched_next_cte(&cte_filter),
        d_sleep_sum = D_SLEEP_SUM_EXPR,
    )
}

fn build_thread_breakdown_query(pid: u32, trace_id: Option<&str>, limit: usize) -> String {
    let cte_filter = trace_id_filter(trace_id, "");
    let t_filter = trace_id_filter(trace_id, "t.");
    let p_filter = trace_id_filter(trace_id, "p.");
    format!(
        "{sched_next_cte} \
         SELECT t.tid, COALESCE(t.name, '') as name, \
         SUM(sn.dur) / 1e9 as cpu_time_s, \
         {d_sleep_sum} / 1e9 as d_sleep_s, \
         COUNT(*) as events, \
         AVG(sn.dur) / 1e3 as avg_slice_us, \
         MIN(sn.dur) / 1e3 as min_slice_us, \
         MAX(sn.dur) / 1e3 as max_slice_us, \
         100.0 * SUM(CASE WHEN sn.end_state IS NULL THEN 1 ELSE 0 END) \
         / NULLIF(COUNT(*), 0) as preempt_pct \
         FROM sched_next sn \
         JOIN thread t ON sn.utid = t.utid AND sn.trace_id = t.trace_id{t_filter} \
         JOIN process p ON t.upid = p.upid AND t.trace_id = p.trace_id{p_filter} \
         WHERE p.pid = {pid} \
         GROUP BY t.tid, t.name \
         ORDER BY cpu_time_s DESC \
         LIMIT {limit}",
        sched_next_cte = build_sched_next_cte(&cte_filter),
        d_sleep_sum = D_SLEEP_SUM_EXPR,
    )
}

fn build_thread_detail_query(tid: u32, trace_id: Option<&str>) -> String {
    let filter = trace_id_filter(trace_id, "");
    let t_filter = trace_id_filter(trace_id, "t.");
    let p_filter = trace_id_filter(trace_id, "p.");
    format!(
        "WITH sched_next AS (\
         SELECT *, \
         LAG(cpu) OVER (PARTITION BY utid ORDER BY ts) as prev_cpu, \
         LEAD(ts) OVER (PARTITION BY utid ORDER BY ts) as next_ts \
         FROM sched_slice \
         WHERE utid = (SELECT utid FROM thread WHERE tid = {tid}{filter} LIMIT 1) \
         AND dur > 0{filter}) \
         SELECT SUM(sn.dur) / 1e9 as cpu_time_s, \
         {d_sleep_sum} / 1e9 as d_sleep_s, \
         COUNT(*) as events, \
         AVG(sn.dur) / 1e3 as avg_slice_us, \
         MIN(sn.dur) / 1e3 as min_slice_us, \
         MAX(sn.dur) / 1e3 as max_slice_us, \
         SUM(CASE WHEN sn.cpu != sn.prev_cpu AND sn.prev_cpu IS NOT NULL \
         THEN 1 ELSE 0 END) as cpu_migrations, \
         t.tid, COALESCE(t.name, '') as thread_name, \
         p.pid, COALESCE(p.name, '') as process_name \
         FROM sched_next sn \
         JOIN thread t ON sn.utid = t.utid AND sn.trace_id = t.trace_id{t_filter} \
         JOIN process p ON t.upid = p.upid AND t.trace_id = p.trace_id{p_filter} \
         GROUP BY t.tid, t.name, p.pid, p.name",
        d_sleep_sum = D_SLEEP_SUM_EXPR,
    )
}

fn build_end_state_query(tid: u32, trace_id: Option<&str>) -> String {
    let ss_filter = trace_id_filter(trace_id, "ss.");
    let t_filter = trace_id_filter(trace_id, "t.");
    format!(
        "SELECT CASE \
         WHEN ss.end_state IS NULL THEN 'Preempted (running)' \
         WHEN ss.end_state & 2 != 0 THEN 'Uninterruptible sleep (D)' \
         WHEN ss.end_state & 1 != 0 THEN 'Interruptible sleep (S)' \
         WHEN ss.end_state & 4 != 0 THEN 'Stopped' \
         WHEN ss.end_state & 8 != 0 THEN 'Traced' \
         WHEN ss.end_state & 16 != 0 THEN 'Exit (dead)' \
         WHEN ss.end_state & 32 != 0 THEN 'Exit (zombie)' \
         ELSE 'Other (' || CAST(ss.end_state AS VARCHAR) || ')' \
         END as state, \
         COUNT(*) as count, \
         100.0 * COUNT(*) / NULLIF(SUM(COUNT(*)) OVER (), 0) as pct \
         FROM sched_slice ss \
         JOIN thread t ON ss.utid = t.utid AND ss.trace_id = t.trace_id{t_filter} \
         WHERE t.tid = {tid} AND ss.dur > 0{ss_filter} \
         GROUP BY ss.end_state \
         ORDER BY count DESC"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_sched_summary_query_no_trace_id() {
        let sql = build_sched_summary_query(None);
        assert!(sql.contains("FROM sched_slice ss"));
        assert!(sql.contains("WHERE ss.dur > 0"));
        assert!(!sql.contains("trace_id"));
    }

    #[test]
    fn test_build_sched_summary_query_with_trace_id() {
        let sql = build_sched_summary_query(Some("trace-1"));
        assert!(sql.contains("ss.trace_id = 'trace-1'"));
    }

    #[test]
    fn test_build_process_ranking_query_has_limit() {
        let sql = build_process_ranking_query(None, 10);
        assert!(sql.contains("LIMIT 10"));
        assert!(sql.contains("ORDER BY cpu_time_s DESC"));
        assert!(sql.contains("JOIN thread t"));
        assert!(sql.contains("JOIN process p"));
    }

    #[test]
    fn test_build_process_ranking_query_uses_cte() {
        let sql = build_process_ranking_query(None, 20);
        assert!(sql.contains("WITH sched_next AS"));
        assert!(sql.contains("LEAD(ts) OVER (PARTITION BY utid ORDER BY ts)"));
    }

    #[test]
    fn test_build_thread_detail_query_has_migrations() {
        let sql = build_thread_detail_query(1234, None);
        assert!(sql.contains("LAG(cpu) OVER (PARTITION BY utid ORDER BY ts)"));
        assert!(sql.contains("cpu_migrations"));
        assert!(sql.contains("WHERE utid = (SELECT utid FROM thread WHERE tid = 1234"));
    }

    #[test]
    fn test_build_thread_detail_query_with_trace_id() {
        let sql = build_thread_detail_query(42, Some("t1"));
        assert!(sql.contains("t.trace_id = 't1'"));
        assert!(sql.contains("p.trace_id = 't1'"));
        // Subquery should use unaliased trace_id filter, not t. alias
        assert!(
            sql.contains("FROM thread WHERE tid = 42 AND trace_id = 't1'"),
            "subquery should use unaliased trace_id filter: {sql}"
        );
    }

    #[test]
    fn test_build_end_state_query_covers_all_states() {
        let sql = build_end_state_query(100, None);
        assert!(sql.contains("Preempted (running)"));
        assert!(sql.contains("Interruptible sleep (S)"));
        assert!(sql.contains("Uninterruptible sleep (D)"));
        assert!(sql.contains("Stopped"));
        assert!(sql.contains("Exit (dead)"));
        assert!(sql.contains("Exit (zombie)"));
        assert!(sql.contains("ORDER BY count DESC"));
        // Verify bitwise checks for compound states
        assert!(
            sql.contains("end_state & 2 != 0"),
            "should use bitwise check for D-state"
        );
    }

    #[test]
    fn test_build_process_aggregate_query_filters_pid() {
        let sql = build_process_aggregate_query(5678, None);
        assert!(sql.contains("WHERE p.pid = 5678"));
        assert!(sql.contains("GROUP BY p.name"));
    }

    #[test]
    fn test_build_thread_breakdown_query_filters_pid_with_limit() {
        let sql = build_thread_breakdown_query(1000, None, 5);
        assert!(sql.contains("WHERE p.pid = 1000"));
        assert!(sql.contains("LIMIT 5"));
        assert!(sql.contains("ORDER BY cpu_time_s DESC"));
    }

    #[test]
    fn test_d_sleep_sum_expr_used_consistently() {
        // Verify the shared D_SLEEP_SUM_EXPR appears in queries that use it
        let total = build_total_d_sleep_query(None);
        assert!(total.contains("end_state & 2 != 0"));
        assert!(total.contains("next_ts IS NOT NULL"));

        let ranking = build_process_ranking_query(None, 10);
        assert!(ranking.contains("end_state & 2 != 0"));
        assert!(ranking.contains("next_ts IS NOT NULL"));
    }

    #[test]
    fn test_sched_stats_params_default() {
        let params = SchedStatsParams::default();
        assert_eq!(params.pid, None);
        assert_eq!(params.tid, None);
        assert_eq!(params.trace_id, None);
        assert_eq!(params.top_n, 20);
    }
}
