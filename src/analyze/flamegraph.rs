use anyhow::{bail, Result};
use serde::Serialize;
use std::fmt;
use std::str::FromStr;

use super::AnalyzeDb;

/// Stack type filter for flamegraph analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackTypeFilter {
    Cpu,
    InterruptibleSleep,
    UninterruptibleSleep,
    AllSleep,
    All,
}

impl StackTypeFilter {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::InterruptibleSleep => "interruptible-sleep",
            Self::UninterruptibleSleep => "uninterruptible-sleep",
            Self::AllSleep => "all-sleep",
            Self::All => "all",
        }
    }
}

impl fmt::Display for StackTypeFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for StackTypeFilter {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "cpu" => Ok(Self::Cpu),
            "interruptible-sleep" => Ok(Self::InterruptibleSleep),
            "uninterruptible-sleep" => Ok(Self::UninterruptibleSleep),
            "all-sleep" => Ok(Self::AllSleep),
            "all" => Ok(Self::All),
            _ => bail!(
                "Invalid stack type: {s}. Must be one of: cpu, interruptible-sleep, \
                 uninterruptible-sleep, all-sleep, all"
            ),
        }
    }
}

/// Parameters for flamegraph analysis.
#[derive(Debug, Clone)]
pub struct FlamegraphParams {
    pub stack_type: StackTypeFilter,
    pub pid: Option<u32>,
    pub tid: Option<u32>,
    pub start_time: Option<f64>,
    pub end_time: Option<f64>,
    pub trace_id: Option<String>,
    pub min_count: u64,
    pub top_n: usize,
}

impl Default for FlamegraphParams {
    fn default() -> Self {
        Self {
            stack_type: StackTypeFilter::Cpu,
            pid: None,
            tid: None,
            start_time: None,
            end_time: None,
            trace_id: None,
            min_count: 1,
            top_n: 500,
        }
    }
}

/// A single stack entry in flamegraph results.
#[derive(Debug, Serialize)]
pub struct StackEntry {
    pub frames: Vec<String>,
    pub count: u64,
}

/// Metadata about a flamegraph result.
#[derive(Debug, Serialize)]
pub struct FlamegraphMetadata {
    pub total_samples: u64,
    pub unique_stacks: u64,
    pub time_range_seconds: (f64, f64),
    pub stack_type: String,
}

/// Result of a flamegraph analysis.
#[derive(Debug, Serialize)]
pub struct FlamegraphResult {
    pub stacks: Vec<StackEntry>,
    pub metadata: FlamegraphMetadata,
    pub folded: String,
}

impl AnalyzeDb {
    /// Run flamegraph analysis and return structured results.
    pub fn flamegraph(&self, params: &FlamegraphParams) -> Result<FlamegraphResult> {
        if !self.table_exists("stack_sample")? || !self.table_exists("stack")? {
            bail!(
                "Database missing required tables (stack_sample, stack). \
                 Is this a systing trace database?"
            );
        }

        let (min_ts, max_ts, total_samples) =
            self.get_trace_time_range(params.trace_id.as_deref())?;

        let abs_start = params.start_time.map(|t| min_ts + (t * 1e9) as i64);
        let abs_end = params.end_time.map(|t| min_ts + (t * 1e9) as i64);

        let sql = build_flamegraph_query(
            params.stack_type,
            params.pid,
            params.tid,
            abs_start,
            abs_end,
            params.trace_id.as_deref(),
            params.min_count,
        );

        let mut stmt = self.conn.prepare(&sql)?;
        let mut rows = stmt.query([])?;

        let mut stacks = Vec::new();
        let mut folded_lines = Vec::new();
        let mut unique_stacks: u64 = 0;

        while let Some(row) = rows.next()? {
            let frames_str: String = row.get(0)?;
            let count: i64 = row.get(1)?;
            let count = count as u64;

            let folded = format_folded_stack(&frames_str);
            if folded.is_empty() {
                continue;
            }

            unique_stacks += 1;

            if stacks.len() < params.top_n {
                let frames: Vec<String> = folded.split(';').map(|s| s.to_string()).collect();
                folded_lines.push(format!("{folded} {count}"));
                stacks.push(StackEntry { frames, count });
            }
        }

        let duration_secs = (max_ts - min_ts) as f64 / 1e9;

        Ok(FlamegraphResult {
            stacks,
            metadata: FlamegraphMetadata {
                total_samples,
                unique_stacks,
                time_range_seconds: (0.0, duration_secs),
                stack_type: params.stack_type.to_string(),
            },
            folded: folded_lines.join("\n"),
        })
    }
}

fn build_flamegraph_query(
    stack_type: StackTypeFilter,
    pid: Option<u32>,
    tid: Option<u32>,
    abs_start: Option<i64>,
    abs_end: Option<i64>,
    trace_id: Option<&str>,
    min_count: u64,
) -> String {
    let mut joins = String::new();
    let mut conditions = Vec::new();

    match stack_type {
        StackTypeFilter::Cpu => {
            conditions.push("ss.stack_event_type = 1".to_string());
        }
        StackTypeFilter::InterruptibleSleep => {
            conditions.push("ss.stack_event_type = 2".to_string());
        }
        StackTypeFilter::UninterruptibleSleep => {
            conditions.push("ss.stack_event_type = 0".to_string());
        }
        StackTypeFilter::AllSleep => {
            conditions.push("ss.stack_event_type IN (0, 2)".to_string());
        }
        StackTypeFilter::All => {}
    }

    if pid.is_some() || tid.is_some() {
        joins.push_str(" JOIN thread t ON ss.utid = t.utid AND ss.trace_id = t.trace_id");
    }
    if pid.is_some() {
        joins.push_str(" JOIN process p ON t.upid = p.upid AND t.trace_id = p.trace_id");
    }

    if let Some(pid_val) = pid {
        conditions.push(format!("p.pid = {pid_val}"));
    }
    if let Some(tid_val) = tid {
        conditions.push(format!("t.tid = {tid_val}"));
    }

    if let Some(start) = abs_start {
        conditions.push(format!("ss.ts >= {start}"));
    }
    if let Some(end) = abs_end {
        conditions.push(format!("ss.ts <= {end}"));
    }

    if let Some(tid) = trace_id {
        // trace_id is escaped via single-quote doubling for safe SQL interpolation
        let escaped = tid.replace('\'', "''");
        conditions.push(format!("ss.trace_id = '{escaped}'"));
    }

    conditions.push("s.frame_names IS NOT NULL".to_string());
    conditions.push("len(s.frame_names) > 0".to_string());

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", conditions.join(" AND "))
    };

    let having_clause = if min_count > 1 {
        format!(" HAVING COUNT(*) >= {min_count}")
    } else {
        String::new()
    };

    format!(
        "SELECT array_to_string(s.frame_names, chr(31)) as frames, \
         COUNT(*) as count \
         FROM stack_sample ss \
         JOIN stack s ON ss.stack_id = s.id AND ss.trace_id = s.trace_id\
         {joins}{where_clause} \
         GROUP BY s.frame_names{having_clause} \
         ORDER BY count DESC"
    )
}

/// Format a DuckDB frame_names array (as chr(31)-separated string) into folded stack format.
///
/// Frame names are stored leaf-to-root in the database, so they are reversed
/// to root-to-leaf order for flamegraph convention (root;child;...;leaf).
fn format_folded_stack(frames_str: &str) -> String {
    if frames_str.is_empty() {
        return String::new();
    }

    let frames: Vec<&str> = frames_str.split('\x1F').collect();

    // Reverse from leaf-to-root (storage order) to root-to-leaf (flamegraph convention)
    let formatted: Vec<String> = frames.iter().rev().map(|f| format_frame(f)).collect();

    formatted.join(";")
}

/// Simplify a frame name for folded output.
///
/// Input format: `function_name (module_name [file:line]) <0xaddr>`
/// Output format: `function_name [module_name]`
///
/// Unsymbolized frames (bare hex addresses like `0x5dbfa1`) become `0x5dbfa1 [unknown]`.
fn format_frame(frame: &str) -> String {
    let frame = frame.trim();
    if frame.is_empty() {
        return "[unknown]".to_string();
    }

    // Try to parse: "function_name (module_name [file:line]) <0xaddr>"
    // or: "function_name (module_name) <0xaddr>"
    if let Some(paren_pos) = frame.find(" (") {
        let func_name = &frame[..paren_pos];
        let rest = &frame[paren_pos + 2..];

        // Extract module name (up to ' [' for source location or ')' for end)
        let module_end = rest
            .find(" [")
            .or_else(|| rest.find(')'))
            .unwrap_or(rest.len());
        let module_name = &rest[..module_end];

        if module_name.is_empty() {
            func_name.to_string()
        } else {
            format!("{func_name} [{module_name}]")
        }
    } else if frame.starts_with("0x") {
        // Bare hex address (unsymbolized)
        format!("{frame} [unknown]")
    } else {
        // Unknown format, return as-is
        frame.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_frame_symbolized() {
        assert_eq!(
            format_frame("tcp_sendmsg (vmlinux [net/ipv4/tcp.c:1234]) <0xffffffff8ec7559e>"),
            "tcp_sendmsg [vmlinux]"
        );
    }

    #[test]
    fn test_format_frame_with_module_only() {
        assert_eq!(format_frame("main (myapp) <0x401234>"), "main [myapp]");
    }

    #[test]
    fn test_format_frame_kernel_unknown() {
        assert_eq!(
            format_frame("unknown ([kernel]) <0xffffffff8e000000>"),
            "unknown [[kernel]]"
        );
    }

    #[test]
    fn test_format_frame_bare_hex() {
        assert_eq!(format_frame("0x5dbfa1"), "0x5dbfa1 [unknown]");
    }

    #[test]
    fn test_format_frame_empty() {
        assert_eq!(format_frame(""), "[unknown]");
    }

    #[test]
    fn test_format_folded_stack_reversal() {
        // frame_names stored leaf-to-root: "leaf\x1Fmid\x1Froot"
        // Should output root-to-leaf: "root;mid;leaf"
        let input = "leaf (app) <0x1>\x1Fmid (app) <0x2>\x1Froot (app) <0x3>";
        let result = format_folded_stack(input);
        assert_eq!(result, "root [app];mid [app];leaf [app]");
    }

    #[test]
    fn test_format_folded_stack_empty() {
        assert_eq!(format_folded_stack(""), "");
    }

    #[test]
    fn test_format_folded_stack_single_frame() {
        let input = "main (myapp) <0x401234>";
        assert_eq!(format_folded_stack(input), "main [myapp]");
    }

    #[test]
    fn test_build_flamegraph_query_cpu() {
        let sql = build_flamegraph_query(StackTypeFilter::Cpu, None, None, None, None, None, 1);
        assert!(sql.contains("stack_event_type = 1"));
        assert!(!sql.contains("sched_slice"));
    }

    #[test]
    fn test_build_flamegraph_query_interruptible_sleep() {
        let sql = build_flamegraph_query(
            StackTypeFilter::InterruptibleSleep,
            None,
            None,
            None,
            None,
            None,
            1,
        );
        assert!(sql.contains("stack_event_type = 2"));
        assert!(!sql.contains("sched_slice"));
        assert!(!sql.contains("end_state"));
    }

    #[test]
    fn test_build_flamegraph_query_uninterruptible_sleep() {
        let sql = build_flamegraph_query(
            StackTypeFilter::UninterruptibleSleep,
            None,
            None,
            None,
            None,
            None,
            1,
        );
        assert!(sql.contains("stack_event_type = 0"));
        assert!(!sql.contains("sched_slice"));
        assert!(!sql.contains("end_state"));
    }

    #[test]
    fn test_build_flamegraph_query_all_sleep() {
        let sql =
            build_flamegraph_query(StackTypeFilter::AllSleep, None, None, None, None, None, 1);
        assert!(sql.contains("stack_event_type IN (0, 2)"));
        assert!(!sql.contains("sched_slice"));
        assert!(!sql.contains("end_state"));
    }

    #[test]
    fn test_build_flamegraph_query_with_pid() {
        let sql =
            build_flamegraph_query(StackTypeFilter::Cpu, Some(1234), None, None, None, None, 1);
        assert!(sql.contains("JOIN thread t"));
        assert!(sql.contains("JOIN process p"));
        assert!(sql.contains("p.pid = 1234"));
    }

    #[test]
    fn test_build_flamegraph_query_with_min_count() {
        let sql = build_flamegraph_query(StackTypeFilter::All, None, None, None, None, None, 10);
        assert!(sql.contains("HAVING COUNT(*) >= 10"));
    }

    #[test]
    fn test_build_flamegraph_query_no_having_for_min_count_1() {
        let sql = build_flamegraph_query(StackTypeFilter::All, None, None, None, None, None, 1);
        assert!(!sql.contains("HAVING"));
    }

    #[test]
    fn test_stack_type_filter_roundtrip() {
        for st in &[
            StackTypeFilter::Cpu,
            StackTypeFilter::InterruptibleSleep,
            StackTypeFilter::UninterruptibleSleep,
            StackTypeFilter::AllSleep,
            StackTypeFilter::All,
        ] {
            let s = st.as_str();
            let parsed: StackTypeFilter = s.parse().unwrap();
            assert_eq!(*st, parsed);
        }
    }

    #[test]
    fn test_stack_type_filter_invalid() {
        let result: Result<StackTypeFilter> = "invalid".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_stack_type_filter_display() {
        assert_eq!(StackTypeFilter::Cpu.to_string(), "cpu");
        assert_eq!(
            StackTypeFilter::UninterruptibleSleep.to_string(),
            "uninterruptible-sleep"
        );
    }
}
