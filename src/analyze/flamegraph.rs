use anyhow::{bail, Result};
use serde::Serialize;
use std::collections::HashMap;
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

/// Per-trace frame interning table: trace_id → Vec indexed by frame id.
/// Frame ids are dense and zero-based per trace, so a Vec is the natural
/// (and allocation-free to look up) container.
type FrameTable = HashMap<String, Vec<String>>;

impl AnalyzeDb {
    /// Run flamegraph analysis and return structured results.
    ///
    /// On a multi-trace database with no `trace_id` filter, stacks are grouped
    /// per trace (frame ids are scoped per `trace_id`), so the same call chain
    /// in two traces appears as two output rows rather than one merged count.
    /// Filter to a single trace if a merged view is needed.
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

        // Load the frame interning table once. The fold query groups by
        // `frame_ids` (cheap BIGINT[] hashing) and we resolve to names here,
        // which is as fast as the pre-v11 frame_names column but lets DuckDB
        // store stacks ~5x smaller.
        let frame_names = self.load_frame_names(params.trace_id.as_deref())?;

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
            let trace_id: String = row.get(0)?;
            let frames_str: String = row.get(1)?;
            let count: i64 = row.get(2)?;
            let count = count as u64;

            let folded = format_folded_stack(&trace_id, &frames_str, &frame_names);
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

    /// Load the frame interning table into a [`FrameTable`].
    fn load_frame_names(&self, trace_id: Option<&str>) -> Result<FrameTable> {
        let sql = match trace_id {
            Some(t) => {
                let escaped = t.replace('\'', "''");
                format!("SELECT trace_id, id, name FROM frame WHERE trace_id = '{escaped}'")
            }
            None => "SELECT trace_id, id, name FROM frame".to_string(),
        };
        let mut stmt = self.conn.prepare(&sql)?;
        let mut rows = stmt.query([])?;
        let mut map: FrameTable = HashMap::new();
        while let Some(row) = rows.next()? {
            let tid: String = row.get(0)?;
            let id: i64 = row.get(1)?;
            let name: String = row.get(2)?;
            let v = map.entry(tid).or_default();
            let idx = id as usize;
            if v.len() <= idx {
                v.resize(idx + 1, String::new());
            }
            v[idx] = name;
        }
        Ok(map)
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

    conditions.push("s.frame_ids IS NOT NULL".to_string());
    conditions.push("len(s.frame_ids) > 0".to_string());

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

    // duckdb-rs has no FromSql for Vec<i64>, so flatten frame_ids to a
    // chr(31)-separated string and parse it Rust-side. Grouping happens on the
    // raw BIGINT[] so the string conversion only runs once per output row.
    // trace_id is carried through because frame ids are scoped per trace.
    format!(
        "SELECT s.trace_id, \
                array_to_string([x::VARCHAR for x in s.frame_ids], chr(31)) as frames, \
                COUNT(*) as count \
         FROM stack_sample ss \
         JOIN stack s ON ss.stack_id = s.id AND ss.trace_id = s.trace_id\
         {joins}{where_clause} \
         GROUP BY s.trace_id, s.frame_ids{having_clause} \
         ORDER BY count DESC"
    )
}

/// Format a chr(31)-separated string of frame ids into folded stack format.
///
/// Frame ids are stored leaf-to-root in the database, so they are reversed
/// to root-to-leaf order for flamegraph convention (root;child;...;leaf).
fn format_folded_stack(trace_id: &str, frames_str: &str, frames: &FrameTable) -> String {
    if frames_str.is_empty() {
        return String::new();
    }

    let trace_frames = frames.get(trace_id);

    // Reverse from leaf-to-root (storage order) to root-to-leaf (flamegraph convention)
    let formatted: Vec<String> = frames_str
        .split('\x1F')
        .rev()
        .map(|id_str| {
            let name = id_str
                .parse::<usize>()
                .ok()
                .and_then(|id| trace_frames.and_then(|v| v.get(id)))
                .map(String::as_str)
                .unwrap_or(id_str);
            format_frame(name)
        })
        .collect();

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

    fn frame_map(names: &[&str]) -> FrameTable {
        let mut m = HashMap::new();
        m.insert(
            "t".to_string(),
            names.iter().map(|s| s.to_string()).collect(),
        );
        m
    }

    #[test]
    fn test_format_folded_stack_reversal() {
        // frame_ids stored leaf-to-root: "0\x1F1\x1F2"
        // Should output root-to-leaf: "root;mid;leaf"
        let frames = frame_map(&["leaf (app) <0x1>", "mid (app) <0x2>", "root (app) <0x3>"]);
        let result = format_folded_stack("t", "0\x1F1\x1F2", &frames);
        assert_eq!(result, "root [app];mid [app];leaf [app]");
    }

    #[test]
    fn test_format_folded_stack_empty() {
        assert_eq!(format_folded_stack("t", "", &HashMap::new()), "");
    }

    #[test]
    fn test_format_folded_stack_single_frame() {
        let frames = frame_map(&["main (myapp) <0x401234>"]);
        assert_eq!(format_folded_stack("t", "0", &frames), "main [myapp]");
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
