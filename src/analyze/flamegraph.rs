use anyhow::{bail, Result};
use regex::Regex;
use serde::Serialize;
use std::collections::HashMap;
use std::fmt::{self, Write as _};
use std::str::FromStr;
use std::sync::LazyLock;

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
    /// Keep only the `top_n` stacks with the most samples (`None` = every
    /// stack). Applied as a `LIMIT` inside the fold query, so DuckDB keeps a
    /// top-N heap and the caller never sees the long tail.
    pub top_n: Option<usize>,
    /// Cut every stack down to its `max_depth` frames nearest the root
    /// (frames are stored root→leaf) before stacks are merged, so two stacks
    /// that only differ below that depth count as one. `None` = full depth.
    pub max_depth: Option<usize>,
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
            top_n: Some(500),
            max_depth: None,
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
///
/// `total_samples` counts every stack sample in the trace (or the selected
/// trace); `matched_samples` and `unique_stacks` count what passed the
/// filters (stack type, pid/tid, time window, `min_count`, and `max_depth`
/// merging) BEFORE any `top_n` cut, so a truncated result can still say
/// what it was cut from.
#[derive(Debug, Serialize)]
pub struct FlamegraphMetadata {
    pub total_samples: u64,
    pub matched_samples: u64,
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
    ///
    /// This collects every emitted stack twice (`stacks` and `folded`), which
    /// is fine for the bounded `top_n` the MCP tool asks for; a caller that
    /// wants the whole fold of a large trace should stream it through
    /// [`AnalyzeDb::flamegraph_stream`] instead.
    pub fn flamegraph(&self, params: &FlamegraphParams) -> Result<FlamegraphResult> {
        let mut stacks = Vec::new();
        let mut folded = String::new();
        let metadata = self.flamegraph_stream(params, |line, count| {
            if !folded.is_empty() {
                folded.push('\n');
            }
            folded.push_str(line);
            let _ = write!(folded, " {count}");
            stacks.push(StackEntry {
                frames: line.split(';').map(str::to_string).collect(),
                count,
            });
            Ok(())
        })?;

        Ok(FlamegraphResult {
            stacks,
            metadata,
            folded,
        })
    }

    /// Run the fold query and hand each folded stack (`root;...;leaf`) and
    /// its sample count to `emit`, heaviest first, without keeping any of
    /// them: the only per-stack state is the one line being formatted. The
    /// stack set is bounded by `params.top_n` and `params.max_depth` inside
    /// DuckDB (a `LIMIT` over the grouped rows, and the group key itself), so
    /// this path's memory is set by the frame-name table — one entry per
    /// unique frame in the trace — not by the number of unique stacks.
    ///
    /// The returned metadata's `unique_stacks` and `matched_samples` count
    /// what passed the filters (after `max_depth` merging and `min_count`),
    /// not what was emitted, so a truncated output can still say how much it
    /// left out.
    pub fn flamegraph_stream<F>(
        &self,
        params: &FlamegraphParams,
        mut emit: F,
    ) -> Result<FlamegraphMetadata>
    where
        F: FnMut(&str, u64) -> Result<()>,
    {
        if !self.table_exists("stack_sample")? || !self.table_exists("stack")? {
            bail!(
                "Database missing required tables (stack_sample, stack). \
                 Is this a systing trace database?"
            );
        }
        if params.top_n == Some(0) {
            bail!("top_n must be at least 1");
        }
        if params.max_depth == Some(0) {
            bail!("max_depth must be at least 1");
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

        let sql = build_flamegraph_query(&FlamegraphQuery {
            stack_type: params.stack_type,
            pid: params.pid,
            tid: params.tid,
            abs_start,
            abs_end,
            trace_id: params.trace_id.as_deref(),
            min_count: params.min_count,
            top_n: params.top_n,
            max_depth: params.max_depth,
        });

        let mut stmt = self.conn.prepare(&sql)?;
        let mut rows = stmt.query([])?;

        let mut unique_stacks: u64 = 0;
        let mut matched_samples: u64 = 0;
        let mut folded = String::new();

        while let Some(row) = rows.next()? {
            let trace_id: String = row.get(0)?;
            let frames_str: String = row.get(1)?;
            let count: i64 = row.get(2)?;
            // Every row carries the same pre-cut totals; a query with no rows
            // leaves them at zero, which is also the truth.
            let total_stacks: i64 = row.get(3)?;
            let total_samples_matched: i64 = row.get(4)?;
            unique_stacks = total_stacks as u64;
            matched_samples = total_samples_matched as u64;

            folded.clear();
            format_folded_stack_into(&mut folded, &trace_id, &frames_str, &frame_names);
            if folded.is_empty() {
                continue;
            }
            emit(&folded, count as u64)?;
        }

        let duration_secs = (max_ts - min_ts) as f64 / 1e9;

        Ok(FlamegraphMetadata {
            total_samples,
            matched_samples,
            unique_stacks,
            time_range_seconds: (0.0, duration_secs),
            stack_type: params.stack_type.to_string(),
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

/// The resolved inputs of the fold query (absolute timestamps, not offsets).
#[derive(Debug)]
struct FlamegraphQuery<'a> {
    stack_type: StackTypeFilter,
    pid: Option<u32>,
    tid: Option<u32>,
    abs_start: Option<i64>,
    abs_end: Option<i64>,
    trace_id: Option<&'a str>,
    min_count: u64,
    top_n: Option<usize>,
    max_depth: Option<usize>,
}

impl Default for FlamegraphQuery<'_> {
    fn default() -> Self {
        Self {
            stack_type: StackTypeFilter::Cpu,
            pid: None,
            tid: None,
            abs_start: None,
            abs_end: None,
            trace_id: None,
            min_count: 1,
            top_n: None,
            max_depth: None,
        }
    }
}

/// Build the fold query. It returns one row per unique stack, heaviest
/// first, as `(trace_id, frames, count, unique_stacks, matched_samples)`:
///
/// * `frames` is the stack's frame ids joined with chr(31) (duckdb-rs has no
///   FromSql for `Vec<i64>`); the caller resolves names.
/// * `unique_stacks` and `matched_samples` are the same numbers on every
///   row: how many unique stacks passed the filters before `LIMIT`, and how
///   many samples those stacks hold, so a `top_n` caller can still report the
///   size of what it cut.
///
/// Grouping happens on the raw `BIGINT[]` (`max_depth` slices it first, so
/// stacks that only differ deeper than that merge in DuckDB and the top-N
/// over the merged stacks is exact). The id→string conversion runs only on
/// the rows that survive the `LIMIT`, and the sort has a total order
/// (`count DESC, trace_id, frame_ids`) so equal-count stacks come out in a
/// fixed order and `top_n` picks the same set every run.
fn build_flamegraph_query(q: &FlamegraphQuery<'_>) -> String {
    let FlamegraphQuery {
        stack_type,
        pid,
        tid,
        abs_start,
        abs_end,
        trace_id,
        min_count,
        top_n,
        max_depth,
    } = *q;
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

    // frame_ids are stored root→leaf, so the first `max_depth` elements are
    // the root-most frames (list_slice bounds are 1-based and inclusive; a
    // shorter list comes back whole).
    let frame_ids_expr = match max_depth {
        Some(d) => format!("list_slice(s.frame_ids, 1, {d})"),
        None => "s.frame_ids".to_string(),
    };

    let limit_clause = match top_n {
        Some(n) => format!(" LIMIT {n}"),
        None => String::new(),
    };

    // Three pieces: (1) `folded` — the samples grouped by stack, keyed on the
    // raw BIGINT[] because that is what DuckDB hashes and compares cheapest,
    // materialized once so it can be both counted and cut; (2) the ordered
    // LIMIT over it, so DuckDB keeps a top-N heap and the total is counted
    // before the cut (a window `COUNT(*) OVER ()` gives the same number but
    // costs a full extra pass over the folded rows); (3) the id→string
    // conversion (duckdb-rs has no FromSql for Vec<i64>) on the surviving
    // rows only — inside the same SELECT as the LIMIT it would run for every
    // folded row. trace_id is carried through because frame ids are scoped
    // per trace.
    format!(
        "WITH folded AS MATERIALIZED ( \
            SELECT s.trace_id AS trace_id, \
                   {frame_ids_expr} AS frame_ids, \
                   COUNT(*) AS count \
            FROM stack_sample ss \
            JOIN stack s ON ss.stack_id = s.id AND ss.trace_id = s.trace_id\
            {joins}{where_clause} \
            GROUP BY s.trace_id, {frame_ids_expr}{having_clause}) \
         SELECT trace_id, \
                array_to_string([x::VARCHAR for x in frame_ids], chr(31)) AS frames, \
                count, \
                (SELECT COUNT(*) FROM folded) AS unique_stacks, \
                (SELECT COALESCE(SUM(count), 0)::BIGINT FROM folded) AS matched_samples \
         FROM (SELECT trace_id, frame_ids, count \
               FROM folded \
               ORDER BY count DESC, trace_id, frame_ids{limit_clause}) \
         ORDER BY count DESC, trace_id, frame_ids"
    )
}

/// Format a chr(31)-separated string of frame ids into folded stack format,
/// appended to a caller-owned buffer so a streaming caller formats every
/// stack through the same allocation.
///
/// Frame ids are stored root-to-leaf in the database (see `Stack` in
/// stack_recorder.rs), which is already the flamegraph folded convention
/// (root;child;...;leaf) — emit in storage order.
fn format_folded_stack_into(
    out: &mut String,
    trace_id: &str,
    frames_str: &str,
    frames: &FrameTable,
) {
    if frames_str.is_empty() {
        return;
    }

    let trace_frames = frames.get(trace_id);

    for (i, id_str) in frames_str.split('\x1F').enumerate() {
        if i > 0 {
            out.push(';');
        }
        let name = id_str
            .parse::<usize>()
            .ok()
            .and_then(|id| trace_frames.and_then(|v| v.get(id)))
            .map(String::as_str)
            .unwrap_or(id_str);
        format_frame_into(out, name);
    }
}

/// The recorder writes frame names in one of three shapes, in order of
/// completeness:
///
/// ```text
/// func (mapping [file:line]) <0xpc>
/// func (mapping) <0xpc>
/// 0xpc
/// ```
///
/// Function names can contain unbalanced angle brackets and parens (Rust
/// generics, C++ templates), so the parse anchors on the trailing pc and
/// mapping rather than reading left to right. `mapping` is a real object
/// name (`vmlinux`, `myapp`) or one of the recorder's bracketed pseudo-mapping
/// labels (`[kernel]`, `[guest]`, `[exited]`, `[gvisor:*]`, `[jit:*]`,
/// `[anon]`, `[buildid:…]`); the label's own brackets are the only ones it
/// ever gets.
static MAPPING_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r" \(([^()]+?)(?: \[([^\[\]:]+)(?::(\d+))?\])?\)$").unwrap());

/// One recorder frame split into the parts the folded output is built from.
/// Fields borrow from the frame text; a missing part is empty (or `0`).
#[derive(Debug, Default, PartialEq, Eq)]
struct Frame<'a> {
    func: &'a str,
    file: &'a str,
    line: i32,
    mapping: &'a str,
    pc: u64,
}

fn parse_frame(raw: &str) -> Frame<'_> {
    if let Some(pc) = raw
        .strip_prefix("0x")
        .and_then(|h| u64::from_str_radix(h, 16).ok())
    {
        return Frame {
            pc,
            ..Frame::default()
        };
    }
    let (head, pc) = raw
        .strip_suffix('>')
        .and_then(|s| s.rsplit_once(" <0x"))
        .and_then(|(head, hex)| Some((head, u64::from_str_radix(hex, 16).ok()?)))
        .unwrap_or((raw, 0));
    let Some(c) = MAPPING_RE.captures(head) else {
        return Frame {
            func: head,
            pc,
            ..Frame::default()
        };
    };
    // The pattern is anchored at the end of `head`, so everything before the
    // match is the function name.
    Frame {
        func: &head[..head.len() - c[0].len()],
        file: c.get(2).map_or("", |m| m.as_str()),
        line: c.get(3).and_then(|m| m.as_str().parse().ok()).unwrap_or(0),
        mapping: c.get(1).map_or("", |m| m.as_str()),
        pc,
    }
}

/// Render one recorder frame for folded output as `file:function:line`,
/// appended to a caller-owned buffer.
///
/// This is the same grammar systing's continuous-profiling frames use, so a
/// frame reads identically whichever mode produced it: `file` falls back to
/// the mapping when the source location is unknown, `function` falls back to
/// `0x{pc}` when unsymbolized, and `:line` is omitted when it is zero.
///
/// ```text
/// tcp_sendmsg (vmlinux [net/ipv4/tcp.c:1234]) <0xffffffff8ec7559e>  →  net/ipv4/tcp.c:tcp_sendmsg:1234
/// main (myapp) <0x401234>                                            →  myapp:main
/// do_syscall_64 ([kernel]) <0xffffffff96f461b1>                      →  [kernel]:do_syscall_64
/// unknown ([guest])                                                  →  [guest]:unknown
/// 0x5dbfa1                                                           →  :0x5dbfa1
/// ```
fn format_frame_into(out: &mut String, frame: &str) {
    let f = parse_frame(frame);
    let file = if f.file.is_empty() { f.mapping } else { f.file };
    out.push_str(file);
    out.push(':');
    if f.func.is_empty() {
        let _ = write!(out, "{:#x}", f.pc);
    } else {
        out.push_str(f.func);
    }
    if f.line > 0 {
        let _ = write!(out, ":{}", f.line);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn format_frame(frame: &str) -> String {
        let mut out = String::new();
        format_frame_into(&mut out, frame);
        out
    }

    fn format_folded_stack(trace_id: &str, frames_str: &str, frames: &FrameTable) -> String {
        let mut out = String::new();
        format_folded_stack_into(&mut out, trace_id, frames_str, frames);
        out
    }

    // --- parse_frame: the recorder's three frame shapes ---

    #[test]
    fn parse_frame_full() {
        let f = parse_frame(
            "<rayon_core::registry::WorkerThread>::wait_until_cold (myserver [registry.rs:806]) <0x57ee0e3679c4>",
        );
        assert_eq!(
            f,
            Frame {
                func: "<rayon_core::registry::WorkerThread>::wait_until_cold",
                file: "registry.rs",
                line: 806,
                mapping: "myserver",
                pc: 0x57ee0e3679c4,
            }
        );
    }

    #[test]
    fn parse_frame_no_source() {
        let f = parse_frame("syscall (libc.so.6) <0x7b9c5b3c390d>");
        assert_eq!(
            f,
            Frame {
                func: "syscall",
                file: "",
                line: 0,
                mapping: "libc.so.6",
                pc: 0x7b9c5b3c390d,
            }
        );
    }

    #[test]
    fn parse_frame_kernel_label() {
        let f = parse_frame("do_syscall_64 ([kernel]) <0xffffffff96f461b1>");
        assert_eq!(f.func, "do_syscall_64");
        assert_eq!(f.mapping, "[kernel]");
        assert_eq!(f.pc, 0xffffffff96f461b1);
    }

    #[test]
    fn parse_frame_bare_hex() {
        assert_eq!(
            parse_frame("0x7b9c5b339ac3"),
            Frame {
                pc: 0x7b9c5b339ac3,
                ..Frame::default()
            }
        );
    }

    #[test]
    fn parse_frame_file_no_line() {
        let f = parse_frame(
            "<rayon_core::registry::WorkerThread>::wait_until_cold (myserver [registry.rs]) <0x57ee0e367975>",
        );
        assert_eq!(
            f.func,
            "<rayon_core::registry::WorkerThread>::wait_until_cold"
        );
        assert_eq!(f.mapping, "myserver");
        assert_eq!(f.file, "registry.rs");
        assert_eq!(f.line, 0);
    }

    #[test]
    fn parse_frame_go_autogenerated_source() {
        let f =
            parse_frame("net.(*UnixConn).Read (containerd [<autogenerated>:1]) <0x56ef7dec7645>");
        assert_eq!(f.func, "net.(*UnixConn).Read");
        assert_eq!(f.mapping, "containerd");
        assert_eq!(f.file, "<autogenerated>");
        assert_eq!(f.line, 1);
    }

    #[test]
    fn parse_frame_label_without_address() {
        // The recorder's synthetic guest frame carries no `<0xpc>` suffix.
        let f = parse_frame("unknown ([guest])");
        assert_eq!(f.func, "unknown");
        assert_eq!(f.mapping, "[guest]");
        assert_eq!(f.pc, 0);
    }

    #[test]
    fn parse_frame_unparseable_is_func() {
        let f = parse_frame("something weird with no structure");
        assert_eq!(f.func, "something weird with no structure");
        assert_eq!(f.mapping, "");
        assert_eq!(f.pc, 0);
    }

    // --- format_frame: `file:function:line`, one grammar for every mode ---

    #[test]
    fn test_format_frame_symbolized_with_source() {
        assert_eq!(
            format_frame("tcp_sendmsg (vmlinux [net/ipv4/tcp.c:1234]) <0xffffffff8ec7559e>"),
            "net/ipv4/tcp.c:tcp_sendmsg:1234"
        );
    }

    #[test]
    fn test_format_frame_symbolized_file_without_line() {
        assert_eq!(
            format_frame("wait_until_cold (myserver [registry.rs]) <0x57ee0e367975>"),
            "registry.rs:wait_until_cold"
        );
    }

    #[test]
    fn test_format_frame_with_module_only() {
        assert_eq!(format_frame("main (myapp) <0x401234>"), "myapp:main");
        assert_eq!(
            format_frame("syscall (libc.so.6) <0x7b9c5b3c390d>"),
            "libc.so.6:syscall"
        );
    }

    #[test]
    fn test_format_frame_kernel_symbolized() {
        assert_eq!(
            format_frame("do_syscall_64 ([kernel]) <0xffffffff96f461b1>"),
            "[kernel]:do_syscall_64"
        );
    }

    #[test]
    fn test_format_frame_kernel_unknown() {
        // The label's own brackets are the only ones it gets: never `[[kernel]]`.
        assert_eq!(
            format_frame("unknown ([kernel]) <0xffffffff8e000000>"),
            "[kernel]:unknown"
        );
    }

    #[test]
    fn test_format_frame_pseudo_mapping_labels() {
        // Every bracketed label the recorder can put in the mapping slot.
        for label in [
            "[guest]",
            "[exited]",
            "[gvisor:runtime]",
            "[gvisor:guest]",
            "[jit:python]",
            "[anon]",
            "[anon:exec]",
            "[buildid:5a5a5a5a]",
        ] {
            assert_eq!(
                format_frame(&format!("unknown ({label}) <0x7f0000000100>")),
                format!("{label}:unknown"),
                "label {label}"
            );
        }
        assert_eq!(format_frame("unknown ([guest])"), "[guest]:unknown");
    }

    #[test]
    fn test_format_frame_bare_hex() {
        // No mapping and no name: an empty file slot, then the address.
        assert_eq!(format_frame("0x5dbfa1"), ":0x5dbfa1");
    }

    #[test]
    fn test_format_frame_unparseable() {
        assert_eq!(
            format_frame("something weird with no structure"),
            ":something weird with no structure"
        );
        assert_eq!(format_frame(""), ":0x0");
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
    fn test_format_folded_stack_storage_order() {
        // frame_ids stored root-to-leaf: "0\x1F1\x1F2" emits in storage
        // order, which is already the folded convention root;mid;leaf.
        let frames = frame_map(&["root (app) <0x1>", "mid (app) <0x2>", "leaf (app) <0x3>"]);
        let result = format_folded_stack("t", "0\x1F1\x1F2", &frames);
        assert_eq!(result, "app:root;app:mid;app:leaf");
    }

    #[test]
    fn test_format_folded_stack_empty() {
        assert_eq!(format_folded_stack("t", "", &HashMap::new()), "");
    }

    #[test]
    fn test_format_folded_stack_single_frame() {
        let frames = frame_map(&["main (myapp) <0x401234>"]);
        assert_eq!(format_folded_stack("t", "0", &frames), "myapp:main");
    }

    #[test]
    fn test_format_folded_stack_mixed_frames() {
        let frames = frame_map(&[
            "entry_SYSCALL_64_after_hwframe ([kernel]) <0xffffffff8e000000>",
            "tcp_sendmsg (vmlinux [net/ipv4/tcp.c:1234]) <0xffffffff8ec7559e>",
            "main (myapp) <0x401234>",
            "unknown ([guest])",
            "0x5dbfa1",
        ]);
        assert_eq!(
            format_folded_stack("t", "0\x1F1\x1F2\x1F3\x1F4", &frames),
            "[kernel]:entry_SYSCALL_64_after_hwframe;net/ipv4/tcp.c:tcp_sendmsg:1234;myapp:main;[guest]:unknown;:0x5dbfa1"
        );
    }

    #[test]
    fn test_format_folded_stack_unknown_frame_id() {
        // A frame id with no table entry falls back to the id text itself.
        let frames = frame_map(&["main (myapp) <0x401234>"]);
        assert_eq!(format_folded_stack("t", "0\x1F7", &frames), "myapp:main;:7");
    }

    fn query(stack_type: StackTypeFilter) -> FlamegraphQuery<'static> {
        FlamegraphQuery {
            stack_type,
            ..FlamegraphQuery::default()
        }
    }

    #[test]
    fn test_build_flamegraph_query_cpu() {
        let sql = build_flamegraph_query(&query(StackTypeFilter::Cpu));
        assert!(sql.contains("stack_event_type = 1"));
        assert!(!sql.contains("sched_slice"));
    }

    #[test]
    fn test_build_flamegraph_query_interruptible_sleep() {
        let sql = build_flamegraph_query(&query(StackTypeFilter::InterruptibleSleep));
        assert!(sql.contains("stack_event_type = 2"));
        assert!(!sql.contains("sched_slice"));
        assert!(!sql.contains("end_state"));
    }

    #[test]
    fn test_build_flamegraph_query_uninterruptible_sleep() {
        let sql = build_flamegraph_query(&query(StackTypeFilter::UninterruptibleSleep));
        assert!(sql.contains("stack_event_type = 0"));
        assert!(!sql.contains("sched_slice"));
        assert!(!sql.contains("end_state"));
    }

    #[test]
    fn test_build_flamegraph_query_all_sleep() {
        let sql = build_flamegraph_query(&query(StackTypeFilter::AllSleep));
        assert!(sql.contains("stack_event_type IN (0, 2)"));
        assert!(!sql.contains("sched_slice"));
        assert!(!sql.contains("end_state"));
    }

    #[test]
    fn test_build_flamegraph_query_with_pid() {
        let sql = build_flamegraph_query(&FlamegraphQuery {
            pid: Some(1234),
            ..query(StackTypeFilter::Cpu)
        });
        assert!(sql.contains("JOIN thread t"));
        assert!(sql.contains("JOIN process p"));
        assert!(sql.contains("p.pid = 1234"));
    }

    #[test]
    fn test_build_flamegraph_query_with_min_count() {
        let sql = build_flamegraph_query(&FlamegraphQuery {
            min_count: 10,
            ..query(StackTypeFilter::All)
        });
        assert!(sql.contains("HAVING COUNT(*) >= 10"));
    }

    #[test]
    fn test_build_flamegraph_query_no_having_for_min_count_1() {
        let sql = build_flamegraph_query(&query(StackTypeFilter::All));
        assert!(!sql.contains("HAVING"));
    }

    #[test]
    fn test_build_flamegraph_query_unbounded_has_no_limit_and_full_depth() {
        let sql = build_flamegraph_query(&query(StackTypeFilter::Cpu));
        assert!(!sql.contains("LIMIT"));
        assert!(!sql.contains("list_slice"));
        assert!(sql.contains("GROUP BY s.trace_id, s.frame_ids"));
        // The total is counted over the materialized fold, before any cut.
        assert!(sql.contains("WITH folded AS MATERIALIZED"));
        assert!(sql.contains("(SELECT COUNT(*) FROM folded) AS unique_stacks"));
        assert!(
            sql.contains("(SELECT COALESCE(SUM(count), 0)::BIGINT FROM folded) AS matched_samples")
        );
        // A total order, so equal counts come out the same way every run.
        assert!(sql.contains("ORDER BY count DESC, trace_id, frame_ids"));
    }

    #[test]
    fn test_build_flamegraph_query_top_n_is_a_sql_limit() {
        let sql = build_flamegraph_query(&FlamegraphQuery {
            top_n: Some(4096),
            ..query(StackTypeFilter::Cpu)
        });
        // The LIMIT closes the inner ordered subquery; the id→string
        // conversion is in the SELECT list outside it, so it only runs on
        // the rows that survive the cut.
        let inner_at = sql
            .find("FROM (SELECT trace_id, frame_ids, count FROM folded")
            .unwrap();
        let limit_at = sql.find(" LIMIT 4096)").unwrap();
        let strings_at = sql.find("array_to_string").unwrap();
        assert!(strings_at < inner_at);
        assert!(inner_at < limit_at);
        assert_eq!(sql.matches("LIMIT").count(), 1);
    }

    #[test]
    fn test_build_flamegraph_query_max_depth_slices_the_group_key() {
        let sql = build_flamegraph_query(&FlamegraphQuery {
            max_depth: Some(64),
            ..query(StackTypeFilter::Cpu)
        });
        assert!(sql.contains("list_slice(s.frame_ids, 1, 64) AS frame_ids"));
        assert!(sql.contains("GROUP BY s.trace_id, list_slice(s.frame_ids, 1, 64)"));
    }

    // --- the fold itself, on an in-memory trace DB ---

    /// Four stacks over four frames, sampled 5/3/3/1 times:
    ///   stack 0 = main;work;spin   ×5
    ///   stack 1 = main;work;sleep  ×3
    ///   stack 2 = main;sleep       ×3
    ///   stack 3 = main;work        ×1
    fn fold_db() -> AnalyzeDb {
        let conn = duckdb::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE frame (trace_id VARCHAR, id BIGINT, name VARCHAR); \
             CREATE TABLE stack (trace_id VARCHAR, id BIGINT, frame_ids BIGINT[], depth INTEGER, leaf_name VARCHAR); \
             CREATE TABLE stack_sample (trace_id VARCHAR, ts BIGINT, utid BIGINT, cpu INTEGER, stack_id BIGINT, stack_event_type TINYINT); \
             INSERT INTO frame VALUES \
               ('t', 0, 'main (app) <0x1>'), ('t', 1, 'work (app) <0x2>'), \
               ('t', 2, 'spin (app) <0x3>'), ('t', 3, 'sleep (app) <0x4>'); \
             INSERT INTO stack VALUES \
               ('t', 0, [0, 1, 2], 3, 'spin'), ('t', 1, [0, 1, 3], 3, 'sleep'), \
               ('t', 2, [0, 3], 2, 'sleep'), ('t', 3, [0, 1], 2, 'work'); \
             INSERT INTO stack_sample \
               SELECT 't', 1000 + i * 1000, 1, 0, \
                      CASE WHEN i < 5 THEN 0 WHEN i < 8 THEN 1 WHEN i < 11 THEN 2 ELSE 3 END, 1 \
               FROM range(12) r(i);",
        )
        .unwrap();
        AnalyzeDb {
            conn,
            path: std::path::PathBuf::new(),
            mem_limit_mib: None,
        }
    }

    fn streamed(
        db: &AnalyzeDb,
        params: &FlamegraphParams,
    ) -> (Vec<(String, u64)>, FlamegraphMetadata) {
        let mut lines = Vec::new();
        let meta = db
            .flamegraph_stream(params, |folded, count| {
                lines.push((folded.to_string(), count));
                Ok(())
            })
            .unwrap();
        (lines, meta)
    }

    fn all() -> FlamegraphParams {
        FlamegraphParams {
            top_n: None,
            ..FlamegraphParams::default()
        }
    }

    #[test]
    fn fold_orders_heaviest_first_with_a_fixed_tie_order() {
        let db = fold_db();
        let (lines, meta) = streamed(&db, &all());
        assert_eq!(
            lines,
            vec![
                ("app:main;app:work;app:spin".to_string(), 5),
                // Equal counts tie-break on the frame-id list: [0,1,3] < [0,3].
                ("app:main;app:work;app:sleep".to_string(), 3),
                ("app:main;app:sleep".to_string(), 3),
                ("app:main;app:work".to_string(), 1),
            ]
        );
        assert_eq!(meta.total_samples, 12);
        assert_eq!(meta.matched_samples, 12);
        assert_eq!(meta.unique_stacks, 4);
        assert_eq!(meta.stack_type, "cpu");
    }

    #[test]
    fn fold_top_n_cuts_the_output_but_not_the_total() {
        let db = fold_db();
        let (lines, meta) = streamed(
            &db,
            &FlamegraphParams {
                top_n: Some(2),
                ..all()
            },
        );
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], ("app:main;app:work;app:spin".to_string(), 5));
        assert_eq!(lines[1], ("app:main;app:work;app:sleep".to_string(), 3));
        assert_eq!(
            meta.unique_stacks, 4,
            "the total is counted before the LIMIT"
        );
        assert_eq!(
            meta.matched_samples, 12,
            "so is the matched-sample total, not the emitted 5 + 3"
        );
        assert_eq!(meta.total_samples, 12);
    }

    #[test]
    fn fold_max_depth_merges_in_the_database() {
        let db = fold_db();
        let (lines, meta) = streamed(
            &db,
            &FlamegraphParams {
                max_depth: Some(2),
                ..all()
            },
        );
        // Root-most two frames: stacks 0, 1 and 3 all become main;work.
        assert_eq!(
            lines,
            vec![
                ("app:main;app:work".to_string(), 9),
                ("app:main;app:sleep".to_string(), 3),
            ]
        );
        assert_eq!(
            meta.unique_stacks, 2,
            "unique stacks are counted after merging"
        );
        assert_eq!(meta.matched_samples, 12, "merging keeps every sample");
        assert_eq!(meta.total_samples, 12);
    }

    #[test]
    fn fold_top_n_over_merged_stacks_is_exact() {
        let db = fold_db();
        let (lines, meta) = streamed(
            &db,
            &FlamegraphParams {
                max_depth: Some(2),
                top_n: Some(1),
                ..all()
            },
        );
        // Without merging first, the single heaviest stack would be
        // main;work;spin at 5; merged, main;work carries 9.
        assert_eq!(lines, vec![("app:main;app:work".to_string(), 9)]);
        assert_eq!(meta.unique_stacks, 2);
    }

    #[test]
    fn fold_min_count_is_applied_before_the_total() {
        let db = fold_db();
        let (lines, meta) = streamed(
            &db,
            &FlamegraphParams {
                min_count: 3,
                ..all()
            },
        );
        assert_eq!(lines.len(), 3);
        assert!(lines.iter().all(|(_, c)| *c >= 3));
        assert_eq!(meta.unique_stacks, 3);
        assert_eq!(
            meta.matched_samples, 11,
            "the one-sample stack is out of the matched total too"
        );
        assert_eq!(meta.total_samples, 12);
    }

    #[test]
    fn fold_with_nothing_in_the_window_reports_zero() {
        let db = fold_db();
        let (lines, meta) = streamed(
            &db,
            &FlamegraphParams {
                start_time: Some(100.0),
                ..all()
            },
        );
        assert!(lines.is_empty());
        assert_eq!(meta.unique_stacks, 0);
        assert_eq!(meta.matched_samples, 0);
        assert_eq!(meta.total_samples, 12, "the trace total is not windowed");
    }

    #[test]
    fn fold_structured_result_matches_the_stream() {
        let db = fold_db();
        let params = FlamegraphParams {
            top_n: Some(3),
            ..all()
        };
        let (lines, _) = streamed(&db, &params);
        let result = db.flamegraph(&params).unwrap();
        assert_eq!(result.stacks.len(), 3);
        assert_eq!(result.metadata.unique_stacks, 4);
        let expected_folded: Vec<String> = lines.iter().map(|(f, c)| format!("{f} {c}")).collect();
        assert_eq!(result.folded, expected_folded.join("\n"));
        assert_eq!(
            result.stacks[0].frames,
            vec!["app:main", "app:work", "app:spin"]
        );
        assert_eq!(result.stacks[0].count, 5);
    }

    #[test]
    fn fold_rejects_zero_bounds() {
        let db = fold_db();
        assert!(db
            .flamegraph_stream(
                &FlamegraphParams {
                    top_n: Some(0),
                    ..all()
                },
                |_, _| Ok(())
            )
            .is_err());
        assert!(db
            .flamegraph_stream(
                &FlamegraphParams {
                    max_depth: Some(0),
                    ..all()
                },
                |_, _| Ok(())
            )
            .is_err());
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
