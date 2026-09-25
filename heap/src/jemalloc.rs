//! jemalloc heap profiles (`prof.dump`, `heap_v2`).
//!
//! The file is text:
//!
//! ```text
//! heap_v2/524288                       <- mean bytes between samples
//!   t*: 28106: 56637512 [0: 0]         <- totals: live objects: bytes [alloc objects: bytes]
//!   t0: ...                            <- per jemalloc thread index (skipped)
//! @ 0x7f4bc7446b86 0x7f4bc7447acc ...  <- one stack, leaf first
//!   t*: 13: 6688 [0: 0]
//!   t0: 13: 6688 [0: 0]
//! MAPPED_LIBRARIES:
//! <the process's /proc/self/maps>
//! ```
//!
//! The file name is `<prefix>.<pid>.<seq>.<kind>[<kind seq>].heap`, with kind
//! `i` (every `lg_prof_interval` bytes allocated), `m` (`mallctl prof.dump`),
//! `u` (`prof_gdump`, a new high-water mark) or `f` (`prof_final`, at exit).

use std::path::Path;
use std::sync::LazyLock;

use anyhow::{bail, Context, Result};
use regex::Regex;

use crate::maps::Maps;
use crate::{Format, Sample, Snapshot};

// A thread line in the header ends with the thread's name when it has one
// (mallctl "thread.prof.name", or prof_sys_thread_name), blanks allowed.
static COUNTS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^t(\*|\d+):\s+(\d+):\s+(\d+)\s+\[\s*(\d+):\s+(\d+)\s*\](?:\s+.*)?$").unwrap()
});

static FILE_NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.(\d+)\.(\d+)\.([imuf])\d*\.heap$").unwrap());

/// What a dump's file name says about it.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct FileName {
    pub pid: Option<i32>,
    pub seq: Option<u64>,
    pub trigger: Option<&'static str>,
}

pub fn parse_file_name(path: &Path) -> FileName {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    let Some(c) = FILE_NAME_RE.captures(name) else {
        return FileName::default();
    };
    FileName {
        pid: c[1].parse().ok(),
        seq: c[2].parse().ok(),
        trigger: c[3].chars().next().and_then(trigger_for_kind),
    }
}

/// The dump trigger a file name's kind letter stands for.
pub fn trigger_for_kind(kind: char) -> Option<&'static str> {
    match kind {
        'i' => Some("interval"),
        'm' => Some("manual"),
        'u' => Some("gdump"),
        'f' => Some("final"),
        _ => None,
    }
}

/// The largest dump read. A dump is one short line per allocation stack plus
/// the process's maps, so real ones are megabytes; the cap only stops a file
/// named like a dump from filling memory.
pub const MAX_DUMP_BYTES: u64 = 1 << 30;

/// Read one dump file.
pub fn read(path: &Path) -> Result<Snapshot> {
    use std::io::Read;
    let file = std::fs::File::open(path).with_context(|| format!("reading {}", path.display()))?;
    let mut text = String::new();
    file.take(MAX_DUMP_BYTES + 1)
        .read_to_string(&mut text)
        .with_context(|| format!("reading {}", path.display()))?;
    if text.len() as u64 > MAX_DUMP_BYTES {
        bail!("{}: larger than {MAX_DUMP_BYTES} bytes", path.display());
    }
    let mut snapshot = parse(&text).with_context(|| format!("parsing {}", path.display()))?;
    let name = parse_file_name(path);
    snapshot.source_path = path.to_path_buf();
    snapshot.pid = name.pid;
    snapshot.seq = name.seq;
    snapshot.trigger = name.trigger;
    snapshot.dumped_at_unix_ns = std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|d| i64::try_from(d.as_nanos()).ok());
    Ok(snapshot)
}

/// Parse a dump's contents. The file-name fields are left empty.
pub fn parse(text: &str) -> Result<Snapshot> {
    let mut lines = text.lines();
    let header = lines.next().unwrap_or_default();
    let Some(period) = header.trim().strip_prefix("heap_v2/") else {
        bail!(
            "not a jemalloc heap_v2 profile (first line {header:?}); \
             gperftools/tcmalloc .heap files are not supported yet"
        );
    };
    let sample_period: u64 = period
        .parse()
        .with_context(|| format!("bad sample period in {header:?}"))?;

    let mut totals: Option<[u64; 4]> = None;
    let mut samples: Vec<Sample> = Vec::new();
    // The stack whose t* line is still to come.
    let mut pending: Option<Vec<u64>> = None;
    let mut maps = Maps::default();

    for (i, raw) in lines.by_ref().enumerate() {
        let line = raw.trim();
        let lineno = i + 2;
        if line.is_empty() {
            continue;
        }
        if line == "MAPPED_LIBRARIES:" {
            break;
        }
        if let Some(rest) = line.strip_prefix('@') {
            if pending.is_some() {
                bail!("line {lineno}: stack with no t* line before it");
            }
            let addrs = rest
                .split_whitespace()
                .map(parse_addr)
                .collect::<Result<Vec<_>>>()
                .with_context(|| format!("line {lineno}"))?;
            pending = Some(addrs);
            continue;
        }
        let Some(c) = COUNTS_RE.captures(line) else {
            bail!("line {lineno}: unexpected {line:?}");
        };
        if &c[1] != "*" {
            // Per jemalloc thread index: an allocator-internal number, not a
            // tid, so nothing to join it to.
            continue;
        }
        let n = |k: usize| {
            c[k].parse::<u64>()
                .with_context(|| format!("line {lineno}"))
        };
        let counts = [n(2)?, n(3)?, n(4)?, n(5)?];
        match pending.take() {
            Some(addrs) => samples.push(Sample {
                addrs,
                live_objects: counts[0],
                live_bytes: counts[1],
                alloc_objects: counts[2],
                alloc_bytes: counts[3],
            }),
            None if totals.is_none() && samples.is_empty() => totals = Some(counts),
            None => bail!("line {lineno}: t* line with no stack"),
        }
    }
    if pending.is_some() {
        bail!("the last stack has no t* line (truncated file?)");
    }
    let rest: Vec<&str> = lines.collect();
    if !rest.is_empty() {
        maps = Maps::parse(&rest.join("\n"));
    }
    // The header's totals are read to keep the grammar, not kept: they are
    // the sum of every stack's pair, and scaling a sum under-counts small
    // objects (see Sample::estimates).
    let _ = totals;

    Ok(Snapshot {
        format: Format::Jemalloc,
        source_path: Default::default(),
        pid: None,
        seq: None,
        trigger: None,
        dumped_at_unix_ns: None,
        owner_uid: None,
        sample_period,
        samples,
        maps,
        perf_map: None,
        py_code: None,
    })
}

fn parse_addr(s: &str) -> Result<u64> {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(hex, 16).with_context(|| format!("bad address {s:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DUMP: &str = "\
heap_v2/4096
  t*: 1270: 5112044 [0: 0]
  t0: 1270: 5112044 [0: 0]
@ 0x7f4bc7446b86 0x7f4bc7447acc 0x56326ffdd225
  t*: 1: 4032 [0: 0]
  t0: 1: 4032 [0: 0]
@ 0x7f4bc7446b86 0x56326ffdd1e1
  t*: 1261: 5028235 [7: 900]
  t0: 1261: 5028235 [7: 900]

MAPPED_LIBRARIES:
56326ffdc000-56326ffdd000 r--p 00000000 00:2a8 156407                    /tmp/je/t
56326ffdd000-56326ffde000 r-xp 00001000 00:2a8 156407                    /tmp/je/t
";

    #[test]
    fn parses_header_stacks_and_maps() {
        let s = parse(DUMP).unwrap();
        assert_eq!(s.sample_period, 4096);
        assert_eq!(s.samples.len(), 2);
        assert_eq!(
            s.samples[0].addrs,
            vec![0x7f4bc7446b86, 0x7f4bc7447acc, 0x56326ffdd225]
        );
        assert_eq!(
            s.samples[1],
            Sample {
                addrs: vec![0x7f4bc7446b86, 0x56326ffdd1e1],
                live_objects: 1261,
                live_bytes: 5028235,
                alloc_objects: 7,
                alloc_bytes: 900,
            }
        );
        assert_eq!(s.maps.mappings().len(), 2);
        assert_eq!(s.maps.lookup(0x56326ffdd225).unwrap().path, "/tmp/je/t");
    }

    #[test]
    fn named_threads_do_not_break_the_header() {
        let dump = "heap_v2/4096\n  t*: 2: 200 [0: 0]\n  t0: 1: 100 [0: 0] worker-1\n  \
                    t3: 1: 100 [0: 0] io pool 2\n@ 0x1\n  t*: 2: 200 [0: 0]\n  t0: 1: 100 [0: 0]\n";
        let s = parse(dump).unwrap();
        assert_eq!(s.samples.len(), 1);
    }

    #[test]
    fn a_gperftools_heap_file_is_refused_by_its_header() {
        let err = parse("heap profile:    1:  4096 [     1:  4096] @ heapprofile\n").unwrap_err();
        assert!(err.to_string().contains("not a jemalloc heap_v2"), "{err}");
    }

    #[test]
    fn a_truncated_stack_is_an_error() {
        assert!(parse("heap_v2/4096\n  t*: 1: 1 [0: 0]\n@ 0x1 0x2\n").is_err());
    }

    #[test]
    fn file_names_carry_pid_seq_and_trigger() {
        let f = parse_file_name(Path::new("/out/app.v1.jeprof.4242.17.i16.heap"));
        assert_eq!(
            f,
            FileName {
                pid: Some(4242),
                seq: Some(17),
                trigger: Some("interval")
            }
        );
        let f = parse_file_name(Path::new("jeprof.5.0.f.heap"));
        assert_eq!((f.pid, f.seq, f.trigger), (Some(5), Some(0), Some("final")));
        assert_eq!(
            parse_file_name(Path::new("renamed.heap")),
            FileName::default()
        );
    }
}
