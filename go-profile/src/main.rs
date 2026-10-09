//! systing-go-profile: a Go program's heap, goroutine, block and mutex
//! profiles, read out of its memory with no pprof port (`snoop`), or read
//! from a pprof file the program wrote (`pprof`), printed the same way so the
//! two can be compared. `flight` copies the program's flight recorder out of
//! its memory as an execution trace.
//!
//! The reading is `systing::golang`'s; this is the command around it. Output
//! is JSON lines: a header object, then one object per stack with its values
//! and its frames, leaf first, by function name (`stack`: the functions that
//! have frames of their own; `inlined_stack`, pprof files only: with the
//! calls inlined into them). `snoop -o FILE` writes a pprof file instead.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::{json, Value};
use systing::golang::{pprof, GoProcess, ReadStats};

#[derive(Parser)]
#[command(name = "systing-go-profile")]
#[command(about = "Read a Go program's own profiles out of its memory (experimental)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Read a profile out of a running Go program's memory.
    Snoop {
        #[arg(long)]
        pid: u32,
        #[arg(long, value_enum)]
        profile: Kind,
        /// Also print each goroutine (goroutine profile only).
        #[arg(long)]
        each: bool,
        /// Write the profile to this file as a pprof profile (gzipped
        /// `profile.proto`, as `/debug/pprof/<profile>` serves it), instead
        /// of printing it; `go tool pprof` reads it.
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Copy a running Go program's flight recorder out of its memory into an
    /// execution trace file (`go tool trace` reads it); prints what was
    /// copied as JSON.
    Flight {
        #[arg(long)]
        pid: u32,
        #[arg(long)]
        out: PathBuf,
    },
    /// Print a pprof file the same way.
    Pprof { file: PathBuf },
}

#[derive(Clone, Copy, ValueEnum, PartialEq, Eq)]
enum Kind {
    Heap,
    Goroutine,
    Block,
    Mutex,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Snoop {
            pid,
            profile,
            each,
            out,
        } => snoop(pid, profile, each, out.as_deref()),
        Command::Flight { pid, out } => flight(pid, &out),
        Command::Pprof { file } => print_pprof(&file),
    }
}

/// The program, and how long opening it took.
fn open(pid: u32) -> Result<(GoProcess, u128)> {
    let opened = Instant::now();
    let go = GoProcess::open(pid, Path::new(&format!("/proc/{pid}")))?;
    Ok((go, opened.elapsed().as_micros()))
}

fn snoop(pid: u32, kind: Kind, each: bool, out: Option<&Path>) -> Result<()> {
    let (go, open_us) = open(pid)?;
    let mut stats = ReadStats::default();
    let mut header = json!({
        "source": "snoop",
        "pid": pid,
        "go_version": go.version,
        "exe": go.exe,
        "globals_found_by": go.found_by.name(),
        "open_us": open_us,
    });
    let module = Path::new(&go.exe)
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_default();
    let frames = |pcs: &[u64]| -> Vec<pprof::Frame> {
        pcs.iter()
            .map(|&pc| pprof::Frame {
                function: go.function(pc, true).unwrap_or("?").to_string(),
                file: String::new(),
                line: 0,
                address: pc,
                module: module.clone(),
                inlined: false,
            })
            .collect()
    };
    let sample = |values: Vec<i64>, frames: Vec<pprof::Frame>, labels| pprof::ProfileSample {
        values,
        frames,
        labels,
        num_labels: Vec::new(),
    };
    let types = |t: &[(&str, &str)]| -> Vec<(String, String)> {
        t.iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect()
    };
    let mut extra: Vec<Value> = Vec::new();
    let (profile, default_type) = match kind {
        Kind::Heap => {
            let heap = go.heap(&mut stats)?;
            header["profile"] = json!("heap");
            header["period"] = json!(heap.rate);
            let samples = heap
                .records
                .iter()
                .map(|r| {
                    let values = r.scaled(heap.rate).map(|v| v as i64).to_vec();
                    sample(values, frames(&r.pcs), Vec::new())
                })
                .collect();
            let profile = pprof::Profile {
                sample_types: types(&[
                    ("alloc_objects", "count"),
                    ("alloc_space", "bytes"),
                    ("inuse_objects", "count"),
                    ("inuse_space", "bytes"),
                ]),
                period_type: Some(("space".into(), "bytes".into())),
                period: heap.rate,
                time_nanos: now_ns(),
                duration_nanos: 0,
                samples,
            };
            (profile, "inuse_space")
        }
        Kind::Block | Kind::Mutex => {
            let mutex = kind == Kind::Mutex;
            let p = go.contention(mutex, &mut stats)?;
            header["profile"] = json!(if mutex { "mutex" } else { "block" });
            header["ticks_per_second"] = json!(p.ticks_per_second);
            let samples = p
                .records
                .iter()
                .map(|r| sample(vec![r.contentions, r.delay_ns], frames(&r.pcs), Vec::new()))
                .collect();
            let profile = pprof::Profile {
                sample_types: types(&[("contentions", "count"), ("delay", "nanoseconds")]),
                period_type: Some(("contentions".into(), "count".into())),
                period: 1,
                time_nanos: now_ns(),
                duration_nanos: 0,
                samples,
            };
            (profile, "delay")
        }
        Kind::Goroutine => {
            let gs = go.goroutines(&mut stats)?;
            header["profile"] = json!("goroutine");
            header["system_goroutines"] = json!(gs.iter().filter(|g| g.system).count());
            header["running_without_stack"] =
                json!(gs.iter().filter(|g| !g.system && g.pcs.is_empty()).count());
            // As pprof's goroutine profile: the program's goroutines, one
            // sample per distinct stack, with how many have it; and here per
            // state too, as a `state` label (a wait reason, or the status of
            // one that is not waiting). A running goroutine has no stack in
            // memory: it stands under the function it started in.
            let mut counts: BTreeMap<(&[u64], &str, &str), i64> = BTreeMap::new();
            for g in gs.iter().filter(|g| !g.system) {
                let state = if g.wait_reason.is_empty() {
                    g.status
                } else {
                    g.wait_reason
                };
                let started = if g.pcs.is_empty() {
                    g.start_function.as_str()
                } else {
                    ""
                };
                *counts.entry((&g.pcs, started, state)).or_default() += 1;
            }
            let mut samples = Vec::with_capacity(counts.len());
            for ((pcs, started, state), count) in counts {
                let frames = if pcs.is_empty() {
                    vec![pprof::Frame {
                        function: started.to_string(),
                        file: String::new(),
                        line: 0,
                        address: 0,
                        module: module.clone(),
                        inlined: false,
                    }]
                } else {
                    frames(pcs)
                };
                let labels = vec![("state".to_string(), state.to_string())];
                samples.push(sample(vec![count], frames, labels));
            }
            if each {
                for g in &gs {
                    extra.push(json!({
                        "goroutine": g.goid,
                        "status": g.status,
                        "wait_reason": g.wait_reason,
                        "wait_since": g.wait_since,
                        "system": g.system,
                        "start": g.start_function,
                        "frames": go.names(&g.pcs),
                    }));
                }
            }
            let profile = pprof::Profile {
                sample_types: types(&[("goroutine", "count")]),
                period_type: Some(("goroutine".into(), "count".into())),
                period: 1,
                time_nanos: now_ns(),
                duration_nanos: 0,
                samples,
            };
            (profile, "goroutine")
        }
    };
    header["sample_types"] = json!(profile
        .sample_types
        .iter()
        .map(|(t, _)| t.as_str())
        .collect::<Vec<_>>());
    header["records_read"] = json!(stats.records);
    header["records_skipped"] = json!(stats.skipped);
    header["read_us"] = json!(stats.micros);
    header["mem_reads"] = json!(stats.reads);
    header["mem_bytes"] = json!(stats.bytes);
    if let Some(out) = out {
        std::fs::write(out, pprof::encode(&profile, Some(default_type))?)
            .with_context(|| format!("writing {}", out.display()))?;
        header["written"] = json!(out.display().to_string());
        println!("{header}");
        return Ok(());
    }
    println!("{header}");
    for s in &profile.samples {
        let stack: Vec<&str> = s.frames.iter().map(|f| f.function.as_str()).collect();
        let labels: BTreeMap<&str, &str> = s
            .labels
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        println!(
            "{}",
            json!({ "values": s.values, "stack": stack, "labels": labels })
        );
    }
    for r in extra {
        println!("{r}");
    }
    Ok(())
}

fn now_ns() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_nanos()).ok())
        .unwrap_or(0)
}

fn flight(pid: u32, out: &Path) -> Result<()> {
    let (go, open_us) = open(pid)?;
    let mut stats = ReadStats::default();
    let t = go.flight_recorder(&mut stats)?;
    std::fs::write(out, &t.bytes)?;
    println!(
        "{}",
        json!({
            "source": "snoop",
            "pid": pid,
            "go_version": go.version,
            "globals_found_by": go.found_by.name(),
            "open_us": open_us,
            "read_us": stats.micros,
            "attempts": t.attempts,
            "generations": t.generations,
            "batches": t.batches,
            "bytes": t.bytes.len(),
            "mem_reads": stats.reads,
            "mem_bytes": stats.bytes,
        })
    );
    Ok(())
}

fn print_pprof(file: &Path) -> Result<()> {
    let p = pprof::read_file(file)?;
    if p.samples.is_empty() && p.sample_types.is_empty() {
        bail!("{}: an empty profile", file.display());
    }
    let header = json!({
        "source": "pprof",
        "file": file.display().to_string(),
        "sample_types": p.sample_types.iter().map(|(t, _)| t.clone()).collect::<Vec<_>>(),
        "units": p.sample_types.iter().map(|(_, u)| u.clone()).collect::<Vec<_>>(),
        "period_type": p.period_type.as_ref().map(|(t, u)| format!("{t}/{u}")),
        "period": p.period,
        "duration_nanos": p.duration_nanos,
    });
    println!("{header}");
    for s in &p.samples {
        let physical: Vec<&str> = s
            .frames
            .iter()
            .filter(|f| !f.inlined)
            .map(|f| f.function.as_str())
            .collect();
        let all: Vec<&str> = s.frames.iter().map(|f| f.function.as_str()).collect();
        let labels: BTreeMap<&str, &str> = s
            .labels
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        println!(
            "{}",
            json!({ "values": s.values, "stack": physical, "inlined_stack": all, "labels": labels })
        );
    }
    Ok(())
}
