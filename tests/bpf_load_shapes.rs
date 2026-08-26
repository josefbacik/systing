//! Load every BPF program at every configuration shape that ships, and —
//! in a second, slower read — require that the union of what the verifier
//! visited covers every instruction of every program.
//!
//! Background: the BPF object's behaviour is selected through `.rodata`
//! constants set before load; the verifier constant-folds them and prunes
//! the branches a configuration disables, so a program that loads at one
//! shape can still be rejected at another, and a load at the defaults says
//! nothing about code only the memory recorder's configuration enables.
//! `every_shape_loads` is the load-time positive control for that class:
//! every shape in `systing::bpf_load_shapes::shape_table()` must load on this
//! kernel, with the rejecting verifier log printed in full. It loads at
//! verifier log level 0 and takes a few minutes even on the VM rig's
//! KVM-less guest.
//!
//! `every_instruction_is_verified_by_some_shape` is the coverage read: any
//! instruction no shape reaches names a configuration the table lacks (or
//! dead code, which is then listed in `ALLOWED_UNVISITED` with a reason). It
//! needs the level-2 verifier log, which costs a formatted line per
//! instruction per state, so it asks for level 2 only on the programs whose
//! union is still incomplete after the shapes loaded so far — most programs
//! are covered by the first shape that selects them and drop to level 0 for
//! the rest. It is still the slow one; run it on its own with a bound that
//! fits the host.
//!
//! Requires root/BPF privileges; run via:
//!   ./scripts/run-integration-tests.sh bpf_load_shapes
//! (or the VM rig with a `-f every_shape_loads` filter for the gate alone).

use std::collections::{BTreeMap, BTreeSet};

use systing::bpf_load_shapes::{coverage_gaps, ranges, shape_table, LoadReport};
use systing::systing_core::bpf_load_probe;

/// Instructions known to be unreachable at every shipping shape, with the
/// reason. Add a row only with the reason; the entry is `(program, ranges)`
/// where ranges is the string `ranges()` prints.
const ALLOWED_UNVISITED: &[(&str, &str, &str)] = &[
    // (program, "start-end, start-end", reason)
];

/// Programs that load only with an attach-time input the table cannot
/// carry, or only on a kernel other than this one (a twin the running
/// kernel does not select), with the reason; they are reported, not
/// failed, when no shape selects them.
const SELECTED_ELSEWHERE: &[(&str, &str)] = &[
    (
        "systing_cgroup_target_add",
        "loads only with a --cgroup target on a kernel with the cgroup kfuncs; the target is an attach-time input",
    ),
    (
        "systing_tracepoint",
        "kernels before 6.10 load it in place of systing_raw_tracepoint",
    ),
    (
        "systing_raw_tracepoint",
        "kernels from 6.10 load it in place of systing_tracepoint",
    ),
    (
        "systing_rss_stat_btf",
        "loads only on a kernel whose BTF carries the rss_stat tracepoint; the classic twin loads elsewhere",
    ),
];

fn allowed(program: &str) -> Option<(&'static str, &'static str)> {
    ALLOWED_UNVISITED
        .iter()
        .find(|(p, _, _)| *p == program)
        .map(|(_, r, why)| (*r, *why))
}

/// Print every rejected program's verifier log and record the rejection.
fn record_rejections(
    shape: &str,
    report: &LoadReport,
    rejected: &mut BTreeMap<String, Vec<String>>,
) {
    if report.loaded {
        return;
    }
    for p in report.failed_programs() {
        eprintln!(
            "[{shape}] program {} REJECTED:\n{}",
            p.name,
            p.verifier_log
                .as_deref()
                .unwrap_or("(no verifier log captured)")
        );
        rejected
            .entry(p.name.clone())
            .or_default()
            .push(shape.to_string());
    }
    if report.failed_programs().is_empty() {
        eprintln!(
            "[{shape}] load failed without a per-program rejection: {}",
            report.error.as_deref().unwrap_or("(no error text)")
        );
        rejected
            .entry("(object)".to_string())
            .or_default()
            .push(shape.to_string());
    }
}

fn rejection_findings(rejected: &BTreeMap<String, Vec<String>>) -> Vec<String> {
    rejected
        .iter()
        .map(|(program, shapes)| {
            format!(
                "verifier rejected {program} at shape(s) {}",
                shapes.join(", ")
            )
        })
        .collect()
}

/// Every program in the object must be selected by at least one shape,
/// unless it needs an attach-time input the table cannot carry.
fn selection_findings(reports: &[(String, LoadReport)]) -> Vec<String> {
    let mut never_selected: Vec<String> = Vec::new();
    if let Some((_, first)) = reports.first() {
        for p in &first.programs {
            let selected_somewhere = reports
                .iter()
                .any(|(_, r)| r.programs.iter().any(|q| q.name == p.name && q.autoload));
            if selected_somewhere {
                continue;
            }
            match SELECTED_ELSEWHERE.iter().find(|(name, _)| *name == p.name) {
                Some((_, why)) => eprintln!("[selection] {} selected by no shape ({why})", p.name),
                None => never_selected.push(p.name.clone()),
            }
        }
    }
    if never_selected.is_empty() {
        Vec::new()
    } else {
        vec![format!(
            "programs selected by no shape in the table (add the shape that loads them, or document why they never load): {}",
            never_selected.join(", ")
        )]
    }
}

/// The gate: every shape in the table loads on this kernel, and every
/// program in the object is selected by some shape (or documented).
#[test]
#[ignore] // Requires root/BPF privileges
fn every_shape_loads() {
    let shapes = shape_table();
    let mut reports: Vec<(String, LoadReport)> = Vec::new();
    let mut rejected: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for shape in &shapes {
        let started = std::time::Instant::now();
        let report = bpf_load_probe(&shape.config, shape.legs, &|_| 0)
            .unwrap_or_else(|e| panic!("[{}] probe failed before load: {e:#}", shape.name));
        let selected = report.programs.iter().filter(|p| p.autoload).count();
        eprintln!(
            "[{}] loaded={} programs selected={} in {:.1?}",
            shape.name,
            report.loaded,
            selected,
            started.elapsed()
        );
        record_rejections(shape.name, &report, &mut rejected);
        reports.push((shape.name.to_string(), report));
    }

    let mut failures = rejection_findings(&rejected);
    failures.extend(selection_findings(&reports));
    assert!(
        failures.is_empty(),
        "{} finding(s):\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

/// The coverage read: the union over all shapes of the instructions the
/// verifier visited covers every instruction of every program that loaded.
/// Level-2 logging is requested only for programs not yet fully covered.
#[test]
#[ignore] // Requires root/BPF privileges; slow (level-2 verifier logs)
fn every_instruction_is_verified_by_some_shape() {
    let shapes = shape_table();
    let mut reports: Vec<(String, LoadReport)> = Vec::new();
    let mut rejected: BTreeMap<String, Vec<String>> = BTreeMap::new();
    // Programs whose visited union already equals their instruction count:
    // no further shape needs the level-2 log for them.
    let mut covered: BTreeSet<String> = BTreeSet::new();
    let mut union: BTreeMap<String, (usize, BTreeSet<u32>)> = BTreeMap::new();

    for shape in &shapes {
        let started = std::time::Instant::now();
        let report = bpf_load_probe(&shape.config, shape.legs, &|name| {
            if covered.contains(name) {
                0
            } else {
                2
            }
        })
        .unwrap_or_else(|e| panic!("[{}] probe failed before load: {e:#}", shape.name));
        let selected = report.programs.iter().filter(|p| p.autoload).count();
        let logged = report
            .programs
            .iter()
            .filter(|p| p.autoload && p.verifier_log.is_some())
            .count();
        let visited: usize = report.programs.iter().map(|p| p.visited.len()).sum();
        eprintln!(
            "[{}] loaded={} programs selected={} logged at level 2={} visited insns={} in {:.1?}",
            shape.name,
            report.loaded,
            selected,
            logged,
            visited,
            started.elapsed()
        );
        record_rejections(shape.name, &report, &mut rejected);
        if report.loaded {
            for p in report.programs.iter().filter(|p| p.autoload) {
                let entry = union
                    .entry(p.name.clone())
                    .or_insert_with(|| (p.insn_total, BTreeSet::new()));
                entry.0 = entry.0.max(p.insn_total);
                entry.1.extend(p.visited.iter().copied());
                if entry.0 > 0 && entry.1.len() >= entry.0 {
                    covered.insert(p.name.clone());
                }
            }
        }
        reports.push((shape.name.to_string(), report));
    }

    let mut failures = rejection_findings(&rejected);

    // Coverage: every instruction of every program that loaded must have
    // been visited by the verifier at some shape.
    for gap in coverage_gaps(&reports) {
        if gap.loaded_by.is_empty() {
            failures.push(format!(
                "program {} was selected by a shape but loaded by none",
                gap.program
            ));
            continue;
        }
        let rendered = ranges(&gap.unvisited);
        match allowed(&gap.program) {
            Some((allowed_ranges, why)) if allowed_ranges == rendered => {
                eprintln!(
                    "[coverage] {}: {} unvisited of {} allowed ({why})",
                    gap.program,
                    gap.unvisited.len(),
                    gap.insn_total
                );
            }
            Some((allowed_ranges, _)) => failures.push(format!(
                "program {}: unvisited instructions {} (of {}) differ from the allowed {} — loaded by {}",
                gap.program,
                rendered,
                gap.insn_total,
                allowed_ranges,
                gap.loaded_by.join(", ")
            )),
            None => failures.push(format!(
                "program {}: instructions {} (of {}) are verified by NO shape in the table — a configuration is missing, or the code is dead (then allow it with a reason); loaded by {}",
                gap.program,
                rendered,
                gap.insn_total,
                gap.loaded_by.join(", ")
            )),
        }
    }

    failures.extend(selection_findings(&reports));
    assert!(
        failures.is_empty(),
        "{} finding(s):\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}
