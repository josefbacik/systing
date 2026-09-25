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
//! kernel, with the rejecting verifier log printed in full, and so must every
//! shape of the task-stacks recorder's own object
//! (`task_stacks_shape_table()`), which no row of the first table opens. It
//! loads at verifier log level 0 and takes a few minutes even on the VM rig's
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
//! `closed_task_stacks_rows_call_nothing_that_reads_another_task` reads the
//! same log for one question: the rows of the task-stacks object that may not
//! read other tasks' memory (the shape an aarch64 host loads below the kernel
//! releases that make the unwinder's mapping lookup safe) hold no call to the
//! lookup, and none to the remote copy where the kernel drops the global
//! functions nothing calls. Four small loads at level 2, the first of them an
//! open row that has to show the calls.
//!
//! Requires root/BPF privileges; run via:
//!   ./scripts/run-integration-tests.sh bpf_load_shapes
//! (or the VM rig with a `-f every_shape_loads` filter for the gate alone).

use std::collections::{BTreeMap, BTreeSet};

use systing::bpf_load_shapes::{
    coverage_gaps, ranges, shape_table, task_stacks_shape_table, LoadReport, TaskStacksLoadShape,
};
use systing::systing_core::{bpf_load_probe, kallsyms_has_funcs, NETWORK_TW_SYMBOLS};
use systing::task_stacks_recorder::TaskStacksIter;

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

/// Programs of a kernel leg the recorder itself switches off on a kernel that
/// lacks one of the leg's hooked functions (`tw_off = nosym`): the network
/// shapes select them wherever the functions exist and no shape selects them
/// where one is missing. They are allowed unselected ONLY on a kernel that
/// lacks one of the functions; on a kernel that has them all, an unselected
/// program here is a real finding. `inet_twsk_hashdance_schedule` exists from
/// 6.11 (b334b924c9b7), so the 6.6 series takes this branch. The task-stacks
/// object's cgroup-members program is the same case by its kfunc: the
/// recorder asks for it only where the kernel has the css_task iterator
/// (6.7, 9c66dc94b62a), and its row selects it there and nowhere else. The
/// recorder and the probe read that from the kernel's BTF and this allowance
/// from kallsyms: two reads of one fact, and a kernel on which they disagree
/// (the function present, its BTF entry absent) fails the gate, which is the
/// side to err on.
const SELECTED_WHEN_KERNEL_HAS: &[(&str, &[&str])] = &[
    ("tcp_time_wait_fentry", NETWORK_TW_SYMBOLS),
    ("tcp_time_wait_entry", NETWORK_TW_SYMBOLS),
    ("inet_twsk_hashdance_schedule_fentry", NETWORK_TW_SYMBOLS),
    ("inet_twsk_hashdance_schedule_entry", NETWORK_TW_SYMBOLS),
    ("inet_twsk_deschedule_put_fentry", NETWORK_TW_SYMBOLS),
    ("inet_twsk_deschedule_put_entry", NETWORK_TW_SYMBOLS),
    (TASK_STACKS_MEMBERS_PROG, CSS_TASK_ITER_SYMBOLS),
];

/// The task-stacks object's cgroup-members program.
const TASK_STACKS_MEMBERS_PROG: &str = "systing_task_stacks_members";
/// The task-stacks object's recording program: the one that walks a thread's
/// user stack, and so the one whose verifier log the closed rows are read by.
const TASK_STACKS_PROG: &str = "systing_task_stacks";

/// The kfunc the cgroup-members program is written with.
const CSS_TASK_ITER_SYMBOLS: &[&str] = &["bpf_iter_css_task_new"];

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
            if let Some((_, why)) = SELECTED_ELSEWHERE.iter().find(|(name, _)| *name == p.name) {
                eprintln!("[selection] {} selected by no shape ({why})", p.name);
                continue;
            }
            if let Some((_, symbols)) = SELECTED_WHEN_KERNEL_HAS
                .iter()
                .find(|(name, _)| *name == p.name)
            {
                let present = kallsyms_has_funcs(symbols);
                let missing: Vec<&str> = symbols
                    .iter()
                    .copied()
                    .filter(|s| !present.contains(*s))
                    .collect();
                if !missing.is_empty() {
                    eprintln!(
                        "[selection] {} selected by no shape (this kernel lacks {}, so the recorder keeps the leg off)",
                        p.name,
                        missing.join(", ")
                    );
                    continue;
                }
            }
            never_selected.push(p.name.clone());
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

/// The gate: every shape in both tables — the main object's and the
/// task-stacks object's — loads on this kernel, and every program in each
/// object is selected by some shape of its table (or documented).
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

    // The task-stacks recorder's own object, which a capture that asks for
    // the recorder loads beside the main one: its rows, the same read. A
    // refused program fails its row's whole load (the probe has no second
    // load without it), so a rejection reads as one here.
    let task_stacks_shapes = task_stacks_shape_table();
    let mut task_stacks_reports: Vec<(String, LoadReport)> = Vec::new();
    for shape in &task_stacks_shapes {
        let started = std::time::Instant::now();
        let (report, configured) = TaskStacksIter::load_probe(
            &shape.filter,
            shape.mode,
            shape.members,
            shape.task_context,
            shape.remote_reads,
            &|_| 0,
        )
        .unwrap_or_else(|e| panic!("[{}] probe failed before load: {e:#}", shape.name));
        let selected = report.programs.iter().filter(|p| p.autoload).count();
        eprintln!(
            "[{}] loaded={} programs selected={} in {:.1?}",
            shape.name,
            report.loaded,
            selected,
            started.elapsed()
        );
        // A row of the shape that reads nothing of another task says what it
        // loaded with, read back from the configured object and not from the
        // row: every leg that needs those reads is off whatever the row asked
        // for, and the user stack is still collected.
        if !shape.remote_reads {
            eprintln!(
                "[{}] loaded with remote_user_reads={} collect_user={} collect_python={} \
                 task_context={}",
                shape.name,
                configured.remote_user_reads,
                configured.collect_user,
                configured.collect_python,
                configured.task_context
            );
            assert!(
                !configured.remote_user_reads
                    && configured.collect_user
                    && !configured.collect_python
                    && !configured.task_context,
                "[{}] a row without other tasks' memory loaded with {configured:?}",
                shape.name
            );
        }
        // The probe leaves the cgroup-members program out for one reason
        // only, decided before it loads anything. Say so where it happens,
        // so that a selection finding below explains itself.
        if shape.members
            && !report
                .programs
                .iter()
                .any(|p| p.autoload && p.name == TASK_STACKS_MEMBERS_PROG)
        {
            eprintln!(
                "[{}] the cgroup-members program was left unselected: this kernel's BTF does not export {}",
                shape.name, CSS_TASK_ITER_SYMBOLS[0]
            );
        }
        record_rejections(shape.name, &report, &mut rejected);
        task_stacks_reports.push((shape.name.to_string(), report));
    }

    let mut failures = rejection_findings(&rejected);
    failures.extend(selection_findings(&reports));
    failures.extend(selection_findings(&task_stacks_reports));
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
/// The main object's shapes only: the task-stacks object's rows are loaded by
/// the gate above and are not folded in here yet.
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

/// A call to each helper that reads another task's user memory, as the
/// verifier prints one at log level 2 (`call <name>#<id>`). The mapping lookup
/// is one helper, matched whole. The remote copy is a family: the helper
/// `bpf_copy_from_user_task` and the kernel functions named after it
/// (`bpf_copy_from_user_task_str`, `_dynptr`, `_str_dynptr`), so its needle
/// ends before the `#` and matches every member by prefix. Today the object
/// calls the helper alone.
const CALL_FIND_VMA: &str = "call bpf_find_vma#";
const CALL_COPY_FROM_USER_TASK: &str = "call bpf_copy_from_user_task";

/// What a kernel that works out the live registers before its walk prints
/// first at log level 2: this heading, and then every instruction of the
/// program, whether the walk will reach it or not (mainline 6.17 does; 6.12
/// and 6.14 do not).
const LIVE_REGS_LISTING: &str = "Live regs before insn:";

/// Whether a level-2 verifier log shows a WALKED instruction that holds
/// `call`. A walked instruction is a line of the form `<n>: (<opcode>) ...`,
/// its registers after it, as `systing::bpf_load_shapes::visited_insns` reads
/// one. The lines under [`LIVE_REGS_LISTING`] are not of that form: each opens
/// with padding and carries ten register marks between the index and the
/// instruction. Nor is a line that quotes an instruction behind other words
/// (`mark_precise: ... before 12: (85) call ...`). A search of the whole text
/// would find in the listing a call the verifier never walks.
fn log_walks(log: &str, call: &str) -> bool {
    log.lines().any(|line| {
        line.trim_start()
            .split_once(": ")
            .is_some_and(|(index, insn)| {
                index.parse::<u32>().is_ok() && insn.starts_with('(') && insn.contains(call)
            })
    })
}

/// Whether this kernel leaves a global function that no verified path calls
/// unverified (6.8 and later). Before that every global function of an object
/// is verified and kept whatever calls it, and the task-stacks object carries
/// two of the Python walker's that copy another task's memory, which nothing
/// calls in a closed row.
fn kernel_skips_uncalled_global_functions() -> bool {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let mut numbers = release
        .split(|c: char| !c.is_ascii_digit())
        .filter_map(|n| n.parse::<u32>().ok());
    matches!(
        (numbers.next(), numbers.next()),
        (Some(major), Some(minor)) if (major, minor) >= (6, 8)
    )
}

/// Load one row of the task-stacks table with every program at verifier log
/// level 2, which prints each instruction the verifier walks, and say whether
/// any program's log shows a walked call to the mapping lookup, and to the
/// remote copy ([`log_walks`]); and, third, whether a log opened with the
/// listing of every instruction that newer kernels print before the walk,
/// which is not read for either. A row that does not load, a program that was
/// loaded and printed no log, or a log that shows no walked helper call at
/// all, is no read of either and fails here.
fn calls_that_read_another_task(shape: &TaskStacksLoadShape) -> (bool, bool, bool) {
    let (report, _) = TaskStacksIter::load_probe(
        &shape.filter,
        shape.mode,
        shape.members,
        shape.task_context,
        shape.remote_reads,
        &|_| 2,
    )
    .unwrap_or_else(|e| panic!("[{}] probe failed before load: {e:#}", shape.name));
    assert!(
        report.loaded,
        "[{}] did not load at verifier log level 2: {}",
        shape.name,
        report.error.as_deref().unwrap_or("no error text")
    );
    // Every program that was loaded has to have printed its log, and the
    // recording program has to be one of them: a program left out in silence
    // would let another program's log answer for it.
    for program in report.programs.iter().filter(|p| p.autoload) {
        assert!(
            program.verifier_log.is_some(),
            "[{}] program `{}` was loaded and printed no verifier log",
            shape.name,
            program.name
        );
    }
    assert!(
        report
            .programs
            .iter()
            .any(|p| p.name == TASK_STACKS_PROG && p.autoload && p.verifier_log.is_some()),
        "[{}] the recording program `{TASK_STACKS_PROG}` is not among the logs read",
        shape.name
    );
    let logs: Vec<&str> = report
        .programs
        .iter()
        .filter_map(|p| p.verifier_log.as_deref())
        .collect();
    // The read has to see a walked call at all: were a kernel to print a
    // walked instruction in another form, every row would read as calling
    // nothing, and this is where that fails.
    assert!(
        logs.iter().any(|log| log_walks(log, "call bpf_")),
        "[{}] the verifier's log of {} program(s) shows no walked helper call at all: the log \
         was not captured, or its walked lines are not of the form read here, so nothing can be \
         read off it",
        shape.name,
        logs.len()
    );
    // A log that ends before the verifier's closing line was cut: a call
    // past the cut could not be seen.
    assert!(
        logs.iter().all(|log| log.contains("processed ")),
        "[{}] the verifier's log of a program ends before its closing `processed N insns` line",
        shape.name
    );
    (
        logs.iter().any(|log| log_walks(log, CALL_FIND_VMA)),
        logs.iter()
            .any(|log| log_walks(log, CALL_COPY_FROM_USER_TASK)),
        logs.iter().any(|log| log.contains(LIVE_REGS_LISTING)),
    )
}

/// The shape a host loads that may not read other tasks' memory makes no call
/// that does, as far as its verifier's log shows. Every closed row of the
/// task-stacks table is loaded with the verifier's log, and no program's log
/// shows a walked call to the mapping lookup or, where the kernel does not
/// verify the global functions nothing calls, to the remote copy: a branch the
/// verifier pruned on the frozen constant is never walked. Only walked lines
/// are read ([`log_walks`]): a kernel that lists every instruction before its
/// walk names the calls in that listing whatever it then walks. What this
/// shows is "never walked by the verifier"; that such instructions are then
/// gone from the loaded image is the kernel's dead-code removal on a privileged
/// load, which this test does not see. The read is shown to see such a call
/// first: the smallest open row, loaded and read the same way, has to show the
/// remote copy walked, and the lookup where the unwinder makes it (aarch64).
#[test]
#[ignore] // Requires root/BPF privileges
fn closed_task_stacks_rows_call_nothing_that_reads_another_task() {
    let shapes = task_stacks_shape_table();

    let open = shapes
        .iter()
        .find(|s| s.name == "task-stacks-native")
        .expect("the open native row");
    assert!(open.remote_reads, "the control has to be an open row");
    let (find_vma, copy, listed) = calls_that_read_another_task(open);
    eprintln!(
        "[{}] the control: calls bpf_find_vma={find_vma} bpf_copy_from_user_task={copy} \
         (every instruction listed before the walk: {listed})",
        open.name
    );
    assert!(
        copy,
        "[{}] the open row's log shows no walked call to bpf_copy_from_user_task: this read cannot \
         see one",
        open.name
    );
    assert_eq!(
        find_vma,
        cfg!(target_arch = "aarch64"),
        "[{}] the unwinder makes the mapping lookup on aarch64 and nowhere else",
        open.name
    );

    let skips = kernel_skips_uncalled_global_functions();
    let closed: Vec<&TaskStacksLoadShape> = shapes.iter().filter(|s| !s.remote_reads).collect();
    assert!(!closed.is_empty(), "the table has no closed row");
    for shape in closed {
        let (find_vma, copy, listed) = calls_that_read_another_task(shape);
        eprintln!(
            "[{}] closed: calls bpf_find_vma={find_vma} bpf_copy_from_user_task={copy} \
             (this kernel leaves uncalled global functions unverified: {skips}; every \
             instruction listed before the walk: {listed})",
            shape.name
        );
        assert!(
            !find_vma,
            "[{}] the verifier walked a call to bpf_find_vma",
            shape.name
        );
        if skips {
            assert!(
                !copy,
                "[{}] the verifier walked a call to bpf_copy_from_user_task",
                shape.name
            );
        }
    }
}

/// [`log_walks`] on the two forms a level-2 log takes: one that opens with the
/// listing of every instruction, where the calls to the lookup and to the
/// remote copy are listed, quoted and never walked, and one without a listing,
/// where both are walked. Runs anywhere: it loads nothing.
#[test]
fn log_walks_reads_walked_instructions_only() {
    let listed_not_walked = "\
Live regs before insn:
      0: .1........ (bf) r6 = r1
      1: ......6... (85) call bpf_find_vma#180
  2   2: 0.....6... (85) call bpf_copy_from_user_task#191
    103: 0......... (95) exit
0: R1=ctx() R10=fp0
; struct task_struct *task; @ prog.bpf.c:12
0: (bf) r6 = r1                       ; R1=ctx() R6_w=ctx()
1: (85) call bpf_map_lookup_elem#1    ; R0_w=map_value_or_null(id=1)
mark_precise: frame0: regs=r2 stack= before 1: (85) call bpf_map_lookup_elem#1
mark_precise: frame0: regs=r1 stack= before 1: (85) call bpf_find_vma#180
regs=2 stack=0 before 2: (85) call bpf_copy_from_user_task#191

from 1 to 103: R0=scalar() R10=fp0
103: (95) exit
processed 3 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
";
    assert!(listed_not_walked.contains(LIVE_REGS_LISTING));
    assert!(listed_not_walked.contains(CALL_FIND_VMA));
    assert!(listed_not_walked.contains(CALL_COPY_FROM_USER_TASK));
    assert!(log_walks(listed_not_walked, "call bpf_"));
    assert!(log_walks(listed_not_walked, "call bpf_map_lookup_elem#"));
    // Listed, and quoted in both forms a precision trace has taken: not walked.
    assert!(!log_walks(listed_not_walked, CALL_FIND_VMA));
    assert!(!log_walks(listed_not_walked, CALL_COPY_FROM_USER_TASK));

    let walked = "\
0: R1=ctx() R10=fp0
0: (bf) r6 = r1                       ; R1=ctx() R6_w=ctx()
1: (85) call bpf_find_vma#180         ; R0_w=scalar()
2: (85) call bpf_copy_from_user_task#191
3: (85) call bpf_copy_from_user_task_str#9001
4: (95) exit
processed 5 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
";
    assert!(!walked.contains(LIVE_REGS_LISTING));
    assert!(log_walks(walked, CALL_FIND_VMA));
    assert!(log_walks(walked, CALL_COPY_FROM_USER_TASK));
    // The helper itself, and a member of its family by the same prefix.
    assert!(log_walks(walked, "call bpf_copy_from_user_task#"));
    assert!(log_walks(walked, "call bpf_copy_from_user_task_str#"));
    assert!(!log_walks(walked, "call bpf_map_lookup_elem#"));
}
