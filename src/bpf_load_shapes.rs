//! Load-every-program × every-configuration-shape: the data and the
//! arithmetic behind `tests/bpf_load_shapes.rs`.
//!
//! The BPF object's behaviour is configured through `.rodata` constants that
//! userspace sets before load (`tool_config`: which recorders are on, sample
//! rates, thresholds, filters). libbpf freezes `.rodata`, and the verifier
//! constant-folds every branch on those constants, so the code a load
//! verifies is exactly the code the configuration enables — a branch no
//! shape turns on is never verified, and a defect in it ships. The
//! instrument here is therefore two-fold: every shape that ships must LOAD
//! (the verifier accepts the object at that configuration), and the union
//! over all shapes of the instructions the verifier visited must cover every
//! instruction of every program that loaded — an instruction no shape
//! reaches names a configuration the table is missing (or dead code, which
//! is then allowed explicitly, with a reason).
//!
//! [`crate::systing_core::bpf_load_probe`] performs one load at one shape and
//! returns the per-program visited sets, read from the verifier's level-2
//! log; this module owns the shape table, the log parsing, and the coverage
//! arithmetic, all of which are plain functions with unit tests.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::systing_core::{Config, KernelHooks};

/// One program's outcome in a load probe.
#[derive(Debug, Clone)]
pub struct ProgramLoad {
    pub name: String,
    /// Selected for load at this shape (`get_required_bpf_programs`).
    pub autoload: bool,
    /// Instructions in the loaded program (main body plus the subprograms
    /// libbpf appended to it); 0 when the object did not load or the program
    /// was not selected.
    pub insn_total: usize,
    /// Instruction indices the verifier visited, from the level-2 log.
    pub visited: BTreeSet<u32>,
    /// The program's own section of the verifier log, when one was printed.
    pub verifier_log: Option<String>,
}

/// The outcome of one load probe.
#[derive(Debug, Clone)]
pub struct LoadReport {
    /// The whole object loaded (every selected program verified).
    pub loaded: bool,
    /// libbpf's error when it did not.
    pub error: Option<String>,
    pub programs: Vec<ProgramLoad>,
}

impl LoadReport {
    /// The programs libbpf reported as rejected by the verifier at this
    /// shape (their log section starts with libbpf's failure line).
    pub fn failed_programs(&self) -> Vec<&ProgramLoad> {
        self.programs
            .iter()
            .filter(|p| {
                p.autoload
                    && p.verifier_log
                        .as_deref()
                        .is_some_and(|l| l.contains("BPF program load failed"))
            })
            .collect()
    }
}

/// Split libbpf's captured print output into one verifier-log section per
/// program, keyed by program name. Sections are delimited by libbpf's
/// `prog '<name>': -- BEGIN PROG LOAD LOG --` / `-- END PROG LOAD LOG --`
/// lines; a program that libbpf reported as failed has its failure line
/// prepended to its section so the caller can tell the two apart.
pub fn split_prog_load_logs(captured: &str) -> HashMap<String, String> {
    let mut sections: HashMap<String, String> = HashMap::new();
    let mut current: Option<(String, String)> = None;
    for line in captured.lines() {
        if let Some(rest) = line.strip_prefix("libbpf: prog '") {
            if let Some((name, tail)) = rest.split_once("': ") {
                if tail.starts_with("-- BEGIN PROG LOAD LOG --") {
                    current = Some((name.to_string(), String::new()));
                    continue;
                }
                if tail.starts_with("BPF program load failed") {
                    sections
                        .entry(name.to_string())
                        .or_default()
                        .push_str(&format!("{line}\n"));
                    continue;
                }
            }
        }
        if line.starts_with("-- END PROG LOAD LOG --") {
            if let Some((name, body)) = current.take() {
                sections.entry(name).or_default().push_str(&body);
            }
            continue;
        }
        if let Some((_, body)) = current.as_mut() {
            body.push_str(line);
            body.push('\n');
        }
    }
    // An unterminated section (the capture ended mid-log) still counts.
    if let Some((name, body)) = current.take() {
        sections.entry(name).or_default().push_str(&body);
    }
    sections
}

/// The instruction indices a level-2 verifier log shows as visited: every
/// line of the form `<n>: (<opcode>) ...`. State lines (`from 12 to 34: ...`,
/// `; source`, `processed N insns`) carry no index of their own.
pub fn visited_insns(section: &str) -> BTreeSet<u32> {
    let mut visited = BTreeSet::new();
    for line in section.lines() {
        let line = line.trim_start();
        let Some((idx, rest)) = line.split_once(": ") else {
            continue;
        };
        if !rest.starts_with('(') {
            continue;
        }
        if let Ok(n) = idx.parse::<u32>() {
            visited.insert(n);
        }
    }
    visited
}

/// How a probe decides the recorders' kernel-probed legs (the memory
/// recorder's mmap/munmap/brk hook form, VFIO and THP; the network
/// recorder's TIME_WAIT hook form): as the host allows, or forced for a
/// load-only read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegSelection {
    /// Probe this kernel's symbols and tracepoints, as a capture does.
    Host,
    /// Select every optional leg regardless of the host (the VFIO ioctl and
    /// teardown pairs included), naming which PMD-split and folio-split
    /// programs to load (the kernel picks one of two of each at capture
    /// time; a load-only read wants each in turn). The syscall hooks stay as
    /// the host decides them.
    Force {
        thp_pmd_prog: &'static str,
        thp_page_prog: &'static str,
    },
    /// The mmap/munmap/brk hooks in classic form only under the trampoline
    /// form — the trampoline set left unselected, as on a kernel whose
    /// kallsyms lacks the arch syscall wrappers (riscv before 6.6) — so the
    /// object a capture there loads is verified too. The other legs as the
    /// host decides them.
    SyscallTracepointOnly,
    /// The network recorder's TIME_WAIT hooks in kprobe form only under the
    /// trampoline form — the fentry set left unselected, as on a kernel
    /// whose vmlinux BTF lacks the three functions — so the object a capture
    /// there loads is verified too. The other legs as the host decides them.
    NetworkTwKprobeOnly,
}

/// One row of the shape table: a name, the configuration it loads, and how
/// the kernel-probed legs are decided for it.
pub struct LoadShape {
    pub name: &'static str,
    pub config: Config,
    pub legs: LegSelection,
}

fn base() -> Config {
    // The continuous capture's defaults: sched + irq + CPU stacks, one
    // ring plan from the host's CPU count.
    Config {
        continuous: 30,
        ..Config::default()
    }
}

/// The configurations that ship, as the agent's launcher and the on-demand
/// lane build them. Every row is one load; a new knob is one new row. The
/// values are the ones a continuous capture runs with, not the CLI
/// defaults, wherever the two differ.
pub fn shape_table() -> Vec<LoadShape> {
    let mut shapes = Vec::new();
    let mut add = |name: &'static str, f: &dyn Fn(&mut Config)| {
        let mut c = base();
        f(&mut c);
        shapes.push(LoadShape {
            name,
            config: c,
            legs: LegSelection::Host,
        });
    };

    // CPU lane.
    add("continuous-default", &|_| {});
    add("continuous-sw-event", &|c| c.sw_event = true);
    add("continuous-no-sched-no-irq", &|c| {
        c.no_sched = true;
        c.no_irq = true;
    });
    add("continuous-no-stack-traces", &|c| c.no_stack_traces = true);
    add("continuous-no-cpu-stack-traces", &|c| {
        c.no_cpu_stack_traces = true
    });
    add("continuous-no-sleep-stack-traces", &|c| {
        c.no_sleep_stack_traces = true;
        c.no_interruptible_stack_traces = true;
    });
    add("continuous-build-id", &|c| c.collect_build_id = true);
    add("continuous-syscalls-markers", &|c| {
        c.syscalls = true;
        c.markers = true;
    });
    add("continuous-pystacks", &|c| c.collect_pystacks = true);
    add("continuous-ringbuf-shards-8", &|c| c.ringbuf_shards = 8);
    add("continuous-ringbuf-25mib", &|c| c.ringbuf_size_mib = 25);

    // Filters (a pid that exists: our own; the cgroup filter needs a target
    // cgroup and is a separate attach-time input, so it is not a load shape).
    add("filter-pid", &|c| c.pid = vec![std::process::id()]);

    // The generic probe handlers load only when a trace event is configured
    // (one tracepoint every kernel has), with the pid filter so the fork
    // and exec trackers load with them.
    add("trace-event-tracepoint", &|c| {
        c.trace_event = vec!["tracepoint:sched:sched_process_exit".to_string()];
        c.pid = vec![std::process::id()];
        c.collect_pystacks = true;
    });

    // Memory lane: the continuous launcher's shape (default rss threshold,
    // fault/map sample rates 0 = every event), then each knob the launcher
    // or the on-demand lane can set.
    add("memory-default", &|c| c.memory = true);
    add("memory-sw-event", &|c| {
        c.memory = true;
        c.sw_event = true;
    });
    add("memory-rss-threshold-0", &|c| {
        c.memory = true;
        c.memory_rss_threshold_bytes = Some(0);
    });
    add("memory-sample-rates-1", &|c| {
        c.memory = true;
        c.memory_fault_sample_rate = 1;
        c.memory_map_sample_rate = 1;
    });
    add("memory-sample-rates-97", &|c| {
        c.memory = true;
        c.memory_fault_sample_rate = 97;
        c.memory_map_sample_rate = 97;
    });
    add("memory-rss-classic", &|c| {
        c.memory = true;
        c.memory_rss_force_classic = true;
    });
    add("memory-alloc", &|c| {
        c.memory = true;
        c.memory_alloc = true;
    });
    add("memory-alloc-sampled", &|c| {
        c.memory = true;
        c.memory_alloc = true;
        c.memory_alloc_sample_rate = 13;
    });
    add("memory-vfio-thp", &|c| {
        c.memory = true;
        c.memory_vfio = true;
        c.memory_thp_sample_rate = 1;
    });
    add("memory-ringbuf-shards-8", &|c| {
        c.memory = true;
        c.ringbuf_shards = 8;
    });

    // Network lane. Every network row selects the TIME_WAIT leg as the host
    // and the hook form allow (`probe_network_kernel_legs`): under the
    // default classic form the kprobe trio alone loads; the `-trampoline`
    // rows below opt into the fentry form, where on a 6.11+ kernel with BTF
    // — every rig kernel — BOTH its program sets load (the fentry trio and
    // the kprobe fallback trio), so the verifier checks both and a capture
    // attaches one. The fentry set cannot be forced onto a kernel whose BTF
    // lacks the functions (the load, not the attach, would fail); the
    // kprobe-only object a trampoline-form capture on such a host loads is
    // the `network-tw-kprobe-only` row below.
    add("network", &|c| c.network = true);
    add("network-packets", &|c| {
        c.network = true;
        c.network_packets = true;
    });
    // The per-packet sampling arm of the data-path packet hooks is dead
    // code at the default rate (rodata, pruned by the verifier); this row
    // is the load that walks it.
    add("network-packets-sampled", &|c| {
        c.network = true;
        c.network_packets = true;
        c.packet_sample_rate = 4;
    });
    add("network-syscalls", &|c| {
        c.network = true;
        c.network_syscalls = true;
    });

    // The opt-in trampoline form (`--kernel-hooks trampoline`): the
    // fentry/fexit syscall hooks and the fentry TIME_WAIT trio load beside
    // their classic fallbacks, so the trampoline programs meet the verifier
    // at the agent's memory and network shapes even though no shipped
    // configuration selects them by default.
    add("memory-trampoline", &|c| {
        c.memory = true;
        c.kernel_hooks = KernelHooks::Trampoline;
    });
    add("network-trampoline", &|c| {
        c.network = true;
        c.kernel_hooks = KernelHooks::Trampoline;
    });

    // Everything on: the widest autoload set in one object.
    add("all-recorders", &|c| {
        c.memory = true;
        c.memory_alloc = true;
        c.memory_vfio = true;
        c.memory_thp_sample_rate = 1;
        c.network = true;
        c.network_packets = true;
        c.network_syscalls = true;
        c.collect_pystacks = true;
        c.syscalls = true;
        c.markers = true;
        c.sw_event = true;
        c.kernel_hooks = KernelHooks::Trampoline;
    });

    // The VFIO/IOMMU and THP-split legs, forced on: a host without the
    // vfio_iommu_type1 module or the split symbols never selects these
    // programs for a capture, so this is the only load they get on such a
    // host — once per PMD-split tier (the worker probe, the 6.10+ global
    // funnel, the entry fallback) and once per folio-split twin.
    for (name, thp_pmd_prog, thp_page_prog) in [
        (
            "memory-vfio-thp-forced",
            "systing_thp_split_pmd_locked",
            "systing_thp_split_page",
        ),
        (
            "memory-vfio-thp-forced-global",
            "systing_thp_split_pmd_global",
            "systing_thp_split_page",
        ),
        (
            "memory-vfio-thp-forced-legacy",
            "systing_thp_split_pmd",
            "systing_thp_split_page_legacy",
        ),
    ] {
        let mut c = base();
        c.memory = true;
        c.memory_vfio = true;
        c.memory_thp_sample_rate = 1;
        shapes.push(LoadShape {
            name,
            config: c,
            legs: LegSelection::Force {
                thp_pmd_prog,
                thp_page_prog,
            },
        });
    }

    // The trampoline form on a host without the arch syscall wrappers in
    // kallsyms (riscv before 6.6): only the classic tracepoint set is
    // selected, the object of a `--kernel-hooks trampoline` capture there.
    // (Under the default classic form every memory row above already loads
    // exactly that set; the trampoline set itself is verified by the
    // `memory-trampoline` row on a host that has the wrappers.)
    let mut c = base();
    c.memory = true;
    c.kernel_hooks = KernelHooks::Trampoline;
    shapes.push(LoadShape {
        name: "memory-syscall-tracepoint-only",
        config: c,
        legs: LegSelection::SyscallTracepointOnly,
    });

    // The trampoline form on a host whose vmlinux BTF lacks the three
    // TIME_WAIT functions: only the kprobe set is selected, the object of a
    // `--kernel-hooks trampoline` capture there. (The default classic form
    // loads that set on every network row above; the fentry set itself is
    // verified by the `network-trampoline` row on a host that has them.)
    let mut c = base();
    c.network = true;
    c.kernel_hooks = KernelHooks::Trampoline;
    shapes.push(LoadShape {
        name: "network-tw-kprobe-only",
        config: c,
        legs: LegSelection::NetworkTwKprobeOnly,
    });

    shapes
}

/// Instructions of a program that no shape in the run reached, with the
/// shapes that loaded the program. Programs that never loaded successfully
/// at any shape are reported as such (their instruction count is unknown).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageGap {
    pub program: String,
    pub insn_total: usize,
    pub unvisited: Vec<u32>,
    pub loaded_by: Vec<String>,
}

/// Union the visited sets of every successful load and name, per program,
/// the instructions no shape visited. A program selected by at least one
/// shape but loaded by none is reported with `insn_total = 0` and an empty
/// `loaded_by`, so the caller can fail on it too.
pub fn coverage_gaps(reports: &[(String, LoadReport)]) -> Vec<CoverageGap> {
    struct Acc {
        insn_total: usize,
        visited: BTreeSet<u32>,
        loaded_by: Vec<String>,
    }
    let mut acc: BTreeMap<String, Acc> = BTreeMap::new();
    for (shape, report) in reports {
        for p in &report.programs {
            if !p.autoload {
                continue;
            }
            let e = acc.entry(p.name.clone()).or_insert_with(|| Acc {
                insn_total: 0,
                visited: BTreeSet::new(),
                loaded_by: Vec::new(),
            });
            // A rejected load still shows which instructions were reached
            // before the rejection; they count as visited for coverage (the
            // rejection itself is the caller's finding).
            e.visited.extend(p.visited.iter().copied());
            if report.loaded {
                e.insn_total = e.insn_total.max(p.insn_total);
                e.loaded_by.push(shape.clone());
            }
        }
    }
    let mut gaps = Vec::new();
    for (program, e) in acc {
        if e.loaded_by.is_empty() {
            gaps.push(CoverageGap {
                program,
                insn_total: 0,
                unvisited: Vec::new(),
                loaded_by: Vec::new(),
            });
            continue;
        }
        let unvisited: Vec<u32> = (0..e.insn_total as u32)
            .filter(|i| !e.visited.contains(i))
            .collect();
        if !unvisited.is_empty() {
            gaps.push(CoverageGap {
                program,
                insn_total: e.insn_total,
                unvisited,
                loaded_by: e.loaded_by,
            });
        }
    }
    gaps
}

/// Render a run of unvisited instruction indices as ranges (`99-145, 202-253`).
pub fn ranges(indices: &[u32]) -> String {
    let mut out = Vec::new();
    let mut i = 0;
    while i < indices.len() {
        let start = indices[i];
        let mut end = start;
        while i + 1 < indices.len() && indices[i + 1] == end + 1 {
            i += 1;
            end = indices[i];
        }
        if start == end {
            out.push(format!("{start}"));
        } else {
            out.push(format!("{start}-{end}"));
        }
        i += 1;
    }
    out.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "libbpf: prog 'systing_a': -- BEGIN PROG LOAD LOG --\n\
0: R1=ctx() R10=fp0\n\
; int systing_a(void *ctx)\n\
0: (b7) r0 = 0\n\
1: (79) r1 = *(u64 *)(r1 +0)\n\
; if (tool_config.collect_memory)\n\
2: (15) if r1 == 0x0 goto pc+5\n\
3: (85) call bpf_get_current_pid_tgid#14\n\
from 2 to 8: R0=0\n\
8: (95) exit\n\
processed 6 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 1\n\
-- END PROG LOAD LOG --\n\
libbpf: prog 'systing_b': BPF program load failed: -EACCES\n\
libbpf: prog 'systing_b': -- BEGIN PROG LOAD LOG --\n\
0: (b7) r0 = 0\n\
1: (95) exit\n\
R0 unbounded memory access\n\
-- END PROG LOAD LOG --\n";

    #[test]
    fn splits_sections_per_program() {
        let s = split_prog_load_logs(SAMPLE);
        assert_eq!(s.len(), 2);
        assert!(s["systing_a"].contains("processed 6 insns"));
        assert!(s["systing_b"].starts_with("libbpf: prog 'systing_b': BPF program load failed"));
        assert!(s["systing_b"].contains("R0 unbounded memory access"));
    }

    #[test]
    fn visited_reads_instruction_lines_only() {
        let s = split_prog_load_logs(SAMPLE);
        let v = visited_insns(&s["systing_a"]);
        assert_eq!(v.into_iter().collect::<Vec<_>>(), vec![0, 1, 2, 3, 8]);
    }

    fn report(loaded: bool, progs: &[(&str, usize, &[u32])]) -> LoadReport {
        LoadReport {
            loaded,
            error: None,
            programs: progs
                .iter()
                .map(|(n, total, vis)| ProgramLoad {
                    name: n.to_string(),
                    autoload: true,
                    insn_total: *total,
                    visited: vis.iter().copied().collect(),
                    verifier_log: None,
                })
                .collect(),
        }
    }

    #[test]
    fn coverage_unions_shapes_and_names_gaps() {
        let reports = vec![
            ("a".to_string(), report(true, &[("p", 10, &[0, 1, 2, 9])])),
            (
                "b".to_string(),
                report(true, &[("p", 10, &[0, 3, 4, 5, 9])]),
            ),
        ];
        let gaps = coverage_gaps(&reports);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].program, "p");
        assert_eq!(gaps[0].unvisited, vec![6, 7, 8]);
        assert_eq!(gaps[0].loaded_by, vec!["a", "b"]);
        assert_eq!(ranges(&gaps[0].unvisited), "6-8");
    }

    #[test]
    fn coverage_full_is_no_gap() {
        let reports = vec![
            ("a".to_string(), report(true, &[("p", 4, &[0, 1])])),
            ("b".to_string(), report(true, &[("p", 4, &[2, 3])])),
        ];
        assert!(coverage_gaps(&reports).is_empty());
    }

    #[test]
    fn never_loaded_program_is_a_gap() {
        let reports = vec![("a".to_string(), report(false, &[("p", 0, &[0, 1])]))];
        let gaps = coverage_gaps(&reports);
        assert_eq!(gaps.len(), 1);
        assert!(gaps[0].loaded_by.is_empty());
        assert_eq!(gaps[0].insn_total, 0);
    }

    #[test]
    fn ranges_render() {
        assert_eq!(ranges(&[1, 2, 3, 7, 9, 10]), "1-3, 7, 9-10");
        assert_eq!(ranges(&[]), "");
    }

    #[test]
    fn shape_table_names_are_unique_and_cover_the_recorders() {
        let shapes = shape_table();
        let names: BTreeSet<&str> = shapes.iter().map(|s| s.name).collect();
        assert_eq!(names.len(), shapes.len(), "duplicate shape name");
        assert!(shapes
            .iter()
            .any(|s| s.config.memory && s.config.memory_rss_threshold_bytes == Some(0)));
        assert!(shapes
            .iter()
            .any(|s| s.config.memory_vfio && s.config.memory_thp_sample_rate > 0));
        assert!(shapes.iter().any(|s| s.config.network_packets));
        assert!(shapes
            .iter()
            .any(|s| s.config.network_packets && s.config.packet_sample_rate > 1));
        assert!(shapes.iter().any(|s| s.config.memory_alloc));
        assert!(shapes
            .iter()
            .any(|s| s.config.memory && s.legs == LegSelection::SyscallTracepointOnly));
        assert!(shapes
            .iter()
            .any(|s| s.config.network && s.legs == LegSelection::NetworkTwKprobeOnly));
        // The shipped shapes take the default (classic) form; the opt-in
        // trampoline form has its own rows for both legs, so the trampoline
        // programs still meet the verifier on every run of the gate.
        assert!(shapes
            .iter()
            .any(|s| s.name == "memory-default" && s.config.kernel_hooks == KernelHooks::Classic));
        assert!(shapes
            .iter()
            .any(|s| s.name == "network" && s.config.kernel_hooks == KernelHooks::Classic));
        assert!(shapes.iter().any(|s| s.config.memory
            && s.config.kernel_hooks == KernelHooks::Trampoline
            && s.legs == LegSelection::Host));
        assert!(shapes.iter().any(|s| s.config.network
            && s.config.kernel_hooks == KernelHooks::Trampoline
            && s.legs == LegSelection::Host));
    }
}
