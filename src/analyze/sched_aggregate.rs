//! Per-capture scheduler aggregates (`systing-analyze sched aggregate`).
//!
//! One pass over the scheduler event stream of a trace (`sched_slice` starts
//! and ends, `thread_state` runnable markers, `wakeup_new`) produces a compact
//! summary meant to be emitted once per capture and compared across hosts or
//! schedulers: wakeup latency, preempt wait, on-CPU slice length, context
//! switch and migration rates, a time-weighted runqueue-length distribution,
//! per-CPU load vectors with imbalance metrics, log2 histograms beside every
//! percentile, and the threads that contribute most to the latency tail.
//!
//! Definitions (all times in ns; "window" = the analyzed time range):
//! - **wakeup latency**: first `sched_slice.ts` of a thread at or after its
//!   runnable marker (`thread_state.state = 0`, stamped with the wakeup's
//!   target CPU) minus the marker's ts. Split by placement: the thread ran on
//!   the target CPU (same) or elsewhere (cross).
//! - **preempt wait**: a slice that ended with `end_state` NULL left the thread
//!   runnable; the wait is until its next slice starts.
//! - **run delay**: wakeup latency and preempt wait together (all
//!   runnable-but-not-running time that ended inside the window).
//! - **slice length**: `sched_slice.dur` of non-idle slices.
//! - **context switches**: non-idle slice starts; voluntary when the slice
//!   ended in a sleep state, involuntary when it was preempted.
//! - **migrations**: consecutive slices of one thread on different CPUs; a
//!   "wakeup migration" had a runnable marker in between (the thread slept,
//!   woke, and ran elsewhere than it last ran), a "preempt migration" did not
//!   (it was moved while runnable).
//! - **runqueue length** of a CPU: 1 if it runs a non-idle task, plus the
//!   threads runnable-but-not-running that are assigned to it — a woken thread
//!   to its wakeup target CPU, a preempted thread to the CPU it was preempted
//!   on — until each starts running. A runnable thread the load balancer moves
//!   before it runs is still counted on its previous CPU (the trace carries no
//!   migrate event), so the per-CPU length is an approximation; the node-wide
//!   total is exact. Distributions are time-weighted over (cpu × time).
//! - **work-conservation violation**: time during which some observed CPU has
//!   runqueue length > 1 while another observed CPU is idle.
//! - Per-CPU accounting starts at the CPU's first event in the window (before
//!   that its state is unknown); CPUs with no events at all are reported as
//!   unobserved, never assumed idle or busy. Waits that do not end inside the
//!   window are counted as censored, never extrapolated.
//!
//! Percentiles come from a log-linear histogram (16 sub-buckets per octave,
//! upper bucket edge reported, so a percentile is within ~6% of the exact
//! value); averages, sums and maxima are exact. The `hist_log2` arrays are the
//! same histograms folded to one count per octave so rows from different
//! captures and hosts can be merged.

use anyhow::{bail, Result};
use serde::Serialize;
use std::collections::HashMap;

use super::{trace_id_filter, AnalyzeDb};

/// Lowest octave of the histograms: bucket 0 covers everything below
/// 2^HIST_BASE_LOG2 ns (256 ns).
pub const HIST_BASE_LOG2: u32 = 8;
/// Number of octaves in `hist_log2`: 2^8 ns .. 2^40 ns (~18 minutes); the
/// last bucket also takes everything larger.
pub const HIST_OCTAVES: usize = 32;
/// Sub-buckets per octave in the internal log-linear histogram.
const HIST_SUB_BITS: u32 = 4;
const HIST_SUB: usize = 1 << HIST_SUB_BITS;
/// Largest runqueue length tracked exactly by the time-weighted histogram;
/// longer queues are clamped into the last bucket.
const RQ_HIST_MAX: usize = 4096;

/// Parameters for [`AnalyzeDb::sched_aggregate`].
///
/// A window narrower than the trace keeps only the slices that lie entirely
/// inside it and the markers that fall inside it; a slice crossing the window
/// edge is dropped, so the CPU it ran on reads as unobserved (or idle) for
/// that stretch rather than being extrapolated.
#[derive(Debug, Clone)]
pub struct SchedAggregateParams {
    /// Restrict to one trace; required when the database holds several.
    pub trace_id: Option<String>,
    /// Window start, seconds from the first scheduler event (None = start).
    pub start_time: Option<f64>,
    /// Window end, seconds from the first scheduler event (None = end).
    pub end_time: Option<f64>,
    /// Number of tail-contributor threads to report per distribution.
    pub top_k: usize,
}

impl Default for SchedAggregateParams {
    fn default() -> Self {
        Self {
            trace_id: None,
            start_time: None,
            end_time: None,
            top_k: 10,
        }
    }
}

/// A value distribution: exact count/sum/min/max, histogram-derived
/// percentiles, and the per-octave histogram for merging.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Dist {
    pub count: u64,
    pub sum_ns: u64,
    pub avg_ns: f64,
    pub min_ns: u64,
    pub p50_ns: u64,
    pub p90_ns: u64,
    pub p99_ns: u64,
    pub max_ns: u64,
    /// Counts per octave; bucket i covers [2^(HIST_BASE_LOG2+i), 2^(HIST_BASE_LOG2+i+1)) ns.
    pub hist_log2: Vec<u64>,
}

/// Log-linear histogram over ns values: HIST_OCTAVES octaves × HIST_SUB
/// sub-buckets, plus exact count/sum/min/max.
#[derive(Debug, Clone)]
struct LogHist {
    counts: Vec<u64>,
    count: u64,
    sum: u64,
    min: u64,
    max: u64,
}

impl LogHist {
    fn new() -> Self {
        Self {
            counts: vec![0; HIST_OCTAVES * HIST_SUB],
            count: 0,
            sum: 0,
            min: u64::MAX,
            max: 0,
        }
    }

    /// Bucket index of a value: octave relative to HIST_BASE_LOG2, then the
    /// next HIST_SUB_BITS bits below the leading one.
    fn bucket(v: u64) -> usize {
        if v < (1u64 << HIST_BASE_LOG2) {
            return 0;
        }
        let log2 = 63 - v.leading_zeros();
        let octave = (log2 - HIST_BASE_LOG2) as usize;
        if octave >= HIST_OCTAVES {
            return HIST_OCTAVES * HIST_SUB - 1;
        }
        let sub = ((v >> (log2 - HIST_SUB_BITS)) & ((HIST_SUB as u64) - 1)) as usize;
        octave * HIST_SUB + sub
    }

    /// Upper edge (exclusive) of a bucket, reported as its value. Bucket 0
    /// also holds every value below 2^HIST_BASE_LOG2, so its edge is the end
    /// of the first sub-bucket of the first octave.
    fn bucket_upper(idx: usize) -> u64 {
        let octave = (idx / HIST_SUB) as u32 + HIST_BASE_LOG2;
        let sub = (idx % HIST_SUB) as u64;
        let base = 1u64 << octave;
        base + (sub + 1) * (base >> HIST_SUB_BITS)
    }

    fn record(&mut self, v: u64) {
        self.counts[Self::bucket(v)] += 1;
        self.count += 1;
        self.sum = self.sum.saturating_add(v);
        self.min = self.min.min(v);
        self.max = self.max.max(v);
    }

    /// Index of the bucket holding the p-th percentile (None when empty).
    fn percentile_bucket(&self, p: f64) -> Option<usize> {
        if self.count == 0 {
            return None;
        }
        let target = ((self.count as f64) * p).ceil().max(1.0) as u64;
        let mut seen = 0u64;
        for (i, c) in self.counts.iter().enumerate() {
            seen += c;
            if seen >= target {
                return Some(i);
            }
        }
        Some(self.counts.len() - 1)
    }

    fn percentile(&self, p: f64) -> u64 {
        match self.percentile_bucket(p) {
            // Never report above the exact maximum.
            Some(i) => Self::bucket_upper(i).min(self.max),
            None => 0,
        }
    }

    /// Count and approximate sum (bucket upper edges) of the values strictly
    /// above bucket `idx`.
    fn above_bucket(&self, idx: usize) -> (u64, u64) {
        let mut count = 0u64;
        let mut sum = 0u64;
        for (i, c) in self.counts.iter().enumerate().skip(idx + 1) {
            count += c;
            sum = sum.saturating_add(c.saturating_mul(Self::bucket_upper(i)));
        }
        (count, sum)
    }

    fn dist(&self) -> Dist {
        let mut hist_log2 = vec![0u64; HIST_OCTAVES];
        for (i, c) in self.counts.iter().enumerate() {
            hist_log2[i / HIST_SUB] += c;
        }
        Dist {
            count: self.count,
            sum_ns: self.sum,
            avg_ns: if self.count > 0 {
                self.sum as f64 / self.count as f64
            } else {
                0.0
            },
            min_ns: if self.count > 0 { self.min } else { 0 },
            p50_ns: self.percentile(0.50),
            p90_ns: self.percentile(0.90),
            p99_ns: self.percentile(0.99),
            max_ns: self.max,
            hist_log2,
        }
    }
}

/// Time-weighted distribution of runqueue length over (cpu × time).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RqDist {
    /// Total observed (cpu × time) in ns the distribution is over.
    pub observed_cpu_ns: u64,
    pub avg: f64,
    pub p50: u32,
    pub p90: u32,
    pub p99: u32,
    pub max: u32,
    /// Observed ns per runqueue length; index = length (last bucket clamps).
    pub hist: Vec<u64>,
}

/// Context-switch and migration counters for the window.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SwitchStats {
    pub switches: u64,
    pub switches_per_s: f64,
    pub voluntary: u64,
    pub involuntary: u64,
    pub migrations: u64,
    pub migrations_per_s: f64,
    pub wakeup_migrations: u64,
    pub preempt_migrations: u64,
}

/// Per-CPU vectors; index = CPU id. Unobserved CPUs carry zeros and are
/// listed in `unobserved_cpus`.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PerCpu {
    pub observed_ns: Vec<u64>,
    pub busy_ns: Vec<u64>,
    pub idle_ns: Vec<u64>,
    pub switches: Vec<u64>,
    pub wakeups_targeted: Vec<u64>,
    pub wakeups_ran: Vec<u64>,
    pub runnable_wait_ns: Vec<u64>,
    pub rq_avg: Vec<f64>,
    pub unobserved_cpus: Vec<u32>,
}

/// Imbalance metrics over the observed CPUs.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Imbalance {
    /// Busiest CPU's share of total busy time (1/ncpu = perfectly even, 1.0 = one CPU does everything).
    pub busy_max_share: f64,
    /// Coefficient of variation (stddev / mean) of per-CPU busy time.
    pub busy_cv: f64,
    pub wakeups_max_share: f64,
    pub wakeups_cv: f64,
    /// Time some observed CPU had runqueue length > 1 while another was idle.
    pub work_conservation_violation_ns: u64,
    /// The same as a fraction of the window.
    pub work_conservation_violation_frac: f64,
}

/// One thread name's contribution to a latency tail: its waits that fall
/// above the distribution's p99 bucket (`count` exact at bucket granularity,
/// `sum_ns` approximated by bucket upper edges).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct TailContributor {
    pub comm: String,
    pub count: u64,
    pub sum_ns: u64,
}

/// Event counts and sanity figures for the window.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SchedAggregateMeta {
    pub window_start_ns: i64,
    pub window_end_ns: i64,
    pub window_ns: u64,
    pub ncpu: u32,
    pub observed_cpus: u32,
    pub slices: u64,
    pub runnable_markers: u64,
    pub wakeup_new: u64,
    pub threads_seen: u64,
    /// Runnable markers whose thread never ran inside the window.
    pub wakeup_censored: u64,
    /// Preemptions whose thread never ran again inside the window.
    pub preempt_censored: u64,
    /// Runnable markers for a thread that was running or already runnable.
    pub spurious_wakeups: u64,
    /// Slice starts for a thread with no marker (first run in the window).
    pub first_runs: u64,
    /// Cumulative scheduler events the BPF side reported dropped (None = no counter track in the trace).
    pub missed_sched_events: Option<u64>,
    pub aggregate_ms: u64,
}

/// The per-capture scheduler summary.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SchedAggregate {
    pub meta: SchedAggregateMeta,
    pub wakeup_latency: Dist,
    pub wakeup_latency_same_cpu: Dist,
    pub wakeup_latency_cross_cpu: Dist,
    pub preempt_wait: Dist,
    pub run_delay: Dist,
    pub slice_len: Dist,
    pub switches: SwitchStats,
    pub runqueue: RqDist,
    pub per_cpu: PerCpu,
    pub imbalance: Imbalance,
    pub wakeup_tail_top: Vec<TailContributor>,
    pub preempt_tail_top: Vec<TailContributor>,
}

// Event kinds in the merged stream; ordered so that at one timestamp a slice
// end is handled before the slice that starts on the same CPU, then markers.
const EV_END: i32 = 0;
const EV_START: i32 = 1;
const EV_WAKING: i32 = 2;
const EV_NEW: i32 = 3;

#[derive(Debug, Clone, Copy, PartialEq)]
enum WaitKind {
    Wakeup,
    Preempt,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ThreadSt {
    Unknown,
    Running {
        cpu: u32,
    },
    Waiting {
        since: i64,
        cpu: u32,
        kind: WaitKind,
    },
    Sleeping,
}

#[derive(Debug, Clone, Copy)]
struct ThreadState {
    st: ThreadSt,
    last_cpu: Option<u32>,
    woke_since_last_run: bool,
}

#[derive(Debug, Clone, Default)]
struct CpuState {
    seen: bool,
    /// The non-idle thread on the CPU, if any (idle counts as nothing running).
    running: Option<i64>,
    waiting: u32,
    last_t: i64,
    rq_weight: u128,
    observed_ns: u64,
    busy_ns: u64,
    idle_ns: u64,
    switches: u64,
    wakeups_targeted: u64,
    wakeups_ran: u64,
    runnable_wait_ns: u64,
}

impl CpuState {
    fn rq(&self) -> u32 {
        self.waiting + u32::from(self.running.is_some())
    }
}

struct Pass {
    threads: HashMap<i64, ThreadState>,
    cpus: Vec<CpuState>,
    idle_utids: HashMap<i64, ()>,
    window_end: i64,
    // Node-wide runqueue bookkeeping.
    rq_hist: Vec<u64>,
    n_over: u32,
    n_idle: u32,
    n_observed: u32,
    last_global_t: Option<i64>,
    wcv_ns: u64,
    // Distributions.
    wakeup_lat: LogHist,
    wakeup_same: LogHist,
    wakeup_cross: LogHist,
    preempt_wait: LogHist,
    run_delay: LogHist,
    slice_len: LogHist,
    // Counters.
    slices: u64,
    markers: u64,
    new_tasks: u64,
    voluntary: u64,
    involuntary: u64,
    migrations: u64,
    wakeup_migrations: u64,
    preempt_migrations: u64,
    spurious_wakeups: u64,
    first_runs: u64,
    // Tail attribution: per-thread-name histograms of each wait kind, so the
    // threads above the p99 can be named without a second pass. Keyed by
    // comm (bounded by the distinct thread names in the window); empty when
    // attribution is disabled.
    names: HashMap<i64, String>,
    attribute_tails: bool,
    wakeup_by_comm: HashMap<String, LogHist>,
    preempt_by_comm: HashMap<String, LogHist>,
}

impl Pass {
    fn new(
        window_end: i64,
        idle_utids: HashMap<i64, ()>,
        names: HashMap<i64, String>,
        attribute_tails: bool,
    ) -> Self {
        Self {
            threads: HashMap::new(),
            cpus: Vec::new(),
            idle_utids,
            window_end,
            rq_hist: vec![0; RQ_HIST_MAX + 1],
            n_over: 0,
            n_idle: 0,
            n_observed: 0,
            last_global_t: None,
            wcv_ns: 0,
            wakeup_lat: LogHist::new(),
            wakeup_same: LogHist::new(),
            wakeup_cross: LogHist::new(),
            preempt_wait: LogHist::new(),
            run_delay: LogHist::new(),
            slice_len: LogHist::new(),
            slices: 0,
            markers: 0,
            new_tasks: 0,
            voluntary: 0,
            involuntary: 0,
            migrations: 0,
            wakeup_migrations: 0,
            preempt_migrations: 0,
            spurious_wakeups: 0,
            first_runs: 0,
            names,
            attribute_tails,
            wakeup_by_comm: HashMap::new(),
            preempt_by_comm: HashMap::new(),
        }
    }

    fn cpu_mut(&mut self, cpu: u32) -> &mut CpuState {
        let idx = cpu as usize;
        if self.cpus.len() <= idx {
            self.cpus.resize_with(idx + 1, CpuState::default);
        }
        &mut self.cpus[idx]
    }

    fn thread_mut(&mut self, utid: i64) -> &mut ThreadState {
        self.threads.entry(utid).or_insert(ThreadState {
            st: ThreadSt::Unknown,
            last_cpu: None,
            woke_since_last_run: false,
        })
    }

    /// Account the time since the last global event against the
    /// work-conservation state that held during it.
    fn advance_global(&mut self, t: i64) {
        if let Some(last) = self.last_global_t {
            if t > last && self.n_over > 0 && self.n_idle > 0 {
                self.wcv_ns += (t - last) as u64;
            }
        }
        self.last_global_t = Some(t);
    }

    /// Close the CPU's current runqueue-length interval at `t` (it is about
    /// to change) and mark the CPU observed from `t` on if it was not.
    fn touch_cpu(&mut self, cpu: u32, t: i64) {
        let c = self.cpu_mut(cpu);
        if !c.seen {
            c.seen = true;
            c.last_t = t;
            let rq = c.rq();
            // Enters the node-wide counts with its current (fresh) state.
            self.n_observed += 1;
            if rq == 0 {
                self.n_idle += 1;
            } else if rq > 1 {
                self.n_over += 1;
            }
            return;
        }
        let mut weighted = None;
        if t > c.last_t {
            let dt = (t - c.last_t) as u64;
            let rq = c.rq();
            c.rq_weight += (rq as u128) * (dt as u128);
            c.observed_ns += dt;
            weighted = Some((rq, dt));
        }
        c.last_t = t;
        if let Some((rq, dt)) = weighted {
            self.rq_hist[(rq as usize).min(RQ_HIST_MAX)] += dt;
        }
    }

    /// Apply a runqueue-length change on `cpu` and keep the node-wide
    /// over/idle counts in step.
    fn change_rq(&mut self, cpu: u32, t: i64, f: impl FnOnce(&mut CpuState)) {
        self.advance_global(t);
        self.touch_cpu(cpu, t);
        let c = self.cpu_mut(cpu);
        let before = c.rq();
        f(c);
        let after = c.rq();
        if before == after {
            return;
        }
        if before == 0 {
            self.n_idle -= 1;
        } else if before > 1 {
            self.n_over -= 1;
        }
        if after == 0 {
            self.n_idle += 1;
        } else if after > 1 {
            self.n_over += 1;
        }
    }

    fn record_wait(&mut self, utid: i64, kind: WaitKind, wait_ns: u64, same_cpu: bool) {
        self.run_delay.record(wait_ns);
        match kind {
            WaitKind::Wakeup => {
                self.wakeup_lat.record(wait_ns);
                if same_cpu {
                    self.wakeup_same.record(wait_ns);
                } else {
                    self.wakeup_cross.record(wait_ns);
                }
            }
            WaitKind::Preempt => self.preempt_wait.record(wait_ns),
        }
        if self.attribute_tails {
            let comm = self.names.get(&utid).cloned().unwrap_or_default();
            let by_comm = match kind {
                WaitKind::Wakeup => &mut self.wakeup_by_comm,
                WaitKind::Preempt => &mut self.preempt_by_comm,
            };
            by_comm
                .entry(comm)
                .or_insert_with(LogHist::new)
                .record(wait_ns);
        }
    }

    fn on_start(&mut self, t: i64, cpu: u32, utid: i64, dur: i64, end_state: Option<i32>) {
        let is_idle = self.idle_utids.contains_key(&utid);
        let th = *self.thread_mut(utid);

        if !is_idle {
            self.slices += 1;
            self.slice_len.record(dur.max(0) as u64);
            if end_state.is_some() {
                self.voluntary += 1;
            } else {
                self.involuntary += 1;
            }
            // Where was the thread waiting, if anywhere?
            match th.st {
                ThreadSt::Waiting {
                    since,
                    cpu: wc,
                    kind,
                } => {
                    let wait_ns = (t - since).max(0) as u64;
                    let same = wc == cpu;
                    self.record_wait(utid, kind, wait_ns, same);
                    self.change_rq(wc, t, |c| {
                        c.waiting = c.waiting.saturating_sub(1);
                        c.runnable_wait_ns += wait_ns;
                    });
                    if kind == WaitKind::Wakeup {
                        self.cpu_mut(cpu).wakeups_ran += 1;
                    }
                }
                ThreadSt::Running { cpu: rc } => {
                    // A start without the matching end (zero-length or
                    // overlapping slice); release the old CPU first.
                    self.change_rq(rc, t, |c| {
                        if c.running == Some(utid) {
                            c.running = None;
                        }
                    });
                }
                ThreadSt::Unknown | ThreadSt::Sleeping => {
                    if th.st == ThreadSt::Unknown {
                        self.first_runs += 1;
                    }
                }
            }
            if let Some(pc) = th.last_cpu {
                if pc != cpu {
                    self.migrations += 1;
                    if th.woke_since_last_run {
                        self.wakeup_migrations += 1;
                    } else {
                        self.preempt_migrations += 1;
                    }
                }
            }
            self.change_rq(cpu, t, |c| {
                c.running = Some(utid);
                c.switches += 1;
                c.busy_ns += dur.max(0) as u64;
            });
        } else {
            // Idle slice: the CPU runs nothing; its queue is whatever waits.
            self.change_rq(cpu, t, |c| {
                c.running = None;
                c.idle_ns += dur.max(0) as u64;
            });
        }

        let th = self.thread_mut(utid);
        th.st = ThreadSt::Running { cpu };
        th.last_cpu = Some(cpu);
        th.woke_since_last_run = false;
    }

    fn on_end(&mut self, t: i64, cpu: u32, utid: i64, end_state: Option<i32>) {
        let is_idle = self.idle_utids.contains_key(&utid);
        let th = *self.thread_mut(utid);
        if th.st != (ThreadSt::Running { cpu }) {
            // End of a slice we never saw start on this CPU (window edge or
            // an overlapping record): nothing to release.
            return;
        }
        if is_idle {
            self.thread_mut(utid).st = ThreadSt::Sleeping;
            return;
        }
        let preempted = end_state.is_none();
        self.change_rq(cpu, t, |c| {
            if c.running == Some(utid) {
                c.running = None;
            }
            if preempted {
                c.waiting += 1;
            }
        });
        let th = self.thread_mut(utid);
        th.st = if preempted {
            ThreadSt::Waiting {
                since: t,
                cpu,
                kind: WaitKind::Preempt,
            }
        } else {
            ThreadSt::Sleeping
        };
    }

    fn on_runnable(&mut self, t: i64, target_cpu: u32, utid: i64, new_task: bool) {
        if new_task {
            self.new_tasks += 1;
        } else {
            self.markers += 1;
        }
        if self.idle_utids.contains_key(&utid) {
            return;
        }
        let th = *self.thread_mut(utid);
        match th.st {
            ThreadSt::Running { .. } | ThreadSt::Waiting { .. } => {
                self.spurious_wakeups += 1;
                self.thread_mut(utid).woke_since_last_run = true;
            }
            ThreadSt::Unknown | ThreadSt::Sleeping => {
                self.change_rq(target_cpu, t, |c| {
                    c.waiting += 1;
                    c.wakeups_targeted += 1;
                });
                let th = self.thread_mut(utid);
                th.st = ThreadSt::Waiting {
                    since: t,
                    cpu: target_cpu,
                    kind: WaitKind::Wakeup,
                };
                th.woke_since_last_run = true;
            }
        }
    }

    fn handle(
        &mut self,
        ts: i64,
        kind: i32,
        cpu: u32,
        utid: i64,
        dur: i64,
        end_state: Option<i32>,
    ) {
        match kind {
            EV_END => self.on_end(ts, cpu, utid, end_state),
            EV_START => self.on_start(ts, cpu, utid, dur, end_state),
            EV_WAKING => self.on_runnable(ts, cpu, utid, false),
            EV_NEW => self.on_runnable(ts, cpu, utid, true),
            _ => {}
        }
    }

    /// Close every observed CPU's last interval at the window end and count
    /// the waits that never ended.
    fn finish(&mut self) -> (u64, u64) {
        let end = self.window_end;
        self.advance_global(end);
        for cpu in 0..self.cpus.len() {
            if self.cpus[cpu].seen {
                self.touch_cpu(cpu as u32, end);
            }
        }
        let mut wakeup_censored = 0;
        let mut preempt_censored = 0;
        for th in self.threads.values() {
            if let ThreadSt::Waiting { kind, .. } = th.st {
                match kind {
                    WaitKind::Wakeup => wakeup_censored += 1,
                    WaitKind::Preempt => preempt_censored += 1,
                }
            }
        }
        (wakeup_censored, preempt_censored)
    }
}

fn share_and_cv(values: &[u64]) -> (f64, f64) {
    let n = values.len();
    if n == 0 {
        return (0.0, 0.0);
    }
    let sum: f64 = values.iter().map(|&v| v as f64).sum();
    if sum <= 0.0 {
        return (0.0, 0.0);
    }
    let max = values.iter().copied().max().unwrap_or(0) as f64;
    let mean = sum / n as f64;
    let var = values
        .iter()
        .map(|&v| {
            let d = v as f64 - mean;
            d * d
        })
        .sum::<f64>()
        / n as f64;
    (max / sum, var.sqrt() / mean)
}

/// The thread names with the most waits above the distribution's p99
/// bucket: count is exact at bucket granularity, `sum_ns` approximates each
/// value by its bucket's upper edge.
fn top_contributors(
    overall: &LogHist,
    by_comm: &HashMap<String, LogHist>,
    k: usize,
) -> Vec<TailContributor> {
    let Some(p99_bucket) = overall.percentile_bucket(0.99) else {
        return Vec::new();
    };
    let mut v: Vec<TailContributor> = by_comm
        .iter()
        .filter_map(|(comm, h)| {
            let (count, sum_ns) = h.above_bucket(p99_bucket);
            (count > 0).then(|| TailContributor {
                comm: comm.clone(),
                count,
                sum_ns,
            })
        })
        .collect();
    v.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then(b.sum_ns.cmp(&a.sum_ns))
            .then(a.comm.cmp(&b.comm))
    });
    v.truncate(k);
    v
}

fn build_event_stream_query(trace_id: Option<&str>, start: i64, end: i64) -> String {
    let f_ss = trace_id_filter(trace_id, "ss.");
    let f_ts = trace_id_filter(trace_id, "t.");
    let f_w = trace_id_filter(trace_id, "w.");
    format!(
        "SELECT ts, kind, cpu, utid, dur, end_state FROM ( \
           SELECT ss.ts AS ts, {EV_START} AS kind, ss.cpu AS cpu, ss.utid AS utid, ss.dur AS dur, ss.end_state AS end_state \
             FROM sched_slice ss WHERE ss.dur > 0 AND ss.ts >= {start} AND ss.ts + ss.dur <= {end}{f_ss} \
           UNION ALL \
           SELECT ss.ts + ss.dur, {EV_END}, ss.cpu, ss.utid, ss.dur, ss.end_state \
             FROM sched_slice ss WHERE ss.dur > 0 AND ss.ts >= {start} AND ss.ts + ss.dur <= {end}{f_ss} \
           UNION ALL \
           SELECT t.ts, {EV_WAKING}, t.cpu, t.utid, CAST(0 AS BIGINT), CAST(NULL AS INTEGER) \
             FROM thread_state t WHERE t.state = 0 AND t.cpu IS NOT NULL AND t.ts >= {start} AND t.ts <= {end}{f_ts} \
           UNION ALL \
           SELECT w.ts, {EV_NEW}, w.target_cpu, w.utid, CAST(0 AS BIGINT), CAST(NULL AS INTEGER) \
             FROM wakeup_new w WHERE w.ts >= {start} AND w.ts <= {end}{f_w} \
         ) ORDER BY ts, kind"
    )
}

fn build_window_query(trace_id: Option<&str>) -> String {
    let f_ss = trace_id_filter(trace_id, "ss.");
    let f_ts = trace_id_filter(trace_id, "t.");
    format!(
        "SELECT MIN(lo), MAX(hi) FROM ( \
           SELECT MIN(ss.ts) AS lo, MAX(ss.ts + ss.dur) AS hi FROM sched_slice ss WHERE ss.dur > 0{f_ss} \
           UNION ALL \
           SELECT MIN(t.ts), MAX(t.ts) FROM thread_state t WHERE t.state = 0{f_ts} \
         )"
    )
}

impl AnalyzeDb {
    /// Compute the per-capture scheduler aggregates; see the module docs for
    /// every definition.
    pub fn sched_aggregate(&self, params: &SchedAggregateParams) -> Result<SchedAggregate> {
        let started = std::time::Instant::now();
        if !self.table_exists("sched_slice")? || !self.table_exists("thread_state")? {
            bail!(
                "Database missing sched_slice/thread_state tables. \
                 Record with the sched recorder enabled."
            );
        }
        if !self.table_has_rows("sched_slice")? {
            bail!("No scheduling events found in database.");
        }

        let trace_id = match &params.trace_id {
            Some(t) => Some(t.clone()),
            None => {
                let mut stmt = self
                    .conn
                    .prepare("SELECT DISTINCT trace_id FROM sched_slice ORDER BY trace_id")?;
                let ids: Vec<String> = stmt
                    .query_map([], |r| r.get::<_, String>(0))?
                    .collect::<std::result::Result<_, _>>()?;
                if ids.len() > 1 {
                    bail!(
                        "Database holds {} traces; pass --trace-id to pick one.",
                        ids.len()
                    );
                }
                ids.into_iter().next()
            }
        };
        let trace_id = trace_id.as_deref();

        // Window.
        let (lo, hi): (i64, i64) = {
            let sql = build_window_query(trace_id);
            let mut stmt = self.conn.prepare(&sql)?;
            let mut rows = stmt.query([])?;
            match rows.next()? {
                Some(r) => (
                    r.get::<_, Option<i64>>(0)?.unwrap_or(0),
                    r.get::<_, Option<i64>>(1)?.unwrap_or(0),
                ),
                None => (0, 0),
            }
        };
        let window_start = params
            .start_time
            .map(|s| lo + (s * 1e9) as i64)
            .unwrap_or(lo);
        let window_end = params.end_time.map(|s| lo + (s * 1e9) as i64).unwrap_or(hi);
        if window_end <= window_start {
            bail!("Empty analysis window.");
        }

        // Thread names and the idle (swapper) threads.
        let mut names: HashMap<i64, String> = HashMap::new();
        let mut idle: HashMap<i64, ()> = HashMap::new();
        let mut ncpu_from_info: u32 = 0;
        if self.table_exists("thread")? {
            let f = trace_id_filter(trace_id, "th.");
            let sql = format!(
                "SELECT th.utid, th.tid, COALESCE(th.name, '') FROM thread th WHERE 1=1{f}"
            );
            let mut stmt = self.conn.prepare(&sql)?;
            let mut rows = stmt.query([])?;
            while let Some(r) = rows.next()? {
                let utid: i64 = r.get(0)?;
                let tid: i32 = r.get(1)?;
                let name: String = r.get(2)?;
                if tid == 0 {
                    idle.insert(utid, ());
                }
                names.insert(utid, name);
            }
        }
        if self.table_exists("cpu_info")? {
            let f = trace_id_filter(trace_id, "ci.");
            let sql = format!("SELECT COUNT(*) FROM cpu_info ci WHERE 1=1{f}");
            let mut stmt = self.conn.prepare(&sql)?;
            let mut rows = stmt.query([])?;
            if let Some(r) = rows.next()? {
                ncpu_from_info = r.get::<_, i64>(0)?.max(0) as u32;
            }
        }

        let stream_sql = build_event_stream_query(trace_id, window_start, window_end);
        let mut pass = Pass::new(window_end, idle, names, params.top_k > 0);
        {
            let mut stmt = self.conn.prepare(&stream_sql)?;
            let mut rows = stmt.query([])?;
            while let Some(r) = rows.next()? {
                let ts: i64 = r.get(0)?;
                let kind: i32 = r.get(1)?;
                let cpu: i32 = r.get(2)?;
                let utid: i64 = r.get(3)?;
                let dur: i64 = r.get(4)?;
                let end_state: Option<i32> = r.get(5)?;
                if cpu < 0 {
                    continue;
                }
                pass.handle(ts, kind, cpu as u32, utid, dur, end_state);
            }
        }
        let (wakeup_censored, preempt_censored) = pass.finish();

        let (wakeup_tail_top, preempt_tail_top) = if params.top_k > 0 {
            (
                top_contributors(&pass.wakeup_lat, &pass.wakeup_by_comm, params.top_k),
                top_contributors(&pass.preempt_wait, &pass.preempt_by_comm, params.top_k),
            )
        } else {
            (Vec::new(), Vec::new())
        };

        let missed_sched_events = self.missed_sched_events(trace_id)?;

        // Assemble.
        let window_ns = (window_end - window_start) as u64;
        let window_s = window_ns as f64 / 1e9;
        let ncpu = (pass.cpus.len() as u32).max(ncpu_from_info);
        let n = ncpu as usize;
        let mut per_cpu = PerCpu {
            observed_ns: vec![0; n],
            busy_ns: vec![0; n],
            idle_ns: vec![0; n],
            switches: vec![0; n],
            wakeups_targeted: vec![0; n],
            wakeups_ran: vec![0; n],
            runnable_wait_ns: vec![0; n],
            rq_avg: vec![0.0; n],
            unobserved_cpus: Vec::new(),
        };
        let mut observed_busy = Vec::new();
        let mut observed_wakeups = Vec::new();
        for i in 0..n {
            match pass.cpus.get(i) {
                Some(c) if c.seen => {
                    per_cpu.observed_ns[i] = c.observed_ns;
                    per_cpu.busy_ns[i] = c.busy_ns;
                    per_cpu.idle_ns[i] = c.idle_ns;
                    per_cpu.switches[i] = c.switches;
                    per_cpu.wakeups_targeted[i] = c.wakeups_targeted;
                    per_cpu.wakeups_ran[i] = c.wakeups_ran;
                    per_cpu.runnable_wait_ns[i] = c.runnable_wait_ns;
                    per_cpu.rq_avg[i] = if c.observed_ns > 0 {
                        c.rq_weight as f64 / c.observed_ns as f64
                    } else {
                        0.0
                    };
                    observed_busy.push(c.busy_ns);
                    observed_wakeups.push(c.wakeups_targeted);
                }
                _ => per_cpu.unobserved_cpus.push(i as u32),
            }
        }
        let (busy_max_share, busy_cv) = share_and_cv(&observed_busy);
        let (wakeups_max_share, wakeups_cv) = share_and_cv(&observed_wakeups);

        let observed_cpu_ns: u64 = pass.rq_hist.iter().sum();
        let rq_weighted: u128 = pass
            .rq_hist
            .iter()
            .enumerate()
            .map(|(len, ns)| (len as u128) * (*ns as u128))
            .sum();
        let rq_pct = |p: f64| -> u32 {
            if observed_cpu_ns == 0 {
                return 0;
            }
            let target = ((observed_cpu_ns as f64) * p).ceil().max(1.0) as u64;
            let mut seen = 0u64;
            for (len, ns) in pass.rq_hist.iter().enumerate() {
                seen += ns;
                if seen >= target {
                    return len as u32;
                }
            }
            RQ_HIST_MAX as u32
        };
        let rq_max = pass
            .rq_hist
            .iter()
            .enumerate()
            .filter(|(_, ns)| **ns > 0)
            .map(|(len, _)| len as u32)
            .max()
            .unwrap_or(0);
        let mut rq_hist = pass.rq_hist.clone();
        while rq_hist.len() > 1 && *rq_hist.last().unwrap() == 0 {
            rq_hist.pop();
        }
        let runqueue = RqDist {
            observed_cpu_ns,
            avg: if observed_cpu_ns > 0 {
                rq_weighted as f64 / observed_cpu_ns as f64
            } else {
                0.0
            },
            p50: rq_pct(0.50),
            p90: rq_pct(0.90),
            p99: rq_pct(0.99),
            max: rq_max,
            hist: rq_hist,
        };

        let switches = SwitchStats {
            switches: pass.slices,
            switches_per_s: pass.slices as f64 / window_s,
            voluntary: pass.voluntary,
            involuntary: pass.involuntary,
            migrations: pass.migrations,
            migrations_per_s: pass.migrations as f64 / window_s,
            wakeup_migrations: pass.wakeup_migrations,
            preempt_migrations: pass.preempt_migrations,
        };

        Ok(SchedAggregate {
            meta: SchedAggregateMeta {
                window_start_ns: window_start,
                window_end_ns: window_end,
                window_ns,
                ncpu,
                observed_cpus: pass.n_observed,
                slices: pass.slices,
                runnable_markers: pass.markers,
                wakeup_new: pass.new_tasks,
                threads_seen: pass.threads.len() as u64,
                wakeup_censored,
                preempt_censored,
                spurious_wakeups: pass.spurious_wakeups,
                first_runs: pass.first_runs,
                missed_sched_events,
                aggregate_ms: started.elapsed().as_millis() as u64,
            },
            wakeup_latency: pass.wakeup_lat.dist(),
            wakeup_latency_same_cpu: pass.wakeup_same.dist(),
            wakeup_latency_cross_cpu: pass.wakeup_cross.dist(),
            preempt_wait: pass.preempt_wait.dist(),
            run_delay: pass.run_delay.dist(),
            slice_len: pass.slice_len.dist(),
            switches,
            runqueue,
            per_cpu,
            imbalance: Imbalance {
                busy_max_share,
                busy_cv,
                wakeups_max_share,
                wakeups_cv,
                work_conservation_violation_ns: pass.wcv_ns,
                work_conservation_violation_frac: if window_ns > 0 {
                    pass.wcv_ns as f64 / window_ns as f64
                } else {
                    0.0
                },
            },
            wakeup_tail_top,
            preempt_tail_top,
        })
    }

    /// The final value of the "Missed sched/IRQ events" counter track, if the
    /// trace carries one (the recorder writes the cumulative BPF drop count
    /// per missed-event class as a counter; the track name is
    /// `MISSED_EVENT_CLASS_LABELS` class 0 under the recorder's
    /// "Missed {} events" naming).
    fn missed_sched_events(&self, trace_id: Option<&str>) -> Result<Option<u64>> {
        if !self.table_exists("counter_track")? || !self.table_exists("counter")? {
            return Ok(None);
        }
        let f_ct = trace_id_filter(trace_id, "ct.");
        let sql = format!(
            "SELECT MAX(c.value) FROM counter c \
             JOIN counter_track ct ON c.track_id = ct.id AND c.trace_id = ct.trace_id \
             WHERE ct.name = 'Missed sched/IRQ events'{f_ct}"
        );
        let mut stmt = match self.conn.prepare(&sql) {
            Ok(s) => s,
            Err(_) => return Ok(None),
        };
        let mut rows = match stmt.query([]) {
            Ok(r) => r,
            Err(_) => return Ok(None),
        };
        match rows.next()? {
            Some(r) => Ok(r.get::<_, Option<f64>>(0)?.map(|v| v.max(0.0) as u64)),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use duckdb::Connection;
    use std::path::PathBuf;

    fn db_with(
        slices: &[(i64, i64, i32, i64, Option<i32>)],
        markers: &[(i64, i64, i32)],
        threads: &[(i64, i32, &str)],
    ) -> AnalyzeDb {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE sched_slice (trace_id VARCHAR, ts BIGINT, dur BIGINT, cpu INTEGER, utid BIGINT, end_state INTEGER, priority INTEGER); \
             CREATE TABLE thread_state (trace_id VARCHAR, ts BIGINT, dur BIGINT, utid BIGINT, state INTEGER, cpu INTEGER); \
             CREATE TABLE wakeup_new (trace_id VARCHAR, ts BIGINT, cpu INTEGER, utid BIGINT, target_cpu INTEGER); \
             CREATE TABLE thread (trace_id VARCHAR, utid BIGINT, tid INTEGER, name VARCHAR, upid BIGINT);",
        )
        .unwrap();
        for (ts, dur, cpu, utid, end_state) in slices {
            conn.execute(
                "INSERT INTO sched_slice VALUES ('t', ?, ?, ?, ?, ?, 120)",
                duckdb::params![ts, dur, cpu, utid, end_state],
            )
            .unwrap();
        }
        for (ts, utid, cpu) in markers {
            conn.execute(
                "INSERT INTO thread_state VALUES ('t', ?, 0, ?, 0, ?)",
                duckdb::params![ts, utid, cpu],
            )
            .unwrap();
        }
        for (utid, tid, name) in threads {
            conn.execute(
                "INSERT INTO thread VALUES ('t', ?, ?, ?, NULL)",
                duckdb::params![utid, tid, name],
            )
            .unwrap();
        }
        AnalyzeDb {
            conn,
            path: PathBuf::new(),
        }
    }

    const IDLE: i64 = 0;
    const A: i64 = 1;
    const B: i64 = 2;

    fn threads() -> Vec<(i64, i32, &'static str)> {
        vec![
            (IDLE, 0, "swapper/0"),
            (A, 101, "worker-a"),
            (B, 102, "worker-b"),
        ]
    }

    #[test]
    fn log_hist_buckets_and_percentiles() {
        let mut h = LogHist::new();
        for v in [100u64, 300, 1_000, 1_000, 10_000, 1_000_000] {
            h.record(v);
        }
        let d = h.dist();
        assert_eq!(d.count, 6);
        assert_eq!(d.min_ns, 100);
        assert_eq!(d.max_ns, 1_000_000);
        // Percentiles report a bucket's upper edge, within one sub-bucket
        // (1/16 of an octave) above the exact value, never above the max.
        assert!(
            d.p50_ns >= 1_000 && d.p50_ns <= 1_000 + 1_000 / 8,
            "p50 {}",
            d.p50_ns
        );
        assert!(
            d.p99_ns >= 1_000_000 - 1 && d.p99_ns <= 1_000_000,
            "p99 {}",
            d.p99_ns
        );
        // The octave histogram sums to the count; bucket 0 holds both the
        // sub-256 ns value and the one in [256, 512).
        assert_eq!(d.hist_log2.iter().sum::<u64>(), 6);
        assert_eq!(d.hist_log2[0], 2);
        // The two 1000 ns values sit in the [512, 1024) octave = bucket 1.
        assert_eq!(d.hist_log2[1], 2);
        assert_eq!(d.hist_log2.len(), HIST_OCTAVES);
    }

    #[test]
    fn log_hist_bucket_edges_are_monotonic() {
        let mut last = 0;
        for i in 0..HIST_OCTAVES * HIST_SUB {
            let up = LogHist::bucket_upper(i);
            assert!(up > last, "bucket {i}: {up} <= {last}");
            // Every value inside the bucket maps back to it.
            assert_eq!(LogHist::bucket(up - 1), i, "value {} bucket", up - 1);
            if i > 0 {
                assert_eq!(LogHist::bucket(last), i, "value {last} bucket");
            }
            last = up;
        }
        // Sub-256 ns values share bucket 0 with [256, 272).
        assert_eq!(LogHist::bucket(0), 0);
        assert_eq!(LogHist::bucket(255), 0);
        assert_eq!(LogHist::bucket(256), 0);
        assert_eq!(LogHist::bucket(272), 1);
    }

    #[test]
    fn wakeup_latency_same_cpu() {
        // A wakes at 1000 targeting cpu 0, runs on cpu 0 from 1500 for 500 ns,
        // then sleeps (end_state 1). Idle fills the rest of cpu 0.
        let db = db_with(
            &[
                (0, 1500, 0, IDLE, None),
                (1500, 500, 0, A, Some(1)),
                (2000, 1000, 0, IDLE, None),
            ],
            &[(1000, A, 0)],
            &threads(),
        );
        let r = db
            .sched_aggregate(&SchedAggregateParams::default())
            .unwrap();
        assert_eq!(r.wakeup_latency.count, 1);
        assert_eq!(r.wakeup_latency.sum_ns, 500);
        assert_eq!(r.wakeup_latency_same_cpu.count, 1);
        assert_eq!(r.wakeup_latency_cross_cpu.count, 0);
        assert_eq!(r.run_delay.count, 1);
        assert_eq!(r.slice_len.count, 1);
        assert_eq!(r.slice_len.sum_ns, 500);
        assert_eq!(r.switches.switches, 1);
        assert_eq!(r.switches.voluntary, 1);
        assert_eq!(r.switches.involuntary, 0);
        assert_eq!(r.meta.wakeup_censored, 0);
        assert_eq!(r.per_cpu.busy_ns[0], 500);
        assert_eq!(r.per_cpu.idle_ns[0], 2500);
        assert_eq!(r.per_cpu.wakeups_targeted[0], 1);
        assert_eq!(r.per_cpu.wakeups_ran[0], 1);
        assert_eq!(r.per_cpu.runnable_wait_ns[0], 500);
        assert_eq!(r.meta.window_ns, 3000);
        // Runqueue over cpu 0 time: 0 for [0,1000), 1 for [1000,2000) (waiting then running), 0 after.
        assert_eq!(r.runqueue.observed_cpu_ns, 3000);
        assert!(
            (r.runqueue.avg - 1000.0 / 3000.0).abs() < 1e-9,
            "avg {}",
            r.runqueue.avg
        );
        assert_eq!(r.runqueue.max, 1);
        assert_eq!(r.imbalance.work_conservation_violation_ns, 0);
    }

    #[test]
    fn wakeup_cross_cpu_migration_and_preempt_wait() {
        // B wakes targeting cpu 1 at 100 but runs on cpu 0 at 600 (cross-CPU
        // placement). It is preempted at 1600 (end_state NULL), waits, then
        // runs again on cpu 1 from 2600 (a preempt migration), and sleeps.
        let db = db_with(
            &[
                (0, 600, 0, IDLE, None),
                (600, 1000, 0, B, None),
                (1600, 2000, 0, IDLE, None),
                (0, 2600, 1, IDLE, None),
                (2600, 400, 1, B, Some(2)),
                (3000, 600, 1, IDLE, None),
            ],
            &[(100, B, 1)],
            &threads(),
        );
        let r = db
            .sched_aggregate(&SchedAggregateParams::default())
            .unwrap();
        assert_eq!(r.wakeup_latency.count, 1);
        assert_eq!(r.wakeup_latency.sum_ns, 500);
        assert_eq!(r.wakeup_latency_cross_cpu.count, 1);
        assert_eq!(r.wakeup_latency_same_cpu.count, 0);
        assert_eq!(r.preempt_wait.count, 1);
        assert_eq!(r.preempt_wait.sum_ns, 1000);
        assert_eq!(r.run_delay.count, 2);
        assert_eq!(r.run_delay.sum_ns, 1500);
        assert_eq!(r.switches.switches, 2);
        assert_eq!(r.switches.involuntary, 1);
        assert_eq!(r.switches.voluntary, 1);
        assert_eq!(r.switches.migrations, 1);
        assert_eq!(r.switches.preempt_migrations, 1);
        assert_eq!(r.switches.wakeup_migrations, 0);
        // The wakeup wait was assigned to the target cpu 1, the preempt wait to cpu 0.
        assert_eq!(r.per_cpu.runnable_wait_ns[1], 500);
        assert_eq!(r.per_cpu.runnable_wait_ns[0], 1000);
        assert_eq!(r.per_cpu.wakeups_targeted[1], 1);
        assert_eq!(r.per_cpu.wakeups_ran[0], 1);
        // Work-conservation violation: B waits on cpu 0's queue [1600,2600)
        // while cpu 1 is idle — but cpu 0 itself is idle during that wait, so
        // its rq is 1 (not >1): no violation. During [100,600) cpu 1 has
        // rq 1 (B waiting) and cpu 0 is idle: rq 1 is not >1 either.
        assert_eq!(r.imbalance.work_conservation_violation_ns, 0);
    }

    #[test]
    fn work_conservation_violation_and_imbalance() {
        // cpu 0 runs A and has B waiting behind it (rq 2) for [1000,2000)
        // while cpu 1 sits idle the whole window: 1000 ns of violation, and
        // all busy time on cpu 0.
        let db = db_with(
            &[
                (0, 1000, 0, IDLE, None),
                (1000, 1000, 0, A, Some(1)),
                (2000, 500, 0, B, Some(1)),
                (2500, 500, 0, IDLE, None),
                (0, 3000, 1, IDLE, None),
            ],
            &[(500, A, 0), (1000, B, 0)],
            &threads(),
        );
        let r = db
            .sched_aggregate(&SchedAggregateParams::default())
            .unwrap();
        assert_eq!(r.imbalance.work_conservation_violation_ns, 1000);
        assert!((r.imbalance.work_conservation_violation_frac - 1000.0 / 3000.0).abs() < 1e-9);
        assert_eq!(r.imbalance.busy_max_share, 1.0);
        assert!(r.imbalance.busy_cv > 0.99, "cv {}", r.imbalance.busy_cv);
        assert_eq!(r.runqueue.max, 2);
        assert_eq!(r.meta.observed_cpus, 2);
        assert_eq!(r.per_cpu.unobserved_cpus, Vec::<u32>::new());
        // B's wakeup latency is 1000 (waiting behind A), A's is 500.
        assert_eq!(r.wakeup_latency.count, 2);
        assert_eq!(r.wakeup_latency.sum_ns, 1500);
        assert_eq!(r.wakeup_latency.max_ns, 1000);
    }

    #[test]
    fn censored_wakeup_and_first_run_are_counted_not_measured() {
        // A runs from the window start with no marker (first run); B is woken
        // but never runs inside the window (censored).
        let db = db_with(
            &[(0, 1000, 0, A, Some(1)), (1000, 1000, 0, IDLE, None)],
            &[(1500, B, 0)],
            &threads(),
        );
        let r = db
            .sched_aggregate(&SchedAggregateParams::default())
            .unwrap();
        assert_eq!(r.wakeup_latency.count, 0);
        assert_eq!(r.meta.wakeup_censored, 1);
        assert_eq!(r.meta.first_runs, 1);
        assert_eq!(r.switches.switches, 1);
    }

    #[test]
    fn tail_contributors_name_the_threads_above_p99() {
        // Many fast wakeups of A and one slow wakeup of B; B must top the tail.
        let mut slices = Vec::new();
        let mut markers = Vec::new();
        let mut t = 0i64;
        for _ in 0..200 {
            markers.push((t, A, 0));
            slices.push((t + 100, 100, 0, A, Some(1)));
            t += 1000;
        }
        markers.push((t, B, 0));
        slices.push((t + 50_000, 100, 0, B, Some(1)));
        let db = db_with(&slices, &markers, &threads());
        let r = db
            .sched_aggregate(&SchedAggregateParams::default())
            .unwrap();
        assert_eq!(r.wakeup_latency.count, 201);
        assert_eq!(r.wakeup_tail_top.len(), 1);
        assert_eq!(r.wakeup_tail_top[0].comm, "worker-b");
        assert_eq!(r.wakeup_tail_top[0].count, 1);
        // The sum is approximated by the bucket's upper edge (within ~6%).
        assert!(
            r.wakeup_tail_top[0].sum_ns >= 50_000 && r.wakeup_tail_top[0].sum_ns <= 53_200,
            "sum {}",
            r.wakeup_tail_top[0].sum_ns
        );
    }

    #[test]
    fn multi_trace_db_requires_trace_id() {
        let db = db_with(&[(0, 100, 0, A, Some(1))], &[], &threads());
        db.conn
            .execute(
                "INSERT INTO sched_slice VALUES ('u', 0, 100, 0, 1, 1, 120)",
                [],
            )
            .unwrap();
        let err = db
            .sched_aggregate(&SchedAggregateParams::default())
            .unwrap_err();
        assert!(err.to_string().contains("trace-id"), "{err}");
        let ok = db.sched_aggregate(&SchedAggregateParams {
            trace_id: Some("t".into()),
            ..Default::default()
        });
        assert!(ok.is_ok());
    }

    #[test]
    fn event_stream_query_shape() {
        let sql = build_event_stream_query(Some("x"), 10, 20);
        assert!(sql.contains("FROM sched_slice ss"));
        assert!(sql.contains("FROM thread_state t WHERE t.state = 0"));
        assert!(sql.contains("FROM wakeup_new w"));
        assert!(sql.contains("ORDER BY ts, kind"));
        assert!(sql.contains("ss.trace_id = 'x'"));
    }
}
