use std::collections::HashMap;
use std::ffi::CStr;
use std::fmt;

use crate::cmds::profile::systing;
use chrono::{DateTime, Local};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

fn pid_comm(pid: u32) -> String {
    let path = format!("/proc/{}/comm", pid);
    let comm = std::fs::read_to_string(path);
    if comm.is_err() {
        return "<unknown>".to_string();
    }
    comm.unwrap().trim().to_string()
}

#[derive(EnumIter, Debug)]
pub enum ProcessStat {
    RunTime,
    SleepTime,
    WaitTime,
    PreemptTime,
    QueueTime,
    IrqTime,
    SoftirqTime,
    WakingTime,
}

#[derive(EnumIter, Debug)]
pub enum TotalProcessStat {
    TotalRunTime,
    TotalSleepTime,
    TotalWaitTime,
    TotalPreemptTime,
    TotalQueueTime,
    TotalIrqTime,
    TotalSoftirqTime,
    TotalWakingTime,
}

#[derive(Debug, Clone)]
pub struct PreemptEvent {
    pub preempt_pid: u32,
    pub preempt_tgid: u32,
    pub cgid: u64,
    pub comm: String,
    pub count: u64,
}

#[derive(Debug, Clone)]
pub struct RunStats {
    pub start_time: DateTime<Local>,
    pub preempt_events: Vec<PreemptEvent>,
    pub stat: systing::types::task_stat,
    total_runtime: u64,
    total_sleep_time: u64,
    total_wait_time: u64,
    total_preempt_time: u64,
    total_queue_time: u64,
    total_irq_time: u64,
    total_softirq_time: u64,
    total_waking_time: u64,
    time: u64,
    potential_runtime: u64,
    total_time: u64,
    total_potential_runtime: u64,
}

#[derive(Debug, Clone)]
pub struct Process {
    pub pid: u32,
    pub comm: String,
    pub cgid: u64,
    pub threads: HashMap<u32, Process>,
    pub runs: Vec<RunStats>,
    total_potential_runtime: u64,
}

impl Process {
    pub fn new(pid: u32) -> Self {
        Process {
            pid,
            comm: String::new(),
            cgid: 0,
            runs: Vec::new(),
            threads: HashMap::new(),
            total_potential_runtime: 0,
        }
    }

    pub fn sort_runs(&mut self) {
        self.runs.sort_by(|a, b| a.start_time.cmp(&b.start_time));
        for (_, thread) in self.threads.iter_mut() {
            thread.sort_runs();
        }
    }

    pub fn sorted_threads(&self) -> Vec<Process> {
        let mut threads = Vec::new();
        for (_, thread) in self.threads.iter() {
            threads.push(thread.clone());
        }
        threads.sort_by(|a, b| {
            let a_total = a.total_potential_runtime();
            let b_total = b.total_potential_runtime();
            b_total.cmp(&a_total)
        });
        threads
    }

    pub fn sort_preempt_events(&mut self) {
        for run in self.runs.iter_mut() {
            run.sort_preempt_events();
        }
        for (_, thread) in self.threads.iter_mut() {
            thread.sort_preempt_events();
        }
    }

    pub fn total_potential_runtime(&self) -> u64 {
        match self.total_potential_runtime {
            0 => 1,
            _ => self.total_potential_runtime,
        }
    }

    pub fn print_summary(&self) {
        println!(
            "{} pid {} cgid {} threads {}",
            self.comm,
            self.pid,
            self.cgid,
            self.threads.len()
        );
        for r in self.runs.iter() {
            let mut pevents = Vec::new();
            let threads = self.sorted_threads();
            for thread in threads.iter() {
                for run in thread.runs.iter() {
                    if run.start_time == r.start_time {
                        pevents.extend(&run.preempt_events);
                        break;
                    }
                }
            }
            pevents.sort_by(|a, b| b.count.cmp(&a.count));
            println!("  Run start time: {}", r.start_time);
            print!("  ");
            for stat in TotalProcessStat::iter() {
                print!(" {}: {}", stat, r.total_stat_str(&stat));
            }
            println!("");
            for event in pevents.iter() {
                println!(
                    "\tPreempted by {}({}) {} times",
                    event.comm, event.preempt_pid, event.count
                );
            }
        }
    }

    pub fn print(&self, thread: bool) {
        let indent = if thread { "\t" } else { "" };
        println!(
            "{}{} pid {} cgid {} threads {}",
            indent,
            self.comm,
            self.pid,
            self.cgid,
            self.threads.len()
        );
        for r in self.runs.iter() {
            println!("{} Run start time: {}", indent, r.start_time);
            print!("{} ", indent);
            for stat in ProcessStat::iter() {
                print!(" {}: {}", stat, r.stat_str(&stat));
            }
            println!("");
            for event in r.preempt_events.iter() {
                println!(
                    "{}  Preempted by {}({}) {} times",
                    indent, event.comm, event.preempt_pid, event.count
                );
            }
            for thread in self.sorted_threads() {
                thread.print(true);
            }
        }
    }

    pub fn add_run(
        &mut self,
        pid: u32,
        start_time: DateTime<Local>,
        event: &systing::types::task_stat,
    ) {
        self.total_potential_runtime += event.run_time
            + event.preempt_time
            + event.queue_time
            + event.irq_time
            + event.softirq_time
            + event.waking_time;

        match self.runs.last_mut() {
            Some(last_run) => {
                if last_run.start_time == start_time {
                    if pid == self.pid {
                        last_run.set_event(event);
                    }
                    last_run.add_event(event);
                } else {
                    let mut run = RunStats::new(start_time);
                    if pid == self.pid {
                        run.set_event(event);
                    }
                    run.add_event(event);
                    self.runs.push(run);
                }
            }
            None => {
                let mut run = RunStats::new(start_time);
                if pid == self.pid {
                    run.set_event(event);
                }
                run.add_event(event);
                self.runs.push(run);
            }
        }

        if pid != self.pid {
            if let Some(thread) = self.threads.get_mut(&pid) {
                thread.add_run(pid, start_time, event);
            }
        }
    }

    pub fn add_thread(&mut self, thread: Process) {
        if self.threads.contains_key(&thread.pid) {
            return;
        }
        self.threads.insert(thread.pid, thread);
    }

    pub fn add_preempt_event(&mut self, event: &systing::types::preempt_event) {
        let pid = event.tgidpid as u32;
        if pid == self.pid {
            let last_run = self.runs.last_mut().unwrap();
            last_run.add_preempt_event(event);
        } else {
            if let Some(thread) = self.threads.get_mut(&pid) {
                thread.add_preempt_event(event);
            }
        }
    }

    fn get_comm(pid: u32, stat: systing::types::task_stat) -> String {
        let comm_cstr = CStr::from_bytes_until_nul(&stat.comm).unwrap();
        let bytes = comm_cstr.to_bytes();
        if bytes.len() == 0 || bytes.starts_with(&[0]) {
            return pid_comm(pid);
        }
        comm_cstr.to_string_lossy().to_string()
    }

    pub fn update_comm(&mut self, pid: u32, stat: systing::types::task_stat) {
        if pid == self.pid {
            if self.comm.len() != 0 {
                return;
            }
            self.comm = Process::get_comm(pid, stat);
        } else {
            if let Some(thread) = self.threads.get_mut(&pid) {
                if thread.comm.len() != 0 {
                    return;
                }
                thread.comm = Process::get_comm(pid, stat);
            }
        }
    }
}

impl RunStats {
    pub fn new(start_time: DateTime<Local>) -> Self {
        RunStats {
            start_time,
            preempt_events: Vec::new(),
            stat: systing::types::task_stat::default(),
            total_runtime: 0,
            total_sleep_time: 0,
            total_wait_time: 0,
            total_preempt_time: 0,
            total_queue_time: 0,
            total_irq_time: 0,
            total_softirq_time: 0,
            total_waking_time: 0,
            time: 0,
            potential_runtime: 0,
            total_time: 0,
            total_potential_runtime: 0,
        }
    }

    pub fn set_event(&mut self, event: &systing::types::task_stat) {
        self.stat = *event;
        self.time = event.run_time
            + event.preempt_time
            + event.queue_time
            + event.irq_time
            + event.softirq_time
            + event.sleep_time
            + event.wait_time
            + event.waking_time;
        self.potential_runtime = event.run_time
            + event.preempt_time
            + event.queue_time
            + event.irq_time
            + event.softirq_time
            + event.waking_time;
    }

    pub fn add_event(&mut self, event: &systing::types::task_stat) {
        self.total_runtime += event.run_time;
        self.total_sleep_time += event.sleep_time;
        self.total_wait_time += event.wait_time;
        self.total_preempt_time += event.preempt_time;
        self.total_queue_time += event.queue_time;
        self.total_irq_time += event.irq_time;
        self.total_softirq_time += event.softirq_time;
        self.total_waking_time += event.waking_time;
        self.total_time += event.run_time
            + event.preempt_time
            + event.queue_time
            + event.irq_time
            + event.softirq_time
            + event.sleep_time
            + event.wait_time
            + event.waking_time;
        self.total_potential_runtime += event.run_time
            + event.preempt_time
            + event.queue_time
            + event.irq_time
            + event.softirq_time
            + event.waking_time;
    }

    pub fn add_preempt_event(&mut self, event: &systing::types::preempt_event) {
        for e in self.preempt_events.iter_mut() {
            let pid = event.preempt_tgidpid as u32;
            if e.preempt_pid == pid {
                e.count += 1;
                return;
            }
        }
        self.preempt_events.push(PreemptEvent::new(event));
    }

    pub fn sort_preempt_events(&mut self) {
        self.preempt_events.sort_by(|a, b| b.count.cmp(&a.count));
    }

    pub fn process_time(&self) -> u64 {
        match self.time {
            0 => 1,
            _ => self.time,
        }
    }

    pub fn potential_runtime(&self) -> u64 {
        match self.potential_runtime {
            0 => 1,
            _ => self.potential_runtime,
        }
    }

    pub fn total_time(&self) -> u64 {
        match self.total_time {
            0 => 1,
            _ => self.total_time,
        }
    }

    pub fn total_potential_runtime(&self) -> u64 {
        match self.total_potential_runtime {
            0 => 1,
            _ => self.total_potential_runtime,
        }
    }

    pub fn stat_str(&self, stat: &ProcessStat) -> String {
        match stat {
            ProcessStat::RunTime => format!(
                "{}({}% total time, {}% runtime)",
                self.stat.run_time,
                self.stat.run_time * 100 / self.process_time(),
                self.stat.run_time * 100 / self.potential_runtime()
            ),
            ProcessStat::SleepTime => format!(
                "{}({}%)",
                self.stat.sleep_time,
                self.stat.sleep_time * 100 / self.process_time()
            ),
            ProcessStat::WaitTime => format!(
                "{}({}%)",
                self.stat.wait_time,
                self.stat.wait_time * 100 / self.process_time()
            ),
            ProcessStat::PreemptTime => format!(
                "{}({}% total time, {}% runtime)",
                self.stat.preempt_time,
                self.stat.preempt_time * 100 / self.process_time(),
                self.stat.preempt_time * 100 / self.potential_runtime()
            ),
            ProcessStat::QueueTime => format!(
                "{}({}% total time, {}% runtime)",
                self.stat.queue_time,
                self.stat.queue_time * 100 / self.process_time(),
                self.stat.queue_time * 100 / self.potential_runtime()
            ),
            ProcessStat::IrqTime => format!(
                "{}({}% total time, {}% runtime)",
                self.stat.irq_time,
                self.stat.irq_time * 100 / self.process_time(),
                self.stat.irq_time * 100 / self.potential_runtime()
            ),
            ProcessStat::SoftirqTime => format!(
                "{}({}% total time, {}% runtime)",
                self.stat.softirq_time,
                self.stat.softirq_time * 100 / self.process_time(),
                self.stat.softirq_time * 100 / self.potential_runtime()
            ),
            ProcessStat::WakingTime => format!(
                "{}({}% total time, {}% runtime)",
                self.stat.waking_time,
                self.stat.waking_time * 100 / self.process_time(),
                self.stat.waking_time * 100 / self.potential_runtime()
            ),
        }
    }

    pub fn total_stat_str(&self, stat: &TotalProcessStat) -> String {
        match stat {
            TotalProcessStat::TotalRunTime => format!(
                "{}({}% total time, {}% runtime)",
                self.total_runtime,
                self.total_runtime * 100 / self.total_time(),
                self.total_runtime * 100 / self.total_potential_runtime()
            ),
            TotalProcessStat::TotalSleepTime => format!(
                "{}({}%)",
                self.total_sleep_time,
                self.total_sleep_time * 100 / self.total_time()
            ),
            TotalProcessStat::TotalWaitTime => format!(
                "{}({}%)",
                self.total_wait_time,
                self.total_wait_time * 100 / self.total_time()
            ),
            TotalProcessStat::TotalPreemptTime => format!(
                "{}({}% total time, {}% runtime)",
                self.total_preempt_time,
                self.total_preempt_time * 100 / self.total_time(),
                self.total_preempt_time * 100 / self.total_potential_runtime()
            ),
            TotalProcessStat::TotalQueueTime => format!(
                "{}({}% total time, {}% runtime)",
                self.total_queue_time,
                self.total_queue_time * 100 / self.total_time(),
                self.total_queue_time * 100 / self.total_potential_runtime()
            ),
            TotalProcessStat::TotalIrqTime => format!(
                "{}({}% total time, {}% runtime)",
                self.total_irq_time,
                self.total_irq_time * 100 / self.total_time(),
                self.total_irq_time * 100 / self.total_potential_runtime()
            ),
            TotalProcessStat::TotalSoftirqTime => format!(
                "{}({}% total time, {}% runtime)",
                self.total_softirq_time,
                self.total_softirq_time * 100 / self.total_time(),
                self.total_softirq_time * 100 / self.total_potential_runtime()
            ),
            TotalProcessStat::TotalWakingTime => format!(
                "{}({}% total time, {}% runtime)",
                self.total_waking_time,
                self.total_waking_time * 100 / self.total_time(),
                self.total_waking_time * 100 / self.total_potential_runtime()
            ),
        }
    }
}

impl PreemptEvent {
    pub fn new(event: &systing::types::preempt_event) -> Self {
        let comm_cstr = CStr::from_bytes_until_nul(&event.comm).unwrap();
        let bytes = comm_cstr.to_bytes();
        let commstr;
        if bytes.len() == 0 || bytes.starts_with(&[0]) {
            commstr = pid_comm(event.preempt_tgidpid as u32);
        } else {
            commstr = comm_cstr.to_string_lossy().to_string();
        }
        PreemptEvent {
            preempt_pid: event.preempt_tgidpid as u32,
            preempt_tgid: (event.preempt_tgidpid >> 32) as u32,
            cgid: event.cgid,
            comm: commstr,
            count: 1,
        }
    }
}

impl fmt::Display for ProcessStat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ProcessStat::RunTime => write!(f, "Run Time"),
            ProcessStat::SleepTime => write!(f, "Sleep Time"),
            ProcessStat::WaitTime => write!(f, "Wait Time"),
            ProcessStat::PreemptTime => write!(f, "Preempt Time"),
            ProcessStat::QueueTime => write!(f, "Queue Time"),
            ProcessStat::IrqTime => write!(f, "IRQ Time"),
            ProcessStat::SoftirqTime => write!(f, "SoftIRQ Time"),
            ProcessStat::WakingTime => write!(f, "Waking Time"),
        }
    }
}

impl fmt::Display for TotalProcessStat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TotalProcessStat::TotalRunTime => write!(f, "Total Run Time"),
            TotalProcessStat::TotalSleepTime => write!(f, "Total Sleep Time"),
            TotalProcessStat::TotalWaitTime => write!(f, "Total Wait Time"),
            TotalProcessStat::TotalPreemptTime => write!(f, "Total Preempt Time"),
            TotalProcessStat::TotalQueueTime => write!(f, "Total Queue Time"),
            TotalProcessStat::TotalIrqTime => write!(f, "Total IRQ Time"),
            TotalProcessStat::TotalSoftirqTime => write!(f, "Total SoftIRQ Time"),
            TotalProcessStat::TotalWakingTime => write!(f, "Total Waking Time"),
        }
    }
}
