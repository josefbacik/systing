use std::collections::HashMap;
use std::fs;
use std::io::{Error, ErrorKind};
use std::mem;
use std::os::fd::{AsRawFd, IntoRawFd, RawFd};
use std::path::Path;

use anyhow::Result;
use bitfield::bitfield;
use libbpf_rs;
use libc;
use nix::errno::Errno;
use nix::ioctl_none;
use regex::Regex;

#[derive(Default, Debug, Clone)]
pub struct PerfHwEvent {
    pub name: String,
    pub event_type: u32,
    pub event_config: u64,
    pub disabled: bool,
    pub need_slots: bool,
    pub cpus: Vec<u32>,
}

#[derive(Debug, Default)]
pub struct PerfCounters {
    events: HashMap<String, Vec<PerfHwEvent>>,
}

#[repr(C)]
pub union sample_un {
    pub sample_period: u64,
    pub sample_freq: u64,
}

#[repr(C)]
pub union wakeup_un {
    pub wakeup_events: u32,
    pub wakeup_atermark: u32,
}

#[repr(C)]
pub union bp_1_un {
    pub bp_addr: u64,
    pub kprobe_func: u64,
    pub uprobe_path: u64,
    pub config1: u64,
}

#[repr(C)]
pub union bp_2_un {
    pub bp_len: u64,
    pub kprobe_addr: u64,
    pub probe_offset: u64,
    pub config2: u64,
}

bitfield! {
    #[allow(non_camel_case_types)]
    pub struct perf_event_attr_flags(u64);
    impl Debug;
    pub disabled, set_disabled: 0, 0;
    pub inherit, set_inherit: 1, 1;
    pub pinned, set_pinned: 2, 2;
    pub exclusive, set_exclusive: 3, 3;
    pub exclude_user, set_exclude_user: 4, 4;
    pub exclude_kernel, set_exclude_kernel: 5, 5;
    pub exclude_hv, set_exclude_hv: 6, 6;
    pub exclude_idle, set_exclude_idle: 7, 7;
    pub mmap, set_mmap: 8, 8;
    pub comm, set_comm: 9, 9;
    pub freq, set_freq: 10, 10;
    pub inherit_stat, set_inherit_stat: 11, 11;
    pub enable_on_exec, set_enable_on_exec: 12, 12;
    pub task, set_task: 13, 13;
    pub watermark, set_watermark: 14, 14;
    pub precise_ip, set_precise_ip: 15, 16;
    pub mmap_data, set_mmap_data: 17, 17;
    pub sample_id_all, set_sample_id_all: 18, 18;
    pub exclude_host, set_exclude_host: 19, 19;
    pub exclude_guest, set_exclude_guest: 20, 20;
    pub exclude_callchain_kernel, set_exclude_callchain_kernel: 21, 21;
    pub exclude_callchain_user, set_exclude_callchain_user: 22, 22;
    pub mmap2, set_mmap2: 23, 23;
    pub comm_exec, set_comm_exec: 24, 24;
    pub use_clockid, set_use_clockid: 25, 25;
    pub context_switch, set_context_switch: 26, 26;
    pub write_backward, set_write_backward: 27, 27;
    pub namespaces, set_namespaces: 28, 28;
    pub ksymbol, set_ksymbol: 29, 29;
    pub bpf_event, set_bpf_event: 30, 30;
    pub aux_output, set_aux_output: 31, 31;
    pub cgroup, set_cgroup: 32, 32;
    pub text_poke, set_text_poke: 33, 33;
    pub build_id, set_build_id: 34, 34;
    pub inherit_thread, set_inherit_thread: 35, 35;
    pub remove_on_exec, set_remove_on_exec: 36, 36;
    pub sigtrap, set_sigtrap: 37, 37;
    pub __reserved_1, _: 38, 63;
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct perf_event_attr {
    pub _type: u32,
    pub size: u32,
    pub config: u64,
    pub sample: sample_un,
    pub sample_type: u64,
    pub read_format: u64,
    pub flags: perf_event_attr_flags,
    pub wakeup: wakeup_un,
    pub bp_type: u32,
    pub bp_1: bp_1_un,
    pub bp_2: bp_2_un,
    pub branch_sample_type: u64,
    pub sample_regs_user: u64,
    pub sample_stack_user: u32,
    pub clockid: i32,
    pub sample_regs_intr: u64,
    pub aux_watermark: u32,
    pub sample_max_stack: u16,
    pub __reserved_2: u16,
    pub aux_sample_size: u32,
    pub __reserved_3: u32,
}

pub const PERF_TYPE_HARDWARE: u32 = 0;
pub const PERF_TYPE_SOFTWARE: u32 = 1;

pub const PERF_COUNT_HW_CPU_CYCLES: u64 = 0;
pub const PERF_COUNT_HW_CACHE_REFERENCES: u64 = 2;
pub const PERF_COUNT_HW_CACHE_MISSES: u64 = 3;
pub const PERF_COUNT_HW_STALLED_CYCLES_FRONTEND: u64 = 7;
pub const PERF_COUNT_HW_STALLED_CYCLES_BACKEND: u64 = 8;

pub const PERF_COUNT_SW_CPU_CLOCK: u64 = 0;

extern "C" {
    fn syscall(number: libc::c_long, ...) -> libc::c_long;
}

pub fn perf_event_open(
    hw_event: &perf_event_attr,
    pid: libc::pid_t,
    cpu: libc::c_int,
    group_fd: libc::c_int,
    flags: libc::c_ulong,
) -> Result<PerfEventFile, Error> {
    let fd = unsafe {
        syscall(
            libc::SYS_perf_event_open,
            hw_event as *const perf_event_attr,
            pid,
            cpu,
            group_fd,
            flags,
        )
    } as i32;

    if fd < 0 {
        return Err(Error::last_os_error());
    }

    Ok(PerfEventFile {
        fd,
        need_disable: false,
    })
}

const PERF_EVENT_MAGIC: u8 = b'$';
const PERF_EVENT_IOC_ENABLE: u8 = 0;
const PERF_EVENT_IOC_DISABLE: u8 = 1;
ioctl_none!(
    perf_event_ioc_enable,
    PERF_EVENT_MAGIC,
    PERF_EVENT_IOC_ENABLE
);
ioctl_none!(
    perf_event_ioc_disable,
    PERF_EVENT_MAGIC,
    PERF_EVENT_IOC_DISABLE
);

#[derive(Debug)]
pub struct PerfEventFile {
    fd: RawFd,
    need_disable: bool,
}

#[derive(Debug)]
pub struct PerfOpenEvents {
    hwevents: Vec<PerfHwEvent>,
    events: HashMap<u32, PerfEventFile>,
}

impl PerfOpenEvents {
    pub fn new() -> Self {
        PerfOpenEvents {
            hwevents: Vec::new(),
            events: HashMap::new(),
        }
    }

    pub fn get(&self, cpu: u32) -> Option<&PerfEventFile> {
        self.events.get(&cpu)
    }

    pub fn add_hw_event(&mut self, hwevent: PerfHwEvent) -> Result<(), Error> {
        // Make sure this has CPU's set
        if hwevent.cpus.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "No CPUs specified for event",
            ));
        }

        // Make sure the added hwevent doesn't overlapp cpu's with existing ones
        for event in self.hwevents.iter() {
            if event.cpus.iter().any(|&cpu| hwevent.cpus.contains(&cpu)) {
                return Err(Error::new(
                    ErrorKind::AlreadyExists,
                    "CPU overlap with existing events",
                ));
            }
        }
        self.hwevents.push(hwevent);
        Ok(())
    }

    pub fn iter(&self) -> impl Iterator<Item = &PerfEventFile> {
        self.events.values()
    }

    pub fn open_events(
        &mut self,
        slots_files: Option<&PerfOpenEvents>,
        freq: u64,
    ) -> Result<(), Error> {
        if !self.events.is_empty() {
            return Ok(());
        }
        for hwevent in self.hwevents.iter() {
            let buf: Vec<u8> = vec![0; mem::size_of::<perf_event_attr>()];
            let mut attr = unsafe {
                Box::<perf_event_attr>::from_raw(buf.leak().as_mut_ptr() as *mut perf_event_attr)
            };
            attr._type = hwevent.event_type;
            attr.size = mem::size_of::<perf_event_attr>() as u32;
            attr.config = hwevent.event_config;
            if freq > 0 {
                attr.sample.sample_freq = freq;
                attr.flags.set_freq(1);
            }
            if hwevent.disabled {
                attr.flags.set_disabled(1);
            }
            for cpu in hwevent.cpus.iter() {
                let group_fd = if hwevent.need_slots {
                    if let Some(slots_files) = slots_files {
                        let slot_file = slots_files.get(*cpu);
                        if slot_file.is_none() {
                            return Err(Error::new(ErrorKind::NotFound, "Slot file not found"));
                        }
                        slot_file.unwrap().as_raw_fd()
                    } else {
                        -1
                    }
                } else {
                    -1
                };
                let res = perf_event_open(attr.as_ref(), -1, *cpu as i32, group_fd, 0);
                match res {
                    Ok(file) => {
                        self.events.insert(*cpu, file);
                    }
                    Err(err) => {
                        let mut error_context = format!(
                            "Failed to open perf event {} on cpu {}: {}",
                            hwevent.name, cpu, err
                        );

                        if let Some(libc::ENODEV) = err.raw_os_error() {
                            // Sometimes available cpus < num_cpus, so we just break here.
                            break;
                        }

                        if err.kind() == ErrorKind::NotFound {
                            error_context = format!(
                                "Failed to open perf event {}.\n\
                                Try running the profile example with the `--sw-event` option.",
                                hwevent.name
                            );
                        }
                        return Err(Error::new(err.kind(), error_context));
                    }
                }
            }
        }
        Ok(())
    }

    pub fn enable(&mut self) -> Result<(), Error> {
        for (_, file) in self.events.iter_mut() {
            file.enable()?;
        }
        Ok(())
    }
}

impl<'h> IntoIterator for &'h PerfOpenEvents {
    type Item = (&'h u32, &'h PerfEventFile);
    type IntoIter = std::collections::hash_map::Iter<'h, u32, PerfEventFile>;

    fn into_iter(self) -> Self::IntoIter {
        self.events.iter()
    }
}

impl IntoIterator for PerfOpenEvents {
    type Item = (u32, PerfEventFile);
    type IntoIter = std::collections::hash_map::IntoIter<u32, PerfEventFile>;

    fn into_iter(self) -> Self::IntoIter {
        self.events.into_iter()
    }
}

impl PerfEventFile {
    pub fn enable(&mut self) -> Result<(), Error> {
        let ret = unsafe { perf_event_ioc_enable(self.fd) };
        match ret {
            Ok(_) => {
                self.need_disable = true;
                return Ok(());
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    }

    pub fn disable(&self) -> Result<(), Error> {
        let ret = unsafe { perf_event_ioc_disable(self.fd) };
        match ret {
            Ok(_) => Ok(()),
            Err(e) => {
                if e == Errno::ENOTTY {
                    return Ok(());
                }
                Err(e.into())
            }
        }
    }
}

impl AsRawFd for PerfEventFile {
    fn as_raw_fd(&self) -> i32 {
        self.fd
    }
}

impl IntoRawFd for PerfEventFile {
    fn into_raw_fd(self) -> i32 {
        self.fd
    }
}

impl Drop for PerfEventFile {
    fn drop(&mut self) {
        if !self.need_disable {
            return;
        }
        unsafe {
            perf_event_ioc_disable(self.fd).unwrap();
        }
    }
}

fn visit_events(dir: &Path, events: &mut Vec<PerfHwEvent>) -> Result<()> {
    let entries = fs::read_dir(dir)?
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();

    // Some of the topdown metrics exposted by Intel Atom don't have a slots entry, so we have to
    // check and see if there's a slots file in this events directory to decide if any topdown
    // metrics require a slots fd.
    let need_slots = entries
        .iter()
        .any(|entry| {
            let filename = entry.file_name().unwrap().to_str().unwrap();
            filename == "slots"
        });

    let event_re = Regex::new(r"event=0x([0-9a-fA-F]+)").unwrap();
    let umask_re = Regex::new(r"umask=0x([0-9a-fA-F]+)").unwrap();
    for path in entries {
        let buf = fs::read_to_string(&path)?;
        let event = event_re.captures(&buf);
        let umask = umask_re.captures(&buf);
        let mut hwevent = PerfHwEvent {
            name: path.file_name().unwrap().to_str().unwrap().to_string(),
            ..Default::default()
        };

        if event.is_some() {
            let event = event.unwrap();
            let event = u64::from_str_radix(&event[1], 16).unwrap();
            hwevent.event_config = event;
        }
        if umask.is_some() {
            let umask = umask.unwrap();
            let umask = u64::from_str_radix(&umask[1], 16).unwrap();
            hwevent.event_config |= umask << 8;
        }

        // Slots events should be disabled
        if hwevent.name == "slots" {
            hwevent.disabled = true;
        }

        // Topdown events need slots
        if hwevent.name.starts_with("topdown") {
            hwevent.need_slots = need_slots;
        }
        events.push(hwevent);
    }
    Ok(())
}

fn visit_dirs(dir: &Path, counters: &mut PerfCounters, toplevel: bool) -> Result<()> {
    if dir.is_dir() {
        let mut event_type: u32 = 0;
        let mut cpus: Vec<u32> = Vec::new();
        let mut events: Vec<PerfHwEvent> = Vec::new();
        let cpus_re = Regex::new(r"(\d+)-(\d+)").unwrap();

        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let filename = path.file_name().unwrap().to_str().unwrap();
            if path.is_dir() {
                if toplevel && filename.starts_with("cpu") {
                    visit_dirs(&path, counters, false)?;
                } else if filename == "events" {
                    visit_events(&path, &mut events)?;
                }
            } else {
                match filename {
                    "type" => {
                        let buf = fs::read_to_string(&path)?;
                        event_type = buf.trim().parse().unwrap();
                    }
                    "cpus" => {
                        let buf = fs::read_to_string(&path)?;
                        for cap in cpus_re.captures_iter(&buf) {
                            let start = cap[1].parse().unwrap();
                            let end = cap[2].parse().unwrap();
                            for cpu in start..=end {
                                cpus.push(cpu);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        if cpus.is_empty() {
            let num_cpus = libbpf_rs::num_possible_cpus()?;
            cpus = (0..num_cpus as u32).collect();
        }
        for mut event in events {
            event.event_type = event_type;
            event.cpus = cpus.clone();
            let entry = counters.events.entry(event.name.clone()).or_default();
            entry.push(event);
        }
    }
    Ok(())
}

impl PerfCounters {
    pub fn discover(&mut self) -> Result<()> {
        if !self.events.is_empty() {
            return Ok(());
        }
        let path = Path::new("/sys/bus/event_source/devices");
        visit_dirs(path, self, true)?;
        Ok(())
    }

    pub fn event(&self, name: &str) -> Option<Vec<PerfHwEvent>> {
        let result = self.events.get(name);
        if let Some(result) = result {
            return Some(result.clone());
        }

        if !name.contains("*") {
            return None;
        }

        let pattern = name.replace('*', ".*");
        let re = Regex::new(pattern.as_str());
        if re.is_err() {
            return None;
        }
        let re = re.unwrap();

        let mut result = Vec::new();
        for (key, value) in &self.events {
            if re.is_match(key) {
                result.extend(value.iter().cloned());
            }
        }
        if !result.is_empty() {
            return Some(result);
        }
        None
    }
}
