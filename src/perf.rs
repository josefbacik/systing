use bitfield::bitfield;
use libc;
use nix::ioctl_none;

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
) -> libc::c_long {
    unsafe {
        syscall(
            libc::SYS_perf_event_open,
            hw_event as *const perf_event_attr,
            pid,
            cpu,
            group_fd,
            flags,
        )
    }
}

const PERF_EVENT_MAGIC: u8 = b'$';
const PERF_EVENT_IOC_ENABLE: u8 = 0;
ioctl_none!(
    perf_event_ioc_enable,
    PERF_EVENT_MAGIC,
    PERF_EVENT_IOC_ENABLE
);
