use std::collections::{HashMap, HashSet};
use std::ffi::CStr;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use anyhow::Result;

use crate::events::SystingProbeRecorder;
use crate::marker_recorder::MarkerRecorder;
use crate::memory_recorder::MemoryRecorder;
use crate::network_recorder::NetworkRecorder;
use crate::parquet::{ParquetSink, StreamingParquetWriter};
use crate::perf_recorder::PerfCounterRecorder;
use crate::record::{RecordCollector, SharedCollector};
use crate::ringbuf::RingBuffer;
use crate::sched::SchedEventRecorder;
use crate::stack_recorder::StackRecorder;
use crate::systing_core::types::task_info;
use crate::systing_core::SystingRecordEvent;
use crate::tpu::metrics_recorder::TpuMetricsRecorder;
use crate::trace::{
    ClockSnapshotRecord, CounterRecord, CounterTrackRecord, ProcessRecord, ThreadRecord,
};
use crate::utid::{
    CounterTrackIdGenerator, ThreadAwareRecorder, TrackEventIdGenerator, UtidGenerator,
};

use perfetto_protos::builtin_clock::BuiltinClock;
use perfetto_protos::clock_snapshot::clock_snapshot::Clock;
use perfetto_protos::clock_snapshot::ClockSnapshot;
use perfetto_protos::process_descriptor::ProcessDescriptor;
use perfetto_protos::process_tree::process_tree::Process as ProtoProcess;
use perfetto_protos::system_info::Utsname;
use perfetto_protos::thread_descriptor::ThreadDescriptor;
use std::fs::{self, File};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

#[derive(Default)]
pub struct SysInfoEvent {
    pub cpu: u32,
    pub ts: u64,
    pub frequency: i64,
}

/// The perf event configuration driving CPU stack sampling. Recorded into the
/// trace's sysinfo row so analysis knows what one stack sample represents:
/// `period` cycles for "cpu-cycles", `period` nanoseconds for "cpu-clock".
#[derive(Clone, Debug)]
pub struct ClockSamplingConfig {
    /// Perf event name: "cpu-cycles" (hardware) or "cpu-clock" (software
    /// fallback, used with --sw-event or when the PMU is unavailable).
    pub event: &'static str,
    /// Sampling period in event units (cycles or nanoseconds).
    pub period: u64,
}

/// Static per-CPU frequency limits from sysfs cpufreq, in kHz (sysfs's native
/// unit). `base_freq_khz` is the sustained (non-turbo) frequency and is only
/// exposed by some drivers (e.g. intel_pstate).
pub struct CpuFreqInfo {
    pub cpu: u32,
    pub min_freq_khz: Option<i64>,
    pub max_freq_khz: Option<i64>,
    pub base_freq_khz: Option<i64>,
}

/// Read each CPU's cpufreq limits from sysfs. CPUs without a cpufreq directory
/// (VM guests, offlined CPUs) are omitted, so the result is empty on systems
/// with no cpufreq support. Used both to pick the cpu-cycles sample period at
/// startup and to record per-CPU frequency provenance in the trace, which is
/// what lets analysis convert cycle-denominated samples into approximate time.
pub fn cpu_freq_limits() -> Vec<CpuFreqInfo> {
    let Ok(entries) = fs::read_dir("/sys/devices/system/cpu") else {
        return Vec::new();
    };
    let mut cpus: Vec<CpuFreqInfo> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name();
            let cpu: u32 = name.to_str()?.strip_prefix("cpu")?.parse().ok()?;
            let cpufreq = entry.path().join("cpufreq");
            let read_khz = |file: &str| -> Option<i64> {
                read_sysfs_string(cpufreq.join(file).to_str()?)?
                    .parse()
                    .ok()
            };
            let info = CpuFreqInfo {
                cpu,
                min_freq_khz: read_khz("cpuinfo_min_freq"),
                max_freq_khz: read_khz("cpuinfo_max_freq"),
                base_freq_khz: read_khz("base_frequency"),
            };
            let has_data = info.min_freq_khz.is_some()
                || info.max_freq_khz.is_some()
                || info.base_freq_khz.is_some();
            has_data.then_some(info)
        })
        .collect();
    cpus.sort_by_key(|c| c.cpu);
    cpus
}

pub struct SysinfoRecorder {
    pub ringbuf: RingBuffer<SysInfoEvent>,
    // Streaming support
    streaming_collector: Option<Box<dyn RecordCollector + Send>>,
    track_ids: HashMap<u32, i64>,
    /// Shared with every other recorder that emits counter tracks (e.g. the
    /// perf-counter recorder) so track IDs stay unique across them.
    counter_track_ids: Arc<CounterTrackIdGenerator>,
    utid_generator: Arc<UtidGenerator>,
}

impl ThreadAwareRecorder for SysinfoRecorder {
    fn utid_generator(&self) -> &UtidGenerator {
        &self.utid_generator
    }
}

impl SysinfoRecorder {
    pub fn new(
        utid_generator: Arc<UtidGenerator>,
        counter_track_ids: Arc<CounterTrackIdGenerator>,
    ) -> Self {
        Self {
            ringbuf: RingBuffer::default(),
            streaming_collector: None,
            track_ids: HashMap::new(),
            counter_track_ids,
            utid_generator,
        }
    }
}

pub struct SessionRecorder {
    pub clock_snapshot: Mutex<ClockSnapshot>,
    /// Scheduler/IRQ event recorder shards, one per `ringbufs`-family ring.
    /// Shard i is fed only by ring i's consumer thread; all recorder state is
    /// keyed by CPU and cpu -> ring is static (cpu % NR_RINGBUFS), so shards
    /// never see each other's CPUs. They stream into one shared parquet
    /// writer (see `init_streaming_output`).
    pub event_recorders: Vec<Mutex<SchedEventRecorder>>,
    pub stack_recorder: Mutex<StackRecorder>,
    pub perf_counter_recorder: Mutex<PerfCounterRecorder>,
    pub sysinfo_recorder: Mutex<SysinfoRecorder>,
    pub probe_recorder: Mutex<SystingProbeRecorder>,
    pub network_recorder: Mutex<NetworkRecorder>,
    pub memory_recorder: Mutex<MemoryRecorder>,
    pub marker_recorder: Mutex<MarkerRecorder>,
    pub tpu_metrics_recorder: Option<Mutex<TpuMetricsRecorder>>,
    pub process_descriptors: RwLock<HashMap<u64, ProcessDescriptor>>,
    pub processes: RwLock<HashMap<u64, ProtoProcess>>,
    pub threads: RwLock<HashMap<u64, ThreadDescriptor>>,
    /// Maps process tgidpid -> cgroup id (the cgroup directory's kernfs node id,
    /// i.e. its inode) as observed in-kernel at event time. This lets us attribute
    /// even short-lived processes to a cgroup, since the id rides in on the event
    /// and does not depend on /proc still existing when userspace runs discovery.
    pub process_cgroups: RwLock<HashMap<u64, u64>>,
    /// Set of pids for processes detected as kernel threads.
    kernel_threads: RwLock<HashSet<u32>>,
    /// Shared utid generator for consistent thread IDs across all recorders.
    utid_generator: Arc<UtidGenerator>,
    /// The perf event/period driving CPU stack sampling, set once perf events
    /// are opened. Unset until then (or in unit tests that never open them).
    pub clock_sampling: OnceLock<ClockSamplingConfig>,
}

pub fn get_clock_value(clock_id: libc::c_int) -> u64 {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(clock_id, &mut ts) } != 0 {
        return 0;
    }
    (ts.tv_sec as u64 * 1_000_000_000) + ts.tv_nsec as u64
}

/// Retrieves system information using the POSIX uname() call.
///
/// Returns a Utsname structure containing system name, kernel release,
/// kernel version, and machine architecture.
///
/// # Returns
///
/// Returns `Some(Utsname)` on success, or `None` if the uname() call fails.
pub fn get_system_utsname() -> Option<Utsname> {
    let mut utsname_buf: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut utsname_buf) } != 0 {
        return None;
    }

    let mut utsname = Utsname::default();

    // Helper macro to extract and set utsname fields
    macro_rules! set_field {
        ($field:ident, $setter:ident) => {
            // SAFETY: utsname_buf is properly initialized by libc::uname, and the pointer
            // points to a valid null-terminated C string within the utsname struct.
            if let Ok(s) = unsafe { CStr::from_ptr(utsname_buf.$field.as_ptr()) }.to_str() {
                utsname.$setter(s.to_string());
            }
        };
    }

    set_field!(sysname, set_sysname);
    set_field!(release, set_release);
    set_field!(version, set_version);
    set_field!(machine, set_machine);

    Some(utsname)
}

/// Read a small sysfs/procfs file into a trimmed string. Returns `None` if the
/// file is missing, unreadable, or empty. Trims NUL bytes as well as
/// whitespace, since device-tree properties are NUL-terminated.
fn read_sysfs_string(path: &str) -> Option<String> {
    let contents = fs::read_to_string(path).ok()?;
    let trimmed = contents.trim_matches(|c: char| c.is_whitespace() || c == '\0');
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Returns the kernel's cpufreq scaling driver name (e.g. "intel_pstate",
/// "acpi-cpufreq"), or `None` if the system has no cpufreq support at all.
///
/// VM guests typically have no cpufreq driver: the guest has no real frequency
/// to report, so `--cpu-frequency` polling there only yields a constant nominal
/// value (and the sysinfo crate's fallback path - a full /proc/cpuinfo parse
/// per CPU per poll - is expensive). Callers use this both to gate the poller
/// and to record frequency-data provenance in the trace.
///
/// Probes the policy directories rather than a per-CPU path: per-CPU `cpufreq`
/// symlinks disappear when a CPU is offlined (possible for any CPU on arm64),
/// while `policyN` directories track the driver itself. Note the `cpufreq`
/// directory can exist and be empty on systems with no driver.
pub fn cpufreq_scaling_driver() -> Option<String> {
    fs::read_dir("/sys/devices/system/cpu/cpufreq")
        .ok()?
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("policy"))
        .find_map(|e| read_sysfs_string(e.path().join("scaling_driver").to_str()?))
}

/// Detect whether we are running under a hypervisor and, if so, identify it.
///
/// On x86_64 this checks the CPUID hypervisor-present bit (leaf 1, ECX bit 31)
/// and reads the vendor signature from leaf 0x40000000 - the canonical,
/// unforgeable-by-DMI way to tell a VM from bare metal (cloud "metal" instances
/// report a vendor like "Amazon EC2" in DMI but do not set the hypervisor bit).
/// Returns a normalized name ("kvm", "xen", ...) or the raw signature for
/// unrecognized hypervisors. Returns `None` on bare metal.
///
/// Caveats: this records the hypervisor *interface* the guest sees - a KVM
/// guest with Hyper-V enlightenments advertises "Microsoft Hv" at leaf
/// 0x40000000 (the KVM signature moves to 0x40000100) and is reported as
/// "hyper-v" here. On non-x86_64 the check is device-tree based and
/// best-effort: ACPI-booted guests (most cloud aarch64) have no
/// /proc/device-tree, so `None` there does not reliably mean bare metal.
pub fn detect_hypervisor() -> Option<String> {
    #[cfg(target_arch = "x86_64")]
    {
        // CPUID is unprivileged and always available on x86_64.
        let leaf1 = std::arch::x86_64::__cpuid(1);
        if leaf1.ecx & (1 << 31) == 0 {
            return None;
        }
        // Leaf 0x40000000 is defined whenever the hypervisor bit is set, and
        // returns the vendor signature in EBX/ECX/EDX.
        let hv = std::arch::x86_64::__cpuid(0x4000_0000);
        let mut sig_bytes = [0u8; 12];
        sig_bytes[0..4].copy_from_slice(&hv.ebx.to_le_bytes());
        sig_bytes[4..8].copy_from_slice(&hv.ecx.to_le_bytes());
        sig_bytes[8..12].copy_from_slice(&hv.edx.to_le_bytes());
        let sig = String::from_utf8_lossy(&sig_bytes)
            .trim_matches(['\0', ' '])
            .to_string();
        let name = match sig.as_str() {
            s if s.starts_with("KVM") => "kvm",
            s if s.starts_with("VMware") => "vmware",
            s if s.starts_with("XenVMM") => "xen",
            "Microsoft Hv" => "hyper-v",
            s if s.starts_with("TCG") => "qemu-tcg",
            s if s.starts_with("bhyve") => "bhyve",
            s if s.starts_with("VBox") => "virtualbox",
            s if s.starts_with("ACRN") => "acrn",
            // Pass unrecognized signatures through so they stay identifiable,
            // but only if they are printable - garbage CPUID output (or the
            // U+FFFD characters from_utf8_lossy substitutes for invalid bytes)
            // should not land in the database verbatim.
            other
                if !other.is_empty() && other.chars().all(|c| c.is_ascii_graphic() || c == ' ') =>
            {
                other
            }
            _ => "unknown",
        };
        Some(name.to_string())
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        // Best effort on other architectures: device-tree-booted ARM guests
        // under KVM/Xen expose a hypervisor node whose `compatible` property
        // names the hypervisor (e.g. "linux,kvm", "xen,xen").
        if Path::new("/proc/device-tree/hypervisor").exists() {
            Some(
                read_sysfs_string("/proc/device-tree/hypervisor/compatible")
                    .unwrap_or_else(|| "unknown".to_string()),
            )
        } else {
            None
        }
    }
}

/// DMI system vendor (e.g. "Amazon EC2", "Dell Inc."), if exposed.
pub fn dmi_sys_vendor() -> Option<String> {
    read_sysfs_string("/sys/class/dmi/id/sys_vendor")
}

/// DMI product name (e.g. "m7i.16xlarge", "PowerEdge R750"), if exposed.
pub fn dmi_product_name() -> Option<String> {
    read_sysfs_string("/sys/class/dmi/id/product_name")
}

/// Track name for network interface metadata in Perfetto traces.
pub const NETWORK_INTERFACES_TRACK_NAME: &str = "Network Interfaces";

/// Represents a network interface with its associated IP addresses.
#[derive(Debug, Clone)]
pub struct NetworkInterface {
    pub name: String,
    pub ipv4_addrs: Vec<Ipv4Addr>,
    pub ipv6_addrs: Vec<Ipv6Addr>,
}

/// Information about a network namespace for deduplication and naming.
#[derive(Debug, Clone)]
pub struct NetnsInfo {
    /// The inode number of the network namespace (unique identifier).
    pub inode: u64,
    /// A representative PID from this namespace.
    pub representative_pid: u32,
    /// Container ID if detected from cgroup (e.g., Docker container ID).
    pub container_id: Option<String>,
    /// Process comm of the representative PID.
    pub comm: String,
    /// Whether this is the host (init) network namespace.
    pub is_host: bool,
}

impl NetnsInfo {
    /// Returns a display name for this network namespace.
    ///
    /// Format examples:
    /// - `"host"` for the host namespace
    /// - `"container:abc123 (nginx)"` for a container with known comm
    /// - `"container:abc123"` for a container without comm
    /// - `"netns:4026532890 (java:1234)"` for a namespace with known comm and PID
    /// - `"netns:4026532890"` for a namespace without comm
    pub fn display_name(&self) -> String {
        if self.is_host {
            "host".to_string()
        } else if let Some(ref container_id) = self.container_id {
            if self.comm.is_empty() {
                format!("container:{container_id}")
            } else {
                format!("container:{} ({})", container_id, self.comm)
            }
        } else if self.comm.is_empty() {
            format!("netns:{}", self.inode)
        } else {
            format!(
                "netns:{} ({}:{})",
                self.inode, self.comm, self.representative_pid
            )
        }
    }
}

/// Gets the network namespace inode for a given PID.
fn get_netns_inode(pid: u32) -> Option<u64> {
    let ns_path = format!("/proc/{pid}/ns/net");
    fs::metadata(&ns_path).ok().map(|m| m.ino())
}

/// Gets the host (init) network namespace inode.
fn get_host_netns_inode() -> Option<u64> {
    get_netns_inode(1)
}

/// Attempts to extract a container ID from a process's cgroup information.
/// Looks for Docker/containerd container IDs in the cgroup path.
fn get_container_id(pid: u32) -> Option<String> {
    let cgroup_path = format!("/proc/{pid}/cgroup");
    let content = fs::read_to_string(&cgroup_path).ok()?;

    for line in content.lines() {
        // Docker format: 0::/docker/<container_id>
        // containerd format: 0::/system.slice/containerd.service/kubepods-.../<container_id>
        // k8s format: various paths containing the container ID

        // Look for 64-char hex strings (Docker container IDs)
        if let Some(docker_idx) = line.find("/docker/") {
            let id_start = docker_idx + 8;
            if line.len() >= id_start + 12 {
                let id = &line[id_start..];
                let id = id.split('/').next().unwrap_or(id);
                if id.len() >= 12 && id.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Some(id[..12].to_string());
                }
            }
        }

        // Look for containerd/cri-o container IDs
        if let Some(cri_idx) = line.find("/cri-containerd-") {
            let id_start = cri_idx + 16;
            if line.len() >= id_start + 12 {
                let id = &line[id_start..];
                let id = id.split('.').next().unwrap_or(id);
                if id.len() >= 12 && id.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Some(id[..12].to_string());
                }
            }
        }

        // Look for crio container IDs
        if let Some(crio_idx) = line.find("/crio-") {
            let id_start = crio_idx + 6;
            if line.len() >= id_start + 12 {
                let id = &line[id_start..];
                let id = id.split('.').next().unwrap_or(id);
                if id.len() >= 12 && id.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Some(id[..12].to_string());
                }
            }
        }
    }

    None
}

/// Gets the comm (process name) for a given PID.
fn get_comm(pid: u32) -> String {
    let comm_path = format!("/proc/{pid}/comm");
    fs::read_to_string(&comm_path)
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Retrieves network interfaces from within a specific network namespace.
/// This function temporarily enters the target namespace, enumerates interfaces,
/// and then returns to the original namespace.
fn get_interfaces_in_netns(pid: u32) -> Vec<NetworkInterface> {
    let self_netns = match File::open("/proc/self/ns/net") {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };

    let target_netns_path = format!("/proc/{pid}/ns/net");
    let target_netns = match File::open(&target_netns_path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };

    // SAFETY: target_netns is a valid file descriptor obtained from File::open() on a
    // namespace pseudo-file. CLONE_NEWNET is a valid namespace type. The setns syscall
    // is safe to call with these arguments - it only changes the calling thread's namespace.
    if unsafe { libc::setns(target_netns.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
        return Vec::new();
    }

    let interfaces = get_network_interfaces();

    // SAFETY: self_netns is a valid file descriptor for our original namespace, obtained
    // before switching. This restores the thread to its original network namespace.
    if unsafe { libc::setns(self_netns.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
        eprintln!(
            "WARNING: Failed to restore original network namespace after enumerating interfaces for pid {pid}"
        );
    }

    interfaces
}

/// Retrieves all network interfaces and their IP addresses using getifaddrs.
///
/// # Returns
///
/// Returns a vector of NetworkInterface structs, one for each interface with at least one address.
pub fn get_network_interfaces() -> Vec<NetworkInterface> {
    let mut interfaces: HashMap<String, NetworkInterface> = HashMap::new();

    unsafe {
        let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifaddrs) != 0 {
            return Vec::new();
        }

        let mut current = ifaddrs;
        while !current.is_null() {
            let ifa = &*current;

            // Get interface name
            if let Ok(name) = CStr::from_ptr(ifa.ifa_name).to_str() {
                let name = name.to_string();

                // Get or create the interface entry
                let iface = interfaces
                    .entry(name.clone())
                    .or_insert_with(|| NetworkInterface {
                        name,
                        ipv4_addrs: Vec::new(),
                        ipv6_addrs: Vec::new(),
                    });

                // Parse address if present
                if !ifa.ifa_addr.is_null() {
                    let sa_family = (*ifa.ifa_addr).sa_family as i32;

                    if sa_family == libc::AF_INET {
                        let sockaddr_in = ifa.ifa_addr as *const libc::sockaddr_in;
                        let addr_bytes = (*sockaddr_in).sin_addr.s_addr.to_ne_bytes();
                        let ipv4 = Ipv4Addr::new(
                            addr_bytes[0],
                            addr_bytes[1],
                            addr_bytes[2],
                            addr_bytes[3],
                        );
                        iface.ipv4_addrs.push(ipv4);
                    } else if sa_family == libc::AF_INET6 {
                        let sockaddr_in6 = ifa.ifa_addr as *const libc::sockaddr_in6;
                        let addr_bytes = (*sockaddr_in6).sin6_addr.s6_addr;
                        let ipv6 = Ipv6Addr::from(addr_bytes);
                        iface.ipv6_addrs.push(ipv6);
                    }
                }
            }

            current = ifa.ifa_next;
        }

        libc::freeifaddrs(ifaddrs);
    }

    // Filter out interfaces with no addresses and sort by name for consistent ordering
    let mut result: Vec<NetworkInterface> = interfaces
        .into_values()
        .filter(|iface| !iface.ipv4_addrs.is_empty() || !iface.ipv6_addrs.is_empty())
        .collect();
    result.sort_by(|a, b| a.name.cmp(&b.name));
    result
}

impl SystingRecordEvent<SysInfoEvent> for SysinfoRecorder {
    fn ringbuf(&self) -> &RingBuffer<SysInfoEvent> {
        &self.ringbuf
    }
    fn ringbuf_mut(&mut self) -> &mut RingBuffer<SysInfoEvent> {
        &mut self.ringbuf
    }
    fn handle_event(&mut self, event: SysInfoEvent) {
        debug_assert!(
            self.streaming_collector.is_some(),
            "streaming collector must be set before handling events"
        );

        let Some(ref mut collector) = self.streaming_collector else {
            return;
        };

        let cpu = event.cpu;
        let track_id = if let Some(&id) = self.track_ids.get(&cpu) {
            id
        } else {
            // First event for this CPU - create the track
            let track_id = self.counter_track_ids.next_id();

            if let Err(e) = collector.add_counter_track(CounterTrackRecord {
                id: track_id,
                name: format!("CPU {cpu} frequency"),
                unit: Some("Hz".to_string()),
            }) {
                eprintln!("Warning: Failed to create frequency track: {e}");
            }

            self.track_ids.insert(cpu, track_id);
            track_id
        };

        if let Err(e) = collector.add_counter(CounterRecord {
            ts: event.ts as i64,
            track_id,
            value: event.frequency as f64,
        }) {
            eprintln!("Warning: Failed to stream frequency record: {e}");
        }
    }
}

impl SysinfoRecorder {
    /// Set the streaming collector for direct parquet output.
    ///
    /// When set, events will be streamed directly to the collector during
    /// handle_event() instead of being accumulated in memory.
    ///
    /// Note: This recorder writes counter / counter_track rows, the same tables
    /// the perf-counter recorder writes to, so the collector passed here must
    /// share its underlying writer with that recorder (see `SharedCollector`).
    pub fn set_streaming_collector(&mut self, collector: Box<dyn RecordCollector + Send>) {
        self.streaming_collector = Some(collector);
    }

    /// Finish streaming and return the collector.
    ///
    /// Flushes pending data, clears internal state, and returns the collector
    /// for finalization.
    pub fn finish(&mut self) -> Result<Option<Box<dyn RecordCollector + Send>>> {
        if let Some(mut collector) = self.streaming_collector.take() {
            // Data already streamed during handle_event, just flush
            collector.flush()?;
            // Clear track_ids cache
            self.track_ids.clear();
            Ok(Some(collector))
        } else {
            Ok(None)
        }
    }
}

impl SessionRecorder {
    pub fn new(
        enable_debuginfod: bool,
        resolve_network_addresses: bool,
        marker_threshold: Option<u64>,
        marker_duration_threshold: Option<u64>,
        tpu_metrics_enabled: bool,
    ) -> Self {
        let utid_generator = Arc::new(UtidGenerator::new());
        // Counter tracks are written by both the perf-counter and the sysinfo
        // (CPU frequency) recorders into the same counter_track table, so they
        // share one ID generator to keep track IDs unique.
        let counter_track_ids = Arc::new(CounterTrackIdGenerator::new());
        // Track/slice/instant rows are written by both the probe recorder
        // (trace-events/syscalls) and the marker recorder, so they share one ID
        // generator for the same reason.
        let track_event_ids = Arc::new(TrackEventIdGenerator::new());
        Self {
            clock_snapshot: Mutex::new(ClockSnapshot::default()),
            event_recorders: (0..crate::systing_core::NR_RINGBUFS)
                .map(|_| Mutex::new(SchedEventRecorder::new(Arc::clone(&utid_generator))))
                .collect(),
            stack_recorder: Mutex::new(StackRecorder::new(
                enable_debuginfod,
                Arc::clone(&utid_generator),
            )),
            perf_counter_recorder: Mutex::new(PerfCounterRecorder::new(
                Arc::clone(&utid_generator),
                Arc::clone(&counter_track_ids),
            )),
            sysinfo_recorder: Mutex::new(SysinfoRecorder::new(
                Arc::clone(&utid_generator),
                Arc::clone(&counter_track_ids),
            )),
            probe_recorder: Mutex::new(SystingProbeRecorder::new(
                Arc::clone(&utid_generator),
                Arc::clone(&track_event_ids),
            )),
            network_recorder: Mutex::new(NetworkRecorder::new(
                Arc::clone(&utid_generator),
                resolve_network_addresses,
            )),
            memory_recorder: Mutex::new(MemoryRecorder::new(Arc::clone(&utid_generator))),
            marker_recorder: Mutex::new(
                MarkerRecorder::new(Arc::clone(&utid_generator), Arc::clone(&track_event_ids))
                    .with_threshold(marker_threshold)
                    .with_duration_threshold(marker_duration_threshold),
            ),
            tpu_metrics_recorder: if tpu_metrics_enabled {
                Some(Mutex::new(TpuMetricsRecorder::new()))
            } else {
                None
            },
            process_descriptors: RwLock::new(HashMap::new()),
            processes: RwLock::new(HashMap::new()),
            threads: RwLock::new(HashMap::new()),
            process_cgroups: RwLock::new(HashMap::new()),
            kernel_threads: RwLock::new(HashSet::new()),
            utid_generator,
            clock_sampling: OnceLock::new(),
        }
    }

    /// Check if a task is a process (pid == tgid)
    fn is_process(info: &task_info) -> bool {
        let pid = info.tgidpid as i32;
        let tgid = (info.tgidpid >> 32) as i32;
        pid == tgid
    }

    /// Extract comm from task_info
    fn extract_comm(info: &task_info) -> String {
        CStr::from_bytes_until_nul(&info.comm)
            .ok()
            .and_then(|s| s.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_default()
    }

    fn fetch_name_from_proc(pid: u32) -> String {
        let exe_path = Path::new("/proc").join(pid.to_string()).join("exe");
        if let Ok(exe) = fs::read_link(&exe_path) {
            if let Some(name) = exe.file_name() {
                let name_str = name.to_string_lossy();
                // Strip " (deleted)" suffix that Linux appends when a binary has
                // been replaced on disk (e.g., during upgrades). Note: this would
                // incorrectly strip the suffix from a binary literally named
                // "foo (deleted)", but that is not a realistic concern.
                return name_str
                    .strip_suffix(" (deleted)")
                    .unwrap_or(&name_str)
                    .to_string();
            }
        }
        String::new()
    }

    fn fetch_cmdline_from_proc(pid: u32) -> Vec<String> {
        let cmdline_path = Path::new("/proc").join(pid.to_string()).join("cmdline");
        if let Ok(data) = fs::read(&cmdline_path) {
            // cmdline is null-separated
            data.split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).to_string())
                .collect()
        } else {
            vec![]
        }
    }

    fn record_new_process(&self, info: &task_info) {
        let comm = Self::extract_comm(info);
        let pid = (info.tgidpid >> 32) as u32;

        // Prefer /proc/PID/exe over BPF comm for process names: exe is stable
        // and consistent regardless of which thread is observed first, while comm
        // is limited to 15 chars and non-deterministic (child thread names can
        // leak to the process when the child is seen before the main thread).
        // Note: record_new_thread() uses the opposite priority (comm first)
        // because thread names set via pthread_setname_np (e.g., "gc-worker-3")
        // are more informative than the binary filename.
        let name_from_proc = Self::fetch_name_from_proc(pid);
        let process_name = if !name_from_proc.is_empty() {
            name_from_proc.clone()
        } else if !comm.is_empty() {
            comm
        } else {
            format!("<pid:{pid}>")
        };

        let cmdline = Self::fetch_cmdline_from_proc(pid);

        // Detect kernel threads: no executable AND no cmdline AND /proc/pid exists.
        // Kernel threads have no /proc/pid/exe (readlink fails) and no cmdline.
        // Short-lived processes that already exited will have /proc/pid gone entirely,
        // so we only mark as kernel thread if the process dir still exists.
        //
        // Limitations: This is a heuristic, not atomic. Zombie processes could be
        // misidentified since they also lack exe/cmdline but still have /proc/pid.
        // A more reliable approach would be to check /proc/pid/status for PF_KTHREAD,
        // but the false positive rate here is negligible in practice.
        if name_from_proc.is_empty()
            && cmdline.is_empty()
            && pid != 0
            && Path::new("/proc").join(pid.to_string()).exists()
        {
            self.kernel_threads.write().unwrap().insert(pid);
        }

        // Create and store ProcessDescriptor
        let mut process_descriptor = ProcessDescriptor::default();
        process_descriptor.set_pid(info.tgidpid as i32);
        process_descriptor.set_process_name(process_name);

        self.process_descriptors
            .write()
            .unwrap()
            .insert(info.tgidpid, process_descriptor);

        // Create and store ProtoProcess
        let proto_process = ProtoProcess {
            cmdline,
            pid: Some(info.tgidpid as i32),
            ..ProtoProcess::default()
        };

        self.processes
            .write()
            .unwrap()
            .insert(info.tgidpid, proto_process);

        // Record the cgroup id observed for this process. `info` may be a synthetic
        // parent built from a thread we saw (when the main thread was never observed),
        // in which case this carries that thread's cgroup id. We attribute the whole
        // process to the first-observed task's cgroup; in a cgroup v2 threaded
        // subtree (or cgroup v1) sibling threads can live in different cgroups, so
        // this is the representative cgroup rather than a guaranteed per-thread one.
        self.process_cgroups
            .write()
            .unwrap()
            .insert(info.tgidpid, info.cgid);
    }

    fn record_new_thread(&self, info: &task_info) {
        let comm = Self::extract_comm(info);
        let tid = info.tgidpid as u32;

        let thread_name = if !comm.is_empty() {
            comm
        } else {
            let name_from_proc = Self::fetch_name_from_proc(tid);
            if !name_from_proc.is_empty() {
                name_from_proc
            } else {
                // Fallback to tid as name when both comm and /proc lookup fail
                format!("<tid:{tid}>")
            }
        };

        // Create and store ThreadDescriptor
        let mut thread_descriptor = ThreadDescriptor::default();
        thread_descriptor.set_tid(info.tgidpid as i32);
        thread_descriptor.set_pid((info.tgidpid >> 32) as i32);
        thread_descriptor.set_thread_name(thread_name);

        self.threads
            .write()
            .unwrap()
            .insert(info.tgidpid, thread_descriptor);
    }

    pub fn maybe_record_task(&self, info: &task_info) {
        // Always record ALL tasks as threads - this ensures every tid that appears
        // in sched events has a corresponding thread record in parquet files.
        // For Perfetto output, write_thread_packets filters out main threads (tid == pid)
        // since those are represented by ProcessDescriptor instead of ThreadDescriptor.
        if !self.threads.read().unwrap().contains_key(&info.tgidpid) {
            self.record_new_thread(info);
        }

        // Also maintain process metadata for Perfetto generation.
        // Note: record_new_process only writes to process_descriptors, not to threads.
        // The thread entry was already added above, so main threads end up in both
        // collections (threads for parquet, process_descriptors for Perfetto).
        let tgid = info.tgidpid >> 32;
        let process_tgidpid = (tgid << 32) | tgid; // process has pid == tgid

        if !self
            .process_descriptors
            .read()
            .unwrap()
            .contains_key(&process_tgidpid)
        {
            if Self::is_process(info) {
                // This is the main thread - use its info directly
                self.record_new_process(info);
            } else {
                // Create a synthetic task_info for the parent process
                let mut parent_info = *info;
                parent_info.tgidpid = process_tgidpid;
                self.record_new_process(&parent_info);
            }
        }
    }

    pub fn drain_all_ringbufs(&self) {
        for event_recorder in &self.event_recorders {
            event_recorder.lock().unwrap().drain_ringbuf();
        }
        self.stack_recorder.lock().unwrap().drain_ringbuf();
        self.perf_counter_recorder.lock().unwrap().drain_ringbuf();
        self.sysinfo_recorder.lock().unwrap().drain_ringbuf();
        self.probe_recorder.lock().unwrap().drain_ringbuf();
        self.network_recorder.lock().unwrap().drain_ringbuf();
        self.marker_recorder.lock().unwrap().drain_ringbuf();
    }

    pub fn snapshot_clocks(&self) {
        let mut clock_snapshot = self.clock_snapshot.lock().unwrap();
        clock_snapshot.set_primary_trace_clock(BuiltinClock::BUILTIN_CLOCK_BOOTTIME);

        let mut clock = Clock::default();
        clock.set_clock_id(BuiltinClock::BUILTIN_CLOCK_MONOTONIC as u32);
        clock.set_timestamp(get_clock_value(libc::CLOCK_MONOTONIC));
        clock_snapshot.clocks.push(clock);

        let mut clock = Clock::default();
        clock.set_clock_id(BuiltinClock::BUILTIN_CLOCK_BOOTTIME as u32);
        clock.set_timestamp(get_clock_value(libc::CLOCK_BOOTTIME));
        clock_snapshot.clocks.push(clock);

        let mut clock = Clock::default();
        clock.set_clock_id(BuiltinClock::BUILTIN_CLOCK_REALTIME as u32);
        clock.set_timestamp(get_clock_value(libc::CLOCK_REALTIME));
        clock_snapshot.clocks.push(clock);

        let mut clock = Clock::default();
        clock.set_clock_id(BuiltinClock::BUILTIN_CLOCK_REALTIME_COARSE as u32);
        clock.set_timestamp(get_clock_value(libc::CLOCK_REALTIME_COARSE));
        clock_snapshot.clocks.push(clock);

        let mut clock = Clock::default();
        clock.set_clock_id(BuiltinClock::BUILTIN_CLOCK_MONOTONIC_COARSE as u32);
        clock.set_timestamp(get_clock_value(libc::CLOCK_MONOTONIC_COARSE));
        clock_snapshot.clocks.push(clock);

        let mut clock = Clock::default();
        clock.set_clock_id(BuiltinClock::BUILTIN_CLOCK_MONOTONIC_RAW as u32);
        clock.set_timestamp(get_clock_value(libc::CLOCK_MONOTONIC_RAW));
        clock_snapshot.clocks.push(clock);
    }

    /// Write network interface records to the RecordCollector.
    ///
    /// Collects network interface metadata from all recorded processes' network namespaces
    /// and writes them as NetworkInterfaceRecord entries.
    fn write_network_interface_records(&self, writer: &mut dyn RecordCollector) -> Result<()> {
        use crate::trace::NetworkInterfaceRecord;

        // Get host network namespace inode for comparison
        let host_netns_inode = get_host_netns_inode();

        // Build a map of unique network namespaces from recorded processes
        let mut netns_map: HashMap<u64, NetnsInfo> = HashMap::new();

        // First, add the host namespace
        if let Some(host_inode) = host_netns_inode {
            netns_map.insert(
                host_inode,
                NetnsInfo {
                    inode: host_inode,
                    representative_pid: 1,
                    container_id: None,
                    comm: "host".to_string(),
                    is_host: true,
                },
            );
        }

        // Iterate through all recorded processes to find unique network namespaces
        for tgidpid in self.process_descriptors.read().unwrap().keys() {
            let pid = (*tgidpid >> 32) as u32;

            if let Some(inode) = get_netns_inode(pid) {
                netns_map.entry(inode).or_insert_with(|| {
                    let is_host = host_netns_inode == Some(inode);
                    NetnsInfo {
                        inode,
                        representative_pid: pid,
                        container_id: if is_host { None } else { get_container_id(pid) },
                        comm: get_comm(pid),
                        is_host,
                    }
                });
            }
        }

        // Sort namespaces: host first, then by inode for consistent ordering
        let mut namespaces: Vec<_> = netns_map.into_values().collect();
        namespaces.sort_by(|a, b| match (a.is_host, b.is_host) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.inode.cmp(&b.inode),
        });

        // Generate records for each namespace
        for netns_info in namespaces {
            // Create namespace name
            let netns_name = netns_info.display_name();

            // Get interfaces for this namespace
            let interfaces = if netns_info.is_host {
                get_network_interfaces()
            } else {
                get_interfaces_in_netns(netns_info.representative_pid)
            };

            // Write a record for each interface and IP address
            for iface in interfaces {
                // Write IPv4 addresses
                for ipv4 in iface.ipv4_addrs {
                    writer.add_network_interface(NetworkInterfaceRecord {
                        namespace: netns_name.clone(),
                        interface_name: iface.name.clone(),
                        ip_address: ipv4.to_string(),
                        address_type: "ipv4".to_string(),
                    })?;
                }

                // Write IPv6 addresses
                for ipv6 in iface.ipv6_addrs {
                    writer.add_network_interface(NetworkInterfaceRecord {
                        namespace: netns_name.clone(),
                        interface_name: iface.name.clone(),
                        ip_address: ipv6.to_string(),
                        address_type: "ipv6".to_string(),
                    })?;
                }
            }
        }

        Ok(())
    }

    /// Initialize streaming parquet output for the scheduler, stack, and network recorders.
    /// This must be called BEFORE recording starts to enable streaming of events
    /// directly to the configured `sink` (a local directory or a socket
    /// endpoint; see [`ParquetSink`]).
    pub fn init_streaming_output(&self, sink: &ParquetSink) -> Result<()> {
        let make_writer = || StreamingParquetWriter::for_sink(sink.clone());
        let spill_dir = sink.spill_dir();

        // Set up streaming collectors for the scheduler event recorder shards.
        // All shards write rows for the same logical tables (sched_slice,
        // thread_state, ...), which map to the same parquet files, so they
        // must share one underlying writer: separate writers would create the
        // same files and the last one to finish would clobber the others'
        // data (same reasoning as the perf-counter/sysinfo SharedCollector
        // below). Rows from different shards interleave in the files; readers
        // sort by timestamp where order matters. Each shard buffers records
        // locally and hands them over in batches, so the shared writer's lock
        // is not a per-event serialization point.
        let sched_writer = SharedCollector::new(Box::new(make_writer()));
        for event_recorder in &self.event_recorders {
            event_recorder
                .lock()
                .unwrap()
                .set_streaming_collector(Box::new(sched_writer.clone()));
        }
        drop(sched_writer);

        // Set up streaming collector for stack recorder so samples are written
        // incrementally instead of buffered for the entire trace. Unique stack
        // contents are spilled to a tempfile under the sink's spill directory so
        // they don't accumulate in memory until end-of-trace symbolization.
        {
            let mut stack_recorder = self.stack_recorder.lock().unwrap();
            stack_recorder.set_streaming_collector(Box::new(make_writer()));
            stack_recorder.set_spill_dir(spill_dir);
        }

        // Set up streaming collector for network recorder (events emitted immediately)
        self.network_recorder
            .lock()
            .unwrap()
            .set_streaming_collector(Box::new(make_writer()));

        // Set up streaming collector for memory recorder (events emitted
        // immediately). Its unique alloc/fault stacks spill to disk like the
        // stack recorder's.
        {
            let mut memory_recorder = self.memory_recorder.lock().unwrap();
            memory_recorder.set_streaming_collector(Box::new(make_writer()));
            memory_recorder.set_spill_dir(spill_dir);
        }

        // Set up streaming collector for probe recorder (events emitted on completion).
        // Note: marker records are also written through this collector during
        // generate_parquet_trace - markers share the track/slice/instant tables with
        // probe events, so writing them through a separate writer would clobber the
        // probe data (see the marker-write step in generate_parquet_trace).
        self.probe_recorder
            .lock()
            .unwrap()
            .set_streaming_collector(Box::new(make_writer()));

        // The perf-counter and sysinfo (CPU frequency) recorders both emit
        // counter / counter_track rows, which map to the same counter.parquet /
        // counter_track.parquet files. They must share a single writer: with
        // separate writers both would create the same files and the last one to
        // finish would clobber the other's data. Track IDs come from the shared
        // CounterTrackIdGenerator so they never collide either.
        let counter_writer = SharedCollector::new(Box::new(make_writer()));
        self.perf_counter_recorder
            .lock()
            .unwrap()
            .set_streaming_collector(Box::new(counter_writer.clone()));
        self.sysinfo_recorder
            .lock()
            .unwrap()
            .set_streaming_collector(Box::new(counter_writer));

        // Set up streaming collector for TPU metrics recorder (if enabled).
        if let Some(ref tpu_metrics) = self.tpu_metrics_recorder {
            tpu_metrics
                .lock()
                .unwrap()
                .set_streaming_collector(Box::new(make_writer()));
        }

        Ok(())
    }

    /// Finalize the streaming parquet trace.
    ///
    /// Flushes all streaming recorders and writes process/thread metadata to
    /// the configured sink. Streaming must have been initialized via
    /// `init_streaming_output` before calling this method.
    pub fn generate_parquet_trace(
        &self,
        tpu_recorder: Option<crate::tpu::recorder::TpuRecorder>,
    ) -> Result<()> {
        // Per-stage elapsed lines below let fleet log pipelines attribute
        // stop-phase cost without relying on collector timestamp granularity.
        let gen_start = std::time::Instant::now();
        let mut stage_start = gen_start;
        let stage_done = |label: &str, start: &mut std::time::Instant| {
            eprintln!("{} in {:.2}s", label, start.elapsed().as_secs_f64());
            *start = std::time::Instant::now();
        };
        eprintln!("Generating Parquet trace...");

        // Get the end timestamp for flushing streaming data
        let end_ts = get_clock_value(libc::CLOCK_BOOTTIME) as i64;

        // Step 1: Finish streaming collection in every event recorder shard
        // and retrieve the collector. The shards share one underlying writer
        // through SharedCollector handles; keep the last handle as the main
        // writer (the records are all in the shared inner writer, so the
        // other handles can simply be dropped) and finalize it in step 6,
        // by which point it is the only live handle.
        eprintln!("Flushing scheduler trace records from streaming...");
        let mut sched_collectors = Vec::new();
        for event_recorder in &self.event_recorders {
            if let Some(collector) = event_recorder.lock().unwrap().finish(end_ts)? {
                sched_collectors.push(collector);
            }
        }

        // The streaming collector has scheduler data already written
        let mut writer: Box<dyn RecordCollector + Send> =
            sched_collectors.pop().ok_or_else(|| {
                anyhow::anyhow!("streaming collector must be initialized before generating trace")
            })?;
        drop(sched_collectors);
        stage_done("Flushed scheduler trace records", &mut stage_start);

        // Step 2: Generate clock snapshot records
        eprintln!("Writing clock snapshot...");
        let clock_snapshot = self.clock_snapshot.lock().unwrap();
        for clock in clock_snapshot.clocks.iter() {
            let clock_name = if clock.has_clock_id() {
                match clock.clock_id() as i32 {
                    x if x == BuiltinClock::BUILTIN_CLOCK_BOOTTIME as i32 => "boottime".to_string(),
                    x if x == BuiltinClock::BUILTIN_CLOCK_MONOTONIC as i32 => {
                        "monotonic".to_string()
                    }
                    x if x == BuiltinClock::BUILTIN_CLOCK_REALTIME as i32 => "realtime".to_string(),
                    other => format!("clock_{other}"),
                }
            } else {
                "unknown".to_string()
            };

            // BOOTTIME is the primary trace clock (as set in write_initial_packets)
            let is_primary = clock.clock_id() == BuiltinClock::BUILTIN_CLOCK_BOOTTIME as u32;

            writer.add_clock_snapshot(ClockSnapshotRecord {
                clock_id: clock.clock_id() as i32,
                clock_name,
                timestamp_ns: clock.timestamp() as i64,
                is_primary,
            })?;
        }
        drop(clock_snapshot);

        // Write system info (utsname + platform provenance)
        if let Some(utsname) = get_system_utsname() {
            let clock_sampling = self.clock_sampling.get();
            writer.set_sysinfo(crate::trace::SysInfoRecord {
                sysname: utsname.sysname().to_string(),
                release: utsname.release().to_string(),
                version: utsname.version().to_string(),
                machine: utsname.machine().to_string(),
                cpufreq_driver: cpufreq_scaling_driver(),
                hypervisor: detect_hypervisor(),
                sys_vendor: dmi_sys_vendor(),
                product_name: dmi_product_name(),
                sample_event: clock_sampling.map(|c| c.event.to_string()),
                sample_period: clock_sampling.map(|c| c.period as i64),
            })?;
        }

        // Write per-CPU frequency limits so cycle-denominated stack samples
        // can be converted to approximate time during analysis. Empty (no
        // rows) on systems without cpufreq support.
        for cpu in cpu_freq_limits() {
            writer.add_cpu_info(crate::trace::CpuInfoRecord {
                cpu: cpu.cpu as i32,
                min_freq_khz: cpu.min_freq_khz,
                max_freq_khz: cpu.max_freq_khz,
                base_freq_khz: cpu.base_freq_khz,
            })?;
        }

        // Step 3: Generate process and thread records
        // Use the shared UtidGenerator to get consistent utid/upid values that match
        // what was used during streaming.
        eprintln!("Writing process and thread data...");

        // Write process records using the shared upid generator
        let processes = self.processes.read().unwrap();
        let kernel_threads = self.kernel_threads.read().unwrap();
        let process_cgroups = self.process_cgroups.read().unwrap();
        // Snapshot the live cgroup hierarchy once so we can resolve the numeric
        // cgroup id recorded for each process into a human-readable path. This is
        // best-effort: cgroups removed before this point simply will not resolve.
        let cgroup_id_map = crate::cgroup::build_cgroup_id_map();
        for (tgidpid, process) in self.process_descriptors.read().unwrap().iter() {
            let pid = process.pid();
            let upid = self.utid_generator.get_or_create_upid(pid);

            let name = if process.has_process_name() {
                Some(process.process_name().to_string())
            } else {
                None
            };

            // Get cmdline from the ProtoProcess stored in self.processes
            let cmdline = processes
                .get(tgidpid)
                .map(|p| p.cmdline.clone())
                .unwrap_or_default();

            let is_kernel_thread = kernel_threads.contains(&((*tgidpid >> 32) as u32));

            let cgroup_id = process_cgroups.get(tgidpid).copied().unwrap_or(0);
            let cgroup_path = cgroup_id_map.get(&cgroup_id).cloned();

            writer.add_process(ProcessRecord {
                upid,
                pid,
                name,
                parent_upid: None, // Could be set from parent_pid if needed
                cmdline,
                is_kernel_thread,
                cgroup_id,
                cgroup_path,
            })?;
        }
        drop(processes);
        drop(process_cgroups);

        // Write thread records using the shared utid generator
        // Threads seen during streaming already have utids assigned; new threads get new utids
        for thread in self.threads.read().unwrap().values() {
            let tid = thread.tid();
            // Use existing utid from streaming, or create new one if not seen during streaming
            let utid = self.utid_generator.get_or_create_utid(tid);

            let name = if thread.has_thread_name() {
                Some(thread.thread_name().to_string())
            } else {
                None
            };

            // Get upid from generator (pid in ThreadDescriptor is the tgid/process id)
            let upid = if thread.has_pid() {
                self.utid_generator.get_upid(thread.pid())
            } else {
                None
            };

            writer.add_thread(ThreadRecord {
                utid,
                tid,
                name,
                upid,
            })?;
        }

        // Step 4: Generate network interface metadata
        eprintln!("Writing network interface metadata...");
        self.write_network_interface_records(&mut *writer)?;
        stage_done("Wrote metadata records", &mut stage_start);

        // Step 5: Flush streaming records from all recorders
        // Scheduler trace records were already written via streaming above.

        eprintln!("Flushing memory trace records...");
        {
            let mut memory = self.memory_recorder.lock().unwrap();
            let memory_interner = memory.take_interner();
            if memory_interner.total() > 0 {
                self.stack_recorder
                    .lock()
                    .unwrap()
                    .merge_external_interner(memory_interner);
            }
            writer = memory.finish(writer)?;
        }
        stage_done("Flushed memory trace records", &mut stage_start);

        eprintln!("Flushing stack samples and symbolizing stacks...");
        writer = self.stack_recorder.lock().unwrap().finish(writer)?;
        stage_done("Flushed and symbolized stack samples", &mut stage_start);

        eprintln!("Flushing network trace records...");
        if let Some(network_collector) = self.network_recorder.lock().unwrap().finish()? {
            network_collector.finish_boxed()?;
        }
        stage_done("Flushed network trace records", &mut stage_start);

        eprintln!("Flushing perf counter records from streaming...");
        if let Some(perf_collector) = self.perf_counter_recorder.lock().unwrap().finish()? {
            perf_collector.finish_boxed()?;
        }
        stage_done("Flushed perf counter records", &mut stage_start);

        eprintln!("Flushing sysinfo records from streaming...");
        if let Some(sysinfo_collector) = self.sysinfo_recorder.lock().unwrap().finish()? {
            sysinfo_collector.finish_boxed()?;
        }
        stage_done("Flushed sysinfo records", &mut stage_start);

        // The probe recorder (trace-events/syscalls) and the marker recorder both
        // emit track/slice/instant/args rows, which map to the same parquet files.
        // Markers must therefore be written through the probe recorder's collector:
        // writing them through the main writer would recreate the same files and
        // whichever writer closed last would clobber the other's data. (Track/slice/
        // instant IDs can't collide either - both recorders allocate them from the
        // shared TrackEventIdGenerator.)
        eprintln!("Flushing probe trace records...");
        let mut track_writer = self
            .probe_recorder
            .lock()
            .unwrap()
            .finish()?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "probe streaming collector must be initialized before generating trace"
                )
            })?;

        // Write marker records (only if any were collected)
        {
            let marker_recorder = self.marker_recorder.lock().unwrap();
            if marker_recorder.has_data() {
                eprintln!("Writing marker records...");
                marker_recorder.write_records(&mut *track_writer)?;
            }
        }
        track_writer.finish_boxed()?;
        stage_done("Flushed probe trace records", &mut stage_start);

        // Write TPU profiling records (if any were captured). TPU device/op IDs are
        // only referenced within the tpu_* tables, which nothing else writes, so
        // write_records assigns them internally.
        let has_tpu = tpu_recorder.is_some() || self.tpu_metrics_recorder.is_some();
        if let Some(tpu) = tpu_recorder {
            eprintln!("Writing TPU profiling records...");
            tpu.write_records(&mut *writer)?;
        }

        // Finish TPU metrics streaming collector (if enabled)
        if let Some(ref tpu_metrics) = self.tpu_metrics_recorder {
            if let Some(collector) = tpu_metrics.lock().unwrap().finish()? {
                collector.finish_boxed()?;
            }
        }
        if has_tpu {
            stage_done("Wrote TPU records", &mut stage_start);
        }

        // Step 6: Finish writing and close all files
        eprintln!("Finishing Parquet trace...");
        // Flush and properly close all Parquet writers
        writer.finish_boxed()?;
        stage_done("Finished Parquet writers", &mut stage_start);

        eprintln!(
            "Parquet trace generation complete in {:.2}s.",
            gen_start.elapsed().as_secs_f64()
        );
        Ok(())
    }
}

impl crate::systing_core::SystingEvent for SysInfoEvent {
    fn ts(&self) -> u64 {
        self.ts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::perfetto::{TraceWriter, VecTraceWriter};
    use perfetto_protos::process_tree::ProcessTree;
    use perfetto_protos::system_info::SystemInfo;
    use perfetto_protos::trace_packet::TracePacket;
    use perfetto_protos::track_descriptor::TrackDescriptor;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Mutex, RwLock};

    // PIDs above Linux's pid_max (4194304) to ensure /proc lookups never
    // resolve to real processes, keeping test assertions deterministic.
    const TEST_PID_A: u32 = 5_000_001;
    const TEST_PID_B: u32 = 5_000_002;
    const TEST_TID_A: u32 = 5_000_011;
    const TEST_TID_B: u32 = 5_000_012;
    const TEST_TID_C: u32 = 5_000_013;
    const TEST_TID_D: u32 = 5_000_014;

    // =========================================================================
    // Test-only helper functions (moved from SessionRecorder impl)
    // =========================================================================

    /// Gets the minimum timestamp from all recorded events across all recorders.
    fn get_min_event_timestamp(recorder: &SessionRecorder) -> u64 {
        [
            recorder.network_recorder.lock().unwrap().min_timestamp(),
            recorder.marker_recorder.lock().unwrap().min_timestamp(),
        ]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or_else(|| get_clock_value(libc::CLOCK_BOOTTIME))
    }

    /// Writes the initial trace packets including clock snapshot and root descriptor
    fn write_initial_packets(
        recorder: &SessionRecorder,
        writer: &mut dyn TraceWriter,
        id_counter: &Arc<AtomicUsize>,
    ) -> Result<()> {
        // Emit the clock snapshot
        let mut packet = TracePacket::default();
        packet.set_clock_snapshot(recorder.clock_snapshot.lock().unwrap().clone());
        packet.set_trusted_packet_sequence_id(id_counter.fetch_add(1, Ordering::Relaxed) as u32);
        writer.write_packet(&packet)?;

        // Emit SystemInfo with UtsName in a separate packet (both are in oneof data)
        if let Some(utsname) = get_system_utsname() {
            let system_info = SystemInfo {
                utsname: Some(utsname).into(),
                ..Default::default()
            };

            let mut packet = TracePacket::default();
            packet.set_system_info(system_info);
            packet
                .set_trusted_packet_sequence_id(id_counter.fetch_add(1, Ordering::Relaxed) as u32);
            writer.write_packet(&packet)?;
        }

        // Add the root Systing track descriptor
        let systing_desc_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;
        let mut desc = TrackDescriptor::default();
        desc.set_uuid(systing_desc_uuid);
        desc.set_name("Systing".to_string());

        let mut packet = TracePacket::default();
        packet.set_track_descriptor(desc);
        writer.write_packet(&packet)?;

        Ok(())
    }

    /// Writes trace packets for all processes
    fn write_process_packets(
        recorder: &SessionRecorder,
        writer: &mut dyn TraceWriter,
        id_counter: &Arc<AtomicUsize>,
        pid_uuids: &mut HashMap<i32, u64>,
    ) -> Result<()> {
        // Generate process track descriptors
        for process in recorder.process_descriptors.read().unwrap().values() {
            let uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;
            pid_uuids.insert(process.pid(), uuid);

            let mut desc = TrackDescriptor::default();
            desc.set_uuid(uuid);
            desc.process = Some(process.clone()).into();

            let mut packet = TracePacket::default();
            packet.set_track_descriptor(desc);
            writer.write_packet(&packet)?;
        }

        // Generate process trees
        for process in recorder.processes.read().unwrap().values() {
            let process_tree = ProcessTree {
                processes: vec![process.clone()],
                ..ProcessTree::default()
            };

            let mut packet = TracePacket::default();
            packet.set_process_tree(process_tree);
            writer.write_packet(&packet)?;
        }

        Ok(())
    }

    /// Writes trace packets for all threads (excluding main threads).
    fn write_thread_packets(
        recorder: &SessionRecorder,
        writer: &mut dyn TraceWriter,
        id_counter: &Arc<AtomicUsize>,
        thread_uuids: &mut HashMap<i32, u64>,
    ) -> Result<()> {
        for thread in recorder.threads.read().unwrap().values() {
            // Skip main threads - they're represented by ProcessDescriptor, not ThreadDescriptor.
            if thread.tid() == thread.pid() {
                continue;
            }

            let uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;
            thread_uuids.insert(thread.tid(), uuid);

            let mut desc = TrackDescriptor::default();
            desc.set_uuid(uuid);
            desc.thread = Some(thread.clone()).into();

            let mut packet = TracePacket::default();
            packet.set_track_descriptor(desc);
            writer.write_packet(&packet)?;
        }

        Ok(())
    }

    // =========================================================================
    // Test helper functions that use the above
    // =========================================================================

    /// Helper to collect process packets for tests
    fn generate_process_packets(
        recorder: &SessionRecorder,
        id_counter: &Arc<AtomicUsize>,
        pid_uuids: &mut HashMap<i32, u64>,
    ) -> Vec<TracePacket> {
        let mut writer = VecTraceWriter::new();
        write_process_packets(recorder, &mut writer, id_counter, pid_uuids).unwrap();
        writer.packets
    }

    /// Helper to collect thread packets for tests
    fn generate_thread_packets(
        recorder: &SessionRecorder,
        id_counter: &Arc<AtomicUsize>,
        thread_uuids: &mut HashMap<i32, u64>,
    ) -> Vec<TracePacket> {
        let mut writer = VecTraceWriter::new();
        write_thread_packets(recorder, &mut writer, id_counter, thread_uuids).unwrap();
        writer.packets
    }

    /// Helper to collect initial packets for tests
    fn generate_initial_packets(
        recorder: &SessionRecorder,
        id_counter: &Arc<AtomicUsize>,
    ) -> Vec<TracePacket> {
        let mut writer = VecTraceWriter::new();
        write_initial_packets(recorder, &mut writer, id_counter).unwrap();
        writer.packets
    }

    fn create_test_task_info(tgid: u32, pid: u32, comm: &str) -> task_info {
        let mut task = task_info {
            tgidpid: ((tgid as u64) << 32) | (pid as u64),
            cgid: 0,
            comm: [0; 16],
        };

        // Copy the comm string into the array
        let comm_bytes = comm.as_bytes();
        let copy_len = std::cmp::min(comm_bytes.len(), task.comm.len() - 1); // Leave space for null terminator
        task.comm[..copy_len].copy_from_slice(&comm_bytes[..copy_len]);
        task.comm[copy_len] = 0; // Null terminator

        task
    }

    fn create_test_session_recorder() -> SessionRecorder {
        let utid_generator = Arc::new(UtidGenerator::new());
        let counter_track_ids = Arc::new(CounterTrackIdGenerator::new());
        let track_event_ids = Arc::new(TrackEventIdGenerator::new());
        SessionRecorder {
            clock_snapshot: Mutex::new(ClockSnapshot::default()),
            event_recorders: (0..crate::systing_core::NR_RINGBUFS)
                .map(|_| Mutex::new(SchedEventRecorder::new(Arc::clone(&utid_generator))))
                .collect(),
            stack_recorder: Mutex::new(StackRecorder::new(false, Arc::clone(&utid_generator))),
            perf_counter_recorder: Mutex::new(PerfCounterRecorder::new(
                Arc::clone(&utid_generator),
                Arc::clone(&counter_track_ids),
            )),
            sysinfo_recorder: Mutex::new(SysinfoRecorder::new(
                Arc::clone(&utid_generator),
                Arc::clone(&counter_track_ids),
            )),
            probe_recorder: Mutex::new(SystingProbeRecorder::new(
                Arc::clone(&utid_generator),
                Arc::clone(&track_event_ids),
            )),
            network_recorder: Mutex::new(NetworkRecorder::new(Arc::clone(&utid_generator), false)),
            memory_recorder: Mutex::new(MemoryRecorder::new(Arc::clone(&utid_generator))),
            marker_recorder: Mutex::new(MarkerRecorder::new(
                Arc::clone(&utid_generator),
                Arc::clone(&track_event_ids),
            )),
            process_descriptors: RwLock::new(HashMap::new()),
            processes: RwLock::new(HashMap::new()),
            threads: RwLock::new(HashMap::new()),
            process_cgroups: RwLock::new(HashMap::new()),
            kernel_threads: RwLock::new(HashSet::new()),
            utid_generator,
            tpu_metrics_recorder: None,
            clock_sampling: OnceLock::new(),
        }
    }

    #[test]
    fn test_fetch_name_from_proc_current_process() {
        // The test process itself should have a valid /proc/PID/exe
        let pid = std::process::id();
        let name = SessionRecorder::fetch_name_from_proc(pid);
        assert!(!name.is_empty(), "should resolve current process exe");
    }

    #[test]
    fn test_fetch_name_from_proc_nonexistent_pid() {
        // A PID above pid_max should not exist
        let name = SessionRecorder::fetch_name_from_proc(u32::MAX);
        assert!(name.is_empty(), "should return empty for nonexistent PID");
    }

    #[test]
    fn test_maybe_record_task_new_process() {
        let recorder = create_test_session_recorder();
        let task = create_test_task_info(TEST_PID_A, TEST_PID_A, "test_process");

        // Initially, no processes should be recorded
        assert!(recorder.process_descriptors.read().unwrap().is_empty());
        assert!(recorder.processes.read().unwrap().is_empty());

        // Record the task
        recorder.maybe_record_task(&task);

        // Now the process should be recorded
        let process_descriptors = recorder.process_descriptors.read().unwrap();
        assert_eq!(process_descriptors.len(), 1);
        assert!(process_descriptors.contains_key(&task.tgidpid));

        let process_desc = process_descriptors.get(&task.tgidpid).unwrap();
        assert_eq!(process_desc.pid(), TEST_PID_A as i32);
        assert_eq!(process_desc.process_name(), "test_process");

        // Check that the process tree entry was also created
        let processes = recorder.processes.read().unwrap();
        assert_eq!(processes.len(), 1);
        assert!(processes.contains_key(&task.tgidpid));

        let process = processes.get(&task.tgidpid).unwrap();
        assert_eq!(process.pid, Some(task.tgidpid as i32));
    }

    #[test]
    fn test_maybe_record_task_new_thread() {
        let recorder = create_test_session_recorder();
        let task = create_test_task_info(TEST_PID_A, TEST_TID_A, "test_thread");

        // Initially, no threads should be recorded
        assert!(recorder.threads.read().unwrap().is_empty());

        // Record the task
        recorder.maybe_record_task(&task);

        // Now the thread should be recorded
        let threads = recorder.threads.read().unwrap();
        assert_eq!(threads.len(), 1);
        assert!(threads.contains_key(&task.tgidpid));

        let thread_desc = threads.get(&task.tgidpid).unwrap();
        assert_eq!(thread_desc.tid(), TEST_TID_A as i32);
        assert_eq!(thread_desc.pid(), TEST_PID_A as i32);
        assert_eq!(thread_desc.thread_name(), "test_thread");

        // Parent process should also be recorded when recording a thread
        let process_descriptors = recorder.process_descriptors.read().unwrap();
        assert_eq!(process_descriptors.len(), 1);
        let parent_tgidpid = (TEST_PID_A as u64) << 32 | TEST_PID_A as u64;
        assert!(process_descriptors.contains_key(&parent_tgidpid));
    }

    #[test]
    fn test_maybe_record_task_duplicate_process() {
        let recorder = create_test_session_recorder();
        let task = create_test_task_info(TEST_PID_A, TEST_PID_A, "test_process");

        // Record the task twice
        recorder.maybe_record_task(&task);
        recorder.maybe_record_task(&task);

        // Should still only have one entry
        let process_descriptors = recorder.process_descriptors.read().unwrap();
        assert_eq!(process_descriptors.len(), 1);

        let processes = recorder.processes.read().unwrap();
        assert_eq!(processes.len(), 1);
    }

    #[test]
    fn test_maybe_record_task_duplicate_thread() {
        let recorder = create_test_session_recorder();
        let task = create_test_task_info(TEST_PID_A, TEST_TID_A, "test_thread");

        // Record the task twice
        recorder.maybe_record_task(&task);
        recorder.maybe_record_task(&task);

        // Should still only have one entry
        let threads = recorder.threads.read().unwrap();
        assert_eq!(threads.len(), 1);
    }

    #[test]
    fn test_maybe_record_task_multiple_processes() {
        let recorder = create_test_session_recorder();
        let task1 = create_test_task_info(TEST_PID_A, TEST_PID_A, "process1");
        let task2 = create_test_task_info(TEST_PID_B, TEST_PID_B, "process2");

        // Record both tasks
        recorder.maybe_record_task(&task1);
        recorder.maybe_record_task(&task2);

        // Should have two processes
        let process_descriptors = recorder.process_descriptors.read().unwrap();
        assert_eq!(process_descriptors.len(), 2);
        assert!(process_descriptors.contains_key(&task1.tgidpid));
        assert!(process_descriptors.contains_key(&task2.tgidpid));

        let processes = recorder.processes.read().unwrap();
        assert_eq!(processes.len(), 2);
    }

    #[test]
    fn test_maybe_record_task_multiple_threads() {
        let recorder = create_test_session_recorder();
        let task1 = create_test_task_info(TEST_PID_A, TEST_TID_A, "thread1");
        let task2 = create_test_task_info(TEST_PID_A, TEST_TID_B, "thread2");

        // Record both tasks
        recorder.maybe_record_task(&task1);
        recorder.maybe_record_task(&task2);

        // Should have two threads
        let threads = recorder.threads.read().unwrap();
        assert_eq!(threads.len(), 2);
        assert!(threads.contains_key(&task1.tgidpid));
        assert!(threads.contains_key(&task2.tgidpid));

        // Verify thread details
        let thread1 = threads.get(&task1.tgidpid).unwrap();
        assert_eq!(thread1.tid(), TEST_TID_A as i32);
        assert_eq!(thread1.pid(), TEST_PID_A as i32);

        let thread2 = threads.get(&task2.tgidpid).unwrap();
        assert_eq!(thread2.tid(), TEST_TID_B as i32);
        assert_eq!(thread2.pid(), TEST_PID_A as i32);
    }

    #[test]
    fn test_maybe_record_task_process_and_threads() {
        let recorder = create_test_session_recorder();
        let process_task = create_test_task_info(TEST_PID_A, TEST_PID_A, "main_process");
        let thread_task1 = create_test_task_info(TEST_PID_A, TEST_TID_A, "thread1");
        let thread_task2 = create_test_task_info(TEST_PID_A, TEST_TID_B, "thread2");

        // Record process and threads
        recorder.maybe_record_task(&process_task);
        recorder.maybe_record_task(&thread_task1);
        recorder.maybe_record_task(&thread_task2);

        // Should have one process entry
        let process_descriptors = recorder.process_descriptors.read().unwrap();
        assert_eq!(process_descriptors.len(), 1);

        // All tasks (including main thread) go to threads for parquet consistency
        let threads = recorder.threads.read().unwrap();
        assert_eq!(threads.len(), 3); // main thread + 2 worker threads

        // Verify the process
        let process_desc = process_descriptors.get(&process_task.tgidpid).unwrap();
        assert_eq!(process_desc.process_name(), "main_process");

        // Verify all threads belong to the same process
        for thread in threads.values() {
            assert_eq!(thread.pid(), TEST_PID_A as i32);
        }
    }

    #[test]
    fn test_maybe_record_task_comm_with_null_terminator() {
        let recorder = create_test_session_recorder();
        let task = create_test_task_info(TEST_PID_A, TEST_PID_A, "short");

        recorder.maybe_record_task(&task);

        let process_descriptors = recorder.process_descriptors.read().unwrap();
        let process_desc = process_descriptors.get(&task.tgidpid).unwrap();
        assert_eq!(process_desc.process_name(), "short");
    }

    #[test]
    fn test_maybe_record_task_long_comm_truncated() {
        let recorder = create_test_session_recorder();
        // Create a long comm name that would exceed the buffer
        let long_name = "this_is_a_very_long_process_name_that_exceeds_the_buffer_size";
        let task = create_test_task_info(TEST_PID_A, TEST_PID_A, long_name);

        recorder.maybe_record_task(&task);

        let process_descriptors = recorder.process_descriptors.read().unwrap();
        let process_desc = process_descriptors.get(&task.tgidpid).unwrap();

        // Should be truncated to fit in the 16-byte buffer (minus null terminator)
        let expected = &long_name[..15]; // 15 chars + null terminator = 16 bytes
        assert_eq!(process_desc.process_name(), expected);
    }

    #[test]
    fn test_maybe_record_task_empty_comm() {
        let recorder = create_test_session_recorder();
        let task = create_test_task_info(TEST_PID_A, TEST_PID_A, "");

        recorder.maybe_record_task(&task);

        let process_descriptors = recorder.process_descriptors.read().unwrap();
        let process_desc = process_descriptors.get(&task.tgidpid).unwrap();
        // When comm is empty and /proc lookup fails, fall back to pid-based name
        assert_eq!(process_desc.process_name(), format!("<pid:{TEST_PID_A}>"));
    }

    #[test]
    fn test_generate_initial_packets() {
        let recorder = create_test_session_recorder();
        let id_counter = Arc::new(AtomicUsize::new(100));

        // Set up a clock snapshot
        recorder.snapshot_clocks();

        let packets = generate_initial_packets(&recorder, &id_counter);

        // Should generate 2-3 packets depending on whether utsname is available
        // (clock snapshot + [optional system info] + root descriptor)
        assert!(packets.len() >= 2 && packets.len() <= 3);

        // First packet should be the clock snapshot
        let _clock_snapshot = packets[0].clock_snapshot();
        assert_eq!(packets[0].trusted_packet_sequence_id(), 100);

        // Last packet should be the root track descriptor
        let last_packet = packets.last().unwrap();
        let track_desc = last_packet.track_descriptor();
        assert_eq!(track_desc.name(), "Systing");

        // Verify id_counter was incremented appropriately
        let expected_final = 100 + packets.len();
        assert_eq!(
            id_counter.load(std::sync::atomic::Ordering::Relaxed),
            expected_final
        );
    }

    #[test]
    fn test_generate_initial_packets_empty_clock() {
        let recorder = create_test_session_recorder();
        let id_counter = Arc::new(AtomicUsize::new(50));

        // Don't set up clock snapshot - should still work with empty snapshot
        let packets = generate_initial_packets(&recorder, &id_counter);

        // Should generate 2-3 packets even with empty clock
        assert!(packets.len() >= 2 && packets.len() <= 3);
        let _clock_snapshot = packets[0].clock_snapshot();
        let _track_desc = packets.last().unwrap().track_descriptor();
    }

    #[test]
    fn test_generate_initial_packets_with_system_info() {
        let recorder = create_test_session_recorder();
        let id_counter = Arc::new(AtomicUsize::new(100));

        // Set up clock snapshot
        recorder.snapshot_clocks();

        let packets = generate_initial_packets(&recorder, &id_counter);

        // Should generate 2-3 packets: clock snapshot + [optional system info] + root descriptor
        assert!(packets.len() >= 2 && packets.len() <= 3);

        // First packet should have clock snapshot
        assert!(packets[0].has_clock_snapshot());
        let clock_snapshot = packets[0].clock_snapshot();
        assert!(!clock_snapshot.clocks.is_empty());

        // If SystemInfo is available (should be on Unix-like systems), verify it
        if packets.len() == 3 {
            // Second packet should have system info (separate because both are in oneof data)
            assert!(packets[1].has_system_info());
            let system_info = packets[1].system_info();
            assert!(system_info.utsname.is_some());

            let utsname = system_info.utsname.as_ref().unwrap();
            // Verify utsname has at least some fields set
            assert!(utsname.has_sysname());
            assert!(!utsname.sysname().is_empty());
            assert!(utsname.has_release());
            assert!(!utsname.release().is_empty());
            assert!(utsname.has_machine());
            assert!(!utsname.machine().is_empty());

            // Verify it's a valid Unix-like system name (not platform-specific)
            assert!(!utsname.sysname().is_empty());
        }
    }

    #[test]
    fn test_get_system_utsname() {
        let utsname = get_system_utsname();
        assert!(utsname.is_some());

        let utsname = utsname.unwrap();
        // Verify all fields are populated
        assert!(!utsname.sysname().is_empty());
        assert!(!utsname.release().is_empty());
        assert!(!utsname.version().is_empty());
        assert!(!utsname.machine().is_empty());

        // On Linux, sysname should be "Linux"
        assert_eq!(utsname.sysname(), "Linux");
    }

    #[test]
    fn test_cpufreq_scaling_driver_matches_sysfs() {
        // The helper must agree with the sysfs layout it probes: Some(non-empty)
        // exactly when at least one policy directory has a scaling_driver file.
        // (The cpufreq directory itself can exist and be empty on systems with
        // no driver, so directory existence alone is not the oracle.)
        let any_policy_driver = std::fs::read_dir("/sys/devices/system/cpu/cpufreq")
            .map(|entries| {
                entries.flatten().any(|e| {
                    e.file_name().to_string_lossy().starts_with("policy")
                        && e.path().join("scaling_driver").exists()
                })
            })
            .unwrap_or(false);
        let driver = cpufreq_scaling_driver();
        assert_eq!(driver.is_some(), any_policy_driver);
        if let Some(d) = driver {
            assert!(!d.is_empty());
            assert!(!d.contains('\n'));
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_detect_hypervisor_matches_cpuinfo_flag() {
        // /proc/cpuinfo's "hypervisor" flag mirrors CPUID.1:ECX bit 31, the
        // same bit detect_hypervisor() checks - the two must agree.
        let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap();
        let flag_set = cpuinfo
            .lines()
            .find(|l| l.starts_with("flags"))
            .is_some_and(|l| l.split_whitespace().any(|f| f == "hypervisor"));
        assert_eq!(detect_hypervisor().is_some(), flag_set);
    }

    #[test]
    fn test_dmi_helpers_match_sysfs() {
        // Compare against a direct read of the sysfs files (an independent
        // oracle) rather than re-calling the helper's own code path.
        for (helper, path) in [
            (
                dmi_sys_vendor as fn() -> Option<String>,
                "/sys/class/dmi/id/sys_vendor",
            ),
            (dmi_product_name, "/sys/class/dmi/id/product_name"),
        ] {
            let expected = std::fs::read_to_string(path)
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false);
            assert_eq!(helper().is_some(), expected, "{path}");
        }
    }

    #[test]
    fn test_generate_process_packets_empty() {
        let recorder = create_test_session_recorder();
        let id_counter = Arc::new(AtomicUsize::new(100));
        let mut pid_uuids = HashMap::new();

        let packets = generate_process_packets(&recorder, &id_counter, &mut pid_uuids);

        // Should generate no packets when no processes are recorded
        assert!(packets.is_empty());
        assert!(pid_uuids.is_empty());

        // id_counter should not be incremented
        assert_eq!(id_counter.load(std::sync::atomic::Ordering::Relaxed), 100);
    }

    #[test]
    fn test_generate_process_packets_single_process() {
        let recorder = create_test_session_recorder();
        let id_counter = Arc::new(AtomicUsize::new(100));
        let mut pid_uuids = HashMap::new();

        // Add a process
        let task = create_test_task_info(TEST_PID_A, TEST_PID_A, "test_process");
        recorder.maybe_record_task(&task);

        let packets = generate_process_packets(&recorder, &id_counter, &mut pid_uuids);

        // Should generate 2 packets: process track descriptor + process tree
        assert_eq!(packets.len(), 2);

        // First packet should be the process track descriptor
        let track_desc = packets[0].track_descriptor();
        assert_eq!(track_desc.uuid(), 100);
        let process_desc = &track_desc.process;
        assert_eq!(process_desc.pid(), TEST_PID_A as i32);
        assert_eq!(process_desc.process_name(), "test_process");

        // Second packet should be the process tree
        let process_tree = packets[1].process_tree();
        assert_eq!(process_tree.processes.len(), 1);
        assert_eq!(process_tree.processes[0].pid, Some(task.tgidpid as i32));

        // pid_uuids should be updated
        assert_eq!(pid_uuids.len(), 1);
        assert_eq!(pid_uuids.get(&(TEST_PID_A as i32)), Some(&100));

        // id_counter should be incremented
        assert_eq!(id_counter.load(std::sync::atomic::Ordering::Relaxed), 101);
    }

    #[test]
    fn test_generate_process_packets_multiple_processes() {
        let recorder = create_test_session_recorder();
        let id_counter = Arc::new(AtomicUsize::new(200));
        let mut pid_uuids = HashMap::new();

        // Add multiple processes
        let task1 = create_test_task_info(TEST_PID_A, TEST_PID_A, "process1");
        let task2 = create_test_task_info(TEST_PID_B, TEST_PID_B, "process2");
        recorder.maybe_record_task(&task1);
        recorder.maybe_record_task(&task2);

        let packets = generate_process_packets(&recorder, &id_counter, &mut pid_uuids);

        // Should generate 4 packets: 2 process track descriptors + 2 process trees
        assert_eq!(packets.len(), 4);

        // Check that we have track descriptors and process trees
        let track_descriptors: Vec<_> = packets
            .iter()
            .enumerate()
            .filter(|(i, _)| i % 2 == 0) // Even indices are track descriptors
            .collect();
        let process_trees: Vec<_> = packets
            .iter()
            .enumerate()
            .filter(|(i, _)| i % 2 == 1) // Odd indices are process trees
            .collect();

        assert_eq!(track_descriptors.len(), 2);
        assert_eq!(process_trees.len(), 2);

        // pid_uuids should contain both processes
        assert_eq!(pid_uuids.len(), 2);
        assert!(pid_uuids.contains_key(&(TEST_PID_A as i32)));
        assert!(pid_uuids.contains_key(&(TEST_PID_B as i32)));

        // UUIDs should be unique
        let uuid1 = pid_uuids.get(&(TEST_PID_A as i32)).unwrap();
        let uuid2 = pid_uuids.get(&(TEST_PID_B as i32)).unwrap();
        assert_ne!(uuid1, uuid2);

        // id_counter should be incremented appropriately
        assert_eq!(id_counter.load(std::sync::atomic::Ordering::Relaxed), 202);
    }

    #[test]
    fn test_generate_thread_packets_empty() {
        let recorder = create_test_session_recorder();
        let id_counter = Arc::new(AtomicUsize::new(100));
        let mut thread_uuids = HashMap::new();

        let packets = generate_thread_packets(&recorder, &id_counter, &mut thread_uuids);

        // Should generate no packets when no threads are recorded
        assert!(packets.is_empty());
        assert!(thread_uuids.is_empty());

        // id_counter should not be incremented
        assert_eq!(id_counter.load(std::sync::atomic::Ordering::Relaxed), 100);
    }

    #[test]
    fn test_generate_thread_packets_single_thread() {
        let recorder = create_test_session_recorder();
        let id_counter = Arc::new(AtomicUsize::new(150));
        let mut thread_uuids = HashMap::new();

        // Add a thread
        let task = create_test_task_info(TEST_PID_A, TEST_TID_A, "test_thread");
        recorder.maybe_record_task(&task);

        let packets = generate_thread_packets(&recorder, &id_counter, &mut thread_uuids);

        // Should generate 1 packet: thread track descriptor
        assert_eq!(packets.len(), 1);

        // Packet should be the thread track descriptor
        let track_desc = packets[0].track_descriptor();
        assert_eq!(track_desc.uuid(), 150);
        let thread_desc = &track_desc.thread;
        assert_eq!(thread_desc.tid(), TEST_TID_A as i32);
        assert_eq!(thread_desc.pid(), TEST_PID_A as i32);
        assert_eq!(thread_desc.thread_name(), "test_thread");

        // thread_uuids should be updated
        assert_eq!(thread_uuids.len(), 1);
        assert_eq!(thread_uuids.get(&(TEST_TID_A as i32)), Some(&150));

        // id_counter should be incremented
        assert_eq!(id_counter.load(std::sync::atomic::Ordering::Relaxed), 151);
    }

    #[test]
    fn test_generate_thread_packets_multiple_threads() {
        let recorder = create_test_session_recorder();
        let id_counter = Arc::new(AtomicUsize::new(300));
        let mut thread_uuids = HashMap::new();

        // Add multiple threads
        let task1 = create_test_task_info(TEST_PID_A, TEST_TID_A, "thread1");
        let task2 = create_test_task_info(TEST_PID_A, TEST_TID_B, "thread2");
        let task3 = create_test_task_info(TEST_PID_B, TEST_TID_C, "thread3");
        recorder.maybe_record_task(&task1);
        recorder.maybe_record_task(&task2);
        recorder.maybe_record_task(&task3);

        let packets = generate_thread_packets(&recorder, &id_counter, &mut thread_uuids);

        // Should generate 3 packets: 3 thread track descriptors
        assert_eq!(packets.len(), 3);

        // All packets should be track descriptors with thread info
        for packet in &packets {
            let track_desc = packet.track_descriptor();
            let _thread_desc = &track_desc.thread;
        }

        // thread_uuids should contain all threads
        assert_eq!(thread_uuids.len(), 3);
        assert!(thread_uuids.contains_key(&(TEST_TID_A as i32))); // TID from task1
        assert!(thread_uuids.contains_key(&(TEST_TID_B as i32))); // TID from task2
        assert!(thread_uuids.contains_key(&(TEST_TID_C as i32))); // TID from task3

        // UUIDs should be unique
        let uuid1 = thread_uuids.get(&(TEST_TID_A as i32)).unwrap();
        let uuid2 = thread_uuids.get(&(TEST_TID_B as i32)).unwrap();
        let uuid3 = thread_uuids.get(&(TEST_TID_C as i32)).unwrap();
        assert_ne!(uuid1, uuid2);
        assert_ne!(uuid1, uuid3);
        assert_ne!(uuid2, uuid3);

        // id_counter should be incremented appropriately
        assert_eq!(id_counter.load(std::sync::atomic::Ordering::Relaxed), 303);
    }

    #[test]
    fn test_generate_thread_packets_thread_details() {
        let recorder = create_test_session_recorder();
        let id_counter = Arc::new(AtomicUsize::new(400));
        let mut thread_uuids = HashMap::new();

        // Add a thread with specific details to verify
        let task = create_test_task_info(TEST_PID_B, TEST_TID_D, "special_thread");
        recorder.maybe_record_task(&task);

        let packets = generate_thread_packets(&recorder, &id_counter, &mut thread_uuids);

        assert_eq!(packets.len(), 1);

        let track_desc = packets[0].track_descriptor();
        let thread_desc = &track_desc.thread;

        // Verify all thread details are correct
        assert_eq!(thread_desc.tid(), TEST_TID_D as i32);
        assert_eq!(thread_desc.pid(), TEST_PID_B as i32);
        assert_eq!(thread_desc.thread_name(), "special_thread");

        // Verify UUID mapping
        assert_eq!(thread_uuids.get(&(TEST_TID_D as i32)), Some(&400));
        assert_eq!(track_desc.uuid(), 400);
    }

    #[test]
    fn test_get_min_event_timestamp_no_events() {
        let recorder = create_test_session_recorder();

        let ts = get_min_event_timestamp(&recorder);

        // Should return a fallback non-zero value (current BOOTTIME) when no events recorded
        assert!(
            ts > 0,
            "Should return current BOOTTIME when no events recorded"
        );
    }
}
