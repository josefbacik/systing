use std::collections::HashMap;
use std::ffi::CStr;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use crate::events::SystingProbeRecorder;
use crate::network_recorder::NetworkRecorder;
use crate::perf_recorder::PerfCounterRecorder;
use crate::perfetto::TrackCounter;
use crate::ringbuf::RingBuffer;
use crate::sched::SchedEventRecorder;
use crate::stack_recorder::StackRecorder;
use crate::systing::types::task_info;
use crate::SystingRecordEvent;

use perfetto_protos::builtin_clock::BuiltinClock;
use perfetto_protos::clock_snapshot::clock_snapshot::Clock;
use perfetto_protos::clock_snapshot::ClockSnapshot;
use perfetto_protos::counter_descriptor::counter_descriptor::Unit;
use perfetto_protos::counter_descriptor::CounterDescriptor;
use perfetto_protos::debug_annotation::DebugAnnotation;
use perfetto_protos::process_descriptor::ProcessDescriptor;
use perfetto_protos::process_tree::{process_tree::Process as ProtoProcess, ProcessTree};
use perfetto_protos::system_info::{SystemInfo, Utsname};
use perfetto_protos::thread_descriptor::ThreadDescriptor;
use perfetto_protos::trace_packet::TracePacket;
use perfetto_protos::track_descriptor::TrackDescriptor;
use perfetto_protos::track_event::track_event::Type;
use perfetto_protos::track_event::TrackEvent;
use std::fs::{self, File};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

#[derive(Default)]
pub struct SysInfoEvent {
    pub cpu: u32,
    pub ts: u64,
    pub frequency: i64,
}

#[derive(Default)]
pub struct SysinfoRecorder {
    pub ringbuf: RingBuffer<SysInfoEvent>,
    pub frequency: HashMap<u32, Vec<TrackCounter>>,
}

#[derive(Default)]
pub struct SessionRecorder {
    pub clock_snapshot: Mutex<ClockSnapshot>,
    pub event_recorder: Mutex<SchedEventRecorder>,
    pub stack_recorder: Mutex<StackRecorder>,
    pub perf_counter_recorder: Mutex<PerfCounterRecorder>,
    pub sysinfo_recorder: Mutex<SysinfoRecorder>,
    pub probe_recorder: Mutex<SystingProbeRecorder>,
    pub network_recorder: Mutex<NetworkRecorder>,
    pub process_descriptors: RwLock<HashMap<u64, ProcessDescriptor>>,
    pub processes: RwLock<HashMap<u64, ProtoProcess>>,
    pub threads: RwLock<HashMap<u64, ThreadDescriptor>>,
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

/// Gets the network namespace inode for a given PID.
fn get_netns_inode(pid: u32) -> Option<u64> {
    let ns_path = format!("/proc/{}/ns/net", pid);
    fs::metadata(&ns_path).ok().map(|m| m.ino())
}

/// Gets the host (init) network namespace inode.
fn get_host_netns_inode() -> Option<u64> {
    get_netns_inode(1)
}

/// Attempts to extract a container ID from a process's cgroup information.
/// Looks for Docker/containerd container IDs in the cgroup path.
fn get_container_id(pid: u32) -> Option<String> {
    let cgroup_path = format!("/proc/{}/cgroup", pid);
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
    let comm_path = format!("/proc/{}/comm", pid);
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

    let target_netns_path = format!("/proc/{}/ns/net", pid);
    let target_netns = match File::open(&target_netns_path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };

    if unsafe { libc::setns(target_netns.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
        return Vec::new();
    }

    let interfaces = get_network_interfaces();

    if unsafe { libc::setns(self_netns.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
        eprintln!(
            "WARNING: Failed to restore original network namespace after enumerating interfaces for pid {}",
            pid
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
        let freq = self.frequency.entry(event.cpu).or_default();
        freq.push(TrackCounter {
            ts: event.ts,
            count: event.frequency,
        });
    }
}

impl SysinfoRecorder {
    pub fn generate_trace(&self, id_counter: &Arc<AtomicUsize>) -> Vec<TracePacket> {
        let mut packets = Vec::new();

        // Populate the sysinfo events
        for (cpu, events) in self.frequency.iter() {
            let desc_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;

            let mut counter_desc = CounterDescriptor::default();
            counter_desc.set_unit(Unit::UNIT_COUNT);
            counter_desc.set_is_incremental(false);

            let mut desc = TrackDescriptor::default();
            desc.set_name(format!("CPU {cpu} frequency").to_string());
            desc.set_uuid(desc_uuid);
            desc.counter = Some(counter_desc).into();

            let mut packet = TracePacket::default();
            packet.set_track_descriptor(desc);
            packets.push(packet);

            let seq = id_counter.fetch_add(1, Ordering::Relaxed) as u32;
            for event in events.iter() {
                packets.push(event.to_track_event(desc_uuid, seq));
            }
        }
        packets
    }

    /// Returns the minimum timestamp from all frequency events, or None if no events recorded.
    pub fn min_timestamp(&self) -> Option<u64> {
        self.frequency
            .values()
            .filter_map(|counters| counters.first())
            .map(|c| c.ts)
            .min()
    }
}

impl SessionRecorder {
    pub fn new(enable_debuginfod: bool, resolve_network_addresses: bool) -> Self {
        Self {
            clock_snapshot: Mutex::new(ClockSnapshot::default()),
            event_recorder: Mutex::new(SchedEventRecorder::default()),
            stack_recorder: Mutex::new(StackRecorder::new(enable_debuginfod)),
            perf_counter_recorder: Mutex::new(PerfCounterRecorder::default()),
            sysinfo_recorder: Mutex::new(SysinfoRecorder::default()),
            probe_recorder: Mutex::new(SystingProbeRecorder::default()),
            network_recorder: Mutex::new(NetworkRecorder::new(resolve_network_addresses)),
            process_descriptors: RwLock::new(HashMap::new()),
            processes: RwLock::new(HashMap::new()),
            threads: RwLock::new(HashMap::new()),
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
                return name.to_string_lossy().to_string();
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

        let process_name = if comm.is_empty() {
            Self::fetch_name_from_proc(pid)
        } else {
            comm
        };

        let cmdline = Self::fetch_cmdline_from_proc(pid);

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
    }

    fn record_new_thread(&self, info: &task_info) {
        let comm = Self::extract_comm(info);
        let tid = info.tgidpid as u32;

        let thread_name = if comm.is_empty() {
            Self::fetch_name_from_proc(tid)
        } else {
            comm
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
        if Self::is_process(info) {
            // Check if process already exists
            if !self
                .process_descriptors
                .read()
                .unwrap()
                .contains_key(&info.tgidpid)
            {
                self.record_new_process(info);
            }
        } else {
            // For threads, ensure the parent process is also recorded
            let tgid = info.tgidpid >> 32;
            let parent_tgidpid = (tgid << 32) | tgid; // parent process has pid == tgid
            if !self
                .process_descriptors
                .read()
                .unwrap()
                .contains_key(&parent_tgidpid)
            {
                // Create a synthetic task_info for the parent process
                let mut parent_info = *info;
                parent_info.tgidpid = parent_tgidpid;
                self.record_new_process(&parent_info);
            }

            // Check if thread already exists
            if !self.threads.read().unwrap().contains_key(&info.tgidpid) {
                self.record_new_thread(info);
            }
        }
    }

    pub fn drain_all_ringbufs(&self) {
        self.event_recorder.lock().unwrap().drain_ringbuf();
        self.stack_recorder.lock().unwrap().drain_ringbuf();
        self.perf_counter_recorder.lock().unwrap().drain_ringbuf();
        self.sysinfo_recorder.lock().unwrap().drain_ringbuf();
        self.probe_recorder.lock().unwrap().drain_ringbuf();
        self.network_recorder.lock().unwrap().drain_ringbuf();
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

    /// Gets the minimum timestamp from all recorded events across all recorders.
    ///
    /// This is used to set the timestamp for metadata events (like network interface
    /// descriptors) so they don't affect Perfetto's trace_bounds. By using the first
    /// actual event timestamp, these metadata events will appear at the trace start
    /// without pushing the timeline back to 0.
    fn get_min_event_timestamp(&self) -> u64 {
        [
            self.event_recorder.lock().unwrap().min_timestamp(),
            self.stack_recorder.lock().unwrap().min_timestamp(),
            self.perf_counter_recorder.lock().unwrap().min_timestamp(),
            self.sysinfo_recorder.lock().unwrap().min_timestamp(),
            self.probe_recorder.lock().unwrap().min_timestamp(),
            self.network_recorder.lock().unwrap().min_timestamp(),
        ]
        .into_iter()
        .flatten()
        .min()
        .unwrap_or_else(|| get_clock_value(libc::CLOCK_BOOTTIME))
    }

    /// Generates the initial trace packets including clock snapshot and root descriptor
    fn generate_initial_packets(&self, id_counter: &Arc<AtomicUsize>) -> Vec<TracePacket> {
        let mut packets = Vec::new();

        // Emit the clock snapshot
        let mut packet = TracePacket::default();
        packet.set_clock_snapshot(self.clock_snapshot.lock().unwrap().clone());
        packet.set_trusted_packet_sequence_id(id_counter.fetch_add(1, Ordering::Relaxed) as u32);
        packets.push(packet);

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
            packets.push(packet);
        }

        // Add the root Systing track descriptor
        let systing_desc_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;
        let mut desc = TrackDescriptor::default();
        desc.set_uuid(systing_desc_uuid);
        desc.set_name("Systing".to_string());

        let mut packet = TracePacket::default();
        packet.set_track_descriptor(desc);
        packets.push(packet);

        packets
    }

    /// Generates trace packets for all processes
    fn generate_process_packets(
        &self,
        id_counter: &Arc<AtomicUsize>,
        pid_uuids: &mut HashMap<i32, u64>,
    ) -> Vec<TracePacket> {
        let mut packets = Vec::new();

        // Generate process track descriptors
        for process in self.process_descriptors.read().unwrap().values() {
            let uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;
            pid_uuids.insert(process.pid(), uuid);

            let mut desc = TrackDescriptor::default();
            desc.set_uuid(uuid);
            desc.process = Some(process.clone()).into();

            let mut packet = TracePacket::default();
            packet.set_track_descriptor(desc);
            packets.push(packet);
        }

        // Generate process trees
        for process in self.processes.read().unwrap().values() {
            let process_tree = ProcessTree {
                processes: vec![process.clone()],
                ..ProcessTree::default()
            };

            let mut packet = TracePacket::default();
            packet.set_process_tree(process_tree);
            packets.push(packet);
        }

        packets
    }

    /// Generates trace packets for all threads
    fn generate_thread_packets(
        &self,
        id_counter: &Arc<AtomicUsize>,
        thread_uuids: &mut HashMap<i32, u64>,
    ) -> Vec<TracePacket> {
        let mut packets = Vec::new();

        for thread in self.threads.read().unwrap().values() {
            let uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;
            thread_uuids.insert(thread.tid(), uuid);

            let mut desc = TrackDescriptor::default();
            desc.set_uuid(uuid);
            desc.thread = Some(thread.clone()).into();

            let mut packet = TracePacket::default();
            packet.set_track_descriptor(desc);
            packets.push(packet);
        }

        packets
    }

    /// Generates trace packets for network interface metadata.
    ///
    /// Creates a hierarchical "Network Interfaces" track structure that includes:
    /// - Host network namespace interfaces
    /// - Container/process network namespace interfaces (deduplicated by namespace inode)
    ///
    /// # Arguments
    ///
    /// * `id_counter` - Atomic counter for generating unique track UUIDs
    /// * `trace_start_ts` - BOOTTIME timestamp for when the trace began (used for metadata events)
    ///
    /// The hierarchy looks like:
    /// ```
    /// Network Interfaces
    /// ├── host
    /// │   ├── eth0
    /// │   └── docker0
    /// ├── container:abc123 (nginx)
    /// │   └── eth0
    /// └── netns:4026532890 (java:1234)
    ///     └── eth0
    /// ```
    fn generate_network_interface_packets(
        &self,
        id_counter: &Arc<AtomicUsize>,
        trace_start_ts: u64,
    ) -> Vec<TracePacket> {
        let mut packets = Vec::new();
        let sequence_id = id_counter.fetch_add(1, Ordering::Relaxed) as u32;

        // Create root "Network Interfaces" track
        let root_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;
        let mut root_desc = TrackDescriptor::default();
        root_desc.set_uuid(root_uuid);
        root_desc.set_name(NETWORK_INTERFACES_TRACK_NAME.to_string());

        let mut root_packet = TracePacket::default();
        root_packet.set_track_descriptor(root_desc);
        packets.push(root_packet);

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
                // Only add if we haven't seen this namespace yet
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

        // Generate tracks for each namespace
        for netns_info in namespaces {
            // Create namespace track name
            let netns_name = if netns_info.is_host {
                "host".to_string()
            } else if let Some(ref container_id) = netns_info.container_id {
                if netns_info.comm.is_empty() {
                    format!("container:{}", container_id)
                } else {
                    format!("container:{} ({})", container_id, netns_info.comm)
                }
            } else if netns_info.comm.is_empty() {
                format!("netns:{}", netns_info.inode)
            } else {
                format!(
                    "netns:{} ({}:{})",
                    netns_info.inode, netns_info.comm, netns_info.representative_pid
                )
            };

            // Get interfaces for this namespace
            let interfaces = if netns_info.is_host {
                // For host namespace, we can use get_network_interfaces directly
                get_network_interfaces()
            } else {
                // For other namespaces, enter the namespace to get interfaces
                get_interfaces_in_netns(netns_info.representative_pid)
            };

            if interfaces.is_empty() {
                continue;
            }

            // Create namespace track (child of root)
            let netns_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;
            let mut netns_desc = TrackDescriptor::default();
            netns_desc.set_uuid(netns_uuid);
            netns_desc.set_name(netns_name);
            netns_desc.set_parent_uuid(root_uuid);

            let mut netns_packet = TracePacket::default();
            netns_packet.set_track_descriptor(netns_desc);
            packets.push(netns_packet);

            // Create child tracks for each interface in this namespace
            for iface in interfaces {
                let iface_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;

                // Create track descriptor for this interface (child of namespace track)
                let mut iface_desc = TrackDescriptor::default();
                iface_desc.set_uuid(iface_uuid);
                iface_desc.set_name(iface.name.clone());
                iface_desc.set_parent_uuid(netns_uuid);

                let mut iface_packet = TracePacket::default();
                iface_packet.set_track_descriptor(iface_desc);
                packets.push(iface_packet);

                // Create an instant event with debug annotations for IP addresses
                let mut track_event = TrackEvent::default();
                track_event.set_type(Type::TYPE_INSTANT);
                track_event.set_track_uuid(iface_uuid);
                track_event.set_name(iface.name);

                // Add IPv4 addresses as debug annotations
                for ipv4 in iface.ipv4_addrs {
                    let mut annotation = DebugAnnotation::default();
                    annotation.set_name("ipv4".to_string());
                    annotation.set_string_value(ipv4.to_string());
                    track_event.debug_annotations.push(annotation);
                }

                // Add IPv6 addresses as debug annotations
                for ipv6 in iface.ipv6_addrs {
                    let mut annotation = DebugAnnotation::default();
                    annotation.set_name("ipv6".to_string());
                    annotation.set_string_value(ipv6.to_string());
                    track_event.debug_annotations.push(annotation);
                }

                let mut event_packet = TracePacket::default();
                // Use trace start timestamp so these don't affect trace_bounds
                event_packet.set_timestamp(trace_start_ts);
                event_packet.set_track_event(track_event);
                event_packet.set_trusted_packet_sequence_id(sequence_id);
                packets.push(event_packet);
            }
        }

        packets
    }

    /// Collects trace packets from all event recorders
    fn collect_recorder_traces(
        &self,
        pid_uuids: &HashMap<i32, u64>,
        thread_uuids: &HashMap<i32, u64>,
        id_counter: &Arc<AtomicUsize>,
    ) -> Vec<TracePacket> {
        let mut packets = Vec::new();

        // Event recorder
        eprintln!("Generating scheduler trace packets...");
        packets.extend(self.event_recorder.lock().unwrap().generate_trace(
            pid_uuids,
            thread_uuids,
            id_counter,
        ));

        // Stack recorder - it has its own detailed progress bar for symbol resolution
        eprintln!("Generating stack trace packets...");
        packets.extend(
            self.stack_recorder
                .lock()
                .unwrap()
                .generate_trace(id_counter),
        );

        // Performance counter recorder
        eprintln!("Generating perf counter trace packets...");
        packets.extend(
            self.perf_counter_recorder
                .lock()
                .unwrap()
                .generate_trace(id_counter),
        );

        // System info recorder
        eprintln!("Generating sysinfo trace packets...");
        packets.extend(
            self.sysinfo_recorder
                .lock()
                .unwrap()
                .generate_trace(id_counter),
        );

        eprintln!("Generating probe trace packets...");
        packets.extend(self.probe_recorder.lock().unwrap().generate_trace(
            pid_uuids,
            thread_uuids,
            id_counter,
        ));

        eprintln!("Generating syscall trace packets...");

        // Network recorder
        eprintln!("Generating network trace packets...");
        packets.extend(
            self.network_recorder
                .lock()
                .unwrap()
                .generate_trace_packets(pid_uuids, thread_uuids, id_counter),
        );

        packets
    }

    pub fn generate_trace(&self) -> Vec<TracePacket> {
        let id_counter = Arc::new(AtomicUsize::new(1));
        let mut pid_uuids = HashMap::new();
        let mut thread_uuids = HashMap::new();

        let mut packets = Vec::new();

        // Step 1: Generate initial packets (clock snapshot and root descriptor)
        packets.extend(self.generate_initial_packets(&id_counter));

        // Get the trace start timestamp for metadata events (first actual event timestamp)
        let trace_start_ts = self.get_min_event_timestamp();

        // Step 2: Generate network interface metadata packets
        packets.extend(self.generate_network_interface_packets(&id_counter, trace_start_ts));

        // Step 3: Generate process-related packets
        packets.extend(self.generate_process_packets(&id_counter, &mut pid_uuids));

        // Step 4: Generate thread-related packets
        packets.extend(self.generate_thread_packets(&id_counter, &mut thread_uuids));

        // Step 5: Collect traces from all recorders
        packets.extend(self.collect_recorder_traces(&pid_uuids, &thread_uuids, &id_counter));

        packets
    }
}

impl crate::SystingEvent for SysInfoEvent {
    fn ts(&self) -> u64 {
        self.ts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, RwLock};

    fn create_test_task_info(tgid: u32, pid: u32, comm: &str) -> task_info {
        let mut task = task_info {
            tgidpid: ((tgid as u64) << 32) | (pid as u64),
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
        SessionRecorder {
            clock_snapshot: Mutex::new(ClockSnapshot::default()),
            event_recorder: Mutex::new(SchedEventRecorder::default()),
            stack_recorder: Mutex::new(StackRecorder::default()),
            perf_counter_recorder: Mutex::new(PerfCounterRecorder::default()),
            sysinfo_recorder: Mutex::new(SysinfoRecorder::default()),
            probe_recorder: Mutex::new(SystingProbeRecorder::default()),
            network_recorder: Mutex::new(NetworkRecorder::default()),
            process_descriptors: RwLock::new(HashMap::new()),
            processes: RwLock::new(HashMap::new()),
            threads: RwLock::new(HashMap::new()),
        }
    }

    #[test]
    fn test_maybe_record_task_new_process() {
        let recorder = create_test_session_recorder();
        let task = create_test_task_info(1234, 1234, "test_process");

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
        assert_eq!(process_desc.pid(), 1234);
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
        let task = create_test_task_info(1234, 5678, "test_thread");

        // Initially, no threads should be recorded
        assert!(recorder.threads.read().unwrap().is_empty());

        // Record the task
        recorder.maybe_record_task(&task);

        // Now the thread should be recorded
        let threads = recorder.threads.read().unwrap();
        assert_eq!(threads.len(), 1);
        assert!(threads.contains_key(&task.tgidpid));

        let thread_desc = threads.get(&task.tgidpid).unwrap();
        assert_eq!(thread_desc.tid(), 5678);
        assert_eq!(thread_desc.pid(), 1234);
        assert_eq!(thread_desc.thread_name(), "test_thread");

        // Parent process should also be recorded when recording a thread
        let process_descriptors = recorder.process_descriptors.read().unwrap();
        assert_eq!(process_descriptors.len(), 1);
        let parent_tgidpid = (1234u64 << 32) | 1234u64;
        assert!(process_descriptors.contains_key(&parent_tgidpid));
    }

    #[test]
    fn test_maybe_record_task_duplicate_process() {
        let recorder = create_test_session_recorder();
        let task = create_test_task_info(1234, 1234, "test_process");

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
        let task = create_test_task_info(1234, 5678, "test_thread");

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
        let task1 = create_test_task_info(1234, 1234, "process1");
        let task2 = create_test_task_info(5678, 5678, "process2");

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
        let task1 = create_test_task_info(1234, 5678, "thread1");
        let task2 = create_test_task_info(1234, 9012, "thread2");

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
        assert_eq!(thread1.tid(), 5678);
        assert_eq!(thread1.pid(), 1234);

        let thread2 = threads.get(&task2.tgidpid).unwrap();
        assert_eq!(thread2.tid(), 9012);
        assert_eq!(thread2.pid(), 1234);
    }

    #[test]
    fn test_maybe_record_task_process_and_threads() {
        let recorder = create_test_session_recorder();
        let process_task = create_test_task_info(1234, 1234, "main_process");
        let thread_task1 = create_test_task_info(1234, 5678, "thread1");
        let thread_task2 = create_test_task_info(1234, 9012, "thread2");

        // Record process and threads
        recorder.maybe_record_task(&process_task);
        recorder.maybe_record_task(&thread_task1);
        recorder.maybe_record_task(&thread_task2);

        // Should have one process and two threads
        let process_descriptors = recorder.process_descriptors.read().unwrap();
        assert_eq!(process_descriptors.len(), 1);

        let threads = recorder.threads.read().unwrap();
        assert_eq!(threads.len(), 2);

        // Verify the process
        let process_desc = process_descriptors.get(&process_task.tgidpid).unwrap();
        assert_eq!(process_desc.process_name(), "main_process");

        // Verify the threads belong to the same process
        for thread in threads.values() {
            assert_eq!(thread.pid(), 1234);
        }
    }

    #[test]
    fn test_maybe_record_task_comm_with_null_terminator() {
        let recorder = create_test_session_recorder();
        let task = create_test_task_info(1234, 1234, "short");

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
        let task = create_test_task_info(1234, 1234, long_name);

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
        let task = create_test_task_info(1234, 1234, "");

        recorder.maybe_record_task(&task);

        let process_descriptors = recorder.process_descriptors.read().unwrap();
        let process_desc = process_descriptors.get(&task.tgidpid).unwrap();
        assert_eq!(process_desc.process_name(), "");
    }

    #[test]
    fn test_generate_initial_packets() {
        let recorder = create_test_session_recorder();
        let id_counter = Arc::new(AtomicUsize::new(100));

        // Set up a clock snapshot
        recorder.snapshot_clocks();

        let packets = recorder.generate_initial_packets(&id_counter);

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
        let packets = recorder.generate_initial_packets(&id_counter);

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

        let packets = recorder.generate_initial_packets(&id_counter);

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
    fn test_generate_process_packets_empty() {
        let recorder = create_test_session_recorder();
        let id_counter = Arc::new(AtomicUsize::new(100));
        let mut pid_uuids = HashMap::new();

        let packets = recorder.generate_process_packets(&id_counter, &mut pid_uuids);

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
        let task = create_test_task_info(1234, 1234, "test_process");
        recorder.maybe_record_task(&task);

        let packets = recorder.generate_process_packets(&id_counter, &mut pid_uuids);

        // Should generate 2 packets: process track descriptor + process tree
        assert_eq!(packets.len(), 2);

        // First packet should be the process track descriptor
        let track_desc = packets[0].track_descriptor();
        assert_eq!(track_desc.uuid(), 100);
        let process_desc = &track_desc.process;
        assert_eq!(process_desc.pid(), 1234);
        assert_eq!(process_desc.process_name(), "test_process");

        // Second packet should be the process tree
        let process_tree = packets[1].process_tree();
        assert_eq!(process_tree.processes.len(), 1);
        assert_eq!(process_tree.processes[0].pid, Some(task.tgidpid as i32));

        // pid_uuids should be updated
        assert_eq!(pid_uuids.len(), 1);
        assert_eq!(pid_uuids.get(&1234), Some(&100));

        // id_counter should be incremented
        assert_eq!(id_counter.load(std::sync::atomic::Ordering::Relaxed), 101);
    }

    #[test]
    fn test_generate_process_packets_multiple_processes() {
        let recorder = create_test_session_recorder();
        let id_counter = Arc::new(AtomicUsize::new(200));
        let mut pid_uuids = HashMap::new();

        // Add multiple processes
        let task1 = create_test_task_info(1234, 1234, "process1");
        let task2 = create_test_task_info(5678, 5678, "process2");
        recorder.maybe_record_task(&task1);
        recorder.maybe_record_task(&task2);

        let packets = recorder.generate_process_packets(&id_counter, &mut pid_uuids);

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
        assert!(pid_uuids.contains_key(&1234));
        assert!(pid_uuids.contains_key(&5678));

        // UUIDs should be unique
        let uuid1 = pid_uuids.get(&1234).unwrap();
        let uuid2 = pid_uuids.get(&5678).unwrap();
        assert_ne!(uuid1, uuid2);

        // id_counter should be incremented appropriately
        assert_eq!(id_counter.load(std::sync::atomic::Ordering::Relaxed), 202);
    }

    #[test]
    fn test_generate_thread_packets_empty() {
        let recorder = create_test_session_recorder();
        let id_counter = Arc::new(AtomicUsize::new(100));
        let mut thread_uuids = HashMap::new();

        let packets = recorder.generate_thread_packets(&id_counter, &mut thread_uuids);

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
        let task = create_test_task_info(1234, 5678, "test_thread");
        recorder.maybe_record_task(&task);

        let packets = recorder.generate_thread_packets(&id_counter, &mut thread_uuids);

        // Should generate 1 packet: thread track descriptor
        assert_eq!(packets.len(), 1);

        // Packet should be the thread track descriptor
        let track_desc = packets[0].track_descriptor();
        assert_eq!(track_desc.uuid(), 150);
        let thread_desc = &track_desc.thread;
        assert_eq!(thread_desc.tid(), 5678);
        assert_eq!(thread_desc.pid(), 1234);
        assert_eq!(thread_desc.thread_name(), "test_thread");

        // thread_uuids should be updated
        assert_eq!(thread_uuids.len(), 1);
        assert_eq!(thread_uuids.get(&5678), Some(&150));

        // id_counter should be incremented
        assert_eq!(id_counter.load(std::sync::atomic::Ordering::Relaxed), 151);
    }

    #[test]
    fn test_generate_thread_packets_multiple_threads() {
        let recorder = create_test_session_recorder();
        let id_counter = Arc::new(AtomicUsize::new(300));
        let mut thread_uuids = HashMap::new();

        // Add multiple threads
        let task1 = create_test_task_info(1234, 5678, "thread1");
        let task2 = create_test_task_info(1234, 9012, "thread2");
        let task3 = create_test_task_info(5678, 1111, "thread3");
        recorder.maybe_record_task(&task1);
        recorder.maybe_record_task(&task2);
        recorder.maybe_record_task(&task3);

        let packets = recorder.generate_thread_packets(&id_counter, &mut thread_uuids);

        // Should generate 3 packets: 3 thread track descriptors
        assert_eq!(packets.len(), 3);

        // All packets should be track descriptors with thread info
        for packet in &packets {
            let track_desc = packet.track_descriptor();
            let _thread_desc = &track_desc.thread;
        }

        // thread_uuids should contain all threads
        assert_eq!(thread_uuids.len(), 3);
        assert!(thread_uuids.contains_key(&5678)); // TID from task1
        assert!(thread_uuids.contains_key(&9012)); // TID from task2
        assert!(thread_uuids.contains_key(&1111)); // TID from task3

        // UUIDs should be unique
        let uuid1 = thread_uuids.get(&5678).unwrap();
        let uuid2 = thread_uuids.get(&9012).unwrap();
        let uuid3 = thread_uuids.get(&1111).unwrap();
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
        let task = create_test_task_info(9999, 8888, "special_thread");
        recorder.maybe_record_task(&task);

        let packets = recorder.generate_thread_packets(&id_counter, &mut thread_uuids);

        assert_eq!(packets.len(), 1);

        let track_desc = packets[0].track_descriptor();
        let thread_desc = &track_desc.thread;

        // Verify all thread details are correct
        assert_eq!(thread_desc.tid(), 8888);
        assert_eq!(thread_desc.pid(), 9999);
        assert_eq!(thread_desc.thread_name(), "special_thread");

        // Verify UUID mapping
        assert_eq!(thread_uuids.get(&8888), Some(&400));
        assert_eq!(track_desc.uuid(), 400);
    }

    #[test]
    fn test_get_min_event_timestamp_no_events() {
        let recorder = create_test_session_recorder();

        let ts = recorder.get_min_event_timestamp();

        // Should return a fallback non-zero value (current BOOTTIME) when no events recorded
        assert!(
            ts > 0,
            "Should return current BOOTTIME when no events recorded"
        );
    }

    #[test]
    fn test_get_min_event_timestamp_with_sched_events() {
        let recorder = create_test_session_recorder();

        // Add a sched event with a known timestamp
        {
            let mut event_recorder = recorder.event_recorder.lock().unwrap();
            // Enable stats to generate runqueue entries
            event_recorder.set_cpu_sched_stats(true);

            let mut task = task_info {
                tgidpid: ((1234u64) << 32) | 5678u64,
                comm: [0; 16],
            };
            task.comm[0..4].copy_from_slice(b"test");

            // Create a wakeup event which adds to runqueue
            let event = crate::systing::types::task_event {
                ts: 1_000_000_000, // 1 second
                r#type: crate::systing::types::event_type::SCHED_WAKEUP,
                cpu: 0,
                target_cpu: 0,
                prev_prio: 0,
                next_prio: 0,
                latency: 0,
                prev: task,
                next: task,
                ..Default::default()
            };
            event_recorder.handle_event(event);
        }

        let ts = recorder.get_min_event_timestamp();

        // Should return the timestamp of the recorded event
        assert_eq!(ts, 1_000_000_000, "Should return min event timestamp");
    }
}
