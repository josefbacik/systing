use std::collections::HashMap;
use std::ffi::CStr;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use anyhow::Result;

use crate::events::SystingProbeRecorder;
use crate::network_recorder::NetworkRecorder;
use crate::parquet::StreamingParquetWriter;
use crate::perf_recorder::PerfCounterRecorder;
use crate::perfetto::{TraceWriter, TrackCounter};
use crate::record::RecordCollector;
use crate::ringbuf::RingBuffer;
use crate::sched::SchedEventRecorder;
use crate::stack_recorder::StackRecorder;
use crate::systing_core::types::task_info;
use crate::systing_core::SystingRecordEvent;
use crate::trace::{
    ClockSnapshotRecord, CounterRecord, CounterTrackRecord, ProcessRecord, ThreadRecord,
};
use crate::utid::UtidGenerator;

use perfetto_protos::builtin_clock::BuiltinClock;
use perfetto_protos::clock_snapshot::clock_snapshot::Clock;
use perfetto_protos::clock_snapshot::ClockSnapshot;
use perfetto_protos::counter_descriptor::counter_descriptor::Unit;
use perfetto_protos::counter_descriptor::CounterDescriptor;
use perfetto_protos::process_descriptor::ProcessDescriptor;
use perfetto_protos::process_tree::process_tree::Process as ProtoProcess;
use perfetto_protos::system_info::Utsname;
use perfetto_protos::thread_descriptor::ThreadDescriptor;
use perfetto_protos::trace_packet::TracePacket;
use perfetto_protos::track_descriptor::TrackDescriptor;
use std::fs::{self, File};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

#[derive(Default)]
pub struct SysInfoEvent {
    pub cpu: u32,
    pub ts: u64,
    pub frequency: i64,
}

pub struct SysinfoRecorder {
    pub ringbuf: RingBuffer<SysInfoEvent>,
    pub frequency: HashMap<u32, Vec<TrackCounter>>,
    // Streaming support
    streaming_collector: Option<Box<dyn RecordCollector + Send>>,
    track_ids: HashMap<u32, i64>,
    next_track_id: i64,
}

impl Default for SysinfoRecorder {
    fn default() -> Self {
        Self {
            ringbuf: RingBuffer::default(),
            frequency: HashMap::new(),
            streaming_collector: None,
            track_ids: HashMap::new(),
            next_track_id: 1,
        }
    }
}

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
    /// Shared utid generator for consistent thread IDs across all recorders.
    utid_generator: Arc<UtidGenerator>,
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
        if let Some(ref mut collector) = self.streaming_collector {
            // STREAMING PATH: emit directly to collector
            let cpu = event.cpu;
            let track_id = if let Some(&id) = self.track_ids.get(&cpu) {
                id
            } else {
                let track_id = self.next_track_id;
                self.next_track_id += 1;

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
        } else {
            // NON-STREAMING PATH: accumulate (existing behavior)
            let freq = self.frequency.entry(event.cpu).or_default();
            freq.push(TrackCounter {
                ts: event.ts,
                count: event.frequency,
            });
        }
    }
}

impl SysinfoRecorder {
    /// Write trace data directly to a RecordCollector (Parquet-first path).
    ///
    /// This method outputs CPU frequency counter records directly.
    pub fn write_records(
        &self,
        collector: &mut dyn RecordCollector,
        track_id_counter: &mut i64,
    ) -> Result<()> {
        for (cpu, events) in self.frequency.iter() {
            let track_id = *track_id_counter;
            *track_id_counter += 1;

            collector.add_counter_track(CounterTrackRecord {
                id: track_id,
                name: format!("CPU {cpu} frequency"),
                unit: Some("Hz".to_string()),
            })?;

            for event in events.iter() {
                collector.add_counter(CounterRecord {
                    ts: event.ts as i64,
                    track_id,
                    value: event.count as f64,
                })?;
            }
        }
        Ok(())
    }

    /// Write trace data to Perfetto format (used by parquet-to-perfetto conversion).
    pub fn write_trace(
        &self,
        writer: &mut dyn TraceWriter,
        id_counter: &Arc<AtomicUsize>,
    ) -> Result<()> {
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
            writer.write_packet(&packet)?;

            let seq = id_counter.fetch_add(1, Ordering::Relaxed) as u32;
            for event in events.iter() {
                writer.write_packet(&event.to_track_event(desc_uuid, seq))?;
            }
        }
        Ok(())
    }

    /// Returns the minimum timestamp from all frequency events, or None if no events recorded.
    ///
    /// Note: In streaming mode, this returns `None` since events bypass the frequency HashMap.
    pub fn min_timestamp(&self) -> Option<u64> {
        self.frequency
            .values()
            .filter_map(|counters| counters.first())
            .map(|c| c.ts)
            .min()
    }

    /// Set the streaming collector for direct parquet output.
    ///
    /// When set, events will be streamed directly to the collector during
    /// handle_event() instead of being accumulated in memory.
    ///
    /// Note: Each streaming recorder gets its own StreamingParquetWriter instance,
    /// so local track IDs (starting at 1) are safe - they write to separate files.
    pub fn set_streaming_collector(&mut self, collector: Box<dyn RecordCollector + Send>) {
        self.streaming_collector = Some(collector);
    }

    /// Returns true if streaming mode is enabled.
    ///
    /// When streaming is enabled, events are written directly to the collector
    /// during `handle_event()` rather than being accumulated in memory.
    /// Use `set_streaming_collector()` to enable streaming mode.
    pub fn is_streaming(&self) -> bool {
        self.streaming_collector.is_some()
    }

    /// Finish streaming and return the collector.
    ///
    /// Flushes pending data, clears internal state, and returns the collector
    /// for finalization.
    pub fn finish(&mut self) -> Result<Option<Box<dyn RecordCollector + Send>>> {
        if let Some(mut collector) = self.streaming_collector.take() {
            // Data already streamed during handle_event, just flush
            collector.flush()?;
            // Clear track_ids cache and reset counter
            self.track_ids.clear();
            self.next_track_id = 1;
            Ok(Some(collector))
        } else {
            Ok(None)
        }
    }
}

impl SessionRecorder {
    pub fn new(enable_debuginfod: bool, resolve_network_addresses: bool) -> Self {
        let utid_generator = Arc::new(UtidGenerator::new());
        Self {
            clock_snapshot: Mutex::new(ClockSnapshot::default()),
            event_recorder: Mutex::new(SchedEventRecorder::new(Arc::clone(&utid_generator))),
            stack_recorder: Mutex::new(StackRecorder::new(
                enable_debuginfod,
                Arc::clone(&utid_generator),
            )),
            perf_counter_recorder: Mutex::new(PerfCounterRecorder::default()),
            sysinfo_recorder: Mutex::new(SysinfoRecorder::default()),
            probe_recorder: Mutex::new(SystingProbeRecorder::new(Arc::clone(&utid_generator))),
            network_recorder: Mutex::new(NetworkRecorder::new(
                resolve_network_addresses,
                Arc::clone(&utid_generator),
            )),
            process_descriptors: RwLock::new(HashMap::new()),
            processes: RwLock::new(HashMap::new()),
            threads: RwLock::new(HashMap::new()),
            utid_generator,
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
            name_from_proc
        } else if !comm.is_empty() {
            comm
        } else {
            format!("<pid:{pid}>")
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
    /// directly to parquet files.
    ///
    /// # Arguments
    /// * `output_dir` - Directory to write Parquet files to
    pub fn init_streaming_parquet(&self, output_dir: &Path) -> Result<()> {
        // Set up streaming collector for scheduler events
        let writer = StreamingParquetWriter::new(output_dir)?;
        self.event_recorder
            .lock()
            .unwrap()
            .set_streaming_collector(Box::new(writer));

        // Enable streaming mode for stack recorder (samples buffered, written at end)
        self.stack_recorder.lock().unwrap().enable_streaming();

        // Set up streaming collector for network recorder (events emitted immediately)
        let network_writer = StreamingParquetWriter::new(output_dir)?;
        self.network_recorder
            .lock()
            .unwrap()
            .set_streaming_collector(Box::new(network_writer));

        // Set up streaming collector for probe recorder (events emitted on completion)
        let probe_writer = StreamingParquetWriter::new(output_dir)?;
        self.probe_recorder
            .lock()
            .unwrap()
            .set_streaming_collector(Box::new(probe_writer));

        // Set up streaming collector for perf counter recorder (events emitted immediately).
        // Perf counters get their own writer because counter tracks are self-contained and
        // the local track_id counter (starting at 1) is safe since each writer outputs to
        // separate parquet files (counter.parquet, counter_track.parquet).
        let perf_writer = StreamingParquetWriter::new(output_dir)?;
        self.perf_counter_recorder
            .lock()
            .unwrap()
            .set_streaming_collector(Box::new(perf_writer));

        // Set up streaming collector for sysinfo recorder (CPU frequency events).
        // Like perf counters, sysinfo gets its own writer for counter tracks.
        let sysinfo_writer = StreamingParquetWriter::new(output_dir)?;
        self.sysinfo_recorder
            .lock()
            .unwrap()
            .set_streaming_collector(Box::new(sysinfo_writer));

        Ok(())
    }

    /// Generate trace data directly to Parquet files (Parquet-first path).
    ///
    /// This method outputs trace data directly to Parquet files without going through
    /// the Perfetto format. It uses the StreamingParquetWriter and calls write_records()
    /// on each recorder.
    ///
    /// # Arguments
    /// * `output_dir` - Directory to write Parquet files to
    pub fn generate_parquet_trace(&self, output_dir: &Path) -> Result<()> {
        eprintln!("Generating Parquet trace to {output_dir:?}...");

        // Get the end timestamp for flushing streaming data
        let end_ts = get_clock_value(libc::CLOCK_BOOTTIME) as i64;

        // Step 1: Finish streaming collection in the event recorder and retrieve the collector
        eprintln!("Flushing scheduler trace records from streaming...");
        let collector_opt = {
            let mut event_recorder = self.event_recorder.lock().unwrap();
            event_recorder.finish(end_ts)?
        };

        // Track whether we got a collector from streaming
        let has_streaming_collector = collector_opt.is_some();

        // Use the streaming collector if available, otherwise create a new writer
        let mut writer: Box<dyn RecordCollector + Send> = if let Some(collector) = collector_opt {
            // We have a streaming collector with scheduler data already written
            collector
        } else {
            // Streaming wasn't enabled, create a new writer
            Box::new(StreamingParquetWriter::new(output_dir)?)
        };

        // ID counters for generating unique IDs across all records
        let mut track_id_counter: i64 = 1;
        let mut slice_id_counter: i64 = 1;
        let mut instant_id_counter: i64 = 1;
        let mut stack_id_counter: i64 = 1;

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

        // Write system info (utsname)
        if let Some(utsname) = get_system_utsname() {
            writer.set_sysinfo(crate::trace::SysInfoRecord {
                sysname: utsname.sysname().to_string(),
                release: utsname.release().to_string(),
                version: utsname.version().to_string(),
                machine: utsname.machine().to_string(),
            })?;
        }

        // Step 3: Generate process and thread records
        // Use the shared UtidGenerator to get consistent utid/upid values that match
        // what was used during streaming.
        eprintln!("Writing process and thread data...");

        // Write process records using the shared upid generator
        let processes = self.processes.read().unwrap();
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

            writer.add_process(ProcessRecord {
                upid,
                pid,
                name,
                parent_upid: None, // Could be set from parent_pid if needed
                cmdline,
            })?;
        }
        drop(processes);

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

        // Step 5: Write records from all recorders
        // Note: We skip the scheduler trace records here because they were already written
        // via streaming (if streaming was enabled), or will be written via write_records (if not).
        // Only write scheduler records if streaming was not enabled.
        if !has_streaming_collector {
            eprintln!("Writing scheduler trace records...");
            self.event_recorder
                .lock()
                .unwrap()
                .write_records(&mut *writer)?;
        }

        // Handle stack records - streaming mode uses finish(), non-streaming uses write_records()
        let stack_streaming = self.stack_recorder.lock().unwrap().is_streaming();
        if stack_streaming {
            eprintln!("Flushing stack samples and symbolizing stacks...");
            // Pass ownership to finish(), which returns it after writing
            writer = self.stack_recorder.lock().unwrap().finish(writer)?;
        } else {
            eprintln!("Writing stack trace records...");
            self.stack_recorder
                .lock()
                .unwrap()
                .write_records(&mut *writer, &mut stack_id_counter)?;
        }

        // Handle network records - streaming mode uses finish(), non-streaming uses write_records()
        let network_streaming = self.network_recorder.lock().unwrap().is_streaming();
        if network_streaming {
            eprintln!("Flushing network trace records...");
            // Finish returns the collector it was using for streaming
            // We need to properly close it to finalize the Parquet files
            if let Some(network_collector) = self.network_recorder.lock().unwrap().finish()? {
                network_collector.finish_boxed()?;
            }
        } else {
            eprintln!("Writing network trace records...");
            self.network_recorder.lock().unwrap().write_records(
                &mut *writer,
                &mut track_id_counter,
                &mut slice_id_counter,
                &mut instant_id_counter,
            )?;
        }

        // Handle perf counter records (streaming or non-streaming)
        let perf_streaming = self.perf_counter_recorder.lock().unwrap().is_streaming();
        if perf_streaming {
            eprintln!("Flushing perf counter records from streaming...");
            if let Some(perf_collector) = self.perf_counter_recorder.lock().unwrap().finish()? {
                perf_collector.finish_boxed()?;
            }
        } else {
            eprintln!("Writing perf counter records...");
            self.perf_counter_recorder
                .lock()
                .unwrap()
                .write_records(&mut *writer, &mut track_id_counter)?;
        }

        // Handle sysinfo records (streaming or non-streaming)
        let sysinfo_streaming = self.sysinfo_recorder.lock().unwrap().is_streaming();
        if sysinfo_streaming {
            eprintln!("Flushing sysinfo records from streaming...");
            if let Some(sysinfo_collector) = self.sysinfo_recorder.lock().unwrap().finish()? {
                sysinfo_collector.finish_boxed()?;
            }
        } else {
            eprintln!("Writing sysinfo records...");
            self.sysinfo_recorder
                .lock()
                .unwrap()
                .write_records(&mut *writer, &mut track_id_counter)?;
        }

        // Handle probe records - streaming mode uses finish(), non-streaming uses write_records()
        let probe_streaming = self.probe_recorder.lock().unwrap().is_streaming();
        if probe_streaming {
            eprintln!("Flushing probe trace records...");
            if let Some(probe_collector) = self.probe_recorder.lock().unwrap().finish()? {
                probe_collector.finish_boxed()?;
            }
        } else {
            eprintln!("Writing probe trace records...");
            self.probe_recorder.lock().unwrap().write_records(
                &mut *writer,
                &mut track_id_counter,
                &mut slice_id_counter,
                &mut instant_id_counter,
            )?;
        }

        // Step 6: Finish writing and close all files
        eprintln!("Finishing Parquet trace...");
        // Flush and properly close all Parquet writers
        writer.finish_boxed()?;

        eprintln!("Parquet trace generation complete.");
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
            recorder.event_recorder.lock().unwrap().min_timestamp(),
            recorder.stack_recorder.lock().unwrap().min_timestamp(),
            recorder
                .perf_counter_recorder
                .lock()
                .unwrap()
                .min_timestamp(),
            recorder.sysinfo_recorder.lock().unwrap().min_timestamp(),
            recorder.probe_recorder.lock().unwrap().min_timestamp(),
            recorder.network_recorder.lock().unwrap().min_timestamp(),
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
        SessionRecorder {
            clock_snapshot: Mutex::new(ClockSnapshot::default()),
            event_recorder: Mutex::new(SchedEventRecorder::new(Arc::clone(&utid_generator))),
            stack_recorder: Mutex::new(StackRecorder::new(false, Arc::clone(&utid_generator))),
            perf_counter_recorder: Mutex::new(PerfCounterRecorder::default()),
            sysinfo_recorder: Mutex::new(SysinfoRecorder::default()),
            probe_recorder: Mutex::new(SystingProbeRecorder::new(Arc::clone(&utid_generator))),
            network_recorder: Mutex::new(NetworkRecorder::default()),
            process_descriptors: RwLock::new(HashMap::new()),
            processes: RwLock::new(HashMap::new()),
            threads: RwLock::new(HashMap::new()),
            utid_generator,
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

    #[test]
    fn test_get_min_event_timestamp_with_sched_events() {
        let recorder = create_test_session_recorder();

        // Add a sched event with a known timestamp
        {
            let mut event_recorder = recorder.event_recorder.lock().unwrap();

            let mut task = task_info {
                tgidpid: ((1234u64) << 32) | 5678u64,
                comm: [0; 16],
            };
            task.comm[0..4].copy_from_slice(b"test");

            // Create a switch event which is stored in compact_sched
            let event = crate::systing_core::types::task_event {
                ts: 1_000_000_000, // 1 second
                r#type: crate::systing_core::types::event_type::SCHED_SWITCH,
                cpu: 0,
                target_cpu: 0,
                prev_prio: 0,
                next_prio: 0,
                prev: task,
                next: task,
                ..Default::default()
            };
            event_recorder.handle_event(event);
        }

        let ts = get_min_event_timestamp(&recorder);

        // Should return the timestamp of the recorded event
        assert_eq!(ts, 1_000_000_000, "Should return min event timestamp");
    }
}
