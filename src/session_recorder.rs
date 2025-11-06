use std::collections::HashMap;
use std::ffi::CStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use crate::events::SystingProbeRecorder;
use crate::perf_recorder::PerfCounterRecorder;
use crate::perfetto::TrackCounter;
use crate::ringbuf::RingBuffer;
use crate::sched::SchedEventRecorder;
use crate::stack_recorder::StackRecorder;
use crate::syscall_recorder::SyscallRecorder;
use crate::systing::types::task_info;
use crate::SystingRecordEvent;

use perfetto_protos::builtin_clock::BuiltinClock;
use perfetto_protos::clock_snapshot::clock_snapshot::Clock;
use perfetto_protos::clock_snapshot::ClockSnapshot;
use perfetto_protos::counter_descriptor::counter_descriptor::Unit;
use perfetto_protos::counter_descriptor::CounterDescriptor;
use perfetto_protos::process_descriptor::ProcessDescriptor;
use perfetto_protos::process_tree::{process_tree::Process as ProtoProcess, ProcessTree};
use perfetto_protos::thread_descriptor::ThreadDescriptor;
use perfetto_protos::trace_packet::TracePacket;
use perfetto_protos::track_descriptor::TrackDescriptor;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

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
    pub syscall_recorder: Mutex<SyscallRecorder>,
    pub process_descriptors: RwLock<HashMap<u64, ProcessDescriptor>>,
    pub processes: RwLock<HashMap<u64, ProtoProcess>>,
    pub threads: RwLock<HashMap<u64, ThreadDescriptor>>,
    pub system: Mutex<System>,
}

pub fn get_clock_value(clock_id: libc::c_int) -> u64 {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(clock_id, &mut ts) } != 0 {
        return 0;
    }
    (ts.tv_sec as u64 * 1_000_000_000) + ts.tv_nsec as u64
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
}

impl SessionRecorder {
    pub fn new(enable_debuginfod: bool) -> Self {
        Self {
            clock_snapshot: Mutex::new(ClockSnapshot::default()),
            event_recorder: Mutex::new(SchedEventRecorder::default()),
            stack_recorder: Mutex::new(StackRecorder::new(enable_debuginfod)),
            perf_counter_recorder: Mutex::new(PerfCounterRecorder::default()),
            sysinfo_recorder: Mutex::new(SysinfoRecorder::default()),
            probe_recorder: Mutex::new(SystingProbeRecorder::default()),
            syscall_recorder: Mutex::new(SyscallRecorder::default()),
            process_descriptors: RwLock::new(HashMap::new()),
            processes: RwLock::new(HashMap::new()),
            threads: RwLock::new(HashMap::new()),
            system: Mutex::new(System::new()),
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

    /// Fetch name from sysinfo when comm is empty
    fn fetch_name_from_system(&self, pid: Pid) -> String {
        let mut system = self.system.lock().unwrap();

        // Refresh with exe to get the process/thread name
        system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[pid]),
            true,
            ProcessRefreshKind::nothing().with_exe(UpdateKind::Always),
        );

        if let Some(process) = system.process(pid) {
            process.name().to_string_lossy().to_string()
        } else {
            String::new()
        }
    }

    /// Fetch cmdline from sysinfo for a process
    fn fetch_cmdline_from_system(&self, pid: Pid) -> Vec<String> {
        let mut system = self.system.lock().unwrap();

        system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[pid]),
            true,
            ProcessRefreshKind::nothing().with_cmd(UpdateKind::Always),
        );

        if let Some(process) = system.process(pid) {
            process
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy().to_string())
                .collect()
        } else {
            vec![]
        }
    }

    /// Record a new process
    fn record_new_process(&self, info: &task_info) {
        // Extract comm
        let comm = Self::extract_comm(info);
        let pid = Pid::from_u32((info.tgidpid >> 32) as u32);

        // Get process name and cmdline
        let process_name = if comm.is_empty() {
            self.fetch_name_from_system(pid)
        } else {
            comm
        };

        let cmdline = self.fetch_cmdline_from_system(pid);

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

    /// Record a new thread
    fn record_new_thread(&self, info: &task_info) {
        // Extract comm
        let comm = Self::extract_comm(info);
        let tid = Pid::from_u32(info.tgidpid as u32);

        // Get thread name
        let thread_name = if comm.is_empty() {
            self.fetch_name_from_system(tid)
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
        self.syscall_recorder.lock().unwrap().drain_ringbuf();
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

    /// Generates the initial trace packets including clock snapshot and root descriptor
    fn generate_initial_packets(&self, id_counter: &Arc<AtomicUsize>) -> Vec<TracePacket> {
        let mut packets = Vec::new();

        // Emit the clock snapshot
        let mut packet = TracePacket::default();
        packet.set_clock_snapshot(self.clock_snapshot.lock().unwrap().clone());
        packet.set_trusted_packet_sequence_id(id_counter.fetch_add(1, Ordering::Relaxed) as u32);
        packets.push(packet);

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

    /// Collects trace packets from all event recorders
    fn collect_recorder_traces(
        &self,
        pid_uuids: &HashMap<i32, u64>,
        thread_uuids: &HashMap<i32, u64>,
        id_counter: &Arc<AtomicUsize>,
    ) -> Vec<TracePacket> {
        let mut packets = Vec::new();

        // Event recorder
        packets.extend(self.event_recorder.lock().unwrap().generate_trace(
            pid_uuids,
            thread_uuids,
            id_counter,
        ));

        // Stack recorder
        packets.extend(
            self.stack_recorder
                .lock()
                .unwrap()
                .generate_trace(id_counter),
        );

        // Performance counter recorder
        packets.extend(
            self.perf_counter_recorder
                .lock()
                .unwrap()
                .generate_trace(id_counter),
        );

        // System info recorder
        packets.extend(
            self.sysinfo_recorder
                .lock()
                .unwrap()
                .generate_trace(id_counter),
        );

        // Probe recorder
        packets.extend(self.probe_recorder.lock().unwrap().generate_trace(
            pid_uuids,
            thread_uuids,
            id_counter,
        ));

        // Syscall recorder
        packets.extend(
            self.syscall_recorder
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

        // Step 2: Generate process-related packets
        packets.extend(self.generate_process_packets(&id_counter, &mut pid_uuids));

        // Step 3: Generate thread-related packets
        packets.extend(self.generate_thread_packets(&id_counter, &mut thread_uuids));

        // Step 4: Collect traces from all recorders
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
    use sysinfo::System;

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
            syscall_recorder: Mutex::new(SyscallRecorder::default()),
            process_descriptors: RwLock::new(HashMap::new()),
            processes: RwLock::new(HashMap::new()),
            threads: RwLock::new(HashMap::new()),
            system: Mutex::new(System::new()),
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

        // Process descriptors should remain empty for threads
        assert!(recorder.process_descriptors.read().unwrap().is_empty());
        assert!(recorder.processes.read().unwrap().is_empty());
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

        // Should generate exactly 2 packets: clock snapshot + root descriptor
        assert_eq!(packets.len(), 2);

        // First packet should be the clock snapshot
        let _clock_snapshot = packets[0].clock_snapshot();
        assert_eq!(packets[0].trusted_packet_sequence_id(), 100);

        // Second packet should be the root track descriptor
        let track_desc = packets[1].track_descriptor();
        assert_eq!(track_desc.name(), "Systing");
        assert_eq!(track_desc.uuid(), 101); // Should be incremented from 100

        // Verify id_counter was incremented appropriately
        assert_eq!(id_counter.load(std::sync::atomic::Ordering::Relaxed), 102);
    }

    #[test]
    fn test_generate_initial_packets_empty_clock() {
        let recorder = create_test_session_recorder();
        let id_counter = Arc::new(AtomicUsize::new(50));

        // Don't set up clock snapshot - should still work with empty snapshot
        let packets = recorder.generate_initial_packets(&id_counter);

        assert_eq!(packets.len(), 2);
        let _clock_snapshot = packets[0].clock_snapshot();
        let _track_desc = packets[1].track_descriptor();
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
}
