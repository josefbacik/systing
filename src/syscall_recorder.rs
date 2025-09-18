use std::collections::HashMap;

use crate::ringbuf::RingBuffer;
use crate::systing::types::syscall_event;
use crate::SystingRecordEvent;

use perfetto_protos::trace_packet::TracePacket;
use perfetto_protos::track_descriptor::TrackDescriptor;
use perfetto_protos::track_event::track_event::Type;
use perfetto_protos::track_event::TrackEvent;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

// Struct to track a pending syscall (sys_enter waiting for sys_exit)
#[derive(Clone)]
struct PendingSyscall {
    enter_ts: u64,
}

#[derive(Default)]
pub struct SyscallRecorder {
    pub ringbuf: RingBuffer<syscall_event>,
    // Map from PID to pending syscalls (syscall_nr -> PendingSyscall)
    pending_syscalls: HashMap<u32, HashMap<u64, PendingSyscall>>,
    // Map from PID to completed syscall ranges
    completed_syscalls: HashMap<u32, Vec<(u64, u64, u64)>>, // (start_ts, end_ts, syscall_nr)
}

impl SyscallRecorder {
    pub fn generate_trace_packets(
        &mut self,
        thread_uuids: &HashMap<i32, u64>,
        id_counter: &Arc<AtomicUsize>,
    ) -> Vec<TracePacket> {
        let mut packets = Vec::new();
        let mut syscall_track_uuids: HashMap<u32, u64> = HashMap::new();

        // Generate per-thread syscall tracks and events
        for (pid, syscalls) in self.completed_syscalls.iter() {
            if syscalls.is_empty() {
                continue;
            }

            // Get the thread UUID if it exists
            let thread_uuid = match thread_uuids.get(&(*pid as i32)) {
                Some(uuid) => *uuid,
                None => continue, // Skip if we don't have a thread UUID
            };

            // Create a syscall track for this thread
            let track_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;
            syscall_track_uuids.insert(*pid, track_uuid);

            let mut desc = TrackDescriptor::default();
            desc.set_uuid(track_uuid);
            desc.set_parent_uuid(thread_uuid);
            desc.set_name("Syscalls".to_string());

            let mut packet = TracePacket::default();
            packet.set_track_descriptor(desc);
            packets.push(packet);

            // Generate range events for each syscall
            let seq = id_counter.fetch_add(1, Ordering::Relaxed) as u32;
            for (start_ts, end_ts, syscall_nr) in syscalls {
                let syscall_name = format!("sys_{}", syscall_nr);

                // Begin event
                let mut begin_event = TrackEvent::default();
                begin_event.set_type(Type::TYPE_SLICE_BEGIN);
                begin_event.set_name(syscall_name.clone());
                begin_event.set_track_uuid(track_uuid);

                let mut begin_packet = TracePacket::default();
                begin_packet.set_timestamp(*start_ts);
                begin_packet.set_track_event(begin_event);
                begin_packet.set_trusted_packet_sequence_id(seq);
                packets.push(begin_packet);

                // End event
                let mut end_event = TrackEvent::default();
                end_event.set_type(Type::TYPE_SLICE_END);
                end_event.set_track_uuid(track_uuid);

                let mut end_packet = TracePacket::default();
                end_packet.set_timestamp(*end_ts);
                end_packet.set_track_event(end_event);
                end_packet.set_trusted_packet_sequence_id(seq);
                packets.push(end_packet);
            }
        }

        // Clear completed syscalls after generating packets
        self.completed_syscalls.clear();

        packets
    }
}

impl SystingRecordEvent<syscall_event> for SyscallRecorder {
    fn ringbuf(&self) -> &RingBuffer<syscall_event> {
        &self.ringbuf
    }

    fn ringbuf_mut(&mut self) -> &mut RingBuffer<syscall_event> {
        &mut self.ringbuf
    }

    fn handle_event(&mut self, event: syscall_event) {
        let pid = event.task.tgidpid as u32;

        if event.is_enter == 1 {
            // sys_enter: record pending syscall
            let pending = PendingSyscall { enter_ts: event.ts };
            self.pending_syscalls
                .entry(pid)
                .or_default()
                .insert(event.syscall_nr, pending);
        } else {
            // sys_exit: match with pending syscall
            if let Some(pid_pending) = self.pending_syscalls.get_mut(&pid) {
                if let Some(pending) = pid_pending.remove(&event.syscall_nr) {
                    // Found matching sys_enter, create a complete range
                    self.completed_syscalls.entry(pid).or_default().push((
                        pending.enter_ts,
                        event.ts,
                        event.syscall_nr,
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::systing::types::task_info;

    fn create_test_task_info(tgid: u32, pid: u32) -> task_info {
        task_info {
            tgidpid: ((tgid as u64) << 32) | (pid as u64),
            comm: [0; 16],
        }
    }

    #[test]
    fn test_syscall_recorder_sys_enter() {
        let mut recorder = SyscallRecorder::default();

        let event = syscall_event {
            ts: 1000,
            task: create_test_task_info(100, 101),
            syscall_nr: 1, // sys_write
            ret: 0,
            cpu: 0,
            is_enter: 1,
        };

        recorder.handle_event(event);

        // Check that the syscall is pending
        assert_eq!(recorder.pending_syscalls.len(), 1);
        assert!(recorder.pending_syscalls.contains_key(&101));
        let pid_pending = &recorder.pending_syscalls[&101];
        assert_eq!(pid_pending.len(), 1);
        assert!(pid_pending.contains_key(&1));

        // No completed syscalls yet
        assert!(recorder.completed_syscalls.is_empty());
    }

    #[test]
    fn test_syscall_recorder_sys_exit_without_enter() {
        let mut recorder = SyscallRecorder::default();

        let event = syscall_event {
            ts: 2000,
            task: create_test_task_info(100, 101),
            syscall_nr: 1,
            ret: 42,
            cpu: 1,
            is_enter: 0,
        };

        recorder.handle_event(event);

        // No pending or completed syscalls since there was no matching enter
        assert!(recorder.pending_syscalls.is_empty());
        assert!(recorder.completed_syscalls.is_empty());
    }

    #[test]
    fn test_syscall_recorder_complete_syscall() {
        let mut recorder = SyscallRecorder::default();

        // sys_enter
        let enter_event = syscall_event {
            ts: 1000,
            task: create_test_task_info(100, 101),
            syscall_nr: 1,
            ret: 0,
            cpu: 0,
            is_enter: 1,
        };

        // sys_exit
        let exit_event = syscall_event {
            ts: 2000,
            task: create_test_task_info(100, 101),
            syscall_nr: 1,
            ret: 42,
            cpu: 0,
            is_enter: 0,
        };

        recorder.handle_event(enter_event);
        recorder.handle_event(exit_event);

        // Check that the syscall is completed (the PID entry exists but is empty)
        assert_eq!(recorder.pending_syscalls.len(), 1);
        assert!(recorder.pending_syscalls[&101].is_empty());
        assert_eq!(recorder.completed_syscalls.len(), 1);
        assert!(recorder.completed_syscalls.contains_key(&101));

        let completed = &recorder.completed_syscalls[&101];
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0], (1000, 2000, 1));
    }

    #[test]
    fn test_syscall_recorder_multiple_threads() {
        let mut recorder = SyscallRecorder::default();

        // Thread 1 enter
        let event1 = syscall_event {
            ts: 1000,
            task: create_test_task_info(100, 101),
            syscall_nr: 1,
            ret: 0,
            cpu: 0,
            is_enter: 1,
        };

        // Thread 2 enter
        let event2 = syscall_event {
            ts: 1500,
            task: create_test_task_info(200, 201),
            syscall_nr: 2,
            ret: 0,
            cpu: 1,
            is_enter: 1,
        };

        // Thread 1 exit
        let event3 = syscall_event {
            ts: 2000,
            task: create_test_task_info(100, 101),
            syscall_nr: 1,
            ret: 10,
            cpu: 0,
            is_enter: 0,
        };

        // Thread 2 exit
        let event4 = syscall_event {
            ts: 2500,
            task: create_test_task_info(200, 201),
            syscall_nr: 2,
            ret: 20,
            cpu: 1,
            is_enter: 0,
        };

        recorder.handle_event(event1);
        recorder.handle_event(event2);
        recorder.handle_event(event3);
        recorder.handle_event(event4);

        // Check that we have completed syscalls for both threads
        assert_eq!(recorder.completed_syscalls.len(), 2);
        assert_eq!(recorder.completed_syscalls[&101].len(), 1);
        assert_eq!(recorder.completed_syscalls[&201].len(), 1);

        assert_eq!(recorder.completed_syscalls[&101][0], (1000, 2000, 1));
        assert_eq!(recorder.completed_syscalls[&201][0], (1500, 2500, 2));
    }

    #[test]
    fn test_generate_trace_packets() {
        let mut recorder = SyscallRecorder::default();
        let mut thread_uuids = HashMap::new();
        thread_uuids.insert(101, 500); // Thread 101 has UUID 500
        let id_counter = Arc::new(AtomicUsize::new(1000));

        // Add some complete syscalls
        let enter_event = syscall_event {
            ts: 1000,
            task: create_test_task_info(100, 101),
            syscall_nr: 1,
            ret: 0,
            cpu: 0,
            is_enter: 1,
        };

        let exit_event = syscall_event {
            ts: 2000,
            task: create_test_task_info(100, 101),
            syscall_nr: 1,
            ret: 42,
            cpu: 0,
            is_enter: 0,
        };

        recorder.handle_event(enter_event);
        recorder.handle_event(exit_event);

        // Generate trace packets
        let packets = recorder.generate_trace_packets(&thread_uuids, &id_counter);

        // Should have:
        // 1. Track descriptor for syscall track
        // 2. Begin event for syscall
        // 3. End event for syscall
        assert_eq!(packets.len(), 3);

        // Check track descriptor
        let track_desc_packet = &packets[0];
        assert!(track_desc_packet.has_track_descriptor());
        let track_desc = track_desc_packet.track_descriptor();
        assert_eq!(track_desc.uuid(), 1000);
        assert_eq!(track_desc.parent_uuid(), 500);
        assert_eq!(track_desc.name(), "Syscalls");

        // Check begin event
        let begin_packet = &packets[1];
        assert!(begin_packet.has_track_event());
        assert_eq!(begin_packet.timestamp(), 1000);
        let begin_event = begin_packet.track_event();
        assert_eq!(begin_event.name(), "sys_1");
        assert_eq!(begin_event.type_(), Type::TYPE_SLICE_BEGIN);
        assert_eq!(begin_event.track_uuid(), 1000);

        // Check end event
        let end_packet = &packets[2];
        assert!(end_packet.has_track_event());
        assert_eq!(end_packet.timestamp(), 2000);
        let end_event = end_packet.track_event();
        assert_eq!(end_event.type_(), Type::TYPE_SLICE_END);
        assert_eq!(end_event.track_uuid(), 1000);

        // Events should be cleared after generating packets
        assert!(recorder.completed_syscalls.is_empty());
    }

    #[test]
    fn test_generate_trace_packets_no_thread_uuid() {
        let mut recorder = SyscallRecorder::default();
        let thread_uuids = HashMap::new(); // No thread UUIDs
        let id_counter = Arc::new(AtomicUsize::new(1000));

        // Add a complete syscall
        recorder
            .completed_syscalls
            .insert(101, vec![(1000, 2000, 1)]);

        // Generate trace packets
        let packets = recorder.generate_trace_packets(&thread_uuids, &id_counter);

        // Should generate no packets since thread UUID is missing
        assert_eq!(packets.len(), 0);

        // Events should still be cleared
        assert!(recorder.completed_syscalls.is_empty());
    }
}
