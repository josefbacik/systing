use std::collections::HashMap;

use crate::ringbuf::RingBuffer;
use crate::systing::types::syscall_event;
use crate::SystingRecordEvent;

use perfetto_protos::interned_data::InternedData;
use perfetto_protos::trace_packet::trace_packet::SequenceFlags;
use perfetto_protos::trace_packet::TracePacket;
use perfetto_protos::track_descriptor::TrackDescriptor;
use perfetto_protos::track_event::track_event::Type;
use perfetto_protos::track_event::{EventName, TrackEvent};
use syscalls::Sysno;

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
    // Map from syscall number to interned id
    syscall_iids: HashMap<u64, u64>,
    // Map from syscall name to interned id (for deduplication)
    syscall_name_ids: HashMap<String, u64>,
    // Counter for generating unique interned IDs
    next_name_iid: u64,
}

impl SyscallRecorder {
    fn get_or_create_syscall_name_iid(&mut self, syscall_nr: u64) -> u64 {
        // Check if we already have an IID for this syscall number
        if let Some(&iid) = self.syscall_iids.get(&syscall_nr) {
            return iid;
        }

        // Map syscall number to name using the syscalls crate
        let syscall_name = match Sysno::new(syscall_nr as usize) {
            Some(sysno) => sysno.name().to_string(),
            None => {
                // For unknown syscalls, just use the number
                format!("syscall_{}", syscall_nr)
            }
        };

        // Get or create IID for this syscall name
        let iid = if let Some(&existing_iid) = self.syscall_name_ids.get(&syscall_name) {
            existing_iid
        } else {
            // Start IIDs at 1000 to avoid conflicts with other interned data
            if self.next_name_iid == 0 {
                self.next_name_iid = 1000;
            }
            let new_iid = self.next_name_iid;
            self.next_name_iid += 1;
            self.syscall_name_ids.insert(syscall_name, new_iid);
            new_iid
        };

        // Store the syscall number to IID mapping
        self.syscall_iids.insert(syscall_nr, iid);
        iid
    }

    pub fn generate_trace_packets(
        &mut self,
        thread_uuids: &HashMap<i32, u64>,
        id_counter: &Arc<AtomicUsize>,
    ) -> Vec<TracePacket> {
        let mut packets = Vec::new();
        let mut syscall_track_uuids: HashMap<u32, u64> = HashMap::new();
        let sequence_id = id_counter.fetch_add(1, Ordering::Relaxed) as u32;

        // Collect all syscall numbers we need to intern
        let mut syscall_numbers: Vec<u64> = Vec::new();
        for (_pid, syscalls) in self.completed_syscalls.iter() {
            for (_start_ts, _end_ts, syscall_nr) in syscalls {
                syscall_numbers.push(*syscall_nr);
            }
        }

        // Create interned IDs for all unique syscall numbers
        for syscall_nr in syscall_numbers {
            self.get_or_create_syscall_name_iid(syscall_nr);
        }

        // Generate interned data packet with syscall names
        let mut event_names = Vec::new();
        for (name, iid) in &self.syscall_name_ids {
            let mut event_name = EventName::default();
            event_name.set_iid(*iid);
            event_name.set_name(name.clone());
            event_names.push(event_name);
        }

        // Sort by iid for consistency
        event_names.sort_by_key(|e| e.iid());

        let mut interned_packet = TracePacket::default();
        let interned_data = InternedData {
            event_names,
            ..Default::default()
        };
        interned_packet.interned_data = Some(interned_data).into();
        interned_packet.set_trusted_packet_sequence_id(sequence_id);
        interned_packet.set_sequence_flags(
            SequenceFlags::SEQ_INCREMENTAL_STATE_CLEARED as u32
                | SequenceFlags::SEQ_NEEDS_INCREMENTAL_STATE as u32,
        );

        // Add interned data packet first
        packets.push(interned_packet);

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
            for (start_ts, end_ts, syscall_nr) in syscalls {
                // Get the already-created interned ID for this syscall number
                let name_iid = *self.syscall_iids.get(syscall_nr).unwrap();

                // Begin event
                let mut begin_event = TrackEvent::default();
                begin_event.set_type(Type::TYPE_SLICE_BEGIN);
                begin_event.set_name_iid(name_iid);
                begin_event.set_track_uuid(track_uuid);

                let mut begin_packet = TracePacket::default();
                begin_packet.set_timestamp(*start_ts);
                begin_packet.set_track_event(begin_event);
                begin_packet.set_trusted_packet_sequence_id(sequence_id);
                packets.push(begin_packet);

                // End event
                let mut end_event = TrackEvent::default();
                end_event.set_type(Type::TYPE_SLICE_END);
                end_event.set_track_uuid(track_uuid);

                let mut end_packet = TracePacket::default();
                end_packet.set_timestamp(*end_ts);
                end_packet.set_track_event(end_event);
                end_packet.set_trusted_packet_sequence_id(sequence_id);
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

        // Check that the syscall is pending (syscall 1 is write)
        assert_eq!(recorder.pending_syscalls.len(), 1);
        assert!(recorder.pending_syscalls.contains_key(&101));
        let pid_pending = &recorder.pending_syscalls[&101];
        assert_eq!(pid_pending.len(), 1);
        assert!(pid_pending.contains_key(&1)); // syscall 1 = write

        // No completed syscalls yet
        assert!(recorder.completed_syscalls.is_empty());
    }

    #[test]
    fn test_syscall_recorder_sys_exit_without_enter() {
        let mut recorder = SyscallRecorder::default();

        let event = syscall_event {
            ts: 2000,
            task: create_test_task_info(100, 101),
            syscall_nr: 1, // write syscall
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

        // sys_enter for write syscall
        let enter_event = syscall_event {
            ts: 1000,
            task: create_test_task_info(100, 101),
            syscall_nr: 1, // write syscall
            ret: 0,
            cpu: 0,
            is_enter: 1,
        };

        // sys_exit for write syscall
        let exit_event = syscall_event {
            ts: 2000,
            task: create_test_task_info(100, 101),
            syscall_nr: 1, // write syscall
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
        assert_eq!(completed[0], (1000, 2000, 1)); // syscall 1 = write
    }

    #[test]
    fn test_syscall_recorder_multiple_threads() {
        let mut recorder = SyscallRecorder::default();

        // Thread 1 enter (write syscall)
        let event1 = syscall_event {
            ts: 1000,
            task: create_test_task_info(100, 101),
            syscall_nr: 1, // write
            ret: 0,
            cpu: 0,
            is_enter: 1,
        };

        // Thread 2 enter (fork syscall)
        let event2 = syscall_event {
            ts: 1500,
            task: create_test_task_info(200, 201),
            syscall_nr: 2, // fork
            ret: 0,
            cpu: 1,
            is_enter: 1,
        };

        // Thread 1 exit (write syscall)
        let event3 = syscall_event {
            ts: 2000,
            task: create_test_task_info(100, 101),
            syscall_nr: 1, // write
            ret: 10,
            cpu: 0,
            is_enter: 0,
        };

        // Thread 2 exit (fork syscall)
        let event4 = syscall_event {
            ts: 2500,
            task: create_test_task_info(200, 201),
            syscall_nr: 2, // fork
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

        assert_eq!(recorder.completed_syscalls[&101][0], (1000, 2000, 1)); // write
        assert_eq!(recorder.completed_syscalls[&201][0], (1500, 2500, 2)); // fork
    }

    #[test]
    fn test_generate_trace_packets() {
        let mut recorder = SyscallRecorder::default();
        let mut thread_uuids = HashMap::new();
        thread_uuids.insert(101, 500); // Thread 101 has UUID 500
        let id_counter = Arc::new(AtomicUsize::new(1000));

        // Add some complete syscalls (write syscall)
        let enter_event = syscall_event {
            ts: 1000,
            task: create_test_task_info(100, 101),
            syscall_nr: 1, // write syscall
            ret: 0,
            cpu: 0,
            is_enter: 1,
        };

        let exit_event = syscall_event {
            ts: 2000,
            task: create_test_task_info(100, 101),
            syscall_nr: 1, // write syscall
            ret: 42,
            cpu: 0,
            is_enter: 0,
        };

        recorder.handle_event(enter_event);
        recorder.handle_event(exit_event);

        // Generate trace packets
        let packets = recorder.generate_trace_packets(&thread_uuids, &id_counter);

        // Should have:
        // 1. Interned data packet with event names
        // 2. Track descriptor for syscall track
        // 3. Begin event for syscall
        // 4. End event for syscall
        assert_eq!(packets.len(), 4);

        // Check interned data packet
        let interned_packet = &packets[0];
        assert!(interned_packet.interned_data.is_some());
        let interned_data = interned_packet.interned_data.as_ref().unwrap();
        assert_eq!(interned_data.event_names.len(), 1);
        let event_name = &interned_data.event_names[0];
        assert_eq!(event_name.iid(), 1000); // First syscall gets iid 1000
        assert_eq!(event_name.name(), "write");

        // Check track descriptor
        let track_desc_packet = &packets[1];
        assert!(track_desc_packet.has_track_descriptor());
        let track_desc = track_desc_packet.track_descriptor();
        assert_eq!(track_desc.uuid(), 1001); // ID counter was at 1000, incremented for track
        assert_eq!(track_desc.parent_uuid(), 500);
        assert_eq!(track_desc.name(), "Syscalls");

        // Check begin event
        let begin_packet = &packets[2];
        assert!(begin_packet.has_track_event());
        assert_eq!(begin_packet.timestamp(), 1000);
        let begin_event = begin_packet.track_event();
        assert_eq!(begin_event.name_iid(), 1000); // References interned "write" name
        assert_eq!(begin_event.type_(), Type::TYPE_SLICE_BEGIN);
        assert_eq!(begin_event.track_uuid(), 1001);

        // Check end event
        let end_packet = &packets[3];
        assert!(end_packet.has_track_event());
        assert_eq!(end_packet.timestamp(), 2000);
        let end_event = end_packet.track_event();
        assert_eq!(end_event.type_(), Type::TYPE_SLICE_END);
        assert_eq!(end_event.track_uuid(), 1001);

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

        // Should generate only the interned data packet since thread UUID is missing
        // The syscall tracks and events won't be generated without thread UUIDs
        assert_eq!(packets.len(), 1);

        // Check that we do have the interned data packet with the syscall name
        let interned_packet = &packets[0];
        assert!(interned_packet.interned_data.is_some());
        let interned_data = interned_packet.interned_data.as_ref().unwrap();
        assert_eq!(interned_data.event_names.len(), 1);
        let event_name = &interned_data.event_names[0];
        assert_eq!(event_name.name(), "write");

        // Events should still be cleared
        assert!(recorder.completed_syscalls.is_empty());
    }
}
