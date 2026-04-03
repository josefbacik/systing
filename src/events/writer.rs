use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::Result;

use perfetto_protos::interned_data::InternedData;
use perfetto_protos::trace_packet::trace_packet::SequenceFlags;
use perfetto_protos::trace_packet::TracePacket;
use perfetto_protos::track_event::track_event::Type;
use perfetto_protos::track_event::{EventName, TrackEvent};

use crate::perfetto::TraceWriter;
use crate::record::RecordCollector;
use crate::trace::{ArgRecord, InstantArgRecord, InstantRecord, SliceRecord, TrackRecord};

use super::{convert_arg, syscall_name, ArgValue, SystingProbeRecorder, SYSCALLS_TRACK_NAME};

impl SystingProbeRecorder {
    pub(super) fn get_or_create_syscall_name_iid(
        &mut self,
        syscall_nr: u64,
        id_counter: &Arc<AtomicUsize>,
    ) -> u64 {
        if let Some(&iid) = self.syscall_iids.get(&syscall_nr) {
            return iid;
        }

        let name = syscall_name(syscall_nr);

        let iid = if let Some(&existing_iid) = self.syscall_name_ids.get(&name) {
            existing_iid
        } else {
            let new_iid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;
            self.syscall_name_ids.insert(name, new_iid);
            new_iid
        };

        self.syscall_iids.insert(syscall_nr, iid);
        iid
    }

    fn add_arg_annotations(tevent: &mut TrackEvent, args: &[(String, ArgValue)]) {
        use perfetto_protos::debug_annotation::DebugAnnotation;

        for (name, value) in args {
            let mut annotation = DebugAnnotation::default();
            annotation.set_name(name.clone());
            match value {
                ArgValue::String(s) => annotation.set_string_value(s.clone()),
                ArgValue::Long(v) => annotation.set_uint_value(*v),
            }
            tevent.debug_annotations.push(annotation);
        }
    }

    /// Write trace data directly to a RecordCollector (Parquet-first path).
    ///
    /// This method outputs probe events as native records without going through Perfetto format.
    /// If streaming mode was enabled, all data was already streamed and this returns early.
    pub fn write_records(
        &self,
        collector: &mut dyn RecordCollector,
        track_id_counter: &mut i64,
        slice_id_counter: &mut i64,
        instant_id_counter: &mut i64,
    ) -> Result<()> {
        // If streaming was enabled, all data was already streamed
        if self.streaming_enabled {
            return Ok(());
        }

        // Process thread instant events
        for (pidtgid, tracks) in self.events.iter() {
            let tid = *pidtgid as i32;
            let utid = Some(self.utid_generator.get_or_create_utid(tid));

            for (track_name, track_events) in tracks.iter() {
                let track_id = *track_id_counter;
                *track_id_counter += 1;

                collector.add_track(TrackRecord {
                    id: track_id,
                    name: track_name.clone(),
                    parent_id: None,
                })?;

                for event in track_events.iter() {
                    let instant_id = *instant_id_counter;
                    *instant_id_counter += 1;

                    collector.add_instant(InstantRecord {
                        id: instant_id,
                        ts: event.ts as i64,
                        track_id,
                        utid,
                        name: event.name.clone(),
                        category: None,
                    })?;

                    // Output args
                    for arg in &event.args {
                        let (key, int_value, string_value) = convert_arg(arg);
                        collector.add_instant_arg(InstantArgRecord {
                            instant_id,
                            key,
                            int_value,
                            string_value,
                            real_value: None,
                        })?;
                    }
                }
            }
        }

        // Process thread range events (slices)
        for (pidtgid, tracks) in self.recorded_ranges.iter() {
            let tid = *pidtgid as i32;
            let utid = Some(self.utid_generator.get_or_create_utid(tid));

            for (track_name, ranges) in tracks.iter() {
                let track_id = *track_id_counter;
                *track_id_counter += 1;

                collector.add_track(TrackRecord {
                    id: track_id,
                    name: track_name.clone(),
                    parent_id: None,
                })?;

                for range in ranges.iter().filter(|r| r.end >= r.start) {
                    let slice_id = *slice_id_counter;
                    *slice_id_counter += 1;

                    collector.add_slice(SliceRecord {
                        id: slice_id,
                        ts: range.start as i64,
                        dur: (range.end - range.start) as i64,
                        track_id,
                        utid,
                        name: range.range_name.clone(),
                        category: None,
                        depth: 0,
                    })?;

                    // Output args
                    for arg in &range.args {
                        let (key, int_value, string_value) = convert_arg(arg);
                        collector.add_arg(ArgRecord {
                            slice_id,
                            key,
                            int_value,
                            string_value,
                            real_value: None,
                        })?;
                    }
                }
            }
        }

        // Process CPU range events
        for (cpu, tracks) in self.cpu_ranges.iter() {
            for (track_name, ranges) in tracks.iter() {
                let track_id = *track_id_counter;
                *track_id_counter += 1;

                collector.add_track(TrackRecord {
                    id: track_id,
                    name: format!("{track_name} CPU {cpu}"),
                    parent_id: None,
                })?;

                for range in ranges.iter().filter(|r| r.end >= r.start) {
                    let slice_id = *slice_id_counter;
                    *slice_id_counter += 1;

                    collector.add_slice(SliceRecord {
                        id: slice_id,
                        ts: range.start as i64,
                        dur: (range.end - range.start) as i64,
                        track_id,
                        utid: None,
                        name: range.range_name.clone(),
                        category: None,
                        depth: 0,
                    })?;

                    // Output args
                    for arg in &range.args {
                        let (key, int_value, string_value) = convert_arg(arg);
                        collector.add_arg(ArgRecord {
                            slice_id,
                            key,
                            int_value,
                            string_value,
                            real_value: None,
                        })?;
                    }
                }
            }
        }

        // Process CPU instant events
        for (cpu, tracks) in self.cpu_events.iter() {
            for (track_name, track_events) in tracks.iter() {
                let track_id = *track_id_counter;
                *track_id_counter += 1;

                collector.add_track(TrackRecord {
                    id: track_id,
                    name: format!("{track_name} CPU {cpu}"),
                    parent_id: None,
                })?;

                for event in track_events.iter() {
                    let instant_id = *instant_id_counter;
                    *instant_id_counter += 1;

                    collector.add_instant(InstantRecord {
                        id: instant_id,
                        ts: event.ts as i64,
                        track_id,
                        utid: None,
                        name: event.name.clone(),
                        category: None,
                    })?;

                    // Output args
                    for arg in &event.args {
                        let (key, int_value, string_value) = convert_arg(arg);
                        collector.add_instant_arg(InstantArgRecord {
                            instant_id,
                            key,
                            int_value,
                            string_value,
                            real_value: None,
                        })?;
                    }
                }
            }
        }

        // Process syscalls
        for (pidtgid, syscalls) in self.completed_syscalls.iter() {
            let tid = *pidtgid as i32;
            let utid = Some(self.utid_generator.get_or_create_utid(tid));

            // Create track for this thread's syscalls if we have any
            if !syscalls.is_empty() {
                let track_id = *track_id_counter;
                *track_id_counter += 1;

                collector.add_track(TrackRecord {
                    id: track_id,
                    name: SYSCALLS_TRACK_NAME.to_string(),
                    parent_id: None,
                })?;

                for (start_ts, end_ts, syscall_nr) in syscalls.iter().filter(|(s, e, _)| e >= s) {
                    let slice_id = *slice_id_counter;
                    *slice_id_counter += 1;

                    collector.add_slice(SliceRecord {
                        id: slice_id,
                        ts: *start_ts as i64,
                        dur: (end_ts - start_ts) as i64,
                        track_id,
                        utid,
                        name: syscall_name(*syscall_nr),
                        category: Some("syscall".to_string()),
                        depth: 0,
                    })?;

                    // Add syscall number as arg
                    collector.add_arg(ArgRecord {
                        slice_id,
                        key: "nr".to_string(),
                        int_value: Some(*syscall_nr as i64),
                        string_value: None,
                        real_value: None,
                    })?;
                }
            }
        }

        Ok(())
    }

    /// Write trace data to Perfetto format (used by parquet-to-perfetto conversion).
    pub fn write_trace(
        &mut self,
        writer: &mut dyn TraceWriter,
        pid_uuids: &HashMap<i32, u64>,
        thread_uuids: &HashMap<i32, u64>,
        id_counter: &Arc<AtomicUsize>,
    ) -> Result<()> {
        // Populate the instant events
        for (pidtgid, events) in self.events.iter() {
            for (track_name, track_events) in events.iter() {
                let desc_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;
                let desc = crate::perfetto::generate_pidtgid_track_descriptor(
                    pid_uuids,
                    thread_uuids,
                    pidtgid,
                    track_name.clone(),
                    desc_uuid,
                );
                let mut packet = TracePacket::default();
                packet.set_track_descriptor(desc);
                writer.write_packet(&packet)?;

                let seq = id_counter.fetch_add(1, Ordering::Relaxed) as u32;
                for event in track_events.iter() {
                    let mut tevent = TrackEvent::default();
                    tevent.set_type(Type::TYPE_INSTANT);
                    tevent.set_name(event.name.clone());
                    tevent.set_track_uuid(desc_uuid);
                    Self::add_arg_annotations(&mut tevent, &event.args);

                    let mut packet = TracePacket::default();
                    packet.set_timestamp(event.ts);
                    packet.set_track_event(tevent);
                    packet.set_trusted_packet_sequence_id(seq);
                    writer.write_packet(&packet)?;
                }
            }
        }

        // Populate the ranges
        for (tgidpid, tracks) in self.recorded_ranges.iter() {
            for (track_name, ranges) in tracks.iter() {
                let desc_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;
                let desc = crate::perfetto::generate_pidtgid_track_descriptor(
                    pid_uuids,
                    thread_uuids,
                    tgidpid,
                    track_name.clone(),
                    desc_uuid,
                );
                let mut packet = TracePacket::default();
                packet.set_track_descriptor(desc);
                writer.write_packet(&packet)?;

                let seq = id_counter.fetch_add(1, Ordering::Relaxed) as u32;
                for range in ranges.iter() {
                    let mut tevent = TrackEvent::default();
                    tevent.set_type(Type::TYPE_SLICE_BEGIN);
                    tevent.set_name(range.range_name.clone());
                    tevent.set_track_uuid(desc_uuid);
                    Self::add_arg_annotations(&mut tevent, &range.args);

                    let mut packet = TracePacket::default();
                    packet.set_timestamp(range.start);
                    packet.set_track_event(tevent);
                    packet.set_trusted_packet_sequence_id(seq);
                    writer.write_packet(&packet)?;

                    let mut tevent = TrackEvent::default();
                    tevent.set_type(Type::TYPE_SLICE_END);
                    tevent.set_name(range.range_name.clone());
                    tevent.set_track_uuid(desc_uuid);

                    let mut packet = TracePacket::default();
                    packet.set_timestamp(range.end);
                    packet.set_track_event(tevent);
                    packet.set_trusted_packet_sequence_id(seq);
                    writer.write_packet(&packet)?;
                }
            }
        }

        // Populate the per cpu range tracks
        let mut cpu_desc_uuids: HashMap<String, u64> = HashMap::new();
        for (cpu, tracks) in self.cpu_ranges.iter() {
            for (track_name, ranges) in tracks.iter() {
                let mut descs = crate::perfetto::generate_cpu_track_descriptors(
                    &mut cpu_desc_uuids,
                    *cpu,
                    track_name.clone(),
                    id_counter,
                );

                let desc = descs.pop().unwrap();
                let desc_uuid = desc.uuid();

                if let Some(new_desc) = descs.pop() {
                    let mut packet = TracePacket::default();
                    packet.set_track_descriptor(new_desc);
                    writer.write_packet(&packet)?;
                }

                let mut packet = TracePacket::default();
                packet.set_track_descriptor(desc);
                writer.write_packet(&packet)?;

                let seq = id_counter.fetch_add(1, Ordering::Relaxed) as u32;
                for range in ranges.iter() {
                    let mut tevent = TrackEvent::default();
                    tevent.set_type(Type::TYPE_SLICE_BEGIN);
                    tevent.set_name(range.range_name.clone());
                    tevent.set_track_uuid(desc_uuid);
                    Self::add_arg_annotations(&mut tevent, &range.args);

                    let mut packet = TracePacket::default();
                    packet.set_timestamp(range.start);
                    packet.set_track_event(tevent);
                    packet.set_trusted_packet_sequence_id(seq);
                    writer.write_packet(&packet)?;

                    let mut tevent = TrackEvent::default();
                    tevent.set_type(Type::TYPE_SLICE_END);
                    tevent.set_name(range.range_name.clone());
                    tevent.set_track_uuid(desc_uuid);

                    let mut packet = TracePacket::default();
                    packet.set_timestamp(range.end);
                    packet.set_track_event(tevent);
                    packet.set_trusted_packet_sequence_id(seq);
                    writer.write_packet(&packet)?;
                }
            }
        }

        // Populate the instant CPU events
        for (cpu, events) in self.cpu_events.iter() {
            for (track_name, track_events) in events.iter() {
                let mut descs = crate::perfetto::generate_cpu_track_descriptors(
                    &mut cpu_desc_uuids,
                    *cpu,
                    track_name.clone(),
                    id_counter,
                );

                let desc = descs.pop().unwrap();
                let desc_uuid = desc.uuid();

                if let Some(new_desc) = descs.pop() {
                    let mut packet = TracePacket::default();
                    packet.set_track_descriptor(new_desc);
                    writer.write_packet(&packet)?;
                }

                let mut packet = TracePacket::default();
                packet.set_track_descriptor(desc);
                writer.write_packet(&packet)?;

                let seq = id_counter.fetch_add(1, Ordering::Relaxed) as u32;
                for event in track_events.iter() {
                    let mut tevent = TrackEvent::default();
                    tevent.set_type(Type::TYPE_INSTANT);
                    tevent.set_name(event.name.clone());
                    tevent.set_track_uuid(desc_uuid);
                    Self::add_arg_annotations(&mut tevent, &event.args);

                    let mut packet = TracePacket::default();
                    packet.set_timestamp(event.ts);
                    packet.set_track_event(tevent);
                    packet.set_trusted_packet_sequence_id(seq);
                    writer.write_packet(&packet)?;
                }
            }
        }

        // Generate syscall trace packets
        let sequence_id = id_counter.fetch_add(1, Ordering::Relaxed) as u32;

        // Collect unique syscall numbers first
        let mut syscall_numbers: Vec<u64> = Vec::new();
        for (_pid, syscalls) in self.completed_syscalls.iter() {
            for (_start_ts, _end_ts, syscall_nr) in syscalls {
                syscall_numbers.push(*syscall_nr);
            }
        }

        // Intern all unique syscall numbers
        for syscall_nr in syscall_numbers {
            self.get_or_create_syscall_name_iid(syscall_nr, id_counter);
        }

        // Generate interned data packet with syscall names
        if !self.syscall_name_ids.is_empty() {
            let mut event_names = Vec::new();
            for (name, iid) in &self.syscall_name_ids {
                let mut event_name = EventName::default();
                event_name.set_iid(*iid);
                event_name.set_name(name.clone());
                event_names.push(event_name);
            }
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
            writer.write_packet(&interned_packet)?;
        }

        // Generate per-thread syscall tracks and events
        for (tgidpid, syscalls) in self.completed_syscalls.iter() {
            if syscalls.is_empty() {
                continue;
            }

            let track_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;
            let desc = crate::perfetto::generate_pidtgid_track_descriptor(
                pid_uuids,
                thread_uuids,
                tgidpid,
                "Syscalls".to_string(),
                track_uuid,
            );

            let mut packet = TracePacket::default();
            packet.set_track_descriptor(desc);
            writer.write_packet(&packet)?;

            for (start_ts, end_ts, syscall_nr) in syscalls {
                let name_iid = *self.syscall_iids.get(syscall_nr).unwrap();

                let mut begin_event = TrackEvent::default();
                begin_event.set_type(Type::TYPE_SLICE_BEGIN);
                begin_event.set_name_iid(name_iid);
                begin_event.set_track_uuid(track_uuid);

                let mut begin_packet = TracePacket::default();
                begin_packet.set_timestamp(*start_ts);
                begin_packet.set_track_event(begin_event);
                begin_packet.set_trusted_packet_sequence_id(sequence_id);
                writer.write_packet(&begin_packet)?;

                let mut end_event = TrackEvent::default();
                end_event.set_type(Type::TYPE_SLICE_END);
                end_event.set_track_uuid(track_uuid);

                let mut end_packet = TracePacket::default();
                end_packet.set_timestamp(*end_ts);
                end_packet.set_track_event(end_event);
                end_packet.set_trusted_packet_sequence_id(sequence_id);
                writer.write_packet(&end_packet)?;
            }
        }

        // Clear syscall state after generating packets
        self.completed_syscalls.clear();
        self.pending_syscalls.clear();
        self.syscall_iids.clear();
        self.syscall_name_ids.clear();

        Ok(())
    }

    /// Returns the minimum timestamp from all events, or None if no events recorded.
    pub fn min_timestamp(&self) -> Option<u64> {
        let instant_min = self
            .events
            .values()
            .flat_map(|track| track.values())
            .filter_map(|events| events.first())
            .map(|e| e.ts)
            .min();

        let cpu_instant_min = self
            .cpu_events
            .values()
            .flat_map(|track| track.values())
            .filter_map(|events| events.first())
            .map(|e| e.ts)
            .min();

        let range_min = self
            .recorded_ranges
            .values()
            .flat_map(|track| track.values())
            .filter_map(|ranges| ranges.first())
            .map(|r| r.start)
            .min();

        let cpu_range_min = self
            .cpu_ranges
            .values()
            .flat_map(|track| track.values())
            .filter_map(|ranges| ranges.first())
            .map(|r| r.start)
            .min();

        [instant_min, cpu_instant_min, range_min, cpu_range_min]
            .into_iter()
            .flatten()
            .min()
    }
}
