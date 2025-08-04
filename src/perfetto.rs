use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use perfetto_protos::trace_packet::TracePacket;
use perfetto_protos::track_descriptor::TrackDescriptor;
use perfetto_protos::track_event::track_event::Type;
use perfetto_protos::track_event::TrackEvent;

pub struct TrackCounter {
    pub ts: u64,
    pub count: i64,
}

pub fn generate_pidtgid_track_descriptor(
    pid_uuids: &HashMap<i32, u64>,
    thread_uuids: &HashMap<i32, u64>,
    tgidpid: &u64,
    name: String,
    desc_uuid: u64,
) -> TrackDescriptor {
    let pid = *tgidpid as i32;
    let tgid = (*tgidpid >> 32) as i32;

    let uuid = if pid == tgid {
        *pid_uuids.get(&tgid).unwrap()
    } else {
        *thread_uuids.get(&pid).unwrap()
    };

    let mut desc = TrackDescriptor::default();
    desc.set_name(name);
    desc.set_uuid(desc_uuid);
    desc.set_parent_uuid(uuid);

    desc
}

pub fn generate_cpu_track_descriptors(
    desc_uuids: &mut HashMap<String, u64>,
    cpu: u32,
    name: String,
    id_counter: &mut Arc<AtomicUsize>,
) -> Vec<TrackDescriptor> {
    let mut descs = Vec::new();
    let parent_uuid = if let Some(uuid) = desc_uuids.get(&name) {
        *uuid
    } else {
        let new_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;
        desc_uuids.insert(name.clone(), new_uuid);

        let mut desc = TrackDescriptor::default();
        desc.set_name(name);
        desc.set_uuid(new_uuid);

        // Set the parent UUID to 1 for the systing track
        desc.set_parent_uuid(1);
        descs.push(desc);

        new_uuid
    };

    let mut desc = TrackDescriptor::default();
    let desc_uuid = id_counter.fetch_add(1, Ordering::Relaxed) as u64;
    desc.set_name(format!("CPU {cpu}"));
    desc.set_uuid(desc_uuid);
    desc.set_parent_uuid(parent_uuid);
    descs.push(desc);

    descs
}

impl TrackCounter {
    pub fn to_track_event(&self, track_uuid: u64, seq: u32) -> TracePacket {
        let mut packet = TracePacket::default();
        let mut track_event = TrackEvent::default();
        track_event.set_type(Type::TYPE_COUNTER);
        track_event.set_counter_value(self.count);
        track_event.set_track_uuid(track_uuid);

        packet.set_track_event(track_event);
        packet.set_timestamp(self.ts);
        packet.set_trusted_packet_sequence_id(seq);
        packet
    }
}
