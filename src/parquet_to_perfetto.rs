//! Parquet to Perfetto converter module.
//!
//! This module reads parquet files from a directory and reconstructs a valid
//! Perfetto trace (.pb file). It is the inverse of the parquet_writer module.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::BufWriter;
use std::path::Path;

use anyhow::{Context, Result};
use arrow::array::{
    Array, Float64Array, Int32Array, Int64Array, ListArray, RecordBatch, StringArray,
};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use perfetto_protos::clock_snapshot::clock_snapshot::Clock;
use perfetto_protos::clock_snapshot::ClockSnapshot;
use perfetto_protos::debug_annotation::DebugAnnotation;
use perfetto_protos::ftrace_event_bundle::ftrace_event_bundle::CompactSched;
use perfetto_protos::ftrace_event_bundle::FtraceEventBundle;
use perfetto_protos::interned_data::InternedData;
use perfetto_protos::process_descriptor::ProcessDescriptor;
use perfetto_protos::profile_common::{Callstack, Frame, Mapping};
use perfetto_protos::profile_packet::PerfSample;
use perfetto_protos::thread_descriptor::ThreadDescriptor;
use perfetto_protos::trace_packet::trace_packet::SequenceFlags;
use perfetto_protos::trace_packet::TracePacket;
use perfetto_protos::track_descriptor::TrackDescriptor;
use perfetto_protos::track_event::track_event::Type;
use perfetto_protos::track_event::TrackEvent;

use crate::perfetto::{StreamingTraceWriter, TraceWriter};

/// Convert parquet files in input_dir to a Perfetto trace at output_file.
pub fn convert(input_dir: &Path, output_file: &Path) -> Result<()> {
    let file = File::create(output_file)
        .with_context(|| format!("Failed to create output file: {}", output_file.display()))?;
    let mut buf_writer = BufWriter::new(file);
    let mut writer = StreamingTraceWriter::new(&mut buf_writer);

    let mut converter = ParquetToPerfettoConverter::new();
    converter.convert(input_dir, &mut writer)?;

    writer.flush()?;
    eprintln!(
        "Wrote {} trace packets to {}",
        writer.packet_count(),
        output_file.display()
    );
    Ok(())
}

/// Converter state for reconstructing Perfetto traces from parquet files.
struct ParquetToPerfettoConverter {
    /// Counter for generating fresh UUIDs (starts at 1)
    next_uuid: u64,
    /// Map from parquet track_id to generated UUID
    track_id_to_uuid: HashMap<i64, u64>,
    /// Map from utid to thread track UUID
    utid_to_uuid: HashMap<i64, u64>,
    /// Map from upid to process track UUID
    upid_to_uuid: HashMap<i64, u64>,
    /// Sequence ID counter for trusted_packet_sequence_id
    next_seq_id: u32,
}

impl ParquetToPerfettoConverter {
    fn new() -> Self {
        Self {
            next_uuid: 1,
            track_id_to_uuid: HashMap::new(),
            utid_to_uuid: HashMap::new(),
            upid_to_uuid: HashMap::new(),
            next_seq_id: 1,
        }
    }

    /// Allocate a new UUID
    fn alloc_uuid(&mut self) -> u64 {
        let uuid = self.next_uuid;
        self.next_uuid += 1;
        uuid
    }

    /// Allocate a new sequence ID
    fn alloc_seq_id(&mut self) -> u32 {
        let seq = self.next_seq_id;
        self.next_seq_id += 1;
        seq
    }

    /// Convert parquet files to Perfetto trace
    fn convert(&mut self, input_dir: &Path, writer: &mut dyn TraceWriter) -> Result<()> {
        // 1. Write clock snapshots first (for timestamp correlation)
        self.write_clock_snapshots(input_dir, writer)?;

        // 2. Write process descriptors (creates process track UUIDs)
        self.write_process_descriptors(input_dir, writer)?;

        // 3. Write thread descriptors (creates thread track UUIDs)
        self.write_thread_descriptors(input_dir, writer)?;

        // 4. Write track descriptors
        self.write_track_descriptors(input_dir, writer)?;

        // 5. Write sched data (compact_sched format)
        self.write_sched_data(input_dir, writer)?;

        // 6. Write slice events (TYPE_SLICE_BEGIN/END)
        self.write_slice_events(input_dir, writer)?;

        // 7. Write instant events
        self.write_instant_events(input_dir, writer)?;

        // 8. Write counter events
        self.write_counter_events(input_dir, writer)?;

        // 9. Write perf samples
        self.write_perf_samples(input_dir, writer)?;

        Ok(())
    }

    /// Write clock snapshot packets
    fn write_clock_snapshots(
        &mut self,
        input_dir: &Path,
        writer: &mut dyn TraceWriter,
    ) -> Result<()> {
        let path = input_dir.join("clock_snapshot.parquet");
        if !path.exists() {
            return Ok(());
        }

        // Read clock snapshot records grouped by primary status
        let batches = read_parquet_file(&path)?;
        if batches.is_empty() {
            return Ok(());
        }

        // Group clocks by snapshot (all clocks in a single ClockSnapshot packet)
        let mut clocks: Vec<Clock> = Vec::new();

        for batch in &batches {
            let clock_ids = batch
                .column_by_name("clock_id")
                .and_then(|c| c.as_any().downcast_ref::<Int32Array>())
                .context("Missing clock_id column")?;
            let timestamps = batch
                .column_by_name("timestamp_ns")
                .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                .context("Missing timestamp_ns column")?;

            for i in 0..batch.num_rows() {
                let clock_id = clock_ids.value(i);
                let timestamp = timestamps.value(i);

                let mut clock = Clock::default();
                clock.set_clock_id(clock_id as u32);
                clock.timestamp = Some(timestamp as u64);
                clocks.push(clock);
            }
        }

        if !clocks.is_empty() {
            #[allow(clippy::field_reassign_with_default)]
            let snapshot = {
                let mut s = ClockSnapshot::default();
                s.clocks = clocks;
                s
            };
            // Note: primary_trace_clock is optional, clocks are still valid for timestamp correlation

            let mut packet = TracePacket::default();
            packet.set_clock_snapshot(snapshot);
            writer.write_packet(&packet)?;
        }

        Ok(())
    }

    /// Write process track descriptors
    fn write_process_descriptors(
        &mut self,
        input_dir: &Path,
        writer: &mut dyn TraceWriter,
    ) -> Result<()> {
        let path = input_dir.join("process.parquet");
        if !path.exists() {
            return Ok(());
        }

        let batches = read_parquet_file(&path)?;
        for batch in &batches {
            let upids = batch
                .column_by_name("upid")
                .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                .context("Missing upid column")?;
            let pids = batch
                .column_by_name("pid")
                .and_then(|c| c.as_any().downcast_ref::<Int32Array>())
                .context("Missing pid column")?;
            let names = batch
                .column_by_name("name")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>());

            for i in 0..batch.num_rows() {
                let upid = upids.value(i);
                let pid = pids.value(i);
                let name = get_optional_string(names, i);

                let uuid = self.alloc_uuid();
                self.upid_to_uuid.insert(upid, uuid);

                let mut desc = TrackDescriptor::default();
                desc.set_uuid(uuid);
                if let Some(n) = &name {
                    desc.set_name(n.clone());
                }

                let mut process = ProcessDescriptor::default();
                process.set_pid(pid);
                if let Some(n) = name {
                    process.set_process_name(n);
                }
                desc.process = Some(process).into();

                let mut packet = TracePacket::default();
                packet.set_track_descriptor(desc);
                writer.write_packet(&packet)?;
            }
        }

        Ok(())
    }

    /// Write thread track descriptors
    fn write_thread_descriptors(
        &mut self,
        input_dir: &Path,
        writer: &mut dyn TraceWriter,
    ) -> Result<()> {
        let path = input_dir.join("thread.parquet");
        if !path.exists() {
            return Ok(());
        }

        let batches = read_parquet_file(&path)?;
        for batch in &batches {
            let utids = batch
                .column_by_name("utid")
                .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                .context("Missing utid column")?;
            let tids = batch
                .column_by_name("tid")
                .and_then(|c| c.as_any().downcast_ref::<Int32Array>())
                .context("Missing tid column")?;
            let names = batch
                .column_by_name("name")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>());
            let upids = batch
                .column_by_name("upid")
                .and_then(|c| c.as_any().downcast_ref::<Int64Array>());

            for i in 0..batch.num_rows() {
                let utid = utids.value(i);
                let tid = tids.value(i);
                let name = get_optional_string(names, i);
                let upid = get_optional_i64(upids, i);

                let uuid = self.alloc_uuid();
                self.utid_to_uuid.insert(utid, uuid);

                let mut desc = TrackDescriptor::default();
                desc.set_uuid(uuid);
                if let Some(n) = &name {
                    desc.set_name(n.clone());
                }

                // Set parent UUID if we have a matching process
                if let Some(u) = upid {
                    if let Some(&parent_uuid) = self.upid_to_uuid.get(&u) {
                        desc.set_parent_uuid(parent_uuid);
                    }
                }

                // Use tid as pid approximation (they match for main threads)
                let pid = tid;

                let mut thread = ThreadDescriptor::default();
                thread.set_tid(tid);
                thread.set_pid(pid);
                if let Some(n) = name {
                    thread.set_thread_name(n);
                }
                desc.thread = Some(thread).into();

                let mut packet = TracePacket::default();
                packet.set_track_descriptor(desc);
                writer.write_packet(&packet)?;
            }
        }

        Ok(())
    }

    /// Write generic track descriptors
    fn write_track_descriptors(
        &mut self,
        input_dir: &Path,
        writer: &mut dyn TraceWriter,
    ) -> Result<()> {
        let path = input_dir.join("track.parquet");
        if !path.exists() {
            return Ok(());
        }

        // First pass: allocate UUIDs and build parent mapping
        let batches = read_parquet_file(&path)?;
        let mut track_parent_map: HashMap<i64, Option<i64>> = HashMap::new();
        let mut track_names: HashMap<i64, String> = HashMap::new();

        for batch in &batches {
            let ids = batch
                .column_by_name("id")
                .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                .context("Missing id column")?;
            let names = batch
                .column_by_name("name")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>())
                .context("Missing name column")?;
            let parent_ids = batch
                .column_by_name("parent_id")
                .and_then(|c| c.as_any().downcast_ref::<Int64Array>());

            for i in 0..batch.num_rows() {
                let id = ids.value(i);
                let name = names.value(i).to_string();
                let parent_id = get_optional_i64(parent_ids, i);

                // Allocate UUID for this track
                let uuid = self.alloc_uuid();
                self.track_id_to_uuid.insert(id, uuid);
                track_parent_map.insert(id, parent_id);
                track_names.insert(id, name);
            }
        }

        // Second pass: write track descriptors with proper parent UUIDs
        for (&id, &parent_id) in &track_parent_map {
            let uuid = *self.track_id_to_uuid.get(&id).unwrap();
            let name = track_names.get(&id).unwrap();

            let mut desc = TrackDescriptor::default();
            desc.set_uuid(uuid);
            desc.set_name(name.clone());

            if let Some(pid) = parent_id {
                if let Some(&parent_uuid) = self.track_id_to_uuid.get(&pid) {
                    desc.set_parent_uuid(parent_uuid);
                }
            }

            let mut packet = TracePacket::default();
            packet.set_track_descriptor(desc);
            writer.write_packet(&packet)?;
        }

        Ok(())
    }

    /// Write scheduling data as FtraceEventBundle with compact_sched
    fn write_sched_data(&mut self, input_dir: &Path, writer: &mut dyn TraceWriter) -> Result<()> {
        let sched_path = input_dir.join("sched_slice.parquet");
        let thread_state_path = input_dir.join("thread_state.parquet");

        // Read sched slices and thread states
        let sched_batches = if sched_path.exists() {
            read_parquet_file(&sched_path)?
        } else {
            Vec::new()
        };

        let thread_state_batches = if thread_state_path.exists() {
            read_parquet_file(&thread_state_path)?
        } else {
            Vec::new()
        };

        // Group events by CPU for compact_sched format
        // Map: cpu -> (switch_events, waking_events)
        let mut cpu_events: HashMap<i32, (Vec<SchedSwitchEvent>, Vec<SchedWakingEvent>)> =
            HashMap::new();

        // Need thread table to map utid -> (tid, name)
        let thread_path = input_dir.join("thread.parquet");
        let utid_to_thread = if thread_path.exists() {
            self.build_utid_to_thread_map(&thread_path)?
        } else {
            HashMap::new()
        };

        // Process sched slices (switch events)
        for batch in &sched_batches {
            let timestamps = batch
                .column_by_name("ts")
                .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                .context("Missing ts column")?;
            let cpus = batch
                .column_by_name("cpu")
                .and_then(|c| c.as_any().downcast_ref::<Int32Array>())
                .context("Missing cpu column")?;
            let utids = batch
                .column_by_name("utid")
                .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                .context("Missing utid column")?;
            let priorities = batch
                .column_by_name("priority")
                .and_then(|c| c.as_any().downcast_ref::<Int32Array>())
                .context("Missing priority column")?;

            for i in 0..batch.num_rows() {
                let ts = timestamps.value(i);
                let cpu = cpus.value(i);
                let utid = utids.value(i);
                let priority = priorities.value(i);

                let (tid, comm) = utid_to_thread
                    .get(&utid)
                    .cloned()
                    .unwrap_or((0, String::new()));

                let entry = cpu_events
                    .entry(cpu)
                    .or_insert_with(|| (Vec::new(), Vec::new()));
                entry.0.push(SchedSwitchEvent {
                    ts,
                    next_pid: tid,
                    next_prio: priority,
                    next_comm: comm,
                    prev_state: 0, // Not stored in parquet, default to TASK_RUNNING
                });
            }
        }

        // Process thread states (waking events)
        for batch in &thread_state_batches {
            let timestamps = batch
                .column_by_name("ts")
                .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                .context("Missing ts column")?;
            let utids = batch
                .column_by_name("utid")
                .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                .context("Missing utid column")?;
            let cpus = batch
                .column_by_name("cpu")
                .and_then(|c| c.as_any().downcast_ref::<Int32Array>());

            for i in 0..batch.num_rows() {
                let ts = timestamps.value(i);
                let utid = utids.value(i);
                let target_cpu = get_optional_i32(cpus, i).unwrap_or(0);

                let (tid, comm) = utid_to_thread
                    .get(&utid)
                    .cloned()
                    .unwrap_or((0, String::new()));

                // Waking events go to CPU 0 by convention (they have target_cpu field)
                let entry = cpu_events
                    .entry(0)
                    .or_insert_with(|| (Vec::new(), Vec::new()));
                entry.1.push(SchedWakingEvent {
                    ts,
                    pid: tid,
                    target_cpu,
                    prio: 120, // Default priority
                    comm,
                });
            }
        }

        // Write FtraceEventBundle packets for each CPU
        for (cpu, (mut switches, mut wakings)) in cpu_events {
            // Sort by timestamp
            switches.sort_by_key(|e| e.ts);
            wakings.sort_by_key(|e| e.ts);

            let mut compact_sched = CompactSched::default();
            let mut intern_table: Vec<String> = Vec::new();
            let mut comm_to_index: HashMap<String, u32> = HashMap::new();

            // Helper to intern comm strings
            let mut intern_comm = |comm: &str| -> u32 {
                if let Some(&idx) = comm_to_index.get(comm) {
                    idx
                } else {
                    let idx = intern_table.len() as u32;
                    intern_table.push(comm.to_string());
                    comm_to_index.insert(comm.to_string(), idx);
                    idx
                }
            };

            // Build compact_sched switch data (delta-encoded timestamps)
            let mut last_switch_ts: i64 = 0;
            for event in &switches {
                let delta = (event.ts - last_switch_ts) as u64;
                last_switch_ts = event.ts;

                compact_sched.switch_timestamp.push(delta);
                compact_sched.switch_next_pid.push(event.next_pid);
                compact_sched.switch_next_prio.push(event.next_prio);
                compact_sched.switch_prev_state.push(event.prev_state);
                let comm_idx = intern_comm(&event.next_comm);
                compact_sched.switch_next_comm_index.push(comm_idx);
            }

            // Build compact_sched waking data (delta-encoded timestamps)
            let mut last_waking_ts: i64 = 0;
            for event in &wakings {
                let delta = (event.ts - last_waking_ts) as u64;
                last_waking_ts = event.ts;

                compact_sched.waking_timestamp.push(delta);
                compact_sched.waking_pid.push(event.pid);
                compact_sched.waking_target_cpu.push(event.target_cpu);
                compact_sched.waking_prio.push(event.prio);
                let comm_idx = intern_comm(&event.comm);
                compact_sched.waking_comm_index.push(comm_idx);
                compact_sched.waking_common_flags.push(1);
            }

            compact_sched.intern_table = intern_table;

            // Only write if there's data
            if !compact_sched.switch_timestamp.is_empty()
                || !compact_sched.waking_timestamp.is_empty()
            {
                let mut bundle = FtraceEventBundle::default();
                bundle.set_cpu(cpu as u32);
                bundle.compact_sched = Some(compact_sched).into();

                let mut packet = TracePacket::default();
                packet.set_ftrace_events(bundle);
                writer.write_packet(&packet)?;
            }
        }

        Ok(())
    }

    /// Build utid -> (tid, name) mapping from thread table
    fn build_utid_to_thread_map(&self, path: &Path) -> Result<HashMap<i64, (i32, String)>> {
        let mut map = HashMap::new();
        let batches = read_parquet_file(path)?;

        for batch in &batches {
            let utids = batch
                .column_by_name("utid")
                .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                .context("Missing utid column")?;
            let tids = batch
                .column_by_name("tid")
                .and_then(|c| c.as_any().downcast_ref::<Int32Array>())
                .context("Missing tid column")?;
            let names = batch
                .column_by_name("name")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>());

            for i in 0..batch.num_rows() {
                let utid = utids.value(i);
                let tid = tids.value(i);
                let name = get_optional_string(names, i).unwrap_or_default();
                map.insert(utid, (tid, name));
            }
        }

        Ok(map)
    }

    /// Write slice events (TrackEvent TYPE_SLICE_BEGIN and TYPE_SLICE_END)
    fn write_slice_events(&mut self, input_dir: &Path, writer: &mut dyn TraceWriter) -> Result<()> {
        let slice_path = input_dir.join("slice.parquet");
        let args_path = input_dir.join("args.parquet");

        if !slice_path.exists() {
            return Ok(());
        }

        // Load args indexed by slice_id
        let args_by_slice = if args_path.exists() {
            self.load_args(&args_path)?
        } else {
            HashMap::new()
        };

        let batches = read_parquet_file(&slice_path)?;
        let seq_id = self.alloc_seq_id();

        for batch in &batches {
            let ids = batch
                .column_by_name("id")
                .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                .context("Missing id column")?;
            let timestamps = batch
                .column_by_name("ts")
                .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                .context("Missing ts column")?;
            let durations = batch
                .column_by_name("dur")
                .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                .context("Missing dur column")?;
            let track_ids = batch
                .column_by_name("track_id")
                .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                .context("Missing track_id column")?;
            let names = batch
                .column_by_name("name")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>())
                .context("Missing name column")?;
            let categories = batch
                .column_by_name("category")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>());

            for i in 0..batch.num_rows() {
                let slice_id = ids.value(i);
                let ts = timestamps.value(i);
                let dur = durations.value(i);
                let track_id = track_ids.value(i);
                let name = names.value(i).to_string();
                let category = get_optional_string(categories, i);

                // Get track UUID
                let track_uuid = self.track_id_to_uuid.get(&track_id).copied().unwrap_or(0);

                // Write TYPE_SLICE_BEGIN
                let mut begin_event = TrackEvent::default();
                begin_event.set_type(Type::TYPE_SLICE_BEGIN);
                begin_event.set_track_uuid(track_uuid);
                begin_event.set_name(name.clone());
                if let Some(cat) = &category {
                    begin_event.categories.push(cat.clone());
                }

                // Add debug annotations from args
                if let Some(args) = args_by_slice.get(&slice_id) {
                    for arg in args {
                        let mut ann = DebugAnnotation::default();
                        ann.set_name(arg.key.clone());
                        if let Some(v) = arg.int_value {
                            ann.set_int_value(v);
                        } else if let Some(ref v) = arg.string_value {
                            ann.set_string_value(v.clone());
                        } else if let Some(v) = arg.real_value {
                            ann.set_double_value(v);
                        }
                        begin_event.debug_annotations.push(ann);
                    }
                }

                let mut begin_packet = TracePacket::default();
                begin_packet.set_timestamp(ts as u64);
                begin_packet.set_track_event(begin_event);
                begin_packet.set_trusted_packet_sequence_id(seq_id);
                writer.write_packet(&begin_packet)?;

                // Write TYPE_SLICE_END
                let mut end_event = TrackEvent::default();
                end_event.set_type(Type::TYPE_SLICE_END);
                end_event.set_track_uuid(track_uuid);

                let mut end_packet = TracePacket::default();
                end_packet.set_timestamp((ts + dur) as u64);
                end_packet.set_track_event(end_event);
                end_packet.set_trusted_packet_sequence_id(seq_id);
                writer.write_packet(&end_packet)?;
            }
        }

        Ok(())
    }

    /// Load args from parquet file indexed by slice_id
    fn load_args(&self, path: &Path) -> Result<HashMap<i64, Vec<ArgRecord>>> {
        let mut args_map: HashMap<i64, Vec<ArgRecord>> = HashMap::new();
        let batches = read_parquet_file(path)?;

        for batch in &batches {
            let slice_ids = batch
                .column_by_name("slice_id")
                .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                .context("Missing slice_id column")?;
            let keys = batch
                .column_by_name("key")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>())
                .context("Missing key column")?;
            let int_values = batch
                .column_by_name("int_value")
                .and_then(|c| c.as_any().downcast_ref::<Int64Array>());
            let string_values = batch
                .column_by_name("string_value")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>());
            let real_values = batch
                .column_by_name("real_value")
                .and_then(|c| c.as_any().downcast_ref::<Float64Array>());

            for i in 0..batch.num_rows() {
                let slice_id = slice_ids.value(i);
                let key = keys.value(i).to_string();
                let int_value = get_optional_i64(int_values, i);
                let string_value = get_optional_string(string_values, i);
                let real_value = get_optional_f64(real_values, i);

                args_map.entry(slice_id).or_default().push(ArgRecord {
                    key,
                    int_value,
                    string_value,
                    real_value,
                });
            }
        }

        Ok(args_map)
    }

    /// Write instant events (TrackEvent TYPE_INSTANT)
    fn write_instant_events(
        &mut self,
        input_dir: &Path,
        writer: &mut dyn TraceWriter,
    ) -> Result<()> {
        let instant_path = input_dir.join("instant.parquet");
        let instant_args_path = input_dir.join("instant_args.parquet");

        if !instant_path.exists() {
            return Ok(());
        }

        // Load instant args indexed by instant_id
        let args_by_instant = if instant_args_path.exists() {
            self.load_instant_args(&instant_args_path)?
        } else {
            HashMap::new()
        };

        let batches = read_parquet_file(&instant_path)?;
        let seq_id = self.alloc_seq_id();

        for batch in &batches {
            let ids = batch
                .column_by_name("id")
                .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                .context("Missing id column")?;
            let timestamps = batch
                .column_by_name("ts")
                .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                .context("Missing ts column")?;
            let track_ids = batch
                .column_by_name("track_id")
                .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                .context("Missing track_id column")?;
            let names = batch
                .column_by_name("name")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>())
                .context("Missing name column")?;
            let categories = batch
                .column_by_name("category")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>());

            for i in 0..batch.num_rows() {
                let instant_id = ids.value(i);
                let ts = timestamps.value(i);
                let track_id = track_ids.value(i);
                let name = names.value(i).to_string();
                let category = get_optional_string(categories, i);

                let track_uuid = self.track_id_to_uuid.get(&track_id).copied().unwrap_or(0);

                let mut event = TrackEvent::default();
                event.set_type(Type::TYPE_INSTANT);
                event.set_track_uuid(track_uuid);
                event.set_name(name);
                if let Some(cat) = category {
                    event.categories.push(cat);
                }

                // Add debug annotations from instant args
                if let Some(args) = args_by_instant.get(&instant_id) {
                    for arg in args {
                        let mut ann = DebugAnnotation::default();
                        ann.set_name(arg.key.clone());
                        if let Some(v) = arg.int_value {
                            ann.set_int_value(v);
                        } else if let Some(ref v) = arg.string_value {
                            ann.set_string_value(v.clone());
                        } else if let Some(v) = arg.real_value {
                            ann.set_double_value(v);
                        }
                        event.debug_annotations.push(ann);
                    }
                }

                let mut packet = TracePacket::default();
                packet.set_timestamp(ts as u64);
                packet.set_track_event(event);
                packet.set_trusted_packet_sequence_id(seq_id);
                writer.write_packet(&packet)?;
            }
        }

        Ok(())
    }

    /// Load instant args from parquet file indexed by instant_id
    fn load_instant_args(&self, path: &Path) -> Result<HashMap<i64, Vec<ArgRecord>>> {
        let mut args_map: HashMap<i64, Vec<ArgRecord>> = HashMap::new();
        let batches = read_parquet_file(path)?;

        for batch in &batches {
            let instant_ids = batch
                .column_by_name("instant_id")
                .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                .context("Missing instant_id column")?;
            let keys = batch
                .column_by_name("key")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>())
                .context("Missing key column")?;
            let int_values = batch
                .column_by_name("int_value")
                .and_then(|c| c.as_any().downcast_ref::<Int64Array>());
            let string_values = batch
                .column_by_name("string_value")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>());
            let real_values = batch
                .column_by_name("real_value")
                .and_then(|c| c.as_any().downcast_ref::<Float64Array>());

            for i in 0..batch.num_rows() {
                let instant_id = instant_ids.value(i);
                let key = keys.value(i).to_string();
                let int_value = get_optional_i64(int_values, i);
                let string_value = get_optional_string(string_values, i);
                let real_value = get_optional_f64(real_values, i);

                args_map.entry(instant_id).or_default().push(ArgRecord {
                    key,
                    int_value,
                    string_value,
                    real_value,
                });
            }
        }

        Ok(args_map)
    }

    /// Write counter events (TrackEvent TYPE_COUNTER)
    fn write_counter_events(
        &mut self,
        input_dir: &Path,
        writer: &mut dyn TraceWriter,
    ) -> Result<()> {
        let counter_path = input_dir.join("counter.parquet");
        let counter_track_path = input_dir.join("counter_track.parquet");

        if !counter_path.exists() {
            return Ok(());
        }

        // First write counter track descriptors if available
        if counter_track_path.exists() {
            let track_batches = read_parquet_file(&counter_track_path)?;
            for batch in &track_batches {
                let ids = batch
                    .column_by_name("id")
                    .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                    .context("Missing id column")?;
                let names = batch
                    .column_by_name("name")
                    .and_then(|c| c.as_any().downcast_ref::<StringArray>())
                    .context("Missing name column")?;

                for i in 0..batch.num_rows() {
                    let id = ids.value(i);
                    let name = names.value(i).to_string();

                    // Allocate UUID if not already done
                    let uuid = if let Some(&existing) = self.track_id_to_uuid.get(&id) {
                        existing
                    } else {
                        let new_uuid = self.alloc_uuid();
                        self.track_id_to_uuid.insert(id, new_uuid);
                        new_uuid
                    };

                    let mut desc = TrackDescriptor::default();
                    desc.set_uuid(uuid);
                    desc.set_name(name);

                    // Mark as counter track
                    let counter = perfetto_protos::counter_descriptor::CounterDescriptor::default();
                    desc.counter = Some(counter).into();

                    let mut packet = TracePacket::default();
                    packet.set_track_descriptor(desc);
                    writer.write_packet(&packet)?;
                }
            }
        }

        // Write counter values
        let batches = read_parquet_file(&counter_path)?;
        let seq_id = self.alloc_seq_id();

        for batch in &batches {
            let timestamps = batch
                .column_by_name("ts")
                .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                .context("Missing ts column")?;
            let track_ids = batch
                .column_by_name("track_id")
                .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                .context("Missing track_id column")?;
            let values = batch
                .column_by_name("value")
                .and_then(|c| c.as_any().downcast_ref::<Float64Array>())
                .context("Missing value column")?;

            for i in 0..batch.num_rows() {
                let ts = timestamps.value(i);
                let track_id = track_ids.value(i);
                let value = values.value(i);

                let track_uuid = self.track_id_to_uuid.get(&track_id).copied().unwrap_or(0);

                let mut event = TrackEvent::default();
                event.set_type(Type::TYPE_COUNTER);
                event.set_track_uuid(track_uuid);
                event.set_counter_value(value as i64);

                let mut packet = TracePacket::default();
                packet.set_timestamp(ts as u64);
                packet.set_track_event(event);
                packet.set_trusted_packet_sequence_id(seq_id);
                writer.write_packet(&packet)?;
            }
        }

        Ok(())
    }

    /// Write perf sample packets
    ///
    /// Supports both new schema (stack_sample.parquet) and legacy schema (perf_sample.parquet).
    ///
    /// When reading from the new schema, stack information is reconstructed into Perfetto
    /// InternedData format with Frame and Callstack protos. Samples reference callstacks
    /// via callstack_iid.
    fn write_perf_samples(&mut self, input_dir: &Path, writer: &mut dyn TraceWriter) -> Result<()> {
        // Try new schema first (stack_sample.parquet), fall back to legacy (perf_sample.parquet)
        let stack_sample_path = input_dir.join("stack_sample.parquet");
        let perf_path = input_dir.join("perf_sample.parquet");

        let sample_path = if stack_sample_path.exists() {
            &stack_sample_path
        } else if perf_path.exists() {
            &perf_path
        } else {
            return Ok(());
        };

        let uses_new_schema = stack_sample_path.exists();

        // Need thread table to map utid -> (tid, pid)
        let thread_path = input_dir.join("thread.parquet");
        let utid_to_thread = if thread_path.exists() {
            self.build_utid_to_thread_map(&thread_path)?
        } else {
            HashMap::new()
        };

        let batches = read_parquet_file(sample_path)?;

        // For new schema, build InternedData with Frame and Callstack protos
        let (stack_to_callstack_iid, sequence_id) = if uses_new_schema {
            let stack_data = read_stack_data(input_dir)?;
            let frame_data = read_frame_data(input_dir)?;
            let mapping_data = read_mapping_data(input_dir)?;

            if !stack_data.is_empty() {
                self.write_interned_stack_data(writer, &stack_data, &frame_data, &mapping_data)?
            } else {
                (HashMap::new(), 0)
            }
        } else {
            (HashMap::new(), 0)
        };

        // Get stack_id column for new schema
        let stack_ids_by_batch: Vec<Option<&Int64Array>> = if uses_new_schema {
            batches
                .iter()
                .map(|batch| {
                    batch
                        .column_by_name("stack_id")
                        .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                })
                .collect()
        } else {
            vec![None; batches.len()]
        };

        for (batch_idx, batch) in batches.iter().enumerate() {
            let timestamps = batch
                .column_by_name("ts")
                .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                .context("Missing ts column")?;
            let utids = batch
                .column_by_name("utid")
                .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                .context("Missing utid column")?;
            let cpus = batch
                .column_by_name("cpu")
                .and_then(|c| c.as_any().downcast_ref::<Int32Array>());
            let stack_ids = stack_ids_by_batch[batch_idx];

            for i in 0..batch.num_rows() {
                let ts = timestamps.value(i);
                let utid = utids.value(i);
                let cpu = get_optional_i32(cpus, i).map(|c| c as u32);

                let (tid, _) = utid_to_thread
                    .get(&utid)
                    .cloned()
                    .unwrap_or((0, String::new()));

                let mut sample = PerfSample::default();
                sample.set_tid(tid as u32);
                sample.set_pid(tid as u32); // Use tid as pid approximation
                if let Some(c) = cpu {
                    sample.set_cpu(c);
                }

                // Set callstack_iid for new schema samples
                if let Some(stack_id_arr) = stack_ids {
                    if !stack_id_arr.is_null(i) {
                        let stack_id = stack_id_arr.value(i);
                        if let Some(&callstack_iid) = stack_to_callstack_iid.get(&stack_id) {
                            sample.set_callstack_iid(callstack_iid);
                        }
                    }
                }

                let mut packet = TracePacket::default();
                packet.set_timestamp(ts as u64);
                // Set sequence ID for samples that have callstack references
                let has_callstack = sample.has_callstack_iid();
                packet.set_perf_sample(sample);
                if sequence_id > 0 && has_callstack {
                    packet.set_trusted_packet_sequence_id(sequence_id);
                }
                writer.write_packet(&packet)?;
            }
        }

        Ok(())
    }

    /// Write InternedData packet with Frame, Callstack, and Mapping protos.
    ///
    /// Returns a map from stack_id to callstack_iid, and the sequence ID used.
    ///
    /// Note: `mapping_data` is currently unused. Perfetto's Mapping proto requires
    /// interned IDs for build_id and path, which would require additional interning
    /// infrastructure. The mapping IDs are still emitted to satisfy frame references.
    fn write_interned_stack_data(
        &mut self,
        writer: &mut dyn TraceWriter,
        stack_data: &HashMap<i64, StackData>,
        frame_data: &HashMap<i64, FrameData>,
        _mapping_data: &HashMap<i64, MappingData>,
    ) -> Result<(HashMap<i64, u64>, u32)> {
        let sequence_id = self.alloc_seq_id();

        // Build Frame protos for each unique frame_id
        // Map: frame_id -> frame iid (we use frame_id as iid for simplicity)
        let mut frames: Vec<Frame> = Vec::new();
        let mut seen_frame_ids: HashMap<i64, u64> = HashMap::new();
        let mut used_mapping_ids: HashSet<i64> = HashSet::new();

        // Build function names alongside frames (avoids second pass over stack_data)
        let mut function_names: Vec<perfetto_protos::profile_common::InternedString> = Vec::new();
        let mut added_function_name_iids: HashSet<u64> = HashSet::new();

        // Build Callstack protos for each stack
        // Map: stack_id -> callstack_iid
        let mut callstacks: Vec<Callstack> = Vec::new();
        let mut stack_to_callstack_iid: HashMap<i64, u64> = HashMap::new();
        let mut next_callstack_iid: u64 = 1;

        for (&stack_id, stack) in stack_data {
            if stack.frame_ids.is_empty() {
                continue;
            }

            // Collect frame iids for this callstack
            let mut callstack_frame_ids: Vec<u64> = Vec::new();

            for (idx, &frame_id) in stack.frame_ids.iter().enumerate() {
                // Get or create frame entry
                let frame_iid = match seen_frame_ids.get(&frame_id) {
                    Some(&iid) => iid,
                    None => {
                        let iid = frame_id as u64;
                        seen_frame_ids.insert(frame_id, iid);

                        // Build Frame proto
                        let mut frame = Frame::default();
                        frame.set_iid(iid);

                        // Determine function name: prefer frame_data, fall back to stack's frame_names
                        let function_name = if let Some(fd) = frame_data.get(&frame_id) {
                            if fd.name.is_some() {
                                frame.set_function_name_id(iid);
                            }
                            if let Some(mapping_id) = fd.mapping_id {
                                frame.set_mapping_id(mapping_id as u64);
                                used_mapping_ids.insert(mapping_id);
                            }
                            frame.set_rel_pc(fd.rel_pc as u64);
                            fd.name.clone()
                        } else if idx < stack.frame_names.len() {
                            frame.set_function_name_id(iid);
                            Some(stack.frame_names[idx].clone())
                        } else {
                            None
                        };

                        // Add function name to interned strings (O(1) HashSet check)
                        if let Some(name) = function_name {
                            if added_function_name_iids.insert(iid) {
                                let mut interned_str =
                                    perfetto_protos::profile_common::InternedString::default();
                                interned_str.set_iid(iid);
                                interned_str.set_str(name.into_bytes());
                                function_names.push(interned_str);
                            }
                        }

                        frames.push(frame);
                        iid
                    }
                };

                callstack_frame_ids.push(frame_iid);
            }

            // Build Callstack proto
            let callstack_iid = next_callstack_iid;
            next_callstack_iid += 1;

            let mut callstack = Callstack::default();
            callstack.set_iid(callstack_iid);
            callstack.frame_ids = callstack_frame_ids;

            callstacks.push(callstack);
            stack_to_callstack_iid.insert(stack_id, callstack_iid);
        }

        // Build Mapping protos for all used mappings
        let mappings: Vec<Mapping> = used_mapping_ids
            .iter()
            .map(|&mapping_id| {
                let mut mapping = Mapping::default();
                mapping.set_iid(mapping_id as u64);
                mapping
            })
            .collect();

        // Write InternedData packet
        if !frames.is_empty() || !callstacks.is_empty() {
            let interned_data = InternedData {
                frames,
                callstacks,
                function_names,
                mappings,
                ..Default::default()
            };

            #[allow(clippy::field_reassign_with_default)]
            let packet = {
                let mut p = TracePacket::default();
                p.interned_data = Some(interned_data).into();
                p.set_trusted_packet_sequence_id(sequence_id);
                p.sequence_flags = Some(
                    SequenceFlags::SEQ_INCREMENTAL_STATE_CLEARED as u32
                        | SequenceFlags::SEQ_NEEDS_INCREMENTAL_STATE as u32,
                );
                p
            };
            writer.write_packet(&packet)?;
        }

        Ok((stack_to_callstack_iid, sequence_id))
    }
}

/// Helper struct for sched switch events
struct SchedSwitchEvent {
    ts: i64,
    next_pid: i32,
    next_prio: i32,
    next_comm: String,
    prev_state: i64,
}

/// Helper struct for sched waking events
struct SchedWakingEvent {
    ts: i64,
    pid: i32,
    target_cpu: i32,
    prio: i32,
    comm: String,
}

/// Helper struct for argument records
struct ArgRecord {
    key: String,
    int_value: Option<i64>,
    string_value: Option<String>,
    real_value: Option<f64>,
}

/// Read a parquet file and return all record batches
fn read_parquet_file(path: &Path) -> Result<Vec<RecordBatch>> {
    let file = File::open(path)
        .with_context(|| format!("Failed to open parquet file: {}", path.display()))?;

    let builder = ParquetRecordBatchReaderBuilder::try_new(file)
        .with_context(|| format!("Failed to create parquet reader for: {}", path.display()))?;

    let reader = builder
        .build()
        .with_context(|| format!("Failed to build parquet reader for: {}", path.display()))?;

    let batches: Result<Vec<_>, _> = reader.collect();
    batches.with_context(|| format!("Failed to read batches from: {}", path.display()))
}

/// Get optional string value from a nullable StringArray column
fn get_optional_string(arr: Option<&StringArray>, i: usize) -> Option<String> {
    arr.and_then(|a| {
        if a.is_null(i) {
            None
        } else {
            Some(a.value(i).to_string())
        }
    })
}

/// Get optional i64 value from a nullable Int64Array column
fn get_optional_i64(arr: Option<&Int64Array>, i: usize) -> Option<i64> {
    arr.and_then(|a| if a.is_null(i) { None } else { Some(a.value(i)) })
}

/// Get optional i32 value from a nullable Int32Array column
fn get_optional_i32(arr: Option<&Int32Array>, i: usize) -> Option<i32> {
    arr.and_then(|a| if a.is_null(i) { None } else { Some(a.value(i)) })
}

/// Get optional f64 value from a nullable Float64Array column
fn get_optional_f64(arr: Option<&Float64Array>, i: usize) -> Option<f64> {
    arr.and_then(|a| if a.is_null(i) { None } else { Some(a.value(i)) })
}

/// Helper struct for stack records from stack.parquet
struct StackData {
    /// Frame IDs in leaf-to-root order
    frame_ids: Vec<i64>,
    /// Frame names in leaf-to-root order (for fallback if frame.parquet is missing)
    frame_names: Vec<String>,
}

/// Helper struct for frame records from frame.parquet
struct FrameData {
    name: Option<String>,
    mapping_id: Option<i64>,
    rel_pc: i64,
}

/// Helper struct for mapping records from mapping.parquet
///
/// Note: Fields are currently unused but kept for future enhancement when
/// we add proper interning support for build_id and path in Perfetto output.
#[allow(dead_code)]
struct MappingData {
    build_id: Option<String>,
    name: Option<String>,
}

/// Read stack.parquet and return a map of stack_id -> StackData
fn read_stack_data(input_dir: &Path) -> Result<HashMap<i64, StackData>> {
    let path = input_dir.join("stack.parquet");
    if !path.exists() {
        return Ok(HashMap::new());
    }

    let mut stack_map = HashMap::new();
    let batches = read_parquet_file(&path)?;

    for batch in &batches {
        let ids = batch
            .column_by_name("id")
            .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
            .context("Missing id column in stack.parquet")?;

        let frame_ids_col = batch
            .column_by_name("frame_ids")
            .and_then(|c| c.as_any().downcast_ref::<ListArray>())
            .context("Missing frame_ids column in stack.parquet")?;

        let frame_names_col = batch
            .column_by_name("frame_names")
            .and_then(|c| c.as_any().downcast_ref::<ListArray>())
            .context("Missing frame_names column in stack.parquet")?;

        for i in 0..batch.num_rows() {
            let id = ids.value(i);

            // Extract frame_ids list
            let frame_ids: Vec<i64> = if frame_ids_col.is_null(i) {
                Vec::new()
            } else {
                let inner = frame_ids_col.value(i);
                let int_array = inner
                    .as_any()
                    .downcast_ref::<Int64Array>()
                    .context("frame_ids inner array is not Int64Array")?;
                (0..int_array.len())
                    .filter_map(|j| {
                        if int_array.is_null(j) {
                            None
                        } else {
                            Some(int_array.value(j))
                        }
                    })
                    .collect()
            };

            // Extract frame_names list
            let frame_names: Vec<String> = if frame_names_col.is_null(i) {
                Vec::new()
            } else {
                let inner = frame_names_col.value(i);
                let str_array = inner
                    .as_any()
                    .downcast_ref::<StringArray>()
                    .context("frame_names inner array is not StringArray")?;
                (0..str_array.len())
                    .map(|j| {
                        if str_array.is_null(j) {
                            String::new()
                        } else {
                            str_array.value(j).to_string()
                        }
                    })
                    .collect()
            };

            stack_map.insert(
                id,
                StackData {
                    frame_ids,
                    frame_names,
                },
            );
        }
    }

    Ok(stack_map)
}

/// Read frame.parquet and return a map of frame_id -> FrameData
fn read_frame_data(input_dir: &Path) -> Result<HashMap<i64, FrameData>> {
    let path = input_dir.join("frame.parquet");
    if !path.exists() {
        return Ok(HashMap::new());
    }

    let mut frame_map = HashMap::new();
    let batches = read_parquet_file(&path)?;

    for batch in &batches {
        let ids = batch
            .column_by_name("id")
            .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
            .context("Missing id column in frame.parquet")?;

        let names = batch
            .column_by_name("name")
            .and_then(|c| c.as_any().downcast_ref::<StringArray>());

        let mapping_ids = batch
            .column_by_name("mapping_id")
            .and_then(|c| c.as_any().downcast_ref::<Int64Array>());

        let rel_pcs = batch
            .column_by_name("rel_pc")
            .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
            .context("Missing rel_pc column in frame.parquet")?;

        for i in 0..batch.num_rows() {
            let id = ids.value(i);
            let name = get_optional_string(names, i);
            let mapping_id = get_optional_i64(mapping_ids, i);
            let rel_pc = rel_pcs.value(i);

            frame_map.insert(
                id,
                FrameData {
                    name,
                    mapping_id,
                    rel_pc,
                },
            );
        }
    }

    Ok(frame_map)
}

/// Read mapping.parquet and return a map of mapping_id -> MappingData
fn read_mapping_data(input_dir: &Path) -> Result<HashMap<i64, MappingData>> {
    let path = input_dir.join("mapping.parquet");
    if !path.exists() {
        return Ok(HashMap::new());
    }

    let mut mapping_map = HashMap::new();
    let batches = read_parquet_file(&path)?;

    for batch in &batches {
        let ids = batch
            .column_by_name("id")
            .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
            .context("Missing id column in mapping.parquet")?;

        let build_ids = batch
            .column_by_name("build_id")
            .and_then(|c| c.as_any().downcast_ref::<StringArray>());

        let names = batch
            .column_by_name("name")
            .and_then(|c| c.as_any().downcast_ref::<StringArray>());

        for i in 0..batch.num_rows() {
            let id = ids.value(i);
            let build_id = get_optional_string(build_ids, i);
            let name = get_optional_string(names, i);

            mapping_map.insert(id, MappingData { build_id, name });
        }
    }

    Ok(mapping_map)
}
