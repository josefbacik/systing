//! Parquet to Perfetto converter module.
//!
//! This module reads parquet files from a directory and reconstructs a valid
//! Perfetto trace (.pb file). It is the inverse of the parquet_writer module.

use std::collections::HashMap;
use std::fs::File;
use std::io::BufWriter;
use std::path::Path;

use anyhow::{Context, Result};
use arrow::array::{Array, Float64Array, Int32Array, Int64Array, RecordBatch, StringArray};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use perfetto_protos::clock_snapshot::clock_snapshot::Clock;
use perfetto_protos::clock_snapshot::ClockSnapshot;
use perfetto_protos::debug_annotation::DebugAnnotation;
use perfetto_protos::ftrace_event_bundle::ftrace_event_bundle::CompactSched;
use perfetto_protos::ftrace_event_bundle::FtraceEventBundle;
use perfetto_protos::process_descriptor::ProcessDescriptor;
use perfetto_protos::profile_packet::PerfSample;
use perfetto_protos::thread_descriptor::ThreadDescriptor;
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
        let mut _primary_clock_id: Option<i32> = None;

        for batch in &batches {
            let clock_ids = batch
                .column_by_name("clock_id")
                .and_then(|c| c.as_any().downcast_ref::<Int32Array>())
                .context("Missing clock_id column")?;
            let timestamps = batch
                .column_by_name("timestamp_ns")
                .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                .context("Missing timestamp_ns column")?;
            let is_primaries = batch
                .column_by_name("is_primary")
                .and_then(|c| c.as_any().downcast_ref::<arrow::array::BooleanArray>());

            for i in 0..batch.num_rows() {
                let clock_id = clock_ids.value(i);
                let timestamp = timestamps.value(i);
                let is_primary = is_primaries.map(|arr| arr.value(i)).unwrap_or(false);

                let mut clock = Clock::default();
                clock.set_clock_id(clock_id as u32);
                clock.timestamp = Some(timestamp as u64);
                clocks.push(clock);

                if is_primary {
                    _primary_clock_id = Some(clock_id);
                }
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
                let name = names.and_then(|arr| {
                    if arr.is_null(i) {
                        None
                    } else {
                        Some(arr.value(i).to_string())
                    }
                });

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
                let name = names.and_then(|arr| {
                    if arr.is_null(i) {
                        None
                    } else {
                        Some(arr.value(i).to_string())
                    }
                });
                let upid = upids.and_then(|arr| {
                    if arr.is_null(i) {
                        None
                    } else {
                        Some(arr.value(i))
                    }
                });

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
                let parent_id = parent_ids.and_then(|arr| {
                    if arr.is_null(i) {
                        None
                    } else {
                        Some(arr.value(i))
                    }
                });

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
                let target_cpu = cpus
                    .and_then(|arr| {
                        if arr.is_null(i) {
                            None
                        } else {
                            Some(arr.value(i))
                        }
                    })
                    .unwrap_or(0);

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
                let name = names
                    .and_then(|arr| {
                        if arr.is_null(i) {
                            None
                        } else {
                            Some(arr.value(i).to_string())
                        }
                    })
                    .unwrap_or_default();
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
                let category = categories.and_then(|arr| {
                    if arr.is_null(i) {
                        None
                    } else {
                        Some(arr.value(i).to_string())
                    }
                });

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
                let int_value = int_values.and_then(|arr| {
                    if arr.is_null(i) {
                        None
                    } else {
                        Some(arr.value(i))
                    }
                });
                let string_value = string_values.and_then(|arr| {
                    if arr.is_null(i) {
                        None
                    } else {
                        Some(arr.value(i).to_string())
                    }
                });
                let real_value = real_values.and_then(|arr| {
                    if arr.is_null(i) {
                        None
                    } else {
                        Some(arr.value(i))
                    }
                });

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
                let category = categories.and_then(|arr| {
                    if arr.is_null(i) {
                        None
                    } else {
                        Some(arr.value(i).to_string())
                    }
                });

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
                let int_value = int_values.and_then(|arr| {
                    if arr.is_null(i) {
                        None
                    } else {
                        Some(arr.value(i))
                    }
                });
                let string_value = string_values.and_then(|arr| {
                    if arr.is_null(i) {
                        None
                    } else {
                        Some(arr.value(i).to_string())
                    }
                });
                let real_value = real_values.and_then(|arr| {
                    if arr.is_null(i) {
                        None
                    } else {
                        Some(arr.value(i))
                    }
                });

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
                    if !self.track_id_to_uuid.contains_key(&id) {
                        let uuid = self.alloc_uuid();
                        self.track_id_to_uuid.insert(id, uuid);
                    }

                    let uuid = *self.track_id_to_uuid.get(&id).unwrap();

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
    fn write_perf_samples(&mut self, input_dir: &Path, writer: &mut dyn TraceWriter) -> Result<()> {
        let perf_path = input_dir.join("perf_sample.parquet");
        if !perf_path.exists() {
            return Ok(());
        }

        // Need thread table to map utid -> (tid, pid)
        let thread_path = input_dir.join("thread.parquet");
        let utid_to_thread = if thread_path.exists() {
            self.build_utid_to_thread_map(&thread_path)?
        } else {
            HashMap::new()
        };

        let batches = read_parquet_file(&perf_path)?;

        for batch in &batches {
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
                let cpu = cpus.and_then(|arr| {
                    if arr.is_null(i) {
                        None
                    } else {
                        Some(arr.value(i) as u32)
                    }
                });

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

                let mut packet = TracePacket::default();
                packet.set_timestamp(ts as u64);
                packet.set_perf_sample(sample);
                writer.write_packet(&packet)?;
            }
        }

        Ok(())
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
