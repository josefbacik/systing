//! Parquet to Perfetto converter module.
//!
//! This module reads parquet files from a directory and reconstructs a valid
//! Perfetto trace (.pb file). It is the inverse of the parquet_writer module.

use std::collections::HashMap;
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
use perfetto_protos::counter_descriptor::counter_descriptor::Unit;
use perfetto_protos::counter_descriptor::CounterDescriptor;
use perfetto_protos::debug_annotation::DebugAnnotation;
use perfetto_protos::ftrace_event::FtraceEvent;
use perfetto_protos::ftrace_event_bundle::ftrace_event_bundle::CompactSched;
use perfetto_protos::ftrace_event_bundle::FtraceEventBundle;
use perfetto_protos::interned_data::InternedData;
use perfetto_protos::irq::{
    IrqHandlerEntryFtraceEvent, IrqHandlerExitFtraceEvent, SoftirqEntryFtraceEvent,
    SoftirqExitFtraceEvent,
};
use perfetto_protos::process_descriptor::ProcessDescriptor;
use perfetto_protos::profile_common::{Callstack, Frame, Mapping};
use perfetto_protos::profile_packet::PerfSample;
use perfetto_protos::sched::{SchedProcessExitFtraceEvent, SchedWakeupNewFtraceEvent};
use perfetto_protos::system_info::{SystemInfo, Utsname};
use perfetto_protos::thread_descriptor::ThreadDescriptor;
use perfetto_protos::trace_packet::trace_packet::SequenceFlags;
use perfetto_protos::trace_packet::TracePacket;
use perfetto_protos::track_descriptor::TrackDescriptor;
use perfetto_protos::track_event::track_event::Type;
use perfetto_protos::track_event::TrackEvent;

use crate::perfetto::{StreamingTraceWriter, TraceWriter};

/// Default process priority (nice value 0 = priority 120 in kernel).
const DEFAULT_PRIORITY: i32 = 120;

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

/// Thread info tuple: (tid, name, upid)
/// - tid: Thread ID
/// - name: Thread name
/// - upid: Optional process ID reference (used to look up actual pid/tgid)
type ThreadInfo = (i32, String, Option<i64>);

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
    /// Map from upid to pid (process ID) for thread descriptors
    upid_to_pid: HashMap<i64, i32>,
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
            upid_to_pid: HashMap::new(),
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

    /// Look up the process ID (tgid) from a upid, falling back to the provided tid.
    ///
    /// This is used to resolve the actual process ID when we have a thread's upid
    /// reference. If the upid is None or not found in upid_to_pid, we fall back
    /// to using the tid (which is correct for main threads where tid == tgid).
    fn resolve_tgid(&self, upid: Option<i64>, fallback_tid: i32) -> i32 {
        upid.and_then(|u| self.upid_to_pid.get(&u).copied())
            .unwrap_or(fallback_tid)
    }

    /// Convert parquet files to Perfetto trace
    fn convert(&mut self, input_dir: &Path, writer: &mut dyn TraceWriter) -> Result<()> {
        // 1. Write clock snapshots first (for timestamp correlation)
        self.write_clock_snapshots(input_dir, writer)?;

        // 1b. Write system info (utsname)
        self.write_system_info(input_dir, writer)?;

        // 2. Write TrackDescriptors for processes (ProcessDescriptor for each TGID)
        // 3. Write TrackDescriptors for threads (ThreadDescriptor for each TID != TGID)
        self.write_process_and_thread_descriptors(input_dir, writer)?;

        // 4. Write track descriptors
        self.write_track_descriptors(input_dir, writer)?;

        // 5. Write sched data (compact_sched format)
        self.write_sched_data(input_dir, writer)?;

        // 5b. Write IRQ/softirq data as FtraceEvents
        self.write_irq_softirq_data(input_dir, writer)?;

        // 5c. Write wakeup_new and process_exit as FtraceEvents
        self.write_misc_sched_events(input_dir, writer)?;

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

    /// Write SystemInfo packet with utsname data
    fn write_system_info(&mut self, input_dir: &Path, writer: &mut dyn TraceWriter) -> Result<()> {
        let path = input_dir.join("sysinfo.parquet");
        if !path.exists() {
            return Ok(());
        }

        let batches = read_parquet_file(&path)?;
        if batches.is_empty() {
            return Ok(());
        }

        // Read the first (and typically only) row
        let batch = &batches[0];
        if batch.num_rows() == 0 {
            return Ok(());
        }

        let sysname = batch
            .column_by_name("sysname")
            .and_then(|c| c.as_any().downcast_ref::<StringArray>())
            .context("Missing sysname column")?;
        let release = batch
            .column_by_name("release")
            .and_then(|c| c.as_any().downcast_ref::<StringArray>())
            .context("Missing release column")?;
        let version = batch
            .column_by_name("version")
            .and_then(|c| c.as_any().downcast_ref::<StringArray>())
            .context("Missing version column")?;
        let machine = batch
            .column_by_name("machine")
            .and_then(|c| c.as_any().downcast_ref::<StringArray>())
            .context("Missing machine column")?;

        let mut utsname = Utsname::default();
        utsname.set_sysname(sysname.value(0).to_string());
        utsname.set_release(release.value(0).to_string());
        utsname.set_version(version.value(0).to_string());
        utsname.set_machine(machine.value(0).to_string());

        let system_info = SystemInfo {
            utsname: Some(utsname).into(),
            ..Default::default()
        };

        let mut packet = TracePacket::default();
        packet.set_system_info(system_info);
        packet.set_trusted_packet_sequence_id(self.alloc_seq_id());
        writer.write_packet(&packet)?;

        Ok(())
    }

    /// Write TrackDescriptors for processes and threads.
    ///
    /// This creates:
    /// - TrackDescriptor with ProcessDescriptor for each TGID (from process.parquet)
    ///   The ProcessDescriptor.pid is set to the TGID.
    /// - TrackDescriptor with ThreadDescriptor for each TID != TGID (from thread.parquet)
    ///   The ThreadDescriptor.tid is set to the TID, and ThreadDescriptor.pid is set to the TGID.
    ///
    /// This is essential for Perfetto to associate sched events with the correct hierarchy.
    fn write_process_and_thread_descriptors(
        &mut self,
        input_dir: &Path,
        writer: &mut dyn TraceWriter,
    ) -> Result<()> {
        let process_path = input_dir.join("process.parquet");
        let thread_path = input_dir.join("thread.parquet");

        // First: Create TrackDescriptor with ProcessDescriptor for each TGID
        if process_path.exists() {
            let batches = read_parquet_file(&process_path)?;
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
                    let tgid = pids.value(i); // This is the TGID (process ID)
                    let name = get_optional_string(names, i);

                    let uuid = self.alloc_uuid();
                    self.upid_to_uuid.insert(upid, uuid);
                    self.upid_to_pid.insert(upid, tgid);

                    // Create TrackDescriptor with ProcessDescriptor
                    let mut desc = TrackDescriptor::default();
                    desc.set_uuid(uuid);
                    if let Some(n) = &name {
                        desc.set_name(n.clone());
                    }

                    let mut process = ProcessDescriptor::default();
                    process.set_pid(tgid);
                    if let Some(n) = &name {
                        process.set_process_name(n.clone());
                        process.cmdline.push(n.clone());
                    }
                    desc.process = Some(process).into();

                    let mut packet = TracePacket::default();
                    packet.set_track_descriptor(desc);
                    writer.write_packet(&packet)?;
                }
            }
        }

        // Second: Create TrackDescriptor with ThreadDescriptor for each TID != TGID
        if thread_path.exists() {
            let batches = read_parquet_file(&thread_path)?;
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

                    // Look up the TGID from the parent process
                    let tgid = self.resolve_tgid(upid, tid);

                    // Skip main threads (TID == TGID) - they're handled by ProcessDescriptor
                    if tid == tgid {
                        continue;
                    }

                    let uuid = self.alloc_uuid();
                    self.utid_to_uuid.insert(utid, uuid);

                    // Create TrackDescriptor with ThreadDescriptor
                    // The pid field in ThreadDescriptor tells Perfetto the parent TGID
                    // No need to set parent_uuid - that's only for custom tracks
                    let mut desc = TrackDescriptor::default();
                    desc.set_uuid(uuid);
                    if let Some(n) = &name {
                        desc.set_name(n.clone());
                    }

                    let mut thread = ThreadDescriptor::default();
                    thread.set_tid(tid); // TID (the thread's PID in Linux terms)
                    thread.set_pid(tgid); // TGID (the process ID) - this links to parent process
                    if let Some(n) = name {
                        thread.set_thread_name(n);
                    }
                    desc.thread = Some(thread).into();

                    let mut packet = TracePacket::default();
                    packet.set_track_descriptor(desc);
                    writer.write_packet(&packet)?;
                }
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

        // Build track_id -> utid mapping by scanning slices and instants
        // This lets us parent tracks to their owning thread
        let track_to_utid = self.build_track_to_utid_map(input_dir)?;

        // Detect CPU tracks and build hierarchy:
        // CPU tracks have names like "MyTrack CPU 0", "MyTrack CPU 1"
        // We create: Systing -> MyTrack -> CPU 0, CPU 1, ...
        let cpu_track_regex = regex::Regex::new(r"^(.+) CPU (\d+)$").unwrap();
        let mut base_track_uuids: HashMap<String, u64> = HashMap::new();
        let mut cpu_track_parents: HashMap<i64, u64> = HashMap::new();
        let mut systing_root_uuid: Option<u64> = None;

        // First, identify CPU tracks and create parent structure
        for (&id, name) in &track_names {
            if let Some(caps) = cpu_track_regex.captures(name) {
                let base_name = caps.get(1).unwrap().as_str().to_string();

                // Create Systing root track if not already created
                if systing_root_uuid.is_none() {
                    let root_uuid = self.alloc_uuid();
                    systing_root_uuid = Some(root_uuid);

                    let mut root_desc = TrackDescriptor::default();
                    root_desc.set_uuid(root_uuid);
                    root_desc.set_name("Systing".to_string());

                    let mut packet = TracePacket::default();
                    packet.set_track_descriptor(root_desc);
                    writer.write_packet(&packet)?;
                }

                // Allocate UUID for this base track name if not already created
                let parent_uuid = *base_track_uuids
                    .entry(base_name)
                    .or_insert_with(|| self.alloc_uuid());

                cpu_track_parents.insert(id, parent_uuid);
            }
        }

        // Write base track descriptors for CPU tracks
        if let Some(root_uuid) = systing_root_uuid {
            for (base_name, uuid) in &base_track_uuids {
                let mut desc = TrackDescriptor::default();
                desc.set_uuid(*uuid);
                desc.set_name(base_name.clone());
                desc.set_parent_uuid(root_uuid);

                let mut packet = TracePacket::default();
                packet.set_track_descriptor(desc);
                writer.write_packet(&packet)?;
            }
        }

        // Second pass: write track descriptors with proper parent UUIDs
        for (&id, &parent_id) in &track_parent_map {
            let uuid = *self.track_id_to_uuid.get(&id).unwrap();
            let name = track_names.get(&id).unwrap();

            let mut desc = TrackDescriptor::default();
            desc.set_uuid(uuid);

            // For CPU tracks, use just "CPU N" as the name and parent to base track
            if let Some(caps) = cpu_track_regex.captures(name) {
                let cpu_num = caps.get(2).unwrap().as_str();
                desc.set_name(format!("CPU {cpu_num}"));

                if let Some(&parent_uuid) = cpu_track_parents.get(&id) {
                    desc.set_parent_uuid(parent_uuid);
                }
            } else {
                desc.set_name(name.clone());

                // Try to find parent: first check explicit parent_id, then check utid
                if let Some(pid) = parent_id {
                    if let Some(&parent_uuid) = self.track_id_to_uuid.get(&pid) {
                        desc.set_parent_uuid(parent_uuid);
                    }
                } else if let Some(&utid) = track_to_utid.get(&id) {
                    // Parent this track to its thread
                    if let Some(&thread_uuid) = self.utid_to_uuid.get(&utid) {
                        desc.set_parent_uuid(thread_uuid);
                    }
                }
            }

            let mut packet = TracePacket::default();
            packet.set_track_descriptor(desc);
            writer.write_packet(&packet)?;
        }

        Ok(())
    }

    /// Build a map from track_id to utid by scanning slices and instants.
    ///
    /// For each track, finds the first utid associated with events on that track.
    /// This allows us to parent tracks to their owning thread.
    ///
    /// Note: If multiple events on the same track have different utids, the first
    /// one encountered wins. This matches the expectation that a track belongs to
    /// a single thread (mixed-thread tracks would be unusual).
    fn build_track_to_utid_map(&self, input_dir: &Path) -> Result<HashMap<i64, i64>> {
        let mut track_to_utid: HashMap<i64, i64> = HashMap::new();

        // Scan both slice.parquet and instant.parquet for track-to-utid mappings
        for filename in ["slice.parquet", "instant.parquet"] {
            let path = input_dir.join(filename);
            if path.exists() {
                scan_parquet_for_track_utids(&path, &mut track_to_utid)?;
            }
        }

        Ok(track_to_utid)
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
            let end_states = batch
                .column_by_name("end_state")
                .and_then(|c| c.as_any().downcast_ref::<Int32Array>());

            for i in 0..batch.num_rows() {
                let ts = timestamps.value(i);
                let cpu = cpus.value(i);
                let utid = utids.value(i);
                let priority = priorities.value(i);

                // Read end_state directly as the kernel task state value
                let prev_state: i64 = if let Some(states) = end_states {
                    if states.is_null(i) {
                        0 // TASK_RUNNING
                    } else {
                        states.value(i) as i64
                    }
                } else {
                    0 // Default to TASK_RUNNING if no end_state column
                };

                let (tid, comm, _) =
                    utid_to_thread
                        .get(&utid)
                        .cloned()
                        .unwrap_or((0, String::new(), None));

                let entry = cpu_events
                    .entry(cpu)
                    .or_insert_with(|| (Vec::new(), Vec::new()));
                entry.0.push(SchedSwitchEvent {
                    ts,
                    next_pid: tid,
                    next_prio: priority,
                    next_comm: comm,
                    prev_state,
                });
            }
        }

        // Process thread states (waking events only - state=0 means runnable)
        // Sleep states (state != 0) are already captured in sched_slices.end_state
        for batch in &thread_state_batches {
            let timestamps = batch
                .column_by_name("ts")
                .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                .context("Missing ts column")?;
            let utids = batch
                .column_by_name("utid")
                .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                .context("Missing utid column")?;
            let states = batch
                .column_by_name("state")
                .and_then(|c| c.as_any().downcast_ref::<Int32Array>())
                .context("Missing state column")?;
            let cpus = batch
                .column_by_name("cpu")
                .and_then(|c| c.as_any().downcast_ref::<Int32Array>());

            for i in 0..batch.num_rows() {
                let state = states.value(i);

                // Only create waking events for state=0 (TASK_RUNNING/runnable)
                // Sleep states (state != 0) are informational and already in sched_slices
                if state != 0 {
                    continue;
                }

                let ts = timestamps.value(i);
                let utid = utids.value(i);
                let target_cpu = get_optional_i32(cpus, i).unwrap_or(0);

                let (tid, comm, _) =
                    utid_to_thread
                        .get(&utid)
                        .cloned()
                        .unwrap_or((0, String::new(), None));

                // Waking events go to CPU 0 by convention (they have target_cpu field)
                let entry = cpu_events
                    .entry(0)
                    .or_insert_with(|| (Vec::new(), Vec::new()));
                entry.1.push(SchedWakingEvent {
                    ts,
                    pid: tid,
                    target_cpu,
                    prio: DEFAULT_PRIORITY,
                    comm,
                });
            }
        }

        // Write FtraceEventBundle packets for each CPU
        for (cpu, (mut switches, mut wakings)) in cpu_events {
            // Sort by timestamp
            switches.sort_by_key(|e| e.ts);
            wakings.sort_by_key(|e| e.ts);

            // Fix prev_state values: In the Parquet slice model, each slice's end_state
            // describes why THIS task left the CPU. In Perfetto's sched_switch event model,
            // prev_state describes why the PREVIOUS task left (i.e., the state of the task
            // being switched FROM). After sorting by timestamp, we shift values so that
            // event[i].prev_state = event[i-1]'s original end_state.
            //
            // Note: This means the LAST slice's end_state is intentionally discarded, as
            // there is no subsequent switch event to associate it with. For single-event
            // traces per CPU, this means all end_state information is lost (prev_state=0).
            if !switches.is_empty() {
                // Iterate backwards to avoid overwriting values we still need
                for i in (1..switches.len()).rev() {
                    switches[i].prev_state = switches[i - 1].prev_state;
                }
                // First event: we don't know what was running before the trace started
                switches[0].prev_state = 0;
            }

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

    /// Write IRQ and softirq data as FtraceEvents
    fn write_irq_softirq_data(
        &mut self,
        input_dir: &Path,
        writer: &mut dyn TraceWriter,
    ) -> Result<()> {
        let irq_path = input_dir.join("irq_slice.parquet");
        let softirq_path = input_dir.join("softirq_slice.parquet");

        // Collect all FtraceEvents keyed by (cpu, timestamp)
        let mut cpu_events: HashMap<i32, Vec<(i64, FtraceEvent)>> = HashMap::new();

        // Process IRQ slices -> generate entry and exit events
        if irq_path.exists() {
            let batches = read_parquet_file(&irq_path)?;
            for batch in &batches {
                let timestamps = batch
                    .column_by_name("ts")
                    .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                    .context("Missing ts column in irq_slice")?;
                let durs = batch
                    .column_by_name("dur")
                    .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                    .context("Missing dur column in irq_slice")?;
                let cpus = batch
                    .column_by_name("cpu")
                    .and_then(|c| c.as_any().downcast_ref::<Int32Array>())
                    .context("Missing cpu column in irq_slice")?;
                let irqs = batch
                    .column_by_name("irq")
                    .and_then(|c| c.as_any().downcast_ref::<Int32Array>())
                    .context("Missing irq column in irq_slice")?;
                let names = batch
                    .column_by_name("name")
                    .and_then(|c| c.as_any().downcast_ref::<StringArray>());
                let rets = batch
                    .column_by_name("ret")
                    .and_then(|c| c.as_any().downcast_ref::<Int32Array>());

                for i in 0..batch.num_rows() {
                    let ts = timestamps.value(i);
                    let dur = durs.value(i);
                    let cpu = cpus.value(i);
                    let irq = irqs.value(i);
                    let name = get_optional_string(names, i).unwrap_or_default();
                    let ret = get_optional_i32(rets, i).unwrap_or(0);

                    // Create entry event
                    let mut entry_event = FtraceEvent::default();
                    entry_event.set_timestamp(ts as u64);
                    entry_event.set_pid(0); // IRQs don't have a pid, use 0
                    let mut entry = IrqHandlerEntryFtraceEvent::default();
                    entry.set_irq(irq);
                    entry.set_name(name);
                    entry_event.set_irq_handler_entry(entry);

                    // Create exit event
                    let mut exit_event = FtraceEvent::default();
                    exit_event.set_timestamp((ts + dur) as u64);
                    exit_event.set_pid(0);
                    let mut exit = IrqHandlerExitFtraceEvent::default();
                    exit.set_irq(irq);
                    exit.set_ret(ret);
                    exit_event.set_irq_handler_exit(exit);

                    let events_for_cpu = cpu_events.entry(cpu).or_default();
                    events_for_cpu.push((ts, entry_event));
                    events_for_cpu.push((ts + dur, exit_event));
                }
            }
        }

        // Process softirq slices -> generate entry and exit events
        if softirq_path.exists() {
            let batches = read_parquet_file(&softirq_path)?;
            for batch in &batches {
                let timestamps = batch
                    .column_by_name("ts")
                    .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                    .context("Missing ts column in softirq_slice")?;
                let durs = batch
                    .column_by_name("dur")
                    .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                    .context("Missing dur column in softirq_slice")?;
                let cpus = batch
                    .column_by_name("cpu")
                    .and_then(|c| c.as_any().downcast_ref::<Int32Array>())
                    .context("Missing cpu column in softirq_slice")?;
                let vecs = batch
                    .column_by_name("vec")
                    .and_then(|c| c.as_any().downcast_ref::<Int32Array>())
                    .context("Missing vec column in softirq_slice")?;

                for i in 0..batch.num_rows() {
                    let ts = timestamps.value(i);
                    let dur = durs.value(i);
                    let cpu = cpus.value(i);
                    let vec = vecs.value(i);

                    // Create entry event
                    let mut entry_event = FtraceEvent::default();
                    entry_event.set_timestamp(ts as u64);
                    entry_event.set_pid(0); // Softirqs don't have a pid, use 0
                    let mut entry = SoftirqEntryFtraceEvent::default();
                    entry.set_vec(vec as u32);
                    entry_event.set_softirq_entry(entry);

                    // Create exit event
                    let mut exit_event = FtraceEvent::default();
                    exit_event.set_timestamp((ts + dur) as u64);
                    exit_event.set_pid(0);
                    let mut exit = SoftirqExitFtraceEvent::default();
                    exit.set_vec(vec as u32);
                    exit_event.set_softirq_exit(exit);

                    let events_for_cpu = cpu_events.entry(cpu).or_default();
                    events_for_cpu.push((ts, entry_event));
                    events_for_cpu.push((ts + dur, exit_event));
                }
            }
        }

        // Write FtraceEventBundle for each CPU
        for (cpu, mut events) in cpu_events {
            // Sort by timestamp
            events.sort_by_key(|(ts, _)| *ts);

            let ftrace_events: Vec<FtraceEvent> = events.into_iter().map(|(_, e)| e).collect();

            if !ftrace_events.is_empty() {
                let mut bundle = FtraceEventBundle::default();
                bundle.set_cpu(cpu as u32);
                bundle.event = ftrace_events;

                let mut packet = TracePacket::default();
                packet.set_ftrace_events(bundle);
                writer.write_packet(&packet)?;
            }
        }

        Ok(())
    }

    /// Write wakeup_new and process_exit as FtraceEvents
    fn write_misc_sched_events(
        &mut self,
        input_dir: &Path,
        writer: &mut dyn TraceWriter,
    ) -> Result<()> {
        let wakeup_path = input_dir.join("wakeup_new.parquet");
        let exit_path = input_dir.join("process_exit.parquet");

        // Need thread/process info for the events
        let thread_path = input_dir.join("thread.parquet");
        let utid_to_thread = if thread_path.exists() {
            self.build_utid_to_thread_map(&thread_path)?
        } else {
            HashMap::new()
        };

        let mut cpu_events: HashMap<i32, Vec<(i64, FtraceEvent)>> = HashMap::new();

        // Process wakeup_new events
        if wakeup_path.exists() {
            let batches = read_parquet_file(&wakeup_path)?;
            for batch in &batches {
                let timestamps = batch
                    .column_by_name("ts")
                    .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                    .context("Missing ts column in wakeup_new")?;
                let cpus = batch
                    .column_by_name("cpu")
                    .and_then(|c| c.as_any().downcast_ref::<Int32Array>())
                    .context("Missing cpu column in wakeup_new")?;
                let utids = batch
                    .column_by_name("utid")
                    .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                    .context("Missing utid column in wakeup_new")?;
                let target_cpus = batch
                    .column_by_name("target_cpu")
                    .and_then(|c| c.as_any().downcast_ref::<Int32Array>())
                    .context("Missing target_cpu column in wakeup_new")?;

                for i in 0..batch.num_rows() {
                    let ts = timestamps.value(i);
                    let cpu = cpus.value(i);
                    let utid = utids.value(i);
                    let target_cpu = target_cpus.value(i);

                    let (pid, comm, _) = utid_to_thread.get(&utid).cloned().unwrap_or((
                        utid as i32,
                        String::new(),
                        None,
                    ));

                    let mut ftrace_event = FtraceEvent::default();
                    ftrace_event.set_timestamp(ts as u64);
                    ftrace_event.set_pid(pid as u32);
                    let mut wakeup = SchedWakeupNewFtraceEvent::default();
                    wakeup.set_pid(pid);
                    wakeup.set_comm(comm);
                    wakeup.set_target_cpu(target_cpu);
                    wakeup.set_prio(DEFAULT_PRIORITY);
                    ftrace_event.set_sched_wakeup_new(wakeup);

                    cpu_events.entry(cpu).or_default().push((ts, ftrace_event));
                }
            }
        }

        // Process process_exit events
        if exit_path.exists() {
            let batches = read_parquet_file(&exit_path)?;
            for batch in &batches {
                let timestamps = batch
                    .column_by_name("ts")
                    .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                    .context("Missing ts column in process_exit")?;
                let cpus = batch
                    .column_by_name("cpu")
                    .and_then(|c| c.as_any().downcast_ref::<Int32Array>())
                    .context("Missing cpu column in process_exit")?;
                let utids = batch
                    .column_by_name("utid")
                    .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                    .context("Missing utid column in process_exit")?;

                for i in 0..batch.num_rows() {
                    let ts = timestamps.value(i);
                    let cpu = cpus.value(i);
                    let utid = utids.value(i);

                    let (tid, comm, upid) = utid_to_thread.get(&utid).cloned().unwrap_or((
                        utid as i32,
                        String::new(),
                        None,
                    ));

                    // Look up the actual process ID (tgid) from upid, fallback to tid
                    let tgid = self.resolve_tgid(upid, tid);

                    let mut ftrace_event = FtraceEvent::default();
                    ftrace_event.set_timestamp(ts as u64);
                    ftrace_event.set_pid(tid as u32);
                    let mut exit = SchedProcessExitFtraceEvent::default();
                    exit.set_pid(tid);
                    exit.set_tgid(tgid);
                    exit.set_comm(comm);
                    exit.set_prio(DEFAULT_PRIORITY);
                    ftrace_event.set_sched_process_exit(exit);

                    cpu_events.entry(cpu).or_default().push((ts, ftrace_event));
                }
            }
        }

        // Write FtraceEventBundle for each CPU
        for (cpu, mut events) in cpu_events {
            events.sort_by_key(|(ts, _)| *ts);

            let ftrace_events: Vec<FtraceEvent> = events.into_iter().map(|(_, e)| e).collect();

            if !ftrace_events.is_empty() {
                let mut bundle = FtraceEventBundle::default();
                bundle.set_cpu(cpu as u32);
                bundle.event = ftrace_events;

                let mut packet = TracePacket::default();
                packet.set_ftrace_events(bundle);
                writer.write_packet(&packet)?;
            }
        }

        Ok(())
    }

    /// Build utid -> ThreadInfo mapping from thread table.
    ///
    /// This also includes tid -> ThreadInfo mappings because the streaming sched
    /// recorder uses `tid as utid` for efficiency. This allows lookups to work
    /// whether the caller has a real utid or a tid-as-utid.
    ///
    /// The upid in ThreadInfo can be used with `upid_to_pid` to get the actual process ID (tgid).
    fn build_utid_to_thread_map(&self, path: &Path) -> Result<HashMap<i64, ThreadInfo>> {
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
            let upids = batch
                .column_by_name("upid")
                .and_then(|c| c.as_any().downcast_ref::<Int64Array>());

            for i in 0..batch.num_rows() {
                let utid = utids.value(i);
                let tid = tids.value(i);
                let name = get_optional_string(names, i).unwrap_or_default();
                let upid = get_optional_i64(upids, i);
                // Insert by utid (for non-streaming cases)
                map.insert(utid, (tid, name.clone(), upid));
                // Also insert by tid (for streaming cases where utid = tid)
                map.insert(tid as i64, (tid, name, upid));
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
                let units = batch
                    .column_by_name("unit")
                    .and_then(|c| c.as_any().downcast_ref::<StringArray>());

                for i in 0..batch.num_rows() {
                    let id = ids.value(i);
                    let name = names.value(i).to_string();
                    let unit = get_optional_string(units, i);

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

                    // Mark as counter track with unit
                    let mut counter_desc = CounterDescriptor::default();
                    if let Some(unit_str) = unit {
                        // Map known unit strings to enum values
                        match unit_str.as_str() {
                            "" | "unspecified" => {} // Leave unit unset
                            "count" => counter_desc.set_unit(Unit::UNIT_COUNT),
                            "ns" | "time_ns" => counter_desc.set_unit(Unit::UNIT_TIME_NS),
                            "bytes" | "size_bytes" => counter_desc.set_unit(Unit::UNIT_SIZE_BYTES),
                            // For unknown units, use unit_name for custom display
                            other => counter_desc.set_unit_name(other.to_string()),
                        }
                    }
                    desc.counter = Some(counter_desc).into();

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

            if !stack_data.is_empty() {
                self.write_interned_stack_data(writer, &stack_data)?
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

                let (tid, _, upid) =
                    utid_to_thread
                        .get(&utid)
                        .cloned()
                        .unwrap_or((0, String::new(), None));

                // Look up the actual process ID (tgid) from upid, fallback to tid
                let pid = self.resolve_tgid(upid, tid);

                let mut sample = PerfSample::default();
                sample.set_tid(tid as u32);
                sample.set_pid(pid as u32);
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
    /// Generates frames and mappings on-the-fly from frame_names strings.
    /// Module names are parsed from the embedded format in frame_names:
    /// `function_name (module_name [file:line]) <0xaddr>`
    fn write_interned_stack_data(
        &mut self,
        writer: &mut dyn TraceWriter,
        stack_data: &HashMap<i64, StackData>,
    ) -> Result<(HashMap<i64, u64>, u32)> {
        let sequence_id = self.alloc_seq_id();

        // Deduplicate frames by their full name string
        // Map: frame_name -> frame iid
        let mut frames: Vec<Frame> = Vec::new();
        let mut frame_name_to_iid: HashMap<String, u64> = HashMap::new();
        let mut next_frame_iid: u64 = 1;

        // Track unique module names and assign mapping IDs
        let mut module_to_mapping_id: HashMap<String, u64> = HashMap::new();
        let mut next_mapping_id: u64 = 1;

        // Build function names alongside frames
        let mut function_names: Vec<perfetto_protos::profile_common::InternedString> = Vec::new();

        // Build Callstack protos for each stack
        // Map: stack_id -> callstack_iid
        let mut callstacks: Vec<Callstack> = Vec::new();
        let mut stack_to_callstack_iid: HashMap<i64, u64> = HashMap::new();
        let mut next_callstack_iid: u64 = 1;

        for (&stack_id, stack) in stack_data {
            if stack.frame_names.is_empty() {
                continue;
            }

            // Collect frame iids for this callstack
            let mut callstack_frame_ids: Vec<u64> = Vec::new();

            for frame_name in &stack.frame_names {
                // Get or create frame entry (deduplicated by full frame_name string)
                let frame_iid = match frame_name_to_iid.get(frame_name) {
                    Some(&iid) => iid,
                    None => {
                        let iid = next_frame_iid;
                        next_frame_iid += 1;
                        frame_name_to_iid.insert(frame_name.clone(), iid);

                        // Build Frame proto
                        let mut frame = Frame::default();
                        frame.set_iid(iid);
                        frame.set_function_name_id(iid);
                        frame.set_rel_pc(0);

                        // Parse module name from frame_name and generate mapping ID
                        if let Some(module_name) = parse_module_name(frame_name) {
                            let mapping_id =
                                *module_to_mapping_id.entry(module_name).or_insert_with(|| {
                                    let id = next_mapping_id;
                                    next_mapping_id += 1;
                                    id
                                });
                            frame.set_mapping_id(mapping_id);
                        }

                        // Add function name to interned strings
                        let mut interned_str =
                            perfetto_protos::profile_common::InternedString::default();
                        interned_str.set_iid(iid);
                        interned_str.set_str(frame_name.as_bytes().to_vec());
                        function_names.push(interned_str);

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

        // Build Mapping protos from unique module names
        // All offsets set to 0 - UI ignores them
        let mappings: Vec<Mapping> = module_to_mapping_id
            .iter()
            .map(|(_module_name, &mapping_id)| {
                let mut mapping = Mapping::default();
                mapping.set_iid(mapping_id);
                mapping.set_exact_offset(0);
                mapping.set_start_offset(0);
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

/// Scan a parquet file for track_id -> utid mappings.
///
/// Populates the provided map with the first utid found for each track_id.
fn scan_parquet_for_track_utids(path: &Path, track_to_utid: &mut HashMap<i64, i64>) -> Result<()> {
    let batches = read_parquet_file(path)?;
    for batch in &batches {
        let track_ids = batch
            .column_by_name("track_id")
            .and_then(|c| c.as_any().downcast_ref::<Int64Array>());
        let utids = batch
            .column_by_name("utid")
            .and_then(|c| c.as_any().downcast_ref::<Int64Array>());

        if let (Some(track_ids), Some(utids)) = (track_ids, utids) {
            for i in 0..batch.num_rows() {
                let track_id = track_ids.value(i);
                if let Some(utid) = get_optional_i64(Some(utids), i) {
                    track_to_utid.entry(track_id).or_insert(utid);
                }
            }
        }
    }
    Ok(())
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
    /// Frame names in leaf-to-root order.
    /// Each name contains embedded module and location info in format:
    /// `function_name (module_name [file:line]) <0xaddr>`
    frame_names: Vec<String>,
}

/// Parse module name from a frame name string.
///
/// Frame names are formatted as: `function_name (module_name [file:line]) <0xaddr>`
/// Returns the module name (e.g., "libc.so.6") or None if not found.
fn parse_module_name(frame_name: &str) -> Option<String> {
    // Find first '(' and extract content until ' [' or ')'
    let start = frame_name.find('(')?;
    let rest = &frame_name[start + 1..];

    // Find end of module name (either ' [' for source location or ')' for end)
    let end = rest
        .find(" [")
        .or_else(|| rest.find(')'))
        .unwrap_or(rest.len());

    let module = rest[..end].trim();
    if module.is_empty() || module == "unknown" {
        None
    } else {
        Some(module.to_string())
    }
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

        let frame_names_col = batch
            .column_by_name("frame_names")
            .and_then(|c| c.as_any().downcast_ref::<ListArray>())
            .context("Missing frame_names column in stack.parquet")?;

        for i in 0..batch.num_rows() {
            let id = ids.value(i);

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

            stack_map.insert(id, StackData { frame_names });
        }
    }

    Ok(stack_map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow::datatypes::{DataType, Field, Schema};
    use parquet::arrow::ArrowWriter;
    use std::sync::Arc;
    use tempfile::tempdir;

    /// Helper to create a test parquet file with process records
    fn create_test_process_parquet(dir: &Path, upid: i64, pid: i32) -> Result<()> {
        let path = dir.join("process.parquet");
        let schema = Arc::new(Schema::new(vec![
            Field::new("upid", DataType::Int64, false),
            Field::new("pid", DataType::Int32, false),
            Field::new("name", DataType::Utf8, true),
            Field::new("parent_upid", DataType::Int64, true),
        ]));

        let upids = Int64Array::from(vec![upid]);
        let pids = Int32Array::from(vec![pid]);
        let names: StringArray = vec![Some("test_process")].into_iter().collect();
        let parent_upids: Int64Array = vec![None::<i64>].into_iter().collect();

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(upids),
                Arc::new(pids),
                Arc::new(names),
                Arc::new(parent_upids),
            ],
        )?;

        let file = File::create(path)?;
        let mut writer = ArrowWriter::try_new(file, schema, None)?;
        writer.write(&batch)?;
        writer.close()?;
        Ok(())
    }

    /// Helper to create a test parquet file with thread records
    fn create_test_thread_parquet(
        dir: &Path,
        utid: i64,
        tid: i32,
        upid: Option<i64>,
    ) -> Result<()> {
        let path = dir.join("thread.parquet");
        let schema = Arc::new(Schema::new(vec![
            Field::new("utid", DataType::Int64, false),
            Field::new("tid", DataType::Int32, false),
            Field::new("name", DataType::Utf8, true),
            Field::new("upid", DataType::Int64, true),
        ]));

        let utids = Int64Array::from(vec![utid]);
        let tids = Int32Array::from(vec![tid]);
        let names: StringArray = vec![Some("test_thread")].into_iter().collect();
        let upids: Int64Array = vec![upid].into_iter().collect();

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(utids),
                Arc::new(tids),
                Arc::new(names),
                Arc::new(upids),
            ],
        )?;

        let file = File::create(path)?;
        let mut writer = ArrowWriter::try_new(file, schema, None)?;
        writer.write(&batch)?;
        writer.close()?;
        Ok(())
    }

    /// Helper to create a test parquet file with perf_sample records
    fn create_test_perf_sample_parquet(dir: &Path, ts: i64, utid: i64, cpu: i32) -> Result<()> {
        let path = dir.join("perf_sample.parquet");
        let schema = Arc::new(Schema::new(vec![
            Field::new("ts", DataType::Int64, false),
            Field::new("utid", DataType::Int64, false),
            Field::new("callsite_id", DataType::Int64, true),
            Field::new("cpu", DataType::Int32, true),
        ]));

        let timestamps = Int64Array::from(vec![ts]);
        let utids = Int64Array::from(vec![utid]);
        let callsite_ids: Int64Array = vec![None::<i64>].into_iter().collect();
        let cpus = Int32Array::from(vec![Some(cpu)]);

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(timestamps),
                Arc::new(utids),
                Arc::new(callsite_ids),
                Arc::new(cpus),
            ],
        )?;

        let file = File::create(path)?;
        let mut writer = ArrowWriter::try_new(file, schema, None)?;
        writer.write(&batch)?;
        writer.close()?;
        Ok(())
    }

    /// Helper to create a test parquet file with process_exit records
    fn create_test_process_exit_parquet(dir: &Path, ts: i64, cpu: i32, utid: i64) -> Result<()> {
        let path = dir.join("process_exit.parquet");
        let schema = Arc::new(Schema::new(vec![
            Field::new("ts", DataType::Int64, false),
            Field::new("cpu", DataType::Int32, false),
            Field::new("utid", DataType::Int64, false),
        ]));

        let timestamps = Int64Array::from(vec![ts]);
        let cpus = Int32Array::from(vec![cpu]);
        let utids = Int64Array::from(vec![utid]);

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![Arc::new(timestamps), Arc::new(cpus), Arc::new(utids)],
        )?;

        let file = File::create(path)?;
        let mut writer = ArrowWriter::try_new(file, schema, None)?;
        writer.write(&batch)?;
        writer.close()?;
        Ok(())
    }

    #[test]
    fn test_build_utid_to_thread_map_returns_upid() {
        let dir = tempdir().unwrap();

        // Create thread parquet with upid
        create_test_thread_parquet(dir.path(), 100, 1234, Some(1)).unwrap();

        let converter = ParquetToPerfettoConverter::new();
        let thread_path = dir.path().join("thread.parquet");
        let map = converter.build_utid_to_thread_map(&thread_path).unwrap();

        // Verify the map contains the expected data
        let (tid, name, upid) = map.get(&100).unwrap();
        assert_eq!(*tid, 1234);
        assert_eq!(name, "test_thread");
        assert_eq!(*upid, Some(1));

        // Also verify the tid-as-utid entry exists
        let (tid2, name2, upid2) = map.get(&1234).unwrap();
        assert_eq!(*tid2, 1234);
        assert_eq!(name2, "test_thread");
        assert_eq!(*upid2, Some(1));
    }

    #[test]
    fn test_build_utid_to_thread_map_handles_missing_upid() {
        let dir = tempdir().unwrap();

        // Create thread parquet without upid
        create_test_thread_parquet(dir.path(), 100, 1234, None).unwrap();

        let converter = ParquetToPerfettoConverter::new();
        let thread_path = dir.path().join("thread.parquet");
        let map = converter.build_utid_to_thread_map(&thread_path).unwrap();

        let (tid, _, upid) = map.get(&100).unwrap();
        assert_eq!(*tid, 1234);
        assert!(upid.is_none());
    }

    #[test]
    fn test_perf_sample_uses_correct_pid_from_upid() {
        use crate::perfetto::VecTraceWriter;

        let dir = tempdir().unwrap();

        // Create process with upid=1, pid=1000 (the tgid/process ID)
        create_test_process_parquet(dir.path(), 1, 1000).unwrap();

        // Create thread with tid=2000 (different from pid), linked to upid=1
        create_test_thread_parquet(dir.path(), 100, 2000, Some(1)).unwrap();

        // Create perf_sample referencing utid=100
        create_test_perf_sample_parquet(dir.path(), 123456789, 100, 0).unwrap();

        // Convert to Perfetto
        let mut converter = ParquetToPerfettoConverter::new();
        let mut writer = VecTraceWriter::default();

        // First write process/thread descriptors to populate upid_to_pid
        converter
            .write_process_and_thread_descriptors(dir.path(), &mut writer)
            .unwrap();

        // Then write perf samples
        converter
            .write_perf_samples(dir.path(), &mut writer)
            .unwrap();

        // Find the PerfSample packet and verify pid/tid
        let perf_sample_packet = writer.packets.iter().find(|p| p.has_perf_sample()).unwrap();
        let sample = perf_sample_packet.perf_sample();

        // tid should be 2000 (the thread ID)
        assert_eq!(sample.tid(), 2000);
        // pid should be 1000 (the process ID from upid lookup), NOT 2000
        assert_eq!(sample.pid(), 1000);
    }

    #[test]
    fn test_perf_sample_falls_back_to_tid_when_no_upid() {
        use crate::perfetto::VecTraceWriter;

        let dir = tempdir().unwrap();

        // Create thread without upid (simulating missing process linkage)
        create_test_thread_parquet(dir.path(), 100, 2000, None).unwrap();

        // Create perf_sample referencing utid=100
        create_test_perf_sample_parquet(dir.path(), 123456789, 100, 0).unwrap();

        // Convert to Perfetto
        let mut converter = ParquetToPerfettoConverter::new();
        let mut writer = VecTraceWriter::default();

        // Write perf samples (no process table, so upid_to_pid will be empty)
        converter
            .write_perf_samples(dir.path(), &mut writer)
            .unwrap();

        // Find the PerfSample packet
        let perf_sample_packet = writer.packets.iter().find(|p| p.has_perf_sample()).unwrap();
        let sample = perf_sample_packet.perf_sample();

        // Both tid and pid should fall back to 2000 when upid lookup fails
        assert_eq!(sample.tid(), 2000);
        assert_eq!(sample.pid(), 2000);
    }

    #[test]
    fn test_process_exit_uses_correct_tgid_from_upid() {
        use crate::perfetto::VecTraceWriter;

        let dir = tempdir().unwrap();

        // Create process with upid=1, pid=1000 (the tgid/process ID)
        create_test_process_parquet(dir.path(), 1, 1000).unwrap();

        // Create thread with tid=2000 (different from pid), linked to upid=1
        create_test_thread_parquet(dir.path(), 100, 2000, Some(1)).unwrap();

        // Create process_exit event for utid=100
        create_test_process_exit_parquet(dir.path(), 123456789, 0, 100).unwrap();

        // Convert to Perfetto
        let mut converter = ParquetToPerfettoConverter::new();
        let mut writer = VecTraceWriter::default();

        // First write process/thread descriptors to populate upid_to_pid
        converter
            .write_process_and_thread_descriptors(dir.path(), &mut writer)
            .unwrap();

        // Then write misc sched events (which includes process_exit)
        converter
            .write_misc_sched_events(dir.path(), &mut writer)
            .unwrap();

        // Find the FtraceEventBundle packet and extract the process_exit event
        let ftrace_bundle = writer
            .packets
            .iter()
            .find(|p| p.has_ftrace_events())
            .expect("Should have ftrace_events packet");

        let bundle = ftrace_bundle.ftrace_events();
        let exit_event = bundle
            .event
            .iter()
            .find(|e| e.has_sched_process_exit())
            .expect("Should have sched_process_exit event");

        let exit = exit_event.sched_process_exit();

        // pid should be 2000 (the thread ID)
        assert_eq!(exit.pid(), 2000);
        // tgid should be 1000 (the process ID from upid lookup), NOT 2000
        assert_eq!(exit.tgid(), 1000);
    }

    #[test]
    fn test_parse_module_name_with_source_location() {
        assert_eq!(
            parse_module_name("main (myprogram [main.rs:10]) <0x1234>"),
            Some("myprogram".to_string())
        );
    }

    #[test]
    fn test_parse_module_name_without_source_location() {
        assert_eq!(
            parse_module_name("func (libc.so.6) <0x5678>"),
            Some("libc.so.6".to_string())
        );
    }

    #[test]
    fn test_parse_module_name_kernel() {
        assert_eq!(
            parse_module_name("schedule ([kernel]) <0xffffffff81234567>"),
            Some("[kernel]".to_string())
        );
    }

    #[test]
    fn test_parse_module_name_no_parens() {
        // Frame names without parentheses (e.g., unsymbolized addresses)
        assert_eq!(parse_module_name("0x9abc"), None);
    }

    #[test]
    fn test_parse_module_name_unknown_module() {
        // "unknown" module should return None
        assert_eq!(parse_module_name("some_func (unknown) <0x1234>"), None);
    }

    #[test]
    fn test_parse_module_name_empty_module() {
        // Empty module between parens
        assert_eq!(parse_module_name("some_func () <0x1234>"), None);
    }

    #[test]
    fn test_parse_module_name_complex_path() {
        // Module with complex characters
        assert_eq!(
            parse_module_name(
                "_ZN4core3fmt5Write9write_fmt (libstd-abc123.so [fmt.rs:200]) <0xdead>"
            ),
            Some("libstd-abc123.so".to_string())
        );
    }
}
