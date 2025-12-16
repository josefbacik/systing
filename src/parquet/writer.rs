//! Streaming Parquet writer for trace data.
//!
//! This module provides a streaming writer that buffers records and writes them
//! to Parquet files when batch thresholds are reached, limiting memory usage.
//!
//! # Thread Safety
//!
//! `StreamingParquetWriter` is NOT thread-safe. Use from a single thread or wrap
//! in appropriate synchronization primitives.

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use arrow::array::{
    BooleanBuilder, Float64Builder, Int32Builder, Int64Builder, ListBuilder, RecordBatch,
    StringBuilder,
};
use arrow::datatypes::Schema;
use parquet::arrow::ArrowWriter;
use parquet::basic::Compression;
use parquet::file::properties::WriterProperties;

use crate::parquet::ParquetPaths;
use crate::record::RecordCollector;
use crate::trace::{
    self, ArgRecord, ClockSnapshotRecord, CounterRecord, CounterTrackRecord, InstantArgRecord,
    InstantRecord, IrqSliceRecord, NetworkInterfaceRecord, ProcessExitRecord, ProcessRecord,
    SchedSliceRecord, SliceRecord, SocketConnectionRecord, SoftirqSliceRecord, StackRecord,
    StackSampleRecord, ThreadRecord, ThreadStateRecord, TrackRecord, WakeupNewRecord,
};

/// Default batch size for streaming writes.
const DEFAULT_BATCH_SIZE: usize = 50_000;

/// A streaming Parquet writer that implements `RecordCollector`.
///
/// Records are buffered in memory and flushed to Parquet files when the
/// batch size threshold is reached. Each flush writes a new row group to
/// the file, preserving all previously written data.
///
/// # Thread Safety
///
/// This type is NOT thread-safe. Use from a single thread.
pub struct StreamingParquetWriter {
    output_dir: PathBuf,
    paths: ParquetPaths,
    batch_size: usize,
    writer_props: WriterProperties,

    // Buffers for each record type
    processes: Vec<ProcessRecord>,
    threads: Vec<ThreadRecord>,
    sched_slices: Vec<SchedSliceRecord>,
    thread_states: Vec<ThreadStateRecord>,
    irq_slices: Vec<IrqSliceRecord>,
    softirq_slices: Vec<SoftirqSliceRecord>,
    wakeup_news: Vec<WakeupNewRecord>,
    process_exits: Vec<ProcessExitRecord>,
    counters: Vec<CounterRecord>,
    counter_tracks: Vec<CounterTrackRecord>,
    slices: Vec<SliceRecord>,
    tracks: Vec<TrackRecord>,
    instants: Vec<InstantRecord>,
    args: Vec<ArgRecord>,
    instant_args: Vec<InstantArgRecord>,
    stacks: Vec<StackRecord>,
    stack_samples: Vec<StackSampleRecord>,
    network_interfaces: Vec<NetworkInterfaceRecord>,
    socket_connections: Vec<SocketConnectionRecord>,
    clock_snapshots: Vec<ClockSnapshotRecord>,

    // Persistent writers (created lazily on first flush, kept alive until finish)
    process_writer: Option<ArrowWriter<File>>,
    thread_writer: Option<ArrowWriter<File>>,
    sched_slice_writer: Option<ArrowWriter<File>>,
    thread_state_writer: Option<ArrowWriter<File>>,
    irq_slice_writer: Option<ArrowWriter<File>>,
    softirq_slice_writer: Option<ArrowWriter<File>>,
    wakeup_new_writer: Option<ArrowWriter<File>>,
    process_exit_writer: Option<ArrowWriter<File>>,
    counter_writer: Option<ArrowWriter<File>>,
    counter_track_writer: Option<ArrowWriter<File>>,
    slice_writer: Option<ArrowWriter<File>>,
    track_writer: Option<ArrowWriter<File>>,
    instant_writer: Option<ArrowWriter<File>>,
    args_writer: Option<ArrowWriter<File>>,
    instant_args_writer: Option<ArrowWriter<File>>,
    stack_writer: Option<ArrowWriter<File>>,
    stack_sample_writer: Option<ArrowWriter<File>>,
    network_interface_writer: Option<ArrowWriter<File>>,
    socket_connection_writer: Option<ArrowWriter<File>>,
    clock_snapshot_writer: Option<ArrowWriter<File>>,

    // Track counts for statistics
    total_records: usize,
}

impl StreamingParquetWriter {
    /// Create a new streaming Parquet writer.
    ///
    /// The output directory will be created if it doesn't exist.
    pub fn new(output_dir: &Path) -> Result<Self> {
        Self::with_batch_size(output_dir, DEFAULT_BATCH_SIZE)
    }

    /// Create a new streaming Parquet writer with a custom batch size.
    pub fn with_batch_size(output_dir: &Path, batch_size: usize) -> Result<Self> {
        // Create the output directory if it doesn't exist
        if !output_dir.exists() {
            fs::create_dir_all(output_dir).with_context(|| {
                format!(
                    "Failed to create output directory: {}",
                    output_dir.display()
                )
            })?;
        } else if !output_dir.is_dir() {
            anyhow::bail!(
                "Output path exists but is not a directory: {}",
                output_dir.display()
            );
        }

        let paths = ParquetPaths::new(output_dir);
        let writer_props = WriterProperties::builder()
            .set_compression(Compression::ZSTD(Default::default()))
            .set_max_row_group_size(1_000_000)
            .build();

        Ok(Self {
            output_dir: output_dir.to_path_buf(),
            paths,
            batch_size,
            writer_props,
            // Buffers with appropriate capacities
            processes: Vec::with_capacity(1024), // Low volume
            threads: Vec::with_capacity(1024),   // Low volume
            sched_slices: Vec::with_capacity(batch_size), // High volume
            thread_states: Vec::with_capacity(batch_size), // High volume
            irq_slices: Vec::with_capacity(batch_size), // High volume
            softirq_slices: Vec::with_capacity(batch_size), // High volume
            wakeup_news: Vec::with_capacity(1024), // Medium volume
            process_exits: Vec::with_capacity(1024), // Medium volume
            counters: Vec::with_capacity(batch_size), // High volume
            counter_tracks: Vec::with_capacity(256), // Low volume
            slices: Vec::with_capacity(batch_size), // High volume
            tracks: Vec::with_capacity(256),     // Low volume
            instants: Vec::with_capacity(batch_size), // High volume
            args: Vec::with_capacity(batch_size), // High volume
            instant_args: Vec::with_capacity(batch_size), // High volume
            stacks: Vec::with_capacity(4096),    // Medium volume (unique stacks)
            stack_samples: Vec::with_capacity(batch_size), // High volume
            network_interfaces: Vec::with_capacity(64), // Very low volume
            socket_connections: Vec::with_capacity(256), // Low volume
            clock_snapshots: Vec::with_capacity(16), // Very low volume
            // Writers start as None, created lazily
            process_writer: None,
            thread_writer: None,
            sched_slice_writer: None,
            thread_state_writer: None,
            irq_slice_writer: None,
            softirq_slice_writer: None,
            wakeup_new_writer: None,
            process_exit_writer: None,
            counter_writer: None,
            counter_track_writer: None,
            slice_writer: None,
            track_writer: None,
            instant_writer: None,
            args_writer: None,
            instant_args_writer: None,
            stack_writer: None,
            stack_sample_writer: None,
            network_interface_writer: None,
            socket_connection_writer: None,
            clock_snapshot_writer: None,
            total_records: 0,
        })
    }

    /// Get the output directory.
    #[allow(dead_code)]
    pub fn output_dir(&self) -> &Path {
        &self.output_dir
    }

    /// Get the paths to all Parquet files.
    #[allow(dead_code)]
    pub fn paths(&self) -> &ParquetPaths {
        &self.paths
    }

    /// Get the total number of records written.
    #[allow(dead_code)]
    pub fn total_records(&self) -> usize {
        self.total_records
    }

    // Helper to check if a buffer needs flushing
    fn should_flush<T>(buffer: &[T], batch_size: usize) -> bool {
        buffer.len() >= batch_size
    }

    // Helper to create or get a writer
    fn get_or_create_writer<'a>(
        writer_opt: &'a mut Option<ArrowWriter<File>>,
        path: &Path,
        schema: Arc<Schema>,
        props: &WriterProperties,
    ) -> Result<&'a mut ArrowWriter<File>> {
        if writer_opt.is_none() {
            let file = File::create(path)
                .with_context(|| format!("Failed to create file: {}", path.display()))?;
            let writer =
                ArrowWriter::try_new(file, schema, Some(props.clone())).with_context(|| {
                    format!("Failed to create Parquet writer for: {}", path.display())
                })?;
            *writer_opt = Some(writer);
        }
        Ok(writer_opt.as_mut().unwrap())
    }

    // Flush processes buffer
    fn flush_processes(&mut self) -> Result<()> {
        if self.processes.is_empty() {
            return Ok(());
        }

        let schema = trace::process_schema();
        let writer = Self::get_or_create_writer(
            &mut self.process_writer,
            &self.paths.process,
            schema.clone(),
            &self.writer_props,
        )?;

        let batch = build_process_batch(&self.processes, &schema)?;
        writer.write(&batch)?;
        self.processes.clear();
        Ok(())
    }

    // Flush threads buffer
    fn flush_threads(&mut self) -> Result<()> {
        if self.threads.is_empty() {
            return Ok(());
        }

        let schema = trace::thread_schema();
        let writer = Self::get_or_create_writer(
            &mut self.thread_writer,
            &self.paths.thread,
            schema.clone(),
            &self.writer_props,
        )?;

        let batch = build_thread_batch(&self.threads, &schema)?;
        writer.write(&batch)?;
        self.threads.clear();
        Ok(())
    }

    // Flush sched_slices buffer
    fn flush_sched_slices(&mut self) -> Result<()> {
        if self.sched_slices.is_empty() {
            return Ok(());
        }

        let schema = trace::sched_slice_schema();
        let writer = Self::get_or_create_writer(
            &mut self.sched_slice_writer,
            &self.paths.sched_slice,
            schema.clone(),
            &self.writer_props,
        )?;

        let batch = build_sched_slice_batch(&self.sched_slices, &schema)?;
        writer.write(&batch)?;
        self.sched_slices.clear();
        Ok(())
    }

    // Flush thread_states buffer
    fn flush_thread_states(&mut self) -> Result<()> {
        if self.thread_states.is_empty() {
            return Ok(());
        }

        let schema = trace::thread_state_schema();
        let writer = Self::get_or_create_writer(
            &mut self.thread_state_writer,
            &self.paths.thread_state,
            schema.clone(),
            &self.writer_props,
        )?;

        let batch = build_thread_state_batch(&self.thread_states, &schema)?;
        writer.write(&batch)?;
        self.thread_states.clear();
        Ok(())
    }

    // Flush irq_slices buffer
    fn flush_irq_slices(&mut self) -> Result<()> {
        if self.irq_slices.is_empty() {
            return Ok(());
        }

        let schema = trace::irq_slice_schema();
        let writer = Self::get_or_create_writer(
            &mut self.irq_slice_writer,
            &self.paths.irq_slice,
            schema.clone(),
            &self.writer_props,
        )?;

        let batch = build_irq_slice_batch(&self.irq_slices, &schema)?;
        writer.write(&batch)?;
        self.irq_slices.clear();
        Ok(())
    }

    // Flush softirq_slices buffer
    fn flush_softirq_slices(&mut self) -> Result<()> {
        if self.softirq_slices.is_empty() {
            return Ok(());
        }

        let schema = trace::softirq_slice_schema();
        let writer = Self::get_or_create_writer(
            &mut self.softirq_slice_writer,
            &self.paths.softirq_slice,
            schema.clone(),
            &self.writer_props,
        )?;

        let batch = build_softirq_slice_batch(&self.softirq_slices, &schema)?;
        writer.write(&batch)?;
        self.softirq_slices.clear();
        Ok(())
    }

    // Flush wakeup_news buffer
    fn flush_wakeup_news(&mut self) -> Result<()> {
        if self.wakeup_news.is_empty() {
            return Ok(());
        }

        let schema = trace::wakeup_new_schema();
        let writer = Self::get_or_create_writer(
            &mut self.wakeup_new_writer,
            &self.paths.wakeup_new,
            schema.clone(),
            &self.writer_props,
        )?;

        let batch = build_wakeup_new_batch(&self.wakeup_news, &schema)?;
        writer.write(&batch)?;
        self.wakeup_news.clear();
        Ok(())
    }

    // Flush process_exits buffer
    fn flush_process_exits(&mut self) -> Result<()> {
        if self.process_exits.is_empty() {
            return Ok(());
        }

        let schema = trace::process_exit_schema();
        let writer = Self::get_or_create_writer(
            &mut self.process_exit_writer,
            &self.paths.process_exit,
            schema.clone(),
            &self.writer_props,
        )?;

        let batch = build_process_exit_batch(&self.process_exits, &schema)?;
        writer.write(&batch)?;
        self.process_exits.clear();
        Ok(())
    }

    // Flush counters buffer
    fn flush_counters(&mut self) -> Result<()> {
        if self.counters.is_empty() {
            return Ok(());
        }

        let schema = trace::counter_schema();
        let writer = Self::get_or_create_writer(
            &mut self.counter_writer,
            &self.paths.counter,
            schema.clone(),
            &self.writer_props,
        )?;

        let batch = build_counter_batch(&self.counters, &schema)?;
        writer.write(&batch)?;
        self.counters.clear();
        Ok(())
    }

    // Flush counter_tracks buffer
    fn flush_counter_tracks(&mut self) -> Result<()> {
        if self.counter_tracks.is_empty() {
            return Ok(());
        }

        let schema = trace::counter_track_schema();
        let writer = Self::get_or_create_writer(
            &mut self.counter_track_writer,
            &self.paths.counter_track,
            schema.clone(),
            &self.writer_props,
        )?;

        let batch = build_counter_track_batch(&self.counter_tracks, &schema)?;
        writer.write(&batch)?;
        self.counter_tracks.clear();
        Ok(())
    }

    // Flush slices buffer
    fn flush_slices(&mut self) -> Result<()> {
        if self.slices.is_empty() {
            return Ok(());
        }

        let schema = trace::slice_schema();
        let writer = Self::get_or_create_writer(
            &mut self.slice_writer,
            &self.paths.slice,
            schema.clone(),
            &self.writer_props,
        )?;

        let batch = build_slice_batch(&self.slices, &schema)?;
        writer.write(&batch)?;
        self.slices.clear();
        Ok(())
    }

    // Flush tracks buffer
    fn flush_tracks(&mut self) -> Result<()> {
        if self.tracks.is_empty() {
            return Ok(());
        }

        let schema = trace::track_schema();
        let writer = Self::get_or_create_writer(
            &mut self.track_writer,
            &self.paths.track,
            schema.clone(),
            &self.writer_props,
        )?;

        let batch = build_track_batch(&self.tracks, &schema)?;
        writer.write(&batch)?;
        self.tracks.clear();
        Ok(())
    }

    // Flush instants buffer
    fn flush_instants(&mut self) -> Result<()> {
        if self.instants.is_empty() {
            return Ok(());
        }

        let schema = trace::instant_schema();
        let writer = Self::get_or_create_writer(
            &mut self.instant_writer,
            &self.paths.instant,
            schema.clone(),
            &self.writer_props,
        )?;

        let batch = build_instant_batch(&self.instants, &schema)?;
        writer.write(&batch)?;
        self.instants.clear();
        Ok(())
    }

    // Flush args buffer
    fn flush_args(&mut self) -> Result<()> {
        if self.args.is_empty() {
            return Ok(());
        }

        let schema = trace::args_schema();
        let writer = Self::get_or_create_writer(
            &mut self.args_writer,
            &self.paths.args,
            schema.clone(),
            &self.writer_props,
        )?;

        let batch = build_arg_batch(&self.args, &schema)?;
        writer.write(&batch)?;
        self.args.clear();
        Ok(())
    }

    // Flush instant_args buffer
    fn flush_instant_args(&mut self) -> Result<()> {
        if self.instant_args.is_empty() {
            return Ok(());
        }

        let schema = trace::instant_args_schema();
        let writer = Self::get_or_create_writer(
            &mut self.instant_args_writer,
            &self.paths.instant_args,
            schema.clone(),
            &self.writer_props,
        )?;

        let batch = build_instant_arg_batch(&self.instant_args, &schema)?;
        writer.write(&batch)?;
        self.instant_args.clear();
        Ok(())
    }

    // Flush stacks buffer
    fn flush_stacks(&mut self) -> Result<()> {
        if self.stacks.is_empty() {
            return Ok(());
        }

        let schema = trace::stack_schema();
        let writer = Self::get_or_create_writer(
            &mut self.stack_writer,
            &self.paths.stack,
            schema.clone(),
            &self.writer_props,
        )?;

        let batch = build_stack_batch(&self.stacks, &schema)?;
        writer.write(&batch)?;
        self.stacks.clear();
        Ok(())
    }

    // Flush stack_samples buffer
    fn flush_stack_samples(&mut self) -> Result<()> {
        if self.stack_samples.is_empty() {
            return Ok(());
        }

        let schema = trace::stack_sample_schema();
        let writer = Self::get_or_create_writer(
            &mut self.stack_sample_writer,
            &self.paths.stack_sample,
            schema.clone(),
            &self.writer_props,
        )?;

        let batch = build_stack_sample_batch(&self.stack_samples, &schema)?;
        writer.write(&batch)?;
        self.stack_samples.clear();
        Ok(())
    }

    // Flush network_interfaces buffer
    fn flush_network_interfaces(&mut self) -> Result<()> {
        if self.network_interfaces.is_empty() {
            return Ok(());
        }

        let schema = trace::network_interface_schema();
        let writer = Self::get_or_create_writer(
            &mut self.network_interface_writer,
            &self.paths.network_interface,
            schema.clone(),
            &self.writer_props,
        )?;

        let batch = build_network_interface_batch(&self.network_interfaces, &schema)?;
        writer.write(&batch)?;
        self.network_interfaces.clear();
        Ok(())
    }

    // Flush socket_connections buffer
    fn flush_socket_connections(&mut self) -> Result<()> {
        if self.socket_connections.is_empty() {
            return Ok(());
        }

        let schema = trace::socket_connection_schema();
        let writer = Self::get_or_create_writer(
            &mut self.socket_connection_writer,
            &self.paths.socket_connection,
            schema.clone(),
            &self.writer_props,
        )?;

        let batch = build_socket_connection_batch(&self.socket_connections, &schema)?;
        writer.write(&batch)?;
        self.socket_connections.clear();
        Ok(())
    }

    // Flush clock_snapshots buffer
    fn flush_clock_snapshots(&mut self) -> Result<()> {
        if self.clock_snapshots.is_empty() {
            return Ok(());
        }

        let schema = trace::clock_snapshot_schema();
        let writer = Self::get_or_create_writer(
            &mut self.clock_snapshot_writer,
            &self.paths.clock_snapshot,
            schema.clone(),
            &self.writer_props,
        )?;

        let batch = build_clock_snapshot_batch(&self.clock_snapshots, &schema)?;
        writer.write(&batch)?;
        self.clock_snapshots.clear();
        Ok(())
    }

    // Close all writers, attempting to close all even if some fail
    fn close_writers(&mut self) -> Result<()> {
        let mut first_error: Option<anyhow::Error> = None;

        // Macro to close a writer and capture the first error
        macro_rules! close_writer {
            ($writer:expr) => {
                if let Some(w) = $writer.take() {
                    if let Err(e) = w.close() {
                        if first_error.is_none() {
                            first_error = Some(e.into());
                        }
                    }
                }
            };
        }

        close_writer!(self.process_writer);
        close_writer!(self.thread_writer);
        close_writer!(self.sched_slice_writer);
        close_writer!(self.thread_state_writer);
        close_writer!(self.irq_slice_writer);
        close_writer!(self.softirq_slice_writer);
        close_writer!(self.wakeup_new_writer);
        close_writer!(self.process_exit_writer);
        close_writer!(self.counter_writer);
        close_writer!(self.counter_track_writer);
        close_writer!(self.slice_writer);
        close_writer!(self.track_writer);
        close_writer!(self.instant_writer);
        close_writer!(self.args_writer);
        close_writer!(self.instant_args_writer);
        close_writer!(self.stack_writer);
        close_writer!(self.stack_sample_writer);
        close_writer!(self.network_interface_writer);
        close_writer!(self.socket_connection_writer);
        close_writer!(self.clock_snapshot_writer);

        match first_error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

impl Drop for StreamingParquetWriter {
    fn drop(&mut self) {
        // Check if any writers are still open (finish() was not called)
        let has_open_writers = self.process_writer.is_some()
            || self.thread_writer.is_some()
            || self.sched_slice_writer.is_some()
            || self.thread_state_writer.is_some()
            || self.irq_slice_writer.is_some()
            || self.softirq_slice_writer.is_some()
            || self.wakeup_new_writer.is_some()
            || self.process_exit_writer.is_some()
            || self.counter_writer.is_some()
            || self.counter_track_writer.is_some()
            || self.slice_writer.is_some()
            || self.track_writer.is_some()
            || self.instant_writer.is_some()
            || self.args_writer.is_some()
            || self.instant_args_writer.is_some()
            || self.stack_writer.is_some()
            || self.stack_sample_writer.is_some()
            || self.network_interface_writer.is_some()
            || self.socket_connection_writer.is_some()
            || self.clock_snapshot_writer.is_some();

        if has_open_writers {
            eprintln!(
                "Warning: StreamingParquetWriter dropped without calling finish(). \
                 Parquet files in {:?} may be incomplete or corrupted.",
                self.output_dir
            );
            // Attempt to close writers to at least flush pending data
            if let Err(e) = self.close_writers() {
                eprintln!("Error closing writers during drop: {e}");
            }
        }
    }
}

impl RecordCollector for StreamingParquetWriter {
    fn add_process(&mut self, record: ProcessRecord) -> Result<()> {
        self.processes.push(record);
        self.total_records += 1;
        if Self::should_flush(&self.processes, self.batch_size) {
            self.flush_processes()?;
        }
        Ok(())
    }

    fn add_thread(&mut self, record: ThreadRecord) -> Result<()> {
        self.threads.push(record);
        self.total_records += 1;
        if Self::should_flush(&self.threads, self.batch_size) {
            self.flush_threads()?;
        }
        Ok(())
    }

    fn add_sched_slice(&mut self, record: SchedSliceRecord) -> Result<()> {
        self.sched_slices.push(record);
        self.total_records += 1;
        if Self::should_flush(&self.sched_slices, self.batch_size) {
            self.flush_sched_slices()?;
        }
        Ok(())
    }

    fn add_thread_state(&mut self, record: ThreadStateRecord) -> Result<()> {
        self.thread_states.push(record);
        self.total_records += 1;
        if Self::should_flush(&self.thread_states, self.batch_size) {
            self.flush_thread_states()?;
        }
        Ok(())
    }

    fn add_irq_slice(&mut self, record: IrqSliceRecord) -> Result<()> {
        self.irq_slices.push(record);
        self.total_records += 1;
        if Self::should_flush(&self.irq_slices, self.batch_size) {
            self.flush_irq_slices()?;
        }
        Ok(())
    }

    fn add_softirq_slice(&mut self, record: SoftirqSliceRecord) -> Result<()> {
        self.softirq_slices.push(record);
        self.total_records += 1;
        if Self::should_flush(&self.softirq_slices, self.batch_size) {
            self.flush_softirq_slices()?;
        }
        Ok(())
    }

    fn add_wakeup_new(&mut self, record: WakeupNewRecord) -> Result<()> {
        self.wakeup_news.push(record);
        self.total_records += 1;
        if Self::should_flush(&self.wakeup_news, self.batch_size) {
            self.flush_wakeup_news()?;
        }
        Ok(())
    }

    fn add_process_exit(&mut self, record: ProcessExitRecord) -> Result<()> {
        self.process_exits.push(record);
        self.total_records += 1;
        if Self::should_flush(&self.process_exits, self.batch_size) {
            self.flush_process_exits()?;
        }
        Ok(())
    }

    fn add_counter(&mut self, record: CounterRecord) -> Result<()> {
        self.counters.push(record);
        self.total_records += 1;
        if Self::should_flush(&self.counters, self.batch_size) {
            self.flush_counters()?;
        }
        Ok(())
    }

    fn add_counter_track(&mut self, record: CounterTrackRecord) -> Result<()> {
        self.counter_tracks.push(record);
        self.total_records += 1;
        if Self::should_flush(&self.counter_tracks, self.batch_size) {
            self.flush_counter_tracks()?;
        }
        Ok(())
    }

    fn add_slice(&mut self, record: SliceRecord) -> Result<()> {
        self.slices.push(record);
        self.total_records += 1;
        if Self::should_flush(&self.slices, self.batch_size) {
            self.flush_slices()?;
        }
        Ok(())
    }

    fn add_track(&mut self, record: TrackRecord) -> Result<()> {
        self.tracks.push(record);
        self.total_records += 1;
        if Self::should_flush(&self.tracks, self.batch_size) {
            self.flush_tracks()?;
        }
        Ok(())
    }

    fn add_instant(&mut self, record: InstantRecord) -> Result<()> {
        self.instants.push(record);
        self.total_records += 1;
        if Self::should_flush(&self.instants, self.batch_size) {
            self.flush_instants()?;
        }
        Ok(())
    }

    fn add_arg(&mut self, record: ArgRecord) -> Result<()> {
        self.args.push(record);
        self.total_records += 1;
        if Self::should_flush(&self.args, self.batch_size) {
            self.flush_args()?;
        }
        Ok(())
    }

    fn add_instant_arg(&mut self, record: InstantArgRecord) -> Result<()> {
        self.instant_args.push(record);
        self.total_records += 1;
        if Self::should_flush(&self.instant_args, self.batch_size) {
            self.flush_instant_args()?;
        }
        Ok(())
    }

    fn add_stack(&mut self, record: StackRecord) -> Result<()> {
        self.stacks.push(record);
        self.total_records += 1;
        if Self::should_flush(&self.stacks, self.batch_size) {
            self.flush_stacks()?;
        }
        Ok(())
    }

    fn add_stack_sample(&mut self, record: StackSampleRecord) -> Result<()> {
        self.stack_samples.push(record);
        self.total_records += 1;
        if Self::should_flush(&self.stack_samples, self.batch_size) {
            self.flush_stack_samples()?;
        }
        Ok(())
    }

    fn add_network_interface(&mut self, record: NetworkInterfaceRecord) -> Result<()> {
        self.network_interfaces.push(record);
        self.total_records += 1;
        if Self::should_flush(&self.network_interfaces, self.batch_size) {
            self.flush_network_interfaces()?;
        }
        Ok(())
    }

    fn add_socket_connection(&mut self, record: SocketConnectionRecord) -> Result<()> {
        self.socket_connections.push(record);
        self.total_records += 1;
        if Self::should_flush(&self.socket_connections, self.batch_size) {
            self.flush_socket_connections()?;
        }
        Ok(())
    }

    fn add_clock_snapshot(&mut self, record: ClockSnapshotRecord) -> Result<()> {
        self.clock_snapshots.push(record);
        self.total_records += 1;
        if Self::should_flush(&self.clock_snapshots, self.batch_size) {
            self.flush_clock_snapshots()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        self.flush_processes()?;
        self.flush_threads()?;
        self.flush_sched_slices()?;
        self.flush_thread_states()?;
        self.flush_irq_slices()?;
        self.flush_softirq_slices()?;
        self.flush_wakeup_news()?;
        self.flush_process_exits()?;
        self.flush_counters()?;
        self.flush_counter_tracks()?;
        self.flush_slices()?;
        self.flush_tracks()?;
        self.flush_instants()?;
        self.flush_args()?;
        self.flush_instant_args()?;
        self.flush_stacks()?;
        self.flush_stack_samples()?;
        self.flush_network_interfaces()?;
        self.flush_socket_connections()?;
        self.flush_clock_snapshots()?;
        Ok(())
    }

    fn finish(mut self) -> Result<()> {
        // Flush any remaining buffered records, but ensure close_writers is called
        // even if flush fails to properly finalize/cleanup Parquet files
        let flush_result = self.flush();
        let close_result = self.close_writers();

        // Return first error encountered, but ensure both operations were attempted
        flush_result?;
        close_result
    }
}

// Helper functions to build RecordBatches from records

fn build_process_batch(records: &[ProcessRecord], schema: &Arc<Schema>) -> Result<RecordBatch> {
    let mut upid_builder = Int64Builder::with_capacity(records.len());
    let mut pid_builder = Int32Builder::with_capacity(records.len());
    let mut name_builder = StringBuilder::with_capacity(records.len(), records.len() * 32);
    let mut parent_upid_builder = Int64Builder::with_capacity(records.len());

    for record in records {
        upid_builder.append_value(record.upid);
        pid_builder.append_value(record.pid);
        name_builder.append_option(record.name.as_deref());
        parent_upid_builder.append_option(record.parent_upid);
    }

    Ok(RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(upid_builder.finish()),
            Arc::new(pid_builder.finish()),
            Arc::new(name_builder.finish()),
            Arc::new(parent_upid_builder.finish()),
        ],
    )?)
}

fn build_thread_batch(records: &[ThreadRecord], schema: &Arc<Schema>) -> Result<RecordBatch> {
    let mut utid_builder = Int64Builder::with_capacity(records.len());
    let mut tid_builder = Int32Builder::with_capacity(records.len());
    let mut name_builder = StringBuilder::with_capacity(records.len(), records.len() * 32);
    let mut upid_builder = Int64Builder::with_capacity(records.len());

    for record in records {
        utid_builder.append_value(record.utid);
        tid_builder.append_value(record.tid);
        name_builder.append_option(record.name.as_deref());
        upid_builder.append_option(record.upid);
    }

    Ok(RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(utid_builder.finish()),
            Arc::new(tid_builder.finish()),
            Arc::new(name_builder.finish()),
            Arc::new(upid_builder.finish()),
        ],
    )?)
}

fn build_sched_slice_batch(
    records: &[SchedSliceRecord],
    schema: &Arc<Schema>,
) -> Result<RecordBatch> {
    let mut ts_builder = Int64Builder::with_capacity(records.len());
    let mut dur_builder = Int64Builder::with_capacity(records.len());
    let mut cpu_builder = Int32Builder::with_capacity(records.len());
    let mut utid_builder = Int64Builder::with_capacity(records.len());
    let mut end_state_builder = StringBuilder::with_capacity(records.len(), records.len() * 4);
    let mut priority_builder = Int32Builder::with_capacity(records.len());

    for record in records {
        ts_builder.append_value(record.ts);
        dur_builder.append_value(record.dur);
        cpu_builder.append_value(record.cpu);
        utid_builder.append_value(record.utid);
        end_state_builder.append_option(record.end_state.as_deref());
        priority_builder.append_value(record.priority);
    }

    Ok(RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(ts_builder.finish()),
            Arc::new(dur_builder.finish()),
            Arc::new(cpu_builder.finish()),
            Arc::new(utid_builder.finish()),
            Arc::new(end_state_builder.finish()),
            Arc::new(priority_builder.finish()),
        ],
    )?)
}

fn build_thread_state_batch(
    records: &[ThreadStateRecord],
    schema: &Arc<Schema>,
) -> Result<RecordBatch> {
    let mut ts_builder = Int64Builder::with_capacity(records.len());
    let mut dur_builder = Int64Builder::with_capacity(records.len());
    let mut utid_builder = Int64Builder::with_capacity(records.len());
    let mut state_builder = StringBuilder::with_capacity(records.len(), records.len() * 4);
    let mut cpu_builder = Int32Builder::with_capacity(records.len());

    for record in records {
        ts_builder.append_value(record.ts);
        dur_builder.append_value(record.dur);
        utid_builder.append_value(record.utid);
        state_builder.append_value(&record.state);
        cpu_builder.append_option(record.cpu);
    }

    Ok(RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(ts_builder.finish()),
            Arc::new(dur_builder.finish()),
            Arc::new(utid_builder.finish()),
            Arc::new(state_builder.finish()),
            Arc::new(cpu_builder.finish()),
        ],
    )?)
}

fn build_irq_slice_batch(records: &[IrqSliceRecord], schema: &Arc<Schema>) -> Result<RecordBatch> {
    let mut ts_builder = Int64Builder::with_capacity(records.len());
    let mut dur_builder = Int64Builder::with_capacity(records.len());
    let mut cpu_builder = Int32Builder::with_capacity(records.len());
    let mut irq_builder = Int32Builder::with_capacity(records.len());
    let mut name_builder = StringBuilder::with_capacity(records.len(), records.len() * 32);
    let mut ret_builder = Int32Builder::with_capacity(records.len());

    for record in records {
        ts_builder.append_value(record.ts);
        dur_builder.append_value(record.dur);
        cpu_builder.append_value(record.cpu);
        irq_builder.append_value(record.irq);
        name_builder.append_option(record.name.as_deref());
        ret_builder.append_option(record.ret);
    }

    Ok(RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(ts_builder.finish()),
            Arc::new(dur_builder.finish()),
            Arc::new(cpu_builder.finish()),
            Arc::new(irq_builder.finish()),
            Arc::new(name_builder.finish()),
            Arc::new(ret_builder.finish()),
        ],
    )?)
}

fn build_softirq_slice_batch(
    records: &[SoftirqSliceRecord],
    schema: &Arc<Schema>,
) -> Result<RecordBatch> {
    let mut ts_builder = Int64Builder::with_capacity(records.len());
    let mut dur_builder = Int64Builder::with_capacity(records.len());
    let mut cpu_builder = Int32Builder::with_capacity(records.len());
    let mut vec_builder = Int32Builder::with_capacity(records.len());

    for record in records {
        ts_builder.append_value(record.ts);
        dur_builder.append_value(record.dur);
        cpu_builder.append_value(record.cpu);
        vec_builder.append_value(record.vec);
    }

    Ok(RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(ts_builder.finish()),
            Arc::new(dur_builder.finish()),
            Arc::new(cpu_builder.finish()),
            Arc::new(vec_builder.finish()),
        ],
    )?)
}

fn build_wakeup_new_batch(
    records: &[WakeupNewRecord],
    schema: &Arc<Schema>,
) -> Result<RecordBatch> {
    let mut ts_builder = Int64Builder::with_capacity(records.len());
    let mut cpu_builder = Int32Builder::with_capacity(records.len());
    let mut utid_builder = Int64Builder::with_capacity(records.len());
    let mut target_cpu_builder = Int32Builder::with_capacity(records.len());

    for record in records {
        ts_builder.append_value(record.ts);
        cpu_builder.append_value(record.cpu);
        utid_builder.append_value(record.utid);
        target_cpu_builder.append_value(record.target_cpu);
    }

    Ok(RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(ts_builder.finish()),
            Arc::new(cpu_builder.finish()),
            Arc::new(utid_builder.finish()),
            Arc::new(target_cpu_builder.finish()),
        ],
    )?)
}

fn build_process_exit_batch(
    records: &[ProcessExitRecord],
    schema: &Arc<Schema>,
) -> Result<RecordBatch> {
    let mut ts_builder = Int64Builder::with_capacity(records.len());
    let mut cpu_builder = Int32Builder::with_capacity(records.len());
    let mut utid_builder = Int64Builder::with_capacity(records.len());

    for record in records {
        ts_builder.append_value(record.ts);
        cpu_builder.append_value(record.cpu);
        utid_builder.append_value(record.utid);
    }

    Ok(RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(ts_builder.finish()),
            Arc::new(cpu_builder.finish()),
            Arc::new(utid_builder.finish()),
        ],
    )?)
}

fn build_counter_batch(records: &[CounterRecord], schema: &Arc<Schema>) -> Result<RecordBatch> {
    let mut ts_builder = Int64Builder::with_capacity(records.len());
    let mut track_id_builder = Int64Builder::with_capacity(records.len());
    let mut value_builder = Float64Builder::with_capacity(records.len());

    for record in records {
        ts_builder.append_value(record.ts);
        track_id_builder.append_value(record.track_id);
        value_builder.append_value(record.value);
    }

    Ok(RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(ts_builder.finish()),
            Arc::new(track_id_builder.finish()),
            Arc::new(value_builder.finish()),
        ],
    )?)
}

fn build_counter_track_batch(
    records: &[CounterTrackRecord],
    schema: &Arc<Schema>,
) -> Result<RecordBatch> {
    let mut id_builder = Int64Builder::with_capacity(records.len());
    let mut name_builder = StringBuilder::with_capacity(records.len(), records.len() * 32);
    let mut unit_builder = StringBuilder::with_capacity(records.len(), records.len() * 8);

    for record in records {
        id_builder.append_value(record.id);
        name_builder.append_value(&record.name);
        unit_builder.append_option(record.unit.as_deref());
    }

    Ok(RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(id_builder.finish()),
            Arc::new(name_builder.finish()),
            Arc::new(unit_builder.finish()),
        ],
    )?)
}

fn build_slice_batch(records: &[SliceRecord], schema: &Arc<Schema>) -> Result<RecordBatch> {
    let mut id_builder = Int64Builder::with_capacity(records.len());
    let mut ts_builder = Int64Builder::with_capacity(records.len());
    let mut dur_builder = Int64Builder::with_capacity(records.len());
    let mut track_id_builder = Int64Builder::with_capacity(records.len());
    let mut utid_builder = Int64Builder::with_capacity(records.len());
    let mut name_builder = StringBuilder::with_capacity(records.len(), records.len() * 32);
    let mut category_builder = StringBuilder::with_capacity(records.len(), records.len() * 16);
    let mut depth_builder = Int32Builder::with_capacity(records.len());

    for record in records {
        id_builder.append_value(record.id);
        ts_builder.append_value(record.ts);
        dur_builder.append_value(record.dur);
        track_id_builder.append_value(record.track_id);
        utid_builder.append_option(record.utid);
        name_builder.append_value(&record.name);
        category_builder.append_option(record.category.as_deref());
        depth_builder.append_value(record.depth);
    }

    Ok(RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(id_builder.finish()),
            Arc::new(ts_builder.finish()),
            Arc::new(dur_builder.finish()),
            Arc::new(track_id_builder.finish()),
            Arc::new(utid_builder.finish()),
            Arc::new(name_builder.finish()),
            Arc::new(category_builder.finish()),
            Arc::new(depth_builder.finish()),
        ],
    )?)
}

fn build_track_batch(records: &[TrackRecord], schema: &Arc<Schema>) -> Result<RecordBatch> {
    let mut id_builder = Int64Builder::with_capacity(records.len());
    let mut name_builder = StringBuilder::with_capacity(records.len(), records.len() * 32);
    let mut parent_id_builder = Int64Builder::with_capacity(records.len());

    for record in records {
        id_builder.append_value(record.id);
        name_builder.append_value(&record.name);
        parent_id_builder.append_option(record.parent_id);
    }

    Ok(RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(id_builder.finish()),
            Arc::new(name_builder.finish()),
            Arc::new(parent_id_builder.finish()),
        ],
    )?)
}

fn build_instant_batch(records: &[InstantRecord], schema: &Arc<Schema>) -> Result<RecordBatch> {
    let mut id_builder = Int64Builder::with_capacity(records.len());
    let mut ts_builder = Int64Builder::with_capacity(records.len());
    let mut track_id_builder = Int64Builder::with_capacity(records.len());
    let mut utid_builder = Int64Builder::with_capacity(records.len());
    let mut name_builder = StringBuilder::with_capacity(records.len(), records.len() * 32);
    let mut category_builder = StringBuilder::with_capacity(records.len(), records.len() * 16);

    for record in records {
        id_builder.append_value(record.id);
        ts_builder.append_value(record.ts);
        track_id_builder.append_value(record.track_id);
        utid_builder.append_option(record.utid);
        name_builder.append_value(&record.name);
        category_builder.append_option(record.category.as_deref());
    }

    Ok(RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(id_builder.finish()),
            Arc::new(ts_builder.finish()),
            Arc::new(track_id_builder.finish()),
            Arc::new(utid_builder.finish()),
            Arc::new(name_builder.finish()),
            Arc::new(category_builder.finish()),
        ],
    )?)
}

fn build_arg_batch(records: &[ArgRecord], schema: &Arc<Schema>) -> Result<RecordBatch> {
    let mut slice_id_builder = Int64Builder::with_capacity(records.len());
    let mut key_builder = StringBuilder::with_capacity(records.len(), records.len() * 16);
    let mut int_value_builder = Int64Builder::with_capacity(records.len());
    let mut string_value_builder = StringBuilder::with_capacity(records.len(), records.len() * 32);
    let mut real_value_builder = Float64Builder::with_capacity(records.len());

    for record in records {
        slice_id_builder.append_value(record.slice_id);
        key_builder.append_value(&record.key);
        int_value_builder.append_option(record.int_value);
        string_value_builder.append_option(record.string_value.as_deref());
        real_value_builder.append_option(record.real_value);
    }

    Ok(RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(slice_id_builder.finish()),
            Arc::new(key_builder.finish()),
            Arc::new(int_value_builder.finish()),
            Arc::new(string_value_builder.finish()),
            Arc::new(real_value_builder.finish()),
        ],
    )?)
}

fn build_instant_arg_batch(
    records: &[InstantArgRecord],
    schema: &Arc<Schema>,
) -> Result<RecordBatch> {
    let mut instant_id_builder = Int64Builder::with_capacity(records.len());
    let mut key_builder = StringBuilder::with_capacity(records.len(), records.len() * 16);
    let mut int_value_builder = Int64Builder::with_capacity(records.len());
    let mut string_value_builder = StringBuilder::with_capacity(records.len(), records.len() * 32);
    let mut real_value_builder = Float64Builder::with_capacity(records.len());

    for record in records {
        instant_id_builder.append_value(record.instant_id);
        key_builder.append_value(&record.key);
        int_value_builder.append_option(record.int_value);
        string_value_builder.append_option(record.string_value.as_deref());
        real_value_builder.append_option(record.real_value);
    }

    Ok(RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(instant_id_builder.finish()),
            Arc::new(key_builder.finish()),
            Arc::new(int_value_builder.finish()),
            Arc::new(string_value_builder.finish()),
            Arc::new(real_value_builder.finish()),
        ],
    )?)
}

fn build_stack_batch(records: &[StackRecord], schema: &Arc<Schema>) -> Result<RecordBatch> {
    // Estimate average stack depth for capacity hints (typical stacks are 20-50 frames)
    const AVG_STACK_DEPTH: usize = 32;
    let estimated_total_frames = records.len() * AVG_STACK_DEPTH;

    let mut id_builder = Int64Builder::with_capacity(records.len());
    let mut frame_names_builder = ListBuilder::with_capacity(
        StringBuilder::with_capacity(estimated_total_frames, estimated_total_frames * 64),
        records.len(),
    );
    let mut depth_builder = Int32Builder::with_capacity(records.len());
    let mut leaf_name_builder = StringBuilder::with_capacity(records.len(), records.len() * 64);

    for record in records {
        id_builder.append_value(record.id);

        // Build frame_names list
        for name in &record.frame_names {
            frame_names_builder.values().append_value(name);
        }
        frame_names_builder.append(true);

        depth_builder.append_value(record.depth);
        leaf_name_builder.append_value(&record.leaf_name);
    }

    Ok(RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(id_builder.finish()),
            Arc::new(frame_names_builder.finish()),
            Arc::new(depth_builder.finish()),
            Arc::new(leaf_name_builder.finish()),
        ],
    )?)
}

fn build_stack_sample_batch(
    records: &[StackSampleRecord],
    schema: &Arc<Schema>,
) -> Result<RecordBatch> {
    let mut ts_builder = Int64Builder::with_capacity(records.len());
    let mut utid_builder = Int64Builder::with_capacity(records.len());
    let mut cpu_builder = Int32Builder::with_capacity(records.len());
    let mut stack_id_builder = Int64Builder::with_capacity(records.len());

    for record in records {
        ts_builder.append_value(record.ts);
        utid_builder.append_value(record.utid);
        cpu_builder.append_option(record.cpu);
        stack_id_builder.append_value(record.stack_id);
    }

    Ok(RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(ts_builder.finish()),
            Arc::new(utid_builder.finish()),
            Arc::new(cpu_builder.finish()),
            Arc::new(stack_id_builder.finish()),
        ],
    )?)
}

fn build_network_interface_batch(
    records: &[NetworkInterfaceRecord],
    schema: &Arc<Schema>,
) -> Result<RecordBatch> {
    let mut namespace_builder = StringBuilder::with_capacity(records.len(), records.len() * 32);
    let mut interface_name_builder =
        StringBuilder::with_capacity(records.len(), records.len() * 16);
    let mut ip_address_builder = StringBuilder::with_capacity(records.len(), records.len() * 45);
    let mut address_type_builder = StringBuilder::with_capacity(records.len(), records.len() * 4);

    for record in records {
        namespace_builder.append_value(&record.namespace);
        interface_name_builder.append_value(&record.interface_name);
        ip_address_builder.append_value(&record.ip_address);
        address_type_builder.append_value(&record.address_type);
    }

    Ok(RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(namespace_builder.finish()),
            Arc::new(interface_name_builder.finish()),
            Arc::new(ip_address_builder.finish()),
            Arc::new(address_type_builder.finish()),
        ],
    )?)
}

fn build_socket_connection_batch(
    records: &[SocketConnectionRecord],
    schema: &Arc<Schema>,
) -> Result<RecordBatch> {
    let mut socket_id_builder = Int64Builder::with_capacity(records.len());
    let mut track_id_builder = Int64Builder::with_capacity(records.len());
    let mut protocol_builder = StringBuilder::with_capacity(records.len(), records.len() * 3);
    let mut src_ip_builder = StringBuilder::with_capacity(records.len(), records.len() * 45);
    let mut src_port_builder = Int32Builder::with_capacity(records.len());
    let mut dest_ip_builder = StringBuilder::with_capacity(records.len(), records.len() * 45);
    let mut dest_port_builder = Int32Builder::with_capacity(records.len());
    let mut address_family_builder = StringBuilder::with_capacity(records.len(), records.len() * 4);

    for record in records {
        socket_id_builder.append_value(record.socket_id);
        track_id_builder.append_value(record.track_id);
        protocol_builder.append_value(&record.protocol);
        src_ip_builder.append_value(&record.src_ip);
        src_port_builder.append_value(record.src_port);
        dest_ip_builder.append_value(&record.dest_ip);
        dest_port_builder.append_value(record.dest_port);
        address_family_builder.append_value(&record.address_family);
    }

    Ok(RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(socket_id_builder.finish()),
            Arc::new(track_id_builder.finish()),
            Arc::new(protocol_builder.finish()),
            Arc::new(src_ip_builder.finish()),
            Arc::new(src_port_builder.finish()),
            Arc::new(dest_ip_builder.finish()),
            Arc::new(dest_port_builder.finish()),
            Arc::new(address_family_builder.finish()),
        ],
    )?)
}

fn build_clock_snapshot_batch(
    records: &[ClockSnapshotRecord],
    schema: &Arc<Schema>,
) -> Result<RecordBatch> {
    let mut clock_id_builder = Int32Builder::with_capacity(records.len());
    let mut clock_name_builder = StringBuilder::with_capacity(records.len(), records.len() * 16);
    let mut timestamp_ns_builder = Int64Builder::with_capacity(records.len());
    let mut is_primary_builder = BooleanBuilder::with_capacity(records.len());

    for record in records {
        clock_id_builder.append_value(record.clock_id);
        clock_name_builder.append_value(&record.clock_name);
        timestamp_ns_builder.append_value(record.timestamp_ns);
        is_primary_builder.append_value(record.is_primary);
    }

    Ok(RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(clock_id_builder.finish()),
            Arc::new(clock_name_builder.finish()),
            Arc::new(timestamp_ns_builder.finish()),
            Arc::new(is_primary_builder.finish()),
        ],
    )?)
}
