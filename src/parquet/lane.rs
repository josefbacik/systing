//! An encode lane: the parquet encode of one table, off the thread that
//! produces its rows.
//!
//! A `StreamingParquetWriter` flush used to build the arrow batch and run
//! `ArrowWriter::write` — definition levels, the column encodings and the
//! compression of every column — inline on the thread that called
//! `add_*`. For the `network_packet` table that thread is the packet
//! consumer: a 200,000-row flush cost it ≈140 ms during which every ring
//! poller sat blocked on a full channel, and those flushes were 83 % of
//! the consumer's time on a saturated host (the measurements are on the
//! PR that introduced this module). The lane moves the whole flush: the
//! producing thread hands the `Vec` of rows over a bounded channel and
//! returns; the lane thread builds the arrow batch in parallel slices and
//! fans the leaf columns out to a fixed set of column-encoder threads
//! through parquet's parallel column-writer API, closing a row group every
//! `row_group_rows` rows exactly where `ArrowWriter` closed one. The file
//! that results carries the same schema, encodings, compression, row-group
//! bounds and `ARROW:schema` metadata as the inline writer produced, so
//! every reader is unchanged.
//!
//! Errors surface on the next `push` after the lane thread stopped and on
//! `finish`, which also returns the first error any encoder hit. A writer
//! asks `stopped` before it buffers more rows for a lane, so a lane that
//! died refuses every later append at once instead of accepting rows that
//! its next flush would drop whole.

use std::any::Any;
use std::io::Write;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::Arc;
use std::thread::JoinHandle;

use anyhow::{anyhow, Context, Result};
use arrow::datatypes::SchemaRef;
use arrow::record_batch::RecordBatch;
use parquet::arrow::arrow_writer::{
    compute_leaves, get_column_writers, ArrowColumnChunk, ArrowColumnWriter, ArrowLeafColumn,
};
use parquet::arrow::{add_encoded_arrow_schema_to_metadata, ArrowSchemaConverter};
use parquet::file::properties::WriterProperties;
use parquet::file::writer::SerializedFileWriter;
use parquet::schema::types::SchemaDescriptor;

/// Builds the arrow batch for a slice of rows.
pub type BatchBuilder<R> = fn(&[R], &SchemaRef) -> Result<RecordBatch>;

/// Rewrites a flushed batch on the lane thread before it is built — the
/// per-batch sort a table wants for its delta encodings, which the inline
/// writer ran on the producing thread.
pub type BatchPrepare<R> = fn(&mut [R]);

/// Flushed row batches the producing thread may run ahead of the lane by
/// before its `push` blocks. Two 200,000-row batches of the widest record
/// are under 200 MB; the backpressure is the point — a lane that cannot
/// keep up shows as missed events in the trace, never as unbounded memory.
const LANE_QUEUE: usize = 2;

/// Leaf columns queued to one encoder thread before the lane thread blocks.
const LEAF_QUEUE: usize = 64;

/// Column-encoder threads for one lane on this host: one per sixteen CPUs,
/// two at least, eight at most (a table has a few dozen columns; past eight
/// encoders the batch build is the longer half).
pub fn encode_workers() -> usize {
    std::thread::available_parallelism()
        .map(|n| (n.get() / 16).clamp(2, 8))
        .unwrap_or(2)
}

/// One table's encode lane. Created on the table's first flush, finished
/// (or dropped, which finishes it) when the writer closes.
pub struct EncodeLane<R: Send + Sync + 'static> {
    table: String,
    tx: Option<SyncSender<Vec<R>>>,
    thread: Option<JoinHandle<Result<()>>>,
    /// The lane thread's outcome once joined: `finish` and a `push` after
    /// the lane stopped both report it.
    outcome: Option<Result<(), String>>,
}

impl<R: Send + Sync + 'static> EncodeLane<R> {
    /// Start the lane: the file writer, the arrow-to-parquet schema and the
    /// `ARROW:schema` metadata are set up on the lane thread exactly as
    /// `ArrowWriter::try_new` does. `prepare`, when given, runs over every
    /// batch on the lane thread before `build` sees it.
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        table: &str,
        out: Box<dyn Write + Send>,
        schema: SchemaRef,
        props: WriterProperties,
        prepare: Option<BatchPrepare<R>>,
        build: BatchBuilder<R>,
        workers: usize,
        row_group_rows: usize,
    ) -> Result<Self> {
        let (tx, rx) = sync_channel::<Vec<R>>(LANE_QUEUE);
        let name = format!("pq_{}", &table[..table.len().min(12)]);
        let table_name = table.to_string();
        let thread = std::thread::Builder::new()
            .name(name)
            .spawn(move || {
                run_lane(
                    &table_name,
                    rx,
                    out,
                    schema,
                    props,
                    prepare,
                    build,
                    workers.max(1),
                    row_group_rows.max(1),
                )
            })
            .with_context(|| format!("spawning the encode lane for table {table}"))?;
        Ok(Self {
            table: table.to_string(),
            tx: Some(tx),
            thread: Some(thread),
            outcome: None,
        })
    }

    /// Hand a flushed batch to the lane. Blocks while `LANE_QUEUE` batches
    /// are already queued; fails once the lane thread has stopped, with the
    /// error that stopped it.
    pub fn push(&mut self, rows: Vec<R>) -> Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let sent = match &self.tx {
            Some(tx) => tx.send(rows).is_ok(),
            None => false,
        };
        if sent {
            return Ok(());
        }
        // The receiver is gone: the lane thread exited. Its result says why.
        Err(self.stop_error())
    }

    /// Has the lane stopped taking batches? True once a `push` found the
    /// lane thread gone, and as soon as that thread has exited on its own —
    /// an encoder or sink error ends it before any `push` notices — so a
    /// writer that asks before buffering rows refuses them on the first
    /// append after the lane died, not on the flush that would have found
    /// out.
    pub fn stopped(&self) -> bool {
        self.tx.is_none() || self.thread.as_ref().is_none_or(|t| t.is_finished())
    }

    /// The error a stopped lane stopped on: the lane thread's own outcome,
    /// or, when it exited clean before the writer finished, that fact. Ends
    /// the lane (no batch is accepted after it) and joins the thread once.
    pub fn stop_error(&mut self) -> anyhow::Error {
        self.tx = None;
        match self.join() {
            Ok(()) => anyhow!(
                "encode lane for table {} stopped before the writer finished",
                self.table
            ),
            Err(e) => e,
        }
    }

    /// Close the lane: every queued batch is encoded, the row groups and the
    /// file are closed. Returns the first error the lane or an encoder hit.
    pub fn finish(mut self) -> Result<()> {
        self.tx = None;
        self.join()
    }

    /// Join the lane thread once; every later call repeats its outcome.
    fn join(&mut self) -> Result<()> {
        if let Some(thread) = self.thread.take() {
            let outcome = match thread.join() {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(format!("{e:#}")),
                Err(payload) => Err(format!(
                    "the lane thread panicked: {}",
                    panic_text(payload.as_ref())
                )),
            };
            self.outcome = Some(outcome);
        }
        match &self.outcome {
            Some(Ok(())) | None => Ok(()),
            Some(Err(text)) => Err(anyhow!("encode lane for table {}: {text}", self.table)),
        }
    }
}

/// The message a panic carried, when it was a string (`panic!("…")` and the
/// formatted form both are); a payload of another type reads as such.
fn panic_text(payload: &(dyn Any + Send)) -> String {
    if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_string()
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else {
        "a non-string panic payload".to_string()
    }
}

impl<R: Send + Sync + 'static> Drop for EncodeLane<R> {
    fn drop(&mut self) {
        if self.thread.is_some() {
            self.tx = None;
            if let Err(e) = self.join() {
                eprintln!(
                    "Error finishing the encode lane for table {}: {e}",
                    self.table
                );
            }
        }
    }
}

/// The lane thread: batches in, one parquet file out.
#[allow(clippy::too_many_arguments)]
fn run_lane<R: Send + Sync + 'static>(
    table: &str,
    rx: Receiver<Vec<R>>,
    out: Box<dyn Write + Send>,
    schema: SchemaRef,
    mut props: WriterProperties,
    prepare: Option<BatchPrepare<R>>,
    build: BatchBuilder<R>,
    workers: usize,
    row_group_rows: usize,
) -> Result<()> {
    add_encoded_arrow_schema_to_metadata(&schema, &mut props);
    let props = Arc::new(props);
    let parquet_schema = ArrowSchemaConverter::new()
        .with_coerce_types(props.coerce_types())
        .convert(&schema)
        .with_context(|| format!("converting the arrow schema of table {table}"))?;
    let mut file = SerializedFileWriter::new(out, parquet_schema.root_schema_ptr(), props.clone())
        .with_context(|| format!("opening the parquet file of table {table}"))?;

    let mut group: Option<RowGroup> = None;
    for mut rows in rx {
        if rows.is_empty() {
            continue;
        }
        if let Some(prepare) = prepare {
            prepare(&mut rows);
        }
        let batches = build_parallel(&rows, &schema, build, workers)?;
        drop(rows);
        // A row group closes at exactly `row_group_rows` rows, as
        // `ArrowWriter::write` closed it: a batch that would carry the open
        // group past the bound is written up to the bound, the group closed,
        // and the rest goes to the next one.
        for batch in &batches {
            let mut offset = 0;
            while offset < batch.num_rows() {
                if group.is_none() {
                    group = Some(RowGroup::open(
                        table,
                        &parquet_schema,
                        &props,
                        &schema,
                        workers,
                    )?);
                }
                let current = group.as_mut().expect("row group opened above");
                let room = row_group_rows.saturating_sub(current.rows).max(1);
                let take = room.min(batch.num_rows() - offset);
                let part = batch.slice(offset, take);
                if let Err(e) = current.write(&schema, &part) {
                    // A closed encoder channel means an encoder failed: its
                    // own error is the one to report, not the send that
                    // found it.
                    let failed = group.take().expect("row group open");
                    return Err(failed.abort().unwrap_or(e));
                }
                offset += take;
                if current.rows >= row_group_rows {
                    let closing = group.take().expect("row group open");
                    closing.close_into(&mut file)?;
                }
            }
        }
    }
    if let Some(closing) = group.take() {
        closing.close_into(&mut file)?;
    }
    file.close()
        .with_context(|| format!("closing the parquet file of table {table}"))?;
    Ok(())
}

/// Build the arrow batches for `rows` in `workers` slices at once.
fn build_parallel<R: Send + Sync>(
    rows: &[R],
    schema: &SchemaRef,
    build: BatchBuilder<R>,
    workers: usize,
) -> Result<Vec<RecordBatch>> {
    let chunk = rows.len().div_ceil(workers).max(1);
    if rows.len() <= chunk {
        return Ok(vec![build(rows, schema)?]);
    }
    std::thread::scope(|scope| {
        let handles: Vec<_> = rows
            .chunks(chunk)
            .map(|slice| scope.spawn(move || build(slice, schema)))
            .collect();
        // Every builder is joined before the first error is returned: a
        // thread the scope would join on its own after a panic makes the
        // scope panic in turn, and the builder's own message would be lost.
        let built: Vec<Result<RecordBatch>> = handles
            .into_iter()
            .map(|h| match h.join() {
                Ok(result) => result,
                Err(payload) => Err(anyhow!(
                    "a batch builder panicked: {}",
                    panic_text(payload.as_ref())
                )),
            })
            .collect();
        built.into_iter().collect()
    })
}

/// A column chunk tagged with its leaf index.
type IndexedChunk = (usize, ArrowColumnChunk);

/// One open row group: its leaf columns spread over the encoder threads.
/// Leaf `i` belongs to encoder `i % n`, which holds its writers in leaf
/// order, so the encoder finds it at `i / n`.
struct RowGroup {
    senders: Vec<SyncSender<(usize, ArrowLeafColumn)>>,
    handles: Vec<JoinHandle<Result<Vec<IndexedChunk>>>>,
    rows: usize,
}

impl RowGroup {
    fn open(
        table: &str,
        parquet_schema: &SchemaDescriptor,
        props: &Arc<WriterProperties>,
        schema: &SchemaRef,
        workers: usize,
    ) -> Result<Self> {
        let column_writers = get_column_writers(parquet_schema, props, schema)?;
        let n = workers.clamp(1, column_writers.len().max(1));
        let mut per_worker: Vec<Vec<ArrowColumnWriter>> = (0..n).map(|_| Vec::new()).collect();
        for (i, writer) in column_writers.into_iter().enumerate() {
            per_worker[i % n].push(writer);
        }
        let mut senders = Vec::with_capacity(n);
        let mut handles = Vec::with_capacity(n);
        for (k, writers) in per_worker.into_iter().enumerate() {
            let (tx, rx) = sync_channel::<(usize, ArrowLeafColumn)>(LEAF_QUEUE);
            let name = format!("pqc_{}_{k}", &table[..table.len().min(7)]);
            let handle = std::thread::Builder::new()
                .name(name)
                .spawn(move || encode_columns(writers, k, n, rx))
                .with_context(|| format!("spawning a column encoder for table {table}"))?;
            senders.push(tx);
            handles.push(handle);
        }
        Ok(Self {
            senders,
            handles,
            rows: 0,
        })
    }

    fn write(&mut self, schema: &SchemaRef, batch: &RecordBatch) -> Result<()> {
        let n = self.senders.len();
        let mut leaf = 0usize;
        for (field, column) in schema.fields().iter().zip(batch.columns()) {
            for levels in compute_leaves(field.as_ref(), column)? {
                self.senders[leaf % n]
                    .send((leaf, levels))
                    .map_err(|_| anyhow!("a column encoder stopped"))?;
                leaf += 1;
            }
        }
        self.rows += batch.num_rows();
        Ok(())
    }

    fn close_into<W: Write + Send>(self, file: &mut SerializedFileWriter<W>) -> Result<()> {
        drop(self.senders);
        let mut chunks: Vec<IndexedChunk> = Vec::new();
        for handle in self.handles {
            chunks.extend(handle.join().map_err(|payload| {
                anyhow!(
                    "a column encoder panicked: {}",
                    panic_text(payload.as_ref())
                )
            })??);
        }
        chunks.sort_by_key(|(i, _)| *i);
        let mut row_group = file.next_row_group()?;
        for (_, chunk) in chunks {
            chunk.append_to_row_group(&mut row_group)?;
        }
        row_group.close()?;
        Ok(())
    }

    /// Stop the encoders without writing the group: the first error one of
    /// them stopped on, if any.
    fn abort(self) -> Option<anyhow::Error> {
        drop(self.senders);
        self.handles
            .into_iter()
            .filter_map(|handle| match handle.join() {
                Ok(Ok(_)) => None,
                Ok(Err(e)) => Some(e),
                Err(payload) => Some(anyhow!(
                    "a column encoder panicked: {}",
                    panic_text(payload.as_ref())
                )),
            })
            .next()
    }
}

/// One encoder thread (the `k`-th of `workers`): writes the leaves it is
/// sent into its column writers, then closes them into column chunks
/// tagged with their leaf index so the row group can append them in
/// schema order.
fn encode_columns(
    mut writers: Vec<ArrowColumnWriter>,
    k: usize,
    workers: usize,
    rx: Receiver<(usize, ArrowLeafColumn)>,
) -> Result<Vec<IndexedChunk>> {
    for (leaf, levels) in rx {
        let slot = (leaf - k) / workers;
        let writer = writers
            .get_mut(slot)
            .ok_or_else(|| anyhow!("no column writer for leaf {leaf}"))?;
        writer.write(&levels)?;
    }
    writers
        .into_iter()
        .enumerate()
        .map(|(slot, writer)| Ok((k + slot * workers, writer.close()?)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow::array::{Int64Array, StringArray};
    use arrow::datatypes::{DataType, Field, Schema};
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    use std::fs::File;
    use tempfile::TempDir;

    #[derive(Clone)]
    struct Row {
        id: i64,
        name: &'static str,
    }

    fn schema() -> SchemaRef {
        Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int64, false),
            Field::new("name", DataType::Utf8, true),
        ]))
    }

    fn build(rows: &[Row], schema: &SchemaRef) -> Result<RecordBatch> {
        let ids = Int64Array::from_iter_values(rows.iter().map(|r| r.id));
        let names = StringArray::from_iter(rows.iter().map(|r| Some(r.name)));
        Ok(RecordBatch::try_new(
            schema.clone(),
            vec![Arc::new(ids), Arc::new(names)],
        )?)
    }

    fn read_back(path: &std::path::Path) -> (usize, Vec<i64>, usize) {
        let (ids, groups) = read_back_groups(path);
        (ids.len(), ids, groups.len())
    }

    /// The ids in file order and the row count of each row group.
    fn read_back_groups(path: &std::path::Path) -> (Vec<i64>, Vec<usize>) {
        let file = File::open(path).unwrap();
        let builder = ParquetRecordBatchReaderBuilder::try_new(file).unwrap();
        let metadata = builder.metadata().clone();
        let groups: Vec<usize> = (0..metadata.num_row_groups())
            .map(|i| usize::try_from(metadata.row_group(i).num_rows()).unwrap())
            .collect();
        let reader = builder.build().unwrap();
        let mut ids = Vec::new();
        for batch in reader {
            let batch = batch.unwrap();
            let col = batch
                .column(0)
                .as_any()
                .downcast_ref::<Int64Array>()
                .unwrap();
            ids.extend(col.iter().map(|v| v.unwrap()));
        }
        (ids, groups)
    }

    /// Rows pushed in several batches come back whole, in order, with the
    /// row groups closed at exactly the configured bound and the arrow
    /// schema carried in the file's metadata.
    #[test]
    fn round_trip_in_order_with_row_groups() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("t.parquet");
        let out: Box<dyn Write + Send> = Box::new(File::create(&path).unwrap());
        let props = WriterProperties::builder()
            .set_max_row_group_size(250)
            .build();
        let mut lane = EncodeLane::start("t", out, schema(), props, None, build, 3, 250).unwrap();
        for b in 0..7 {
            let rows: Vec<Row> = (0..100)
                .map(|i| Row {
                    id: b * 100 + i,
                    name: if i % 2 == 0 { "even" } else { "odd" },
                })
                .collect();
            lane.push(rows).unwrap();
        }
        lane.push(Vec::new()).unwrap();
        lane.finish().unwrap();

        let (ids, groups) = read_back_groups(&path);
        assert_eq!(ids.len(), 700);
        assert_eq!(ids, (0..700).collect::<Vec<i64>>());
        // 700 rows in 100-row batches with a 250-row bound: the batch that
        // reaches the bound is split there, so the groups hold exactly the
        // bound — 250, 250, 200 — as `ArrowWriter::write` would close them.
        assert_eq!(groups, [250, 250, 200]);
        let file = File::open(&path).unwrap();
        let builder = ParquetRecordBatchReaderBuilder::try_new(file).unwrap();
        assert_eq!(builder.schema().as_ref(), schema().as_ref());
    }

    /// One batch larger than the bound is split into full row groups and a
    /// remainder, still in order — the shape a 200,000-row flush takes at a
    /// small bound, and a 1,000,000-row bound takes at the crossing batch.
    #[test]
    fn a_batch_past_the_bound_is_split_into_exact_row_groups() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("s.parquet");
        let out: Box<dyn Write + Send> = Box::new(File::create(&path).unwrap());
        let props = WriterProperties::builder()
            .set_max_row_group_size(100)
            .build();
        let mut lane = EncodeLane::start("s", out, schema(), props, None, build, 4, 100).unwrap();
        let rows: Vec<Row> = (0..350).map(|i| Row { id: i, name: "r" }).collect();
        lane.push(rows).unwrap();
        // A second batch continues the open 50-row group up to its bound.
        let rows: Vec<Row> = (350..420).map(|i| Row { id: i, name: "r" }).collect();
        lane.push(rows).unwrap();
        lane.finish().unwrap();

        let (ids, groups) = read_back_groups(&path);
        assert_eq!(ids, (0..420).collect::<Vec<i64>>());
        assert_eq!(groups, [100, 100, 100, 100, 20]);
    }

    /// An empty lane still produces a well-formed file with no rows.
    #[test]
    fn empty_lane_writes_an_empty_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("e.parquet");
        let out: Box<dyn Write + Send> = Box::new(File::create(&path).unwrap());
        let lane = EncodeLane::start(
            "e",
            out,
            schema(),
            WriterProperties::default(),
            None,
            build,
            2,
            1000,
        )
        .unwrap();
        lane.finish().unwrap();
        let (n, _, groups) = read_back(&path);
        assert_eq!(n, 0);
        assert_eq!(groups, 0);
    }

    /// A sink that fails is reported by `finish`, not swallowed.
    #[test]
    fn a_failing_sink_surfaces_at_finish() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("disk gone"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let out: Box<dyn Write + Send> = Box::new(Broken);
        let mut lane = EncodeLane::start(
            "b",
            out,
            schema(),
            WriterProperties::default(),
            None,
            build,
            2,
            10,
        )
        .unwrap();
        let rows: Vec<Row> = (0..50).map(|i| Row { id: i, name: "x" }).collect();
        // The first push may be accepted (the write happens on the lane);
        // finish must fail either way.
        let _ = lane.push(rows);
        let err = lane.finish().unwrap_err();
        assert!(format!("{err:#}").contains("disk gone"), "{err:#}");
    }

    /// A lane whose thread died reads as stopped before any push finds out,
    /// and `stop_error` names the error it died on; a live lane does not.
    #[test]
    fn a_dead_lane_reads_stopped_and_names_its_error() {
        fn fail_build(_: &[Row], _: &SchemaRef) -> Result<RecordBatch> {
            Err(anyhow!("lane down"))
        }
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("d.parquet");
        let out: Box<dyn Write + Send> = Box::new(File::create(&path).unwrap());
        let mut lane = EncodeLane::start(
            "d",
            out,
            schema(),
            WriterProperties::default(),
            None,
            fail_build,
            2,
            10,
        )
        .unwrap();
        assert!(!lane.stopped(), "a fresh lane is live");
        let rows: Vec<Row> = (0..50).map(|i| Row { id: i, name: "x" }).collect();
        // The batch is accepted (the build happens on the lane), fails
        // there and ends the lane thread; the lane reads stopped once it
        // has, before any push has found the receiver gone.
        lane.push(rows).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while !lane.stopped() {
            assert!(
                std::time::Instant::now() < deadline,
                "the lane never stopped"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let err = lane.stop_error();
        assert!(format!("{err:#}").contains("lane down"), "{err:#}");
        assert!(lane.stopped());
        // Every later push is refused with the same error.
        let rows: Vec<Row> = (50..60).map(|i| Row { id: i, name: "x" }).collect();
        let err = lane.push(rows).unwrap_err();
        assert!(format!("{err:#}").contains("lane down"), "{err:#}");
        let err = lane.finish().unwrap_err();
        assert!(format!("{err:#}").contains("lane down"), "{err:#}");
    }

    /// A panic on the lane carries its message into the outcome instead of
    /// the fixed "panicked" text — whether the builder ran on the lane
    /// thread itself (a batch at most one chunk long) or on a scoped
    /// builder thread.
    #[test]
    fn a_builder_panic_carries_its_message() {
        fn boom(rows: &[Row], _: &SchemaRef) -> Result<RecordBatch> {
            panic!("builder boom on {} rows", rows.len())
        }
        for (workers, rows) in [(1usize, 20i64), (4, 200)] {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("b.parquet");
            let out: Box<dyn Write + Send> = Box::new(File::create(&path).unwrap());
            let mut lane = EncodeLane::start(
                "b",
                out,
                schema(),
                WriterProperties::default(),
                None,
                boom,
                workers,
                1000,
            )
            .unwrap();
            let batch: Vec<Row> = (0..rows).map(|i| Row { id: i, name: "x" }).collect();
            let _ = lane.push(batch);
            let err = lane.finish().unwrap_err();
            let text = format!("{err:#}");
            assert!(text.contains("builder boom on"), "{text}");
            assert!(text.contains("panicked"), "{text}");
        }
    }

    /// `prepare` runs on the lane thread over each batch before the build:
    /// rows pushed in reverse come out sorted, batch by batch.
    #[test]
    fn prepare_rewrites_each_batch_before_the_build() {
        fn sort_rows(rows: &mut [Row]) {
            rows.sort_unstable_by_key(|r| r.id);
        }
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("p.parquet");
        let out: Box<dyn Write + Send> = Box::new(File::create(&path).unwrap());
        let mut lane = EncodeLane::start(
            "p",
            out,
            schema(),
            WriterProperties::default(),
            Some(sort_rows),
            build,
            2,
            1000,
        )
        .unwrap();
        for b in 0..3 {
            let rows: Vec<Row> = (0..100)
                .rev()
                .map(|i| Row {
                    id: b * 100 + i,
                    name: "r",
                })
                .collect();
            lane.push(rows).unwrap();
        }
        lane.finish().unwrap();
        let (n, ids, _) = read_back(&path);
        assert_eq!(n, 300);
        assert_eq!(ids, (0..300).collect::<Vec<i64>>());
    }
}
