//! Label records off the BPF side's ring, as rows of the `go_labels` table.
//!
//! A record is one label set of one process (`struct
//! go_context_labels_event` in `bpf/go_context.bpf.h`): its id, a hash of
//! the copied labels, and up to eight labels, each a key and a value cut at
//! the BPF side's bounds. Keys and values are whatever the program set, and
//! are made safe to store the way `task_context` makes its values safe
//! (invalid UTF-8 and control characters replaced).

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::Result;

use crate::record::RecordCollector;
use crate::task_context::values::sanitize;
use crate::trace::GoLabelRecord;
use crate::utid::UtidGenerator;

/// The record's numbers, as `bpf/go_context.bpf.h` has them.
const LABELS: usize = 8;
const KEY_MAX: usize = 64;
const VALUE_MAX: usize = 128;
const HEAD: usize = 32;
const LABEL_SIZE: usize = 8 + KEY_MAX + VALUE_MAX;
pub(crate) const RECORD_SIZE: usize = HEAD + LABELS * LABEL_SIZE;

/// Sets remembered as written before the memory is let go; one repeat may
/// then get through.
const WRITTEN_MAX: usize = 1 << 16;

/// What the sink did; printed once when a capture ends.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LabelCounters {
    pub records: u64,
    pub rows: u64,
    /// A set this process had sent already (the BPF side's table of sent
    /// sets was full): nothing written.
    pub duplicate_records: u64,
    /// Shorter than a record, or claiming more labels than it holds.
    pub bad_records: u64,
    /// Keys or values in which at least one byte was replaced.
    pub replaced: u64,
    pub write_errors: u64,
}

impl LabelCounters {
    /// The counters as `name=value` pairs, zero ones left out.
    pub fn summary(&self) -> String {
        [
            ("records", self.records),
            ("rows", self.rows),
            ("duplicate_records", self.duplicate_records),
            ("bad_records", self.bad_records),
            ("replaced", self.replaced),
            ("write_errors", self.write_errors),
        ]
        .iter()
        .filter(|(_, count)| *count > 0)
        .map(|(name, count)| format!("{name}={count}"))
        .collect::<Vec<_>>()
        .join(" ")
    }
}

/// One record, read: (ts, tgid, image, id, labels).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ParsedRecord {
    pub ts: u64,
    pub tgid: u32,
    pub image: u32,
    pub id: u64,
    pub labels: Vec<(String, String)>,
    pub replaced: bool,
}

fn word<const N: usize>(data: &[u8], at: usize) -> [u8; N] {
    data[at..at + N].try_into().unwrap()
}

pub(crate) fn parse_record(data: &[u8]) -> Option<ParsedRecord> {
    if data.len() < RECORD_SIZE {
        return None;
    }
    let count = u32::from_ne_bytes(word(data, 28)) as usize;
    if count > LABELS {
        return None;
    }
    let mut replaced = false;
    let mut labels = Vec::with_capacity(count);
    for i in 0..count {
        let label = &data[HEAD + i * LABEL_SIZE..HEAD + (i + 1) * LABEL_SIZE];
        let key_len = (u16::from_ne_bytes(word(label, 0)) as usize).min(KEY_MAX);
        let value_len = (u16::from_ne_bytes(word(label, 2)) as usize).min(VALUE_MAX);
        let (key, k) = sanitize(&label[8..8 + key_len]);
        let (value, v) = sanitize(&label[8 + KEY_MAX..8 + KEY_MAX + value_len]);
        replaced |= k || v;
        labels.push((key, value));
    }
    Some(ParsedRecord {
        ts: u64::from_ne_bytes(word(data, 0)),
        tgid: u32::from_ne_bytes(word(data, 8)),
        id: u64::from_ne_bytes(word(data, 16)),
        image: u32::from_ne_bytes(word(data, 24)),
        labels,
        replaced,
    })
}

/// Where the rows go: the feature's own writer, so that the `go_labels`
/// table has exactly one writer.
pub(crate) struct LabelsSink<C: RecordCollector> {
    writer: C,
    utids: Arc<UtidGenerator>,
    /// (process, image, set) already written. The BPF side sends a set once
    /// per process image while its own table has room; this keeps the table
    /// to one copy when it has not.
    written: HashSet<(u32, u32, u64)>,
    counters: LabelCounters,
}

impl<C: RecordCollector> LabelsSink<C> {
    pub(crate) fn new(writer: C, utids: Arc<UtidGenerator>) -> Self {
        Self {
            writer,
            utids,
            written: HashSet::new(),
            counters: LabelCounters::default(),
        }
    }

    /// One record off the ring.
    pub(crate) fn handle(&mut self, data: &[u8]) {
        self.counters.records += 1;
        let Some(record) = parse_record(data) else {
            self.counters.bad_records += 1;
            return;
        };
        if self.written.len() >= WRITTEN_MAX {
            self.written.clear();
        }
        if !self.written.insert((record.tgid, record.image, record.id)) {
            self.counters.duplicate_records += 1;
            return;
        }
        if record.replaced {
            self.counters.replaced += 1;
        }
        let upid = self.utids.get_or_create_upid(record.tgid as i32);
        for (name, value_str) in record.labels {
            let row = GoLabelRecord {
                upid,
                id: record.id,
                ts: record.ts as i64,
                name,
                value_str,
            };
            match self.writer.add_go_label(row) {
                Ok(()) => self.counters.rows += 1,
                Err(_) => self.counters.write_errors += 1,
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn writer(&self) -> &C {
        &self.writer
    }

    /// Close the table's file and hand the counters back.
    pub(crate) fn finish(self) -> Result<LabelCounters> {
        self.writer.finish()?;
        Ok(self.counters)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::InMemoryCollector;

    fn record(tgid: u32, id: u64, labels: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut data = vec![0u8; RECORD_SIZE];
        data[0..8].copy_from_slice(&1000u64.to_ne_bytes());
        data[8..12].copy_from_slice(&tgid.to_ne_bytes());
        data[12..16].copy_from_slice(&(tgid + 1).to_ne_bytes());
        data[16..24].copy_from_slice(&id.to_ne_bytes());
        data[24..28].copy_from_slice(&7u32.to_ne_bytes());
        data[28..32].copy_from_slice(&(labels.len() as u32).to_ne_bytes());
        for (i, (k, v)) in labels.iter().enumerate() {
            let at = HEAD + i * LABEL_SIZE;
            data[at..at + 2].copy_from_slice(&(k.len() as u16).to_ne_bytes());
            data[at + 2..at + 4].copy_from_slice(&(v.len() as u16).to_ne_bytes());
            data[at + 8..at + 8 + k.len()].copy_from_slice(k);
            data[at + 8 + KEY_MAX..at + 8 + KEY_MAX + v.len()].copy_from_slice(v);
        }
        data
    }

    #[test]
    fn a_set_becomes_a_row_per_label_once_per_process() {
        let utids = Arc::new(UtidGenerator::new());
        let mut sink = LabelsSink::new(InMemoryCollector::new(), Arc::clone(&utids));
        let set = record(42, 0xabc, &[(b"route", b"/v1/x"), (b"worker", b"hash")]);
        sink.handle(&set);
        sink.handle(&set);
        // The same set in another process is that process's.
        sink.handle(&record(
            43,
            0xabc,
            &[(b"route", b"/v1/x"), (b"worker", b"hash")],
        ));
        let rows = &sink.writer().data().go_labels;
        assert_eq!(rows.len(), 4);
        assert_eq!(rows[0].name, "route");
        assert_eq!(rows[1].value_str, "hash");
        assert_eq!(rows[0].upid, utids.get_or_create_upid(42));
        assert_ne!(rows[2].upid, rows[0].upid);
        assert_eq!(sink.counters.duplicate_records, 1);
    }

    #[test]
    fn what_a_trace_must_not_carry_is_replaced_and_bounds_hold() {
        let mut data = record(1, 1, &[(b"k\x1b", b"\xff")]);
        // A length past the bound reads no further than the bound.
        data[HEAD + 2..HEAD + 4].copy_from_slice(&u16::MAX.to_ne_bytes());
        let parsed = parse_record(&data).unwrap();
        assert!(parsed.replaced);
        assert_eq!(parsed.labels[0].0, "k\u{fffd}");
        assert_eq!(parsed.labels[0].1.chars().count(), VALUE_MAX);
        // More labels than a record holds, or a short record: refused.
        data[28..32].copy_from_slice(&9u32.to_ne_bytes());
        assert!(parse_record(&data).is_none());
        assert!(parse_record(&data[..RECORD_SIZE - 1]).is_none());
    }
}
