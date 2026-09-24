//! Turning a value record from the BPF side into `task_context` rows.
//!
//! A record is the tracer's own 32-byte head followed by the ABI part of a
//! thread's block exactly as it stood in the traced process (see
//! `crates/task-context/include/task_context.h`). Everything in the block
//! is untrusted input. This file walks it with its OWN constants, whatever
//! the block says about itself, keeps a name only if it is in the class the
//! library enforces, replaces what a trace must not carry in a string, and
//! counts everything it refuses. No byte of a process ever reaches a log
//! line from here: the counters have fixed names.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;

use crate::record::RecordCollector;
use crate::trace::TaskContextRecord;
use crate::utid::UtidGenerator;

// The reader's own copy of the ABI's numbers (task_context.h, version 1).
// A block that disagrees with them is refused, never believed.
pub(crate) const ABI_VERSION: u16 = 1;
pub(crate) const VALUE_MAX: usize = 256;
pub(crate) const NAME_MAX: usize = 32;
pub(crate) const SLOTS: usize = 8;
pub(crate) const BLOCK_MAGIC: u32 = 0x4258_4354; // "TCXB"
pub(crate) const BLOCK_HDR_SIZE: usize = 32;
pub(crate) const SLOT_SIZE: usize = 296;
pub(crate) const BLOCK_SIZE: usize = BLOCK_HDR_SIZE + SLOTS * SLOT_SIZE;

const BLOCK_SEQ_AT: usize = 8;
const BLOCK_MASK_AT: usize = 16;
const SLOT_TYPE_AT: usize = 0;
const SLOT_NAME_LEN_AT: usize = 1;
const SLOT_VALUE_LEN_AT: usize = 2;
const SLOT_NAME_AT: usize = 8;
const SLOT_VALUE_AT: usize = 40;
const TYPE_UNSET: u8 = 0;
const TYPE_U64: u8 = 1;
const TYPE_STRING: u8 = 2;
const SEQ_BUSY: u64 = 1;

/// `struct task_context_value_event` in `task_context_reader.bpf.h`: ts,
/// tgid, tid, id, cpu, image, then the block.
pub(crate) const RECORD_HEAD: usize = 32;
pub(crate) const RECORD_SIZE: usize = RECORD_HEAD + BLOCK_SIZE;

/// Threads whose last written id is remembered, to drop a record the BPF
/// side sent twice. Past this the table starts again; see `ValuesSink`.
const LAST_WRITTEN_MAX: usize = 1 << 20;

const _: () = assert!(BLOCK_SIZE == 2400);
const _: () = assert!(SLOT_VALUE_AT + VALUE_MAX == SLOT_SIZE);
const _: () = assert!(SLOT_NAME_AT + NAME_MAX == SLOT_VALUE_AT);

/// What the walk did and what it refused; printed once when a capture ends.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ValueCounters {
    /// Records taken off the ring.
    pub records: u64,
    /// Rows handed to the writer.
    pub rows: u64,
    /// A record for the (thread, id) already written: nothing written.
    pub duplicate_records: u64,
    /// Shorter than a record: nothing read from it.
    pub short_records: u64,
    /// Magic, version, header size or sequence word not what the head says.
    pub bad_blocks: u64,
    /// A slot whose mask bit and type disagree, or of an unknown type.
    pub bad_slots: u64,
    /// A name of length 0 or over 31, with a byte outside the class, or one
    /// the record already has.
    pub bad_names: u64,
    /// String values in which at least one byte was replaced.
    pub replaced_values: u64,
    /// Rows the writer refused.
    pub write_errors: u64,
}

impl ValueCounters {
    /// The counters as `name=value` pairs, zero ones left out.
    pub fn summary(&self) -> String {
        let pairs = [
            ("records", self.records),
            ("rows", self.rows),
            ("duplicate_records", self.duplicate_records),
            ("short_records", self.short_records),
            ("bad_blocks", self.bad_blocks),
            ("bad_slots", self.bad_slots),
            ("bad_names", self.bad_names),
            ("replaced_values", self.replaced_values),
            ("write_errors", self.write_errors),
        ];
        pairs
            .iter()
            .filter(|(_, count)| *count > 0)
            .map(|(name, count)| format!("{name}={count}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// One named value, as kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Value {
    U64(u64),
    Str(String),
}

/// A record after the walk: whose it is and the values that passed. (Rows are
/// keyed by the thread; the process id and `image`, which the head also
/// carries, are kept only to tell a record sent twice from another thread's or
/// another image's.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedRecord {
    pub ts: u64,
    pub tgid: u32,
    pub tid: u32,
    pub image: u32,
    pub id: u64,
    pub values: Vec<(String, Value)>,
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_ne_bytes([bytes[at], bytes[at + 1]])
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    let mut word = [0u8; 4];
    word.copy_from_slice(&bytes[at..at + 4]);
    u32::from_ne_bytes(word)
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    let mut word = [0u8; 8];
    word.copy_from_slice(&bytes[at..at + 8]);
    u64::from_ne_bytes(word)
}

/// The class the library enforces on a name, enforced again here because
/// the library is not the only thing that can write a process's memory.
fn name_byte_ok(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-')
}

/// A name of 1 to 31 bytes of the class, or `None`.
fn parse_name(slot: &[u8]) -> Option<String> {
    let length = slot[SLOT_NAME_LEN_AT] as usize;
    if length == 0 || length >= NAME_MAX {
        return None;
    }
    let bytes = &slot[SLOT_NAME_AT..SLOT_NAME_AT + length];
    if !bytes.iter().copied().all(name_byte_ok) {
        return None;
    }
    // Every byte is ASCII, so this cannot fail.
    String::from_utf8(bytes.to_vec()).ok()
}

/// A string value as a trace may carry it: bytes that are not valid UTF-8,
/// and the control ranges U+0000-U+001F and U+007F-U+009F, become U+FFFD.
/// The second part of the result says whether anything was replaced.
fn sanitize(bytes: &[u8]) -> (String, bool) {
    let lossy = String::from_utf8_lossy(bytes);
    let mut replaced = matches!(lossy, std::borrow::Cow::Owned(_));
    let mut kept = String::with_capacity(lossy.len());
    for character in lossy.chars() {
        let code = character as u32;
        if code <= 0x1f || (0x7f..=0x9f).contains(&code) {
            kept.push(char::REPLACEMENT_CHARACTER);
            replaced = true;
        } else {
            kept.push(character);
        }
    }
    (kept, replaced)
}

/// Walk one record. `None` when nothing of it can be used; the reason is in
/// `counters` either way.
pub(crate) fn parse_record(data: &[u8], counters: &mut ValueCounters) -> Option<ParsedRecord> {
    counters.records += 1;
    if data.len() < RECORD_SIZE {
        counters.short_records += 1;
        return None;
    }
    let ts = u64_at(data, 0);
    let tgid = u32_at(data, 8);
    let tid = u32_at(data, 12);
    let id = u64_at(data, 16);
    let image = u32_at(data, 28);
    let block = &data[RECORD_HEAD..RECORD_SIZE];

    // The BPF side checked all of this before it sent the record; a record
    // that fails here did not come from that code.
    let seq = u64_at(block, BLOCK_SEQ_AT);
    if u32_at(block, 0) != BLOCK_MAGIC
        || u16_at(block, 4) != ABI_VERSION
        || u16_at(block, 6) as usize != BLOCK_HDR_SIZE
        || id == 0
        || id & SEQ_BUSY != 0
        || seq != id
    {
        counters.bad_blocks += 1;
        return None;
    }

    let mask = u32_at(block, BLOCK_MASK_AT);
    let mut values = Vec::new();
    for index in 0..SLOTS {
        let at = BLOCK_HDR_SIZE + index * SLOT_SIZE;
        let slot = &block[at..at + SLOT_SIZE];
        let in_mask = (mask >> index) & 1 == 1;
        let kind = slot[SLOT_TYPE_AT];
        if !in_mask && kind == TYPE_UNSET {
            continue;
        }
        if !in_mask || (kind != TYPE_U64 && kind != TYPE_STRING) {
            counters.bad_slots += 1;
            continue;
        }
        let Some(name) = parse_name(slot) else {
            counters.bad_names += 1;
            continue;
        };
        // The library never sets a name twice; a block that does was not
        // written by it, and the table's rows are one per name.
        if values.iter().any(|(kept, _)| *kept == name) {
            counters.bad_names += 1;
            continue;
        }
        let value = if kind == TYPE_U64 {
            Value::U64(u64_at(slot, SLOT_VALUE_AT))
        } else {
            // value_len is a hint: never more than this reader's own bound.
            let length = (u16_at(slot, SLOT_VALUE_LEN_AT) as usize).min(VALUE_MAX);
            let (text, replaced) = sanitize(&slot[SLOT_VALUE_AT..SLOT_VALUE_AT + length]);
            if replaced {
                counters.replaced_values += 1;
            }
            Value::Str(text)
        };
        values.push((name, value));
    }
    Some(ParsedRecord {
        ts,
        tgid,
        tid,
        image,
        id,
        values,
    })
}

/// Where the rows go: the feature's own writer, so that the `task_context`
/// table has exactly one writer like every other table.
pub(crate) struct ValuesSink<C: RecordCollector> {
    writer: C,
    utids: Arc<UtidGenerator>,
    /// (tgid, tid) -> the id whose values were last written for it, and the
    /// image it was read in. A thread's ids never repeat except for the
    /// newest one sent again (the BPF side sends a record again when it could
    /// not note that it had), so this drops exactly those. The process is
    /// part of the key, and the image of the value, because a thread id the
    /// kernel reuses for a thread of another process, or an exec, starts
    /// again at the same first id, and that record must not be taken for a
    /// repeat. It is cleared when it reaches `LAST_WRITTEN_MAX` threads; one
    /// repeat may then get through.
    last_written: HashMap<(u32, u32), (u64, u32)>,
    counters: ValueCounters,
}

impl<C: RecordCollector> ValuesSink<C> {
    pub(crate) fn new(writer: C, utids: Arc<UtidGenerator>) -> Self {
        Self {
            writer,
            utids,
            last_written: HashMap::new(),
            counters: ValueCounters::default(),
        }
    }

    /// One record off the ring.
    pub(crate) fn handle(&mut self, data: &[u8]) {
        let Some(record) = parse_record(data, &mut self.counters) else {
            return;
        };
        let thread = (record.tgid, record.tid);
        let written = (record.id, record.image);
        if self.last_written.get(&thread) == Some(&written) {
            self.counters.duplicate_records += 1;
            return;
        }
        if self.last_written.len() >= LAST_WRITTEN_MAX {
            self.last_written.clear();
        }
        self.last_written.insert(thread, written);

        let utid = self.utids.get_or_create_utid(record.tid as i32);
        for (name, value) in record.values {
            let (value_u64, value_str) = match value {
                Value::U64(number) => (Some(number), None),
                Value::Str(text) => (None, Some(text)),
            };
            let row = TaskContextRecord {
                utid,
                id: record.id,
                ts: record.ts as i64,
                name,
                value_u64,
                value_str,
            };
            match self.writer.add_task_context(row) {
                Ok(()) => self.counters.rows += 1,
                Err(_) => self.counters.write_errors += 1,
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn counters(&self) -> &ValueCounters {
        &self.counters
    }

    #[cfg(test)]
    pub(crate) fn writer(&self) -> &C {
        &self.writer
    }

    /// Close the table's file and hand the counters back.
    pub(crate) fn finish(self) -> Result<ValueCounters> {
        self.writer.finish()?;
        Ok(self.counters)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::InMemoryCollector;

    /// A record as the BPF side would send it, built by hand: the head, a
    /// valid block header carrying `id`, and no slot set.
    fn empty_record(tgid: u32, tid: u32, id: u64) -> Vec<u8> {
        let mut data = vec![0u8; RECORD_SIZE];
        data[0..8].copy_from_slice(&1_000u64.to_ne_bytes());
        data[8..12].copy_from_slice(&tgid.to_ne_bytes());
        data[12..16].copy_from_slice(&tid.to_ne_bytes());
        data[16..24].copy_from_slice(&id.to_ne_bytes());
        let block = &mut data[RECORD_HEAD..];
        block[0..4].copy_from_slice(&BLOCK_MAGIC.to_ne_bytes());
        block[4..6].copy_from_slice(&ABI_VERSION.to_ne_bytes());
        block[6..8].copy_from_slice(&(BLOCK_HDR_SIZE as u16).to_ne_bytes());
        block[BLOCK_SEQ_AT..BLOCK_SEQ_AT + 8].copy_from_slice(&id.to_ne_bytes());
        data
    }

    /// Fill slot `index` and set its mask bit.
    fn set_slot(data: &mut [u8], index: usize, kind: u8, name: &[u8], value: &[u8]) {
        let block = &mut data[RECORD_HEAD..];
        let mask = u32_at(block, BLOCK_MASK_AT) | (1 << index);
        block[BLOCK_MASK_AT..BLOCK_MASK_AT + 4].copy_from_slice(&mask.to_ne_bytes());
        let at = BLOCK_HDR_SIZE + index * SLOT_SIZE;
        let slot = &mut block[at..at + SLOT_SIZE];
        slot[SLOT_TYPE_AT] = kind;
        slot[SLOT_NAME_LEN_AT] = name.len() as u8;
        let length: u16 = if kind == TYPE_U64 {
            8
        } else {
            value.len() as u16
        };
        slot[SLOT_VALUE_LEN_AT..SLOT_VALUE_LEN_AT + 2].copy_from_slice(&length.to_ne_bytes());
        let name_room = name.len().min(NAME_MAX);
        slot[SLOT_NAME_AT..SLOT_NAME_AT + name_room].copy_from_slice(&name[..name_room]);
        let value_room = value.len().min(VALUE_MAX);
        slot[SLOT_VALUE_AT..SLOT_VALUE_AT + value_room].copy_from_slice(&value[..value_room]);
    }

    const ID: u64 = (3 << 40) | 8;

    #[test]
    fn a_string_and_a_number_become_two_values() {
        let mut data = empty_record(100, 101, ID);
        set_slot(&mut data, 0, TYPE_STRING, b"request_id", b"abc-123");
        set_slot(
            &mut data,
            5,
            TYPE_U64,
            b"iteration_id",
            &42u64.to_ne_bytes(),
        );
        let mut counters = ValueCounters::default();
        let record = parse_record(&data, &mut counters).unwrap();
        assert_eq!(
            (record.ts, record.tgid, record.tid, record.id),
            (1_000, 100, 101, ID)
        );
        assert_eq!(
            record.values,
            vec![
                ("request_id".to_string(), Value::Str("abc-123".to_string())),
                ("iteration_id".to_string(), Value::U64(42)),
            ]
        );
        assert_eq!(
            counters,
            ValueCounters {
                records: 1,
                ..Default::default()
            }
        );
    }

    #[test]
    fn a_short_record_and_a_wrong_header_are_refused_and_counted() {
        let mut counters = ValueCounters::default();
        assert!(parse_record(&[0u8; RECORD_SIZE - 1], &mut counters).is_none());
        assert_eq!(counters.short_records, 1);

        // All zeros: what a failed copy leaves behind is never a block.
        assert!(parse_record(&[0u8; RECORD_SIZE], &mut counters).is_none());
        assert_eq!(counters.bad_blocks, 1);

        let good = empty_record(1, 2, ID);
        let mut wrong_version = good.clone();
        wrong_version[RECORD_HEAD + 4] = 2;
        assert!(parse_record(&wrong_version, &mut counters).is_none());
        let mut odd = empty_record(1, 2, ID | 1);
        assert!(parse_record(&odd, &mut counters).is_none());
        // The block's word must be the id the head carries.
        odd = empty_record(1, 2, ID);
        odd[16..24].copy_from_slice(&(ID + 2).to_ne_bytes());
        assert!(parse_record(&odd, &mut counters).is_none());
        assert_eq!(counters.bad_blocks, 4);
        assert_eq!(counters.records, 5);
        assert!(parse_record(&good, &mut counters).is_some());
    }

    #[test]
    fn lengths_are_bounded_by_this_readers_own_numbers() {
        let mut data = empty_record(1, 2, ID);
        let long = vec![b'x'; VALUE_MAX];
        set_slot(&mut data, 0, TYPE_STRING, b"full", &long);
        // A value_len past the field: clamped, not believed.
        let at = RECORD_HEAD + BLOCK_HDR_SIZE + SLOT_VALUE_LEN_AT;
        data[at..at + 2].copy_from_slice(&u16::MAX.to_ne_bytes());
        // A name_len of 32 would run into the value: refused.
        set_slot(&mut data, 1, TYPE_U64, b"n", &7u64.to_ne_bytes());
        data[RECORD_HEAD + BLOCK_HDR_SIZE + SLOT_SIZE + SLOT_NAME_LEN_AT] = NAME_MAX as u8;
        let mut counters = ValueCounters::default();
        let record = parse_record(&data, &mut counters).unwrap();
        assert_eq!(
            record.values,
            vec![("full".to_string(), Value::Str("x".repeat(VALUE_MAX)))]
        );
        assert_eq!(counters.bad_names, 1);
    }

    #[test]
    fn names_outside_the_class_are_refused() {
        for name in [
            &b"has space"[..],
            b"slash/",
            b"quote'",
            b"nul\0in",
            b"caf\xc3\xa9",
        ] {
            let mut data = empty_record(1, 2, ID);
            set_slot(&mut data, 0, TYPE_U64, name, &1u64.to_ne_bytes());
            let mut counters = ValueCounters::default();
            let record = parse_record(&data, &mut counters).unwrap();
            assert!(record.values.is_empty(), "{name:?}");
            assert_eq!(counters.bad_names, 1, "{name:?}");
        }
        let mut data = empty_record(1, 2, ID);
        set_slot(&mut data, 0, TYPE_U64, b"A-z_0.9:x", &1u64.to_ne_bytes());
        let mut counters = ValueCounters::default();
        assert_eq!(parse_record(&data, &mut counters).unwrap().values.len(), 1);
        // An empty name.
        set_slot(&mut data, 1, TYPE_U64, b"", &1u64.to_ne_bytes());
        assert_eq!(parse_record(&data, &mut counters).unwrap().values.len(), 1);
        assert_eq!(counters.bad_names, 1);
    }

    #[test]
    fn a_mask_and_a_type_that_disagree_are_refused() {
        let mut data = empty_record(1, 2, ID);
        set_slot(&mut data, 0, TYPE_U64, b"kept", &1u64.to_ne_bytes());
        // Slot 1: a type with no mask bit.
        set_slot(&mut data, 1, TYPE_U64, b"no_bit", &1u64.to_ne_bytes());
        // Slot 2: a mask bit with no type. Slot 3: an unknown type.
        set_slot(&mut data, 2, TYPE_UNSET, b"no_type", &[]);
        set_slot(&mut data, 3, 9, b"odd_type", &[]);
        let block = RECORD_HEAD + BLOCK_MASK_AT;
        let mask = u32_at(&data, block) & !(1 << 1);
        data[block..block + 4].copy_from_slice(&mask.to_ne_bytes());
        let mut counters = ValueCounters::default();
        let record = parse_record(&data, &mut counters).unwrap();
        assert_eq!(record.values, vec![("kept".to_string(), Value::U64(1))]);
        assert_eq!(counters.bad_slots, 3);
    }

    #[test]
    fn a_name_the_record_already_has_is_refused_and_counted() {
        let mut data = empty_record(1, 2, ID);
        set_slot(&mut data, 0, TYPE_U64, b"same", &1u64.to_ne_bytes());
        set_slot(&mut data, 1, TYPE_STRING, b"same", b"second");
        set_slot(&mut data, 2, TYPE_U64, b"other", &3u64.to_ne_bytes());
        let mut counters = ValueCounters::default();
        let record = parse_record(&data, &mut counters).unwrap();
        assert_eq!(
            record.values,
            vec![
                ("same".to_string(), Value::U64(1)),
                ("other".to_string(), Value::U64(3)),
            ]
        );
        assert_eq!(counters.bad_names, 1);
    }

    #[test]
    fn what_a_trace_must_not_carry_is_replaced() {
        let (text, replaced) = sanitize(b"plain text, 100%");
        assert_eq!((text.as_str(), replaced), ("plain text, 100%", false));
        let (text, replaced) = sanitize("caf\u{e9} \u{1f600}".as_bytes());
        assert_eq!((text.as_str(), replaced), ("caf\u{e9} \u{1f600}", false));
        // A line feed, an escape, a NUL, DEL and a C1 control.
        let (text, replaced) = sanitize("a\nb\x1bc\0d\x7fe\u{85}f".as_bytes());
        assert_eq!(
            text,
            "a\u{fffd}b\u{fffd}c\u{fffd}d\u{fffd}e\u{fffd}f".to_string()
        );
        assert!(replaced);
        // Bytes that are not UTF-8.
        let (text, replaced) = sanitize(b"ok\xff\xfeok");
        assert_eq!(text, "ok\u{fffd}\u{fffd}ok".to_string());
        assert!(replaced);

        let mut data = empty_record(1, 2, ID);
        set_slot(&mut data, 0, TYPE_STRING, b"v", b"a\nb");
        let mut counters = ValueCounters::default();
        parse_record(&data, &mut counters).unwrap();
        assert_eq!(counters.replaced_values, 1);
    }

    #[test]
    fn rows_carry_the_threads_utid_and_a_repeat_is_written_once() {
        let utids = Arc::new(UtidGenerator::new());
        let mut sink = ValuesSink::new(InMemoryCollector::new(), Arc::clone(&utids));
        let mut data = empty_record(100, 101, ID);
        set_slot(&mut data, 0, TYPE_STRING, b"request_id", b"abc");
        set_slot(&mut data, 1, TYPE_U64, b"iteration_id", &7u64.to_ne_bytes());
        sink.handle(&data);
        sink.handle(&data);
        // The next id of the same thread, one name cleared.
        let mut next = empty_record(100, 101, ID + 2);
        set_slot(&mut next, 1, TYPE_U64, b"iteration_id", &8u64.to_ne_bytes());
        sink.handle(&next);

        let utid = utids.get_or_create_utid(101);
        let rows = &sink.writer().data().task_contexts;
        assert_eq!(rows.len(), 3);
        assert!(rows.iter().all(|row| row.utid == utid && row.ts == 1_000));
        assert_eq!(
            (
                rows[0].id,
                rows[0].name.as_str(),
                rows[0].value_str.as_deref()
            ),
            (ID, "request_id", Some("abc"))
        );
        assert_eq!(
            (rows[1].id, rows[1].name.as_str(), rows[1].value_u64),
            (ID, "iteration_id", Some(7))
        );
        assert_eq!(
            (rows[2].id, rows[2].name.as_str(), rows[2].value_u64),
            (ID + 2, "iteration_id", Some(8))
        );
        assert_eq!(rows[1].value_str, None);
        let counters = sink.counters().clone();
        assert_eq!(
            (counters.records, counters.rows, counters.duplicate_records),
            (3, 3, 1)
        );
        assert_eq!(sink.finish().unwrap(), counters);
    }

    /// A thread id the kernel hands to a thread of another process, or a new
    /// image of the same one, starts at the same first id: its record is not a
    /// repeat of the earlier one.
    #[test]
    fn a_reused_thread_id_in_another_process_is_not_a_repeat() {
        let utids = Arc::new(UtidGenerator::new());
        let mut sink = ValuesSink::new(InMemoryCollector::new(), utids);
        let mut old = empty_record(100, 101, ID);
        set_slot(&mut old, 0, TYPE_STRING, b"request_id", b"first process");
        let mut reused = empty_record(200, 101, ID);
        set_slot(
            &mut reused,
            0,
            TYPE_STRING,
            b"request_id",
            b"second process",
        );
        sink.handle(&old);
        sink.handle(&reused);
        // The repeat of each is still one.
        sink.handle(&reused);
        sink.handle(&old);

        let values: Vec<_> = sink
            .writer()
            .data()
            .task_contexts
            .iter()
            .map(|row| row.value_str.clone().unwrap())
            .collect();
        assert_eq!(values, vec!["first process", "second process"]);
        assert_eq!(sink.counters().duplicate_records, 2);
    }

    /// An exec keeps the process id and the thread id, and the new image
    /// numbers its ids from the start: only the image tells its first record
    /// from a repeat of the old image's.
    #[test]
    fn a_new_image_of_the_same_thread_is_not_a_repeat() {
        let utids = Arc::new(UtidGenerator::new());
        let mut sink = ValuesSink::new(InMemoryCollector::new(), utids);
        let record = |image: u32, value: &[u8]| {
            let mut data = empty_record(100, 100, ID);
            data[28..32].copy_from_slice(&image.to_ne_bytes());
            set_slot(&mut data, 0, TYPE_STRING, b"request_id", value);
            data
        };
        let (before, after) = (
            record(0xa000, b"before exec"),
            record(0xb000, b"after exec"),
        );
        sink.handle(&before);
        sink.handle(&after);
        // A record sent twice is still one.
        sink.handle(&after);

        let values: Vec<_> = sink
            .writer()
            .data()
            .task_contexts
            .iter()
            .map(|row| row.value_str.clone().unwrap())
            .collect();
        assert_eq!(values, vec!["before exec", "after exec"]);
        assert_eq!(sink.counters().duplicate_records, 1);
    }

    /// What leaves the tracer is per slot: a slot that is set, and of a string
    /// the `value_len` bytes and no more. The block is copied whole out of the
    /// process, so whatever else lies in it must stop here.
    #[test]
    fn bytes_past_value_len_and_the_bytes_of_an_unset_slot_never_leave() {
        let mut data = empty_record(1, 2, ID);
        // A slot that held a longer string before: the old tail is still
        // there, past value_len.
        set_slot(&mut data, 0, TYPE_STRING, b"request_id", b"new");
        let value_at = RECORD_HEAD + BLOCK_HDR_SIZE + SLOT_VALUE_AT;
        data[value_at + 3..value_at + 15].copy_from_slice(b"OLD-SECRET-X");
        // A slot that was cleared without being wiped: no mask bit, no
        // type, a name and a value still in its bytes.
        let slot_1 = RECORD_HEAD + BLOCK_HDR_SIZE + SLOT_SIZE;
        data[slot_1 + SLOT_NAME_LEN_AT] = 5;
        data[slot_1 + SLOT_NAME_AT..slot_1 + SLOT_NAME_AT + 5].copy_from_slice(b"stale");
        data[slot_1 + SLOT_VALUE_AT..slot_1 + SLOT_VALUE_AT + 6].copy_from_slice(b"SECRET");
        // And bytes in a word no row is made from (the slot's reserved one).
        data[slot_1 + 4..slot_1 + 8].copy_from_slice(b"PADS");

        let mut sink = ValuesSink::new(InMemoryCollector::new(), Arc::new(UtidGenerator::new()));
        sink.handle(&data);
        let rows = &sink.writer().data().task_contexts;
        assert_eq!(rows.len(), 1);
        assert_eq!(
            (rows[0].name.as_str(), rows[0].value_str.as_deref()),
            ("request_id", Some("new"))
        );
        let everything = format!("{rows:?}");
        for never in ["SECRET", "stale", "PADS", "OLD"] {
            assert!(!everything.contains(never), "{never} left the tracer");
        }
        assert_eq!(sink.counters().bad_slots, 0);
    }

    #[test]
    fn the_summary_names_only_what_happened() {
        let counters = ValueCounters {
            records: 4,
            rows: 6,
            bad_names: 1,
            ..Default::default()
        };
        assert_eq!(counters.summary(), "records=4 rows=6 bad_names=1");
        assert_eq!(ValueCounters::default().summary(), "");
    }
}
