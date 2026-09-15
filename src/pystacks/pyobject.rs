/// Reading Python objects out of a process: a dict's items, an instance's
/// attributes, a string, an int.
///
/// The same shape as `linetable.rs`: the bytes are copied out of the process
/// (`process::ReadMemory`) and parsed here, with the layout taken from
/// `offsets::ObjectOffsets`. The process is running while it is read, so a
/// structure can be torn, resized or freed under the reader: every length is
/// bounded before it is used, and anything that does not add up is `None`,
/// never a panic. A caller retries later.
///
/// The dict is CPython's compact dict (3.6+; python-dev 2012-December/123028,
/// and the comments at the top of Objects/dictobject.c):
///
/// ```text
///   PyDictObject        ma_keys ──► PyDictKeysObject   header (dk_nentries, dk_kind, ...)
///                       ma_values                      dk_indices[]  sparse: the hash table,
///                          │                                         each slot an index into
///                          ▼                                         dk_entries, or empty
///                       PyDictValues                   dk_entries[]  dense, insertion order
/// ```
///
/// Looking a key up goes through the hash table; iterating does not. It walks
/// `dk_entries[0..dk_nentries)` and skips the holes deletions leave (an entry
/// whose value is NULL), which is all this reader does: a lookup by name is an
/// iteration that compares keys, because the hash of a str is seeded per
/// process. An entry is (hash, key, value), or (key, value) when every key is
/// a str (`dk_kind` != 0). In a split table (`ma_values` != NULL: instances of
/// one class sharing their keys) the values are not in the entries but in the
/// dict's own PyDictValues, at the entry's index.
use super::offsets::ObjectOffsets;
use super::process::ReadMemory;
use std::cell::RefCell;
use std::collections::HashMap;

/// PyDictKeysObject.dk_kind: every key of the others is a str.
const DICT_KEYS_GENERAL: u8 = 0;

/// The most entries a dict is read for: 6 MB of entries. sys.modules has
/// thousands, `threading._active` one per thread.
const MAX_DICT_ENTRIES: usize = 1 << 18;
/// log2 of the most bytes an index table is taken to have: what a dict of
/// MAX_DICT_ENTRIES needs, with room to spare.
const MAX_LOG2_INDEX_BYTES: u8 = 24;
/// The most characters a string is read for.
const MAX_STR_CHARS: usize = 1024;

// PyTypeObject.tp_flags
const TPFLAGS_INLINE_VALUES: u64 = 1 << 2;
const TPFLAGS_MANAGED_DICT: u64 = 1 << 4;
const TPFLAGS_HEAPTYPE: u64 = 1 << 9;
const TPFLAGS_LONG_SUBCLASS: u64 = 1 << 24;
const TPFLAGS_UNICODE_SUBCLASS: u64 = 1 << 28;
const TPFLAGS_DICT_SUBCLASS: u64 = 1 << 29;

// PyASCIIObject.state, a bit field, so not something offsetof() can give:
// interned:2, kind:3, compact:1, ascii:1. The same in every GIL build from
// 3.8 to 3.14; a free-threaded build makes `interned` a byte of its own.
const STATE_KIND_SHIFT: u32 = 2;
const STATE_KIND_MASK: u32 = 7;
const STATE_COMPACT: u32 = 1 << 5;
const STATE_ASCII: u32 = 1 << 6;

// PyLongObject.long_value.lv_tag (3.12+): the sign in the low two bits (0
// positive, 1 zero, 2 negative), a reserved bit, then the number of 30-bit
// digits.
const LONG_SIGN_MASK: u64 = 3;
const LONG_SIGN_ZERO: u64 = 1;
const LONG_SIGN_NEGATIVE: u64 = 2;
const LONG_NON_SIZE_BITS: u32 = 3;
const LONG_SHIFT: u32 = 30;

/// (key, value): the addresses of a dict item's two objects.
pub type Item = (usize, usize);

fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_ne_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

fn usize_at(bytes: &[u8], at: usize) -> Option<usize> {
    u64_at(bytes, at).map(|v| v as usize)
}

/// A process's Python objects, read through `mem` with `offsets`' layout.
pub struct PyReader<'a, M: ReadMemory> {
    mem: &'a M,
    o: ObjectOffsets,
    /// tp_flags and tp_basicsize by type: there are few types, and every
    /// object has one.
    type_flags: RefCell<HashMap<usize, u64>>,
    type_basicsize: RefCell<HashMap<usize, usize>>,
}

impl<'a, M: ReadMemory> PyReader<'a, M> {
    pub fn new(mem: &'a M, offsets: ObjectOffsets) -> Self {
        Self {
            mem,
            o: offsets,
            type_flags: RefCell::new(HashMap::new()),
            type_basicsize: RefCell::new(HashMap::new()),
        }
    }

    fn flags_of_type(&self, tp: usize) -> Option<u64> {
        if let Some(flags) = self.type_flags.borrow().get(&tp) {
            return Some(*flags);
        }
        let flags = u64_at(&self.bytes(tp + self.o.type_flags, 8)?, 0)?;
        self.type_flags.borrow_mut().insert(tp, flags);
        Some(flags)
    }

    fn basicsize_of_type(&self, tp: usize) -> Option<usize> {
        if let Some(size) = self.type_basicsize.borrow().get(&tp) {
            return Some(*size);
        }
        let size = usize_at(&self.bytes(tp + self.o.type_basicsize, 8)?, 0)?;
        self.type_basicsize.borrow_mut().insert(tp, size);
        Some(size)
    }

    /// Whether the object whose header is `head` is of a type with `flag`:
    /// what is read is whatever a pointer led to, and an attribute can hold
    /// anything (`None`, say, where an int is expected).
    fn is_a(&self, head: &[u8], flag: u64) -> bool {
        usize_at(head, self.o.ob_type)
            .and_then(|tp| self.flags_of_type(tp))
            .is_some_and(|flags| flags & flag != 0)
    }

    fn bytes(&self, addr: usize, len: usize) -> Option<Vec<u8>> {
        if addr == 0 {
            return None;
        }
        let mut buf = vec![0u8; len];
        self.mem.read_exact_at(addr, &mut buf).then_some(buf)
    }

    /// The pointer stored at `addr`.
    pub fn ptr(&self, addr: usize) -> Option<usize> {
        usize_at(&self.bytes(addr, 8)?, 0)
    }

    /// A str's text. A str is "compact" (every str a program makes is): its
    /// characters follow its header, one, two or four bytes each.
    pub fn str(&self, addr: usize) -> Option<String> {
        let header = self.bytes(addr, self.o.ascii_size)?;
        if !self.is_a(&header, TPFLAGS_UNICODE_SUBCLASS) {
            return None;
        }
        let length = usize_at(&header, self.o.ascii_length)?;
        let state = u32::from_ne_bytes(
            header
                .get(self.o.ascii_state..self.o.ascii_state + 4)?
                .try_into()
                .ok()?,
        );
        if state & STATE_COMPACT == 0 || length > MAX_STR_CHARS {
            return None;
        }
        let kind = ((state >> STATE_KIND_SHIFT) & STATE_KIND_MASK) as usize;
        let ascii = state & STATE_ASCII != 0;
        // An ASCII str ends with its header; any other carries its UTF-8 form's
        // length and pointer before the characters.
        let data = if ascii {
            self.o.ascii_size
        } else {
            self.o.compact_unicode_size
        };
        if length == 0 {
            return Some(String::new());
        }
        let raw = self.bytes(addr + data, length.checked_mul(kind)?)?;
        Some(match kind {
            // Latin-1: a byte is its code point. (ASCII is the lower half.)
            1 => raw.iter().map(|&b| b as char).collect(),
            2 => {
                let units: Vec<u16> = raw
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_ne_bytes(*c))
                    .collect();
                String::from_utf16_lossy(&units)
            }
            4 => raw
                .as_chunks::<4>()
                .0
                .iter()
                .map(|c| {
                    char::from_u32(u32::from_ne_bytes(*c)).unwrap_or(char::REPLACEMENT_CHARACTER)
                })
                .collect(),
            _ => return None,
        })
    }

    /// An int's value, when it fits 60 bits (two digits): a thread id does.
    pub fn long(&self, addr: usize) -> Option<i64> {
        let head = self.bytes(addr, self.o.long_ob_digit + 8)?;
        if !self.is_a(&head, TPFLAGS_LONG_SUBCLASS) {
            return None;
        }
        let tag = u64_at(&head, self.o.long_lv_tag)?;
        if tag & LONG_SIGN_MASK == LONG_SIGN_ZERO {
            return Some(0);
        }
        let digits = (tag >> LONG_NON_SIZE_BITS) as usize;
        if digits == 0 || digits > 2 {
            return None;
        }
        let digit = |i: usize| {
            let at = self.o.long_ob_digit + i * 4;
            Some(u32::from_ne_bytes(head.get(at..at + 4)?.try_into().ok()?) as i64)
        };
        let mut value = digit(0)?;
        if digits == 2 {
            value |= digit(1)? << LONG_SHIFT;
        }
        Some(if tag & LONG_SIGN_MASK == LONG_SIGN_NEGATIVE {
            -value
        } else {
            value
        })
    }

    /// A dict's items in insertion order.
    pub fn dict_items(&self, dict: usize) -> Option<Vec<Item>> {
        let head = self.bytes(dict, self.o.dict_ma_values + 8)?;
        if !self.is_a(&head, TPFLAGS_DICT_SUBCLASS) {
            return None;
        }
        let keys = usize_at(&head, self.o.dict_ma_keys)?;
        // Split table: the values are in the dict's own array.
        let values = match usize_at(&head, self.o.dict_ma_values)? {
            0 => None,
            values => Some(values + self.o.values_values),
        };
        self.keys_items(keys, values)
    }

    /// The items of a keys object: its entries' own values, or, for a split
    /// table, those of the `values` array (a `PyObject *` per entry).
    fn keys_items(&self, keys: usize, values: Option<usize>) -> Option<Vec<Item>> {
        let header = self.bytes(keys, self.o.keys_indices)?;
        let log2_index_bytes = *header.get(self.o.keys_log2_index_bytes)?;
        let kind = *header.get(self.o.keys_kind)?;
        let nentries = usize_at(&header, self.o.keys_nentries)?;
        if log2_index_bytes > MAX_LOG2_INDEX_BYTES || nentries > MAX_DICT_ENTRIES {
            return None;
        }
        if nentries == 0 {
            return Some(Vec::new());
        }
        let (size, key_at, value_at) = if kind == DICT_KEYS_GENERAL {
            (
                self.o.key_entry_size,
                self.o.key_entry_key,
                self.o.key_entry_value,
            )
        } else {
            (
                self.o.unicode_entry_size,
                self.o.unicode_entry_key,
                self.o.unicode_entry_value,
            )
        };
        // The entries follow the index table: one read for all of them.
        let entries_addr = keys + self.o.keys_indices + (1usize << log2_index_bytes);
        let entries = self.bytes(entries_addr, nentries * size)?;
        let split = match values {
            Some(values) => Some(self.bytes(values, nentries * 8)?),
            None => None,
        };
        let mut items = Vec::with_capacity(nentries);
        for i in 0..nentries {
            let key = usize_at(&entries, i * size + key_at)?;
            let value = match &split {
                Some(values) => usize_at(values, i * 8)?,
                None => usize_at(&entries, i * size + value_at)?,
            };
            // A hole: a deleted item, or a shared key this instance has not set.
            if key != 0 && value != 0 {
                items.push((key, value));
            }
        }
        Some(items)
    }

    /// An instance's attributes: the items of its `__dict__`, which more
    /// often than not is no dict at all.
    ///
    /// A class written in Python has `Py_TPFLAGS_MANAGED_DICT`: a pointer ahead
    /// of the object is its dict once something has asked for one. Until then
    /// (`Py_TPFLAGS_INLINE_VALUES`, 3.13+) the values are an array that follows
    /// the object, as long as its `valid` byte says so, and the keys are the
    /// class's (`ht_cached_keys`), shared by its instances.
    pub fn instance_items(&self, obj: usize) -> Option<Vec<Item>> {
        let tp = self.ptr(obj + self.o.ob_type)?;
        let flags = self.flags_of_type(tp)?;
        if flags & TPFLAGS_MANAGED_DICT == 0 {
            // A dict pointer in the object itself, where the type says.
            let at = u64_at(&self.bytes(tp + self.o.type_dictoffset, 8)?, 0)? as i64;
            if at <= 0 {
                return None;
            }
            return match self.ptr(obj + at as usize)? {
                0 => Some(Vec::new()),
                dict => self.dict_items(dict),
            };
        }
        if flags & TPFLAGS_INLINE_VALUES != 0 && flags & TPFLAGS_HEAPTYPE != 0 {
            // 3.13 has them after a bare PyObject, 3.14 after whatever the
            // type's instances are: tp_basicsize is both.
            let basicsize = self.basicsize_of_type(tp)?;
            if !(16..=4096).contains(&basicsize) {
                return None;
            }
            let values = obj + basicsize;
            let valid = *self.bytes(values + self.o.values_valid, 1)?.first()?;
            if valid != 0 {
                let keys = self.ptr(tp + self.o.heap_type_cached_keys)?;
                return self.keys_items(keys, Some(values + self.o.values_values));
            }
        }
        match self.ptr(obj.checked_sub(self.o.managed_dict_before)?)? {
            0 => Some(Vec::new()),
            dict => self.dict_items(dict),
        }
    }

    /// The value of the item whose key is the str `name`.
    pub fn get(&self, items: &[Item], name: &str) -> Option<usize> {
        items
            .iter()
            .find(|(key, _)| self.str(*key).as_deref() == Some(name))
            .map(|&(_, value)| value)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::pystacks::offsets::object_offsets_for_version;
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    /// A made-up address space: objects are laid out at the addresses the
    /// builder hands out, and reads are served from them.
    #[derive(Default)]
    pub(crate) struct FakeMemory {
        bytes: RefCell<BTreeMap<usize, u8>>,
        next: RefCell<usize>,
    }

    impl ReadMemory for FakeMemory {
        fn read_exact_at(&self, addr: usize, buf: &mut [u8]) -> bool {
            let bytes = self.bytes.borrow();
            for (i, b) in buf.iter_mut().enumerate() {
                match bytes.get(&(addr + i)) {
                    Some(v) => *b = *v,
                    None => return false,
                }
            }
            true
        }
    }

    // The builtin types an object is checked against, by their flags.
    pub(crate) const STR_TYPE: usize = 0x1000;
    pub(crate) const INT_TYPE: usize = 0x2000;
    pub(crate) const DICT_TYPE: usize = 0x3000;
    pub(crate) const NONE_TYPE: usize = 0x4000;

    impl FakeMemory {
        pub(crate) fn new() -> Self {
            let mem = Self::default();
            *mem.next.borrow_mut() = 0x10_0000;
            let o = object_offsets_for_version(3, 13).unwrap();
            for (tp, flags) in [
                (STR_TYPE, TPFLAGS_UNICODE_SUBCLASS),
                (INT_TYPE, TPFLAGS_LONG_SUBCLASS),
                (DICT_TYPE, TPFLAGS_DICT_SUBCLASS),
                (NONE_TYPE, 0),
            ] {
                mem.write(tp, &vec![0; o.heap_type_cached_keys + 8]);
                mem.write_u64(tp + o.type_flags, flags);
            }
            mem
        }

        /// `None`: an object that is no str, int or dict.
        pub(crate) fn none(&self, o: &ObjectOffsets) -> usize {
            let addr = self.alloc(64);
            self.write_u64(addr + o.ob_type, NONE_TYPE as u64);
            addr
        }

        /// `len` zeroed bytes at a fresh address, `before` more ahead of it.
        pub(crate) fn alloc_with_prefix(&self, before: usize, len: usize) -> usize {
            let mut next = self.next.borrow_mut();
            let addr = *next + before;
            *next = (addr + len + 0x40) & !0xf;
            let mut bytes = self.bytes.borrow_mut();
            for a in addr - before..addr + len {
                bytes.insert(a, 0);
            }
            addr
        }

        pub(crate) fn alloc(&self, len: usize) -> usize {
            self.alloc_with_prefix(0, len)
        }

        pub(crate) fn write(&self, addr: usize, data: &[u8]) {
            let mut bytes = self.bytes.borrow_mut();
            for (i, b) in data.iter().enumerate() {
                bytes.insert(addr + i, *b);
            }
        }

        pub(crate) fn write_u64(&self, addr: usize, v: u64) {
            self.write(addr, &v.to_ne_bytes());
        }

        /// A compact str: ASCII, Latin-1, or wider, as its characters need.
        pub(crate) fn str(&self, o: &ObjectOffsets, text: &str) -> usize {
            let max = text.chars().map(|c| c as u32).max().unwrap_or(0);
            let (kind, ascii) = match max {
                0..=0x7f => (1u32, true),
                0x80..=0xff => (1, false),
                0x100..=0xffff => (2, false),
                _ => (4, false),
            };
            let data: Vec<u8> = match kind {
                1 => text.chars().map(|c| c as u8).collect(),
                2 => text
                    .chars()
                    .flat_map(|c| (c as u16).to_ne_bytes())
                    .collect(),
                _ => text
                    .chars()
                    .flat_map(|c| (c as u32).to_ne_bytes())
                    .collect(),
            };
            let header = if ascii {
                o.ascii_size
            } else {
                o.compact_unicode_size
            };
            let addr = self.alloc(header + data.len());
            self.write_u64(addr + o.ob_type, STR_TYPE as u64);
            self.write_u64(addr + o.ascii_length, text.chars().count() as u64);
            let state =
                (kind << STATE_KIND_SHIFT) | STATE_COMPACT | if ascii { STATE_ASCII } else { 0 };
            self.write(addr + o.ascii_state, &state.to_ne_bytes());
            self.write(addr + header, &data);
            addr
        }

        pub(crate) fn long(&self, o: &ObjectOffsets, value: i64) -> usize {
            let addr = self.alloc(o.long_ob_digit + 8);
            self.write_u64(addr + o.ob_type, INT_TYPE as u64);
            let magnitude = value.unsigned_abs();
            let digits = [
                (magnitude & ((1 << LONG_SHIFT) - 1)) as u32,
                (magnitude >> LONG_SHIFT) as u32,
            ];
            let ndigits = match magnitude {
                0 => 0u64,
                m if m < 1 << LONG_SHIFT => 1,
                _ => 2,
            };
            let sign = match value {
                0 => LONG_SIGN_ZERO,
                v if v < 0 => LONG_SIGN_NEGATIVE,
                _ => 0,
            };
            self.write_u64(addr + o.long_lv_tag, (ndigits << LONG_NON_SIZE_BITS) | sign);
            self.write(addr + o.long_ob_digit, &digits[0].to_ne_bytes());
            self.write(addr + o.long_ob_digit + 4, &digits[1].to_ne_bytes());
            addr
        }

        /// A keys object of `kind` with these entries (key, value; 0 for none)
        /// behind an index table of 8 bytes.
        pub(crate) fn keys(&self, o: &ObjectOffsets, kind: u8, entries: &[Item]) -> usize {
            let log2_index_bytes = 3u8;
            let size = if kind == DICT_KEYS_GENERAL {
                o.key_entry_size
            } else {
                o.unicode_entry_size
            };
            let index_bytes = 1usize << log2_index_bytes;
            let addr = self.alloc(o.keys_indices + index_bytes + entries.len() * size);
            self.write(addr + o.keys_log2_index_bytes, &[log2_index_bytes]);
            self.write(addr + o.keys_kind, &[kind]);
            self.write_u64(addr + o.keys_nentries, entries.len() as u64);
            // An index table that is not entries: all "empty" (-1).
            self.write(addr + o.keys_indices, &vec![0xff; index_bytes]);
            for (i, (key, value)) in entries.iter().enumerate() {
                let at = addr + o.keys_indices + index_bytes + i * size;
                let (key_at, value_at) = if kind == DICT_KEYS_GENERAL {
                    (o.key_entry_key, o.key_entry_value)
                } else {
                    (o.unicode_entry_key, o.unicode_entry_value)
                };
                self.write_u64(at + key_at, *key as u64);
                self.write_u64(at + value_at, *value as u64);
            }
            addr
        }

        /// A combined-table dict of these items.
        pub(crate) fn dict(&self, o: &ObjectOffsets, kind: u8, entries: &[Item]) -> usize {
            let keys = self.keys(o, kind, entries);
            let addr = self.alloc(o.dict_ma_values + 8);
            self.write_u64(addr + o.ob_type, DICT_TYPE as u64);
            self.write_u64(addr + o.dict_ma_keys, keys as u64);
            addr
        }

        /// A dict of str keys and these values.
        pub(crate) fn str_dict(&self, o: &ObjectOffsets, items: &[(&str, usize)]) -> usize {
            let entries: Vec<Item> = items
                .iter()
                .map(|(key, value)| (self.str(o, key), *value))
                .collect();
            self.dict(o, 1, &entries)
        }

        /// A heap type of `flags` whose instances are `basicsize` bytes and
        /// share `cached_keys`.
        pub(crate) fn heap_type(
            &self,
            o: &ObjectOffsets,
            flags: u64,
            basicsize: usize,
            cached_keys: usize,
        ) -> usize {
            let addr = self.alloc(o.heap_type_cached_keys + 8);
            self.write_u64(addr + o.type_flags, flags);
            self.write_u64(addr + o.type_basicsize, basicsize as u64);
            self.write_u64(addr + o.heap_type_cached_keys, cached_keys as u64);
            addr
        }

        /// An instance of `tp` with inline values (`valid` or not) and, ahead
        /// of it, its managed dict pointer.
        pub(crate) fn instance(
            &self,
            o: &ObjectOffsets,
            tp: usize,
            basicsize: usize,
            values: &[usize],
            valid: bool,
            dict: usize,
        ) -> usize {
            let inline = o.values_values + values.len() * 8;
            let addr = self.alloc_with_prefix(o.managed_dict_before + 8, basicsize + inline);
            self.write_u64(addr + o.ob_type, tp as u64);
            self.write_u64(addr - o.managed_dict_before, dict as u64);
            // The word ahead of that is the weakref list: never the values.
            self.write_u64(addr - o.managed_dict_before - 8, 0xdead_beef);
            self.write(addr + basicsize + o.values_valid, &[valid as u8]);
            for (i, value) in values.iter().enumerate() {
                self.write_u64(addr + basicsize + o.values_values + i * 8, *value as u64);
            }
            addr
        }
    }

    pub(crate) const INLINE_TYPE: u64 =
        TPFLAGS_MANAGED_DICT | TPFLAGS_INLINE_VALUES | TPFLAGS_HEAPTYPE;

    fn offsets() -> ObjectOffsets {
        object_offsets_for_version(3, 13).unwrap()
    }

    #[test]
    fn a_str_is_read_whatever_the_width_of_its_characters() {
        let (mem, o) = (FakeMemory::new(), offsets());
        let py = PyReader::new(&mem, o);
        for text in ["", "MainThread", "wörker-ü", "工作线程", "thread-🧵"] {
            assert_eq!(py.str(mem.str(&o, text)).as_deref(), Some(text));
        }
        // Not a str that can be read: no memory there, or a length gone wild.
        assert_eq!(py.str(0), None);
        assert_eq!(py.str(0x42), None);
        let torn = mem.str(&o, "x");
        mem.write_u64(torn + o.ascii_length, u64::MAX);
        assert_eq!(py.str(torn), None);
    }

    #[test]
    fn an_int_is_read_up_to_two_digits() {
        let (mem, o) = (FakeMemory::new(), offsets());
        let py = PyReader::new(&mem, o);
        for value in [0, 1, 4_194_303, 1 << 30, (1 << 60) - 1, -7] {
            assert_eq!(py.long(mem.long(&o, value)), Some(value), "{value}");
        }
        // Three digits: more than a thread id, not read.
        let big = mem.long(&o, 1);
        mem.write_u64(big + o.long_lv_tag, 3 << LONG_NON_SIZE_BITS);
        assert_eq!(py.long(big), None);
    }

    #[test]
    fn an_object_of_another_type_is_not_read_as_a_str_an_int_or_a_dict() {
        let (mem, o) = (FakeMemory::new(), offsets());
        let py = PyReader::new(&mem, o);
        // `_native_id` is None until the thread has started.
        let none = mem.none(&o);
        assert_eq!(
            (py.str(none), py.long(none), py.dict_items(none)),
            (None, None, None)
        );
        let text = mem.str(&o, "7");
        assert_eq!((py.long(text), py.dict_items(text)), (None, None));
        assert_eq!(py.str(mem.long(&o, 7)), None);
    }

    #[test]
    fn a_dict_is_its_entries_in_order_without_the_holes() {
        let (mem, o) = (FakeMemory::new(), offsets());
        let py = PyReader::new(&mem, o);
        // str keys: (key, value) entries.
        let dict = mem.str_dict(&o, &[("os", 0xa0), ("sys", 0xb0), ("threading", 0xc0)]);
        let items = py.dict_items(dict).unwrap();
        assert_eq!(
            items.iter().map(|i| i.1).collect::<Vec<_>>(),
            [0xa0, 0xb0, 0xc0]
        );
        assert_eq!(py.get(&items, "threading"), Some(0xc0));
        assert_eq!(py.get(&items, "_thread"), None);

        // Any keys: (hash, key, value) entries. A deleted item leaves a hole.
        let (one, two) = (mem.long(&o, 1), mem.long(&o, 2));
        let dict = mem.dict(&o, DICT_KEYS_GENERAL, &[(one, 0x111), (0, 0), (two, 0x222)]);
        assert_eq!(py.dict_items(dict).unwrap(), [(one, 0x111), (two, 0x222)]);

        assert_eq!(py.dict_items(mem.dict(&o, 1, &[])).unwrap(), []);
    }

    #[test]
    fn a_dict_that_does_not_add_up_is_not_read() {
        let (mem, o) = (FakeMemory::new(), offsets());
        let py = PyReader::new(&mem, o);
        let dict = mem.str_dict(&o, &[("a", 1)]);
        let keys = py.ptr(dict + o.dict_ma_keys).unwrap();
        // More entries than there is memory, than any dict has, and an index
        // table of a size no dict has.
        mem.write_u64(keys + o.keys_nentries, 1000);
        assert_eq!(py.dict_items(dict), None);
        mem.write_u64(keys + o.keys_nentries, u64::MAX);
        assert_eq!(py.dict_items(dict), None);
        mem.write_u64(keys + o.keys_nentries, 1);
        mem.write(keys + o.keys_log2_index_bytes, &[63]);
        assert_eq!(py.dict_items(dict), None);
        assert_eq!(py.dict_items(0), None);
    }

    #[test]
    fn an_instances_attributes_are_its_inline_values_under_the_class_keys() {
        let (mem, o) = (FakeMemory::new(), offsets());
        let py = PyReader::new(&mem, o);
        let names: Vec<Item> = ["_target", "_name", "_native_id"]
            .iter()
            .map(|n| (mem.str(&o, n), 0))
            .collect();
        let shared = mem.keys(&o, 2, &names);
        let name = mem.str(&o, "flip-100ms");
        let tid = mem.long(&o, 4242);

        // 3.13: values after a bare object. `_target` is not set: a hole.
        let tp = mem.heap_type(&o, INLINE_TYPE, 16, shared);
        let obj = mem.instance(&o, tp, 16, &[0, name, tid], true, 0);
        let attrs = py.instance_items(obj).unwrap();
        assert_eq!(attrs.len(), 2);
        assert_eq!(py.get(&attrs, "_name"), Some(name));
        assert_eq!(py.long(py.get(&attrs, "_native_id").unwrap()), Some(4242));

        // 3.14: after an instance that is more than a bare object.
        let tp = mem.heap_type(&o, INLINE_TYPE, 48, shared);
        let obj = mem.instance(&o, tp, 48, &[0, name, tid], true, 0);
        assert_eq!(
            py.get(&py.instance_items(obj).unwrap(), "_name"),
            Some(name)
        );
    }

    #[test]
    fn an_instance_whose_values_are_no_longer_valid_has_a_dict() {
        let (mem, o) = (FakeMemory::new(), offsets());
        let py = PyReader::new(&mem, o);
        let shared = mem.keys(&o, 2, &[(mem.str(&o, "_name"), 0)]);
        let tp = mem.heap_type(&o, INLINE_TYPE, 16, shared);
        let stale = mem.str(&o, "stale");
        let current = mem.str(&o, "renamed");
        let dict = mem.str_dict(&o, &[("_name", current)]);

        let obj = mem.instance(&o, tp, 16, &[stale], false, dict);
        assert_eq!(
            py.get(&py.instance_items(obj).unwrap(), "_name"),
            Some(current)
        );
        // Neither: an instance with no attributes yet.
        let obj = mem.instance(&o, tp, 16, &[stale], false, 0);
        assert_eq!(py.instance_items(obj).unwrap(), []);
    }

    #[test]
    fn an_instance_of_a_type_without_a_managed_dict_has_one_at_dictoffset() {
        let (mem, o) = (FakeMemory::new(), offsets());
        let py = PyReader::new(&mem, o);
        let tp = mem.heap_type(&o, TPFLAGS_HEAPTYPE, 32, 0);
        mem.write_u64(tp + o.type_dictoffset, 16);
        let dict = mem.str_dict(&o, &[("x", 0x77)]);
        let obj = mem.alloc(32);
        mem.write_u64(obj + o.ob_type, tp as u64);
        mem.write_u64(obj + 16, dict as u64);
        assert_eq!(py.get(&py.instance_items(obj).unwrap(), "x"), Some(0x77));
        // A module is such an object: md_dict is where its type says.
        assert_eq!(o.module_md_dict, 16);
    }
}
