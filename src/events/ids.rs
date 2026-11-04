use std::collections::HashMap;

/// The most values that one capture numbers. A HashMap with 2^23 slots holds this many,
/// and one more value would double it.
const MAX_VALUES: usize = 7 << 20;

/// What an "id" arg records for a new value once the table is full: -1 in the trace, whose
/// integers are signed.
const NOT_NUMBERED: u64 = u64::MAX;

/// Numbers the values of "id" args in the order they are first seen, so that a trace shows which
/// events name the same value without showing the value. 0 stays 0, so NULL still reads as NULL.
/// A value's number is `(group << shift) + n`. Values equal above their low `shift` bits form a
/// group. Groups count from 1, and `n` counts a group's values from 0, so it fits `shift` bits.
pub(super) struct IdTable {
    shift: Option<u8>,
    max_values: usize,
    numbers: HashMap<u64, u64>,
    groups: HashMap<u64, Group>,
    not_numbered: u64,
}

struct Group {
    number: u32,
    values: u32,
}

impl Default for IdTable {
    fn default() -> Self {
        Self::with_max_values(MAX_VALUES)
    }
}

impl IdTable {
    pub(super) fn with_max_values(max_values: usize) -> Self {
        Self {
            shift: None,
            max_values,
            numbers: HashMap::new(),
            groups: HashMap::new(),
            not_numbered: 0,
        }
    }

    /// Sets the capture's shift, unless it has one. Returns the one that it has now.
    pub(super) fn set_shift(&mut self, shift: u8) -> u8 {
        *self.shift.get_or_insert(shift)
    }

    /// How many times `id()` found the table full. None if no arg is an "id".
    pub(super) fn not_numbered(&self) -> Option<u64> {
        self.shift.map(|_| self.not_numbered)
    }

    pub(super) fn id(&mut self, value: u64) -> u64 {
        if value == 0 {
            return 0;
        }
        if let Some(number) = self.numbers.get(&value) {
            return *number;
        }
        if self.numbers.len() >= self.max_values {
            self.not_numbered += 1;
            return NOT_NUMBERED;
        }
        let shift = self.shift.unwrap_or(0);
        let number = if shift == 0 {
            // A value is its own group here, so `groups` would only repeat `numbers`.
            self.numbers.len() as u64 + 1
        } else {
            let next = self.groups.len() as u32 + 1;
            let group = self.groups.entry(value >> shift).or_insert(Group {
                number: next,
                values: 0,
            });
            group.values += 1;
            (u64::from(group.number) << shift) + u64::from(group.values) - 1
        };
        self.numbers.insert(value, number);
        number
    }
}
