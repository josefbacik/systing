/// Python line table parsing.
///
/// Ports PyLineTable.cpp: supports Python 3.10 (lnotab) and 3.11+ (location table)
/// formats for mapping instruction indices to source line numbers.
use super::process;

const PY_CODE_UNIT_SIZE: usize = 2;
const MAX_LINE_TABLE_SIZE: usize = 1024 * 1024;

/// Parsed line table for a Python code object.
pub struct PyLineTable {
    data: Vec<u8>,
    first_line: i32,
    py_major_ver: i32,
    py_minor_ver: i32,
}

impl PyLineTable {
    /// Create a line table by reading data from process memory.
    pub fn from_process(
        pid: i32,
        first_line: i32,
        addr: usize,
        length: usize,
        py_major_ver: i32,
        py_minor_ver: i32,
    ) -> Option<Self> {
        if length == 0 || length > MAX_LINE_TABLE_SIZE || addr == 0 {
            return None;
        }

        let mut data = vec![0u8; length];
        let bytes_read = process::read_process_memory(pid, addr, &mut data).ok()?;
        if bytes_read != length {
            return None;
        }

        Some(Self {
            data,
            first_line,
            py_major_ver,
            py_minor_ver,
        })
    }

    /// Create a line table from an existing data buffer (for testing).
    #[cfg(test)]
    pub fn from_data(data: Vec<u8>, first_line: i32, py_major_ver: i32, py_minor_ver: i32) -> Self {
        Self {
            data,
            first_line,
            py_major_ver,
            py_minor_ver,
        }
    }

    /// Get the line number for a given instruction index.
    /// Returns 0 if no line information is available.
    pub fn get_line_for_inst_index(&self, addrq: i32) -> i32 {
        if self.py_major_ver > 3 || (self.py_major_ver == 3 && self.py_minor_ver > 10) {
            self.get_line_311_plus(addrq)
        } else if self.py_major_ver == 3 && self.py_minor_ver == 10 {
            self.get_line_310(addrq)
        } else {
            0
        }
    }

    /// Python 3.10 lnotab format: (offset_delta: u8, line_delta: i8) pairs.
    fn get_line_310(&self, addrq: i32) -> i32 {
        if addrq < 0 {
            return self.first_line;
        }
        let offset = (addrq as usize) * PY_CODE_UNIT_SIZE;
        let mut line = self.first_line;
        let mut end: usize = 0;

        // Each entry is 2 bytes: (offset_delta: u8, line_delta: i8)
        let entry_count = self.data.len() / 2;
        for i in 0..entry_count {
            let offset_delta = self.data[i * 2];
            let line_delta = self.data[i * 2 + 1] as i8;

            if line_delta == 0 {
                end += offset_delta as usize;
                continue;
            }

            let start = end;
            end = start + offset_delta as usize;

            if line_delta == -128 {
                // No valid line number -- skip entry
                continue;
            }
            line += line_delta as i32;

            if end == start {
                // Empty range, omit
                continue;
            }

            if start <= offset && offset < end {
                return line;
            }
        }

        0
    }

    /// Python 3.11+ location table format: varint-encoded entries.
    fn get_line_311_plus(&self, addrq: i32) -> i32 {
        if addrq < 0 {
            return self.first_line;
        }
        let offset = (addrq as usize) * PY_CODE_UNIT_SIZE;
        let mut ret = 0;

        // Use a closure-based iterator to parse the location table
        self.parse_location_table(|start, end, line| {
            if offset >= start && offset < end {
                ret = line;
                false // break
            } else if end > offset {
                false // break
            } else {
                true // continue
            }
        });

        ret
    }

    /// Parse CPython 3.11+ location table.
    /// Callback receives (start_addr, end_addr, line_number). Return false to stop.
    fn parse_location_table<F>(&self, mut callback: F)
    where
        F: FnMut(usize, usize, i32) -> bool,
    {
        let data = &self.data;
        let mut pos = 0;
        let len = data.len();

        let mut line_number = self.first_line;
        let mut addr: i32 = 0;

        while pos < len {
            let byte = data[pos];
            pos += 1;
            let delta = ((byte & 7) as i32) + 1;
            let code = (byte >> 3) & 15;

            let line_delta = if code == 15 {
                0
            } else if code == 14 {
                let ld = read_signed_varint(data, &mut pos);
                read_varint(data, &mut pos); // end line
                read_varint(data, &mut pos); // start column
                read_varint(data, &mut pos); // end column
                ld
            } else if code == 13 {
                read_signed_varint(data, &mut pos)
            } else if (10..=12).contains(&code) {
                let ld = (code - 10) as i32;
                if pos < len {
                    pos += 1;
                } // start column
                if pos < len {
                    pos += 1;
                } // end column
                ld
            } else {
                if pos < len {
                    pos += 1;
                } // column
                0
            };

            line_number += line_delta;
            let end_addr = addr + delta * 2;

            if !callback(addr as usize, end_addr as usize, line_number) {
                break;
            }
            addr = end_addr;
        }
    }
}

/// Read a varint from the location table data.
fn read_varint(data: &[u8], pos: &mut usize) -> u32 {
    let len = data.len();
    if *pos >= len {
        return 0;
    }
    let mut b = data[*pos];
    *pos += 1;
    let mut val = (b & 63) as u32;
    let mut shift = 0u32;
    while b & 64 != 0 {
        if *pos >= len {
            break;
        }
        b = data[*pos];
        *pos += 1;
        shift += 6;
        val += ((b & 63) as u32) << shift;
    }
    val
}

/// Read a signed varint from the location table data.
fn read_signed_varint(data: &[u8], pos: &mut usize) -> i32 {
    let uval = read_varint(data, pos);
    if uval & 1 != 0 {
        -((uval >> 1) as i32)
    } else {
        (uval >> 1) as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_310_simple_lnotab() {
        // Simple lnotab: offset_delta=4, line_delta=1; offset_delta=4, line_delta=1
        let data = vec![4, 1, 4, 1];
        let lt = PyLineTable::from_data(data, 10, 3, 10);

        // inst_idx 0 -> offset 0, in range [0,4) -> line 11
        assert_eq!(lt.get_line_for_inst_index(0), 11);
        // inst_idx 1 -> offset 2, in range [0,4) -> line 11
        assert_eq!(lt.get_line_for_inst_index(1), 11);
        // inst_idx 2 -> offset 4, in range [4,8) -> line 12
        assert_eq!(lt.get_line_for_inst_index(2), 12);
    }

    #[test]
    fn test_310_negative_addrq() {
        let data = vec![4, 1];
        let lt = PyLineTable::from_data(data, 42, 3, 10);
        assert_eq!(lt.get_line_for_inst_index(-1), 42);
    }

    #[test]
    fn test_310_skip_minus_128() {
        // line_delta = -128 means "no valid line number"
        let data = vec![4, 128u8, 4, 1]; // 128 as u8 = -128 as i8
        let lt = PyLineTable::from_data(data, 10, 3, 10);
        // First entry skipped (line_delta=-128), second is line 11
        assert_eq!(lt.get_line_for_inst_index(2), 11);
    }

    #[test]
    fn test_pre_310_returns_zero() {
        let data = vec![4, 1];
        let lt = PyLineTable::from_data(data, 10, 3, 9);
        assert_eq!(lt.get_line_for_inst_index(0), 0);
    }

    #[test]
    fn test_311_code_13_signed_varint() {
        // Code 13: signed varint line delta
        // byte = (13 << 3) | 0 = 0x68, delta = 0+1 = 1
        // signed varint: 4 -> uval=4, 4&1=0, so delta = 4/2 = 2
        let data = vec![0x68, 4];
        let lt = PyLineTable::from_data(data, 10, 3, 11);
        // offset range [0, 2), line = 10 + 2 = 12
        assert_eq!(lt.get_line_for_inst_index(0), 12);
    }

    #[test]
    fn test_311_code_15_no_line() {
        // Code 15: no line change
        // byte = (15 << 3) | 0 = 0x78
        let data = vec![0x78];
        let lt = PyLineTable::from_data(data, 10, 3, 11);
        // line stays at 10
        assert_eq!(lt.get_line_for_inst_index(0), 10);
    }

    #[test]
    fn test_empty_data() {
        let lt = PyLineTable::from_data(Vec::new(), 10, 3, 11);
        assert_eq!(lt.get_line_for_inst_index(0), 0);
    }
}
