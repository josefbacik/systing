/// Process memory reading via /proc/pid/mem and /proc/pid/maps parsing.
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

/// A memory mapping entry from /proc/pid/maps.
#[derive(Debug, Clone)]
pub struct MemoryMapping {
    pub start: usize,
    pub end: usize,
    pub perms: String,
    pub offset: u64,
    pub dev_major: u32,
    pub dev_minor: u32,
    pub inode: u64,
    pub name: String,
}

/// Parse /proc/pid/maps to get memory mappings.
pub fn parse_proc_maps(pid: i32) -> Vec<MemoryMapping> {
    let path = format!("/proc/{pid}/maps");
    let content = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut mappings = Vec::new();
    for line in content.lines() {
        if let Some(mapping) = parse_maps_line(line) {
            mappings.push(mapping);
        }
    }
    mappings
}

fn parse_maps_line(line: &str) -> Option<MemoryMapping> {
    let mut parts = line.split_whitespace();
    let range = parts.next()?;
    let perms = parts.next()?.to_string();
    let offset_str = parts.next()?;
    let dev = parts.next()?;
    let inode_str = parts.next()?;
    let name = parts.collect::<Vec<_>>().join(" ");

    let (start_str, end_str) = range.split_once('-')?;
    let start = usize::from_str_radix(start_str, 16).ok()?;
    let end = usize::from_str_radix(end_str, 16).ok()?;
    let offset = u64::from_str_radix(offset_str, 16).ok()?;
    let (dev_major_str, dev_minor_str) = dev.split_once(':')?;
    let dev_major = u32::from_str_radix(dev_major_str, 16).ok()?;
    let dev_minor = u32::from_str_radix(dev_minor_str, 16).ok()?;
    let inode = inode_str.parse().ok()?;

    Some(MemoryMapping {
        start,
        end,
        perms,
        offset,
        dev_major,
        dev_minor,
        inode,
        name,
    })
}

/// Find the base load address for a module in the process's memory maps.
/// Returns the start address of the first mapping with offset 0 for the given path.
pub fn find_base_address(pid: i32, module_path: &str) -> Option<usize> {
    let maps = parse_proc_maps(pid);
    maps.iter()
        .find(|m| m.offset == 0 && m.name == module_path)
        .map(|m| m.start)
}

/// Read memory from a process via /proc/pid/mem.
pub fn read_process_memory(pid: i32, addr: usize, buf: &mut [u8]) -> std::io::Result<usize> {
    let path = format!("/proc/{pid}/mem");
    let mut file = fs::File::open(&path)?;
    file.seek(SeekFrom::Start(addr as u64))?;
    file.read(buf)
}

/// Read the exe link for a process.
pub fn read_exe_path(pid: i32) -> Option<PathBuf> {
    fs::read_link(format!("/proc/{pid}/exe")).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_maps_line() {
        let line =
            "7f1234560000-7f1234570000 r-xp 00001000 08:01 12345   /usr/lib/libpython3.10.so";
        let m = parse_maps_line(line).unwrap();
        assert_eq!(m.start, 0x7f1234560000);
        assert_eq!(m.end, 0x7f1234570000);
        assert_eq!(m.perms, "r-xp");
        assert_eq!(m.offset, 0x1000);
        assert_eq!(m.dev_major, 8);
        assert_eq!(m.dev_minor, 1);
        assert_eq!(m.inode, 12345);
        assert_eq!(m.name, "/usr/lib/libpython3.10.so");
    }

    #[test]
    fn test_parse_maps_line_no_name() {
        let line = "7fff12340000-7fff12360000 rw-p 00000000 00:00 0";
        let m = parse_maps_line(line).unwrap();
        assert_eq!(m.name, "");
        assert_eq!(m.inode, 0);
    }

    #[test]
    fn test_parse_current_process_maps() {
        let maps = parse_proc_maps(std::process::id() as i32);
        // Current process should have at least some mappings
        assert!(!maps.is_empty());
    }
}
