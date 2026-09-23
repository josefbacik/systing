//! The `/proc/<pid>/maps` text a dump carries, and address lookups in it.

use std::path::Path;

/// One mapping line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapping {
    pub start: u64,
    pub end: u64,
    /// File offset of `start`.
    pub offset: u64,
    pub inode: u64,
    /// The file's device, (major, minor): with `inode`, the file's identity.
    pub dev: (u32, u32),
    /// Mapped executable (`x` in the permissions).
    pub exec: bool,
    /// The pathname column: a file path, a `[bracketed]` kernel name, or
    /// empty for anonymous memory.
    pub path: String,
}

impl Mapping {
    /// Whether the mapping is a file, so its offsets can be symbolized.
    pub fn is_file(&self) -> bool {
        self.path.starts_with('/')
    }

    /// The module name frames show: the file's base name, or the kernel's
    /// `[name]`. `None` for anonymous memory.
    pub fn label(&self) -> Option<&str> {
        if self.is_file() {
            Path::new(&self.path).file_name().and_then(|f| f.to_str())
        } else if self.path.starts_with('[') {
            Some(&self.path)
        } else {
            None
        }
    }
}

/// A process's mappings, sorted by start address.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Maps {
    mappings: Vec<Mapping>,
}

impl Maps {
    /// Parse maps text. Lines that do not parse are skipped: a dump written
    /// by a crashing process may end mid-line.
    pub fn parse(text: &str) -> Maps {
        let mut mappings: Vec<Mapping> = text.lines().filter_map(parse_line).collect();
        mappings.sort_by_key(|m| m.start);
        Maps { mappings }
    }

    pub fn mappings(&self) -> &[Mapping] {
        &self.mappings
    }

    /// The mapping holding `addr`.
    pub fn lookup(&self, addr: u64) -> Option<&Mapping> {
        let i = self.mappings.partition_point(|m| m.start <= addr);
        let m = self.mappings.get(i.checked_sub(1)?)?;
        (addr < m.end).then_some(m)
    }

    /// The main executable, taken to be the first file mapped (the kernel
    /// maps it first, below the libraries).
    pub fn exe_name(&self) -> Option<&str> {
        self.mappings.iter().find(|m| m.is_file())?.label()
    }
}

fn parse_line(line: &str) -> Option<Mapping> {
    // start-end perms offset dev inode [path]; the path may contain spaces.
    let mut fields = line.splitn(6, char::is_whitespace);
    let range = fields.next()?;
    let perms = fields.next()?;
    let offset = fields.next()?;
    let dev = fields.next()?;
    let inode = fields.next()?;
    let path = fields.next().unwrap_or("").trim().to_string();
    let (start, end) = range.split_once('-')?;
    Some(Mapping {
        start: u64::from_str_radix(start, 16).ok()?,
        end: u64::from_str_radix(end, 16).ok()?,
        offset: u64::from_str_radix(offset, 16).ok()?,
        inode: inode.parse().ok()?,
        dev: {
            let (maj, min) = dev.split_once(':')?;
            (
                u32::from_str_radix(maj, 16).ok()?,
                u32::from_str_radix(min, 16).ok()?,
            )
        },
        exec: perms.as_bytes().get(2) == Some(&b'x'),
        path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAPS: &str = "\
56326ffdc000-56326ffdd000 r--p 00000000 00:2a8 156407                    /tmp/je/t
56326ffdd000-56326ffde000 r-xp 00001000 00:2a8 156407                    /tmp/je/t
7f4bc4300000-7f4bc5000000 rw-p 00000000 00:00 0
7f4bc6dfc000-7f4bc6e20000 r-xp 00004000 00:637 964724045                 /usr/lib/x86_64-linux-gnu/libgcc_s.so.1
7ffd1c3f0000-7ffd1c3f2000 r-xp 00000000 00:00 0                          [vdso]
7ffd1c400000-7ffd1c401000 r-xp 00000000 00:2a8 7                         /tmp/a dir/lib x.so
";

    #[test]
    fn lookup_finds_the_mapping_and_its_file_offset() {
        let maps = Maps::parse(MAPS);
        let m = maps.lookup(0x56326ffdd225).unwrap();
        assert_eq!(m.path, "/tmp/je/t");
        assert_eq!(0x56326ffdd225 - m.start + m.offset, 0x1225);
        assert_eq!(m.label(), Some("t"));
        assert!(m.exec);
        assert_eq!(m.dev, (0, 0x2a8));
        assert!(!maps.lookup(0x56326ffdc000).unwrap().exec);
    }

    #[test]
    fn end_is_exclusive_and_gaps_miss() {
        let maps = Maps::parse(MAPS);
        assert!(maps.lookup(0x56326ffde000).is_none());
        assert!(maps.lookup(0x1000).is_none());
    }

    #[test]
    fn anonymous_and_kernel_mappings_have_no_file() {
        let maps = Maps::parse(MAPS);
        let anon = maps.lookup(0x7f4bc4300010).unwrap();
        assert!(!anon.is_file());
        assert_eq!(anon.label(), None);
        let vdso = maps.lookup(0x7ffd1c3f0010).unwrap();
        assert_eq!(vdso.label(), Some("[vdso]"));
    }

    #[test]
    fn paths_keep_their_spaces() {
        let maps = Maps::parse(MAPS);
        assert_eq!(
            maps.lookup(0x7ffd1c400000).unwrap().path,
            "/tmp/a dir/lib x.so"
        );
    }

    #[test]
    fn exe_is_the_first_file() {
        assert_eq!(Maps::parse(MAPS).exe_name(), Some("t"));
    }
}
