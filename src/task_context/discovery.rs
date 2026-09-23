//! Which processes publish a task_context recipe, and what it is.
//!
//! The writer library (`crates/task-context`) keeps one 104-byte record per
//! process, in a section of its own, and reports in it how far its one
//! thread-local slot sits from the thread pointer and which region every
//! block lives in. This file finds that record, from OUTSIDE the process:
//!
//! 1. The process's EXECUTABLE is opened through `/proc/<pid>/exe` and its
//!    ELF facts are read once per distinct file: does it carry the section
//!    (a statically linked writer), or does it name `libtask_context*` among
//!    its direct dependencies (a dynamically linked one)? Every other
//!    process costs one open and one stat, and nothing of it is read.
//! 2. For a dynamically linked writer the library is found in the process's
//!    map by its file name and opened through `/proc/<pid>/map_files`, the
//!    route symbolization already takes to a mapped file.
//! 3. The record's run-time address is its link-time address plus the load
//!    bias of the object it is in. Exactly 104 bytes are read there, and
//!    every field is checked against this reader's OWN numbers before one
//!    of them is believed: a record that claims another geometry, a region
//!    larger than the ABI's, or an address other than its own is refused.
//!
//! NOT looked for in this version: a library reached only through another
//! library, through `LD_PRELOAD` or through `dlopen`, and a file whose
//! section header table was removed. Such a process simply has no recipe.
//!
//! Nothing here is printed from a process's memory or files: findings are
//! counted under fixed names, beside the process id.

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::time::{Duration, Instant};

use object::elf::{FileHeader64, DT_NEEDED, PN_XNUM, PT_LOAD, SHN_XINDEX, SHT_DYNAMIC, SHT_NOBITS};
use object::read::elf::{Dyn, FileHeader, ProgramHeader, SectionHeader, SectionTable};
use object::read::{ReadCache, ReadRef};
use object::Endianness;

use super::values::{ABI_VERSION, BLOCK_HDR_SIZE, NAME_MAX, SLOTS, SLOT_SIZE, VALUE_MAX};
// The tree's one reader of a process's map and memory lives under the Python
// walker's module, which is always compiled (no feature gates it). If that
// ever changes, this path must keep its reader: it has no other.
use crate::pystacks::process::{parse_proc_maps, MemoryMapping, ProcessMemory, ReadMemory};

/// The section the library keeps its record in (`TASK_CONTEXT_INFO_SECTION`).
pub(crate) const INFO_SECTION: &str = "task_context_info";
/// What the library's file is called, up to its version suffix.
const LIBRARY_PREFIX: &str = "libtask_context";

// The reader's own copy of the info record's numbers (task_context.h).
pub(crate) const INFO_SIZE: usize = 104;
const INFO_MAGIC: u32 = 0x3158_4354; // "TCX1"
const RECIPE_UNSET: u32 = 0;
const RECIPE_TP_OFFSET: u32 = 1;
const BLOCK_STRIDE: u64 = 2560;
const REGION_SIZE_MAX: u64 = 16 * 1024 * 1024;

const INFO_VERSION_AT: usize = 4;
const INFO_SIZE_AT: usize = 6;
const INFO_TAG_AT: usize = 8;
const INFO_TP_OFFSET_AT: usize = 16;
const INFO_SELF_ADDRESS_AT: usize = 48;
const INFO_REGION_BASE_AT: usize = 56;
const INFO_REGION_SIZE_AT: usize = 64;
const INFO_BLOCK_SIZE_AT: usize = 72;
const INFO_BLOCK_HDR_SIZE_AT: usize = 76;
const INFO_SLOT_SIZE_AT: usize = 78;
const INFO_NSLOTS_AT: usize = 80;
const INFO_NAME_MAX_AT: usize = 82;
const INFO_VALUE_MAX_AT: usize = 84;

/// The farthest a slot in static TLS can plausibly sit from the thread
/// pointer. Static TLS of a whole process is kilobytes to a few megabytes.
const TP_OFFSET_MAX: u64 = 1 << 30;
/// The lowest and highest address a region can have in a 64-bit process.
const USER_ADDR_MIN: u64 = 0x1_0000;
const USER_ADDR_MAX: u64 = 0x00ff_ffff_ffff_ffff;

/// Distinct files whose ELF facts are remembered; past this the table
/// starts again.
const ELF_CACHE_MAX: usize = 1 << 16;

/// The longest a file may say its info section and its dynamic section are
/// for this reader to read them. A file states its own sizes, a sparse file
/// can state any, and the cache a file is read through allocates what it is
/// told: a size past these is refused unread. (The record is 104 bytes; a
/// dynamic section of a megabyte is 65,536 entries.)
const INFO_SECTION_MAX: u64 = 4096;
const DYNAMIC_SECTION_MAX: u64 = 1 << 20;

/// One process's recipe, as the BPF side takes it: the layout of
/// `struct task_context_recipe` in `task_context_reader.bpf.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recipe {
    /// `&slot - thread pointer`.
    pub tp_offset: i64,
    pub region_base: u64,
    pub region_size: u64,
}

impl Recipe {
    /// The map value: three native-endian 8-byte words.
    pub fn to_bytes(self) -> [u8; 24] {
        let mut bytes = [0u8; 24];
        bytes[0..8].copy_from_slice(&self.tp_offset.to_ne_bytes());
        bytes[8..16].copy_from_slice(&self.region_base.to_ne_bytes());
        bytes[16..24].copy_from_slice(&self.region_size.to_ne_bytes());
        bytes
    }
}

/// Why a record that was found is not believed. A closed set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The section in the FILE is too short or its constant fields are wrong.
    FileRecord,
    Magic,
    Version,
    InfoSize,
    /// A recipe tag this reader does not implement.
    Tag,
    /// The record is not at the address the file says it is at.
    SelfAddress,
    /// Block, slot or value sizes other than this reader's own.
    Geometry,
    /// A region that is unaligned, empty, larger than the ABI's or outside
    /// the user address range.
    Region,
    /// An offset that is zero, unaligned, too far or on the wrong side of
    /// the thread pointer for this architecture.
    TpOffset,
}

/// How many reasons `Refusal` has.
const REFUSAL_KINDS: usize = 9;

impl Refusal {
    const ALL: [Refusal; REFUSAL_KINDS] = [
        Refusal::FileRecord,
        Refusal::Magic,
        Refusal::Version,
        Refusal::InfoSize,
        Refusal::Tag,
        Refusal::SelfAddress,
        Refusal::Geometry,
        Refusal::Region,
        Refusal::TpOffset,
    ];

    fn name(self) -> &'static str {
        match self {
            Refusal::FileRecord => "file_record",
            Refusal::Magic => "magic",
            Refusal::Version => "version",
            Refusal::InfoSize => "info_size",
            Refusal::Tag => "tag",
            Refusal::SelfAddress => "self_address",
            Refusal::Geometry => "geometry",
            Refusal::Region => "region",
            Refusal::TpOffset => "tp_offset",
        }
    }
}

/// What looking at one process found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Finding {
    Published(Recipe),
    /// Neither the executable nor a direct dependency carries the record.
    NotLinked,
    /// The process links the library, and the library is not mapped yet or
    /// has not published yet: look again.
    NotYet,
    Refused(Refusal),
    /// The process is gone, or its files or memory cannot be read.
    Gone,
}

/// What discovery did; printed once when a capture ends.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DiscoveryCounters {
    /// Processes looked at (attach pass, exec notices and second looks).
    pub looked: u64,
    pub published: u64,
    pub not_yet: u64,
    pub refused: u64,
    /// `refused`, by reason (the order of `Refusal::ALL`).
    pub refused_by: [u64; REFUSAL_KINDS],
    pub gone: u64,
    /// Processes the attach pass did not reach before its time ran out.
    pub not_reached: u64,
    /// Recipes the map did not take.
    pub map_errors: u64,
    /// Processes dropped from the look-again list, unpublished to the end.
    pub gave_up: u64,
    /// Distinct files whose ELF facts were read.
    pub files_parsed: u64,
}

impl DiscoveryCounters {
    /// The counters as `name=value` pairs, zero ones left out.
    pub fn summary(&self) -> String {
        let pairs = [
            ("looked", self.looked),
            ("published", self.published),
            ("not_yet", self.not_yet),
            ("refused", self.refused),
            ("gone", self.gone),
            ("not_reached", self.not_reached),
            ("map_errors", self.map_errors),
            ("gave_up", self.gave_up),
            ("files_parsed", self.files_parsed),
        ];
        let mut parts: Vec<String> = pairs
            .iter()
            .filter(|(_, count)| *count > 0)
            .map(|(name, count)| format!("{name}={count}"))
            .collect();
        for (refusal, count) in Refusal::ALL.iter().zip(self.refused_by) {
            if count > 0 {
                parts.push(format!("refused_{}={count}", refusal.name()));
            }
        }
        parts.join(" ")
    }
}

/// What one ELF file says, independent of any process that maps it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ElfFacts {
    /// Link-time address of a record whose constant fields check out.
    pub record_address: Option<u64>,
    /// The file has the section, and what is in it is not a record.
    pub record_refused: bool,
    /// The file names the library among its direct dependencies.
    pub needs_library: bool,
    /// The loadable segment with the lowest address: that address, and
    /// where the segment sits in the file.
    pub first_load_address: u64,
    pub first_load_offset: u64,
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

/// The fields the library's compiler wrote: magic, version, the record's
/// size and the block geometry. They are the same in the file and in every
/// process that maps it.
fn constants_ok(record: &[u8]) -> Result<(), Refusal> {
    if record.len() < INFO_SIZE {
        return Err(Refusal::InfoSize);
    }
    if u32_at(record, 0) != INFO_MAGIC {
        return Err(Refusal::Magic);
    }
    if u16_at(record, INFO_VERSION_AT) != ABI_VERSION {
        return Err(Refusal::Version);
    }
    // A later build may make the record longer; this reader takes its own
    // 104 bytes of it. A shorter one cannot hold the fields read below.
    if (u16_at(record, INFO_SIZE_AT) as usize) < INFO_SIZE {
        return Err(Refusal::InfoSize);
    }
    let geometry_ok = u64::from(u32_at(record, INFO_BLOCK_SIZE_AT)) == BLOCK_STRIDE
        && u16_at(record, INFO_BLOCK_HDR_SIZE_AT) as usize == BLOCK_HDR_SIZE
        && u16_at(record, INFO_SLOT_SIZE_AT) as usize == SLOT_SIZE
        && u16_at(record, INFO_NSLOTS_AT) as usize == SLOTS
        && u16_at(record, INFO_NAME_MAX_AT) as usize == NAME_MAX
        && u32_at(record, INFO_VALUE_MAX_AT) as usize == VALUE_MAX;
    if !geometry_ok {
        return Err(Refusal::Geometry);
    }
    Ok(())
}

/// The record as read from a process at `address`: a recipe, "not yet", or
/// the reason it is refused.
pub(crate) fn validate_info(record: &[u8; INFO_SIZE], address: u64) -> Finding {
    if let Err(refusal) = constants_ok(record) {
        return Finding::Refused(refusal);
    }
    match u32_at(record, INFO_TAG_AT) {
        RECIPE_UNSET => return Finding::NotYet,
        RECIPE_TP_OFFSET => {}
        _ => return Finding::Refused(Refusal::Tag),
    }
    if u64_at(record, INFO_SELF_ADDRESS_AT) != address {
        return Finding::Refused(Refusal::SelfAddress);
    }

    let region_base = u64_at(record, INFO_REGION_BASE_AT);
    let region_size = u64_at(record, INFO_REGION_SIZE_AT);
    let region_ok = region_base >= USER_ADDR_MIN
        && region_base.is_multiple_of(4096)
        && (BLOCK_STRIDE..=REGION_SIZE_MAX).contains(&region_size)
        && region_base
            .checked_add(region_size)
            .is_some_and(|end| end <= USER_ADDR_MAX);
    if !region_ok {
        return Finding::Refused(Refusal::Region);
    }

    let tp_offset = u64_at(record, INFO_TP_OFFSET_AT) as i64;
    // Static TLS lies below the thread pointer on x86-64 (variant 2) and
    // above it on aarch64 (variant 1); the tracer and the traced process
    // run on the same machine.
    let side_ok = if cfg!(target_arch = "x86_64") {
        tp_offset < 0
    } else if cfg!(target_arch = "aarch64") {
        tp_offset > 0
    } else {
        tp_offset != 0
    };
    if !side_ok || tp_offset % 8 != 0 || tp_offset.unsigned_abs() > TP_OFFSET_MAX {
        return Finding::Refused(Refusal::TpOffset);
    }

    Finding::Published(Recipe {
        tp_offset,
        region_base,
        region_size,
    })
}

/// Whether `name` (a DT_NEEDED string, or the last component of a mapped
/// file's path) is the library's file.
fn is_library_name(name: &[u8]) -> bool {
    name.starts_with(LIBRARY_PREFIX.as_bytes())
}

fn needs_library<'data, R: ReadRef<'data>>(
    sections: &SectionTable<'data, FileHeader64<Endianness>, R>,
    endian: Endianness,
    data: R,
) -> bool {
    // A dynamic section that says it is longer than any real one is not
    // read: such a file does not name the library as far as this goes.
    let too_long = sections.iter().any(|section| {
        section.sh_type(endian) == SHT_DYNAMIC && section.sh_size(endian) > DYNAMIC_SECTION_MAX
    });
    if too_long {
        return false;
    }
    let Ok(Some((entries, link))) = sections.dynamic(endian, data) else {
        return false;
    };
    let Ok(strings) = sections.strings(endian, data, link) else {
        return false;
    };
    entries.iter().any(|entry| {
        entry.tag32(endian) == Some(DT_NEEDED)
            && entry
                .val32(endian)
                .and_then(|at| strings.get(at).ok())
                .is_some_and(|name| {
                    // A dependency may be named with a path.
                    let file = name.rsplit(|&byte| byte == b'/').next().unwrap_or(name);
                    is_library_name(file)
                })
    })
}

/// Read a file's ELF facts. `None` for anything that is not a 64-bit ELF
/// file with a loadable segment.
///
/// Only the file header, the program headers, the section header table and
/// the two small sections of interest are read. In particular no symbol
/// table is, so a large unstripped executable costs what a small one does.
/// Every length followed is one this reader bounds itself: the header's own
/// 16-bit counts, and `INFO_SECTION_MAX` / `DYNAMIC_SECTION_MAX`.
pub(crate) fn elf_facts<'data, R: ReadRef<'data>>(data: R) -> Option<ElfFacts> {
    let header = FileHeader64::<Endianness>::parse(data).ok()?;
    let endian = header.endian().ok()?;
    // Extended numbering keeps a count too large for the header's 16 bits
    // in section 0 instead, where a file can state billions of headers. No
    // program this looks for needs it: such a file is not of interest.
    if header.e_phnum(endian) == PN_XNUM
        || header.e_shstrndx(endian) == SHN_XINDEX
        || (header.e_shnum(endian) == 0 && header.e_shoff(endian) != 0)
    {
        return None;
    }
    let (first_load_address, first_load_offset) = header
        .program_headers(endian, data)
        .ok()?
        .iter()
        .filter(|segment| segment.p_type(endian) == PT_LOAD)
        .map(|segment| (segment.p_vaddr(endian), segment.p_offset(endian)))
        .min()?;
    // A file without a section header table has an empty one here.
    let sections = header.sections(endian, data).ok()?;

    let mut record_address = None;
    let mut record_refused = false;
    if let Some((_, section)) = sections.section_by_name(endian, INFO_SECTION.as_bytes()) {
        // The constant fields are in the file's data image, so a section
        // that occupies no file space is not the library's; nor is one
        // that says it is longer than this reader will read.
        let unreadable =
            section.sh_type(endian) == SHT_NOBITS || section.sh_size(endian) > INFO_SECTION_MAX;
        let bytes = if unreadable {
            None
        } else {
            section.data(endian, data).ok()
        };
        match bytes {
            Some(bytes) if constants_ok(bytes).is_ok() => {
                record_address = Some(section.sh_addr(endian))
            }
            _ => record_refused = true,
        }
    }

    Some(ElfFacts {
        record_address,
        record_refused,
        needs_library: needs_library(&sections, endian, data),
        first_load_address,
        first_load_offset,
    })
}

/// Where an object was loaded: `start` is where file offset `map_offset` of
/// it is mapped. The object's link-time addresses plus the result are its
/// run-time addresses (0 for an executable linked at fixed addresses).
pub(crate) fn load_bias(facts: &ElfFacts, start: u64, map_offset: u64) -> Option<u64> {
    // The lowest mapping of a file starts at or before its first segment.
    let into_file = facts.first_load_offset.checked_sub(map_offset)?;
    Some(
        start
            .wrapping_sub(facts.first_load_address)
            .wrapping_add(into_file),
    )
}

/// The last component of a mapped file's name as `/proc/<pid>/maps` prints
/// it, without the " (deleted)" the kernel appends to a removed file.
fn mapped_file_name(name: &str) -> &str {
    let name = name.strip_suffix(" (deleted)").unwrap_or(name);
    name.rsplit('/').next().unwrap_or(name)
}

/// The lowest mapping among `maps` that `wanted` accepts.
fn lowest_mapping(
    maps: &[MemoryMapping],
    wanted: impl Fn(&MemoryMapping) -> bool,
) -> Option<&MemoryMapping> {
    maps.iter()
        .filter(|mapping| !mapping.name.is_empty() && wanted(mapping))
        .min_by_key(|mapping| mapping.start)
}

/// The lowest mapping of the process's own executable. Which mapping is the
/// executable's is decided through the kernel's handles, not a path: the
/// entry of `/proc/<pid>/map_files` for a mapping is the mapped file itself,
/// as `/proc/<pid>/exe` is the executable itself, so the two are the same
/// file exactly when their device and inode agree. Only where that finds
/// nothing (no privilege to read those entries, or an executable that is not
/// among the first file mappings) is the path the map prints compared with
/// the path the `exe` link prints; whatever is found is checked by content
/// afterwards, like everything else here.
fn exe_mapping<'a>(
    pid: u32,
    exe: &fs::File,
    maps: &'a [MemoryMapping],
) -> Option<&'a MemoryMapping> {
    /// The executable is the lowest file mapping of nearly every process.
    const HANDLES_TRIED: usize = 64;

    let exe_meta = exe.metadata().ok()?;
    let exe_file = (exe_meta.dev(), exe_meta.ino());
    // The map is in address order, so the first match is the lowest.
    let by_handle = maps
        .iter()
        .filter(|mapping| mapping.inode != 0 && !mapping.name.is_empty())
        .take(HANDLES_TRIED)
        .find(|mapping| {
            let by_range = format!(
                "/proc/{pid}/map_files/{:x}-{:x}",
                mapping.start, mapping.end
            );
            fs::metadata(by_range).is_ok_and(|meta| (meta.dev(), meta.ino()) == exe_file)
        });
    if by_handle.is_some() {
        return by_handle;
    }
    let exe_path = fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    let exe_path = exe_path.to_string_lossy();
    lowest_mapping(maps, |mapping| mapping.name == exe_path)
}

/// Open the file behind a mapping through the process's own map: the entry
/// of `/proc/<pid>/map_files` is that file whatever the process's mount
/// namespace, and whether or not the file still has a name. Never by the
/// path the map prints: a path is the traced process's to choose, it means
/// something else in another namespace, and an open acts (a device node, a
/// FIFO) before anything can be checked. A process whose entry cannot be
/// opened counts as gone, and its next exec is looked at again.
fn open_mapped_file(pid: u32, mapping: &MemoryMapping) -> Option<fs::File> {
    let by_range = format!(
        "/proc/{pid}/map_files/{:x}-{:x}",
        mapping.start, mapping.end
    );
    fs::File::open(by_range).ok()
}

/// Discovery's state: what each distinct file said, and the counters.
pub(crate) struct Discovery {
    /// (st_dev, st_ino, st_size) of a file -> its facts; `None` for a file
    /// that is not a 64-bit ELF file.
    files: HashMap<(u64, u64, u64), Option<ElfFacts>>,
    pub(crate) counters: DiscoveryCounters,
}

impl Discovery {
    pub(crate) fn new() -> Self {
        Self {
            files: HashMap::new(),
            counters: DiscoveryCounters::default(),
        }
    }

    /// The facts of an open file, read once per distinct file. The outer
    /// `None` is a file that could not be read at all (nothing remembered).
    fn facts_of(&mut self, file: &fs::File) -> Option<Option<ElfFacts>> {
        let meta = file.metadata().ok()?;
        let key = (meta.dev(), meta.ino(), meta.len());
        if let Some(known) = self.files.get(&key) {
            return Some(*known);
        }
        let facts = elf_facts(&ReadCache::new(file));
        if facts.is_none() {
            // Not an ELF file, or a read that failed half way? Only the
            // first is worth remembering.
            let mut header = [0u8; 64];
            if file.read_exact_at(&mut header, 0).is_err() {
                return None;
            }
        }
        if self.files.len() >= ELF_CACHE_MAX {
            self.files.clear();
        }
        self.files.insert(key, facts);
        self.counters.files_parsed += 1;
        Some(facts)
    }

    /// Look at one process and count what was found.
    pub(crate) fn look(&mut self, pid: u32) -> Finding {
        let finding = self.look_uncounted(pid);
        self.counters.looked += 1;
        match finding {
            Finding::Published(_) => self.counters.published += 1,
            Finding::NotYet => self.counters.not_yet += 1,
            Finding::Refused(refusal) => {
                self.counters.refused += 1;
                if let Some(at) = Refusal::ALL.iter().position(|each| *each == refusal) {
                    self.counters.refused_by[at] += 1;
                }
            }
            Finding::Gone => self.counters.gone += 1,
            Finding::NotLinked => {}
        }
        finding
    }

    fn look_uncounted(&mut self, pid: u32) -> Finding {
        // A kernel thread has no executable; a process that is gone has no
        // directory.
        let Ok(exe) = fs::File::open(format!("/proc/{pid}/exe")) else {
            return Finding::Gone;
        };
        let Some(exe_facts) = self.facts_of(&exe) else {
            return Finding::Gone;
        };
        let Some(exe_facts) = exe_facts else {
            return Finding::NotLinked;
        };
        if exe_facts.record_address.is_none() && !exe_facts.needs_library {
            return if exe_facts.record_refused {
                Finding::Refused(Refusal::FileRecord)
            } else {
                Finding::NotLinked
            };
        }

        // Only a process that links the library costs a read of its map.
        let maps = parse_proc_maps(pid as i32);
        if maps.is_empty() {
            return Finding::Gone;
        }
        let (facts, start, map_offset) = if exe_facts.record_address.is_some() {
            let Some(mapping) = exe_mapping(pid, &exe, &maps) else {
                return Finding::Gone;
            };
            (exe_facts, mapping.start as u64, mapping.offset)
        } else {
            let Some(mapping) = lowest_mapping(&maps, |mapping| {
                is_library_name(mapped_file_name(&mapping.name).as_bytes())
            }) else {
                // The loader has not mapped it yet.
                return Finding::NotYet;
            };
            let Some(library) = open_mapped_file(pid, mapping) else {
                return Finding::Gone;
            };
            let Some(library_facts) = self.facts_of(&library) else {
                return Finding::Gone;
            };
            match library_facts {
                Some(facts) if facts.record_address.is_some() => {
                    (facts, mapping.start as u64, mapping.offset)
                }
                Some(facts) if facts.record_refused => {
                    return Finding::Refused(Refusal::FileRecord)
                }
                _ => return Finding::NotLinked,
            }
        };
        let (Some(record_address), Some(bias)) =
            (facts.record_address, load_bias(&facts, start, map_offset))
        else {
            return Finding::Gone;
        };
        let address = bias.wrapping_add(record_address);

        let Ok(memory) = ProcessMemory::open(pid as i32) else {
            return Finding::Gone;
        };
        read_record(&memory, address)
    }
}

/// Read the record at `address` and judge it. The library stores the recipe
/// tag last, with release ordering; this side has no matching acquire to
/// give a copy made by the kernel, so a record whose tag reads "published"
/// is read a second time and the SECOND copy is the one judged: every field
/// stored before the tag is in place by then.
pub(crate) fn read_record(memory: &impl ReadMemory, address: u64) -> Finding {
    let mut record = [0u8; INFO_SIZE];
    if !memory.read_exact_at(address as usize, &mut record) {
        return Finding::Gone;
    }
    let first = validate_info(&record, address);
    if !matches!(first, Finding::Published(_)) {
        return first;
    }
    if !memory.read_exact_at(address as usize, &mut record) {
        return Finding::Gone;
    }
    validate_info(&record, address)
}

/// Every process on the host: the numeric entries of `/proc` (thread group
/// leaders only; that is what the directory lists).
pub(crate) fn all_pids() -> Vec<u32> {
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse().ok())
        .collect()
}

/// What one pass over a list of processes did.
#[derive(Debug, Default)]
pub(crate) struct Pass {
    /// Processes that publish, with their recipes.
    pub published: Vec<(u32, Recipe)>,
    /// Processes that link the library and have not published yet.
    pub not_yet: Vec<u32>,
    pub looked: usize,
    /// Processes left unlooked-at when the time ran out.
    pub not_reached: usize,
    pub elapsed: Duration,
}

impl Discovery {
    /// Look at each of `pids` until `budget` is spent. The budget is what
    /// keeps a host with very many processes from paying for a feature one
    /// of them uses: what it cuts off is counted, never silent.
    pub(crate) fn pass(&mut self, pids: &[u32], budget: Duration) -> Pass {
        let started = Instant::now();
        let mut pass = Pass::default();
        for (at, &pid) in pids.iter().enumerate() {
            if started.elapsed() >= budget {
                pass.not_reached = pids.len() - at;
                self.counters.not_reached += pass.not_reached as u64;
                break;
            }
            pass.looked += 1;
            match self.look(pid) {
                Finding::Published(recipe) => pass.published.push((pid, recipe)),
                Finding::NotYet => pass.not_yet.push(pid),
                Finding::NotLinked | Finding::Refused(_) | Finding::Gone => {}
            }
        }
        pass.elapsed = started.elapsed();
        pass
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A well-formed, published record at `address`.
    fn record_at(address: u64) -> [u8; INFO_SIZE] {
        let mut record = [0u8; INFO_SIZE];
        record[0..4].copy_from_slice(&INFO_MAGIC.to_ne_bytes());
        record[INFO_VERSION_AT..INFO_VERSION_AT + 2].copy_from_slice(&ABI_VERSION.to_ne_bytes());
        record[INFO_SIZE_AT..INFO_SIZE_AT + 2].copy_from_slice(&(INFO_SIZE as u16).to_ne_bytes());
        record[INFO_TAG_AT..INFO_TAG_AT + 4].copy_from_slice(&RECIPE_TP_OFFSET.to_ne_bytes());
        record[12..16].copy_from_slice(&1u32.to_ne_bytes());
        record[INFO_TP_OFFSET_AT..INFO_TP_OFFSET_AT + 8]
            .copy_from_slice(&good_tp_offset().to_ne_bytes());
        record[INFO_SELF_ADDRESS_AT..INFO_SELF_ADDRESS_AT + 8]
            .copy_from_slice(&address.to_ne_bytes());
        record[INFO_REGION_BASE_AT..INFO_REGION_BASE_AT + 8]
            .copy_from_slice(&0x7f00_0000_0000u64.to_ne_bytes());
        record[INFO_REGION_SIZE_AT..INFO_REGION_SIZE_AT + 8]
            .copy_from_slice(&REGION_SIZE_MAX.to_ne_bytes());
        record[INFO_BLOCK_SIZE_AT..INFO_BLOCK_SIZE_AT + 4]
            .copy_from_slice(&(BLOCK_STRIDE as u32).to_ne_bytes());
        record[INFO_BLOCK_HDR_SIZE_AT..INFO_BLOCK_HDR_SIZE_AT + 2]
            .copy_from_slice(&(BLOCK_HDR_SIZE as u16).to_ne_bytes());
        record[INFO_SLOT_SIZE_AT..INFO_SLOT_SIZE_AT + 2]
            .copy_from_slice(&(SLOT_SIZE as u16).to_ne_bytes());
        record[INFO_NSLOTS_AT..INFO_NSLOTS_AT + 2].copy_from_slice(&(SLOTS as u16).to_ne_bytes());
        record[INFO_NAME_MAX_AT..INFO_NAME_MAX_AT + 2]
            .copy_from_slice(&(NAME_MAX as u16).to_ne_bytes());
        record[INFO_VALUE_MAX_AT..INFO_VALUE_MAX_AT + 4]
            .copy_from_slice(&(VALUE_MAX as u32).to_ne_bytes());
        record
    }

    /// An offset on the side of the thread pointer this machine keeps static
    /// TLS on.
    fn good_tp_offset() -> i64 {
        if cfg!(target_arch = "aarch64") {
            16
        } else {
            -8
        }
    }

    fn with(mut record: [u8; INFO_SIZE], at: usize, bytes: &[u8]) -> [u8; INFO_SIZE] {
        record[at..at + bytes.len()].copy_from_slice(bytes);
        record
    }

    const ADDRESS: u64 = 0x55_5555_0040;

    #[test]
    fn a_published_record_gives_its_recipe() {
        assert_eq!(
            validate_info(&record_at(ADDRESS), ADDRESS),
            Finding::Published(Recipe {
                tp_offset: good_tp_offset(),
                region_base: 0x7f00_0000_0000,
                region_size: REGION_SIZE_MAX,
            })
        );
        // A later, longer record is read as far as this reader knows it.
        let longer = with(record_at(ADDRESS), INFO_SIZE_AT, &200u16.to_ne_bytes());
        assert!(matches!(
            validate_info(&longer, ADDRESS),
            Finding::Published(_)
        ));
    }

    #[test]
    fn an_unpublished_record_is_looked_at_again_not_refused() {
        let unset = with(record_at(ADDRESS), INFO_TAG_AT, &RECIPE_UNSET.to_ne_bytes());
        assert_eq!(validate_info(&unset, ADDRESS), Finding::NotYet);
        // The reserved recipes are not this reader's.
        for tag in [2u32, 3, 0x100] {
            let other = with(record_at(ADDRESS), INFO_TAG_AT, &tag.to_ne_bytes());
            assert_eq!(
                validate_info(&other, ADDRESS),
                Finding::Refused(Refusal::Tag)
            );
        }
    }

    #[test]
    fn a_record_is_refused_for_each_thing_it_can_lie_about() {
        let good = record_at(ADDRESS);
        let refused = |record: [u8; INFO_SIZE]| match validate_info(&record, ADDRESS) {
            Finding::Refused(refusal) => refusal,
            other => panic!("not refused: {other:?}"),
        };
        // What a failed read leaves behind.
        assert_eq!(refused([0u8; INFO_SIZE]), Refusal::Magic);
        assert_eq!(
            refused(with(good, INFO_VERSION_AT, &2u16.to_ne_bytes())),
            Refusal::Version
        );
        assert_eq!(
            refused(with(good, INFO_SIZE_AT, &96u16.to_ne_bytes())),
            Refusal::InfoSize
        );
        // Not where the file says the record is.
        assert_eq!(
            validate_info(&good, ADDRESS + 8),
            Finding::Refused(Refusal::SelfAddress)
        );
        // Another stride, more slots, longer values: never believed.
        for (at, bytes) in [
            (INFO_BLOCK_SIZE_AT, 4096u32.to_ne_bytes().to_vec()),
            (INFO_BLOCK_HDR_SIZE_AT, 64u16.to_ne_bytes().to_vec()),
            (INFO_SLOT_SIZE_AT, 1024u16.to_ne_bytes().to_vec()),
            (INFO_NSLOTS_AT, 64u16.to_ne_bytes().to_vec()),
            (INFO_NAME_MAX_AT, 255u16.to_ne_bytes().to_vec()),
            (INFO_VALUE_MAX_AT, 65536u32.to_ne_bytes().to_vec()),
        ] {
            assert_eq!(refused(with(good, at, &bytes)), Refusal::Geometry, "{at}");
        }
        // A region that would make the range test a formality.
        for (base, size) in [
            (0u64, REGION_SIZE_MAX),
            (0x7f00_0000_0100, REGION_SIZE_MAX),
            (0x7f00_0000_0000, REGION_SIZE_MAX + 4096),
            (0x7f00_0000_0000, 0),
            (0x7f00_0000_0000, u64::MAX),
            (u64::MAX - 4095, REGION_SIZE_MAX),
            (0xffff_8000_0000_0000, REGION_SIZE_MAX),
        ] {
            let record = with(
                with(good, INFO_REGION_BASE_AT, &base.to_ne_bytes()),
                INFO_REGION_SIZE_AT,
                &size.to_ne_bytes(),
            );
            assert_eq!(refused(record), Refusal::Region, "{base:#x} {size:#x}");
        }
        for offset in [
            0i64,
            -good_tp_offset(),
            good_tp_offset() + 1,
            good_tp_offset() * (1 << 40),
            i64::MIN,
        ] {
            let record = with(good, INFO_TP_OFFSET_AT, &offset.to_ne_bytes());
            assert_eq!(refused(record), Refusal::TpOffset, "{offset}");
        }
    }

    /// Reads served from a buffer that stands for a process's memory at
    /// `base`, counting them.
    struct FakeMemory {
        base: u64,
        bytes: Vec<u8>,
        reads: std::cell::Cell<usize>,
    }

    impl ReadMemory for FakeMemory {
        fn read_exact_at(&self, addr: usize, buf: &mut [u8]) -> bool {
            self.reads.set(self.reads.get() + 1);
            let Some(at) = (addr as u64).checked_sub(self.base) else {
                return false;
            };
            let at = at as usize;
            match self.bytes.get(at..at + buf.len()) {
                Some(bytes) => {
                    buf.copy_from_slice(bytes);
                    true
                }
                None => false,
            }
        }
    }

    #[test]
    fn a_published_record_is_read_twice_and_anything_else_once() {
        let memory = FakeMemory {
            base: ADDRESS,
            bytes: record_at(ADDRESS).to_vec(),
            reads: Default::default(),
        };
        assert!(matches!(
            read_record(&memory, ADDRESS),
            Finding::Published(_)
        ));
        assert_eq!(memory.reads.get(), 2);

        let unset = FakeMemory {
            base: ADDRESS,
            bytes: with(record_at(ADDRESS), INFO_TAG_AT, &RECIPE_UNSET.to_ne_bytes()).to_vec(),
            reads: Default::default(),
        };
        assert_eq!(read_record(&unset, ADDRESS), Finding::NotYet);
        assert_eq!(unset.reads.get(), 1);

        // Nothing mapped there.
        assert_eq!(read_record(&memory, ADDRESS - 4096), Finding::Gone);
    }

    #[test]
    fn a_record_in_this_process_is_found_through_its_own_memory() {
        // The record lives on this test's heap; its address is its own.
        let mut boxed = Box::new(record_at(0));
        let address = boxed.as_ptr() as u64;
        boxed[INFO_SELF_ADDRESS_AT..INFO_SELF_ADDRESS_AT + 8]
            .copy_from_slice(&address.to_ne_bytes());
        let memory = match ProcessMemory::open(std::process::id() as i32) {
            Ok(memory) => memory,
            Err(error) => {
                eprintln!("skipped: this process's own memory cannot be opened: {error}");
                return;
            }
        };
        assert!(matches!(
            read_record(&memory, address),
            Finding::Published(_)
        ));
        drop(boxed);
    }

    #[test]
    fn the_load_bias_is_the_writers_own_arithmetic() {
        // A position-independent object whose first segment is at address
        // 0, offset 0, mapped at 0x7f12_3456_0000.
        let pie = ElfFacts {
            record_address: Some(0x4010),
            record_refused: false,
            needs_library: false,
            first_load_address: 0,
            first_load_offset: 0,
        };
        assert_eq!(load_bias(&pie, 0x7f12_3456_0000, 0), Some(0x7f12_3456_0000));
        // An executable linked at 0x400000 and mapped there: no bias.
        let fixed = ElfFacts {
            first_load_address: 0x40_0000,
            ..pie
        };
        assert_eq!(load_bias(&fixed, 0x40_0000, 0), Some(0));
        // A first segment that starts 0x1000 into the file, seen through a
        // mapping of the file's offset 0.
        let later = ElfFacts {
            first_load_address: 0x1000,
            first_load_offset: 0x1000,
            ..pie
        };
        assert_eq!(
            load_bias(&later, 0x7f00_0000_0000, 0),
            Some(0x7f00_0000_0000)
        );
        // A lowest mapping that starts past the first segment is not the
        // file's lowest mapping.
        assert_eq!(load_bias(&pie, 0x7f00_0000_0000, 0x1000), None);
    }

    #[test]
    fn a_mapped_files_name_is_its_last_component() {
        assert_eq!(
            mapped_file_name("/usr/lib/libtask_context.so.1"),
            "libtask_context.so.1"
        );
        assert_eq!(
            mapped_file_name("/tmp/x/libtask_context.so (deleted)"),
            "libtask_context.so"
        );
        assert_eq!(mapped_file_name("[heap]"), "[heap]");
        assert!(is_library_name(b"libtask_context.so"));
        assert!(!is_library_name(b"libtask.so"));
        assert!(!is_library_name(b"mylibtask_context.so"));
    }

    // -- a small ELF file, written by hand, so that the file side is tested
    //    without a compiler ------------------------------------------------

    const LOAD_ADDRESS: u64 = 0x40_0000;

    // One section header, field by field in the order the file keeps them.
    #[allow(clippy::too_many_arguments)]
    fn push_section(
        table: &mut Vec<u8>,
        name: u32,
        kind: u32,
        flags: u64,
        address: u64,
        offset: u64,
        size: u64,
        link: u32,
        entry_size: u64,
    ) {
        table.extend_from_slice(&name.to_le_bytes());
        table.extend_from_slice(&kind.to_le_bytes());
        table.extend_from_slice(&flags.to_le_bytes());
        table.extend_from_slice(&address.to_le_bytes());
        table.extend_from_slice(&offset.to_le_bytes());
        table.extend_from_slice(&size.to_le_bytes());
        table.extend_from_slice(&link.to_le_bytes());
        table.extend_from_slice(&0u32.to_le_bytes()); // sh_info
        table.extend_from_slice(&8u64.to_le_bytes()); // sh_addralign
        table.extend_from_slice(&entry_size.to_le_bytes());
    }

    /// A little-endian ELF64 file with one loadable segment at
    /// `LOAD_ADDRESS`, optionally the record's section (holding `record`)
    /// and optionally one DT_NEEDED entry naming `needed`.
    fn small_elf(record: Option<&[u8]>, needed: Option<&str>) -> Vec<u8> {
        small_elf_padded(record, needed, 0)
    }

    /// The same, with `padding` empty entries in its dynamic section after
    /// the one that names `needed`.
    fn small_elf_padded(record: Option<&[u8]>, needed: Option<&str>, padding: usize) -> Vec<u8> {
        use object::elf;
        let machine = if cfg!(target_arch = "aarch64") {
            elf::EM_AARCH64
        } else {
            elf::EM_X86_64
        };
        let mut file = vec![0u8; 64 + 56];
        let record_at = file.len() as u64;
        file.extend_from_slice(record.unwrap_or(&[]));
        let dynstr_at = file.len() as u64;
        let mut dynstr = vec![0u8];
        if let Some(needed) = needed {
            dynstr.extend_from_slice(needed.as_bytes());
            dynstr.push(0);
        }
        file.extend_from_slice(&dynstr);
        while file.len() % 8 != 0 {
            file.push(0);
        }
        let dynamic_at = file.len() as u64;
        let mut dynamic = Vec::new();
        if needed.is_some() {
            dynamic.extend_from_slice(&u64::from(elf::DT_NEEDED).to_le_bytes());
            dynamic.extend_from_slice(&1u64.to_le_bytes());
        }
        for _ in 0..=padding {
            dynamic.extend_from_slice(&u64::from(elf::DT_NULL).to_le_bytes());
            dynamic.extend_from_slice(&0u64.to_le_bytes());
        }
        file.extend_from_slice(&dynamic);
        let names_at = file.len() as u64;
        let names = b"\0task_context_info\0.dynstr\0.dynamic\0.shstrtab\0";
        file.extend_from_slice(names);
        while file.len() % 8 != 0 {
            file.push(0);
        }
        let sections_at = file.len() as u64;

        let mut table = vec![0u8; 64]; // the null section
        let mut count = 1u16;
        if let Some(record) = record {
            push_section(
                &mut table,
                1,
                elf::SHT_PROGBITS,
                u64::from(elf::SHF_ALLOC | elf::SHF_WRITE),
                LOAD_ADDRESS + record_at,
                record_at,
                record.len() as u64,
                0,
                0,
            );
            count += 1;
        }
        let dynstr_index = u32::from(count);
        push_section(
            &mut table,
            19,
            elf::SHT_STRTAB,
            u64::from(elf::SHF_ALLOC),
            LOAD_ADDRESS + dynstr_at,
            dynstr_at,
            dynstr.len() as u64,
            0,
            0,
        );
        push_section(
            &mut table,
            27,
            elf::SHT_DYNAMIC,
            u64::from(elf::SHF_ALLOC | elf::SHF_WRITE),
            LOAD_ADDRESS + dynamic_at,
            dynamic_at,
            dynamic.len() as u64,
            dynstr_index,
            16,
        );
        push_section(
            &mut table,
            36,
            elf::SHT_STRTAB,
            0,
            0,
            names_at,
            names.len() as u64,
            0,
            0,
        );
        count += 3;
        file.extend_from_slice(&table);

        // The ELF header.
        file[0..4].copy_from_slice(&elf::ELFMAG);
        file[4] = elf::ELFCLASS64;
        file[5] = elf::ELFDATA2LSB;
        file[6] = elf::EV_CURRENT;
        file[16..18].copy_from_slice(&elf::ET_EXEC.to_le_bytes());
        file[18..20].copy_from_slice(&machine.to_le_bytes());
        file[20..24].copy_from_slice(&u32::from(elf::EV_CURRENT).to_le_bytes());
        file[24..32].copy_from_slice(&LOAD_ADDRESS.to_le_bytes()); // e_entry
        file[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        file[40..48].copy_from_slice(&sections_at.to_le_bytes()); // e_shoff
        file[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        file[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        file[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
        file[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
        file[60..62].copy_from_slice(&count.to_le_bytes()); // e_shnum
        file[62..64].copy_from_slice(&(count - 1).to_le_bytes()); // e_shstrndx

        // The one program header: the whole file, loaded at LOAD_ADDRESS.
        let size = file.len() as u64;
        let header = &mut file[64..64 + 56];
        header[0..4].copy_from_slice(&elf::PT_LOAD.to_le_bytes());
        header[4..8].copy_from_slice(&(elf::PF_R | elf::PF_W).to_le_bytes());
        header[8..16].copy_from_slice(&0u64.to_le_bytes()); // p_offset
        header[16..24].copy_from_slice(&LOAD_ADDRESS.to_le_bytes()); // p_vaddr
        header[24..32].copy_from_slice(&LOAD_ADDRESS.to_le_bytes()); // p_paddr
        header[32..40].copy_from_slice(&size.to_le_bytes()); // p_filesz
        header[40..48].copy_from_slice(&size.to_le_bytes()); // p_memsz
        header[48..56].copy_from_slice(&4096u64.to_le_bytes()); // p_align
        file
    }

    /// The record as it is in a FILE: the constants, nothing published.
    fn record_in_file() -> [u8; INFO_SIZE] {
        let mut record = record_at(0);
        for at in [
            INFO_TAG_AT,
            12,
            INFO_TP_OFFSET_AT,
            INFO_TP_OFFSET_AT + 4,
            INFO_SELF_ADDRESS_AT,
            INFO_SELF_ADDRESS_AT + 4,
            INFO_REGION_BASE_AT,
            INFO_REGION_BASE_AT + 4,
            INFO_REGION_SIZE_AT,
            INFO_REGION_SIZE_AT + 4,
        ] {
            record[at..at + 4].copy_from_slice(&[0; 4]);
        }
        record
    }

    #[test]
    fn a_file_that_carries_the_record_says_where() {
        if cfg!(target_endian = "big") {
            return; // the hand-written file is little-endian
        }
        let file = small_elf(Some(&record_in_file()), None);
        let facts = elf_facts(&file[..]).expect("an ELF file");
        assert_eq!(facts.record_address, Some(LOAD_ADDRESS + 64 + 56));
        assert!(!facts.record_refused);
        assert!(!facts.needs_library);
        assert_eq!(
            (facts.first_load_address, facts.first_load_offset),
            (LOAD_ADDRESS, 0)
        );
        // Mapped where it was linked: the record is where the file says.
        assert_eq!(load_bias(&facts, LOAD_ADDRESS, 0), Some(0));
    }

    #[test]
    fn a_section_of_that_name_that_is_not_a_record_is_refused_in_the_file() {
        if cfg!(target_endian = "big") {
            return;
        }
        let short = small_elf(Some(&record_in_file()[..96]), None);
        let facts = elf_facts(&short[..]).unwrap();
        assert_eq!((facts.record_address, facts.record_refused), (None, true));

        let mut other_geometry = record_in_file();
        other_geometry[INFO_NSLOTS_AT..INFO_NSLOTS_AT + 2].copy_from_slice(&64u16.to_ne_bytes());
        let facts = elf_facts(&small_elf(Some(&other_geometry), None)[..]).unwrap();
        assert_eq!((facts.record_address, facts.record_refused), (None, true));
    }

    #[test]
    fn a_direct_dependency_on_the_library_is_seen_and_nothing_else_is() {
        if cfg!(target_endian = "big") {
            return;
        }
        let links = small_elf(None, Some("libtask_context.so.1"));
        let facts = elf_facts(&links[..]).unwrap();
        assert!(facts.needs_library);
        assert_eq!((facts.record_address, facts.record_refused), (None, false));

        let by_path = small_elf(None, Some("/opt/lib/libtask_context.so"));
        assert!(elf_facts(&by_path[..]).unwrap().needs_library);

        let other = small_elf(None, Some("libc.so.6"));
        assert!(!elf_facts(&other[..]).unwrap().needs_library);
        let none = small_elf(None, None);
        assert!(!elf_facts(&none[..]).unwrap().needs_library);

        assert!(elf_facts(&b"not an ELF file"[..]).is_none());
    }

    /// A file states its own sizes. What starts as a good record, in a
    /// section that says it is longer than any record, is refused unread; a
    /// dynamic section past the bound is not searched, though its first
    /// entry names the library.
    #[test]
    fn a_size_the_file_states_is_followed_only_up_to_this_readers_bound() {
        if cfg!(target_endian = "big") {
            return;
        }
        let mut long = record_in_file().to_vec();
        long.resize(INFO_SECTION_MAX as usize, 0);
        let facts = elf_facts(&small_elf(Some(&long), None)[..]).unwrap();
        assert!(facts.record_address.is_some(), "at the bound it is read");
        long.push(0);
        let facts = elf_facts(&small_elf(Some(&long), None)[..]).unwrap();
        assert_eq!((facts.record_address, facts.record_refused), (None, true));

        // With the entry that names the library and the one that ends the
        // section, this many empty entries make exactly the bound.
        let at_the_bound = DYNAMIC_SECTION_MAX as usize / 16 - 2;
        let name = Some("libtask_context.so.1");
        let searched = small_elf_padded(None, name, at_the_bound);
        assert!(elf_facts(&searched[..]).unwrap().needs_library);
        let too_long = small_elf_padded(None, name, at_the_bound + 1);
        assert!(!elf_facts(&too_long[..]).unwrap().needs_library);
    }

    /// Extended numbering moves a count out of the header into section 0,
    /// where it can be any size. A file that uses it, for its segments, its
    /// sections or its section names, is not looked into at all.
    #[test]
    fn a_file_with_extended_numbering_is_not_a_file_of_interest() {
        if cfg!(target_endian = "big") {
            return;
        }
        let good = small_elf(Some(&record_in_file()), None);
        assert!(elf_facts(&good[..]).is_some());
        for (at, value) in [
            (56, 0xffffu16), // e_phnum = PN_XNUM
            (60, 0),         // e_shnum = 0 with a section table
            (62, 0xffff),    // e_shstrndx = SHN_XINDEX
        ] {
            let mut file = good.clone();
            file[at..at + 2].copy_from_slice(&value.to_le_bytes());
            assert!(elf_facts(&file[..]).is_none(), "header field at {at}");
        }
    }

    #[test]
    fn this_process_does_not_publish_and_looking_at_it_costs_no_map_read() {
        let mut discovery = Discovery::new();
        let me = std::process::id();
        assert_eq!(discovery.look(me), Finding::NotLinked);
        // The second look is answered from the table.
        assert_eq!(discovery.look(me), Finding::NotLinked);
        assert_eq!(discovery.counters.looked, 2);
        assert_eq!(discovery.counters.files_parsed, 1);
        // No such process.
        assert_eq!(discovery.look(u32::MAX - 1), Finding::Gone);
        assert_eq!(discovery.counters.gone, 1);
    }

    #[test]
    fn this_processs_own_executable_is_found_in_its_map() {
        let me = std::process::id();
        let exe = fs::File::open(format!("/proc/{me}/exe")).unwrap();
        let maps = parse_proc_maps(me as i32);
        let mapping = exe_mapping(me, &exe, &maps).expect("the executable is mapped");
        let path = fs::read_link(format!("/proc/{me}/exe")).unwrap();
        assert_eq!(mapping.name, path.to_string_lossy());
        // Nothing of the executable is mapped below what was found.
        assert!(maps
            .iter()
            .filter(|other| other.name == mapping.name)
            .all(|other| other.start >= mapping.start));
        // Its first segment is at or after the start of that mapping.
        let facts = elf_facts(&ReadCache::new(&exe)).expect("an ELF file");
        assert!(load_bias(&facts, mapping.start as u64, mapping.offset).is_some());
    }

    #[test]
    fn a_pass_stops_when_its_time_is_spent_and_says_what_it_left() {
        let mut discovery = Discovery::new();
        let me = std::process::id();
        let pass = discovery.pass(&[me, me, me], Duration::ZERO);
        assert_eq!((pass.looked, pass.not_reached), (0, 3));
        assert_eq!(discovery.counters.not_reached, 3);
        let pass = discovery.pass(&[me, me], Duration::from_secs(60));
        assert_eq!((pass.looked, pass.not_reached), (2, 0));
        assert!(pass.published.is_empty() && pass.not_yet.is_empty());
        assert!(all_pids().contains(&me));
    }

    #[test]
    fn the_summary_names_what_happened_and_why_a_record_was_refused() {
        let mut counters = DiscoveryCounters {
            looked: 5,
            published: 1,
            refused: 2,
            ..Default::default()
        };
        counters.refused_by[Refusal::ALL
            .iter()
            .position(|each| *each == Refusal::Geometry)
            .unwrap()] = 2;
        assert_eq!(
            counters.summary(),
            "looked=5 published=1 refused=2 refused_geometry=2"
        );
        assert_eq!(DiscoveryCounters::default().summary(), "");
        assert_eq!(Refusal::ALL.len(), REFUSAL_KINDS);
    }
}
