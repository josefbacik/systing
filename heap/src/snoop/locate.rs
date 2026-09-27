//! Finding jemalloc's profile table in a process.
//!
//! The table, `bt2gctx`, is a `static` in jemalloc's `prof_data.c`: no name
//! of it is exported. Two ways to its address:
//!
//! - **By symbol.** A build that keeps its `.symtab` (from source, a static
//!   binary that is not stripped, Ray's) names `bt2gctx`, and the same table
//!   names `lg_prof_sample`, the sampling period.
//! - **By shape.** A stripped library (Debian's and Ubuntu's `libjemalloc2`)
//!   has neither. But no other static in it looks like the table: a `ckh_t`
//!   whose two function pointers point into jemalloc's own code, whose `tab`
//!   points to a hash table, every entry of which is a `prof_gctx_t` that
//!   points back at itself (see [`walk::read_gctx`]). It is found by scanning
//!   the library's data for that, and only when there is exactly one.
//!
//! Either way the table found is checked against that shape before it is
//! used, so a wrong symbol (a different build than the one mapped) or an
//! unknown layout is an error, not a wrong answer.

use std::collections::HashSet;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::Path;

use anyhow::{bail, Context, Result};

use super::elf;
use super::layout::Ckh;
use super::mem::Memory;
use super::walk::{is_gctx_table, VALIDATE_BYTES};
use crate::maps::{Mapping, Maps};
use crate::root::{on_remote_fs, Root};

/// Symbols wanted. jemalloc prefixes the names it exports (`je_`, or
/// `_rjem_je_` in the Rust crate); `bt2gctx` is static and is not prefixed.
const BT2GCTX: &str = "bt2gctx";
const LG_PROF_SAMPLE: [&str; 3] = [
    "lg_prof_sample",
    "je_lg_prof_sample",
    "_rjem_je_lg_prof_sample",
];

/// The most files looked in: the ones named for jemalloc, then the program. A
/// process can map as many as it likes under such names, and each costs a scan.
const MAX_OBJECTS: usize = 8;

/// A path taken from `/proc/PID/maps` is whatever the process's owner named
/// its file. It is printed with control characters escaped, so it cannot
/// write to the terminal of whoever runs the tool.
pub fn shown(path: &str) -> String {
    path.escape_debug().to_string()
}

/// What may be spent finding the table, in all, over every file looked in.
/// The process chooses how many there are and what is in them.
#[derive(Debug, Default)]
struct Budget {
    /// Bytes of a library's data scanned.
    scanned: u64,
    /// Bytes read deciding whether a candidate is the table.
    validated: u64,
}

/// How the table was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum How {
    Symbol,
    Shape,
}

#[derive(Debug)]
pub struct Located {
    /// The address of the table's header in the process.
    pub bt2gctx: u64,
    pub how: How,
    /// The file it was found in.
    pub object: String,
    /// `lg_prof_sample`, when the file's symbols gave its address.
    pub lg_prof_sample: Option<u32>,
}

/// Find the profile of the process whose memory is `mem` and whose mappings
/// are `maps`. Files are read beneath `root`, the process's own.
pub fn locate(mem: &dyn Memory, maps: &Maps, root: &Root) -> Result<Located> {
    let objects = candidates(maps);
    if objects.is_empty() {
        bail!("the process has no file mapped");
    }
    let mut why: Vec<String> = Vec::new();
    let mut budget = Budget::default();
    for path in &objects {
        match try_object(mem, maps, root, path, &mut budget) {
            Ok(found) => return Ok(found),
            Err(e) => why.push(format!("{}: {e:#}", shown(path))),
        }
    }
    let jemalloc = objects.iter().any(|p| p.contains("jemalloc"));
    bail!(
        "no jemalloc profile found in this process{}:\n  {}",
        if jemalloc {
            ""
        } else {
            " (no jemalloc is mapped; if it is linked into the program, that is looked at too)"
        },
        why.join("\n  ")
    )
}

/// The files to look in: every mapped file with jemalloc in its name, then
/// the program itself, which may have jemalloc linked in.
fn candidates(maps: &Maps) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let files = maps.mappings().iter().filter(|m| m.is_file());
    for m in files.clone() {
        if m.path.contains("jemalloc") && !out.contains(&m.path) {
            out.push(m.path.clone());
        }
    }
    out.truncate(MAX_OBJECTS - 1);
    if let Some(exe) = files.clone().next() {
        if !out.contains(&exe.path) {
            out.push(exe.path.clone());
        }
    }
    out
}

fn try_object(
    mem: &dyn Memory,
    maps: &Maps,
    root: &Root,
    path: &str,
    budget: &mut Budget,
) -> Result<Located> {
    let ours: Vec<&Mapping> = maps.mappings().iter().filter(|m| m.path == path).collect();
    let image_start = ours
        .iter()
        .filter_map(|m| m.start.checked_sub(m.offset))
        .min()
        .context("mapped at an impossible offset")?;

    let mut note = String::new();
    // Symbols, if the file can be read and has any.
    let syms = match read_symbols(root, path) {
        Ok(s) => Some(s),
        // The file is on a filesystem that is not to be read from (or is not a
        // file): its pages, which a scan would read out of the process, may be
        // on the same one and just as slow.
        Err(Unreadable::Refused(why)) => bail!("{why}; its mapped pages are left unread too"),
        Err(Unreadable::Failed(e)) => {
            note = format!("its symbols could not be read ({e:#}); ");
            None
        }
    };
    let mut lg_prof_sample = None;
    if let Some(s) = &syms {
        let bias = s.load_bias(image_start);
        lg_prof_sample = LG_PROF_SAMPLE
            .iter()
            .find_map(|n| s.found.get(n))
            .and_then(|v| mem.u64_at(v.wrapping_add(bias)).ok())
            .and_then(|lg| u32::try_from(lg).ok())
            // Zero is a period of one byte: every allocation is sampled.
            .filter(|&lg| lg <= 63);
        if let Some(&v) = s.found.get(BT2GCTX) {
            let addr = v.wrapping_add(bias);
            let head = Ckh::read(mem, addr).context("reading bt2gctx")?;
            // A busy process can tear one of the entries looked at; a table
            // named by a symbol is worth a few tries. Its two function
            // pointers are jemalloc's own code, as the shape scan requires.
            let in_code = code_ranges(maps, path);
            if in_code(head.hash)
                && in_code(head.keycomp)
                && (0..3).any(|_| is_gctx_table(mem, &head))
            {
                return Ok(Located {
                    bt2gctx: addr,
                    how: How::Symbol,
                    object: path.to_string(),
                    lg_prof_sample,
                });
            }
            if head.count == 0 || head.tab == 0 {
                bail!("bt2gctx is empty: profiling is off (MALLOC_CONF needs prof:true) or nothing has been sampled yet");
            }
            // Not what the symbol says: the file on disk may not be the one
            // mapped (a library replaced under a process that was not
            // restarted), so look at the memory by its shape too.
            note.push_str("the bt2gctx symbol does not name the table in memory; ");
        } else {
            note.push_str("no bt2gctx symbol (stripped); ");
        }
    }
    match scan(mem, maps, path, budget)? {
        Scan::Found(addr) => Ok(Located {
            bt2gctx: addr,
            how: How::Shape,
            object: path.to_string(),
            lg_prof_sample,
        }),
        Scan::Nothing => bail!(
            "{note}no profile table found by its shape: profiling is off (MALLOC_CONF needs \
             prof:true), nothing has been sampled yet, or this is not a jemalloc layout this tool knows"
        ),
        Scan::Many(n) => bail!("{note}{n} places look like the profile table; not guessing"),
    }
}

/// Why symbols were not read.
enum Unreadable {
    /// Not to be opened: not a regular file, or on a filesystem that may stall.
    Refused(String),
    /// Could not be read (gone, not permitted, not ELF): a scan may still do.
    Failed(anyhow::Error),
}

fn read_symbols(root: &Root, path: &str) -> std::result::Result<elf::Symbols, Unreadable> {
    let failed = |e: std::io::Error| {
        Unreadable::Failed(anyhow::Error::new(e).context(format!("opening {}", shown(path))))
    };
    // Opened as a bare handle first, so nothing the file is (a device, a FIFO)
    // runs before it is known to be a plain file on a local filesystem.
    let handle = root
        .open_at(Path::new(path), libc::O_PATH)
        .map_err(failed)?;
    if !handle.metadata().map_err(failed)?.is_file() {
        return Err(Unreadable::Refused("not a regular file".into()));
    }
    // Beneath a root, the paths are whoever wrote the process's to choose; a
    // read from a mount the container only borrows could stall.
    if on_remote_fs(&handle) {
        return Err(Unreadable::Refused(
            "on a FUSE or network filesystem, left unread".into(),
        ));
    }
    let file = File::open(format!("/proc/self/fd/{}", handle.as_raw_fd())).map_err(failed)?;
    let mut wanted = vec![BT2GCTX];
    wanted.extend(LG_PROF_SAMPLE);
    elf::find(&file, &wanted).map_err(failed)
}

/// Whether an address is in a part of `path` that is mapped as code.
fn code_ranges<'a>(maps: &'a Maps, path: &'a str) -> impl Fn(u64) -> bool + 'a {
    move |a| {
        maps.mappings()
            .iter()
            .any(|m| m.path == path && m.exec && m.start <= a && a < m.end)
    }
}

/// The most of a library's data read looking for the table, and the most read
/// deciding whether candidates are it. The process may be lying about both.
const SCAN_BYTES: u64 = 1 << 30;
const VALIDATE_TOTAL: u64 = 256 << 20;

enum Scan {
    Found(u64),
    Nothing,
    Many(usize),
}

/// Scan the data of `path` for the table. The candidates are the file's
/// mappings that are not code, and the anonymous mapping right after each
/// (where zero-initialised statics live).
fn scan(mem: &dyn Memory, maps: &Maps, path: &str, budget: &mut Budget) -> Result<Scan> {
    let all = maps.mappings();
    let in_code = code_ranges(maps, path);

    let mut regions: Vec<(u64, u64)> = Vec::new();
    for (i, m) in all.iter().enumerate() {
        if m.path != path || m.exec {
            continue;
        }
        regions.push((m.start, m.end));
        if let Some(next) = all.get(i + 1) {
            if next.path.is_empty() && next.start == m.end {
                regions.push((next.start, next.end));
            }
        }
    }

    const CHUNK: usize = 1 << 20;
    const HEAD: usize = super::layout::ckh::SIZE;
    let mut hits: Vec<u64> = Vec::new();
    let mut tables_seen: HashSet<u64> = HashSet::new();
    for (start, end) in regions {
        let mut at = start;
        while at < end {
            let len = (end - at).min((CHUNK + HEAD) as u64) as usize;
            budget.scanned += len as u64;
            if budget.scanned > SCAN_BYTES {
                bail!(
                    "gave up looking for the table after {} MiB of data",
                    SCAN_BYTES >> 20
                );
            }
            let mut buf = vec![0u8; len];
            // A chunk that cannot be read (guard pages, a hole) is skipped.
            if mem.read_exact(at, &mut buf).is_ok() {
                for off in (0..len.saturating_sub(HEAD - 1)).step_by(8) {
                    // Each chunk overlaps the next by a header, and owns only
                    // the offsets before that overlap.
                    if off >= CHUNK {
                        break;
                    }
                    let head = Ckh::parse(&buf[off..off + HEAD]);
                    let (hash, keycomp) = (
                        u64::from_le_bytes(buf[off + 24..off + 32].try_into().unwrap()),
                        u64::from_le_bytes(buf[off + 32..off + 40].try_into().unwrap()),
                    );
                    if head.count == 0 || !head.plausible() || !in_code(hash) || !in_code(keycomp) {
                        continue;
                    }
                    // Many headers pointing at one table are judged once, and
                    // what is spent judging is bounded.
                    if !tables_seen.insert(head.tab) {
                        continue;
                    }
                    budget.validated += VALIDATE_BYTES;
                    if budget.validated > VALIDATE_TOTAL {
                        bail!("gave up: too many places that look like the table");
                    }
                    if is_gctx_table(mem, &head) {
                        hits.push(at + off as u64);
                    }
                }
            }
            at += CHUNK as u64;
        }
    }
    Ok(match hits.len() {
        0 => Scan::Nothing,
        1 => Scan::Found(hits[0]),
        n => Scan::Many(n),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidates_are_jemalloc_files_then_the_program() {
        let maps = Maps::parse(
            "55d000000000-55d000001000 r--p 00000000 08:01 5 /usr/bin/app\n\
             55d000001000-55d000002000 r-xp 00001000 08:01 5 /usr/bin/app\n\
             7f0000000000-7f0000001000 r--p 00000000 08:01 6 /usr/lib/libc.so.6\n\
             7f0000010000-7f0000011000 r--p 00000000 08:01 7 /usr/lib/x86_64-linux-gnu/libjemalloc.so.2\n\
             7f0000011000-7f0000012000 r-xp 00001000 08:01 7 /usr/lib/x86_64-linux-gnu/libjemalloc.so.2\n",
        );
        assert_eq!(
            candidates(&maps),
            vec![
                "/usr/lib/x86_64-linux-gnu/libjemalloc.so.2".to_string(),
                "/usr/bin/app".to_string()
            ]
        );
    }

    /// Counts what is read.
    struct Counting<'a> {
        inner: &'a crate::snoop::mem::fake::FakeMem,
        bytes: std::cell::Cell<u64>,
    }

    impl Memory for Counting<'_> {
        fn read_some(&self, addr: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.inner.read_some(addr, buf)?;
            self.bytes.set(self.bytes.get() + n as u64);
            Ok(n)
        }
    }

    #[test]
    fn many_candidates_pointing_at_one_table_read_it_once() {
        use crate::snoop::mem::fake::FakeMem;
        let maps = Maps::parse(
            "7f0000010000-7f0000011000 r-xp 00000000 08:01 7 /lib/libjemalloc.so.2\n\
             7f0000020000-7f0000022000 rw-p 00010000 08:01 7 /lib/libjemalloc.so.2\n",
        );
        // A hundred look-alikes of the table's header in the data, each with
        // code pointers into the library and the same 256 KiB `tab`, which
        // holds nothing.
        let mut data = vec![0u8; 0x2000];
        for i in 0..100usize {
            let h = &mut data[i * 48..(i + 1) * 48];
            h[8..16].copy_from_slice(&5u64.to_le_bytes());
            h[16..20].copy_from_slice(&4u32.to_le_bytes());
            h[20..24].copy_from_slice(&12u32.to_le_bytes());
            h[24..32].copy_from_slice(&0x7f00_0001_0100u64.to_le_bytes());
            h[32..40].copy_from_slice(&0x7f00_0001_0200u64.to_le_bytes());
            h[40..48].copy_from_slice(&0x7f00_0010_0000u64.to_le_bytes());
        }
        let mut fake = FakeMem::default();
        fake.put(0x7f00_0002_0000, data);
        fake.put(0x7f00_0010_0000, vec![0u8; 256 << 10]);
        let mem = Counting {
            inner: &fake,
            bytes: Default::default(),
        };
        let found = scan(&mem, &maps, "/lib/libjemalloc.so.2", &mut Budget::default()).unwrap();
        assert!(matches!(found, Scan::Nothing));
        // The data once (8 KiB) and the one table once (256 KiB), not a
        // hundred tables (25 MiB).
        assert!(
            mem.bytes.get() < 512 << 10,
            "{} bytes read",
            mem.bytes.get()
        );
    }

    #[test]
    fn what_is_spent_is_counted_over_every_file_looked_in() {
        use crate::snoop::mem::fake::FakeMem;
        let maps = Maps::parse(
            "7f0000010000-7f0000011000 r-xp 00000000 08:01 7 /lib/libjemalloc.so.2\n\
             7f0000020000-7f0000021000 rw-p 00010000 08:01 7 /lib/libjemalloc.so.2\n",
        );
        let mut fake = FakeMem::default();
        fake.put(0x7f00_0002_0000, vec![0u8; 0x1000]);
        // Scanning 4 KiB with the whole budget already spent is refused.
        let mut spent = Budget {
            scanned: SCAN_BYTES,
            ..Default::default()
        };
        assert!(scan(&fake, &maps, "/lib/libjemalloc.so.2", &mut spent).is_err());
        // With some left, it runs and adds to what was spent.
        let mut some = Budget::default();
        assert!(matches!(
            scan(&fake, &maps, "/lib/libjemalloc.so.2", &mut some).unwrap(),
            Scan::Nothing
        ));
        assert_eq!(some.scanned, 0x1000);
    }

    #[test]
    fn a_process_cannot_make_the_tool_look_in_more_than_a_few_files() {
        let mut text =
            String::from("55d000000000-55d000001000 r-xp 00000000 08:01 5 /usr/bin/app\n");
        for i in 0..100 {
            text.push_str(&format!(
                "7f00{i:08x}0000-7f00{i:08x}1000 r--p 00000000 08:01 {i} /tmp/libjemalloc{i}.so\n"
            ));
        }
        let found = candidates(&Maps::parse(&text));
        assert_eq!(found.len(), MAX_OBJECTS);
        // The program is still one of them.
        assert!(found.contains(&"/usr/bin/app".to_string()));
    }

    #[test]
    fn a_file_that_is_not_plain_is_refused_before_anything_reads_it() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("looks_like_a_library")).unwrap();
        let root = Root::open(dir.path()).unwrap();
        match read_symbols(&root, "/looks_like_a_library") {
            Err(Unreadable::Refused(why)) => assert!(why.contains("regular"), "{why}"),
            other => panic!("expected a refusal, got {}", other.is_ok()),
        }
        // A file that is not there is a failure, not a refusal: the pages of
        // a deleted library may still be scanned.
        assert!(matches!(
            read_symbols(&root, "/gone.so"),
            Err(Unreadable::Failed(_))
        ));
    }

    #[test]
    fn a_path_is_shown_with_control_characters_escaped() {
        assert_eq!(shown("/lib/a\x1b[31mb\x07"), "/lib/a\\u{1b}[31mb\\u{7}");
        assert_eq!(
            shown("/usr/lib/libjemalloc.so.2"),
            "/usr/lib/libjemalloc.so.2"
        );
    }

    #[test]
    fn a_program_that_is_all_there_is_is_the_one_candidate() {
        let maps = Maps::parse("400000-401000 r-xp 00000000 08:01 5 /bin/app\n");
        assert_eq!(candidates(&maps), vec!["/bin/app".to_string()]);
    }
}
