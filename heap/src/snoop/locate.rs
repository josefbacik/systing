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
    for path in &objects {
        match try_object(mem, maps, root, path) {
            Ok(found) => return Ok(found),
            Err(e) => why.push(format!("{path}: {e:#}")),
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
    if let Some(exe) = files.clone().next() {
        if !out.contains(&exe.path) {
            out.push(exe.path.clone());
        }
    }
    out
}

fn try_object(mem: &dyn Memory, maps: &Maps, root: &Root, path: &str) -> Result<Located> {
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
        Err(e) => {
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
            .filter(|&lg| (1..=63).contains(&lg));
        if let Some(&v) = s.found.get(BT2GCTX) {
            let addr = v.wrapping_add(bias);
            let head = Ckh::read(mem, addr).context("reading bt2gctx")?;
            if is_gctx_table(mem, &head) {
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
            bail!("bt2gctx does not look like the table this tool knows (another jemalloc layout, or a file that is not the one mapped)");
        }
        note.push_str("no bt2gctx symbol (stripped); ");
    }
    match scan(mem, maps, path)? {
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

fn read_symbols(root: &Root, path: &str) -> Result<elf::Symbols> {
    let file = root
        .open_at(Path::new(path), libc::O_RDONLY | libc::O_NONBLOCK)
        .with_context(|| format!("opening {path}"))?;
    if !file.metadata()?.is_file() {
        bail!("not a regular file");
    }
    // Beneath a root, the paths are whoever wrote the process's to choose; a
    // read from a mount the container only borrows could stall.
    if on_remote_fs(&file) {
        bail!("on a FUSE or network filesystem, left unread");
    }
    let mut wanted = vec![BT2GCTX];
    wanted.extend(LG_PROF_SAMPLE);
    Ok(elf::find(&file, &wanted)?)
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
fn scan(mem: &dyn Memory, maps: &Maps, path: &str) -> Result<Scan> {
    let all = maps.mappings();
    let code: Vec<(u64, u64)> = all
        .iter()
        .filter(|m| m.path == path && m.exec)
        .map(|m| (m.start, m.end))
        .collect();
    let in_code = |a: u64| code.iter().any(|&(s, e)| s <= a && a < e);

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
    let (mut scanned, mut validated) = (0u64, 0u64);
    let mut tables_seen: HashSet<u64> = HashSet::new();
    for (start, end) in regions {
        let mut at = start;
        while at < end {
            let len = (end - at).min((CHUNK + HEAD) as u64) as usize;
            scanned += len as u64;
            if scanned > SCAN_BYTES {
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
                    validated += VALIDATE_BYTES;
                    if validated > VALIDATE_TOTAL {
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
        let found = scan(&mem, &maps, "/lib/libjemalloc.so.2").unwrap();
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
    fn a_program_that_is_all_there_is_is_the_one_candidate() {
        let maps = Maps::parse("400000-401000 r-xp 00000000 08:01 5 /bin/app\n");
        assert_eq!(candidates(&maps), vec!["/bin/app".to_string()]);
    }
}
