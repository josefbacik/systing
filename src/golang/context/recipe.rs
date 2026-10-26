//! What the BPF side needs to find a Go program's running goroutine, from the
//! program's executable alone: where `g` is from the thread pointer, and the
//! layout to read its id and labels with.
//!
//! The Go runtime keeps the running goroutine's `g` in a thread-local word,
//! and loads it with `mov r14, fs:[disp32]` where it needs it (every function
//! that enters Go from outside: `runtime.mstart`, signal handlers, cgo
//! callbacks). The displacement is the same in every one of them: -8 for
//! Go's own linker and for most externally linked programs. It is read from
//! the code, not assumed, and a program whose loads disagree, or that has
//! too few of them to tell, gets no recipe. Nor does a position-independent
//! program: it loads the displacement into a register first (from the GOT, or
//! as an immediate), so what has this form in it is C code.
//!
//! On arm64 there is nothing to find: Go keeps `g` in register x28 and writes
//! it to thread-local storage only under cgo, so the sampler reads the
//! register, wherever the program was loaded.
//!
//! Every executable of the host may be looked at, and a file states its own
//! sizes, so what one can make this read is bounded. It is read as
//! `task_context::discovery::elf_facts` reads one: the file header, a section
//! header table of at most [`SECTIONS_MAX`] entries, the first
//! [`BUILDINFO_MAX`] bytes of `.go.buildinfo`, and at most [`MAX_TEXT_SCAN`]
//! bytes of a Go program's code, [`SCAN_CHUNK`] at a time. No symbol table is
//! read. The runtime is linked first, so its loads of `g` are near the start,
//! and the scan stops once it has [`ENOUGH_G_LOADS`] of them.

use std::collections::HashMap;
use std::fs::File;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::sync::{Arc, LazyLock, Mutex};

use anyhow::{bail, Context, Result};
use object::elf::{FileHeader64, EM_AARCH64, EM_X86_64, ET_EXEC, PN_XNUM, SHN_XINDEX, SHT_NOBITS};
use object::read::elf::{FileHeader, SectionHeader};
use object::read::{ReadCache, ReadRef};
use object::Endianness;

use crate::golang::discovery::{version_in, version_numbers};
use crate::golang::offsets;

/// The most sections a file may state for this reader to look through them.
/// A Go program has a few dozen.
const SECTIONS_MAX: u16 = 128;
/// How much of `.go.buildinfo` is read: the version is its first string.
const BUILDINFO_MAX: u64 = 4096;

/// The fewest loads of `g` a program must have for its displacement to be
/// believed. A Go program has hundreds.
const MIN_G_LOADS: usize = 8;
/// Loads of `g` after which the scan stops.
const ENOUGH_G_LOADS: usize = 64;
/// The most of `.text` that is read, and how much at a time.
const MAX_TEXT_SCAN: u64 = 64 << 20;
const SCAN_CHUNK: u64 = 1 << 20;
/// `mov r14, fs:[disp32]`, before its displacement.
const G_LOAD: [u8; 5] = [0x64, 0x4c, 0x8b, 0x34, 0x25];
/// What a program must be built for: this machine.
const NATIVE_MACHINE: u16 = if cfg!(target_arch = "aarch64") {
    EM_AARCH64
} else {
    EM_X86_64
};

/// The recipe of one executable: the BPF map's value, as it is laid out
/// there (`struct go_context_recipe` in `bpf/go_context.bpf.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recipe {
    /// `&g's thread-local word - the thread pointer`; unused on arm64.
    pub g_tls_offset: i64,
    /// Offsets in `runtime.g`, `runtime.m` and the label types.
    pub goid: u64,
    pub labels: u64,
    pub g_m: u64,
    pub m_curg: u64,
    pub m_is_extra_in_c: u64,
    pub label_map_list: u64,
    pub label_size: u64,
    pub label_key: u64,
    pub label_value: u64,
}

impl Recipe {
    /// The map value: ten native-endian 8-byte words, in the order of
    /// `struct go_context_recipe`.
    pub fn to_bytes(self) -> [u8; 80] {
        let words = [
            self.g_tls_offset as u64,
            self.goid,
            self.labels,
            self.g_m,
            self.m_curg,
            self.m_is_extra_in_c,
            self.label_map_list,
            self.label_size,
            self.label_key,
            self.label_value,
        ];
        let mut bytes = [0u8; 80];
        for (chunk, word) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(words) {
            *chunk = word.to_ne_bytes();
        }
        bytes
    }
}

/// What looking at an executable found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    Recipe(Recipe),
    /// Not a Go program.
    NotGo,
    /// A Go program this reader cannot read: no bindings for its version,
    /// another architecture, no load of `g` to go by.
    Refused(String),
    /// The file could not be opened: the process is gone, or not ours.
    Gone,
}

/// What each executable was found to be, by (st_dev, st_ino, st_size):
/// processes of one program share its file, and finding the displacement
/// reads its code.
type Cache = HashMap<(u64, u64, u64), Arc<Finding>>;

static CACHE: LazyLock<Mutex<Cache>> = LazyLock::new(Default::default);

/// What the executable `file` (opened through a process's `/proc/<pid>/exe`)
/// is.
pub fn of_executable(file: &File) -> Finding {
    let Ok(meta) = file.metadata() else {
        return Finding::Gone;
    };
    let key = (meta.dev(), meta.ino(), meta.len());
    if let Some(cached) = CACHE.lock().unwrap().get(&key).cloned() {
        return cached.as_ref().clone();
    }
    let found = match read_recipe(file) {
        Ok(Some(recipe)) => Finding::Recipe(recipe),
        Ok(None) => Finding::NotGo,
        Err(e) => Finding::Refused(format!("{e:#}")),
    };
    CACHE.lock().unwrap().insert(key, Arc::new(found.clone()));
    found
}

fn read_recipe(file: &File) -> Result<Option<Recipe>> {
    let cache = ReadCache::new(file);
    let data = &cache;
    let Ok(header) = FileHeader64::<Endianness>::parse(data) else {
        return Ok(None);
    };
    let Ok(endian) = header.endian() else {
        return Ok(None);
    };
    // Extended numbering keeps a count too large for the header's 16 bits in
    // section 0, where a file can state billions (see `elf_facts`).
    if header.e_phnum(endian) == PN_XNUM
        || header.e_shstrndx(endian) == SHN_XINDEX
        || (header.e_shnum(endian) == 0 && header.e_shoff(endian) != 0)
        || header.e_shnum(endian) > SECTIONS_MAX
    {
        bail!("more sections than this reader looks through");
    }
    let Ok(sections) = header.sections(endian, data) else {
        return Ok(None);
    };
    if sections.section_by_name(endian, b".gopclntab").is_none() {
        return Ok(None);
    }
    if header.e_machine(endian) != NATIVE_MACHINE {
        bail!("only Go programs of this machine's architecture are supported");
    }
    // Where a section's bytes are in the file, and how many it states.
    let range = |name: &str| -> Result<(u64, u64)> {
        let (_, section) = sections
            .section_by_name(endian, name.as_bytes())
            .with_context(|| format!("no {name} section"))?;
        if section.sh_type(endian) == SHT_NOBITS {
            bail!("{name} has no bytes in the file");
        }
        Ok((section.sh_offset(endian), section.sh_size(endian)))
    };
    let (info_offset, info_size) = range(".go.buildinfo")?;
    let version = version_in(
        data.read_bytes_at(info_offset, info_size.min(BUILDINFO_MAX))
            .ok()
            .context("reading .go.buildinfo")?,
    )?;
    let Some(layout) =
        version_numbers(&version).and_then(|(a, b)| offsets::context_for_version(a, b))
    else {
        bail!("built with {version}: no bindings for its runtime's layout");
    };
    let g_tls_offset = if NATIVE_MACHINE == EM_AARCH64 {
        0
    } else {
        if header.e_type(endian) != ET_EXEC {
            bail!("a position-independent program: g is not loaded from a fixed offset");
        }
        let (text_offset, text_size) = range(".text")?;
        g_tls_offset(
            |at, buf| file.read_exact_at(buf, text_offset + at),
            text_size,
        )?
    };
    Ok(Some(Recipe {
        g_tls_offset,
        goid: layout.g_goid as u64,
        labels: layout.g_labels as u64,
        g_m: layout.g_m as u64,
        m_curg: layout.m_curg as u64,
        m_is_extra_in_c: layout.m_is_extra_in_c as u64,
        label_map_list: layout.label_map_list as u64,
        label_size: layout.label_size as u64,
        label_key: layout.label_key as u64,
        label_value: layout.label_value as u64,
    }))
}

/// The displacement of `mov r14, fs:[disp32]` (64 4c 8b 34 25 disp32) in
/// the code of `size` bytes that `read` reads (`read(at, buf)` fills `buf`
/// from `at`): the one every such load uses. Only a negative one counts: a
/// thread's static TLS lies below the thread pointer, and what lies at and
/// above it is the C library's own (`fs:0x28` is the stack protector's canary,
/// which C code linked into a cgo program loads with these same bytes). Read a chunk at a time, each
/// overlapping the last by a load's length so that none is cut in two, up to
/// [`MAX_TEXT_SCAN`] bytes or [`ENOUGH_G_LOADS`] loads.
fn g_tls_offset(read: impl Fn(u64, &mut [u8]) -> std::io::Result<()>, size: u64) -> Result<i64> {
    const LOAD_LEN: u64 = G_LOAD.len() as u64 + 4;
    let mut seen: HashMap<i32, usize> = HashMap::new();
    let mut chunk = Vec::new();
    let end = size.min(MAX_TEXT_SCAN);
    let mut at = 0;
    while at < end && seen.values().sum::<usize>() < ENOUGH_G_LOADS {
        let len = SCAN_CHUNK.min(end - at);
        chunk.resize(len as usize, 0);
        read(at, &mut chunk).context("reading .text")?;
        for w in chunk
            .windows(LOAD_LEN as usize)
            .filter(|w| w[..5] == G_LOAD)
        {
            let disp = i32::from_le_bytes(w[5..9].try_into().unwrap());
            if disp < 0 {
                *seen.entry(disp).or_default() += 1;
            }
        }
        if at + len >= end {
            break;
        }
        at += len - (LOAD_LEN - 1);
    }
    let loads: usize = seen.values().sum();
    match (seen.len(), loads) {
        (1, n) if n >= MIN_G_LOADS => Ok(i64::from(*seen.keys().next().unwrap())),
        (0, _) => bail!("no thread-local load of g in the code"),
        (1, n) => bail!("only {n} thread-local loads of g in the code"),
        (k, _) => bail!("thread-local loads of g at {k} different offsets"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(disp: i32) -> Vec<u8> {
        let mut v = vec![0x64, 0x4c, 0x8b, 0x34, 0x25];
        v.extend_from_slice(&disp.to_le_bytes());
        v
    }

    /// `g_tls_offset` over `code` in memory.
    fn scan(code: &[u8]) -> Result<i64> {
        g_tls_offset(
            |at, buf| {
                buf.copy_from_slice(&code[at as usize..at as usize + buf.len()]);
                Ok(())
            },
            code.len() as u64,
        )
    }

    #[test]
    fn the_offset_every_load_of_g_uses() {
        let mut code = Vec::new();
        for _ in 0..MIN_G_LOADS {
            code.extend(load(-8));
            code.extend([0x90, 0x90]);
        }
        assert_eq!(scan(&code).unwrap(), -8);
        // Too few to tell.
        assert!(scan(&load(-8)).is_err());
        // Two that disagree.
        code.extend(load(-16));
        assert!(scan(&code).is_err());
        assert!(scan(&[0x90; 64]).is_err());
    }

    #[test]
    fn a_load_across_two_chunks_is_seen_once() {
        // Each load straddles a chunk's end once: found once, not twice.
        let mut code = vec![0x90u8; (SCAN_CHUNK - 4) as usize];
        for _ in 0..MIN_G_LOADS {
            code.extend(load(-8));
            code.extend(vec![0x90u8; (SCAN_CHUNK - 9) as usize]);
        }
        assert_eq!(scan(&code).unwrap(), -8);
        // One more than is enough to tell, and no more: a load counted twice
        // would make one too many look like two offsets' worth.
        code.truncate(code.len() - (SCAN_CHUNK - 9) as usize - 9);
        assert!(scan(&code).is_err(), "{} loads", MIN_G_LOADS - 1);
    }

    #[test]
    fn the_c_librarys_own_words_are_not_loads_of_g() {
        // A cgo program: Go's loads, and the stack protector's in its C code.
        let mut code = Vec::new();
        for _ in 0..MIN_G_LOADS {
            code.extend(load(-8));
            code.extend(load(0x28));
        }
        assert_eq!(scan(&code).unwrap(), -8);
        // The stack protector's alone are no loads of g at all.
        let canaries: Vec<u8> = (0..MIN_G_LOADS).flat_map(|_| load(0x28)).collect();
        assert!(scan(&canaries).is_err());
    }

    #[test]
    fn a_file_that_states_too_many_sections_is_refused_unread() {
        use std::io::Write;
        // An ELF64 little-endian x86-64 header alone, over a hole of 1 GiB:
        // the extended count (0, the real one in section 0), and one too many.
        for shnum in [0u16, SECTIONS_MAX + 1] {
            let mut header = vec![0u8; 64];
            header[..8].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
            header[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
            header[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
            header[20..24].copy_from_slice(&1u32.to_le_bytes());
            header[40..48].copy_from_slice(&64u64.to_le_bytes()); // e_shoff
            header[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
            header[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
            header[60..62].copy_from_slice(&shnum.to_le_bytes());
            let mut file = tempfile::tempfile().unwrap();
            file.write_all(&header).unwrap();
            file.set_len(1 << 30).unwrap();
            assert!(read_recipe(&file).is_err(), "e_shnum {shnum}");
        }
    }

    /// Every word, each with a value of its own, in the order of
    /// `struct go_context_recipe` in `bpf/go_context.bpf.h`: two words that
    /// changed places would read wrong fields, not fail.
    #[test]
    fn a_recipe_is_ten_words_in_the_bpf_structs_order() {
        let r = Recipe {
            g_tls_offset: -8,
            goid: 1,
            labels: 2,
            g_m: 3,
            m_curg: 4,
            m_is_extra_in_c: 5,
            label_map_list: 6,
            label_size: 7,
            label_key: 8,
            label_value: 9,
        };
        let words: Vec<u64> = r
            .to_bytes()
            .as_chunks::<8>()
            .0
            .iter()
            .map(|w| u64::from_ne_bytes(*w))
            .collect();
        assert_eq!(words, [-8i64 as u64, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }

    /// The header's own words, in its own order: the one thing that ties
    /// [`Recipe::to_bytes`] to `struct go_context_recipe` before a load.
    #[test]
    fn the_bpf_struct_has_these_fields_in_this_order() {
        let header = include_str!("../bpf/go_context.bpf.h");
        let body = header
            .split("struct go_context_recipe {")
            .nth(1)
            .and_then(|rest| rest.split("};").next())
            .expect("struct go_context_recipe is in the header");
        let fields: Vec<&str> = body
            .lines()
            .filter_map(|line| line.split(';').next()?.split_whitespace().nth(1))
            .collect();
        assert_eq!(
            fields,
            [
                "g_tls_offset",
                "goid",
                "labels",
                "g_m",
                "m_curg",
                "m_is_extra_in_c",
                "label_map_list",
                "label_size",
                "label_key",
                "label_value",
            ]
        );
    }
}
