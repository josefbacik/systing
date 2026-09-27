//! Finding a few named symbols in an ELF file's `.symtab`.
//!
//! A stripped library has no `.symtab`, and then nothing is found; the caller
//! goes on to look for the data by its shape. The file may have been chosen
//! by whoever runs in the container, so every size read from it is bounded.

use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;

/// The most of a symbol or string table that is read.
const MAX_TABLE: u64 = 256 << 20;
const MAX_SECTIONS: u64 = 65_535;
const MAX_SEGMENTS: u64 = 4096;

const SHT_SYMTAB: u32 = 2;
const PT_LOAD: u32 = 1;
const ET_EXEC: u16 = 2;

/// What was found in one file.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Symbols {
    /// A fixed-address executable, whose symbols are addresses as they are.
    /// Anything else (a shared object, a PIE) is loaded at some base.
    pub fixed_address: bool,
    /// The lowest virtual address of a loadable segment.
    pub min_load_vaddr: u64,
    /// The addresses of the requested symbols that the file defines.
    pub found: HashMap<&'static str, u64>,
}

impl Symbols {
    /// Where the file's first page is mapped, given the mapping of its start:
    /// added to a symbol's address it gives the symbol's address in memory.
    pub fn load_bias(&self, image_start: u64) -> u64 {
        if self.fixed_address {
            0
        } else {
            image_start.wrapping_sub(self.min_load_vaddr & !0xfff)
        }
    }
}

fn invalid(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("not a usable ELF file: {what}"),
    )
}

fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}
fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// Look up `wanted` in `file`'s `.symtab`.
pub fn find(file: &File, wanted: &[&'static str]) -> io::Result<Symbols> {
    let mut eh = [0u8; 64];
    file.read_exact_at(&mut eh, 0)?;
    // ELF, 64-bit, little endian: the layouts here are those of x86-64 and
    // aarch64 Linux.
    if &eh[..4] != b"\x7fELF" || eh[4] != 2 || eh[5] != 1 {
        return Err(invalid("not 64-bit little-endian ELF"));
    }
    let e_type = u16_at(&eh, 16);
    let (e_phoff, e_shoff) = (u64_at(&eh, 32), u64_at(&eh, 40));
    let (e_phentsize, e_phnum) = (u16_at(&eh, 54) as u64, u16_at(&eh, 56) as u64);
    let (e_shentsize, e_shnum) = (u16_at(&eh, 58) as u64, u16_at(&eh, 60) as u64);

    let mut out = Symbols {
        fixed_address: e_type == ET_EXEC,
        ..Default::default()
    };

    if e_phentsize < 56 || e_phnum > MAX_SEGMENTS {
        return Err(invalid("program headers"));
    }
    let mut min_vaddr: Option<u64> = None;
    for i in 0..e_phnum {
        let mut ph = [0u8; 56];
        file.read_exact_at(&mut ph, e_phoff.saturating_add(i * e_phentsize))?;
        if u32_at(&ph, 0) == PT_LOAD {
            let vaddr = u64_at(&ph, 16);
            min_vaddr = Some(min_vaddr.map_or(vaddr, |m| m.min(vaddr)));
        }
    }
    out.min_load_vaddr = min_vaddr.unwrap_or(0);

    // No section headers: nothing to look symbols up in.
    if e_shnum == 0 || e_shoff == 0 {
        return Ok(out);
    }
    if e_shentsize < 64 || e_shnum > MAX_SECTIONS {
        return Err(invalid("section headers"));
    }
    let mut shdrs = vec![0u8; (e_shnum * e_shentsize) as usize];
    file.read_exact_at(&mut shdrs, e_shoff)?;
    let sh = |i: u64| &shdrs[(i * e_shentsize) as usize..];

    for i in 0..e_shnum {
        let s = sh(i);
        if u32_at(s, 4) != SHT_SYMTAB {
            continue;
        }
        let (sym_off, sym_size) = (u64_at(s, 24), u64_at(s, 32));
        let link = u32_at(s, 40) as u64;
        if link >= e_shnum || sym_size > MAX_TABLE {
            return Err(invalid("symbol table"));
        }
        let (str_off, str_size) = (u64_at(sh(link), 24), u64_at(sh(link), 32));
        if str_size > MAX_TABLE {
            return Err(invalid("string table"));
        }
        let mut strtab = vec![0u8; str_size as usize];
        file.read_exact_at(&mut strtab, str_off)?;

        // In chunks: a large program's table has millions of entries.
        const ENTRY: u64 = 24;
        const CHUNK: u64 = 1 << 20;
        let mut done = 0;
        while done + ENTRY <= sym_size {
            let len = CHUNK.min(sym_size - done) / ENTRY * ENTRY;
            let mut buf = vec![0u8; len as usize];
            file.read_exact_at(&mut buf, sym_off + done)?;
            for e in buf.chunks_exact(ENTRY as usize) {
                let (name, shndx, value) = (u32_at(e, 0) as usize, u16_at(e, 6), u64_at(e, 8));
                if shndx == 0 || value == 0 || name >= strtab.len() {
                    continue;
                }
                let end = strtab[name..]
                    .iter()
                    .position(|&c| c == 0)
                    .map_or(strtab.len(), |n| name + n);
                let name = &strtab[name..end];
                if let Some(&w) = wanted.iter().find(|w| w.as_bytes() == name) {
                    out.found.entry(w).or_insert(value);
                }
            }
            done += len;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[no_mangle]
    #[used]
    pub static HEAP_SNOOP_ELF_TEST_SYMBOL: u64 = 0x5eed;

    /// This test binary's own symbol table names the static above; with the
    /// load bias from /proc/self/maps its address is where the static is.
    #[test]
    fn a_symbol_is_found_at_its_address_in_memory() {
        let exe = File::open("/proc/self/exe").unwrap();
        let syms = find(
            &exe,
            &["heap_snoop_elf_test_symbol", "HEAP_SNOOP_ELF_TEST_SYMBOL"],
        )
        .unwrap();
        let value = syms.found["HEAP_SNOOP_ELF_TEST_SYMBOL"];
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
        let exe_path = std::fs::read_link("/proc/self/exe").unwrap();
        let image_start = crate::maps::Maps::parse(&maps)
            .mappings()
            .iter()
            .filter(|m| m.path == exe_path.to_str().unwrap())
            .map(|m| m.start - m.offset)
            .min()
            .unwrap();
        let addr = value + syms.load_bias(image_start);
        assert_eq!(addr, &HEAP_SNOOP_ELF_TEST_SYMBOL as *const u64 as u64);
        assert!(!syms.found.contains_key("heap_snoop_elf_test_symbol"));
    }

    #[test]
    fn something_that_is_not_elf_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x");
        std::fs::write(&path, b"#!/bin/sh\n").unwrap();
        assert!(find(&File::open(&path).unwrap(), &["a"]).is_err());
        std::fs::write(&path, [0x7f, b'E', b'L', b'F', 2, 1, 1, 0]).unwrap();
        assert!(find(&File::open(&path).unwrap(), &["a"]).is_err()); // truncated header
    }
}
