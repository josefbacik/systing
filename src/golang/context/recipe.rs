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
//! too few of them to tell, gets no recipe (a position-independent program
//! linked by the system linker reaches it through the GOT instead).

use std::collections::HashMap;
use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::{Arc, LazyLock, Mutex};

use anyhow::{bail, Context, Result};
use object::{Object, ObjectSection};

use crate::golang::discovery::{build_version, version_numbers};
use crate::golang::offsets;

/// The fewest loads of `g` a program must have for its displacement to be
/// believed. A Go program has hundreds.
const MIN_G_LOADS: usize = 8;

/// The recipe of one executable: the BPF map's value, as it is laid out
/// there (`struct go_context_recipe` in `bpf/go_context.bpf.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recipe {
    /// `&g's thread-local word - the thread pointer`.
    pub g_tls_offset: i64,
    pub goid: u64,
    pub labels: u64,
    pub label_map_list: u64,
    pub label_size: u64,
    pub label_key: u64,
    pub label_value: u64,
}

impl Recipe {
    /// The map value: seven native-endian 8-byte words.
    pub fn to_bytes(self) -> [u8; 56] {
        let words = [
            self.g_tls_offset as u64,
            self.goid,
            self.labels,
            self.label_map_list,
            self.label_size,
            self.label_key,
            self.label_value,
        ];
        let mut bytes = [0u8; 56];
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

/// What the executable at `path` (a process's `/proc/<pid>/exe`) is.
pub fn of_executable(path: &Path) -> Finding {
    let Ok(file) = File::open(path) else {
        return Finding::Gone;
    };
    let Ok(meta) = file.metadata() else {
        return Finding::Gone;
    };
    let key = (meta.dev(), meta.ino(), meta.len());
    if let Some(cached) = CACHE.lock().unwrap().get(&key).cloned() {
        return cached.as_ref().clone();
    }
    let found = match read_recipe(&file) {
        Ok(Some(recipe)) => Finding::Recipe(recipe),
        Ok(None) => Finding::NotGo,
        Err(e) => Finding::Refused(format!("{e:#}")),
    };
    CACHE.lock().unwrap().insert(key, Arc::new(found.clone()));
    found
}

fn read_recipe(file: &File) -> Result<Option<Recipe>> {
    let cache = object::read::ReadCache::new(file);
    let Ok(obj) = object::File::parse(&cache) else {
        return Ok(None);
    };
    if obj.section_by_name(".gopclntab").is_none() {
        return Ok(None);
    }
    if obj.architecture() != object::Architecture::X86_64 {
        bail!("only x86-64 Go programs are supported");
    }
    let version = build_version(&obj)?;
    let Some(layout) = version_numbers(&version).and_then(|(a, b)| offsets::for_version(a, b))
    else {
        bail!("built with {version}: no bindings for its runtime's layout");
    };
    let text = obj
        .section_by_name(".text")
        .context("no .text section")?
        .data()
        .context("reading .text")?;
    let g_tls_offset = g_tls_offset(text)?;
    Ok(Some(Recipe {
        g_tls_offset,
        goid: layout.g_goid as u64,
        labels: layout.g_labels as u64,
        label_map_list: layout.label_map_list as u64,
        label_size: layout.label_size as u64,
        label_key: layout.label_key as u64,
        label_value: layout.label_value as u64,
    }))
}

/// The displacement of `mov r14, fs:[disp32]` (64 4c 8b 34 25 disp32) in
/// `code`: the one every such load uses.
fn g_tls_offset(code: &[u8]) -> Result<i64> {
    const LOAD: [u8; 5] = [0x64, 0x4c, 0x8b, 0x34, 0x25];
    let mut seen: HashMap<i32, usize> = HashMap::new();
    let mut i = 0;
    while let Some(at) = code[i..]
        .windows(LOAD.len() + 4)
        .position(|w| w[..5] == LOAD)
    {
        let w = &code[i + at + 5..i + at + 9];
        *seen
            .entry(i32::from_le_bytes(w.try_into().unwrap()))
            .or_default() += 1;
        i += at + 9;
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

    #[test]
    fn the_offset_every_load_of_g_uses() {
        let mut code = Vec::new();
        for _ in 0..MIN_G_LOADS {
            code.extend(load(-8));
            code.extend([0x90, 0x90]);
        }
        assert_eq!(g_tls_offset(&code).unwrap(), -8);
        // Too few to tell.
        assert!(g_tls_offset(&load(-8)).is_err());
        // Two that disagree.
        code.extend(load(-16));
        assert!(g_tls_offset(&code).is_err());
        assert!(g_tls_offset(&[0x90; 64]).is_err());
    }

    #[test]
    fn a_recipe_is_seven_words() {
        let r = Recipe {
            g_tls_offset: -8,
            goid: 152,
            labels: 352,
            label_map_list: 0,
            label_size: 32,
            label_key: 0,
            label_value: 16,
        };
        let b = r.to_bytes();
        assert_eq!(i64::from_ne_bytes(b[0..8].try_into().unwrap()), -8);
        assert_eq!(u64::from_ne_bytes(b[16..24].try_into().unwrap()), 352);
    }
}
