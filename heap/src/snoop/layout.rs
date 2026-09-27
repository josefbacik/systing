//! Where jemalloc keeps its heap profile, as bytes.
//!
//! These are the profiler's structures as jemalloc 5.3.0 and the current
//! `dev` branch lay them out on 64-bit little-endian Linux (x86-64 and
//! aarch64): `ckh_t` (`ckh.h`), `prof_gctx_t`, `prof_tctx_t` and `prof_cnt_t`
//! (`prof_structs.h` in 5.3.0, `prof.h` in `dev`). The two agree on all of
//! them. They were read off the compiler's DWARF, not counted by hand; the
//! walk does not trust them anyway, and checks every structure it reads
//! against the invariants jemalloc keeps between them (see `walk`).
//!
//! A jemalloc laid out otherwise (another major version, a debug build of the
//! counters `CKH_COUNT`, a patched fork) fails those checks and is refused.

use super::mem::Memory;

/// `ckh_t`: jemalloc's cuckoo hash table.
pub mod ckh {
    pub const SIZE: usize = 48;
    pub const COUNT: usize = 8;
    pub const LG_MIN_BUCKETS: usize = 16;
    pub const LG_CUR_BUCKETS: usize = 20;
    pub const HASH: usize = 24;
    pub const KEYCOMP: usize = 32;
    pub const TAB: usize = 40;
    /// `2^LG_CKH_BUCKET_CELLS`: one cache line of cells (`LG_CACHELINE` is 6).
    pub const CELLS_PER_BUCKET: u64 = 4;
    /// `ckhc_t`: a key and its data pointer.
    pub const CELL_SIZE: u64 = 16;
}

/// `prof_gctx_t`: one backtrace, with the counters of every thread that
/// allocated from it.
pub mod gctx {
    /// Root of the tree of `prof_tctx_t`.
    pub const TCTXS_ROOT: usize = 16;
    pub const BT_VEC: usize = 104;
    pub const BT_LEN: usize = 112;
    /// The backtrace itself, stored inline after the header.
    pub const VEC: usize = 120;
}

/// `prof_tctx_t`: one thread's counters for one backtrace.
pub mod tctx {
    pub const CNTS: usize = 32;
    pub const GCTX: usize = 96;
    /// Left child, and right child with the red-black colour in its low bit.
    pub const LINK_LEFT: usize = 112;
    pub const LINK_RIGHT_RED: usize = 120;
    pub const STATE: usize = 132;
    /// Enough of it to hold everything above.
    pub const READ: usize = 136;
    pub const STATE_INITIALIZING: u32 = 0;
}

/// `prof_cnt_t`: eight counters.
pub const CNT_SIZE: usize = 64;

/// A `ckh_t`, decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ckh {
    pub count: u64,
    pub lg_min_buckets: u32,
    pub lg_cur_buckets: u32,
    pub tab: u64,
}

/// The most buckets a table is believed to have: 2^20 buckets of 64 bytes is
/// 64 MiB, room for millions of backtraces, far past any real profile. It
/// bounds what one read can ask for.
pub const MAX_LG_BUCKETS: u32 = 20;

impl Ckh {
    pub fn parse(b: &[u8]) -> Ckh {
        let u64_at = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        let u32_at = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        Ckh {
            count: u64_at(ckh::COUNT),
            lg_min_buckets: u32_at(ckh::LG_MIN_BUCKETS),
            lg_cur_buckets: u32_at(ckh::LG_CUR_BUCKETS),
            tab: u64_at(ckh::TAB),
        }
    }

    pub fn read(mem: &dyn Memory, addr: u64) -> std::io::Result<Ckh> {
        Ok(Ckh::parse(&mem.bytes(addr, ckh::SIZE)?))
    }

    /// Whether the fields are ones a live table can have.
    pub fn plausible(&self) -> bool {
        self.tab != 0
            && self.tab & 15 == 0
            && self.lg_min_buckets >= 1
            && self.lg_min_buckets <= self.lg_cur_buckets
            && self.lg_cur_buckets <= MAX_LG_BUCKETS
            && self.count <= self.cells()
    }

    /// The number of cells in the table.
    pub fn cells(&self) -> u64 {
        ckh::CELLS_PER_BUCKET << self.lg_cur_buckets.min(MAX_LG_BUCKETS)
    }

    /// Every (key, data) cell in use, read out of the table's memory.
    pub fn entries(&self, mem: &dyn Memory) -> std::io::Result<Vec<(u64, u64)>> {
        let raw = mem.bytes(self.tab, (self.cells() * ckh::CELL_SIZE) as usize)?;
        Ok(cells_in_use(&raw).collect())
    }

    /// Up to `want` cells in use, taken from the start of the table: it is
    /// read in small pieces, and no more than `max_bytes` of it. Enough to
    /// tell what a table holds without reading all of one that may not be
    /// what it claims. A piece that cannot be read ends the reading, and what
    /// came before it is returned; only a failure of the first is an error.
    pub fn first_entries(
        &self,
        mem: &dyn Memory,
        want: usize,
        max_bytes: u64,
    ) -> std::io::Result<Vec<(u64, u64)>> {
        const PIECE: u64 = 16 << 10;
        let total = (self.cells() * ckh::CELL_SIZE).min(max_bytes);
        let mut out = Vec::new();
        let mut at = 0;
        while at < total && out.len() < want {
            let len = PIECE.min(total - at) as usize;
            match mem.bytes(self.tab.wrapping_add(at), len) {
                Ok(raw) => out.extend(cells_in_use(&raw).take(want - out.len())),
                // What was read is still what the table holds.
                Err(_) if !out.is_empty() => break,
                Err(e) => return Err(e),
            }
            at += len as u64;
        }
        Ok(out)
    }
}

fn cells_in_use(raw: &[u8]) -> impl Iterator<Item = (u64, u64)> + '_ {
    raw.as_chunks::<{ ckh::CELL_SIZE as usize }>()
        .0
        .iter()
        .map(|c| {
            (
                u64::from_le_bytes(c[..8].try_into().unwrap()),
                u64::from_le_bytes(c[8..].try_into().unwrap()),
            )
        })
        .filter(|&(key, _)| key != 0)
}

/// The eight counters of a `prof_cnt_t`, as jemalloc keeps them.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    pub cur_objs: u64,
    /// The unbiased object count, times 8 (jemalloc keeps it as an integer).
    pub cur_objs_shifted_unbiased: u64,
    pub cur_bytes: u64,
    pub cur_bytes_unbiased: u64,
    pub accum_objs: u64,
    pub accum_objs_shifted_unbiased: u64,
    pub accum_bytes: u64,
    pub accum_bytes_unbiased: u64,
}

impl Counts {
    pub fn parse(b: &[u8]) -> Counts {
        let n = |i: usize| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
        Counts {
            cur_objs: n(0),
            cur_objs_shifted_unbiased: n(1),
            cur_bytes: n(2),
            cur_bytes_unbiased: n(3),
            accum_objs: n(4),
            accum_objs_shifted_unbiased: n(5),
            accum_bytes: n(6),
            accum_bytes_unbiased: n(7),
        }
    }

    /// Add `o` in, wrapping as jemalloc's unsigned sums do, so counters read
    /// from a moving heap can never panic.
    pub fn add(&mut self, o: &Counts) {
        self.cur_objs = self.cur_objs.wrapping_add(o.cur_objs);
        self.cur_objs_shifted_unbiased = self
            .cur_objs_shifted_unbiased
            .wrapping_add(o.cur_objs_shifted_unbiased);
        self.cur_bytes = self.cur_bytes.wrapping_add(o.cur_bytes);
        self.cur_bytes_unbiased = self.cur_bytes_unbiased.wrapping_add(o.cur_bytes_unbiased);
        self.accum_objs = self.accum_objs.wrapping_add(o.accum_objs);
        self.accum_objs_shifted_unbiased = self
            .accum_objs_shifted_unbiased
            .wrapping_add(o.accum_objs_shifted_unbiased);
        self.accum_bytes = self.accum_bytes.wrapping_add(o.accum_bytes);
        self.accum_bytes_unbiased = self
            .accum_bytes_unbiased
            .wrapping_add(o.accum_bytes_unbiased);
    }

    /// What `prof_dump_gctx` prints a backtrace for: live objects, or, when
    /// jemalloc accumulates, any allocation ever made from it. A count of
    /// accumulated objects is nonzero whenever the live count is, so this one
    /// test covers both settings.
    pub fn is_reported(&self) -> bool {
        self.cur_objs != 0 || self.accum_objs != 0
    }
}
