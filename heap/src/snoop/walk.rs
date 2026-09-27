//! Reading jemalloc's heap profile out of memory.
//!
//! This does what `prof_dump_impl` does, minus the locks and the file: take
//! every backtrace in the global table `bt2gctx`, and for each add up the
//! counters of the threads that allocated from it.
//!
//! ```text
//! bt2gctx (ckh)  --data-->  prof_gctx_t  --tctxs-->  prof_tctx_t (red-black tree)
//!                           bt: the stack            cnts: this thread's counters
//! ```
//!
//! jemalloc takes locks so that a dump sees a still picture. Here nothing is
//! locked and the process goes on, so anything read can be wrong: a table can
//! be swapped for a larger one, and a `gctx` or `tctx` freed and its memory
//! reused, between one read and the next. Nothing read from the process is
//! believed for its own sake:
//!
//! - a `gctx` must have jemalloc's own invariants (its table key is the
//!   address of its `bt`, whose `vec` is its inline array), else it is reused
//!   memory and is skipped;
//! - a `tctx` must point back at the `gctx` it was found under;
//! - every loop and every length is bounded;
//! - the table pointer is read again after the walk, and a walk during which
//!   it changed is done again.
//!
//! Counters are read as the process updates them, so a stack's numbers can be
//! from slightly different moments, as a live `mallctl` read of them would be.

use std::collections::HashSet;
use std::io;

use super::layout::{gctx, tctx, Ckh, Counts, CNT_SIZE};
use super::mem::Memory;

/// The most frames read for one stack. jemalloc keeps 128 by default; `dev`
/// lets `opt.prof_bt_max` raise that.
const MAX_FRAMES: usize = 8192;
/// Frames read with the header, in the same read; nearly every stack fits.
const FIRST_FRAMES: usize = 32;
/// The most `prof_tctx_t` visited under one `gctx`: one per allocating thread.
const MAX_TCTX_PER_GCTX: usize = 1 << 16;
/// The most visited in a whole walk. A real profile has a few per backtrace;
/// a table that claims millions of backtraces with thousands of threads each
/// is not one, and is not read to the end.
const MAX_TCTX_TOTAL: u64 = 1 << 22;
/// The most frames held over a whole walk: 2^25 addresses is 256 MiB. Real
/// profiles have a few million (hundreds of thousands of stacks of tens of
/// frames); a process that lays out records to make each claim thousands of
/// frames could otherwise make the tool hold tens of GiB.
const MAX_FRAMES_TOTAL: u64 = 1 << 25;
/// The most of a table read to decide whether it holds backtraces.
pub const VALIDATE_BYTES: u64 = 1 << 20;
/// How many times a walk is done again when the table changed under it.
const ATTEMPTS: u32 = 5;

/// What went wrong along the way, and did not stop the walk.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Stats {
    /// Walks done again because the table changed during them.
    pub retries: u32,
    /// `gctx` read: backtraces that passed the shape check.
    pub gctx_read: u64,
    /// `gctx` skipped: freed or reused while being read.
    pub gctx_skipped: u64,
    /// `tctx` skipped for the same reason.
    pub tctx_skipped: u64,
    /// `tctx` read and counted.
    pub tctx_read: u64,
    /// Parent and child thread records compared for the tree's order, and
    /// those out of it (see [`read_tctxs`]).
    pub order_checked: u64,
    pub order_violated: u64,
    /// Thread records whose counters were compared with each other, and those
    /// that cannot be jemalloc's (see [`read_tctxs`]).
    pub counters_checked: u64,
    pub counters_violated: u64,
    /// The table was changing while it was read, and kept changing for every
    /// attempt: jemalloc was rebuilding it, or moving entries in it. The
    /// profile is what was read last and may be missing stacks.
    pub unsteady: bool,
}

/// What a walk will not go past.
#[derive(Debug, Clone, Copy)]
struct Limits {
    max_tctx: u64,
    max_frames: u64,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_tctx: MAX_TCTX_TOTAL,
            max_frames: MAX_FRAMES_TOTAL,
        }
    }
}

/// One backtrace and its counters, added up over all threads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stack {
    /// Return addresses, innermost first, as jemalloc stores them.
    pub addrs: Vec<u64>,
    pub counts: Counts,
}

#[derive(Debug)]
pub struct Profile {
    /// The stacks jemalloc would dump, in address order.
    pub stacks: Vec<Stack>,
    pub stats: Stats,
}

/// Read the profile whose table header is at `bt2gctx`.
pub fn walk(mem: &dyn Memory, bt2gctx: u64) -> io::Result<Profile> {
    walk_limited(mem, bt2gctx, Limits::default())
}

fn walk_limited(mem: &dyn Memory, bt2gctx: u64, limits: Limits) -> io::Result<Profile> {
    let mut retries = 0;
    let mut last = io::Error::other("the profile kept changing");
    // A walk that was not clean, kept in case none is.
    let mut best: Option<Profile> = None;
    for _ in 0..ATTEMPTS {
        let head = Ckh::read(mem, bt2gctx)?;
        if !head.plausible() {
            last = io::Error::new(
                io::ErrorKind::InvalidData,
                "the table at bt2gctx is not a jemalloc hash table",
            );
            retries += 1;
            continue;
        }
        let entries = match head.entries(mem) {
            Ok(e) => e,
            Err(e) => {
                last = e;
                retries += 1;
                continue;
            }
        };
        let mut stats = Stats::default();
        let mut stacks = read_stacks(mem, &entries, &mut stats, limits)?;
        let after = Ckh::read(mem, bt2gctx)?;
        // The table was swapped for another meanwhile.
        if (after.tab, after.lg_cur_buckets) != (head.tab, head.lg_cur_buckets) {
            retries += 1;
            continue;
        }
        stacks.sort_by(|a, b| a.addrs.cmp(&b.addrs));
        // At rest, the cells in use are what `count` says. They are far from
        // it while jemalloc rebuilds the table (it stores the new table first,
        // sets `count` to 0 and inserts the entries again), so that read may be
        // missing stacks, though the table's own fields are the same before and
        // after. A few entries either way is a process adding and removing
        // stacks as it runs, which every busy one does all the time.
        let slack = (head.count / 64).max(2);
        let at_rest = (entries.len() as u64).abs_diff(head.count) <= slack
            && head.count.abs_diff(after.count) <= slack;
        // A record that was freed and reused under the walk, or a tree that
        // was rotated under it, shows as records skipped: worth another go.
        let skips = stats.gctx_skipped + stats.tctx_skipped;
        if at_rest && skips == 0 {
            stats.retries = retries;
            return Ok(Profile { stacks, stats });
        }
        stats.unsteady = !at_rest;
        // Of the walks that were not clean, the one with the fewest problems.
        let problems = |p: &Profile| {
            p.stats.gctx_skipped + p.stats.tctx_skipped + u64::from(p.stats.unsteady) * (1 << 40)
        };
        let candidate = Profile { stacks, stats };
        if best
            .as_ref()
            .is_none_or(|b| problems(&candidate) < problems(b))
        {
            best = Some(candidate);
        }
        retries += 1;
    }
    match best {
        Some(mut profile) => {
            profile.stats.retries = retries;
            Ok(profile)
        }
        None => Err(last),
    }
}

fn read_stacks(
    mem: &dyn Memory,
    entries: &[(u64, u64)],
    stats: &mut Stats,
    limits: Limits,
) -> io::Result<Vec<Stack>> {
    let mut seen = HashSet::new();
    let mut stacks = Vec::new();
    let mut frames = 0u64;
    for &(key, gaddr) in entries {
        // Cuckoo hashing moves entries: one seen twice is one entry.
        if !seen.insert(gaddr) {
            continue;
        }
        let Some((root, addrs)) = read_gctx(mem, key, gaddr) else {
            stats.gctx_skipped += 1;
            continue;
        };
        stats.gctx_read += 1;
        let mut counts = Counts::default();
        for c in read_tctxs(mem, gaddr, root, stats) {
            counts.add(&c);
        }
        if counts.is_reported() {
            frames += addrs.len() as u64;
            stacks.push(Stack { addrs, counts });
        }
        if stats.tctx_read + stats.tctx_skipped > limits.max_tctx {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "more per-thread records than any real profile has; not reading on",
            ));
        }
        if frames > limits.max_frames {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "more stack frames than any real profile has; not reading on",
            ));
        }
    }
    Ok(stacks)
}

fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// The root of a `gctx`'s tctx tree and its stack, if `gaddr` is a `gctx` that
/// the table `key`s. Also the check a candidate table is found by: jemalloc
/// sets `key` to the address of the `gctx`'s own `bt`, and `bt.vec` to its own
/// inline `vec`.
pub fn read_gctx(mem: &dyn Memory, key: u64, gaddr: u64) -> Option<(u64, Vec<u64>)> {
    if key != gaddr.checked_add(gctx::BT_VEC as u64)? {
        return None;
    }
    let want = gctx::VEC + FIRST_FRAMES * 8;
    let mut buf = vec![0u8; want];
    // A gctx at the end of a mapping may have fewer bytes than that after it.
    let mut have = 0;
    while have < gctx::VEC {
        match mem.read_some(gaddr.checked_add(have as u64)?, &mut buf[have..]) {
            Ok(n) => have += n,
            Err(_) => return None,
        }
    }
    let vec_ptr = u64_at(&buf, gctx::BT_VEC);
    let len = u32::from_le_bytes(buf[gctx::BT_LEN..gctx::BT_LEN + 4].try_into().unwrap()) as usize;
    if vec_ptr != gaddr.checked_add(gctx::VEC as u64)? || len == 0 || len > MAX_FRAMES {
        return None;
    }
    let total = gctx::VEC + len * 8;
    if have < total {
        buf.resize(total, 0);
        mem.read_exact(gaddr.checked_add(have as u64)?, &mut buf[have..total])
            .ok()?;
    }
    let root = u64_at(&buf, gctx::TCTXS_ROOT);
    let addrs = (0..len).map(|i| u64_at(&buf, gctx::VEC + i * 8)).collect();
    Some((root, addrs))
}

/// The key jemalloc orders a `gctx`'s tree of thread records by
/// (`prof_tctx_comp`): the thread, then which of its tdata, then the record.
type TctxKey = (u64, u64, u64);

/// The counters of every `tctx` in a `gctx`'s tree that a dump would add up.
///
/// Two things are checked across the whole walk and not record by record, since
/// a moving heap breaks either for a moment, and `refuse_unusable` looks at the
/// share: that each left child sorts below its parent and each right child
/// above (the tree's own order, which ties the link offsets to the key
/// offsets), and that a record's unbiased counters are at least its raw ones
/// (each sampled object adds at least 8 to the shifted count and at least its
/// size to the unbiased bytes, `prof_unbias_map_init`).
fn read_tctxs(mem: &dyn Memory, gaddr: u64, root: u64, stats: &mut Stats) -> Vec<Counts> {
    let mut out = Vec::new();
    // Each address to visit, with its parent's key and which side it hangs on.
    let mut todo: Vec<(u64, Option<(TctxKey, bool)>)> = vec![(root, None)];
    let mut seen = HashSet::new();
    while let Some((addr, parent)) = todo.pop() {
        if addr == 0 {
            continue;
        }
        // The visited set bounds a tree that a torn read made cyclic.
        if seen.len() >= MAX_TCTX_PER_GCTX {
            stats.tctx_skipped += 1;
            break;
        }
        if !seen.insert(addr) {
            continue;
        }
        let Ok(b) = mem.bytes(addr, tctx::READ) else {
            stats.tctx_skipped += 1;
            continue;
        };
        if u64_at(&b, tctx::GCTX) != gaddr {
            stats.tctx_skipped += 1;
            continue;
        }
        // What the enum holds is one of four values: anything else is not a
        // `prof_tctx_t`, and its links are not followed.
        let state = u32::from_le_bytes(b[tctx::STATE..tctx::STATE + 4].try_into().unwrap());
        if state > tctx::STATE_MAX {
            stats.tctx_skipped += 1;
            continue;
        }
        let key: TctxKey = (
            u64_at(&b, tctx::THR_UID),
            u64_at(&b, tctx::THR_DISCRIM),
            u64_at(&b, tctx::TCTX_UID),
        );
        if let Some((parent_key, is_left)) = parent {
            stats.order_checked += 1;
            if (is_left && key >= parent_key) || (!is_left && key <= parent_key) {
                stats.order_violated += 1;
            }
        }
        // The low bit of the right link is the node's colour. A child is
        // either NULL or the address of a record, which is 8-aligned.
        for (child, is_left) in [
            (u64_at(&b, tctx::LINK_LEFT), true),
            (u64_at(&b, tctx::LINK_RIGHT_RED) & !1, false),
        ] {
            if child & 7 != 0 {
                stats.tctx_skipped += 1;
            } else {
                todo.push((child, Some((key, is_left))));
            }
        }
        // prof_tctx_merge_tdata() leaves a tctx that is `initializing` out of
        // a dump, and so does this. It is counted as skipped, so that a layout
        // whose "state" is some other field, which reads as 0 wherever a node
        // has no right child, does not pass for an idle process. (jemalloc
        // 5.3.0 links a record into the tree only once it is nominal.)
        if state == tctx::STATE_INITIALIZING {
            stats.tctx_skipped += 1;
            continue;
        }
        let c = Counts::parse(&b[tctx::CNTS..tctx::CNTS + CNT_SIZE]);
        if c.cur_objs > 0 {
            stats.counters_checked += 1;
            if c.cur_objs_shifted_unbiased < c.cur_objs.saturating_mul(8)
                || c.cur_bytes_unbiased < c.cur_bytes
            {
                stats.counters_violated += 1;
            }
        }
        stats.tctx_read += 1;
        out.push(c);
    }
    out
}

/// Whether the table at `head` holds jemalloc backtraces: at least one entry,
/// and each of the first few a real `gctx`. This is what finds `bt2gctx`
/// in a library with no symbols, and what confirms one that has them.
pub fn is_gctx_table(mem: &dyn Memory, head: &Ckh) -> bool {
    if !head.plausible() {
        return false;
    }
    // The first few entries are enough to tell, and all of a table that may
    // not be one is not worth reading.
    let Ok(entries) = head.first_entries(mem, 16, VALIDATE_BYTES) else {
        return false;
    };
    !entries.is_empty()
        && entries
            .iter()
            .all(|&(key, gaddr)| read_gctx(mem, key, gaddr).is_some())
}

#[cfg(test)]
mod tests {
    use super::super::layout::ckh;
    use super::super::mem::fake::FakeMem;
    use super::*;
    use std::cell::{Cell, RefCell};

    const HEADER: u64 = 0x1000;
    const TAB: u64 = 0x2000;
    const LG: u32 = 4;

    fn put_u64(v: &mut [u8], o: usize, x: u64) {
        v[o..o + 8].copy_from_slice(&x.to_le_bytes());
    }

    fn counts_bytes(c: [u64; 8]) -> Vec<u8> {
        c.iter().flat_map(|x| x.to_le_bytes()).collect()
    }

    /// A process's memory with a profile in it, made the way jemalloc lays it
    /// out.
    struct Heap {
        mem: FakeMem,
        cells: Vec<(u64, u64)>,
    }

    impl Heap {
        fn new() -> Heap {
            Heap {
                mem: FakeMem::default(),
                cells: Vec::new(),
            }
        }

        /// Set the key a `tctx` is ordered by.
        fn key(&mut self, at: u64, key: (u64, u64, u64)) {
            self.mem.poke_u64(at + tctx::THR_UID as u64, key.0);
            self.mem.poke_u64(at + tctx::THR_DISCRIM as u64, key.1);
            self.mem.poke_u64(at + tctx::TCTX_UID as u64, key.2);
        }

        /// A perfect binary tree of `tctx` for keys `lo..=hi` under `gaddr`,
        /// ordered as jemalloc orders them (reversed if `backwards`); the
        /// address of its root.
        fn tree(&mut self, gaddr: u64, lo: u64, hi: u64, backwards: bool) -> u64 {
            if lo > hi {
                return 0;
            }
            let mid = (lo + hi) / 2;
            let at = 0x100000 + mid * 0x100;
            let left = self.tree(gaddr, lo, mid.wrapping_sub(1), backwards);
            let right = self.tree(gaddr, mid + 1, hi, backwards);
            self.tctx(at, gaddr, left, right, NOMINAL, (1, 100));
            // The thread first, the record last: order on any of the three.
            let k = if backwards { 100 - mid } else { mid };
            self.key(at, (k, 0, 0));
            at
        }

        /// A `tctx` under `gaddr`, with its children, and its counters.
        fn tctx(
            &mut self,
            at: u64,
            gaddr: u64,
            left: u64,
            right: u64,
            state: u32,
            cur: (u64, u64),
        ) {
            let mut b = vec![0u8; 256];
            let c = counts_bytes([
                cur.0,
                cur.0 * 8,
                cur.1,
                cur.1,
                cur.0,
                cur.0 * 8,
                cur.1,
                cur.1,
            ]);
            b[tctx::CNTS..tctx::CNTS + 64].copy_from_slice(&c);
            put_u64(&mut b, tctx::GCTX, gaddr);
            put_u64(&mut b, tctx::LINK_LEFT, left);
            put_u64(&mut b, tctx::LINK_RIGHT_RED, right);
            b[tctx::STATE..tctx::STATE + 4].copy_from_slice(&state.to_le_bytes());
            self.mem.put(at, b);
        }

        /// A `gctx` for `frames`, whose tree starts at `root`; entered in the
        /// table.
        fn gctx(&mut self, at: u64, frames: &[u64], root: u64) {
            let mut b = vec![0u8; gctx::VEC + frames.len() * 8];
            put_u64(&mut b, gctx::TCTXS_ROOT, root);
            put_u64(&mut b, gctx::BT_VEC, at + gctx::VEC as u64);
            b[gctx::BT_LEN..gctx::BT_LEN + 4].copy_from_slice(&(frames.len() as u32).to_le_bytes());
            for (i, f) in frames.iter().enumerate() {
                put_u64(&mut b, gctx::VEC + i * 8, *f);
            }
            self.mem.put(at, b);
            self.cells.push((at + gctx::BT_VEC as u64, at));
        }

        /// Write the table and its header.
        fn finish(mut self) -> FakeMem {
            let ncells = (ckh::CELLS_PER_BUCKET << LG) as usize;
            let mut tab = vec![0u8; ncells * 16];
            for (i, (k, d)) in self.cells.iter().enumerate() {
                // Any free cell will do; spread them out.
                let cell = i * 5 % ncells;
                put_u64(&mut tab, cell * 16, *k);
                put_u64(&mut tab, cell * 16 + 8, *d);
            }
            self.mem.put(TAB, tab);
            let mut h = vec![0u8; ckh::SIZE];
            put_u64(&mut h, ckh::COUNT, self.cells.len() as u64);
            h[ckh::LG_MIN_BUCKETS..ckh::LG_MIN_BUCKETS + 4].copy_from_slice(&2u32.to_le_bytes());
            h[ckh::LG_CUR_BUCKETS..ckh::LG_CUR_BUCKETS + 4].copy_from_slice(&LG.to_le_bytes());
            put_u64(&mut h, ckh::TAB, TAB);
            self.mem.put(HEADER, h);
            self.mem
        }
    }

    const NOMINAL: u32 = 1;

    #[test]
    fn counters_are_added_up_over_a_stacks_threads() {
        let mut h = Heap::new();
        // Three threads' tctx in a tree: 0x100000 with a left and a red right child.
        h.tctx(0x100000, 0x10000, 0x100400, 0x100800 | 1, NOMINAL, (2, 200));
        h.tctx(0x100400, 0x10000, 0, 0, NOMINAL, (3, 300));
        h.tctx(0x100800, 0x10000, 0, 0, NOMINAL, (5, 500));
        h.gctx(0x10000, &[0xa1, 0xa2, 0xa3], 0x100000);
        // A stack that has nothing live is not in a dump.
        h.tctx(0x101000, 0x10400, 0, 0, NOMINAL, (0, 0));
        h.gctx(0x10400, &[0xb1], 0x101000);
        let mem = h.finish();

        let p = walk(&mem, HEADER).unwrap();
        assert_eq!(p.stacks.len(), 1);
        assert_eq!(p.stacks[0].addrs, vec![0xa1, 0xa2, 0xa3]);
        assert_eq!(p.stacks[0].counts.cur_objs, 10);
        assert_eq!(p.stacks[0].counts.cur_bytes, 1000);
        assert_eq!(p.stacks[0].counts.cur_objs_shifted_unbiased, 80);
        assert_eq!(p.stats.tctx_read, 4);
        assert_eq!(p.stats.gctx_read, 2);
        assert_eq!(
            (p.stats.retries, p.stats.gctx_skipped, p.stats.tctx_skipped),
            (0, 0, 0)
        );
        assert!(!p.stats.unsteady);
    }

    #[test]
    fn a_tctx_still_being_set_up_is_left_out_as_a_dump_leaves_it() {
        let mut h = Heap::new();
        h.tctx(0x100000, 0x10000, 0x100400, 0, NOMINAL, (2, 200));
        h.tctx(0x100400, 0x10000, 0, 0, tctx::STATE_INITIALIZING, (9, 900));
        h.gctx(0x10000, &[0xa1], 0x100000);
        let p = walk(&h.finish(), HEADER).unwrap();
        assert_eq!(p.stacks[0].counts.cur_objs, 2);
    }

    #[test]
    fn memory_that_is_not_what_it_was_is_skipped_not_believed() {
        let mut h = Heap::new();
        h.tctx(0x100000, 0x10000, 0, 0, NOMINAL, (2, 200));
        h.gctx(0x10000, &[0xa1], 0x100000);
        // A gctx freed and reused: its table key no longer points at its bt.
        h.tctx(0x101000, 0x10400, 0, 0, NOMINAL, (7, 700));
        h.gctx(0x10400, &[0xb1], 0x101000);
        h.cells.last_mut().unwrap().0 = 0xdead_beef;
        // A gctx whose vec points somewhere else.
        h.tctx(0x102000, 0x10800, 0, 0, NOMINAL, (7, 700));
        h.gctx(0x10800, &[0xc1], 0x102000);
        // A gctx that says it has far too many frames.
        h.tctx(0x103000, 0x10c00, 0, 0, NOMINAL, (7, 700));
        h.gctx(0x10c00, &[0xd1], 0x103000);
        let mut mem = h.finish();
        mem.poke_u64(0x10800 + gctx::BT_VEC as u64, 0x1234);
        mem.poke(0x10c00 + gctx::BT_LEN as u64, &u32::MAX.to_le_bytes());
        // A tctx that belongs to another gctx.
        let mut h2 = Heap::new();
        h2.tctx(0x100000, 0x99999, 0, 0, NOMINAL, (2, 200));
        h2.gctx(0x10000, &[0xe1], 0x100000);
        let p2 = walk(&h2.finish(), HEADER).unwrap();
        assert!(p2.stacks.is_empty());
        assert_eq!(p2.stats.tctx_skipped, 1);

        let p = walk(&mem, HEADER).unwrap();
        assert_eq!(p.stacks.len(), 1);
        assert_eq!(p.stacks[0].addrs, vec![0xa1]);
        assert_eq!(p.stats.gctx_skipped, 3);
    }

    #[test]
    fn a_tree_torn_into_a_cycle_ends() {
        let mut h = Heap::new();
        h.tctx(0x100000, 0x10000, 0x100400, 0x100400, NOMINAL, (1, 100));
        // Its child points back at it.
        h.tctx(0x100400, 0x10000, 0x100000, 0x100000, NOMINAL, (1, 100));
        h.gctx(0x10000, &[0xa1], 0x100000);
        let p = walk(&h.finish(), HEADER).unwrap();
        assert_eq!(p.stacks[0].counts.cur_objs, 2);
    }

    #[test]
    fn a_stack_longer_than_the_first_read_is_read_whole() {
        let frames: Vec<u64> = (1..=100).map(|i| 0x7000_0000 + i).collect();
        let mut h = Heap::new();
        h.tctx(0x100000, 0x10000, 0, 0, NOMINAL, (1, 100));
        h.gctx(0x10000, &frames, 0x100000);
        let p = walk(&h.finish(), HEADER).unwrap();
        assert_eq!(p.stacks[0].addrs, frames);
    }

    /// Serves the table header differently the second time it is read, as if
    /// the table had been swapped for another during the walk.
    struct Swapped {
        inner: RefCell<FakeMem>,
        header_reads: Cell<u32>,
    }

    impl Memory for Swapped {
        fn read_some(&self, addr: u64, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.inner.borrow().read_some(addr, buf)?;
            if addr == HEADER {
                let k = self.header_reads.get();
                self.header_reads.set(k + 1);
                if k == 1 {
                    buf[ckh::TAB..ckh::TAB + 8].copy_from_slice(&0x9000u64.to_le_bytes());
                }
            }
            Ok(n)
        }
    }

    #[test]
    fn a_walk_during_which_the_table_was_swapped_is_done_again() {
        let mut h = Heap::new();
        h.tctx(0x100000, 0x10000, 0, 0, NOMINAL, (2, 200));
        h.gctx(0x10000, &[0xa1], 0x100000);
        let mem = Swapped {
            inner: RefCell::new(h.finish()),
            header_reads: Cell::new(0),
        };
        let p = walk(&mem, HEADER).unwrap();
        assert_eq!(p.stacks.len(), 1);
        assert_eq!(p.stats.retries, 1);
    }

    #[test]
    fn a_table_that_is_not_one_is_an_error() {
        let mut h = Heap::new();
        h.gctx(0x10000, &[0xa1], 0);
        let mut mem = h.finish();
        mem.poke(HEADER + ckh::LG_CUR_BUCKETS as u64, &99u32.to_le_bytes());
        assert!(walk(&mem, HEADER).is_err());
        assert!(!is_gctx_table(&mem, &Ckh::read(&mem, HEADER).unwrap()));
    }

    #[test]
    fn a_walk_stops_at_more_records_than_a_profile_has() {
        let mut h = Heap::new();
        // One gctx with a chain of four tctx.
        h.tctx(0x100000, 0x10000, 0x100400, 0, NOMINAL, (1, 100));
        h.tctx(0x100400, 0x10000, 0x100800, 0, NOMINAL, (1, 100));
        h.tctx(0x100800, 0x10000, 0x100c00, 0, NOMINAL, (1, 100));
        h.tctx(0x100c00, 0x10000, 0, 0, NOMINAL, (1, 100));
        h.gctx(0x10000, &[0xa1], 0x100000);
        let mem = h.finish();
        let limit = |max_tctx| Limits {
            max_tctx,
            ..Limits::default()
        };
        assert!(walk_limited(&mem, HEADER, limit(3)).is_err());
        let p = walk_limited(&mem, HEADER, limit(4)).unwrap();
        assert_eq!(p.stacks[0].counts.cur_objs, 4);
    }

    #[test]
    fn a_walk_stops_at_more_frames_than_a_profile_has() {
        let mut h = Heap::new();
        for i in 0..3u64 {
            let (g, t) = (0x10000 + i * 0x400, 0x100000 + i * 0x400);
            h.tctx(t, g, 0, 0, NOMINAL, (1, 100));
            h.gctx(g, &[0xa1, 0xa2, 0xa3, 0xa4], t);
        }
        let mem = h.finish();
        let limit = |max_frames| Limits {
            max_frames,
            ..Limits::default()
        };
        assert!(walk_limited(&mem, HEADER, limit(11)).is_err());
        assert_eq!(
            walk_limited(&mem, HEADER, limit(12)).unwrap().stacks.len(),
            3
        );
    }

    #[test]
    fn a_tree_in_jemallocs_order_is_not_flagged_and_one_out_of_it_is() {
        for (backwards, violated) in [(false, 0), (true, 14)] {
            let mut h = Heap::new();
            let root = h.tree(0x10000, 1, 15, backwards);
            h.gctx(0x10000, &[0xa1], root);
            let p = walk(&h.finish(), HEADER).unwrap();
            assert_eq!(p.stats.tctx_read, 15);
            assert_eq!(
                (p.stats.order_checked, p.stats.order_violated),
                (14, violated),
                "backwards {backwards}"
            );
        }
    }

    #[test]
    fn counters_that_cannot_be_jemallocs_are_counted() {
        let mut h = Heap::new();
        // Eight records: the first four with an unbiased count below the
        // raw one, the rest as jemalloc keeps them.
        for i in 0..8u64 {
            let (g, t) = (0x10000 + i * 0x400, 0x100000 + i * 0x400);
            h.tctx(t, g, 0, 0, NOMINAL, (2, 200));
            h.gctx(g, &[0xa1 + i], t);
            if i < 4 {
                h.mem.poke_u64(t + tctx::CNTS as u64 + 8, 1); // shifted count
            }
        }
        let p = walk(&h.finish(), HEADER).unwrap();
        assert_eq!(
            (p.stats.counters_checked, p.stats.counters_violated),
            (8, 4)
        );
    }

    #[test]
    fn a_walk_with_skips_is_tried_again_and_the_cleanest_is_kept() {
        // A record that reads as skipped every time: the walk goes round its
        // attempts and returns the one it has, with the skip counted.
        let mut h = Heap::new();
        h.tctx(0x100000, 0x99999, 0, 0, NOMINAL, (2, 200));
        h.gctx(0x10000, &[0xa1], 0x100000);
        h.tctx(0x101000, 0x10400, 0, 0, NOMINAL, (3, 300));
        h.gctx(0x10400, &[0xb1], 0x101000);
        let p = walk(&h.finish(), HEADER).unwrap();
        assert_eq!(p.stats.retries, ATTEMPTS);
        assert_eq!(p.stats.tctx_skipped, 1);
        assert_eq!(p.stacks.len(), 1);
    }

    #[test]
    fn a_record_that_reads_as_initializing_is_counted_as_skipped() {
        // What a layout with another field where the state is shows wherever
        // a node has no right child. It must not pass for an idle process.
        let mut h = Heap::new();
        h.tctx(0x100000, 0x10000, 0, 0, tctx::STATE_INITIALIZING, (2, 200));
        h.gctx(0x10000, &[0xa1], 0x100000);
        let p = walk(&h.finish(), HEADER).unwrap();
        assert_eq!((p.stats.tctx_read, p.stats.tctx_skipped), (0, 1));
        assert_eq!(p.stats.gctx_read, 1);
    }

    #[test]
    fn a_table_whose_cells_are_not_what_its_count_says_is_flagged() {
        // What a read inside jemalloc's rebuild of the table sees: the header
        // is the same before and after, but `count` says 50 and one cell is in
        // use. Every attempt sees it, so the profile is returned, and says so.
        let mut h = Heap::new();
        h.tctx(0x100000, 0x10000, 0, 0, NOMINAL, (2, 200));
        h.gctx(0x10000, &[0xa1], 0x100000);
        let mut mem = h.finish();
        mem.poke_u64(HEADER + ckh::COUNT as u64, 50);
        let p = walk(&mem, HEADER).unwrap();
        assert!(p.stats.unsteady);
        assert_eq!(p.stats.retries, ATTEMPTS);
        assert_eq!(p.stacks.len(), 1);
        // At rest it is not flagged, nor is a table a couple of entries out,
        // as a busy process's always is.
        for count in [1, 3] {
            mem.poke_u64(HEADER + ckh::COUNT as u64, count);
            let p = walk(&mem, HEADER).unwrap();
            assert!(!p.stats.unsteady, "count {count}");
            assert_eq!(p.stats.retries, 0);
        }
    }

    #[test]
    fn a_thread_record_that_cannot_be_one_is_not_followed() {
        let mut h = Heap::new();
        // A root whose state is not one of the four, with a child that would
        // add 9 objects if it were followed.
        h.tctx(0x100000, 0x10000, 0x100400, 0, 77, (5, 500));
        h.tctx(0x100400, 0x10000, 0, 0, NOMINAL, (9, 900));
        h.gctx(0x10000, &[0xa1], 0x100000);
        // A second gctx whose root has a child pointer that is not aligned.
        h.tctx(0x101000, 0x10400, 0x100401, 0, NOMINAL, (3, 300));
        h.gctx(0x10400, &[0xb1], 0x101000);
        let p = walk(&h.finish(), HEADER).unwrap();
        assert_eq!(p.stacks.len(), 1);
        assert_eq!(p.stacks[0].addrs, vec![0xb1]);
        assert_eq!(p.stacks[0].counts.cur_objs, 3);
        assert_eq!(p.stats.tctx_skipped, 2);
    }

    #[test]
    fn a_table_is_judged_by_its_first_entries_without_reading_the_rest() {
        // A table of 2^15 buckets (2 MiB) whose entries are all one real
        // gctx: recognised, and only the first piece of it was read.
        let mut h = Heap::new();
        h.tctx(0x100000, 0x10000, 0, 0, NOMINAL, (2, 200));
        h.gctx(0x10000, &[0xa1], 0x100000);
        let mut mem = h.finish();
        mem.poke(HEADER + ckh::LG_CUR_BUCKETS as u64, &15u32.to_le_bytes());
        // The table claims 2 MiB but its memory ends after 16 KiB: reading it
        // all fails, and the first entries are all that is asked for.
        let mut first = mem.bytes(TAB, 1024).unwrap();
        first.resize(16 << 10, 0);
        mem.put(TAB, first);
        let head = Ckh::read(&mem, HEADER).unwrap();
        assert!(head.entries(&mem).is_err());
        assert!(is_gctx_table(&mem, &head));
    }

    #[test]
    fn a_table_of_gctx_is_recognised_by_its_shape() {
        let mut h = Heap::new();
        h.tctx(0x100000, 0x10000, 0, 0, NOMINAL, (2, 200));
        h.gctx(0x10000, &[0xa1], 0x100000);
        let mem = h.finish();
        assert!(is_gctx_table(&mem, &Ckh::read(&mem, HEADER).unwrap()));
        // An empty table has no shape to go by.
        let mut empty = Heap::new().finish();
        empty.poke_u64(HEADER + ckh::COUNT as u64, 0);
        assert!(!is_gctx_table(&empty, &Ckh::read(&empty, HEADER).unwrap()));
    }
}
