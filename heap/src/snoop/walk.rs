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
/// The most of a table read to decide whether it holds backtraces.
pub const VALIDATE_BYTES: u64 = 1 << 20;
/// How many times a walk is done again when the table changed under it.
const ATTEMPTS: u32 = 5;

/// What went wrong along the way, and did not stop the walk.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Stats {
    /// Walks done again because the table changed during them.
    pub retries: u32,
    /// `gctx` skipped: freed or reused while being read.
    pub gctx_skipped: u64,
    /// `tctx` skipped for the same reason.
    pub tctx_skipped: u64,
    /// `tctx` read and counted.
    pub tctx_read: u64,
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
    walk_limited(mem, bt2gctx, MAX_TCTX_TOTAL)
}

fn walk_limited(mem: &dyn Memory, bt2gctx: u64, max_tctx: u64) -> io::Result<Profile> {
    let mut retries = 0;
    let mut last = io::Error::other("the profile kept changing");
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
        let mut stacks = read_stacks(mem, &entries, &mut stats, max_tctx)?;
        let after = Ckh::read(mem, bt2gctx)?;
        if (after.tab, after.lg_cur_buckets) == (head.tab, head.lg_cur_buckets) {
            stacks.sort_by(|a, b| a.addrs.cmp(&b.addrs));
            stats.retries = retries;
            return Ok(Profile { stacks, stats });
        }
        retries += 1;
    }
    Err(last)
}

fn read_stacks(
    mem: &dyn Memory,
    entries: &[(u64, u64)],
    stats: &mut Stats,
    max_tctx: u64,
) -> io::Result<Vec<Stack>> {
    let mut seen = HashSet::new();
    let mut stacks = Vec::new();
    for &(key, gaddr) in entries {
        // Cuckoo hashing moves entries: one seen twice is one entry.
        if !seen.insert(gaddr) {
            continue;
        }
        let Some((root, addrs)) = read_gctx(mem, key, gaddr) else {
            stats.gctx_skipped += 1;
            continue;
        };
        let mut counts = Counts::default();
        for c in read_tctxs(mem, gaddr, root, stats) {
            counts.add(&c);
        }
        if counts.is_reported() {
            stacks.push(Stack { addrs, counts });
        }
        if stats.tctx_read + stats.tctx_skipped > max_tctx {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "more per-thread records than any real profile has; not reading on",
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

/// The counters of every `tctx` in a `gctx`'s tree that a dump would add up.
fn read_tctxs(mem: &dyn Memory, gaddr: u64, root: u64, stats: &mut Stats) -> Vec<Counts> {
    let mut out = Vec::new();
    let mut todo = vec![root];
    let mut seen = HashSet::new();
    while let Some(addr) = todo.pop() {
        if addr == 0 {
            continue;
        }
        // The visited set bounds a tree that a torn read made cyclic.
        if seen.len() >= MAX_TCTX_PER_GCTX || !seen.insert(addr) {
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
        todo.push(u64_at(&b, tctx::LINK_LEFT));
        // The low bit of the right link is the node's colour.
        todo.push(u64_at(&b, tctx::LINK_RIGHT_RED) & !1);
        // prof_tctx_merge_tdata() leaves a tctx still being set up out of a
        // dump; so does this.
        let state = u32::from_le_bytes(b[tctx::STATE..tctx::STATE + 4].try_into().unwrap());
        if state == tctx::STATE_INITIALIZING {
            continue;
        }
        stats.tctx_read += 1;
        out.push(Counts::parse(&b[tctx::CNTS..tctx::CNTS + CNT_SIZE]));
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
        assert_eq!(
            p.stats,
            Stats {
                tctx_read: 4,
                ..Default::default()
            }
        );
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
        assert!(walk_limited(&mem, HEADER, 3).is_err());
        assert_eq!(
            walk_limited(&mem, HEADER, 4).unwrap().stacks[0]
                .counts
                .cur_objs,
            4
        );
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
