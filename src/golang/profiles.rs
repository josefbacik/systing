//! The heap, block and mutex profiles the Go runtime keeps for
//! `runtime/pprof`, read out of the program.
//!
//! All three are lists of buckets (`runtime.mbuckets`, `bbuckets`,
//! `xbuckets`), each bucket a fixed header, its stack, and its record. The
//! numbers are what `pprof.Lookup(...).WriteTo` would write at the same
//! moment: the heap's as of the last finished GC cycle, block and mutex
//! delays turned from CPU ticks into nanoseconds.

use std::time::{Duration, Instant};

use anyhow::{bail, Result};

use super::discovery::{u64_in, Global};
use super::{GoProcess, ReadStats};

/// The deepest stack the runtime records (`maxProfStackDepth`).
const MAX_STACK: u64 = 1024;
/// The most buckets walked: real programs have thousands.
pub(crate) const MAX_RECORDS: usize = 4_000_000;
/// The most frames kept in one read, over all its stacks (as systing-heap's
/// jemalloc reader has it).
pub(crate) const MAX_FRAMES_TOTAL: u64 = 1 << 25;
/// A read is given up after this long.
pub(crate) const MAX_TIME: Duration = Duration::from_secs(180);

/// One heap profile stack: as sampled, and frames leaf first, without the
/// allocator's own (pprof's `hideRuntime`).
#[derive(Debug, Clone)]
pub struct HeapRecord {
    pub pcs: Vec<u64>,
    pub alloc_objects: u64,
    pub alloc_bytes: u64,
    pub live_objects: u64,
    pub live_bytes: u64,
}

impl HeapRecord {
    /// (alloc_objects, alloc_space, inuse_objects, inuse_space) as pprof
    /// writes them: scaled up from the samples at `rate`, as Go scales them.
    pub fn scaled(&self, rate: i64) -> [u64; 4] {
        let (ao, ab) = scale_heap_sample(self.alloc_objects, self.alloc_bytes, rate);
        let (lo, lb) = scale_heap_sample(self.live_objects, self.live_bytes, rate);
        [ao, ab, lo, lb]
    }
}

/// One heap bucket as read: its allocs and frees of the active cycle, and of
/// the future ones together.
struct HeapBucket {
    pcs: Vec<u64>,
    size: u64,
    active: [u64; 2],
    future: [u64; 2],
}

/// The heap profile.
#[derive(Debug, Clone)]
pub struct HeapProfile {
    pub records: Vec<HeapRecord>,
    /// `runtime.MemProfileRate`: mean bytes between samples.
    pub rate: i64,
}

/// One block or mutex profile stack, frames leaf first.
#[derive(Debug, Clone)]
pub struct ContentionRecord {
    pub pcs: Vec<u64>,
    pub contentions: i64,
    pub delay_ns: i64,
}

/// The block or mutex profile.
#[derive(Debug, Clone)]
pub struct ContentionProfile {
    pub records: Vec<ContentionRecord>,
    /// The CPU ticks per second the delays were converted with.
    pub ticks_per_second: f64,
}

impl GoProcess {
    /// The runtime's sampling period for the heap profile, in bytes.
    pub fn mem_profile_rate(&self) -> Result<i64> {
        Ok(self.mem.u64_at(self.global(Global::MemProfileRate)?)? as i64)
    }

    /// Walk the bucket list at `head` (`mbuckets`, `bbuckets` or `xbuckets`),
    /// giving each bucket of type `typ` its stack, its object size and the
    /// `record_len` bytes of record after it.
    fn walk_buckets(
        &self,
        head: Global,
        typ: u64,
        record_len: usize,
        stats: &mut ReadStats,
        mut each: impl FnMut(Vec<u64>, u64, &[u8]),
    ) -> Result<()> {
        let l = &self.layout;
        let mut b = self.mem.u64_at(self.global(head)?)?;
        let mut seen = 0usize;
        let mut frames = 0u64;
        let started = Instant::now();
        while b != 0 {
            seen += 1;
            if seen > MAX_RECORDS {
                bail!("more than {MAX_RECORDS} buckets: the list is not what it seems");
            }
            if started.elapsed() > MAX_TIME {
                bail!("the bucket list took more than {MAX_TIME:?} to walk");
            }
            let Ok(header) = self.mem.bytes(b, l.bucket_size) else {
                stats.skipped += 1;
                break;
            };
            let allnext = u64_in(&header, l.bucket_allnext);
            let nstk = u64_in(&header, l.bucket_nstk);
            if u64_in(&header, l.bucket_typ) != typ || nstk > MAX_STACK {
                stats.skipped += 1;
                b = allnext;
                continue;
            }
            frames += nstk;
            if frames > MAX_FRAMES_TOTAL {
                bail!("more than {MAX_FRAMES_TOTAL} stack frames in {seen} buckets: the list is not what it seems");
            }
            let stack_len = nstk as usize * 8;
            match self
                .mem
                .bytes(b + l.bucket_size as u64, stack_len + record_len)
            {
                Ok(body) => {
                    let pcs = body[..stack_len]
                        .as_chunks::<8>()
                        .0
                        .iter()
                        .map(|c| u64::from_le_bytes(*c))
                        .collect();
                    stats.records += 1;
                    each(
                        pcs,
                        u64_in(&header, l.bucket_object_size),
                        &body[stack_len..],
                    );
                }
                Err(_) => stats.skipped += 1,
            }
            b = allnext;
        }
        Ok(())
    }

    /// The heap profile, as `pprof.Lookup("heap")` would give it now.
    pub fn heap(&self, stats: &mut ReadStats) -> Result<HeapProfile> {
        let started = Instant::now();
        let before = self.mem.traffic();
        let l = self.layout;
        let rate = self.mem_profile_rate()?;
        if rate == 0 {
            bail!(
                "MemProfileRate is {rate}: the program samples no allocations (its code cannot \
                 reach runtime.MemProfile, or it turned sampling off)"
            );
        }
        // allocs, frees of one cycle.
        let cycle = |rec: &[u8], at: usize| {
            [
                u64_in(rec, at + l.cycle_allocs),
                u64_in(rec, at + l.cycle_frees),
            ]
        };
        let mut recs = Vec::new();
        self.walk_buckets(
            Global::MBuckets,
            l.mem_profile,
            l.mem_record_size,
            stats,
            |pcs, size, rec| {
                let active = cycle(rec, l.mem_record_active);
                let mut future = [0u64; 2];
                for i in 0..l.mem_record_future_cycles {
                    let c = cycle(rec, l.mem_record_future + i * l.cycle_size);
                    for (sum, v) in future.iter_mut().zip(c) {
                        *sum = sum.wrapping_add(v);
                    }
                }
                recs.push(HeapBucket {
                    pcs,
                    size,
                    active,
                    future,
                });
            },
        )?;
        // As memProfileInternal: with no GC yet nothing is in the active
        // cycle, and every cycle is summed instead.
        let none_active = recs
            .iter()
            .all(|b: &HeapBucket| b.active[0] == 0 && b.active[1] == 0);
        let mut records = Vec::with_capacity(recs.len());
        for HeapBucket {
            pcs,
            size,
            active,
            future,
        } in recs
        {
            let mut c = active;
            if none_active {
                for (sum, v) in c.iter_mut().zip(future) {
                    *sum = sum.wrapping_add(v);
                }
            }
            let [allocs, frees] = c;
            if allocs == 0 && frees == 0 {
                continue;
            }
            // A bucket holds one object size, so its bytes are its objects
            // times that (Go 1.27 keeps no byte counts of its own).
            let Some(alloc_bytes) = allocs.checked_mul(size).filter(|_| frees <= allocs) else {
                stats.skipped += 1;
                continue;
            };
            records.push(HeapRecord {
                pcs: self.hide_runtime(&pcs),
                alloc_objects: allocs,
                alloc_bytes,
                live_objects: allocs - frees,
                live_bytes: (allocs - frees) * size,
            });
        }
        self.account(stats, before, started.elapsed());
        Ok(HeapProfile { records, rate })
    }

    /// The block (`mutex` false) or mutex profile, as pprof gives it.
    pub fn contention(&self, mutex: bool, stats: &mut ReadStats) -> Result<ContentionProfile> {
        let started = Instant::now();
        let before = self.mem.traffic();
        let l = self.layout;
        let ticks_per_second = self.ticks_per_second()?;
        let per_ns = ticks_per_second / 1e9;
        let (head, typ) = if mutex {
            (Global::XBuckets, l.mutex_profile)
        } else {
            (Global::BBuckets, l.block_profile)
        };
        let mut records = Vec::new();
        self.walk_buckets(head, typ, l.block_record_size, stats, |pcs, _, rec| {
            let count = f64::from_bits(u64_in(rec, l.block_record_count));
            let cycles = u64_in(rec, l.block_record_cycles) as i64;
            records.push(ContentionRecord {
                // A stack the runtime stored already expanded starts with
                // logicalStackSentinel (^0), up to Go 1.26.
                pcs: pcs.into_iter().filter(|&pc| pc != u64::MAX).collect(),
                // As blockProfileInternal: a count that rounds to 0 is 1.
                contentions: (count as i64).max(1),
                delay_ns: (cycles as f64 / per_ns) as i64,
            });
        })?;
        self.account(stats, before, started.elapsed());
        Ok(ContentionProfile {
            records,
            ticks_per_second,
        })
    }

    /// CPU ticks per second as the runtime has worked it out (it does the
    /// first time a profile asks), or else worked out here as the runtime
    /// would: ticks and monotonic time since the start values it saved at
    /// init. The program reads the same TSC and the same clock.
    fn ticks_per_second(&self) -> Result<f64> {
        let l = &self.layout;
        let ticks = self.global(Global::Ticks)?;
        let val = self.mem.u64_at(ticks + l.ticks_val as u64)?;
        if val != 0 {
            return Ok(val as f64);
        }
        let start_ticks = self.mem.u64_at(ticks + l.ticks_start_ticks as u64)? as i64;
        let start_time = self.mem.u64_at(ticks + l.ticks_start_time as u64)? as i64;
        let (now_ticks, now_time) = tsc_and_monotonic();
        if now_ticks > start_ticks && now_time > start_time {
            return Ok((now_ticks - start_ticks) as f64 * 1e9 / (now_time - start_time) as f64);
        }
        Ok(measure_tsc())
    }

    /// Add what was read since `before` to `stats`.
    pub(crate) fn account(&self, stats: &mut ReadStats, before: (u64, u64), took: Duration) {
        let (reads, bytes) = self.mem.traffic();
        stats.reads += reads - before.0;
        stats.bytes += bytes - before.1;
        stats.micros += took.as_micros();
    }
}

/// `scaleHeapSample` from runtime/pprof, to the bit: Go truncates.
pub fn scale_heap_sample(count: u64, size: u64, rate: i64) -> (u64, u64) {
    if count == 0 || size == 0 {
        return (0, 0);
    }
    if rate <= 1 {
        return (count, size);
    }
    let avg = size as f64 / count as f64;
    let scale = 1.0 / (1.0 - (-avg / rate as f64).exp());
    (
        (count as f64 * scale) as i64 as u64,
        (size as f64 * scale) as i64 as u64,
    )
}

/// The runtime's cputicks and nanotime now.
fn tsc_and_monotonic() -> (i64, i64) {
    (cputicks() as i64, monotonic_ns())
}

/// CLOCK_MONOTONIC, the runtime's nanotime.
fn monotonic_ns() -> i64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: a valid timespec to fill.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec * 1_000_000_000 + ts.tv_nsec
}

/// CPU ticks per second, measured over a short wait.
fn measure_tsc() -> f64 {
    let t0 = Instant::now();
    let c0 = cputicks();
    std::thread::sleep(Duration::from_millis(50));
    let c1 = cputicks();
    c1.wrapping_sub(c0) as f64 / t0.elapsed().as_secs_f64()
}

#[cfg(target_arch = "x86_64")]
fn cputicks() -> u64 {
    // SAFETY: rdtsc has no preconditions on x86-64.
    unsafe { core::arch::x86_64::_rdtsc() }
}

/// On arm64 the runtime's cputicks is its nanotime.
#[cfg(not(target_arch = "x86_64"))]
fn cputicks() -> u64 {
    monotonic_ns() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_scaling_truncates_as_pprof_does() {
        // 149 objects of 4096 bytes at 512 KiB.
        let (o, b) = scale_heap_sample(149, 149 * 4096, 524_288);
        assert_eq!((o, b), (19146, 78424461));
        assert_eq!(scale_heap_sample(5, 500, 1), (5, 500));
        assert_eq!(scale_heap_sample(0, 500, 512), (0, 0));
    }
}
