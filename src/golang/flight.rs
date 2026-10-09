//! Go's flight recorder (`runtime/trace.FlightRecorder`, Go 1.25+), copied
//! out of the program's memory as an execution trace, with no call into the
//! program: the window `WriteTo` would write, less the generation still being
//! recorded. The program has to run the recorder; this only copies it.
//!
//! The recorder keeps the trace as finished generations (about a second
//! each), every one a list of batches, each batch its own copy of what the
//! runtime wrote. When a generation ends it builds a new ring and swaps it
//! in under `ringMu`; it never changes a ring or a batch in place. So a copy
//! is whole if the ring pointer is the same after it as before: everything
//! the copy read was still reachable from that ring, so not yet freed. A
//! ring swapped mid-copy is copied again. Each batch's header is also checked
//! against its generation, as a guard against reading memory reused under us.
//!
//! The file is the recorder's own header followed by every batch, oldest
//! generation first, as `WriteTo` writes it.

use std::time::Instant;

use anyhow::{bail, Context, Result};

use super::discovery::{u64_in, Global};
use super::offsets::Layout;
use super::{GoProcess, ReadStats};

/// A Go slice header: pointer, length, capacity.
const SLICE_HEADER: usize = 24;
/// `tracev2.MaxBatchSize`, plus room for the batch header.
const MAX_BATCH: u64 = (64 << 10) + 64;
const MAX_GENERATIONS: u64 = 4096;
const MAX_BATCHES: u64 = 1 << 20;
/// Copies tried while the recorder keeps swapping its ring.
const MAX_ATTEMPTS: u32 = 5;

/// A copy of the flight recorder's window.
#[derive(Debug, Default)]
pub struct FlightTrace {
    /// A Go execution trace file.
    pub bytes: Vec<u8>,
    /// The generations copied, oldest first.
    pub generations: Vec<u64>,
    pub batches: usize,
    /// Copies made: more than one when the ring was swapped during a copy.
    pub attempts: u32,
}

impl GoProcess {
    /// Copy the flight recorder's finished generations out of the program.
    pub fn flight_recorder(&self, stats: &mut ReadStats) -> Result<FlightTrace> {
        let started = Instant::now();
        let before = self.mem.traffic();
        let l = &self.layout;
        let tracing = self.global(Global::Tracing)?;
        let recorder = self
            .mem
            .u64_at(tracing + l.trace_mux_flight_recorder as u64)?;
        if recorder == 0 {
            bail!("the program has no flight recorder running");
        }
        let fr = self.mem.u64_at(recorder + l.trace_recorder_r as u64)?;
        let header = self.mem.bytes(fr + l.flight_recorder_header as u64, 16)?;
        if !header.starts_with(b"go 1.") {
            bail!("the flight recorder has no trace header yet");
        }
        let ring_at = fr + l.flight_recorder_ring as u64;
        let mut last_err = None;
        for attempt in 1..=MAX_ATTEMPTS {
            let ring = self.mem.bytes(ring_at, 16)?;
            let copied = self.copy_ring(&ring, &header);
            let same = self.mem.bytes(ring_at, 16)? == ring;
            match copied {
                Ok(mut t) if same => {
                    t.attempts = attempt;
                    stats.records += t.batches as u64;
                    self.account(stats, before, started.elapsed());
                    return Ok(t);
                }
                Ok(_) => stats.skipped += 1,
                Err(e) => {
                    stats.skipped += 1;
                    last_err = Some(e);
                }
            }
        }
        match last_err {
            Some(e) => Err(e.context("copying the flight recorder's ring")),
            None => bail!("the flight recorder swapped its ring during every copy"),
        }
    }

    /// The ring whose slice header (pointer, length) is `ring`.
    fn copy_ring(&self, ring: &[u8], header: &[u8]) -> Result<FlightTrace> {
        let l = &self.layout;
        let (ptr, len) = (u64_in(ring, 0), u64_in(ring, 8));
        if len > MAX_GENERATIONS {
            bail!("a ring of {len} generations");
        }
        let gens = self.mem.bytes(ptr, len as usize * l.raw_generation_size)?;
        let mut t = FlightTrace {
            bytes: header.to_vec(),
            ..Default::default()
        };
        for g in gens.chunks_exact(l.raw_generation_size) {
            let gen = u64_in(g, l.raw_generation_gen);
            let (bptr, blen) = (
                u64_in(g, l.raw_generation_batches),
                u64_in(g, l.raw_generation_batches + 8),
            );
            if blen > MAX_BATCHES {
                bail!("generation {gen} has {blen} batches");
            }
            let slices = self.mem.bytes(bptr, blen as usize * SLICE_HEADER)?;
            for s in slices.as_chunks::<SLICE_HEADER>().0 {
                let (dptr, dlen) = (u64_in(s, 0), u64_in(s, 8));
                if dlen == 0 || dlen > MAX_BATCH {
                    bail!("generation {gen} has a batch of {dlen} bytes");
                }
                let data = self
                    .mem
                    .bytes(dptr, dlen as usize)
                    .with_context(|| format!("reading a batch of generation {gen}"))?;
                check_batch(l, &data, gen)?;
                t.bytes.extend_from_slice(&data);
                t.batches += 1;
            }
            t.generations.push(gen);
        }
        Ok(t)
    }
}

/// Whether `data` is one whole batch of generation `gen`, as the recorder's
/// `readBatch` takes it.
fn check_batch(l: &Layout, data: &[u8], gen: u64) -> Result<()> {
    let mut b = &data[1..];
    let mut next = || -> Result<u64> {
        let (v, n) = super::uvarint(b).context("a batch header cut short")?;
        b = &b[n..];
        Ok(v)
    };
    match data[0] {
        ev if ev == l.ev_end_of_generation && data.len() == 1 => return Ok(()),
        ev if ev == l.ev_event_batch => {}
        ev if ev == l.ev_experimental_batch => {
            next()?; // the experiment
        }
        other => bail!("a batch of generation {gen} starts with event {other}"),
    }
    let batch_gen = next()?;
    next()?; // M
    next()?; // timestamp
    let size = next()?;
    if batch_gen != gen {
        bail!("a batch of generation {batch_gen} in generation {gen}");
    }
    if size != b.len() as u64 {
        bail!("a batch of {size} bytes holds {}", b.len());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::golang::offsets::go1_26;

    #[test]
    fn checks_batch_headers() {
        let l = go1_26();
        // EvEventBatch, gen 7, M 3, time 1000 (two bytes), 2 bytes of events.
        let batch = [l.ev_event_batch, 7, 3, 0xe8, 0x07, 2, 0xaa, 0xbb];
        assert!(check_batch(&l, &batch, 7).is_ok());
        assert!(check_batch(&l, &batch, 8).is_err());
        assert!(check_batch(&l, &batch[..7], 7).is_err());
        assert!(check_batch(&l, &[l.ev_end_of_generation], 7).is_ok());
        assert!(check_batch(&l, &[l.ev_end_of_generation, 0], 7).is_err());
        assert!(check_batch(&l, &[0x33, 7, 3, 0, 0], 7).is_err());
    }
}
