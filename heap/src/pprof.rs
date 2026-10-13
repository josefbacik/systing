//! Go heap profile files as heap snapshots.
//!
//! A pprof file is already symbolized by the program that wrote it, so a
//! snapshot made from one keeps the names it has and is not symbolized again.
//! The file format is read by `systing::golang::pprof`; [`heap_snapshot`]
//! turns a heap profile (`inuse_space` and friends) into a [`Snapshot`].

use std::path::Path;

use anyhow::{Context, Result};
use systing::golang::pprof::{read_file, Frame, Profile};

use crate::maps::Maps;
use crate::{Format, Sample, Snapshot};

/// A frame's name in systing's form, `function (module [file:line])
/// <0xaddr>`, as the recorders write a symbolized native frame.
pub fn frame_name(f: &Frame) -> String {
    let module = if f.module.is_empty() {
        "unknown"
    } else {
        &f.module
    };
    let function = if f.function.is_empty() {
        "unknown"
    } else {
        &f.function
    };
    // An inlined call shares its caller's address: it is named without one,
    // so the two are not taken for one frame where symbols attach by address.
    let address = if f.inlined {
        String::new()
    } else {
        format!(" <{:#x}>", f.address)
    };
    if f.file.is_empty() {
        return format!("{function} ({module}){address}");
    }
    let base = Path::new(&f.file)
        .file_name()
        .and_then(|b| b.to_str())
        .unwrap_or(&f.file);
    format!("{function} ({module} [{base}:{}]){address}", f.line)
}

/// Read a Go heap profile file into a snapshot.
pub fn read(path: &Path) -> Result<Snapshot> {
    let profile = read_file(path)?;
    let mut snapshot = heap_snapshot(&profile)?;
    snapshot.source_path = path.to_path_buf();
    Ok(snapshot)
}

/// A heap profile as a snapshot. Go writes each stack's estimate, already
/// scaled up from its samples at the profile's period (`scaleHeapSample` in
/// runtime/pprof): those are the snapshot's estimates as they are, and the
/// sampled counts are worked back from them by the same formula.
pub fn heap_snapshot(profile: &Profile) -> Result<Snapshot> {
    let idx = |name: &str| {
        profile
            .value_index(name)
            .with_context(|| format!("not a heap profile: no {name} values"))
    };
    let (ao, ab, io, ib) = (
        idx("alloc_objects")?,
        idx("alloc_space")?,
        idx("inuse_objects")?,
        idx("inuse_space")?,
    );
    let period = u64::try_from(profile.period).unwrap_or(0);
    let mut samples = Vec::with_capacity(profile.samples.len());
    let mut named = Vec::with_capacity(profile.samples.len());
    for smp in &profile.samples {
        let v = |i: usize| u64::try_from(smp.values.get(i).copied().unwrap_or(0)).unwrap_or(0);
        let (live_objects, live_bytes) = sampled(v(io), v(ib), period);
        let (alloc_objects, alloc_bytes) = sampled(v(ao), v(ab), period);
        samples.push(Sample {
            addrs: smp
                .frames
                .iter()
                .filter(|f| !f.inlined)
                .map(|f| f.address)
                .collect(),
            live_objects,
            live_bytes,
            alloc_objects,
            alloc_bytes,
            exact_estimates: Some([v(ib), v(io), v(ab), v(ao)]),
        });
        // Root (outermost) first, as `stack.frame_ids` has them.
        named.push(smp.frames.iter().rev().map(frame_name).collect());
    }
    Ok(Snapshot {
        format: Format::Pprof,
        source_path: Default::default(),
        pid: None,
        seq: None,
        trigger: Some("pprof"),
        dumped_at_unix_ns: (profile.time_nanos > 0).then_some(profile.time_nanos),
        owner_uid: None,
        sample_period: period,
        samples,
        maps: Maps::default(),
        perf_map: None,
        py_code: None,
        live_read: None,
        named_frames: Some(named),
    })
}

/// The sampled (objects, bytes) behind an estimate Go scaled up at `period`:
/// the estimate divided by the chance `1 - exp(-mean / period)` that an
/// object of the stack's mean size is sampled. The mean is the same before
/// and after scaling, so this undoes `scaleHeapSample` up to its rounding
/// (Go truncates objects and bytes apart, so the mean is a little off).
fn sampled(objects: u64, bytes: u64, period: u64) -> (u64, u64) {
    if objects == 0 || bytes == 0 || period <= 1 {
        return (objects, bytes);
    }
    let mean = bytes as f64 / objects as f64;
    let p = 1.0 - (-mean / period as f64).exp();
    // A mean too small against the period to register (or not a number).
    if p.is_nan() || p <= 0.0 {
        return (objects, bytes);
    }
    let back = |v: u64| (v as f64 * p).round().max(1.0) as u64;
    (back(objects), back(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sampled_undoes_go_scaling() {
        // 4 KiB objects at Go's default 512 KiB period: Go scales 149 sampled
        // objects up to int64(149 / (1 - exp(-4096/524288))).
        let period = 524_288u64;
        let scale = 1.0 / (1.0 - (-4096.0 / period as f64).exp());
        let est_objects = (149.0 * scale) as u64;
        let est_bytes = (149.0 * 4096.0 * scale) as u64;
        // Go truncates the two estimates apart, so the mean worked back from
        // them is a little off, and so are the bytes: within 0.01% here.
        let (objects, bytes) = sampled(est_objects, est_bytes, period);
        assert_eq!(objects, 149);
        assert!(bytes.abs_diff(149 * 4096) * 10_000 < 149 * 4096, "{bytes}");
        // A period of 1 is every allocation: nothing to undo.
        assert_eq!(sampled(5, 500, 1), (5, 500));
    }
}
