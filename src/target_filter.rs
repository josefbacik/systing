//! The `--pid` / `--cgroup` targeting shared by systing's BPF objects
//! (`src/bpf/systing_shared.bpf.h`): one [`TargetFilter`] per capture,
//! written into each object's `target_filter` rodata, and the main object's
//! target maps, which every other object reuses so all of them read the one
//! live target set.

use std::os::fd::BorrowedFd;

use anyhow::{Context, Result};
use libbpf_rs::OpenMapMut;

/// A BPF object's `target_filter` rodata (`struct target_filter_config`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TargetFilter {
    pub filter_pid: bool,
    pub filter_cgroup: bool,
    /// The kernel decides `--cgroup` membership (`bpf_task_under_cgroup()`)
    /// rather than the legacy start-time set of cgroup ids.
    pub cgroup_match_kernel: bool,
    pub num_cgroup_targets: u32,
}

/// Writes a [`TargetFilter`] into a skeleton's `target_filter` rodata. A macro
/// because every skeleton generates its own `target_filter_config` type.
macro_rules! set_target_filter {
    ($rodata:expr, $filter:expr) => {{
        let filter: &$crate::target_filter::TargetFilter = $filter;
        let config = &mut $rodata.target_filter;
        config.filter_pid = filter.filter_pid as u32;
        config.filter_cgroup = filter.filter_cgroup as u32;
        config.cgroup_match_kernel = filter.cgroup_match_kernel as u32;
        config.num_cgroup_targets = filter.num_cgroup_targets;
    }};
}
pub(crate) use set_target_filter;

/// The main object's target maps.
pub struct TargetFilterMaps<'a> {
    pub cgroup_targets: BorrowedFd<'a>,
    pub cgroup_target_refs: BorrowedFd<'a>,
    pub cgroups: BorrowedFd<'a>,
    pub pids: BorrowedFd<'a>,
}

impl TargetFilterMaps<'_> {
    /// Points another object's target maps at these; call before it loads.
    pub fn reuse_in<'obj>(
        &self,
        cgroup_targets: &mut OpenMapMut<'obj>,
        cgroup_target_refs: &mut OpenMapMut<'obj>,
        cgroups: &mut OpenMapMut<'obj>,
        pids: &mut OpenMapMut<'obj>,
    ) -> Result<()> {
        for (map, fd) in [
            (cgroup_targets, self.cgroup_targets),
            (cgroup_target_refs, self.cgroup_target_refs),
            (cgroups, self.cgroups),
            (pids, self.pids),
        ] {
            map.reuse_fd(fd)
                .with_context(|| format!("Failed to reuse the {:?} map", map.name()))?;
        }
        Ok(())
    }
}
