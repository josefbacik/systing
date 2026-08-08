//! Runtime confirmation that evicting by systing's `map_files` link releases
//! the blazesym elf_cache entry (its open file descriptor) — the observed
//! counterpart to the source-verified key match in `stack_recorder.rs`:
//! `exec_file_links`' `/proc/pid/map_files/<start>-<end>` link is byte-for-byte
//! blazesym's `EntryPath::maps_file`, which is the elf_cache key (`actual_path`).
//!
//! `#[ignore]`, run only under the vng rig: reading `/proc/<pid>/map_files/`
//! requires CAP_SYS_ADMIN. The systing tracer has it (BPF needs it) but an
//! unprivileged `cargo test` does not, and without it blazesym's own stat of
//! the map_files path fails EPERM before it can cache — so this must run where
//! the tracer runs, privileged. The vng rig boots the test as root.

use std::path::PathBuf;

use blazesym::symbolize::source::{Process, Source};
use blazesym::symbolize::{evict, Input, Symbolizer};
use blazesym::Pid;
use systing::sandbox_maps::ProcessMaps;

/// Number of open fds in /proc/self/fd whose target is one of `backing`.
/// blazesym's FileCache holds one open `File` (fd) per cached ELF, so this
/// count drops when the corresponding entry is evicted.
fn count_fds_to(backing: &[PathBuf]) -> usize {
    let mut n = 0;
    if let Ok(rd) = std::fs::read_dir("/proc/self/fd") {
        for entry in rd.flatten() {
            if let Ok(target) = std::fs::read_link(entry.path()) {
                if backing.contains(&target) {
                    n += 1;
                }
            }
        }
    }
    n
}

#[test]
#[ignore = "needs CAP_SYS_ADMIN for /proc/pid/map_files; runs under the vng rig"]
fn evict_by_map_files_link_releases_elf_cache_fd() {
    let pid = std::process::id() as i32;
    let maps = ProcessMaps::load(pid).expect("read own /proc/<pid>/maps");
    let links = maps.exec_file_links();
    assert!(!links.is_empty(), "self must have mapped executable files");

    let backing: Vec<PathBuf> = links
        .iter()
        .filter_map(|(link, _display)| std::fs::read_link(link).ok())
        .collect();
    assert!(
        !backing.is_empty(),
        "map_files links must resolve to backing files (needs CAP_SYS_ADMIN)"
    );

    let mut symbolizer = Symbolizer::new();
    // Symbolize an address in this test binary's own text so blazesym opens and
    // caches the backing ELF via its map_files path, holding an fd.
    let proc_src = Source::Process(Process::new(Pid::from(pid as u32)));
    let addr = evict_by_map_files_link_releases_elf_cache_fd as fn() as usize as u64;
    let sym_result = symbolizer.symbolize_single(&proc_src, Input::AbsAddr(addr));
    assert!(
        sym_result.is_ok(),
        "symbolization must succeed under the tracer's privilege: {sym_result:?}"
    );

    let before = count_fds_to(&backing);
    assert!(
        before > 0,
        "blazesym must hold at least one cached ELF fd after symbolizing"
    );

    // Evict every mapped ELF by its map_files link — the exact key the valve in
    // stack_recorder.rs uses. A wrong key would be a silent no-op that left the
    // fd count unchanged.
    for (link, _display) in &links {
        symbolizer
            .evict(&evict::Evict::from(evict::Elf::new(link.clone())))
            .expect("evict returns Ok");
    }

    let after = count_fds_to(&backing);
    assert!(
        after < before,
        "evict via map_files link must release cached ELF fds: before={before} after={after}"
    );
}
