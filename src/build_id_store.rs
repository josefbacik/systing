//! Build-id-keyed symbol store for `--collect-build-id` mode.
//!
//! In build-id mode the kernel stack walker emits `(build_id, file offset)`
//! pairs instead of raw IPs for user frames (`BPF_F_USER_BUILD_ID`), so a
//! frame's identity survives the process that produced it. Symbolization
//! becomes a pure lookup: build-id -> binary (or debug info) -> name. This
//! module is that lookup.
//!
//! Fill sources, in trust order:
//!
//! 1. **`.build-id` debug directories** (`/usr/lib/debug/.build-id/xx/rest`)
//!    — trusted: the path is *derived from the id*, so a traced process
//!    cannot influence which file answers for an id it doesn't own.
//! 2. **debuginfod** (when `--enable-debuginfod` is set) — trusted for the
//!    same reason: the server is queried *by id*.
//! 3. **Live binaries** — opportunistic: while a sampled process is still
//!    alive at symbolization time, its executable mappings are read (via
//!    namespace-immune `/proc/<pid>/map_files` links) and indexed by their
//!    build-id note. Untrusted in the limit: a binary can carry a copied
//!    build-id note. Therefore live fills **never override** a trusted
//!    entry and never overwrite anything already stored — a forged note can
//!    only affect the rendering of ids that no trusted source knows, which
//!    is the same capability class as forging sample content outright.
//!
//! Misses are not failures: the caller renders the frame with its full
//! build-id and offset, which a later pass (or downstream tooling) can
//! resolve whenever a store learns the id.
//!
//! Growth is bounded from day one: the store caps its entry count and
//! evicts the least-recently-used slot past the cap.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use debuginfod::{BuildId, CachingClient};

/// Render a build-id as lowercase hex (the form `file(1)`, `readelf` and
/// debuginfod all use).
pub fn build_id_hex(id: &[u8]) -> String {
    let mut s = String::with_capacity(id.len() * 2);
    for b in id {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Where symbols for one build-id come from.
#[derive(Debug, Clone)]
pub struct ResolvedBinary {
    /// ELF (or separate debug file) to symbolize file offsets against.
    pub path: PathBuf,
    /// Module name to render in frames. For live-binary fills this is the
    /// mapped file's basename; for `.build-id`/debuginfod hits (where the
    /// on-disk name is just the hex id) it is `[buildid:<hex8>]`.
    pub display_module: String,
}

#[derive(Debug, Default)]
struct StoreSlot {
    /// Entry from a trusted source (`.build-id` dir or debuginfod).
    trusted: Option<ResolvedBinary>,
    /// Trusted sources already probed for this id (probe once, remember
    /// misses — debuginfod fetches are not free).
    trusted_probed: bool,
    /// Opportunistic live-binary entry. Consulted only when no trusted
    /// source knows the id; never overwritten once set.
    live: Option<ResolvedBinary>,
    /// LRU stamp for cap eviction.
    last_used: u64,
}

/// Default entry cap. A trace window sees one entry per unique binary
/// sampled — hundreds on busy hosts — so this is generous while still
/// bounding a pathological (or adversarial) unique-build-id storm.
const DEFAULT_CAP: usize = 16384;

/// Debug directories probed for `.build-id/xx/<rest>.debug` (and the bare
/// `<rest>` variant some distros install).
const BUILD_ID_DIRS: &[&str] = &["/usr/lib/debug/.build-id"];

pub struct BuildIdStore {
    entries: HashMap<[u8; 20], StoreSlot>,
    debuginfod: Option<Arc<CachingClient>>,
    tick: u64,
    cap: usize,
}

impl BuildIdStore {
    pub fn new(debuginfod: Option<Arc<CachingClient>>) -> Self {
        Self {
            entries: HashMap::new(),
            debuginfod,
            tick: 0,
            cap: DEFAULT_CAP,
        }
    }

    #[cfg(test)]
    fn with_cap(mut self, cap: usize) -> Self {
        self.cap = cap;
        self
    }

    /// Resolve a build-id to the binary to symbolize against, probing
    /// trusted sources on first sight. Returns `None` when no source knows
    /// the id (the caller renders the deferred `[buildid:...]` form).
    pub fn lookup(&mut self, id: &[u8; 20]) -> Option<ResolvedBinary> {
        self.tick += 1;
        let tick = self.tick;
        self.evict_past_cap(id);
        let debuginfod = self.debuginfod.clone();
        let slot = self.entries.entry(*id).or_default();
        slot.last_used = tick;
        if !slot.trusted_probed {
            slot.trusted_probed = true;
            slot.trusted =
                probe_build_id_dirs(id).or_else(|| fetch_debuginfod(debuginfod.as_deref(), id));
        }
        slot.trusted.clone().or_else(|| slot.live.clone())
    }

    /// Opportunistic fill from a live process's mapping. Never overrides a
    /// trusted entry (lookup prefers trusted regardless) and never
    /// overwrites an existing live entry.
    pub fn fill_live(&mut self, id: [u8; 20], path: PathBuf, display_module: String) {
        self.tick += 1;
        let tick = self.tick;
        self.evict_past_cap(&id);
        let slot = self.entries.entry(id).or_default();
        slot.last_used = tick;
        if slot.live.is_none() {
            slot.live = Some(ResolvedBinary {
                path,
                display_module,
            });
        }
    }

    /// Evict the least-recently-used slot while at the cap, unless `keep`
    /// is already present (its slot is about to be reused, not grown).
    fn evict_past_cap(&mut self, keep: &[u8; 20]) {
        while self.entries.len() >= self.cap && !self.entries.contains_key(keep) {
            let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, s)| s.last_used)
                .map(|(k, _)| *k)
            else {
                return;
            };
            self.entries.remove(&oldest);
        }
    }
}

/// Probe the distro `.build-id` debug directories: `<dir>/xx/<rest>.debug`
/// (the debug-info file) and `<dir>/xx/<rest>` (a full-binary variant some
/// layouts install). The path is derived from the id, which is what makes
/// this source trusted.
fn probe_build_id_dirs(id: &[u8; 20]) -> Option<ResolvedBinary> {
    let head = format!("{:02x}", id[0]);
    let rest = build_id_hex(&id[1..]);
    for dir in BUILD_ID_DIRS {
        for name in [format!("{rest}.debug"), rest.clone()] {
            let path = Path::new(dir).join(&head).join(&name);
            if path.is_file() {
                return Some(ResolvedBinary {
                    path,
                    display_module: format!("[buildid:{}]", &build_id_hex(id)[..8]),
                });
            }
        }
    }
    None
}

/// Fetch debug info by build-id from debuginfod (only when the client was
/// enabled). Queried by id, so equally trusted as the `.build-id` dirs.
///
/// Ids shorter than 20 bytes (rare non-sha1 notes) were zero-padded by the
/// kernel's fixed-size field, and the padding is indistinguishable from
/// trailing zero bytes of a real sha1 — so the query uses the padded form
/// and such ids simply miss here (deferred rendering covers them).
fn fetch_debuginfod(client: Option<&CachingClient>, id: &[u8; 20]) -> Option<ResolvedBinary> {
    let client = client?;
    let build_id = BuildId::raw(id.to_vec());
    match client.fetch_debug_info(&build_id) {
        Ok(Some(path)) => Some(ResolvedBinary {
            path,
            display_module: format!("[buildid:{}]", &build_id_hex(id)[..8]),
        }),
        Ok(None) => None,
        Err(e) => {
            // One line per failing id (memoized by trusted_probed), then the
            // frame falls back to the deferred rendering.
            eprintln!(
                "Warning: debuginfod fetch for build-id {} failed: {e}",
                build_id_hex(id)
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bid(seed: u8) -> [u8; 20] {
        [seed; 20]
    }

    fn resolved(p: &str) -> (PathBuf, String) {
        (PathBuf::from(p), p.to_string())
    }

    #[test]
    fn test_live_fill_never_overwrites() {
        let mut store = BuildIdStore::new(None);
        let (p1, d1) = resolved("/proc/1/map_files/a-b");
        let (p2, _) = resolved("/proc/2/map_files/c-d");
        store.fill_live(bid(1), p1.clone(), d1.clone());
        store.fill_live(bid(1), p2, "other".into());
        let hit = store.lookup(&bid(1)).expect("live entry");
        assert_eq!(hit.path, p1, "second live fill must not overwrite first");
    }

    #[test]
    fn test_trusted_preferred_over_live() {
        // No trusted source exists in the test environment, so simulate one
        // by injecting the slot directly: the lookup preference (trusted
        // first) is what's under test, not the probe.
        let mut store = BuildIdStore::new(None);
        let (lp, ld) = resolved("/live/binary");
        store.fill_live(bid(2), lp, ld);
        let slot = store.entries.get_mut(&bid(2)).unwrap();
        slot.trusted = Some(ResolvedBinary {
            path: PathBuf::from("/usr/lib/debug/.build-id/aa/bb.debug"),
            display_module: "[buildid:trusted]".into(),
        });
        slot.trusted_probed = true;
        let hit = store.lookup(&bid(2)).expect("entry");
        assert_eq!(
            hit.display_module, "[buildid:trusted]",
            "trusted entry must win over a live fill"
        );
    }

    #[test]
    fn test_miss_is_memoized_and_returns_none() {
        let mut store = BuildIdStore::new(None);
        assert!(store.lookup(&bid(3)).is_none());
        // Second lookup takes the memoized-miss path (trusted_probed set).
        assert!(store.lookup(&bid(3)).is_none());
        assert!(store.entries.get(&bid(3)).unwrap().trusted_probed);
    }

    #[test]
    fn test_cap_evicts_least_recently_used() {
        let mut store = BuildIdStore::new(None).with_cap(2);
        let (p, d) = resolved("/x");
        store.fill_live(bid(1), p.clone(), d.clone());
        store.fill_live(bid(2), p.clone(), d.clone());
        // Touch 1 so 2 is the LRU.
        store.lookup(&bid(1));
        store.fill_live(bid(3), p, d);
        assert!(store.entries.contains_key(&bid(1)));
        assert!(!store.entries.contains_key(&bid(2)), "LRU slot evicted");
        assert!(store.entries.contains_key(&bid(3)));
    }

    #[test]
    fn test_build_id_hex() {
        assert_eq!(build_id_hex(&[0xab, 0x01, 0xff]), "ab01ff");
    }
}
