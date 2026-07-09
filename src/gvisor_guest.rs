//! Guest-side process truth for gVisor sandboxes.
//!
//! The host view of a sandboxed process (a systrap *stub*) is enough to
//! symbolize file-backed guest text, but three things only the Sentry
//! knows: which guest process a stub mirrors (host comm is always the
//! runtime's own), the guest-path identity of mappings whose host backing
//! is the memory pool (copied-up files, donation-less configurations), and
//! the authoritative extent of runtime-injected regions (`[usertrap]`).
//!
//! runsc's control socket already serves all of it: the
//! `containerManager.ProcfsDump` RPC returns, per guest process, the full
//! guest maps (path, offset, perms), comm/exe/args, and the task creation
//! time. The socket lives in the runsc state directory
//! (`<root>/runsc-<sandbox-id>.sock`), the protocol is a single JSON
//! request/response over a unix stream socket, and the call is
//! Sentry-side only — nothing executes inside the guest.
//!
//! [`SandboxIndex::load`] snapshots every reachable sandbox once per
//! symbolization pass; [`SandboxIndex::correlate`] matches a host stub's
//! address space to the guest process it mirrors (stub VAs are guest VAs
//! under systrap, so file-backed ranges must agree exactly); the returned
//! [`GuestProcess`] then answers per-address queries.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

/// State directories probed for control sockets: the containerd shim's
/// (Kubernetes) and the standalone default. `SYSTING_RUNSC_ROOTS`
/// (colon-separated) replaces the list when set.
const DEFAULT_RUNSC_ROOTS: &[&str] = &["/run/containerd/runsc/k8s.io", "/var/run/runsc"];

/// Per-call I/O timeout. The RPC is served from Sentry memory and is
/// fast; a wedged sandbox must not stall symbolization.
const RPC_TIMEOUT: Duration = Duration::from_secs(2);

/// Response size cap: a sandbox with thousands of guest processes stays
/// well under this; anything larger is malformed or hostile.
const RPC_MAX_RESPONSE: usize = 64 << 20;

/// Total time allowed for snapshotting all sandboxes on the host.
const LOAD_BUDGET: Duration = Duration::from_secs(10);

/// One guest memory mapping, from the Sentry's `/proc/<pid>/maps` view.
#[derive(Debug, Clone, Deserialize)]
pub struct GuestMapping {
    #[serde(rename = "address")]
    addr: GuestAddrRange,
    #[serde(rename = "permissions")]
    perms: GuestPerms,
    #[serde(default)]
    offset: u64,
    #[serde(default)]
    pathname: String,
}

#[derive(Debug, Clone, Deserialize)]
struct GuestAddrRange {
    #[serde(rename = "Start")]
    start: u64,
    #[serde(rename = "End")]
    end: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct GuestPerms {
    #[serde(rename = "Read", default)]
    read: bool,
    #[serde(rename = "Execute", default)]
    execute: bool,
}

impl GuestMapping {
    fn contains(&self, addr: u64) -> bool {
        self.addr.start <= addr && addr < self.addr.end
    }

    /// A regular guest file mapping (absolute path, not a `[...]` pseudo
    /// entry).
    fn is_file(&self) -> bool {
        self.pathname.starts_with('/')
    }
}

/// One guest process from the procfs dump.
#[derive(Debug, Clone, Deserialize)]
pub struct GuestProcess {
    #[serde(default)]
    pub exe: String,
    /// Task creation time, nanoseconds since the Unix epoch.
    #[serde(rename = "clone_ts", default)]
    pub clone_ts_ns: i64,
    #[serde(default)]
    status: GuestStatus,
    #[serde(default)]
    maps: Vec<GuestMapping>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct GuestStatus {
    #[serde(default)]
    comm: String,
    #[serde(default)]
    pid: i32,
}

/// What a guest-maps lookup says about one address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestAddr {
    /// Falls in a guest file mapping: symbolizable against the file at
    /// `guest_path` (resolved via the container rootfs) at `file_offset`.
    File {
        guest_path: String,
        file_offset: u64,
        module: String,
    },
    /// Runtime-injected region (`[usertrap]`): sandbox overhead.
    Runtime,
    /// Guest-anonymous memory (JIT output, heap made executable, ...).
    Anon,
    /// Not mapped in the guest at all.
    Unmapped,
}

impl GuestProcess {
    pub fn comm(&self) -> &str {
        &self.status.comm
    }

    pub fn pid(&self) -> i32 {
        self.status.pid
    }

    /// Classify one guest virtual address against this process's maps.
    pub fn lookup(&self, addr: u64) -> GuestAddr {
        let Some(m) = self.maps.iter().find(|m| m.contains(addr)) else {
            return GuestAddr::Unmapped;
        };
        match m.pathname.as_str() {
            path if m.is_file() => {
                let module = Path::new(path)
                    .file_name()
                    .and_then(|f| f.to_str())
                    .unwrap_or("unknown")
                    .to_string();
                GuestAddr::File {
                    guest_path: path.to_string(),
                    file_offset: addr - m.addr.start + m.offset,
                    module,
                }
            }
            "[usertrap]" => GuestAddr::Runtime,
            _ => GuestAddr::Anon,
        }
    }

    /// Executable file ranges, the correlation fingerprint: under systrap
    /// a stub maps guest text at identical addresses, so a mirroring stub
    /// agrees on every one of these.
    fn exec_file_ranges(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.maps
            .iter()
            .filter(|m| m.perms.execute && m.perms.read && m.is_file())
            .map(|m| (m.addr.start, m.addr.end))
    }
}

/// One sandbox reached over its control socket.
#[derive(Debug)]
struct Sandbox {
    processes: Vec<GuestProcess>,
}

/// Snapshot of every reachable sandbox on the host.
#[derive(Debug, Default)]
pub struct SandboxIndex {
    sandboxes: Vec<Sandbox>,
}

impl SandboxIndex {
    /// Probe the runsc state roots and dump every reachable sandbox.
    /// Errors are per-sandbox and non-fatal: an unreachable socket (racing
    /// teardown, permissions) just leaves that sandbox out, and callers
    /// degrade to host-only symbolization.
    pub fn load() -> Self {
        let roots = std::env::var("SYSTING_RUNSC_ROOTS")
            .map(|v| v.split(':').map(PathBuf::from).collect::<Vec<_>>())
            .unwrap_or_else(|_| DEFAULT_RUNSC_ROOTS.iter().map(PathBuf::from).collect());

        // Each wedged sandbox can cost up to RPC_TIMEOUT per I/O step, so a
        // host full of broken sandboxes must not stall symbolization: stop
        // enumerating once the total budget is spent and work with what was
        // gathered.
        let deadline = std::time::Instant::now() + LOAD_BUDGET;

        let mut index = SandboxIndex::default();
        for root in roots {
            let Ok(entries) = std::fs::read_dir(&root) else {
                continue;
            };
            for entry in entries.flatten() {
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                if !name.starts_with("runsc-") || !name.ends_with(".sock") {
                    continue;
                }
                if std::time::Instant::now() >= deadline {
                    eprintln!(
                        "Note: gvisor sandbox enumeration stopped after {LOAD_BUDGET:?}; \
                         {} sandbox(es) snapshotted",
                        index.sandboxes.len()
                    );
                    return index;
                }
                match procfs_dump(&entry.path()) {
                    Ok(processes) => index.sandboxes.push(Sandbox { processes }),
                    Err(e) => {
                        eprintln!(
                            "Note: gvisor guest maps unavailable for {}: {e}",
                            entry.path().display()
                        );
                    }
                }
            }
        }
        index
    }

    /// Whether any sandbox was reached.
    pub fn is_empty(&self) -> bool {
        self.sandboxes.is_empty()
    }

    /// Find the guest process a host stub mirrors, from the stub's own
    /// executable file-backed ranges (as `(start, end)` pairs). Every
    /// stub exec-file range must appear in the guest's maps (the stub may
    /// see *fewer* — pool islands split its view — never different ones),
    /// and the best-scoring guest process wins. Fork-siblings can tie
    /// (identical layouts); any of them symbolizes identically, so ties
    /// resolve to the first.
    pub fn correlate(&self, stub_exec_ranges: &[(u64, u64)]) -> Option<&GuestProcess> {
        if stub_exec_ranges.is_empty() {
            return None;
        }
        let mut best: Option<(usize, &GuestProcess)> = None;
        for sandbox in &self.sandboxes {
            for proc in &sandbox.processes {
                let guest: Vec<(u64, u64)> = proc.exec_file_ranges().collect();
                if guest.is_empty() {
                    continue;
                }
                // Score: stub ranges contained in some guest range. The
                // stub's file mappings are fragments of the guest's
                // (usertrap islands split them), so containment — not
                // equality — is the right test.
                let score = stub_exec_ranges
                    .iter()
                    .filter(|(s, e)| guest.iter().any(|(gs, ge)| gs <= s && e <= ge))
                    .count();
                if score == stub_exec_ranges.len() && best.map(|(b, _)| score > b).unwrap_or(true) {
                    best = Some((score, proc));
                }
            }
        }
        best.map(|(_, p)| p)
    }
}

/// Issue one `containerManager.ProcfsDump` call on a control socket.
fn procfs_dump(socket: &Path) -> std::io::Result<Vec<GuestProcess>> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(RPC_TIMEOUT))?;
    stream.set_write_timeout(Some(RPC_TIMEOUT))?;
    stream.write_all(br#"{"method":"containerManager.ProcfsDump","arg":{}}"#)?;

    let mut buf = Vec::new();
    let mut chunk = [0u8; 65536];
    loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > RPC_MAX_RESPONSE {
            return Err(std::io::Error::other("oversized urpc response"));
        }
        if json_complete(&buf) {
            break;
        }
    }
    parse_dump_response(&buf)
}

/// The urpc response has no length framing — it is one JSON object on a
/// stream socket — so completion is detected by brace balance outside
/// string literals.
fn json_complete(buf: &[u8]) -> bool {
    let mut depth = 0i64;
    let mut in_str = false;
    let mut esc = false;
    let mut seen = false;
    for &b in buf {
        if esc {
            esc = false;
            continue;
        }
        match b {
            b'\\' if in_str => esc = true,
            b'"' => in_str = !in_str,
            b'{' | b'[' if !in_str => {
                depth += 1;
                seen = true;
            }
            b'}' | b']' if !in_str => depth -= 1,
            _ => {}
        }
    }
    seen && depth == 0
}

#[derive(Deserialize)]
struct UrpcResponse {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    err: String,
    #[serde(default)]
    result: Vec<GuestProcess>,
}

fn parse_dump_response(buf: &[u8]) -> std::io::Result<Vec<GuestProcess>> {
    let resp: UrpcResponse = serde_json::from_slice(buf)
        .map_err(|e| std::io::Error::other(format!("urpc decode: {e}")))?;
    if !resp.success {
        return Err(std::io::Error::other(format!("urpc error: {}", resp.err)));
    }
    Ok(resp.result)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Captured from a live runsc (release-20260622.0, systrap) via
    /// `containerManager.ProcfsDump`; trimmed to one process, values
    /// verbatim (addresses are decimal in the wire format).
    const DUMP_FIXTURE: &str = r#"{"success":true,"err":"","result":[{
        "exe":"/bin/guestbox",
        "args":["/bin/sh","-c","i=0; while true; do i=$((i+1)); done"],
        "clone_ts":1783097237157224250,
        "status":{"comm":"sh","pid":1,"ppid":0},
        "maps":[
            {"address":{"Start":405504,"End":425984},
             "permissions":{"Read":true,"Write":false,"Execute":true},
             "private":"p","offset":0,"pathname":"[usertrap]"},
            {"address":{"Start":4194304,"End":5316608},
             "permissions":{"Read":true,"Write":false,"Execute":true},
             "private":"p","offset":0,"deviceMinor":17,"inode":8,
             "pathname":"/bin/guestbox"},
            {"address":{"Start":7409664,"End":7421952},
             "permissions":{"Read":true,"Write":true,"Execute":false},
             "private":"p","offset":1118208,"deviceMinor":17,"inode":8,
             "pathname":"/bin/guestbox"},
            {"address":{"Start":7426048,"End":7430144},
             "permissions":{"Read":true,"Write":true,"Execute":false},
             "private":"p","offset":0,"pathname":"[heap]"},
            {"address":{"Start":139437156392960,"End":139437164781568},
             "permissions":{"Read":true,"Write":true,"Execute":false},
             "private":"p","offset":0,"pathname":"[stack]"}
        ]}]}"#;

    #[test]
    fn test_parse_dump_fixture() {
        let procs = parse_dump_response(DUMP_FIXTURE.as_bytes()).unwrap();
        assert_eq!(procs.len(), 1);
        let p = &procs[0];
        assert_eq!(p.comm(), "sh");
        assert_eq!(p.pid(), 1);
        assert_eq!(p.exe, "/bin/guestbox");
        assert_eq!(p.clone_ts_ns, 1783097237157224250);
        assert_eq!(p.maps.len(), 5);
    }

    #[test]
    fn test_lookup_classification() {
        let procs = parse_dump_response(DUMP_FIXTURE.as_bytes()).unwrap();
        let p = &procs[0];

        // Guest text: file offset math against the mapping base.
        match p.lookup(0x400000 + 0x1234) {
            GuestAddr::File {
                guest_path,
                file_offset,
                module,
            } => {
                assert_eq!(guest_path, "/bin/guestbox");
                assert_eq!(file_offset, 0x1234);
                assert_eq!(module, "guestbox");
            }
            other => panic!("expected File, got {other:?}"),
        }

        // Data segment carries its own file offset.
        match p.lookup(7409664 + 0x10) {
            GuestAddr::File { file_offset, .. } => assert_eq!(file_offset, 1118208 + 0x10),
            other => panic!("expected File, got {other:?}"),
        }

        // The Sentry labels its trampoline table; heap/stack are guest
        // anonymous; unmapped is unmapped.
        assert_eq!(p.lookup(405504 + 0x100), GuestAddr::Runtime);
        assert_eq!(p.lookup(7426048 + 0x10), GuestAddr::Anon);
        assert_eq!(p.lookup(0xdead_0000_0000), GuestAddr::Unmapped);
    }

    #[test]
    fn test_correlate_containment() {
        let procs = parse_dump_response(DUMP_FIXTURE.as_bytes()).unwrap();
        let index = SandboxIndex {
            sandboxes: vec![Sandbox { processes: procs }],
        };

        // A stub's file view is fragments of the guest text range
        // (usertrap islands split it) — containment must match.
        let stub_fragments = vec![(0x400000u64, 0x4c2000u64), (0x4c3000u64, 0x4cd000u64)];
        let p = index.correlate(&stub_fragments).expect("must correlate");
        assert_eq!(p.comm(), "sh");

        // A range outside every guest mapping must not correlate.
        assert!(index
            .correlate(&[(0x7f00_0000_0000, 0x7f00_0000_1000)])
            .is_none());
        // Partial agreement (one matching, one alien) must not correlate.
        assert!(index
            .correlate(&[(0x400000, 0x4c2000), (0x7f00_0000_0000, 0x7f00_0000_1000)])
            .is_none());
        // Empty stub view never correlates.
        assert!(index.correlate(&[]).is_none());
    }

    #[test]
    fn test_json_complete() {
        assert!(json_complete(br#"{"a":1}"#));
        assert!(json_complete(br#"{"a":"}{"}"#), "braces in strings ignored");
        assert!(json_complete(br#"{"a":"\"}{"}"#), "escapes handled");
        assert!(!json_complete(br#"{"a":1"#));
        assert!(!json_complete(b""));
        assert!(json_complete(DUMP_FIXTURE.as_bytes()));
    }

    #[test]
    fn test_error_response() {
        let err = parse_dump_response(br#"{"success":false,"err":"nope","result":[]}"#);
        assert!(err.is_err());
        let garbage = parse_dump_response(b"not json");
        assert!(garbage.is_err());
    }
}
