//! Socket-streaming output transport.
//!
//! When `--stream <URI>` is passed, each parquet table is written to its own
//! socket connection instead of a local file. The wire format is one ASCII
//! header line followed by the raw parquet bytes:
//!
//! ```text
//! systing/<SCHEMA_VERSION> <table_name>\n
//! PAR1 ... <parquet row groups + footer> ... PAR1
//! ```
//!
//! The receiver strips the header line and writes the remainder verbatim to
//! `<table>.parquet`; the resulting directory is bit-identical to what
//! `--output-dir` would have produced and can be fed to `parquet_to_duckdb`.
//!
//! Connections are opened lazily — one per table per writer instance — so a
//! typical trace opens 20–30 connections over its lifetime.

use std::fmt;
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{bail, Context, Result};
use vsock::{VsockAddr, VsockListener, VsockStream};

use crate::duckdb::SCHEMA_VERSION;

/// Prefix on every stream header line.
pub const HEADER_PREFIX: &str = "systing/";

/// Closed allowlist of table names the streaming writer can emit.
///
/// The receiver rejects any header whose table name is not in this list.
/// Keep in sync with the writer fields in `StreamingParquetWriter` and the
/// file stems in `ParquetPaths::new`.
pub const TABLE_NAMES: &[&str] = &[
    "process",
    "thread",
    "sched_slice",
    "thread_state",
    "irq_slice",
    "softirq_slice",
    "wakeup_new",
    "process_exit",
    "counter",
    "counter_track",
    "slice",
    "track",
    "instant",
    "args",
    "instant_args",
    "stack",
    "stack_sample",
    "network_interface",
    "socket_connection",
    "network_syscall",
    "network_packet",
    "network_socket",
    "network_poll",
    "network_dns",
    "memory_rss",
    "memory_map",
    "memory_fault",
    "memory_alloc",
    "clock_snapshot",
    "sysinfo",
    "cpu_info",
    "tpu_device",
    "tpu_op",
    "tpu_metric",
];

/// A socket endpoint to stream parquet data to (or, on the receive side,
/// to listen on).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamTarget {
    /// AF_VSOCK — for guest-VM → host. From inside a guest, the host is CID 2.
    Vsock { cid: u32, port: u32 },
    /// AF_UNIX stream socket.
    Unix(PathBuf),
    /// TCP — `host:port`. Unauthenticated; for trusted networks only.
    Tcp(String),
}

/// Wrap a connected socket in a 64 KiB BufWriter and emit the header line.
/// Generic so the BufWriter holds the concrete stream type — avoids an extra
/// `Box<dyn Write>` vtable hop under parquet's own internal buffering.
fn dial<S: Write + Send + 'static>(sock: S, table: &str) -> Result<Box<dyn Write + Send>> {
    let mut w = BufWriter::with_capacity(64 * 1024, sock);
    writeln!(w, "{HEADER_PREFIX}{SCHEMA_VERSION} {table}")?;
    Ok(Box::new(w))
}

impl StreamTarget {
    /// Dial the target, write the protocol header for `table`, and return a
    /// buffered writer ready for parquet bytes.
    pub fn connect(&self, table: &str) -> Result<Box<dyn Write + Send>> {
        if !TABLE_NAMES.contains(&table) {
            bail!(
                "table {table:?} missing from stream::TABLE_NAMES allowlist; \
                 update the constant when adding a new parquet table"
            );
        }
        match self {
            Self::Vsock { cid, port } => dial(
                VsockStream::connect(&VsockAddr::new(*cid, *port))
                    .with_context(|| format!("vsock connect to cid={cid} port={port}"))?,
                table,
            ),
            Self::Unix(path) => dial(
                UnixStream::connect(path)
                    .with_context(|| format!("unix connect to {}", path.display()))?,
                table,
            ),
            Self::Tcp(addr) => dial(
                TcpStream::connect(addr).with_context(|| format!("tcp connect to {addr}"))?,
                table,
            ),
        }
    }

    /// Bind a listener on this target. Returns an iterator of accepted
    /// `(stream, peer_description)` pairs for the receive side.
    pub fn listen(&self) -> Result<StreamListener> {
        match self {
            Self::Vsock { cid, port } => {
                let l = VsockListener::bind(&VsockAddr::new(*cid, *port))
                    .with_context(|| format!("vsock bind cid={cid} port={port}"))?;
                Ok(StreamListener::Vsock(l))
            }
            Self::Unix(path) => {
                if path.exists() {
                    std::fs::remove_file(path).with_context(|| {
                        format!("removing existing socket path {}", path.display())
                    })?;
                }
                let l = UnixListener::bind(path)
                    .with_context(|| format!("unix bind {}", path.display()))?;
                Ok(StreamListener::Unix(l))
            }
            Self::Tcp(addr) => {
                let l = TcpListener::bind(addr).with_context(|| format!("tcp bind {addr}"))?;
                Ok(StreamListener::Tcp(l))
            }
        }
    }
}

/// Listener side, mirroring [`StreamTarget`].
pub enum StreamListener {
    Vsock(VsockListener),
    Unix(UnixListener),
    Tcp(TcpListener),
}

impl StreamListener {
    /// Block until a peer connects; return the byte stream and a peer label
    /// for logging.
    pub fn accept(&self) -> io::Result<(Box<dyn Read + Send>, String)> {
        match self {
            Self::Vsock(l) => {
                let (s, addr) = l.accept()?;
                Ok((Box::new(s), format!("vsock:{addr:?}")))
            }
            Self::Unix(l) => {
                let (s, _addr) = l.accept()?;
                Ok((Box::new(s), "unix".to_string()))
            }
            Self::Tcp(l) => {
                let (s, addr) = l.accept()?;
                Ok((Box::new(s), format!("tcp:{addr}")))
            }
        }
    }
}

impl FromStr for StreamTarget {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        if let Some(rest) = s.strip_prefix("vsock://") {
            let (cid, port) = rest
                .split_once(':')
                .context("vsock URI must be vsock://CID:PORT")?;
            let cid: u32 = match cid {
                "any" => libc::VMADDR_CID_ANY,
                "host" => libc::VMADDR_CID_HOST,
                "local" => libc::VMADDR_CID_LOCAL,
                n => n.parse().context("invalid vsock CID")?,
            };
            let port: u32 = port.parse().context("invalid vsock port")?;
            Ok(Self::Vsock { cid, port })
        } else if let Some(rest) = s.strip_prefix("unix://") {
            if rest.is_empty() {
                bail!("unix URI must be unix://PATH");
            }
            Ok(Self::Unix(PathBuf::from(rest)))
        } else if let Some(rest) = s.strip_prefix("tcp://") {
            if rest.is_empty() {
                bail!("tcp URI must be tcp://HOST:PORT");
            }
            Ok(Self::Tcp(rest.to_string()))
        } else {
            bail!("unknown stream URI scheme: {s} (expected vsock://, unix://, or tcp://)")
        }
    }
}

impl fmt::Display for StreamTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vsock { cid, port } => write!(f, "vsock://{cid}:{port}"),
            Self::Unix(p) => write!(f, "unix://{}", p.display()),
            Self::Tcp(a) => write!(f, "tcp://{a}"),
        }
    }
}

/// Parsed stream header line.
#[derive(Debug, PartialEq, Eq)]
pub struct StreamHeader {
    pub schema_version: u32,
    pub table: String,
}

impl StreamHeader {
    /// Read and validate the header line from a freshly-accepted stream.
    ///
    /// Returns the parsed header and a `BufReader` positioned at the first
    /// parquet byte. Rejects unknown table names so a hostile peer cannot
    /// influence the output path.
    pub fn read(stream: Box<dyn Read + Send>) -> Result<(Self, BufReader<Box<dyn Read + Send>>)> {
        const MAX_HEADER_LEN: u64 = 256;
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader
            .by_ref()
            .take(MAX_HEADER_LEN)
            .read_line(&mut line)
            .context("reading stream header line")?;
        if !line.ends_with('\n') {
            bail!("stream header missing newline within {MAX_HEADER_LEN} bytes");
        }
        let line = line.trim_end_matches(['\r', '\n']);
        let rest = line.strip_prefix(HEADER_PREFIX).with_context(|| {
            format!("bad stream header (no {HEADER_PREFIX:?} prefix): {line:?}")
        })?;
        let (ver, table) = rest
            .split_once(' ')
            .with_context(|| format!("bad stream header (no table name): {line:?}"))?;
        let schema_version: u32 = ver
            .parse()
            .with_context(|| format!("bad schema version in header: {line:?}"))?;
        if !TABLE_NAMES.contains(&table) {
            bail!("stream header names unknown table {table:?}; rejecting connection");
        }
        Ok((
            Self {
                schema_version,
                table: table.to_string(),
            },
            reader,
        ))
    }
}

/// Reference receiver for `systing --stream`. Used by `systing-util receive`
/// and the integration tests.
pub mod receive {
    use super::*;
    use std::fs::{self, File, OpenOptions};
    use std::net::ToSocketAddrs;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Listen on `target` and write each incoming table stream into
    /// `output_dir`. Runs until interrupted (Ctrl-C) or the listener errors.
    pub fn run(
        target: StreamTarget,
        output_dir: PathBuf,
        insecure_tcp_bind_any: bool,
    ) -> Result<()> {
        if let StreamTarget::Tcp(addr) = &target {
            // Resolve through the same path TcpListener::bind uses, then check
            // for the unspecified address — string prefix matching would miss
            // forms like `0:PORT` or `00.0.0.0:PORT`.
            let bind_any = addr
                .to_socket_addrs()
                .with_context(|| format!("resolving tcp bind address {addr}"))?
                .any(|sa| sa.ip().is_unspecified());
            if bind_any && !insecure_tcp_bind_any {
                bail!(
                    "refusing to bind TCP listener on {addr} (any-address) without \
                     --insecure-tcp-bind-any; this transport is unauthenticated"
                );
            }
        }

        fs::create_dir_all(&output_dir)
            .with_context(|| format!("creating output dir {}", output_dir.display()))?;
        let listener = target.listen()?;
        eprintln!(
            "Listening on {target} (schema version {SCHEMA_VERSION}); writing to {}",
            output_dir.display()
        );

        let active = Arc::new(AtomicUsize::new(0));
        loop {
            let (stream, peer) = match listener.accept() {
                Ok(x) => x,
                Err(e) => {
                    eprintln!("accept error: {e}");
                    return Err(e.into());
                }
            };
            let dir = output_dir.clone();
            let active = active.clone();
            active.fetch_add(1, Ordering::SeqCst);
            std::thread::spawn(move || {
                if let Err(e) = handle_connection(stream, &peer, &dir) {
                    eprintln!("[{peer}] error: {e:#}");
                }
                let n = active.fetch_sub(1, Ordering::SeqCst) - 1;
                eprintln!("[{peer}] closed ({n} active)");
            });
        }
    }

    /// Read one stream's header, validate it, and copy the parquet body into
    /// `dir`. Exposed for the integration test in `tests/stream_unix.rs`.
    pub fn handle_connection(stream: Box<dyn Read + Send>, peer: &str, dir: &Path) -> Result<()> {
        let (hdr, mut body) = StreamHeader::read(stream)?;
        if hdr.schema_version != SCHEMA_VERSION {
            bail!(
                "schema version mismatch: peer sent {}, this build is {}",
                hdr.schema_version,
                SCHEMA_VERSION
            );
        }
        let (path, mut out) = create_unique(dir, &hdr.table)
            .with_context(|| format!("creating output file for table {}", hdr.table))?;
        eprintln!(
            "[{peer}] table={} -> {}",
            hdr.table,
            path.file_name().unwrap().to_string_lossy()
        );
        let bytes = io::copy(&mut body, &mut out)?;
        eprintln!("[{peer}] table={} {} bytes", hdr.table, bytes);
        Ok(())
    }

    /// Atomically create `<dir>/<table>.parquet`, or `<dir>/<table>.<n>.parquet`
    /// for the first free `n`. Uses `create_new` so two handler threads racing
    /// on the same table can't both claim the same path. Multiple
    /// `StreamingParquetWriter` instances may emit the same table, so the
    /// receiver may see e.g. two `process` streams in one trace; duckdb's
    /// `read_parquet` glob handles the suffixed files.
    fn create_unique(dir: &Path, table: &str) -> io::Result<(PathBuf, File)> {
        for n in 0.. {
            let p = if n == 0 {
                dir.join(format!("{table}.parquet"))
            } else {
                dir.join(format!("{table}.{n}.parquet"))
            };
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&p)
            {
                Ok(f) => return Ok((p, f)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        unreachable!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_roundtrip() {
        for s in [
            "vsock://2:5000",
            "unix:///tmp/systing.sock",
            "tcp://127.0.0.1:9000",
        ] {
            let t: StreamTarget = s.parse().unwrap();
            assert_eq!(t.to_string(), s);
        }
    }

    #[test]
    fn parse_vsock() {
        assert_eq!(
            "vsock://2:5000".parse::<StreamTarget>().unwrap(),
            StreamTarget::Vsock { cid: 2, port: 5000 }
        );
    }

    #[test]
    fn parse_rejects_unknown_scheme() {
        assert!("http://foo".parse::<StreamTarget>().is_err());
        assert!("vsock://2".parse::<StreamTarget>().is_err());
        assert!("unix://".parse::<StreamTarget>().is_err());
    }

    #[test]
    fn header_rejects_oversize() {
        let buf = vec![b'x'; 4096];
        let r: Box<dyn Read + Send> = Box::new(io::Cursor::new(buf));
        let err = StreamHeader::read(r)
            .err()
            .expect("expected error")
            .to_string();
        assert!(err.contains("newline"), "{err}");
    }

    #[test]
    fn header_rejects_unknown_table() {
        let buf = format!("{HEADER_PREFIX}{SCHEMA_VERSION} ../../etc/passwd\n").into_bytes();
        let r: Box<dyn Read + Send> = Box::new(io::Cursor::new(buf));
        assert!(StreamHeader::read(r).is_err());
    }

    #[test]
    fn header_accepts_known_table() {
        let buf = format!("{HEADER_PREFIX}{SCHEMA_VERSION} sched_slice\nPAR1rest").into_bytes();
        let r: Box<dyn Read + Send> = Box::new(io::Cursor::new(buf));
        let (hdr, mut rest) = StreamHeader::read(r).unwrap();
        assert_eq!(hdr.table, "sched_slice");
        assert_eq!(hdr.schema_version, SCHEMA_VERSION);
        let mut body = Vec::new();
        rest.read_to_end(&mut body).unwrap();
        assert_eq!(body, b"PAR1rest");
    }
}
