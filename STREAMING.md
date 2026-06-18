# Streaming output (`--stream`)

`--stream <URI>` makes systing write each parquet table to a socket connection
instead of the local filesystem. This is intended for running systing inside a
guest VM (or other constrained environment) and shipping the trace out to a
host-side receiver that assembles parquet files and imports them into DuckDB.

## URI schemes

| URI                      | Transport | Notes |
|--------------------------|-----------|-------|
| `vsock://CID:PORT`       | AF_VSOCK  | Guest → host. From inside a guest, the host is **CID 2**. |
| `unix:///path/to.sock`   | AF_UNIX   | Local stream socket. |
| `tcp://host:port`        | TCP       | **Unauthenticated.** Trusted networks only. |

`--stream` is mutually exclusive with `--output` and `--parquet-only`. No local
parquet directory or DuckDB file is produced; the receiver owns conversion.

## Wire protocol

One connection per parquet table, opened lazily on the first row-group flush
for that table (≈20–30 connections over a trace lifetime). Each connection
carries:

```
systing/<SCHEMA_VERSION> <table_name>\n
<raw parquet bytes ...>
```

The first line is ASCII; everything after the `\n` is the unmodified parquet
file (PAR1 magic, row groups, footer, PAR1). `SCHEMA_VERSION` is the integer
from `src/duckdb.rs`; `table_name` is the DuckDB table / parquet file stem
(`sched_slice`, `stack_sample`, …) and is always one of the names in
`systing::stream::TABLE_NAMES`.

The connection is closed after the parquet footer is written. A receiver can
treat the body as opaque: strip the header line, write the rest to
`<table>.parquet`, and run the existing parquet → DuckDB import.

Multiple writer instances may emit the same table (e.g. `process` rows come
from several recorders), so a receiver should suffix duplicates
(`process.1.parquet`, …); DuckDB's `read_parquet('dir/process*.parquet')`
handles this.

## Reference receiver

```sh
# Host (or wherever the listener lives):
systing-util receive unix:///tmp/systing.sock --output-dir ./traces

# Guest / sender:
sudo systing --duration 10 --stream unix:///tmp/systing.sock
```

For vsock from a KVM/QEMU guest, the host listens with
`systing-util receive vsock://any:5000 -o ./traces` (`any` =
`VMADDR_CID_ANY`; `host` and `local` are also accepted) and the guest dials
`--stream vsock://2:5000` (or `vsock://host:5000`). With Firecracker /
Cloud Hypervisor's vhost-user-vsock backend the host side is exposed as a
unix socket, so the receiver uses `unix://` instead.

The receiver validates the header against `TABLE_NAMES` and rejects anything
else, so a hostile peer cannot influence the output path. TCP listeners refuse
to bind on `0.0.0.0` / `[::]` without `--insecure-tcp-bind-any`.

`systing-util receive` is a reference implementation: it spawns one thread per
connection without bound and has no graceful-shutdown handling, so Ctrl-C
during an active trace can leave a half-written `.parquet` file. A production
host-side daemon should bound concurrency and drain in-flight connections on
SIGINT.

## Spill files

Stack and memory recorders spill interner state to disk during recording. In
stream mode this goes to a private (mode 0700) `systing-spill-*` directory
under `$TMPDIR`, removed when the trace ends. No trace data is left on the
guest.
