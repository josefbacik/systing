# systing-heap

`systing-heap` reads heap snapshots into a systing DuckDB database.

A heap snapshot is a file an allocator writes on its own: for each allocation stack, the objects and bytes the process still had allocated from it at that moment.
It is not a recording of malloc and free calls; systing's `memory-alloc` recorder does that.

The tool parses each snapshot, symbolizes its stacks, and writes them into the same `frame` and `stack` tables every systing recorder uses, plus two heap tables.
The database opens in `systing-analyze` and merges with other traces like any capture.

## Formats

The format is chosen by file extension.
Pass `--format` to override it.

| Extension | Format | Status |
|---|---|---|
| `.heap` | jemalloc `prof.dump` (`heap_v2`) | supported |
| `.pb.gz`, `.pprof`, `.pb` | pprof | not yet |

gperftools (tcmalloc) also writes `.heap` files.
The jemalloc parser checks the first line and refuses those with a clear error.

## Usage

```bash
cargo build --release -p systing-heap

# The prof_prefix given to jemalloc: the latest snapshot of each process,
# and that process's older dumps deleted.
systing-heap -o heap.duckdb /data/heap/jeprof
systing-heap -o heap.duckdb /data/heap/jeprof --dry-run   # show, change nothing
systing-heap -o heap.duckdb /data/heap/jeprof --keep-all  # every snapshot, delete nothing

# Files or directories: loaded, never deleted.
systing-heap -o heap.duckdb a.heap b.heap
systing-heap -o heap.duckdb ./snapshots/
```

An input that exists as a file or directory is only loaded.
Any other input is taken as a jemalloc `prof_prefix`, and that is the only mode that deletes files.

The database is replaced on every run.
It is written to a temporary file next to it and renamed into place, so a failed run leaves the previous database whole.
Snapshots get ids in dump order: by process id, then by the allocator's sequence number.
All snapshots go under one trace id (`--trace-id`, default `heap`).

Run it one-shot, from cron or a loop, as often as you want the database refreshed.

## One snapshot per process

Users usually care about the current state, so with a prefix input the tool keeps one snapshot per process and removes the rest.

- **Which files.** Files directly in the prefix's directory whose names start with the prefix's file name. Subdirectories are never read.
- **Which process.** The pid is the number jemalloc writes right after the prefix (`<prefix>.<pid>.<seq>...`). Nothing after the sequence number is examined.
- **Which snapshot.** The highest sequence number for that pid. If a name has no sequence number, the file's modification time decides.
- **Loaded.** Each pid's latest snapshot. If the latest does not parse (jemalloc may still be writing it), the newest one that parses is loaded, and the unparsed newer file is kept.
- **Deleted.** That pid's files older than the loaded one, and only after the new database is in place. Each deletion is printed.
- **Kept.** The loaded file itself, and any newer unparsed file.

A file is never read or deleted unless it is a regular file (symlinks are not followed) and its first line is `heap_v2/`.
Files that start with the prefix but fail these checks, or have no pid after the prefix, are left alone with a warning.
Every check and delete goes through one open handle on the directory, and a file is deleted only if its name still refers to the file that was examined.

One pid is one process.
Two processes that write the same pid into the same directory count as one, and the higher sequence numbers win, so the other process's dumps can be deleted.
This happens after a restart that gets its old pid back, or with pid 1 in several containers sharing a directory.
Give each process or container its own directory (or prefix) to avoid it.

jemalloc has no limit on how many dumps it writes, and the interval (`lg_prof_interval`) sets how often it writes one.
Choosing values that fit the disk is up to whoever sets `MALLOC_CONF`; running this tool regularly keeps one file per process on disk.

## Symbolization

Symbolization is offline.
Each jemalloc dump ends with a copy of the process's `/proc/self/maps`.
The tool uses it to turn each address into a file and a file offset, then reads symbols from that file on the machine running `systing-heap`.
So the binaries must exist at the same paths, on the same host or in the same image the process ran in.
The tool warns about files that are missing, and about files whose inode differs from the one in the dump, since those may be a different build.

Frames are named the way systing's recorders name them: `function (module [file:line]) <0xaddr>`.
A frame in a known file with no symbol is `unknown (module) <0xaddr>`.
Stripped system libraries (libc, the distro's libjemalloc) have no symbols for their internal functions, so those frames stay `unknown`.
Every frame except the innermost is a return address, so the tool looks up the byte before it to land on the call itself.

## Python stacks

A Python program's heap stacks can show its Python functions among the native frames:

```
_start → … → outer (python) [app.py] → leak_in_python (python) [app.py] → PyByteArray… → malloc
```

Two things make this work, and the program chooses both at runtime with the helper in `hooks/`:

- **Perf trampolines** (Python 3.12+). Python gives each Python function a small piece of generated code of its own, so a native stack shows one frame per Python function, and names that code in `/tmp/perf-<pid>.map`.
- **A backtrace that walks through them.** The distro jemalloc captures stacks with libgcc's unwinder, which stops at the first trampoline, so only the innermost Python function shows. libunwind walks through them. The hook makes jemalloc use libunwind (`libunwind.so.8`, loaded at runtime).

```bash
make -C heap/hooks          # builds heap/hooks/libsysting_heap_hooks.so
```

```python
import systing_heap_hooks   # heap/hooks on PYTHONPATH, or copy the .py and .so together
print(systing_heap_hooks.install(backtrace="libunwind", trampolines=True))
# {'backtrace': 'libunwind', 'trampolines': True, 'reasons': []}
```

What can't be done is skipped with a warning, and the result says what is active.
For example, without libunwind8 you get `{'backtrace': 'default', ..., 'reasons': ['libunwind.so.8 not found']}`, and stacks keep only the innermost Python function.
It also reports when jemalloc isn't the process's allocator, when profiling is off (`MALLOC_CONF` without `prof:true`), and when jemalloc is older than 5.3.
Pass `strict=True` to raise instead.
`backtrace="default"` puts jemalloc's own back.

The options, from most to least complete:

| Setup | Stacks show |
|---|---|
| Trampolines + `backtrace="libunwind"` | Every Python function, among the native frames |
| Trampolines + a jemalloc built with `--enable-prof-libunwind` (no hook) | The same, expected: jemalloc's libunwind backend makes the same call as the hook; not tested here |
| Trampolines + jemalloc's default | Only the innermost Python function |
| No trampolines | Native frames only (the interpreter's C functions) |

Things to know:

- **Turn trampolines on early.** Trampolines only wrap functions called after they are on, so a frame already running (the module that calls `install()`) has none. `PYTHONPERFSUPPORT=1` turns them on at startup. The hook applies only to allocations sampled after `install()`.
- **Function granularity.** A trampoline is per function, so Python frames name the function and file (full path in `frame_file`), not the line.
- **Keep the perf map.** `systing-heap` looks for `perf-<pid>.map` in `--perf-map-dir`, then beside the snapshot, then `/tmp`. In a container, `/tmp` is the container's, so copy the map out with the dumps. Without it, Python frames show as `unknown ([anon])` and the tool warns. A map is read only if it is a regular file (symlinks are not followed) of at most 256 MiB, and one in a world-writable directory such as `/tmp` only if you or root own it, as perf requires: otherwise another user could name your frames.
- **Cost.** Trampolines add a native call to every Python call: a benchmark made only of function calls ran about 40% slower. Code that spends its time in C pays far less. The hook itself runs only for sampled allocations.

## Tables

`heap_snapshot` has one row per snapshot file.

| Column | Meaning |
|---|---|
| `id` | Snapshot id, dense within the trace |
| `format` | `jemalloc` |
| `source_path` | The file read |
| `upid` | `process.upid` of the pid in the file name; NULL if the name has none |
| `seq` | The allocator's dump sequence number |
| `dump_trigger` | `interval` (every `lg_prof_interval` bytes), `manual` (`mallctl("prof.dump")`), `gdump` (new high-water mark), `final` (at exit) |
| `dumped_at_unix_ns` | The file's modification time |
| `sample_period` | Mean bytes between samples (`2^lg_prof_sample`) |
| `header_live_objects`, `header_live_bytes` | The dump's header totals, as written |

The header totals do not always match the sum of the snapshot's stacks: in jemalloc 5.3 interval dumps they disagree.
Sum `heap_sample` for a snapshot's total.

`heap_sample` has one row per distinct allocation stack in a snapshot.

| Column | Meaning |
|---|---|
| `snapshot_id` | `heap_snapshot.id` |
| `stack_id` | `stack.id` |
| `live_objects`, `live_bytes` | Allocated from this stack and not yet freed |
| `alloc_objects`, `alloc_bytes` | Cumulative since start; 0 unless jemalloc ran with `prof_accum:true` |

Counts are stored as the allocator wrote them.
jemalloc 5.3 and later already scale sampled counts up to estimates of the true totals (`prof_unbias`, on by default).

## Queries

Live bytes by the function that allocated, per snapshot: the innermost frame of each stack that is in the program's own binary (`myprogram` here):

```sql
WITH own AS (
  SELECT h.snapshot_id, h.live_bytes, arg_max(fr.name, u.idx) AS fn
  FROM heap_sample h
  JOIN stack s ON s.trace_id = h.trace_id AND s.id = h.stack_id,
       unnest(s.frame_ids) WITH ORDINALITY AS u(fid, idx)
  JOIN frame fr ON fr.trace_id = s.trace_id AND fr.id = u.fid
  WHERE fr.name LIKE '%(myprogram%'
  GROUP BY h.trace_id, h.snapshot_id, h.stack_id, h.live_bytes
)
SELECT snapshot_id, fn, sum(live_bytes) AS live_bytes
FROM own GROUP BY ALL ORDER BY snapshot_id, live_bytes DESC;
```

Whole stacks, largest first, in the final snapshot:

```sql
SELECT h.live_bytes, sf.frame_names
FROM heap_sample h
JOIN heap_snapshot hs ON hs.trace_id = h.trace_id AND hs.id = h.snapshot_id
JOIN stack_frames sf ON sf.trace_id = h.trace_id AND sf.id = h.stack_id
WHERE hs.dump_trigger = 'final'
ORDER BY h.live_bytes DESC;
```

Growth between the first and last snapshot, by stack:

```sql
WITH b AS (
  SELECT stack_id, snapshot_id, live_bytes FROM heap_sample
)
SELECT stack_id,
       coalesce(max(live_bytes) FILTER (WHERE snapshot_id = (SELECT max(id) FROM heap_snapshot)), 0)
     - coalesce(max(live_bytes) FILTER (WHERE snapshot_id = (SELECT min(id) FROM heap_snapshot)), 0) AS growth
FROM b GROUP BY stack_id ORDER BY growth DESC;
```

## Examples

`examples/<format>/` holds a program that produces snapshots of that format.

`examples/jemalloc/` builds `alloc_and_dump.c` and runs it with jemalloc preloaded and `MALLOC_CONF` set, so jemalloc writes snapshots on its own.
The program never calls jemalloc directly.
It needs a C compiler and a libjemalloc built with profiling; Debian and Ubuntu's `libjemalloc2` is.

```bash
heap/examples/jemalloc/run.sh /tmp/snaps     # writes jeprof.<pid>.<seq>.<kind>.heap files
systing-heap -o /tmp/heap.duckdb /tmp/snaps
```

In the result, `leak_buffers` grows by about 2 MiB a round and reaches about 16 MiB in the final snapshot.
`cache_fill` stays under 1 MiB, and `churn` does not appear, since it frees everything it allocates.
