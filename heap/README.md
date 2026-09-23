# systing-heap

`systing-heap` reads heap snapshots into a systing DuckDB database.

A heap snapshot is a file an allocator writes on its own: for each allocation stack, the objects and bytes the process still had allocated from it at that moment.
It is not a recording of malloc and free calls; systing's `memory-alloc` recorder does that.

The tool parses each snapshot, symbolizes its stacks, and writes them into the same `frame` and `stack` tables every systing recorder uses, plus two heap tables.
The database opens in `systing-analyze` and merges with other traces like any capture.

To set a service up to write snapshots, see [`docs/HEAP_SNAPSHOTS.md`](../docs/HEAP_SNAPSHOTS.md).

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

## Perfetto output

Give `-o` a Perfetto extension (`.pb`, as systing's traces use, or `.perfetto`, `.pftrace`, `.perfetto-trace`) and the snapshots are written as native heap profiles, the format Perfetto's own heap profiler (heapprofd) writes, instead of a DuckDB database:

```bash
systing-heap -o heap.pb /data/heap/jeprof
```

Open it at [ui.perfetto.dev](https://ui.perfetto.dev): each process gets a heap-profile track with a marker per snapshot, and clicking a marker shows its flamegraph.

- **Frames are split like task stacks'.** A frame is named after the function alone, its module is the frame's mapping, and the source file and line are its symbols (Python frames: the file and line 0, since a trampoline names a function and its file but not a line). Python frames' mapping is `[python]`. Mappings carry a `systing-heap:<module>` build id, which Perfetto needs to attach the symbols; it is not an ELF build id.
- **The numbers are estimates.** Each stack's sampled counts are unbiased before anything is added up (see Sampling and unbiasing), the same `est_*` values the DuckDB tables hold.
- **Each snapshot holds its increase since the previous one,** and Perfetto adds them up, so the flamegraph at a marker shows the state at that snapshot. "Unreleased" is the live estimate. "Total allocated" is jemalloc's cumulative total when it ran with `prof_accum:true`; otherwise it is the smallest total consistent with the live counts seen, which is a lower bound.
- **Every snapshot is loaded.** A timeline is for history, so with a prefix input a Perfetto output loads every snapshot on disk, then, once the trace is written, deletes each process's older ones as the DuckDB output does. The history is in the trace; each run's trace covers the snapshots written since the last run. `--keep-all` deletes nothing.

## One snapshot per process

Users usually care about the current state, so with a prefix input the tool keeps one snapshot per process and removes the rest.

- **Which files.** Files directly in the prefix's directory whose names start with the prefix's file name. Subdirectories are never read.
- **Which process.** The pid is the number jemalloc writes right after the prefix (`<prefix>.<pid>.<seq>...`). Nothing after the sequence number is examined.
- **Which snapshot.** The highest sequence number for that pid. If a name has no sequence number, the file's modification time decides.
- **Loaded.** Each pid's latest snapshot. If the latest does not parse (jemalloc may still be writing it), the newest one that parses is loaded, and the unparsed newer file is kept. A Perfetto output loads the older ones too (see Perfetto output).
- **Deleted.** That pid's files older than the loaded one, and only after the new output is in place and synced. Each deletion is printed. With a DuckDB output their contents are in no database: only the latest is loaded.
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
The tool warns about files that are missing, and about files whose device and inode differ from the ones in the dump, since those may be a different build.
On an overlay filesystem (most container images) the pair the dump records and the pair the file shows can differ for the same file, so there the warning means "not provably the same file", not "changed".

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

- **Turn trampolines on early.** Trampolines only wrap functions called after they are on, so a frame already running (the module that calls `install()`, a long-lived main loop) has none, in this and every later snapshot. `PYTHONPERFSUPPORT=1` turns them on at startup. The hook applies only to allocations sampled after `install()`.
- **Forking processes.** Each worker starts a perf map of its own, so the frames it inherited already running from the parent (a pre-fork server's loop, under every worker's stacks) are named in none the worker's dumps can use. On Python 3.13+, call `systing_heap_hooks.keep_perf_map_across_fork()` once in the parent, with trampolines on, before it forks: each child then adds the parent's map to its own. (CPython's own persist-after-fork setting is not used: it stops the child making trampolines, so what the worker runs afterwards goes unnamed.) The hook itself is fork-safe: unwinds take one lock, and a fork waits for any unwind in progress, since libunwind's cache lock has no fork handler of its own.
- **Function granularity.** A trampoline is per function, so Python frames name the function and file (full path in `frame_file`), not the line. Library code gets pystacks' module prefix (`pkg.mod:Cls.run (python) [mod.py]`), so the same function has the same name as in a capture's stacks, apart from the line: pystacks writes `[mod.py:42]`, so drop the `:<line>` (`regexp_replace(name, ':\d+\]$', ']')`) to join the two by name.
Application code has no module prefix, so two functions with the same qualified name in files with the same base name are one frame.
- **Keep the perf map.** `systing-heap` looks for `perf-<pid>.map` in `--perf-map-dir`, then beside the snapshot, then `/tmp`. In a container, `/tmp` is the container's, so copy the map out with the dumps. Without it, Python frames show as `unknown ([anon:exec])` and the tool warns. It prints which map named each process's frames, and a map is consulted only for addresses the dump's own memory map puts in anonymous executable memory, so a stale map cannot name data. A refused candidate falls through to the next. A map is read only if it is a regular file (symlinks are not followed) of at most 256 MiB, and one in a world-writable directory such as `/tmp` only if you or root own it, as perf requires: otherwise another user could name your frames.
- **Cost.** Trampolines add a native call to every Python call: a benchmark made only of function calls ran about 40% slower. Code that spends its time in C pays far less. The hook runs only for sampled allocations, so a finer sample period runs it more often (32 times as often per byte at a 16 KiB period as at the 512 KiB default), and threads unwinding at the same moment wait for one another.

## Sampling and unbiasing

jemalloc does not record every allocation.
It samples: on average one allocation per `sample_period` bytes allocated (`2^lg_prof_sample`, 512 KiB by default), so an allocation of `s` bytes is recorded with probability `1 - exp(-s / sample_period)`.
Large allocations are nearly always recorded; small ones rarely.
At a 16 KiB period a 64 KiB buffer is recorded 98% of the time and a 256-byte object about once in 64.

So a dump's counts are samples, not totals, and each stack's counts must be scaled back up to estimate what the process really holds.
`systing-heap` does this for every row, the way jeprof does:

```
factor = 1 / (1 - exp(-(bytes / objects) / sample_period))
est_bytes   = bytes   * factor
est_objects = objects * factor
```

`bytes / objects` is the stack's mean object size, so small objects get a large factor and large ones a factor near 1.
jemalloc 5.3 writes each stack's counts so that this per-stack step gives jemalloc's own estimate for that stack, even when the stack mixes object sizes.

**Scale first, then add up.**
The factor depends on the object size, so it must be applied to each stack on its own, and only the scaled values added together, across stacks, snapshots or machines.
Adding the raw counts first and scaling the sum under-counts small objects badly, as jemalloc's own notes explain ([PROFILING_INTERNALS.md, "Aggregation must be done after unbiasing samples"](https://github.com/jemalloc/jemalloc/blob/dev/doc_internal/PROFILING_INTERNALS.md#aggregation-must-be-done-after-unbiasing-samples)).
This is why the tables store the estimate of every row (`est_*`) and not the dump's header totals, which are a sum over stacks (in jemalloc 5.3 interval dumps not always equal to the rows' own sum).

**How close it gets.**
For a Python program holding 97.1 MB (jemalloc's own count, with sampling off) in a mix of small, medium and large objects, the sum of `est_live_bytes` came to 86 to 102 MB over three runs at the default period, and to within 2% at a 16 KiB period.
The sampled counts alone came to 3% and 6% of the real heap; how far off they are depends on object size, and for objects several times the period they come close.
A finer period gives a closer estimate, but sampling itself costs memory: jemalloc keeps each sampled object in a larger block, so the process's real heap grew from 97 MB to 159 MB at the 16 KiB period.
`heap/tests/estimates.rs` checks this end to end.

## Tables

`heap_snapshot` has one row per snapshot file.

| Column | Meaning |
|---|---|
| `id` | Snapshot id, dense within the trace |
| `format` | `jemalloc` |
| `source_path` | The file read |
| `upid` | `process.upid` of the pid in the file name, as the writing process saw it in its own pid namespace; NULL if the name has none |
| `seq` | The allocator's dump sequence number |
| `dump_trigger` | `interval` (every `lg_prof_interval` bytes), `manual` (`mallctl("prof.dump")`), `gdump` (new high-water mark), `final` (at exit) |
| `dumped_at_unix_ns` | The file's modification time when read, wall-clock; a copy that does not keep times moves it |
| `sample_period` | Mean bytes between samples (`2^lg_prof_sample`) |

`heap_sample` has one row per distinct allocation stack in a snapshot.

| Column | Meaning |
|---|---|
| `snapshot_id` | `heap_snapshot.id` |
| `stack_id` | `stack.id` |
| `est_live_objects`, `est_live_bytes` | **Estimated** objects and bytes allocated from this stack and not yet freed, in the whole process. Use these. |
| `est_alloc_objects`, `est_alloc_bytes` | Estimated cumulative allocations since start; 0 unless jemalloc ran with `prof_accum:true` |
| `live_objects`, `live_bytes`, `alloc_objects`, `alloc_bytes` | The sampled counts as jemalloc wrote them, before unbiasing. Never add them up as totals |

A total over many rows is close; one row's estimate is only as good as the samples behind it, about ±1/√`live_objects`.
One sampled 256-byte object at a 16 KiB period reads 16,512 bytes, give or take all of it, so check `live_objects` before trusting a small stack's estimate.

Pids are the writing process's own, in its pid namespace.
Two containers whose main process is pid 1 share one `process` row when their dumps are read into one database, and heap rows carry no host or container of their own; `source_path` says where each came from.
A DuckDB merge keeps these tables; a schema-24 reader's merge, or an export to parquet and back, drops them without a message.

## Queries

Ids are per trace, so a database holding more than one trace (a merge) groups by `trace_id` as well.

A snapshot's estimated live heap:

```sql
SELECT trace_id, snapshot_id, sum(est_live_bytes) AS est_live_bytes
FROM heap_sample GROUP BY trace_id, snapshot_id ORDER BY trace_id, snapshot_id;
```

Estimated live bytes by the function that allocated, per snapshot: the innermost frame of each stack that is in the program's own binary (`myprogram` here):

```sql
WITH own AS (
  SELECT h.snapshot_id, h.est_live_bytes, arg_max(fr.name, u.idx) AS fn
  FROM heap_sample h
  JOIN stack s ON s.trace_id = h.trace_id AND s.id = h.stack_id,
       unnest(s.frame_ids) WITH ORDINALITY AS u(fid, idx)
  JOIN frame fr ON fr.trace_id = s.trace_id AND fr.id = u.fid
  WHERE fr.name LIKE '%(myprogram%'
  GROUP BY h.trace_id, h.snapshot_id, h.stack_id, h.est_live_bytes
)
SELECT snapshot_id, fn, sum(est_live_bytes) AS est_live_bytes
FROM own GROUP BY ALL ORDER BY snapshot_id, est_live_bytes DESC;
```

Whole stacks, largest first, in the final snapshot:

```sql
SELECT h.est_live_bytes, sf.frame_names
FROM heap_sample h
JOIN heap_snapshot hs ON hs.trace_id = h.trace_id AND hs.id = h.snapshot_id
JOIN stack_frames sf ON sf.trace_id = h.trace_id AND sf.id = h.stack_id
WHERE hs.dump_trigger = 'final'
ORDER BY h.est_live_bytes DESC;
```

Growth between each process's first and last snapshot, by stack.
Stack ids compare only within one process (frames carry absolute addresses, which differ between processes), and one stack id can have more than one row in a snapshot, hence the sums.
With a prefix input and no `--keep-all` there is one snapshot per process, so read with `--keep-all` for this.
A snapshot whose file name lost its pid or its sequence number has none to order by, and drops out.

```sql
WITH rows AS (
  SELECT h.*, s.upid, s.seq FROM heap_sample h
  JOIN heap_snapshot s ON s.trace_id = h.trace_id AND s.id = h.snapshot_id
),
ends AS (
  SELECT trace_id, upid, min(seq) AS first_seq, max(seq) AS last_seq
  FROM heap_snapshot GROUP BY trace_id, upid
)
SELECT r.trace_id, r.upid, r.stack_id,
       coalesce(sum(r.est_live_bytes) FILTER (WHERE r.seq = ends.last_seq), 0)
     - coalesce(sum(r.est_live_bytes) FILTER (WHERE r.seq = ends.first_seq), 0) AS growth
FROM rows r JOIN ends USING (trace_id, upid)
GROUP BY ALL ORDER BY growth DESC;
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

In the result (`est_live_bytes`), `leak_buffers` grows by about 2 MiB a round and reaches about 16 MiB in the final snapshot.
`build_list` grows to about 3 MB before the program frees the list, `cache_fill` stays about 1 MiB, and `churn` does not appear, since it frees everything it allocates.
Unscaled, `build_list` reads about 45 KB: its 256-byte objects are the ones sampling misses most.
