# Systing Heap Snapshots

What a team changes in an existing service so it writes heap snapshots that systing can load: which code holds the service's memory, by call stack.
Part 1 works for any service and gives native stacks.
Part 2 adds Python functions to those stacks for Python services.
The last part shows how to collect the snapshots with `systing-heap`.
For every column of the tables and more queries, see the tool's README, [`heap/README.md`](../heap/README.md).

## In short

- **Any service** (part 1): run it with jemalloc as its allocator and turn on jemalloc's heap profiling. It then writes a snapshot at a regular interval. Environment variables only; no code changes.
- **Python services** also set `PYTHONMALLOC=malloc`, so jemalloc sees all of Python's memory.
- **To see Python functions in the stacks** (part 2): add `PYTHONPERFSUPPORT=1`, and one call at startup so every Python caller is kept.
- **To collect them**: run `systing-heap` on the snapshot folder, for a DuckDB database or a Perfetto trace.

## What a heap snapshot is

A snapshot is a file jemalloc writes on its own, listing the memory the process has allocated and not yet freed at that moment, grouped by the call stack that allocated it.
jemalloc doesn't track every allocation: it samples some of them, and systing scales the samples back up into estimates of the real heap (see "Sampling and unbiasing" in [`heap/README.md`](../heap/README.md)).
The two settings that matter most are how often jemalloc samples and how often it writes a snapshot (both in part 1, step 2).

## Before you start

- **Linux**, and **jemalloc 5.3 or newer built with profiling**. Debian and Ubuntu's `libjemalloc2` package is.
- For part 2: **Python 3.12 or newer** (tested on 3.13; older versions have no perf trampolines) and **`libunwind8`**.
- A folder for snapshots that the service can write to, on a volume if they must outlive the container.

## Part 1: Native stacks (any service)

Stacks show the service's native functions (C, C++, Rust, and in a Python service the interpreter and its C extensions), with file and line where the binaries have debug info.

### 1. Run the service with jemalloc

Install jemalloc in the image and preload it into the service.

```bash
apt-get install -y libjemalloc2
LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libjemalloc.so.2
```

If the service already uses jemalloc, keep it; just check that its build has profiling support.
Without it, no snapshots are written.

> **Services that link jemalloc themselves** instead of preloading it (for example a Rust service using the `tikv-jemallocator` crate) need the build's profiling feature turned on, and a prefixed build may read its settings from a differently named variable, such as `_RJEM_MALLOC_CONF`.
> Check your jemalloc crate or build for both.

### 2. Turn on heap profiling

```bash
MALLOC_CONF=prof:true,prof_prefix:/heap-dumps/jeprof,lg_prof_sample:19,lg_prof_interval:30
```

| Setting | What it means |
|---|---|
| `prof:true` | Turn heap profiling on. |
| `prof_prefix:/heap-dumps/jeprof` | Where snapshots go, and the start of their names: `jeprof.<pid>.<seq>.<kind>.heap`. |
| `lg_prof_sample:19` | Sample about one allocation per 2^19 bytes = **512 KiB** allocated. This is jemalloc's own default, written out so it's visible. A lower number means more detail and more overhead. systing scales the samples back up, so this setting changes how precise the estimates are, not how big. |
| `lg_prof_interval:30` | Write a snapshot every 2^30 bytes = **1 GiB** the service allocates. This counts every allocation, including memory freed again since, so how often it fires depends on how fast the service allocates. jemalloc's default is -1, which writes no snapshots on its own at all. |

| Service allocates | Snapshots at `lg_prof_interval:30` |
|---|---|
| 10 MB/s | About one every 2 minutes (~34 per hour) |
| 100 MB/s | About one every 11 seconds (~340 per hour) |
| 1 GB/s | About one per second: raise the number |

> **Size the interval for your service.**
> 30 suits most services.
> Each step up halves how often snapshots are written: for a service allocating around 1 GB per second, 33 (every 8 GiB) gives about one every 9 seconds.
> For a short test run, a smaller number such as 25 (every 32 MiB) gives snapshots sooner.
> jemalloc itself never deletes snapshots; `systing-heap` does (see "Collect the snapshots").

### 3. Python services: send all of Python's memory through jemalloc

```bash
PYTHONMALLOC=malloc
```

By default Python serves small objects (512 bytes and under) from its own pools, which jemalloc never sees.
In a test with 400,000 small objects, jemalloc saw about 4.5 MB in 2,000 objects without this setting and 59.8 MB in 1.1 million objects with it.
It's needed for native-only stacks too.

### Part 1 as pod environment

```yaml
env:
  - name: LD_PRELOAD
    value: /usr/lib/x86_64-linux-gnu/libjemalloc.so.2
  - name: MALLOC_CONF
    value: prof:true,prof_prefix:/heap-dumps/jeprof,lg_prof_sample:19,lg_prof_interval:30
  - name: PYTHONMALLOC          # Python services only
    value: malloc
volumeMounts:
  - name: heap-dumps
    mountPath: /heap-dumps
```

A Python service set up this way shows the interpreter's own C functions (such as `_PyEval_EvalFrameDefault`) where its Python code ran.
Part 2 replaces those with the Python functions.

## Part 2: Python + native stacks

Everything in part 1, plus two changes, so the stacks show each Python function in its place among the native frames:

```
_start → … → outer (python) [app.py] → leak_in_python (python) [app.py] → PyByteArray… → malloc
```

### 1. Give Python functions their own frames

```bash
PYTHONPERFSUPPORT=1
```

Python then gives each Python function its own native frame (a "perf trampoline"), and writes `/tmp/perf-<pid>.map` naming them.
**Keep that file** with the snapshots: without it, Python frames can't be named.
Each process, forked workers included, writes its own map, named by its pid.
Setting this in the environment, rather than from code, also covers the frames already running at startup, such as the main module and a long-lived loop.

### 2. Keep every Python caller in the stack (recommended)

jemalloc's built-in stack capture stops at the first Python function, so without this step a stack shows only the innermost one.
Ship the helper from [`heap/hooks`](../heap/hooks) in the image (`make` builds `libsysting_heap_hooks.so`; put it next to `systing_heap_hooks.py`) and call it once, early:

```python
import systing_heap_hooks
print(systing_heap_hooks.install(backtrace="libunwind"))
# {'backtrace': 'libunwind', 'trampolines': True, 'reasons': []}
```

If something is missing (no libunwind8, jemalloc not preloaded, profiling off), it falls back to jemalloc's own stacks and says why in `reasons`; it never stops the service.
Pass `strict=True` to fail instead.

> **Services that fork workers** (gunicorn, multiprocessing with fork): call `install()` in each worker after it forks, for example in gunicorn's `post_fork` hook.
> On Python 3.13+, also call `systing_heap_hooks.keep_perf_map_across_fork()` once in the parent at startup, before any worker forks.
> Without it, frames the worker inherited already running from the parent, such as the server's own loop under every request, can't be named in the worker's snapshots.

### Part 1 + part 2 as pod environment

```yaml
env:
  - name: LD_PRELOAD
    value: /usr/lib/x86_64-linux-gnu/libjemalloc.so.2
  - name: MALLOC_CONF
    value: prof:true,prof_prefix:/heap-dumps/jeprof,lg_prof_sample:19,lg_prof_interval:30
  - name: PYTHONMALLOC
    value: malloc
  - name: PYTHONPERFSUPPORT
    value: "1"
volumeMounts:
  - name: heap-dumps
    mountPath: /heap-dumps
```

## Optional: a snapshot on demand

Besides the regular snapshots, a service can write one at a moment it chooses, such as from a debug endpoint or a signal handler.
It needs the same `MALLOC_CONF` as above.

```python
# Python
import ctypes
ctypes.CDLL(None).mallctl(b"prof.dump", None, None, None, ctypes.c_size_t(0))
```

```c
/* C, C++ */
mallctl("prof.dump", NULL, NULL, NULL, 0);
```

> **Not at exit, for Python.**
> jemalloc's snapshot at exit (`prof_final:true`) shows almost nothing for a Python service, because Python frees its objects during shutdown before jemalloc writes it.

## Collect the snapshots with systing-heap

`systing-heap` reads the snapshot files, turns their addresses into function names, scales the samples up into estimates of the real heap, and writes a DuckDB database (for SQL) or a Perfetto trace (to browse as flamegraphs).

### Build it

From the root of this repository:

```bash
cargo build --release -p systing-heap   # target/release/systing-heap
```

### Run it where the service's binaries are

A snapshot records addresses, not names, and `systing-heap` looks the names up in the binaries at the paths the snapshot lists.
Run it in the service's container, or on a machine with the same image.
Otherwise frames show as `unknown (libfoo.so)`, and the tool prints a warning for each missing file.

### The everyday command

Give it the same prefix as `prof_prefix` in `MALLOC_CONF`:

```bash
systing-heap -o heap.duckdb /heap-dumps/jeprof
```

It loads the **latest snapshot of each process**, writes the database, and only then **deletes that process's older snapshots**, so interval snapshots don't pile up on disk.
Each run replaces `heap.duckdb`.
It deletes only regular files directly in that folder whose names start with the prefix and a pid, and whose first line is jemalloc's `heap_v2/` header, and it prints every file it deletes.

| Option | What it does |
|---|---|
| `--dry-run` | Print what would be loaded and deleted; change nothing. Try this first. |
| `--keep-all` | Load every snapshot and delete nothing, for example to see how the heap grew over time. |
| `-o heap.pb` | Write a Perfetto trace instead (also `.perfetto`, `.pftrace`, `.perfetto-trace`). Open it at [ui.perfetto.dev](https://ui.perfetto.dev): each process has a heap-profile track with a marker per snapshot, and clicking one shows its flamegraph. It loads every snapshot on disk, so the timeline shows all of them, then deletes the older ones as above. |
| `--perf-map-dir DIR` | Where to look first for Python's `perf-<pid>.map` (part 2). Without it, the tool looks beside the snapshots, then in `/tmp`. |

Named files or a folder (`systing-heap -o heap.duckdb /heap-dumps/`) are only loaded, never deleted.

### A first look at the database

Each row of `heap_sample` is one allocation stack in one snapshot.
Use the `est_*` columns: they are the estimates for the whole process.
The other count columns are the raw samples, far too small as totals, but they say how many samples an estimate rests on: a stack with only one or two sampled objects has a rough estimate.

```sql
-- estimated live heap per snapshot
SELECT snapshot_id, sum(est_live_bytes) AS est_live_bytes
FROM heap_sample GROUP BY snapshot_id;

-- the biggest stacks in each process's newest snapshot
WITH newest AS (
  SELECT trace_id, id FROM heap_snapshot
  QUALIFY row_number() OVER (PARTITION BY trace_id, upid ORDER BY seq DESC) = 1
)
SELECT h.est_live_bytes, sf.frame_names
FROM heap_sample h
JOIN newest n ON n.trace_id = h.trace_id AND n.id = h.snapshot_id
JOIN stack_frames sf ON sf.trace_id = h.trace_id AND sf.id = h.stack_id
ORDER BY h.est_live_bytes DESC LIMIT 10;
```

The database has systing's full schema, so it also opens with `systing-analyze query -d heap.duckdb`.
[`heap/README.md`](../heap/README.md) has more queries and the details of every column.

### Triggering collection remotely

Coming soon: how to run this remotely, without a shell in the service's container.

## What it costs

| Change | Cost |
|---|---|
| jemalloc profiling | Small at the default `lg_prof_sample:19`. It grows as the number goes down, and each sampled allocation takes some extra memory. |
| Snapshots | Disk: a few KB to a few MB each, as often as the interval fires. |
| `PYTHONMALLOC=malloc` | Some CPU and memory for small objects, which now go through jemalloc instead of Python's pools. Measure it on your workload. |
| Perf trampolines (part 2) | An extra native call on every Python function call: about 40% slower on a benchmark made only of Python calls, far less for code that spends its time in C (numpy, torch). |
| The hook (part 2) | Runs only when jemalloc samples an allocation, so a lower `lg_prof_sample` runs it more often; threads unwinding at the same moment wait for one another. |

## Check that it works

- **Part 1:** after the service has allocated the interval's worth of memory, `/heap-dumps` holds `jeprof.<pid>.<seq>.i<n>.heap` files whose first line is `heap_v2/…`.
- **Part 2:** `install()` prints `'backtrace': 'libunwind'` with empty `reasons`, and `/tmp/perf-<pid>.map` lists lines starting `py::`.

## Known limits

- **No Python line numbers yet.** Python frames name the function and file, not the line, so two functions with the same name in files with the same name show as one.
- **One service per snapshot folder.** Processes are told apart by pid, and containers often share pid 1, so two services writing to one folder would mix.
- **Same binaries later.** Stacks are resolved from the service's own binaries after the fact, so the image must still be available where the snapshots are loaded.
