//! Integration test for the memory recorder.
//!
//! Spawns an allocator workload, traces it with `--add-recorder memory`, and
//! validates the `memory_rss`, `memory_map`, and `memory_fault` tables.
//!
//! Requires root/BPF privileges; run via:
//! ```
//! ./scripts/run-integration-tests.sh memory_recorder
//! ```

mod common;

use common::workload::{wait_until, SLOW_MACHINE_BUDGET};
use systing::{systing, Config, KernelHooks};
use tempfile::TempDir;

/// Size of each allocation in the workload. Must be well above the glibc
/// MMAP_THRESHOLD (128 KiB default) so that every `bytearray` goes through
/// mmap rather than the brk-managed heap.
const ALLOC_SIZE_BYTES: i64 = 2 * 1024 * 1024;
const ALLOC_COUNT: i64 = 50;
/// Upper bound for anon-RSS sanity (guards against unit bugs like bytes vs pages).
const RSS_SANITY_CEILING_BYTES: i64 = 64 * 1024 * 1024 * 1024;

/// SQL fragment that resolves the set of utids belonging to a given Linux pid.
const UTIDS_FOR_PID: &str =
    "(SELECT t.utid FROM thread t JOIN process p ON p.upid = t.upid WHERE p.pid = ?)";

#[test]
#[ignore] // Requires root/BPF privileges
fn test_memory_recorder_e2e() {
    let dir = TempDir::new().expect("Failed to create temp dir");
    let trace_path = dir.path().join("trace.pb");

    // Workload: allocate ALLOC_COUNT buffers of ALLOC_SIZE_BYTES each, touch
    // them (to force page faults / anon-RSS growth), then release them. A short
    // pre-sleep is not needed: spawn_traced_child holds the child until BPF is
    // attached and then signals exec.
    let py_prog = format!(
        "import time\n\
         bufs=[]\n\
         for _ in range({count}):\n\
         \x20 b=bytearray({size})\n\
         \x20 b[0]=1; b[-1]=1\n\
         \x20 bufs.append(b)\n\
         \x20 time.sleep(0.01)\n\
         del bufs\n\
         time.sleep(0.2)\n",
        count = ALLOC_COUNT,
        size = ALLOC_SIZE_BYTES,
    );
    let run_cmd = vec!["python3".to_string(), "-c".to_string(), py_prog];
    let traced_child =
        systing::traced_command::spawn_traced_child(&run_cmd).expect("Failed to spawn child");
    let child_pid = traced_child.pid as i32;

    eprintln!(
        "Recording memory trace (pid {}, {}x{} MiB allocs)...",
        child_pid,
        ALLOC_COUNT,
        ALLOC_SIZE_BYTES >> 20
    );

    let config = Config {
        memory: true,
        // Record every page fault so the assertion is deterministic.
        memory_fault_sample_rate: 1,
        parquet_only: true,
        output_dir: dir.path().to_path_buf(),
        output: trace_path,
        ..Config::default()
    };

    let exit_code = systing(config, Some(traced_child)).expect("systing recording failed");
    assert_eq!(exit_code, 0, "allocator workload should exit with code 0");
    eprintln!("Recording complete.\n");

    // --- Check: memory parquet files exist ---
    for name in ["memory_rss", "memory_map", "memory_fault"] {
        assert!(
            dir.path().join(format!("{name}.parquet")).exists(),
            "{name}.parquet not found in output dir"
        );
    }

    // --- Convert to DuckDB for SQL assertions ---
    let duckdb_path = dir.path().join("trace.duckdb");
    systing::duckdb::parquet_to_duckdb(dir.path(), &duckdb_path, "memtest")
        .expect("DuckDB conversion failed");
    let conn = duckdb::Connection::open(&duckdb_path).expect("Failed to open DuckDB");

    // --- Check: sysinfo says which form of the mmap/munmap/brk hooks ran ---
    // The default form is the classic tracepoint set on every kernel (the
    // trampoline form is opt-in, `kernel_hooks: Trampoline`, exercised by
    // its own tests below): the value is the plain `tracepoint`, never a
    // qualified one, since no trampoline was tried.
    eprintln!("  sysinfo.memory_syscall_leg...");
    let syscall_leg = read_syscall_leg(&conn);
    assert_eq!(
        syscall_leg, "tracepoint",
        "[sysinfo] memory_syscall_leg: the classic form is the default on every kernel"
    );
    eprintln!("    memory_syscall_leg = {syscall_leg}");

    // --- Check: memory_rss has anon rows with plausible byte values ---
    eprintln!("  memory_rss anon sanity...");
    let (anon_rows, max_anon): (i64, i64) = conn
        .query_row(
            &format!(
                "SELECT COUNT(*), COALESCE(MAX(size), 0)
                 FROM memory_rss WHERE member = 1 AND utid IN {UTIDS_FOR_PID}"
            ),
            [child_pid],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("Failed to query memory_rss");
    assert!(
        anon_rows > 0,
        "[memory_rss] no anon-RSS rows (member=1) for workload pid {child_pid}"
    );
    assert!(
        max_anon > 0 && max_anon < RSS_SANITY_CEILING_BYTES,
        "[memory_rss] max anon size {} bytes is outside sane range (0, {})",
        max_anon,
        RSS_SANITY_CEILING_BYTES
    );
    // The AnonHugePages sample (member -6) belongs to the THP-split leg.
    // Whether a plain capture takes it cannot be told here: in command
    // mode the workload is reaped before the end samples, so its
    // smaps_rollup is gone on either code path. The gate is asserted in
    // test_memory_anon_huge_sample_follows_the_thp_leg against a workload
    // that outlives the capture.
    eprintln!(
        "    {} anon-RSS rows, max {} MiB",
        anon_rows,
        max_anon >> 20
    );

    // --- Check: memory_map has mmap rows near the workload allocation size ---
    eprintln!("  memory_map mmap events...");
    let (mmap_rows, big_mmap_rows): (i64, i64) = conn
        .query_row(
            &format!(
                "SELECT COUNT(*), COUNT(*) FILTER (WHERE size >= ?)
                 FROM memory_map WHERE event_type = 'mmap' AND utid IN {UTIDS_FOR_PID}"
            ),
            [ALLOC_SIZE_BYTES, child_pid as i64],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("Failed to query memory_map mmap");
    assert!(
        mmap_rows > 0,
        "[memory_map] no mmap events for workload pid {child_pid}"
    );
    // Allow some slack: glibc may coalesce or the interpreter may add overhead,
    // but we should see at least half of the explicit large allocations.
    assert!(
        big_mmap_rows >= ALLOC_COUNT / 2,
        "[memory_map] expected >= {} mmap events with size >= {} bytes, got {} (total mmaps: {})",
        ALLOC_COUNT / 2,
        ALLOC_SIZE_BYTES,
        big_mmap_rows,
        mmap_rows
    );
    eprintln!(
        "    {} mmap events ({} >= {} MiB)",
        mmap_rows,
        big_mmap_rows,
        ALLOC_SIZE_BYTES >> 20
    );

    // --- Check: memory_map has munmap rows ---
    eprintln!("  memory_map munmap events...");
    let munmap_rows: i64 = conn
        .query_row(
            &format!(
                "SELECT COUNT(*) FROM memory_map
                 WHERE event_type = 'munmap' AND utid IN {UTIDS_FOR_PID}"
            ),
            [child_pid],
            |row| row.get(0),
        )
        .expect("Failed to query memory_map munmap");
    assert!(
        munmap_rows > 0,
        "[memory_map] no munmap events for workload pid {child_pid}"
    );
    eprintln!("    {} munmap events", munmap_rows);

    // --- Check: memory_map.rss_delta_bytes captures the munmap RSS drop ---
    // The workload's bytearray(size) memsets the full buffer, so each large
    // munmap releases ~ALLOC_SIZE_BYTES of resident anon. First make sure the
    // column is populated at all (if the BPF-side mm read failed, every row
    // would carry the absent sentinel and decode to NULL — a vacuous pass),
    // then require the signed drop on at least half the large frees. The
    // negative bound also catches an enter/exit sign inversion, which would
    // render frees as +2 MiB gains.
    eprintln!("  memory_map.rss_delta_bytes munmap drop...");
    let (delta_rows, drop_rows): (i64, i64) = conn
        .query_row(
            &format!(
                "SELECT COUNT(*) FILTER (WHERE rss_delta_bytes IS NOT NULL),
                        COUNT(*) FILTER (WHERE rss_delta_bytes <= -?)
                 FROM memory_map WHERE event_type = 'munmap' AND utid IN {UTIDS_FOR_PID}"
            ),
            [ALLOC_SIZE_BYTES / 2, child_pid as i64],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("Failed to query memory_map rss_delta_bytes");
    assert!(
        delta_rows > 0,
        "[memory_map] rss_delta_bytes is NULL on all {munmap_rows} munmap rows \
         (BPF mm read never succeeded?)"
    );
    assert!(
        drop_rows >= ALLOC_COUNT / 2,
        "[memory_map] expected >= {} munmap events with rss_delta_bytes <= -{} bytes, \
         got {} ({} non-NULL of {} munmaps)",
        ALLOC_COUNT / 2,
        ALLOC_SIZE_BYTES / 2,
        drop_rows,
        delta_rows,
        munmap_rows
    );
    eprintln!(
        "    {} munmap drops <= -{} MiB ({} non-NULL)",
        drop_rows,
        (ALLOC_SIZE_BYTES / 2) >> 20,
        delta_rows
    );

    // --- Check: memory_map.stack_id joins to stack.id ---
    eprintln!("  memory_map.stack_id -> stack.id join...");
    let (with_stack, joined): (i64, i64) = conn
        .query_row(
            &format!(
                "SELECT
                     (SELECT COUNT(*) FROM memory_map
                      WHERE stack_id IS NOT NULL AND utid IN {UTIDS_FOR_PID}),
                     (SELECT COUNT(*) FROM memory_map mm JOIN stack s ON s.id = mm.stack_id
                      WHERE mm.utid IN {UTIDS_FOR_PID})"
            ),
            [child_pid, child_pid],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("Failed to query memory_map/stack join");
    assert!(
        with_stack > 0,
        "[memory_map] no rows with non-null stack_id for workload pid {child_pid}"
    );
    assert_eq!(
        with_stack, joined,
        "[memory_map] {} rows have stack_id but only {} join to stack.id",
        with_stack, joined
    );
    eprintln!("    {} memory_map rows join to stack table", joined);

    // --- Check: memory_fault has rows (every arch: the x86 tracepoint path or
    // the perf software page-fault event elsewhere) ---
    eprintln!("  memory_fault events...");
    let fault_rows: i64 = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM memory_fault WHERE utid IN {UTIDS_FOR_PID}"),
            [child_pid],
            |row| row.get(0),
        )
        .expect("Failed to query memory_fault");
    assert!(
        fault_rows > 0,
        "[memory_fault] no page-fault rows for workload pid {child_pid}"
    );
    eprintln!("    {} page-fault events", fault_rows);
    // The fault address is the one field both attach paths fill the same way;
    // error_code is the x86 tracepoint's error_code and 0 on the software-event
    // path, so only its presence is pinned here.
    let fault_rows_with_addr: i64 = conn
        .query_row(
            &format!(
                "SELECT COUNT(*) FROM memory_fault WHERE utid IN {UTIDS_FOR_PID} AND addr != 0"
            ),
            [child_pid],
            |row| row.get(0),
        )
        .expect("Failed to query memory_fault addr");
    assert!(
        fault_rows_with_addr > 0,
        "[memory_fault] page-fault rows carry no fault address for workload pid {child_pid}"
    );

    // --- Check: every memory_* utid joins to thread.utid ---
    eprintln!("  memory_*.utid -> thread.utid FK integrity...");
    let orphaned_utids: i64 = conn
        .query_row(
            "SELECT
                 (SELECT COUNT(*) FROM memory_rss   r WHERE NOT EXISTS (SELECT 1 FROM thread t WHERE t.utid = r.utid))
               + (SELECT COUNT(*) FROM memory_map   m WHERE NOT EXISTS (SELECT 1 FROM thread t WHERE t.utid = m.utid))
               + (SELECT COUNT(*) FROM memory_fault f WHERE NOT EXISTS (SELECT 1 FROM thread t WHERE t.utid = f.utid))",
            [],
            |row| row.get(0),
        )
        .expect("Failed to query utid FK integrity");
    assert_eq!(
        orphaned_utids, 0,
        "[memory_*] {} rows have utid that does not exist in thread table",
        orphaned_utids
    );

    eprintln!("\ntest_memory_recorder_e2e: all checks passed");
}

/// `sysinfo.memory_syscall_leg` of the one trace in `conn`.
fn read_syscall_leg(conn: &duckdb::Connection) -> String {
    conn.query_row("SELECT memory_syscall_leg FROM sysinfo", [], |row| {
        row.get::<_, Option<String>>(0)
    })
    .expect("Failed to query sysinfo.memory_syscall_leg")
    .expect("memory_syscall_leg must be recorded when the memory recorder ran")
}

/// Does this kernel list the arch syscall wrappers the trampoline set attaches
/// to (`__x64_sys_mmap` … on x86, `__arm64_sys_*` on arm64)? The same read
/// the recorder's own probe makes; decides which form the tests can expect.
fn host_has_syscall_wrappers() -> bool {
    let prefix = if cfg!(target_arch = "x86_64") {
        "__x64_sys_"
    } else if cfg!(target_arch = "aarch64") {
        "__arm64_sys_"
    } else {
        "__riscv_sys_"
    };
    let Ok(kallsyms) = std::fs::read_to_string("/proc/kallsyms") else {
        return false;
    };
    ["mmap", "munmap", "brk"].iter().all(|name| {
        let sym = format!("{prefix}{name}");
        kallsyms.lines().any(|line| {
            let mut fields = line.split_whitespace();
            matches!(
                (fields.next(), fields.next(), fields.next()),
                (Some(_), Some("t" | "T"), Some(s)) if s == sym
            )
        })
    })
}

/// One memory capture of the allocator workload under the opt-in trampoline
/// form of the mmap/munmap/brk hooks (`kernel_hooks: Trampoline`), with the
/// testing-only attach-failure switch on or off. Returns the trace's DuckDB
/// connection, the workload's pid and the `sysinfo.memory_syscall_leg` value.
fn record_trampoline_capture(
    dir: &TempDir,
    label: &str,
    force_fallback: bool,
) -> (duckdb::Connection, i32, String) {
    let py_prog = format!(
        "import time\n\
         bufs=[]\n\
         for _ in range({count}):\n\
         \x20 b=bytearray({size})\n\
         \x20 b[0]=1; b[-1]=1\n\
         \x20 bufs.append(b)\n\
         del bufs\n\
         time.sleep(0.2)\n",
        count = ALLOC_COUNT,
        size = ALLOC_SIZE_BYTES,
    );
    let run_cmd = vec!["python3".to_string(), "-c".to_string(), py_prog];
    let traced_child =
        systing::traced_command::spawn_traced_child(&run_cmd).expect("Failed to spawn child");
    let child_pid = traced_child.pid as i32;
    eprintln!("Recording memory trace ({label}, pid {child_pid})...");

    let config = Config {
        memory: true,
        kernel_hooks: KernelHooks::Trampoline,
        memory_syscall_force_fallback: force_fallback,
        parquet_only: true,
        output_dir: dir.path().to_path_buf(),
        output: dir.path().join("trace.pb"),
        ..Config::default()
    };
    let exit_code = systing(config, Some(traced_child)).expect("systing recording failed");
    assert_eq!(exit_code, 0, "allocator workload should exit with code 0");

    let duckdb_path = dir.path().join("trace.duckdb");
    systing::duckdb::parquet_to_duckdb(dir.path(), &duckdb_path, label)
        .expect("DuckDB conversion failed");
    let conn = duckdb::Connection::open(&duckdb_path).expect("Failed to open DuckDB");
    let syscall_leg = read_syscall_leg(&conn);
    (conn, child_pid, syscall_leg)
}

/// The rows either form of the hooks must carry for the allocator workload:
/// the big mmaps and their munmaps.
fn assert_syscall_rows(conn: &duckdb::Connection, child_pid: i32, form: &str) -> (i64, i64) {
    let (mmap_rows, munmap_rows): (i64, i64) = conn
        .query_row(
            &format!(
                "SELECT COUNT(*) FILTER (WHERE event_type = 'mmap' AND size >= ?),
                        COUNT(*) FILTER (WHERE event_type = 'munmap')
                 FROM memory_map WHERE utid IN {UTIDS_FOR_PID}"
            ),
            [ALLOC_SIZE_BYTES, child_pid as i64],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("Failed to query memory_map");
    assert!(
        mmap_rows >= ALLOC_COUNT / 2,
        "[memory_map] expected >= {} mmap events of >= {} bytes through the {form}, got {}",
        ALLOC_COUNT / 2,
        ALLOC_SIZE_BYTES,
        mmap_rows
    );
    assert!(
        munmap_rows > 0,
        "[memory_map] no munmap events for workload pid {child_pid} through the {form}"
    );
    (mmap_rows, munmap_rows)
}

/// The opt-in trampoline form of the mmap/munmap/brk hooks
/// (`--kernel-hooks trampoline`): on a kernel that lists the arch syscall
/// wrappers in kallsyms and vmlinux BTF and can attach a trampoline to them
/// (the rig guest) the fentry/fexit set runs and carries the rows; a kernel
/// without the wrappers records the classic form with the reason.
#[test]
#[ignore] // Requires root/BPF privileges
fn test_memory_syscall_hooks_trampoline_opt_in() {
    let dir = TempDir::new().expect("Failed to create temp dir");
    let (conn, child_pid, syscall_leg) = record_trampoline_capture(&dir, "trampoline", false);
    if host_has_syscall_wrappers() {
        // `tracepoint:nobtf` only on a kernel whose BTF lacks the wrappers
        // (the trampoline set is then never loaded); the rig guest has them.
        assert!(
            syscall_leg == "fentry" || syscall_leg == "tracepoint:nobtf",
            "[sysinfo] memory_syscall_leg = {syscall_leg:?}: expected the trampoline form \
             on a kernel that lists the syscall wrappers"
        );
    } else {
        assert_eq!(
            syscall_leg, "tracepoint:nosym",
            "[sysinfo] memory_syscall_leg: the classic form on a kernel without the wrappers"
        );
    }
    let (mmap_rows, munmap_rows) = assert_syscall_rows(&conn, child_pid, "trampoline form");
    eprintln!(
        "    memory_syscall_leg = {syscall_leg}; {mmap_rows} big mmap + {munmap_rows} munmap rows"
    );
    eprintln!("\ntest_memory_syscall_hooks_trampoline_opt_in: all checks passed");
}

/// The attach-time fallback of the opt-in trampoline form: when a program
/// of the trampoline set fails to attach, the links attached before it are
/// dropped and the classic tracepoint set takes over — the capture still
/// carries the syscall rows, and sysinfo says which form ran. The failure is
/// the testing-only switch (after the first trampoline program attached, so a
/// real link is dropped), because no rig kernel refuses trampolines; on a
/// kernel that does (arm64 without direct-call ftrace) this is the path a
/// trampoline-form capture takes.
#[test]
#[ignore] // Requires root/BPF privileges
fn test_memory_syscall_hooks_fall_back_to_tracepoints() {
    let dir = TempDir::new().expect("Failed to create temp dir");
    let (conn, child_pid, syscall_leg) = record_trampoline_capture(&dir, "fallback", true);
    if host_has_syscall_wrappers() {
        // (`tracepoint:nobtf` only on a kernel whose BTF lacks the wrappers:
        // no trampoline set loaded, nothing for the switch to force.)
        assert!(
            syscall_leg == "tracepoint:notramp" || syscall_leg == "tracepoint:nobtf",
            "[sysinfo] memory_syscall_leg = {syscall_leg:?}: the forced trampoline failure \
             must land on the classic tracepoint set"
        );
    } else {
        // No trampoline set was loaded to fail: the classic set is the
        // only form, and the switch has nothing to force.
        assert_eq!(syscall_leg, "tracepoint:nosym");
    }
    let (mmap_rows, munmap_rows) = assert_syscall_rows(&conn, child_pid, "classic set");
    eprintln!(
        "    memory_syscall_leg = {syscall_leg}; {mmap_rows} big mmap + {munmap_rows} munmap rows"
    );
    eprintln!("\ntest_memory_syscall_hooks_fall_back_to_tracepoints: all checks passed");
}

#[test]
#[ignore] // Requires root/BPF privileges
fn test_memory_alloc_e2e() {
    let dir = TempDir::new().expect("Failed to create temp dir");
    let trace_path = dir.path().join("trace.pb");

    // Workload: many small allocations that stay below the glibc MMAP_THRESHOLD
    // so they go through malloc (brk-backed), plus an explicit free pass.
    const SMALL_COUNT: i64 = 4000;
    const SMALL_SIZE: i64 = 512;
    let py_prog = format!(
        "objs=[bytes({size}) for _ in range({count})]\n\
         del objs\n\
         import time; time.sleep(0.1)\n",
        count = SMALL_COUNT,
        size = SMALL_SIZE,
    );
    let run_cmd = vec!["python3".to_string(), "-c".to_string(), py_prog];
    let traced_child =
        systing::traced_command::spawn_traced_child(&run_cmd).expect("Failed to spawn child");
    let child_pid = traced_child.pid as i32;

    eprintln!(
        "Recording memory-alloc trace (pid {}, {}x{}B allocs)...",
        child_pid, SMALL_COUNT, SMALL_SIZE
    );

    let config = Config {
        memory: true,
        memory_alloc: true,
        memory_alloc_sample_rate: 1,
        memory_fault_sample_rate: 1,
        parquet_only: true,
        output_dir: dir.path().to_path_buf(),
        output: trace_path,
        ..Config::default()
    };

    let exit_code = systing(config, Some(traced_child)).expect("systing recording failed");
    assert_eq!(exit_code, 0, "allocator workload should exit with code 0");
    eprintln!("Recording complete.\n");

    assert!(
        dir.path().join("memory_alloc.parquet").exists(),
        "memory_alloc.parquet not found in output dir"
    );

    let duckdb_path = dir.path().join("trace.duckdb");
    systing::duckdb::parquet_to_duckdb(dir.path(), &duckdb_path, "allotest")
        .expect("DuckDB conversion failed");
    let conn = duckdb::Connection::open(&duckdb_path).expect("Failed to open DuckDB");

    // --- Check: memory_alloc has malloc rows for our workload ---
    eprintln!("  memory_alloc malloc events...");
    let (malloc_rows, free_rows): (i64, i64) = conn
        .query_row(
            &format!(
                "SELECT
                     COUNT(*) FILTER (WHERE op = 'malloc'),
                     COUNT(*) FILTER (WHERE op = 'free')
                 FROM memory_alloc WHERE utid IN {UTIDS_FOR_PID}"
            ),
            [child_pid],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("Failed to query memory_alloc");
    // Python interpreter startup alone does thousands of mallocs; a loose floor
    // keeps this robust across libc versions.
    assert!(
        malloc_rows >= SMALL_COUNT / 4,
        "[memory_alloc] expected >= {} malloc rows, got {}",
        SMALL_COUNT / 4,
        malloc_rows
    );
    assert!(
        free_rows > 0,
        "[memory_alloc] no free rows for workload pid {child_pid}"
    );
    eprintln!("    {} malloc, {} free events", malloc_rows, free_rows);

    // --- Check: malloc sizes look sane (non-zero, below 64GiB) ---
    let max_size: i64 = conn
        .query_row(
            &format!(
                "SELECT COALESCE(MAX(size), 0) FROM memory_alloc
                 WHERE op != 'free' AND utid IN {UTIDS_FOR_PID}"
            ),
            [child_pid],
            |row| row.get(0),
        )
        .expect("Failed to query memory_alloc max size");
    assert!(
        max_size > 0 && max_size < RSS_SANITY_CEILING_BYTES,
        "[memory_alloc] max alloc size {} outside sane range",
        max_size
    );

    // --- Check: memory_alloc.stack_id joins to stack.id ---
    eprintln!("  memory_alloc.stack_id -> stack.id join...");
    let (with_stack, joined): (i64, i64) = conn
        .query_row(
            &format!(
                "SELECT
                     (SELECT COUNT(*) FROM memory_alloc
                      WHERE stack_id IS NOT NULL AND utid IN {UTIDS_FOR_PID}),
                     (SELECT COUNT(*) FROM memory_alloc ma JOIN stack s ON s.id = ma.stack_id
                      WHERE ma.utid IN {UTIDS_FOR_PID})"
            ),
            [child_pid, child_pid],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("Failed to query memory_alloc/stack join");
    assert!(
        with_stack > 0,
        "[memory_alloc] no rows with non-null stack_id for workload pid {child_pid}"
    );
    assert_eq!(
        with_stack, joined,
        "[memory_alloc] {} rows have stack_id but only {} join to stack.id",
        with_stack, joined
    );
    eprintln!("    {} memory_alloc rows join to stack table", joined);

    // --- Check: every memory_alloc utid joins to thread.utid ---
    let orphaned_utids: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memory_alloc a
             WHERE NOT EXISTS (SELECT 1 FROM thread t WHERE t.utid = a.utid)",
            [],
            |row| row.get(0),
        )
        .expect("Failed to query memory_alloc utid FK integrity");
    assert_eq!(
        orphaned_utids, 0,
        "[memory_alloc] {} rows have utid that does not exist in thread table",
        orphaned_utids
    );

    eprintln!("\ntest_memory_alloc_e2e: all checks passed");
}

/// Trace `run_cmd` with the memory-alloc recorder and return the number of
/// `malloc` rows attributed to the workload pid. Returns 0 if no parquet was
/// emitted (i.e., no uprobes attached / no events).
fn count_malloc_rows(run_cmd: Vec<String>, memory_alloc_lib: Option<String>) -> i64 {
    let dir = TempDir::new().expect("Failed to create temp dir");
    let traced_child =
        systing::traced_command::spawn_traced_child(&run_cmd).expect("Failed to spawn child");
    let child_pid = traced_child.pid as i32;
    let config = Config {
        memory_alloc: true,
        memory_alloc_sample_rate: 1,
        memory_alloc_lib,
        parquet_only: true,
        output_dir: dir.path().to_path_buf(),
        output: dir.path().join("trace.pb"),
        ..Config::default()
    };
    let exit_code = systing(config, Some(traced_child)).expect("systing recording failed");
    assert_eq!(exit_code, 0, "allocator workload should exit cleanly");
    if !dir.path().join("memory_alloc.parquet").exists() {
        return 0;
    }
    let duckdb_path = dir.path().join("trace.duckdb");
    systing::duckdb::parquet_to_duckdb(dir.path(), &duckdb_path, "allotest")
        .expect("DuckDB conversion failed");
    let conn = duckdb::Connection::open(&duckdb_path).expect("Failed to open DuckDB");
    conn.query_row(
        &format!(
            "SELECT COUNT(*) FROM memory_alloc WHERE op = 'malloc' AND utid IN {UTIDS_FOR_PID}"
        ),
        [child_pid],
        |row| row.get(0),
    )
    .expect("Failed to query memory_alloc")
}

fn small_malloc_workload() -> Vec<String> {
    vec![
        "python3".to_string(),
        "-c".to_string(),
        "objs=[bytes(512) for _ in range(2000)]\ndel objs\nimport time; time.sleep(0.1)\n"
            .to_string(),
    ]
}

fn find_jemalloc() -> Option<String> {
    let out = std::process::Command::new("ldconfig")
        .arg("-p")
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find(|l| l.contains("libjemalloc.so"))
        .and_then(|l| l.split("=> ").nth(1))
        .map(|p| p.trim().to_string())
}

#[test]
#[ignore] // Requires root/BPF privileges
fn test_memory_alloc_jemalloc_preload() {
    let Some(jemalloc) = find_jemalloc() else {
        eprintln!("SKIP: libjemalloc not found via ldconfig -p");
        return;
    };
    eprintln!("Using LD_PRELOAD={jemalloc}");
    let dir = TempDir::new().expect("Failed to create temp dir");

    // Spawn the workload independently (not via spawn_traced_child) so that
    // allocator discovery scans a process that has already exec'd and mapped
    // jemalloc. Run-command mode attaches pre-exec and would only see the
    // parent's libc.
    //
    // The workload must stay alive until uprobe attach, which happens after
    // BPF skeleton load — tens of seconds on slow/emulated machines (e.g.
    // QEMU TCG). A fixed iteration count races that, so it runs until the
    // test drops a stop file (with a deadline as the orphan backstop should
    // the test die before cleanup).
    let stop_file = dir.path().join("stop-workload");
    // The in-workload deadline is the orphan backstop should the test die
    // before writing the stop file; it must comfortably exceed the test's own
    // wait budget so it can never fire first.
    let orphan_backstop_secs = 2 * SLOW_MACHINE_BUDGET.as_secs();
    let mut child = std::process::Command::new("python3")
        .env("LD_PRELOAD", &jemalloc)
        .arg("-c")
        .arg(format!(
            "import os, sys, time\n\
             deadline = time.time() + {orphan_backstop_secs}\n\
             while time.time() < deadline and not os.path.exists(sys.argv[1]):\n\
             \x20 objs=[bytes(512) for _ in range(200)]\n\
             \x20 del objs\n\
             \x20 time.sleep(0.005)\n"
        ))
        .arg(&stop_file)
        .spawn()
        .expect("Failed to spawn jemalloc workload");
    let child_pid = child.id();
    // python exec + dynamic linking can take seconds on slow machines; poll
    // for the actual postcondition instead of a hardcoded settle time.
    wait_until(
        &format!("libjemalloc in /proc/{child_pid}/maps (LD_PRELOAD ineffective?)"),
        || {
            std::fs::read_to_string(format!("/proc/{child_pid}/maps"))
                .map(|m| m.contains("libjemalloc"))
                .unwrap_or(false)
        },
    );

    let config = Config {
        memory_alloc: true,
        memory_alloc_sample_rate: 1,
        pid: vec![child_pid],
        duration: 2,
        parquet_only: true,
        output_dir: dir.path().to_path_buf(),
        output: dir.path().join("trace.pb"),
        ..Config::default()
    };
    let exit_code = systing(config, None).expect("systing recording failed");
    assert_eq!(exit_code, 0);
    let exited_early = child.try_wait().expect("try_wait failed");
    let _ = std::fs::write(&stop_file, b"");
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        exited_early.is_none(),
        "workload exited before the trace completed (status {exited_early:?}); \
         it must outlive BPF load + attach + the 2s trace window"
    );

    assert!(
        dir.path().join("memory_alloc.parquet").exists(),
        "memory_alloc.parquet not written (discovery missed jemalloc?)"
    );
    let duckdb_path = dir.path().join("trace.duckdb");
    systing::duckdb::parquet_to_duckdb(dir.path(), &duckdb_path, "jetest")
        .expect("DuckDB conversion failed");
    let conn = duckdb::Connection::open(&duckdb_path).expect("Failed to open DuckDB");
    let rows: i64 = conn
        .query_row(
            &format!(
                "SELECT COUNT(*) FROM memory_alloc WHERE op = 'malloc' AND utid IN {UTIDS_FOR_PID}"
            ),
            [child_pid as i64],
            |row| row.get(0),
        )
        .expect("Failed to query memory_alloc");
    assert!(
        rows > 0,
        "[memory_alloc] expected malloc rows with jemalloc preloaded, got 0"
    );
    eprintln!("    {rows} malloc events recorded under jemalloc");
}

#[test]
#[ignore] // Requires root/BPF privileges
fn test_memory_alloc_lib_override_name() {
    // spawn_traced_child resolves the override against the forked child's
    // pre-exec maps (== this test binary's maps). That's fine here because the
    // test binary and python3 share the system libc.so.6.
    let rows = count_malloc_rows(small_malloc_workload(), Some("libc.so.6".to_string()));
    assert!(
        rows > 0,
        "[memory_alloc] expected malloc rows with --memory-alloc-lib libc.so.6, got 0"
    );
    eprintln!("    {rows} malloc events via --memory-alloc-lib name override");
}

#[test]
#[ignore] // Requires root/BPF privileges
fn test_memory_alloc_lib_override_bad_path() {
    let rows = count_malloc_rows(
        small_malloc_workload(),
        Some("/nonexistent/liballoc.so".to_string()),
    );
    assert_eq!(
        rows, 0,
        "[memory_alloc] expected 0 rows for nonexistent --memory-alloc-lib, got {rows}"
    );
}

/// Regression guard: a dynamically-linked binary lists `malloc` as an
/// *undefined* import in `.dynsym`; `exe_defines_malloc` must not treat that
/// as a locally-defined allocator.
#[test]
fn test_exe_defines_malloc_negative() {
    let self_pid = std::process::id();
    assert_eq!(
        systing::systing_core::exe_defines_malloc(self_pid),
        None,
        "test binary is glibc-linked; exe_defines_malloc should return None"
    );
}

/// Threshold-batching correctness test: with a known threshold, a workload
/// that touches N * threshold bytes of anon memory should produce on the
/// order of N rss_stat events — not one per 4 KiB page — and the peak
/// emitted value should match the workload's ground-truth RSS.
///
/// Exercised on BOTH attach paths: the default (tp_btf/rss_stat where the
/// kernel supports it) and the forced classic tracepoint fallback.
fn run_rss_threshold_test(force_classic: bool) {
    const THRESHOLD: u64 = 4 << 20; // 4 MiB: small and kernel-independent
    const STEPS: i64 = 32; // ~128 MiB total anon growth

    let dir = TempDir::new().expect("Failed to create temp dir");

    // Workload: grow a single bytearray in THRESHOLD-sized steps, touching
    // every page so each step produces ~THRESHOLD of anon-RSS growth. Using
    // one resized buffer (not many) keeps the kernel's rss_stat firings on a
    // single monotonic ramp, which is what the threshold gate sees.
    let py_prog = format!(
        "import time\n\
         buf = bytearray()\n\
         step = {step}\n\
         for _ in range({steps}):\n\
         \x20 buf.extend(b'\\x00' * step)\n\
         \x20 for i in range(len(buf)-step, len(buf), 4096):\n\
         \x20\x20 buf[i] = 1\n\
         \x20 time.sleep(0.01)\n\
         time.sleep(0.2)\n",
        step = THRESHOLD,
        steps = STEPS,
    );
    let run_cmd = vec!["python3".to_string(), "-c".to_string(), py_prog];
    let traced_child =
        systing::traced_command::spawn_traced_child(&run_cmd).expect("Failed to spawn child");
    let child_pid = traced_child.pid as i32;

    eprintln!(
        "Recording rss_stat threshold test (pid {}, {}x{} MiB, force_classic={})...",
        child_pid,
        STEPS,
        THRESHOLD >> 20,
        force_classic,
    );

    let config = Config {
        memory: true,
        memory_rss_threshold_bytes: Some(THRESHOLD),
        memory_rss_force_classic: force_classic,
        parquet_only: true,
        output_dir: dir.path().to_path_buf(),
        output: dir.path().join("trace.pb"),
        ..Config::default()
    };
    let exit_code = systing(config, Some(traced_child)).expect("systing recording failed");
    assert_eq!(exit_code, 0, "workload should exit 0");

    let duckdb_path = dir.path().join("trace.duckdb");
    systing::duckdb::parquet_to_duckdb(dir.path(), &duckdb_path, "rsstest")
        .expect("DuckDB conversion failed");
    let conn = duckdb::Connection::open(&duckdb_path).expect("Failed to open DuckDB");

    let (anon_rows, max_anon): (i64, i64) = conn
        .query_row(
            &format!(
                "SELECT COUNT(*), COALESCE(MAX(size), 0)
                 FROM memory_rss WHERE member = 1 AND utid IN {UTIDS_FOR_PID}"
            ),
            [child_pid],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("Failed to query memory_rss");

    let target_bytes = STEPS * THRESHOLD as i64;
    eprintln!(
        "    anon rss_stat events: {} (target ~{}); max size: {} MiB (target ~{} MiB)",
        anon_rows,
        STEPS,
        max_anon >> 20,
        target_bytes >> 20,
    );

    // Event count: without thresholding, ~THRESHOLD/4096 * STEPS = ~32768
    // events. With a THRESHOLD gate, expect on the order of STEPS emits on
    // the ramp plus interpreter startup/teardown — bound generously, but
    // tight enough to fail if the gate is broken (which would give >=1000).
    assert!(
        (STEPS / 2..STEPS * 8).contains(&anon_rows),
        "[rss_stat threshold] anon event count {} outside [{}..{}) \
         (force_classic={}, target ~{}) — threshold gate broken?",
        anon_rows,
        STEPS / 2,
        STEPS * 8,
        force_classic,
        STEPS,
    );

    // Peak value: max emitted anon size should be within [target - threshold,
    // target + python-overhead]. The lower bound checks that threshold
    // batching didn't drop the peak; the upper is a loose sanity ceiling.
    assert!(
        (target_bytes - THRESHOLD as i64..target_bytes + (128 << 20)).contains(&max_anon),
        "[rss_stat threshold] max anon {} bytes outside [{}, {}) \
         (force_classic={}) — peak value wrong?",
        max_anon,
        target_bytes - THRESHOLD as i64,
        target_bytes + (128 << 20),
        force_classic,
    );

    // Byte semantics guard: fails if the tp_btf path emitted pages instead
    // of bytes (off by 4096x).
    assert!(
        max_anon > target_bytes / 16,
        "[rss_stat threshold] max anon {} suspiciously small vs target {} \
         — page/byte unit bug on tp_btf path?",
        max_anon,
        target_bytes,
    );
}

#[test]
#[ignore] // Requires root/BPF privileges
fn test_memory_rss_threshold_tp_btf() {
    run_rss_threshold_test(false);
}

#[test]
#[ignore] // Requires root/BPF privileges
fn test_memory_rss_threshold_classic_fallback() {
    run_rss_threshold_test(true);
}

/// The per-process AnonHugePages sample (`memory_rss` member -6) is taken
/// only with the THP-split leg, and when it is taken the capture says how
/// complete it was (`sysinfo.memory_anon_huge_walk`). Both halves need a
/// workload that is still alive at the end of the capture — in command mode
/// the child is reaped before the end samples, so `/proc/<pid>/smaps_rollup`
/// is gone on either code path and an "absent" assertion proves nothing.
/// So: one long-lived workload (huge-page-advised, touched, then mapping and
/// unmapping a page every turn — a memory event per turn, so each capture
/// sees the process — until a stop file appears), two duration-stopped
/// pid-filtered captures against it: without the leg the sample must be
/// absent (and the workload still alive, so its absence is the gate's
/// doing), with the leg it must be present, complete, and non-zero when the
/// guest has THP enabled.
#[test]
#[ignore] // Requires root/BPF privileges
fn test_memory_anon_huge_sample_follows_the_thp_leg() {
    let dir = TempDir::new().expect("Failed to create temp dir");
    let stop_file = dir.path().join("stop-workload");
    let ready_file = dir.path().join("workload-ready");
    let orphan_backstop_secs = 2 * SLOW_MACHINE_BUDGET.as_secs();
    let mut child = std::process::Command::new("python3")
        .arg("-c")
        .arg(format!(
            "import mmap, ctypes, os, sys, time\n\
             libc = ctypes.CDLL(None, use_errno=True)\n\
             libc.madvise.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]\n\
             MADV_HUGEPAGE = 14\n\
             HUGE = 2 * 1024 * 1024\n\
             size = 16 * HUGE\n\
             m = mmap.mmap(-1, size + HUGE, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS)\n\
             base = ctypes.addressof(ctypes.c_char.from_buffer(m))\n\
             start = (base + HUGE - 1) & ~(HUGE - 1)\n\
             libc.madvise(ctypes.c_void_p(start), size, MADV_HUGEPAGE)\n\
             off = start - base\n\
             for i in range(0, size, 4096):\n\
             \x20 m[off + i] = 1\n\
             open(sys.argv[2], 'w').close()\n\
             deadline = time.time() + {orphan_backstop_secs}\n\
             while time.time() < deadline and not os.path.exists(sys.argv[1]):\n\
             \x20 m[off] = 2\n\
             \x20 mmap.mmap(-1, 4096, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS).close()\n\
             \x20 time.sleep(0.05)\n"
        ))
        .arg(&stop_file)
        .arg(&ready_file)
        .spawn()
        .expect("Failed to spawn THP workload");
    let child_pid = child.id();
    wait_until("the THP workload to touch its mapping", || {
        ready_file.exists()
    });

    let capture = |name: &str, thp_rate: u32| -> duckdb::Connection {
        let out = dir.path().join(name);
        std::fs::create_dir_all(&out).expect("mkdir");
        let config = Config {
            memory: true,
            memory_thp_sample_rate: thp_rate,
            pid: vec![child_pid],
            duration: 2,
            parquet_only: true,
            output_dir: out.clone(),
            output: out.join("trace.pb"),
            ..Config::default()
        };
        let exit_code = systing(config, None).expect("systing recording failed");
        assert_eq!(exit_code, 0);
        let duckdb_path = out.join("trace.duckdb");
        systing::duckdb::parquet_to_duckdb(&out, &duckdb_path, name)
            .expect("DuckDB conversion failed");
        duckdb::Connection::open(&duckdb_path).expect("Failed to open DuckDB")
    };
    let anon_huge_for = |conn: &duckdb::Connection| -> (i64, Option<i64>) {
        conn.query_row(
            &format!(
                "SELECT COUNT(*), MAX(size) FROM memory_rss WHERE member = -6 AND utid IN {UTIDS_FOR_PID}"
            ),
            [child_pid as i64],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("memory_rss anon_huge query")
    };

    // Without the leg: no sample, and the workload was there to be sampled.
    let without = capture("without-thp-leg", 0);
    assert!(
        child.try_wait().expect("try_wait failed").is_none(),
        "workload exited before the first capture completed; the absent sample would prove nothing"
    );
    let (rows_without, _) = anon_huge_for(&without);
    assert_eq!(
        rows_without, 0,
        "[memory_rss] anon_huge rows (member=-6) written for a live workload without the THP-split leg"
    );
    let walk_without: Option<String> = without
        .query_row("SELECT memory_anon_huge_walk FROM sysinfo", [], |row| {
            row.get(0)
        })
        .expect("sysinfo query");
    assert_eq!(walk_without, None, "no walk, no walk outcome");

    // With the leg: the sample, and the walk's own account of itself.
    let with = capture("with-thp-leg", 1);
    assert!(
        child.try_wait().expect("try_wait failed").is_none(),
        "workload exited before the second capture completed"
    );
    let (rows_with, max_with) = anon_huge_for(&with);
    let walk_with: Option<String> = with
        .query_row("SELECT memory_anon_huge_walk FROM sysinfo", [], |row| {
            row.get(0)
        })
        .expect("sysinfo query");
    let thp_enabled = std::fs::read_to_string("/sys/kernel/mm/transparent_hugepage/enabled")
        .map(|s| !s.contains("[never]"))
        .unwrap_or(false);
    eprintln!(
        "  anon_huge: without leg {rows_without} rows; with leg {rows_with} rows, max {max_with:?} bytes; walk {walk_with:?}; thp_enabled={thp_enabled}"
    );
    assert_eq!(
        rows_with, 1,
        "[memory_rss] one anon_huge row (member=-6) expected for the live workload with the THP-split leg"
    );
    let walk_with = walk_with.expect("memory_anon_huge_walk must be recorded when the leg ran");
    assert!(
        walk_with.starts_with("complete:"),
        "one live process cannot hit the walk's cap or budget: {walk_with}"
    );
    if thp_enabled {
        assert!(
            max_with.unwrap_or(0) > 0,
            "[memory_rss] a huge-page-advised, touched 32 MiB mapping should show AnonHugePages > 0 with THP enabled"
        );
    }

    let _ = std::fs::write(&stop_file, b"");
    let _ = child.kill();
    let _ = child.wait();
}

/// The THP-split and vmstat legs (`--memory-thp-sample-rate`, and the
/// always-on `memory_vmstat` sample). The workload maps 64 MiB of anonymous
/// memory, asks for huge pages (`MADV_HUGEPAGE`), touches it, then frees one
/// 4 KiB page inside each 2 MiB range (`MADV_DONTNEED`) — on a kernel with
/// THP enabled for madvise, every such partial free splits the PMD
/// (`thp_split_pmd`) and the huge folio itself (`thp_split_page`, possibly
/// deferred). The split kprobes need the kernel symbols; the test asserts
/// the leg's own status from `sysinfo` and only demands `memory_thp` rows
/// when the leg says it is on and THP is enabled in the guest.
///
/// The VFIO leg cannot be exercised here (no VFIO device in the guest): it
/// is asserted only as far as a host without vfio_iommu_type1 reports —
/// `memory_vfio_leg = off:nosym` with the capture intact.
#[test]
#[ignore] // Requires root/BPF privileges
fn test_memory_thp_vmstat_e2e() {
    let dir = TempDir::new().expect("Failed to create temp dir");
    let trace_path = dir.path().join("trace.pb");

    let py_prog = "import mmap, ctypes, time\n\
         libc = ctypes.CDLL(None, use_errno=True)\n\
         libc.madvise.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]\n\
         MADV_DONTNEED, MADV_HUGEPAGE = 4, 14\n\
         HUGE = 2 * 1024 * 1024\n\
         size = 32 * HUGE\n\
         m = mmap.mmap(-1, size + HUGE, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS)\n\
         base = ctypes.addressof(ctypes.c_char.from_buffer(m))\n\
         start = (base + HUGE - 1) & ~(HUGE - 1)\n\
         libc.madvise(ctypes.c_void_p(start), size, MADV_HUGEPAGE)\n\
         off = start - base\n\
         for i in range(0, size, 4096):\n\
         \x20 m[off + i] = 1\n\
         time.sleep(0.1)\n\
         for i in range(0, size, HUGE):\n\
         \x20 libc.madvise(ctypes.c_void_p(start + i + 8192), 4096, MADV_DONTNEED)\n\
         time.sleep(0.3)\n\
         m.close()\n\
         time.sleep(0.2)\n"
        .to_string();
    let run_cmd = vec!["python3".to_string(), "-c".to_string(), py_prog];
    let traced_child =
        systing::traced_command::spawn_traced_child(&run_cmd).expect("Failed to spawn child");
    let child_pid = traced_child.pid as i32;

    let config = Config {
        memory: true,
        memory_vfio: true,
        memory_thp_sample_rate: 1,
        parquet_only: true,
        output_dir: dir.path().to_path_buf(),
        output: trace_path,
        ..Config::default()
    };
    let exit_code = systing(config, Some(traced_child)).expect("systing recording failed");
    assert_eq!(exit_code, 0, "THP workload should exit with code 0");

    let duckdb_path = dir.path().join("trace.duckdb");
    systing::duckdb::parquet_to_duckdb(dir.path(), &duckdb_path, "thptest")
        .expect("DuckDB conversion failed");
    let conn = duckdb::Connection::open(&duckdb_path).expect("Failed to open DuckDB");

    // --- sysinfo names both legs' status ---
    let (vfio_leg, thp_leg, thp_rate): (Option<String>, Option<String>, Option<i64>) = conn
        .query_row(
            "SELECT memory_vfio_leg, memory_thp_leg, memory_thp_sample_rate FROM sysinfo",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("sysinfo row");
    eprintln!("  sysinfo: vfio_leg={vfio_leg:?} thp_leg={thp_leg:?} thp_rate={thp_rate:?}");
    let vfio_leg = vfio_leg.expect("memory_vfio_leg must be recorded when --memory-vfio is given");
    assert!(
        vfio_leg == "on" || vfio_leg.starts_with("off:"),
        "memory_vfio_leg must be 'on' or 'off:<cause>', got {vfio_leg}"
    );
    let thp_leg = thp_leg.expect("memory_thp_leg must be recorded when the rate is non-zero");
    assert_eq!(thp_rate, Some(1));

    // --- memory_vmstat: start/end samples of the THP family, monotonic ---
    let (vmstat_rows, thp_fault_delta, split_pmd_delta, bad_rows): (i64, i64, i64, i64) = conn
        .query_row(
            "SELECT COUNT(*),
                    COALESCE(SUM(value_end - value_start) FILTER (WHERE name = 'thp_fault_alloc'), 0),
                    COALESCE(SUM(value_end - value_start) FILTER (WHERE name = 'thp_split_pmd'), 0),
                    COUNT(*) FILTER (WHERE ts_end <= ts_start OR (value_end < value_start AND name NOT LIKE 'nr_%'))
             FROM memory_vmstat",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("memory_vmstat query");
    eprintln!(
        "  memory_vmstat: {vmstat_rows} counters, thp_fault_alloc +{thp_fault_delta}, thp_split_pmd +{split_pmd_delta}"
    );
    assert!(
        vmstat_rows >= 10,
        "[memory_vmstat] expected the THP/compaction counter family, got {vmstat_rows} rows"
    );
    assert_eq!(
        bad_rows, 0,
        "[memory_vmstat] counters must be monotonic between the start and end samples"
    );

    // --- memory_thp: split events when the leg is on and THP is enabled ---
    let thp_enabled = std::fs::read_to_string("/sys/kernel/mm/transparent_hugepage/enabled")
        .map(|s| s.contains("[always]") || s.contains("[madvise]"))
        .unwrap_or(false);
    let (thp_rows, pmd_rows, page_rows, with_stack): (i64, i64, i64, i64) = conn
        .query_row(
            &format!(
                "SELECT COUNT(*),
                        COUNT(*) FILTER (WHERE kind = 'pmd'),
                        COUNT(*) FILTER (WHERE kind = 'page'),
                        COUNT(*) FILTER (WHERE stack_id IS NOT NULL)
                 FROM memory_thp WHERE utid IN {UTIDS_FOR_PID}"
            ),
            [child_pid],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("memory_thp query");
    eprintln!(
        "  memory_thp: {thp_rows} rows ({pmd_rows} pmd, {page_rows} page, {with_stack} with stacks); thp_enabled={thp_enabled} leg={thp_leg}"
    );
    if thp_leg.starts_with("on") && thp_enabled && thp_fault_delta > 0 {
        assert!(
            pmd_rows > 0,
            "[memory_thp] the partial MADV_DONTNEED frees should split PMDs (vmstat thp_split_pmd +{split_pmd_delta})"
        );
        assert!(
            with_stack > 0,
            "[memory_thp] split rows should carry kernel stacks"
        );
        // At the worker probe (`on`, `on:pmd-only`) a row is one counted
        // split, so the per-process rows are bounded by the host-wide
        // counter. The entry fallback (`on:pmd-entry`) also fires for a PMD
        // that is not huge, so there the bound does not hold.
        if thp_leg == "on" || thp_leg == "on:pmd-only" {
            assert!(
                split_pmd_delta >= pmd_rows,
                "[memory_thp] per-process pmd rows ({pmd_rows}) cannot exceed the host-wide thp_split_pmd delta ({split_pmd_delta})"
            );
        } else {
            eprintln!(
                "  (pmd-vs-vmstat bound not asserted: leg={thp_leg} probes the public entry)"
            );
        }
    } else {
        eprintln!("  (THP split assertions skipped: leg={thp_leg}, thp_enabled={thp_enabled}, thp faults={thp_fault_delta})");
    }

    // --- memory_rss anon_huge sample for the workload when THP faulted ---
    let anon_huge: Option<i64> = conn
        .query_row(
            &format!(
                "SELECT MAX(size) FROM memory_rss WHERE member = -6 AND utid IN {UTIDS_FOR_PID}"
            ),
            [child_pid],
            |row| row.get(0),
        )
        .expect("memory_rss anon_huge query");
    eprintln!("  memory_rss anon_huge (member -6): {anon_huge:?}");

    // --- utid FK integrity: every new-table utid resolves to a thread row ---
    for table in ["memory_thp", "memory_vfio", "memory_iommu"] {
        let orphans: i64 = conn
            .query_row(
                &format!(
                    "SELECT COUNT(*) FROM {table} m LEFT JOIN thread t ON t.utid = m.utid WHERE t.utid IS NULL"
                ),
                [],
                |row| row.get(0),
            )
            .expect("orphan query");
        assert_eq!(orphans, 0, "[{table}] utids without a thread row");
    }

    // --- the VFIO tables: empty in the guest, and the leg says why ---
    let vfio_rows: i64 = conn
        .query_row("SELECT COUNT(*) FROM memory_vfio", [], |row| row.get(0))
        .expect("memory_vfio count");
    let iommu_rows: i64 = conn
        .query_row("SELECT COUNT(*) FROM memory_iommu", [], |row| row.get(0))
        .expect("memory_iommu count");
    eprintln!("  memory_vfio rows={vfio_rows} memory_iommu rows={iommu_rows} (leg {vfio_leg})");
    if vfio_leg != "on" {
        assert_eq!(vfio_rows, 0);
        assert_eq!(iommu_rows, 0);
    }
}
