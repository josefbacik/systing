//! Integration test for the memory recorder.
//!
//! Spawns an allocator workload, traces it with `--add-recorder memory`, and
//! validates the `memory_rss`, `memory_map`, and `memory_fault` tables.
//!
//! Requires root/BPF privileges; run via:
//! ```
//! ./scripts/run-integration-tests.sh memory_recorder
//! ```

use systing::{bump_memlock_rlimit, systing, Config};
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

fn setup_bpf_environment() {
    bump_memlock_rlimit().expect("Failed to bump memlock rlimit");
}

#[test]
#[ignore] // Requires root/BPF privileges
fn test_memory_recorder_e2e() {
    setup_bpf_environment();

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

    // --- Check: memory_fault has rows (x86_64 only) ---
    #[cfg(target_arch = "x86_64")]
    {
        eprintln!("  memory_fault events (x86_64)...");
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
    }
    #[cfg(not(target_arch = "x86_64"))]
    eprintln!("  memory_fault: skipped (non-x86_64)");

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

#[test]
#[ignore] // Requires root/BPF privileges
fn test_memory_alloc_e2e() {
    setup_bpf_environment();

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
