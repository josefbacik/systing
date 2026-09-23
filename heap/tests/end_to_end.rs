//! Parse, symbolize and write a dump whose stacks point into this test
//! binary, so symbolization is checked without jemalloc.

use std::io::Write;

use duckdb::Connection;
use systing_heap::{db, jemalloc, symbolize};

#[inline(never)]
#[no_mangle]
pub extern "C" fn heap_e2e_allocating_function(x: u64) -> u64 {
    // Enough body that addr + 8 is still inside the function.
    std::hint::black_box(x).wrapping_mul(31).rotate_left(7) ^ std::hint::black_box(x)
}

#[test]
fn a_dump_becomes_named_stacks_and_heap_rows() {
    let f = heap_e2e_allocating_function as extern "C" fn(u64) -> u64 as usize as u64;
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    let dump = format!(
        "heap_v2/524288\n  t*: 3: 3000 [0: 0]\n\
         @ 0x{f:x} 0x{caller:x} 0x10\n  t*: 2: 2048 [5: 4096]\n  t0: 2: 2048 [5: 4096]\n\
         @ 0x{f:x}\n  t*: 1: 952 [0: 0]\n\
         \nMAPPED_LIBRARIES:\n{maps}",
        caller = f + 8,
    );
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("jeprof.4242.3.m1.heap");
    std::fs::File::create(&path)
        .unwrap()
        .write_all(dump.as_bytes())
        .unwrap();

    let snapshot = jemalloc::read(&path).unwrap();
    assert_eq!(snapshot.pid, Some(4242));
    assert_eq!(snapshot.seq, Some(3));
    assert_eq!(snapshot.trigger, Some("manual"));
    let snapshots = vec![snapshot];
    let symbolized = symbolize::symbolize(&snapshots);

    let out = dir.path().join("heap.duckdb");
    let written = db::write(&out, "heap", "test", &snapshots, &symbolized).unwrap();
    assert_eq!(
        (written.snapshots, written.samples, written.stacks),
        (1, 2, 2)
    );

    let conn = Connection::open(&out).unwrap();
    let version: i32 = conn
        .query_row("SELECT version FROM _schema_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, systing::duckdb::SCHEMA_VERSION as i32);

    // Root first: the unmapped 0x10 is the outermost frame, the function the
    // leaf; the caller frame resolved to the same function via addr - 1.
    let names: Vec<String> = conn
        .prepare(
            "SELECT unnest(sf.frame_names) FROM heap_sample h
             JOIN stack_frames sf ON sf.trace_id = h.trace_id AND sf.id = h.stack_id
             WHERE h.live_bytes = 2048",
        )
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(names.len(), 3, "{names:?}");
    assert_eq!(names[0], "0x10");
    for n in &names[1..] {
        assert!(n.starts_with("heap_e2e_allocating_function ("), "{n}");
    }
    assert!(names[2].ends_with(&format!("<{f:#x}>")), "{}", names[2]);

    let (upid, trigger, header_bytes, pname): (i64, String, i64, String) = conn
        .query_row(
            "SELECT s.upid, s.dump_trigger, s.header_live_bytes, p.name
             FROM heap_snapshot s JOIN process p USING (trace_id, upid)",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    assert_eq!((upid, trigger.as_str(), header_bytes), (1, "manual", 3000));
    assert!(!pname.is_empty());

    let (alloc_objects, alloc_bytes): (i64, i64) = conn
        .query_row(
            "SELECT alloc_objects, alloc_bytes FROM heap_sample WHERE live_bytes = 2048",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((alloc_objects, alloc_bytes), (5, 4096));
}

#[test]
fn a_dump_naming_a_device_is_not_opened() {
    // A dump is untrusted input: its maps could point symbolization at a
    // device or FIFO that never ends. /dev/zero must be refused, not read.
    let dump = "heap_v2/524288\n  t*: 1: 64 [0: 0]\n@ 0x1010\n  t*: 1: 64 [0: 0]\n\
                \nMAPPED_LIBRARIES:\n\
                00001000-00002000 r-xp 00000000 00:05 4 /dev/zero\n";
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("jeprof.1.0.f.heap");
    std::fs::write(&path, dump).unwrap();
    let snapshots = vec![jemalloc::read(&path).unwrap()];
    let symbolized = symbolize::symbolize(&snapshots);
    assert_eq!(
        symbolized.stats.refused_files,
        vec![std::path::PathBuf::from("/dev/zero")]
    );
    assert_eq!(symbolized.frames[0][0], vec!["unknown (zero) <0x1010>"]);
}

fn anon_exec_dump(dir: &std::path::Path) -> std::path::PathBuf {
    // 0x20008 is in an anonymous executable mapping, as a perf trampoline is.
    let dump = "heap_v2/524288\n  t*: 1: 64 [0: 0]\n@ 0x20008 0x20028\n  t*: 1: 64 [0: 0]\n\
                \nMAPPED_LIBRARIES:\n\
                00020000-00021000 r-xp 00000000 00:00 0 \n";
    let path = dir.join("jeprof.77.0.f.heap");
    std::fs::write(&path, dump).unwrap();
    path
}

#[test]
fn perf_map_names_python_trampoline_frames() {
    let dir = tempfile::tempdir().unwrap();
    let mut snapshot = jemalloc::read(&anon_exec_dump(dir.path())).unwrap();
    snapshot.perf_map = Some(std::sync::Arc::new(systing_heap::perfmap::PerfMap::parse(
        "20000 10 py::leak:/srv/app/work.py\n20020 10 py::Outer.run:/srv/app/work.py\n",
    )));
    let snapshots = vec![snapshot];
    let symbolized = symbolize::symbolize(&snapshots);
    // Root first: the caller (0x20028, looked up one byte back) then the leaf.
    assert_eq!(
        symbolized.frames[0][0],
        vec!["Outer.run (python) [work.py]", "leak (python) [work.py]"]
    );
    assert_eq!(
        symbolized
            .files
            .get("leak (python) [work.py]")
            .map(String::as_str),
        Some("/srv/app/work.py")
    );
    assert!(symbolized.stats.unnamed_generated.is_empty());
}

#[test]
fn generated_code_without_a_perf_map_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let snapshots = vec![jemalloc::read(&anon_exec_dump(dir.path())).unwrap()];
    let symbolized = symbolize::symbolize(&snapshots);
    assert_eq!(symbolized.frames[0][0][1], "unknown ([anon]) <0x20008>");
    assert_eq!(
        symbolized.stats.unnamed_generated,
        vec![snapshots[0].source_path.clone()]
    );
}
