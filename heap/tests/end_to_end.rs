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

    // The trace names its recorder: NULL recorder columns would read as
    // "imported from a directory with no manifest".
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as i64
        - 3_600_000_000_000;
    let (recorder, recorder_schema, recorded_at): (String, i32, i64) = conn
        .query_row(
            "SELECT recorder_version, recorder_schema_version, recorded_at_unix_ns FROM _traces",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(recorder, systing::duckdb::SYSTING_VERSION);
    assert_eq!(recorder_schema, systing::duckdb::SCHEMA_VERSION as i32);
    assert!(recorded_at > before, "{recorded_at}");

    // Root first: the unmapped 0x10 is the outermost frame (the recorders'
    // label for an address in no mapping), the function the
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
    assert_eq!(names[0], "unknown ([unmapped]) <0x10>");
    for n in &names[1..] {
        assert!(n.starts_with("heap_e2e_allocating_function ("), "{n}");
    }
    assert!(names[2].ends_with(&format!("<{f:#x}>")), "{}", names[2]);

    let (upid, trigger, period, pname): (i64, String, i64, String) = conn
        .query_row(
            "SELECT s.upid, s.dump_trigger, s.sample_period, p.name
             FROM heap_snapshot s JOIN process p USING (trace_id, upid)",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    assert_eq!((upid, trigger.as_str(), period), (1, "manual", 524288));
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
    assert_eq!(
        symbolized.frames[0][0][1],
        "unknown ([anon:exec]) <0x20008>"
    );
    assert_eq!(
        symbolized.stats.unnamed_generated,
        vec![snapshots[0].source_path.clone()]
    );
}

#[test]
fn a_perf_map_names_only_generated_code() {
    // 0x30008 is in writable anonymous memory, 0x50008 in no mapping: a
    // stale perf map that covers them must not name them.
    let dump = "heap_v2/524288\n  t*: 1: 64 [0: 0]\n@ 0x30008 0x50008\n  t*: 1: 64 [0: 0]\n\
                \nMAPPED_LIBRARIES:\n\
                00030000-00031000 rw-p 00000000 00:00 0 \n";
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("jeprof.78.0.f.heap");
    std::fs::write(&path, dump).unwrap();
    let mut snapshot = jemalloc::read(&path).unwrap();
    snapshot.perf_map = Some(std::sync::Arc::new(systing_heap::perfmap::PerfMap::parse(
        "30000 100 py::stale:/srv/a.py\n50000 100 py::stale2:/srv/a.py\n",
    )));
    let snapshots = vec![snapshot];
    let symbolized = symbolize::symbolize(&snapshots);
    assert_eq!(
        symbolized.frames[0][0],
        vec![
            "unknown ([unmapped]) <0x50008>",
            "unknown ([anon]) <0x30008>"
        ]
    );
}

#[test]
fn library_python_frames_carry_the_module_like_pystacks() {
    let dir = tempfile::tempdir().unwrap();
    let mut snapshot = jemalloc::read(&anon_exec_dump(dir.path())).unwrap();
    let file = "/usr/lib/python3.13/site-packages/pkg/mod.py";
    snapshot.perf_map = Some(std::sync::Arc::new(systing_heap::perfmap::PerfMap::parse(
        &format!("20000 10 py::Cls.run:{file}\n20020 10 py::main:/srv/app.py\n"),
    )));
    let snapshots = vec![snapshot];
    let symbolized = symbolize::symbolize(&snapshots);
    let module = systing::pystacks::symbols::get_module_name_from_filename(file);
    assert!(!module.is_empty());
    assert_eq!(
        symbolized.frames[0][0],
        vec![
            "main (python) [app.py]".to_string(),
            format!("{module}:Cls.run (python) [mod.py]"),
        ]
    );
}

#[test]
fn perfetto_output_splits_frames_and_reports_cumulative_counts() {
    use perfetto_protos::trace::Trace;
    use protobuf::Message;

    // Two snapshots of one process: the stack holds 64 bytes, then 16.
    let dir = tempfile::tempdir().unwrap();
    let maps = "00020000-00021000 r-xp 00000000 00:00 0 \n";
    for (seq, bytes) in [(0, 64), (1, 16)] {
        let dump = format!(
            "heap_v2/1\n  t*: 1: {bytes} [0: 0]\n@ 0x20008 0x20028\n  t*: 1: {bytes} [0: 0]\n\
             \nMAPPED_LIBRARIES:\n{maps}"
        );
        std::fs::write(
            dir.path().join(format!("jeprof.91.{seq}.i{seq}.heap")),
            dump,
        )
        .unwrap();
    }
    std::fs::write(
        dir.path().join("perf-91.map"),
        "20000 10 py::leak:/srv/app/work.py\n20020 10 py::Outer.run:/srv/app/work.py\n",
    )
    .unwrap();
    let out = dir.path().join("heap.perfetto");
    let st = std::process::Command::new(env!("CARGO_BIN_EXE_systing-heap"))
        .arg(dir.path().join("jeprof"))
        .args(["--keep-all", "-o"])
        .arg(&out)
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "{}",
        String::from_utf8_lossy(&st.stderr)
    );

    let trace = Trace::parse_from_bytes(&std::fs::read(&out).unwrap()).unwrap();
    let mut strings = std::collections::HashMap::new();
    let mut frames = Vec::new();
    let mut dumps = Vec::new();
    let mut symbols = Vec::new();
    for p in &trace.packet {
        if p.has_profile_packet() {
            let pp = p.profile_packet();
            for s in &pp.strings {
                strings.insert(s.iid(), String::from_utf8(s.str().to_vec()).unwrap());
            }
            frames.extend(pp.frames.iter().map(|f| (f.function_name_id(), f.rel_pc())));
            dumps.extend(pp.process_dumps.iter().cloned());
        }
        if p.has_module_symbols() {
            let m = p.module_symbols();
            assert_eq!(m.build_id(), "systing-heap:[python]");
            // No line from a trampoline: 0, so the UI still shows the file.
            assert!(m
                .address_symbols
                .iter()
                .all(|a| a.lines[0].line_number() == 0));
            for a in &m.address_symbols {
                symbols.push((
                    m.path().to_string(),
                    a.lines[0].source_file_name().to_string(),
                ));
            }
        }
    }
    // Frames are named after the function alone, the source is a symbol,
    // and each snapshot's packet defines the frames it uses again.
    let names: Vec<&str> = frames.iter().map(|(id, _)| strings[id].as_str()).collect();
    assert_eq!(names, vec!["Outer.run", "leak", "Outer.run", "leak"]);
    assert_eq!(
        symbols,
        vec![
            ("/[python]".to_string(), "/srv/app/work.py".to_string()),
            ("/[python]".to_string(), "/srv/app/work.py".to_string())
        ]
    );
    // Each snapshot carries its increase since the previous one; summed up
    // to a snapshot, unreleased follows live and totals never fall.
    assert_eq!(dumps.len(), 2);
    let (a0, f0) = (
        dumps[0].samples[0].self_allocated(),
        dumps[0].samples[0].self_freed(),
    );
    let (a1, f1) = (
        dumps[1].samples[0].self_allocated(),
        dumps[1].samples[0].self_freed(),
    );
    assert!(a0 > 0 && f0 == 0, "{a0} {f0}");
    assert_eq!(a1, 0, "live fell, so nothing more was allocated");
    assert!(f1 > 0 && f1 < a0, "{f1} of {a0} freed");
    assert_eq!(dumps[0].pid(), 91);
    assert_eq!(dumps[0].heap_name(), "jemalloc");
}

#[test]
fn perfetto_output_keeps_processes_and_snapshot_order_apart() {
    use perfetto_protos::trace::Trace;
    use protobuf::Message;
    use std::time::{Duration, SystemTime};

    // Two processes whose Python functions sit at the same addresses, and a
    // copy that left process 91's first dump newer than its second.
    let dir = tempfile::tempdir().unwrap();
    let maps = "00020000-00021000 r-xp 00000000 00:00 0 \n";
    let dump = "heap_v2/1\n  t*: 1: 64 [0: 0]\n@ 0x20008 0x20028\n  t*: 1: 64 [0: 0]\n\
                \nMAPPED_LIBRARIES:\n"
        .to_string()
        + maps;
    let now = SystemTime::now();
    for (name, age) in [
        ("jeprof.91.0.i0.heap", 0),
        ("jeprof.91.1.i1.heap", 60),
        ("jeprof.92.0.i0.heap", 30),
    ] {
        let path = dir.path().join(name);
        std::fs::write(&path, &dump).unwrap();
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(now - Duration::from_secs(age))
            .unwrap();
    }
    for (pid, leaf, outer) in [(91, "leak", "Outer.run"), (92, "fetch", "Client.get")] {
        std::fs::write(
            dir.path().join(format!("perf-{pid}.map")),
            format!("20000 10 py::{leaf}:/srv/{pid}.py\n20020 10 py::{outer}:/srv/{pid}.py\n"),
        )
        .unwrap();
    }
    let out = dir.path().join("heap.pb");
    let st = std::process::Command::new(env!("CARGO_BIN_EXE_systing-heap"))
        .arg(dir.path().join("jeprof"))
        .args(["--keep-all", "-o"])
        .arg(&out)
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "{}",
        String::from_utf8_lossy(&st.stderr)
    );

    let trace = Trace::parse_from_bytes(&std::fs::read(&out).unwrap()).unwrap();
    // Perfetto merges both processes' [python] mapping and attaches symbols
    // by rel_pc, so each rel_pc must stand for one function in every packet.
    let mut symbol_at = std::collections::HashMap::new();
    let mut frames = Vec::new();
    let mut timestamps = Vec::new();
    for p in &trace.packet {
        if p.has_module_symbols() {
            for a in &p.module_symbols().address_symbols {
                let f = a.lines[0].function_name().to_string();
                assert!(
                    symbol_at.insert(a.address(), f.clone()).is_none(),
                    "two symbols at {:#x}",
                    a.address()
                );
            }
        }
        if p.has_profile_packet() {
            let pp = p.profile_packet();
            let strings: std::collections::HashMap<u64, String> = pp
                .strings
                .iter()
                .map(|s| (s.iid(), String::from_utf8(s.str().to_vec()).unwrap()))
                .collect();
            for f in &pp.frames {
                frames.push((strings[&f.function_name_id()].clone(), f.rel_pc()));
            }
            for d in &pp.process_dumps {
                timestamps.push((d.pid(), d.timestamp()));
            }
        }
    }
    for (name, rel_pc) in &frames {
        assert_eq!(&symbol_at[rel_pc], name, "frame {name} at {rel_pc:#x}");
    }
    let mut named: Vec<&String> = symbol_at.values().collect();
    named.sort();
    assert_eq!(named, vec!["Client.get", "Outer.run", "fetch", "leak"]);
    // Snapshots are in sequence order per process, and so are their times.
    let t91: Vec<u64> = timestamps
        .iter()
        .filter(|t| t.0 == 91)
        .map(|t| t.1)
        .collect();
    assert_eq!(t91.len(), 2);
    assert!(t91[0] < t91[1], "{t91:?}");
}
