//! The example program, built two ways and checked from OUTSIDE the process.
//!
//! One C source (`examples/tcx_example.c`) is linked once against a static
//! archive with `-static` and once against a shared object, each built here
//! from the library's one C file with the system compiler. Each program is
//! run as a child, and the test then does what a reader does, with no help
//! from the child beyond the thread pointer it prints:
//!
//! 1. find the info record in the ELF file by its section name, add the load
//!    bias taken from the child's map, and read the record out of the child's
//!    memory — it must carry its own address;
//! 2. for every thread, read the slot at thread pointer + the PUBLISHED
//!    offset, follow it to the block, and compare the id, the names and the
//!    values found there with the line the thread printed;
//! 3. let the program change a value and clear a name, and see the id move
//!    and the name go.
//!
//! What this cannot do is read the thread pointer the way a tracer's BPF
//! program does (from the task's saved registers): the program prints it.
//!
//! A tool that is missing (no C compiler, no static C library, no leave to
//! read a child's memory) makes a test SKIP with a line on stderr — except
//! when the `CI` environment variable is set, where it FAILS instead, so that
//! a green run there means the checks ran. Setting
//! `TASK_CONTEXT_TESTS_MAY_SKIP` turns that back into a skip.

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use object::{Object, ObjectSection, ObjectSegment};

const INFO_SECTION: &str = "task_context_info";
const INFO_SIZE: usize = 104;
const INFO_MAGIC: u32 = 0x3158_4354;
const BLOCK_MAGIC: u32 = 0x4258_4354;
const REGION_SIZE: u64 = 16 * 1024 * 1024;
const BLOCK_STRIDE: u64 = 2560;
const BLOCK_SIZE: usize = 2400;
const BLOCK_SLOTS_AT: usize = 32;
const SLOT_SIZE: usize = 296;
const SLOT_NAME_AT: usize = 8;
const SLOT_VALUE_AT: usize = 40;
const SLOTS: usize = 8;
const VALUE_MAX: usize = 256;
const THREADS: usize = 3;

// ---------------------------------------------------------------------------
// Skipping, and building the two programs
// ---------------------------------------------------------------------------

fn skips_are_failures() -> bool {
    std::env::var_os("CI").is_some_and(|v| !v.is_empty())
        && std::env::var_os("TASK_CONTEXT_TESTS_MAY_SKIP").is_none()
}

/// Returns after printing the reason, or panics where a skip is not allowed.
fn skip(reason: &str) {
    if skips_are_failures() {
        panic!("this check must run here (CI is set) and cannot: {reason}");
    }
    eprintln!("SKIPPED: {reason}");
}

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn fresh_dir(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("a directory to build in");
    dir
}

fn compiler() -> String {
    std::env::var("CC").unwrap_or_else(|_| "cc".to_string())
}

fn run_tool(command: &mut Command) -> Result<(), String> {
    match command.output() {
        Err(error) => Err(format!("{command:?}: {error}")),
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => Err(format!(
            "{command:?}: {}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )),
    }
}

fn compile(arguments: &[&str], inputs: &[&Path], output: &Path) -> Result<(), String> {
    let mut command = Command::new(compiler());
    command
        .args(["-O2", "-Wall", "-Wextra", "-pthread", "-I"])
        .arg(crate_dir().join("include"))
        .args(arguments)
        .args(inputs)
        .arg("-o")
        .arg(output);
    run_tool(&mut command)
}

/// A program to run, and the ELF file that holds the library's info record.
struct Fixture {
    program: PathBuf,
    record_is_in: PathBuf,
    library_dir: Option<PathBuf>,
}

fn have_a_compiler() -> bool {
    match Command::new(compiler()).arg("--version").output() {
        Ok(output) if output.status.success() => true,
        _ => {
            skip("no C compiler answers to `cc --version` (or to $CC)");
            false
        }
    }
}

fn build_static() -> Option<Fixture> {
    if !have_a_compiler() {
        return None;
    }
    let dir = fresh_dir("static");
    let source = crate_dir().join("src/task_context.c");
    let example = crate_dir().join("examples/tcx_example.c");
    let object = dir.join("task_context.o");
    let archive = dir.join("libtask_context.a");
    let program = dir.join("tcx_example_static");

    compile(&["-c"], &[&source], &object).expect("the library compiles");
    let mut ar = Command::new("ar");
    ar.arg("rcs").arg(&archive).arg(&object);
    if let Err(error) = run_tool(&mut ar) {
        skip(&format!("no archiver: {error}"));
        return None;
    }
    // The one step that can fail for want of a tool: a static C library.
    if let Err(error) = compile(&["-static"], &[&example, &archive], &program) {
        skip(&format!("the static link failed: {error}"));
        return None;
    }
    Some(Fixture {
        record_is_in: program.clone(),
        program,
        library_dir: None,
    })
}

fn build_dynamic() -> Option<Fixture> {
    if !have_a_compiler() {
        return None;
    }
    let dir = fresh_dir("dynamic");
    let source = crate_dir().join("src/task_context.c");
    let example = crate_dir().join("examples/tcx_example.c");
    let library = dir.join("libtask_context.so");
    let program = dir.join("tcx_example_dynamic");

    // nodelete: a thread's exit handler and the record point into the object.
    compile(
        &["-fPIC", "-shared", "-Wl,-z,nodelete"],
        &[&source],
        &library,
    )
    .expect("the shared object builds");
    let mut command = Command::new(compiler());
    command
        .args(["-O2", "-Wall", "-Wextra", "-pthread", "-I"])
        .arg(crate_dir().join("include"))
        .arg(&example)
        .arg("-L")
        .arg(&dir)
        .arg("-ltask_context")
        .arg("-o")
        .arg(&program);
    run_tool(&mut command).expect("the example links against the shared object");
    Some(Fixture {
        program,
        record_is_in: library,
        library_dir: Some(dir),
    })
}

// ---------------------------------------------------------------------------
// The line each thread prints
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Value {
    Number(u64),
    Text(Vec<u8>),
}

#[derive(Debug, Clone)]
struct ThreadLine {
    tid: u64,
    thread_pointer: u64,
    slot: u64,
    offset: i64,
    block: u64,
    id: u64,
    set: usize,
    values: Vec<(String, Value)>,
}

fn hex(text: &str) -> u64 {
    let digits = text.strip_prefix("0x").expect("a 0x prefix");
    u64::from_str_radix(digits, 16).expect("hex digits")
}

fn percent_decode(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' {
            let pair = std::str::from_utf8(&bytes[at + 1..at + 3]).expect("two hex digits");
            out.push(u8::from_str_radix(pair, 16).expect("two hex digits"));
            at += 3;
        } else {
            out.push(bytes[at]);
            at += 1;
        }
    }
    out
}

fn parse_line(line: &str) -> ThreadLine {
    let mut fields = line.split_whitespace();
    assert_eq!(fields.next(), Some("TCX1"), "not an example line: {line}");
    let mut fixed: HashMap<&str, &str> = HashMap::new();
    let mut values = Vec::new();
    for field in fields {
        let (key, value) = field.split_once('=').expect("key=value");
        match key.rsplit_once(':') {
            Some((name, "u")) => {
                values.push((name.to_string(), Value::Number(value.parse().unwrap())));
            }
            Some((name, "s")) => {
                values.push((name.to_string(), Value::Text(percent_decode(value))));
            }
            _ => {
                fixed.insert(key, value);
            }
        }
    }
    ThreadLine {
        tid: fixed["tid"].parse().unwrap(),
        thread_pointer: hex(fixed["tp"]),
        slot: hex(fixed["slot"]),
        offset: fixed["off"].parse().unwrap(),
        block: hex(fixed["block"]),
        id: hex(fixed["id"]),
        set: fixed["set"].parse().unwrap(),
        values,
    }
}

// ---------------------------------------------------------------------------
// Running the program, one phase at a time
// ---------------------------------------------------------------------------

struct Running {
    child: Arc<Mutex<Child>>,
    pid: u32,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    finished: Arc<AtomicBool>,
}

impl Running {
    fn start(fixture: &Fixture) -> Running {
        let mut command = Command::new(&fixture.program);
        command
            .arg("--hold")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        if let Some(dir) = &fixture.library_dir {
            command.env("LD_LIBRARY_PATH", dir);
        }
        let mut child = command.spawn().expect("the example starts");
        let pid = child.id();
        let stdin = child.stdin.take();
        let stdout = BufReader::new(child.stdout.take().expect("a pipe to read"));
        let child = Arc::new(Mutex::new(child));
        let finished = Arc::new(AtomicBool::new(false));

        // A program that hangs must fail the test, not the whole run.
        let watched = Arc::clone(&child);
        let done = Arc::clone(&finished);
        thread::spawn(move || {
            for _ in 0..1200 {
                if done.load(Ordering::Acquire) {
                    return;
                }
                thread::sleep(Duration::from_millis(100));
            }
            let _ = watched.lock().unwrap().kill();
        });

        Running {
            child,
            pid,
            stdin,
            stdout,
            finished,
        }
    }

    /// The lines of phase `number`, read up to its closing marker.
    fn phase(&mut self, number: usize) -> Vec<ThreadLine> {
        let marker = format!("TCX-PHASE {number} done");
        let mut lines = Vec::new();
        loop {
            let mut line = String::new();
            let read = self.stdout.read_line(&mut line).expect("a line");
            assert_ne!(
                read, 0,
                "the example ended before `{marker}`; its lines so far: {lines:?}"
            );
            let line = line.trim_end();
            if line == marker {
                return lines;
            }
            if line.starts_with("TCX1 ") {
                lines.push(parse_line(line));
            }
        }
    }

    fn go_on(&mut self) {
        let stdin = self.stdin.as_mut().expect("a pipe to write");
        stdin
            .write_all(b"go\n")
            .expect("the example reads its input");
        stdin.flush().expect("the example reads its input");
    }

    fn finish(mut self) {
        drop(self.stdin.take());
        let status = self.child.lock().unwrap().wait().expect("the example ends");
        self.finished.store(true, Ordering::Release);
        assert!(status.success(), "the example ended with {status}");
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        // After a failed assertion: do not leave the program behind.
        self.finished.store(true, Ordering::Release);
        if let Ok(mut child) = self.child.lock() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

// ---------------------------------------------------------------------------
// Reading the process from outside: its ELF file, its map, its memory
// ---------------------------------------------------------------------------

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

/// The three numbers needed to turn the file into a run-time address.
struct ElfFacts {
    record_address: u64,
    first_load_address: u64,
    first_load_offset: u64,
}

fn elf_facts(path: &Path) -> ElfFacts {
    let data = fs::read(path).expect("the ELF file");
    let file = object::File::parse(&*data).expect("a file the object crate can read");

    // The section the library puts its record in, by name.
    let record = file
        .section_by_name(INFO_SECTION)
        .expect("a section named task_context_info");
    assert!(record.size() as usize >= INFO_SIZE);

    // The loadable segment with the lowest address, and where it sits in
    // the file.
    let (first_load_address, first_load_offset) = file
        .segments()
        .map(|segment| (segment.address(), segment.file_range().0))
        .min()
        .expect("a loadable segment");

    ElfFacts {
        record_address: record.address(),
        first_load_address,
        first_load_offset,
    }
}

/// Every mapping of `file` in the process: (start address, file offset).
fn mappings_of(pid: u32, file: &Path) -> Vec<(u64, u64)> {
    let wanted = fs::canonicalize(file).expect("the file exists");
    let wanted = wanted.to_str().expect("a UTF-8 path");
    let maps = fs::read_to_string(format!("/proc/{pid}/maps")).expect("the map of a child");
    let mut found = Vec::new();
    for line in maps.lines() {
        let Some(path_at) = line.find('/') else {
            continue;
        };
        if &line[path_at..] != wanted {
            continue;
        }
        let mut fields = line.split_whitespace();
        let range = fields.next().unwrap();
        let _permissions = fields.next().unwrap();
        let offset = fields.next().unwrap();
        let start = range.split_once('-').unwrap().0;
        found.push((
            u64::from_str_radix(start, 16).unwrap(),
            u64::from_str_radix(offset, 16).unwrap(),
        ));
    }
    found
}

struct Memory {
    file: fs::File,
}

impl Memory {
    fn of(pid: u32) -> Option<Memory> {
        match fs::File::open(format!("/proc/{pid}/mem")) {
            Ok(file) => Some(Memory { file }),
            Err(error) => {
                skip(&format!("the child's memory cannot be opened: {error}"));
                None
            }
        }
    }

    fn bytes(&self, address: u64, length: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; length];
        self.file
            .read_exact_at(&mut bytes, address)
            .unwrap_or_else(|error| panic!("{length} bytes at {address:#x}: {error}"));
        bytes
    }
}

/// The fields of the info record this test uses.
#[derive(Debug)]
struct Info {
    address: u64,
    tp_offset: i64,
    region_base: u64,
}

/// Step 1: from the file and the map to the record in memory.
fn find_the_record(fixture: &Fixture, pid: u32, memory: &Memory) -> Info {
    let facts = elf_facts(&fixture.record_is_in);
    let (start, map_offset) = mappings_of(pid, &fixture.record_is_in)
        .into_iter()
        .min()
        .expect("the file is mapped in the child");
    assert!(map_offset <= facts.first_load_offset);
    // File offset `map_offset` is at `start`; the first segment's own offset
    // is at its link-time address plus the bias.
    let bias = start
        .wrapping_sub(facts.first_load_address)
        .wrapping_add(facts.first_load_offset - map_offset);
    let address = bias.wrapping_add(facts.record_address);

    let record = memory.bytes(address, INFO_SIZE);
    assert_eq!(u32_at(&record, 0), INFO_MAGIC, "magic");
    assert_eq!(u16_at(&record, 4), 1, "version");
    assert_eq!(u16_at(&record, 6) as usize, INFO_SIZE, "info_size");
    assert_eq!(u32_at(&record, 8), 1, "recipe_tag: thread pointer + offset");
    assert!(u32_at(&record, 12) >= 1, "recipe_generation");
    assert_eq!(
        u64_at(&record, 48),
        address,
        "self_address: the record says where it is, and the file agrees"
    );
    assert_eq!(u64_at(&record, 64), REGION_SIZE, "region_size");
    assert_eq!(u64::from(u32_at(&record, 72)), BLOCK_STRIDE, "block_size");
    assert_eq!(
        u16_at(&record, 76) as usize,
        BLOCK_SLOTS_AT,
        "block_hdr_size"
    );
    assert_eq!(u16_at(&record, 78) as usize, SLOT_SIZE, "slot_size");
    assert_eq!(u16_at(&record, 80) as usize, SLOTS, "nslots");
    assert_eq!(u32_at(&record, 84) as usize, VALUE_MAX, "value_max");
    let info = Info {
        address,
        tp_offset: u64_at(&record, 16) as i64,
        region_base: u64_at(&record, 56),
    };
    assert_ne!(info.region_base, 0);
    assert_eq!(info.region_base % 4096, 0);
    if cfg!(target_arch = "x86_64") {
        assert!(
            info.tp_offset < 0,
            "static TLS lies below the thread pointer"
        );
    } else if cfg!(target_arch = "aarch64") {
        assert!(
            info.tp_offset > 0,
            "static TLS lies above the thread pointer"
        );
    }
    info
}

/// Step 2: from a thread pointer to that thread's values.
fn check_thread(memory: &Memory, info: &Info, line: &ThreadLine) {
    let who = format!("thread {}", line.tid);
    assert_eq!(line.offset, info.tp_offset, "{who}: one offset per process");
    assert_eq!(
        line.slot.wrapping_sub(line.thread_pointer) as i64,
        info.tp_offset,
        "{who}"
    );
    let slot = line.thread_pointer.wrapping_add(info.tp_offset as u64);
    let block = u64_at(&memory.bytes(slot, 8), 0);
    assert_eq!(
        block, line.block,
        "{who}: the slot holds the block's address"
    );
    assert_ne!(block, 0, "{who}: it has set values");

    assert!(block >= info.region_base && block + BLOCK_STRIDE <= info.region_base + REGION_SIZE);
    assert_eq!((block - info.region_base) % BLOCK_STRIDE, 0, "{who}");

    let bytes = memory.bytes(block, BLOCK_SIZE);
    assert_eq!(u32_at(&bytes, 0), BLOCK_MAGIC, "{who}: block magic");
    assert_eq!(u16_at(&bytes, 4), 1, "{who}: block version");
    assert_eq!(
        u16_at(&bytes, 6) as usize,
        BLOCK_SLOTS_AT,
        "{who}: hdr_size"
    );
    let word = u64_at(&bytes, 8);
    assert_eq!(
        word, line.id,
        "{who}: the sequence word is the id it printed"
    );
    assert_ne!(word, 0, "{who}");
    assert_eq!(
        word & 1,
        0,
        "{who}: no update in progress while it holds still"
    );
    assert_ne!(word >> 40, 0, "{who}: a thread index is never 0");

    let mask = u32_at(&bytes, 16);
    assert_eq!(mask.count_ones() as usize, line.set, "{who}: set_mask");
    assert_eq!(line.values.len(), line.set, "{who}");

    // Every name the thread says it set is there, with that value; since the
    // counts agree, nothing else is.
    for (name, value) in &line.values {
        let found = (0..SLOTS).find(|&index| {
            let at = BLOCK_SLOTS_AT + index * SLOT_SIZE;
            (mask >> index) & 1 == 1
                && bytes[at + 1] as usize == name.len()
                && &bytes[at + SLOT_NAME_AT..at + SLOT_NAME_AT + name.len()] == name.as_bytes()
        });
        let index = found.unwrap_or_else(|| panic!("{who}: no slot named {name}"));
        let at = BLOCK_SLOTS_AT + index * SLOT_SIZE;
        let stored = &bytes[at + SLOT_VALUE_AT..at + SLOT_VALUE_AT + VALUE_MAX];
        let length = u16_at(&bytes, at + 2) as usize;
        match value {
            Value::Number(number) => {
                assert_eq!(bytes[at], 1, "{who}: {name} is a number");
                assert_eq!(length, 8, "{who}: {name}");
                assert_eq!(u64_at(stored, 0), *number, "{who}: {name}");
            }
            Value::Text(text) => {
                assert_eq!(bytes[at], 2, "{who}: {name} is a string");
                assert_eq!(length, text.len(), "{who}: {name}");
                assert_eq!(&stored[..length], &text[..], "{who}: {name}");
                assert!(stored[length..].iter().all(|&b| b == 0), "{who}: {name}");
            }
        }
    }
}

fn by_tid(lines: &[ThreadLine]) -> HashMap<u64, &ThreadLine> {
    lines.iter().map(|line| (line.tid, line)).collect()
}

fn check_fixture(fixture: &Fixture) {
    // Run plainly first: straight through, three phases of three lines, a few
    // milliseconds on a CPU after each.
    let mut plain = Command::new(&fixture.program);
    plain.args(["--busy-ms", "5"]);
    if let Some(dir) = &fixture.library_dir {
        plain.env("LD_LIBRARY_PATH", dir);
    }
    let output = plain.output().expect("the example runs");
    assert!(
        output.status.success(),
        "the example ended with {}",
        output.status
    );
    let text = String::from_utf8(output.stdout).expect("the example prints text");
    assert_eq!(
        text.lines().filter(|l| l.starts_with("TCX1 ")).count(),
        3 * THREADS
    );
    assert_eq!(
        text.lines().filter(|l| l.starts_with("TCX-PHASE ")).count(),
        3
    );

    // Then holding still between phases, looked at from outside.
    let mut running = Running::start(fixture);
    let first = running.phase(0);
    assert_eq!(first.len(), THREADS);

    // The program is what it says it is: the shared object is mapped in the
    // dynamic one and only there.
    let shared_object_mapped = fs::read_to_string(format!("/proc/{}/maps", running.pid))
        .expect("the map of a child")
        .contains("libtask_context.so");
    assert_eq!(shared_object_mapped, fixture.library_dir.is_some());

    let Some(memory) = Memory::of(running.pid) else {
        return;
    };
    let info = find_the_record(fixture, running.pid, &memory);
    for line in &first {
        assert_eq!(line.set, 2, "request_id and iteration_id");
        check_thread(&memory, &info, line);
    }
    for a in 0..THREADS {
        for b in a + 1..THREADS {
            assert_ne!(first[a].block, first[b].block, "two threads, two blocks");
            assert_ne!(first[a].id >> 40, first[b].id >> 40, "two thread indices");
        }
    }

    // A value changes: the id moves, inside the same thread index.
    running.go_on();
    let second = running.phase(1);
    assert_eq!(second.len(), THREADS);
    let before = by_tid(&first);
    for line in &second {
        let earlier = before[&line.tid];
        assert_ne!(line.id, earlier.id, "thread {}: the id moved", line.tid);
        assert_eq!(line.id >> 40, earlier.id >> 40, "thread {}", line.tid);
        assert_eq!(line.block, earlier.block, "thread {}", line.tid);
        check_thread(&memory, &info, line);
    }

    // A name is cleared: one value is left, and the name is gone.
    running.go_on();
    let third = running.phase(2);
    assert_eq!(third.len(), THREADS);
    for line in &third {
        assert_eq!(line.set, 1, "only iteration_id is left");
        assert!(line.values.iter().all(|(name, _)| name != "request_id"));
        check_thread(&memory, &info, line);
    }

    // The record did not move or change its recipe while the program ran.
    let again = find_the_record(fixture, running.pid, &memory);
    assert_eq!(again.address, info.address);
    assert_eq!(again.tp_offset, info.tp_offset);
    assert_eq!(again.region_base, info.region_base);

    running.finish();
}

#[test]
fn the_statically_linked_example_is_found_by_its_published_recipe() {
    let Some(fixture) = build_static() else {
        return;
    };
    check_fixture(&fixture);
}

#[test]
fn the_dynamically_linked_example_is_found_by_its_published_recipe() {
    let Some(fixture) = build_dynamic() else {
        return;
    };
    check_fixture(&fixture);
}
