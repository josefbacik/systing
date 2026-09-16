/// The names a Python process gave its threads (`threading.Thread(name=...)`).
///
/// The interpreter's thread state has no name; the name is an attribute of the
/// `threading.Thread` object, and those are found the way Python finds them:
///
/// ```text
///   _PyRuntime.interpreters.main ─► PyInterpreterState.imports.modules   (sys.modules)
///     ["threading"] ─► module.__dict__ ["_active"]                       ({ident: Thread})
///       each Thread ─► its attributes: _name, _native_id
/// ```
///
/// `_native_id` is the thread's tid, so the names are keyed by tid and no
/// mapping from pthread ids is needed. It is the tid as the process sees it:
/// for a process in a pid namespace of its own (a container) it is translated
/// to the host's through /proc.
///
/// All of it is read from the running process (`pyobject.rs`); a name that
/// cannot be read is left out, and the next call tries again.
use super::offsets::{self, ObjectOffsets};
use super::process::{ProcessMemory, ReadMemory};
use super::pyobject::PyReader;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::time::{Duration, Instant};

/// How long to leave a process alone after finding no `threading` module in
/// it: looking means reading all of sys.modules.
const RETRY_AFTER: Duration = Duration::from_secs(2);

/// How long a process's names are taken as read. Finding them is a walk of
/// `_active` and several reads for each thread in it, every thread of the
/// process and not just the ones asked about, and a name hardly ever changes.
/// A thread not seen before is looked up at once; a rename shows this much
/// later at most.
const REFRESH_AFTER: Duration = Duration::from_secs(1);

/// Most entries of `threading._active` that are followed. It has one per live
/// thread, but it is the process's dict and the process can put what it likes
/// in it; every entry costs several reads of its memory, on every read of its
/// names. This many threads is as many as the task-stacks recorder tracks.
const MAX_THREADS: usize = 1 << 16;

/// What `_PyRuntime` starts with in a Python that publishes its offsets.
const DEBUG_OFFSETS_COOKIE: &[u8; 8] = b"xdebugpy";
/// No struct the offsets are into is anywhere near this big.
const MAX_DEBUG_OFFSET: usize = 1 << 20;

/// Where the main interpreter is in `_PyRuntime`, and sys.modules in an
/// interpreter: what the process's own `_Py_DebugOffsets` says, else what the
/// bindings have. The interpreter's state grows in patch releases (its
/// `imports.modules` is 24 bytes further in 3.14.6 than in 3.14.0); the table
/// is there so that a reader need not know.
///
/// The main interpreter, not the head of the list of them: that list is
/// newest first, so with a subinterpreter alive its head is the
/// subinterpreter, whose `threading` knows its own threads alone and calls
/// the one it runs on `MainThread`. The table has where `interpreters.head`
/// is; `interpreters.main` is the field after it.
fn runtime_hops<M: ReadMemory>(
    py: &PyReader<M>,
    o: &ObjectOffsets,
    runtime_addr: usize,
) -> (usize, usize) {
    let table = runtime_addr + o.runtime_debug_offsets;
    let own = |at: usize| {
        py.ptr(table + at)
            .filter(|offset| *offset < MAX_DEBUG_OFFSET)
    };
    match (
        py.ptr(table).map(|cookie| cookie.to_ne_bytes()),
        own(o.debug_interpreters_head),
        own(o.debug_imports_modules),
    ) {
        (Some(cookie), Some(head), Some(modules)) if &cookie == DEBUG_OFFSETS_COOKIE => (
            head + (o.runtime_interpreters_main - o.runtime_interpreters_head),
            modules,
        ),
        _ => (o.runtime_interpreters_main, o.interp_modules),
    }
}

/// The module `name` of the process's main interpreter, if it is imported.
pub fn find_module<M: ReadMemory>(
    py: &PyReader<M>,
    o: &ObjectOffsets,
    runtime_addr: usize,
    name: &str,
) -> Option<usize> {
    let (interpreters_main, imports_modules) = runtime_hops(py, o, runtime_addr);
    let interp = py.ptr(runtime_addr + interpreters_main)?;
    let modules = py.ptr(interp + imports_modules)?;
    py.get(&py.dict_items(modules)?, name)
}

/// `threading._active`: the dict of the threads that are running.
fn find_active_threads<M: ReadMemory>(
    py: &PyReader<M>,
    o: &ObjectOffsets,
    runtime_addr: usize,
) -> Option<usize> {
    let threading = find_module(py, o, runtime_addr, "threading")?;
    let globals = py.ptr(threading + o.module_md_dict)?;
    py.get(&py.dict_items(globals)?, "_active")
}

/// Whether what was read as a thread's name is one to show. It goes into a
/// table and a track's title as it is, and it is whatever the process has
/// there: a name with a newline or an escape sequence in it, or, when a str
/// is read while it is being replaced, a length that reaches into whatever
/// follows it on the heap. Control characters, and code points that are none
/// (they are read as U+FFFD), say it is not text worth keeping.
fn is_a_name(name: &str) -> bool {
    !name
        .chars()
        .any(|c| c.is_control() || c == char::REPLACEMENT_CHARACTER)
}

/// (`_native_id`, `_name`) of every thread in `active` that has both, as far
/// as its first `max_threads` entries.
fn read_names<M: ReadMemory>(
    py: &PyReader<M>,
    active: usize,
    max_threads: usize,
) -> Option<Vec<(i64, String)>> {
    // Instances of a class share their keys: a key's text is read once.
    let mut key_text: HashMap<usize, Option<String>> = HashMap::new();
    let mut names = Vec::new();
    for (_, thread) in py.dict_items(active)?.into_iter().take(max_threads) {
        let Some(attrs) = py.instance_items(thread) else {
            continue;
        };
        let (mut name, mut native_id) = (None, None);
        for (key, value) in attrs {
            match key_text
                .entry(key)
                .or_insert_with(|| py.str(key))
                .as_deref()
            {
                Some("_name") => name = py.str(value).filter(|name| is_a_name(name)),
                // None until the thread has started.
                Some("_native_id") => native_id = py.long(value),
                _ => {}
            }
        }
        if let (Some(name), Some(native_id)) = (name, native_id) {
            names.push((native_id, name));
        }
    }
    Some(names)
}

/// The innermost and the host's id of the task whose `status` this is, when
/// they differ: `NSpid:` lists a task's id in every pid namespace it is in,
/// the reader's first and its own last.
fn nspid(status: &str) -> Option<(i32, i32)> {
    let ids: Vec<i32> = status
        .lines()
        .find_map(|line| line.strip_prefix("NSpid:"))?
        .split_whitespace()
        .filter_map(|id| id.parse().ok())
        .collect();
    match ids.as_slice() {
        [host, .., inner] => Some((*inner, *host)),
        _ => None,
    }
}

/// A process's tids as it sees them, to the host's.
struct HostTids {
    pid: i32,
    /// Whether the process is in a pid namespace of its own; `None` until asked.
    nested: Option<bool>,
    by_inner: HashMap<i32, i32>,
    /// Whether the tasks have been looked at again in this read of the names:
    /// once is enough, however many ids turn out to be no task's.
    rescanned: bool,
}

impl HostTids {
    fn host_tid(&mut self, inner: i32) -> Option<i32> {
        let pid = self.pid;
        let nested = *self.nested.get_or_insert_with(|| {
            fs::read_to_string(format!("/proc/{pid}/status"))
                .is_ok_and(|status| nspid(&status).is_some())
        });
        if !nested {
            return Some(inner);
        }
        if !self.by_inner.contains_key(&inner) && !self.rescanned {
            // A thread not seen before: look at the tasks again.
            self.rescanned = true;
            self.by_inner.clear();
            for task in fs::read_dir(format!("/proc/{pid}/task")).ok()?.flatten() {
                if let Some((inner, host)) = fs::read_to_string(task.path().join("status"))
                    .ok()
                    .as_deref()
                    .and_then(nspid)
                {
                    self.by_inner.insert(inner, host);
                }
            }
        }
        self.by_inner.get(&inner).copied()
    }
}

/// The thread names of one Python process.
pub struct ThreadNames<M: ReadMemory = ProcessMemory> {
    mem: M,
    offsets: ObjectOffsets,
    runtime_addr: usize,
    /// `threading._active`, once found: the module keeps the one dict for as
    /// long as the process lives (a fork clears and refills it).
    active: Option<usize>,
    /// When to look for it again, after not finding it.
    retry_at: Option<Instant>,
    host_tids: HostTids,
    /// The names as the last walk of `_active` found them, by host tid, and
    /// when that was.
    names: HashMap<i32, String>,
    walked_at: Option<Instant>,
    /// The tids asked about so far that a walk found no thread for: one that
    /// `threading` did not start (a C library's pool, say) is never in
    /// `_active`, and is no reason to walk again. Kept from walk to walk, as
    /// the snapshots ask about different threads each time; one that gets a
    /// Thread object after all is named at the next timed walk.
    absent: HashSet<i32>,
    /// `_PyRuntime` itself could not be read: see [`Self::is_gone`].
    gone: bool,
}

impl ThreadNames {
    /// `None` for a Python whose objects `pyobject.rs` cannot read yet (see
    /// `offsets::object_offsets_for_version`), or a process that is gone.
    pub fn open(pid: i32, runtime_addr: usize, major: i32, minor: i32) -> Option<Self> {
        // The version first: it costs nothing, and is asked again on every
        // snapshot of a process that has no reader.
        let offsets = offsets::object_offsets_for_version(major, minor)?;
        let mem = match ProcessMemory::open(pid) {
            Ok(mem) => mem,
            Err(e) => {
                // Refused, as opposed to gone: the names will all be missing,
                // and nothing else would say why. Once is enough.
                static SAID: std::sync::Once = std::sync::Once::new();
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    SAID.call_once(|| {
                        eprintln!(
                            "pystacks: no Python thread names: cannot open /proc/{pid}/mem ({e}). \
                             It takes root with CAP_SYS_PTRACE, and Yama's ptrace_scope 3 forbids it."
                        );
                    });
                }
                return None;
            }
        };
        Some(Self {
            mem,
            offsets,
            runtime_addr,
            active: None,
            retry_at: None,
            host_tids: HostTids {
                pid,
                nested: None,
                by_inner: HashMap::new(),
                rescanned: false,
            },
            names: HashMap::new(),
            walked_at: None,
            absent: HashSet::new(),
            gone: false,
        })
    }
}

impl<M: ReadMemory> ThreadNames<M> {
    /// The names there are to take note of, by host tid, when the threads
    /// `changed` have run since they were last asked about and `seen` are all
    /// the threads the process has now (`changed` among them).
    ///
    /// The names are read again, with a walk of `_active`, when one of
    /// `changed` has not been seen before, or when the last walk is
    /// [`REFRESH_AFTER`] old: a thread can have been renamed only if one of the
    /// process's threads has run. What comes back then is the name of every
    /// one of `seen` that has one, whether it was asked about or not: a thread
    /// that stays blocked can be renamed by another, and one can have been
    /// asked about before its name could be read. When nothing is read there
    /// is nothing new, and nothing comes back. Nothing either when the process
    /// has not imported `threading`, or is gone.
    ///
    /// Only `seen` are answered for, and they have to be the process's own: a
    /// name's tid is the process's word (`Thread._native_id`), checked against
    /// its tasks only for a process in a pid namespace, on the way to the
    /// host's ids.
    pub fn read(&mut self, changed: &HashSet<i32>, seen: &HashSet<i32>) -> HashMap<i32, String> {
        self.read_at(changed, seen, Instant::now())
    }

    /// Whether this reader has lost its process: not `_active` but
    /// `_PyRuntime` itself no longer reads. The open /proc/pid/mem is of the
    /// address space it was opened on, and after an exec (the pid lives on)
    /// every read of it comes back short for good. A reader opened afresh
    /// sees the new one.
    pub fn is_gone(&self) -> bool {
        self.gone
    }

    fn read_at(
        &mut self,
        changed: &HashSet<i32>,
        seen: &HashSet<i32>,
        now: Instant,
    ) -> HashMap<i32, String> {
        let stale = self
            .walked_at
            .is_none_or(|at| now.duration_since(at) >= REFRESH_AFTER);
        let unseen = |tid: &i32| !self.names.contains_key(tid) && !self.absent.contains(tid);
        if !stale && !changed.iter().any(unseen) {
            return HashMap::new();
        }
        self.walk(seen, now);
        seen.iter()
            .filter_map(|tid| Some((*tid, self.names.get(tid)?.clone())))
            .collect()
    }

    /// Read every thread's name again, and note which of `tids` have none.
    fn walk(&mut self, tids: &HashSet<i32>, now: Instant) {
        self.host_tids.rescanned = false;
        let py = PyReader::new(&self.mem, self.offsets);
        if self.active.is_none() {
            if self.retry_at.is_some_and(|at| now < at) {
                return;
            }
            self.active = find_active_threads(&py, &self.offsets, self.runtime_addr);
            self.retry_at = self.active.is_none().then(|| now + RETRY_AFTER);
        }
        let names = self
            .active
            .and_then(|active| read_names(&py, active, MAX_THREADS));
        let Some(names) = names else {
            // No dict, or not the dict it was: the process may have exec'd.
            // Look for it again, and do not answer with what is no longer so.
            self.gone = py.ptr(self.runtime_addr).is_none();
            self.active = None;
            self.names.clear();
            self.absent.clear();
            self.walked_at = None;
            return;
        };
        self.names = names
            .into_iter()
            .filter_map(|(native_id, name)| {
                let host = self.host_tids.host_tid(i32::try_from(native_id).ok()?)?;
                Some((host, name))
            })
            .collect();
        self.absent.retain(|tid| !self.names.contains_key(tid));
        if self.absent.len() > MAX_THREADS {
            // Tids come and go over a long capture. Start over.
            self.absent.clear();
        }
        self.absent.extend(
            tids.iter()
                .filter(|tid| !self.names.contains_key(tid))
                .copied(),
        );
        self.walked_at = Some(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pystacks::pyobject::tests::{FakeMemory, INLINE_TYPE};

    #[test]
    fn names_are_read_from_threading_active_by_native_id() {
        let mem = FakeMemory::new();
        let o = offsets::object_offsets_for_version(3, 13).unwrap();
        let py = PyReader::new(&mem, o);

        // class Thread: instances share these keys.
        let keys: Vec<(usize, usize)> = ["_target", "_name", "_native_id"]
            .iter()
            .map(|k| (mem.str(&o, k), 0))
            .collect();
        let tp = mem.heap_type(&o, INLINE_TYPE, 16, mem.keys(&o, 2, &keys));
        let thread = |name: &str, native_id: usize| {
            mem.instance(&o, tp, 16, &[0, mem.str(&o, name), native_id], true, 0)
        };
        let main = thread("MainThread", mem.long(&o, 100));
        let worker = thread("wörker-1", mem.long(&o, 101));
        // Created, not started: no native id yet, so no tid to name.
        let unstarted = thread("later", mem.none(&o));
        // Not text to put in a table or a title.
        let garbled = thread("two\nlines\x1b[31m", mem.long(&o, 102));

        // threading._active = {ident: Thread}
        let idents: Vec<usize> = (1..=4).map(|i| mem.long(&o, 0x7f00 + i)).collect();
        let active = mem.dict(
            &o,
            0,
            &[
                (idents[0], main),
                (idents[1], worker),
                (idents[2], unstarted),
                (idents[3], garbled),
            ],
        );
        // The module, sys.modules, the interpreter and the runtime.
        let globals = mem.str_dict(
            &o,
            &[("__name__", mem.str(&o, "threading")), ("_active", active)],
        );
        let module = mem.alloc(o.module_md_dict + 8);
        mem.write_u64(module + o.module_md_dict, globals as u64);
        let modules = mem.str_dict(&o, &[("sys", 0x51), ("threading", module)]);
        let interp = mem.alloc(o.interp_modules + 8);
        mem.write_u64(interp + o.interp_modules, modules as u64);
        // A subinterpreter, newer and so at the head of the list, with a
        // `threading` of its own: not the one to ask.
        let sub_module = mem.alloc(o.module_md_dict + 8);
        let sub_modules = mem.str_dict(&o, &[("threading", sub_module)]);
        let sub_interp = mem.alloc(o.interp_modules + 8);
        mem.write_u64(sub_interp + o.interp_modules, sub_modules as u64);
        let runtime = mem.alloc(o.runtime_interpreters_main + 8);
        mem.write_u64(runtime + o.runtime_interpreters_head, sub_interp as u64);
        mem.write_u64(runtime + o.runtime_interpreters_main, interp as u64);

        assert_eq!(find_module(&py, &o, runtime, "threading"), Some(module));
        assert_eq!(find_module(&py, &o, runtime, "asyncio"), None);

        // A patch release whose interpreter has sys.modules 24 bytes further
        // on, and says so in its table.
        let moved = mem.alloc(o.interp_modules + 32);
        mem.write_u64(moved + o.interp_modules + 24, modules as u64);
        let newer = mem.alloc(o.runtime_interpreters_main + 8);
        mem.write(newer, DEBUG_OFFSETS_COOKIE);
        mem.write_u64(
            newer + o.debug_interpreters_head,
            o.runtime_interpreters_head as u64,
        );
        mem.write_u64(
            newer + o.debug_imports_modules,
            (o.interp_modules + 24) as u64,
        );
        mem.write_u64(newer + o.runtime_interpreters_head, sub_interp as u64);
        mem.write_u64(newer + o.runtime_interpreters_main, moved as u64);
        assert_eq!(find_module(&py, &o, newer, "threading"), Some(module));
        assert_eq!(find_active_threads(&py, &o, runtime), Some(active));
        let mut names = read_names(&py, active, MAX_THREADS).unwrap();
        names.sort();
        assert_eq!(
            names,
            [
                (100, "MainThread".to_string()),
                (101, "wörker-1".to_string())
            ]
        );
        // The dict is the process's, and only so much of it is followed.
        assert_eq!(
            read_names(&py, active, 1).unwrap(),
            [(100, "MainThread".to_string())]
        );
    }

    #[test]
    fn names_are_remembered_until_a_thread_is_new_or_a_second_has_passed() {
        let mem = FakeMemory::new();
        let o = offsets::object_offsets_for_version(3, 13).unwrap();
        let keys: Vec<(usize, usize)> = ["_target", "_name", "_native_id"]
            .iter()
            .map(|k| (mem.str(&o, k), 0))
            .collect();
        let tp = mem.heap_type(&o, INLINE_TYPE, 16, mem.keys(&o, 2, &keys));
        let main = mem.instance(
            &o,
            tp,
            16,
            &[0, mem.str(&o, "MainThread"), mem.long(&o, 100)],
            true,
            0,
        );
        // Created, not started: no native id, so no tid, yet.
        let later = mem.instance(
            &o,
            tp,
            16,
            &[0, mem.str(&o, "later"), mem.none(&o)],
            true,
            0,
        );
        let active = mem.dict(
            &o,
            0,
            &[(mem.long(&o, 0x7f01), main), (mem.long(&o, 0x7f02), later)],
        );
        // Where a Thread keeps the value of its i-th attribute.
        let slot = |thread: usize, i: usize| thread + 16 + o.values_values + i * 8;

        let mut names = ThreadNames {
            mem,
            offsets: o,
            runtime_addr: 0,
            active: Some(active),
            retry_at: None,
            host_tids: HostTids {
                pid: 0,
                nested: Some(false),
                by_inner: HashMap::new(),
                rescanned: false,
            },
            names: HashMap::new(),
            walked_at: None,
            absent: HashSet::new(),
            gone: false,
        };
        let start = Instant::now();
        // What there is to take note of when `changed` have run and `seen` are
        // all the process's threads, this long after the start.
        let ask =
            |names: &mut ThreadNames<FakeMemory>, changed: &[i32], seen: &[i32], after_ms: u64| {
                let mut got: Vec<_> = names
                    .read_at(
                        &changed.iter().copied().collect(),
                        &seen.iter().copied().collect(),
                        start + Duration::from_millis(after_ms),
                    )
                    .into_iter()
                    .collect();
                got.sort();
                got
            };
        let named = |pairs: &[(i32, &str)]| -> Vec<(i32, String)> {
            pairs.iter().map(|(t, n)| (*t, n.to_string())).collect()
        };
        let nothing = named(&[]);

        assert_eq!(
            ask(&mut names, &[100], &[100], 0),
            named(&[(100, "MainThread")])
        );
        // Renamed, which is not seen until the names are read again: until
        // then there is nothing new.
        let renamed = names.mem.str(&o, "renamed");
        names.mem.write_u64(slot(main, 1), renamed as u64);
        assert_eq!(ask(&mut names, &[100], &[100], 100), nothing);
        // A thread not seen before: they are all read again, now.
        let tid = names.mem.long(&o, 101);
        names.mem.write_u64(slot(later, 2), tid as u64);
        let both = named(&[(100, "renamed"), (101, "later")]);
        assert_eq!(ask(&mut names, &[100, 101], &[100, 101], 200), both);
        // Two that `threading` did not start have no name. Each is looked
        // for once, and neither is a reason to read them all again after
        // that, whichever of them a snapshot asks about.
        assert_eq!(ask(&mut names, &[999], &[100, 101, 999], 300), both);
        assert_eq!(ask(&mut names, &[998], &[100, 101, 998, 999], 350), both);
        let again = names.mem.str(&o, "again");
        names.mem.write_u64(slot(main, 1), again as u64);
        assert_eq!(
            ask(&mut names, &[100, 999], &[100, 101, 998, 999], 400),
            nothing
        );
        assert_eq!(
            ask(&mut names, &[100, 998], &[100, 101, 998, 999], 450),
            nothing
        );
        // A second after they were last read, they are read again whoever
        // asks, and what has no name is still remembered.
        assert_eq!(
            ask(&mut names, &[999], &[100, 101, 998, 999], 1_350),
            named(&[(100, "again"), (101, "later")])
        );
        assert_eq!(
            ask(&mut names, &[998], &[100, 101, 998, 999], 1_400),
            nothing
        );
        // A thread that stays blocked is renamed by another. It is not asked
        // about, having not run, and its new name comes all the same.
        let by_another = names.mem.str(&o, "renamed by another");
        names.mem.write_u64(slot(later, 1), by_another as u64);
        assert_eq!(ask(&mut names, &[100], &[100, 101], 1_450), nothing);
        assert_eq!(
            ask(&mut names, &[100], &[100, 101], 2_350),
            named(&[(100, "again"), (101, "renamed by another")])
        );
    }

    #[test]
    fn nspid_gives_the_two_ends_of_a_nested_task() {
        let status = "Name:\tpython3\nPid:\t4100\nNSpid:\t4100\t17\nThreads:\t3\n";
        assert_eq!(nspid(status), Some((17, 4100)));
        // Three levels: the host's first, the task's own last.
        assert_eq!(nspid("NSpid:\t4100\t250\t17\n"), Some((17, 4100)));
        // The reader's own namespace: nothing to translate.
        assert_eq!(nspid("Name:\tpython3\nNSpid:\t4100\n"), None);
        assert_eq!(nspid("Name:\tpython3\n"), None);
    }
}
