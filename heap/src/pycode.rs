//! Python frames the hooks' "python" backtrace put in a dump's stacks, and
//! the code map that names them.
//!
//! jemalloc keeps a stack as a list of addresses, so the hook stores a Python
//! frame as a 64-bit slot no address can equal: `0x5059` in the top 16 bits,
//! then a 24-bit code id and a 24-bit instruction index plus one (zero: the
//! frame has not started). Code id 0 is an interpreter entry frame, which
//! names no function: it marks where, among the native frames, a run of
//! Python frames belongs.
//!
//! The ids are the process's own, written to `pycode-<pid>-<token>.map`
//! beside its dumps, one line per code object as raw bytes:
//!
//! ```text
//! # systing-pycode 1 token=<token> pid=<pid> python=3.<minor>
//! <id hex> <first line> <kind>:<qualname hex> <kind>:<file hex> <line table hex>
//! ```
//!
//! `kind` is the bytes per character the str is stored with (1: Latin-1, 2:
//! UTF-16, 4: UTF-32; 0: not read), and the line table is CPython's own
//! (`co_linetable`), `-` when it was not read. The token is also the name of
//! a mapping in the process (`systing-pycode-<token>`), so a dump, which
//! carries the process's maps, says which code map is its own. A forked
//! child's map begins with the lines its parent had written by the fork, and
//! its ids go on from there: its dumps hold the stacks sampled before it.
//!
//! The file is the profiled process's to write, so nothing in it is taken on
//! trust: a line longer than the hook writes is not a code object, and a
//! name's control characters are not printed.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use systing::pystacks::linetable::PyLineTable;

use crate::maps::Maps;
use crate::root::Root;

const TAG: u64 = 0x5059;
const FIELD: u64 = 0xff_ffff;
const UNKNOWN_ID: u32 = FIELD as u32;
const MAPPING: &str = "systing-pycode-";
/// The first Python the hook writes a map for. An older one has another
/// line table, which the hook never wrote.
const FIRST_MINOR: i32 = 12;
/// The most the hook writes of a name, a file and a line table
/// (`MAX_NAME_CHARS`, `MAX_FILE_CHARS` and `MAX_LINETABLE` there).
const MAX_NAME_CHARS: usize = 1024;
const MAX_FILE_CHARS: usize = 4096;
const MAX_LINETABLE: usize = 65536;

/// What a slot in a stack says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Slot {
    /// An interpreter entry frame.
    Entry,
    /// A Python frame: its code object's id, and the index of the
    /// instruction it was at, `None` before its first.
    Frame { id: u32, inst: Option<u32> },
}

/// The slot `addr` is, `None` for an address.
pub fn slot(addr: u64) -> Option<Slot> {
    if addr >> 48 != TAG {
        return None;
    }
    let id = ((addr >> 24) & FIELD) as u32;
    let index = (addr & FIELD) as u32;
    Some(if id == 0 {
        Slot::Entry
    } else {
        Slot::Frame {
            id,
            inst: index.checked_sub(1),
        }
    })
}

/// One code object.
pub struct Code {
    pub qualname: String,
    pub filename: String,
    pub first_line: i32,
    linetable: Option<PyLineTable>,
}

impl std::fmt::Debug for Code {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Code")
            .field("qualname", &self.qualname)
            .field("filename", &self.filename)
            .field("first_line", &self.first_line)
            .finish_non_exhaustive()
    }
}

/// A parsed code map.
#[derive(Debug, Default)]
pub struct CodeMap {
    pub token: String,
    /// The minor version of the Python that wrote it.
    pub minor: i32,
    codes: HashMap<u32, Code>,
}

/// A Python frame, named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame<'a> {
    pub qualname: &'a str,
    pub filename: &'a str,
    /// `None` where the line table has no line for the instruction.
    pub line: Option<i32>,
}

impl CodeMap {
    /// Parse code-map text; `None` without its header, or with one from a
    /// Python the hook does not write for. Lines that do not parse are
    /// skipped, and so is a last line without its newline: the process was
    /// writing it, or ran out of disk, and a line cut short can still read
    /// as a whole one.
    pub fn parse(text: &str) -> Option<CodeMap> {
        let text = &text[..text.rfind('\n').map_or(0, |at| at + 1)];
        let mut lines = text.lines();
        let mut header = lines
            .next()?
            .strip_prefix("# systing-pycode 1 ")?
            .split(' ');
        let token = header.next()?.strip_prefix("token=")?;
        if !is_token(token) {
            return None;
        }
        let token = token.to_string();
        let minor: i32 = header
            .find_map(|f| f.strip_prefix("python=3."))?
            .parse()
            .ok()?;
        if minor < FIRST_MINOR {
            return None;
        }
        let codes = lines
            .filter_map(|l| {
                let mut f = l.split(' ');
                let id = u32::from_str_radix(f.next()?, 16).ok()?;
                let first_line = f.next()?.parse().ok()?;
                let qualname = text_of(f.next()?, MAX_NAME_CHARS)?;
                let filename = text_of(f.next()?, MAX_FILE_CHARS)?;
                let linetable = match f.next()? {
                    "-" => None,
                    hex if hex.len() > 2 * MAX_LINETABLE => return None,
                    hex => Some(PyLineTable::from_data(bytes_of(hex)?, first_line, 3, minor)),
                };
                (id != 0 && id != UNKNOWN_ID).then_some((
                    id,
                    Code {
                        qualname,
                        filename,
                        first_line,
                        linetable,
                    },
                ))
            })
            .collect();
        Some(CodeMap {
            token,
            minor,
            codes,
        })
    }

    pub fn len(&self) -> usize {
        self.codes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.codes.is_empty()
    }

    /// The frame a slot stands for, `None` for an id the map does not have.
    pub fn frame(&self, id: u32, inst: Option<u32>) -> Option<Frame<'_>> {
        let code = self.codes.get(&id)?;
        let line = match (inst, &code.linetable) {
            // Not started: the line the function starts on.
            (None, _) => Some(code.first_line),
            (Some(inst), Some(table)) => i32::try_from(inst)
                .ok()
                .map(|inst| table.get_line_for_inst_index(inst))
                .filter(|&l| l > 0),
            (Some(_), None) => None,
        };
        Some(Frame {
            qualname: &code.qualname,
            filename: &code.filename,
            line,
        })
    }
}

/// `<kind>:<hex>` as text of at most `max_chars` characters, `None` for more;
/// an unread str (`0:`) is empty. The text ends in frame names, which are
/// printed and drawn: a control character in it (a newline, an escape) is
/// replaced.
fn text_of(field: &str, max_chars: usize) -> Option<String> {
    let (kind, hex) = field.split_once(':')?;
    let width = match kind {
        "0" => return Some(String::new()),
        "1" => 1,
        "2" => 2,
        "4" => 4,
        _ => return None,
    };
    if hex.len() > 2 * width * max_chars {
        return None;
    }
    let raw = bytes_of(hex)?;
    if raw.len() % width != 0 {
        return None;
    }
    Some(
        raw.chunks_exact(width)
            .map(|c| {
                let mut v = [0u8; 4];
                v[..width].copy_from_slice(c);
                // A str may hold a lone surrogate; a Rust one may not.
                match char::from_u32(u32::from_le_bytes(v)) {
                    Some(c) if !c.is_control() => c,
                    _ => char::REPLACEMENT_CHARACTER,
                }
            })
            .collect(),
    )
}

fn bytes_of(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) || !hex.is_ascii() {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

/// The token of the code map a dump's process wrote, from the name of the
/// mapping its hook made.
pub fn token_of(maps: &Maps) -> Option<&str> {
    maps.mappings().iter().find_map(|m| {
        let name = &m.path[m.path.find(MAPPING)? + MAPPING.len()..];
        let token = name.split(' ').next()?;
        is_token(token).then_some(token)
    })
}

/// Whether `s` can be a token: the hook writes sixteen hex digits. It ends
/// in a file name and in what is printed.
fn is_token(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Where the code map `token` names may be, in order: `dir`
/// (--perf-map-dir), then beside the snapshot, where the hook writes it.
pub fn places(pid: i32, token: &str, snapshot: &Path, dir: Option<&Path>) -> Vec<PathBuf> {
    let name = format!("pycode-{pid}-{token}.map");
    [
        dir.map(|d| d.join(&name)),
        snapshot.parent().map(|p| p.join(&name)),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// The [`places`] that exist. Beneath a [`Root`] nothing filters them: each
/// place is tried with [`read_in`], and one that holds nothing falls through
/// to the next.
pub fn candidates(pid: i32, token: &str, snapshot: &Path, dir: Option<&Path>) -> Vec<PathBuf> {
    places(pid, token, snapshot, dir)
        .into_iter()
        .filter(|p| p.symlink_metadata().is_ok())
        .collect()
}

/// Read the code map at `path`, under the rules a perf map is read by
/// ([`crate::perfmap::read_text_in`]). A map whose token is not `token` is
/// another process's.
pub fn read(path: &Path, token: &str) -> std::io::Result<CodeMap> {
    read_in(None, path, token, None)
}

/// As [`read`], with `path` beneath `root` when there is one, `dump_owner`
/// being the user who owns the dump the map is for.
pub fn read_in(
    root: Option<&Root>,
    path: &Path,
    token: &str,
    dump_owner: Option<u32>,
) -> std::io::Result<CodeMap> {
    use std::io::{Error, ErrorKind};
    let text = crate::perfmap::read_text_in(root, path, dump_owner)?;
    let map = CodeMap::parse(&text)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "not a code map"))?;
    if map.token != token {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("its token is not the dump's, {token}"),
        ));
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    // def leak():            <- line 8
    //     for _ in range(n): <- line 9
    //         keep.append(bytearray(65536))  <- line 10
    const MAP: &str = "\
# systing-pycode 1 token=dead0a9f94b985ac pid=12 python=3.13
1 8 1:6c65616b 1:2f7372762f6170702e7079 8000dc0d1290318e588801dc080c8f0b890b94499869d31428d60829f203000e16
2 3 2:e565 1:2f7372762f63616621e92e7079 -
3 1 0: 0: -
garbage
4 1 1:zz 1:00 -
";

    #[test]
    fn slots_are_told_from_addresses() {
        assert_eq!(slot(0x7f4b_c744_6b86), None);
        assert_eq!(slot(0xffff_ffff_8100_0000), None);
        assert_eq!(slot(0x5059_0000_0000_0000), Some(Slot::Entry));
        assert_eq!(
            slot(0x5059_0000_0500_0083),
            Some(Slot::Frame {
                id: 5,
                inst: Some(0x82)
            })
        );
        assert_eq!(
            slot(0x5059_0000_0500_0000),
            Some(Slot::Frame { id: 5, inst: None })
        );
    }

    #[test]
    fn a_frame_has_its_name_file_and_line() {
        let m = CodeMap::parse(MAP).unwrap();
        assert_eq!(
            (m.token.as_str(), m.minor, m.len()),
            ("dead0a9f94b985ac", 13, 3)
        );
        let f = m.frame(1, None).unwrap();
        assert_eq!(
            (f.qualname, f.filename, f.line),
            ("leak", "/srv/app.py", Some(8))
        );
        // The table's first entry is the function's first line.
        assert_eq!(m.frame(1, Some(0)).unwrap().line, Some(8));
        // Far past the last instruction there is no line.
        assert_eq!(m.frame(1, Some(100_000)).unwrap().line, None);
        assert!(m.frame(9, None).is_none());
    }

    #[test]
    fn names_are_decoded_from_their_stored_width() {
        let m = CodeMap::parse(MAP).unwrap();
        let f = m.frame(2, Some(0)).unwrap();
        // UTF-16 for the name, Latin-1 for the file; no line table, no line.
        assert_eq!(
            (f.qualname, f.filename, f.line),
            ("\u{65e5}", "/srv/caf!\u{e9}.py", None)
        );
        // A str the hook could not read is empty, not an error.
        assert_eq!(m.frame(3, None).unwrap().qualname, "");
    }

    #[test]
    fn a_name_is_printed_without_its_control_characters() {
        // "a\nb\x1b[31m\0" as a name, "/srv/\u{202e}.py" as a file.
        let m = CodeMap::parse(
            "# systing-pycode 1 token=ab pid=1 python=3.13\n\
             1 1 1:610a621b5b33316d00 2:2f007300720076002f002e202e0070007900 -\n",
        )
        .unwrap();
        let f = m.frame(1, None).unwrap();
        assert_eq!(f.qualname, "a\u{fffd}b\u{fffd}[31m\u{fffd}");
        assert!(!f.qualname.chars().any(char::is_control));
        // Not a control character: a file may be named in any script.
        assert_eq!(f.filename, "/srv/\u{202e}.py");
    }

    #[test]
    fn a_line_longer_than_the_hook_writes_is_not_a_code_object() {
        let head = "# systing-pycode 1 token=ab pid=1 python=3.13\n";
        let name = |chars: usize| format!("{head}1 1 1:{} 1:61 -\n", "61".repeat(chars));
        assert_eq!(CodeMap::parse(&name(MAX_NAME_CHARS)).unwrap().len(), 1);
        assert_eq!(CodeMap::parse(&name(MAX_NAME_CHARS + 1)).unwrap().len(), 0);
        let file = |chars: usize| format!("{head}1 1 1:61 4:{} -\n", "61000000".repeat(chars));
        assert_eq!(CodeMap::parse(&file(MAX_FILE_CHARS)).unwrap().len(), 1);
        assert_eq!(CodeMap::parse(&file(MAX_FILE_CHARS + 1)).unwrap().len(), 0);
        let table = |bytes: usize| format!("{head}1 1 1:61 1:61 {}\n", "80".repeat(bytes));
        assert_eq!(CodeMap::parse(&table(MAX_LINETABLE)).unwrap().len(), 1);
        assert_eq!(CodeMap::parse(&table(MAX_LINETABLE + 1)).unwrap().len(), 0);
    }

    #[test]
    fn a_map_from_a_python_the_hook_does_not_write_for_is_refused() {
        // 3.10 has another line table, read another way: the hook never
        // wrote one, so a map that says so is not the hook's.
        for minor in [9, 10, 11] {
            let text =
                format!("# systing-pycode 1 token=ab pid=1 python=3.{minor}\n1 1 1:61 1:61 0a7f\n");
            assert!(CodeMap::parse(&text).is_none(), "3.{minor}");
        }
        let text = "# systing-pycode 1 token=ab pid=1 python=3.12\n1 1 1:61 1:61 0a7f\n";
        assert_eq!(CodeMap::parse(text).unwrap().len(), 1);
    }

    #[test]
    fn a_line_cut_short_is_not_a_code_object() {
        // Cut inside the line table, at a length that still reads as hex.
        let cut = &MAP[..MAP.find("8e588801").unwrap()];
        assert!(!cut.ends_with('\n'));
        let m = CodeMap::parse(cut).unwrap();
        assert_eq!(m.len(), 0);
        assert!(CodeMap::parse("# systing-pycode 1 token=ab pid=1 python=3.13").is_none());
    }

    #[test]
    fn a_file_without_the_header_is_not_a_code_map() {
        assert!(CodeMap::parse("7f75cb8c74e0 8 py::f:/srv/app.py\n").is_none());
        assert!(CodeMap::parse("").is_none());
    }

    #[test]
    fn a_header_whose_token_is_not_hex_is_not_a_code_map() {
        // The token is printed and compared: it is hex digits or the file
        // is not the hook's.
        for token in ["", "\u{1b}[31mdead", "../../etc", &"a".repeat(65)] {
            let text = format!("# systing-pycode 1 token={token} pid=1 python=3.13\n");
            assert!(CodeMap::parse(&text).is_none(), "{token:?}");
        }
        let text = "# systing-pycode 1 token=dead0a9f94b985ac pid=1 python=3.13\n";
        assert!(CodeMap::parse(text).is_some());
    }

    #[test]
    fn the_token_comes_from_the_dumps_maps() {
        let maps = Maps::parse(
            "\
7fe5b7d00000-7fe5b8200000 rw-p 00000000 00:01 94950                      /memfd:systing-pycode-dead0a9f94b985ac (deleted)
7ffd1c3f0000-7ffd1c3f2000 r-xp 00000000 00:00 0                          [vdso]
",
        );
        assert_eq!(token_of(&maps), Some("dead0a9f94b985ac"));
        assert_eq!(token_of(&Maps::parse("")), None);
    }

    #[test]
    fn a_map_with_another_token_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("pycode-12-dead0a9f94b985ac.map");
        std::fs::write(&p, MAP).unwrap();
        assert!(read(&p, "dead0a9f94b985ac").is_ok());
        assert!(read(&p, "0000000000000000").is_err());
        let snap = d.path().join("jeprof.12.0.m0.heap");
        assert_eq!(candidates(12, "dead0a9f94b985ac", &snap, None), vec![p]);
        assert!(candidates(13, "dead0a9f94b985ac", &snap, None).is_empty());
    }

    #[test]
    fn a_map_in_the_given_directory_comes_first() {
        let beside = tempfile::tempdir().unwrap();
        let given = tempfile::tempdir().unwrap();
        let name = "pycode-12-dead0a9f94b985ac.map";
        let snap = beside.path().join("jeprof.12.0.m0.heap");
        // Nowhere yet.
        assert!(candidates(12, "dead0a9f94b985ac", &snap, Some(given.path())).is_empty());
        std::fs::write(beside.path().join(name), MAP).unwrap();
        assert_eq!(
            candidates(12, "dead0a9f94b985ac", &snap, Some(given.path())),
            vec![beside.path().join(name)]
        );
        std::fs::write(given.path().join(name), MAP).unwrap();
        assert_eq!(
            candidates(12, "dead0a9f94b985ac", &snap, Some(given.path())),
            vec![given.path().join(name), beside.path().join(name)]
        );
    }
}
