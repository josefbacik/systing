//! `hooks/py_offsets.h`: the CPython struct offsets the hooks' Python
//! backtrace reads, rendered from the offsets systing's own Python walker
//! uses ([`systing::pystacks::offsets`]) so the two cannot disagree.
//!
//! The header is checked in, because the hooks library is built with a C
//! compiler alone. The test below fails when it differs from what these
//! offsets render; `SYSTING_HEAP_UPDATE_OFFSETS=1 cargo test -p systing-heap
//! hook_offsets` rewrites it.

use std::fmt::Write;

use systing::pystacks::bindings;
use systing::pystacks::offsets::for_version;
use systing::pystacks::types::{OffsetConfig, BPF_LIB_DEFAULT_FIELD_OFFSET};

/// The minor versions the Python backtrace supports.
const MINORS: [i32; 3] = [12, 13, 14];

/// What `OffsetConfig` has no fields for: a str's layout, and where a code
/// object says its traceable instructions start.
struct Extra {
    str_length: usize,
    str_state: usize,
    str_compact_size: usize,
    code_firsttraceable: usize,
}

macro_rules! extra {
    ($v:ident) => {
        Extra {
            str_length: bindings::$v::PY_ASCII_OBJECT_LENGTH,
            str_state: bindings::$v::PY_ASCII_OBJECT_STATE,
            str_compact_size: bindings::$v::PY_COMPACT_UNICODE_OBJECT_SIZE,
            code_firsttraceable: bindings::$v::PY_CODE_OBJECT_CO_FIRSTTRACEABLE,
        }
    };
}

fn extra(minor: i32) -> Extra {
    match minor {
        12 => extra!(v3_12_0),
        13 => extra!(v3_13_0),
        14 => extra!(v3_14_0),
        _ => unreachable!("not in MINORS"),
    }
}

/// The fields of `struct shh_py_offsets`, in order, for one version.
fn fields(minor: i32, c: &OffsetConfig, x: &Extra) -> Vec<(&'static str, usize)> {
    vec![
        ("minor", minor as usize),
        // PyThreadState: to the current frame in one hop (3.13+) or through
        // its _PyCFrame (3.12), as the BPF walker does.
        ("ts_frame", c.py_thread_state_cframe),
        ("cframe_current_frame", c.py_cframe_current_frame),
        // _PyInterpreterFrame
        ("frame_code", c.py_interpreter_frame_code),
        ("frame_previous", c.py_interpreter_frame_previous),
        ("frame_instr", c.py_interpreter_frame_prev_instr),
        ("frame_owner", c.py_frame_object_owner),
        // PyObject
        ("ob_type", c.py_object_type),
        // PyCodeObject
        ("code_firstlineno", c.py_code_object_firstlineno),
        ("code_filename", c.py_code_object_filename),
        ("code_qualname", c.py_code_object_qualname),
        ("code_linetable", c.py_code_object_linetable),
        ("code_adaptive", c.py_code_object_code_adaptive),
        ("code_firsttraceable", x.code_firsttraceable),
        // str
        ("str_length", x.str_length),
        ("str_state", x.str_state),
        ("str_ascii_size", c.string_data),
        ("str_compact_size", x.str_compact_size),
        // bytes
        ("bytes_size", c.py_var_object_size),
        ("bytes_data", c.py_bytes_object_data),
    ]
}

pub fn render() -> String {
    let versions: Vec<_> = MINORS
        .iter()
        .map(|&minor| {
            let c = for_version(3, minor).expect("a supported version");
            fields(minor, &c, &extra(minor))
        })
        .collect();

    let mut h = String::new();
    h.push_str(
        "\
/*
 * CPython struct offsets the Python backtrace reads, by minor version.
 *
 * Rendered from systing's pystacks offsets (heap/src/hook_offsets.rs): do not
 * edit. `cargo test -p systing-heap hook_offsets` fails when this file and
 * those offsets differ, and rewrites it when run with
 * SYSTING_HEAP_UPDATE_OFFSETS=1.
 */
#ifndef SYSTING_HEAP_PY_OFFSETS_H
#define SYSTING_HEAP_PY_OFFSETS_H

/* An offset this version does not have. */
",
    );
    writeln!(h, "#define SHH_PY_NO_OFFSET {BPF_LIB_DEFAULT_FIELD_OFFSET}").unwrap();
    h.push_str("\nstruct shh_py_offsets {\n");
    for (name, _) in &versions[0] {
        writeln!(h, "\tint {name};").unwrap();
    }
    h.push_str("};\n\nstatic const struct shh_py_offsets shh_py_offsets[] = {\n");
    for version in &versions {
        h.push_str("\t{\n");
        for (name, value) in version {
            if *value == BPF_LIB_DEFAULT_FIELD_OFFSET {
                writeln!(h, "\t\t.{name} = SHH_PY_NO_OFFSET,").unwrap();
            } else {
                writeln!(h, "\t\t.{name} = {value},").unwrap();
            }
        }
        h.push_str("\t},\n");
    }
    h.push_str("};\n\n#endif\n");
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/hooks/py_offsets.h");

    #[test]
    fn hook_offsets_header_matches_the_pystacks_offsets() {
        let rendered = render();
        if std::env::var_os("SYSTING_HEAP_UPDATE_OFFSETS").is_some_and(|v| !v.is_empty()) {
            std::fs::write(HEADER, &rendered).unwrap();
        }
        let checked_in = std::fs::read_to_string(HEADER).unwrap_or_default();
        assert!(
            checked_in == rendered,
            "{HEADER} is not what the pystacks offsets render; \
             rerun with SYSTING_HEAP_UPDATE_OFFSETS=1 to rewrite it"
        );
    }

    #[test]
    fn every_offset_the_walk_needs_is_there() {
        for minor in MINORS {
            let c = for_version(3, minor).unwrap();
            for (name, value) in fields(minor, &c, &extra(minor)) {
                // Only the second hop to the frame may be absent (3.13+).
                assert!(
                    value != BPF_LIB_DEFAULT_FIELD_OFFSET || name == "cframe_current_frame",
                    "3.{minor}: no {name}"
                );
            }
        }
    }
}
