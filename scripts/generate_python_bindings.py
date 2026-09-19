#!/usr/bin/env python3
"""Generate Rust offset constants from CPython headers.

Compiles a C program against CPython headers to compute offsetof() and sizeof()
values, then outputs minimal Rust files containing only `pub const` declarations.

Requires:
  - gcc
  - A CPython git repo (cloned or worktree), or an installed CPython with its
    headers (<prefix>/include/python3.X[t]/, internal/ included)

Usage:
  python3 scripts/generate_python_bindings.py --cpython ~/src/cpython --all
  python3 scripts/generate_python_bindings.py --cpython ~/src/cpython v3.13.0
  python3 scripts/generate_python_bindings.py --cpython ~/src/cpython --free-threaded v3.14.0
  python3 scripts/generate_python_bindings.py --installed /usr --free-threaded v3.14.0
"""
import argparse
import os
import subprocess
import sys
import tempfile

VERSIONS = ["v3.8.0", "v3.9.0", "v3.10.0", "v3.11.0", "v3.12.0", "v3.13.0", "v3.14.0"]


def version_tuple(version_str):
    """Parse 'v3.X.Y' into (3, X, Y)."""
    v = version_str.lstrip("v")
    parts = v.split(".")
    return tuple(int(p) for p in parts)


def run(cmd, **kwargs):
    """Run a command, raising on failure."""
    print(f"  $ {cmd}")
    result = subprocess.run(cmd, shell=True, **kwargs)
    if result.returncode != 0:
        raise RuntimeError(f"Command failed with exit code {result.returncode}: {cmd}")
    return result


def checkout_and_configure(cpython_path, version, free_threaded):
    """Check out the CPython tag and run ./configure to generate pyconfig.h."""
    run(f"cd {cpython_path} && git checkout {version}", capture_output=True)
    # Clean up any stale pyconfig.h, then configure
    run(f"cd {cpython_path} && rm -f pyconfig.h", capture_output=True)
    install_prefix = os.path.abspath(os.path.join(cpython_path, f"build_{version}"))
    # --disable-gil defines Py_GIL_DISABLED in pyconfig.h
    flavour = " --disable-gil" if free_threaded else ""
    run(
        f"cd {cpython_path} && ./configure --prefix={install_prefix}{flavour} 2>&1 | tail -3",
    )


def installed_headers(prefix, version, free_threaded):
    """Return (root, include) for an installed CPython: its headers are in
    <prefix>/include/python3.X (python3.Xt for a free-threaded build), with
    pyconfig.h beside Python.h. The counterpart of (cpython_path, "Include")."""
    major, minor, micro = version_tuple(version)
    root = os.path.join(prefix, "include")
    include = f"python{major}.{minor}{'t' if free_threaded else ''}"
    patchlevel = os.path.join(root, include, "patchlevel.h")
    if not os.path.isfile(patchlevel):
        raise RuntimeError(f"No CPython headers in {os.path.join(root, include)}")
    with open(patchlevel) as f:
        found = [
            l.split()[2].strip('"') for l in f if l.startswith("#define PY_VERSION ")
        ]
    if found != [f"{major}.{minor}.{micro}"]:
        found = " ".join(found) or "of no known version"
        raise RuntimeError(f"{patchlevel} is CPython {found}, not {version}")
    return root, include


def get_offset_program(root, include, version, free_threaded=None):
    """Return a C program that prints all offset and sizeof constants.

    The headers are in <root>/<include>: "Include" in a CPython checkout.
    With free_threaded given, the program only compiles against headers of
    that build (True) or of the default one (False).

    Uses GCC nested-member offsetof extension: offsetof(type, a.b.c).
    All offsets needed by offsets.rs are computed here.
    """
    _, minor, _ = version_tuple(version)

    # Determine which internal headers exist for this version
    include_dir = os.path.join(root, include)
    internal = os.path.join(include_dir, "internal")
    internal_cpython = os.path.join(include_dir, "cpython")

    includes = [
        "#include <stddef.h>",
        "#include <stdio.h>",
        "#define Py_BUILD_CORE 1",
        f'#include "{include}/Python.h"',
    ]

    # frameobject.h exposes the internal frame struct
    if os.path.isfile(os.path.join(include_dir, "frameobject.h")):
        includes.append(f'#include "{include}/frameobject.h"')

    # Internal headers for nested struct access
    for hdr in [
        "pycore_pystate.h",
        "pystate.h",
        "pycore_runtime.h",
        "pycore_interp.h",
        "pycore_frame.h",
        "pycore_dict.h",
        "pycore_object.h",
        "pycore_moduleobject.h",
    ]:
        if os.path.isfile(os.path.join(internal, hdr)):
            includes.append(f'#include "{include}/internal/{hdr}"')

    # genobject.h for PyGenObject / PyCoroObject
    if os.path.isfile(os.path.join(internal_cpython, "genobject.h")):
        includes.append(f'#include "{include}/cpython/genobject.h"')
    elif os.path.isfile(os.path.join(include_dir, "genobject.h")):
        includes.append(f'#include "{include}/genobject.h"')

    # The other build's headers would give a module that is not what it says
    if free_threaded:
        includes += [
            "#ifndef Py_GIL_DISABLED",
            '#error "these are not the headers of a free-threaded build"',
            "#endif",
        ]
    elif free_threaded is not None:
        includes += [
            "#ifdef Py_GIL_DISABLED",
            '#error "these are the headers of a free-threaded build: use --free-threaded"',
            "#endif",
        ]

    body_lines = []
    emitted = set()

    def emit(const_name, expr):
        if const_name in emitted:
            return  # skip duplicate
        emitted.add(const_name)
        body_lines.append(
            f'    printf("pub const {const_name}: usize = %zu;\\n", {expr});'
        )

    # --- Common offsets (all versions) ---
    emit("PY_OBJECT_OB_TYPE", "offsetof(PyObject, ob_type)")
    emit("PY_TYPE_OBJECT_TP_NAME", "offsetof(PyTypeObject, tp_name)")
    emit("PY_ASCII_OBJECT_SIZE", "sizeof(PyASCIIObject)")
    emit("PY_TUPLE_OBJECT_OB_ITEM", "offsetof(PyTupleObject, ob_item)")
    emit("PY_CODE_OBJECT_CO_FLAGS", "offsetof(PyCodeObject, co_flags)")
    emit("PY_CODE_OBJECT_CO_FILENAME", "offsetof(PyCodeObject, co_filename)")
    emit("PY_CODE_OBJECT_CO_NAME", "offsetof(PyCodeObject, co_name)")

    # --- 3.9+ offsets ---
    if minor >= 9:
        emit("PY_VAR_OBJECT_OB_SIZE", "offsetof(PyVarObject, ob_size)")
        emit("PY_BYTES_OBJECT_OB_SVAL", "offsetof(PyBytesObject, ob_sval)")
        emit(
            "PY_CODE_OBJECT_CO_FIRSTLINENO",
            "offsetof(PyCodeObject, co_firstlineno)",
        )

    # --- 3.8-3.10: traditional frame ---
    if minor <= 10:
        emit("PY_THREAD_STATE_FRAME", "offsetof(PyThreadState, frame)")
        emit("PY_THREAD_STATE_THREAD", "offsetof(PyThreadState, thread_id)")

        # _frame struct (exposed via frameobject.h)
        # Use struct _frame directly since PyFrameObject may be a typedef
        emit("PY_FRAME_OBJECT_BACK", "offsetof(struct _frame, f_back)")
        emit("PY_FRAME_OBJECT_CODE", "offsetof(struct _frame, f_code)")
        emit("PY_FRAME_OBJECT_LOCALSPLUS", "offsetof(struct _frame, f_localsplus)")
        emit("PY_FRAME_OBJECT_GEN", "offsetof(struct _frame, f_gen)")
        emit("PY_CODE_OBJECT_CO_VARNAMES", "offsetof(PyCodeObject, co_varnames)")

    # --- 3.9-3.10: f_lasti ---
    if 9 <= minor <= 10:
        emit("PY_FRAME_OBJECT_LASTI", "offsetof(struct _frame, f_lasti)")

    # --- 3.10+: interp and linetable ---
    if minor >= 10:
        emit("PY_THREAD_STATE_INTERP", "offsetof(PyThreadState, interp)")
        emit(
            "PY_CODE_OBJECT_CO_LINETABLE", "offsetof(PyCodeObject, co_linetable)"
        )

    # --- 3.11-3.12: _PyCFrame ---
    if 11 <= minor <= 12:
        emit("PY_THREAD_STATE_CFRAME", "offsetof(PyThreadState, cframe)")
        emit("PY_THREAD_STATE_THREAD", "offsetof(PyThreadState, thread_id)")
        emit("PY_CFRAME_CURRENT_FRAME", "offsetof(_PyCFrame, current_frame)")

    # --- 3.13+: direct current_frame (no _PyCFrame indirection) ---
    if minor >= 13:
        emit(
            "PY_THREAD_STATE_CURRENT_FRAME",
            "offsetof(PyThreadState, current_frame)",
        )
        emit("PY_THREAD_STATE_THREAD", "offsetof(PyThreadState, thread_id)")

    # --- 3.11+: interpreter frame ---
    if minor >= 11:
        if minor >= 13:
            emit(
                "PY_INTERP_FRAME_CODE",
                "offsetof(_PyInterpreterFrame, f_executable)",
            )
        else:
            emit(
                "PY_INTERP_FRAME_CODE", "offsetof(_PyInterpreterFrame, f_code)"
            )
        emit(
            "PY_INTERP_FRAME_PREVIOUS",
            "offsetof(_PyInterpreterFrame, previous)",
        )
        emit(
            "PY_INTERP_FRAME_LOCALSPLUS",
            "offsetof(_PyInterpreterFrame, localsplus)",
        )
        if minor >= 13:
            emit(
                "PY_INTERP_FRAME_PREV_INSTR",
                "offsetof(_PyInterpreterFrame, instr_ptr)",
            )
        else:
            emit(
                "PY_INTERP_FRAME_PREV_INSTR",
                "offsetof(_PyInterpreterFrame, prev_instr)",
            )
        emit("PY_CODE_OBJECT_CO_QUALNAME", "offsetof(PyCodeObject, co_qualname)")

    # --- 3.12+: frame owner, code_adaptive, gen/coro ---
    if minor >= 12:
        emit(
            "PY_INTERP_FRAME_OWNER", "offsetof(_PyInterpreterFrame, owner)"
        )
        emit(
            "PY_CODE_OBJECT_CO_CODE_ADAPTIVE",
            "offsetof(PyCodeObject, co_code_adaptive)",
        )
        emit(
            "PY_CORO_OBJECT_CR_ORIGIN_OR_FINALIZER",
            "offsetof(PyCoroObject, cr_origin_or_finalizer)",
        )
        emit("PY_GEN_OBJECT_GI_IFRAME", "offsetof(PyGenObject, gi_iframe)")

    # --- Reading objects out of a process: dicts, instances, modules, ints,
    # strings (the thread-name lookup). 3.13+ for now; an older version needs
    # its own block here, as its dict and managed-dict layouts differ.
    if minor >= 13:
        # PyDictObject and what ma_keys / ma_values point to
        emit("PY_DICT_OBJECT_MA_USED", "offsetof(PyDictObject, ma_used)")
        emit("PY_DICT_OBJECT_MA_KEYS", "offsetof(PyDictObject, ma_keys)")
        emit("PY_DICT_OBJECT_MA_VALUES", "offsetof(PyDictObject, ma_values)")
        emit(
            "PY_DICT_KEYS_DK_LOG2_INDEX_BYTES",
            "offsetof(PyDictKeysObject, dk_log2_index_bytes)",
        )
        emit("PY_DICT_KEYS_DK_KIND", "offsetof(PyDictKeysObject, dk_kind)")
        emit("PY_DICT_KEYS_DK_NENTRIES", "offsetof(PyDictKeysObject, dk_nentries)")
        emit("PY_DICT_KEYS_DK_INDICES", "offsetof(PyDictKeysObject, dk_indices)")
        emit("PY_DICT_KEY_ENTRY_SIZE", "sizeof(PyDictKeyEntry)")
        emit("PY_DICT_KEY_ENTRY_ME_KEY", "offsetof(PyDictKeyEntry, me_key)")
        emit("PY_DICT_KEY_ENTRY_ME_VALUE", "offsetof(PyDictKeyEntry, me_value)")
        emit("PY_DICT_UNICODE_ENTRY_SIZE", "sizeof(PyDictUnicodeEntry)")
        emit("PY_DICT_UNICODE_ENTRY_ME_KEY", "offsetof(PyDictUnicodeEntry, me_key)")
        emit(
            "PY_DICT_UNICODE_ENTRY_ME_VALUE",
            "offsetof(PyDictUnicodeEntry, me_value)",
        )
        emit("PY_DICT_VALUES_VALID", "offsetof(PyDictValues, valid)")
        emit("PY_DICT_VALUES_VALUES", "offsetof(PyDictValues, values)")

        # An instance's attributes: the type says where they are
        emit("PY_TYPE_OBJECT_TP_BASICSIZE", "offsetof(PyTypeObject, tp_basicsize)")
        emit("PY_TYPE_OBJECT_TP_FLAGS", "offsetof(PyTypeObject, tp_flags)")
        emit("PY_TYPE_OBJECT_TP_DICTOFFSET", "offsetof(PyTypeObject, tp_dictoffset)")
        emit(
            "PY_HEAP_TYPE_OBJECT_HT_CACHED_KEYS",
            "offsetof(PyHeapTypeObject, ht_cached_keys)",
        )
        # Bytes ahead of the object at which its managed dict pointer sits
        emit("PY_OBJECT_MANAGED_DICT_BEFORE", "(size_t)(-(MANAGED_DICT_OFFSET))")

        emit("PY_MODULE_OBJECT_MD_DICT", "offsetof(PyModuleObject, md_dict)")

        emit("PY_LONG_OBJECT_LV_TAG", "offsetof(PyLongObject, long_value.lv_tag)")
        emit("PY_LONG_OBJECT_OB_DIGIT", "offsetof(PyLongObject, long_value.ob_digit)")

        emit("PY_ASCII_OBJECT_LENGTH", "offsetof(PyASCIIObject, length)")
        emit("PY_ASCII_OBJECT_STATE", "offsetof(PyASCIIObject, state)")
        emit("PY_COMPACT_UNICODE_OBJECT_SIZE", "sizeof(PyCompactUnicodeObject)")

        # _Py_DebugOffsets, the table at the start of _PyRuntime that a process
        # publishes for readers like this one (3.13+). PyInterpreterState grows
        # in patch releases (imports.modules is 24 bytes further in 3.14.6 than
        # in 3.14.0), so the two offsets that lead to sys.modules are read from
        # the process's own table, whose layout a minor version keeps: what is
        # generated is where they are in it.
        emit("PYRUNTIME_DEBUG_OFFSETS_OFFSET", "offsetof(_PyRuntimeState, debug_offsets)")
        # How a reader knows the table, its Python, and which build it is of:
        # free_threaded is non-zero in a free-threaded one
        emit("PY_DEBUG_OFFSETS_COOKIE", "offsetof(_Py_DebugOffsets, cookie)")
        emit("PY_DEBUG_OFFSETS_VERSION", "offsetof(_Py_DebugOffsets, version)")
        emit(
            "PY_DEBUG_OFFSETS_FREE_THREADED",
            "offsetof(_Py_DebugOffsets, free_threaded)",
        )
        emit(
            "PY_DEBUG_OFFSETS_RUNTIME_INTERPRETERS_HEAD",
            "offsetof(_Py_DebugOffsets, runtime_state.interpreters_head)",
        )
        emit(
            "PY_DEBUG_OFFSETS_INTERP_IMPORTS_MODULES",
            "offsetof(_Py_DebugOffsets, interpreter_state.imports_modules)",
        )

    # --- _PyRuntimeState / PyInterpreterState compound offsets ---

    # _PyRuntimeState TLS key
    if minor <= 11:
        emit(
            "PYRUNTIME_TLS_KEY_OFFSET",
            "offsetof(_PyRuntimeState, gilstate.autoTSSkey._key)",
        )
        emit(
            "PYRUNTIME_TSTATE_CURRENT_OFFSET",
            "offsetof(_PyRuntimeState, gilstate.tstate_current)",
        )
        emit(
            "PYRUNTIME_GIL_LOCKED_OFFSET",
            "offsetof(_PyRuntimeState, ceval.gil.locked)",
        )
        emit(
            "PYRUNTIME_GIL_LAST_HOLDER_OFFSET",
            "offsetof(_PyRuntimeState, ceval.gil.last_holder)",
        )
    elif minor == 12:
        emit(
            "PYRUNTIME_TLS_KEY_OFFSET",
            "offsetof(_PyRuntimeState, autoTSSkey._key)",
        )
    else:  # 3.13+
        emit(
            "PYRUNTIME_TLS_KEY_OFFSET",
            "offsetof(_PyRuntimeState, autoTSSkey._key)",
        )
        emit(
            "PYRUNTIME_INTERPRETERS_HEAD_OFFSET",
            "offsetof(_PyRuntimeState, interpreters.head)",
        )
        # The list that starts at head is newest first: with a subinterpreter
        # alive, head is not the interpreter the program started in. main is.
        emit(
            "PYRUNTIME_INTERPRETERS_MAIN_OFFSET",
            "offsetof(_PyRuntimeState, interpreters.main)",
        )

    # PyInterpreterState modules
    if 10 <= minor <= 11:
        emit("PYINTERP_MODULES_OFFSET", "offsetof(PyInterpreterState, modules)")
    elif minor >= 12:
        emit(
            "PYINTERP_MODULES_OFFSET",
            "offsetof(PyInterpreterState, imports.modules)",
        )

    # 3.13: GIL in interpreter state
    if minor >= 13:
        emit(
            "PYINTERP_GIL_LOCKED_OFFSET",
            "offsetof(PyInterpreterState, _gil.locked)",
        )
        emit(
            "PYINTERP_GIL_LAST_HOLDER_OFFSET",
            "offsetof(PyInterpreterState, _gil.last_holder)",
        )

    body = "\n".join(body_lines)
    includes_str = "\n".join(includes)

    program = f"""{includes_str}

int main(int argc, const char *argv[]) {{
{body}
    return 0;
}}
"""
    return program


def compile_and_run_offset_program(root, include, version, free_threaded=None):
    """Compile and run the offset C program, return output lines."""
    program = get_offset_program(root, include, version, free_threaded)

    with tempfile.TemporaryDirectory() as tmpdir:
        src = os.path.join(tmpdir, "offsets.c")
        exe = os.path.join(tmpdir, "offsets")
        with open(src, "w") as f:
            f.write(program)

        try:
            run(
                f"gcc {src} -I {root} -I {root}/{include} "
                f"-I {root}/{include}/internal -o {exe}",
                capture_output=True,
            )
        except RuntimeError:
            # Some versions need different include structure; try with -w to suppress warnings
            run(
                f"gcc -w {src} -I {root} -I {root}/{include} "
                f"-I {root}/{include}/internal -o {exe}",
            )

        result = subprocess.run(exe, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"Offset program failed: {result.stderr}")
        return result.stdout.strip().split("\n")


def group_constants(lines):
    """Group constant lines by section based on naming patterns.

    Returns a list of (section_comment, [lines]) tuples.
    """
    sections = []
    # Define section groupings by constant name prefix
    section_map = [
        ("// PyObject", ["PY_OBJECT_"]),
        ("// PyTypeObject", ["PY_TYPE_OBJECT_"]),
        ("// PyVarObject", ["PY_VAR_OBJECT_"]),
        ("// PyASCIIObject", ["PY_ASCII_OBJECT_"]),
        ("// PyCompactUnicodeObject", ["PY_COMPACT_UNICODE_OBJECT_"]),
        ("// PyHeapTypeObject", ["PY_HEAP_TYPE_OBJECT_"]),
        ("// PyLongObject", ["PY_LONG_OBJECT_"]),
        ("// PyModuleObject", ["PY_MODULE_OBJECT_"]),
        (
            "// PyDictObject, PyDictKeysObject, its entries, PyDictValues",
            ["PY_DICT_"],
        ),
        ("// _Py_DebugOffsets", ["PY_DEBUG_OFFSETS_"]),
        ("// PyTupleObject", ["PY_TUPLE_OBJECT_"]),
        ("// PyBytesObject", ["PY_BYTES_OBJECT_"]),
        ("// PyThreadState", ["PY_THREAD_STATE_"]),
        ("// _PyCFrame", ["PY_CFRAME_"]),
        ("// _PyInterpreterFrame", ["PY_INTERP_FRAME_"]),
        ("// PyFrameObject (via _frame)", ["PY_FRAME_OBJECT_"]),
        ("// PyCodeObject", ["PY_CODE_OBJECT_"]),
        ("// PyCoroObject / PyGenObject", ["PY_CORO_OBJECT_", "PY_GEN_OBJECT_"]),
        (
            "// _PyRuntimeState / PyInterpreterState compound offsets",
            ["PYRUNTIME_", "PYINTERP_"],
        ),
    ]

    used = set()
    for comment, prefixes in section_map:
        section_lines = []
        for line in lines:
            if any(f"pub const {p}" in line for p in prefixes):
                section_lines.append(line)
                used.add(line)
        if section_lines:
            sections.append((comment, section_lines))

    # Any remaining lines
    remaining = [l for l in lines if l not in used and l.strip()]
    if remaining:
        sections.append(("// Other offsets", remaining))

    return sections


def write_binding_file(cpython_path, installed, free_threaded, version, output_dir):
    """Generate and write the offset constants file for a Python version."""
    major, minor, micro = version_tuple(version)
    if free_threaded and minor < 13:
        raise RuntimeError(f"CPython {version} has no free-threaded build")
    # The "t" of the free-threaded ABI tag (python3.14t, cpython-314t)
    mod_name = f"v{major}_{minor}_{micro}{'t' if free_threaded else ''}"
    output_path = os.path.join(output_dir, f"{mod_name}.rs")
    flavour = " --free-threaded" if free_threaded else ""
    build = " (free-threaded)" if free_threaded else ""

    print(f"\n{'='*60}")
    print(f"Generating offset constants for Python {version}{build}")
    print(f"{'='*60}")

    # Step 1: Checkout and configure, or find the installed headers
    if installed is not None:
        root, include = installed_headers(installed, version, free_threaded)
        source = "--installed <prefix>"
    else:
        checkout_and_configure(cpython_path, version, free_threaded)
        root, include = cpython_path, "Include"
        source = "--cpython <path>"

    # Step 2: Compile and run offset program. A default build from a checkout
    # is configured here, so its headers need no check.
    check_build = free_threaded if installed is not None or free_threaded else None
    offset_lines = compile_and_run_offset_program(root, include, version, check_build)

    # Step 3: Write output file with grouped sections
    sections = group_constants(offset_lines)

    with open(output_path, "w") as f:
        f.write(f"// Auto-generated offset constants for CPython {version}{build}\n")
        f.write(f"// Generated by scripts/generate_python_bindings.py\n")
        f.write(f"// Target: x86_64-unknown-linux-gnu\n")
        f.write(f"//\n")
        f.write(f"// DO NOT EDIT - regenerate with:\n")
        f.write(
            f"//   python3 scripts/generate_python_bindings.py {source}{flavour} {version}\n"
        )

        for comment, lines in sections:
            f.write(f"\n{comment}\n")
            for line in lines:
                f.write(f"{line}\n")

    print(f"  -> Written to {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Generate Python offset constants from CPython headers for systing pystacks",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--cpython",
        type=str,
        help="Path to CPython git repo",
    )
    source.add_argument(
        "--installed",
        type=str,
        help="Prefix of an installed CPython of the given version, to use its "
        "headers (<prefix>/include/python3.X[t]/) instead of a checkout",
    )
    parser.add_argument(
        "--free-threaded",
        action="store_true",
        help="Generate for the free-threaded build (--disable-gil, 3.13+): "
        "a separate ABI, written to a module with a 't' suffix",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "src",
            "pystacks",
            "bindings",
        ),
        help="Output directory for offset constant files",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Generate bindings for all supported versions",
    )
    parser.add_argument(
        "versions",
        nargs="*",
        help=f"CPython version tags to generate (e.g. v3.13.0). Supported: {', '.join(VERSIONS)}",
    )

    args = parser.parse_args()

    if args.cpython is not None and not os.path.isdir(args.cpython):
        print(f"Error: CPython directory '{args.cpython}' does not exist")
        sys.exit(1)

    if args.cpython is not None and not os.path.isdir(os.path.join(args.cpython, ".git")):
        print(f"Error: '{args.cpython}' is not a git repository")
        sys.exit(1)

    versions = VERSIONS if args.all else args.versions
    if args.all and args.free_threaded:
        versions = [v for v in versions if version_tuple(v)[1] >= 13]
    if not versions:
        print("Error: specify versions or --all")
        parser.print_help()
        sys.exit(1)

    os.makedirs(args.output, exist_ok=True)

    for version in versions:
        if version not in VERSIONS:
            print(f"Warning: {version} is not in the known list {VERSIONS}")
        write_binding_file(
            args.cpython, args.installed, args.free_threaded, version, args.output
        )

    print(f"\nDone! Generated {len(versions)} offset constant files in {args.output}")


if __name__ == "__main__":
    main()
