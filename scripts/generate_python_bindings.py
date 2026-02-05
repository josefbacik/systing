#!/usr/bin/env python3
"""Generate Rust offset constants from CPython headers.

Compiles a C program against CPython headers to compute offsetof() and sizeof()
values, then outputs minimal Rust files containing only `pub const` declarations.

Requires:
  - gcc
  - A CPython git repo (cloned or worktree)

Usage:
  python3 scripts/generate_python_bindings.py --cpython ~/src/cpython --all
  python3 scripts/generate_python_bindings.py --cpython ~/src/cpython v3.13.0
"""
import argparse
import os
import subprocess
import sys
import tempfile

VERSIONS = ["v3.8.0", "v3.9.0", "v3.10.0", "v3.11.0", "v3.12.0", "v3.13.0"]


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


def checkout_and_configure(cpython_path, version):
    """Check out the CPython tag and run ./configure to generate pyconfig.h."""
    run(f"cd {cpython_path} && git checkout {version}", capture_output=True)
    # Clean up any stale pyconfig.h, then configure
    run(f"cd {cpython_path} && rm -f pyconfig.h", capture_output=True)
    install_prefix = os.path.abspath(os.path.join(cpython_path, f"build_{version}"))
    run(
        f"cd {cpython_path} && ./configure --prefix={install_prefix} 2>&1 | tail -3",
    )


def get_offset_program(cpython_path, version):
    """Return a C program that prints all offset and sizeof constants.

    Uses GCC nested-member offsetof extension: offsetof(type, a.b.c).
    All offsets needed by offsets.rs are computed here.
    """
    _, minor, _ = version_tuple(version)

    # Determine which internal headers exist for this version
    include_dir = os.path.join(cpython_path, "Include")
    internal = os.path.join(include_dir, "internal")
    internal_cpython = os.path.join(include_dir, "cpython")

    includes = [
        "#include <stddef.h>",
        "#include <stdio.h>",
        "#define Py_BUILD_CORE 1",
        '#include "Include/Python.h"',
    ]

    # frameobject.h exposes the internal frame struct
    if os.path.isfile(os.path.join(include_dir, "frameobject.h")):
        includes.append('#include "Include/frameobject.h"')

    # Internal headers for nested struct access
    for hdr in [
        "pycore_pystate.h",
        "pystate.h",
        "pycore_runtime.h",
        "pycore_interp.h",
        "pycore_frame.h",
        "pycore_dict.h",
    ]:
        if os.path.isfile(os.path.join(internal, hdr)):
            includes.append(f'#include "Include/internal/{hdr}"')

    # genobject.h for PyGenObject / PyCoroObject
    if os.path.isfile(os.path.join(internal_cpython, "genobject.h")):
        includes.append('#include "Include/cpython/genobject.h"')
    elif os.path.isfile(os.path.join(include_dir, "genobject.h")):
        includes.append('#include "Include/genobject.h"')

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


def compile_and_run_offset_program(cpython_path, version):
    """Compile and run the offset C program, return output lines."""
    program = get_offset_program(cpython_path, version)

    with tempfile.TemporaryDirectory() as tmpdir:
        src = os.path.join(tmpdir, "offsets.c")
        exe = os.path.join(tmpdir, "offsets")
        with open(src, "w") as f:
            f.write(program)

        try:
            run(
                f"gcc {src} -I {cpython_path} -I {cpython_path}/Include "
                f"-I {cpython_path}/Include/internal -o {exe}",
                capture_output=True,
            )
        except RuntimeError:
            # Some versions need different include structure; try with -w to suppress warnings
            run(
                f"gcc -w {src} -I {cpython_path} -I {cpython_path}/Include "
                f"-I {cpython_path}/Include/internal -o {exe}",
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


def write_binding_file(cpython_path, version, output_dir):
    """Generate and write the offset constants file for a Python version."""
    major, minor, micro = version_tuple(version)
    mod_name = f"v{major}_{minor}_{micro}"
    output_path = os.path.join(output_dir, f"{mod_name}.rs")

    print(f"\n{'='*60}")
    print(f"Generating offset constants for Python {version}")
    print(f"{'='*60}")

    # Step 1: Checkout and configure
    checkout_and_configure(cpython_path, version)

    # Step 2: Compile and run offset program
    offset_lines = compile_and_run_offset_program(cpython_path, version)

    # Step 3: Write output file with grouped sections
    sections = group_constants(offset_lines)

    with open(output_path, "w") as f:
        f.write(f"// Auto-generated offset constants for CPython {version}\n")
        f.write(f"// Generated by scripts/generate_python_bindings.py\n")
        f.write(f"// Target: x86_64-unknown-linux-gnu\n")
        f.write(f"//\n")
        f.write(f"// DO NOT EDIT - regenerate with:\n")
        f.write(
            f"//   python3 scripts/generate_python_bindings.py --cpython <path> {version}\n"
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
    parser.add_argument(
        "--cpython",
        type=str,
        required=True,
        help="Path to CPython git repo",
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

    if not os.path.isdir(args.cpython):
        print(f"Error: CPython directory '{args.cpython}' does not exist")
        sys.exit(1)

    if not os.path.isdir(os.path.join(args.cpython, ".git")):
        print(f"Error: '{args.cpython}' is not a git repository")
        sys.exit(1)

    versions = VERSIONS if args.all else args.versions
    if not versions:
        print("Error: specify versions or --all")
        parser.print_help()
        sys.exit(1)

    os.makedirs(args.output, exist_ok=True)

    for version in versions:
        if version not in VERSIONS:
            print(f"Warning: {version} is not in the known list {VERSIONS}")
        write_binding_file(args.cpython, version, args.output)

    print(f"\nDone! Generated {len(versions)} offset constant files in {args.output}")


if __name__ == "__main__":
    main()
