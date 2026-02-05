#!/usr/bin/env python3
"""Generate bindgen-based Rust bindings from CPython headers.

Requires:
  - bindgen CLI (cargo install bindgen-cli)
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

# Types we need from CPython headers.
# py-spy's list plus PyGenObject, PyCoroObject for systing's pystacks.
COMMON_ALLOWLIST = [
    "PyInterpreterState",
    "PyFrameObject",
    "PyThreadState",
    "PyCodeObject",
    "PyVarObject",
    "PyBytesObject",
    "PyASCIIObject",
    "PyUnicodeObject",
    "PyCompactUnicodeObject",
    "PyTupleObject",
    "PyObject",
    "PyTypeObject",
    "PyGenObject",
    "PyCoroObject",
    "PyInterpreterFrame",
]

# Additional types needed for specific version ranges.
V311_PLUS_ALLOWLIST = [
    "_PyCFrame",
    "_PyInterpreterFrame",
]

V310_ALLOWLIST = [
    "CFrame",
    "_cframe",
]


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


def build_combined_header(cpython_path, version):
    """Create the combined header for bindgen."""
    major, minor, micro = version_tuple(version)
    include_dir = os.path.join(cpython_path, "Include")

    lines = [
        "// Auto-generated combined header for bindgen",
        "#define Py_BUILD_CORE 1",
        "",
        '#include "Include/Python.h"',
        "",
        "// Undo HAVE_STD_ATOMIC to avoid C11 atomics in older bindgen",
        "#undef HAVE_STD_ATOMIC",
        "",
    ]

    # frameobject.h exposes the internal frame struct
    if os.path.isfile(os.path.join(include_dir, "frameobject.h")):
        lines.append('#include "Include/frameobject.h"')

    # Internal headers vary by version
    internal = os.path.join(include_dir, "internal")
    internal_cpython = os.path.join(include_dir, "cpython")

    # pycore_interp.h / pycore_pystate.h
    for hdr in ["pycore_interp.h", "pycore_pystate.h", "pystate.h"]:
        path = os.path.join(internal, hdr)
        if os.path.isfile(path):
            lines.append(f'#include "Include/internal/{hdr}"')

    # pycore_frame.h (3.11+)
    if os.path.isfile(os.path.join(internal, "pycore_frame.h")):
        lines.append('#include "Include/internal/pycore_frame.h"')

    # pycore_dict.h
    if os.path.isfile(os.path.join(internal, "pycore_dict.h")):
        lines.append('#include "Include/internal/pycore_dict.h"')

    # genobject.h for PyGenObject / PyCoroObject
    # In 3.12+ the cpython/ subdir has the detailed struct
    if os.path.isfile(os.path.join(internal_cpython, "genobject.h")):
        lines.append('#include "Include/cpython/genobject.h"')
    elif os.path.isfile(os.path.join(include_dir, "genobject.h")):
        lines.append('#include "Include/genobject.h"')

    header_path = os.path.join(cpython_path, "bindgen_input.h")
    with open(header_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    return header_path


def get_allowlist_args(version):
    """Return bindgen --allowlist-type arguments for the version."""
    major, minor, micro = version_tuple(version)
    types = list(COMMON_ALLOWLIST)
    if minor >= 11:
        types.extend(V311_PLUS_ALLOWLIST)
    if minor == 10:
        types.extend(V310_ALLOWLIST)
    args = []
    for t in types:
        args.append(f"--allowlist-type {t}")
    return " ".join(args)


def run_bindgen(cpython_path, version):
    """Run bindgen to generate Rust bindings."""
    allowlist = get_allowlist_args(version)
    output_path = os.path.join(cpython_path, "bindgen_output.rs")

    cmd = (
        f"cd {cpython_path} && bindgen bindgen_input.h "
        f"-o bindgen_output.rs "
        f"--with-derive-default "
        f"--no-layout-tests --no-doc-comments "
        f"{allowlist} "
        f"-- -I . -I ./Include -I ./Include/internal "
        f"-target x86_64-unknown-linux-gnu"
    )
    run(cmd)
    return output_path


def get_compound_offset_program(cpython_path, version):
    """Return a C program that prints compound offset constants.

    These offsets require walking nested structs that bindgen may represent
    as opaque types (e.g. _PyRuntimeState internals).

    Uses GCC nested-member offsetof extension: offsetof(type, a.b.c).
    """
    _, minor, _ = version_tuple(version)

    # Determine which internal headers exist for this version
    internal = os.path.join(cpython_path, "Include", "internal")
    includes = [
        "#include <stddef.h>",
        "#include <stdio.h>",
        "#define Py_BUILD_CORE 1",
        '#include "Include/Python.h"',
    ]

    # Add internal headers needed for _PyRuntimeState and PyInterpreterState
    for hdr in [
        "pycore_pystate.h",
        "pystate.h",
        "pycore_runtime.h",
        "pycore_interp.h",
    ]:
        if os.path.isfile(os.path.join(internal, hdr)):
            includes.append(f'#include "Include/internal/{hdr}"')

    body_lines = []

    # --- _PyRuntimeState compound offsets ---

    if minor <= 11:
        # _PyRuntimeState.gilstate.autoTSSkey._key
        body_lines.append(
            '    printf("pub const PYRUNTIME_TLS_KEY_OFFSET: usize = %zu;\\n", '
            "offsetof(_PyRuntimeState, gilstate.autoTSSkey._key));"
        )
        # _PyRuntimeState.gilstate.tstate_current
        body_lines.append(
            '    printf("pub const PYRUNTIME_TSTATE_CURRENT_OFFSET: usize = %zu;\\n", '
            "offsetof(_PyRuntimeState, gilstate.tstate_current));"
        )
        # _PyRuntimeState.ceval.gil.locked
        body_lines.append(
            '    printf("pub const PYRUNTIME_GIL_LOCKED_OFFSET: usize = %zu;\\n", '
            "offsetof(_PyRuntimeState, ceval.gil.locked));"
        )
        # _PyRuntimeState.ceval.gil.last_holder
        body_lines.append(
            '    printf("pub const PYRUNTIME_GIL_LAST_HOLDER_OFFSET: usize = %zu;\\n", '
            "offsetof(_PyRuntimeState, ceval.gil.last_holder));"
        )

    if minor == 12:
        # 3.12: autoTSSkey moved to top-level of _PyRuntimeState
        body_lines.append(
            '    printf("pub const PYRUNTIME_TLS_KEY_OFFSET: usize = %zu;\\n", '
            "offsetof(_PyRuntimeState, autoTSSkey._key));"
        )

    if minor >= 13:
        # 3.13: autoTSSkey moved to top-level
        body_lines.append(
            '    printf("pub const PYRUNTIME_TLS_KEY_OFFSET: usize = %zu;\\n", '
            "offsetof(_PyRuntimeState, autoTSSkey._key));"
        )
        # 3.13: interpreters.head
        body_lines.append(
            '    printf("pub const PYRUNTIME_INTERPRETERS_HEAD_OFFSET: usize = %zu;\\n", '
            "offsetof(_PyRuntimeState, interpreters.head));"
        )

    # --- PyInterpreterState compound offsets ---

    if 10 <= minor <= 11:
        # 3.10-3.11: modules is a direct member
        body_lines.append(
            '    printf("pub const PYINTERP_MODULES_OFFSET: usize = %zu;\\n", '
            "offsetof(PyInterpreterState, modules));"
        )

    if minor >= 12:
        # 3.12+: modules moved into imports sub-struct
        body_lines.append(
            '    printf("pub const PYINTERP_MODULES_OFFSET: usize = %zu;\\n", '
            "offsetof(PyInterpreterState, imports.modules));"
        )

    if minor >= 13:
        # 3.13: GIL in interpreter state at _gil (direct embed, not via ceval pointer)
        body_lines.append(
            '    printf("pub const PYINTERP_GIL_LOCKED_OFFSET: usize = %zu;\\n", '
            "offsetof(PyInterpreterState, _gil.locked));"
        )
        body_lines.append(
            '    printf("pub const PYINTERP_GIL_LAST_HOLDER_OFFSET: usize = %zu;\\n", '
            "offsetof(PyInterpreterState, _gil.last_holder));"
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
    """Compile and run the compound offset C program, return output lines."""
    program = get_compound_offset_program(cpython_path, version)

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


def write_binding_file(cpython_path, version, output_dir):
    """Generate and write the complete binding file for a Python version."""
    major, minor, micro = version_tuple(version)
    mod_name = f"v{major}_{minor}_{micro}"
    output_path = os.path.join(output_dir, f"{mod_name}.rs")

    print(f"\n{'='*60}")
    print(f"Generating bindings for Python {version}")
    print(f"{'='*60}")

    # Step 1: Checkout and configure
    checkout_and_configure(cpython_path, version)

    # Step 2: Build combined header
    build_combined_header(cpython_path, version)

    # Step 3: Run bindgen
    run_bindgen(cpython_path, version)

    # Step 4: Get compound offsets
    try:
        offset_lines = compile_and_run_offset_program(cpython_path, version)
    except RuntimeError as e:
        print(f"WARNING: Failed to compute compound offsets: {e}")
        offset_lines = []

    # Step 5: Write output file
    bindgen_output = os.path.join(cpython_path, "bindgen_output.rs")
    with open(bindgen_output) as f:
        bindgen_rs = f.read()

    with open(output_path, "w") as f:
        f.write(f"// Auto-generated bindings for CPython {version}\n")
        f.write(f"// Generated by scripts/generate_python_bindings.py\n")
        f.write(f"// Target: x86_64-unknown-linux-gnu\n")
        f.write(f"//\n")
        f.write(f"// DO NOT EDIT - regenerate with:\n")
        f.write(
            f"//   python3 scripts/generate_python_bindings.py --cpython <path> {version}\n"
        )
        f.write("\n")
        f.write("#![allow(dead_code)]\n")
        f.write("#![allow(non_upper_case_globals)]\n")
        f.write("#![allow(non_camel_case_types)]\n")
        f.write("#![allow(non_snake_case)]\n")
        f.write("#![allow(clippy::useless_transmute)]\n")
        f.write("#![allow(clippy::default_trait_access)]\n")
        f.write("#![allow(clippy::cast_lossless)]\n")
        f.write("#![allow(clippy::trivially_copy_pass_by_ref)]\n")
        f.write("#![allow(clippy::upper_case_acronyms)]\n")
        f.write("#![allow(clippy::too_many_arguments)]\n")
        f.write("#![allow(clippy::missing_safety_doc)]\n")
        f.write("\n")
        f.write(bindgen_rs)
        f.write("\n")

        if offset_lines:
            f.write("// Compound offset constants computed from CPython internal structs.\n")
            f.write(
                "// These offsets involve nested structs that bindgen cannot resolve.\n"
            )
            for line in offset_lines:
                if line.strip():
                    f.write(f"{line}\n")

    print(f"  -> Written to {output_path}")

    # Cleanup generated files in cpython dir
    for fname in ["bindgen_input.h", "bindgen_output.rs"]:
        path = os.path.join(cpython_path, fname)
        if os.path.isfile(path):
            os.remove(path)


def main():
    parser = argparse.ArgumentParser(
        description="Generate Python bindings from CPython headers for systing pystacks",
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
        help="Output directory for binding files",
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

    print(f"\nDone! Generated {len(versions)} binding files in {args.output}")


if __name__ == "__main__":
    main()
