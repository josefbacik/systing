#!/bin/bash
# The python-function-trace end-to-end step, in a guest or on the native arm64 runner
# (.github/workflows/bpf-load-shapes.yml): run tests/python_function_trace.rs, as
# root on the guest kernel, and require the line the main case prints once every
# call of three processes was accounted for, so that a run that found no Python
# proves nothing and fails.
#
# The verdict travels in the FILE, as in vmtest-load-shapes.sh: a guest kernel
# without a virtio console makes the VM tool return 255 whatever the test did. The
# host side reads the `VNG-TEST-EXIT:<rc>` line.
#
# Usage (from vng's --exec, as root in the guest, or as root on the runner):
#   vmtest-python-function-trace-e2e.sh <test binary> <dir holding libduckdb.so> <output file>
set -u
BIN="$1"
LIBDUCKDB_DIR="$2"
OUT="$3"
RAW="$OUT.raw"

export LD_LIBRARY_PATH="$LIBDUCKDB_DIR"
{
    echo "=== guest: $(uname -a)"
    echo "=== pythons: $(command -v python3.12 python3.13 python3.14 | tr '\n' ' ')"
    "$BIN" --ignored --test-threads=1 --nocapture
    echo "TEST-BINARY-EXIT:$?"
} > "$RAW" 2>&1

rc=0
{
    cat "$RAW"
    grep -q '^TEST-BINARY-EXIT:0$' "$RAW" || rc=1
    if ! grep -q 'every call accounted for' "$RAW"; then
        echo "E2E-CHECK FAILED: no Python was traced"
        rc=1
    fi
    echo "VNG-TEST-EXIT:$rc"
} > "$OUT" 2>&1
sync
