#!/bin/bash
# Guest side of the CI load-shape gate (.github/workflows/bpf-load-shapes.yml): run the
# pre-built `bpf_load_shapes` test binary's `every_shape_loads` test and write everything
# it prints, plus the exit code, into a file on the 9p-shared workspace.
#
# The exit code travels in the FILE, not in the VM tool's own status: a guest kernel
# without a virtio console (the Container-Optimized OS builds) has no script I/O
# ports, so vng runs this script through its console fallback and returns 255
# whatever the test did. The host side reads the `VNG-TEST-EXIT:<rc>` line.
#
# Usage (from vng's --exec, as root in the guest):
#   vmtest-load-shapes.sh <bpf_load_shapes binary> <dir holding libduckdb.so> <output file>
set -u
BIN="$1"
LIBDUCKDB_DIR="$2"
OUT="$3"

export LD_LIBRARY_PATH="$LIBDUCKDB_DIR"
{
    echo "=== guest: $(uname -a)"
    echo "=== accelerator: $(grep -q hypervisor /proc/cpuinfo && echo 'hypervisor flag set' || echo 'no hypervisor flag')"
    echo "=== btf: $(ls -l /sys/kernel/btf/vmlinux 2>&1)"
    echo "=== tracefs: $(grep -c tracefs /proc/mounts) mount(s)"
    "$BIN" --ignored --test-threads=1 every_shape_loads --nocapture
    rc=$?
    # A second, small run: the task-stacks rows that may not read other tasks' memory are
    # loaded with the verifier's log (four loads at level 2, the first an open row that has
    # to show the calls), and the log says what the loaded programs call.
    "$BIN" --ignored --test-threads=1 closed_task_stacks_rows_call_nothing_that_reads_another_task --nocapture
    closed_rc=$?
    [ "$rc" -ne 0 ] || rc="$closed_rc"
    echo "VNG-TEST-EXIT:$rc"
} > "$OUT" 2>&1
sync
