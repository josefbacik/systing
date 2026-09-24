#!/bin/bash
# Guest side of the task-stacks end-to-end step (.github/workflows/bpf-load-shapes.yml):
# run the three `test_e2e_task_stacks_scoped_walk*` cases of the pre-built
# `trace_validation` test binary as root on the guest kernel, and decide by what the
# cases PRINT, not by the exit code alone.
#
# Why the exit code is not enough: each case returns early, and passes, where it
# cannot do its work (no cgroup v2 mount, no right to create a cgroup, a kernel whose
# BTF lacks the cgroup task iterator, a run outside the root pid namespace). Those
# early returns are right on a developer's machine and wrong here: on these kernels
# every one of them would mean the step proved nothing. The cases word them three
# ways (a line that says it is skipping, `took the full walk`, `took the walk over
# every thread`) and any of the three fails the step: that is what shows the walks
# were scoped. A line only a run of each case prints is required of every case: that
# is what shows all three ran.
#
# The verdict travels in the FILE, as in vmtest-load-shapes.sh: a guest kernel
# without a virtio console makes the VM tool return 255 whatever the test did. The
# host side reads the `VNG-TEST-EXIT:<rc>` line.
#
# Usage (from vng's --exec, as root in the guest):
#   vmtest-task-stacks-e2e.sh <trace_validation binary> <dir holding libduckdb.so> <output file>
set -u
BIN="$1"
LIBDUCKDB_DIR="$2"
OUT="$3"
RAW="$OUT.raw"

export LD_LIBRARY_PATH="$LIBDUCKDB_DIR"
{
    echo "=== guest: $(uname -a)"
    echo "=== accelerator: $(grep -q hypervisor /proc/cpuinfo && echo 'hypervisor flag set' || echo 'no hypervisor flag')"
    echo "=== btf: $(ls -l /sys/kernel/btf/vmlinux 2>&1)"
    echo "=== cpus: $(nproc), memory: $(grep MemTotal /proc/meminfo)"
    # The cases build cgroups of their own under the cgroup v2 mount and skip without
    # one; mount it where the guest's init did not.
    if ! grep -q ' cgroup2 ' /proc/mounts; then
        mkdir -p /sys/fs/cgroup
        mount -t cgroup2 none /sys/fs/cgroup
        echo "=== cgroup2: mounted here (rc=$?)"
    else
        echo "=== cgroup2: $(grep ' cgroup2 ' /proc/mounts | head -n 1)"
    fi
    "$BIN" --ignored --test-threads=1 --nocapture test_e2e_task_stacks_scoped_walk
    echo "TEST-BINARY-EXIT:$?"
} > "$RAW" 2>&1

# Decide by the cases' own lines. Every check says what it looked for, so a red
# step names its reason in the guest's output.
rc=0
fail() {
    echo "E2E-CHECK FAILED: $1"
    rc=1
}
# A line only a run that did its work prints. Fixed strings, not patterns.
need() {
    if grep -q -F -- "$1" "$RAW"; then
        echo "E2E-CHECK ok: found: $1"
    else
        fail "missing: $1"
    fi
}
# A line only an early return prints: $1 the words, $2 what they mean.
forbid() {
    if grep -q -F -- "$1" "$RAW"; then
        fail "$2: $(grep -m 1 -F -- "$1" "$RAW")"
    else
        echo "E2E-CHECK ok: absent: $1"
    fi
}
{
    cat "$RAW"
    echo "=== checks"
    grep -q '^TEST-BINARY-EXIT:0$' "$RAW" || fail "the test binary did not exit 0"
    if grep -q -E 'test result: ok\. [1-9][0-9]* passed; 0 failed; 0 ignored' "$RAW"; then
        echo "E2E-CHECK ok: the summary reads ok with one case or more passed, none failed, none ignored"
    else
        fail "no summary line reading ok with one case or more passed, 0 failed, 0 ignored"
    fi
    # The three wordings of an early return. The first is the bare word: the cases
    # write both `skipping: ...` and `skipping the --cgroup half: ...`.
    forbid 'skipping' 'a case skipped its work'
    forbid 'took the full walk' 'a scoped walk fell back to every thread on the host'
    forbid 'took the walk over every thread' 'a capture walked every thread on the host'
    # One line or more of each case, so that all three ran. No line anchors: with one
    # test thread the test runner prints `test <name> ... ` without a newline before a
    # case runs, so a case's first line follows it.
    need '[--pid] scoped: '
    need '[--cgroup] scoped: '
    need 'the listing came back whole: 10 processes in two cgroups below the target, all recorded'
    need 'most walks cut, as it comes] visited '
    need 'most walks whole, as it comes] visited '
    echo "VNG-TEST-EXIT:$rc"
} > "$OUT" 2>&1
sync
