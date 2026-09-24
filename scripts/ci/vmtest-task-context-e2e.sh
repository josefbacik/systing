#!/bin/bash
# Guest side of the task_context end-to-end step (.github/workflows/bpf-load-shapes.yml):
# run the root cases of the pre-built `task_context_record` test binary
# (tests/task_context_record.rs) on the guest kernel, and decide by what the cases and
# the tracer PRINT, not by the exit code alone.
#
# Why the exit code is not enough. The cases build the library's example with the
# system C compiler and return early, and pass, where there is none: right on a
# developer's machine, wrong here, where it would mean the step proved nothing. And two
# of the cases assert that NOTHING was read (the kernel's confidentiality mode; a recipe
# planted over a process it is wrong for): a reader that never ran would pass them too.
# So this script requires
#   - no early return, and the line each case prints only when it ran to its end;
#   - of the tracer's own `task_context samples:` line, printed once per capture with
#     the reader's counters by reason: that the captures which must read did read
#     (`new_id=`), that the confidentiality capture counted its refusals (`restricted=`)
#     and nothing else, and that each wrong-recipe capture counted a refusal of the
#     planted recipe. A process with no recipe is not counted at all, so a recipe that
#     was never consulted leaves an empty line and fails here;
#   - the start-of-capture look's own line saying it found the running program.
#
# In the workflow's guest, and only there (the kernel command line says which it is),
# the cases build, run and map the example from a tmpfs this script mounts at
# /run/task-context-e2e, not from the 9p share /tmp is on in these guests: the program
# under test should sit on an ordinary filesystem. It mounts nothing else and writes
# only its three output files beside <output file>.
#
# The verdict travels in the FILE, as in vmtest-load-shapes.sh: a guest kernel without a
# virtio console makes the VM tool return 255 whatever the tests did. The host side
# reads the `VNG-TEST-EXIT:<rc>` line.
#
# Usage (from vng's --exec, as root in the guest):
#   vmtest-task-context-e2e.sh <task_context_record binary> <dir holding libduckdb.so> \
#       <the checkout the binary was built from> <output file>
set -u
BIN="$1"
LIBDUCKDB_DIR="$2"
SRC="$3"
OUT="$4"
RAW="$OUT.raw"
# The cases this run must have: see the list of `need_line` calls below.
CASES=9
CAPTURES=13

export LD_LIBRARY_PATH="$LIBDUCKDB_DIR"
{
    echo "=== guest: $(uname -a)"
    echo "=== accelerator: $(grep -q hypervisor /proc/cpuinfo && echo 'hypervisor flag set' || echo 'no hypervisor flag')"
    echo "=== btf: $(ls -l /sys/kernel/btf/vmlinux 2>&1)"
    echo "=== cpus: $(nproc), memory: $(grep MemTotal /proc/meminfo)"
    echo "=== cc: $(${CC:-cc} --version 2>&1 | head -n 1)"
    echo "=== library source: $(ls -l "$SRC/crates/task-context/src/task_context.c" "$SRC/crates/task-context/examples/tcx_example.c" 2>&1)"
    # Only inside the guest this workflow boots is anything mounted: its kernel command
    # line carries the `virtme_root_user=1` the step appends. Run anywhere else, the cases
    # use the caller's own temporary directory and this script touches nothing.
    scratch=/run/task-context-e2e
    if ! grep -q -w 'virtme_root_user=1' /proc/cmdline; then
        echo "=== tmpdir: not the workflow's guest, nothing mounted; the cases use $(dirname "$(mktemp -u)")"
    elif mkdir -p "$scratch" && mount -t tmpfs -o mode=1777 tmpfs "$scratch"; then
        export TMPDIR="$scratch"
        echo "=== tmpdir: tmpfs at $scratch"
    else
        echo "=== tmpdir: no tmpfs could be mounted at $scratch; the cases use $(dirname "$(mktemp -u)")"
    fi
    "$BIN" --ignored --test-threads=1 --nocapture
    echo "TEST-BINARY-EXIT:$?"
} > "$RAW" 2>&1

# Decide by the printed lines. Every check says what it looked for, so a red step names
# its reason in the guest's output.
rc=0
fail() {
    echo "E2E-CHECK FAILED: $1"
    rc=1
}
ok() {
    echo "E2E-CHECK ok: $1"
}
# A line only a case that ran to its end prints: $1 an extended regular expression.
need_line() {
    if grep -q -E -- "$1" "$RAW"; then
        ok "found: $1"
    else
        fail "missing: $1"
    fi
}
# $1 a count, $2 the count wanted, $3 what was counted.
want_count() {
    if [ "$1" -eq "$2" ]; then
        ok "$1 $3"
    else
        fail "$1 $3, $2 wanted"
    fi
}
{
    cat "$RAW"
    echo "=== checks"
    grep -q '^TEST-BINARY-EXIT:0$' "$RAW" || fail "the test binary did not exit 0"
    if grep -q -F "test result: ok. $CASES passed; 0 failed; 0 ignored" "$RAW"; then
        ok "the summary reads ok with $CASES cases passed, none failed, none ignored"
    else
        fail "no summary line reading ok with $CASES passed, 0 failed, 0 ignored"
    fi
    # The one early return: no C compiler.
    if grep -q -F 'SKIPPED:' "$RAW"; then
        fail "a case returned early: $(grep -m 1 -F 'SKIPPED:' "$RAW")"
    else
        ok "absent: SKIPPED:"
    fi

    # One line of each capture's check, printed after its last assert held. No anchor at
    # the line's start: with one test thread the test runner prints `test <name> ... `
    # without a newline before a case runs.
    read_whole='[0-9]+ samples, [0-9]+ with a context id, [0-9]+ contexts of 3 threads'
    read_nothing='[0-9]+ samples, none with a context id, no task_context row'
    need_line "\[linked in\] $read_whole"
    need_line "\[shared object\] $read_whole"
    need_line "\[shared object, dtv\] $read_whole"
    need_line "\[already running, every process\] $read_whole"
    need_line "\[already running, by pid\] $read_whole"
    need_line "\[confidentiality mode\] $read_nothing"
    need_line "\[a small region\] $read_nothing"
    need_line "\[all of user memory\] $read_nothing"
    need_line "\[vfork child\] [0-9]+ samples of the child, none with a context id; [0-9]+ of the parent's carry one"
    # The task-stacks recorder's cases, with the CPU sampler off: what they read, the
    # recorder's iterator read, from another task's memory.
    events_whole='[0-9]+ events, [0-9]+ with a context id, [0-9]+ contexts of 3 threads'
    need_line "\[task stacks: linked in\] $events_whole"
    need_line "\[task stacks: shared object\] $events_whole"
    need_line "\[task stacks: shared object, dtv\] $events_whole"
    need_line "\[task stacks: confidentiality mode\] [0-9]+ events, none with a context id, no task_context row"

    # The reader's own counters, one line a capture.
    counters="$OUT.counters"
    grep -F 'task_context samples:' "$RAW" > "$counters"
    echo "=== the reader's counters, one line a capture"
    cat "$counters"
    refusal='(unset|out_of_range|slot_read_failed|tp_implausible|block_read_failed|bad_header)=[1-9]'
    want_count "$(grep -c '' "$counters")" "$CAPTURES" "captures printed their counters"
    want_count "$(grep -c -E 'new_id=[1-9]' "$counters")" 9 \
        "captures read a context (the three started programs, the running program twice, the vfork parent, the three started programs again through the task-stacks recorder)"
    want_count "$(grep -E 'restricted=[1-9]' "$counters" | grep -c -v -E '(new|same)_id=')" 2 \
        "captures counted the confidentiality mode's refusals and read nothing (the sampler's, the task-stacks recorder's)"
    want_count "$(grep -v -E '(new_id|same_id|restricted)=' "$counters" | grep -c -E "$refusal")" 2 \
        "captures counted a refusal of the recipe planted on them and read nothing"

    # The look at the start of a capture over every process found a program that was
    # already running (no exec announced it; the case's own line above says whose values
    # the samples then carried).
    need_line 'task_context: looked at [0-9]+ processes in [0-9]+ ms, [1-9][0-9]* publish a recipe, '
    echo "VNG-TEST-EXIT:$rc"
} > "$OUT" 2>&1
sync
