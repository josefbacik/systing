#!/bin/bash
# Guest side of the go_context end-to-end step (.github/workflows/bpf-load-shapes.yml):
# run the root cases of the pre-built `go_context_record` test binary
# (tests/go_context_record.rs) on the guest kernel, and decide by what the cases and
# the tracer PRINT, not by the exit code alone.
#
# The cases build small Go programs with the Go toolchain they are given ($GO) and
# return early, and pass, where there is none: right on a developer's machine, wrong
# here, where it would mean the step proved nothing. They run once with each Go
# toolchain given, and for each run this script requires
#   - no early return, and the line each case prints only when it ran to its end;
#   - of the tracer's own `go_context discovery:` line, printed once per capture, that
#     the program was looked at and its recipe published;
#   - of its `go_context samples:` line, that each capture read label sets.
# The cases run one at a time: each holds a share of its program's samples to a bar,
# and cases sampling side by side on four CPUs take samples from each other.
#
# In the workflow's guest, and only there (the kernel command line says which it is),
# the Go build cache and the cases' programs go on a tmpfs this script mounts at
# /run/go-context-e2e, not on the 9p share /tmp is on in these guests. It mounts nothing
# else and writes only its output files beside <output file>.
#
# The verdict travels in the FILE, as in vmtest-load-shapes.sh: a guest kernel without a
# virtio console makes the VM tool return 255 whatever the tests did. The host side
# reads the `VNG-TEST-EXIT:<rc>` line.
#
# Usage (from vng's --exec, as root in the guest):
#   vmtest-go-context-e2e.sh <go_context_record binary> <dir holding libduckdb.so> \
#       <output file> <go binary>...
set -u
BIN="$1"
LIBDUCKDB_DIR="$2"
OUT="$3"
shift 3
CASES=6
CAPTURES=6
# The cases whose programs set labels, and so send a set.
LABELLED=4

export LD_LIBRARY_PATH="$LIBDUCKDB_DIR"
scratch=/run/go-context-e2e
mounted=""
if grep -q -w 'virtme_root_user=1' /proc/cmdline && mkdir -p "$scratch" &&
    mount -t tmpfs -o mode=1777 tmpfs "$scratch"; then
    mounted="tmpfs at $scratch"
fi

rc=0
fail() {
    echo "E2E-CHECK FAILED: $1"
    rc=1
}
ok() {
    echo "E2E-CHECK ok: $1"
}
# $1 the run's output, $2 an extended regular expression a case prints only
# when it ran to its end.
need_line() {
    if grep -q -E -- "$2" "$1"; then
        ok "found: $2"
    else
        fail "missing: $2"
    fi
}
want_count() {
    if [ "$1" -eq "$2" ]; then
        ok "$1 $3"
    else
        fail "$1 $3, $2 wanted"
    fi
}
{
    echo "=== guest: $(uname -a)"
    echo "=== cc: $(${CC:-cc} --version 2>&1 | head -n 1)"
    echo "=== tmpdir: ${mounted:-none mounted, the default one}"
    # Each toolchain given must be another Go: the same one twice proves
    # nothing more.
    versions="$(for go in "$@"; do "$go" env GOVERSION 2>/dev/null || echo "unknown:$go"; done)"
    echo "=== go versions: $(echo $versions)"
    if [ "$(printf '%s\n' "$versions" | sort | uniq -d | wc -l)" -ne 0 ]; then
        fail "a Go version was given twice: $(echo $versions)"
    fi
    for go in "$@"; do
        raw="$OUT.$("$go" env GOVERSION 2>/dev/null || echo unknown).raw"
        {
            echo "=== go: $("$go" version 2>&1)"
            if [ -n "$mounted" ]; then
                work="$scratch/$(basename "$raw" .raw)"
                mkdir -p "$work"
                export TMPDIR="$work" GOCACHE="$work/gocache" GOPATH="$work/gopath" HOME="$work"
            fi
            GO="$go" "$BIN" --ignored --test-threads=1 --nocapture
            echo "TEST-BINARY-EXIT:$?"
        } > "$raw" 2>&1
        cat "$raw"
        echo "=== checks for $("$go" version 2>&1)"
        grep -q '^TEST-BINARY-EXIT:0$' "$raw" || fail "the test binary did not exit 0"
        if grep -q -F "test result: ok. $CASES passed; 0 failed; 0 ignored" "$raw"; then
            ok "the summary reads ok with $CASES cases passed, none failed, none ignored"
        else
            fail "no summary line reading ok with $CASES passed, 0 failed, 0 ignored"
        fi
        # The one early return: no Go toolchain.
        if grep -q -F 'SKIPPED:' "$raw"; then
            fail "a case returned early: $(grep -m 1 -F 'SKIPPED:' "$raw")"
        else
            ok "absent: SKIPPED:"
        fi
        # One line of each case, printed after its last assert held.
        need_line "$raw" '\[built as it is\]: [0-9]+ samples with a goroutine, 3 label sets, [0-9]+ without labels'
        need_line "$raw" '\[stripped\]: [0-9]+ samples with a goroutine, 3 label sets, [0-9]+ without labels'
        need_line "$raw" "\[cgo\]: [0-9]+ of the program's [0-9]+ samples carry its goroutine's labels"
        need_line "$raw" "\[iter.Pull\]: [0-9]+ of the program's [0-9]+ samples carry its goroutine's labels"
        need_line "$raw" "\[C thread\]: [0-9]+ samples in Go under its labels; [0-9]+ of the [0-9]+ others carry no goroutine"
        need_line "$raw" "\[empty set\]: [0-9]+ of the program's [0-9]+ samples carry a goroutine, none a label set"
        # The tracer's own lines, one of each a capture.
        want_count "$(grep -c -E 'go_context discovery: .*published=[12] ' "$raw")" "$CAPTURES" \
            "captures published the program's recipe"
        labelled="$(grep -c -E 'go_context samples: .*new_labels=[1-9]' "$raw")"
        if [ "$labelled" -ge "$LABELLED" ]; then
            ok "$labelled captures sent label sets"
        else
            fail "$labelled captures sent label sets, at least $LABELLED wanted"
        fi
    done
    [ "$#" -gt 0 ] || fail "no Go toolchain given"
    echo "VNG-TEST-EXIT:$rc"
} > "$OUT" 2>&1
sync
