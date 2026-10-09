#!/bin/bash
# The end-to-end check of systing-go-profile: build the workload four times
# (by Go's own linker, as it is and stripped; by the system linker, as
# distributions build Go programs, as it is and stripped, where Go's function
# table counts from Go's own start of code rather than the .text section's),
# and compare everything read out of its memory with what the program itself
# serves (check.py says what must hold).
#
#   go-profile/e2e/run.sh
#
# Needs Go 1.26 (the version systing has bindings for), a C compiler (for the
# system linker) and a build of the tool:
# `cargo build --release -p systing-go-profile`. TOOL overrides its path.
# Every build must succeed: a build it cannot make fails the check. Runs as
# any user who may read the workloads' memory (its own, where
# kernel.yama.ptrace_scope is 0; else root).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
tool=${TOOL:-$here/../../target/release/systing-go-profile}
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
cd "$here/workload"
go build -o "$out/workload" .
go build -ldflags="-s -w" -o "$out/workload_stripped" .
CGO_ENABLED=1 go build -ldflags="-linkmode=external" -o "$out/workload_external" .
CGO_ENABLED=1 go build -ldflags="-s -w -linkmode=external" -o "$out/workload_external_stripped" .
python3 "$here/check.py" "$tool" "$out/workload" "$out/workload_stripped" \
    "$out/workload_external" "$out/workload_external_stripped"
