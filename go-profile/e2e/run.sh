#!/bin/bash
# The end-to-end check of systing-go-profile: build the workload twice (as it
# is, and stripped), and compare everything read out of its memory with what
# the program itself serves (check.py says what must hold).
#
#   go-profile/e2e/run.sh
#
# Needs Go 1.26 (the version systing has bindings for) and a build of the
# tool: `cargo build --release -p systing-go-profile`. TOOL overrides its
# path. Runs as any user: the workloads are its own processes.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
tool=${TOOL:-$here/../../target/release/systing-go-profile}
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
(cd "$here/workload" && go build -o "$out/workload" . && go build -ldflags="-s -w" -o "$out/workload_stripped" .)
python3 "$here/check.py" "$tool" "$out/workload" "$out/workload_stripped"
