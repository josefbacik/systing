#!/bin/bash
# The end-to-end check of the Python function trace: run workload.py under
# the tool and compare every slice with what the script is known to do.
#
#   sudo python-function-trace/e2e/run.sh PYTHON [MODE] [PYTHON ARGS...]
#
# e.g. `run.sh /usr/bin/python3.12`, `run.sh python3.13 dispatch -X perf`.
# Needs root (it loads BPF programs). TOOL overrides the tool's path.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
tool=${TOOL:-$here/../../target/release/systing-python-function-trace}
python=$1
mode=${2:-dispatch}
shift $(($# < 2 ? $# : 2))
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
"$tool" --duration 0 --mode "$mode" --slices "$out/slices.tsv" -o "$out/trace.pb" --top 0 \
    -- "$python" "$@" "$here/workload.py"
python3 "$here/check.py" "$out/slices.tsv" "$mode"
