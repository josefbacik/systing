#!/bin/bash
# What the probes cost: the best of three runs of a benchmark untraced and
# traced, each mode with and without perf trampolines.
#
#   sudo python-function-trace/e2e/bench.sh PYTHON bench_calls.py|bench_mixed.py
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
tool=${TOOL:-$here/../../target/release/systing-python-function-trace}
py=$1
script=$here/$2
best() { sort -t= -k2 -n | head -1; }
run3() { for _ in 1 2 3; do "$@" 2>&1 | grep -o "wall=[0-9.]*"; done | best; }
trace() { "$tool" --duration 0 --min-duration-us 100000000 -o /dev/null --top 0 "$@"; }
echo "untraced:            $(run3 "$py" "$script")"
echo "untraced, -X perf:   $(run3 "$py" -X perf "$script")"
echo "dispatch:            $(run3 trace --mode dispatch -- "$py" "$script")"
echo "dispatch, -X perf:   $(run3 trace --mode dispatch -- "$py" -X perf "$script")"
echo "eval-frame, -X perf: $(run3 trace --mode eval-frame -- "$py" -X perf "$script")"
