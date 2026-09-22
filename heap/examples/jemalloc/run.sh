#!/usr/bin/env bash
# Build alloc_and_dump.c and run it under jemalloc with heap profiling on, so
# jemalloc writes heap snapshots into OUT_DIR (default ./snapshots).
#
#   ./run.sh [OUT_DIR]
#   systing-heap -o heap.duckdb OUT_DIR
#
# Needs a C compiler and a libjemalloc built with profiling (--enable-prof;
# Debian/Ubuntu's libjemalloc2 is). Set JEMALLOC to its path if it is not
# found below.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
out="${1:-$here/snapshots}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"

if [[ -z "${JEMALLOC:-}" ]]; then
	JEMALLOC="$(ldconfig -p 2>/dev/null | awk '/libjemalloc\.so\.2 / {print $NF; exit}')"
fi
if [[ -z "$JEMALLOC" || ! -e "$JEMALLOC" ]]; then
	echo "libjemalloc.so.2 not found; set JEMALLOC=/path/to/libjemalloc.so.2" >&2
	exit 1
fi

bin="$out/alloc_and_dump"
# Frame pointers and -g so every frame symbolizes to a function and line.
"${CC:-cc}" -O1 -g -fno-omit-frame-pointer -o "$bin" "$here/alloc_and_dump.c"

# prof:true            turn heap profiling on
# prof_prefix          where snapshots go: <prefix>.<pid>.<seq>.<kind>.heap
# lg_prof_sample:14    sample about one allocation per 16 KiB allocated
# lg_prof_interval:22  write a snapshot every 4 MiB allocated (kind "i")
# prof_final:true      and one when the process exits (kind "f")
MALLOC_CONF="prof:true,prof_prefix:$out/jeprof,lg_prof_sample:14,lg_prof_interval:22,prof_final:true" \
	LD_PRELOAD="$JEMALLOC" "$bin"

ls -1 "$out"/*.heap
