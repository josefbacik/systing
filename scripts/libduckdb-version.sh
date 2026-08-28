#!/usr/bin/env bash
# Print the DuckDB release version the `duckdb` crate pins, read from Cargo.lock.
#
# libduckdb-sys encodes the DuckDB version it wraps as 1.MMmmPP.N (1.10504.0 is
# DuckDB v1.5.4). CI links the tests against the pre-built libduckdb of that
# exact version, so a change to the pinned crate moves CI with it and the
# tests run on the engine the release build bundles.
#
# Refuses, with a message on stderr and a non-zero exit, a lock that does not
# name the crate exactly once, or a version outside the encoded shape: the
# crate's older 1.x line (1.4.5 and the like) is still published beside it and
# would otherwise decode to a version that does not exist, and a pre-release
# suffix must not be silently read as its release.
set -euo pipefail

lock="$(cd "$(dirname "$0")/.." && pwd)/Cargo.lock"
versions=$(grep -A1 '^name = "libduckdb-sys"$' "$lock" | sed -n 's/^version = "\(.*\)"$/\1/p' || true)
count=$(printf '%s\n' "$versions" | grep -c . || true)
if [ "$count" -eq 0 ]; then
    echo "libduckdb-sys not found in $lock" >&2
    exit 1
fi
if [ "$count" -ne 1 ]; then
    echo "libduckdb-sys appears $count times in $lock ($(echo "$versions" | tr '\n' ' ')); cannot pick one" >&2
    exit 1
fi
if [[ ! "$versions" =~ ^1\.([0-9]{5,})\.[0-9]+$ ]]; then
    echo "unexpected libduckdb-sys version scheme: $versions (expected the encoded 1.MMmmPP.N form)" >&2
    exit 1
fi

encoded=${BASH_REMATCH[1]}
echo "$((10#$encoded / 10000)).$((10#$encoded / 100 % 100)).$((10#$encoded % 100))"
