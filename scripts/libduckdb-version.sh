#!/usr/bin/env bash
# Print the DuckDB release version the `duckdb` crate pins, read from Cargo.lock.
#
# libduckdb-sys encodes the DuckDB version it wraps as 1.MMmmPP.0 (1.10504.0 is
# DuckDB v1.5.4). CI links the tests against the pre-built libduckdb of that
# exact version, so a change to the pinned crate moves CI with it and the
# tests run on the engine the release build bundles.
set -euo pipefail

lock="$(cd "$(dirname "$0")/.." && pwd)/Cargo.lock"
crate_version=$(grep -A1 '^name = "libduckdb-sys"$' "$lock" | sed -n 's/^version = "\(.*\)"$/\1/p')
if [ -z "$crate_version" ]; then
    echo "libduckdb-sys not found in $lock" >&2
    exit 1
fi
case "$crate_version" in
    1.*) ;;
    *)
        echo "unexpected libduckdb-sys version scheme: $crate_version" >&2
        exit 1
        ;;
esac

encoded=${crate_version#1.}
encoded=${encoded%%.*}
echo "$((10#$encoded / 10000)).$((10#$encoded / 100 % 100)).$((10#$encoded % 100))"
