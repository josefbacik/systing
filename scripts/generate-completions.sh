#!/bin/bash
# Generate shell completion scripts for all systing binaries.
#
# Binaries are taken from $SYSTING_BIN_DIR if set (packagers point this at the
# built artifacts, e.g. target/release), otherwise from $PATH.
#
# Usage:
#   ./scripts/generate-completions.sh [OUTPUT_DIR]   # default: ./completions
#
# Output layout:
#   OUTPUT_DIR/bash/systing            OUTPUT_DIR/zsh/_systing
#   OUTPUT_DIR/fish/systing.fish
set -euo pipefail

OUT_DIR="${1:-completions}"
BIN_DIR="${SYSTING_BIN_DIR:-}"

bin() {
    if [[ -n "$BIN_DIR" ]]; then
        echo "$BIN_DIR/$1"
    else
        echo "$1"
    fi
}

# systing takes a --completions flag; the subcommand-based tools take a
# `completions` subcommand.
gen() {
    local binary="$1" shell="$2"
    if [[ "$binary" == "systing" ]]; then
        "$(bin "$binary")" --completions "$shell"
    else
        "$(bin "$binary")" completions "$shell"
    fi
}

mkdir -p "$OUT_DIR"/{bash,zsh,fish}

for binary in systing systing-analyze systing-util; do
    gen "$binary" bash > "$OUT_DIR/bash/$binary"
    gen "$binary" zsh > "$OUT_DIR/zsh/_$binary"
    gen "$binary" fish > "$OUT_DIR/fish/$binary.fish"
    echo "Generated completions for $binary"
done

echo "Completions written to $OUT_DIR/"
