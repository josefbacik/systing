#!/bin/bash
# Cross-compile systing for aarch64 using the 'cross' tool.
#
# Prerequisites:
#   - cross: cargo install cross
#   - podman or docker
#
# Usage:
#   ./scripts/cross-build.sh           # Debug build
#   ./scripts/cross-build.sh --release # Release build
set -euo pipefail

# Detect container engine (prefer podman)
if command -v podman &>/dev/null; then
    ENGINE=podman
elif command -v docker &>/dev/null; then
    ENGINE=docker
else
    echo "ERROR: podman or docker is required"
    exit 1
fi

if ! command -v cross &>/dev/null; then
    echo "ERROR: cross is not installed"
    echo "Install with: cargo install cross"
    exit 1
fi

# The cross container doesn't have clang, so override the x86_64 linker
# settings from .cargo/config.toml for the build-script host compilation.
export CROSS_CONTAINER_ENGINE="$ENGINE"
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=gcc
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS=""

cross build --target aarch64-unknown-linux-gnu "$@"
