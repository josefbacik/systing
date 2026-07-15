#!/bin/bash
# Cross-compile systing using the 'cross' tool.
#
# Prerequisites:
#   - cross: cargo install cross
#   - podman or docker
#
# Usage:
#   ./scripts/cross-build.sh [--arch=ARCH] [cross build arguments...]
#
# ARCH may be aarch64 (the default) or riscv64.
# Examples:
#   ./scripts/cross-build.sh --arch=aarch64
#   ./scripts/cross-build.sh --arch=riscv64 --release
set -euo pipefail

ARCH=aarch64
ARCH_SET=false
BUILD_ARGS=()

for arg in "$@"; do
    case "$arg" in
        --arch=*)
            if [[ "$ARCH_SET" == true ]]; then
                echo "ERROR: --arch may only be specified once"
                exit 1
            fi
            ARCH=${arg#--arch=}
            ARCH_SET=true
            ;;
        --arch)
            echo "ERROR: use --arch=aarch64 or --arch=riscv64"
            exit 1
            ;;
        *)
            BUILD_ARGS+=("$arg")
            ;;
    esac
done

case "$ARCH" in
    aarch64)
        TARGET=aarch64-unknown-linux-gnu
        ;;
    riscv64)
        TARGET=riscv64gc-unknown-linux-gnu
        ;;
    *)
        echo "ERROR: unsupported architecture: $ARCH"
        echo "Supported architectures: aarch64, riscv64"
        exit 1
        ;;
esac

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

cross build --target "$TARGET" "${BUILD_ARGS[@]}"
