#!/bin/bash
# Run integration tests that require root/BPF privileges.
#
# This script builds test binaries as the current user (avoiding root-owned
# build artifacts), then runs only the compiled test binary with sudo.
#
# Usage:
#   ./scripts/run-integration-tests.sh                    # Run all ignored tests
#   ./scripts/run-integration-tests.sh trace_validation   # Specify test name
#   ./scripts/run-integration-tests.sh trace_validation test_e2e_parquet_validation  # Run specific test
set -euo pipefail

# Check for jq dependency
if ! command -v jq &>/dev/null; then
    echo "ERROR: jq is required but not installed"
    echo "Install with: apt-get install jq (Debian/Ubuntu) or brew install jq (macOS)"
    exit 1
fi

# Check that tracefs is mounted (required for BPF tracepoints used by integration tests)
if ! grep -q 'tracefs' /proc/mounts; then
    echo "ERROR: tracefs is not mounted"
    echo ""
    echo "Integration tests require tracefs for BPF tracepoints. Mount it with:"
    echo "  mount -t tracefs tracefs /sys/kernel/tracing"
    echo ""
    echo "Or if using debugfs (older kernels):"
    echo "  mount -t debugfs debugfs /sys/kernel/debug"
    exit 1
fi

# Check if pystacks Python versions are installed (needed for pystacks integration tests)
SETUP_PYSTACKS="$(dirname "$0")/setup-pystacks.sh"
if [[ -f "$SETUP_PYSTACKS" ]]; then
    if ! command -v pyenv &>/dev/null; then
        echo "WARNING: pyenv is not installed. Pystacks integration tests will fail."
        echo "Install pyenv and run: ./scripts/setup-pystacks.sh"
    else
        mapfile -t REQUIRED_PYVERSIONS < <(grep -o '"[0-9]*\.[0-9]*\.[0-9]*"' "$SETUP_PYSTACKS" | tr -d '"')
        NEEDS_PYSETUP=false
        for ver in "${REQUIRED_PYVERSIONS[@]}"; do
            if ! pyenv versions --bare 2>/dev/null | grep -qx "$ver"; then
                NEEDS_PYSETUP=true
                break
            fi
        done
        if [[ "$NEEDS_PYSETUP" == true ]]; then
            echo "Some pystacks Python versions are missing. Running setup-pystacks.sh..."
            "$SETUP_PYSTACKS"
        fi
    fi
fi

# Parse flags
USE_SUDO=true
POSITIONAL=()
for arg in "$@"; do
    case "$arg" in
        --no-sudo) USE_SUDO=false ;;
        *) POSITIONAL+=("$arg") ;;
    esac
done
set -- "${POSITIONAL[@]+"${POSITIONAL[@]}"}"

# Configuration with defaults
TEST_NAME="${1:-trace_validation}"
shift || true  # Allow $@ to be empty if no additional args provided
CARGO_FEATURES="${CARGO_FEATURES:-}"

run_test() {
    if [[ "$USE_SUDO" == true ]]; then
        sudo -E "$@"
    else
        "$@"
    fi
}

# If TEST_BINARY is set, skip build/discovery and run directly
if [[ -n "${TEST_BINARY:-}" ]]; then
    if [[ ! -x "$TEST_BINARY" ]]; then
        echo "ERROR: TEST_BINARY is set but not executable: $TEST_BINARY"
        exit 1
    fi
    echo "Using pre-built test binary: $TEST_BINARY"
    run_test "$TEST_BINARY" --ignored --test-threads=1 "$@"
    exit $?
fi

# Build arguments
BUILD_ARGS=(--test "$TEST_NAME" --no-run --message-format=json)
[[ -n "$CARGO_FEATURES" ]] && BUILD_ARGS+=(--features "$CARGO_FEATURES")

echo "Building test binary..."

# Temp files for build output (JSON on stdout, errors on stderr)
BUILD_OUTPUT=$(mktemp)
BUILD_LOG=$(mktemp)

cleanup() {
    rm -f "$BUILD_OUTPUT" "$BUILD_LOG"
}
trap cleanup EXIT

# Build the test binary, capturing output separately
# This ensures we detect cargo build failures (not masked by pipeline)
if ! cargo test "${BUILD_ARGS[@]}" >"$BUILD_OUTPUT" 2>"$BUILD_LOG"; then
    echo "ERROR: Build failed for '$TEST_NAME'"
    echo ""
    echo "Build output:"
    cat "$BUILD_LOG"
    exit 1
fi

# Parse the JSON output to find the test binary path
# Using --arg for safe variable interpolation
TEST_BINARY=$(jq -r --arg name "$TEST_NAME" '
    select(.reason == "compiler-artifact") |
    select(.target.kind[] == "test") |
    select(.target.name == $name) |
    .executable' "$BUILD_OUTPUT" 2>/dev/null | tail -1)

if [[ -z "$TEST_BINARY" || ! -x "$TEST_BINARY" ]]; then
    echo "ERROR: Failed to locate test binary for '$TEST_NAME'"
    echo ""
    echo "Build output:"
    cat "$BUILD_LOG"
    exit 1
fi

echo "Found test binary: $TEST_BINARY"
echo "Running: $TEST_BINARY --ignored --test-threads=1 $*"

# Run tests serially: systing attaches system-wide BPF tracepoints, so only
# one instance can run at a time without ring buffer contention and event drops.
# Use sudo -E to preserve environment (DEBUGINFOD_URLS, PATH, etc.)
run_test "$TEST_BINARY" --ignored --test-threads=1 "$@"
