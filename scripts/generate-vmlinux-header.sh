#!/bin/bash
# Generate an architecture-specific vmlinux.h header from the running kernel's BTF.
#
# Run this on each target architecture to produce src/bpf/vmlinux_<arch>.h.
# Requires: bpftool, /sys/kernel/btf/vmlinux (CONFIG_DEBUG_INFO_BTF=y)
#
# Usage:
#   ./scripts/generate-vmlinux-header.sh

set -euo pipefail

ARCH=$(uname -m)
OUTPUT="src/bpf/vmlinux_${ARCH}.h"

if ! command -v bpftool &>/dev/null; then
    echo "ERROR: bpftool is not installed"
    exit 1
fi

if [[ ! -f /sys/kernel/btf/vmlinux ]]; then
    echo "ERROR: /sys/kernel/btf/vmlinux not found"
    echo "Your kernel must be built with CONFIG_DEBUG_INFO_BTF=y"
    exit 1
fi

echo "Generating ${OUTPUT} from running kernel BTF..."
bpftool btf dump file /sys/kernel/btf/vmlinux format c > "${OUTPUT}"
echo "Done. Commit ${OUTPUT} to the repository."
