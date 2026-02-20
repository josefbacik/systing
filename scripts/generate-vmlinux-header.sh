#!/bin/bash
# Generate an architecture-specific vmlinux.h header from the running kernel's BTF.
#
# Run this on each target architecture to produce src/bpf/vmlinux_<arch>.h.
# Requires: bpftool, /sys/kernel/btf/vmlinux (CONFIG_DEBUG_INFO_BTF=y),
#           vfio module loaded (modprobe vfio)
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

if [[ ! -f /sys/kernel/btf/vfio ]]; then
    echo "ERROR: /sys/kernel/btf/vfio not found"
    echo "Is the vfio module loaded? Try: modprobe vfio"
    exit 1
fi

echo "Generating ${OUTPUT} from running kernel BTF (including vfio module types)..."
bpftool btf dump file /sys/kernel/btf/vfio format c \
    --base /sys/kernel/btf/vmlinux > "${OUTPUT}"
echo "Done. Commit ${OUTPUT} to the repository."
