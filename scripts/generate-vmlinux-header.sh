#!/bin/bash
# Generate an architecture-specific vmlinux.h header from the running kernel's BTF.
#
# Run this on each target architecture to produce src/bpf/vmlinux_<arch>.h.
# Requires: custom bpftool (multi-file support), /sys/kernel/btf/vmlinux
#           (CONFIG_DEBUG_INFO_BTF=y), vfio modules loaded
#           (modprobe vfio vfio-pci vfio-pci-core vfio-iommu-type1)
#
# Usage:
#   ./scripts/generate-vmlinux-header.sh

set -euo pipefail

BPFTOOL="/linux/tools/bpf/bpftool/bpftool"
ARCH=$(uname -m)
OUTPUT="src/bpf/vmlinux_${ARCH}.h"

if [[ ! -x "${BPFTOOL}" ]]; then
    echo "ERROR: bpftool not found at ${BPFTOOL}"
    exit 1
fi

if [[ ! -f /sys/kernel/btf/vmlinux ]]; then
    echo "ERROR: /sys/kernel/btf/vmlinux not found"
    echo "Your kernel must be built with CONFIG_DEBUG_INFO_BTF=y"
    exit 1
fi

# VFIO modules we need BTF from (sysfs uses underscores)
VFIO_MODULES=(vfio vfio_pci vfio_pci_core vfio_iommu_type1)

for mod in "${VFIO_MODULES[@]}"; do
    if [[ ! -f /sys/kernel/btf/${mod} ]]; then
        echo "ERROR: /sys/kernel/btf/${mod} not found"
        echo "Is the ${mod//_/-} module loaded? Try: modprobe ${mod//_/-}"
        exit 1
    fi
done

echo "Generating ${OUTPUT} from running kernel BTF (including vfio module types)..."
"${BPFTOOL}" btf dump file /sys/kernel/btf/vmlinux \
    file /sys/kernel/btf/vfio \
    file /sys/kernel/btf/vfio_pci \
    file /sys/kernel/btf/vfio_pci_core \
    file /sys/kernel/btf/vfio_iommu_type1 \
    format c > "${OUTPUT}"
echo "Done. Commit ${OUTPUT} to the repository."
