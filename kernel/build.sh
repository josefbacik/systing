#!/bin/bash
#
# Build a custom v6.12 kernel for vmtest CI.
#
# Uses the BPF selftests config fragments from the Linux kernel tree
# (config + config.vm + config.x86_64) which provide BPF, BTF, networking
# (including CONFIG_VETH=y), namespaces, and VIRTIO/9P boot support.
#
# Usage:
#   cd kernel && ./build.sh
#   # Produces: kernel/bzImage-v6.12-bpf
#
set -euo pipefail

KERNEL_VERSION="v6.12"
OUTPUT_NAME="bzImage-v6.12-bpf"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Build inside Docker to get a reproducible environment
docker run --rm \
    -v "${SCRIPT_DIR}:/output" \
    ubuntu:24.04 \
    /bin/bash -c '
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -yq --no-install-recommends \
    git bc bison flex libssl-dev libelf-dev \
    build-essential dwarves cpio kmod \
    ca-certificates python3

cd /tmp
git clone --depth 1 --branch '"${KERNEL_VERSION}"' \
    https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git linux
cd linux

# Start from the BPF selftests config fragments
FRAG_DIR=tools/testing/selftests/bpf
cat "${FRAG_DIR}/config" \
    "${FRAG_DIR}/config.vm" \
    "${FRAG_DIR}/config.x86_64" \
    > .config

# Add explicit overrides for configs systing needs
cat >> .config <<EXTRA
# Tracing / perf_event support
CONFIG_PERF_EVENTS=y
CONFIG_KPROBE_EVENTS=y
CONFIG_UPROBE_EVENTS=y

# Namespace support
CONFIG_NET_NS=y
CONFIG_PID_NS=y
CONFIG_IPC_NS=y
CONFIG_UTS_NS=y

# Speed up boot
# CONFIG_X86_DECODER_SELFTEST is not set
EXTRA

make olddefconfig
make -j"$(nproc)" bzImage

cp arch/x86/boot/bzImage "/output/'"${OUTPUT_NAME}"'"
echo "Kernel built successfully: /output/'"${OUTPUT_NAME}"'"
'

echo "Output: ${SCRIPT_DIR}/${OUTPUT_NAME}"
