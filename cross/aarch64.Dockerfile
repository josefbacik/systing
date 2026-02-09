FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Add arm64 architecture and the ports repo for arm64 packages
RUN dpkg --add-architecture arm64 && \
    echo 'deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports jammy main universe' > /etc/apt/sources.list.d/arm64.list && \
    echo 'deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports jammy-updates main universe' >> /etc/apt/sources.list.d/arm64.list && \
    echo 'deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports jammy-security main universe' >> /etc/apt/sources.list.d/arm64.list && \
    # Restrict default sources to amd64 only
    sed -i 's/^deb /deb [arch=amd64] /' /etc/apt/sources.list

# Install build tools, aarch64 cross-compilation toolchain, and modern clang
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        clang \
        curl \
        g++-aarch64-linux-gnu \
        gcc-aarch64-linux-gnu \
        libc6-dev-arm64-cross \
        libelf-dev \
        libelf-dev:arm64 \
        linux-libc-dev \
        linux-libc-dev-arm64-cross \
        pkg-config \
        zlib1g-dev \
        zlib1g-dev:arm64 && \
    rm -rf /var/lib/apt/lists/*

# Ensure /usr/include/asm and /usr/include/bits exist so that
# build.rs detect_multiarch_include() returns None (avoids adding
# -I/usr/include/x86_64-linux-gnu to BPF clang args).
# On Ubuntu, headers like asm/, bits/, sys/, gnu/ are under the multiarch
# triplet directory (x86_64-linux-gnu/). BPF clang with -target bpf doesn't
# search multiarch paths, so symlink them to the standard include dir.
RUN for dir in asm bits sys gnu; do \
        [ -d /usr/include/x86_64-linux-gnu/$dir ] && \
        ln -sf /usr/include/x86_64-linux-gnu/$dir /usr/include/$dir; \
    done && \
    # BPF clang with -D__aarch64__ won't match __x86_64__ guards in gnu/stubs.h,
    # causing it to look for gnu/stubs-32.h. Create an empty placeholder since
    # BPF code doesn't need userspace stubs.
    touch /usr/include/gnu/stubs-32.h

# Symlink kernel headers for the aarch64 cross compiler
RUN for dir in linux asm-generic mtd rdma video sound misc; do \
        [ -d /usr/include/$dir ] && \
        ln -sf /usr/include/$dir /usr/aarch64-linux-gnu/include/$dir 2>/dev/null; \
    done; \
    [ -d /usr/include/aarch64-linux-gnu/asm ] && \
    ln -sf /usr/include/aarch64-linux-gnu/asm /usr/aarch64-linux-gnu/include/asm || \
    ln -sf /usr/include/asm-generic /usr/aarch64-linux-gnu/include/asm
