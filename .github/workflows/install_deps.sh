#!/bin/sh

export DEBIAN_FRONTEND=noninteractive

sudo apt-get install -y rustup linux-tools-common libelf-dev linux-libc-dev \
    clang libbpf-dev make pkg-config libfmt-dev libre2-dev libcap-dev \
    --no-install-recommends

# make errno/asm.h available.
sudo ln -s /usr/include/asm-generic /usr/include/asm

rustup toolchain install stable --profile minimal

git submodule update --init --recursive
