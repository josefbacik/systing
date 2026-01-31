#!/bin/bash
#
# Install Python versions required by pystacks integration tests.
#
# Prerequisites: pyenv must be installed and available in PATH.
#
# Usage:
#   ./scripts/setup-pystacks.sh

set -euo pipefail

# Python versions must match the constants in tests/trace_validation.rs
PYTHON_VERSIONS=("3.13.11" "3.11.14")

if ! command -v pyenv &>/dev/null; then
    echo "ERROR: pyenv is not installed or not in PATH"
    echo "Install pyenv: https://github.com/pyenv/pyenv#installation"
    exit 1
fi

for version in "${PYTHON_VERSIONS[@]}"; do
    if pyenv versions --bare | grep -qx "$version"; then
        echo "Python $version already installed"
    else
        echo "Installing Python $version..."
        pyenv install "$version"
    fi
done

echo ""
echo "All required Python versions are installed."
