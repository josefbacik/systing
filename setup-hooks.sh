#!/bin/bash
#
# Setup script to configure git hooks for the systing project
#
# This script configures git to use the shared hooks directory,
# ensuring that code formatting, linting, and test checks are enforced.

set -e

echo "Setting up git hooks for systing..."

# Configure git to use the hooks directory
git config core.hooksPath hooks

echo ""
echo "✓ Git hooks configured successfully!"
echo ""
echo "The following hooks are now active:"
echo "  - pre-commit: Enforces cargo fmt before commits"
echo "  - pre-push: Enforces cargo fmt, clippy, and tests before pushes"
echo ""
echo "If a hook fails:"
echo "  - For formatting: run 'cargo fmt'"
echo "  - For clippy: fix the reported warnings/errors"
echo "  - For tests: fix the failing tests"
