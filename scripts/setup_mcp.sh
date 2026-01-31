#!/bin/bash
# Setup systing-analyze as a Claude Code MCP server.
#
# This script:
#   1. Builds the systing-analyze binary in release mode
#   2. Registers it as a Claude Code MCP server (user scope)
#
# Usage:
#   ./scripts/setup_mcp.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "Building systing-analyze (release)..."
cargo build --release --bin systing-analyze --manifest-path "$PROJECT_DIR/Cargo.toml"

# Resolve absolute path to the built binary
BINARY="$PROJECT_DIR/target/release/systing-analyze"
if [ ! -f "$BINARY" ]; then
    echo "Error: Binary not found at $BINARY"
    exit 1
fi

echo "Registering systing-analyze as Claude Code MCP server..."
claude mcp add systing-analyze --scope user -- "$BINARY" mcp

echo ""
echo "Done! systing-analyze MCP server registered."
echo ""
echo "The server provides these tools:"
echo "  - open_database  Open a .duckdb trace database"
echo "  - query          Run SQL queries against the database"
echo "  - list_tables    List tables with row counts"
echo "  - describe_table Get column names and types"
echo "  - flamegraph     Stack trace analysis"
echo "  - trace_info     Get trace metadata"
echo ""
echo "Restart Claude Code to pick up the new server."
