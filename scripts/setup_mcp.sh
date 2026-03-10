#!/bin/bash
# Setup systing-analyze as a Claude Code MCP server.
#
# This script:
#   1. Builds the systing-analyze binary in release mode
#   2. Registers it as a Claude Code MCP server (user scope)
#   3. Installs systing skills into ~/.claude/skills/
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
# Remove any existing registration so re-running this script picks up a new binary path.
claude mcp remove systing-analyze --scope user 2>/dev/null || true
claude mcp add systing-analyze --scope user -- "$BINARY" mcp

# -- Install skills --
SKILLS_SRC="$PROJECT_DIR/skills"
SKILLS_DST="$HOME/.claude/skills"

if [ -d "$SKILLS_SRC" ]; then
    echo "Installing systing skills into $SKILLS_DST..."
    mkdir -p "$SKILLS_DST"
    for skill_dir in "$SKILLS_SRC"/*/; do
        [ -d "$skill_dir" ] || continue
        skill_name="$(basename "$skill_dir")"
        # Copy (replacing any prior version) rather than symlink so the skill
        # survives if the checkout moves or is deleted.
        rm -rf "${SKILLS_DST:?}/${skill_name}"
        cp -r "$skill_dir" "$SKILLS_DST/$skill_name"
        echo "  - /$skill_name"
    done
fi

echo ""
echo "Done! systing-analyze MCP server registered."
echo ""
echo "MCP tools available:"
echo "  - trace_info     Get trace metadata and database overview"
echo "  - query          Run SQL queries against the database"
echo "  - list_tables    List tables with row counts"
echo "  - describe_table Get column names and types"
echo "  - flamegraph     Stack trace analysis"
echo "  - sched_stats    Scheduling timing statistics"
echo "  - cpu_stats      Per-CPU scheduling statistics"
echo "  - network_connections    Per-connection traffic summary"
echo "  - network_interfaces     Per-interface traffic summary"
echo "  - network_socket_pairs   Find matched socket pairs"
echo ""
echo "Skills installed (invoke with /<name> in Claude Code):"
echo "  - /systing-trace     Capture a trace with the systing binary"
echo "  - /systing-analyze   Analyze a trace database"
echo ""
echo "Restart Claude Code to pick up the new server and skills."
