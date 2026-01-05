# Claude Configuration Directory

This directory contains Claude Code configuration and context files for the Systing project.

## Structure

- **`commands/`** - Custom slash commands for Claude Code
- **`prompts/`** - Reusable prompts and templates
- **`context/`** - Additional context files and documentation
  - `stack-trace-schema.md` - Stack trace storage schema in DuckDB (tables, queries, design notes)
  - `network-schema.md` - Network event schema in DuckDB (track metadata, debug annotations, query examples)
  - `perfetto-reference.md` - Perfetto format reference
  - `perfetto-messages.md` - Perfetto message definitions

## Usage

Project instructions for Claude are in `CLAUDE.md` at the project root. Additional context files can be placed in the `context/` directory and referenced as needed.

## Adding Custom Commands

Place `.md` files in the `commands/` directory to create custom slash commands. See the [Claude Code documentation](https://github.com/anthropics/claude-code) for details on creating commands.
