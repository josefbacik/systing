# Claude Configuration Directory

This directory contains Claude Code configuration and context files for the Systing project.

## Structure

- **`instructions.md`** - Main project instructions for Claude Code (formerly `CLAUDE.md`)
- **`commands/`** - Custom slash commands for Claude Code
- **`prompts/`** - Reusable prompts and templates
- **`context/`** - Additional context files and documentation
  - `stack-trace-schema.md` - Stack trace storage schema in DuckDB (tables, queries, design notes)

## Usage

Claude Code automatically reads `instructions.md` when working on this project. Additional context files can be placed in the `context/` directory and referenced as needed.

## Adding Custom Commands

Place `.md` files in the `commands/` directory to create custom slash commands. See the [Claude Code documentation](https://github.com/anthropics/claude-code) for details on creating commands.
