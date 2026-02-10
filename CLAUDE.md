# Claude Development Guide

This document contains information for Claude (AI assistant) when working on the systing codebase.

## Project Information

- **Language**: Rust
- **Build Tool**: Cargo
- **Main Binary**: systing
- **Built-in support**: Python stack tracing (pystacks) is always compiled in, enabled at runtime with `--collect-pystacks`

## Running Tests

### Unit Tests

Regular unit tests can be run without privileges:

```bash
cargo test
```

### Integration Tests

Integration tests require root/BPF privileges and are marked as `#[ignore]` in the test suite.

**To run integration tests, use the dedicated script:**

```bash
./scripts/run-integration-tests.sh
```

**Usage patterns:**

```bash
# Run all ignored integration tests
./scripts/run-integration-tests.sh

# Run specific test file
./scripts/run-integration-tests.sh trace_validation

# Run specific test within a file
./scripts/run-integration-tests.sh trace_validation test_e2e_parquet_validation

```

**Why use the script:**
- Builds test binaries as the current user (avoids root-owned build artifacts)
- Only runs the compiled test binary with sudo
- Preserves environment variables (like DEBUGINFOD_URLS, PATH)
- Properly handles the `--ignored` flag to run tests that require privileges

**Do NOT use:**
- `cargo test --test '*'` - This only runs non-ignored tests
- `sudo cargo test` - This creates root-owned build artifacts

## Pystacks Architecture

Pystacks provides Python stack tracing via BPF. It is always compiled in but only active when `--collect-pystacks` is passed. The implementation is split into:

- **BPF kernel code** (`src/pystacks/bpf/`) - C code compiled by clang for BPF, walks Python frames in-kernel
- **Rust userspace code** (`src/pystacks/`) - Process discovery, symbol resolution, line table parsing

Key modules:
- `types.rs` - `#[repr(C)]` structs matching BPF map key/value layouts
- `offsets.rs` - Python version-specific struct offset configurations (3.8-3.13)
- `discovery.rs` - Detects Python processes, parses ELF binaries for version and runtime info
- `symbols.rs` - Resolves BPF symbol IDs to function names and source locations
- `linetable.rs` - Parses Python line number tables (3.10 lnotab and 3.11+ location table formats)
- `process.rs` - Reads process memory via `/proc/pid/mem`
- `stack_walker.rs` - High-level API integrating all components

No C++ dependencies or external submodules required.

## Git Hooks

This repository uses shared git hooks to automatically enforce code formatting and linting. The hooks are tracked in the `hooks/` directory.

### Setup for New Developers

After cloning the repository, run:

```bash
./setup-hooks.sh
```

Or manually:

```bash
git config core.hooksPath hooks
```

### Active Hooks

- **pre-commit**: Runs comprehensive checks before each commit:
  - `cargo fmt --check`
  - `cargo clippy`
  - `cargo test`
  - Note: Integration tests run in CI only (GitHub Actions), not in the pre-commit hook

## Temporary Files and Scratch Work

**IMPORTANT**: All temporary files, scratch scripts, and working files MUST be placed in the `./scratch` directory.

This includes:
- Temporary .md files
- Test/scratch .py scripts
- Test/scratch .sh scripts
- Any experimental or temporary work files

**DO NOT** create these types of files in the project root unless explicitly asked by the user.

## Project Structure

- `scripts/` - Helper scripts including `run-integration-tests.sh`
- `tests/` - Integration tests (many require root privileges)
- `src/` - Main source code
- `hooks/` - Shared git hooks
- `scratch/` - Temporary and experimental files
- `.claude/` - Claude Code configuration
  - `.claude/context/` - Additional context documentation
    - `stack-trace-schema.md` - Stack trace storage schema
    - `network-schema.md` - Network event schema
    - `perfetto-reference.md` - Perfetto format reference
    - `perfetto-messages.md` - Perfetto message definitions
