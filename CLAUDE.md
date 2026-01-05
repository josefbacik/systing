# Claude Development Guide

This document contains information for Claude (AI assistant) when working on the systing codebase.

## Project Information

- **Language**: Rust
- **Build Tool**: Cargo
- **Main Binary**: systing
- **Features**:
  - `pystacks` - Optional Python stack tracing support
  - `generate-vmlinux-header` - Optional VMLinux header generation

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

# Run with features enabled
CARGO_FEATURES=pystacks ./scripts/run-integration-tests.sh
```

**Why use the script:**
- Builds test binaries as the current user (avoids root-owned build artifacts)
- Only runs the compiled test binary with sudo
- Preserves environment variables (like DEBUGINFOD_URLS, PATH)
- Properly handles the `--ignored` flag to run tests that require privileges

**Do NOT use:**
- `cargo test --test '*'` - This only runs non-ignored tests
- `sudo cargo test` - This creates root-owned build artifacts

## Generated Files

The `src/pystacks/bindings.rs` file is **generated from C++ headers** using bindgen and is **committed to the repository**. This avoids requiring all developers to have the C++ build dependencies (libfmt-dev, libre2-dev, libcap-dev) installed.

**When to regenerate:**
- After updating the `strobelight-libs` submodule
- After modifying C++ headers that affect the bindings

**How to regenerate:**
```bash
cargo clean
cargo check --features pystacks
git add src/pystacks/bindings.rs
```

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
  - `cargo clippy` (both with and without features)
  - `cargo test` (both with and without features)
  - Integration tests (via `scripts/run-integration-tests.sh`, requires sudo)

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
