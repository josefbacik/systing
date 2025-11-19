# Claude Code Configuration

This file contains project-specific instructions for Claude Code when working on the Systing project.

## Build Commands

When making changes to this project, run the following commands to validate your work:

### 1. Build (Default Features)
```bash
cargo build
```

### 2. Build with pystacks feature
```bash
cargo build --features pystacks
```

### 3. Run Tests
```bash
cargo test
```

### 4. Run Clippy (Linter)
```bash
cargo clippy --all-targets -- -D warnings
```

### 5. Format Code (BEFORE COMMITTING)
```bash
cargo fmt
```

## Project Information

- **Language**: Rust
- **Features**:
  - `pystacks` - Optional Python stack tracing support
  - `generate-vmlinux-header` - Optional VMLinux header generation
- **Build Tool**: Cargo
- **Main Binary**: systing

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

## Development Workflow

1. Make your code changes
2. Build with default features: `cargo build`
3. Build with pystacks feature: `cargo build --features pystacks`
4. Run all tests: `cargo test`
5. Run clippy for linting: `cargo clippy --all-targets -- -D warnings`
6. **Run `cargo fmt` before committing** to ensure consistent formatting

**Note:** All commands must pass before considering the work complete. Running `cargo fmt` is MANDATORY before any commit to prevent whitespace errors.

## Testing Strategy

- Run the full test suite with `cargo test`
- Ensure both feature configurations build successfully
- Address any clippy warnings before completion

## Code Style

- Use `cargo fmt` for consistent formatting
- Follow Rust idioms and best practices
- Address all clippy warnings

## Before Committing

**MANDATORY pre-commit checklist:**
1. Run `cargo build` - must compile without errors
2. Run `cargo build --features pystacks` - must compile with features
3. Run `cargo test` - all tests must pass
4. Run `cargo clippy --all-targets -- -D warnings` - no warnings allowed
5. **Run `cargo fmt`** - apply formatting to prevent whitespace errors

⚠️ **IMPORTANT**: Always run `cargo fmt` as the LAST step before committing to ensure consistent formatting.

## Git Hooks

This repository uses shared git hooks to automatically enforce code formatting and linting. The hooks are tracked in the `hooks/` directory and shared with all developers.

### Setup for New Developers

After cloning the repository, run the setup script to enable the hooks:

```bash
./setup-hooks.sh
```

Alternatively, you can manually configure the hooks:

```bash
git config core.hooksPath hooks
```

### Active Hooks

- **pre-commit**: Runs `cargo fmt --check` before each commit. Fast feedback on formatting issues.
- **pre-push**: Runs comprehensive checks before each push:
  - `cargo fmt --check` - Verifies code formatting
  - `cargo clippy --all-targets --no-default-features -- -D warnings`
  - `cargo clippy --all-targets --features pystacks -- -D warnings`
  - `cargo test --no-default-features`
  - `cargo test --features pystacks`

These hooks ensure that improperly formatted, non-compliant, or failing code cannot be committed or pushed to the repository.

**If a hook fails:**

1. For formatting issues: Run `cargo fmt` to format your code
2. For clippy issues: Fix the warnings/errors reported by clippy
3. For test failures: Fix the failing tests
4. Stage your changes with `git add` (if needed)
5. Try your commit or push again

### Hook Location

The git hooks are stored in the `hooks/` directory (tracked by git) and are shared across all developers. This ensures consistent code quality enforcement for everyone working on the project.
