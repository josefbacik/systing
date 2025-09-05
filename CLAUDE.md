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
