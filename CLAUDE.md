# Claude Code Configuration

This file contains project-specific instructions for Claude Code when working on the Systing project.

## Build Commands

When making changes to this project, always run the following commands in order:

### 1. Format Code
```bash
cargo fmt
```

### 2. Build (Default Features)
```bash
cargo build
```

### 3. Build with pystacks feature
```bash
cargo build --features pystacks
```

### 4. Run Tests
```bash
cargo test
```

### 5. Run Clippy (Linter)
```bash
cargo clippy -- -D warnings
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
2. Run `cargo fmt` to format the code
3. Build with default features: `cargo build`
4. Build with pystacks feature: `cargo build --features pystacks`
5. Run all tests: `cargo test`
6. Run clippy for linting: `cargo clippy -- -D warnings`

All commands must pass before considering the work complete.

## Testing Strategy

- Run the full test suite with `cargo test`
- Ensure both feature configurations build successfully
- Address any clippy warnings before completion

## Code Style

- Use `cargo fmt` for consistent formatting
- Follow Rust idioms and best practices
- Address all clippy warnings
