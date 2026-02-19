# Contributing to mcpmap

## Requirements

- Rust 1.85+ (edition 2024)
- Docker (optional, for integration tests)

## Building

```bash
cargo build
```

## Testing

```bash
# Unit tests + integration tests (no Docker required)
cargo test --lib --test integration_test

# All tests including Docker-based integration tests
cargo test
```

## Code Quality

All contributions must pass:

```bash
# Formatting
cargo fmt --check

# Linting (zero warnings)
cargo clippy --all-targets -- -D warnings

# Tests
cargo test --lib --test integration_test
```

## Pull Requests

1. Fork the repository
2. Create a feature branch from `main`
3. Ensure `cargo fmt`, `cargo clippy`, and `cargo test` pass
4. Submit a PR with a clear description of the change

## Security

If you discover a security vulnerability, please report it via [GitHub Security Advisories](https://github.com/canack/mcpmap/security/advisories/new) instead of opening a public issue.
