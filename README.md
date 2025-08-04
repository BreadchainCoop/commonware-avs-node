# Commonware AVS Node

Please see [the following repo](https://github.com/BreadchainCoop/commonware-avs-router.git) for context on how to use this repo.

## Setup

```sh
cp example.env .env 
```

## Development

### Prerequisites

- Rust (stable toolchain)

### Development Workflow

This project uses automated linting and formatting. Before committing code, ensure it passes all quality checks:

```bash
# Format code
cargo fmt

# Run linter
cargo clippy --all-targets --all-features -- -D warnings

# Run tests
cargo test

# Security audit
cargo audit
```

### Code Quality

The project enforces strict code quality standards:

- **Formatting**: Code must be formatted with `rustfmt` using the project's configuration
- **Linting**: All code must pass `clippy` checks with additional custom lints
- **Testing**: All tests must pass
- **Security**: Dependencies are audited for security vulnerabilities

### CI/CD

The project uses GitHub Actions for continuous integration. The CI pipeline runs:

1. **Format Check**: Ensures all code is properly formatted
2. **Lint Check**: Runs clippy with strict linting rules
3. **Build & Test**: Compiles and runs all tests
4. **Security Audit**: Checks for security vulnerabilities
5. **Coverage**: Generates code coverage reports

All checks must pass before code can be merged.

## Contributor 1
```bash
source .env
cargo run --release -- --key-file $CONTRIBUTOR_1_KEYFILE --port 3001 --orchestrator orchestrator.json 
```

## Contributor 2
```bash
source .env
cargo run --release -- --key-file $CONTRIBUTOR_2_KEYFILE --port 3002 --orchestrator orchestrator.json 

```

## Contributor 3
```bash
source .env
cargo run --release -- --key-file $CONTRIBUTOR_3_KEYFILE --port 3003 --orchestrator orchestrator.json 
```
