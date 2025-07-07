# lint

Run cargo clippy with strict linting rules and fix any errors and warnings.

## Usage

```
/lint
```

## Description

This command runs `cargo clippy --all-targets --all-features -- -D warnings` to perform comprehensive linting on the Rust codebase, treating all warnings as errors. It will identify and help fix code quality issues, style violations, and potential bugs.

## Implementation

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

The command uses:
- `--all-targets`: Check all targets (bins, tests, examples, etc.)
- `--all-features`: Enable all available features
- `-- -D warnings`: Treat warnings as errors for stricter checking
