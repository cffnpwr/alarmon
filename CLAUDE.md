# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

alarmon is a Rust implementation of a TUI-based network monitoring tool based on the [deadman](https://github.com/upa/deadman) concept. The project is structured as a Cargo workspace with three main components:

- **Main binary (`alarmon`)**: TUI-based network monitoring application with real-time ping and traceroute monitoring
- **`pcap` crate**: Cross-platform packet capture library with libpcap backend support
- **`tcpip` crate**: TCP/IP packet parsing library for Ethernet, IPv4, ARP, and ICMP protocols

## Architecture

### Workspace Structure
The project uses Cargo workspace configuration with shared dependencies (anyhow, thiserror) and consistent package metadata across all crates.

### Key Components
- **TUI Interface**: Real-time monitoring display using `ratatui` and `crossterm`
- **Worker Pool**: Asynchronous worker system for parallel ping and traceroute operations
- **Configuration Management**: TOML-based configuration with flexible target specification
- **Packet Capture**: Uses the `pcap` crate with feature-gated backends (libpcap, netmap, pcap-rs, ebpf, dpdk)
- **Protocol Parsing**: The `tcpip` crate implements parsing for network protocols using a `TryFromBytes` trait pattern
- **Network Utilities**: Platform-specific network interface management and ARP table operations

### Current Implementation
The main application implements a TUI-based network monitoring system that:
- Loads monitoring targets from TOML configuration files
- Manages worker pools for ping and traceroute operations
- Provides real-time monitoring display with status updates
- Supports both ping (ICMP Echo) and traceroute functionality
- Uses platform-specific network interface discovery (Netlink on Linux, socket2 on macOS)
- Implements ARP table resolution for network topology discovery

## Development Commands

### Build and Run

```bash
# Build the project
cargo build

# Build with release optimizations
cargo build --release

# Run the main application (requires network interface access)
cargo run

# Run with specific configuration file
cargo run -- --config config.toml

# Run with debug logging
RUST_LOG=debug cargo run

# Run with tokio console for async debugging
TOKIO_CONSOLE=1 cargo run

# Run specific crate examples or binaries
cargo run -p pcap --example <example_name>
```

### Code Quality

```bash
# Check code for errors without building
cargo check

# Format code according to rustfmt.toml configuration
cargo fmt

# Run clippy linter
cargo clippy

# Run all tests
cargo test

# Run individual workspace tests
cargo test -p pcap
cargo test -p tcpip
cargo test -p alarmon

# Run specific test functions
cargo test <test_name>

# Measure code coverage
cargo llvm-cov

# Run tests with output
cargo test -- --nocapture

# Run tests in single thread (for debugging)
cargo test -- --test-threads=1
```

### Platform-Specific Dependencies
- **libpcap development libraries**: Required for packet capture functionality
- **Administrator privileges**: Required for network interface access and raw socket operations
- **Platform-specific**: 
  - Linux: `rtnetlink` for Netlink communication, `nix` for system calls
  - macOS: `nix`, `socket2`, `libc` for socket operations and interface management

### Key Dependencies
- **TUI**: `ratatui` for terminal UI, `crossterm` for terminal control
- **Async Runtime**: `tokio` with console-subscriber for debugging
- **Configuration**: `serde` and `toml` for configuration management
- **CLI**: `clap` for command-line argument parsing
- **Error Handling**: `color-eyre` for comprehensive error reporting
- **Performance**: `fxhash` for optimized hash operations, `parking_lot` for efficient synchronization

## Code Style

- Uses `.editorconfig` with 4-space indentation for Rust files, 2-space for others
- Follows rustfmt configuration with `StdExternalCrate` import grouping and `Module` granularity
- Uses nightly Rust toolchain (configured in mise.toml)

### Modern Rust Module Organization (Rust 2018+)

- **Avoid `mod.rs`**: No longer required for modules with submodules
- **Flexible module layout**: Can have both `foo.rs` and `foo/` directory for the same module
- **Direct submodule placement**: Submodules can be placed directly in `foo/bar.rs` without needing `mod.rs`
- **Simplified imports**: `extern crate` is no longer needed in most cases
- **Consistent path resolution**: Use `crate::` prefix for referencing items within the current crate
- **External crate references**: `::` prefix exclusively references external crates

#### Preferred Module Structure Example:
```
src/
├── lib.rs
├── core.rs           # Instead of core/mod.rs
├── core/
│   ├── monitor.rs
│   └── config.rs
├── tui.rs            # Instead of tui/mod.rs
└── tui/
    ├── display.rs
    └── event.rs
```

#### Import Guidelines:
- Use `crate::` for internal crate references
- Remove unnecessary `extern crate` declarations
- Organize imports with `use` statements following rustfmt configuration

## Configuration Management

The application uses TOML configuration files for flexible monitoring setup:

```toml
[ping]
targets = ["8.8.8.8", "1.1.1.1"]
interval = 1000  # milliseconds

[traceroute]
targets = ["8.8.8.8"]
interval = 5000  # milliseconds
max_hops = 30
```

### Configuration Options
- **ping.targets**: Array of IP addresses to monitor with ping
- **ping.interval**: Ping interval in milliseconds
- **traceroute.targets**: Array of IP addresses to traceroute
- **traceroute.interval**: Traceroute interval in milliseconds
- **traceroute.max_hops**: Maximum number of hops for traceroute

## TUI Usage

The application provides a real-time terminal interface with:

- **Ping monitoring**: Real-time ping status and latency display
- **Traceroute visualization**: Network path discovery and hop analysis
- **Status indicators**: Color-coded status for network reachability
- **Dynamic updates**: Live updating of monitoring results

### TUI Controls
- **q**: Quit the application
- **Tab**: Switch between different monitoring views
- **Arrow keys**: Navigate through monitoring results

## Tool Management

The project uses mise.toml for development tool management with:

- `rust = "nightly"`: Required for const trait implementations
- `cargo-expand = "latest"`: For macro expansion debugging
- `cargo-llvm-cov = "latest"`: For code coverage measurement
- `cargo-watch = "latest"`: For development file watching

## Language Usage

- User-facing messages (CLI output, error messages) are written in Japanese
- Code comments and internal documentation use English
- Test descriptions use Japanese with `[正常系]` and `[異常系]` prefixes

## Development Workflow

### Issue-Based Development
- **ALWAYS create an Issue before starting any development work**
- Use existing Issue format: 概要, 背景, 実装要件, 受け入れ条件, テスト要件
- Include appropriate labels for categorization

#### Sub-Issue Management
GitHub's sub-issue feature allows breaking down large work into smaller, manageable tasks with hierarchical structure.

**Sub-Issue API Operations via GitHub CLI:**
```bash
# List sub-issues for a parent issue
gh api repos/{owner}/{repo}/issues/{issue_number}/sub_issues

# Add existing issue as sub-issue
gh api -X POST repos/{owner}/{repo}/issues/{issue_number}/sub_issues -f sub_issue_id={sub_issue_id}

# Remove sub-issue from parent
gh api -X DELETE repos/{owner}/{repo}/issues/{issue_number}/sub_issue -f sub_issue_id={sub_issue_id}

# Reprioritize sub-issue position
gh api -X PATCH repos/{owner}/{repo}/issues/{issue_number}/sub_issues/priority -f sub_issue_id={sub_issue_id} -f after_id={after_id}
```

**Sub-Issue Guidelines:**
- Use sub-issues for complex features requiring multiple implementation steps
- Maximum 100 sub-issues per parent issue, up to 8 levels of nesting
- Sub-issues provide visual progress tracking with `sub_issues_summary` data
- Cross-repository sub-issues are supported
- Requires "triage" permissions for sub-issue operations

### Branch Naming Convention
- Branch names MUST follow the pattern: `feature/[Issue番号]`
- Examples: `feature/11`, `feature/23`
- **ALWAYS create branches from the latest main branch**
- Before creating a new branch, ensure you are on main and pull the latest changes

### Pull Request Process
- Create PRs only after completing the implementation
- PR titles should clearly describe the changes
- Link the corresponding Issue in the PR description
- **ALWAYS write PR descriptions in 常態 (declarative/constant tense) in Japanese**
- Ensure all CI/CD checks pass before requesting review

### GitHub Actions CI/CD
- All PRs automatically trigger CI/CD pipeline
- Required checks: cargo build, cargo test, cargo clippy
- Code coverage measurement with cargo llvm-cov
- PRs can only be merged when all checks pass

## Performance Optimization

The application uses several optimization strategies:

- **FxHashMap**: Uses `fxhash` instead of standard HashMap for better performance
- **Parking Lot**: Efficient synchronization primitives for reduced contention
- **Async Worker Pool**: Parallel processing of monitoring tasks
- **Efficient Memory Management**: Reuses buffers and minimizes allocations

## Error Handling

The project uses `color-eyre` for comprehensive error reporting:
- Structured error types with context
- Color-coded error output in development
- Detailed stack traces for debugging
- Graceful error recovery in production

## Protocol Implementation Pattern

Network protocols are implemented using the `TryFromBytes` trait in the `tcpip` crate, which provides a consistent interface for parsing byte streams into structured packet types.

### Implementation Requirements
- All protocol structs must implement bidirectional conversion: `TryFrom<&[u8]>` and `Into<Vec<u8>>`
- Error handling uses `thiserror` for structured error definitions
- Modular design with submodules for each protocol component (header, address, etc.)
- Comprehensive validation during parsing with detailed error messages

### Current Protocol Support
- **Ethernet**: Frame parsing with EtherType identification and VLAN tag support
- **IPv4**: Header parsing with protocol field extraction, flags, and type of service
- **ARP**: Complete Request/Reply packet parsing and generation for Ethernet/IPv4
- **ICMP**: Basic message structure parsing (foundation only)

### Testing Guidelines
- Implement only the minimum necessary tests to achieve C1 coverage
- Group test functions by the target function being tested
- Add descriptive comments for test cases using `[正常系] description` or `[異常系] description` format
- Consolidate tests for a single function into one test function (e.g., `test_function_name()`)
- Within the test function, separate test cases with comments describing each scenario

# important-instruction-reminders
Do what has been asked; nothing more, nothing less.
NEVER create files unless they're absolutely necessary for achieving your goal.
ALWAYS prefer editing an existing file to creating a new one.
NEVER proactively create documentation files (*.md) or README files. Only create documentation files if explicitly requested by the User.