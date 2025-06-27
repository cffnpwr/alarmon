# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

deadman-rs is a Rust implementation of the [deadman](https://github.com/upa/deadman) network monitoring tool. The project is structured as a Cargo workspace with three main components:

- **Main binary (`deadman`)**: The primary application that captures and processes network packets
- **`pcap` crate**: Cross-platform packet capture library with libpcap backend support
- **`tcpip` crate**: TCP/IP packet parsing library for Ethernet, IPv4, ARP, and ICMP protocols

## Architecture

### Workspace Structure
The project uses Cargo workspace configuration with shared dependencies (anyhow, thiserror) and consistent package metadata across all crates.

### Key Components
- **Packet Capture**: Uses the `pcap` crate with feature-gated backends (libpcap, netmap, pcap-rs, ebpf, dpdk)
- **Protocol Parsing**: The `tcpip` crate implements parsing for network protocols using a `TryFromBytes` trait pattern
- **Async Runtime**: Main application uses Tokio for asynchronous packet processing

### Current Implementation
The main application implements an ARP resolver that:
- Accepts an IPv4 address as command line argument
- Uses Netlink-based network interface information retrieval to find appropriate interface
- Sends ARP request packets via the determined network interface
- Listens for ARP reply packets with timeout mechanism
- Resolves target IP addresses to MAC addresses using Ethernet/IPv4 ARP protocol

## Development Commands

### Build and Run

```bash
# Build the project
cargo build

# Build with release optimizations
cargo build --release

# Run the main application (requires network interface access)
cargo run

# Run with specific target IP address
cargo run -- 192.168.1.1

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
cargo test -p deadman

# Run specific test functions
cargo test <test_name>

# Measure code coverage
cargo llvm-cov
```

### Platform-Specific Dependencies
- **libpcap development libraries**: Required for packet capture functionality
- **Administrator privileges**: Required for network interface access
- **Platform-specific**: 
  - Linux: `rtnetlink` for Netlink communication
  - macOS: `nix`, `socket2`, `libc` for socket operations

## Code Style

- Uses `.editorconfig` with 4-space indentation for Rust files, 2-space for others
- Follows rustfmt configuration with `StdExternalCrate` import grouping and `Module` granularity
- Uses nightly Rust toolchain (configured in mise.toml)

## Tool Management

The project uses mise.toml for development tool management with:

- `rust = "nightly"`: Required for const trait implementations
- `cargo-expand = "latest"`: For macro expansion debugging
- `cargo-llvm-cov = "latest"`: For code coverage measurement

## Language Usage

- User-facing messages (CLI output, error messages) are written in Japanese
- Code comments and internal documentation use English
- Test descriptions use Japanese with `[正常系]` and `[異常系]` prefixes

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

# important-instruction-reminders
Do what has been asked; nothing more, nothing less.
NEVER create files unless they're absolutely necessary for achieving your goal.
ALWAYS prefer editing an existing file to creating a new one.
NEVER proactively create documentation files (*.md) or README files. Only create documentation files if explicitly requested by the User.