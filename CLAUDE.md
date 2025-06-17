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
The main application currently captures Ethernet frames, filters for IPv4 packets, and prints basic packet information (src, dst, protocol).

## Development Commands

### Build and Run
```bash
# Build the project
cargo build

# Build with release optimizations
cargo build --release

# Run the main application (requires network interface access)
cargo run
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
```

### Dependencies
The project requires libpcap development libraries for packet capture functionality. Installation varies by platform as documented in README.md.

## Code Style

- Uses `.editorconfig` with 4-space indentation for Rust files, 2-space for others
- Follows rustfmt configuration with `StdExternalCrate` import grouping and `Module` granularity
- Uses nightly Rust toolchain (configured in mise.toml)

## Protocol Implementation Pattern

Network protocols are implemented using the `TryFromBytes` trait in the `tcpip` crate, which provides a consistent interface for parsing byte streams into structured packet types.