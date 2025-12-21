# Tor-like Onion Routing System

[![CI](https://github.com/asaft29/mini-tor/actions/workflows/ci.yml/badge.svg)](https://github.com/asaft29/mini-tor/actions/workflows/ci.yml)

**Bachelor's Thesis (Licență)** - Simplified Tor-like onion routing implementation in Rust

## Overview

This project implements a simplified version of the Tor anonymity network for educational purposes. It demonstrates three-layer onion encryption, circuit building, and anonymous communication through relay nodes.

### System Architecture

```
Client (SOCKS5) → Entry Node → Middle Node → Exit Node → Destination
     └─────────── 3-layer encryption ─────────┘
```

## Project Status

| Component | Status | Description |
|-----------|--------|-------------|
| **Discovery Service** | ✅ Complete | REST API for node registry and path selection |
| **Relay Nodes** | ✅ Complete | Entry/Middle/Exit node implementations |
| **Common Library** | ✅ Complete | Shared types, protocol, and crypto |
| **Tor Client** | ❌ Not Started | SOCKS5 proxy with circuit management |

**Overall Progress:** ~70% complete

## Quick Start

### Prerequisites

- Rust 1.92.0 or later
- Docker (optional)

### Running the System

```bash
# 1. Start Discovery Service
cargo run -p discovery

# 2. Start Relay Nodes (in separate terminals)
cargo run -p relay-node -- --type entry --port 9001 --directory-url http://localhost:8080
cargo run -p relay-node -- --type middle --port 9002 --directory-url http://localhost:8080
cargo run -p relay-node -- --type exit --port 9003 --directory-url http://localhost:8080

# 3. Test Discovery API
curl http://localhost:8080/api/nodes
curl http://localhost:8080/api/nodes/random?count=3

# 4. View API Documentation
open http://localhost:8080/swagger-ui
```

### Building

```bash
# Build all services
cargo build --release

# Run tests
cargo test --workspace

# Run quality checks
cargo clippy --workspace --all-targets --all-features
```

## Project Structure

```
licenta/
├── services/
│   ├── common/              # Shared library (types, protocol, crypto)
│   ├── discovery/           # Directory service (REST API)
│   ├── relay-node/          # Relay node service (Entry/Middle/Exit)
│   └── tor-client/          # SOCKS5 proxy client (to be implemented)
├── doc/                     # Documentation
│   ├── TOR_FLOW_EXPLAINED.md
│   └── diagrams/
├── CLAUDE.md                # AI assistant guidelines
├── PROJECT_STATUS.md        # Detailed implementation status
├── CODING_RULES.md          # Safety and coding standards
└── Cargo.toml               # Workspace configuration
```

## Key Features

- **Strict Safety Rules:** No `unwrap()`, `expect()`, `panic!()`, or unsafe indexing
- **Type-Safe Protocol:** Strong typing for security-critical components
- **Modern Async:** Built on Tokio with async/await
- **REST-Based Discovery:** HTTP API instead of distributed consensus
- **OpenAPI Documentation:** Auto-generated Swagger UI
- **CI/CD:** Automated testing, linting, and security audits

## Documentation

- **[CLAUDE.md](CLAUDE.md)** - Complete project guide and implementation plan
- **[PROJECT_STATUS.md](PROJECT_STATUS.md)** - Detailed status (617 lines)
- **[TOR_FLOW_EXPLAINED.md](doc/TOR_FLOW_EXPLAINED.md)** - Technical flow (981 lines)
- **[CODING_RULES.md](CODING_RULES.md)** - Safety requirements

## Development

### Coding Standards

This project enforces strict clippy lints to ensure reliability:

```toml
[workspace.lints.clippy]
unwrap_used = "deny"       # Use .ok_or(...)?
expect_used = "deny"       # Use .ok_or_else(...)?
panic = "deny"             # Return errors instead
indexing_slicing = "deny"  # Use .get(...).ok_or(...)?
```

All errors must be handled gracefully - services must never crash unexpectedly.

### Testing

```bash
# Run all tests
cargo test --workspace

# Run specific service tests
cargo test -p common
cargo test -p discovery
cargo test -p relay-node

# Run with logging
RUST_LOG=debug cargo test -- --nocapture
```

### CI/CD Pipeline

The GitHub Actions workflow runs on every push and PR:

- ✅ Compilation check
- ✅ Test suite (18 tests)
- ✅ Clippy with strict rules + pattern verification
- ✅ Rustfmt check
- ✅ Security audit (cargo-audit)
- ✅ Documentation build
- ✅ Release build (artifacts uploaded)

## Next Steps

The main remaining work is implementing the **Tor Client** component:

1. SOCKS5 proxy server (port 1080)
2. Circuit manager (build and maintain circuit pool)
3. Stream manager (map connections to circuits)
4. 3-layer onion encryption/decryption
5. Directory client (fetch paths from discovery service)

See [CLAUDE.md](CLAUDE.md) for detailed implementation plan.

## License

Educational project for bachelor's thesis.

## Acknowledgments

- Based on the [Tor Project](https://www.torproject.org/) design
- Uses `tor-llcrypto` for cryptographic primitives
- Built with Rust ecosystem tools (Tokio, Axum, etc.)