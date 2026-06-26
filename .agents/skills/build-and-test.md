---
description: Build, test, and lint the AETHER_01 MCP server
alwaysApply: false
---

# Build & Test

Build the AETHER_01 MCP server from source and run the full test suite.

## Preparation

Before building, ensure `CARGO_HOME` is set:

```powershell
$env:CARGO_HOME = ".\\.cargo_home"
```

## Build

```powershell
# Quick verification (recommended during development)
cargo check

# Debug build
cargo build

# Release build (hardened: CFG, ASLR, DEP, static CRT, LTO, strip)
cargo build --release
```

## Test

```powershell
# Full test suite (thread-safe)
cargo test -- --test-threads=1

# Unit tests only
cargo test --lib

# Integration tests only
cargo test --test "*"
```

## Lint

```powershell
# Format check
cargo fmt --all -- --check

# Clippy (zero warnings required)
cargo clippy -- -D clippy::all -D clippy::pedantic

# Install audit tools (first time only)
cargo install cargo-audit cargo-deny

# Security audit
cargo audit

# License compliance
cargo deny check
```

## Run Locally

```powershell
# Start the server (waits for MCP messages on stdin)
cargo run

# Test with a JSON-RPC message
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | .\target\debug\aether-mcp-server.exe
```

## Common Issues

| Symptom | Solution |
|---------|----------|
| `linker `link.exe` not found` | Install Visual Studio MSVC tools or run from `x64 Native Tools Command Prompt` |
| `error[A0400]: cannot find crate` | Run `cargo fetch` or check `CARGO_HOME` env var |
| `windows crate errors` | Ensure Rust target is `x86_64-pc-windows-msvc` (run `rustup target add x86_64-pc-windows-msvc`) |
