# Development Guide

## Prerequisites

- **Rust 1.85+** (install via [rustup](https://rustup.rs/))
- **Windows 10/11 x86-64** (MSVC target)
- **Git**

---

## Setup

```powershell
# Clone the repository
git clone https://github.com/foursecondfivefour/aether-mcp-server.git
cd aether-mcp-server

# Create default configuration
Copy-Item .env.example .env

# Verify compilation
$env:CARGO_HOME = ".\\.cargo_home"
cargo check
```

---

## Development Workflow

### Building

```powershell
# Quick check (recommended during development)
cargo check

# Debug build
cargo build

# Release build (hardened: CFG, ASLR, DEP, static CRT, LTO, strip)
cargo build --release
```

The release profile is optimized for security and performance:

```toml
[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
panic = "abort"
strip = "symbols"
```

### Testing

```powershell
# Run all tests
cargo test -- --test-threads=1

# Run only unit tests
cargo test --lib

# Run only integration tests
cargo test --test "*"
```

### Linting

```powershell
# Format check
cargo fmt --all -- --check

# Clippy
cargo clippy -- -D clippy::all -D clippy::pedantic

# Full audit
cargo audit
cargo deny check
```

### Running Locally

```powershell
# Start the server (it will wait for MCP messages on stdin)
cargo run

# Test with a JSON-RPC message
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | .\target\debug\aether-mcp-server.exe
```

---

## Code Style

### Rust Conventions

- `snake_case` for functions, variables, and modules
- `PascalCase` for types, enums, and traits
- `SCREAMING_CASE` for constants
- Doc comments (`///`) on all public items
- `// SAFETY:` comments on every `unsafe` block
- Line width: 120 characters

### File Structure

- One tool = one file in `src/tools/`
- Section separators use `// ═══════════════════════` pattern
- Imports ordered: `std` → external crates → local crate
- Named constants for magic strings and numbers

### Tool Patterns

Every tool function follows this pattern:

```rust
pub fn handle_*(
    action: &str,
    params: serde_json::Value,
) -> Result<String, AetherError> {
    let ctx = ErrorContext::new("tool_name", action);
    match action {
        "action_name" => { /* implementation */ }
        _ => Err(AetherError::invalid_param(ctx, "Unknown action"))
    }
}
```

### Secure Command Execution

Always use `SafeCommand` for external commands — never raw `std::process::Command`:

```rust
// ✅ Correct
let output = SafeCommand::new("icacls", "file_system", "acl_get")
    .timeout(15)
    .arg(path, ParamType::Path)?
    .output()?;

// ❌ Wrong — never use this
// let output = Command::new("icacls").args([...]).output()?;
```

### Dangerous Operations

Every destructive operation must:

1. Check for `force: true` in parameters
2. Log via `audit::log_forced()` on success
3. Log all security events via `audit::log_security()`

---

## Adding a New Tool

1. Create `src/tools/new_tool.rs`
2. Add `pub fn handle_new_tool(...)` with action dispatch
3. Register in `src/tools/mod.rs` (`pub mod new_tool;`)
4. Add tool method in `src/server.rs` with `#[tool(description = "...")]`
5. Add audit logging for all actions
6. Add feature gates if the tool has dangerous capabilities
7. Update documentation (README.md, ARCHITECTURE.md)

---

## Testing Guidelines

### Unit Tests

- Test error paths (invalid params, missing force, feature gate disabled)
- Test valid dispatch for each action
- No Win32 API calls in unit tests (use mock-friendly patterns)

### Integration Tests

- Test tool dispatch end-to-end
- Run with `--test-threads=1` to avoid race conditions
- Keep tests safe — no destructive operations

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RUST_LOG` | `info` | Log level (trace, debug, info, warn, error) |
| `AETHER_BCD_EDIT` | `0` | Enable BCD editing |
| `AETHER_HAL_CONFIG` | `0` | Enable HAL/crash dump config |
| `AETHER_OFFLINE_REGISTRY` | `0` | Enable offline registry |
| `AETHER_DLL_INJECT` | `0` | Enable DLL injection |
| `AETHER_TOKEN_MANIPULATION` | `0` | Enable token manipulation |
| `AETHER_LSA_SECRETS` | `0` | Enable LSA secrets access |

---

## Release Process

1. Update version in `Cargo.toml`
2. Update `CHANGELOG.md` with new version notes
3. Run full test suite: `cargo test -- --test-threads=1`
4. Build release: `cargo build --release`
5. Verify binary SHA256
6. Create GitHub release with tag
7. Update `install.ps1` with new binary URL and SHA256
