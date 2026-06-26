# GitHub Copilot Instructions — AETHER_01

## Project Overview

AETHER_01 is a Rust-based MCP (Model Context Protocol) server for Windows 10/11 administration. It communicates via stdio JSON-RPC and exposes 10 tools for process, file, registry, service, GUI, system info, network, user, security, and automation management.

## Coding Guidelines

### DO NOT
- Never use `cmd.exe` or `powershell.exe` for system operations — use Win32 API
- Never print to stdout (MCP uses it for JSON-RPC)
- Never use `windows::core::*` (shadows `Result`)
- Never use raw `std::process::Command` — use `SafeCommand`
- Never modify `mcp.json` or `.env` without explicit user request

### ALWAYS
- Add `// SAFETY:` comments on every `unsafe` block
- Use `.map_err(|e| AetherError::win32(e))?` on Win32 API calls
- Check `force: true` for destructive operations
- Log all actions via `audit::log_*`
- Validate external command parameters with `ParamType`
- Use `// ════` section separators in tool files
- Order imports: std → external crates → local crate

## Build & Test

```powershell
$env:CARGO_HOME = ".\\.cargo_home"
cargo check
cargo test -- --test-threads=1
```

## Key Types

| Type | Location | Purpose |
|------|----------|---------|
| `AetherServer` | `server.rs` | Server with tool router |
| `AetherError` | `error.rs` | Typed errors |
| `SafeCommand` | `command.rs` | Secure command runner |
| `ParamType` | `command.rs` | Parameter validation |
| `FeatureGates` | `config.rs` | Feature flags |

## Tool Template

```rust
pub fn handle_*(action: &str, params: Value) -> Result<String, AetherError> {
    let ctx = ErrorContext::new("tool_name", action);
    match action {
        "action_name" => { /* validate → execute → audit */ }
        _ => Err(AetherError::invalid_param(ctx, "..."))
    }
}
```
