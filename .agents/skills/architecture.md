---
description: Code architecture overview for AETHER_01
alwaysApply: false
---

# Architecture

High-level architecture of AETHER_01 MCP server.

## Layered Architecture

```
MCP Client (stdin)
   │ JSON-RPC
   ▼
server.rs ──→ tools/*.rs ──→ Win32 API / SafeCommand
   │               │
   ├── audit.rs    ├── command.rs (SafeCommand)
   ├── error.rs    ├── common.rs (shared helpers)
   └── config.rs
```

## Key Types

| Type | Location | Purpose |
|------|----------|---------|
| `AetherServer` | `server.rs` | Main server struct with `ToolRouter` |
| `AetherError` | `error.rs` | Typed errors with Win32 code translation |
| `SafeCommand` | `command.rs` | Secure external command builder |
| `ParamType` | `command.rs` | Parameter validation enum (Path, Name, etc.) |
| `FeatureGates` | `config.rs` | Feature gate bitmask from `.env` |

## Tool Handler Signature

Simple (no server state):
```rust
pub fn handle_tool(action: &str, params: Value) -> Result<String, AetherError>
```

With server state:
```rust
pub fn handle_tool(server: &AetherServer, action: &str, params: Value) -> Result<String, AetherError>
```

## Security Flow

1. JSON-RPC message arrives at `server.rs`
2. `#[tool_router]` dispatches to the correct tool handler
3. Handler validates `force: true` for destructive ops
4. Handler checks feature gates (if applicable)
5. Handler validates parameters via `ParamType`
6. Handler executes via Win32 API or `SafeCommand`
7. Audit logged to stderr via `audit::log_*`
8. Result returned as JSON string
