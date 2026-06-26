---
description: 
alwaysApply: true
---

# AGENTS.md — AETHER_01

## Project Identity

- **Name**: AETHER_01
- **Type**: MCP (Model Context Protocol) server over stdio
- **Language**: Rust (edition 2021, stable 1.85+)
- **Target**: Windows 10/11 x86-64 MSVC only
- **Transport**: stdio (no HTTP, no SSE)

---

## Stack

| Dependency | Version | Purpose |
|-----------|---------|---------|
| `rmcp` | 0.5 | Official MCP Rust SDK — server, tools, transport |
| `windows` | 0.58 | Win32 API bindings (50+ features) |
| `windows-registry` | 0.3 | High-level registry access |
| `tokio` | 1 | Async runtime |
| `serde` / `serde_json` | 1 | JSON serialization |
| `schemars` | 0.8 | JSON Schema generation for MCP tool params |
| `tracing` | 0.1 | Structured logging |
| `dotenvy` | 0.15 | .env loading |
| `thiserror` | 2 | Error derive macros |
| `chrono` | 0.4 | Timestamps |
| `base64` | 0.22 | Binary encoding (screenshots) |

---

## Build

```powershell
# Dev check
$env:CARGO_HOME = ".\\.cargo_home"
cargo check

# Dev build
cargo build

# Release build (hardened: CFG, ASLR, DEP, static CRT, LTO, strip)
cargo build --release
```

---

## Architecture

```
main.rs
  ├── dotenvy::dotenv()         # Load .env
  ├── tracing_subscriber::fmt() # stderr, no ANSI
  ├── FeatureGates::load()
  ├── AetherServer::new(gates)
  └── serve((stdin, stdout)).await

server.rs
  ├── struct AetherServer { gates, tool_router: ToolRouter<Self> }
  ├── #[tool_router(router = tool_router)]   # 10 tool methods
  └── #[tool_handler(router = self.tool_router)]  # ServerHandler metadata

tools/*.rs
  ├── pub fn handle_*(action, params) -> Result<String, AetherError>
  └── Dispatch: match action { "list" => ..., "kill" => ..., ... }

error.rs
  ├── enum AetherError (thiserror)
  ├── FormatMessageW FFI → win32_description(code: u32) -> String
  └── Helpers: invalid_param, permission_denied, not_found, win32, feature_disabled, wmi_error, internal

command.rs
  ├── struct SafeCommand (builder pattern)
  ├── enum ParamType: Path, Name, RegistryPath, SafeString, Numeric, Text, Guid
  ├── fn run_safe() / fn run_mixed()
  └── Output capping (1 MB), timeout (30s default), audit logging

audit.rs
  ├── fn log_success / log_failure / log_forced / log_security
  ├── fn redact_sensitive() — masks passwords, tokens, secrets in logs
  └── Structured audit to stderr
```

---

## Key Patterns

### Tool Registration (rmcp 0.5)

```rust
#[derive(Clone)]
pub struct AetherServer {
    pub gates: FeatureGates,
    tool_router: ToolRouter<Self>,
}

#[tool_router(router = tool_router)]
impl AetherServer {
    #[tool(description = "...")]
    async fn tool_name(&self, Parameters(args): Parameters<ActionParams>) -> String {
        tools::module::handle_*(&args.action, args.params)
            .unwrap_or_else(|e| format!("Error: {e}"))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for AetherServer { ... }
```

### Secure Command Execution

```rust
let output = SafeCommand::new("icacls", "file_system", "acl_get")
    .timeout(15)
    .arg(path, ParamType::Path)?
    .output()?;
```

### Feature Gates

```rust
server.gates.check(server.gates.dll_inject, "AETHER_DLL_INJECT")?;
```

---

## Conventions

- **File layout**: One tool = one file in `src/tools/`
- **Naming**: `snake_case` for Rust, `camelCase` for JSON keys
- **Unsafe**: `#![allow(unsafe_code)]` per module, each block has `// SAFETY:` comment
- **Logging**: `tracing::info!` / `warn!` / `error!` to stderr only
- **MCP transport**: stdout is JSON-RPC ONLY — never print to stdout
- **Section separators**: Use `// ═══════════════════════════════════` pattern

---

## Testing

```powershell
# Compile check
cargo check

# Run (manually — test via MCP client)
cargo run

# Lint
cargo clippy -- -D clippy::all -D clippy::pedantic
```

---

## Notes for AI Agents

- NEVER use `cmd.exe` or `powershell.exe` to perform system operations — use Win32 API directly
- NEVER print to stdout — MCP uses stdout for JSON-RPC exclusively
- ALWAYS canonicalize file paths before operations
- ALWAYS check `force: true` for dangerous operations
- ALWAYS audit-log via `audit::log_*` functions
- NEVER modify `mcp.json` or `.env` without explicit user request
- ALWAYS use `SafeCommand` for any external command invocation — never raw `std::process::Command`
