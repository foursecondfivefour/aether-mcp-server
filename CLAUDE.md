---
description: 
alwaysApply: true
---

# CLAUDE.md — AETHER_01

## Project Identity

- **Name:** AETHER_01
- **Type:** MCP server over stdio — 10 tools, full Windows management
- **Language:** Rust (edition 2021, stable 1.85+)
- **Target:** Windows 10/11 x86-64 MSVC only
- **Transport:** stdio — stdout is JSON-RPC ONLY. Never print to stdout.

---

## Build

```powershell
$env:CARGO_HOME = ".\\.cargo_home"
cargo check    # Quick verification
cargo build    # Debug build
```

Release: `lto=fat`, `codegen-units=1`, `panic=abort`, `strip=symbols`, `target-cpu=native`, CFG, ASLR, DEP, static CRT.

---

## Architecture

```
main.rs → dotenvy → FeatureGates → AetherServer → serve((stdin, stdout))

server.rs
  ├── struct AetherServer { gates, tool_router: ToolRouter<Self> }
  ├── #[tool_router(router = tool_router)]     # 10 tool methods
  └── #[tool_handler(router = self.tool_router)] # ServerHandler

tools/*.rs → pub fn handle_*(action, params) -> Result<String, AetherError>
error.rs   → AetherError + FormatMessageW FFI
audit.rs   → log_success/failure/forced/security + redact_sensitive
command.rs → SafeCommand builder with ParamType validation
```

---

## 10 Tools

1. `process_control` — list, kill, create, priority, threads, affinity, modules, DLL inject*
2. `file_system` — read/write/delete, ACL, symlinks, ADS, EFS, volumes, shares
3. `registry_editor` — read/write/delete/enumerate, security, monitor, offline mount*
4. `service_manager` — list, start/stop/restart, config, triggers, drivers
5. `gui_automation` — mouse, keyboard, windows, screenshot, clipboard, display, audio
6. `system_info` — CPU, memory, disk, OS, power, devices, BIOS, NTP, software, updates, BCD*
7. `network_manager` — adapters, connections, DNS, firewall, proxy, routing, WiFi, VPN, BT
8. `user_management` — users, groups, sessions, policies, certificates, credentials, token*
9. `security_audit` — audit, UAC, Defender, AppLocker, BitLocker, TPM, Secure Boot, exploit
10. `system_automation` — Event Log, scheduled tasks, WMI queries

`*` = Disabled by default; enabled via `.env` feature gate.

---

## Key Patterns

### Tool Registration

```rust
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

### Feature Gates

```rust
server.gates.check(server.gates.dll_inject, "AETHER_DLL_INJECT")?;
```

Available: `AETHER_BCD_EDIT`, `AETHER_HAL_CONFIG`, `AETHER_OFFLINE_REGISTRY`, `AETHER_DLL_INJECT`, `AETHER_TOKEN_MANIPULATION`, `AETHER_LSA_SECRETS`.

---

## Conventions

- **NEVER** `use windows::core::*` (shadows `Result`)
- **NEVER** print to stdout (MCP JSON-RPC)
- **NEVER** spawn cmd/powershell for system ops — use Win32 API
- **ALWAYS** use `// SAFETY:` on unsafe blocks
- **ALWAYS** `.map_err(|e| AetherError::win32(e))?` on Win32 calls
- **ALWAYS** canonicalize paths before operations
- **ALWAYS** check `force: true` for dangerous operations
- **ALWAYS** audit-log via `audit::log_*` functions
- **NEVER** modify `mcp.json` or `.env` without explicit user request
- `snake_case` for Rust, `camelCase` for JSON
- Log via `tracing::info!` to stderr (`.with_ansi(false).with_writer(std::io::stderr)`)
