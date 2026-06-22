# CLAUDE.md — AETHER_01

## Project Identity

- **Name:** AETHER_01
- **Type:** MCP server over stdio, 10 tools, 99% Windows management
- **Language:** Rust (edition 2021, stable 1.85+)
- **Target:** Windows 10/11 x86-64 MSVC only
- **Transport:** stdio — stdout is JSON-RPC ONLY, never print to stdout

## Build

```powershell
$env:CARGO_HOME = ".\.cargo_home"
cargo check    # verify
cargo build    # binary → target/debug/aether-mcp-server.exe
```

Release: `lto=fat, codegen-units=1, panic=abort, strip=symbols, target-cpu=native, CFG, ASLR, DEP, static CRT`.

## Architecture

```
main.rs → dotenvy → FeatureGates → AetherServer → serve((stdin,stdout))

server.rs: AetherServer { gates, tool_router }
  #[tool_router(router = tool_router)] → 10 tools
  #[tool_handler(router = self.tool_router)] → ServerHandler

tools/*.rs → pub fn handle_*(action, params) -> Result<String, AetherError>
error.rs  → AetherError + FormatMessageW FFI (Russian errors)
audit.rs  → log_success/failure/forced/security
config.rs → FeatureGates from .env (all disabled by default)
```

## 10 Tools

1. `process_control` — list, kill, create, priority, threads, affinity, jobs, suspend, modules, DLL inject*
2. `file_system` — read/write/delete, ACL, symlinks, ADS, EFS, quotas, volumes, shares
3. `registry_editor` — read/write/delete/enumerate, security, monitor, offline mount*
4. `service_manager` — list, start/stop/restart, config, triggers, failures, drivers
5. `gui_automation` — mouse, keyboard, windows, screenshot, clipboard, display, audio
6. `system_info` — CPU, memory, disk, OS, power, devices, BIOS, NTP, software, updates, BCD*
7. `network_manager` — adapters, TCP/UDP, DNS, firewall, proxy, routing, WiFi, VPN, BT
8. `user_management` — users, groups, sessions, policies, certificates, credentials, token*
9. `security_audit` — audit, UAC, Defender, AppLocker, BitLocker, TPM, Secure Boot, exploit
10. `system_automation` — Event Log, Scheduled Tasks, WMI queries

* = disabled by default, enabled via .env feature gate

## Key Patterns

### Tool Registration

```rust
#[tool_router(router = tool_router)]
impl AetherServer {
    #[tool(description = "...")]
    async fn my_tool(&self, Parameters(args): Parameters<ActionParams>) -> String {
        tools::module::handle_*(&args.action, args.params)
            .unwrap_or_else(|e| format!("Error: {e}"))
    }
}
#[tool_handler(router = self.tool_router)]
impl ServerHandler for AetherServer { fn get_info(&self) -> ServerInfo { ... } }
```

### Error Handling

```rust
// Validate params
let val = params.get("key").and_then(|v| v.as_str())
    .ok_or_else(|| AetherError::invalid_param("key required"))?;

// Force gate
check_force(&params)?;

// Windows API
unsafe { SomeWin32Call() }.map_err(|e| AetherError::win32(e))?;

// Audit
audit::log_success("tool", "action", "detail");
```

### Feature Gates

```rust
server.gates.check(server.gates.dll_inject, "AETHER_DLL_INJECT")?;
```
All gates: `AETHER_BCD_EDIT`, `AETHER_HAL_CONFIG`, `AETHER_OFFLINE_REGISTRY`, `AETHER_DLL_INJECT`, `AETHER_TOKEN_MANIPULATION`, `AETHER_LSA_SECRETS`.

## Conventions

- NEVER `use windows::core::*` (shadows `Result`)
- NEVER print to stdout (MCP uses it for JSON-RPC)
- NEVER spawn cmd/powershell for system ops — use Win32 API
- ALWAYS use `// SAFETY:` comments on unsafe blocks
- ALWAYS `.map_err(|e| AetherError::win32(e))?` on Win32 calls
- `snake_case` for Rust, `camelCase` for JSON, Russian for error messages
- Log: `tracing::info!` to stderr with `.with_ansi(false).with_writer(std::io::stderr)`
