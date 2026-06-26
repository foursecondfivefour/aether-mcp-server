# Architecture

AETHER_01 is an MCP (Model Context Protocol) server that runs over stdio. This document describes the internal architecture, tool registration patterns, and key design decisions.

---

## Overview

```
┌─────────────────────────────────────────────────────────────┐
│                      AI Client                              │
│            (Cursor / Claude / VS Code / etc.)               │
└──────────────────────┬──────────────────────────────────────┘
                       │ JSON-RPC over stdin/stdout
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                    AETHER_01 Server                          │
│                                                             │
│  main.rs ──→ dotenvy ──→ FeatureGates ──→ AetherServer     │
│                                                   │         │
│                          tool_router (10 tools)───┤         │
│                                                   ▼         │
│                          tools/*.rs                          │
│                              │                              │
│                              ▼                              │
│                     Windows API (Win32)                      │
└─────────────────────────────────────────────────────────────┘
```

---

## Startup Sequence

1. **`main.rs`** initializes the tokio async runtime
2. **`dotenvy::dotenv()`** loads `.env` — feature gates, log level
3. **`tracing_subscriber::fmt()`** configures structured logging to stderr (no ANSI)
4. **`FeatureGates::load()`** parses environment variables into a bitmask
5. **`AetherServer::new(gates)`** creates the server with its `ToolRouter`
6. **`serve((stdin, stdout)).await`** blocks on stdin, dispatching JSON-RPC messages to registered tools

---

## Tool Registration Pattern

Each tool is registered using the `rmcp` 0.5 `#[tool_router]` macro:

```rust
#[derive(Clone)]
pub struct AetherServer {
    pub gates: FeatureGates,
    tool_router: ToolRouter<Self>,
}

#[tool_router(router = tool_router)]
impl AetherServer {
    #[tool(description = "Full control over Windows processes: list, kill, create, set priority, inject DLLs")]
    async fn process_control(&self, Parameters(args): Parameters<ActionParams>) -> String {
        tools::process::handle_process_control(&args.action, args.params)
            .unwrap_or_else(|e| format!("Error: {e}"))
    }

    // ... 9 more tools
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for AetherServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: "Windows systems administrator — use responsibly with force:true for destructive ops.",
            ..Default::default()
        }
    }
}
```

Each tool file in `src/tools/` exports a single public function:

```rust
pub fn handle_*(
    action: &str,
    params: serde_json::Value,
) -> Result<String, AetherError>
```

Or for tools requiring server state:

```rust
pub fn handle_*(
    server: &AetherServer,
    action: &str,
    params: serde_json::Value,
) -> Result<String, AetherError>
```

---

## Error Handling

All errors pass through `AetherError` (defined in `src/error.rs`):

```rust
pub enum AetherError {
    InvalidParam(ErrorContext, String),       // Bad input from AI
    PermissionDenied(ErrorContext, String),   // force: true missing
    NotFound(ErrorContext, String, Option<String>), // Resource not found
    Win32Error(ErrorContext, String, u32),     // Windows API failure
    FeatureDisabled(ErrorContext, String),     // Feature gate off
    WmiError(ErrorContext, String),           // WMI query failure
    Internal(String),                         // Unexpected internal error
    Io(String),                               // I/O error
}
```

Win32 error codes are translated to human-readable descriptions via `FormatMessageW` FFI.

---

## Security Architecture

### Feature Gates

Six capability gates, all disabled by default:

| Gate | Environment Variable | What It Controls |
|------|---------------------|-----------------|
| `bcd_edit` | `AETHER_BCD_EDIT` | BCDEdit — boot configuration |
| `hal_config` | `AETHER_HAL_CONFIG` | HAL and crash dump settings |
| `offline_registry` | `AETHER_OFFLINE_REGISTRY` | Offline registry hive mounting |
| `dll_inject` | `AETHER_DLL_INJECT` | DLL injection into processes |
| `token_manipulation` | `AETHER_TOKEN_MANIPULATION` | Token privilege adjustment |
| `lsa_secrets` | `AETHER_LSA_SECRETS` | LSA secret reading |

### SafeCommand

`src/command.rs` provides a secure wrapper around `std::process::Command`:

```rust
let output = SafeCommand::new("icacls", "file_system", "acl_get")
    .timeout(15)
    .arg(path, ParamType::Path)?
    .output()?;
```

Features:
- **Timeout enforcement**: 30s default, configurable per call
- **Parameter type validation**: `Path`, `Name`, `RegistryPath`, `SafeString`, `Numeric`, `Text`, `Guid`
- **Shell metacharacter rejection**: `&|;`$(){}[]<>^%` blocked
- **Path traversal prevention**: `..` blocked in path parameters
- **Output capping**: 1 MB max output
- **Audit logging**: every invocation logged

### Audit Logging

`src/audit.rs` provides structured logging:

- `log_success(tool, action, detail)` — successful operations
- `log_failure(tool, action, detail)` — failed operations  
- `log_forced(tool, action)` — `force: true` operations
- `log_security(tool, action, reason)` — security events (gate rejections)
- `redact_sensitive(msg)` — auto-redacts passwords, tokens, secrets

---

## Module Dependency Graph

```
main.rs
  ├── lib.rs
  │   ├── server.rs
  │   │   ├── tools/mod.rs
  │   │   │   ├── tools/common.rs
  │   │   │   ├── tools/process.rs
  │   │   │   ├── tools/filesystem.rs
  │   │   │   ├── tools/registry.rs
  │   │   │   ├── tools/service.rs
  │   │   │   ├── tools/gui.rs
  │   │   │   ├── tools/sysinfo.rs
  │   │   │   ├── tools/network.rs
  │   │   │   ├── tools/user.rs
  │   │   │   ├── tools/security.rs
  │   │   │   └── tools/automation.rs
  │   │   ├── config.rs
  │   │   ├── error.rs
  │   │   ├── audit.rs
  │   │   └── command.rs
  │   └── ...
  └── ...
```

All tool files depend on `error.rs`, `audit.rs`, and `command.rs`. Tools with server state access also depend on `config.rs` (via `FeatureGates`).

---

## Win32 API Usage

AETHER_01 uses the `windows` crate (v0.58) for direct Win32 API access. Key API families:

| Domain | Key Types / Functions |
|--------|----------------------|
| Processes | `CreateProcessW`, `TerminateProcess`, `OpenProcess`, `NtQueryInformationProcess` |
| Registry | `RegOpenKeyExW`, `RegQueryValueExW`, `RegSetValueExW`, `RegNotifyChangeKeyValue` |
| Services | `OpenSCManagerW`, `CreateServiceW`, `StartServiceW`, `ControlService`, `QueryServiceConfigW` |
| GUI | `SendInput`, `FindWindowW`, `GetWindowTextW`, `EnumWindows`, `CreateDCW` |
| Network | `GetAdaptersInfo`, `GetIfTable`, `GetExtendedTcpTable`, `WlanOpenHandle`, `WlanEnumInterfaces` |
| Security | `OpenProcessToken`, `AdjustTokenPrivileges`, `LookupPrivilegeValueW`, `CertOpenSystemStoreW` |
| System | `GetSystemInfo`, `GlobalMemoryStatusEx`, `GetLogicalDrives`, `GetSystemPowerStatus` |
| User | `NetUserEnum`, `NetLocalGroupEnum`, `CredEnumerateW`, `LogonUserW` |

---

## Performance Characteristics

- **Binary size**: ~2.65 MB release build
- **Startup time**: < 100ms (tokio runtime + .env parsing)
- **Memory usage**: ~8-15 MB idle
- **Concurrency**: Single-threaded tokio runtime (one MCP message at a time over stdio)
