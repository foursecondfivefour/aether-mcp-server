# GitHub Copilot Instructions — AETHER_01

## Always

- Never print to stdout — MCP uses stdout for JSON-RPC exclusively
- Always canonicalize file paths before operations
- Always check `force: true` for dangerous operations
- Always audit-log via `audit::log_*` functions
- Never modify `mcp.json` or `.env` without explicit user request

## Project Context

This is AETHER_01 — a Windows MCP server in Rust (edition 2021). 10 tools for 99% Windows management over stdio transport.
Target: Windows 10/11 x86-64 MSVC only.

Build: `cargo check` (verify) / `cargo build` (binary). Release profile is hardened with CFG/ASLR/DEP/static CRT.

## Key Dependencies

- `rmcp` 0.5 — MCP SDK, use `#[tool_router(router = tool_router)]` + `#[tool_handler(router = self.tool_router)]`
- `windows` 0.58 — Win32 API, avoid importing `windows::core::*` (it shadows `std::result::Result`)
- `windows-registry` 0.3 — high-level registry crate
- `tracing` 0.1 — logging to stderr with `.with_ansi(false).with_writer(std::io::stderr)`

## Adding a Tool Action

```rust
// In handle_* function in tools/<tool>.rs:
"new_action" => {
    let param = params.get("key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AetherError::invalid_param("key is required"))?;

    check_force(&params)?;  // if dangerous

    // Win32 API call
    let result = unsafe { SomeWin32Function(param) }
        .map_err(|e| AetherError::win32(e))?;

    audit::log_success("tool_name", "new_action", &format!("param={param}"));
    Ok(serde_json::json!({"status":"ok"}).to_string())
}
```

## Error Pattern

```rust
// Win32 errors: always translate
.map_err(|e| AetherError::win32(e))?

// Not found
AetherError::not_found("Registry key not found: HKLM\\...\\MissingKey")

// Permission
AetherError::permission_denied("Это опасная операция. Используйте `\"force\": true`")

// Feature disabled
server.gates.check(server.gates.bcd_edit, "AETHER_BCD_EDIT")?;
```

## Warning Signs (flag these in review)

- `use windows::core::*` — shadows Result, only import needed types
- `Result<T, E>` instead of `std::result::Result<T, AetherError>`
- Windows API calls without `.map_err(|e| AetherError::win32(e))?`
- Dangerous operation without `check_force(&params)?`
- Print to stdout (use `tracing::info!` to stderr instead)
- Missing `// SAFETY:` comment on unsafe blocks
