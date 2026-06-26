---
description: Security practices and hardening guidelines for AETHER_01
alwaysApply: false
---

# Security Practices

Security guidelines for the AETHER_01 MCP server.

## Core Rules

### 1. NO raw `std::process::Command`

Every external command invocation MUST go through `SafeCommand`:

```rust
// ✅ CORRECT
let output = SafeCommand::new("icacls", "file_system", "acl_get")
    .timeout(15)
    .arg(path, ParamType::Path)?
    .output()?;

// ❌ WRONG — never use this
let output = Command::new("icacls").args([...]).output()?;
```

### 2. ALWAYS validate parameters with `ParamType`

```rust
// ✅ CORRECT
let output = SafeCommand::new("bcdedit", "sysinfo", "bcd_list")
    .arg_unchecked("/enum")
    .arg(id, ParamType::Guid)?    // Validated: hex + hyphens only
    .arg(key, ParamType::Name)?   // Validated: alphanumeric + underscores
    .run()?;
```

### 3. ALWAYS gate dangerous operations

```rust
// Feature gate check (disabled by default in .env)
server.gates.check(ctx, server.gates.dll_inject, "AETHER_DLL_INJECT")?;

// Force confirmation
if !params.get("force").and_then(|v| v.as_bool()).unwrap_or(false) {
    return Err(AetherError::permission_denied(ctx, "..."));
}
```

### 4. ALWAYS audit-log

```rust
audit::log_success("tool", "action", "detail");
audit::log_failure("tool", "action", "error detail");
audit::log_forced("tool", "action");     // force: true operations
audit::log_security("tool", "action", "reason");  // security events
```

### 5. ALWAYS use `// SAFETY:` on unsafe blocks

```rust
unsafe {
    // SAFETY: `buffer` is `needed` bytes large and was just allocated.
    let config = &*config_ptr;
    // ...
}
```

## ParamType Reference

| Type | Allowed Characters | Rejected |
|------|-------------------|----------|
| `Path` | Alphanumeric, `\/:._-~$` | `&|;`(){}[]<>^%`, `..`, control chars |
| `Name` | Alphanumeric, `_-` | Everything else |
| `SafeString` | Alphanumeric, `_\-.:/` | Shell metacharacters |
| `Guid` | Hex, `-`, `{}` | Everything else |
| `RegistryPath` | Alphanumeric, `\:_-.` | Shell metacharacters, `..` |
| `Numeric` | Digits | Everything else |
| `Text` | Any (PowerShell scripts) | Length only (max 4096) |

## NO-GO List

- NEVER use `cmd.exe` or `powershell.exe` for system operations — use Win32 API
- NEVER print to stdout — MCP uses stdout for JSON-RPC exclusively
- NEVER use `windows::core::*` wildcard import (shadows `Result`)
- NEVER modify `mcp.json` or `.env` without explicit user request
- NEVER accept `"force": true` from untrusted/unvalidated input without audit log
