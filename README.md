# AETHER_01 — Full-Spectrum Windows Management MCP Server

[![Rust](https://img.shields.io/badge/rust-1.85+-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Build](https://img.shields.io/badge/build-release-success.svg)]()

<p align="center">
  <a href="cursor://anysphere.cursor-deeplink/mcp/install?name=aether-01&config=eyJhcmdzIjpbIi1FeGVjdXRpb25Qb2xpY3kiLCJCeXBhc3MiLCItTm9Qcm9maWxlIiwiLUNvbW1hbmQiLCJpcm0gaHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2ZvdXJzZWNvbmRmaXZlZm91ci9hZXRoZXItbWNwLXNlcnZlci9tYWluL2luc3RhbGwucHMxIHwgaWV4Il0sImNvbW1hbmQiOiJwb3dlcnNoZWxsIn0=">
    <img src="https://img.shields.io/badge/Add%20to-Cursor-3ecf8e?logo=cursor&logoColor=white&style=for-the-badge" alt="Add to Cursor" />
  </a>
  <a href="vscode://mcp/install?%7B%22args%22%3A%5B%22-ExecutionPolicy%22%2C%22Bypass%22%2C%22-NoProfile%22%2C%22-Command%22%2C%22irm+https%3A%2F%2Fraw.githubusercontent.com%2Ffoursecondfivefour%2Faether-mcp-server%2Fmain%2Finstall.ps1+%7C+iex%22%5D%2C%22command%22%3A%22powershell%22%7D">
    <img src="https://img.shields.io/badge/Add%20to-VSCode-007acc?logo=visualstudiocode&logoColor=white&style=for-the-badge" alt="Add to VS Code" />
  </a>
  <a href="vscode-insiders://mcp/install?%7B%22args%22%3A%5B%22-ExecutionPolicy%22%2C%22Bypass%22%2C%22-NoProfile%22%2C%22-Command%22%2C%22irm+https%3A%2F%2Fraw.githubusercontent.com%2Ffoursecondfivefour%2Faether-mcp-server%2Fmain%2Finstall.ps1+%7C+iex%22%5D%2C%22command%22%3A%22powershell%22%7D">
    <img src="https://img.shields.io/badge/Add%20to-VSCode%20Insiders-007acc?logo=visualstudio&logoColor=white&style=for-the-badge" alt="Add to VS Code Insiders" />
  </a>
</p>

<p align="center">
  <a href="https://raw.githubusercontent.com/foursecondfivefour/aether-mcp-server/main/install.ps1"><img src="https://img.shields.io/badge/PowerShell-Install%20Script-5391FE?logo=powershell&logoColor=white&style=for-the-badge" alt="Install via PowerShell" /></a>
</p>

**10 tools. 99% Windows coverage. Zero security compromises.**

AETHER_01 is a Rust-based [MCP (Model Context Protocol)](https://modelcontextprotocol.io) server that gives AI assistants full control over Windows 10/11 through standard I/O. From process management to GUI automation, from registry editing to WMI queries — everything a system administrator needs, delivered through a secure, auditable interface.

---

## Features

| # | Tool | Actions |
|---|------|---------|
| 1 | `process_control` | List, kill, create, priority, threads, affinity, modules, DLL injection* |
| 2 | `file_system` | Read/write/delete, ACLs, symlinks, ADS streams, EFS, volumes, network shares |
| 3 | `registry_editor` | Read/write/delete, all hives, security, monitoring, offline mounting* |
| 4 | `service_manager` | List, start/stop/restart, configuration, triggers, drivers |
| 5 | `gui_automation` | Mouse, keyboard, windows, screenshots, clipboard, display, audio |
| 6 | `system_info` | CPU, memory, disks, OS, power, devices, BIOS, NTP, software, updates, BCD* |
| 7 | `network_manager` | Adapters, connections, DNS, firewall, proxy, routing, WiFi, VPN, Bluetooth |
| 8 | `user_management` | Users, groups, sessions, policies, certificates, credentials, tokens* |
| 9 | `security_audit` | Audit, UAC, Defender, AppLocker, BitLocker, TPM, Secure Boot, exploit protection |
| 10 | `system_automation` | Event Log, scheduled tasks, **WMI queries** |

`*` = Disabled by default; enabled via `.env` feature gates.

---

## Quick Start

### One-Click Install

Run the following command in **PowerShell (Administrator)**:

```powershell
irm https://raw.githubusercontent.com/foursecondfivefour/aether-mcp-server/main/install.ps1 | iex
```

The script automatically:
1. Locates or downloads the latest AETHER_01 binary
2. Creates a `.env` file with secure default settings
3. Registers the server with **all detected** AI environments: Cursor, Claude Desktop, Windsurf, VS Code

### Selective Installation

```powershell
# Cursor only
.\install.ps1 -Targets cursor

# Claude Desktop + Windsurf
.\install.ps1 -Targets claude,windsurf

# Custom binary path
.\install.ps1 -BinaryPath target\release\aether-mcp-server.exe

# Specific release version
.\install.ps1 -ReleaseTag v1.0.0
```

### Build from Source

```powershell
git clone https://github.com/foursecondfivefour/aether-mcp-server
cd aether-mcp-server
Copy-Item .env.example .env
cargo build --release
.\install.ps1 -BinaryPath target\release\aether-mcp-server.exe
```

### Manual Configuration

Add the following to your AI environment's MCP configuration file:

<details>
<summary><b>Cursor</b> — <code>%USERPROFILE%\.cursor\mcp.json</code></summary>

```json
{
  "mcpServers": {
    "aether-01": {
      "command": "D:\\path\\to\\aether-mcp-server.exe",
      "env": { "RUST_LOG": "info" }
    }
  }
}
```
</details>

<details>
<summary><b>Claude Desktop</b> — <code>%APPDATA%\Claude\claude_desktop_config.json</code></summary>

```json
{
  "mcpServers": {
    "aether-01": {
      "command": "D:\\path\\to\\aether-mcp-server.exe",
      "env": { "RUST_LOG": "info" }
    }
  }
}
```
</details>

<details>
<summary><b>Windsurf</b> — <code>%USERPROFILE%\.codeium\windsurf\mcp_config.json</code></summary>

```json
{
  "mcpServers": {
    "aether-01": {
      "command": "D:\\path\\to\\aether-mcp-server.exe",
      "env": { "RUST_LOG": "info" }
    }
  }
}
```
</details>

<details>
<summary><b>VS Code (Claude MCP)</b> — <code>%APPDATA%\Code\User\globalStorage\anthropic.claude-mcp\mcp.json</code></summary>

```json
{
  "mcpServers": {
    "aether-01": {
      "command": "D:\\path\\to\\aether-mcp-server.exe",
      "env": { "RUST_LOG": "info" }
    }
  }
}
```
</details>

> **After configuration**, restart your AI application. All 10 AETHER_01 tools will appear in the MCP interface.

---

## Feature Gates (.env)

Dangerous operations are disabled by default. Enable them explicitly as needed:

```env
AETHER_BCD_EDIT=0              # Modify Windows boot configuration
AETHER_HAL_CONFIG=0            # Configure HAL and crash dump settings
AETHER_OFFLINE_REGISTRY=0      # Mount offline registry hives
AETHER_DLL_INJECT=0            # Inject DLLs into running processes
AETHER_TOKEN_MANIPULATION=0    # Manipulate access tokens
AETHER_LSA_SECRETS=0           # Read LSA secrets
```

---

## Security

> **The only real vulnerability is the human factor.**  
> AETHER_01 is a system administration tool — like `sudo`, `regedit`, or `services.msc`.  
> If you enable all feature gates, bypass `force` checks, and execute AI instructions blindly,  
> the server will do exactly what it's told. That's not a bug — it's the nature of administrative software.  
> See [SECURITY.md](SECURITY.md) for a full threat analysis.

### Threat Model

```
Your machine (trusted environment)
│
├── Cursor / Claude / VS Code (AI client) ─── same user, same machine
│   │
│   └── AETHER_01 (stdio subprocess) ← THE SERVER
│       │
│       └── Windows API (system calls) — same machine, kernel
│
└── Internet ← AETHER_01 does NOT connect here
```

**AETHER_01 has no network access.** It is a pure stdio process — no HTTP requests, no open ports, no listening sockets. All communication occurs through stdin/stdout with the local AI client.

### What the Server CANNOT Do

| Capability | Status | Reason |
|------------|--------|--------|
| Network connections | Impossible | No HTTP/TCP/UDP code in the codebase |
| Shell command execution | Impossible | Direct Win32 API only; no `cmd.exe` invocation |
| Remote access | Impossible | stdio-only transport; no HTTP/SSE/TCP |
| Data exfiltration via network | Impossible | No network path exists |
| Self-installation / persistence | Impossible | No installer, no service, no autorun |
| Auto-updates | Impossible | No code for network requests |

### Protective Measures

| Mechanism | Severity | Description |
|-----------|----------|-------------|
| **Feature Gates** | Maximum | BCD Edit, DLL Injection, LSA Secrets, Token Manipulation, Offline Registry, HAL Config — **all disabled by default** in `.env`. Inaccessible without explicit administrator approval. |
| **`force: true`** | High | Every destructive operation requires explicit confirmation via `"force": true`. Without it, the server refuses. |
| **Input Validation** | High | Every parameter is validated before any Win32 API call. Invalid types, empty strings, bad PIDs — instant rejection. |
| **Secure Command Runner** | High | All external commands (icacls, compact, cipher, reg, netsh, bcdedit, PowerShell, etc.) execute through `SafeCommand` with a strict 30s timeout and parameter validation against shell metacharacters. |
| **Command Injection Protection** | High | Parameters for external commands pass through `SafeCommand::arg()` — shell metacharacters (`&|;`$(){}[]<>^%`) and path traversal (`..`) are blocked. Parameter type is strictly enforced: Path, Name, SafeString, Numeric, Guid. |
| **No Shell Injection** | High | No `cmd.exe` / `powershell.exe` invocation for system operations. All operations use direct Win32 APIs. External utilities are spawned directly via CreateProcessW — no shell wrapper. |
| **Secret Redaction in Logs** | High | Audit logs automatically redact passwords, tokens, LSA secrets, DLL paths, and certificates. Patterns include `password=`, `secret=`, `token=`, `dll_path=` and their JSON equivalents. |
| **JSON Depth Limiting** | Medium | Tool parameters are checked for nesting depth (max 32 levels) and payload size (max 256 KB). Protection against DoS via deeply nested JSON. |
| **WMI SELECT Only** | Medium | WMI queries are restricted to SELECT. DELETE/INSERT/UPDATE are rejected. 30s timeout, 1000-row limit. |
| **Path Canonicalization** | Medium | All file paths pass through `canonicalize` to prevent path traversal attacks. |
| **Full Audit Trail** | Medium | Every tool invocation is logged to stderr: tool name, action, parameters, result. Sensitive data is automatically redacted. |
| **Output Size Cap** | Medium | External command output is limited to 1 MB. Protection against memory exhaustion when reading large files or logs. |

### Security Architecture

#### `src/command.rs` — SafeCommand

A dedicated module through which **all** external command invocations pass:

- **`SafeCommand`** — Builder for secure external process execution
- **`run_safe()` / `run_mixed()`** — Convenience functions for common use cases
- **`ParamType`** — Strongly-typed parameter validation: `Path`, `Name`, `RegistryPath`, `SafeString`, `Numeric`, `Text`, `Guid`

Each parameter is validated according to these rules:

| Type | Allowed Characters | Rejected |
|------|-------------------|----------|
| `Path` | Alphanumeric, `\/:._-~$` | `&|;`(){}[]<>^%`, `..`, control characters |
| `Name` | Alphanumeric, `_-` | Everything else |
| `SafeString` | Alphanumeric, `_\-.:/` | Shell metacharacters |
| `Guid` | Hex, `-`, `{}` | Everything else |
| `Text` | Any (for PowerShell scripts) | Length only (max 4096) |

#### `src/audit.rs` — Secret Redaction

The `redact_sensitive()` function automatically processes all logs:

- Replaces values of known sensitive keys with `<REDACTED>`
- Handles both plain-text (`key=value`) and JSON (`"key":"value"`) formats
- Patterns include: `password`, `secret`, `token`, `credential`, `certificate`, `lsa_secret`, `key_name`, `dll_path`, `passwd`

#### Binary Hardening

| Technology | Effect |
|-----------|--------|
| **Control Flow Guard** (`/GUARD:CF`) | Validates every indirect call — blocks ROP/JOP attacks |
| **ASLR** (`/DYNAMICBASE` + `/HIGHENTROPYVA`) | Random load address — prevents code location prediction |
| **DEP/NX** (`/NXCOMPAT`) | Stack and heap are non-executable — prevents shellcode injection |
| **Static CRT** (`+crt-static`) | No external DLL dependencies — prevents library hijacking |
| **Fat LTO** + `codegen-units=1` | Full dead code elimination — reduces attack surface |
| **Symbol Stripping** (`strip=symbols`) | No function names in binary — harder reverse engineering |
| **Panic=abort** | No unwind tables — smaller binary, no stack leakage |

### Standards Compliance

AETHER_01 follows these industry recommendations:

- **[IETF draft: MCP Security Considerations](https://www.ietf.org/archive/id/draft-mohiuddin-mcp-security-considerations-00.html)** — All tool parameters are treated as untrusted (originating from an LLM susceptible to prompt injection)
- **[OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)** — LLM06 (Excessive Agency) is mitigated through `force: true` + feature gates; LLM02 (Insecure Output Handling) is mitigated through input validation
- **[Anthropic MCP Security Best Practices](https://modelcontextprotocol.io/docs/concepts/security)** — stdio transport (isolated), least privilege via gates, audit logging

### Prompt Injection Resistance

AETHER_01 tool parameters originate from an LLM, which is susceptible to prompt injection. Therefore:

- **Every string parameter is validated** before use in Win32 API calls
- **No eval-like operations** — arbitrary code cannot be executed through a parameter
- **No format strings** in Win32 API — parameters are never interpreted as code
- **WMI WQL is sanitized** — single quotes in query strings are escaped
- **Paths are canonicalized** — `..\..\windows\system32` is normalized before verification

### Known CVEs and Non-Applicability

| CVE | Applicable to AETHER? | Why Not |
|-----|----------------------|---------|
| CVE-2025-54136 (MCPoison) | No | AETHER is a native `.exe`, not via `npx`/npm. MCP config contains no executable code — only a binary path. |
| CVE-2025-54135 (CurXecute) | No | AETHER does not process MCP configs from repositories. Config is written once via `install.ps1`. |
| CVE-2025-64106 (TrustFall) | No | AETHER does not load workspace-level configs. |
| Command Injection | No | AETHER does not use shell. All Win32 API calls use typed parameters. |

> **Bottom line**: If you don't enable feature gates without understanding them, don't bypass `force` checks, and don't run the binary from untrusted sources — AETHER_01 is secure. It's like `sudo` on Linux: a powerful tool that requires mindful use.

### Reporting a Vulnerability

See [SECURITY.md](SECURITY.md) for our disclosure process, supported versions, and supply chain audit.

---

## Performance

- `opt-level = 3` (all LLVM optimizations)
- `lto = true` (fat LTO across all crates)
- `codegen-units = 1` (full dead code elimination)
- `panic = "abort"` (no unwind tables)
- `strip = "symbols"` (minimal binary size)
- `target-cpu = native` (AVX2, BMI2, FMA, POPCNT)

---

## Project Structure

```
src/
├── main.rs              # tokio::main, stdio transport
├── server.rs            # AetherServer + tool_router
├── command.rs           # SafeCommand — secure external command runner
├── config.rs            # FeatureGates from .env
├── error.rs             # AetherError + FormatMessageW
├── audit.rs             # Structured audit logging with secret redaction
└── tools/
    ├── process.rs       # process_control
    ├── filesystem.rs    # file_system
    ├── registry.rs      # registry_editor
    ├── service.rs       # service_manager
    ├── gui.rs           # gui_automation
    ├── sysinfo.rs       # system_info
    ├── network.rs       # network_manager
    ├── user.rs          # user_management
    ├── security.rs      # security_audit
    ├── automation.rs    # system_automation
    └── common.rs        # Shared helpers for tool implementations
```

---

## License

MIT — see [LICENSE](LICENSE)
