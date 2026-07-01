# AETHER_01 — Full-Spectrum Windows Management MCP Server

[![Rust](https://img.shields.io/badge/rust-1.85+-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![npm](https://img.shields.io/npm/v/%40foursecondfivefour%2Faether-mcp-server?color=red)](https://www.npmjs.com/package/@foursecondfivefour/aether-mcp-server)

[![Add AETHER_01 MCP server to Cursor](https://cursor.com/deeplink/mcp-install-dark.png)](cursor://anysphere.cursor-deeplink/mcp/install?name=aether-01&config=eyJjb21tYW5kIjoibnB4IiwiYXJncyI6WyIteSIsIkBmb3Vyc2Vjb25kZml2ZWZvdXIvYWV0aGVyLW1jcC1zZXJ2ZXIiXSwiZW52Ijp7IlJVU1RfTE9HIjoiaW5mbyJ9fQ==)
[![Install in VS Code](https://img.shields.io/badge/Install_in-VS_Code-007ACC?style=for-the-badge&logo=visualstudiocode&logoColor=white)](https://vscode.dev/redirect/mcp/install?name=aether-01&config=%7B%22command%22%3A%22npx%22%2C%22args%22%3A%5B%22-y%22%2C%22%40foursecondfivefour%2Faether-mcp-server%22%5D%2C%22env%22%3A%7B%22RUST_LOG%22%3A%22info%22%7D%7D)
[![Install in VS Code Insiders](https://img.shields.io/badge/Install_in-VS_Code_Insiders-24BFA5?style=for-the-badge&logo=visualstudiocode&logoColor=white)](https://insiders.vscode.dev/redirect/mcp/install?name=aether-01&config=%7B%22command%22%3A%22npx%22%2C%22args%22%3A%5B%22-y%22%2C%22%40foursecondfivefour%2Faether-mcp-server%22%5D%2C%22env%22%3A%7B%22RUST_LOG%22%3A%22info%22%7D%7D&quality=insiders)

[![npm install](https://img.shields.io/badge/npm%20install-g%20aether--mcp--server-CB3837?logo=npm&style=for-the-badge)](https://www.npmjs.com/package/@foursecondfivefour/aether-mcp-server)
[![PowerShell install](https://img.shields.io/badge/PowerShell-irm%20%7C%20iex-5391FE?logo=powershell&logoColor=white&style=for-the-badge)](https://raw.githubusercontent.com/foursecondfivefour/aether-mcp-server/main/install.ps1)

**10 tools. 99% Windows coverage. Zero security compromises.**

AETHER_01 is an [MCP (Model Context Protocol)](https://modelcontextprotocol.io) server written in Rust that gives AI assistants full control over Windows 10/11 via standard input/output. From process management to GUI automation, from registry to WMI queries — everything a system administrator needs.

---

## Features

| # | Tool | Actions |
|---|------|---------|
| 1 | `process_control` | list, kill, create, priority, threads, affinity, modules, DLL injection* |
| 2 | `file_system` | read/write/delete, ACL, symlinks, ADS streams, EFS, volumes, network shares |
| 3 | `registry_editor` | read/write/delete, all hives, security, monitoring, offline mounting* |
| 4 | `service_manager` | list, start/stop/restart, config, triggers, drivers |
| 5 | `gui_automation` | mouse, keyboard, windows, screenshots, clipboard, display, audio |
| 6 | `system_info` | CPU, memory, disk, OS, power, devices, BIOS, NTP, software, updates, BCD* |
| 7 | `network_manager` | adapters, connections, DNS, firewall, proxy, routing, WiFi, VPN, Bluetooth |
| 8 | `user_management` | users, groups, sessions, policies, certificates, credentials, tokens* |
| 9 | `security_audit` | audit, UAC, Defender, AppLocker, BitLocker, TPM, Secure Boot, exploit protection |
| 10 | `system_automation` | Event Log, Scheduled Tasks, **WMI queries** |

`*` = disabled by default, enabled via `.env` feature gates.

---

## Installation

AETHER_01 provides **5 installation methods** — pick the one that works best for you.

### Method 1: npm global install (easiest)

```powershell
npm install -g @foursecondfivefour/aether-mcp-server
```

The postinstall script automatically downloads the latest Windows x64 binary from GitHub Releases and places it in your PATH.

### Method 2: One-click PowerShell install

Run this in **PowerShell 7+ (Administrator)**:

```powershell
irm https://raw.githubusercontent.com/foursecondfivefour/aether-mcp-server/main/install.ps1 | iex
```

The script automatically:
1. Downloads the latest AETHER_01 binary
2. Creates `.env` with safe default settings
3. Registers the server in **all detected** AI environments: Cursor, Claude Desktop, Windsurf, VS Code, and more

### Method 3: One-click editor integration

Click the badge for your editor:

| Editor | Install |
|--------|---------|
| **Cursor** | [![Add AETHER_01 MCP server to Cursor](https://cursor.com/deeplink/mcp-install-dark.png)](cursor://anysphere.cursor-deeplink/mcp/install?name=aether-01&config=eyJjb21tYW5kIjoibnB4IiwiYXJncyI6WyIteSIsIkBmb3Vyc2Vjb25kZml2ZWZvdXIvYWV0aGVyLW1jcC1zZXJ2ZXIiXSwiZW52Ijp7IlJVU1RfTE9HIjoiaW5mbyJ9fQ==) |
| **VS Code** | [![Install in VS Code](https://img.shields.io/badge/Install_in-VS_Code-007ACC?logo=visualstudiocode&logoColor=white)](https://vscode.dev/redirect/mcp/install?name=aether-01&config=%7B%22command%22%3A%22npx%22%2C%22args%22%3A%5B%22-y%22%2C%22%40foursecondfivefour%2Faether-mcp-server%22%5D%2C%22env%22%3A%7B%22RUST_LOG%22%3A%22info%22%7D%7D) |
| **VS Code Insiders** | [![Install in VS Code Insiders](https://img.shields.io/badge/Install_in-VS_Code_Insiders-24BFA5?logo=visualstudiocode&logoColor=white)](https://insiders.vscode.dev/redirect/mcp/install?name=aether-01&config=%7B%22command%22%3A%22npx%22%2C%22args%22%3A%5B%22-y%22%2C%22%40foursecondfivefour%2Faether-mcp-server%22%5D%2C%22env%22%3A%7B%22RUST_LOG%22%3A%22info%22%7D%7D&quality=insiders) |

If your browser/GitHub client does not open the Cursor deeplink, copy this link into the address bar:

```text
cursor://anysphere.cursor-deeplink/mcp/install?name=aether-01&config=eyJjb21tYW5kIjoibnB4IiwiYXJncyI6WyIteSIsIkBmb3Vyc2Vjb25kZml2ZWZvdXIvYWV0aGVyLW1jcC1zZXJ2ZXIiXSwiZW52Ijp7IlJVU1RfTE9HIjoiaW5mbyJ9fQ==
```

### Method 4: Selective install with install.ps1

```powershell
# Cursor only
.\install.ps1 -Targets cursor

# Claude Desktop + Windsurf
.\install.ps1 -Targets claude,windsurf

# Custom binary path
.\install.ps1 -BinaryPath target\release\aether-mcp-server.exe

# Specific release version
.\install.ps1 -ReleaseTag v1.0.1
```

### Method 5: Build from source

```powershell
git clone https://github.com/foursecondfivefour/aether-mcp-server
cd aether-mcp-server
Copy-Item .env.example .env
cargo build --release
.\install.ps1 -BinaryPath target\release\aether-mcp-server.exe
```

### Manual configuration (without install script)

<details>
<summary><b>Cursor</b> — <code>%USERPROFILE%\.cursor\mcp.json</code></summary>

```json
{
  "mcpServers": {
    "aether-01": {
      "command": "d:\\path\\to\\aether-mcp-server.exe",
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
      "command": "d:\\path\\to\\aether-mcp-server.exe",
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
      "command": "d:\\path\\to\\aether-mcp-server.exe",
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
      "command": "d:\\path\\to\\aether-mcp-server.exe",
      "env": { "RUST_LOG": "info" }
    }
  }
}
```
</details>

> **After configuring**, restart your editor. The MCP panel will show 10 AETHER_01 tools.

---

## Feature Gates (.env)

Dangerous operations are **disabled by default** and enabled by the system administrator:

```env
AETHER_BCD_EDIT=0          # Windows boot configuration editing
AETHER_HAL_CONFIG=0        # HAL and memory dump configuration
AETHER_OFFLINE_REGISTRY=0  # Offline registry hive mounting
AETHER_DLL_INJECT=0        # DLL injection into processes
AETHER_TOKEN_MANIPULATION=0 # Access token manipulation
AETHER_LSA_SECRETS=0       # LSA secret reading
```

---

## Security

> **The only vulnerability is human error.**
> AETHER_01 is a system administrator tool — like `sudo`, `regedit`, or `services.msc`.
> If you enable all feature gates, disable `force` checks, and blindly execute AI commands —
> the server does exactly what you tell it. That's not a bug. That's the nature of an administrative tool.
> Full threat analysis: [SECURITY.md](SECURITY.md)

### Threat Model

```
Your computer (trusted environment)
│
├── Cursor / Claude / VS Code (AI client) ─── same user, same machine
│   │
│   └── AETHER_01 (stdio subprocess) ← SERVER
│       │
│       └── Windows API (system calls) — same machine, kernel
│
└── Internet ← AETHER_01 has NO network access
```

**AETHER_01 has no network access.** It is a pure stdio process. It does not make HTTP requests, open ports, or listen for connections. All communication is through stdin/stdout with the local AI client.

### What the server CANNOT do

| Capability | Status | Reason |
|------------|--------|--------|
| Network connections | Impossible | No HTTP/TCP/UDP code |
| Shell execution | Impossible | Direct Win32 API only, no `cmd.exe` |
| Remote access | Impossible | stdio only, no HTTP/SSE/TCP |
| Data exfiltration | Impossible | No network path at all |
| Auto-start / persistence | Impossible | No installer, no service, no autorun |
| Auto-update | Impossible | No network request code |

### Defense mechanisms

| Mechanism | Protection Level | Description |
|-----------|-----------------|-------------|
| **Feature Gates** | Maximum | BCD Edit, DLL Injection, LSA Secrets, Token Manipulation, Offline Registry, HAL Config — **disabled by default** in `.env`. Operations are unavailable without explicit admin enablement. |
| **`force: true`** | High | Every dangerous operation requires explicit confirmation in parameters. Without `"force": true` the server refuses. |
| **Input validation** | High | Every parameter is validated before Win32 API calls. Invalid types, empty strings, invalid PIDs — immediate rejection. |
| **No shell injection** | High | Zero `cmd.exe` / `powershell.exe` calls. All operations through direct Win32 API. No command injection path. |
| **WMI SELECT only** | Medium | WMI queries restricted to SELECT. DELETE/INSERT/UPDATE — rejected. 30s timeout, 1000 row limit. |
| **Path canonicalization** | Medium | All file paths go through `canonicalize` to prevent path traversal. |
| **Full audit logging** | Medium | Every tool call logged to stderr: tool, action, parameters, result. |

### Binary hardening

| Technology | Effect |
|-----------|--------|
| **Control Flow Guard** (`/GUARD:CF`) | Checks every indirect call — blocks ROP/JOP attacks |
| **ASLR** (`/DYNAMICBASE` + `/HIGHENTROPYVA`) | Random load address — can't predict code location |
| **DEP/NX** (`/NXCOMPAT`) | Stack and heap non-executable — no shellcode injection |
| **Static CRT** (`+crt-static`) | No external DLL dependency — can't swap the library |
| **Fat LTO** + `codegen-units=1` | Full dead code removal — smaller attack surface |
| **Symbol stripping** | No function names in binary — harder reverse engineering |
| **Panic=abort** | No unwind tables — smaller binary, no stack leaks |

### Standards compliance

AETHER_01 follows:

- **[IETF draft: MCP Security Considerations](https://www.ietf.org/archive/id/draft-mohiuddin-mcp-security-considerations-00.html)** — all tool parameters treated as untrusted (originate from LLM susceptible to prompt injection)
- **[OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)** — LLM06 (Excessive Agency) mitigated via `force: true` + feature gates; LLM02 (Insecure Output Handling) mitigated via parameter validation
- **[Anthropic MCP Security Best Practices](https://modelcontextprotocol.io/docs/concepts/security)** — stdio transport (isolated), least privilege via gates, audit logging

### Prompt injection resistance

AETHER_01 tool parameters come from an LLM that is susceptible to prompt injection. Therefore:
- **Every string parameter is escaped** before use in Win32 API
- **No eval-like operations** — cannot "execute arbitrary code" through a parameter
- **No format strings** in Win32 API — parameters are never interpreted as code
- **WMI WQL is escaped** — single quotes in query strings are transformed
- **Paths are canonicalized** — `..\..\windows\system32` is normalized to a checkable path

### Known CVEs and inapplicability

| CVE | Applicable to AETHER? | Why not |
|-----|----------------------|---------|
| CVE-2025-54136 (MCPoison) | No | AETHER is a native .exe, not via `npx`/npm. MCP config contains no executable code — only a binary path. |
| CVE-2025-54135 (CurXecute) | No | AETHER does not process MCP configs from repositories. Config is written once via `install.ps1`. |
| CVE-2025-64106 (TrustFall) | No | AETHER does not load workspace-level configs. |
| Command Injection | No | AETHER does not use shell. All Win32 API calls with typed parameters. |

> **Bottom line**: if you don't enable feature gates without understanding them, don't disable `force` checks, and don't run the binary from an untrusted source — AETHER_01 is safe. Like `sudo` on Linux: a powerful tool requiring conscious use.

### Report a vulnerability

[SECURITY.md](SECURITY.md) — disclosure process, supported versions, supply chain audit.

---

## Performance

- `opt-level = 3` (all LLVM optimizations)
- `lto = true` (fat LTO across all crates)
- `codegen-units = 1` (full dead code elimination)
- `panic = "abort"` (no unwind tables)
- `strip = "symbols"` (minimal binary)
- `target-cpu = native` (AVX2, BMI2, FMA, POPCNT)

---

## Project Structure

```
src/
├── main.rs              # tokio::main, stdio transport
├── server.rs            # AetherServer + tool_router
├── config.rs            # FeatureGates from .env
├── error.rs             # AetherError + FormatMessageW
├── audit.rs             # Structured audit logging
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
    └── automation.rs    # system_automation
```

---

## License

MIT
