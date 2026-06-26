# AETHER_01 — Full-Spectrum Windows Management for AI

<p align="center">
  <img src="https://img.shields.io/badge/rust-1.85+-orange.svg" alt="Rust" />
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License" />
  <img src="https://img.shields.io/badge/platform-Windows%2010%2F11-blueviolet" alt="Platform" />
  <img src="https://img.shields.io/badge/build-release-success" alt="Build" />
</p>

<p align="center">
  <b>10 tools · 99% Windows coverage · Zero network surface</b>
</p>

<p align="center">
  <a href="cursor://anysphere.cursor-deeplink/mcp/install?name=aether-01&config=eyJhcmdzIjpbIi1FeGVjdXRpb25Qb2xpY3kiLCJCeXBhc3MiLCItTm9Qcm9maWxlIiwiLUNvbW1hbmQiLCJpcm0gaHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2ZvdXJzZWNvbmRmaXZlZm91ci9hZXRoZXItbWNwLXNlcnZlci9tYWluL2luc3RhbGwucHMxIHwgaWV4Il0sImNvbW1hbmQiOiJwb3dlcnNoZWxsIn0=">
    <img src="https://img.shields.io/badge/Add%20to-Cursor-3ecf8e?logo=cursor&logoColor=white&style=for-the-badge" alt="Add to Cursor" />
  </a>
  <a href="vscode://mcp/install?%7B%22args%22%3A%5B%22-ExecutionPolicy%22%2C%22Bypass%22%2C%22-NoProfile%22%2C%22-Command%22%2C%22irm+https%3A%2F%2Fraw.githubusercontent.com%2Ffoursecondfivefour%2Faether-mcp-server%2Fmain%2Finstall.ps1+%7C+iex%22%5D%2C%22command%22%3A%22powershell%22%7D">
    <img src="https://img.shields.io/badge/Add%20to-VS%20Code-007acc?logo=visualstudiocode&logoColor=white&style=for-the-badge" alt="Add to VS Code" />
  </a>
  <a href="vscode-insiders://mcp/install?%7B%22args%22%3A%5B%22-ExecutionPolicy%22%2C%22Bypass%22%2C%22-NoProfile%22%2C%22-Command%22%2C%22irm+https%3A%2F%2Fraw.githubusercontent.com%2Ffoursecondfivefour%2Faether-mcp-server%2Fmain%2Finstall.ps1+%7C+iex%22%5D%2C%22command%22%3A%22powershell%22%7D">
    <img src="https://img.shields.io/badge/Add%20to-VS%20Code%20Insiders-007acc?logo=visualstudio&logoColor=white&style=for-the-badge" alt="Add to VS Code Insiders" />
  </a>
</p>

<p align="center">
  <a href="https://raw.githubusercontent.com/foursecondfivefour/aether-mcp-server/main/install.ps1"><img src="https://img.shields.io/badge/PowerShell-One--Click%20Install-5391FE?logo=powershell&logoColor=white&style=for-the-badge" alt="Install via PowerShell" /></a>
</p>

**AETHER_01** is a Rust-based [MCP (Model Context Protocol)](https://modelcontextprotocol.io) server that gives AI assistants comprehensive Windows management capabilities through standard I/O. From process control to GUI automation, registry editing to WMI queries — everything a systems administrator needs, delivered through a secure, auditable, zero-network interface.

---

## Features

| # | Tool | Key Actions |
|---|------|-------------|
| 1 | `process_control` | List, kill, create, priority, threads, affinity, modules, DLL injection* |
| 2 | `file_system` | Read/write/delete, ACLs, symlinks, ADS streams, EFS, volumes, network shares |
| 3 | `registry_editor` | Read/write/delete, all hives, security descriptors, monitoring, offline mount* |
| 4 | `service_manager` | List, start/stop/restart, configuration, triggers, driver enumeration |
| 5 | `gui_automation` | Mouse, keyboard, window management, screenshots, clipboard, display, audio |
| 6 | `system_info` | CPU, memory, disks, OS version, power, devices, BIOS, NTP, installed software, BCD* |
| 7 | `network_manager` | Adapters, TCP/UDP connections, DNS cache, firewall, proxy, routing, WiFi, VPN, Bluetooth |
| 8 | `user_management` | Users, groups, sessions, policies, certificates, credentials, token manipulation* |
| 9 | `security_audit` | Audit policy, UAC, Defender, AppLocker, BitLocker, TPM, Secure Boot, exploit protection |
| 10 | `system_automation` | Event Log querying, scheduled tasks, WMI queries |

`*` = Disabled by default; enabled via `.env` feature gates.

---

## Quick Start

### One-Click Install (PowerShell Administrator)

```powershell
irm https://raw.githubusercontent.com/foursecondfivefour/aether-mcp-server/main/install.ps1 | iex
```

The script automatically:
1. Downloads the latest release binary
2. Creates `.env` with secure defaults (all feature gates disabled)
3. Registers with all detected AI environments (Cursor, VS Code, Claude Desktop, Windsurf, and more)

### Build from Source

```powershell
git clone https://github.com/foursecondfivefour/aether-mcp-server.git
cd aether-mcp-server
Copy-Item .env.example .env
cargo build --release
.\install.ps1 -BinaryPath target\release\aether-mcp-server.exe
```

### Manual Configuration

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

> **After configuration**, restart your AI application. All 10 AETHER_01 tools will appear in the MCP interface.

---

## Feature Gates

Dangerous operations are **disabled by default**. Enable them explicitly in `.env`:

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
> Enable all gates, bypass `force` checks, and blindly execute AI instructions at your own risk.

### Threat Model

```
Your machine (trusted environment)
│
├── AI Client (Cursor / Claude / VS Code) — same user, same machine
│   │
│   └── AETHER_01 (stdio subprocess) ← THE SERVER
│       │
│       └── Windows API (system calls) — same machine, kernel
│
└── Internet ← AETHER_01 does NOT connect here
```

**AETHER_01 has zero network surface.** No HTTP, no TCP, no UDP, no listening sockets. Pure stdio communication with the local AI client.

### Protective Measures Summary

| Layer | Protection |
|-------|-----------|
| **Feature Gates** | 6 critical capabilities disabled by default |
| **`force: true`** | Every destructive operation requires explicit confirmation |
| **Input Validation** | Every parameter validated before API calls |
| **SafeCommand** | All external commands run with strict type validation, timeout (30s), output cap (1 MB), and shell metacharacter blocking |
| **Secret Redaction** | Passwords, tokens, LSA secrets, certificate paths auto-redacted from logs |
| **JSON Limits** | Max 32 nesting levels, 256 KB payload size |
| **WMI Sandbox** | SELECT-only queries, 30s timeout, 1000-row limit |
| **Path Canonicalization** | All paths normalized to prevent traversal attacks |
| **Binary Hardening** | CFG, ASLR, DEP, static CRT, LTO, panic=abort, symbol stripping |

> **Full threat analysis:** [SECURITY.md](SECURITY.md)

---

## Project Architecture

```
src/
├── main.rs              # Entrypoint: tokio runtime, stdio transport
├── lib.rs               # Library surface (integration tests)
├── server.rs            # AetherServer + tool_router (10 tools)
├── command.rs           # SafeCommand — secure command runner
├── config.rs            # FeatureGates from .env
├── error.rs             # AetherError with Win32 code translation
├── audit.rs             # Structured audit logging with redaction
└── tools/
    ├── common.rs        # Shared helpers (ps_output, ps_json, check_force, etc.)
    ├── process.rs       # Process control
    ├── filesystem.rs    # File system operations
    ├── registry.rs      # Registry editor
    ├── service.rs       # Service management
    ├── gui.rs           # GUI automation
    ├── sysinfo.rs       # System information
    ├── network.rs       # Network management
    ├── user.rs          # User management
    ├── security.rs      # Security auditing
    └── automation.rs    # System automation
```

> **Deep dive:** [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

---

## Documentation

| Resource | Description |
|----------|-------------|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Codebase architecture, tool patterns, MCP protocol |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | Development setup, coding standards, testing guide |
| [CHANGELOG.md](CHANGELOG.md) | Version history and release notes |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute |
| [SECURITY.md](SECURITY.md) | Security policy and vulnerability reporting |
| [SUPPORT.md](SUPPORT.md) | Getting help |

---

## Performance

| Setting | Value |
|---------|-------|
| Optimization level | `opt-level = 3` |
| Link-time optimization | `lto = fat` |
| Codegen units | `codegen-units = 1` |
| Panic strategy | `panic = "abort"` |
| Symbol stripping | `strip = "symbols"` |
| Target CPU | `target-cpu = native` |

---

## License

[MIT](LICENSE) © 2025 foursecondfivefour
