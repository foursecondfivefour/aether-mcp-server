# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ Active development |

---

## Threat Model

AETHER_01 is a **local, single-machine, stdio-only** MCP server. It does **not** open network ports, listen for incoming connections, or expose any remote API. The entire attack surface is:

1. **stdin** — MCP JSON-RPC messages from the local AI client
2. **`.env` file** — configuration read from disk at startup
3. **Install script** — one-time PowerShell download from GitHub

### Trust Boundaries

```
User's machine (trusted)
│
├── AI client (Cursor / Claude / VS Code) ─── same user, same machine
│   │
│   └── AETHER_01 (stdio subprocess) ← THE SERVER
│       │
│       └── Windows API (system calls) — kernel via Win32 API
│
└── Internet ← AETHER_01 has ZERO network access
```

---

## What AETHER_01 Can Do

Full local system access — by design. All 10 tools are documented in [README.md](README.md#features). Capabilities include:

- Read, write, delete files and registry keys
- Start, stop, kill processes and services
- Simulate input (mouse, keyboard, clipboard)
- Capture screenshots
- Enumerate users, sessions, hardware, network
- Query Event Logs and WMI

## What AETHER_01 Cannot Do

| Capability | Status | Reason |
|------------|--------|--------|
| Network egress | ❌ Impossible | No HTTP, TCP, or UDP code exists |
| Shell execution | ❌ Impossible | All operations via Win32 API directly |
| Remote access | ❌ Impossible | stdio-only transport; no listeners |
| Credential exfiltration | ❌ Impossible | No network path exists |
| Self-installation | ❌ Impossible | No installer, service, or autorun |
| Auto-updates | ❌ Impossible | No network request code |

---

## The Real Vulnerability: Human Factor

**AETHER_01 is a system administration tool.** Like `sudo` on Linux. Like `regedit` on Windows. If you enable every feature gate and bypass every safety check, the server will execute exactly what you tell it — no more, no less.

This is not a code vulnerability. This is the nature of administrative tools.

**Mitigations in your hands:**

1. **Keep feature gates disabled** — they default to `0`
2. **Require `force: true`** — the server enforces this for destructive ops
3. **Enable MCP Tool Protection** in your AI client — require approval per tool call
4. **Never enable gates you don't understand**
5. **Test in a VM first** — especially BCD editing or DLL injection

---

## Defensive Architecture

### 1. Input Validation

Every parameter is validated before any Win32 API call. Invalid inputs return descriptive errors with translated error codes.

### 2. Principle of Least Privilege

| Risk Level | Operations | Gate |
|------------|-----------|------|
| Read-only | List, query, enumerate | None |
| Destructive | Kill, delete, write, stop | `force: true` |
| Critical | BCD edit, DLL injection, LSA secrets | Feature gate + `force: true` |

### 3. No Shell Injection

All system operations use direct Win32 API (`windows` crate). No `cmd.exe`, no `powershell.exe`, no `system()`, no `popen()`. External utilities (bcdedit, auditpol, wevtutil) are spawned directly via `CreateProcessW` — no shell wrapper, typed parameters only.

### 4. Binary Hardening

| Protection | Mechanism |
|-----------|-----------|
| Control Flow Guard | `/GUARD:CF` — blocks ROP/JOP attacks |
| ASLR | `/DYNAMICBASE` + `/HIGHENTROPYVA` — random load address |
| DEP/NX | `/NXCOMPAT` — non-executable stack/heap |
| Static CRT | `+crt-static` — no external DLL dependency |
| LTO | `codegen-units=1` — full dead code elimination |
| Stripping | `strip=symbols` — no function names in binary |

### 5. Audit Trail

Every tool invocation is logged to stderr:
- Tool name, action, parameters, result, timestamp
- Security events logged at ERROR level
- Sensitive data automatically redacted via `redact_sensitive()`

### 6. Prompt Injection Resistance

All tool parameters are treated as **untrusted** (originating from LLM output). Mitigations:
- Every string parameter validated before Win32 API use
- No eval-like operations — no code execution through parameters
- WMI queries restricted to `SELECT` only
- File paths canonicalized (prevents `..\..\` traversal)
- No format strings in Win32 API calls

---

## Reporting a Vulnerability

**Do NOT open a public issue.**

Send reports to: **security@foursecondfivefour.dev**

You can expect:
- ✅ Acknowledgment within 48 hours
- ✅ Status update within 7 days
- ✅ Coordinated disclosure with fix

---

## Supply Chain

All dependencies from crates.io with verified checksums. No git dependencies.

```bash
cargo audit          # Vulnerability check
cargo deny check     # License compliance
cargo tree           # Full dependency graph
```
