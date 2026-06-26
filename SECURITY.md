# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ Active |

---

## Threat Model

AETHER_01 is a **local, single-machine, stdio-only** MCP server. It does **not** open network ports, listen for incoming connections, or expose any remote API. Its entire attack surface consists of:

1. **stdin** — MCP JSON-RPC messages from the AI client (local, same-machine, same-user)
2. **Feature gates in `.env`** — configuration read from disk at startup
3. **PowerShell install script** — one-time setup fetched from the internet

### Trust Boundaries

```
User's machine (fully trusted)
│
├── Cursor / Claude / VS Code (AI client) ─── same user, same machine
│   │
│   └── AETHER_01 (stdio subprocess) ← THE SERVER
│       │
│       └── Windows API (system calls) — same machine, kernel
│
└── Internet ← AETHER_01 does NOT connect here
```

**AETHER_01 has no network access.** It is a pure stdio process that only communicates with the AI client that spawned it.

---

## Capabilities

The server has **full local system access** — by design. It is a Windows system administration tool. Every tool invocation runs with the same privileges as the process that launched it (typically the user's AI client; ideally Administrator).

All 10 tools are documented in [README.md](README.md#features). In summary:

- Read, write, and delete files
- Read, write, and delete registry keys
- Start, stop, and kill processes and services
- Simulate mouse and keyboard input (GUI automation)
- Capture screenshots and read the clipboard
- Enumerate users, sessions, network adapters, and hardware
- Query Windows Event Logs and WMI

### What AETHER_01 CANNOT Do

- **No network egress** — AETHER_01 does not make any outbound HTTP, TCP, or UDP connections. It is a purely local process.
- **No shell execution** — AETHER_01 never spawns `cmd.exe` or `powershell.exe` for system operations. All operations use direct Win32 API calls via the `windows` crate.
- **No remote access** — AETHER_01 is stdio-only. No HTTP, no SSE, no WebSocket, no TCP listener.
- **No credential exfiltration** — AETHER_01 reads credentials from the local machine only. There is no network path to transmit them elsewhere.
- **No persistence** — AETHER_01 installs nothing. It runs as a child process and exits when the parent closes stdin.

---

## The Only Vulnerability: The Human Factor

The primary — and honestly, only — attack vector is **misconfiguration by the administrator**. AETHER_01 provides powerful system access. If you enable every feature gate and bypass every safety check, the server will execute exactly what you (or the AI you are instructing) tell it to.

This is not a vulnerability in the code. This is the **inherent nature of a system administration tool**. `sudo rm -rf /` is not a Linux vulnerability. Deleting `HKEY_LOCAL_MACHINE` is not a Windows vulnerability. These are powerful tools wielded without understanding the consequences.

**The mitigations are in your hands:**

1. **Keep feature gates disabled** — they default to `0` in `.env`
2. **Require `force: true` for dangerous operations** — the server enforces this
3. **Enable MCP Tool Protection in Cursor** — require explicit user approval for every tool call
4. **Never enable gates you do not understand** — read the documentation first
5. **Test in a VM first** — especially before experimenting with BCD editing or DLL injection

---

## Defensive Architecture

### 1. Input Validation

Every parameter is validated before any Win32 API call. Invalid parameters return descriptive errors with translated Win32 error codes via `FormatMessageW`.

### 2. Principle of Least Privilege

- Read-only operations (list, query, enumerate) require **no confirmation**
- Destructive operations (kill, delete, stop, write to system areas) require **`force: true`**
- Critically dangerous operations (BCD edit, DLL injection, LSA secrets) are **gated behind `.env` feature flags**, all **disabled by default**

### 3. No Shell Injection

All system operations use direct Win32 API calls via the `windows` crate. No `cmd.exe`, no `powershell.exe`, no `system()`, no `popen()`. The only exceptions are a small number of external utilities that have no Win32 API equivalent (e.g., `bcdedit`, `wevtutil`, `auditpol`), and even those use hardcoded arguments with validated parameters — no user-controlled shell interpolation.

### 4. Binary Hardening

The release binary is compiled with:

- **Control Flow Guard** (`/GUARD:CF`) — runtime indirect-call validation
- **ASLR** (`/DYNAMICBASE`, `/HIGHENTROPYVA`) — address space randomization
- **DEP/NX** (`/NXCOMPAT`) — non-executable stack and heap
- **Fat LTO + codegen-units=1** — maximum dead code elimination
- **Static CRT** (`+crt-static`) — no external DLL dependencies
- **Symbol stripping** (`strip=symbols`) — minimal attack surface
- **Panic=abort** — no unwind tables

### 5. Audit Trail

Every tool invocation is logged via `tracing` to stderr:

- Tool name, action, parameters, result, and timestamp
- Security events (feature gate rejections, force-denied operations) logged at ERROR level
- All dangerous operations logged with `audit::log_forced`

### 6. Prompt Injection Resistance

AETHER_01 follows the IETF draft [Security Considerations for MCP](https://www.ietf.org/archive/id/draft-mohiuddin-mcp-security-considerations-00.html):

- All tool parameters are treated as **untrusted** — they originate from LLM output, which is susceptible to prompt injection
- Every parameter is validated before any Win32 API call
- No parameter can cause shell injection — there is no shell path in the codebase
- WMI queries are restricted to `SELECT` only — no `DELETE`, `INSERT`, `UPDATE`, or destructive WQL
- File paths are canonicalized to prevent path traversal

---

## Reporting a Vulnerability

**Please do NOT open a public issue.**

Send vulnerability reports to: **security@foursecondfivefour.dev** (or open a private security advisory on GitHub).

You can expect:

- Acknowledgment within 48 hours
- Status update within 7 days
- Coordinated disclosure with fix availability

---

## Supply Chain & Dependencies

### Runtime Dependencies

| Crate | Version | Purpose | Audit Status |
|-------|---------|---------|-------------|
| `rmcp` | 0.5 | Official MCP Rust SDK | Maintained by Anthropic |
| `windows` | 0.58 | Microsoft Win32 API bindings | Maintained by Microsoft |
| `windows-registry` | 0.3 | Registry access | Maintained by Microsoft |
| `tokio` | 1 | Async runtime | Widely audited |
| `serde` / `serde_json` | 1 | JSON serialization | Standard Rust ecosystem |

All dependencies are from crates.io with verified checksums. No git dependencies. No unaudited dependencies. No deprecated or unmaintained crates.

### Verifying Dependencies

```bash
cargo audit          # Vulnerability check
cargo deny check     # License compliance
cargo tree           # Full dependency graph
```

---

## License

MIT — see [LICENSE](LICENSE)
