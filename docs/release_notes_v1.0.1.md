# AETHER_01 v1.0.1 — Hardened Release

**Windows x86-64 | Rust 1.85+ | 2.65 MB**

---

## What's New Since v1.0.0

### Testing & Quality
- **79 unit + integration tests** — all passing, covering error formatting, config loading, tool dispatch, and 9 out of 10 tools with real Win32 API calls
- **0 compiler warnings** — all 68 warnings resolved across 8 source files

### Error Handling
- **Structured error format** — RFC 9457-inspired ProblemDetails for consistent, machine-readable errors
- **12 curated Win32 error translations** — human-readable descriptions for common Windows error codes
- **No dead-end errors** — all error paths produce actionable messages

### Architecture
- **Dual crate layout** — the project is now both `[[bin]]` and `[lib]`, enabling integration tests
- **Cleaner lib.rs split** — separation of binary entrypoint from library surface

### Developer Experience
- **14+ IDE support** — the install script now includes an interactive menu for Cursor, VS Code, Claude Desktop, Windsurf, JetBrains, Zed, Cline, Continue, and Goose
- **AI agent configuration** — `.agents/skills/`, `.cursor/rules/`, `CLAUDE.md`, `.windsurfrules`, and `.github/copilot-instructions.md` for better AI-assisted development

### Governance
- **Code of Conduct** — `CODE_OF_CONDUCT.md` added
- **Improved `.gitignore`** — cleaner source tree management

---

## Binary

| Property | Value |
|----------|-------|
| File | `aether-mcp-server.exe` |
| Size | 2.65 MB |
| SHA256 | `5516285AE0AB4164DA9A45C7D0BD5EDCD33EF75E8E82891F372C89853526A4D8` |

### Compiler Hardening

```
opt-level=3      lto=fat         codegen-units=1   panic=abort
strip=symbols    target-cpu=native
control-flow-guard=yes  /GUARD:CF  /DYNAMICBASE
/NXCOMPAT        /HIGHENTROPYVA  +crt-static
```

---

## Quick Install

```powershell
irm https://raw.githubusercontent.com/foursecondfivefour/aether-mcp-server/main/install.ps1 | iex
```

## Verify

```powershell
$hash = (Get-FileHash aether-mcp-server.exe -Algorithm SHA256).Hash
# Expected: 5516285AE0AB4164DA9A45C7D0BD5EDCD33EF75E8E82891F372C89853526A4D8
```
