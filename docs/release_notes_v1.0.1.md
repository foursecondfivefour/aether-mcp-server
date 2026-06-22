## AETHER_01 v1.0.1 — Hardened Release

**Windows x86-64 | Rust 1.85+ | 2.65 MB**

---

### What's new since v1.0.0

- **79 unit + integration tests** — all passing, covering error formatting, config, tool dispatch, 9/10 tools with real Win32 API calls
- **RFC 9457 error overhaul** — structured ProblemDetails format, formal tone, 12 curated Win32 code translations, no dead-ends
- **0 compiler warnings** — all 68 warnings fixed across 8 files
- **lib.rs split** — crate is now both `[[bin]]` and `[lib]` for integration testing
- **14+ IDE support** — install script with interactive menu for Cursor, VS Code, Claude, Windsurf, JetBrains, Zed, Cline, Continue, Goose
- **AI skill files** — `.agents/skills/`, `.cursor/rules/`, `CLAUDE.md`, `.windsurfrules`, `.github/copilot-instructions.md`
- **Governance** — `CODE_OF_CONDUCT.md`, updated `.gitignore`

### Binary

| Property | Value |
|----------|-------|
| File | `aether-mcp-server.exe` |
| Size | 2.65 MB |
| SHA256 | `5516285AE0AB4164DA9A45C7D0BD5EDCD33EF75E8E82891F372C89853526A4D8` |

### Compiler Hardening

```
opt-level=3  lto=fat  codegen-units=1  panic=abort  strip=symbols
target-cpu=native  control-flow-guard=yes  /GUARD:CF  /DYNAMICBASE
/NXCOMPAT  /HIGHENTROPYVA  +crt-static
```

### Quick Install

```powershell
irm https://raw.githubusercontent.com/foursecondfivefour/aether-mcp-server/main/install.ps1 | iex
```

### Verify

```powershell
$hash = (Get-FileHash aether-mcp-server.exe -Algorithm SHA256).Hash
# Must match: 5516285AE0AB4164DA9A45C7D0BD5EDCD33EF75E8E82891F372C89853526A4D8
```
