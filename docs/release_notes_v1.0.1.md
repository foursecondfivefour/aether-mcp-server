# Release Notes: v1.0.1

**Windows x86-64 · Rust 1.85+ · 2.65 MB**

---

## What's New

### Testing & Quality
- **79 tests** — unit + integration, covering error formatting, config, tool dispatch, and 9/10 tools with real Win32 API calls
- **0 compiler warnings** — all 68 warnings resolved

### Error Handling
- Structured ProblemDetails format (RFC 9457-inspired)
- 12 curated Win32 error code translations
- No dead-end error paths

### Architecture
- Dual crate layout (`[[bin]]` + `[lib]`) for integration testing
- Clean `main.rs` / `lib.rs` separation

### Developer Experience
- 14+ IDE support in install script (interactive menu)
- AI agent configs: `.agents/skills/`, `.cursor/rules/`, `CLAUDE.md`, `.windsurfrules`

### Governance
- `CODE_OF_CONDUCT.md` added
- Improved `.gitignore`

---

## Binary

| Property | Value |
|----------|-------|
| **File** | `aether-mcp-server.exe` |
| **Size** | 2.65 MB |
| **SHA256** | `5516285AE0AB4164DA9A45C7D0BD5EDCD33EF75E8E82891F372C89853526A4D8` |

### Compiler Hardening

```
opt-level=3      lto=fat         codegen-units=1   panic=abort
strip=symbols    target-cpu=native
control-flow-guard=yes  /GUARD:CF  /DYNAMICBASE
/NXCOMPAT        /HIGHENTROPYVA  +crt-static
```

---

## Install

```powershell
irm https://raw.githubusercontent.com/foursecondfivefour/aether-mcp-server/main/install.ps1 | iex
```

## Verify

```powershell
$hash = (Get-FileHash aether-mcp-server.exe -Algorithm SHA256).Hash
# Expected: 5516285AE0AB4164DA9A45C7D0BD5EDCD33EF75E8E82891F372C89853526A4D8
```
