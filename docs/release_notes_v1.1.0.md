# Release Notes: v1.1.0

**Windows x86-64 · Rust 1.85+**

---

## What's New

### Code Quality Foundation
- **Shared `common.rs` module** — eliminates duplication across security and automation tools
- **12 source files standardized** — consistent separators, named constants, organized imports
- **Full documentation architecture** — ARCHITECTURE.md, DEVELOPMENT.md, SUPPORT.md, CHANGELOG.md, LICENSE

### Developer Experience
- **AI Agent Skills** — 7 Codebuff skills for tool patterns, build/test, security, architecture, code style, Win32 patterns, and testing
- **IDE configuration** — Cursor rules (`.mdc`), Windsurf rules, GitHub Copilot instructions
- **GitHub templates** — structured bug report, feature request, and PR templates

### Security Hardening
- **Compilation fixes** — 3 previously-blocking compilation errors resolved (duplicate functions, duplicate constant, malformed attribute)
- **Audit trail** — `hosts_file` write operations now pass through audited execution paths
- **Explicit safety** — all `unsafe` blocks correctly annotated

---

## Binary

| Property | Value |
|----------|-------|
| **File** | `aether-mcp-server.exe` |
| **Size** | ~2.7 MB |

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
