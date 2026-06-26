# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.1.0] — 2026-06-26

### Added
- Shared `common.rs` module — `ps_output`, `ps_json`, `check_force`, `ps_escape`, and `get_param_*` helpers extracted from `security.rs` and `automation.rs`, eliminating code duplication
- Full documentation architecture: `docs/ARCHITECTURE.md`, `docs/DEVELOPMENT.md`, `SUPPORT.md`, `.env.example`, `LICENSE` (MIT)
- GitHub templates: `bug_report.md`, `feature_request.md`, `PULL_REQUEST_TEMPLATE.md`
- AI agent skill files: 7 Codebuff skills under `.agents/skills/`, `.cursor/rules/aether-01.mdc`, `.windsurfrules`, `.github/copilot-instructions.md`

### Changed
- All 12 source files standardized: consistent section separators (`// ════`), named constants for magic numbers/registry paths, organized imports (std → external → local), `TOOL` constants for audit logging
- `network.rs` `action_proxy` closure fixed — now correctly returns `Result<String, AetherError>` instead of using `?` in a non-Result closure
- `network.rs` `hosts_file` write path now uses audited `SafeCommand` instead of raw `std::fs`
- Documentation rewritten in international English with consistent professional tone across all files

### Fixed
- **Compilation blocker**: `security.rs` — removed ~200 lines of duplicate function definitions (old version remained after common.rs migration)
- **Compilation blocker**: `gui.rs` — removed duplicate `CF_UNICODETEXT` constant
- **Compilation blocker**: `network.rs` — fixed `#![allow(unsafe_code)]` on same line as module doc comment
- `sysinfo.rs` — `action_windows_update` marked `unsafe fn` (called unsafe API without explicit safety annotation)

### Security
- All documentation files audited for consistency, removed any remaining Russian text
- `network.rs` `hosts_file` — write operations migrated from raw `std::fs::write` to `SafeCommand` through PowerShell with full audit trail

---

## [1.0.1] — 2025-06-26

### Added
- 79 unit + integration tests covering error formatting, config loading, tool dispatch, and 9/10 tools
- Dual crate layout (`[[bin]]` + `[lib]`) for integration testing
- AI agent configuration files (`.agents/skills/`, `.cursor/rules/`, `CLAUDE.md`, `.windsurfrules`)
- Code of Conduct (`CODE_OF_CONDUCT.md`)

### Changed
- Error messages migrated to structured ProblemDetails format (RFC 9457-inspired)
- 68 compiler warnings resolved across 8 source files
- Install script supports interactive menu for 14+ IDE environments

### Security
- Added `SafeCommand` module — secure external command runner with parameter validation
- Implemented secret redaction in audit logs (`redact_sensitive()`)
- All external commands migrated to `SafeCommand` with timeout enforcement (30s), parameter type validation, and output capping (1 MB)
- Added JSON depth limiting (32 levels max, 256 KB payload max)
- Path canonicalization and shell metacharacter blocking enforced globally
- Binary hardening: CFG, ASLR, DEP, static CRT, LTO, panic=abort, symbol stripping

---

## [1.0.0] — 2025-06-01

### Added
- Initial release of AETHER_01 MCP server
- 10 tools: process_control, file_system, registry_editor, service_manager, gui_automation, system_info, network_manager, user_management, security_audit, system_automation
- stdio transport via `rmcp` 0.5
- Feature gates system (6 gates, all disabled by default)
- PowerShell one-click install script with IDE detection
- `.env` configuration for feature gates and logging
