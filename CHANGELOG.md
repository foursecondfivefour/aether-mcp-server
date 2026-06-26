# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
