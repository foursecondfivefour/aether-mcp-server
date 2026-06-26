# Contributing to AETHER_01

Thank you for your interest in contributing to AETHER_01! This document outlines the development workflow, coding standards, and pull request process.

---

## Development Setup

**Requirements:** Rust 1.85+, Windows 10/11

```powershell
git clone https://github.com/YOUR_USER/aether-mcp-server
cd aether-mcp-server
Copy-Item .env.example .env
cargo check
```

---

## Code Style

- Run `cargo fmt` before every commit (`max_width = 120`)
- Run `cargo clippy -- -D clippy::all -D clippy::pedantic`
- Add documentation comments on all public items
- Include `// SAFETY:` comments on every `unsafe` block
- Error messages should be descriptive and include Win32 error code context
- Use `// ════` section separators for visual structure in tool files

---

## Commit Messages

Follow conventional commits:

```
feat: add BCD editor to system_info tool
fix: handle null pointer in registry offline mount
refactor: extract win32_description to error module
docs: add AGENTS.md with build instructions
perf: cache SCM handle in service_manager
security: harden SafeCommand against path traversal
```

---

## Branch Strategy

- `main` — stable releases
- `feat/feature-name` — new features
- `fix/bug-description` — bug fixes

Pull requests target `main`. Keep PRs small and focused on a single concern.

---

## Testing

```powershell
# Lint
cargo clippy

# Run all tests
cargo test -- --test-threads=1
```

---

## Pull Request Checklist

- [ ] `cargo fmt` passes
- [ ] `cargo clippy` passes with no warnings
- [ ] `cargo check` passes
- [ ] Documentation updated (README, AGENTS, etc.)
- [ ] Dangerous operations have a `force: true` gate
- [ ] New feature gates added to `.env.example`
- [ ] Audit logging added for all new operations
- [ ] All external commands use `SafeCommand` (never raw `std::process::Command`)

---

## Code Review Process

All PRs undergo review by project maintainers. Review criteria:

- Correctness — does the code do what it claims?
- Safety — are all edge cases handled? Are unsafe blocks justified?
- Maintainability — is the code readable and well-structured?
- Consistency — does it follow the project's established patterns?

---

## Getting Help

Open an issue on GitHub or start a discussion. For security vulnerabilities, see [SECURITY.md](SECURITY.md) — do not open a public issue.
