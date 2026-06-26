# Contributing to AETHER_01

Thank you for your interest in contributing! This guide covers everything you need to know to get started.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Code Standards](#code-standards)
- [Pull Request Process](#pull-request-process)
- [Issue Reporting](#issue-reporting)
- [Security](#security)

---

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

---

## Getting Started

### Prerequisites

- Rust 1.85+ ([rustup](https://rustup.rs/))
- Windows 10/11 (MSVC target)
- Git

### Development Setup

```powershell
git clone https://github.com/foursecondfivefour/aether-mcp-server.git
cd aether-mcp-server
Copy-Item .env.example .env
cargo check
```

> **Full development guide:** [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)

---

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feat/your-feature-name
# or
git checkout -b fix/your-bug-fix
```

### 2. Make Changes

- Follow the [Code Standards](#code-standards)
- Write tests for new functionality
- Update documentation

### 3. Run Checks

```powershell
cargo fmt --all -- --check
cargo clippy -- -D clippy::all -D clippy::pedantic
cargo test -- --test-threads=1
```

### 4. Commit

Use [conventional commits](https://www.conventionalcommits.org/):

```
feat: add BCD editor to system_info tool
fix: handle null pointer in registry offline mount
refactor: extract win32_description to error module
docs: add development guide
perf: cache SCM handle in service_manager
security: harden SafeCommand against path traversal
```

### 5. Submit a Pull Request

Open a PR against `main`. Use the [PR template](.github/PULL_REQUEST_TEMPLATE.md).

---

## Code Standards

### Rust

- `cargo fmt` (line width: 120)
- `cargo clippy` — zero warnings
- Doc comments (`///`) on all public items
- `// SAFETY:` comments on every `unsafe` block
- Section separators: `// ═══════════════════════`
- Imports: `std` → external crates → local crate
- Named constants for magic numbers/strings

### Security Requirements

All contributions must follow these security practices:

- **All external commands** must use `SafeCommand` (never raw `std::process::Command`)
- **Parameter validation** — every user-facing parameter must be validated with `ParamType`
- **`force: true`** — every destructive operation must require explicit confirmation
- **Audit logging** — every action must be logged (success, failure, or forced)
- **Feature gates** — new dangerous capabilities must be gated behind `.env` flags

---

## Pull Request Checklist

Before submitting, verify:

- [ ] `cargo fmt` passes
- [ ] `cargo clippy` passes with zero new warnings
- [ ] `cargo check` passes
- [ ] Tests added/updated for new functionality
- [ ] Documentation updated (README, docs/, relevant .md files)
- [ ] Dangerous operations include `force: true` gate
- [ ] New feature gates added to `.env.example`
- [ ] Audit logging added for all new operations
- [ ] All external commands use `SafeCommand`

---

## Issue Reporting

### Bug Reports

Open a [Bug Report](https://github.com/foursecondfivefour/aether-mcp-server/issues/new?template=bug_report.md).

Include:
- Windows version and build
- AETHER_01 version
- AI client and version
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs

### Feature Requests

Open a [Feature Request](https://github.com/foursecondfivefour/aether-mcp-server/issues/new?template=feature_request.md).

Include:
- Problem statement
- Proposed solution
- Which tool it belongs to
- Alternatives considered

---

## Security

**Do NOT open public issues for security vulnerabilities.**

See [SECURITY.md](SECURITY.md) for our disclosure process.

---

## Getting Help

- **Documentation:** [SUPPORT.md](SUPPORT.md)
- **Development setup:** [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)
- **Architecture:** [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- **GitHub Discussions:** [Start a discussion](https://github.com/foursecondfivefour/aether-mcp-server/discussions)
