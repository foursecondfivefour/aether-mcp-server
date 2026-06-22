# Contributing

## Development Setup

```powershell
# Requirements: Rust 1.85+, Windows 10/11
git clone https://github.com/YOUR_USER/aether-mcp-server
cd aether-mcp-server
Copy-Item .env.example .env
cargo check
```

## Code Style

- `cargo fmt` before commit (max_width = 120)
- `cargo clippy -- -D clippy::all -D clippy::pedantic`
- Documentation comments on all public items
- `// SAFETY:` comments on every `unsafe` block
- Error messages in Russian with Win32 code translation

## Commit Messages

```
feat: add BCD editor to system_info tool
fix: handle null pointer in registry offline mount
refactor: extract win32_description to error module
docs: add AGENTS.md with build instructions
perf: cache SCM handle in service_manager
```

## Branch Strategy

- `main` — stable releases
- `feat/feature-name` — new features
- `fix/bug-description` — bug fixes

PRs target `main`. Keep PRs small and focused.

## Testing

```powershell
# Lint
cargo clippy

# Integration test (requires running MCP server)
cargo test -- --test-threads=1
```

## Pull Request Checklist

- [ ] `cargo fmt` passes
- [ ] `cargo clippy` passes
- [ ] `cargo check` passes
- [ ] Documentation updated
- [ ] Dangerous operations have `force: true` gate
- [ ] New feature gates added to `.env.example`
- [ ] Audit logging added for all new operations
