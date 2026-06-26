## Description

Please include a summary of the change and which issue is fixed.

Fixes # (issue)

## Type of Change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that causes existing functionality to change)
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Security hardening

## Checklist

- [ ] `cargo fmt` passes
- [ ] `cargo clippy` passes with no new warnings
- [ ] `cargo check` passes
- [ ] Tests added/updated for new functionality
- [ ] Documentation updated
- [ ] Dangerous operations include `force: true` gate
- [ ] New feature gates added to `.env.example`
- [ ] Audit logging added for all new operations
- [ ] All external commands use `SafeCommand` (not raw `std::process::Command`)

## Test Plan

Describe how you tested your changes:

- [ ] Ran `cargo test`
- [ ] Manual testing with MCP client (describe)

## Additional Context

Add any other context about the PR here.
