---
description: Testing patterns and guidelines for AETHER_01
alwaysApply: false
---

# Testing

Testing patterns for the AETHER_01 project.

## Unit Tests

Test error paths — no Win32 API calls:

```rust
#[test]
fn tool_unknown_action_returns_error() {
    let ctx = ErrorContext::new("tool", "made_up_action");
    let err = AetherError::invalid_param(ctx, "action: made_up_action");
    let msg = format!("{err}");
    assert!(msg.contains("tool"));
    assert!(msg.contains("made_up_action"));
}
```

## Integration Tests

Located in `tests/` directory. Test tool dispatch end-to-end:

```rust
#[test]
fn process_dispatch_valid_list() {
    // Test that the action dispatcher routes correctly
    // (actual Win32 calls not made in unit tests)
}
```

## Running Tests

```powershell
# Full suite (thread-safe)
cargo test -- --test-threads=1

# Specific test
cargo test process_unknown_action -- --test-threads=1

# Without capture (see stdout)
cargo test -- --nocapture --test-threads=1
```

## Test Checklist

- [ ] Unknown action returns error with proper context
- [ ] Missing required params return clear error
- [ ] Dangerous actions without `force` return `PermissionDenied`
- [ ] Feature gates block gated operations when disabled
- [ ] Error format is consistent across all tools
