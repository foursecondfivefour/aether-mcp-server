---
description: Reference for Windows API patterns used in AETHER_01
alwaysApply: false
---

# Win32 API Patterns

Common Windows API patterns used throughout AETHER_01.

## Handle Management

Always close handles obtained from Win32 API:

```rust
let handle = unsafe { OpenSCManagerW(...) }
    .map_err(|e| AetherError::win32(ctx, "OpenSCManagerW", e))?;

// ... use handle ...

unsafe { let _ = CloseServiceHandle(handle); }
```

## Wide Strings

Convert Rust `&str` to null-terminated UTF-16:

```rust
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

let wide = to_wide("SomeString");
let pcwstr = PCWSTR::from_raw(wide.as_ptr());
```

## Buffer Size Discovery Pattern

Many Win32 APIs follow a two-call size discovery pattern:

```rust
// First call: get required buffer size
let mut needed: u32 = 0;
let _ = unsafe { QueryServiceConfigW(svc, None, 0, &mut needed) };

// Second call: allocate and read
let mut buffer: Vec<u8> = vec![0u8; needed as usize];
unsafe {
    QueryServiceConfigW(svc, Some(buffer.as_mut_ptr() as *mut _), needed, &mut needed)
}.map_err(|e| AetherError::win32(ctx, "QueryServiceConfigW", e))?;
```

## Error Translation

Always translate Win32 errors to `AetherError`:

```rust
// Single error
SomeWin32Call().map_err(|e| AetherError::win32(ctx.clone(), "FunctionName", e))?;

// With formatted context
SomeWin32Call().map_err(|e| {
    AetherError::win32(ctx.clone(), "FunctionName", format!("additional context: {e}"))
})?;
```

## Common Error Codes

| Code | Symbol | Meaning |
|------|--------|---------|
| 0 | `ERROR_SUCCESS` | Success |
| 2 | `ERROR_FILE_NOT_FOUND` | File or path not found |
| 5 | `ERROR_ACCESS_DENIED` | Access denied (run as Administrator) |
| 87 | `ERROR_INVALID_PARAMETER` | Invalid parameter |
| 234 | `ERROR_MORE_DATA` | Buffer too small (use size discovery) |
