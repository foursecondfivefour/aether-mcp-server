---
description: Code style and conventions for AETHER_01
alwaysApply: false
---

# Code Style

Rust code style and conventions for the AETHER_01 project.

## Formatting

- Line width: 120 characters
- Run `cargo fmt` before every commit
- Section separators: `// ═══════════════════════════════════`

## Naming

| Convention | Example |
|-----------|---------|
| `snake_case` functions/variables | `fn list_services()` |
| `PascalCase` types/traits | `struct AetherServer` |
| `SCREAMING_CASE` constants | `const SERVICE_NO_CHANGE: u32 = 0xFFFF_FFFF` |
| `camelCase` JSON keys | `"service_name"`, `"startup_type"` |

## Imports

Ordered in three groups, separated by blank line:

```rust
// 1. Standard library
use std::mem;
use std::time::Duration;

// 2. External crates
use serde_json::{json, Value};
use windows::Win32::Foundation::*;

// 3. Local crate
use crate::audit;
use crate::command::{ParamType, SafeCommand};
use crate::error::{AetherError, ErrorContext};
```

## Tool File Template

```rust
//! Doc comment describing the tool.
//!
//! Lists all actions and their required/optional parameters.

#![allow(unsafe_code)]

use crate::audit;
use crate::command::{ParamType, SafeCommand};
use crate::error::{AetherError, ErrorContext};

use serde_json::{json, Value};

// ═══════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════

const TOOL: &str = "tool_name";

// ═══════════════════════════════════════════════════════════════════════════════
// Public entry point
// ═══════════════════════════════════════════════════════════════════════════════

pub fn handle_tool_name(...) -> Result<String, AetherError> { ... }

// ═══════════════════════════════════════════════════════════════════════════════
// Actions
// ═══════════════════════════════════════════════════════════════════════════════

fn action_one(...) -> Result<String, AetherError> { ... }
```

## Doc Comments

- `///` on all public items
- `// SAFETY:` on every `unsafe` block
- Module-level doc: `//!` at top of file
- Include `# Errors` section in doc comments for fallible functions
