---
description: Add a new tool or action to the AETHER_01 MCP server
alwaysApply: false
---

# Tool Pattern

Guide for adding new tools or actions to AETHER_01.

## File Structure

One tool = one file in `src/tools/`. Each file exports a single public handler function.

## Step-by-Step

### 1. Create the tool file

Create `src/tools/my_tool.rs`:

```rust
//! My new tool for AETHER_01 MCP server.
//!
//! Provides N actions covering [description].

#![allow(unsafe_code)]

use crate::audit;
use crate::command::{ParamType, SafeCommand};
use crate::error::{AetherError, ErrorContext};

use serde_json::{json, Value};

// ═══════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════

/// Tool name for audit logging.
const TOOL: &str = "my_tool";

// ═══════════════════════════════════════════════════════════════════════════════
// Public entry point
// ═══════════════════════════════════════════════════════════════════════════════

pub fn handle_my_tool(
    action: &str,
    params: Value,
) -> Result<String, AetherError> {
    let action_static: &'static str = Box::leak(action.to_string().into_boxed_str());
    let ctx = ErrorContext::new(TOOL, action_static);
    
    match action {
        "action1" => action_one(&ctx, &params),
        "action2" => action_two(&ctx, &params),
        _ => Err(AetherError::invalid_param(ctx, format!(
            "Unknown action: {action}"
        ))),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Actions
// ═══════════════════════════════════════════════════════════════════════════════

fn action_one(ctx: &ErrorContext, params: &Value) -> Result<String, AetherError> {
    // Implementation
    audit::log_success(TOOL, "action1", "detail");
    Ok(json!({"status": "ok"}).to_string())
}
```

### 2. Register in `src/tools/mod.rs`

```rust
pub mod common;
pub mod automation;
pub mod filesystem;
pub mod gui;
pub mod my_tool;          // ← add this
pub mod network;
pub mod process;
pub mod registry;
pub mod security;
pub mod service;
pub mod sysinfo;
pub mod user;
```

### 3. Register in `src/server.rs`

```rust
#[tool(description = "Description of my tool and its capabilities")]
async fn my_tool(&self, Parameters(args): Parameters<ActionParams>) -> String {
    tools::my_tool::handle_my_tool(&args.action, args.params)
        .unwrap_or_else(|e| format!("Error: {e}"))
}
```

### 4. For tools requiring server state (feature gates)

If the tool needs access to `FeatureGates`:

```rust
pub fn handle_my_tool(
    server: &AetherServer,  // ← extra parameter
    action: &str,
    params: Value,
) -> Result<String, AetherError> {
    // Check feature gate
    server.gates.check(ctx.clone(), server.gates.some_gate, "AETHER_SOME_GATE")?;
    // ...
}
```

And in `server.rs`:

```rust
async fn my_tool(&self, Parameters(args): Parameters<ActionParams>) -> String {
    tools::my_tool::handle_my_tool(self, &args.action, args.params)
        .unwrap_or_else(|e| format!("Error: {e}"))
}
```

### 5. Add documentation

- Update `README.md` feature table
- Update `AGENTS.md` tool list
- Add `#[tool(description = "...")]` with comprehensive docs

## Conventions

- Section separators: `// ═══════════════════════════════════`
- Named constants for magic strings/numbers
- Imports: `std` → external crates → local crate
- Doc comments on all public items
- `TOOL` constant for audit logging
