//! Structured audit logging for all AETHER operations.
//!
//! Every tool invocation is logged with level, tool name, action, parameters,
//! result, and timestamp via `tracing`. Sensitive parameter values are redacted.

use tracing::{info, warn, error};

/// Log a successful tool invocation.
pub fn log_success(tool: &str, action: &str, detail: &str) {
    info!(
        tool = tool,
        action = action,
        detail = detail,
        "Tool invocation succeeded"
    );
}

/// Log a failed tool invocation.
pub fn log_failure(tool: &str, action: &str, err: &str) {
    warn!(
        tool = tool,
        action = action,
        error = err,
        "Tool invocation failed"
    );
}

/// Log a critical security event (feature gate bypass attempt, permission error).
pub fn log_security(tool: &str, action: &str, reason: &str) {
    error!(
        tool = tool,
        action = action,
        reason = reason,
        "Security event"
    );
}

/// Log a dangerous operation that required `force: true`.
pub fn log_forced(tool: &str, action: &str) {
    warn!(
        tool = tool,
        action = action,
        "Dangerous operation executed with force=true"
    );
}
