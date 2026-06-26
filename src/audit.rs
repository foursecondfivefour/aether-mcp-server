//! Structured audit logging for all AETHER operations.
//!
//! Every tool invocation is logged with level, tool name, action, parameters,
//! result, and timestamp via `tracing`. Sensitive parameter values are redacted
//! to prevent passwords, tokens, certificates, and LSA secrets from appearing
//! in log files.

use tracing::{info, warn, error};

// ── Sensitive key patterns ────────────────────────────────────────────────
//
// Any audit log `detail` string containing these substrings will have its
// value redacted to <REDACTED>.

const SENSITIVE_PATTERNS: &[&str] = &[
    "password",
    "secret",
    "token",
    "credential",
    "certificate",
    "lsa_secret",
    "key_name",
    "passwd",
    "pwd=",
    "dll_path",
];

/// Redact sensitive data from a log detail string.
///
/// Looks for patterns like `password=...`, `secret=...`, `token=...`
/// in log messages and replaces their values with `<REDACTED>`.
/// Also handles JSON-like structures.
fn redact_sensitive(mut detail: String) -> String {
    // Redact known sensitive JSON keys in our audit detail format
    // Pattern: `key=value` where key matches a sensitive pattern
    for pattern in SENSITIVE_PATTERNS {
        // Case: `pattern=value`
        let search = format!("{pattern}=");
        while let Some(start) = detail.find(&search) {
            let end = detail[start..]
                .find(|c: char| c == ' ' || c == ',' || c == '}' || c == ']' || c == '"' || c == '\n')
                .map(|pos| start + pos)
                .unwrap_or(detail.len());
            detail.replace_range(start..end, &format!("{pattern}=<REDACTED>"));
        }

        // Case: `pattern: value` (JSON-like)
        let search_json = format!("\"{pattern}\":\"");
        while let Some(start) = detail.find(&search_json) {
            let value_start = start + search_json.len();
            if let Some(end) = detail[value_start..].find('"') {
                detail.replace_range(
                    value_start..value_start + end,
                    "<REDACTED>",
                );
            } else {
                break;
            }
        }
    }

    // Redact values that look like password fields in any format
    detail
}

/// Log a successful tool invocation with automatic sensitive data redaction.
pub fn log_success(tool: &str, action: &str, detail: &str) {
    let safe_detail = redact_sensitive(detail.to_string());
    info!(
        tool = tool,
        action = action,
        detail = safe_detail,
        "Tool invocation succeeded"
    );
}

/// Log a failed tool invocation with automatic sensitive data redaction.
pub fn log_failure(tool: &str, action: &str, err: &str) {
    let safe_err = redact_sensitive(err.to_string());
    warn!(
        tool = tool,
        action = action,
        error = safe_err,
        "Tool invocation failed"
    );
}

/// Log a critical security event (feature gate bypass attempt, permission error).
pub fn log_security(tool: &str, action: &str, reason: &str) {
    let safe_reason = redact_sensitive(reason.to_string());
    error!(
        tool = tool,
        action = action,
        reason = safe_reason,
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

/// Expose redact_sensitive for use by the command runner module.
pub fn redact_for_log(detail: &str) -> String {
    redact_sensitive(detail.to_string())
}
