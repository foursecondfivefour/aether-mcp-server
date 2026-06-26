//! Common helpers shared across all tool modules.
//!
//! Extracted from duplicate implementations in `security.rs` and `automation.rs`
//! to ensure consistent parameter validation, PowerShell execution, and audit
//! logging patterns across all tool files. Every tool should import from here
//! instead of reimplementing the same helpers.

use crate::command::{ParamType, SafeCommand};
use crate::error::{AetherError, ErrorContext};

use serde_json::Value;

// ═══════════════════════════════════════════════════════════════════════════════
// PowerShell helpers
// ═══════════════════════════════════════════════════════════════════════════════

/// Run a PowerShell command with timeout and return stdout as a trimmed String.
///
/// `tool_name` is used for audit logging (e.g., `"security"`, `"automation"`).
pub fn ps_output(script: &str, tool_name: &'static str) -> Result<String, AetherError> {
    SafeCommand::new("powershell.exe", tool_name, "ps_output")
        .timeout(30)
        .arg_unchecked("-NoProfile")
        .arg_unchecked("-NonInteractive")
        .arg_unchecked("-Command")
        .arg(script, ParamType::Text)?
        .output()
        .map(|s| s.trim().to_string())
}

/// Run PowerShell and parse output as JSON.
///
/// Returns `Ok(Value::Null)` when the output is empty.
/// Returns `AetherError::Internal` when JSON parsing fails (with the raw
/// output included in the error message for debugging).
pub fn ps_json(script: &str, tool_name: &'static str) -> Result<Value, AetherError> {
    let raw = ps_output(script, tool_name)?;
    if raw.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str(&raw).map_err(|e| {
        AetherError::Internal(format!(
            "Failed to parse PowerShell JSON output: {e} — raw: {raw}"
        ))
    })
}

// ═══════════════════════════════════════════════════════════════════════════════
// Parameter validation
// ═══════════════════════════════════════════════════════════════════════════════

/// Check that `"force": true` is present in the JSON `params`.
///
/// Returns `AetherError::PermissionDenied` with the `action` name in the
/// error message when the force flag is missing or `false`.
pub fn check_force(ctx: ErrorContext, params: &Value, action: &str) -> Result<(), AetherError> {
    if params.get("force").and_then(|v| v.as_bool()) != Some(true) {
        return Err(AetherError::permission_denied(
            ctx,
            format!("Action '{action}' requires \"force\": true"),
        ));
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// String escaping
// ═══════════════════════════════════════════════════════════════════════════════

/// Escape a PowerShell single-quoted string by doubling embedded single quotes.
///
/// PowerShell single-quoted strings treat `''` as an escaped quote character.
pub fn ps_escape(s: &str) -> String {
    s.replace('\'', "''")
}

// ═══════════════════════════════════════════════════════════════════════════════
// Parameter extraction from JSON
// ═══════════════════════════════════════════════════════════════════════════════

/// Extract a required string parameter from the JSON params object.
pub fn get_param_str<'a>(
    ctx: ErrorContext,
    params: &'a Value,
    key: &str,
) -> Result<&'a str, AetherError> {
    params
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| AetherError::invalid_param(ctx, format!("Missing or invalid parameter: '{key}'")))
}

/// Extract an optional string parameter from the JSON params object.
pub fn get_param_str_opt<'a>(params: &'a Value, key: &str) -> Option<&'a str> {
    params.get(key).and_then(|v| v.as_str())
}

/// Extract a required u64 integer parameter from the JSON params object.
pub fn get_param_u64(ctx: ErrorContext, params: &Value, key: &str) -> Result<u64, AetherError> {
    params
        .get(key)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| AetherError::invalid_param(ctx, format!("Missing or invalid integer: '{key}'")))
}

/// Extract a required boolean parameter from the JSON params object.
pub fn get_param_bool(ctx: ErrorContext, params: &Value, key: &str) -> Result<bool, AetherError> {
    params
        .get(key)
        .and_then(|v| v.as_bool())
        .ok_or_else(|| AetherError::invalid_param(ctx, format!("Missing or invalid boolean: '{key}'")))
}

/// Extract an optional boolean parameter from the JSON params object (default `false`).
pub fn get_param_bool_opt(params: &Value, key: &str) -> bool {
    params.get(key).and_then(|v| v.as_bool()).unwrap_or(false)
}

/// Extract a required owned String parameter from the JSON params object.
pub fn get_param_string(ctx: ErrorContext, params: &Value, key: &str) -> Result<String, AetherError> {
    params
        .get(key)
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or_else(|| AetherError::invalid_param(ctx, format!("Missing or invalid parameter: '{key}'")))
}

/// Extract an optional owned String parameter from the JSON params object.
pub fn get_param_string_opt(params: &Value, key: &str) -> Option<String> {
    params.get(key).and_then(|v| v.as_str()).map(String::from)
}

// ═══════════════════════════════════════════════════════════════════════════════
// JSON output helpers
// ═══════════════════════════════════════════════════════════════════════════════

/// Serialize a value to a pretty-printed JSON string.
///
/// Convenience wrapper around `serde_json::to_string_pretty` that converts
/// the error to `AetherError::Serde`.
pub fn to_json_pretty(value: &impl serde::Serialize) -> Result<String, AetherError> {
    serde_json::to_string_pretty(value).map_err(AetherError::from)
}
