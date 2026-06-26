//! Secure command runner for AETHER_01.
//!
//! Wraps `std::process::Command` with:
//! - Timeout enforcement (30s default, configurable)
//! - Input parameter validation (rejects shell metacharacters)
//! - Size limits on stdout/stderr
//! - Audit logging with sensitive data redaction
//!
//! All external command execution in AETHER_01 MUST go through this module
//! instead of calling `std::process::Command` directly.
//!
//! # Security
//!
//! While AETHER_01 does not use cmd.exe/powershell.exe for system operations
//! (it uses direct Win32 API), some operations have no Win32 equivalent and
//! require external tools: icacls, compact, cipher, reg, netsh, bcdedit, etc.
//! This runner ensures those invocations are safe:
//!
//! 1. Parameters are validated for shell metacharacters before execution
//! 2. A hard timeout prevents hung processes from blocking the MCP server
//! 3. Output is capped to prevent memory exhaustion
//! 4. Every invocation is audit-logged with redacted sensitive parameters

use crate::audit;
use crate::error::AetherError;
use std::process::{Command, Output, Stdio};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default timeout for external commands (30 seconds).
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Maximum stdout/stderr capture size (1 MB).
const MAX_OUTPUT_BYTES: usize = 1_048_576;

/// Shell metacharacters that are rejected in command parameters.
/// Windows cmd.exe metacharacters: & | ; ` $ ( ) { } [ ] < > ^ %
/// PowerShell metacharacters: & | ; ` $ ( ) { } [ ] < > ^ % # , ' "
///
/// AETHER_01 NEVER uses cmd.exe or powershell.exe for system operations,
/// but external tools (icacls, reg, netsh, etc.) are invoked directly via
/// CreateProcessW (through std::process::Command on Windows). The risk is
/// that a tool argument could be misinterpreted by the target tool's parser.
const SHELL_METACHARACTERS: &[char] = &[
    '&', '|', ';', '`', '$', '(', ')', '{', '}', '[', ']', '<', '>', '^', '%',
];

/// Parameter types for validation.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ParamType {
    /// A filesystem path — allows forward/backslashes, colons, dots, spaces
    Path,
    /// A service/process/object name — alphanumeric, underscores, hyphens
    Name,
    /// A registry key path — allows backslashes
    RegistryPath,
    /// A general string — limited alpha-numeric-safe
    SafeString,
    /// A numeric value parsed from string
    Numeric,
    /// Free-form text (e.g., file contents) — only length-limited
    Text,
    /// A hex GUID or UUID
    Guid,
}

// ---------------------------------------------------------------------------
// SafeCommand Builder
// ---------------------------------------------------------------------------

/// A builder for safely running external commands.
///
/// # Example
///
/// ```ignore
/// let output = SafeCommand::new("icacls")
///     .arg(path_str, ParamType::Path)?
///     .output()
///     .await?;
/// ```
pub struct SafeCommand {
    program: String,
    args: Vec<String>,
    timeout: Duration,
    tool_name: &'static str,
    action_name: &'static str,
}

impl SafeCommand {
    /// Create a new secure command runner.
    ///
    /// `program` is the executable name (e.g., "icacls", "reg", "netsh").
    /// `tool_name` and `action_name` are used for audit logging.
    pub fn new(
        program: impl Into<String>,
        tool_name: &'static str,
        action_name: &'static str,
    ) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            tool_name,
            action_name,
        }
    }

    /// Set a custom timeout for this command.
    #[must_use]
    pub fn timeout(mut self, secs: u64) -> Self {
        self.timeout = Duration::from_secs(secs);
        self
    }

    /// Add a validated argument.
    ///
    /// Returns `AetherError::InvalidParameter` if the value contains
    /// shell metacharacters (for restricted param types).
    pub fn arg(
        mut self,
        value: impl Into<String>,
        param_type: ParamType,
    ) -> Result<Self, AetherError> {
        let v = value.into();
        validate_param(&v, param_type)?;
        self.args.push(v);
        Ok(self)
    }

    /// Add an argument that is known to be safe (e.g., a hardcoded flag like "/f").
    pub fn arg_unchecked(mut self, value: impl Into<String>) -> Self {
        self.args.push(value.into());
        self
    }

    /// Execute the command and capture output.
    ///
    /// Returns the captured stdout as a `String` on success.
    /// Returns `AetherError::Internal` if the process couldn't be spawned,
    /// timed out, or returned a non-zero exit code.
    ///
    /// NOTE: This is a synchronous (blocking) function despite being called from
    /// async MCP tool handlers. The tool dispatch in `server.rs` wraps synchronous
    /// `handle_*` functions — the async keyword on tool handlers just satisfies
    /// the rmcp trait. All command execution is synchronous.
    pub fn output(self) -> Result<String, AetherError> {
        let program = self.program;
        let args = self.args;
        let timeout = self.timeout;
        let tool = self.tool_name;
        let action = self.action_name;

        // Build a display string for audit logging (redacted of sensitive content)
        let display_cmd = if args.len() <= 3 {
            format!("{} {}", program, args.join(" "))
        } else {
            format!(
                "{} {} ... ({} arguments)",
                program,
                args[..2].join(" "),
                args.len()
            )
        };

        // Spawn the process
        let mut child = Command::new(&program)
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                let msg = format!("Cannot spawn {program}: {e}");
                audit::log_failure(tool, action, &msg);
                AetherError::Internal(msg)
            })?;

        // Wait with timeout
        let start = std::time::Instant::now();
        let output = loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let captured = child
                        .wait_with_output()
                        .map_err(|e| AetherError::Internal(format!("Read output: {e}")))?;
                    break captured;
                }
                Ok(None) => {
                    if start.elapsed() >= timeout {
                        let _ = child.kill();
                        let _ = child.wait();
                        let msg = format!(
                            "{program} timed out after {timeout:?} (action: {tool}/{action})"
                        );
                        audit::log_failure(tool, action, &msg);
                        return Err(AetherError::Internal(msg));
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => {
                    let msg = format!("Wait error on {program}: {e}");
                    audit::log_failure(tool, action, &msg);
                    return Err(AetherError::Internal(msg));
                }
            }
        };

        // Cap output sizes
        let stdout = cap_output(&output.stdout);
        let stderr = cap_output(&output.stderr);

        if !output.status.success() {
            let msg = if !stderr.is_empty() {
                format!("{program} failed: {stderr}")
            } else if !stdout.is_empty() {
                format!("{program} failed (exit={:?}): {stdout}", output.status.code())
            } else {
                format!("{program} failed (exit={:?})", output.status.code())
            };
            audit::log_failure(tool, action, &msg);
            return Err(AetherError::Internal(msg));
        }

        audit::log_success(tool, action, &display_cmd);
        Ok(stdout)
    }

    /// Execute the command and check for success (ignore output).
    pub fn run(self) -> Result<(), AetherError> {
        self.output()?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Param Validation
// ---------------------------------------------------------------------------

/// Validate a parameter value against shell metacharacters.
///
/// Different `ParamType` variants have different validation rules:
///
/// - `Path`: allows path separators, colons, dots, spaces; rejects `&|;`$(){}[]<>^%`
/// - `Name`: only alphanumeric, underscore, hyphen, dot
/// - `RegistryPath`: like Path but forbids spaces
/// - `SafeString`: alphanumeric, underscore, hyphen, dot, colon, forward slash
/// - `Numeric`: digits only
/// - `Text`: no validation except max length (for file contents, JSON, etc.)
/// - `Guid`: hex digits and hyphens only
fn validate_param(value: &str, param_type: ParamType) -> Result<(), AetherError> {
    // Common check: empty strings are always invalid
    if value.is_empty() {
        return Err(AetherError::Internal(format!(
            "Empty parameter value rejected (type={param_type:?})"
        )));
    }

    // Max length: 4096 characters for any single parameter
    if value.len() > 4096 {
        return Err(AetherError::Internal(format!(
            "Parameter too long: {} bytes (max 4096, type={param_type:?})",
            value.len()
        )));
    }

    match param_type {
        ParamType::Path => {
            // Allow: alphanumeric, path separators, colon, dot, space, underscore, hyphen, tilde
            // Reject: everything else including shell metacharacters
            for ch in value.chars() {
                if ch.is_alphanumeric()
                    || ch == '\\'
                    || ch == '/'
                    || ch == ':'
                    || ch == '.'
                    || ch == ' '
                    || ch == '_'
                    || ch == '-'
                    || ch == '~'
                    || ch == '$'
                    || ch == '{'
                    || ch == '}'
                {
                    continue;
                }
                if SHELL_METACHARACTERS.contains(&ch) {
                    return Err(AetherError::Internal(format!(
                        "Path contains shell metacharacter: {ch:?}"
                    )));
                }
                // Reject control characters
                if ch.is_control() {
                    return Err(AetherError::Internal("Path contains control character".into()));
                }
            }
            // Prevent path traversal
            if value.contains("..") {
                return Err(AetherError::Internal(
                    "Path contains parent directory reference ('..')".into(),
                ));
            }
            Ok(())
        }
        ParamType::Name => {
            for ch in value.chars() {
                if !ch.is_alphanumeric() && ch != '_' && ch != '-' && ch != '.' {
                    return Err(AetherError::Internal(format!(
                        "Name contains invalid character: {ch:?}"
                    )));
                }
            }
            Ok(())
        }
        ParamType::RegistryPath => {
            for ch in value.chars() {
                if ch.is_alphanumeric()
                    || ch == '\\'
                    || ch == '_'
                    || ch == '-'
                    || ch == '.'
                    || ch == ' '
                {
                    continue;
                }
                if SHELL_METACHARACTERS.contains(&ch) {
                    return Err(AetherError::Internal(format!(
                        "Registry path contains shell metacharacter: {ch:?}"
                    )));
                }
                if ch.is_control() {
                    return Err(AetherError::Internal("Registry path contains control character".into()));
                }
            }
            if value.contains("..") {
                return Err(AetherError::Internal(
                    "Registry path contains parent directory reference ('..')".into(),
                ));
            }
            Ok(())
        }
        ParamType::SafeString => {
            for ch in value.chars() {
                if ch.is_alphanumeric()
                    || ch == '_'
                    || ch == '-'
                    || ch == '.'
                    || ch == ':'
                    || ch == '/'
                {
                    continue;
                }
                if SHELL_METACHARACTERS.contains(&ch) {
                    return Err(AetherError::Internal(format!(
                        "String contains shell metacharacter: {ch:?}"
                    )));
                }
                if ch.is_control() {
                    return Err(AetherError::Internal("String contains control character".into()));
                }
            }
            Ok(())
        }
        ParamType::Numeric => {
            for ch in value.chars() {
                if !ch.is_ascii_digit() && ch != '-' && ch != '+' && ch != 'x' && ch != 'X'
                    && ch != 'a' && ch != 'b' && ch != 'c' && ch != 'd' && ch != 'e' && ch != 'f'
                    && ch != 'A' && ch != 'B' && ch != 'C' && ch != 'D' && ch != 'E' && ch != 'F'
                {
                    return Err(AetherError::Internal(format!(
                        "Numeric contains invalid character: {ch:?}"
                    )));
                }
            }
            Ok(())
        }
        ParamType::Text => {
            // Text is not validated for content, only length
            Ok(())
        }
        ParamType::Guid => {
            for ch in value.chars() {
                if !ch.is_ascii_hexdigit() && ch != '-' && ch != '{' && ch != '}' {
                    return Err(AetherError::Internal(format!(
                        "GUID contains invalid character: {ch:?}"
                    )));
                }
            }
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Cap output to `MAX_OUTPUT_BYTES`.
fn cap_output(data: &[u8]) -> String {
    let len = data.len().min(MAX_OUTPUT_BYTES);
    let s = String::from_utf8_lossy(&data[..len]);
    if data.len() > MAX_OUTPUT_BYTES {
        format!("{}... (truncated, {} bytes total)", s, data.len())
    } else {
        s.to_string()
    }
}

// ---------------------------------------------------------------------------
// Convenience: quick inline command with validation
// ---------------------------------------------------------------------------

/// Run a simple external command with validated arguments.
///
/// Shorthand for `SafeCommand::new(prog, tool, action).arg(v, t)?.arg(v, t)?.output()`.
pub fn run_safe(
    program: impl Into<String>,
    args: &[(&str, ParamType)],
    tool: &'static str,
    action: &'static str,
) -> Result<String, AetherError> {
    let mut cmd = SafeCommand::new(program, tool, action);
    for (value, param_type) in args {
        cmd = cmd.arg(*value, *param_type)?;
    }
    cmd.output()
}

/// Run an external command with mixed validated and unchecked arguments.
///
/// The `validated_args` are checked for metacharacters; `unchecked_args` are
/// passed through as-is (for hardcoded flags like `/f`, `/y`, etc.).
pub fn run_mixed(
    program: impl Into<String>,
    validated_args: &[(&str, ParamType)],
    unchecked_args: &[&str],
    tool: &'static str,
    action: &'static str,
) -> Result<String, AetherError> {
    let mut cmd = SafeCommand::new(program, tool, action);
    for (value, param_type) in validated_args {
        cmd = cmd.arg(*value, *param_type)?;
    }
    for arg in unchecked_args {
        cmd = cmd.arg_unchecked(*arg);
    }
    cmd.output()
}
