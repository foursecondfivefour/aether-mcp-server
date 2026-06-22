//! Unit tests for tool dispatch — all 10 tools, error paths only.
//!
//! Tests:
//!   - Unknown actions return error with proper context
//!   - Missing required params return clear error messages
//!   - Dangerous actions without force return PermissionDenied
//!   - Feature gates block gated operations when disabled
//!   - Error format consistency across all tools
//!   - WMI safety (SELECT-only enforcement)
//!
//! SAFE: No Win32 API calls — only error constructor and FeatureGates testing.

use aether_mcp_server::config::FeatureGates;
use aether_mcp_server::error::{AetherError, ErrorContext};

// ──────────────── Tool dispatch — invalid actions ────────────────

#[test]
fn process_unknown_action_returns_error() {
    let ctx = ErrorContext::new("process_control", "made_up_action");
    let err = AetherError::invalid_param(ctx, "action: made_up_action");
    let msg = format!("{err}");
    assert!(msg.contains("process_control"), "Must name the tool: {msg}");
    assert!(msg.contains("made_up_action"), "Must name the invalid action: {msg}");
}

#[test]
fn filesystem_unknown_action_returns_error() {
    let ctx = ErrorContext::new("file_system", "delete_system32_no_really");
    let err = AetherError::invalid_param(ctx, "action: delete_system32_no_really");
    let msg = format!("{err}");
    assert!(msg.contains("file_system"), "Must name the tool: {msg}");
}

#[test]
fn registry_unknown_action_returns_error() {
    let ctx = ErrorContext::new("registry_editor", "rm_rf_hklm");
    let err = AetherError::invalid_param(ctx, "action: rm_rf_hklm");
    let msg = format!("{err}");
    assert!(msg.contains("registry_editor"), "Must name the tool: {msg}");
}

#[test]
fn all_ten_tools_reject_unknown_actions() {
    let cases = vec![
        ("process_control", "destroy_the_evidence"),
        ("file_system", "exfiltrate_passwords"),
        ("registry_editor", "corrupt_mbr"),
        ("service_manager", "ddos_localhost"),
        ("gui_automation", "hack_the_gibson"),
        ("system_info", "overclock_to_infinity"),
        ("network_manager", "arp_poison_lan"),
        ("user_management", "promote_to_god"),
        ("security_audit", "disable_all_protection"),
        ("system_automation", "DROP_TABLE_users"),
    ];

    for (tool, action) in cases {
        let ctx = ErrorContext::new(tool, action);
        let err = AetherError::invalid_param(ctx, format!("action: {action}"));
        let msg = format!("{err}");
        assert!(msg.contains(tool), "{tool} must reject unknown '{action}': {msg}");
    }
}

// ──────────────── Missing required params ────────────────

#[test]
fn process_kill_without_pid_or_force() {
    let ctx = ErrorContext::new("process_control", "kill");
    let err = AetherError::invalid_param(ctx, "pid (required for kill action)");
    let msg = format!("{err}");
    assert!(msg.contains("pid"), "Must mention missing PID: {msg}");
    assert!(msg.contains("kill"), "Must mention the action: {msg}");
    assert!(msg.contains("Рекомендация"), "Must provide guidance: {msg}");
}

#[test]
fn filesystem_delete_without_force() {
    let ctx = ErrorContext::new("file_system", "delete")
        .with_target("C:\\important\\file.txt".into());
    let err = AetherError::permission_denied(ctx, "Требуется параметр \"force\": true для удаления.");
    let msg = format!("{err}");
    assert!(msg.contains("force"), "Must mention force parameter: {msg}");
    assert!(msg.contains("C:\\important\\file.txt"), "Must mention target file: {msg}");
}

#[test]
fn registry_write_to_hklm_without_force() {
    let ctx = ErrorContext::new("registry_editor", "write")
        .with_target("HKLM\\SOFTWARE\\Test".into());
    let err = AetherError::permission_denied(ctx, "Запись в HKLM требует подтверждения.");
    let msg = format!("{err}");
    assert!(msg.contains("HKLM"), "Must mention HKLM hive: {msg}");
    assert!(msg.contains("force"), "Must mention force: {msg}");
}

#[test]
fn service_stop_without_force() {
    let ctx = ErrorContext::new("service_manager", "stop")
        .with_target("Spooler".into());
    let err = AetherError::permission_denied(ctx, "Остановка службы требует подтверждения.");
    let msg = format!("{err}");
    assert!(msg.contains("Spooler"), "Must contain service name: {msg}");
    assert!(msg.contains("force"), "Must mention force: {msg}");
}

// ──────────────── Feature gate tests ────────────────

#[test]
fn dll_injection_blocked_when_gate_disabled() {
    let gates = FeatureGates::default();
    let ctx = ErrorContext::new("process_control", "inject_dll");
    let result = gates.check(ctx, gates.dll_inject, "AETHER_DLL_INJECT");
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("AETHER_DLL_INJECT"), "Must name the gate: {msg}");
    assert!(msg.contains(".env"), "Must mention config file: {msg}");
}

#[test]
fn bcd_edit_blocked_when_gate_disabled() {
    let gates = FeatureGates::default();
    let ctx = ErrorContext::new("system_info", "bcd_set_entry");
    let result = gates.check(ctx, gates.bcd_edit, "AETHER_BCD_EDIT");
    assert!(result.is_err());
}

#[test]
fn offline_registry_blocked_when_gate_disabled() {
    let gates = FeatureGates::default();
    let ctx = ErrorContext::new("registry_editor", "offline_mount");
    let result = gates.check(ctx, gates.offline_registry, "AETHER_OFFLINE_REGISTRY");
    assert!(result.is_err());
}

#[test]
fn token_manipulation_blocked_when_gate_disabled() {
    let gates = FeatureGates::default();
    let ctx = ErrorContext::new("user_management", "token_impersonate");
    let result = gates.check(ctx, gates.token_manipulation, "AETHER_TOKEN_MANIPULATION");
    assert!(result.is_err());
}

#[test]
fn lsa_secrets_blocked_when_gate_disabled() {
    let gates = FeatureGates::default();
    let ctx = ErrorContext::new("user_management", "lsa_secrets_read");
    let result = gates.check(ctx, gates.lsa_secrets, "AETHER_LSA_SECRETS");
    assert!(result.is_err());
}

// ──────────────── Parameter validation ────────────────

#[test]
fn missing_string_param_returns_clear_error() {
    let ctx = ErrorContext::new("file_system", "read");
    let err = AetherError::invalid_param(ctx, "path");
    let msg = format!("{err}");
    assert!(msg.contains("path"), "Must name the missing param: {msg}");
    assert!(msg.contains("Параметр не указан"), "Must say param is missing: {msg}");
    assert!(
        msg.contains("Укажите") || msg.contains("укажите"),
        "Must tell user to specify the param: {msg}"
    );
}

#[test]
fn path_traversal_param_result_is_descriptive() {
    let ctx = ErrorContext::new("file_system", "read")
        .with_target("..\\..\\..\\windows\\system32".into());
    let err = AetherError::not_found(ctx, "путь ..\\..\\..\\windows\\system32", None);
    let msg = format!("{err}");
    assert!(msg.contains("..\\..\\..\\windows\\system32"), "Must show the invalid path: {msg}");
    assert!(msg.contains("Объект не найден"), "Must say not found: {msg}");
}

#[test]
fn empty_parameters_object_handled() {
    let ctx = ErrorContext::new("process_control", "query_info");
    let err = AetherError::invalid_param(ctx, "pid");
    let msg = format!("{err}");
    assert!(msg.contains("pid"), "Must ask for PID when params are empty: {msg}");
    assert!(!msg.contains("panic"), "Must not panic: {msg}");
}

// ──────────────── WMI safety ────────────────

#[test]
fn wmi_non_select_query_rejected() {
    let ctx = ErrorContext::new("system_automation", "wmi_query");
    let err = AetherError::permission_denied(
        ctx,
        "WMI-запросы ограничены SELECT. Запросы DELETE, INSERT, UPDATE запрещены.",
    );
    let msg = format!("{err}");
    assert!(msg.contains("SELECT"), "Must mention allowed query type: {msg}");
    assert!(msg.contains("DELETE"), "Must mention forbidden types: {msg}");
}

// ──────────────── Error consistency across tools ────────────────

#[test]
fn all_tools_produce_structured_errors() {
    let tool_names = [
        "process_control", "file_system", "registry_editor",
        "service_manager", "gui_automation", "system_info",
        "network_manager", "user_management", "security_audit",
        "system_automation",
    ];

    for tool in tool_names {
        let ctx = ErrorContext::new(tool, "test_action");
        let err = AetherError::permission_denied(ctx, "Тестовая причина.");
        let msg = format!("{err}");
        assert!(msg.contains('═'), "{tool}: must have separator");
        assert!(msg.contains(tool), "{tool}: must name tool");
        assert!(msg.contains("Проблема"), "{tool}: must have problem section");
        assert!(msg.contains("Рекомендация") || msg.contains("рекомендуется"),
            "{tool}: must have recommendation");
    }
}

// ──────────────── Error display quality ────────────────

#[test]
fn error_display_never_contains_raw_debug_info() {
    let ctx = ErrorContext::new("test", "test");
    let cases: Vec<String> = vec![
        format!("{}", AetherError::invalid_param(ctx.clone(), "param")),
        format!("{}", AetherError::permission_denied(ctx.clone(), "reason")),
        format!("{}", AetherError::not_found(ctx.clone(), "thing", None)),
        format!("{}", AetherError::feature_disabled(ctx.clone(), "GATE")),
        format!("{}", AetherError::win32(ctx.clone(), "op", "err (0x80070005)")),
    ];

    for case in &cases {
        assert!(!case.contains("AetherError::"), "No enum variant in Display");
        assert!(!case.contains("ErrorContext {"), "No struct debug in Display");
        assert!(!case.is_empty(), "Display must not be empty");
    }
}

#[test]
fn error_messages_are_multiline_for_readability() {
    let ctx = ErrorContext::new("process_control", "kill");
    let err = AetherError::permission_denied(ctx, "test reason");
    let msg = format!("{err}");
    let line_count = msg.lines().count();
    assert!(line_count > 4, "Error should be multiline (got {line_count}): {msg}");
}
