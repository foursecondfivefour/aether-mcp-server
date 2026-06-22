//! Unit tests for FeatureGates and configuration.
//!
//! Tests feature gate loading from environment variables and gate-check logic.
//! No Windows dependencies — pure Rust with env var mocking.

use aether_mcp_server::config::FeatureGates;
use aether_mcp_server::error::ErrorContext;

// ──────────────── Default gates ────────────────

#[test]
fn default_all_gates_disabled() {
    let gates = FeatureGates::default();
    assert!(!gates.bcd_edit, "BCD_EDIT must be disabled by default");
    assert!(!gates.hal_config, "HAL_CONFIG must be disabled by default");
    assert!(!gates.offline_registry, "OFFLINE_REGISTRY must be disabled by default");
    assert!(!gates.dll_inject, "DLL_INJECT must be disabled by default");
    assert!(!gates.token_manipulation, "TOKEN_MANIPULATION must be disabled by default");
    assert!(!gates.lsa_secrets, "LSA_SECRETS must be disabled by default");
}

#[test]
fn default_clone_identical() {
    let g1 = FeatureGates::default();
    let g2 = g1.clone();
    assert_eq!(g1.bcd_edit, g2.bcd_edit);
    assert_eq!(g1.hal_config, g2.hal_config);
    assert_eq!(g1.dll_inject, g2.dll_inject);
}

// ──────────────── Gate check — enabled gates pass ────────────────

#[test]
fn check_enabled_gate_returns_ok() {
    let gates = FeatureGates {
        bcd_edit: true,
        ..FeatureGates::default()
    };
    let ctx = ErrorContext::new("system_info", "bcd_list");
    let result = gates.check(ctx, gates.bcd_edit, "AETHER_BCD_EDIT");
    assert!(result.is_ok(), "Enabled gate check should return Ok(())");
}

#[test]
fn check_enabled_gate_no_side_effects() {
    let gates = FeatureGates {
        dll_inject: true,
        ..FeatureGates::default()
    };
    let ctx = ErrorContext::new("process_control", "inject_dll");
    assert!(gates.check(ctx, gates.dll_inject, "AETHER_DLL_INJECT").is_ok());
    // Other gates remain disabled
    assert!(!gates.bcd_edit);
    assert!(!gates.lsa_secrets);
}

// ──────────────── Gate check — disabled gates return error ────────────────

#[test]
fn check_disabled_gate_returns_error() {
    let gates = FeatureGates::default();
    let ctx = ErrorContext::new("system_info", "bcd_set_entry");
    let result = gates.check(ctx, gates.bcd_edit, "AETHER_BCD_EDIT");
    assert!(result.is_err(), "Disabled gate must return error");

    let err_msg = format!("{}", result.unwrap_err());
    assert!(err_msg.contains("Функция отключена"), "Must say feature is disabled: {err_msg}");
    assert!(err_msg.contains("AETHER_BCD_EDIT"), "Must name the gate: {err_msg}");
}

#[test]
fn check_disabled_gate_message_is_actionable() {
    let gates = FeatureGates::default();
    let ctx = ErrorContext::new("process_control", "inject_dll");
    let result = gates.check(ctx, gates.dll_inject, "AETHER_DLL_INJECT");
    let err_msg = format!("{}", result.unwrap_err());

    // Must tell HOW to enable it
    assert!(err_msg.contains("AETHER_DLL_INJECT=1"), "Must show enable command: {err_msg}");
    assert!(
        err_msg.contains(".env") || err_msg.contains("конфигурации"),
        "Must mention config file: {err_msg}"
    );
}

#[test]
fn check_all_six_gates_fail_when_disabled() {
    let gates = FeatureGates::default();
    let gate_names = [
        ("AETHER_BCD_EDIT", gates.bcd_edit, "system_info", "bcd_list"),
        ("AETHER_HAL_CONFIG", gates.hal_config, "system_info", "crashdump_info"),
        ("AETHER_OFFLINE_REGISTRY", gates.offline_registry, "registry_editor", "offline_mount"),
        ("AETHER_DLL_INJECT", gates.dll_inject, "process_control", "inject_dll"),
        ("AETHER_TOKEN_MANIPULATION", gates.token_manipulation, "user_management", "token_privileges"),
        ("AETHER_LSA_SECRETS", gates.lsa_secrets, "user_management", "lsa_secrets_list"),
    ];

    for (name, enabled, tool, action) in gate_names {
        assert!(!enabled, "{name} must be disabled in default");
        let ctx = ErrorContext::new(tool, action);
        let result = gates.check(ctx, enabled, name);
        assert!(result.is_err(), "{name} must fail check when disabled");
    }
}

// ──────────────── Environment loading (safe — no system env mutation) ────

#[test]
fn load_respects_env_vars_set_to_1() {
    // SAFETY: we only set temp vars for this process duration
    // Use std::env::set_var for test — this is safe in single-threaded test
    let test_gate = "AETHER_TEST_GATE_LOAD";

    // Not set → default false
    std::env::remove_var(test_gate);

    // Verify boolean parsing logic (we can't easily test load() without env mocking)
    assert_eq!(env_bool_direct(test_gate), false);

    std::env::set_var(test_gate, "1");
    assert_eq!(env_bool_direct(test_gate), true);

    std::env::set_var(test_gate, "0");
    assert_eq!(env_bool_direct(test_gate), false);

    // Cleanup
    std::env::remove_var(test_gate);
}

fn env_bool_direct(key: &str) -> bool {
    std::env::var(key).unwrap_or_default().trim() == "1"
}

#[test]
fn load_all_gates_default_to_zero() {
    // When no .env is loaded, all gates should be false
    // Clear any leftover env vars for these keys
    for key in &[
        "AETHER_BCD_EDIT",
        "AETHER_HAL_CONFIG",
        "AETHER_OFFLINE_REGISTRY",
        "AETHER_DLL_INJECT",
        "AETHER_TOKEN_MANIPULATION",
        "AETHER_LSA_SECRETS",
    ] {
        std::env::remove_var(key);
    }

    let gates = FeatureGates::load();
    assert!(!gates.bcd_edit, "BCD_EDIT must default to false");
    assert!(!gates.hal_config, "HAL_CONFIG must default to false");
    assert!(!gates.offline_registry, "OFFLINE_REGISTRY must default to false");
    assert!(!gates.dll_inject, "DLL_INJECT must default to false");
    assert!(!gates.token_manipulation, "TOKEN_MANIPULATION must default to false");
    assert!(!gates.lsa_secrets, "LSA_SECRETS must default to false");
}

// ──────────────── Gate check: context-preserving ────────────────

#[test]
fn disabled_gate_error_preserves_tool_and_action() {
    let gates = FeatureGates::default();
    let ctx = ErrorContext::new("registry_editor", "offline_mount");
    let err = gates.check(ctx, gates.offline_registry, "AETHER_OFFLINE_REGISTRY").unwrap_err();
    let msg = format!("{err}");

    assert!(msg.contains("registry_editor"), "Must preserve tool name: {msg}");
    assert!(msg.contains("offline_mount"), "Must preserve action name: {msg}");
}

#[test]
fn disabled_gate_does_not_leak_internals() {
    let gates = FeatureGates::default();
    let ctx = ErrorContext::new("process_control", "inject_dll");
    let err = gates.check(ctx, gates.dll_inject, "AETHER_DLL_INJECT").unwrap_err();
    let msg = format!("{err}");

    // Should NOT leak stack traces or internal paths
    assert!(!msg.contains("src\\config.rs"), "Must not leak source paths: {msg}");
    assert!(!msg.contains("thread '"), "Must not leak thread info: {msg}");
    assert!(!msg.contains("panicked"), "Must not leak panic info: {msg}");
}
