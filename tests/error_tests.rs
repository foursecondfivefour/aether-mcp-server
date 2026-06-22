//! Unit tests for error handling — pure Rust, no Windows dependencies.
//!
//! Tests: ErrorContext, format_error(), extract_win32_code(), humanize_win32(),
//! error constructors with structured output, Display trait.

use aether_mcp_server::error::{AetherError, ErrorContext};

// ──────────────── ErrorContext ────────────────

#[test]
fn error_context_new_has_correct_tool_and_action() {
    let ctx = ErrorContext::new("process_control", "kill");
    assert_eq!(ctx.tool, "process_control");
    assert_eq!(ctx.action, "kill");
    assert_eq!(ctx.target, None);
}

#[test]
fn error_context_with_target_sets_target() {
    let ctx = ErrorContext::new("file_system", "delete")
        .with_target("C:\\test.txt".into());
    assert_eq!(ctx.tool, "file_system");
    assert_eq!(ctx.action, "delete");
    assert_eq!(ctx.target.as_deref(), Some("C:\\test.txt"));
}

#[test]
fn error_context_clone_works() {
    let ctx = ErrorContext::new("network_manager", "adapters")
        .with_target("Ethernet".into());
    let cloned = ctx.clone();
    assert_eq!(cloned.tool, ctx.tool);
    assert_eq!(cloned.action, ctx.action);
    assert_eq!(cloned.target, ctx.target);
}

// ──────────────── extract_win32_code ────────────────

#[test]
fn extract_hex_code_0x80070005() {
    // Use the public API through win32() which calls extract_win32_code internally
    let raw = "Отказано в доступе. (0x80070005)";
    // extract_win32_code is private but called by win32()
    let err = AetherError::win32(
        ErrorContext::new("test", "test"),
        "test_op",
        raw,
    );
    let msg = format!("{err}");
    assert!(msg.contains("0x80070005"), "Error should contain the hex code: {msg}");
}

#[test]
fn extract_hex_code_0x80070002() {
    let raw = "Не удается найти указанный файл. (0x80070002)";
    let err = AetherError::win32(
        ErrorContext::new("test", "test"),
        "test_op",
        raw,
    );
    let msg = format!("{err}");
    assert!(msg.contains("0x80070002"), "Error should contain the hex code: {msg}");
}

#[test]
fn extract_hex_code_0x80070424() {
    let raw = "Указанная служба не установлена. (0x80070424)";
    let err = AetherError::win32(
        ErrorContext::new("test", "test"),
        "test_op",
        raw,
    );
    let msg = format!("{err}");
    assert!(msg.contains("0x80070424"), "Error should contain the hex code: {msg}");
}

// ──────────────── format_error structure ────────────────

#[test]
fn invalid_param_includes_header_and_sections() {
    let ctx = ErrorContext::new("process_control", "kill");
    let err = AetherError::invalid_param(ctx, "pid");

    let msg = format!("{err}");

    // Header section
    assert!(msg.contains("Инструмент:"), "Must contain header: {msg}");
    assert!(msg.contains("process_control"), "Must contain tool name: {msg}");
    assert!(msg.contains("kill"), "Must contain action name: {msg}");
    assert!(msg.contains("Параметр не указан"), "Must contain error type: {msg}");

    // Problem section
    assert!(msg.contains("Проблема:"), "Must contain problem section: {msg}");
    assert!(msg.contains("pid"), "Must mention missing param: {msg}");

    // Recommendation section
    assert!(msg.contains("Рекомендация:"), "Must contain recommendation: {msg}");
}

#[test]
fn permission_denied_includes_force_hint() {
    let ctx = ErrorContext::new("process_control", "kill");
    let err = AetherError::permission_denied(ctx, "Система отклонила операцию.");

    let msg = format!("{err}");

    assert!(msg.contains("Доступ запрещён"), "Must contain error type: {msg}");
    assert!(msg.contains("Проблема:"), "Must contain problem: {msg}");
    assert!(msg.contains("force"), "Must mention force parameter: {msg}");
    assert!(msg.contains("Рекомендация:"), "Must contain recommendation: {msg}");
}

#[test]
fn not_found_includes_guidance() {
    let ctx = ErrorContext::new("registry_editor", "read");
    let err = AetherError::not_found(ctx, "registry key HKCU\\Test", Some("registry_editor.enumerate"));

    let msg = format!("{err}");

    assert!(msg.contains("Объект не найден"), "Must contain error type: {msg}");
    assert!(msg.contains("HKCU\\Test"), "Must mention what was not found: {msg}");
    assert!(msg.contains("registry_editor.enumerate"), "Must mention where to look: {msg}");
}

#[test]
fn feature_disabled_includes_env_instructions() {
    let ctx = ErrorContext::new("process_control", "inject_dll");
    let err = AetherError::feature_disabled(ctx, "AETHER_DLL_INJECT");

    let msg = format!("{err}");

    assert!(msg.contains("Функция отключена"), "Must contain error type: {msg}");
    assert!(msg.contains("AETHER_DLL_INJECT"), "Must mention gate name: {msg}");
    assert!(msg.contains(".env"), "Must mention .env file: {msg}");
    assert!(msg.contains("AETHER_DLL_INJECT=1"), "Must show how to enable: {msg}");
}

#[test]
fn win32_error_includes_explanation() {
    let ctx = ErrorContext::new("file_system", "delete");
    let err = AetherError::win32(ctx, "DeleteFileW", "Отказано в доступе. (0x80070005)");

    let msg = format!("{err}");

    assert!(msg.contains("Системная ошибка"), "Must contain error type: {msg}");
    assert!(msg.contains("DeleteFileW"), "Must contain operation name: {msg}");
    assert!(msg.contains("0x80070005"), "Must contain error code: {msg}");
    assert!(msg.contains("Система сообщает:"), "Must contain system section: {msg}");
}

// ──────────────── Error message quality ────────────────

#[test]
fn errors_never_contain_dead_end_phrases() {
    let ctx = ErrorContext::new("test", "test");
    let cases: Vec<String> = vec![
        format!("{}", AetherError::invalid_param(ctx.clone(), "param")),
        format!("{}", AetherError::permission_denied(ctx.clone(), "reason")),
        format!("{}", AetherError::not_found(ctx.clone(), "thing", None)),
        format!("{}", AetherError::feature_disabled(ctx.clone(), "GATE")),
        format!("{}", AetherError::win32(ctx.clone(), "op", "error (0x80070005)")),
    ];

    for case in &cases {
        // No dead-end phrases
        assert!(!case.contains("что-то пошло не так"), "Must not use vague language");
        assert!(!case.contains("обратитесь к администратору"), "Must not redirect to admin");
        assert!(!case.contains("Invalid"), "Must not use English 'Invalid'");
        assert!(!case.contains("Illegal"), "Must not use 'Illegal'");
        assert!(!case.contains("Fatal"), "Must not use 'Fatal'");

        // Must have a path forward
        assert!(case.contains("Рекомендация") || case.contains("рекомендуется"),
            "Every error must have a recommendation: {case}");
    }
}

#[test]
fn errors_use_formal_vy_tone() {
    let ctx = ErrorContext::new("test", "test");
    let cases: Vec<String> = vec![
        format!("{}", AetherError::invalid_param(ctx.clone(), "param")),
        format!("{}", AetherError::permission_denied(ctx.clone(), "reason")),
    ];

    for case in &cases {
        // Formal tone markers: polite imperatives or «Вы» forms
        let has_vy_tone = case.contains("Вы")
            || case.contains("Вам")
            || case.contains("Вас")
            || case.contains("Укажите")
            || case.contains("Проверьте")
            || case.contains("Запустите")
            || case.contains("Убедитесь");
        assert!(has_vy_tone, "Errors must use formal tone: {case}");
        // No exclamation marks
        assert!(!case.contains('!'), "No exclamation marks allowed: {case}");
        // No accusations
        assert!(!case.contains("Вы неверно"), "Must not blame user: {case}");
        assert!(!case.contains("ваша ошибка"), "Must not blame user: {case}");
    }
}

// ──────────────── From impls ────────────────

#[test]
fn from_std_io_error() {
    let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
    let aether: AetherError = io_err.into();
    let msg = format!("{aether}");
    assert!(msg.contains("Ошибка ввода/вывода"), "Must contain IO error prefix: {msg}");
    assert!(msg.contains("access denied"), "Must contain original message: {msg}");
}

#[test]
fn from_serde_json_error() {
    let serde_err = serde_json::from_str::<serde_json::Value>("not valid json").unwrap_err();
    let aether: AetherError = serde_err.into();
    let msg = format!("{aether}");
    assert!(msg.contains("Ошибка обработки данных"), "Must contain serde error prefix: {msg}");
}

// ──────────────── humanize_win32 coverage ────────────────

#[test]
fn humanize_known_code_0x80070005() {
    let ctx = ErrorContext::new("test", "test");
    let err = AetherError::win32(ctx, "test_op", "(0x80070005)");
    let msg = format!("{err}");
    // Our dictionary for 0x80070005 mentions "штатный защитный механизм"
    assert!(msg.contains("безопасности") || msg.contains("доступа"), "Must explain security context: {msg}");
}

#[test]
fn humanize_known_code_0x80070002() {
    let ctx = ErrorContext::new("test", "test");
    let err = AetherError::win32(ctx, "test_op", "(0x80070002)");
    let msg = format!("{err}");
    assert!(msg.contains("обнаружен") || msg.contains("найден"),
        "Must mention 'not found' context: {msg}");
}

#[test]
fn humanize_known_code_0x80070424() {
    let ctx = ErrorContext::new("test", "test");
    let err = AetherError::win32(ctx, "test_op", "(0x80070424)");
    let msg = format!("{err}");
    assert!(msg.contains("Служба") || msg.contains("установлена"),
        "Must mention service context: {msg}");
}

#[test]
fn humanize_unknown_code_falls_back_to_format_message() {
    let ctx = ErrorContext::new("test", "test");
    // 0x8007139F is a real Win32 code (The group already exists) — not in our dictionary
    let err = AetherError::win32(ctx, "test_op", "(0x8007139F)");
    let msg = format!("{err}");
    // Should still contain the code — FormatMessageW will fill it in
    assert!(msg.contains("0x8007139F"), "Unknown code should still be shown: {msg}");
}

// ──────────────── Cyrillic in errors ────────────────

#[test]
fn cyrillic_param_names_in_errors() {
    let ctx = ErrorContext::new("file_system", "write");
    let err = AetherError::invalid_param(ctx, "путь_к_файлу");

    let msg = format!("{err}");

    assert!(msg.contains("путь_к_файлу"), "Cyrillic param names must be preserved: {msg}");
    assert!(msg.contains("Укажите корректное значение"), "Must show guidance in Russian: {msg}");
}

#[test]
fn cyrillic_error_reasons_preserved() {
    let ctx = ErrorContext::new("test", "test");
    let err = AetherError::permission_denied(
        ctx,
        "Файл защищён от записи, так как находится в системной директории.",
    );
    let msg = format!("{err}");

    assert!(msg.contains("Файл защищён"), "Cyrillic text must be preserved: {msg}");
    assert!(msg.contains("системной директории"), "Cyrillic text must be preserved: {msg}");
}
