//! Unified error types for the AETHER_01 MCP server.
//!
//! Design (RFC 9457 + Elastic UI Framework + NN Group, June 2026):
//!   - Structured: Problem → Reason → Recommendation
//!   - Formal tone: «Вы», no accusations, no dead-ends
//!   - Win32 codes auto-translated via FormatMessageW + curated dictionary
//!   - Every error provides a concrete path forward

#![allow(unsafe_code)]

use thiserror::Error;

/// Context for every error — stable fields for categorisation (RFC 9457).
///
/// Captures *where* the error occurred before any constructor is called.
#[derive(Debug, Clone)]
pub struct ErrorContext {
    /// Tool name (e.g. "process_control")
    pub tool: &'static str,
    /// Action name (e.g. "kill")
    pub action: &'static str,
    /// Optional description of the target (e.g. "notepad.exe (PID 1234)")
    pub target: Option<String>,
}

impl ErrorContext {
    /// Create a new error context without a target.
    #[must_use]
    pub fn new(tool: &'static str, action: &'static str) -> Self {
        Self { tool, action, target: None }
    }

    /// Attach a target description and return the context.
    #[must_use]
    #[allow(dead_code)]
    pub fn with_target(mut self, target: String) -> Self {
        self.target = Some(target);
        self
    }
}

// ──────────────────────────────────────────────────────────────────────────
// FFI: FormatMessageW — Win32 error code → human-readable text
// ──────────────────────────────────────────────────────────────────────────

#[link(name = "kernel32")]
extern "system" {
    fn FormatMessageW(
        dwflags: u32, lpsource: *const std::ffi::c_void,
        dwmessageid: u32, dwlanguageid: u32,
        lpbuffer: *mut u16, nsize: u32,
        arguments: *const *const i8,
    ) -> u32;
}

const FORMAT_MESSAGE_FROM_SYSTEM: u32 = 0x00001000;
const FORMAT_MESSAGE_IGNORE_INSERTS: u32 = 0x00000200;

/// Convert a Win32 error code to a human-readable message in the system language.
#[must_use]
fn win32_description(code: u32) -> String {
    let mut buf = vec![0u16; 512];
    let flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    let len = unsafe {
        FormatMessageW(flags, std::ptr::null(), code, 0, buf.as_mut_ptr(), buf.len() as u32, std::ptr::null())
    };
    if len == 0 {
        return format!("0x{code:08X}");
    }
    String::from_utf16_lossy(&buf[..len as usize]).trim().to_string()
}

/// Curated human explanations for the 12 most common Win32 codes.
/// Falls back to FormatMessageW for everything else.
#[must_use]
fn humanize_win32(code: u32) -> String {
    let sys = win32_description(code);
    match code {
        0x80070005 => format!(
            "Система отклонила операцию из соображений безопасности.\n\
             Это штатный защитный механизм Windows. Наиболее вероятные причины:\n\
             (1) отсутствие прав администратора,\n\
             (2) целевой объект защищён на уровне ядра,\n\
             (3) необходима конкретная привилегия (SeBackupPrivilege, SeDebugPrivilege).\n\
             Системный ответ: {} (0x{code:08X})", sys
        ),
        0x80070002 => format!(
            "Указанный объект не обнаружен в системе.\n\
             Возможно, путь, имя или идентификатор указаны некорректно,\n\
             либо объект был удалён или перемещён.\n\
             Системный ответ: {} (0x{code:08X})", sys
        ),
        0x80070057 => format!(
            "Один из переданных параметров имеет недопустимое значение или формат.\n\
             Убедитесь, что идентификаторы (PID, TID) существуют,\n\
             а пути соответствуют требованиям файловой системы.\n\
             Системный ответ: {} (0x{code:08X})", sys
        ),
        0x80070424 => format!(
            "Служба с указанным именем не зарегистрирована в системе.\n\
             Проверьте список доступных служб через service_manager.list.\n\
             Системный ответ: {} (0x{code:08X})", sys
        ),
        0x80070426 => format!(
            "Операция невозможна, поскольку служба не запущена.\n\
             Сначала запустите службу, затем повторите операцию.\n\
             Системный ответ: {} (0x{code:08X})", sys
        ),
        0x8007007E => format!(
            "Не удалось найти указанный модуль или библиотеку.\n\
             Проверьте, что файл существует по указанному пути и не повреждён.\n\
             Системный ответ: {} (0x{code:08X})", sys
        ),
        0x8007007A => format!(
            "Недостаточно системных ресурсов для завершения операции.\n\
             Возможно, исчерпан лимит памяти, handles или виртуального адресного пространства.\n\
             Системный ответ: {} (0x{code:08X})", sys
        ),
        0x800700B7 => format!(
            "Ошибка целостности данных. Переданные данные повреждены,\n\
             не соответствуют ожидаемому формату или были изменены.\n\
             Системный ответ: {} (0x{code:08X})", sys
        ),
        0x80070020 => format!(
            "Нарушение совместного доступа к файлу: файл заблокирован другим процессом.\n\
             Закройте программу, использующую файл, и повторите попытку.\n\
             Системный ответ: {} (0x{code:08X})", sys
        ),
        0x80070013 => format!(
            "Носитель защищён от записи.\n\
             Снимите защиту от записи или выберите другой путь для сохранения данных.\n\
             Системный ответ: {} (0x{code:08X})", sys
        ),
        0x800700DF => format!(
            "Файл превышает максимально допустимый размер для данной операции.\n\
             Используйте буферизованное чтение/запись или разбейте файл на части.\n\
             Системный ответ: {} (0x{code:08X})", sys
        ),
        0x80070050 => format!(
            "Файл с таким именем уже существует.\n\
             Используйте другое имя, удалите существующий файл\n\
             (с параметром \"force\": true) или включите режим перезаписи.\n\
             Системный ответ: {} (0x{code:08X})", sys
        ),
        _ => format!("Система сообщает: {sys} (0x{code:08X})"),
    }
}

/// Extract a numeric Win32 code from an error string.
fn extract_win32_code(raw: &str) -> Option<u32> {
    if let Some(pos) = raw.find("0x") {
        let hex = &raw[pos..];
        let end = hex.chars().position(|c| !c.is_ascii_hexdigit() && c != 'x' && c != 'X').unwrap_or(hex.len());
        u32::from_str_radix(&hex[2..end], 16).ok()
    } else {
        raw.chars().filter(|c| c.is_ascii_digit()).collect::<String>().parse().ok()
    }
}

// ════════════════════════════════════════════════════════════════════════
// Unified error formatter (Elastic UI 3-part: Problem → Reason → Recommendation)
// ════════════════════════════════════════════════════════════════════════

const SEP: &str = "══════════════════════════════════════════════════════";

/// Render a structured error message.
///
/// Layout:
///   ────────────────────────────
///     Инструмент:  <tool>
///     Действие:    <action>
///     Цель:        <target>?   (only if present)
///     Тип ошибки:  <title>
///   ────────────────────────────
///   Проблема:
///     <problem>
///   Причина:                    (only if Some)
///     <reason>
///   Система сообщает:           (only if Some)
///     <sys_msg>
///   Рекомендация:
///     <recommendation>
///   Пример корректного вызова:   (only if Some)
///     <example>
fn format_error(ctx: &ErrorContext, title: &str, problem: &str, reason: Option<&str>, sys_msg: Option<&str>, recommendation: &str, example: Option<&str>) -> String {
    let mut s = String::with_capacity(1024);

    // ── Header ──────────────────────────────────────────────────────────
    s.push_str(SEP);
    s.push('\n');
    s.push_str(&format!("  Инструмент:  {}\n  Действие:    {}\n", ctx.tool, ctx.action));
    if let Some(ref t) = ctx.target {
        s.push_str(&format!("  Цель:        {}\n", t));
    }
    s.push_str(&format!("  Тип ошибки:  {}\n", title));
    s.push_str(SEP);
    s.push_str("\n\n");

    // ── Problem ─────────────────────────────────────────────────────────
    s.push_str("Проблема:\n  ");
    s.push_str(problem);
    s.push_str("\n\n");

    // ── Reason (optional) ───────────────────────────────────────────────
    if let Some(r) = reason {
        s.push_str("Причина:\n  ");
        s.push_str(r);
        s.push_str("\n\n");
    }

    // ── System message (optional) ───────────────────────────────────────
    if let Some(m) = sys_msg {
        s.push_str("Система сообщает:\n  ");
        s.push_str(m);
        s.push_str("\n\n");
    }

    // ── Recommendation (mandatory — never a dead-end) ─────────────────────
    s.push_str("Рекомендация:\n  ");
    s.push_str(&recommendation.replace('\n', "\n  "));
    s.push('\n');

    // ── Example (optional) ──────────────────────────────────────────────
    if let Some(e) = example {
        s.push_str("\nПример корректного вызова:\n  ");
        s.push_str(e);
        s.push('\n');
    }

    s
}

// ════════════════════════════════════════════════════════════════════════
// Error variants
// ════════════════════════════════════════════════════════════════════════

/// Top-level error type for all AETHER operations.
#[derive(Error, Debug)]
pub enum AetherError {
    /// A required parameter is missing or has an unacceptable value.
    #[error("{0}")]
    InvalidParameter(String),

    /// The operation was denied by the system or requires elevation.
    #[error("{0}")]
    PermissionDenied(String),

    /// The target (file, key, process, service) does not exist.
    #[error("{0}")]
    NotFound(String),

    /// A Windows API call failed.
    #[error("{0}")]
    Win32Error(String),

    /// The operation is gated behind a `.env` feature flag.
    #[error("{0}")]
    FeatureDisabled(String),

    /// Disk or network I/O error.
    #[error("{0}")]
    Io(String),

    /// JSON parsing or serialisation failed.
    #[error("{0}")]
    Serde(String),

    /// WMI query failed or was rejected.
    #[error("{0}")]
    WmiError(String),

    /// Unexpected internal error.
    #[error("{0}")]
    Internal(String),
}

// ════════════════════════════════════════════════════════════════════════
// Constructors — formal «Вы» style, no blame, always a path forward
// ════════════════════════════════════════════════════════════════════════

impl AetherError {
    // ── InvalidParameter ────────────────────────────────────────────────

    /// A required parameter is missing.
    #[must_use]
    pub fn invalid_param(ctx: ErrorContext, what_is_missing: impl Into<String>) -> Self {
        let m = what_is_missing.into();
        Self::InvalidParameter(format_error(
            &ctx, "Параметр не указан",
            &format!("Для выполнения «{}» требуется параметр: {m}.", ctx.action),
            None, None,
            &format!("Укажите корректное значение для параметра «{m}» и повторите запрос. Для получения списка всех допустимых параметров данного действия обратитесь к описанию инструмента «{}».", ctx.tool),
            None,
        ))
    }

    /// A parameter has an unacceptable value.
    #[must_use]
    #[allow(dead_code)]
    pub fn invalid_value(ctx: ErrorContext, param_name: &str, reason: impl Into<String>) -> Self {
        let r = reason.into();
        Self::InvalidParameter(format_error(
            &ctx, "Некорректное значение параметра",
            &format!("Значение параметра «{param_name}» недопустимо."),
            Some(&format!("{r}")), None,
            &format!("Укажите корректное значение для параметра «{param_name}» и повторите запрос."),
            None,
        ))
    }

    // ── PermissionDenied ────────────────────────────────────────────────

    /// Access denied or admin rights required.
    #[must_use]
    pub fn permission_denied(ctx: ErrorContext, reason: impl Into<String>) -> Self {
        Self::PermissionDenied(format_error(
            &ctx, "Доступ запрещён",
            &format!("Система отклонила операцию «{}».", ctx.action),
            Some(&reason.into()), None,
            &format!(
                "Если Вы уверены в необходимости данной операции:\n\
                1. Передайте параметр \"force\": true в запросе.\n\
                2. Убедитесь, что среда разработки запущена от имени Администратора.\n\
                3. Проверьте, что целевой объект не защищён на уровне ядра (системные процессы, службы PPL).\n\
                4. Проверьте, что целевой объект не используется другим процессом."
            ),
            Some(&format!("{{\"action\":\"{}\",\"params\":{{\"force\":true}}}}", ctx.action)),
        ))
    }

    // ── NotFound ────────────────────────────────────────────────────────

    /// The requested resource was not found.
    #[must_use]
    pub fn not_found(ctx: ErrorContext, what: impl Into<String>, where_to_look: Option<&str>) -> Self {
        let w = what.into();
        let look_hint = where_to_look.map_or(String::new(), |l| format!(" Для получения списка доступных объектов используйте {l}."));
        Self::NotFound(format_error(
            &ctx, "Объект не найден",
            &format!("Не удалось обнаружить {w}."),
            None, None,
            &format!(
                "Проверьте корректность пути, имени или идентификатора.{look_hint}\n\
                Если объект был удалён или перемещён, укажите новое расположение."
            ),
            None,
        ))
    }

    // ── Win32Error ──────────────────────────────────────────────────────

    /// A Win32 API call failed.
    pub fn win32(ctx: ErrorContext, operation: impl Into<String>, err: impl std::fmt::Display) -> Self {
        let op = operation.into();
        let raw = err.to_string();
        let code = extract_win32_code(&raw).unwrap_or(0);
        let explanation = if code != 0 { humanize_win32(code) } else { raw.clone() };
        Self::Win32Error(format_error(
            &ctx, "Системная ошибка",
            &format!("Операция «{op}» завершилась с системной ошибкой."),
            Some(&format!("{raw}")),
            Some(&explanation),
            "Если ошибка повторяется:\n\
             1. Проверьте корректность переданных параметров.\n\
             2. Убедитесь, что среда запущена с необходимыми правами.\n\
             3. Обратитесь к документации или отправьте отчёт.",
            None,
        ))
    }

    // ── FeatureDisabled ─────────────────────────────────────────────────

    /// A feature gate is disabled.
    #[must_use]
    pub fn feature_disabled(ctx: ErrorContext, gate_name: impl Into<String>) -> Self {
        let g = gate_name.into();
        Self::FeatureDisabled(format_error(
            &ctx, "Функция отключена",
            &format!("Операция «{}» требует компонент «{g}», который отключён в конфигурации сервера.", ctx.action),
            None, None,
            &format!(
                "Чтобы включить данную возможность:\n\
                1. Откройте файл .env в корневой директории сервера.\n\
                2. Установите значение: {g}=1\n\
                3. Перезапустите MCP-сервер.\n\
                Внимание: включение этого компонента расширяет возможности сервера и требует осознанного решения администратора."
            ),
            Some(&format!("# В файле .env:\n{g}=1")),
        ))
    }

    // ── Io ──────────────────────────────────────────────────────────────

    /// Create an I/O error.
    #[must_use]
    pub fn io_error(ctx: ErrorContext, operation: impl Into<String>, err: std::io::Error) -> Self {
        let op = operation.into();
        Self::Io(format_error(
            &ctx, "Ошибка ввода/вывода",
            &format!("Операция «{op}» прервана из-за ошибки ввода/вывода."),
            Some(&err.to_string()), None,
            "Проверьте:\n\
             1. Достаточно ли свободного места на диске.\n\
             2. Не заблокирован ли файл другим процессом.\n\
             3. Имеются ли права на чтение/запись по указанному пути.",
            None,
        ))
    }

    // ── Serde ───────────────────────────────────────────────────────────

    /// Create a JSON serialisation error.
    #[must_use]
    #[allow(dead_code)]
    pub fn serde_error(msg: impl Into<String>) -> Self {
        Self::Serde(format!(
            "Ошибка обработки данных: {}\n\
             Проверьте формат передаваемых параметров.",
            msg.into()
        ))
    }

    // ── WMI ─────────────────────────────────────────────────────────────

    /// Create a WMI error.
    #[must_use]
    #[allow(dead_code)]
    pub fn wmi_error(msg: impl Into<String>) -> Self {
        Self::WmiError(format!(
            "Ошибка WMI: {}\n\
             Убедитесь, что служба инструментария управления Windows (Winmgmt) запущена.\n\
             Проверьте, что у процесса есть права на чтение WMI.\n\
             Допускаются только запросы SELECT.",
            msg.into()
        ))
    }

    // ── Internal ────────────────────────────────────────────────────────

    /// Create an internal server error.
    #[must_use]
    #[allow(dead_code)]
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(format!(
            "Внутренняя ошибка сервера: {}\n\
             Это неожиданная ситуация. Если она повторяется, пожалуйста, отправьте отчёт разработчику.",
            msg.into()
        ))
    }
}

// ── Convenience: old-style constructors (for minimal delta in tool files) ─

impl AetherError {
    /// Quick invalid param (no context). Prefer `invalid_param(ctx, msg)`.
    #[must_use]
    #[allow(dead_code)]
    pub fn quick_invalid(msg: impl Into<String>) -> Self {
        Self::InvalidParameter(format!("Параметр не указан: {}", msg.into()))
    }
}

// ── From impls ──────────────────────────────────────────────────────────

impl From<std::io::Error> for AetherError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(format!("Ошибка ввода/вывода: {e}"))
    }
}

impl From<serde_json::Error> for AetherError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serde(format!("Ошибка обработки данных: {e}"))
    }
}
