//! Unified error types for the AETHER_01 MCP server.
//!
//! All errors are user-facing and designed for maximum readability.
//! Win32 error codes are automatically translated to Russian via FormatMessageW.

#![allow(unsafe_code)]

use thiserror::Error;

/// Top-level error type for all AETHER operations.
///
/// Every variant carries a human-readable message in Russian
/// explaining what went wrong and (where possible) what to do.
#[derive(Error, Debug)]
pub enum AetherError {
    /// A required parameter is missing, wrong type, or out of range.
    #[error("{0}")]
    InvalidParameter(String),

    /// The operation needs administrator rights (or was denied by the system).
    #[error("{0}")]
    PermissionDenied(String),

    /// The target (file, key, process, service, etc.) does not exist.
    #[error("{0}")]
    NotFound(String),

    /// A Windows API call failed — the message includes the translated Win32 description.
    #[error("{0}")]
    Win32Error(String),

    /// The operation is gated behind a feature flag in `.env`.
    #[error("{0}")]
    FeatureDisabled(String),

    /// Disk or network I/O error (permissions, locked file, full disk, etc.).
    #[error("Ошибка ввода/вывода: {0}")]
    Io(#[from] std::io::Error),

    /// JSON parsing or serialisation failed (bad data from client).
    #[error("Ошибка обработки данных: {0}")]
    Serde(#[from] serde_json::Error),

    /// WMI query failed or was rejected.
    #[error("{0}")]
    WmiError(String),

    /// Unexpected internal server error.
    #[error("{0}")]
    Internal(String),
}

// ──────────────────────────────────────────────────────────────────────────
// FFI: FormatMessageW — Win32 error code → human-readable Russian text
// ──────────────────────────────────────────────────────────────────────────

#[link(name = "kernel32")]
extern "system" {
    fn FormatMessageW(
        dwflags: u32,
        lpsource: *const std::ffi::c_void,
        dwmessageid: u32,
        dwlanguageid: u32,
        lpbuffer: *mut u16,
        nsize: u32,
        arguments: *const *const i8,
    ) -> u32;
}

const FORMAT_MESSAGE_FROM_SYSTEM: u32 = 0x00001000;
const FORMAT_MESSAGE_IGNORE_INSERTS: u32 = 0x00000200;

/// Convert a Win32 error code to a human-readable message in the system language (Russian on ru-RU).
///
/// Uses `FormatMessageW` with `FORMAT_MESSAGE_FROM_SYSTEM`.
/// Falls back to the raw hex code if the translation API fails.
#[must_use]
pub fn win32_description(code: u32) -> String {
    let mut buf = vec![0u16; 512];
    let flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;

    let len = unsafe {
        FormatMessageW(
            flags,
            std::ptr::null(),
            code,
            0, // LANG_SYSTEM_DEFAULT — picks the OS UI language
            buf.as_mut_ptr(),
            buf.len() as u32,
            std::ptr::null(),
        )
    };

    if len == 0 {
        return format!("Код ошибки: 0x{code:08X} (описание недоступно)");
    }

    // Trim trailing CRLF/whitespace that FormatMessageW appends
    let s = String::from_utf16_lossy(&buf[..len as usize]);
    s.trim().to_string()
}

/// Try to extract a numeric Win32 code from an error representation string
/// (e.g. "0x80070002", "(0x80070005)", "error 5").
/// Returns the code if found, otherwise None.
fn extract_win32_code(raw: &str) -> Option<u32> {
    // Pattern: "(0xNNNNNNNN)" or "0xNNNNNNNN"
    if let Some(pos) = raw.find("0x") {
        let hex_part = &raw[pos..];
        let end = hex_part
            .chars()
            .position(|c| !c.is_ascii_hexdigit() && c != 'x' && c != 'X')
            .unwrap_or(hex_part.len());
        u32::from_str_radix(&hex_part[2..end], 16).ok()
    } else {
        // Try raw number like "error 5"
        raw.chars()
            .filter(|c| c.is_ascii_digit())
            .collect::<String>()
            .parse()
            .ok()
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Constructor helpers — each prefixes the context with a clear label
// ──────────────────────────────────────────────────────────────────────────

impl AetherError {
    /// «Неверный параметр» — параметр отсутствует, пуст или имеет недопустимое значение.
    #[must_use]
    pub fn invalid_param(msg: impl Into<String>) -> Self {
        Self::InvalidParameter(format!(
            "Неверный параметр: {}\n\
             Проверьте имя и тип параметра. Для списка доступных действий используйте описание инструмента.",
            msg.into()
        ))
    }

    /// «Недостаточно прав» — операция требует прав администратора или доступ запрещён.
    #[must_use]
    pub fn permission_denied(msg: impl Into<String>) -> Self {
        let m = msg.into();
        // If it contains a Win32 code, translate it
        let desc = if let Some(code) = extract_win32_code(&m) {
            format!("\nСистема сообщает: {}", win32_description(code))
        } else {
            String::new()
        };
        Self::PermissionDenied(format!(
            "Недостаточно прав: {m}{desc}\n\
             Запустите программу от имени администратора или выдайте нужные разрешения."
        ))
    }

    /// «Не найдено» — файл, ключ реестра, процесс или служба не существует.
    #[must_use]
    pub fn not_found(msg: impl Into<String>) -> Self {
        let m = msg.into();
        let desc = if let Some(code) = extract_win32_code(&m) {
            format!("\nСистема сообщает: {}", win32_description(code))
        } else {
            String::new()
        };
        Self::NotFound(format!(
            "Не найдено: {m}{desc}\n\
             Проверьте правильность пути, имени или идентификатора."
        ))
    }

    /// «Ошибка Windows API» — вызов Win32 не удался. Код ошибки переводится на русский язык.
    pub fn win32(err: impl std::fmt::Display) -> Self {
        let raw = err.to_string();
        if let Some(code) = extract_win32_code(&raw) {
            let sys_msg = win32_description(code);
            Self::Win32Error(format!(
                "{raw}\n\nОбъяснение: {sys_msg}\n\
                 Код ошибки: 0x{code:08X}"
            ))
        } else {
            Self::Win32Error(raw)
        }
    }

    /// «Функция отключена» — операция заблокирована feature gate в `.env`.
    #[must_use]
    pub fn feature_disabled(gate_name: impl Into<String>) -> Self {
        let g = gate_name.into();
        Self::FeatureDisabled(format!(
            "Функция отключена: {g}\n\
             Чтобы включить эту возможность, установите `{g}=1` в файле `.env` и перезапустите сервер."
        ))
    }

    /// WMI-ошибка с пояснением.
    #[must_use]
    pub fn wmi_error(msg: impl Into<String>) -> Self {
        Self::WmiError(format!(
            "Ошибка WMI: {}\n\
             Убедитесь, что служба WMI запущена и у процесса есть права на чтение WMI.",
            msg.into()
        ))
    }

    /// Внутренняя ошибка сервера.
    #[must_use]
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(format!(
            "Внутренняя ошибка: {}\n\
             Это неожиданная ошибка. Если она повторяется, сообщите разработчику.",
            msg.into()
        ))
    }
}
