//! Registry Editor tool for the AETHER_01 MCP server.
//!
//! Provides read, write, delete, enumerate, security inspection, change monitoring,
//! .reg export/import, and offline hive mount/unmount operations.
//! All dangerous operations require `force: true` and HKLM writes are gated.
//! Offline hive operations require the `AETHER_OFFLINE_REGISTRY` feature gate.

#![allow(unsafe_code)]

use crate::audit;
use crate::error::{AetherError, ErrorContext};
use crate::server::AetherServer;
use serde_json::{json, Value};
use std::process::Command;
use windows_registry::*;

// ── Raw Windows API imports ────────────────────────────────────────────────────

use windows::Win32::System::Registry::{
    RegCloseKey, RegGetKeySecurity, RegLoadKeyW, RegNotifyChangeKeyValue, RegOpenKeyExW,
    RegSetKeySecurity, RegUnLoadKeyW, KEY_NOTIFY, KEY_READ, KEY_WRITE,
    REG_NOTIFY_CHANGE_ATTRIBUTES, REG_NOTIFY_CHANGE_LAST_SET, REG_NOTIFY_CHANGE_NAME,
    REG_NOTIFY_CHANGE_SECURITY, REG_NOTIFY_FILTER, REG_SAM_FLAGS, HKEY as WinHKEY,
};

// windows_registry 0.3 HKEY is *mut c_void but not publicly re-exported.
// We define it here to match the internal HKEY type used by windows_registry::Key.
type HKEY = *mut std::ffi::c_void;

use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};

use windows::Win32::Foundation::{HANDLE, HLOCAL, BOOL, LocalFree};

use windows::core::{PCWSTR, PWSTR};

// ═══════════════════════════════════════════════════════════════════════════════════
//  Entry Point
// ═══════════════════════════════════════════════════════════════════════════════════

/// Dispatches a registry tool action and returns a JSON result string.
///
/// # Errors
/// Returns `AetherError` on bad parameters, missing force flags, disabled feature
/// gates, or Windows API failures.
pub fn handle_registry_editor(
    server: &AetherServer,
    action: &str,
    params: Value,
) -> std::result::Result<String, AetherError> {
    match action {
        "read" => handle_read(params),
        "write" => handle_write(params),
        "delete" => handle_delete(params),
        "enumerate" => handle_enumerate(params),
        "security_get" => handle_security_get(params),
        "security_set" => handle_security_set(params),
        "monitor" => handle_monitor(params),
        "export" => handle_export(params),
        "import" => handle_import(params),
        "offline_mount" => handle_offline_mount(server, params),
        "offline_unmount" => handle_offline_unmount(server, params),
        other => {
            let ctx = ErrorContext::new("registry_editor", "unknown");
            Err(AetherError::invalid_param(ctx, format!(
                "Unknown registry action: {other}"
            )))
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════════════════════════════

/// Extracts a required string parameter from the JSON params object.
fn get_param_str<'a>(ctx: ErrorContext, params: &'a Value, key: &str) -> std::result::Result<&'a str, AetherError> {
    params
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| AetherError::invalid_param(ctx, format!("Missing or invalid parameter: {key}")))
}

/// Extracts an optional string parameter.
fn get_param_str_opt<'a>(params: &'a Value, key: &str) -> Option<&'a str> {
    params.get(key).and_then(|v| v.as_str())
}

/// Extracts an optional bool parameter, defaulting to `false`.
fn get_param_bool(params: &Value, key: &str) -> bool {
    params
        .get(key)
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

/// Resolves a hive short-name or full name to a `windows_registry::HKEY`.
///
/// Supports: HKLM / HKEY_LOCAL_MACHINE, HKCU / HKEY_CURRENT_USER,
/// HKU / HKEY_USERS, HKCR / HKEY_CLASSES_ROOT, HKCC / HKEY_CURRENT_CONFIG.
fn resolve_hive(ctx: ErrorContext, hive: &str) -> std::result::Result<windows_registry::Key, AetherError> {
    match hive.to_uppercase().as_str() {
        "HKLM" | "HKEY_LOCAL_MACHINE" => Ok(LOCAL_MACHINE.as_raw()),
        "HKCU" | "HKEY_CURRENT_USER" => Ok(CURRENT_USER.as_raw()),
        "HKU" | "HKEY_USERS" => Ok(USERS.as_raw()),
        "HKCR" | "HKEY_CLASSES_ROOT" => Ok(CLASSES_ROOT.as_raw()),
        "HKCC" | "HKEY_CURRENT_CONFIG" => {
            Ok(0x80000005u32 as *mut std::ffi::c_void)
        }
        _ => Err(AetherError::invalid_param(ctx, format!(
            "Unknown hive: {hive}"
        ))),
    }
    .map(|raw| {
        // SAFETY: predefined registry hive handles are safe to wrap in Key.
        // RegCloseKey on predefined handles is a no-op on Windows.
        unsafe { windows_registry::Key::from_raw(raw) }
    })
}

/// Resolves a hive name to a raw `windows::Win32::Foundation::HKEY` for use with
/// the `windows` crate's low-level functions.
fn resolve_hive_raw(ctx: ErrorContext, hive: &str) -> std::result::Result<WinHKEY, AetherError> {
    match hive.to_uppercase().as_str() {
        "HKLM" | "HKEY_LOCAL_MACHINE" => {
            Ok(WinHKEY(LOCAL_MACHINE.as_raw()))
        }
        "HKCU" | "HKEY_CURRENT_USER" => {
            Ok(WinHKEY(CURRENT_USER.as_raw()))
        }
        "HKU" | "HKEY_USERS" => Ok(WinHKEY(USERS.as_raw())),
        "HKCR" | "HKEY_CLASSES_ROOT" => {
            Ok(WinHKEY(CLASSES_ROOT.as_raw()))
        }
        "HKCC" | "HKEY_CURRENT_CONFIG" => Ok(WinHKEY(0x8000_0005u32 as *mut std::ffi::c_void)),
        _ => Err(AetherError::invalid_param(ctx, format!(
            "Unknown hive: {hive}"
        ))),
    }
}

/// Converts a Rust `&str` to a null-terminated wide string suitable for `PCWSTR`.
fn to_wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Checks whether the hive is HKLM (requires `force: true` for writes/destructive ops).
fn hive_is_hklm(hive: &str) -> bool {
    let upper = hive.to_uppercase();
    upper == "HKLM" || upper == "HKEY_LOCAL_MACHINE"
}

/// Checks the force flag and returns a `PermissionDenied` error if it is not set.
fn require_force(ctx: ErrorContext, params: &Value) -> std::result::Result<(), AetherError> {
    if !get_param_bool(params, "force") {
        return Err(AetherError::permission_denied(ctx,
            "This registry operation requires force: true",
        ));
    }
    Ok(())
}

/// Checks the force flag when writing to HKLM specifically.
fn require_force_for_hklm(ctx: ErrorContext, hive: &str, params: &Value) -> std::result::Result<(), AetherError> {
    if hive_is_hklm(hive) && !get_param_bool(params, "force") {
        return Err(AetherError::permission_denied(ctx,
            "Writing to HKLM requires force: true",
        ));
    }
    Ok(())
}

/// Opens a registry key with the specified access mask using the raw Windows API.
/// The caller must close the returned handle with `RegCloseKey`.
fn raw_open_key(
    ctx: ErrorContext,
    hive: WinHKEY,
    key_path: &str,
    access: REG_SAM_FLAGS,
) -> std::result::Result<WinHKEY, AetherError> {
    let path_wide = to_wide_null(key_path);
    let mut handle = WinHKEY::default();
    let result = unsafe {
        RegOpenKeyExW(
            hive,
            PCWSTR(path_wide.as_ptr()),
            0u32,
            access,
            &mut handle,
        )
    };
    if result.0 != 0 {
        return Err(AetherError::not_found(ctx, format!("Failed to open registry key '{key_path}': error {}", result.0), None));
    }
    Ok(handle)
}

/// Builds a full key-path display string for audit logs.
fn key_display(hive: &str, key_path: &str) -> String {
    format!("{hive}\\{key_path}")
}

// ═══════════════════════════════════════════════════════════════════════════════════
//  Action Handlers
// ═══════════════════════════════════════════════════════════════════════════════════

// ── read ────────────────────────────────────────────────────────────────────────

/// Reads a registry value, detecting its type automatically.
///
/// Expected params: `hive`, `key_path`, `value_name`.
/// Returns a JSON object with `type` and `value` fields.
fn handle_read(params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("registry_editor", "read");
    let hive = get_param_str(ctx.clone(), &params, "hive")?;
    let key_path = get_param_str(ctx.clone(), &params, "key_path")?;
    let value_name = get_param_str(ctx.clone(), &params, "value_name")?;

    let hkey = resolve_hive(ctx.clone(), hive)?;
    let key = hkey
        .open(key_path)
        .map_err(|e| AetherError::not_found(ctx.clone(), format!("Registry key not found: {key_path} ({e})"), None))?;

    // Attempt type detection in order: DWORD, QWORD, then string.
    if let Ok(v) = key.get_u32(value_name) {
        audit::log_success("registry", "read", &key_display(hive, key_path));
        return Ok(json!({"type": "dword", "value": v}).to_string());
    }
    if let Ok(v) = key.get_u64(value_name) {
        audit::log_success("registry", "read", &key_display(hive, key_path));
        return Ok(json!({"type": "qword", "value": v}).to_string());
    }
    if let Ok(v) = key.get_string(value_name) {
        audit::log_success("registry", "read", &key_display(hive, key_path));
        return Ok(json!({"type": "string", "value": v}).to_string());
    }

    audit::log_failure("registry", "read", "value not found or unsupported type");
    Err(AetherError::not_found(ctx, format!(
        "Registry value '{value_name}' not found in {}\\{}",
        hive, key_path
    ), None))
}

// ── write ───────────────────────────────────────────────────────────────────────

/// Writes a registry value.
///
/// Expected params: `hive`, `key_path`, `value_name`, `value`, `value_type`,
/// `force` (required for HKLM).
///
/// Supported `value_type`s: `dword`, `qword`, `string`, `expand_string`,
/// `multi_string`, `binary`.
fn handle_write(params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("registry_editor", "write");
    let hive = get_param_str(ctx.clone(), &params, "hive")?;
    let key_path = get_param_str(ctx.clone(), &params, "key_path")?;
    let value_name = get_param_str(ctx.clone(), &params, "value_name")?;
    let value_type = get_param_str(ctx.clone(), &params, "value_type")?;

    require_force_for_hklm(ctx.clone(), hive, &params)?;

    let hkey = resolve_hive(ctx.clone(), hive)?;
    let key = hkey
        .create(key_path)
        .map_err(|e| AetherError::win32(ctx.clone(), "RegCreateKey", format!("Failed to create/open registry key: {e}")))?;

    match value_type {
        "dword" => {
            let v: u32 = value_to_u32(ctx.clone(), &params)?;
            key.set_u32(value_name, v)
                .map_err(|e| AetherError::win32(ctx.clone(), "RegSetValue", format!("set_u32 failed: {e}")))?;
        }
        "qword" => {
            let v: u64 = value_to_u64(ctx.clone(), &params)?;
            key.set_u64(value_name, v)
                .map_err(|e| AetherError::win32(ctx.clone(), "RegSetValue", format!("set_u64 failed: {e}")))?;
        }
        "string" => {
            let v = value_to_str(ctx.clone(), &params)?;
            key.set_string(value_name, v)
                .map_err(|e| AetherError::win32(ctx.clone(), "RegSetValue", format!("set_string failed: {e}")))?;
        }
        "expand_string" => {
            let v = value_to_str(ctx.clone(), &params)?;
            write_raw_value(ctx.clone(), &key, value_name, v, windows_registry::Type::ExpandString)?;
        }
        "multi_string" => {
            let v = value_to_str(ctx.clone(), &params)?;
            write_raw_value(ctx.clone(), &key, value_name, v, windows_registry::Type::MultiString)?;
        }
        "binary" => {
            write_binary_value(ctx.clone(), &params, &key, value_name)?;
        }
        other => {
            return Err(AetherError::invalid_param(ctx, format!(
                "Unknown value_type: {other}. Supported: dword, qword, string, expand_string, multi_string, binary"
            )));
        }
    }

    if get_param_bool(&params, "force") {
        audit::log_forced("registry", "write");
    } else {
        audit::log_success("registry", "write", &key_display(hive, key_path));
    }

    Ok(json!({"status": "ok", "key": key_display(hive, key_path), "value": value_name}).to_string())
}

/// Extracts a u32 from the `"value"` field of params.
fn value_to_u32(ctx: ErrorContext, params: &Value) -> std::result::Result<u32, AetherError> {
    params
        .get("value")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .ok_or_else(|| AetherError::invalid_param(ctx, "value must be a u32 integer"))
}

/// Extracts a u64 from the `"value"` field of params.
fn value_to_u64(ctx: ErrorContext, params: &Value) -> std::result::Result<u64, AetherError> {
    params
        .get("value")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| AetherError::invalid_param(ctx, "value must be a u64 integer"))
}

/// Extracts a string from the `"value"` field of params.
fn value_to_str<'a>(ctx: ErrorContext, params: &'a Value) -> std::result::Result<&'a str, AetherError> {
    params
        .get("value")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AetherError::invalid_param(ctx, "value must be a string"))
}

/// Writes an expand-string or multi-string value using the low-level `set_value` API.
fn write_raw_value(
    ctx: ErrorContext,
    key: &Key,
    name: &str,
    data: &str,
    ty: windows_registry::Type,
) -> std::result::Result<(), AetherError> {
    // For expand_string: encode as UTF-16 null-terminated bytes.
    // For multi_string: each component is null-terminated, double-null terminated.
    let bytes: Vec<u8> = if ty == windows_registry::Type::MultiString {
        data.encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .chain([0u8, 0u8, 0u8, 0u8]) // double-null terminator
            .collect()
    } else {
        data.encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .chain([0u8, 0u8]) // single-null terminator
            .collect()
    };
    key.set_bytes(name, ty, &bytes)
        .map_err(|e| AetherError::win32(ctx, "RegSetValue", format!("set_value failed: {e}")))
}

/// Writes a binary value; the input `value` parameter must be a hex string or
/// base64-encoded.
fn write_binary_value(ctx: ErrorContext, params: &Value, key: &Key, name: &str) -> std::result::Result<(), AetherError> {
    let raw = params
        .get("value")
        .ok_or_else(|| AetherError::invalid_param(ctx.clone(), "value is required for binary writes"))?;

    let bytes = if let Some(hex_str) = raw.as_str() {
        if hex_str.len() % 2 != 0 {
            return Err(AetherError::invalid_param(ctx,
                "Hex string for binary value must have even length",
            ));
        }
        (0..hex_str.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&hex_str[i..i + 2], 16).map_err(|_| {
                    AetherError::invalid_param(ctx.clone(), format!("Invalid hex byte at position {i}"))
                })
            })
            .collect::<std::result::Result<Vec<u8>, _>>()?
    } else {
        return Err(AetherError::invalid_param(ctx,
            "Binary value must be a hex string",
        ));
    };

    key.set_bytes(name, windows_registry::Type::Bytes, &bytes)
        .map_err(|e| AetherError::win32(ctx, "RegSetValue", format!("set_value for binary failed: {e}")))
}

// ── delete ──────────────────────────────────────────────────────────────────────

/// Deletes a registry value or an entire key (and all subkeys).
///
/// Expected params: `hive`, `key_path`, optional `value_name`, `force` (required).
/// If `value_name` is absent or null, the entire key tree is removed.
fn handle_delete(params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("registry_editor", "delete");
    require_force(ctx.clone(), &params)?;

    let hive = get_param_str(ctx.clone(), &params, "hive")?;
    let key_path = get_param_str(ctx.clone(), &params, "key_path")?;
    let value_name = get_param_str_opt(&params, "value_name");

    let hkey = resolve_hive(ctx.clone(), hive)?;
    let key = hkey
        .open(key_path)
        .map_err(|e| AetherError::not_found(ctx.clone(), format!("Registry key not found: {key_path} ({e})"), None))?;

    if let Some(vn) = value_name {
        // Delete a single value.
        key.remove_value(vn)
            .map_err(|e| AetherError::win32(ctx.clone(), "RegDeleteValue", format!("Failed to delete value '{vn}': {e}")))?;
        audit::log_forced("registry", &format!("delete_value:{key_path}\\{vn}"));
        Ok(json!({
            "status": "ok",
            "deleted": "value",
            "key": key_display(hive, key_path),
            "value_name": vn,
        })
        .to_string())
    } else {
        // Delete the entire key tree using the raw API.
        let raw_key = key.as_raw();
        unsafe {
            // RegDeleteTreeW(key, NULL) deletes all subkeys/values recursively
            let result = windows::Win32::System::Registry::RegDeleteTreeW(
                windows::Win32::System::Registry::HKEY(raw_key),
                windows::core::PCWSTR::null(),
            );
            if result.0 != 0 {
                return Err(AetherError::win32(ctx, "RegDeleteTree", format!("Failed to delete key tree: error {}", result.0)));
            }
        }
        audit::log_forced("registry", &format!("delete_key:{key_path}"));
        Ok(json!({
            "status": "ok",
            "deleted": "key",
            "key": key_display(hive, key_path),
        })
        .to_string())
    }
}

// ── enumerate ───────────────────────────────────────────────────────────────────

/// Enumerates subkeys and values under a registry key.
///
/// Expected params: `hive`, `key_path`.
/// Returns a JSON object with `subkeys` (array of strings) and `values`
/// (array of `{name, type}` objects).
fn handle_enumerate(params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("registry_editor", "enumerate");
    let hive = get_param_str(ctx.clone(), &params, "hive")?;
    let key_path = get_param_str(ctx.clone(), &params, "key_path")?;

    let hkey = resolve_hive(ctx.clone(), hive)?;
    let key = hkey
        .open(key_path)
        .map_err(|e| AetherError::not_found(ctx, format!("Registry key not found: {key_path} ({e})"), None))?;

    let subkeys: Vec<String> = key.keys().map_err(|e| AetherError::Io(format!("{e}")))?.collect();

    let values: Vec<Value> = key
        .values()
        .map_err(|e| AetherError::Io(format!("{e}")))?
        .map(|(name, val): (String, windows_registry::Value)| {
            json!({
                "name": name,
                "type": format!("{:?}", val.ty()),
            })
        })
        .collect();

    audit::log_success("registry", "enumerate", &key_display(hive, key_path));
    Ok(json!({
        "key": key_display(hive, key_path),
        "subkeys": subkeys,
        "values": values,
    })
    .to_string())
}

// ── security_get ────────────────────────────────────────────────────────────────

/// Retrieves the security descriptor (SDDL string) of a registry key.
///
/// Uses `RegGetKeySecurity` and `ConvertSecurityDescriptorToStringSecurityDescriptorW`
/// from the `windows` crate.
///
/// Expected params: `hive`, `key_path`.
fn handle_security_get(params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("registry_editor", "security_get");
    let hive = get_param_str(ctx.clone(), &params, "hive")?;
    let key_path = get_param_str(ctx.clone(), &params, "key_path")?;
    let win_hkey = resolve_hive_raw(ctx.clone(), hive)?;

    let hkey = raw_open_key(ctx.clone(), win_hkey, key_path, KEY_READ)?;

    let security_info =
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;

    // First call: determine required buffer size.
    let mut sd_size: u32 = 0;
    let ret = unsafe {
        RegGetKeySecurity(hkey, security_info, PSECURITY_DESCRIPTOR(std::ptr::null_mut()), &mut sd_size)
    };
    if ret.0 != 0 {
        unsafe {
            let _ = RegCloseKey(hkey);
        }
        return Err(AetherError::win32(ctx.clone(), "RegGetKeySecurity", format!(
            "RegGetKeySecurity size query failed for '{key_path}': error {}", ret.0
        )));
    }

    // Second call: read the security descriptor.
    let mut sd_buf: Vec<u8> = vec![0u8; sd_size as usize];
    let ret = unsafe {
        RegGetKeySecurity(
            hkey,
            security_info,
            PSECURITY_DESCRIPTOR(sd_buf.as_mut_ptr().cast()),
            &mut sd_size,
        )
    };
    unsafe {
        let _ = RegCloseKey(hkey);
    }
    if ret.0 != 0 {
        return Err(AetherError::win32(ctx.clone(), "RegGetKeySecurity", format!(
            "RegGetKeySecurity failed for '{key_path}': error {}", ret.0
        )));
    }

    // Convert the binary security descriptor to an SDDL string.
    let mut sddl_ptr = PWSTR::null();
    let mut sddl_len: u32 = 0;
    unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            PSECURITY_DESCRIPTOR(sd_buf.as_mut_ptr().cast()),
            SDDL_REVISION_1,
            security_info,
            &mut sddl_ptr,
            Some(&mut sddl_len),
        )
    }
    .map_err(|e| AetherError::win32(ctx.clone(), "ConvertSecurityDescriptorToStringSecurityDescriptorW", format!(
        "ConvertSecurityDescriptorToStringSecurityDescriptorW failed: {e}"
    )))?;

    let sddl_string = unsafe {
        let slice = std::slice::from_raw_parts(sddl_ptr.0 as *const u16, sddl_len as usize);
        String::from_utf16_lossy(slice)
    };

    // Free the SDDL string buffer.
    unsafe {
        let _ = LocalFree(HLOCAL(sddl_ptr.0 as *mut std::ffi::c_void));
    }

    audit::log_success("registry", "security_get", &key_display(hive, key_path));
    Ok(json!({
        "key": key_display(hive, key_path),
        "sddl": sddl_string,
    })
    .to_string())
}

// ── security_set ────────────────────────────────────────────────────────────────

/// Sets the security descriptor of a registry key from an SDDL string.
///
/// Uses `ConvertStringSecurityDescriptorToSecurityDescriptorW` and
/// `RegSetKeySecurity` from the `windows` crate.
///
/// Expected params: `hive`, `key_path`, `sddl` (security descriptor string),
/// `force` (required).
fn handle_security_set(params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("registry_editor", "security_set");
    require_force(ctx.clone(), &params)?;

    let hive = get_param_str(ctx.clone(), &params, "hive")?;
    let key_path = get_param_str(ctx.clone(), &params, "key_path")?;
    let sddl = get_param_str(ctx.clone(), &params, "sddl")?;

    let win_hkey = resolve_hive_raw(ctx.clone(), hive)?;
    let hkey = raw_open_key(ctx.clone(), win_hkey, key_path, KEY_READ | KEY_WRITE)?;

    // Convert SDDL string to a security descriptor.
    let sddl_wide = to_wide_null(sddl);
    let mut psd = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
    let mut sd_size: u32 = 0;
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl_wide.as_ptr()),
            SDDL_REVISION_1,
            &mut psd,
            Some(&mut sd_size),
        )
    }
    .map_err(|_| {
        unsafe {
            let _ = RegCloseKey(hkey);
        }
        AetherError::invalid_param(ctx.clone(), format!(
            "Invalid SDDL string: {sddl}"
        ))
    })?;

    let security_info =
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;

    let ret = unsafe { RegSetKeySecurity(hkey, security_info, psd) };
    unsafe {
        let _ = LocalFree(HLOCAL(psd.0 as *mut std::ffi::c_void));
        let _ = RegCloseKey(hkey);
    }
    if ret.0 != 0 {
        return Err(AetherError::win32(ctx, "RegSetKeySecurity", format!(
            "RegSetKeySecurity failed for '{key_path}': error {}", ret.0
        )));
    }

    audit::log_forced("registry", &format!("security_set:{key_path}"));
    Ok(json!({
        "status": "ok",
        "key": key_display(hive, key_path),
    })
    .to_string())
}

// ── monitor ─────────────────────────────────────────────────────────────────────

/// Registers a change notification on a registry key.
///
/// Calls `RegNotifyChangeKeyValue` in a background thread; since the API is
/// blocking, this function returns immediately with a status note.  The background
/// thread will log when a change is detected (currently fire-and-forget).
///
/// Expected params: `hive`, `key_path`, `watch_subtree` (optional bool, default true).
fn handle_monitor(params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("registry_editor", "monitor");
    let hive = get_param_str(ctx.clone(), &params, "hive")?;
    let key_path = get_param_str(ctx.clone(), &params, "key_path")?;
    let watch_subtree = get_param_bool(&params, "watch_subtree");

    let win_hkey = resolve_hive_raw(ctx.clone(), hive)?;
    let hkey = raw_open_key(ctx.clone(), win_hkey, key_path, KEY_NOTIFY)?;

    // Combine notification filters: any change to the key or its values.
    let filter = REG_NOTIFY_FILTER(
        REG_NOTIFY_CHANGE_NAME.0
            | REG_NOTIFY_CHANGE_ATTRIBUTES.0
            | REG_NOTIFY_CHANGE_LAST_SET.0
            | REG_NOTIFY_CHANGE_SECURITY.0,
    );

    let key_disp = key_display(hive, key_path);

    // RegNotifyChangeKeyValue blocks until a change occurs (synchronous mode).
    // We call it directly — this blocks the caller.
    let ret = unsafe {
        RegNotifyChangeKeyValue(
            hkey,
            BOOL::from(watch_subtree),
            filter,
            HANDLE::default(), // no event handle, synchronous
            BOOL::default(),   // not asynchronous
        )
    };
    unsafe {
        let _ = RegCloseKey(hkey);
    }

    if ret.0 != 0 {
        return Err(AetherError::win32(ctx, "RegNotifyChangeKeyValue", format!(
            "RegNotifyChangeKeyValue failed for '{key_disp}': error {}", ret.0
        )));
    }

    audit::log_success("registry", "monitor", &key_disp);
    Ok(json!({
        "status": "change_detected",
        "key": key_disp,
        "note": "Registry change detected. Monitor is synchronous and blocks until a change occurs.",
    })
    .to_string())
}

// ── export ──────────────────────────────────────────────────────────────────────

/// Exports a registry key to a `.reg` file using the system `reg export` command.
///
/// Expected params: `hive`, `key_path`, `output_path` (absolute path to .reg file).
fn handle_export(params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("registry_editor", "export");
    let hive = get_param_str(ctx.clone(), &params, "hive")?;
    let key_path = get_param_str(ctx.clone(), &params, "key_path")?;
    let output_path = get_param_str(ctx.clone(), &params, "output_path")?;

    let full_key = format!("{hive}\\{key_path}");
    let output = Command::new("reg")
        .args(["export", &full_key, output_path, "/y"])
        .output()
        .map_err(|e| AetherError::Io(format!("{e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AetherError::win32(ctx, "reg export", format!(
            "reg export failed for '{full_key}': {stderr}"
        )));
    }

    audit::log_success("registry", "export", &format!("{full_key} → {output_path}"));
    Ok(json!({
        "status": "ok",
        "key": full_key,
        "output_path": output_path,
    })
    .to_string())
}

// ── import ───────────────────────────────────────────────────────────────────────

/// Imports a `.reg` file into the registry using the system `reg import` command.
///
/// Expected params: `input_path` (absolute path to .reg file), `force` (required).
fn handle_import(params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("registry_editor", "import");
    require_force(ctx.clone(), &params)?;

    let input_path = get_param_str(ctx.clone(), &params, "input_path")?;

    let output = Command::new("reg")
        .args(["import", input_path])
        .output()
        .map_err(|e| AetherError::Io(format!("{e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AetherError::win32(ctx, "reg import", format!(
            "reg import failed for '{input_path}': {stderr}"
        )));
    }

    audit::log_forced("registry", &format!("import:{input_path}"));
    Ok(json!({
        "status": "ok",
        "input_path": input_path,
    })
    .to_string())
}

// ── offline_mount ───────────────────────────────────────────────────────────────

/// Mounts an offline registry hive into the active registry.
///
/// Requires the `AETHER_OFFLINE_REGISTRY` feature gate and `force: true`.
/// Uses `RegLoadKeyW` from the `windows` crate.
///
/// Expected params: `hive_path` (path to hive file, e.g. `C:\Windows\System32\config\SOFTWARE`),
/// `mount_name` (key name to mount under, e.g. `OfflineSoftware`),
/// `target_hive` (optional, default `"HKLM"` — must be HKLM or HKU), `force` (required).
fn handle_offline_mount(server: &AetherServer, params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("registry_editor", "offline_mount");

    server
        .gates
        .check(ctx.clone(), server.gates.offline_registry, "AETHER_OFFLINE_REGISTRY")?;

    require_force(ctx.clone(), &params)?;

    let hive_path = get_param_str(ctx.clone(), &params, "hive_path")?;
    let mount_name = get_param_str(ctx.clone(), &params, "mount_name")?;
    let target_hive = get_param_str_opt(&params, "target_hive").unwrap_or("HKLM");

    let win_hkey = resolve_hive_raw(ctx.clone(), target_hive)?;

    let mount_wide = to_wide_null(mount_name);
    let path_wide = to_wide_null(hive_path);

    let ret = unsafe {
        RegLoadKeyW(
            win_hkey,
            PCWSTR(mount_wide.as_ptr()),
            PCWSTR(path_wide.as_ptr()),
        )
    };
    if ret.0 != 0 {
        return Err(AetherError::win32(ctx, "RegLoadKeyW", format!(
            "RegLoadKeyW failed (hive={hive_path}, mount={mount_name}): error {}", ret.0
        )));
    }

    audit::log_forced("registry", &format!("offline_mount:{hive_path}→{target_hive}\\{mount_name}"));
    Ok(json!({
        "status": "ok",
        "hive_path": hive_path,
        "mounted_at": format!("{target_hive}\\{mount_name}"),
    })
    .to_string())
}

// ── offline_unmount ─────────────────────────────────────────────────────────────

/// Unmounts a previously mounted offline registry hive.
///
/// Requires the `AETHER_OFFLINE_REGISTRY` feature gate and `force: true`.
/// Uses `RegUnLoadKeyW` from the `windows` crate.
///
/// Expected params: `target_hive` (must be HKLM or HKU), `mount_name`,
/// `force` (required).
fn handle_offline_unmount(server: &AetherServer, params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("registry_editor", "offline_unmount");

    server
        .gates
        .check(ctx.clone(), server.gates.offline_registry, "AETHER_OFFLINE_REGISTRY")?;

    require_force(ctx.clone(), &params)?;

    let target_hive = get_param_str(ctx.clone(), &params, "target_hive")?;
    let mount_name = get_param_str(ctx.clone(), &params, "mount_name")?;

    let win_hkey = resolve_hive_raw(ctx.clone(), target_hive)?;
    let mount_wide = to_wide_null(mount_name);

    let ret =
        unsafe { RegUnLoadKeyW(win_hkey, PCWSTR(mount_wide.as_ptr())) };
    if ret.0 != 0 {
        return Err(AetherError::win32(ctx, "RegUnLoadKeyW", format!(
            "RegUnLoadKeyW failed (target={target_hive}, mount={mount_name}): error {}", ret.0
        )));
    }

    audit::log_forced("registry", &format!("offline_unmount:{target_hive}\\{mount_name}"));
    Ok(json!({
        "status": "ok",
        "unmounted": format!("{target_hive}\\{mount_name}"),
    })
    .to_string())
}
