//! Windows Service Control Manager tool for AETHER_01.
//!
//! Full service lifecycle management: list, start, stop, restart,
//! query configuration, query status, set startup type, and list drivers.
//! All operations are performed via the Win32 SCM API.
//!
//! # Safety
//!
//! This module uses `unsafe` to call raw Win32 SCM APIs. Every handle is
//! closed via `CloseServiceHandle`, and buffer lifetimes are scoped so
//! that Windows never writes through a dangling pointer.

#![allow(unsafe_code)]

use std::thread;
use std::time::{Duration, Instant};

use crate::audit;
use crate::error::{AetherError, ErrorContext};

use serde_json::json;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::System::Services::*;

// ═══════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════

/// Tool name for audit logging.
const TOOL: &str = "service_manager";

/// Polling interval (ms) when waiting for service status transitions.
const POLL_INTERVAL_MS: u64 = 250;

/// Maximum wait time (ms) for a service to reach a desired state.
const MAX_WAIT_MS: u64 = 30_000;

/// Sentinel value passed to `ChangeServiceConfigW` to leave an existing
/// setting unchanged.
const SERVICE_NO_CHANGE: u32 = 0xFFFF_FFFF;

/// Initial buffer size for `EnumServicesStatusExW` (256 KiB).
const ENUM_BUFFER_INITIAL: u32 = 262_144;

/// Maximum number of buffer-growth attempts during enumeration.
const ENUM_MAX_RETRIES: u32 = 4;

// ═══════════════════════════════════════════════════════════════════════════════
// Public entry point
// ═══════════════════════════════════════════════════════════════════════════════

/// Dispatch the given `action` with its JSON `params`.
///
/// # Actions
///
/// | Action          | Required params           | Optional    |
/// |-----------------|---------------------------|-------------|
/// | `list`          | —                         | —           |
/// | `start`         | `service_name`            | `force`     |
/// | `stop`          | `service_name`            | `force`     |
/// | `restart`       | `service_name`            | `force`     |
/// | `query_config`  | `service_name`            | —           |
/// | `query_status`  | `service_name`            | —           |
/// | `set_startup`   | `service_name`, `startup_type` | `force` |
/// | `drivers`       | —                         | `filter`    |
///
/// Returns a JSON string with the result, or an `AetherError`.
pub fn handle_service_manager(
    action: &str,
    params: serde_json::Value,
) -> std::result::Result<String, AetherError> {
    let action_static: &'static str = Box::leak(action.to_string().into_boxed_str());
    let ctx = ErrorContext::new("service_manager", action_static);
    match action {
        "list" => list_services(),
        "start" => {
            let name = required_str(&ctx, &params, "service_name")?;
            let force = optional_bool(&params, "force");
            start_service(&ctx, &name, force)
        }
        "stop" => {
            let name = required_str(&ctx, &params, "service_name")?;
            let force = optional_bool(&params, "force");
            stop_service(&ctx, &name, force)
        }
        "restart" => {
            let name = required_str(&ctx, &params, "service_name")?;
            let force = optional_bool(&params, "force");
            restart_service(&ctx, &name, force)
        }
        "query_config" => {
            let name = required_str(&ctx, &params, "service_name")?;
            query_service_config(&ctx, &name)
        }
        "query_status" => {
            let name = required_str(&ctx, &params, "service_name")?;
            query_service_status(&ctx, &name)
        }
        "set_startup" => {
            let name = required_str(&ctx, &params, "service_name")?;
            let startup = required_str(&ctx, &params, "startup_type")?;
            let force = optional_bool(&params, "force");
            set_startup_type(&ctx, &name, &startup, force)
        }
        "drivers" => {
            let filter = optional_str(&params, "filter");
            list_drivers(&ctx, filter.as_deref())
        }
        _ => Err(AetherError::invalid_param(ctx.clone(), format!(
            "Unknown service action: {action}. Valid: list, start, stop, restart, query_config, query_status, set_startup, drivers"
        ))),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// JSON parameter helpers
// ═══════════════════════════════════════════════════════════════════════════════

fn required_str(ctx: &ErrorContext, params: &serde_json::Value, key: &str) -> std::result::Result<String, AetherError> {
    params
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| AetherError::invalid_param(ctx.clone(), format!("Missing or invalid parameter: '{key}'")))
}

fn optional_str(params: &serde_json::Value, key: &str) -> Option<String> {
    params.get(key).and_then(|v| v.as_str()).map(|s| s.to_string())
}

fn optional_bool(params: &serde_json::Value, key: &str) -> bool {
    params
        .get(key)
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

// ═══════════════════════════════════════════════════════════════════════════════
// String ↔ wide-string conversion
// ═══════════════════════════════════════════════════════════════════════════════

/// Encode a Rust `&str` as a null-terminated UTF-16 vector suitable for
/// constructing a `PCWSTR`.
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Read a null-terminated wide string from a `PWSTR` pointer.
///
/// # Safety
///
/// `p` must point to a valid null-terminated UTF-16 string.
unsafe fn pwstr_to_owned(p: PWSTR) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: `p` is non-null and points to a valid null-terminated string.
    String::from_utf16_lossy(unsafe { p.as_wide() })
        .trim_end_matches('\0')
        .to_string()
}

// ═══════════════════════════════════════════════════════════════════════════════
// Status / type → human-readable string
// ═══════════════════════════════════════════════════════════════════════════════

fn status_to_string(state: SERVICE_STATUS_CURRENT_STATE) -> &'static str {
    match state {
        SERVICE_STOPPED => "stopped",
        SERVICE_START_PENDING => "start_pending",
        SERVICE_STOP_PENDING => "stop_pending",
        SERVICE_RUNNING => "running",
        SERVICE_CONTINUE_PENDING => "continue_pending",
        SERVICE_PAUSE_PENDING => "pause_pending",
        SERVICE_PAUSED => "paused",
        _ => "unknown",
    }
}

fn start_type_to_string(t: SERVICE_START_TYPE) -> &'static str {
    match t {
        SERVICE_BOOT_START => "boot",
        SERVICE_SYSTEM_START => "system",
        SERVICE_AUTO_START => "auto",
        SERVICE_DEMAND_START => "demand",
        SERVICE_DISABLED => "disabled",
        _ => "unknown",
    }
}

fn error_control_to_string(ec: SERVICE_ERROR) -> &'static str {
    match ec {
        SERVICE_ERROR_IGNORE => "ignore",
        SERVICE_ERROR_NORMAL => "normal",
        SERVICE_ERROR_SEVERE => "severe",
        SERVICE_ERROR_CRITICAL => "critical",
        _ => "unknown",
    }
}

fn parse_start_type(ctx: &ErrorContext, raw: &str) -> std::result::Result<SERVICE_START_TYPE, AetherError> {
    match raw {
        "boot" => Ok(SERVICE_BOOT_START),
        "system" => Ok(SERVICE_SYSTEM_START),
        "auto" => Ok(SERVICE_AUTO_START),
        "demand" => Ok(SERVICE_DEMAND_START),
        "disabled" => Ok(SERVICE_DISABLED),
        _ => Err(AetherError::invalid_param(ctx.clone(), format!(
            "Invalid startup_type: '{raw}'. Valid: boot, system, auto, demand, disabled"
        ))),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SCM handle helpers
// ═══════════════════════════════════════════════════════════════════════════════

/// Open the Service Control Manager with the requested access mask.
unsafe fn open_scm(ctx: &ErrorContext, access: u32) -> std::result::Result<SC_HANDLE, AetherError> {
    // SAFETY: null pointers for machine/database → local machine, default db.
    unsafe {
        OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), access)
            .map_err(|e| AetherError::win32(ctx.clone(), "OpenSCManagerW", e))
    }
}

/// Open a specific service by name with the requested access mask.
///
/// The caller must close the returned handle with `CloseServiceHandle`.
unsafe fn open_svc(
    ctx: &ErrorContext,
    scm: SC_HANDLE,
    name: &str,
    access: u32,
) -> std::result::Result<SC_HANDLE, AetherError> {
    let wide = to_wide(name);
    // SAFETY: `wide` is a null-terminated UTF-16 copy of `name`.
    unsafe {
        OpenServiceW(scm, PCWSTR::from_raw(wide.as_ptr()), access).map_err(|_e| {
            let _ = _e;
            AetherError::not_found(ctx.clone(), format!("Service '{name}' not found or access denied"), None)
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// State-polling helper
// ═══════════════════════════════════════════════════════════════════════════════

/// Poll `QueryServiceStatusEx` until the service reaches `desired_state`
/// or `MAX_WAIT_MS` elapses.
///
/// Returns the final `SERVICE_STATUS_PROCESS` on success.
unsafe fn wait_for_state(
    ctx: &ErrorContext,
    svc: SC_HANDLE,
    desired_state: SERVICE_STATUS_CURRENT_STATE,
    name: &str,
) -> std::result::Result<SERVICE_STATUS_PROCESS, AetherError> {
    let deadline = Instant::now() + Duration::from_millis(MAX_WAIT_MS);

    loop {
        let mut status: SERVICE_STATUS_PROCESS = unsafe { std::mem::zeroed() };
        let status_ptr: *mut SERVICE_STATUS_PROCESS = &mut status;
        let mut needed: u32 = 0;

        // SAFETY: `status_ptr` points to a valid, aligned
        // `SERVICE_STATUS_PROCESS` sized buffer on the stack.
        unsafe {
            QueryServiceStatusEx(
                svc,
                SC_STATUS_PROCESS_INFO,
                Some(std::slice::from_raw_parts_mut(
                    status_ptr.cast::<u8>(),
                    std::mem::size_of::<SERVICE_STATUS_PROCESS>(),
                )),
                &mut needed,
            )
        }
        .map_err(|e| AetherError::win32(ctx.clone(), "QueryServiceStatusEx", e))?;

        if status.dwCurrentState == desired_state {
            return Ok(status);
        }

        if Instant::now() >= deadline {
            return Err(AetherError::Internal(format!(
                "Timed out waiting for service '{name}' to reach state {:?} (current: {:?})",
                desired_state.0, status.dwCurrentState.0,
            )));
        }

        thread::sleep(Duration::from_millis(POLL_INTERVAL_MS));
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Action: list
// ═══════════════════════════════════════════════════════════════════════════════

/// Query the startup type for a single service by name.
/// The SCM handle must already be open.
unsafe fn query_startup_type(
    ctx: &ErrorContext,
    scm: SC_HANDLE,
    service_name: &str,
) -> std::result::Result<SERVICE_START_TYPE, AetherError> {
    let svc = unsafe { open_svc(ctx, scm, service_name, SERVICE_QUERY_CONFIG) }?;

    let mut needed: u32 = 0;
    let _ = unsafe { QueryServiceConfigW(svc, None, 0, &mut needed) };

    let mut buffer: Vec<u8> = vec![0u8; needed as usize];
    let config_ptr = buffer.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW;

    let result = unsafe { QueryServiceConfigW(svc, Some(config_ptr), needed, &mut needed) };
    let _ = unsafe { CloseServiceHandle(svc) };

    result.map_err(|e| {
        AetherError::win32(ctx.clone(), "QueryServiceConfigW", e)
    })?;

    // SAFETY: the OS filled `buffer` with a valid `QUERY_SERVICE_CONFIGW`.
    let config = unsafe { &*config_ptr };
    Ok(config.dwStartType)
}

fn list_services() -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("service_manager", "list");
    let scm =
        unsafe { open_scm(&ctx, SC_MANAGER_ENUMERATE_SERVICE) }.map_err(|e| {
            audit::log_failure("service", "list", &e.to_string());
            e
        })?;

    let mut buffer_size: u32 = ENUM_BUFFER_INITIAL;
    let mut attempt: u32 = 0;

    loop {
        let mut buffer: Vec<u8> = vec![0u8; buffer_size as usize];
        let mut needed: u32 = 0;
        let mut returned: u32 = 0;
        let mut resume: u32 = 0;

        // SAFETY: `buffer` is a vec with `buffer_size` bytes.
        let result = unsafe {
            EnumServicesStatusExW(
                scm,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                Some(buffer.as_mut_slice()),
                &mut needed,
                &mut returned,
                Some(&mut resume),
                PCWSTR::null(),
            )
        };

        match result {
            Ok(()) => {
                // SAFETY: buffer was written by the OS and contains `returned`
                // valid `ENUM_SERVICE_STATUS_PROCESSW` structs.
                let services = unsafe {
                    std::slice::from_raw_parts(
                        buffer.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
                        returned as usize,
                    )
                };

                // First pass: extract basic info from enumeration.
                struct Entry {
                    name: String,
                    display: String,
                    status: &'static str,
                    pid: u32,
                }
                let entries: Vec<Entry> = services
                    .iter()
                    .map(|s| {
                        let name = unsafe { pwstr_to_owned(s.lpServiceName) };
                        let display = unsafe { pwstr_to_owned(s.lpDisplayName) };
                        let sp = &s.ServiceStatusProcess;
                        Entry {
                            name,
                            display,
                            status: status_to_string(sp.dwCurrentState),
                            pid: sp.dwProcessId,
                        }
                    })
                    .collect();

                // Second pass: query startup type for each service.
                let items: Vec<serde_json::Value> = entries
                    .iter()
                    .map(|e| {
                        let startup = unsafe { query_startup_type(&ctx, scm, &e.name) }
                            .map(|t| start_type_to_string(t))
                            .unwrap_or("unknown");

                        json!({
                            "service_name": e.name,
                            "display_name": e.display,
                            "status": e.status,
                            "startup_type": startup,
                            "pid": e.pid,
                        })
                    })
                    .collect();

                let _ = unsafe { CloseServiceHandle(scm) };

                audit::log_success("service", "list", &format!("{} services", items.len()));
                return Ok(serde_json::to_string(&items)?);
            }
            Err(_) => {
                if needed > buffer_size && attempt < ENUM_MAX_RETRIES {
                    buffer_size = needed + 4096; // small headroom
                    attempt += 1;
                    continue;
                }
                let _ = unsafe { CloseServiceHandle(scm) };
                let err = AetherError::win32(
                    ctx.clone(),
                    "EnumServicesStatusExW",
                    format!("failed after {attempt} retries"),
                );
                audit::log_failure("service", "list", &err.to_string());
                return Err(err);
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Action: start
// ═══════════════════════════════════════════════════════════════════════════════

fn start_service(ctx: &ErrorContext, name: &str, force: bool) -> std::result::Result<String, AetherError> {
    if !force {
        audit::log_security("service", "start", "force not provided");
        return Err(AetherError::permission_denied(
            ctx.clone(),
            "Starting a service requires force: true",
        ));
    }

    let scm = unsafe { open_scm(ctx, SC_MANAGER_CONNECT) }.map_err(|e| {
        audit::log_failure("service", "start", &e.to_string());
        e
    })?;

    let svc = unsafe { open_svc(ctx, scm, name, SERVICE_START) };
    let _ = unsafe { CloseServiceHandle(scm) };

    let svc = match svc {
        Ok(h) => h,
        Err(e) => {
            audit::log_failure("service", "start", &e.to_string());
            return Err(e);
        }
    };

    // Start the service (no arguments).
    if let Err(e) = unsafe { StartServiceW(svc, None) } {
        let _ = unsafe { CloseServiceHandle(svc) };
        let err = AetherError::win32(ctx.clone(), "StartServiceW", e);
        audit::log_failure("service", "start", &err.to_string());
        return Err(err);
    }

    // Wait for SERVICE_RUNNING.
    let final_status = match unsafe { wait_for_state(ctx, svc, SERVICE_RUNNING, name) } {
        Ok(s) => s,
        Err(e) => {
            let _ = unsafe { CloseServiceHandle(svc) };
            audit::log_failure("service", "start", &e.to_string());
            return Err(e);
        }
    };

    let _ = unsafe { CloseServiceHandle(svc) };

    let result = json!({
        "service_name": name,
        "status": status_to_string(final_status.dwCurrentState),
        "pid": final_status.dwProcessId,
    });

    audit::log_forced("service", "start");
    audit::log_success("service", "start", name);
    Ok(serde_json::to_string(&result)?)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Action: stop
// ═══════════════════════════════════════════════════════════════════════════════

fn stop_service(ctx: &ErrorContext, name: &str, force: bool) -> std::result::Result<String, AetherError> {
    if !force {
        audit::log_security("service", "stop", "force not provided");
        return Err(AetherError::permission_denied(
            ctx.clone(),
            "Stopping a service requires force: true",
        ));
    }

    let scm = unsafe { open_scm(ctx, SC_MANAGER_CONNECT) }.map_err(|e| {
        audit::log_failure("service", "stop", &e.to_string());
        e
    })?;

    let svc = unsafe { open_svc(ctx, scm, name, SERVICE_STOP) };
    let _ = unsafe { CloseServiceHandle(scm) };

    let svc = match svc {
        Ok(h) => h,
        Err(e) => {
            audit::log_failure("service", "stop", &e.to_string());
            return Err(e);
        }
    };

    let mut ss = unsafe { std::mem::zeroed::<SERVICE_STATUS>() };

    // SAFETY: `ss` is a stack-allocated `SERVICE_STATUS`.
    if let Err(e) = unsafe { ControlService(svc, SERVICE_CONTROL_STOP, &mut ss) } {
        let _ = unsafe { CloseServiceHandle(svc) };
        let err = AetherError::win32(ctx.clone(), "ControlService(STOP)", e);
        audit::log_failure("service", "stop", &err.to_string());
        return Err(err);
    }

    // Wait for SERVICE_STOPPED.
    let final_status = match unsafe { wait_for_state(ctx, svc, SERVICE_STOPPED, name) } {
        Ok(s) => s,
        Err(e) => {
            let _ = unsafe { CloseServiceHandle(svc) };
            audit::log_failure("service", "stop", &e.to_string());
            return Err(e);
        }
    };

    let _ = unsafe { CloseServiceHandle(svc) };

    let result = json!({
        "service_name": name,
        "status": status_to_string(final_status.dwCurrentState),
    });

    audit::log_forced("service", "stop");
    audit::log_success("service", "stop", name);
    Ok(serde_json::to_string(&result)?)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Action: restart
// ═══════════════════════════════════════════════════════════════════════════════

fn restart_service(ctx: &ErrorContext, name: &str, force: bool) -> std::result::Result<String, AetherError> {
    if !force {
        audit::log_security("service", "restart", "force not provided");
        return Err(AetherError::permission_denied(
            ctx.clone(),
            "Restarting a service requires force: true",
        ));
    }

    // --- Stop phase ---
    {
        let scm = unsafe { open_scm(ctx, SC_MANAGER_CONNECT) }?;
        let svc = unsafe { open_svc(ctx, scm, name, SERVICE_STOP) };
        let _ = unsafe { CloseServiceHandle(scm) };

        let svc = match svc {
            Ok(h) => h,
            Err(_) => {
                // Service might not exist or already be stopped; we'll
                // try the start phase regardless.
                // Only fail if we cannot open at all.
                return Err(AetherError::not_found(ctx.clone(), format!("Service '{name}' not found"), None));
            }
        };

        let mut ss = unsafe { std::mem::zeroed::<SERVICE_STATUS>() };
        // Best-effort stop: if already stopped, this is a no-op success.
        let _ = unsafe { ControlService(svc, SERVICE_CONTROL_STOP, &mut ss) };

        // Wait for stopped.
        let _ = unsafe { wait_for_state(ctx, svc, SERVICE_STOPPED, name) };
        let _ = unsafe { CloseServiceHandle(svc) };
    } // svc handle closed

    // Brief pause to let the SCM settle.
    thread::sleep(Duration::from_millis(500));

    // --- Start phase ---
    {
        let scm = unsafe { open_scm(ctx, SC_MANAGER_CONNECT) }?;
        let svc = unsafe { open_svc(ctx, scm, name, SERVICE_START) };
        let _ = unsafe { CloseServiceHandle(scm) };

        let svc = svc.map_err(|e| {
            audit::log_failure("service", "restart", &e.to_string());
            e
        })?;

        if let Err(e) = unsafe { StartServiceW(svc, None) } {
            let _ = unsafe { CloseServiceHandle(svc) };
            let err = AetherError::win32(ctx.clone(), "StartServiceW", e);
            audit::log_failure("service", "restart", &err.to_string());
            return Err(err);
        }

        let final_status = unsafe { wait_for_state(ctx, svc, SERVICE_RUNNING, name) }
            .map_err(|e| {
                let _ = unsafe { CloseServiceHandle(svc) };
                audit::log_failure("service", "restart", &e.to_string());
                e
            })?;

        let _ = unsafe { CloseServiceHandle(svc) };

        let result = json!({
            "service_name": name,
            "status": status_to_string(final_status.dwCurrentState),
            "pid": final_status.dwProcessId,
        });

        audit::log_forced("service", "restart");
        audit::log_success("service", "restart", name);
        Ok(serde_json::to_string(&result)?)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Action: query_config
// ═══════════════════════════════════════════════════════════════════════════════

fn query_service_config(ctx: &ErrorContext, name: &str) -> std::result::Result<String, AetherError> {
    let scm = unsafe { open_scm(ctx, SC_MANAGER_CONNECT) }.map_err(|e| {
        audit::log_failure("service", "query_config", &e.to_string());
        e
    })?;

    let svc = unsafe { open_svc(ctx, scm, name, SERVICE_QUERY_CONFIG) };
    let _ = unsafe { CloseServiceHandle(scm) };

    let svc = match svc {
        Ok(h) => h,
        Err(e) => {
            audit::log_failure("service", "query_config", &e.to_string());
            return Err(e);
        }
    };

    // First call to determine buffer size.
    let mut needed: u32 = 0;
    let _ = unsafe { QueryServiceConfigW(svc, None, 0, &mut needed) };

    let mut buffer: Vec<u8> = vec![0u8; needed as usize];

    // SAFETY: `buffer` is `needed` bytes large.
    let config_ptr = buffer.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW;
    unsafe { QueryServiceConfigW(svc, Some(config_ptr), needed, &mut needed) }.map_err(
        |e| {
            let _ = unsafe { CloseServiceHandle(svc) };
            let err = AetherError::win32(ctx.clone(), "QueryServiceConfigW", e);
            audit::log_failure("service", "query_config", &err.to_string());
            err
        },
    )?;

    // SAFETY: the OS filled `buffer` with a valid `QUERY_SERVICE_CONFIGW`.
    let config = unsafe { &*config_ptr };

    let binary_path = unsafe { pwstr_to_owned(config.lpBinaryPathName) };
    let load_order = unsafe { pwstr_to_owned(config.lpLoadOrderGroup) };
    let account = unsafe { pwstr_to_owned(config.lpServiceStartName) };
    let deps = unsafe { pwstr_to_owned(config.lpDependencies) };

    let _ = unsafe { CloseServiceHandle(svc) };

    let result = json!({
        "service_name": name,
        "binary_path": binary_path,
        "start_type": start_type_to_string(config.dwStartType),
        "account": account,
        "error_control": error_control_to_string(config.dwErrorControl),
        "load_order_group": load_order,
        "dependencies": deps,
    });

    audit::log_success("service", "query_config", name);
    Ok(serde_json::to_string(&result)?)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Action: query_status
// ═══════════════════════════════════════════════════════════════════════════════

fn query_service_status(ctx: &ErrorContext, name: &str) -> std::result::Result<String, AetherError> {
    let scm = unsafe { open_scm(ctx, SC_MANAGER_CONNECT) }.map_err(|e| {
        audit::log_failure("service", "query_status", &e.to_string());
        e
    })?;

    let svc = unsafe { open_svc(ctx, scm, name, SERVICE_QUERY_STATUS) };
    let _ = unsafe { CloseServiceHandle(scm) };

    let svc = match svc {
        Ok(h) => h,
        Err(e) => {
            audit::log_failure("service", "query_status", &e.to_string());
            return Err(e);
        }
    };

    let mut status: SERVICE_STATUS_PROCESS = unsafe { std::mem::zeroed() };
    let status_ptr: *mut SERVICE_STATUS_PROCESS = &mut status;
    let mut needed: u32 = 0;

    // SAFETY: `status_ptr` points to a valid stack buffer.
    unsafe {
        QueryServiceStatusEx(
            svc,
            SC_STATUS_PROCESS_INFO,
            Some(std::slice::from_raw_parts_mut(
                status_ptr.cast::<u8>(),
                std::mem::size_of::<SERVICE_STATUS_PROCESS>(),
            )),
            &mut needed,
        )
    }
    .map_err(|e| {
        let _ = unsafe { CloseServiceHandle(svc) };
        let err = AetherError::win32(ctx.clone(), "QueryServiceStatusEx", e);
        audit::log_failure("service", "query_status", &err.to_string());
        err
    })?;

    let _ = unsafe { CloseServiceHandle(svc) };

    let result = json!({
        "service_name": name,
        "state": status_to_string(status.dwCurrentState),
        "controls_accepted": status.dwControlsAccepted,
        "exit_code": status.dwWin32ExitCode,
        "service_specific_exit_code": status.dwServiceSpecificExitCode,
        "check_point": status.dwCheckPoint,
        "wait_hint": status.dwWaitHint,
        "pid": status.dwProcessId,
    });

    audit::log_success("service", "query_status", name);
    Ok(serde_json::to_string(&result)?)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Action: set_startup
// ═══════════════════════════════════════════════════════════════════════════════

fn set_startup_type(ctx: &ErrorContext, name: &str, startup: &str, force: bool) -> std::result::Result<String, AetherError> {
    let new_type = parse_start_type(ctx, startup)?;

    // boot / system require force.
    if matches!(new_type, SERVICE_BOOT_START | SERVICE_SYSTEM_START) && !force {
        audit::log_security("service", "set_startup", "force not provided for boot/system");
        return Err(AetherError::permission_denied(
            ctx.clone(),
            "Setting boot or system startup type requires force: true",
        ));
    }

    let scm = unsafe { open_scm(ctx, SC_MANAGER_CONNECT) }.map_err(|e| {
        audit::log_failure("service", "set_startup", &e.to_string());
        e
    })?;

    let svc = unsafe { open_svc(ctx, scm, name, SERVICE_CHANGE_CONFIG) };
    let _ = unsafe { CloseServiceHandle(scm) };

    let svc = match svc {
        Ok(h) => h,
        Err(e) => {
            audit::log_failure("service", "set_startup", &e.to_string());
            return Err(e);
        }
    };

    // Keep all other config settings at their current values.
    let result = unsafe {
        ChangeServiceConfigW(
            svc,
            ENUM_SERVICE_TYPE(SERVICE_NO_CHANGE),   // dwServiceType
            new_type,                                    // dwStartType
            SERVICE_ERROR(SERVICE_NO_CHANGE),        // dwErrorControl
            PCWSTR::null(),                              // lpBinaryPathName
            PCWSTR::null(),                              // lpLoadOrderGroup
            None,                                        // lpdwTagId
            PCWSTR::null(),                              // lpDependencies
            PCWSTR::null(),                              // lpServiceStartName
            PCWSTR::null(),                              // lpPassword
            PCWSTR::null(),                              // lpDisplayName
        )
    };

    match result {
        Ok(()) => {
            let _ = unsafe { CloseServiceHandle(svc) };
            if force {
                audit::log_forced("service", "set_startup");
            }
            audit::log_success("service", "set_startup", &format!("{name} → {startup}"));

            let out = json!({
                "service_name": name,
                "startup_type": startup,
            });
            Ok(serde_json::to_string(&out)?)
        }
        Err(e) => {
            let _ = unsafe { CloseServiceHandle(svc) };
            let err =
                AetherError::win32(ctx.clone(), "ChangeServiceConfigW", e);
            audit::log_failure("service", "set_startup", &err.to_string());
            Err(err)
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Action: drivers
// ═══════════════════════════════════════════════════════════════════════════════

fn list_drivers(ctx: &ErrorContext, filter: Option<&str>) -> std::result::Result<String, AetherError> {
    let scm =
        unsafe { open_scm(ctx, SC_MANAGER_ENUMERATE_SERVICE) }.map_err(|e| {
            audit::log_failure("service", "drivers", &e.to_string());
            e
        })?;

    let mut buffer_size: u32 = ENUM_BUFFER_INITIAL;
    let mut attempt: u32 = 0;

    loop {
        let mut buffer: Vec<u8> = vec![0u8; buffer_size as usize];
        let mut needed: u32 = 0;
        let mut returned: u32 = 0;
        let mut resume: u32 = 0;

        let result = unsafe {
            EnumServicesStatusExW(
                scm,
                SC_ENUM_PROCESS_INFO,
                ENUM_SERVICE_TYPE(SERVICE_DRIVER.0),   // kernel drivers
                SERVICE_STATE_ALL,
                Some(buffer.as_mut_slice()),
                &mut needed,
                &mut returned,
                Some(&mut resume),
                PCWSTR::null(),
            )
        };

        match result {
            Ok(()) => {
                let services = unsafe {
                    std::slice::from_raw_parts(
                        buffer.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
                        returned as usize,
                    )
                };

                // First pass: extract basic info.
                struct DrvEntry {
                    name: String,
                    display: String,
                    status: &'static str,
                }
                let entries: Vec<DrvEntry> = services
                    .iter()
                    .map(|s| {
                        let name = unsafe { pwstr_to_owned(s.lpServiceName) };
                        let display = unsafe { pwstr_to_owned(s.lpDisplayName) };
                        let sp = &s.ServiceStatusProcess;
                        DrvEntry {
                            name,
                            display,
                            status: status_to_string(sp.dwCurrentState),
                        }
                    })
                    .collect();

                // Second pass: query startup type for each driver.
                let mut items: Vec<serde_json::Value> = entries
                    .iter()
                    .map(|e| {
                        let startup = unsafe { query_startup_type(ctx, scm, &e.name) }
                            .map(|t| start_type_to_string(t))
                            .unwrap_or("unknown");

                        json!({
                            "name": e.name,
                            "display_name": e.display,
                            "status": e.status,
                            "startup_type": startup,
                        })
                    })
                    .collect();

                // Apply optional name filter.
                if let Some(f) = filter {
                    let f_lower = f.to_lowercase();
                    items.retain(|v| {
                        v["name"]
                            .as_str()
                            .map_or(false, |n| n.to_lowercase().contains(&f_lower))
                    });
                }

                let _ = unsafe { CloseServiceHandle(scm) };

                audit::log_success("service", "drivers", &format!("{} drivers", items.len()));
                return Ok(serde_json::to_string(&items)?);
            }
            Err(_) => {
                if needed > buffer_size && attempt < ENUM_MAX_RETRIES {
                    buffer_size = needed + 4096;
                    attempt += 1;
                    continue;
                }
                let _ = unsafe { CloseServiceHandle(scm) };
                let err = AetherError::win32(
                    ctx.clone(),
                    "EnumServicesStatusExW",
                    format!("(drivers) failed after {attempt} retries"),
                );
                audit::log_failure("service", "drivers", &err.to_string());
                return Err(err);
            }
        }
    }
}
