//! User management tool for AETHER_01 MCP server.
//!
//! Provides 23 actions covering local user/group management, sessions,
//! privileges, certificates, credentials, token manipulation, and LSA secrets.
//!
//! Required additional Cargo.toml windows features:
//!   "Win32_NetworkManagement_NetManagement"
//!   "Win32_System_RemoteDesktop"

#![allow(unsafe_code)]

use crate::audit;
use crate::command::{ParamType, SafeCommand};
use crate::error::{AetherError, ErrorContext};
use crate::server::AetherServer;

use serde_json::{json, Value};
use std::ffi::c_void;
use std::mem;

use windows::core::{HSTRING, PCWSTR, PWSTR};
use windows::Win32::Foundation::*;
use windows::Win32::NetworkManagement::NetManagement::*;
use windows::Win32::Security::*;
use windows::Win32::Security::Authorization::*;
use windows::Win32::Security::Credentials::*;
use windows::Win32::Security::Cryptography::*;
use windows::Win32::System::RemoteDesktop::*;
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcessToken,
};

// ──────────────────────────────────────────────────────────────────────────
// FFI: LSA and security functions (advapi32.dll) — not available in windows 0.58
// ──────────────────────────────────────────────────────────────────────────

#[link(name = "advapi32")]
extern "system" {
    fn LsaOpenPolicy(
        SystemName: *const UNICODE_STRING,
        ObjectAttributes: *const LSA_OBJECT_ATTRIBUTES,
        DesiredAccess: u32,
        PolicyHandle: *mut isize,
    ) -> NTSTATUS;

    fn LsaClose(ObjectHandle: isize) -> NTSTATUS;

    fn LsaEnumerateLogonSessions(
        LogonSessionCount: *mut u32,
        LogonSessionList: *mut *mut LUID,
    ) -> NTSTATUS;

    fn LsaGetLogonSessionData(
        LogonId: *const LUID,
        ppLogonSessionData: *mut *mut SECURITY_LOGON_SESSION_DATA,
    ) -> NTSTATUS;

    fn LsaEnumerateAccountsWithUserRight(
        PolicyHandle: isize,
        UserRight: *const UNICODE_STRING,
        EnumerationBuffer: *mut *mut c_void,
        CountReturned: *mut u32,
    ) -> NTSTATUS;

    fn LsaRetrievePrivateData(
        PolicyHandle: isize,
        KeyName: *const UNICODE_STRING,
        PrivateData: *mut *mut UNICODE_STRING,
    ) -> NTSTATUS;

    fn LsaFreeReturnBuffer(Buffer: *mut c_void) -> NTSTATUS;

    fn GetUserNameW(
        lpBuffer: *mut u16,
        pcbBuffer: *mut u32,
    ) -> i32;
}

// ──────────────────────────────────────────────────────────────────────────
// Constants
// ──────────────────────────────────────────────────────────────────────────

const UF_ACCOUNTDISABLE: u32 = 0x0002;
const UF_LOCKOUT: u32 = 0x0010;
const UF_PASSWD_CANT_CHANGE: u32 = 0x0040;
const UF_PASSWORD_EXPIRED: u32 = 0x800000;

const FILTER_NORMAL_ACCOUNT: u32 = 0x0002;

const POLICY_VIEW_LOCAL_INFORMATION: u32 = 0x00000001;

const _CERT_SYSTEM_STORE_CURRENT_USER: u32 = 0x00010000;

// ──────────────────────────────────────────────────────────────────────────
// LSA types (manual definition for LsaOpenPolicy compatibility)
// ──────────────────────────────────────────────────────────────────────────

#[repr(C)]
#[allow(non_camel_case_types, non_snake_case)]
struct LSA_OBJECT_ATTRIBUTES {
    Length: u32,
    RootDirectory: HANDLE,
    ObjectName: *mut UNICODE_STRING,
    Attributes: u32,
    SecurityDescriptor: *mut c_void,
    SecurityQualityOfService: *mut c_void,
}

impl Default for LSA_OBJECT_ATTRIBUTES {
    fn default() -> Self {
        Self {
            Length: mem::size_of::<Self>() as u32,
            RootDirectory: HANDLE::default(),
            ObjectName: std::ptr::null_mut(),
            Attributes: 0,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        }
    }
}

#[repr(C)]
#[allow(non_camel_case_types, non_snake_case)]
struct SECURITY_LOGON_SESSION_DATA {
    Size: u32,
    LoginID: LUID,
    UserName: UNICODE_STRING,
    LogonDomain: UNICODE_STRING,
    AuthenticationPackage: UNICODE_STRING,
    LogonType: u32,
    Session: u32,
    Sid: PSID,
    LogonTime: i64,
    LogonServer: UNICODE_STRING,
    DnsDomainName: UNICODE_STRING,
    Upn: UNICODE_STRING,
}

// ──────────────────────────────────────────────────────────────────────────
// Helper functions
// ──────────────────────────────────────────────────────────────────────────

/// Convert a PCWSTR (wide string pointer) to a Rust String.
unsafe fn pcwstr_to_string(ptr: PCWSTR) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let raw = ptr.as_wide();
    let len = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
    String::from_utf16_lossy(&raw[..len])
}

/// Convert a PWSTR to a Rust String.
unsafe fn pwstr_to_string(ptr: PWSTR) -> String {
    pcwstr_to_string(PCWSTR(ptr.0))
}

/// Convert an UNICODE_STRING to a Rust String.
unsafe fn lsa_unicode_to_string(s: UNICODE_STRING) -> String {
    if s.Length == 0 || s.Buffer.is_null() {
        return String::new();
    }
    let len = (s.Length / 2) as usize;
    let raw = std::slice::from_raw_parts(s.Buffer.0 as *const u16, len);
    String::from_utf16_lossy(raw)
}

/// Create a null-terminated wide string Vec<u16> from &str.
fn to_wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Convert a FILETIME to Unix seconds (None if zero).
fn filetime_to_seconds(ft: FILETIME) -> Option<i64> {
    let ticks = ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64);
    if ticks == 0 {
        return None;
    }
    let unix = (ticks / 10_000_000).saturating_sub(11_644_473_600);
    Some(unix as i64)
}

/// Parse the `force` flag from JSON params.
fn require_force(ctx: ErrorContext, params: &Value) -> std::result::Result<(), AetherError> {
    let force = params.get("force").and_then(|v| v.as_bool()).unwrap_or(false);
    if !force {
        return Err(AetherError::invalid_param(
            ctx,
            "This operation requires `force: true` to confirm the destructive action.",
        ));
    }
    Ok(())
}

/// Check a feature gate.
fn check_gate(ctx: ErrorContext, enabled: bool, gate_name: &str) -> std::result::Result<(), AetherError> {
    if !enabled {
        return Err(AetherError::feature_disabled(
            ctx,
            gate_name,
        ));
    }
    Ok(())
}

/// Run a command and capture stdout with timeout and validation.
fn run_command(program: &str, args: &[&str]) -> std::result::Result<String, AetherError> {
    let mut cmd = SafeCommand::new(program, "user_management", "run_command")
        .timeout(30);
    for arg in args {
        cmd = cmd.arg(*arg, ParamType::SafeString)?;
    }
    cmd.output()
}

/// Parse a JSON string param, or default.
fn str_param(params: &Value, key: &str) -> String {
    params
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

// ──────────────────────────────────────────────────────────────────────────
// Main dispatch
// ──────────────────────────────────────────────────────────────────────────

/// Dispatch `user_management` actions.
///
/// # Errors
///
/// Returns `AetherError` on any failure (invalid params, Win32 error,
/// feature disabled, etc.).
pub fn handle_user_management(
    server: &AetherServer,
    action: &str,
    params: Value,
) -> std::result::Result<String, AetherError> {
    let result = match action {
        "users" => list_users(server),
        "groups" => list_groups(server),
        "create_user" => create_user(server, &params),
        "delete_user" => delete_user(server, &params),
        "create_group" => create_group(server, &params),
        "delete_group" => delete_group(server, &params),
        "group_membership" => group_membership(server, &params),
        "sessions" => list_sessions(server),
        "current_user" => current_user_info(server),
        "privileges" => list_privileges(server),
        "password_policies" => password_policies(server),
        "account_lockout" => account_lockout(server),
        "logon_rights" => logon_rights(server),
        "cert_store_list" => cert_store_list(server, &params),
        "cert_info" => cert_info(server, &params),
        "cert_export" => cert_export(server, &params),
        "cert_import" => cert_import(server, &params),
        "cert_delete" => cert_delete(server, &params),
        "cred_list" => cred_list(server),
        "cred_read" => cred_read(server, &params),
        "token_privileges" => token_privileges(server, &params),
        "token_impersonate" => token_impersonate(server, &params),
        "lsa_secrets_list" => lsa_secrets_list(server),
        "lsa_secret_read" => lsa_secret_read(server, &params),
        _ => Err(AetherError::invalid_param(ErrorContext::new("user_management", "unknown"), format!(
            "Unknown user action: {action}"
        ))),
    };

    match &result {
        Ok(_) => audit::log_success("user_management", action, ""),
        Err(e) => audit::log_failure("user_management", action, &e.to_string()),
    }

    result
}

// ══════════════════════════════════════════════════════════════════════════
// 1. users — list local users
// ══════════════════════════════════════════════════════════════════════════

fn list_users(_server: &AetherServer) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("user_management", "users");
    unsafe {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let mut entries_read: u32 = 0;
        let mut total_entries: u32 = 0;

        let status = NetUserEnum(
            PCWSTR::null(),
            2, // USER_INFO_2
            NET_USER_ENUM_FILTER_FLAGS(FILTER_NORMAL_ACCOUNT),
            &mut buf,
            u32::MAX,
            &mut entries_read,
            &mut total_entries,
            None,
        );

        if status != 0 && status != ERROR_MORE_DATA.0 as u32 {
            NetApiBufferFree(Some(buf as *const c_void));
            return Err(AetherError::win32(ctx.clone(), "NetUserEnum", format!("error {status}")));
        }

        if entries_read == 0 {
            NetApiBufferFree(Some(buf as *const c_void));
            return Ok(serde_json::to_string_pretty(&json!([]))?);
        }

        let users =
            std::slice::from_raw_parts(buf as *const USER_INFO_2, entries_read as usize);
        let mut result_list: Vec<Value> = Vec::new();

        for u in users {
            let flags_raw: u32 = u.usri2_flags.0;

            result_list.push(json!({
                "username": pcwstr_to_string(PCWSTR(u.usri2_name.0)),
                "full_name": pcwstr_to_string(PCWSTR(u.usri2_full_name.0)),
                "comment": pcwstr_to_string(PCWSTR(u.usri2_comment.0)),
                "flags": {
                    "disabled": (flags_raw & UF_ACCOUNTDISABLE) != 0,
                    "locked": (flags_raw & UF_LOCKOUT) != 0,
                    "password_expired": (flags_raw & UF_PASSWORD_EXPIRED) != 0,
                    "password_cant_change": (flags_raw & UF_PASSWD_CANT_CHANGE) != 0,
                    "raw": flags_raw
                },
                "last_logon": u.usri2_last_logon,
                "last_logoff": u.usri2_last_logoff,
                "password_age_seconds": u.usri2_password_age,
                "priv_level": u.usri2_priv.0,
                "num_logons": u.usri2_num_logons,
                "bad_pw_count": u.usri2_bad_pw_count,
            }));
        }

        NetApiBufferFree(Some(buf as *const c_void));
        Ok(serde_json::to_string_pretty(&json!(result_list))?)
    }
}

// ══════════════════════════════════════════════════════════════════════════
// 2. groups — list local groups with members
// ══════════════════════════════════════════════════════════════════════════

fn list_groups(_server: &AetherServer) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("user_management", "groups");
    unsafe {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let mut entries_read: u32 = 0;
        let mut total_entries: u32 = 0;

        let status = NetLocalGroupEnum(
            PCWSTR::null(),
            1, // LOCALGROUP_INFO_1 (name + comment)
            &mut buf,
            u32::MAX,
            &mut entries_read,
            &mut total_entries,
            None,
        );

        if status != 0 && status != ERROR_MORE_DATA.0 as u32 {
            NetApiBufferFree(Some(buf as *const c_void));
            return Err(AetherError::win32(ctx.clone(), "NetLocalGroupEnum", format!("error {status}")));
        }

        if entries_read == 0 {
            NetApiBufferFree(Some(buf as *const c_void));
            return Ok(serde_json::to_string_pretty(&json!([]))?);
        }

        let groups = std::slice::from_raw_parts(
            buf as *const LOCALGROUP_INFO_1,
            entries_read as usize,
        );
        let mut result_list: Vec<Value> = Vec::new();

        for g in groups {
            let group_name = pcwstr_to_string(PCWSTR(g.lgrpi1_name.0));
            let comment = pcwstr_to_string(PCWSTR(g.lgrpi1_comment.0));

            let members = get_local_group_members(&group_name);

            result_list.push(json!({
                "group_name": group_name,
                "comment": comment,
                "members": members,
            }));
        }

        NetApiBufferFree(Some(buf as *const c_void));
        Ok(serde_json::to_string_pretty(&json!(result_list))?)
    }
}

unsafe fn get_local_group_members(group_name: &str) -> Vec<String> {
    let gn = HSTRING::from(group_name);
    let mut mbuf: *mut u8 = std::ptr::null_mut();
    let mut entries_read: u32 = 0;
    let mut total_entries: u32 = 0;

    // Try LOCALGROUP_MEMBERS_INFO_2 for domain\name
    let status = NetLocalGroupGetMembers(
        PCWSTR::null(),
        &gn,
        2,
        &mut mbuf,
        u32::MAX,
        &mut entries_read,
        &mut total_entries,
        None,
    );

    if status != 0 {
        // Fallback to level 0 (SID only)
        let status0 = NetLocalGroupGetMembers(
            PCWSTR::null(),
            &gn,
            0,
            &mut mbuf,
            u32::MAX,
            &mut entries_read,
            &mut total_entries,
            None,
        );
        if status0 != 0 {
            NetApiBufferFree(Some(mbuf as *const c_void));
            return Vec::new();
        }
        let members = std::slice::from_raw_parts(
            mbuf as *const LOCALGROUP_MEMBERS_INFO_0,
            entries_read as usize,
        );
        let result: Vec<String> = members
            .iter()
            .map(|m| sid_to_string_impl(m.lgrmi0_sid))
            .collect();
        NetApiBufferFree(Some(mbuf as *const c_void));
        return result;
    }

    let members = std::slice::from_raw_parts(
        mbuf as *const LOCALGROUP_MEMBERS_INFO_2,
        entries_read as usize,
    );
    let result: Vec<String> = members
        .iter()
        .map(|m| pcwstr_to_string(PCWSTR(m.lgrmi2_domainandname.0)))
        .collect();
    NetApiBufferFree(Some(mbuf as *const c_void));
    result
}

unsafe fn sid_to_string_impl(sid: PSID) -> String {
    let mut str_sid = PWSTR::null();
    if ConvertSidToStringSidW(sid, &mut str_sid).is_ok() {
        let s = pwstr_to_string(str_sid);
        let _ = LocalFree(HLOCAL(str_sid.0 as *mut c_void));
        s
    } else {
        String::from("(unknown)")
    }
}

// ══════════════════════════════════════════════════════════════════════════
// 3. create_user — create a local user account
// ══════════════════════════════════════════════════════════════════════════

fn create_user(_server: &AetherServer, params: &Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("user_management", "create_user");
    require_force(ctx.clone(), params)?;

    let username = str_param(params, "username");
    let password = str_param(params, "password");
    let full_name = str_param(params, "full_name");
    let comment = str_param(params, "comment");

    if username.is_empty() || password.is_empty() {
        return Err(AetherError::invalid_param(ctx.clone(),
                "Both 'username' and 'password' are required.",
            ));
    }

    let w_username = to_wide_null(&username);
    let w_password = to_wide_null(&password);
    let _w_full = to_wide_null(&full_name);
    let w_comment = to_wide_null(&comment);

    let info = USER_INFO_1 {
        usri1_name: PWSTR(w_username.as_ptr() as *mut u16),
        usri1_password: PWSTR(w_password.as_ptr() as *mut u16),
        usri1_password_age: 0,
        usri1_priv: USER_PRIV(1), // USER_PRIV_USER
        usri1_home_dir: PWSTR::null(),
        usri1_comment: PWSTR(w_comment.as_ptr() as *mut u16),
        usri1_flags: USER_ACCOUNT_FLAGS(0), // Enabled by default
        usri1_script_path: PWSTR::null(),
    };

    unsafe {
        let mut parm_err: u32 = 0;
        let status = NetUserAdd(
            PCWSTR::null(),
            1,
            &info as *const USER_INFO_1 as *const u8,
            Some(&mut parm_err),
        );

        if status != 0 {
            return Err(AetherError::win32(ctx.clone(), "NetUserAdd", format!("error {status} (parm_err={parm_err})")));
        }
    }

    audit::log_forced("user_management", "create_user");
    Ok(serde_json::to_string_pretty(&json!({
        "status": "created",
        "username": username,
        "full_name": full_name,
        "comment": comment,
    }))?)
}

// ══════════════════════════════════════════════════════════════════════════
// 4. delete_user — delete a local user account
// ══════════════════════════════════════════════════════════════════════════

fn delete_user(_server: &AetherServer, params: &Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("user_management", "delete_user");
    require_force(ctx.clone(), params)?;

    let username = str_param(params, "username");
    if username.is_empty() {
        return Err(AetherError::invalid_param(ctx.clone(), "'username' is required."));
    }

    let w_username = HSTRING::from(username.as_str());

    unsafe {
        let status = NetUserDel(PCWSTR::null(), &w_username);
        if status != 0 {
            return Err(AetherError::win32(ctx.clone(), "NetUserDel", format!("error {status}")));
        }
    }

    audit::log_forced("user_management", "delete_user");
    Ok(serde_json::to_string_pretty(&json!({
        "status": "deleted",
        "username": username,
    }))?)
}

// ══════════════════════════════════════════════════════════════════════════
// 5. create_group — create a local group
// ══════════════════════════════════════════════════════════════════════════

fn create_group(_server: &AetherServer, params: &Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("user_management", "create_group");
    require_force(ctx.clone(), params)?;

    let group_name = str_param(params, "group_name");
    let comment = str_param(params, "comment");

    if group_name.is_empty() {
        return Err(AetherError::invalid_param(ctx.clone(), "'group_name' is required."));
    }

    let w_name = to_wide_null(&group_name);
    let w_comment = to_wide_null(&comment);

    let info = LOCALGROUP_INFO_1 {
        lgrpi1_name: PWSTR(w_name.as_ptr() as *mut u16),
        lgrpi1_comment: PWSTR(w_comment.as_ptr() as *mut u16),
    };

    unsafe {
        let mut parm_err: u32 = 0;
        let status = NetLocalGroupAdd(
            PCWSTR::null(),
            1,
            &info as *const LOCALGROUP_INFO_1 as *const u8,
            Some(&mut parm_err),
        );

        if status != 0 {
            return Err(AetherError::win32(ctx.clone(), "NetLocalGroupAdd", format!("error {status} (parm_err={parm_err})")));
        }
    }

    audit::log_forced("user_management", "create_group");
    Ok(serde_json::to_string_pretty(&json!({
        "status": "created",
        "group_name": group_name,
        "comment": comment,
    }))?)
}

// ══════════════════════════════════════════════════════════════════════════
// 6. delete_group — delete a local group
// ══════════════════════════════════════════════════════════════════════════

fn delete_group(_server: &AetherServer, params: &Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("user_management", "delete_group");
    require_force(ctx.clone(), params)?;

    let group_name = str_param(params, "group_name");
    if group_name.is_empty() {
        return Err(AetherError::invalid_param(ctx.clone(), "'group_name' is required."));
    }

    let w_name = HSTRING::from(group_name.as_str());

    unsafe {
        let status = NetLocalGroupDel(PCWSTR::null(), &w_name);
        if status != 0 {
            return Err(AetherError::win32(ctx.clone(), "NetLocalGroupDel", format!("error {status}")));
        }
    }

    audit::log_forced("user_management", "delete_group");
    Ok(serde_json::to_string_pretty(&json!({
        "status": "deleted",
        "group_name": group_name,
    }))?)
}

// ══════════════════════════════════════════════════════════════════════════
// 7. group_membership — add or remove user from group
// ══════════════════════════════════════════════════════════════════════════

fn group_membership(_server: &AetherServer, params: &Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("user_management", "group_membership");
    let sub_action = str_param(params, "action");
    let username = str_param(params, "username");
    let group_name = str_param(params, "group_name");

    if username.is_empty() || group_name.is_empty() {
        return Err(AetherError::invalid_param(ctx.clone(),
            "Both 'username' and 'group_name' are required.",
        ));
    }

    let domain_user = if username.contains('\\') {
        username.clone()
    } else {
        format!(".\\{username}")
    };

    let w_domain_user = to_wide_null(&domain_user);
    let w_group = HSTRING::from(group_name.as_str());

    match sub_action.as_str() {
        "add" => {
            let member_info = LOCALGROUP_MEMBERS_INFO_3 {
                lgrmi3_domainandname: PWSTR(w_domain_user.as_ptr() as *mut u16),
            };

            unsafe {
                let status = NetLocalGroupAddMembers(
                    PCWSTR::null(),
                    &w_group,
                    3,
                    &member_info as *const LOCALGROUP_MEMBERS_INFO_3 as *const u8,
                    1,
                );
                if status != 0 {
                    return Err(AetherError::win32(ctx.clone(), "NetLocalGroupAddMembers", format!("error {status}")));
                }
            }
        }
        "remove" => {
            // Use `net localgroup` command as the most reliable cross-platform approach
            SafeCommand::new("net", "user_management", "group_membership_remove")
                .timeout(15)
                .arg_unchecked("localgroup")
                .arg(&group_name, ParamType::Name)?
                .arg(&username, ParamType::Name)?
                .arg_unchecked("/delete")
                .run()
                .map_err(|e| AetherError::Internal(format!(
                    "Failed to remove {username} from {group_name}: {e}"
                )))?;
        }
        _ => {
            return Err(AetherError::invalid_param(ctx.clone(),
                "Action must be 'add' or 'remove'.",
            ));
        }
    }

    Ok(serde_json::to_string_pretty(&json!({
        "status": "ok",
        "action": sub_action,
        "username": username,
        "group_name": group_name,
    }))?)
}

// ══════════════════════════════════════════════════════════════════════════
// 8. sessions — active logon sessions + terminal services sessions
// ══════════════════════════════════════════════════════════════════════════

fn list_sessions(_server: &AetherServer) -> std::result::Result<String, AetherError> {
    let mut result = json!({
        "logon_sessions": [],
        "terminal_sessions": [],
    });

        // ── LSA logon sessions ────────────────────────────────────────────────
    unsafe {
        let mut session_count: u32 = 0;
        let mut session_list: *mut LUID = std::ptr::null_mut();

        if LsaEnumerateLogonSessions(&mut session_count, &mut session_list).0 == 0
            && session_count > 0
        {
            let luids = std::slice::from_raw_parts(session_list, session_count as usize);
            let mut sessions_arr: Vec<Value> = Vec::new();

            for luid in luids {
                let mut session_data: *mut SECURITY_LOGON_SESSION_DATA = std::ptr::null_mut();
                let s = LsaGetLogonSessionData(luid, &mut session_data);

                if RtlNtStatusToDosError(s) == 0 && !session_data.is_null() {
                    let data = &*session_data;

                    sessions_arr.push(json!({
                        "logon_id": {
                            "high_part": luid.HighPart,
                            "low_part": luid.LowPart,
                        },
                        "username": lsa_unicode_to_string(data.UserName),
                        "logon_domain": lsa_unicode_to_string(data.LogonDomain),
                        "auth_package": lsa_unicode_to_string(data.AuthenticationPackage),
                        "logon_type": logon_type_name(data.LogonType),
                        "logon_time": data.LogonTime,
                        "session": data.Session,
                        "sid": sid_to_string_impl(data.Sid),
                    }));

                    let _ = LsaFreeReturnBuffer(session_data as *mut c_void);
                }
            }

            result["logon_sessions"] = json!(sessions_arr);
            let _ = LsaFreeReturnBuffer(session_list as *mut c_void);
        }
    }

    // ── Terminal Services sessions ────────────────────────────────────────
    unsafe {
        let mut p_session_info: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
        let mut count: u32 = 0;

        if WTSEnumerateSessionsW(None, 0, 1, &mut p_session_info, &mut count).is_ok()
            && count > 0
        {
            let sessions =
                std::slice::from_raw_parts(p_session_info, count as usize);
            let mut ts_arr: Vec<Value> = Vec::new();

            for s in sessions {
                let station_name = pcwstr_to_string(PCWSTR(s.pWinStationName.0));
                let connect_state = format!("{:?}", s.State);

                // WTS_INFO_CLASS values: 5=WTSUserName, 7=WTSDomainName
                let user_name = wts_query_string(s.SessionId, WTS_INFO_CLASS(5));
                let domain = wts_query_string(s.SessionId, WTS_INFO_CLASS(7));
                let client_name = wts_query_string(s.SessionId, WTS_INFO_CLASS(10));
                let idle_time = wts_query_u32(s.SessionId, WTS_INFO_CLASS(17));

                ts_arr.push(json!({
                    "session_id": s.SessionId,
                    "state": connect_state,
                    "win_station_name": station_name,
                    "client_name": client_name,
                    "user_name": user_name,
                    "domain": domain,
                    "idle_time_seconds": idle_time,
                }));
            }

            result["terminal_sessions"] = json!(ts_arr);
            let _ = WTSFreeMemory(p_session_info as *mut c_void);
        }
    }

    Ok(serde_json::to_string_pretty(&result)?)
}

unsafe fn wts_query_string(session_id: u32, info_class: WTS_INFO_CLASS) -> String {
    let mut buffer: PWSTR = PWSTR::null();
    let mut bytes_returned: u32 = 0;

    if WTSQuerySessionInformationW(
        None,
        session_id,
        info_class,
        &mut buffer,
        &mut bytes_returned,
    )
    .is_ok()
        && !buffer.is_null()
    {
        let s = pwstr_to_string(buffer);
        let _ = WTSFreeMemory(buffer.0 as *mut c_void);
        s
    } else {
        String::new()
    }
}

unsafe fn wts_query_u32(session_id: u32, info_class: WTS_INFO_CLASS) -> u32 {
    let mut buffer: PWSTR = PWSTR::null();
    let mut bytes_returned: u32 = 0;

    if WTSQuerySessionInformationW(
        None,
        session_id,
        info_class,
        &mut buffer,
        &mut bytes_returned,
    )
    .is_ok()
        && !buffer.is_null()
        && bytes_returned >= 4
    {
        let val = *(buffer.0 as *const u32);
        let _ = WTSFreeMemory(buffer.0 as *mut c_void);
        val
    } else {
        0
    }
}

fn logon_type_name(logon_type: u32) -> &'static str {
    match logon_type {
        2 => "interactive",
        3 => "network",
        4 => "batch",
        5 => "service",
        6 => "proxy",
        7 => "unlock",
        8 => "network_cleartext",
        9 => "new_credentials",
        10 => "remote_interactive",
        11 => "cached_interactive",
        _ => "unknown",
    }
}

// ══════════════════════════════════════════════════════════════════════════
// 9. current_user — current user info (username, SID, elevated, groups)
// ══════════════════════════════════════════════════════════════════════════

fn current_user_info(_server: &AetherServer) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("user_management", "current_user");
    unsafe {
        // ── Username ──────────────────────────────────────────────────────
        let mut name_buf = vec![0u16; 256];
        let mut name_len: u32 = name_buf.len() as u32;
        let result = GetUserNameW(name_buf.as_mut_ptr(), &mut name_len);
        if result == 0 {
            return Err(AetherError::win32(ctx.clone(), "GetUserNameW", "GetUserNameW failed"));
        }
        let username =
            String::from_utf16_lossy(&name_buf[..name_len as usize - 1]);

        // ── SID ───────────────────────────────────────────────────────────
        let w_user = to_wide_null(&username);
        let mut sid_buf = vec![0u8; 256];
        let mut sid_size: u32 = sid_buf.len() as u32;
        let mut domain_buf = vec![0u16; 256];
        let mut domain_size: u32 = domain_buf.len() as u32;
        let mut sid_type: SID_NAME_USE = SID_NAME_USE(0);

        LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(w_user.as_ptr()),
            PSID(sid_buf.as_mut_ptr() as *mut c_void),
            &mut sid_size,
            PWSTR(domain_buf.as_mut_ptr()),
            &mut domain_size,
            &mut sid_type,
        )
        .map_err(|e| AetherError::win32(ctx.clone(), "LookupAccountNameW", format!("{e}")))?;

        let sid_str = sid_to_string_impl(PSID(sid_buf.as_ptr() as *mut c_void));

        // ── Token info (elevation + groups) ───────────────────────────────
        let mut token_handle = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle)
            .map_err(|e| AetherError::win32(ctx.clone(), "OpenProcessToken", format!("{e}")))?;

        // Elevation
        let mut elevated = false;
        let mut elevation = TOKEN_ELEVATION::default();
        let mut return_len: u32 = 0;

        if GetTokenInformation(
            token_handle,
            TokenElevation,
            Some(
                &mut elevation as *mut TOKEN_ELEVATION as *mut c_void,
            ),
            mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_len,
        )
        .is_ok()
        {
            elevated = elevation.TokenIsElevated != 0;
        }

        // Groups
        let mut groups: Vec<Value> = Vec::new();
        let mut required_size: u32 = 0;
        let _ = GetTokenInformation(
            token_handle,
            TokenGroups,
            None,
            0,
            &mut required_size,
        );

        if required_size > 0 {
            let mut group_buf: Vec<u8> = vec![0u8; required_size as usize];
            if GetTokenInformation(
                token_handle,
                TokenGroups,
                Some(group_buf.as_mut_ptr() as *mut c_void),
                required_size,
                &mut return_len,
            )
            .is_ok()
            {
                let token_groups =
                    &*(group_buf.as_ptr() as *const TOKEN_GROUPS);
                let sids = std::slice::from_raw_parts(
                    token_groups.Groups.as_ptr(),
                    token_groups.GroupCount as usize,
                );

                for entry in sids {
                    let group_sid = sid_to_string_impl(entry.Sid);
                    groups.push(json!({
                        "sid": group_sid,
                        "attributes": entry.Attributes,
                    }));
                }
            }
        }

        let _ = CloseHandle(token_handle);

        Ok(serde_json::to_string_pretty(&json!({
            "username": username,
            "sid": sid_str,
            "elevated": elevated,
            "groups": groups,
        }))?)
    }
}

// ══════════════════════════════════════════════════════════════════════════
// 10. privileges — list privileges (well-known + account rights)
// ══════════════════════════════════════════════════════════════════════════

fn list_privileges(_server: &AetherServer) -> std::result::Result<String, AetherError> {
    let well_known: &[(&str, &str)] = &[
        ("SeAssignPrimaryTokenPrivilege", "Replace a process level token"),
        ("SeAuditPrivilege", "Generate security audits"),
        ("SeBackupPrivilege", "Back up files and directories"),
        ("SeChangeNotifyPrivilege", "Bypass traverse checking"),
        ("SeCreateGlobalPrivilege", "Create global objects"),
        ("SeCreatePagefilePrivilege", "Create a pagefile"),
        ("SeCreatePermanentPrivilege", "Create permanent shared objects"),
        ("SeCreateSymbolicLinkPrivilege", "Create symbolic links"),
        ("SeCreateTokenPrivilege", "Create a token object"),
        ("SeDebugPrivilege", "Debug programs"),
        ("SeDelegateSessionUserImpersonatePrivilege", "Obtain an impersonation token for another user in the same session"),
        ("SeEnableDelegationPrivilege", "Enable computer and user accounts to be trusted for delegation"),
        ("SeImpersonatePrivilege", "Impersonate a client after authentication"),
        ("SeIncreaseBasePriorityPrivilege", "Increase scheduling priority"),
        ("SeIncreaseQuotaPrivilege", "Adjust memory quotas for a process"),
        ("SeIncreaseWorkingSetPrivilege", "Increase a process working set"),
        ("SeLoadDriverPrivilege", "Load and unload device drivers"),
        ("SeLockMemoryPrivilege", "Lock pages in memory"),
        ("SeMachineAccountPrivilege", "Add workstations to domain"),
        ("SeManageVolumePrivilege", "Perform volume maintenance tasks"),
        ("SeProfileSingleProcessPrivilege", "Profile single process"),
        ("SeRelabelPrivilege", "Modify an object label"),
        ("SeRemoteShutdownPrivilege", "Force shutdown from a remote system"),
        ("SeRestorePrivilege", "Restore files and directories"),
        ("SeSecurityPrivilege", "Manage auditing and security log"),
        ("SeShutdownPrivilege", "Shut down the system"),
        ("SeSyncAgentPrivilege", "Synchronize directory service data"),
        ("SeSystemEnvironmentPrivilege", "Modify firmware environment values"),
        ("SeSystemProfilePrivilege", "Profile system performance"),
        ("SeSystemtimePrivilege", "Change the system time"),
        ("SeTakeOwnershipPrivilege", "Take ownership of files or other objects"),
        ("SeTcbPrivilege", "Act as part of the operating system"),
        ("SeTimeZonePrivilege", "Change the time zone"),
        ("SeTrustedCredManAccessPrivilege", "Access Credential Manager as a trusted caller"),
        ("SeUndockPrivilege", "Remove computer from docking station"),
        ("SeUnsolicitedInputPrivilege", "Read unsolicited input from a terminal device"),
    ];

    unsafe {
        let mut token_handle = HANDLE::default();
        let open_result =
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle);

        let mut results: Vec<Value> = Vec::new();

        for (name, desc) in well_known {
            let w_name = to_wide_null(name);
            let mut luid = LUID::default();

            let found = LookupPrivilegeValueW(
                PCWSTR::null(),
                PCWSTR(w_name.as_ptr()),
                &mut luid,
            )
            .is_ok();

            let mut assigned = false;
            if found && open_result.is_ok() {
                let mut priv_set = PRIVILEGE_SET {
                    PrivilegeCount: 1,
                    Control: 0,
                    Privilege: [LUID_AND_ATTRIBUTES {
                        Luid: luid,
                        Attributes: TOKEN_PRIVILEGES_ATTRIBUTES(0),
                    }],
                };

                let mut check_result: BOOL = BOOL(0);
                if PrivilegeCheck(token_handle, &mut priv_set, &mut check_result)
                    .is_ok()
                {
                    assigned = check_result.0 != 0;
                }
            }

            results.push(json!({
                "privilege": name,
                "description": desc,
                "exists": found,
                "assigned": assigned,
            }));
        }

        if open_result.is_ok() {
            let _ = CloseHandle(token_handle);
        }

        Ok(serde_json::to_string_pretty(&json!(results))?)
    }
}

// ══════════════════════════════════════════════════════════════════════════
// 11. password_policies — password policies via NetUserModalsGet level 0
// ══════════════════════════════════════════════════════════════════════════

fn password_policies(_server: &AetherServer) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("user_management", "password_policies");
    unsafe {
        let mut buf: *mut u8 = std::ptr::null_mut();

        let status = NetUserModalsGet(PCWSTR::null(), 0, &mut buf);
        if status != 0 {
            NetApiBufferFree(Some(buf as *const c_void));
            return Err(AetherError::win32(ctx.clone(), "NetUserModalsGet", format!("error {status}")));
        }

        let info = &*(buf as *const USER_MODALS_INFO_0);

        let max_passwd_age_secs = info.usrmod0_max_passwd_age;
        let max_passwd_age_days =
            if max_passwd_age_secs == u32::MAX || max_passwd_age_secs == 0 {
                json!("unlimited")
            } else {
                json!(max_passwd_age_secs / 86400)
            };

        let result = json!({
            "min_password_length": info.usrmod0_min_passwd_len,
            "max_password_age_seconds": max_passwd_age_secs,
            "max_password_age_days": max_passwd_age_days,
            "min_password_age_seconds": info.usrmod0_min_passwd_age,
            "password_history_length": info.usrmod0_password_hist_len,
        });

        NetApiBufferFree(Some(buf as *const c_void));
        Ok(serde_json::to_string_pretty(&result)?)
    }
}

// ══════════════════════════════════════════════════════════════════════════
// 12. account_lockout — lockout policies via NetUserModalsGet level 3
// ══════════════════════════════════════════════════════════════════════════

fn account_lockout(_server: &AetherServer) -> std::result::Result<String, AetherError> {
    unsafe {
        let mut buf: *mut u8 = std::ptr::null_mut();

        let status = NetUserModalsGet(PCWSTR::null(), 3, &mut buf);

        let (lockout_threshold, lockout_duration_secs, lockout_reset_secs, from_api);

        if status == 0 && !buf.is_null() {
            let info = &*(buf as *const USER_MODALS_INFO_3);
            lockout_threshold = info.usrmod3_lockout_threshold;
            lockout_duration_secs = info.usrmod3_lockout_duration;
            lockout_reset_secs = info.usrmod3_lockout_observation_window;
            from_api = true;
            NetApiBufferFree(Some(buf as *const c_void));
        } else {
            from_api = false;
            if !buf.is_null() {
                NetApiBufferFree(Some(buf as *const c_void));
            }
            let output = SafeCommand::new("net", "user_management", "account_lockout")
                .timeout(15)
                .arg_unchecked("accounts")
                .output()?;
            lockout_threshold = parse_net_accounts_u32(&output, "Lockout threshold");
            lockout_duration_secs =
                parse_net_accounts_minutes(&output, "Lockout duration") * 60;
            lockout_reset_secs =
                parse_net_accounts_minutes(&output, "Lockout observation window") * 60;
        }

        Ok(serde_json::to_string_pretty(&json!({
            "lockout_threshold": lockout_threshold,
            "lockout_duration_minutes": lockout_duration_secs / 60,
            "lockout_duration_seconds": lockout_duration_secs,
            "lockout_reset_minutes": lockout_reset_secs / 60,
            "lockout_reset_seconds": lockout_reset_secs,
            "source": if from_api { "NetUserModalsGet" } else { "net accounts" }
        }))?)
    }
}

fn parse_net_accounts_u32(output: &str, key: &str) -> u32 {
    for line in output.lines() {
        if line.contains(key) {
            return line
                .split_whitespace()
                .last()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
        }
    }
    0
}

fn parse_net_accounts_minutes(output: &str, key: &str) -> u32 {
    for line in output.lines() {
        if line.contains(key) {
            if let Some(last) = line.split_whitespace().last() {
                return last.parse().unwrap_or(0);
            }
        }
    }
    0
}

// ══════════════════════════════════════════════════════════════════════════
// 13. logon_rights — logon rights via LSA
// ══════════════════════════════════════════════════════════════════════════

fn logon_rights(_server: &AetherServer) -> std::result::Result<String, AetherError> {
    let rights: &[(&str, &str)] = &[
        ("SeInteractiveLogonRight", "Allow log on locally"),
        ("SeNetworkLogonRight", "Access this computer from the network"),
        (
            "SeRemoteInteractiveLogonRight",
            "Allow log on through Remote Desktop Services",
        ),
        ("SeServiceLogonRight", "Log on as a service"),
        ("SeBatchLogonRight", "Log on as a batch job"),
        ("SeDenyInteractiveLogonRight", "Deny log on locally"),
        (
            "SeDenyNetworkLogonRight",
            "Deny access to this computer from the network",
        ),
        (
            "SeDenyRemoteInteractiveLogonRight",
            "Deny log on through Remote Desktop Services",
        ),
        ("SeDenyServiceLogonRight", "Deny log on as a service"),
        ("SeDenyBatchLogonRight", "Deny log on as a batch job"),
    ];

    unsafe {
        let obj_attrs = LSA_OBJECT_ATTRIBUTES::default();
        let mut policy_handle: isize = isize::default();

        let nt_status = LsaOpenPolicy(
            std::ptr::null(),
            &obj_attrs as *const LSA_OBJECT_ATTRIBUTES as *const _,
            POLICY_VIEW_LOCAL_INFORMATION,
            &mut policy_handle,
        );
        let open_ok = RtlNtStatusToDosError(nt_status) == 0;

        let mut results: Vec<Value> = Vec::new();

        for (right, desc) in rights {
            let mut assigned = false;
            let mut accounts: Vec<String> = Vec::new();

            if open_ok {
                let w_right = to_wide_null(right);
                let right_len = (w_right.len() - 1) as u16 * 2;
                let right_lsa = UNICODE_STRING {
                    Length: right_len,
                    MaximumLength: right_len + 2,
                    Buffer: PWSTR(w_right.as_ptr() as *mut u16),
                };

                let mut enum_buf: *mut c_void = std::ptr::null_mut();
                let mut enum_count: u32 = 0;
                let s = LsaEnumerateAccountsWithUserRight(
                    policy_handle,
                    &right_lsa,
                    &mut enum_buf,
                    &mut enum_count,
                );

                if RtlNtStatusToDosError(s) == 0 && enum_count > 0 {
                    assigned = true;
                    let sids =
                        std::slice::from_raw_parts(enum_buf as *const SID, enum_count as usize);
                    for sid_ptr in sids {
                        accounts.push(sid_to_string_impl(PSID(sid_ptr as *const SID as *mut c_void)));
                    }
                    let _ = LsaFreeReturnBuffer(enum_buf);
                }
            }

            results.push(json!({
                "right": right,
                "description": desc,
                "assigned": assigned,
                "accounts": accounts,
            }));
        }

        if open_ok {
            let _ = LsaClose(policy_handle);
        }

        Ok(serde_json::to_string_pretty(&json!(results))?)
    }
}

// ══════════════════════════════════════════════════════════════════════════
// 14. cert_store_list — list certificates in system stores
// ══════════════════════════════════════════════════════════════════════════

fn cert_store_list(_server: &AetherServer, params: &Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("user_management", "cert_store_list");
    let store = str_param(params, "store");
    let stores: Vec<&str> = if store.is_empty() {
        vec!["MY", "CA", "ROOT"]
    } else {
        vec![&store]
    };

    let mut all_results: Vec<Value> = Vec::new();

    for store_name in &stores {
        let w_store = to_wide_null(store_name);

        unsafe {
            let h_store = CertOpenSystemStoreW(None, PCWSTR(w_store.as_ptr()))
                .map_err(|e| {
                    AetherError::win32(ctx.clone(), "CertOpenSystemStoreW", format!("({store_name}) failed: {e}"))
                })?;

            let mut p_prev: *const CERT_CONTEXT = std::ptr::null();
            loop {
                let p_cert = CertEnumCertificatesInStore(h_store, Some(p_prev));
                if p_cert.is_null() {
                    break;
                }
                let cert = &*p_cert;

                // Use CertGetNameStringW for subject and issuer
                let subject = unsafe_cert_get_name(cert, 4); // CERT_NAME_SIMPLE_DISPLAY_TYPE
                let issuer = unsafe_cert_get_name_issuer(cert);

                // Friendly name (prop ID 11 = CERT_FRIENDLY_NAME_PROP_ID)
                let friendly = unsafe_cert_get_property_str(cert, 11);

                // Thumbprint hash (prop ID 3 = CERT_SHA1_HASH_PROP_ID)
                let thumbprint = unsafe_cert_get_hash(cert);

                if !cert.pCertInfo.is_null() {
                    let info = &*cert.pCertInfo;
                    let not_before =
                        filetime_to_seconds(info.NotBefore);
                    let not_after =
                        filetime_to_seconds(info.NotAfter);
                    let serial = blob_to_hex(&info.SerialNumber);

                    all_results.push(json!({
                        "store": store_name,
                        "subject": subject,
                        "issuer": issuer,
                        "serial_number": serial,
                        "thumbprint": thumbprint,
                        "friendly_name": friendly,
                        "not_before": not_before,
                        "not_after": not_after,
                    }));
                }

                p_prev = p_cert;
            }

            let _ = CertCloseStore(h_store, 0);
        }
    }

    Ok(serde_json::to_string_pretty(&json!(all_results))?)
}

unsafe fn unsafe_cert_get_name(p_cert: *const CERT_CONTEXT, display_type: u32) -> String {
    // First call to get required buffer size
    let len = CertGetNameStringW(p_cert, display_type, 0, None, None);
    if len <= 1 {
        return String::new();
    }

    let mut buf: Vec<u16> = vec![0u16; len as usize];
    let actual =
        CertGetNameStringW(p_cert, display_type, 0, None, Some(&mut buf[..]));
    if actual <= 1 {
        String::new()
    } else {
        String::from_utf16_lossy(&buf[..actual as usize - 1])
    }
}

unsafe fn unsafe_cert_get_name_issuer(p_cert: *const CERT_CONTEXT) -> String {
    // Use CERT_NAME_SIMPLE_DISPLAY_TYPE with CERT_NAME_ISSUER_FLAG (0x1)
    let flags = 0x1; // CERT_NAME_ISSUER_FLAG
    let len = CertGetNameStringW(p_cert, 4, flags, None, None);
    if len <= 1 {
        return String::new();
    }
    let mut buf: Vec<u16> = vec![0u16; len as usize];
    let actual = CertGetNameStringW(p_cert, 4, flags, None, Some(&mut buf[..]));
    if actual <= 1 {
        String::new()
    } else {
        String::from_utf16_lossy(&buf[..actual as usize - 1])
    }
}

unsafe fn unsafe_cert_get_property_str(
    p_cert: *const CERT_CONTEXT,
    prop_id: u32,
) -> String {
    let mut data_size: u32 = 0;
    // First call to get size
    if CertGetCertificateContextProperty(p_cert, prop_id, None, &mut data_size).is_err() {
        return String::new();
    }
    if data_size == 0 {
        return String::new();
    }
    let mut buf: Vec<u8> = vec![0u8; data_size as usize];
    if CertGetCertificateContextProperty(p_cert, prop_id, Some(buf.as_mut_ptr() as *mut c_void), &mut data_size).is_err() {
        return String::new();
    }
    // CERT_FRIENDLY_NAME_PROP_ID (11): data is CRYPT_DATA_BLOB (4 byte LE u32 cbData + wide string)
    if data_size > 4 && prop_id == 11 {
        let cb = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if cb > 0 && 4 + cb <= buf.len() {
            let wide: &[u16] = std::slice::from_raw_parts(buf[4..].as_ptr() as *const u16, cb / 2);
            return String::from_utf16_lossy(&wide[..wide.iter().position(|&c| c == 0).unwrap_or(wide.len())]);
        }
    }
    String::from_utf8_lossy(&buf).to_string()
}

unsafe fn unsafe_cert_get_hash(p_cert: *const CERT_CONTEXT) -> String {
    let mut data_size: u32 = 0;
    // 3 = CERT_SHA1_HASH_PROP_ID
    if CertGetCertificateContextProperty(p_cert, 3, None, &mut data_size).is_err() || data_size == 0 {
        return String::new();
    }
    let mut buf: Vec<u8> = vec![0u8; data_size as usize];
    if CertGetCertificateContextProperty(p_cert, 3, Some(buf.as_mut_ptr() as *mut c_void), &mut data_size).is_err() {
        return String::new();
    }
    buf.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join("")
}

unsafe fn blob_to_hex(blob: &CRYPT_INTEGER_BLOB) -> String {
    let data = std::slice::from_raw_parts(blob.pbData, blob.cbData as usize);
    data.iter()
        .rev()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

// ══════════════════════════════════════════════════════════════════════════
// 15. cert_info — certificate details via certutil
// ══════════════════════════════════════════════════════════════════════════

fn cert_info(_server: &AetherServer, params: &Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("user_management", "cert_info");
    let store_name = str_param(params, "store_name");
    let thumbprint = str_param(params, "thumbprint");

    if store_name.is_empty() || thumbprint.is_empty() {
        return Err(AetherError::invalid_param(ctx.clone(),
            "'store_name' and 'thumbprint' are required.",
        ));
    }

    let output = run_command("certutil", &["-store", &store_name, &thumbprint])?;

    Ok(serde_json::to_string_pretty(&json!({
        "store": store_name,
        "thumbprint": thumbprint,
        "details": output,
    }))?)
}

// ══════════════════════════════════════════════════════════════════════════
// 16. cert_export — export certificate via certutil
// ══════════════════════════════════════════════════════════════════════════

fn cert_export(_server: &AetherServer, params: &Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("user_management", "cert_export");
    let store_name = str_param(params, "store_name");
    let thumbprint = str_param(params, "thumbprint");
    let output_path = str_param(params, "output_path");

    if store_name.is_empty() || thumbprint.is_empty() || output_path.is_empty() {
        return Err(AetherError::invalid_param(ctx.clone(),
            "'store_name', 'thumbprint', and 'output_path' are required.",
        ));
    }

    let pfx = params
        .get("pfx")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let cmd = if pfx { "-exportPFX" } else { "-exportCert" };

    let output = run_command(
        "certutil",
        &[cmd, "-p", "", "-f", &store_name, &thumbprint, &output_path],
    )?;

    Ok(serde_json::to_string_pretty(&json!({
        "status": "exported",
        "output_path": output_path,
        "details": output,
    }))?)
}

// ══════════════════════════════════════════════════════════════════════════
// 17. cert_import — import certificate via certutil
// ══════════════════════════════════════════════════════════════════════════

fn cert_import(_server: &AetherServer, params: &Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("user_management", "cert_import");
    let cert_path = str_param(params, "cert_path");
    let store_name = str_param(params, "store_name");

    if cert_path.is_empty() {
        return Err(AetherError::invalid_param(ctx.clone(), "'cert_path' is required."));
    }

    let effective_store = if store_name.is_empty() {
        "MY"
    } else {
        &store_name
    };

    let output = run_command(
        "certutil",
        &["-addstore", "-f", effective_store, &cert_path],
    )?;

    Ok(serde_json::to_string_pretty(&json!({
        "status": "imported",
        "store": effective_store,
        "details": output,
    }))?)
}

// ══════════════════════════════════════════════════════════════════════════
// 18. cert_delete — delete certificate from store
// ══════════════════════════════════════════════════════════════════════════

fn cert_delete(_server: &AetherServer, params: &Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("user_management", "cert_delete");
    require_force(ctx.clone(), params)?;

    let store_name = str_param(params, "store_name");
    let thumbprint = str_param(params, "thumbprint");

    if store_name.is_empty() || thumbprint.is_empty() {
        return Err(AetherError::invalid_param(ctx.clone(),
            "'store_name' and 'thumbprint' are required.",
        ));
    }

    unsafe {
        let w_store = to_wide_null(&store_name);
        let h_store = CertOpenSystemStoreW(None, PCWSTR(w_store.as_ptr()))
            .map_err(|e| AetherError::win32(ctx.clone(), "CertOpenSystemStoreW", format!("{e}")))?;

        // Build SHA1 hash blob from thumbprint hex string
        let hash_bytes = hex_string_to_bytes(&thumbprint);
        let mut hash_data: [u8; 20] = [0; 20];
        let len = hash_bytes.len().min(20);
        hash_data[..len].copy_from_slice(&hash_bytes[..len]);

        let p_found = CertFindCertificateInStore(
            h_store,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_SHA1_HASH,
            Some(hash_data.as_ptr() as *const c_void),
            None,
        );

        if p_found.is_null() {
            let _ = CertCloseStore(h_store, 0);
            return Err(AetherError::not_found(ctx.clone(), format!(
                "Certificate with thumbprint {thumbprint} not found in store {store_name}"
            ), None));
        }

        CertDeleteCertificateFromStore(p_found).map_err(|e| {
            AetherError::win32(ctx.clone(), "CertDeleteCertificateFromStore", format!("{e}"))
        })?;

        let _ = CertCloseStore(h_store, 0);
    }

    audit::log_forced("user_management", "cert_delete");
    Ok(serde_json::to_string_pretty(&json!({
        "status": "deleted",
        "store": store_name,
        "thumbprint": thumbprint,
    }))?)
}

fn hex_string_to_bytes(s: &str) -> Vec<u8> {
    let s = s.replace(' ', "").replace(':', "").replace('-', "");
    (0..s.len())
        .step_by(2)
        .filter_map(|i| {
            if i + 1 < s.len() {
                u8::from_str_radix(&s[i..i + 2], 16).ok()
            } else {
                u8::from_str_radix(&s[i..i + 1], 16).ok()
            }
        })
        .collect()
}

// ══════════════════════════════════════════════════════════════════════════
// 19. cred_list — list credential manager entries
// ══════════════════════════════════════════════════════════════════════════

fn cred_list(_server: &AetherServer) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("user_management", "cred_list");
    unsafe {
        let mut count: u32 = 0;
        let mut creds: *mut *mut CREDENTIALW = std::ptr::null_mut();

        CredEnumerateW(PCWSTR::null(), CRED_ENUMERATE_FLAGS::default(), &mut count, &mut creds)
            .map_err(|e| AetherError::win32(ctx.clone(), "CredEnumerateW", format!("{e}")))?;

        if count == 0 || creds.is_null() {
            return Ok(serde_json::to_string_pretty(&json!([]))?);
        }

        let entries = std::slice::from_raw_parts(creds, count as usize);
        let mut result_list: Vec<Value> = Vec::new();

        for entry_ptr in entries {
            let entry = &**entry_ptr;

            result_list.push(json!({
                "target_name": pwstr_to_string(entry.TargetName),
                "type": credential_type_name(entry.Type),
                "type_raw": entry.Type.0,
                "username": pwstr_to_string(entry.UserName),
                "persist": entry.Persist.0,
                "last_written": filetime_to_seconds(entry.LastWritten),
            }));
        }

        CredFree(creds as *mut c_void);

        Ok(serde_json::to_string_pretty(&json!(result_list))?)
    }
}

fn credential_type_name(ct: CRED_TYPE) -> &'static str {
    match ct.0 {
        1 => "generic",
        2 => "domain_password",
        3 => "domain_certificate",
        4 => "domain_visible_password",
        5 => "generic_certificate",
        6 => "domain_extended",
        _ => "unknown",
    }
}

// ══════════════════════════════════════════════════════════════════════════
// 20. cred_read — read a specific credential (requires force)
// ══════════════════════════════════════════════════════════════════════════

fn cred_read(_server: &AetherServer, params: &Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("user_management", "cred_read");
    require_force(ctx.clone(), params)?;

    let target_name = str_param(params, "target_name");
    if target_name.is_empty() {
        return Err(AetherError::invalid_param(ctx.clone(), "'target_name' is required."));
    }

    let w_target = HSTRING::from(target_name.as_str());

    unsafe {
        let mut p_cred: *mut CREDENTIALW = std::ptr::null_mut();

        CredReadW(&w_target, CRED_TYPE(0), 0, &mut p_cred)
            .map_err(|e| AetherError::win32(ctx.clone(), "CredReadW", format!("{e}")))?;

        if p_cred.is_null() {
            return Err(AetherError::not_found(ctx.clone(), format!(
                "Credential '{target_name}' not found"
            ), None));
        }

        let cred = &*p_cred;
        let password =
            if cred.CredentialBlobSize > 0 && !cred.CredentialBlob.is_null() {
                let blob = std::slice::from_raw_parts(
                    cred.CredentialBlob,
                    cred.CredentialBlobSize as usize,
                );
                String::from_utf8_lossy(blob).to_string()
            } else {
                String::new()
            };

        let result = json!({
            "target_name": pwstr_to_string(cred.TargetName),
            "username": pwstr_to_string(cred.UserName),
            "password": password,
            "type": credential_type_name(cred.Type),
            "type_raw": cred.Type.0,
            "persist": cred.Persist.0,
            "last_written": filetime_to_seconds(cred.LastWritten),
        });

        CredFree(p_cred as *mut c_void);
        Ok(serde_json::to_string_pretty(&result)?)
    }
}

// ══════════════════════════════════════════════════════════════════════════
// 21. token_privileges — enable/disable token privileges
// ══════════════════════════════════════════════════════════════════════════

fn token_privileges(server: &AetherServer, params: &Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("user_management", "token_privileges");
    check_gate(
        ctx.clone(),
        server.gates.token_manipulation,
        "AETHER_TOKEN_MANIPULATION",
    )?;

    let privilege = str_param(params, "privilege");
    let enable = params
        .get("enable")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    if privilege.is_empty() {
        return Err(AetherError::invalid_param(ctx.clone(), "'privilege' is required."));
    }

    let w_priv = to_wide_null(&privilege);
    let mut luid = LUID::default();

    unsafe {
        LookupPrivilegeValueW(PCWSTR::null(), PCWSTR(w_priv.as_ptr()), &mut luid)
            .map_err(|e| AetherError::win32(ctx.clone(), "LookupPrivilegeValueW", format!("{e}")))?;

        let mut token_handle = HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token_handle,
        )
        .map_err(|e| AetherError::win32(ctx.clone(), "OpenProcessToken (adj)", format!("{e}")))?;

        let new_attr = if enable { SE_PRIVILEGE_ENABLED } else { TOKEN_PRIVILEGES_ATTRIBUTES(0) };

        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: new_attr,
            }],
        };

        AdjustTokenPrivileges(
            token_handle,
            false,
            Some(&tp),
            mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            None,
            None,
        )
        .map_err(|e| {
            AetherError::win32(ctx.clone(), "AdjustTokenPrivileges", format!("{e}"))
        })?;

        let _ = CloseHandle(token_handle);
    }

    Ok(serde_json::to_string_pretty(&json!({
        "status": "ok",
        "privilege": privilege,
        "state": if enable { "enabled" } else { "disabled" },
    }))?)
}

// ══════════════════════════════════════════════════════════════════════════
// 22. token_impersonate — impersonate another user
// ══════════════════════════════════════════════════════════════════════════

fn token_impersonate(server: &AetherServer, params: &Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("user_management", "token_impersonate");
    check_gate(
        ctx.clone(),
        server.gates.token_manipulation,
        "AETHER_TOKEN_MANIPULATION",
    )?;
    require_force(ctx.clone(), params)?;

    let username = str_param(params, "username");
    let domain = str_param(params, "domain");
    let password = str_param(params, "password");

    if username.is_empty() || password.is_empty() {
        return Err(AetherError::invalid_param(ctx.clone(),
            "'username' and 'password' are required.",
        ));
    }

    let domain_str = if domain.is_empty() {
        ".".to_string()
    } else {
        domain
    };

    let w_user = HSTRING::from(username.as_str());
    let w_domain = HSTRING::from(domain_str.as_str());
    let w_pass = HSTRING::from(password.as_str());

    unsafe {
        let mut token_handle = HANDLE::default();

        LogonUserW(
            &w_user,
            &w_domain,
            &w_pass,
            LOGON32_LOGON_INTERACTIVE,
            LOGON32_PROVIDER_DEFAULT,
            &mut token_handle,
        )
        .map_err(|e| AetherError::win32(ctx.clone(), "LogonUserW", format!("{e}")))?;

        ImpersonateLoggedOnUser(token_handle)
            .map_err(|e| {
                AetherError::win32(ctx.clone(), "ImpersonateLoggedOnUser", format!("{e}"))
            })?;

        let _ = CloseHandle(token_handle);
    }

    audit::log_forced("user_management", "token_impersonate");
    Ok(serde_json::to_string_pretty(&json!({
        "status": "impersonating",
        "username": username,
        "domain": domain_str,
        "note": "Current thread is now impersonating the user. Call RevertToSelf to stop.",
    }))?)
}

// ══════════════════════════════════════════════════════════════════════════
// 23. lsa_secrets_list — list LSA secret keys
// ══════════════════════════════════════════════════════════════════════════

fn lsa_secrets_list(server: &AetherServer) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("user_management", "lsa_secrets_list");
    check_gate(ctx.clone(), server.gates.lsa_secrets, "AETHER_LSA_SECRETS")?;

    // Primary approach: registry scan via SafeCommand
    let reg_result = SafeCommand::new("reg", "user_management", "lsa_secrets_list")
        .timeout(15)
        .arg_unchecked("query")
        .arg(r"HKLM\SECURITY\Policy\Secrets", ParamType::RegistryPath)
        .and_then(|cmd| cmd.output());

    match reg_result {
        Ok(reg_stdout) => {
            // Registry scan succeeded — parse the output
            let mut secrets: Vec<String> = Vec::new();
            let mut current_key = String::new();

            for line in reg_stdout.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("HKEY_LOCAL_MACHINE\\") {
                    if let Some(pos) = trimmed.rfind('\\') {
                        let name = trimmed[pos + 1..].trim();
                        if !name.is_empty()
                            && !name.contains("\\SECURITY\\Policy\\Secrets")
                            && name != "Secrets"
                        {
                            current_key = name.to_string();
                        }
                    }
                }
                // Check if we see subkeys under a secret
                if !current_key.is_empty()
                    && (trimmed.contains("CurrVal")
                        || trimmed.contains("OldVal")
                        || trimmed.contains("CupdTime")
                        || trimmed.contains("SecDesc"))
                {
                    if !secrets.contains(&current_key) {
                        secrets.push(current_key.clone());
                    }
                }
            }

            let mut result: Vec<Value> = Vec::new();
            for secret in &secrets {
                let detail = SafeCommand::new("reg", "user_management", "lsa_secrets_detail")
                    .timeout(15)
                    .arg_unchecked("query")
                    .arg(&format!(r"HKLM\SECURITY\Policy\Secrets\{secret}"), ParamType::RegistryPath)
                    .and_then(|cmd| cmd.output())
                    .unwrap_or_default();

                result.push(json!({
                    "key": secret,
                    "has_curr_val": detail.contains("CurrVal"),
                    "has_old_val": detail.contains("OldVal"),
                    "has_cupd_time": detail.contains("CupdTime"),
                    "has_sec_desc": detail.contains("SecDesc"),
                }));
            }

            // Also try to get keys directly from the output
            if result.is_empty() {
                for line in reg_stdout.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("HKEY_LOCAL_MACHINE\\")
                        && !trimmed.ends_with("\\SECURITY\\Policy\\Secrets")
                        && !trimmed.ends_with("\\Secrets")
                    {
                        if let Some(pos) = trimmed.rfind('\\') {
                            let name = trimmed[pos + 1..].trim();
                            if !name.is_empty()
                                && !name.contains('\\')
                                && name != "Secrets"
                            {
                                result.push(json!({
                                    "key": name,
                                    "accessible": false,
                                }));
                            }
                        }
                    }
                }
            }

            Ok(serde_json::to_string_pretty(&json!({ "source": "registry", "count": result.len(), "secrets": result }))?)
        }
        Err(_) => {
            // Fallback: try LSA enumerate
            unsafe {
                let obj_attrs = LSA_OBJECT_ATTRIBUTES::default();
                let mut policy_handle: isize = isize::default();

                let nt_status = LsaOpenPolicy(
                    std::ptr::null(),
                    &obj_attrs as *const LSA_OBJECT_ATTRIBUTES as *const _,
                    POLICY_VIEW_LOCAL_INFORMATION,
                    &mut policy_handle,
                );

                if RtlNtStatusToDosError(nt_status) != 0 {
                    return Err(AetherError::permission_denied(ctx.clone(),
                        "Cannot access LSA policy. Run as Administrator.",
                    ));
                }

                let known_keys = [
                    "$MACHINE.ACC",
                    "DefaultPassword",
                    "NL$KM",
                    "L$HYDRAENCKEY",
                    "DPAPI_SYSTEM",
                ];

                let mut found: Vec<Value> = Vec::new();
                for key in &known_keys {
                    let w_key = to_wide_null(key);
                    let key_str = UNICODE_STRING {
                        Length: ((w_key.len() - 1) * 2) as u16,
                        MaximumLength: (w_key.len() * 2) as u16,
                        Buffer: PWSTR(w_key.as_ptr() as *mut u16),
                    };

                    let mut private_data: *mut UNICODE_STRING = std::ptr::null_mut();
                    let s = LsaRetrievePrivateData(
                        policy_handle,
                        &key_str,
                        &mut private_data,
                    );

                    found.push(json!({
                        "key": key,
                        "exists": RtlNtStatusToDosError(s) == 0,
                    }));

                    if !private_data.is_null() {
                        let _ = LsaFreeReturnBuffer(private_data as *mut c_void);
                    }
                }

                let _ = LsaClose(policy_handle);

                Ok(serde_json::to_string_pretty(&json!({
                    "source": "lsa",
                    "count": found.len(),
                    "secrets": found,
                }))?)
            }
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════
// 24. lsa_secret_read — read a specific LSA secret
// ══════════════════════════════════════════════════════════════════════════

fn lsa_secret_read(server: &AetherServer, params: &Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("user_management", "lsa_secret_read");
    check_gate(ctx.clone(), server.gates.lsa_secrets, "AETHER_LSA_SECRETS")?;
    require_force(ctx.clone(), params)?;

    let key_name = str_param(params, "key_name");
    if key_name.is_empty() {
        return Err(AetherError::invalid_param(ctx.clone(), "'key_name' is required."));
    }

    unsafe {
        let obj_attrs = LSA_OBJECT_ATTRIBUTES::default();
        let mut policy_handle: isize = isize::default();

        let nt_status = LsaOpenPolicy(
            std::ptr::null(),
            &obj_attrs as *const LSA_OBJECT_ATTRIBUTES as *const _,
            POLICY_VIEW_LOCAL_INFORMATION,
            &mut policy_handle,
        );

        let win32_err = RtlNtStatusToDosError(nt_status);
        if win32_err != 0 {
            return Err(AetherError::permission_denied(ctx.clone(), format!(
                "Cannot open LSA policy (error {win32_err}). Run as Administrator."
            )));
        }

        let w_key = to_wide_null(&key_name);
        let key_lsa = UNICODE_STRING {
            Length: ((w_key.len() - 1) * 2) as u16,
            MaximumLength: (w_key.len() * 2) as u16,
            Buffer: PWSTR(w_key.as_ptr() as *mut u16),
        };

        let mut private_data: *mut UNICODE_STRING = std::ptr::null_mut();
        let s =
            LsaRetrievePrivateData(policy_handle, &key_lsa, &mut private_data);

        let win32 = RtlNtStatusToDosError(s);
        if win32 != 0 {
            let _ = LsaClose(policy_handle);
            return Err(AetherError::not_found(ctx.clone(), format!(
                "LSA secret '{key_name}' not found or not accessible (error {win32})"
            ), None));
        }

        let data_str = lsa_unicode_to_string(*private_data);

        if !private_data.is_null() {
            let _ = LsaFreeReturnBuffer(private_data as *mut c_void);
        }

        let _ = LsaClose(policy_handle);

        audit::log_forced("user_management", "lsa_secret_read");

        let data_len = data_str.len();
        let display_data = if data_len > 200 {
            format!(
                "{}... (truncated, {} bytes total)",
                &data_str[..200],
                data_len
            )
        } else {
            data_str
        };

        Ok(serde_json::to_string_pretty(&json!({
            "key": key_name,
            "data": display_data,
            "data_length": data_len,
        }))?)
    }
}
