//! Process control tool for AETHER_01 MCP server.
//!
//! 13 actions for comprehensive Windows process management:
//! list, kill, create, set_priority, query_info, threads, set_affinity,
//! memory_limits, suspend, resume, list_handles, list_modules, inject_dll.
//!
//! Dangerous operations (kill, realtime priority, DLL injection) require `force: true`.
//! DLL injection requires the `AETHER_DLL_INJECT` feature gate.

#![allow(unsafe_code)]

use crate::audit;
use crate::error::{AetherError, ErrorContext};
use crate::server::AetherServer;

use serde_json::{json, Value};
use std::ffi::c_void;
use std::mem;

use windows::core::{s, w, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, FALSE, FILETIME, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW, Process32NextW,
    Thread32First, Thread32Next, CREATE_TOOLHELP_SNAPSHOT_FLAGS, MODULEENTRY32W, PROCESSENTRY32W,
    TH32CS_SNAPMODULE, TH32CS_SNAPPROCESS, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
    VIRTUAL_ALLOCATION_TYPE,
};
use windows::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows::Win32::System::Threading::{
    CreateProcessW, CreateRemoteThread, GetProcessTimes, OpenProcess, OpenThread, ResumeThread,
    SetPriorityClass, SetProcessAffinityMask, SetProcessWorkingSetSize, SuspendThread,
    TerminateProcess, WaitForSingleObject, ABOVE_NORMAL_PRIORITY_CLASS,
    BELOW_NORMAL_PRIORITY_CLASS, CREATE_NEW_CONSOLE, CREATE_NO_WINDOW,
    CREATE_UNICODE_ENVIRONMENT, HIGH_PRIORITY_CLASS, IDLE_PRIORITY_CLASS, LPTHREAD_START_ROUTINE,
    NORMAL_PRIORITY_CLASS, PROCESS_ACCESS_RIGHTS, PROCESS_CREATE_THREAD,
    PROCESS_QUERY_INFORMATION, PROCESS_SET_QUOTA, PROCESS_SET_INFORMATION, PROCESS_TERMINATE,
    PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, PROCESS_INFORMATION,
    REALTIME_PRIORITY_CLASS, STARTUPINFOW, THREAD_ACCESS_RIGHTS, THREAD_SUSPEND_RESUME,
};

// ═══════════════════════════════════════════════════════════════════════════════
// NtQuerySystemInformation / NtWriteVirtualMemory (ntdll FFI)
// ═══════════════════════════════════════════════════════════════════════════════
#[repr(C)]
#[allow(non_snake_case)]
struct SystemHandleTableEntryInfo {
    UniqueProcessId: u16,
    CreatorBackTraceIndex: u16,
    ObjectTypeIndex: u8,
    HandleAttributes: u8,
    HandleValue: u16,
    Object: *mut c_void,
    GrantedAccess: u32,
}

const SYSTEM_HANDLE_INFORMATION: u32 = 16;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004u32 as i32;

extern "system" {
    fn NtQuerySystemInformation(
        system_information_class: u32,
        system_information: *mut c_void,
        system_information_length: u32,
        return_length: *mut u32,
    ) -> i32;

    fn NtWriteVirtualMemory(
        process_handle: HANDLE,
        base_address: *mut c_void,
        buffer: *const c_void,
        number_of_bytes_to_write: u32,
        number_of_bytes_written: *mut u32,
    ) -> i32;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Main dispatch
// ═══════════════════════════════════════════════════════════════════════════════

/// Dispatch `process_control` actions.
///
/// # Errors
///
/// Returns `AetherError::InvalidParameter` when required parameters are missing
/// or the action is unknown. Returns `AetherError::Win32Error` on Windows API
/// failures. Returns `AetherError::FeatureDisabled` when a gated operation is
/// attempted without the required feature gate.
pub async fn handle_process_control(
    server: &AetherServer,
    action: &str,
    params: Value,
) -> std::result::Result<String, AetherError> {
    let tool = "process_control";

    let result = match action {
        "list" => list_processes(params).await,
        "kill" => kill_process(params).await,
        "create" => create_process(params).await,
        "set_priority" => set_priority(params).await,
        "query_info" => query_info(params).await,
        "threads" => list_threads(params).await,
        "set_affinity" => set_affinity(params).await,
        "memory_limits" => memory_limits(params).await,
        "suspend" => suspend_process_or_thread(params).await,
        "resume" => resume_process_or_thread(params).await,
        "list_handles" => list_handles(params).await,
        "list_modules" => list_modules(params).await,
        "inject_dll" => inject_dll(server, params).await,
        unknown => {
            let ctx = ErrorContext::new("process_control", "unknown");
            Err(AetherError::invalid_param(ctx, format!(
                "Unknown action: {unknown}. Valid: list, kill, create, set_priority, query_info, threads, set_affinity, memory_limits, suspend, resume, list_handles, list_modules, inject_dll"
            )))
        }
    };

    match &result {
        Ok(detail) => audit::log_success(tool, action, detail),
        Err(e) => audit::log_failure(tool, action, &e.to_string()),
    }

    result
}

// ═══════════════════════════════════════════════════════════════════════════════
// Parameter extraction helpers
// ═══════════════════════════════════════════════════════════════════════════════

fn get_u32(ctx: ErrorContext, params: &Value, key: &str) -> std::result::Result<u32, AetherError> {
    params
        .get(key)
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .ok_or_else(|| AetherError::invalid_param(ctx, format!("Missing or invalid `{key}` (u32)")))
}

fn get_bool(params: &Value, key: &str) -> bool {
    params.get(key).and_then(|v| v.as_bool()).unwrap_or(false)
}

fn get_string(ctx: ErrorContext, params: &Value, key: &str) -> std::result::Result<String, AetherError> {
    params
        .get(key)
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or_else(|| AetherError::invalid_param(ctx, format!("Missing or invalid `{key}` (string)")))
}

fn get_optional_string(params: &Value, key: &str) -> Option<String> {
    params.get(key).and_then(|v| v.as_str()).map(String::from)
}

fn check_force(ctx: ErrorContext, params: &Value) -> std::result::Result<(), AetherError> {
    if !get_bool(params, "force") {
        return Err(AetherError::permission_denied(ctx,
            "This operation requires `force: true` for safety. Set `force: true` to proceed.",
        ));
    }
    Ok(())
}

fn wide_string(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// ═══════════════════════════════════════════════════════════════════════════════
// 1. list — enumerate all processes
// ═══════════════════════════════════════════════════════════════════════════════

async fn list_processes(_params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("process_control", "list");

    // SAFETY: CreateToolhelp32Snapshot is a read-only diagnostic API.
    // HANDLE is closed via CloseHandle before returning.
    let snapshot = unsafe {
        CreateToolhelp32Snapshot(
            CREATE_TOOLHELP_SNAPSHOT_FLAGS(TH32CS_SNAPPROCESS.0),
            0,
        )
    }
    .map_err(|e| AetherError::win32(ctx.clone(), "CreateToolhelp32Snapshot", format!("CreateToolhelp32Snapshot failed: {e}")))?;

    let mut entry = PROCESSENTRY32W {
        dwSize: mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    let mut processes: Vec<Value> = Vec::new();

    // SAFETY: Process32FirstW reads process entry from a valid snapshot handle.
    // The entry struct is correctly initialized with dwSize.
    let first_ok = unsafe { Process32FirstW(snapshot, &mut entry) };

    if first_ok.is_ok() {
        loop {
            let name = String::from_utf16_lossy(
                &entry.szExeFile[..entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len())],
            );

            processes.push(json!({
                "pid": entry.th32ProcessID,
                "ppid": entry.th32ParentProcessID,
                "threads": entry.cntThreads,
                "name": name,
            }));

            // SAFETY: Process32NextW iterates entries from a valid snapshot handle.
            if unsafe { Process32NextW(snapshot, &mut entry) }.is_err() {
                break;
            }
        }
    }

    // SAFETY: Closing a valid snapshot handle — idempotent, no side effects.
    unsafe {
        let _ = CloseHandle(snapshot);
    }

    let result = json!({ "processes": processes, "count": processes.len() });
    serde_json::to_string(&result).map_err(AetherError::from)
}

// ═══════════════════════════════════════════════════════════════════════════════
// 2. kill — terminate a process by PID or name
// ═══════════════════════════════════════════════════════════════════════════════

async fn kill_process(params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("process_control", "kill");
    check_force(ctx.clone(), &params)?;
    audit::log_forced("process_control", "kill");

    let pid = if let Some(name) = get_optional_string(&params, "name") {
        find_pid_by_name(ctx.clone(), &name)?
    } else {
        get_u32(ctx.clone(), &params, "pid")?
    };

    let handle = open_process(ctx.clone(), pid, PROCESS_TERMINATE)?;

    // SAFETY: handle was opened with PROCESS_TERMINATE access for the target pid.
    // uExitCode of 1 indicates forced termination.
    let result = unsafe { TerminateProcess(handle, 1) };
    unsafe {
        let _ = CloseHandle(handle);
    }
    result.map_err(|e| AetherError::win32(ctx.clone(), "TerminateProcess", format!("TerminateProcess({pid}) failed: {e}")))?;

    let output = json!({ "terminated_pid": pid });
    serde_json::to_string(&output).map_err(AetherError::from)
}

fn find_pid_by_name(ctx: ErrorContext, name: &str) -> std::result::Result<u32, AetherError> {
    let snapshot = unsafe {
        CreateToolhelp32Snapshot(
            CREATE_TOOLHELP_SNAPSHOT_FLAGS(TH32CS_SNAPPROCESS.0),
            0,
        )
    }
    .map_err(|e| AetherError::win32(ctx.clone(), "CreateToolhelp32Snapshot", format!("CreateToolhelp32Snapshot failed: {e}")))?;

    let mut entry = PROCESSENTRY32W {
        dwSize: mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    let mut found: Option<u32> = None;

    if unsafe { Process32FirstW(snapshot, &mut entry) }.is_ok() {
        loop {
            let pname = String::from_utf16_lossy(
                &entry.szExeFile[..entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len())],
            );
            if pname.eq_ignore_ascii_case(name) {
                found = Some(entry.th32ProcessID);
                break;
            }
            if unsafe { Process32NextW(snapshot, &mut entry) }.is_err() {
                break;
            }
        }
    }

    unsafe {
        let _ = CloseHandle(snapshot);
    }

    found.ok_or_else(|| AetherError::not_found(ctx, format!("No process matching name: {name}"), None))
}

// ═══════════════════════════════════════════════════════════════════════════════
// 3. create — launch an executable
// ═══════════════════════════════════════════════════════════════════════════════

async fn create_process(params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("process_control", "create");
    let path = get_string(ctx.clone(), &params, "path")?;
    let args = get_optional_string(&params, "args");
    let working_dir = get_optional_string(&params, "working_dir");
    let show_window = get_bool(&params, "show_window");

    let mut cmd_line: Vec<u16> = if let Some(ref a) = args {
        wide_string(&format!("\"{path}\" {a}"))
    } else {
        wide_string(&format!("\"{path}\""))
    };

    let mut startup = STARTUPINFOW {
        cb: mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };

    if show_window {
        startup.wShowWindow = 1; // SW_SHOWNORMAL
    }

    let creation_flags = if show_window {
        CREATE_NEW_CONSOLE
    } else {
        CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT
    };

    let cwd_wide: Option<Vec<u16>> = working_dir.as_deref().map(wide_string);

    let mut proc_info = PROCESS_INFORMATION::default();

    // SAFETY: All pointer arguments are valid for the lifetime of the call.
    // cmd_line is a mutable wide string buffer (required by CreateProcessW which may modify it).
    // cwd_wide is an optional directory path.
    // startup is correctly initialized with cb set.
    // proc_info receives output handles that must be closed.
    let result = unsafe {
        CreateProcessW(
            PCWSTR::null(), // lpApplicationName — use command line instead
            PWSTR(cmd_line.as_mut_ptr()),
            None,           // lpProcessAttributes
            None,           // lpThreadAttributes
            FALSE,          // bInheritHandles
            creation_flags,
            None, // lpEnvironment
            cwd_wide
                .as_ref()
                .map(|w| PCWSTR(w.as_ptr()))
                .unwrap_or(PCWSTR::null()),
            &startup,
            &mut proc_info,
        )
    };

    result.map_err(|e| AetherError::win32(ctx.clone(), "CreateProcessW", format!("CreateProcessW failed: {e}")))?;

    let pid = proc_info.dwProcessId;
    let tid = proc_info.dwThreadId;

    // SAFETY: Closing handles returned by CreateProcessW is mandatory to avoid leaks.
    unsafe {
        let _ = CloseHandle(proc_info.hProcess);
        let _ = CloseHandle(proc_info.hThread);
    }

    let output = json!({
        "pid": pid,
        "tid": tid,
        "path": path,
    });
    serde_json::to_string(&output).map_err(AetherError::from)
}

// ═══════════════════════════════════════════════════════════════════════════════
// 4. set_priority — set process priority class
// ═══════════════════════════════════════════════════════════════════════════════

async fn set_priority(params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("process_control", "set_priority");
    let pid = get_u32(ctx.clone(), &params, "pid")?;
    let priority_str = get_string(ctx.clone(), &params, "priority")?;

    let priority_class = match priority_str.to_lowercase().as_str() {
        "idle" => IDLE_PRIORITY_CLASS,
        "below_normal" => BELOW_NORMAL_PRIORITY_CLASS,
        "normal" => NORMAL_PRIORITY_CLASS,
        "above_normal" => ABOVE_NORMAL_PRIORITY_CLASS,
        "high" => HIGH_PRIORITY_CLASS,
        "realtime" => {
            check_force(ctx.clone(), &params)?;
            audit::log_forced("process_control", "set_priority_realtime");
            REALTIME_PRIORITY_CLASS
        }
        other => {
            return Err(AetherError::invalid_param(ctx, format!(
                "Unknown priority: {other}. Valid: idle, below_normal, normal, above_normal, high, realtime"
            )));
        }
    };

    let handle = open_process(
        ctx.clone(),
        pid,
        PROCESS_SET_INFORMATION,
    )?;

    // SAFETY: handle was opened with PROCESS_SET_INFORMATION for the target pid.
    let result = unsafe { SetPriorityClass(handle, priority_class) };
    unsafe {
        let _ = CloseHandle(handle);
    }
    result.map_err(|e| AetherError::win32(ctx.clone(), "SetPriorityClass", format!("SetPriorityClass({pid}) failed: {e}")))?;

    let output = json!({
        "pid": pid,
        "priority": priority_str,
    });
    serde_json::to_string(&output).map_err(AetherError::from)
}

// ═══════════════════════════════════════════════════════════════════════════════
// 5. query_info — detailed process information
// ═══════════════════════════════════════════════════════════════════════════════

async fn query_info(params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("process_control", "query_info");
    let pid = get_u32(ctx.clone(), &params, "pid")?;

    let handle = open_process(
        ctx.clone(),
        pid,
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
    )?;

    // Get process times
    let mut creation_time = FILETIME::default();
    let mut exit_time = FILETIME::default();
    let mut kernel_time = FILETIME::default();
    let mut user_time = FILETIME::default();

    // SAFETY: handle is valid with PROCESS_QUERY_INFORMATION. All FILETIME
    // pointers are properly aligned stack variables.
    unsafe {
        GetProcessTimes(
            handle,
            &mut creation_time,
            &mut exit_time,
            &mut kernel_time,
            &mut user_time,
        )
    }
    .map_err(|e| AetherError::win32(ctx.clone(), "GetProcessTimes", format!("GetProcessTimes({pid}) failed: {e}")))?;

    // Get memory info
    let mut mem_counters = PROCESS_MEMORY_COUNTERS {
        cb: mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        ..Default::default()
    };

    // SAFETY: handle is valid with PROCESS_VM_READ. mem_counters is properly
    // initialized with cb set.
    let mem_ok = unsafe {
        K32GetProcessMemoryInfo(
            handle,
            &mut mem_counters,
            mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        )
    };
    if !mem_ok.as_bool() {
        unsafe {
            let _ = CloseHandle(handle);
        }
        return Err(AetherError::win32(ctx, "K32GetProcessMemoryInfo", format!(
            "K32GetProcessMemoryInfo({pid}) failed"
        )));
    }

    unsafe {
        let _ = CloseHandle(handle);
    }

    let output = json!({
        "pid": pid,
        "creation_time": filetime_to_u64(&creation_time),
        "exit_time": filetime_to_u64(&exit_time),
        "kernel_time": filetime_to_u64(&kernel_time),
        "user_time": filetime_to_u64(&user_time),
        "page_fault_count": mem_counters.PageFaultCount,
        "peak_working_set_size": mem_counters.PeakWorkingSetSize,
        "working_set_size": mem_counters.WorkingSetSize,
        "quota_peak_paged_pool": mem_counters.QuotaPeakPagedPoolUsage,
        "quota_paged_pool": mem_counters.QuotaPagedPoolUsage,
        "quota_peak_non_paged_pool": mem_counters.QuotaPeakNonPagedPoolUsage,
        "quota_non_paged_pool": mem_counters.QuotaNonPagedPoolUsage,
        "pagefile_usage": mem_counters.PagefileUsage,
        "peak_pagefile_usage": mem_counters.PeakPagefileUsage,
    });
    serde_json::to_string(&output).map_err(AetherError::from)
}

fn filetime_to_u64(ft: &FILETIME) -> u64 {
    ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64)
}

// ═══════════════════════════════════════════════════════════════════════════════
// 6. threads — list threads of a process
// ═══════════════════════════════════════════════════════════════════════════════

async fn list_threads(params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("process_control", "threads");
    let pid = get_u32(ctx.clone(), &params, "pid")?;

    // SAFETY: CreateToolhelp32Snapshot is a read-only diagnostic API.
    let snapshot = unsafe {
        CreateToolhelp32Snapshot(
            CREATE_TOOLHELP_SNAPSHOT_FLAGS(TH32CS_SNAPTHREAD.0),
            0,
        )
    }
    .map_err(|e| AetherError::win32(ctx.clone(), "CreateToolhelp32Snapshot", format!("CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD) failed: {e}")))?;

    let mut entry = THREADENTRY32 {
        dwSize: mem::size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };

    let mut threads: Vec<Value> = Vec::new();

    // SAFETY: entry is correctly initialized with dwSize. Snapshot handle is valid.
    if unsafe { Thread32First(snapshot, &mut entry) }.is_ok() {
        loop {
            if entry.th32OwnerProcessID == pid {
                threads.push(json!({
                    "tid": entry.th32ThreadID,
                    "pid": entry.th32OwnerProcessID,
                    "base_priority": entry.tpBasePri,
                }));
            }

            // SAFETY: iterating over valid snapshot handle.
            if unsafe { Thread32Next(snapshot, &mut entry) }.is_err() {
                break;
            }
        }
    }

    unsafe {
        let _ = CloseHandle(snapshot);
    }

    let output = json!({
        "pid": pid,
        "threads": threads,
        "count": threads.len(),
    });
    serde_json::to_string(&output).map_err(AetherError::from)
}

// ═══════════════════════════════════════════════════════════════════════════════
// 7. set_affinity — set CPU affinity mask
// ═══════════════════════════════════════════════════════════════════════════════

async fn set_affinity(params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("process_control", "set_affinity");
    let pid = get_u32(ctx.clone(), &params, "pid")?;
    let cores: Vec<usize> = params
        .get("cores")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            AetherError::invalid_param(ctx.clone(), "Missing required `cores` (array of core indices)")
        })?
        .iter()
        .filter_map(|c| c.as_u64().map(|n| n as usize))
        .collect();

    if cores.is_empty() {
        return Err(AetherError::invalid_param(ctx, "`cores` must contain at least one core index"));
    }

    let mut mask: usize = 0;
    for core in &cores {
        if *core >= mem::size_of::<usize>() * 8 {
            return Err(AetherError::invalid_param(ctx.clone(), format!(
                "Core index {core} exceeds maximum of {}",
                mem::size_of::<usize>() * 8 - 1
            )));
        }
        mask |= 1usize << core;
    }

    let handle = open_process(
        ctx.clone(),
        pid,
        PROCESS_SET_INFORMATION
    )?;

    // SAFETY: handle is valid with PROCESS_SET_INFORMATION. mask is a valid
    // affinity bitmap derived from validated core indices.
    let result = unsafe { SetProcessAffinityMask(handle, mask) };
    unsafe {
        let _ = CloseHandle(handle);
    }
    result
        .map_err(|e| AetherError::win32(ctx.clone(), "SetProcessAffinityMask", format!("SetProcessAffinityMask({pid}) failed: {e}")))?;

    let output = json!({
        "pid": pid,
        "affinity_mask": format!("0x{mask:X}"),
        "cores": cores,
    });
    serde_json::to_string(&output).map_err(AetherError::from)
}

// ═══════════════════════════════════════════════════════════════════════════════
// 8. memory_limits — set working set size
// ═══════════════════════════════════════════════════════════════════════════════

async fn memory_limits(params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("process_control", "memory_limits");
    let pid = get_u32(ctx.clone(), &params, "pid")?;
    let min_ws = params
        .get("min_ws")
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
        .unwrap_or(usize::MAX); // usize::MAX means "don't change minimum"
    let max_ws = params
        .get("max_ws")
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
        .unwrap_or(usize::MAX); // usize::MAX means "don't change maximum"

    let handle = open_process(
        ctx.clone(),
        pid,
        PROCESS_SET_QUOTA | PROCESS_SET_INFORMATION,
    )?;

    // SAFETY: handle is valid with PROCESS_SET_QUOTA. min_ws and max_ws are
    // validated sizes (usize::MAX signals "no change" to the kernel).
    let result = unsafe { SetProcessWorkingSetSize(handle, min_ws, max_ws) };
    unsafe {
        let _ = CloseHandle(handle);
    }
    result.map_err(|e| {
        AetherError::win32(ctx.clone(), "SetProcessWorkingSetSize", format!("SetProcessWorkingSetSize({pid}) failed: {e}"))
    })?;

    let output = json!({
        "pid": pid,
        "min_ws": if min_ws == usize::MAX { None } else { Some(min_ws) },
        "max_ws": if max_ws == usize::MAX { None } else { Some(max_ws) },
    });
    serde_json::to_string(&output).map_err(AetherError::from)
}

// ═══════════════════════════════════════════════════════════════════════════════
// 9a. suspend — suspend a process (all threads) or single thread
// ═══════════════════════════════════════════════════════════════════════════════

async fn suspend_process_or_thread(params: Value) -> std::result::Result<String, AetherError> {
    suspend_resume_inner(params, false).await
}

// ═══════════════════════════════════════════════════════════════════════════════
// 9b. resume — resume a process (all threads) or single thread
// ═══════════════════════════════════════════════════════════════════════════════

async fn resume_process_or_thread(params: Value) -> std::result::Result<String, AetherError> {
    suspend_resume_inner(params, true).await
}

async fn suspend_resume_inner(params: Value, resume: bool) -> std::result::Result<String, AetherError> {
    let op_name = if resume { "resume" } else { "suspend" };
    let ctx = ErrorContext::new("process_control", op_name);

    // Single thread mode: tid is provided
    if let Ok(tid) = get_u32(ctx.clone(), &params, "tid") {
        let handle = open_thread(ctx.clone(), tid, THREAD_SUSPEND_RESUME)?;

        // SAFETY: handle is valid with THREAD_SUSPEND_RESUME for the target tid.
        // SuspendThread/ResumeThread return the previous suspend count (u32).
        // A return value of u32::MAX indicates failure.
        let previous_count = if resume {
            unsafe { ResumeThread(handle) }
        } else {
            unsafe { SuspendThread(handle) }
        };

        unsafe {
            let _ = CloseHandle(handle);
        }

        if previous_count == u32::MAX {
            return Err(AetherError::win32(ctx, "SuspendThread/ResumeThread", format!(
                "{}(thread {tid}) failed",
                if resume { "ResumeThread" } else { "SuspendThread" }
            )));
        }

        let output = json!({
            "action": op_name,
            "tid": tid,
            "previous_suspend_count": previous_count,
        });
        return serde_json::to_string(&output).map_err(AetherError::from);
    }

    // Process mode: pid is provided — enumerate and suspend/resume all threads
    let pid = get_u32(ctx.clone(), &params, "pid")?;

    let threads = enumerate_thread_ids(ctx.clone(), pid)?;
    let mut results: Vec<Value> = Vec::new();

    for &tid in &threads {
        let handle = match open_thread(ctx.clone(), tid, THREAD_SUSPEND_RESUME) {
            Ok(h) => h,
            Err(e) => {
                results.push(json!({
                    "tid": tid,
                    "result": "error",
                    "error": e.to_string(),
                }));
                continue;
            }
        };

        // SAFETY: handle is valid with THREAD_SUSPEND_RESUME for the target tid.
        // Returns u32 (previous suspend count), u32::MAX on failure.
        let count = if resume {
            unsafe { ResumeThread(handle) }
        } else {
            unsafe { SuspendThread(handle) }
        };

        unsafe {
            let _ = CloseHandle(handle);
        }

        if count == u32::MAX {
            results.push(json!({
                "tid": tid,
                "result": "error",
                "error": format!(
                    "{}(thread {tid}) failed",
                    if resume { "ResumeThread" } else { "SuspendThread" }
                ),
            }));
        } else {
            results.push(json!({
                "tid": tid,
                "result": "ok",
                "previous_suspend_count": count,
            }));
        }
    }
    let output = json!({
        "action": op_name,
        "pid": pid,
        "threads_affected": threads.len(),
        "details": results,
    });
    serde_json::to_string(&output).map_err(AetherError::from)
}

fn enumerate_thread_ids(ctx: ErrorContext, pid: u32) -> std::result::Result<Vec<u32>, AetherError> {
    // SAFETY: CreateToolhelp32Snapshot is a read-only diagnostic API.
    let snapshot = unsafe {
        CreateToolhelp32Snapshot(
            CREATE_TOOLHELP_SNAPSHOT_FLAGS(TH32CS_SNAPTHREAD.0),
            0,
        )
    }
    .map_err(|e| {
        AetherError::win32(ctx.clone(), "CreateToolhelp32Snapshot", format!("CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD) failed: {e}"))
    })?;

    let mut entry = THREADENTRY32 {
        dwSize: mem::size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };

    let mut tids: Vec<u32> = Vec::new();

    if unsafe { Thread32First(snapshot, &mut entry) }.is_ok() {
        loop {
            if entry.th32OwnerProcessID == pid {
                tids.push(entry.th32ThreadID);
            }
            if unsafe { Thread32Next(snapshot, &mut entry) }.is_err() {
                break;
            }
        }
    }

    unsafe {
        let _ = CloseHandle(snapshot);
    }

    if tids.is_empty() {
        return Err(AetherError::not_found(ctx, format!(
            "No threads found for PID {pid} (process may have exited)"
        ), None));
    }

    Ok(tids)
}

// ═══════════════════════════════════════════════════════════════════════════════
// 10. list_handles — enumerate open handles via NtQuerySystemInformation
// ═══════════════════════════════════════════════════════════════════════════════

async fn list_handles(params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("process_control", "list_handles");
    let pid = get_u32(ctx.clone(), &params, "pid")?;

    let mut buffer_size: u32 = 0x100000; // 1 MB initial
    let mut retry_count = 0u8;
    const MAX_RETRIES: u8 = 4;

    loop {
        let mut buf: Vec<u8> = vec![0u8; buffer_size as usize];
        let mut return_length: u32 = 0;

        // SAFETY: NtQuerySystemInformation reads system handle table into a
        // pre-allocated buffer. The buffer is sized conservatively and grown on
        // STATUS_INFO_LENGTH_MISMATCH.
        let status = unsafe {
            NtQuerySystemInformation(
                SYSTEM_HANDLE_INFORMATION,
                buf.as_mut_ptr().cast::<c_void>(),
                buffer_size,
                &mut return_length,
            )
        };

        if status == STATUS_INFO_LENGTH_MISMATCH && retry_count < MAX_RETRIES {
            buffer_size = return_length.max(buffer_size * 2);
            retry_count += 1;
            continue;
        }

        if status < 0 {
            return Err(AetherError::win32(ctx, "NtQuerySystemInformation", format!(
                "NtQuerySystemInformation returned NTSTATUS 0x{status:08X}"
            )));
        }

        // Parse the buffer: first 4 bytes = number of handles (u32 on 32-bit,
        // but the structure in the return is actually ULONG which is 4 bytes).
        // In practice, on 64-bit Windows, there's 4 bytes of padding after the count
        // before the first entry. The count is a ULONG.
        let count =
            u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;

        // On 64-bit systems, entries start at offset 8 (4-byte count + 4-byte padding).
        // On 32-bit, entries start at offset 4. We use size_of::<usize>() as the offset.
        let entry_offset = mem::size_of::<usize>();
        let entry_size = mem::size_of::<SystemHandleTableEntryInfo>();

        let mut handles: Vec<Value> = Vec::new();

        for i in 0..count {
            let offset = entry_offset + i * entry_size;
            if offset + entry_size > buf.len() {
                break;
            }

            // SAFETY: We verified bounds. The buffer contains properly aligned
            // SYSTEM_HANDLE_TABLE_ENTRY_INFO structs from the kernel.
            let entry: &SystemHandleTableEntryInfo =
                unsafe { &*(buf[offset..].as_ptr() as *const SystemHandleTableEntryInfo) };

            if entry.UniqueProcessId as u32 == pid {
                handles.push(json!({
                    "handle": entry.HandleValue,
                    "object_type_index": entry.ObjectTypeIndex,
                    "granted_access": format!("0x{:08X}", entry.GrantedAccess),
                    "handle_attributes": entry.HandleAttributes,
                }));
            }
        }

        let output = json!({
            "pid": pid,
            "total_system_handles": count,
            "process_handles": handles.len(),
            "handles": handles,
        });
        return serde_json::to_string(&output).map_err(AetherError::from);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 11. list_modules — list loaded DLLs (modules)
// ═══════════════════════════════════════════════════════════════════════════════

async fn list_modules(params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("process_control", "list_modules");
    let pid = get_u32(ctx.clone(), &params, "pid")?;

    // SAFETY: CreateToolhelp32Snapshot with TH32CS_SNAPMODULE is read-only.
    let snapshot = unsafe {
        CreateToolhelp32Snapshot(
            CREATE_TOOLHELP_SNAPSHOT_FLAGS(TH32CS_SNAPMODULE.0),
            pid,
        )
    }
    .map_err(|e| {
        AetherError::win32(ctx.clone(), "CreateToolhelp32Snapshot", format!("CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, {pid}) failed: {e}"))
    })?;

    let mut entry = MODULEENTRY32W {
        dwSize: mem::size_of::<MODULEENTRY32W>() as u32,
        ..Default::default()
    };

    let mut modules: Vec<Value> = Vec::new();

    // SAFETY: entry is correctly initialized with dwSize. Snapshot handle is valid.
    if unsafe { Module32FirstW(snapshot, &mut entry) }.is_ok() {
        loop {
            let name = String::from_utf16_lossy(
                &entry.szModule[..entry
                    .szModule
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szModule.len())],
            );
            let path = String::from_utf16_lossy(
                &entry.szExePath[..entry
                    .szExePath
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExePath.len())],
            );

            modules.push(json!({
                "name": name,
                "path": path,
                "base_address": format!("0x{:X}", entry.modBaseAddr as usize),
                "size": entry.modBaseSize,
            }));

            // SAFETY: iterating over valid snapshot handle.
            if unsafe { Module32NextW(snapshot, &mut entry) }.is_err() {
                break;
            }
        }
    }

    unsafe {
        let _ = CloseHandle(snapshot);
    }

    let output = json!({
        "pid": pid,
        "modules": modules,
        "count": modules.len(),
    });
    serde_json::to_string(&output).map_err(AetherError::from)
}

// ═══════════════════════════════════════════════════════════════════════════════
// 12. inject_dll — DLL injection via CreateRemoteThread(LoadLibraryW)
// ═══════════════════════════════════════════════════════════════════════════════

async fn inject_dll(server: &AetherServer, params: Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("process_control", "inject_dll");

    // Feature gate check
    server
        .gates
        .check(ctx.clone(), server.gates.dll_inject, "AETHER_DLL_INJECT")?;

    check_force(ctx.clone(), &params)?;
    audit::log_forced("process_control", "inject_dll");
    audit::log_security("process_control", "inject_dll", "DLL injection requested");

    let pid = get_u32(ctx.clone(), &params, "pid")?;
    let dll_path = get_string(ctx.clone(), &params, "dll_path")?;
    let dll_path_wide = wide_string(&dll_path);
    let dll_path_bytes: &[u8] = unsafe {
        std::slice::from_raw_parts(
            dll_path_wide.as_ptr().cast::<u8>(),
            dll_path_wide.len() * 2,
        )
    };
    let dll_path_byte_len = dll_path_bytes.len();

    // Open target process with required access rights
    let handle = open_process(
        ctx.clone(),
        pid,
        PROCESS_CREATE_THREAD
            | PROCESS_QUERY_INFORMATION
            | PROCESS_VM_OPERATION
            | PROCESS_VM_WRITE
            | PROCESS_VM_READ,
    )?;

    // Allocate memory in the target process for the DLL path
    // SAFETY: handle is valid with PROCESS_VM_OPERATION. We allocate
    // MEM_COMMIT | MEM_RESERVE with PAGE_READWRITE to hold the DLL path string.
    let remote_mem = unsafe {
        VirtualAllocEx(
            handle,
            None, // let the system choose the address
            dll_path_byte_len,
            VIRTUAL_ALLOCATION_TYPE(MEM_COMMIT.0 | MEM_RESERVE.0),
            PAGE_READWRITE,
        )
    };

    if remote_mem.is_null() {
        unsafe {
            let _ = CloseHandle(handle);
        }
        return Err(AetherError::win32(ctx.clone(), "VirtualAllocEx", format!(
            "VirtualAllocEx({pid}) failed — returned null"
        )));
    }

    // Write the DLL path into the target process using NtWriteVirtualMemory
    let mut bytes_written: u32 = 0;

    // SAFETY: remote_mem is a valid committed region in the target process
    // with PAGE_READWRITE. dll_path_bytes contains the wide-char DLL path.
    let write_status = unsafe {
        NtWriteVirtualMemory(
            handle,
            remote_mem,
            dll_path_bytes.as_ptr().cast::<c_void>(),
            dll_path_byte_len as u32,
            &mut bytes_written,
        )
    };

    if write_status < 0 || bytes_written != dll_path_byte_len as u32 {
        // SAFETY: Freeing the remote allocation we just created.
        unsafe {
            VirtualFreeEx(handle, remote_mem, 0, MEM_RELEASE).ok();
            let _ = CloseHandle(handle);
        }
        return Err(AetherError::win32(ctx.clone(), "NtWriteVirtualMemory", format!(
            "NtWriteVirtualMemory({pid}) failed (NTSTATUS=0x{write_status:08X}) — wrote {bytes_written}/{dll_path_byte_len} bytes"
        )));
    }

    // Get the address of LoadLibraryW in kernel32.dll
    // SAFETY: GetModuleHandleW with a valid constant string. Returns HMODULE to kernel32
    // which is always loaded in every process.
    let kernel32 = unsafe { GetModuleHandleW(w!("kernel32")) }
        .map_err(|e| AetherError::win32(ctx.clone(), "GetModuleHandleW", format!("GetModuleHandleW(kernel32) failed: {e}")))?;

    // SAFETY: GetProcAddress with valid HMODULE and constant function name.
    // LoadLibraryW is always exported by kernel32.
    // GetProcAddress returns Option<FARPROC> where FARPROC = Option<fn ptr>,
    // so we flatten the double Option, then transmute to the expected signature.
    let load_library_addr: LPTHREAD_START_ROUTINE = unsafe {
        let farproc = GetProcAddress(kernel32, s!("LoadLibraryW"))
            .ok_or_else(|| {
                AetherError::win32(ctx.clone(), "GetProcAddress", "GetProcAddress(LoadLibraryW) returned None".to_string())
            })?;
        // FARPROC and LPTHREAD_START_ROUTINE are both function pointers;
        // the signature mismatch is safe because LoadLibraryW's calling
        // convention is compatible (stdcall on x86, same ABI on x64).
        std::mem::transmute(farproc)
    };

    // Create remote thread that calls LoadLibraryW with the DLL path
    // SAFETY: handle is valid with PROCESS_CREATE_THREAD. remote_mem contains
    // the DLL path. load_library_addr points to the real LoadLibraryW in kernel32.
    // Thread is started immediately (dwCreationFlags = 0).
    let remote_thread = unsafe {
        CreateRemoteThread(
            handle,
            None, // default security
            0,    // stack size (default)
            load_library_addr,
            Some(remote_mem),
            0, // run immediately
            None,
        )
    };

    match remote_thread {
        Ok(thread_handle) => {
            // Wait for the remote thread to complete (LoadLibraryW returns)
            // SAFETY: thread_handle is a valid handle from CreateRemoteThread.
            // We wait up to 30 seconds for the DLL to load.
            unsafe {
                WaitForSingleObject(thread_handle, 30_000);
                let _ = CloseHandle(thread_handle);
            }

            // Note: We intentionally do NOT free remote_mem after LoadLibraryW,
            // because the DLL may still reference its own path string.
            // The memory will be freed when the target process exits.

            unsafe {
                let _ = CloseHandle(handle);
            }

            let output = json!({
                "pid": pid,
                "dll_path": dll_path,
                "status": "injected",
                "note": "DLL loaded via CreateRemoteThread(LoadLibraryW). Remote memory intentionally not freed — it is released on process exit.",
            });
            serde_json::to_string(&output).map_err(AetherError::from)
        }
        Err(e) => {
            // Clean up on failure
            // SAFETY: Freeing the remote allocation we created.
            unsafe {
                VirtualFreeEx(handle, remote_mem, 0, MEM_RELEASE).ok();
                let _ = CloseHandle(handle);
            }
            Err(AetherError::win32(ctx, "CreateRemoteThread", format!(
                "CreateRemoteThread({pid}) failed: {e}"
            )))
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Shared helpers
// ═══════════════════════════════════════════════════════════════════════════════

/// Open a process with the requested access rights.
fn open_process(ctx: ErrorContext, pid: u32, access: PROCESS_ACCESS_RIGHTS) -> std::result::Result<HANDLE, AetherError> {
    // SAFETY: pid is user-provided but validated. bInheritHandle is FALSE.
    // Returns NULL on failure, which the windows crate wraps as an Error.
    unsafe { OpenProcess(access, FALSE, pid) }
        .map_err(|e| AetherError::win32(ctx.clone(), "OpenProcess", format!("OpenProcess({pid}) failed: {e}")))
        .and_then(|h| {
            if h.is_invalid() {
                Err(AetherError::not_found(ctx, format!(
                    "Process {pid} not found or access denied"
                ), None))
            } else {
                Ok(h)
            }
        })
}

/// Open a thread with the requested access rights.
fn open_thread(ctx: ErrorContext, tid: u32, access: THREAD_ACCESS_RIGHTS) -> std::result::Result<HANDLE, AetherError> {
    // SAFETY: tid is user-provided but validated. bInheritHandle is FALSE.
    unsafe { OpenThread(access, FALSE, tid) }
        .map_err(|e| AetherError::win32(ctx.clone(), "OpenThread", format!("OpenThread({tid}) failed: {e}")))
        .and_then(|h| {
            if h.is_invalid() {
                Err(AetherError::not_found(ctx, format!(
                    "Thread {tid} not found or access denied"
                ), None))
            } else {
                Ok(h)
            }
        })
}
