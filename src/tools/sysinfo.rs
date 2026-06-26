//! System Information tool for AETHER_01 MCP server.
//!
//! Covers CPU, memory, disk, OS, uptime, environment, power, battery,
//! devices, drivers, BIOS, time/NTP, installed software, updates,
//! startup programs, restore points, performance counters, BCD,
//! and crash dump configuration.

use crate::audit;
use crate::command::{ParamType, SafeCommand};
use crate::error::{AetherError, ErrorContext};
use crate::server::AetherServer;

use std::mem;
use std::ptr;
use std::thread;
use std::time::Duration;

use windows::core::{s, w, PCWSTR, PWSTR};
use windows::Win32::Devices::DeviceAndDriverInstallation::*;
use windows::Win32::Foundation::*;
use windows::Win32::Storage::FileSystem::*;
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Power::*;
use windows::Win32::System::Registry::*;
use windows::Win32::System::SystemInformation::*;
use windows::Win32::System::Threading::*;
use windows::Win32::System::Time::{GetTimeZoneInformation, TIME_ZONE_INFORMATION};

// ═══════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════

/// IOCTL code for retrieving physical disk geometry.
const IOCTL_DISK_GET_DRIVE_GEOMETRY: u32 = 0x00070000;

// ═══════════════════════════════════════════════════════════════════════════════
// Helper: read a registry string value
// ═══════════════════════════════════════════════════════════════════════════════

unsafe fn reg_read_string(ctx: &ErrorContext, hkey: HKEY, subkey: &str, value_name: &str) -> std::result::Result<String, AetherError> {
    let subkey_wide: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
    let mut key: HKEY = HKEY::default();

    let result = RegOpenKeyExW(
        hkey,
        PCWSTR::from_raw(subkey_wide.as_ptr()),
        0,
        KEY_READ,
        &mut key,
    );
    if result != WIN32_ERROR(0) {
        return Err(AetherError::win32(ctx.clone(), "RegOpenKeyExW", format!("{result:?}")));
    }

    let value_wide: Vec<u16> = value_name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut data_type: REG_VALUE_TYPE = REG_VALUE_TYPE(0);
    let mut data_size: u32 = 0;

    let status = RegQueryValueExW(
        key,
        PCWSTR::from_raw(value_wide.as_ptr()),
        Some(ptr::null()),
        Some(&mut data_type),
        None,
        Some(&mut data_size),
    );
    if status != WIN32_ERROR(0) && data_size == 0 {
        let _ = RegCloseKey(key);
        return Err(AetherError::not_found(
            ctx.clone(),
            format!("Registry value '{value_name}' not found in {subkey}"),
            None,
        ));
    }
    if data_type.0 != REG_SZ.0 && data_type.0 != REG_EXPAND_SZ.0 {
        let _ = RegCloseKey(key);
        return Err(AetherError::win32(
            ctx.clone(),
            "RegQueryValueExW",
            format!("Registry value '{value_name}' is not a string (type={})", data_type.0),
        ));
    }

    let byte_count = data_size as usize;
    let mut buffer: Vec<u8> = vec![0u8; byte_count.max(2)];
    let result = RegQueryValueExW(
        key,
        PCWSTR::from_raw(value_wide.as_ptr()),
        Some(ptr::null()),
        Some(&mut data_type),
        Some(buffer.as_mut_ptr()),
        Some(&mut data_size),
    );
    if result != WIN32_ERROR(0) {
        let _ = RegCloseKey(key);
        return Err(AetherError::win32(ctx.clone(), "RegQueryValueExW", format!("(data) {result:?}")));
    }
    let _ = RegCloseKey(key);

    let len = if data_size >= 2 { (data_size as usize - 2) / 2 } else { 0 };
    let wide: &[u16] = std::slice::from_raw_parts(buffer.as_ptr() as *const u16, len);
    Ok(String::from_utf16_lossy(wide))
}

// ═══════════════════════════════════════════════════════════════════════════════
// Helper: enumerate subkeys of a registry key
// ═══════════════════════════════════════════════════════════════════════════════

unsafe fn reg_enum_subkeys(hkey: HKEY, subkey: &str) -> std::result::Result<Vec<String>, AetherError> {
    let subkey_wide: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
    let mut key: HKEY = HKEY::default();

    let result = RegOpenKeyExW(
        hkey,
        PCWSTR::from_raw(subkey_wide.as_ptr()),
        0,
        KEY_READ,
        &mut key,
    );
    if result != WIN32_ERROR(0) {
        return Ok(Vec::new());
    }

    let mut names: Vec<String> = Vec::new();
    let mut buf: [u16; 512] = [0u16; 512];
    for idx in 0u32.. {
        let mut buf_size: u32 = buf.len() as u32;
        let status = RegEnumKeyExW(
            key,
            idx,
            PWSTR::from_raw(buf.as_mut_ptr()),
            &mut buf_size,
            Some(ptr::null()),
            PWSTR::null(),
            None,
            None,
        );
        if status != WIN32_ERROR(0) {
            break;
        }
        if buf_size > 0 {
            let s = String::from_utf16_lossy(&buf[..buf_size as usize]);
            names.push(s);
        }
    }
    let _ = RegCloseKey(key);
    Ok(names)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Helper: read all values from a registry key as JSON
// ═══════════════════════════════════════════════════════════════════════════════

unsafe fn reg_read_all_values_to_json(hkey: HKEY, subkey: &str) -> std::result::Result<serde_json::Value, AetherError> {
    let subkey_wide: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
    let mut key: HKEY = HKEY::default();

    let result = RegOpenKeyExW(
        hkey,
        PCWSTR::from_raw(subkey_wide.as_ptr()),
        0,
        KEY_READ,
        &mut key,
    );
    if result != WIN32_ERROR(0) {
        return Ok(serde_json::Value::Null);
    }

    let mut map = serde_json::Map::new();
    let mut name_buf: [u16; 256] = [0u16; 256];
    let mut data_buf: [u8; 2048] = [0u8; 2048];

    for idx in 0u32.. {
        let mut name_len: u32 = name_buf.len() as u32;
        let mut data_type: u32 = 0;
        let mut data_len: u32 = data_buf.len() as u32;

        let status = RegEnumValueW(
            key,
            idx,
            PWSTR::from_raw(name_buf.as_mut_ptr()),
            &mut name_len,
            Some(ptr::null()),
            Some(&mut data_type),
            Some(data_buf.as_mut_ptr()),
            Some(&mut data_len),
        );
        if status != WIN32_ERROR(0) {
            break;
        }

        let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
        let val = match data_type {
            t if t == REG_SZ.0 || t == REG_EXPAND_SZ.0 => {
                let len = if data_len >= 2 { (data_len as usize - 2) / 2 } else { 0 };
                let wide: &[u16] = std::slice::from_raw_parts(data_buf.as_ptr() as *const u16, len);
                serde_json::Value::String(String::from_utf16_lossy(wide))
            }
            t if t == REG_DWORD.0 => {
                if data_len >= 4 {
                    let dw = *(data_buf.as_ptr() as *const u32);
                    serde_json::Value::Number(serde_json::Number::from(dw))
                } else {
                    serde_json::Value::Null
                }
            }
            t if t == REG_QWORD.0 => {
                if data_len >= 8 {
                    let qw = *(data_buf.as_ptr() as *const u64);
                    serde_json::Value::Number(serde_json::Number::from(qw))
                } else {
                    serde_json::Value::Null
                }
            }
            _ => serde_json::Value::Null,
        };
        map.insert(name, val);
    }

    let _ = RegCloseKey(key);
    Ok(serde_json::Value::Object(map))
}

// ═══════════════════════════════════════════════════════════════════════════════
// Helper: wide string from &str
// ═══════════════════════════════════════════════════════════════════════════════

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// ═══════════════════════════════════════════════════════════════════════════════
// Action: cpu_info
// ═══════════════════════════════════════════════════════════════════════════════

unsafe fn action_cpu_info(ctx: &ErrorContext) -> std::result::Result<String, AetherError> {
    let mut result = serde_json::Map::new();

    // GetSystemInfo
    let mut sys_info: SYSTEM_INFO = mem::zeroed();
    GetSystemInfo(&mut sys_info);

    let arch = match sys_info.Anonymous.Anonymous.wProcessorArchitecture.0 {
        0 => "x86",
        5 => "ARM",
        6 => "IA64",
        9 => "x64",
        12 => "ARM64",
        _ => "Unknown",
    };
    result.insert("architecture".into(), serde_json::Value::String(arch.into()));
    result.insert("logical_processors".into(), serde_json::Value::Number(
        serde_json::Number::from(sys_info.dwNumberOfProcessors)
    ));

    // GetLogicalProcessorInformationEx for cores and cache
    let mut buf_size: u32 = 0;
    GetLogicalProcessorInformationEx(RelationAll, None, &mut buf_size).ok();
    if buf_size > 0 {
        let mut buf: Vec<u8> = vec![0u8; buf_size as usize];
        if GetLogicalProcessorInformationEx(
            RelationAll,
            Some(buf.as_mut_ptr() as *mut SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX),
            &mut buf_size,
        ).is_ok()
        {
            let mut cores: u32 = 0;
            let mut cache_sizes: Vec<String> = Vec::new();
            let mut offset: usize = 0;

            loop {
                if offset + mem::size_of::<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>() > buf.len() {
                    break;
                }
                let info = &*(buf.as_ptr().add(offset) as *const SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX);
                if info.Relationship == RelationProcessorCore {
                    cores += 1;
                } else if info.Relationship == RelationCache {
                    let cache = &info.Anonymous.Cache;
                    if cache.Level > 0 && cache.Level <= 3 {
                        let kind = match cache.Type.0 {
                            1 => "Data",
                            2 => "Instruction",
                            3 => "Unified",
                            _ => "Unknown",
                        };
                        cache_sizes.push(format!("L{} {}={}KB", cache.Level, kind, cache.CacheSize / 1024));
                    }
                }
                let size = info.Size;
                if size == 0 {
                    break;
                }
                offset += size as usize;
            }

            result.insert("cores".into(), serde_json::Value::Number(serde_json::Number::from(cores)));
            if !cache_sizes.is_empty() {
                result.insert("cache".into(), serde_json::Value::String(cache_sizes.join(", ")));
            }
        }
    }

    // Registry: CPU name
    if let Ok(name) = reg_read_string(
        ctx,
        HKEY_LOCAL_MACHINE,
        r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
        "ProcessorNameString",
    ) {
        result.insert("name".into(), serde_json::Value::String(name.trim().into()));
    }

    // CPU load via GetSystemTimes (two calls with sleep)
    let mut idle1: FILETIME = mem::zeroed();
    let mut kernel1: FILETIME = mem::zeroed();
    let mut user1: FILETIME = mem::zeroed();
    let mut idle2: FILETIME = mem::zeroed();
    let mut kernel2: FILETIME = mem::zeroed();
    let mut user2: FILETIME = mem::zeroed();

    if GetSystemTimes(Some(&mut idle1), Some(&mut kernel1), Some(&mut user1)).is_ok() {
        thread::sleep(Duration::from_millis(100));
        if GetSystemTimes(Some(&mut idle2), Some(&mut kernel2), Some(&mut user2)).is_ok() {
            let idle_diff = (idle2.dwLowDateTime as u64 | ((idle2.dwHighDateTime as u64) << 32))
                .wrapping_sub(idle1.dwLowDateTime as u64 | ((idle1.dwHighDateTime as u64) << 32));
            let kernel_diff = (kernel2.dwLowDateTime as u64 | ((kernel2.dwHighDateTime as u64) << 32))
                .wrapping_sub(kernel1.dwLowDateTime as u64 | ((kernel1.dwHighDateTime as u64) << 32));
            let user_diff = (user2.dwLowDateTime as u64 | ((user2.dwHighDateTime as u64) << 32))
                .wrapping_sub(user1.dwLowDateTime as u64 | ((user1.dwHighDateTime as u64) << 32));
            let total = kernel_diff + user_diff;
            if total > 0 {
                let load = (total - idle_diff) as f64 / total as f64 * 100.0;
                result.insert("load_percent".into(), serde_json::Value::Number(
                    serde_json::Number::from_f64((load * 10.0).round() / 10.0).unwrap_or_else(|| serde_json::Number::from(0))
                ));
            }
        }
    }

    let output = serde_json::to_string_pretty(&result)?;
    audit::log_success("sysinfo", "cpu_info", &output);
    Ok(output)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Action: memory_info
// ═══════════════════════════════════════════════════════════════════════════════

unsafe fn action_memory_info(ctx: &ErrorContext) -> std::result::Result<String, AetherError> {
    let mut mem_ex: MEMORYSTATUSEX = mem::zeroed();
    mem_ex.dwLength = mem::size_of::<MEMORYSTATUSEX>() as u32;

    GlobalMemoryStatusEx(&mut mem_ex)
        .map_err(|e| AetherError::win32(ctx.clone(), "GlobalMemoryStatusEx", e))?;

    let result = serde_json::json!({
        "total_physical": mem_ex.ullTotalPhys,
        "available_physical": mem_ex.ullAvailPhys,
        "total_pagefile": mem_ex.ullTotalPageFile,
        "available_pagefile": mem_ex.ullAvailPageFile,
        "total_virtual": mem_ex.ullTotalVirtual,
        "available_virtual": mem_ex.ullAvailVirtual,
        "memory_load_percent": mem_ex.dwMemoryLoad,
    });

    let output = serde_json::to_string_pretty(&result)?;
    audit::log_success("sysinfo", "memory_info", &output);
    Ok(output)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Action: disk_info
// ═══════════════════════════════════════════════════════════════════════════════

unsafe fn action_disk_info(_ctx: &ErrorContext) -> std::result::Result<String, AetherError> {
    let drives_mask = GetLogicalDrives();
    let mut volumes = Vec::new();
    let mut physical_disks = Vec::new();

    for drive_letter in 0u8..26u8 {
        if (drives_mask & (1u32 << drive_letter)) == 0 {
            continue;
        }

        let root_path = format!("{}:\\", (b'A' + drive_letter) as char);
        let root_wide = to_wide(&root_path);
        let drive_type = GetDriveTypeW(PCWSTR::from_raw(root_wide.as_ptr()));

        let type_str = match drive_type {
            0 => "Unknown",
            1 => "No Root Dir",
            2 => "Removable",
            3 => "Fixed",
            4 => "Remote",
            5 => "CD-ROM",
            6 => "RAM Disk",
            _ => "Unknown",
        };

        let mut vol_obj = serde_json::json!({
            "drive": root_path,
            "type": type_str,
        });

        // Get volume info
        let mut vol_name_buf: [u16; 256] = [0u16; 256];
        let mut fs_buf: [u16; 256] = [0u16; 256];
        let mut serial: u32 = 0;
        let mut max_component: u32 = 0;
        let mut fs_flags: u32 = 0;

        if GetVolumeInformationW(
            PCWSTR::from_raw(root_wide.as_ptr()),
            Some(&mut vol_name_buf),
            Some(&mut serial),
            Some(&mut max_component),
            Some(&mut fs_flags),
            Some(&mut fs_buf),
        ).is_ok()
        {
            let label = String::from_utf16_lossy(&vol_name_buf);
            let label = label.trim_end_matches('\0').trim();
            if !label.is_empty() {
                vol_obj["label"] = serde_json::Value::String(label.into());
            }
            let fs = String::from_utf16_lossy(&fs_buf);
            let fs = fs.trim_end_matches('\0').trim();
            if !fs.is_empty() {
                vol_obj["filesystem"] = serde_json::Value::String(fs.into());
            }
            vol_obj["serial"] = serde_json::json!(format!("{:08X}", serial));
        }

        // Get disk free space
        let mut free_available: u64 = 0;
        let mut total_bytes: u64 = 0;
        let mut free_total: u64 = 0;

        if GetDiskFreeSpaceExW(
            PCWSTR::from_raw(root_wide.as_ptr()),
            Some(&mut free_available),
            Some(&mut total_bytes),
            Some(&mut free_total),
        ).is_ok()
        {
            vol_obj["total_bytes"] = serde_json::json!(total_bytes);
            vol_obj["free_bytes"] = serde_json::json!(free_available);
            vol_obj["used_bytes"] = serde_json::json!(total_bytes - free_available);
        }

        volumes.push(vol_obj);
    }

    // Physical disk info via IOCTL
    for disk_idx in 0u32..16u32 {
        let device_path = format!(r"\\.\PhysicalDrive{disk_idx}");
        let device_wide = to_wide(&device_path);

        let handle = match CreateFileW(
            PCWSTR::from_raw(device_wide.as_ptr()),
            FILE_READ_ATTRIBUTES.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE::default(),
        ) {
            Ok(h) if !h.is_invalid() => h,
            _ => break, // No more physical drives
        };

        #[repr(C)]
        struct DiskGeometry {
            pub cylinders: i64,
            pub media_type: u32,
            pub tracks_per_cylinder: u32,
            pub sectors_per_track: u32,
            pub bytes_per_sector: u32,
        }

        let mut geom: DiskGeometry = mem::zeroed();
        let mut bytes_returned: u32 = 0;
        if DeviceIoControl(
            handle,
            IOCTL_DISK_GET_DRIVE_GEOMETRY,
            None,
            0,
            Some(&mut geom as *mut _ as *mut _),
            mem::size_of::<DiskGeometry>() as u32,
            Some(&mut bytes_returned),
            None,
        ).is_ok()
        {
            let disk_size: u64 = (geom.cylinders as u64)
                .saturating_mul(geom.tracks_per_cylinder as u64)
                .saturating_mul(geom.sectors_per_track as u64)
                .saturating_mul(geom.bytes_per_sector as u64);
            let media = match geom.media_type {
                12 => "Fixed",
                11 => "Removable",
                _ => "Unknown",
            };
            physical_disks.push(serde_json::json!({
                "index": disk_idx,
                "size_bytes": disk_size,
                "media_type": media,
                "sectors_per_track": geom.sectors_per_track,
                "bytes_per_sector": geom.bytes_per_sector,
            }));
        }
        let _ = CloseHandle(handle);
    }

    let result = serde_json::json!({
        "volumes": volumes,
        "physical_disks": physical_disks,
    });

    let output = serde_json::to_string_pretty(&result)?;
    audit::log_success("sysinfo", "disk_info", &output);
    Ok(output)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Action: os_info
// ═══════════════════════════════════════════════════════════════════════════════

unsafe fn action_os_info(ctx: &ErrorContext) -> std::result::Result<String, AetherError> {
    let mut result = serde_json::Map::new();

    // RtlGetVersion via dynamic load from ntdll
    #[repr(C)]
    struct OsVersionInfoExW {
        pub dw_os_version_info_size: u32,
        pub dw_major_version: u32,
        pub dw_minor_version: u32,
        pub dw_build_number: u32,
        pub dw_platform_id: u32,
        pub sz_csd_version: [u16; 128],
        pub w_service_pack_major: u16,
        pub w_service_pack_minor: u16,
        pub w_suite_mask: u16,
        pub w_product_type: u8,
        pub w_reserved: u8,
    }

    type RtlGetVersionFn = unsafe extern "system" fn(*mut OsVersionInfoExW) -> i32;
    let ntdll = GetModuleHandleW(w!("ntdll.dll"))
        .map_err(|e| AetherError::win32(ctx.clone(), "GetModuleHandleW", e))?;
    let proc_addr = GetProcAddress(ntdll, s!("RtlGetVersion"))
        .ok_or_else(|| AetherError::win32(ctx.clone(), "GetProcAddress", "RtlGetVersion not found"))?;
    let rtl_get_version: RtlGetVersionFn = mem::transmute(proc_addr);

    let mut os_vi: OsVersionInfoExW = mem::zeroed();
    os_vi.dw_os_version_info_size = mem::size_of::<OsVersionInfoExW>() as u32;
    let status = rtl_get_version(&mut os_vi);
    if status == 0 {
        result.insert("version".into(), serde_json::Value::String(format!(
            "{}.{}.{}",
            os_vi.dw_major_version, os_vi.dw_minor_version, os_vi.dw_build_number
        )));
        let product_type = match os_vi.w_product_type {
            1 => "Workstation",
            2 => "Domain Controller",
            3 => "Server",
            _ => "Unknown",
        };
        result.insert("product_type".into(), serde_json::Value::String(product_type.into()));
    }

    // Registry: ProductName, EditionID, DisplayVersion, InstallDate, RegisteredOwner
    let nt_current = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    for (reg_name, json_key) in &[
        ("ProductName", "product_name"),
        ("EditionID", "edition_id"),
        ("DisplayVersion", "display_version"),
        ("InstallDate", "install_date"),
        ("RegisteredOwner", "registered_owner"),
    ] {
        if let Ok(val) = reg_read_string(ctx, HKEY_LOCAL_MACHINE, nt_current, reg_name) {
            result.insert(json_key.to_string(), serde_json::Value::String(val.trim().into()));
        }
    }

    // BuildLab
    if let Ok(val) = reg_read_string(ctx, HKEY_LOCAL_MACHINE, nt_current, "BuildLab") {
        result.insert("build_lab".into(), serde_json::Value::String(val.trim().into()));
    }

    let output = serde_json::to_string_pretty(&result)?;
    audit::log_success("sysinfo", "os_info", &output);
    Ok(output)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Action: uptime
// ═══════════════════════════════════════════════════════════════════════════════

fn action_uptime() -> std::result::Result<String, AetherError> {
    let ticks = unsafe { GetTickCount64() };
    let total_seconds = ticks / 1000;
    let days = total_seconds / 86400;
    let hours = (total_seconds % 86400) / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;

    let result = serde_json::json!({
        "uptime_ms": ticks,
        "days": days,
        "hours": hours,
        "minutes": minutes,
        "seconds": seconds,
        "display": format!("{days}d {hours}h {minutes}m {seconds}s"),
    });

    let output = serde_json::to_string_pretty(&result)?;
    audit::log_success("sysinfo", "uptime", &output);
    Ok(output)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Action: env_vars
// ═══════════════════════════════════════════════════════════════════════════════

unsafe fn action_env_vars(ctx: &ErrorContext, params: &serde_json::Value) -> std::result::Result<String, AetherError> {
    let sub_action = params.get("action").and_then(|v| v.as_str()).unwrap_or("list");

    match sub_action {
        "list" => {
            let mut result = serde_json::Map::new();
            let mut user_map = serde_json::Map::new();
            for (k, v) in std::env::vars() {
                user_map.insert(k, serde_json::Value::String(v));
            }
            result.insert("user".into(), serde_json::Value::Object(user_map));

            // Machine env from registry
            let machine_key =
                r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";
            if let Ok(machine_val) =
                reg_read_all_values_to_json(HKEY_LOCAL_MACHINE, machine_key)
            {
                result.insert("machine".into(), machine_val);
            }

            let output = serde_json::to_string_pretty(&result)?;
            audit::log_success("sysinfo", "env_vars/list", &output);
            Ok(output)
        }
        "get" => {
            let name = params
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AetherError::invalid_param(ctx.clone(), "name is required for env get"))?;
            match std::env::var(name) {
                Ok(val) => {
                    let result = serde_json::json!({ "name": name, "value": val });
                    Ok(serde_json::to_string_pretty(&result)?)
                }
                Err(_) => Err(AetherError::not_found(ctx.clone(), format!("Environment variable '{name}' not found"), None)),
            }
        }
        "set" => {
            let name = params
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AetherError::invalid_param(ctx.clone(), "name is required for env set"))?;
            let value = params
                .get("value")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AetherError::invalid_param(ctx.clone(), "value is required for env set"))?;
            std::env::set_var(name, value);
            audit::log_forced("sysinfo", "env_vars/set");
            let result = serde_json::json!({ "name": name, "value": value, "status": "set" });
            Ok(serde_json::to_string_pretty(&result)?)
        }
        _ => Err(AetherError::invalid_param(ctx.clone(), format!(
            "Unknown env action: {sub_action}. Use list, get, or set."
        ))),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Action: power_plans
// ═══════════════════════════════════════════════════════════════════════════════

unsafe fn action_power_plans(ctx: &ErrorContext) -> std::result::Result<String, AetherError> {
    let mut plans = Vec::new();

    // Try PowerEnumerate
    let mut buf_size: u32 = 0;

    let idx_result = PowerEnumerate(
        HKEY::default(),
        None,
        None,
        POWER_DATA_ACCESSOR(16), // ACCESS_SCHEME = 16
        0,
        None,
        &mut buf_size,
    );

    // If PowerEnumerate doesn't work, fallback to powercfg
    if idx_result.is_err() || buf_size == 0 {
        return action_power_plans_fallback(ctx);
    }

    // Enumerate schemes
    for idx in 0u32.. {
        buf_size = 0;
        let status = PowerEnumerate(
            HKEY::default(),
            None,
            None,
            POWER_DATA_ACCESSOR(16),
            idx,
            None,
            &mut buf_size,
        );
        if status.is_err() || buf_size == 0 {
            break;
        }

        let mut guid_buf: Vec<u16> = vec![0u16; buf_size as usize + 1];
        let status = PowerEnumerate(
            HKEY::default(),
            None,
            None,
            POWER_DATA_ACCESSOR(16),
            idx,
            Some(guid_buf.as_mut_ptr() as *mut u8),
            &mut buf_size,
        );
        if status.is_err() {
            break;
        }

        let guid_str = String::from_utf16_lossy(&guid_buf[..buf_size as usize])
            .trim_matches('\0')
            .to_string();

        let name = power_read_scheme_name(ctx, &guid_str).unwrap_or_else(|| guid_str.clone());
        plans.push((name, guid_str));
    }

    // Get active scheme
    let mut active_guid_ptr: *mut windows::core::GUID = ptr::null_mut();
    let mut active_guid_str = String::new();
    if PowerGetActiveScheme(HKEY::default(), &mut active_guid_ptr).is_ok()
        && !active_guid_ptr.is_null()
    {
        let guid_buf: &[u16] = std::slice::from_raw_parts(active_guid_ptr as *const u16, 39);
        active_guid_str = String::from_utf16_lossy(guid_buf);
        LocalFree(HLOCAL(active_guid_ptr as *mut std::ffi::c_void));
    }

    let json_plans: Vec<serde_json::Value> = plans
        .into_iter()
        .map(|(name, guid)| {
            serde_json::json!({
                "name": name,
                "guid": guid,
                "is_active": guid == active_guid_str,
            })
        })
        .collect();

    let result = serde_json::json!({ "power_plans": json_plans });
    let output = serde_json::to_string_pretty(&result)?;
    audit::log_success("sysinfo", "power_plans", &output);
    Ok(output)
}

unsafe fn power_read_scheme_name(ctx: &ErrorContext, guid: &str) -> Option<String> {
    let subkey = format!(
        r"SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\{guid}"
    );
    reg_read_string(ctx, HKEY_LOCAL_MACHINE, &subkey, "FriendlyName").ok()
}

fn action_power_plans_fallback(ctx: &ErrorContext) -> std::result::Result<String, AetherError> {
    let _ = ctx;
    let stdout = SafeCommand::new("powercfg", "sysinfo", "power_plans_fallback")
        .timeout(15)
        .arg_unchecked("/list")
        .output()?;
    let mut plans = Vec::new();
    let mut current_name = String::new();
    let mut current_guid = String::new();
    let mut is_active = false;

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.contains('*') {
            is_active = true;
        }
        if trimmed.contains(':')
            && !trimmed.starts_with("Existing")
            && !trimmed.starts_with("Power")
        {
            if !current_name.is_empty() && !current_guid.is_empty() {
                plans.push(serde_json::json!({
                    "name": current_name.trim(),
                    "guid": current_guid.trim(),
                    "is_active": is_active,
                }));
            }
            let parts: Vec<&str> = trimmed.splitn(2, ':').collect();
            let name_part = parts.first().map(|s| s.trim().trim_start_matches('*').trim()).unwrap_or("");
            let guid_part = parts.get(1).map(|s| s.trim()).unwrap_or("");
            current_name = if let Some(open) = name_part.find('(') {
                name_part[..open].trim().to_string()
            } else {
                name_part.to_string()
            };
            current_guid = if let (Some(start), Some(end)) = (guid_part.find('('), guid_part.find(')')) {
                guid_part[start + 1..end].to_string()
            } else {
                guid_part.to_string()
            };
            is_active = trimmed.starts_with('*');
        }
    }
    if !current_name.is_empty() && !current_guid.is_empty() {
        plans.push(serde_json::json!({
            "name": current_name,
            "guid": current_guid,
            "is_active": is_active,
        }));
    }

    let result = serde_json::json!({ "power_plans": plans });
    Ok(serde_json::to_string_pretty(&result)?)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Action: power_set_plan
// ═══════════════════════════════════════════════════════════════════════════════

unsafe fn action_power_set_plan(ctx: &ErrorContext, params: &serde_json::Value) -> std::result::Result<String, AetherError> {
    let force = params.get("force").and_then(|v| v.as_bool()).unwrap_or(false);
    if !force {
        return Err(AetherError::invalid_param(
            ctx.clone(),
            "power_set_plan requires force: true for safety",
        ));
    }

    let guid_str = params
        .get("guid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AetherError::invalid_param(ctx.clone(), "guid is required for power_set_plan"))?;

    let guid_wide = to_wide(guid_str);
    let result = PowerSetActiveScheme(HKEY::default(), Some(&guid_wide as *const _ as *const windows::core::GUID));
    if result != WIN32_ERROR(0) {
        return Err(AetherError::win32(ctx.clone(), "PowerSetActiveScheme", format!("{result:?}")));
    }

    audit::log_forced("sysinfo", "power_set_plan");

    let result = serde_json::json!({
        "status": "success",
        "active_guid": guid_str,
    });
    Ok(serde_json::to_string_pretty(&result)?)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Action: power_query
// ═══════════════════════════════════════════════════════════════════════════════

unsafe fn action_power_query(ctx: &ErrorContext) -> std::result::Result<String, AetherError> {
    let mut result = serde_json::Map::new();

    let power_policy_key =
        r"SYSTEM\CurrentControlSet\Control\Power\PowerSettings";

    let sub_groups = [
        ("238C9FA8-0AAD-41ED-83F4-97BE242C8F20", "sleep_timeout_ac_hibernate"),
        ("29F6C1DB-86DA-48C5-9FDB-F2B67B1F44DA", "sleep_timeout_ac"),
        ("0012EE47-9041-4B5D-9B77-535FBA8B1442", "dim_display_ac"),
        ("3C0BC021-C8A8-4E07-A973-6B14CBCB2B7E", "turn_off_display_ac"),
        ("6738E2C4-E8A5-4A42-B16A-E040E769756E", "turn_off_disk_ac"),
    ];

    for (guid, label) in &sub_groups {
        let subkey = format!("{power_policy_key}\\{guid}");
        if let Ok(default_key) = reg_read_string(ctx, HKEY_LOCAL_MACHINE, &format!("{subkey}\\DefaultPowerSchemeValues"), "AcSettingIndex") {
            let num: u32 = default_key.trim().parse().unwrap_or(0);
            let display = if *guid == "238C9FA8-0AAD-41ED-83F4-97BE242C8F20" {
                format!("{} seconds", num)
            } else {
                format!("{} seconds ({} min)", num, num / 60)
            };
            result.insert(label.to_string(), serde_json::json!({ "value": num, "display": display }));
        }
    }

    if result.is_empty() {
        let stdout = SafeCommand::new("powercfg", "sysinfo", "power_query")
            .timeout(15)
            .arg_unchecked("/query")
            .output()?;
        result.insert("raw".into(), serde_json::Value::String(stdout));
    }

    let output = serde_json::to_string_pretty(&result)?;
    audit::log_success("sysinfo", "power_query", &output);
    Ok(output)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Action: battery
// ═══════════════════════════════════════════════════════════════════════════════

unsafe fn action_battery(ctx: &ErrorContext) -> std::result::Result<String, AetherError> {
    let mut sps: SYSTEM_POWER_STATUS = mem::zeroed();
    GetSystemPowerStatus(&mut sps)
        .map_err(|e| AetherError::win32(ctx.clone(), "GetSystemPowerStatus", e))?;

    let ac_line = match sps.ACLineStatus {
        0 => "Offline",
        1 => "Online",
        255 => "Unknown",
        _ => "Unknown",
    };

    let battery_flag = sps.BatteryFlag;
    let flag_str = if battery_flag & 1 != 0 {
        "High"
    } else if battery_flag & 2 != 0 {
        "Low"
    } else if battery_flag & 4 != 0 {
        "Critical"
    } else if battery_flag & 8 != 0 {
        "Charging"
    } else if battery_flag & 128 != 0 {
        "No Battery"
    } else {
        "Unknown"
    };

    let percent = sps.BatteryLifePercent;
    let percent_str = if percent == 255 {
        "Unknown".to_string()
    } else {
        format!("{percent}%")
    };

    let life_time = if sps.BatteryLifeTime == u32::MAX {
        serde_json::Value::Null
    } else {
        serde_json::Value::Number(serde_json::Number::from(sps.BatteryLifeTime))
    };

    let full_life = if sps.BatteryFullLifeTime == u32::MAX {
        serde_json::Value::Null
    } else {
        serde_json::Value::Number(serde_json::Number::from(sps.BatteryFullLifeTime))
    };

    let result = serde_json::json!({
        "ac_line_status": ac_line,
        "battery_flag": flag_str,
        "battery_life_percent": percent_str,
        "battery_life_time_seconds": life_time,
        "battery_full_life_time_seconds": full_life,
        "system_status_flag": sps.SystemStatusFlag,
    });

    let output = serde_json::to_string_pretty(&result)?;
    audit::log_success("sysinfo", "battery", &output);
    Ok(output)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Action: device_list
// ═══════════════════════════════════════════════════════════════════════════════

unsafe fn action_device_list(ctx: &ErrorContext) -> std::result::Result<String, AetherError> {
    let class_guid = windows::core::GUID::zeroed();
    let dev_info = match SetupDiGetClassDevsW(
        Some(&class_guid),
        None,
        HWND::default(),
        DIGCF_ALLCLASSES,
    ) {
        Ok(h) if !h.is_invalid() => h,
        _ => return Err(AetherError::win32(ctx.clone(), "SetupDiGetClassDevsW", "failed")),
    };

    let mut devices = Vec::new();
    let mut dev_data: SP_DEVINFO_DATA = mem::zeroed();
    dev_data.cbSize = mem::size_of::<SP_DEVINFO_DATA>() as u32;

    for idx in 0u32.. {
        if SetupDiEnumDeviceInfo(dev_info, idx, &mut dev_data).is_err() {
            break;
        }

        let mut friendly_buf: [u16; 256] = [0u16; 256];
        let friendly_buf_u8: &mut [u8] = std::slice::from_raw_parts_mut(
            friendly_buf.as_mut_ptr() as *mut u8,
            friendly_buf.len() * 2,
        );
        let friendly_name = if SetupDiGetDeviceRegistryPropertyW(
            dev_info,
            &dev_data,
            SPDRP_FRIENDLYNAME,
            None,
            Some(friendly_buf_u8),
            None,
        ).is_ok()
        {
            String::from_utf16_lossy(&friendly_buf)
                .trim_matches('\0')
                .to_string()
        } else {
            String::new()
        };

        let mut desc_buf: [u16; 256] = [0u16; 256];
        let desc_buf_u8: &mut [u8] = std::slice::from_raw_parts_mut(
            desc_buf.as_mut_ptr() as *mut u8,
            desc_buf.len() * 2,
        );
        let description = if SetupDiGetDeviceRegistryPropertyW(
            dev_info,
            &dev_data,
            SPDRP_DEVICEDESC,
            None,
            Some(desc_buf_u8),
            None,
        ).is_ok()
        {
            String::from_utf16_lossy(&desc_buf)
                .trim_matches('\0')
                .to_string()
        } else {
            String::new()
        };

        let mut hw_id_buf: [u16; 512] = [0u16; 512];
        let hw_id_buf_u8: &mut [u8] = std::slice::from_raw_parts_mut(
            hw_id_buf.as_mut_ptr() as *mut u8,
            hw_id_buf.len() * 2,
        );
        let hardware_ids = if SetupDiGetDeviceRegistryPropertyW(
            dev_info,
            &dev_data,
            SPDRP_HARDWAREID,
            None,
            Some(hw_id_buf_u8),
            None,
        ).is_ok()
        {
            let ids: Vec<String> = hw_id_buf
                .split(|&c| c == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf16_lossy(s))
                .collect();
            serde_json::Value::Array(ids.into_iter().map(serde_json::Value::String).collect())
        } else {
            serde_json::Value::Null
        };

        let name = if !friendly_name.is_empty() {
            friendly_name
        } else {
            description.clone()
        };

        if name.is_empty() {
            continue;
        }

        devices.push(serde_json::json!({
            "name": name,
            "description": description,
            "hardware_ids": hardware_ids,
            "index": idx,
        }));
    }

    let _ = SetupDiDestroyDeviceInfoList(dev_info);

    let result = serde_json::json!({ "devices": devices, "count": devices.len() });
    let output = serde_json::to_string_pretty(&result)?;
    audit::log_success("sysinfo", "device_list", &output);
    Ok(output)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Action: driver_list
// ═══════════════════════════════════════════════════════════════════════════════

fn action_driver_list(ctx: &ErrorContext) -> Result<String, AetherError> {
    let _ = ctx;
    // Use sc query to list drivers (avoids complex EnumServicesStatusExW API)
    let stdout = SafeCommand::new("sc", "sysinfo", "driver_list")
        .timeout(15)
        .arg_unchecked("query")
        .arg("type=", ParamType::SafeString)?
        .arg_unchecked("driver")
        .output()?;
    let mut drivers = Vec::new();
    let mut current: Option<serde_json::Map<String, serde_json::Value>> = None;

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("SERVICE_NAME:") {
            if let Some(entry) = current.take() {
                drivers.push(serde_json::Value::Object(entry));
            }
            current = Some(serde_json::Map::new());
            let name = trimmed.trim_start_matches("SERVICE_NAME:").trim().to_string();
            if let Some(ref mut cur) = current {
                cur.insert("name".into(), serde_json::Value::String(name));
            }
        } else if trimmed.starts_with("DISPLAY_NAME:") {
            let val = trimmed.trim_start_matches("DISPLAY_NAME:").trim().to_string();
            if let Some(ref mut cur) = current {
                cur.insert("display_name".into(), serde_json::Value::String(val));
            }
        } else if trimmed.starts_with("STATE") && trimmed.contains(':') {
            let val = trimmed.splitn(2, ':').nth(1).map(|s| s.trim().to_string()).unwrap_or_default();
            if let Some(ref mut cur) = current {
                cur.insert("status".into(), serde_json::Value::String(val));
            }
        } else if trimmed.starts_with("TYPE") && trimmed.contains(':') {
            let val = trimmed.splitn(2, ':').nth(1).map(|s| s.trim().to_string()).unwrap_or_default();
            if let Some(ref mut cur) = current {
                cur.insert("startup_type".into(), serde_json::Value::String(val));
            }
        }
    }
    if let Some(entry) = current.take() {
        drivers.push(serde_json::Value::Object(entry));
    }

    let result = serde_json::json!({ "drivers": drivers, "count": drivers.len() });
    let output = serde_json::to_string_pretty(&result)?;
    audit::log_success("sysinfo", "driver_list", &output);
    Ok(output)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Action: bios_info
// ═══════════════════════════════════════════════════════════════════════════════

unsafe fn action_bios_info(ctx: &ErrorContext) -> std::result::Result<String, AetherError> {
    let bios_key = r"HARDWARE\DESCRIPTION\System\BIOS";
    let mut result = serde_json::Map::new();

    let fields = [
        ("SystemManufacturer", "vendor"),
        ("SystemProductName", "product"),
        ("SystemVersion", "version"),
        ("BIOSVendor", "bios_vendor"),
        ("BIOSVersion", "bios_version"),
        ("BIOSReleaseDate", "release_date"),
        ("SystemSerialNumber", "serial_number"),
        ("BaseBoardManufacturer", "baseboard_manufacturer"),
        ("BaseBoardProduct", "baseboard_product"),
        ("BaseBoardVersion", "baseboard_version"),
    ];

    for (reg_name, json_key) in &fields {
        if let Ok(val) = reg_read_string(ctx, HKEY_LOCAL_MACHINE, bios_key, reg_name) {
            result.insert(json_key.to_string(), serde_json::Value::String(val.trim().into()));
        }
    }

    let output = serde_json::to_string_pretty(&result)?;
    audit::log_success("sysinfo", "bios_info", &output);
    Ok(output)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Action: time_get
// ═══════════════════════════════════════════════════════════════════════════════

fn action_time_get() -> std::result::Result<String, AetherError> {
    let now = std::time::SystemTime::now();
    let since_epoch = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = since_epoch.as_secs();
    let millis = since_epoch.subsec_millis();

    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hour = time_of_day / 3600;
    let minute = (time_of_day % 3600) / 60;
    let second = time_of_day % 60;

    let mut y = 1970i64;
    let mut remaining = days as i64;
    loop {
        let days_in_year = if is_leap(y) { 366 } else { 365 };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        y += 1;
    }
    let month_days = if is_leap(y) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut m = 1u32;
    for (i, &md) in month_days.iter().enumerate() {
        if remaining < md as i64 {
            m = i as u32 + 1;
            break;
        }
        remaining -= md as i64;
    }

    let day_of_week = ((days + 4) % 7) as u32;

    let tz_info = unsafe {
        let mut tz: TIME_ZONE_INFORMATION = mem::zeroed();
        let tz_id = GetTimeZoneInformation(&mut tz);
        match tz_id {
            0xFFFFFFFF => "Unknown".to_string(),
            1 => {
                let name = String::from_utf16_lossy(&tz.StandardName);
                format!("{} (UTC{:+})", name.trim_matches('\0'), -(tz.Bias as i32) / 60)
            }
            2 => {
                let name = String::from_utf16_lossy(&tz.DaylightName);
                format!("{} (UTC{:+})", name.trim_matches('\0'), -(tz.Bias as i32 + tz.DaylightBias as i32) / 60)
            }
            _ => format!("UTC{:+}", -(tz.Bias as i32) / 60),
        }
    };

    let result = serde_json::json!({
        "year": y,
        "month": m,
        "day": remaining + 1,
        "hour": hour,
        "minute": minute,
        "second": second,
        "milliseconds": millis,
        "day_of_week": day_of_week,
        "timezone": tz_info,
    });

    let output = serde_json::to_string_pretty(&result)?;
    audit::log_success("sysinfo", "time_get", &output);
    Ok(output)
}

fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

// ═══════════════════════════════════════════════════════════════════════════════
// Action: time_set
// ═══════════════════════════════════════════════════════════════════════════════

fn action_time_set(ctx: &ErrorContext, params: &serde_json::Value) -> std::result::Result<String, AetherError> {
    let force = params.get("force").and_then(|v| v.as_bool()).unwrap_or(false);
    if !force {
        return Err(AetherError::invalid_param(
            ctx.clone(),
            "time_set requires force: true for safety",
        ));
    }

    let year = params.get("year").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
    let month = params.get("month").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
    let day = params.get("day").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
    let hour = params.get("hour").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
    let minute = params.get("minute").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
    let second = params.get("second").and_then(|v| v.as_u64()).unwrap_or(0) as u16;

    if year < 2020 || month < 1 || month > 12 || day < 1 || day > 31 {
        return Err(AetherError::invalid_param(ctx.clone(), "Invalid date/time values"));
    }

    // Use PowerShell as fallback (SetLocalTime requires SE_SYSTEMTIME_NAME privilege)
    audit::log_forced("sysinfo", "time_set");

    let cmd = format!(
        "Set-Date -Year {year} -Month {month} -Day {day} -Hour {hour} -Minute {minute} -Second {second}"
    );
    let _ = SafeCommand::new("powershell", "sysinfo", "time_set")
        .timeout(30)
        .arg_unchecked("-NoProfile")
        .arg_unchecked("-Command")
        .arg(&cmd, ParamType::Text)?.run().map_err(|e| AetherError::win32(ctx.clone(), "Set-Date", e.to_string()))?;

    let result = serde_json::json!({
        "status": "success",
        "time": format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}"),
    });
    Ok(serde_json::to_string_pretty(&result)?)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Action: ntp_sync
// ═══════════════════════════════════════════════════════════════════════════════

fn action_ntp_sync(ctx: &ErrorContext) -> std::result::Result<String, AetherError> {
    let _ = ctx;
    let output = SafeCommand::new("w32tm", "sysinfo", "ntp_sync")
        .timeout(30)
        .arg_unchecked("/resync")
        .output()?;

    let stdout = output.trim();

    let result = serde_json::json!({
        "status": "initiated",
        "output": stdout,
    });

    audit::log_success("sysinfo", "ntp_sync", "w32tm /resync completed");
    Ok(serde_json::to_string_pretty(&result)?)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Action: installed_software
// ═══════════════════════════════════════════════════════════════════════════════

unsafe fn action_installed_software(ctx: &ErrorContext) -> std::result::Result<String, AetherError> {
    let mut software = Vec::new();

    let uninstall_paths = [
        (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ];

    let fields = [
        ("DisplayName", "name"),
        ("DisplayVersion", "version"),
        ("Publisher", "publisher"),
        ("InstallDate", "install_date"),
        ("UninstallString", "uninstall_string"),
        ("InstallLocation", "install_location"),
        ("DisplayIcon", "display_icon"),
    ];

    let mut seen = std::collections::HashSet::new();

    for (hkey, base_path) in &uninstall_paths {
        let subkeys = reg_enum_subkeys(*hkey, base_path).unwrap_or_default();
        for sk in &subkeys {
            let full_path = format!("{base_path}\\{sk}");
            let mut entry = serde_json::Map::new();

            for (reg_name, json_key) in &fields {
                if let Ok(val) = reg_read_string(ctx, *hkey, &full_path, reg_name) {
                    let val = val.trim().to_string();
                    if !val.is_empty() {
                        entry.insert(json_key.to_string(), serde_json::Value::String(val));
                    }
                }
            }

            if let Some(name) = entry.get("name").and_then(|v| v.as_str()) {
                if seen.insert(name.to_lowercase()) {
                    software.push(serde_json::Value::Object(entry));
                }
            }
        }
    }

    software.sort_by(|a, b| {
        let a_name = a.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let b_name = b.get("name").and_then(|v| v.as_str()).unwrap_or("");
        a_name.to_lowercase().cmp(&b_name.to_lowercase())
    });

    let result = serde_json::json!({
        "installed_software": software,
        "count": software.len(),
    });
    let output = serde_json::to_string_pretty(&result)?;
    audit::log_success("sysinfo", "installed_software", &output);
    Ok(output)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Action: windows_update
// ═══════════════════════════════════════════════════════════════════════════════

unsafe fn action_windows_update() -> std::result::Result<String, AetherError> {
    let mut result = serde_json::Map::new();

    let wu_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate";
    let ctx = ErrorContext::new("system_info", "windows_update");
    if let Ok(settings) = reg_read_all_values_to_json(HKEY_LOCAL_MACHINE, wu_key) {
        result.insert("settings".into(), settings);
    }
    let _ = ctx; // suppress unused warning

    let qfe = SafeCommand::new("wmic", "sysinfo", "windows_update")
        .timeout(30)
        .arg("qfe", ParamType::Name)?
        .arg_unchecked("get")
        .arg("HotFixID,InstalledOn,Description", ParamType::SafeString)?
        .arg_unchecked("/format:csv")
        .output();

    match qfe {
        Ok(stdout) => {
            let mut updates = Vec::new();
            for line in stdout.lines().skip(2) {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let parts: Vec<&str> = trimmed.split(',').collect();
                if parts.len() >= 3 {
                    updates.push(serde_json::json!({
                        "hotfix_id": parts.get(1).map(|s| s.trim()).unwrap_or(""),
                        "installed_on": parts.get(2).map(|s| s.trim()).unwrap_or(""),
                        "description": parts.get(3).map(|s| s.trim()).unwrap_or(""),
                    }));
                }
            }
            result.insert("update_history".into(), serde_json::json!(updates));
        }
        Err(e) => {
            result.insert("update_history".into(), serde_json::Value::String(format!("wmic failed: {e}").into()));
        }
    }

    let output = serde_json::to_string_pretty(&result)?;
    audit::log_success("sysinfo", "windows_update", &output);
    Ok(output)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Action: startup_programs
// ═══════════════════════════════════════════════════════════════════════════════

unsafe fn action_startup_programs() -> std::result::Result<String, AetherError> {
    let mut programs = Vec::new();

    let run_keys = [
        (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        (HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ];

    for (hkey, path) in &run_keys {
        let hkey_label = if *hkey == HKEY_LOCAL_MACHINE {
            if path.contains("WOW6432Node") { "HKLM\\WOW6432Node\\Run" } else { "HKLM\\Run" }
        } else {
            "HKCU\\Run"
        };

        let subkey_wide = to_wide(path);
        let mut key: HKEY = HKEY::default();
        if RegOpenKeyExW(*hkey, PCWSTR::from_raw(subkey_wide.as_ptr()), 0, KEY_READ, &mut key).is_ok()
        {
            let mut name_buf: [u16; 256] = [0u16; 256];
            let mut data_buf: [u8; 2048] = [0u8; 2048];
            for idx in 0u32.. {
                let mut name_len: u32 = name_buf.len() as u32;
                let mut data_type: u32 = 0;
                let mut data_len: u32 = data_buf.len() as u32;
                let status = RegEnumValueW(
                    key,
                    idx,
                    PWSTR::from_raw(name_buf.as_mut_ptr()),
                    &mut name_len,
                    Some(ptr::null()),
                    Some(&mut data_type),
                    Some(data_buf.as_mut_ptr()),
                    Some(&mut data_len),
                );
                if status != WIN32_ERROR(0) {
                    break;
                }
                let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
                let value = if data_type == REG_SZ.0 || data_type == REG_EXPAND_SZ.0 {
                    let len = if data_len >= 2 { (data_len as usize - 2) / 2 } else { 0 };
                    let wide: &[u16] = std::slice::from_raw_parts(data_buf.as_ptr() as *const u16, len);
                    String::from_utf16_lossy(wide)
                } else {
                    format!("(type={data_type})")
                };
                programs.push(serde_json::json!({
                    "source": hkey_label,
                    "name": name,
                    "command": value,
                }));
            }
            let _ = RegCloseKey(key);
        }
    }

    // Startup folder
    if let Ok(appdata) = std::env::var("APPDATA") {
        let startup_dir = format!(
            r"{appdata}\Microsoft\Windows\Start Menu\Programs\Startup"
        );
        if let Ok(entries) = std::fs::read_dir(&startup_dir) {
            for entry in entries.flatten() {
                programs.push(serde_json::json!({
                    "source": "Startup Folder",
                    "name": entry.file_name().to_string_lossy(),
                    "command": entry.path().to_string_lossy(),
                }));
            }
        }
    }

    if let Ok(program_data) = std::env::var("ProgramData") {
        let common_startup = format!(
            r"{program_data}\Microsoft\Windows\Start Menu\Programs\Startup"
        );
        if let Ok(entries) = std::fs::read_dir(&common_startup) {
            for entry in entries.flatten() {
                programs.push(serde_json::json!({
                    "source": "Common Startup Folder",
                    "name": entry.file_name().to_string_lossy(),
                    "command": entry.path().to_string_lossy(),
                }));
            }
        }
    }

    let result = serde_json::json!({
        "startup_programs": programs,
        "count": programs.len(),
    });
    let output = serde_json::to_string_pretty(&result)?;
    audit::log_success("sysinfo", "startup_programs", &output);
    Ok(output)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Action: restore_points
// ═══════════════════════════════════════════════════════════════════════════════

fn action_restore_points(ctx: &ErrorContext, params: &serde_json::Value) -> std::result::Result<String, AetherError> {
    let action = params.get("action").and_then(|v| v.as_str()).unwrap_or("list");

    match action {
        "list" => {
            let stdout = SafeCommand::new("powershell", "sysinfo", "restore_points_list")
                .timeout(30)
                .arg_unchecked("-NoProfile")
                .arg_unchecked("-Command")
                .arg("Get-ComputerRestorePoint | Select-Object SequenceNumber,Description,CreationTime,RestorePointType | ConvertTo-Json", ParamType::Text)?
                .output()?;

            if stdout.trim().is_empty() || stdout.contains("Error") {
                let vss_out = SafeCommand::new("vssadmin", "sysinfo", "restore_points_fallback")
                    .timeout(15)
                    .arg_unchecked("list")
                    .arg("shadows", ParamType::Name)?
                    .output()?;
                return Ok(serde_json::json!({
                    "restore_points": vss_out.trim(),
                    "method": "vssadmin",
                }).to_string());
            }

            let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or(
                serde_json::Value::String(stdout.into_owned()),
            );
            let result = serde_json::json!({
                "restore_points": parsed,
                "method": "powershell",
            });
            Ok(serde_json::to_string_pretty(&result)?)
        }
        "create" => {
            let force = params.get("force").and_then(|v| v.as_bool()).unwrap_or(false);
            if !force {
                return Err(AetherError::invalid_param(
                    ctx.clone(),
                    "restore_points create requires force: true for safety",
                ));
            }
            let description = params
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("AETHER_01 Restore Point");

            let cmd = format!("Checkpoint-Computer -Description \"{description}\" -RestorePointType MODIFY_SETTINGS");
            SafeCommand::new("powershell", "sysinfo", "restore_points_create")
                .timeout(120)
                .arg_unchecked("-NoProfile")
                .arg_unchecked("-Command")
                .arg(&cmd, ParamType::Text)?
                .run().map_err(|e| AetherError::win32(ctx.clone(), "Checkpoint-Computer", e.to_string()))?;

            audit::log_forced("sysinfo", "restore_points/create");
            Ok(serde_json::json!({
                "status": "success",
                "description": description,
            })
            .to_string())
        }
        _ => Err(AetherError::invalid_param(ctx.clone(), format!(
            "Unknown restore_points action: {action}. Use list or create."
        ))),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Action: perf_counters
// ═══════════════════════════════════════════════════════════════════════════════

unsafe fn action_perf_counters(ctx: &ErrorContext) -> std::result::Result<String, AetherError> {
    let mut result = serde_json::Map::new();

    let mut idle: FILETIME = mem::zeroed();
    let mut kernel: FILETIME = mem::zeroed();
    let mut user: FILETIME = mem::zeroed();

    if GetSystemTimes(Some(&mut idle), Some(&mut kernel), Some(&mut user)).is_ok() {
        let idle_ticks = idle.dwLowDateTime as u64 | ((idle.dwHighDateTime as u64) << 32);
        let kernel_ticks = kernel.dwLowDateTime as u64 | ((kernel.dwHighDateTime as u64) << 32);
        let user_ticks = user.dwLowDateTime as u64 | ((user.dwHighDateTime as u64) << 32);

        result.insert("cpu_idle_ticks".into(), serde_json::json!(idle_ticks));
        result.insert("cpu_kernel_ticks".into(), serde_json::json!(kernel_ticks));
        result.insert("cpu_user_ticks".into(), serde_json::json!(user_ticks));
    }

    let mut mem_ex: MEMORYSTATUSEX = mem::zeroed();
    mem_ex.dwLength = mem::size_of::<MEMORYSTATUSEX>() as u32;

    if GlobalMemoryStatusEx(&mut mem_ex).is_ok() {
        result.insert("memory_load_percent".into(), serde_json::json!(mem_ex.dwMemoryLoad));
        result.insert("memory_available_bytes".into(), serde_json::json!(mem_ex.ullAvailPhys));
        result.insert("memory_total_bytes".into(), serde_json::json!(mem_ex.ullTotalPhys));
        result.insert(
            "memory_used_bytes".into(),
            serde_json::json!(mem_ex.ullTotalPhys.saturating_sub(mem_ex.ullAvailPhys)),
        );
    }

    let perf_lib = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\009";
    if let Ok(counter_index) = reg_read_string(ctx, HKEY_LOCAL_MACHINE, perf_lib, "Counter") {
        result.insert("available_counters".into(), serde_json::Value::String(counter_index));
    }

    let output = serde_json::to_string_pretty(&result)?;
    audit::log_success("sysinfo", "perf_counters", &output);
    Ok(output)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Action: bcd_list
// ═══════════════════════════════════════════════════════════════════════════════

fn action_bcd_list(server: &AetherServer, ctx: &ErrorContext) -> std::result::Result<String, AetherError> {
    server
        .gates
        .check(ctx.clone(), server.gates.bcd_edit, "AETHER_BCD_EDIT")?;

    let stdout = SafeCommand::new("bcdedit", "sysinfo", "bcd_list")
        .timeout(15)
        .arg_unchecked("/enum")
        .output()?;
    let mut entries = Vec::new();
    let mut current: Option<serde_json::Map<String, serde_json::Value>> = None;

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            if let Some(entry) = current.take() {
                entries.push(serde_json::Value::Object(entry));
            }
            continue;
        }
        if trimmed.starts_with("identifier") || trimmed.starts_with("标识符") {
            if let Some(entry) = current.take() {
                entries.push(serde_json::Value::Object(entry));
            }
            current = Some(serde_json::Map::new());
            let id = trimmed
                .splitn(2, ' ')
                .nth(1)
                .unwrap_or("")
                .trim()
                .to_string();
            if let Some(ref mut cur) = current {
                cur.insert("identifier".into(), serde_json::Value::String(id));
            }
        } else if let Some(ref mut cur) = current {
            if let Some((key, value)) = trimmed.split_once(' ') {
                let key = key.trim().to_lowercase();
                let value = value.trim().to_string();
                cur.insert(key, serde_json::Value::String(value));
            }
        }
    }
    if let Some(entry) = current.take() {
        entries.push(serde_json::Value::Object(entry));
    }

    let result = serde_json::json!({
        "bcd_entries": entries,
        "count": entries.len(),
    });
    let output_str = serde_json::to_string_pretty(&result)?;
    audit::log_success("sysinfo", "bcd_list", &output_str);
    Ok(output_str)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Action: bcd_get_entry / bcd_set_entry
// ═══════════════════════════════════════════════════════════════════════════════

fn action_bcd_get_entry(server: &AetherServer, ctx: &ErrorContext, params: &serde_json::Value) -> std::result::Result<String, AetherError> {
    server
        .gates
        .check(ctx.clone(), server.gates.bcd_edit, "AETHER_BCD_EDIT")?;

    let id = params
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AetherError::invalid_param(ctx.clone(), "id is required for bcd_get_entry"))?;

    let stdout = SafeCommand::new("bcdedit", "sysinfo", "bcd_get_entry")
        .timeout(15)
        .arg_unchecked("/enum")
        .arg(id, ParamType::Guid)?
        .output()?;

    let result = serde_json::json!({
        "id": id,
        "output": stdout.trim(),
    });
    let output_str = serde_json::to_string_pretty(&result)?;
    audit::log_success("sysinfo", "bcd_get_entry", &output_str);
    Ok(output_str)
}

fn action_bcd_set_entry(server: &AetherServer, ctx: &ErrorContext, params: &serde_json::Value) -> std::result::Result<String, AetherError> {
    server
        .gates
        .check(ctx.clone(), server.gates.bcd_edit, "AETHER_BCD_EDIT")?;

    let force = params.get("force").and_then(|v| v.as_bool()).unwrap_or(false);
    if !force {
        return Err(AetherError::invalid_param(
            ctx.clone(),
            "bcd_set_entry requires force: true for safety",
        ));
    }

    let id = params
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AetherError::invalid_param(ctx.clone(), "id is required for bcd_set_entry"))?;
    let key = params
        .get("key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AetherError::invalid_param(ctx.clone(), "key is required for bcd_set_entry"))?;
    let value = params
        .get("value")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AetherError::invalid_param(ctx.clone(), "value is required for bcd_set_entry"))?;

    let stdout = SafeCommand::new("bcdedit", "sysinfo", "bcd_set_entry")
        .timeout(15)
        .arg_unchecked("/set")
        .arg(id, ParamType::Guid)?
        .arg(key, ParamType::Name)?
        .arg(value, ParamType::SafeString)?
        .output()?;

    audit::log_forced("sysinfo", "bcd_set_entry");

    let result = serde_json::json!({
        "status": "success",
        "id": id,
        "key": key,
        "value": value,
        "output": stdout.trim(),
    });
    let output_str = serde_json::to_string_pretty(&result)?;
    audit::log_success("sysinfo", "bcd_set_entry", &output_str);
    Ok(output_str)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Action: crashdump_info / crashdump_configure
// ═══════════════════════════════════════════════════════════════════════════════

fn action_crashdump_info(server: &AetherServer, ctx: &ErrorContext) -> std::result::Result<String, AetherError> {
    server
        .gates
        .check(ctx.clone(), server.gates.hal_config, "AETHER_HAL_CONFIG")?;

    let crash_key = r"SYSTEM\CurrentControlSet\Control\CrashControl";
    let mut result = serde_json::Map::new();

    let fields = [
        ("CrashDumpEnabled", "crash_dump_enabled"),
        ("DumpFile", "dump_file"),
        ("MinidumpDir", "minidump_dir"),
        ("AutoReboot", "auto_reboot"),
        ("Overwrite", "overwrite"),
        ("LogEvent", "log_event"),
        ("DumpFilters", "dump_filters"),
    ];

    for (reg_name, json_key) in &fields {
        unsafe {
            if let Ok(val) = reg_read_string(ctx, HKEY_LOCAL_MACHINE, crash_key, reg_name) {
                let val = val.trim();
                if let Ok(n) = val.parse::<u32>() {
                    let display = match *reg_name {
                        "CrashDumpEnabled" => match n {
                            0 => "None",
                            1 => "Complete memory dump",
                            2 => "Kernel memory dump",
                            3 => "Small memory dump (minidump)",
                            7 => "Automatic memory dump",
                            _ => "Unknown",
                        },
                        "AutoReboot" | "Overwrite" | "LogEvent" => {
                            if n == 1 { "Enabled" } else { "Disabled" }
                        }
                        _ => val,
                    };
                    result.insert(
                        json_key.to_string(),
                        serde_json::json!({ "value": n, "display": display }),
                    );
                } else {
                    result.insert(json_key.to_string(), serde_json::Value::String(val.into()));
                }
            }
        }
    }

    let output = serde_json::to_string_pretty(&result)?;
    audit::log_success("sysinfo", "crashdump_info", &output);
    Ok(output)
}

fn action_crashdump_configure(server: &AetherServer, ctx: &ErrorContext, params: &serde_json::Value) -> std::result::Result<String, AetherError> {
    server
        .gates
        .check(ctx.clone(), server.gates.hal_config, "AETHER_HAL_CONFIG")?;

    let force = params.get("force").and_then(|v| v.as_bool()).unwrap_or(false);
    if !force {
        return Err(AetherError::invalid_param(
            ctx.clone(),
            "crashdump_configure requires force: true for safety",
        ));
    }

    let crash_key = r"SYSTEM\CurrentControlSet\Control\CrashControl";
    let writable_fields = [
        ("CrashDumpEnabled", "crash_dump_enabled"),
        ("DumpFile", "dump_file"),
        ("MinidumpDir", "minidump_dir"),
        ("AutoReboot", "auto_reboot"),
        ("Overwrite", "overwrite"),
        ("LogEvent", "log_event"),
    ];

    let mut changes = Vec::new();

    for (reg_name, param_name) in &writable_fields {
        if let Some(val) = params.get(param_name) {
            let value_str = match val {
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Bool(b) => (if *b { "1" } else { "0" }).to_string(),
                _ => continue,
            };

            unsafe {
                let subkey_wide = to_wide(crash_key);
                let mut key: HKEY = HKEY::default();
                let result = RegOpenKeyExW(
                    HKEY_LOCAL_MACHINE,
                    PCWSTR::from_raw(subkey_wide.as_ptr()),
                    0,
                    KEY_SET_VALUE,
                    &mut key,
                );
                if result != WIN32_ERROR(0) {
                    return Err(AetherError::win32(ctx.clone(), "RegOpenKeyExW", format!("CrashControl: {result:?}")));
                }

                let value_wide = to_wide(reg_name);
                let data_wide = to_wide(&value_str);
                let data_bytes: &[u8] = std::slice::from_raw_parts(
                    data_wide.as_ptr() as *const u8,
                    data_wide.len() * 2,
                );
                let set_result = RegSetValueExW(
                    key,
                    PCWSTR::from_raw(value_wide.as_ptr()),
                    0,
                    REG_SZ,
                    Some(data_bytes),
                );
                if set_result != WIN32_ERROR(0) {
                    let _ = RegCloseKey(key);
                    return Err(AetherError::win32(ctx.clone(), "RegSetValueExW", format!("{reg_name}: {set_result:?}")));
                }
                let _ = RegCloseKey(key);
                changes.push(format!("{reg_name} = {value_str}"));
            }
        }
    }

    audit::log_forced("sysinfo", "crashdump_configure");

    let result = serde_json::json!({
        "status": "success",
        "changes": changes,
    });
    Ok(serde_json::to_string_pretty(&result)?)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Main dispatch: handle_system_info
// ═══════════════════════════════════════════════════════════════════════════════

/// Handle all system information tool actions.
///
/// Supported actions:
/// `cpu_info`, `memory_info`, `disk_info`, `os_info`, `uptime`,
/// `env_vars`, `power_plans`, `power_set_plan`, `power_query`, `battery`,
/// `device_list`, `driver_list`, `bios_info`, `time_get`, `time_set`,
/// `ntp_sync`, `installed_software`, `windows_update`, `startup_programs`,
/// `restore_points`, `perf_counters`, `bcd_list`, `bcd_get_entry`,
/// `bcd_set_entry`, `crashdump_info`, `crashdump_configure`.
pub fn handle_system_info(
    server: &AetherServer,
    action: &str,
    params: serde_json::Value,
) -> std::result::Result<String, AetherError> {
    let action_static: &'static str = Box::leak(action.to_string().into_boxed_str());
    let ctx = ErrorContext::new("system_info", action_static);
    match action {
        "cpu_info" => unsafe { action_cpu_info(&ctx) },
        "memory_info" => unsafe { action_memory_info(&ctx) },
        "disk_info" => unsafe { action_disk_info(&ctx) },
        "os_info" => unsafe { action_os_info(&ctx) },
        "uptime" => action_uptime(),
        "env_vars" => unsafe { action_env_vars(&ctx, &params) },
        "power_plans" => unsafe { action_power_plans(&ctx) },
        "power_set_plan" => unsafe { action_power_set_plan(&ctx, &params) },
        "power_query" => unsafe { action_power_query(&ctx) },
        "battery" => unsafe { action_battery(&ctx) },
        "device_list" => unsafe { action_device_list(&ctx) },
        "driver_list" => action_driver_list(&ctx),
        "bios_info" => unsafe { action_bios_info(&ctx) },
        "time_get" => action_time_get(),
        "time_set" => action_time_set(&ctx, &params),
        "ntp_sync" => action_ntp_sync(&ctx),
        "installed_software" => unsafe { action_installed_software(&ctx) },
        "windows_update" => action_windows_update(),
        "startup_programs" => unsafe { action_startup_programs() },
        "restore_points" => action_restore_points(&ctx, &params),
        "perf_counters" => unsafe { action_perf_counters(&ctx) },
        "bcd_list" => action_bcd_list(server, &ctx),
        "bcd_get_entry" => action_bcd_get_entry(server, &ctx, &params),
        "bcd_set_entry" => action_bcd_set_entry(server, &ctx, &params),
        "crashdump_info" => action_crashdump_info(server, &ctx),
        "crashdump_configure" => action_crashdump_configure(server, &ctx, &params),
        _ => Err(AetherError::invalid_param(ctx.clone(), format!(
            "Unknown sysinfo action: {action}"
        ))),
    }
}
