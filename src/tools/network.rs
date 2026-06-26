#![allow(unsafe_code)]

//! Network management tool for AETHER_01 MCP server.
//!
//! Provides 13 actions: adapters, connections, dns_cache, firewall_rules,
//! firewall_profiles, proxy, routing_table, network_stats, wifi_profiles,
//! vpn_connections, bluetooth_devices, hosts_file, network_shares.
//!
//! Uses Win32 APIs with `std::process::Command` fallbacks.

use crate::audit;
use crate::command::{ParamType, SafeCommand};
use crate::error::{AetherError, ErrorContext};

use serde_json::{json, Value};
use std::mem;
use std::path::Path;
use std::ptr;
use std::slice;

use windows::core::{PCWSTR, PWSTR, w, s};
use windows::Win32::Foundation::*;
use windows::Win32::NetworkManagement::IpHelper::*;
use windows::Win32::NetworkManagement::WiFi::*;
use windows::Win32::Networking::WinSock::*;
use windows::Win32::System::Diagnostics::ToolHelp::*;
use windows::Win32::System::LibraryLoader::*;

// ---------------------------------------------------------------------------
// FFI: Bluetooth device discovery (bthprops.cpl)
// ---------------------------------------------------------------------------

#[link(name = "bthprops")]
extern "system" {
    fn BluetoothFindFirstDevice(
        search_params: *const BLUETOOTH_DEVICE_SEARCH_PARAMS,
        device_info: *mut BLUETOOTH_DEVICE_INFO,
    ) -> isize;

    fn BluetoothFindNextDevice(
        h_find: isize,
        device_info: *mut BLUETOOTH_DEVICE_INFO,
    ) -> BOOL;

    fn BluetoothFindDeviceClose(h_find: isize) -> BOOL;
}

// ---------------------------------------------------------------------------
// FFI: Windows HTTP proxy (winhttp.dll)
// ---------------------------------------------------------------------------

#[link(name = "winhttp")]
extern "system" {
    fn WinHttpGetIEProxyConfigForCurrentUser(
        proxy_config: *mut WINHTTP_CURRENT_USER_IE_PROXY_CONFIG,
    ) -> BOOL;
}

// ---------------------------------------------------------------------------
// FFI: RAS / VPN connections (rasapi32.dll)
// ---------------------------------------------------------------------------

#[link(name = "rasapi32")]
extern "system" {
    fn RasEnumConnectionsW(
        rasconn: *mut RASCONNW,
        lpcb: *mut u32,
        lpc_connections: *mut u32,
    ) -> u32;

    fn RasGetConnectStatusW(
        hrasconn: isize,
        rasconnstatus: *mut RASCONNSTATUSW,
    ) -> u32;
}

// ---------------------------------------------------------------------------
// FFI structs (manually defined to match Windows SDK layouts)
// ---------------------------------------------------------------------------

#[repr(C)]
struct BLUETOOTH_DEVICE_SEARCH_PARAMS {
    dw_size: u32,
    f_return_authenticated: BOOL,
    f_return_remembered: BOOL,
    f_return_unknown: BOOL,
    f_return_connected: BOOL,
    f_issue_inquiry: BOOL,
    c_timeout_multiplier: u8,
    h_radio: isize,
}

#[repr(C)]
struct BLUETOOTH_DEVICE_INFO {
    dw_size: u32,
    address: u64,
    ul_classofdevice: u32,
    f_connected: BOOL,
    f_remembered: BOOL,
    f_authenticated: BOOL,
    st_last_seen: [u32; 2],
    st_last_used: [u32; 2],
    sz_name: [u16; 248],
}

#[repr(C)]
struct WINHTTP_CURRENT_USER_IE_PROXY_CONFIG {
    f_auto_detect: BOOL,
    lpsz_auto_config_url: PCWSTR,
    lpsz_proxy: PCWSTR,
    lpsz_proxy_bypass: PCWSTR,
}

#[repr(C)]
struct RASCONNW {
    dw_size: u32,
    h_ras_conn: isize,
    sz_entry_name: [u16; 257],
}

#[repr(C)]
struct RASCONNSTATUSW {
    dw_size: u32,
    ras_connstate: u32,
    dw_error: u32,
    sz_device_type: [u16; 17],
    sz_device_name: [u16; 129],
    _padding: [u16; 4],
}

#[repr(C)]
#[allow(non_camel_case_types, non_snake_case)]
struct DNS_CACHE_ENTRY {
    pNext: *mut DNS_CACHE_ENTRY,
    pszName: PCWSTR,
    wType: u16,
    _pad1: u16,
    DataLength: u32,
    dwFlags: u32,
    Data: PCWSTR,
    dwTtl: u32,
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Convert a `SOCKADDR` pointer to a human-readable IP string.
unsafe fn sockaddr_to_ip(addr_ptr: *const SOCKADDR) -> String {
    if addr_ptr.is_null() {
        return String::new();
    }
    let family = (*addr_ptr).sa_family;
    if family == ADDRESS_FAMILY(AF_INET.0 as u16) {
        let sa = &*(addr_ptr as *const SOCKADDR_IN);
        let octets = sa.sin_addr.S_un.S_addr.to_be_bytes();
        format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
    } else if family == ADDRESS_FAMILY(AF_INET6.0 as u16) {
        let sa = &*(addr_ptr as *const SOCKADDR_IN6);
        let b = sa.sin6_addr.u.Byte;
        format!(
            "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
            b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
        )
    } else {
        String::new()
    }
}

/// Convert a `SOCKADDR` pointer to a port number (host byte order).
#[allow(dead_code)]
unsafe fn sockaddr_to_port(addr_ptr: *const SOCKADDR) -> u16 {
    if addr_ptr.is_null() {
        return 0;
    }
    if (*addr_ptr).sa_family == ADDRESS_FAMILY(AF_INET.0 as u16) {
        let sa = &*(addr_ptr as *const SOCKADDR_IN);
        u16::from_be(sa.sin_port)
    } else if (*addr_ptr).sa_family == ADDRESS_FAMILY(AF_INET6.0 as u16) {
        let sa = &*(addr_ptr as *const SOCKADDR_IN6);
        u16::from_be(sa.sin6_port)
    } else {
        0
    }
}

/// Format raw MAC bytes to "XX:XX:XX:XX:XX:XX".
fn mac_bytes_display(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Format a u64 Bluetooth address to "XX:XX:XX:XX:XX:XX".
fn bt_addr_display(addr: u64) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        ((addr >> 40) & 0xFF) as u8,
        ((addr >> 32) & 0xFF) as u8,
        ((addr >> 24) & 0xFF) as u8,
        ((addr >> 16) & 0xFF) as u8,
        ((addr >> 8) & 0xFF) as u8,
        (addr & 0xFF) as u8,
    )
}

/// Truncate a wide char slice at the first null terminator.
fn wstr_until_null(wide: &[u16]) -> Vec<u16> {
    wide.iter().copied().take_while(|&c| c != 0).collect()
}

/// Convert a truncated wide slice to a Rust String.
fn wstr_to_string(wide: &[u16]) -> String {
    String::from_utf16_lossy(&wstr_until_null(wide))
}

/// Translate TCP MIB state code to human-readable form.
fn tcp_state_label(state: u32) -> &'static str {
    match state {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RECEIVED",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "UNKNOWN",
    }
}

/// Translate IF_OPER_STATUS discriminant.
fn if_oper_status_label(status: u32) -> &'static str {
    match status {
        0 => "up",
        1 => "down",
        2 => "testing",
        3 => "unknown",
        4 => "dormant",
        5 => "not_present",
        6 => "lower_layer_down",
        _ => "unknown",
    }
}

/// Translate DNS record type code.
fn dns_type_label(t: u16) -> &'static str {
    match t {
        1 => "A",
        28 => "AAAA",
        5 => "CNAME",
        15 => "MX",
        2 => "NS",
        6 => "SOA",
        12 => "PTR",
        33 => "SRV",
        16 => "TXT",
        _ => "UNKNOWN",
    }
}

/// Resolve a PID to its process name via ToolHelp snapshot.
fn pid_to_name(pid: u32) -> String {
    if pid == 0 {
        return "System Idle Process".into();
    }
    if pid == 4 {
        return "System".into();
    }
    unsafe {
        let snap = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) if !h.is_invalid() => h,
            _ => return format!("PID_{}", pid),
        };
        let mut pe: PROCESSENTRY32W = mem::zeroed();
        pe.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut pe).is_ok() {
            loop {
                if pe.th32ProcessID == pid {
                    let name = wstr_to_string(&pe.szExeFile);
                    return if name.is_empty() {
                        format!("PID_{}", pid)
                    } else {
                        name
                    };
                }
                if Process32NextW(snap, &mut pe).is_err() {
                    break;
                }
            }
        }
    }
    format!("PID_{}", pid)
}

/// Run a system command and return its combined stdout+stderr.
fn run_cmd(exe: &str, args: &[&str]) -> std::result::Result<String, AetherError> {
    let mut cmd = SafeCommand::new(exe, "network", "run_cmd").timeout(30);
    for arg in args {
        cmd = cmd.arg(*arg, ParamType::SafeString)?;
    }
    cmd.output()
}

/// IPv4 u32 (network byte order) → dotted-decimal string.
fn u32_to_ipv4(n: u32) -> String {
    let b = n.to_be_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

// =======================================================================
// Action: adapters — list network adapters
// =======================================================================

fn action_adapters() -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("network_manager", "adapters");
    unsafe {
        let family = AF_UNSPEC.0 as u32;
        let flags = GAA_FLAG_INCLUDE_PREFIX;

        // First call to get required buffer size
        let mut size: u32 = 0;
        let err = GetAdaptersAddresses(family, flags, None, None, &mut size);
        if err != ERROR_BUFFER_OVERFLOW.0 {
            return Err(AetherError::win32(ctx.clone(), "GetAdaptersAddresses sizing", format!("error {err}")));
        }

        let mut buf: Vec<u8> = vec![0u8; size as usize];
        let err = GetAdaptersAddresses(
            family,
            flags,
            None,
            Some(buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
            &mut size,
        );
        if err != NO_ERROR.0 {
            return Err(AetherError::win32(ctx.clone(), "GetAdaptersAddresses", format!("error {err}")));
        }

        let mut items = Vec::new();
        let mut cur: *const IP_ADAPTER_ADDRESSES_LH =
            buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;

        while !cur.is_null() {
            let a = &*cur;

            let name = a
                .FriendlyName
                .to_string()
                .unwrap_or_default();

            let desc = a
                .Description
                .to_string()
                .unwrap_or_default();

            // Walk unicast IP addresses
            let mut ips: Vec<String> = Vec::new();
            let mut uni = a.FirstUnicastAddress;
            while !uni.is_null() {
                let u = &*uni;
                let addr = sockaddr_to_ip(u.Address.lpSockaddr);
                if !addr.is_empty() {
                    ips.push(addr);
                }
                uni = u.Next;
            }

            // MAC address
            let mac_bytes = &a.PhysicalAddress[..a.PhysicalAddressLength as usize];
            let mac = mac_bytes_display(mac_bytes);

            // DHCP enabled — Flags union in Anonymous2
            let dhcp_flags: u32 = a.Anonymous2.Flags;
            let dhcp_enabled = (dhcp_flags & IP_ADAPTER_DHCP_ENABLED) != 0;

            // Gateway addresses
            let mut gateways: Vec<String> = Vec::new();
            let mut gw = a.FirstGatewayAddress;
            while !gw.is_null() {
                let g = &*gw;
                let gw_ip = sockaddr_to_ip(g.Address.lpSockaddr);
                if !gw_ip.is_empty() {
                    gateways.push(gw_ip);
                }
                gw = g.Next;
            }

            // DNS servers
            let mut dns: Vec<String> = Vec::new();
            let mut ds = a.FirstDnsServerAddress;
            while !ds.is_null() {
                let d = &*ds;
                let dns_ip = sockaddr_to_ip(d.Address.lpSockaddr);
                if !dns_ip.is_empty() {
                    dns.push(dns_ip);
                }
                ds = d.Next;
            }

            let oper = a.OperStatus.0 as u32;

            items.push(json!({
                "name": name,
                "description": desc,
                "ip_addresses": ips,
                "mac_address": mac,
                "dhcp_enabled": dhcp_enabled,
                "gateway": gateways,
                "dns_servers": dns,
                "status": if_oper_status_label(oper),
            }));

            cur = a.Next;
        }

        Ok(serde_json::to_string_pretty(&items)?)
    }
}

// =======================================================================
// Action: connections — TCP and UDP
// =======================================================================

fn action_connections() -> std::result::Result<String, AetherError> {
    let mut rows = Vec::new();

    // --- TCP ---
    unsafe {
        let mut size: u32 = 0;
        let _ = GetExtendedTcpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_MODULE_ALL,
            0,
        );
        if size > 0 {
            let mut buf: Vec<u8> = vec![0u8; size as usize];
            let r = GetExtendedTcpTable(
                Some(buf.as_mut_ptr() as *mut std::ffi::c_void),
                &mut size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_MODULE_ALL,
                0,
            );
            if r == NO_ERROR.0 {
                let row_sz = mem::size_of::<MIB_TCPROW_OWNER_MODULE>();
                if row_sz > 0 {
                    let count = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
                    let data = &buf[4..];
                    let max = data.len() / row_sz;
                    let entries = slice::from_raw_parts(
                        data.as_ptr() as *const MIB_TCPROW_OWNER_MODULE,
                        count.min(max),
                    );
                    for e in entries {
                        rows.push(json!({
                            "protocol": "tcp",
                            "local_addr": u32_to_ipv4(e.dwLocalAddr),
                            "local_port": u16::from_be(e.dwLocalPort as u16),
                            "remote_addr": u32_to_ipv4(e.dwRemoteAddr),
                            "remote_port": u16::from_be(e.dwRemotePort as u16),
                            "state": tcp_state_label(e.dwState),
                            "pid": e.dwOwningPid,
                            "process_name": pid_to_name(e.dwOwningPid),
                        }));
                    }
                }
            }
        }
    }

    // --- UDP ---
    unsafe {
        let mut size: u32 = 0;
        let _ = GetExtendedUdpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            UDP_TABLE_OWNER_MODULE,
            0,
        );
        if size > 0 {
            let mut buf: Vec<u8> = vec![0u8; size as usize];
            let r = GetExtendedUdpTable(
                Some(buf.as_mut_ptr() as *mut std::ffi::c_void),
                &mut size,
                false,
                AF_INET.0 as u32,
                UDP_TABLE_OWNER_MODULE,
                0,
            );
            if r == NO_ERROR.0 {
                let row_sz = mem::size_of::<MIB_UDPROW_OWNER_MODULE>();
                if row_sz > 0 {
                    let count = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
                    let data = &buf[4..];
                    let max = data.len() / row_sz;
                    let entries = slice::from_raw_parts(
                        data.as_ptr() as *const MIB_UDPROW_OWNER_MODULE,
                        count.min(max),
                    );
                    for e in entries {
                        rows.push(json!({
                            "protocol": "udp",
                            "local_addr": u32_to_ipv4(e.dwLocalAddr),
                            "local_port": u16::from_be(e.dwLocalPort as u16),
                            "remote_addr": "0.0.0.0",
                            "remote_port": 0,
                            "state": "N/A",
                            "pid": e.dwOwningPid,
                            "process_name": pid_to_name(e.dwOwningPid),
                        }));
                    }
                }
            }
        }
    }

    if rows.is_empty() {
        let fallback = run_cmd("netstat", &["-ano"])?;
        return Ok(json!({"fallback": "netstat -ano", "raw_output": fallback}).to_string());
    }

    Ok(serde_json::to_string_pretty(&rows)?)
}

// =======================================================================
// Action: dns_cache — DNS resolver cache
// =======================================================================

fn action_dns_cache() -> std::result::Result<String, AetherError> {
    unsafe {
        // Dynamically load DnsGetCacheDataTable from dnsapi.dll
        let dll = LoadLibraryW(w!("dnsapi.dll"))
            .map_err(|e| AetherError::Internal(format!("LoadLibrary dnsapi: {e}")))?;

        let proc = GetProcAddress(dll, s!("DnsGetCacheDataTable"))
            .ok_or_else(|| AetherError::Internal("DnsGetCacheDataTable not found".into()))?;

        type FnType = unsafe extern "system" fn(*mut *const DNS_CACHE_ENTRY) -> i32;
        let func: FnType = mem::transmute(proc);

        let mut entry_ptr: *const DNS_CACHE_ENTRY = ptr::null();
        let status = func(&mut entry_ptr);
        if status != 0 {
            let fallback = run_cmd("ipconfig", &["/displaydns"])?;
            return Ok(json!({"source":"ipconfig /displaydns","raw_output":fallback}).to_string());
        }

        let mut entries = Vec::new();
        let mut cur = entry_ptr;
        while !cur.is_null() {
            let e = &*cur;
            let name = e.pszName.to_string().unwrap_or_default();
            let rtype = dns_type_label(e.wType);

            let data = if e.DataLength > 0 && !e.Data.is_null() {
                let raw = slice::from_raw_parts(e.Data.as_ptr() as *const u8, e.DataLength as usize);
                if e.wType == 1 && e.DataLength >= 4 {
                    format!("{}.{}.{}.{}", raw[0], raw[1], raw[2], raw[3])
                } else if e.wType == 28 && e.DataLength >= 16 {
                    format!(
                        "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                        raw[0], raw[1], raw[2], raw[3],
                        raw[4], raw[5], raw[6], raw[7],
                        raw[8], raw[9], raw[10], raw[11],
                        raw[12], raw[13], raw[14], raw[15],
                    )
                } else {
                    String::from_utf8_lossy(raw).into_owned()
                }
            } else {
                String::new()
            };

            entries.push(json!({
                "name": name,
                "type": rtype,
                "ttl": e.dwTtl,
                "data": data,
            }));

            cur = e.pNext;
        }

        Ok(serde_json::to_string_pretty(&entries)?)
    }
}

// =======================================================================
// Action: firewall_rules — Windows Firewall rules
// =======================================================================

fn action_firewall_rules() -> std::result::Result<String, AetherError> {
    let output = run_cmd("netsh", &["advfirewall", "firewall", "show", "rule", "name=all"])?;
    let mut rules = Vec::new();
    let mut cur: std::collections::HashMap<&str, String> = std::collections::HashMap::new();

    let mut flush = |m: &mut std::collections::HashMap<&str, String>| {
        if !m.is_empty() {
            rules.push(json!({
                "name": m.get("Rule Name").cloned().unwrap_or_default(),
                "description": m.get("Description").cloned().unwrap_or_default(),
                "direction": m.get("Direction").cloned().unwrap_or_default(),
                "protocol": m.get("Protocol").cloned().unwrap_or_default(),
                "local_ports": m.get("LocalPort").cloned().unwrap_or_default(),
                "remote_ports": m.get("RemotePort").cloned().unwrap_or_default(),
                "application_name": m.get("Program").cloned().unwrap_or_default(),
                "enabled": m.get("Enabled").cloned().unwrap_or_default(),
                "action": m.get("Action").cloned().unwrap_or_default(),
            }));
            m.clear();
        }
    };

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            flush(&mut cur);
        } else if let Some((k, v)) = line.split_once(':') {
            cur.insert(k.trim(), v.trim().to_string());
        }
    }
    flush(&mut cur);

    Ok(serde_json::to_string_pretty(&rules)?)
}

// =======================================================================
// Action: firewall_profiles — firewall profile status
// =======================================================================

fn action_firewall_profiles() -> std::result::Result<String, AetherError> {
    let output = run_cmd("netsh", &["advfirewall", "show", "allprofiles"])?;
    let mut profiles = Vec::new();
    let mut prof = String::new();
    let mut enabled = String::new();
    let mut inbound = String::new();
    let mut outbound = String::new();

    for line in output.lines() {
        let l = line.trim();
        if l.starts_with("Domain Profile") {
            if !prof.is_empty() {
                profiles.push(json!({"profile":prof,"firewall_enabled":enabled,"default_inbound_action":inbound,"default_outbound_action":outbound}));
            }
            prof = "Domain".into();
            enabled.clear();
            inbound.clear();
            outbound.clear();
        } else if l.starts_with("Private Profile") {
            if !prof.is_empty() {
                profiles.push(json!({"profile":prof,"firewall_enabled":enabled,"default_inbound_action":inbound,"default_outbound_action":outbound}));
            }
            prof = "Private".into();
            enabled.clear();
            inbound.clear();
            outbound.clear();
        } else if l.starts_with("Public Profile") {
            if !prof.is_empty() {
                profiles.push(json!({"profile":prof,"firewall_enabled":enabled,"default_inbound_action":inbound,"default_outbound_action":outbound}));
            }
            prof = "Public".into();
            enabled.clear();
            inbound.clear();
            outbound.clear();
        } else if l.to_lowercase().contains("state") && l.to_lowercase().contains("on") {
            enabled = "Yes".into();
        } else if l.to_lowercase().contains("state") && l.to_lowercase().contains("off") {
            enabled = "No".into();
        } else if l.starts_with("Firewall Policy") || l.starts_with("Inbound") {
            for w in l.split_whitespace() {
                let lo = w.to_lowercase();
                if lo == "allow" || lo == "blockinbound" || lo == "block" {
                    inbound = w.to_string();
                }
            }
        } else if l.starts_with("Outbound") {
            for w in l.split_whitespace() {
                let lo = w.to_lowercase();
                if lo == "allow" || lo == "blockoutbound" || lo == "block" {
                    outbound = w.to_string();
                }
            }
        }
    }
    if !prof.is_empty() {
        profiles.push(json!({"profile":prof,"firewall_enabled":enabled,"default_inbound_action":inbound,"default_outbound_action":outbound}));
    }

    if profiles.is_empty() {
        return Ok(json!({"source":"netsh","raw_output":output}).to_string());
    }
    Ok(serde_json::to_string_pretty(&profiles)?)
}

// =======================================================================
// Action: proxy — get / set proxy settings
// =======================================================================

fn action_proxy(params: &Value) -> std::result::Result<String, AetherError> {
    let force = params.get("force").and_then(|v| v.as_bool()).unwrap_or(false);

    // --- Write path ---
    if force {
        let enable = params.get("proxy_enable").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let server = params.get("proxy_server").and_then(|v| v.as_str()).unwrap_or("");
        let overrides = params.get("proxy_override").and_then(|v| v.as_str()).unwrap_or("");

        audit::log_forced("network", "proxy_set");

        let _ = SafeCommand::new("reg", "network", "proxy_set")
            .timeout(15)
            .arg_unchecked("add")
            .arg(r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings", ParamType::RegistryPath)?
            .arg_unchecked("/v")
            .arg("ProxyEnable", ParamType::Name)?
            .arg_unchecked("/t")
            .arg_unchecked("REG_DWORD")
            .arg_unchecked("/d")
            .arg(&enable.to_string(), ParamType::Numeric)?
            .arg_unchecked("/f")
            .run()?;

        if !server.is_empty() {
            let _ = SafeCommand::new("reg", "network", "proxy_set")
                .timeout(15)
                .arg_unchecked("add")
                .arg(r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings", ParamType::RegistryPath)?
                .arg_unchecked("/v")
                .arg("ProxyServer", ParamType::Name)?
                .arg_unchecked("/t")
                .arg_unchecked("REG_SZ")
                .arg_unchecked("/d")
                .arg(server, ParamType::SafeString)?.arg_unchecked("/f")
            .run()?;
        }
        if !overrides.is_empty() {
            let _ = SafeCommand::new("reg", "network", "proxy_set")
                .timeout(15)
                .arg_unchecked("add")
                .arg(r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings", ParamType::RegistryPath)?
                .arg_unchecked("/v")
                .arg("ProxyOverride", ParamType::Name)?
                .arg_unchecked("/t")
                .arg_unchecked("REG_SZ")
                .arg_unchecked("/d")
                .arg(overrides, ParamType::SafeString)?.arg_unchecked("/f")
            .run()?;
        }
        return Ok(json!({"status":"proxy_updated","proxy_enable":enable,"proxy_server":server,"proxy_override":overrides}).to_string());
    }

    // --- Read path: try WinHttpGetIEProxyConfigForCurrentUser first ---
    unsafe {
        let mut cfg = WINHTTP_CURRENT_USER_IE_PROXY_CONFIG {
            f_auto_detect: BOOL::default(),
            lpsz_auto_config_url: PCWSTR::null(),
            lpsz_proxy: PCWSTR::null(),
            lpsz_proxy_bypass: PCWSTR::null(),
        };
        if WinHttpGetIEProxyConfigForCurrentUser(&mut cfg).as_bool() {
            let auto = cfg.f_auto_detect.as_bool();
            let url = if cfg.lpsz_auto_config_url.is_null() { String::new() } else {
                wstr_to_string(slice::from_raw_parts(cfg.lpsz_auto_config_url.as_ptr(), 1024))
            };
            let proxy = if cfg.lpsz_proxy.is_null() { String::new() } else {
                wstr_to_string(slice::from_raw_parts(cfg.lpsz_proxy.as_ptr(), 1024))
            };
            let bypass = if cfg.lpsz_proxy_bypass.is_null() { String::new() } else {
                wstr_to_string(slice::from_raw_parts(cfg.lpsz_proxy_bypass.as_ptr(), 1024))
            };
            let _ = GlobalFree(HGLOBAL(cfg.lpsz_auto_config_url.0 as *mut _));
            let _ = GlobalFree(HGLOBAL(cfg.lpsz_proxy.0 as *mut _));
            let _ = GlobalFree(HGLOBAL(cfg.lpsz_proxy_bypass.0 as *mut _));
            return Ok(json!({"source":"winhttp","auto_detect":auto,"auto_config_url":url,"proxy":proxy,"proxy_bypass":bypass}).to_string());
        }
    }

    // Fallback to registry
    let reg_val = |name: &str| -> String {
        SafeCommand::new("reg", "network", "proxy_reg_fallback")
            .timeout(15)
            .arg_unchecked("query")
            .arg(r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings", ParamType::RegistryPath)?
            .arg_unchecked("/v")
            .arg(name, ParamType::Name)?
            .output()
            .unwrap_or_default()
            .lines()
            .filter(|l| l.contains("REG_"))
            .filter_map(|l| l.split_whitespace().last())
            .next()
            .unwrap_or("")
            .to_string()
    };

    let enabled = reg_val("ProxyEnable").to_lowercase() == "0x1";
    Ok(json!({
        "source": "registry",
        "proxy_enabled": enabled,
        "proxy_server": reg_val("ProxyServer"),
        "proxy_override": reg_val("ProxyOverride"),
    }).to_string())
}

// =======================================================================
// Action: routing_table — IP routing table
// =======================================================================

fn action_routing_table() -> std::result::Result<String, AetherError> {
    unsafe {
        let mut size: u32 = 0;
        let _ = GetIpForwardTable(None, &mut size, false);
        if size == 0 {
            let fallback = run_cmd("route", &["print"])?;
            return Ok(json!({"source":"route print","raw_output":fallback}).to_string());
        }

        let mut buf: Vec<u8> = vec![0u8; size as usize];
        let r = GetIpForwardTable(Some(buf.as_mut_ptr() as *mut MIB_IPFORWARDTABLE), &mut size, false);
        if r != NO_ERROR.0 {
            let fallback = run_cmd("route", &["print"])?;
            return Ok(json!({"source":"route print","raw_output":fallback}).to_string());
        }

        let tbl = &*(buf.as_ptr() as *const MIB_IPFORWARDTABLE);
        let n = tbl.dwNumEntries as usize;
        let entries = slice::from_raw_parts(tbl.table.as_ptr(), n);

        let proto_label = |p: u32| -> &str {
            match p {
                2 => "local", 3 => "netmgmt", 4 => "icmp", 5 => "egp",
                6 => "ggp", 7 => "hello", 8 => "rip", 9 => "is-is",
                10 => "es-is", 11 => "cisco", 12 => "BBN", 13 => "ospf",
                14 => "bgp", _ => "other",
            }
        };

        let items: Vec<_> = entries.iter().map(|e| json!({
            "destination": u32_to_ipv4(e.dwForwardDest),
            "mask": u32_to_ipv4(e.dwForwardMask),
            "gateway": u32_to_ipv4(e.dwForwardNextHop),
            "interface_index": e.dwForwardIfIndex,
            "metric": e.dwForwardMetric1,
            "protocol": proto_label(e.Anonymous2.dwForwardProto),
        })).collect();

        Ok(serde_json::to_string_pretty(&items)?)
    }
}

// =======================================================================
// Action: network_stats — interface stats + global IP stats
// =======================================================================

fn action_network_stats() -> std::result::Result<String, AetherError> {
    let mut result = json!({});

    unsafe {
        // Per-interface stats via GetIfTable2
        let mut if_table: *mut MIB_IF_TABLE2 = ptr::null_mut();
        let r = GetIfTable2(&mut if_table);
        if r.is_ok() && !if_table.is_null() {
            let tbl = &*if_table;
            let n = tbl.NumEntries as usize;
            let rows = slice::from_raw_parts(tbl.Table.as_ptr(), n);

            let mut ifaces = Vec::new();
            for row in rows {
                // Try GetIfEntry2 for detailed stats
                let mut r2: MIB_IF_ROW2 = mem::zeroed();
                r2.InterfaceIndex = row.InterfaceIndex;
                if GetIfEntry2(&mut r2).is_ok() {
                    ifaces.push(json!({
                        "index": r2.InterfaceIndex,
                        "name": wstr_to_string(r2.Description.as_slice()),
                        "alias": wstr_to_string(r2.Alias.as_slice()),
                        "in_octets": r2.InOctets,
                        "out_octets": r2.OutOctets,
                        "in_errors": r2.InErrors,
                        "out_errors": r2.OutErrors,
                        "in_discards": r2.InDiscards,
                        "out_discards": r2.OutDiscards,
                        "speed": r2.TransmitLinkSpeed,
                        "oper_status": if_oper_status_label(r2.OperStatus.0 as u32),
                        "mtu": r2.Mtu,
                        "type": r2.Type,
                    }));
                } else {
                    ifaces.push(json!({
                        "index": row.InterfaceIndex,
                        "name": wstr_to_string(row.Alias.as_slice()),
                        "in_octets": row.InOctets,
                        "out_octets": row.OutOctets,
                        "speed": row.TransmitLinkSpeed,
                        "oper_status": if_oper_status_label(row.OperStatus.0 as u32),
                        "type": row.Type,
                    }));
                }
            }
            result["interfaces"] = json!(ifaces);
            FreeMibTable(if_table as *const _);
        }

        // Global IP stats
        let mut ip_stats: MIB_IPSTATS_LH = mem::zeroed();
        if GetIpStatistics(&mut ip_stats) == NO_ERROR.0 {
            result["ip_statistics"] = json!({
                "forwarding": ip_stats.Anonymous.Forwarding.0,
                "default_ttl": ip_stats.dwDefaultTTL,
                "in_receives": ip_stats.dwInReceives,
                "in_header_errors": ip_stats.dwInHdrErrors,
                "in_addr_errors": ip_stats.dwInAddrErrors,
                "forward_datagrams": ip_stats.dwForwDatagrams,
                "in_unknown_protos": ip_stats.dwInUnknownProtos,
                "in_discards": ip_stats.dwInDiscards,
                "in_delivers": ip_stats.dwInDelivers,
                "out_requests": ip_stats.dwOutRequests,
                "routing_discards": ip_stats.dwRoutingDiscards,
                "out_discards": ip_stats.dwOutDiscards,
                "out_no_routes": ip_stats.dwOutNoRoutes,
                "reassembly_timeout": ip_stats.dwReasmTimeout,
                "reassembly_required": ip_stats.dwReasmReqds,
                "reassembly_oks": ip_stats.dwReasmOks,
                "reassembly_fails": ip_stats.dwReasmFails,
                "fragmentation_oks": ip_stats.dwFragOks,
                "fragmentation_fails": ip_stats.dwFragFails,
                "fragmentation_creates": ip_stats.dwFragCreates,
                "num_interfaces": ip_stats.dwNumIf,
                "num_addresses": ip_stats.dwNumAddr,
                "num_routes": ip_stats.dwNumRoutes,
            });
        }
    }

    if result.as_object().map_or(true, |o| o.is_empty()) {
        let fb = run_cmd("netstat", &["-e", "-s"])?;
        return Ok(json!({"source":"netstat -e -s","raw_output":fb}).to_string());
    }

    Ok(serde_json::to_string_pretty(&result)?)
}

// =======================================================================
// Action: wifi_profiles — WiFi profiles (no passwords)
// =======================================================================

fn action_wifi_profiles() -> std::result::Result<String, AetherError> {
    unsafe {
        let mut handle: HANDLE = HANDLE::default();
        let mut negotiated: u32 = 0;
        let r = WlanOpenHandle(2, None, &mut negotiated, &mut handle);
        if r != 0 {
            let fb = run_cmd("netsh", &["wlan", "show", "profiles"])?;
            return Ok(json!({"source":"netsh wlan show profiles","raw_output":fb}).to_string());
        }

        let mut if_list: *mut WLAN_INTERFACE_INFO_LIST = ptr::null_mut();
        if WlanEnumInterfaces(handle, None, &mut if_list) != 0 || if_list.is_null() {
            let _ = WlanCloseHandle(handle, None);
            let fb = run_cmd("netsh", &["wlan", "show", "profiles"])?;
            return Ok(json!({"source":"netsh wlan show profiles","raw_output":fb}).to_string());
        }

        let if_ref = &*if_list;
        let ifaces = slice::from_raw_parts(if_ref.InterfaceInfo.as_ptr(), if_ref.dwNumberOfItems as usize);

        let mut profiles = Vec::new();

        for iface in ifaces {
            let iface_desc = wstr_to_string(&iface.strInterfaceDescription);

            let mut pl: *mut WLAN_PROFILE_INFO_LIST = ptr::null_mut();
            if WlanGetProfileList(handle, &iface.InterfaceGuid, None, &mut pl) != 0 || pl.is_null() {
                continue;
            }
            let pl_ref = &*pl;
            let profs = slice::from_raw_parts(pl_ref.ProfileInfo.as_ptr(), pl_ref.dwNumberOfItems as usize);

            for prof in profs {
                let ssid = wstr_to_string(&prof.strProfileName);
                let mut xml: PWSTR = PWSTR::null();
                let mut flags: u32 = 0;
                let r = WlanGetProfile(
                    handle,
                    &iface.InterfaceGuid,
                    PCWSTR(prof.strProfileName.as_ptr()),
                    None,
                    &mut xml,
                    Some(&mut flags),
                    None,
                );

                let (auth, enc) = if r == 0 && !xml.is_null() {
                    let s = wstr_to_string(slice::from_raw_parts(xml.as_ptr(), 4096)).to_lowercase();
                    let a = if s.contains("wpa3") { "WPA3" }
                        else if s.contains("wpa2") { "WPA2" }
                        else if s.contains("wpa") { "WPA" }
                        else if s.contains("wep") { "WEP" }
                        else { "open" };
                    let e = if s.contains("aes") { "AES" }
                        else if s.contains("tkip") { "TKIP" }
                        else { "unknown" };
                    WlanFreeMemory(xml.0 as *const _);
                    (a.to_string(), e.to_string())
                } else {
                    ("unknown".to_string(), "unknown".to_string())
                };

                profiles.push(json!({
                    "ssid": ssid,
                    "authentication": auth,
                    "encryption": enc,
                    "interface": iface_desc,
                }));
            }

            WlanFreeMemory(pl as *const _);
        }

        WlanFreeMemory(if_list as *const _);
        let _ = WlanCloseHandle(handle, None);

        if profiles.is_empty() {
            return Ok(json!({"message":"No WiFi profiles found"}).to_string());
        }
        Ok(serde_json::to_string_pretty(&profiles)?)
    }
}

// =======================================================================
// Action: vpn_connections — VPN / RAS connections
// =======================================================================

fn action_vpn_connections() -> std::result::Result<String, AetherError> {
    unsafe {
        let mut size: u32 = mem::size_of::<RASCONNW>() as u32;
        let mut count: u32 = 0;
        let mut conns = vec![RASCONNW { dw_size: mem::size_of::<RASCONNW>() as u32, h_ras_conn: 0, sz_entry_name: [0u16; 257] }];

        let mut r = RasEnumConnectionsW(conns.as_mut_ptr(), &mut size, &mut count);
        if r == 603 {
            // ERROR_BUFFER_TOO_SMALL
            let needed = size / mem::size_of::<RASCONNW>() as u32;
            conns = (0..needed).map(|_| RASCONNW { dw_size: mem::size_of::<RASCONNW>() as u32, h_ras_conn: 0, sz_entry_name: [0u16; 257] }).collect();
            r = RasEnumConnectionsW(conns.as_mut_ptr(), &mut size, &mut count);
        }

        if r != 0 || count == 0 {
            return Ok(json!({"vpn_connections":[],"status":"no_active"}).to_string());
        }

        let out: Vec<_> = conns[..count as usize].iter().map(|c| {
            let name = wstr_to_string(&c.sz_entry_name);
            let mut st: RASCONNSTATUSW = mem::zeroed();
            st.dw_size = mem::size_of::<RASCONNSTATUSW>() as u32;
            let state = if RasGetConnectStatusW(c.h_ras_conn, &mut st) == 0 {
                match st.ras_connstate {
                    0 => "idle", 1 => "connecting", 2 => "connected", 3 => "disconnected",
                    s if (0x2000..=0x200A).contains(&s) => "authenticating",
                    _ => "unknown",
                }
            } else { "unknown" };
            let dev = wstr_to_string(&st.sz_device_type);
            json!({"name":name,"status":state,"device_type":dev})
        }).collect();

        Ok(serde_json::to_string_pretty(&out)?)
    }
}

// =======================================================================
// Action: bluetooth_devices
// =======================================================================

fn action_bluetooth_devices() -> std::result::Result<String, AetherError> {
    unsafe {
        let sp = BLUETOOTH_DEVICE_SEARCH_PARAMS {
            dw_size: mem::size_of::<BLUETOOTH_DEVICE_SEARCH_PARAMS>() as u32,
            f_return_authenticated: BOOL::from(true),
            f_return_remembered: BOOL::from(true),
            f_return_unknown: BOOL::from(true),
            f_return_connected: BOOL::from(true),
            f_issue_inquiry: BOOL::from(false),
            c_timeout_multiplier: 0,
            h_radio: 0,
        };

        let mut di = BLUETOOTH_DEVICE_INFO {
            dw_size: mem::size_of::<BLUETOOTH_DEVICE_INFO>() as u32,
            address: 0,
            ul_classofdevice: 0,
            f_connected: BOOL::default(),
            f_remembered: BOOL::default(),
            f_authenticated: BOOL::default(),
            st_last_seen: [0u32; 2],
            st_last_used: [0u32; 2],
            sz_name: [0u16; 248],
        };

        let h = BluetoothFindFirstDevice(&sp, &mut di);
        if h == 0 {
            return Ok(json!({"bluetooth_devices":[],"status":"none"}).to_string());
        }

        let mut devs = Vec::new();
        let add_dev = |d: &BLUETOOTH_DEVICE_INFO| -> Value {
            json!({
                "name": wstr_to_string(&d.sz_name),
                "address": bt_addr_display(d.address),
                "paired": d.f_authenticated.as_bool(),
                "connected": d.f_connected.as_bool(),
            })
        };
        devs.push(add_dev(&di));

        loop {
            let mut nd = BLUETOOTH_DEVICE_INFO {
                dw_size: mem::size_of::<BLUETOOTH_DEVICE_INFO>() as u32,
                address: 0, ul_classofdevice: 0,
                f_connected: BOOL::default(), f_remembered: BOOL::default(),
                f_authenticated: BOOL::default(),
                st_last_seen: [0; 2], st_last_used: [0; 2],
                sz_name: [0u16; 248],
            };
            if !BluetoothFindNextDevice(h, &mut nd).as_bool() {
                break;
            }
            devs.push(add_dev(&nd));
        }
        let _ = BluetoothFindDeviceClose(h);
        Ok(serde_json::to_string_pretty(&devs)?)
    }
}

// =======================================================================
// Action: hosts_file — read / write hosts file
// =======================================================================

fn action_hosts_file(params: &Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("network_manager", "hosts_file");
    let path = Path::new(r"C:\Windows\System32\drivers\etc\hosts");
    let force = params.get("force").and_then(|v| v.as_bool()).unwrap_or(false);

    if force {
        let content = params.get("content").and_then(|v| v.as_str())
            .ok_or_else(|| AetherError::invalid_param(ctx.clone(), "content field required for write"))?;
        audit::log_forced("network", "hosts_write");
        std::fs::write(path, content.as_bytes())
            .map_err(|e| AetherError::permission_denied(ctx.clone(), format!("Cannot write hosts: {e}")))?;
        return Ok(json!({"status":"written","path":path.to_string_lossy()}).to_string());
    }

    let text = std::fs::read_to_string(path)
        .map_err(|e| AetherError::not_found(ctx.clone(), format!("hosts file: {e}"), None))?;

    let mut entries = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if t.starts_with('#') {
            entries.push(json!({"ip":"","hostname":"","comment":t}));
            continue;
        }
        let (main, comment) = match t.split_once('#') {
            Some((m, c)) => (m.trim(), format!("#{}", c)),
            None => (t, String::new()),
        };
        let parts: Vec<&str> = main.split_whitespace().collect();
        if parts.len() >= 2 {
            entries.push(json!({"ip":parts[0],"hostname":parts[1..].join(" "),"comment":comment}));
        } else if !main.is_empty() {
            entries.push(json!({"ip":main,"hostname":"","comment":comment}));
        }
    }

    Ok(json!({"path":path.to_string_lossy(),"content":text,"entries":entries}).to_string())
}

// =======================================================================
// Action: network_shares — enumerate / create / delete shares
// =======================================================================

fn action_network_shares(params: &Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("network_manager", "network_shares");
    let force = params.get("force").and_then(|v| v.as_bool()).unwrap_or(false);

    // Create share
    if params.get("create_share").and_then(|v| v.as_bool()).unwrap_or(false) {
        if !force {
            return Err(AetherError::invalid_param(ctx.clone(), "force=true required to create share"));
        }
        let name = params.get("share_name").and_then(|v| v.as_str())
            .ok_or_else(|| AetherError::invalid_param(ctx.clone(), "share_name required"))?;
        let share_path = params.get("share_path").and_then(|v| v.as_str())
            .ok_or_else(|| AetherError::invalid_param(ctx.clone(), "share_path required"))?;
        audit::log_forced("network", "share_create");
        let out = SafeCommand::new("net", "network", "net_share_create")
                .timeout(15)
                .arg_unchecked("share")
                .arg(name, ParamType::Name)?
                .arg_unchecked("=")
                .arg(share_path, ParamType::Path)?
                .output()?;
        return Ok(json!({"status":"created","share_name":name,"output":out}).to_string());
    }

    // Delete share
    if let Some(del) = params.get("delete_share").and_then(|v| v.as_str()) {
        if !force {
            return Err(AetherError::invalid_param(ctx.clone(), "force=true required to delete share"));
        }
        audit::log_forced("network", "share_delete");
        let out = SafeCommand::new("net", "network", "net_share_delete")
                .timeout(15)
                .arg_unchecked("share")
                .arg(del, ParamType::Name)?
                .arg_unchecked("/delete")
                .output()?;
        return Ok(json!({"status":"deleted","share_name":del,"output":out}).to_string());
    }

    // Enumerate — use net share
    let out = SafeCommand::new("net", "network", "net_shares_list")
        .timeout(15)
        .arg_unchecked("share")
        .output()?;
    Ok(json!({"source":"net share","raw_output":out}).to_string())
}

// =======================================================================
// Dispatch
// =======================================================================

/// Handle network management actions.
///
/// Supported actions:
///
/// | Action | Description |
/// |--------|-------------|
/// | `adapters` | List network adapters (IP, MAC, gateway, DNS, status) |
/// | `connections` | TCP/UDP connections with process info |
/// | `dns_cache` | DNS resolver cache entries |
/// | `firewall_rules` | Windows Firewall rules |
/// | `firewall_profiles` | Firewall profile status (Domain/Private/Public) |
/// | `proxy` | Get or set proxy (set requires `force: true`) |
/// | `routing_table` | IP routing table |
/// | `network_stats` | Interface statistics and global IP stats |
/// | `wifi_profiles` | WiFi profiles (SSID, auth, encryption — no passwords) |
/// | `vpn_connections` | Active VPN / RAS connections |
/// | `bluetooth_devices` | Paired Bluetooth devices |
/// | `hosts_file` | Read or write hosts file (write requires `force: true`) |
/// | `network_shares` | Enum/create/delete shares (create/delete require `force: true`) |
pub fn handle_network_manager(action: &str, params: serde_json::Value) -> std::result::Result<String, AetherError> {
    audit::log_success("network", action, "");

    let result = match action {
        "adapters" => action_adapters(),
        "connections" => action_connections(),
        "dns_cache" => action_dns_cache(),
        "firewall_rules" => action_firewall_rules(),
        "firewall_profiles" => action_firewall_profiles(),
        "proxy" => action_proxy(&params),
        "routing_table" => action_routing_table(),
        "network_stats" => action_network_stats(),
        "wifi_profiles" => action_wifi_profiles(),
        "vpn_connections" => action_vpn_connections(),
        "bluetooth_devices" => action_bluetooth_devices(),
        "hosts_file" => action_hosts_file(&params),
        "network_shares" => action_network_shares(&params),
        _ => {
            return Err(AetherError::invalid_param(ErrorContext::new("network_manager", "unknown"), format!(
                "Unknown network action: {action}. Valid: adapters, connections, dns_cache, firewall_rules, firewall_profiles, proxy, routing_table, network_stats, wifi_profiles, vpn_connections, bluetooth_devices, hosts_file, network_shares"
            )));
        }
    };

    if let Err(ref e) = result {
        audit::log_failure("network", action, &e.to_string());
    }

    result
}
