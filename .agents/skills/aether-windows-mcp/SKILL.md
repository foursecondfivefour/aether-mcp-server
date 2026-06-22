# AETHER_01 — Windows MCP Agent Skill

## When to use this skill

Use this skill whenever:

1. The user asks to **manage Windows 10/11** — processes, files, registry, services, GUI, network, users, security
2. The user mentions **AETHER_01** or **aether-mcp-server** by name
3. The user needs to **audit, harden, or optimize** a Windows system
4. The user wants to **debug** Windows system behavior (processes, handles, DLLs, network connections)
5. The user needs to **automate** Windows administration tasks that normally require clicking through Control Panel or running PowerShell

## System prompt (for AI agents)

You have access to AETHER_01 — a local MCP server that provides full Windows 10/11 system management via 10 tools. All tools run over stdio with **zero network access**. The server runs as a child process of your IDE with the same privileges.

### Tools available

1. `process_control` — list, kill, create, set_priority, threads, affinity, memory_limits, suspend/resume, list_handles, list_modules, inject_dll*
2. `file_system` — read/write/delete/copy/move, list_dir, stat, mkdir, acl, symlinks, ADS streams, compress/uncompress, EFS, quotas, volumes, mount/unmount, shares
3. `registry_editor` — read/write/delete/enumerate (all hives), security_get/set, monitor, export/import, offline_mount*
4. `service_manager` — list, start/stop/restart, query_config/status, set_startup, triggers, failure_actions, dependencies, drivers
5. `gui_automation` — mouse_move/click/scroll, keyboard_type/press, find_window, list_windows, set_window_pos, focus_window, screenshot, clipboard_read/write, display_info, audio_volume, screen_lock
6. `system_info` — cpu_info, memory_info, disk_info, os_info, uptime, env_vars, power_plans, battery, device_list, bios_info, time_get, ntp_sync, installed_software, windows_update, perf_counters, bcd_*, crashdump_*
7. `network_manager` — adapters, connections, dns_cache, firewall_rules, firewall_profiles, proxy, routing_table, network_stats, wifi_profiles, vpn_connections, bluetooth_devices, hosts_file, network_shares
8. `user_management` — users, groups, create/delete_user, sessions, current_user, privileges, password_policies, account_lockout, logon_rights, cert_store_list, cred_list/read, token_*, lsa_secrets_*
9. `security_audit` — audit_policies, uac_status, defender_status/threats/scan, applocker_rules, bitlocker_status, tpm_status, secure_boot, credential_guard, lsa_protection, exploit_protection, sandbox, hyperv, smartscreen, windows_hello
10. `system_automation` — event_query/write, event_channels, task_list/query/create/delete/run, wmi_query

* = requires feature gate enabled in `.env`

### Safety rules

- **force: true required** for: kill, delete, stop, unmount, write to HKLM/system, create/delete users, DLL injection, token manipulation
- **Feature gates** (all OFF by default): BCD_EDIT, HAL_CONFIG, OFFLINE_REGISTRY, DLL_INJECT, TOKEN_MANIPULATION, LSA_SECRETS
- WMI queries: SELECT only, 30s timeout, 1000 row limit
- All errors include Russian descriptions + Win32 error code translation
- Audit logging on every tool invocation

### Action pattern

All tools use the same action+params pattern:

```json
{
  "action": "list",
  "params": { "optional": "parameters", "force": true }
}
```

### Performance

- The binary is compiled with `opt-level=3, fat LTO, native CPU, panic=abort, strip=symbols`
- All tool responses are JSON strings

## Quick reference — common tasks

### System audit

```
process_control.list → what's running?
service_manager.list → what services?
system_info.cpu_info → hardware
system_info.memory_info → RAM status
network_manager.adapters → network config
network_manager.connections → who's connected?
security_audit.uac_status → security posture
security_audit.defender_status → AV status
user_management.current_user → who am I?
```

### System hardening

```
registry_editor.write (force:true) → flip security keys
service_manager.set_startup (force:true) → disable unnecessary services
process_control.kill (force:true) → stop unwanted processes
firewall_rules → check network perimeter
```

### Filesystem operations

```
file_system.read "C:\\path\\to\\file" → read file
file_system.write "C:\\path" "content" → write file
file_system.list_dir "C:\\path" → recursive listing
file_system.acl_get "C:\\path" → check permissions
file_system.symlink target link → create symlink
```

### Windows customization

```
registry_editor.read "HKCU" "Control Panel\\Desktop" → desktop settings
registry_editor.write (force:true) → change registry values
gui_automation.screenshot "base64" → capture screen
system_info.power_plans → power settings
```

### Malware investigation

```
process_control.list → look for suspicious names
process_control.list_modules <pid> → check loaded DLLs
process_control.list_handles <pid> → what files/keys is it touching?
system_automation.event_query → check Windows Event Logs
security_audit.defender_threats → AV detection history
network_manager.connections → any suspicious outbound?
```

### WMI power queries

```
system_automation.wmi_query "SELECT * FROM Win32_Product" → installed software
system_automation.wmi_query "SELECT * FROM Win32_StartupCommand" → startup programs
system_automation.wmi_query "SELECT * FROM Win32_Printer" → printers
system_automation.wmi_query "SELECT * FROM Win32_PnPEntity WHERE Status != 'OK'" → problem devices
```
