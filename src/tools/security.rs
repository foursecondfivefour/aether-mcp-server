#![allow(unsafe_code)]

//! Security audit tool for AETHER_01 MCP server.
//!
//! 20 actions covering audit policies, UAC, Windows Defender, AppLocker,
//! BitLocker, firewall profiles, TPM, Secure Boot, Credential Guard,
//! LSA protection, exploit protection, sandbox, Hyper-V, SmartScreen,
//! and Windows Hello status.
//!
//! # Architecture
//!
//! Most read-only actions query Windows Registry (`windows_registry` crate)
//! for speed and reliability. Write actions and complex queries fall back to
//! PowerShell via the shared `ps_output`/`ps_json` helpers from `common`.

use crate::audit;
use crate::error::{AetherError, ErrorContext};
use crate::tools::common;

use serde_json::{json, Value};
use windows_registry::LOCAL_MACHINE;

// ═══════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════

/// Tool name for audit logging.
const TOOL: &str = "security";

/// Registry path for UAC settings.
const REG_UAC: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";

/// Registry path for firewall profile settings.
const REG_FIREWALL: &str = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";

/// Registry path for LSA settings.
const REG_LSA: &str = r"SYSTEM\CurrentControlSet\Control\Lsa";

/// Registry path for Credential Guard.
const REG_CG: &str = r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard";

/// Registry path for SmartScreen: Explorer.
const REG_SMARTSCREEN_EXPLORER: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer";

/// Registry path for SmartScreen: AppHost.
const REG_SMARTSCREEN_APPHOST: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost";

/// Registry path for SmartScreen: policy.
const REG_SMARTSCREEN_POLICY: &str = r"SOFTWARE\Policies\Microsoft\Windows\System";

/// Registry path for Secure Boot state.
const REG_SECUREBOOT: &str = r"SYSTEM\CurrentControlSet\Control\SecureBoot\State";

// ═══════════════════════════════════════════════════════════════════════════════
// Registry helpers
// ═══════════════════════════════════════════════════════════════════════════════

/// Read a DWORD value from HKLM, returning `default` if key or value is missing.
fn reg_dword(path: &str, name: &str, default: u32) -> Result<u32, AetherError> {
    let key = match LOCAL_MACHINE.open(path) {
        Ok(k) => k,
        Err(_) => return Ok(default),
    };
    match key.get_u32(name) {
        Ok(v) => Ok(v),
        Err(_) => Ok(default),
    }
}

/// Read a string value from HKLM, returning `None` if key or value is missing.
fn reg_string(path: &str, name: &str) -> Result<Option<String>, AetherError> {
    let key = match LOCAL_MACHINE.open(path) {
        Ok(k) => k,
        Err(_) => return Ok(None),
    };
    match key.get_string(name) {
        Ok(v) => Ok(Some(v)),
        Err(_) => Ok(None),
    }
}

/// Write a DWORD to HKLM registry. Returns `AetherError::Internal` on failure.
fn reg_set_dword(path: &str, name: &str, value: u32) -> Result<(), AetherError> {
    let key = LOCAL_MACHINE
        .open(path)
        .map_err(|e| AetherError::Internal(format!("Cannot open registry key {path}: {e}")))?;
    key.set_u32(name, value)
        .map_err(|e| AetherError::Internal(format!("Cannot write {name} to {path}: {e}")))
}

// ═══════════════════════════════════════════════════════════════════════════════
// Action implementations (alphabetically ordered by action name)
// ═══════════════════════════════════════════════════════════════════════════════

fn action_audit_policies() -> Result<String, AetherError> {
    let raw = common::ps_output("auditpol /get /category:*", TOOL)?;
    let mut policies = Vec::new();
    let mut current_category = String::new();

    for line in raw.lines().skip(1) {
        let line = line.trim();
        if line.is_empty() || line.starts_with("----") {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        let is_sub = line.starts_with(' ') || line.starts_with('\t');
        let name = parts[0].trim();

        if !is_sub && !name.is_empty() {
            // Category line
            current_category = name.to_string();
        } else if is_sub && !name.is_empty() && !current_category.is_empty() {
            let status = if parts.len() >= 2 {
                let rest: Vec<&str> = parts[1..]
                    .iter()
                    .filter(|s| !s.is_empty() && **s != "and")
                    .copied()
                    .collect();
                rest.join(" ")
            } else {
                String::from("No Auditing")
            };

            policies.push(json!({
                "category": current_category,
                "subcategory": name,
                "setting": status,
            }));
        }
    }

    serde_json::to_string_pretty(&policies).map_err(AetherError::from)
}

fn action_audit_set_policy(params: &Value) -> Result<String, AetherError> {
    let ctx = ErrorContext::new(TOOL, "audit_set_policy");
    common::check_force(ctx.clone(), params, "audit_set_policy")?;

    let category = common::get_param_str(ctx.clone(), params, "category")?;
    let enable = params.get("enable").and_then(|v| v.as_bool()).unwrap_or(true);
    let enable_str = if enable { "enable" } else { "disable" };
    let subcategory = common::get_param_str_opt(params, "subcategory");

    let cmd = if let Some(sub) = subcategory {
        format!(
            "auditpol /set /subcategory:\"{sub}\" /success:{enable_str} /failure:{enable_str}"
        )
    } else {
        format!(
            "auditpol /set /category:\"{category}\" /success:{enable_str} /failure:{enable_str}"
        )
    };
    let _ = common::ps_output(&cmd, TOOL)?;
    audit::log_forced(TOOL, "audit_set_policy");

    Ok(json!({
        "action": "audit_set_policy",
        "category": category,
        "subcategory": subcategory,
        "enabled": enable,
        "status": "success"
    }).to_string())
}

fn action_uac_status() -> Result<String, AetherError> {
    let enable_lua = reg_dword(REG_UAC, "EnableLUA", 0)?;
    let consent_admin = reg_dword(REG_UAC, "ConsentPromptBehaviorAdmin", 5)?;
    let consent_user = reg_dword(REG_UAC, "ConsentPromptBehaviorUser", 3)?;
    let secure_desktop = reg_dword(REG_UAC, "PromptOnSecureDesktop", 1)?;
    let filter_admin = reg_dword(REG_UAC, "FilterAdministratorToken", 0)?;

    let consent_admin_desc = match consent_admin {
        0 => "Elevate without prompting",
        1 => "Prompt for credentials on the secure desktop",
        2 => "Prompt for consent on the secure desktop",
        3 => "Prompt for credentials",
        4 => "Prompt for consent",
        5 => "Prompt for consent for non-Windows binaries",
        _ => "Unknown value",
    };

    let consent_user_desc = match consent_user {
        0 => "Automatically deny elevation requests",
        1 => "Prompt for credentials on the secure desktop",
        3 => "Prompt for credentials",
        _ => "Unknown value",
    };

    Ok(json!({
        "uac_enabled": enable_lua != 0,
        "enable_lua": enable_lua,
        "enable_lua_description": if enable_lua != 0 { "UAC is enabled" } else { "UAC is disabled (NOT recommended)" },
        "consent_prompt_behavior_admin": consent_admin,
        "consent_prompt_behavior_admin_description": consent_admin_desc,
        "consent_prompt_behavior_user": consent_user,
        "consent_prompt_behavior_user_description": consent_user_desc,
        "prompt_on_secure_desktop": secure_desktop != 0,
        "filter_administrator_token": filter_admin != 0,
        "filter_administrator_token_description": if filter_admin != 0 { "Admin approval mode for built-in Administrator is enabled" } else { "Built-in Administrator runs with full token" }
    }).to_string())
}

fn action_uac_set_level(params: &Value) -> Result<String, AetherError> {
    let ctx = ErrorContext::new(TOOL, "uac_set_level");
    common::check_force(ctx.clone(), params, "uac_set_level")?;

    let level = common::get_param_u64(ctx.clone(), params, "level")?;
    if level > 5 {
        return Err(AetherError::invalid_param(ctx.clone(), "level must be 0-5"));
    }
    let level = level as u32;

    reg_set_dword(REG_UAC, "ConsentPromptBehaviorAdmin", level)?;
    reg_set_dword(REG_UAC, "EnableLUA", if level == 0 { 0 } else { 1 })?;

    audit::log_forced(TOOL, "uac_set_level");

    Ok(json!({
        "action": "uac_set_level",
        "level": level,
        "status": "success",
        "note": "Registry values written. A reboot may be required for full effect."
    }).to_string())
}

fn action_defender_status() -> Result<String, AetherError> {
    let script = r#"
        $status = Get-MpComputerStatus -ErrorAction SilentlyContinue;
        if (-not $status) { Write-Output '{}'; exit 0 }
        @{
            realtime_enabled = $status.AntispywareEnabled -or $status.AntivirusEnabled;
            antispyware_enabled = $status.AntispywareEnabled;
            antivirus_enabled = $status.AntivirusEnabled;
            behavior_monitor_enabled = $status.BehaviorMonitorEnabled;
            ioav_protection_enabled = $status.IoavProtectionEnabled;
            nis_enabled = $status.NISEnabled;
            on_access_protection_enabled = $status.OnAccessProtectionEnabled;
            cloud_protection = $status.MAPSReporting;
            cloud_block_level = $status.CloudBlockLevel;
            sample_submission = $status.SubmitSamplesConsent;
            last_scan_date = $status.LastFullScanDate;
            last_scan_type = $status.LastScanType;
            last_quick_scan_date = $status.LastQuickScanDate;
            definitions_version = $status.AntivirusSignatureVersion;
            definitions_updated = $status.AntivirusSignatureLastUpdated;
            definitions_age_days = if ($status.AntivirusSignatureLastUpdated) { [int]((Get-Date) - $status.AntivirusSignatureLastUpdated).TotalDays } else { $null };
            engine_version = $status.AMEngineVersion;
            product_status = $status.AMProductStatus;
        } | ConvertTo-Json
    "#;
    let v = common::ps_json(script, TOOL)?;
    Ok(v.to_string())
}

fn action_defender_threats() -> Result<String, AetherError> {
    let script = r#"
        Get-MpThreat -ErrorAction SilentlyContinue |
        Select-Object ThreatID, ThreatName, SeverityID, CategoryID, InitialDetectionTime, LastThreatStatusChangeTime, IsActive, Action, Resources, PendingActions, DidThreatExecute |
        ConvertTo-Json -Compress
    "#;
    let v = common::ps_json(script, TOOL)?;
    Ok(v.to_string())
}

fn action_defender_scan(params: &Value) -> Result<String, AetherError> {
    let ctx = ErrorContext::new(TOOL, "defender_scan");
    common::check_force(ctx.clone(), params, "defender_scan")?;

    let scan_type = common::get_param_str_opt(params, "scan_type").unwrap_or("QuickScan");
    let valid = ["QuickScan", "FullScan", "CustomScan"];
    if !valid.contains(&scan_type) {
        return Err(AetherError::invalid_param(ctx.clone(), format!(
            "scan_type must be one of: {}",
            valid.join(", ")
        )));
    }

    let script = format!("Start-MpScan -ScanType {scan_type} -ErrorAction Stop");
    let result = common::ps_output(&script, TOOL)?;
    audit::log_forced(TOOL, "defender_scan");

    Ok(json!({
        "action": "defender_scan",
        "scan_type": scan_type,
        "result": result,
        "status": "scan_initiated"
    }).to_string())
}

fn action_defender_exclusions(params: &Value) -> Result<String, AetherError> {
    let ctx = ErrorContext::new(TOOL, "defender_exclusions");
    let operation = common::get_param_str_opt(params, "operation").unwrap_or("list");

    match operation {
        "list" => {
            let script = r#"
                $prefs = Get-MpPreference -ErrorAction SilentlyContinue
                @{
                    exclusion_path = @($prefs.ExclusionPath)
                    exclusion_process = @($prefs.ExclusionProcess)
                    exclusion_extension = @($prefs.ExclusionExtension)
                    exclusion_ip_address = @($prefs.ExclusionIpAddress)
                } | ConvertTo-Json
            "#;
            let v = common::ps_json(script, TOOL)?;
            Ok(v.to_string())
        }
        "add" | "remove" => {
            common::check_force(ctx.clone(), params, &format!("defender_exclusions/{operation}"))?;
            let exclusion_type = common::get_param_str(ctx.clone(), params, "exclusion_type")?;
            let value = common::get_param_str(ctx.clone(), params, "value")?;

            let flag = match exclusion_type {
                "path" => "ExclusionPath",
                "process" => "ExclusionProcess",
                "extension" => "ExclusionExtension",
                "ip" => "ExclusionIpAddress",
                other => return Err(AetherError::invalid_param(ctx.clone(), format!(
                    "Unknown exclusion_type: {other}"
                ))),
            };

            let ps_cmd = if operation == "add" { "Add-MpPreference" } else { "Remove-MpPreference" };
            let script = format!("{ps_cmd} -{flag} \"{value}\" -ErrorAction Stop");
            let _ = common::ps_output(&script, TOOL)?;
            audit::log_forced(TOOL, &format!("defender_exclusions/{operation}"));

            Ok(json!({
                "action": format!("defender_exclusion_{operation}"),
                "exclusion_type": exclusion_type,
                "value": value,
                "status": "success"
            }).to_string())
        }
        other => Err(AetherError::invalid_param(ctx.clone(), format!(
            "Unknown operation: {other}. Use list, add, or remove."
        ))),
    }
}

fn action_applocker_rules() -> Result<String, AetherError> {
    let script = r#"
        try {
            $policy = Get-AppLockerPolicy -Effective -ErrorAction Stop
            if (-not $policy) { @{ rules = @() } | ConvertTo-Json; exit 0 }
            $rules = foreach ($rule in $policy.RuleCollections) {
                @{
                    collection = $rule.RuleCollectionType
                    enforcement = $rule.EnforcementMode
                    rules = foreach ($r in $rule) {
                        @{
                            name = $r.Name
                            description = $r.Description
                            user_or_group_sid = $r.UserOrGroupSid
                            action = $r.Action
                            conditions = foreach ($c in $r.Conditions) {
                                @{ type = $c.GetType().Name; path = $c.Path; publisher = $c.Publisher; hash = $c.Hash }
                            }
                            exceptions = foreach ($e in $r.Exceptions) { $e.Path }
                        }
                    }
                }
            }
            @{ rules = $rules } | ConvertTo-Json -Depth 5
        } catch {
            @{
                error = $_.Exception.Message
                note = "AppLocker policy may not be configured or the service is not running"
                rules = @()
            } | ConvertTo-Json
        }
    "#;
    let v = common::ps_json(script, TOOL)?;
    Ok(v.to_string())
}

fn action_bitlocker_status() -> Result<String, AetherError> {
    let script = r#"
        Get-BitLockerVolume -ErrorAction SilentlyContinue |
        Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionMethod, VolumeType,
                      @{N='PercentageEncrypted';E={$_.EncryptionPercentage}},
                      KeyProtector, AutoUnlockEnabled, MetadataVersion |
        ConvertTo-Json -Compress
    "#;
    let v = common::ps_json(script, TOOL)?;
    Ok(v.to_string())
}

fn action_firewall_profile_status() -> Result<String, AetherError> {
    let profiles = [
        ("Domain", format!("{REG_FIREWALL}\\DomainProfile")),
        ("Private", format!("{REG_FIREWALL}\\PrivateProfile")),
        ("Public", format!("{REG_FIREWALL}\\PublicProfile")),
    ];
    let standard_path = format!("{REG_FIREWALL}\\StandardProfile");

    let mut result = Vec::new();
    for (name, path) in &profiles {
        let enabled = reg_dword(path, "EnableFirewall", 1).unwrap_or(
            reg_dword(&standard_path, "EnableFirewall", 1).unwrap_or(1),
        );
        let default_inbound = reg_dword(path, "DefaultInboundAction", 1).unwrap_or(
            reg_dword(&standard_path, "DefaultInboundAction", 1).unwrap_or(1),
        );
        let default_outbound = reg_dword(path, "DefaultOutboundAction", 0).unwrap_or(
            reg_dword(&standard_path, "DefaultOutboundAction", 0).unwrap_or(0),
        );

        result.push(json!({
            "profile": name,
            "enabled": enabled != 0,
            "default_inbound_action": if default_inbound == 1 { "Block" } else { "Allow" },
            "default_inbound_raw": default_inbound,
            "default_outbound_action": if default_outbound == 0 { "Allow" } else { "Block" },
            "default_outbound_raw": default_outbound,
        }));
    }

    serde_json::to_string_pretty(&result).map_err(AetherError::from)
}

fn action_tpm_status() -> Result<String, AetherError> {
    let script = r#"
        try {
            $tpm = Get-Tpm -ErrorAction Stop
            @{
                present = $true
                tpm_ready = $tpm.TpmReady
                tpm_present = $tpm.TpmPresent
                tpm_enabled = $tpm.TpmEnabled
                tpm_activated = $tpm.TpmActivated
                tpm_owned = $tpm.TpmOwned
                manufacturer_version = $tpm.ManufacturerVersion
                manufacturer_id = $tpm.ManufacturerId
                spec_version = $tpm.SpecVersion
                physical_presence_version = $tpm.PhysicalPresenceVersionInfo
                lockdown_state = $tpm.LockoutHealTime
            } | ConvertTo-Json
        } catch {
            @{ present = $false; error = $_.Exception.Message } | ConvertTo-Json
        }
    "#;
    let v = common::ps_json(script, TOOL)?;
    Ok(v.to_string())
}

fn action_secure_boot_status() -> Result<String, AetherError> {
    // First try registry
    let reg_val = reg_dword(REG_SECUREBOOT, "UEFISecureBootEnabled", 2)?;

    if reg_val != 2 {
        return Ok(json!({
            "secure_boot_enabled": reg_val == 1,
            "source": "registry",
            "uefi_secure_boot_enabled": reg_val
        }).to_string());
    }

    // Fallback to PowerShell
    let script = r#"
        try {
            $sb = Confirm-SecureBootUEFI -ErrorAction Stop
            @{ secure_boot_enabled = $sb } | ConvertTo-Json
        } catch {
            @{ secure_boot_enabled = $false; error = $_.Exception.Message } | ConvertTo-Json
        }
    "#;
    let v = common::ps_json(script, TOOL)?;
    Ok(v.to_string())
}

fn action_credential_guard_status() -> Result<String, AetherError> {
    let enabled = reg_dword(REG_CG, "Enabled", 0).unwrap_or(0);

    let script = format!(r#"
        try {{
            $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop
            @{{
                virtualization_based_security_status = $dg.VirtualizationBasedSecurityStatus
                required_security_properties = $dg.RequiredSecurityProperties
                available_security_properties = $dg.AvailableSecurityProperties
                configured_security_services = $dg.ConfiguredSecurityServices
                credential_guard_state = if ($dg.SecurityServicesConfigured -band 1) {{ "running" }} else {{ "not_configured" }}
            }} | ConvertTo-Json
        }} catch {{
            @{{
                virtualization_based_security_status = "unknown"
                credential_guard_state = if ({enabled} -eq 1) {{ "likely_running" }} else {{ "not_configured" }}
                registry_enabled = {enabled}
            }} | ConvertTo-Json
        }}
    "#);

    let v = common::ps_json(&script, TOOL)?;
    Ok(v.to_string())
}

fn action_lsa_protection_status() -> Result<String, AetherError> {
    let run_as_ppl = reg_dword(REG_LSA, "RunAsPPL", 0)?;

    Ok(json!({
        "lsa_protection_enabled": run_as_ppl != 0,
        "run_as_ppl": run_as_ppl,
        "description": match run_as_ppl {
            0 => "LSA runs as standard process (not protected)",
            1 => "LSA runs as Protected Process Light (PPL) — UEFI lock preferred",
            2 => "LSA runs as PPL with UEFI lock (most secure, requires UEFI variable)",
            _ => "Unknown value"
        }
    }).to_string())
}

fn action_exploit_protection() -> Result<String, AetherError> {
    let script = r#"
        $m = Get-ProcessMitigation -System -ErrorAction SilentlyContinue
        if (-not $m) {
            @{ error = "Get-ProcessMitigation not available on this system" } | ConvertTo-Json
            exit 0
        }
        $sehop = $m.SEHBOP
        $dep = $m.DEP
        @{
            cfg_enabled = $m.CFG.Enable -eq 1
            dep_enabled = if ($dep.Enable) { $true } else { $dep.SystemPolicy -eq 1 }
            dep_permanent = ($m.DEP.SystemPolicy -eq 3)
            force_aslr = $m.ASLR.ForceRelocateImages -eq 1
            bottom_up_aslr = $m.ASLR.BottomUp -eq 1
            high_entropy_aslr = $m.ASLR.HighEntropy -eq 1
            sehop_enabled = $sehop.Enable -eq 1
            sehop_telemetry = $sehop.TelemetryOnly -eq 1
            heap_integrity = $m.Heap.TerminateOnError -eq 1
            strict_handle_check = $m.StrictHandle.Enable -eq 1
            extension_point_disable = $m.ExtensionPoint.DisableExtensionPoints -eq 1
            block_remote_image_loads = $m.ImageLoad.BlockRemoteImageLoads -eq 1
            font_disable = $m.Font.Disable -eq 1
            system_mandatory_aslr = $m.ASLR.SystemPolicy -eq 1
            payload_enable_export_suppression = $m.Payload.EnableExportAddressFilter -eq 1
            payload_enable_import_suppression = $m.Payload.EnableImportAddressFilter -eq 1
        } | ConvertTo-Json
    "#;
    let v = common::ps_json(script, TOOL)?;
    Ok(v.to_string())
}

fn action_sandbox_status() -> Result<String, AetherError> {
    let raw = common::ps_output(
        "dism /online /get-featureinfo /featurename:Containers-DisposableClientVM",
        TOOL,
    )?;
    let installed = raw.contains("State : Enabled") || raw.contains("State: Enabled");

    Ok(json!({
        "sandbox_installed": installed,
        "feature_name": "Containers-DisposableClientVM",
        "dism_output_snippet": if raw.len() > 500 { raw[..500].to_string() } else { raw }
    }).to_string())
}

fn action_hyperv_status() -> Result<String, AetherError> {
    let script = r#"
        $hyperv = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction SilentlyContinue
        $hypervisor = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Hypervisor -ErrorAction SilentlyContinue
        $platform = Get-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -ErrorAction SilentlyContinue
        @{
            hyperv_all_state = $hyperv.State
            hyperv_hypervisor_state = $hypervisor.State
            hypervisor_platform_state = $platform.State
            hyperv_installed = $hyperv.State -eq 'Enabled'
        } | ConvertTo-Json
    "#;
    let v = common::ps_json(script, TOOL)?;
    Ok(v.to_string())
}

fn action_smartscreen_status() -> Result<String, AetherError> {
    let smartscreen_explorer = reg_string(REG_SMARTSCREEN_EXPLORER, "SmartScreenEnabled")?;
    let enable_smartscreen_policy = reg_dword(REG_SMARTSCREEN_POLICY, "EnableSmartScreen", 0)?;
    let smartscreen_apphost = reg_string(REG_SMARTSCREEN_APPHOST, "SmartScreenEnabled")?;

    Ok(json!({
        "smartscreen_explorer": smartscreen_explorer,
        "smartscreen_explorer_description": match smartscreen_explorer.as_deref() {
            Some("RequireAdmin") => "SmartScreen requires admin approval",
            Some("Prompt") => "SmartScreen prompts before running unrecognized apps",
            Some("Off") => "SmartScreen is disabled for Explorer",
            Some(other) => other,
            None => "Not configured"
        },
        "enable_smartscreen_policy": enable_smartscreen_policy,
        "smartscreen_store_apps": smartscreen_apphost,
        "smartscreen_store_apps_description": match smartscreen_apphost.as_deref() {
            Some("Block") => "SmartScreen blocks unrecognized Store apps",
            Some("Warn") => "SmartScreen warns about unrecognized Store apps",
            Some("Off") => "SmartScreen is disabled for Store apps",
            Some(other) => other,
            None => "Not configured (default: Warn)"
        }
    }).to_string())
}

fn action_windows_hello_status() -> Result<String, AetherError> {
    let script = r#"
        $ngcFolders = @()
        try {
            $ngcPath = "$env:SystemDrive\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\NGC"
            if (Test-Path $ngcPath) {
                $ngcFolders = Get-ChildItem $ngcPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
            }
        } catch { }
        $configured = $false
        $biometric = $false
        $pin = $false
        try {
            $passportKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{D6886603-9D2F-4D62-8EC9-9EF3D09B2F48}"
            $passport = Get-ItemProperty -Path $passportKey -ErrorAction SilentlyContinue
            if ($passport) { $configured = $true }
        } catch {}
        try {
            $biometricKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{8AF662BF-65A0-4D0A-A540-A338A999D36F}"
            $bio = Get-ItemProperty -Path $biometricKey -ErrorAction SilentlyContinue
            if ($bio) { $biometric = $true }
        } catch {}
        try {
            $pinKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{D6886603-9D2F-4D62-8EC9-9EF3D09B2F48}"
            $pinProp = Get-ItemProperty -Path $pinKey -Name "Disabled" -ErrorAction SilentlyContinue
            if ($pinProp -and $pinProp.Disabled -eq 0) { $pin = $true }
        } catch {}
        $helloConfigured = $ngcFolders.Count -gt 0
        @{
            configured = $helloConfigured -or $configured
            biometric_enabled = $biometric
            pin_enabled = $helloConfigured -or $pin
            face_enabled = $faceEnabled
            fingerprint_enabled = $fingerprintEnabled
            ngc_folders_count = $ngcFolders.Count
            note = "Face/fingerprint detection requires hardware sensor queries"
        } | ConvertTo-Json
    "#;
    let v = common::ps_json(script, TOOL)?;
    Ok(v.to_string())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Public entry point
// ═══════════════════════════════════════════════════════════════════════════════

/// Handle all security audit actions.
///
/// # Arguments
/// * `action` — the name of the security action (see table below).
/// * `params` — JSON parameters; write actions require `"force": true`.
///
/// # Supported actions
///
/// | Action                    | Description                          | Requires force |
/// |---------------------------|--------------------------------------|----------------|
/// | `audit_policies`          | Read audit policies                  | No             |
/// | `audit_set_policy`        | Enable/disable audit category        | Yes            |
/// | `uac_status`              | Read UAC configuration               | No             |
/// | `uac_set_level`           | Set UAC consent level (0-5)          | Yes            |
/// | `defender_status`         | Windows Defender status              | No             |
/// | `defender_threats`        | Detected threats                     | No             |
/// | `defender_scan`           | Run a Defender scan                  | Yes            |
/// | `defender_exclusions`     | List/add/remove exclusions           | Add/remove     |
/// | `applocker_rules`         | AppLocker rules                      | No             |
/// | `bitlocker_status`        | BitLocker status for all volumes     | No             |
/// | `firewall_profile_status` | Firewall profile status              | No             |
/// | `tpm_status`              | TPM status                           | No             |
/// | `secure_boot_status`      | Secure Boot status                   | No             |
/// | `credential_guard_status` | Credential Guard status              | No             |
/// | `lsa_protection_status`   | LSA RunAsPPL status                  | No             |
/// | `exploit_protection`      | System exploit protection mitigations| No             |
/// | `sandbox_status`          | Windows Sandbox status               | No             |
/// | `hyperv_status`           | Hyper-V status                       | No             |
/// | `smartscreen_status`      | SmartScreen configuration            | No             |
/// | `windows_hello_status`    | Windows Hello status                 | No             |
pub fn handle_security_audit(action: &str, params: Value) -> Result<String, AetherError> {
    let result = match action {
        "audit_policies" => action_audit_policies(),
        "audit_set_policy" => action_audit_set_policy(&params),
        "uac_status" => action_uac_status(),
        "uac_set_level" => action_uac_set_level(&params),
        "defender_status" => action_defender_status(),
        "defender_threats" => action_defender_threats(),
        "defender_scan" => action_defender_scan(&params),
        "defender_exclusions" => action_defender_exclusions(&params),
        "applocker_rules" => action_applocker_rules(),
        "bitlocker_status" => action_bitlocker_status(),
        "firewall_profile_status" => action_firewall_profile_status(),
        "tpm_status" => action_tpm_status(),
        "secure_boot_status" => action_secure_boot_status(),
        "credential_guard_status" => action_credential_guard_status(),
        "lsa_protection_status" => action_lsa_protection_status(),
        "exploit_protection" => action_exploit_protection(),
        "sandbox_status" => action_sandbox_status(),
        "hyperv_status" => action_hyperv_status(),
        "smartscreen_status" => action_smartscreen_status(),
        "windows_hello_status" => action_windows_hello_status(),
        unknown => Err(AetherError::invalid_param(
            ErrorContext::new(TOOL, "unknown"),
            format!("Unknown security action: {unknown}"),
        )),
    };

    match &result {
        Ok(_) => audit::log_success(TOOL, action, "completed"),
        Err(e) => audit::log_failure(TOOL, action, &e.to_string()),
    }
    result
}

