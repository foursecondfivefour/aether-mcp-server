#![allow(unsafe_code)]

//! Security audit tool for AETHER_01 MCP server.
//!
//! Provides 20 security audit and configuration actions covering audit policies,
//! UAC, Windows Defender, AppLocker, BitLocker, firewall, TPM, Secure Boot,
//! Credential Guard, LSA protection, exploit protection, sandbox/Hyper-V/Hello status.

use crate::audit;
use crate::command::{ParamType, SafeCommand};
use crate::error::{AetherError, ErrorContext};
use serde_json::{json, Value};
use windows_registry::LOCAL_MACHINE;

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Run a PowerShell command with timeout and return stdout as a trimmed String.
fn ps_output(script: &str) -> std::result::Result<String, AetherError> {
    SafeCommand::new("powershell.exe", "security", "ps_output")
        .timeout(30)
        .arg_unchecked("-NoProfile")
        .arg_unchecked("-NonInteractive")
        .arg_unchecked("-Command")
        .arg(script, ParamType::Text)?
        .output()
        .map(|s| s.trim().to_string())
}

/// Run PowerShell and parse output as JSON.
fn ps_json(script: &str) -> std::result::Result<Value, AetherError> {
    let raw = ps_output(script)?;
    if raw.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str(&raw).map_err(|e| {
        AetherError::Internal(format!(
            "Failed to parse PowerShell JSON output: {e} — raw: {raw}"
        ))
    })
}

/// Check that `force: true` is set in params for dangerous operations.
fn check_force(ctx: ErrorContext, params: &Value, action: &str) -> std::result::Result<(), AetherError> {
    if params.get("force").and_then(|v| v.as_bool()) != Some(true) {
        return Err(AetherError::permission_denied(ctx,
            format!("Action '{action}' requires \"force\": true")
        ));
    }
    Ok(())
}

/// Read a DWORD value from HKLM registry, returning a default if the key or value is missing.
fn reg_dword(path: &str, name: &str, default: u32) -> std::result::Result<u32, AetherError> {
    let key = match LOCAL_MACHINE.open(path) {
        Ok(k) => k,
        Err(_) => return Ok(default),
    };
    match key.get_u32(name) {
        Ok(v) => Ok(v),
        Err(_) => Ok(default),
    }
}

/// Read a string value from HKLM registry.
fn reg_string(path: &str, name: &str) -> std::result::Result<Option<String>, AetherError> {
    let key = match LOCAL_MACHINE.open(path) {
        Ok(k) => k,
        Err(_) => return Ok(None),
    };
    match key.get_string(name) {
        Ok(v) => Ok(Some(v)),
        Err(_) => Ok(None),
    }
}

/// Write a DWORD to HKLM registry. Requires administrator privileges.
fn reg_set_dword(path: &str, name: &str, value: u32) -> std::result::Result<(), AetherError> {
    let key = LOCAL_MACHINE
        .open(path)
        .map_err(|e| AetherError::Internal(format!("Cannot open registry key {path}: {e}")))?;
    key.set_u32(name, value)
        .map_err(|e| AetherError::Internal(format!("Cannot write {name} to {path}: {e}")))
}

/// Escape a single-quoted PowerShell string argument.
    #[allow(dead_code)]
    fn ps_escape(s: &str) -> String {
    s.replace('\'', "''")
}

// ── Action implementations ───────────────────────────────────────────────────

/// Parse `auditpol /get /category:*` output into structured JSON.
fn action_audit_policies() -> std::result::Result<String, AetherError> {
    let raw = ps_output("auditpol /get /category:*")?;
    let mut policies = Vec::new();
    let mut current_category = String::new();

    for line in raw.lines().skip(1) {
        let line = line.trim();
        if line.is_empty() || line.starts_with("----") {
            continue;
        }

        // Category header lines look like: "Category/Subcategory" alone or followed by status
        // The auditpol output format groups subcategories under categories
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        // Lines with indentation are subcategories; top-level items are categories
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

    Ok(serde_json::to_string_pretty(&policies)?)
}

/// Enable or disable an audit category via `auditpol /set`.
fn action_audit_set_policy(params: &Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("security_audit", "audit_set_policy");
    check_force(ctx.clone(), params, "audit_set_policy")?;

    let category = params
        .get("category")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AetherError::invalid_param(ctx.clone(), "category (string) is required"))?;

    let enable = params.get("enable").and_then(|v| v.as_bool()).unwrap_or(true);
    let enable_str = if enable { "enable" } else { "disable" };
    let subcategory = params
        .get("subcategory")
        .and_then(|v| v.as_str());

    let cmd = if let Some(sub) = subcategory {
        format!(
            "auditpol /set /subcategory:\"{}\" /success:{} /failure:{}",
            sub, enable_str, enable_str
        )
    } else {
        format!(
            "auditpol /set /category:\"{}\" /success:{} /failure:{}",
            category, enable_str, enable_str
        )
    };

    let _ = ps_output(&cmd)?;

    audit::log_forced("security", "audit_set_policy");

    Ok(json!({
        "action": "audit_set_policy",
        "category": category,
        "subcategory": subcategory,
        "enabled": enable,
        "status": "success"
    })
    .to_string())
}

/// Read UAC configuration from registry.
fn action_uac_status() -> std::result::Result<String, AetherError> {
    let path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";

    let enable_lua = reg_dword(path, "EnableLUA", 0)?;
    let consent_admin = reg_dword(path, "ConsentPromptBehaviorAdmin", 5)?;
    let consent_user = reg_dword(path, "ConsentPromptBehaviorUser", 3)?;
    let secure_desktop = reg_dword(path, "PromptOnSecureDesktop", 1)?;
    let filter_admin = reg_dword(path, "FilterAdministratorToken", 0)?;

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
    })
    .to_string())
}

/// Set UAC consent level.
fn action_uac_set_level(params: &Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("security_audit", "uac_set_level");
    check_force(ctx.clone(), params, "uac_set_level")?;

    let path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";

    let level = params
        .get("level")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| AetherError::invalid_param(ctx.clone(), "level (0-5 integer) is required"))?;

    if level > 5 {
        return Err(AetherError::invalid_param(ctx.clone(), "level must be 0-5"));
    }

    let level = level as u32;
    reg_set_dword(path, "ConsentPromptBehaviorAdmin", level)?;
    reg_set_dword(path, "EnableLUA", if level == 0 { 0 } else { 1 })?;

    audit::log_forced("security", "uac_set_level");

    Ok(json!({
        "action": "uac_set_level",
        "level": level,
        "status": "success",
        "note": "Registry values written. A reboot may be required for full effect."
    })
    .to_string())
}

/// Get Windows Defender status via PowerShell.
fn action_defender_status() -> std::result::Result<String, AetherError> {
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
    let v = ps_json(script)?;
    Ok(v.to_string())
}

/// Get detected threats from Windows Defender.
fn action_defender_threats() -> std::result::Result<String, AetherError> {
    let script = r#"
        Get-MpThreat -ErrorAction SilentlyContinue |
        Select-Object ThreatID, ThreatName, SeverityID, CategoryID, InitialDetectionTime, LastThreatStatusChangeTime, IsActive, Action, Resources, PendingActions, DidThreatExecute |
        ConvertTo-Json -Compress
    "#;
    let v = ps_json(script)?;
    Ok(v.to_string())
}

/// Run a Windows Defender scan.
fn action_defender_scan(params: &Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("security_audit", "defender_scan");
    check_force(ctx.clone(), params, "defender_scan")?;

    let scan_type = params
        .get("scan_type")
        .and_then(|v| v.as_str())
        .unwrap_or("QuickScan");
    let valid = ["QuickScan", "FullScan", "CustomScan"];
    if !valid.contains(&scan_type) {
        return Err(AetherError::invalid_param(ctx.clone(), format!(
                "scan_type must be one of: {}",
                valid.join(", ")
            )));
    }

    let script = format!("Start-MpScan -ScanType {scan_type} -ErrorAction Stop");
    let result = ps_output(&script)?;
    audit::log_forced("security", "defender_scan");

    Ok(json!({
        "action": "defender_scan",
        "scan_type": scan_type,
        "result": result,
        "status": "scan_initiated"
    })
    .to_string())
}

/// List, add, or remove Defender exclusions.
fn action_defender_exclusions(params: &Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("security_audit", "defender_exclusions");
    let operation = params
        .get("operation")
        .and_then(|v| v.as_str())
        .unwrap_or("list");

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
            let v = ps_json(script)?;
            Ok(v.to_string())
        }
        "add" => {
            check_force(ctx.clone(), params, "defender_exclusions/add")?;
            let exclusion_type = params
                .get("exclusion_type")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    AetherError::invalid_param(ctx.clone(),
                        "exclusion_type is required: path, process, extension, or ip",
                    )
                })?;
            let value = params
                .get("value")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AetherError::invalid_param(ctx.clone(), "value (string) is required"))?;

            let flag = match exclusion_type {
                "path" => "ExclusionPath",
                "process" => "ExclusionProcess",
                "extension" => "ExclusionExtension",
                "ip" => "ExclusionIpAddress",
                other => {
                    return Err(AetherError::invalid_param(ctx.clone(), format!(
                        "Unknown exclusion_type: {other}"
                    )))
                }
            };

            let script = format!("Add-MpPreference -{flag} \"{}\" -ErrorAction Stop", value);
            let _ = ps_output(&script)?;
            audit::log_forced("security", "defender_exclusions/add");

            Ok(json!({
                "action": "defender_exclusion_add",
                "exclusion_type": exclusion_type,
                "value": value,
                "status": "success"
            })
            .to_string())
        }
        "remove" => {
            check_force(ctx.clone(), params, "defender_exclusions/remove")?;
            let exclusion_type = params
                .get("exclusion_type")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    AetherError::invalid_param(ctx.clone(),
                        "exclusion_type is required: path, process, extension, or ip",
                    )
                })?;
            let value = params
                .get("value")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AetherError::invalid_param(ctx.clone(), "value (string) is required"))?;

            let flag = match exclusion_type {
                "path" => "ExclusionPath",
                "process" => "ExclusionProcess",
                "extension" => "ExclusionExtension",
                "ip" => "ExclusionIpAddress",
                other => {
                    return Err(AetherError::invalid_param(ctx.clone(), format!(
                        "Unknown exclusion_type: {other}"
                    )))
                }
            };

            let script = format!(
                "Remove-MpPreference -{flag} \"{}\" -ErrorAction Stop",
                value
            );
            let _ = ps_output(&script)?;
            audit::log_forced("security", "defender_exclusions/remove");

            Ok(json!({
                "action": "defender_exclusion_remove",
                "exclusion_type": exclusion_type,
                "value": value,
                "status": "success"
            })
            .to_string())
        }
        other => Err(AetherError::invalid_param(ctx.clone(), format!(
            "Unknown operation: {other}. Use list, add, or remove."
        ))),
    }
}

/// Retrieve AppLocker rules.
fn action_applocker_rules() -> std::result::Result<String, AetherError> {
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
    let v = ps_json(script)?;
    Ok(v.to_string())
}

/// BitLocker status for all volumes.
fn action_bitlocker_status() -> std::result::Result<String, AetherError> {
    let script = r#"
        Get-BitLockerVolume -ErrorAction SilentlyContinue |
        Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionMethod, VolumeType,
                      @{N='PercentageEncrypted';E={$_.EncryptionPercentage}},
                      KeyProtector, AutoUnlockEnabled, MetadataVersion |
        ConvertTo-Json -Compress
    "#;
    let v = ps_json(script)?;
    Ok(v.to_string())
}

/// Firewall profile status from registry.
fn action_firewall_profile_status() -> std::result::Result<String, AetherError> {
    let _base = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";

    let profiles = [
        ("Domain", r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"),
        ("Private", r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PrivateProfile"),
        ("Public", r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"),
    ];

    // Standard profile has the defaults
    let standard_path = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile";

    let mut result = Vec::new();
    for (name, path) in &profiles {
        // Try the profile-specific key first, then the standard
        let enabled = reg_dword(path, "EnableFirewall", 1).unwrap_or(
            reg_dword(standard_path, "EnableFirewall", 1).unwrap_or(1),
        );
        let default_inbound = reg_dword(path, "DefaultInboundAction", 1).unwrap_or(
            reg_dword(standard_path, "DefaultInboundAction", 1).unwrap_or(1),
        );
        let default_outbound = reg_dword(path, "DefaultOutboundAction", 0).unwrap_or(
            reg_dword(standard_path, "DefaultOutboundAction", 0).unwrap_or(0),
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

    Ok(serde_json::to_string_pretty(&result)?)
}

/// TPM status.
fn action_tpm_status() -> std::result::Result<String, AetherError> {
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
    let v = ps_json(script)?;
    Ok(v.to_string())
}

/// Secure Boot status.
fn action_secure_boot_status() -> std::result::Result<String, AetherError> {
    // First try registry
    let reg_path = r"SYSTEM\CurrentControlSet\Control\SecureBoot\State";
    let reg_val = reg_dword(reg_path, "UEFISecureBootEnabled", 2)?; // 2 = not present

    if reg_val != 2 {
        return Ok(json!({
            "secure_boot_enabled": reg_val == 1,
            "source": "registry",
            "uefi_secure_boot_enabled": reg_val
        })
        .to_string());
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
    let v = ps_json(script)?;
    Ok(v.to_string())
}

/// Credential Guard status.
fn action_credential_guard_status() -> std::result::Result<String, AetherError> {
    let path = r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard";
    let enabled = reg_dword(path, "Enabled", 0).unwrap_or(0);

    let script = r#"
        try {
            $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop
            @{
                virtualization_based_security_status = $dg.VirtualizationBasedSecurityStatus
                required_security_properties = $dg.RequiredSecurityProperties
                available_security_properties = $dg.AvailableSecurityProperties
                configured_security_services = $dg.ConfiguredSecurityServices
                credential_guard_state = if ($dg.SecurityServicesConfigured -band 1) { "running" } else { "not_configured" }
            } | ConvertTo-Json
        } catch {
            @{
                virtualization_based_security_status = "unknown"
                credential_guard_state = if ($enabled_flag) { "likely_running" } else { "not_configured" }
                registry_enabled = $enabled_flag
            } | ConvertTo-Json
        }
    "#;
    let script = format!(
        "$enabled_flag = {enabled}; {script}",
        enabled = enabled,
        script = script,
    );
    let v = ps_json(&script)?;
    Ok(v.to_string())
}

/// LSA Protection (RunAsPPL) status.
fn action_lsa_protection_status() -> std::result::Result<String, AetherError> {
    let path = r"SYSTEM\CurrentControlSet\Control\Lsa";
    let run_as_ppl = reg_dword(path, "RunAsPPL", 0)?;

    Ok(json!({
        "lsa_protection_enabled": run_as_ppl != 0,
        "run_as_ppl": run_as_ppl,
        "description": match run_as_ppl {
            0 => "LSA runs as standard process (not protected)",
            1 => "LSA runs as Protected Process Light (PPL) — UEFI lock preferred",
            2 => "LSA runs as PPL with UEFI lock (most secure, requires UEFI variable)",
            _ => "Unknown value"
        }
    })
    .to_string())
}

/// Exploit Protection (process mitigation) status.
fn action_exploit_protection() -> std::result::Result<String, AetherError> {
    let script = r#"
        $m = Get-ProcessMitigation -System -ErrorAction SilentlyContinue
        if (-not $m) {
            @{ error = "Get-ProcessMitigation not available on this system" } | ConvertTo-Json
            exit 0
        }

        # System-wide mitigations
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
    let v = ps_json(script)?;
    Ok(v.to_string())
}

/// Windows Sandbox status via DISM.
fn action_sandbox_status() -> std::result::Result<String, AetherError> {
    let raw = ps_output("dism /online /get-featureinfo /featurename:Containers-DisposableClientVM")?;
    let installed = raw.contains("State : Enabled") || raw.contains("State: Enabled");
    let _enabled = raw.contains("Enabled");

    Ok(json!({
        "sandbox_installed": installed,
        "feature_name": "Containers-DisposableClientVM",
        "dism_output_snippet": if raw.len() > 500 { raw[..500].to_string() } else { raw }
    })
    .to_string())
}

/// Hyper-V status from registry.
fn action_hyperv_status() -> std::result::Result<String, AetherError> {
    let _virt_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization";

    let _hypervisor_present = reg_dword(
        r"HARDWARE\ACPI\FADT",
        "", // HypervisorPresentBit is in FADT, but registry approach is simpler
        0,
    );

    // Check virtualization-related registry keys
    let _hyperv_enabled = reg_dword(
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization",
        "IsVirtualMachine",
        0,
    );

    // More reliable: check for Hyper-V hypervisor via PowerShell
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
    let v = ps_json(script)?;
    Ok(v.to_string())
}

/// SmartScreen status.
fn action_smartscreen_status() -> std::result::Result<String, AetherError> {
    let explorer_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer";
    let policy_path = r"SOFTWARE\Policies\Microsoft\Windows\System";
    let apphost_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost";

    let smartscreen_explorer = reg_string(explorer_path, "SmartScreenEnabled")?;
    let enable_smartscreen_policy = reg_dword(policy_path, "EnableSmartScreen", 0)?;
    let smartscreen_apphost = reg_string(apphost_path, "SmartScreenEnabled")?;

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
    })
    .to_string())
}

/// Windows Hello for Business status.
fn action_windows_hello_status() -> std::result::Result<String, AetherError> {
    // Registry path for credential providers
    let script = r#"
        # Check Windows Hello for Business configuration
        $helloKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers"
        $ngcKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"

        # Check if WHfB is provisioned via NGC folder
        $ngcFolders = @()
        try {
            $ngcPath = "$env:SystemDrive\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\NGC"
            if (Test-Path $ngcPath) {
                $ngcFolders = Get-ChildItem $ngcPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
            }
        } catch { }

        # Check registry for Hello configuration
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

        # Check biometric device availability
        $faceEnabled = $false
        $fingerprintEnabled = $false
        try {
            $bioDevices = Get-CimInstance -Namespace root\WMI -ClassName Win32_BIOSDevice -ErrorAction SilentlyContinue
        } catch {}

        # Simplified: check if Windows Hello is set up
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
    let v = ps_json(script)?;
    Ok(v.to_string())
}

// ── Public entry point ───────────────────────────────────────────────────────

/// Handle all security audit actions.
///
/// # Arguments
/// * `action` - The name of the security action to perform (see below).
/// * `params` - JSON parameters for the action. Many write actions require `"force": true`.
///
/// # Supported actions
///
/// | Action                  | Description                           | Requires force |
/// |-------------------------|---------------------------------------|----------------|
/// | `audit_policies`        | Read audit policies                   | No             |
/// | `audit_set_policy`      | Enable/disable audit category         | Yes            |
/// | `uac_status`            | Read UAC configuration                | No             |
/// | `uac_set_level`         | Set UAC consent level (0-5)           | Yes            |
/// | `defender_status`       | Windows Defender status               | No             |
/// | `defender_threats`      | Detected threats                      | No             |
/// | `defender_scan`         | Run a Defender scan                   | Yes            |
/// | `defender_exclusions`   | List/add/remove exclusions            | Add/remove     |
/// | `applocker_rules`       | AppLocker rules                       | No             |
/// | `bitlocker_status`      | BitLocker status for all volumes      | No             |
/// | `firewall_profile_status`| Firewall profile status               | No             |
/// | `tpm_status`            | TPM status                            | No             |
/// | `secure_boot_status`    | Secure Boot status                    | No             |
/// | `credential_guard_status`| Credential Guard status              | No             |
/// | `lsa_protection_status` | LSA RunAsPPL status                   | No             |
/// | `exploit_protection`    | System exploit protection mitigations | No             |
/// | `sandbox_status`        | Windows Sandbox status                | No             |
/// | `hyperv_status`         | Hyper-V status                        | No             |
/// | `smartscreen_status`    | SmartScreen configuration             | No             |
/// | `windows_hello_status`   | Windows Hello status                  | No             |
pub fn handle_security_audit(action: &str, params: Value) -> std::result::Result<String, AetherError> {
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
        unknown => Err(AetherError::invalid_param(ErrorContext::new("security_audit", "unknown"), format!(
            "Unknown security action: {unknown}"
        ))),
    };

    match &result {
        Ok(_) => audit::log_success("security", action, "completed"),
        Err(e) => audit::log_failure("security", action, &e.to_string()),
    }

    result
}
