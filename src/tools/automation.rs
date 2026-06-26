#![allow(unsafe_code)]

//! System automation tool for AETHER_01 MCP server.
//!
//! 12 actions covering Windows Event Log (query/write/channel listing/detail),
//! Scheduled Tasks (list/query/create/delete/run/enable/disable), and WMI queries.
//!
//! # Architecture
//!
//! PowerShell is used as the backend for Event Log and Scheduled Tasks because
//! the PowerShell API provides richer filtering, XML access, and task scheduling
//! than the raw Win32 Event Log APIs. WMI queries are also routed through
//! PowerShell (`Get-CimInstance`) for reliable COM lifecycle management.

use crate::audit;
use crate::command::{ParamType, SafeCommand};
use crate::error::{AetherError, ErrorContext};
use crate::tools::common;

use serde_json::{json, Value};

// ═══════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════

/// Tool name for audit logging.
const TOOL: &str = "automation";

/// Default number of events to return in a query.
const DEFAULT_MAX_EVENTS: u64 = 100;

/// Maximum number of events a query can return.
const MAX_EVENTS_LIMIT: u64 = 10_000;

// ═══════════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════════

/// Run an external command with SafeCommand and return trimmed stdout.
fn cmd_output(program: &str, args: &[&str]) -> Result<String, AetherError> {
    let mut cmd = SafeCommand::new(program, TOOL, "cmd_output").timeout(30);
    for arg in args {
        cmd = cmd.arg(*arg, ParamType::SafeString)?;
    }
    cmd.output().map(|s| s.trim().to_string())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Event Log actions
// ═══════════════════════════════════════════════════════════════════════════════

/// Query Event Log entries with optional filters.
fn action_event_query(params: &Value) -> Result<String, AetherError> {
    let log_name = common::get_param_str_opt(params, "log_name").unwrap_or("System");
    let max_results = common::get_param_u64(
        ErrorContext::new(TOOL, "event_query"),
        params,
        "max_results",
    )
    .unwrap_or(DEFAULT_MAX_EVENTS)
    .min(MAX_EVENTS_LIMIT);

    let mut filters = vec![format!("LogName='{}'", common::ps_escape(log_name))];

    if let Some(level) = params.get("level").and_then(|v| v.as_u64()) {
        if (1..=5).contains(&level) {
            filters.push(format!("Level={level}"));
        }
    }
    if let Some(ids) = params.get("event_ids").and_then(|v| v.as_array()) {
        let id_str: Vec<String> = ids
            .iter()
            .filter_map(|v| v.as_u64())
            .map(|i| i.to_string())
            .collect();
        if !id_str.is_empty() {
            filters.push(format!("ID={}", id_str.join(",")));
        }
    }
    if let Some(source) = common::get_param_str_opt(params, "source") {
        filters.push(format!("ProviderName='{}'", common::ps_escape(source)));
    }

    let mut time_clauses = Vec::new();
    if let Some(start) = common::get_param_str_opt(params, "time_start") {
        time_clauses.push(format!("StartTime>='{start}'"));
    }
    if let Some(end) = common::get_param_str_opt(params, "time_end") {
        time_clauses.push(format!("EndTime<='{end}'"));
    }

    let filter_str = filters.join("; ");
    let base_cmd = format!(
        "Get-WinEvent -FilterHashtable @{{{filter_str}}} -MaxEvents {max_results} -ErrorAction SilentlyContinue"
    );

    let v = if !time_clauses.is_empty() {
        let time_filter = time_clauses.join(" AND ");
        let cmd = format!("{base_cmd} | Where-Object {{ {time_filter} }} | Select-Object Id, LevelDisplayName, ProviderName, TimeCreated, Message | ConvertTo-Json -Compress");
        common::ps_json(&cmd, TOOL)?
    } else {
        let cmd = format!("{base_cmd} | Select-Object Id, LevelDisplayName, ProviderName, TimeCreated, Message | ConvertTo-Json -Compress");
        common::ps_json(&cmd, TOOL)?
    };
    Ok(v.to_string())
}

/// Write an event to the Windows Event Log.
fn action_event_write(params: &Value) -> Result<String, AetherError> {
    let ctx = ErrorContext::new(TOOL, "event_write");
    common::check_force(ctx.clone(), params, "event_write")?;

    let log_name = common::get_param_str(ctx.clone(), params, "log_name")?;
    let source = common::get_param_str(ctx.clone(), params, "source")?;
    let event_id = common::get_param_u64(ctx.clone(), params, "event_id")?;
    let message = common::get_param_str(ctx.clone(), params, "message")?;
    let event_type = common::get_param_str_opt(params, "event_type").unwrap_or("info");

    let entry_type = match event_type {
        "info" | "information" => "Information",
        "warning" | "warn" => "Warning",
        "error" | "err" => "Error",
        other => {
            return Err(AetherError::invalid_param(
                ctx.clone(),
                format!("event_type must be info/warning/error, got: {other}"),
            ))
        }
    };

    let ps_script = format!(
        "Write-EventLog -LogName \"{log_name}\" -Source \"{source}\" -EventId {event_id} -EntryType {entry_type} -Message \"{message}\" -ErrorAction Stop"
    );
    let _ = common::ps_output(&ps_script, TOOL)?;
    audit::log_forced(TOOL, "event_write");

    Ok(json!({
        "action": "event_write",
        "log_name": log_name,
        "source": source,
        "event_id": event_id,
        "event_type": entry_type,
        "status": "written"
    }).to_string())
}

/// List all available event log channels via `wevtutil el`.
fn action_event_channels() -> Result<String, AetherError> {
    let raw = cmd_output("wevtutil", &["el"])?;
    let channels: Vec<&str> = raw.lines().filter(|l| !l.trim().is_empty()).collect();

    Ok(json!({ "count": channels.len(), "channels": channels }).to_string())
}

/// Get detailed event information by record ID (includes XML).
fn action_event_details(params: &Value) -> Result<String, AetherError> {
    let ctx = ErrorContext::new(TOOL, "event_details");
    let log_name = common::get_param_str(ctx.clone(), params, "log_name")?;
    let record_id = common::get_param_u64(ctx.clone(), params, "event_record_id")?;

    let script = format!(
        "Get-WinEvent -LogName \"{log_name}\" -FilterXPath \"*[System[EventRecordID={record_id}]]\" -ErrorAction Stop | ForEach-Object {{ [xml]$xml = $_.ToXml(); @{{ id = $_.Id; level = $_.LevelDisplayName; provider = $_.ProviderName; time_created = $_.TimeCreated; machine = $_.MachineName; message = $_.Message; xml = $xml.OuterXml }} }} | ConvertTo-Json -Depth 10"
    );
    let v = common::ps_json(&script, TOOL)?;
    Ok(v.to_string())
}

// ═══════════════════════════════════════════════════════════════════════════════
// Scheduled Task actions
// ═══════════════════════════════════════════════════════════════════════════════

/// List all scheduled tasks via PowerShell.
fn action_task_list() -> Result<String, AetherError> {
    let script = r#"
        Get-ScheduledTask -ErrorAction SilentlyContinue |
        Select-Object TaskName, TaskPath, State, Description,
                      @{N='NextRunTime';E={$_.NextRunTime}},
                      @{N='LastRunTime';E={$_.LastRunTime}},
                      @{N='LastTaskResult';E={$_.LastTaskResult}} |
        ConvertTo-Json -Compress
    "#;
    let v = common::ps_json(script, TOOL)?;
    Ok(v.to_string())
}

/// Query detailed information about a specific scheduled task by path.
fn action_task_query(params: &Value) -> Result<String, AetherError> {
    let ctx = ErrorContext::new(TOOL, "task_query");
    let task_path = common::get_param_str(ctx.clone(), params, "task_path")?;
    let escaped = common::ps_escape(task_path);

    // We wrap the PowerShell in a block so PS can run it immediately.
    let script = format!(
        r#"
        $task = Get-ScheduledTask -TaskPath '\' -TaskName '{escaped}' -ErrorAction Stop
        $info = Get-ScheduledTaskInfo -TaskPath $task.TaskPath -TaskName $task.TaskName -ErrorAction SilentlyContinue
        $triggers = foreach ($t in $task.Triggers) {{ @{{ type = $t.CimClass.CimClassName; enabled = $t.Enabled; details = ($t | ConvertTo-Json -Compress -Depth 3) }}  }}
        $actions = foreach ($a in $task.Actions) {{ @{{ type = $a.CimClass.CimClassName; details = ($a | ConvertTo-Json -Compress -Depth 3) }}  }}
        @{{{{
            name = $task.TaskName; path = $task.TaskPath; state = $task.State
            description = $task.Description; author = $task.Author
            principal = @{{ user_id = $task.Principal.UserId; logon_type = $task.Principal.LogonType; run_level = $task.Principal.RunLevel }}
            triggers = @($triggers); actions = @($actions)
            settings = @{{{{
                allow_demand_start = $task.Settings.AllowDemandStart; allow_hard_terminate = $task.Settings.AllowHardTerminate
                compatibility = $task.Settings.Compatibility; hidden = $task.Settings.Hidden
                run_only_if_idle = $task.Settings.RunOnlyIfIdle; run_only_if_network_available = $task.Settings.RunOnlyIfNetworkAvailable
                start_when_available = $task.Settings.StartWhenAvailable; priority = $task.Settings.Priority
                restart_count = $task.Settings.RestartCount; restart_interval = $task.Settings.RestartInterval
                execution_time_limit = $task.Settings.ExecutionTimeLimit
            }}}}
            last_run_time = $info.LastRunTime; last_task_result = $info.LastTaskResult
            next_run_time = $info.NextRunTime; number_of_missed_runs = $info.NumberOfMissedRuns
        }}}} | ConvertTo-Json -Depth 4
    "#
    );

    let v = common::ps_json(&script, TOOL)?;
    Ok(v.to_string())
}

/// Create a new scheduled task via `schtasks`.
fn action_task_create(params: &Value) -> Result<String, AetherError> {
    let ctx = ErrorContext::new(TOOL, "task_create");
    common::check_force(ctx.clone(), params, "task_create")?;

    let task_name = common::get_param_str(ctx.clone(), params, "task_name")?;
    let program = common::get_param_str(ctx.clone(), params, "program")?;
    let schedule = common::get_param_str_opt(params, "schedule").unwrap_or("once");
    let arguments = common::get_param_str_opt(params, "arguments").unwrap_or("");
    let start_time = common::get_param_str_opt(params, "start_time").unwrap_or("00:00");
    let run_level = common::get_param_str_opt(params, "run_level").unwrap_or("highest");
    let username = common::get_param_str_opt(params, "username").unwrap_or("SYSTEM");
    let password = common::get_param_str_opt(params, "password");
    let days = common::get_param_str_opt(params, "days").unwrap_or("*");
    let months = common::get_param_str_opt(params, "months").unwrap_or("*");

    let sc_args = match schedule {
        "once" => format!("/sc once /st {start_time}"),
        "daily" => format!("/sc daily /st {start_time}"),
        "weekly" => format!("/sc weekly /d {days} /st {start_time}"),
        "monthly" => format!("/sc monthly /m {months} /st {start_time}"),
        "onstart" => "/sc onstart".to_string(),
        "onlogon" => "/sc onlogon".to_string(),
        "onidle" => "/sc onidle".to_string(),
        other => {
            return Err(AetherError::invalid_param(
                ctx.clone(),
                format!("Unknown schedule type: {other}"),
            ))
        }
    };

    let tr = if arguments.is_empty() {
        program.to_string()
    } else {
        format!("{program} {arguments}")
    };

    let mut cmd_line = format!(
        "schtasks /create /tn \"{task_name}\" /tr \"{tr}\" {sc_args} /ru \"{username}\" /rl {run_level} /f"
    );
    if let Some(pwd) = password {
        cmd_line.push_str(&format!(" /rp \"{pwd}\""));
    }

    let _ = common::ps_output(&format!("& {cmd_line}"), TOOL)?;
    audit::log_forced(TOOL, "task_create");

    Ok(json!({
        "action": "task_create",
        "task_name": task_name,
        "program": program,
        "schedule": schedule,
        "status": "created"
    }).to_string())
}

/// Delete a scheduled task via `schtasks`.
fn action_task_delete(params: &Value) -> Result<String, AetherError> {
    let ctx = ErrorContext::new(TOOL, "task_delete");
    common::check_force(ctx.clone(), params, "task_delete")?;

    let task_path = common::get_param_str(ctx.clone(), params, "task_path")?;
    let _ = cmd_output("schtasks", &["/delete", "/tn", task_path, "/f"])?;
    audit::log_forced(TOOL, "task_delete");

    Ok(json!({
        "action": "task_delete",
        "task_path": task_path,
        "status": "deleted"
    }).to_string())
}

/// Run a scheduled task immediately via `schtasks /run`.
fn action_task_run(params: &Value) -> Result<String, AetherError> {
    let ctx = ErrorContext::new(TOOL, "task_run");
    let task_path = common::get_param_str(ctx.clone(), params, "task_path")?;
    let output = cmd_output("schtasks", &["/run", "/tn", task_path])?;

    Ok(json!({
        "action": "task_run",
        "task_path": task_path,
        "result": output,
        "status": "initiated"
    }).to_string())
}

/// Enable a scheduled task via `schtasks /change /enable`.
fn action_task_enable(params: &Value) -> Result<String, AetherError> {
    let ctx = ErrorContext::new(TOOL, "task_enable");
    let task_path = common::get_param_str(ctx.clone(), params, "task_path")?;
    let _ = cmd_output("schtasks", &["/change", "/tn", task_path, "/enable"])?;

    Ok(json!({
        "action": "task_enable",
        "task_path": task_path,
        "status": "enabled"
    }).to_string())
}

/// Disable a scheduled task via `schtasks /change /disable`.
fn action_task_disable(params: &Value) -> Result<String, AetherError> {
    let ctx = ErrorContext::new(TOOL, "task_disable");
    let task_path = common::get_param_str(ctx.clone(), params, "task_path")?;
    let _ = cmd_output("schtasks", &["/change", "/tn", task_path, "/disable"])?;

    Ok(json!({
        "action": "task_disable",
        "task_path": task_path,
        "status": "disabled"
    }).to_string())
}

// ═══════════════════════════════════════════════════════════════════════════════
// WMI Query
// ═══════════════════════════════════════════════════════════════════════════════

/// Execute a WMI SELECT query via PowerShell `Get-CimInstance`.
///
/// Uses PowerShell as the backend because it handles COM lifecycle,
/// apartment model negotiation, and namespace resolution reliably across
/// all Windows 10/11 editions in a multi-threaded Tokio runtime.
fn action_wmi_query(params: &Value) -> Result<String, AetherError> {
    let ctx = ErrorContext::new(TOOL, "wmi_query");
    let query = common::get_param_str(ctx.clone(), params, "query")?;
    let trimmed = query.trim();

    if !trimmed.to_uppercase().starts_with("SELECT") {
        return Err(AetherError::invalid_param(
            ctx.clone(),
            "Only SELECT WQL queries are supported. Non-SELECT queries are rejected.",
        ));
    }
    if trimmed.len() > 4096 {
        return Err(AetherError::invalid_param(
            ctx.clone(),
            "Query exceeds maximum length of 4096 characters",
        ));
    }

    let namespace = common::get_param_str_opt(params, "namespace").unwrap_or("ROOT\\CIMV2");
    let max_rows = common::get_param_u64(
        ErrorContext::new(TOOL, "wmi_query"),
        params,
        "max_results",
    )
    .unwrap_or(1000)
    .min(10000);

    let escaped_query = common::ps_escape(trimmed);
    let escaped_ns = common::ps_escape(namespace);

    let script = format!(
        r#"
        $ErrorActionPreference = 'Stop'
        $results = Get-CimInstance -Query '{escaped_query}' -Namespace '{escaped_ns}' -ErrorAction Stop |
            Select-Object -First {max_rows}
        if ($null -eq $results) {{ @() | ConvertTo-Json -Compress; exit 0 }}
        $results | ForEach-Object {{
            $obj = @{{}}
            $_.PSObject.Properties | ForEach-Object {{
                $val = $_.Value
                if ($val -is [System.Management.Automation.SwitchParameter]) {{
                    $val = $val.IsPresent
                }}
                $obj[$_.Name] = $val
            }}
            [PSCustomObject]$obj
        }} | ConvertTo-Json -Compress -Depth 4
    "#
    );

    // Use SafeCommand directly (not common::ps_output) to avoid the .trim() that
    // ps_output applies, as structured JSON output must not be trimmed.
    let result = SafeCommand::new("powershell.exe", TOOL, "wmi_query")
        .timeout(30)
        .arg_unchecked("-NoProfile")
        .arg_unchecked("-NonInteractive")
        .arg_unchecked("-Command")
        .arg(&script, ParamType::Text)?
        .output()?;
    Ok(result)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Public entry point
// ═══════════════════════════════════════════════════════════════════════════════

/// Handle all system automation actions.
///
/// # Arguments
///
/// * `action` — the name of the automation action (see table below).
/// * `params` — JSON parameters; write/create/delete actions require `"force": true`.
///
/// # Supported actions
///
/// | Action            | Description                          | Requires force |
/// |-------------------|--------------------------------------|----------------|
/// | `event_query`     | Query Event Log with filters         | No             |
/// | `event_write`     | Write an event to Event Log          | Yes            |
/// | `event_channels`  | List available event log channels    | No             |
/// | `event_details`   | Detailed event by record ID          | No             |
/// | `task_list`       | List all scheduled tasks             | No             |
/// | `task_query`      | Query task details by path           | No             |
/// | `task_create`     | Create a new scheduled task          | Yes            |
/// | `task_delete`     | Delete a scheduled task              | Yes            |
/// | `task_run`        | Run a scheduled task immediately     | No             |
/// | `task_enable`     | Enable a scheduled task              | No             |
/// | `task_disable`    | Disable a scheduled task             | No             |
/// | `wmi_query`       | Execute a WMI WQL SELECT query       | No             |
pub fn handle_system_automation(action: &str, params: Value) -> Result<String, AetherError> {
    let result = match action {
        "event_query" => action_event_query(&params),
        "event_write" => action_event_write(&params),
        "event_channels" => action_event_channels(),
        "event_details" => action_event_details(&params),
        "task_list" => action_task_list(),
        "task_query" => action_task_query(&params),
        "task_create" => action_task_create(&params),
        "task_delete" => action_task_delete(&params),
        "task_run" => action_task_run(&params),
        "task_enable" => action_task_enable(&params),
        "task_disable" => action_task_disable(&params),
        "wmi_query" => action_wmi_query(&params),
        unknown => Err(AetherError::invalid_param(
            ErrorContext::new(TOOL, "unknown"),
            format!("Unknown automation action: {unknown}"),
        )),
    };

    match &result {
        Ok(_) => audit::log_success(TOOL, action, "completed"),
        Err(e) => audit::log_failure(TOOL, action, &e.to_string()),
    }
    result
}
