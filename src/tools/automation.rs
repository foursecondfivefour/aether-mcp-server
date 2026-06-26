#![allow(unsafe_code)]

//! System automation tool for AETHER_01 MCP server.
//!
//! Provides 12 actions covering Windows Event Log (query/write/channel listing/detail),
//! Scheduled Tasks (list/query/create/delete/run/enable/disable), and WMI queries.

use crate::audit;
use crate::command::{ParamType, SafeCommand};
use crate::error::{AetherError, ErrorContext};
use serde_json::{json, Value};
use std::time::Duration;

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Run a PowerShell command with timeout and return stdout as a trimmed String.
fn ps_output(script: &str) -> std::result::Result<String, AetherError> {
    SafeCommand::new("powershell.exe", "automation", "ps_output")
        .timeout(30)
        .arg_unchecked("-NoProfile")
        .arg_unchecked("-NonInteractive")
        .arg_unchecked("-Command")
        .arg(script, ParamType::Text)?
        .output()
        .map(|s| s.trim().to_string())
}

/// Run a raw command and return stdout.
fn cmd_output(program: &str, args: &[&str]) -> std::result::Result<String, AetherError> {
    let mut cmd = SafeCommand::new(program, "automation", "cmd_output").timeout(30);
    // All args are treated as SafeString validated params
    for arg in args {
        cmd = cmd.arg(*arg, ParamType::SafeString)?;
    }
    cmd.output().map(|s| s.trim().to_string())
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

/// Escape a single-quoted PowerShell string argument.
fn ps_escape(s: &str) -> String {
    s.replace('\'', "''")
}

// ── Event Log actions ────────────────────────────────────────────────────────

/// Query Event Log with filters.
fn action_event_query(params: &Value) -> std::result::Result<String, AetherError> {
    let log_name = params
        .get("log_name")
        .and_then(|v| v.as_str())
        .unwrap_or("System");

    let max_results = params
        .get("max_results")
        .and_then(|v| v.as_u64())
        .unwrap_or(100)
        .min(10000);

    let mut filters = vec![format!("LogName='{}'", ps_escape(log_name))];

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

    if let Some(source) = params.get("source").and_then(|v| v.as_str()) {
        filters.push(format!("ProviderName='{}'", ps_escape(source)));
    }

    let mut time_clauses = Vec::new();
    if let Some(start) = params.get("time_start").and_then(|v| v.as_str()) {
        time_clauses.push(format!("StartTime>='{start}'"));
    }
    if let Some(end) = params.get("time_end").and_then(|v| v.as_str()) {
        time_clauses.push(format!("EndTime<='{end}'"));
    }

    let filter_str = filters.join("; ");
    let script = if !time_clauses.is_empty() {
        let time_filter = time_clauses.join(" AND ");
        format!(
            "Get-WinEvent -FilterHashtable @{{{filter_str}}} -MaxEvents {max_results} -ErrorAction SilentlyContinue | Where-Object {{ {time_filter} }} | Select-Object Id, LevelDisplayName, ProviderName, TimeCreated, Message | ConvertTo-Json -Compress"
        )
    } else {
        format!(
            "Get-WinEvent -FilterHashtable @{{{filter_str}}} -MaxEvents {max_results} -ErrorAction SilentlyContinue | Select-Object Id, LevelDisplayName, ProviderName, TimeCreated, Message | ConvertTo-Json -Compress"
        )
    };

    let v = ps_json(&script)?;
    Ok(v.to_string())
}

/// Write an event to the Event Log.
fn action_event_write(params: &Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("system_automation", "event_write");
    check_force(ctx.clone(), params, "event_write")?;

    let log_name = params
        .get("log_name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AetherError::invalid_param(ctx.clone(), "log_name (string) is required"))?;

    let source = params
        .get("source")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AetherError::invalid_param(ctx.clone(), "source (string) is required"))?;

    let event_id = params
        .get("event_id")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| AetherError::invalid_param(ctx.clone(), "event_id (integer) is required"))?;

    let message = params
        .get("message")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AetherError::invalid_param(ctx.clone(), "message (string) is required"))?;

    let event_type = params
        .get("event_type")
        .and_then(|v| v.as_str())
        .unwrap_or("info");

    let entry_type = match event_type {
        "info" | "information" => "Information",
        "warning" | "warn" => "Warning",
        "error" | "err" => "Error",
        other => {
            return Err(AetherError::invalid_param(ctx.clone(), format!(
                "event_type must be info/warning/error, got: {other}"
            )))
        }
    };

    let ps_script = format!(
        "Write-EventLog -LogName \"{log_name}\" -Source \"{source}\" -EventId {event_id} -EntryType {entry_type} -Message \"{message}\" -ErrorAction Stop"
    );

    let _ = ps_output(&ps_script)?;
    audit::log_forced("automation", "event_write");

    Ok(json!({
        "action": "event_write",
        "log_name": log_name,
        "source": source,
        "event_id": event_id,
        "event_type": entry_type,
        "status": "written"
    })
    .to_string())
}

/// List available event log channels.
fn action_event_channels() -> std::result::Result<String, AetherError> {
    let raw = cmd_output("wevtutil", &["el"])?;
    let channels: Vec<&str> = raw.lines().filter(|l| !l.trim().is_empty()).collect();

    Ok(json!({
        "count": channels.len(),
        "channels": channels
    })
    .to_string())
}

/// Get detailed event information by record ID.
fn action_event_details(params: &Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("system_automation", "event_details");
    let log_name = params
        .get("log_name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AetherError::invalid_param(ctx.clone(), "log_name (string) is required"))?;

    let record_id = params
        .get("event_record_id")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| AetherError::invalid_param(ctx.clone(), "event_record_id (integer) is required"))?;

    let script = format!(
        "Get-WinEvent -LogName \"{log_name}\" -FilterXPath \"*[System[EventRecordID={record_id}]]\" -ErrorAction Stop | ForEach-Object {{ [xml]$xml = $_.ToXml(); @{{ id = $_.Id; level = $_.LevelDisplayName; provider = $_.ProviderName; time_created = $_.TimeCreated; machine = $_.MachineName; message = $_.Message; xml = $xml.OuterXml }} }} | ConvertTo-Json -Depth 10"
    );

    let v = ps_json(&script)?;
    Ok(v.to_string())
}

// ── Scheduled Task actions ───────────────────────────────────────────────────

/// List all scheduled tasks via PowerShell.
fn action_task_list() -> std::result::Result<String, AetherError> {
    let script = r#"
        Get-ScheduledTask -ErrorAction SilentlyContinue |
        Select-Object TaskName, TaskPath, State, Description,
                      @{N='NextRunTime';E={$_.NextRunTime}},
                      @{N='LastRunTime';E={$_.LastRunTime}},
                      @{N='LastTaskResult';E={$_.LastTaskResult}} |
        ConvertTo-Json -Compress
    "#;
    let v = ps_json(script)?;
    Ok(v.to_string())
}

/// Query detailed information about a specific task.
fn action_task_query(params: &Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("system_automation", "task_query");
    let task_path = params
        .get("task_path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AetherError::invalid_param(ctx.clone(), "task_path (string) is required"))?;

    let escaped = ps_escape(task_path);
    let script = format!(
        r#"
        $task = Get-ScheduledTask -TaskPath '\' -TaskName '{escaped}' -ErrorAction Stop
        $info = Get-ScheduledTaskInfo -TaskPath $task.TaskPath -TaskName $task.TaskName -ErrorAction SilentlyContinue
        $triggers = foreach ($t in $task.Triggers) {{ @{{ type = $t.CimClass.CimClassName; enabled = $t.Enabled; details = ($t | ConvertTo-Json -Compress -Depth 3) }}  }}
        $actions = foreach ($a in $task.Actions) {{ @{{ type = $a.CimClass.CimClassName; details = ($a | ConvertTo-Json -Compress -Depth 3) }}  }}
        @{{
            name = $task.TaskName
            path = $task.TaskPath
            state = $task.State
            description = $task.Description
            author = $task.Author
            principal = @{{ user_id = $task.Principal.UserId; logon_type = $task.Principal.LogonType; run_level = $task.Principal.RunLevel }}
            triggers = @($triggers)
            actions = @($actions)
            settings = @{{
                allow_demand_start = $task.Settings.AllowDemandStart
                allow_hard_terminate = $task.Settings.AllowHardTerminate
                compatibility = $task.Settings.Compatibility
                disallow_start_if_on_batteries = $task.Settings.DisallowStartIfOnBatteries
                hidden = $task.Settings.Hidden
                run_only_if_idle = $task.Settings.RunOnlyIfIdle
                run_only_if_network_available = $task.Settings.RunOnlyIfNetworkAvailable
                start_when_available = $task.Settings.StartWhenAvailable
                multiple_instances = $task.Settings.MultipleInstances
                priority = $task.Settings.Priority
                restart_count = $task.Settings.RestartCount
                restart_interval = $task.Settings.RestartInterval
                stop_if_going_on_batteries = $task.Settings.StopIfGoingOnBatteries
                execution_time_limit = $task.Settings.ExecutionTimeLimit
                delete_expired_task_after = $task.Settings.DeleteExpiredTaskAfter
            }}
            last_run_time = $info.LastRunTime
            last_task_result = $info.LastTaskResult
            next_run_time = $info.NextRunTime
            number_of_missed_runs = $info.NumberOfMissedRuns
        }} | ConvertTo-Json -Depth 4
    "#
    );

    let v = ps_json(&script)?;
    Ok(v.to_string())
}

/// Create a new scheduled task via schtasks.
fn action_task_create(params: &Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("system_automation", "task_create");
    check_force(ctx.clone(), params, "task_create")?;

    let task_name = params
        .get("task_name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AetherError::invalid_param(ctx.clone(), "task_name (string) is required"))?;

    let program = params
        .get("program")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AetherError::invalid_param(ctx.clone(), "program (string) is required"))?;

    let schedule = params
        .get("schedule")
        .and_then(|v| v.as_str())
        .unwrap_or("once");

    let arguments = params
        .get("arguments")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let start_time = params
        .get("start_time")
        .and_then(|v| v.as_str())
        .unwrap_or("00:00");

    let run_level = params
        .get("run_level")
        .and_then(|v| v.as_str())
        .unwrap_or("highest");

    let username = params
        .get("username")
        .and_then(|v| v.as_str())
        .unwrap_or("SYSTEM");

    let password = params
        .get("password")
        .and_then(|v| v.as_str());

    let days = params
        .get("days")
        .and_then(|v| v.as_str())
        .unwrap_or("*");

    let months = params
        .get("months")
        .and_then(|v| v.as_str())
        .unwrap_or("*");

    let sc_args = match schedule {
        "once" => format!("/sc once /st {start_time}"),
        "daily" => format!("/sc daily /st {start_time}"),
        "weekly" => format!("/sc weekly /d {days} /st {start_time}"),
        "monthly" => format!("/sc monthly /m {months} /st {start_time}"),
        "onstart" => String::from("/sc onstart"),
        "onlogon" => String::from("/sc onlogon"),
        "onidle" => String::from("/sc onidle"),
        other => {
            return Err(AetherError::invalid_param(ctx.clone(), format!(
                "Unknown schedule type: {other}"
            )))
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

    let _ = ps_output(&format!("& {cmd_line}"))?;
    audit::log_forced("automation", "task_create");

    Ok(json!({
        "action": "task_create",
        "task_name": task_name,
        "program": program,
        "schedule": schedule,
        "status": "created"
    })
    .to_string())
}

/// Delete a scheduled task.
fn action_task_delete(params: &Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("system_automation", "task_delete");
    check_force(ctx.clone(), params, "task_delete")?;

    let task_path = params
        .get("task_path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AetherError::invalid_param(ctx.clone(), "task_path (string) is required"))?;

    let _ = cmd_output("schtasks", &["/delete", "/tn", task_path, "/f"])?;
    audit::log_forced("automation", "task_delete");

    Ok(json!({
        "action": "task_delete",
        "task_path": task_path,
        "status": "deleted"
    })
    .to_string())
}

/// Run a scheduled task immediately.
fn action_task_run(params: &Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("system_automation", "task_run");
    let task_path = params
        .get("task_path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AetherError::invalid_param(ctx.clone(), "task_path (string) is required"))?;

    let output = cmd_output("schtasks", &["/run", "/tn", task_path])?;

    Ok(json!({
        "action": "task_run",
        "task_path": task_path,
        "result": output,
        "status": "initiated"
    })
    .to_string())
}

/// Enable a scheduled task.
fn action_task_enable(params: &Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("system_automation", "task_enable");
    let task_path = params
        .get("task_path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AetherError::invalid_param(ctx.clone(), "task_path (string) is required"))?;

    let _ = cmd_output("schtasks", &["/change", "/tn", task_path, "/enable"])?;

    Ok(json!({
        "action": "task_enable",
        "task_path": task_path,
        "status": "enabled"
    })
    .to_string())
}

/// Disable a scheduled task.
fn action_task_disable(params: &Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("system_automation", "task_disable");
    let task_path = params
        .get("task_path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AetherError::invalid_param(ctx.clone(), "task_path (string) is required"))?;

    let _ = cmd_output("schtasks", &["/change", "/tn", task_path, "/disable"])?;

    Ok(json!({
        "action": "task_disable",
        "task_path": task_path,
        "status": "disabled"
    })
    .to_string())
}

// ── WMI Query ────────────────────────────────────────────────────────────────

/// Execute a WMI query via PowerShell Get-CimInstance with strict validation.
///
/// Uses PowerShell as the backend because it handles COM lifecycle,
/// apartment model negotiation, and namespace resolution reliably across
/// all Windows 10/11 editions in a multi-threaded Tokio runtime.
///
/// The COM-based alternative (CoInitializeEx → IWbemLocator → IWbemServices →
/// ExecQuery → IEnumWbemClassObject) would require the `windows` crate's
/// `Win32_System_Wmi` COM interface bindings. PowerShell is preferred here
/// for stability and is semantically equivalent.
fn action_wmi_query(params: &Value) -> std::result::Result<String, AetherError> {
    let ctx = ErrorContext::new("system_automation", "wmi_query");
    let query = params
        .get("query")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AetherError::invalid_param(ctx.clone(), "query (WQL string) is required"))?;

    let trimmed = query.trim();
    if !trimmed.to_uppercase().starts_with("SELECT") {
        return Err(AetherError::invalid_param(ctx.clone(),
            "Only SELECT WQL queries are supported. Non-SELECT queries are rejected.",
        ));
    }

    if trimmed.len() > 4096 {
        return Err(AetherError::invalid_param(ctx.clone(),
            "Query exceeds maximum length of 4096 characters",
        ));
    }

    let namespace = params
        .get("namespace")
        .and_then(|v| v.as_str())
        .unwrap_or("ROOT\\CIMV2");

    let max_rows = params
        .get("max_results")
        .and_then(|v| v.as_u64())
        .unwrap_or(1000)
        .min(10000);

    let escaped_query = ps_escape(trimmed);
    let escaped_ns = ps_escape(namespace);

    let script = format!(
        r#"
        $ErrorActionPreference = 'Stop'
        $results = Get-CimInstance -Query '{escaped_query}' -Namespace '{escaped_ns}' -ErrorAction Stop |
            Select-Object -First {max_rows}
        if ($null -eq $results) {{ @() | ConvertTo-Json -Compress; exit 0 }}
        # Convert all properties to a JSON array, handling SwitchParameter types
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

    let result = SafeCommand::new("powershell.exe", "automation", "wmi_query")
        .timeout(30)
        .arg_unchecked("-NoProfile")
        .arg_unchecked("-NonInteractive")
        .arg_unchecked("-Command")
        .arg(&script, ParamType::Text)?
        .output()?;
    return Ok(result);
}

// ── Public entry point ───────────────────────────────────────────────────────

/// Handle all system automation actions.
///
/// # Arguments
/// * `action` - The name of the automation action to perform (see below).
/// * `params` - JSON parameters for the action. Write/create/delete actions require `"force": true`.
///
/// # Supported actions
///
/// | Action            | Description                              | Requires force |
/// |-------------------|------------------------------------------|----------------|
/// | `event_query`     | Query Event Log with filters             | No             |
/// | `event_write`     | Write an event to Event Log              | Yes            |
/// | `event_channels`  | List available event log channels        | No             |
/// | `event_details`   | Detailed event by record ID              | No             |
/// | `task_list`       | List all scheduled tasks                 | No             |
/// | `task_query`      | Query task details by path               | No             |
/// | `task_create`     | Create a new scheduled task              | Yes            |
/// | `task_delete`     | Delete a scheduled task                  | Yes            |
/// | `task_run`        | Run a scheduled task immediately         | No             |
/// | `task_enable`     | Enable a scheduled task                  | No             |
/// | `task_disable`    | Disable a scheduled task                 | No             |
/// | `wmi_query`       | Execute a WMI WQL SELECT query           | No             |
pub fn handle_system_automation(action: &str, params: Value) -> std::result::Result<String, AetherError> {
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
        unknown => Err(AetherError::invalid_param(ErrorContext::new("system_automation", "unknown"), format!(
            "Unknown automation action: {unknown}"
        ))),
    };

    match &result {
        Ok(_) => audit::log_success("automation", action, "completed"),
        Err(e) => audit::log_failure("automation", action, &e.to_string()),
    }

    result
}
