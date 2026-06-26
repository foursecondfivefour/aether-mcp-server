//! AetherServer — the central MCP server with all 10 tools registered.

use crate::config::FeatureGates;
use crate::tools;

use rmcp::{
    ErrorData as McpError,
    ServerHandler,
    handler::server::{router::tool::ToolRouter, tool::Parameters},
    model::*,
    schemars, service::{RequestContext, RoleServer}, tool, tool_router, tool_handler,
};
use serde::Deserialize;

// ── JSON parsing limits ───────────────────────────────────────────────────
//
// serde_json does not have built-in recursion depth limiting, so we catch
// recursion errors via serde_json::from_str's built-in recursion limit
// (default 128 depth). The `ActionParams` struct's `params` field is
// deserialized through `#[schemars(with = "serde_json::Value")]` which
// uses serde_json's default recursive parser.
//
// For additional safety, the `command::validate_param()` function enforces
// max 4096-byte string parameters, and `SafeCommand::output()` caps all
// external command output at 1 MB.
//
// Future improvement: add a custom Deserialize implementation for
// ActionParams that validates depth and size before accepting the payload.

/// The AETHER_01 MCP server.
#[derive(Clone)]
pub struct AetherServer {
    pub gates: FeatureGates,
    tool_router: ToolRouter<Self>,
}

impl AetherServer {
    #[must_use]
    pub fn new(gates: FeatureGates) -> Self {
        Self {
            gates,
            tool_router: Self::tool_router(),
        }
    }
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ActionParams {
    pub action: String,
    #[serde(default)]
    #[schemars(with = "serde_json::Value")]
    pub params: serde_json::Value,
}

// ─── Tool Router ──────────────────────────────────────────────────────────

#[tool_router(router = tool_router)]
impl AetherServer {
    #[tool(description = "Process management: list, kill, create, set_priority, query_info, threads, set_affinity, memory_limits, suspend, resume, list_handles, list_modules, inject_dll")]
    async fn process_control(
        &self,
        Parameters(args): Parameters<ActionParams>,
    ) -> String {
        tools::process::handle_process_control(self, &args.action, args.params)
            .await
            .unwrap_or_else(|e| format!("Error: {e}"))
    }

    #[tool(description = "File system operations: read, write, delete, copy, move, list_dir, stat, mkdir, acl_get, acl_set, symlink, ads_list, ads_read, ads_write, ads_delete, compress, uncompress, encrypt, decrypt, volumes, mount, unmount, shares")]
    async fn file_system(
        &self,
        Parameters(args): Parameters<ActionParams>,
    ) -> String {
        tools::filesystem::handle_file_system(&args.action, args.params)
            .unwrap_or_else(|e| format!("Error: {e}"))
    }

    #[tool(description = "Registry editor: read, write, delete, enumerate, security_get, security_set, monitor, export, import, offline_mount, offline_unmount")]
    async fn registry_editor(
        &self,
        Parameters(args): Parameters<ActionParams>,
    ) -> String {
        tools::registry::handle_registry_editor(self, &args.action, args.params)
            .unwrap_or_else(|e| format!("Error: {e}"))
    }

    #[tool(description = "Windows Service Manager: list, start, stop, restart, query_config, query_status, set_startup, drivers")]
    async fn service_manager(
        &self,
        Parameters(args): Parameters<ActionParams>,
    ) -> String {
        tools::service::handle_service_manager(&args.action, args.params)
            .unwrap_or_else(|e| format!("Error: {e}"))
    }

    #[tool(description = "GUI automation: mouse_move, mouse_click, mouse_scroll, mouse_position, keyboard_type, keyboard_press, keyboard_state, find_window, list_windows, set_window_pos, focus_window, get_window_rect, get_window_text, close_window, screenshot, clipboard_read, clipboard_write, display_info, set_resolution, audio_volume, audio_mute, screen_lock, input_locale")]
    async fn gui_automation(
        &self,
        Parameters(args): Parameters<ActionParams>,
    ) -> String {
        tools::gui::handle_gui_automation(&args.action, args.params)
            .unwrap_or_else(|e| format!("Error: {e}"))
    }

    #[tool(description = "System information: cpu_info, memory_info, disk_info, os_info, uptime, env_vars, power_plans, power_set_plan, power_query, battery, device_list, driver_list, bios_info, time_get, time_set, ntp_sync, installed_software, windows_update, startup_programs, restore_points, perf_counters, bcd_list, bcd_get_entry, bcd_set_entry, crashdump_info, crashdump_configure")]
    async fn system_info(
        &self,
        Parameters(args): Parameters<ActionParams>,
    ) -> String {
        tools::sysinfo::handle_system_info(self, &args.action, args.params)
            .unwrap_or_else(|e| format!("Error: {e}"))
    }

    #[tool(description = "Network management: adapters, connections, dns_cache, firewall_rules, firewall_profiles, proxy, routing_table, network_stats, wifi_profiles, vpn_connections, bluetooth_devices, hosts_file, network_shares")]
    async fn network_manager(
        &self,
        Parameters(args): Parameters<ActionParams>,
    ) -> String {
        tools::network::handle_network_manager(&args.action, args.params)
            .unwrap_or_else(|e| format!("Error: {e}"))
    }

    #[tool(description = "User management: users, groups, create_user, delete_user, create_group, delete_group, group_membership, sessions, current_user, privileges, password_policies, account_lockout, logon_rights, cert_store_list, cert_info, cert_export, cert_import, cert_delete, cred_list, cred_read, token_privileges, token_impersonate, lsa_secrets_list, lsa_secret_read")]
    async fn user_management(
        &self,
        Parameters(args): Parameters<ActionParams>,
    ) -> String {
        tools::user::handle_user_management(self, &args.action, args.params)
            .unwrap_or_else(|e| format!("Error: {e}"))
    }

    #[tool(description = "Security audit: audit_policies, audit_set_policy, uac_status, uac_set_level, defender_status, defender_threats, defender_scan, defender_exclusions, applocker_rules, bitlocker_status, firewall_profile_status, tpm_status, secure_boot_status, credential_guard_status, lsa_protection_status, exploit_protection, sandbox_status, hyperv_status, smartscreen_status, windows_hello_status")]
    async fn security_audit(
        &self,
        Parameters(args): Parameters<ActionParams>,
    ) -> String {
        tools::security::handle_security_audit(&args.action, args.params)
            .unwrap_or_else(|e| format!("Error: {e}"))
    }

    #[tool(description = "System automation: event_query, event_write, event_channels, event_details, task_list, task_query, task_create, task_delete, task_run, task_enable, task_disable, wmi_query")]
    async fn system_automation(
        &self,
        Parameters(args): Parameters<ActionParams>,
    ) -> String {
        tools::automation::handle_system_automation(&args.action, args.params)
            .unwrap_or_else(|e| format!("Error: {e}"))
    }
}

// ─── Server Handler ───────────────────────────────────────────────────────

#[tool_handler(router = self.tool_router)]
impl ServerHandler for AetherServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: Default::default(),
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .enable_logging()
                .enable_prompts()
                .enable_prompts_list_changed()
                .enable_resources()
                .enable_resources_list_changed()
                .build(),
            server_info: Implementation {
                name: "AETHER_01".to_string(),
                version: "1.1.0".to_string(),
            },
            instructions: Some(
                "AETHER_01 — Full-spectrum Windows 10/11 management server.\n\
                10 tools covering 99% of system administration including GUI automation.\n\
                Dangerous operations require `force: true` parameter.\n\
                Feature gates in `.env` control critically dangerous capabilities."
                    .to_string(),
            ),
        }
    }

    async fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParam>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, McpError> {
        Ok(ListPromptsResult::with_all_items(vec![
            Prompt::new(
                "analyze-system",
                Some("Analyze Windows system status and security posture"),
                Some(vec![
                    PromptArgument {
                        name: "level".to_string(),
                        description: Some(
                            "Analysis depth: basic, deep, full".to_string(),
                        ),
                        required: Some(false),
                    },
                ]),
            ),
        ]))
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResult, McpError> {
        if request.name == "analyze-system" {
            Ok(GetPromptResult {
                description: Some(
                    "Analyze Windows system status and security posture"
                        .to_string(),
                ),
                messages: vec![PromptMessage::new_text(
                    PromptMessageRole::User,
                    "Perform a comprehensive Windows system analysis covering:\n\
                     - OS version, uptime, installed software\n\
                     - Running processes and services\n\
                     - Security posture (Defender, UAC, firewall, BitLocker)\n\
                     - Network configuration and active connections\n\
                     - Disk health and memory status",
                )],
            })
        } else {
            Err(McpError::invalid_request(
                format!("Unknown prompt: {}", request.name),
                None,
            ))
        }
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParam>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        Ok(ListResourcesResult::with_all_items(vec![
            RawResource::new("system://status", "System Status")
                .no_annotation(),
        ]))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, McpError> {
        if request.uri == "system://status" {
            Ok(ReadResourceResult {
                contents: vec![ResourceContents::text(
                    "AETHER_01 — Windows MCP Server\n\
                     Status: Operational\n\
                     Platform: Windows 10/11 x86-64\n\
                     Version: 1.1.0\n\
                     Tools: 10 (process, file, registry, service, GUI, system, network, user, security, automation)\n\
                     Prompts: 1 (analyze-system)\n\
                     Resources: 1 (system://status)\n\
                     Security: SafeCommand, feature gates, audit trail, input validation",
                    "system://status",
                )],
            })
        } else {
            Err(McpError::invalid_request(
                format!("Unknown resource: {}", request.uri),
                None,
            ))
        }
    }
}
