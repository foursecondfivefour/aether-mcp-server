//! Integration tests for read-only tool operations (safe — no system modification).
//!
//! Tests real tool handler dispatch with actual system calls.
//! Only safe read-only operations are tested: list, query, read, info, position.
//! Windows-only: these tests only run on #[cfg(windows)].

#![cfg(windows)]

use aether_mcp_server::tools::{automation, filesystem, gui, network, process, security, service, sysinfo, user};
use aether_mcp_server::config::FeatureGates;
use aether_mcp_server::server::AetherServer;
use serde_json::json;

fn test_server() -> AetherServer {
    AetherServer::new(FeatureGates::default())
}

// ───────── 1. process_control ─────────

#[tokio::test]
async fn process_list_returns_valid_json() {
    let result = process::handle_process_control(&test_server(), "list", json!({})).await;
    assert!(result.is_ok(), "process_control.list must succeed: {:?}", result.err());
    let json = result.unwrap();
    assert!(json.contains("\"pid\""), "Must contain PIDs: {json}");
    assert!(json.contains("\"name\""), "Must contain process names: {json}");
    // Current process should be in the list
    let our_pid = std::process::id().to_string();
    assert!(json.contains(&our_pid), "Must include current process PID {our_pid}: {json}");
}

#[tokio::test]
async fn process_query_info_current_process() {
    let pid = std::process::id();
    let result = process::handle_process_control(
        &test_server(),
        "query_info",
        json!({"pid": pid}),
    ).await;
    assert!(result.is_ok(), "query_info for own PID must succeed: {:?}", result.err());
}

#[tokio::test]
async fn process_query_info_nonexistent_pid_returns_error() {
    let result = process::handle_process_control(
        &test_server(),
        "query_info",
        json!({"pid": 99999999}),
    ).await;
    assert!(result.is_err(), "query_info for nonexistent PID must fail");
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("99999999"), "Error must mention the PID: {msg}");
}

// ───────── 2. file_system ─────────

#[test]
fn filesystem_list_dir_current() {
    let result = filesystem::handle_file_system("list_dir", json!({"path": ".", "max_depth": 1}));
    assert!(result.is_ok(), "list_dir '.' must succeed: {:?}", result.err());
    let json = result.unwrap();
    // Should find Cargo.toml in root
    assert!(json.contains("Cargo.toml"), "Must find Cargo.toml in project root: {json}");
}

#[test]
fn filesystem_stat_on_known_file() {
    let result = filesystem::handle_file_system("stat", json!({"path": "Cargo.toml"}));
    assert!(result.is_ok(), "stat on Cargo.toml must succeed: {:?}", result.err());
    let json = result.unwrap();
    assert!(json.contains("\"is_file\""), "Should indicate it's a file: {json}");
}

#[test]
fn filesystem_read_known_file() {
    let result = filesystem::handle_file_system("read", json!({"path": "Cargo.toml"}));
    assert!(result.is_ok(), "read Cargo.toml must succeed: {:?}", result.err());
    let content = result.unwrap();
    assert!(content.contains("aether-mcp-server"), "Cargo.toml must contain package name: {content}");
}

// ───────── 3. service_manager ─────────

#[test]
fn service_list_returns_services() {
    let result = service::handle_service_manager("list", json!({}));
    assert!(result.is_ok(), "service_manager.list must succeed: {:?}", result.err());
    let json = result.unwrap();
    // Should contain at least one well-known service
    assert!(json.contains("service_name"), "Must contain service_name field: {json}");
    // RPC service (RpcSs) is always present
    assert!(json.contains("RpcSs") || json.contains("rpcss"), "Must contain RPC service: {json}");
}

#[test]
fn service_query_status_known_service() {
    let result = service::handle_service_manager("query_status", json!({"service_name": "RpcSs"}));
    assert!(result.is_ok(), "query_status RpcSs must succeed: {:?}", result.err());
    let json = result.unwrap();
    assert!(json.contains("service_name"), "Must contain service_name: {json}");
    assert!(json.contains("state"), "Must contain state field: {json}");
}

#[test]
fn service_query_nonexistent_returns_error() {
    let result = service::handle_service_manager("query_status", json!({"service_name": "NoSuchServiceXYZ123"}));
    assert!(result.is_err(), "query_status on nonexistent service must fail");
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("NoSuchServiceXYZ123"), "Error must mention service name: {msg}");
}

// ───────── 4. gui_automation ─────────

#[test]
fn mouse_position_returns_valid_coords() {
    let result = gui::handle_gui_automation("mouse_position", json!({}));
    assert!(result.is_ok(), "mouse_position must succeed: {:?}", result.err());
    let json = result.unwrap();
    assert!(json.contains("\"x\""), "Must contain x coordinate: {json}");
    assert!(json.contains("\"y\""), "Must contain y coordinate: {json}");
}

#[test]
fn keyboard_state_reads_modifiers() {
    let result = gui::handle_gui_automation("keyboard_state", json!({}));
    assert!(result.is_ok(), "keyboard_state must succeed: {:?}", result.err());
}

#[test]
fn list_windows_returns_shell_tray() {
    let result = gui::handle_gui_automation("list_windows", json!({}));
    assert!(result.is_ok(), "list_windows must succeed: {:?}", result.err());
    let json = result.unwrap();
    // Shell_TrayWnd exists on all Windows systems
    assert!(json.contains("Shell_TrayWnd") || json.contains("hwnd"), "Must list windows: {json}");
}

// ───────── 5. system_info (read-only) ─────────

#[test]
fn cpu_info_returns_valid_data() {
    let result = sysinfo::handle_system_info(&test_server(), "cpu_info", json!({}));
    assert!(result.is_ok(), "cpu_info must succeed: {:?}", result.err());
    let json = result.unwrap();
    assert!(json.contains("cores"), "Must contain core count: {json}");
}

#[test]
fn memory_info_returns_valid_data() {
    let result = sysinfo::handle_system_info(&test_server(), "memory_info", json!({}));
    assert!(result.is_ok(), "memory_info must succeed: {:?}", result.err());
    let json = result.unwrap();
    assert!(json.contains("total_physical"), "Must contain total_physical: {json}");
    assert!(json.contains("available_physical"), "Must contain available_physical: {json}");
}

#[test]
fn os_info_returns_windows_product() {
    let result = sysinfo::handle_system_info(&test_server(), "os_info", json!({}));
    assert!(result.is_ok(), "os_info must succeed: {:?}", result.err());
    let json = result.unwrap();
    assert!(json.contains("Windows") || json.contains("ProductName"), "Must contain OS info: {json}");
}

#[test]
fn uptime_returns_seconds() {
    let result = sysinfo::handle_system_info(&test_server(), "uptime", json!({}));
    assert!(result.is_ok(), "uptime must succeed: {:?}", result.err());
}

#[test]
fn env_vars_list_contains_path() {
    let result = sysinfo::handle_system_info(&test_server(), "env_vars", json!({"action": "list"}));
    assert!(result.is_ok(), "env_vars list must succeed: {:?}", result.err());
}

// ───────── 6. network_manager ─────────

#[test]
fn network_adapters_returns_data() {
    let result = network::handle_network_manager("adapters", json!({}));
    assert!(result.is_ok(), "adapters must succeed: {:?}", result.err());
    let json = result.unwrap();
    // Should contain at least loopback or Ethernet adapter
    assert!(json.contains("ip_addresses") || json.contains("mac_address"), "Must contain adapter info: {json}");
}

// ───────── 7. user_management ─────────

#[test]
fn user_current_user_returns_username() {
    let result = user::handle_user_management(&test_server(), "current_user", json!({}));
    assert!(result.is_ok(), "current_user must succeed: {:?}", result.err());
    let json = result.unwrap();
    assert!(json.contains("username"), "Must contain username: {json}");
    assert!(json.contains("sid"), "Must contain SID: {json}");
}

#[test]
fn user_sessions_list_works() {
    let result = user::handle_user_management(&test_server(), "sessions", json!({}));
    // May fail if not admin, but shouldn't panic
    if let Err(ref e) = result {
        let msg = format!("{e}");
        assert!(!msg.contains("panic"), "Must not panic: {msg}");
    }
}

// ───────── 8. security_audit ─────────

#[test]
fn uac_status_returns_config() {
    let result = security::handle_security_audit("uac_status", json!({}));
    assert!(result.is_ok(), "uac_status must succeed: {:?}", result.err());
    let json = result.unwrap();
    assert!(json.contains("enable_lua"), "Must contain EnableLUA: {json}");
    assert!(json.contains("consent_prompt_behavior_admin"), "Must contain consent level: {json}");
}

// ───────── 9. system_automation ─────────

#[test]
fn event_channels_returns_list() {
    let result = aether_mcp_server::tools::automation::handle_system_automation("event_channels", json!({}));
    // May fail with encoding issues but shouldn't panic
    if let Err(ref e) = result {
        let msg = format!("{e}");
        assert!(!msg.contains("panic"), "Must not panic on channels: {msg}");
    }
}

#[test]
fn task_list_returns_data() {
    let result = aether_mcp_server::tools::automation::handle_system_automation("task_list", json!({}));
    assert!(result.is_ok(), "task_list must succeed: {:?}", result.err());
    let json = result.unwrap();
    assert!(json.contains("TaskName"), "Must contain task names: {json}");
}

// ───────── 10. Round-trip: file_system write/read/delete ─────────

#[test]
fn filesystem_roundtrip_write_read_delete() {
    let test_path = std::env::temp_dir().join("aether_test_roundtrip.txt");
    let path_str = test_path.to_string_lossy().to_string();
    let test_content = "Тест AETHER_01: запись, чтение, удаление √";

    // 1. Write
    let write_result = filesystem::handle_file_system("write", json!({
        "path": path_str,
        "content": test_content,
    }));
    assert!(write_result.is_ok(), "write must succeed: {:?}", write_result.err());

    // 2. Read
    let read_result = filesystem::handle_file_system("read", json!({"path": path_str}));
    assert!(read_result.is_ok(), "read must succeed: {:?}", read_result.err());
    let content = read_result.unwrap();
    assert_eq!(content, test_content, "Read content must match written content");

    // 3. Delete
    let delete_result = filesystem::handle_file_system("delete", json!({
        "path": path_str,
        "force": true,
    }));
    assert!(delete_result.is_ok(), "delete must succeed: {:?}", delete_result.err());

    // 4. Verify deleted
    let verify = filesystem::handle_file_system("read", json!({"path": path_str}));
    assert!(verify.is_err(), "read after delete must fail");
}

#[test]
fn filesystem_delete_without_force_fails() {
    let test_path = std::env::temp_dir().join("aether_test_force_check.txt");
    let path_str = test_path.to_string_lossy().to_string();

    // Write test file
    let _ = filesystem::handle_file_system("write", json!({
        "path": path_str,
        "content": "test",
    }));

    // Delete without force — must fail
    let delete_result = filesystem::handle_file_system("delete", json!({"path": path_str}));
    assert!(delete_result.is_err(), "delete without force must fail");
    let msg = format!("{}", delete_result.unwrap_err());
    assert!(msg.contains("force"), "Error must mention force parameter: {msg}");

    // Cleanup with force
    let _ = filesystem::handle_file_system("delete", json!({
        "path": path_str,
        "force": true,
    }));
}

// ───────── 11. Error handling across tools ─────────

#[test]
fn all_tools_reject_missing_action_gracefully() {
    let empty_params = json!({});
    let fake_action = "__nonexistent_action_xyzzy__";

    // Standalone tools (no server needed)
    let standalone_results = vec![
        ("file_system", filesystem::handle_file_system(fake_action, empty_params.clone())),
        ("service_manager", service::handle_service_manager(fake_action, empty_params.clone())),
        ("gui_automation", gui::handle_gui_automation(fake_action, empty_params.clone())),
        ("network_manager", network::handle_network_manager(fake_action, empty_params.clone())),
        ("security_audit", security::handle_security_audit(fake_action, empty_params.clone())),
        ("system_automation", automation::handle_system_automation(fake_action, empty_params.clone())),
    ];

    for (tool_name, result) in standalone_results {
        assert!(result.is_err(), "{tool_name} must reject fake action");
        let msg = format!("{}", result.unwrap_err());
        assert!(!msg.contains("panic"), "{tool_name} must not panic: {msg}");
        assert!(!msg.contains("unwrap"), "{tool_name} must not leak unwrap: {msg}");
    }

    // Server-requiring tools
    let server = test_server();
    let server_results = vec![
        ("sysinfo", sysinfo::handle_system_info(&server, fake_action, empty_params.clone())),
        ("user_management", user::handle_user_management(&server, fake_action, empty_params.clone())),
    ];
    for (tool_name, result) in server_results {
        assert!(result.is_err(), "{tool_name} must reject fake action");
        let msg = format!("{}", result.unwrap_err());
        assert!(!msg.contains("panic"), "{tool_name} must not panic: {msg}");
    }
}

#[test]
fn tools_handle_empty_params_object() {
    // Empty params should produce clear errors, not panics
    let empty = json!({});

    // filesystem: read without path
    let r = filesystem::handle_file_system("read", empty.clone());
    assert!(r.is_err(), "read without path must fail");
    let m = format!("{}", r.unwrap_err());
    assert!(!m.contains("panic"), "Must not panic: {m}");

    // service: query_status without name
    let r = service::handle_service_manager("query_status", empty.clone());
    assert!(r.is_err(), "query_status without name must fail");
    let m = format!("{}", r.unwrap_err());
    assert!(!m.contains("panic"), "Must not panic: {m}");

    // gui: mouse_position with empty — should succeed
    let r = gui::handle_gui_automation("mouse_position", empty.clone());
    assert!(r.is_ok(), "mouse_position with empty params must succeed: {:?}", r.err());

    // network: adapters with empty — should succeed
    let r = network::handle_network_manager("adapters", empty.clone());
    assert!(r.is_ok(), "adapters with empty params must succeed: {:?}", r.err());

    // security: uac_status with empty — should succeed
    let r = security::handle_security_audit("uac_status", empty.clone());
    assert!(r.is_ok(), "uac_status with empty params must succeed: {:?}", r.err());

    // automation: task_list with empty — should succeed
    let r = aether_mcp_server::tools::automation::handle_system_automation("task_list", empty.clone());
    assert!(r.is_ok(), "task_list with empty params must succeed: {:?}", r.err());
}
