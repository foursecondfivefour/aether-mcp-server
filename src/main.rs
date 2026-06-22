//! AETHER_01 — Windows MCP Server
//!
//! Full-spectrum Windows 10/11 management via 10 MCP tools over stdio.
//! Maximum speed (opt-level=3, LTO, native CPU), maximum security (CFG, ASLR, DEP).

use aether_mcp_server::config::FeatureGates;
use aether_mcp_server::server::AetherServer;
use rmcp::ServiceExt;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();

    // CRITICAL: MCP uses stdout exclusively for JSON-RPC.
    // All tracing/logging output MUST go to stderr and MUST be stripped of ANSI codes
    // to avoid corrupting the MCP protocol stream or Cursor's log parser.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .with_thread_ids(false)
        .without_time()
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .init();

    let gates = FeatureGates::load();

    tracing::info!("AETHER_01 starting");
    tracing::info!(
        "Feature gates: BCD={} HAL={} OFFLINE_REG={} DLL_INJ={} TOKEN={} LSA={}",
        gates.bcd_edit,
        gates.hal_config,
        gates.offline_registry,
        gates.dll_inject,
        gates.token_manipulation,
        gates.lsa_secrets
    );

    let server = AetherServer::new(gates);

    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    let service = server.serve((stdin, stdout)).await?;

    tracing::info!("AETHER_01 ready on stdio");

    service.waiting().await?;

    tracing::info!("AETHER_01 shutting down");
    Ok(())
}
