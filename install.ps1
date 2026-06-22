# AETHER_01 — One-Click Installer
# Adds AETHER_01 MCP server to Cursor, Claude Desktop, and other agent environments.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File install.ps1
#   powershell -ExecutionPolicy Bypass -File install.ps1 -Targets cursor,claude
#   powershell -c "irm https://raw.githubusercontent.com/foursecondfivefour/aether-mcp-server/main/install.ps1 | iex"

param(
    [string]$Targets = "auto",     # auto, cursor, claude, windsurf, all — or comma-separated
    [string]$BinaryPath = "",      # auto-detect if empty
    [string]$ReleaseTag = "v1.0.0" # download release if not built locally
)

$ErrorActionPreference = "Stop"
$Host.UI.RawUI.WindowTitle = "AETHER_01 — MCP Installer"

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  AETHER_01 — Windows MCP Server Installer" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# ── Find binary ────────────────────────────────────────────────────────────

if ($BinaryPath -and (Test-Path $BinaryPath)) {
    $exePath = (Resolve-Path $BinaryPath).Path
    Write-Host "[✓] Using binary: $exePath" -ForegroundColor Green
}
else {
    $localExe = Get-ChildItem -Recurse -Path "$PSScriptRoot\target\debug\aether-mcp-server.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($localExe) {
        $exePath = $localExe.FullName
        Write-Host "[✓] Found local build: $exePath" -ForegroundColor Green
    }
    else {
        Write-Host "[!] No local binary found. Checking GitHub releases..." -ForegroundColor Yellow
        try {
            $releaseUrl = "https://github.com/foursecondfivefour/aether-mcp-server/releases/download/$ReleaseTag/aether-mcp-server.exe"
            $downloadPath = "$env:LOCALAPPDATA\AetherMCP\aether-mcp-server.exe"
            New-Item -ItemType Directory -Force -Path "$env:LOCALAPPDATA\AetherMCP" | Out-Null
            Invoke-WebRequest -Uri $releaseUrl -OutFile $downloadPath
            $exePath = $downloadPath
            Write-Host "[✓] Downloaded to: $exePath" -ForegroundColor Green
        }
        catch {
            Write-Host "[✗] Failed to download. Build the project first with: cargo build" -ForegroundColor Red
            Write-Host "    Then run: .\install.ps1 -BinaryPath target\debug\aether-mcp-server.exe" -ForegroundColor Yellow
            exit 1
        }
    }
}

# ── Create .env if missing ─────────────────────────────────────────────────

$envFile = Join-Path (Split-Path $exePath -Parent) ".env"
if (-not (Test-Path $envFile)) {
    $envTemplate = Join-Path $PSScriptRoot ".env.example"
    if (Test-Path $envTemplate) {
        Copy-Item $envTemplate $envFile -Force
        Write-Host "[✓] Created .env from .env.example" -ForegroundColor Green
    }
    else {
        @"
# AETHER_01 — Feature Gates
AETHER_BCD_EDIT=0
AETHER_HAL_CONFIG=0
AETHER_OFFLINE_REGISTRY=0
AETHER_DLL_INJECT=0
AETHER_TOKEN_MANIPULATION=0
AETHER_LSA_SECRETS=0
"@ | Out-File $envFile -Encoding UTF8
        Write-Host "[✓] Created default .env" -ForegroundColor Green
    }
}

# ── MCP config template ────────────────────────────────────────────────────

$mcpEntry = @{
    command = $exePath.Replace("\", "\\")
    env     = @{
        RUST_LOG = "info"
    }
}

function Add-McpServer {
    param($ConfigPath, $ClientName)

    Write-Host ""
    Write-Host "--- $ClientName ---" -ForegroundColor Magenta

    if (-not (Test-Path $ConfigPath)) {
        @{ mcpServers = @{ "aether-01" = $mcpEntry } } | ConvertTo-Json -Depth 4 | Out-File $ConfigPath -Encoding UTF8
        Write-Host "[✓] Created: $ConfigPath" -ForegroundColor Green
        return
    }

    try {
        $config = Get-Content $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json -AsHashtable
    }
    catch {
        Write-Host "[!] Invalid JSON in $ConfigPath — creating backup and fresh config" -ForegroundColor Yellow
        Copy-Item $ConfigPath "$ConfigPath.bak" -Force
        @{ mcpServers = @{ "aether-01" = $mcpEntry } } | ConvertTo-Json -Depth 4 | Out-File $ConfigPath -Encoding UTF8
        Write-Host "[✓] Created fresh config (old backed up)" -ForegroundColor Green
        return
    }

    if (-not $config.ContainsKey("mcpServers")) {
        $config["mcpServers"] = @{}
    }

    if ($config["mcpServers"].ContainsKey("aether-01")) {
        Write-Host "[i] AETHER_01 already configured in $ClientName" -ForegroundColor Cyan
    }
    else {
        $config["mcpServers"]["aether-01"] = $mcpEntry
        $config | ConvertTo-Json -Depth 4 | Out-File $ConfigPath -Encoding UTF8
        Write-Host "[✓] Added AETHER_01 to $ClientName" -ForegroundColor Green
    }
}

# ── Detect and install ─────────────────────────────────────────────────────

$targetsList = if ($Targets -eq "auto") { @() } else { $Targets -split "," | ForEach-Object { $_.Trim().ToLower() } }
$autoMode = ($Targets -eq "auto")

if ($autoMode -or $targetsList -contains "cursor") {
    $cursorConfig = "$env:USERPROFILE\.cursor\mcp.json"
    if (Test-Path "$env:USERPROFILE\.cursor") { Add-McpServer $cursorConfig "Cursor" }
    elseif ($autoMode) { Write-Host "[i] Cursor not found (skipping)" -ForegroundColor DarkGray }
}

if ($autoMode -or $targetsList -contains "claude") {
    $claudeConfig = "$env:APPDATA\Claude\claude_desktop_config.json"
    $claudeDir = "$env:APPDATA\Claude"
    if (Test-Path $claudeDir) { Add-McpServer $claudeConfig "Claude Desktop" }
    elseif ($autoMode) { Write-Host "[i] Claude Desktop not found (skipping)" -ForegroundColor DarkGray }
}

if ($autoMode -or $targetsList -contains "windsurf") {
    $windsurfConfig = "$env:USERPROFILE\.codeium\windsurf\mcp_config.json"
    $windsurfDir = "$env:USERPROFILE\.codeium\windsurf"
    if (Test-Path $windsurfDir) { Add-McpServer $windsurfConfig "Windsurf" }
    elseif ($autoMode) { Write-Host "[i] Windsurf not found (skipping)" -ForegroundColor DarkGray }
}

if ($autoMode -or $targetsList -contains "vscode") {
    $vscodeConfig = "$env:APPDATA\Code\User\globalStorage\anthropic.claude-mcp\mcp.json"
    $vscodeDir = "$env:APPDATA\Code"
    if (Test-Path $vscodeDir) { Add-McpServer $vscodeConfig "VS Code (Claude MCP)" }
    elseif ($autoMode) { Write-Host "[i] VS Code not found (skipping)" -ForegroundColor DarkGray }
}

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  Installation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "  Binary: $exePath" -ForegroundColor White
Write-Host "  .env:   $envFile" -ForegroundColor White
Write-Host ""
Write-Host "  Restart your agent to activate AETHER_01." -ForegroundColor Yellow
Write-Host "=============================================" -ForegroundColor Cyan
