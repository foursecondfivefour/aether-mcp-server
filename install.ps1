# AETHER_01 — One-Click Installer
# Adds AETHER_01 MCP server to Cursor, Claude Desktop, Windsurf, and VS Code.
#
# Usage:
#   Local:   powershell -ExecutionPolicy Bypass -File install.ps1
#   Remote:  powershell -c "irm https://raw.githubusercontent.com/foursecondfivefour/aether-mcp-server/main/install.ps1 | iex"

[CmdletBinding()]
param(
    [ValidateSet("auto", "cursor", "claude", "windsurf", "vscode", "all")]
    [string[]]$Targets = @("auto"),
    [string]$BinaryPath = "",
    [string]$ReleaseTag = "v1.0.0",
    [switch]$Force,
    [switch]$NoAdminWarning,
    [string]$DownloadDir = "$env:LOCALAPPDATA\AetherMCP"
)

# ── Safety wrapper: don't pollute global scope ──────────────────────────

$script:ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"  # faster Invoke-WebRequest

# ── Constants ────────────────────────────────────────────────────────────

$REPO_OWNER = "foursecondfivefour"
$REPO_NAME  = "aether-mcp-server"
$REPO_URL   = "https://github.com/$REPO_OWNER/$REPO_NAME"
$RAW_URL    = "https://raw.githubusercontent.com/$REPO_OWNER/$REPO_NAME/main"

# ── Helpers ──────────────────────────────────────────────────────────────

function Write-Step { param($msg) Write-Host "[✓] $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Info { param($msg) Write-Host "[i] $msg" -ForegroundColor Cyan }
function Write-Err  { param($msg) Write-Host "[✗] $msg" -ForegroundColor Red }

# Detect if we're running from a local file or piped from the internet
$isPiped = (-not $PSScriptRoot -or $PSScriptRoot -eq "")

# ── Version detection for ConvertFrom-Json -AsHashtable ─────────────────

$PSVersionOK = ($PSVersionTable.PSVersion.Major -ge 6)
if (-not $PSVersionOK) {
    Write-Err "AETHER_01 installer requires PowerShell 7+ (you have $($PSVersionTable.PSVersion))"
    Write-Host "  Install PowerShell 7: winget install Microsoft.PowerShell"
    Write-Host "  Or run the installer as: pwsh -c `"irm $RAW_URL/install.ps1 | iex`""
    exit 2
}

# ── Admin check ─────────────────────────────────────────────────────────

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $NoAdminWarning) {
    Write-Warn "Not running as Administrator."
    Write-Host "  AETHER_01 tools require admin rights for most operations."
    Write-Host "  The MCP config WILL be added, but tools will fail without elevation."
    Write-Host "  To suppress: install.ps1 -NoAdminWarning"
    Write-Host ""
}

# ── Print header (skip if non-interactive) ─────────────────────────────

try { $Host.UI.RawUI.WindowTitle = "AETHER_01 — MCP Installer" } catch { }
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  AETHER_01 — Windows MCP Server Installer" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# ════════════════════════════════════════════════════════════════════════
# Step 1: Find or download binary
# ════════════════════════════════════════════════════════════════════════

$exePath = $null

if ($BinaryPath -and (Test-Path -LiteralPath $BinaryPath -PathType Leaf)) {
    $exePath = (Resolve-Path -LiteralPath $BinaryPath).Path
    Write-Step "Using provided binary: $exePath"
}
else {
    # Try local build (only when running from local file, $PSScriptRoot is set)
    if (-not $isPiped -and $PSScriptRoot) {
        $localExe = Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot "target\debug") -Filter "aether-mcp-server.exe" -Depth 0 -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $localExe) {
            $localExe = Get-ChildItem -LiteralPath $PSScriptRoot -Recurse -Filter "aether-mcp-server.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
        }
        if ($localExe) {
            $exePath = $localExe.FullName
            Write-Step "Found local build: $exePath"
        }
    }

    if (-not $exePath) {
        Write-Warn "No local binary found. Downloading from GitHub releases..."
        try {
            $releaseUrl = "$REPO_URL/releases/download/$ReleaseTag/aether-mcp-server.exe"
            New-Item -ItemType Directory -Force -Path $DownloadDir -ErrorAction Stop | Out-Null
            $downloadPath = Join-Path $DownloadDir "aether-mcp-server.exe"

            Write-Host "  Downloading from: $releaseUrl"
            Write-Host "  Target:           $downloadPath"
            Write-Host "  (Large file ~110MB — this may take a minute)"

            Invoke-WebRequest -Uri $releaseUrl -OutFile $downloadPath -ErrorAction Stop

            if (-not (Test-Path -LiteralPath $downloadPath)) {
                throw "Downloaded file not found on disk"
            }

            $fileSize = (Get-Item -LiteralPath $downloadPath).Length
            if ($fileSize -lt 1024) {
                throw "Downloaded file is too small ($fileSize bytes) — likely a GitHub error page"
            }

            $exePath = $downloadPath
            Write-Step "Downloaded: $exePath ($("{0:N0}" -f ($fileSize / 1MB)) MB)"
        }
        catch {
            Write-Err "Failed to download binary from GitHub releases."
            Write-Host "  Error: $_"
            Write-Host ""
            Write-Host "  Possible causes:"
            Write-Host "    1. No internet connection"
            Write-Host "    2. GitHub is unreachable"
            Write-Host "    3. Release $ReleaseTag does not have a compiled binary yet"
            Write-Host ""
            Write-Host "  Workarounds:"
            Write-Host "    - Build locally:  git clone $REPO_URL && cd $REPO_NAME && cargo build --release"
            Write-Host "    - Provide binary:  .\install.ps1 -BinaryPath C:\path\to\aether-mcp-server.exe"
            Write-Host "    - Try latest tag:  .\install.ps1 -ReleaseTag v1.0.1"
            exit 3
        }
    }
}

# Final validation
if (-not $exePath -or -not (Test-Path -LiteralPath $exePath)) {
    Write-Err "Binary not found at: $exePath"
    exit 4
}

# ════════════════════════════════════════════════════════════════════════
# Step 2: Create .env
# ════════════════════════════════════════════════════════════════════════

$envDir = Split-Path -LiteralPath $exePath -Parent
$envFile = Join-Path $envDir ".env"

if (Test-Path -LiteralPath $envFile) {
    if ($Force) {
        Write-Warn ".env already exists — overwriting with defaults (--Force)"
    } else {
        Write-Info ".env already exists — keeping existing configuration"
        Write-Host "  To reset to defaults, run: install.ps1 --Force"
    }
}
else {
    try {
        @"
# AETHER_01 — Feature Gates
# 0 = disabled (safe, default)
# 1 = enabled (administrator accepts risk)
#
# Read the docs: $REPO_URL#feature-gates-env
AETHER_BCD_EDIT=0
AETHER_HAL_CONFIG=0
AETHER_OFFLINE_REGISTRY=0
AETHER_DLL_INJECT=0
AETHER_TOKEN_MANIPULATION=0
AETHER_LSA_SECRETS=0
"@ | Out-File -LiteralPath $envFile -Encoding UTF8 -ErrorAction Stop
        Write-Step "Created .env with safe defaults: $envFile"
    }
    catch {
        Write-Err "Failed to create .env at $envFile`: $_"
        Write-Host "  You can create it manually later — AETHER_01 will start with all gates disabled."
    }
}

# ════════════════════════════════════════════════════════════════════════
# Step 3: MCP config helper
# ════════════════════════════════════════════════════════════════════════

# NOTE: ConvertTo-Json already escapes backslashes — do NOT double-escape
$mcpEntry = @{
    command = $exePath
    env     = @{
        RUST_LOG = "info"
    }
}

function Safe-ConvertFromJson {
    param($Path, [hashtable]$Existing = $null)

    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }

    # Read raw to check if empty/whitespace
    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return $null
    }

    try {
        # PowerShell 5 fallback: use -AsHashtable on 7+, fall back to PSCustomObject on 5
        if ($PSVersionOK) {
            return $raw | ConvertFrom-Json -AsHashtable -NoEnumerate
        }
        else {
            return $raw | ConvertFrom-Json
        }
    }
    catch {
        return $null  # invalid JSON → caller handles
    }
}

function Add-McpServer {
    param(
        [string]$ConfigPath,
        [string]$ClientName
    )

    Write-Host ""
    Write-Host "--- $ClientName ---" -ForegroundColor Magenta

    # Ensure parent directory exists
    $configDir = Split-Path -LiteralPath $ConfigPath -Parent
    if (-not (Test-Path -LiteralPath $configDir)) {
        try {
            New-Item -ItemType Directory -Force -Path $configDir -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Err "Cannot create config directory: $configDir — skipping $ClientName"
            return
        }
    }

    # Parse existing config
    $existing = Safe-ConvertFromJson $ConfigPath

    if ($null -eq $existing) {
        # File doesn't exist or is broken → create fresh
        if (Test-Path -LiteralPath $ConfigPath) {
            # Invalid JSON → back up
            $backupPath = "$ConfigPath.aether-backup-$(Get-Date -Format 'yyyyMMddHHmmss')"
            Copy-Item -LiteralPath $ConfigPath -Destination $backupPath -Force -ErrorAction SilentlyContinue
            Write-Warn "Invalid or empty JSON in $ConfigPath — backed up to $backupPath"
        }
        @{ mcpServers = @{ "aether-01" = $mcpEntry } } | ConvertTo-Json -Depth 6 | Out-File -LiteralPath $ConfigPath -Encoding UTF8
        Write-Step "Created: $ConfigPath"
        return
    }

    # Normalize mcpServers
    if (-not $existing.ContainsKey("mcpServers")) {
        $existing["mcpServers"] = @{}
    }
    elseif ($existing["mcpServers"] -isnot [hashtable]) {
        # Convert from PSCustomObject if running PS5
        $existing["mcpServers"] = @{}
    }

    if ($existing["mcpServers"].ContainsKey("aether-01")) {
        if ($Force) {
            Write-Warn "AETHER_01 already configured — overwriting (--Force)"
            $existing["mcpServers"]["aether-01"] = $mcpEntry
            $existing | ConvertTo-Json -Depth 6 | Out-File -LiteralPath $ConfigPath -Encoding UTF8
            Write-Step "Updated AETHER_01 in $ClientName"
        }
        else {
            Write-Info "AETHER_01 already configured in $ClientName — skipping"
            Write-Host "  To overwrite: install.ps1 --Force"
        }
    }
    else {
        $existing["mcpServers"]["aether-01"] = $mcpEntry
        $existing | ConvertTo-Json -Depth 6 | Out-File -LiteralPath $ConfigPath -Encoding UTF8
        Write-Step "Added AETHER_01 to $ClientName"
    }
}

# ════════════════════════════════════════════════════════════════════════
# Step 4: Detect targets and install
# ════════════════════════════════════════════════════════════════════════

$targetSet   = [System.Collections.Generic.HashSet[string]]::new()
$autoMode    = ($Targets -contains "auto")

if ($Targets -contains "all") {
    $autoMode = $true
    $targetSet.Add("cursor")   | Out-Null
    $targetSet.Add("claude")   | Out-Null
    $targetSet.Add("windsurf") | Out-Null
    $targetSet.Add("vscode")   | Out-Null
}

foreach ($t in ($Targets | Where-Object { $_ -ne "auto" -and $_ -ne "all" })) {
    $targetSet.Add($t) | Out-Null
}

$installedCount = 0
$skippedCount   = 0

# ── Cursor ──────────────────────────────────────────────────────────────

if ($autoMode -or $targetSet.Contains("cursor")) {
    $dir = "$env:USERPROFILE\.cursor"
    if (Test-Path -LiteralPath $dir) {
        Add-McpServer (Join-Path $dir "mcp.json") "Cursor"
        $installedCount++
    }
    elseif (-not $autoMode) { Write-Warn "Cursor directory not found: $dir" }
    elseif ($autoMode) { Write-Host "[i] Cursor not found (skipping)" -ForegroundColor DarkGray ; $skippedCount++ }
}

# ── Claude Desktop ──────────────────────────────────────────────────────

if ($autoMode -or $targetSet.Contains("claude")) {
    $dir = "$env:APPDATA\Claude"
    if (Test-Path -LiteralPath $dir) {
        Add-McpServer (Join-Path $dir "claude_desktop_config.json") "Claude Desktop"
        $installedCount++
    }
    elseif (-not $autoMode) { Write-Warn "Claude Desktop directory not found: $dir" }
    elseif ($autoMode) { Write-Host "[i] Claude Desktop not found (skipping)" -ForegroundColor DarkGray ; $skippedCount++ }
}

# ── Windsurf ────────────────────────────────────────────────────────────

if ($autoMode -or $targetSet.Contains("windsurf")) {
    $dir = "$env:USERPROFILE\.codeium\windsurf"
    if (Test-Path -LiteralPath $dir) {
        Add-McpServer (Join-Path $dir "mcp_config.json") "Windsurf"
        $installedCount++
    }
    elseif (-not $autoMode) { Write-Warn "Windsurf directory not found: $dir" }
    elseif ($autoMode) { Write-Host "[i] Windsurf not found (skipping)" -ForegroundColor DarkGray ; $skippedCount++ }
}

# ── VS Code (Claude MCP extension) ──────────────────────────────────────

if ($autoMode -or $targetSet.Contains("vscode")) {
    $dir = "$env:APPDATA\Code"
    if (Test-Path -LiteralPath $dir) {
        Add-McpServer (Join-Path $dir "User\globalStorage\anthropic.claude-mcp\mcp.json") "VS Code (Claude MCP)"
        $installedCount++
    }
    elseif (-not $autoMode) { Write-Warn "VS Code directory not found: $dir" }
    elseif ($autoMode) { Write-Host "[i] VS Code not found (skipping)" -ForegroundColor DarkGray ; $skippedCount++ }
}

# ════════════════════════════════════════════════════════════════════════
# Step 5: Summary
# ════════════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  Summary" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  Binary:   $exePath" -ForegroundColor White
Write-Host "  .env:     $envFile" -ForegroundColor White
Write-Host "  Installed into: $installedCount client(s)" -ForegroundColor Green
if ($skippedCount -gt 0) {
    Write-Host "  Not found: $skippedCount client(s) (install them first)" -ForegroundColor DarkGray
}
Write-Host ""
Write-Host "  Restart your agent application to activate AETHER_01." -ForegroundColor Yellow
Write-Host ""
if (-not $isAdmin -and -not $NoAdminWarning) {
    Write-Host "  REMINDER: Run your agent as Administrator for full AETHER_01 access." -ForegroundColor Magenta
}
Write-Host "=============================================" -ForegroundColor Cyan
