# AETHER_01 — One-Click Installer
# Maximum error handling. Every operation is wrapped. Every failure has a recovery path.
#
# Usage:
#   Local:   pwsh -ExecutionPolicy Bypass -File install.ps1
#   Remote:  pwsh -c "irm https://raw.githubusercontent.com/foursecondfivefour/aether-mcp-server/main/install.ps1 | iex"

[CmdletBinding()]
param(
    [ValidateSet("auto", "cursor", "claude", "windsurf", "vscode", "all")]
    [string[]]$Targets = @("auto"),

    [string]$BinaryPath = "",

    [string]$ReleaseTag = "v1.0.0",

    [switch]$Force,

    [switch]$NoAdminWarning,

    [string]$DownloadDir = "$env:LOCALAPPDATA\AetherMCP",

    [int]$RetryCount = 3,

    [int]$RetryDelaySeconds = 5,

    [int]$DownloadTimeoutSeconds = 300
)

# ════════════════════════════════════════════════════════════════════════
# Boot-level safety: never pollute the caller's session and exit scope cleanly
# ════════════════════════════════════════════════════════════════════════

$script:ErrorActionPreference = "Stop"
$script:ProgressPreference   = "SilentlyContinue"
$script:errors               = [System.Collections.Generic.List[string]]::new()
$script:warnings             = [System.Collections.Generic.List[string]]::new()

# Wrapper script so "iex" captures the correct exit code
$script:exitCode = 0

function Register-Error   { param($msg) $script:errors.Add($msg)   ; $script:exitCode = [Math]::Max($script:exitCode, 1) }
function Register-Warning { param($msg) $script:warnings.Add($msg) }

# ════════════════════════════════════════════════════════════════════════
# Constants
# ════════════════════════════════════════════════════════════════════════

$REPO_OWNER = "foursecondfivefour"
$REPO_NAME  = "aether-mcp-server"
$REPO_URL   = "https://github.com/$REPO_OWNER/$REPO_NAME"
$RAW_URL    = "https://raw.githubusercontent.com/$REPO_OWNER/$REPO_NAME/main"
$API_URL    = "https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/releases/tags/$ReleaseTag"

$EXE_NAME   = "aether-mcp-server.exe"
$MIN_EXE_SIZE_BYTES = 10240  # 10 KB — anything smaller is definitely corrupt

# ════════════════════════════════════════════════════════════════════════
# Output helpers (safe across interactive/non-interactive/running)
# ════════════════════════════════════════════════════════════════════════

function Write-Step { param($msg) Write-Host "  [OK] $msg"       -ForegroundColor Green     }
function Write-Warn { param($msg) Write-Host "  [!!] $msg"       -ForegroundColor Yellow     }
function Write-Info { param($msg) Write-Host "  [..] $msg"       -ForegroundColor Cyan       }
function Write-Err  { param($msg) Write-Host "  [XX] $msg"       -ForegroundColor Red        ; Register-Error $msg }
function Write-Dbg  { param($msg) Write-Debug $msg }

# ════════════════════════════════════════════════════════════════════════
# Pre-flight checks
# ════════════════════════════════════════════════════════════════════════

# 1. PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 6) {
    Write-Err "AETHER_01 installer requires PowerShell 7+"
    Write-Host "       Detected: PowerShell $($PSVersionTable.PSVersion)"
    Write-Host "       Install PS7: winget install Microsoft.PowerShell"
    Write-Host "       Then run:    pwsh -c `"irm $RAW_URL/install.ps1 | iex`""
    exit 2
}

# 2. Platform
if (-not $IsWindows -and $PSVersionTable.Platform -ne "Win32NT") {
    Write-Err "AETHER_01 is Windows-only (Windows 10/11 x64 required)"
    Write-Host "       Detected platform: $($PSVersionTable.Platform)"
    Write-Host "       AETHER_01 manages Windows APIs — it cannot run on non-Windows systems."
    exit 5
}

# 3. Check if essential env vars exist
if (-not $env:USERPROFILE) {
    Write-Err "Environment variable USERPROFILE is not set"
    Write-Host "       This is required to locate agent config files."
    Write-Host "       Set USERPROFILE to your user directory and retry."
    exit 6
}

if (-not $env:LOCALAPPDATA) {
    # Fallback: create under USERPROFILE
    $env:LOCALAPPDATA = "$env:USERPROFILE\AppData\Local"
    Write-Warn "LOCALAPPDATA was not set — using $env:LOCALAPPDATA"
}

# 4. Admin check
try {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $isAdmin   = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
catch {
    $isAdmin = $false
    Write-Warn "Could not determine admin status: $_"
}

if (-not $isAdmin -and -not $NoAdminWarning) {
    Write-Warn "Not running as Administrator"
    Write-Host "       Most AETHER_01 tools require admin rights to operate."
    Write-Host "       The MCP config WILL be added, but tools will fail."
    Write-Host "       Suppress: install.ps1 -NoAdminWarning"
    Write-Host ""
}

# 5. Print header — safe in non-interactive contexts
try { $Host.UI.RawUI.WindowTitle = "AETHER_01 — MCP Installer" } catch { }

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   AETHER_01 — Windows MCP Server Installer"               -ForegroundColor Cyan
Write-Host "   PowerShell $($PSVersionTable.PSVersion) — $((Get-Date).ToString('yyyy-MM-dd HH:mm'))" -ForegroundColor DarkGray
if ($isPiped) { Write-Host "   Running from: remote (irm | iex)"          -ForegroundColor DarkGray }
else          { Write-Host "   Running from: local file"                  -ForegroundColor DarkGray }
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# ════════════════════════════════════════════════════════════════════════
# Utility: retry network-bound operations with backoff
# ════════════════════════════════════════════════════════════════════════

function Invoke-WithRetry {
    param(
        [ScriptBlock]$ScriptBlock,
        [string]$OperationDescription,
        [int]$MaxRetries = $RetryCount,
        [int]$DelaySeconds = $RetryDelaySeconds
    )

    $attempt = 0
    $errors  = @()

    while ($attempt -lt $MaxRetries) {
        $attempt++
        try {
            if ($attempt -gt 1) {
                Write-Host "       Retry $attempt/$MaxRetries ..." -ForegroundColor DarkGray
                Start-Sleep -Seconds $DelaySeconds
            }
            return & $ScriptBlock
        }
        catch {
            $errors += $_
            if ($attempt -ge $MaxRetries) {
                throw "`"$OperationDescription`" failed after $MaxRetries attempts. Last error: $_`nAll errors: $($errors -join ' | ')"
            }
        }
    }
}

# ════════════════════════════════════════════════════════════════════════
# Utility: safe file I/O with fallback paths
# ════════════════════════════════════════════════════════════════════════

function Write-File-Safe {
    param(
        [string]$LiteralPath,
        [string]$Content,
        [string]$Description
    )

    $dir = [System.IO.Path]::GetDirectoryName($LiteralPath)

    if (-not (Test-Path -LiteralPath $dir)) {
        try {
            New-Item -ItemType Directory -Force -Path $dir -ErrorAction Stop | Out-Null
        }
        catch {
            throw "Cannot create directory '$dir' for $Description`: $_"
        }
    }

    try {
        [System.IO.File]::WriteAllText($LiteralPath, $Content, [System.Text.UTF8Encoding]::new($false))
        return
    }
    catch {
        Write-Dbg "Primary write to '$LiteralPath' failed: $_"
    }

    $tempPath = "$LiteralPath.aether-tmp-$(Get-Random)"
    try {
        [System.IO.File]::WriteAllText($tempPath, $Content, [System.Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $tempPath -Destination $LiteralPath -Force -ErrorAction Stop
    }
    catch {
        Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        throw "Cannot write $Description to '$LiteralPath' (tried atomic replace): $_"
    }
}

function Read-File-Safe {
    param([string]$LiteralPath, [string]$Description)

    if (-not (Test-Path -LiteralPath $LiteralPath)) {
        return $null
    }

    try {
        $raw = Get-Content -LiteralPath $LiteralPath -Raw -Encoding UTF8 -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
        return $raw
    }
    catch {
        Write-Dbg "Read-File-Safe '$LiteralPath' failed: $_"
        return $null
    }
}

function Backup-File {
    param([string]$LiteralPath, [string]$Reason)

    if (-not (Test-Path -LiteralPath $LiteralPath)) { return }

    $timestamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
    $backupPath = "$LiteralPath.aether-backup-$timestamp"

    try {
        Copy-Item -LiteralPath $LiteralPath -Destination $backupPath -Force -ErrorAction Stop
        Write-Warn "$Reason — backed up to: $backupPath"
    }
    catch {
        Write-Dbg "Backup of '$LiteralPath' failed: $_ (non-fatal)"
    }
}

# ════════════════════════════════════════════════════════════════════════
# Utility: disk space check
# ════════════════════════════════════════════════════════════════════════

function Test-DiskSpace {
    param([string]$Path, [long]$RequiredBytes)

    $drive = [System.IO.Path]::GetPathRoot($Path)
    if (-not $drive) { return $true }  # can't determine — don't block

    try {
        $driveInfo = [System.IO.DriveInfo]::new($drive)
        if ($driveInfo.AvailableFreeSpace -lt $RequiredBytes) {
            Write-Err "Insufficient disk space on ${drive}: needed $("{0:N0}" -f ($RequiredBytes / 1MB)) MB, available $("{0:N0}" -f ($driveInfo.AvailableFreeSpace / 1MB)) MB"
            return $false
        }
        return $true
    }
    catch {
        Write-Dbg "Disk space check failed: $_ (non-fatal)"
        return $true
    }
}

# ════════════════════════════════════════════════════════════════════════
# Step 1: Find or download binary
# ════════════════════════════════════════════════════════════════════════

$exePath = $null

# 1a — User-provided path
if ($BinaryPath) {
    if (-not (Test-Path -LiteralPath $BinaryPath -PathType Leaf)) {
        Write-Err "Provided binary path does not exist or is not a file: $BinaryPath"
        exit 7
    }
    try {
        $exePath = (Resolve-Path -LiteralPath $BinaryPath -ErrorAction Stop).Path
        Write-Step "Using provided binary: $exePath"
    }
    catch {
        Write-Err "Cannot resolve provided binary path '$BinaryPath': $_"
        exit 8
    }
}

# 1b — Auto-detect local build (only when running from disk, not from irm | iex)
if (-not $exePath -and -not $isPiped -and $PSScriptRoot) {
    Write-Dbg "Searching for local build in: $PSScriptRoot"

    $searchPaths = @(
        (Join-Path $PSScriptRoot "target\debug\$EXE_NAME"),
        (Join-Path $PSScriptRoot "target\release\$EXE_NAME")
    )

    foreach ($searchPath in $searchPaths) {
        if (Test-Path -LiteralPath $searchPath -PathType Leaf) {
            $exePath = $searchPath
            Write-Step "Found local build: $exePath"
            break
        }
    }

    # Deep search as last resort
    if (-not $exePath) {
        try {
            $found = Get-ChildItem -LiteralPath $PSScriptRoot -Recurse -Filter $EXE_NAME -Depth 5 -ErrorAction SilentlyContinue |
                     Where-Object { $_.FullName -match "\\target\\(debug|release)\\" } |
                     Select-Object -First 1
            if ($found) {
                $exePath = $found.FullName
                Write-Step "Found local build (deep search): $exePath"
            }
        }
        catch {
            Write-Dbg "Deep search failed: $_"
        }
    }
}

# 1c — Download from GitHub releases
if (-not $exePath) {
    Write-Warn "No local binary found. Will download from GitHub releases..."

    if (-not (Test-DiskSpace $DownloadDir (120 * 1MB))) {
        Write-Err "Cannot proceed — insufficient disk space for download"
        exit 9
    }

    # Validate release exists before attempting download
    $releaseExists = $false
    try {
        Invoke-RestMethod -Uri $API_URL -Method Head -TimeoutSec 10 -ErrorAction SilentlyContinue | Out-Null
        $releaseExists = $true
    }
    catch {
        Write-Dbg "Release API check failed: $_"
    }

    if (-not $releaseExists) {
        Write-Warn "Release '$ReleaseTag' not found on GitHub API (may still exist)"
    }

    # Ensure download directory
    try {
        New-Item -ItemType Directory -Force -Path $DownloadDir -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Err "Cannot create download directory '$DownloadDir': $_"
        exit 10
    }

    $downloadPath = Join-Path $DownloadDir $EXE_NAME
    $releaseUrl   = "$REPO_URL/releases/download/$ReleaseTag/$EXE_NAME"

    Write-Host "       URL:    $releaseUrl"        -ForegroundColor DarkGray
    Write-Host "       Target: $downloadPath"       -ForegroundColor DarkGray
    Write-Host "       (Binary ~110MB — this may take a minute)" -ForegroundColor DarkGray

    # Download with retry logic
    $downloadSuccess = $false
    for ($attempt = 1; $attempt -le $RetryCount; $attempt++) {
        try {
            if ($attempt -gt 1) {
                Write-Host "       Retry $attempt/$RetryCount ..." -ForegroundColor DarkGray
                Start-Sleep -Seconds $RetryDelaySeconds
            }

            # Remove partial download from previous attempt
            Remove-Item -LiteralPath $downloadPath -Force -ErrorAction SilentlyContinue

            Invoke-WebRequest -Uri $releaseUrl -OutFile $downloadPath -TimeoutSec $DownloadTimeoutSeconds -ErrorAction Stop

            # Validate download
            if (-not (Test-Path -LiteralPath $downloadPath)) {
                throw "File not created on disk after download completes"
            }

            $downloadedSize = (Get-Item -LiteralPath $downloadPath).Length
            if ($downloadedSize -lt $MIN_EXE_SIZE_BYTES) {
                # Read what we got to diagnose
                $badContent = try { Get-Content -LiteralPath $downloadPath -Raw -TotalCount 200 -ErrorAction SilentlyContinue } catch { "unreadable" }
                Remove-Item -LiteralPath $downloadPath -Force -ErrorAction SilentlyContinue
                throw "Downloaded file is only $downloadedSize bytes (likely a GitHub error page). Content: $badContent"
            }

            # Verify it looks like a PE executable
            try {
                $header = [System.IO.File]::ReadAllBytes($downloadPath)
                if ($header.Length -lt 2 -or $header[0] -ne 0x4D -or $header[1] -ne 0x5A) {
                    Remove-Item -LiteralPath $downloadPath -Force -ErrorAction SilentlyContinue
                    throw "Downloaded file is not a valid Windows executable (missing MZ header)"
                }
            }
            catch [System.IO.IOException] {
                # If we can't read the header, the file might be locked — treat as partial
                throw "Cannot validate downloaded file: $_"
            }

            $exePath = $downloadPath
            $downloadSuccess = $true
            Write-Step "Downloaded: $exePath ($("{0:N0}" -f ($downloadedSize / 1MB)) MB)"
            break
        }
        catch {
            if ($attempt -ge $RetryCount) {
                Remove-Item -LiteralPath $downloadPath -Force -ErrorAction SilentlyContinue
                Write-Err "Download failed after $RetryCount attempts"
                Write-Host "       URL: $releaseUrl"
                Write-Host "       Error: $_"
                Write-Host ""
                Write-Host "       Possible causes:"
                Write-Host "         1. No internet connection"
                Write-Host "         2. GitHub is unreachable or rate-limited"
                Write-Host "         3. Release $ReleaseTag has no compiled binary yet"
                Write-Host "         4. Corporate proxy/firewall blocking downloads"
                Write-Host "         5. Antivirus quarantining the file mid-download"
                Write-Host ""
                Write-Host "       Workarounds:"
                Write-Host "         - Build locally:  git clone $REPO_URL && cd $REPO_NAME && cargo build --release"
                Write-Host "         - Specify binary:  install.ps1 -BinaryPath C:\path\to\$EXE_NAME"
                Write-Host "         - Download manually and run: install.ps1 -BinaryPath .\$EXE_NAME"
                Write-Host "         - Check releases:    $REPO_URL/releases"
                exit 3
            }
        }
    }
}

# Final binary validation
if (-not $exePath) {
    Write-Err "Binary not set after all discovery methods"
    exit 4
}
if (-not (Test-Path -LiteralPath $exePath)) {
    Write-Err "Binary not found at: $exePath (deleted after discovery?)"
    exit 4
}

# ════════════════════════════════════════════════════════════════════════
# Step 2: Create .env file
# ════════════════════════════════════════════════════════════════════════

$envDir  = [System.IO.Path]::GetDirectoryName($exePath)
if (-not $envDir) { $envDir = "." }
$envFile = Join-Path $envDir ".env"

$envContent = @"
# AETHER_01 — Feature Gates
# 0 = disabled (safe, default)
# 1 = enabled (administrator accepts risk)
#
# Docs: $REPO_URL#feature-gates-env
AETHER_BCD_EDIT=0
AETHER_HAL_CONFIG=0
AETHER_OFFLINE_REGISTRY=0
AETHER_DLL_INJECT=0
AETHER_TOKEN_MANIPULATION=0
AETHER_LSA_SECRETS=0
"@

if (Test-Path -LiteralPath $envFile) {
    if ($Force) {
        try {
            Write-File-Safe $envFile $envContent ".env file"
            Write-Step "Overwrote .env with defaults (--Force)"
        }
        catch {
            Write-Err "Failed to overwrite .env`: $_"
        }
    }
    else {
        Write-Info ".env already exists — keeping existing configuration"
        Write-Host "       To reset: install.ps1 --Force"
    }
}
else {
    try {
        Write-File-Safe $envFile $envContent ".env file"
        Write-Step "Created .env with safe defaults: $envFile"
    }
    catch {
        Write-Err "Failed to create .env`: $_"
        Write-Host "       AETHER_01 will start with all gates disabled (safe default)."
        Write-Host "       Create $envFile manually if needed."
    }
}

# ════════════════════════════════════════════════════════════════════════
# Step 3: MCP config builder
# ════════════════════════════════════════════════════════════════════════

$mcpEntry = @{
    command = $exePath
    env     = @{
        RUST_LOG = "info"
    }
}

function Parse-McpConfig {
    param([string]$LiteralPath)

    $raw = Read-File-Safe $LiteralPath "MCP config"
    if (-not $raw) { return $null }

    try {
        $obj = $raw | ConvertFrom-Json -AsHashtable -NoEnumerate -ErrorAction Stop
        return $obj
    }
    catch {
        Write-Dbg "Parse-McpConfig JSON parse error: $_"
        return $null
    }
}

function Add-McpServer {
    param(
        [string]$ConfigPath,
        [string]$ClientName
    )

    Write-Host "       --- $ClientName ---" -ForegroundColor Magenta

    # Ensure parent directory exists
    $configDir = [System.IO.Path]::GetDirectoryName($ConfigPath)
    if (-not (Test-Path -LiteralPath $configDir)) {
        try {
            New-Item -ItemType Directory -Force -Path $configDir -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Err "Cannot create config directory '$configDir' for $ClientName`: $_"
            return
        }
    }

    # Parse existing config (catches invalid JSON, empty files, permission errors)
    $existing = $null
    if (Test-Path -LiteralPath $ConfigPath) {
        $existing = Parse-McpConfig $ConfigPath
        if ($null -eq $existing) {
            # File exists but is invalid → back it up
            Backup-File $ConfigPath "Invalid or empty JSON"
        }
    }

    # Build new config
    if ($null -eq $existing) {
        $newConfig = @{ mcpServers = @{ "aether-01" = $mcpEntry } }
        try {
            $json = $newConfig | ConvertTo-Json -Depth 10 -Compress
            Write-File-Safe $ConfigPath $json "MCP config for $ClientName"
            Write-Step "${ClientName}: created new config"
        }
        catch {
            Write-Err "Cannot write MCP config for $ClientName`: $_"
        }
        return
    }

    # Normalize mcpServers key
    if (-not $existing.ContainsKey("mcpServers") -or $existing["mcpServers"] -isnot [hashtable]) {
        $existing["mcpServers"] = @{}
    }

    # Check if already installed
    if ($existing["mcpServers"].ContainsKey("aether-01")) {
        if ($Force) {
            $existing["mcpServers"]["aether-01"] = $mcpEntry
            try {
                $json = $existing | ConvertTo-Json -Depth 10 -Compress
                Write-File-Safe $ConfigPath $json "MCP config for $ClientName"
                Write-Step "${ClientName}: updated existing config (--Force)"
            }
            catch {
                Write-Err "Cannot update MCP config for $ClientName`: $_"
            }
        }
        else {
            Write-Info "${ClientName}: AETHER_01 already configured — skipping"
            Write-Host "              To overwrite: install.ps1 --Force"
        }
    }
    else {
        $existing["mcpServers"]["aether-01"] = $mcpEntry
        try {
            $json = $existing | ConvertTo-Json -Depth 10 -Compress
            Write-File-Safe $ConfigPath $json "MCP config for $ClientName"
            Write-Step "${ClientName}: added AETHER_01"
        }
        catch {
            Write-Err "Cannot write MCP config for $ClientName`: $_"
        }
    }
}

# ════════════════════════════════════════════════════════════════════════
# Step 4: Detect environments and install
# ════════════════════════════════════════════════════════════════════════

# Build target set
$targetSet  = [System.Collections.Generic.HashSet[string]]::new()
$autoMode   = ($Targets -contains "auto")

if ($Targets -contains "all") {
    $autoMode = $true
    foreach ($t in @("cursor","claude","windsurf","vscode")) { $targetSet.Add($t) | Out-Null }
}

foreach ($t in ($Targets | Where-Object { $_ -ne "auto" -and $_ -ne "all" })) {
    $targetSet.Add($t) | Out-Null
}

$installedCount = 0
$skippedCount   = 0
$failedCount    = 0

# ── Environment definitions ─────────────────────────────────────────────

$environments = @(
    @{
        Key       = "cursor"
        Dir       = "$env:USERPROFILE\.cursor"
        Config    = "$env:USERPROFILE\.cursor\mcp.json"
        Name      = "Cursor"
    },
    @{
        Key       = "claude"
        Dir       = "$env:APPDATA\Claude"
        Config    = "$env:APPDATA\Claude\claude_desktop_config.json"
        Name      = "Claude Desktop"
    },
    @{
        Key       = "windsurf"
        Dir       = "$env:USERPROFILE\.codeium\windsurf"
        Config    = "$env:USERPROFILE\.codeium\windsurf\mcp_config.json"
        Name      = "Windsurf"
    },
    @{
        Key       = "vscode"
        Dir       = "$env:APPDATA\Code"
        Config    = "$env:APPDATA\Code\User\globalStorage\anthropic.claude-mcp\mcp.json"
        Name      = "VS Code (Claude MCP)"
    }
)

foreach ($env in $environments) {
    if (-not ($autoMode -or $targetSet.Contains($env.Key))) { continue }

    if (Test-Path -LiteralPath $env.Dir) {
        try {
            Add-McpServer $env.Config $env.Name
            $installedCount++
        }
        catch {
            Write-Err "$($env.Name): unexpected error — $_"
            $failedCount++
        }
    }
    else {
        if (-not $autoMode) {
            Write-Warn "$($env.Name): directory not found — $($env.Dir)"
        }
        elseif ($autoMode) {
            Write-Host "       [--] $($env.Name): not found (skipping)" -ForegroundColor DarkGray
        }
        $skippedCount++
    }
}

# ════════════════════════════════════════════════════════════════════════
# Step 5: Summary
# ════════════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   Installation Summary"                                      -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   Binary:       $exePath"                                   -ForegroundColor White
Write-Host "   .env:         $envFile"                                   -ForegroundColor White
Write-Host "   Installed:    $installedCount environment(s)"              -ForegroundColor Green

if ($skippedCount -gt 0) {
    Write-Host "   Not found:    $skippedCount environment(s)"            -ForegroundColor DarkGray
}

if ($failedCount -gt 0) {
    Write-Host "   Failed:       $failedCount environment(s)"            -ForegroundColor Red
}

if ($script:warnings.Count -gt 0) {
    Write-Host ""
    Write-Host "   Warnings:" -ForegroundColor Yellow
    foreach ($w in $script:warnings) { Write-Host "     - $w" -ForegroundColor DarkGray }
}

if ($script:errors.Count -gt 0) {
    Write-Host ""
    Write-Host "   Errors encountered:" -ForegroundColor Red
    foreach ($e in $script:errors) { Write-Host "     - $e" -ForegroundColor Red }
}

Write-Host ""
Write-Host "   Next steps:" -ForegroundColor Cyan
Write-Host "     1. Close and reopen your agent application"              -ForegroundColor White
Write-Host "     2. Check that AETHER_01 appears in the MCP panel"        -ForegroundColor White
Write-Host "     3. If not, check logs in your agent's MCP settings"      -ForegroundColor White
Write-Host ""

if (-not $isAdmin -and -not $NoAdminWarning) {
    Write-Host "   REMINDER: Run agent as Administrator for full access."  -ForegroundColor Magenta
    Write-Host ""
}

Write-Host "============================================================" -ForegroundColor Cyan

# Exit with the worst error code accumulated
exit $script:exitCode

