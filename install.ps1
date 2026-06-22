# AETHER_01 — One-Click Installer
# Supports 14+ MCP-compatible editors and IDEs with an interactive selection menu.
#
# Usage:
#   Local:   pwsh -ExecutionPolicy Bypass -File install.ps1
#   Remote:  pwsh -c "irm https://raw.githubusercontent.com/foursecondfivefour/aether-mcp-server/main/install.ps1 | iex"
#   Silent:  pwsh -File install.ps1 -Targets cursor,claude -Silent

[CmdletBinding()]
param(
    [string[]]$Targets = @(""),
    [string]$BinaryPath = "",
    [string]$ReleaseTag = "v1.0.0",
    [switch]$Force,
    [switch]$NoAdminWarning,
    [Switch]$Silent,
    [string]$DownloadDir = "$env:LOCALAPPDATA\AetherMCP",
    [int]$RetryCount = 3,
    [int]$RetryDelaySeconds = 5,
    [int]$DownloadTimeoutSeconds = 300
)

# ════════════════════════════════════════════════════════════════════════
# Boot-level safety
# ════════════════════════════════════════════════════════════════════════
$script:ErrorActionPreference = "Stop"
$script:ProgressPreference   = "SilentlyContinue"
$script:errors               = [System.Collections.Generic.List[string]]::new()
$script:warnings             = [System.Collections.Generic.List[string]]::new()
$script:exitCode             = 0

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
$MIN_EXE_SIZE_BYTES = 10240

# ════════════════════════════════════════════════════════════════════════
# Output helpers
# ════════════════════════════════════════════════════════════════════════
function Write-Step { param($msg) Write-Host "  [OK] $msg"       -ForegroundColor Green     }
function Write-Warn { param($msg) Write-Host "  [!!] $msg"       -ForegroundColor Yellow     }
function Write-Info { param($msg) Write-Host "  [..] $msg"       -ForegroundColor Cyan       }
function Write-Err  { param($msg) Write-Host "  [XX] $msg"       -ForegroundColor Red        ; Register-Error $msg }
function Write-Dbg  { param($msg) Write-Debug $msg }

# Detect execution mode
$isPiped = (-not $PSScriptRoot -or $PSScriptRoot -eq "")

if (-not $PSVersionTable.PSVersion.Major -ge 6) {
    Write-Err "Requires PowerShell 7+ (detected: $($PSVersionTable.PSVersion))"
    Write-Host "       winget install Microsoft.PowerShell"
    exit 2
}

if (-not $IsWindows -and $PSVersionTable.Platform -ne "Win32NT") {
    Write-Err "Windows 10/11 x64 required"
    exit 5
}
if (-not $env:USERPROFILE) { Write-Err "USERPROFILE not set"; exit 6 }
if (-not $env:LOCALAPPDATA) { $env:LOCALAPPDATA = "$env:USERPROFILE\AppData\Local"; Write-Warn "LOCALAPPDATA fallback: $env:LOCALAPPDATA" }

try { $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()); $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { $isAdmin = $false }

try { $Host.UI.RawUI.WindowTitle = "AETHER_01 — Installer" } catch { }

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   AETHER_01 — Windows MCP Server Installer"               -ForegroundColor Cyan
Write-Host "   PS $($PSVersionTable.PSVersion) — $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor DarkGray
if ($isPiped) { Write-Host "   Source: remote (irm | iex)"               -ForegroundColor DarkGray }
else          { Write-Host "   Source: local file"                       -ForegroundColor DarkGray }
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

if (-not $isAdmin -and -not $NoAdminWarning) {
    Write-Warn "Not Administrator — MCP config will be added, but tools will fail without admin rights"
    Write-Host "       Suppress: install.ps1 -NoAdminWarning"
    Write-Host ""
}

# ════════════════════════════════════════════════════════════════════════
# Utility functions (retry, safe io, disk check)
# ════════════════════════════════════════════════════════════════════════
function Write-File-Safe { param([string]$LiteralPath, [string]$Content, [string]$Description)
    $dir = [IO.Path]::GetDirectoryName($LiteralPath)
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir -ErrorAction Stop | Out-Null }
    try { [IO.File]::WriteAllText($LiteralPath, $Content, [Text.UTF8Encoding]::new($false)); return } catch { Write-Dbg "Write to '$LiteralPath' failed: $_" }
    $tmp = "$LiteralPath.aether-tmp-$(Get-Random)"
    try { [IO.File]::WriteAllText($tmp, $Content, [Text.UTF8Encoding]::new($false)); Move-Item $tmp $LiteralPath -Force -ErrorAction Stop }
    catch { Remove-Item $tmp -Force -ErrorAction SilentlyContinue; throw "Cannot write $Description to '$LiteralPath': $_" }
}
function Read-File-Safe { param([string]$LiteralPath)
    if (-not (Test-Path $LiteralPath)) { return $null }
    try { $raw = Get-Content $LiteralPath -Raw -Encoding UTF8 -ErrorAction Stop; if ([string]::IsNullOrWhiteSpace($raw)) { $null } else { $raw } } catch { $null }
}
function Backup-File { param([string]$LiteralPath, [string]$Reason)
    if (-not (Test-Path $LiteralPath)) { return }
    $bkp = "$LiteralPath.aether-backup-$((Get-Date).ToString('yyyyMMdd-HHmmss'))"
    try { Copy-Item $LiteralPath $bkp -Force -ErrorAction Stop; Write-Warn "$Reason — $bkp" } catch { Write-Dbg "Backup failed: $_" }
}
function Test-DiskSpace { param([string]$Path, [long]$Bytes)
    $drv = [IO.Path]::GetPathRoot($Path); if (-not $drv) { return $true }
    try { $di = [IO.DriveInfo]::new($drv); if ($di.AvailableFreeSpace -lt $Bytes) { Write-Err "Disk full on $drv"; return $false }; return $true } catch { return $true }
}

# ════════════════════════════════════════════════════════════════════════
# Step 1: Find or download binary (unchanged from previous version)
# ════════════════════════════════════════════════════════════════════════
$exePath = $null
if ($BinaryPath) {
    if (-not (Test-Path -LiteralPath $BinaryPath -PathType Leaf)) { Write-Err "Not a file: $BinaryPath"; exit 7 }
    $exePath = (Resolve-Path -LiteralPath $BinaryPath -ErrorAction Stop).Path; Write-Step "Binary: $exePath"
}
if (-not $exePath -and -not $isPiped -and $PSScriptRoot) {
    foreach ($p in @("$PSScriptRoot\target\debug\$EXE_NAME","$PSScriptRoot\target\release\$EXE_NAME")) { if (Test-Path $p) { $exePath = $p; Write-Step "Local build: $exePath"; break } }
    if (-not $exePath) { try { $f = Get-ChildItem $PSScriptRoot -Recurse -Filter $EXE_NAME -Depth 5 -ErrorAction SilentlyContinue | ? { $_ -match "\\target\\(debug|release)\\" } | select -First 1; if ($f) { $exePath = $f.FullName; Write-Step "Deep: $exePath" } } catch {} }
}
if (-not $exePath) {
    Write-Warn "Downloading from GitHub..."
    if (-not (Test-DiskSpace $DownloadDir (120*1MB))) { exit 9 }
    try { New-Item -ItemType Directory -Force -Path $DownloadDir -ErrorAction Stop | Out-Null } catch { Write-Err "Cannot create $DownloadDir"; exit 10 }
    $dlPath = Join-Path $DownloadDir $EXE_NAME
    $dlUrl  = "$REPO_URL/releases/download/$ReleaseTag/$EXE_NAME"
    Write-Host "       $dlUrl -> $dlPath" -ForegroundColor DarkGray
    Write-Host "       (~110MB — please wait)" -ForegroundColor DarkGray
    for ($a=1; $a -le $RetryCount; $a++) {
        try {
            if ($a -gt 1) { Write-Host "       Retry $a/$RetryCount..." -ForegroundColor DarkGray; Start-Sleep $RetryDelaySeconds }
            Remove-Item $dlPath -Force -ErrorAction SilentlyContinue
            Invoke-WebRequest -Uri $dlUrl -OutFile $dlPath -TimeoutSec $DownloadTimeoutSeconds -ErrorAction Stop
            if (-not (Test-Path $dlPath)) { throw "Not written to disk" }
            $sz = (Get-Item $dlPath).Length
            if ($sz -lt $MIN_EXE_SIZE_BYTES) { $bc = try { Get-Content $dlPath -Raw -TotalCount 200 -EA SilentlyContinue } catch { "unreadable" }; Remove-Item $dlPath -Force -EA SilentlyContinue; throw "Too small: $sz bytes ($bc)" }
            try { $hdr = [IO.File]::ReadAllBytes($dlPath); if ($hdr[0] -ne 0x4D -or $hdr[1] -ne 0x5A) { Remove-Item $dlPath -Force -EA SilentlyContinue; throw "Not a valid .exe (no MZ header)" } } catch [IO.IOException] { throw "Locked file: $_" }
            $exePath = $dlPath; Write-Step "Downloaded: $exePath ($('{0:N0}' -f ($sz/1MB)) MB)"; break
        } catch { if ($a -ge $RetryCount) { Remove-Item $dlPath -Force -EA SilentlyContinue; Write-Err "Download failed after $RetryCount attempts: $_"; Write-Host "       Build locally: git clone $REPO_URL && cargo build --release"; exit 3 } }
    }
}
if (-not $exePath -or -not (Test-Path $exePath)) { Write-Err "No binary"; exit 4 }

# ════════════════════════════════════════════════════════════════════════
# Step 2: Create .env
# ════════════════════════════════════════════════════════════════════════
$envDir  = [IO.Path]::GetDirectoryName($exePath); if (-not $envDir) { $envDir = "." }
$envFile = Join-Path $envDir ".env"
$envContent = @"
# AETHER_01 — Feature Gates
# 0=disabled 1=enabled
AETHER_BCD_EDIT=0
AETHER_HAL_CONFIG=0
AETHER_OFFLINE_REGISTRY=0
AETHER_DLL_INJECT=0
AETHER_TOKEN_MANIPULATION=0
AETHER_LSA_SECRETS=0
"@
if (Test-Path $envFile) { if ($Force) { try { Write-File-Safe $envFile $envContent ".env"; Write-Step ".env overwritten" } catch { Write-Err ".env write failed: $_" } } else { Write-Info ".env exists — skip. Use --Force to overwrite." } }
else { try { Write-File-Safe $envFile $envContent ".env"; Write-Step ".env created: $envFile" } catch { Write-Err ".env create failed: $_" } }

# ════════════════════════════════════════════════════════════════════════
# Step 3: MCP config engine
# ════════════════════════════════════════════════════════════════════════
$mcpEntry = @{ command = $exePath; env = @{ RUST_LOG = "info" } }

function Parse-McpConfig { param([string]$LiteralPath)
    $raw = Read-File-Safe $LiteralPath; if (-not $raw) { return $null }
    try { return $raw | ConvertFrom-Json -AsHashtable -NoEnumerate -ErrorAction Stop } catch { return $null }
}

function Write-McpConfig {
    param([string]$ConfigPath,[string]$ClientName,[string]$RootKey,[bool]$IsYaml=$false,[string]$YamlIndent="")

    Write-Host "       --- $ClientName ---" -ForegroundColor Magenta
    $configDir = [IO.Path]::GetDirectoryName($ConfigPath)
    if (-not (Test-Path $configDir)) { try { New-Item -ItemType Directory -Force -Path $configDir -ErrorAction Stop | Out-Null } catch { Write-Err "Cannot create dir '$configDir' for $ClientName`: $_"; return } }

    # ── YAML path (Continue.dev, Goose) ────────────────────────────────
    if ($IsYaml) {
        if (Test-Path $ConfigPath) {
            $existingYaml = Read-File-Safe $ConfigPath
            if ($existingYaml -match "aether-01") {
                if ($Force) { Write-Warn "${ClientName}: already configured — overwriting (--Force)" }
                else { Write-Info "${ClientName}: already configured — skip. Use --Force to overwrite."; return }
            }
        }
        # Append aether entry
        $yamlEntry = @"
$YamlIndent  aether-01:
$YamlIndent    command: $($exePath -replace '\\','/')
$YamlIndent    env:
$YamlIndent      RUST_LOG: info
"@
        if (Test-Path $ConfigPath) {
            $content = Read-File-Safe $ConfigPath
            if ($content -match "mcpServers:") {
                $content = $content -replace "(mcpServers:\r?\n)", "`$1$yamlEntry"
            } else {
                $content = "mcpServers:`n$yamlEntry`n$content"
            }
            try { Write-File-Safe $ConfigPath $content "YAML config for $ClientName" } catch { Write-Err "Cannot write YAML for $ClientName`: $_"; return }
        } else {
            try { Write-File-Safe $ConfigPath "mcpServers:`n$yamlEntry" "YAML config for $ClientName" } catch { Write-Err "Cannot create YAML for $ClientName`: $_"; return }
        }
        Write-Step "${ClientName}: added to YAML config"
        return
    }

    # ── JSON path (all others) ─────────────────────────────────────────
    $existing = $null
    if (Test-Path $ConfigPath) { $existing = Parse-McpConfig $ConfigPath; if ($null -eq $existing) { Backup-File $ConfigPath "Invalid JSON" } }
    if ($null -eq $existing) {
        $newCfg = @{ $RootKey = @{ "aether-01" = $mcpEntry } }
        try { Write-File-Safe $ConfigPath ($newCfg | ConvertTo-Json -Depth 10 -Compress) "JSON for $ClientName"; Write-Step "${ClientName}: created" }
        catch { Write-Err "Write $ClientName` failed: $_" }
        return
    }
    if (-not $existing.ContainsKey($RootKey) -or $existing[$RootKey] -isnot [hashtable]) { $existing[$RootKey] = @{} }
    if ($existing[$RootKey].ContainsKey("aether-01")) {
        if ($Force) { $existing[$RootKey]["aether-01"] = $mcpEntry; try { Write-File-Safe $ConfigPath ($existing | ConvertTo-Json -Depth 10 -Compress) "JSON for $ClientName"; Write-Step "${ClientName}: updated (--Force)" } catch { Write-Err "Update $ClientName` failed: $_" } }
        else { Write-Info "${ClientName}: already installed — skip. Use --Force to overwrite." }
    } else {
        $existing[$RootKey]["aether-01"] = $mcpEntry
        try { Write-File-Safe $ConfigPath ($existing | ConvertTo-Json -Depth 10 -Compress) "JSON for $ClientName"; Write-Step "${ClientName}: added" }
        catch { Write-Err "Write $ClientName` failed: $_" }
    }
}

# ════════════════════════════════════════════════════════════════════════
# Step 4: Environment catalog (14+ editors/IDEs/plugins)
# ════════════════════════════════════════════════════════════════════════

$ALL_ENVIRONMENTS = @(

    # ─── AI-first editors ──────────────────────────────────────────────
    @{ Key="cursor";       Dir="$env:USERPROFILE\.cursor";                         Config="$env:USERPROFILE\.cursor\mcp.json";                                                   Root="mcpServers";     Name="Cursor (AI-first IDE)";                    Icon="🖥️" },
    @{ Key="windsurf";     Dir="$env:USERPROFILE\.codeium\windsurf";               Config="$env:USERPROFILE\.codeium\windsurf\mcp_config.json";                                 Root="mcpServers";     Name="Windsurf (Codeium Cascade)";               Icon="🌊" },
    @{ Key="claude-dt";    Dir="$env:APPDATA\Claude";                               Config="$env:APPDATA\Claude\claude_desktop_config.json";                                      Root="mcpServers";     Name="Claude Desktop (Anthropic)";               Icon="🧠" },

    # ─── Microsoft ecosystem ───────────────────────────────────────────
    @{ Key="vscode-mcp";   Dir="$env:APPDATA\Code";                                Config="$env:APPDATA\Code\User\globalStorage\anthropic.claude-mcp\mcp.json";                  Root="mcpServers";     Name="VS Code (MCP extension)";                  Icon="🔵" },
    @{ Key="vscode-copilot";Dir="$env:APPDATA\Code";                               Config="$env:USERPROFILE\.vscode\mcp.json";                                                    Root="servers";        Name="VS Code (GitHub Copilot)";                 Icon="🤖" },

    # ─── Open-source agents ────────────────────────────────────────────
    @{ Key="cline";         Dir="$env:APPDATA\Code";                                Config="$env:APPDATA\Code\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json"; Root="mcpServers"; Name="Cline (VS Code Agent)";                Icon="🤖" },
    @{ Key="continue";      Dir="$env:USERPROFILE\.continue";                       Config="$env:USERPROFILE\.continue\config.yaml";                                               Root="mcpServers";     Name="Continue.dev (OSS AI Assistant)";          Icon="🔄";  Yaml=$true; Indent="  " },

    # ─── Terminal / CLI ────────────────────────────────────────────────
    @{ Key="claude-code";   Dir="$env:USERPROFILE";                                 Config="$env:USERPROFILE\.claude.json";                                                         Root="mcpServers";     Name="Claude Code (Anthropic CLI)";              Icon="⌨️" },
    @{ Key="gemini-cli";    Dir="$env:USERPROFILE";                                 Config="$env:USERPROFILE\.gemini\mcp.json";                                                      Root="mcpServers";     Name="Gemini CLI (Google)";                      Icon="🌐" },

    # ─── High-performance editors ──────────────────────────────────────
    @{ Key="zed";           Dir="$env:USERPROFILE\.config\zed";                     Config="$env:USERPROFILE\.config\zed\settings.json";                                            Root="context_servers"; Name="Zed (Rust-native IDE)";                Icon="⚡" },

    # ─── JetBrains ecosystem ───────────────────────────────────────────
    @{ Key="jetbrains-idea";Dir="$env:APPDATA\JetBrains\IntelliJIdea2025.1";       Config="$env:APPDATA\JetBrains\IntelliJIdea2025.1\options\mcp-settings.xml";                  Root="mcpServers";     Name="IntelliJ IDEA (JetBrains)";                Icon="🧩" },
    @{ Key="jetbrains-pc";  Dir="$env:APPDATA\JetBrains\PyCharm2025.1";            Config="$env:APPDATA\JetBrains\PyCharm2025.1\options\mcp-settings.xml";                       Root="mcpServers";     Name="PyCharm (JetBrains)";                      Icon="🐍" },
    @{ Key="jetbrains-ws";  Dir="$env:APPDATA\JetBrains\WebStorm2025.1";           Config="$env:APPDATA\JetBrains\WebStorm2025.1\options\mcp-settings.xml";                      Root="mcpServers";     Name="WebStorm (JetBrains)";                     Icon="🌐" },

    # ─── Other environments ────────────────────────────────────────────
    @{ Key="goose";         Dir="$env:USERPROFILE\.config\goose";                   Config="$env:USERPROFILE\.config\goose\config.yaml";                                            Root="extensions";      Name="Goose (Block/Square Agent)";               Icon="🦆";  Yaml=$true; Indent="" }
)

# ════════════════════════════════════════════════════════════════════════
# Step 5: Interactive menu system
# ════════════════════════════════════════════════════════════════════════

function Show-Menu {
    param([array]$Options, [string]$Title, [string]$Prompt)

    Write-Host ""
    Write-Host $Title -ForegroundColor Cyan
    Write-Host ("─" * 65) -ForegroundColor DarkGray

    $selected = @{}
    $optionsMap = @{}

    for ($i = 0; $i -lt $Options.Count; $i++) {
        $num  = $i + 1
        $opt  = $Options[$i]
        $key  = $opt.Key
        $name = $opt.Name
        $found = Test-Path -LiteralPath $opt.Dir -ErrorAction SilentlyContinue
        $icon = if ($found) { $opt.Icon } else { "⬜" }
        $status = if ($found) { "FOUND" } else { "not installed" }
        $sc = if ($found) { "Green" } else { "DarkGray" }
        $optionsMap[$num] = $opt
        Write-Host "  [$num] $icon  $name" -ForegroundColor White -NoNewline
        Write-Host "  ($status)" -ForegroundColor $sc
    }

    Write-Host ("─" * 65) -ForegroundColor DarkGray
    Write-Host "  [A]  ALL — select all found environments"
    Write-Host "  [S]  SKIP — don't install into any editor"
    Write-Host "  [Q]  QUIT — abort installation entirely"
    Write-Host ("─" * 65) -ForegroundColor DarkGray

    Write-Host ""
    Write-Host $Prompt -ForegroundColor Yellow -NoNewline
    Write-Host " " -NoNewline
    $input = (Read-Host).Trim().ToUpperInvariant()

    $result = @()
    switch ($input) {
        "Q"    { Write-Host ""; Write-Err "Installation cancelled by user"; exit 0 }
        "S"    { Write-Host ""; Write-Info "Skipping editor installation — binary and .env are ready"; return @() }
        "A"    { foreach ($idx in $optionsMap.Keys | Sort-Object) { $opt = $optionsMap[$idx]; if (Test-Path $opt.Dir) { $result += $opt } }; break }
        default {
            foreach ($part in ($input -split '[\s,;]+')) {
                $num = try { [int]$part } catch { 0 }
                if ($num -gt 0 -and $optionsMap.ContainsKey($num)) { $result += $optionsMap[$num] }
            }
        }
    }

    if ($result.Count -eq 0) {
        Write-Warn "No valid selections — installing only binary and .env"
    }

    return $result
}

# ════════════════════════════════════════════════════════════════════════
# Step 6: Dispatch: silent mode or interactive menu
# ════════════════════════════════════════════════════════════════════════

$toInstall = @()

if ($Silent -or ($Targets.Count -gt 0 -and $Targets[0] -ne "")) {
    # ── Silent / CLI mode ──────────────────────────────────────────────
    $targetSet  = [Collections.Generic.HashSet[string]]::new()
    $autoMode   = ($Targets -contains "auto" -or $Targets.Count -eq 0 -or ($Targets.Count -eq 1 -and $Targets[0] -eq ""))

    if ($Targets -contains "all" -or $autoMode) {
        foreach ($env in $ALL_ENVIRONMENTS) { $targetSet.Add($env.Key) | Out-Null }
    }
    foreach ($t in ($Targets | Where-Object { $_ -ne "auto" -and $_ -ne "all" -and $_ -ne "" })) { $targetSet.Add($t) | Out-Null }

    foreach ($env in $ALL_ENVIRONMENTS) {
        if (($autoMode -or $targetSet.Contains($env.Key)) -and (Test-Path $env.Dir)) { $toInstall += $env }
    }
}
else {
    # ── Interactive menu ───────────────────────────────────────────────
    $menuOptions = $ALL_ENVIRONMENTS | Where-Object {
        # Filter: only show items where the parent directory structure makes sense
        # (JetBrains versions are wild — show all variants; users see which exist)
        $true
    }

    $toInstall = @(Show-Menu $menuOptions "Select editors to install AETHER_01 into:" "Enter numbers, 'A' for all, 'S' to skip, 'Q' to quit:")
}

# ════════════════════════════════════════════════════════════════════════
# Step 7: Install into chosen environments
# ════════════════════════════════════════════════════════════════════════

$installedCount = 0
$skippedCount   = 0
$failedCount    = 0

foreach ($env in $toInstall) {
    if (-not (Test-Path -LiteralPath $env.Dir)) {
        Write-Host "       [--] $($env.Icon) $($env.Name): not found — skipping" -ForegroundColor DarkGray
        $skippedCount++
        continue
    }
    try {
        Write-McpConfig -ConfigPath $env.Config -ClientName "$($env.Icon) $($env.Name)" -RootKey $env.Root `
                        -IsYaml:($env.Yaml -eq $true) -YamlIndent:($env.Indent)
        $installedCount++
    }
    catch {
        Write-Err "$($env.Name): $_"
        $failedCount++
    }
}

# ════════════════════════════════════════════════════════════════════════
# Step 8: Summary
# ════════════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   Installation Complete"                                    -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   Binary:    $exePath"                                      -ForegroundColor White
Write-Host "   .env:      $envFile"                                      -ForegroundColor White
Write-Host "   Installed: $installedCount environment(s)"                -ForegroundColor Green
if ($skippedCount -gt 0) { Write-Host "   Skipped:   $skippedCount"     -ForegroundColor DarkGray }
if ($failedCount  -gt 0) { Write-Host "   Failed:    $failedCount"      -ForegroundColor Red }

if ($script:warnings.Count -gt 0) { Write-Host ""; Write-Host "   Warnings:" -ForegroundColor Yellow; foreach ($w in $script:warnings) { Write-Host "     - $w" -ForegroundColor DarkGray } }
if ($script:errors.Count   -gt 0) { Write-Host ""; Write-Host "   Errors:"   -ForegroundColor Red;    foreach ($e in $script:errors)   { Write-Host "     - $e" -ForegroundColor Red } }

Write-Host ""
Write-Host "   Next steps:" -ForegroundColor Cyan
Write-Host "     1. Restart your editor/IDE"                            -ForegroundColor White
Write-Host "     2. Check AETHER_01 in the MCP panel"                   -ForegroundColor White
Write-Host "     3. For JetBrains: Settings → Tools → MCP → Refresh"    -ForegroundColor White
Write-Host "     4. For Continue.dev: restart the extension"            -ForegroundColor White
Write-Host ""

if (-not $isAdmin -and -not $NoAdminWarning) {
    Write-Host "   REMINDER: Run editor as Administrator."               -ForegroundColor Magenta
    Write-Host ""
}

Write-Host "============================================================" -ForegroundColor Cyan

exit $script:exitCode
