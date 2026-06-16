param(
    [string]$InstallDir,
    [string]$DataDir,
    [int]$Port = 0,
    [string]$ServiceName
)

$ErrorActionPreference = "Stop"

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Read-Default {
    param(
        [string]$Prompt,
        [string]$Default
    )
    $answer = Read-Host "$Prompt [$Default]"
    if ([string]::IsNullOrWhiteSpace($answer)) {
        return $Default
    }
    return $answer.Trim()
}

function Confirm-Continue {
    param([string]$Message)
    $answer = Read-Host "$Message (y/N)"
    if ($answer -notmatch "^[Yy]$") {
        throw "Installation cancelled."
    }
}

function Test-DirectoryHasEntries {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        return $false
    }
    $first = Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue | Select-Object -First 1
    return $null -ne $first
}

function New-Token {
    param([int]$Bytes = 32)
    $buffer = New-Object byte[] $Bytes
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($buffer)
    } finally {
        $rng.Dispose()
    }
    return [Convert]::ToBase64String($buffer).TrimEnd("=").Replace("+", "-").Replace("/", "_")
}

if (-not (Test-Admin)) {
    throw "Run this installer from an elevated PowerShell window."
}

$sourceDir = Split-Path -Parent $PSScriptRoot
if (-not $InstallDir) {
    $InstallDir = Read-Default "Install directory" "$env:ProgramFiles\IPMI_WEB"
}
if (-not $DataDir) {
    $DataDir = Read-Default "Data directory" "$env:ProgramData\IPMI_WEB"
}
if ($Port -eq 0) {
    $Port = [int](Read-Default "HTTP port" "90")
}
if (-not $ServiceName) {
    $ServiceName = Read-Default "Startup task name" "IPMI_WEB"
}
$installDependencies = Read-Default "Install Python dependencies automatically? (Y/n)" "Y"
if ($Port -lt 1 -or $Port -gt 65535) {
    throw "Invalid port: $Port"
}
if (Test-DirectoryHasEntries $InstallDir) {
    Confirm-Continue "Install directory '$InstallDir' already contains files. Continue and overwrite managed project files?"
}
if (Test-DirectoryHasEntries $DataDir) {
    Confirm-Continue "Data directory '$DataDir' already contains files. Continue and reuse this data directory?"
}
$existingTask = Get-ScheduledTask -TaskName $ServiceName -ErrorAction SilentlyContinue
if ($existingTask) {
    Confirm-Continue "Startup task '$ServiceName' already exists. Continue and replace its task definition?"
    Stop-ScheduledTask -TaskName $ServiceName -ErrorAction SilentlyContinue
}

$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    $python = Get-Command py -ErrorAction SilentlyContinue
}
if (-not $python) {
    throw "Python 3 was not found in PATH. Install Python 3 first, then rerun this script."
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null

$robocopyArgs = @(
    $sourceDir,
    $InstallDir,
    "/E",
    "/XD", ".venv", "__pycache__",
    "/XF", "*.pyc", "app.log*", "data.db*"
)
& robocopy @robocopyArgs | Out-Null
if ($LASTEXITCODE -gt 7) {
    throw "Failed to copy project files. robocopy exit code: $LASTEXITCODE"
}

$venvDir = Join-Path $InstallDir ".venv"
if ($installDependencies -match "^[Nn]$") {
    Write-Host "Skipping dependency installation. The selected Python environment must already provide the project requirements."
    $appPython = $python.Source
} else {
    & $python.Source -m venv $venvDir
    $appPython = Join-Path $venvDir "Scripts\python.exe"
    & $appPython -m pip install --upgrade pip
    & $appPython -m pip install -r (Join-Path $InstallDir "requirements.txt")
}

$bootstrapPassword = New-Token 24
$bootstrapSecret = New-Token 48
$dbPath = Join-Path $DataDir "data.db"
$repoUrl = ""
$repoBranch = "main"
$currentCommit = ""
try {
    $repoUrl = (& git -C $sourceDir config --get remote.origin.url 2>$null)
    $repoBranch = (& git -C $sourceDir rev-parse --abbrev-ref HEAD 2>$null)
    $currentCommit = (& git -C $sourceDir rev-parse HEAD 2>$null)
    if ([string]::IsNullOrWhiteSpace($repoBranch)) {
        $repoBranch = "main"
    }
} catch {
    $repoUrl = ""
    $repoBranch = "main"
    $currentCommit = ""
}

$config = [ordered]@{
    DATABASE = [ordered]@{
        path = $dbPath
        retention_days = 7
    }
    SERVER = [ordered]@{
        port = $Port
        server_name = "IPMI_WEB"
    }
    SECURITY = [ordered]@{
        login_password = $bootstrapPassword
        secret_key = $bootstrapSecret
        trusted_proxies = @()
    }
}
$metadata = [ordered]@{
    service_name = $ServiceName
    service_mode = "scheduled_task"
    install_root = $InstallDir
    data_root = $DataDir
    db_path = $dbPath
    port = $Port
    python = $appPython
    entrypoint = (Join-Path $InstallDir "app.py")
    auto_update_mode = "auto"
    update_channel = "release"
    update_channels = @("release", "dev")
    repo_url = $repoUrl
    branch = $repoBranch
    current_commit = $currentCommit
    setup_required = $true
}

$config | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 -Path (Join-Path $InstallDir "config.json")
$metadata | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 -Path (Join-Path $InstallDir "install.json")
$metadata | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 -Path (Join-Path $DataDir "install.json")

$action = New-ScheduledTaskAction `
    -Execute $appPython `
    -Argument ('"{0}"' -f (Join-Path $InstallDir "app.py")) `
    -WorkingDirectory $InstallDir
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
Register-ScheduledTask -TaskName $ServiceName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName $ServiceName

Write-Host ""
Write-Host "IPMI_WEB is installed and starting."
Write-Host "Open the setup wizard:"
Write-Host "  http://127.0.0.1:$Port/setup"
Write-Host ""
Write-Host "Startup task commands:"
Write-Host "  Get-ScheduledTask -TaskName $ServiceName"
Write-Host "  Stop-ScheduledTask -TaskName $ServiceName"
