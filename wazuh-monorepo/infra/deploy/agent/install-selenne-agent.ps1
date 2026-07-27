# ─────────────────────────────────────────────────────────────────────────────
#  Selenne — Windows endpoint installer
#
#  Installs the Wazuh agent on this Windows machine and enrols it with the
#  Selenne platform, so this computer's security events are collected, scored by
#  Selenne's ML engine and shown in your dashboard at https://__MANAGER__.
#
#  Run in an ADMINISTRATOR PowerShell:
#      powershell -ExecutionPolicy Bypass -File .\install-selenne-agent.ps1
#
#  Enrolment details below are unique to your account — do not share this file.
# ─────────────────────────────────────────────────────────────────────────────
$ErrorActionPreference = 'Stop'

$Manager      = '__MANAGER__'
$RegPassword  = '__REG_PASSWORD__'
$AgentGroup   = '__AGENT_GROUP__'
$AgentVersion = '__AGENT_VERSION__'
$AgentName    = if ($env:SELENNE_AGENT_NAME) { $env:SELENNE_AGENT_NAME } else { $env:COMPUTERNAME }

function Say  { param($m) Write-Host $m -ForegroundColor Cyan }
function Warn { param($m) Write-Host "  $m" -ForegroundColor Yellow }
function Die  { param($m) Write-Host "ERROR: $m" -ForegroundColor Red; Read-Host 'Press Enter to close'; exit 1 }

Say '== Selenne endpoint installer =='

# 1. Must be elevated — the agent installs as a Windows service ---------------
$admin = ([Security.Principal.WindowsPrincipal] `
          [Security.Principal.WindowsIdentity]::GetCurrent()
         ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    Die 'Run this from an Administrator PowerShell (right-click PowerShell -> "Run as administrator").'
}

# 2. Already installed? Re-enrol instead of installing twice ------------------
$installDir = Join-Path ${env:ProgramFiles(x86)} 'ossec-agent'
$existing   = Test-Path (Join-Path $installDir 'wazuh-agent.exe')
if ($existing) {
    Warn 'Agent already installed — re-enrolling it with your Selenne account.'
    Stop-Service -Name WazuhSvc -ErrorAction SilentlyContinue
}

# 3. Download the official Wazuh agent package -------------------------------
$msiName = "wazuh-agent-$AgentVersion-1.msi"
$msiUrl  = "https://packages.wazuh.com/4.x/windows/$msiName"
$msiPath = Join-Path $env:TEMP $msiName

if (-not $existing) {
    Say "  Downloading the agent ($msiName)..."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    try {
        Invoke-WebRequest -Uri $msiUrl -OutFile $msiPath -UseBasicParsing
    } catch {
        Die "Could not download the agent from $msiUrl — check the internet connection. ($_)"
    }

    # 4. Silent install, enrolling against the Selenne manager ----------------
    Say "  Installing and enrolling as '$AgentName'..."
    $args = @(
        '/i', "`"$msiPath`"", '/q',
        "WAZUH_MANAGER=`"$Manager`"",
        "WAZUH_REGISTRATION_SERVER=`"$Manager`"",
        "WAZUH_REGISTRATION_PASSWORD=`"$RegPassword`"",
        "WAZUH_AGENT_NAME=`"$AgentName`"",
        "WAZUH_AGENT_GROUP=`"$AgentGroup`""
    )
    $p = Start-Process msiexec.exe -ArgumentList $args -Wait -PassThru
    if ($p.ExitCode -ne 0) { Die "Installer failed with exit code $($p.ExitCode)." }
} else {
    # Re-enrol an existing installation
    Say "  Re-enrolling as '$AgentName'..."
    & (Join-Path $installDir 'agent-auth.exe') -m $Manager -P $RegPassword -A $AgentName -G $AgentGroup
    if ($LASTEXITCODE -ne 0) { Die 'Enrolment failed — check that the manager is reachable on port 1515.' }
}

# 5. Start the service --------------------------------------------------------
Say '  Starting the Selenne agent service...'
Start-Service -Name WazuhSvc
Set-Service  -Name WazuhSvc -StartupType Automatic

Start-Sleep -Seconds 5
$svc = Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') {
    Write-Host ''
    Say 'Done — this computer is now monitored by Selenne.'
    Write-Host "  Events flow to https://$Manager — they appear in Live Alerts within a minute." -ForegroundColor Gray
    Write-Host "  Endpoint name: $AgentName" -ForegroundColor Gray
} else {
    Warn 'The agent service did not start. Check C:\Program Files (x86)\ossec-agent\ossec.log'
}

if (Test-Path $msiPath) { Remove-Item $msiPath -Force -ErrorAction SilentlyContinue }
Write-Host ''
Read-Host 'Press Enter to close'
