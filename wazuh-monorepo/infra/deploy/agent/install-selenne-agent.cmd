<# : batch portion
@echo off
rem ── Selenne — Windows endpoint installer (batch + PowerShell hybrid) ────────
rem  Windows never runs a .ps1 on double-click: Microsoft associates that
rem  extension with an editor on purpose, which is why double-clicking one only
rem  offers "choose an app". .cmd is always associated with the command
rem  processor, so this file ships as .cmd and hands itself to PowerShell here.
rem  Everything from ": end batch" down is the installer, in plain PowerShell —
rem  PowerShell reads the lines above as one block comment, so the very same
rem  file also runs as a .ps1 for anyone who prefers that.
rem
rem  %~f0 (this file's own path) is invisible to the PowerShell side, so pass it
rem  along: the script needs it to re-launch itself elevated.
setlocal
set "SELENNE_SELF=%~f0"
rem  -Encoding UTF8 is not optional: Windows PowerShell 5.1 otherwise reads this
rem  file in the system ANSI codepage and garbles the accented output text.
powershell -NoProfile -ExecutionPolicy Bypass -Command "& ([ScriptBlock]::Create((Get-Content -Raw -Encoding UTF8 -LiteralPath $env:SELENNE_SELF)))"
set "SELENNE_RC=%errorlevel%"
rem  Double-clicked windows vanish on exit; hold the console open if it failed
rem  before PowerShell got far enough to say anything (rc 2 = the script itself
rem  reported the error and already waited).
if not "%SELENNE_RC%"=="0" if not "%SELENNE_RC%"=="2" pause
exit /b %SELENNE_RC%
: end batch / begin powershell #>

# ─────────────────────────────────────────────────────────────────────────────
#  Selenne — Windows endpoint installer
#
#  Installs the Wazuh agent on this Windows machine and enrols it with the
#  Selenne platform, so this computer's security events are collected, scored by
#  Selenne's ML engine and shown in your dashboard at https://__DASHBOARD__.
#
#  Easiest: double-click this file. It asks Windows for administrator rights
#  itself (the standard UAC prompt) — no need to open an elevated console first.
#
#  Or from any PowerShell / cmd prompt:
#      .\install-selenne-agent.cmd
#  (-File needs a .ps1 name, so call the file itself — it re-enters PowerShell.)
#
#  Keep selenne.ico (shipped in the same download package) next to this file:
#  it becomes the Start Menu entry's icon. Missing it costs only the shortcut.
#
#  Enrolment details below are unique to your account — do not share this file.
# ─────────────────────────────────────────────────────────────────────────────
$ErrorActionPreference = 'Stop'
# The console is on the OEM codepage by default, which renders the dashes and
# accents in the messages below as '?'. Cosmetic only — never fail over it.
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }

# Two hosts on purpose: agent traffic is raw TCP on 1514/1515, so $Manager must
# be a DNS-only name pointing at the origin. $Dashboard is the https name to open.
$Manager      = '__MANAGER__'
$Dashboard    = '__DASHBOARD__'
$RegPassword  = '__REG_PASSWORD__'
$AgentGroup   = '__AGENT_GROUP__'
$AgentVersion = '__AGENT_VERSION__'
$Owner        = '__OWNER__'
# The owner travels with the agent name, so this machine's events are attributed
# to the right Selenne account even after a re-enrolment or a database restore.
$Machine      = if ($env:SELENNE_AGENT_NAME) { $env:SELENNE_AGENT_NAME } else { $env:COMPUTERNAME }
$AgentName    = "$Owner`__$Machine"

function Say  { param($m) Write-Host $m -ForegroundColor Cyan }
function Warn { param($m) Write-Host "  $m" -ForegroundColor Yellow }
# Exit code 2 tells the batch header "already reported, already waited" so the
# user does not get a second 'press any key' prompt on the way out.
function Die  { param($m) Write-Host "ERROR: $m" -ForegroundColor Red; Read-Host 'Press Enter to close'; exit 2 }

Say '== Selenne endpoint installer =='

# 1. Must be elevated — the agent installs as a Windows service ---------------
# Rather than telling the user to go and find an admin PowerShell, relaunch
# ourselves elevated: Windows shows its standard UAC consent dialog, which is
# the same prompt any app installer raises. Declining it throws, and we fall
# back to the manual instruction.
#
# Which path to relaunch depends on how we were started: the batch header sets
# SELENNE_SELF (the .cmd), while a direct `-File script.ps1` run only has
# $PSCommandPath. Running through the ScriptBlock hand-off leaves $PSCommandPath
# empty, so the env var has to come first.
$Self = if ($env:SELENNE_SELF)  { $env:SELENNE_SELF }
        elseif ($PSCommandPath) { $PSCommandPath }
        else                    { $null }

$admin = ([Security.Principal.WindowsPrincipal] `
          [Security.Principal.WindowsIdentity]::GetCurrent()
         ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    if (-not $Self) {
        Die 'Run this from an Administrator PowerShell (right-click PowerShell -> "Run as administrator").'
    }
    Say '  Requesting administrator rights — approve the Windows prompt...'
    try {
        if ($Self -like '*.ps1') {
            Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList @(
                '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$Self`""
            ) | Out-Null
        } else {
            # cmd.exe /c keeps the elevated console attached to this script, and
            # the batch header re-establishes SELENNE_SELF in that new process.
            Start-Process -FilePath $env:ComSpec -Verb RunAs -ArgumentList @(
                '/c', "`"$Self`""
            ) | Out-Null
        }
    } catch {
        Die 'Administrator rights are required, and the prompt was dismissed. Right-click PowerShell -> "Run as administrator", then run this script again.'
    }
    exit 0
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
    # Not $args: that automatic variable carries the script block's own
    # arguments when this file is run through the batch hand-off.
    $msiArgs = @(
        '/i', "`"$msiPath`"", '/q',
        "WAZUH_MANAGER=`"$Manager`"",
        "WAZUH_REGISTRATION_SERVER=`"$Manager`"",
        "WAZUH_REGISTRATION_PASSWORD=`"$RegPassword`"",
        "WAZUH_AGENT_NAME=`"$AgentName`"",
        "WAZUH_AGENT_GROUP=`"$AgentGroup`""
    )
    $p = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
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

# 6. Start Menu entry ---------------------------------------------------------
# selenne.ico ships next to this script in the download package. A .url
# shortcut is deliberate: a .lnk cannot point at a web address without going
# through explorer.exe, while an InternetShortcut takes its own IconFile.
# Purely cosmetic — never let it fail the install.
$iconSrc = if ($Self) { Join-Path (Split-Path -Parent $Self) 'selenne.ico' } else { $null }
if ($iconSrc -and (Test-Path $iconSrc)) {
    try {
        $iconDst = Join-Path $installDir 'selenne.ico'
        Copy-Item -LiteralPath $iconSrc -Destination $iconDst -Force
        $programs = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs'
        @('[InternetShortcut]',
          "URL=https://$Dashboard/",
          "IconFile=$iconDst",
          'IconIndex=0') |
            Set-Content -LiteralPath (Join-Path $programs 'Selenne.url') -Encoding ASCII
        Say '  Added Selenne to the Start Menu.'
    } catch {
        Warn "Could not create the Start Menu shortcut ($($_.Exception.Message))"
    }
}
# No icon beside the script (bare .cmd download, or run straight out of the zip
# viewer) is a normal case, not a problem — skip the shortcut without comment.

Start-Sleep -Seconds 5
$svc = Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') {
    Write-Host ''
    Say 'Done — this computer is now monitored by Selenne.'
    Write-Host "  Events flow to https://$Dashboard — they appear in Live Alerts within a minute." -ForegroundColor Gray
    Write-Host "  Endpoint: $Machine   (account: $Owner)" -ForegroundColor Gray
    Write-Host "  Your dashboard is in the Start Menu under 'Selenne'." -ForegroundColor Gray
} else {
    Warn 'The agent service did not start. Check C:\Program Files (x86)\ossec-agent\ossec.log'
}

if (Test-Path $msiPath) { Remove-Item $msiPath -Force -ErrorAction SilentlyContinue }
Write-Host ''
Read-Host 'Press Enter to close'
