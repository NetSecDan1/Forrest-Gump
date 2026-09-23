#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    EXAMPLE - DO NOT RUN IN PRODUCTION WITHOUT CHANGE APPROVAL.
    Registers adhealth-agent as scheduled tasks on the agent host (reads the drop share directly - Option A).

.DESCRIPTION
    CHANGE to the agent host only (creates scheduled tasks). No change to AD. Supports -WhatIf / -Confirm.

      * ADHealth-Agent-Process : hourly - ingest new bundles (idempotent), urgent Teams alerts, SharePoint archive
      * ADHealth-Agent-Digest  : 2nd of each month at -DigestTime - monthly narrative digest

    Runs as a gMSA that has READ on the drop share. Secrets are machine environment variables on this dedicated
    host (ADHEALTH_TEAMS_*, ADHEALTH_GRAPH_*, AWS_CONFIG_FILE/AWS_PROFILE for Bedrock via Roles Anywhere); keep the host Tier-0 hardened, or move secrets
    to a vault when the agent moves to a managed platform.

.PARAMETER GmsaName
    e.g. 'CONTOSO\gmsa-adhealth-agent$' (a separate gMSA from the collector: read-only on the share).

.PARAMETER AgentExe
    Full path to adhealth-agent.exe in the agent's virtualenv, e.g. C:\ADHealth\agent\.venv\Scripts\adhealth-agent.exe

.PARAMETER ConfigPath
    Full path to settings.yaml.

.EXAMPLE
    .\Register-ADHealthAgentTask.ps1 -GmsaName 'CONTOSO\gmsa-adhealth-agent$' -AgentExe C:\ADHealth\agent\.venv\Scripts\adhealth-agent.exe -ConfigPath C:\ADHealth\agent\config\settings.yaml -WhatIf

.NOTES
    Backout: Unregister-ScheduledTask -TaskPath '\ADHealth\' -TaskName 'ADHealth-Agent-Process','ADHealth-Agent-Digest' -Confirm
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][ValidatePattern('\$$')][string]$GmsaName,
    [Parameter(Mandatory)][string]$AgentExe,
    [Parameter(Mandatory)][string]$ConfigPath,
    [ValidatePattern('^\d{2}:\d{2}$')][string]$DigestTime = '08:00'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---- pre-flight (read-only) ----
foreach ($p in $AgentExe, $ConfigPath) { if (-not (Test-Path -LiteralPath $p)) { throw "Not found: $p" } }
Import-Module ActiveDirectory
if (-not (Test-ADServiceAccount -Identity $GmsaName.Split('\')[-1])) { throw "gMSA $GmsaName is not usable on this host." }
foreach ($v in 'ADHEALTH_TEAMS_URGENT_WEBHOOK', 'ADHEALTH_TEAMS_DIGEST_WEBHOOK') {
    if (-not [Environment]::GetEnvironmentVariable($v, 'Machine')) { Write-Warning "$v not set at machine scope - agent will stay in dry-run for Teams." }
}

$esc = [System.Security.SecurityElement]
$start = (Get-Date).Date.AddDays(1).ToString('yyyy-MM-dd')
$workDir = Split-Path -Parent $ConfigPath
$tasks = @(
    @{ Name = 'ADHealth-Agent-Process'; Args = "process -c `"$ConfigPath`""; Desc = 'AD health agent - ingest bundles and send urgent alerts'
        Trigger = "<CalendarTrigger><StartBoundary>${start}T00:15:00</StartBoundary><Repetition><Interval>PT1H</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger>" }
    @{ Name = 'ADHealth-Agent-Digest'; Args = "digest -c `"$ConfigPath`""; Desc = 'AD health agent - monthly digest'
        Trigger = "<CalendarTrigger><StartBoundary>${start}T${DigestTime}:00</StartBoundary><ScheduleByMonth><DaysOfMonth><Day>2</Day></DaysOfMonth><Months><January/><February/><March/><April/><May/><June/><July/><August/><September/><October/><November/><December/></Months></ScheduleByMonth></CalendarTrigger>" }
)

foreach ($t in $tasks) {
    $xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>$($esc::Escape($t.Desc))</Description></RegistrationInfo>
  <Triggers>$($t.Trigger)</Triggers>
  <Principals><Principal id="Author"><UserId>$($esc::Escape($GmsaName))</UserId><LogonType>Password</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author"><Exec>
    <Command>$($esc::Escape($AgentExe))</Command>
    <Arguments>$($esc::Escape($t.Args))</Arguments>
    <WorkingDirectory>$($esc::Escape($workDir))</WorkingDirectory>
  </Exec></Actions>
</Task>
"@
    Write-Verbose $xml
    if ($PSCmdlet.ShouldProcess("\ADHealth\$($t.Name) as $GmsaName", "Register scheduled task: $AgentExe $($t.Args)")) {
        Register-ScheduledTask -TaskPath '\ADHealth\' -TaskName $t.Name -Xml $xml -Force | Out-Null
        Write-Output "Registered \ADHealth\$($t.Name)"
    }
}
