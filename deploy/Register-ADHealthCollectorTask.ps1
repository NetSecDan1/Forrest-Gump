#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    EXAMPLE - DO NOT RUN IN PRODUCTION WITHOUT CHANGE APPROVAL.
    Registers the AD health collector as scheduled tasks on the collector (jump) host, running as a gMSA.

.DESCRIPTION
    This is a CHANGE to the collector host (creates scheduled tasks). It makes no change to Active Directory.
    Supports -WhatIf / -Confirm (ConfirmImpact High: prompts unless -Confirm:$false).

    Creates up to two tasks under \ADHealth\:
      * ADHealth-Monthly-Full : 1st of each month at -MonthlyTime, all checks (the digest baseline)
      * ADHealth-Daily-Light  : daily at -DailyTime, low-load checks only (-SkipHygiene -SkipDcDiag) for fast urgent alerts
    Tasks run with the gMSA (no stored password), highest privileges NOT requested, 6-hour execution limit,
    no overlapping instances.

    Pre-flight (read-only): verifies the gMSA can be used on this host (Test-ADServiceAccount), the collector
    script exists, and the output path is reachable.

.PARAMETER GmsaName
    gMSA sAMAccountName including the trailing $, e.g. 'CONTOSO\gmsa-adhealth$'.

.PARAMETER CollectorPath
    Full path to Invoke-ADForestHealthReport.ps1 on this host.

.PARAMETER OutputPath
    The -OutputPath passed to the collector (drop share inbox).

.PARAMETER IncludeDaily
    Also register the daily light task.

.EXAMPLE
    .\Register-ADHealthCollectorTask.ps1 -GmsaName 'CONTOSO\gmsa-adhealth$' -CollectorPath C:\ADHealth\collector\Invoke-ADForestHealthReport.ps1 -OutputPath \\fs01\ADHealth$\inbox -WhatIf
    Shows exactly what would be registered. Nothing is changed.

.NOTES
    Backout: Unregister-ScheduledTask -TaskPath '\ADHealth\' -TaskName 'ADHealth-Monthly-Full','ADHealth-Daily-Light' -Confirm
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][ValidatePattern('\$$')][string]$GmsaName,
    [Parameter(Mandatory)][string]$CollectorPath,
    [Parameter(Mandatory)][string]$OutputPath,
    [ValidatePattern('^\d{2}:\d{2}$')][string]$MonthlyTime = '02:00',
    [ValidatePattern('^\d{2}:\d{2}$')][string]$DailyTime = '05:30',
    [switch]$IncludeDaily
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---- pre-flight (read-only) ----
if (-not (Test-Path -LiteralPath $CollectorPath)) { throw "Collector not found: $CollectorPath" }
Import-Module ActiveDirectory
$samOnly = $GmsaName.Split('\')[-1]
if (-not (Test-ADServiceAccount -Identity $samOnly)) {
    throw "gMSA $GmsaName cannot be used on this host. Add this computer to the gMSA's PrincipalsAllowedToRetrieveManagedPassword (change) and reboot/klist purge."
}
if (-not (Test-Path -LiteralPath $OutputPath)) { Write-Warning "OutputPath $OutputPath not reachable from this session; confirm the gMSA has Modify on it." }

function New-TaskXml {
    param([string]$Arguments, [string]$TriggerXml, [string]$Description)
    $esc = [System.Security.SecurityElement]
    @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>$($esc::Escape($Description))</Description></RegistrationInfo>
  <Triggers>$TriggerXml</Triggers>
  <Principals><Principal id="Author"><UserId>$($esc::Escape($GmsaName))</UserId><LogonType>Password</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT6H</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author"><Exec>
    <Command>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Command>
    <Arguments>$($esc::Escape($Arguments))</Arguments>
  </Exec></Actions>
</Task>
"@
}

$start = (Get-Date).Date.AddDays(1).ToString('yyyy-MM-dd')
$base = "-NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File `"$CollectorPath`" -OutputPath `"$OutputPath`""
$tasks = @(
    @{ Name = 'ADHealth-Monthly-Full'; Args = "$base -HoursBack 720"; Desc = 'AD forest health - monthly full read-only collection'
        Trigger = "<CalendarTrigger><StartBoundary>${start}T${MonthlyTime}:00</StartBoundary><ScheduleByMonth><DaysOfMonth><Day>1</Day></DaysOfMonth><Months><January/><February/><March/><April/><May/><June/><July/><August/><September/><October/><November/><December/></Months></ScheduleByMonth></CalendarTrigger>" }
)
if ($IncludeDaily) {
    $tasks += @{ Name = 'ADHealth-Daily-Light'; Args = "$base -HoursBack 26 -SkipHygiene -SkipDcDiag"; Desc = 'AD forest health - daily low-load read-only collection (urgent alerting)'
        Trigger = "<CalendarTrigger><StartBoundary>${start}T${DailyTime}:00</StartBoundary><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger>" }
}

foreach ($t in $tasks) {
    $xml = New-TaskXml -Arguments $t.Args -TriggerXml $t.Trigger -Description $t.Desc
    Write-Verbose $xml
    if ($PSCmdlet.ShouldProcess("\ADHealth\$($t.Name) as $GmsaName", "Register scheduled task: powershell.exe $($t.Args)")) {
        Register-ScheduledTask -TaskPath '\ADHealth\' -TaskName $t.Name -Xml $xml -Force | Out-Null
        Write-Output "Registered \ADHealth\$($t.Name)"
    }
}
