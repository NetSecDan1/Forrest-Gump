#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only Active Directory forest health collector. Produces an HTML + JSON + CSV report bundle
    designed to be consumed by humans (HTML) and by the downstream triage agent (report.json).

.DESCRIPTION
    Runs a fixed catalog of READ-ONLY checks across the forest (or a scoped subset of domains/DCs):

      Forest / FSMO      : functional levels, Recycle Bin, tombstone lifetime, FSMO holder validity
      DC health          : TCP reachability (LDAP/Kerberos/SMB/RPC/GC/DNS/WinRM), RootDSE bind,
                           OS lifecycle, core services, disk free, uptime (CIM)
      Time               : per-DC clock offset vs forest-root PDC, root PDC time source (w32tm)
      Replication        : partner metadata (lag / consecutive failures), replication failures,
                           repadmin /showrepl /csv cross-check, repadmin /replsummary evidence
      SYSVOL             : FRS->DFSR migration state, SYSVOL/NETLOGON share availability,
                           DFSR replicated-folder state (CIM)
      DNS                : DC-locator SRV registration (domain, PDC, GC) and per-DC DNS consistency
      Backup             : per-naming-context last backup (dSASignature metadata)
      dcdiag             : per-DC dcdiag (default read-only test set, SystemLog skipped)
      Event logs         : targeted high-signal event IDs (USN rollback, lingering objects, DFSR
                           dirty shutdown, Netlogon, W32Time, KDC) within -HoursBack
      Trusts             : SID filtering, TGT delegation, AES, secure channel (nltest /sc_query)
      Sites              : sites without subnets, unassigned subnets, degenerate site links
      Kerberos           : krbtgt (incl. RODC krbtgt_*) password age
      Privileged access  : protected group membership (SID-based, nested via IN_CHAIN), privileged
                           account hygiene, adminCount orphans, built-in Administrator
      Hygiene            : stale users/computers, password-never-expires, PASSWD_NOTREQD,
                           AS-REP roastable, kerberoastable, unconstrained/protocol-transition
                           delegation, reversible encryption, DES-only, sIDHistory, unsupported OS,
                           LAPS coverage, MachineAccountQuota, Guest, default password policy

    NOTHING in this script writes to Active Directory, DNS, GPO, the registry, or services on any
    DC. The only writes are the report files under -OutputPath.

    Output bundle is built in <OutputPath>\.staging\<bundle> and renamed into <OutputPath>\<bundle>
    only when complete. manifest.json (SHA-256 of every file) is written last. Downstream automation
    MUST only pick up folders that contain manifest.json.

.PARAMETER OutputPath
    Root folder (local path or UNC share) where the bundle folder is created.

.PARAMETER Forest
    Optional forest DNS name. Defaults to the forest of the logged-on user.

.PARAMETER Domain
    Optional list of domain DNS names to limit scope. Default: all domains in the forest.

.PARAMETER DomainController
    Optional list of DC names (short or FQDN) to limit per-DC checks. Useful for pilots.

.PARAMETER HoursBack
    Event-log look-back window in hours. Default 720 (30 days) for a monthly cadence.

.PARAMETER StaleDays
    Inactivity threshold for stale users/computers. Default 90.

.PARAMETER BackupWarnDays
    Naming-context backup age that raises a High finding. Default 7. Critical at tombstone/2.

.PARAMETER ReplLagWarnHours
    Replication lag (hours since last success) that raises a High finding. Default 24.

.PARAMETER TimeSkewWarnSeconds
    DC clock offset vs forest-root PDC that raises a High finding. Default 60. Critical at 240
    (Kerberos default tolerance is 300 s).

.PARAMETER PrivilegedGroupWarnCount
    Member count above which Domain/Enterprise Admins membership raises a Medium finding. Default 10.

.PARAMETER SampleSize
    Max object names embedded per finding in report.json. Full lists go to detail\*.csv. Default 25.

.PARAMETER MaxEventsPerQuery
    Cap on events read per DC per log query. Default 500.

.PARAMETER NativeToolTimeoutSec
    Timeout for each dcdiag/repadmin/nltest/w32tm invocation. Default 600.

.PARAMETER PortTimeoutMs
    TCP connect timeout per port probe. Default 2000.

.PARAMETER MaxRuntimeMinutes
    Performance budget. Exceeding it adds a Low finding (the run is not aborted). Default 240.

.PARAMETER SkipDcDiag
    Do not run dcdiag (fastest reduction in DC load and runtime).

.PARAMETER SkipEventLogs
    Do not query remote event logs.

.PARAMETER SkipRemoteCim
    Do not use CIM/WinRM (services, disk, uptime, DFSR folder state are then not collected).

.PARAMETER SkipHygiene
    Do not run object-hygiene/privileged-access LDAP queries (the heaviest LDAP load in large domains).

.PARAMETER RedactNames
    Replace account names in report.json, findings and detail CSVs with stable hashed identifiers.

.PARAMETER SigningCertificateThumbprint
    Sign manifest.json with this certificate (LocalMachine\My or CurrentUser\My, private key required) and write
    manifest.sig.json. The agent pins the thumbprint, so an attacker who can write to the share cannot forge a
    bundle by editing files and re-hashing the manifest. Fails closed: if signing fails, nothing is published.

.EXAMPLE
    .\Invoke-ADForestHealthReport.ps1 -OutputPath D:\ADHealth -DomainController LABDC01,LABDC02 -Verbose
    Pilot: two DCs only, full check set, verbose progress.

.EXAMPLE
    .\Invoke-ADForestHealthReport.ps1 -OutputPath \\fs01\ADHealth$\inbox -HoursBack 720
    Monthly production run to the drop share consumed by the triage agent.

.EXAMPLE
    .\Invoke-ADForestHealthReport.ps1 -OutputPath D:\ADHealth -SkipDcDiag -SkipEventLogs -SkipHygiene
    Minimal-load run (LDAP topology/replication/DNS/backup/time only).

.NOTES
    Version        : 1.0.0 (report schema 1.0)
    Requires       : Windows PowerShell 5.1 or PowerShell 7 on Windows; RSAT ActiveDirectory module;
                     repadmin/dcdiag/nltest/w32tm (RSAT AD DS tools) for native-tool checks.
    Permissions    : Authenticated domain user is sufficient for most checks. Remote event logs
                     require Event Log Readers on DCs; CIM requires WinRM access (Remote Management
                     Users) or admin; DFSR WMI namespace may require admin. Missing rights surface as
                     collection errors, never as "healthy".
    Exit codes     : 0 = complete, no collection gaps; 3 = complete with collection gaps; 1 = fatal.
    Safety         : Read-only against AD/DCs. Writes only under -OutputPath.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$OutputPath,
    [string]$Forest,
    [string[]]$Domain,
    [string[]]$DomainController,
    [ValidateRange(1, 8760)][int]$HoursBack = 720,
    [ValidateRange(7, 3650)][int]$StaleDays = 90,
    [ValidateRange(1, 365)][int]$BackupWarnDays = 7,
    [ValidateRange(1, 720)][int]$ReplLagWarnHours = 24,
    [ValidateRange(1, 3600)][int]$TimeSkewWarnSeconds = 60,
    [ValidateRange(1, 1000)][int]$PrivilegedGroupWarnCount = 10,
    [ValidateRange(1, 1000)][int]$SampleSize = 25,
    [ValidateRange(10, 10000)][int]$MaxEventsPerQuery = 500,
    [ValidateRange(30, 7200)][int]$NativeToolTimeoutSec = 600,
    [ValidateRange(200, 30000)][int]$PortTimeoutMs = 2000,
    [ValidateRange(5, 1440)][int]$MaxRuntimeMinutes = 240,
    [switch]$SkipDcDiag,
    [switch]$SkipEventLogs,
    [switch]$SkipRemoteCim,
    [switch]$SkipHygiene,
    [switch]$RedactNames,
    [ValidatePattern('^[0-9A-Fa-f ]{40,59}$')][string]$SigningCertificateThumbprint
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:CollectorVersion = '1.0.0'
$script:SchemaVersion = '1.0'
$script:StartTime = Get-Date
. (Join-Path $PSScriptRoot 'ADHealth.Report.ps1')

$script:Findings = [System.Collections.Generic.List[object]]::new()
$script:Checks = [System.Collections.Generic.List[object]]::new()
$script:Errors = [System.Collections.Generic.List[object]]::new()
$script:RawOutputs = [System.Collections.Generic.List[object]]::new()
$script:Metrics = [ordered]@{}
$script:DcList = [System.Collections.Generic.List[object]]::new()      # [ordered] hashtables
$script:DomainList = [System.Collections.Generic.List[object]]::new()  # [ordered] hashtables
$script:ProtectedMemberDNs = @{}                                        # DN -> $true (for adminCount orphans)
$script:LogFile = $null

#region ---------- helpers -------------------------------------------------------------------------

function Write-CollectorLog {
    param([Parameter(Mandatory)][string]$Message, [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'), $Level, $Message
    Write-Verbose $line
    if ($script:LogFile) { Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 }
}

function Add-CollectorError {
    param([string]$Stage, [string]$Target, [string]$Message)
    $script:Errors.Add([pscustomobject][ordered]@{ stage = $Stage; target = $Target; message = $Message })
    Write-CollectorLog -Level ERROR -Message "[$Stage] $Target :: $Message"
}

function Add-Finding {
    param(
        [Parameter(Mandatory)][string]$CheckId,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')][string]$Severity,
        [Parameter(Mandatory)][string]$Title,
        [string]$Target = 'forest',
        [string]$Detail = '',
        [string]$Recommendation = '',
        [int]$Count = 1,
        [string]$EvidenceRef = '',
        [string[]]$Sample = @()
    )
    # id is a STABLE key (check + target) so the agent can diff month over month.
    $script:Findings.Add([pscustomobject][ordered]@{
            id             = ('{0}|{1}' -f $CheckId, $Target.ToLowerInvariant())
            checkId        = $CheckId
            category       = $Category
            severity       = $Severity
            title          = $Title
            target         = $Target
            count          = $Count
            detail         = $Detail
            recommendation = $Recommendation
            evidenceRef    = $EvidenceRef
            sample         = @($Sample | Select-Object -First $SampleSize)
        })
}

function Add-Metric {
    param([Parameter(Mandatory)][string]$Name, [double]$Value, [ValidateSet('Sum', 'Max', 'Min', 'Set')][string]$Mode = 'Sum')
    if (-not $script:Metrics.Contains($Name)) { $script:Metrics[$Name] = $Value; return }
    switch ($Mode) {
        'Sum' { $script:Metrics[$Name] = $script:Metrics[$Name] + $Value }
        'Max' { if ($Value -gt $script:Metrics[$Name]) { $script:Metrics[$Name] = $Value } }
        'Min' { if ($Value -lt $script:Metrics[$Name]) { $script:Metrics[$Name] = $Value } }
        'Set' { $script:Metrics[$Name] = $Value }
    }
}

function Invoke-HealthCheck {
    <#
        Runs one check in isolation. A throw marks the check 'Error' (area NOT verified) and the run
        continues. Per-target errors logged via Add-CollectorError mark the check 'Partial'.
        The scriptblock's LAST output line is used as the check summary.
    #>
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Command,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [switch]$Skip,
        [string]$SkipReason = 'Skipped by operator switch.'
    )
    if ($Skip) {
        $script:Checks.Add([pscustomobject][ordered]@{ id = $Id; category = $Category; name = $Name; status = 'Skipped'; summary = $SkipReason; findingCount = 0; durationMs = 0; command = $Command })
        Write-CollectorLog "SKIP  $Id $Name"
        return
    }
    Write-CollectorLog "START $Id $Name"
    Write-Progress -Activity 'AD forest health' -Status "$Id $Name"
    $findingsBefore = $script:Findings.Count
    $errorsBefore = $script:Errors.Count
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $status = 'Pass'
    $summary = ''
    try {
        $out = @(& $ScriptBlock)
        if ($out.Count -gt 0) { $summary = [string]$out[-1] }
    }
    catch {
        $status = 'Error'
        $summary = "Check failed: $($_.Exception.Message)"
        Add-CollectorError -Stage $Id -Target 'check' -Message $_.Exception.Message
    }
    $sw.Stop()
    $new = @()
    if ($script:Findings.Count -gt $findingsBefore) { $new = @($script:Findings.GetRange($findingsBefore, $script:Findings.Count - $findingsBefore)) }
    if ($status -ne 'Error') {
        if (@($new | Where-Object { $_.severity -in 'Critical', 'High' }).Count -gt 0) { $status = 'Fail' }
        elseif (@($new | Where-Object { $_.severity -in 'Medium', 'Low' }).Count -gt 0) { $status = 'Warn' }
        if ($script:Errors.Count -gt $errorsBefore -and $status -eq 'Pass') { $status = 'Partial' }
    }
    $script:Checks.Add([pscustomobject][ordered]@{ id = $Id; category = $Category; name = $Name; status = $status; summary = $summary; findingCount = $new.Count; durationMs = $sw.ElapsedMilliseconds; command = $Command })
    Write-CollectorLog "END   $Id status=$status findings=$($new.Count) ms=$($sw.ElapsedMilliseconds)"
}

function Test-TcpPort {
    param([Parameter(Mandatory)][string]$ComputerName, [Parameter(Mandatory)][int]$Port, [int]$TimeoutMs = $PortTimeoutMs)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return $false }
        $client.EndConnect($iar)
        return $true
    }
    catch { return $false }
    finally { $client.Close() }
}

function Invoke-NativeTool {
    <# Runs a read-only native tool with a hard timeout; full output is saved under raw\. #>
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$ArgumentList,
        [Parameter(Mandatory)][string]$RawName,
        [int]$TimeoutSec = $NativeToolTimeoutSec
    )
    $exe = Get-Command -Name $FilePath -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $exe) { throw "$FilePath not found on collector host (install RSAT AD DS tools)." }
    $safe = $RawName -replace '[^\w\.-]', '_'
    $outFile = Join-Path $script:RawDir "$safe.txt"
    $errFile = Join-Path $script:RawDir "$safe.stderr.txt"
    $cmd = "$FilePath $($ArgumentList -join ' ')"
    $p = Start-Process -FilePath $exe.Source -ArgumentList $ArgumentList -NoNewWindow -PassThru `
        -RedirectStandardOutput $outFile -RedirectStandardError $errFile
    $null = $p.Handle   # caches the handle so ExitCode is available after exit
    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
        try { $p.Kill() } catch { Write-CollectorLog -Level WARN "Could not stop timed-out $FilePath : $($_.Exception.Message)" }
        throw "$cmd timed out after $TimeoutSec s"
    }
    $text = Get-Content -LiteralPath $outFile -Raw -ErrorAction SilentlyContinue
    if ($null -eq $text) { $text = '' }
    if ((Test-Path -LiteralPath $errFile) -and (Get-Item -LiteralPath $errFile).Length -eq 0) { Remove-Item -LiteralPath $errFile -Force }
    $excerpt = $text
    if ($excerpt.Length -gt 6000) { $excerpt = $excerpt.Substring(0, 6000) + "`n... [truncated - see raw file]" }
    $script:RawOutputs.Add([pscustomobject][ordered]@{ name = $RawName; command = $cmd; file = "raw/$safe.txt"; exitCode = $p.ExitCode; excerpt = $excerpt })
    return [pscustomobject]@{ Text = $text; ExitCode = $p.ExitCode; Command = $cmd; File = "raw/$safe.txt" }
}

function Get-DisplayName {
    param([AllowNull()][string]$Name)
    if (-not $RedactNames -or [string]::IsNullOrEmpty($Name)) { return $Name }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Name.ToLowerInvariant()))
        return 'id-' + (($bytes[0..4] | ForEach-Object { $_.ToString('x2') }) -join '')
    }
    finally { $sha.Dispose() }
}

function Get-PropValue {
    <# StrictMode-safe property read for AD/CIM/PSObjects. #>
    param([AllowNull()][object]$InputObject, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $InputObject) { return $null }
    $p = $InputObject.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function ConvertTo-GeneralizedTime { param([datetime]$Date) return $Date.ToUniversalTime().ToString('yyyyMMddHHmmss.0Z') }

function ConvertFrom-FileTimeValue {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    $v = [int64]$Value
    if ($v -le 0 -or $v -eq [int64]::MaxValue) { return $null }
    return [DateTime]::FromFileTimeUtc($v)
}

function Save-DetailCsv {
    param([AllowEmptyCollection()][object[]]$Rows, [Parameter(Mandatory)][string]$Name)
    $safe = $Name -replace '[^\w\.-]', '_'
    $path = Join-Path $script:DetailDir "$safe.csv"
    @($Rows) | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8
    return "detail/$safe.csv"
}

function Get-DirectoryObject {
    <# Paged LDAP query with attribute minimization. #>
    param([Parameter(Mandatory)][string]$Server, [Parameter(Mandatory)][string]$LdapFilter, [string[]]$Properties = @(), [string]$SearchBase)
    $p = @{ LDAPFilter = $LdapFilter; Server = $Server; ResultPageSize = 1000; ErrorAction = 'Stop' }
    if ($Properties.Count -gt 0) { $p['Properties'] = $Properties }
    if ($SearchBase) { $p['SearchBase'] = $SearchBase }
    return @(Get-ADObject @p)
}

function Get-DcRecord { param([string]$HostName) return ($script:DcList | Where-Object { $_.name -eq $HostName } | Select-Object -First 1) }

function Get-DomainRecord { param([string]$Name) return ($script:DomainList | Where-Object { $_.name -eq $Name } | Select-Object -First 1) }

#endregion

#region ---------- output staging -----------------------------------------------------------------

$runStamp = $script:StartTime.ToUniversalTime().ToString('yyyyMMdd-HHmmss')
try {
    if (-not (Test-Path -LiteralPath $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
    $stagingRoot = Join-Path $OutputPath '.staging'
    if (-not (Test-Path -LiteralPath $stagingRoot)) { New-Item -ItemType Directory -Path $stagingRoot -Force | Out-Null }
}
catch {
    Write-Error "Cannot create output path '$OutputPath': $($_.Exception.Message)"
    exit 1
}

#endregion

#region ---------- discovery ----------------------------------------------------------------------

try {
    Import-Module ActiveDirectory -ErrorAction Stop -Verbose:$false
    if ($Forest) { $forestObj = Get-ADForest -Identity $Forest -Server $Forest } else { $forestObj = Get-ADForest }
}
catch {
    Write-Error "Discovery failed (ActiveDirectory module / forest bind): $($_.Exception.Message)"
    exit 1
}

$signingCert = $null
if ($SigningCertificateThumbprint) {
    try { $signingCert = Find-ADHealthSigningCertificate -Thumbprint $SigningCertificateThumbprint }
    catch { Write-Error "Signing requested but unavailable: $($_.Exception.Message)"; exit 1 }
}

$forestName = [string]$forestObj.Name
$bundleName = 'ADForestHealth_{0}_{1}' -f ($forestName -replace '[^\w\.-]', '_'), $runStamp
$script:BundleDir = Join-Path $stagingRoot $bundleName
$script:RawDir = Join-Path $script:BundleDir 'raw'
$script:DetailDir = Join-Path $script:BundleDir 'detail'
New-Item -ItemType Directory -Path $script:RawDir, $script:DetailDir -Force | Out-Null
$script:LogFile = Join-Path $script:BundleDir 'collector.log'
Write-CollectorLog "Collector $script:CollectorVersion starting. Forest=$forestName Output=$OutputPath"

$rootDomain = [string]$forestObj.RootDomain
$serverAffinity = [ordered]@{}
$domainsInScope = @($forestObj.Domains | ForEach-Object { [string]$_ })
if ($Domain) { $domainsInScope = @($domainsInScope | Where-Object { $Domain -contains $_ }) }
if ($domainsInScope.Count -eq 0) { Write-Error "No domains in scope after applying -Domain filter."; exit 1 }

$rootServer = $null
foreach ($d in (@($rootDomain) + $domainsInScope | Select-Object -Unique)) {
    try {
        $disc = Get-ADDomainController -Discover -DomainName $d -Service ADWS -ErrorAction Stop
        $serverAffinity[$d] = [string]@($disc.HostName)[0]
    }
    catch {
        Add-CollectorError -Stage 'DISCOVERY' -Target $d -Message "ADWS DC locate failed: $($_.Exception.Message)"
    }
}
if ($serverAffinity.Contains($rootDomain)) { $rootServer = $serverAffinity[$rootDomain] } else { $rootServer = $rootDomain }

foreach ($d in $domainsInScope) {
    if (-not $serverAffinity.Contains($d)) { continue }
    $srv = $serverAffinity[$d]
    try {
        $dom = Get-ADDomain -Identity $d -Server $srv
        $script:DomainList.Add([ordered]@{
                name                  = $d
                netBIOSName           = [string]$dom.NetBIOSName
                distinguishedName     = [string]$dom.DistinguishedName
                domainSID             = [string]$dom.DomainSID.Value
                domainMode            = [string]$dom.DomainMode
                pdcEmulator           = [string]$dom.PDCEmulator
                ridMaster             = [string]$dom.RIDMaster
                infrastructureMaster  = [string]$dom.InfrastructureMaster
                server                = $srv
                dcCount               = 0
                krbtgtPasswordAgeDays = $null
                sysvolReplication     = $null
                machineAccountQuota   = $null
                metrics               = [ordered]@{}
            })
        $dcs = @(Get-ADDomainController -Filter * -Server $srv)
        if ($DomainController) {
            $dcs = @($dcs | Where-Object { ($DomainController -contains $_.Name) -or ($DomainController -contains $_.HostName) })
        }
        foreach ($dc in $dcs) {
            $script:DcList.Add([ordered]@{
                    name               = ([string]$dc.HostName).ToLowerInvariant()
                    shortName          = [string]$dc.Name
                    domain             = $d
                    site               = [string]$dc.Site
                    ipv4Address        = [string]$dc.IPv4Address
                    operatingSystem    = [string]$dc.OperatingSystem
                    operatingSystemVersion = [string]$dc.OperatingSystemVersion
                    isGlobalCatalog    = [bool]$dc.IsGlobalCatalog
                    isReadOnly         = [bool]$dc.IsReadOnly
                    fsmoRoles          = @($dc.OperationMasterRoles | ForEach-Object { [string]$_ })
                    reachable          = $null
                    openPorts          = @()
                    ldapOk             = $null
                    timeOffsetSeconds  = $null
                    timeSkewSeconds    = $null
                    uptimeDays         = $null
                    minFreeDiskPercent = $null
                    stoppedServices    = @()
                    sysvolState        = $null
                    dcdiagFailedTests  = @()
                    replicationFailures = 0
                    maxReplicationLagHours = $null
                })
        }
        (Get-DomainRecord $d).dcCount = $dcs.Count
    }
    catch {
        Add-CollectorError -Stage 'DISCOVERY' -Target $d -Message $_.Exception.Message
    }
}
Write-CollectorLog "Discovery: $($script:DomainList.Count) domain(s), $($script:DcList.Count) DC(s) in scope."
$reachableDcs = { @($script:DcList | Where-Object { $_.reachable -eq $true }) }

#endregion

#region ---------- checks: forest / FSMO / DC ------------------------------------------------------

$forestInfo = [ordered]@{
    name                  = $forestName
    rootDomain            = $rootDomain
    forestMode            = [string]$forestObj.ForestMode
    schemaMaster          = [string]$forestObj.SchemaMaster
    domainNamingMaster    = [string]$forestObj.DomainNamingMaster
    domains               = @($forestObj.Domains | ForEach-Object { [string]$_ })
    domainsInScope        = $domainsInScope
    sites                 = @($forestObj.Sites | ForEach-Object { [string]$_ })
    globalCatalogs        = @($forestObj.GlobalCatalogs | ForEach-Object { [string]$_ })
    upnSuffixes           = @($forestObj.UPNSuffixes | ForEach-Object { [string]$_ })
    recycleBinEnabled     = $null
    tombstoneLifetimeDays = $null
}

Invoke-HealthCheck -Id 'FOREST-001' -Category 'Forest' -Name 'Forest configuration (functional level, Recycle Bin, tombstone lifetime)' `
    -Command 'Get-ADForest; Get-ADOptionalFeature -Filter "Name -eq ''Recycle Bin Feature''"; Get-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,<ConfigNC>" -Properties tombstoneLifetime' -ScriptBlock {
    $configNC = (Get-ADRootDSE -Server $rootServer).configurationNamingContext
    $ds = Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,$configNC" -Properties tombstoneLifetime -Server $rootServer
    $tsl = Get-PropValue $ds 'tombstoneLifetime'
    if (-not $tsl) { $tsl = 60 }   # attribute absent => legacy default of 60 days
    $script:forestInfo.tombstoneLifetimeDays = [int]$tsl
    $rb = Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'" -Server $rootServer
    $enabled = $false
    if ($rb) { $enabled = @($rb.EnabledScopes | Where-Object { $_ }).Count -gt 0 }
    $script:forestInfo.recycleBinEnabled = $enabled
    if (-not $enabled) {
        Add-Finding -CheckId 'FOREST-001' -Category 'Forest' -Severity 'Medium' -Title 'AD Recycle Bin is not enabled' `
            -Detail 'Deleted objects cannot be restored with attributes/links intact without an authoritative restore.' `
            -Recommendation 'Plan enablement via change control (irreversible, forest-wide).'
    }
    if ([int]$tsl -lt 180) {
        Add-Finding -CheckId 'FOREST-001' -Category 'Forest' -Severity 'Low' -Title "Tombstone lifetime is $tsl days" `
            -Detail 'Shorter tombstone lifetime shortens the window for recovering from backups and for DCs being offline before lingering objects.' `
            -Recommendation 'Review against backup retention; 180 days is the modern default.'
    }
    $modeText = [string]$forestObj.ForestMode
    if ($modeText -match 'Windows200[038]|Windows2012') {
        Add-Finding -CheckId 'FOREST-001' -Category 'Forest' -Severity 'Low' -Title "Forest functional level is $modeText" `
            -Recommendation 'Plan FFL/DFL uplift after all DCs run a supported OS (irreversible change - change control required).'
    }
    "FFL=$modeText; RecycleBin=$enabled; TSL=$tsl"
}

Invoke-HealthCheck -Id 'DC-001' -Category 'DCHealth' -Name 'DC network reachability (LDAP 389, Kerberos 88, SMB 445, RPC 135, GC 3268, DNS 53, WinRM 5985)' `
    -Command 'TcpClient.BeginConnect(<dc>, <port>) with timeout' -ScriptBlock {
    $unreachable = 0
    foreach ($dc in $script:DcList) {
        $ports = @(389, 88, 445, 135, 53, 5985)
        if ($dc.isGlobalCatalog) { $ports += 3268 }
        $open = @($ports | Where-Object { Test-TcpPort -ComputerName $dc.name -Port $_ })
        $dc.openPorts = $open
        $core = @(389, 88, 445) | Where-Object { $open -notcontains $_ }
        $dc.reachable = (@($core).Count -eq 0)
        if (-not $dc.reachable) {
            $unreachable++
            $sev = 'High'
            if ($open -notcontains 389) { $sev = 'Critical' }
            Add-Finding -CheckId 'DC-001' -Category 'DCHealth' -Severity $sev -Title 'Domain controller not reachable on core ports' -Target $dc.name `
                -Detail "Closed/filtered: $(@($core) -join ', '). Open: $($open -join ', ')" `
                -Recommendation 'Verify DC is online, NTDS/KDC/Netlogon running, and firewall path from collector host. Later per-DC checks are skipped for this DC.'
        }
        elseif ($dc.isGlobalCatalog -and ($open -notcontains 3268)) {
            Add-Finding -CheckId 'DC-001' -Category 'DCHealth' -Severity 'High' -Title 'Global Catalog port 3268 not reachable' -Target $dc.name `
                -Recommendation 'Confirm GC is advertising (nltest /dsgetdc:<domain> /gc) and firewall rules.'
        }
    }
    Add-Metric 'dcUnreachable' $unreachable 'Set'
    "$($script:DcList.Count - $unreachable)/$($script:DcList.Count) DCs reachable on core ports"
}

$script:RootPdcOffset = $null
Invoke-HealthCheck -Id 'DC-002' -Category 'DCHealth' -Name 'LDAP RootDSE bind and clock offset per DC' `
    -Command 'Get-ADRootDSE -Server <dc> (currentTime compared to collector UTC)' -ScriptBlock {
    foreach ($dc in (& $reachableDcs)) {
        try {
            $t0 = [DateTime]::UtcNow
            $dse = Get-ADRootDSE -Server $dc.name
            $t1 = [DateTime]::UtcNow
            $dc.ldapOk = $true
            $ct = Get-PropValue $dse 'currentTime'
            if ($ct -is [string]) { $ct = [DateTime]::ParseExact($ct.Substring(0, 14), 'yyyyMMddHHmmss', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AssumeUniversal,AdjustToUniversal') }
            if ($ct) {
                $mid = $t0.AddTicks(($t1 - $t0).Ticks / 2)
                $dc.timeOffsetSeconds = [math]::Round(([datetime]$ct).ToUniversalTime().Subtract($mid).TotalSeconds, 1)
            }
            if ((Get-PropValue $dse 'isSynchronized') -eq $false) {
                Add-Finding -CheckId 'DC-002' -Category 'DCHealth' -Severity 'Critical' -Title 'DC reports isSynchronized = FALSE' -Target $dc.name `
                    -Detail 'The DC has not completed initial replication and will not advertise.' -Recommendation 'Investigate inbound replication (repadmin /showrepl) on this DC.'
            }
        }
        catch {
            $dc.ldapOk = $false
            Add-Finding -CheckId 'DC-002' -Category 'DCHealth' -Severity 'Critical' -Title 'LDAP bind to RootDSE failed' -Target $dc.name -Detail $_.Exception.Message `
                -Recommendation 'Check NTDS service, LDAP port, and certificates/channel binding if LDAPS enforced.'
        }
    }
    $ok = @($script:DcList | Where-Object { $_.ldapOk }).Count
    "$ok DC(s) answered RootDSE"
}

Invoke-HealthCheck -Id 'TIME-001' -Category 'Time' -Name 'DC clock offset relative to forest-root PDC emulator' `
    -Command 'Derived from DC-002 currentTime samples' -ScriptBlock {
    $rootDom = Get-DomainRecord $rootDomain
    $rootPdcName = $null
    if ($rootDom) { $rootPdcName = $rootDom.pdcEmulator.ToLowerInvariant() }
    $ref = $script:DcList | Where-Object { $_.name -eq $rootPdcName -and $null -ne $_.timeOffsetSeconds } | Select-Object -First 1
    $refOffset = 0.0
    $refName = 'collector host clock'
    if ($ref) { $refOffset = [double]$ref.timeOffsetSeconds; $refName = $ref.name }
    $maxSkew = 0.0
    foreach ($dc in ($script:DcList | Where-Object { $null -ne $_.timeOffsetSeconds })) {
        $skew = [math]::Round([math]::Abs([double]$dc.timeOffsetSeconds - $refOffset), 1)
        $dc.timeSkewSeconds = $skew
        if ($skew -gt $maxSkew) { $maxSkew = $skew }
        if ($skew -ge 240) {
            Add-Finding -CheckId 'TIME-001' -Category 'Time' -Severity 'Critical' -Title "Clock skew $skew s vs $refName" -Target $dc.name `
                -Detail 'Kerberos default tolerance is 300 s; authentication failures are imminent or occurring.' -Recommendation 'Check W32Time hierarchy (w32tm /query /status /computer:<dc>).'
        }
        elseif ($skew -ge $TimeSkewWarnSeconds) {
            Add-Finding -CheckId 'TIME-001' -Category 'Time' -Severity 'High' -Title "Clock skew $skew s vs $refName" -Target $dc.name `
                -Recommendation 'Check W32Time source and NT5DS hierarchy on this DC.'
        }
    }
    Add-Metric 'maxTimeSkewSeconds' $maxSkew 'Set'
    "Reference=$refName; max skew=$maxSkew s (sample precision ~1 s incl. network latency)"
}

Invoke-HealthCheck -Id 'TIME-002' -Category 'Time' -Name 'Forest-root PDC emulator time source' `
    -Command 'w32tm /query /computer:<rootPDC> /source' -ScriptBlock {
    $rootDom = Get-DomainRecord $rootDomain
    if (-not $rootDom) { throw 'Forest root domain not in scope; cannot evaluate root PDC time source.' }
    $pdc = $rootDom.pdcEmulator
    $r = Invoke-NativeTool -FilePath 'w32tm.exe' -ArgumentList @('/query', "/computer:$pdc", '/source') -RawName "w32tm-source-$pdc" -TimeoutSec 60
    $src = ($r.Text -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)
    if (-not $src) { $src = '' }
    $src = $src.Trim()
    if ($src -match 'Local CMOS Clock|Free-running System Clock|VM IC Time Synchronization Provider') {
        Add-Finding -CheckId 'TIME-002' -Category 'Time' -Severity 'High' -Title "Forest-root PDC uses '$src' as time source" -Target $pdc `
            -Detail 'The forest-root PDC is the authoritative time source for the forest and should sync from reliable external NTP.' `
            -Recommendation 'Configure the root PDC for a reliable NTP source (change control; example only, not executed here).' -EvidenceRef $r.File
    }
    elseif ($r.ExitCode -ne 0 -or -not $src) {
        Add-CollectorError -Stage 'TIME-002' -Target $pdc -Message "w32tm exit $($r.ExitCode): $src"
    }
    "Root PDC $pdc source: $src"
}

Invoke-HealthCheck -Id 'FSMO-001' -Category 'FSMO' -Name 'FSMO role holders exist in DC inventory and are reachable' `
    -Command 'Get-ADForest (SchemaMaster, DomainNamingMaster); Get-ADDomain (PDCEmulator, RIDMaster, InfrastructureMaster)' -ScriptBlock {
    $roles = [System.Collections.Generic.List[object]]::new()
    $roles.Add(@('SchemaMaster', [string]$forestObj.SchemaMaster, $rootDomain))
    $roles.Add(@('DomainNamingMaster', [string]$forestObj.DomainNamingMaster, $rootDomain))
    foreach ($dom in $script:DomainList) {
        $roles.Add(@('PDCEmulator', $dom.pdcEmulator, $dom.name))
        $roles.Add(@('RIDMaster', $dom.ridMaster, $dom.name))
        $roles.Add(@('InfrastructureMaster', $dom.infrastructureMaster, $dom.name))
    }
    foreach ($r in $roles) {
        $role = $r[0]; $holder = ([string]$r[1]).ToLowerInvariant(); $dname = $r[2]
        if (-not $holder -or $holder -match '\\0ADEL|cnf:') {
            Add-Finding -CheckId 'FSMO-001' -Category 'FSMO' -Severity 'Critical' -Title "$role holder is invalid or points to a deleted DC" -Target "$dname/$role" `
                -Detail "Holder value: '$holder'" -Recommendation 'Investigate metadata; role seizure is a controlled change (not performed by this tool).'
            continue
        }
        $rec = Get-DcRecord $holder
        if (-not $rec) {
            if (-not $DomainController) {
                Add-Finding -CheckId 'FSMO-001' -Category 'FSMO' -Severity 'High' -Title "$role holder not found in DC inventory" -Target "$dname/$role" -Detail "Holder: $holder"
            }
            continue
        }
        if ($rec.reachable -ne $true) {
            Add-Finding -CheckId 'FSMO-001' -Category 'FSMO' -Severity 'Critical' -Title "$role holder is unreachable" -Target "$dname/$role" -Detail "Holder: $holder" `
                -Recommendation 'Restore the DC; role-dependent operations (password changes/lockout for PDC, RID pool, schema/domain changes) are impacted.'
        }
    }
    "$($roles.Count) role assignments evaluated"
}

Invoke-HealthCheck -Id 'DC-003' -Category 'DCHealth' -Name 'Domain controller operating system lifecycle' `
    -Command 'Get-ADDomainController -Filter * (OperatingSystem)' -ScriptBlock {
    foreach ($dc in $script:DcList) {
        $os = $dc.operatingSystem
        if ($os -match '2003|2008|2012') {
            Add-Finding -CheckId 'DC-003' -Category 'DCHealth' -Severity 'High' -Title "DC runs unsupported OS ($os)" -Target $dc.name `
                -Recommendation 'Prioritize DC replacement (promote new DC on supported OS, transfer roles, demote).'
        }
        elseif ($os -match '2016') {
            Add-Finding -CheckId 'DC-003' -Category 'DCHealth' -Severity 'Medium' -Title "DC runs $os (extended support ends 2027-01-12)" -Target $dc.name `
                -Recommendation 'Plan replacement before end of extended support.'
        }
    }
    $counts = $script:DcList | ForEach-Object { $_.operatingSystem } | Group-Object | ForEach-Object { "$($_.Name)=$($_.Count)" }
    ($counts -join '; ')
}

Invoke-HealthCheck -Id 'DC-004' -Category 'DCHealth' -Name 'DC services, disk free space and uptime (CIM/WinRM, DCOM fallback)' -Skip:$SkipRemoteCim `
    -Command 'Get-CimInstance Win32_Service/Win32_LogicalDisk/Win32_OperatingSystem -CimSession <dc>' -ScriptBlock {
    $svcNames = @('NTDS', 'Netlogon', 'KDC', 'DFSR', 'W32Time', 'ADWS', 'DNS', 'LanmanServer')
    foreach ($dc in (& $reachableDcs)) {
        $session = $null
        try {
            try { $session = New-CimSession -ComputerName $dc.name -OperationTimeoutSec 30 -ErrorAction Stop }
            catch { $session = New-CimSession -ComputerName $dc.name -SessionOption (New-CimSessionOption -Protocol Dcom) -OperationTimeoutSec 30 -ErrorAction Stop }
            $os = Get-CimInstance -CimSession $session -ClassName Win32_OperatingSystem -Property LastBootUpTime
            $dc.uptimeDays = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 1)
            $filter = ($svcNames | ForEach-Object { "Name='$_'" }) -join ' OR '
            $svcs = @(Get-CimInstance -CimSession $session -ClassName Win32_Service -Filter $filter -Property Name, State, StartMode)
                        $stopped = @($svcs | Where-Object { $_.State -ne 'Running' -and $_.StartMode -ne 'Disabled' } | ForEach-Object { $_.Name })
            $present = @($svcs | ForEach-Object { [string]$_.Name })
            $missing = @($svcNames | Where-Object { $_ -ne 'DNS' -and ($present -notcontains $_) })
            $dc.stoppedServices = $stopped
            if ($stopped.Count -gt 0) {
                Add-Finding -CheckId 'DC-004' -Category 'DCHealth' -Severity 'Critical' -Title "Core DC service(s) not running: $($stopped -join ', ')" -Target $dc.name `
                    -Recommendation 'Investigate the service and its event log before restarting (restart is a change - follow runbook).'
            }
            if ($missing.Count -gt 0) {
                Add-Finding -CheckId 'DC-004' -Category 'DCHealth' -Severity 'Medium' -Title "Expected DC service(s) not present: $($missing -join ', ')" -Target $dc.name
            }
            $disks = @(Get-CimInstance -CimSession $session -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -Property DeviceID, Size, FreeSpace)
            $minPct = 100.0
            foreach ($dk in $disks) {
                if (-not $dk.Size) { continue }
                $pct = [math]::Round(100.0 * $dk.FreeSpace / $dk.Size, 1)
                if ($pct -lt $minPct) { $minPct = $pct }
                if ($pct -lt 10) {
                    Add-Finding -CheckId 'DC-004' -Category 'DCHealth' -Severity 'High' -Title "Volume $($dk.DeviceID) has $pct% free" -Target "$($dc.name)/$($dk.DeviceID)" `
                        -Recommendation 'NTDS/SYSVOL/log volumes running out of space will stop AD DS. Free space or extend (change).'
                }
                elseif ($pct -lt 20) {
                    Add-Finding -CheckId 'DC-004' -Category 'DCHealth' -Severity 'Medium' -Title "Volume $($dk.DeviceID) has $pct% free" -Target "$($dc.name)/$($dk.DeviceID)"
                }
            }
            $dc.minFreeDiskPercent = $minPct
            if ($dc.uptimeDays -gt 60) {
                Add-Finding -CheckId 'DC-004' -Category 'DCHealth' -Severity 'Low' -Title "DC uptime $($dc.uptimeDays) days (patching cadence?)" -Target $dc.name
            }
        }
        catch {
            Add-CollectorError -Stage 'DC-004' -Target $dc.name -Message "CIM: $($_.Exception.Message)"
        }
        finally {
            if ($session) { Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue }
        }
    }
    "CIM collected from $(@($script:DcList | Where-Object { $null -ne $_.uptimeDays }).Count) DC(s)"
}

#endregion

#region ---------- checks: replication ------------------------------------------------------------

Invoke-HealthCheck -Id 'REPL-001' -Category 'Replication' -Name 'Inbound replication partner metadata (last success, consecutive failures)' `
    -Command 'Get-ADReplicationPartnerMetadata -Target <dc> -Partition * -PartnerType Inbound' -ScriptBlock {
    $tsl = 60
    if ($script:forestInfo.tombstoneLifetimeDays) { $tsl = [int]$script:forestInfo.tombstoneLifetimeDays }
    $maxLag = 0.0
    $links = 0
    $failingLinks = 0
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($dc in (& $reachableDcs)) {
        try {
            $meta = @(Get-ADReplicationPartnerMetadata -Target $dc.name -Partition * -PartnerType Inbound -ErrorAction Stop)
        }
        catch { Add-CollectorError -Stage 'REPL-001' -Target $dc.name -Message $_.Exception.Message; continue }
        $dcMaxLag = 0.0
        foreach ($m in $meta) {
            $links++
            $partner = ([string](Get-PropValue $m 'Partner')) -replace '^CN=NTDS Settings,CN=([^,]+),.*$', '$1'
            $partition = [string](Get-PropValue $m 'Partition')
            $lastSuccess = Get-PropValue $m 'LastReplicationSuccess'
            $consec = [int](Get-PropValue $m 'ConsecutiveReplicationFailures')
            $lastResult = [int64](Get-PropValue $m 'LastReplicationResult')
            $lagH = $null
            if ($lastSuccess) { $lagH = [math]::Round(((Get-Date) - [datetime]$lastSuccess).TotalHours, 1) }
            $rows.Add([pscustomobject][ordered]@{ destination = $dc.name; source = $partner; partition = $partition; lastSuccess = $lastSuccess; lagHours = $lagH; consecutiveFailures = $consec; lastResult = $lastResult })
            if ($null -ne $lagH -and $lagH -gt $dcMaxLag) { $dcMaxLag = $lagH }
            $tgt = "$($dc.name)<-$partner/$partition"
            if ($null -ne $lagH -and $lagH -ge ($tsl * 24 * 0.5)) {
                $failingLinks++
                Add-Finding -CheckId 'REPL-001' -Category 'Replication' -Severity 'Critical' -Title "Replication stalled $lagH h (>= 50% of tombstone lifetime)" -Target $tgt `
                    -Detail "Last result $lastResult; consecutive failures $consec" -Recommendation 'Risk of lingering objects / DC quarantine. Investigate immediately (repadmin /showrepl, event 1864/2042).'
            }
            elseif ($consec -gt 0 -or ($null -ne $lagH -and $lagH -ge $ReplLagWarnHours)) {
                $failingLinks++
                Add-Finding -CheckId 'REPL-001' -Category 'Replication' -Severity 'High' -Title "Replication failing or lagging ($lagH h, $consec consecutive failures)" -Target $tgt `
                    -Detail "Last result $lastResult (0x$('{0:X}' -f $lastResult))" -Recommendation 'Map the error code (e.g. 8453 access denied, 1722 RPC unavailable, 8606 lingering objects) and investigate the link.'
            }
        }
        $dc.maxReplicationLagHours = $dcMaxLag
        if ($dcMaxLag -gt $maxLag) { $maxLag = $dcMaxLag }
    }
    $ref = Save-DetailCsv -Rows $rows -Name 'replication-partner-metadata'
    Add-Metric 'replicationLinks' $links 'Set'
    Add-Metric 'replicationLinksFailing' $failingLinks 'Set'
    Add-Metric 'maxReplicationLagHours' $maxLag 'Set'
    "$links inbound links; $failingLinks failing/lagging; max lag $maxLag h (detail: $ref)"
}

Invoke-HealthCheck -Id 'REPL-002' -Category 'Replication' -Name 'Replication failure records' `
    -Command 'Get-ADReplicationFailure -Target <dc>' -ScriptBlock {
    $total = 0
    foreach ($dc in (& $reachableDcs)) {
        try { $fails = @(Get-ADReplicationFailure -Target $dc.name -ErrorAction Stop) }
        catch { Add-CollectorError -Stage 'REPL-002' -Target $dc.name -Message $_.Exception.Message; continue }
        foreach ($f in $fails) {
            $count = [int](Get-PropValue $f 'FailureCount')
            if ($count -le 0) { continue }
            $total++
            $dc.replicationFailures = $dc.replicationFailures + 1
            $partner = ([string](Get-PropValue $f 'Partner')) -replace '^CN=NTDS Settings,CN=([^,]+),.*$', '$1'
            $err = Get-PropValue $f 'LastError'
            $first = Get-PropValue $f 'FirstFailureTime'
            $sev = 'High'
            if ([int64]$err -in 8606, 8614) { $sev = 'Critical' }   # lingering objects / tombstone exceeded
            Add-Finding -CheckId 'REPL-002' -Category 'Replication' -Severity $sev -Title "Replication failure from $partner (error $err, $count failures)" -Target "$($dc.name)<-$partner" `
                -Detail "First failure: $first" -Recommendation 'Use repadmin /showrepl <dc> for per-NC status; 8606/8614 require lingering-object remediation plan.'
        }
    }
    Add-Metric 'replicationFailureRecords' $total 'Set'
    "$total active failure record(s)"
}

Invoke-HealthCheck -Id 'REPL-003' -Category 'Replication' -Name 'repadmin /showrepl cross-check (native tool vs cmdlets)' `
    -Command 'repadmin /showrepl <dc> /csv ; repadmin /replsummary' -ScriptBlock {
    $nativeFailing = [System.Collections.Generic.List[object]]::new()
    foreach ($dc in (& $reachableDcs)) {
        try {
            $r = Invoke-NativeTool -FilePath 'repadmin.exe' -ArgumentList @('/showrepl', $dc.name, '/csv') -RawName "repadmin-showrepl-$($dc.name)"
            $csvLines = @($r.Text -split "`r?`n" | Where-Object { $_ -like 'showrepl_*' })
            if ($csvLines.Count -lt 2) { continue }
            $rows = @($csvLines | ConvertFrom-Csv)
            foreach ($row in $rows) {
                $nf = Get-PropValue $row 'Number of Failures'
                if ($nf -and [int]$nf -gt 0) { $nativeFailing.Add($row) }
            }
        }
        catch { Add-CollectorError -Stage 'REPL-003' -Target $dc.name -Message $_.Exception.Message }
    }
    try { $null = Invoke-NativeTool -FilePath 'repadmin.exe' -ArgumentList @('/replsummary', '/bysrc', '/bydest', '/sort:delta') -RawName 'repadmin-replsummary' }
    catch { Add-CollectorError -Stage 'REPL-003' -Target 'replsummary' -Message $_.Exception.Message }

    $cmdletFailing = @($script:Findings | Where-Object { $_.checkId -in 'REPL-001', 'REPL-002' -and $_.severity -in 'Critical', 'High' }).Count
    if ($nativeFailing.Count -gt 0 -and $cmdletFailing -eq 0) {
        Add-Finding -CheckId 'REPL-003' -Category 'Replication' -Severity 'High' -Title 'Conflicting signals: repadmin reports failing links, cmdlets do not' `
            -Count $nativeFailing.Count -Detail 'repadmin /showrepl shows non-zero failure counts that Get-ADReplication* did not surface.' `
            -Recommendation 'Treat as failing until reconciled; review raw/repadmin-showrepl-*.txt.'
    }
    elseif ($nativeFailing.Count -gt 0) {
        Add-Finding -CheckId 'REPL-003' -Category 'Replication' -Severity 'Info' -Title "repadmin confirms $($nativeFailing.Count) failing link(s)" -Count $nativeFailing.Count
    }
    "repadmin failing links: $($nativeFailing.Count); cmdlet-derived failing findings: $cmdletFailing"
}

#endregion

#region ---------- checks: SYSVOL / DNS / backup ---------------------------------------------------

Invoke-HealthCheck -Id 'SYSVOL-001' -Category 'SYSVOL' -Name 'SYSVOL replication engine (FRS vs DFSR migration state)' `
    -Command 'Get-ADObject "CN=DFSR-GlobalSettings,CN=System,<domainDN>" -Properties msDFSR-Flags' -ScriptBlock {
    foreach ($dom in $script:DomainList) {
        try {
            $gs = Get-ADObject -Identity "CN=DFSR-GlobalSettings,CN=System,$($dom.distinguishedName)" -Properties 'msDFSR-Flags' -Server $dom.server -ErrorAction Stop
            $flags = Get-PropValue $gs 'msDFSR-Flags'
        }
        catch { $flags = $null }
        # 48 = ELIMINATED (DFSR only). null/0/16/32 = FRS still present or migration incomplete.
        if ($flags -eq 48) { $dom.sysvolReplication = 'DFSR' }
        else {
            $dom.sysvolReplication = "FRS-or-migrating(flags=$flags)"
            Add-Finding -CheckId 'SYSVOL-001' -Category 'SYSVOL' -Severity 'High' -Title 'SYSVOL is not fully migrated to DFSR' -Target $dom.name `
                -Detail "msDFSR-Flags=$flags. FRS is deprecated and blocks promotion of Windows Server 2019+ DCs." `
                -Recommendation 'Plan FRS->DFSR migration (dfsrmig) under change control.'
        }
    }
    (@($script:DomainList | ForEach-Object { "$($_.name)=$($_.sysvolReplication)" }) -join '; ')
}

Invoke-HealthCheck -Id 'SYSVOL-002' -Category 'SYSVOL' -Name 'SYSVOL/NETLOGON shares and DFSR replicated folder state per DC' `
    -Command 'Test-Path \\<dc>\SYSVOL, \\<dc>\NETLOGON; Get-CimInstance -Namespace root\microsoftdfs DfsrReplicatedFolderInfo' -ScriptBlock {
    $stateMap = @{ 0 = 'Uninitialized'; 1 = 'Initialized'; 2 = 'InitialSync'; 3 = 'AutoRecovery'; 4 = 'Normal'; 5 = 'InError' }
    foreach ($dc in (& $reachableDcs)) {
        foreach ($share in 'SYSVOL', 'NETLOGON') {
            $ok = $false
            try { $ok = Test-Path -LiteralPath "\\$($dc.name)\$share" } catch { $ok = $false }
            if (-not $ok) {
                Add-Finding -CheckId 'SYSVOL-002' -Category 'SYSVOL' -Severity 'Critical' -Title "$share share not accessible" -Target $dc.name `
                    -Detail 'DC will not advertise as a DC / GPOs and logon scripts unavailable from this DC.' -Recommendation 'Check SysvolReady registry value and DFSR state (event log DFS Replication).'
            }
        }
        if ($SkipRemoteCim) { continue }
        try {
            $rf = @(Get-CimInstance -ComputerName $dc.name -Namespace 'root\microsoftdfs' -ClassName 'DfsrReplicatedFolderInfo' -Filter "ReplicatedFolderName='SYSVOL Share'" -OperationTimeoutSec 30 -ErrorAction Stop)
            if ($rf.Count -gt 0) {
                $st = [int]$rf[0].State
                $dc.sysvolState = $stateMap[$st]
                if ($st -eq 5) {
                    Add-Finding -CheckId 'SYSVOL-002' -Category 'SYSVOL' -Severity 'Critical' -Title 'DFSR SYSVOL replicated folder In Error' -Target $dc.name -Recommendation 'Review DFS Replication log (events 2213, 4012, 5002, 5008).'
                }
                elseif ($st -ne 4) {
                    Add-Finding -CheckId 'SYSVOL-002' -Category 'SYSVOL' -Severity 'High' -Title "DFSR SYSVOL state is $($stateMap[$st])" -Target $dc.name
                }
            }
        }
        catch { Add-CollectorError -Stage 'SYSVOL-002' -Target $dc.name -Message "DFSR WMI: $($_.Exception.Message)" }
    }
    "Shares tested on $(@(& $reachableDcs).Count) DC(s)"
}

Invoke-HealthCheck -Id 'DNS-001' -Category 'DNS' -Name 'DC locator SRV records (domain DCs, PDC, GCs)' `
    -Command 'Resolve-DnsName _ldap._tcp.dc._msdcs.<domain> / _ldap._tcp.pdc._msdcs.<domain> / _gc._tcp.<forest> -Type SRV' -ScriptBlock {
    foreach ($dom in $script:DomainList) {
        $expected = @($script:DcList | Where-Object { $_.domain -eq $dom.name -and -not $_.isReadOnly } | ForEach-Object { $_.name })
        try {
            $srv = @(Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.$($dom.name)" -Type SRV -DnsOnly -ErrorAction Stop | Where-Object { $_.Type -eq 'SRV' } | ForEach-Object { ([string]$_.NameTarget).ToLowerInvariant() })
            $missing = @($expected | Where-Object { $srv -notcontains $_ })
            foreach ($m in $missing) {
                Add-Finding -CheckId 'DNS-001' -Category 'DNS' -Severity 'High' -Title 'Writable DC missing from _ldap._tcp.dc._msdcs SRV records' -Target $m `
                    -Detail "Domain $($dom.name)" -Recommendation 'Check Netlogon registration (netlogon.dns, event 5774/5781) - clients cannot locate this DC.'
            }
            $stale = @($srv | Where-Object { $_ -notin @($script:DcList | ForEach-Object { $_.name }) })
            if ($stale.Count -gt 0 -and -not $DomainController) {
                Add-Finding -CheckId 'DNS-001' -Category 'DNS' -Severity 'High' -Title 'SRV records point to hosts that are not current DCs' -Target $dom.name -Count $stale.Count `
                    -Sample $stale -Recommendation 'Stale locator records send clients to decommissioned DCs; validate metadata cleanup and DNS scavenging.'
            }
            $pdcSrv = @(Resolve-DnsName -Name "_ldap._tcp.pdc._msdcs.$($dom.name)" -Type SRV -DnsOnly -ErrorAction Stop | Where-Object { $_.Type -eq 'SRV' } | ForEach-Object { ([string]$_.NameTarget).ToLowerInvariant() })
            if ($pdcSrv -notcontains $dom.pdcEmulator.ToLowerInvariant()) {
                Add-Finding -CheckId 'DNS-001' -Category 'DNS' -Severity 'High' -Title 'PDC SRV record does not match PDC emulator' -Target $dom.name -Detail "SRV: $($pdcSrv -join ','); PDC: $($dom.pdcEmulator)"
            }
        }
        catch { Add-CollectorError -Stage 'DNS-001' -Target $dom.name -Message $_.Exception.Message }
    }
    try {
        $gcSrv = @(Resolve-DnsName -Name "_gc._tcp.$rootDomain" -Type SRV -DnsOnly -ErrorAction Stop | Where-Object { $_.Type -eq 'SRV' } | ForEach-Object { ([string]$_.NameTarget).ToLowerInvariant() })
        foreach ($gc in @($script:DcList | Where-Object { $_.isGlobalCatalog -and -not $_.isReadOnly })) {
            if ($gcSrv -notcontains $gc.name) {
                Add-Finding -CheckId 'DNS-001' -Category 'DNS' -Severity 'Medium' -Title 'GC missing from _gc._tcp SRV records' -Target $gc.name
            }
        }
    }
    catch { Add-CollectorError -Stage 'DNS-001' -Target "_gc._tcp.$rootDomain" -Message $_.Exception.Message }
    'Locator records evaluated for writable DCs (RODCs excluded by design)'
}

Invoke-HealthCheck -Id 'DNS-002' -Category 'DNS' -Name 'Per-DC DNS server consistency for DC locator records' `
    -Command 'Resolve-DnsName _ldap._tcp.dc._msdcs.<domain> -Type SRV -Server <each DC with 53/tcp open>' -ScriptBlock {
    $tested = 0
    foreach ($dc in @(& $reachableDcs | Where-Object { $_.openPorts -contains 53 })) {
        $tested++
        $expected = @($script:DcList | Where-Object { $_.domain -eq $dc.domain -and -not $_.isReadOnly } | ForEach-Object { $_.name })
        try {
            $srv = @(Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.$($dc.domain)" -Type SRV -DnsOnly -Server $dc.name -QuickTimeout -ErrorAction Stop | Where-Object { $_.Type -eq 'SRV' } | ForEach-Object { ([string]$_.NameTarget).ToLowerInvariant() })
            $missing = @($expected | Where-Object { $srv -notcontains $_ })
            if ($missing.Count -gt 0) {
                Add-Finding -CheckId 'DNS-002' -Category 'DNS' -Severity 'Medium' -Title "DNS on this DC is missing $($missing.Count) DC locator record(s)" -Target $dc.name `
                    -Sample $missing -Count $missing.Count -Recommendation 'Indicates AD-integrated zone replication or registration inconsistency between DNS servers.'
            }
        }
        catch {
            Add-Finding -CheckId 'DNS-002' -Category 'DNS' -Severity 'High' -Title 'DC DNS server failed to answer locator query' -Target $dc.name -Detail $_.Exception.Message
        }
    }
    "$tested DC DNS server(s) queried"
}

Invoke-HealthCheck -Id 'BACKUP-001' -Category 'Backup' -Name 'Last backup per naming context (dSASignature metadata)' `
    -Command 'Get-ADReplicationAttributeMetadata -Object <NC DN> -Properties dSASignature -Server <dc>' -ScriptBlock {
    $tsl = 60
    if ($script:forestInfo.tombstoneLifetimeDays) { $tsl = [int]$script:forestInfo.tombstoneLifetimeDays }
    # RootDSE.namingContexts only lists NCs hosted by that DC, so union across one DC per in-scope domain.
    $ncServer = [ordered]@{}
    foreach ($nc in @((Get-ADRootDSE -Server $rootServer).namingContexts)) { $ncServer[[string]$nc] = $rootServer }
    foreach ($dom in $script:DomainList) {
        foreach ($nc in @((Get-ADRootDSE -Server $dom.server).namingContexts)) { if (-not $ncServer.Contains([string]$nc)) { $ncServer[[string]$nc] = $dom.server } }
    }
    $domainDns = @($forestObj.Domains | ForEach-Object { [string]$_ } | Sort-Object Length -Descending)
    $ncs = @($ncServer.Keys)
    $oldest = 0.0
    foreach ($nc in $ncs) {
        $srv = $ncServer[$nc]
        if ($nc -notmatch '^(CN=Configuration|CN=Schema|DC=ForestDnsZones),') {
            $owner = $null
            foreach ($d in $domainDns) { if ($nc -like ('*DC=' + ($d -replace '\.', ',DC='))) { $owner = $d; break } }
            if ($owner -and $domainsInScope -notcontains $owner) { continue }
            $rec = Get-DomainRecord $owner
            if ($rec) { $srv = $rec.server }
        }
        try {
            $md = Get-ADReplicationAttributeMetadata -Object $nc -Properties dSASignature -Server $srv -ErrorAction Stop | Where-Object { $_.AttributeName -eq 'dSASignature' } | Select-Object -First 1
            $last = $null
            if ($md) { $last = $md.LastOriginatingChangeTime }
            if (-not $last -or ([datetime]$last).Year -lt 1990) {
                Add-Finding -CheckId 'BACKUP-001' -Category 'Backup' -Severity 'Critical' -Title 'No recorded backup for naming context' -Target $nc -Recommendation 'Confirm a system-state backup of at least two DCs per domain exists and is tested.'
                continue
            }
            $age = [math]::Round(((Get-Date) - [datetime]$last).TotalDays, 1)
            if ($age -gt $oldest) { $oldest = $age }
            if ($age -ge ($tsl / 2)) {
                Add-Finding -CheckId 'BACKUP-001' -Category 'Backup' -Severity 'Critical' -Title "Last backup $age days ago (>= half tombstone lifetime)" -Target $nc -Detail "Last: $last"
            }
            elseif ($age -ge $BackupWarnDays) {
                Add-Finding -CheckId 'BACKUP-001' -Category 'Backup' -Severity 'High' -Title "Last backup $age days ago" -Target $nc -Detail "Last: $last" -Recommendation 'Verify backup jobs for system state on DCs in this NC.'
            }
        }
        catch { Add-CollectorError -Stage 'BACKUP-001' -Target $nc -Message $_.Exception.Message }
    }
    Add-Metric 'oldestBackupDays' $oldest 'Set'
    "$($ncs.Count) naming contexts; oldest backup $oldest days"
}

#endregion

#region ---------- checks: dcdiag / events ---------------------------------------------------------

Invoke-HealthCheck -Id 'DCDIAG-001' -Category 'DCHealth' -Name 'dcdiag per DC (default tests, SystemLog skipped)' -Skip:$SkipDcDiag `
    -Command 'dcdiag /s:<dc> /skip:SystemLog' -ScriptBlock {
    $failedTotal = 0
    foreach ($dc in (& $reachableDcs)) {
        try {
            $r = Invoke-NativeTool -FilePath 'dcdiag.exe' -ArgumentList @("/s:$($dc.name)", '/skip:SystemLog') -RawName "dcdiag-$($dc.name)"
            $failed = @([regex]::Matches($r.Text, '\.{3,}\s*(\S+)\s+failed test\s+(\S+)') | ForEach-Object { $_.Groups[2].Value } | Select-Object -Unique)
            $dc.dcdiagFailedTests = $failed
            if ($failed.Count -gt 0) {
                $failedTotal += $failed.Count
                $sev = 'Medium'
                if (@($failed | Where-Object { $_ -in 'Advertising', 'Replications', 'NetLogons', 'Services', 'MachineAccount', 'KccEvent', 'FsmoCheck', 'RidManager', 'SysVolCheck', 'Connectivity' }).Count -gt 0) { $sev = 'High' }
                Add-Finding -CheckId 'DCDIAG-001' -Category 'DCHealth' -Severity $sev -Title "dcdiag failed test(s): $($failed -join ', ')" -Target $dc.name -Count $failed.Count `
                    -EvidenceRef $r.File -Recommendation 'Review the raw dcdiag output; correlate with REPL/SYSVOL/DNS findings before acting.'
            }
        }
        catch { Add-CollectorError -Stage 'DCDIAG-001' -Target $dc.name -Message $_.Exception.Message }
    }
    Add-Metric 'dcdiagFailedTests' $failedTotal 'Set'
    "$failedTotal failed dcdiag test(s) across DCs"
}

# Targeted high-signal event IDs. Severity is what a single occurrence in the window implies.
$script:EventCatalog = @(
    @{ Log = 'Directory Service'; Id = 2095; Sev = 'Critical'; Meaning = 'USN rollback detected' }
    @{ Log = 'Directory Service'; Id = 2103; Sev = 'Critical'; Meaning = 'AD DB restored by unsupported method (USN rollback)' }
    @{ Log = 'Directory Service'; Id = 2042; Sev = 'Critical'; Meaning = 'Replication blocked: exceeded tombstone lifetime' }
    @{ Log = 'Directory Service'; Id = 1988; Sev = 'Critical'; Meaning = 'Lingering object detected' }
    @{ Log = 'Directory Service'; Id = 1864; Sev = 'High'; Meaning = 'Replication has not occurred for a long time' }
    @{ Log = 'Directory Service'; Id = 1168; Sev = 'High'; Meaning = 'Internal AD error' }
    @{ Log = 'Directory Service'; Id = 1173; Sev = 'High'; Meaning = 'Internal AD error' }
    @{ Log = 'Directory Service'; Id = 2089; Sev = 'Medium'; Meaning = 'Partition not backed up within backup latency interval' }
    @{ Log = 'Directory Service'; Id = 2887; Sev = 'Medium'; Meaning = 'Unsigned/cleartext LDAP binds occurred (daily summary)' }
    @{ Log = 'Directory Service'; Id = 1311; Sev = 'Medium'; Meaning = 'KCC cannot build complete replication topology' }
    @{ Log = 'Directory Service'; Id = 1925; Sev = 'Medium'; Meaning = 'Replication link establish failure' }
    @{ Log = 'DFS Replication'; Id = 2213; Sev = 'Critical'; Meaning = 'DFSR stopped replication after dirty shutdown' }
    @{ Log = 'DFS Replication'; Id = 4012; Sev = 'Critical'; Meaning = 'DFSR disconnected longer than MaxOfflineTimeInDays' }
    @{ Log = 'DFS Replication'; Id = 2104; Sev = 'High'; Meaning = 'DFSR database recovery failed' }
    @{ Log = 'DFS Replication'; Id = 5002; Sev = 'Medium'; Meaning = 'DFSR communication error with partner' }
    @{ Log = 'DFS Replication'; Id = 5008; Sev = 'Medium'; Meaning = 'DFSR failed to communicate with partner' }
    @{ Log = 'DFS Replication'; Id = 5014; Sev = 'Low'; Meaning = 'DFSR RPC connection interrupted' }
    @{ Log = 'System'; Id = 5719; Sev = 'High'; Meaning = 'Netlogon: no DC available for secure session' }
    @{ Log = 'System'; Id = 5722; Sev = 'Medium'; Meaning = 'Netlogon: session setup failed (computer account)' }
    @{ Log = 'System'; Id = 5805; Sev = 'Medium'; Meaning = 'Netlogon: session setup failed (access denied)' }
    @{ Log = 'System'; Id = 5774; Sev = 'High'; Meaning = 'Netlogon: DNS registration failed' }
    @{ Log = 'System'; Id = 5781; Sev = 'High'; Meaning = 'Netlogon: dynamic DNS registration failed' }
    @{ Log = 'System'; Id = 36; Sev = 'Medium'; Meaning = 'W32Time: no time sync for extended period' }
    @{ Log = 'System'; Id = 47; Sev = 'Low'; Meaning = 'W32Time: no valid response from peer' }
    @{ Log = 'System'; Id = 129; Sev = 'Low'; Meaning = 'W32Time: NtpClient unable to set domain peer' }
    @{ Log = 'System'; Id = 134; Sev = 'Low'; Meaning = 'W32Time: NtpClient DNS resolution failed' }
    @{ Log = 'System'; Id = 14; Sev = 'High'; Meaning = 'KDC: no suitable key for encryption type (etype mismatch)' }
    @{ Log = 'System'; Id = 16; Sev = 'Medium'; Meaning = 'KDC: requested etype not supported by account' }
    @{ Log = 'System'; Id = 26; Sev = 'Medium'; Meaning = 'KDC: etype mismatch (client/service)' }
    @{ Log = 'System'; Id = 29; Sev = 'High'; Meaning = 'KDC: no suitable certificate for smart card logon' }
    @{ Log = 'System'; Id = 39; Sev = 'Medium'; Meaning = 'KDC: certificate not strongly mapped (KB5014754)' }
    @{ Log = 'System'; Id = 41; Sev = 'Medium'; Meaning = 'KDC: certificate predates account (KB5014754)' }
)

Invoke-HealthCheck -Id 'EVT-001' -Category 'EventLogs' -Name "Targeted high-signal event IDs in the last $HoursBack h" -Skip:$SkipEventLogs `
    -Command 'Get-WinEvent -ComputerName <dc> -FilterHashtable @{LogName=<log>; Id=<list>; StartTime=<since>} -MaxEvents <cap>' -ScriptBlock {
    $since = (Get-Date).AddHours(-$HoursBack)
    $rows = [System.Collections.Generic.List[object]]::new()
    $critical = 0
    foreach ($dc in (& $reachableDcs)) {
        foreach ($grp in ($script:EventCatalog | Group-Object { $_.Log })) {
            $ids = @($grp.Group | ForEach-Object { $_.Id })
            # FilterHashtable XPath is limited to ~22 IDs per query - chunk to be safe.
            for ($i = 0; $i -lt $ids.Count; $i += 20) {
                $chunk = $ids[$i..([math]::Min($i + 19, $ids.Count - 1))]
                try {
                    $events = @(Get-WinEvent -ComputerName $dc.name -FilterHashtable @{ LogName = $grp.Name; Id = $chunk; StartTime = $since } -MaxEvents $MaxEventsPerQuery -ErrorAction Stop)
                }
                catch {
                    if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { continue }
                    Add-CollectorError -Stage 'EVT-001' -Target "$($dc.name)/$($grp.Name)" -Message $_.Exception.Message
                    continue
                }
                foreach ($g in ($events | Group-Object Id)) {
                    $cat = $script:EventCatalog | Where-Object { $_.Log -eq $grp.Name -and $_.Id -eq [int]$g.Name } | Select-Object -First 1
                    if (-not $cat) { continue }
                    $last = ($g.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1)
                    $msg = ''
                    try { $msg = ([string]$last.Message) } catch { $msg = '' }
                    if ($msg.Length -gt 400) { $msg = $msg.Substring(0, 400) + '...' }
                    $rows.Add([pscustomobject][ordered]@{ dc = $dc.name; log = $grp.Name; id = [int]$g.Name; count = $g.Count; lastSeen = $last.TimeCreated; meaning = $cat.Meaning; lastMessage = $msg })
                    if ($cat.Sev -eq 'Critical') { $critical += $g.Count }
                    Add-Finding -CheckId 'EVT-001' -Category 'EventLogs' -Severity $cat.Sev -Title "Event $($g.Name) x$($g.Count): $($cat.Meaning)" -Target "$($dc.name)/$($grp.Name)/$($g.Name)" `
                        -Count $g.Count -Detail "Last seen $($last.TimeCreated)." -EvidenceRef 'detail/event-summary.csv'
                }
            }
        }
    }
    $null = Save-DetailCsv -Rows $rows -Name 'event-summary'
    Add-Metric 'criticalEventCount' $critical 'Set'
    "$($rows.Count) distinct (DC, event ID) signal(s); $critical critical occurrence(s)"
}

#endregion

#region ---------- checks: trusts / sites ----------------------------------------------------------

Invoke-HealthCheck -Id 'TRUST-001' -Category 'Trusts' -Name 'Trust configuration and secure channel' `
    -Command 'Get-ADTrust -Filter * -Properties whenChanged; nltest /server:<pdc> /sc_query:<trust>' -ScriptBlock {
    $n = 0
    foreach ($dom in $script:DomainList) {
        try { $trusts = @(Get-ADTrust -Filter * -Properties whenChanged -Server $dom.server -ErrorAction Stop) }
        catch { Add-CollectorError -Stage 'TRUST-001' -Target $dom.name -Message $_.Exception.Message; continue }
        foreach ($t in $trusts) {
            $n++
            $target = [string]$t.Target
            $tgt = "$($dom.name)->$target"
            $direction = [string]$t.Direction
            $intra = [bool](Get-PropValue $t 'IntraForest')
            $forestTransitive = [bool](Get-PropValue $t 'ForestTransitive')
            if (-not $intra) {
                if (-not $forestTransitive -and -not [bool](Get-PropValue $t 'SIDFilteringQuarantined') -and $direction -in 'Outbound', 'BiDirectional') {
                    Add-Finding -CheckId 'TRUST-001' -Category 'Trusts' -Severity 'High' -Title 'External trust without SID filtering (quarantine)' -Target $tgt `
                        -Recommendation 'SID history from the trusted domain is honored - privilege escalation path. Evaluate enabling quarantine (change control).'
                }
                if ([bool](Get-PropValue $t 'TGTDelegation')) {
                    Add-Finding -CheckId 'TRUST-001' -Category 'Trusts' -Severity 'High' -Title 'TGT delegation enabled across trust' -Target $tgt `
                        -Recommendation 'Unconstrained delegation across the trust boundary allows TGT capture; disable unless explicitly required.'
                }
                if (-not [bool](Get-PropValue $t 'UsesAESKeys') -and -not $forestTransitive) {
                    Add-Finding -CheckId 'TRUST-001' -Category 'Trusts' -Severity 'Medium' -Title 'Trust not configured for AES' -Target $tgt -Recommendation 'RC4 across trusts is being deprecated; plan AES enablement.'
                }
                $wc = Get-PropValue $t 'whenChanged'
                if ($wc -and ((Get-Date) - [datetime]$wc).TotalDays -gt 60) {
                    Add-Finding -CheckId 'TRUST-001' -Category 'Trusts' -Severity 'Low' -Title "Trust object unchanged for $([int]((Get-Date) - [datetime]$wc).TotalDays) days (heuristic: trust password may not be rotating)" -Target $tgt
                }
            }
            if ($direction -in 'Outbound', 'BiDirectional') {
                try {
                    $r = Invoke-NativeTool -FilePath 'nltest.exe' -ArgumentList @("/server:$($dom.pdcEmulator)", "/sc_query:$target") -RawName "nltest-scquery-$($dom.name)-$target" -TimeoutSec 120
                    if ($r.Text -notmatch 'Trusted DC Connection Status Status = 0 0x0') {
                        Add-Finding -CheckId 'TRUST-001' -Category 'Trusts' -Severity 'High' -Title 'Trust secure channel query did not return success' -Target $tgt -EvidenceRef $r.File `
                            -Recommendation 'Authentication across this trust may fail. Review raw nltest output; do NOT reset the channel without change control.'
                    }
                }
                catch { Add-CollectorError -Stage 'TRUST-001' -Target $tgt -Message $_.Exception.Message }
            }
        }
    }
    Add-Metric 'trustCount' $n 'Set'
    "$n trust(s) evaluated"
}

Invoke-HealthCheck -Id 'SITE-001' -Category 'Sites' -Name 'Sites, subnets and site links' `
    -Command 'Get-ADReplicationSite/Subnet/SiteLink -Filter *' -ScriptBlock {
    $sites = @(Get-ADReplicationSite -Filter * -Server $rootServer)
    $subnets = @(Get-ADReplicationSubnet -Filter * -Properties Site -Server $rootServer)
    $links = @(Get-ADReplicationSiteLink -Filter * -Properties SitesIncluded, ReplicationFrequencyInMinutes -Server $rootServer)
    $sitesWithSubnets = @($subnets | Where-Object { $_.Site } | ForEach-Object { [string]$_.Site } | Select-Object -Unique)
    $noSubnet = @($sites | Where-Object { $sitesWithSubnets -notcontains [string]$_.DistinguishedName } | ForEach-Object { [string]$_.Name })
    $orphanSubnets = @($subnets | Where-Object { -not $_.Site } | ForEach-Object { [string]$_.Name })
    $degenerate = @($links | Where-Object { @($_.SitesIncluded).Count -lt 2 } | ForEach-Object { [string]$_.Name })
    $dcSites = @($script:DcList | ForEach-Object { $_.site } | Select-Object -Unique)
    $noDc = @($sites | Where-Object { $dcSites -notcontains [string]$_.Name } | ForEach-Object { [string]$_.Name })
    if ($noSubnet.Count) { Add-Finding -CheckId 'SITE-001' -Category 'Sites' -Severity 'Low' -Title "$($noSubnet.Count) site(s) have no subnets" -Count $noSubnet.Count -Sample $noSubnet -Recommendation 'Clients cannot be mapped to these sites; remove or assign subnets.' }
    if ($orphanSubnets.Count) { Add-Finding -CheckId 'SITE-001' -Category 'Sites' -Severity 'Low' -Title "$($orphanSubnets.Count) subnet(s) not associated with a site" -Count $orphanSubnets.Count -Sample $orphanSubnets }
    if ($degenerate.Count) { Add-Finding -CheckId 'SITE-001' -Category 'Sites' -Severity 'Low' -Title "$($degenerate.Count) site link(s) include fewer than 2 sites" -Count $degenerate.Count -Sample $degenerate }
    if ($noDc.Count -and -not $DomainController -and -not $Domain) { Add-Finding -CheckId 'SITE-001' -Category 'Sites' -Severity 'Info' -Title "$($noDc.Count) site(s) have no DC (clients use site coverage / next closest)" -Count $noDc.Count -Sample $noDc }
    Add-Metric 'siteCount' $sites.Count 'Set'
    Add-Metric 'subnetCount' $subnets.Count 'Set'
    Add-Metric 'siteLinkCount' $links.Count 'Set'
    "$($sites.Count) sites, $($subnets.Count) subnets, $($links.Count) site links"
}

#endregion

#region ---------- checks: Kerberos / privileged / hygiene -----------------------------------------

Invoke-HealthCheck -Id 'KRB-001' -Category 'Kerberos' -Name 'krbtgt password age (incl. RODC krbtgt_*)' `
    -Command 'Get-ADUser -LDAPFilter "(|(sAMAccountName=krbtgt)(sAMAccountName=krbtgt_*))" -Properties pwdLastSet' -ScriptBlock {
    $maxAge = 0
    foreach ($dom in $script:DomainList) {
        $accts = @(Get-ADUser -LDAPFilter '(|(sAMAccountName=krbtgt)(sAMAccountName=krbtgt_*))' -Properties PasswordLastSet -Server $dom.server)
        foreach ($a in $accts) {
            if (-not $a.PasswordLastSet) { continue }
            $age = [int]((Get-Date) - $a.PasswordLastSet).TotalDays
            if ($a.SamAccountName -eq 'krbtgt') { $dom.krbtgtPasswordAgeDays = $age }
            if ($age -gt $maxAge) { $maxAge = $age }
            $t = "$($dom.name)/$($a.SamAccountName)"
            if ($age -gt 365) {
                Add-Finding -CheckId 'KRB-001' -Category 'Kerberos' -Severity 'High' -Title "krbtgt password is $age days old" -Target $t `
                    -Recommendation 'Plan a staged double rotation (allow full replication + max ticket lifetime between resets) under change control.'
            }
            elseif ($age -gt 180) {
                Add-Finding -CheckId 'KRB-001' -Category 'Kerberos' -Severity 'Medium' -Title "krbtgt password is $age days old" -Target $t -Recommendation 'Rotate on a regular cadence (e.g. every 180 days) via a staged process.'
            }
        }
    }
    Add-Metric 'krbtgtMaxAgeDays' $maxAge 'Set'
    "Oldest krbtgt password: $maxAge days"
}

Invoke-HealthCheck -Id 'PRIV-001' -Category 'PrivilegedAccess' -Name 'Protected group membership (SID-resolved, nested via LDAP_MATCHING_RULE_IN_CHAIN)' -Skip:$SkipHygiene `
    -Command 'Get-ADObject -LDAPFilter "(memberOf:1.2.840.113556.1.4.1941:=<groupDN>)"' -ScriptBlock {
    $rootDom = Get-DomainRecord $rootDomain
    $total = 0
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($dom in $script:DomainList) {
        $groups = [ordered]@{
            'Domain Admins'                = "$($dom.domainSID)-512"
            'Administrators'               = 'S-1-5-32-544'
            'Account Operators'            = 'S-1-5-32-548'
            'Server Operators'             = 'S-1-5-32-549'
            'Print Operators'              = 'S-1-5-32-550'
            'Backup Operators'             = 'S-1-5-32-551'
            'Group Policy Creator Owners'  = "$($dom.domainSID)-520"
            'Key Admins'                   = "$($dom.domainSID)-526"
        }
        if ($rootDom -and $dom.name -eq $rootDomain) {
            $groups['Enterprise Admins'] = "$($rootDom.domainSID)-519"
            $groups['Schema Admins'] = "$($rootDom.domainSID)-518"
            $groups['Enterprise Key Admins'] = "$($rootDom.domainSID)-527"
        }
        try {
            $dnsAdmins = Get-ADGroup -Identity 'DnsAdmins' -Server $dom.server -ErrorAction Stop
            $groups['DnsAdmins'] = [string]$dnsAdmins.SID.Value
        }
        catch { Write-CollectorLog "DnsAdmins not found in $($dom.name) (DNS may not be AD-integrated)" }

        foreach ($gName in $groups.Keys) {
            try { $g = Get-ADGroup -Identity $groups[$gName] -Server $dom.server -ErrorAction Stop }
            catch { continue }
            $members = @(Get-DirectoryObject -Server $dom.server -LdapFilter "(&(|(objectClass=user)(objectClass=computer)(objectClass=msDS-GroupManagedServiceAccount))(memberOf:1.2.840.113556.1.4.1941:=$($g.DistinguishedName)))" -Properties sAMAccountName, userAccountControl)
            foreach ($m in $members) {
                $script:ProtectedMemberDNs[[string]$m.DistinguishedName] = $true
                $enabled = -not ([int](Get-PropValue $m 'userAccountControl') -band 2)
                $rows.Add([pscustomobject][ordered]@{ domain = $dom.name; group = $gName; member = (Get-DisplayName ([string](Get-PropValue $m 'sAMAccountName'))); enabled = $enabled; objectClass = [string]$m.ObjectClass })
            }
            $total += $members.Count
            $tgt = "$($dom.name)/$gName"
            if ($gName -in 'Domain Admins', 'Enterprise Admins' -and $members.Count -gt $PrivilegedGroupWarnCount) {
                Add-Finding -CheckId 'PRIV-001' -Category 'PrivilegedAccess' -Severity 'Medium' -Title "$gName has $($members.Count) effective members (threshold $PrivilegedGroupWarnCount)" -Target $tgt -Count $members.Count `
                    -Sample @($members | ForEach-Object { Get-DisplayName ([string](Get-PropValue $_ 'sAMAccountName')) }) -Recommendation 'Reduce standing Tier-0 membership; use JIT/PAM where possible.'
            }
            if ($gName -eq 'Schema Admins' -and $members.Count -gt 0) {
                Add-Finding -CheckId 'PRIV-001' -Category 'PrivilegedAccess' -Severity 'Medium' -Title "Schema Admins is not empty ($($members.Count))" -Target $tgt -Count $members.Count `
                    -Sample @($members | ForEach-Object { Get-DisplayName ([string](Get-PropValue $_ 'sAMAccountName')) }) -Recommendation 'Keep empty except during approved schema changes.'
            }
            if ($gName -in 'Account Operators', 'Server Operators', 'Print Operators', 'Backup Operators' -and $members.Count -gt 0) {
                Add-Finding -CheckId 'PRIV-001' -Category 'PrivilegedAccess' -Severity 'Medium' -Title "$gName has $($members.Count) member(s) (legacy operator groups are Tier-0 equivalent)" -Target $tgt -Count $members.Count `
                    -Sample @($members | ForEach-Object { Get-DisplayName ([string](Get-PropValue $_ 'sAMAccountName')) })
            }
        }
    }
    $null = Save-DetailCsv -Rows $rows -Name 'privileged-membership'
    Add-Metric 'privilegedMemberships' $total 'Set'
    Add-Metric 'privilegedAccountsUnique' $script:ProtectedMemberDNs.Count 'Set'
    "$($script:ProtectedMemberDNs.Count) unique privileged principals ($total memberships)"
}

Invoke-HealthCheck -Id 'PRIV-002' -Category 'PrivilegedAccess' -Name 'Privileged account hygiene (adminCount=1 accounts)' -Skip:$SkipHygiene `
    -Command 'Get-ADUser -LDAPFilter "(adminCount=1)" -Properties servicePrincipalName, pwdLastSet, lastLogonTimestamp, userAccountControl, memberOf' -ScriptBlock {
    foreach ($dom in $script:DomainList) {
        $admins = @(Get-DirectoryObject -Server $dom.server -LdapFilter '(&(objectCategory=person)(objectClass=user)(adminCount=1))' -Properties sAMAccountName, userAccountControl, servicePrincipalName, pwdLastSet, lastLogonTimestamp, memberOf)
        $enabledAdmins = @($admins | Where-Object { -not ([int]$_.userAccountControl -band 2) })
        $protectedUsersDN = $null
        try { $protectedUsersDN = (Get-ADGroup -Identity "$($dom.domainSID)-525" -Server $dom.server -ErrorAction Stop).DistinguishedName } catch { $protectedUsersDN = $null }
        $spn = @(); $neverExp = @(); $oldPwd = @(); $stale = @(); $orphans = @(); $notProtected = @()
        foreach ($a in $enabledAdmins) {
            $name = [string]$a.sAMAccountName
            if ($name -eq 'krbtgt') { continue }
            $isCurrent = $script:ProtectedMemberDNs.ContainsKey([string]$a.DistinguishedName)
            if (-not $isCurrent -and $script:ProtectedMemberDNs.Count -gt 0) { $orphans += $name; continue }
            $spnVal = Get-PropValue $a 'servicePrincipalName'
            if ($spnVal -and @($spnVal | Where-Object { $_ }).Count -gt 0) { $spn += $name }
            if ([int]$a.userAccountControl -band 65536) { $neverExp += $name }
            $pls = ConvertFrom-FileTimeValue (Get-PropValue $a 'pwdLastSet')
            if ($pls -and ((Get-Date).ToUniversalTime() - $pls).TotalDays -gt 365) { $oldPwd += $name }
            $llt = ConvertFrom-FileTimeValue (Get-PropValue $a 'lastLogonTimestamp')
            if (-not $llt -or ((Get-Date).ToUniversalTime() - $llt).TotalDays -gt $StaleDays) { $stale += $name }
            if ($protectedUsersDN -and (@(Get-PropValue $a 'memberOf') -notcontains $protectedUsersDN)) { $notProtected += $name }
        }
        $d = $dom.name
        $map = @(
            @{ K = 'spn'; L = $spn; Sev = 'High'; T = 'Privileged accounts with SPNs (kerberoastable Tier-0)'; R = 'Remove SPNs from privileged users or move services to gMSA.' }
            @{ K = 'pwd-never-expires'; L = $neverExp; Sev = 'High'; T = 'Privileged accounts with password never expires'; R = 'Enforce rotation or vault-managed credentials.' }
            @{ K = 'pwd-older-365d'; L = $oldPwd; Sev = 'Medium'; T = 'Privileged accounts with password older than 365 days'; R = 'Rotate credentials.' }
            @{ K = 'inactive'; L = $stale; Sev = 'Medium'; T = "Privileged accounts inactive > $StaleDays days"; R = 'Disable/remove unused privileged accounts (change control).' }
            @{ K = 'admincount-orphans'; L = $orphans; Sev = 'Low'; T = 'adminCount=1 accounts not found in in-scope protected groups (possible orphans)'; R = 'Verify (cross-domain/universal group membership is not expanded), then clear adminCount and restore ACL inheritance under change control.' }
            @{ K = 'not-in-protected-users'; L = $notProtected; Sev = 'Info'; T = 'Privileged accounts not in Protected Users'; R = 'Evaluate Protected Users for interactive admin accounts (test first: breaks NTLM/delegation).' }
        )
        foreach ($m in $map) {
            $list = @($m.L)
            if ($list.Count -eq 0) { continue }
            $names = @($list | ForEach-Object { Get-DisplayName $_ })
            Add-Finding -CheckId 'PRIV-002' -Category 'PrivilegedAccess' -Severity $m.Sev -Title $m.T -Target "$d/priv-$($m.K)" -Count $list.Count -Sample $names -Recommendation $m.R
        }
        try {
            $builtin = Get-ADUser -Identity "$($dom.domainSID)-500" -Properties PasswordLastSet, Enabled -Server $dom.server
            if ($builtin.PasswordLastSet -and ((Get-Date) - $builtin.PasswordLastSet).TotalDays -gt 365) {
                Add-Finding -CheckId 'PRIV-002' -Category 'PrivilegedAccess' -Severity 'Medium' -Title "Built-in Administrator (RID 500) password is $([int]((Get-Date) - $builtin.PasswordLastSet).TotalDays) days old" -Target "$d/RID500"
            }
            $guest = Get-ADUser -Identity "$($dom.domainSID)-501" -Properties Enabled -Server $dom.server
            if ($guest.Enabled) {
                Add-Finding -CheckId 'PRIV-002' -Category 'PrivilegedAccess' -Severity 'High' -Title 'Guest account is enabled' -Target "$d/RID501" -Recommendation 'Disable the Guest account (change control).'
            }
        }
        catch { Add-CollectorError -Stage 'PRIV-002' -Target $d -Message "Built-in accounts: $($_.Exception.Message)" }
    }
    'Privileged account hygiene evaluated'
}

Invoke-HealthCheck -Id 'HYG-000' -Category 'Hygiene' -Name 'Domain policy: default password policy, MachineAccountQuota' -Skip:$SkipHygiene `
    -Command 'Get-ADDefaultDomainPasswordPolicy; Get-ADObject <domainDN> -Properties ms-DS-MachineAccountQuota; Get-ADFineGrainedPasswordPolicy -Filter *' -ScriptBlock {
    foreach ($dom in $script:DomainList) {
        $pp = Get-ADDefaultDomainPasswordPolicy -Server $dom.server
        if ($pp.MinPasswordLength -lt 8 -or -not $pp.ComplexityEnabled) {
            Add-Finding -CheckId 'HYG-000' -Category 'Hygiene' -Severity 'High' -Title "Weak default password policy (min length $($pp.MinPasswordLength), complexity $($pp.ComplexityEnabled))" -Target "$($dom.name)/password-policy"
        }
        elseif ($pp.MinPasswordLength -lt 14) {
            Add-Finding -CheckId 'HYG-000' -Category 'Hygiene' -Severity 'Low' -Title "Default minimum password length is $($pp.MinPasswordLength) (< 14)" -Target "$($dom.name)/password-policy"
        }
        if ($pp.LockoutThreshold -eq 0) {
            Add-Finding -CheckId 'HYG-000' -Category 'Hygiene' -Severity 'Medium' -Title 'No account lockout threshold configured' -Target "$($dom.name)/lockout-policy" -Recommendation 'Password spraying is unthrottled. Evaluate lockout or smart lockout equivalents.'
        }
        $maqObj = Get-ADObject -Identity $dom.distinguishedName -Properties 'ms-DS-MachineAccountQuota' -Server $dom.server
        $maq = Get-PropValue $maqObj 'ms-DS-MachineAccountQuota'
        $dom.machineAccountQuota = $maq
        if ($maq -and [int]$maq -gt 0) {
            Add-Finding -CheckId 'HYG-000' -Category 'Hygiene' -Severity 'Medium' -Title "ms-DS-MachineAccountQuota is $maq (any user can join computers)" -Target "$($dom.name)/MAQ" `
                -Recommendation 'Set to 0 and delegate join rights to specific groups (enables several RBCD/relay attack paths otherwise).'
        }
        $fgpp = @(Get-ADFineGrainedPasswordPolicy -Filter * -Server $dom.server)
        $dom.metrics['fineGrainedPasswordPolicies'] = $fgpp.Count
    }
    'Domain policies evaluated'
}

# Data-driven hygiene rules. Each rule is one paged LDAP query per domain.
$now = Get-Date
$staleFt = $now.AddDays(-$StaleDays).ToFileTimeUtc()
$staleGt = ConvertTo-GeneralizedTime $now.AddDays(-$StaleDays)
$uacDisabled = '(userAccountControl:1.2.840.113556.1.4.803:=2)'
$enabledUser = "(objectCategory=person)(objectClass=user)(!$uacDisabled)"
$enabledComputer = "(objectCategory=computer)(!$uacDisabled)"
$notDc = '(!(primaryGroupID=516))(!(primaryGroupID=521))'
$activeRecently = "(lastLogonTimestamp>=$staleFt)"
$script:HygieneRules = @(
    @{ Id = 'HYG-001'; Sev = 'Medium'; Title = "Enabled user accounts inactive > $StaleDays days"; Metric = 'staleUsers'
        Filter = "(&$enabledUser(|(lastLogonTimestamp<=$staleFt)(&(!(lastLogonTimestamp=*))(whenCreated<=$staleGt))))"; Rec = 'Disable after owner validation (change control); feeds attack surface and licensing.' }
    @{ Id = 'HYG-002'; Sev = 'Low'; Title = "Enabled computer accounts inactive > $StaleDays days"; Metric = 'staleComputers'
        Filter = "(&$enabledComputer$notDc(|(lastLogonTimestamp<=$staleFt)(&(!(lastLogonTimestamp=*))(whenCreated<=$staleGt))))"; Rec = 'Disable/cleanup via lifecycle process.' }
    @{ Id = 'HYG-003'; Sev = 'Medium'; Title = 'Enabled users with password never expires'; Metric = 'passwordNeverExpires'
        Filter = "(&$enabledUser(userAccountControl:1.2.840.113556.1.4.803:=65536))"; Rec = 'Move service accounts to gMSA; enforce expiry or vaulting for people.' }
    @{ Id = 'HYG-004'; Sev = 'High'; Title = 'Enabled accounts with PASSWD_NOTREQD (may have empty password)'; Metric = 'passwordNotRequired'
        Filter = "(&(|(&$enabledUser)(&$enabledComputer))(userAccountControl:1.2.840.113556.1.4.803:=32))"; Rec = 'Clear the flag and verify a password is set (change control).' }
    @{ Id = 'HYG-005'; Sev = 'High'; Title = 'Enabled accounts not requiring Kerberos pre-authentication (AS-REP roastable)'; Metric = 'asRepRoastable'
        Filter = "(&$enabledUser(userAccountControl:1.2.840.113556.1.4.803:=4194304))"; Rec = 'Require pre-auth unless a documented legacy dependency exists.' }
    @{ Id = 'HYG-006'; Sev = 'Medium'; Title = 'Enabled user accounts with SPNs (kerberoastable)'; Metric = 'kerberoastableUsers'
        Filter = "(&$enabledUser(servicePrincipalName=*)(!(sAMAccountName=krbtgt)))"; Rec = 'Use gMSA or long random passwords (25+ chars) and AES-only.' }
    @{ Id = 'HYG-007'; Sev = 'High'; Title = 'Non-DC principals trusted for unconstrained delegation'; Metric = 'unconstrainedDelegation'
        Filter = "(&(|(&$enabledUser)(&$enabledComputer))$notDc(userAccountControl:1.2.840.113556.1.4.803:=524288))"; Rec = 'Replace with constrained/RBCD delegation; unconstrained hosts can capture TGTs of any authenticating user.' }
    @{ Id = 'HYG-008'; Sev = 'Medium'; Title = 'Accounts with constrained delegation + protocol transition (T2A4D)'; Metric = 'protocolTransitionDelegation'
        Filter = "(&(|(&$enabledUser)(&$enabledComputer))$notDc(userAccountControl:1.2.840.113556.1.4.803:=16777216))"; Rec = 'Validate each target SPN list; protocol transition allows impersonation without user credentials.' }
    @{ Id = 'HYG-009'; Sev = 'High'; Title = 'Enabled accounts storing passwords with reversible encryption'; Metric = 'reversibleEncryption'
        Filter = "(&$enabledUser(userAccountControl:1.2.840.113556.1.4.803:=128))"; Rec = 'Clear the flag and reset passwords (change control).' }
    @{ Id = 'HYG-010'; Sev = 'Medium'; Title = 'Enabled accounts restricted to DES Kerberos'; Metric = 'desOnly'
        Filter = "(&(|(&$enabledUser)(&$enabledComputer))(userAccountControl:1.2.840.113556.1.4.803:=2097152))"; Rec = 'DES is disabled by default since 2008 R2; these accounts are broken or weak.' }
    @{ Id = 'HYG-011'; Sev = 'Medium'; Title = 'Principals with sIDHistory populated'; Metric = 'sidHistory'
        Filter = '(sIDHistory=*)'; Rec = 'Clean up post-migration sIDHistory; it is a persistence/escalation vector.' }
    @{ Id = 'HYG-012'; Sev = 'High'; Title = 'Active computers on unsupported legacy OS (XP/Vista/7/8/2003/2008/2012)'; Metric = 'legacyOsActive'
        Filter = "(&$enabledComputer$activeRecently(|(operatingSystem=*XP*)(operatingSystem=*Vista*)(operatingSystem=Windows 7*)(operatingSystem=Windows 8*)(operatingSystem=*2003*)(operatingSystem=*2008*)(operatingSystem=*2012*)))"; Rec = 'Isolate, upgrade or retire; confirm ESU coverage where applicable.' }
    @{ Id = 'HYG-013'; Sev = 'Medium'; Title = 'Active Windows 10 computers (end of support 2025-10-14)'; Metric = 'windows10Active'
        Filter = "(&$enabledComputer$activeRecently(operatingSystem=Windows 10*))"; Rec = 'Confirm ESU enrollment or migrate to a supported OS.' }
)

Invoke-HealthCheck -Id 'HYG-100' -Category 'Hygiene' -Name "Object hygiene rules ($($script:HygieneRules.Count) LDAP rules per domain)" -Skip:$SkipHygiene `
    -Command 'Get-ADObject -LDAPFilter <rule filter> -Properties sAMAccountName,lastLogonTimestamp,operatingSystem (ResultPageSize 1000). Filters listed in report.collector.hygieneRules' -ScriptBlock {
    foreach ($dom in $script:DomainList) {
        foreach ($rule in $script:HygieneRules) {
            try {
                $objs = @(Get-DirectoryObject -Server $dom.server -LdapFilter $rule.Filter -Properties sAMAccountName, lastLogonTimestamp, operatingSystem, whenCreated)
            }
            catch { Add-CollectorError -Stage $rule.Id -Target $dom.name -Message $_.Exception.Message; continue }
            Add-Metric $rule.Metric $objs.Count 'Sum'
            $dom.metrics[$rule.Metric] = $objs.Count
            if ($objs.Count -eq 0) { continue }
            $rows = @($objs | ForEach-Object {
                    $llt = ConvertFrom-FileTimeValue (Get-PropValue $_ 'lastLogonTimestamp')
                    [pscustomobject][ordered]@{
                        sAMAccountName     = (Get-DisplayName ([string](Get-PropValue $_ 'sAMAccountName')))
                        objectClass        = [string]$_.ObjectClass
                        lastLogonTimestamp = if ($llt) { $llt.ToString('yyyy-MM-dd') } else { '' }
                        operatingSystem    = [string](Get-PropValue $_ 'operatingSystem')
                        whenCreated        = [string](Get-PropValue $_ 'whenCreated')
                        distinguishedName  = if ($RedactNames) { '' } else { [string]$_.DistinguishedName }
                    }
                })
            $ref = Save-DetailCsv -Rows $rows -Name "$($dom.name)-$($rule.Id)"
            Add-Finding -CheckId $rule.Id -Category 'Hygiene' -Severity $rule.Sev -Title $rule.Title -Target $dom.name -Count $objs.Count `
                -Sample @($rows | ForEach-Object { $_.sAMAccountName }) -EvidenceRef $ref -Recommendation $rule.Rec -Detail "LDAP: $($rule.Filter)"
        }
        # Population denominators for trend ratios
        try {
            $dom.metrics['enabledUsers'] = @(Get-DirectoryObject -Server $dom.server -LdapFilter "(&$enabledUser)").Count
            $dom.metrics['enabledComputers'] = @(Get-DirectoryObject -Server $dom.server -LdapFilter "(&$enabledComputer)").Count
            Add-Metric 'enabledUsers' $dom.metrics['enabledUsers'] 'Sum'
            Add-Metric 'enabledComputers' $dom.metrics['enabledComputers'] 'Sum'
        }
        catch { Add-CollectorError -Stage 'HYG-100' -Target $dom.name -Message "Population counts: $($_.Exception.Message)" }
    }
    "$($script:HygieneRules.Count) rules x $($script:DomainList.Count) domain(s)"
}

Invoke-HealthCheck -Id 'HYG-014' -Category 'Hygiene' -Name 'LAPS coverage (Windows LAPS or legacy LAPS) on active non-DC Windows computers' -Skip:$SkipHygiene `
    -Command 'Schema lookup for msLAPS-PasswordExpirationTime / ms-Mcs-AdmPwdExpirationTime; Get-ADObject -LDAPFilter <active windows computers without either attribute>' -ScriptBlock {
    $schemaNC = (Get-ADRootDSE -Server $rootServer).schemaNamingContext
    $attrs = @()
    foreach ($a in 'msLAPS-PasswordExpirationTime', 'ms-Mcs-AdmPwdExpirationTime') {
        $found = @(Get-ADObject -SearchBase $schemaNC -LDAPFilter "(lDAPDisplayName=$a)" -Server $rootServer)
        if ($found.Count -gt 0) { $attrs += $a }
    }
    if ($attrs.Count -eq 0) {
        Add-Finding -CheckId 'HYG-014' -Category 'Hygiene' -Severity 'High' -Title 'No LAPS schema attributes present (LAPS not deployed)' -Target 'forest' `
            -Recommendation 'Deploy Windows LAPS to eliminate shared local administrator passwords (lateral movement).'
        return 'LAPS schema absent'
    }
    $missingClause = ($attrs | ForEach-Object { "(!($_=*))" }) -join ''
    foreach ($dom in $script:DomainList) {
        $objs = @(Get-DirectoryObject -Server $dom.server -LdapFilter "(&$enabledComputer$notDc$activeRecently(operatingSystem=Windows*)$missingClause)" -Properties sAMAccountName, operatingSystem)
        Add-Metric 'lapsMissing' $objs.Count 'Sum'
        $dom.metrics['lapsMissing'] = $objs.Count
        if ($objs.Count -gt 0) {
            $rows = @($objs | ForEach-Object { [pscustomobject]@{ sAMAccountName = (Get-DisplayName ([string]$_.sAMAccountName)); operatingSystem = [string](Get-PropValue $_ 'operatingSystem') } })
            $ref = Save-DetailCsv -Rows $rows -Name "$($dom.name)-HYG-014"
            Add-Finding -CheckId 'HYG-014' -Category 'Hygiene' -Severity 'Medium' -Title 'Active Windows computers without a LAPS-managed password' -Target $dom.name -Count $objs.Count `
                -Sample @($rows | ForEach-Object { $_.sAMAccountName }) -EvidenceRef $ref -Recommendation 'Extend LAPS policy scope; note expiration attribute may be unreadable if collector lacks rights (verify on a sample).'
        }
    }
    "LAPS attributes present: $($attrs -join ', ')"
}

#endregion

#region ---------- finalize ------------------------------------------------------------------------

$elapsed = (Get-Date) - $script:StartTime
if ($elapsed.TotalMinutes -gt $MaxRuntimeMinutes) {
    Add-Finding -CheckId 'COLLECT-002' -Category 'Collector' -Severity 'Low' -Title "Collector exceeded runtime budget ($([int]$elapsed.TotalMinutes) min > $MaxRuntimeMinutes min)" `
        -Recommendation 'Scope runs (-Domain / -DomainController), skip heavy checks, or run closer to DCs.'
}
foreach ($c in @($script:Checks | Where-Object { $_.status -in 'Error', 'Partial' })) {
    $sev = 'Low'
    if ($c.status -eq 'Error') { $sev = 'High' }
    Add-Finding -CheckId 'COLLECT-001' -Category 'Collector' -Severity $sev -Title "Collection gap: $($c.id) $($c.status.ToLower()) - area NOT verified" -Target $c.id `
        -Detail $c.summary -Recommendation 'Fix permissions/connectivity for the collector identity; do not treat this area as healthy.'
}

$findingsArr = @($script:Findings)
$checksArr = @($script:Checks)
$ran = @($checksArr | Where-Object { $_.status -ne 'Skipped' })
$ok = @($ran | Where-Object { $_.status -ne 'Error' })
$coverage = 100
if ($ran.Count -gt 0) { $coverage = [math]::Round(100.0 * $ok.Count / $ran.Count, 0) }
Add-Metric 'domainCount' $script:DomainList.Count 'Set'
Add-Metric 'dcCount' $script:DcList.Count 'Set'
Add-Metric 'gcCount' @($script:DcList | Where-Object { $_.isGlobalCatalog }).Count 'Set'
Add-Metric 'rodcCount' @($script:DcList | Where-Object { $_.isReadOnly }).Count 'Set'

$sevCounts = [ordered]@{}
foreach ($k in 'Critical', 'High', 'Medium', 'Low', 'Info') { $sevCounts[$k] = @($findingsArr | Where-Object { $_.severity -eq $k }).Count }

$runAs = "$env:USERDOMAIN\$env:USERNAME"
try { $runAs = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { Write-CollectorLog -Level WARN 'WindowsIdentity unavailable; using environment user name.' }

$report = [pscustomobject][ordered]@{
    schemaVersion     = $script:SchemaVersion
    reportType        = 'ADForestHealth'
    reportId          = [guid]::NewGuid().ToString()
    generatedUtc      = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    collector         = [pscustomobject][ordered]@{
        name            = 'Invoke-ADForestHealthReport'
        version         = $script:CollectorVersion
        host            = [System.Net.Dns]::GetHostName()
        runAs           = $runAs
        psVersion       = $PSVersionTable.PSVersion.ToString()
        adModuleVersion = [string](Get-Module ActiveDirectory).Version
        durationSeconds = [int]((Get-Date) - $script:StartTime).TotalSeconds
        serverAffinity  = [pscustomobject]$serverAffinity
        commandLine     = $MyInvocation.Line
        parameters      = [pscustomobject][ordered]@{
            HoursBack = $HoursBack; StaleDays = $StaleDays; BackupWarnDays = $BackupWarnDays; ReplLagWarnHours = $ReplLagWarnHours
            TimeSkewWarnSeconds = $TimeSkewWarnSeconds; PrivilegedGroupWarnCount = $PrivilegedGroupWarnCount
            Domain = @($Domain); DomainController = @($DomainController)
            SkipDcDiag = [bool]$SkipDcDiag; SkipEventLogs = [bool]$SkipEventLogs; SkipRemoteCim = [bool]$SkipRemoteCim; SkipHygiene = [bool]$SkipHygiene; RedactNames = [bool]$RedactNames
            Signed = [bool]$signingCert
        }
        hygieneRules    = @($script:HygieneRules | ForEach-Object { [pscustomobject]@{ id = $_.Id; filter = $_.Filter } })
    }
    summary           = [pscustomobject][ordered]@{
        overallStatus         = (Get-ADHealthOverallStatus -Findings $findingsArr)
        healthScore           = (Get-ADHealthScore -Findings $findingsArr)
        severityCounts        = [pscustomobject]$sevCounts
        domainCount           = $script:DomainList.Count
        domainControllerCount = $script:DcList.Count
        checkCount            = $checksArr.Count
        checkCoveragePercent  = $coverage
        collectionErrorCount  = $script:Errors.Count
        scoped                = [bool]($Domain -or $DomainController)
    }
    forest            = [pscustomobject]$script:forestInfo
    domains           = @($script:DomainList | ForEach-Object { $o = [pscustomobject]$_; $o.metrics = [pscustomobject]$_.metrics; $o })
    domainControllers = @($script:DcList | ForEach-Object { [pscustomobject]$_ })
    metrics           = [pscustomobject]$script:Metrics
    checks            = $checksArr
    findings          = $findingsArr
    errors            = @($script:Errors)
    rawOutputs        = @($script:RawOutputs)
}

try {
    Export-ADHealthArtifacts -Report $report -Directory $script:BundleDir
    if ($signingCert) { Protect-ADHealthManifest -Directory $script:BundleDir -Certificate $signingCert }   # before publish; fail closed
    $final = Join-Path $OutputPath $bundleName
    Move-Item -LiteralPath $script:BundleDir -Destination $final   # same-volume rename = atomic hand-off
}
catch {
    Write-Error "Failed to write/publish report bundle: $($_.Exception.Message). Partial output left in $script:BundleDir"
    exit 1
}

Write-Progress -Activity 'AD forest health' -Completed
[pscustomobject]@{
    BundlePath    = $final
    OverallStatus = $report.summary.overallStatus
    HealthScore   = $report.summary.healthScore
    Critical      = $sevCounts['Critical']
    High          = $sevCounts['High']
    Coverage      = "$coverage%"
    Errors        = $script:Errors.Count
}
if ($script:Errors.Count -gt 0) { exit 3 }
exit 0

#endregion
