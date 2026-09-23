<#
.SYNOPSIS
    End-to-end smoke test of Invoke-ADForestHealthReport.ps1 against a MOCK ActiveDirectory module.

.DESCRIPTION
    Runs on any OS with PowerShell 7 (no domain required). Opens loopback TCP listeners on the DC ports so
    the mock DCs 'localhost' and '127.0.0.2' look reachable (binding <1024 needs root/admin; without it the
    DCs appear unreachable and fewer code paths run - the test still validates the bundle contract).
    Remote-only checks (dcdiag, event logs, CIM) are skipped.

    Asserts: exit code, atomic bundle publish (manifest present, staging empty), manifest hashes, and
    that expected findings from the mock topology are present.

.EXAMPLE
    pwsh ./collector/tests/Invoke-CollectorSmokeTest.ps1
#>
[CmdletBinding()]
param([string]$OutputPath = (Join-Path ([System.IO.Path]::GetTempPath()) "adhealth-smoke-$([guid]::NewGuid().ToString('N').Substring(0,8))"))

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$here = $PSScriptRoot
$collector = Join-Path (Split-Path $here -Parent) 'Invoke-ADForestHealthReport.ps1'
$env:PSModulePath = $here + [System.IO.Path]::PathSeparator + $env:PSModulePath   # MockActiveDirectory folder
$modDir = Join-Path $here 'ActiveDirectory'
if (-not (Test-Path $modDir)) { New-Item -ItemType Directory -Path $modDir | Out-Null }
Copy-Item (Join-Path $here 'MockActiveDirectory/ActiveDirectory.psm1') $modDir -Force   # module name must match folder name

$listeners = @()
foreach ($port in 389, 88, 445, 135, 53, 3268) {
    try { $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $port); $l.Start(); $listeners += $l }
    catch { Write-Warning "Cannot bind port $port ($($_.Exception.Message)); mock DCs will look unreachable." }
}

$failures = [System.Collections.Generic.List[string]]::new()
function Assert-That([bool]$Condition, [string]$Message) { if (-not $Condition) { $failures.Add($Message); Write-Host "FAIL: $Message" -ForegroundColor Red } else { Write-Host "ok:   $Message" } }

try {
    & pwsh -NoProfile -File $collector -OutputPath $OutputPath -SkipDcDiag -SkipEventLogs -SkipRemoteCim -PortTimeoutMs 500 | Out-Host
    $code = $LASTEXITCODE
    Assert-That ($code -in 0, 3) "collector exit code is 0 or 3 (got $code)"

    $bundle = @(Get-ChildItem -LiteralPath $OutputPath -Directory | Where-Object { $_.Name -like 'ADForestHealth_*' })
    Assert-That ($bundle.Count -eq 1) 'exactly one published bundle folder'
    Assert-That (@(Get-ChildItem -LiteralPath (Join-Path $OutputPath '.staging')).Count -eq 0) 'staging folder is empty after publish'
    if ($bundle.Count -ne 1) { throw 'No bundle published; see collector output above.' }
    $b = $bundle[0].FullName
    foreach ($f in 'report.json', 'report.html', 'findings.csv', 'checks.csv', 'domain-controllers.csv', 'manifest.json', 'collector.log') {
        Assert-That (Test-Path (Join-Path $b $f)) "$f exists"
    }
    $manifest = Get-Content (Join-Path $b 'manifest.json') -Raw | ConvertFrom-Json
    foreach ($entry in $manifest.files) {
        $actual = (Get-FileHash -LiteralPath (Join-Path $b $entry.path) -Algorithm SHA256).Hash.ToLower()
        Assert-That ($actual -eq $entry.sha256) "manifest hash matches $($entry.path)"
    }
    $r = Get-Content (Join-Path $b 'report.json') -Raw | ConvertFrom-Json
    Assert-That ($r.schemaVersion -eq '1.0') 'schemaVersion 1.0'
    Assert-That ($r.summary.overallStatus -eq 'Red') "overall status Red (got $($r.summary.overallStatus))"
    $ids = @($r.findings | ForEach-Object { $_.checkId })
    foreach ($expect in 'DC-001', 'DC-003', 'FOREST-001', 'KRB-001', 'TRUST-001', 'SITE-001', 'PRIV-001', 'PRIV-002', 'HYG-000', 'HYG-001', 'HYG-005', 'HYG-012', 'HYG-014', 'DNS-001') {
        Assert-That ($ids -contains $expect) "finding from $expect present"
    }
    if ($listeners.Count -eq 6) {
        foreach ($expect in 'REPL-001', 'REPL-002', 'TIME-001') { Assert-That ($ids -contains $expect) "finding from $expect present (listeners bound)" }
    }
    $errored = @($r.checks | Where-Object { $_.status -eq 'Error' } | ForEach-Object { $_.id })
    # TIME-002/REPL-003 need w32tm/repadmin (absent on test hosts) - they may be Partial/Error; nothing else may error.
    $unexpected = @($errored | Where-Object { $_ -notin 'TIME-002' })
    Assert-That ($unexpected.Count -eq 0) "no unexpected check errors (errored: $($errored -join ', '))"
    $html = Get-Content (Join-Path $b 'report.html') -Raw
    Assert-That ($html -notmatch '<script') 'HTML contains no script tags'
    Write-Host "Bundle: $b"
}
finally {
    foreach ($l in $listeners) { $l.Stop() }
}

if ($failures.Count -gt 0) { Write-Host "$($failures.Count) assertion(s) failed." -ForegroundColor Red; exit 1 }
Write-Host 'Smoke test passed.' -ForegroundColor Green
exit 0
