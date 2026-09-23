<#
.SYNOPSIS
    Rendering and export helpers for the AD Forest Health report (HTML / CSV / JSON / manifest).

.DESCRIPTION
    Dot-sourced by Invoke-ADForestHealthReport.ps1. Contains NO Active Directory calls, so it can
    be loaded on any PowerShell 5.1+/7+ host (including Linux CI) to re-render a report from its
    JSON, e.g.:

        . ./ADHealth.Report.ps1
        $r = Get-Content ./report.json -Raw | ConvertFrom-Json
        ConvertTo-ADHealthHtml -Report $r | Set-Content ./report.html -Encoding UTF8

    HTML is executive-safe and JS-free (native <details> elements only).

.NOTES
    Keep this file free of side effects on load. Only the Export-* functions write files, and only
    under the path they are given.
#>

Set-StrictMode -Version Latest

$script:SeverityOrder = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3; 'Info' = 4 }
$script:SeverityWeight = @{ 'Critical' = 20; 'High' = 8; 'Medium' = 3; 'Low' = 1; 'Info' = 0 }
$script:ScorePerCheckCap = 25

function Get-ADHealthScore {
    <#
    .SYNOPSIS
        Deterministic 0-100 score: 100 minus weighted findings, where each checkId's penalty is capped at 25
        so one noisy check (e.g. 40 DCs with the same event) cannot zero the score on its own. Floored at 0.
        The agent recomputes this; keep in sync with agent/adhealth_agent/triage.py :: health_score.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Findings)
    $perCheck = @{}
    foreach ($f in $Findings) {
        $k = [string]$f.checkId
        if (-not $perCheck.ContainsKey($k)) { $perCheck[$k] = 0 }
        $perCheck[$k] += $script:SeverityWeight[[string]$f.severity]
    }
    $penalty = 0
    foreach ($v in $perCheck.Values) { $penalty += [math]::Min($script:ScorePerCheckCap, $v) }
    return [int][math]::Max(0, 100 - $penalty)
}

function Get-ADHealthOverallStatus {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Findings)
    $sev = @($Findings | ForEach-Object { [string]$_.severity })
    if ($sev -contains 'Critical') { return 'Red' }
    if ($sev -contains 'High') { return 'Amber' }
    return 'Green'
}

function ConvertTo-HtmlSafe {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function ConvertTo-ADHealthTable {
    <# Renders objects to an HTML table with encoded cells. Optional severity/status column coloring. #>
    param(
        [AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory)][string[]]$Columns,
        [string]$ColorColumn,
        [string]$EmptyText = 'None.'
    )
    if (-not $Rows -or $Rows.Count -eq 0) { return "<p class='muted'>$(ConvertTo-HtmlSafe $EmptyText)</p>" }
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append('<table><thead><tr>')
    foreach ($c in $Columns) { [void]$sb.Append("<th>$(ConvertTo-HtmlSafe $c)</th>") }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($r in $Rows) {
        [void]$sb.Append('<tr>')
        foreach ($c in $Columns) {
            $v = $null
            if ($r.PSObject.Properties[$c]) { $v = $r.$c }
            if ($v -is [System.Array]) { $v = ($v -join ', ') }
            $cls = ''
            if ($ColorColumn -and $c -eq $ColorColumn -and $v) { $cls = " class='sev sev-$(([string]$v).ToLower())'" }
            [void]$sb.Append("<td$cls>$(ConvertTo-HtmlSafe $v)</td>")
        }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table>')
    return $sb.ToString()
}

function ConvertTo-ADHealthHtml {
    <#
    .SYNOPSIS
        Builds the full JS-free HTML report string from the report object (same shape as report.json).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Report)

    $findings = @($Report.findings | Sort-Object { $script:SeverityOrder[[string]$_.severity] }, category, checkId)
    $checks = @($Report.checks)
    $s = $Report.summary
    $ctx = $Report.collector
    $forest = $Report.forest

    $counts = [ordered]@{}
    foreach ($k in 'Critical', 'High', 'Medium', 'Low', 'Info') {
        $counts[$k] = @($findings | Where-Object { $_.severity -eq $k }).Count
    }
    $statusClass = ([string]$s.overallStatus).ToLower()

    $css = @'
:root{--red:#b42318;--red-bg:#fee4e2;--amber:#b54708;--amber-bg:#fef0c7;--green:#067647;--green-bg:#dcfae6;
--blue:#175cd3;--blue-bg:#d1e9ff;--ink:#101828;--muted:#667085;--line:#eaecf0;--bg:#ffffff;--panel:#f9fafb}
*{box-sizing:border-box}body{font-family:"Segoe UI",Arial,sans-serif;color:var(--ink);background:var(--bg);margin:0;padding:24px;line-height:1.45;font-size:14px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 10px;padding-bottom:6px;border-bottom:2px solid var(--line)}
h3{font-size:14px;margin:18px 0 6px}.muted{color:var(--muted)}
.banner{display:flex;flex-wrap:wrap;gap:12px;align-items:stretch;margin:16px 0}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:10px 14px;min-width:120px}
.tile .v{font-size:22px;font-weight:600}.tile .k{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.status{font-weight:700;border-radius:8px;padding:10px 16px;font-size:18px}
.status.red{background:var(--red-bg);color:var(--red)}.status.amber{background:var(--amber-bg);color:var(--amber)}.status.green{background:var(--green-bg);color:var(--green)}
table{border-collapse:collapse;width:100%;margin:6px 0 14px;font-size:13px}
th,td{border:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top;word-break:break-word}
th{background:var(--panel);font-weight:600;white-space:nowrap}tbody tr:nth-child(even){background:#fcfcfd}
.sev{font-weight:600;white-space:nowrap}
.sev-critical,.sev-fail,.sev-error{background:var(--red-bg);color:var(--red)}
.sev-high,.sev-warn,.sev-partial{background:var(--amber-bg);color:var(--amber)}
.sev-medium{background:#fff6ed;color:#c4320a}.sev-low,.sev-info,.sev-skipped{background:var(--blue-bg);color:var(--blue)}
.sev-pass{background:var(--green-bg);color:var(--green)}
pre{background:var(--panel);border:1px solid var(--line);padding:10px;overflow-x:auto;font-size:12px;white-space:pre-wrap}
details{margin:6px 0}summary{cursor:pointer;font-weight:600}
.kv td:first-child{width:260px;color:var(--muted)}
footer{margin-top:32px;color:var(--muted);font-size:12px}
@media print{details{display:block}body{padding:0}}
'@

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append("<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>")
    [void]$sb.Append("<title>AD Forest Health - $(ConvertTo-HtmlSafe $forest.name)</title><style>$css</style></head><body>")

    # ---- Executive summary ------------------------------------------------------------------
    [void]$sb.Append("<h1>Active Directory Forest Health Report</h1>")
    [void]$sb.Append("<div class='muted'>Forest <b>$(ConvertTo-HtmlSafe $forest.name)</b> &middot; generated $(ConvertTo-HtmlSafe $Report.generatedUtc) UTC &middot; window: last $(ConvertTo-HtmlSafe $ctx.parameters.HoursBack) h &middot; schema $(ConvertTo-HtmlSafe $Report.schemaVersion)</div>")
    [void]$sb.Append("<div class='banner'><div class='status $statusClass'>Overall: $(ConvertTo-HtmlSafe $s.overallStatus)<br><span style='font-size:13px;font-weight:500'>Score $(ConvertTo-HtmlSafe $s.healthScore)/100</span></div>")
    foreach ($k in $counts.Keys) {
        [void]$sb.Append("<div class='tile'><div class='v'>$($counts[$k])</div><div class='k'>$k</div></div>")
    }
    [void]$sb.Append("<div class='tile'><div class='v'>$(ConvertTo-HtmlSafe $s.domainControllerCount)</div><div class='k'>DCs</div></div>")
    [void]$sb.Append("<div class='tile'><div class='v'>$(ConvertTo-HtmlSafe $s.checkCoveragePercent)%</div><div class='k'>Check coverage</div></div></div>")

    $top = @($findings | Where-Object { $_.severity -in 'Critical', 'High' } | Select-Object -First 10)
    [void]$sb.Append('<h2>Key risks (Critical / High)</h2>')
    [void]$sb.Append((ConvertTo-ADHealthTable -Rows $top -Columns 'severity', 'category', 'title', 'target', 'recommendation' -ColorColumn 'severity' -EmptyText 'No Critical or High findings.'))
    if (@($Report.errors).Count -gt 0) {
        [void]$sb.Append("<p class='sev sev-high' style='padding:8px'>Collection gaps: $(@($Report.errors).Count) collection error(s). Areas that could not be checked are NOT confirmed healthy. See 'Collection errors'.</p>")
    }

    # ---- Context -----------------------------------------------------------------------------
    [void]$sb.Append('<h2>Context</h2><table class="kv"><tbody>')
    $kv = [ordered]@{
        'Forest / root domain'     = "$($forest.name) / $($forest.rootDomain)"
        'Forest functional level'  = $forest.forestMode
        'Domains'                  = (@($Report.domains | ForEach-Object { $_.name }) -join ', ')
        'Schema / Naming master'   = "$($forest.schemaMaster) / $($forest.domainNamingMaster)"
        'AD Recycle Bin'           = $forest.recycleBinEnabled
        'Tombstone lifetime (days)'= $forest.tombstoneLifetimeDays
        'Collector host / identity'= "$($ctx.host) / $($ctx.runAs)"
        'Collector version'        = $ctx.version
        'PowerShell / AD module'   = "$($ctx.psVersion) / $($ctx.adModuleVersion)"
        'Query affinity (per domain)' = (@($ctx.serverAffinity.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '; ')
        'Duration (s)'             = $ctx.durationSeconds
    }
    foreach ($k in $kv.Keys) { [void]$sb.Append("<tr><td>$(ConvertTo-HtmlSafe $k)</td><td>$(ConvertTo-HtmlSafe $kv[$k])</td></tr>") }
    [void]$sb.Append('</tbody></table>')

    # ---- Findings --------------------------------------------------------------------------
    [void]$sb.Append("<h2>All findings ($($findings.Count))</h2>")
    [void]$sb.Append((ConvertTo-ADHealthTable -Rows $findings -Columns 'severity', 'id', 'category', 'title', 'target', 'count', 'detail', 'recommendation', 'evidenceRef' -ColorColumn 'severity' -EmptyText 'No findings.'))

    # ---- Domain controllers ----------------------------------------------------------------
    [void]$sb.Append('<h2>Domain controllers</h2>')
    [void]$sb.Append((ConvertTo-ADHealthTable -Rows @($Report.domainControllers) -Columns 'name', 'domain', 'site', 'ipv4Address', 'operatingSystem', 'isGlobalCatalog', 'isReadOnly', 'reachable', 'timeSkewSeconds', 'uptimeDays', 'minFreeDiskPercent', 'sysvolState', 'fsmoRoles'))

    [void]$sb.Append('<h2>Domains</h2>')
    [void]$sb.Append((ConvertTo-ADHealthTable -Rows @($Report.domains) -Columns 'name', 'netBIOSName', 'domainMode', 'pdcEmulator', 'ridMaster', 'infrastructureMaster', 'dcCount', 'krbtgtPasswordAgeDays', 'sysvolReplication', 'machineAccountQuota'))

    [void]$sb.Append('<h2>Key metrics</h2>')
    $metricRows = @($Report.metrics.PSObject.Properties | ForEach-Object { [pscustomobject]@{ metric = $_.Name; value = $_.Value } })
    [void]$sb.Append((ConvertTo-ADHealthTable -Rows $metricRows -Columns 'metric', 'value'))

    # ---- Evidence (checks) ----------------------------------------------------------------
    [void]$sb.Append("<h2>Evidence: checks executed ($($checks.Count))</h2><p class='muted'>Every check is read-only. 'Command' shows exactly what was queried.</p>")
    [void]$sb.Append((ConvertTo-ADHealthTable -Rows $checks -Columns 'id', 'category', 'name', 'status', 'summary', 'durationMs', 'command' -ColorColumn 'status'))

    if (@($Report.errors).Count -gt 0) {
        [void]$sb.Append('<h2>Collection errors</h2>')
        [void]$sb.Append((ConvertTo-ADHealthTable -Rows @($Report.errors) -Columns 'stage', 'target', 'message'))
    }

    # ---- Appendix --------------------------------------------------------------------------
    [void]$sb.Append('<h2>Appendix: raw native-tool output</h2>')
    $raw = @($Report.rawOutputs)
    if ($raw.Count -eq 0) { [void]$sb.Append("<p class='muted'>None captured.</p>") }
    foreach ($r in $raw) {
        [void]$sb.Append("<details><summary>$(ConvertTo-HtmlSafe $r.name)</summary><p class='muted'>Command: <code>$(ConvertTo-HtmlSafe $r.command)</code> &middot; file: $(ConvertTo-HtmlSafe $r.file)</p><pre>$(ConvertTo-HtmlSafe $r.excerpt)</pre></details>")
    }
    [void]$sb.Append('<h3>Reproduction</h3><pre>')
    [void]$sb.Append((ConvertTo-HtmlSafe $ctx.commandLine))
    [void]$sb.Append('</pre>')
    [void]$sb.Append("<footer>Read-only collection. Report may contain sensitive directory data - handle per your data classification policy. Machine-readable twin: report.json (schema $(ConvertTo-HtmlSafe $Report.schemaVersion)).</footer></body></html>")
    return $sb.ToString()
}

function Export-ADHealthArtifacts {
    <#
    .SYNOPSIS
        Writes report.json, report.html, findings.csv, checks.csv, domain-controllers.csv and manifest.json
        into -Directory. manifest.json (SHA-256 of every file) is written LAST so downstream automation can
        treat its presence as "bundle complete" and verify integrity.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][object]$Report,
        [Parameter(Mandatory)][string]$Directory
    )
    if (-not $PSCmdlet.ShouldProcess($Directory, 'Write AD health report artifacts')) { return }
    if (-not (Test-Path -LiteralPath $Directory)) { New-Item -ItemType Directory -Path $Directory -Force | Out-Null }

    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $json = $Report | ConvertTo-Json -Depth 12
    [System.IO.File]::WriteAllText((Join-Path $Directory 'report.json'), $json, $utf8)
    [System.IO.File]::WriteAllText((Join-Path $Directory 'report.html'), (ConvertTo-ADHealthHtml -Report $Report), $utf8)

    @($Report.findings) | Select-Object id, severity, category, checkId, title, target, count, detail, recommendation, evidenceRef |
        Export-Csv -LiteralPath (Join-Path $Directory 'findings.csv') -NoTypeInformation -Encoding UTF8
    @($Report.checks) | Select-Object id, category, name, status, summary, durationMs, command |
        Export-Csv -LiteralPath (Join-Path $Directory 'checks.csv') -NoTypeInformation -Encoding UTF8
    @($Report.domainControllers) | Select-Object name, domain, site, ipv4Address, operatingSystem, isGlobalCatalog, isReadOnly, reachable, timeSkewSeconds, uptimeDays, minFreeDiskPercent, sysvolState, @{n = 'fsmoRoles'; e = { @($_.fsmoRoles) -join ';' } } |
        Export-Csv -LiteralPath (Join-Path $Directory 'domain-controllers.csv') -NoTypeInformation -Encoding UTF8

    $root = (Resolve-Path -LiteralPath $Directory).ProviderPath.TrimEnd('\', '/')   # relative -OutputPath safe
    $files = Get-ChildItem -LiteralPath $root -Recurse -File | Where-Object { $_.Name -ne 'manifest.json' }
    $manifest = [ordered]@{
        schemaVersion = $Report.schemaVersion
        reportId      = $Report.reportId
        forest        = $Report.forest.name
        generatedUtc  = $Report.generatedUtc
        overallStatus = $Report.summary.overallStatus
        files         = @($files | ForEach-Object {
                [ordered]@{
                    path   = $_.FullName.Substring($root.Length + 1).Replace('\', '/')
                    bytes  = $_.Length
                    sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLower()
                }
            })
    }
    [System.IO.File]::WriteAllText((Join-Path $Directory 'manifest.json'), ($manifest | ConvertTo-Json -Depth 5), $utf8)
}
