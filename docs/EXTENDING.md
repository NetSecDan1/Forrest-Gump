# Extending Forrest-Gump: Adding Health Checks & Baselines

This guide shows how to add new health checks to the collector and new metrics/rules to the agent without breaking invariants (stable finding IDs, score parity, schema contract).

## Adding a New Health Check to the Collector

All checks flow through `Invoke-HealthCheck` to ensure failures become `Error`/`Partial` rather than silent passes. Here's the pattern:

### 1. Define the check ID

Find an unused `FAMILY-NNN` ID. Families are:
- `DC-0xx`: Data center / domain controller connectivity
- `REPL-1xx`: Replication
- `SYSVOL-2xx`: SYSVOL
- `DNS-3xx`: DNS
- `TIME-4xx`: Time sync (W32TM)
- `FSMO-5xx`: FSMO roles
- `BACKUP-6xx`: Backup/snapshots
- `DCDIAG-7xx`: dcdiag checks
- `EVENT-8xx`: Event log scanning
- `TRUST-9xx`: Forest/realm trusts
- `SITE-10xx`: Sites and subnets
- `KERBEROS-11xx`: Kerberos / krbtgt
- `PRIVACCESS-12xx`: Privileged access (admin accounts, ACLs)
- `HYGIENE-13xx`: General hygiene (disabled users, stale computers, duplicate SPNs)
- `LAPS-14xx`: LAPS status

Example: if adding a new SYSVOL check, use `SYSVOL-214`.

### 2. Write the check block

In `collector/Invoke-ADForestHealthReport.ps1`, add a block like this:

```powershell
Invoke-HealthCheck -Id 'SYSVOL-214' -Title 'SYSVOL replication latency' -Description 'Measure time lag for SYSVOL updates across DCs' `
    -Command {
        # Read-only queries only. Use Get-ADReplicationPartnerMetadata, Get-ADReplicationUpToDateVector, repadmin output, etc.
        # Always use repadmin in read-only mode: /showrepl, /showvector, /showutdvec, etc. Never use /syncall, /replicate, /removelingeringobjects.
        $repadmin = & repadmin /showrepl /csv 2>$null | ConvertFrom-Csv
        
        $latencies = @()
        foreach ($dc in $repadmin | select -ExpandProperty 'Source DC Site' -Unique) {
            $latency = [int]$repadmin | where { $_.'Source DC Site' -eq $dc } | measure -Property 'Days Since Last Sync' -Maximum
            $latencies += @{ DC = $dc; LatencyDays = $latency.Maximum }
        }
        
        $maxLatency = ($latencies | measure -Property LatencyDays -Maximum).Maximum
        if ($maxLatency -gt 1) {
            Add-Finding -Severity Warn -Target "SYSVOL" -Message "Max replication latency: $maxLatency days"
        } else {
            Add-Finding -Severity Pass -Target "SYSVOL" -Message "Replication latency within acceptable range"
        }
        
        # Export detailed results (optional, for Evidence tab in HTML)
        Add-Metric -Name 'MaxSysvolLatencyDays' -Value $maxLatency
        Save-DetailCsv -Path $csv -Data $latencies
    }
```

**Key rules:**
- Use only read-only cmdlets (`Get-*`, `Test-*`). Never `Set-`, `New-`, `Remove-`, `Add-`, `Move-`, `Rename-`, `Enable-`, `Disable-`, `Reset-`.
- Never use `repadmin /syncall`, `/replicate`, `/removelingeringobjects`.
- Never use `nltest /sc_reset`, `dcdiag /fix`, `w32tm /resync`.
- Always wrap in `Invoke-HealthCheck` so failures become `Partial`/`Error`.
- Use `Add-Finding` for results, `Add-Metric` for numeric KPIs, `Save-DetailCsv` for object lists.
- The `-Target` in findings must be **stable across runs** — no counts, timestamps, or dynamic names. Use DC name, partition name, or a static role.

### 3. Update the mock for the smoke test

In `collector/tests/MockActiveDirectory/ActiveDirectory.psm1`, add a mock for any new cmdlets you use. For example, if you call `Get-ADReplicationUpToDateVector`, add:

```powershell
function Get-ADReplicationUpToDateVector {
    param($Identity, $EnumerationServer)
    # Return mock data matching your check's assumptions
    return @{
        Partner = 'DC01'
        Filter = 'ObjectClass=*'
        USNFilter = 12345
    }
}
```

### 4. Update smoke test assertions

In `collector/tests/Invoke-CollectorSmokeTest.ps1`, verify your new check:

```powershell
# Assertion for SYSVOL-214
$report.findings | where { $_.checkId -eq 'SYSVOL-214' } | should -not -be $null
```

### 5. Run the smoke test

```bash
pwsh -NoProfile -File collector/tests/Invoke-CollectorSmokeTest.ps1
```

Expected: all tests pass, including your new check.

### 6. Update the check catalog

Add a row to the table in `docs/ARCHITECTURE.md` (section 6, "Check Catalog"):

| ID | Family | Title | Collects | Evidence |
|---|---|---|---|---|
| `SYSVOL-214` | SYSVOL | SYSVOL replication latency | Time lag across DCs | repadmin /showrepl output |

### 7. Update the schema if needed

If your check introduces a **new top-level metric** (not just a new finding), update `schema/ad-health-report.schema.json`:

```json
"metrics": {
  "type": "array",
  "items": {
    "properties": {
      "name": { "type": "string" },
      "value": { "type": ["number", "string", "integer"] }
    }
  }
}
```

If the change is non-additive (removing or renaming a field), bump `schemaVersion` to `2.0` in both:
- `collector/Invoke-ADForestHealthReport.ps1`: `$script:SchemaVersion = '2.0'`
- `agent/adhealth_agent/__init__.py`: `SUPPORTED_SCHEMA_MAJOR = 2`

Then regenerate the schema with:
```bash
python -c "from adhealth_agent.ingest import ADHealthBundle; print(ADHealthBundle.schema_json(indent=2))" > schema/ad-health-report.schema.json
```

---

## Adding a New Metric to the Agent's Triage

If your check exports a metric (via `Add-Metric`), the agent's `triage.py` needs to know whether increases are good or bad.

### 1. Edit `agent/adhealth_agent/triage.py`

Find the `BAD_WHEN_UP` set:

```python
BAD_WHEN_UP = {
    'MaxSysvolLatencyDays',  # add your metric here if higher = worse
    'KerberosClockSkewSeconds',
    'ReplicationDelayMinutes',
    'DcDiagErrorCount',
    ...
}
```

Or if your metric is good when it's high:

```python
GOOD_WHEN_UP = {
    'HealthyReplicationLinksPercent',
    'BackupAgeHours',
    ...
}
```

### 2. Update health score logic

In the `health_score()` function, add a rule if your metric affects the overall score:

```python
def health_score(bundle: ADHealthBundle) -> float:
    """Compute forest health 0-100."""
    score = 100.0
    
    # Deduct points for bad metrics
    for metric in bundle.metrics:
        if metric.name == 'MaxSysvolLatencyDays' and metric.value > 1:
            score -= 5  # lose 5 points per day over threshold
    
    return max(0, score)
```

### 3. Test score parity

Run the tests to confirm PowerShell and Python scores match:

```bash
cd agent && python -m pytest tests/test_score.py -v
```

---

## Adding Environment-Specific Rules

Never commit custom rules to GitHub. Instead, use the placeholder file `agent/config/custom_rules.example.yaml`:

1. Copy it to `agent/config/custom_rules.yaml` in your environment (add to `.gitignore`).
2. Add suppressions, custom baselines, and notes:

```yaml
suppressions:
  - id: "REPL-8606|DC-Sales-01"
    reason: "Lingering object from DC decommission, backlog ticket #12345"
    owner: "alice@contoso.com"
    expires: "2027-01-31"

environment_notes:
  forest: "contoso.com"
  sla_replication_minutes: 15
  backup_window: "20:00-04:00 UTC"
```

3. Load it in `agent/adhealth_agent/triage.py` (if not already done):

```python
from pathlib import Path
import yaml

def load_custom_rules(config_dir: Path) -> dict:
    """Load environment-specific custom rules."""
    custom_file = config_dir / 'custom_rules.yaml'
    if custom_file.exists():
        with open(custom_file) as f:
            return yaml.safe_load(f) or {}
    return {}
```

---

## Workflow: From Idea to Pilot

1. **Design**: describe the check in a comment or issue (what data, why it matters, how it affects urgency)
2. **Implement**: add the check to `Invoke-ADForestHealthReport.ps1` + mock + smoke test
3. **Test**: run `Invoke-CollectorSmokeTest.ps1` locally
4. **Verify**: run the collector on 1–2 test DCs, spot-check the HTML report
5. **Deploy**: schedule the collector on the production jump host
6. **Monitor**: watch the first full run, adjust thresholds in `custom_rules.yaml` if needed

---

## Quick Checklist

- [ ] Check ID is stable (`FAMILY-NNN`, no timestamps or counts in target)
- [ ] Check uses only read-only cmdlets
- [ ] `Invoke-HealthCheck` wraps the check (failures → `Partial`/`Error`)
- [ ] Mock is added to `MockActiveDirectory.psm1`
- [ ] Smoke test assertion validates the check runs
- [ ] Score parity test passes (`test_score_matches_collector`)
- [ ] Catalog row added to `ARCHITECTURE.md` §6
- [ ] Schema version bumped (if non-additive) and regenerated
- [ ] New metrics added to `BAD_WHEN_UP` or `GOOD_WHEN_UP` in `triage.py`
- [ ] Tested on 1–2 test DCs before production

---

## Example: Full New Check Workflow

**Goal**: Add a check for DNS record stale-ness (old A/AAAA records for DCs).

### Step 1: Skeleton

```powershell
Invoke-HealthCheck -Id 'DNS-310' -Title 'DC DNS records freshness' -Description 'Verify DC host records are recently registered' `
    -Command {
        # Get DNS records for all DCs
        $records = Get-DnsServerResourceRecord -ZoneName $forestRoot -Name * -RRType A, AAAA | where { $_.Timestamp -lt (Get-Date).AddDays(-30) }
        
        if ($records) {
            Add-Finding -Severity Warn -Target "DNS" -Message "Found $($records.Count) stale DC records (>30 days old)"
        } else {
            Add-Finding -Severity Pass -Target "DNS" -Message "All DC DNS records are fresh"
        }
    }
```

### Step 2: Mock

```powershell
function Get-DnsServerResourceRecord {
    param($ZoneName, $Name, $RRType)
    return @(
        @{ HostName = 'DC01'; RecordType = 'A'; Timestamp = (Get-Date).AddDays(-5) },
        @{ HostName = 'DC02'; RecordType = 'A'; Timestamp = (Get-Date).AddDays(-5) }
    )
}
```

### Step 3: Smoke test assertion

```powershell
$dnsCheck = $report.findings | where { $_.checkId -eq 'DNS-310' }
$dnsCheck | should -not -be $null
$dnsCheck.severity | should -be 'Pass'
```

### Step 4: Verify → pilot on test DCs → deploy.

---

For any check that involves external systems (e.g., O365, Azure, Bedrock), keep it read-only and fail gracefully with `Add-Finding -Severity Partial -Target ... -Message "Collection error: $error"` if the API is unreachable. The goal is never a silent pass.
