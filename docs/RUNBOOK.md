# Runbook — deploy, validate, operate, back out

Everything below is ordered **lab → pilot → production**. Steps marked **CHANGE** alter something (a host, an ACL, a tenant setting) and need your normal change approval. The collector itself never changes AD.

## 0. Prerequisites checklist

| Item | Detail |
|---|---|
| Collector host | Windows Server 2019+ management/jump host, domain-joined, Tier-0 hardened. RSAT: `RSAT.ActiveDirectory.DS-LDS.Tools` (gives the AD module plus `repadmin`/`dcdiag`/`nltest`). `w32tm` is built in. |
| gMSA | e.g. `gmsa-adhealth$`, with `PrincipalsAllowedToRetrieveManagedPassword` = the collector host (**CHANGE**, AD) |
| Rights for the gMSA | Event Log Readers (domain builtin) and Remote Management Users on DCs for full coverage (**CHANGE**, AD group membership, via your Tier-0 process). **No** Domain Admins. |
| Drop share | `\\fs01\ADHealth$\inbox`: gMSA **Modify**, agent identity **Read**, Tier-0 admins **Read**, nobody else (**CHANGE**) |
| Agent host | Python 3.10+ on an internal VM (phase 1) that can read the share. Outbound HTTPS to the Teams Workflow URL, `graph.microsoft.com`, and your LLM endpoint (Anthropic API or Bedrock) if enabled |
| Teams | Two channels plus two Workflows ("When a Teams webhook request is received" → "Post card in a chat or channel") (**CHANGE**, M365) |
| SharePoint | Entra app registration with Graph **Sites.Selected** (application), admin consent, then grant `write` on the single target site. Certificate credential (**CHANGE**, Entra) |

## 1. Lab validation (no domain needed)

```bash
# Agent tests (31), incl. PowerShell/Python score parity and end-to-end dry run
cd agent && pip install -e ".[dev,llm]" && PYTHONPATH=tests python -m pytest -q

# Collector end-to-end against a mock ActiveDirectory module (pwsh 7; root/admin to bind loopback DC ports)
pwsh -NoProfile -File collector/tests/Invoke-CollectorSmokeTest.ps1
```
Expected: `31 passed`; `Smoke test passed.` The HTML output is in the temp path printed.

## 2. Pilot the collector (read-only, 1–2 DCs)

```powershell
# As your own admin account first, then as the gMSA (via the scheduled task) to find permission gaps.
.\collector\Invoke-ADForestHealthReport.ps1 -OutputPath D:\ADHealth-pilot -DomainController DC01,DC02 -Verbose
```

| Validate | Expected |
|---|---|
| Exit code | `0` (no gaps) or `3` (gaps, listed in the report under "Collection errors") |
| `D:\ADHealth-pilot\ADForestHealth_<forest>_<stamp>\manifest.json` exists | Yes. `.staging\` is empty |
| `report.html` → Evidence table | Every check shows `Pass/Warn/Fail`. `Partial`/`Error` rows name the missing right |
| Cross-check 3 findings by hand | e.g. `repadmin /showrepl DC01`, `w32tm /stripchart /computer:DC01 /samples:3 /dataonly`, `Get-ADUser krbtgt -Properties PasswordLastSet` |
| DC load during run | Watch LSASS CPU and LDAP searches/sec in PerfMon. Expect short bursts during the HYG-100 queries. Use `-SkipHygiene` if a DC is already stressed |
| Runtime | Record it. It sets `-MaxRuntimeMinutes` for production (default budget 240 min) |

Then run it forest-wide (no `-DomainController`), still to a local path, and review before pointing it at the share.

## 3. Schedule the collector (CHANGE on the collector host)

```powershell
# Dry run first - shows the exact task definitions, changes nothing:
.\deploy\Register-ADHealthCollectorTask.ps1 -GmsaName 'CONTOSO\gmsa-adhealth$' `
    -CollectorPath C:\ADHealth\collector\Invoke-ADForestHealthReport.ps1 -OutputPath \\fs01\ADHealth$\inbox -IncludeDaily -WhatIf
# Then without -WhatIf (prompts for confirmation).
```
Validate: `Get-ScheduledTask -TaskPath \ADHealth\`; `Start-ScheduledTask -TaskPath \ADHealth\ -TaskName ADHealth-Daily-Light`; a new bundle appears in the inbox; `LastTaskResult` is `0` or `3`.

## 4. Deploy the agent (dry-run first)

```bash
cd agent
pip install -e ".[llm,graph]"          # llm: Strands + Anthropic; add [bedrock] for Bedrock
cp config/settings.example.yaml config/settings.yaml   # set inbox to the share path; keep dry_run: true
adhealth-agent validate "/mnt/adhealth/inbox/ADForestHealth_contoso.com_20261001-020000"
adhealth-agent process -c config/settings.yaml          # urgent cards -> ./outbox/*.json (not sent)
adhealth-agent digest  -c config/settings.yaml          # digest page + card -> ./outbox
```
Review the outbox payloads with the identity team. Paste one card JSON into the Adaptive Card Designer to preview it. Then set the secrets as environment variables, not in files:

| Variable | Purpose |
|---|---|
| `ADHEALTH_TEAMS_URGENT_WEBHOOK`, `ADHEALTH_TEAMS_DIGEST_WEBHOOK` | Workflows URLs (secrets) |
| `ADHEALTH_GRAPH_TENANT_ID`, `ADHEALTH_GRAPH_CLIENT_ID`, `ADHEALTH_GRAPH_CERT_PATH`, `ADHEALTH_GRAPH_CERT_THUMBPRINT` | SharePoint upload (certificate preferred) |
| `ANTHROPIC_API_KEY` (or AWS credentials for Bedrock) | Only if `llm.provider` is not `none` |

Flip `dry_run: false` and `sharepoint.enabled: true`. Schedule it (**CHANGE** on the agent host; uses a separate gMSA with **Read** only on the share):

```powershell
.\deploy\Register-ADHealthAgentTask.ps1 -GmsaName 'CONTOSO\gmsa-adhealth-agent$' `
    -AgentExe C:\ADHealth\agent\.venv\Scripts\adhealth-agent.exe -ConfigPath C:\ADHealth\agent\config\settings.yaml -WhatIf
```
* `process`: hourly. Cheap and idempotent: bundles already in history are skipped by `reportId` without re-hashing. New bundles are always fully verified.
* `digest`: 2nd of each month, 08:00 local.
* Set secrets as **machine** environment variables on this dedicated host (`[Environment]::SetEnvironmentVariable(name, value, 'Machine')`). With no `ANTHROPIC_API_KEY`, the digest uses the template automatically.

## 5. Operating it

**When an urgent card arrives:** open the report link, then follow the finding's recommendation and the troubleshooting model:
1. Confirm with the native tool shown in the report's Evidence section. The command is copied there verbatim.
2. Rank hypotheses. For example, REPL 8606 points to lingering objects: check `repadmin /showrepl`, event 1988, and whether the source DC was offline longer than the TSL.
3. Collect read-only evidence and open an incident. Remediation goes through change control.

**Accepting a risk:** add a suppression to `policy.yaml` with `id` (copied from `findings.csv`), `reason`, `owner` and `expires`. Critical findings cannot be suppressed.

**Monthly:** read the digest. Anything under "Collection gaps" means that area was not checked.

## 6. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Collector exit `1`, no bundle | AD module missing / cannot bind forest / output path not writable | Read the console error; check RSAT and the share ACL |
| Many `Partial` checks | gMSA lacks Event Log Readers / WinRM / DFSR WMI rights | Grant the specific right, or accept the gap with the matching `-Skip*` switch |
| `DC-001` Critical for a healthy DC | Firewall between collector host and DC | Allow the ports listed in DC-001 from the collector host |
| `REPL-003` "conflicting signals" | Cmdlets and repadmin disagree | Trust neither alone. Inspect `raw/repadmin-showrepl-<dc>.txt` |
| Agent: `REJECTED ... SHA-256 mismatch` | Partial copy or edit after collection | Recopy the whole folder. If nobody copied it, treat it as a security event |
| Agent: narrative `source=deterministic` with warnings | LLM failed or was rejected by the faithfulness guard | See the log warnings. The digest is still correct (template) |
| No digest | No *full* run in history (only light runs) | Check that the monthly task ran without `-Skip*` switches |

## 7. Rollback / backout

| Component | Backout |
|---|---|
| Scheduled tasks | `Unregister-ScheduledTask -TaskPath '\ADHealth\' -TaskName 'ADHealth-Monthly-Full','ADHealth-Daily-Light','ADHealth-Agent-Process','ADHealth-Agent-Digest' -Confirm` |
| gMSA rights | Remove it from Event Log Readers / Remote Management Users. Delete the gMSA if you are decommissioning |
| Agent | Stop the schedule. Delete `state/` and `outbox/` (they contain directory data) |
| Teams | Turn off or delete the two Workflows (this invalidates the URLs) |
| SharePoint | Remove the Sites.Selected grant, then delete the app registration |
| Report data | Apply the retention policy, or purge the share and the SPO library folder |
