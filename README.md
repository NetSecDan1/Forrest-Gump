# Forrest-Gump: AD forest health, collected safely and triaged by an agent

A read-only PowerShell collector produces a detailed Active Directory forest health bundle (HTML + JSON + CSV). A Python agent built on [Strands Agents](https://strandsagents.com) and Claude verifies each bundle and compares it with last month. It sends urgent issues to Teams and publishes a monthly hygiene digest to SharePoint.

```
DCs ──read-only──▶ Collector (gMSA, scheduled) ──atomic bundle + SHA-256 manifest──▶ drop share
                                                                                         │
      Teams #identity-alerts ◀── urgent (deterministic rules, throttled) ◀── adhealth-agent process
      Teams #identity-health + SharePoint digest ◀── Strands/Claude narrative (guarded) ◀── adhealth-agent digest
```

| Path | What |
|---|---|
| `collector/Invoke-ADForestHealthReport.ps1` | Collector: 26 checks in 14 families (replication, SYSVOL, DNS, time, FSMO, backup, dcdiag, events, trusts, sites, Kerberos, privileged access, hygiene, LAPS). Read-only. |
| `collector/ADHealth.Report.ps1` | JS-free HTML renderer, CSV/JSON export, manifest. No AD calls, so it re-renders anywhere. |
| `collector/tests/` | End-to-end smoke test against a mock `ActiveDirectory` module (runs on Linux CI). |
| `agent/adhealth_agent/` | `ingest` → `history` → `triage` (deterministic) → `narrative` (Strands + faithfulness guard) → `publish` (Teams / SharePoint, dry-run by default). |
| `agent/config/` | `settings.example.yaml` (no secrets, only env-var names) and `policy.yaml` (urgent rules, suppressions). |
| `schema/ad-health-report.schema.json` | The collector → agent contract (schema 1.x). |
| `samples/` | Synthetic bundle (`contoso.test`) from the mock run. Open `report.html` to see the output. |
| `deploy/Register-ADHealthCollectorTask.ps1` | EXAMPLE scheduled-task registration (gMSA, `-WhatIf`). |
| `docs/ARCHITECTURE.md` | Design, options considered, threat model, check catalog, roadmap. |
| `docs/RUNBOOK.md` | Prerequisites, pilot, validation, operations, troubleshooting, backout. |

## Quick start (no domain needed)

```bash
cd agent && pip install -e ".[dev,llm]" && PYTHONPATH=tests python -m pytest -q     # 30 tests
adhealth-agent validate ../samples/ADForestHealth_contoso.test_20260901-020000
pwsh -NoProfile -File ../collector/tests/Invoke-CollectorSmokeTest.ps1               # needs root/admin for loopback ports
```

## Pilot on a real forest (read-only)

```powershell
.\collector\Invoke-ADForestHealthReport.ps1 -OutputPath D:\ADHealth-pilot -DomainController DC01,DC02 -Verbose
```

## Safety properties
* The collector makes **no changes** to AD, DNS, GPO, registry or services. It writes files only under `-OutputPath`.
* A check that cannot run becomes a **collection-gap finding**, never a silent pass.
* Only deterministic code decides what is urgent. The LLM writes prose over triaged data through read-only tools, never sees account names, and its output is checked against the report before it is published.
* Every channel defaults to **dry-run**. Payloads are written to `agent/outbox/` until you enable delivery.
