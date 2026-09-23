---
name: ad-health-triage
description: Investigate an AD forest health report bundle (ADForestHealth_* folder with report.json/manifest.json) and produce a ranked, read-only investigation plan. Use when the user points at a bundle, pastes findings from report.json/findings.csv, or asks "what should we look at first" about an AD health report or an urgent Teams alert from this pipeline.
---

# AD health bundle triage

You are helping a senior AD engineer act on a report from this repo's collector. Detection is done. Your job is prioritization and a **read-only** verification plan. Never propose running a state-changing command without labeling it `EXAMPLE – DO NOT RUN`, and add change-control and rollback notes when you do.

## Steps
1. **Verify before trusting.** Run `adhealth-agent validate <bundle>` (install with `pip install -e agent` if needed). If it fails (hash mismatch, schema), stop and report it. A tampered or partial bundle is itself a finding.
2. **Load the facts.** Read `report.json` → `summary`, `checks` (look at `Error`/`Partial`/`Skipped` first: those areas are *unverified*), then `findings` sorted Critical → Info. Use `detail/*.csv` and `raw/*.txt` for evidence and cite the file paths.
3. **Compare** with a previous bundle if the user has one (same `forest.name`). Diff on finding `id`: new / escalated / resolved / persisting.
4. **Look for conflicting signals** and name them explicitly. Examples: `REPL-003` says repadmin disagrees with the cmdlets; `dcdiag` passes while `REPL-001` fails; `TIME-001` skew on one DC alongside `EVT-001` W32Time events elsewhere.
5. **Output** using the troubleshooting model:
   - Problem statement (1–2 lines)
   - Ranked hypotheses (most likely / most impactful first), each tied to finding IDs
   - Evidence to collect (read-only), with exact commands (`repadmin /showrepl <dc> /csv`, `repadmin /showobjmeta`, `dcdiag /s:<dc> /test:<t>`, `nltest /dsgetdc:<domain> /force`, `w32tm /query /status /computer:<dc>`, `Get-WinEvent -ComputerName <dc> -FilterHashtable @{LogName='Directory Service';Id=<id>}`)
   - Interpretation guidance: what good and bad look like, with thresholds
   - Safe next steps, with blast radius noted if a change is eventually needed
6. Keep account names out of anything meant for Teams or broad distribution.

## Reference
- Check catalog and thresholds: `docs/ARCHITECTURE.md` §6
- Urgent rules: `agent/config/policy.yaml`
- Collector command for each check: `report.json` → `checks[].command`
