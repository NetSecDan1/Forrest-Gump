# CLAUDE.md: working in this repo

Pipeline: read-only PowerShell AD forest health **collector** → bundle on a share → Python **agent** (Strands Agents, model-agnostic, Bedrock) → Teams / SharePoint. Read `docs/ARCHITECTURE.md` before a non-trivial change.

## Invariants (do not break)
1. **Collector is read-only.** No `Set-/New-/Remove-/Add-/Move-/Rename-/Enable-/Disable-/Reset-` cmdlets against AD, DNS, GPO, services or registry. No `repadmin /syncall`, `/replicate`, `/removelingeringobjects`, `nltest /sc_reset`, `w32tm /resync`, and no `dcdiag /fix`. The only writes allowed are files under `-OutputPath`.
2. **Every check goes through `Invoke-HealthCheck`** so failures become `Error`/`Partial` and then collection-gap findings. Never let a failure look like a pass.
3. **Finding `id` = `checkId|target` must be stable** across runs. It is the month-over-month diff key and the suppression key. Do not put counts or dates in `target`.
4. **Score parity:** `Get-ADHealthScore` (PowerShell) and `triage.health_score` (Python) must match. `test_score_matches_collector` enforces it.
5. **Schema contract:** additive fields are fine within 1.x. Renames and removals mean bumping the major version in both the collector (`$script:SchemaVersion`) and the agent (`SUPPORTED_SCHEMA_MAJOR`), then regenerating `schema/ad-health-report.schema.json`.
6. **Urgency is deterministic** (`triage.py`, `policy.yaml`). The LLM never decides severity or who gets paged.
7. **No account names** in Teams cards or LLM prompts unless `llm.include_names` is explicitly enabled. Tests assert this.
8. Secrets exist only as env-var names in config. Never log a webhook URL.
9. Deploy scripts that change anything are labeled EXAMPLE and use `SupportsShouldProcess` with `ConfirmImpact='High'`.
10. **Model-agnostic, Strands + Bedrock.** Never hard-code a model family: prompts, the guard and parsing must stay vendor-neutral. Providers live in the `llm.py` registry and only `bedrock` is approved; adding one needs architecture/security review. `LlmConfig.validate()` accepts only `bedrock` or `none`. Never add a default model ID or region. Changing model or mode needs a passing `adhealth-agent qualify` run.
11. **Signing format is a contract** between `Protect-ADHealthManifest` (PowerShell) and `verify_manifest_signature` (Python). Change both together; CI cross-verifies a PowerShell-signed bundle in Python.

## Commands
```bash
cd agent && PYTHONPATH=tests python -m pytest -q                              # agent tests
pwsh -NoProfile -File collector/tests/Invoke-CollectorSmokeTest.ps1           # collector e2e vs mock AD (root for ports <1024)
adhealth-agent validate samples/ADForestHealth_contoso.test_20260901-020000   # bundle integrity + schema (+ --require-signature --trusted-thumbprint X)
adhealth-agent doctor -c <settings.yaml> [--online] [--probe-model]           # agent host preflight
adhealth-agent qualify -c <settings.yaml> -b <bundle> [-b <bundle>]           # model change evidence
```
Regenerate the sample after collector changes: run the smoke test, copy the bundle into `samples/`, scrub host/identity, and re-export with `Export-ADHealthArtifacts` so the manifest hashes match.

## Adding a check
1. Add an `Invoke-HealthCheck -Id '<FAMILY>-NNN'` block with the exact read-only `-Command` text. Use `Add-Finding`, `Add-Metric` and `Save-DetailCsv` for object lists.
2. For a new metric where an increase is bad, add it to `BAD_WHEN_UP` in `triage.py`.
3. Extend `collector/tests/MockActiveDirectory/ActiveDirectory.psm1` and the smoke-test assertions.
4. Add a row to the check catalog in `docs/ARCHITECTURE.md` §6.

## Skill
`.claude/skills/ad-health-triage` investigates a bundle interactively (validate → triage → read-only investigation plan).
