# Runbook — deploy, validate, operate, back out

Everything below is ordered **lab → pilot → production**. Steps marked **CHANGE** alter something (a host, an ACL, a tenant setting) and need your normal change approval. The collector itself never changes AD.

## 0. Prerequisites checklist

| Item | Detail |
|---|---|
| Collector host | Windows Server 2019+ management/jump host, domain-joined, Tier-0 hardened. RSAT: `RSAT.ActiveDirectory.DS-LDS.Tools` (gives the AD module plus `repadmin`/`dcdiag`/`nltest`). `w32tm` is built in. |
| gMSA | e.g. `gmsa-adhealth$`, with `PrincipalsAllowedToRetrieveManagedPassword` = the collector host (**CHANGE**, AD) |
| Rights for the gMSA | Event Log Readers (domain builtin) and Remote Management Users on DCs for full coverage (**CHANGE**, AD group membership, via your Tier-0 process). **No** Domain Admins. |
| Drop share | `\\fs01\ADHealth$\inbox`: gMSA **Modify**, agent identity **Read**, Tier-0 admins **Read**, nobody else (**CHANGE**) |
| Agent host | Python 3.10+ on an internal VM (phase 1) that can read the share. Outbound HTTPS to the Teams Workflow URL, `graph.microsoft.com`, and Bedrock Runtime in the approved region (PrivateLink endpoint if your golden path requires it) |
| Bedrock access | The approved model/inference-profile ID and region from your platform team. An IAM role scoped by `deploy/bedrock-invoke-policy.example.json`. On-prem host → **IAM Roles Anywhere** (host certificate from your PKI + `aws_signing_helper` `credential_process` profile; no long-lived access keys). Model invocation logging per your golden path (**CHANGE**, AWS) |
| Signing certificate | Issued by your internal CA to the collector host (Enhanced Key Usage: Code Signing or Document Signing; RSA 3072+ or ECDSA P-256). Non-exportable private key in `LocalMachine\My`, with **read on the private key** for the collector gMSA only (**CHANGE**) |
| Teams | Two channels plus two Workflows ("When a Teams webhook request is received" → "Post card in a chat or channel") (**CHANGE**, M365) |
| SharePoint | Entra app registration with Graph **Sites.Selected** (application), admin consent, then grant `write` on the single target site. Certificate credential (**CHANGE**, Entra) |

## 1. Lab validation (no domain needed)

```bash
# Agent tests (66), incl. PowerShell/Python score parity and end-to-end dry run
cd agent && pip install -e ".[dev,llm]" && PYTHONPATH=tests python -m pytest -q

# Collector end-to-end against a mock ActiveDirectory module (pwsh 7; root/admin to bind loopback DC ports)
pwsh -NoProfile -File collector/tests/Invoke-CollectorSmokeTest.ps1
```
Expected: `65 passed, 1 skipped` (the skipped test is the PowerShell→Python signature cross-check, which runs in CI); `Smoke test passed.` The HTML output is in the temp path printed.

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

### 3a. Turn on bundle signing (recommended before production)
1. Enroll the signing certificate on the collector host and grant the gMSA read on its private key (**CHANGE**).
2. Re-run the task registration with `-SigningCertificateThumbprint <thumbprint>` (use `-WhatIf` first).
3. Check a new bundle: `adhealth-agent validate <bundle> --require-signature --trusted-thumbprint <thumbprint>` prints `"signer": {..., "trusted": true}`.
4. In the agent's `settings.yaml`, set `integrity.trusted_signer_thumbprints: [<thumbprint>]` and then `integrity.require_signature: true`.
5. **Rotation:** enroll the new certificate, add its thumbprint to the pin list, switch the task to it, and remove the old pin after the last old-signed bundle is processed.

If signing fails, the collector **fails closed**: exit `1`, and the bundle stays in `.staging\` unpublished. That surfaces as a stale-collector alert rather than an unsigned report.

## 4. Deploy the agent (dry-run first)

```bash
cd agent
pip install -e ".[llm,graph]"          # llm: Strands + boto3 (Bedrock). Set llm.model_id + llm.bedrock_region, or provider: none for a pilot
cp config/settings.example.yaml config/settings.yaml   # set inbox to the share path; keep dry_run: true
adhealth-agent validate "/mnt/adhealth/inbox/ADForestHealth_contoso.com_20261001-020000"
adhealth-agent process -c config/settings.yaml          # urgent cards -> ./outbox/*.json (not sent)
adhealth-agent digest  -c config/settings.yaml          # digest page + card -> ./outbox
```
Run the preflight and fix every `FAIL` before scheduling. `--online` checks the AWS identity; `--probe-model` sends one tiny model request:
```bash
adhealth-agent doctor -c config/settings.yaml --online --probe-model
```
Review the outbox payloads with the identity team. Paste one card JSON into the Adaptive Card Designer to preview it. Then set the secrets as environment variables, not in files:

| Variable | Purpose |
|---|---|
| `ADHEALTH_TEAMS_URGENT_WEBHOOK`, `ADHEALTH_TEAMS_DIGEST_WEBHOOK` | Workflows URLs (secrets) |
| `ADHEALTH_GRAPH_TENANT_ID`, `ADHEALTH_GRAPH_CLIENT_ID`, `ADHEALTH_GRAPH_CERT_PATH`, `ADHEALTH_GRAPH_CERT_THUMBPRINT` | SharePoint upload (certificate preferred) |
| `AWS_CONFIG_FILE` + `AWS_PROFILE` (machine scope) | Point at the Roles Anywhere `credential_process` profile the gMSA's task will use. No access keys in env or files |

Flip `dry_run: false` and `sharepoint.enabled: true`. Schedule it (**CHANGE** on the agent host; uses a separate gMSA with **Read** only on the share):

```powershell
.\deploy\Register-ADHealthAgentTask.ps1 -GmsaName 'CONTOSO\gmsa-adhealth-agent$' `
    -AgentExe C:\ADHealth\agent\.venv\Scripts\adhealth-agent.exe -ConfigPath C:\ADHealth\agent\config\settings.yaml -WhatIf
```
* `process`: hourly. Cheap and idempotent: bundles already in history are skipped by `reportId` without re-hashing. New bundles are always fully verified.
* `digest`: 2nd of each month, 08:00 local.
* Set secrets as **machine** environment variables on this dedicated host (`[Environment]::SetEnvironmentVariable(name, value, 'Machine')`). If Bedrock is unreachable or refuses, the digest uses the template automatically, and the log says why.

### 4a. Qualify the model (required before first use and before any model/mode change)
```bash
adhealth-agent qualify -c config/settings.yaml -b <last-month-bundle> -b <this-month-bundle> --runs 5 --out qualification/
```
This runs the real narrator N times per bundle through the same tools, sanitization and faithfulness guard. It reports `verdict` (default bar: 90% guard pass rate), failure reasons, latency p50/p95 and token usage, and writes JSON and Markdown evidence to attach to the change record. Any Bedrock model can be used. If a model can't do tool use, set `llm.mode: single_shot` and qualify again. Exit `0` = PASS, `2` = FAIL.

## 4b. Test Environment Implementation (Estimated Timeline)

**Estimated effort: 2–4 days for a pilot forest (1–3 DCs), assuming prerequisites are met.**

This section consolidates steps 2–4a into a sequential walkthrough for a test environment, with key validation points.

### Prerequisites (before you start)

- [ ] **Lab validation passed** (`§1`): `66 tests pass`, smoke test produces HTML output
- [ ] **Test domain** available: at least 1–2 domain-joined test DCs, or a lab VM with AD, DNS, LDAP, Kerberos
- [ ] **Network access**: collector host can reach all test DCs (LDAP, RPC, WinRM); agent host can reach collector's file share
- [ ] **Accounts**: gMSA (e.g., `gmsa-adhealth-test$`) in test domain, at least one domain admin account for initial config
- [ ] **Teams tenant** (optional for pilot): create two webhook URLs for urgent alerts and digest (or mock them with dummy HTTPS endpoints)
- [ ] **AWS account**: at least temporary Bedrock invoke + IAM Roles Anywhere certs (for agent), or skip Bedrock and use `provider: none` for dry-run

### Day 1–2: Collector on Test Domain

**Goal**: Verify the collector runs on test DCs, finds issues, and exports signed bundles to a test share.

#### 1. Create the test share and gMSA

```powershell
# On your file server (Tier-0):
New-Item -ItemType Directory -Path "C:\ADHealth$\test-inbox" -Force
$adhealth_gmsa = Get-ADServiceAccount -Identity 'gmsa-adhealth-test$' -ErrorAction SilentlyContinue
if (-not $adhealth_gmsa) {
    New-ADServiceAccount -Name 'gmsa-adhealth-test$' -DNSHostName collector-host.test.contoso.com -ManagedPasswordIntervalInDays 30
}

# Grant the gMSA to the collector host:
Add-ADComputerServiceAccount -Identity collector-host$ -ServiceAccount 'gmsa-adhealth-test$'

# Share permissions:
icacls C:\ADHealth$\test-inbox /grant "CONTOSO\gmsa-adhealth-test`$:(OI)(CI)M" /grant "CONTOSO\Domain Admins:(OI)(CI)R"
```

#### 2. Clone the repo onto the collector host

```powershell
# On the test collector host (C:\Forrest-Gump or equivalent):
git clone https://github.com/your-org/forrest-gump.git C:\Forrest-Gump
cd C:\Forrest-Gump
```

#### 3. Test the collector locally (as yourself first)

```powershell
# Run against 1–2 test DCs first, output to a local path:
.\collector\Invoke-ADForestHealthReport.ps1 -OutputPath D:\ADHealth-test `
    -DomainController DC01.test.contoso.com, DC02.test.contoso.com -Verbose
```

**Validation:**
- Exit code `0` or `3` (gaps are OK for a test environment)
- `D:\ADHealth-test\ADForestHealth_<forest>_<stamp>\manifest.json` exists
- Open `report.html` in a browser; check a few findings against `repadmin /showrepl`, `dcdiag`, `w32tm /stripchart`
- **Note runtime:** if it takes 30 minutes on 2 DCs, set `-MaxRuntimeMinutes 45` in the task

#### 4. Grant gMSA rights and re-test

```powershell
# On Tier-0 (or via your change control):
Add-ADGroupMember -Identity "Event Log Readers" -Members 'gmsa-adhealth-test$'
Add-ADGroupMember -Identity "Remote Management Users" -Members 'gmsa-adhealth-test$' -ErrorAction SilentlyContinue  # on each DC WinRM group

# Test running as the gMSA via the task (next step will do this):
```

#### 5. Schedule the collector task

```powershell
# On the collector host:
.\deploy\Register-ADHealthCollectorTask.ps1 -GmsaName 'CONTOSO\gmsa-adhealth-test$' `
    -CollectorPath C:\Forrest-Gump\collector\Invoke-ADForestHealthReport.ps1 `
    -OutputPath "\\fileserver\ADHealth$\test-inbox" -IncludeDaily -WhatIf
# Review output, then run without -WhatIf to register
```

#### 6. Run the task manually to verify

```powershell
# On the collector host:
Start-ScheduledTask -TaskPath '\ADHealth\' -TaskName 'ADHealth-Daily-Light'
# Wait 2–5 minutes, then check:
Get-ScheduledTask -TaskPath '\ADHealth\' -TaskName 'ADHealth-Daily-Light' | select LastTaskResult, LastRunTime
# Should be 0 or 3 (0 = no gaps, 3 = gaps found, both are OK)

# Check the share:
ls "\\fileserver\ADHealth$\test-inbox"
# Should show ADForestHealth_*.zip or folder with manifest.json
```

**Expected at end of Day 1–2:**
- Collector task runs without errors
- Bundles appear on the share every 24 hours (for Daily-Light) and at the start of the month (Monthly-Full)
- At least one bundle is ready for the agent

### Day 3: Agent on Separate VM

**Goal**: Deploy the agent to a separate Windows or Linux VM, validate bundle reading, and test dry-run alerts.

#### 1. Clone the repo onto the agent host

```bash
# On the agent VM (not the collector host):
git clone https://github.com/your-org/forrest-gump.git ~/forrest-gump
cd ~/forrest-gump/agent
```

#### 2. Install dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\Activate on Windows
pip install -e ".[dev,llm,graph]"
```

#### 3. Mount or access the test share

```bash
# Linux/WSL: mount the share
sudo mount -t cifs "//fileserver/ADHealth$" /mnt/adhealth -o username=your-domain-account,password=your-password

# Windows: map a drive or UNC path
net use Z: "\\fileserver\ADHealth$" /user:your-domain-account your-password
```

#### 4. Set up config (dry-run mode)

```bash
cp agent/config/settings.example.yaml agent/config/settings.yaml
```

Edit `settings.yaml`:

```yaml
inbox: "/mnt/adhealth/test-inbox"  # or Z:\test-inbox on Windows
state_db: "../state/adhealth.test.sqlite"
dry_run: true                       # MUST be true for pilot
llm:
  provider: none                    # No Bedrock yet; use template fallback
  mode: agent
  max_tokens: 4096

teams:
  urgent_webhook_env: DUMMY_URL     # Not sent in dry-run, but required in config
  digest_webhook_env: DUMMY_URL

sharepoint:
  enabled: false
```

#### 5. Validate and process bundles

```bash
# List bundles on the share:
adhealth-agent validate /mnt/adhealth/test-inbox/ADForestHealth_test.contoso_<stamp>

# Process (generate dry-run alerts):
adhealth-agent process -c agent/config/settings.yaml --verbose

# Check outbox:
ls agent/outbox/
# Should show urgent_*.json, findings.csv, etc.
```

#### 6. Review dry-run payloads

```bash
cat agent/outbox/urgent_*.json | head -50
# Inspect Adaptive Card structure, finding IDs, severity levels
```

**Expected at end of Day 3:**
- Agent reads bundles from the test share without errors
- At least one finding is triaged as urgent/warning
- Dry-run payloads exist in `outbox/`
- Exit code 0

### Day 4 (Optional): Bedrock Integration

**Goal**: If your Bedrock and Roles Anywhere are set up, test the agent with model-generated prose.

#### 1. Set up AWS credentials (Roles Anywhere)

```bash
# On the agent VM, install aws-signing-helper and configure credential_process:
# (See your AWS docs for Roles Anywhere cert setup)
# Validate:
aws sts get-caller-identity --profile adhealth-role-anywhere
```

#### 2. Update config with Bedrock model

```yaml
llm:
  provider: bedrock
  model_id: "anthropic.claude-3-5-sonnet-20241022-v2:0"  # approved by your platform team
  bedrock_region: us-east-1
  bedrock_endpoint_url: ""  # or your PrivateLink endpoint
  mode: agent
```

#### 3. Run preflight checks

```bash
adhealth-agent doctor -c agent/config/settings.yaml --online --probe-model
# Should report OK for all checks
```

#### 4. Qualify the model (optional, but recommended)

```bash
# If you have 2 bundles available:
adhealth-agent qualify -c agent/config/settings.yaml \
  -b /mnt/adhealth/test-inbox/bundle1 \
  -b /mnt/adhealth/test-inbox/bundle2 \
  --runs 3 \
  --out qualification/
# Reports pass/fail and evidence (exit 0 = pass, 2 = fail)
```

#### 5. Process with Bedrock (still dry-run)

```bash
# Still in dry-run; payloads go to outbox, not Teams:
adhealth-agent process -c agent/config/settings.yaml --verbose
# Check outbox for narrative prose generated by Bedrock
```

#### 6. Flip to live (optional, requires approval)

```yaml
# Only after reviewing outbox and gaining approval:
dry_run: false
teams:
  urgent_webhook_env: ADHEALTH_TEAMS_URGENT_WEBHOOK  # set as env var
  digest_webhook_env: ADHEALTH_TEAMS_DIGEST_WEBHOOK

sharepoint:
  enabled: false  # or true if SharePoint is ready
```

**Expected at end of Day 4:**
- Model-generated prose is coherent and relates to findings
- Dry-run alerts are reviewed by security/identity team
- Ready to flip `dry_run: false` with approval

### Checklist: Test Environment Ready

- [ ] Collector runs daily on test forest (tasks exist, exit code 0 or 3)
- [ ] Bundles appear on test share (manifest.json + JSON + CSV + HTML)
- [ ] Agent reads bundles without errors (no SHA-256 mismatch, no schema errors)
- [ ] At least 1 urgent or warning finding is triaged
- [ ] Dry-run payloads reviewed by identity team
- [ ] (Optional) Bedrock model qualified with pass-rate ≥90%
- [ ] Custom rules file created locally (`agent/config/custom_rules.yaml`, not committed)
- [ ] Team is trained on finding IDs, suppression workflow, and reading the HTML report

### Transition to Production

Once the test environment is stable (2–3 weeks of data):

1. **Create production share** and gMSA accounts
2. **Schedule production collector** with signing certificate (§3a)
3. **Move agent to production VM** with Bedrock access
4. **Turn off dry-run** (`dry_run: false`) and set webhook URLs as machine environment variables
5. **Schedule production agent tasks** (process hourly, digest monthly)
6. **Configure monitoring** (alert if `heartbeat_process.json` is older than 3 hours)

---

## 5. Operating it

**Monitoring the monitor:** each `process`/`digest` run writes `state/heartbeat_<command>.json` (`finishedUtc`, `exitCode`, `status`). Alert in SCOM/CloudWatch/Zabbix if `heartbeat_process.json` is older than 3 hours or `status` isn't `ok`. Use `--log-format json` to ship logs to your SIEM; every line carries a `runId`.

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
| Agent: narrative `source=deterministic` with warnings | Bedrock call failed (AccessDenied / model not enabled / wrong region / guardrail intervened) or the output was rejected by the faithfulness guard | See the log warnings. Check the IAM policy resources match the exact profile ARN and **its underlying foundation-model ARNs**. The digest is still correct (template) |
| Agent exits 1: `llm.model_id is required` / `llm.provider must be bedrock or none` | Config is off the golden path | Set the approved Bedrock model ID and region, or `provider: none` |
| `REJECTED ... untrusted certificate` | Collector signed with a certificate that isn't pinned (rotation, or a rogue signer) | If it's a planned rotation, add the thumbprint. Otherwise treat it as a security event |
| `REJECTED ... signature is INVALID` | The manifest changed after signing | Security event: someone edited the bundle on the share or in transit |
| Collector exit `1`: `Signing requested but unavailable` | Certificate missing or expired, or the gMSA can't read the private key | Fix the certificate or its private-key ACL. Nothing was published (fail closed) |
| `qualify` verdict FAIL | The model doesn't reliably follow the digest contract | Read `failureReasons` and the rejected example. Try `single_shot` mode, another model, or keep the current model |
| No digest | No *full* run in history (only light runs) | Check that the monthly task ran without `-Skip*` switches |

## 7. Rollback / backout

| Component | Backout |
|---|---|
| Scheduled tasks | `Unregister-ScheduledTask -TaskPath '\ADHealth\' -TaskName 'ADHealth-Monthly-Full','ADHealth-Daily-Light','ADHealth-Agent-Process','ADHealth-Agent-Digest' -Confirm` |
| gMSA rights | Remove it from Event Log Readers / Remote Management Users. Delete the gMSA if you are decommissioning |
| Agent | Stop the schedule. Delete `state/`, `outbox/` and `qualification/` (they contain directory data) |
| Signing | Set `integrity.require_signature: false`, re-register the collector task without `-SigningCertificateThumbprint`, then revoke the certificate |
| Teams | Turn off or delete the two Workflows (this invalidates the URLs) |
| SharePoint | Remove the Sites.Selected grant, then delete the app registration |
| Report data | Apply the retention policy, or purge the share and the SPO library folder |
