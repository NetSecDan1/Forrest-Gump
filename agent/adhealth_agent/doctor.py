"""Preflight checks for the agent host. Read-only except for a throwaway write probe in state/ and outbox/.

Offline by default. ``--online`` adds an STS identity call; ``--probe-model`` adds one minimal model request
(costs a few tokens) to prove IAM, region, endpoint, guardrail and model access end to end.
"""

from __future__ import annotations

import importlib.util
import os
import uuid
from dataclasses import dataclass
from pathlib import Path

from .config import Settings, env_secret


@dataclass
class Check:
    name: str
    status: str  # PASS | WARN | FAIL | SKIP
    detail: str = ""


def _writable(d: Path) -> tuple[bool, str]:
    try:
        d.mkdir(parents=True, exist_ok=True)
        probe = d / f".probe-{uuid.uuid4().hex[:8]}"
        probe.write_text("x", encoding="utf-8")
        probe.unlink()
        return True, str(d)
    except OSError as e:
        return False, f"{d}: {e.strerror or type(e).__name__}"


def run_doctor(s: Settings, online: bool = False, probe_model: bool = False) -> list[Check]:
    out: list[Check] = [Check("config", "PASS", "settings, policy, llm and integrity validated")]

    if s.inbox.is_dir() and os.access(s.inbox, os.R_OK):
        n = sum(1 for p in s.inbox.iterdir() if p.is_dir() and (p / "manifest.json").is_file())
        out.append(Check("inbox readable", "PASS", f"{s.inbox} ({n} bundle(s))"))
    else:
        out.append(Check("inbox readable", "FAIL", f"{s.inbox} not found or not readable by this identity"))
    for label, d in (("state writable", s.state_db.parent), ("outbox writable", s.outbox)):
        ok, detail = _writable(d)
        out.append(Check(label, "PASS" if ok else "FAIL", detail))

    out.append(Check("dry_run", "WARN" if s.dry_run else "PASS",
                     "dry_run=true: nothing is delivered (payloads go to outbox)" if s.dry_run else "delivery enabled"))
    for label, env in (("Teams urgent webhook", s.teams.urgent_webhook_env), ("Teams digest webhook", s.teams.digest_webhook_env)):
        present = bool(env_secret(env))
        out.append(Check(label, "PASS" if present else ("WARN" if s.dry_run else "FAIL"),
                         f"${env} {'set' if present else 'NOT set'}"))  # never print the value
    if s.sharepoint.enabled:
        missing = [e for e in (s.sharepoint.tenant_id_env, s.sharepoint.client_id_env) if not env_secret(e)]
        cred = (env_secret(s.sharepoint.cert_path_env) and env_secret(s.sharepoint.cert_thumbprint_env)) or env_secret(s.sharepoint.client_secret_env)
        ok = not missing and cred and s.sharepoint.site_id and importlib.util.find_spec("msal")
        out.append(Check("SharePoint (Graph)", "PASS" if ok else "FAIL",
                         "configured" if ok else f"missing: {missing or ''} {'credential ' if not cred else ''}{'site_id ' if not s.sharepoint.site_id else ''}"
                         f"{'msal' if not importlib.util.find_spec('msal') else ''}".strip()))
    else:
        out.append(Check("SharePoint (Graph)", "SKIP", "sharepoint.enabled=false"))

    if s.integrity.require_signature:
        out.append(Check("bundle signatures", "PASS", f"required; {len(s.integrity.trusted_signer_thumbprints)} pinned signer(s)"))
    else:
        out.append(Check("bundle signatures", "WARN", "not required - enable integrity.require_signature once the collector signs"))

    if s.llm.provider == "none":
        out.append(Check("LLM", "SKIP", "provider=none (template narrative)"))
        return out
    missing_mods = [m for m in ("strands", "boto3") if importlib.util.find_spec(m) is None]
    if missing_mods:
        out.append(Check("LLM libraries", "FAIL", f"missing {missing_mods}: pip install 'adhealth-agent[llm]'"))
        return out
    out.append(Check("LLM config", "PASS", f"{s.llm.provider} model={s.llm.model_id} mode={s.llm.mode} region={s.llm.bedrock_region or '(from ARN)'}"
                     + (f" guardrail={s.llm.bedrock_guardrail_id}" if s.llm.bedrock_guardrail_id else "")
                     + (f" endpoint={s.llm.bedrock_endpoint_url}" if s.llm.bedrock_endpoint_url else "")))
    import boto3

    session = boto3.Session(region_name=s.llm.bedrock_region or None)
    creds = session.get_credentials()
    if creds is None:
        out.append(Check("AWS credentials", "FAIL", "no credentials in the default chain (expected Roles Anywhere profile or task role)"))
        return out
    out.append(Check("AWS credentials", "PASS", f"source={getattr(creds, 'method', 'unknown')} profile={os.environ.get('AWS_PROFILE', 'default')}"))
    if online:
        try:
            ident = session.client("sts").get_caller_identity()
            out.append(Check("AWS identity (STS)", "PASS", ident.get("Arn", "")))
        except Exception as e:  # noqa: BLE001
            out.append(Check("AWS identity (STS)", "FAIL", type(e).__name__))
    if probe_model:
        try:
            from strands import Agent

            from .llm import build_model

            reply = str(Agent(model=build_model(s.llm), callback_handler=None)("Reply with the single word OK.")).strip()
            out.append(Check("model probe", "PASS", f"model answered ({len(reply)} chars)"))
        except Exception as e:  # noqa: BLE001
            out.append(Check("model probe", "FAIL", f"{type(e).__name__}: {str(e)[:160]}"))
    return out
