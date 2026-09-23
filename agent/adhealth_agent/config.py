"""Configuration loading. Secrets are NEVER read from YAML - only the *names* of environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

import yaml


@dataclass
class LlmConfig:
    provider: str = "none"  # anthropic | bedrock | none
    model_id: str = "claude-opus-5"
    max_tokens: int = 16000
    server_side_fallbacks: bool = True  # Anthropic API only
    bedrock_region: str = ""
    include_names: bool = False  # account names never leave the boundary unless explicitly enabled


@dataclass
class TeamsConfig:
    urgent_webhook_env: str = "ADHEALTH_TEAMS_URGENT_WEBHOOK"
    digest_webhook_env: str = "ADHEALTH_TEAMS_DIGEST_WEBHOOK"
    report_link_base: str = ""


@dataclass
class SharePointConfig:
    enabled: bool = False
    tenant_id_env: str = "ADHEALTH_GRAPH_TENANT_ID"
    client_id_env: str = "ADHEALTH_GRAPH_CLIENT_ID"
    client_secret_env: str = "ADHEALTH_GRAPH_CLIENT_SECRET"
    cert_path_env: str = "ADHEALTH_GRAPH_CERT_PATH"
    cert_thumbprint_env: str = "ADHEALTH_GRAPH_CERT_THUMBPRINT"
    site_id: str = ""
    folder: str = "ADHealth"


@dataclass
class Suppression:
    id: str
    reason: str
    owner: str
    expires: date


@dataclass
class Policy:
    urgent_severities: list[str] = field(default_factory=lambda: ["Critical"])
    high_categories_if_new: list[str] = field(
        default_factory=lambda: ["Replication", "DCHealth", "SYSVOL", "Backup", "FSMO", "Time", "DNS", "Collector"]
    )
    min_coverage_percent: float = 80.0
    max_report_age_days: int = 35
    score_drop_points: int = 15
    realert_after_days: int = 7
    suppressions: list[Suppression] = field(default_factory=list)


@dataclass
class Settings:
    inbox: Path
    state_db: Path
    outbox: Path
    dry_run: bool = True
    max_file_bytes: int = 50 * 1024 * 1024
    llm: LlmConfig = field(default_factory=LlmConfig)
    teams: TeamsConfig = field(default_factory=TeamsConfig)
    sharepoint: SharePointConfig = field(default_factory=SharePointConfig)
    policy: Policy = field(default_factory=Policy)


def _sub(cls, data: dict[str, Any] | None):
    data = data or {}
    known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
    unknown = set(data) - set(known)
    if unknown:
        raise ValueError(f"Unknown {cls.__name__} keys: {sorted(unknown)}")
    return cls(**known)


def load_policy(path: Path) -> Policy:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    urgent = raw.get("urgent") or {}
    sups = []
    for s in raw.get("suppressions") or []:
        exp = s["expires"]
        sups.append(Suppression(id=str(s["id"]).lower(), reason=s["reason"], owner=s["owner"],
                                expires=exp if isinstance(exp, date) else date.fromisoformat(str(exp))))
    p = _sub(Policy, urgent)
    p.suppressions = sups
    return p


def load_settings(path: str | os.PathLike) -> Settings:
    path = Path(path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    base = path.parent

    def rel(p: str) -> Path:
        q = Path(os.path.expandvars(p))
        return q if q.is_absolute() or str(p).startswith("\\\\") else (base / q).resolve()

    policy = Policy()
    if raw.get("policy_file"):
        policy = load_policy(rel(raw["policy_file"]))
    return Settings(
        inbox=rel(raw["inbox"]),
        state_db=rel(raw.get("state_db", "state/adhealth.sqlite")),
        outbox=rel(raw.get("outbox", "outbox")),
        dry_run=bool(raw.get("dry_run", True)),
        max_file_bytes=int(raw.get("max_file_bytes", 50 * 1024 * 1024)),
        llm=_sub(LlmConfig, raw.get("llm")),
        teams=_sub(TeamsConfig, raw.get("teams")),
        sharepoint=_sub(SharePointConfig, raw.get("sharepoint")),
        policy=policy,
    )


def env_secret(name: str) -> str | None:
    v = os.environ.get(name)
    return v.strip() if v else None
