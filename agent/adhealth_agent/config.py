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
    # Golden path: Claude on Amazon Bedrock through Strands. No other provider exists.
    provider: str = "bedrock"  # bedrock | none
    model_id: str = ""  # REQUIRED for bedrock: your approved model id / inference profile id / ARN - no default on purpose
    max_tokens: int = 16000
    bedrock_region: str = ""  # REQUIRED for bedrock: approved region (no silent fallback to Strands' default)
    bedrock_endpoint_url: str = ""  # PrivateLink/VPC endpoint URL if your golden path mandates it
    bedrock_guardrail_id: str = ""  # Bedrock Guardrail id, if mandated
    bedrock_guardrail_version: str = ""
    include_names: bool = False  # account names never leave the boundary unless explicitly enabled

    def validate(self) -> None:
        if self.provider not in ("bedrock", "none"):
            raise ValueError(f"llm.provider must be bedrock or none (got {self.provider!r})")
        if self.provider == "bedrock":
            if not self.model_id:
                raise ValueError("llm.model_id is required for bedrock (approved model/inference-profile id or ARN). "
                                 "Refusing to fall back to the Strands default model, which may be a cross-region profile.")
            if self.model_id.startswith("claude-"):
                raise ValueError(f"llm.model_id {self.model_id!r} is not a Bedrock model id; Bedrock needs a Bedrock "
                                 "model id, inference profile id or ARN (e.g. the one your platform team publishes).")
            if not self.bedrock_region and not self.model_id.startswith("arn:"):
                raise ValueError("llm.bedrock_region is required for bedrock so requests stay in the approved region.")
            if bool(self.bedrock_guardrail_id) != bool(self.bedrock_guardrail_version):
                raise ValueError("Set both llm.bedrock_guardrail_id and llm.bedrock_guardrail_version, or neither.")


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

    llm = _sub(LlmConfig, raw.get("llm"))
    llm.validate()
    policy = Policy()
    if raw.get("policy_file"):
        policy = load_policy(rel(raw["policy_file"]))
    return Settings(
        inbox=rel(raw["inbox"]),
        state_db=rel(raw.get("state_db", "state/adhealth.sqlite")),
        outbox=rel(raw.get("outbox", "outbox")),
        dry_run=bool(raw.get("dry_run", True)),
        max_file_bytes=int(raw.get("max_file_bytes", 50 * 1024 * 1024)),
        llm=llm,
        teams=_sub(TeamsConfig, raw.get("teams")),
        sharepoint=_sub(SharePointConfig, raw.get("sharepoint")),
        policy=policy,
    )


def env_secret(name: str) -> str | None:
    v = os.environ.get(name)
    return v.strip() if v else None
