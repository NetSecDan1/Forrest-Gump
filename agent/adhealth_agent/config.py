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
    """Model-agnostic: Strands is the framework, the model is configuration. Approved provider: bedrock."""
    provider: str = "bedrock"  # bedrock | none   (registered providers live in llm.py)
    model_id: str = ""  # REQUIRED: approved Bedrock model id / inference profile id / ARN (any vendor) - no default
    mode: str = "agent"  # agent: model explores read-only tools | single_shot: data inlined, for models without tool use
    max_tokens: int = 4096
    temperature: float | None = None  # None = provider default
    request_timeout_seconds: int = 120
    max_attempts: int = 3  # botocore adaptive retries (throttling)
    bedrock_region: str = ""  # REQUIRED for bedrock (unless model_id is an ARN): no silent default region
    bedrock_endpoint_url: str = ""  # PrivateLink/VPC endpoint URL if your golden path mandates it
    bedrock_guardrail_id: str = ""  # Bedrock Guardrail id, if mandated
    bedrock_guardrail_version: str = ""
    max_findings_in_prompt: int = 150  # single_shot: cap on inlined findings (most severe first)
    include_names: bool = False  # account names never leave the boundary unless explicitly enabled

    def validate(self) -> None:
        if self.provider not in ("bedrock", "none"):
            raise ValueError(f"llm.provider must be bedrock or none (got {self.provider!r})")
        if self.mode not in ("agent", "single_shot"):
            raise ValueError(f"llm.mode must be agent or single_shot (got {self.mode!r})")
        if self.provider == "none":
            return
        if not self.model_id:
            raise ValueError("llm.model_id is required (approved model/inference-profile id or ARN). "
                             "Refusing to fall back to a framework default model, which may be a cross-region profile.")
        # Bedrock ids are '<vendor>.<model>', '<geo>.<vendor>.<model>' or an ARN - vendor-neutral check.
        if not (self.model_id.startswith("arn:") or "." in self.model_id):
            raise ValueError(f"llm.model_id {self.model_id!r} is not a Bedrock model id; use '<vendor>.<model>', an "
                             "inference profile id or an ARN, as published by your platform team.")
        if not self.bedrock_region and not self.model_id.startswith("arn:"):
            raise ValueError("llm.bedrock_region is required for bedrock so requests stay in the approved region.")
        if bool(self.bedrock_guardrail_id) != bool(self.bedrock_guardrail_version):
            raise ValueError("Set both llm.bedrock_guardrail_id and llm.bedrock_guardrail_version, or neither.")
        if not 1 <= self.max_attempts <= 10 or not 10 <= self.request_timeout_seconds <= 900:
            raise ValueError("llm.max_attempts must be 1-10 and llm.request_timeout_seconds 10-900.")


@dataclass
class IntegrityConfig:
    """Bundle authenticity. Hashes alone stop corruption; a pinned signature stops forgery by share writers."""
    require_signature: bool = False  # set true in production once the collector signs
    trusted_signer_thumbprints: list[str] = field(default_factory=list)  # SHA-1 thumbprints as shown in the cert store

    def validate(self) -> None:
        if self.require_signature and not self.trusted_signer_thumbprints:
            raise ValueError("integrity.require_signature is true but integrity.trusted_signer_thumbprints is empty")


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
    integrity: IntegrityConfig = field(default_factory=IntegrityConfig)
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
    integrity = _sub(IntegrityConfig, raw.get("integrity"))
    integrity.validate()
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
        integrity=integrity,
        teams=_sub(TeamsConfig, raw.get("teams")),
        sharepoint=_sub(SharePointConfig, raw.get("sharepoint")),
        policy=policy,
    )


def env_secret(name: str) -> str | None:
    v = os.environ.get(name)
    return v.strip() if v else None
