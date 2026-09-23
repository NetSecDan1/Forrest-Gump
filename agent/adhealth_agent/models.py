"""Pydantic models for report.json (collector schema 1.x).

Models are tolerant of additive changes (extra="allow") so a newer collector minor version does not
break the agent; a new schema MAJOR version is rejected in ingest.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Severity = Literal["Critical", "High", "Medium", "Low", "Info"]
SEVERITY_ORDER: dict[str, int] = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def _as_list(v: Any) -> list:
    """PowerShell 5.1 can serialize one-element arrays as scalars; normalize."""
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


class _Tolerant(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)


class Finding(_Tolerant):
    id: str
    checkId: str
    category: str
    severity: Severity
    title: str
    target: str = "forest"
    count: int = 1
    detail: str = ""
    recommendation: str = ""
    evidenceRef: str = ""
    sample: list[str] = Field(default_factory=list)

    @field_validator("sample", mode="before")
    @classmethod
    def _sample_list(cls, v: Any) -> list:
        return [str(x) for x in _as_list(v)]

    @field_validator("detail", "recommendation", "evidenceRef", "target", mode="before")
    @classmethod
    def _none_to_empty(cls, v: Any) -> Any:
        return "" if v is None else v


class Check(_Tolerant):
    id: str
    category: str
    name: str
    status: Literal["Pass", "Warn", "Fail", "Partial", "Error", "Skipped"]
    summary: str = ""
    findingCount: int = 0
    durationMs: int = 0
    command: str = ""

    @field_validator("summary", "command", mode="before")
    @classmethod
    def _none_to_empty(cls, v: Any) -> Any:
        return "" if v is None else v


class Summary(_Tolerant):
    overallStatus: Literal["Red", "Amber", "Green"]
    healthScore: int
    checkCoveragePercent: float
    collectionErrorCount: int = 0
    domainControllerCount: int = 0
    domainCount: int = 0
    checkCount: int = 0
    scoped: bool = False


class Forest(_Tolerant):
    name: str
    rootDomain: str = ""
    forestMode: str = ""


class Report(_Tolerant):
    schemaVersion: str
    reportType: Literal["ADForestHealth"]
    reportId: str
    generatedUtc: datetime
    collector: dict[str, Any] = Field(default_factory=dict)
    summary: Summary
    forest: Forest
    domains: list[dict[str, Any]] = Field(default_factory=list)
    domainControllers: list[dict[str, Any]] = Field(default_factory=list)
    metrics: dict[str, float] = Field(default_factory=dict)
    checks: list[Check] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    errors: list[dict[str, Any]] = Field(default_factory=list)

    @field_validator("domains", "domainControllers", "checks", "findings", "errors", mode="before")
    @classmethod
    def _lists(cls, v: Any) -> list:
        return _as_list(v)

    @field_validator("metrics", mode="before")
    @classmethod
    def _metrics(cls, v: Any) -> dict:
        if not v:
            return {}
        return {k: float(x) for k, x in dict(v).items() if isinstance(x, (int, float))}

    @property
    def is_full_run(self) -> bool:
        """A 'full' run is unscoped and ran every check family. Only full runs are trend baselines."""
        p = self.collector.get("parameters") or {}
        skipped = any(bool(p.get(k)) for k in ("SkipDcDiag", "SkipEventLogs", "SkipRemoteCim", "SkipHygiene"))
        return not self.summary.scoped and not skipped
