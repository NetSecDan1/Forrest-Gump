"""Deterministic triage: score, month-over-month diff, suppressions, urgent rules.

Everything that decides *whether someone gets paged* lives here, in plain testable code - not in the LLM.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from .config import Policy, Suppression
from .history import StoredReport
from .models import SEVERITY_ORDER, Finding, Report

# Keep in sync with collector/ADHealth.Report.ps1 :: Get-ADHealthScore
SEVERITY_WEIGHT = {"Critical": 20, "High": 8, "Medium": 3, "Low": 1, "Info": 0}
SCORE_PER_CHECK_CAP = 25

# Metrics where an increase is bad (used to label trend direction).
BAD_WHEN_UP = {
    "dcUnreachable", "maxTimeSkewSeconds", "replicationLinksFailing", "maxReplicationLagHours", "replicationFailureRecords",
    "oldestBackupDays", "dcdiagFailedTests", "criticalEventCount", "krbtgtMaxAgeDays", "privilegedMemberships",
    "privilegedAccountsUnique", "staleUsers", "staleComputers", "passwordNeverExpires", "passwordNotRequired", "asRepRoastable",
    "kerberoastableUsers", "unconstrainedDelegation", "protocolTransitionDelegation", "reversibleEncryption", "desOnly",
    "sidHistory", "legacyOsActive", "windows10Active", "lapsMissing",
}


def health_score(findings: list[Finding]) -> int:
    per_check: dict[str, int] = {}
    for f in findings:
        per_check[f.checkId] = per_check.get(f.checkId, 0) + SEVERITY_WEIGHT[f.severity]
    penalty = sum(min(SCORE_PER_CHECK_CAP, v) for v in per_check.values())
    return max(0, 100 - penalty)


@dataclass
class Delta:
    new: list[Finding] = field(default_factory=list)
    escalated: list[Finding] = field(default_factory=list)
    persisting: list[Finding] = field(default_factory=list)
    resolved: list[dict] = field(default_factory=list)  # rows from history
    baseline_report_id: str | None = None


@dataclass
class UrgentItem:
    key: str  # stable throttle key
    reason: str
    severity: str
    finding: Finding | None = None


@dataclass
class MetricTrend:
    metric: str
    previous: float | None
    current: float
    change: float | None
    direction: str  # improved | worsened | unchanged | new


@dataclass
class TriageResult:
    report: Report
    score: int
    score_previous: int | None
    active: list[Finding]
    suppressed: list[tuple[Finding, Suppression]]
    expired_suppressions: list[Suppression]
    delta: Delta
    urgent: list[UrgentItem]
    trends: list[MetricTrend]

    @property
    def counts(self) -> dict[str, int]:
        c = {k: 0 for k in SEVERITY_ORDER}
        for f in self.active:
            c[f.severity] += 1
        return c


def apply_suppressions(findings: list[Finding], sups: list[Suppression], today) -> tuple[list[Finding], list, list[Suppression]]:
    active, suppressed, expired = [], [], []
    by_id = {s.id.lower(): s for s in sups}
    for s in sups:
        if s.expires < today:
            expired.append(s)
    for f in findings:
        s = by_id.get(f.id.lower())
        # Critical findings can never be suppressed - accepted risk stops at High.
        if s and s.expires >= today and f.severity != "Critical":
            suppressed.append((f, s))
        else:
            active.append(f)
    return active, suppressed, expired


def diff(active: list[Finding], previous: StoredReport | None) -> Delta:
    d = Delta(baseline_report_id=previous.report_id if previous else None)
    if previous is None:
        d.new = list(active)
        return d
    prev_map = {k.lower(): v for k, v in previous.findings.items()}
    cur_ids = set()
    for f in active:
        fid = f.id.lower()
        cur_ids.add(fid)
        prev = prev_map.get(fid)
        if prev is None:
            d.new.append(f)
        elif SEVERITY_ORDER[f.severity] < SEVERITY_ORDER[prev["severity"]]:
            d.escalated.append(f)
        else:
            d.persisting.append(f)
    d.resolved = [row for fid, row in prev_map.items() if fid not in cur_ids]
    return d


def trends(report: Report, previous: StoredReport | None) -> list[MetricTrend]:
    out = []
    for m, cur in sorted(report.metrics.items()):
        prev = previous.metrics.get(m) if previous else None
        if prev is None:
            out.append(MetricTrend(m, None, cur, None, "new"))
            continue
        ch = round(cur - prev, 2)
        if ch == 0:
            direction = "unchanged"
        elif m in BAD_WHEN_UP:
            direction = "worsened" if ch > 0 else "improved"
        else:
            direction = "changed"
        out.append(MetricTrend(m, prev, cur, ch, direction))
    return out


def urgent_items(report: Report, active: list[Finding], delta: Delta, policy: Policy, score: int,
                 score_previous: int | None) -> list[UrgentItem]:
    items: list[UrgentItem] = []
    new_or_escalated = {f.id for f in delta.new + delta.escalated}
    for f in active:
        if f.severity in policy.urgent_severities:
            items.append(UrgentItem(key=f"finding:{f.id.lower()}", reason=f"{f.severity} finding", severity=f.severity, finding=f))
        elif f.severity == "High" and f.category in policy.high_categories_if_new and f.id in new_or_escalated:
            items.append(UrgentItem(key=f"finding:{f.id.lower()}", reason=f"New/escalated High in {f.category}", severity="High", finding=f))
    if report.summary.checkCoveragePercent < policy.min_coverage_percent:
        items.append(UrgentItem(key="coverage", severity="High",
                                reason=f"Check coverage {report.summary.checkCoveragePercent:.0f}% below {policy.min_coverage_percent:.0f}% - large blind spots"))
    if score_previous is not None and score_previous - score >= policy.score_drop_points:
        items.append(UrgentItem(key="score-drop", severity="High", reason=f"Health score dropped {score_previous} -> {score}"))
    items.sort(key=lambda i: (SEVERITY_ORDER.get(i.severity, 9), i.key))
    return items


def stale_collector_item(latest: StoredReport | None, forest: str, policy: Policy, now: datetime) -> UrgentItem | None:
    """Silence is a signal: no report for too long means we are blind, not healthy."""
    if latest is None:
        return None
    age = (now - latest.generated_utc).total_seconds() / 86400
    if age > policy.max_report_age_days:
        return UrgentItem(key="collector-stale", severity="High",
                          reason=f"No AD health report for {forest} in {age:.0f} days (limit {policy.max_report_age_days}) - collector may be broken")
    return None


def triage(report: Report, previous: StoredReport | None, policy: Policy, now: datetime | None = None) -> TriageResult:
    now = now or datetime.now(timezone.utc)
    active, suppressed, expired = apply_suppressions(report.findings, policy.suppressions, now.date())
    score = health_score(report.findings)  # score is computed on ALL findings: suppression hides noise, not risk
    score_prev = previous.score if previous else None
    delta = diff(active, previous)
    return TriageResult(
        report=report, score=score, score_previous=score_prev, active=active, suppressed=suppressed,
        expired_suppressions=expired, delta=delta, urgent=urgent_items(report, active, delta, policy, score, score_prev),
        trends=trends(report, previous),
    )
