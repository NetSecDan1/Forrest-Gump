from datetime import date, datetime, timezone

from adhealth_agent.config import Policy, Suppression
from adhealth_agent.history import StoredReport
from adhealth_agent.ingest import open_bundle
from adhealth_agent.models import Finding
from adhealth_agent.triage import health_score, stale_collector_item, triage

MAX = 50 * 1024 * 1024
NOW = datetime(2026, 9, 2, tzinfo=timezone.utc)


def _prev(findings: dict[str, str], score: int = 90) -> StoredReport:
    return StoredReport(
        report_id="prev", forest="contoso.test", generated_utc=datetime(2026, 8, 1, tzinfo=timezone.utc), status="Amber",
        score=score, coverage=100, is_full=True, metrics={"staleUsers": 5.0, "krbtgtMaxAgeDays": 870.0}, bundle_path="x",
        findings={fid: {"finding_id": fid, "check_id": fid.split("|")[0], "severity": sev, "title": f"t {fid}"} for fid, sev in findings.items()},
    )


def test_score_matches_collector(sample_bundle):
    """Python and PowerShell scoring must agree (collector/ADHealth.Report.ps1 :: Get-ADHealthScore)."""
    r = open_bundle(sample_bundle, MAX).report
    assert health_score(r.findings) == r.summary.healthScore


def test_score_per_check_cap():
    many = [Finding(id=f"EVT-001|dc{i}", checkId="EVT-001", category="EventLogs", severity="Critical", title="x") for i in range(10)]
    assert health_score(many) == 75  # one noisy check is capped at 25 points


def test_no_baseline_everything_new(sample_bundle):
    r = open_bundle(sample_bundle, MAX).report
    t = triage(r, None, Policy(), NOW)
    assert len(t.delta.new) == len(r.findings)
    assert t.delta.baseline_report_id is None
    assert any(u.severity == "Critical" for u in t.urgent)


def test_diff_new_escalated_resolved(sample_bundle):
    r = open_bundle(sample_bundle, MAX).report
    krb = next(f for f in r.findings if f.checkId == "KRB-001")          # High now
    tsl = next(f for f in r.findings if f.checkId == "TIME-001")
    prev = _prev({krb.id: "Medium", tsl.id: "High", "HYG-999|gone": "Low"})
    t = triage(r, prev, Policy(), NOW)
    assert krb in t.delta.escalated
    assert tsl in t.delta.persisting
    assert [x["finding_id"] for x in t.delta.resolved] == ["HYG-999|gone"]
    trend = {m.metric: m for m in t.trends}
    assert trend["krbtgtMaxAgeDays"].direction == "worsened"
    assert trend["staleUsers"].direction == "improved"


def test_new_high_in_watched_category_is_urgent_but_persisting_is_not(sample_bundle):
    r = open_bundle(sample_bundle, MAX).report
    time_high = next(f for f in r.findings if f.checkId == "TIME-001")
    everything_else = {f.id: f.severity for f in r.findings if f.id != time_high.id}
    t = triage(r, _prev(everything_else), Policy(), NOW)
    keys = {u.key for u in t.urgent}
    assert f"finding:{time_high.id.lower()}" in keys
    # persisting High in a watched category (DC-003 unsupported OS) is not re-paged as "new"
    dc003 = next(f for f in r.findings if f.checkId == "DC-003" and f.severity == "High")
    assert f"finding:{dc003.id.lower()}" not in keys


def test_coverage_and_score_drop_rules(sample_bundle):
    r = open_bundle(sample_bundle, MAX).report
    r.summary.checkCoveragePercent = 50
    t = triage(r, _prev({}, score=95), Policy(), NOW)
    keys = {u.key for u in t.urgent}
    assert {"coverage", "score-drop"} <= keys


def test_suppression_cannot_hide_critical_and_expiry_is_reported(sample_bundle):
    r = open_bundle(sample_bundle, MAX).report
    crit = next(f for f in r.findings if f.severity == "Critical")
    med = next(f for f in r.findings if f.severity == "Medium")
    pol = Policy(suppressions=[
        Suppression(crit.id.lower(), "nope", "me", date(2027, 1, 1)),
        Suppression(med.id.lower(), "accepted", "me", date(2027, 1, 1)),
        Suppression("hyg-001|old", "expired", "me", date(2026, 1, 1)),
    ])
    t = triage(r, None, pol, NOW)
    assert crit in t.active
    assert med not in t.active and any(f is med for f, _ in t.suppressed)
    assert [s.id for s in t.expired_suppressions] == ["hyg-001|old"]
    assert t.score == health_score(r.findings)  # suppression hides noise, not risk


def test_stale_collector():
    latest = _prev({})
    assert stale_collector_item(latest, "contoso.test", Policy(max_report_age_days=35), datetime(2026, 9, 1, tzinfo=timezone.utc)) is None
    item = stale_collector_item(latest, "contoso.test", Policy(max_report_age_days=35), datetime(2026, 10, 1, tzinfo=timezone.utc))
    assert item and item.key == "collector-stale"
