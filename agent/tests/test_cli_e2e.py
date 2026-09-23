"""End-to-end, dry-run: two monthly bundles -> process -> digest. No network."""

import json

from adhealth_agent.cli import main
from conftest import make_bundle


def _outbox(workdir, pattern):
    return sorted((workdir / "outbox").glob(pattern))


def test_process_then_digest_dry_run(workdir):
    cfg = str(workdir / "config" / "settings.yaml")

    def august(r):  # last month: fewer findings, better score, no replication failure
        r["findings"] = [f for f in r["findings"] if f["checkId"] not in ("REPL-001", "REPL-002", "TIME-001")]
        r["summary"]["healthScore"] = 40
        r["metrics"]["staleUsers"] = 1

    make_bundle(workdir / "inbox", "2026-08-01T02:00:00Z", mutate=august)
    make_bundle(workdir / "inbox", "2026-09-01T02:00:00Z")

    assert main(["process", "-c", cfg]) == 0
    urgent = _outbox(workdir, "*teams_urgent_contoso.test.json")
    assert len(urgent) == 2  # one card per bundle
    texts = [json.dumps(json.loads(p.read_text())) for p in urgent]
    assert sum("REPL-002" in x for x in texts) == 1  # new Critical replication failure in September
    assert sum("DC-001" in x for x in texts) == 1    # August Critical is throttled, not re-paged in September
    assert len(_outbox(workdir, "*sharepoint_contoso.test__2026-09__*report.html")) == 1

    # Idempotent: re-running does not reprocess or re-alert (throttle).
    before = len(_outbox(workdir, "*teams_*"))
    assert main(["process", "-c", cfg]) == 0
    assert len(_outbox(workdir, "*teams_*")) == before

    assert main(["digest", "-c", cfg]) == 0
    digest_cards = _outbox(workdir, "*teams_digest_contoso.test_2026-09.json")
    assert len(digest_cards) == 1
    page = _outbox(workdir, "*sharepoint_contoso.test__digests__2026-09-digest.html")[0].read_text()
    assert "What changed since last month" in page and "REPL-002" in page


def test_rejected_bundle_alerts_and_returns_2(workdir):
    cfg = str(workdir / "config" / "settings.yaml")
    b = make_bundle(workdir / "inbox", "2026-09-01T02:00:00Z")
    (b / "findings.csv").write_text("tampered", encoding="utf-8")
    assert main(["process", "-c", cfg]) == 2
    assert len(_outbox(workdir, "*teams_rejected.json")) == 1


def test_validate_command(sample_bundle, capsys):
    assert main(["validate", str(sample_bundle)]) == 0
    assert '"forest": "contoso.test"' in capsys.readouterr().out
