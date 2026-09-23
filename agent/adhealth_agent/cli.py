"""adhealth-agent command line.

  adhealth-agent validate <bundle_dir>          signature + integrity + schema check, prints summary (no side effects)
  adhealth-agent process  -c settings.yaml      ingest new bundles, store history, archive, urgent Teams alerts
  adhealth-agent digest   -c settings.yaml      monthly narrative digest -> SharePoint page + Teams card
  adhealth-agent qualify  -c settings.yaml -b <bundle> [-b ...]   model qualification evidence (guard pass rate, latency, tokens)
  adhealth-agent doctor   -c settings.yaml [--online] [--probe-model]   preflight checks for the agent host

Exit codes: 0 ok; 2 completed but some bundles were rejected or deliveries failed; 1 fatal.
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

from .config import IntegrityConfig, Settings, env_secret, load_settings
from .doctor import run_doctor
from .history import History
from .ingest import BundleError, discover_bundles, open_bundle, peek_report_id
from .models import Report
from .narrative import StrandsNarrator
from .ops import configure_logging, write_heartbeat
from .qualify import run_qualification, write_evidence
from .publish.sharepoint import SharePointPublisher
from .publish.teams import TeamsPublisher
from .render import digest_html, teams_digest_card, teams_urgent_card
from .triage import UrgentItem, stale_collector_item, triage

log = logging.getLogger("adhealth_agent")


def _archive_dir(s: Settings) -> Path:
    return s.state_db.parent / "archive"


def _report_link(s: Settings, forest: str, month: str, bundle: str, uploaded: str | None) -> str | None:
    if uploaded and uploaded.startswith("http"):
        return uploaded
    if s.teams.report_link_base:
        return f"{s.teams.report_link_base.rstrip('/')}/{forest}/{month}/{bundle}/report.html"
    return None


def _simple_alert(forest: str, items: list[UrgentItem]) -> dict:
    body = [{"type": "TextBlock", "size": "Large", "weight": "Bolder", "color": "attention", "wrap": True, "text": f"AD health pipeline alert: {forest}"}]
    body += [{"type": "TextBlock", "wrap": True, "text": f"**{i.severity}** · {i.reason}"} for i in items]
    card = {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4", "body": body}
    return {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None, "content": card}]}


def cmd_validate(args) -> int:
    path = Path(args.bundle)
    integrity = IntegrityConfig(require_signature=args.require_signature, trusted_signer_thumbprints=args.trusted_thumbprint or [])
    try:
        integrity.validate()
        b = open_bundle(path, args.max_file_bytes, integrity)
    except BundleError as e:
        print(f"INVALID: {e}")
        return 2
    r = b.report
    print(json.dumps({
        "reportId": r.reportId, "forest": r.forest.name, "generatedUtc": r.generatedUtc.isoformat(), "status": r.summary.overallStatus,
        "score": r.summary.healthScore, "coverage": r.summary.checkCoveragePercent, "fullRun": r.is_full_run,
        "findings": len(r.findings), "checks": len(r.checks), "files": len(b.manifest.get("files", [])),
        "signer": b.signer,
    }, indent=2))
    return 0


def cmd_process(args) -> int:
    s = load_settings(args.config)
    hist = History(s.state_db)
    now = datetime.now(timezone.utc)
    teams = TeamsPublisher(env_secret(s.teams.urgent_webhook_env), s.outbox, s.dry_run)
    sp = SharePointPublisher(s.sharepoint, s.outbox, s.dry_run)
    rc = 0
    processed = 0
    for path in discover_bundles(s.inbox):
        rid = peek_report_id(path)
        if rid and hist.has_report(rid):
            continue  # already ingested (and verified) on an earlier run
        try:
            b = open_bundle(path, s.max_file_bytes, s.integrity)
        except BundleError as e:
            rc = 2
            log.error("REJECTED %s: %s", path.name, e)
            key = f"bundle-rejected:{path.name}"
            if hist.should_alert("_pipeline", key, now, s.policy.realert_after_days):
                try:
                    teams.post("rejected", _simple_alert("pipeline", [UrgentItem(key, f"Bundle {path.name} rejected: {e}", "High")]))
                    hist.mark_alerted("_pipeline", [key], now)
                except RuntimeError as post_err:
                    log.error("Rejection alert delivery failed: %s", post_err)
            continue
        r = b.report
        if hist.has_report(r.reportId):
            continue
        forest = r.forest.name.lower()
        prev = hist.previous_full(forest, before=r.generatedUtc)
        t = triage(r, prev, s.policy, now)
        month = r.generatedUtc.strftime("%Y-%m")

        uploaded = None
        try:
            for name in ("report.html", "report.json", "findings.csv"):
                if (path / name).is_file():
                    res = sp.upload(f"{forest}/{month}/{path.name}/{name}", (path / name).read_bytes())
                    if name == "report.html":
                        uploaded = res
        except Exception as e:  # noqa: BLE001 - archive failure must not block alerting
            rc = 2
            log.error("SharePoint archive failed for %s: %s", path.name, e)

        archive = _archive_dir(s)
        archive.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path / "report.json", archive / f"{r.reportId}.json")
        hist.save_report(r, str(archive / f"{r.reportId}.json"))
        processed += 1
        log.info("Processed %s forest=%s status=%s score=%d urgent=%d signer=%s", path.name, forest, r.summary.overallStatus,
                 t.score, len(t.urgent), (b.signer or {}).get("thumbprint", "unsigned"))

        due = [u for u in t.urgent if hist.should_alert(forest, u.key, now, s.policy.realert_after_days)]
        if due:
            try:
                teams.post(f"urgent_{forest}", teams_urgent_card(t, due, _report_link(s, forest, month, path.name, uploaded)))
                hist.mark_alerted(forest, [u.key for u in due], now)
            except RuntimeError as e:
                rc = 2
                log.error("Urgent alert delivery failed: %s", e)

    for forest in hist.forests():
        item = stale_collector_item(hist.latest(forest), forest, s.policy, now)
        if item and hist.should_alert(forest, item.key, now, s.policy.realert_after_days):
            try:
                teams.post(f"stale_{forest}", _simple_alert(forest, [item]))
                hist.mark_alerted(forest, [item.key], now)
            except RuntimeError as e:
                rc = 2
                log.error("Stale-collector alert delivery failed: %s", e)
    log.info("Done: %d new bundle(s) processed", processed)
    hist.close()
    return rc


def _month_bounds(month: str) -> tuple[datetime, datetime]:
    start = datetime.strptime(month, "%Y-%m").replace(tzinfo=timezone.utc)
    end = start.replace(year=start.year + 1, month=1) if start.month == 12 else start.replace(month=start.month + 1)
    return start, end


def cmd_digest(args) -> int:
    s = load_settings(args.config)
    hist = History(s.state_db)
    teams = TeamsPublisher(env_secret(s.teams.digest_webhook_env), s.outbox, s.dry_run)
    sp = SharePointPublisher(s.sharepoint, s.outbox, s.dry_run)
    narrator = StrandsNarrator(s.llm)
    forests = [args.forest.lower()] if args.forest else hist.forests()
    rc = 0
    for forest in forests:
        before = _month_bounds(args.month)[1] if args.month else None
        cur_row = hist.latest(forest, full_only=True, before=before)
        if cur_row is None:
            log.warning("No full report for %s%s; skipping digest", forest, f" in/before {args.month}" if args.month else "")
            rc = 2
            continue
        # Archived copy (<state>/archive/<reportId>.json) was hash-verified at ingest time.
        report = Report.model_validate(json.loads(Path(cur_row.bundle_path).read_text(encoding="utf-8-sig")))
        month = report.generatedUtc.strftime("%Y-%m")
        label = report.generatedUtc.strftime("%B %Y")
        prev = hist.previous_full(forest, before=_month_bounds(month)[0])  # baseline = last full report of an earlier month
        t = triage(report, prev, s.policy)
        nar = narrator.generate(t, label, metric_history=lambda m, f=forest: hist.metric_series(f, m))
        for w in nar.warnings:
            log.warning("Narrative: %s", w)
        page = digest_html(t, nar.markdown, label, nar.source, None)
        try:
            url = sp.upload(f"{forest}/digests/{month}-digest.html", page.encode("utf-8"))
            sp.upload(f"{forest}/digests/{month}-digest.md", nar.markdown.encode("utf-8"))
        except Exception as e:  # noqa: BLE001
            rc = 2
            url = None
            log.error("SharePoint digest upload failed: %s", e)
        link = url if url and url.startswith("http") else (f"{s.teams.report_link_base.rstrip('/')}/{forest}/digests/{month}-digest.html" if s.teams.report_link_base else None)
        try:
            teams.post(f"digest_{forest}_{month}", teams_digest_card(t, nar.markdown, label, link, nar.source))
        except RuntimeError as e:
            rc = 2
            log.error("Digest delivery failed: %s", e)
        log.info("Digest %s %s: score=%d source=%s model=%s latencyMs=%s usage=%s", forest, month, t.score, nar.source,
                 nar.meta.get("modelId"), nar.meta.get("latencyMs"), nar.meta.get("usage"))
    hist.close()
    return rc


def cmd_qualify(args) -> int:
    s = load_settings(args.config)
    result = run_qualification(s, [Path(b) for b in args.bundle], args.runs, args.min_pass_rate)
    jpath, mpath = write_evidence(result, Path(args.out))
    print(json.dumps({k: result[k] for k in ("verdict", "passRate", "attempts", "failureReasons", "latencyMs", "tokens")}, indent=2))
    print(f"Evidence: {jpath}\n          {mpath}")
    return 0 if result["verdict"] == "PASS" else 2


def cmd_doctor(args) -> int:
    s = load_settings(args.config)
    checks = run_doctor(s, online=args.online, probe_model=args.probe_model)
    width = max(len(c.name) for c in checks)
    for c in checks:
        print(f"{c.status:<5} {c.name:<{width}}  {c.detail}")
    if any(c.status == "FAIL" for c in checks):
        return 1
    return 2 if any(c.status == "WARN" for c in checks) else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="adhealth-agent", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--log-format", choices=["text", "json"], default="text", help="json = one object per line for SIEM/CloudWatch")
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate", help="verify a bundle (read-only)")
    v.add_argument("bundle")
    v.add_argument("--max-file-bytes", type=int, default=50 * 1024 * 1024)
    v.add_argument("--require-signature", action="store_true", help="fail if manifest.sig.json is missing")
    v.add_argument("--trusted-thumbprint", action="append", help="pinned signer thumbprint (repeatable)")
    v.set_defaults(fn=cmd_validate)
    p = sub.add_parser("process", help="ingest new bundles and send urgent alerts")
    p.add_argument("-c", "--config", required=True)
    p.set_defaults(fn=cmd_process)
    d = sub.add_parser("digest", help="build and publish the monthly digest")
    d.add_argument("-c", "--config", required=True)
    d.add_argument("--month", help="YYYY-MM; default: latest full report")
    d.add_argument("--forest")
    d.set_defaults(fn=cmd_digest)
    q = sub.add_parser("qualify", help="qualify the configured model against real bundles (guard pass rate, latency, tokens)")
    q.add_argument("-c", "--config", required=True)
    q.add_argument("-b", "--bundle", action="append", required=True, help="bundle directory (repeatable; same forest = month-over-month)")
    q.add_argument("--runs", type=int, default=3, help="attempts per bundle (default 3)")
    q.add_argument("--min-pass-rate", type=float, default=0.9)
    q.add_argument("--out", default="qualification", help="evidence output directory")
    q.set_defaults(fn=cmd_qualify)
    dr = sub.add_parser("doctor", help="preflight checks for the agent host")
    dr.add_argument("-c", "--config", required=True)
    dr.add_argument("--online", action="store_true", help="also call STS GetCallerIdentity")
    dr.add_argument("--probe-model", action="store_true", help="also send one minimal model request")
    dr.set_defaults(fn=cmd_doctor)
    args = ap.parse_args(argv)
    configure_logging(args.log_format, args.verbose)
    started = datetime.now(timezone.utc)
    rc = 1
    try:
        rc = args.fn(args)
    except (BundleError, ValueError) as e:
        log.error("%s", e)
        rc = 1
    except Exception as e:  # noqa: BLE001
        log.exception("Fatal: %s", type(e).__name__)
        rc = 1
    if args.cmd in ("process", "digest"):
        try:
            write_heartbeat(load_settings(args.config).state_db.parent, args.cmd, started, rc)
        except Exception as e:  # noqa: BLE001 - heartbeat must never mask the real exit code
            log.warning("Heartbeat not written: %s", type(e).__name__)
    return rc


if __name__ == "__main__":
    sys.exit(main())
