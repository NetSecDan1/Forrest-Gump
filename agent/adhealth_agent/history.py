"""SQLite history: the month-over-month memory of the agent (reports, findings, alert throttling)."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .models import Report

_SCHEMA = """
CREATE TABLE IF NOT EXISTS reports (
    report_id     TEXT PRIMARY KEY,
    forest        TEXT NOT NULL,
    generated_utc TEXT NOT NULL,
    status        TEXT NOT NULL,
    score         INTEGER NOT NULL,
    coverage      REAL NOT NULL,
    is_full       INTEGER NOT NULL,
    metrics_json  TEXT NOT NULL,
    bundle_path   TEXT NOT NULL,
    processed_utc TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_reports_forest_time ON reports(forest, generated_utc);
CREATE TABLE IF NOT EXISTS findings (
    report_id  TEXT NOT NULL REFERENCES reports(report_id),
    finding_id TEXT NOT NULL,
    check_id   TEXT NOT NULL,
    category   TEXT NOT NULL,
    severity   TEXT NOT NULL,
    title      TEXT NOT NULL,
    target     TEXT NOT NULL,
    count      INTEGER NOT NULL,
    PRIMARY KEY (report_id, finding_id)
);
CREATE TABLE IF NOT EXISTS alerts (
    forest           TEXT NOT NULL,
    alert_key        TEXT NOT NULL,
    last_alerted_utc TEXT NOT NULL,
    PRIMARY KEY (forest, alert_key)
);
"""


@dataclass
class StoredReport:
    report_id: str
    forest: str
    generated_utc: datetime
    status: str
    score: int
    coverage: float
    is_full: bool
    metrics: dict[str, float]
    bundle_path: str
    findings: dict[str, dict]  # finding_id -> row


def _utc(s: str) -> datetime:
    d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


class History:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path))
        self.db.row_factory = sqlite3.Row
        self.db.executescript(_SCHEMA)

    def close(self) -> None:
        self.db.close()

    def has_report(self, report_id: str) -> bool:
        return self.db.execute("SELECT 1 FROM reports WHERE report_id=?", (report_id,)).fetchone() is not None

    def save_report(self, report: Report, bundle_path: str) -> None:
        gen = report.generatedUtc.astimezone(timezone.utc).isoformat()
        with self.db:
            self.db.execute(
                "INSERT INTO reports VALUES (?,?,?,?,?,?,?,?,?,?)",
                (report.reportId, report.forest.name.lower(), gen, report.summary.overallStatus, report.summary.healthScore,
                 report.summary.checkCoveragePercent, int(report.is_full_run), json.dumps(report.metrics, sort_keys=True),
                 bundle_path, datetime.now(timezone.utc).isoformat()),
            )
            self.db.executemany(
                "INSERT OR REPLACE INTO findings VALUES (?,?,?,?,?,?,?,?)",
                [(report.reportId, f.id.lower(), f.checkId, f.category, f.severity, f.title, f.target, f.count) for f in report.findings],
            )

    def _load(self, row: sqlite3.Row | None) -> StoredReport | None:
        if row is None:
            return None
        frows = self.db.execute("SELECT * FROM findings WHERE report_id=?", (row["report_id"],)).fetchall()
        return StoredReport(
            report_id=row["report_id"], forest=row["forest"], generated_utc=_utc(row["generated_utc"]), status=row["status"],
            score=row["score"], coverage=row["coverage"], is_full=bool(row["is_full"]), metrics=json.loads(row["metrics_json"]),
            bundle_path=row["bundle_path"], findings={r["finding_id"]: dict(r) for r in frows},
        )

    def previous_full(self, forest: str, before: datetime) -> StoredReport | None:
        row = self.db.execute(
            "SELECT * FROM reports WHERE forest=? AND is_full=1 AND generated_utc < ? ORDER BY generated_utc DESC LIMIT 1",
            (forest.lower(), before.astimezone(timezone.utc).isoformat()),
        ).fetchone()
        return self._load(row)

    def latest(self, forest: str | None = None, full_only: bool = False, before: datetime | None = None) -> StoredReport | None:
        q, args = "SELECT * FROM reports WHERE 1=1", []
        if forest:
            q += " AND forest=?"
            args.append(forest.lower())
        if full_only:
            q += " AND is_full=1"
        if before:
            q += " AND generated_utc < ?"
            args.append(before.astimezone(timezone.utc).isoformat())
        return self._load(self.db.execute(q + " ORDER BY generated_utc DESC LIMIT 1", args).fetchone())

    def forests(self) -> list[str]:
        return [r[0] for r in self.db.execute("SELECT DISTINCT forest FROM reports ORDER BY forest")]

    def metric_series(self, forest: str, metric: str, limit: int = 12) -> list[tuple[str, float]]:
        rows = self.db.execute(
            "SELECT generated_utc, metrics_json FROM reports WHERE forest=? AND is_full=1 ORDER BY generated_utc DESC LIMIT ?",
            (forest.lower(), limit),
        ).fetchall()
        out = []
        for r in reversed(rows):
            m = json.loads(r["metrics_json"])
            if metric in m:
                out.append((r["generated_utc"][:10], float(m[metric])))
        return out

    def should_alert(self, forest: str, key: str, now: datetime, realert_after_days: int) -> bool:
        row = self.db.execute("SELECT last_alerted_utc FROM alerts WHERE forest=? AND alert_key=?", (forest.lower(), key)).fetchone()
        if row is None:
            return True
        return (now - _utc(row[0])).total_seconds() >= realert_after_days * 86400

    def mark_alerted(self, forest: str, keys: list[str], now: datetime) -> None:
        with self.db:
            self.db.executemany(
                "INSERT OR REPLACE INTO alerts VALUES (?,?,?)",
                [(forest.lower(), k, now.astimezone(timezone.utc).isoformat()) for k in keys],
            )
