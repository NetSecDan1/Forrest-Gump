"""Operational plumbing: structured logging, run ids, heartbeat files for external monitoring."""

from __future__ import annotations

import json
import logging
import socket
import uuid
from datetime import datetime, timezone
from pathlib import Path

RUN_ID = uuid.uuid4().hex[:12]


class JsonFormatter(logging.Formatter):
    """One JSON object per line - ingestible by CloudWatch Logs, Splunk, Sentinel, Elastic without parsing rules."""

    def format(self, record: logging.LogRecord) -> str:
        doc = {
            "ts": datetime.fromtimestamp(record.created, timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "runId": RUN_ID,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            doc["exc"] = self.formatException(record.exc_info)
        for k in ("forest", "reportId", "bundle", "event"):
            if hasattr(record, k):
                doc[k] = getattr(record, k)
        return json.dumps(doc, default=str)


def configure_logging(fmt: str, verbose: bool) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter() if fmt == "json" else
                         logging.Formatter(f"%(asctime)s %(levelname)s %(name)s [{RUN_ID}]: %(message)s"))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    # Third-party HTTP/AWS logs can include URLs (webhook secrets) or request bodies.
    for noisy in ("urllib3", "botocore", "boto3", "strands", "httpx"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def write_heartbeat(state_dir: Path, command: str, started: datetime, rc: int, **counts) -> Path:
    """state/heartbeat_<command>.json - monitor its age and rc (SCOM/CloudWatch/Zabbix file monitor).

    A pipeline that silently stops running is the most common failure of 'monthly' automation.
    """
    state_dir.mkdir(parents=True, exist_ok=True)
    p = state_dir / f"heartbeat_{command}.json"
    doc = {
        "command": command, "runId": RUN_ID, "startedUtc": started.isoformat(timespec="seconds"),
        "finishedUtc": datetime.now(timezone.utc).isoformat(timespec="seconds"), "exitCode": rc,
        "status": {0: "ok", 2: "degraded"}.get(rc, "failed"), "host": socket.gethostname(), **counts,
    }
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    tmp.replace(p)  # atomic for file monitors
    return p
