"""Teams delivery through a Power Automate / Teams *Workflows* webhook ("When a Teams webhook request is received").

Classic Office 365 connector incoming webhooks are retired; Workflows accepts the same
{"type": "message", "attachments": [adaptive card]} body. The webhook URL is a bearer secret:
it is read from an environment variable and never logged.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

import requests

from . import write_outbox

log = logging.getLogger(__name__)


class TeamsPublisher:
    def __init__(self, webhook_url: str | None, outbox: Path, dry_run: bool, timeout: int = 30, retries: int = 3):
        self.url = webhook_url
        self.outbox = outbox
        self.dry_run = dry_run or not webhook_url
        self.timeout = timeout
        self.retries = retries

    def post(self, name: str, payload: dict) -> str:
        if self.dry_run:
            p = write_outbox(self.outbox, f"teams_{name}.json", payload)
            log.info("DRY-RUN Teams payload written to %s", p)
            return f"dry-run:{p}"
        delay = 2.0
        for attempt in range(1, self.retries + 1):
            try:
                resp = requests.post(self.url, json=payload, timeout=self.timeout)
            except requests.RequestException as e:
                log.warning("Teams post attempt %d failed: %s", attempt, type(e).__name__)
            else:
                if resp.status_code < 300:
                    return f"sent:{resp.status_code}"
                if resp.status_code not in (408, 429) and resp.status_code < 500:
                    raise RuntimeError(f"Teams webhook rejected payload: HTTP {resp.status_code}")
                log.warning("Teams post attempt %d got HTTP %d", attempt, resp.status_code)
            if attempt < self.retries:
                time.sleep(delay)
                delay *= 2
        # Never lose an alert silently: persist it for manual follow-up.
        p = write_outbox(self.outbox, f"UNDELIVERED_teams_{name}.json", payload)
        raise RuntimeError(f"Teams delivery failed after {self.retries} attempts; payload saved to {p}")
